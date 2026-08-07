//! The runtime configuration model.
//!
//! The AST is what nginx *said*; this is what the server *does*. Everything
//! here is resolved at load time — regexes compiled, templates compiled,
//! inherited directives flattened into each location — so the request path
//! never re-interprets configuration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;

use super::vars::{Template, Var};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerProcesses {
    Auto,
    N(usize),
}

impl WorkerProcesses {
    pub fn resolve(self) -> usize {
        match self {
            WorkerProcesses::Auto => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            WorkerProcesses::N(n) => n.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Notice,
    Warn,
    Error,
    Crit,
    Alert,
    Emerg,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<LogLevel> {
        Some(match s {
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "notice" => LogLevel::Notice,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "crit" => LogLevel::Crit,
            "alert" => LogLevel::Alert,
            "emerg" => LogLevel::Emerg,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Notice => "notice",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Crit => "crit",
            LogLevel::Alert => "alert",
            LogLevel::Emerg => "emerg",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ErrorLogConf {
    pub path: PathBuf,
    pub level: LogLevel,
    /// `error_log /dev/null;` or `off`
    pub disabled: bool,
}

impl Default for ErrorLogConf {
    fn default() -> Self {
        ErrorLogConf {
            path: PathBuf::from("logs/error.log"),
            level: LogLevel::Error,
            disabled: false,
        }
    }
}

/// Where an `access_log` writes.
///
/// nginx uses a prefix on the path for non-file destinations
/// (`access_log syslog:server=...`); `oxidb:` follows that convention.
#[derive(Debug, Clone)]
pub enum LogSink {
    File(PathBuf),
    /// `access_log oxidb:server=127.0.0.1:12202[,db=name] fmt;`
    ///
    /// Fire-and-forget MessagePack over UDP into OxiDB's ingest listener.
    /// Per ADR-0002 this is off the request path in the sense that matters:
    /// a datagram is handed to the kernel and never waited on, so a slow or
    /// absent collector cannot stall a request.
    ///
    /// `db=` sets the `db` field OxiDB's MessagePack ingest routes on, picking
    /// the target database in a multi-tenant setup. The *collection* is fixed
    /// server-side (`OXIDB_MSGPACK_COLLECTION`, default `_msgpack_logs`) and
    /// cannot be chosen by the sender — an earlier `collection=` parameter
    /// here was a guess that would have silently done nothing.
    OxiDb {
        addr: Arc<str>,
        db: Option<Arc<str>>,
    },
}

#[derive(Debug, Clone)]
pub struct AccessLogConf {
    pub sink: LogSink,
    pub format: Arc<Template>,
    /// Bytes of in-memory buffering before a flush; `buffer=` in nginx.
    pub buffer: usize,
    /// `flush=` — maximum time a buffered line may sit unwritten.
    pub flush: Option<Duration>,
}

impl AccessLogConf {
    /// Key identifying the destination, for de-duplicating open sinks.
    pub fn key(&self) -> String {
        match &self.sink {
            LogSink::File(p) => p.to_string_lossy().into_owned(),
            LogSink::OxiDb { addr, .. } => format!("oxidb:{addr}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTokens {
    On,
    Off,
    Build,
}

/// `open_file_cache` and its companion directives.
///
/// The cache lives per worker thread (as nginx's does) and keeps open file
/// descriptors plus their `fstat` results, so a cache hit serves a request
/// with **zero** filesystem syscalls. Profiling showed 3 of the ~5.5 syscalls
/// per static request were path metadata — this is the directive that removes
/// them. Defaults mirror nginx: disabled, `valid` 60s, `min_uses` 1,
/// `errors` off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFileCache {
    pub enabled: bool,
    /// Maximum cached entries per worker (`max=`).
    pub max: usize,
    /// Entries unused for this long are dropped (`inactive=`).
    pub inactive: Duration,
    /// How long a cached fstat result is trusted before re-validation
    /// (`open_file_cache_valid`).
    pub valid: Duration,
    /// Entries used fewer times than this are preferred eviction victims
    /// (`open_file_cache_min_uses`).
    pub min_uses: u32,
    /// Whether lookup failures (404 and friends) are cached too
    /// (`open_file_cache_errors`).
    pub errors: bool,
}

impl Default for OpenFileCache {
    fn default() -> Self {
        OpenFileCache {
            enabled: false,
            max: 0,
            inactive: Duration::from_secs(60),
            valid: Duration::from_secs(60),
            min_uses: 1,
            errors: false,
        }
    }
}

/// A `limit_req_zone` declaration, before its runtime state exists.
#[derive(Debug, Clone)]
pub struct LimitReqZoneDef {
    pub name: Box<str>,
    /// The key to rate-limit on, e.g. `$binary_remote_addr`.
    pub key: Arc<Template>,
    /// Requests per second, scaled by 1000 so `30r/m` stays exact.
    pub rate: u64,
    /// Derived from `zone=name:SIZE` the way nginx does: 64 bytes per entry.
    pub max_entries: usize,
}

/// One `limit_req` applied at a level. Several may apply to one request; nginx
/// evaluates them all and the most restrictive outcome wins.
#[derive(Debug, Clone)]
pub struct LimitReq {
    pub zone: Box<str>,
    /// Burst allowance, scaled by 1000.
    pub burst: u64,
    /// `nodelay` — admit the whole burst immediately.
    pub nodelay: bool,
    /// `delay=N` — admit N of the burst immediately, delay the rest.
    pub delay_after: u64,
}

/// A `limit_conn_zone` declaration, before its runtime state exists.
#[derive(Debug, Clone)]
pub struct LimitConnZoneDef {
    pub name: Box<str>,
    /// The key to count against, e.g. `$binary_remote_addr`.
    pub key: Arc<Template>,
    /// Derived from `zone=name:SIZE` the way nginx does.
    pub max_entries: usize,
}

/// One `limit_conn zone number;` applied at a level. As with `limit_req`,
/// several may apply and every one of them has to admit the request.
#[derive(Debug, Clone)]
pub struct LimitConn {
    pub zone: Box<str>,
    /// Requests this key may have in flight at once.
    pub limit: u32,
}

/// `proxy_cache_valid [code…] time;` — how long each status stays fresh.
#[derive(Debug, Clone)]
pub struct CacheValid {
    /// Empty means "any status nginx caches by default" (200, 301, 302).
    pub codes: Vec<u16>,
    pub ttl: Duration,
}

/// The caching settings that apply to a location.
#[derive(Debug, Clone)]
pub struct ProxyCacheConf {
    /// Zone name; `None` means `proxy_cache off`.
    pub zone: Option<Arc<str>>,
    pub key: Arc<Template>,
    pub valid: Arc<Vec<CacheValid>>,
    pub methods: Arc<Vec<Box<str>>>,
    pub min_uses: u32,
    /// `proxy_cache_bypass` — non-empty, non-"0" means skip the lookup.
    pub bypass: Arc<Vec<Arc<Template>>>,
    /// `proxy_no_cache` — non-empty, non-"0" means do not store the response.
    pub no_cache: Arc<Vec<Arc<Template>>>,
    /// `proxy_cache_use_stale` — when an expired entry beats an error.
    pub use_stale: Arc<Vec<crate::server::cache::StaleWhen>>,
    /// `proxy_cache_lock` — only one request populates a key at a time.
    pub lock: bool,
    /// How long a waiting request queues before giving up and fetching itself.
    pub lock_timeout: Duration,
}

impl Default for ProxyCacheConf {
    fn default() -> Self {
        ProxyCacheConf {
            zone: None,
            // nginx's default key.
            key: Arc::new(Template::compile("$scheme$proxy_host$request_uri")),
            valid: Arc::new(Vec::new()),
            methods: Arc::new(vec![Box::from("GET"), Box::from("HEAD")]),
            min_uses: 1,
            bypass: Arc::new(Vec::new()),
            no_cache: Arc::new(Vec::new()),
            use_stale: Arc::new(Vec::new()),
            lock: false,
            lock_timeout: Duration::from_secs(5),
        }
    }
}

/// Directives that inherit down `http` → `server` → `location`.
///
/// Every field is resolved (no `Option`) by the time a request sees it; the
/// builder carries a parallel `Option`-valued struct while merging.
#[derive(Debug, Clone)]
pub struct CoreConf {
    pub root: Arc<Template>,
    pub alias: Option<Arc<Template>>,
    pub index: Arc<Vec<Template>>,
    pub autoindex: bool,
    pub default_type: Arc<str>,
    pub charset: Option<Arc<str>>,
    pub sendfile: bool,
    pub tcp_nopush: bool,
    pub tcp_nodelay: bool,
    pub keepalive_timeout: Duration,
    pub keepalive_requests: u64,
    pub client_header_timeout: Duration,
    pub client_body_timeout: Duration,
    pub send_timeout: Duration,
    pub client_max_body_size: u64,
    pub client_header_buffer_size: usize,
    pub large_client_header_buffers: (usize, usize),
    /// The rule set in force here, shared with every level that inherits it.
    /// `None` means no rules were loaded for this level — distinct from
    /// `modsecurity off`, which keeps the rules but stops consulting them.
    #[cfg(feature = "modsecurity")]
    pub modsecurity_rules: Option<Arc<crate::waf::Engine>>,
    /// Whether to enforce them. Rules loaded at `http` with `modsecurity off`
    /// in one location is the ordinary way to exempt a path.
    #[cfg(feature = "modsecurity")]
    pub modsecurity: bool,
    pub server_tokens: ServerTokens,
    pub etag: bool,
    pub msie_padding: bool,
    pub gzip: GzipConf,
    pub add_headers: Arc<Vec<AddHeader>>,
    pub expires: Option<Expires>,
    pub proxy: Arc<ProxyConf>,
    pub output_buffers: (usize, usize),
    pub directio: Option<u64>,
    pub log_not_found: bool,
    pub absolute_redirect: bool,
    pub port_in_redirect: bool,
    pub server_name_in_redirect: bool,
    pub if_modified_since: IfModifiedSince,
    pub max_ranges: Option<usize>,
    pub limit_rate: u64,
    pub limit_rate_after: u64,
    pub satisfy_any: bool,
    pub internal: bool,
    /// `auth_request URI` — the subrequest that decides whether this location
    /// may be served at all. `None` is `auth_request off`.
    pub auth_request: Option<Arc<str>>,
    /// `auth_request_set $var value`, evaluated after the subrequest with its
    /// response headers visible as `$upstream_http_*`.
    pub auth_request_set: Vec<(Arc<str>, Arc<Template>)>,
    pub open_file_cache: OpenFileCache,
    pub fastcgi: Arc<FastCgiConf>,
    pub proxy_cache: ProxyCacheConf,
    pub limit_reqs: Arc<Vec<LimitReq>>,
    /// `limit_req_status` — the status returned when a limit rejects.
    pub limit_req_status: u16,
    pub limit_conns: Arc<Vec<LimitConn>>,
    /// `limit_conn_status` — the status returned when a limit rejects.
    pub limit_conn_status: u16,
    /// `limit_conn_dry_run on` — account the request but never refuse it, so a
    /// limit can be sized against real traffic before it starts rejecting.
    pub limit_conn_dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfModifiedSince {
    Off,
    Exact,
    Before,
}

#[derive(Debug, Clone)]
pub struct GzipConf {
    pub enabled: bool,
    pub level: u32,
    pub min_length: u64,
    pub types: Arc<Vec<Box<str>>>,
    pub vary: bool,
    /// `gzip_proxied` — simplified to on/off/any for now.
    pub proxied_any: bool,
    pub http_version_1_0: bool,
    pub disable_msie6: bool,
}

impl Default for GzipConf {
    fn default() -> Self {
        GzipConf {
            enabled: false,
            level: 1,
            min_length: 20,
            types: Arc::new(vec![Box::from("text/html")]),
            vary: false,
            proxied_any: false,
            http_version_1_0: false,
            disable_msie6: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddHeader {
    pub name: Arc<str>,
    pub value: Arc<Template>,
    /// `always` — emit even on error responses.
    pub always: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expires {
    Off,
    Epoch,
    Max,
    /// Seconds; negative means "already expired".
    Secs(i64),
    /// `@12h` — next occurrence of a wall-clock time.
    Daily(i64),
}

#[derive(Debug, Clone, Default)]
pub struct ProxyConf {
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub set_headers: Vec<(Arc<str>, Arc<Template>)>,
    pub hide_headers: Vec<Box<str>>,
    pub pass_headers: Vec<Box<str>>,
    pub buffering: bool,
    pub http_version_11: bool,
    /// `proxy_next_upstream` — which failures are worth another peer.
    pub next_upstream: NextUpstream,
    /// `proxy_next_upstream_tries` — 0 means "as many peers as there are".
    pub next_upstream_tries: u32,
    /// `proxy_next_upstream_timeout` — 0 means no overall bound.
    pub next_upstream_timeout: Duration,
    pub ssl_server_name: bool,
    pub set_body: Option<Arc<Template>>,
}

/// Which upstream failures justify trying the next peer.
///
/// nginx's default is `error timeout`: a peer that could not be reached or did
/// not answer in time is worth retrying, while a peer that answered — even
/// with a 500 — has done its job as far as the proxy is concerned, and
/// retrying would double the load on a backend already in trouble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextUpstream {
    /// Connection refused, reset, or otherwise unusable.
    pub error: bool,
    /// Connect or read timed out.
    pub timeout: bool,
    /// The peer answered with something that is not a response head.
    pub invalid_header: bool,
    /// Specific status codes that count as a failure of this peer.
    pub statuses: Vec<u16>,
    /// Retry even a request that is not safe to repeat. Off by default,
    /// because a retried `POST` can charge a card twice.
    pub non_idempotent: bool,
    /// `proxy_next_upstream off` — never try another peer.
    pub off: bool,
}

impl Default for NextUpstream {
    fn default() -> NextUpstream {
        NextUpstream {
            error: true,
            timeout: true,
            invalid_header: false,
            statuses: Vec::new(),
            non_idempotent: false,
            off: false,
        }
    }
}

/// How a `location` was written, which drives nginx's matching order.
#[derive(Debug, Clone)]
pub enum LocMatch {
    /// `location = /exact`
    Exact(Box<str>),
    /// `location /prefix`
    Prefix(Box<str>),
    /// `location ^~ /prefix` — wins over regexes when it is the longest match.
    PrefixNoRegex(Box<str>),
    /// `location ~ re` / `location ~* re`
    Regex { re: Box<Regex>, ci: bool },
    /// `location @name` — only reachable via `error_page` / `try_files`.
    Named(Box<str>),
}

impl LocMatch {
    pub fn prefix(&self) -> Option<&str> {
        match self {
            LocMatch::Exact(p) | LocMatch::Prefix(p) | LocMatch::PrefixNoRegex(p) => Some(p),
            _ => None,
        }
    }
}

/// What a location does once matched.
#[derive(Debug, Clone)]
pub enum Action {
    /// Serve from the filesystem (`root`/`alias` + `index`).
    Static,
    /// `return code [text|url];`
    Return { status: u16, body: Option<Arc<Template>> },
    /// `proxy_pass http://backend;`
    Proxy(Arc<ProxyPass>),
    /// `fastcgi_pass 127.0.0.1:9000;`
    FastCgi(Arc<FastCgiPass>),
    /// `stub_status;` — the server's own counters.
    ///
    /// `json` is an extension: nginx has no upstream visibility outside its
    /// commercial build, and a pool you cannot inspect is one you debug by
    /// guessing. Plain `stub_status;` is byte-for-byte nginx.
    StubStatus { json: bool },
    /// A location that only exists to hold configuration (e.g. `internal;`).
    None,
}

/// `fastcgi_pass` plus everything that shapes the FastCGI environment.
#[derive(Debug, Clone)]
pub struct FastCgiPass {
    pub target: ProxyTarget,
}

#[derive(Debug, Clone)]
pub struct FastCgiConf {
    /// `fastcgi_param NAME value [if_not_empty]`, in configuration order.
    pub params: Vec<FastCgiParam>,
    /// `fastcgi_index` — appended when the script path ends in `/`.
    pub index: Option<Arc<str>>,
    /// `fastcgi_split_path_info` — capture 1 is SCRIPT_NAME, capture 2 is
    /// PATH_INFO. This is what makes `/app.php/users/42` route correctly.
    pub split_path_info: Option<Arc<Regex>>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    /// `fastcgi_keep_conn` — ask the application not to close the connection.
    pub keep_conn: bool,
    pub hide_headers: Vec<Box<str>>,
    /// `fastcgi_buffering` — with it off, the response is forwarded as it
    /// arrives instead of being collected first.
    pub buffering: bool,
    /// Total bytes of response body worth collecting before giving up on
    /// buffering and streaming the rest, from `fastcgi_buffers` ×
    /// `fastcgi_buffer_size`.
    ///
    /// Buffering a whole response is what lets us send a `Content-Length`; a
    /// response that outgrows this becomes chunked, which is the trade nginx
    /// makes at the same point.
    pub buffer_budget: usize,
}

impl Default for FastCgiConf {
    /// Written out rather than derived: `bool` derives to `false` and `usize`
    /// to `0`, which would have turned buffering off for every configuration
    /// that never mentions it and made the budget zero — streaming everything,
    /// silently, as a "default".
    fn default() -> FastCgiConf {
        FastCgiConf {
            params: Vec::new(),
            index: None,
            split_path_info: None,
            connect_timeout: None,
            read_timeout: None,
            send_timeout: None,
            keep_conn: false,
            hide_headers: Vec::new(),
            buffering: true,
            // nginx's `fastcgi_buffers 8 8k` on a 64-bit page size.
            buffer_budget: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FastCgiParam {
    pub name: Arc<str>,
    pub value: Arc<Template>,
    /// `if_not_empty` — omit the parameter when the value renders empty.
    pub if_not_empty: bool,
}

#[derive(Debug, Clone)]
pub struct ProxyPass {
    /// Named upstream, or a literal host to dial.
    pub target: ProxyTarget,
    /// URI portion of `proxy_pass`; `None` means "pass $uri through unchanged".
    pub uri: Option<Arc<Template>>,
    pub tls: bool,
}

#[derive(Debug, Clone)]
pub enum ProxyTarget {
    Upstream(Arc<str>),
    Addr { host: Arc<str>, port: u16 },
    /// `unix:/run/php-fpm.sock` — how php-fpm ships by default.
    Unix(Arc<str>),
    /// `proxy_pass $backend;` — resolved per request.
    Dynamic(Arc<Template>),
}

#[derive(Debug, Clone)]
pub struct TryFiles {
    pub items: Vec<Arc<Template>>,
    pub fallback: TryFallback,
}

#[derive(Debug, Clone)]
pub enum TryFallback {
    /// `try_files $uri =404;`
    Status(u16),
    /// `try_files $uri /index.html;` — internal redirect.
    Uri(Arc<Template>),
    /// `try_files $uri @named;`
    Named(Arc<str>),
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub re: Box<Regex>,
    pub replacement: Arc<Template>,
    pub flag: RewriteFlag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteFlag {
    None,
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Debug, Clone)]
pub struct IfBlock {
    pub cond: Cond,
    pub actions: Vec<IfAction>,
}

#[derive(Debug, Clone)]
pub enum Cond {
    /// Unconditional. A bare `set` outside any `if` is modelled as an
    /// always-true block so both forms run through one evaluator.
    Always,
    /// Truthy test: non-empty and not "0".
    Truthy(Var),
    Eq(Var, Arc<Template>),
    Ne(Var, Arc<Template>),
    Match { var: Var, re: Box<Regex>, negate: bool },
    FileExists { t: Arc<Template>, negate: bool },
    DirExists { t: Arc<Template>, negate: bool },
    AnyExists { t: Arc<Template>, negate: bool },
    Executable { t: Arc<Template>, negate: bool },
}

#[derive(Debug, Clone)]
pub enum IfAction {
    Return { status: u16, body: Option<Arc<Template>> },
    Rewrite(Rewrite),
    Set { var: Arc<str>, value: Arc<Template> },
    AddHeader(AddHeader),
    Break,
}

#[derive(Debug, Clone)]
pub struct ErrorPage {
    pub codes: Vec<u16>,
    /// `error_page 404 =200 /empty.gif;`
    pub replace_status: Option<u16>,
    pub target: ErrorTarget,
}

#[derive(Debug, Clone)]
pub enum ErrorTarget {
    Uri(Arc<Template>),
    Named(Arc<str>),
    /// An absolute URL causes a redirect rather than an internal jump.
    Redirect(Arc<Template>),
}

#[derive(Debug)]
pub struct Location {
    pub matcher: LocMatch,
    pub core: CoreConf,
    pub action: Action,
    pub try_files: Option<TryFiles>,
    pub rewrites: Vec<Rewrite>,
    pub ifs: Vec<IfBlock>,
    pub error_pages: Vec<ErrorPage>,
    pub access_logs: Vec<AccessLogConf>,
    /// Nested `location` blocks, searched only after this one matches.
    pub nested: Option<Box<LocSet>>,
    /// Methods permitted, `None` = all. From `limit_except`.
    pub allowed_methods: Option<Vec<Box<str>>>,
    pub raw_line: u32,
}

/// Locations grouped by match kind so lookup follows nginx's documented order.
#[derive(Debug, Default)]
pub struct LocSet {
    /// `=` matches, sorted by path for binary search.
    pub exact: Vec<Arc<Location>>,
    /// Prefix matches, sorted longest-first so the first hit is the best hit.
    pub prefix: Vec<Arc<Location>>,
    /// Regex matches in configuration order — first match wins.
    pub regex: Vec<Arc<Location>>,
    /// `@name` locations, reachable only by internal redirect.
    pub named: HashMap<Box<str>, Arc<Location>>,
}

impl LocSet {
    /// nginx's location search:
    ///   1. an `=` match ends the search immediately;
    ///   2. remember the longest prefix match;
    ///   3. if that prefix was `^~`, use it and skip regexes;
    ///   4. otherwise try regexes in order, first match wins;
    ///   5. fall back to the remembered prefix.
    ///
    /// Returns the matched location plus regex captures, if any.
    pub fn find<'s, 'u>(
        &'s self,
        uri: &'u str,
    ) -> Option<(&'s Arc<Location>, Option<regex::Captures<'u>>)> {
        if let Ok(i) = self
            .exact
            .binary_search_by(|l| l.matcher.prefix().unwrap_or("").cmp(uri))
        {
            return Some((&self.exact[i], None));
        }

        let best_prefix = self
            .prefix
            .iter()
            .find(|l| uri.starts_with(l.matcher.prefix().unwrap_or("")));

        if let Some(l) = best_prefix {
            if matches!(l.matcher, LocMatch::PrefixNoRegex(_)) {
                return Some((l, None));
            }
        }

        for l in &self.regex {
            if let LocMatch::Regex { re, .. } = &l.matcher {
                if let Some(c) = re.captures(uri) {
                    return Some((l, Some(c)));
                }
            }
        }

        best_prefix.map(|l| (l, None))
    }
}

/// A parsed `server_name` entry. nginx resolves these in a fixed priority
/// order, which is why they are separated rather than kept as one list.
#[derive(Debug, Clone)]
pub enum ServerName {
    Exact(Box<str>),
    /// `*.example.com` — also matches the bare `example.com`.
    LeadingWildcard(Box<str>),
    /// `www.example.*`
    TrailingWildcard(Box<str>),
    Regex(Box<Regex>),
    /// An empty `server_name ""`, matching requests with no Host header.
    Empty,
}

#[derive(Debug)]
pub struct ServerConf {
    pub names: Vec<ServerName>,
    pub core: CoreConf,
    pub locations: LocSet,
    pub rewrites: Vec<Rewrite>,
    pub ifs: Vec<IfBlock>,
    pub error_pages: Vec<ErrorPage>,
    pub access_logs: Vec<AccessLogConf>,
    /// `return` written directly in the server block.
    pub action: Action,
    pub tls: Option<Arc<TlsConf>>,
    pub listens: Vec<ListenSpec>,
    /// Pre-rendered `Alt-Svc` value advertising this server's QUIC port, or
    /// `None` when it has no `listen ... quic`.
    ///
    /// Built here rather than per request because the request path never
    /// re-reads configuration — the port and the lifetime are both fixed the
    /// moment the `listen` lines are parsed.
    pub alt_svc: Option<Box<str>>,
    pub raw_line: u32,
}

#[derive(Debug, Clone)]
pub struct TlsConf {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub protocols: Vec<Box<str>>,
    pub alpn_h2: bool,
}

/// Where a listener binds. nginx allows both on the same `listen` directive
/// family, and a config commonly has a TCP port plus a Unix socket for a
/// front proxy on the same host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    Tcp(SocketAddr),
    Unix(Arc<str>),
}

impl ListenAddr {
    pub fn port(&self) -> u16 {
        match self {
            ListenAddr::Tcp(a) => a.port(),
            ListenAddr::Unix(_) => 0,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, ListenAddr::Tcp(a) if a.is_ipv6())
    }
}

impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenAddr::Tcp(a) => write!(f, "{a}"),
            ListenAddr::Unix(p) => write!(f, "unix:{p}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListenSpec {
    pub addr: ListenAddr,
    pub default_server: bool,
    pub ssl: bool,
    pub http2: bool,
    /// `listen ... udp` — a datagram listener in a `stream` block. Mutually
    /// exclusive with everything TCP: there is no accept, no connection, and
    /// no ordering.
    pub udp: bool,
    /// `listen ... quic` — this address is served over QUIC, on UDP. A `listen`
    /// line is either TCP or UDP, never both, so this partitions the specs
    /// rather than decorating them: `listen 443 ssl; listen 443 quic;` is two
    /// sockets on one port, which is exactly how HTTP/3 is deployed.
    pub quic: bool,
    pub reuseport: bool,
    pub backlog: Option<i32>,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    pub ipv6_only: bool,
    pub deferred: bool,
}

/// One bound socket, plus every server that can be selected on it.
#[derive(Debug)]
pub struct Listener {
    pub addr: ListenAddr,
    pub backlog: i32,
    pub reuseport: bool,
    pub ssl: bool,
    pub http2: bool,
    /// A UDP/QUIC listener. Lives in `Http::quic_listeners`, never in
    /// `Http::listeners`, so nothing on the TCP accept path has to ask.
    pub quic: bool,
    pub ipv6_only: bool,
    pub deferred: bool,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    pub servers: Vec<Arc<ServerConf>>,
    /// Index into `servers` used when no `server_name` matches.
    pub default_server: usize,
}

impl Listener {
    /// Picks a server by `Host`, following nginx's precedence:
    /// exact → longest leading wildcard → longest trailing wildcard →
    /// first matching regex → default server.
    pub fn match_host(&self, host: &str) -> &Arc<ServerConf> {
        let host = host.trim_end_matches('.');
        let mut best_lead: Option<(usize, &Arc<ServerConf>)> = None;
        let mut best_trail: Option<(usize, &Arc<ServerConf>)> = None;

        for s in &self.servers {
            for n in &s.names {
                match n {
                    ServerName::Exact(e) => {
                        if host.eq_ignore_ascii_case(e) {
                            return s;
                        }
                    }
                    ServerName::LeadingWildcard(suffix) => {
                        // `*.example.com` matches `a.example.com` and `example.com`.
                        let m = host.len() > suffix.len()
                            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                            && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix);
                        if m && best_lead.map_or(true, |(l, _)| suffix.len() > l) {
                            best_lead = Some((suffix.len(), s));
                        }
                    }
                    ServerName::TrailingWildcard(pre) => {
                        let m = host.len() > pre.len()
                            && host.as_bytes()[pre.len()] == b'.'
                            && host[..pre.len()].eq_ignore_ascii_case(pre);
                        if m && best_trail.map_or(true, |(l, _)| pre.len() > l) {
                            best_trail = Some((pre.len(), s));
                        }
                    }
                    ServerName::Empty => {
                        if host.is_empty() {
                            return s;
                        }
                    }
                    ServerName::Regex(_) => {}
                }
            }
        }

        if let Some((_, s)) = best_lead {
            return s;
        }
        if let Some((_, s)) = best_trail {
            return s;
        }
        for s in &self.servers {
            for n in &s.names {
                if let ServerName::Regex(re) = n {
                    if re.is_match(host) {
                        return s;
                    }
                }
            }
        }
        &self.servers[self.default_server]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbMethod {
    RoundRobin,
    LeastConn,
    IpHash,
    Random,
}

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub addr: Box<str>,
    /// Opaque identifier this peer is known by in a `sticky cookie`.
    ///
    /// A hash of the address rather than the address itself, so the cookie
    /// does not hand a client the backend topology, and deterministic rather
    /// than seeded, so a reload does not invalidate every session in flight.
    pub sticky_id: Box<str>,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout: Duration,
    pub backup: bool,
    pub down: bool,
    pub max_conns: Option<u32>,
}

/// `health_check` — active probing, run whether or not traffic is flowing.
///
/// This is the difference from passive tracking: passive health only learns a
/// peer is dead when a real request fails on it, so a backend that dies during
/// a quiet period is discovered by the first unlucky visitor. Active checks
/// find it first. Open-source nginx has no equivalent (it is an nginx Plus
/// feature), so this is a capability gained rather than parity.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub interval: Duration,
    /// Consecutive failures before a peer is taken out.
    pub fails: u32,
    /// Consecutive successes before it is put back.
    pub passes: u32,
    /// `uri=` makes it an HTTP probe; without one it is a plain TCP connect,
    /// which is all that is meaningful for a `stream` upstream.
    pub uri: Option<Arc<str>>,
    pub expect_status: u16,
    pub timeout: Duration,
}

impl Default for HealthCheck {
    fn default() -> Self {
        HealthCheck {
            interval: Duration::from_secs(5),
            fails: 1,
            passes: 1,
            uri: None,
            expect_status: 200,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug)]
pub struct Upstream {
    pub name: Box<str>,
    pub servers: Vec<UpstreamServer>,
    pub method: LbMethod,
    /// `keepalive N;` — idle upstream connections to retain per worker.
    pub keepalive: usize,
    /// Live per-peer health and load, parallel to `servers`. Shared across
    /// workers so one worker's discovery of a dead backend spares the rest.
    pub health: Vec<crate::server::upstream::PeerHealth>,
    /// Reference point for the millisecond timestamps in `health`.
    pub origin: std::time::Instant,
    /// `health_check` in this upstream block, if any.
    pub health_check: Option<HealthCheck>,
    /// `sticky cookie name [expires=] [domain=] [path=] …`
    pub sticky: Option<StickyCookie>,
}

/// `sticky cookie` — pin a client to the peer that first served it.
///
/// Layered over the balancing method rather than replacing it: the cookie
/// decides when it is present and names a peer that can still take traffic,
/// and `least_conn` or round-robin decides in every other case.
#[derive(Debug, Clone)]
pub struct StickyCookie {
    pub name: Box<str>,
    /// `expires=` — absent means a session cookie, gone when the browser is.
    pub expires: Option<Duration>,
    pub domain: Option<Box<str>>,
    pub path: Option<Box<str>>,
    pub httponly: bool,
    pub secure: bool,
    pub samesite: Option<Box<str>>,
}

impl StickyCookie {
    /// Renders the `Set-Cookie` value pinning a client to `id`.
    pub fn set_cookie(&self, id: &str) -> String {
        let mut v = format!("{}={}", self.name, id);
        v.push_str("; Path=");
        v.push_str(self.path.as_deref().unwrap_or("/"));
        if let Some(d) = &self.domain {
            v.push_str("; Domain=");
            v.push_str(d);
        }
        if let Some(e) = self.expires {
            // Max-Age rather than Expires: no date formatting, no clock skew
            // between us and the client, and every browser in use supports it.
            v.push_str("; Max-Age=");
            v.push_str(&e.as_secs().to_string());
        }
        if let Some(s) = &self.samesite {
            v.push_str("; SameSite=");
            v.push_str(s);
        }
        if self.secure {
            v.push_str("; Secure");
        }
        if self.httponly {
            v.push_str("; HttpOnly");
        }
        v
    }
}

/// The identifier a peer is known by in a sticky cookie.
///
/// FNV-1a over a domain-separated address. Deterministic on purpose: a
/// `sticky` value that changed on reload would scatter every established
/// session across the pool on a routine certificate renewal, which is a worse
/// failure than the mild disclosure of letting someone who already knows a
/// backend's `host:port` confirm it.
pub fn sticky_id_for(addr: &str) -> Box<str> {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in b"oxiserve-sticky\0".iter().chain(addr.as_bytes()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}").into_boxed_str()
}

/// A compiled `map $in $out { ... }`.
#[derive(Debug)]
pub struct MapConf {
    pub source: Var,
    pub target: Arc<str>,
    pub exact: HashMap<Box<str>, Arc<Template>>,
    pub wildcards: Vec<(Box<str>, Arc<Template>, bool)>,
    pub regexes: Vec<(Box<Regex>, Arc<Template>)>,
    pub default: Option<Arc<Template>>,
    pub hostnames: bool,
}

#[derive(Debug, Default)]
pub struct MimeTypes {
    by_ext: HashMap<Box<str>, Arc<str>>,
}

impl MimeTypes {
    pub fn insert(&mut self, ext: &str, ty: &str) {
        self.by_ext
            .insert(ext.to_ascii_lowercase().into_boxed_str(), Arc::from(ty));
    }

    pub fn lookup(&self, path: &str) -> Option<&Arc<str>> {
        let ext = path.rsplit('.').next()?;
        if ext.len() == path.len() {
            return None;
        }
        // Extensions are stored lowercased; avoid allocating for the common
        // case where the request path is already lowercase.
        if ext.bytes().any(|b| b.is_ascii_uppercase()) {
            self.by_ext.get(ext.to_ascii_lowercase().as_str())
        } else {
            self.by_ext.get(ext)
        }
    }

    pub fn len(&self) -> usize {
        self.by_ext.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ext.is_empty()
    }
}

#[derive(Debug)]
pub struct Http {
    pub cache_zones: HashMap<Box<str>, Arc<crate::server::cache::Zone>>,
    pub limit_req_zones: HashMap<Box<str>, Arc<crate::server::limit_req::Zone>>,
    /// Each zone's key template, kept beside it so a location only names a zone.
    pub limit_req_keys: HashMap<Box<str>, Arc<Template>>,
    pub limit_conn_zones: HashMap<Box<str>, Arc<crate::server::limit_conn::Zone>>,
    pub limit_conn_keys: HashMap<Box<str>, Arc<Template>>,
    pub listeners: Vec<Arc<Listener>>,
    /// QUIC listeners, grouped by address exactly as `listeners` is but bound
    /// on UDP. Separate because a port can carry both and they are different
    /// sockets with different accept loops.
    pub quic_listeners: Vec<Arc<Listener>>,
    pub upstreams: HashMap<Box<str>, Arc<Upstream>>,
    pub maps: Vec<Arc<MapConf>>,
    pub mime: Arc<MimeTypes>,
    pub servers: Vec<Arc<ServerConf>>,
}

/// One `server { }` inside a `stream` block: a listener and where its bytes go.
#[derive(Debug)]
pub struct StreamServer {
    pub listens: Vec<ListenSpec>,
    pub target: ProxyTarget,
    pub connect_timeout: Duration,
    /// `proxy_timeout` — how long a connection may sit **idle** before it is
    /// closed. Measured between reads, not from the start, so a long-lived but
    /// busy connection is never cut off.
    pub timeout: Duration,
    /// `ssl_preread on;` — inspect the TLS ClientHello before choosing a
    /// backend, so `proxy_pass` can route on `$ssl_preread_server_name`.
    pub ssl_preread: bool,
    /// `preread_buffer_size` — the cap on how much we will hold while waiting
    /// for a complete ClientHello. A client that never sends one costs this
    /// much memory and no more.
    pub preread_buffer_size: usize,
    /// `preread_timeout` — how long to wait for it. On expiry the connection
    /// is proxied with empty preread variables rather than dropped: a client
    /// that is slow is not a client that is wrong.
    pub preread_timeout: Duration,
    /// `proxy_responses N` — how many datagrams the backend is expected to
    /// send back per client datagram, after which the UDP session is finished
    /// without waiting for the idle timeout. `None` means "however many",
    /// and the session lives until `proxy_timeout` expires.
    pub proxy_responses: Option<u64>,
    pub raw_line: u32,
}

/// A bound stream listener and the server behind it.
#[derive(Debug)]
pub struct StreamListener {
    pub addr: ListenAddr,
    pub backlog: i32,
    pub reuseport: bool,
    pub ipv6_only: bool,
    /// Datagrams rather than connections. UDP listeners live in
    /// [`StreamConf::udp_listeners`], never in `listeners`.
    pub udp: bool,
    pub server: Arc<StreamServer>,
}

/// The `stream { }` block: layer 4 proxying, no HTTP parsing at all.
#[derive(Debug)]
pub struct StreamConf {
    pub listeners: Vec<Arc<StreamListener>>,
    /// Datagram listeners, bound per worker with `SO_REUSEPORT`. Kept apart
    /// from `listeners` because a UDP socket has no accept loop to share.
    pub udp_listeners: Vec<Arc<StreamListener>>,
    pub upstreams: HashMap<Box<str>, Arc<Upstream>>,
    /// `map` blocks declared inside `stream { }`. Kept separate from the HTTP
    /// ones because the two scopes have different variables available — an
    /// `$ssl_preread_server_name` map means nothing to a request, and a
    /// `$http_host` map means nothing to a raw TCP connection.
    pub maps: Vec<Arc<MapConf>>,
}

#[derive(Debug)]
pub struct Config {
    pub worker_processes: WorkerProcesses,
    pub worker_connections: usize,
    pub worker_rlimit_nofile: Option<u64>,
    pub error_log: ErrorLogConf,
    pub pid: Option<PathBuf>,
    pub daemon: bool,
    pub user: Option<(Box<str>, Option<Box<str>>)>,
    pub prefix: PathBuf,
    pub http: Option<Http>,
    pub stream: Option<StreamConf>,
    /// Directives we parsed but do not implement, kept so `-t` can report them.
    pub unsupported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(m: LocMatch) -> Arc<Location> {
        Arc::new(Location {
            matcher: m,
            core: crate::config::build::default_core(),
            action: Action::Static,
            try_files: None,
            rewrites: vec![],
            ifs: vec![],
            error_pages: vec![],
            access_logs: vec![],
            nested: None,
            allowed_methods: None,
            raw_line: 0,
        })
    }

    fn set(mut locs: Vec<Arc<Location>>) -> LocSet {
        let mut s = LocSet::default();
        for l in locs.drain(..) {
            match &l.matcher {
                LocMatch::Exact(_) => s.exact.push(l),
                LocMatch::Prefix(_) | LocMatch::PrefixNoRegex(_) => s.prefix.push(l),
                LocMatch::Regex { .. } => s.regex.push(l),
                LocMatch::Named(n) => {
                    s.named.insert(n.clone(), l);
                }
            }
        }
        s.exact.sort_by(|a, b| a.matcher.prefix().cmp(&b.matcher.prefix()));
        s.prefix.sort_by_key(|l| std::cmp::Reverse(l.matcher.prefix().unwrap_or("").len()));
        s
    }

    #[test]
    fn exact_beats_everything() {
        let s = set(vec![
            loc(LocMatch::Exact("/a".into())),
            loc(LocMatch::Prefix("/a".into())),
            loc(LocMatch::Regex { re: Box::new(Regex::new("^/a$").unwrap()), ci: false }),
        ]);
        let (m, _) = s.find("/a").unwrap();
        assert!(matches!(m.matcher, LocMatch::Exact(_)));
    }

    #[test]
    fn longest_prefix_wins() {
        let s = set(vec![
            loc(LocMatch::Prefix("/".into())),
            loc(LocMatch::Prefix("/img/".into())),
            loc(LocMatch::Prefix("/img/big/".into())),
        ]);
        let (m, _) = s.find("/img/big/x.png").unwrap();
        assert_eq!(m.matcher.prefix(), Some("/img/big/"));
    }

    #[test]
    fn regex_beats_plain_prefix_but_not_caret_tilde() {
        let plain = set(vec![
            loc(LocMatch::Prefix("/img/".into())),
            loc(LocMatch::Regex { re: Box::new(Regex::new(r"\.png$").unwrap()), ci: false }),
        ]);
        assert!(matches!(plain.find("/img/a.png").unwrap().0.matcher, LocMatch::Regex { .. }));

        let caret = set(vec![
            loc(LocMatch::PrefixNoRegex("/img/".into())),
            loc(LocMatch::Regex { re: Box::new(Regex::new(r"\.png$").unwrap()), ci: false }),
        ]);
        assert!(matches!(caret.find("/img/a.png").unwrap().0.matcher, LocMatch::PrefixNoRegex(_)));
    }

    #[test]
    fn first_regex_in_config_order_wins() {
        let s = set(vec![
            loc(LocMatch::Regex { re: Box::new(Regex::new(r"^/a").unwrap()), ci: false }),
            loc(LocMatch::Regex { re: Box::new(Regex::new(r"\.png$").unwrap()), ci: false }),
        ]);
        let (m, _) = s.find("/a/x.png").unwrap();
        if let LocMatch::Regex { re, .. } = &m.matcher {
            assert_eq!(re.as_str(), "^/a");
        } else {
            panic!("expected regex");
        }
    }

    fn srv(names: Vec<ServerName>) -> Arc<ServerConf> {
        Arc::new(ServerConf {
            names,
            core: crate::config::build::default_core(),
            locations: LocSet::default(),
            rewrites: vec![],
            ifs: vec![],
            error_pages: vec![],
            access_logs: vec![],
            action: Action::None,
            tls: None,
            listens: vec![],
            alt_svc: None,
            raw_line: 0,
        })
    }

    fn listener(servers: Vec<Arc<ServerConf>>) -> Listener {
        Listener {
            addr: ListenAddr::Tcp("0.0.0.0:80".parse().unwrap()),
            backlog: 511,
            reuseport: false,
            ssl: false,
            http2: false,
            quic: false,
            ipv6_only: true,
            deferred: false,
            rcvbuf: None,
            sndbuf: None,
            servers,
            default_server: 0,
        }
    }

    #[test]
    fn host_matching_precedence() {
        let default = srv(vec![ServerName::Exact("default".into())]);
        let exact = srv(vec![ServerName::Exact("www.example.com".into())]);
        let lead = srv(vec![ServerName::LeadingWildcard("example.com".into())]);
        let re = srv(vec![ServerName::Regex(Box::new(Regex::new(r"^\d+\.example\.com$").unwrap()))]);
        let l = listener(vec![default.clone(), exact.clone(), lead.clone(), re.clone()]);

        assert!(Arc::ptr_eq(l.match_host("www.example.com"), &exact));
        assert!(Arc::ptr_eq(l.match_host("api.example.com"), &lead));
        assert!(Arc::ptr_eq(l.match_host("42.example.com"), &lead)); // wildcard outranks regex
        assert!(Arc::ptr_eq(l.match_host("nope.org"), &default));
        // A trailing dot in Host is stripped before matching.
        assert!(Arc::ptr_eq(l.match_host("www.example.com."), &exact));
    }

    #[test]
    fn regex_host_used_when_no_wildcard_matches() {
        let default = srv(vec![ServerName::Exact("d".into())]);
        let re = srv(vec![ServerName::Regex(Box::new(Regex::new(r"^\d+\.test$").unwrap()))]);
        let l = listener(vec![default, re.clone()]);
        assert!(Arc::ptr_eq(l.match_host("42.test"), &re));
    }

    #[test]
    fn mime_lookup_is_case_insensitive_on_extension() {
        let mut m = MimeTypes::default();
        m.insert("PNG", "image/png");
        assert_eq!(&**m.lookup("/a/b.png").unwrap(), "image/png");
        assert_eq!(&**m.lookup("/a/b.PNG").unwrap(), "image/png");
        assert!(m.lookup("/a/noext").is_none());
    }
}

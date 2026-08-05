//! Lowers the directive tree into the runtime [`Config`].
//!
//! This is where nginx's inheritance rules live. Two flavours exist and the
//! difference matters:
//!
//! * **Scalar** directives (`root`, `sendfile`, `keepalive_timeout`, …) inherit
//!   from the enclosing level unless overridden.
//! * **List** directives (`add_header`, `index`, `error_page`, `access_log`, …)
//!   inherit *only if the current level defines none at all*. Defining one
//!   `add_header` in a location discards every inherited header — a real and
//!   frequently-surprising nginx behaviour that we reproduce exactly.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;

use super::ast::Directive;
use super::model::*;
use super::vars::{Template, Var};

pub struct BuildError {
    pub msg: String,
    pub loc: String,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} in {}", self.msg, self.loc)
    }
}

impl std::fmt::Debug for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for BuildError {}

macro_rules! bail {
    ($d:expr, $($t:tt)*) => {
        return Err(BuildError { msg: format!($($t)*), loc: $d.loc() })
    };
}

type R<T> = Result<T, BuildError>;

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn want_args(d: &Directive, n: usize) -> R<()> {
    if d.args.len() != n {
        bail!(d, "invalid number of arguments in \"{}\" directive", d.name);
    }
    Ok(())
}

fn want_args_range(d: &Directive, lo: usize, hi: usize) -> R<()> {
    if d.args.len() < lo || d.args.len() > hi {
        bail!(d, "invalid number of arguments in \"{}\" directive", d.name);
    }
    Ok(())
}

fn flag(d: &Directive) -> R<bool> {
    want_args(d, 1)?;
    match d.args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => bail!(d, "invalid value \"{other}\" in \"{}\" directive, it must be \"on\" or \"off\"", d.name),
    }
}

/// `1024`, `10k`, `8m`, `2g` — nginx's size syntax.
pub fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1024),
        b'm' | b'M' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// `60s`, `1h`, `500ms`, `1d`, `2w`, `90` (bare = seconds). Compound values
/// like `1h30m` are accepted, as nginx does.
pub fn parse_time(s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }
    let b = s.as_bytes();
    let mut total = Duration::ZERO;
    let mut i = 0;
    let mut any = false;

    while i < b.len() {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let n: u64 = s[start..i].parse().ok()?;
        let ustart = i;
        while i < b.len() && b[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &s[ustart..i];
        let d = match unit {
            "ms" => Duration::from_millis(n),
            "s" | "" => Duration::from_secs(n),
            "m" => Duration::from_secs(n * 60),
            "h" => Duration::from_secs(n * 3600),
            "d" => Duration::from_secs(n * 86400),
            "w" => Duration::from_secs(n * 604800),
            "M" => Duration::from_secs(n * 2592000),
            "y" => Duration::from_secs(n * 31536000),
            _ => return None,
        };
        total += d;
        any = true;
    }
    any.then_some(total)
}

fn time_arg(d: &Directive, i: usize) -> R<Duration> {
    let a = d.arg(i).unwrap_or("");
    parse_time(a).ok_or_else(|| BuildError {
        msg: format!("invalid time value \"{a}\" in \"{}\" directive", d.name),
        loc: d.loc(),
    })
}

fn size_arg(d: &Directive, i: usize) -> R<u64> {
    let a = d.arg(i).unwrap_or("");
    parse_size(a).ok_or_else(|| BuildError {
        msg: format!("invalid size value \"{a}\" in \"{}\" directive", d.name),
        loc: d.loc(),
    })
}

/// Translates a PCRE-flavoured nginx regex to the `regex` crate's syntax.
///
/// The two disagree on named groups in older syntax and on inline flags; more
/// importantly, `regex` has no backreferences or lookaround, so a config using
/// them gets a clear error instead of silently mismatching.
fn compile_regex(pat: &str, ci: bool, d: &Directive) -> R<Box<Regex>> {
    let translated = pat.replace("(?<", "(?P<").replace("(?P P<", "(?P<");
    let full = if ci {
        format!("(?i){translated}")
    } else {
        translated
    };
    match Regex::new(&full) {
        Ok(re) => Ok(Box::new(re)),
        Err(e) => {
            let hint = if pat.contains("(?=") || pat.contains("(?!") || pat.contains("(?<=") {
                "\n  note: lookahead/lookbehind is a PCRE feature OxiServe does not support"
            } else if pat.contains('\\') && pat.contains(|c: char| c.is_ascii_digit()) {
                "\n  note: backreferences are a PCRE feature OxiServe does not support"
            } else {
                ""
            };
            bail!(d, "invalid regular expression \"{pat}\": {e}{hint}")
        }
    }
}

// ---------------------------------------------------------------------------
// Inheritable core configuration
// ---------------------------------------------------------------------------

pub fn default_core() -> CoreConf {
    CoreConf {
        root: Arc::new(Template::compile("html")),
        alias: None,
        index: Arc::new(vec![Template::compile("index.html")]),
        autoindex: false,
        default_type: Arc::from("text/plain"),
        charset: None,
        sendfile: false,
        tcp_nopush: false,
        tcp_nodelay: true,
        keepalive_timeout: Duration::from_secs(75),
        keepalive_requests: 1000,
        client_header_timeout: Duration::from_secs(60),
        client_body_timeout: Duration::from_secs(60),
        send_timeout: Duration::from_secs(60),
        client_max_body_size: 1024 * 1024,
        client_header_buffer_size: 1024,
        large_client_header_buffers: (4, 8192),
        server_tokens: ServerTokens::On,
        etag: true,
        msie_padding: true,
        gzip: GzipConf::default(),
        add_headers: Arc::new(Vec::new()),
        expires: None,
        proxy: Arc::new(ProxyConf {
            connect_timeout: Some(Duration::from_secs(60)),
            read_timeout: Some(Duration::from_secs(60)),
            send_timeout: Some(Duration::from_secs(60)),
            set_headers: Vec::new(),
            hide_headers: Vec::new(),
            pass_headers: Vec::new(),
            buffering: true,
            http_version_11: false,
            next_upstream_tries: 0,
            ssl_server_name: false,
            set_body: None,
        }),
        output_buffers: (2, 32768),
        directio: None,
        log_not_found: true,
        absolute_redirect: true,
        port_in_redirect: true,
        server_name_in_redirect: false,
        if_modified_since: IfModifiedSince::Exact,
        max_ranges: None,
        limit_rate: 0,
        limit_rate_after: 0,
        satisfy_any: false,
        internal: false,
    }
}

/// A level's worth of core directives, layered over its parent.
///
/// `Option::None` means "not set here, inherit". List-valued fields follow the
/// replace-wholesale rule described in the module docs.
#[derive(Clone, Default)]
struct CoreLayer {
    root: Option<Arc<Template>>,
    alias: Option<Arc<Template>>,
    index: Option<Vec<Template>>,
    autoindex: Option<bool>,
    default_type: Option<Arc<str>>,
    charset: Option<Arc<str>>,
    sendfile: Option<bool>,
    tcp_nopush: Option<bool>,
    tcp_nodelay: Option<bool>,
    keepalive_timeout: Option<Duration>,
    keepalive_requests: Option<u64>,
    client_header_timeout: Option<Duration>,
    client_body_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    client_max_body_size: Option<u64>,
    client_header_buffer_size: Option<usize>,
    large_client_header_buffers: Option<(usize, usize)>,
    server_tokens: Option<ServerTokens>,
    etag: Option<bool>,
    gzip: Option<bool>,
    gzip_level: Option<u32>,
    gzip_min_length: Option<u64>,
    gzip_types: Option<Vec<Box<str>>>,
    gzip_vary: Option<bool>,
    gzip_proxied_any: Option<bool>,
    add_headers: Option<Vec<AddHeader>>,
    expires: Option<Expires>,
    output_buffers: Option<(usize, usize)>,
    log_not_found: Option<bool>,
    absolute_redirect: Option<bool>,
    port_in_redirect: Option<bool>,
    server_name_in_redirect: Option<bool>,
    if_modified_since: Option<IfModifiedSince>,
    max_ranges: Option<usize>,
    limit_rate: Option<u64>,
    limit_rate_after: Option<u64>,
    internal: Option<bool>,
    // proxy_* are accumulated rather than replaced, matching nginx's
    // per-directive inheritance for proxy_set_header et al.
    proxy_connect_timeout: Option<Duration>,
    proxy_read_timeout: Option<Duration>,
    proxy_send_timeout: Option<Duration>,
    proxy_set_headers: Option<Vec<(Arc<str>, Arc<Template>)>>,
    proxy_hide_headers: Option<Vec<Box<str>>>,
    proxy_buffering: Option<bool>,
    proxy_http_11: Option<bool>,
    proxy_ssl_server_name: Option<bool>,
}

impl CoreLayer {
    /// Applies this layer on top of `parent`, producing a fully-resolved conf.
    fn resolve(&self, parent: &CoreConf) -> CoreConf {
        let mut c = parent.clone();
        // `alias` and `root` are mutually exclusive; setting one clears the
        // other so a location with `alias` does not also inherit a `root`.
        if let Some(v) = &self.root {
            c.root = v.clone();
            c.alias = None;
        }
        if let Some(v) = &self.alias {
            c.alias = Some(v.clone());
        }
        if let Some(v) = &self.index {
            c.index = Arc::new(v.clone());
        }
        macro_rules! set {
            ($($f:ident),* $(,)?) => { $( if let Some(v) = self.$f.clone() { c.$f = v; } )* };
        }
        set!(
            autoindex,
            default_type,
            sendfile,
            tcp_nopush,
            tcp_nodelay,
            keepalive_timeout,
            keepalive_requests,
            client_header_timeout,
            client_body_timeout,
            send_timeout,
            client_max_body_size,
            client_header_buffer_size,
            large_client_header_buffers,
            server_tokens,
            etag,
            output_buffers,
            log_not_found,
            absolute_redirect,
            port_in_redirect,
            server_name_in_redirect,
            if_modified_since,
            limit_rate,
            limit_rate_after,
            internal,
        );
        if self.charset.is_some() {
            c.charset = self.charset.clone();
        }
        if self.expires.is_some() {
            c.expires = self.expires;
        }
        if self.max_ranges.is_some() {
            c.max_ranges = self.max_ranges;
        }
        if let Some(v) = &self.add_headers {
            c.add_headers = Arc::new(v.clone());
        }

        let g = &mut c.gzip;
        if let Some(v) = self.gzip {
            g.enabled = v;
        }
        if let Some(v) = self.gzip_level {
            g.level = v;
        }
        if let Some(v) = self.gzip_min_length {
            g.min_length = v;
        }
        if let Some(v) = &self.gzip_types {
            g.types = Arc::new(v.clone());
        }
        if let Some(v) = self.gzip_vary {
            g.vary = v;
        }
        if let Some(v) = self.gzip_proxied_any {
            g.proxied_any = v;
        }

        if self.proxy_connect_timeout.is_some()
            || self.proxy_read_timeout.is_some()
            || self.proxy_send_timeout.is_some()
            || self.proxy_set_headers.is_some()
            || self.proxy_hide_headers.is_some()
            || self.proxy_buffering.is_some()
            || self.proxy_http_11.is_some()
            || self.proxy_ssl_server_name.is_some()
        {
            let mut p = (*c.proxy).clone();
            if let Some(v) = self.proxy_connect_timeout {
                p.connect_timeout = Some(v);
            }
            if let Some(v) = self.proxy_read_timeout {
                p.read_timeout = Some(v);
            }
            if let Some(v) = self.proxy_send_timeout {
                p.send_timeout = Some(v);
            }
            if let Some(v) = &self.proxy_set_headers {
                p.set_headers = v.clone();
            }
            if let Some(v) = &self.proxy_hide_headers {
                p.hide_headers = v.clone();
            }
            if let Some(v) = self.proxy_buffering {
                p.buffering = v;
            }
            if let Some(v) = self.proxy_http_11 {
                p.http_version_11 = v;
            }
            if let Some(v) = self.proxy_ssl_server_name {
                p.ssl_server_name = v;
            }
            c.proxy = Arc::new(p);
        }
        c
    }
}

/// Everything a level can declare, core or otherwise.
#[derive(Default)]
struct Level {
    core: CoreLayer,
    action: Option<Action>,
    try_files: Option<TryFiles>,
    rewrites: Vec<Rewrite>,
    ifs: Vec<IfBlock>,
    error_pages: Option<Vec<ErrorPage>>,
    access_logs: Option<Vec<AccessLogConf>>,
    allowed_methods: Option<Vec<Box<str>>>,
    locations: Vec<Directive>,
}

pub struct Builder {
    pub prefix: PathBuf,
    log_formats: HashMap<Box<str>, Arc<Template>>,
    pub unsupported: Vec<String>,
}

/// Directives OxiServe recognises as valid nginx but does not yet implement.
/// Listing them explicitly means `oxiserve -t` can say "not implemented"
/// instead of "unknown directive", which is a very different message for
/// someone porting a config.
const KNOWN_UNIMPLEMENTED: &[&str] = &[
    "fastcgi_pass", "fastcgi_param", "fastcgi_index", "fastcgi_split_path_info",
    "uwsgi_pass", "scgi_pass", "grpc_pass", "memcached_pass",
    "auth_basic", "auth_basic_user_file", "auth_request",
    "limit_req", "limit_req_zone", "limit_conn", "limit_conn_zone",
    "ssi", "sub_filter", "sub_filter_types", "addition_before_body",
    "dav_methods", "mp4", "flv", "xslt_stylesheet", "image_filter",
    "stub_status", "perl", "js_content",
    "geo", "split_clients", "referer_hash_bucket_size",
    "open_file_cache", "open_file_cache_valid", "open_file_cache_min_uses",
    "proxy_cache", "proxy_cache_path", "proxy_cache_valid", "proxy_cache_key",
];

impl Builder {
    pub fn new(prefix: PathBuf) -> Builder {
        Builder {
            prefix,
            log_formats: HashMap::new(),
            unsupported: Vec::new(),
        }
    }

    fn note_unsupported(&mut self, d: &Directive) {
        let msg = if KNOWN_UNIMPLEMENTED.contains(&d.name.as_str()) {
            format!("{}: directive \"{}\" is recognised but not implemented yet", d.loc(), d.name)
        } else {
            format!("{}: unknown directive \"{}\"", d.loc(), d.name)
        };
        if !self.unsupported.contains(&msg) {
            self.unsupported.push(msg);
        }
    }

    pub fn build(&mut self, dirs: &[Directive]) -> R<Config> {
        let mut cfg = Config {
            worker_processes: WorkerProcesses::N(1),
            worker_connections: 512,
            worker_rlimit_nofile: None,
            error_log: ErrorLogConf::default(),
            pid: None,
            daemon: false,
            user: None,
            prefix: self.prefix.clone(),
            http: None,
            unsupported: Vec::new(),
        };

        for d in dirs {
            match d.name.as_str() {
                "worker_processes" => {
                    want_args(d, 1)?;
                    cfg.worker_processes = if d.args[0] == "auto" {
                        WorkerProcesses::Auto
                    } else {
                        match d.args[0].parse() {
                            Ok(n) => WorkerProcesses::N(n),
                            Err(_) => bail!(d, "invalid value \"{}\" in \"worker_processes\"", d.args[0]),
                        }
                    };
                }
                "worker_rlimit_nofile" => {
                    want_args(d, 1)?;
                    cfg.worker_rlimit_nofile = Some(size_arg(d, 0)?);
                }
                "error_log" => cfg.error_log = self.error_log(d)?,
                "pid" => {
                    want_args(d, 1)?;
                    cfg.pid = Some(self.abs(&d.args[0]));
                }
                "daemon" => cfg.daemon = flag(d)?,
                "user" => {
                    want_args_range(d, 1, 2)?;
                    cfg.user = Some((
                        d.args[0].as_str().into(),
                        d.arg(1).map(|g| g.into()),
                    ));
                }
                "events" => {
                    for e in d.children() {
                        match e.name.as_str() {
                            "worker_connections" => {
                                want_args(e, 1)?;
                                cfg.worker_connections = e.args[0].parse().map_err(|_| BuildError {
                                    msg: format!("invalid value \"{}\"", e.args[0]),
                                    loc: e.loc(),
                                })?;
                            }
                            // Event model selection is meaningless here: the
                            // runtime always uses the platform's best poller.
                            "use" | "multi_accept" | "accept_mutex" | "accept_mutex_delay" => {}
                            _ => self.note_unsupported(e),
                        }
                    }
                }
                "http" => {
                    let http = self.http(d)?;
                    cfg.http = Some(http);
                }
                "stream" | "mail" => self.note_unsupported(d),
                "load_module" | "master_process" | "worker_shutdown_timeout"
                | "worker_priority" | "working_directory" | "lock_file"
                | "timer_resolution" | "pcre_jit" | "thread_pool" => {}
                _ => self.note_unsupported(d),
            }
        }

        cfg.unsupported = std::mem::take(&mut self.unsupported);
        Ok(cfg)
    }

    fn abs(&self, p: &str) -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.prefix.join(path)
        }
    }

    fn error_log(&self, d: &Directive) -> R<ErrorLogConf> {
        want_args_range(d, 1, 2)?;
        if d.args[0] == "off" {
            return Ok(ErrorLogConf { disabled: true, ..Default::default() });
        }
        let level = match d.arg(1) {
            Some(l) => LogLevel::parse(l).ok_or_else(|| BuildError {
                msg: format!("invalid log level \"{l}\""),
                loc: d.loc(),
            })?,
            None => LogLevel::Error,
        };
        Ok(ErrorLogConf {
            path: self.abs(&d.args[0]),
            level,
            disabled: false,
        })
    }

    // -----------------------------------------------------------------------
    // http { }
    // -----------------------------------------------------------------------

    fn http(&mut self, d: &Directive) -> R<Http> {
        let mut mime = MimeTypes::default();
        crate::mime::load_defaults(&mut mime);

        let mut upstreams: HashMap<Box<str>, Arc<Upstream>> = HashMap::new();
        let mut maps = Vec::new();
        let mut level = Level::default();
        let mut server_dirs = Vec::new();

        // log_format must be collected before access_log directives reference
        // it, but nginx allows either order — so do a dedicated pass first.
        for c in d.children() {
            if c.name == "log_format" {
                want_args_range(c, 2, 64)?;
                let joined = c.args[1..].concat();
                self.log_formats
                    .insert(c.args[0].as_str().into(), Arc::new(Template::compile(&joined)));
            }
        }
        if !self.log_formats.contains_key("combined") {
            self.log_formats.insert(
                "combined".into(),
                Arc::new(Template::compile(COMBINED_FORMAT)),
            );
        }

        for c in d.children() {
            match c.name.as_str() {
                "log_format" => {}
                "types" => {
                    for t in c.children() {
                        for ext in &t.args {
                            mime.insert(ext, &t.name);
                        }
                    }
                }
                "upstream" => {
                    want_args(c, 1)?;
                    let u = self.upstream(c)?;
                    upstreams.insert(c.args[0].as_str().into(), Arc::new(u));
                }
                "map" => maps.push(Arc::new(self.map(c)?)),
                "server" => server_dirs.push(c),
                _ => {
                    if !self.level_directive(&mut level, c, Scope::Http)? {
                        self.note_unsupported(c);
                    }
                }
            }
        }

        let http_core = level.core.resolve(&default_core());
        let http_error_pages = level.error_pages.clone().unwrap_or_default();
        let http_access_logs = level.access_logs.clone().unwrap_or_else(|| {
            vec![AccessLogConf {
                path: self.abs("logs/access.log"),
                format: self.log_formats["combined"].clone(),
                buffer: 0,
                flush: None,
            }]
        });

        let mut servers = Vec::new();
        for sd in server_dirs {
            servers.push(Arc::new(self.server(
                sd,
                &http_core,
                &http_error_pages,
                &http_access_logs,
            )?));
        }

        if servers.is_empty() {
            bail!(d, "no server blocks defined in http");
        }

        let listeners = self.listeners(&servers)?;

        Ok(Http {
            listeners,
            upstreams,
            maps,
            mime: Arc::new(mime),
            servers,
        })
    }

    fn upstream(&mut self, d: &Directive) -> R<Upstream> {
        let mut servers = Vec::new();
        let mut method = LbMethod::RoundRobin;
        let mut keepalive = 0;

        for c in d.children() {
            match c.name.as_str() {
                "server" => {
                    want_args_range(c, 1, 16)?;
                    let mut s = UpstreamServer {
                        addr: c.args[0].as_str().into(),
                        weight: 1,
                        max_fails: 1,
                        fail_timeout: Duration::from_secs(10),
                        backup: false,
                        down: false,
                        max_conns: None,
                    };
                    for p in &c.args[1..] {
                        if let Some(v) = p.strip_prefix("weight=") {
                            s.weight = v.parse().unwrap_or(1);
                        } else if let Some(v) = p.strip_prefix("max_fails=") {
                            s.max_fails = v.parse().unwrap_or(1);
                        } else if let Some(v) = p.strip_prefix("fail_timeout=") {
                            s.fail_timeout = parse_time(v).unwrap_or(Duration::from_secs(10));
                        } else if let Some(v) = p.strip_prefix("max_conns=") {
                            s.max_conns = v.parse().ok();
                        } else if p == "backup" {
                            s.backup = true;
                        } else if p == "down" {
                            s.down = true;
                        } else if p.starts_with("resolve") || p.starts_with("slow_start") {
                            // commercial-only knobs; accepted and ignored
                        } else {
                            bail!(c, "invalid parameter \"{p}\" in upstream server");
                        }
                    }
                    servers.push(s);
                }
                "least_conn" => method = LbMethod::LeastConn,
                "ip_hash" => method = LbMethod::IpHash,
                "random" => method = LbMethod::Random,
                "hash" => method = LbMethod::RoundRobin, // consistent hashing: TODO
                "keepalive" => {
                    want_args(c, 1)?;
                    keepalive = c.args[0].parse().unwrap_or(0);
                }
                "keepalive_requests" | "keepalive_timeout" | "zone" | "queue" => {}
                _ => self.note_unsupported(c),
            }
        }
        if servers.is_empty() {
            bail!(d, "no servers defined in upstream \"{}\"", d.args[0]);
        }
        Ok(Upstream {
            name: d.args[0].as_str().into(),
            servers,
            method,
            keepalive,
        })
    }

    fn map(&mut self, d: &Directive) -> R<MapConf> {
        want_args(d, 2)?;
        let src = d.args[0]
            .strip_prefix('$')
            .ok_or_else(|| BuildError {
                msg: format!("invalid map source \"{}\", expected a variable", d.args[0]),
                loc: d.loc(),
            })?;
        let target = d.args[1].strip_prefix('$').ok_or_else(|| BuildError {
            msg: format!("invalid map target \"{}\", expected a variable", d.args[1]),
            loc: d.loc(),
        })?;

        let mut m = MapConf {
            source: Var::parse(src),
            target: Arc::from(target),
            exact: HashMap::new(),
            wildcards: Vec::new(),
            regexes: Vec::new(),
            default: None,
            hostnames: false,
        };

        for c in d.children() {
            match c.name.as_str() {
                "hostnames" => m.hostnames = true,
                "volatile" => {}
                "include" => {}
                "default" => {
                    want_args(c, 1)?;
                    m.default = Some(Arc::new(Template::compile(&c.args[0])));
                }
                key => {
                    want_args(c, 1)?;
                    let val = Arc::new(Template::compile(&c.args[0]));
                    if let Some(re) = key.strip_prefix("~*") {
                        m.regexes.push((compile_regex(re, true, c)?, val));
                    } else if let Some(re) = key.strip_prefix('~') {
                        m.regexes.push((compile_regex(re, false, c)?, val));
                    } else if let Some(suffix) = key.strip_prefix("*.") {
                        m.wildcards.push((suffix.into(), val, true));
                    } else if let Some(pre) = key.strip_suffix(".*") {
                        m.wildcards.push((pre.into(), val, false));
                    } else {
                        m.exact.insert(key.to_ascii_lowercase().into_boxed_str(), val);
                    }
                }
            }
        }
        Ok(m)
    }

    // -----------------------------------------------------------------------
    // server { }
    // -----------------------------------------------------------------------

    fn server(
        &mut self,
        d: &Directive,
        parent: &CoreConf,
        parent_errs: &[ErrorPage],
        parent_logs: &[AccessLogConf],
    ) -> R<ServerConf> {
        let mut level = Level::default();
        let mut names = Vec::new();
        let mut listens = Vec::new();
        let mut cert: Option<PathBuf> = None;
        let mut key: Option<PathBuf> = None;
        let mut protocols: Vec<Box<str>> = Vec::new();

        for c in d.children() {
            match c.name.as_str() {
                "listen" => listens.push(self.listen(c)?),
                "server_name" => {
                    for a in &c.args {
                        names.push(self.server_name(a, c)?);
                    }
                }
                "ssl_certificate" => {
                    want_args(c, 1)?;
                    cert = Some(self.abs(&c.args[0]));
                }
                "ssl_certificate_key" => {
                    want_args(c, 1)?;
                    key = Some(self.abs(&c.args[0]));
                }
                "ssl_protocols" => protocols = c.args.iter().map(|s| s.as_str().into()).collect(),
                "ssl_ciphers" | "ssl_prefer_server_ciphers" | "ssl_session_cache"
                | "ssl_session_timeout" | "ssl_session_tickets" | "ssl_dhparam"
                | "ssl_ecdh_curve" | "ssl_stapling" | "ssl_stapling_verify" => {}
                "location" => level.locations.push(c.clone()),
                _ => {
                    if !self.level_directive(&mut level, c, Scope::Server)? {
                        self.note_unsupported(c);
                    }
                }
            }
        }

        if listens.is_empty() {
            listens.push(ListenSpec {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
                default_server: false,
                ssl: false,
                http2: false,
                reuseport: false,
                backlog: None,
                rcvbuf: None,
                sndbuf: None,
                ipv6_only: true,
                deferred: false,
            });
        }
        if names.is_empty() {
            names.push(ServerName::Exact("".into()));
        }

        let core = level.core.resolve(parent);
        let tls = match (cert, key) {
            (Some(c), Some(k)) => Some(Arc::new(TlsConf {
                cert: c,
                key: k,
                protocols,
                alpn_h2: listens.iter().any(|l| l.http2),
            })),
            (None, None) => None,
            _ => bail!(d, "both ssl_certificate and ssl_certificate_key are required"),
        };
        if listens.iter().any(|l| l.ssl) && tls.is_none() {
            bail!(d, "no \"ssl_certificate\" is defined for the server listening on an ssl port");
        }

        let locations = self.loc_set(&level.locations, &core)?;

        Ok(ServerConf {
            names,
            core,
            locations,
            rewrites: level.rewrites,
            ifs: level.ifs,
            error_pages: level.error_pages.unwrap_or_else(|| parent_errs.to_vec()),
            access_logs: level.access_logs.unwrap_or_else(|| parent_logs.to_vec()),
            action: level.action.unwrap_or(Action::None),
            tls,
            listens,
            raw_line: d.line,
        })
    }

    fn server_name(&self, a: &str, d: &Directive) -> R<ServerName> {
        if a.is_empty() || a == "\"\"" {
            return Ok(ServerName::Empty);
        }
        if let Some(re) = a.strip_prefix("~*") {
            return Ok(ServerName::Regex(compile_regex(re, true, d)?));
        }
        if let Some(re) = a.strip_prefix('~') {
            return Ok(ServerName::Regex(compile_regex(re, false, d)?));
        }
        if let Some(suffix) = a.strip_prefix("*.") {
            return Ok(ServerName::LeadingWildcard(suffix.into()));
        }
        if let Some(pre) = a.strip_suffix(".*") {
            return Ok(ServerName::TrailingWildcard(pre.into()));
        }
        Ok(ServerName::Exact(a.to_ascii_lowercase().into_boxed_str()))
    }

    fn listen(&mut self, d: &Directive) -> R<ListenSpec> {
        want_args_range(d, 1, 16)?;
        let spec = &d.args[0];

        if spec.starts_with("unix:") {
            bail!(d, "unix domain sockets are not supported yet");
        }

        let addr = parse_listen_addr(spec).ok_or_else(|| BuildError {
            msg: format!("invalid listen address \"{spec}\""),
            loc: d.loc(),
        })?;

        let mut l = ListenSpec {
            addr,
            default_server: false,
            ssl: false,
            http2: false,
            reuseport: false,
            backlog: None,
            rcvbuf: None,
            sndbuf: None,
            ipv6_only: true,
            deferred: false,
        };

        for p in &d.args[1..] {
            match p.as_str() {
                "default_server" | "default" => l.default_server = true,
                "ssl" => l.ssl = true,
                "http2" | "spdy" | "quic" => l.http2 = true,
                "reuseport" => l.reuseport = true,
                "deferred" => l.deferred = true,
                "bind" | "fastopen" | "accept_filter" | "so_keepalive" | "proxy_protocol" => {}
                other => {
                    if let Some(v) = other.strip_prefix("backlog=") {
                        l.backlog = v.parse().ok();
                    } else if let Some(v) = other.strip_prefix("rcvbuf=") {
                        l.rcvbuf = parse_size(v).map(|n| n as usize);
                    } else if let Some(v) = other.strip_prefix("sndbuf=") {
                        l.sndbuf = parse_size(v).map(|n| n as usize);
                    } else if let Some(v) = other.strip_prefix("ipv6only=") {
                        l.ipv6_only = v == "on";
                    } else if other.starts_with("so_keepalive=") || other.starts_with("fastopen=") {
                        // accepted, applied where the platform allows
                    } else {
                        bail!(d, "invalid parameter \"{other}\" in \"listen\" directive");
                    }
                }
            }
        }
        Ok(l)
    }

    /// Groups every server's `listen` directives into one [`Listener`] per
    /// bound address.
    fn listeners(&mut self, servers: &[Arc<ServerConf>]) -> R<Vec<Arc<Listener>>> {
        struct Acc {
            spec: ListenSpec,
            servers: Vec<Arc<ServerConf>>,
            default: Option<usize>,
        }
        let mut by_addr: Vec<(SocketAddr, Acc)> = Vec::new();

        for s in servers {
            for l in &s.listens {
                let entry = match by_addr.iter_mut().find(|(a, _)| *a == l.addr) {
                    Some((_, acc)) => acc,
                    None => {
                        by_addr.push((
                            l.addr,
                            Acc { spec: l.clone(), servers: Vec::new(), default: None },
                        ));
                        &mut by_addr.last_mut().unwrap().1
                    }
                };
                // Socket-level options come from whichever listen line sets
                // them; nginx warns on conflicts, we take the first non-default.
                entry.spec.ssl |= l.ssl;
                entry.spec.http2 |= l.http2;
                entry.spec.reuseport |= l.reuseport;
                entry.spec.deferred |= l.deferred;
                entry.spec.backlog = entry.spec.backlog.or(l.backlog);
                entry.spec.rcvbuf = entry.spec.rcvbuf.or(l.rcvbuf);
                entry.spec.sndbuf = entry.spec.sndbuf.or(l.sndbuf);

                if l.default_server {
                    if entry.default.is_some() {
                        return Err(BuildError {
                            msg: format!("a duplicate default server for {}", l.addr),
                            loc: format!("server at line {}", s.raw_line),
                        });
                    }
                    entry.default = Some(entry.servers.len());
                }
                entry.servers.push(s.clone());
            }
        }

        Ok(by_addr
            .into_iter()
            .map(|(addr, acc)| {
                Arc::new(Listener {
                    addr,
                    backlog: acc.spec.backlog.unwrap_or(511),
                    reuseport: acc.spec.reuseport,
                    ssl: acc.spec.ssl,
                    http2: acc.spec.http2,
                    ipv6_only: acc.spec.ipv6_only,
                    deferred: acc.spec.deferred,
                    rcvbuf: acc.spec.rcvbuf,
                    sndbuf: acc.spec.sndbuf,
                    default_server: acc.default.unwrap_or(0),
                    servers: acc.servers,
                })
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // location { }
    // -----------------------------------------------------------------------

    fn loc_set(&mut self, dirs: &[Directive], parent: &CoreConf) -> R<LocSet> {
        let mut set = LocSet::default();
        for d in dirs {
            let l = Arc::new(self.location(d, parent)?);
            match &l.matcher {
                LocMatch::Exact(_) => set.exact.push(l),
                LocMatch::Prefix(_) | LocMatch::PrefixNoRegex(_) => set.prefix.push(l),
                LocMatch::Regex { .. } => set.regex.push(l),
                LocMatch::Named(n) => {
                    set.named.insert(n.clone(), l);
                }
            }
        }
        set.exact
            .sort_by(|a, b| a.matcher.prefix().unwrap_or("").cmp(b.matcher.prefix().unwrap_or("")));
        // Longest-first, so the first prefix that matches is the longest match.
        set.prefix
            .sort_by_key(|l| std::cmp::Reverse(l.matcher.prefix().unwrap_or("").len()));
        Ok(set)
    }

    fn location(&mut self, d: &Directive, parent: &CoreConf) -> R<Location> {
        want_args_range(d, 1, 2)?;
        let matcher = match (d.arg(0).unwrap(), d.arg(1)) {
            ("=", Some(p)) => LocMatch::Exact(p.into()),
            ("^~", Some(p)) => LocMatch::PrefixNoRegex(p.into()),
            ("~", Some(p)) => LocMatch::Regex { re: compile_regex(p, false, d)?, ci: false },
            ("~*", Some(p)) => LocMatch::Regex { re: compile_regex(p, true, d)?, ci: true },
            (p, None) if p.starts_with('@') => LocMatch::Named(p[1..].into()),
            (p, None) => LocMatch::Prefix(p.into()),
            (m, _) => bail!(d, "invalid location modifier \"{m}\""),
        };

        let mut level = Level::default();
        for c in d.children() {
            match c.name.as_str() {
                "location" => level.locations.push(c.clone()),
                _ => {
                    if !self.level_directive(&mut level, c, Scope::Location)? {
                        self.note_unsupported(c);
                    }
                }
            }
        }

        let core = level.core.resolve(parent);
        let nested = if level.locations.is_empty() {
            None
        } else {
            Some(Box::new(self.loc_set(&level.locations, &core)?))
        };

        Ok(Location {
            matcher,
            core,
            action: level.action.unwrap_or(Action::Static),
            try_files: level.try_files,
            rewrites: level.rewrites,
            ifs: level.ifs,
            error_pages: level.error_pages.unwrap_or_default(),
            access_logs: level.access_logs.unwrap_or_default(),
            nested,
            allowed_methods: level.allowed_methods,
            raw_line: d.line,
        })
    }

    // -----------------------------------------------------------------------
    // Directives valid at more than one level
    // -----------------------------------------------------------------------

    /// Returns `Ok(false)` when the directive is not one we handle, so the
    /// caller can record it as unknown.
    fn level_directive(&mut self, lv: &mut Level, d: &Directive, scope: Scope) -> R<bool> {
        let c = &mut lv.core;
        match d.name.as_str() {
            "root" => {
                want_args(d, 1)?;
                c.root = Some(Arc::new(Template::compile(d.args[0].trim_end_matches('/'))));
            }
            "alias" => {
                if scope != Scope::Location {
                    bail!(d, "\"alias\" directive is only allowed inside location");
                }
                want_args(d, 1)?;
                c.alias = Some(Arc::new(Template::compile(&d.args[0])));
            }
            "index" => {
                want_args_range(d, 1, 32)?;
                c.index = Some(d.args.iter().map(|a| Template::compile(a)).collect());
            }
            "autoindex" => c.autoindex = Some(flag(d)?),
            "default_type" => {
                want_args(d, 1)?;
                c.default_type = Some(Arc::from(d.args[0].as_str()));
            }
            "charset" => {
                want_args(d, 1)?;
                c.charset = if d.args[0] == "off" {
                    None
                } else {
                    Some(Arc::from(d.args[0].as_str()))
                };
            }
            "sendfile" => c.sendfile = Some(flag(d)?),
            "tcp_nopush" => c.tcp_nopush = Some(flag(d)?),
            "tcp_nodelay" => c.tcp_nodelay = Some(flag(d)?),
            "etag" => c.etag = Some(flag(d)?),
            "keepalive_timeout" => {
                want_args_range(d, 1, 2)?;
                c.keepalive_timeout = Some(time_arg(d, 0)?);
            }
            "keepalive_requests" => {
                want_args(d, 1)?;
                c.keepalive_requests = d.args[0].parse().ok();
            }
            "client_header_timeout" => c.client_header_timeout = Some(time_arg(d, 0)?),
            "client_body_timeout" => c.client_body_timeout = Some(time_arg(d, 0)?),
            "send_timeout" => c.send_timeout = Some(time_arg(d, 0)?),
            "client_max_body_size" => c.client_max_body_size = Some(size_arg(d, 0)?),
            "client_header_buffer_size" => {
                c.client_header_buffer_size = Some(size_arg(d, 0)? as usize)
            }
            "large_client_header_buffers" => {
                want_args(d, 2)?;
                let n = d.args[0].parse().unwrap_or(4);
                c.large_client_header_buffers = Some((n, size_arg(d, 1)? as usize));
            }
            "server_tokens" => {
                want_args(d, 1)?;
                c.server_tokens = Some(match d.args[0].as_str() {
                    "on" => ServerTokens::On,
                    "off" => ServerTokens::Off,
                    "build" => ServerTokens::Build,
                    v => bail!(d, "invalid value \"{v}\" in \"server_tokens\""),
                });
            }
            "log_not_found" => c.log_not_found = Some(flag(d)?),
            "absolute_redirect" => c.absolute_redirect = Some(flag(d)?),
            "port_in_redirect" => c.port_in_redirect = Some(flag(d)?),
            "server_name_in_redirect" => c.server_name_in_redirect = Some(flag(d)?),
            "if_modified_since" => {
                want_args(d, 1)?;
                c.if_modified_since = Some(match d.args[0].as_str() {
                    "off" => IfModifiedSince::Off,
                    "exact" => IfModifiedSince::Exact,
                    "before" => IfModifiedSince::Before,
                    v => bail!(d, "invalid value \"{v}\" in \"if_modified_since\""),
                });
            }
            "max_ranges" => {
                want_args(d, 1)?;
                c.max_ranges = d.args[0].parse().ok();
            }
            "limit_rate" => c.limit_rate = Some(size_arg(d, 0)?),
            "limit_rate_after" => c.limit_rate_after = Some(size_arg(d, 0)?),
            "internal" => c.internal = Some(true),
            "output_buffers" => {
                want_args(d, 2)?;
                c.output_buffers = Some((d.args[0].parse().unwrap_or(2), size_arg(d, 1)? as usize));
            }
            "gzip" => c.gzip = Some(flag(d)?),
            "gzip_comp_level" => {
                want_args(d, 1)?;
                c.gzip_level = d.args[0].parse().ok();
            }
            "gzip_min_length" => c.gzip_min_length = Some(size_arg(d, 0)?),
            "gzip_types" => {
                c.gzip_types = Some(d.args.iter().map(|a| a.as_str().into()).collect());
            }
            "gzip_vary" => c.gzip_vary = Some(flag(d)?),
            "gzip_proxied" => {
                c.gzip_proxied_any = Some(d.args.iter().any(|a| a == "any"));
            }
            "gzip_http_version" | "gzip_buffers" | "gzip_disable" | "gzip_static" => {}
            "expires" => {
                want_args_range(d, 1, 2)?;
                let a = d.args.last().unwrap();
                c.expires = Some(match a.as_str() {
                    "off" => Expires::Off,
                    "epoch" => Expires::Epoch,
                    "max" => Expires::Max,
                    v => {
                        if let Some(t) = v.strip_prefix('@') {
                            Expires::Daily(
                                parse_time(t).map(|d| d.as_secs() as i64).ok_or_else(|| {
                                    BuildError { msg: format!("invalid expires \"{v}\""), loc: d.loc() }
                                })?,
                            )
                        } else {
                            let (neg, rest) = match v.strip_prefix('-') {
                                Some(r) => (true, r),
                                None => (false, v),
                            };
                            let secs = parse_time(rest)
                                .map(|d| d.as_secs() as i64)
                                .ok_or_else(|| BuildError {
                                    msg: format!("invalid expires \"{v}\""),
                                    loc: d.loc(),
                                })?;
                            Expires::Secs(if neg { -secs } else { secs })
                        }
                    }
                });
            }
            "add_header" => {
                want_args_range(d, 2, 3)?;
                let h = AddHeader {
                    name: Arc::from(d.args[0].as_str()),
                    value: Arc::new(Template::compile(&d.args[1])),
                    always: d.arg(2) == Some("always"),
                };
                c.add_headers.get_or_insert_with(Vec::new).push(h);
            }
            "access_log" => {
                want_args_range(d, 1, 8)?;
                let logs = lv.access_logs.get_or_insert_with(Vec::new);
                if d.args[0] == "off" {
                    logs.clear();
                    return Ok(true);
                }
                let fmt_name = d.arg(1).unwrap_or("combined");
                let format = self.log_formats.get(fmt_name).cloned().ok_or_else(|| BuildError {
                    msg: format!("unknown log format \"{fmt_name}\""),
                    loc: d.loc(),
                })?;
                let mut buffer = 0;
                let mut flush = None;
                for p in d.args.iter().skip(2) {
                    if let Some(v) = p.strip_prefix("buffer=") {
                        buffer = parse_size(v).unwrap_or(0) as usize;
                    } else if let Some(v) = p.strip_prefix("flush=") {
                        flush = parse_time(v);
                    }
                }
                logs.push(AccessLogConf { path: self.abs(&d.args[0]), format, buffer, flush });
            }
            "error_page" => {
                want_args_range(d, 2, 32)?;
                let target_s = d.args.last().unwrap();
                let mut codes = Vec::new();
                let mut replace = None;
                for a in &d.args[..d.args.len() - 1] {
                    if let Some(r) = a.strip_prefix('=') {
                        replace = if r.is_empty() { Some(0) } else { r.parse().ok() };
                    } else {
                        match a.parse::<u16>() {
                            Ok(n) => codes.push(n),
                            Err(_) => bail!(d, "invalid value \"{a}\" in \"error_page\""),
                        }
                    }
                }
                let target = if let Some(n) = target_s.strip_prefix('@') {
                    ErrorTarget::Named(Arc::from(n))
                } else if target_s.starts_with("http://") || target_s.starts_with("https://") {
                    ErrorTarget::Redirect(Arc::new(Template::compile(target_s)))
                } else {
                    ErrorTarget::Uri(Arc::new(Template::compile(target_s)))
                };
                lv.error_pages
                    .get_or_insert_with(Vec::new)
                    .push(ErrorPage { codes, replace_status: replace, target });
            }
            "return" => {
                want_args_range(d, 1, 2)?;
                lv.action = Some(parse_return(d)?);
            }
            "rewrite" => lv.rewrites.push(self.rewrite(d)?),
            "if" => lv.ifs.push(self.if_block(d)?),
            "set" => {
                want_args(d, 2)?;
                // A bare `set` outside an `if` still needs to run per request;
                // model it as a single-action always-true if-block.
                let var = d.args[0].strip_prefix('$').ok_or_else(|| BuildError {
                    msg: format!("invalid variable name \"{}\"", d.args[0]),
                    loc: d.loc(),
                })?;
                lv.ifs.push(IfBlock {
                    cond: Cond::Always,
                    actions: vec![IfAction::Set {
                        var: Arc::from(var),
                        value: Arc::new(Template::compile(&d.args[1])),
                    }],
                });
            }
            "try_files" => {
                want_args_range(d, 2, 32)?;
                let last = d.args.last().unwrap();
                let fallback = if let Some(s) = last.strip_prefix('=') {
                    TryFallback::Status(s.parse().map_err(|_| BuildError {
                        msg: format!("invalid code \"{last}\" in \"try_files\""),
                        loc: d.loc(),
                    })?)
                } else if let Some(n) = last.strip_prefix('@') {
                    TryFallback::Named(Arc::from(n))
                } else {
                    TryFallback::Uri(Arc::new(Template::compile(last)))
                };
                lv.try_files = Some(TryFiles {
                    items: d.args[..d.args.len() - 1]
                        .iter()
                        .map(|a| Arc::new(Template::compile(a)))
                        .collect(),
                    fallback,
                });
            }
            "limit_except" => {
                want_args_range(d, 1, 16)?;
                lv.allowed_methods = Some(d.args.iter().map(|m| m.to_ascii_uppercase().into_boxed_str()).collect());
            }
            "proxy_pass" => {
                want_args(d, 1)?;
                lv.action = Some(Action::Proxy(Arc::new(parse_proxy_pass(&d.args[0], d)?)));
            }
            "proxy_set_header" => {
                want_args(d, 2)?;
                c.proxy_set_headers.get_or_insert_with(Vec::new).push((
                    Arc::from(d.args[0].as_str()),
                    Arc::new(Template::compile(&d.args[1])),
                ));
            }
            "proxy_hide_header" => {
                want_args(d, 1)?;
                c.proxy_hide_headers
                    .get_or_insert_with(Vec::new)
                    .push(d.args[0].to_ascii_lowercase().into_boxed_str());
            }
            "proxy_connect_timeout" => c.proxy_connect_timeout = Some(time_arg(d, 0)?),
            "proxy_read_timeout" => c.proxy_read_timeout = Some(time_arg(d, 0)?),
            "proxy_send_timeout" => c.proxy_send_timeout = Some(time_arg(d, 0)?),
            "proxy_buffering" => c.proxy_buffering = Some(flag(d)?),
            "proxy_ssl_server_name" => c.proxy_ssl_server_name = Some(flag(d)?),
            "proxy_http_version" => {
                want_args(d, 1)?;
                c.proxy_http_11 = Some(d.args[0] == "1.1");
            }
            "proxy_redirect" | "proxy_buffers" | "proxy_buffer_size" | "proxy_next_upstream"
            | "proxy_busy_buffers_size" | "proxy_temp_file_write_size" | "proxy_intercept_errors"
            | "proxy_request_buffering" | "proxy_max_temp_file_size" | "proxy_ignore_headers" => {}
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn rewrite(&mut self, d: &Directive) -> R<Rewrite> {
        want_args_range(d, 2, 3)?;
        let flag = match d.arg(2) {
            None => RewriteFlag::None,
            Some("last") => RewriteFlag::Last,
            Some("break") => RewriteFlag::Break,
            Some("redirect") => RewriteFlag::Redirect,
            Some("permanent") => RewriteFlag::Permanent,
            Some(f) => bail!(d, "invalid flag \"{f}\" in \"rewrite\" directive"),
        };
        Ok(Rewrite {
            re: compile_regex(&d.args[0], false, d)?,
            replacement: Arc::new(Template::compile(&d.args[1])),
            flag,
        })
    }

    fn if_block(&mut self, d: &Directive) -> R<IfBlock> {
        // The lexer hands us `($a`, `=`, `b)` — nginx parses `if` the same way,
        // by stripping the parens off the first and last argument.
        if d.args.is_empty() {
            bail!(d, "invalid condition in \"if\" directive");
        }
        let mut parts: Vec<String> = d.args.clone();
        let first = parts[0].strip_prefix('(').map(str::to_string);
        if let Some(f) = first {
            parts[0] = f;
        } else {
            bail!(d, "invalid condition in \"if\": expected \"(\"");
        }
        let lastidx = parts.len() - 1;
        match parts[lastidx].strip_suffix(')') {
            Some(l) => parts[lastidx] = l.to_string(),
            None => bail!(d, "invalid condition in \"if\": expected \")\""),
        }
        parts.retain(|p| !p.is_empty());

        let cond = self.cond(&parts, d)?;

        let mut actions = Vec::new();
        for c in d.children() {
            match c.name.as_str() {
                "return" => match parse_return(c)? {
                    Action::Return { status, body } => actions.push(IfAction::Return { status, body }),
                    _ => unreachable!(),
                },
                "rewrite" => actions.push(IfAction::Rewrite(self.rewrite(c)?)),
                "set" => {
                    want_args(c, 2)?;
                    let var = c.args[0].strip_prefix('$').ok_or_else(|| BuildError {
                        msg: format!("invalid variable name \"{}\"", c.args[0]),
                        loc: c.loc(),
                    })?;
                    actions.push(IfAction::Set {
                        var: Arc::from(var),
                        value: Arc::new(Template::compile(&c.args[1])),
                    });
                }
                "add_header" => {
                    want_args_range(c, 2, 3)?;
                    actions.push(IfAction::AddHeader(AddHeader {
                        name: Arc::from(c.args[0].as_str()),
                        value: Arc::new(Template::compile(&c.args[1])),
                        always: c.arg(2) == Some("always"),
                    }));
                }
                "break" => actions.push(IfAction::Break),
                other => bail!(c, "\"{other}\" is not allowed inside \"if\" in OxiServe"),
            }
        }
        Ok(IfBlock { cond, actions })
    }

    fn cond(&mut self, parts: &[String], d: &Directive) -> R<Cond> {
        let var_of = |s: &str| -> R<Var> {
            s.strip_prefix('$').map(Var::parse).ok_or_else(|| BuildError {
                msg: format!("invalid condition operand \"{s}\", expected a variable"),
                loc: d.loc(),
            })
        };

        match parts.len() {
            1 => {
                let p = &parts[0];
                // File tests take the form `-f /path` but the lexer may hand
                // them to us joined when quoted.
                Ok(Cond::Truthy(var_of(p)?))
            }
            2 => {
                let (op, arg) = (parts[0].as_str(), parts[1].as_str());
                let t = Arc::new(Template::compile(arg));
                Ok(match op {
                    "-f" => Cond::FileExists { t, negate: false },
                    "!-f" => Cond::FileExists { t, negate: true },
                    "-d" => Cond::DirExists { t, negate: false },
                    "!-d" => Cond::DirExists { t, negate: true },
                    "-e" => Cond::AnyExists { t, negate: false },
                    "!-e" => Cond::AnyExists { t, negate: true },
                    "-x" => Cond::Executable { t, negate: false },
                    "!-x" => Cond::Executable { t, negate: true },
                    _ => bail!(d, "invalid condition operator \"{op}\""),
                })
            }
            3 => {
                let (lhs, op, rhs) = (parts[0].as_str(), parts[1].as_str(), parts[2].as_str());
                let v = var_of(lhs)?;
                Ok(match op {
                    "=" => Cond::Eq(v, Arc::new(Template::compile(rhs))),
                    "!=" => Cond::Ne(v, Arc::new(Template::compile(rhs))),
                    "~" => Cond::Match { var: v, re: compile_regex(rhs, false, d)?, negate: false },
                    "~*" => Cond::Match { var: v, re: compile_regex(rhs, true, d)?, negate: false },
                    "!~" => Cond::Match { var: v, re: compile_regex(rhs, false, d)?, negate: true },
                    "!~*" => Cond::Match { var: v, re: compile_regex(rhs, true, d)?, negate: true },
                    _ => bail!(d, "invalid condition operator \"{op}\""),
                })
            }
            _ => bail!(d, "invalid condition in \"if\" directive"),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Scope {
    Http,
    Server,
    Location,
}

fn parse_return(d: &Directive) -> R<Action> {
    let first = &d.args[0];
    // `return https://x/` (no code) means 302.
    if first.starts_with("http://") || first.starts_with("https://") || first.starts_with('/') {
        if d.args.len() > 1 {
            bail!(d, "invalid arguments in \"return\" directive");
        }
        return Ok(Action::Return {
            status: 302,
            body: Some(Arc::new(Template::compile(first))),
        });
    }
    let status: u16 = first.parse().map_err(|_| BuildError {
        msg: format!("invalid return code \"{first}\""),
        loc: d.loc(),
    })?;
    Ok(Action::Return {
        status,
        body: d.arg(1).map(|b| Arc::new(Template::compile(b))),
    })
}

fn parse_proxy_pass(s: &str, d: &Directive) -> R<ProxyPass> {
    if s.contains('$') && !s.starts_with("http://") && !s.starts_with("https://") {
        return Ok(ProxyPass {
            target: ProxyTarget::Dynamic(Arc::new(Template::compile(s))),
            uri: None,
            tls: false,
        });
    }
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        bail!(d, "invalid URL prefix in \"proxy_pass\" — expected http:// or https://");
    };

    let (authority, uri) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    if authority.is_empty() {
        bail!(d, "no host in \"proxy_pass\"");
    }

    // A bare name with no port and no dots is an upstream reference. Anything
    // with a port, an IP, or a dotted hostname is a literal address.
    let target = if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(port) => ProxyTarget::Addr { host: Arc::from(h), port },
            Err(_) => ProxyTarget::Upstream(Arc::from(authority)),
        }
    } else if authority.contains('.') || authority.parse::<IpAddr>().is_ok() {
        ProxyTarget::Addr {
            host: Arc::from(authority),
            port: if tls { 443 } else { 80 },
        }
    } else {
        ProxyTarget::Upstream(Arc::from(authority))
    };

    Ok(ProxyPass {
        target,
        uri: uri.map(|u| Arc::new(Template::compile(u))),
        tls,
    })
}

/// `80`, `*:80`, `1.2.3.4:80`, `[::]:80`, `localhost:8080`.
fn parse_listen_addr(s: &str) -> Option<SocketAddr> {
    if let Ok(port) = s.parse::<u16>() {
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    if let Some(rest) = s.strip_prefix("*:") {
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), rest.parse().ok()?));
    }
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if s.starts_with('[') {
        // `[::]` with no port
        let end = s.find(']')?;
        let ip: Ipv6Addr = s[1..end].parse().ok()?;
        let port = s[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(80);
        return Some(SocketAddr::new(IpAddr::V6(ip), port));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 80));
    }
    // `hostname:port` — resolve now, as nginx does at config load.
    let (h, p) = s.rsplit_once(':')?;
    let port: u16 = p.parse().ok()?;
    std::net::ToSocketAddrs::to_socket_addrs(&(h, port)).ok()?.next()
}

pub const COMBINED_FORMAT: &str = concat!(
    r#"$remote_addr - $remote_user [$time_local] "$request" "#,
    r#"$status $body_bytes_sent "$http_referer" "$http_user_agent""#
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ast;

    /// Tests run in parallel within one process, so the scratch file must be
    /// unique per config — a shared path let one test read another's config.
    fn build(src: &str) -> R<Config> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        src.hash(&mut h);
        let dir = std::env::temp_dir().join(format!(
            "oxiserve-test-{}-{:016x}",
            std::process::id(),
            h.finish()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("test.conf");
        std::fs::write(&f, src).unwrap();
        let tree = ast::parse_file(&f).expect("parse");
        Builder::new(dir).build(&tree)
    }

    const MIN: &str = "events {} http { server { listen 80; ";

    #[test]
    fn sizes_and_times() {
        assert_eq!(parse_size("10"), Some(10));
        assert_eq!(parse_size("10k"), Some(10240));
        assert_eq!(parse_size("2m"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("1g"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("abc"), None);

        assert_eq!(parse_time("60"), Some(Duration::from_secs(60)));
        assert_eq!(parse_time("60s"), Some(Duration::from_secs(60)));
        assert_eq!(parse_time("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_time("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_time("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_time("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_time("x"), None);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(parse_listen_addr("80").unwrap().to_string(), "0.0.0.0:80");
        assert_eq!(parse_listen_addr("*:8080").unwrap().to_string(), "0.0.0.0:8080");
        assert_eq!(parse_listen_addr("127.0.0.1:81").unwrap().to_string(), "127.0.0.1:81");
        assert_eq!(parse_listen_addr("[::]:80").unwrap().to_string(), "[::]:80");
        assert_eq!(parse_listen_addr("[::1]:443").unwrap().to_string(), "[::1]:443");
    }

    #[test]
    fn scalar_directives_inherit_downward() {
        let c = build("events {} http { sendfile on; root /srv; server { listen 80; location /a { } } }").unwrap();
        let http = c.http.unwrap();
        let loc = &http.servers[0].locations.prefix[0];
        assert!(loc.core.sendfile);
        assert_eq!(loc.core.root.as_literal(), Some("/srv"));
    }

    #[test]
    fn server_level_overrides_http_level() {
        let c = build("events {} http { root /a; server { listen 80; root /b; location /x { root /c; } } }").unwrap();
        let http = c.http.unwrap();
        assert_eq!(http.servers[0].core.root.as_literal(), Some("/b"));
        assert_eq!(http.servers[0].locations.prefix[0].core.root.as_literal(), Some("/c"));
    }

    #[test]
    fn add_header_replaces_rather_than_appends() {
        // nginx: a level with any add_header discards all inherited ones.
        let c = build(
            "events {} http { add_header X-A a; server { listen 80; \
             location /keep { } location /drop { add_header X-B b; } } }",
        )
        .unwrap();
        let http = c.http.unwrap();
        let locs = &http.servers[0].locations.prefix;
        let keep = locs.iter().find(|l| l.matcher.prefix() == Some("/keep")).unwrap();
        let drop = locs.iter().find(|l| l.matcher.prefix() == Some("/drop")).unwrap();
        assert_eq!(keep.core.add_headers.len(), 1);
        assert_eq!(&*keep.core.add_headers[0].name, "X-A");
        assert_eq!(drop.core.add_headers.len(), 1);
        assert_eq!(&*drop.core.add_headers[0].name, "X-B");
    }

    #[test]
    fn alias_clears_inherited_root() {
        let c = build("events {} http { root /a; server { listen 80; location /x { alias /b/; } } }").unwrap();
        let http = c.http.unwrap();
        let l = &http.servers[0].locations.prefix[0];
        assert!(l.core.alias.is_some());
    }

    #[test]
    fn listeners_group_by_address() {
        let c = build(
            "events {} http { \
             server { listen 80; server_name a.com; } \
             server { listen 80; server_name b.com; } \
             server { listen 8080; server_name c.com; } }",
        )
        .unwrap();
        let http = c.http.unwrap();
        assert_eq!(http.listeners.len(), 2);
        let p80 = http.listeners.iter().find(|l| l.addr.port() == 80).unwrap();
        assert_eq!(p80.servers.len(), 2);
    }

    #[test]
    fn duplicate_default_server_is_rejected() {
        let e = build(
            "events {} http { server { listen 80 default_server; } server { listen 80 default_server; } }",
        )
        .unwrap_err();
        assert!(e.msg.contains("duplicate default server"), "{}", e.msg);
    }

    #[test]
    fn return_and_proxy_pass_actions() {
        let c = build(&format!(
            "{MIN} location /r {{ return 301 https://x/; }} location /p {{ proxy_pass http://127.0.0.1:9000/api; }} }} }}"
        ))
        .unwrap();
        let http = c.http.unwrap();
        let locs = &http.servers[0].locations.prefix;
        let r = locs.iter().find(|l| l.matcher.prefix() == Some("/r")).unwrap();
        assert!(matches!(r.action, Action::Return { status: 301, .. }));
        let p = locs.iter().find(|l| l.matcher.prefix() == Some("/p")).unwrap();
        match &p.action {
            Action::Proxy(pp) => {
                assert!(matches!(&pp.target, ProxyTarget::Addr { port: 9000, .. }));
                assert_eq!(pp.uri.as_ref().unwrap().as_literal(), Some("/api"));
            }
            _ => panic!("expected proxy"),
        }
    }

    #[test]
    fn proxy_pass_bare_name_is_an_upstream() {
        let c = build(
            "events {} http { upstream backend { server 127.0.0.1:9000; } \
             server { listen 80; location / { proxy_pass http://backend; } } }",
        )
        .unwrap();
        let http = c.http.unwrap();
        match &http.servers[0].locations.prefix[0].action {
            Action::Proxy(p) => assert!(matches!(&p.target, ProxyTarget::Upstream(n) if &**n == "backend")),
            _ => panic!("expected proxy"),
        }
        assert!(http.upstreams.contains_key("backend"));
    }

    #[test]
    fn try_files_fallbacks() {
        let c = build(&format!("{MIN} location / {{ try_files $uri $uri/ =404; }} }} }}")).unwrap();
        let http = c.http.unwrap();
        let tf = http.servers[0].locations.prefix[0].try_files.as_ref().unwrap();
        assert_eq!(tf.items.len(), 2);
        assert!(matches!(tf.fallback, TryFallback::Status(404)));
    }

    #[test]
    fn nested_locations_build() {
        let c = build(&format!("{MIN} location /a {{ location /a/b {{ return 204; }} }} }} }}")).unwrap();
        let http = c.http.unwrap();
        let outer = &http.servers[0].locations.prefix[0];
        assert!(outer.nested.is_some());
        assert_eq!(outer.nested.as_ref().unwrap().prefix.len(), 1);
    }

    #[test]
    fn if_conditions_parse() {
        let c = build(&format!(
            "{MIN} if ($http_user_agent ~* bot) {{ return 403; }} if (!-f $request_filename) {{ return 404; }} }} }}"
        ))
        .unwrap();
        let http = c.http.unwrap();
        let ifs = &http.servers[0].ifs;
        assert_eq!(ifs.len(), 2);
        assert!(matches!(ifs[0].cond, Cond::Match { negate: false, .. }));
        assert!(matches!(ifs[1].cond, Cond::FileExists { negate: true, .. }));
    }

    #[test]
    fn unknown_directive_is_reported_not_fatal() {
        let c = build(&format!("{MIN} frobnicate on; }} }}")).unwrap();
        assert!(c.unsupported.iter().any(|u| u.contains("unknown directive \"frobnicate\"")), "{:?}", c.unsupported);
    }

    #[test]
    fn known_unimplemented_gets_a_clearer_message() {
        let c = build(&format!("{MIN} location / {{ fastcgi_pass 127.0.0.1:9000; }} }} }}")).unwrap();
        assert!(
            c.unsupported.iter().any(|u| u.contains("not implemented yet") && u.contains("fastcgi_pass")),
            "{:?}",
            c.unsupported
        );
    }

    #[test]
    fn bad_regex_gives_a_useful_error() {
        let e = build(&format!("{MIN} location ~ \"(?=foo)\" {{ }} }} }}")).unwrap_err();
        assert!(e.msg.contains("lookahead"), "{}", e.msg);
    }

    #[test]
    fn missing_ssl_certificate_is_rejected() {
        let e = build("events {} http { server { listen 443 ssl; } }").unwrap_err();
        assert!(e.msg.contains("ssl_certificate"), "{}", e.msg);
    }
}

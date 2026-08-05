//! Per-request context and nginx variable resolution.
//!
//! One [`Ctx`] exists per request. It owns the *mutable* view of the request —
//! the URI and args, which `rewrite` and internal redirects change — while
//! borrowing the immutable parts (the read buffer, the parsed request, the
//! matched server) from the connection.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::config::model::{Http, MapConf, ServerConf};
use crate::config::vars::{Var, VarSource};
use crate::http::date;
use crate::http::request::{Hot, Req};
use crate::http::response::{push_num, Resp};

pub struct Ctx<'a> {
    /// The connection read buffer that `req`'s ranges point into.
    pub buf: &'a [u8],
    pub req: &'a Req,
    /// The decoded request body, already de-chunked by the connection layer.
    pub body: &'a [u8],
    pub http: &'a Http,
    pub server: &'a Arc<ServerConf>,

    /// Normalised request path. Mutated by `rewrite` and internal redirects.
    pub uri: String,
    /// Query string, without the `?`. `rewrite ... ?` can replace it.
    pub args: String,

    /// `$1` … `$9` from the most recent regex match.
    pub captures: Vec<String>,
    /// Variables assigned by `set`.
    pub set_vars: Vec<(Arc<str>, String)>,

    /// `None` for a Unix-socket client, which has no address at all.
    pub remote: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
    pub scheme: &'static str,
    pub start: Instant,
    /// Requests already served on this connection, for `$connection_requests`.
    pub conn_id: u64,
    pub conn_requests: u64,

    /// `$document_root` — the root of the matched location.
    pub document_root: String,
    /// `$request_filename` — the path the file handler resolved.
    pub filename: String,

    /// Filled in by the FastCGI handler before any parameter is rendered.
    pub fastcgi_script_name: String,
    pub fastcgi_path_info: String,

    pub upstream_addr: String,
    pub upstream_status: u16,
    pub upstream_time: f64,

    /// How many internal redirects have happened, to break `try_files` loops.
    pub redirects: u32,
    /// The location `route` selected, cached so response decoration and
    /// `error_page` lookup do not each repeat the location search.
    pub matched: Option<Arc<crate::config::model::Location>>,
}

impl<'a> Ctx<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        buf: &'a [u8],
        req: &'a Req,
        body: &'a [u8],
        http: &'a Http,
        server: &'a Arc<ServerConf>,
        uri: String,
        remote: Option<SocketAddr>,
        local: Option<SocketAddr>,
        scheme: &'static str,
        conn_id: u64,
        conn_requests: u64,
    ) -> Ctx<'a> {
        let args = req.query_str(buf).to_string();
        Ctx {
            buf,
            req,
            body,
            http,
            server,
            uri,
            args,
            captures: Vec::new(),
            set_vars: Vec::new(),
            remote,
            local,
            scheme,
            start: Instant::now(),
            conn_id,
            conn_requests,
            document_root: String::new(),
            filename: String::new(),
            fastcgi_script_name: String::new(),
            fastcgi_path_info: String::new(),
            upstream_addr: String::new(),
            upstream_status: 0,
            upstream_time: 0.0,
            redirects: 0,
            matched: None,
        }
    }

    pub fn set(&mut self, name: &Arc<str>, value: String) {
        match self.set_vars.iter_mut().find(|(n, _)| n == name) {
            Some((_, v)) => *v = value,
            None => self.set_vars.push((name.clone(), value)),
        }
    }

    pub fn set_captures(&mut self, c: &regex::Captures<'_>) {
        self.captures.clear();
        for i in 1..c.len() {
            self.captures
                .push(c.get(i).map(|m| m.as_str()).unwrap_or("").to_string());
        }
    }

    /// Resolves a `map`-defined or `set`-defined variable.
    fn user_var(&self, name: &str, out: &mut String, depth: u32) {
        if depth > 8 {
            return; // a map cycle; nginx caps recursion the same way
        }
        if let Some((_, v)) = self.set_vars.iter().find(|(n, _)| &**n == name) {
            out.push_str(v);
            return;
        }
        let Some(m) = self.http.maps.iter().find(|m| &*m.target == name) else {
            return;
        };
        let mut key = String::new();
        self.var_depth(&m.source, &mut key, depth + 1);
        if let Some(t) = map_lookup(m, &key) {
            t.render_into(&DepthSource { ctx: self, depth: depth + 1 }, out);
        }
    }

    fn var_depth(&self, v: &Var, out: &mut String, depth: u32) {
        let b = self.buf;
        let r = self.req;
        match v {
            Var::Uri | Var::DocumentUri => out.push_str(&self.uri),
            Var::RequestUri => out.push_str(r.target_str(b)),
            Var::Args => out.push_str(&self.args),
            Var::IsArgs => {
                if !self.args.is_empty() {
                    out.push('?');
                }
            }
            Var::Arg(name) => {
                if let Some(v) = crate::http::uri::query_param(&self.args, name) {
                    out.push_str(v);
                }
            }
            Var::Host => {
                let h = r.host(b);
                if h.is_empty() {
                    // nginx falls back to the matched server_name.
                    out.push_str(&first_server_name(self.server));
                } else {
                    push_lower(out, h);
                }
            }
            Var::Hostname => out.push_str(hostname()),
            Var::Scheme => out.push_str(self.scheme),
            Var::RequestMethod => out.push_str(r.slice(b, &r.method_raw)),
            Var::Request => {
                out.push_str(r.slice(b, &r.method_raw));
                out.push(' ');
                out.push_str(r.target_str(b));
                out.push_str(if r.minor == 0 { " HTTP/1.0" } else { " HTTP/1.1" });
            }
            Var::ServerProtocol => out.push_str(if r.minor == 0 { "HTTP/1.0" } else { "HTTP/1.1" }),
            Var::ServerName => out.push_str(&first_server_name(self.server)),
            Var::ServerPort => push_num(out, self.local.map(|a| a.port()).unwrap_or(0) as u64),
            Var::ServerAddr => push_addr(out, &self.local),
            Var::RemoteAddr => push_addr(out, &self.remote),
            Var::RemotePort => push_num(out, self.remote.map(|a| a.port()).unwrap_or(0) as u64),
            Var::RemoteUser => {
                // Only the userinfo half of Basic auth, un-decoded users get "".
                if let Some(a) = r.hot_value(b, Hot::Authorization) {
                    if let Some(rest) = a.strip_prefix("Basic ") {
                        if let Some(d) = base64_decode(rest.trim()) {
                            if let Some(i) = d.iter().position(|&c| c == b':') {
                                out.push_str(&String::from_utf8_lossy(&d[..i]));
                            }
                        }
                    }
                }
            }
            Var::RequestLength => push_num(out, r.head_len as u64),
            Var::RequestTime => push_secs(out, self.start.elapsed().as_secs_f64()),
            Var::Msec => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                push_secs(out, now.as_secs_f64());
            }
            Var::TimeLocal => date::append_time_local(out),
            Var::TimeIso8601 => date::append_time_iso8601(out),
            Var::DocumentRoot => {
                // The static handler records the root it resolved. Any other
                // handler (FastCGI, proxy) never touches the filesystem, so
                // fall back to the matched location's `root`/`alias` — nginx
                // makes `$document_root` available regardless of handler, and
                // `SCRIPT_FILENAME $document_root$fastcgi_script_name` is the
                // single most common use of it.
                if !self.document_root.is_empty() {
                    out.push_str(&self.document_root);
                } else {
                    let core = match &self.matched {
                        Some(l) => &l.core,
                        None => &self.server.core,
                    };
                    let t = core.alias.as_ref().unwrap_or(&core.root);
                    t.render_into(&DepthSource { ctx: self, depth: depth + 1 }, out);
                }
            }
            Var::RequestFilename => out.push_str(&self.filename),
            Var::ContentType => {
                if let Some(v) = r.hot_value(b, Hot::ContentType) {
                    out.push_str(v);
                }
            }
            Var::ContentLength => {
                if let Some(v) = r.hot_value(b, Hot::ContentLength) {
                    out.push_str(v);
                }
            }
            Var::Connection => push_num(out, self.conn_id),
            Var::ConnectionRequests => push_num(out, self.conn_requests),
            Var::Pid => push_num(out, std::process::id() as u64),
            Var::NginxVersion => out.push_str(crate::http::response::VERSION),
            Var::Http(name) => {
                if let Some(v) = r.header(b, name) {
                    out.push_str(v);
                }
            }
            Var::Cookie(name) => {
                if let Some(c) = r.hot_value(b, Hot::Cookie) {
                    if let Some(v) = cookie_value(c, name) {
                        out.push_str(v);
                    }
                }
            }
            Var::Capture(i) => {
                if let Some(c) = self.captures.get((*i as usize).wrapping_sub(1)) {
                    out.push_str(c);
                }
            }
            Var::FastcgiScriptName => out.push_str(&self.fastcgi_script_name),
            Var::FastcgiPathInfo => out.push_str(&self.fastcgi_path_info),
            Var::Https => {
                if self.scheme == "https" {
                    out.push_str("on");
                }
            }
            Var::ProxyHost => {
                // Before the upstream is chosen this is empty; proxy.rs fills
                // `upstream_addr` in before rendering any header template.
                out.push_str(&self.upstream_addr);
            }
            Var::ProxyPort => {
                let port = self.upstream_addr.rsplit(':').next().unwrap_or("");
                out.push_str(port);
            }
            Var::ProxyAddXForwardedFor => {
                // Append, never replace: dropping the inbound chain would hide
                // every proxy between the client and us.
                if let Some(existing) = r.header(b, "x-forwarded-for") {
                    out.push_str(existing);
                    out.push_str(", ");
                }
                push_addr(out, &self.remote);
            }
            Var::UpstreamAddr => out.push_str(&self.upstream_addr),
            Var::UpstreamStatus => {
                if self.upstream_status > 0 {
                    push_num(out, self.upstream_status as u64);
                }
            }
            Var::UpstreamResponseTime | Var::UpstreamConnectTime => {
                if self.upstream_status > 0 {
                    push_secs(out, self.upstream_time);
                }
            }
            Var::User(name) => self.user_var(name, out, depth),
            // Resolved only once a response exists; see `LogVars`.
            Var::Status | Var::BodyBytesSent | Var::BytesSent | Var::SentHttp(_) => {}
        }
    }
}

impl VarSource for Ctx<'_> {
    fn var(&self, v: &Var, out: &mut String) {
        self.var_depth(v, out, 0);
    }
}

/// Wraps a [`Ctx`] so nested map lookups carry their recursion depth.
struct DepthSource<'a, 'b> {
    ctx: &'a Ctx<'b>,
    depth: u32,
}

impl VarSource for DepthSource<'_, '_> {
    fn var(&self, v: &Var, out: &mut String) {
        self.ctx.var_depth(v, out, self.depth);
    }
}

/// A [`VarSource`] for access logging, where response-side variables exist.
pub struct LogVars<'a, 'b> {
    pub ctx: &'a Ctx<'b>,
    pub resp: &'a Resp,
    pub status: u16,
    pub body_bytes: u64,
    pub total_bytes: u64,
}

impl VarSource for LogVars<'_, '_> {
    fn var(&self, v: &Var, out: &mut String) {
        match v {
            Var::Status => push_num(out, self.status as u64),
            Var::BodyBytesSent => push_num(out, self.body_bytes),
            Var::BytesSent => push_num(out, self.total_bytes),
            Var::SentHttp(name) => {
                if let Some(v) = self.resp.get(name) {
                    out.push_str(v);
                }
            }
            other => self.ctx.var(other, out),
        }
    }
}

fn map_lookup<'m>(
    m: &'m MapConf,
    key: &str,
) -> Option<&'m Arc<crate::config::vars::Template>> {
    let lowered;
    let k = if m.hostnames || key.bytes().any(|b| b.is_ascii_uppercase()) {
        lowered = key.to_ascii_lowercase();
        lowered.as_str()
    } else {
        key
    };
    if let Some(t) = m.exact.get(k) {
        return Some(t);
    }
    // Longest wildcard wins, matching nginx's hash-based lookup order.
    let mut best: Option<(usize, &Arc<crate::config::vars::Template>)> = None;
    for (pat, t, leading) in &m.wildcards {
        let hit = if *leading {
            k.len() > pat.len() && k.as_bytes()[k.len() - pat.len() - 1] == b'.' && k.ends_with(&**pat)
        } else {
            k.len() > pat.len() && k.as_bytes()[pat.len()] == b'.' && k.starts_with(&**pat)
        };
        if hit && best.map_or(true, |(l, _)| pat.len() > l) {
            best = Some((pat.len(), t));
        }
    }
    if let Some((_, t)) = best {
        return Some(t);
    }
    for (re, t) in &m.regexes {
        if re.is_match(key) {
            return Some(t);
        }
    }
    m.default.as_ref()
}

fn first_server_name(s: &ServerConf) -> String {
    use crate::config::model::ServerName;
    for n in &s.names {
        match n {
            ServerName::Exact(e) if !e.is_empty() => return e.to_string(),
            ServerName::LeadingWildcard(x) => return format!("*.{x}"),
            ServerName::TrailingWildcard(x) => return format!("{x}.*"),
            _ => {}
        }
    }
    String::new()
}

fn hostname() -> &'static str {
    use std::sync::OnceLock;
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        let mut buf = [0u8; 256];
        // SAFETY: `gethostname` writes at most `len` bytes into our buffer.
        let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ok != 0 {
            return "localhost".to_string();
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).to_string()
    })
}

fn push_lower(out: &mut String, s: &str) {
    for c in s.chars() {
        out.push(c.to_ascii_lowercase());
    }
}

fn push_addr(out: &mut String, a: &Option<SocketAddr>) {
    // nginx reports "unix:" for a peer on a Unix socket.
    let Some(a) = a else {
        out.push_str("unix:");
        return;
    };
    match a {
        SocketAddr::V4(v) => {
            let o = v.ip().octets();
            for (i, b) in o.iter().enumerate() {
                if i > 0 {
                    out.push('.');
                }
                push_num(out, *b as u64);
            }
        }
        SocketAddr::V6(v) => out.push_str(&v.ip().to_string()),
    }
}

/// Formats seconds with nginx's three-decimal precision.
fn push_secs(out: &mut String, s: f64) {
    let ms = (s * 1000.0).round() as u64;
    push_num(out, ms / 1000);
    out.push('.');
    let frac = ms % 1000;
    if frac < 100 {
        out.push('0');
    }
    if frac < 10 {
        out.push('0');
    }
    push_num(out, frac);
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let part = part.trim_start();
        let (k, v) = part.split_once('=')?;
        if k == name {
            return Some(v.trim());
        }
    }
    None
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const INV: u8 = 255;
    let mut table = [INV; 256];
    let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < alpha.len() {
        table[alpha[i] as usize] = i as u8;
        i += 1;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = table[c as usize];
        if v == INV {
            return None;
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_get_three_decimals() {
        let mut s = String::new();
        push_secs(&mut s, 1.5);
        assert_eq!(s, "1.500");
        s.clear();
        push_secs(&mut s, 0.001);
        assert_eq!(s, "0.001");
        s.clear();
        push_secs(&mut s, 0.0);
        assert_eq!(s, "0.000");
        s.clear();
        push_secs(&mut s, 12.0345);
        assert_eq!(s, "12.035");
    }

    #[test]
    fn ipv4_formatting_avoids_allocation_path() {
        let mut s = String::new();
        push_addr(&mut s, &Some("192.168.1.10:1234".parse().unwrap()));
        assert_eq!(s, "192.168.1.10");
        s.clear();
        push_addr(&mut s, &None);
        assert_eq!(s, "unix:", "a Unix peer has no address");
    }

    #[test]
    fn cookies_are_split_correctly() {
        let h = "a=1; sessionid=abc123; b=2";
        assert_eq!(cookie_value(h, "sessionid"), Some("abc123"));
        assert_eq!(cookie_value(h, "a"), Some("1"));
        assert_eq!(cookie_value(h, "missing"), None);
    }

    #[test]
    fn basic_auth_base64() {
        // "alice:secret"
        let d = base64_decode("YWxpY2U6c2VjcmV0").unwrap();
        assert_eq!(String::from_utf8(d).unwrap(), "alice:secret");
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn base64_handles_padding() {
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
    }
}

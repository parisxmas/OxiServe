//! nginx variables and the string templates that embed them.
//!
//! Variables show up in `log_format`, `return`, `add_header`, `proxy_pass`,
//! `try_files`, `root`, `set` and more. Rather than re-scanning `$foo` at
//! request time, a template is compiled once at config load into a flat list of
//! literal / variable segments, and evaluated against whatever implements
//! [`VarSource`].

use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Var {
    Uri,
    DocumentUri,
    RequestUri,
    Args,
    IsArgs,
    Arg(Arc<str>),
    Host,
    Hostname,
    Scheme,
    RequestMethod,
    Request,
    ServerProtocol,
    ServerName,
    ServerPort,
    ServerAddr,
    RemoteAddr,
    /// `$binary_remote_addr` — nginx's compact address form, the conventional
    /// `limit_req_zone` key because it is shorter than the text one.
    BinaryRemoteAddr,
    RemotePort,
    RemoteUser,
    Status,
    BodyBytesSent,
    BytesSent,
    RequestLength,
    RequestTime,
    Msec,
    TimeLocal,
    TimeIso8601,
    DocumentRoot,
    RequestFilename,
    ContentType,
    ContentLength,
    Connection,
    ConnectionRequests,
    Pid,
    NginxVersion,
    /// `$http_user_agent` — a request header, name lowercased with `_`→`-`.
    Http(Arc<str>),
    /// `$sent_http_content_type` — a response header.
    SentHttp(Arc<str>),
    /// `$fastcgi_script_name` — the script path after `fastcgi_split_path_info`
    /// and `fastcgi_index` have been applied.
    FastcgiScriptName,
    /// `$fastcgi_path_info` — capture 2 of `fastcgi_split_path_info`.
    FastcgiPathInfo,
    /// `$https` — "on" over TLS, empty otherwise. Used with `if_not_empty`.
    Https,
    /// The `host:port` of the upstream `proxy_pass` chose — nginx's default
    /// value for the forwarded `Host` header.
    ProxyHost,
    /// The port of the chosen upstream.
    ProxyPort,
    /// The client's `X-Forwarded-For` with `$remote_addr` appended.
    ProxyAddXForwardedFor,
    /// `$upstream_addr` and friends.
    UpstreamAddr,
    UpstreamStatus,
    UpstreamResponseTime,
    UpstreamConnectTime,
    /// `$cookie_sessionid`
    Cookie(Arc<str>),
    /// `$1` … `$9`, captured by a regex `location` or `if`.
    Capture(u8),
    /// A `set`-defined or otherwise user-declared variable.
    User(Arc<str>),
}

impl Var {
    /// Maps a variable name (without the `$`) onto a [`Var`].
    pub fn parse(name: &str) -> Var {
        if let Some(rest) = name.strip_prefix("http_") {
            return Var::Http(header_name(rest));
        }
        if let Some(rest) = name.strip_prefix("sent_http_") {
            return Var::SentHttp(header_name(rest));
        }
        if let Some(rest) = name.strip_prefix("arg_") {
            return Var::Arg(Arc::from(rest));
        }
        if let Some(rest) = name.strip_prefix("cookie_") {
            return Var::Cookie(Arc::from(rest));
        }
        match name {
            "uri" => Var::Uri,
            "document_uri" => Var::DocumentUri,
            "request_uri" => Var::RequestUri,
            "args" | "query_string" => Var::Args,
            "is_args" => Var::IsArgs,
            "host" => Var::Host,
            "hostname" => Var::Hostname,
            "scheme" => Var::Scheme,
            "request_method" => Var::RequestMethod,
            "request" => Var::Request,
            "server_protocol" => Var::ServerProtocol,
            "server_name" => Var::ServerName,
            "server_port" => Var::ServerPort,
            "server_addr" => Var::ServerAddr,
            "remote_addr" => Var::RemoteAddr,
            "binary_remote_addr" => Var::BinaryRemoteAddr,
            "remote_port" => Var::RemotePort,
            "remote_user" => Var::RemoteUser,
            "status" => Var::Status,
            "body_bytes_sent" => Var::BodyBytesSent,
            "bytes_sent" => Var::BytesSent,
            "request_length" => Var::RequestLength,
            "request_time" => Var::RequestTime,
            "msec" => Var::Msec,
            "time_local" => Var::TimeLocal,
            "time_iso8601" => Var::TimeIso8601,
            "document_root" => Var::DocumentRoot,
            "request_filename" => Var::RequestFilename,
            "content_type" => Var::ContentType,
            "content_length" => Var::ContentLength,
            "connection" => Var::Connection,
            "connection_requests" => Var::ConnectionRequests,
            "pid" => Var::Pid,
            "nginx_version" => Var::NginxVersion,
            "fastcgi_script_name" => Var::FastcgiScriptName,
            "fastcgi_path_info" => Var::FastcgiPathInfo,
            "https" => Var::Https,
            "proxy_host" => Var::ProxyHost,
            "proxy_port" => Var::ProxyPort,
            "proxy_add_x_forwarded_for" => Var::ProxyAddXForwardedFor,
            "upstream_addr" => Var::UpstreamAddr,
            "upstream_status" => Var::UpstreamStatus,
            "upstream_response_time" => Var::UpstreamResponseTime,
            "upstream_connect_time" => Var::UpstreamConnectTime,
            _ => Var::User(Arc::from(name)),
        }
    }
}

impl Var {
    /// The field name this variable becomes in a structured log record.
    ///
    /// Mirrors the name written in the config (`$remote_addr` → `remote_addr`)
    /// so a `log_format` and the resulting OxiDB documents line up.
    pub fn field_name(&self) -> String {
        let fixed = match self {
            Var::Uri => "uri",
            Var::DocumentUri => "document_uri",
            Var::RequestUri => "request_uri",
            Var::Args => "args",
            Var::IsArgs => "is_args",
            Var::Host => "host",
            Var::Hostname => "hostname",
            Var::Scheme => "scheme",
            Var::RequestMethod => "request_method",
            Var::Request => "request",
            Var::ServerProtocol => "server_protocol",
            Var::ServerName => "server_name",
            Var::ServerPort => "server_port",
            Var::ServerAddr => "server_addr",
            Var::RemoteAddr => "remote_addr",
            Var::BinaryRemoteAddr => "binary_remote_addr",
            Var::RemotePort => "remote_port",
            Var::RemoteUser => "remote_user",
            Var::Status => "status",
            Var::BodyBytesSent => "body_bytes_sent",
            Var::BytesSent => "bytes_sent",
            Var::RequestLength => "request_length",
            Var::RequestTime => "request_time",
            Var::Msec => "msec",
            Var::TimeLocal => "time_local",
            Var::TimeIso8601 => "time_iso8601",
            Var::DocumentRoot => "document_root",
            Var::RequestFilename => "request_filename",
            Var::ContentType => "content_type",
            Var::ContentLength => "content_length",
            Var::Connection => "connection",
            Var::ConnectionRequests => "connection_requests",
            Var::Pid => "pid",
            Var::NginxVersion => "nginx_version",
            Var::FastcgiScriptName => "fastcgi_script_name",
            Var::FastcgiPathInfo => "fastcgi_path_info",
            Var::Https => "https",
            Var::ProxyHost => "proxy_host",
            Var::ProxyPort => "proxy_port",
            Var::ProxyAddXForwardedFor => "proxy_add_x_forwarded_for",
            Var::UpstreamAddr => "upstream_addr",
            Var::UpstreamStatus => "upstream_status",
            Var::UpstreamResponseTime => "upstream_response_time",
            Var::UpstreamConnectTime => "upstream_connect_time",
            // The dynamic ones rebuild the name they were written with.
            Var::Http(h) => return format!("http_{}", h.replace('-', "_")),
            Var::SentHttp(h) => return format!("sent_http_{}", h.replace('-', "_")),
            Var::Arg(a) => return format!("arg_{a}"),
            Var::Cookie(c) => return format!("cookie_{c}"),
            Var::Capture(i) => return format!("capture_{i}"),
            Var::User(u) => return u.to_string(),
        };
        fixed.to_string()
    }
}

fn header_name(s: &str) -> Arc<str> {
    let mut n = String::with_capacity(s.len());
    for c in s.chars() {
        n.push(if c == '_' { '-' } else { c.to_ascii_lowercase() });
    }
    Arc::from(n.as_str())
}

#[derive(Debug, Clone)]
enum Seg {
    Lit(Box<str>),
    Var(Var),
}

/// A compiled `"...$var..."` string.
#[derive(Debug, Clone, Default)]
pub struct Template {
    segs: Vec<Seg>,
    /// Fast path: the template is a single literal with no variables.
    literal: Option<Box<str>>,
}

impl Template {
    pub fn compile(src: &str) -> Template {
        let mut segs = Vec::new();
        let b = src.as_bytes();
        let mut lit = String::new();
        let mut i = 0;

        while i < b.len() {
            if b[i] != b'$' {
                lit.push(b[i] as char);
                i += 1;
                continue;
            }
            // `$$` is not special in nginx, but a trailing or non-name `$` is
            // simply a literal dollar sign.
            let (name, next) = if i + 1 < b.len() && b[i + 1] == b'{' {
                match b[i + 2..].iter().position(|&c| c == b'}') {
                    Some(off) => {
                        let end = i + 2 + off;
                        (&src[i + 2..end], end + 1)
                    }
                    None => {
                        lit.push('$');
                        i += 1;
                        continue;
                    }
                }
            } else {
                let start = i + 1;
                let mut e = start;
                while e < b.len() && (b[e].is_ascii_alphanumeric() || b[e] == b'_') {
                    e += 1;
                }
                if e == start {
                    lit.push('$');
                    i += 1;
                    continue;
                }
                (&src[start..e], e)
            };

            if !lit.is_empty() {
                segs.push(Seg::Lit(std::mem::take(&mut lit).into_boxed_str()));
            }
            // A bare digit is a regex capture group.
            let var = if name.len() == 1 && name.as_bytes()[0].is_ascii_digit() {
                Var::Capture(name.as_bytes()[0] - b'0')
            } else {
                Var::parse(name)
            };
            segs.push(Seg::Var(var));
            i = next;
        }
        if !lit.is_empty() {
            segs.push(Seg::Lit(lit.into_boxed_str()));
        }

        let literal = match segs.as_slice() {
            [] => Some(Box::from("")),
            [Seg::Lit(l)] => Some(l.clone()),
            _ => None,
        };
        Template { segs, literal }
    }

    /// True when the template contains no variables — lets callers skip
    /// evaluation entirely and borrow the literal.
    pub fn is_literal(&self) -> bool {
        self.literal.is_some()
    }

    pub fn as_literal(&self) -> Option<&str> {
        self.literal.as_deref()
    }

    pub fn vars(&self) -> impl Iterator<Item = &Var> {
        self.segs.iter().filter_map(|s| match s {
            Seg::Var(v) => Some(v),
            _ => None,
        })
    }

    pub fn render_into(&self, src: &dyn VarSource, out: &mut String) {
        if let Some(l) = &self.literal {
            out.push_str(l);
            return;
        }
        for s in &self.segs {
            match s {
                Seg::Lit(l) => out.push_str(l),
                Seg::Var(v) => src.var(v, out),
            }
        }
    }

    pub fn render(&self, src: &dyn VarSource) -> String {
        if let Some(l) = &self.literal {
            return l.to_string();
        }
        let mut s = String::with_capacity(64);
        self.render_into(src, &mut s);
        s
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in &self.segs {
            match s {
                Seg::Lit(l) => write!(f, "{l}")?,
                Seg::Var(v) => write!(f, "${v:?}")?,
            }
        }
        Ok(())
    }
}

/// Anything that can resolve nginx variables — implemented by the per-request
/// context in the server. Values are appended; an unset variable appends
/// nothing (log formats render it as `-` separately).
pub trait VarSource {
    fn var(&self, v: &Var, out: &mut String);
}

/// A [`VarSource`] that knows nothing — useful for rendering templates at
/// config-load time (e.g. a `root` that turns out to be constant).
pub struct NoVars;

impl VarSource for NoVars {
    fn var(&self, _v: &Var, _out: &mut String) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl VarSource for Fixed {
        fn var(&self, v: &Var, out: &mut String) {
            match v {
                Var::Uri => out.push_str("/index.html"),
                Var::Host => out.push_str("example.com"),
                Var::Http(h) if &**h == "user-agent" => out.push_str("curl/8"),
                Var::Arg(a) if &**a == "q" => out.push_str("rust"),
                Var::Capture(1) => out.push_str("cap1"),
                _ => {}
            }
        }
    }

    #[test]
    fn literal_fast_path() {
        let t = Template::compile("/var/www/html");
        assert!(t.is_literal());
        assert_eq!(t.render(&Fixed), "/var/www/html");
    }

    #[test]
    fn interpolates_vars() {
        let t = Template::compile("$scheme://$host$uri");
        assert!(!t.is_literal());
        assert_eq!(t.render(&Fixed), "://example.com/index.html");
    }

    #[test]
    fn braced_form() {
        let t = Template::compile("${host}x");
        assert_eq!(t.render(&Fixed), "example.comx");
    }

    #[test]
    fn header_and_arg_vars() {
        assert_eq!(Template::compile("$http_user_agent").render(&Fixed), "curl/8");
        assert_eq!(Template::compile("$arg_q").render(&Fixed), "rust");
    }

    #[test]
    fn header_name_normalisation() {
        assert_eq!(Var::parse("http_x_forwarded_for"), Var::Http(Arc::from("x-forwarded-for")));
    }

    #[test]
    fn regex_captures() {
        assert_eq!(Template::compile("/a/$1").render(&Fixed), "/a/cap1");
    }

    #[test]
    fn field_names_match_what_the_config_wrote() {
        assert_eq!(Var::parse("remote_addr").field_name(), "remote_addr");
        assert_eq!(Var::parse("status").field_name(), "status");
        // Header names are stored lowercased with dashes; the field name goes
        // back to the underscore form the config used.
        assert_eq!(Var::parse("http_user_agent").field_name(), "http_user_agent");
        assert_eq!(Var::parse("http_x_forwarded_for").field_name(), "http_x_forwarded_for");
        assert_eq!(Var::parse("arg_q").field_name(), "arg_q");
        assert_eq!(Var::parse("cookie_sid").field_name(), "cookie_sid");
        assert_eq!(Var::parse("my_var").field_name(), "my_var");
    }

    #[test]
    fn lone_dollar_is_literal() {
        assert_eq!(Template::compile("a$ b").render(&Fixed), "a$ b");
        assert_eq!(Template::compile("cost: $").render(&Fixed), "cost: $");
    }
}

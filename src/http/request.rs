//! Zero-copy request representation.
//!
//! Parsed requests hold byte ranges into the connection's read buffer rather
//! than owned strings, so a request costs no allocations beyond the (reused)
//! header vector. The hot headers get an index side-table, turning
//! `Host` / `Connection` / `Content-Length` lookups into an array read instead
//! of a linear scan.

use std::ops::Range;

use super::uri;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Connect,
    Trace,
    Other,
}

impl Method {
    fn parse(s: &str) -> Method {
        match s.as_bytes() {
            b"GET" => Method::Get,
            b"HEAD" => Method::Head,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"OPTIONS" => Method::Options,
            b"PATCH" => Method::Patch,
            b"CONNECT" => Method::Connect,
            b"TRACE" => Method::Trace,
            _ => Method::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
            Method::Connect => "CONNECT",
            Method::Trace => "TRACE",
            Method::Other => "",
        }
    }

    /// GET and HEAD are the only methods the static file handler serves.
    pub fn is_safe(self) -> bool {
        matches!(self, Method::Get | Method::Head)
    }
}

/// Headers we look up often enough to be worth an index slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Hot {
    Host = 0,
    Connection,
    ContentLength,
    TransferEncoding,
    AcceptEncoding,
    IfNoneMatch,
    IfModifiedSince,
    IfMatch,
    IfUnmodifiedSince,
    IfRange,
    RangeH,
    UserAgent,
    Referer,
    Cookie,
    Expect,
    XForwardedFor,
    ContentType,
    Upgrade,
    Authorization,
}

const HOT_COUNT: usize = 19;

fn hot_of(name: &[u8]) -> Option<Hot> {
    // Dispatch on length first: it separates almost every candidate before a
    // single byte comparison happens.
    Some(match name.len() {
        4 if name.eq_ignore_ascii_case(b"host") => Hot::Host,
        5 if name.eq_ignore_ascii_case(b"range") => Hot::RangeH,
        6 if name.eq_ignore_ascii_case(b"cookie") => Hot::Cookie,
        6 if name.eq_ignore_ascii_case(b"expect") => Hot::Expect,
        7 if name.eq_ignore_ascii_case(b"referer") => Hot::Referer,
        7 if name.eq_ignore_ascii_case(b"upgrade") => Hot::Upgrade,
        8 if name.eq_ignore_ascii_case(b"if-match") => Hot::IfMatch,
        8 if name.eq_ignore_ascii_case(b"if-range") => Hot::IfRange,
        10 if name.eq_ignore_ascii_case(b"connection") => Hot::Connection,
        10 if name.eq_ignore_ascii_case(b"user-agent") => Hot::UserAgent,
        12 if name.eq_ignore_ascii_case(b"content-type") => Hot::ContentType,
        13 if name.eq_ignore_ascii_case(b"if-none-match") => Hot::IfNoneMatch,
        13 if name.eq_ignore_ascii_case(b"authorization") => Hot::Authorization,
        14 if name.eq_ignore_ascii_case(b"content-length") => Hot::ContentLength,
        15 if name.eq_ignore_ascii_case(b"accept-encoding") => Hot::AcceptEncoding,
        15 if name.eq_ignore_ascii_case(b"x-forwarded-for") => Hot::XForwardedFor,
        17 if name.eq_ignore_ascii_case(b"if-modified-since") => Hot::IfModifiedSince,
        17 if name.eq_ignore_ascii_case(b"transfer-encoding") => Hot::TransferEncoding,
        19 if name.eq_ignore_ascii_case(b"if-unmodified-since") => Hot::IfUnmodifiedSince,
        _ => return None,
    })
}

#[derive(Debug, Clone)]
pub struct HeaderRef {
    pub name: Range<usize>,
    pub value: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    None,
    Length(u64),
    Chunked,
}

#[derive(Debug)]
pub struct Req {
    pub method: Method,
    pub method_raw: Range<usize>,
    /// The full request target, including any query string.
    pub target: Range<usize>,
    pub path: Range<usize>,
    pub query: Range<usize>,
    /// 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor: u8,
    pub headers: Vec<HeaderRef>,
    hot: [u16; HOT_COUNT],
    /// Byte length of the request line plus headers, including the final CRLF.
    pub head_len: usize,
    pub body: Body,
    pub keep_alive: bool,
}

const NO_HEADER: u16 = u16::MAX;

/// Upper bound on request headers. nginx's practical limit is set by
/// `large_client_header_buffers`; this caps the parse scratch array.
pub const MAX_HEADERS: usize = 96;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseResult {
    /// Need more bytes before a decision can be made.
    Partial,
    Complete,
    /// Malformed; the connection must be answered with this status and closed.
    Error(u16),
}

impl Default for Req {
    fn default() -> Self {
        Req::new()
    }
}

impl Req {
    pub fn new() -> Req {
        Req {
            method: Method::Get,
            method_raw: 0..0,
            target: 0..0,
            path: 0..0,
            query: 0..0,
            minor: 1,
            headers: Vec::with_capacity(24),
            hot: [NO_HEADER; HOT_COUNT],
            head_len: 0,
            body: Body::None,
            keep_alive: true,
        }
    }

    /// Resets in place so the allocation survives into the next keep-alive
    /// request on this connection.
    pub fn reset(&mut self) {
        self.headers.clear();
        self.hot = [NO_HEADER; HOT_COUNT];
        self.head_len = 0;
        self.body = Body::None;
        self.keep_alive = true;
    }

    /// Parses a request head out of `buf`.
    ///
    /// The header scratch space is an uninitialised stack array rather than a
    /// heap `Vec`: allocating and zeroing one per request cost more than the
    /// parse itself at small payload sizes. [`MAX_HEADERS`] bounds it, so a
    /// hostile peer cannot force unbounded work.
    pub fn parse(&mut self, buf: &[u8], _max_headers: usize) -> ParseResult {
        self.reset();

        // SAFETY: an array of `MaybeUninit` needs no initialisation, and
        // `parse_with_uninit_headers` only ever reads back the entries it has
        // itself written (httparse documents this contract).
        let mut hbuf: [std::mem::MaybeUninit<httparse::Header<'_>>; MAX_HEADERS] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        let mut p = httparse::Request::new(&mut []);
        let status = match p.parse_with_uninit_headers(buf, &mut hbuf) {
            Ok(s) => s,
            Err(httparse::Error::TooManyHeaders) => return ParseResult::Error(431),
            Err(httparse::Error::Version) => return ParseResult::Error(505),
            Err(_) => return ParseResult::Error(400),
        };
        let head_len = match status {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => return ParseResult::Partial,
        };

        let base = buf.as_ptr() as usize;
        let range_of = |s: &[u8]| -> Range<usize> {
            let start = s.as_ptr() as usize - base;
            start..start + s.len()
        };

        let Some(m) = p.method else {
            return ParseResult::Error(400);
        };
        let Some(t) = p.path else {
            return ParseResult::Error(400);
        };
        self.method = Method::parse(m);
        self.method_raw = range_of(m.as_bytes());
        self.target = range_of(t.as_bytes());

        let (path, query) = uri::split_query(t);
        self.path = range_of(path.as_bytes());
        self.query = if query.is_empty() {
            // Point at the end of the target so an empty query is still a
            // valid (empty) range rather than a sentinel.
            self.target.end..self.target.end
        } else {
            range_of(query.as_bytes())
        };

        self.minor = match p.version {
            Some(0) => 0,
            Some(1) => 1,
            _ => return ParseResult::Error(505),
        };
        self.head_len = head_len;

        for h in p.headers.iter() {
            if h.name.is_empty() {
                break;
            }
            let idx = self.headers.len();
            if let Some(hot) = hot_of(h.name.as_bytes()) {
                let slot = hot as usize;
                // Keep the first occurrence, as nginx does for Host.
                if self.hot[slot] == NO_HEADER {
                    self.hot[slot] = idx as u16;
                }
            }
            self.headers.push(HeaderRef {
                name: range_of(h.name.as_bytes()),
                value: range_of(h.value),
            });
        }

        // HTTP/1.1 defaults to keep-alive; 1.0 defaults to close.
        self.keep_alive = self.minor == 1;
        if let Some(v) = self.hot_value(buf, Hot::Connection) {
            if header_has_token(v, "close") {
                self.keep_alive = false;
            } else if header_has_token(v, "keep-alive") {
                self.keep_alive = true;
            }
        }

        // Framing. Transfer-Encoding wins over Content-Length; a request with
        // both is a smuggling vector and is rejected outright.
        let te = self.hot_value(buf, Hot::TransferEncoding);
        let cl = self.hot_value(buf, Hot::ContentLength);
        match (te, cl) {
            (Some(te), cl_opt) => {
                if !te.eq_ignore_ascii_case("chunked") {
                    return ParseResult::Error(400);
                }
                if cl_opt.is_some() {
                    return ParseResult::Error(400);
                }
                self.body = Body::Chunked;
            }
            (None, Some(cl)) => {
                // Duplicate Content-Length headers are also a smuggling vector.
                let dups = self
                    .headers
                    .iter()
                    .filter(|h| buf[h.name.clone()].eq_ignore_ascii_case(b"content-length"))
                    .count();
                if dups > 1 {
                    return ParseResult::Error(400);
                }
                match cl.trim().parse::<u64>() {
                    Ok(n) => self.body = Body::Length(n),
                    Err(_) => return ParseResult::Error(400),
                }
            }
            (None, None) => self.body = Body::None,
        }

        if self.minor == 1 && self.hot[Hot::Host as usize] == NO_HEADER {
            // HTTP/1.1 mandates Host.
            return ParseResult::Error(400);
        }

        ParseResult::Complete
    }

    /// Builds a request from parts rather than from HTTP/1 text.
    ///
    /// HTTP/2 carries the method, target and headers as separate decoded
    /// fields, so there is no request line to parse. The alternative was to
    /// re-serialise them into HTTP/1.1 bytes and run the normal parser over
    /// them, which would have been less code and a per-request round trip
    /// through a format neither end used.
    ///
    /// The returned buffer is what every `Range` in the request points into;
    /// the two must be kept together for the request's whole life.
    pub fn from_parts(method: &str, target: &str, headers: &[(&str, &str)]) -> (Vec<u8>, Req) {
        let cap = method.len()
            + target.len()
            + headers.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>();
        let mut buf = Vec::with_capacity(cap);
        let mut req = Req::new();

        let put = |buf: &mut Vec<u8>, s: &str| {
            let start = buf.len();
            buf.extend_from_slice(s.as_bytes());
            start..buf.len()
        };

        req.method_raw = put(&mut buf, method);
        req.method = Method::parse(method);
        req.target = put(&mut buf, target);

        // The query split is the same one HTTP/1 does on the request target;
        // `:path` carries both halves exactly as an origin-form target does.
        let (p, q) = uri::split_query(target);
        let t = req.target.start;
        req.path = t..t + p.len();
        req.query = if q.is_empty() { t..t } else { t + p.len() + 1..t + target.len() };

        for (name, value) in headers {
            let n = put(&mut buf, name);
            let v = put(&mut buf, value);
            req.push_header(n, v, &buf);
        }

        // HTTP/2 has no version token and no `Connection` header: the
        // connection outlives the stream by construction, and framing comes
        // from END_STREAM rather than from Content-Length. A caller that knows
        // a body is coming sets `body` afterwards.
        req.minor = 1;
        req.keep_alive = true;
        req.head_len = 0;
        (buf, req)
    }

    /// Appends a header and updates the hot-header index.
    ///
    /// `buf` must already contain the bytes both ranges point at.
    pub fn push_header(&mut self, name: Range<usize>, value: Range<usize>, buf: &[u8]) {
        let idx = self.headers.len();
        if let Some(hot) = hot_of(&buf[name.clone()]) {
            let slot = hot as usize;
            // Keep the first occurrence, as the HTTP/1 parser does.
            if self.hot[slot] == NO_HEADER {
                self.hot[slot] = idx as u16;
            }
        }
        self.headers.push(HeaderRef { name, value });
    }

    #[inline]
    pub fn slice<'b>(&self, buf: &'b [u8], r: &Range<usize>) -> &'b str {
        // Header bytes are validated as ASCII-compatible by httparse; anything
        // that is not valid UTF-8 is passed through lossily rather than
        // failing the request, matching nginx's byte-oriented tolerance.
        std::str::from_utf8(&buf[r.clone()]).unwrap_or("")
    }

    #[inline]
    pub fn hot_value<'b>(&self, buf: &'b [u8], h: Hot) -> Option<&'b str> {
        let i = self.hot[h as usize];
        if i == NO_HEADER {
            return None;
        }
        let hr = &self.headers[i as usize];
        Some(self.slice(buf, &hr.value))
    }

    /// Case-insensitive lookup for headers without a hot slot (`$http_*`).
    pub fn header<'b>(&self, buf: &'b [u8], name: &str) -> Option<&'b str> {
        if let Some(h) = hot_of(name.as_bytes()) {
            return self.hot_value(buf, h);
        }
        let n = name.as_bytes();
        self.headers
            .iter()
            .find(|h| buf[h.name.clone()].eq_ignore_ascii_case(n))
            .map(|h| self.slice(buf, &h.value))
    }

    pub fn path_str<'b>(&self, buf: &'b [u8]) -> &'b str {
        self.slice(buf, &self.path)
    }

    pub fn query_str<'b>(&self, buf: &'b [u8]) -> &'b str {
        self.slice(buf, &self.query)
    }

    pub fn target_str<'b>(&self, buf: &'b [u8]) -> &'b str {
        self.slice(buf, &self.target)
    }

    /// The `Host` header with any port stripped, lowercased by the caller.
    pub fn host<'b>(&self, buf: &'b [u8]) -> &'b str {
        let h = self.hot_value(buf, Hot::Host).unwrap_or("");
        // Strip the port, but not from a bracketed IPv6 literal's interior.
        if h.starts_with('[') {
            // Keep the brackets, drop only a `:port` after the closing one.
            return match h.find(']') {
                Some(i) => &h[..i + 1],
                None => h,
            };
        }
        match h.rfind(':') {
            Some(i) => &h[..i],
            None => h,
        }
    }

    pub fn accepts_gzip(&self, buf: &[u8]) -> bool {
        match self.hot_value(buf, Hot::AcceptEncoding) {
            Some(v) => header_has_token(v, "gzip"),
            None => false,
        }
    }

    pub fn expects_continue(&self, buf: &[u8]) -> bool {
        self.hot_value(buf, Hot::Expect)
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    }
}

/// True when a comma-separated header value contains `token` as an element.
/// Avoids `contains()`, which would match `keep-alive` inside `no-keep-alive`.
pub fn header_has_token(value: &str, token: &str) -> bool {
    value.split(',').any(|p| {
        // Strip any `;q=…` parameter before comparing.
        let p = p.split(';').next().unwrap_or("").trim();
        p.eq_ignore_ascii_case(token)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> (Req, Vec<u8>, ParseResult) {
        let buf = raw.as_bytes().to_vec();
        let mut r = Req::new();
        let res = r.parse(&buf, 64);
        (r, buf, res)
    }

    #[test]
    fn minimal_get() {
        let (r, b, res) = parse("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(res, ParseResult::Complete);
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.path_str(&b), "/index.html");
        assert_eq!(r.host(&b), "x");
        assert!(r.keep_alive);
        assert_eq!(r.body, Body::None);
    }

    #[test]
    fn query_is_split_off() {
        let (r, b, _) = parse("GET /s?q=a&b=2 HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(r.path_str(&b), "/s");
        assert_eq!(r.query_str(&b), "q=a&b=2");
        assert_eq!(r.target_str(&b), "/s?q=a&b=2");
    }

    #[test]
    fn empty_query_is_an_empty_range() {
        let (r, b, _) = parse("GET /s HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(r.query_str(&b), "");
    }

    #[test]
    fn partial_head_returns_partial() {
        let (_, _, res) = parse("GET / HTTP/1.1\r\nHost: x\r\n");
        assert_eq!(res, ParseResult::Partial);
    }

    #[test]
    fn http_10_defaults_to_close() {
        let (r, _, res) = parse("GET / HTTP/1.0\r\n\r\n");
        assert_eq!(res, ParseResult::Complete);
        assert!(!r.keep_alive);
        assert_eq!(r.minor, 0);
    }

    #[test]
    fn http_10_keepalive_opt_in() {
        let (r, _, _) = parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert!(r.keep_alive);
    }

    #[test]
    fn connection_close_honoured() {
        let (r, _, _) = parse("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assert!(!r.keep_alive);
    }

    #[test]
    fn http_11_without_host_is_400() {
        let (_, _, res) = parse("GET / HTTP/1.1\r\n\r\n");
        assert_eq!(res, ParseResult::Error(400));
    }

    #[test]
    fn host_port_is_stripped() {
        let (r, b, _) = parse("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
        assert_eq!(r.host(&b), "example.com");
    }

    #[test]
    fn ipv6_host_keeps_its_brackets() {
        let (r, b, _) = parse("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
        assert_eq!(r.host(&b), "[::1]");
    }

    #[test]
    fn content_length_framing() {
        let (r, _, _) = parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 42\r\n\r\n");
        assert_eq!(r.body, Body::Length(42));
    }

    #[test]
    fn chunked_framing() {
        let (r, _, _) = parse("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(r.body, Body::Chunked);
    }

    // Request smuggling defences.
    #[test]
    fn both_te_and_cl_is_rejected() {
        let (_, _, res) = parse(
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        );
        assert_eq!(res, ParseResult::Error(400));
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        let (_, _, res) =
            parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n");
        assert_eq!(res, ParseResult::Error(400));
    }

    #[test]
    fn unknown_transfer_encoding_is_rejected() {
        let (_, _, res) = parse("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n");
        assert_eq!(res, ParseResult::Error(400));
    }

    #[test]
    fn non_numeric_content_length_is_rejected() {
        let (_, _, res) = parse("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n");
        assert_eq!(res, ParseResult::Error(400));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let (r, b, _) = parse("GET / HTTP/1.1\r\nHost: x\r\nX-Custom-Thing: v\r\n\r\n");
        assert_eq!(r.header(&b, "x-custom-thing"), Some("v"));
        assert_eq!(r.header(&b, "X-CUSTOM-THING"), Some("v"));
        assert_eq!(r.header(&b, "nope"), None);
    }

    #[test]
    fn token_matching_is_not_substring_matching() {
        assert!(header_has_token("gzip, deflate", "gzip"));
        assert!(header_has_token("br;q=1.0, gzip;q=0.8", "gzip"));
        assert!(!header_has_token("x-gzip-custom", "gzip"));
        assert!(!header_has_token("no-keep-alive", "keep-alive"));
    }

    #[test]
    fn accept_encoding_detection() {
        let (r, b, _) = parse("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, deflate\r\n\r\n");
        assert!(r.accepts_gzip(&b));
        let (r2, b2, _) = parse("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: br\r\n\r\n");
        assert!(!r2.accepts_gzip(&b2));
    }

    #[test]
    fn reset_preserves_capacity() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\n\r\n".to_vec();
        let mut r = Req::new();
        r.parse(&buf, 64);
        let cap = r.headers.capacity();
        r.reset();
        assert_eq!(r.headers.len(), 0);
        assert_eq!(r.headers.capacity(), cap);
    }
}

//! `fastcgi_pass` — the responder side of FastCGI, as php-fpm speaks it.
//!
//! The record framing lives in [`super::fcgi_proto`]; this module builds the
//! CGI environment, drives the exchange, and turns the application's CGI-style
//! response into an HTTP one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::transport::Stream;

use super::ctx::Ctx;
use super::fcgi_proto as p;
use super::reply::{Body, Reply};
use crate::config::model::{FastCgiConf, FastCgiPass, Location, ProxyTarget};
use crate::http::response::Resp;

/// Response headers the application must not dictate — these describe our hop.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "content-length", // we re-frame from the body we actually buffered
];

/// Absolute cap on a buffered response body.
///
/// Reached only when an application keeps a single record stream open past
/// every other bound; ordinary large responses switch to streaming at
/// `fastcgi_buffers × fastcgi_buffer_size` long before this.
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

/// A CGI header block larger than this is not a header block. Bounded
/// separately from the body because the headers must be collected whole
/// before anything can be streamed.
const MAX_HEADERS: usize = 256 * 1024;

pub async fn fastcgi(
    ctx: &mut Ctx<'_>,
    loc: &Arc<Location>,
    pass: &FastCgiPass,
) -> Result<Reply, u16> {
    let conf = &loc.core.fastcgi;
    let started = Instant::now();

    let addr = match &pass.target {
        ProxyTarget::Addr { host, port } => format!("{host}:{port}"),
        // Kept in nginx's own `unix:` form; `Stream::connect` dispatches on it.
        ProxyTarget::Unix(path) => format!("unix:{path}"),
        ProxyTarget::Upstream(name) => {
            // FastCGI upstreams get the same health-aware selection as HTTP
            // ones; a dead php-fpm peer is skipped exactly the same way.
            let up = ctx.http.upstreams.get(&**name).ok_or(502u16)?;
            let idx = super::proxy::select_peer(ctx, up)?;
            super::proxy::peer_addr(&up.servers[idx].addr)
        }
        ProxyTarget::Dynamic(t) => {
            let a = t.render(&*ctx);
            if a.is_empty() {
                return Err(502);
            }
            if a.contains(':') { a } else { format!("{a}:9000") }
        }
    };
    ctx.upstream_addr = addr.clone();

    // SCRIPT_NAME / PATH_INFO must be settled before any parameter template is
    // rendered, since the stock fastcgi_params reference them.
    split_script_and_path_info(ctx, conf);

    let params = build_params(ctx, conf);

    let mut out = Vec::with_capacity(params.len() + ctx.body.len() + 256);
    p::push_begin_request(&mut out, conf.keep_conn);
    p::push_params(&mut out, &params);
    p::push_stdin(&mut out, ctx.body);

    let connect_to = conf.connect_timeout.unwrap_or(Duration::from_secs(60));
    let mut sock = match tokio::time::timeout(connect_to, Stream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };

    if sock.write_all(&out).await.is_err() {
        return Err(502);
    }
    let _ = sock.flush().await;

    match read_response(sock, conf).await? {
        Collected::Complete { stdout, app_status } => {
            ctx.upstream_time = started.elapsed().as_secs_f64();
            // A non-zero application status with no output is a crashed script.
            if stdout.is_empty() {
                if app_status != 0 {
                    return Err(502);
                }
                // An empty but successful response is legal (e.g. a 204).
                let mut resp = Resp::new();
                ctx.upstream_status = 200;
                resp.status = 200;
                return Ok(Reply::new(resp, Body::Empty));
            }
            build_reply(ctx, conf, stdout)
        }
        Collected::Streaming { head, pre, reader } => {
            // The clock stops at the headers, as it does for a proxied
            // response: the rest is the client's transfer, not the
            // application's think time.
            ctx.upstream_time = started.elapsed().as_secs_f64();
            build_streaming_reply(ctx, conf, head, pre, reader)
        }
    }
}

/// Applies `fastcgi_split_path_info`, filling `$fastcgi_script_name` and
/// `$fastcgi_path_info`.
///
/// Without the directive the whole URI is the script name. With it, capture 1
/// is the script and capture 2 the trailing path — the mechanism that lets
/// `/index.php/users/42` reach `index.php` with `PATH_INFO=/users/42`.
fn split_script_and_path_info(ctx: &mut Ctx<'_>, conf: &FastCgiConf) {
    let uri = ctx.uri.clone();

    if let Some(re) = &conf.split_path_info {
        if let Some(c) = re.captures(&uri) {
            let script = c.get(1).map(|m| m.as_str()).unwrap_or("");
            let info = c.get(2).map(|m| m.as_str()).unwrap_or("");
            ctx.fastcgi_script_name = script.to_string();
            ctx.fastcgi_path_info = info.to_string();
            append_index_if_directory(ctx, conf);
            return;
        }
    }

    ctx.fastcgi_script_name = uri;
    ctx.fastcgi_path_info.clear();
    append_index_if_directory(ctx, conf);
}

/// `fastcgi_index` completes a script path that names a directory.
fn append_index_if_directory(ctx: &mut Ctx<'_>, conf: &FastCgiConf) {
    if ctx.fastcgi_script_name.ends_with('/') {
        if let Some(idx) = &conf.index {
            ctx.fastcgi_script_name.push_str(idx);
        }
    }
}

/// Encodes the CGI environment as FastCGI name/value pairs.
fn build_params(ctx: &Ctx<'_>, conf: &FastCgiConf) -> Vec<u8> {
    let mut params = Vec::with_capacity(1024);
    let mut value = String::with_capacity(128);

    for prm in &conf.params {
        value.clear();
        prm.value.render_into(ctx, &mut value);
        if prm.if_not_empty && value.is_empty() {
            continue;
        }
        p::push_nv_pair(&mut params, prm.name.as_bytes(), value.as_bytes());
    }

    // Every client header is also exposed as HTTP_*, which is what the CGI
    // specification requires and what applications actually read.
    let mut name_buf = Vec::with_capacity(64);
    for h in &ctx.req.headers {
        let name = ctx.req.slice(ctx.buf, &h.name);
        // Content-Type and Content-Length have unprefixed CGI names and are
        // normally supplied via fastcgi_param; skip the HTTP_ duplicates.
        if name.eq_ignore_ascii_case("content-type") || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        name_buf.clear();
        p::http_param_name(name, &mut name_buf);
        let v = ctx.req.slice(ctx.buf, &h.value);
        p::push_nv_pair(&mut params, &name_buf, v.as_bytes());
    }
    params
}

/// Reads records until `END_REQUEST`, collecting `STDOUT`.
///
/// `STDERR` is drained and discarded rather than mixed into the response —
/// applications log to it, and folding that into the page would corrupt output.
/// What the response turned out to be.
enum Collected {
    /// The whole thing arrived: headers and body, with the request ended.
    /// This is the ordinary case for a page, and the only one that can carry
    /// a `Content-Length`.
    Complete { stdout: Vec<u8>, app_status: u32 },
    /// Headers are in hand and more body is still coming. The connection goes
    /// with it — the rest is decoded as the client reads.
    Streaming { head: Vec<u8>, pre: Vec<u8>, reader: FcgiBody },
}

/// Reads until the response is complete, or until it is clear it will not be.
///
/// Buffering the whole response is what lets us send a `Content-Length`, so it
/// is worth doing for anything that fits. Past `fastcgi_buffers ×
/// fastcgi_buffer_size` the trade inverts: holding a 200 MB export in memory
/// to save the client a chunked encoding is how a worker dies. nginx switches
/// at the same point.
async fn read_response(sock: Stream, conf: &FastCgiConf) -> Result<Collected, u16> {
    let read_to = conf.read_timeout.unwrap_or(Duration::from_secs(60));
    let mut r = FcgiBody::new(sock, read_to);
    let mut stdout: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut head_end: Option<usize> = None;

    loop {
        match r.pump(&mut stdout).await? {
            Pump::Ended => {
                return Ok(Collected::Complete { stdout, app_status: r.app_status })
            }
            Pump::More => {}
        }

        if head_end.is_none() {
            head_end = find_header_end(&stdout).map(|(_, at)| at);
        }
        // Only stream once the headers are complete: they are what the reply
        // is built from, and a half-read header block is not a response.
        let Some(at) = head_end else {
            // A header block this large is not a header block.
            if stdout.len() > MAX_HEADERS {
                return Err(502);
            }
            continue;
        };
        let over_budget = stdout.len() - at > conf.buffer_budget;
        if !conf.buffering || over_budget {
            let pre = stdout.split_off(at);
            return Ok(Collected::Streaming { head: stdout, pre, reader: r });
        }
        if stdout.len() > MAX_RESPONSE {
            return Err(502);
        }
    }
}

enum Pump {
    /// Some progress; call again.
    More,
    /// `FCGI_END_REQUEST`, or the peer closed.
    Ended,
}

/// Decodes `FCGI_STDOUT` out of a FastCGI connection.
///
/// Doubles as the body of a streamed response: [`AsyncRead`] hands the client
/// the payload bytes with the record framing removed, which is why the
/// connection travels into the [`Body::Stream`] rather than being drained
/// first.
pub struct FcgiBody {
    sock: Stream,
    /// Bytes read from the socket that have not been parsed into records yet.
    raw: Vec<u8>,
    /// How much of `raw` has been parsed.
    consumed: usize,
    /// Decoded payload the caller has not taken yet.
    out: Vec<u8>,
    out_at: usize,
    app_status: u32,
    done: bool,
    read_to: Duration,
}

impl FcgiBody {
    fn new(sock: Stream, read_to: Duration) -> FcgiBody {
        FcgiBody {
            sock,
            raw: Vec::with_capacity(16 * 1024),
            consumed: 0,
            out: Vec::new(),
            out_at: 0,
            app_status: 0,
            done: false,
            read_to,
        }
    }

    /// Parses whatever is buffered, appending payload to `sink`.
    ///
    /// Returns whether the request ended. Malformed framing is fatal: a record
    /// stream we cannot follow leaves no way to tell payload from padding.
    fn drain_records(&mut self, sink: &mut Vec<u8>) -> Result<bool, u16> {
        loop {
            match p::parse_record(&self.raw[self.consumed..]) {
                Ok(rec) => {
                    match rec.ty {
                        p::RecordType::Stdout => sink.extend_from_slice(rec.body),
                        p::RecordType::Stderr => { /* application log; not ours */ }
                        p::RecordType::EndRequest => {
                            if let Some((app, proto)) = p::end_request_status(rec.body) {
                                self.app_status = app;
                                // Anything but FCGI_REQUEST_COMPLETE (0) means
                                // the application refused the request.
                                if proto != 0 {
                                    return Err(502);
                                }
                            }
                            self.consumed += rec.total;
                            self.done = true;
                            return Ok(true);
                        }
                        _ => {}
                    }
                    self.consumed += rec.total;
                }
                Err(p::ParseError::Incomplete) => return Ok(false),
                Err(p::ParseError::Malformed) => return Err(502),
            }
        }
    }

    fn compact(&mut self) {
        if self.consumed > 0 {
            self.raw.drain(..self.consumed);
            self.consumed = 0;
        }
    }

    /// One read plus a parse pass, for the header-collection phase.
    async fn pump(&mut self, sink: &mut Vec<u8>) -> Result<Pump, u16> {
        if self.drain_records(sink)? {
            return Ok(Pump::Ended);
        }
        self.compact();

        let mut chunk = [0u8; 16 * 1024];
        let n = match tokio::time::timeout(self.read_to, self.sock.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                // Closed before END_REQUEST. Whatever arrived is the response;
                // the caller decides whether that is enough.
                self.done = true;
                return Ok(Pump::Ended);
            }
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(502),
            Err(_) => return Err(504),
        };
        self.raw.extend_from_slice(&chunk[..n]);
        if self.drain_records(sink)? {
            return Ok(Pump::Ended);
        }
        Ok(Pump::More)
    }
}

impl tokio::io::AsyncRead for FcgiBody {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.get_mut();
        loop {
            // Hand over anything already decoded.
            if me.out_at < me.out.len() {
                let n = (me.out.len() - me.out_at).min(buf.remaining());
                buf.put_slice(&me.out[me.out_at..me.out_at + n]);
                me.out_at += n;
                if me.out_at == me.out.len() {
                    me.out.clear();
                    me.out_at = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if me.done {
                // Zero filled: end of body.
                return Poll::Ready(Ok(()));
            }

            // Parse whatever is already buffered before touching the socket.
            let mut decoded = std::mem::take(&mut me.out);
            decoded.clear();
            match me.drain_records(&mut decoded) {
                Ok(_) => {}
                Err(_) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed FastCGI record",
                    )))
                }
            }
            me.out = decoded;
            me.compact();
            if !me.out.is_empty() || me.done {
                continue;
            }

            // Nothing decodable yet: read more.
            let before = me.raw.len();
            me.raw.resize(before + 16 * 1024, 0);
            let mut rb = tokio::io::ReadBuf::new(&mut me.raw[before..]);
            match std::pin::Pin::new(&mut me.sock).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    me.raw.truncate(before);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    me.raw.truncate(before);
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    me.raw.truncate(before + n);
                    if n == 0 {
                        // The peer closed without END_REQUEST. There is no way
                        // to signal truncation once the head is already on the
                        // wire, so the body simply ends here — the same thing
                        // the proxy path does for a length-less upstream.
                        me.done = true;
                    }
                }
            }
        }
    }
}

/// Splits the CGI response into headers and body and maps it onto HTTP.
fn build_reply(ctx: &mut Ctx<'_>, conf: &FastCgiConf, stdout: Vec<u8>) -> Result<Reply, u16> {
    let Some((head_len, body_at)) = find_header_end(&stdout) else {
        // No header block at all: the application emitted a bare body or died
        // mid-header. Either way it is not a valid CGI response.
        return Err(502);
    };
    let (resp, _) = parse_cgi_headers(ctx, conf, &stdout[..head_len]);
    let body = stdout[body_at..].to_vec();
    Ok(Reply::new(resp, Body::Bytes(body)))
}

/// The same response, when the body is still arriving.
///
/// The only difference that reaches the client is framing: a buffered response
/// can carry a `Content-Length` computed from what we hold, a streamed one
/// cannot, so it goes out chunked unless the application declared a length
/// itself — which `Reply::frame` works out from the headers.
fn build_streaming_reply(
    ctx: &mut Ctx<'_>,
    conf: &FastCgiConf,
    head: Vec<u8>,
    pre: Vec<u8>,
    reader: FcgiBody,
) -> Result<Reply, u16> {
    let Some((head_len, _)) = find_header_end(&head) else {
        return Err(502);
    };
    // An application that declared its own length is taken at its word: it is
    // the only party that knows, and nginx trusts it the same way. Without one
    // the length is unknown and framing falls to chunked.
    let (resp, len) = parse_cgi_headers(ctx, conf, &head[..head_len]);
    Ok(Reply::new(resp, Body::Stream { pre, io: Box::new(reader), len }))
}

/// Maps a CGI header block onto an HTTP response head.
fn parse_cgi_headers(
    ctx: &mut Ctx<'_>,
    conf: &FastCgiConf,
    head: &[u8],
) -> (Resp, Option<u64>) {
    let mut resp = Resp::new();
    let mut status = 200u16;
    let mut saw_location_only = false;
    // Captured before the hop-by-hop filter drops it. A buffered response
    // re-frames from the bytes actually held, so the application's own value
    // is redundant there — but a streamed one has no other way to know a
    // length the application already worked out.
    let mut declared_len = None;

    for line in split_lines(head) {
        let Some((name, value)) = split_header(line) else {
            continue;
        };
        let lname = name.to_ascii_lowercase();
        if lname == "content-length" {
            declared_len = value.trim().parse::<u64>().ok();
        }

        // `Status: 404 Not Found` sets the HTTP status and is not forwarded.
        if lname == "status" {
            status = value
                .split_whitespace()
                .next()
                .and_then(|c| c.parse().ok())
                .unwrap_or(200);
            continue;
        }
        if HOP_BY_HOP.contains(&lname.as_str())
            || conf.hide_headers.iter().any(|h| &**h == lname.as_str())
        {
            continue;
        }
        if lname == "location" {
            saw_location_only = true;
        }
        resp.header(name, value);
    }

    // CGI: a Location header with no explicit Status means a 302.
    if saw_location_only && status == 200 {
        status = 302;
    }

    resp.status = status;
    ctx.upstream_status = status;
    (resp, declared_len)
}

fn find_header_end(b: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\n' {
            // `\n\n`
            if i + 1 < b.len() && b[i + 1] == b'\n' {
                return Some((i, i + 2));
            }
            // `\n\r\n`
            if i + 2 < b.len() && b[i + 1] == b'\r' && b[i + 2] == b'\n' {
                return Some((i, i + 3));
            }
            // A header block that ends exactly at the buffer end has no body.
            if i + 1 == b.len() {
                return Some((i, b.len()));
            }
        }
        i += 1;
    }
    None
}

fn split_lines(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    b.split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
}

fn split_header(line: &[u8]) -> Option<(&str, &str)> {
    let i = line.iter().position(|&c| c == b':')?;
    let name = std::str::from_utf8(&line[..i]).ok()?.trim();
    let value = std::str::from_utf8(&line[i + 1..]).ok()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_ends_at_crlfcrlf_or_lflf() {
        let a = b"Content-Type: text/html\r\n\r\nbody";
        let (h, b) = find_header_end(a).unwrap();
        assert_eq!(&a[..h], b"Content-Type: text/html\r");
        assert_eq!(&a[b..], b"body");

        let c = b"Content-Type: text/html\n\nbody";
        let (h, b2) = find_header_end(c).unwrap();
        assert_eq!(&c[..h], b"Content-Type: text/html");
        assert_eq!(&c[b2..], b"body");
    }

    #[test]
    fn headers_without_a_body_are_accepted() {
        let a = b"Status: 204 No Content\n";
        let (h, b) = find_header_end(a).unwrap();
        assert_eq!(b, a.len(), "no body after the header block");
        assert!(!a[..h].is_empty());
    }

    #[test]
    fn missing_header_terminator_is_detected() {
        assert!(find_header_end(b"Content-Type: text/html").is_none());
    }

    #[test]
    fn header_lines_split_on_the_first_colon() {
        assert_eq!(split_header(b"X-Time: 12:30:00"), Some(("X-Time", "12:30:00")));
        assert_eq!(split_header(b"Content-Type:text/html"), Some(("Content-Type", "text/html")));
        assert_eq!(split_header(b"garbage"), None);
        assert_eq!(split_header(b": novalue"), None);
    }

    #[test]
    fn lines_iterate_without_the_carriage_returns() {
        let v: Vec<_> = split_lines(b"A: 1\r\nB: 2\r\n").collect();
        assert_eq!(v, vec![&b"A: 1"[..], &b"B: 2"[..]]);
    }
}

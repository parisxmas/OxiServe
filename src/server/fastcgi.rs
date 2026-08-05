//! `fastcgi_pass` — the responder side of FastCGI, as php-fpm speaks it.
//!
//! The record framing lives in [`super::fcgi_proto`]; this module builds the
//! CGI environment, drives the exchange, and turns the application's CGI-style
//! response into an HTTP one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

/// Cap on a buffered response body. `fastcgi_buffering` is always on for now,
/// so a runaway application cannot exhaust the worker's memory silently.
const MAX_RESPONSE: usize = 64 * 1024 * 1024;

pub async fn fastcgi(
    ctx: &mut Ctx<'_>,
    loc: &Arc<Location>,
    pass: &FastCgiPass,
) -> Result<Reply, u16> {
    let conf = &loc.core.fastcgi;
    let started = Instant::now();

    let addr = match &pass.target {
        ProxyTarget::Addr { host, port } => format!("{host}:{port}"),
        ProxyTarget::Upstream(name) => {
            let up = ctx.http.upstreams.get(&**name).ok_or(502u16)?;
            super::proxy::pick_upstream(ctx, up)?
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
    let mut sock = match tokio::time::timeout(connect_to, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };
    let _ = sock.set_nodelay(true);

    if sock.write_all(&out).await.is_err() {
        return Err(502);
    }
    let _ = sock.flush().await;

    let (stdout, app_status) = read_response(&mut sock, conf).await?;
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
async fn read_response(
    sock: &mut TcpStream,
    conf: &FastCgiConf,
) -> Result<(Vec<u8>, u32), u16> {
    let read_to = conf.read_timeout.unwrap_or(Duration::from_secs(60));
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut stdout = Vec::with_capacity(16 * 1024);
    let mut app_status = 0u32;
    let mut consumed = 0usize;

    loop {
        // Drain every complete record currently buffered.
        loop {
            match p::parse_record(&buf[consumed..]) {
                Ok(rec) => {
                    match rec.ty {
                        p::RecordType::Stdout => {
                            if stdout.len() + rec.body.len() > MAX_RESPONSE {
                                return Err(502);
                            }
                            stdout.extend_from_slice(rec.body);
                        }
                        p::RecordType::Stderr => { /* application log; not ours */ }
                        p::RecordType::EndRequest => {
                            if let Some((app, proto)) = p::end_request_status(rec.body) {
                                app_status = app;
                                // Anything but FCGI_REQUEST_COMPLETE (0) means
                                // the application refused the request.
                                if proto != 0 {
                                    return Err(502);
                                }
                            }
                            return Ok((stdout, app_status));
                        }
                        _ => {}
                    }
                    consumed += rec.total;
                }
                Err(p::ParseError::Incomplete) => break,
                Err(p::ParseError::Malformed) => return Err(502),
            }
        }

        // Compact so the buffer does not grow without bound on long responses.
        if consumed > 0 {
            buf.drain(..consumed);
            consumed = 0;
        }

        let mut chunk = [0u8; 16 * 1024];
        let n = match tokio::time::timeout(read_to, sock.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                // Closed before END_REQUEST. If output arrived, use it.
                return if stdout.is_empty() { Err(502) } else { Ok((stdout, app_status)) };
            }
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(502),
            Err(_) => return Err(504),
        };
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Splits the CGI response into headers and body and maps it onto HTTP.
fn build_reply(ctx: &mut Ctx<'_>, conf: &FastCgiConf, stdout: Vec<u8>) -> Result<Reply, u16> {
    let Some((head_len, body_at)) = find_header_end(&stdout) else {
        // No header block at all: the application emitted a bare body or died
        // mid-header. Either way it is not a valid CGI response.
        return Err(502);
    };

    let mut resp = Resp::new();
    let mut status = 200u16;
    let mut saw_location_only = false;

    for line in split_lines(&stdout[..head_len]) {
        let Some((name, value)) = split_header(line) else {
            continue;
        };
        let lname = name.to_ascii_lowercase();

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

    let body = stdout[body_at..].to_vec();
    Ok(Reply::new(resp, Body::Bytes(body)))
}

/// Finds the blank line ending the header block, tolerating both `\r\n\r\n`
/// and bare `\n\n` — applications emit both.
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

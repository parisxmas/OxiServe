//! `proxy_pass` — reverse proxying to an upstream.
//!
//! Load-balancer state is per worker thread, which is also how nginx works:
//! each worker keeps its own round-robin cursor rather than coordinating
//! through shared memory. That keeps the proxy path free of atomics on the
//! common case.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::ctx::Ctx;
use super::reply::{Body, Reply};
use crate::config::model::{LbMethod, Location, ProxyPass, ProxyTarget, Upstream};
use crate::http::request::Body as ReqBody;
use crate::http::response::{Framing, Resp};

/// Headers that describe *this* hop and must never be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

thread_local! {
    /// Round-robin cursor per upstream, keyed by the upstream's address.
    static RR: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

pub async fn proxy(ctx: &mut Ctx<'_>, loc: &Arc<Location>, pp: &ProxyPass) -> Result<Reply, u16> {
    let conf = &loc.core.proxy;
    let started = Instant::now();

    let (addr_str, tls) = match &pp.target {
        ProxyTarget::Addr { host, port } => (format!("{host}:{port}"), pp.tls),
        ProxyTarget::Dynamic(t) => {
            let rendered = t.render(&*ctx);
            let (scheme_tls, rest) = match rendered.strip_prefix("https://") {
                Some(r) => (true, r.to_string()),
                None => (false, rendered.trim_start_matches("http://").to_string()),
            };
            let authority = rest.split('/').next().unwrap_or("").to_string();
            if authority.is_empty() {
                return Err(502);
            }
            let with_port = if authority.contains(':') {
                authority
            } else {
                format!("{}:{}", authority, if scheme_tls { 443 } else { 80 })
            };
            (with_port, scheme_tls)
        }
        ProxyTarget::Upstream(name) => {
            let up = ctx.http.upstreams.get(&**name).ok_or(502u16)?;
            (pick(ctx, up)?, pp.tls)
        }
    };

    if tls {
        // TLS to the upstream needs the connector plumbing that only the
        // listener side has today; say so instead of silently downgrading.
        return Err(502);
    }

    ctx.upstream_addr = addr_str.clone();

    let connect_to = Duration::from_secs(60).min(conf.connect_timeout.unwrap_or(Duration::from_secs(60)));
    let mut up = match tokio::time::timeout(connect_to, TcpStream::connect(&addr_str)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(502),
        Err(_) => return Err(504),
    };
    let _ = up.set_nodelay(true);

    // ---- request head -----------------------------------------------------
    let mut head = String::with_capacity(512);
    head.push_str(ctx.req.slice(ctx.buf, &ctx.req.method_raw));
    head.push(' ');
    head.push_str(&upstream_uri(ctx, loc, pp));
    head.push_str(if conf.http_version_11 {
        " HTTP/1.1\r\n"
    } else {
        " HTTP/1.0\r\n"
    });

    // proxy_set_header wins over anything inherited from the client.
    let mut overridden: Vec<String> = Vec::with_capacity(conf.set_headers.len() + 1);
    let mut host_set = false;
    for (name, tmpl) in &conf.set_headers {
        let value = tmpl.render(&*ctx);
        overridden.push(name.to_ascii_lowercase());
        if name.eq_ignore_ascii_case("host") {
            host_set = true;
        }
        // An empty value means "do not send this header at all".
        if value.is_empty() {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    if !host_set {
        // nginx's default is `proxy_set_header Host $proxy_host`.
        head.push_str("Host: ");
        head.push_str(host_of(&addr_str));
        head.push_str("\r\n");
    }

    for h in &ctx.req.headers {
        let name = ctx.req.slice(ctx.buf, &h.name);
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str())
            || lower == "host"
            || overridden.contains(&lower)
            || conf.hide_headers.iter().any(|x| &**x == lower.as_str())
        {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(ctx.req.slice(ctx.buf, &h.value));
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");

    if up.write_all(head.as_bytes()).await.is_err() {
        return Err(502);
    }

    // ---- request body -----------------------------------------------------
    // Whatever of the body already sits in the connection buffer is forwarded
    // first; the rest is not read here because the connection layer owns the
    // socket. Bodies larger than the buffered prefix are truncated for now.
    if let ReqBody::Length(n) = ctx.req.body {
        let available = ctx.buf.len().saturating_sub(ctx.req.head_len);
        let take = (n as usize).min(available);
        if take > 0 {
            let start = ctx.req.head_len;
            if up.write_all(&ctx.buf[start..start + take]).await.is_err() {
                return Err(502);
            }
        }
    }
    let _ = up.flush().await;

    // ---- response head ----------------------------------------------------
    let read_to = conf.read_timeout.unwrap_or(Duration::from_secs(60));
    let mut buf = Vec::with_capacity(8192);
    let head_len;
    let mut status;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut upstream_chunked = false;
    let mut upstream_len: Option<u64> = None;

    loop {
        let mut chunk = [0u8; 8192];
        let n = match tokio::time::timeout(read_to, up.read(&mut chunk)).await {
            Ok(Ok(0)) => return Err(502),
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return Err(502),
            Err(_) => return Err(504),
        };
        buf.extend_from_slice(&chunk[..n]);

        let mut hbuf = [httparse::EMPTY_HEADER; 96];
        let mut r = httparse::Response::new(&mut hbuf);
        match r.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                head_len = len;
                status = r.code.unwrap_or(502);
                for h in r.headers.iter() {
                    if h.name.is_empty() {
                        break;
                    }
                    let name = h.name.to_string();
                    let value = String::from_utf8_lossy(h.value).into_owned();
                    let lower = name.to_ascii_lowercase();
                    if lower == "transfer-encoding" {
                        upstream_chunked = value.eq_ignore_ascii_case("chunked");
                        continue;
                    }
                    if lower == "content-length" {
                        upstream_len = value.trim().parse().ok();
                        continue;
                    }
                    if HOP_BY_HOP.contains(&lower.as_str()) {
                        continue;
                    }
                    if conf.hide_headers.iter().any(|x| &**x == lower.as_str()) {
                        continue;
                    }
                    headers.push((name, value));
                }
                break;
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() > 64 * 1024 {
                    return Err(502);
                }
            }
            Err(_) => return Err(502),
        }
    }

    if status == 0 {
        status = 502;
    }
    ctx.upstream_status = status;
    ctx.upstream_time = started.elapsed().as_secs_f64();

    let mut resp = Resp::new();
    resp.status = status;
    for (n, v) in headers {
        resp.header(&n, &v);
    }

    let pre = buf[head_len..].to_vec();

    // Framing is decided here rather than by `Reply::frame`, so a chunked
    // upstream body passes through byte-for-byte instead of being decoded and
    // re-encoded on the way out.
    if upstream_chunked {
        resp.framing = Framing::Chunked;
        Ok(Reply::new(
            resp,
            Body::Stream { pre, io: Box::new(up), len: None },
        ))
    } else if let Some(n) = upstream_len {
        resp.framing = Framing::Length(n);
        let remaining = n.saturating_sub(pre.len() as u64);
        if remaining == 0 {
            Ok(Reply::new(resp, Body::Bytes(pre)))
        } else {
            Ok(Reply::new(
                resp,
                Body::Stream { pre, io: Box::new(up), len: Some(n) },
            ))
        }
    } else {
        // No length and no chunking: the body ends when the upstream closes,
        // so our own response must close too.
        resp.framing = Framing::UntilClose;
        resp.keep_alive = false;
        Ok(Reply::new(
            resp,
            Body::Stream { pre, io: Box::new(up), len: None },
        ))
    }
}

/// Builds the URI sent upstream.
///
/// `proxy_pass http://x/` (with a URI part) replaces the matched location
/// prefix; without one, the request URI passes through unchanged. This is the
/// single most misunderstood nginx behaviour, hence the explicit split.
fn upstream_uri(ctx: &Ctx<'_>, loc: &Arc<Location>, pp: &ProxyPass) -> String {
    let mut out = String::with_capacity(ctx.uri.len() + 32);
    match &pp.uri {
        Some(t) => {
            let base = t.render(ctx);
            out.push_str(&base);
            if let Some(prefix) = loc.matcher.prefix() {
                // The trailing slash form appends the unmatched remainder.
                if base.ends_with('/') {
                    let rest = ctx.uri.get(prefix.len()..).unwrap_or("");
                    out.push_str(rest.trim_start_matches('/'));
                }
            }
        }
        None => out.push_str(&ctx.uri),
    }
    if !ctx.args.is_empty() {
        out.push('?');
        out.push_str(&ctx.args);
    }
    out
}

fn host_of(addr: &str) -> &str {
    addr
}

/// Chooses an upstream server according to the configured method.
fn pick(ctx: &Ctx<'_>, up: &Arc<Upstream>) -> Result<String, u16> {
    let live: Vec<&crate::config::model::UpstreamServer> =
        up.servers.iter().filter(|s| !s.down && !s.backup).collect();
    let pool = if live.is_empty() {
        // Everything primary is down: fall back to the backup set.
        up.servers.iter().filter(|s| !s.down).collect::<Vec<_>>()
    } else {
        live
    };
    if pool.is_empty() {
        return Err(502);
    }

    let idx = match up.method {
        LbMethod::IpHash => {
            let mut h: u64 = 0;
            for b in addr_bytes(&ctx.remote) {
                h = h.wrapping_mul(31).wrapping_add(b as u64);
            }
            (h % pool.len() as u64) as usize
        }
        LbMethod::Random => {
            // Cheap per-connection jitter; no RNG dependency needed.
            (ctx.conn_id as usize).wrapping_add(ctx.conn_requests as usize) % pool.len()
        }
        // LeastConn needs live connection counts we do not track yet; round
        // robin is the honest fallback rather than a wrong approximation.
        LbMethod::RoundRobin | LbMethod::LeastConn => {
            let key = Arc::as_ptr(up) as usize;
            RR.with(|rr| {
                let mut m = rr.borrow_mut();
                let c = m.entry(key).or_insert(0);
                let i = *c;
                *c = c.wrapping_add(1);
                i % pool.len()
            })
        }
    };

    let s = pool[idx];
    let addr = s.addr.to_string();
    Ok(if addr.contains(':') {
        addr
    } else {
        format!("{addr}:80")
    })
}

fn addr_bytes(a: &SocketAddr) -> Vec<u8> {
    match a {
        SocketAddr::V4(v) => v.ip().octets().to_vec(),
        SocketAddr::V6(v) => v.ip().octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_list_is_lowercase_and_complete() {
        for h in HOP_BY_HOP {
            assert_eq!(*h, h.to_ascii_lowercase());
        }
        assert!(HOP_BY_HOP.contains(&"connection"));
        assert!(HOP_BY_HOP.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP.contains(&"upgrade"));
    }
}

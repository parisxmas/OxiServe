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

use super::transport::Stream;

use super::ctx::Ctx;
use super::reply::{Body, Reply};
use crate::config::model::{LbMethod, Location, ProxyPass, ProxyTarget, Upstream};
use super::upstream::{self as up_state, InFlightGuard};
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

    // ---- cache lookup -----------------------------------------------------
    // Done before a connection is even considered: a hit must not cost an
    // upstream round trip, which is the entire point.
    let cache = cache_context(ctx, loc);
    // An expired entry is kept in hand: `proxy_cache_use_stale` may let it
    // answer if the refresh fails, which is the difference between a stale
    // page and a 502.
    let mut stale: Option<cache::Decoded> = None;
    // Never read, and that is the point: this binding holds the fetch lock for
    // the rest of the function and releases it on drop, whether the fetch
    // succeeds, fails, or returns early. The leading underscore keeps the
    // compiler quiet without shortening its life (a bare `_` would drop it
    // immediately and silently disable the thundering-herd protection).
    let mut _fetch_lock: Option<cache::FetchLock> = None;

    if let Some(cc) = &cache {
        if cc.bypassed {
            ctx.cache_status = Some(cache::CacheStatus::Bypass);
        } else {
            match cache::load(&cc.zone, &cc.key, cc.hash) {
                Some((entry, cache::CacheStatus::Hit)) => {
                    ctx.cache_status = Some(cache::CacheStatus::Hit);
                    return Ok(cached_reply(entry));
                }
                Some((entry, _)) => {
                    ctx.cache_status = Some(cache::CacheStatus::Expired);
                    stale = Some(entry);
                }
                None => ctx.cache_status = Some(cache::CacheStatus::Miss),
            }

            if cc.conf.lock {
                match cache::try_lock(&cc.zone.name, cc.hash) {
                    // We own the refresh.
                    Some(l) => _fetch_lock = Some(l),
                    None => {
                        // Someone else is already fetching this key. With
                        // `use_stale updating` we answer from the old copy
                        // immediately rather than queueing — that is the whole
                        // point of the combination.
                        if let Some(entry) = stale.take() {
                            if cache::stale_allowed(&cc.conf.use_stale, cache::StaleWhen::Updating) {
                                ctx.cache_status = Some(cache::CacheStatus::Stale);
                                return Ok(cached_reply(entry));
                            }
                            stale = Some(entry);
                        }
                        // Otherwise wait for the winner to populate the entry.
                        if let Some(r) = wait_for_fetch(ctx, cc).await {
                            return Ok(r);
                        }
                        // Timed out waiting: fetch it ourselves rather than
                        // failing, accepting a duplicate upstream request.
                    }
                }
            }
        }
    }

    // When the target is an upstream we keep hold of the chosen peer, so the
    // outcome of this request can be fed back into its health state.
    let mut chosen: Option<(&Arc<Upstream>, usize)> = None;
    let (addr_str, tls) = match &pp.target {
        ProxyTarget::Addr { host, port } => (format!("{host}:{port}"), pp.tls),
        ProxyTarget::Unix(path) => (format!("unix:{path}"), false),
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
            let idx = select_peer(ctx, up)?;
            let addr = peer_addr(&up.servers[idx].addr);
            chosen = Some((up, idx));
            (addr, pp.tls)
        }
    };

    if tls {
        // TLS to the upstream needs the connector plumbing that only the
        // listener side has today; say so instead of silently downgrading.
        return Err(502);
    }

    ctx.upstream_addr = addr_str.clone();

    // Counted for the whole life of the request, released even on an early
    // return — this is the number `least_conn` balances on.
    let _in_flight = chosen.map(|(u, i)| InFlightGuard::enter(&u.health[i]));

    let keepalive = chosen.map(|(u, _)| u.keepalive).unwrap_or(0);
    let connect_to = conf.connect_timeout.unwrap_or(Duration::from_secs(60));

    // A pooled connection skips the handshake entirely.
    let (mut up, reused) = match up_state::take(&addr_str) {
        Some(s) => (s, true),
        None => match tokio::time::timeout(connect_to, Stream::connect(&addr_str)).await {
            Ok(Ok(s)) => (s, false),
            Ok(Err(_)) | Err(_) => {
                // A refused or timed-out connection is exactly what passive
                // health tracking exists to notice.
                note_failure(chosen, ctx);
                // An old copy beats an error page, when the config says so.
                if let Some(r) = try_stale(ctx, &cache, &mut stale, cache::StaleWhen::Error) {
                    return Ok(r);
                }
                return Err(502);
            }
        },
    };

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
            || lower == "content-length"
            || lower == "expect"
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
    // The decoded body length replaces whatever framing the client used.
    if !ctx.body.is_empty() {
        head.push_str("Content-Length: ");
        crate::http::response::push_num(&mut head, ctx.body.len() as u64);
        head.push_str("\r\n");
    }
    // With a pool we must ask the upstream to keep the connection, and that
    // only works on HTTP/1.1.
    let want_keepalive = keepalive > 0 && conf.http_version_11;
    if want_keepalive {
        head.push_str("Connection: keep-alive\r\n\r\n");
    } else {
        head.push_str("Connection: close\r\n\r\n");
    }

    if up.write_all(head.as_bytes()).await.is_err() {
        // Only counted against the peer when we opened the connection
        // ourselves; a reused one that died is our bookkeeping, not their
        // fault. `take` probes for liveness, so this is already rare.
        if !reused {
            note_failure(chosen, ctx);
        }
        return Err(502);
    }

    // ---- request body -----------------------------------------------------
    // The connection layer has already read and de-chunked the whole body, so
    // it forwards as a plain Content-Length regardless of how it arrived.
    if !ctx.body.is_empty() && up.write_all(ctx.body).await.is_err() {
        note_failure(chosen, ctx);
        return Err(502);
    }
    let _ = up.flush().await;

    // ---- response head ----------------------------------------------------
    // Header values are needed twice when caching (once to answer, once to
    // store), so they are collected rather than streamed straight through.
    let read_to = conf.read_timeout.unwrap_or(Duration::from_secs(60));
    let mut buf = Vec::with_capacity(8192);
    let head_len;
    let mut status;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut upstream_chunked = false;
    let mut upstream_len: Option<u64> = None;
    let mut upstream_said_close = false;

    loop {
        let mut chunk = [0u8; 8192];
        let n = match tokio::time::timeout(read_to, up.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                // EOF before a response. On a reused connection that is the
                // peer having closed it while idle, not a fault of theirs.
                if !(reused && buf.is_empty()) {
                    note_failure(chosen, ctx);
                }
                // A backend that accepts and then closes without answering is
                // a common way for one to die, and it is an `error` for
                // use_stale exactly like a refused connection.
                if let Some(r) = try_stale(ctx, &cache, &mut stale, cache::StaleWhen::Error) {
                    return Ok(r);
                }
                return Err(502);
            }
            Ok(Ok(n)) => n,
            Ok(Err(_)) => {
                if !(reused && buf.is_empty()) {
                    note_failure(chosen, ctx);
                }
                if let Some(r) = try_stale(ctx, &cache, &mut stale, cache::StaleWhen::Error) {
                    return Ok(r);
                }
                return Err(502);
            }
            Err(_) => {
                note_failure(chosen, ctx);
                if let Some(r) = try_stale(ctx, &cache, &mut stale, cache::StaleWhen::Timeout) {
                    return Ok(r);
                }
                return Err(504);
            }
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
                    if lower == "connection" {
                        upstream_said_close = value.eq_ignore_ascii_case("close");
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
                    note_failure(chosen, ctx);
                    return Err(502);
                }
            }
            Err(_) => {
                note_failure(chosen, ctx);
                if let Some(r) =
                    try_stale(ctx, &cache, &mut stale, cache::StaleWhen::InvalidHeader)
                {
                    return Ok(r);
                }
                return Err(502);
            }
        }
    }

    if status == 0 {
        status = 502;
    }
    // A complete response head is proof the peer is serving; clear its
    // failure count. nginx treats 5xx as a failure only with
    // proxy_next_upstream, which we do not implement, so a 500 from a live
    // backend is not held against it.
    if let Some((u, i)) = chosen {
        u.health[i].record_success();
    }
    ctx.upstream_status = status;

    // `proxy_cache_use_stale http_5xx` — a working backend returning an error
    // is still a reason to prefer the last good copy.
    if status >= 400 {
        if let Some(r) = try_stale(ctx, &cache, &mut stale, cache::StaleWhen::Status(status)) {
            return Ok(r);
        }
    }
    ctx.upstream_time = started.elapsed().as_secs_f64();

    let mut resp = Resp::new();
    resp.status = status;
    let resp_headers = headers.clone();
    for (n, v) in headers {
        resp.header(&n, &v);
    }

    let pre = buf[head_len..].to_vec();

    // Store, when the response is cacheable and fully in hand. Only bodies
    // that arrived complete are cached: writing a partial entry would be
    // worse than not caching at all.
    let store_ttl = cache.as_ref().and_then(|cc| cacheable_ttl(cc, ctx, status));

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
            // The entire body already arrived with the head, so the connection
            // is at a clean boundary and can be reused. Only ever pooled here:
            // returning one mid-body would corrupt whoever picked it up next.
            if want_keepalive && !upstream_said_close {
                up_state::put(&addr_str, up, keepalive);
            }
            if let (Some(cc), Some(ttl)) = (&cache, store_ttl) {
                let entry = cache::encode_entry(&cc.key, status, &resp_headers, &pre, ttl);
                let _ = cache::store(&cc.zone, cc.hash, &entry);
            }
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
    // `unix:/run/app.sock` is not a valid Host value; nginx sends the socket
    // path's basename-free form, so fall back to a stable placeholder.
    if addr.starts_with("unix:") {
        "localhost"
    } else {
        addr
    }
}


fn addr_bytes(a: &Option<SocketAddr>) -> Vec<u8> {
    match a {
        Some(SocketAddr::V4(v)) => v.ip().octets().to_vec(),
        Some(SocketAddr::V6(v)) => v.ip().octets().to_vec(),
        // A Unix peer has no address, so every such client hashes alike.
        None => Vec::new(),
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

/// Records a failed attempt against the chosen peer, if the target was an
/// upstream. A literal `proxy_pass` address has no health state to update.
fn note_failure(chosen: Option<(&Arc<Upstream>, usize)>, _ctx: &Ctx<'_>) {
    if let Some((up, i)) = chosen {
        let now_ms = Instant::now()
            .saturating_duration_since(up.origin)
            .as_millis() as u64;
        let s = &up.servers[i];
        up.health[i].record_failure(
            now_ms,
            s.max_fails,
            s.fail_timeout.as_millis() as u64,
        );
    }
}


/// Peer address in the form `Stream::connect` understands.
pub fn peer_addr(addr: &str) -> String {
    if addr.starts_with("unix:") || addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:80")
    }
}

/// Chooses a peer via the shared health/load state.
pub fn select_peer(ctx: &Ctx<'_>, up: &Arc<Upstream>) -> Result<usize, u16> {
    let hash = match up.method {
        LbMethod::IpHash => {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in addr_bytes(&ctx.remote) {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            Some(h)
        }
        _ => None,
    };
    let cursor = RR.with(|rr| {
        let mut m = rr.borrow_mut();
        let c = m.entry(Arc::as_ptr(up) as usize).or_insert(0);
        let i = *c;
        *c = c.wrapping_add(1);
        i
    });
    up_state::select(up, Instant::now(), hash, cursor).ok_or(502)
}

use super::cache;

/// Everything the cache needs for one request, resolved once.
struct CacheCtx {
    zone: Arc<cache::Zone>,
    key: String,
    hash: cache::KeyHash,
    bypassed: bool,
    conf: crate::config::model::ProxyCacheConf,
}

/// Resolves the caching context, or `None` when this request is not cacheable
/// at all (`proxy_cache off`, or a method outside `proxy_cache_methods`).
fn cache_context(ctx: &Ctx<'_>, loc: &Arc<Location>) -> Option<CacheCtx> {
    let c = &loc.core.proxy_cache;
    let zone_name = c.zone.as_ref()?;
    let zone = ctx.http.cache_zones.get(&**zone_name)?.clone();

    // nginx caches only the configured methods; a POST must never be served
    // from, or written to, the cache.
    let method = ctx.req.method.as_str();
    if !c.methods.iter().any(|m| &**m == method) {
        return None;
    }

    let key = c.key.render(ctx);
    let hash = cache::KeyHash::of(&key);
    // `proxy_cache_bypass` skips the lookup but still allows storing.
    let bypassed = c.bypass.iter().any(|t| truthy(&t.render(ctx)));

    Some(CacheCtx { zone, key, hash, bypassed, conf: c.clone() })
}

/// nginx's truth test for these directives: non-empty and not "0".
fn truthy(s: &str) -> bool {
    !s.is_empty() && s != "0"
}

/// How long this response may be cached, or `None` if it must not be.
fn cacheable_ttl(cc: &CacheCtx, ctx: &Ctx<'_>, status: u16) -> Option<Duration> {
    // `proxy_no_cache` wins over everything.
    if cc.conf.no_cache.iter().any(|t| truthy(&t.render(ctx))) {
        return None;
    }
    // `proxy_cache_min_uses` — a URL requested once does not earn a disk write.
    if cc.conf.min_uses > 1 && cache::note_use(&cc.zone, cc.hash) < cc.conf.min_uses {
        return None;
    }
    // First an exact status match, then a catch-all `proxy_cache_valid` entry.
    cc.conf
        .valid
        .iter()
        .find(|v| v.codes.contains(&status))
        .or_else(|| cc.conf.valid.iter().find(|v| v.codes.is_empty()))
        .map(|v| v.ttl)
}

/// Builds a response from a cache entry.
fn cached_reply(entry: cache::Decoded) -> Reply {
    let mut resp = Resp::new();
    resp.status = entry.status;
    for (n, v) in &entry.headers {
        // Framing is decided from the body we actually hold.
        if n.eq_ignore_ascii_case("content-length") || n.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        resp.header(n, v);
    }
    resp.framing = Framing::Length(entry.body.len() as u64);
    Reply::new(resp, Body::Bytes(entry.body))
}

/// Serves the retained stale entry when `proxy_cache_use_stale` covers this
/// outcome. Returns `None` to let the caller surface the error normally.
fn try_stale(
    ctx: &mut Ctx<'_>,
    cache: &Option<CacheCtx>,
    stale: &mut Option<cache::Decoded>,
    outcome: cache::StaleWhen,
) -> Option<Reply> {
    let cc = cache.as_ref()?;
    if !cache::stale_allowed(&cc.conf.use_stale, outcome) {
        return None;
    }
    let entry = stale.take()?;
    ctx.cache_status = Some(cache::CacheStatus::Stale);
    Some(cached_reply(entry))
}

/// Waits for whoever holds the fetch lock to populate the entry.
///
/// Polls rather than using a condition variable: a cache fill takes
/// milliseconds, the wait is bounded by `proxy_cache_lock_timeout`, and
/// polling keeps the lock table free of per-key wakers. Returns the response
/// once it appears, or `None` on timeout so the caller fetches it itself —
/// a slow refresh must not turn into a failed request.
async fn wait_for_fetch(ctx: &mut Ctx<'_>, cc: &CacheCtx) -> Option<Reply> {
    const POLL: Duration = Duration::from_millis(10);
    let deadline = Instant::now() + cc.conf.lock_timeout;

    while Instant::now() < deadline {
        tokio::time::sleep(POLL).await;
        if !cache::is_locked(&cc.zone.name, cc.hash) {
            // The holder finished; the entry should be there now.
            if let Some((entry, cache::CacheStatus::Hit)) =
                cache::load(&cc.zone, &cc.key, cc.hash)
            {
                ctx.cache_status = Some(cache::CacheStatus::Hit);
                return Some(cached_reply(entry));
            }
            // It released without storing (an error, or uncacheable). Fetch.
            return None;
        }
    }
    None
}

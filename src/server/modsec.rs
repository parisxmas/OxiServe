//! Runs the configured ModSecurity rules against a request and its response.
//!
//! All five phases are wired. The transaction opened for the request phases is
//! parked in the [`Ctx`] and picked up again for the response, because CRS
//! accumulates an anomaly score across phases and a second transaction would
//! start that count from zero — a request that scored 4 on the way in and 3 on
//! the way out has to reach the blocking threshold, not look like two harmless
//! halves.

use std::sync::Arc;

use crate::config::model::CoreConf;
use crate::http::response::Resp;
use crate::server::ctx::Ctx;
use crate::server::reply::{Body, Reply};
use crate::waf::Verdict;

/// The outcome, when the rules had something to say. `None` means carry on.
pub enum Blocked {
    Status(u16),
    Redirect(Reply),
}

/// Phases 1 and 2: connection, URI, request headers, request body.
///
/// On `None` the transaction is left in `ctx.modsec` for [`inspect_response`].
pub fn inspect_request(ctx: &mut Ctx<'_>, core: &CoreConf) -> Option<Blocked> {
    let engine: &Arc<crate::waf::Engine> = core.modsecurity_rules.as_ref()?;
    if !core.modsecurity {
        return None;
    }

    let mut t = engine.transaction()?;

    // A Unix-socket client has no address at all. ModSecurity wants
    // *something* for REMOTE_ADDR, and inventing a routable-looking address
    // would be worse than an obviously local one.
    let (client, client_port) = match ctx.remote {
        Some(a) => (a.ip().to_string(), a.port()),
        None => ("127.0.0.1".to_string(), 0),
    };
    let (server, server_port) = match ctx.local {
        Some(a) => (a.ip().to_string(), a.port()),
        None => ("127.0.0.1".to_string(), 0),
    };
    t.connection(&client, client_port, &server, server_port);

    // The query string has to travel with the path: `ARGS` is what the
    // majority of CRS rules read, and libmodsecurity parses it out of the URI
    // it is handed here rather than from anything passed separately.
    let uri = if ctx.args.is_empty() {
        ctx.uri.clone()
    } else {
        format!("{}?{}", ctx.uri, ctx.args)
    };
    let version = if ctx.req.minor == 0 { "1.0" } else { "1.1" };
    t.uri(&uri, ctx.req.method.as_str(), version);

    for h in &ctx.req.headers {
        t.request_header(&ctx.buf[h.name.clone()], &ctx.buf[h.value.clone()]);
    }

    let verdict = match t.process_request_headers() {
        Verdict::Allow => t.request_body(ctx.body),
        other => other,
    };

    match verdict {
        Verdict::Allow => {
            ctx.modsec = Some(t);
            None
        }
        // A blocked request still gets its logging phase; the transaction then
        // drops here, because there is no response of ours to inspect.
        other => {
            t.logging();
            Some(blocked_from(other))
        }
    }
}

/// Phases 3, 4 and 5: response headers, response body, logging.
///
/// Takes the reply by `&mut` because inspecting a body means having it in
/// memory, and a streamed body has to be put back together afterwards.
pub async fn inspect_response(
    ctx: &mut Ctx<'_>,
    core: &CoreConf,
    reply: &mut Reply,
) -> Option<Blocked> {
    let mut t = ctx.modsec.take()?;

    for (name, value) in reply.resp.iter() {
        t.response_header(name.as_bytes(), value.as_bytes());
    }
    let version = if ctx.req.minor == 0 { "1.0" } else { "1.1" };

    let mut verdict = t.process_response_headers(reply.resp.status, version);

    // Phase 4 only when asked for. Reading a body that `sendfile` would
    // otherwise hand straight to the kernel is a real cost, and one an
    // operator should opt into rather than discover in a flame graph.
    if verdict == Verdict::Allow && core.modsecurity_response_body {
        match materialise(&mut reply.body, core.modsecurity_response_body_limit).await {
            Some(bytes) => verdict = t.response_body(&bytes),
            // Over the limit, or a body shape that cannot be read back. The
            // rules simply do not see it; saying so is better than a silent
            // gap, and better than buffering without bound.
            None => {}
        }
    }

    t.logging();

    match verdict {
        Verdict::Allow => None,
        other => Some(blocked_from(other)),
    }
}

fn blocked_from(v: Verdict) -> Blocked {
    match v {
        Verdict::Block { status } => Blocked::Status(status),
        Verdict::Redirect { status, url } => {
            let mut resp = Resp::new();
            resp.status = status;
            resp.header("Location", &url);
            resp.header("Content-Length", "0");
            Blocked::Redirect(Reply::new(resp, Body::Bytes(Vec::new())))
        }
        // Only ever called with a disruptive verdict.
        Verdict::Allow => Blocked::Status(403),
    }
}

/// Reads a response body into memory so the rules can see it, leaving `body`
/// able to serve the same bytes afterwards.
///
/// Returns `None` when the body is longer than `limit`, or when it is a shape
/// that cannot be read without changing what the client receives.
async fn materialise(body: &mut Body, limit: usize) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    match body {
        Body::Empty => Some(Vec::new()),

        // A tunnel, not a response body. Reading it would consume the client's
        // connection, and there is no phase-4 notion of "the body" once the
        // protocol has been handed over.
        Body::Upgraded { .. } => None,
        Body::Bytes(v) => (v.len() <= limit).then(|| v.clone()),

        // Already resident: the map is the page cache, so this reads no more
        // than serving it would.
        Body::Mmap { map, range } => {
            (range.len() <= limit).then(|| map[range.clone()].to_vec())
        }

        // A file the serving path re-reads anyway. Reading it here costs one
        // extra pass; over the limit it is left alone entirely.
        Body::Inline { file, offset, len } | Body::File { file, offset, len } => {
            if *len as usize > limit {
                return None;
            }
            let (file, offset, len) = (file.clone(), *offset, *len as usize);
            // Blocking pread on the worker thread would stall the runtime.
            tokio::task::spawn_blocking(move || {
                use std::os::unix::fs::FileExt;
                let mut buf = vec![0u8; len];
                file.read_exact_at(&mut buf, offset).ok()?;
                Some(buf)
            })
            .await
            .ok()
            .flatten()
        }

        // The proxied case, and the one response-body rules exist for: a
        // backend leaking a stack trace. The bytes read here are put back into
        // `pre`, which the writer drains before touching `io`, so the client
        // still receives exactly what it would have.
        Body::Stream { pre, io, len } => {
            if let Some(n) = len {
                if *n as usize > limit {
                    return None;
                }
            }
            let mut buf = std::mem::take(pre);
            if buf.len() > limit {
                *pre = buf;
                return None;
            }
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                let n = match io.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    // A read error here is the response failing, not a rule
                    // decision. Put back what we have and let the writer hit
                    // the same error.
                    Err(_) => {
                        *pre = buf;
                        return None;
                    }
                };
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > limit {
                    *pre = buf;
                    return None;
                }
            }
            *pre = buf.clone();
            // The length is known now, which lets the writer frame it exactly.
            *len = Some(buf.len() as u64);
            Some(buf)
        }
    }
}

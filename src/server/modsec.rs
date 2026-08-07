//! Runs the configured ModSecurity rules against a request.
//!
//! Only the request phases are wired: connection, URI, request headers and
//! request body. That is where CRS does nearly all of its blocking, but it is
//! *not* the whole engine — response-phase rules, the ones that catch a
//! backend leaking SQL errors or stack traces, do not run yet. The README says
//! so plainly rather than letting a `SecRule RESPONSE_BODY` in a rules file
//! look like it is being enforced.

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

/// Evaluates the request. Returns `None` when it should proceed.
pub fn inspect(ctx: &Ctx<'_>, core: &CoreConf) -> Option<Blocked> {
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

    // Run the logging phase whatever the verdict — an audit log that records
    // only blocks is not much of an audit log, and rules that merely warn have
    // nowhere else to surface.
    t.logging();

    match verdict {
        Verdict::Allow => None,
        Verdict::Block { status } => Some(Blocked::Status(status)),
        Verdict::Redirect { status, url } => {
            let mut resp = Resp::new();
            resp.status = status;
            resp.header("Location", &url);
            resp.header("Content-Length", "0");
            Some(Blocked::Redirect(Reply::new(resp, Body::Bytes(Vec::new()))))
        }
    }
}

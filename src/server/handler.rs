//! Request routing: the rewrite phase, location search, and action dispatch.
//!
//! This is nginx's request lifecycle in miniature:
//!
//! 1. server-level `rewrite` / `if` run first (nginx's *server rewrite* phase);
//! 2. the location is chosen (see [`LocSet::find`]);
//! 3. location-level `rewrite` / `if` run;
//! 4. `try_files` probes the filesystem;
//! 5. the location's action produces a reply;
//! 6. an error status is mapped through `error_page`, which re-enters at (2).
//!
//! [`LocSet::find`]: crate::config::model::LocSet::find

use std::sync::Arc;

use super::ctx::Ctx;
use super::files;
use super::reply::{Body, Reply};
use crate::config::model::*;
use crate::config::vars::VarSource;
use crate::http::response::{push_num, Resp};
use crate::http::status;

/// Bounds internal redirects, so a `try_files` cycle answers 500 rather than
/// spinning a worker forever. nginx uses the same limit.
const MAX_INTERNAL_REDIRECTS: u32 = 10;

/// Largest file compressed on the fly. Above this the CPU and the memory to
/// hold both copies cost more than the bandwidth saved, and `sendfile` — which
/// compression rules out — is the better trade.
const GZIP_MAX_FILE: u64 = 8 * 1024 * 1024;

/// Outcome of one routing pass.
enum Step {
    Done(Reply),
    Fail(u16),
    /// Re-run location selection against a new URI.
    Internal(String),
    /// Jump to a named `@location`.
    Named(Arc<str>),
}

pub async fn handle(ctx: &mut Ctx<'_>) -> Reply {
    // Phase 1: server-level rewrites and conditions.
    //
    // The `Arc` is cloned, not the directive lists. Cloning the `Vec<Rewrite>`
    // here deep-copied every compiled regex on every request; bumping a
    // refcount instead ends the borrow on `ctx` just as effectively.
    let srv = ctx.server.clone();
    if !srv.rewrites.is_empty() {
        if let Some(step) = run_rewrites(ctx, &srv.rewrites) {
            if let Some(r) = finish(ctx, step).await {
                return r;
            }
        }
    }
    if !srv.ifs.is_empty() {
        if let Some(step) = run_ifs(ctx, &srv.ifs) {
            if let Some(r) = finish(ctx, step).await {
                return r;
            }
        }
    }

    let mut named: Option<Arc<str>> = None;
    // An `auth_request` subrequest counts as internal from its first routing
    // pass. The auth location is almost always marked `internal;` — that is
    // what keeps clients from calling the authoriser directly — so entering it
    // as an outside request would 404 every time and turn every verdict into a
    // 500.
    let mut internal = ctx.auth_depth > 0;
    let mut status_override: Option<u16> = None;

    loop {
        let step = match &named {
            Some(n) => match ctx.server.locations.named.get(&**n) {
                Some(loc) => {
                    let loc = loc.clone();
                    // `route` records the matched location for everything that
                    // reads it afterwards — `add_header`, `expires`,
                    // `$document_root`. Jumping straight to a named location
                    // skipped that, so a `@name` reached by `error_page` was
                    // decorated with the *server's* directives instead of its
                    // own and its `add_header` silently did nothing.
                    ctx.matched = Some(loc.clone());
                    dispatch(ctx, &loc, true).await
                }
                None => Step::Fail(500),
            },
            None => route(ctx, internal).await,
        };

        match step {
            Step::Done(mut r) => {
                if let Some(s) = status_override {
                    r.resp.status = s;
                }
                return decorate(ctx, r);
            }
            Step::Internal(uri) => {
                ctx.redirects += 1;
                if ctx.redirects > MAX_INTERNAL_REDIRECTS {
                    return decorate(ctx, error_reply(ctx, 500));
                }
                ctx.uri = uri;
                named = None;
                internal = true;
            }
            Step::Named(n) => {
                ctx.redirects += 1;
                if ctx.redirects > MAX_INTERNAL_REDIRECTS {
                    return decorate(ctx, error_reply(ctx, 500));
                }
                named = Some(n);
                internal = true;
            }
            Step::Fail(code) => {
                // error_page can turn this into another routing pass.
                match error_page_for(ctx, code) {
                    Some(ErrorRoute::Uri(uri, replace)) => {
                        ctx.redirects += 1;
                        if ctx.redirects > MAX_INTERNAL_REDIRECTS {
                            return decorate(ctx, error_reply(ctx, 500));
                        }
                        status_override = replace;
                        ctx.uri = uri;
                        named = None;
                        internal = true;
                    }
                    Some(ErrorRoute::Named(n, replace)) => {
                        ctx.redirects += 1;
                        if ctx.redirects > MAX_INTERNAL_REDIRECTS {
                            return decorate(ctx, error_reply(ctx, 500));
                        }
                        status_override = replace;
                        named = Some(n);
                        internal = true;
                    }
                    Some(ErrorRoute::Redirect(url, replace)) => {
                        let mut resp = Resp::new();
                        resp.status = replace.unwrap_or(302);
                        resp.header("Location", &url);
                        return decorate(ctx, Reply::new(resp, Body::Empty));
                    }
                    None => return decorate(ctx, error_reply(ctx, code)),
                }
            }
        }
    }
}

/// Selects a location and dispatches to it.
///
/// The chosen location is cached on the context. Response decoration and
/// `error_page` lookup both need it, and re-running the location search for
/// each meant matching every prefix and regex three times per request.
async fn route(ctx: &mut Ctx<'_>, internal: bool) -> Step {
    // The URI is moved out of `ctx` rather than cloned so the match can hold a
    // reference to it while `ctx` is mutated. It is put straight back.
    let uri = std::mem::take(&mut ctx.uri);

    let mut caps: Option<Vec<String>> = None;
    let found = match ctx.server.locations.find(&uri) {
        None => None,
        Some((loc, c)) => {
            if let Some(c) = c {
                caps = Some(owned_captures(&c));
            }
            // Nested locations are searched only within the matched parent.
            let mut cur = loc.clone();
            loop {
                let next = match &cur.nested {
                    Some(nested) => nested
                        .find(&uri)
                        .map(|(inner, c)| (inner.clone(), c.map(|c| owned_captures(&c)))),
                    None => None,
                };
                match next {
                    Some((inner, c)) => {
                        if let Some(c) = c {
                            caps = Some(c);
                        }
                        cur = inner;
                    }
                    None => break,
                }
            }
            Some(cur)
        }
    };

    ctx.uri = uri;
    if let Some(c) = caps {
        ctx.captures = c;
    }
    ctx.matched = found.clone();

    let Some(loc) = found else {
        // No location matched, so `dispatch` never runs — but a `limit_req`
        // declared at server level still applies. Missing this meant a config
        // with no location block was not rate limited at all.
        let srv = ctx.server.clone();
        if !internal {
            if let Some(status) = apply_limits(ctx, &srv.core).await {
                return Step::Fail(status);
            }
        }
        // Fall back to the server's own action or static serving.
        return match &ctx.server.action {
            Action::Return { status, body } => Step::Done(return_reply(ctx, *status, body.clone())),
            _ => served_to_step(files::serve(ctx, None).await),
        };
    };

    dispatch(ctx, &loc, internal).await
}

fn served_to_step(s: files::Served) -> Step {
    match s {
        files::Served::Reply(r) => Step::Done(r),
        files::Served::Internal(uri) => Step::Internal(uri),
        files::Served::Status(c) => Step::Fail(c),
    }
}

fn owned_captures(c: &regex::Captures<'_>) -> Vec<String> {
    (1..c.len())
        .map(|i| c.get(i).map(|m| m.as_str()).unwrap_or("").to_string())
        .collect()
}

async fn dispatch(ctx: &mut Ctx<'_>, loc: &Arc<Location>, internal: bool) -> Step {
    // `internal;` locations are reachable only via an internal redirect.
    if loc.core.internal && !internal {
        return Step::Fail(404);
    }

    // Limiting runs before any work is done for the request, and only on the
    // real client request — an internal redirect is the same request and must
    // not be charged twice.
    if !internal {
        if let Some(status) = apply_limits(ctx, &loc.core).await {
            return Step::Fail(status);
        }
    }

    if let Some(allowed) = &loc.allowed_methods {
        let m = ctx.req.method.as_str();
        // limit_except names the methods that stay unrestricted; GET implies HEAD.
        let ok = allowed.iter().any(|a| {
            &**a == m || (&**a == "GET" && ctx.req.method == crate::http::Method::Head)
        });
        if !ok {
            return Step::Fail(405);
        }
    }

    // Authorisation runs before any content work — that is the whole point of
    // delegating it — but after `limit_except`, so a method that is not
    // allowed here is refused without bothering the auth service.
    if let Some(uri) = &loc.core.auth_request {
        if let Err(code) = run_auth_request(ctx, uri, &loc.core).await {
            return Step::Fail(code);
        }
    }

    if let Some(step) = run_rewrites(ctx, &loc.rewrites) {
        match step {
            Step::Internal(_) | Step::Named(_) | Step::Done(_) | Step::Fail(_) => return step,
        }
    }
    if let Some(step) = run_ifs(ctx, &loc.ifs) {
        return step;
    }

    if let Some(tf) = &loc.try_files {
        if let Some(step) = run_try_files(ctx, loc, tf) {
            return step;
        }
    }

    match &loc.action {
        Action::Return { status, body } => Step::Done(return_reply(ctx, *status, body.clone())),
        Action::None => Step::Fail(404),
        Action::Proxy(p) => match super::proxy::proxy(ctx, loc, p).await {
            Ok(r) => Step::Done(r),
            Err(c) => Step::Fail(c),
        },
        Action::FastCgi(f) => match super::fastcgi::fastcgi(ctx, loc, f).await {
            Ok(r) => Step::Done(r),
            Err(c) => Step::Fail(c),
        },
        Action::Static => served_to_step(files::serve(ctx, Some(loc)).await),
    }
}

/// Runs an `auth_request` subrequest and decides whether to continue.
///
/// The subrequest is a fresh `GET` at the configured URI carrying the client's
/// headers and **no body**: the authorisation service is being asked about the
/// request, not asked to process it, and streaming a 2 GB upload past it would
/// be absurd. nginx makes the same choice.
///
/// `2xx` continues. `401` and `403` are returned to the client as they stand —
/// they are the service's answer, not our error. Anything else is a `500`,
/// because an authorisation service that cannot say yes or no has failed, and
/// failing open would be the one truly unacceptable outcome.
async fn run_auth_request(
    ctx: &mut Ctx<'_>,
    uri: &str,
    core: &CoreConf,
) -> Result<(), u16> {
    // An auth location that itself requires authorisation would recurse until
    // the stack ran out.
    if ctx.auth_depth > 0 {
        return Err(500);
    }

    // The client's headers travel with the subrequest — cookies and
    // `Authorization` are usually the whole basis for the decision — but never
    // the framing of a body that is not being sent.
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(ctx.req.headers.len());
    for h in &ctx.req.headers {
        let name = ctx.req.slice(ctx.buf, &h.name);
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "content-length" | "transfer-encoding" | "expect") {
            continue;
        }
        headers.push((name, ctx.req.slice(ctx.buf, &h.value)));
    }

    let (buf, req) = crate::http::request::Req::from_parts("GET", uri, &headers);
    let normalised = match crate::http::uri::normalize(req.path_str(&buf)) {
        Ok(u) => u,
        Err(_) => return Err(500),
    };

    let reply = {
        let mut sub = Ctx::new(
            &buf,
            &req,
            &[],
            ctx.http,
            ctx.server,
            normalised,
            ctx.remote,
            ctx.local,
            ctx.scheme,
            ctx.conn_id,
            ctx.conn_requests,
        );
        sub.auth_depth = ctx.auth_depth + 1;
        // The full pipeline, so the auth location can be a `proxy_pass`, a
        // `fastcgi_pass`, a `return`, or anything else a location can be.
        Box::pin(handle(&mut sub)).await
    };

    let status = reply.resp.status;
    // Kept whatever the verdict: `auth_request_set` is evaluated below, and a
    // `401` carrying `WWW-Authenticate` is exactly when its headers matter.
    ctx.upstream_headers = reply.resp.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();

    for (name, tmpl) in &core.auth_request_set {
        let value = tmpl.render(&*ctx);
        ctx.set(name, value);
    }

    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(status),
        _ => Err(500),
    }
}

/// Applies `limit_conn` and then `limit_req`, in nginx's module order.
///
/// The order is load-bearing: a `limit_req` delay holds the request, and the
/// connection slot has to be held across that wait — otherwise a delayed
/// request would stop counting against `limit_conn` precisely while it is
/// occupying the server.
///
/// Both callers gate this on the request not being internal, which is what
/// keeps an `auth_request` subrequest from being charged as a second request.
/// With `limit_conn` that would be a self-deadlock, not just an overcount: the
/// main request holds the only slot while its own subrequest asks for another.
async fn apply_limits(ctx: &mut Ctx<'_>, core: &CoreConf) -> Option<u16> {
    if !core.limit_conns.is_empty() {
        if let Some(status) = apply_limit_conn(ctx, core) {
            return Some(status);
        }
    }
    if !core.limit_reqs.is_empty() {
        return apply_limit_req(ctx, core).await;
    }
    None
}

/// Takes a slot in every `limit_conn` zone that applies, parking the guards on
/// the context so they are released when the request ends.
///
/// A rejection leaves the slots already taken in place rather than unwinding
/// them; they come back with the rest at the end of the request, which is
/// exactly what nginx's per-limit cleanup handlers do.
fn apply_limit_conn(ctx: &mut Ctx<'_>, core: &CoreConf) -> Option<u16> {
    // Lifted out of the loop so the zone lookups borrow the configuration
    // rather than `ctx`, which the guards are pushed onto.
    let http = ctx.http;
    let mut key = String::with_capacity(32);
    for l in core.limit_conns.iter() {
        let Some(zone) = http.limit_conn_zones.get(&l.zone) else {
            // Config load rejects unknown zones, so this is unreachable.
            continue;
        };
        key.clear();
        if let Some(t) = http.limit_conn_keys.get(&l.zone) {
            t.render_into(&*ctx, &mut key);
        }
        if key.is_empty() {
            // nginx skips a request whose key evaluates empty.
            continue;
        }
        match zone.acquire(&key, l.limit) {
            Some(g) => ctx.limit_conns.push(g),
            // Dry run still had its chance to take a slot, and did not get
            // one; the point of the mode is that the request goes through
            // anyway, so the operator can size the limit before it bites.
            None if core.limit_conn_dry_run => {}
            None => return Some(core.limit_conn_status),
        }
    }
    None
}

/// Evaluates every `limit_req` that applies. Returns the rejection status if
/// any limit refuses the request.
///
/// nginx evaluates all applicable limits and the most restrictive wins; a
/// delay from one and a rejection from another means rejection.
async fn apply_limit_req(ctx: &mut Ctx<'_>, core: &CoreConf) -> Option<u16> {
    use crate::server::limit_req::Decision;

    let mut longest_delay = 0u64;
    for l in core.limit_reqs.iter() {
        let Some(zone) = ctx.http.limit_req_zones.get(&l.zone) else {
            // Config load rejects unknown zones, so this is unreachable.
            continue;
        };
        let mut key = String::with_capacity(32);
        // The zone's key template belongs to the zone, not the location.
        zone_key(ctx, &l.zone, &mut key);
        if key.is_empty() {
            // nginx skips a request whose key evaluates empty.
            continue;
        }
        match zone.check(&key, ctx.start, l.burst, l.nodelay, l.delay_after) {
            Decision::Pass => {}
            Decision::Delay(ms) => longest_delay = longest_delay.max(ms),
            Decision::Reject => return Some(core.limit_req_status),
        }
    }

    if longest_delay > 0 {
        // Holding the task is what shapes traffic to the configured rate; the
        // worker stays free for other connections while this one waits.
        tokio::time::sleep(std::time::Duration::from_millis(longest_delay)).await;
    }
    None
}

fn zone_key(ctx: &Ctx<'_>, zone: &str, out: &mut String) {
    if let Some(t) = ctx.http.limit_req_keys.get(zone) {
        t.render_into(ctx, out);
    }
}

/// Probes each `try_files` candidate and returns the first that exists.
fn run_try_files(ctx: &mut Ctx<'_>, loc: &Arc<Location>, tf: &TryFiles) -> Option<Step> {
    let root = loc
        .core
        .alias
        .as_ref()
        .map(|a| a.render(&*ctx))
        .unwrap_or_else(|| loc.core.root.render(&*ctx));

    for item in &tf.items {
        let candidate = item.render(&*ctx);
        if candidate.is_empty() {
            continue;
        }
        let wants_dir = candidate.ends_with('/');
        let mut path = String::with_capacity(root.len() + candidate.len());
        path.push_str(&root);
        if !candidate.starts_with('/') {
            path.push('/');
        }
        path.push_str(&candidate);

        if let Ok(m) = std::fs::metadata(&path) {
            // `$uri/` only matches a directory; `$uri` only a regular file.
            if (wants_dir && m.is_dir()) || (!wants_dir && m.is_file()) {
                if candidate == ctx.uri {
                    // The current URI already resolves; serve it in place
                    // rather than looping through another redirect.
                    return None;
                }
                return Some(Step::Internal(candidate));
            }
        }
    }

    Some(match &tf.fallback {
        TryFallback::Status(s) => Step::Fail(*s),
        TryFallback::Named(n) => Step::Named(n.clone()),
        TryFallback::Uri(u) => {
            let mut target = u.render(&*ctx);
            if let Some(i) = target.find('?') {
                ctx.args = target[i + 1..].to_string();
                target.truncate(i);
            }
            Step::Internal(target)
        }
    })
}

fn run_rewrites(ctx: &mut Ctx<'_>, rules: &[Rewrite]) -> Option<Step> {
    for r in rules {
        let uri = ctx.uri.clone();
        let Some(caps) = r.re.captures(&uri) else {
            continue;
        };
        ctx.set_captures(&caps);
        let mut target = r.replacement.render(&*ctx);

        // A replacement carrying its own query string replaces `$args`; a
        // trailing `?` clears them.
        if let Some(i) = target.find('?') {
            ctx.args = target[i + 1..].to_string();
            target.truncate(i);
        }

        let absolute = target.starts_with("http://") || target.starts_with("https://");
        match r.flag {
            RewriteFlag::Redirect => return Some(Step::Done(redirect(ctx, 302, target))),
            RewriteFlag::Permanent => return Some(Step::Done(redirect(ctx, 301, target))),
            _ if absolute => {
                // nginx implicitly redirects when the replacement is absolute.
                return Some(Step::Done(redirect(ctx, 302, target)));
            }
            RewriteFlag::Last => {
                ctx.uri = target;
                return Some(Step::Internal(ctx.uri.clone()));
            }
            RewriteFlag::Break => {
                ctx.uri = target;
                return None;
            }
            RewriteFlag::None => ctx.uri = target,
        }
    }
    None
}

fn run_ifs(ctx: &mut Ctx<'_>, blocks: &[IfBlock]) -> Option<Step> {
    for b in blocks {
        if !eval_cond(ctx, &b.cond) {
            continue;
        }
        for a in &b.actions {
            match a {
                IfAction::Return { status, body } => {
                    return Some(Step::Done(return_reply(ctx, *status, body.clone())))
                }
                IfAction::Set { var, value } => {
                    let v = value.render(&*ctx);
                    ctx.set(var, v);
                }
                IfAction::Rewrite(r) => {
                    if let Some(s) = run_rewrites(ctx, std::slice::from_ref(r)) {
                        return Some(s);
                    }
                }
                IfAction::AddHeader(_) => {
                    // Applied during decoration; recorded via the location conf.
                }
                IfAction::Break => return None,
            }
        }
    }
    None
}

fn eval_cond(ctx: &Ctx<'_>, c: &Cond) -> bool {
    let mut s = String::new();
    match c {
        Cond::Always => true,
        Cond::Truthy(v) => {
            ctx.var(v, &mut s);
            // nginx: empty string and "0" are false, everything else is true.
            !s.is_empty() && s != "0"
        }
        Cond::Eq(v, t) => {
            ctx.var(v, &mut s);
            s == t.render(ctx)
        }
        Cond::Ne(v, t) => {
            ctx.var(v, &mut s);
            s != t.render(ctx)
        }
        Cond::Match { var, re, negate } => {
            ctx.var(var, &mut s);
            re.is_match(&s) != *negate
        }
        Cond::FileExists { t, negate } => {
            let p = t.render(ctx);
            std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false) != *negate
        }
        Cond::DirExists { t, negate } => {
            let p = t.render(ctx);
            std::fs::metadata(&p).map(|m| m.is_dir()).unwrap_or(false) != *negate
        }
        Cond::AnyExists { t, negate } => {
            let p = t.render(ctx);
            std::fs::metadata(&p).is_ok() != *negate
        }
        Cond::Executable { t, negate } => {
            let p = t.render(ctx);
            let x = std::fs::metadata(&p)
                .map(|m| {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o111 != 0
                })
                .unwrap_or(false);
            x != *negate
        }
    }
}

enum ErrorRoute {
    Uri(String, Option<u16>),
    Named(Arc<str>, Option<u16>),
    Redirect(String, Option<u16>),
}

/// Finds the `error_page` covering `code`, preferring the location's list.
fn error_page_for(ctx: &Ctx<'_>, code: u16) -> Option<ErrorRoute> {
    let loc_pages = ctx
        .matched
        .as_ref()
        .map(|l| l.error_pages.as_slice())
        .filter(|p| !p.is_empty());

    let pages = loc_pages.unwrap_or(ctx.server.error_pages.as_slice());
    let ep = pages.iter().find(|p| p.codes.contains(&code))?;

    // Three cases, and they differ:
    //   `error_page 404 /x`      → serve /x but keep the 404 status
    //   `error_page 404 =200 /x` → serve /x and report 200
    //   `error_page 404 = /x`    → serve /x and report whatever /x produces
    let replace = match ep.replace_status {
        None => Some(code),
        Some(0) => None,
        Some(n) => Some(n),
    };
    Some(match &ep.target {
        ErrorTarget::Uri(t) => {
            let target = t.render(ctx);
            // A target identical to the current URI would loop forever.
            if target == ctx.uri {
                return None;
            }
            ErrorRoute::Uri(target, replace)
        }
        ErrorTarget::Named(n) => ErrorRoute::Named(n.clone(), replace),
        ErrorTarget::Redirect(t) => ErrorRoute::Redirect(t.render(ctx), replace),
    })
}

fn return_reply(ctx: &Ctx<'_>, code: u16, body: Option<Arc<crate::config::vars::Template>>) -> Reply {
    let mut resp = Resp::new();
    resp.status = code;

    let text = body.map(|t| t.render(ctx));
    // For 3xx, the argument is a URL; for everything else it is a body.
    if (300..400).contains(&code) {
        if let Some(url) = text {
            resp.header("Location", &url);
        }
        return Reply::new(resp, Body::Empty);
    }
    if code == 204 {
        return Reply::new(resp, Body::Empty);
    }
    match text {
        Some(t) => {
            if !resp.has("content-type") {
                resp.header("Content-Type", "text/plain");
            }
            Reply::new(resp, Body::Bytes(t.into_bytes()))
        }
        None => error_reply(ctx, code),
    }
}

fn redirect(ctx: &Ctx<'_>, code: u16, target: String) -> Reply {
    let mut resp = Resp::new();
    resp.status = code;
    let mut loc = target;
    if !ctx.args.is_empty() && !loc.contains('?') {
        loc.push('?');
        loc.push_str(&ctx.args);
    }
    resp.header("Location", &loc);
    error_body(ctx, resp, code)
}

/// Builds the default error page for a status.
pub fn error_reply(ctx: &Ctx<'_>, code: u16) -> Reply {
    let mut resp = Resp::new();
    resp.status = code;
    if code >= 400 {
        // An error terminates a request whose body we never read, so the
        // connection cannot be safely reused for pipelined requests.
        if matches!(code, 400 | 408 | 413 | 414 | 431 | 500 | 501 | 505) {
            resp.keep_alive = false;
        }
    }
    error_body(ctx, resp, code)
}

fn error_body(ctx: &Ctx<'_>, mut resp: Resp, code: u16) -> Reply {
    if status::is_bodyless(code) {
        return Reply::new(resp, Body::Empty);
    }
    let tokens = ctx.server.core.server_tokens;
    let body = status::error_page(code, Resp::signature(tokens).as_deref());
    if !resp.has("content-type") {
        resp.header("Content-Type", "text/html");
    }
    Reply::new(resp, Body::Bytes(body.into_bytes()))
}

/// Applies `add_header`, `expires`, and compression to a finished reply.
fn decorate(ctx: &Ctx<'_>, mut r: Reply) -> Reply {
    let core = matched_core(ctx);

    for h in core.add_headers.iter() {
        // Without `always`, nginx only adds the header on 2xx/3xx.
        let ok = h.always || matches!(r.resp.status, 200..=299 | 301 | 302 | 303 | 304 | 307 | 308);
        if !ok {
            continue;
        }
        let v = h.value.render(ctx);
        if !v.is_empty() {
            r.resp.header(&h.name, &v);
        }
    }

    if let Some(e) = core.expires {
        apply_expires(&mut r.resp, e);
    }

    // Advertise HTTP/3, so a browser arriving over TCP knows to try QUIC next
    // time. nginx has no automatic `Alt-Svc` and expects an explicit
    // `add_header`, which is a deliberate deviation here: without the header a
    // `listen ... quic` line serves no browser at all, and a feature that
    // silently does nothing is worse than one that differs from nginx.
    //
    // A config that sets its own `Alt-Svc` wins — that is the escape hatch for
    // an operator who wants a different `ma=`, a different port, or none.
    if let Some(alt) = &ctx.server.alt_svc {
        if !r.resp.iter().any(|(n, _)| n.eq_ignore_ascii_case("alt-svc")) {
            r.resp.header("Alt-Svc", alt);
        }
    }

    maybe_gzip(ctx, core, &mut r);
    r
}

/// The core conf of whichever location matched, for post-processing.
fn matched_core<'a>(ctx: &'a Ctx<'a>) -> &'a CoreConf {
    match &ctx.matched {
        Some(l) => &l.core,
        None => &ctx.server.core,
    }
}

fn apply_expires(resp: &mut Resp, e: Expires) {
    use std::time::{Duration, SystemTime};
    let (cache_control, expires) = match e {
        Expires::Off => return,
        Expires::Epoch => (
            "no-cache".to_string(),
            crate::http::date::http_date(std::time::UNIX_EPOCH),
        ),
        Expires::Max => (
            "max-age=315360000".to_string(),
            "Thu, 31 Dec 2037 23:55:55 GMT".to_string(),
        ),
        Expires::Secs(s) if s < 0 => (
            "no-cache".to_string(),
            crate::http::date::http_date(SystemTime::now()),
        ),
        Expires::Secs(s) => (
            format!("max-age={s}"),
            crate::http::date::http_date(SystemTime::now() + Duration::from_secs(s as u64)),
        ),
        Expires::Daily(secs_of_day) => {
            let now = SystemTime::now();
            (
                format!("max-age={secs_of_day}"),
                crate::http::date::http_date(now + Duration::from_secs(secs_of_day as u64)),
            )
        }
    };
    resp.set("Expires", &expires);
    resp.set("Cache-Control", &cache_control);
}

/// Compresses the body when `gzip on` and the client advertises support.
fn maybe_gzip(ctx: &Ctx<'_>, core: &CoreConf, r: &mut Reply) {
    let g = &core.gzip;
    if !g.enabled || r.resp.has("content-encoding") {
        return;
    }
    if !ctx.req.accepts_gzip(ctx.buf) {
        return;
    }
    if ctx.req.minor == 0 && !g.http_version_1_0 {
        return;
    }
    let Some(ct) = r.resp.get("content-type") else {
        return;
    };
    let base = ct.split(';').next().unwrap_or("").trim().to_string();
    if !g.types.iter().any(|t| **t == base) && base != "text/html" {
        return;
    }
    let Some(len) = r.body.known_len() else { return };
    if len < g.min_length {
        return;
    }

    // Only in-memory bodies are compressed inline; streaming a compressor over
    // a large file would cost more than it saves at these sizes.
    //
    // `Inline` bodies have not been read yet — they are normally handed to the
    // connection to `pread` straight into the write buffer — so compressing one
    // means reading it here first. That is still cheaper than the compression.
    // A file body has not been read yet — the write path would normally hand
    // it to `sendfile`. Compressing means reading it here instead, which is
    // the trade nginx also makes: gzip and sendfile are mutually exclusive,
    // because compression has to happen in user space.
    if len > GZIP_MAX_FILE {
        return;
    }
    let file_read;
    let raw: &[u8] = match &r.body {
        Body::Bytes(b) => b,
        Body::Mmap { map, range } => &map[range.clone()],
        Body::Inline { file, offset, len } | Body::File { file, offset, len } => {
            let mut v = vec![0u8; *len as usize];
            match read_exact_at(file, &mut v, *offset) {
                Ok(n) => {
                    v.truncate(n);
                    file_read = v;
                    &file_read
                }
                Err(_) => return,
            }
        }
        _ => return,
    };

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::with_capacity(raw.len() / 2), Compression::new(g.level));
    if enc.write_all(raw).is_err() {
        return;
    }
    let Ok(out) = enc.finish() else { return };

    r.body = Body::Bytes(out);
    r.resp.header("Content-Encoding", "gzip");
    if g.vary {
        r.resp.header("Vary", "Accept-Encoding");
    }
    // The entity changed, so a strong ETag no longer identifies these bytes.
    if let Some(e) = r.resp.get("etag").map(str::to_string) {
        if !e.starts_with("W/") {
            r.resp.set("ETag", &format!("W/{e}"));
        }
    }
}

/// Turns a mid-phase `Step` into a final reply, or `None` to keep routing.
async fn finish(ctx: &mut Ctx<'_>, step: Step) -> Option<Reply> {
    match step {
        Step::Done(r) => Some(decorate(ctx, r)),
        Step::Fail(c) => Some(decorate(ctx, error_reply(ctx, c))),
        Step::Internal(uri) => {
            ctx.uri = uri;
            None
        }
        Step::Named(_) => None,
    }
}

/// Renders a `Location` header value for an absolute redirect.
pub fn absolute_url(ctx: &Ctx<'_>, path: &str) -> String {
    let mut s = String::with_capacity(path.len() + 32);
    s.push_str(ctx.scheme);
    s.push_str("://");
    let host = ctx.req.host(ctx.buf);
    s.push_str(if host.is_empty() { "localhost" } else { host });
    let port = ctx.local.map(|a| a.port()).unwrap_or(0);
    let default = if ctx.scheme == "https" { 443 } else { 80 };
    if port != default {
        s.push(':');
        push_num(&mut s, port as u64);
    }
    s.push_str(path);
    s
}

/// Reads `buf.len()` bytes at `off`, tolerating short reads.
fn read_exact_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            match f.read_at(&mut buf[done..], off + done as u64)? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
    #[cfg(not(unix))]
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = f.try_clone()?;
        f.seek(SeekFrom::Start(off))?;
        let mut done = 0;
        while done < buf.len() {
            match f.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
}

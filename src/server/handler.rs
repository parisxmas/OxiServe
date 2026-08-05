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
    if let Some(step) = run_rewrites(ctx, &ctx.server.rewrites.clone()) {
        if let Some(r) = finish(ctx, step).await {
            return r;
        }
    }
    if let Some(step) = run_ifs(ctx, &ctx.server.ifs.clone()) {
        if let Some(r) = finish(ctx, step).await {
            return r;
        }
    }

    let mut named: Option<Arc<str>> = None;
    let mut internal = false;
    let mut status_override: Option<u16> = None;

    loop {
        let step = match &named {
            Some(n) => match ctx.server.locations.named.get(&**n) {
                Some(loc) => dispatch(ctx, &loc.clone(), true).await,
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
async fn route(ctx: &mut Ctx<'_>, internal: bool) -> Step {
    let uri = ctx.uri.clone();
    let Some((loc, caps)) = ctx.server.locations.find(&uri) else {
        // No location at all: fall back to the server's own action or static.
        return match &ctx.server.action {
            Action::Return { status, body } => Step::Done(return_reply(ctx, *status, body.clone())),
            _ => match files::serve(ctx, None).await {
                Ok(r) => Step::Done(r),
                Err(c) => Step::Fail(c),
            },
        };
    };
    let mut loc = loc.clone();
    if let Some(c) = caps {
        ctx.set_captures(&c);
    }

    // Nested locations are searched only within the matched parent.
    while let Some(nested) = &loc.nested {
        let Some((inner, caps)) = nested.find(&uri) else {
            break;
        };
        let inner = inner.clone();
        if let Some(c) = caps {
            ctx.set_captures(&c);
        }
        loc = inner;
    }

    dispatch(ctx, &loc, internal).await
}

async fn dispatch(ctx: &mut Ctx<'_>, loc: &Arc<Location>, internal: bool) -> Step {
    // `internal;` locations are reachable only via an internal redirect.
    if loc.core.internal && !internal {
        return Step::Fail(404);
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
        Action::Static => match files::serve(ctx, Some(loc)).await {
            Ok(r) => Step::Done(r),
            Err(c) => Step::Fail(c),
        },
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
    let uri = ctx.uri.clone();
    let loc_pages = ctx
        .server
        .locations
        .find(&uri)
        .map(|(l, _)| l.error_pages.as_slice())
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

    maybe_gzip(ctx, core, &mut r);
    r
}

/// The core conf of whichever location matched, for post-processing.
fn matched_core<'a>(ctx: &'a Ctx<'a>) -> &'a CoreConf {
    ctx.server
        .locations
        .find(&ctx.uri)
        .map(|(l, _)| &l.core)
        .unwrap_or(&ctx.server.core)
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
    let raw: &[u8] = match &r.body {
        Body::Bytes(b) => b,
        Body::Mmap { map, range } => &map[range.clone()],
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
    let port = ctx.local.port();
    let default = if ctx.scheme == "https" { 443 } else { 80 };
    if port != default {
        s.push(':');
        push_num(&mut s, port as u64);
    }
    s.push_str(path);
    s
}

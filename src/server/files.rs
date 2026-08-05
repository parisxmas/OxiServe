//! Static file serving: path resolution, conditional requests, and ranges.
//!
//! Files under [`MMAP_MAX`] are served straight out of a memory map, so the
//! bytes travel page-cache → socket with no intermediate copy. Larger files
//! fall back to chunked reads on the blocking pool, because a page fault on a
//! cold multi-megabyte file would otherwise stall the whole worker.

use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use super::ctx::Ctx;
use super::reply::{Body, Reply};
use crate::config::model::{CoreConf, LocMatch, Location};
use crate::http::date;
use crate::http::request::Hot;
use crate::http::response::{push_num, Resp};

/// Files at or below this size are memory-mapped; above it we stream.
pub const MMAP_MAX: u64 = 1024 * 1024;

/// Maps a request URI onto a filesystem path using `root` or `alias`.
///
/// With `alias`, the matched location prefix is *replaced*; with `root` it is
/// appended. Getting this backwards is the classic nginx misconfiguration, so
/// the two paths are kept visibly distinct.
pub fn map_path(ctx: &Ctx, core: &CoreConf, matcher: Option<&LocMatch>) -> PathBuf {
    if let Some(alias) = &core.alias {
        let base = alias.render(ctx);
        let prefix_len = match matcher {
            Some(LocMatch::Prefix(p)) | Some(LocMatch::PrefixNoRegex(p)) | Some(LocMatch::Exact(p)) => {
                p.len()
            }
            // For a regex location, `alias` names the whole path.
            _ => ctx.uri.len(),
        };
        let rest = ctx.uri.get(prefix_len..).unwrap_or("");
        let mut p = base;
        if !rest.is_empty() {
            if p.ends_with('/') && rest.starts_with('/') {
                p.pop();
            } else if !p.ends_with('/') && !rest.starts_with('/') {
                p.push('/');
            }
            p.push_str(rest);
        }
        return PathBuf::from(p);
    }

    let mut p = core.root.render(ctx);
    // `uri` is already normalised and absolute, so this cannot escape `root`.
    p.push_str(&ctx.uri);
    PathBuf::from(p)
}

/// Serves a file or directory for the matched location.
///
/// Returns `Err(status)` for anything the caller should turn into an error
/// page (404, 403, 405, …).
pub async fn serve(ctx: &mut Ctx<'_>, loc: Option<&Arc<Location>>) -> Result<Reply, u16> {
    let core = loc.map(|l| &l.core).unwrap_or(&ctx.server.core);
    let matcher = loc.map(|l| &l.matcher);

    ctx.document_root = core
        .alias
        .as_ref()
        .map(|a| a.render(&*ctx))
        .unwrap_or_else(|| core.root.render(&*ctx));

    let path = map_path(ctx, core, matcher);
    ctx.filename = path.to_string_lossy().into_owned();

    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => return Err(io_status(&e)),
    };

    if meta.is_dir() {
        // nginx redirects a directory request that lacks its trailing slash,
        // so relative links inside the index page resolve correctly.
        if !ctx.uri.ends_with('/') {
            return Ok(dir_redirect(ctx, core));
        }
        return serve_directory(ctx, core, &path).await;
    }

    serve_file(ctx, core, &path, &meta).await
}

async fn serve_directory(ctx: &mut Ctx<'_>, core: &CoreConf, dir: &Path) -> Result<Reply, u16> {
    for idx in core.index.iter() {
        let name = idx.render(&*ctx);
        if name.is_empty() {
            continue;
        }
        // An absolute index is an internal redirect in nginx; we resolve it
        // against the root instead, which is equivalent for the common case.
        let candidate = dir.join(name.trim_start_matches('/'));
        if let Ok(m) = std::fs::metadata(&candidate) {
            if m.is_file() {
                ctx.filename = candidate.to_string_lossy().into_owned();
                return serve_file(ctx, core, &candidate, &m).await;
            }
        }
    }

    if core.autoindex {
        return super::autoindex::render(ctx, dir).await;
    }
    Err(403)
}

fn dir_redirect(ctx: &Ctx, core: &CoreConf) -> Reply {
    let mut resp = Resp::new();
    resp.status = 301;
    let mut loc = String::with_capacity(ctx.uri.len() + 32);
    if core.absolute_redirect {
        loc.push_str(ctx.scheme);
        loc.push_str("://");
        let host = ctx.req.host(ctx.buf);
        loc.push_str(if host.is_empty() { "localhost" } else { host });
        if core.port_in_redirect {
            let port = ctx.local.port();
            let default = if ctx.scheme == "https" { 443 } else { 80 };
            if port != default {
                loc.push(':');
                push_num(&mut loc, port as u64);
            }
        }
    }
    crate::http::uri::encode_path(&ctx.uri, &mut loc);
    loc.push('/');
    if !ctx.args.is_empty() {
        loc.push('?');
        loc.push_str(&ctx.args);
    }
    resp.header("Location", &loc);
    resp.header("Content-Type", "text/html");

    let body = crate::http::status::error_page(301, Resp::signature(core.server_tokens).as_deref());
    Reply::new(resp, Body::Bytes(body.into_bytes()))
}

async fn serve_file(
    ctx: &mut Ctx<'_>,
    core: &CoreConf,
    path: &Path,
    meta: &Metadata,
) -> Result<Reply, u16> {
    if !ctx.req.method.is_safe() && ctx.req.method != crate::http::Method::Options {
        return Err(405);
    }

    let size = meta.len();
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let etag = make_etag(mtime, size);
    let last_modified = date::http_date(mtime);

    // Conditional requests short-circuit before any I/O on the body.
    if let Some(status) = evaluate_preconditions(ctx, core, &etag, mtime) {
        let mut resp = Resp::new();
        resp.status = status;
        if status == 304 {
            // RFC 9110: a 304 repeats the validators and cache headers.
            if core.etag {
                resp.header("ETag", &etag);
            }
            resp.header("Last-Modified", &last_modified);
        }
        return Ok(Reply::new(resp, Body::Empty));
    }

    let mut resp = Resp::new();
    let ctype = content_type(ctx, core, path);
    resp.header("Content-Type", &ctype);
    resp.header("Last-Modified", &last_modified);
    if core.etag {
        resp.header("ETag", &etag);
    }
    resp.header("Accept-Ranges", "bytes");

    // Range handling.
    let range = match ctx.req.hot_value(ctx.buf, Hot::RangeH) {
        Some(h) if core.max_ranges != Some(0) && if_range_matches(ctx, &etag, mtime) => {
            match parse_range(h, size) {
                RangeSpec::None => None,
                RangeSpec::Unsatisfiable => {
                    resp.status = 416;
                    resp.header_with("Content-Range", |s| {
                        s.push_str("bytes */");
                        push_num(s, size);
                    });
                    return Ok(Reply::new(resp, Body::Empty));
                }
                RangeSpec::One(r) => Some(r),
            }
        }
        _ => None,
    };

    let (start, len) = match &range {
        Some(r) => {
            resp.status = 206;
            resp.header_with("Content-Range", |s| {
                s.push_str("bytes ");
                push_num(s, r.start);
                s.push('-');
                push_num(s, r.end - 1);
                s.push('/');
                push_num(s, size);
            });
            (r.start, r.end - r.start)
        }
        None => (0, size),
    };

    // HEAD gets every header but no body.
    if ctx.req.method == crate::http::Method::Head {
        let mut r = Reply::new(resp, Body::Empty);
        r.resp.framing = crate::http::response::Framing::Length(len);
        return Ok(r);
    }

    let body = open_body(path, start, len).map_err(|e| io_status(&e))?;
    Ok(Reply::new(resp, body))
}

fn open_body(path: &Path, start: u64, len: u64) -> io::Result<Body> {
    let file = std::fs::File::open(path)?;
    if len == 0 {
        return Ok(Body::Empty);
    }
    if len <= MMAP_MAX {
        // SAFETY: mapping a file another process may truncate can fault on
        // access. We accept the same exposure nginx has with sendfile, and
        // bound it by only mapping small, already-stat'd regular files.
        let map = unsafe { Mmap::map(&file) }?;
        let s = start as usize;
        let e = (start + len) as usize;
        if e <= map.len() {
            return Ok(Body::Mmap { map: Arc::new(map), range: s..e });
        }
        // The file shrank between stat and map; fall through to a plain read.
    }
    Ok(Body::File { file, offset: start, len })
}

fn content_type(ctx: &Ctx, core: &CoreConf, path: &Path) -> String {
    let name = path.to_string_lossy();
    let base = ctx
        .http
        .mime
        .lookup(&name)
        .map(|t| t.to_string())
        .unwrap_or_else(|| core.default_type.to_string());
    match &core.charset {
        // nginx appends charset only to text types.
        Some(cs) if base.starts_with("text/") || base == "application/javascript" => {
            format!("{base}; charset={cs}")
        }
        _ => base,
    }
}

/// nginx's ETag: `"<hex mtime>-<hex size>"`.
pub fn make_etag(mtime: SystemTime, size: u64) -> String {
    let secs = mtime.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("\"{secs:x}-{size:x}\"")
}

/// Returns `Some(status)` when the request should short-circuit.
fn evaluate_preconditions(
    ctx: &Ctx,
    core: &CoreConf,
    etag: &str,
    mtime: SystemTime,
) -> Option<u16> {
    let buf = ctx.buf;

    // If-Match / If-Unmodified-Since gate the request (412 on failure).
    if let Some(v) = ctx.req.hot_value(buf, Hot::IfMatch) {
        if v.trim() != "*" && !etag_list_matches(v, etag, false) {
            return Some(412);
        }
    } else if let Some(v) = ctx.req.hot_value(buf, Hot::IfUnmodifiedSince) {
        if let Some(t) = date::parse_http_date(v) {
            if mtime > t {
                return Some(412);
            }
        }
    }

    // If-None-Match takes precedence over If-Modified-Since.
    if let Some(v) = ctx.req.hot_value(buf, Hot::IfNoneMatch) {
        let hit = v.trim() == "*" || etag_list_matches(v, etag, true);
        return hit.then_some(304);
    }

    if core.if_modified_since == crate::config::model::IfModifiedSince::Off {
        return None;
    }
    if let Some(v) = ctx.req.hot_value(buf, Hot::IfModifiedSince) {
        if let Some(t) = date::parse_http_date(v) {
            let unmodified = match core.if_modified_since {
                crate::config::model::IfModifiedSince::Before => mtime < t,
                _ => mtime <= t,
            };
            // Compare at second granularity: HTTP dates carry no sub-second part.
            if unmodified || truncate_secs(mtime) == truncate_secs(t) {
                return Some(304);
            }
        }
    }
    None
}

fn truncate_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Matches a comma-separated ETag list. `weak` allows weak comparison, which
/// is what If-None-Match uses.
fn etag_list_matches(list: &str, etag: &str, weak: bool) -> bool {
    let target = etag.trim_start_matches("W/");
    list.split(',').any(|c| {
        let c = c.trim();
        let c = if weak { c.trim_start_matches("W/") } else { c };
        c == target
    })
}

fn if_range_matches(ctx: &Ctx, etag: &str, mtime: SystemTime) -> bool {
    match ctx.req.hot_value(ctx.buf, Hot::IfRange) {
        None => true,
        Some(v) => {
            let v = v.trim();
            if v.starts_with('"') || v.starts_with("W/") {
                // Strong comparison is required for If-Range.
                v == etag
            } else {
                match date::parse_http_date(v) {
                    Some(t) => truncate_secs(mtime) == truncate_secs(t),
                    None => false,
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RangeSpec {
    /// No usable range; serve the whole entity.
    None,
    Unsatisfiable,
    One(std::ops::Range<u64>),
}

/// Parses a `Range` header. Only single ranges are honoured; a multi-range
/// request degrades to the full entity rather than a multipart response.
fn parse_range(h: &str, size: u64) -> RangeSpec {
    let Some(spec) = h.trim().strip_prefix("bytes=") else {
        return RangeSpec::None;
    };
    let mut parts = spec.split(',');
    let Some(first) = parts.next() else {
        return RangeSpec::None;
    };
    if parts.next().is_some() {
        return RangeSpec::None;
    }
    let first = first.trim();
    let Some((a, b)) = first.split_once('-') else {
        return RangeSpec::None;
    };

    if a.is_empty() {
        // `-N`: the final N bytes.
        let n: u64 = match b.parse() {
            Ok(n) => n,
            Err(_) => return RangeSpec::None,
        };
        if n == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let start = size.saturating_sub(n);
        return RangeSpec::One(start..size);
    }

    let start: u64 = match a.parse() {
        Ok(n) => n,
        Err(_) => return RangeSpec::None,
    };
    if start >= size {
        return RangeSpec::Unsatisfiable;
    }
    let end = if b.is_empty() {
        size
    } else {
        match b.parse::<u64>() {
            // Range end is inclusive on the wire, exclusive here.
            Ok(n) => (n + 1).min(size),
            Err(_) => return RangeSpec::None,
        }
    };
    if end <= start {
        return RangeSpec::Unsatisfiable;
    }
    RangeSpec::One(start..end)
}

pub fn io_status(e: &io::Error) -> u16 {
    match e.kind() {
        io::ErrorKind::NotFound => 404,
        io::ErrorKind::PermissionDenied => 403,
        _ => {
            // ENAMETOOLONG and friends are client errors, not server faults.
            match e.raw_os_error() {
                Some(libc::ENAMETOOLONG) | Some(libc::ELOOP) => 404,
                _ => 500,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_full_and_partial() {
        assert_eq!(parse_range("bytes=0-99", 1000), RangeSpec::One(0..100));
        assert_eq!(parse_range("bytes=100-", 1000), RangeSpec::One(100..1000));
        assert_eq!(parse_range("bytes=0-", 1000), RangeSpec::One(0..1000));
    }

    #[test]
    fn suffix_range() {
        assert_eq!(parse_range("bytes=-100", 1000), RangeSpec::One(900..1000));
        // A suffix longer than the file clamps to the whole file.
        assert_eq!(parse_range("bytes=-5000", 1000), RangeSpec::One(0..1000));
    }

    #[test]
    fn range_end_is_inclusive_and_clamped() {
        assert_eq!(parse_range("bytes=0-0", 1000), RangeSpec::One(0..1));
        assert_eq!(parse_range("bytes=990-5000", 1000), RangeSpec::One(990..1000));
    }

    #[test]
    fn unsatisfiable_ranges() {
        assert_eq!(parse_range("bytes=1000-", 1000), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=2000-3000", 1000), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 1000), RangeSpec::Unsatisfiable);
    }

    #[test]
    fn multi_and_malformed_ranges_fall_back_to_the_whole_entity() {
        assert_eq!(parse_range("bytes=0-10,20-30", 1000), RangeSpec::None);
        assert_eq!(parse_range("items=0-10", 1000), RangeSpec::None);
        assert_eq!(parse_range("bytes=abc", 1000), RangeSpec::None);
        assert_eq!(parse_range("bytes=x-y", 1000), RangeSpec::None);
    }

    #[test]
    fn etag_shape_matches_nginx() {
        let t = UNIX_EPOCH + std::time::Duration::from_secs(0x5f5e100);
        assert_eq!(make_etag(t, 255), "\"5f5e100-ff\"");
    }

    #[test]
    fn etag_list_matching() {
        assert!(etag_list_matches("\"abc\"", "\"abc\"", false));
        assert!(etag_list_matches("\"x\", \"abc\"", "\"abc\"", false));
        assert!(!etag_list_matches("\"x\"", "\"abc\"", false));
        // Weak comparison ignores the W/ prefix; strong does not.
        assert!(etag_list_matches("W/\"abc\"", "\"abc\"", true));
        assert!(!etag_list_matches("W/\"abc\"", "\"abc\"", false));
    }

    #[test]
    fn io_errors_map_to_sensible_statuses() {
        assert_eq!(io_status(&io::Error::from(io::ErrorKind::NotFound)), 404);
        assert_eq!(io_status(&io::Error::from(io::ErrorKind::PermissionDenied)), 403);
        assert_eq!(io_status(&io::Error::from(io::ErrorKind::Other)), 500);
    }
}

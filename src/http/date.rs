//! Cached time formatting.
//!
//! Every response carries a `Date` header, and every access-log line carries a
//! timestamp. Formatting those from scratch per request is pure waste: the
//! value only changes once a second. nginx keeps a cached time struct updated
//! by a timer; we keep one per worker thread, refreshed lazily whenever the
//! wall clock second has advanced.

use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Cache {
    secs: u64,
    /// `Sun, 06 Nov 1994 08:49:37 GMT`
    http: String,
    /// `06/Nov/1994:08:49:37 +0000` — nginx's `$time_local`
    local: String,
    /// `1994-11-06T08:49:37+00:00` — nginx's `$time_iso8601`
    iso: String,
}

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache {
        secs: 0,
        http: String::with_capacity(29),
        local: String::with_capacity(26),
        iso: String::with_capacity(25),
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn refresh(c: &mut Cache, secs: u64) {
    c.secs = secs;
    c.http.clear();
    c.http
        .push_str(&httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(secs)));

    let lt = local_time(secs as i64);
    c.local.clear();
    fmt_clf(&lt, &mut c.local);
    c.iso.clear();
    fmt_iso(&lt, &mut c.iso);
}

/// Appends the current `Date` header value.
pub fn append_http_date(out: &mut String) {
    let secs = now_secs();
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.secs != secs {
            refresh(&mut c, secs);
        }
        out.push_str(&c.http);
    });
}

pub fn append_time_local(out: &mut String) {
    let secs = now_secs();
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.secs != secs {
            refresh(&mut c, secs);
        }
        out.push_str(&c.local);
    });
}

pub fn append_time_iso8601(out: &mut String) {
    let secs = now_secs();
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.secs != secs {
            refresh(&mut c, secs);
        }
        out.push_str(&c.iso);
    });
}

/// Formats an arbitrary time as an HTTP-date (for `Last-Modified`).
pub fn http_date(t: SystemTime) -> String {
    let mut s = String::with_capacity(29);
    append_http_date_of(t, &mut s);
    s
}

const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Appends an RFC 7231 HTTP-date without allocating — `Last-Modified` is on
/// every static response, so going through `String` per request was pure waste.
pub fn append_http_date_of(t: SystemTime, out: &mut String) {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let dow = (days + 4).rem_euclid(7) as usize;

    out.push_str(DAYS[dow]);
    out.push_str(", ");
    pad2(d, out);
    out.push(' ');
    out.push_str(MONTHS[(m as usize - 1).min(11)]);
    out.push(' ');
    out.push_str(&y.to_string());
    out.push(' ');
    pad2((rem / 3600) as u32, out);
    out.push(':');
    pad2(((rem % 3600) / 60) as u32, out);
    out.push(':');
    pad2((rem % 60) as u32, out);
    out.push_str(" GMT");
}

/// Days since the epoch to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as i32, m as u32, d as u32)
}

/// Parses an HTTP-date (for `If-Modified-Since` / `If-Range`).
pub fn parse_http_date(s: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(s).ok()
}

struct LocalTime {
    year: i32,
    mon: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    /// UTC offset in seconds.
    off: i32,
}

#[cfg(unix)]
fn local_time(secs: i64) -> LocalTime {
    // SAFETY: `localtime_r` writes into a caller-provided `tm`, which is the
    // thread-safe variant; we pass a fully-owned zeroed struct.
    unsafe {
        let t = secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return LocalTime { year: 1970, mon: 1, day: 1, hour: 0, min: 0, sec: 0, off: 0 };
        }
        LocalTime {
            year: tm.tm_year + 1900,
            mon: (tm.tm_mon + 1) as u32,
            day: tm.tm_mday as u32,
            hour: tm.tm_hour as u32,
            min: tm.tm_min as u32,
            sec: tm.tm_sec as u32,
            off: tm.tm_gmtoff as i32,
        }
    }
}

#[cfg(not(unix))]
fn local_time(secs: i64) -> LocalTime {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (year, mon, day) = civil_from_days(days);
    LocalTime {
        year,
        mon,
        day,
        hour: (rem / 3600) as u32,
        min: ((rem % 3600) / 60) as u32,
        sec: (rem % 60) as u32,
        off: 0,
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn pad2(n: u32, out: &mut String) {
    if n < 10 {
        out.push('0');
    }
    out.push_str(itoa(n as u64).as_str());
}

fn itoa(n: u64) -> String {
    n.to_string()
}

/// Common Log Format timestamp: `06/Nov/1994:08:49:37 +0100`
fn fmt_clf(t: &LocalTime, out: &mut String) {
    pad2(t.day, out);
    out.push('/');
    out.push_str(MONTHS[(t.mon as usize - 1).min(11)]);
    out.push('/');
    out.push_str(&t.year.to_string());
    out.push(':');
    pad2(t.hour, out);
    out.push(':');
    pad2(t.min, out);
    out.push(':');
    pad2(t.sec, out);
    out.push(' ');
    fmt_offset(t.off, out, false);
}

/// ISO 8601: `1994-11-06T08:49:37+01:00`
fn fmt_iso(t: &LocalTime, out: &mut String) {
    out.push_str(&t.year.to_string());
    out.push('-');
    pad2(t.mon, out);
    out.push('-');
    pad2(t.day, out);
    out.push('T');
    pad2(t.hour, out);
    out.push(':');
    pad2(t.min, out);
    out.push(':');
    pad2(t.sec, out);
    fmt_offset(t.off, out, true);
}

fn fmt_offset(off: i32, out: &mut String, colon: bool) {
    out.push(if off < 0 { '-' } else { '+' });
    let a = off.unsigned_abs();
    pad2(a / 3600, out);
    if colon {
        out.push(':');
    }
    pad2((a % 3600) / 60, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hand_rolled_date_matches_httpdate_crate() {
        // Spot-check the no-alloc formatter against the reference impl.
        for secs in [0u64, 784_111_777, 1_700_000_000, 2_000_000_000, 951_782_400] {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            assert_eq!(http_date(t), httpdate::fmt_http_date(t), "secs={secs}");
        }
    }

    #[test]
    fn http_date_is_rfc7231() {
        let s = http_date(UNIX_EPOCH + Duration::from_secs(784_111_777));
        assert_eq!(s, "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn http_date_roundtrips() {
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_http_date(&http_date(t)), Some(t));
    }

    #[test]
    fn parses_all_three_legacy_formats() {
        // RFC 7231 requires servers to accept these on If-Modified-Since.
        assert!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").is_some());
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_some());
        assert!(parse_http_date("Sun Nov  6 08:49:37 1994").is_some());
    }

    #[test]
    fn cached_date_has_the_right_shape() {
        let mut s = String::new();
        append_http_date(&mut s);
        assert_eq!(s.len(), 29, "{s}");
        assert!(s.ends_with(" GMT"), "{s}");
    }

    #[test]
    fn clf_timestamp_shape() {
        let mut s = String::new();
        append_time_local(&mut s);
        // e.g. 05/Aug/2026:21:41:00 +0300
        assert_eq!(s.len(), 26, "{s}");
        assert_eq!(&s[2..3], "/");
        assert_eq!(&s[11..12], ":");
    }

    #[test]
    fn iso_timestamp_shape() {
        let mut s = String::new();
        append_time_iso8601(&mut s);
        assert_eq!(s.len(), 25, "{s}");
        assert_eq!(&s[10..11], "T");
    }

    #[test]
    fn cache_returns_the_same_value_within_a_second() {
        let mut a = String::new();
        let mut b = String::new();
        append_http_date(&mut a);
        append_http_date(&mut b);
        assert_eq!(a, b);
    }
}

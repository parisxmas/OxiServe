//! Server-wide counters, and the `stub_status` endpoint that reports them.
//!
//! # Why these are in shared memory
//!
//! Workers are processes. A counter kept per process would make `stub_status`
//! report whichever worker happened to answer the status request — a number
//! that is not wrong so much as meaningless, and that changes every time you
//! refresh. The counters therefore live in the same `MAP_SHARED` mapping
//! created before the fork that [`limit_req`](super::limit_req) and
//! [`limit_conn`](super::limit_conn) use, so every worker adds to one set.
//!
//! They are `Relaxed` throughout. Nothing branches on them, they are read for
//! display, and making them ordered would put a barrier on the accept path to
//! buy nothing.
//!
//! # Which numbers are real
//!
//! nginx's `stub_status` reports `Reading`, `Writing` and `Waiting`, and it
//! would be easy to emit plausible values for all three. Instead the
//! connection state machine moves a connection between the three counters as
//! it actually changes state, so a connection counted as `Waiting` really is
//! idle between keep-alive requests. `Active` is their sum plus connections
//! still being set up.
//!
//! `accepts` and `handled` differ in nginx only when a connection is accepted
//! and then dropped without being processed, which happens when
//! `worker_connections` is exhausted. That limit is not enforced here, so the
//! two are always equal — stated plainly rather than by quietly reporting the
//! same variable twice.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use super::shm::Shared;

/// Slots in the shared block.
mod slot {
    pub const ACCEPTS: usize = 0;
    pub const HANDLED: usize = 1;
    pub const REQUESTS: usize = 2;
    pub const ACTIVE: usize = 3;
    pub const READING: usize = 4;
    pub const WRITING: usize = 5;
    pub const WAITING: usize = 6;
    pub const COUNT: usize = 7;
}

static COUNTERS: OnceLock<Shared> = OnceLock::new();

/// Creates the shared block. Called once, in the master, before any fork.
///
/// Idempotent so a reload — which builds a new generation — keeps the counters
/// it already had rather than resetting them, matching nginx, where a reload
/// does not zero `stub_status`.
pub fn init() {
    COUNTERS.get_or_init(|| Shared::new(slot::COUNT, "stub_status"));
}

#[inline]
fn at(i: usize) -> Option<&'static AtomicU64> {
    COUNTERS.get().map(|c| c.at(i))
}

#[inline]
fn add(i: usize, n: i64) {
    if let Some(c) = at(i) {
        if n >= 0 {
            c.fetch_add(n as u64, Ordering::Relaxed);
        } else {
            c.fetch_sub((-n) as u64, Ordering::Relaxed);
        }
    }
}

#[inline]
fn get(i: usize) -> u64 {
    at(i).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// A connection was accepted.
pub fn accepted() {
    add(slot::ACCEPTS, 1);
    add(slot::HANDLED, 1);
    add(slot::ACTIVE, 1);
}

/// A connection ended, whatever state it was in.
pub fn closed() {
    add(slot::ACTIVE, -1);
}

/// One request was served.
pub fn request_done() {
    add(slot::REQUESTS, 1);
}

/// Counts a live connection, releasing it on every exit path.
///
/// The connection loops return from a dozen places — parse errors, timeouts,
/// write failures, a client that closes mid-request — and paired
/// increment/decrement calls would leak a count on all but the tidiest of
/// them. A leaked "active connection" never comes back.
pub struct ConnGuard;

impl ConnGuard {
    pub fn enter() -> ConnGuard {
        accepted();
        ConnGuard
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        closed();
    }
}

/// Which of the three per-connection states a connection is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Reading,
    Writing,
    Waiting,
}

fn slot_of(s: State) -> usize {
    match s {
        State::Reading => slot::READING,
        State::Writing => slot::WRITING,
        State::Waiting => slot::WAITING,
    }
}

/// Holds a connection in one state, moving it as the connection progresses and
/// releasing it on drop.
///
/// A guard rather than paired calls because every early return in the
/// connection loop — a parse error, a write failure, a timeout — would
/// otherwise leak a count, and a leaked count never comes back: `Reading`
/// would climb forever on a server that sees malformed requests.
pub struct StateGuard {
    current: State,
}

impl StateGuard {
    pub fn enter(s: State) -> StateGuard {
        add(slot_of(s), 1);
        StateGuard { current: s }
    }

    pub fn switch(&mut self, s: State) {
        if s == self.current {
            return;
        }
        add(slot_of(self.current), -1);
        add(slot_of(s), 1);
        self.current = s;
    }
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        add(slot_of(self.current), -1);
    }
}

/// nginx's `stub_status` body, byte for byte.
///
/// The trailing spaces and the exact line breaks are part of it: monitoring
/// agents in the wild parse this with regexes written against nginx's output,
/// so "close enough" is a broken integration.
pub fn stub_status_body() -> String {
    format!(
        "Active connections: {} \nserver accepts handled requests\n {} {} {} \nReading: {} Writing: {} Waiting: {} \n",
        get(slot::ACTIVE),
        get(slot::ACCEPTS),
        get(slot::HANDLED),
        get(slot::REQUESTS),
        get(slot::READING),
        get(slot::WRITING),
        get(slot::WAITING),
    )
}

/// The same counters plus per-peer upstream state, as JSON.
///
/// `stub_status json` is **not** an nginx directive — nginx has no upstream
/// visibility outside its commercial build. It is here because a load balancer
/// whose pool state cannot be inspected is a load balancer you debug by
/// guessing, and because the health data already exists: this only reads what
/// `least_conn` and the health checks are already maintaining.
pub fn json_body(http: &crate::config::model::Http) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("{\n  \"connections\": {");
    s.push_str(&format!(
        "\"active\": {}, \"accepts\": {}, \"handled\": {}, \"requests\": {}, ",
        get(slot::ACTIVE),
        get(slot::ACCEPTS),
        get(slot::HANDLED),
        get(slot::REQUESTS)
    ));
    s.push_str(&format!(
        "\"reading\": {}, \"writing\": {}, \"waiting\": {}}},\n",
        get(slot::READING),
        get(slot::WRITING),
        get(slot::WAITING)
    ));

    s.push_str("  \"upstreams\": {");
    let mut names: Vec<&Box<str>> = http.upstreams.keys().collect();
    // Sorted so the output is stable between requests; a diffable status page
    // is worth more than saving a sort on an endpoint nobody polls hard.
    names.sort();
    for (i, name) in names.iter().enumerate() {
        let up = &http.upstreams[&***name];
        let now_ms = std::time::Instant::now()
            .saturating_duration_since(up.origin)
            .as_millis() as u64;
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("\n    {}: [", json_str(name)));
        for (j, srv) in up.servers.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            let h = &up.health[j];
            let state = if srv.down {
                "down"
            } else if h.is_down(now_ms) {
                "unhealthy"
            } else {
                "up"
            };
            s.push_str(&format!(
                "\n      {{\"server\": {}, \"state\": \"{}\", \"in_flight\": {}, \"weight\": {}, \"backup\": {}}}",
                json_str(&srv.addr),
                state,
                h.in_flight(),
                srv.weight,
                srv.backup
            ));
        }
        s.push_str("\n    ]");
    }
    s.push_str("\n  }\n}\n");
    s
}

/// Minimal JSON string escaping. Addresses and upstream names are the only
/// things that reach it, but a config is user input and a stray quote should
/// not produce a document nobody can parse.
fn json_str(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_status_format_is_nginx_exact() {
        init();
        let body = stub_status_body();
        let lines: Vec<&str> = body.split('\n').collect();
        // Four lines plus the trailing empty one from the final newline.
        assert_eq!(lines.len(), 5, "unexpected line count in {body:?}");
        assert!(lines[0].starts_with("Active connections: "), "{body:?}");
        assert!(lines[0].ends_with(' '), "nginx leaves a trailing space: {body:?}");
        assert_eq!(lines[1], "server accepts handled requests");
        assert!(lines[2].starts_with(' '), "the counters line is indented: {body:?}");
        assert!(lines[3].starts_with("Reading: "), "{body:?}");
        assert!(lines[3].contains(" Writing: ") && lines[3].contains(" Waiting: "), "{body:?}");
        assert_eq!(lines[4], "");
    }

    #[test]
    fn a_state_guard_returns_its_count_on_every_path() {
        init();
        let before = get(slot::READING);
        {
            let _g = StateGuard::enter(State::Reading);
            assert_eq!(get(slot::READING), before + 1);
        }
        assert_eq!(get(slot::READING), before, "the guard must release on drop");
    }

    #[test]
    fn switching_state_moves_the_count_rather_than_duplicating_it() {
        init();
        let (r0, w0) = (get(slot::READING), get(slot::WRITING));
        let mut g = StateGuard::enter(State::Reading);
        g.switch(State::Writing);
        assert_eq!(get(slot::READING), r0, "reading must be given back");
        assert_eq!(get(slot::WRITING), w0 + 1);
        // Switching to the state already held is a no-op, not a double count.
        g.switch(State::Writing);
        assert_eq!(get(slot::WRITING), w0 + 1);
        drop(g);
        assert_eq!(get(slot::WRITING), w0);
    }

    #[test]
    fn counters_work_before_init_without_panicking() {
        // `stub_status` in a config that somehow never initialised the block
        // must report zeroes, not abort a request.
        assert!(stub_status_body().contains("Active connections:"));
        request_done();
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("tab\there"), "\"tab\\there\"");
    }
}

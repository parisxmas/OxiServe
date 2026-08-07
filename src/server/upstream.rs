//! Per-peer runtime state for `upstream` blocks: health, in-flight counts,
//! and the idle connection pool.
//!
//! Implements items 1–3 of [ADR-0001]: passive health tracking, a keepalive
//! pool, and a real `least_conn`. They live together because they are the same
//! state viewed three ways — whether a peer is usable, how loaded it is, and
//! which of its connections can be reused.
//!
//! Health is shared across workers (atomics behind the `Arc<Upstream>`) so one
//! worker discovering a dead backend spares the others from rediscovering it.
//! The connection pool is deliberately **not** shared: a socket is registered
//! with the reactor of the worker that opened it, so handing it to another
//! thread would be wrong.
//!
//! [ADR-0001]: ../../docs/decisions/0001-load-balancer-scope.md

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::config::model::{LbMethod, Upstream};

/// Liveness and load for one upstream server.
#[derive(Debug, Default)]
pub struct PeerHealth {
    /// Failures counted inside the current `fail_timeout` window.
    fails: AtomicU32,
    /// Milliseconds (since the upstream's origin) until which this peer stays
    /// out of rotation. Zero means available.
    down_until_ms: AtomicU64,
    /// When the current failure window started, for expiring stale counts.
    window_start_ms: AtomicU64,
    /// Requests in flight right now — the number `least_conn` balances on.
    in_flight: AtomicU32,
    /// Consecutive failed active probes.
    probe_fails: AtomicU32,
    /// Consecutive successful active probes.
    probe_passes: AtomicU32,
    /// Set by the active checker. Separate from `down_until_ms` because it has
    /// no expiry: a peer failing its probes stays out until the probes say
    /// otherwise, rather than drifting back in after a timeout.
    probe_down: AtomicBool,
}

impl PeerHealth {
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn is_down(&self, now_ms: u64) -> bool {
        if self.probe_down.load(Ordering::Relaxed) {
            return true;
        }
        let until = self.down_until_ms.load(Ordering::Relaxed);
        until != 0 && now_ms < until
    }

    /// Records the result of one active probe.
    ///
    /// The counters are consecutive, and each result clears the other's: a
    /// peer must fail `fails` times in a row to go down and pass `passes`
    /// times in a row to come back. That hysteresis is the whole point — a
    /// single blip should not flap a peer in or out of rotation.
    pub fn record_probe(&self, ok: bool, fails: u32, passes: u32) {
        if ok {
            self.probe_fails.store(0, Ordering::Relaxed);
            let p = self.probe_passes.fetch_add(1, Ordering::Relaxed) + 1;
            if p >= passes.max(1) {
                self.probe_down.store(false, Ordering::Relaxed);
                // A peer the probes have vouched for should not stay out on
                // stale passive failures either.
                self.fails.store(0, Ordering::Relaxed);
                self.down_until_ms.store(0, Ordering::Relaxed);
            }
        } else {
            self.probe_passes.store(0, Ordering::Relaxed);
            let f = self.probe_fails.fetch_add(1, Ordering::Relaxed) + 1;
            if f >= fails.max(1) {
                self.probe_down.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Whether the active checker currently considers this peer down.
    pub fn probe_says_down(&self) -> bool {
        self.probe_down.load(Ordering::Relaxed)
    }

    /// Records a failed attempt. Once `max_fails` failures land inside one
    /// `fail_timeout` window the peer is taken out for that long — nginx's
    /// passive check, which until now was parsed and never enforced.
    pub fn record_failure(&self, now_ms: u64, max_fails: u32, fail_timeout_ms: u64) {
        if max_fails == 0 {
            return; // max_fails=0 disables the check, as in nginx
        }
        let start = self.window_start_ms.load(Ordering::Relaxed);
        // Whether a window is open is decided by the counter, not by the
        // timestamp: zero is a legitimate instant (a failure in the first
        // millisecond of the process) and using it as a sentinel meant the
        // count reset on every failure and a peer was never ejected.
        let counting = self.fails.load(Ordering::Relaxed) > 0;
        // A failure long after the last one starts a fresh window rather than
        // accumulating forever.
        let fails = if !counting || now_ms.saturating_sub(start) > fail_timeout_ms {
            self.window_start_ms.store(now_ms, Ordering::Relaxed);
            self.fails.store(1, Ordering::Relaxed);
            1
        } else {
            self.fails.fetch_add(1, Ordering::Relaxed) + 1
        };

        if fails >= max_fails {
            self.down_until_ms
                .store(now_ms + fail_timeout_ms, Ordering::Relaxed);
        }
    }

    /// A success clears the slate: the peer is healthy again.
    pub fn record_success(&self) {
        self.fails.store(0, Ordering::Relaxed);
        self.window_start_ms.store(0, Ordering::Relaxed);
        self.down_until_ms.store(0, Ordering::Relaxed);
    }
}

/// Increments the in-flight count for a peer and decrements it on drop, so a
/// `?` or a panic mid-request cannot leak the count and slowly poison
/// `least_conn`.
pub struct InFlightGuard<'a> {
    health: &'a PeerHealth,
}

impl<'a> InFlightGuard<'a> {
    pub fn enter(health: &'a PeerHealth) -> InFlightGuard<'a> {
        health.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard { health }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.health.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Chooses a peer, skipping any that passive health has taken out.
///
/// Primary servers are tried first; only when every primary is down do backup
/// servers enter the rotation. If everything is down, the least recently
/// failed peer is returned anyway — refusing to try at all would turn a
/// transient outage into a permanent one.
pub fn select(up: &Upstream, now: Instant, hash: Option<u64>, rr_cursor: usize) -> Option<usize> {
    select_excluding(up, now, hash, rr_cursor, &[])
}

/// The peer a sticky cookie names, if it can still take the request.
///
/// Returns `None` — and so falls through to ordinary balancing — when the
/// cookie is absent, names nothing we recognise, or names a peer that is
/// administratively down, health-ejected, or already tried and failed in this
/// request. Honouring a pin to a dead backend would be worse than having no
/// stickiness at all: every one of that peer's clients would get an error
/// instead of being spread over the survivors.
pub fn sticky_peer(
    up: &Upstream,
    now: Instant,
    cookie: Option<&str>,
    exclude: &[usize],
) -> Option<usize> {
    let id = cookie?;
    up.sticky.as_ref()?;
    let now_ms = now.saturating_duration_since(up.origin).as_millis() as u64;
    let i = up.servers.iter().position(|s| &*s.sticky_id == id)?;
    let ok = !up.servers[i].down && !up.health[i].is_down(now_ms) && !exclude.contains(&i);
    ok.then_some(i)
}

/// [`select`], skipping peers already tried for this request.
///
/// `proxy_next_upstream` needs this: retrying is only useful against a peer
/// that has not just failed, and round-robin alone would happily hand back the
/// same one — a "retry" that repeats the failure and doubles the latency.
pub fn select_excluding(
    up: &Upstream,
    now: Instant,
    hash: Option<u64>,
    rr_cursor: usize,
    exclude: &[usize],
) -> Option<usize> {
    let now_ms = now.saturating_duration_since(up.origin).as_millis() as u64;

    for want_backup in [false, true] {
        let candidates: Vec<usize> = up
            .servers
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                !s.down
                    && s.backup == want_backup
                    && !up.health[*i].is_down(now_ms)
                    && !exclude.contains(i)
            })
            .map(|(i, _)| i)
            .collect();

        if candidates.is_empty() {
            continue;
        }
        return Some(pick_from(up, &candidates, hash, rr_cursor));
    }

    // Everything is marked down. Take the peer whose penalty expires soonest
    // so recovery is attempted rather than waiting for a health check we do
    // not have yet. Excluded peers stay excluded: one already tried and failed
    // in this very request is the worst candidate there is.
    up.servers
        .iter()
        .enumerate()
        .filter(|(i, s)| !s.down && !exclude.contains(i))
        .min_by_key(|(i, _)| up.health[*i].down_until_ms.load(Ordering::Relaxed))
        .map(|(i, _)| i)
}

fn pick_from(up: &Upstream, candidates: &[usize], hash: Option<u64>, rr_cursor: usize) -> usize {
    match up.method {
        LbMethod::IpHash => {
            let h = hash.unwrap_or(0);
            candidates[(h % candidates.len() as u64) as usize]
        }
        LbMethod::LeastConn => {
            // Fewest in-flight wins; weight breaks ties so a heavier server
            // takes proportionally more load, as nginx does.
            *candidates
                .iter()
                .min_by_key(|&&i| {
                    let w = up.servers[i].weight.max(1) as u64;
                    // Scale so a weight-2 peer is preferred until it carries
                    // twice the connections of a weight-1 peer.
                    (up.health[i].in_flight() as u64 * 1000) / w
                })
                .expect("candidates is non-empty")
        }
        LbMethod::Random => candidates[rr_cursor % candidates.len()],
        LbMethod::RoundRobin => {
            // Weighted round robin: a peer with weight N occupies N slots.
            let total: u32 = candidates.iter().map(|&i| up.servers[i].weight.max(1)).sum();
            let mut slot = (rr_cursor as u32) % total.max(1);
            for &i in candidates {
                let w = up.servers[i].weight.max(1);
                if slot < w {
                    return i;
                }
                slot -= w;
            }
            candidates[0]
        }
    }
}

// ---------------------------------------------------------------------------
// Idle connection pool
// ---------------------------------------------------------------------------

use super::transport::Stream;

struct Idle {
    stream: Stream,
    /// When it was returned, so a long-idle connection is not handed out after
    /// the peer has already closed it.
    since: Instant,
}

thread_local! {
    /// Idle upstream connections for this worker, keyed by peer address.
    static POOL: RefCell<HashMap<String, Vec<Idle>>> = RefCell::new(HashMap::new());
}

/// How long an idle connection may sit before it is assumed dead. Upstreams
/// commonly close at 60s; staying well under avoids handing out a socket that
/// the peer has already reset.
const MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Takes a pooled connection for `addr`, if one is available and fresh.
pub fn take(addr: &str) -> Option<Stream> {
    POOL.with(|p| {
        let mut pool = p.borrow_mut();
        let entries = pool.get_mut(addr)?;
        // Newest first: the most recently used connection is likeliest alive.
        while let Some(idle) = entries.pop() {
            if idle.since.elapsed() >= MAX_IDLE {
                // Entries below are older still.
                entries.clear();
                return None;
            }
            // Verified here rather than discovered mid-request: handing out a
            // connection the peer already closed would surface as a 502 caused
            // by our own reuse, and would wrongly count against the peer's
            // health.
            if idle.stream.is_reusable() {
                return Some(idle.stream);
            }
            // Dead or dirty: drop it and try the next.
        }
        None
    })
}

/// Returns a connection to the pool after a clean exchange.
///
/// Only ever called when the full response body was read and neither side
/// asked to close — a connection returned mid-body would corrupt the next
/// request that picked it up.
pub fn put(addr: &str, stream: Stream, keepalive: usize) {
    if keepalive == 0 {
        return;
    }
    POOL.with(|p| {
        let mut pool = p.borrow_mut();
        let entries = pool.entry(addr.to_string()).or_default();
        if entries.len() >= keepalive {
            // At capacity: drop the oldest rather than growing without bound.
            entries.remove(0);
        }
        entries.push(Idle { stream, since: Instant::now() });
    });
}

/// Idle connections held for `addr` on this worker. Test hook.
#[cfg(test)]
pub fn pooled(addr: &str) -> usize {
    POOL.with(|p| p.borrow().get(addr).map(|v| v.len()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::UpstreamServer;
    use std::time::Duration;

    fn peer(addr: &str, weight: u32, backup: bool, down: bool) -> UpstreamServer {
        UpstreamServer {
            sticky_id: crate::config::model::sticky_id_for(addr),
            addr: addr.into(),
            weight,
            max_fails: 2,
            fail_timeout: Duration::from_secs(10),
            backup,
            down,
            max_conns: None,
        }
    }

    fn upstream(servers: Vec<UpstreamServer>, method: LbMethod) -> Upstream {
        let health = servers.iter().map(|_| PeerHealth::default()).collect();
        Upstream {
            name: "test".into(),
            servers,
            method,
            keepalive: 0,
            health,
            origin: Instant::now(),
            health_check: None,
            sticky: None,
        }
    }

    #[test]
    fn healthy_peers_are_selected() {
        let up = upstream(vec![peer("a", 1, false, false), peer("b", 1, false, false)], LbMethod::RoundRobin);
        let now = Instant::now();
        assert!(select(&up, now, None, 0).is_some());
    }

    #[test]
    fn failures_take_a_peer_out_after_max_fails() {
        let up = upstream(vec![peer("a", 1, false, false), peer("b", 1, false, false)], LbMethod::RoundRobin);
        let now = Instant::now();
        // max_fails = 2: one failure is not enough.
        up.health[0].record_failure(0, 2, 10_000);
        assert_eq!(select(&up, now, None, 0), Some(0), "one failure must not eject");
        up.health[0].record_failure(1, 2, 10_000);
        // Now peer 0 is out and every selection must land on peer 1.
        for cursor in 0..8 {
            assert_eq!(select(&up, now, None, cursor), Some(1), "dead peer must be skipped");
        }
    }

    #[test]
    fn a_peer_returns_after_fail_timeout() {
        let up = upstream(vec![peer("a", 1, false, false), peer("b", 1, false, false)], LbMethod::RoundRobin);
        up.health[0].record_failure(0, 1, 5_000); // out until t=5000ms
        let origin = up.origin;
        assert_eq!(select(&up, origin + Duration::from_millis(1000), None, 0), Some(1));
        // Past the penalty window it is eligible again.
        let later = origin + Duration::from_millis(6000);
        let picks: Vec<_> = (0..4).map(|c| select(&up, later, None, c)).collect();
        assert!(picks.contains(&Some(0)), "peer must return after fail_timeout: {picks:?}");
    }

    #[test]
    fn success_clears_the_failure_count() {
        let up = upstream(vec![peer("a", 1, false, false)], LbMethod::RoundRobin);
        up.health[0].record_failure(0, 2, 10_000);
        up.health[0].record_success();
        // The earlier failure is forgotten, so one more must not eject.
        up.health[0].record_failure(1, 2, 10_000);
        assert!(!up.health[0].is_down(2), "count must have restarted after success");
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let up = upstream(vec![peer("a", 1, false, false)], LbMethod::RoundRobin);
        up.health[0].record_failure(0, 3, 1_000);
        // Well past the window: this starts a new one rather than adding on.
        up.health[0].record_failure(50_000, 3, 1_000);
        up.health[0].record_failure(50_100, 3, 1_000);
        assert!(!up.health[0].is_down(50_200), "stale failures must expire");
    }

    #[test]
    fn backups_are_used_only_when_primaries_are_down() {
        let up = upstream(
            vec![peer("primary", 1, false, false), peer("backup", 1, true, false)],
            LbMethod::RoundRobin,
        );
        let now = Instant::now();
        assert_eq!(select(&up, now, None, 0), Some(0), "primary preferred");
        up.health[0].record_failure(0, 1, 10_000);
        assert_eq!(select(&up, now, None, 0), Some(1), "backup takes over");
    }

    #[test]
    fn everything_down_still_attempts_recovery() {
        // Refusing to try would turn a transient outage into a permanent one.
        let up = upstream(vec![peer("a", 1, false, false), peer("b", 1, false, false)], LbMethod::RoundRobin);
        up.health[0].record_failure(0, 1, 10_000);
        up.health[1].record_failure(0, 1, 10_000);
        assert!(select(&up, Instant::now(), None, 0).is_some(), "must still try someone");
    }

    #[test]
    fn explicitly_down_servers_are_never_selected() {
        let up = upstream(
            vec![peer("off", 1, false, true), peer("on", 1, false, false)],
            LbMethod::RoundRobin,
        );
        for c in 0..8 {
            assert_eq!(select(&up, Instant::now(), None, c), Some(1));
        }
    }

    #[test]
    fn least_conn_prefers_the_idle_peer() {
        let up = upstream(
            vec![peer("busy", 1, false, false), peer("idle", 1, false, false)],
            LbMethod::LeastConn,
        );
        let _g1 = InFlightGuard::enter(&up.health[0]);
        let _g2 = InFlightGuard::enter(&up.health[0]);
        assert_eq!(up.health[0].in_flight(), 2);
        assert_eq!(select(&up, Instant::now(), None, 0), Some(1), "least loaded must win");
    }

    #[test]
    fn in_flight_count_is_released_on_drop() {
        let up = upstream(vec![peer("a", 1, false, false)], LbMethod::LeastConn);
        {
            let _g = InFlightGuard::enter(&up.health[0]);
            assert_eq!(up.health[0].in_flight(), 1);
        }
        assert_eq!(up.health[0].in_flight(), 0, "guard must release on drop");
    }

    #[test]
    fn least_conn_respects_weight() {
        let up = upstream(
            vec![peer("light", 1, false, false), peer("heavy", 2, false, false)],
            LbMethod::LeastConn,
        );
        // An idle peer always wins, whatever the weights — sending work to a
        // server doing nothing is the point of least_conn.
        let _a = InFlightGuard::enter(&up.health[1]);
        assert_eq!(select(&up, Instant::now(), None, 0), Some(0), "idle peer wins");

        // With both busy, weight decides: heavy carries 1 connection against
        // light's 1, but has twice the capacity, so it takes the next one.
        let _b = InFlightGuard::enter(&up.health[0]);
        assert_eq!(select(&up, Instant::now(), None, 0), Some(1), "weight breaks the tie");
    }

    #[test]
    fn round_robin_honours_weight() {
        let up = upstream(
            vec![peer("a", 1, false, false), peer("b", 3, false, false)],
            LbMethod::RoundRobin,
        );
        let now = Instant::now();
        let picks: Vec<usize> = (0..8).map(|c| select(&up, now, None, c).unwrap()).collect();
        let b_share = picks.iter().filter(|&&i| i == 1).count();
        assert_eq!(b_share, 6, "weight 3 vs 1 should take 3/4 of requests: {picks:?}");
    }

    #[test]
    fn ip_hash_is_stable_for_the_same_client() {
        let up = upstream(
            vec![peer("a", 1, false, false), peer("b", 1, false, false), peer("c", 1, false, false)],
            LbMethod::IpHash,
        );
        let now = Instant::now();
        let first = select(&up, now, Some(12345), 0);
        for _ in 0..10 {
            assert_eq!(select(&up, now, Some(12345), 0), first, "same client must be sticky");
        }
    }
}

// ---------------------------------------------------------------------------
// Active health checks
// ---------------------------------------------------------------------------

use crate::config::model::HealthCheck;

/// Probes every peer of an upstream once and records the results.
///
/// Runs on one worker only. Several workers probing the same backend would
/// multiply the load on it by the worker count for no extra information, and
/// the health state they write to is shared anyway.
pub async fn probe_round(up: &Arc<Upstream>, hc: &HealthCheck) {
    for (i, server) in up.servers.iter().enumerate() {
        if server.down {
            continue; // administratively disabled; nothing to learn
        }
        let addr = if server.addr.starts_with("unix:") || server.addr.contains(':') {
            server.addr.to_string()
        } else {
            format!("{}:80", server.addr)
        };
        let ok = probe_one(&addr, hc).await;
        up.health[i].record_probe(ok, hc.fails, hc.passes);
    }
}

/// One probe: connect, and for an HTTP check also send a request and read the
/// status line.
async fn probe_one(addr: &str, hc: &HealthCheck) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let connect = tokio::time::timeout(hc.timeout, super::transport::Stream::connect(addr));
    let Ok(Ok(mut sock)) = connect.await else {
        return false;
    };

    let Some(uri) = &hc.uri else {
        // A TCP check: being able to connect is the whole test. That is all
        // that is meaningful in front of a database or a message broker.
        return true;
    };

    let host = addr.strip_prefix("unix:").unwrap_or(addr);
    let req = format!(
        "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: oxiserve-health\r\n\
         Connection: close\r\n\r\n"
    );
    if tokio::time::timeout(hc.timeout, sock.write_all(req.as_bytes()))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return false;
    }

    // Only the status line is needed, so read once rather than draining the
    // whole response — a probe should be cheap for the backend too.
    let mut buf = [0u8; 256];
    let n = match tokio::time::timeout(hc.timeout, sock.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return false,
    };

    parse_status(&buf[..n]) == Some(hc.expect_status)
}

/// Extracts the status code from a status line, without a full HTTP parse.
fn parse_status(buf: &[u8]) -> Option<u16> {
    let line = buf.split(|&b| b == b'\r' || b == b'\n').next()?;
    let mut parts = line.split(|&b| b == b' ');
    let version = parts.next()?;
    if !version.starts_with(b"HTTP/") {
        return None;
    }
    std::str::from_utf8(parts.next()?).ok()?.parse().ok()
}

#[cfg(test)]
mod health_check_tests {
    use super::*;
    use crate::config::model::UpstreamServer;
    use std::time::Duration;

    fn health() -> PeerHealth {
        PeerHealth::default()
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(parse_status(b"HTTP/1.1 404\r\n"), Some(404));
        // Anything that is not a status line must not be read as a success.
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b""), None);
        assert_eq!(parse_status(b"+OK redis\r\n"), None);
    }

    #[test]
    fn a_peer_goes_down_only_after_consecutive_failures() {
        let h = health();
        // fails=3: two failures are not enough.
        h.record_probe(false, 3, 1);
        h.record_probe(false, 3, 1);
        assert!(!h.probe_says_down(), "two of three failures must not eject");
        h.record_probe(false, 3, 1);
        assert!(h.probe_says_down(), "the third must");
    }

    #[test]
    fn a_success_resets_the_failure_streak() {
        // The counters are consecutive: a blip between failures must not
        // accumulate towards ejection.
        let h = health();
        h.record_probe(false, 3, 1);
        h.record_probe(false, 3, 1);
        h.record_probe(true, 3, 1);
        h.record_probe(false, 3, 1);
        h.record_probe(false, 3, 1);
        assert!(!h.probe_says_down(), "the streak must have restarted");
    }

    #[test]
    fn recovery_needs_consecutive_passes() {
        let h = health();
        h.record_probe(false, 1, 3);
        assert!(h.probe_says_down());
        h.record_probe(true, 1, 3);
        h.record_probe(true, 1, 3);
        assert!(h.probe_says_down(), "two of three passes must not restore");
        h.record_probe(true, 1, 3);
        assert!(!h.probe_says_down(), "the third must");
    }

    #[test]
    fn a_failure_during_recovery_restarts_the_count() {
        let h = health();
        h.record_probe(false, 1, 3);
        h.record_probe(true, 1, 3);
        h.record_probe(true, 1, 3);
        h.record_probe(false, 1, 3); // blip
        h.record_probe(true, 1, 3);
        h.record_probe(true, 1, 3);
        assert!(h.probe_says_down(), "recovery must start over after a failure");
    }

    #[test]
    fn probe_down_has_no_expiry_unlike_passive_ejection() {
        // Passive ejection lapses after fail_timeout; an active check has a
        // live opinion, so it must not drift back in on its own.
        let h = health();
        h.record_probe(false, 1, 1);
        assert!(h.is_down(0));
        assert!(h.is_down(u64::MAX / 2), "must stay down until the probes say otherwise");
        h.record_probe(true, 1, 1);
        assert!(!h.is_down(0));
    }

    #[test]
    fn a_vouched_peer_is_cleared_of_stale_passive_failures() {
        // Passive tracking may have ejected a peer that has since recovered.
        // Once probes vouch for it, that stale penalty must not keep it out.
        let h = health();
        h.record_failure(0, 1, 60_000); // passive: down until t=60s
        assert!(h.is_down(1000));
        h.record_probe(true, 1, 1);
        assert!(!h.is_down(1000), "an active pass must clear a passive ejection");
    }

    #[test]
    fn administratively_down_servers_are_not_probed() {
        // `server ... down;` means the operator took it out; probing it would
        // be load on a machine nobody asked us to talk to.
        let servers = vec![UpstreamServer {
            sticky_id: crate::config::model::sticky_id_for("127.0.0.1:1"),
            addr: "127.0.0.1:1".into(),
            weight: 1,
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
            backup: false,
            down: true,
            max_conns: None,
        }];
        let up = Arc::new(Upstream {
            name: "t".into(),
            servers,
            method: LbMethod::RoundRobin,
            keepalive: 0,
            health: vec![PeerHealth::default()],
            origin: Instant::now(),
            health_check: None,
            sticky: None,
        });
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(probe_round(&up, &HealthCheck::default()));
        // No probe ran, so nothing was recorded either way.
        assert!(!up.health[0].probe_says_down());
    }
}

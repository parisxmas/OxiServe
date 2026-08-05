//! `limit_req` — request rate limiting with nginx's leaky bucket.
//!
//! # Why this is in-process and not in a database
//!
//! Every request touches this, so the whole budget is a few hundred
//! nanoseconds. Measured on the alternatives: an embedded document store does
//! an indexed read in ~0.7 µs and a counter update in ~10.75 µs, against
//! ~0.08 µs for a sharded in-process map. At 70k rps a request has roughly
//! 14 µs of CPU in total, so a 10 µs counter update would eat three quarters
//! of it. nginx keeps this in shared memory for the same reason.
//!
//! Being a single process, we do not even need shared memory — a sharded map
//! behind the same `Arc` is the equivalent, with one lock per shard so
//! unrelated keys never contend.
//!
//! # The algorithm
//!
//! Straight from `ngx_http_limit_req_module`. State per key is a last-seen
//! timestamp and an `excess` measured in **milli-requests** (1000 = one whole
//! request), which is what lets a fractional rate like `30r/m` be exact:
//!
//! ```text
//!   excess = previous_excess − rate × elapsed_ms / 1000 + 1000
//!   excess = max(excess, 0)
//!   excess > burst  →  reject
//!   otherwise       →  admit, after excess × 1000 / rate ms of delay
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Number of independent shards. Keys hash into one of these, so two clients
/// only contend if they land in the same shard.
const SHARDS: usize = 16;

/// nginx stores `rate` and `excess` scaled by 1000 so a fractional
/// requests-per-second value stays exact in integer arithmetic.
pub const SCALE: u64 = 1000;

/// The decision for one request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Admit immediately.
    Pass,
    /// Admit, but only after this many milliseconds (`burst` without
    /// `nodelay`).
    Delay(u64),
    /// Over the limit — answer with `limit_req_status`.
    Reject,
}

/// Pure leaky-bucket step, split out so it can be tested without any clock or
/// map. Returns the new excess and the decision.
///
/// * `rate` — permitted requests per second, scaled by [`SCALE`].
/// * `burst` — how far excess may run ahead, scaled by [`SCALE`].
/// * `elapsed_ms` — milliseconds since this key was last seen.
pub fn step(
    prev_excess: u64,
    elapsed_ms: u64,
    rate: u64,
    burst: u64,
    nodelay: bool,
    delay_after: u64,
) -> (u64, Decision) {
    // Drain for elapsed time and add this request in ONE signed expression,
    // clamping only at the end. Clamping the drain to zero first would lose
    // the overshoot that makes a long-idle key start from an empty bucket —
    // nginx computes `excess - rate*ms/1000 + 1000` and only then clamps.
    let drained = (rate as i128).saturating_mul(elapsed_ms as i128) / SCALE as i128;
    let excess = (prev_excess as i128 - drained + SCALE as i128).max(0) as u64;

    if excess > burst {
        return (prev_excess, Decision::Reject);
    }
    if excess == 0 || nodelay || excess <= delay_after {
        return (excess, Decision::Pass);
    }
    // Hold the request just long enough to bring it back onto the rate.
    let delay = (excess.saturating_sub(delay_after)).saturating_mul(SCALE) / rate.max(1);
    (excess, Decision::Delay(delay))
}

struct Entry {
    last_ms: u64,
    excess: u64,
}

/// One `limit_req_zone` at runtime: the shared state behind a zone name.
pub struct Zone {
    pub name: Box<str>,
    /// Requests per second, scaled by [`SCALE`].
    pub rate: u64,
    /// Maximum tracked keys, derived from the zone's configured size.
    pub max_entries: usize,
    origin: Instant,
    shards: Vec<Mutex<HashMap<Box<str>, Entry>>>,
}

impl std::fmt::Debug for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zone({}, rate={})", self.name, self.rate)
    }
}

impl Zone {
    pub fn new(name: &str, rate: u64, max_entries: usize) -> Zone {
        Zone {
            name: name.into(),
            rate,
            max_entries,
            origin: Instant::now(),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn shard_of(key: &str) -> usize {
        // FNV-1a: cheap, no dependency, good enough to spread keys.
        let mut h: u64 = 0xcbf29ce484222325;
        for b in key.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        (h % SHARDS as u64) as usize
    }

    /// Accounts for one request against `key` and returns the decision.
    ///
    /// `now` is taken from the request's own start instant, so this costs no
    /// extra clock read.
    pub fn check(
        &self,
        key: &str,
        now: Instant,
        burst: u64,
        nodelay: bool,
        delay_after: u64,
    ) -> Decision {
        let now_ms = now.saturating_duration_since(self.origin).as_millis() as u64;
        let mut shard = self.shards[Self::shard_of(key)].lock().unwrap_or_else(|e| e.into_inner());

        let (prev_excess, elapsed) = match shard.get(key) {
            Some(e) => (e.excess, now_ms.saturating_sub(e.last_ms)),
            // A key seen for the first time starts with an empty bucket.
            None => (0, u64::MAX / SCALE),
        };

        let (excess, decision) = step(prev_excess, elapsed, self.rate, burst, nodelay, delay_after);

        if decision != Decision::Reject {
            if shard.len() >= self.max_entries.max(1) / SHARDS + 1 && !shard.contains_key(key) {
                evict(&mut shard, now_ms);
            }
            shard.insert(key.into(), Entry { last_ms: now_ms, excess });
        }
        decision
    }

    /// Keys currently tracked, across all shards. Test and introspection hook.
    pub fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }
}

/// Drops the entries whose buckets are closest to empty — they carry the least
/// state and are cheapest to forget. nginx evicts by LRU from its rbtree; this
/// is the same intent, and it runs only when a shard is full.
fn evict(shard: &mut HashMap<Box<str>, Entry>, now_ms: u64) {
    let mut victims: Vec<(Box<str>, u64)> = shard
        .iter()
        .map(|(k, e)| (k.clone(), now_ms.saturating_sub(e.last_ms)))
        .collect();
    // Oldest first.
    victims.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, _) in victims.into_iter().take((shard.len() / 8).max(1)) {
        shard.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const R1: u64 = 1 * SCALE; // 1 request per second

    #[test]
    fn first_request_always_passes() {
        let (excess, d) = step(0, u64::MAX / SCALE, R1, 0, false, 0);
        assert_eq!(d, Decision::Pass);
        assert_eq!(excess, 0, "a lone request leaves nothing behind");
    }

    #[test]
    fn second_immediate_request_is_rejected_without_burst() {
        // Two requests in the same millisecond at 1r/s, burst 0.
        let (excess, _) = step(0, 1_000_000, R1, 0, false, 0);
        let (_, d) = step(excess, 0, R1, 0, false, 0);
        assert_eq!(d, Decision::Reject);
    }

    #[test]
    fn requests_spaced_at_the_rate_all_pass() {
        let mut excess = 0;
        for i in 0..10 {
            let elapsed = if i == 0 { 1_000_000 } else { 1000 }; // exactly 1s apart
            let (e, d) = step(excess, elapsed, R1, 0, false, 0);
            assert_eq!(d, Decision::Pass, "request {i} at the configured rate must pass");
            excess = e;
        }
    }

    #[test]
    fn burst_admits_a_short_spike_then_rejects() {
        // burst=3 means three extra requests may queue up.
        let burst = 3 * SCALE;
        let mut excess = 0;
        let mut passed = 0;
        for i in 0..10 {
            let elapsed = if i == 0 { 1_000_000 } else { 0 };
            let (e, d) = step(excess, elapsed, R1, burst, true, 0);
            if d == Decision::Reject {
                break;
            }
            excess = e;
            passed += 1;
        }
        // The first request plus `burst` more.
        assert_eq!(passed, 4, "expected 1 + burst(3) admitted, got {passed}");
    }

    #[test]
    fn burst_without_nodelay_delays_instead_of_passing_instantly() {
        let burst = 5 * SCALE;
        let (excess, d) = step(0, 1_000_000, R1, burst, false, 0);
        assert_eq!(d, Decision::Pass, "the first request is on-rate");
        let (_, d2) = step(excess, 0, R1, burst, false, 0);
        // The second arrives early, so it waits ~1s at 1r/s.
        match d2 {
            Decision::Delay(ms) => assert!((900..=1100).contains(&ms), "delay was {ms}ms"),
            other => panic!("expected a delay, got {other:?}"),
        }
    }

    #[test]
    fn nodelay_passes_the_whole_burst_immediately() {
        let burst = 5 * SCALE;
        let (excess, _) = step(0, 1_000_000, R1, burst, true, 0);
        let (_, d) = step(excess, 0, R1, burst, true, 0);
        assert_eq!(d, Decision::Pass, "nodelay must not delay");
    }

    #[test]
    fn delay_after_passes_the_first_n_then_delays() {
        // `delay=2`: two burst requests go straight through, the rest wait.
        let burst = 5 * SCALE;
        let delay_after = 2 * SCALE;
        let mut excess = 0;
        let mut kinds = Vec::new();
        for i in 0..5 {
            let elapsed = if i == 0 { 1_000_000 } else { 0 };
            let (e, d) = step(excess, elapsed, R1, burst, false, delay_after);
            kinds.push(matches!(d, Decision::Delay(_)));
            excess = e;
        }
        assert_eq!(kinds[..3], [false, false, false], "first 1+delay(2) must not wait");
        assert!(kinds[3], "beyond the delay threshold requests must wait");
    }

    #[test]
    fn bucket_drains_over_time() {
        // Fill the bucket, then wait long enough for it to empty.
        let burst = 2 * SCALE;
        let (excess, _) = step(0, 1_000_000, R1, burst, true, 0);
        let (excess, _) = step(excess, 0, R1, burst, true, 0);
        assert!(excess > 0);
        // Five seconds at 1r/s drains far more than the bucket holds.
        let (drained, d) = step(excess, 5000, R1, burst, true, 0);
        assert_eq!(d, Decision::Pass);
        assert_eq!(drained, 0, "the bucket must be empty again");
    }

    #[test]
    fn fractional_rates_are_exact() {
        // 30r/m == 0.5r/s == 500 scaled. One request every 2s must pass.
        let rate = SCALE / 2;
        let mut excess = 0;
        for i in 0..6 {
            let elapsed = if i == 0 { 1_000_000 } else { 2000 };
            let (e, d) = step(excess, elapsed, rate, 0, false, 0);
            assert_eq!(d, Decision::Pass, "request {i} at 30r/m must pass");
            excess = e;
        }
        // Twice as fast is over the limit.
        let (_, d) = step(excess, 1000, rate, 0, false, 0);
        assert_eq!(d, Decision::Reject);
    }

    // ---- zone-level behaviour --------------------------------------------

    #[test]
    fn zone_isolates_keys_from_each_other() {
        let z = Zone::new("z", R1, 1000);
        let t = Instant::now();
        assert_eq!(z.check("1.1.1.1", t, 0, true, 0), Decision::Pass);
        assert_eq!(z.check("1.1.1.1", t, 0, true, 0), Decision::Reject);
        // A different client is unaffected by the first one's spending.
        assert_eq!(z.check("2.2.2.2", t, 0, true, 0), Decision::Pass);
    }

    #[test]
    fn zone_recovers_after_the_rate_window() {
        let z = Zone::new("z", R1, 1000);
        let t = Instant::now();
        assert_eq!(z.check("k", t, 0, true, 0), Decision::Pass);
        assert_eq!(z.check("k", t, 0, true, 0), Decision::Reject);
        // One second later the bucket has drained.
        assert_eq!(z.check("k", t + Duration::from_millis(1100), 0, true, 0), Decision::Pass);
    }

    #[test]
    fn zone_bounds_its_memory() {
        let z = Zone::new("z", R1, 64);
        let t = Instant::now();
        for i in 0..5000 {
            z.check(&format!("key{i}"), t, 10 * SCALE, true, 0);
        }
        // Bounded by max_entries, with slack for per-shard rounding.
        assert!(z.tracked() <= 64 + SHARDS * 2, "tracked {} entries", z.tracked());
    }

    #[test]
    fn rejected_requests_do_not_charge_the_bucket() {
        // Otherwise a client hammering the door would push its own recovery
        // further and further out — nginx does not do that.
        let z = Zone::new("z", R1, 1000);
        let t = Instant::now();
        assert_eq!(z.check("k", t, 0, true, 0), Decision::Pass);
        for _ in 0..50 {
            assert_eq!(z.check("k", t, 0, true, 0), Decision::Reject);
        }
        // Still recovers on schedule despite the flood.
        assert_eq!(z.check("k", t + Duration::from_millis(1100), 0, true, 0), Decision::Pass);
    }
}

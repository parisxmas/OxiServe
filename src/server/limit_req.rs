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
//! The state lives in a `MAP_SHARED` anonymous mapping created at config load
//! — before any worker exists — so it is one bucket table no matter how the
//! workers are arranged: threads see it through the shared address space, and
//! forked worker processes inherit the very same pages. Without this, process
//! workers would each keep a private bucket per key and every configured rate
//! would silently multiply by the worker count.
//!
//! The table is fixed-size open addressing over 16-byte entries — a key hash
//! and a packed (timestamp, excess) word, both atomics. No allocator runs in
//! shared memory, which is precisely what makes nginx's slab-in-shm machinery
//! its most delicate code; a fixed table sidesteps all of it. The costs of
//! that trade are bounded and accepted: a full probe window evicts the stalest
//! entry it can see, and two keys colliding on the same 64-bit seeded hash
//! would share a bucket (the seed is random per zone, so collisions cannot be
//! manufactured offline).
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::shm::Shared;

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

/// How far a probe walks before giving up and evicting.
const PROBE: usize = 16;

/// `excess` occupies the low 24 bits of the packed state word: 16.7 million
/// milli-requests, or ~16,777 whole queued requests. A `burst` beyond that is
/// clamped — no realistic config reaches it.
const EXCESS_BITS: u32 = 24;
const EXCESS_MASK: u64 = (1 << EXCESS_BITS) - 1;

/// The timestamp gets 39 bits of milliseconds: ~17 years of uptime before
/// wrap.
const MS_MASK: u64 = (1 << 39) - 1;

/// Set on every stored state so that no legitimate state is ever the 0 that
/// means "freshly claimed". Without it, `pack(0, 0)` — a request with no
/// excess in the same millisecond the zone was created — would read back as
/// an empty bucket and admit what should have been rejected.
const PRESENT: u64 = 1 << 63;

fn pack(last_ms: u64, excess: u64) -> u64 {
    PRESENT | ((last_ms & MS_MASK) << EXCESS_BITS) | excess.min(EXCESS_MASK)
}

fn unpack(w: u64) -> (u64, u64) {
    ((w >> EXCESS_BITS) & MS_MASK, w & EXCESS_MASK)
}

/// One `limit_req_zone` at runtime: the shared state behind a zone name.
///
/// Layout: `slots` entries of two words each — `[hash, state]` — where a hash
/// of 0 marks an empty slot and `state` packs `(last_ms, excess)`.
pub struct Zone {
    pub name: Box<str>,
    /// Requests per second, scaled by [`SCALE`].
    pub rate: u64,
    /// Maximum tracked keys, derived from the zone's configured size.
    pub max_entries: usize,
    /// Created in the master before any worker, so after `fork` every process
    /// holds the same value and instants stay comparable across them —
    /// `Instant` is the monotonic clock, which is machine-wide.
    origin: Instant,
    /// Randomises the key hash per zone so a colliding pair of keys cannot be
    /// computed offline. Also fixed pre-fork, hence identical in all workers.
    seed: u64,
    slots: usize,
    mem: Shared,
}

impl std::fmt::Debug for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zone({}, rate={})", self.name, self.rate)
    }
}

impl Zone {
    pub fn new(name: &str, rate: u64, max_entries: usize) -> Zone {
        // Power of two for mask indexing. At 16 bytes per entry this is far
        // smaller than the nginx zone size the config asked for, which
        // budgeted for full keys in a slab; rounding up cannot exceed it.
        let slots = max_entries.next_power_of_two().max(64);
        Zone {
            name: name.into(),
            rate,
            max_entries,
            origin: Instant::now(),
            seed: {
                use std::hash::{BuildHasher, Hasher};
                // RandomState is seeded per process; hashing the name gives a
                // per-zone value. This runs in the master, once.
                let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                h.write(name.as_bytes());
                h.finish()
            },
            slots,
            mem: Shared::new(slots * 2, "limit_req"),
        }
    }

    #[inline]
    fn hash_slot(&self, i: usize) -> &AtomicU64 {
        self.mem.at(i * 2)
    }

    #[inline]
    fn state_slot(&self, i: usize) -> &AtomicU64 {
        self.mem.at(i * 2 + 1)
    }

    fn hash_key(&self, key: &str) -> u64 {
        // FNV-1a over the seed and the key: cheap, no dependency.
        let mut h: u64 = 0xcbf29ce484222325 ^ self.seed;
        for b in key.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // 0 marks an empty slot; a real key must never look like one.
        if h == 0 {
            1
        } else {
            h
        }
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
        let h = self.hash_key(key);
        let mask = self.slots - 1;

        // One pass: find our entry, or an empty slot, remembering the stalest
        // occupant in case the window is full.
        let mut stalest: Option<(usize, u64)> = None;
        for p in 0..PROBE {
            let i = (h as usize).wrapping_add(p) & mask;
            let eh = self.hash_slot(i).load(Ordering::Acquire);
            if eh == h {
                return self.bump(i, h, now_ms, burst, nodelay, delay_after);
            }
            if eh == 0 {
                // Claim it. Losing the race to the same key is a bump; to a
                // different key, the probe continues.
                match self.hash_slot(i).compare_exchange(
                    0,
                    h,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.state_slot(i).store(0, Ordering::Release);
                        return self.bump(i, h, now_ms, burst, nodelay, delay_after);
                    }
                    Err(winner) if winner == h => {
                        return self.bump(i, h, now_ms, burst, nodelay, delay_after)
                    }
                    Err(_) => continue,
                }
            }
            let (last, _) = unpack(self.state_slot(i).load(Ordering::Acquire));
            if stalest.map_or(true, |(_, l)| last < l) {
                stalest = Some((i, last));
            }
        }

        // Window full of other keys: take over the one idle longest. nginx
        // evicts LRU nodes here for the same reason — refusing instead would
        // let a burst of distinct keys lock every regular out of the zone.
        // The takeover is racy by design: two workers can fight over a slot,
        // and the loser's single request is accounted against a fresh bucket.
        // That imprecision is bounded to one request and only under a window
        // already saturated with distinct keys.
        let (i, _) = stalest.expect("PROBE > 0 means at least one candidate");
        self.hash_slot(i).store(h, Ordering::Release);
        self.state_slot(i).store(0, Ordering::Release);
        self.bump(i, h, now_ms, burst, nodelay, delay_after)
    }

    /// Runs the leaky-bucket step against slot `i`, retrying while other
    /// workers race on the same key.
    fn bump(
        &self,
        i: usize,
        h: u64,
        now_ms: u64,
        burst: u64,
        nodelay: bool,
        delay_after: u64,
    ) -> Decision {
        loop {
            // The slot can be evicted from under us by a saturated window in
            // another worker. Starting over would be arbitrarily unfair to
            // this request; treating the takeover as our fresh bucket matches
            // what the evictor just did.
            if self.hash_slot(i).load(Ordering::Acquire) != h {
                let (_, decision) = step(0, u64::MAX / SCALE, self.rate, burst, nodelay, delay_after);
                return decision;
            }
            let cur = self.state_slot(i).load(Ordering::Acquire);
            let (prev_excess, elapsed) = if cur == 0 {
                // A freshly claimed slot: an empty bucket, as a first-seen key.
                (0, u64::MAX / SCALE)
            } else {
                let (last, excess) = unpack(cur);
                (excess, now_ms.saturating_sub(last))
            };
            let (excess, decision) = step(prev_excess, elapsed, self.rate, burst, nodelay, delay_after);
            if decision == Decision::Reject {
                // nginx does not account a rejected request against the
                // bucket, and neither did the map-based version.
                return decision;
            }
            let next = pack(now_ms, excess);
            if self
                .state_slot(i)
                .compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return decision;
            }
        }
    }

    /// Keys currently tracked. Test and introspection hook.
    pub fn tracked(&self) -> usize {
        (0..self.slots)
            .filter(|&i| self.hash_slot(i).load(Ordering::Relaxed) != 0)
            .count()
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
        // The table is fixed at construction: whatever the traffic does, the
        // occupancy can never exceed the slot count.
        assert!(z.tracked() <= 64, "tracked {} entries", z.tracked());
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

    /// The property the shared mapping exists for: a forked process must see
    /// the same bucket, in both directions. Everything the child does between
    /// `fork` and `_exit` is allocation-free (`check` is pure arithmetic over
    /// the mapping), which is what makes forking from a threaded test binary
    /// safe — no inherited malloc lock is ever taken.
    #[cfg(unix)]
    #[test]
    fn a_forked_process_shares_the_buckets() {
        let z = Zone::new("fork", 1, 1024); // 0.001 r/s — nothing drains mid-test
        let now = Instant::now();

        // Parent spends the only token for "k".
        assert_eq!(z.check("k", now, 0, false, 0), Decision::Pass);

        match unsafe { libc::fork() } {
            0 => {
                // Child: "k" must already be over the limit (parent's spend is
                // visible), and "j" is claimed here for the parent to see.
                let k = z.check("k", now, 0, false, 0);
                let j = z.check("j", now, 0, false, 0);
                let code = match (k, j) {
                    (Decision::Reject, Decision::Pass) => 0,
                    (Decision::Reject, _) => 2,
                    _ => 1,
                };
                unsafe { libc::_exit(code) };
            }
            pid if pid > 0 => {
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                assert!(libc::WIFEXITED(status), "child died abnormally");
                match libc::WEXITSTATUS(status) {
                    0 => {}
                    1 => panic!("child saw a fresh bucket for \"k\" — the mapping is not shared"),
                    c => panic!("child exit {c}"),
                }
                // And the child's spend on "j" must be visible here.
                assert_eq!(
                    z.check("j", now, 0, false, 0),
                    Decision::Reject,
                    "the child's bucket write did not reach the parent"
                );
            }
            _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
        }
    }
}

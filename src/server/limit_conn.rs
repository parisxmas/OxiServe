//! `limit_conn` — a cap on how many requests one key may have in flight.
//!
//! # What is counted
//!
//! Despite the name, `ngx_http_limit_conn_module` does not count connections:
//! it counts *requests being processed*. The counter goes up in the preaccess
//! phase and comes back down in the request's cleanup handler, so a keep-alive
//! connection sitting idle between requests occupies nothing. This
//! implementation keeps that behaviour — the count is held by a [`Guard`]
//! parked on the request context, released when the request is answered.
//!
//! # Where the state lives
//!
//! The same reasoning as [`limit_req`](super::limit_req): a `MAP_SHARED`
//! anonymous mapping created at config load, before any worker exists, so one
//! zone stays one zone whether workers are threads or forked processes. Get
//! this wrong and every configured limit silently multiplies by the worker
//! count.
//!
//! # Why one word per slot
//!
//! `limit_req` splits a slot into `[hash, state]` and tolerates a race on the
//! pair, because the worst case there is one request accounted against a fresh
//! bucket. Here a lost race is not survivable: if a slot could be taken over
//! between the moment a worker reads the count and the moment it increments,
//! the eventual decrement would land on somebody else's key and the two counts
//! would drift apart permanently — a leak that only a restart clears.
//!
//! So a slot is a single `AtomicU64` of `[tag:48][count:16]`, and every
//! transition — claim, increment, take over, release — is one CAS on the whole
//! thing. A takeover is only ever offered a slot whose count is zero, and that
//! zero is part of the compare, so a slot with a live count can never be
//! stolen from under the guard that holds it. Releases are therefore exact.
//!
//! 16 bits of count is not a compromise: nginx caps `limit_conn`'s number at
//! 65535 for the same `u_short` reason.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::shm::Shared;

/// How far a probe walks before giving up.
const PROBE: usize = 16;

/// The largest `limit_conn` number, matching nginx's `u_short conn`.
pub const MAX_CONNS: u32 = 65535;

const COUNT_BITS: u32 = 16;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;

#[inline]
fn pack(tag: u64, count: u64) -> u64 {
    (tag << COUNT_BITS) | (count & COUNT_MASK)
}

#[inline]
fn tag_of(w: u64) -> u64 {
    w >> COUNT_BITS
}

#[inline]
fn count_of(w: u64) -> u64 {
    w & COUNT_MASK
}

/// One `limit_conn_zone` at runtime: the shared counters behind a zone name.
pub struct Zone {
    pub name: Box<str>,
    /// Maximum tracked keys, derived from the zone's configured size.
    pub max_entries: usize,
    /// Randomises the key tag per zone so a colliding pair of keys cannot be
    /// computed offline. Fixed pre-fork, hence identical in all workers.
    seed: u64,
    slots: usize,
    mem: Shared,
}

impl std::fmt::Debug for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnZone({}, entries={})", self.name, self.max_entries)
    }
}

impl Zone {
    pub fn new(name: &str, max_entries: usize) -> Zone {
        // Power of two for mask indexing. At 8 bytes per entry this is far
        // smaller than the nginx zone size the config asked for, which
        // budgeted for full keys in a slab; rounding up cannot exceed it.
        let slots = max_entries.next_power_of_two().max(64);
        Zone {
            name: name.into(),
            max_entries,
            seed: {
                use std::hash::{BuildHasher, Hasher};
                let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                h.write(name.as_bytes());
                h.finish()
            },
            slots,
            mem: Shared::new(slots, "limit_conn"),
        }
    }

    #[inline]
    fn slot(&self, i: usize) -> &std::sync::atomic::AtomicU64 {
        self.mem.at(i)
    }

    /// FNV-1a over the seed and the key, folded into the 48 bits a slot has
    /// room for. A tag of 0 marks an empty slot, so a real key never gets one.
    fn tag(&self, key: &str) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325 ^ self.seed;
        for b in key.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // Fold the top bits down rather than truncating, so all 64 bits of the
        // hash contribute to the 48 that survive.
        let t = (h ^ (h >> 48)) & ((1 << 48) - 1);
        if t == 0 {
            1
        } else {
            t
        }
    }

    /// Takes one slot of `limit` for `key`, or returns `None` if the key is
    /// already at its limit.
    ///
    /// The returned guard must be held for as long as the request is being
    /// processed; dropping it gives the slot back.
    pub fn acquire(self: &Arc<Self>, key: &str, limit: u32) -> Option<Guard> {
        let tag = self.tag(key);
        let limit = limit.min(MAX_CONNS) as u64;
        let mask = self.slots - 1;
        let start = (tag as usize) & mask;

        // First pass: our key, or an empty slot, noting the first reusable
        // occupant (count 0) in case neither is there.
        let mut reusable: Option<usize> = None;
        for p in 0..PROBE {
            let i = (start + p) & mask;
            let w = self.slot(i).load(Ordering::Acquire);
            if w == 0 {
                // Claim it. Losing the race to the same key is an increment;
                // to a different key, the probe simply carries on.
                match self.slot(i).compare_exchange(
                    0,
                    pack(tag, 1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Some(self.guard(i, tag)),
                    Err(w) if tag_of(w) == tag => return self.increment(i, tag, limit),
                    Err(_) => continue,
                }
            }
            if tag_of(w) == tag {
                return self.increment(i, tag, limit);
            }
            if reusable.is_none() && count_of(w) == 0 {
                reusable = Some(i);
            }
        }

        // The window holds only other keys. Any of them sitting at zero is
        // finished with its slot, so take it over — the CAS carries the zero,
        // so a key with requests in flight cannot be evicted.
        if let Some(i) = reusable {
            let w = self.slot(i).load(Ordering::Acquire);
            if count_of(w) == 0
                && self
                    .slot(i)
                    .compare_exchange(w, pack(tag, 1), Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Some(self.guard(i, tag));
            }
        }

        // Every slot in the window is busy with another key. nginx answers
        // limit_conn_status here too ("could not allocate node in zone"):
        // refusing is the only safe answer when the count cannot be tracked.
        None
    }

    /// CAS loop for `+1` on a slot believed to hold `tag`.
    fn increment(self: &Arc<Self>, i: usize, tag: u64, limit: u64) -> Option<Guard> {
        loop {
            let w = self.slot(i).load(Ordering::Acquire);
            if w != 0 && tag_of(w) != tag {
                // Taken over while we looked at it — the slot had to be at
                // zero for that, so nothing of ours was lost. Refuse rather
                // than walk the probe again: under a window this contended,
                // retrying is unbounded work on the request path.
                return None;
            }
            let count = count_of(w);
            if count >= limit || count >= COUNT_MASK {
                return None;
            }
            let next = pack(tag, count + 1);
            if self
                .slot(i)
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(self.guard(i, tag));
            }
        }
    }

    fn guard(self: &Arc<Self>, slot: usize, tag: u64) -> Guard {
        Guard { zone: self.clone(), slot, tag }
    }

    /// Gives one slot back. Only ever called from [`Guard::drop`], which means
    /// the count it decrements is one this process put there.
    fn release(&self, i: usize, tag: u64) {
        loop {
            let w = self.slot(i).load(Ordering::Acquire);
            // A slot holding a count is never taken over, so this can only
            // fail if something is very wrong; leaving it alone is the safe
            // response either way.
            if tag_of(w) != tag || count_of(w) == 0 {
                return;
            }
            // At zero the tag stays: the slot is reusable by any key, but
            // until someone needs it this one keeps its place in the window.
            let next = pack(tag, count_of(w) - 1);
            if self
                .slot(i)
                .compare_exchange(w, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Requests currently counted against `key`. Test and introspection hook.
    pub fn count(&self, key: &str) -> u32 {
        let tag = self.tag(key);
        let mask = self.slots - 1;
        for p in 0..PROBE {
            let w = self.slot(((tag as usize) + p) & mask).load(Ordering::Relaxed);
            if w == 0 {
                return 0;
            }
            if tag_of(w) == tag {
                return count_of(w) as u32;
            }
        }
        0
    }

    /// Slots holding a live count. Test and introspection hook.
    pub fn active(&self) -> usize {
        (0..self.slots)
            .filter(|&i| count_of(self.slot(i).load(Ordering::Relaxed)) != 0)
            .count()
    }
}

/// A held slot in a [`Zone`]. Dropping it releases the count.
///
/// The request context owns these for the life of a request, which is what
/// makes the release automatic on every exit path — including the error paths
/// where forgetting an explicit decrement would leak a slot permanently.
pub struct Guard {
    zone: Arc<Zone>,
    slot: usize,
    tag: u64,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "limit_conn::Guard({})", self.zone.name)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.zone.release(self.slot, self.tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(entries: usize) -> Arc<Zone> {
        Arc::new(Zone::new("z", entries))
    }

    #[test]
    fn a_lone_request_is_admitted() {
        let z = zone(1000);
        let g = z.acquire("1.1.1.1", 1);
        assert!(g.is_some());
        assert_eq!(z.count("1.1.1.1"), 1);
    }

    #[test]
    fn the_limit_is_the_number_admitted_at_once() {
        let z = zone(1000);
        let held: Vec<_> = (0..3).map(|_| z.acquire("k", 3)).collect();
        assert!(held.iter().all(|g| g.is_some()), "3 concurrent under limit 3");
        assert!(z.acquire("k", 3).is_none(), "the fourth must be refused");
        assert_eq!(z.count("k"), 3);
    }

    #[test]
    fn a_finished_request_frees_its_slot() {
        let z = zone(1000);
        let g = z.acquire("k", 1).expect("first admitted");
        assert!(z.acquire("k", 1).is_none(), "at the limit while the first is live");
        drop(g);
        assert_eq!(z.count("k"), 0, "the count must come back down");
        assert!(z.acquire("k", 1).is_some(), "and the next request goes through");
    }

    #[test]
    fn keys_do_not_share_a_budget() {
        let z = zone(1000);
        let _a = z.acquire("1.1.1.1", 1).expect("first client admitted");
        assert!(z.acquire("1.1.1.1", 1).is_none());
        assert!(z.acquire("2.2.2.2", 1).is_some(), "a second client is unaffected");
    }

    #[test]
    fn releases_are_exact_over_many_cycles() {
        // The failure this guards against is a slow leak: any drift between
        // increment and decrement eventually locks a key out for good.
        let z = zone(1000);
        for _ in 0..10_000 {
            let a = z.acquire("k", 2).expect("under the limit");
            let b = z.acquire("k", 2).expect("at the limit");
            assert!(z.acquire("k", 2).is_none());
            drop(a);
            drop(b);
            assert_eq!(z.count("k"), 0);
        }
    }

    #[test]
    fn a_full_window_refuses_rather_than_evicting_a_live_key() {
        // Fill the table with keys that are all still in flight, then check
        // that the holder of a slot keeps its count intact.
        let z = zone(64);
        let mut held = Vec::new();
        for i in 0..1000 {
            if let Some(g) = z.acquire(&format!("key{i}"), 1) {
                held.push((format!("key{i}"), g));
            }
        }
        assert!(!held.is_empty());
        assert!(z.active() <= 64, "active {} exceeds the table", z.active());
        for (k, _) in &held {
            assert_eq!(z.count(k), 1, "key {k} lost its count to an eviction");
        }
    }

    #[test]
    fn a_finished_key_gives_its_slot_to_a_newcomer() {
        // The counterpart to the test above: zero-count entries must not
        // permanently occupy the table, or a long-running server would stop
        // limiting new keys entirely.
        let z = zone(64);
        for i in 0..1000 {
            drop(z.acquire(&format!("key{i}"), 1));
        }
        assert_eq!(z.active(), 0);
        let g = z.acquire("fresh", 1);
        assert!(g.is_some(), "a table of finished keys must still admit a new one");
        assert_eq!(z.count("fresh"), 1);
    }

    #[test]
    fn concurrent_acquire_never_exceeds_the_limit() {
        use std::sync::atomic::AtomicU32;
        const LIMIT: u32 = 8;
        let z = zone(1000);
        let peak = Arc::new(AtomicU32::new(0));
        let live = Arc::new(AtomicU32::new(0));

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (z, peak, live) = (z.clone(), peak.clone(), live.clone());
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        if let Some(g) = z.acquire("hot", LIMIT) {
                            let n = live.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(n, Ordering::SeqCst);
                            live.fetch_sub(1, Ordering::SeqCst);
                            drop(g);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= LIMIT, "peak {} > limit", peak.load(Ordering::SeqCst));
        assert_eq!(z.count("hot"), 0, "every acquire was matched by a release");
    }

    /// The property the shared mapping exists for: without it, each forked
    /// worker would keep a private count and the configured limit would
    /// multiply by the worker count. Everything the child does between `fork`
    /// and `_exit` is allocation-free, which is what makes forking from a
    /// threaded test binary safe.
    #[cfg(unix)]
    #[test]
    fn a_forked_process_shares_the_counts() {
        let z = zone(1024);
        let held = z.acquire("k", 1).expect("parent takes the only slot");

        match unsafe { libc::fork() } {
            0 => {
                let code = match z.acquire("k", 1) {
                    Some(g) => {
                        std::mem::forget(g);
                        1
                    }
                    None => 0,
                };
                unsafe { libc::_exit(code) };
            }
            pid if pid > 0 => {
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                assert!(libc::WIFEXITED(status), "child died abnormally");
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    0,
                    "the child saw a free slot — the mapping is not shared"
                );
                drop(held);
                // The child's counts died with it, so the parent's release is
                // the only one outstanding.
                assert_eq!(z.count("k"), 0);
            }
            _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
        }
    }
}

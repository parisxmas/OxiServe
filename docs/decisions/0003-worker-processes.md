# ADR 0003 — Worker processes, not worker threads

**Status:** Accepted
**Date:** 2026-08-06
**Related:** [ADR-0002](0002-no-database-on-the-request-path.md);
`src/server/mod.rs` (`prefork`), `src/server/limit_req.rs`;
`bench/nginx-compare.sh`.

## Context

OxiServe launched thread-per-core: one process, N worker threads, each with
its own single-threaded runtime, `SO_REUSEPORT` per worker, no work stealing.
The claim was that this is equivalent to nginx's process-per-worker with less
machinery — and on five of six benchmark scenarios it was.

The sixth — one connection per request, the harshest accept-path workload —
persistently lost by 4–7% and resisted every syscall-level explanation.
Driving our syscall count 19% *below* nginx's did not close it. The
measurement that finally attributed it:

| arrangement | vs nginx (2 workers) |
|---|---:|
| 1 process × 1 worker thread | **1.03×** |
| 1 process × 2 worker threads | 0.93× |
| **2 processes × 1 worker thread each** | **1.00×** |

Same binary, same total cores. The entire loss is contention on state that
threads in one process share and separate processes do not — candidates being
the shared `files_struct` (four descriptor ops per connection, each taking its
spinlock) and the shared `mm` (one `mmap_lock` for every fault). A partial
test supports the diagnosis being *aggregate*: `unshare(CLONE_FILES)` alone
recovered only ~0.5 of the ~7 points, so no single shared structure is the
story — being one process is.

## Decision

**`worker_processes N` with N > 1 forks N worker processes**, supervised by a
single-threaded master that respawns any worker that dies and forwards
termination — nginx's shape. Workers set `PR_SET_PDEATHSIG` on Linux so even
a SIGKILLed master cannot orphan them.

**N = 1 keeps the in-process path.** Tests and embedders run the server on a
thread inside a larger program; forking would clone that program mid-flight,
including whatever locks its other threads hold. The master only ever forks
before it has spawned anything, which is what makes its own fork safe.
`OXISERVE_WORKER_MODEL=threads` preserves the old model for A/B measurement.

**Anything that must be one thing across workers now lives in `MAP_SHARED`
memory created before the fork.** First occupant: `limit_req` zones, rebuilt
as a fixed-size open-addressing table of atomics — without this, forked
workers would each keep private buckets and every configured rate would
silently multiply by N. A test proves the property through the real binary:
at `1r/m`, thirty connections spread across two workers admit exactly one
request.

No allocator runs in the shared memory. nginx's slab-in-shm is its most
delicate machinery; a fixed table with bounded, documented imprecision (a
saturated probe window evicts the stalest entry it can see) sidesteps all of
it, at the cost nginx pays too — a full zone degrades rather than grows.

## Per-worker state that deliberately stays per-worker

- **Passive upstream health and the keepalive pool** — per process. This *is*
  stock nginx semantics: without a `zone` directive nginx tracks `max_fails`
  per worker too.
- **Active health checks** — every worker probes for itself in process mode,
  because a worker that did not probe would never learn what the probes know.
  The multiplied probe load is the honest price of isolation; worker counts
  are small.
- **The `proxy_cache` index** — was per worker already; the on-disk store and
  its single sweeper (worker 0) are shared through the filesystem.
- **`proxy_cache_lock`** — collapses a stampede per process rather than
  globally: N workers can fetch the same expired entry concurrently instead
  of 1. Bounded degradation, documented, and a candidate for the shared
  mapping if it ever shows up in a measurement.

## Consequences

- The connection-churn scenario went from 0.93× to **1.00×**, closing the
  last benchmark row nginx held. Nothing else regressed.
- The "single process needs no shared memory" argument in ADR-0002 is now
  historical: we do use shared memory, for exactly the thing nginx uses it
  for. The measured conclusion of ADR-0002 — nothing on the request path
  talks to a database — is unchanged.
- Future cross-worker state (a stats endpoint, cache-lock globalisation) has a
  template to follow: fixed-layout atomics in the pre-fork mapping, never an
  allocator. `limit_conn` was the first to follow it, and sharpened it: a
  *count* must be incremented and decremented in the same place, so its slot
  is one atomic word — tag and count together — and every transition is a
  single CAS. The looser pair-of-words layout `limit_req` uses would let a
  slot be taken over between the read and the increment, and the eventual
  decrement would land on another key's count.
- A worker crash no longer takes the server down: the master respawns it.
  This was previously impossible — a panicking worker thread died silently
  and its cores went idle.

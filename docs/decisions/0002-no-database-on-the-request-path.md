# ADR 0002 — No database on the request path

**Status:** Accepted
**Date:** 2026-08-06
**Related:** [ADR-0001](0001-load-balancer-scope.md); `src/server/limit_req.rs`;
OxiDB (`../docdb`).

## Context

`limit_req` and `proxy_cache` both need state that survives between requests,
and OxiDB sits in the same workspace family with an embedded mode — no network
hop, just a function call. The obvious move is to reach for it, and earlier in
the project I described OxiDB as "the natural backing store" for exactly these
two features.

That claim was made without measuring. Measured properly it does not hold.

### Measurement

Embedded OxiDB (`OxiDb::open`, in-process, no server, no network), against a
sharded in-process map doing the same job:

| Operation | OxiDB embedded | in-process map |
|---|---:|---:|
| indexed `find` | 0.67 µs | 0.08 µs |
| `update` `$inc` (lazy sync) | 10.75 µs | 0.08 µs |
| `insert` (lazy sync) | 9.5 µs | — |
| `insert` (default, fsync per write) | 3067 µs | — |

The budget these numbers have to fit into: at ~70k rps a request has roughly
**14 µs of CPU in total**. A rate limiter touches its counter on *every*
request, read and write.

- A 10.75 µs counter update consumes ~77% of the entire request budget.
- The default fsync path, at 3 ms, caps the server at ~330 rps.
- The in-process map costs ~0.6% of the budget.

134× on the write path. This is not a criticism of OxiDB — 10 µs is a
respectable durable document write. It is the wrong shape of tool: a rate
limiter is an atomic increment, not a query. nginx keeps this in shared memory
for the same reason.

One result was better than expected and worth recording: an indexed `find` at
0.67 µs is fast enough to be *arguable* for a cache index lookup. It is still
~8× an in-process lookup, so it loses, but not by the margin the write path
does.

## Decision

**Nothing on the per-request path talks to a database — including an embedded
one.** Two layers instead:

**Layer 1 — per request, in-process, mandatory.**
`limit_req` counters and the future `proxy_cache` index live in sharded
in-process maps behind an `Arc`, one lock per shard so unrelated keys never
contend. Being a single process, this *is* our equivalent of nginx's shared
memory segment, with less machinery.

**Layer 2 — off the request path, asynchronous, optional.**
This is where OxiDB earns its place, doing things a single process cannot:

- **Cross-node limit synchronisation.** Each node keeps its local bucket at
  0.08 µs and batches state to OxiDB every ~100 ms, reading peers' state back.
  Open-source nginx cannot do this at all (`zone sync` is an nginx Plus
  feature), so it is a genuine differentiator rather than parity work.
- **Cache purge fan-out** via OxiDB change streams, so a purge on one node
  reaches the others — again an nginx Plus feature.
- **Cache metadata durability**, so a restart does not throw away a warm
  on-disk cache.
- **Access log sink and analytics**, which is OxiDB playing to its strengths:
  aggregation, full-text, time series. **Implemented in v0.2.5** as
  `access_log oxidb:server=…` — MessagePack over UDP, fire-and-forget, so the
  request path hands a datagram to the kernel and never waits. This is the
  shape Layer 2 work should take.

## Consequences

- `limit_req` shipped with no OxiDB dependency and no measurable throughput
  cost (within run-to-run noise on a loaded box).
- OxiDB stays an **optional** dependency. A build without it loses cross-node
  features and nothing else — single-node behaviour is complete on its own.
- The earlier "OxiDB is where the caching/limiting lives" framing was wrong and
  is superseded by this ADR. Recording it rather than quietly changing course:
  the claim was made from architectural intuition, and a 15-minute benchmark
  contradicted it.
- Any future proposal to put a store on the request path should be required to
  show a per-operation cost against the ~14 µs request budget first. The
  numbers above are the baseline to beat.

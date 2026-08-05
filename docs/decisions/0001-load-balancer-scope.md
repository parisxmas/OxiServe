# ADR 0001 — Load balancer scope: what "HAProxy-like" would require

**Status:** Accepted — items 1–3 implemented (v0.2.4), 4–5 outstanding
**Date:** 2026-08-06
**Related:** README "Not implemented"; `src/server/proxy.rs`; `src/config/model.rs` (`Upstream`, `LbMethod`).

## Context

The question was whether OxiServe can already act as a load balancer in the
HAProxy sense. It reverse-proxies HTTP and spreads requests across an
`upstream` block, so at a glance it looks close. Reading the code says
otherwise, and the gap is not where the feature list suggests.

What is genuinely implemented today:

- `proxy_pass` to an `upstream` block, a literal address, a Unix socket, or a
  variable
- `upstream` with `weight`, `backup`, `down`, `max_conns`
- Round-robin (per worker, no cross-worker coordination) and `ip_hash`
- Request/response header manipulation, connect/read/send timeouts, chunked
  pass-through

What is missing, verified against the source rather than the directive list:

| Capability | State |
|---|---|
| **Passive health tracking** | **Parsed but not enforced.** `max_fails` and `fail_timeout` are read into `UpstreamServer` and never consulted; `pick()` filters only on `down` and `backup`. A dead backend keeps receiving traffic. |
| **`least_conn`** | **Falsely advertised.** `LbMethod::LeastConn` falls through to the round-robin arm because no per-peer connection count exists. A config asking for it silently gets something else. |
| **Upstream keepalive** | **Absent.** Every proxied request opens a new TCP connection and sends `Connection: close`. `keepalive N` is parsed and ignored. |
| **Active health checks** | Absent. |
| **L4 (`stream` block)** | Absent — reported as "not implemented" by `oxiserve -t`. |
| **Sticky sessions (cookie)** | Absent (`ip_hash` only). |
| **Stats endpoint / runtime API** | Absent. |
| **Circuit breaking, retry budgets, slow start** | Absent. |

The first two entries matter more than their size suggests. They are not
missing features — they are **features that appear to work and do not**. A
config saying `server 10.0.0.1:8080 max_fails=3 fail_timeout=30s;` reads as
fault tolerance and delivers none, and `least_conn` reads as a balancing
strategy and delivers round-robin. Both are worse than an honest "not
supported", because they fail silently and only under load.

## Decision

**OxiServe is not a load balancer today and will not be described as one.** It
is an HTTP reverse proxy with request distribution. The README and `-t` output
must not imply otherwise.

Work is ordered by how much correctness it buys, not by how impressive it
sounds:

**1. Passive health tracking** — enforce `max_fails` / `fail_timeout`.
Per-peer failure counter and a "down until" timestamp in the upstream's
runtime state; `pick()` skips peers inside their penalty window and falls back
to `backup` peers when every primary is out. *Not sending traffic to a dead
backend is the minimum bar for anything called balancing*, and the directives
are already parsed, so this is enforcement rather than new surface.

**2. Upstream keepalive pool** — honour `keepalive N`. A per-worker idle
connection pool keyed by peer address, with `proxy_http_version 1.1` and
`Connection:` cleared. Biggest single win for both latency and backend load;
opening a TCP connection per proxied request is the current default.

**3. Real `least_conn`** — an in-flight counter per peer, incremented for the
life of a proxied request. Shares the runtime state introduced by (1) and (2),
which is why it comes third rather than first.

**4. Active health checks** — periodic probes with configurable interval,
timeout and rise/fall thresholds. Deliberately after (1): passive tracking
already prevents the worst outcome, and open-source nginx has no active checks
at all, so this differentiates against nginx *and* moves toward HAProxy.

**5. `stream` block (L4 TCP/UDP)** — accept and splice, no HTTP parsing. The
largest piece and HAProxy's core competence, but genuinely simpler than the
HTTP path once connection handling is factored out.

Items 1–3 are treated as one unit of work because they share the same runtime
structure (per-peer state hanging off `Upstream`) and splitting them would mean
building that structure three times.

### Implementation notes (added after 1–3 shipped)

Health is shared across workers via atomics on `Arc<Upstream>`; the connection
pool is per worker, because a socket belongs to the reactor of the thread that
opened it. `least_conn` uses an RAII guard so an early return cannot leak the
in-flight count and slowly poison balancing.

Two decisions worth recording because they were not obvious going in:

- **A pooled connection is probed before reuse** (non-blocking read:
  `WouldBlock` = alive, `Ok(0)` = peer closed, any bytes = dirty). The first
  design instead retried on a fresh connection after a failed write, which
  meant duplicating the whole request/response path and risked charging the
  peer for our own stale socket. Probing is both simpler and more correct.
- **A failure on a reused connection is not counted against the peer.** An
  upstream closing an idle connection is normal; counting it would eject
  healthy backends under light traffic, which is precisely backwards.

A `5xx` from a live backend is also not counted as a failure. nginx only does
that under `proxy_next_upstream`, which is not implemented, so a backend
returning 500 stays in rotation rather than being ejected for doing its job.

## Consequences

- ~~Until (1) lands, `max_fails` / `fail_timeout` / `least_conn` are recorded
  as accepted-but-ignored.~~ **Resolved in v0.2.4** — all four directives now
  have real behaviour, and the `-t` warning for them was removed. The
  reporting mechanism itself is kept for the next directive that ships as
  parse-only.
- Per-worker state means round-robin and `least_conn` balance within a worker,
  not globally. With N workers the distribution is still even in aggregate, but
  `least_conn` is approximate. nginx has the same property; it should be
  documented rather than hidden.
- Cross-node coordination (shared limits, shared health state) is explicitly
  **out of scope for the data path**, per the measurement in
  [ADR-0002](0002-no-database-on-the-request-path.md). If it is ever wanted, it
  belongs in an asynchronous layer above, never in `pick()`.
- Every item here needs verification under real load, not just unit tests. This
  session produced two false readings — a `sed` that silently matched nothing,
  and a `wrk` throughput figure misread as successful requests when it was
  counting rejections. Health-check work is especially prone to this, because a
  broken implementation and a working one look identical while every backend is
  up.

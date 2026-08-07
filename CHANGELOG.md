# Changelog

Notable changes per version. The version reaches clients in the `Server:`
header and in `oxiserve -v`, so every release that changes behaviour has its
own — see [Building](README.md#building).

Entries say what changed and, where it is not obvious, why. Measurements are
the ones actually taken, not estimates.

## [0.2.38] — 2026-08-08

### Changed

- The ModSecurity call path allocates nothing per request. Addresses format
  into stack buffers, the method and HTTP version are `c""` constants, and the
  URI is assembled in a per-worker buffer — about eight heap allocations
  removed. **It changed throughput by nothing measurable** (89,877 → 90,232
  req/s, inside the run-to-run spread), which is the useful result: the fixed
  cost belongs to libmodsecurity, not to the integration.

### Added

- `bench/modsec-cost.sh` — measures what the WAF costs, with the same fairness
  rules as `bench/run.sh`. Full OWASP CRS takes a 1 KiB request from 5.18 µs of
  CPU to 285.65 µs; ~17 µs of that is the engine's fixed cost and ~60% of *that*
  is `msc_new_transaction` and its cleanup, before any rule exists to evaluate.
- A profiling test (`transaction_cost_breakdown`, `--ignored`) that times each
  phase against an engine with no rules loaded.

### Fixed

- The benchmark harness sends browser-like headers. `wrk`'s bare request has no
  `Accept` or `User-Agent` and a numeric `Host`, which trips CRS 920300, 920320
  and 920350 on every request — the first measurement taken was of the logging
  path rather than the inspection path.

## [0.2.37] — 2026-08-08

### Added

- ModSecurity response phases. All five now run: connection and request (1–2),
  response headers (3), response body (4), logging (5), so the CRS rules that
  catch a backend leaking SQL errors or a stack trace are in force.
- `modsecurity_response_body` and `modsecurity_response_body_limit`. Phase 4 is
  off by default — inspecting a response body means holding it in memory, which
  is the opposite of what `sendfile` and the mmap path exist to do. Over the
  limit a body is served **uninspected** rather than buffered without bound.

One transaction spans every phase. CRS accumulates an anomaly score across
them, and a second transaction for the response would score it from zero,
letting a request that scored 4 going in and 3 coming out pass as two harmless
halves.

Proxied bodies are buffered up to the limit and forwarded unchanged — verified
byte-for-byte on a 400 KB response, both under and over the limit. An upgraded
connection is never inspected: past the upgrade there is no response body in
the HTTP sense.

## [0.2.36] — 2026-08-08

### Added

- **ModSecurity**, via libmodsecurity v3, behind `--features modsecurity`.
  Real rules, OWASP CRS included. `modsecurity`, `modsecurity_rules_file` and
  `modsecurity_rules`, inheriting `http` → `server` → `location`.

Off by default: it is the project's only C dependency and the released binaries
are static musl with none. nginx's ModSecurity *module* cannot be loaded — a
module `.so` carries a signature of nginx's compile-time options and nginx
rejects one that differs by a single bit — but the rule engine was never the
nginx-coupled part, and libmodsecurity is standalone.

Rules compile at configuration load, so `-t` fails on a bad rules file rather
than the server discovering it on the first request. A level naming its own
rules replaces the inherited engine instead of merging, because libmodsecurity
cannot combine two compiled sets.

### Fixed

- A blocked request logs which rule blocked it. The disruptive action reports
  itself through the intervention struct rather than the log callback, and the
  first version discarded that field — leaving a 403 with no way to learn its
  cause.
- Rule parsing is serialised. libmodsecurity's parser is a non-reentrant flex
  scanner and two threads in it abort the process outright.

## 0.2.35 — 2026-08-07

### Fixed

- `load_module` is reported instead of silently accepted. It used to sit in the
  list of directives ignored without comment, so `-t` said "syntax is ok" while
  everything the module did was missing. The message names the module, and when
  the module's job was rejecting requests it says outright that what it would
  have blocked is now served. It deliberately does not say "not implemented
  yet": that is never arriving.
- `load_module` takes exactly one argument, as nginx does.
- The README listed UDP in `stream` as missing; it shipped in 0.2.33.

## [0.2.34] — 2026-08-07

### Added

- Linux release artifacts: static musl binaries for x86_64 and aarch64, built
  by `scripts/release.sh`, with one `SHA256SUMS` for the release. One binary
  per architecture runs on any distribution — no glibc version to match.
- An install section in the README, with `setcap` for port 80 and a systemd
  unit.

### Fixed

- Release tarballs carry no Apple xattrs, which GNU tar warned about once per
  file when unpacking.

## 0.2.33 — 2026-08-07

### Added

- UDP in `stream` — `listen ... udp;` proxies datagrams.
- `stub_status`, plus `stub_status json` for per-peer upstream state.

## 0.2.32 — 2026-08-07

### Added

- Sticky cookie sessions (`sticky cookie`); `ip_hash` was the only option
  before.

## 0.2.31 — 2026-08-07

### Added

- Four worked example configurations: a TLS site, a reverse proxy, a load
  balancer and an API gateway, all passing `oxiserve -t` with no warnings.

### Fixed

- `return` honours `default_type`.

## 0.2.30 — 2026-08-07

### Added

- HTTP/3 over QUIC. See [ADR-0004](docs/decisions/0004-quic-transport.md).

## Earlier

Condensed; see `git log` for the full record.

- **0.2.24–0.2.29** — WebSocket proxying, `-s stop|quit|reload|reopen`, FastCGI
  response streaming, `auth_request`, `proxy_next_upstream`, `limit_conn`.
- **0.2.16–0.2.22** — measured against nginx 1.28.3 on Linux, then the syscall
  and contention work that followed: 10.07 → 8.07 syscalls per connection, and
  worker processes, after which no benchmark row was left where nginx was
  ahead.
- **0.2.14–0.2.15** — HTTP/2, then conformance: h2spec 144/145 with 0 failed
  over TLS.
- **0.2.9–0.2.13** — the `stream` block (layer 4 TCP proxying), active health
  checks completing ADR-0001, `ssl_preread`, and the fuzzing and Miri setup.
- **0.2.6–0.2.8** — `proxy_cache`: on-disk content cache with an in-process
  index, a cache manager enforcing `max_size` and `inactive`,
  `proxy_cache_use_stale` and `proxy_cache_lock`.
- **0.2.3–0.2.5** — ADR-0001 and ADR-0002 recorded, directives stopped being
  silently ignored, passive health checks, a keepalive pool, real `least_conn`,
  and structured access logs over UDP.
- **0.2.1–0.2.2** — `limit_req` fixed when used without a location block, then
  verified under load with a measurement mistake corrected.

[0.2.38]: https://github.com/parisxmas/OxiServe/releases/tag/v0.2.38
[0.2.37]: https://github.com/parisxmas/OxiServe/releases/tag/v0.2.37
[0.2.36]: https://github.com/parisxmas/OxiServe/releases/tag/v0.2.36
[0.2.34]: https://github.com/parisxmas/OxiServe/releases/tag/v0.2.34

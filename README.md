# OxiServe

An nginx-configuration-compatible web server written in Rust.

OxiServe reads your existing `nginx.conf` — the real grammar, includes, variables,
`server_name` and `location` matching semantics included — and serves it from a
thread-per-core data plane.

The original goal was to beat nginx on the static hot path. **On a realistic
Linux benchmark it does not** — nginx is faster at every payload size (see
[Benchmarks](#benchmarks)). The macOS numbers that suggested otherwise turned
out to be an artifact of the test conditions. Closing that gap — starting with
`sendfile()`, which OxiServe does not yet implement — is the active work.

```console
$ oxiserve -t -c /etc/nginx/nginx.conf
oxiserve: the configuration file /etc/nginx/nginx.conf syntax is ok
oxiserve: configuration file /etc/nginx/nginx.conf test is successful

$ oxiserve -c /etc/nginx/nginx.conf
oxiserve: listening on 0.0.0.0:80
```

## Status

This is an early but genuinely working server, not a demo. It serves real
traffic for the feature set below, with 154 tests (128 unit + 26 end-to-end
over real sockets). It is **not yet a drop-in nginx replacement** —
see [Not implemented](#not-implemented) for exactly what is missing, and run
`oxiserve -t` against your own config to get a precise list for *your* setup.

## Design

Three layers, with a hard rule: nothing in the request path re-interprets
configuration.

| Layer | What it does |
|---|---|
| `config` | `nginx.conf` → tokens → directive tree → fully-resolved runtime model. Regexes compiled, templates compiled, inheritance flattened — all at load time. |
| `http` | Wire format. Zero-copy request parsing (headers are byte ranges into the connection buffer), pre-rendered status lines, a per-worker date cache. |
| `server` | The data plane: listeners, the connection state machine, and handlers. |

**Thread-per-core.** Every worker owns a `current_thread` Tokio runtime, its own
listening socket (via `SO_REUSEPORT`, where the kernel load-balances accepts), its
own log buffers, and its own connection state. A connection is accepted, handled
and answered on one core — no work stealing, no cross-core wakeups, no shared
mutable state on the request path.

**Allocation-free steady state.** A keep-alive connection reuses its read buffer,
write buffer, parsed-request header vector, and response header arena. Small
static files are served from a memory map and written with `writev` alongside the
response head — one syscall for a cached response.

## Implemented

**Config** — full nginx lexer (quoting, escapes, comments), `include` with globs,
directive tree, `-t` / `-T`, inheritance across `http`/`server`/`location`
including the list-directive replace-wholesale rule.

**Matching** — `server_name` (exact, `*.x`, `x.*`, regex, priority-ordered),
`location` (`=`, `^~`, `~`, `~*`, prefix, `@named`, nested), the full nginx
search order.

**Bodies** — `Content-Length` and chunked request bodies are read and decoded
before routing, `Expect: 100-continue`, `client_max_body_size` enforcement.

**Serving** — static files, `root` / `alias`, `index`, `autoindex`, `try_files`,
byte ranges, `If-None-Match` / `If-Modified-Since` / `If-Range` / `If-Match`,
ETags, MIME types, `expires`, `add_header`, gzip, `error_page`, `return`,
`rewrite` (all four flags), `if` (all condition forms), `set`, `map`,
`limit_except`, `internal`.

**Proxying** — `proxy_pass` to upstreams or literal addresses, `upstream` blocks
with `weight` / `backup` / `down` / `max_fails`, round-robin and `ip_hash`,
`proxy_set_header`, `proxy_hide_header`, timeouts, chunked pass-through.

**TLS** — rustls, `ssl_certificate` / `ssl_certificate_key`, SNI across servers
sharing a listener.

**Logging** — `log_format` with the full variable set, `access_log` with
`buffer=` / `flush=`, `error_log` with levels.

**Variables** — ~50 including `$uri`, `$args`, `$arg_*`, `$http_*`, `$sent_http_*`,
`$cookie_*`, `$upstream_*`, `$proxy_add_x_forwarded_for`, regex captures `$1`–`$9`.

## Not implemented

`oxiserve -t` reports these per-config, distinguishing "not implemented yet" from
"unknown directive". Currently missing:

- **HTTP/2 and HTTP/3** — `listen ... http2` is parsed and ignored (serves 1.1).
- **FastCGI / uwsgi / SCGI / gRPC** — `fastcgi_pass` and friends.
- **`proxy_cache`** and the content cache.
- **`limit_req` / `limit_conn`** rate limiting.
- **`auth_basic`**, `auth_request`.
- **Unix domain sockets** in `listen`.
- **`stream` and `mail`** blocks.
- **PCRE-only regex** — lookaround and backreferences are rejected with a clear
  error rather than silently mismatching (Rust's `regex` has neither).

## Benchmarks

```console
$ bench/run.sh 10 128
```

The harness runs both servers with matched settings — same worker count, same
keepalive, access logging off on both, page cache warmed before each
measurement — across four payload sizes chosen to exercise different paths.
It requires `nginx` and one of `wrk` / `oha` / `bombardier`.

### Linux — the result that counts

Debian 12, kernel 6.1, 4 cores, `wrk -t2 -c16`, nginx 1.22.1. Both servers and
the load generator pinned to 2 cores (a shared box; this bounds the blast
radius, and handicaps both equally). **nginx wins at every size, with
`sendfile` on or off:**

| Payload | OxiServe | nginx (sendfile on) | nginx (sendfile off) |
|---|---:|---:|---:|
| 0 B | 45,277 rps | 67,876 (**0.67×**) | 74,925 (**0.58×**) |
| 1 KiB | 26,554 rps | 48,149 (**0.55×**) | 55,675 (**0.44×**) |
| 100 KiB | 12,523 rps | 27,825 (**0.45×**) | 19,102 (**0.61×**) |
| 10 MiB | 125 rps | 405 (**0.31×**) | 252 (**0.53×**) |

Two things this shows:

- **The gap is not just `sendfile`.** With sendfile off — the setup that
  favoured OxiServe on macOS — nginx still wins 1.6–2.3×. On small payloads,
  which have no body to zero-copy, nginx simply has a cheaper per-request path.
- **`sendfile` is a real, unimplemented advantage.** It roughly doubles nginx's
  large-file throughput (252 → 405 rps on 10 MiB) while doing nothing for
  OxiServe, which reads through userspace. This is the single biggest concrete
  item to close, and it is on the list.

### macOS — where the story began, and why it misled

macOS 15, M-series, 10 cores, unloaded, `wrk -t10 -c128`, nginx 1.31.3,
`sendfile off` on both:

| Payload | OxiServe | nginx | |
|---|---:|---:|---|
| 0 B | 140,076 rps | 80,326 rps | 1.74× |
| 1 KiB | 108,280 rps | 76,289 rps | 1.42× |
| 100 KiB | 74,087 rps | 37,273 rps | 1.99× |
| 10 MiB | 667 rps | 703 rps | 0.95× |

These looked like wins. They were mostly artifacts, and the Linux run above is
why I no longer trust them:

- **`sendfile off` was hiding nginx's best trick.** It was forced off because
  macOS's `sendfile` has a pathology (nginx collapses to ~100 MB/s). But
  turning off a feature nginx has and OxiServe lacks flatters OxiServe. The
  fair Linux comparison puts it back.
- **An unloaded 10-core Mac hides per-request CPU cost.** OxiServe uses more
  CPU per request than nginx; with 8 spare cores that never showed. On 2
  contended Linux cores it dominates.
- Loopback benchmarks measure the server and the kernel, not a network.

The honest summary: **OxiServe is correct and reasonably fast, but it does not
beat nginx on Linux today.** The name of the game now is closing that gap, not
claiming it is closed.

### Large files (macOS tuning notes)

The 10 MiB path went through several strategies on macOS before reaching the
0.95× above. Recorded here because the obvious explanations were wrong and the
measurements said so — but note the Linux table above supersedes these as the
headline result. Throughput per concurrency level, 10 MiB, macOS:

| strategy | c=1 | c=10 | c=128 |
|---|---:|---:|---:|
| blocking pool, 512 KiB buffers | 813 | 809 | 473 |
| blocking pool, 32 KiB buffers | 393 | 745 | 689 |
| inline `pread`, 32 KiB buffers | 699 | 809 | 393 |
| whole file from a memory map | 807 | 744 | 475 |
| **adaptive (shipped)** | **694** | **793** | **667** |
| nginx | 704 | 779 | 706 |

Three findings, none of which were guessable from reading the code:

1. **Per-connection we were always faster than nginx** (813 vs 704 at c=1).
   The problem was purely how throughput scaled — it fell off past ~10
   concurrent transfers.
2. **Buffer size dominates, and bigger is not better.** 64 KiB and above cost
   ~30% at 128 connections. nginx's `output_buffers 2 32k` default is that
   number, and OxiServe now honours the directive rather than hardcoding one.
3. **Offloading reads to a thread pool is right only under load.** A pool round
   trip per chunk halves single-stream throughput, because a page-cache read is
   cheaper than the handoff. Under concurrency the same offload is what keeps
   the worker free. So the choice is made at runtime from the number of
   transfers that worker is currently running — inline below the threshold,
   pooled above it.

Serving large files from a memory map was also tried, and is *worse* under
concurrency regardless of write size. Mapping is therefore reserved for small
files, where its single-syscall write is what produces the 2× at 100 KiB.

## Building

```console
$ cargo build --release
$ cargo test
```

The release profile uses fat LTO and a single codegen unit; both matter
measurably here.

## Layout

```
src/config/    lexer, directive tree, variable engine, runtime model, builder
src/http/      request parsing, response building, URI normalisation, dates
src/server/    workers, connection loop, routing, static files, proxy, logging
bench/         head-to-head harness against nginx
conf/          sample configuration
```

## License

Apache-2.0

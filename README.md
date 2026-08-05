# OxiServe

An nginx-configuration-compatible web server written in Rust.

OxiServe reads your existing `nginx.conf` — the real grammar, includes, variables,
`server_name` and `location` matching semantics included — and serves it from a
thread-per-core data plane designed to beat nginx on the static and proxy hot paths.

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

**Measured** on macOS 15 (Darwin 25.3), M-series, 10 cores, loopback,
`wrk -t10 -c128 -d10s`, nginx 1.31.3, `sendfile off` on both:

| Payload | OxiServe | nginx | |
|---|---:|---:|---|
| 0 B | **139,850** rps | 79,948 rps | **1.75×** |
| 1 KiB | **105,287** rps | 75,022 rps | **1.40×** |
| 100 KiB | **73,971** rps | 37,043 rps | **2.00×** |
| 10 MiB | 479 rps | **725** rps | **0.66×** — we lose |

Read the caveats before quoting any of this:

- **We lose on multi-megabyte files**, by a third. The cost is in the bulk
  write path, not the read path: raising the mmap threshold so 10 MiB files are
  served from a mapping changed nothing (479 → 482 rps). This is a real,
  unfixed gap, not a measurement artifact.
- **`sendfile off` on both is deliberate.** On macOS, nginx's `sendfile on`
  path collapses to ~100 MB/s — a Darwin pathology, not an nginx
  characteristic. Leaving it on produces a flattering 63× "win" on the 10 MiB
  case that means nothing. The harness turns it off for both and says so.
  On Linux, re-run with `SENDFILE=on`.
- **macOS is not nginx's best platform.** No `epoll`, no `SO_REUSEPORT` accept
  load-balancing. Expect nginx to close much of the small-payload gap on Linux.
  These numbers are a starting point, not a verdict.
- Loopback benchmarks measure the server and the kernel, not a network.

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

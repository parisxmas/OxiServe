# OxiServe

An nginx-configuration-compatible web server written in Rust.

OxiServe reads your existing `nginx.conf` — the real grammar, includes, variables,
`server_name` and `location` matching semantics included — and serves it from a
thread-per-core data plane.

The goal is to beat nginx on the static hot path. Current standing on a fair
Linux benchmark, both servers configured identically with `open_file_cache`
(see [Benchmarks](#benchmarks) for the full history, including one measurement
bug in each direction that had to be found and corrected): **+63% at 1 KiB,
+10% at 0 B, tie at 100 KiB and 10 MiB.** `sendfile(2)` and `open_file_cache`
are implemented; a cache hit serves a request with zero filesystem syscalls.

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

**Rate limiting** — `limit_req_zone` / `limit_req` (`burst`, `nodelay`,
`delay=N`) / `limit_req_status`, using nginx's leaky bucket with excess in
milli-requests so `30r/m` is exact. In-process and sharded: no detectable throughput cost (within
run-to-run noise). Verified under load on Linux — `rate=50r/s burst=10` over
5 seconds admitted 263 requests and rejected 460,495, against 260 predicted.

**Bodies** — `Content-Length` and chunked request bodies are read and decoded
before routing, `Expect: 100-continue`, `client_max_body_size` enforcement.

**Serving** — static files, `root` / `alias`, `index`, `autoindex`, `try_files`,
byte ranges, `If-None-Match` / `If-Modified-Since` / `If-Range` / `If-Match`,
ETags, MIME types, `expires`, `add_header`, gzip, `error_page`, `return`,
`rewrite` (all four flags), `if` (all condition forms), `set`, `map`,
`limit_except`, `internal`.

**FastCGI** — `fastcgi_pass` (responder role) to an address or `upstream`
block, `fastcgi_param` with `if_not_empty`, `fastcgi_index`,
`fastcgi_split_path_info`, timeouts, `fastcgi_keep_conn`,
`fastcgi_hide_header`. Verified against real php-fpm (PHP 8.5): `$_GET`,
`$_POST`, `PATH_INFO`, PHP-set status headers, the WordPress-style
`try_files $uri $uri/ /index.php?$args` front-controller pattern, and
300 KB responses spanning multiple records.

**Proxying** — `proxy_pass` to upstreams, literal addresses or Unix sockets,
`upstream` blocks with `weight` / `backup` / `down`, round-robin and `ip_hash`,
`proxy_set_header`, `proxy_hide_header`, timeouts, chunked pass-through.

**Content cache** — `proxy_cache_path` (with `levels=`, `keys_zone=`,
`inactive=`, `max_size=`, enforced by a background cache manager),
`proxy_cache`, `proxy_cache_key`,
`proxy_cache_valid`, `proxy_cache_methods`, `proxy_cache_min_uses`,
`proxy_cache_bypass`, `proxy_no_cache`, `proxy_cache_use_stale`,
`proxy_cache_lock` (+ `_timeout`), and `$upstream_cache_status`
(MISS/HIT/EXPIRED/BYPASS/STALE).

`proxy_cache_lock` collapses a stampede: when a popular entry expires, one
request refreshes it and the rest wait for that result instead of each opening
its own upstream connection. `proxy_cache_use_stale` decides when a expired
copy beats an error — including `updating`, where a waiter is answered from
the old copy immediately rather than queueing behind the refresh at all. The index every request consults is in-process;
only bodies touch the disk. Each entry stores its own cache key and it is
compared on every read, so a digest collision cannot serve one URL's response
for another.

A background *cache manager* (which caches nothing — it prunes) sweeps the
directory on one worker: entries past `inactive=`, oldest-first eviction down
to `max_size=`, temporary files left by an interrupted write, and the empty
directories `levels=` leaves behind. It walks the filesystem rather than
trusting the in-process index, because that index is per worker and empty
after a restart — the same reason nginx runs a separate cache loader.

**Load balancing** — active health checks (`health_check interval= fails=
passes= uri= status=`, HTTP or plain TCP, with hysteresis in both directions),
passive health checks (`max_fails` / `fail_timeout`, with ejection and
automatic recovery), `backup` failover, weighted round-robin, real
`least_conn` (in-flight counts, weight-aware), `ip_hash`, and an upstream
`keepalive` pool that probes a connection for liveness before reusing it.
Health is shared across workers; the pool is per worker.

**HTTP/2** — `listen 443 ssl http2` negotiates `h2` over ALPN;
`listen 80 http2` also serves cleartext h2c by prior knowledge, sharing the
port with HTTP/1.1 (the first bytes are inspected, never consumed, so an
HTTP/1 client is unaffected). Streams are genuinely concurrent: each request
runs as its own task and a writer owns the socket, so a slow backend on one
stream does not hold up a cache hit on another. HPACK with Huffman, flow
control on both the connection and each stream, and the connection/stream
error split (a malformed request resets its own stream; a compression error
ends the connection).

HTTP/2 is a *transport* swap and nothing above the framing layer is
reimplemented: a decoded request becomes the same `Req` the HTTP/1 parser
produces and goes through the same handler, so `proxy_pass`, `proxy_cache`,
`limit_req`, FastCGI, `try_files`, `error_page` and every variable behave
identically. `:authority` is turned back into a `Host` header so `server_name`
matching and `$host` need no special case.

> `sendfile` cannot apply to HTTP/2 — every byte must be wrapped in a DATA
> frame, so the kernel cannot hand the page cache straight to the socket.
> That is inherent to the protocol; nginx pays the same cost.

**Layer 4 (`stream`)** — TCP proxying with no HTTP parsing, so it fronts
PostgreSQL, Redis, MQTT or anything else with a TCP protocol. Shares upstream
selection, passive health and `least_conn` with the HTTP proxy; `proxy_timeout`
is an *idle* timeout, so a long-lived session is never severed for being long.
`listen unix:` works here too.

**`ssl_preread`** — route TLS on SNI without terminating it. The ClientHello is
read and *not consumed*: every byte, including the ones inspected, is forwarded,
so the backend completes the handshake against untouched input and we never hold
a key or a certificate. `$ssl_preread_server_name`,
`$ssl_preread_alpn_protocols` and `$ssl_preread_protocol` feed a `stream`-level
`map`, with `preread_buffer_size` and `preread_timeout` bounding the wait.
Traffic that is not TLS is proxied unchanged rather than dropped — important
because it shares the port with protocols where the server speaks first.

```nginx
stream {
    map $ssl_preread_server_name $backend {
        api.example.com   api_pool;
        git.example.com   git_pool;
        default           web_pool;
    }
    server { listen 443; ssl_preread on; proxy_pass $backend; }
}
```

> **Still missing for a true HAProxy replacement:** UDP in `stream`,
> cookie-based sticky sessions, a stats endpoint.
> Scope and order: [ADR-0001](docs/decisions/0001-load-balancer-scope.md).

**TLS** — rustls, `ssl_certificate` / `ssl_certificate_key`, SNI across servers
sharing a listener.

**Logging** — `log_format` with the full variable set, `access_log` with
`buffer=` / `flush=`, `error_log` with levels, and a structured sink into
OxiDB:

```nginx
log_format structured '$remote_addr $request_method $uri $status $body_bytes_sent $request_time';
access_log oxidb:server=127.0.0.1:12202[,db=tenant] structured;
```

Each `$variable` in the format becomes a field in a MessagePack document sent
fire-and-forget over UDP to OxiDB's ingest listener — so records arrive
queryable rather than as lines to re-parse, and `$status` / `$body_bytes_sent`
arrive as numbers so they can be range-queried. A collector that is down or
slow cannot stall a request ([ADR-0002](docs/decisions/0002-no-database-on-the-request-path.md)).

**Variables** — ~50 including `$uri`, `$args`, `$arg_*`, `$http_*`, `$sent_http_*`,
`$cookie_*`, `$upstream_*`, `$proxy_add_x_forwarded_for`,
`$fastcgi_script_name`, `$fastcgi_path_info`, `$https`,
regex captures `$1`–`$9`.

## Not implemented

`oxiserve -t` reports these per-config, distinguishing "not implemented yet" from
"unknown directive". Currently missing:

- **HTTP/3** (QUIC). `listen ... quic` is parsed and ignored.
- **HTTP/2 server push** — deprecated by RFC 9113 and advertised as disabled;
  **HTTP/2 CONNECT**; **HTTP/2 trailers** (accepted and discarded);
  **`Upgrade: h2c`** (the deprecated cleartext upgrade — prior-knowledge h2c
  works).
- **uwsgi / SCGI / gRPC** — `uwsgi_pass` and friends (FastCGI *is* supported).
- **FastCGI response streaming** — responses are fully buffered
  (`fastcgi_buffering on`, capped at 64 MB) rather than streamed.
- **`proxy_cache_background_update` / `proxy_cache_revalidate`** — parsed and
  ignored; a refresh is always a full fetch, never a conditional revalidation.
- **`limit_conn`** connection limiting (`limit_req` is implemented).
- **`auth_basic`**, `auth_request`.
- **Unix domain sockets** in `listen`.
- **`mail`** block; **UDP** inside `stream` (`ssl_preread` is implemented).
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

### Real-world check: WordPress

WordPress 6.x on PHP 8.3 (php-fpm in a container over a Unix socket, MariaDB,
`try_files $uri $uri/ /index.php?$args`, pretty permalinks) runs on OxiServe
end to end: front page, static assets, admin login and dashboard, REST API,
and creating + publishing a post through `POST /wp-json/wp/v2/posts`.

Against nginx on the **same** php-fpm socket, same files, same port taken in
turn, responses verified byte-identical (69,783 B) before trusting either
number:

| | OxiServe | nginx |
|---|---:|---:|
| WordPress page (PHP) | **70.9 rps** | 64.6 rps |
| static CSS | 19,601 rps | 19,895 rps |

The PHP number is dominated by php-fpm, so neither server is really being
measured there; the honest reading is "no regression from the FastCGI path".

Running it found two bugs that no unit test had:

- **`index` leaked PHP source.** nginx treats an `index` match as an internal
  redirect so location selection runs again and `/` reaches
  `location ~ \.php$`. We served the matched file directly — meaning
  `wp-config.php` credentials would go to the client verbatim. Fixed, with a
  regression test that asserts neither `<?php` nor a planted secret appears in
  the body.
- **gzip skipped every file above 64 KB.** Those take the sendfile path, and
  the compressor only handled in-memory bodies — so WordPress's 131 KB
  stylesheet shipped uncompressed. Now compressed (81% smaller), bounded at
  8 MB.

Known gap found in the same run: a `HEAD` request does not report
`Content-Encoding: gzip` (the body is dropped before the compressor sees it),
where nginx does.

### Linux — the corrected result

The first Linux comparison reported here said nginx wins at every size. **That
conclusion was wrong, and the error was ours**: the benchmark pinned OxiServe's
workers to 2 of the 4 cores, but the same pinning command only ever matched
nginx's *master* process — its workers (forked earlier, cmdline `nginx: worker
process`, unmatched by the pgrep pattern) kept all 4 cores. Every previous
Linux table gave nginx twice the CPU.

With both servers verified onto the same 2 cores (`taskset -cp` checked on the
actual worker PIDs) and wrk isolated on the other 2, three alternating rounds,
Debian 12 / kernel 6.1 / nginx 1.22.1, `sendfile on` both:

| Payload | OxiServe (avg) | nginx (avg) | verdict |
|---|---:|---:|---|
| 0 B | 83,092 rps | 81,896 rps | tie (lead flips run to run) |
| 1 KiB | **75,418 rps** | 56,466 rps | **OxiServe +33%, consistent** |
| 100 KiB | 30,082 rps | 29,689 rps | tie |
| 10 MiB | 540 rps | 529 rps | tie (both sendfile) |

**Where the 1 KiB win comes from.** Syscall traces (2,000 keep-alive requests
under `strace -c`) show both servers make ~5.5 syscalls per request, but they
spend them differently. For a small file nginx issues `writev(head)` +
`sendfile(body)` — two body-path syscalls; OxiServe reads the file into the
per-connection write buffer and emits head+body in a **single `sendto`**. One
syscall instead of two, and no sendfile setup cost on a file that fits in one
segment anyway.

**Why the earlier optimisation conclusions still stand.** The +55% (1 KiB) and
+82% (10 MiB) gains from the allocation/sendfile pass were measured
OxiServe-vs-OxiServe under identical conditions, so the pinning bug does not
touch them — without that pass, today's numbers would be losses.

**What profiling established** (perf, 0 B path, 8s sample): 88.5% of CPU is in
the kernel, 8% in OxiServe's own code, and the top kernel entries are path
lookup (`strncpy_from_user`, `link_path_walk`) from the per-request
`stat`+`open`+`close`. Two consequences:

- Optimising user-space further is fighting over 8% of the pie. Stop.
- The next real lever is **`open_file_cache`**: 3 of our ~5.5 syscalls per
  request are filesystem metadata that a cache removes entirely. nginx ships
  this directive but defaults it off; implementing it would honour existing
  configs and is the clearest route from "tie" to "win" on small files.

Single-run noise on this box is ±5%; the tables above are means of three
alternating rounds.

### With `open_file_cache` — the current standing

`open_file_cache` is now implemented (per-worker, fd + fstat cached, zero
filesystem syscalls on a hit — verified with `strace`: `statx`/`openat`/`close`
vanish from the trace, ~5.5 → ~3.5 syscalls per 1 KiB request). Same method,
both servers configured with `open_file_cache max=1000; open_file_cache_valid
60s;`, three alternating rounds, per-round ratios:

| Payload | round ratios (OxiServe / nginx) | mean | verdict |
|---|---|---:|---|
| 0 B | 0.94× / 1.15× / 1.21× | **1.10×** | OxiServe ahead 2 of 3 |
| 1 KiB | 1.91× / 1.48× / 1.59× | **1.63×** | **OxiServe, decisively** |
| 100 KiB | 0.87× / 1.07× / 1.06× | 1.00× | tie |
| 10 MiB | — | ~1× | tie (both `sendfile` from cached fd) |

Why the 1 KiB gap widened: with metadata syscalls gone on both sides, what
remains is the data path — nginx spends `writev(head)` + `sendfile(body)` per
small file, OxiServe one `pread` + one `sendto`. The same two-vs-one syscall
difference is now a larger share of a smaller total.

Cache semantics match nginx's documented behaviour: entries are trusted for
`open_file_cache_valid`, so deploys should replace files atomically (`rename`)
— the cached descriptor then serves the old content intact until revalidation.
An in-place truncate writes through any fd-caching server, nginx included.

### macOS — where the story began, and why it misled

macOS 15, M-series, 10 cores, unloaded, `wrk -t10 -c128`, nginx 1.31.3,
`sendfile off` on both:

| Payload | OxiServe | nginx | |
|---|---:|---:|---|
| 0 B | 140,076 rps | 80,326 rps | 1.74× |
| 1 KiB | 108,280 rps | 76,289 rps | 1.42× |
| 100 KiB | 74,087 rps | 37,273 rps | 1.99× |
| 10 MiB | 667 rps | 703 rps | 0.95× |

These early numbers looked like large wins. They were partly artifacts, and
they are kept here because both of this project's measurement lessons live in
this table:

- **`sendfile off` was hiding nginx's best trick.** It was forced off because
  macOS's `sendfile` has a pathology (nginx collapses to ~100 MB/s). But
  turning off a feature nginx has and OxiServe lacks flatters OxiServe. The
  fair Linux comparison puts it back.
- **An unloaded 10-core Mac hides per-request CPU cost.** OxiServe uses more
  CPU per request than nginx; with 8 spare cores that never showed. On 2
  contended Linux cores it dominates.
- Loopback benchmarks measure the server and the kernel, not a network.

Between this table and the Linux one sits the whole story: a benchmark setup
error first flattered OxiServe (macOS, sendfile off), then a different one
flattered nginx (Linux, workers never actually pinned). Both had to be found
before the numbers meant anything. Trust measurements you have tried to break.

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

## Decisions

Architecture decisions are recorded in [`docs/decisions/`](docs/decisions/):

- [ADR-0001](docs/decisions/0001-load-balancer-scope.md) — load balancer scope:
  what is real, what only looks real, and the order the gaps close.
- [ADR-0002](docs/decisions/0002-no-database-on-the-request-path.md) — why no
  store, not even an embedded one, sits on the per-request path, with the
  measurements that overturned my earlier claim.

## Testing

```console
$ cargo test                                   # 315 tests
$ cargo +nightly miri test --lib http::request # UB checking on the unsafe code
$ cargo +nightly fuzz run uri_normalize        # 5 targets under fuzz/
```

Five libFuzzer targets cover the parsers that read attacker-influenced input:
the HTTP request parser, URI normalisation, the cache entry decoder, FastCGI
records, and the config lexer. They assert properties rather than just
absence of panics — that normalisation output is absolute and dot-free, that
`Transfer-Encoding` and `Content-Length` are never both accepted, that a cache
entry decoded under one key is refused under another.

That pass found two real bugs: UTF-8 corruption in path handling, and an
integer overflow decoding a corrupt cache file. Miri reports no undefined
behaviour across the modules containing `unsafe`.

## Building

```console
$ cargo build --release
$ cargo test
$ scripts/bump.sh          # 0.2.3 -> 0.2.4, before committing a change
```

The version reaches clients in the `Server:` header and in `oxiserve -v`, so
each build that changes behaviour should carry its own.

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

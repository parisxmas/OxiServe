<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <img src="assets/logo.png" alt="OxiServe" width="520">
  </picture>
</p>

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

Four worked examples — a TLS site, a reverse proxy, a load balancer and an API
gateway — are in [`conf/examples/`](conf/examples/). All four pass `oxiserve -t`
with no warnings, so every directive in them is implemented rather than parsed
and ignored.

## Install on Linux

Releases ship one statically linked binary per architecture, built against musl.
There is no glibc version to match and nothing to install alongside it, so the
same file runs on Debian, Ubuntu, RHEL, Alpine or anything else with a kernel
new enough to matter.

The latest release is **v0.2.38**. `$(uname -m)` picks the right architecture,
so these run as they are on both x86_64 and aarch64:

```console
$ curl -fsSLO https://github.com/parisxmas/OxiServe/releases/download/v0.2.38/oxiserve-0.2.38-linux-$(uname -m).tar.gz
$ curl -fsSLO https://github.com/parisxmas/OxiServe/releases/download/v0.2.38/SHA256SUMS
$ sha256sum -c --ignore-missing SHA256SUMS

$ tar -xzf oxiserve-0.2.38-linux-$(uname -m).tar.gz
$ sudo install -m 755 oxiserve-0.2.38-linux-$(uname -m)/oxiserve /usr/local/bin/
```

`SHA256SUMS` covers every archive in the release, hence `--ignore-missing` —
without it the check fails on the architecture you did not download.

Point it at a configuration you already have. `-t` parses and validates without
binding anything, and names any directive OxiServe does not implement, so it is
worth running against your real `nginx.conf` before anything else:

```console
$ oxiserve -v
oxiserve version: oxiserve/0.2.38

$ oxiserve -t -c /etc/nginx/nginx.conf
```

Ports below 1024 need either root or the capability on its own, which is the
better of the two — the worker never needs the rest of what root carries:

```console
$ sudo setcap cap_net_bind_service=+ep /usr/local/bin/oxiserve
```

OxiServe never daemonises — it stays in the foreground and leaves the process to
whatever is supervising it, which is exactly what systemd's default `Type=simple`
expects, so no `daemon off;` equivalent is needed:

```ini
[Unit]
Description=OxiServe
After=network.target

[Service]
ExecStartPre=/usr/local/bin/oxiserve -t -c /etc/oxiserve/oxiserve.conf
ExecStart=/usr/local/bin/oxiserve -c /etc/oxiserve/oxiserve.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The tarball also carries `conf/oxiserve.conf` and the four worked examples, so
there is something to start from if you are not bringing an existing config.

To build the release artifacts yourself rather than downloading them, see
[Building](#building). What changed in each version is in
[CHANGELOG.md](CHANGELOG.md).

## Status

This is an early but genuinely working server, not a demo. It serves real
traffic for the feature set below, with 560 tests (360 unit + 200 end-to-end
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

**Concurrency limiting** — `limit_conn_zone` / `limit_conn` /
`limit_conn_status` / `limit_conn_dry_run`. As in nginx this counts *requests
in flight*, not connections, so an idle keep-alive connection costs nothing;
the count is taken before any work is done and given back when the response
has been written, on every exit path. One shared table across worker
processes, so `limit_conn perip 1` means one, not one per worker.

**Bodies** — `Content-Length` and chunked request bodies are read and decoded
before routing, `Expect: 100-continue`, `client_max_body_size` enforcement.

**Serving** — static files, `root` / `alias`, `index`, `autoindex`, `try_files`,
byte ranges, `If-None-Match` / `If-Modified-Since` / `If-Range` / `If-Match`,
ETags, MIME types, `expires`, `add_header`, gzip, `error_page`, `return`,
`rewrite` (all four flags), `if` (all condition forms), `set`, `map`,
`limit_except`, `internal`.

**FastCGI** — `fastcgi_pass` (responder role) over TCP, a Unix socket or an
`upstream` block, with `fastcgi_param` (including `if_not_empty`),
`fastcgi_index`, `fastcgi_split_path_info`, `fastcgi_keep_conn`,
`fastcgi_hide_header`, timeouts, and the CGI `Status:` / bare `Location:`
rules.

A response is collected whole while it fits `fastcgi_buffers ×
fastcgi_buffer_size` (64 KB by default), which is what lets it carry a
`Content-Length`; past that it is forwarded as it arrives and the transfer is
chunked. `fastcgi_buffering off` forwards from the first byte regardless. An
application that declares its own `Content-Length` keeps it either way — it is
the only party that knows the length of something we never hold.

Verified against real php-fpm (PHP 8.5): `$_GET`, `$_POST`, `PATH_INFO`,
PHP-set status headers, the WordPress-style
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

**Load balancing** — `proxy_next_upstream error timeout invalid_header
http_500 …` retries a failed peer against another one, bounded by
`proxy_next_upstream_tries` and `proxy_next_upstream_timeout`. A `POST` is not
retried unless `non_idempotent` says so — "the first attempt might have
succeeded" is exactly when retrying is worse than failing — and nothing past
the response head is retryable, because by then the client is already
receiving the answer. Active health checks (`health_check interval= fails=
passes= uri= status=`, HTTP or plain TCP, with hysteresis in both directions),
passive health checks (`max_fails` / `fail_timeout`, with ejection and
automatic recovery), `backup` failover, weighted round-robin, real
`least_conn` (in-flight counts, weight-aware), `ip_hash`, and an upstream
`keepalive` pool that probes a connection for liveness before reusing it.

**Sticky sessions** — `sticky cookie name [expires=] [domain=] [path=]
[httponly] [secure] [samesite=]`, using NGINX Plus's spelling so a config
written for it works unchanged. Unlike `ip_hash` this survives a client whose
address changes, which is the case that makes address stickiness fail on
mobile networks and behind rotating NAT.

The pin layers *over* the balancing method rather than replacing it: the
cookie decides when it is present and names a peer that can still take
traffic, and `least_conn` or round-robin decides in every other case. A pin to
a backend that has since been ejected falls through to ordinary balancing and
the client is re-pinned — honouring it would hand every one of that peer's
clients an error instead of spreading them over the survivors.

The cookie value is an opaque hash of the peer's address, so it does not
disclose the backend topology, and it is deterministic rather than seeded, so
a reload does not scatter every established session. No shared state is
needed: any worker in any process can decode a cookie the others issued.
Health is shared across workers; the pool is per worker.

**`auth_request`** — the yes/no is delegated to another service, which is how
an API gateway does authentication without the gateway knowing anything about
it:

```nginx
location /private/ {
    auth_request /_auth;
    auth_request_set $user $upstream_http_x_user;
    proxy_pass http://app;
}
location = /_auth {
    internal;
    proxy_pass http://auth-service;
}
```

The subrequest is a fresh `GET` carrying the client's headers and **no body** —
the service is being asked *about* the request, not asked to process it. `2xx`
continues; `401` and `403` are returned to the client as they stand, since they
are the service's answer and not our error; anything else, including an
unreachable service, is a `500`. Failing open is the one outcome an
authorisation check must never have.

**Signals** — `-s stop | quit | reload | reopen`, found through the `pid` file
the configuration names, so a host running two servers signals the right one.

`reload` re-reads and fully validates the configuration *before* it forks
anything. A file that does not load costs one log line and nothing else — the
running workers keep serving the old configuration, which is the entire reason
to reload rather than restart. On success the new workers start first and only
then are the old ones asked to drain, so there is no moment with nobody
listening; `SO_REUSEPORT` is what lets both generations hold the port, and
without it the new workers inherit the master's descriptors instead.

`quit` and a superseded generation drain gracefully: they stop accepting, and
requests already in progress finish. "In progress" starts at the *first byte*
of a request — a connection merely sitting open, including a keep-alive slot
or a readiness probe, is closed at once rather than delaying the handover.
A WebSocket tunnel counts as in progress, which is why the drain is bounded at
30 seconds.

`reopen` reopens every log file by name, and takes effect on the next line
written rather than at the next flush — a lazier check left a window in which
lines still went to the inode `logrotate` had just moved aside.

**WebSockets** — a `101` from the backend switches the connection out of HTTP
and wires the two sockets together until a peer hangs up. Configured as nginx
configures it:

```nginx
location /ws {
    proxy_pass http://app;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

`proxy_read_timeout` becomes an *idle* timeout on the tunnel rather than a
bound on its life — a WebSocket that sits quiet for an hour and then carries a
message is working, not stuck. A `101` the client never asked for is refused
with `502`: forwarding it would leave a client that speaks HTTP wired to one
that no longer does.

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

Conformance is measured, not asserted: [h2spec] 2.6 reports **144/145 passed,
0 failed** over TLS (1 skipped). On a cleartext port the same suite reports
144/145 with one failure, and it is the one deliberate deviation —
`listen 80 http2` shares the port with HTTP/1.1, so bytes that are not the
HTTP/2 preface go to the HTTP/1 parser, which answers `505` and closes.
h2spec wants the connection closed in silence. Sharing the port is worth more
than that test.

> `sendfile` cannot apply to HTTP/2 — every byte must be wrapped in a DATA
> frame, so the kernel cannot hand the page cache straight to the socket.
> That is inherent to the protocol; nginx pays the same cost.

[h2spec]: https://github.com/summerwind/h2spec

**HTTP/3** — `listen 443 quic;` serves HTTP/3 over QUIC, and an `Alt-Svc`
header on the TCP side tells browsers to use it:

```nginx
server {
    listen 443 ssl;
    listen 443 quic;
    server_name example.com;
    ssl_certificate     /etc/ssl/example.crt;
    ssl_certificate_key /etc/ssl/example.key;
}
```

The split is deliberate and is written up in [ADR-0004]. **The QUIC transport
is [quinn]** — packet and header protection, the TLS 1.3 handshake, loss
recovery, congestion control, connection IDs, path validation. Those are the
parts where a mistake is an exploit rather than a bug, where a decade of
congestion-control tuning is the difference between HTTP/3 being an
improvement and being a downgrade, and where no `nginx.conf` can tell one
conformant implementation from another.

**The HTTP/3 framing and QPACK are ours** (`src/http3/`), because that layer
sits between the config and the wire exactly as HPACK does. QPACK reuses the
Huffman coder and the prefixed-integer coding already written for HPACK — RFC
9204 shares both with RFC 7541 — and is checked byte-for-byte against RFC
9204's own test vector rather than only against itself.

`SETTINGS_QPACK_MAX_TABLE_CAPACITY` is **0**, on purpose. That is a conformant
configuration, not a gap: a peer given a capacity of zero may not send a table
insertion, so no field section can arrive that we would fail to decode. It
removes the entire reason QPACK is bigger than HPACK — blocked streams, insert
counts, section acknowledgements — at the cost of some compression on repeated
request headers, which the 99-entry static table already covers. The HPACK
encoder makes the same trade in the other direction.

As with HTTP/2, HTTP/3 is a *transport* swap: a decoded request becomes the
same `Req` the HTTP/1 parser produces and runs through the same handler, so
`proxy_pass`, `proxy_cache`, `limit_req`, `limit_conn`, FastCGI, `try_files`
and every variable behave identically — there is a test asserting `limit_req`
still rejects over h3. `src/http3/conn.rs` is a third the size of the HTTP/2
one, because stream states, flow-control windows and CONTINUATION reassembly
are the transport's problem now.

> **Connection migration does not survive a worker change.** QUIC listeners are
> bound per worker with `SO_REUSEPORT` — one shared UDP socket would hand a
> connection's packets to workers that cannot decrypt them — and the kernel
> hashes the 4-tuple, so a client that changes address lands on a worker that
> has never seen its connection ID. It reconnects, costing a round trip.
> nginx has the same limitation and fixes it with an eBPF steering program;
> that is Linux-only and not written yet.

> `sendfile` cannot apply here either, for the same reason it cannot apply to
> HTTP/2 — and 0-RTT is deliberately not offered, because early data is
> replayable and which requests may accept a replay is a policy question with
> a config surface, not a default.

[quinn]: https://github.com/quinn-rs/quinn
[ADR-0004]: docs/decisions/0004-quic-transport.md

**Layer 4 (`stream`)** — TCP proxying with no HTTP parsing, so it fronts
PostgreSQL, Redis, MQTT or anything else with a TCP protocol. Shares upstream
selection, passive health and `least_conn` with the HTTP proxy; `proxy_timeout`
is an *idle* timeout, so a long-lived session is never severed for being long.
`listen unix:` works here too.

**UDP** — `listen ... udp;` in a `stream` server proxies datagrams, for DNS,
syslog, QUIC-behind-a-balancer and anything else that is not a byte stream:

```nginx
stream {
    upstream dns { server 10.0.0.1:53; server 10.0.0.2:53; }
    server { listen 53 udp; proxy_pass dns; proxy_responses 1; proxy_timeout 5s; }
}
```

UDP has no connections, so a *session* is invented the way nginx does it: the
first datagram from a source address starts one, later datagrams from the same
address join it, and it ends when `proxy_responses` replies have come back or
`proxy_timeout` passes with nothing happening. Each session gets its own
socket `connect`ed to the chosen peer, which is what makes replies
attributable and lets the kernel drop datagrams from anywhere else. A client
that changes address simply starts a new session — for UDP that is the correct
outcome, not the limitation it is for QUIC. Upstream selection, weights and
health are shared with the TCP path, and a port can carry both at once.

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

> The three items this section used to list as missing for a HAProxy
> replacement — cookie sticky sessions, UDP in `stream`, and a stats endpoint —
> all shipped, in v0.2.32 and v0.2.33.
> Scope and order: [ADR-0001](docs/decisions/0001-load-balancer-scope.md).

**TLS** — rustls, `ssl_certificate` / `ssl_certificate_key`, SNI across servers
sharing a listener.

**Status** — `stub_status;` in a location, byte-for-byte nginx's format, so
the monitoring agents that parse it with regexes written against nginx keep
working. The counters live in the pre-fork `MAP_SHARED` mapping, so they
report the whole server rather than whichever worker answered — with
`worker_processes 2` that is the difference between the real number and half
of it. `Reading` / `Writing` / `Waiting` are moved by the connection state
machine as it actually changes state rather than estimated.

`stub_status json;` is an extension — nginx has no upstream visibility outside
its commercial build — adding per-peer state, in-flight counts, weights and
which peers are `down` versus health-ejected. A pool that cannot be inspected
is one you debug by guessing, and the data already exists: it is what
`least_conn` and the health checks are maintaining anyway.

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

- **HTTP/2 server push** — deprecated by RFC 9113 and advertised as disabled;
  **HTTP/2 CONNECT**; **HTTP/2 trailers** (accepted and discarded);
  **`Upgrade: h2c`** (the deprecated cleartext upgrade — prior-knowledge h2c
  works).
- **HTTP/3 0-RTT early data**, **QUIC connection migration across workers**
  (see [ADR-0004]), and **Extended CONNECT** — so no WebSockets over HTTP/3.
- **uwsgi / SCGI / gRPC** — `uwsgi_pass` and friends (FastCGI *is* supported).
- **`proxy_cache_background_update` / `proxy_cache_revalidate`** — parsed and
  ignored; a refresh is always a full fetch, never a conditional revalidation.
- **`auth_basic`** / `auth_basic_user_file` (`auth_request` is implemented).
- **`mail`** block — SMTP/IMAP/POP3 proxying.
- **nginx binary modules** — an `.so` is compiled against nginx's internal C
  ABI, so there is no version of this that gets implemented later: NAXSI, njs
  and the rest are absent. `load_module` is *reported* rather than quietly
  accepted, naming the module, and saying so outright when the missing one was
  there to filter requests. ModSecurity is the exception, and it is available
  properly rather than through a module — see [ModSecurity](#modsecurity-waf).
- **Binary upgrade** (`USR2`/`WINCH`) — replacing the executable without
  dropping connections. `-s reload` covers configuration changes.
- **PCRE-only regex** — lookaround and backreferences are rejected with a clear
  error rather than silently mismatching (Rust's `regex` has neither).

## ModSecurity (WAF)

OxiServe runs real ModSecurity rules — the OWASP Core Rule Set included —
through **libmodsecurity v3**, linked directly.

The reason it is not nginx's ModSecurity *module* is worth stating, because it
is the same reason every other nginx module is out of reach. A module's `.so`
is compiled against nginx's internal C ABI and carries a signature of the
host's compile-time options; nginx refuses to load one whose signature differs
by a single bit. Hosting one would mean being byte-compatible with one
particular nginx build. But the rule engine was never the nginx-coupled part —
libmodsecurity is a standalone library with a plain C API, and nginx's module
is a thin shim over it. Calling it directly gets the real engine, with nginx
nowhere in the picture.

It is **off by default**, because it is the one C dependency in the project and
the released binaries are static musl with none:

```console
$ cargo build --release --features modsecurity
```

Configuration follows the nginx connector's directive names, so an existing
setup ports across:

```nginx
http {
    modsecurity on;
    modsecurity_rules_file /etc/oxiserve/modsec/crs-setup.conf;
    modsecurity_rules_file /etc/oxiserve/modsec/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf;

    # Inline, for the short things that are not worth a file.
    modsecurity_rules '
        SecRuleEngine On
        SecRequestBodyAccess On
    ';

    server {
        listen 80;
        location /health { modsecurity off; }   # rules stay loaded, not consulted
    }
}
```

`modsecurity on|off` and the rule directives inherit `http` → `server` →
`location` the way the rest of the configuration does. A level naming its own
rules replaces the inherited engine rather than merging — libmodsecurity offers
no way to combine two compiled sets, and pretending otherwise would silently
drop one.

Rules compile at configuration load, so `oxiserve -t` fails on a bad rules file
instead of the server starting and discovering it on the first request. A
blocked request logs which rule blocked it, at `[warn]`, alongside everything
else.

### Response-phase rules

All five phases run: connection, URI and request headers (1–2), response
headers (3), response body (4), logging (5). One transaction spans them, which
matters for CRS — its anomaly score accumulates across phases, and a fresh
transaction for the response would start that count from zero and let a request
that scored 4 going in and 3 coming out look like two harmless halves.

Phase 4 is **off by default**, because inspecting a response body means holding
it in memory — the opposite of what `sendfile` and the mmap path exist to do:

```nginx
http {
    modsecurity_response_body on;
    modsecurity_response_body_limit 512k;   # the default
}
```

A body over the limit is served without being inspected rather than buffered
without bound. That is a real gap, so it is worth setting the limit above the
responses you actually care about rather than leaving a 2 MB error page
unexamined. Proxied bodies are buffered up to the limit and then forwarded
unchanged — verified byte-for-byte on a 400 KB response, both under and over
the limit. A `Connection: upgrade` tunnel is never inspected: past the upgrade
there is no response body in the HTTP sense.

Verified against CRS 4.7.0 — SQLi, XSS and path traversal blocked on the way
in, and a backend leaking `SQL syntax error` blocked on the way out, with
benign traffic untouched in both directions.

One implementation note that is easy to be bitten by: libmodsecurity's rule
parser is a non-reentrant flex scanner, and two threads calling it at once
abort the process outright. Configuration load is single-threaded so this is
not reachable in practice, but the lock is there rather than resting on that.

### What it costs

Measured on the Linux box, 1 KiB file, two workers pinned to cores 0–1 with the
load generator on 2–5, median of 5 rounds. Reproduce with
[`bench/modsec-cost.sh`](bench/modsec-cost.sh).

| Configuration | req/s | CPU µs/req | vs plain |
|---|---:|---:|---:|
| plain (default build) | 386,107 | 5.18 | — |
| built with the feature, no rules | 367,844 | 5.44 | within noise |
| two hand-written rules | 89,877 | 22.25 | **−77%** |
| OWASP CRS 4.7.0 | 7,001 | 285.65 | **−98.2%** |
| CRS + response body | 6,581 | 303.91 | **−98.3%** |

The percentage is the wrong number to carry away, because it is a statement
about how fast the baseline is: a request that took 5.18 µs now takes 285 µs.
The transferable figure is the **~280 µs of CPU that CRS costs per request**,
which is the price of evaluating several hundred rules and is paid by anything
running them. The fixed cost of the engine itself — opening a transaction and
running the phases with almost no rules loaded — is **~17 µs**; the remaining
~263 µs is CRS. Phase 4 adds ~18 µs on a 1 KiB body.

So: turning this on trades roughly 55× of static-file throughput for the rule
set. That is worth it exactly when a WAF is worth it, and it is a good reason
to scope `modsecurity on` to the locations that need it rather than the whole
`http` block — that is the one lever with real leverage, because a location
without it pays nothing at all.

### Where the fixed ~17 µs goes

Broken down with `cargo test --release --features modsecurity transaction_cost
-- --ignored --nocapture`, which times each stage against an engine with no
rules loaded:

| Stage | Cumulative |
|---|---:|
| `msc_new_transaction` + cleanup, zero rules | ~10 µs |
| + connection, URI, 5 headers | ~15 µs |
| + all five phases | ~17 µs |

**About 60% of the fixed cost is creating and destroying the transaction**,
before a single rule exists to evaluate. That happens entirely inside
libmodsecurity — its constructor generates a unique id and initialises the
collections every phase writes into — and there is no pooling or reset in the
C API to avoid it.

The calling side was made allocation-free anyway: addresses format into stack
buffers, the method and HTTP version are `c""` constants rather than a fresh
`CString` per request, and the URI is assembled in a per-worker buffer. That is
about eight heap allocations per request removed, and it changed throughput by
**nothing measurable** — 89,877 → 90,232 req/s, inside the run-to-run spread.
It is recorded here because "we removed the allocations and it did not help" is
the useful result: the floor is the engine's, not the integration's.

Two things the harness does deliberately, because getting them wrong quietly
inflates the cost. It sends browser-like headers: `wrk`'s bare request has no
`Accept` or `User-Agent` and a numeric `Host`, which trips CRS 920300, 920320
and 920350 on *every* request and would measure the logging path instead of
the inspection path. And it checks for non-2xx responses, since a run where
CRS blocked the fixture is not the question being asked.

## Benchmarks

```console
$ bench/run.sh 10 128
```

The harness runs both servers with matched settings — same worker count, same
keepalive, access logging off on both, page cache warmed before each
measurement — across four payload sizes chosen to exercise different paths.
It requires `nginx` and one of `wrk` / `oha` / `bombardier`.

### nginx 1.28.3, Ubuntu on 6 cores

Two workers each, pinned to cores 0–1 (verified per thread — nginx forks
worker processes, OxiServe runs worker threads, so a process count would have
compared 3 against 1). The load generator gets cores 2–5 so it is never
competing with either server; during a run the server cores sit at ~0% idle
and the generator at ~6%, which is what makes the server the thing being
measured. `sendfile on`, `gzip off`, `reuseport` and identical keepalive
settings on both. Warmup runs discarded.

Median of 5 rounds, alternating which server runs first. Reproduce with
`bench/nginx-compare.sh`, which prints the worker pinning it verified before
measuring anything.

Median of 5 rounds, alternating which server runs first. Reproduce with
`bench/nginx-compare.sh`, which prints the worker pinning it verified before
measuring anything.

Median of 5 rounds, alternating which server runs first. Reproduce with
`bench/nginx-compare.sh`, which prints the worker pinning it verified before
measuring anything.

| Scenario | nginx | OxiServe | |
|---|---:|---:|---|
| HTTPS/1.1, keepalive, 100 B | 249,262 rps | **363,975 rps** | **1.46×** |
| HTTP/2 over TLS (100 conns × 32 streams) | 296,122 rps | **408,493 rps** | **1.38×** |
| HTTP/1.1, keepalive, 100 B | 296,595 rps | **395,471 rps** | **1.33×** |
| HTTP/1.1, keepalive, 10 KB | 294,015 rps | **334,101 rps** | **1.14×** |
| HTTP/1.1, keepalive, 1 MB | 27,942 rps | 28,532 rps | 1.02× |
| HTTP/1.1, new connection per request | 177,955 rps | 177,891 rps | 1.00× |

No scenario remains where nginx is ahead. The last row was the stubborn one
and its story is [ADR-0003]: with worker *threads* it measured 0.93× and no
syscall-level fix moved it — not even driving our syscall count 19% below
nginx's. The attribution experiment was three arrangements of the same binary:
one worker thread scored 1.03×, two worker threads 0.93×, and two single-worker
*processes* 1.00×. The whole loss was contention on state threads share and
processes do not. So `worker_processes N` now means what it says — N forked
worker processes under a supervising master, as nginx runs — and the churn row
reads dead even — across three assertion-guarded runs the medians were
1.002×, 1.002× and 1.000×, the sign flipping inside a ±0.2% band. Moving to processes also lifted every other row: 10 KB, which
was bandwidth-tied at 1.03×, opened to 1.11×.

Process mode forced one piece of real shared-memory engineering: `limit_req`
and `limit_conn` zones live in a `MAP_SHARED` mapping created before the fork
— a fixed-size open-addressing table of atomics, no allocator in shared memory
— because per-process state would silently multiply every configured limit by
the worker count. Tests drive the real binary across both workers and assert
exactly one admitted request, at `1r/m` for the rate and at `limit_conn 1` for
the concurrency count. `limit_conn` is the stricter of the two: a count has to
be incremented and decremented in the same table to stay balanced, so its
slots are a single atomic word each and every transition — claim, increment,
take over, release — is one compare-and-swap. A worker that dies is respawned by
the master, and `PR_SET_PDEATHSIG` means even a SIGKILLed master cannot leave
orphans holding the port.

[ADR-0003]: docs/decisions/0003-worker-processes.md

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

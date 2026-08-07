# ADR 0004 — HTTP/3: what we write and what we delegate

**Status:** Accepted — shipped in v0.2.30.
**Date:** 2026-08-07
**Related:** README "Implemented"; `src/http3/`; `src/server/quic.rs`;
[ADR-0003](0003-worker-processes.md) for the worker model this has to fit.

## Context

Every other protocol in this server is hand-written: the HTTP/1 parser, the
HTTP/2 framing with its own HPACK and Huffman, the FastCGI record layer, the
MessagePack encoder for the OxiDB log sink. The default answer to "should we
write this ourselves" has been yes, and it has been the right answer, because
each of those is a few hundred to a few thousand lines of pure format work
whose correctness is fully determined by a specification and a test suite.

QUIC is not that. HTTP/3 is four specifications, and only one of them is
format work:

| | What it is | Ours? |
|---|---|---|
| RFC 9000 | QUIC transport: packets, streams, connection IDs, migration, path validation, anti-amplification | no |
| RFC 9001 | QUIC-TLS: packet protection, header protection, key derivation and update | no |
| RFC 9002 | Loss detection and congestion control | no |
| RFC 9114 | HTTP/3 framing over QUIC | **yes** |
| RFC 9204 | QPACK field compression | **yes** |

The first three differ from everything else we have written in two ways that
matter. First, a mistake is an exploit rather than a bug: getting the
anti-amplification limit wrong makes the server a DDoS reflector, and getting
header protection wrong leaks packet numbers. Second, congestion control is not
a correctness problem with a right answer but a performance problem with a
decade of tuning behind it — a naive NewReno would make HTTP/3 measurably worse
than the HTTP/2 it is supposed to improve on, and we would have shipped a
feature that is a downgrade.

They also differ in a third way that is decisive for *this* project: they have
no nginx-compatibility surface. The whole reason to hand-write HPACK was that
it sits between an `nginx.conf` and the wire, and how it behaves is something a
config can observe. No directive can tell one conformant congestion controller
from another.

## Decision

**Delegate RFC 9000/9001/9002 to quinn. Write RFC 9114 and RFC 9204 ourselves.**

quinn is the mature Rust QUIC implementation, it is already built on rustls,
and rustls is already a dependency — the crypto provider unifies on `ring` and
the version resolves to the same rustls 0.23 the TCP path uses. Cost measured
rather than guessed: **44 → 60 crates compiled for the host.** The lockfile
grows by 32 entries, but half of those are `wasm-bindgen` and friends that are
target-gated and never built.

The `h3` crate was considered for the HTTP/3 layer and rejected. It is 0.0.x
with breaking changes between minor releases, and the layer it provides is
precisely the layer that is ours to own: framing and field compression, sitting
directly between the config and the wire. Taking quinn's transport and writing
our own framing puts the boundary exactly where the reasoning above puts it.

### QPACK has no dynamic table, deliberately

`SETTINGS_QPACK_MAX_TABLE_CAPACITY` is 0. This is a conformant configuration,
not a shortcut: RFC 9204 section 3.2.2 forbids a peer from sending an insertion
once it has been given a capacity of zero, so a legal client cannot produce a
field section we would fail to decode.

What it removes is the entire reason QPACK is larger than HPACK — blocked-stream
accounting, Required Insert Count, section acknowledgements, and a
deadlock-avoidance story for all of it, all of which exist only because QUIC can
deliver streams out of order. What it costs is compression on repeated request
headers, with the 99-entry static table still covering the common ones.

This is the same trade `http2::hpack::Encoder` already makes in the other
direction and for the same stated reason: the two ends disagreeing about table
state is a class of bug that not having a table cannot have.

### Connection migration is a known gap

QUIC listeners are always bound per worker with `SO_REUSEPORT`, whether or not
the `listen` line asked for it. That is structural: a QUIC connection is a run
of datagrams that must all reach the same state machine, and one shared UDP
socket read by every worker would hand consecutive packets to workers that
cannot decrypt them.

The kernel's reuseport hash is over the 4-tuple, so **a client that migrates —
a phone moving from Wi-Fi to cellular, a NAT rebinding — lands on a worker that
has never seen its connection ID, and the connection is lost rather than
migrated.** The client recovers by opening a new one, so it costs a round trip
and not a request.

nginx has exactly this limitation and solves it by encoding the worker into the
connection ID and installing an eBPF `SO_REUSEPORT` program to steer on it.
That is Linux-only and a separate piece of work. It is documented here and in
`src/server/quic.rs` rather than left to be discovered.

## Consequences

- **HTTP/3 is a transport swap, as HTTP/2 was.** A decoded request becomes the
  same `Req` the HTTP/1 parser produces and goes through the same
  `handler::handle`, so `proxy_pass`, `proxy_cache`, `limit_req`, `limit_conn`,
  FastCGI, `try_files`, `error_page` and every variable work unchanged. There
  is a test asserting `limit_req` rejects over h3, because the claim is worth
  an assertion rather than a paragraph.
- **`src/http3/conn.rs` is a third the size of `src/http2/conn.rs`** — 519 lines
  against 1,357 — and the difference is almost entirely concurrency that QUIC
  now provides: stream state machines, two levels of flow-control window,
  CONTINUATION reassembly, and a writer task owning the socket. A request is one
  bidirectional stream, so it is one straight-line async task.
- **`sendfile` cannot apply**, exactly as it cannot for HTTP/2: every byte must
  be wrapped in a DATA frame and then encrypted into QUIC packets. HTTP/3 will
  not move the static-hot-path benchmark, and is not meant to.
- **The first TLS tests in the repository exist now**, because QUIC forced them
  — there is no cleartext HTTP/3 to test with. Certificates are generated per
  run with `rcgen` as a dev-dependency rather than committed, so nothing in the
  repository can expire.
- **A real bug was found on the way in.** `listen ... quic` had been sharing the
  `http2` arm since the listener parser was written, so `listen 443 quic;`
  silently switched the *TCP* listener to HTTP/2 and opened no UDP socket at
  all. The README described it as "parsed and ignored"; it was neither.
- **A second, unrelated bug surfaced.** Two workers logging the same line at
  the same instant during QUIC startup produced one merged record: the
  unbuffered log path wrote the line and its newline as two separate
  `write_all` calls, and forked workers append to the same file. Now one write.
  Pre-existing and not specific to QUIC — it affected every unbuffered log
  line in process mode — but it took two workers announcing a listener
  simultaneously to make it visible.
- **0-RTT is not offered.** `max_early_data_size` is 0. Early data is replayable
  by definition, and deciding which requests may accept a replay is a policy
  question with a config surface (nginx has `ssl_early_data`), not a default to
  slip in with the transport.

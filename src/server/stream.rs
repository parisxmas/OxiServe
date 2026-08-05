//! The `stream` block: layer 4 TCP proxying.
//!
//! No HTTP is parsed here. A connection is accepted, an upstream is chosen,
//! and bytes are copied in both directions until one side closes or goes
//! quiet. That makes it usable in front of anything with a TCP protocol —
//! PostgreSQL, Redis, MQTT, an SMTP server — which is HAProxy's core
//! competence and item 5 of [ADR-0001].
//!
//! Upstream selection, passive health tracking and `least_conn` are the same
//! code the HTTP proxy uses. A dead backend is dead the same way whether the
//! bytes above TCP are HTTP or not.
//!
//! With `ssl_preread on`, the first bytes are inspected before a backend is
//! chosen so `proxy_pass` can route on the TLS SNI — see [`super::preread`].
//! Inspected, never consumed: every byte read is forwarded, so the backend
//! terminates TLS against a handshake we did not touch.
//!
//! [ADR-0001]: ../../docs/decisions/0001-load-balancer-scope.md

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::preread::{self, Hello, Preread};
use super::transport::Stream;
use super::upstream::{self as up_state, InFlightGuard};
use crate::config::model::{ProxyTarget, StreamConf, StreamServer, Upstream};
use crate::config::vars::{Var, VarSource};

/// Copy buffer per direction. Large enough that a bulk transfer is not
/// syscall-bound, small enough that thousands of idle connections do not cost
/// much — the same trade as `output_buffers` on the HTTP side.
const BUF: usize = 32 * 1024;

/// Handles one accepted connection start to finish.
pub async fn serve(
    mut client: Stream,
    srv: Arc<StreamServer>,
    conf: Arc<StreamConf>,
    remote: Option<SocketAddr>,
) {
    // ---- look, do not consume --------------------------------------------
    // Whatever this reads stays in `head` and is written to the backend before
    // anything else, so the peer sees the stream exactly as the client sent
    // it. A failed or disabled preread is not an error: it just means the
    // variables are empty and routing falls back to the map default.
    let mut head = Vec::new();
    let hello = if srv.ssl_preread {
        read_client_hello(&mut client, &mut head, &srv).await
    } else {
        None
    };

    let vars = StreamVars { conf: &conf, remote, hello: hello.as_ref() };

    // ---- pick a peer ------------------------------------------------------
    let (addr, health) = match &srv.target {
        ProxyTarget::Addr { host, port } => (format!("{host}:{port}"), None),
        ProxyTarget::Unix(p) => (format!("unix:{p}"), None),
        ProxyTarget::Upstream(name) => match pick(&conf, name) {
            Some(v) => v,
            None => return,
        },
        // `proxy_pass $backend;` — the usual shape once ssl_preread is on.
        ProxyTarget::Dynamic(t) => {
            let rendered = t.render(&vars);
            let rendered = rendered.trim();
            // An unmatched map with no default renders to nothing. Closing is
            // the honest outcome: there is no backend, and picking an
            // arbitrary one would send a client's TLS session to a service it
            // never asked for.
            if rendered.is_empty() {
                return;
            }
            match conf.upstreams.get(rendered) {
                Some(_) => match pick(&conf, rendered) {
                    Some(v) => v,
                    None => return,
                },
                // Not a group name, so it is an address.
                None => (peer_addr(rendered), None),
            }
        }
    };

    let _in_flight = health
        .as_ref()
        .map(|(up, i)| InFlightGuard::enter(&up.health[*i]));

    // ---- connect ----------------------------------------------------------
    let upstream = match tokio::time::timeout(srv.connect_timeout, Stream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            // Nothing to answer with at layer 4: the client simply sees the
            // connection close. The failure still counts against the peer.
            if let Some((up, i)) = &health {
                let now_ms = Instant::now()
                    .saturating_duration_since(up.origin)
                    .as_millis() as u64;
                let s = &up.servers[*i];
                up.health[*i].record_failure(
                    now_ms,
                    s.max_fails,
                    s.fail_timeout.as_millis() as u64,
                );
            }
            return;
        }
    };

    // Connecting is not yet proof of health at layer 4: a crashed backend
    // often still accepts and then closes. Health is decided by what the
    // exchange produced.
    let (sent, received) = pump(client, upstream, srv.timeout, head).await;

    if let Some((up, i)) = &health {
        if sent > 0 && received == 0 {
            // The client spoke and the peer said nothing before closing. A
            // healthy backend answers; this one is broken.
            let now_ms = Instant::now()
                .saturating_duration_since(up.origin)
                .as_millis() as u64;
            let s = &up.servers[*i];
            up.health[*i].record_failure(
                now_ms,
                s.max_fails,
                s.fail_timeout.as_millis() as u64,
            );
        } else {
            // Either it answered, or the client never asked anything — the
            // latter is not the peer's fault, so it is not held against it.
            up.health[*i].record_success();
        }
    }
}

/// Copies bytes both ways until either side finishes or stalls.
///
/// `proxy_timeout` is an **idle** timeout: it bounds the gap between reads,
/// not the life of the connection. Wrapping the whole copy in one timeout
/// would have been far simpler and would have severed every long-lived
/// session — exactly the connections a stream proxy exists to carry.
async fn pump(client: Stream, upstream: Stream, idle: Duration, head: Vec<u8>) -> (u64, u64) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = async {
        let mut total = 0u64;
        // Anything preread belongs to the client's stream and has to lead.
        // Dropping it would hand the backend a TLS handshake missing its
        // ClientHello, and the connection would fail in a way that looks like
        // a backend fault.
        if !head.is_empty() {
            if uw.write_all(&head).await.is_err() {
                let _ = uw.shutdown().await;
                return 0;
            }
            total += head.len() as u64;
        }
        let mut buf = vec![0u8; BUF];
        loop {
            let n = match tokio::time::timeout(idle, cr.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break,
            };
            if uw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        // Half-close: tell the upstream the client is done sending, so a
        // protocol that answers on EOF still gets its chance.
        let _ = uw.shutdown().await;
        total
    };

    let u2c = async {
        let mut total = 0u64;
        let mut buf = vec![0u8; BUF];
        loop {
            let n = match tokio::time::timeout(idle, ur.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break,
            };
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        let _ = cw.shutdown().await;
        total
    };

    // Both directions run concurrently; the connection is done when both have
    // finished. Stopping at the first would truncate a reply still in flight.
    tokio::join!(c2u, u2c)
}

/// Chooses a live peer from a named upstream group.
fn pick(conf: &StreamConf, name: &str) -> Option<(String, Option<(Arc<Upstream>, usize)>)> {
    let up = conf.upstreams.get(name)?;
    // No request context at layer 4, so `ip_hash` has no key and the cursor
    // drives selection.
    let cursor = next_cursor(up);
    let idx = up_state::select(up, Instant::now(), None, cursor)?;
    Some((peer_addr(&up.servers[idx].addr), Some((up.clone(), idx))))
}

/// Reads until the client's TLS ClientHello is complete, or until it is clear
/// none is coming.
///
/// Everything read lands in `head` **whatever the outcome**, because those
/// bytes belong to the client's stream and are forwarded verbatim. Returning
/// `None` costs the connection nothing: it is proxied as before, with the
/// preread variables empty.
async fn read_client_hello(
    client: &mut Stream,
    head: &mut Vec<u8>,
    srv: &StreamServer,
) -> Option<Hello> {
    let deadline = Instant::now() + srv.preread_timeout;
    let mut chunk = [0u8; 4096];

    loop {
        match preread::parse(head) {
            Preread::Hello(h) => return Some(h),
            // Not TLS, or malformed beyond repair. Either way no further byte
            // would change the answer, so waiting would burn the timeout for
            // nothing — and for a protocol where the server speaks first, it
            // would deadlock the connection outright.
            Preread::NotTls => return None,
            Preread::Incomplete => {}
        }
        // The cap is what stops a client that dribbles bytes forever from
        // growing this buffer without bound.
        let want = srv.preread_buffer_size.saturating_sub(head.len()).min(chunk.len());
        if want == 0 {
            return None;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let n = match tokio::time::timeout(left, client.read(&mut chunk[..want])).await {
            Ok(Ok(0)) => return None, // client closed before finishing
            Ok(Ok(n)) => n,
            // A slow client is not a wrong client: proxy it with empty
            // variables rather than dropping the connection.
            Ok(Err(_)) | Err(_) => return None,
        };
        head.extend_from_slice(&chunk[..n]);
    }
}

/// Resolves variables for a `stream` connection.
///
/// A much smaller world than the HTTP one: there is no request, so the only
/// facts available are the peer address and whatever the TLS ClientHello
/// disclosed. Anything else renders empty, which is what nginx does too.
struct StreamVars<'a> {
    conf: &'a StreamConf,
    remote: Option<SocketAddr>,
    hello: Option<&'a Hello>,
}

impl StreamVars<'_> {
    fn var_depth(&self, v: &Var, out: &mut String, depth: u32) {
        match v {
            Var::SslPrereadServerName => {
                if let Some(h) = self.hello {
                    out.push_str(&h.server_name);
                }
            }
            Var::SslPrereadAlpnProtocols => {
                if let Some(h) = self.hello {
                    out.push_str(&h.alpn_list());
                }
            }
            Var::SslPrereadProtocol => {
                if let Some(h) = self.hello {
                    out.push_str(h.protocol);
                }
            }
            Var::RemoteAddr | Var::BinaryRemoteAddr => {
                if let Some(a) = self.remote {
                    out.push_str(&a.ip().to_string());
                }
            }
            Var::RemotePort => {
                if let Some(a) = self.remote {
                    out.push_str(&a.port().to_string());
                }
            }
            Var::User(name) => self.user_var(name, out, depth),
            _ => {}
        }
    }

    /// Resolves a `map`-defined variable against the `stream` block's own
    /// maps. HTTP maps are deliberately not consulted: they key off request
    /// variables that do not exist here, so every one of them would match its
    /// default and quietly route traffic somewhere arbitrary.
    fn user_var(&self, name: &str, out: &mut String, depth: u32) {
        if depth > 8 {
            return; // a map cycle; the HTTP side caps recursion the same way
        }
        let Some(m) = self.conf.maps.iter().find(|m| &*m.target == name) else {
            return;
        };
        let mut key = String::new();
        self.var_depth(&m.source, &mut key, depth + 1);
        if let Some(t) = crate::server::ctx::map_lookup(m, &key) {
            t.render_into(&Depth { vars: self, depth: depth + 1 }, out);
        }
    }
}

impl VarSource for StreamVars<'_> {
    fn var(&self, v: &Var, out: &mut String) {
        self.var_depth(v, out, 0);
    }
}

struct Depth<'a> {
    vars: &'a StreamVars<'a>,
    depth: u32,
}

impl VarSource for Depth<'_> {
    fn var(&self, v: &Var, out: &mut String) {
        self.vars.var_depth(v, out, self.depth);
    }
}

/// Round-robin cursor per upstream, per worker — the same approach the HTTP
/// proxy takes.
fn next_cursor(up: &Arc<crate::config::model::Upstream>) -> usize {
    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static RR: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
    }
    RR.with(|rr| {
        let mut m = rr.borrow_mut();
        let c = m.entry(Arc::as_ptr(up) as usize).or_insert(0);
        let i = *c;
        *c = c.wrapping_add(1);
        i
    })
}

fn peer_addr(addr: &str) -> String {
    if addr.starts_with("unix:") || addr.contains(':') {
        addr.to_string()
    } else {
        // A stream upstream without a port is a config mistake, but guessing
        // 80 is friendlier than failing to connect with no explanation.
        format!("{addr}:80")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_addresses_are_normalised() {
        assert_eq!(peer_addr("10.0.0.1:3306"), "10.0.0.1:3306");
        assert_eq!(peer_addr("unix:/run/db.sock"), "unix:/run/db.sock");
        assert_eq!(peer_addr("[::1]:5432"), "[::1]:5432");
    }
}

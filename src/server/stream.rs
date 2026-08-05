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
//! [ADR-0001]: ../../docs/decisions/0001-load-balancer-scope.md

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::transport::Stream;
use super::upstream::{self as up_state, InFlightGuard};
use crate::config::model::{ProxyTarget, StreamConf, StreamServer};

/// Copy buffer per direction. Large enough that a bulk transfer is not
/// syscall-bound, small enough that thousands of idle connections do not cost
/// much — the same trade as `output_buffers` on the HTTP side.
const BUF: usize = 32 * 1024;

/// Handles one accepted connection start to finish.
pub async fn serve(client: Stream, srv: Arc<StreamServer>, conf: Arc<StreamConf>) {
    // ---- pick a peer ------------------------------------------------------
    let (addr, health) = match &srv.target {
        ProxyTarget::Addr { host, port } => (format!("{host}:{port}"), None),
        ProxyTarget::Unix(p) => (format!("unix:{p}"), None),
        ProxyTarget::Upstream(name) => {
            let Some(up) = conf.upstreams.get(&**name) else {
                return; // config load rejects this; unreachable in practice
            };
            // No request context at layer 4, so `ip_hash` has no key and the
            // cursor drives selection.
            let cursor = next_cursor(up);
            let Some(idx) = up_state::select(up, Instant::now(), None, cursor) else {
                return;
            };
            (peer_addr(&up.servers[idx].addr), Some((up.clone(), idx)))
        }
        // A variable target needs a request to render against; there is none.
        ProxyTarget::Dynamic(_) => return,
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
    let (sent, received) = pump(client, upstream, srv.timeout).await;

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
async fn pump(client: Stream, upstream: Stream, idle: Duration) -> (u64, u64) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = async {
        let mut total = 0u64;
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

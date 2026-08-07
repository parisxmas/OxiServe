//! UDP proxying for the `stream` block.
//!
//! # What a "session" is when there are no connections
//!
//! TCP hands the proxy a connection, and the connection *is* the session: it
//! begins, it carries bytes, it ends, and the kernel says when. UDP has none
//! of that. All that arrives is a datagram with a source address, so a session
//! has to be invented: the first datagram from an address starts one, later
//! datagrams from the same address join it, and it ends on a timer or on a
//! count of replies. nginx does exactly this, and `proxy_timeout` and
//! `proxy_responses` are the two knobs that decide when.
//!
//! # Why each session owns its socket
//!
//! A session gets its own upstream socket, `connect`ed to the chosen peer.
//! That is what makes replies attributable: a single shared socket would
//! receive every backend's datagrams into one queue with only the source
//! address to tell them apart, which fails the moment two peers share an
//! address family and a client talks to both. A connected socket also lets
//! the kernel drop datagrams from anywhere else, which is a small piece of
//! spoofing resistance for free.
//!
//! # Thread-per-core
//!
//! Bound per worker with `SO_REUSEPORT`, like the QUIC listener. The kernel
//! hashes the client's 4-tuple, so every datagram of one session lands on the
//! worker holding it — and unlike QUIC there is no connection ID to migrate,
//! so a client that changes address simply starts a new session, which is the
//! correct outcome rather than a limitation.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::model::{ListenAddr, StreamConf, StreamListener, StreamServer};
use super::upstream::InFlightGuard;

/// The largest datagram we will accept. A UDP payload cannot exceed this, so
/// a buffer this size can never truncate one — and truncation is silent and
/// unrecoverable, unlike a short read on a stream.
const MAX_DATAGRAM: usize = 65_535;

/// Binds this worker's UDP socket for `l`.
pub fn bind(l: &StreamListener) -> io::Result<std::net::UdpSocket> {
    let addr = match &l.addr {
        ListenAddr::Tcp(a) => *a,
        ListenAddr::Unix(p) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("udp cannot listen on unix:{p}"),
            ))
        }
    };
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    if addr.is_ipv6() {
        let _ = sock.set_only_v6(l.ipv6_only);
    }
    // Every worker needs its own queue, or one of them would take every
    // datagram and the rest would idle.
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind to udp {addr} failed: {e}")))?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// One live client, and the channel its datagrams go down.
struct Session {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Reads datagrams for as long as the worker runs, fanning them into sessions.
pub async fn serve(sock: std::net::UdpSocket, conf: Arc<StreamConf>, srv: Arc<StreamServer>) {
    let Ok(sock) = UdpSocket::from_std(sock) else { return };
    let sock = Rc::new(sock);
    let sessions: Rc<RefCell<HashMap<SocketAddr, Session>>> =
        Rc::new(RefCell::new(HashMap::new()));

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, client) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // On some platforms an ICMP "port unreachable" for an earlier
            // datagram surfaces as an error on the *listening* socket. It says
            // nothing about this socket's health, so it must not end the loop.
            Err(_) => continue,
        };
        let payload = buf[..n].to_vec();

        // An existing session takes it; a dead one is replaced rather than
        // resurrected, since its upstream socket is already gone.
        let existing = sessions
            .borrow()
            .get(&client)
            .map(|s| s.tx.clone());
        if let Some(tx) = existing {
            if tx.send(payload.clone()).is_ok() {
                continue;
            }
            sessions.borrow_mut().remove(&client);
        }

        let (tx, rx) = mpsc::unbounded_channel();
        if tx.send(payload).is_err() {
            continue;
        }
        sessions.borrow_mut().insert(client, Session { tx });

        let (conf, srv) = (conf.clone(), srv.clone());
        let (sock, sessions) = (sock.clone(), sessions.clone());
        tokio::task::spawn_local(async move {
            session(rx, client, sock, conf, srv).await;
            // Self-removal, so the map never holds a session whose task has
            // exited and whose channel would silently swallow datagrams.
            sessions.borrow_mut().remove(&client);
        });
    }
}

/// One client's worth of proxying, until it goes quiet or the replies run out.
async fn session(
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    client: SocketAddr,
    listen_sock: Rc<UdpSocket>,
    conf: Arc<StreamConf>,
    srv: Arc<StreamServer>,
) {
    let Some((addr, health)) = super::stream::resolve_target(&conf, &srv, Some(client), None)
    else {
        return;
    };
    let _in_flight = health.as_ref().map(|(up, i)| InFlightGuard::enter(&up.health[*i]));

    // Resolve first so the local socket is bound in the peer's address family;
    // binding v4 and connecting to a v6 peer fails, and the reverse wastes a
    // dual-stack socket.
    let Ok(mut addrs) = tokio::net::lookup_host(&addr).await else {
        record(&health, false);
        return;
    };
    let Some(peer) = addrs.next() else {
        record(&health, false);
        return;
    };
    // A socket per session, connected to the peer: replies are then
    // unambiguous, and the kernel drops datagrams from anywhere else, which is
    // a little spoofing resistance for free.
    let bind_addr = if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let Ok(up_sock) = UdpSocket::bind(bind_addr).await else { return };
    if up_sock.connect(peer).await.is_err() {
        record(&health, false);
        return;
    }

    let mut responses = 0u64;
    let mut sent_any = false;
    let mut reply_buf = vec![0u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            // A datagram from the client, forwarded upstream.
            got = rx.recv() => {
                let Some(payload) = got else { break };
                if up_sock.send(&payload).await.is_err() {
                    record(&health, false);
                    return;
                }
                sent_any = true;
            }

            // A reply, sent back to the client from the listening socket, so
            // it appears to come from the address the client wrote to.
            got = up_sock.recv(&mut reply_buf) => {
                let Ok(n) = got else {
                    // ICMP port-unreachable arrives here on a connected
                    // socket: the backend is not listening.
                    record(&health, false);
                    return;
                };
                if listen_sock.send_to(&reply_buf[..n], client).await.is_err() {
                    return;
                }
                responses += 1;
                record(&health, true);
                // `proxy_responses N` — the exchange is complete, so the
                // session ends now instead of holding a socket open for the
                // whole idle timeout.
                if srv.proxy_responses.is_some_and(|want| responses >= want) {
                    return;
                }
            }

            // `proxy_timeout` as an idle timeout: it bounds the gap between
            // datagrams, not the life of the session, so a long-lived but
            // busy flow is never cut off.
            _ = tokio::time::sleep(srv.timeout) => {
                // Silence after we forwarded something and heard nothing is
                // the backend failing to answer.
                if sent_any && responses == 0 && srv.proxy_responses != Some(0) {
                    record(&health, false);
                }
                return;
            }
        }
    }
}

/// Records the outcome against the peer's shared health, if there is one.
fn record(health: &Option<(Arc<crate::config::model::Upstream>, usize)>, ok: bool) {
    let Some((up, i)) = health else { return };
    if ok {
        up.health[*i].record_success();
        return;
    }
    let now_ms = Instant::now().saturating_duration_since(up.origin).as_millis() as u64;
    let s = &up.servers[*i];
    up.health[*i].record_failure(now_ms, s.max_fails, s.fail_timeout.as_millis() as u64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_buffer_cannot_truncate_a_legal_payload() {
        // 65535 is the ceiling a UDP length field can express, so a buffer of
        // that size always receives a whole datagram. Truncation here would be
        // silent: `recv_from` reports the truncated length, not the real one.
        assert_eq!(MAX_DATAGRAM, u16::MAX as usize);
    }
}

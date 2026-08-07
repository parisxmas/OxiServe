//! The QUIC listener: UDP sockets, the quinn endpoint, and the accept loop.
//!
//! # What is delegated and what is not
//!
//! Everything below the HTTP/3 framing is quinn's: packet protection and
//! header protection, the TLS 1.3 handshake carried in CRYPTO frames, loss
//! detection and congestion control (RFC 9002), stream flow control,
//! connection IDs, path validation and the anti-amplification limit. Those are
//! the parts where a subtle mistake is an exploit rather than a bug, and they
//! are also the parts with no nginx-compatibility surface — a config file
//! cannot tell them apart from anyone else's.
//!
//! Everything above is ours: [`crate::http3`] does the framing, QPACK, and the
//! translation into the same `Req` the HTTP/1 parser produces.
//!
//! # Thread-per-core and connection migration
//!
//! QUIC listeners are always bound per worker with `SO_REUSEPORT`, whether or
//! not the `listen` line asked for it. This is structural rather than a
//! performance choice: a QUIC connection is a run of datagrams that must all
//! reach the same state machine, and one shared UDP socket read by every
//! worker would hand consecutive packets of one connection to different
//! workers, none of which could decrypt them.
//!
//! The kernel's reuseport hash is over the 4-tuple, so it holds a connection
//! to one worker only for as long as the client's address does not change.
//! **A client that migrates — a phone moving from Wi-Fi to cellular, or a NAT
//! rebinding — will land on a worker that has never seen its connection ID,
//! and the connection is lost rather than migrated.** The client recovers by
//! opening a new one, so this costs a round trip and not a request.
//!
//! Fixing it properly means steering by connection ID rather than by 4-tuple:
//! nginx encodes the worker into the CID and installs an eBPF `SO_REUSEPORT`
//! program to route on it, and has the same limitation without one. That is a
//! Linux-only mechanism and a separate piece of work; until it exists, this is
//! a documented gap and not a silent one.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::model::{Http, Listener, ListenAddr, LogLevel};
use super::log::Logs;

/// ALPN for HTTP/3, RFC 9114 section 3.1. Unlike HTTP/2 there is no cleartext
/// or upgrade path at all: a QUIC connection that does not negotiate `h3` has
/// nothing to fall back to.
pub const ALPN_H3: &[u8] = b"h3";

/// Binds this worker's UDP socket for `l`.
pub fn bind(l: &Listener) -> io::Result<std::net::UdpSocket> {
    let addr = match &l.addr {
        ListenAddr::Tcp(a) => *a,
        // Rejected at config load; unreachable, and cheaper to state than to
        // encode in the type.
        ListenAddr::Unix(p) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("QUIC cannot listen on unix:{p}"),
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
    if let Some(n) = l.rcvbuf {
        let _ = sock.set_recv_buffer_size(n);
    }
    if let Some(n) = l.sndbuf {
        let _ = sock.set_send_buffer_size(n);
    }
    // Not conditional on `l.reuseport`: see the module docs. Without it every
    // worker would read from one queue and no connection would survive.
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    sock.set_reuse_port(true)?;

    sock.bind(&addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind to udp {addr} failed: {e}")))?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

/// Builds one quinn server config per QUIC listener, or `None` where the
/// listener has no usable certificate.
///
/// Shares [`super::SniResolver`] with the TCP side, so a certificate is
/// configured once and both transports resolve it the same way.
pub fn build_configs(http: &Http) -> io::Result<Vec<Option<Arc<quinn::ServerConfig>>>> {
    let mut out = Vec::with_capacity(http.quic_listeners.len());
    for l in &http.quic_listeners {
        let Some(resolver) = super::sni_resolver_for(l)? else {
            out.push(None);
            continue;
        };

        // TLS 1.3 only. QUIC has no TLS 1.2 mode — RFC 9001 section 4.2 makes
        // that a connection error — so the config the TCP side builds, which
        // offers 1.2 for compatibility, cannot be reused here.
        let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        tls.max_early_data_size = 0; // 0-RTT is deliberately not offered yet

        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("quic tls: {e}")))?;
        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        let transport = Arc::get_mut(&mut cfg.transport)
            .expect("freshly built config is unshared");
        // One request is one bidirectional stream, so this is the HTTP/3
        // equivalent of `http2_max_concurrent_streams`.
        transport.max_concurrent_bidi_streams(256u32.into());
        // The peer needs exactly three: control, QPACK encoder, QPACK decoder.
        // Server push is not implemented, so it never needs a fourth.
        transport.max_concurrent_uni_streams(8u32.into());
        let idle = l.servers[l.default_server].core.keepalive_timeout;
        if !idle.is_zero() {
            transport.max_idle_timeout(Some(
                idle.try_into().unwrap_or(quinn::VarInt::MAX.into()),
            ));
        }

        out.push(Some(Arc::new(cfg)));
    }
    Ok(out)
}

/// Accepts QUIC connections until the worker shuts down.
pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    conf: Arc<Listener>,
    http: Arc<Http>,
    logs: Rc<RefCell<Logs>>,
) {
    let local_addr = match &conf.addr {
        ListenAddr::Tcp(a) => Some(*a),
        ListenAddr::Unix(_) => None,
    };

    while let Some(incoming) = endpoint.accept().await {
        let conf = conf.clone();
        let http = http.clone();
        let logs = logs.clone();
        let id = super::CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::task::spawn_local(async move {
            // A failed handshake is routine — scanners, version probes, a
            // client that does not speak h3 — and says nothing worth logging.
            let Ok(conn) = incoming.await else { return };
            let remote = conn.remote_address();
            crate::http3::conn::serve(conn, &conf, &http, &logs, Some(remote), local_addr, id)
                .await;
        });
    }
}

/// Creates the endpoint for one worker and returns it ready to accept.
pub fn endpoint(
    l: &Listener,
    cfg: Arc<quinn::ServerConfig>,
    logs: &Rc<RefCell<Logs>>,
) -> io::Result<quinn::Endpoint> {
    let sock = bind(l)?;
    let ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some((*cfg).clone()),
        sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    logs.borrow_mut()
        .error(LogLevel::Info, &format!("quic listening on {}", l.addr));
    Ok(ep)
}

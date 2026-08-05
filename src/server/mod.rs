//! The data plane: listeners, workers, and connection dispatch.
//!
//! # Why thread-per-core
//!
//! nginx runs one process per core, each with its own accept queue, and shares
//! nothing on the request path. OxiServe does the same with threads: every
//! worker owns a `current_thread` Tokio runtime, its own listening socket
//! (via `SO_REUSEPORT` where the kernel load-balances them), its own log
//! buffers, and its own connection state. A request is accepted, handled and
//! answered on one core, so there is no work stealing, no cross-core wakeup,
//! and no atomics in the steady state.

pub mod autoindex;
pub mod cache;
pub mod conn;
pub mod ctx;
pub mod fastcgi;
pub mod fcache;
pub mod fcgi_proto;
pub mod files;
pub mod handler;
pub mod limit_req;
pub mod log;
pub mod msgpack;
pub mod proxy;
pub mod reply;
pub mod stream;
pub mod transport;
pub mod upstream;

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use crate::config::model::{Config, Http, Listener, LogLevel};
use log::Logs;

/// Connection ids only feed `$connection`, so a relaxed global counter is
/// enough — no ordering guarantees are needed.
static CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Binds every configured listener and runs workers until shutdown.
pub fn run(config: Config) -> io::Result<()> {
    let stream_conf = config.stream.map(Arc::new);
    let http = match config.http {
        Some(h) => Arc::new(h),
        None if stream_conf.is_some() => {
            // A stream-only configuration is legitimate: a pure L4 proxy.
            Arc::new(Http {
                cache_zones: Default::default(),
                limit_req_zones: Default::default(),
                limit_req_keys: Default::default(),
                listeners: Vec::new(),
                upstreams: Default::default(),
                maps: Vec::new(),
                mime: Arc::new(Default::default()),
                servers: Vec::new(),
            })
        }
        None => {
            eprintln!("oxiserve: no http or stream block in configuration, nothing to serve");
            return Ok(());
        }
    };
    let error_log = config.error_log.clone();
    let workers = config.worker_processes.resolve();

    // Sockets are bound before workers start, so a port conflict is reported
    // once, at startup, rather than N times from N threads.
    let mut shared: Vec<Option<BoundSocket>> = Vec::new();
    for l in &http.listeners {
        if cfg!(target_os = "linux") && l.reuseport {
            // Each worker will bind its own socket instead.
            shared.push(None);
        } else {
            shared.push(Some(bind(l)?));
        }
    }

    for (i, l) in http.listeners.iter().enumerate() {
        eprintln!(
            "oxiserve: listening on {}{}{}",
            l.addr,
            if l.ssl { " ssl" } else { "" },
            if shared[i].is_none() { " (reuseport)" } else { "" }
        );
    }

    // Stream listeners bind up front too, so a port clash is one startup error.
    let mut stream_bound: Vec<Option<BoundSocket>> = Vec::new();
    if let Some(sc) = &stream_conf {
        for l in &sc.listeners {
            if cfg!(target_os = "linux") && l.reuseport {
                stream_bound.push(None);
            } else {
                stream_bound.push(Some(bind_stream(l)?));
            }
            eprintln!("oxiserve: stream listening on {}", l.addr);
        }
    }

    let tls = build_tls(&http)?;
    let cores = core_affinity::get_core_ids().unwrap_or_default();
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let http = http.clone();
        let error_log = error_log.clone();
        let tls = tls.clone();
        let core = if cores.is_empty() {
            None
        } else {
            Some(cores[w % cores.len()])
        };

        // Each worker needs its own listener handle. Cloning the descriptor
        // gives every worker an independent accept loop on the same queue.
        let mut listeners: Vec<(Arc<Listener>, Option<BoundSocket>)> = Vec::new();
        for (i, l) in http.listeners.iter().enumerate() {
            let sock = match &shared[i] {
                Some(s) => Some(s.try_clone()?),
                None => None,
            };
            listeners.push((l.clone(), sock));
        }

        let stream_conf_w = stream_conf.clone();
        let mut stream_listeners: Vec<(Arc<crate::config::model::StreamListener>, Option<BoundSocket>)> =
            Vec::new();
        if let Some(sc) = &stream_conf {
            for (i, l) in sc.listeners.iter().enumerate() {
                let sock = match &stream_bound[i] {
                    Some(s) => Some(s.try_clone()?),
                    None => None,
                };
                stream_listeners.push((l.clone(), sock));
            }
        }

        handles.push(
            std::thread::Builder::new()
                .name(format!("oxiserve-worker-{w}"))
                .spawn(move || {
                    if let Some(c) = core {
                        // Pinning keeps a connection's buffers in one core's cache.
                        core_affinity::set_for_current(c);
                    }
                    if let Err(e) =
                        worker(w, http, listeners, error_log, tls, stream_conf_w, stream_listeners)
                    {
                        eprintln!("oxiserve: worker {w} exited: {e}");
                    }
                })?,
        );
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

type TlsMap = Arc<Vec<Option<Arc<rustls::ServerConfig>>>>;

fn worker(
    id: usize,
    http: Arc<Http>,
    listeners: Vec<(Arc<Listener>, Option<BoundSocket>)>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
    stream_conf: Option<Arc<crate::config::model::StreamConf>>,
    stream_listeners: Vec<(Arc<crate::config::model::StreamListener>, Option<BoundSocket>)>,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let logs = Rc::new(RefCell::new(Logs::new(&error_log)));
    {
        let mut l = logs.borrow_mut();
        for s in &http.servers {
            l.open_access(&s.access_logs);
        }
        l.error(LogLevel::Notice, &format!("worker {id} started"));
    }

    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(async move {
        let mut tasks = Vec::new();

        for (idx, (lconf, sock)) in listeners.into_iter().enumerate() {
            let bound = match sock {
                Some(s) => s,
                None => bind(&lconf)?,
            };
            let listener = bound.into_listener()?;

            let http = http.clone();
            let logs = logs.clone();
            let tls_cfg = tls.get(idx).cloned().flatten();

            tasks.push(tokio::task::spawn_local(async move {
                accept_loop(listener, lconf, http, logs, tls_cfg).await;
            }));
        }

        for (lconf, sock) in stream_listeners {
            let bound = match sock {
                Some(s) => s,
                None => bind_stream(&lconf)?,
            };
            let listener = bound.into_listener()?;
            let Some(sc) = stream_conf.clone() else { continue };
            tasks.push(tokio::task::spawn_local(async move {
                stream_accept_loop(listener, lconf, sc).await;
            }));
        }

        // Active health checks, on ONE worker only. Every worker probing the
        // same backend would multiply the load on it by the worker count for
        // no extra information, and the health state is shared anyway.
        if id == 0 {
            let mut probed: Vec<Arc<crate::config::model::Upstream>> = Vec::new();
            probed.extend(http.upstreams.values().cloned());
            if let Some(sc) = &stream_conf {
                probed.extend(sc.upstreams.values().cloned());
            }
            for up in probed {
                let Some(hc) = up.health_check.clone() else { continue };
                tasks.push(tokio::task::spawn_local(async move {
                    // Probe once at startup so a backend that is already down
                    // is known before the first request rather than after it.
                    crate::server::upstream::probe_round(&up, &hc).await;
                    let mut tick = tokio::time::interval(hc.interval);
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        crate::server::upstream::probe_round(&up, &hc).await;
                    }
                }));
            }
        }

        // The cache manager runs on ONE worker only. Every worker shares the
        // same directory, so several of them pruning at once would race to
        // delete the same files and each see a different total size. Worker 0
        // is as good a choice as any and needs no coordination.
        if id == 0 {
            for zone in http.cache_zones.values() {
                let zone = zone.clone();
                tasks.push(tokio::task::spawn_local(async move {
                    // Sweep at a fraction of `inactive`, so an entry is not
                    // kept far past its welcome, with sane bounds either way.
                    let every = (zone.inactive / 10)
                        .clamp(std::time::Duration::from_secs(10), std::time::Duration::from_secs(300));
                    let mut tick = tokio::time::interval(every);
                    loop {
                        tick.tick().await;
                        let z = zone.clone();
                        // Walking a large cache directory is blocking work and
                        // must not sit on the worker's event loop.
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::server::cache::manager_pass(&z)
                        })
                        .await;
                    }
                }));
            }
        }

        // A periodic tick flushes buffered log lines waiting on a `flush=`
        // deadline rather than on buffer pressure.
        let flusher_logs = logs.clone();
        tasks.push(tokio::task::spawn_local(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                tick.tick().await;
                flusher_logs.borrow_mut().flush_due();
            }
        }));

        shutdown_signal().await;
        logs.borrow_mut().flush_all();
        for t in tasks {
            t.abort();
        }
        Ok::<(), io::Error>(())
    }))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn accept_loop(
    listener: transport::Listener,
    conf: Arc<Listener>,
    http: Arc<Http>,
    logs: Rc<RefCell<Logs>>,
    tls: Option<Arc<rustls::ServerConfig>>,
) {
    let local_addr = match &conf.addr {
        crate::config::model::ListenAddr::Tcp(a) => Some(*a),
        crate::config::model::ListenAddr::Unix(_) => None,
    };
    let nodelay = conf.servers[conf.default_server].core.tcp_nodelay;

    loop {
        let (sock, remote) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                // A connection aborted between SYN and accept is routine.
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                // Descriptor exhaustion would otherwise spin the accept loop.
                logs.borrow_mut()
                    .error(LogLevel::Alert, &format!("accept() failed: {e}"));
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if nodelay {
            if let transport::Stream::Tcp(t) = &sock {
                let _ = t.set_nodelay(true);
            }
        }

        let conf = conf.clone();
        let http = http.clone();
        let logs = logs.clone();
        let tls = tls.clone();
        let id = CONN_ID.fetch_add(1, Ordering::Relaxed);

        tokio::task::spawn_local(async move {
            match tls {
                Some(cfg) => {
                    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                    // A failed handshake is routine (scanners, probes); drop it.
                    if let Ok(stream) = acceptor.accept(sock).await {
                        conn::serve(stream, &conf, &http, &logs, remote, local_addr, "https", id)
                            .await;
                    }
                }
                None => {
                    conn::serve(sock, &conf, &http, &logs, remote, local_addr, "http", id).await;
                }
            }
        });
    }
}

/// A bound socket, before it is handed to a worker's runtime.
enum BoundSocket {
    Tcp(StdListener),
    Unix(std::os::unix::net::UnixListener),
}

impl BoundSocket {
    fn try_clone(&self) -> io::Result<BoundSocket> {
        match self {
            BoundSocket::Tcp(l) => l.try_clone().map(BoundSocket::Tcp),
            BoundSocket::Unix(l) => l.try_clone().map(BoundSocket::Unix),
        }
    }

    fn into_listener(self) -> io::Result<transport::Listener> {
        match self {
            BoundSocket::Tcp(l) => {
                l.set_nonblocking(true)?;
                tokio::net::TcpListener::from_std(l).map(transport::Listener::Tcp)
            }
            BoundSocket::Unix(l) => {
                l.set_nonblocking(true)?;
                tokio::net::UnixListener::from_std(l).map(transport::Listener::Unix)
            }
        }
    }
}

/// Creates and binds one listening socket with the configured options.
fn bind(l: &Listener) -> io::Result<BoundSocket> {
    let tcp_addr = match &l.addr {
        crate::config::model::ListenAddr::Tcp(a) => *a,
        crate::config::model::ListenAddr::Unix(path) => {
            let p = std::path::Path::new(&**path);
            // A socket file left by a crash blocks `bind` with EADDRINUSE.
            transport::unlink_stale_socket(p)?;
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let ul = std::os::unix::net::UnixListener::bind(p).map_err(|e| {
                io::Error::new(e.kind(), format!("bind to unix:{path} failed: {e}"))
            })?;
            // Default 0666 so a front proxy running as another user can reach
            // it, which is the whole point of a Unix listener.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666));
            return Ok(BoundSocket::Unix(ul));
        }
    };

    let domain = match tcp_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;

    if l.addr.is_ipv6() {
        let _ = sock.set_only_v6(l.ipv6_only);
    }
    if let Some(n) = l.rcvbuf {
        let _ = sock.set_recv_buffer_size(n);
    }
    if let Some(n) = l.sndbuf {
        let _ = sock.set_send_buffer_size(n);
    }

    // `SO_REUSEPORT` gives each worker an accept queue the kernel load-balances,
    // which is where most of the accept-path scaling comes from.
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if l.reuseport {
        sock.set_reuse_port(true)?;
    }

    sock.bind(&tcp_addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind to {} failed: {e}", l.addr)))?;
    sock.listen(l.backlog)?;
    Ok(BoundSocket::Tcp(sock.into()))
}

/// Builds one rustls config per listener, with SNI resolution across every
/// server sharing that listener.
fn build_tls(http: &Http) -> io::Result<TlsMap> {
    let mut out = Vec::with_capacity(http.listeners.len());
    for l in &http.listeners {
        if !l.ssl {
            out.push(None);
            continue;
        }
        let mut resolver = SniResolver::default();
        for s in &l.servers {
            let Some(t) = &s.tls else { continue };
            let key = load_certified_key(&t.cert, &t.key)?;
            let names: Vec<String> = s
                .names
                .iter()
                .filter_map(|n| match n {
                    crate::config::model::ServerName::Exact(e) if !e.is_empty() => {
                        Some(e.to_string())
                    }
                    crate::config::model::ServerName::LeadingWildcard(x) => Some(format!("*.{x}")),
                    _ => None,
                })
                .collect();
            resolver.add(names, Arc::new(key));
        }
        if resolver.is_empty() {
            out.push(None);
            continue;
        }

        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        out.push(Some(Arc::new(cfg)));
    }
    Ok(Arc::new(out))
}

#[derive(Default)]
struct SniResolver {
    /// (`server_name` patterns, key). The first entry doubles as the default.
    entries: Vec<(Vec<String>, Arc<rustls::sign::CertifiedKey>)>,
}

impl SniResolver {
    fn add(&mut self, names: Vec<String>, key: Arc<rustls::sign::CertifiedKey>) {
        self.entries.push((names, key));
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SniResolver({} certs)", self.entries.len())
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = hello.server_name() {
            for (names, key) in &self.entries {
                for n in names {
                    let hit = match n.strip_prefix("*.") {
                        Some(suffix) => {
                            sni.len() > suffix.len()
                                && sni.as_bytes()[sni.len() - suffix.len() - 1] == b'.'
                                && sni.ends_with(suffix)
                        }
                        None => sni.eq_ignore_ascii_case(n),
                    };
                    if hit {
                        return Some(key.clone());
                    }
                }
            }
        }
        // No SNI, or no match: the first configured certificate is the default,
        // matching nginx's behaviour for the default server on a port.
        self.entries.first().map(|(_, k)| k.clone())
    }
}

fn load_certified_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<rustls::sign::CertifiedKey> {
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut io::BufReader::new(std::fs::File::open(cert_path)?))
            .collect::<Result<_, _>>()
            .map_err(|e| io::Error::other(format!("{}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(io::Error::other(format!(
            "{}: no certificates found",
            cert_path.display()
        )));
    }

    let key = rustls_pemfile::private_key(&mut io::BufReader::new(std::fs::File::open(key_path)?))
        .map_err(|e| io::Error::other(format!("{}: {e}", key_path.display())))?
        .ok_or_else(|| io::Error::other(format!("{}: no private key found", key_path.display())))?;

    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| io::Error::other(format!("{}: {e}", key_path.display())))?;
    Ok(rustls::sign::CertifiedKey::new(certs, signing))
}

/// Binds a `stream` listener. Same socket options as the HTTP side, minus the
/// pieces that only make sense for HTTP.
fn bind_stream(l: &crate::config::model::StreamListener) -> io::Result<BoundSocket> {
    use crate::config::model::ListenAddr;
    let tcp_addr = match &l.addr {
        ListenAddr::Tcp(a) => *a,
        ListenAddr::Unix(path) => {
            let p = std::path::Path::new(&**path);
            transport::unlink_stale_socket(p)?;
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let ul = std::os::unix::net::UnixListener::bind(p).map_err(|e| {
                io::Error::new(e.kind(), format!("bind to unix:{path} failed: {e}"))
            })?;
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666));
            return Ok(BoundSocket::Unix(ul));
        }
    };
    let domain = match tcp_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if tcp_addr.is_ipv6() {
        let _ = sock.set_only_v6(l.ipv6_only);
    }
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if l.reuseport {
        sock.set_reuse_port(true)?;
    }
    sock.bind(&tcp_addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind to {} failed: {e}", l.addr)))?;
    sock.listen(l.backlog)?;
    Ok(BoundSocket::Tcp(sock.into()))
}

async fn stream_accept_loop(
    listener: transport::Listener,
    conf: Arc<crate::config::model::StreamListener>,
    sc: Arc<crate::config::model::StreamConf>,
) {
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if let transport::Stream::Tcp(t) = &sock {
            // Proxied protocols are usually request/response; Nagle would add
            // latency to every small exchange.
            let _ = t.set_nodelay(true);
        }
        let srv = conf.server.clone();
        let sc = sc.clone();
        tokio::task::spawn_local(async move {
            stream::serve(sock, srv, sc).await;
        });
    }
}

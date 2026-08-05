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
pub mod conn;
pub mod ctx;
pub mod fastcgi;
pub mod fcache;
pub mod fcgi_proto;
pub mod files;
pub mod handler;
pub mod log;
pub mod proxy;
pub mod reply;

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
    let Some(http) = config.http else {
        eprintln!("oxiserve: no http block in configuration, nothing to serve");
        return Ok(());
    };
    let http = Arc::new(http);
    let error_log = config.error_log.clone();
    let workers = config.worker_processes.resolve();

    // Sockets are bound before workers start, so a port conflict is reported
    // once, at startup, rather than N times from N threads.
    let mut shared: Vec<Option<StdListener>> = Vec::new();
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
        let mut listeners: Vec<(Arc<Listener>, Option<StdListener>)> = Vec::new();
        for (i, l) in http.listeners.iter().enumerate() {
            let sock = match &shared[i] {
                Some(s) => Some(s.try_clone()?),
                None => None,
            };
            listeners.push((l.clone(), sock));
        }

        handles.push(
            std::thread::Builder::new()
                .name(format!("oxiserve-worker-{w}"))
                .spawn(move || {
                    if let Some(c) = core {
                        // Pinning keeps a connection's buffers in one core's cache.
                        core_affinity::set_for_current(c);
                    }
                    if let Err(e) = worker(w, http, listeners, error_log, tls) {
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
    listeners: Vec<(Arc<Listener>, Option<StdListener>)>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
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
            let std_sock = match sock {
                Some(s) => s,
                None => bind(&lconf)?,
            };
            std_sock.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(std_sock)?;

            let http = http.clone();
            let logs = logs.clone();
            let tls_cfg = tls.get(idx).cloned().flatten();

            tasks.push(tokio::task::spawn_local(async move {
                accept_loop(listener, lconf, http, logs, tls_cfg).await;
            }));
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
    listener: tokio::net::TcpListener,
    conf: Arc<Listener>,
    http: Arc<Http>,
    logs: Rc<RefCell<Logs>>,
    tls: Option<Arc<rustls::ServerConfig>>,
) {
    let local_addr = listener.local_addr().unwrap_or(conf.addr);
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
            let _ = sock.set_nodelay(true);
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

/// Creates and binds one listening socket with the configured options.
fn bind(l: &Listener) -> io::Result<StdListener> {
    let domain = match l.addr {
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

    sock.bind(&l.addr.into())
        .map_err(|e| io::Error::new(e.kind(), format!("bind to {} failed: {e}", l.addr)))?;
    sock.listen(l.backlog)?;
    Ok(sock.into())
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

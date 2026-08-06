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
pub mod preread;
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

    // Assembles one worker's inputs. In thread mode this runs in the parent
    // and the values move into the thread; in process mode it runs in the
    // child, where `try_clone` dups the descriptor the child inherited.
    let build = |w: usize| -> io::Result<WorkerInputs> {
        let core = if cores.is_empty() { None } else { Some(cores[w % cores.len()]) };
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
        Ok(WorkerInputs {
            http: http.clone(),
            error_log: error_log.clone(),
            tls: tls.clone(),
            core,
            listeners,
            stream_conf: stream_conf.clone(),
            stream_listeners,
        })
    };

    // Workers are processes, as nginx's are, unless there is only one (tests
    // and embedders run the server on a thread inside a larger program, where
    // forking would clone that whole program mid-flight) or the platform has
    // no fork. Two worker threads in one process measured 0.93x nginx on
    // connection churn where two processes measure 1.00x — the difference is
    // contention on state the threads share and the processes do not.
    // `OXISERVE_WORKER_MODEL=threads` keeps the old model for A/B runs.
    let process_mode = workers > 1
        && cfg!(unix)
        && std::env::var_os("OXISERVE_WORKER_MODEL").map(|v| v != "threads").unwrap_or(true);

    if process_mode {
        return prefork(workers, &build);
    }

    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let inp = build(w)?;
        handles.push(
            std::thread::Builder::new()
                .name(format!("oxiserve-worker-{w}"))
                .spawn(move || {
                    if let Some(c) = inp.core {
                        // Pinning keeps a connection's buffers in one core's cache.
                        core_affinity::set_for_current(c);
                    }
                    if let Err(e) = worker(
                        w,
                        inp.http,
                        inp.listeners,
                        inp.error_log,
                        inp.tls,
                        inp.stream_conf,
                        inp.stream_listeners,
                        false,
                    ) {
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

/// Everything one worker needs, built per worker.
struct WorkerInputs {
    http: Arc<Http>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
    core: Option<core_affinity::CoreId>,
    listeners: Vec<(Arc<Listener>, Option<BoundSocket>)>,
    stream_conf: Option<Arc<crate::config::model::StreamConf>>,
    stream_listeners: Vec<(Arc<crate::config::model::StreamListener>, Option<BoundSocket>)>,
}

/// Runs `workers` forked worker processes and supervises them.
///
/// The master stays single-threaded — it has not spawned anything before this
/// point, which is what makes `fork` safe — and does exactly what nginx's
/// master does: wait, respawn a worker that dies, and forward termination.
/// Shared-state rules in this mode: `limit_req` zones live in `MAP_SHARED`
/// memory and remain one zone; upstream health and the keepalive pool are per
/// process (nginx's own semantics without a `zone` directive); the cache
/// *index* was per worker already; `proxy_cache_lock` collapses a stampede per
/// process rather than globally.
#[cfg(unix)]
fn prefork<F>(workers: usize, build: &F) -> io::Result<()>
where
    F: Fn(usize) -> io::Result<WorkerInputs>,
{
    use std::sync::atomic::AtomicBool;
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_stop(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    // Installed WITHOUT SA_RESTART, so a signal interrupts `waitpid` with
    // EINTR instead of transparently resuming it — the loop below depends on
    // waking up to notice STOP.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_stop as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }

    let spawn = |w: usize| -> io::Result<libc::pid_t> {
        // SAFETY: the master has spawned no threads, so the child is a clean
        // single-threaded copy with no lock held by a thread that no longer
        // exists.
        match unsafe { libc::fork() } {
            -1 => Err(io::Error::last_os_error()),
            0 => {
                unsafe {
                    // The child must not inherit the master's stop handler:
                    // its own termination is the default action.
                    libc::signal(libc::SIGTERM, libc::SIG_DFL);
                    libc::signal(libc::SIGINT, libc::SIG_DFL);
                    #[cfg(target_os = "linux")]
                    {
                        // Die with the master even if it is SIGKILLed and
                        // never gets to signal us. The getppid check closes
                        // the race where the master died before prctl ran.
                        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                        if libc::getppid() == 1 {
                            libc::_exit(0);
                        }
                    }
                }
                // Distinct $connection ranges per process; purely cosmetic,
                // but collisions in logs would look like cross-talk.
                CONN_ID.store((w as u64) << 56, Ordering::Relaxed);
                // Name the process what it is, as nginx labels its workers.
                // Fifteen bytes is the comm limit; "oxiserve-worker" is
                // exactly that, deliberately.
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::prctl(libc::PR_SET_NAME, c"oxiserve-worker".as_ptr());
                }
                let code = match build(w) {
                    Ok(inp) => {
                        if let Some(c) = inp.core {
                            core_affinity::set_for_current(c);
                        }
                        match worker(
                            w,
                            inp.http,
                            inp.listeners,
                            inp.error_log,
                            inp.tls,
                            inp.stream_conf,
                            inp.stream_listeners,
                            true,
                        ) {
                            Ok(()) => 0,
                            Err(e) => {
                                eprintln!("oxiserve: worker {w} exited: {e}");
                                1
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("oxiserve: worker {w} setup failed: {e}");
                        1
                    }
                };
                std::process::exit(code);
            }
            pid => Ok(pid),
        }
    };

    let mut children: Vec<(libc::pid_t, usize)> = Vec::with_capacity(workers);
    for w in 0..workers {
        children.push((spawn(w)?, w));
    }

    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                if STOP.load(Ordering::SeqCst) {
                    for (p, _) in &children {
                        unsafe { libc::kill(*p, libc::SIGTERM) };
                    }
                    for (p, _) in &children {
                        unsafe { libc::waitpid(*p, &mut status, 0) };
                    }
                    return Ok(());
                }
                continue;
            }
            if e.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            return Err(e);
        }
        let Some(pos) = children.iter().position(|(p, _)| *p == pid) else { continue };
        let (_, w) = children.swap_remove(pos);
        if STOP.load(Ordering::SeqCst) {
            if children.is_empty() {
                return Ok(());
            }
            continue;
        }
        // A worker died out from under us. Respawning is what keeps one bad
        // request from turning into an outage; the pause keeps a worker that
        // dies instantly from turning the master into a fork loop.
        eprintln!("oxiserve: worker {w} exited unexpectedly, respawning");
        std::thread::sleep(std::time::Duration::from_millis(100));
        children.push((spawn(w)?, w));
    }
}

#[cfg(not(unix))]
fn prefork<F>(_workers: usize, _build: &F) -> io::Result<()>
where
    F: Fn(usize) -> io::Result<WorkerInputs>,
{
    unreachable!("process_mode is only ever true on unix")
}

// The connection-churn story, for whoever benchmarks next: with worker
// THREADS this workload measured 0.93x nginx and no syscall-level fix moved
// it — the loss was contention on process-shared state (see ADR-0003). Worker
// processes closed it. If a future change reintroduces threads on the hot
// path, re-run `bench/nginx-compare.sh` before trusting it.

type TlsMap = Arc<Vec<Option<Arc<rustls::ServerConfig>>>>;

#[allow(clippy::too_many_arguments)]
fn worker(
    id: usize,
    http: Arc<Http>,
    listeners: Vec<(Arc<Listener>, Option<BoundSocket>)>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
    stream_conf: Option<Arc<crate::config::model::StreamConf>>,
    stream_listeners: Vec<(Arc<crate::config::model::StreamListener>, Option<BoundSocket>)>,
    // True in process mode: this worker's upstream-health state is private to
    // its process, so relying on worker 0's probes would leave every other
    // process blind. Each probes for itself.
    own_state: bool,
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
        //
        // Except in process mode: there the health state is per process, so a
        // worker that did not probe would never learn what the probes know.
        // The multiplied probe load is the honest price of that isolation.
        if id == 0 || own_state {
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
        let (mut sock, remote) = match listener.accept().await {
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
            sock.set_nodelay(true);
        }

        let conf = conf.clone();
        let http = http.clone();
        let logs = logs.clone();
        let tls = tls.clone();
        let id = CONN_ID.fetch_add(1, Ordering::Relaxed);

        let h2_enabled = conf.http2;
        tokio::task::spawn_local(async move {
            match tls {
                Some(cfg) => {
                    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                    // A failed handshake is routine (scanners, probes); drop it.
                    let Ok(stream) = acceptor.accept(sock).await else { return };
                    // ALPN is the only negotiation HTTP/2 over TLS has: RFC
                    // 9113 section 3.1 gives no in-band upgrade, so what the
                    // handshake agreed on is final.
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    if h2 {
                        crate::http2::conn::serve(
                            stream, &conf, &http, &logs, remote, local_addr, "https", id,
                            Vec::new(),
                        )
                        .await;
                    } else {
                        conn::serve(stream, &conf, &http, &logs, remote, local_addr, "https", id)
                            .await;
                    }
                }
                None => {
                    // Cleartext HTTP/2 has no ALPN, so a client either knows
                    // the server speaks it and opens with the preface ("prior
                    // knowledge"), or it speaks HTTP/1.1. Peeking for the
                    // preface is how both share a port.
                    if h2_enabled {
                        match peek_preface(sock).await {
                            Preface::H2(sock, pre) => {
                                crate::http2::conn::serve(
                                    sock, &conf, &http, &logs, remote, local_addr, "http", id, pre,
                                )
                                .await;
                                return;
                            }
                            Preface::Http1(sock, pre) => {
                                conn::serve_with_prefix(
                                    sock, &conf, &http, &logs, remote, local_addr, "http", id, pre,
                                )
                                .await;
                                return;
                            }
                            Preface::Gone => return,
                        }
                    }
                    conn::serve(sock, &conf, &http, &logs, remote, local_addr, "http", id).await;
                }
            }
        });
    }
}

/// What the first bytes on a cleartext connection turned out to be.
enum Preface {
    /// The HTTP/2 client preface, plus whatever else arrived with it.
    H2(transport::Stream, Vec<u8>),
    /// Not HTTP/2. The bytes read must be handed back — they are the start of
    /// an HTTP/1 request line.
    Http1(transport::Stream, Vec<u8>),
    Gone,
}

/// Reads just enough of a cleartext connection to tell HTTP/2 from HTTP/1.1.
///
/// Cleartext HTTP/2 has no ALPN to negotiate with, so a client that knows the
/// server supports it simply opens with the connection preface. The preface
/// begins `PRI * HTTP/2.0`, which is not a valid HTTP/1 request line, so the
/// two are distinguishable without ambiguity — and the bytes are never
/// consumed, only inspected, so an HTTP/1 client is unaffected.
async fn peek_preface(mut sock: transport::Stream) -> Preface {
    use tokio::io::AsyncReadExt;
    const P: &[u8] = crate::http2::frame::PREFACE;
    let mut buf = Vec::with_capacity(P.len());
    let mut chunk = [0u8; 64];
    loop {
        // Compare only what we hold: a client that dribbles the preface a byte
        // at a time must not be mistaken for an HTTP/1 client.
        let have = buf.len().min(P.len());
        if buf[..have] != P[..have] {
            return Preface::Http1(sock, buf);
        }
        if buf.len() >= P.len() {
            return Preface::H2(sock, buf);
        }
        let want = (P.len() - buf.len()).min(chunk.len());
        match sock.read(&mut chunk[..want]).await {
            Ok(0) => {
                // EOF before we could tell. An HTTP/1 request cannot be this
                // short either, so let the HTTP/1 path produce the error.
                return Preface::Http1(sock, buf);
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Preface::Gone,
        }
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
                l.set_nonblocking(true)?;
                tokio::io::unix::AsyncFd::new(l).map(transport::Listener::Tcp)
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
        // Order is a preference list: the client picks the first it also
        // supports, so `h2` must lead for `listen ... http2` to mean anything.
        // Without `http2` on the listener we do not offer it at all, which is
        // how a config keeps HTTP/1.1 deliberately.
        cfg.alpn_protocols = if l.http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
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
        let (sock, peer) = match listener.accept().await {
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
            stream::serve(sock, srv, sc, peer).await;
        });
    }
}

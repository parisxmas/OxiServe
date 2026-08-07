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
pub mod limit_conn;
pub mod limit_req;
pub mod log;
#[cfg(feature = "modsecurity")]
pub mod modsec;
pub mod msgpack;
pub mod preread;
pub mod proxy;
pub mod quic;
pub mod reply;
pub mod shm;
pub mod stats;
pub mod stream;
pub mod transport;
pub mod udp;
pub mod upstream;

use std::cell::RefCell;
use std::io;
use std::path::PathBuf;
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
/// Sends one of nginx's control signals to a running master.
///
/// The pid file is located by loading the configuration, because that is what
/// names it — guessing a conventional path would send `-s stop` to the wrong
/// server on a host running two.
#[cfg(unix)]
pub fn signal_master(conf: &std::path::Path, prefix: PathBuf, name: &str) -> io::Result<()> {
    let sig = match name {
        // nginx's mapping, exactly.
        "stop" => libc::SIGTERM,
        "quit" => libc::SIGQUIT,
        "reload" => libc::SIGHUP,
        "reopen" => libc::SIGUSR1,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid option: \"-s {other}\""),
            ))
        }
    };

    let cfg = crate::config::load(conf, prefix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = cfg.pid.clone().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no \"pid\" directive in the configuration")
    })?;
    let text = std::fs::read_to_string(&path).map_err(|e| {
        io::Error::new(e.kind(), format!("open() \"{}\" failed ({e})", path.display()))
    })?;
    let pid: libc::pid_t = text
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid PID number"))?;

    // SAFETY: `kill` with a plain signal number; a stale pid is reported, not
    // acted on further.
    if unsafe { libc::kill(pid, sig) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("kill({pid}, {name}) failed ({e})")));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn signal_master(_c: &std::path::Path, _p: PathBuf, _n: &str) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "signals are a unix feature"))
}

pub fn run(config: Config) -> io::Result<()> {
    run_from(config, None)
}

/// [`run`], plus where the configuration came from.
///
/// The master needs the path to honour `-s reload`: reloading means reading
/// the file again, and a `Config` does not remember where it was parsed from.
/// Embedders that build a `Config` by hand pass `None` and simply have no
/// reload.
/// One configuration's worth of prepared state: everything a worker needs,
/// already bound and built.
///
/// A reload produces a *new* `Generation` and forks from that. The earlier
/// version validated the new configuration and then forked from the old one
/// still in memory — it logged "reloaded" and changed nothing, which is worse
/// than failing.
struct Generation {
    http: Arc<Http>,
    stream_conf: Option<Arc<crate::config::model::StreamConf>>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
    /// One quinn config per entry in `http.quic_listeners`, `None` where the
    /// listener has no certificate. The sockets themselves are not pre-bound:
    /// QUIC binds per worker with `SO_REUSEPORT`, always. See
    /// [`quic`](crate::server::quic) for why that is structural.
    quic_configs: Vec<Option<Arc<quinn::ServerConfig>>>,
    shared: Vec<Option<BoundSocket>>,
    stream_bound: Vec<Option<BoundSocket>>,
    workers: usize,
}

impl Generation {
    /// Binds sockets and builds TLS state for `config`.
    ///
    /// `previous` supplies already-bound sockets for addresses that have not
    /// changed. Rebinding those would fail with `EADDRINUSE` while the old
    /// generation still holds them — reuseport listeners are the exception,
    /// which is why they are bound per worker in the first place.
    fn prepare(config: Config, previous: Option<&Generation>, announce: bool) -> io::Result<Option<Generation>> {
        let stream_conf = config.stream.map(Arc::new);
        let http = match config.http {
            Some(h) => Arc::new(h),
            None if stream_conf.is_some() => {
                // A stream-only configuration is legitimate: a pure L4 proxy.
                Arc::new(Http {
                    cache_zones: Default::default(),
                    limit_req_zones: Default::default(),
                    limit_req_keys: Default::default(),
                    limit_conn_zones: Default::default(),
                    limit_conn_keys: Default::default(),
                    listeners: Vec::new(),
                    quic_listeners: Vec::new(),
                    upstreams: Default::default(),
                    maps: Vec::new(),
                    mime: Arc::new(Default::default()),
                    servers: Vec::new(),
                })
            }
            None => {
                eprintln!("oxiserve: no http or stream block in configuration, nothing to serve");
                return Ok(None);
            }
        };

        // Sockets are bound before workers start, so a port conflict is
        // reported once, at startup, rather than N times from N workers.
        let mut shared: Vec<Option<BoundSocket>> = Vec::new();
        for l in &http.listeners {
            if cfg!(target_os = "linux") && l.reuseport {
                // Each worker will bind its own socket instead.
                shared.push(None);
            } else if let Some(s) = previous.and_then(|p| p.socket_for(&l.addr)) {
                shared.push(Some(s.try_clone()?));
            } else {
                shared.push(Some(bind(l)?));
            }
        }
        if announce {
            for (i, l) in http.listeners.iter().enumerate() {
                eprintln!(
                    "oxiserve: listening on {}{}{}",
                    l.addr,
                    if l.ssl { " ssl" } else { "" },
                    if shared[i].is_none() { " (reuseport)" } else { "" }
                );
            }
        }

        let mut stream_bound: Vec<Option<BoundSocket>> = Vec::new();
        if let Some(sc) = &stream_conf {
            for l in &sc.udp_listeners {
                if announce {
                    eprintln!("oxiserve: stream listening on {} udp (reuseport)", l.addr);
                }
            }
            for l in &sc.listeners {
                if cfg!(target_os = "linux") && l.reuseport {
                    stream_bound.push(None);
                } else if let Some(s) = previous.and_then(|p| p.stream_socket_for(&l.addr)) {
                    stream_bound.push(Some(s.try_clone()?));
                } else {
                    stream_bound.push(Some(bind_stream(l)?));
                }
                if announce {
                    eprintln!("oxiserve: stream listening on {}", l.addr);
                }
            }
        }

        // Before any worker exists, so every process shares one set.
        stats::init();
        let tls = build_tls(&http)?;
        let quic_configs = quic::build_configs(&http)?;
        if announce {
            for (i, l) in http.quic_listeners.iter().enumerate() {
                if quic_configs[i].is_some() {
                    eprintln!("oxiserve: listening on {} quic (udp, reuseport)", l.addr);
                }
            }
        }
        Ok(Some(Generation {
            workers: config.worker_processes.resolve(),
            error_log: config.error_log,
            http,
            stream_conf,
            tls,
            quic_configs,
            shared,
            stream_bound,
        }))
    }

    fn socket_for(&self, addr: &crate::config::model::ListenAddr) -> Option<&BoundSocket> {
        let i = self.http.listeners.iter().position(|l| &l.addr == addr)?;
        self.shared.get(i)?.as_ref()
    }

    fn stream_socket_for(&self, addr: &crate::config::model::ListenAddr) -> Option<&BoundSocket> {
        let sc = self.stream_conf.as_ref()?;
        let i = sc.listeners.iter().position(|l| &l.addr == addr)?;
        self.stream_bound.get(i)?.as_ref()
    }

    /// Assembles one worker's inputs. In thread mode this runs in the parent
    /// and the values move into the thread; in process mode it runs in the
    /// child, where `try_clone` dups the descriptor the child inherited.
    fn build(&self, w: usize, cores: &[core_affinity::CoreId]) -> io::Result<WorkerInputs> {
        let core = if cores.is_empty() { None } else { Some(cores[w % cores.len()]) };
        // Each worker needs its own listener handle. Cloning the descriptor
        // gives every worker an independent accept loop on the same queue.
        let mut listeners: Vec<(Arc<Listener>, Option<BoundSocket>)> = Vec::new();
        for (i, l) in self.http.listeners.iter().enumerate() {
            let sock = match &self.shared[i] {
                Some(s) => Some(s.try_clone()?),
                None => None,
            };
            listeners.push((l.clone(), sock));
        }
        let mut stream_listeners: Vec<(
            Arc<crate::config::model::StreamListener>,
            Option<BoundSocket>,
        )> = Vec::new();
        if let Some(sc) = &self.stream_conf {
            for (i, l) in sc.listeners.iter().enumerate() {
                let sock = match &self.stream_bound[i] {
                    Some(s) => Some(s.try_clone()?),
                    None => None,
                };
                stream_listeners.push((l.clone(), sock));
            }
        }
        let quic = self
            .http
            .quic_listeners
            .iter()
            .zip(&self.quic_configs)
            .filter_map(|(l, c)| c.as_ref().map(|c| (l.clone(), c.clone())))
            .collect();

        Ok(WorkerInputs {
            http: self.http.clone(),
            error_log: self.error_log.clone(),
            tls: self.tls.clone(),
            core,
            listeners,
            quic,
            stream_conf: self.stream_conf.clone(),
            stream_listeners,
            own_state: false,
        })
    }
}

pub fn run_from(config: Config, source: Option<(PathBuf, PathBuf)>) -> io::Result<()> {
    let pid_path = config.pid.clone();
    let Some(gen) = Generation::prepare(config, None, true)? else { return Ok(()) };
    let workers = gen.workers;
    let cores = core_affinity::get_core_ids().unwrap_or_default();

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

    // Written before any worker exists, so `-s reload` immediately after start
    // finds a pid rather than a missing file. Removed on a clean exit; a stale
    // one left by a crash is harmless, since `kill` on a dead pid reports
    // ESRCH rather than signalling whatever reused the number... on Linux,
    // where pids are not reused that fast. It is the same exposure nginx has.
    let _pid_file = pid_path.as_ref().map(|p| PidFile::write(p)).transpose()?;

    if process_mode {
        return prefork(gen, cores, source.as_ref());
    }

    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let inp = gen.build(w, &cores)?;
        handles.push(
            std::thread::Builder::new()
                .name(format!("oxiserve-worker-{w}"))
                .spawn(move || {
                    if let Some(c) = inp.core {
                        // Pinning keeps a connection's buffers in one core's cache.
                        core_affinity::set_for_current(c);
                    }
                    if let Err(e) = worker(w, inp) {
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

/// The master's pid file, removed when the master goes away.
///
/// `-s reload` has nowhere to send its signal without this, so a config with a
/// `pid` directive that produced no file would make the whole control
/// interface silently unavailable.
struct PidFile(PathBuf);

impl PidFile {
    fn write(path: &std::path::Path) -> io::Result<PidFile> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        std::fs::write(path, format!("{}\n", std::process::id()))?;
        Ok(PidFile(path.to_path_buf()))
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Everything one worker needs, built per worker.
struct WorkerInputs {
    http: Arc<Http>,
    error_log: crate::config::model::ErrorLogConf,
    tls: TlsMap,
    core: Option<core_affinity::CoreId>,
    listeners: Vec<(Arc<Listener>, Option<BoundSocket>)>,
    /// QUIC listeners that have a certificate, with the config to serve them.
    quic: Vec<(Arc<Listener>, Arc<quinn::ServerConfig>)>,
    stream_conf: Option<Arc<crate::config::model::StreamConf>>,
    stream_listeners: Vec<(Arc<crate::config::model::StreamListener>, Option<BoundSocket>)>,
    /// True in process mode: this worker's upstream-health state is private to
    /// its process, so relying on worker 0's probes would leave every other
    /// process blind. Each probes for itself.
    own_state: bool,
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
fn prefork(
    mut gen: Generation,
    cores: Vec<core_affinity::CoreId>,
    source: Option<&(PathBuf, PathBuf)>,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicU32};
    static STOP: AtomicBool = AtomicBool::new(false);
    /// Set by SIGHUP/SIGUSR1 and drained by the supervisor loop. A counter
    /// rather than a flag so two reloads in quick succession are two reloads.
    static RELOAD: AtomicU32 = AtomicU32::new(0);
    static REOPEN: AtomicU32 = AtomicU32::new(0);

    extern "C" fn on_stop(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    extern "C" fn on_reload(_: libc::c_int) {
        RELOAD.fetch_add(1, Ordering::SeqCst);
    }
    extern "C" fn on_reopen(_: libc::c_int) {
        REOPEN.fetch_add(1, Ordering::SeqCst);
    }
    // Installed WITHOUT SA_RESTART, so a signal interrupts `waitpid` with
    // EINTR instead of transparently resuming it — the loop below depends on
    // waking up to notice these flags.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = on_stop as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_reload as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_reopen as extern "C" fn(libc::c_int) as usize;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    let spawn = |gen: &Generation, w: usize| -> io::Result<libc::pid_t> {
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
                let code = match gen.build(w, &cores) {
                    Ok(inp) => {
                        if let Some(c) = inp.core {
                            core_affinity::set_for_current(c);
                        }
                        match worker(w, WorkerInputs { own_state: true, ..inp }) {
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

    let mut children: Vec<(libc::pid_t, usize)> = Vec::with_capacity(gen.workers);
    for w in 0..gen.workers {
        children.push((spawn(&gen, w)?, w));
    }

    // Workers from a superseded configuration. They are draining, must not be
    // respawned when they exit, and must not be counted as the live set.
    let mut retiring: Vec<libc::pid_t> = Vec::new();

    loop {
        // Signals are handled before blocking again, so one that arrived while
        // we were inside `waitpid` is not left sitting until the next event.
        if REOPEN.swap(0, Ordering::SeqCst) > 0 {
            // Draining workers reopen too: they may still be writing lines
            // for connections they have not finished.
            for p in children.iter().map(|(p, _)| *p).chain(retiring.iter().copied()) {
                unsafe { libc::kill(p, libc::SIGUSR1) };
            }
        }
        if RELOAD.swap(0, Ordering::SeqCst) > 0 && !STOP.load(Ordering::SeqCst) {
            match reload(source, &gen, &spawn) {
                Ok((fresh_gen, fresh)) => {
                    // Old workers only start draining once the new ones exist,
                    // so there is no window with nobody serving. `SO_REUSEPORT`
                    // is what lets both generations hold the port at once.
                    eprintln!("oxiserve: reloaded configuration");
                    retiring.extend(children.iter().map(|(p, _)| *p));
                    for (p, _) in &children {
                        unsafe { libc::kill(*p, libc::SIGQUIT) };
                    }
                    children = fresh;
                    // The old generation drops here, closing any listening
                    // socket the new one did not take over.
                    gen = fresh_gen;
                }
                // A bad configuration must never cost the running server. This
                // is the whole reason reload validates before it acts.
                Err(e) => eprintln!("oxiserve: [emerg] reload failed, keeping the old configuration: {e}"),
            }
            continue;
        }

        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                if STOP.load(Ordering::SeqCst) {
                    for p in children.iter().map(|(p, _)| *p).chain(retiring.iter().copied()) {
                        unsafe { libc::kill(p, libc::SIGQUIT) };
                    }
                    for p in children.iter().map(|(p, _)| *p).chain(retiring.iter().copied()) {
                        unsafe { libc::waitpid(p, &mut status, 0) };
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

        // A retiring worker finishing is the expected end of a reload, not a
        // failure, and must not be respawned.
        if let Some(i) = retiring.iter().position(|p| *p == pid) {
            retiring.swap_remove(i);
            continue;
        }
        let Some(pos) = children.iter().position(|(p, _)| *p == pid) else { continue };
        let (_, w) = children.swap_remove(pos);
        if STOP.load(Ordering::SeqCst) {
            if children.is_empty() && retiring.is_empty() {
                return Ok(());
            }
            continue;
        }
        // A worker died out from under us. Respawning is what keeps one bad
        // request from turning into an outage; the pause keeps a worker that
        // dies instantly from turning the master into a fork loop.
        eprintln!("oxiserve: worker {w} exited unexpectedly, respawning");
        std::thread::sleep(std::time::Duration::from_millis(100));
        children.push((spawn(&gen, w)?, w));
    }
}

/// Re-reads the configuration and starts a fresh generation of workers.
///
/// Returns the new children, or an error that leaves the caller's existing
/// ones untouched — validation happens before anything is forked, so a
/// configuration with a typo costs a log line and nothing else. That ordering
/// is the entire value of `-s reload` over `restart`.
///
/// New workers bind their own listening sockets: `SO_REUSEPORT` means both
/// generations can hold the port while the old one drains, which is what makes
/// the handover seamless. Without `reuseport` the new workers inherit the
/// master's already-bound descriptors, so the port is never released either.
#[cfg(unix)]
fn reload<S>(
    source: Option<&(PathBuf, PathBuf)>,
    current: &Generation,
    spawn: &S,
) -> io::Result<(Generation, Vec<(libc::pid_t, usize)>)>
where
    S: Fn(&Generation, usize) -> io::Result<libc::pid_t>,
{
    let Some((conf, prefix)) = source else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this server was started from an in-memory configuration, so there is no file to re-read",
        ));
    };
    // Parsed and lowered in full — the same work startup does — so a config
    // that would have failed to start fails here instead of in a child that
    // then exits and gets respawned into a loop.
    let config = crate::config::load(conf, prefix.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Binding happens before any fork too, so a port that is now taken by
    // something else is also caught while the old workers are still serving.
    let Some(next) = Generation::prepare(config, Some(current), false)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the new configuration serves nothing",
        ));
    };

    let mut fresh = Vec::with_capacity(next.workers);
    for w in 0..next.workers {
        fresh.push((spawn(&next, w)?, w));
    }
    Ok((next, fresh))
}

#[cfg(not(unix))]
fn prefork(
    _gen: Generation,
    _cores: Vec<core_affinity::CoreId>,
    _source: Option<&(PathBuf, PathBuf)>,
) -> io::Result<()> {
    unreachable!("process_mode is only ever true on unix")
}

// The connection-churn story, for whoever benchmarks next: with worker
// THREADS this workload measured 0.93x nginx and no syscall-level fix moved
// it — the loss was contention on process-shared state (see ADR-0003). Worker
// processes closed it. If a future change reintroduces threads on the hot
// path, re-run `bench/nginx-compare.sh` before trusting it.

type TlsMap = Arc<Vec<Option<Arc<rustls::ServerConfig>>>>;

fn worker(id: usize, inp: WorkerInputs) -> io::Result<()> {
    let WorkerInputs {
        http,
        error_log,
        tls,
        core: _,
        listeners,
        quic,
        stream_conf,
        stream_listeners,
        own_state,
    } = inp;
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

        // QUIC endpoints are created here rather than in the master: the
        // socket must belong to this worker for the reuseport hash to keep a
        // connection on one core.
        for (lconf, cfg) in quic {
            let ep = match quic::endpoint(&lconf, cfg, &logs) {
                Ok(ep) => ep,
                Err(e) => {
                    logs.borrow_mut().error(
                        LogLevel::Alert,
                        &format!("quic listen on {} failed: {e}", lconf.addr),
                    );
                    continue;
                }
            };
            let http = http.clone();
            let logs = logs.clone();
            tasks.push(tokio::task::spawn_local(async move {
                quic::accept_loop(ep, lconf, http, logs).await;
            }));
        }

        // UDP stream listeners bind per worker, like the QUIC ones: a
        // datagram socket has no accept queue to share, and one socket read by
        // every worker would scatter a session's packets across all of them.
        if let Some(sc) = stream_conf.clone() {
            for lconf in sc.udp_listeners.clone() {
                let sock = match udp::bind(&lconf) {
                    Ok(s) => s,
                    Err(e) => {
                        logs.borrow_mut().error(
                            LogLevel::Alert,
                            &format!("udp listen on {} failed: {e}", lconf.addr),
                        );
                        continue;
                    }
                };
                let (sc, srv) = (sc.clone(), lconf.server.clone());
                tasks.push(tokio::task::spawn_local(async move {
                    udp::serve(sock, sc, srv).await;
                }));
            }
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
                let mut l = flusher_logs.borrow_mut();
                l.reopen_if_asked();
                l.flush_due();
            }
        }));

        match shutdown_signal().await {
            Stop::Now => {}
            Stop::Graceful => {
                // Accept loops and background tasks stop first, so no new work
                // arrives; then the connections already in hand get to finish.
                // Cutting them here is exactly what makes a naive reload drop
                // requests.
                for t in &tasks {
                    t.abort();
                }
                let deadline = std::time::Instant::now() + GRACEFUL_TIMEOUT;
                while LIVE_REQUESTS.load(Ordering::Acquire) > 0
                    && std::time::Instant::now() < deadline
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        logs.borrow_mut().flush_all();
        for t in tasks {
            t.abort();
        }
        Ok::<(), io::Error>(())
    }))
}

/// Requests currently being handled by this process.
///
/// Requests, not connections. A keep-alive connection sitting idle between
/// requests has nothing to lose by being closed, and counting those made a
/// graceful shutdown wait out its whole timeout for clients that were not
/// asking for anything — including the connection a readiness probe opens and
/// abandons.
///
/// Process-wide rather than per worker: a graceful shutdown wants everything
/// this process is still doing, and in thread mode several workers share it.
pub(crate) static LIVE_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Increments [`LIVE_REQUESTS`] for as long as it exists.
pub(crate) struct LiveRequest;

impl LiveRequest {
    pub(crate) fn enter() -> LiveRequest {
        LIVE_REQUESTS.fetch_add(1, Ordering::AcqRel);
        LiveRequest
    }
}

impl Drop for LiveRequest {
    fn drop(&mut self) {
        LIVE_REQUESTS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What ended the worker's run.
enum Stop {
    /// `SIGTERM` — nginx's "fast shutdown". Stop now.
    Now,
    /// `SIGQUIT` — nginx's "graceful shutdown", and what a reload sends to the
    /// previous generation. Stop accepting, then let what is in flight finish.
    Graceful,
}

/// How long a draining worker waits for its connections.
///
/// A WebSocket or a long download can outlive any sensible reload, so the wait
/// is bounded: past this, finishing the reload matters more than the last
/// stragglers. nginx has the same knob as `worker_shutdown_timeout`.
const GRACEFUL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn shutdown_signal() -> Stop {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut quit = signal(SignalKind::quit()).ok();
        let mut term = signal(SignalKind::terminate()).ok();
        // Reopening logs must not end the run, so it loops rather than
        // returning: a worker can be told to reopen any number of times and
        // keep serving.
        let mut usr1 = signal(SignalKind::user_defined1()).ok();
        loop {
            let quit_fut = async {
                match quit.as_mut() {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            let term_fut = async {
                match term.as_mut() {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            let usr1_fut = async {
                match usr1.as_mut() {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = quit_fut => return Stop::Graceful,
                _ = term_fut => return Stop::Now,
                _ = tokio::signal::ctrl_c() => return Stop::Now,
                _ = usr1_fut => {
                    // The next line written reopens the file, so a rotated log
                    // stops being written to the moved inode.
                    REOPEN_LOGS.store(true, Ordering::Release);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        Stop::Now
    }
}

/// Set by `SIGUSR1`; the logging layer clears it when it has reopened.
pub static REOPEN_LOGS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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

/// Collects every certificate on `l` into one SNI resolver.
///
/// Shared by the TCP and QUIC config builders: a `server` block names its
/// certificate once, and which transport serves it is not that directive's
/// business. Returns `None` when the listener has no certificate at all.
fn sni_resolver_for(l: &Listener) -> io::Result<Option<SniResolver>> {
    let mut resolver = SniResolver::default();
    for s in &l.servers {
        let Some(t) = &s.tls else { continue };
        let key = load_certified_key(&t.cert, &t.key)?;
        let names: Vec<String> = s
            .names
            .iter()
            .filter_map(|n| match n {
                crate::config::model::ServerName::Exact(e) if !e.is_empty() => Some(e.to_string()),
                crate::config::model::ServerName::LeadingWildcard(x) => Some(format!("*.{x}")),
                _ => None,
            })
            .collect();
        resolver.add(names, Arc::new(key));
    }
    Ok(if resolver.is_empty() { None } else { Some(resolver) })
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
        let Some(resolver) = sni_resolver_for(l)? else {
            out.push(None);
            continue;
        };

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

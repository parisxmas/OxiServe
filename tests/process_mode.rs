//! Process-mode tests, driven through the compiled binary.
//!
//! Fork mode cannot be tested in-process: `cargo test` binaries are heavily
//! multi-threaded, and forking one mid-run clones whatever locks other test
//! threads happen to hold. The real server never has that problem — the
//! master forks before it spawns anything — so these tests exercise exactly
//! that shape by running the real binary.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(21500);

struct Master {
    child: Child,
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Master {
    fn start(name: &str, body: &str) -> Master {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("oxiserve-pm-{}-{name}", std::process::id()));
        std::fs::create_dir_all(dir.join("www")).unwrap();
        std::fs::write(dir.join("www/index.html"), b"process-mode-ok").unwrap();
        let conf = format!(
            "worker_processes 2;\nerror_log {d}/error.log info;\n\
             events {{ worker_connections 256; }}\nhttp {{ access_log off;\n{body}\n}}",
            d = dir.display()
        )
        .replace("{PORT}", &port.to_string())
        .replace("{ROOT}", dir.join("www").to_str().unwrap());
        let cpath = dir.join("oxiserve.conf");
        std::fs::write(&cpath, conf).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_oxiserve"))
            .arg("-c")
            .arg(&cpath)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn oxiserve binary");

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Master { child, port, dir };
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        panic!("master never came up");
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn worker_pids(&self) -> Vec<i32> {
        let out = Command::new("pgrep").arg("-P").arg(self.pid().to_string()).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    /// One request on a fresh connection.
    fn get(&self, path: &str) -> (u16, String) {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        let status =
            resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        // SIGTERM first so the supervisor path runs; SIGKILL as the backstop.
        unsafe { libc::kill(self.pid(), libc::SIGTERM) };
        std::thread::sleep(Duration::from_millis(300));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gone(pids: &[i32], within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if pids.iter().all(|p| unsafe { libc::kill(*p, 0) } != 0) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

const STATIC: &str =
    "server { listen {PORT} reuseport; root {ROOT}; location / { index index.html; } }";

#[test]
fn two_workers_really_are_two_processes() {
    let m = Master::start("procs", STATIC);
    let workers = m.worker_pids();
    assert_eq!(workers.len(), 2, "expected 2 forked workers, found {workers:?}");
    let (status, body) = m.get("/");
    assert_eq!(status, 200);
    assert_eq!(body, "process-mode-ok");
}

#[test]
fn sigterm_to_the_master_takes_the_workers_with_it() {
    let m = Master::start("term", STATIC);
    let workers = m.worker_pids();
    assert_eq!(workers.len(), 2);
    unsafe { libc::kill(m.pid(), libc::SIGTERM) };
    assert!(gone(&workers, Duration::from_secs(5)), "workers survived the master's SIGTERM");
}

/// The supervisor's job: a worker that dies is replaced, and service holds.
#[test]
fn a_killed_worker_is_respawned() {
    let m = Master::start("respawn", STATIC);
    let before = m.worker_pids();
    assert_eq!(before.len(), 2);
    unsafe { libc::kill(before[0], libc::SIGKILL) };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = m.worker_pids();
        if now.len() == 2 && now.iter().any(|p| !before.contains(p)) {
            break;
        }
        assert!(Instant::now() < deadline, "no replacement worker appeared: {now:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
    let (status, _) = m.get("/");
    assert_eq!(status, 200, "service must hold across a worker death");
}

/// PDEATHSIG: even a SIGKILLed master — which never runs its supervisor
/// cleanup — must not leave orphaned workers holding the port.
#[cfg(target_os = "linux")]
#[test]
fn workers_die_with_a_sigkilled_master() {
    let m = Master::start("orphan", STATIC);
    let workers = m.worker_pids();
    assert_eq!(workers.len(), 2);
    unsafe { libc::kill(m.pid(), libc::SIGKILL) };
    assert!(gone(&workers, Duration::from_secs(5)), "orphaned workers survived: {workers:?}");
}

/// The reason limit_req moved into MAP_SHARED memory: with per-process
/// buckets, every configured rate silently multiplies by the worker count.
/// At 1r/m across 30 fresh connections spread over both workers by reuseport,
/// one shared bucket admits exactly one request; two private buckets admit
/// one per worker.
#[test]
fn a_rate_limit_is_one_limit_across_worker_processes() {
    let m = Master::start(
        "shmlimit",
        "limit_req_zone $binary_remote_addr zone=pm:1m rate=1r/m;\n\
         server { listen {PORT} reuseport; root {ROOT};\n\
             location / { limit_req zone=pm; index index.html; } }",
    );
    assert_eq!(m.worker_pids().len(), 2);

    let mut passed = 0;
    for _ in 0..30 {
        // Each iteration is a fresh connection with a fresh source port, so
        // the reuseport hash spreads them across both workers.
        let (status, _) = m.get("/");
        if status == 200 {
            passed += 1;
        }
    }
    assert_eq!(
        passed, 1,
        "1r/m must admit exactly one request across BOTH workers; \
         2 would mean each process kept a private bucket"
    );
}

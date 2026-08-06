//! `-s reload` / `quit` / `stop` / `reopen`, driven through the compiled
//! binary.
//!
//! Signal handling belongs to the master process, so nothing here can be
//! tested in-process: a `cargo test` binary has no master, and forking one
//! mid-run would clone whatever the other test threads hold.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(21800);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

struct Master {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Master {
    /// Starts a master serving `body` as the response text.
    fn start(name: &str, body: &str) -> Master {
        let p = port();
        let dir = std::env::temp_dir()
            .join(format!("oxiserve-rl-{}-{name}-{p}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let m = Master {
            // Placeholder replaced below; `Child` has no cheap dummy.
            child: Command::new("true").spawn().unwrap(),
            port: p,
            dir,
        };
        m.write_conf(body);
        let mut m = m;
        m.child = m.spawn_binary();
        m.wait_ready();
        m
    }

    fn conf_path(&self) -> PathBuf {
        self.dir.join("oxiserve.conf")
    }

    fn write_conf(&self, body: &str) {
        std::fs::write(
            self.dir.join("oxiserve.conf"),
            format!(
                "worker_processes 2;\n\
                 pid {d}/oxiserve.pid;\n\
                 error_log {d}/error.log info;\n\
                 events {{ worker_connections 128; }}\n\
                 http {{\n\
                   access_log {d}/access.log;\n\
                   server {{ listen {p} reuseport;\n\
                     location / {{ return 200 \"{body}\"; }}\n\
                     location /slow {{ return 200 \"slow-{body}\"; }}\n\
                   }} }}\n",
                d = self.dir.display(),
                p = self.port,
                body = body
            ),
        )
        .unwrap();
    }

    /// Writes a configuration that cannot possibly load.
    fn write_broken_conf(&self) {
        std::fs::write(
            self.conf_path(),
            "worker_processes 2;\nevents { worker_connections 128; }\n\
             http { server { listen ; location / { return 200 \"x\"; } } }\n",
        )
        .unwrap();
    }

    fn spawn_binary(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_oxiserve"))
            .arg("-c")
            .arg(self.conf_path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn oxiserve")
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
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

    /// Runs `oxiserve -s <signal>` against this master's configuration, which
    /// is how an operator does it — via the pid file, not a remembered pid.
    fn signal(&self, sig: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_oxiserve"))
            .arg("-c")
            .arg(self.conf_path())
            .arg("-s")
            .arg(sig)
            .output()
            .expect("run oxiserve -s")
    }

    fn get(&self, path: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }

    /// Polls until the body matches, so a test is not racing the handover.
    fn wait_for_body(&self, want: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.get("/") == want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        false
    }
}

impl Master {
    /// Waits for the master itself to exit.
    ///
    /// Not `kill(pid, 0)`: a process that has exited but not been reaped is a
    /// zombie, and a zombie still answers that signal successfully. Only the
    /// parent reaping it can tell the difference, which is what `try_wait`
    /// does.
    fn wait_exit(&mut self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return false,
            }
        }
        false
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        unsafe { libc::kill(self.pid(), libc::SIGTERM) };
        std::thread::sleep(Duration::from_millis(300));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn gone(pids: &[i32], within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if pids.iter().all(|p| !alive(*p)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------------------

#[test]
fn the_master_writes_its_pid_file_and_removes_it_on_exit() {
    let m = Master::start("pidfile", "one");
    let pf = m.dir.join("oxiserve.pid");
    let text = std::fs::read_to_string(&pf).expect("pid file must exist");
    assert_eq!(text.trim().parse::<i32>().unwrap(), m.pid());

    unsafe { libc::kill(m.pid(), libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && pf.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!pf.exists(), "the pid file must not outlive the master");
}

#[test]
fn reload_swaps_the_configuration_and_replaces_the_workers() {
    let m = Master::start("swap", "before");
    assert_eq!(m.get("/"), "before");
    let old = m.worker_pids();
    assert_eq!(old.len(), 2);

    m.write_conf("after");
    let out = m.signal("reload");
    assert!(out.status.success(), "-s reload failed: {out:?}");

    assert!(m.wait_for_body("after", Duration::from_secs(5)), "config never took effect");
    assert!(gone(&old, Duration::from_secs(5)), "the old workers never drained");
    let new = m.worker_pids();
    assert_eq!(new.len(), 2, "expected 2 workers after reload, got {new:?}");
    assert!(new.iter().all(|p| !old.contains(p)), "workers were not replaced");
}

/// The property that makes reload safer than restart: a configuration that
/// does not load must cost a log line and nothing else.
#[test]
fn a_broken_configuration_leaves_the_running_server_untouched() {
    let m = Master::start("broken", "good");
    assert_eq!(m.get("/"), "good");
    let before = m.worker_pids();
    assert_eq!(before.len(), 2);

    m.write_broken_conf();
    // `-s reload` itself fails, because the CLI has to parse the config to
    // find the pid file — so signal the master directly, which is the case
    // that matters: a config edited badly between a good start and a reload.
    unsafe { libc::kill(m.pid(), libc::SIGHUP) };
    std::thread::sleep(Duration::from_millis(800));

    assert!(alive(m.pid()), "the master must survive a bad reload");
    let after = m.worker_pids();
    assert_eq!(after, before, "workers must not be replaced by a config that does not load");
    assert_eq!(m.get("/"), "good", "the old configuration must keep serving");
}

/// A reload must not cut a request that is already being served.
#[test]
fn a_request_in_flight_survives_a_reload() {
    let m = Master::start("inflight", "before");
    // Open a connection and send only a partial request, so the worker is
    // holding it when the reload lands.
    let mut c = TcpStream::connect(("127.0.0.1", m.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\n").unwrap();
    c.flush().unwrap();
    std::thread::sleep(Duration::from_millis(200));

    m.write_conf("after");
    assert!(m.signal("reload").status.success());
    std::thread::sleep(Duration::from_millis(200));

    // Finish the request the old worker is still holding.
    c.write_all(b"Connection: close\r\n\r\n").unwrap();
    c.flush().unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "in-flight request was dropped: {resp:?}");
    assert!(
        resp.ends_with("slow-before"),
        "it must be finished by the OLD configuration it started under: {resp:?}"
    );

    // And new requests get the new configuration.
    assert!(m.wait_for_body("after", Duration::from_secs(5)));
}

#[test]
fn reopen_makes_the_workers_write_to_a_rotated_log_again() {
    let m = Master::start("reopen", "logged");
    let log = m.dir.join("access.log");
    m.get("/");
    m.get("/");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !log.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }

    // Rotate: an open descriptor keeps writing to the renamed inode, which is
    // exactly the problem `reopen` solves.
    let rotated = m.dir.join("access.log.1");
    std::fs::rename(&log, &rotated).unwrap();
    assert!(m.signal("reopen").status.success());
    std::thread::sleep(Duration::from_millis(400));

    for _ in 0..5 {
        m.get("/after-rotation");
    }
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut fresh = String::new();
    while Instant::now() < deadline {
        fresh = std::fs::read_to_string(&log).unwrap_or_default();
        if fresh.contains("/after-rotation") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let rotated_text = std::fs::read_to_string(&rotated).unwrap_or_default();
    assert!(
        fresh.contains("/after-rotation"),
        "post-rotation requests must land in the new file.\n  new: {fresh:?}\n  rotated: {rotated_text:?}\n  dir: {:?}",
        std::fs::read_dir(&m.dir).unwrap().filter_map(|e| e.ok().map(|e| e.file_name())).collect::<Vec<_>>()
    );
}

#[test]
fn quit_drains_and_stop_is_immediate() {
    let mut m = Master::start("quit", "bye");
    let workers = m.worker_pids();
    assert_eq!(workers.len(), 2);
    assert!(m.signal("quit").status.success());
    assert!(gone(&workers, Duration::from_secs(5)), "quit must end the workers");
    assert!(m.wait_exit(Duration::from_secs(5)), "quit must end the master");

    let m2 = Master::start("stop", "bye");
    let w2 = m2.worker_pids();
    assert!(m2.signal("stop").status.success());
    assert!(gone(&w2, Duration::from_secs(5)), "stop must end the workers");
}

#[test]
fn an_unknown_signal_name_is_refused() {
    let m = Master::start("badsig", "x");
    let out = m.signal("frobnicate");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("frobnicate"), "the message should name it: {err}");
}

#[test]
fn signalling_with_no_pid_directive_says_so() {
    // Without `pid`, there is no file to read and nothing to signal — an error
    // worth naming rather than a silent no-op.
    let dir = std::env::temp_dir().join(format!("oxiserve-rl-nopid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf: &Path = &dir.join("c.conf");
    std::fs::write(
        conf,
        "events { worker_connections 8; }\nhttp { server { listen 21999; location / { return 200 \"x\"; } } }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_oxiserve"))
        .arg("-c")
        .arg(conf)
        .arg("-s")
        .arg("reload")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("pid"), "got: {err}");
}

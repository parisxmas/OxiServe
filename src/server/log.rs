//! Access and error logging.
//!
//! Log files are owned per worker and written with buffering, so a request
//! that logs does not pay a syscall. nginx's `buffer=`/`flush=` parameters map
//! directly onto the buffer size and the maximum age of an unflushed line.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::model::{AccessLogConf, ErrorLogConf, LogLevel, LogSink};

struct Sink {
    file: File,
    buf: Vec<u8>,
    /// Flush once the buffer passes this size. Zero means unbuffered.
    cap: usize,
    flush_every: Option<Duration>,
    last_flush: Instant,
    /// Kept so the file can be opened again by name after a rotation.
    path: PathBuf,
}

impl Sink {
    fn open(path: &Path, cap: usize, flush_every: Option<Duration>) -> std::io::Result<Sink> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Sink {
            file,
            buf: Vec::with_capacity(cap.max(4096)),
            cap,
            flush_every,
            last_flush: Instant::now(),
            path: path.to_path_buf(),
        })
    }

    /// Reopens the file by name, after flushing what is buffered.
    ///
    /// This is what makes `logrotate` work: once the file is moved aside, an
    /// open descriptor keeps writing to the renamed inode, so the new file
    /// stays empty and disk is never reclaimed. Reopening by path lands on
    /// whatever the name refers to now, and the flush first means the lines
    /// already formatted go to the old file rather than being lost.
    fn reopen(&mut self) {
        self.flush();
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(&self.path) {
            self.file = f;
        }
    }

    fn write_line(&mut self, line: &[u8]) {
        if self.cap == 0 {
            // One write, not two. Worker processes append to the same file, so
            // a second `write_all` for the newline leaves a window in which
            // another process's line lands between a record and its terminator
            // and the two run together. `buf` is reused as scratch rather than
            // allocating, since an unbuffered access log takes this path on
            // every request.
            self.buf.clear();
            self.buf.extend_from_slice(line);
            self.buf.push(b'\n');
            let _ = self.file.write_all(&self.buf);
            self.buf.clear();
            return;
        }
        self.buf.extend_from_slice(line);
        self.buf.push(b'\n');
        if self.buf.len() >= self.cap {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.buf.is_empty() {
            let _ = self.file.write_all(&self.buf);
            self.buf.clear();
        }
        self.last_flush = Instant::now();
    }

    fn flush_if_due(&mut self) {
        if let Some(every) = self.flush_every {
            if !self.buf.is_empty() && self.last_flush.elapsed() >= every {
                self.flush();
            }
        }
    }
}

/// Fire-and-forget UDP sink for OxiDB's MessagePack ingest.
///
/// `send_to` on a connectionless socket hands the datagram to the kernel and
/// returns; there is no handshake, no ack, and no retry. A collector that is
/// down or slow therefore cannot slow a request down — the packet is simply
/// lost, which is the right trade for access logs and is what ADR-0002 means
/// by keeping the store off the request path.
struct UdpSink {
    socket: std::net::UdpSocket,
    addr: String,
    /// Datagrams the kernel refused, so the loss is visible rather than silent.
    dropped: u64,
}

impl UdpSink {
    fn new(addr: &str) -> std::io::Result<UdpSink> {
        // Bind to an ephemeral port on the matching family.
        let bind: &str = if addr.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
        let socket = std::net::UdpSocket::bind(bind)?;
        // Never block a worker: a full send buffer drops the record instead.
        socket.set_nonblocking(true)?;
        Ok(UdpSink { socket, addr: addr.to_string(), dropped: 0 })
    }

    fn send(&mut self, payload: &[u8]) {
        if self.socket.send_to(payload, &self.addr).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

pub struct Logs {
    access: HashMap<PathBuf, Sink>,
    udp: HashMap<String, UdpSink>,
    error: Option<Sink>,
    error_level: LogLevel,
    error_to_stderr: bool,
    /// Reused across log lines so formatting allocates nothing steady-state.
    scratch: String,
}

impl Logs {
    pub fn new(err: &ErrorLogConf) -> Logs {
        let to_stderr = err.path.as_os_str() == "stderr"
            || err.path.as_os_str() == "/dev/stderr";
        let sink = if err.disabled || to_stderr {
            None
        } else {
            // An unopenable error log is itself worth reporting, but there is
            // nowhere to report it to except stderr.
            match Sink::open(&err.path, 0, None) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("oxiserve: cannot open error log {}: {e}", err.path.display());
                    None
                }
            }
        };
        // If the configured file could not be opened, errors still need to go
        // somewhere — stderr is the only remaining option.
        let error_to_stderr = !err.disabled && sink.is_none();
        Logs {
            access: HashMap::new(),
            udp: HashMap::new(),
            error: sink,
            error_level: err.level,
            error_to_stderr,
            scratch: String::with_capacity(1024),
        }
    }

    /// Pre-opens every access log a config references, so the first request
    /// does not pay for an open (and so a bad path fails at startup).
    pub fn open_access(&mut self, confs: &[AccessLogConf]) {
        for c in confs {
            match &c.sink {
                LogSink::File(path) => {
                    if self.access.contains_key(path) {
                        continue;
                    }
                    match Sink::open(path, c.buffer, c.flush) {
                        Ok(s) => {
                            self.access.insert(path.clone(), s);
                        }
                        Err(e) => {
                            eprintln!("oxiserve: cannot open access log {}: {e}", path.display());
                        }
                    }
                }
                LogSink::OxiDb { addr, .. } => {
                    if self.udp.contains_key(&**addr) {
                        continue;
                    }
                    match UdpSink::new(addr) {
                        Ok(s) => {
                            self.udp.insert(addr.to_string(), s);
                        }
                        Err(e) => {
                            eprintln!("oxiserve: cannot open oxidb log socket {addr}: {e}");
                        }
                    }
                }
            }
        }
    }

    pub fn access(&mut self, conf: &AccessLogConf, line: &str) {
        self.reopen_if_asked();
        if let LogSink::File(path) = &conf.sink {
            if let Some(s) = self.access.get_mut(path) {
                s.write_line(line.as_bytes());
            }
        }
    }

    /// Sends an already-encoded MessagePack record to an OxiDB sink.
    pub fn access_oxidb(&mut self, addr: &str, payload: &[u8]) {
        if let Some(s) = self.udp.get_mut(addr) {
            s.send(payload);
        }
    }

    /// Datagrams dropped for a sink. Test and introspection hook.
    pub fn dropped(&self, addr: &str) -> u64 {
        self.udp.get(addr).map(|s| s.dropped).unwrap_or(0)
    }

    pub fn scratch(&mut self) -> &mut String {
        self.scratch.clear();
        &mut self.scratch
    }

    pub fn error(&mut self, level: LogLevel, msg: &str) {
        self.reopen_if_asked();
        if level < self.error_level {
            return;
        }
        let mut line = String::with_capacity(msg.len() + 64);
        crate::http::date::append_time_local(&mut line);
        line.push_str(" [");
        line.push_str(level.as_str());
        line.push_str("] ");
        crate::http::response::push_num(&mut line, std::process::id() as u64);
        line.push_str(": ");
        line.push_str(msg);

        match &mut self.error {
            Some(s) => s.write_line(line.as_bytes()),
            None => {
                if self.error_to_stderr {
                    eprintln!("{line}");
                }
            }
        }
    }

    pub fn flush_due(&mut self) {
        for s in self.access.values_mut() {
            s.flush_if_due();
        }
    }

    /// Reopens every log file, if `SIGUSR1` asked for it since the last check.
    ///
    /// Polled rather than done in the signal handler, where almost nothing is
    /// safe to call — but polled *before every line*, not only on the flush
    /// timer. Deferring it to the timer left a window after `-s reopen` in
    /// which lines still went to the renamed inode, which is precisely the
    /// data `logrotate` expects to have stopped arriving there.
    ///
    /// The common case is one relaxed load of a `bool`, so the check costs
    /// nothing worth measuring per line.
    #[inline]
    pub fn reopen_if_asked(&mut self) {
        use std::sync::atomic::Ordering;
        if !crate::server::REOPEN_LOGS.load(Ordering::Relaxed) {
            return;
        }
        if !crate::server::REOPEN_LOGS.swap(false, Ordering::AcqRel) {
            return;
        }
        for s in self.access.values_mut() {
            s.reopen();
        }
        if let Some(e) = &mut self.error {
            e.reopen();
        }
    }

    pub fn flush_all(&mut self) {
        for s in self.access.values_mut() {
            s.flush();
        }
        if let Some(s) = &mut self.error {
            s.flush();
        }
    }
}

impl Drop for Logs {
    fn drop(&mut self) {
        self.flush_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oxiserve-log-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Records must never run together when several worker *processes* append
    /// to one log.
    ///
    /// This is what a two-`write_all` unbuffered path gets wrong: a child can
    /// land between a record and its newline, and the two merge into a line no
    /// parser can split. The check is one-sided by construction — a malformed
    /// line is always a real bug, while a clean run only means this scheduling
    /// did not hit the window — so it can fail honestly but never spuriously.
    #[cfg(unix)]
    #[test]
    fn concurrent_processes_never_merge_two_records() {
        const KIDS: usize = 4;
        const LINES: usize = 200;

        let d = tmpdir("interleave");
        let p = d.join("shared.log");
        // Every child inherits its own O_APPEND descriptor, exactly as forked
        // workers do.
        std::fs::write(&p, b"").unwrap();

        let mut pids = Vec::new();
        for k in 0..KIDS {
            // The line is built before the fork so the child allocates nothing.
            let line = format!("child-{k}-{}", "x".repeat(64)).into_bytes();
            match unsafe { libc::fork() } {
                0 => {
                    let mut sink = Sink::open(&p, 0, None).unwrap();
                    for _ in 0..LINES {
                        sink.write_line(&line);
                    }
                    unsafe { libc::_exit(0) };
                }
                pid if pid > 0 => pids.push(pid),
                _ => panic!("fork failed: {}", std::io::Error::last_os_error()),
            }
        }
        for pid in pids {
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        }

        let text = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for l in &lines {
            assert!(
                l.starts_with("child-") && l.len() == "child-0-".len() + 64,
                "two records merged into one line: {l:?}"
            );
        }
        assert_eq!(lines.len(), KIDS * LINES, "every record must appear exactly once");
    }

    #[test]
    fn unbuffered_writes_land_immediately() {
        let d = tmpdir("unbuf");
        let p = d.join("a.log");
        let mut s = Sink::open(&p, 0, None).unwrap();
        s.write_line(b"hello");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello\n");
    }

    #[test]
    fn buffered_writes_wait_for_the_threshold() {
        let d = tmpdir("buf");
        let p = d.join("b.log");
        let mut s = Sink::open(&p, 64, None).unwrap();
        s.write_line(b"one");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "", "should still be buffered");
        // Push past the 64-byte cap.
        for _ in 0..10 {
            s.write_line(b"0123456789");
        }
        let contents = std::fs::read_to_string(&p).unwrap();
        assert!(contents.starts_with("one\n"), "{contents:?}");
    }

    #[test]
    fn flush_writes_the_remainder() {
        let d = tmpdir("flush");
        let p = d.join("c.log");
        let mut s = Sink::open(&p, 4096, None).unwrap();
        s.write_line(b"pending");
        s.flush();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "pending\n");
    }

    #[test]
    fn logs_are_created_with_their_parent_directory() {
        let d = tmpdir("mkdir");
        let p = d.join("nested/deep/d.log");
        let mut s = Sink::open(&p, 0, None).unwrap();
        s.write_line(b"x");
        assert!(p.exists());
    }

    #[test]
    fn error_level_filtering() {
        let d = tmpdir("level");
        let p = d.join("e.log");
        let mut l = Logs::new(&ErrorLogConf {
            path: p.clone(),
            level: LogLevel::Error,
            disabled: false,
        });
        l.error(LogLevel::Info, "quiet");
        l.error(LogLevel::Error, "loud");
        l.flush_all();
        let c = std::fs::read_to_string(&p).unwrap();
        assert!(!c.contains("quiet"), "{c}");
        assert!(c.contains("loud"), "{c}");
        assert!(c.contains("[error]"), "{c}");
    }
}

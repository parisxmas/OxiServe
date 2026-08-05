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

use crate::config::model::{AccessLogConf, ErrorLogConf, LogLevel};

struct Sink {
    file: File,
    buf: Vec<u8>,
    /// Flush once the buffer passes this size. Zero means unbuffered.
    cap: usize,
    flush_every: Option<Duration>,
    last_flush: Instant,
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
        })
    }

    fn write_line(&mut self, line: &[u8]) {
        if self.cap == 0 {
            let _ = self.file.write_all(line);
            let _ = self.file.write_all(b"\n");
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

pub struct Logs {
    access: HashMap<PathBuf, Sink>,
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
            if self.access.contains_key(&c.path) {
                continue;
            }
            match Sink::open(&c.path, c.buffer, c.flush) {
                Ok(s) => {
                    self.access.insert(c.path.clone(), s);
                }
                Err(e) => {
                    eprintln!("oxiserve: cannot open access log {}: {e}", c.path.display());
                }
            }
        }
    }

    pub fn access(&mut self, conf: &AccessLogConf, line: &str) {
        if let Some(s) = self.access.get_mut(&conf.path) {
            s.write_line(line.as_bytes());
        }
    }

    pub fn scratch(&mut self) -> &mut String {
        self.scratch.clear();
        &mut self.scratch
    }

    pub fn error(&mut self, level: LogLevel, msg: &str) {
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

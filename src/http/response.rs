//! Response head construction.
//!
//! Headers accumulate into a per-connection string arena and are recorded as
//! ranges, so building a response allocates nothing once the connection has
//! warmed up. `write_head` then serialises the whole head into a single
//! contiguous buffer, which the connection writes together with the body via
//! `writev` — one syscall for a small static response.

use std::ops::Range;

use super::date;
use super::status;
use crate::config::model::ServerTokens;

/// What frames the response body on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `Content-Length: n`
    Length(u64),
    /// `Transfer-Encoding: chunked`
    Chunked,
    /// Body runs until the connection closes (HTTP/1.0 style).
    UntilClose,
    /// No body at all (204/304/HEAD).
    None,
}

pub struct Resp {
    pub status: u16,
    /// Reused scratch space holding every header name and value.
    arena: String,
    hdrs: Vec<(Range<usize>, Range<usize>)>,
    pub framing: Framing,
    pub keep_alive: bool,
    /// Bytes of body actually written — the `$body_bytes_sent` log variable.
    pub body_bytes: u64,
}

pub const SERVER_NAME: &str = "oxiserve";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

impl Default for Resp {
    fn default() -> Self {
        Resp::new()
    }
}

impl Resp {
    pub fn new() -> Resp {
        Resp {
            status: 200,
            arena: String::with_capacity(1024),
            hdrs: Vec::with_capacity(16),
            framing: Framing::None,
            keep_alive: true,
            body_bytes: 0,
        }
    }

    pub fn reset(&mut self) {
        self.status = 200;
        self.arena.clear();
        self.hdrs.clear();
        self.framing = Framing::None;
        self.keep_alive = true;
        self.body_bytes = 0;
    }

    pub fn header(&mut self, name: &str, value: &str) {
        let ns = self.arena.len();
        self.arena.push_str(name);
        let vs = self.arena.len();
        self.arena.push_str(value);
        self.hdrs.push((ns..vs, vs..self.arena.len()));
    }

    pub fn header_num(&mut self, name: &str, value: u64) {
        let ns = self.arena.len();
        self.arena.push_str(name);
        let vs = self.arena.len();
        push_num(&mut self.arena, value);
        self.hdrs.push((ns..vs, vs..self.arena.len()));
    }

    /// Builds a value in place, for headers assembled from several pieces
    /// (`Content-Range`, `ETag`) without a temporary `String`.
    pub fn header_with(&mut self, name: &str, f: impl FnOnce(&mut String)) {
        let ns = self.arena.len();
        self.arena.push_str(name);
        let vs = self.arena.len();
        f(&mut self.arena);
        self.hdrs.push((ns..vs, vs..self.arena.len()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.hdrs
            .iter()
            .find(|(n, _)| self.arena[n.clone()].eq_ignore_ascii_case(name))
            .map(|(_, v)| &self.arena[v.clone()])
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Removes every instance of a header (used by `proxy_hide_header`).
    pub fn remove(&mut self, name: &str) {
        let arena = &self.arena;
        self.hdrs
            .retain(|(n, _)| !arena[n.clone()].eq_ignore_ascii_case(name));
    }

    /// Replaces a header if present, otherwise appends it.
    pub fn set(&mut self, name: &str, value: &str) {
        self.remove(name);
        self.header(name, value);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.hdrs
            .iter()
            .map(|(n, v)| (&self.arena[n.clone()], &self.arena[v.clone()]))
    }

    /// Serialises the status line and all headers into `out`.
    ///
    /// `Date`, `Server`, `Content-Length`/`Transfer-Encoding` and `Connection`
    /// are emitted here rather than stored, so handlers cannot forget them and
    /// cannot duplicate them.
    pub fn write_head(&self, out: &mut Vec<u8>, tokens: ServerTokens) {
        match status::status_line(self.status) {
            Some(l) => out.extend_from_slice(l.as_bytes()),
            None => {
                out.extend_from_slice(b"HTTP/1.1 ");
                let mut n = String::new();
                push_num(&mut n, self.status as u64);
                out.extend_from_slice(n.as_bytes());
                out.push(b' ');
                out.extend_from_slice(status::reason(self.status).as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }

        if !self.has("server") {
            match tokens {
                ServerTokens::On => {
                    out.extend_from_slice(b"Server: ");
                    out.extend_from_slice(SERVER_NAME.as_bytes());
                    out.push(b'/');
                    out.extend_from_slice(VERSION.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
                ServerTokens::Build | ServerTokens::Off => {
                    out.extend_from_slice(b"Server: ");
                    out.extend_from_slice(SERVER_NAME.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }

        if !self.has("date") {
            out.extend_from_slice(b"Date: ");
            let mut d = String::with_capacity(29);
            date::append_http_date(&mut d);
            out.extend_from_slice(d.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        match self.framing {
            Framing::Length(n) => {
                out.extend_from_slice(b"Content-Length: ");
                let mut s = String::new();
                push_num(&mut s, n);
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
            Framing::UntilClose | Framing::None => {}
        }

        // A `101` carries its own `Connection: Upgrade`, set by whoever built
        // the switch. Adding ours would put two contradictory `Connection`
        // headers on the same response — "close" and "Upgrade" — which is
        // exactly the sort of thing a strict client rejects and a lenient one
        // acts on unpredictably.
        if self.status != 101 {
            out.extend_from_slice(if self.keep_alive {
                b"Connection: keep-alive\r\n".as_slice()
            } else {
                b"Connection: close\r\n".as_slice()
            });
        }

        for (n, v) in self.iter() {
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
    }

    /// The `oxiserve/x.y.z` string used in default error page footers.
    pub fn signature(tokens: ServerTokens) -> Option<String> {
        match tokens {
            ServerTokens::On => Some(format!("{SERVER_NAME}/{VERSION}")),
            ServerTokens::Build => Some(SERVER_NAME.to_string()),
            ServerTokens::Off => None,
        }
    }
}

/// Appends a decimal integer without going through `format!`.
pub fn push_num(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // SAFETY: every byte written above is an ASCII digit.
    out.push_str(unsafe { std::str::from_utf8_unchecked(&buf[i..]) });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(r: &Resp) -> String {
        let mut v = Vec::new();
        r.write_head(&mut v, ServerTokens::On);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn num_formatting() {
        let mut s = String::new();
        push_num(&mut s, 0);
        push_num(&mut s, 1);
        push_num(&mut s, 1234567890);
        push_num(&mut s, u64::MAX);
        assert_eq!(s, format!("0{}{}{}", 1, 1234567890u64, u64::MAX));
    }

    #[test]
    fn basic_head() {
        let mut r = Resp::new();
        r.framing = Framing::Length(5);
        r.header("Content-Type", "text/plain");
        let h = head(&r);
        assert!(h.starts_with("HTTP/1.1 200 OK\r\n"), "{h}");
        assert!(h.contains("Content-Length: 5\r\n"), "{h}");
        assert!(h.contains("Content-Type: text/plain\r\n"), "{h}");
        assert!(h.contains("Connection: keep-alive\r\n"), "{h}");
        assert!(h.contains("Server: oxiserve/"), "{h}");
        assert!(h.contains("Date: "), "{h}");
        assert!(h.ends_with("\r\n\r\n"), "{h}");
    }

    #[test]
    fn server_tokens_off_shortens_the_banner() {
        let r = Resp::new();
        let mut v = Vec::new();
        r.write_head(&mut v, ServerTokens::Off);
        let h = String::from_utf8(v).unwrap();
        assert!(h.contains("Server: oxiserve\r\n"), "{h}");
        assert!(!h.contains("oxiserve/"), "{h}");
    }

    #[test]
    fn chunked_framing_header() {
        let mut r = Resp::new();
        r.framing = Framing::Chunked;
        assert!(head(&r).contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn close_is_signalled() {
        let mut r = Resp::new();
        r.keep_alive = false;
        assert!(head(&r).contains("Connection: close\r\n"));
    }

    #[test]
    fn a_protocol_switch_gets_exactly_one_connection_header() {
        // The switch names `Upgrade`; the writer must not also announce the
        // close it is otherwise about to do.
        let mut r = Resp::new();
        r.status = 101;
        r.keep_alive = false;
        r.framing = Framing::None;
        r.header("Upgrade", "websocket");
        r.header("Connection", "Upgrade");
        let h = head(&r);
        assert_eq!(h.matches("Connection:").count(), 1, "in: {h}");
        assert!(h.contains("Connection: Upgrade\r\n"));
        assert!(!h.contains("Content-Length"), "a switch has no body to measure");
    }

    #[test]
    fn get_set_remove() {
        let mut r = Resp::new();
        r.header("X-A", "1");
        r.header("X-B", "2");
        assert_eq!(r.get("x-a"), Some("1"));
        r.set("X-A", "9");
        assert_eq!(r.get("X-A"), Some("9"));
        assert_eq!(r.iter().count(), 2);
        r.remove("x-b");
        assert_eq!(r.get("X-B"), None);
        assert_eq!(r.iter().count(), 1);
    }

    #[test]
    fn duplicate_headers_are_preserved() {
        // Set-Cookie legitimately repeats.
        let mut r = Resp::new();
        r.header("Set-Cookie", "a=1");
        r.header("Set-Cookie", "b=2");
        let h = head(&r);
        assert_eq!(h.matches("Set-Cookie:").count(), 2, "{h}");
    }

    #[test]
    fn header_with_builds_in_place() {
        let mut r = Resp::new();
        r.header_with("Content-Range", |s| {
            s.push_str("bytes 0-99/");
            push_num(s, 1000);
        });
        assert_eq!(r.get("Content-Range"), Some("bytes 0-99/1000"));
    }

    #[test]
    fn handler_supplied_server_header_wins() {
        let mut r = Resp::new();
        r.header("Server", "custom");
        let h = head(&r);
        assert_eq!(h.matches("Server:").count(), 1, "{h}");
        assert!(h.contains("Server: custom"), "{h}");
    }

    #[test]
    fn unknown_status_is_formatted() {
        let mut r = Resp::new();
        r.status = 418;
        assert!(head(&r).starts_with("HTTP/1.1 418 Client Error\r\n"));
    }

    #[test]
    fn reset_clears_everything_but_keeps_capacity() {
        let mut r = Resp::new();
        r.header("X", "1");
        r.status = 500;
        let cap = r.arena.capacity();
        r.reset();
        assert_eq!(r.status, 200);
        assert_eq!(r.iter().count(), 0);
        assert_eq!(r.arena.capacity(), cap);
    }
}

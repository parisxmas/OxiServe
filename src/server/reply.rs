//! What a handler produces: a response head plus a body the connection knows
//! how to put on the wire.
//!
//! The body variants exist to keep copies out of the hot path. A small static
//! file is served straight from its memory map, so the bytes go from page
//! cache to socket without ever landing in a user-space buffer we allocated.

use std::ops::Range;
use std::sync::Arc;

use memmap2::Mmap;
use tokio::io::AsyncRead;

use crate::http::response::{Framing, Resp};

pub enum Body {
    Empty,
    /// Generated content: error pages, autoindex listings, `return` text.
    Bytes(Vec<u8>),
    /// A window into a memory-mapped file.
    Mmap { map: Arc<Mmap>, range: Range<usize> },
    /// A small file read directly into the connection's write buffer, so the
    /// head and body leave in a single `write`. Cheaper than mapping: `mmap` +
    /// `munmap` per request costs more than one `pread` at these sizes.
    /// `Arc` because the descriptor may be shared with the open-file cache;
    /// all reads use explicit offsets, never the shared file position.
    Inline { file: Arc<std::fs::File>, offset: u64, len: u64 },
    /// A file too large to map, streamed (or `sendfile`d) in chunks.
    File { file: Arc<std::fs::File>, offset: u64, len: u64 },
    /// A proxied upstream body. `pre` is whatever already arrived in the
    /// header read; `io` supplies the rest.
    Stream {
        pre: Vec<u8>,
        io: Box<dyn AsyncRead + Send + Unpin>,
        len: Option<u64>,
    },
}

impl Body {
    /// Byte length when known up front, which is what sets `Content-Length`.
    pub fn known_len(&self) -> Option<u64> {
        match self {
            Body::Empty => Some(0),
            Body::Bytes(b) => Some(b.len() as u64),
            Body::Mmap { range, .. } => Some(range.len() as u64),
            Body::Inline { len, .. } => Some(*len),
            Body::File { len, .. } => Some(*len),
            Body::Stream { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.known_len(), Some(0))
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Empty => write!(f, "Empty"),
            Body::Bytes(b) => write!(f, "Bytes({})", b.len()),
            Body::Mmap { range, .. } => write!(f, "Mmap({}..{})", range.start, range.end),
            Body::Inline { offset, len, .. } => write!(f, "Inline(@{offset}, {len})"),
            Body::File { offset, len, .. } => write!(f, "File(@{offset}, {len})"),
            Body::Stream { len, .. } => write!(f, "Stream({len:?})"),
        }
    }
}

pub struct Reply {
    pub resp: Resp,
    pub body: Body,
}

impl Reply {
    pub fn new(resp: Resp, body: Body) -> Reply {
        Reply { resp, body }
    }

    /// Sets `Content-Length` from the body when the length is known, otherwise
    /// falls back to chunked framing.
    ///
    /// A handler that already chose its framing keeps it — the proxy relies on
    /// this to forward an upstream's chunked body verbatim instead of having
    /// it decoded and re-encoded.
    pub fn frame(mut self, http11: bool) -> Reply {
        if crate::http::status::is_bodyless(self.resp.status) {
            self.body = Body::Empty;
            // 304 must not carry Content-Length; 204 must not either.
            self.resp.framing = Framing::None;
            return self;
        }
        if self.resp.framing != Framing::None {
            return self;
        }
        self.resp.framing = match self.body.known_len() {
            Some(n) => Framing::Length(n),
            None if http11 => Framing::Chunked,
            None => Framing::UntilClose,
        };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_reported_per_variant() {
        assert_eq!(Body::Empty.known_len(), Some(0));
        assert_eq!(Body::Bytes(vec![1, 2, 3]).known_len(), Some(3));
        assert_eq!(
            Body::File { file: Arc::new(std::fs::File::open("/dev/null").unwrap()), offset: 0, len: 99 }
                .known_len(),
            Some(99)
        );
    }

    #[test]
    fn framing_follows_the_body() {
        let r = Reply::new(Resp::new(), Body::Bytes(vec![0; 10])).frame(true);
        assert_eq!(r.resp.framing, Framing::Length(10));
    }

    #[test]
    fn bodyless_statuses_drop_the_body_and_the_length() {
        let mut resp = Resp::new();
        resp.status = 304;
        let r = Reply::new(resp, Body::Bytes(vec![0; 10])).frame(true);
        assert_eq!(r.resp.framing, Framing::None);
        assert!(r.body.is_empty());

        let mut resp = Resp::new();
        resp.status = 204;
        let r = Reply::new(resp, Body::Bytes(vec![0; 10])).frame(true);
        assert_eq!(r.resp.framing, Framing::None);
    }
}

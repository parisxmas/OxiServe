//! The per-connection state machine.
//!
//! One connection is handled start to finish on one worker thread, with a read
//! buffer and a write buffer that are reused across every keep-alive request.
//! The steady state for a small static file is: one `readv`, one `writev`
//! (head + mapped body), no allocation.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ctx::{Ctx, LogVars};
use crate::config::vars::VarSource;
use super::handler;
use super::log::Logs;
use super::reply::{Body, Reply};
use crate::config::model::{Http, Listener, ServerConf};
use crate::http::request::{ParseResult, Req};
use crate::http::response::{Framing, Resp};
use crate::http::{uri, Method};

/// Starting size of a connection's read buffer. Grows up to
/// `large_client_header_buffers` when a request head needs it.
const READ_BUF_INIT: usize = 8 * 1024;



/// Gives the write path access to the raw socket when the transport is plain
/// TCP. `sendfile(2)` needs a real file descriptor pair, and a TLS stream has
/// no such thing — the default implementation returns `None`, so TLS simply
/// takes the ordinary copy path.
pub trait RawStream {
    fn as_tcp(&self) -> Option<&tokio::net::TcpStream> {
        None
    }
}

impl RawStream for tokio::net::TcpStream {
    fn as_tcp(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }
}

impl<T: RawStream> RawStream for tokio_rustls::server::TlsStream<T> {
    fn as_tcp(&self) -> Option<&tokio::net::TcpStream> {
        // TLS records must be encrypted in user space, so sendfile can never
        // apply here regardless of the transport underneath.
        None
    }
}

pub struct ConnState {
    pub read: Vec<u8>,
    pub write: Vec<u8>,
    /// The decoded request body. Chunked encoding is resolved here, so
    /// handlers only ever see plain bytes.
    pub body: Vec<u8>,
    /// Bytes of `read` belonging to the current request (head + body).
    /// Draining is deferred until the response is written, because the parsed
    /// request holds byte ranges into `read` for its whole lifetime.
    pub consumed: usize,
    pub req: Req,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            read: Vec::with_capacity(READ_BUF_INIT),
            write: Vec::with_capacity(READ_BUF_INIT),
            body: Vec::new(),
            consumed: 0,
            req: Req::new(),
        }
    }
}

/// Drives one client connection to completion.
#[allow(clippy::too_many_arguments)]
pub async fn serve<S>(
    sock: S,
    listener: &Arc<Listener>,
    http: &Arc<Http>,
    logs: &Rc<RefCell<Logs>>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    scheme: &'static str,
    conn_id: u64,
) where
    S: AsyncRead + AsyncWrite + Unpin + RawStream,
{
    serve_with_prefix(sock, listener, http, logs, remote, local, scheme, conn_id, Vec::new()).await
}

/// [`serve`], but starting with bytes already read off the socket.
///
/// The cleartext HTTP/2 probe has to read the first bytes to tell a preface
/// from a request line. Those bytes belong to the request, so they are handed
/// back rather than discarded — anything else would truncate the request line
/// of every HTTP/1 client on a port that also offers h2c.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_prefix<S>(
    mut sock: S,
    listener: &Arc<Listener>,
    http: &Arc<Http>,
    logs: &Rc<RefCell<Logs>>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    scheme: &'static str,
    conn_id: u64,
    prefix: Vec<u8>,
) where
    S: AsyncRead + AsyncWrite + Unpin + RawStream,
{
    let mut st = ConnState::default();
    if !prefix.is_empty() {
        st.read.extend_from_slice(&prefix);
    }
    let mut requests: u64 = 0;

    // Defaults come from the listener's default server until a Host is parsed.
    let default_server = &listener.servers[listener.default_server];

    loop {
        // `read` is NOT cleared here: it may already hold a pipelined request.
        st.write.clear();

        let core = &default_server.core;
        let header_timeout = if requests == 0 {
            core.client_header_timeout
        } else {
            core.keepalive_timeout
        };

        // ---- read the request head ----------------------------------------
        let max_head = core.large_client_header_buffers.0 * core.large_client_header_buffers.1;
        let parse = match read_head(&mut sock, &mut st, header_timeout, max_head).await {
            Ok(p) => p,
            // A clean EOF while idle is a normal keep-alive close.
            Err(HeadError::Eof) => return,
            Err(HeadError::Timeout) => {
                if requests > 0 {
                    return; // idle keep-alive expiry: just close
                }
                let _ = write_bare_error(&mut sock, 408).await;
                return;
            }
            Err(HeadError::TooLarge) => {
                let _ = write_bare_error(&mut sock, 431).await;
                return;
            }
            Err(HeadError::Io) => return,
        };

        if let ParseResult::Error(code) = parse {
            let _ = write_bare_error(&mut sock, code).await;
            return;
        }

        requests += 1;

        // ---- pick the server and normalise the URI -------------------------
        // No `to_ascii_lowercase()` here: `match_host` compares
        // case-insensitively, so lowercasing first was a wasted allocation.
        let server: &Arc<ServerConf> = listener.match_host(st.req.host(&st.read));

        let raw_path = st.req.path_str(&st.read);
        let normalised = match uri::normalize(raw_path) {
            Ok(u) => u,
            Err(_) => {
                let _ = write_bare_error(&mut sock, 400).await;
                return;
            }
        };

        // ---- read the request body -----------------------------------------
        // nginx buffers the request body before proxying (`proxy_request_buffering
        // on`, the default). Buffering it here means handlers see a complete body
        // and the connection is left correctly positioned for the next request.
        st.body.clear();
        let body_result = read_body(
            &mut sock,
            &mut st,
            server.core.client_max_body_size,
            server.core.client_body_timeout,
        )
        .await;

        let body_status = body_result.err();

        let mut ctx = Ctx::new(
            &st.read,
            &st.req,
            &st.body,
            http,
            server,
            normalised,
            remote,
            local,
            scheme,
            conn_id,
            requests,
        );

        let started = Instant::now();
        let mut reply = match body_status {
            Some(code) => handler::error_reply(&ctx, code),
            None => handler::handle(&mut ctx).await,
        };

        // ---- decide whether the connection survives ------------------------
        let client_wants_keepalive = st.req.keep_alive;
        let over_request_limit = requests >= server.core.keepalive_requests;

        reply.resp.keep_alive = reply.resp.keep_alive
            && client_wants_keepalive
            && !over_request_limit
            // A body we could not finish reading leaves the stream misaligned.
            && body_status.is_none()
            && server.core.keepalive_timeout > Duration::ZERO;

        let http11 = st.req.minor == 1;
        let head_only = st.req.method == Method::Head;
        let mut reply = reply.frame(http11);
        if head_only {
            reply.body = Body::Empty;
        }

        let keep = reply.resp.keep_alive;
        let status = reply.resp.status;

        // ---- write it out --------------------------------------------------
        let written = match write_reply(&mut sock, &mut st.write, reply, server, head_only).await {
            Ok(w) => w,
            Err(_) => {
                log_request(logs, &ctx, &Resp::new(), status, 0, 0, started);
                return;
            }
        };

        log_request(
            logs,
            &ctx,
            &written.resp,
            status,
            written.body_bytes,
            written.total_bytes,
            started,
        );

        if !keep {
            // Returning drops the socket, and `close(2)` sends the FIN on its
            // own. The `shutdown(SHUT_WR)` that used to be here bought nothing
            // — it does not flush, and it does not prevent the RST that unread
            // inbound data causes — while costing a syscall on every
            // connection that does not keep alive. Measured against nginx on
            // a `Connection: close` workload, that one syscall was an eighth
            // of our per-connection kernel work.
            return;
        }
        // Now that nothing borrows `read` any more, drop this request's bytes
        // and keep whatever a pipelined next request already sent.
        let consumed = st.consumed.min(st.read.len());
        if consumed >= st.read.len() {
            st.read.clear();
        } else {
            st.read.copy_within(consumed.., 0);
            let left = st.read.len() - consumed;
            st.read.truncate(left);
        }
    }
}

/// Reads and decodes the request body into `st.body`, recording in
/// `st.consumed` how much of `st.read` belongs to this request.
///
/// Returns `Err(status)` for a body that is too large (413), malformed (400),
/// or that never arrives (408).
async fn read_body<S>(
    sock: &mut S,
    st: &mut ConnState,
    max: u64,
    timeout: Duration,
) -> Result<(), u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use crate::http::request::Body as ReqBody;

    let head_len = st.req.head_len;
    let mut pos = head_len;

    let result = match st.req.body {
        ReqBody::None => Ok(()),
        ReqBody::Length(n) => {
            if n > max {
                Err(413)
            } else {
                // 100-continue must be answered before the client will send.
                if st.req.expects_continue(&st.read) {
                    let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                    let _ = sock.flush().await;
                }
                read_exact_body(sock, st, &mut pos, n, timeout).await
            }
        }
        ReqBody::Chunked => {
            if st.req.expects_continue(&st.read) {
                let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                let _ = sock.flush().await;
            }
            read_chunked_body(sock, st, &mut pos, max, timeout).await
        }
    };

    // The buffer itself is drained only after the response is written: the
    // parsed request holds byte ranges into it until then.
    st.consumed = pos;
    result
}

async fn read_exact_body<S>(
    sock: &mut S,
    st: &mut ConnState,
    pos: &mut usize,
    n: u64,
    timeout: Duration,
) -> Result<(), u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let n = n as usize;
    st.body.reserve(n);

    // Take whatever already arrived alongside the head.
    let have = (st.read.len() - *pos).min(n);
    st.body.extend_from_slice(&st.read[*pos..*pos + have]);
    *pos += have;

    while st.body.len() < n {
        let start = st.body.len();
        st.body.resize(n, 0);
        let got = match tokio::time::timeout(timeout, sock.read(&mut st.body[start..])).await {
            Ok(Ok(0)) => {
                st.body.truncate(start);
                return Err(400); // client vanished mid-body
            }
            Ok(Ok(g)) => g,
            Ok(Err(_)) => {
                st.body.truncate(start);
                return Err(400);
            }
            Err(_) => {
                st.body.truncate(start);
                return Err(408);
            }
        };
        st.body.truncate(start + got);
    }
    Ok(())
}

/// Decodes `Transfer-Encoding: chunked` into `st.body`.
async fn read_chunked_body<S>(
    sock: &mut S,
    st: &mut ConnState,
    pos: &mut usize,
    max: u64,
    timeout: Duration,
) -> Result<(), u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // Ensure a full chunk-size line is buffered.
        let line_end = loop {
            if let Some(i) = find_crlf(&st.read[*pos..]) {
                break *pos + i;
            }
            if st.read.len() - *pos > 1024 {
                return Err(400); // absurd chunk header
            }
            fill(sock, st, timeout).await?;
        };

        let line = &st.read[*pos..line_end];
        // A chunk extension (`;name=value`) follows the size and is ignored.
        let size_str = match line.iter().position(|&c| c == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        let size = parse_hex(size_str).ok_or(400u16)?;
        *pos = line_end + 2;

        if size == 0 {
            // Trailers, then the final CRLF.
            loop {
                let end = loop {
                    if let Some(i) = find_crlf(&st.read[*pos..]) {
                        break *pos + i;
                    }
                    fill(sock, st, timeout).await?;
                };
                let is_blank = end == *pos;
                *pos = end + 2;
                if is_blank {
                    return Ok(());
                }
            }
        }

        if st.body.len() as u64 + size > max {
            return Err(413);
        }

        // Buffer the chunk data plus its trailing CRLF.
        let need = size as usize + 2;
        while st.read.len() - *pos < need {
            fill(sock, st, timeout).await?;
        }
        st.body
            .extend_from_slice(&st.read[*pos..*pos + size as usize]);
        *pos += size as usize;
        if &st.read[*pos..*pos + 2] != b"\r\n" {
            return Err(400);
        }
        *pos += 2;
    }
}

/// Appends more bytes from the socket into the read buffer.
async fn fill<S>(sock: &mut S, st: &mut ConnState, timeout: Duration) -> Result<(), u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = st.read.len();
    st.read.resize(start + 8192, 0);
    let n = match tokio::time::timeout(timeout, sock.read(&mut st.read[start..])).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => {
            st.read.truncate(start);
            return Err(400);
        }
        Err(_) => {
            st.read.truncate(start);
            return Err(408);
        }
    };
    st.read.truncate(start + n);
    if n == 0 {
        return Err(400);
    }
    Ok(())
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < b.len() {
        match memchr::memchr(b'\r', &b[i..]) {
            Some(off) => {
                let p = i + off;
                if p + 1 < b.len() {
                    if b[p + 1] == b'\n' {
                        return Some(p);
                    }
                    i = p + 1;
                } else {
                    return None;
                }
            }
            None => return None,
        }
    }
    None
}

fn parse_hex(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 16 {
        return None;
    }
    let mut n: u64 = 0;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b' ' | b'\t' => continue,
            _ => return None,
        };
        n = n.checked_mul(16)?.checked_add(d as u64)?;
    }
    Some(n)
}

enum HeadError {
    Eof,
    Timeout,
    TooLarge,
    Io,
}

/// Reads until a complete request head is buffered.
///
/// Bytes already in `st.read` (from pipelining) are parsed before touching the
/// socket, which is what makes pipelined requests cost zero extra syscalls.
async fn read_head<S>(
    sock: &mut S,
    st: &mut ConnState,
    timeout: Duration,
    max_head: usize,
) -> Result<ParseResult, HeadError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        if !st.read.is_empty() {
            match st.req.parse(&st.read, 128) {
                ParseResult::Complete => return Ok(ParseResult::Complete),
                ParseResult::Error(c) => return Ok(ParseResult::Error(c)),
                ParseResult::Partial => {}
            }
            if st.read.len() > max_head {
                return Err(HeadError::TooLarge);
            }
        }

        let start = st.read.len();
        if st.read.capacity() - start < 2048 {
            st.read.reserve(READ_BUF_INIT);
        }
        st.read.resize(st.read.capacity(), 0);

        let n = match tokio::time::timeout(timeout, sock.read(&mut st.read[start..])).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => {
                st.read.truncate(start);
                return Err(HeadError::Io);
            }
            Err(_) => {
                st.read.truncate(start);
                return Err(HeadError::Timeout);
            }
        };
        st.read.truncate(start + n);

        if n == 0 {
            return Err(if start == 0 { HeadError::Eof } else { HeadError::Io });
        }
    }
}

struct Written {
    resp: Resp,
    body_bytes: u64,
    total_bytes: u64,
}

async fn write_reply<S>(
    sock: &mut S,
    wbuf: &mut Vec<u8>,
    reply: Reply,
    server: &Arc<ServerConf>,
    head_only: bool,
) -> io::Result<Written>
where
    S: AsyncRead + AsyncWrite + Unpin + RawStream,
{
    let Reply { resp, body } = reply;
    wbuf.clear();
    resp.write_head(wbuf, server.core.server_tokens);
    let head_len = wbuf.len() as u64;

    if head_only || matches!(body, Body::Empty) {
        sock.write_all(wbuf).await?;
        sock.flush().await?;
        return Ok(Written { resp, body_bytes: 0, total_bytes: head_len });
    }

    let body_bytes = match body {
        Body::Empty => 0,
        Body::Bytes(b) => {
            // Small bodies ride along in the head buffer: one write syscall.
            if b.len() <= 16 * 1024 {
                wbuf.extend_from_slice(&b);
                sock.write_all(wbuf).await?;
                b.len() as u64
            } else {
                write_head_and_slice(sock, wbuf, &b).await?;
                b.len() as u64
            }
        }
        Body::Mmap { map, range } => {
            // One vectored write, head and body together. Splitting this into
            // `output_buffers`-sized pieces was measured to cost ~10% on
            // 100 KiB files for no benefit: nothing reaching this arm exceeds
            // `files::MMAP_MAX`, so no single write is long enough to starve
            // the other connections on this worker.
            let slice = &map[range.clone()];
            write_head_and_slice(sock, wbuf, slice).await?;
            slice.len() as u64
        }
        Body::Inline { file, offset, len } => {
            // Append the file to the head buffer and send both in one write.
            // The buffer is per-connection and reused, so this costs a `pread`
            // and no allocation once the connection has warmed up.
            let head = wbuf.len();
            let want = len as usize;
            wbuf.resize(head + want, 0);
            let n = read_at(&file, &mut wbuf[head..], offset)?;
            wbuf.truncate(head + n);
            sock.write_all(wbuf).await?;
            n as u64
        }
        Body::File { file, offset, len } => {
            sock.write_all(wbuf).await?;
            stream_file(
                sock,
                file,
                offset,
                len,
                server.core.output_buffers.1,
                server.core.sendfile,
            )
            .await?
        }
        Body::Stream { pre, io, len } => {
            sock.write_all(wbuf).await?;
            stream_upstream(sock, pre, io, len, resp.framing).await?
        }
    };

    sock.flush().await?;
    Ok(Written {
        resp,
        body_bytes,
        total_bytes: head_len + body_bytes,
    })
}

/// Writes the head and a borrowed body in one vectored call when the transport
/// supports it, so a cached static file costs a single syscall.
async fn write_head_and_slice<S>(sock: &mut S, head: &[u8], body: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    use std::io::IoSlice;
    if !sock.is_write_vectored() {
        sock.write_all(head).await?;
        sock.write_all(body).await?;
        return Ok(());
    }

    let mut head_off = 0usize;
    let mut body_off = 0usize;
    while head_off < head.len() || body_off < body.len() {
        let slices = [
            IoSlice::new(&head[head_off.min(head.len())..]),
            IoSlice::new(&body[body_off.min(body.len())..]),
        ];
        let n = std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut *sock).poll_write_vectored(cx, &slices)
        })
        .await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let head_take = n.min(head.len() - head_off);
        head_off += head_take;
        body_off += n - head_take;
    }
    Ok(())
}

/// Streams a file too large to map, into one recycled per-connection buffer.
///
/// Every design choice here was measured on the 10 MiB case, and the intuitive
/// answer was wrong twice:
///
/// * **`pread` runs inline on the worker, not on the blocking pool.** A pool
///   round trip per chunk costs more than the read itself when the file is in
///   page cache, which it usually is — it halved single-stream throughput
///   (786 → 393 rps). This is what nginx does too: its default is `aio off`,
///   i.e. blocking reads on the worker. A genuinely cold file will stall this
///   worker, exactly as it stalls an nginx worker.
/// * **The buffer is small and reused.** `buf_size` follows nginx's
///   `output_buffers` (default 32 KiB). Larger buffers are faster for a single
///   stream but fall off a cliff under concurrency — 64 KiB and above dropped
///   the 128-connection result from ~690 to ~470 rps. nginx's 32 KiB default
///   is tuned for the same reason.
///
/// Serving large files from a memory map was also tried and is *worse* under
/// concurrency (~470 rps at 128 connections regardless of write size), so
/// mapping is deliberately reserved for small files by [`files::MMAP_MAX`].
///
/// [`files::MMAP_MAX`]: super::files::MMAP_MAX
async fn stream_file<S>(
    sock: &mut S,
    file: Arc<std::fs::File>,
    offset: u64,
    len: u64,
    buf_size: usize,
    sendfile: bool,
) -> io::Result<u64>
where
    S: AsyncWrite + Unpin + RawStream,
{
    // Zero-copy first: `sendfile(2)` moves the file straight from page cache to
    // socket without it ever entering user space. This is the single biggest
    // advantage nginx had on Linux.
    #[cfg(target_os = "linux")]
    if sendfile {
        if let Some(tcp) = sock.as_tcp() {
            return sendfile_all(tcp, &file, offset, len).await;
        }
    }
    let _ = sendfile; // not consulted on platforms without sendfile(2)

    let mut sent = 0u64;
    let mut pos = offset;
    let chunk = buf_size.clamp(16 * 1024, 512 * 1024).min(len.max(1) as usize);
    let mut buf = vec![0u8; chunk];

    let _guard = StreamGuard::enter();

    while sent < len {
        let want = chunk.min((len - sent) as usize);

        // Offload only when this worker is juggling several transfers at once
        // (see the doc comment). `STREAMING` counts them, so the decision
        // tracks real load instead of a compile-time guess.
        let n = if StreamGuard::active() > INLINE_STREAM_MAX {
            let f = file.clone();
            let (b, n) = tokio::task::spawn_blocking(move || {
                let n = read_at(&f, &mut buf[..want], pos)?;
                Ok::<_, io::Error>((buf, n))
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::Other))??;
            buf = b;
            n
        } else {
            read_at(&file, &mut buf[..want], pos)?
        };

        if n == 0 {
            break; // the file shrank underneath us
        }
        sock.write_all(&buf[..n]).await?;
        sent += n as u64;
        pos += n as u64;
    }
    Ok(sent)
}

/// Above this many concurrent large-file transfers on one worker, reads move
/// to the blocking pool. Below it, they run inline.
const INLINE_STREAM_MAX: usize = 2;

thread_local! {
    /// Large-file transfers currently in flight on this worker.
    static STREAMING: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Keeps [`STREAMING`] accurate even if a transfer ends early via `?`.
struct StreamGuard;

impl StreamGuard {
    fn enter() -> StreamGuard {
        STREAMING.with(|c| c.set(c.get() + 1));
        StreamGuard
    }

    fn active() -> usize {
        STREAMING.with(|c| c.get())
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        STREAMING.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

#[cfg(unix)]
fn read_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    f.read_at(buf, off)
}

#[cfg(not(unix))]
fn read_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = f.try_clone()?;
    f.seek(SeekFrom::Start(off))?;
    f.read(buf)
}

/// Copies a proxied body downstream.
///
/// When `framing` is `Chunked` the upstream bytes already carry chunk framing,
/// so they are forwarded verbatim rather than decoded and re-encoded.
async fn stream_upstream<S>(
    sock: &mut S,
    pre: Vec<u8>,
    mut io: Box<dyn AsyncRead + Send + Unpin>,
    len: Option<u64>,
    _framing: Framing,
) -> io::Result<u64>
where
    S: AsyncWrite + Unpin,
{
    let mut sent = 0u64;
    if !pre.is_empty() {
        sock.write_all(&pre).await?;
        sent += pre.len() as u64;
    }

    let mut buf = vec![0u8; 32 * 1024];
    loop {
        if let Some(total) = len {
            if sent >= total {
                break;
            }
        }
        let n = io.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let take = match len {
            Some(total) => n.min((total - sent) as usize),
            None => n,
        };
        sock.write_all(&buf[..take]).await?;
        sent += take as u64;
    }
    Ok(sent)
}

/// Emits a response for a request too broken to route (bad syntax, oversized
/// head). These bypass the handler entirely, so they get a minimal body.
async fn write_bare_error<S>(sock: &mut S, code: u16) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let body = crate::http::status::error_page(code, Some("oxiserve"));
    let mut out = Vec::with_capacity(body.len() + 160);
    let mut resp = Resp::new();
    resp.status = code;
    resp.keep_alive = false;
    resp.framing = Framing::Length(body.len() as u64);
    resp.header("Content-Type", "text/html");
    resp.write_head(&mut out, crate::config::model::ServerTokens::On);
    out.extend_from_slice(body.as_bytes());
    sock.write_all(&out).await?;
    sock.flush().await
}

/// Encodes one access-log record as a MessagePack map.
///
/// The `log_format` supplies the field set: each `$variable` in it becomes a
/// key, and the literal text between them is dropped. That gives OxiDB a
/// structured document to query rather than a line to re-parse, while still
/// letting the operator choose the fields with the directive they already know.
fn encode_record(
    out: &mut Vec<u8>,
    format: &crate::config::vars::Template,
    vars: &LogVars<'_, '_>,
    db: Option<&str>,
) {
    use crate::server::msgpack as mp;
    let n = format.vars().count() + usize::from(db.is_some());
    mp::map_header(out, n);

    if let Some(name) = db {
        // OxiDB's MessagePack writer routes a record to a tenant database on
        // exactly this field name; anything else is stored as ordinary data.
        mp::write_str(out, "db");
        mp::write_str(out, name);
    }

    let mut value = String::with_capacity(64);
    for v in format.vars() {
        mp::write_str(out, &v.field_name());
        value.clear();
        vars.var(v, &mut value);
        mp::write_auto(out, &value);
    }
}

/// Shared with the HTTP/2 path, which produces the same `Ctx` and `Resp` and
/// so must produce identical log lines — a `log_format` cannot be allowed to
/// mean different things depending on the transport.
pub(crate) fn log_request(
    logs: &Rc<RefCell<Logs>>,
    ctx: &Ctx<'_>,
    resp: &Resp,
    status: u16,
    body_bytes: u64,
    total_bytes: u64,
    _started: Instant,
) {
    let confs = &ctx.server.access_logs;
    if confs.is_empty() {
        return;
    }
    let vars = LogVars { ctx, resp, status, body_bytes, total_bytes };
    let mut logs = logs.borrow_mut();
    let mut record = Vec::new();
    for c in confs {
        match &c.sink {
            crate::config::model::LogSink::File(_) => {
                let mut line = String::with_capacity(256);
                c.format.render_into(&vars, &mut line);
                logs.access(c, &line);
            }
            crate::config::model::LogSink::OxiDb { addr, db } => {
                record.clear();
                encode_record(&mut record, &c.format, &vars, db.as_deref());
                logs.access_oxidb(addr, &record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_state_starts_with_room_for_a_typical_head() {
        let s = ConnState::default();
        assert!(s.read.capacity() >= READ_BUF_INIT);
        assert!(s.write.capacity() >= READ_BUF_INIT);
    }
}

/// Copies a file to a socket with `sendfile(2)`, never touching user space.
///
/// The socket is non-blocking, so `sendfile` returns `EAGAIN` once the send
/// buffer fills; `writable()` parks the task until the kernel has drained it.
#[cfg(target_os = "linux")]
async fn sendfile_all(
    tcp: &tokio::net::TcpStream,
    file: &std::fs::File,
    offset: u64,
    len: u64,
) -> io::Result<u64> {
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    let mut off = offset as libc::off_t;
    let mut sent = 0u64;

    while sent < len {
        let want = (len - sent).min(1 << 30) as usize;
        // Try the syscall first and only park when the kernel says the send
        // buffer is full. Awaiting writability up front cost an epoll round
        // trip per chunk even when the socket could already accept data.
        let res = tcp.try_io(Interest::WRITABLE, || {
            // SAFETY: both descriptors are owned and open for the call, and
            // `off` is a valid mutable pointer the kernel advances for us.
            let n = unsafe { libc::sendfile(tcp.as_raw_fd(), file.as_raw_fd(), &mut off, want) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as u64)
            }
        });
        match res {
            Ok(0) => break, // the file ended early (truncated underneath us)
            Ok(n) => sent += n,
            // Send buffer full: wait for the kernel to drain it, then retry.
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => tcp.writable().await.map(|_| ())?,
            Err(e) => return Err(e),
        }
    }
    Ok(sent)
}

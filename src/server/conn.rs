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

/// Chunk size for streaming large files off the blocking pool.
const FILE_CHUNK: usize = 128 * 1024;

pub struct ConnState {
    pub read: Vec<u8>,
    pub write: Vec<u8>,
    pub req: Req,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            read: Vec::with_capacity(READ_BUF_INIT),
            write: Vec::with_capacity(READ_BUF_INIT),
            req: Req::new(),
        }
    }
}

/// Drives one client connection to completion.
#[allow(clippy::too_many_arguments)]
pub async fn serve<S>(
    mut sock: S,
    listener: &Arc<Listener>,
    http: &Arc<Http>,
    logs: &Rc<RefCell<Logs>>,
    remote: SocketAddr,
    local: SocketAddr,
    scheme: &'static str,
    conn_id: u64,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut st = ConnState::default();
    let mut requests: u64 = 0;

    // Defaults come from the listener's default server until a Host is parsed.
    let default_server = &listener.servers[listener.default_server];

    loop {
        st.read.clear();
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
        let host_owned = st.req.host(&st.read).to_ascii_lowercase();
        let server: &Arc<ServerConf> = listener.match_host(&host_owned);

        let raw_path = st.req.path_str(&st.read);
        let normalised = match uri::normalize(raw_path) {
            Ok(u) => u,
            Err(_) => {
                let _ = write_bare_error(&mut sock, 400).await;
                return;
            }
        };

        // A body we are not going to consume makes the connection unreusable.
        let body_len = match st.req.body {
            crate::http::request::Body::Length(n) => n,
            _ => 0,
        };
        let body_fits = body_len <= server.core.client_max_body_size;

        let mut ctx = Ctx::new(
            &st.read,
            &st.req,
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
        let mut reply = if !body_fits {
            handler::error_reply(&ctx, 413)
        } else {
            handler::handle(&mut ctx).await
        };

        // ---- decide whether the connection survives ------------------------
        let client_wants_keepalive = st.req.keep_alive;
        let over_request_limit = requests >= server.core.keepalive_requests;
        let body_unread = body_len as usize > st.read.len().saturating_sub(st.req.head_len);

        reply.resp.keep_alive = reply.resp.keep_alive
            && client_wants_keepalive
            && !over_request_limit
            && !body_unread
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
            let _ = sock.shutdown().await;
            return;
        }

        // Carry over any pipelined bytes that arrived with the last request.
        let consumed = st.req.head_len + (body_len as usize).min(st.read.len() - st.req.head_len);
        if consumed < st.read.len() {
            st.read.copy_within(consumed.., 0);
            st.read.truncate(st.read.len() - consumed);
        } else {
            st.read.clear();
        }
    }
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
    S: AsyncRead + AsyncWrite + Unpin,
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
            let slice = &map[range.clone()];
            write_head_and_slice(sock, wbuf, slice).await?;
            slice.len() as u64
        }
        Body::File { file, offset, len } => {
            sock.write_all(wbuf).await?;
            stream_file(sock, file, offset, len).await?
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

/// Streams a file too large to map, reading on the blocking pool so a cold
/// page never stalls the worker's event loop.
async fn stream_file<S>(
    sock: &mut S,
    file: std::fs::File,
    offset: u64,
    len: u64,
) -> io::Result<u64>
where
    S: AsyncWrite + Unpin,
{
    let file = Arc::new(file);
    let mut sent = 0u64;
    let mut pos = offset;

    while sent < len {
        let want = FILE_CHUNK.min((len - sent) as usize);
        let f = file.clone();
        let chunk = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; want];
            let n = read_at(&f, &mut buf, pos)?;
            buf.truncate(n);
            Ok::<_, io::Error>(buf)
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::Other))??;

        if chunk.is_empty() {
            break; // file shrank underneath us
        }
        sock.write_all(&chunk).await?;
        sent += chunk.len() as u64;
        pos += chunk.len() as u64;
    }
    Ok(sent)
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

fn log_request(
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
    for c in confs {
        let mut line = String::with_capacity(256);
        c.format.render_into(&vars, &mut line);
        logs.access(c, &line);
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

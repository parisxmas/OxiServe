//! One HTTP/3 connection: the control stream, the request streams, and the
//! translation into the handler every other transport already uses.
//!
//! # How little there is here
//!
//! [`crate::http2::conn`] is 1,300 lines, and most of them are concurrency:
//! stream state machines, two levels of flow-control window, CONTINUATION
//! reassembly, a writer task owning the socket so one slow stream cannot block
//! another. QUIC provides every one of those, so this module does not.
//!
//! What remains is genuinely HTTP/3: set up the unidirectional streams RFC
//! 9114 requires, read frames off each request stream, and answer. A request
//! is one bidirectional stream from first byte to last, which means it can be
//! one straight-line async task with no shared state at all — the shape the
//! HTTP/1 path has, arrived at from the opposite direction.
//!
//! # The seam
//!
//! A decoded request becomes the same [`Req`] the HTTP/1 parser produces and
//! goes through the same [`handler::handle`], so `proxy_pass`, `proxy_cache`,
//! `limit_req`, `limit_conn`, FastCGI, `try_files`, `error_page` and every
//! variable behave identically. `:authority` is turned back into a `Host`
//! header by the shared [`parse_headers`], so `server_name` matching and
//! `$host` need no special case.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use tokio::io::AsyncReadExt;

use super::frame::{self, code, kind, stream_type, Settings};
use super::qpack;
use crate::config::model::{Http, Listener};
use crate::http::request::{Body as ReqBody, Req};
use crate::http::response::Resp;
use crate::http2::conn::parse_headers;
use crate::server::ctx::Ctx;
use crate::server::handler;
use crate::server::log::Logs;
use crate::server::reply::{Body, Reply};

/// Largest request head we will decode, and what we advertise.
const MAX_FIELD_SECTION: usize = 64 * 1024;

/// Chunk size for streaming a body out. Matches the HTTP/2 path.
const CHUNK: usize = 64 * 1024;

/// Serves one QUIC connection until the peer or the transport ends it.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    conn: quinn::Connection,
    conf: &Arc<Listener>,
    http: &Arc<Http>,
    logs: &Rc<RefCell<Logs>>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    conn_id: u64,
) {
    // Counted for `stub_status` for as long as the QUIC connection lives.
    let _conn = crate::server::stats::ConnGuard::enter();
    // RFC 9114 section 6.2.1: the control stream must be opened first and must
    // carry SETTINGS as its first frame. A peer is entitled to close the
    // connection if it sees anything else, so this happens before we so much
    // as look at an incoming stream.
    if open_control(&conn).await.is_err() {
        return;
    }
    // Both QPACK streams exist and stay empty. With a table capacity of zero
    // neither end can send an instruction, but some clients wait for the
    // streams themselves before sending a request, and one byte each is a
    // cheaper answer than finding out which ones.
    for t in [stream_type::QPACK_ENCODER, stream_type::QPACK_DECODER] {
        let Ok(mut s) = conn.open_uni().await else { return };
        let mut b = Vec::new();
        frame::put_varint(t, &mut b);
        if s.write_all(&b).await.is_err() {
            return;
        }
    }

    // The peer's unidirectional streams are read for as long as the connection
    // lives, on their own task: the control stream stays open by definition,
    // so waiting on it inline would mean never accepting a request.
    tokio::task::spawn_local({
        let conn = conn.clone();
        async move { peer_uni_streams(conn).await }
    });

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            // Includes the ordinary close: the client is done with us.
            Err(_) => return,
        };

        let conf = conf.clone();
        let http = http.clone();
        let logs = logs.clone();
        let conn2 = conn.clone();
        // A stream id divided by four is the request's ordinal on this
        // connection, which is what `$connection_requests` wants.
        let requests = recv.id().index() + 1;

        tokio::task::spawn_local(async move {
            if let Err(e) =
                request(send, recv, &conf, &http, &logs, remote, local, conn_id, requests).await
            {
                // A framing or QPACK failure is not recoverable per stream:
                // both leave connection-wide state we can no longer trust.
                conn2.close(quinn::VarInt::from_u64(e).unwrap_or_default(), b"");
            }
        });
    }
}

/// Opens our control stream and sends SETTINGS.
async fn open_control(conn: &quinn::Connection) -> Result<(), ()> {
    let mut s = conn.open_uni().await.map_err(|_| ())?;
    let mut out = Vec::with_capacity(32);
    frame::put_varint(stream_type::CONTROL, &mut out);

    let mut payload = Vec::with_capacity(16);
    Settings::default().encode(&mut payload);
    frame::put_frame(kind::SETTINGS, &payload, &mut out);

    s.write_all(&out).await.map_err(|_| ())?;
    // Deliberately not finished: RFC 9114 section 6.2.1 makes closing the
    // control stream a CLOSED_CRITICAL_STREAM error for the whole connection.
    Ok(())
}

/// Reads every unidirectional stream the peer opens.
async fn peer_uni_streams(conn: quinn::Connection) {
    let mut seen_control = false;
    while let Ok(mut recv) = conn.accept_uni().await {
        let mut r = Reader::new();
        // The stream type is a varint at the very front.
        let Some(t) = r.varint(&mut recv).await else { continue };
        match t {
            stream_type::CONTROL => {
                if seen_control {
                    // A second control stream is a protocol error, not a
                    // second opinion.
                    conn.close(quinn::VarInt::from_u64(code::STREAM_CREATION_ERROR).unwrap(), b"");
                    return;
                }
                seen_control = true;
                if let Err(e) = control_stream(&mut r, &mut recv).await {
                    conn.close(quinn::VarInt::from_u64(e).unwrap_or_default(), b"");
                    return;
                }
            }
            // A server that never promised a push must never receive one.
            stream_type::PUSH => {
                conn.close(quinn::VarInt::from_u64(code::STREAM_CREATION_ERROR).unwrap(), b"");
                return;
            }
            // Drained, never closed: these are critical streams too, and with
            // a zero table capacity there is nothing on them to apply.
            stream_type::QPACK_ENCODER | stream_type::QPACK_DECODER => {
                tokio::task::spawn_local(async move {
                    let mut sink = [0u8; 1024];
                    while let Ok(Some(_)) = recv.read(&mut sink).await {}
                });
            }
            // Unknown or grease: RFC 9114 section 6.2 says abandon it, and
            // says so precisely because peers send them to check we do.
            _ => {
                let _ = recv.stop(quinn::VarInt::from_u64(code::NO_ERROR).unwrap());
            }
        }
    }
}

/// Reads the peer's control stream for as long as it lives.
async fn control_stream(r: &mut Reader, recv: &mut quinn::RecvStream) -> Result<(), u64> {
    let mut first = true;
    loop {
        let Some(head) = r.head(recv).await? else { return Ok(()) };
        // RFC 9114 section 6.2.1: SETTINGS must come first, exactly once.
        if first && head.kind != kind::SETTINGS {
            return Err(code::MISSING_SETTINGS);
        }
        if !first && head.kind == kind::SETTINGS {
            return Err(code::FRAME_UNEXPECTED);
        }
        first = false;

        let payload = r.exact(recv, head.len as usize).await.ok_or(code::FRAME_ERROR)?;
        match head.kind {
            kind::SETTINGS => {
                Settings::decode(&payload).map_err(|e| e.0)?;
                // Nothing to apply: we index only the static table, so the
                // peer's QPACK capacity cannot change what we emit, and its
                // field-section limit is honoured by keeping responses small
                // rather than by bookkeeping.
            }
            // The client is telling us to stop; it will close when its
            // outstanding requests finish, and there is nothing to do here
            // that dropping the connection would not also do.
            kind::GOAWAY | kind::MAX_PUSH_ID | kind::CANCEL_PUSH => {}
            // These belong on a request stream and nowhere else.
            kind::DATA | kind::HEADERS => return Err(code::FRAME_UNEXPECTED),
            kind::PUSH_PROMISE => return Err(code::FRAME_UNEXPECTED),
            _ => {} // unknown and grease: skipped, which `exact` already did
        }
    }
}

/// Reads one request off its stream, answers it, and logs it.
#[allow(clippy::too_many_arguments)]
async fn request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conf: &Arc<Listener>,
    http: &Arc<Http>,
    logs: &Rc<RefCell<Logs>>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    conn_id: u64,
    requests: u64,
) -> Result<(), u64> {
    let mut r = Reader::new();

    // ---- the request head ------------------------------------------------
    let Some(head) = r.head(&mut recv).await? else {
        // The peer opened a stream and closed it without a request. Nothing
        // was asked, so nothing is answered.
        return Ok(());
    };
    if head.kind != kind::HEADERS {
        return Err(code::FRAME_UNEXPECTED);
    }
    if head.len as usize > MAX_FIELD_SECTION {
        return Err(code::EXCESSIVE_LOAD);
    }
    let block = r.exact(&mut recv, head.len as usize).await.ok_or(code::FRAME_ERROR)?;
    let fields = qpack::decode(&block, MAX_FIELD_SECTION).map_err(|e| e.0)?;

    let parsed = match parse_headers(&fields) {
        Ok(p) => p,
        // The pseudo-header rules are the same as HTTP/2's, but the remedy is
        // not: there is no RST_STREAM here, so a malformed request is answered
        // as one rather than reset.
        Err(_) => return respond_bare(&mut send, 400).await,
    };

    // ---- the body --------------------------------------------------------
    let max_body = conf.servers[conf.default_server].core.client_max_body_size;
    let mut body = Vec::new();
    loop {
        let Some(h) = r.head(&mut recv).await? else { break };
        match h.kind {
            kind::DATA => {
                if body.len() as u64 + h.len > max_body {
                    return respond_bare(&mut send, 413).await;
                }
                let chunk = r.exact(&mut recv, h.len as usize).await.ok_or(code::FRAME_ERROR)?;
                body.extend_from_slice(&chunk);
            }
            // Trailers. Accepted and discarded, as the HTTP/2 path does.
            kind::HEADERS => {
                r.exact(&mut recv, h.len as usize).await.ok_or(code::FRAME_ERROR)?;
            }
            kind::SETTINGS | kind::GOAWAY | kind::MAX_PUSH_ID | kind::CANCEL_PUSH => {
                return Err(code::FRAME_UNEXPECTED)
            }
            _ => {
                r.exact(&mut recv, h.len as usize).await.ok_or(code::FRAME_ERROR)?;
            }
        }
    }

    // ---- route it --------------------------------------------------------
    let (buf, mut req) = Req::from_parts(&parsed.method, &parsed.path, &parsed.headers());
    if !body.is_empty() {
        req.body = ReqBody::Length(body.len() as u64);
    }

    let server = conf.match_host(&parsed.authority);
    let normalised = match crate::http::uri::normalize(req.path_str(&buf)) {
        Ok(u) => u,
        Err(_) => return respond_bare(&mut send, 400).await,
    };

    let mut ctx = Ctx::new(
        &buf, &req, &body, http, server, normalised, remote, local, "https", conn_id, requests,
    );
    let reply = handler::handle(&mut ctx).await;

    // `frame(true)` fills in Content-Length when the length is known. Its
    // chunked fallback is meaningless here — HTTP/3 frames the body with DATA
    // and ends it by finishing the stream — so the write path ignores it,
    // exactly as the HTTP/2 path does.
    let mut reply = reply.frame(true);
    let head_only = req.method == crate::http::Method::Head;
    if head_only {
        reply.body = Body::Empty;
    }
    let status = reply.resp.status;

    // Split so the response headers survive into logging: `$sent_http_*` must
    // work over HTTP/3 exactly as it does everywhere else.
    let Reply { resp, body: out_body } = reply;
    let (body_bytes, total) = write_response(&mut send, &resp, out_body).await;
    crate::server::conn::log_request(logs, &ctx, &resp, status, body_bytes, total);
    crate::server::stats::request_done();
    Ok(())
}

/// Answers with a status and no body, for a request we could not even route.
async fn respond_bare(send: &mut quinn::SendStream, status: u16) -> Result<(), u64> {
    let mut resp = Resp::new();
    resp.status = status;
    write_response(send, &resp, Body::Empty).await;
    Ok(())
}

/// Writes HEADERS then DATA, and finishes the stream.
///
/// Returns `(body bytes, total bytes)` for logging.
async fn write_response(send: &mut quinn::SendStream, resp: &Resp, body: Body) -> (u64, u64) {
    let mut block = Vec::with_capacity(256);
    qpack::begin_section(&mut block);
    qpack::encode(":status", &resp.status.to_string(), &mut block);
    for (n, v) in resp.iter() {
        // Connection-specific headers have no meaning over HTTP/3 and are
        // exactly the shape a downgrade attack takes when a proxy
        // re-serialises to HTTP/1.
        if matches!(
            n.to_ascii_lowercase().as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "proxy-connection"
        ) {
            continue;
        }
        qpack::encode(&n.to_ascii_lowercase(), v, &mut block);
    }
    if let crate::http::response::Framing::Length(n) = resp.framing {
        qpack::encode("content-length", &n.to_string(), &mut block);
    }

    let mut out = Vec::with_capacity(block.len() + 16);
    frame::put_frame(kind::HEADERS, &block, &mut out);
    let mut total = out.len() as u64;
    if send.write_all(&out).await.is_err() {
        return (0, total);
    }

    let body_bytes = write_body(send, body).await;
    total += body_bytes;
    // Finishing is what ends the response: HTTP/3 has no END_STREAM flag, the
    // stream's own FIN carries it.
    let _ = send.finish();
    (body_bytes, total)
}

/// Streams a body as DATA frames. Returns the payload bytes written.
async fn write_body(send: &mut quinn::SendStream, body: Body) -> u64 {
    // No flow-control bookkeeping: `write_all` is back-pressured by QUIC's own
    // stream and connection windows, which is the work `super::super::http2`
    // has to do by hand.
    async fn data(send: &mut quinn::SendStream, chunk: &[u8]) -> bool {
        if chunk.is_empty() {
            return true;
        }
        let mut head = Vec::with_capacity(16);
        frame::put_data_head(chunk.len() as u64, &mut head);
        send.write_all(&head).await.is_ok() && send.write_all(chunk).await.is_ok()
    }

    let mut sent = 0u64;
    match body {
        Body::Empty => {}
        Body::Bytes(b) => {
            if data(send, &b).await {
                sent += b.len() as u64;
            }
        }
        Body::Mmap { map, range } => {
            let slice = &map[range];
            if data(send, slice).await {
                sent += slice.len() as u64;
            }
        }
        Body::Inline { file, offset, len } | Body::File { file, offset, len } => {
            // No `sendfile`, and there cannot be: every byte has to be wrapped
            // in a DATA frame and then encrypted into QUIC packets, so the
            // kernel cannot hand the page cache straight to the socket. This
            // is inherent to HTTP/3 — nginx pays the same cost, and so does
            // our own HTTP/2 path.
            let mut left = len;
            let mut off = offset;
            let mut chunk = vec![0u8; CHUNK];
            while left > 0 {
                let want = (left as usize).min(chunk.len());
                let n = match crate::http2::conn::read_at(&file, &mut chunk[..want], off) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if !data(send, &chunk[..n]).await {
                    break;
                }
                sent += n as u64;
                off += n as u64;
                left -= n as u64;
            }
        }
        Body::Stream { pre, mut io, .. } => {
            if !pre.is_empty() {
                if !data(send, &pre).await {
                    return sent;
                }
                sent += pre.len() as u64;
            }
            let mut chunk = vec![0u8; CHUNK];
            loop {
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if !data(send, &chunk[..n]).await {
                            break;
                        }
                        sent += n as u64;
                    }
                }
            }
        }
        Body::Upgraded { .. } => {
            // Unreachable: `parse_headers` refuses a request carrying
            // `connection` or `upgrade`, so no HTTP/3 stream can ask for a
            // protocol switch. Extended CONNECT, which is how WebSockets ride
            // on HTTP/3, is not implemented.
        }
    }
    sent
}

/// An incremental frame reader over one QUIC stream.
///
/// HTTP/3 frame headers are two varints of one to eight bytes each, so even
/// the header can arrive in pieces. Everything here returns "not yet" rather
/// than parsing half a value, and the buffer keeps what has not been consumed.
struct Reader {
    buf: Vec<u8>,
    /// Set once the peer has finished its half of the stream, so a short read
    /// stops meaning "wait" and starts meaning "that was all".
    eof: bool,
}

impl Reader {
    fn new() -> Reader {
        Reader { buf: Vec::with_capacity(1024), eof: false }
    }

    /// Pulls more bytes in. Returns false at end of stream.
    async fn fill(&mut self, recv: &mut quinn::RecvStream) -> bool {
        if self.eof {
            return false;
        }
        let mut chunk = [0u8; 4096];
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
            Ok(None) | Err(_) => {
                self.eof = true;
                false
            }
        }
    }

    /// Reads a leading varint, waiting for as many bytes as it needs.
    async fn varint(&mut self, recv: &mut quinn::RecvStream) -> Option<u64> {
        loop {
            if let Some((v, n)) = frame::get_varint(&self.buf) {
                self.buf.drain(..n);
                return Some(v);
            }
            if !self.fill(recv).await {
                return None;
            }
        }
    }

    /// Reads a frame header. `Ok(None)` is a clean end of stream between
    /// frames, which is how a request with no body ends.
    async fn head(&mut self, recv: &mut quinn::RecvStream) -> Result<Option<frame::Head>, u64> {
        loop {
            match frame::parse_head(&self.buf) {
                Err(e) => return Err(e.0),
                Ok(Some(h)) => {
                    self.buf.drain(..h.head_len);
                    return Ok(Some(h));
                }
                Ok(None) => {
                    if !self.fill(recv).await {
                        // Mid-header at end of stream is a truncated frame;
                        // between frames it is simply the end.
                        return if self.buf.is_empty() {
                            Ok(None)
                        } else {
                            Err(code::FRAME_ERROR)
                        };
                    }
                }
            }
        }
    }

    /// Reads exactly `n` bytes of payload.
    async fn exact(&mut self, recv: &mut quinn::RecvStream, n: usize) -> Option<Vec<u8>> {
        while self.buf.len() < n {
            if !self.fill(recv).await {
                return None;
            }
        }
        Some(self.buf.drain(..n).collect())
    }
}

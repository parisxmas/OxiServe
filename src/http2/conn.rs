//! An HTTP/2 connection.
//!
//! The design goal is that HTTP/2 is a *transport* swap and nothing more:
//! frames are decoded into a [`Req`] and handed to the same
//! [`handler::handle`] the HTTP/1 path uses, so `proxy_pass`, `proxy_cache`,
//! `limit_req`, FastCGI, `try_files` and every variable behave identically.
//! There is no second implementation of anything above the framing layer.
//!
//! Concurrency is what HTTP/2 is for, so streams really do run concurrently:
//! each complete request is spawned onto the same current-thread runtime, and
//! a writer task owns the socket's write half. Responses interleave; a slow
//! backend on one stream does not hold up a cache hit on another.
//!
//! Request bodies are buffered before the handler runs, exactly as the HTTP/1
//! path buffers them (`proxy_request_buffering on` is nginx's default). That
//! keeps one body-reading policy rather than two, and it is why a stream's
//! state stays in the reader loop until END_STREAM.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

use super::frame::{self, flag, kind, setting, Code, Head};
use super::hpack::{self, HpackError};
use crate::config::model::{Http, Listener, ServerConf};
use crate::http::request::{Body as ReqBody, Method, Req};
use crate::http::response::{Framing, Resp};
use crate::http::uri;
use crate::server::ctx::Ctx;
use crate::server::handler;
use crate::server::log::Logs;
use crate::server::reply::{Body, Reply};

/// What we advertise for `SETTINGS_INITIAL_WINDOW_SIZE`.
///
/// Well above the 64 KB default so a client uploading a body is not forced
/// into a stop-and-wait exchange with us. Request bodies are capped by
/// `client_max_body_size` regardless, so a large window costs at most that
/// much buffered per stream.
const OUR_INITIAL_WINDOW: u32 = 1024 * 1024;

/// Cap on concurrent streams per connection. Each one can hold a buffered
/// request body, so this is the multiplier on a connection's memory cost.
const MAX_CONCURRENT: u32 = 128;

/// Cap on a decoded header list, charged the HPACK way (name + value + 32).
const MAX_HEADER_LIST: usize = 64 * 1024;

/// How much of the connection window we let the peer consume before topping it
/// back up. Replenishing per DATA frame would put a WINDOW_UPDATE on the wire
/// for every frame; half the window is the usual compromise.
const WINDOW_REFILL_AT: i64 = (OUR_INITIAL_WINDOW as i64) / 2;

/// A connection-fatal error. Everything that produces one ends with GOAWAY.
struct ConnErr(Code, &'static str);

/// Flow-control state shared between the reader loop and the stream tasks.
///
/// `Rc` + `Cell` rather than atomics: the whole connection lives on one thread,
/// so there is no contention to protect against and no reason to pay for
/// synchronisation. `Notify` wakes senders blocked on a window.
struct Flow {
    /// Our remaining send allowance for the whole connection.
    conn_window: Cell<i64>,
    max_frame: Cell<usize>,
    /// Bumped whenever any window grows, so blocked senders re-check.
    wake: Notify,
    /// The connection is going away; stream tasks should stop writing.
    closed: Cell<bool>,
}

/// Per-stream state the sending task needs.
///
/// Outlives the reader loop's assembly state: a stream's window keeps being
/// adjusted by WINDOW_UPDATE long after its request was dispatched, so this is
/// tracked in its own map. Keeping it inside the request-assembly entry meant
/// dispatching a request dropped the window with it, and the response stalled
/// forever at exactly the initial window size.
struct StreamFlow {
    window: Cell<i64>,
    /// Set when the peer sends RST_STREAM: the task should abandon the
    /// response rather than keep framing a body nobody will read.
    reset: Cell<bool>,
    /// Set by the stream task when it is finished, so the reader can drop the
    /// entry instead of accumulating one per request for the connection's life.
    done: Cell<bool>,
}

/// RFC 9113 section 5.1, reduced to what a server needs. `Idle` is not a
/// variant because an idle stream has no entry at all — see [`state_of`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
    Open,
    /// The peer sent END_STREAM; it may not send more. A dispatched stream in
    /// this state is closed as far as the peer is concerned — there is no
    /// separate `Closed` variant, because the only difference that matters is
    /// whether the request has been handed off.
    HalfClosedRemote,
    /// We sent RST_STREAM.
    Reset,
}

/// A stream, from its first HEADERS until its response is written.
///
/// Entries outlive dispatch. An earlier version dropped them as soon as the
/// request was handed off, which meant a stray DATA frame on a finished stream
/// looked identical to one on a stream that never existed, and every later
/// WINDOW_UPDATE was thrown away.
struct Stream {
    state: State,
    flow: Rc<StreamFlow>,
    /// The header block currently being assembled across CONTINUATION frames.
    pending: Vec<u8>,
    /// True when `pending` is a trailer block rather than the request's.
    pending_is_trailers: bool,
    headers: Vec<hpack::Header>,
    headers_done: bool,
    body: Vec<u8>,
    /// The declared `content-length`, checked against the body actually sent.
    content_length: Option<u64>,
    dispatched: bool,
}

impl Stream {
    fn new(initial_window: i64) -> Stream {
        Stream {
            state: State::Open,
            flow: Rc::new(StreamFlow {
                window: Cell::new(initial_window),
                reset: Cell::new(false),
                done: Cell::new(false),
            }),
            pending: Vec::new(),
            pending_is_trailers: false,
            headers: Vec::new(),
            headers_done: false,
            body: Vec::new(),
            content_length: None,
            dispatched: false,
        }
    }
}

/// Everything a spawned stream task needs, owned.
struct Task {
    listener: Arc<Listener>,
    http: Arc<Http>,
    logs: Rc<RefCell<Logs>>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    scheme: &'static str,
    conn_id: u64,
}

/// Serves one HTTP/2 connection to completion.
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
    preread: Vec<u8>,
) where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let (rd, wr) = tokio::io::split(sock);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // The writer owns the write half so nothing else can interleave a partial
    // frame. Every producer hands it whole frames.
    let writer = tokio::task::spawn_local(write_loop(wr, rx));

    let shared = Task {
        listener: listener.clone(),
        http: http.clone(),
        logs: logs.clone(),
        remote,
        local,
        scheme,
        conn_id,
    };

    let flow = Rc::new(Flow {
        conn_window: Cell::new(frame::DEFAULT_WINDOW),
        max_frame: Cell::new(frame::DEFAULT_MAX_FRAME as usize),
        wake: Notify::new(),
        closed: Cell::new(false),
    });

    let last = Rc::new(Cell::new(0u32));
    let result = read_loop(rd, &tx, &shared, &flow, &last, preread).await;

    // Tell the peer why, then let the writer drain what is already queued.
    let mut bye = Vec::new();
    match result {
        Ok(()) => frame::goaway(last.get(), Code::NoError, "", &mut bye),
        Err(ConnErr(code, why)) => frame::goaway(last.get(), code, why, &mut bye),
    }
    let _ = tx.send(bye);
    flow.closed.set(true);
    flow.wake.notify_waiters();
    drop(tx);
    let _ = writer.await;
}

/// Drains the frame channel onto the socket.
///
/// Batches whatever is already queued into one write. Under multiplexing many
/// small frames become ready together — a DATA frame per stream — and writing
/// each one separately would turn a single syscall into a dozen.
async fn write_loop<W>(mut wr: W, mut rx: mpsc::UnboundedReceiver<Vec<u8>>)
where
    W: AsyncWrite + Unpin,
{
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(16);
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    loop {
        let n = rx.recv_many(&mut batch, 16).await;
        if n == 0 {
            break;
        }
        buf.clear();
        for b in batch.drain(..) {
            buf.extend_from_slice(&b);
        }
        if wr.write_all(&buf).await.is_err() {
            break;
        }
        if wr.flush().await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

/// Reads frames until the connection ends.
async fn read_loop<R>(
    mut rd: R,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
    shared: &Task,
    flow: &Rc<Flow>,
    last_stream: &Rc<Cell<u32>>,
    preread: Vec<u8>,
) -> R2
where
    R: AsyncRead + Unpin,
{
    let core = &shared.listener.servers[shared.listener.default_server].core;
    let idle = core.keepalive_timeout.max(Duration::from_secs(1));

    let mut buf = Buf::new(preread);
    // The preface is fixed bytes; a client that sends anything else is not
    // speaking HTTP/2 and there is no version negotiation to fall back to.
    let got = buf.take(&mut rd, frame::PREFACE.len(), idle).await?;
    if got != frame::PREFACE {
        return Err(ConnErr(Code::Protocol, "bad preface"));
    }

    let mut out = Vec::new();
    frame::settings(
        &[
            (setting::MAX_CONCURRENT_STREAMS, MAX_CONCURRENT),
            (setting::INITIAL_WINDOW_SIZE, OUR_INITIAL_WINDOW),
            // We never push. Saying so up front stops a client reserving for it.
            (setting::ENABLE_PUSH, 0),
            (setting::MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST as u32),
        ],
        &mut out,
    );
    // Open the connection window to match the per-stream one.
    frame::window_update(0, OUR_INITIAL_WINDOW - frame::DEFAULT_WINDOW as u32, &mut out);
    let _ = tx.send(out);

    let mut dec = hpack::Decoder::new(4096);
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut peer_initial_window: i64 = frame::DEFAULT_WINDOW;
    let mut recv_window: i64 = OUR_INITIAL_WINDOW as i64;
    let mut highest_client_stream = 0u32;
    // Set while a header block is open: only CONTINUATION may follow.
    let mut expect_continuation: Option<u32> = None;

    loop {
        let head_bytes = match buf.take_opt(&mut rd, frame::HEADER_LEN, idle).await? {
            Some(b) => b,
            None => return Ok(()), // clean close
        };
        let head = Head::parse(&head_bytes[..frame::HEADER_LEN].try_into().unwrap());

        // A frame bigger than we advertised is refused before its payload is
        // read, so an oversized length cannot make us allocate.
        if head.len as usize > frame::DEFAULT_MAX_FRAME as usize {
            return Err(ConnErr(Code::FrameSize, "frame exceeds max size"));
        }
        let payload = buf.take(&mut rd, head.len as usize, idle).await?.to_vec();

        // A header block is atomic on the wire. Anything interleaved would
        // leave the HPACK tables ambiguous, so RFC 9113 section 6.10 makes it
        // a connection error rather than something to reorder around.
        if let Some(open) = expect_continuation {
            if head.kind != kind::CONTINUATION || head.stream != open {
                return Err(ConnErr(Code::Protocol, "expected CONTINUATION"));
            }
        }

        match head.kind {
            kind::DATA => {
                if head.stream == 0 {
                    return Err(ConnErr(Code::Protocol, "DATA on stream 0"));
                }
                // Charged on the padded length: padding consumed window even
                // though it carries nothing.
                recv_window -= head.len as i64;
                let data = frame::unpad(&payload, head.has(flag::PADDED))
                    .ok_or(ConnErr(Code::Protocol, "bad padding"))?;
                replenish(&mut recv_window, tx);

                match state_of(&streams, head.stream, highest_client_stream) {
                    // Never opened. There is no stream to report an error on,
                    // so it can only be a connection error.
                    Where::Idle => return Err(ConnErr(Code::Protocol, "DATA on an idle stream")),
                    // Closed by END_STREAM: the peer is contradicting itself
                    // about a stream we both agreed was finished.
                    Where::Closed => {
                        return Err(ConnErr(Code::StreamClosed, "DATA on a closed stream"))
                    }
                    // We reset it. The peer may simply not have seen the
                    // RST_STREAM yet, so this is its stream's problem, not the
                    // connection's.
                    Where::Reset => {
                        reset_stream(&mut streams, head.stream, Code::StreamClosed, tx);
                        continue;
                    }
                    Where::HalfClosed => {
                        reset_stream(&mut streams, head.stream, Code::StreamClosed, tx);
                        continue;
                    }
                    Where::Open => {}
                }

                let st = streams.get_mut(&head.stream).expect("open implies present");
                if st.body.len() + data.len() > core.client_max_body_size as usize {
                    reset_stream(&mut streams, head.stream, Code::EnhanceYourCalm, tx);
                    continue;
                }
                st.body.extend_from_slice(data);
                if head.has(flag::END_STREAM) {
                    st.state = State::HalfClosedRemote;
                }
            }

            kind::HEADERS => {
                if head.stream == 0 {
                    return Err(ConnErr(Code::Protocol, "HEADERS on stream 0"));
                }
                if head.stream % 2 == 0 {
                    return Err(ConnErr(Code::Protocol, "even client stream id"));
                }

                let mut block = frame::unpad(&payload, head.has(flag::PADDED))
                    .ok_or(ConnErr(Code::Protocol, "bad padding"))?;
                if head.has(flag::PRIORITY) {
                    // Deprecated by RFC 9113 section 5.3.2 but still sent, and
                    // the five bytes have to be skipped regardless.
                    if block.len() < 5 {
                        return Err(ConnErr(Code::FrameSize, "short priority field"));
                    }
                    let dep = frame::u32_at(block, 0).unwrap_or(0) & 0x7fff_ffff;
                    if dep == head.stream {
                        // A stream cannot depend on itself: there is no
                        // ordering that satisfies it.
                        let mut o = Vec::new();
                        frame::rst(head.stream, Code::Protocol, &mut o);
                        let _ = tx.send(o);
                        continue;
                    }
                    block = &block[5..];
                }

                let live = match state_of(&streams, head.stream, highest_client_stream) {
                    Where::Open | Where::HalfClosed => true,
                    Where::Closed | Where::Reset => {
                        return Err(ConnErr(Code::StreamClosed, "HEADERS on a closed stream"))
                    }
                    Where::Idle => false,
                };

                // Falls through to the dispatch step at the bottom of the loop
                // rather than `continue`-ing: trailers are what completes a
                // request, so skipping dispatch here left the response
                // waiting for some unrelated later frame to arrive.
                let mut open_block = true;
                if live {
                    // A second header block on a live stream is trailers, and
                    // trailers must end the stream — without END_STREAM the
                    // peer is opening a block that can never be closed.
                    if !head.has(flag::END_STREAM) {
                        reset_stream(&mut streams, head.stream, Code::Protocol, tx);
                        open_block = false;
                    } else {
                        let st = streams.get_mut(&head.stream).expect("live");
                        st.pending.clear();
                        st.pending.extend_from_slice(block);
                        st.pending_is_trailers = true;
                        st.state = State::HalfClosedRemote;
                    }
                } else {
                    if head.stream <= highest_client_stream {
                        return Err(ConnErr(Code::Protocol, "stream id went backwards"));
                    }
                    highest_client_stream = head.stream;
                    last_stream.set(head.stream);

                    // Drop the state of streams whose tasks have finished, so
                    // a long-lived connection does not accumulate one entry
                    // per request it ever served.
                    streams.retain(|_, s| !(s.dispatched && s.flow.done.get()));

                    // Everything still in flight counts, not just requests
                    // waiting to be dispatched: a stream whose response is
                    // still being written is very much concurrent.
                    let active = streams.values().filter(|s| !s.flow.done.get()).count();
                    if active >= MAX_CONCURRENT as usize {
                        let mut o = Vec::new();
                        frame::rst(head.stream, Code::RefusedStream, &mut o);
                        let _ = tx.send(o);
                        open_block = false;
                    } else {
                        let mut st = Stream::new(peer_initial_window);
                        st.state = if head.has(flag::END_STREAM) {
                            State::HalfClosedRemote
                        } else {
                            State::Open
                        };
                        st.pending.extend_from_slice(block);
                        streams.insert(head.stream, st);
                    }
                }

                if open_block {
                    if head.has(flag::END_HEADERS) {
                        if let Err(e) = finish_block(&mut dec, &mut streams, head.stream, tx)? {
                            return Err(e);
                        }
                    } else {
                        expect_continuation = Some(head.stream);
                    }
                }
            }

            kind::CONTINUATION => {
                // Only legal while a header block is open on this exact
                // stream. The check at the top of the loop catches a *wrong*
                // frame arriving mid-block; this catches a CONTINUATION with
                // no block open at all, which is otherwise indistinguishable
                // from a header block appearing out of nowhere.
                if expect_continuation != Some(head.stream) {
                    return Err(ConnErr(Code::Protocol, "CONTINUATION without an open block"));
                }
                {
                    let st = streams.get_mut(&head.stream).expect("checked");
                    if st.pending.len() + payload.len() > MAX_HEADER_LIST * 2 {
                        return Err(ConnErr(Code::Protocol, "header block too large"));
                    }
                    st.pending.extend_from_slice(&payload);
                }
                if head.has(flag::END_HEADERS) {
                    expect_continuation = None;
                    if let Err(e) = finish_block(&mut dec, &mut streams, head.stream, tx)? {
                        return Err(e);
                    }
                }
            }

            kind::PRIORITY => {
                if head.len != 5 {
                    return Err(ConnErr(Code::FrameSize, "bad PRIORITY length"));
                }
                if head.stream == 0 {
                    return Err(ConnErr(Code::Protocol, "PRIORITY on stream 0"));
                }
                let dep = frame::u32_at(&payload, 0).unwrap_or(0) & 0x7fff_ffff;
                if dep == head.stream {
                    let mut o = Vec::new();
                    frame::rst(head.stream, Code::Protocol, &mut o);
                    let _ = tx.send(o);
                }
                // Otherwise deprecated and ignored.
            }

            kind::RST_STREAM => {
                if head.stream == 0 {
                    return Err(ConnErr(Code::Protocol, "RST_STREAM on stream 0"));
                }
                if head.len != 4 {
                    return Err(ConnErr(Code::FrameSize, "bad RST_STREAM length"));
                }
                if matches!(
                    state_of(&streams, head.stream, highest_client_stream),
                    Where::Idle
                ) {
                    return Err(ConnErr(Code::Protocol, "RST_STREAM on an idle stream"));
                }
                if let Some(st) = streams.get_mut(&head.stream) {
                    st.state = State::Reset;
                    st.flow.reset.set(true);
                }
                flow.wake.notify_waiters();
            }

            kind::SETTINGS => {
                if head.stream != 0 {
                    return Err(ConnErr(Code::Protocol, "SETTINGS on a stream"));
                }
                if head.has(flag::ACK) {
                    if head.len != 0 {
                        return Err(ConnErr(Code::FrameSize, "SETTINGS ack with payload"));
                    }
                    continue;
                }
                if head.len % 6 != 0 {
                    return Err(ConnErr(Code::FrameSize, "SETTINGS length not a multiple of 6"));
                }
                let old_initial = peer_initial_window;
                for c in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([c[0], c[1]]);
                    let v = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
                    match id {
                        setting::INITIAL_WINDOW_SIZE => {
                            if v as i64 > frame::MAX_WINDOW {
                                return Err(ConnErr(Code::FlowControl, "window too large"));
                            }
                            peer_initial_window = v as i64;
                        }
                        setting::MAX_FRAME_SIZE => {
                            if !(frame::DEFAULT_MAX_FRAME..=frame::MAX_FRAME_LIMIT).contains(&v) {
                                return Err(ConnErr(Code::Protocol, "bad MAX_FRAME_SIZE"));
                            }
                            flow.max_frame.set(v as usize);
                        }
                        setting::ENABLE_PUSH => {
                            if v > 1 {
                                return Err(ConnErr(Code::Protocol, "bad ENABLE_PUSH"));
                            }
                        }
                        setting::HEADER_TABLE_SIZE => dec.set_max_size(v as usize),
                        // Unknown settings must be ignored, not refused: that
                        // is how the protocol stays extensible.
                        _ => {}
                    }
                }
                // A changed INITIAL_WINDOW_SIZE retroactively adjusts every
                // open stream by the delta — it is not a new absolute value.
                let delta = peer_initial_window - old_initial;
                if delta != 0 {
                    for s in streams.values() {
                        s.flow.window.set(s.flow.window.get() + delta);
                    }
                    flow.wake.notify_waiters();
                }
                let mut o = Vec::new();
                frame::settings_ack(&mut o);
                let _ = tx.send(o);
            }

            kind::PING => {
                if head.stream != 0 {
                    return Err(ConnErr(Code::Protocol, "PING on a stream"));
                }
                if head.len != 8 {
                    return Err(ConnErr(Code::FrameSize, "bad PING length"));
                }
                if !head.has(flag::ACK) {
                    let mut o = Vec::new();
                    frame::write_frame(kind::PING, flag::ACK, 0, &payload, &mut o);
                    let _ = tx.send(o);
                }
            }

            kind::WINDOW_UPDATE => {
                if head.len != 4 {
                    return Err(ConnErr(Code::FrameSize, "bad WINDOW_UPDATE length"));
                }
                if head.stream != 0
                    && matches!(
                        state_of(&streams, head.stream, highest_client_stream),
                        Where::Idle
                    )
                {
                    return Err(ConnErr(Code::Protocol, "WINDOW_UPDATE on an idle stream"));
                }
                let inc = frame::u32_at(&payload, 0).unwrap_or(0) & 0x7fff_ffff;
                if inc == 0 {
                    if head.stream == 0 {
                        return Err(ConnErr(Code::Protocol, "zero connection window update"));
                    }
                    reset_stream(&mut streams, head.stream, Code::Protocol, tx);
                    continue;
                }
                if head.stream == 0 {
                    let w = flow.conn_window.get() + inc as i64;
                    if w > frame::MAX_WINDOW {
                        return Err(ConnErr(Code::FlowControl, "connection window overflow"));
                    }
                    flow.conn_window.set(w);
                } else if let Some(s) = streams.get(&head.stream) {
                    let w = s.flow.window.get() + inc as i64;
                    if w > frame::MAX_WINDOW {
                        reset_stream(&mut streams, head.stream, Code::FlowControl, tx);
                        continue;
                    }
                    s.flow.window.set(w);
                }
                flow.wake.notify_waiters();
            }

            kind::GOAWAY => {
                // The peer is finished. Anything already in flight still gets
                // written; we simply stop accepting new streams.
                return Ok(());
            }

            kind::PUSH_PROMISE => {
                // Only a server may push, and we advertised that we do not.
                return Err(ConnErr(Code::Protocol, "PUSH_PROMISE from a client"));
            }

            // Unknown frame types must be discarded, which is what makes
            // extensions possible. The payload was already consumed above.
            _ => {}
        }

        // Dispatch anything now complete.
        let ready: Vec<u32> = streams
            .iter()
            .filter(|(_, s)| !s.dispatched && s.headers_done && s.state == State::HalfClosedRemote)
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            let st = streams.get_mut(&id).expect("just listed");
            st.dispatched = true;

            // RFC 9113 section 8.1.1: a content-length that disagrees with the
            // body actually sent is malformed. Two intermediaries could read
            // such a request differently, which is the whole shape of request
            // smuggling — so it is refused rather than reconciled.
            if let Some(n) = st.content_length {
                if n != st.body.len() as u64 {
                    let sf = st.flow.clone();
                    sf.done.set(true);
                    reset_stream(&mut streams, id, Code::Protocol, tx);
                    continue;
                }
            }

            let headers = std::mem::take(&mut st.headers);
            let body = std::mem::take(&mut st.body);
            let sf = st.flow.clone();
            spawn_stream(id, headers, body, sf, shared, flow, tx.clone());
        }
    }
}

/// Where a stream id sits, which decides whether a stray frame is the
/// stream's problem or the connection's.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Where {
    /// Never opened. There is no stream to blame, so errors are connection
    /// errors.
    Idle,
    Open,
    /// The peer said END_STREAM; it may not send more.
    HalfClosed,
    /// Finished normally.
    Closed,
    /// We sent RST_STREAM. Frames may still be in flight from before the peer
    /// saw it, so this is treated more leniently than `Closed`.
    Reset,
}

fn state_of(streams: &HashMap<u32, Stream>, id: u32, highest: u32) -> Where {
    match streams.get(&id) {
        Some(s) => match s.state {
            State::Open => Where::Open,
            State::HalfClosedRemote if s.dispatched => Where::Closed,
            State::HalfClosedRemote => Where::HalfClosed,
            State::Reset => Where::Reset,
        },
        // Pruned entries were dispatched and finished, so a higher-or-equal id
        // that is absent is closed rather than idle.
        None if id <= highest => Where::Closed,
        None => Where::Idle,
    }
}

/// Resets a stream and records that we did, so a DATA frame the peer had
/// already sent is not then treated as a connection error.
fn reset_stream(
    streams: &mut HashMap<u32, Stream>,
    id: u32,
    code: Code,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut o = Vec::new();
    frame::rst(id, code, &mut o);
    let _ = tx.send(o);
    if let Some(s) = streams.get_mut(&id) {
        s.state = State::Reset;
        s.flow.reset.set(true);
        s.flow.done.set(true);
    }
}

/// Decodes a completed header block.
///
/// Decoding happens the moment END_HEADERS arrives rather than at dispatch,
/// because HPACK is a running conversation: blocks must be decoded in the
/// order they arrived on the connection. Deferring meant another stream's
/// block could be decoded in between, and trailers were never decoded at all —
/// both leave the two ends with different dynamic tables, after which every
/// later header decodes to something neither side sent.
#[allow(clippy::type_complexity)]
fn finish_block(
    dec: &mut hpack::Decoder,
    streams: &mut HashMap<u32, Stream>,
    id: u32,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> Result<Result<(), ConnErr>, ConnErr> {
    let Some(st) = streams.get_mut(&id) else { return Ok(Ok(())) };
    let block = std::mem::take(&mut st.pending);
    let trailers = st.pending_is_trailers;

    let mut out = Vec::with_capacity(16);
    match dec.decode(&block, MAX_HEADER_LIST, &mut out) {
        Ok(()) => {}
        // Not recoverable per stream: the tables are shared, so every later
        // block on this connection would decode wrong.
        Err(HpackError::Compression) => {
            return Err(ConnErr(Code::Compression, "hpack decoding error"))
        }
        Err(HpackError::TooLarge) => {
            reset_stream(streams, id, Code::EnhanceYourCalm, tx);
            return Ok(Ok(()));
        }
    }

    if trailers {
        // RFC 9113 section 8.1: trailers carry no pseudo-header fields. The
        // block was still decoded above, because skipping it would desync the
        // HPACK table even though we discard the result.
        if out.iter().any(|h| h.name.starts_with(':')) {
            reset_stream(streams, id, Code::Protocol, tx);
        }
        return Ok(Ok(()));
    }

    st.content_length = out
        .iter()
        .find(|h| h.name == "content-length")
        .and_then(|h| h.value.parse::<u64>().ok());
    st.headers = out;
    st.headers_done = true;
    Ok(Ok(()))
}


type R2 = Result<(), ConnErr>;

/// Returns connection-level window to the peer once enough has been used.
fn replenish(recv_window: &mut i64, tx: &mpsc::UnboundedSender<Vec<u8>>) {
    let used = OUR_INITIAL_WINDOW as i64 - *recv_window;
    if used >= WINDOW_REFILL_AT {
        let mut o = Vec::new();
        frame::window_update(0, used as u32, &mut o);
        let _ = tx.send(o);
        *recv_window = OUR_INITIAL_WINDOW as i64;
    }
}

/// Turns a decoded header list into a request and runs it.
#[allow(clippy::too_many_arguments)]
fn spawn_stream(
    id: u32,
    headers: Vec<hpack::Header>,
    req_body: Vec<u8>,
    sflow: Rc<StreamFlow>,
    shared: &Task,
    flow: &Rc<Flow>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    let listener = shared.listener.clone();
    let http = shared.http.clone();
    let logs = shared.logs.clone();
    let (remote, local, scheme, conn_id) =
        (shared.remote, shared.local, shared.scheme, shared.conn_id);
    let flow = flow.clone();

    tokio::task::spawn_local(async move {
        // Whatever happens below, the reader must be told this stream is over
        // or its flow entry lives as long as the connection.
        let _done = DoneGuard(sflow.clone());
        let parsed = match parse_headers(&headers) {
            Ok(p) => p,
            Err(code) => {
                // A malformed request is a stream error, not a connection one:
                // the other streams are unaffected.
                let mut o = Vec::new();
                frame::rst(id, code, &mut o);
                let _ = tx.send(o);
                return;
            }
        };

        let (buf, mut req) = Req::from_parts(&parsed.method, &parsed.path, &parsed.headers());
        if !req_body.is_empty() {
            req.body = ReqBody::Length(req_body.len() as u64);
        }

        let server: &Arc<ServerConf> = listener.match_host(&parsed.authority);
        let normalised = match uri::normalize(req.path_str(&buf)) {
            Ok(u) => u,
            Err(_) => {
                let mut o = Vec::new();
                frame::rst(id, Code::Protocol, &mut o);
                let _ = tx.send(o);
                return;
            }
        };

        let mut ctx = Ctx::new(
            &buf, &req, &req_body, &http, server, normalised, remote, local, scheme, conn_id, id
                as u64,
        );

        let reply = handler::handle(&mut ctx).await;
        // `frame(true)` fills in Content-Length when the length is known. Its
        // chunked fallback is meaningless here — HTTP/2 frames the body with
        // END_STREAM — so the write path ignores that case rather than
        // emitting a Transfer-Encoding header, which RFC 9113 section 8.2.2
        // forbids outright.
        let mut reply = reply.frame(true);
        let head_only = req.method == Method::Head;
        if head_only {
            reply.body = Body::Empty;
        }
        let status = reply.resp.status;

        // Split so the response headers survive into logging: `$sent_http_*`
        // must work over HTTP/2 exactly as it does over HTTP/1.
        let Reply { resp, body } = reply;
        let (body_bytes, total) = send_response(id, &resp, body, &flow, &sflow, &tx).await;
        crate::server::conn::log_request(&logs, &ctx, &resp, status, body_bytes, total);
    });
}

/// Marks a stream's flow entry finished however the task exits, including on
/// an early return for a malformed request.
struct DoneGuard(Rc<StreamFlow>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.0.done.set(true);
    }
}

/// The pseudo-headers plus the ordinary ones, validated.
struct Parsed {
    method: String,
    path: String,
    authority: String,
    ordinary: Vec<(String, String)>,
}

impl Parsed {
    fn headers(&self) -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> = Vec::with_capacity(self.ordinary.len() + 1);
        // HTTP/2 replaces `Host` with `:authority`. Everything downstream —
        // `server_name` matching, `$host`, `proxy_set_header Host` — reads a
        // Host header, so it is reconstructed here rather than special-cased
        // in a dozen places.
        v.push(("host", &self.authority));
        for (n, val) in &self.ordinary {
            v.push((n, val));
        }
        v
    }
}

/// Validates a decoded header list against RFC 9113 section 8.3.
fn parse_headers(headers: &[hpack::Header]) -> Result<Parsed, Code> {
    let (mut method, mut path, mut authority, mut scheme) = (None, None, None, None);
    let mut ordinary = Vec::with_capacity(headers.len());
    let mut seen_ordinary = false;

    for h in headers {
        if let Some(name) = h.name.strip_prefix(':') {
            // Pseudo-headers must all precede the ordinary ones; a peer that
            // interleaves them is producing a request two parsers could read
            // differently.
            if seen_ordinary {
                return Err(Code::Protocol);
            }
            let slot = match name {
                "method" => &mut method,
                "path" => &mut path,
                "authority" => &mut authority,
                "scheme" => &mut scheme,
                // ":protocol" and anything else is not something we implement,
                // and an unknown pseudo-header is malformed, not ignorable.
                _ => return Err(Code::Protocol),
            };
            if slot.is_some() {
                return Err(Code::Protocol); // duplicates are malformed
            }
            *slot = Some(h.value.clone());
            continue;
        }
        seen_ordinary = true;

        // Field names are lowercase in HTTP/2. An uppercase one is malformed
        // rather than something to normalise: normalising would let a peer
        // send `Content-Length` and `content-length` as distinct fields.
        if h.name.bytes().any(|b| b.is_ascii_uppercase()) || h.name.is_empty() {
            return Err(Code::Protocol);
        }
        // Connection-specific headers have no meaning here and are exactly the
        // shape a downgrade attack uses when a proxy re-serialises to HTTP/1.
        match h.name.as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
            | "upgrade" => return Err(Code::Protocol),
            // RFC 9113 section 8.2.2: TE may only say "trailers".
            "te" if h.value != "trailers" => return Err(Code::Protocol),
            _ => {}
        }
        ordinary.push((h.name.clone(), h.value.clone()));
    }

    let method = method.ok_or(Code::Protocol)?;
    let path = path.ok_or(Code::Protocol)?;
    // CONNECT omits :scheme and :path, and we do not implement it.
    if method == "CONNECT" {
        return Err(Code::Protocol);
    }
    scheme.ok_or(Code::Protocol)?;
    // An empty :path never identifies a resource.
    if path.is_empty() {
        return Err(Code::Protocol);
    }

    Ok(Parsed { method, path, authority: authority.unwrap_or_default(), ordinary })
}

/// Writes a response as HEADERS plus DATA, respecting flow control.
///
/// Returns `(body bytes, total bytes)` for logging.
async fn send_response(
    id: u32,
    resp: &Resp,
    body: Body,
    flow: &Rc<Flow>,
    st: &Rc<StreamFlow>,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> (u64, u64) {
    let mut enc = hpack::Encoder::new(4096);
    let mut block = Vec::with_capacity(256);
    enc.begin_block(&mut block);
    enc.encode(":status", &resp.status.to_string(), &mut block);
    for (n, v) in resp.iter() {
        // Never re-emit connection-specific headers over HTTP/2.
        if matches!(
            n.to_ascii_lowercase().as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "proxy-connection"
        ) {
            continue;
        }
        enc.encode(&n.to_ascii_lowercase(), v, &mut block);
    }
    if let Framing::Length(n) = resp.framing {
        enc.encode("content-length", &n.to_string(), &mut block);
    }

    let empty = body.is_empty();
    let mut out = Vec::with_capacity(block.len() + frame::HEADER_LEN);
    let flags = flag::END_HEADERS | if empty { flag::END_STREAM } else { 0 };
    frame::write_frame(kind::HEADERS, flags, id, &block, &mut out);
    let total_head = out.len() as u64;
    if tx.send(out).is_err() || empty {
        return (0, total_head);
    }

    let body_bytes = write_body(id, body, flow, st, tx).await;
    (body_bytes, total_head + body_bytes)
}

/// Frames a response body into DATA, waiting when a window closes.
async fn write_body(
    id: u32,
    body: Body,
    flow: &Rc<Flow>,
    st: &Rc<StreamFlow>,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> u64 {
    let mut sent = 0u64;
    let send = |chunk: &[u8], end: bool, tx: &mpsc::UnboundedSender<Vec<u8>>| -> bool {
        let mut o = Vec::with_capacity(chunk.len() + frame::HEADER_LEN);
        frame::write_frame(kind::DATA, if end { flag::END_STREAM } else { 0 }, id, chunk, &mut o);
        tx.send(o).is_ok()
    };

    match body {
        Body::Empty => {
            send(&[], true, tx);
        }
        Body::Bytes(b) => {
            sent += pump(id, &b, flow, st, tx).await;
            send(&[], true, tx);
        }
        Body::Mmap { map, range } => {
            sent += pump(id, &map[range], flow, st, tx).await;
            send(&[], true, tx);
        }
        Body::Inline { file, offset, len } | Body::File { file, offset, len } => {
            // No `sendfile` here, and there cannot be: every byte has to be
            // wrapped in a DATA frame, so the kernel cannot hand the page
            // cache straight to the socket. This is inherent to HTTP/2, not a
            // shortcut — nginx pays the same cost.
            let mut left = len;
            let mut off = offset;
            let mut chunk = vec![0u8; 64 * 1024];
            while left > 0 {
                let want = (left as usize).min(chunk.len());
                let n = match read_at(&file, &mut chunk[..want], off) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                sent += pump(id, &chunk[..n], flow, st, tx).await;
                off += n as u64;
                left -= n as u64;
                if st.reset.get() || flow.closed.get() {
                    return sent;
                }
            }
            send(&[], true, tx);
        }
        Body::Upgraded { .. } => {
            // Unreachable: RFC 9113 has no 101, and `parse_headers` refuses a
            // request carrying `connection` or `upgrade`, so no HTTP/2 stream
            // can ever ask for a protocol switch. Ending the stream is the
            // only honest thing to do if one somehow arrives.
            send(&[], true, tx);
        }
        Body::Stream { pre, mut io, .. } => {
            sent += pump(id, &pre, flow, st, tx).await;
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                if st.reset.get() || flow.closed.get() {
                    return sent;
                }
                match io.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sent += pump(id, &chunk[..n], flow, st, tx).await,
                }
            }
            send(&[], true, tx);
        }
    }
    sent
}

/// Sends `data` as one or more DATA frames, blocking while the windows are
/// closed.
async fn pump(
    id: u32,
    data: &[u8],
    flow: &Rc<Flow>,
    st: &Rc<StreamFlow>,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> u64 {
    let mut off = 0usize;
    let mut sent = 0u64;
    while off < data.len() {
        if st.reset.get() || flow.closed.get() {
            return sent;
        }
        // Register for the wakeup *before* reading the windows. `notify_waiters`
        // wakes only tasks already waiting and leaves no permit behind, so
        // checking first and awaiting second loses any WINDOW_UPDATE that lands
        // in between — and the response hangs until the connection times out.
        let notified = flow.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let allowed = flow.conn_window.get().min(st.window.get()).max(0) as usize;
        if allowed == 0 {
            // Nothing to do but wait. This is the whole point of flow control:
            // a client that stops reading must not be able to make us buffer
            // without bound.
            notified.await;
            continue;
        }
        let n = allowed.min(flow.max_frame.get()).min(data.len() - off);
        let mut o = Vec::with_capacity(n + frame::HEADER_LEN);
        frame::write_frame(kind::DATA, 0, id, &data[off..off + n], &mut o);
        if tx.send(o).is_err() {
            return sent;
        }
        flow.conn_window.set(flow.conn_window.get() - n as i64);
        st.window.set(st.window.get() - n as i64);
        off += n;
        sent += n as u64;
    }
    sent
}

#[cfg(unix)]
fn read_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    f.read_at(buf, off)
}

#[cfg(not(unix))]
fn read_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = f;
    f.seek(SeekFrom::Start(off))?;
    f.read(buf)
}

/// A growable read buffer that hands out exact-length slices.
struct Buf {
    data: Vec<u8>,
    start: usize,
}

impl Buf {
    fn new(initial: Vec<u8>) -> Buf {
        Buf { data: initial, start: 0 }
    }

    /// Reads exactly `n` bytes, or fails the connection.
    async fn take<R: AsyncRead + Unpin>(
        &mut self,
        rd: &mut R,
        n: usize,
        idle: Duration,
    ) -> Result<&[u8], ConnErr> {
        match self.take_opt(rd, n, idle).await? {
            Some(_) => {}
            None => return Err(ConnErr(Code::Protocol, "truncated frame")),
        }
        let s = self.start - n;
        Ok(&self.data[s..self.start])
    }

    /// Like `take`, but a clean EOF on a frame boundary returns `None`.
    async fn take_opt<R: AsyncRead + Unpin>(
        &mut self,
        rd: &mut R,
        n: usize,
        idle: Duration,
    ) -> Result<Option<&[u8]>, ConnErr> {
        // Compact once the consumed prefix is worth reclaiming, so a long-lived
        // connection does not grow its buffer forever.
        if self.start > 0 && self.start >= self.data.len() {
            self.data.clear();
            self.start = 0;
        } else if self.start > 64 * 1024 {
            self.data.drain(..self.start);
            self.start = 0;
        }

        while self.data.len() - self.start < n {
            let before = self.data.len();
            self.data.resize(before + 16 * 1024, 0);
            let got = match tokio::time::timeout(idle, rd.read(&mut self.data[before..])).await {
                Ok(Ok(g)) => g,
                Ok(Err(_)) | Err(_) => {
                    self.data.truncate(before);
                    return Err(ConnErr(Code::NoError, "read failed"));
                }
            };
            self.data.truncate(before + got);
            if got == 0 {
                // EOF exactly between frames is how a well-behaved client
                // closes; mid-frame it is truncation.
                if self.data.len() == self.start {
                    return Ok(None);
                }
                return Err(ConnErr(Code::Protocol, "truncated frame"));
            }
        }
        self.start += n;
        let s = self.start - n;
        Ok(Some(&self.data[s..self.start]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: &str, v: &str) -> hpack::Header {
        hpack::Header { name: n.into(), value: v.into() }
    }

    #[test]
    fn a_minimal_request_parses() {
        let p = parse_headers(&[
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":authority", "example.com"),
            h(":path", "/a?b=1"),
            h("user-agent", "x"),
        ])
        .unwrap();
        assert_eq!(p.method, "GET");
        assert_eq!(p.path, "/a?b=1");
        assert_eq!(p.authority, "example.com");
        assert_eq!(p.ordinary, [("user-agent".to_string(), "x".to_string())]);
    }

    #[test]
    fn the_authority_becomes_a_host_header() {
        // Everything downstream reads Host: server_name matching, `$host`,
        // `proxy_set_header Host $host`. Reconstructing it here keeps that
        // single path rather than teaching each one about :authority.
        let p = parse_headers(&[
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":authority", "api.example.com"),
            h(":path", "/"),
        ])
        .unwrap();
        assert_eq!(p.headers()[0], ("host", "api.example.com"));
    }

    #[test]
    fn a_pseudo_header_after_a_regular_one_is_malformed() {
        // Two parsers could disagree about such a request, which is what makes
        // it worth refusing rather than reordering.
        assert!(parse_headers(&[
            h(":method", "GET"),
            h("x", "1"),
            h(":path", "/"),
            h(":scheme", "https"),
        ])
        .is_err());
    }

    #[test]
    fn duplicate_and_unknown_pseudo_headers_are_malformed() {
        let base = [h(":method", "GET"), h(":scheme", "https"), h(":path", "/")];
        let mut dup = base.to_vec();
        dup.push(h(":path", "/other"));
        assert!(parse_headers(&dup).is_err(), "duplicate :path");

        let mut unknown = base.to_vec();
        unknown.push(h(":madeup", "1"));
        assert!(parse_headers(&unknown).is_err(), "unknown pseudo-header");
    }

    #[test]
    fn connection_specific_headers_are_refused() {
        // These are exactly what a request-smuggling downgrade relies on when
        // a proxy re-serialises an HTTP/2 request as HTTP/1.1.
        for bad in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"]
        {
            let hs = [
                h(":method", "GET"),
                h(":scheme", "https"),
                h(":path", "/"),
                h(bad, "x"),
            ];
            assert!(parse_headers(&hs).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn te_may_only_say_trailers() {
        let ok = [
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h("te", "trailers"),
        ];
        assert!(parse_headers(&ok).is_ok());
        let bad = [
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h("te", "gzip"),
        ];
        assert!(parse_headers(&bad).is_err());
    }

    #[test]
    fn an_uppercase_field_name_is_malformed() {
        // Normalising instead would let a peer send Content-Length and
        // content-length as two distinct fields.
        let hs = [
            h(":method", "GET"),
            h(":scheme", "https"),
            h(":path", "/"),
            h("Content-Length", "5"),
        ];
        assert!(parse_headers(&hs).is_err());
    }

    #[test]
    fn the_required_pseudo_headers_are_required() {
        assert!(parse_headers(&[h(":scheme", "https"), h(":path", "/")]).is_err(), "no :method");
        assert!(parse_headers(&[h(":method", "GET"), h(":scheme", "https")]).is_err(), "no :path");
        assert!(parse_headers(&[h(":method", "GET"), h(":path", "/")]).is_err(), "no :scheme");
        assert!(
            parse_headers(&[h(":method", "GET"), h(":scheme", "https"), h(":path", "")]).is_err(),
            "empty :path"
        );
    }

    #[test]
    fn connect_is_refused_rather_than_half_implemented() {
        let hs = [h(":method", "CONNECT"), h(":authority", "example.com:443")];
        assert!(parse_headers(&hs).is_err());
    }

    #[test]
    fn a_request_becomes_a_req_the_rest_of_the_server_understands() {
        // The whole point of the design: after this, every handler, variable
        // and directive sees an ordinary request.
        let p = parse_headers(&[
            h(":method", "POST"),
            h(":scheme", "https"),
            h(":authority", "example.com"),
            h(":path", "/upload?x=1"),
            h("content-type", "text/plain"),
        ])
        .unwrap();
        let (buf, req) = Req::from_parts(&p.method, &p.path, &p.headers());
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.path_str(&buf), "/upload");
        assert_eq!(req.target_str(&buf), "/upload?x=1");
        assert_eq!(req.host(&buf), "example.com");
        assert_eq!(
            req.hot_value(&buf, crate::http::request::Hot::ContentType),
            Some("text/plain")
        );
    }
}

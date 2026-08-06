//! HTTP/2 tests, driven by a hand-rolled client.
//!
//! The client is deliberately explicit about frames rather than wrapping a
//! library: these tests exist to check *our* framing, flow control and error
//! handling, and a client that papered over a protocol violation would hide
//! exactly what is under test.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use oxiserve::http2::frame::{self, flag, kind, setting, Head};
use oxiserve::http2::hpack;

static NEXT_PORT: AtomicU16 = AtomicU16::new(19700);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

struct Server {
    port: u16,
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, body: &str) -> Server {
        let p = port();
        let dir =
            std::env::temp_dir().join(format!("oxiserve-h2-{}-{name}-{p}", std::process::id()));
        std::fs::create_dir_all(dir.join("www")).unwrap();
        let text = format!(
            "worker_processes 1;\nerror_log {}/error.log crit;\nevents {{ worker_connections 256; }}\nhttp {{\naccess_log off;\n{}\n}}",
            dir.display(),
            body
        )
        .replace("{PORT}", &p.to_string())
        .replace("{ROOT}", dir.join("www").to_str().unwrap());
        let cpath = dir.join("oxiserve.conf");
        std::fs::write(&cpath, text).unwrap();
        let cfg = oxiserve::config::load(&cpath, dir.clone()).unwrap_or_else(|e| panic!("{e}"));
        std::thread::spawn(move || {
            let _ = oxiserve::server::run(cfg);
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", p)).is_ok() {
                return Server { port: p, dir };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("server never came up");
    }

    fn write_file(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join("www").join(name), bytes).unwrap();
    }

    fn connect(&self) -> H2 {
        H2::open(self.port)
    }
}

/// A minimal HTTP/2 client speaking to one connection.
struct H2 {
    sock: TcpStream,
    enc: hpack::Encoder,
    dec: hpack::Decoder,
    buf: Vec<u8>,
}

/// One frame as the client saw it.
#[derive(Debug, Clone)]
struct Frame {
    head: Head,
    payload: Vec<u8>,
}

impl H2 {
    fn open(port: u16) -> H2 {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        sock.write_all(frame::PREFACE).unwrap();
        let mut out = Vec::new();
        frame::settings(&[], &mut out);
        sock.write_all(&out).unwrap();
        H2 {
            sock,
            enc: hpack::Encoder::new(4096),
            dec: hpack::Decoder::new(4096),
            buf: Vec::new(),
        }
    }

    /// Opens a stream with a HEADERS frame.
    fn request(&mut self, id: u32, method: &str, path: &str, extra: &[(&str, &str)], end: bool) {
        let mut block = Vec::new();
        self.enc.begin_block(&mut block);
        self.enc.encode(":method", method, &mut block);
        self.enc.encode(":scheme", "http", &mut block);
        self.enc.encode(":authority", "localhost", &mut block);
        self.enc.encode(":path", path, &mut block);
        for (n, v) in extra {
            self.enc.encode(n, v, &mut block);
        }
        let flags = flag::END_HEADERS | if end { flag::END_STREAM } else { 0 };
        let mut out = Vec::new();
        frame::write_frame(kind::HEADERS, flags, id, &block, &mut out);
        self.sock.write_all(&out).unwrap();
    }

    /// Sends a raw header block, so a test can violate the rules on purpose.
    fn raw_headers(&mut self, id: u32, fields: &[(&str, &str)], end: bool) {
        let mut block = Vec::new();
        self.enc.begin_block(&mut block);
        for (n, v) in fields {
            self.enc.encode(n, v, &mut block);
        }
        let flags = flag::END_HEADERS | if end { flag::END_STREAM } else { 0 };
        let mut out = Vec::new();
        frame::write_frame(kind::HEADERS, flags, id, &block, &mut out);
        self.sock.write_all(&out).unwrap();
    }

    fn data(&mut self, id: u32, bytes: &[u8], end: bool) {
        let mut out = Vec::new();
        frame::write_frame(kind::DATA, if end { flag::END_STREAM } else { 0 }, id, bytes, &mut out);
        self.sock.write_all(&out).unwrap();
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let _ = self.sock.write_all(bytes);
    }

    /// Reads one frame, or `None` at end of stream.
    fn frame(&mut self) -> Option<Frame> {
        let head_bytes = self.read_exact(frame::HEADER_LEN)?;
        let head = Head::parse(&head_bytes[..].try_into().unwrap());
        let payload = if head.len == 0 {
            Vec::new()
        } else {
            self.read_exact(head.len as usize)?
        };
        Some(Frame { head, payload })
    }

    fn read_exact(&mut self, n: usize) -> Option<Vec<u8>> {
        let mut chunk = [0u8; 16384];
        while self.buf.len() < n {
            match self.sock.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(got) => self.buf.extend_from_slice(&chunk[..got]),
            }
        }
        Some(self.buf.drain(..n).collect())
    }

    /// Collects frames until every listed stream has ended, or the connection
    /// goes away.
    fn collect(&mut self, streams: &[u32]) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut open: Vec<u32> = streams.to_vec();
        while !open.is_empty() {
            let Some(f) = self.frame() else { break };
            if f.head.kind == kind::GOAWAY {
                out.push(f);
                break;
            }
            if f.head.has(flag::END_STREAM) && f.head.kind != kind::SETTINGS {
                open.retain(|s| *s != f.head.stream);
            }
            if f.head.kind == kind::RST_STREAM {
                open.retain(|s| *s != f.head.stream);
            }
            out.push(f);
        }
        out
    }

    /// The decoded response headers for a stream.
    fn headers_of(&mut self, frames: &[Frame], id: u32) -> Vec<(String, String)> {
        let block: Vec<u8> = frames
            .iter()
            .filter(|f| f.head.kind == kind::HEADERS && f.head.stream == id)
            .flat_map(|f| f.payload.clone())
            .collect();
        let mut out = Vec::new();
        self.dec.decode(&block, 1 << 20, &mut out).expect("response headers must decode");
        out.into_iter().map(|h| (h.name, h.value)).collect()
    }
}

fn body_of(frames: &[Frame], id: u32) -> Vec<u8> {
    frames
        .iter()
        .filter(|f| f.head.kind == kind::DATA && f.head.stream == id)
        .flat_map(|f| f.payload.clone())
        .collect()
}

fn status_of(headers: &[(String, String)]) -> &str {
    headers.iter().find(|(n, _)| n == ":status").map(|(_, v)| v.as_str()).unwrap_or("")
}

const STATIC: &str = "server { listen {PORT} http2; root {ROOT}; location / { index index.html; } }";

// ---------------------------------------------------------------------------

#[test]
fn a_simple_get_works_over_h2c() {
    let s = Server::start("get", STATIC);
    s.write_file("index.html", b"<h1>hello</h1>");
    let mut c = s.connect();
    c.request(1, "GET", "/", &[], true);
    let frames = c.collect(&[1]);
    let h = c.headers_of(&frames, 1);
    assert_eq!(status_of(&h), "200");
    assert_eq!(body_of(&frames, 1), b"<h1>hello</h1>");
    assert!(
        h.iter().any(|(n, v)| n == "content-type" && v.starts_with("text/html")),
        "the normal handler pipeline must still set the type: {h:?}"
    );
}

#[test]
fn no_connection_specific_headers_are_ever_sent() {
    // RFC 9113 section 8.2.2 forbids them outright, and a client is entitled
    // to treat one as a connection error.
    let s = Server::start("nohop", STATIC);
    s.write_file("index.html", b"x");
    let mut c = s.connect();
    c.request(1, "GET", "/", &[], true);
    let frames = c.collect(&[1]);
    let h = c.headers_of(&frames, 1);
    for (n, _) in &h {
        assert!(
            !matches!(
                n.as_str(),
                "connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "proxy-connection"
            ),
            "must not send {n}"
        );
        assert!(!n.bytes().any(|b| b.is_ascii_uppercase()), "field names are lowercase: {n}");
    }
}

#[test]
fn streams_are_multiplexed_not_serialised() {
    // The reason HTTP/2 exists. Three requests are sent before any response is
    // read; all three must complete on one connection.
    let s = Server::start("mux", STATIC);
    s.write_file("a.txt", b"AAA");
    s.write_file("b.txt", b"BBB");
    s.write_file("c.txt", b"CCC");
    let mut c = s.connect();
    c.request(1, "GET", "/a.txt", &[], true);
    c.request(3, "GET", "/b.txt", &[], true);
    c.request(5, "GET", "/c.txt", &[], true);
    let frames = c.collect(&[1, 3, 5]);
    assert_eq!(body_of(&frames, 1), b"AAA");
    assert_eq!(body_of(&frames, 3), b"BBB");
    assert_eq!(body_of(&frames, 5), b"CCC");
}

#[test]
fn a_large_body_crosses_flow_control_windows_intact() {
    // The default window is 64 KB and the default frame 16 KB, so a 1 MB file
    // exercises both the frame split and the WINDOW_UPDATE loop. A truncation
    // or an off-by-one in the window accounting shows up here and nowhere else.
    let s = Server::start("bigbody", STATIC);
    let big: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    s.write_file("big.bin", &big);

    let mut c = s.connect();
    c.request(1, "GET", "/big.bin", &[], true);

    let mut got = Vec::new();
    let mut done = false;
    while !done {
        let Some(f) = c.frame() else { break };
        match f.head.kind {
            kind::DATA if f.head.stream == 1 => {
                assert!(
                    f.payload.len() <= frame::DEFAULT_MAX_FRAME as usize,
                    "a DATA frame must not exceed the negotiated max frame size"
                );
                got.extend_from_slice(&f.payload);
                // Give the window back, or the transfer stalls by design.
                let mut o = Vec::new();
                frame::window_update(0, f.payload.len() as u32, &mut o);
                frame::window_update(1, f.payload.len() as u32, &mut o);
                c.send_raw(&o);
                if f.head.has(flag::END_STREAM) {
                    done = true;
                }
            }
            kind::HEADERS if f.head.has(flag::END_STREAM) => done = true,
            _ => {}
        }
    }
    assert_eq!(got.len(), big.len(), "body length");
    assert_eq!(got, big, "body content");
}

#[test]
fn a_closed_window_stops_the_sender_until_it_reopens() {
    // The property flow control exists for: a client that stops reading must
    // not be able to make the server buffer without bound. With the default
    // 64 KB window and no updates, exactly that much may arrive and no more.
    let s = Server::start("window", STATIC);
    let big: Vec<u8> = vec![b'z'; 300_000];
    s.write_file("big.bin", &big);

    let mut c = s.connect();
    c.request(1, "GET", "/big.bin", &[], true);

    let mut got = 0usize;
    c.sock.set_read_timeout(Some(Duration::from_millis(600))).unwrap();
    while let Some(f) = c.frame() {
        if f.head.kind == kind::DATA {
            got += f.payload.len();
        }
    }
    assert!(
        got <= frame::DEFAULT_WINDOW as usize,
        "sent {got} bytes into a {} byte window",
        frame::DEFAULT_WINDOW
    );
    assert!(got > 0, "the server should have filled the window it was given");
}

#[test]
fn a_post_body_reaches_the_handler() {
    let s = Server::start("post", "server { listen {PORT} http2; root {ROOT};\n\
        location / { return 200 \"len=$content_length\"; } }");
    let mut c = s.connect();
    c.request(1, "POST", "/upload", &[("content-length", "11")], false);
    c.data(1, b"hello ", false);
    c.data(1, b"world", true);
    let frames = c.collect(&[1]);
    assert_eq!(status_of(&c.headers_of(&frames, 1)), "200");
    assert_eq!(body_of(&frames, 1), b"len=11");
}

#[test]
fn variables_and_directives_behave_as_they_do_over_http_1() {
    // The whole design claim: HTTP/2 is a transport swap, so everything above
    // the framing layer must be unchanged. If `$request_method`, `$uri`,
    // `$args` and `$host` all survive, the request really did become an
    // ordinary one.
    let s = Server::start(
        "vars",
        "server { listen {PORT} http2; root {ROOT};\n\
         location /probe { return 200 \"$request_method|$uri|$args|$host|$scheme|$http_user_agent\"; } }",
    );
    let mut c = s.connect();
    c.request(1, "GET", "/probe?a=1&b=2", &[("user-agent", "probe/1.0")], true);
    let frames = c.collect(&[1]);
    assert_eq!(
        String::from_utf8_lossy(&body_of(&frames, 1)),
        "GET|/probe|a=1&b=2|localhost|http|probe/1.0"
    );
}

#[test]
fn the_authority_selects_the_server_block() {
    // :authority replaces Host, so server_name matching has to see it or a
    // virtual-host config silently collapses onto the default server.
    let s = Server::start(
        "vhost",
        "server { listen {PORT} http2; server_name a.test; location / { return 200 \"A\"; } }\n\
         server { listen {PORT} http2; server_name b.test; location / { return 200 \"B\"; } }",
    );
    let mut c = s.connect();
    let mut block = Vec::new();
    c.enc.begin_block(&mut block);
    for (n, v) in [(":method", "GET"), (":scheme", "http"), (":authority", "b.test"), (":path", "/")]
    {
        c.enc.encode(n, v, &mut block);
    }
    let mut out = Vec::new();
    frame::write_frame(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block, &mut out);
    c.send_raw(&out);
    let frames = c.collect(&[1]);
    assert_eq!(body_of(&frames, 1), b"B");
}

#[test]
fn a_head_request_sends_headers_and_no_body() {
    let s = Server::start("head", STATIC);
    s.write_file("index.html", b"<h1>hello</h1>");
    let mut c = s.connect();
    c.request(1, "HEAD", "/", &[], true);
    let frames = c.collect(&[1]);
    let h = c.headers_of(&frames, 1);
    assert_eq!(status_of(&h), "200");
    assert_eq!(
        h.iter().find(|(n, _)| n == "content-length").map(|(_, v)| v.as_str()),
        Some("14"),
        "HEAD still reports the length it would have sent"
    );
    assert!(body_of(&frames, 1).is_empty(), "HEAD must carry no body");
}

#[test]
fn a_malformed_request_resets_only_its_own_stream() {
    // A bad request is a stream error. Killing the connection would punish
    // every other request multiplexed onto it.
    let s = Server::start("malformed", STATIC);
    s.write_file("index.html", b"ok");
    let mut c = s.connect();
    // Uppercase field name: malformed per RFC 9113 section 8.2.1.
    c.raw_headers(
        1,
        &[(":method", "GET"), (":scheme", "http"), (":path", "/"), ("Bad-Name", "x")],
        true,
    );
    c.request(3, "GET", "/", &[], true);
    let frames = c.collect(&[1, 3]);
    assert!(
        frames.iter().any(|f| f.head.kind == kind::RST_STREAM && f.head.stream == 1),
        "stream 1 should be reset: {:?}",
        frames.iter().map(|f| (f.head.kind, f.head.stream)).collect::<Vec<_>>()
    );
    assert_eq!(body_of(&frames, 3), b"ok", "stream 3 must be unaffected");
}

#[test]
fn a_missing_pseudo_header_is_refused() {
    let s = Server::start("nopath", STATIC);
    let mut c = s.connect();
    c.raw_headers(1, &[(":method", "GET"), (":scheme", "http")], true);
    let frames = c.collect(&[1]);
    assert!(
        frames.iter().any(|f| matches!(f.head.kind, kind::RST_STREAM | kind::GOAWAY)),
        "a request without :path must not be served"
    );
}

#[test]
fn a_corrupt_preface_never_starts_an_http2_connection() {
    // On a cleartext port there is no way to tell "a client that meant HTTP/2
    // and got the preface wrong" from "a client sending an odd HTTP/1
    // request" — nothing has committed either side to a version. So the bytes
    // fall through to the HTTP/1 parser, which rejects them: `PRI * HTTP/2.0`
    // is not a valid request line. What must not happen is the server
    // proceeding to read HTTP/2 frames from a peer that never proved it
    // speaks HTTP/2. Over TLS the same input is a GOAWAY, because ALPN has
    // already settled the question.
    let s = Server::start("preface", STATIC);
    let mut sock = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    // 505: the HTTP/1 parser reads `HTTP/2.0` as a version it does not
    // support, which is exactly the right thing to say about these bytes.
    assert!(
        text.starts_with("HTTP/1.1 505"),
        "expected an HTTP/1 rejection, got {:?}",
        &text[..text.len().min(60)]
    );
}

#[test]
fn ping_is_answered_with_an_ack() {
    let s = Server::start("ping", STATIC);
    let mut c = s.connect();
    let mut out = Vec::new();
    frame::write_frame(kind::PING, 0, 0, b"12345678", &mut out);
    c.send_raw(&out);
    let mut seen = false;
    for _ in 0..8 {
        let Some(f) = c.frame() else { break };
        if f.head.kind == kind::PING && f.head.has(flag::ACK) {
            assert_eq!(f.payload, b"12345678", "the ack must echo the payload");
            seen = true;
            break;
        }
    }
    assert!(seen, "PING must be acked");
}

#[test]
fn a_ping_on_a_stream_is_a_connection_error() {
    let s = Server::start("badping", STATIC);
    let mut c = s.connect();
    let mut out = Vec::new();
    frame::write_frame(kind::PING, 0, 1, b"12345678", &mut out);
    c.send_raw(&out);
    let mut saw_goaway = false;
    for _ in 0..8 {
        let Some(f) = c.frame() else { break };
        if f.head.kind == kind::GOAWAY {
            assert_eq!(
                frame::u32_at(&f.payload, 4),
                Some(frame::Code::Protocol as u32),
                "should be PROTOCOL_ERROR"
            );
            saw_goaway = true;
            break;
        }
    }
    assert!(saw_goaway, "PING on a stream must end the connection");
}

#[test]
fn the_server_announces_its_settings_before_anything_else() {
    let s = Server::start("settings", STATIC);
    let mut c = s.connect();
    let f = c.frame().expect("a frame");
    assert_eq!(f.head.kind, kind::SETTINGS, "the first frame must be SETTINGS");
    assert_eq!(f.head.stream, 0);
    // Push is not implemented, and saying so stops a client reserving for it.
    let mut push_disabled = false;
    for ch in f.payload.chunks_exact(6) {
        let id = u16::from_be_bytes([ch[0], ch[1]]);
        let v = u32::from_be_bytes([ch[2], ch[3], ch[4], ch[5]]);
        if id == setting::ENABLE_PUSH {
            assert_eq!(v, 0);
            push_disabled = true;
        }
    }
    assert!(push_disabled, "ENABLE_PUSH must be advertised as 0");
}

#[test]
fn http_1_1_still_works_on_a_port_that_offers_h2c() {
    // The preface probe reads bytes off the socket to decide. Those bytes are
    // the start of an HTTP/1 request line, so handing them back is what stops
    // this from truncating every HTTP/1 request on the port.
    let s = Server::start("both", STATIC);
    s.write_file("index.html", b"<h1>hello</h1>");
    let mut sock = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {}", &resp[..resp.len().min(80)]);
    assert!(resp.contains("<h1>hello</h1>"));
}

#[test]
fn an_http_1_request_arriving_one_byte_at_a_time_is_not_mistaken_for_a_preface() {
    // The probe compares only the bytes it holds. A naive implementation that
    // waited for the full 24-byte preface would hang here, because an HTTP/1
    // client sends its request and then waits for us.
    let s = Server::start("dribble", STATIC);
    s.write_file("index.html", b"ok");
    let mut sock = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for b in b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" {
        sock.write_all(&[*b]).unwrap();
        sock.flush().unwrap();
    }
    let mut resp = String::new();
    sock.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {}", &resp[..resp.len().min(80)]);
}

#[test]
fn hpack_state_carries_across_requests_on_one_connection() {
    // The point of HPACK: the second request references the first's headers by
    // index. If the decoder's dynamic table were reset per stream, this would
    // fail with a compression error rather than a wrong answer.
    let s = Server::start("hpackstate", "server { listen {PORT} http2; root {ROOT};\n\
        location / { return 200 \"$http_x_thing\"; } }");
    let mut c = s.connect();
    c.request(1, "GET", "/", &[("x-thing", "value-one")], true);
    let f1 = c.collect(&[1]);
    assert_eq!(body_of(&f1, 1), b"value-one");
    c.request(3, "GET", "/", &[("x-thing", "value-two")], true);
    let f3 = c.collect(&[3]);
    assert_eq!(body_of(&f3, 3), b"value-two");
}

#[test]
fn a_reused_stream_id_ends_the_connection() {
    // Stream ids must strictly increase. Reuse would leave the two ends
    // disagreeing about which stream is which.
    let s = Server::start("reuse", STATIC);
    s.write_file("index.html", b"ok");
    let mut c = s.connect();
    c.request(3, "GET", "/", &[], true);
    let _ = c.collect(&[3]);
    c.request(1, "GET", "/", &[], true);
    let mut saw = false;
    for _ in 0..10 {
        let Some(f) = c.frame() else { break };
        if f.head.kind == kind::GOAWAY {
            saw = true;
            break;
        }
    }
    assert!(saw, "a lower stream id after a higher one must be refused");
}

//! End-to-end HTTP/3: a real QUIC handshake, real packets, real frames.
//!
//! The client here is built on quinn and on OxiServe's own framing and QPACK.
//! Reusing our codec to test our codec would be circular if the codec were
//! what was under test — it is not. The unit tests in `src/http3/qpack.rs`
//! check the encoding against RFC 9204's own byte vector, and these tests
//! check the thing that cannot be unit tested: that a QUIC connection is
//! accepted, the control streams are set up in the order RFC 9114 demands, a
//! request reaches the ordinary handler, and the response comes back framed.

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oxiserve::http3::frame::{self, kind, stream_type, Settings};
use oxiserve::http3::qpack;

static NEXT_PORT: AtomicU16 = AtomicU16::new(19400);

/// A port that is free on **both** TCP and UDP.
///
/// The h3 tests need a UDP port, but a server config almost always also opens
/// the TCP one, and a collision on either is a hang rather than an error.
fn free_port() -> u16 {
    loop {
        let p = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        if UdpSocket::bind(("127.0.0.1", p)).is_ok()
            && std::net::TcpListener::bind(("127.0.0.1", p)).is_ok()
        {
            return p;
        }
    }
}

struct Server {
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Server {
    /// Starts a server with a freshly generated certificate for `localhost`.
    fn start(name: &str, body: &str) -> Server {
        let port = free_port();
        let dir = std::env::temp_dir()
            .join(format!("oxiserve-h3-{}-{name}-{port}", std::process::id()));
        let root = dir.join("html");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), b"static-over-h3").unwrap();

        // A self-signed leaf is all a QUIC handshake needs; the test client
        // below does not verify it. Generated per run rather than committed,
        // so nothing in the repository can expire.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(dir.join("cert.pem"), cert.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), cert.key_pair.serialize_pem()).unwrap();

        let conf = format!(
            "worker_processes 1;\nerror_log {d}/error.log info;\n\
             events {{ worker_connections 128; }}\nhttp {{ access_log off;\n{body}\n}}",
            d = dir.display()
        )
        .replace("{PORT}", &port.to_string())
        .replace("{ROOT}", root.to_str().unwrap())
        .replace("{DIR}", dir.to_str().unwrap());
        let cpath = dir.join("oxiserve.conf");
        std::fs::write(&cpath, conf).unwrap();

        let cfg = oxiserve::config::load(&cpath, dir.clone())
            .unwrap_or_else(|e| panic!("config load failed: {e}"));
        std::thread::spawn(move || {
            let _ = oxiserve::server::run(cfg);
        });

        // The UDP socket answers nothing until it exists, so readiness is a
        // successful handshake rather than a successful connect.
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if H3::connect(port).is_ok() {
                return Server { port, dir };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("quic server on port {port} never came up");
    }
}

/// The base config: one server with both a TCP and a QUIC listener on `{PORT}`.
fn conf(extra: &str) -> String {
    format!(
        "server {{\n\
           listen {{PORT}} ssl;\n\
           listen {{PORT}} quic;\n\
           server_name localhost;\n\
           ssl_certificate {{DIR}}/cert.pem;\n\
           ssl_certificate_key {{DIR}}/key.pem;\n\
           root {{ROOT}};\n\
           {extra}\n\
         }}"
    )
}

// ---------------------------------------------------------------------------
// A minimal HTTP/3 client.

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct H3 {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    rt: tokio::runtime::Runtime,
}

impl H3 {
    fn connect(port: u16) -> Result<H3, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;

        let (endpoint, conn) = rt.block_on(async move {
            let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS13,
            ])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
            tls.alpn_protocols = vec![b"h3".to_vec()];

            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| e.to_string())?;
            let mut endpoint =
                quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).map_err(|e| e.to_string())?;
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

            let addr: SocketAddr = ([127, 0, 0, 1], port).into();
            let conn = endpoint
                .connect(addr, "localhost")
                .map_err(|e| e.to_string())?
                .await
                .map_err(|e| e.to_string())?;

            // RFC 9114 section 6.2.1: our control stream, SETTINGS first.
            let mut ctl = conn.open_uni().await.map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            frame::put_varint(stream_type::CONTROL, &mut out);
            let mut payload = Vec::new();
            Settings::default().encode(&mut payload);
            frame::put_frame(kind::SETTINGS, &payload, &mut out);
            ctl.write_all(&out).await.map_err(|e| e.to_string())?;
            // Deliberately leaked: closing a control stream is a connection
            // error, so it has to outlive this function.
            std::mem::forget(ctl);

            Ok::<_, String>((endpoint, conn))
        })?;

        Ok(H3 { conn, _endpoint: endpoint, rt })
    }

    fn request(&self, method: &str, path: &str, body: &[u8]) -> Response {
        self.rt.block_on(one(&self.conn, method, path, body))
    }

    /// Issues every request on its own stream and awaits them together, so
    /// they really are in flight at the same time.
    fn request_all(&self, paths: &[&str]) -> Vec<Response> {
        self.rt.block_on(async {
            let futures: Vec<_> =
                paths.iter().map(|p| one(&self.conn, "GET", p, b"")).collect();
            futures_join(futures).await
        })
    }
}

/// Awaits a set of futures concurrently without pulling in a futures crate.
async fn futures_join<F: std::future::Future<Output = Response>>(fs: Vec<F>) -> Vec<Response> {
    // `tokio::join!` needs a fixed arity, so drive them by polling a boxed set
    // through a tiny scheduler: spawn is unavailable here (the client's
    // runtime is current-thread and the futures borrow `conn`), and the point
    // of the test is that the *streams* overlap, which they do as soon as all
    // the requests are written before any response is read.
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = fs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<Response>> = (0..pinned.len()).map(|_| None).collect();
    let mut left = pinned.len();
    while left > 0 {
        for (i, f) in pinned.iter_mut().enumerate() {
            if out[i].is_some() {
                continue;
            }
            if let Some(r) = poll_once(f.as_mut()).await {
                out[i] = Some(r);
                left -= 1;
            }
        }
        tokio::task::yield_now().await;
    }
    out.into_iter().map(|r| r.unwrap()).collect()
}

/// Polls `f` exactly once, returning `None` if it is not ready.
async fn poll_once<F: std::future::Future>(mut f: std::pin::Pin<&mut F>) -> Option<F::Output> {
    std::future::poll_fn(move |cx| {
        std::task::Poll::Ready(match f.as_mut().poll(cx) {
            std::task::Poll::Ready(v) => Some(v),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

/// One request/response exchange on a fresh bidirectional stream.
async fn one(conn: &quinn::Connection, method: &str, path: &str, body: &[u8]) -> Response {
    {
            let (mut send, mut recv) = conn.open_bi().await.expect("open request stream");

            let mut block = Vec::new();
            qpack::begin_section(&mut block);
            qpack::encode(":method", method, &mut block);
            qpack::encode(":scheme", "https", &mut block);
            qpack::encode(":authority", "localhost", &mut block);
            qpack::encode(":path", path, &mut block);
            if !body.is_empty() {
                qpack::encode("content-length", &body.len().to_string(), &mut block);
            }

            let mut out = Vec::new();
            frame::put_frame(kind::HEADERS, &block, &mut out);
            if !body.is_empty() {
                frame::put_frame(kind::DATA, body, &mut out);
            }
            send.write_all(&out).await.expect("write request");
            send.finish().expect("finish request");

            let raw = recv.read_to_end(8 * 1024 * 1024).await.expect("read response");
            parse_response(&raw)
    }
}

/// Pulls a status, headers and body out of a raw HTTP/3 response stream.
fn parse_response(mut raw: &[u8]) -> Response {
    let mut status = 0u16;
    let mut headers = Vec::new();
    let mut body = Vec::new();

    while !raw.is_empty() {
        let head = frame::parse_head(raw).expect("framing").expect("complete frame");
        let start = head.head_len;
        let end = start + head.len as usize;
        let payload = &raw[start..end];
        match head.kind {
            kind::HEADERS => {
                for h in qpack::decode(payload, 1 << 20).expect("qpack") {
                    if h.name == ":status" {
                        status = h.value.parse().unwrap_or(0);
                    } else {
                        headers.push((h.name, h.value));
                    }
                }
            }
            kind::DATA => body.extend_from_slice(payload),
            _ => {}
        }
        raw = &raw[end..];
    }
    Response { status, headers, body }
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------

#[test]
fn a_return_directive_is_served_over_http3() {
    let s = Server::start("return", &conf("location /hi { return 200 \"hello h3\"; }"));
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/hi", b"");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"hello h3");
}

#[test]
fn a_static_file_is_served_over_http3() {
    // Proves the whole file path runs: `root`, `index`, MIME typing and the
    // body writer, none of which know which transport asked.
    let s = Server::start("static", &conf("location / { index index.html; }"));
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/", b"");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"static-over-h3");
    assert_eq!(r.header("content-type"), Some("text/html"));
    assert_eq!(r.header("content-length"), Some("14"));
}

#[test]
fn the_server_is_selected_by_authority_not_sni() {
    // `:authority` becomes a Host header before routing, so `server_name`
    // matching works exactly as it does over HTTP/1.
    let s = Server::start(
        "host",
        &conf("location /who { return 200 \"host=$host uri=$uri scheme=$scheme\"; }"),
    );
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/who", b"");
    assert_eq!(
        String::from_utf8_lossy(&r.body),
        "host=localhost uri=/who scheme=https",
        "variables must resolve the same over h3"
    );
}

#[test]
fn a_request_body_arrives_intact() {
    let s = Server::start("post", &conf("location /echo { return 200 \"len=$content_length\"; }"));
    let c = H3::connect(s.port).unwrap();
    let r = c.request("POST", "/echo", &b"x".repeat(5000));
    assert_eq!(r.status, 200);
    assert_eq!(String::from_utf8_lossy(&r.body), "len=5000");
}

#[test]
fn a_body_larger_than_one_data_frame_round_trips() {
    // 512 KB exercises the chunked write path and QUIC's own flow control,
    // which is the part HTTP/2 needs a window manager for and this does not.
    let s = Server::start("big", &conf("location / { index index.html; }"));
    let big = vec![b'z'; 512 * 1024];
    std::fs::write(s.dir.join("html/big.bin"), &big).unwrap();
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/big.bin", b"");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), big.len(), "truncated body");
    assert_eq!(r.body, big);
}

#[test]
fn concurrent_streams_are_independent() {
    // Genuinely overlapping: all four requests are written before any response
    // is read, so a mix-up between streams would show as a swapped body rather
    // than being hidden by doing them one at a time.
    let s = Server::start("concurrent", &conf("location / { return 200 \"uri=$uri\"; }"));
    let c = H3::connect(s.port).unwrap();
    let paths = ["/p0", "/p1", "/p2", "/p3"];
    let out = c.request_all(&paths);
    assert_eq!(out.len(), 4);
    for (r, path) in out.iter().zip(paths) {
        assert_eq!(r.status, 200);
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            format!("uri={path}"),
            "stream for {path} got another stream's answer"
        );
    }
}

#[test]
fn an_error_page_is_produced_over_http3() {
    let s = Server::start("404", &conf("location / { index index.html; }"));
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/nope.html", b"");
    assert_eq!(r.status, 404);
    assert!(!r.body.is_empty(), "the error page body must come through");
}

#[test]
fn limit_req_applies_over_http3_too() {
    // The whole claim of the seam: a feature written for HTTP/1 works here
    // because it was never told which transport it was on.
    let s = Server::start(
        "limit",
        &format!(
            "limit_req_zone $binary_remote_addr zone=h3z:1m rate=1r/s;\n{}",
            conf("location / { limit_req zone=h3z; return 200 \"ok\"; }")
        ),
    );
    let c = H3::connect(s.port).unwrap();
    assert_eq!(c.request("GET", "/", b"").status, 200);
    assert_eq!(c.request("GET", "/", b"").status, 503, "the rate limit must apply over h3");
}

#[test]
fn alt_svc_advertises_h3_on_the_tcp_side() {
    // Without this header a browser never discovers the QUIC listener, so it
    // is the difference between h3 being configured and h3 being used.
    let s = Server::start("altsvc", &conf("location / { return 200 \"ok\"; }"));
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/", b"");
    assert_eq!(
        r.header("alt-svc"),
        Some(format!("h3=\":{}\"; ma=86400", s.port).as_str())
    );
}

#[test]
fn a_configured_alt_svc_is_not_overridden() {
    // The escape hatch: an operator who sets their own must get theirs.
    let s = Server::start(
        "altsvcown",
        &conf("add_header Alt-Svc 'h3=\":8443\"; ma=60' always;\nlocation / { return 200 \"ok\"; }"),
    );
    let c = H3::connect(s.port).unwrap();
    let r = c.request("GET", "/", b"");
    assert_eq!(r.header("alt-svc"), Some("h3=\":8443\"; ma=60"));
}

#[test]
fn a_server_without_quic_advertises_nothing() {
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("oxiserve-h3-noquic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cpath = dir.join("oxiserve.conf");
    std::fs::write(
        &cpath,
        format!(
            "worker_processes 1;\nerror_log {d}/error.log crit;\n\
             events {{ worker_connections 64; }}\n\
             http {{ access_log off; server {{ listen {port}; location / {{ return 200 \"ok\"; }} }} }}",
            d = dir.display()
        ),
    )
    .unwrap();
    let cfg = oxiserve::config::load(&cpath, dir.clone()).unwrap();
    std::thread::spawn(move || {
        let _ = oxiserve::server::run(cfg);
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    use std::io::{Read, Write};
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    assert!(
        !resp.to_ascii_lowercase().contains("alt-svc"),
        "a server with no quic listener must not advertise one: {resp}"
    );
}

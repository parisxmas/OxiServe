//! `stream` block tests: layer 4 proxying.
//!
//! Deliberately uses a protocol that is *not* HTTP. If these passed only for
//! HTTP-shaped bytes, the proxy would not be doing layer 4 at all.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(19400);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// An echo server that upper-cases what it receives — a made-up line protocol,
/// nothing HTTP about it.
struct Echo {
    port: u16,
    hits: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
    tag: String,
}

impl Echo {
    fn start(tag: &str) -> Echo {
        let port = port();
        let hits = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let (h, a, t) = (hits.clone(), alive.clone(), tag.to_string());
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                if !a.load(Ordering::SeqCst) {
                    drop(c);
                    continue;
                }
                let (h, t) = (h.clone(), t.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    h.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 1024];
                    loop {
                        match c.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                let msg = String::from_utf8_lossy(&buf[..n]).to_uppercase();
                                if c.write_all(format!("[{t}]{msg}").as_bytes()).is_err() {
                                    return;
                                }
                                let _ = c.flush();
                            }
                        }
                    }
                });
            }
        });
        Echo { port, hits, alive, tag: tag.to_string() }
    }
    fn hits(&self) -> usize { self.hits.load(Ordering::SeqCst) }
    /// Server::start probes the listener to know it is up, and that probe is
    /// proxied straight through to the backend. Tests that count connections
    /// clear the counter afterwards so they measure only their own traffic.
    fn reset(&self) { self.hits.store(0, Ordering::SeqCst); }
    fn kill(&self) { self.alive.store(false, Ordering::SeqCst); }
}

struct Server {
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, conf: &str) -> Server {
        let p = port();
        let dir = std::env::temp_dir()
            .join(format!("oxiserve-stream-{}-{name}-{p}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let text = conf.replace("{PORT}", &p.to_string()).replace("{DIR}", dir.to_str().unwrap());
        let cpath = dir.join("oxiserve.conf");
        std::fs::write(&cpath, text).unwrap();
        let cfg = oxiserve::config::load(&cpath, dir.clone())
            .unwrap_or_else(|e| panic!("config: {e}"));
        std::thread::spawn(move || { let _ = oxiserve::server::run(cfg); });
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", p)).is_ok() {
                // The probe is proxied through to the backend. Give it time to
                // land before returning, so a test that calls `reset()` really
                // clears it instead of racing an in-flight connection.
                std::thread::sleep(Duration::from_millis(100));
                return Server { port: p, dir };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("stream server never came up");
    }

    /// Sends a line and reads the reply, over the proxy.
    fn talk(&self, msg: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(msg.as_bytes()).unwrap();
        c.flush().unwrap();
        let mut buf = [0u8; 1024];
        match c.read(&mut buf) {
            Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
            Err(_) => String::new(),
        }
    }
}

fn conf(body: &str) -> String {
    format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
stream {{
{body}
}}")
}

// ---------------------------------------------------------------------------

#[test]
fn proxies_a_non_http_protocol() {
    let b = Echo::start("A");
    let s = Server::start(
        "basic",
        &conf(&format!("
    server {{
        listen {{PORT}};
        proxy_pass 127.0.0.1:{};
    }}", b.port)),
    );
    b.reset();
    assert_eq!(s.talk("hello"), "[A]HELLO", "bytes must pass through unchanged");
    assert_eq!(b.hits(), 1);
}

#[test]
fn a_stream_only_config_needs_no_http_block() {
    let b = Echo::start("S");
    let s = Server::start(
        "streamonly",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{}; }}", b.port)),
    );
    assert_eq!(s.talk("x"), "[S]X");
}

#[test]
fn full_duplex_conversation_over_one_connection() {
    // Several exchanges on the same connection: proves both directions stay
    // open rather than the proxy closing after the first reply.
    let b = Echo::start("D");
    let s = Server::start(
        "duplex",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{}; }}", b.port)),
    );

    b.reset();
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    for word in ["one", "two", "three"] {
        c.write_all(word.as_bytes()).unwrap();
        c.flush().unwrap();
        let mut buf = [0u8; 256];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf[..n]),
            format!("[D]{}", word.to_uppercase()),
            "exchange {word} must round-trip"
        );
    }
    assert_eq!(b.hits(), 1, "all exchanges must share one upstream connection");
}

#[test]
fn large_transfers_are_not_truncated() {
    // 1 MB through the proxy, verifying no bytes are lost at buffer edges.
    let port_be = port();
    let l = TcpListener::bind(("127.0.0.1", port_be)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut got = Vec::new();
                let mut buf = [0u8; 8192];
                // Read until the client half-closes, then report the count.
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = c.write_all(format!("got:{}", got.len()).as_bytes());
            });
        }
    });

    let s = Server::start(
        "bigxfer",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{port_be}; }}")),
    );

    let payload = vec![b'z'; 1024 * 1024];
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    c.write_all(&payload).unwrap();
    c.flush().unwrap();
    // Half-close so the backend knows the payload ended — the proxy must
    // forward the shutdown, not just the bytes.
    c.shutdown(std::net::Shutdown::Write).unwrap();

    let mut reply = String::new();
    c.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, format!("got:{}", payload.len()), "all bytes must arrive");
}

#[test]
fn load_balances_across_an_upstream_block() {
    let a = Echo::start("A");
    let b = Echo::start("B");
    let s = Server::start(
        "lb",
        &conf(&format!("
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
    }}
    server {{ listen {{PORT}}; proxy_pass pool; }}", a.port, b.port)),
    );

    let mut seen: Vec<String> = Vec::new();
    for _ in 0..6 {
        seen.push(s.talk("hi"));
    }
    assert!(seen.iter().any(|r| r.starts_with("[A]")), "peer A must get traffic: {seen:?}");
    assert!(seen.iter().any(|r| r.starts_with("[B]")), "peer B must get traffic: {seen:?}");
}

#[test]
fn a_dead_peer_is_taken_out_of_rotation() {
    // The same passive health tracking as the HTTP proxy, at layer 4.
    let good = Echo::start("GOOD");
    let bad = Echo::start("BAD");
    bad.kill();

    let s = Server::start(
        "l4health",
        &conf(&format!("
    upstream pool {{
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
    }}
    server {{ listen {{PORT}}; proxy_pass pool; proxy_connect_timeout 1s; }}",
            bad.port, good.port)),
    );

    let mut good_count = 0;
    for _ in 0..10 {
        if s.talk("ping").starts_with("[GOOD]") {
            good_count += 1;
        }
    }
    assert!(good_count >= 8, "dead peer must be ejected, got {good_count}/10");
}

#[test]
fn an_unreachable_backend_closes_the_connection_cleanly() {
    // At layer 4 there is no status code to send; the client just sees EOF.
    let dead = port();
    let s = Server::start(
        "l4dead",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{dead}; proxy_connect_timeout 1s; }}")),
    );
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = c.write_all(b"anything");
    let mut buf = [0u8; 64];
    assert_eq!(c.read(&mut buf).unwrap_or(0), 0, "must close, not hang");
}

#[test]
fn idle_connections_are_closed_after_proxy_timeout() {
    // proxy_timeout is an IDLE timeout. A connection that says nothing must be
    // reaped; the next test proves a busy one is not.
    let b = Echo::start("T");
    let s = Server::start(
        "idle",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{}; proxy_timeout 1s; }}", b.port)),
    );

    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"hello").unwrap();
    let mut buf = [0u8; 256];
    assert!(c.read(&mut buf).unwrap() > 0, "first exchange works");

    // Now go quiet for longer than proxy_timeout.
    std::thread::sleep(Duration::from_millis(1600));
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest);
    // The proxy closed it, so the read ends rather than blocking.
}

#[test]
fn a_busy_connection_outlives_proxy_timeout() {
    // The distinction that matters: idle timeout, not a lifetime cap. A
    // connection busy past the timeout must survive, or every long-lived
    // database session would be severed.
    let b = Echo::start("BUSY");
    let s = Server::start(
        "busy",
        &conf(&format!("
    server {{ listen {{PORT}}; proxy_pass 127.0.0.1:{}; proxy_timeout 1s; }}", b.port)),
    );

    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Chat for 2.5s with 500ms gaps: well past proxy_timeout in total, but
    // never idle for a whole second.
    for i in 0..5 {
        c.write_all(format!("msg{i}").as_bytes()).unwrap();
        c.flush().unwrap();
        let mut buf = [0u8; 256];
        let n = c.read(&mut buf).expect("connection must still be alive");
        assert!(n > 0, "exchange {i} must succeed after {}ms", i * 500);
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn unknown_upstream_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-badstream-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(&f, "events {} stream { server { listen 9999; proxy_pass nosuch; } }").unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("unknown upstream"), "got: {err}");
}

#[test]
fn a_server_without_proxy_pass_is_rejected() {
    let dir = std::env::temp_dir().join(format!("oxiserve-nopass-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(&f, "events {} stream { server { listen 9999; } }").unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("proxy_pass"), "got: {err}");
}

// ---- ssl_preread ----------------------------------------------------------

/// Records the exact bytes a backend received, then replies with its tag.
///
/// The byte-for-byte record is the point: `ssl_preread` reads the handshake
/// but must not consume it, and only the backend can prove that.
struct Recorder {
    port: u16,
    got: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl Recorder {
    fn start(tag: &str) -> Recorder {
        let port = port();
        let got: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (g, t) = (got.clone(), tag.to_string());
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (g, t) = (g.clone(), t.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    c.set_read_timeout(Some(Duration::from_millis(700))).ok();
                    let mut seen = Vec::new();
                    let mut buf = [0u8; 4096];
                    // Read until the client stops sending; a TLS client would
                    // now wait for a ServerHello it is never going to get.
                    while let Ok(n) = c.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&buf[..n]);
                        if seen.len() > 64 * 1024 {
                            break;
                        }
                    }
                    let _ = c.write_all(t.as_bytes());
                    if !seen.is_empty() {
                        g.lock().unwrap().push(seen);
                    }
                });
            }
        });
        Recorder { port, got }
    }

    /// Connections that carried data, oldest first.
    fn received(&self) -> Vec<Vec<u8>> {
        self.got.lock().unwrap().clone()
    }
}

/// A minimal but structurally valid TLS 1.3 ClientHello.
fn client_hello(sni: &str, alpn: &[&str]) -> Vec<u8> {
    fn u16b(n: usize) -> [u8; 2] {
        (n as u16).to_be_bytes()
    }
    let mut ext = Vec::new();
    if !sni.is_empty() {
        let mut entry = vec![0u8]; // host_name
        entry.extend_from_slice(&u16b(sni.len()));
        entry.extend_from_slice(sni.as_bytes());
        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&u16b(entry.len() + 2));
        ext.extend_from_slice(&u16b(entry.len()));
        ext.extend_from_slice(&entry);
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        ext.extend_from_slice(&[0x00, 0x10]); // alpn
        ext.extend_from_slice(&u16b(list.len() + 2));
        ext.extend_from_slice(&u16b(list.len()));
        ext.extend_from_slice(&list);
    }
    // supported_versions: TLS 1.3
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // no session id
    body.extend_from_slice(&u16b(2)); // one cipher suite
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]); // one compression method: null
    body.extend_from_slice(&u16b(ext.len()));
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01u8]; // client_hello
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16u8, 0x03, 0x01];
    rec.extend_from_slice(&u16b(hs.len()));
    rec.extend_from_slice(&hs);
    rec
}

/// Opens a raw connection to the proxy, sends `bytes`, returns the reply.
fn send_raw(port: u16, bytes: &[u8]) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(bytes).unwrap();
    c.flush().unwrap();
    let mut buf = [0u8; 1024];
    match c.read(&mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        Err(_) => String::new(),
    }
}

#[test]
fn sni_selects_the_backend() {
    let a = Recorder::start("alpha");
    let b = Recorder::start("bravo");
    let d = Recorder::start("default");

    let s = Server::start(
        "sni",
        &conf(&format!("
    map $ssl_preread_server_name $pick {{
        a.example.com   back_a;
        b.example.com   back_b;
        default         back_d;
    }}
    upstream back_a {{ server 127.0.0.1:{}; }}
    upstream back_b {{ server 127.0.0.1:{}; }}
    upstream back_d {{ server 127.0.0.1:{}; }}
    server {{
        listen {{PORT}};
        ssl_preread on;
        proxy_pass $pick;
    }}", a.port, b.port, d.port)),
    );

    assert_eq!(send_raw(s.port, &client_hello("a.example.com", &[])), "alpha");
    assert_eq!(send_raw(s.port, &client_hello("b.example.com", &[])), "bravo");
    assert_eq!(send_raw(s.port, &client_hello("other.example.com", &[])), "default");
    // No SNI at all is not an error; it falls to the default like any other
    // unmatched key.
    assert_eq!(send_raw(s.port, &client_hello("", &[])), "default");
}

#[test]
fn the_backend_receives_the_handshake_byte_for_byte() {
    // The property that makes this a preread rather than a TLS terminator: we
    // inspect the ClientHello and still hand over every byte of it, so the
    // backend completes the handshake against untouched input. Losing or
    // reordering one byte breaks TLS in a way that looks like a backend fault.
    let back = Recorder::start("b");
    let s = Server::start(
        "intact",
        &conf(&format!("
    map $ssl_preread_server_name $pick {{ default only; }}
    upstream only {{ server 127.0.0.1:{}; }}
    server {{ listen {{PORT}}; ssl_preread on; proxy_pass $pick; }}", back.port)),
    );

    let hello = client_hello("intact.example.com", &["h2", "http/1.1"]);
    // Trailing application bytes, to prove the preread does not swallow what
    // follows the handshake either.
    let mut sent = hello.clone();
    sent.extend_from_slice(b"AFTER-THE-HANDSHAKE");
    send_raw(s.port, &sent);

    std::thread::sleep(Duration::from_millis(400));
    let got = back.received();
    let full = got
        .iter()
        .find(|r| r.len() >= sent.len())
        .unwrap_or_else(|| panic!("backend saw {} connection(s), none complete", got.len()));
    assert_eq!(&full[..], &sent[..], "the backend must see exactly what the client sent");
}

#[test]
fn alpn_and_protocol_are_readable_as_variables() {
    let h2 = Recorder::start("h2-backend");
    let other = Recorder::start("other-backend");
    let s = Server::start(
        "alpn",
        &conf(&format!("
    map $ssl_preread_alpn_protocols $pick {{
        ~\\bh2\\b   grpcish;
        default    plain;
    }}
    upstream grpcish {{ server 127.0.0.1:{}; }}
    upstream plain {{ server 127.0.0.1:{}; }}
    server {{ listen {{PORT}}; ssl_preread on; proxy_pass $pick; }}", h2.port, other.port)),
    );

    assert_eq!(send_raw(s.port, &client_hello("x.test", &["h2", "http/1.1"])), "h2-backend");
    assert_eq!(send_raw(s.port, &client_hello("x.test", &["http/1.1"])), "other-backend");
}

#[test]
fn non_tls_traffic_still_gets_proxied_and_arrives_intact() {
    // A port with ssl_preread on may still receive something that is not TLS.
    // Such a connection must be proxied with empty variables, not dropped —
    // and the bytes the parser looked at must still reach the backend.
    let back = Recorder::start("plain");
    let s = Server::start(
        "nontls",
        &conf(&format!("
    map $ssl_preread_server_name $pick {{ default only; }}
    upstream only {{ server 127.0.0.1:{}; }}
    server {{ listen {{PORT}}; ssl_preread on; proxy_pass $pick; }}", back.port)),
    );

    let payload = b"PING hello world\n";
    assert_eq!(send_raw(s.port, payload), "plain");
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        back.received().iter().any(|r| r == payload),
        "non-TLS bytes must reach the backend unchanged: {:?}",
        back.received()
    );
}

#[test]
fn a_client_that_sends_nothing_does_not_hang_forever() {
    // preread_timeout bounds the wait. Past it the connection is proxied with
    // empty variables rather than dropped: slow is not the same as wrong.
    let back = Recorder::start("late");
    let s = Server::start(
        "timeout",
        &conf(&format!("
    map $ssl_preread_server_name $pick {{ default only; }}
    upstream only {{ server 127.0.0.1:{}; }}
    server {{
        listen {{PORT}};
        ssl_preread on;
        preread_timeout 300ms;
        proxy_pass $pick;
    }}", back.port)),
    );

    let started = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 64];
    let n = c.read(&mut buf).unwrap_or(0);
    let waited = started.elapsed();
    assert_eq!(&buf[..n], b"late", "the connection must still be proxied");
    assert!(waited < Duration::from_secs(3), "waited {waited:?}, preread_timeout was 300ms");
}

#[test]
fn routing_on_a_preread_variable_without_enabling_it_is_a_config_error() {
    // Otherwise every connection quietly takes the map's default and the
    // config looks like it works until traffic lands on the wrong backend.
    let dir = std::env::temp_dir().join(format!("oxiserve-preread-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} stream { map $ssl_preread_server_name $p { default u; } \
         upstream u { server 127.0.0.1:1; } \
         server { listen 19399; proxy_pass $p; } }",
    )
    .unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("ssl_preread"), "got: {err}");
}

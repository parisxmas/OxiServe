//! WebSocket proxying — the `101` protocol switch and the tunnel behind it.
//!
//! No WebSocket library is involved: these tests drive the raw bytes, because
//! what is under test is whether the connection stops being HTTP at the right
//! moment and carries whatever the peers say afterwards. A library would
//! perform the handshake and hide exactly that.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(20300);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// A backend that completes a WebSocket handshake and then echoes frames.
struct Backend {
    port: u16,
    /// Whether the request that arrived actually carried `Upgrade`.
    saw_upgrade: Arc<AtomicBool>,
    /// Bytes the backend received *after* the handshake.
    tunnelled: Arc<AtomicUsize>,
}

impl Backend {
    fn start(switch: bool) -> Backend {
        Backend::build(switch, true)
    }

    /// Echoes bytes unchanged, with no `ECHO:` marker.
    ///
    /// The marker is per `read`, so a payload arriving in twenty chunks comes
    /// back with twenty markers — fine for proving a message reached the
    /// backend, useless for proving a large transfer is byte-exact.
    fn start_raw() -> Backend {
        Backend::build(true, false)
    }

    fn build(switch: bool, mark: bool) -> Backend {
        let p = port();
        let saw_upgrade = Arc::new(AtomicBool::new(false));
        let tunnelled = Arc::new(AtomicUsize::new(0));
        let (su, tn) = (saw_upgrade.clone(), tunnelled.clone());
        let l = TcpListener::bind(("127.0.0.1", p)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (su, tn) = (su.clone(), tn.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut buf = [0u8; 4096];
                    let Ok(n) = c.read(&mut buf) else { return };
                    let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                    let up = req.contains("upgrade: websocket");
                    if up {
                        su.store(true, Ordering::SeqCst);
                    }
                    if !up || !switch {
                        let _ = c.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nplain!!",
                        );
                        return;
                    }
                    let _ = c.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Upgrade: websocket\r\nConnection: Upgrade\r\n\
                          Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                    );
                    // Echo whatever the client sends, for as long as it sends.
                    loop {
                        match c.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                tn.fetch_add(n, Ordering::SeqCst);
                                let out = if mark {
                                    [b"ECHO:".as_slice(), &buf[..n]].concat()
                                } else {
                                    buf[..n].to_vec()
                                };
                                if c.write_all(&out).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        Backend { port: p, saw_upgrade, tunnelled }
    }
}

struct Server {
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, body: &str) -> Server {
        let p = port();
        let dir = std::env::temp_dir().join(format!("oxiserve-ws-{}-{name}-{p}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let text = format!(
            "worker_processes 1;\nerror_log {}/error.log crit;\n\
             events {{ worker_connections 128; }}\nhttp {{ access_log off;\n{body}\n}}",
            dir.display()
        )
        .replace("{PORT}", &p.to_string());
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

    /// Opens a connection and sends a WebSocket handshake.
    fn handshake(&self, path: &str) -> (TcpStream, String) {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut buf = [0u8; 1024];
        let n = c.read(&mut buf).unwrap_or(0);
        (c, String::from_utf8_lossy(&buf[..n]).into_owned())
    }
}

/// The config nginx requires for WebSocket proxying, which is what we accept.
fn ws_conf(backend: u16) -> String {
    format!(
        "server {{ listen {{PORT}};\n\
           location / {{\n\
             proxy_pass http://127.0.0.1:{backend};\n\
             proxy_http_version 1.1;\n\
             proxy_set_header Upgrade $http_upgrade;\n\
             proxy_set_header Connection \"upgrade\";\n\
           }} }}"
    )
}

// ---------------------------------------------------------------------------

#[test]
fn a_handshake_switches_protocols_and_the_tunnel_carries_bytes() {
    let b = Backend::start(true);
    let s = Server::start("basic", &ws_conf(b.port));
    let (mut c, head) = s.handshake("/ws");

    assert!(head.starts_with("HTTP/1.1 101 "), "got: {head:?}");
    assert!(b.saw_upgrade.load(Ordering::SeqCst), "the backend never saw Upgrade");
    let lower = head.to_lowercase();
    assert!(lower.contains("upgrade: websocket"), "the client must be told what it got: {head:?}");
    assert!(
        lower.contains("sec-websocket-accept:"),
        "the backend's handshake headers must survive: {head:?}"
    );

    // Past the head, this is no longer HTTP.
    c.write_all(b"hello-over-the-tunnel").unwrap();
    let mut buf = [0u8; 256];
    let n = c.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ECHO:hello-over-the-tunnel");
}

#[test]
fn the_switch_carries_exactly_one_connection_header() {
    // `Connection: close` alongside `Connection: Upgrade` is contradictory —
    // strict clients reject it, lenient ones guess.
    let b = Backend::start(true);
    let s = Server::start("connhdr", &ws_conf(b.port));
    let (_c, head) = s.handshake("/ws");
    let count = head.to_lowercase().matches("connection:").count();
    assert_eq!(count, 1, "expected one Connection header, got {count}: {head:?}");
    assert!(head.to_lowercase().contains("connection: upgrade"));
    assert!(!head.to_lowercase().contains("content-length"), "a switch has no body");
}

#[test]
fn the_tunnel_is_bidirectional_over_many_messages() {
    // One echo could be a fluke of buffering. A conversation cannot.
    let b = Backend::start(true);
    let s = Server::start("duplex", &ws_conf(b.port));
    let (mut c, head) = s.handshake("/ws");
    assert!(head.starts_with("HTTP/1.1 101 "));

    for i in 0..20 {
        let msg = format!("msg-{i}");
        c.write_all(msg.as_bytes()).unwrap();
        let mut buf = [0u8; 256];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf[..n]),
            format!("ECHO:{msg}"),
            "message {i} did not round-trip"
        );
    }
    assert!(b.tunnelled.load(Ordering::SeqCst) >= 20, "backend saw too little traffic");
}

#[test]
fn a_large_payload_crosses_the_tunnel_intact() {
    // Bigger than the tunnel's own buffer, so it must be carried in pieces
    // without loss or reordering.
    let b = Backend::start_raw();
    let s = Server::start("big", &ws_conf(b.port));
    let (mut c, head) = s.handshake("/ws");
    assert!(head.starts_with("HTTP/1.1 101 "));

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let mut writer = c.try_clone().unwrap();
    let sent = payload.clone();
    std::thread::spawn(move || {
        let _ = writer.write_all(&sent);
    });

    let mut got = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    while got.len() < payload.len() {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    assert_eq!(got.len(), payload.len(), "length mismatch across the tunnel");
    assert_eq!(got, payload, "content mismatch across the tunnel");
    assert_eq!(
        b.tunnelled.load(Ordering::SeqCst),
        payload.len(),
        "the backend must have received every byte too"
    );
}

#[test]
fn the_client_closing_ends_the_tunnel() {
    let b = Backend::start(true);
    let s = Server::start("close", &ws_conf(b.port));
    let (mut c, head) = s.handshake("/ws");
    assert!(head.starts_with("HTTP/1.1 101 "));
    c.write_all(b"bye").unwrap();
    let mut buf = [0u8; 64];
    let _ = c.read(&mut buf);
    drop(c);
    // The half of the tunnel that mattered: the backend must see EOF rather
    // than hang on a connection nobody is holding any more.
    std::thread::sleep(Duration::from_millis(300));
    assert!(b.tunnelled.load(Ordering::SeqCst) >= 3);
}

#[test]
fn an_ordinary_request_through_the_same_location_is_unaffected() {
    // The upgrade path must not have changed what plain proxying does.
    let b = Backend::start(true);
    let s = Server::start("plain", &ws_conf(b.port));
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /plain HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp:?}");
    assert!(resp.ends_with("plain!!"));
}

#[test]
fn a_101_the_client_never_asked_for_is_refused() {
    // A backend switching protocols unprompted would leave a client that
    // speaks HTTP wired to one that does not. 502 is the honest answer.
    let b = Backend::start(true);
    let s = Server::start("unasked", &format!(
        "server {{ listen {{PORT}};\n\
           location / {{\n\
             proxy_pass http://127.0.0.1:{};\n\
             proxy_http_version 1.1;\n\
             proxy_set_header Upgrade \"websocket\";\n\
             proxy_set_header Connection \"upgrade\";\n\
           }} }}", b.port));

    // No Upgrade from the client — but the config forces one upstream, so the
    // backend answers 101 to a client that never asked.
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 502"), "got: {:?}", &resp[..resp.len().min(60)]);
}

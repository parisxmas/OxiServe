//! `proxy_next_upstream` — retrying a failed peer against another one.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(20800);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// A backend that answers with a fixed raw response and counts its hits.
struct Peer {
    port: u16,
    hits: Arc<AtomicUsize>,
}

impl Peer {
    fn start(raw: &'static str) -> Peer {
        Peer::with(move |_| Some(raw.to_string()))
    }

    /// `reply` returning `None` closes the connection without answering,
    /// which is how a backend that accepted and then died looks on the wire.
    fn with(reply: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Peer {
        let p = port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let reply = Arc::new(reply);
        let l = TcpListener::bind(("127.0.0.1", p)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (h, reply) = (h.clone(), reply.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut buf = [0u8; 8192];
                    let Ok(n) = c.read(&mut buf) else { return };
                    h.fetch_add(1, Ordering::SeqCst);
                    if let Some(r) = reply(&String::from_utf8_lossy(&buf[..n])) {
                        let _ = c.write_all(r.as_bytes());
                    }
                });
            }
        });
        Peer { port: p, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// A port nothing listens on: connections are refused outright.
fn dead_port() -> u16 {
    port()
}

struct Server {
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, body: &str) -> Server {
        let p = port();
        let dir =
            std::env::temp_dir().join(format!("oxiserve-nu-{}-{name}-{p}", std::process::id()));
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

    fn request(&self, raw: &str) -> (u16, String) {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        c.write_all(raw.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        let status = resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn get(&self, path: &str) -> (u16, String) {
        self.request(&format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    }
}

fn ok(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

fn conf(servers: &str, extra: &str) -> String {
    format!(
        "upstream pool {{\n{servers}\n}}\n\
         server {{ listen {{PORT}};\n\
           location / {{ proxy_pass http://pool; {extra} }}\n\
         }}"
    )
}

// ---------------------------------------------------------------------------

/// The measurement that motivated this: with a dead peer in the pool, the
/// first request to land on it used to be a 502 even though a healthy peer was
/// sitting right there.
#[test]
fn a_refused_connection_is_retried_on_the_next_peer() {
    let live = Peer::start(&*Box::leak(ok("alive").into_boxed_str()));
    let dead = dead_port();
    let s = Server::start(
        "refused",
        &conf(
            &format!("server 127.0.0.1:{};\nserver 127.0.0.1:{dead};", live.port),
            "",
        ),
    );
    for i in 0..20 {
        let (status, body) = s.get("/");
        assert_eq!(status, 200, "request {i} fell through to an error");
        assert_eq!(body, "alive");
    }
}

/// A backend that accepts and then closes without answering is a common way
/// for one to die, and it is an `error` just like a refused connection.
#[test]
fn a_peer_that_accepts_then_closes_is_retried() {
    let live = Peer::start(&*Box::leak(ok("second").into_boxed_str()));
    let broken = Peer::with(|_| None); // accepts, says nothing, closes
    let s = Server::start(
        "silent",
        &conf(
            &format!("server 127.0.0.1:{};\nserver 127.0.0.1:{};", broken.port, live.port),
            "",
        ),
    );
    for _ in 0..10 {
        assert_eq!(s.get("/"), (200, "second".to_string()));
    }
    assert!(broken.hits() > 0, "the broken peer should have been tried at least once");
}

/// `error timeout` is the default, and a peer that merely answered `500` has
/// done its job as far as the proxy is concerned. Retrying it would double the
/// load on a backend already in trouble.
#[test]
fn a_500_is_not_retried_by_default() {
    let bad = Peer::start("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nerr");
    let good = Peer::start(&*Box::leak(ok("good").into_boxed_str()));
    let s = Server::start(
        "no500",
        &conf(
            &format!("server 127.0.0.1:{};\nserver 127.0.0.1:{};", bad.port, good.port),
            "",
        ),
    );
    let mut saw_500 = false;
    for _ in 0..8 {
        if s.get("/").0 == 500 {
            saw_500 = true;
        }
    }
    assert!(saw_500, "a 500 must reach the client unless http_500 is configured");
}

#[test]
fn http_500_makes_it_retryable() {
    let bad = Peer::start("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nerr");
    let good = Peer::start(&*Box::leak(ok("good").into_boxed_str()));
    let s = Server::start(
        "yes500",
        &conf(
            &format!("server 127.0.0.1:{};\nserver 127.0.0.1:{};", bad.port, good.port),
            "proxy_next_upstream error timeout http_500;",
        ),
    );
    for i in 0..8 {
        let (status, body) = s.get("/");
        assert_eq!(status, 200, "request {i}: a retryable 500 should have moved on");
        assert_eq!(body, "good");
    }
    assert!(bad.hits() > 0, "the failing peer should still have been tried");
}

/// A retried `POST` can charge a card twice. nginx does not retry
/// non-idempotent methods unless told to, and neither do we.
#[test]
fn a_post_is_not_retried_unless_non_idempotent_is_asked_for() {
    let dead = dead_port();
    let live = Peer::start(&*Box::leak(ok("alive").into_boxed_str()));
    let servers = format!("server 127.0.0.1:{dead};\nserver 127.0.0.1:{};", live.port);

    let strict = Server::start("post-strict", &conf(&servers, ""));
    let mut saw_error = false;
    for _ in 0..8 {
        let (status, _) = strict.request(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        if status == 502 {
            saw_error = true;
        }
    }
    assert!(saw_error, "a POST must not be silently retried");

    let loose = Server::start(
        "post-loose",
        &conf(&servers, "proxy_next_upstream error timeout non_idempotent;"),
    );
    for i in 0..8 {
        let (status, body) = loose.request(
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        );
        assert_eq!(status, 200, "request {i}: non_idempotent should allow the retry");
        assert_eq!(body, "alive");
    }
}

/// With every peer dead there is nothing to retry onto, and the client gets
/// the error rather than a hang.
#[test]
fn all_peers_dead_answers_with_the_error() {
    let (a, b) = (dead_port(), dead_port());
    let s = Server::start(
        "alldead",
        &conf(&format!("server 127.0.0.1:{a};\nserver 127.0.0.1:{b};"), ""),
    );
    let started = Instant::now();
    assert_eq!(s.get("/").0, 502);
    assert!(started.elapsed() < Duration::from_secs(5), "it must fail promptly, not hang");
}

#[test]
fn off_disables_retrying_entirely() {
    let dead = dead_port();
    let live = Peer::start(&*Box::leak(ok("alive").into_boxed_str()));
    let s = Server::start(
        "off",
        &conf(
            &format!("server 127.0.0.1:{dead};\nserver 127.0.0.1:{};", live.port),
            "proxy_next_upstream off;",
        ),
    );
    let mut saw_error = false;
    for _ in 0..10 {
        if s.get("/").0 == 502 {
            saw_error = true;
        }
    }
    assert!(saw_error, "`off` must let the failure reach the client");
}

/// `proxy_next_upstream_tries 1` means one attempt and no retry.
#[test]
fn tries_bounds_how_many_peers_are_burned() {
    let dead = dead_port();
    let live = Peer::start(&*Box::leak(ok("alive").into_boxed_str()));
    let s = Server::start(
        "tries",
        &conf(
            &format!("server 127.0.0.1:{dead};\nserver 127.0.0.1:{};", live.port),
            "proxy_next_upstream_tries 1;",
        ),
    );
    let mut saw_error = false;
    for _ in 0..10 {
        if s.get("/").0 == 502 {
            saw_error = true;
        }
    }
    assert!(saw_error, "a single try means no retry");
}

/// A single address is not a group: there is no next peer to move to.
#[test]
fn a_single_address_has_nothing_to_retry_onto() {
    let dead = dead_port();
    let s = Server::start(
        "single",
        &format!(
            "server {{ listen {{PORT}}; location / {{ proxy_pass http://127.0.0.1:{dead}; }} }}"
        ),
    );
    assert_eq!(s.get("/").0, 502);
}

#[test]
fn an_unknown_next_upstream_parameter_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-nu-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} http { upstream u { server 1.2.3.4:80; } \
         server { listen 20799; location / { proxy_pass http://u; \
         proxy_next_upstream error frobnicate; } } }",
    )
    .unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("frobnicate"), "the message should name it: {err}");
}

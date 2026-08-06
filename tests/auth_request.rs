//! `auth_request` — delegating the yes/no to another service.
//!
//! The authorisation service here is a real HTTP backend rather than a
//! `return`, because that is how it is deployed and because it lets the tests
//! see exactly what the subrequest carried.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(20600);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// The authorisation service. Answers by rule and records what it was asked.
struct Auth {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    calls: Arc<AtomicUsize>,
}

impl Auth {
    /// `reply` maps the raw request text to a raw HTTP response.
    fn start(reply: impl Fn(&str) -> String + Send + Sync + 'static) -> Auth {
        let p = port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let (s2, c2) = (seen.clone(), calls.clone());
        let reply = Arc::new(reply);
        let l = TcpListener::bind(("127.0.0.1", p)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (s2, c2, reply) = (s2.clone(), c2.clone(), reply.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut buf = [0u8; 8192];
                    let Ok(n) = c.read(&mut buf) else { return };
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    c2.fetch_add(1, Ordering::SeqCst);
                    s2.lock().unwrap().push(req.clone());
                    let _ = c.write_all(reply(&req).as_bytes());
                });
            }
        });
        Auth { port: p, seen, calls }
    }

    fn last(&self) -> String {
        self.seen.lock().unwrap().last().cloned().unwrap_or_default()
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
        let dir =
            std::env::temp_dir().join(format!("oxiserve-auth-{}-{name}-{p}", std::process::id()));
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

    fn request(&self, raw: &str) -> (u16, Vec<(String, String)>, String) {
        let mut c = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(raw.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = c.read_to_string(&mut resp);
        let status = resp.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let head_end = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(resp.len());
        let headers = resp[..head_end]
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .map(|(a, b)| (a.to_string(), b.trim().to_string()))
            .collect();
        (status, headers, resp[head_end..].to_string())
    }

    fn get(&self, path: &str) -> (u16, Vec<(String, String)>, String) {
        self.request(&format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
    }
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn ok(body: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
}

/// A protected location, an internal auth location proxying to `auth`, and an
/// open one for contrast.
fn conf(auth: u16, extra: &str) -> String {
    format!(
        "server {{ listen {{PORT}};\n\
           location /private {{ auth_request /_auth; return 200 \"secret\"; }}\n\
           location /open {{ return 200 \"public\"; }}\n\
           location = /_auth {{ internal; proxy_pass http://127.0.0.1:{auth}; }}\n\
           {extra}\n\
         }}"
    )
}

// ---------------------------------------------------------------------------

#[test]
fn a_2xx_from_the_auth_service_lets_the_request_through() {
    let a = Auth::start(|_| ok(""));
    let s = Server::start("allow", &conf(a.port, ""));
    let (status, _, body) = s.get("/private");
    assert_eq!(status, 200);
    assert_eq!(body, "secret");
    assert_eq!(a.calls.load(Ordering::SeqCst), 1, "the auth service must be consulted");
}

#[test]
fn a_401_and_a_403_are_returned_to_the_client_as_they_stand() {
    for code in [401u16, 403] {
        let a = Auth::start(move |_| format!("HTTP/1.1 {code} No\r\nContent-Length: 0\r\n\r\n"));
        let s = Server::start(&format!("deny{code}"), &conf(a.port, ""));
        let (status, _, body) = s.get("/private");
        assert_eq!(status, code, "the service's verdict is the client's answer");
        assert!(!body.contains("secret"), "the protected content must not leak: {body:?}");
    }
}

/// The failure mode that matters: an auth service that cannot answer must not
/// accidentally allow the request.
#[test]
fn an_unusable_auth_response_fails_closed() {
    for reply in [
        "HTTP/1.1 500 Boom\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 204 No Content\r\n\r\n", // 2xx — this one DOES allow
    ] {
        let expect_allow = reply.contains(" 204 ");
        let a = Auth::start(move |_| reply.to_string());
        let s = Server::start("closed", &conf(a.port, ""));
        let (status, _, body) = s.get("/private");
        if expect_allow {
            assert_eq!(status, 200, "any 2xx is a yes");
        } else {
            assert_eq!(status, 500, "an answer that is not yes/401/403 is a failure: {reply:?}");
            assert!(!body.contains("secret"));
        }
    }
}

/// An auth service that is not running at all must also fail closed.
#[test]
fn an_unreachable_auth_service_fails_closed() {
    let dead = port(); // nothing listens
    let s = Server::start("unreachable", &conf(dead, ""));
    let (status, _, body) = s.get("/private");
    assert_eq!(status, 500);
    assert!(!body.contains("secret"));
}

#[test]
fn locations_without_auth_request_are_untouched() {
    let a = Auth::start(|_| "HTTP/1.1 403 No\r\nContent-Length: 0\r\n\r\n".to_string());
    let s = Server::start("open", &conf(a.port, ""));
    let (status, _, body) = s.get("/open");
    assert_eq!(status, 200);
    assert_eq!(body, "public");
    assert_eq!(a.calls.load(Ordering::SeqCst), 0, "an open location must not consult it");
}

#[test]
fn the_subrequest_is_a_get_carrying_the_client_headers_and_no_body() {
    let a = Auth::start(|_| ok(""));
    let s = Server::start("shape", &conf(a.port, ""));
    // A POST with a body: the auth service should see a GET, the cookie, and
    // no body framing at all.
    let (status, _, _) = s.request(
        "POST /private HTTP/1.1\r\nHost: x\r\nCookie: sid=abc\r\n\
         Content-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    assert_eq!(status, 200);
    let seen = a.last().to_lowercase();
    assert!(seen.starts_with("get "), "the subrequest must be a GET: {seen:?}");
    assert!(seen.contains("cookie: sid=abc"), "client headers must travel: {seen:?}");
    assert!(
        !seen.contains("content-length") && !seen.contains("transfer-encoding"),
        "the subrequest must carry no body framing: {seen:?}"
    );
    assert!(!seen.contains("hello"), "the body must not be forwarded: {seen:?}");
}

#[test]
fn auth_request_set_carries_a_value_out_of_the_auth_response() {
    let a = Auth::start(|_| {
        "HTTP/1.1 200 OK\r\nX-User: alice\r\nX-Role: admin\r\nContent-Length: 0\r\n\r\n".to_string()
    });
    let s = Server::start(
        "setvar",
        &format!(
            "server {{ listen {{PORT}};\n\
               location /private {{\n\
                 auth_request /_auth;\n\
                 auth_request_set $user $upstream_http_x_user;\n\
                 auth_request_set $role $upstream_http_x_role;\n\
                 return 200 \"user=$user role=$role\";\n\
               }}\n\
               location = /_auth {{ internal; proxy_pass http://127.0.0.1:{}; }}\n\
             }}",
            a.port
        ),
    );
    let (status, _, body) = s.get("/private");
    assert_eq!(status, 200);
    assert_eq!(body, "user=alice role=admin");
}

/// `auth_request off` in a nested location undoes an inherited one, which is
/// how a health check is exempted from an otherwise protected server.
#[test]
fn auth_request_off_disables_an_inherited_one() {
    let a = Auth::start(|_| "HTTP/1.1 403 No\r\nContent-Length: 0\r\n\r\n".to_string());
    let s = Server::start(
        "off",
        &format!(
            "server {{ listen {{PORT}};\n\
               auth_request /_auth;\n\
               location /guarded {{ return 200 \"guarded\"; }}\n\
               location /health {{ auth_request off; return 200 \"ok\"; }}\n\
               location = /_auth {{ internal; auth_request off; proxy_pass http://127.0.0.1:{}; }}\n\
             }}",
            a.port
        ),
    );
    assert_eq!(s.get("/guarded").0, 403, "the server-level auth_request must apply");
    let (status, _, body) = s.get("/health");
    assert_eq!(status, 200, "auth_request off must exempt this location");
    assert_eq!(body, "ok");
}

/// The auth location is `internal`, so a client cannot reach it directly — but
/// the subrequest still can.
#[test]
fn the_auth_location_stays_internal() {
    let a = Auth::start(|_| ok("auth-body"));
    let s = Server::start("internal", &conf(a.port, ""));
    assert_eq!(s.get("/_auth").0, 404, "an internal location is not reachable from outside");
    assert_eq!(s.get("/private").0, 200, "but the subrequest reaches it");
}

/// A `401` from the service usually carries `WWW-Authenticate`, and the client
/// needs it to know how to authenticate.
#[test]
fn a_401_keeps_its_www_authenticate_header() {
    let a = Auth::start(|_| {
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"api\"\r\n\
         Content-Length: 0\r\n\r\n"
            .to_string()
    });
    let s = Server::start(
        "wwwauth",
        &format!(
            "server {{ listen {{PORT}};\n\
               location /private {{\n\
                 auth_request /_auth;\n\
                 auth_request_set $chal $upstream_http_www_authenticate;\n\
                 return 200 \"secret\";\n\
               }}\n\
               error_page 401 = @unauth;\n\
               location @unauth {{ add_header WWW-Authenticate $chal always; return 401 \"\"; }}\n\
               location = /_auth {{ internal; proxy_pass http://127.0.0.1:{}; }}\n\
             }}",
            a.port
        ),
    );
    let (status, h, _) = s.get("/private");
    assert_eq!(status, 401);
    assert_eq!(
        header(&h, "WWW-Authenticate"),
        Some("Bearer realm=\"api\""),
        "the challenge must reach the client, headers: {h:?}"
    );
}

/// An auth location that itself requires authorisation would recurse forever.
#[test]
fn a_recursive_auth_request_is_refused_rather_than_looping() {
    let s = Server::start(
        "recurse",
        "server { listen {PORT};\n\
           location /private { auth_request /_auth; return 200 \"secret\"; }\n\
           location = /_auth { internal; auth_request /_auth; return 200 \"\"; }\n\
         }",
    );
    let (status, _, body) = s.get("/private");
    assert_eq!(status, 500, "recursion must be refused, not survived");
    assert!(!body.contains("secret"));
}

#[test]
fn a_relative_auth_request_uri_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-auth-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} http { server { listen 20599; location / { auth_request notaslash; } } }",
    )
    .unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("auth_request"), "got: {err}");
}

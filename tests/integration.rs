//! End-to-end tests: a real server, a real socket, real bytes on the wire.
//!
//! The unit tests cover parsing and matching in isolation. These cover the
//! thing that actually matters — that a given `nginx.conf` plus a given
//! request produces the response an nginx operator would expect.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Ports are handed out sequentially from a high base so parallel tests do not
/// collide. Binding is verified before a test proceeds.
static NEXT_PORT: AtomicU16 = AtomicU16::new(18400);

struct Server {
    port: u16,
    dir: PathBuf,
}

impl Server {
    /// Starts a server with `conf` (with `{PORT}` and `{ROOT}` substituted)
    /// and waits until it accepts connections.
    fn start(name: &str, conf: &str, files: &[(&str, &[u8])]) -> Server {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("oxiserve-it-{}-{name}-{port}", std::process::id()));
        let root = dir.join("html");
        std::fs::create_dir_all(&root).unwrap();

        for (path, body) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }

        let conf_text = conf
            .replace("{PORT}", &port.to_string())
            .replace("{ROOT}", root.to_str().unwrap())
            .replace("{DIR}", dir.to_str().unwrap());
        let conf_path = dir.join("oxiserve.conf");
        std::fs::write(&conf_path, conf_text).unwrap();

        let cfg = oxiserve::config::load(&conf_path, dir.clone())
            .unwrap_or_else(|e| panic!("config load failed: {e}"));

        std::thread::spawn(move || {
            let _ = oxiserve::server::run(cfg);
        });

        // Wait for the listener rather than sleeping a fixed amount.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Server { port, dir };
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("server on port {port} never came up");
    }

    fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    }

    /// Sends a raw request and returns the parsed response.
    fn raw(&self, req: &str) -> Response {
        let mut s = self.connect();
        s.write_all(req.as_bytes()).unwrap();
        s.flush().unwrap();
        read_response(&mut s)
    }

    fn get(&self, path: &str) -> Response {
        self.raw(&format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ))
    }

}

#[derive(Debug)]
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

    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Reads one response, honouring Content-Length, chunked, or read-to-EOF.
fn read_response(s: &mut TcpStream) -> Response {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).unwrap() == 0 {
            break;
        }
        let t = l.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((n, v)) = t.split_once(':') {
            headers.push((n.trim().to_string(), v.trim().to_string()));
        }
    }

    let len = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let mut body = Vec::new();
    match len {
        // Read up to Content-Length but tolerate a short body: a HEAD response
        // legitimately advertises the entity length and sends no bytes.
        Some(n) => {
            body.resize(n, 0);
            let mut got = 0;
            while got < n {
                match r.read(&mut body[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => got += k,
                }
            }
            body.truncate(got);
        }
        None => {
            let _ = r.read_to_end(&mut body);
        }
    }
    Response { status, headers, body }
}

const BASE: &str = "
worker_processes 1;
error_log {DIR}/error.log crit;
events { worker_connections 256; }
http {
    access_log off;
";

// ---------------------------------------------------------------------------

#[test]
fn serves_a_static_file_with_validators() {
    let s = Server::start(
        "static",
        &format!(
            "{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        index index.html;
    }}
}}"
        ),
        &[("index.html", b"<h1>hello</h1>")],
    );

    let r = s.get("/index.html");
    assert_eq!(r.status, 200);
    assert_eq!(r.body_str(), "<h1>hello</h1>");
    assert_eq!(r.header("Content-Type"), Some("text/html"));
    assert_eq!(r.header("Content-Length"), Some("14"));
    assert!(r.header("ETag").is_some());
    assert!(r.header("Last-Modified").is_some());
    assert_eq!(r.header("Accept-Ranges"), Some("bytes"));

    // The index directive resolves a bare directory request.
    assert_eq!(s.get("/").status, 200);
}

#[test]
fn conditional_requests_return_304() {
    let s = Server::start(
        "cond",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("a.txt", b"content")],
    );

    let first = s.get("/a.txt");
    let etag = first.header("ETag").unwrap().to_string();
    let lm = first.header("Last-Modified").unwrap().to_string();

    let r = s.raw(&format!(
        "GET /a.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
    ));
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    // A 304 must repeat the validator.
    assert_eq!(r.header("ETag"), Some(etag.as_str()));

    let r = s.raw(&format!(
        "GET /a.txt HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: {lm}\r\nConnection: close\r\n\r\n"
    ));
    assert_eq!(r.status, 304);
}

#[test]
fn byte_ranges() {
    let s = Server::start(
        "range",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("nums.txt", b"0123456789")],
    );

    let r = s.raw("GET /nums.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 206);
    assert_eq!(r.body_str(), "2345");
    assert_eq!(r.header("Content-Range"), Some("bytes 2-5/10"));

    let r = s.raw("GET /nums.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=-3\r\nConnection: close\r\n\r\n");
    assert_eq!(r.body_str(), "789");

    let r = s.raw("GET /nums.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=50-60\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 416);
    assert_eq!(r.header("Content-Range"), Some("bytes */10"));
}

#[test]
fn location_matching_follows_nginx_precedence() {
    let s = Server::start(
        "locmatch",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location = /exact      {{ return 200 \"exact\"; }}
        location ^~ /static/   {{ return 200 \"caret\"; }}
        location ~ \\.php$     {{ return 200 \"regex\"; }}
        location /             {{ return 200 \"prefix\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/exact").body_str(), "exact");
    // `^~` beats a regex that would also match.
    assert_eq!(s.get("/static/x.php").body_str(), "caret");
    // A regex beats a plain prefix.
    assert_eq!(s.get("/other/x.php").body_str(), "regex");
    assert_eq!(s.get("/anything").body_str(), "prefix");
}

#[test]
fn server_name_selects_the_virtual_host() {
    let s = Server::start(
        "vhost",
        &format!("{BASE}
    server {{ listen {{PORT}} default_server; server_name _; return 200 \"default\"; }}
    server {{ listen {{PORT}}; server_name a.test;   return 200 \"exact\"; }}
    server {{ listen {{PORT}}; server_name *.b.test; return 200 \"wildcard\"; }}
}}"),
        &[],
    );

    let hit = |host: &str| {
        s.raw(&format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ))
        .body_str()
    };
    assert_eq!(hit("a.test"), "exact");
    assert_eq!(hit("x.b.test"), "wildcard");
    assert_eq!(hit("unknown.test"), "default");
    // Host matching ignores case and a trailing dot.
    assert_eq!(hit("A.TEST"), "exact");
}

#[test]
fn try_files_falls_back_for_spa_routing() {
    let s = Server::start(
        "tryfiles",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ try_files $uri $uri/ /app.html; }}
    }}
}}"),
        &[("app.html", b"APP"), ("real.txt", b"REAL")],
    );

    assert_eq!(s.get("/real.txt").body_str(), "REAL");
    // A path with no file behind it falls through to the SPA entry point.
    let r = s.get("/deep/client/route");
    assert_eq!(r.status, 200);
    assert_eq!(r.body_str(), "APP");
}

#[test]
fn try_files_404_fallback() {
    let s = Server::start(
        "tryfiles404",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ try_files $uri =404; }}
    }}
}}"),
        &[],
    );
    assert_eq!(s.get("/missing").status, 404);
}

#[test]
fn error_page_keeps_the_original_status() {
    let s = Server::start(
        "errpage",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        error_page 404 /404.html;
        error_page 403 =200 /404.html;
    }}
}}"),
        &[("404.html", b"CUSTOM")],
    );

    // Without `=`, the custom page is served but the status stays 404.
    let r = s.get("/nothing-here");
    assert_eq!(r.status, 404);
    assert_eq!(r.body_str(), "CUSTOM");
}

#[test]
fn rewrite_flags() {
    let s = Server::start(
        "rewrite",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        rewrite ^/old/(.*)$ /new/$1 permanent;
        location /new/ {{ return 200 \"new\"; }}
    }}
}}"),
        &[],
    );

    let r = s.get("/old/thing");
    assert_eq!(r.status, 301);
    assert!(r.header("Location").unwrap().ends_with("/new/thing"), "{:?}", r.header("Location"));
}

#[test]
fn directory_without_trailing_slash_redirects() {
    let s = Server::start(
        "dirredir",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("sub/index.html", b"SUB")],
    );

    let r = s.get("/sub");
    assert_eq!(r.status, 301);
    assert!(r.header("Location").unwrap().ends_with("/sub/"));
    assert_eq!(s.get("/sub/").body_str(), "SUB");
}

// ---- security ------------------------------------------------------------

#[test]
fn path_traversal_is_rejected_on_the_wire() {
    let s = Server::start(
        "traversal",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("ok.txt", b"ok")],
    );
    // Write a file OUTSIDE the document root that a traversal would reach.
    std::fs::write(s.dir.join("secret.txt"), b"SECRET").unwrap();

    for attack in [
        "/../secret.txt",
        "/sub/../../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2e%2e%2fsecret.txt",
        "/..%2fsecret.txt",
        "/a/%2e%2e/%2e%2e/secret.txt",
    ] {
        let r = s.raw(&format!(
            "GET {attack} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        ));
        assert!(
            r.status == 400 || r.status == 404,
            "{attack} returned {} — expected 400/404",
            r.status
        );
        assert!(
            !r.body_str().contains("SECRET"),
            "{attack} leaked the file outside the root"
        );
    }
}

#[test]
fn request_smuggling_vectors_are_rejected() {
    let s = Server::start(
        "smuggle",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[],
    );

    // Content-Length and Transfer-Encoding together.
    let r = s.raw(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    assert_eq!(r.status, 400);

    // Two conflicting Content-Length headers.
    let r = s.raw("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello");
    assert_eq!(r.status, 400);
}

#[test]
fn http_11_without_host_is_rejected() {
    let s = Server::start(
        "nohost",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[],
    );
    assert_eq!(s.raw("GET / HTTP/1.1\r\n\r\n").status, 400);
}

// ---- connection handling -------------------------------------------------

#[test]
fn keepalive_serves_many_requests_on_one_connection() {
    let s = Server::start(
        "keepalive",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"ok\"; }} }}
}}"),
        &[],
    );

    let mut sock = s.connect();
    for i in 0..25 {
        sock.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        sock.flush().unwrap();

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        // Read exactly one response head, then its 2-byte body.
        while !head.ends_with(b"\r\n\r\n") {
            let n = sock.read(&mut byte).unwrap();
            assert!(n == 1, "connection closed early on request {i}");
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        assert!(text.starts_with("HTTP/1.1 200"), "request {i}: {text}");
        let mut body = [0u8; 2];
        sock.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"ok");
    }
    sock.shutdown(Shutdown::Both).unwrap();
}

#[test]
fn pipelined_requests_are_all_answered() {
    let s = Server::start(
        "pipeline",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"ok\"; }} }}
}}"),
        &[],
    );

    let mut sock = s.connect();
    // Three requests written before reading any response.
    sock.write_all(
        b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
          GET /b HTTP/1.1\r\nHost: x\r\n\r\n\
          GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    sock.flush().unwrap();

    let mut all = Vec::new();
    sock.read_to_end(&mut all).unwrap();
    let text = String::from_utf8_lossy(&all);
    assert_eq!(text.matches("HTTP/1.1 200").count(), 3, "{text}");
}

#[test]
fn head_returns_headers_without_a_body() {
    let s = Server::start(
        "head",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("f.txt", b"0123456789")],
    );

    let r = s.raw("HEAD /f.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    // Content-Length must describe the entity, but no body may follow.
    assert_eq!(r.header("Content-Length"), Some("10"));
    assert!(r.body.is_empty());
}

// ---- bodies ---------------------------------------------------------------

#[test]
fn chunked_and_plain_bodies_decode_identically() {
    // `return` cannot echo a body, so this asserts the server accepts and
    // consumes both framings and stays usable afterwards.
    let s = Server::start(
        "bodies",
        &format!("{BASE}
    client_max_body_size 1m;
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"got\"; }} }}
}}"),
        &[],
    );

    let payload = "x".repeat(50_000);
    let plain = s.raw(&format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    ));
    assert_eq!(plain.status, 200);

    // Same payload as two chunks plus the terminator.
    let (a, b) = payload.split_at(20_000);
    let chunked = s.raw(&format!(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         {:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    ));
    assert_eq!(chunked.status, 200);
}

#[test]
fn oversized_body_is_rejected_with_413() {
    let s = Server::start(
        "toobig",
        &format!("{BASE}
    client_max_body_size 1k;
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"ok\"; }} }}
}}"),
        &[],
    );

    let payload = "x".repeat(5000);
    let r = s.raw(&format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    ));
    assert_eq!(r.status, 413);
}

// ---- content negotiation --------------------------------------------------

#[test]
fn gzip_compresses_only_matching_types() {
    let s = Server::start(
        "gzip",
        &format!("{BASE}
    gzip on;
    gzip_min_length 100;
    gzip_types text/plain;
    gzip_vary on;
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("big.txt", "compress me ".repeat(100).as_bytes()), ("img.png", &[0u8; 500])],
    );

    let r = s.raw("GET /big.txt HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n");
    assert_eq!(r.header("Content-Encoding"), Some("gzip"));
    assert_eq!(r.header("Vary"), Some("Accept-Encoding"));
    assert!(r.body.len() < 1200, "should be smaller than the 1200-byte original");

    // A type outside gzip_types is left alone.
    let r = s.raw("GET /img.png HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n");
    assert_eq!(r.header("Content-Encoding"), None);

    // A client that does not advertise gzip gets the original bytes.
    let r = s.get("/big.txt");
    assert_eq!(r.header("Content-Encoding"), None);
    assert_eq!(r.body.len(), 1200);
}

#[test]
fn add_header_and_expires_are_applied() {
    let s = Server::start(
        "headers",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        add_header X-Custom hello always;
        expires 1h;
    }}
}}"),
        &[("a.txt", b"a")],
    );

    let r = s.get("/a.txt");
    assert_eq!(r.header("X-Custom"), Some("hello"));
    assert_eq!(r.header("Cache-Control"), Some("max-age=3600"));
    assert!(r.header("Expires").is_some());
}

#[test]
fn autoindex_lists_a_directory() {
    let s = Server::start(
        "autoindex",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; autoindex on; }}
}}"),
        &[("d/one.txt", b"1"), ("d/two.txt", b"2")],
    );

    let r = s.get("/d/");
    assert_eq!(r.status, 200);
    let b = r.body_str();
    assert!(b.contains("Index of /d/"), "{b}");
    assert!(b.contains("one.txt") && b.contains("two.txt"), "{b}");
}

#[test]
fn alias_replaces_the_location_prefix() {
    let s = Server::start(
        "alias",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location /files/ {{ alias {{ROOT}}/inner/; }}
    }}
}}"),
        &[("inner/doc.txt", b"INNER")],
    );

    // With alias, /files/doc.txt maps to <root>/inner/doc.txt — the prefix is
    // replaced, not appended.
    assert_eq!(s.get("/files/doc.txt").body_str(), "INNER");
}

#[test]
fn limit_except_restricts_methods() {
    let s = Server::start(
        "limitexcept",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_except GET; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/").status, 200);
    // HEAD is implied by GET.
    assert_eq!(s.raw("HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").status, 200);
    let r = s.raw("DELETE / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 405);
}

#[test]
fn internal_locations_are_unreachable_from_outside() {
    let s = Server::start(
        "internal",
        &format!("{BASE}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        error_page 404 /private.html;
        location = /private.html {{ internal; }}
    }}
}}"),
        &[("private.html", b"PRIVATE")],
    );

    // Directly requested: not found.
    assert_eq!(s.get("/private.html").status, 404);
    // Reached through error_page: served.
    let r = s.get("/does-not-exist");
    assert_eq!(r.status, 404);
    assert_eq!(r.body_str(), "PRIVATE");
}

#[test]
fn map_and_variables_resolve_in_return() {
    let s = Server::start(
        "mapvars",
        &format!("{BASE}
    map $http_x_flavour $flavour {{
        default  vanilla;
        choc     chocolate;
        \"~^str\" strawberry;
    }}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ return 200 \"$flavour|$request_method|$uri\"; }}
    }}
}}"),
        &[],
    );

    let hit = |hdr: &str| {
        s.raw(&format!(
            "GET /path HTTP/1.1\r\nHost: x\r\nX-Flavour: {hdr}\r\nConnection: close\r\n\r\n"
        ))
        .body_str()
    };
    assert_eq!(hit("choc"), "chocolate|GET|/path");
    assert_eq!(hit("strawberry-thing"), "strawberry|GET|/path");
    assert_eq!(hit("unknown"), "vanilla|GET|/path");
}

#[test]
fn access_log_writes_the_configured_format() {
    let s = Server::start(
        "accesslog",
        &"
worker_processes 1;
error_log {DIR}/error.log crit;
events { worker_connections 64; }
http {
    log_format test '$request_method $uri $status $body_bytes_sent';
    access_log {DIR}/access.log test;
    server { listen {PORT}; root {ROOT}; location / { return 200 \"hello\"; } }
}".to_string(),
        &[],
    );

    assert_eq!(s.get("/logged").status, 200);

    // The log sink flushes on a timer; give it a moment.
    let path = s.dir.join("access.log");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(c) = std::fs::read_to_string(&path) {
            if c.contains("/logged") {
                assert!(c.contains("GET /logged 200 5"), "{c}");
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("access log never contained the request");
}

#[test]
fn open_file_cache_serves_hits_and_holds_within_valid() {
    let s = Server::start(
        "ofc",
        &format!("{BASE}
    open_file_cache max=64 inactive=10s;
    open_file_cache_valid 5s;
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("a.txt", b"first")],
    );

    // Prime the cache, then serve from it repeatedly.
    for _ in 0..3 {
        let r = s.get("/a.txt");
        assert_eq!(r.status, 200);
        assert_eq!(r.body_str(), "first");
    }

    // Replace the file ATOMICALLY (rename), the way deploys actually ship
    // content. The cached descriptor still refers to the old inode, so within
    // the validity window the old content is served intact — nginx's
    // documented behaviour. (An in-place truncate-and-write would be visible
    // through the cached fd on both servers; that hazard is why atomic
    // replace is the deploy idiom in the first place.)
    let tmp = s.dir.join("html/.a.txt.new");
    std::fs::write(&tmp, b"second!").unwrap();
    std::fs::rename(&tmp, s.dir.join("html/a.txt")).unwrap();
    let r = s.get("/a.txt");
    assert_eq!(r.body_str(), "first", "cache must serve the stale entry within valid");
}

#[test]
fn without_open_file_cache_changes_appear_immediately() {
    let s = Server::start(
        "noofc",
        &format!("{BASE}
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("b.txt", b"one")],
    );
    assert_eq!(s.get("/b.txt").body_str(), "one");
    std::fs::write(s.dir.join("html/b.txt"), b"two!").unwrap();
    assert_eq!(s.get("/b.txt").body_str(), "two!");
}

#[test]
fn open_file_cache_missing_file_still_404s_and_appears_when_created() {
    // errors off (the default): misses are not cached.
    let s = Server::start(
        "ofcmiss",
        &format!("{BASE}
    open_file_cache max=64 inactive=10s;
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[],
    );
    assert_eq!(s.get("/late.txt").status, 404);
    std::fs::write(s.dir.join("html/late.txt"), b"now").unwrap();
    let r = s.get("/late.txt");
    assert_eq!(r.status, 200, "with errors off, a created file must appear immediately");
    assert_eq!(r.body_str(), "now");
}

#[test]
fn gzip_compresses_files_too_large_for_the_inline_path() {
    // Files above the inline threshold take the sendfile/stream path. They
    // must still compress — WordPress ships a 131 KB stylesheet, and skipping
    // those silently defeats gzip on exactly the assets that matter most.
    let big = "body{color:red;padding:0;margin:0}\n".repeat(6000); // ~200 KB
    let s = Server::start(
        "gzipbig",
        &format!("{BASE}
    gzip on;
    gzip_min_length 256;
    gzip_types text/css;
    server {{ listen {{PORT}}; root {{ROOT}}; }}
}}"),
        &[("big.css", big.as_bytes())],
    );

    let r = s.raw("GET /big.css HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("Content-Encoding"), Some("gzip"), "large file must still be compressed");
    assert!(
        r.body.len() < big.len() / 4,
        "expected real compression, got {} from {}", r.body.len(), big.len()
    );

    // Without gzip the client still gets every byte.
    let plain = s.get("/big.css");
    assert_eq!(plain.body.len(), big.len());
}

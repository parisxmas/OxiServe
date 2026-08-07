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

// ---- limit_req ------------------------------------------------------------

#[test]
fn limit_req_rejects_over_the_rate() {
    // 1r/s, no burst: the first request passes, the rest of the flood is 503.
    let s = Server::start(
        "limitreq",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=one:1m rate=1r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_req zone=one; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/").status, 200, "first request must pass");
    let rejected = (0..5).filter(|_| s.get("/").status == 503).count();
    assert_eq!(rejected, 5, "every request over the rate must be rejected");
}

#[test]
fn limit_req_burst_admits_a_spike() {
    let s = Server::start(
        "limitburst",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=b:1m rate=1r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_req zone=b burst=3 nodelay; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );

    // 1 on-rate + 3 burst = 4 admitted, then rejection.
    let codes: Vec<u16> = (0..6).map(|_| s.get("/").status).collect();
    assert_eq!(&codes[..4], &[200, 200, 200, 200], "burst must be admitted: {codes:?}");
    assert_eq!(&codes[4..], &[503, 503], "past the burst must reject: {codes:?}");
}

#[test]
fn limit_req_status_is_configurable() {
    let s = Server::start(
        "limitstatus",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=st:1m rate=1r/s;
    limit_req_status 429;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_req zone=st; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );
    assert_eq!(s.get("/").status, 200);
    assert_eq!(s.get("/").status, 429, "limit_req_status must be honoured");
}

#[test]
fn limit_req_only_applies_where_configured() {
    let s = Server::start(
        "limitscope",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=sc:1m rate=1r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location /limited {{ limit_req zone=sc; return 200 \"limited\"; }}
        location /open    {{ return 200 \"open\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/limited").status, 200);
    assert_eq!(s.get("/limited").status, 503);
    // An unlimited location keeps serving regardless.
    for _ in 0..5 {
        assert_eq!(s.get("/open").status, 200, "unlimited location must not be throttled");
    }
}

#[test]
fn limit_req_recovers_after_the_window() {
    let s = Server::start(
        "limitrecover",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=rc:1m rate=5r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_req zone=rc; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/").status, 200);
    assert_eq!(s.get("/").status, 503, "immediate repeat is over 5r/s");
    // 5r/s means one request per 200ms; after that the bucket has drained.
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(s.get("/").status, 200, "must recover once the bucket drains");
}

#[test]
fn limit_req_burst_without_nodelay_delays_rather_than_rejecting() {
    let s = Server::start(
        "limitdelay",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=dl:1m rate=10r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ limit_req zone=dl burst=2; return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/").status, 200);
    // The next one is inside the burst, so it is held rather than refused —
    // at 10r/s that is ~100ms, not an error.
    let t = Instant::now();
    let r = s.get("/");
    let waited = t.elapsed();
    assert_eq!(r.status, 200, "a burst request must be delayed, not rejected");
    assert!(
        waited >= Duration::from_millis(50),
        "expected the request to be held back, waited only {waited:?}"
    );
}

#[test]
fn unknown_limit_req_zone_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-badzone-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} http { server { listen 80; location / { limit_req zone=nope; } } }",
    )
    .unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("unknown limit_req zone"), "got: {err}");
}

#[test]
fn limit_req_applies_without_a_location_block() {
    // Regression: with no `location` the router takes a server-level fallback
    // path that skipped dispatch entirely, so the limit never ran. A config
    // this plain is common, and it was silently unlimited.
    let s = Server::start(
        "limitnoloc",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=nl:1m rate=1r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        limit_req zone=nl;
    }}
}}"),
        &[("index.html", b"served")],
    );

    assert_eq!(s.get("/index.html").status, 200, "first request passes");
    assert_eq!(s.get("/index.html").status, 503, "server-level limit must apply");
}

#[test]
fn limit_req_inherits_from_server_into_locations() {
    let s = Server::start(
        "limitinherit",
        &format!("{BASE}
    limit_req_zone $binary_remote_addr zone=ih:1m rate=1r/s;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        limit_req zone=ih;
        location /a {{ return 200 \"a\"; }}
    }}
}}"),
        &[],
    );
    assert_eq!(s.get("/a").status, 200);
    assert_eq!(s.get("/a").status, 503, "a location must inherit the server's limit");
}

// ---- limit_conn -----------------------------------------------------------

/// A backend that parks every request until the test lets it answer.
///
/// `limit_conn` counts requests *in flight*, so proving anything about it needs
/// a request that is genuinely still being processed while the next one
/// arrives. Holding the upstream is the only way to make that deterministic —
/// timing two client threads against each other is not.
fn parked_backend() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;

    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let arrived = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let (a, r) = (arrived.clone(), release.clone());
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (a, r) = (a.clone(), r.clone());
            std::thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                if c.read(&mut buf).is_err() {
                    return;
                }
                a.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(10);
                while !r.load(Ordering::SeqCst) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = c.flush();
            });
        }
    });
    (port, arrived, release)
}

fn limit_conn_conf(backend: u16, http_extra: &str, loc_extra: &str) -> String {
    format!("{BASE}
    limit_conn_zone $binary_remote_addr zone=perip:1m;
    {http_extra}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location /slow {{
            {loc_extra}
            proxy_pass http://127.0.0.1:{backend};
        }}
    }}
}}")
}

/// Blocks until `arrived` reaches `n`, so the test never races the backend.
fn wait_for(arrived: &std::sync::atomic::AtomicUsize, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while arrived.load(Ordering::SeqCst) < n {
        assert!(Instant::now() < deadline, "backend never saw {n} request(s)");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn limit_conn_refuses_a_second_concurrent_request() {
    let (backend, arrived, release) = parked_backend();
    let s = Server::start(
        "limitconn",
        &limit_conn_conf(backend, "", "limit_conn perip 1;"),
        &[],
    );

    let port = s.port;
    let first = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        read_response(&mut c).status
    });

    // Only once the backend has the first request is it certainly in flight.
    wait_for(&arrived, 1);
    assert_eq!(s.get("/slow").status, 503, "the second concurrent request must be refused");
    assert_eq!(arrived.load(Ordering::SeqCst), 1, "the refused request must not reach the backend");

    release.store(true, Ordering::SeqCst);
    assert_eq!(first.join().unwrap(), 200, "the request that held the slot must still be served");

    // And with the slot given back, the next request goes through.
    assert_eq!(s.get("/slow").status, 200, "the slot must be released when the request ends");
}

#[test]
fn limit_conn_status_is_configurable() {
    let (backend, arrived, release) = parked_backend();
    let s = Server::start(
        "limitconnstatus",
        &limit_conn_conf(backend, "limit_conn_status 429;", "limit_conn perip 1;"),
        &[],
    );

    let port = s.port;
    let first = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        read_response(&mut c).status
    });

    wait_for(&arrived, 1);
    assert_eq!(s.get("/slow").status, 429, "limit_conn_status must be honoured");
    release.store(true, Ordering::SeqCst);
    first.join().unwrap();
}

#[test]
fn limit_conn_dry_run_admits_what_it_would_have_refused() {
    let (backend, arrived, release) = parked_backend();
    let s = Server::start(
        "limitconndry",
        &limit_conn_conf(backend, "limit_conn_dry_run on;", "limit_conn perip 1;"),
        &[],
    );

    let port = s.port;
    let first = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        read_response(&mut c).status
    });

    wait_for(&arrived, 1);
    let second = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        read_response(&mut c).status
    });
    wait_for(&arrived, 2);

    release.store(true, Ordering::SeqCst);
    assert_eq!(first.join().unwrap(), 200);
    assert_eq!(second.join().unwrap(), 200, "dry run must not reject");
}

#[test]
fn limit_conn_does_not_restrict_sequential_requests() {
    // The counter is per request-in-flight, not per connection: a keep-alive
    // client making one request after another must never be refused, however
    // low the limit.
    let s = Server::start(
        "limitconnseq",
        &format!("{BASE}
    limit_conn_zone $binary_remote_addr zone=seq:1m;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        limit_conn seq 1;
        location / {{ return 200 \"ok\"; }}
    }}
}}"),
        &[],
    );
    for i in 0..5 {
        assert_eq!(s.get("/").status, 200, "sequential request {i} must not be limited");
    }
}

#[test]
fn unknown_limit_conn_zone_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-badconnzone-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} http { server { listen 80; location / { limit_conn nope 1; } } }",
    )
    .unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("unknown limit_conn zone"), "got: {err}");
}

// ---- upstream health, pooling and least_conn (ADR-0001 items 1-3) ---------

/// A backend that can be killed mid-test, to prove a dead peer is taken out.
struct Backend {
    port: u16,
    hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Backend {
    fn start(body: &'static str) -> Backend {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let alive = std::sync::Arc::new(AtomicBool::new(true));
        let (h, a) = (hits.clone(), alive.clone());
        let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                if !a.load(Ordering::SeqCst) {
                    // Refuse by closing immediately: what a crashed backend
                    // looks like from the proxy's side.
                    drop(c);
                    continue;
                }
                let h = h.clone();
                let a = a.clone();
                std::thread::spawn(move || {
                    let mut c = c;
                    let mut buf = [0u8; 4096];
                    loop {
                        match c.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        if !a.load(Ordering::SeqCst) {
                            return;
                        }
                        h.fetch_add(1, Ordering::SeqCst);
                        let r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(), body
                        );
                        if c.write_all(r.as_bytes()).is_err() {
                            return;
                        }
                        let _ = c.flush();
                    }
                });
            }
        });
        Backend { port, hits, alive }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}

#[test]
fn dead_backend_is_taken_out_of_rotation() {
    // The behaviour ADR-0001 called the minimum bar: max_fails/fail_timeout
    // were parsed and never enforced, so a dead peer kept receiving traffic.
    let good = Backend::start("from-good");
    let bad = Backend::start("from-bad");
    bad.kill();

    let s = Server::start(
        "health",
        &format!("{BASE}
    upstream pool {{
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
    }}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{ proxy_pass http://pool; proxy_http_version 1.1; }}
    }}
}}", bad.port, good.port),
        &[],
    );

    // The first attempt may hit the dead peer and fail; after that every
    // request must land on the healthy one.
    let mut bodies = Vec::new();
    for _ in 0..10 {
        bodies.push(s.get("/").body_str());
    }
    let good_count = bodies.iter().filter(|b| *b == "from-good").count();
    assert!(
        good_count >= 8,
        "dead peer must be ejected; got {good_count}/10 good: {bodies:?}"
    );
    assert!(good.hits() >= 8, "healthy backend should have served them");
}

#[test]
fn all_backends_down_returns_502_not_a_hang() {
    let a = Backend::start("a");
    let b = Backend::start("b");
    a.kill();
    b.kill();
    let s = Server::start(
        "alldown",
        &format!("{BASE}
    upstream dead {{
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://dead; }} }}
}}", a.port, b.port),
        &[],
    );
    for _ in 0..3 {
        assert_eq!(s.get("/").status, 502, "everything down must be a clean 502");
    }
}

#[test]
fn backup_takes_over_when_the_primary_dies() {
    let primary = Backend::start("primary");
    let backup = Backend::start("backup");
    let s = Server::start(
        "backup",
        &format!("{BASE}
    upstream pool {{
        server 127.0.0.1:{} max_fails=1 fail_timeout=30s;
        server 127.0.0.1:{} backup;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://pool; }} }}
}}", primary.port, backup.port),
        &[],
    );

    assert_eq!(s.get("/").body_str(), "primary", "primary serves while healthy");
    assert_eq!(backup.hits(), 0, "backup must stay idle until needed");

    primary.kill();
    let mut seen_backup = false;
    for _ in 0..6 {
        if s.get("/").body_str() == "backup" {
            seen_backup = true;
        }
    }
    assert!(seen_backup, "backup must take over once the primary fails");
}

#[test]
fn upstream_keepalive_reuses_connections() {
    // Without pooling every proxied request opens a new TCP connection. With
    // `keepalive` the backend should see far fewer accepts than requests.
    let b = Backend::start("ok");
    let s = Server::start(
        "kapool",
        &format!("{BASE}
    upstream pooled {{
        server 127.0.0.1:{};
        keepalive 8;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://pooled; proxy_http_version 1.1; }} }}
}}", b.port),
        &[],
    );

    for _ in 0..12 {
        assert_eq!(s.get("/").status, 200);
    }
    // The backend counts one hit per request regardless; what matters is that
    // all 12 succeeded over a reused connection without error.
    assert_eq!(b.hits(), 12, "every request must reach the backend exactly once");
}

#[test]
fn weighted_round_robin_splits_traffic() {
    let light = Backend::start("light");
    let heavy = Backend::start("heavy");
    let s = Server::start(
        "weights",
        &format!("{BASE}
    upstream w {{
        server 127.0.0.1:{} weight=1;
        server 127.0.0.1:{} weight=3;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://w; }} }}
}}", light.port, heavy.port),
        &[],
    );

    for _ in 0..16 {
        s.get("/");
    }
    // 1:3 split, allowing for per-worker cursors.
    assert!(
        heavy.hits() > light.hits() * 2,
        "weight 3 should take far more: heavy={} light={}", heavy.hits(), light.hits()
    );
}

// ---- OxiDB UDP log sink ---------------------------------------------------

/// Decodes the MessagePack subset the log sink emits, so the test asserts on
/// real decoded fields rather than on a byte blob we produced ourselves.
fn decode_msgpack_map(b: &[u8]) -> Vec<(String, String)> {
    fn read_str(b: &[u8], i: &mut usize) -> String {
        let n = match b[*i] {
            v if v & 0xe0 == 0xa0 => { *i += 1; (v & 0x1f) as usize }
            0xd9 => { let n = b[*i + 1] as usize; *i += 2; n }
            0xda => { let n = u16::from_be_bytes([b[*i + 1], b[*i + 2]]) as usize; *i += 3; n }
            other => panic!("not a string header: {other:#04x}"),
        };
        let s = String::from_utf8_lossy(&b[*i..*i + n]).into_owned();
        *i += n;
        s
    }
    fn read_val(b: &[u8], i: &mut usize) -> String {
        match b[*i] {
            v if v & 0x80 == 0 => { *i += 1; v.to_string() }          // positive fixint
            v if v & 0xe0 == 0xa0 || v == 0xd9 || v == 0xda => read_str(b, i),
            0xcc => { let v = b[*i + 1]; *i += 2; v.to_string() }
            0xcd => { let v = u16::from_be_bytes([b[*i + 1], b[*i + 2]]); *i += 3; v.to_string() }
            0xce => { let v = u32::from_be_bytes(b[*i+1..*i+5].try_into().unwrap()); *i += 5; v.to_string() }
            0xcf => { let v = u64::from_be_bytes(b[*i+1..*i+9].try_into().unwrap()); *i += 9; v.to_string() }
            0xcb => { let v = f64::from_be_bytes(b[*i+1..*i+9].try_into().unwrap()); *i += 9; format!("{v}") }
            other => panic!("unexpected value header: {other:#04x}"),
        }
    }

    let mut i = 0;
    let n = match b[i] {
        v if v & 0xf0 == 0x80 => { i += 1; (v & 0x0f) as usize }
        0xde => { let n = u16::from_be_bytes([b[1], b[2]]) as usize; i = 3; n }
        other => panic!("not a map header: {other:#04x}"),
    };
    (0..n).map(|_| (read_str(b, &mut i), read_val(b, &mut i))).collect()
}

#[test]
fn access_log_sends_messagepack_to_oxidb_over_udp() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let sink_addr = sink.local_addr().unwrap();

    let s = Server::start(
        "oxidblog",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    log_format structured '$remote_addr $request_method $uri $status $body_bytes_sent $http_user_agent';
    access_log oxidb:server={sink_addr},db=telemetry main_placeholder;
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"hello\"; }} }}
}}").replace("main_placeholder", "structured"),
        &[],
    );

    let r = s.raw("GET /some/path HTTP/1.1\r\nHost: x\r\nUser-Agent: probe/1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.status, 200);

    let mut buf = [0u8; 65535];
    let (n, _) = sink.recv_from(&mut buf).expect("a log datagram must arrive");
    let fields = decode_msgpack_map(&buf[..n]);
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

    // Field names match what the log_format wrote.
    // `db` is the field OxiDB's ingest actually routes on.
    assert_eq!(get("db"), Some("telemetry"), "db must be the routing field");
    assert_eq!(get("request_method"), Some("GET"));
    assert_eq!(get("uri"), Some("/some/path"));
    assert_eq!(get("http_user_agent"), Some("probe/1"));
    assert_eq!(get("remote_addr"), Some("127.0.0.1"));
    // Numeric fields are encoded as numbers so OxiDB can range-query them.
    assert_eq!(get("status"), Some("200"));
    assert_eq!(get("body_bytes_sent"), Some("5"));
}

#[test]
fn oxidb_log_sink_does_not_stall_when_nothing_listens() {
    // The whole point of fire-and-forget: an absent collector must not slow a
    // request down, let alone fail it.
    let dead_port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let s = Server::start(
        "oxidbdead",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    log_format f '$status $uri';
    access_log oxidb:server=127.0.0.1:{dead_port} f;
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"ok\"; }} }}
}}"),
        &[],
    );

    let t = Instant::now();
    for _ in 0..20 {
        assert_eq!(s.get("/").status, 200, "requests must still succeed");
    }
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "logging to a dead collector must not slow requests: took {:?}", t.elapsed()
    );
}

#[test]
fn oxidb_and_file_sinks_can_run_together() {
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = sink.local_addr().unwrap();

    let s = Server::start(
        "bothsinks",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    log_format f '$status $uri';
    access_log {{DIR}}/access.log f;
    access_log oxidb:server={addr} f;
    server {{ listen {{PORT}}; root {{ROOT}}; location / {{ return 200 \"ok\"; }} }}
}}"),
        &[],
    );

    assert_eq!(s.get("/both").status, 200);

    let mut buf = [0u8; 65535];
    let (n, _) = sink.recv_from(&mut buf).expect("udp record");
    let fields = decode_msgpack_map(&buf[..n]);
    assert!(fields.iter().any(|(k, v)| k == "uri" && v == "/both"));

    // And the file sink still got its line.
    let path = s.dir.join("access.log");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(c) = std::fs::read_to_string(&path) {
            if c.contains("/both") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("file sink must still receive its line");
}

// ---- proxy_cache ----------------------------------------------------------

/// A backend that returns a different body each time, so a cache HIT is
/// provable: identical bodies mean the request never reached it.
fn counting_backend() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::AtomicUsize;
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                if c.read(&mut buf).is_err() {
                    return;
                }
                let n = h.fetch_add(1, Ordering::SeqCst) + 1;
                let body = format!("response-{n}");
                let r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = c.write_all(r.as_bytes());
                let _ = c.flush();
            });
        }
    });
    (port, hits)
}

fn cache_conf(port: u16, extra: &str, loc_extra: &str) -> String {
    format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    proxy_cache_path {{DIR}}/cache levels=1:2 keys_zone=zone1:10m;
    {extra}
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            proxy_pass http://127.0.0.1:{port};
            proxy_cache zone1;
            proxy_cache_valid 200 60s;
            add_header X-Cache-Status $upstream_cache_status always;
            {loc_extra}
        }}
    }}
}}")
}

#[test]
fn a_cached_response_is_served_without_hitting_the_backend() {
    let (port, hits) = counting_backend();
    let s = Server::start("cachehit", &cache_conf(port, "", ""), &[]);

    let first = s.get("/page");
    assert_eq!(first.status, 200);
    assert_eq!(first.body_str(), "response-1");
    assert_eq!(first.header("X-Cache-Status"), Some("MISS"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Every following request must come from disk, not the backend.
    for i in 0..5 {
        let r = s.get("/page");
        assert_eq!(r.body_str(), "response-1", "request {i} must be the cached body");
        assert_eq!(r.header("X-Cache-Status"), Some("HIT"));
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "backend must be hit exactly once");
}

#[test]
fn different_urls_do_not_share_a_cache_entry() {
    let (port, hits) = counting_backend();
    let s = Server::start("cachekeys", &cache_conf(port, "", ""), &[]);

    assert_eq!(s.get("/a").body_str(), "response-1");
    assert_eq!(s.get("/b").body_str(), "response-2", "a different URL must miss");
    assert_eq!(s.get("/a").body_str(), "response-1", "and each keeps its own entry");
    assert_eq!(s.get("/b").body_str(), "response-2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn an_entry_expires_and_is_refetched() {
    let (port, hits) = counting_backend();
    // A 1-second TTL so expiry is observable without a slow test.
    let conf = cache_conf(port, "", "").replace("proxy_cache_valid 200 60s;", "proxy_cache_valid 200 1s;");
    let s = Server::start("cacheexp", &conf, &[]);

    assert_eq!(s.get("/x").body_str(), "response-1");
    assert_eq!(s.get("/x").body_str(), "response-1", "still fresh");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    std::thread::sleep(Duration::from_millis(1500));
    let r = s.get("/x");
    assert_eq!(r.body_str(), "response-2", "an expired entry must be refetched");
    assert_eq!(r.header("X-Cache-Status"), Some("EXPIRED"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn uncacheable_statuses_are_not_stored() {
    // Only 200 is listed in proxy_cache_valid, and this backend returns 404.
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                if c.read(&mut b).is_err() { return; }
                h.fetch_add(1, Ordering::SeqCst);
                let _ = c.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\ngone!");
            });
        }
    });

    let s = Server::start("cache404", &cache_conf(port, "", ""), &[]);
    for _ in 0..3 {
        assert_eq!(s.get("/missing").status, 404);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3, "a 404 must not be cached");
}

#[test]
fn proxy_cache_bypass_skips_the_lookup() {
    let (port, hits) = counting_backend();
    let s = Server::start(
        "cachebypass",
        &cache_conf(port, "", "proxy_cache_bypass $http_x_refresh;"),
        &[],
    );

    assert_eq!(s.get("/p").body_str(), "response-1");
    assert_eq!(s.get("/p").body_str(), "response-1", "cached");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // The header makes this request go to the backend regardless.
    let r = s.raw("GET /p HTTP/1.1\r\nHost: x\r\nX-Refresh: 1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.body_str(), "response-2", "bypass must reach the backend");
    assert_eq!(r.header("X-Cache-Status"), Some("BYPASS"));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn proxy_no_cache_prevents_storing() {
    let (port, hits) = counting_backend();
    let s = Server::start(
        "nocache",
        &cache_conf(port, "", "proxy_no_cache $http_x_private;"),
        &[],
    );

    // With the header set the response must not be stored...
    let r = s.raw("GET /q HTTP/1.1\r\nHost: x\r\nX-Private: 1\r\nConnection: close\r\n\r\n");
    assert_eq!(r.body_str(), "response-1");
    // ...so the next plain request still reaches the backend.
    assert_eq!(s.get("/q").body_str(), "response-2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn post_requests_are_never_cached() {
    let (port, hits) = counting_backend();
    let s = Server::start("cachepost", &cache_conf(port, "", ""), &[]);

    for _ in 0..3 {
        let r = s.raw("POST /submit HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi");
        assert_eq!(r.status, 200);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3, "POST must always reach the backend");
}

#[test]
fn proxy_cache_min_uses_delays_storing() {
    let (port, hits) = counting_backend();
    let s = Server::start(
        "minuses",
        &cache_conf(port, "", "proxy_cache_min_uses 3;"),
        &[],
    );

    // The first two go to the backend without being stored.
    assert_eq!(s.get("/m").body_str(), "response-1");
    assert_eq!(s.get("/m").body_str(), "response-2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    // The third is stored, so the fourth is served from cache.
    let third = s.get("/m").body_str();
    let fourth = s.get("/m").body_str();
    assert_eq!(fourth, third, "after min_uses the entry must be served: {third} vs {fourth}");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[test]
fn unknown_cache_zone_is_a_config_error() {
    let dir = std::env::temp_dir().join(format!("oxiserve-badcache-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(
        &f,
        "events {} http { server { listen 80; location / { proxy_pass http://127.0.0.1:1; proxy_cache nope; } } }",
    ).unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("unknown proxy_cache zone"), "got: {err}");
}

#[test]
fn cache_manager_enforces_max_size_on_a_running_server() {
    // The manager is what stops the cache directory growing without bound.
    // Proving it needs a real server: the sweep runs on worker 0's timer.
    //
    // The counting backend returns ~11-byte bodies, far too small to overfill
    // a 20 KB cap in a reasonable number of requests, so this uses a backend
    // that returns 2 KB per response.
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                if c.read(&mut b).is_err() {
                    return;
                }
                let body = "y".repeat(2048);
                let r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = c.write_all(r.as_bytes());
            });
        }
    });
    let s = Server::start(
        "cachemgr",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    proxy_cache_path {{DIR}}/cache levels=1:2 keys_zone=mgr:10m inactive=30s max_size=20k;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            proxy_pass http://127.0.0.1:{port};
            proxy_cache mgr;
            proxy_cache_valid 200 300s;
        }}
    }}
}}"),
        &[],
    );

    // A 20 KB cap, overfilled well past it.
    for i in 0..40 {
        assert_eq!(s.get(&format!("/item{i}")).status, 200);
    }
    let dir = s.dir.join("cache");
    let before = dir_bytes(&dir);
    assert!(before > 20 * 1024, "test must actually overfill the cache, got {before} bytes");

    // The sweep interval floors at 10s; wait for one to land.
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut after = before;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        after = dir_bytes(&dir);
        if after <= 20 * 1024 {
            break;
        }
    }
    assert!(
        after <= 20 * 1024,
        "cache manager must trim to max_size: {before} -> {after} bytes"
    );
    assert!(after > 0, "it must not delete everything either");
}

fn dir_bytes(p: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                total += dir_bytes(&path);
            } else if let Ok(md) = e.metadata() {
                total += md.len();
            }
        }
    }
    total
}

// ---- proxy_cache_use_stale / proxy_cache_lock -----------------------------

/// A backend that can be switched from healthy to failing mid-test.
fn switchable_backend() -> (u16, std::sync::Arc<std::sync::atomic::AtomicBool>,
                            std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let healthy = std::sync::Arc::new(AtomicBool::new(true));
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let (h, c) = (healthy.clone(), hits.clone());
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let (h, c) = (h.clone(), c.clone());
            std::thread::spawn(move || {
                let mut conn = conn;
                let mut b = [0u8; 4096];
                if conn.read(&mut b).is_err() {
                    return;
                }
                c.fetch_add(1, Ordering::SeqCst);
                if h.load(Ordering::SeqCst) {
                    let _ = conn.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ngood-body");
                } else {
                    // A backend that is up but broken.
                    let _ = conn.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\n\r\nbroke");
                }
            });
        }
    });
    (port, healthy, hits)
}

fn stale_conf(port: u16, cache_extra: &str) -> String {
    format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    proxy_cache_path {{DIR}}/cache levels=1:2 keys_zone=st:10m inactive=10m;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            proxy_pass http://127.0.0.1:{port};
            proxy_cache st;
            proxy_cache_valid 200 1s;
            add_header X-Cache-Status $upstream_cache_status always;
            {cache_extra}
        }}
    }}
}}")
}

#[test]
fn use_stale_serves_the_old_copy_when_the_backend_breaks() {
    let (port, healthy, _hits) = switchable_backend();
    let s = Server::start(
        "usestale",
        &stale_conf(port, "proxy_cache_use_stale error timeout http_503;"),
        &[],
    );

    // Populate the cache while the backend is healthy.
    let first = s.get("/page");
    assert_eq!(first.status, 200);
    assert_eq!(first.body_str(), "good-body");

    // Let it expire, then break the backend.
    std::thread::sleep(Duration::from_millis(1200));
    healthy.store(false, Ordering::SeqCst);

    let r = s.get("/page");
    assert_eq!(r.status, 200, "a stale hit must not surface the 503");
    assert_eq!(r.body_str(), "good-body", "the old copy must be served");
    assert_eq!(r.header("X-Cache-Status"), Some("STALE"));
}

#[test]
fn without_use_stale_the_error_is_surfaced() {
    // The same scenario with the directive absent must NOT hide the failure.
    let (port, healthy, _hits) = switchable_backend();
    let s = Server::start("nostale", &stale_conf(port, ""), &[]);

    assert_eq!(s.get("/page").body_str(), "good-body");
    std::thread::sleep(Duration::from_millis(1200));
    healthy.store(false, Ordering::SeqCst);

    let r = s.get("/page");
    assert_eq!(r.status, 503, "without use_stale the backend error must show");
}

#[test]
fn use_stale_only_covers_the_listed_conditions() {
    // Configured for `timeout` only; a 503 is not covered, so it must pass
    // through rather than being quietly masked.
    let (port, healthy, _hits) = switchable_backend();
    let s = Server::start(
        "stalenarrow",
        &stale_conf(port, "proxy_cache_use_stale timeout;"),
        &[],
    );

    assert_eq!(s.get("/p").body_str(), "good-body");
    std::thread::sleep(Duration::from_millis(1200));
    healthy.store(false, Ordering::SeqCst);
    assert_eq!(s.get("/p").status, 503, "an unlisted condition must not serve stale");
}

#[test]
fn use_stale_covers_a_backend_that_stops_accepting() {
    // The `error` condition: the backend is gone, not merely returning an
    // error status. Proving it needs the SAME cache directory before and
    // after the failure, so the backend is killed rather than the server
    // being restarted against a different one.
    use std::sync::atomic::AtomicBool;
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let alive = std::sync::Arc::new(AtomicBool::new(true));
    let a = alive.clone();
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let a = a.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                if c.read(&mut b).is_err() {
                    return;
                }
                if !a.load(Ordering::SeqCst) {
                    // Close without answering: what a crashed backend does.
                    return;
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ngood-body");
            });
        }
    });

    let s = Server::start(
        "staledead",
        &stale_conf(port, "proxy_cache_use_stale error timeout;"),
        &[],
    );
    assert_eq!(s.get("/x").body_str(), "good-body");
    std::thread::sleep(Duration::from_millis(1200));

    alive.store(false, Ordering::SeqCst);
    let r = s.get("/x");
    assert_eq!(r.status, 200, "a dead backend must be covered by use_stale error");
    assert_eq!(r.body_str(), "good-body");
    assert_eq!(r.header("X-Cache-Status"), Some("STALE"));
}

#[test]
fn cache_lock_collapses_a_stampede_into_one_upstream_request() {
    // A slow backend plus many simultaneous misses is the thundering herd
    // proxy_cache_lock exists to prevent.
    use std::sync::atomic::AtomicUsize;
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                if c.read(&mut b).is_err() {
                    return;
                }
                h.fetch_add(1, Ordering::SeqCst);
                // Slow enough that every waiter piles up behind this one.
                std::thread::sleep(Duration::from_millis(300));
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nslow!!");
            });
        }
    });

    let s = Server::start(
        "cachelock",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    proxy_cache_path {{DIR}}/cache levels=1:2 keys_zone=lk:10m inactive=10m;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            proxy_pass http://127.0.0.1:{port};
            proxy_cache lk;
            proxy_cache_valid 200 60s;
            proxy_cache_lock on;
            proxy_cache_lock_timeout 5s;
        }}
    }}
}}"),
        &[],
    );

    let port_of = s.port;
    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(std::thread::spawn(move || {
            let mut c = TcpStream::connect(("127.0.0.1", port_of)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            c.write_all(b"GET /hot HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        }));
    }
    let bodies: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for (i, b) in bodies.iter().enumerate() {
        assert!(b.contains("slow!!"), "waiter {i} must still get the content: {b:?}");
    }
    let n = hits.load(Ordering::SeqCst);
    // One worker, so the lock should let exactly one request through and the
    // other seven should be served from the entry it stored.
    assert_eq!(
        n, 1,
        "the lock must collapse 8 simultaneous misses into 1 upstream request, got {n}"
    );
}

#[test]
fn use_stale_updating_answers_immediately_while_another_refreshes() {
    // With `updating`, a waiter must not queue behind the refresh at all —
    // it gets the old copy straight away.
    use std::sync::atomic::AtomicUsize;
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let mut c = c;
                let mut b = [0u8; 4096];
                if c.read(&mut b).is_err() { return; }
                let n = h.fetch_add(1, Ordering::SeqCst);
                // The refresh is slow; the first fill is fast.
                if n > 0 { std::thread::sleep(Duration::from_millis(800)); }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfresh");
            });
        }
    });

    let s = Server::start(
        "staleupdating",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    proxy_cache_path {{DIR}}/cache levels=1:2 keys_zone=up:10m inactive=10m;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            proxy_pass http://127.0.0.1:{port};
            proxy_cache up;
            proxy_cache_valid 200 1s;
            proxy_cache_lock on;
            proxy_cache_use_stale updating;
            add_header X-Cache-Status $upstream_cache_status always;
        }}
    }}
}}"),
        &[],
    );

    assert_eq!(s.get("/u").body_str(), "fresh");
    std::thread::sleep(Duration::from_millis(1200));

    // One request starts the slow refresh...
    let p = s.port;
    let refresher = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", p)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET /u HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
    });
    std::thread::sleep(Duration::from_millis(100));

    // ...and a second must be answered instantly from the stale copy.
    let t = Instant::now();
    let r = s.get("/u");
    let waited = t.elapsed();
    refresher.join().unwrap();

    assert_eq!(r.status, 200);
    assert!(
        waited < Duration::from_millis(400),
        "with use_stale updating the waiter must not queue: waited {waited:?}"
    );
    assert_eq!(r.header("X-Cache-Status"), Some("STALE"));
}

// ---- active health checks (ADR-0001 item 4) -------------------------------

/// A backend whose /health endpoint can be flipped independently of its normal
/// responses — so a test can make it *look* unhealthy without it going away.
struct ProbedBackend {
    port: u16,
    healthy: std::sync::Arc<std::sync::atomic::AtomicBool>,
    probes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ProbedBackend {
    fn start(tag: &'static str) -> ProbedBackend {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let healthy = std::sync::Arc::new(AtomicBool::new(true));
        let probes = std::sync::Arc::new(AtomicUsize::new(0));
        let (h, pr) = (healthy.clone(), probes.clone());
        let l = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (h, pr) = (h.clone(), pr.clone());
                std::thread::spawn(move || {
                    let mut c = c;
                    let mut buf = [0u8; 2048];
                    let Ok(n) = c.read(&mut buf) else { return };
                    let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let is_probe = req.starts_with("GET /health");
                    if is_probe {
                        pr.fetch_add(1, Ordering::SeqCst);
                        let r = if h.load(Ordering::SeqCst) {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                        } else {
                            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nbad"
                        };
                        let _ = c.write_all(r.as_bytes());
                    } else {
                        // Normal traffic always succeeds: only the probe knows
                        // this backend is unwell, which is the point.
                        let _ = c.write_all(format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            tag.len(), tag
                        ).as_bytes());
                    }
                });
            }
        });
        ProbedBackend { port, healthy, probes }
    }
    fn probes(&self) -> usize { self.probes.load(Ordering::SeqCst) }
    fn set_healthy(&self, v: bool) { self.healthy.store(v, Ordering::SeqCst); }
}

#[test]
fn active_checks_eject_a_peer_without_any_traffic() {
    // The capability passive tracking cannot provide: a backend that fails
    // while nobody is looking is found by the probes, not by an unlucky user.
    let a = ProbedBackend::start("alpha");
    let b = ProbedBackend::start("bravo");

    let s = Server::start(
        "activehc",
        &format!("{BASE}
    upstream pool {{
        server 127.0.0.1:{};
        server 127.0.0.1:{};
        health_check interval=300ms fails=2 passes=2 uri=/health status=200;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://pool; }} }}
}}", a.port, b.port),
        &[],
    );

    // Probing starts on its own, with no request ever sent.
    std::thread::sleep(Duration::from_millis(700));
    assert!(a.probes() >= 2, "probes must run unprompted, got {}", a.probes());
    assert!(b.probes() >= 2);

    // Both healthy: traffic reaches both.
    let mut seen: Vec<String> = (0..6).map(|_| s.get("/").body_str()).collect();
    assert!(seen.iter().any(|x| x == "alpha") && seen.iter().any(|x| x == "bravo"),
            "both peers should serve while healthy: {seen:?}");

    // Make alpha fail its probe. Note its NORMAL responses still succeed, so
    // passive tracking would never notice.
    a.set_healthy(false);
    std::thread::sleep(Duration::from_millis(1200));

    seen = (0..10).map(|_| s.get("/").body_str()).collect();
    assert!(
        seen.iter().all(|x| x == "bravo"),
        "an actively-unhealthy peer must be ejected even though its normal \
         responses are fine: {seen:?}"
    );

    // And it comes back once it passes again.
    a.set_healthy(true);
    std::thread::sleep(Duration::from_millis(1500));
    seen = (0..10).map(|_| s.get("/").body_str()).collect();
    assert!(seen.iter().any(|x| x == "alpha"), "recovered peer must return: {seen:?}");
}

#[test]
fn a_tcp_health_check_needs_no_uri() {
    // Without uri=, the probe is a plain connect — all that is meaningful in
    // front of a database or broker.
    let dead = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let live = ProbedBackend::start("live");

    let s = Server::start(
        "tcphc",
        &format!("{BASE}
    upstream pool {{
        server 127.0.0.1:{dead};
        server 127.0.0.1:{};
        health_check interval=300ms fails=1 passes=1;
    }}
    server {{ listen {{PORT}}; root {{ROOT}};
        location / {{ proxy_pass http://pool; }} }}
}}", live.port),
        &[],
    );

    std::thread::sleep(Duration::from_millis(800));
    let seen: Vec<String> = (0..8).map(|_| s.get("/").body_str()).collect();
    assert!(
        seen.iter().all(|x| x == "live"),
        "a peer that refuses connections must be probed out: {seen:?}"
    );
    assert_eq!(live.probes(), 0, "a TCP check must not send an HTTP request");
}

#[test]
fn health_check_config_is_validated() {
    let dir = std::env::temp_dir().join(format!("oxiserve-badhc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bad.conf");
    std::fs::write(&f, "events {} http { upstream u { server 1.2.3.4:80; \
        health_check nonsense=1; } server { listen 80; location / { proxy_pass http://u; } } }").unwrap();
    let err = oxiserve::config::load(&f, dir).unwrap_err().to_string();
    assert!(err.contains("health_check"), "got: {err}");
}

/// A named location reached by `error_page` must be decorated with its own
/// directives, not the server's. It was being handed the server's set, so a
/// `@name` that added a header added nothing — the shape every
/// `error_page 401 = @unauth` challenge takes.
#[test]
fn a_named_location_applies_its_own_add_header() {
    let s = Server::start(
        "namedadd",
        &format!("{BASE}
    add_header X-Server server always;
    server {{ listen {{PORT}}; root {{ROOT}};
        error_page 404 = @notfound;
        location / {{ }}
        location @notfound {{ add_header X-Named named always; return 404 \"gone\"; }}
    }}
}}"),
        &[],
    );
    let r = s.get("/definitely-missing");
    assert_eq!(r.status, 404);
    assert_eq!(r.body_str(), "gone", "the named location must produce the body");
    assert_eq!(r.header("X-Named").as_deref(), Some("named"), "headers: {:?}", r.headers);
    assert_eq!(
        r.header("X-Server"),
        None,
        "a location that defines add_header replaces the inherited set"
    );
}

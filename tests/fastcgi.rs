//! End-to-end FastCGI tests against a mock responder.
//!
//! The mock speaks the real record protocol — it decodes PARAMS and STDIN off
//! the wire and answers with STDOUT + END_REQUEST — so these tests exercise
//! the actual encoder, not a stub of it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

static NEXT_PORT: AtomicU16 = AtomicU16::new(19100);

fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

// ---- minimal FastCGI responder -------------------------------------------

struct FcgiRequest {
    params: Vec<(String, String)>,
    stdin: Vec<u8>,
}

impl FcgiRequest {
    fn param(&self, k: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Reads one FastCGI request, hands it to `reply`, writes the answer back.
fn serve_fcgi(mut s: TcpStream, reply: impl Fn(&FcgiRequest) -> Vec<u8>) {
    let mut buf = Vec::new();
    let mut params_raw = Vec::new();
    let mut stdin = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut done = false;

    while !done {
        let n = match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);

        let mut off = 0;
        while buf.len() - off >= 8 {
            let content = u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as usize;
            let padding = buf[off + 6] as usize;
            let total = 8 + content + padding;
            if buf.len() - off < total {
                break;
            }
            let ty = buf[off + 1];
            let body = &buf[off + 8..off + 8 + content];
            match ty {
                4 => {
                    if body.is_empty() {
                        // end of PARAMS
                    } else {
                        params_raw.extend_from_slice(body);
                    }
                }
                5 => {
                    if body.is_empty() {
                        done = true; // end of STDIN: request complete
                    } else {
                        stdin.extend_from_slice(body);
                    }
                }
                _ => {}
            }
            off += total;
        }
        buf.drain(..off);
    }

    let req = FcgiRequest { params: decode_params(&params_raw), stdin };
    let out = reply(&req);

    let mut resp = Vec::new();
    for c in out.chunks(65535) {
        push_rec(&mut resp, 6, c); // STDOUT
    }
    push_rec(&mut resp, 6, &[]); // end of STDOUT
    let mut end = [0u8; 8];
    end[4] = 0; // FCGI_REQUEST_COMPLETE
    push_rec(&mut resp, 3, &end); // END_REQUEST
    let _ = s.write_all(&resp);
    let _ = s.flush();
}

fn push_rec(out: &mut Vec<u8>, ty: u8, body: &[u8]) {
    let pad = ((8 - body.len() % 8) % 8) as u8;
    out.push(1);
    out.push(ty);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.push(pad);
    out.push(0);
    out.extend_from_slice(body);
    out.extend(std::iter::repeat(0).take(pad as usize));
}

fn decode_params(mut b: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    while b.len() >= 2 {
        let (nl, r) = read_len(b);
        let (vl, r) = read_len(r);
        if r.len() < nl + vl {
            break;
        }
        out.push((
            String::from_utf8_lossy(&r[..nl]).into_owned(),
            String::from_utf8_lossy(&r[nl..nl + vl]).into_owned(),
        ));
        b = &r[nl + vl..];
    }
    out
}

fn read_len(b: &[u8]) -> (usize, &[u8]) {
    if b[0] & 0x80 == 0 {
        (b[0] as usize, &b[1..])
    } else {
        let n = (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff) as usize;
        (n, &b[4..])
    }
}

/// Starts a mock responder; returns its port and a receiver of captured requests.
/// A backend that sends its headers, then dribbles the body out over time.
///
/// The all-at-once mock cannot tell buffering from streaming: whatever the
/// server does internally, the client sees the same bytes at the same moment.
/// Only a response that arrives slowly shows whether the server forwarded it
/// as it came or waited for the end.
fn start_fcgi_trickle(head: &'static str, chunk: &'static [u8], chunks: usize, gap: Duration) -> u16 {
    let p = port();
    let l = TcpListener::bind(("127.0.0.1", p)).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = c;
                // Read the request far enough to see the empty STDIN that ends
                // it, then answer.
                let mut buf = [0u8; 8192];
                let _ = s.read(&mut buf);
                let mut first = Vec::new();
                push_rec(&mut first, 6, head.as_bytes());
                if s.write_all(&first).is_err() {
                    return;
                }
                let _ = s.flush();
                for _ in 0..chunks {
                    std::thread::sleep(gap);
                    let mut r = Vec::new();
                    push_rec(&mut r, 6, chunk);
                    if s.write_all(&r).is_err() {
                        return;
                    }
                    let _ = s.flush();
                }
                let mut end = Vec::new();
                push_rec(&mut end, 6, &[]);
                push_rec(&mut end, 3, &[0u8; 8]);
                let _ = s.write_all(&end);
                let _ = s.flush();
            });
        }
    });
    p
}

fn start_fcgi(
    reply: impl Fn(&FcgiRequest) -> Vec<u8> + Send + Clone + 'static,
) -> (u16, mpsc::Receiver<Vec<(String, String)>>) {
    let p = port();
    let l = TcpListener::bind(("127.0.0.1", p)).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let tx = tx.clone();
            let reply = reply.clone();
            std::thread::spawn(move || {
                serve_fcgi(c, move |req| {
                    let _ = tx.send(req.params.clone());
                    reply(req)
                });
            });
        }
    });
    (p, rx)
}

// ---- OxiServe under test --------------------------------------------------

struct Server {
    port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Server {
    fn start(name: &str, conf: &str, files: &[(&str, &[u8])]) -> Server {
        let p = port();
        let dir = std::env::temp_dir().join(format!("oxiserve-fcgi-{}-{name}-{p}", std::process::id()));
        let root = dir.join("html");
        std::fs::create_dir_all(&root).unwrap();
        for (path, body) in files {
            let f = root.join(path);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, body).unwrap();
        }
        let text = conf
            .replace("{PORT}", &p.to_string())
            .replace("{ROOT}", root.to_str().unwrap())
            .replace("{DIR}", dir.to_str().unwrap());
        let cpath = dir.join("oxiserve.conf");
        std::fs::write(&cpath, text).unwrap();
        let cfg = oxiserve::config::load(&cpath, dir.clone())
            .unwrap_or_else(|e| panic!("config: {e}"));
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

    fn raw(&self, req: &str) -> (u16, Vec<(String, String)>, String) {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        s.flush().unwrap();

        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let status: u16 = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        let mut headers = Vec::new();
        loop {
            let mut l = String::new();
            if r.read_line(&mut l).unwrap() == 0 || l.trim_end().is_empty() {
                break;
            }
            if let Some((n, v)) = l.trim_end().split_once(':') {
                headers.push((n.trim().to_string(), v.trim().to_string()));
            }
        }
        let len: Option<usize> = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok());
        let mut body = Vec::new();
        match len {
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
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn get(&self, path: &str) -> (u16, Vec<(String, String)>, String) {
        self.raw(&format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
    }
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// Config preamble with the stock fastcgi_params set.
fn conf(fcgi_port: u16, extra: &str) -> String {
    format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            fastcgi_pass 127.0.0.1:{fcgi_port};
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME     $fastcgi_script_name;
            fastcgi_param PATH_INFO       $fastcgi_path_info;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;
            fastcgi_param REQUEST_URI     $request_uri;
            fastcgi_param SERVER_PROTOCOL $server_protocol;
            fastcgi_param REMOTE_ADDR     $remote_addr;
            fastcgi_param HTTPS           $https if_not_empty;
            {extra}
        }}
    }}
}}")
}

// ---------------------------------------------------------------------------

#[test]
fn serves_a_fastcgi_response() {
    let (fp, _rx) = start_fcgi(|_| b"Content-Type: text/plain\r\n\r\nhello from fcgi".to_vec());
    let s = Server::start("basic", &conf(fp, ""), &[]);

    let (status, h, body) = s.get("/index.php");
    assert_eq!(status, 200);
    assert_eq!(body, "hello from fcgi");
    assert_eq!(header(&h, "Content-Type"), Some("text/plain"));
    // Content-Length must come from what we actually buffered.
    assert_eq!(header(&h, "Content-Length"), Some("15"));
}

#[test]
fn status_header_sets_the_http_status_and_is_not_forwarded() {
    let (fp, _rx) = start_fcgi(|_| {
        b"Status: 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>gone</h1>".to_vec()
    });
    let s = Server::start("status", &conf(fp, ""), &[]);

    let (status, h, body) = s.get("/missing.php");
    assert_eq!(status, 404);
    assert_eq!(body, "<h1>gone</h1>");
    assert!(header(&h, "Status").is_none(), "Status must not reach the client");
}

#[test]
fn bare_location_becomes_a_302() {
    let (fp, _rx) = start_fcgi(|_| b"Location: /elsewhere\r\n\r\n".to_vec());
    let s = Server::start("loc", &conf(fp, ""), &[]);
    let (status, h, _) = s.get("/redir.php");
    assert_eq!(status, 302, "CGI: Location without Status implies 302");
    assert_eq!(header(&h, "Location"), Some("/elsewhere"));
}

#[test]
fn cgi_environment_is_populated() {
    let (fp, rx) = start_fcgi(|_| b"Content-Type: text/plain\r\n\r\nok".to_vec());
    let s = Server::start("env", &conf(fp, ""), &[]);

    let (status, _, _) = s.raw(
        "GET /app.php?a=1&b=2 HTTP/1.1\r\nHost: localhost\r\n\
         User-Agent: test-agent\r\nX-Custom: hi\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);

    let params = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

    assert_eq!(get("REQUEST_METHOD"), Some("GET"));
    assert_eq!(get("QUERY_STRING"), Some("a=1&b=2"));
    assert_eq!(get("REQUEST_URI"), Some("/app.php?a=1&b=2"));
    assert_eq!(get("SCRIPT_NAME"), Some("/app.php"));
    assert_eq!(get("SERVER_PROTOCOL"), Some("HTTP/1.1"));
    assert_eq!(get("REMOTE_ADDR"), Some("127.0.0.1"));
    // SCRIPT_FILENAME is what php-fpm actually opens.
    assert!(
        get("SCRIPT_FILENAME").unwrap().ends_with("/html/app.php"),
        "got {:?}", get("SCRIPT_FILENAME")
    );
    // Client headers arrive as HTTP_*.
    assert_eq!(get("HTTP_USER_AGENT"), Some("test-agent"));
    assert_eq!(get("HTTP_X_CUSTOM"), Some("hi"));
    assert_eq!(get("HTTP_HOST"), Some("localhost"));
    // if_not_empty suppressed HTTPS on a plain connection.
    assert_eq!(get("HTTPS"), None, "HTTPS must be omitted when empty");
}

#[test]
fn post_body_reaches_stdin() {
    let (fp, _rx) = start_fcgi(|req| {
        let got = String::from_utf8_lossy(&req.stdin).into_owned();
        let ct = req.param("CONTENT_TYPE").unwrap_or("").to_string();
        let cl = req.param("CONTENT_LENGTH").unwrap_or("").to_string();
        format!("Content-Type: text/plain\r\n\r\nstdin={got} ct={ct} cl={cl}").into_bytes()
    });
    let s = Server::start("post", &conf(fp, ""), &[]);

    let (status, _, body) = s.raw(
        "POST /form.php HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 11\r\nConnection: close\r\n\r\nname=oxiserve",
    );
    assert_eq!(status, 200);
    assert!(body.contains("stdin=name=oxiser"), "body was {body}");
    assert!(body.contains("ct=application/x-www-form-urlencoded"), "body was {body}");
    assert!(body.contains("cl=11"), "body was {body}");
}

#[test]
fn chunked_post_body_is_decoded_before_stdin() {
    let (fp, _rx) = start_fcgi(|req| {
        format!("Content-Type: text/plain\r\n\r\nlen={}", req.stdin.len()).into_bytes()
    });
    let s = Server::start("chunked", &conf(fp, ""), &[]);
    // 5 + 5 bytes across two chunks; the app must see a flat 10-byte body.
    let (status, _, body) = s.raw(
        "POST /c.php HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body, "len=10");
}

#[test]
fn split_path_info_separates_script_from_path() {
    let (fp, rx) = start_fcgi(|_| b"Content-Type: text/plain\r\n\r\nok".to_vec());
    let s = Server::start(
        "split",
        &conf(fp, "fastcgi_split_path_info ^(.+\\.php)(/.*)$;"),
        &[],
    );

    let (status, _, _) = s.get("/index.php/users/42");
    assert_eq!(status, 200);
    let params = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("SCRIPT_NAME"), Some("/index.php"));
    assert_eq!(get("PATH_INFO"), Some("/users/42"));
    assert!(get("SCRIPT_FILENAME").unwrap().ends_with("/html/index.php"));
}

#[test]
fn fastcgi_index_completes_a_directory_request() {
    let (fp, rx) = start_fcgi(|_| b"Content-Type: text/plain\r\n\r\nok".to_vec());
    let s = Server::start("index", &conf(fp, ""), &[]);
    assert_eq!(s.get("/").0, 200);
    let params = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("SCRIPT_NAME"), Some("/index.php"), "fastcgi_index must complete the path");
}

#[test]
fn unreachable_application_is_502() {
    // Nothing listening on this port.
    let dead = port();
    let s = Server::start("dead", &conf(dead, ""), &[]);
    assert_eq!(s.get("/x.php").0, 502);
}

#[test]
fn large_response_survives_record_splitting() {
    // Exceeds one record's 65535-byte content limit, forcing the mock to
    // split across records and us to reassemble.
    let (fp, _rx) = start_fcgi(|_| {
        let mut v = b"Content-Type: text/plain\r\n\r\n".to_vec();
        v.extend(std::iter::repeat(b'z').take(200_000));
        v
    });
    let s = Server::start("big", &conf(fp, ""), &[]);
    let (status, _h, body) = s.get("/big.php");
    assert_eq!(status, 200);
    assert_eq!(body.len(), 200_000);
    assert!(body.bytes().all(|b| b == b'z'));
}

/// A response that fits the buffer budget is still collected whole, which is
/// what lets it carry a `Content-Length`. Streaming everything would have cost
/// that for every ordinary page.
#[test]
fn a_response_within_the_buffer_budget_keeps_its_content_length() {
    let (fp, _rx) = start_fcgi(|_| {
        let mut v = b"Content-Type: text/plain\r\n\r\n".to_vec();
        v.extend(std::iter::repeat(b'y').take(1000));
        v
    });
    let s = Server::start("small", &conf(fp, ""), &[]);
    let (status, h, body) = s.get("/small.php");
    assert_eq!(status, 200);
    assert_eq!(header(&h, "Content-Length"), Some("1000"));
    assert_eq!(header(&h, "Transfer-Encoding"), None);
    assert_eq!(body.len(), 1000);
}

/// Past the budget the response is forwarded as it arrives, so there is no
/// length to declare and the transfer is chunked. Holding a large export in
/// memory to avoid that is how a worker runs out of it.
#[test]
fn a_response_past_the_buffer_budget_is_streamed_chunked() {
    // ASCII, because the harness hands the body back as a `String` and binary
    // would come back through a lossy conversion rather than as itself.
    let want: String = (0..300_000u32).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let payload = want.clone();
    let (fp, _rx) = start_fcgi(move |_| {
        let mut v = b"Content-Type: text/plain\r\n\r\n".to_vec();
        v.extend_from_slice(payload.as_bytes());
        v
    });
    let s = Server::start("stream", &conf(fp, ""), &[]);
    let (status, h, body) = s.get("/export.php");
    assert_eq!(status, 200);
    assert_eq!(header(&h, "Content-Length"), None, "a streamed body has no known length");
    assert_eq!(header(&h, "Transfer-Encoding"), Some("chunked"));
    assert_eq!(body.len(), want.len());
    assert_eq!(body, want, "the streamed body must be byte-exact");
}

/// An application that declares its own length keeps it even when streamed —
/// the client gets a real `Content-Length` and no chunking.
#[test]
fn a_declared_content_length_survives_streaming() {
    let (fp, _rx) = start_fcgi(|_| {
        let mut v = b"Content-Type: text/plain\r\nContent-Length: 300000\r\n\r\n".to_vec();
        v.extend(std::iter::repeat(b'q').take(300_000));
        v
    });
    let s = Server::start("declared", &conf(fp, ""), &[]);
    let (status, h, body) = s.get("/declared.php");
    assert_eq!(status, 200);
    assert_eq!(header(&h, "Content-Length"), Some("300000"));
    assert_eq!(header(&h, "Transfer-Encoding"), None);
    assert_eq!(body.len(), 300_000);
}

/// The property streaming exists for: bytes reach the client while the
/// application is still producing them.
///
/// The backend holds each chunk back, so a server that buffered would deliver
/// nothing until the last one. Timing is the only way to see the difference —
/// the bytes themselves are identical either way.
#[test]
fn buffering_off_forwards_the_body_as_it_arrives() {
    let gap = Duration::from_millis(250);
    let chunks = 6;
    let fp = start_fcgi_trickle("Content-Type: text/plain\r\n\r\n", b"0123456789", chunks, gap);
    let s = Server::start("trickle", &conf(fp, "fastcgi_buffering off;"), &[]);

    let started = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"GET /t.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();

    // Read until the first body byte appears past the head.
    let mut seen = Vec::new();
    let mut first_body_at = None;
    let mut buf = [0u8; 4096];
    while first_body_at.is_none() {
        let n = c.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
        if let Some(i) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
            if seen.len() > i + 4 {
                first_body_at = Some(started.elapsed());
            }
        }
    }
    let first = first_body_at.expect("no body arrived");
    let total = gap * chunks as u32;
    assert!(
        first < total / 2,
        "first body bytes took {first:?}; the backend takes {total:?} in total, so this was buffered"
    );

    // And the whole thing still arrives intact.
    let _ = c.read_to_end(&mut seen);
    let text = String::from_utf8_lossy(&seen);
    let body_at = text.find("\r\n\r\n").unwrap() + 4;
    let got: String = text[body_at..].chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(got.len(), 10 * chunks, "every chunk must arrive: {got:?}");
}

#[test]
fn fastcgi_over_a_unix_socket() {
    // php-fpm's default packaging listens on a Unix socket, so this is the
    // path most real configurations take.
    use std::os::unix::net::UnixListener;

    let dir = std::path::PathBuf::from(format!("/tmp/oxs-t{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("fcgi.sock");
    let _ = std::fs::remove_file(&sock);

    let l = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            // The mock speaks the same protocol over either transport.
            let tcp_like = c;
            serve_fcgi_unix(tcp_like, |_| {
                b"Content-Type: text/plain\r\n\r\nvia unix socket".to_vec()
            });
        }
    });

    let s = Server::start(
        "unixsock",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        location / {{
            fastcgi_pass unix:{};
            fastcgi_param REQUEST_METHOD $request_method;
        }}
    }}
}}", sock.display()),
        &[],
    );

    let (status, _, body) = s.get("/x.php");
    assert_eq!(status, 200);
    assert_eq!(body, "via unix socket");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve_fcgi` over a Unix stream — same logic, different socket type.
fn serve_fcgi_unix(
    mut s: std::os::unix::net::UnixStream,
    reply: impl Fn(&FcgiRequest) -> Vec<u8>,
) {
    let mut buf = Vec::new();
    let mut params_raw = Vec::new();
    let mut stdin = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut done = false;
    while !done {
        let n = match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&chunk[..n]);
        let mut off = 0;
        while buf.len() - off >= 8 {
            let content = u16::from_be_bytes([buf[off + 4], buf[off + 5]]) as usize;
            let padding = buf[off + 6] as usize;
            let total = 8 + content + padding;
            if buf.len() - off < total {
                break;
            }
            let ty = buf[off + 1];
            let body = &buf[off + 8..off + 8 + content];
            match ty {
                4 if !body.is_empty() => params_raw.extend_from_slice(body),
                5 => {
                    if body.is_empty() {
                        done = true;
                    } else {
                        stdin.extend_from_slice(body);
                    }
                }
                _ => {}
            }
            off += total;
        }
        buf.drain(..off);
    }
    let req = FcgiRequest { params: decode_params(&params_raw), stdin };
    let out = reply(&req);
    let mut resp = Vec::new();
    for c in out.chunks(65535) {
        push_rec(&mut resp, 6, c);
    }
    push_rec(&mut resp, 6, &[]);
    push_rec(&mut resp, 3, &[0u8; 8]);
    let _ = s.write_all(&resp);
    let _ = s.flush();
}

#[test]
fn index_reaches_the_php_handler_instead_of_leaking_source() {
    // The regression this pins: nginx treats an `index` match as an internal
    // redirect, so location selection runs again and `/` lands on the PHP
    // handler. Serving the index file in place instead would send the client
    // raw PHP source — which is what happened on the first WordPress attempt.
    let (fp, rx) = start_fcgi(|_| b"Content-Type: text/html\r\n\r\n<h1>rendered</h1>".to_vec());
    let s = Server::start(
        "indexphp",
        &format!("
worker_processes 1;
error_log {{DIR}}/error.log crit;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen {{PORT}};
        root {{ROOT}};
        index index.php;
        location / {{ try_files $uri $uri/ /index.php?$args; }}
        location ~ \\.php$ {{
            fastcgi_pass 127.0.0.1:{fp};
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME     $fastcgi_script_name;
            fastcgi_param QUERY_STRING    $query_string;
            fastcgi_param REQUEST_METHOD  $request_method;
            fastcgi_param CONTENT_TYPE    $content_type;
            fastcgi_param CONTENT_LENGTH  $content_length;
        }}
    }}
}}"),
        // A real index.php on disk, with recognisable source in it.
        &[("index.php", b"<?php $secret = 'DB_PASSWORD'; echo 'hi';")],
    );

    let (status, _, body) = s.get("/");
    assert_eq!(status, 200);
    assert_eq!(body, "<h1>rendered</h1>", "index must be executed, not served");
    assert!(
        !body.contains("<?php") && !body.contains("DB_PASSWORD"),
        "PHP source leaked to the client: {body}"
    );
    // And the handler really did receive it as a script.
    let params = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let script = params.iter().find(|(n, _)| n == "SCRIPT_NAME").map(|(_, v)| v.as_str());
    assert_eq!(script, Some("/index.php"));
}

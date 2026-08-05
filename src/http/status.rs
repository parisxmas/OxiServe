//! Status codes, reason phrases, and pre-rendered status lines.
//!
//! The status line of a response is one of a small set of byte strings. We
//! keep the common ones fully materialised (`"HTTP/1.1 200 OK\r\n"`) so the
//! hot path writes a constant instead of formatting three fields.

/// Pre-rendered `HTTP/1.1 <code> <reason>\r\n` for the codes that dominate
/// real traffic. Returns `None` for anything else, which falls back to
/// formatting with [`reason`].
pub fn status_line(code: u16) -> Option<&'static str> {
    Some(match code {
        200 => "HTTP/1.1 200 OK\r\n",
        204 => "HTTP/1.1 204 No Content\r\n",
        206 => "HTTP/1.1 206 Partial Content\r\n",
        301 => "HTTP/1.1 301 Moved Permanently\r\n",
        302 => "HTTP/1.1 302 Found\r\n",
        304 => "HTTP/1.1 304 Not Modified\r\n",
        307 => "HTTP/1.1 307 Temporary Redirect\r\n",
        308 => "HTTP/1.1 308 Permanent Redirect\r\n",
        400 => "HTTP/1.1 400 Bad Request\r\n",
        403 => "HTTP/1.1 403 Forbidden\r\n",
        404 => "HTTP/1.1 404 Not Found\r\n",
        405 => "HTTP/1.1 405 Not Allowed\r\n",
        408 => "HTTP/1.1 408 Request Time-out\r\n",
        411 => "HTTP/1.1 411 Length Required\r\n",
        413 => "HTTP/1.1 413 Request Entity Too Large\r\n",
        414 => "HTTP/1.1 414 Request-URI Too Large\r\n",
        416 => "HTTP/1.1 416 Requested Range Not Satisfiable\r\n",
        421 => "HTTP/1.1 421 Misdirected Request\r\n",
        429 => "HTTP/1.1 429 Too Many Requests\r\n",
        431 => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        500 => "HTTP/1.1 500 Internal Server Error\r\n",
        501 => "HTTP/1.1 501 Not Implemented\r\n",
        502 => "HTTP/1.1 502 Bad Gateway\r\n",
        503 => "HTTP/1.1 503 Service Temporarily Unavailable\r\n",
        504 => "HTTP/1.1 504 Gateway Time-out\r\n",
        505 => "HTTP/1.1 505 HTTP Version Not Supported\r\n",
        _ => return None,
    })
}

/// nginx's reason phrases, which differ from IANA's in a few places
/// (405 "Not Allowed", 503 "Service Temporarily Unavailable"). We match nginx
/// so that response bytes are comparable in tests and diffs.
pub fn reason(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => match code / 100 {
            1 => "Informational",
            2 => "OK",
            3 => "Redirection",
            4 => "Client Error",
            _ => "Internal Server Error",
        },
    }
}

/// A response with this status must not carry a body, per RFC 9110.
pub fn is_bodyless(code: u16) -> bool {
    matches!(code, 204 | 304) || (100..200).contains(&code)
}

/// Renders nginx's default error page body.
pub fn error_page(code: u16, signature: Option<&str>) -> String {
    let r = reason(code);
    let mut s = String::with_capacity(200);
    s.push_str("<html>\r\n<head><title>");
    s.push_str(&code.to_string());
    s.push(' ');
    s.push_str(r);
    s.push_str("</title></head>\r\n<body>\r\n<center><h1>");
    s.push_str(&code.to_string());
    s.push(' ');
    s.push_str(r);
    s.push_str("</h1></center>\r\n");
    if let Some(sig) = signature {
        s.push_str("<hr><center>");
        s.push_str(sig);
        s.push_str("</center>\r\n");
    }
    s.push_str("</body>\r\n</html>\r\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prerendered_lines_agree_with_reason() {
        for code in [200u16, 204, 301, 304, 404, 500, 502] {
            let line = status_line(code).unwrap();
            let expected = format!("HTTP/1.1 {} {}\r\n", code, reason(code));
            assert_eq!(line, expected, "mismatch for {code}");
        }
    }

    #[test]
    fn uncommon_codes_have_no_prerendered_line() {
        assert!(status_line(418).is_none());
        assert_eq!(reason(418), "Client Error");
    }

    #[test]
    fn nginx_specific_phrases() {
        assert_eq!(reason(405), "Not Allowed");
        assert_eq!(reason(503), "Service Temporarily Unavailable");
    }

    #[test]
    fn bodyless_statuses() {
        assert!(is_bodyless(204));
        assert!(is_bodyless(304));
        assert!(is_bodyless(100));
        assert!(!is_bodyless(200));
        assert!(!is_bodyless(404));
    }

    #[test]
    fn error_page_contains_code_and_signature() {
        let p = error_page(404, Some("oxiserve/0.1.0"));
        assert!(p.contains("404 Not Found"));
        assert!(p.contains("oxiserve/0.1.0"));
        let bare = error_page(404, None);
        assert!(!bare.contains("<hr>"));
    }
}

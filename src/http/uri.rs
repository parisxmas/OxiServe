//! URI decoding and path normalisation.
//!
//! This is the security-critical part of a static file server. Everything that
//! reaches the filesystem goes through [`normalize`], which mirrors nginx's
//! `ngx_http_parse_complex_uri`: percent-decode, collapse duplicate slashes,
//! resolve `.` and `..`, and **reject** any path that would climb above the
//! document root. A `..` that escapes is a hard error, not a silent clamp —
//! nginx returns 400 for these and so do we.

/// Splits a request target into (path, query). The query keeps everything
/// after the first `?`, exactly as nginx's `$args` does.
pub fn split_query(target: &str) -> (&str, &str) {
    match target.as_bytes().iter().position(|&b| b == b'?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UriError {
    /// `..` climbed above the root, or the path contained a NUL byte.
    Invalid,
    /// The path did not start with `/`.
    NotAbsolute,
}

/// Percent-decodes and normalises an absolute request path.
///
/// Returns a path that always starts with `/`, contains no `.`/`..` segments,
/// and no empty segments. A trailing slash is preserved because `try_files`
/// and directory-index handling depend on it.
pub fn normalize(path: &str) -> Result<String, UriError> {
    if !path.starts_with('/') {
        return Err(UriError::NotAbsolute);
    }
    let b = path.as_bytes();
    // Segment start offsets within `out`, so `..` can truncate cheaply.
    let mut out = String::with_capacity(path.len());
    let mut starts: Vec<usize> = Vec::with_capacity(16);
    out.push('/');

    let mut i = 1;
    let mut seg = String::with_capacity(64);
    let trailing_slash = b.len() > 1 && b[b.len() - 1] == b'/';

    loop {
        // Collect one segment, decoding as we go.
        seg.clear();
        while i < b.len() && b[i] != b'/' {
            let c = if b[i] == b'%' {
                if i + 2 >= b.len() {
                    return Err(UriError::Invalid);
                }
                let h = hex(b[i + 1]).ok_or(UriError::Invalid)?;
                let l = hex(b[i + 2]).ok_or(UriError::Invalid)?;
                i += 3;
                (h << 4) | l
            } else {
                let c = b[i];
                i += 1;
                c
            };
            // A decoded NUL or a decoded `/` would let an attacker smuggle a
            // separator past this loop; both are rejected outright.
            if c == 0 || c == b'/' {
                return Err(UriError::Invalid);
            }
            seg.push(c as char);
        }

        match seg.as_str() {
            "" | "." => {}
            ".." => {
                // Climbing above the root is an error, never a no-op.
                let last = starts.pop().ok_or(UriError::Invalid)?;
                out.truncate(last);
            }
            s => {
                starts.push(out.len());
                out.push_str(s);
                out.push('/');
            }
        }

        if i >= b.len() {
            break;
        }
        i += 1; // skip the '/'
    }

    // `out` currently ends with '/' after every segment. Drop it unless the
    // original path genuinely ended in a slash.
    if !trailing_slash && out.len() > 1 {
        out.pop();
    }
    Ok(out)
}

#[inline]
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes a path for use in a `Location` header or an autoindex link.
pub fn encode_path(s: &str, out: &mut String) {
    for &c in s.as_bytes() {
        let safe = c.is_ascii_alphanumeric()
            || matches!(c, b'-' | b'_' | b'.' | b'~' | b'/' | b'@' | b':' | b'+' | b'$' | b',' | b';' | b'=');
        if safe {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(HEX[(c >> 4) as usize] as char);
            out.push(HEX[(c & 0xf) as usize] as char);
        }
    }
}

/// Escapes text for inclusion in HTML (autoindex listings, error pages).
pub fn escape_html(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Finds a named parameter in a query string: `?a=1&b=2`.
pub fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if k == name {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths_pass_through() {
        assert_eq!(normalize("/").unwrap(), "/");
        assert_eq!(normalize("/index.html").unwrap(), "/index.html");
        assert_eq!(normalize("/a/b/c").unwrap(), "/a/b/c");
    }

    #[test]
    fn trailing_slash_is_preserved() {
        assert_eq!(normalize("/a/b/").unwrap(), "/a/b/");
        assert_eq!(normalize("/a/b").unwrap(), "/a/b");
    }

    #[test]
    fn duplicate_slashes_collapse() {
        assert_eq!(normalize("//a///b").unwrap(), "/a/b");
        assert_eq!(normalize("/a//").unwrap(), "/a/");
    }

    #[test]
    fn dot_segments_resolve() {
        assert_eq!(normalize("/a/./b").unwrap(), "/a/b");
        assert_eq!(normalize("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(normalize("/a/b/..").unwrap(), "/a");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(normalize("/a%20b").unwrap(), "/a b");
        assert_eq!(normalize("/%68%65%6c%6c%6f").unwrap(), "/hello");
    }

    // The traversal suite. Every one of these must fail closed.
    #[test]
    fn traversal_above_root_is_rejected() {
        for p in [
            "/../etc/passwd",
            "/a/../../etc/passwd",
            "/..",
            "/a/b/../../../x",
            "/%2e%2e/etc/passwd",
            "/%2e%2e%2f%2e%2e%2fetc/passwd",
            "/a/%2e%2e/%2e%2e/etc",
        ] {
            assert_eq!(normalize(p), Err(UriError::Invalid), "should reject {p}");
        }
    }

    #[test]
    fn encoded_slash_is_rejected() {
        // %2f must not become a path separator after decoding.
        assert_eq!(normalize("/a%2fb"), Err(UriError::Invalid));
    }

    #[test]
    fn nul_byte_is_rejected() {
        assert_eq!(normalize("/a%00.html"), Err(UriError::Invalid));
    }

    #[test]
    fn malformed_escapes_are_rejected() {
        assert_eq!(normalize("/a%zz"), Err(UriError::Invalid));
        assert_eq!(normalize("/a%2"), Err(UriError::Invalid));
        assert_eq!(normalize("/a%"), Err(UriError::Invalid));
    }

    #[test]
    fn relative_target_is_rejected() {
        assert_eq!(normalize("a/b"), Err(UriError::NotAbsolute));
    }

    #[test]
    fn query_split() {
        assert_eq!(split_query("/a?b=1"), ("/a", "b=1"));
        assert_eq!(split_query("/a"), ("/a", ""));
        assert_eq!(split_query("/a?"), ("/a", ""));
        assert_eq!(split_query("/a?b=1?c=2"), ("/a", "b=1?c=2"));
    }

    #[test]
    fn query_params() {
        assert_eq!(query_param("a=1&b=2", "b"), Some("2"));
        assert_eq!(query_param("a=1&b=2", "c"), None);
        assert_eq!(query_param("flag&b=2", "flag"), Some(""));
    }

    #[test]
    fn encoding_roundtrip() {
        let mut s = String::new();
        encode_path("/a b/c%d", &mut s);
        assert_eq!(s, "/a%20b/c%25d");
        assert_eq!(normalize(&s).unwrap(), "/a b/c%d");
    }

    #[test]
    fn html_escaping() {
        let mut s = String::new();
        escape_html("<a href=\"x\">&</a>", &mut s);
        assert_eq!(s, "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;");
    }
}

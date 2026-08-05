//! The FastCGI record protocol (FastCGI Specification 1.0).
//!
//! Split out from the request handler so the wire format is testable without a
//! socket. Everything here is pure byte manipulation.
//!
//! A responder exchange looks like this:
//!
//! ```text
//!   us → app:  BEGIN_REQUEST(role=RESPONDER)
//!              PARAMS(name/value pairs…)  PARAMS(empty = end of params)
//!              STDIN(body…)               STDIN(empty = end of body)
//!   app → us:  STDOUT(CGI headers + body…)  [STDERR(log text…)]
//!              END_REQUEST
//! ```

/// Every record starts with this fixed 8-byte header.
pub const HEADER_LEN: usize = 8;
pub const VERSION: u8 = 1;

/// Content length is a `u16`, so this is the most one record can carry.
pub const MAX_CONTENT: usize = 0xFFFF;

/// We only ever open one request per connection, so the id is constant.
pub const REQUEST_ID: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    BeginRequest = 1,
    AbortRequest = 2,
    EndRequest = 3,
    Params = 4,
    Stdin = 5,
    Stdout = 6,
    Stderr = 7,
    Data = 8,
    GetValues = 9,
    GetValuesResult = 10,
    UnknownType = 11,
}

impl RecordType {
    pub fn from_u8(v: u8) -> Option<RecordType> {
        Some(match v {
            1 => RecordType::BeginRequest,
            2 => RecordType::AbortRequest,
            3 => RecordType::EndRequest,
            4 => RecordType::Params,
            5 => RecordType::Stdin,
            6 => RecordType::Stdout,
            7 => RecordType::Stderr,
            8 => RecordType::Data,
            9 => RecordType::GetValues,
            10 => RecordType::GetValuesResult,
            11 => RecordType::UnknownType,
            _ => return None,
        })
    }
}

/// FastCGI roles. We implement the responder role, which is what
/// `fastcgi_pass` to php-fpm uses.
pub const ROLE_RESPONDER: u16 = 1;

/// `FCGI_KEEP_CONN` — ask the application to keep the connection open after
/// `END_REQUEST` instead of closing it.
pub const FLAG_KEEP_CONN: u8 = 1;

/// Appends a record header.
fn push_header(out: &mut Vec<u8>, ty: RecordType, content_len: usize, padding: u8) {
    out.push(VERSION);
    out.push(ty as u8);
    out.extend_from_slice(&REQUEST_ID.to_be_bytes());
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.push(padding);
    out.push(0); // reserved
}

/// Appends a complete record, padding the body to an 8-byte boundary.
///
/// Padding is optional in the specification but applications are measurably
/// happier with aligned records, and nginx emits it too.
pub fn push_record(out: &mut Vec<u8>, ty: RecordType, body: &[u8]) {
    debug_assert!(body.len() <= MAX_CONTENT);
    let padding = ((8 - (body.len() % 8)) % 8) as u8;
    push_header(out, ty, body.len(), padding);
    out.extend_from_slice(body);
    out.extend(std::iter::repeat_n(0u8, padding as usize));
}

/// Appends `BEGIN_REQUEST` for the responder role.
pub fn push_begin_request(out: &mut Vec<u8>, keep_conn: bool) {
    let mut body = [0u8; 8];
    body[0..2].copy_from_slice(&ROLE_RESPONDER.to_be_bytes());
    body[2] = if keep_conn { FLAG_KEEP_CONN } else { 0 };
    push_record(out, RecordType::BeginRequest, &body);
}

/// Encodes one name/value pair.
///
/// Lengths below 128 take one byte; larger ones take four with the top bit of
/// the first byte set as the discriminator.
pub fn push_nv_pair(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    push_len(out, name.len());
    push_len(out, value.len());
    out.extend_from_slice(name);
    out.extend_from_slice(value);
}

fn push_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        let v = (n as u32) | 0x8000_0000;
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Splits an encoded name/value blob across as many `PARAMS` records as it
/// needs, then terminates the stream with an empty one.
pub fn push_params(out: &mut Vec<u8>, params: &[u8]) {
    for chunk in params.chunks(MAX_CONTENT) {
        push_record(out, RecordType::Params, chunk);
    }
    push_record(out, RecordType::Params, &[]); // end of stream
}

/// Same for the request body on `STDIN`.
pub fn push_stdin(out: &mut Vec<u8>, body: &[u8]) {
    for chunk in body.chunks(MAX_CONTENT) {
        push_record(out, RecordType::Stdin, chunk);
    }
    push_record(out, RecordType::Stdin, &[]);
}

/// A record parsed out of the response stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub ty: RecordType,
    pub request_id: u16,
    pub body: &'a [u8],
    /// Total bytes consumed, including header and padding.
    pub total: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// More bytes are needed before this record is complete.
    Incomplete,
    /// Unsupported version or an unknown record type.
    Malformed,
}

/// Parses one record from the front of `buf`.
pub fn parse_record(buf: &[u8]) -> Result<Record<'_>, ParseError> {
    if buf.len() < HEADER_LEN {
        return Err(ParseError::Incomplete);
    }
    if buf[0] != VERSION {
        return Err(ParseError::Malformed);
    }
    let Some(ty) = RecordType::from_u8(buf[1]) else {
        return Err(ParseError::Malformed);
    };
    let request_id = u16::from_be_bytes([buf[2], buf[3]]);
    let content_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let padding = buf[6] as usize;

    let total = HEADER_LEN + content_len + padding;
    if buf.len() < total {
        return Err(ParseError::Incomplete);
    }
    Ok(Record {
        ty,
        request_id,
        body: &buf[HEADER_LEN..HEADER_LEN + content_len],
        total,
    })
}

/// The protocol status byte inside `END_REQUEST`.
pub fn end_request_status(body: &[u8]) -> Option<(u32, u8)> {
    if body.len() < 8 {
        return None;
    }
    let app_status = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    Some((app_status, body[4]))
}

/// Turns a request header name into its CGI environment form:
/// `X-Forwarded-For` → `HTTP_X_FORWARDED_FOR`.
pub fn http_param_name(name: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(b"HTTP_");
    for b in name.bytes() {
        out.push(if b == b'-' { b'_' } else { b.to_ascii_uppercase() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_matches_the_spec() {
        let mut out = Vec::new();
        push_record(&mut out, RecordType::Stdout, b"hi");
        assert_eq!(out[0], 1, "version");
        assert_eq!(out[1], RecordType::Stdout as u8);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 1, "request id");
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 2, "content length");
        assert_eq!(out[6], 6, "padding to the next 8-byte boundary");
        assert_eq!(out.len(), 8 + 2 + 6);
    }

    #[test]
    fn records_are_padded_to_eight_bytes() {
        for len in [0usize, 1, 7, 8, 9, 16, 100] {
            let mut out = Vec::new();
            push_record(&mut out, RecordType::Params, &vec![b'x'; len]);
            assert_eq!(out.len() % 8, 0, "record of {len} bytes must be 8-aligned");
        }
    }

    #[test]
    fn begin_request_declares_the_responder_role() {
        let mut out = Vec::new();
        push_begin_request(&mut out, false);
        let r = parse_record(&out).unwrap();
        assert_eq!(r.ty, RecordType::BeginRequest);
        assert_eq!(u16::from_be_bytes([r.body[0], r.body[1]]), ROLE_RESPONDER);
        assert_eq!(r.body[2], 0, "keep-conn flag clear");

        let mut out = Vec::new();
        push_begin_request(&mut out, true);
        let r = parse_record(&out).unwrap();
        assert_eq!(r.body[2], FLAG_KEEP_CONN);
    }

    #[test]
    fn short_name_value_pairs_use_one_byte_lengths() {
        let mut out = Vec::new();
        push_nv_pair(&mut out, b"KEY", b"value");
        assert_eq!(out, b"\x03\x05KEYvalue");
    }

    #[test]
    fn long_values_use_four_byte_lengths_with_the_high_bit_set() {
        let long = vec![b'v'; 200];
        let mut out = Vec::new();
        push_nv_pair(&mut out, b"K", &long);
        assert_eq!(out[0], 1, "short name stays one byte");
        // 4-byte length, high bit set on the first byte.
        assert_eq!(out[1] & 0x80, 0x80);
        let len = u32::from_be_bytes([out[1], out[2], out[3], out[4]]) & 0x7fff_ffff;
        assert_eq!(len, 200);
        assert_eq!(&out[5..6], b"K");
    }

    #[test]
    fn params_stream_is_terminated_by_an_empty_record() {
        let mut params = Vec::new();
        push_nv_pair(&mut params, b"A", b"1");
        let mut out = Vec::new();
        push_params(&mut out, &params);

        let first = parse_record(&out).unwrap();
        assert_eq!(first.ty, RecordType::Params);
        assert!(!first.body.is_empty());
        let second = parse_record(&out[first.total..]).unwrap();
        assert_eq!(second.ty, RecordType::Params);
        assert!(second.body.is_empty(), "stream must end with an empty record");
    }

    #[test]
    fn oversized_payloads_split_across_records() {
        let big = vec![b'x'; MAX_CONTENT + 100];
        let mut out = Vec::new();
        push_stdin(&mut out, &big);

        let mut off = 0;
        let mut data = 0usize;
        let mut records = 0;
        loop {
            let r = parse_record(&out[off..]).unwrap();
            records += 1;
            data += r.body.len();
            off += r.total;
            if r.body.is_empty() {
                break;
            }
        }
        assert_eq!(data, big.len(), "no payload bytes lost");
        assert_eq!(records, 3, "two data records plus the terminator");
    }

    #[test]
    fn incomplete_input_is_reported_not_guessed() {
        let mut out = Vec::new();
        push_record(&mut out, RecordType::Stdout, b"body");
        for cut in 0..out.len() {
            assert_eq!(
                parse_record(&out[..cut]).unwrap_err(),
                ParseError::Incomplete,
                "truncated at {cut} must be Incomplete"
            );
        }
        assert!(parse_record(&out).is_ok());
    }

    #[test]
    fn bad_version_or_type_is_malformed() {
        let mut out = Vec::new();
        push_record(&mut out, RecordType::Stdout, b"x");
        let mut bad_ver = out.clone();
        bad_ver[0] = 9;
        assert_eq!(parse_record(&bad_ver).unwrap_err(), ParseError::Malformed);
        let mut bad_ty = out.clone();
        bad_ty[1] = 99;
        assert_eq!(parse_record(&bad_ty).unwrap_err(), ParseError::Malformed);
    }

    #[test]
    fn end_request_decodes_app_status() {
        let mut body = [0u8; 8];
        body[0..4].copy_from_slice(&255u32.to_be_bytes());
        body[4] = 0; // FCGI_REQUEST_COMPLETE
        assert_eq!(end_request_status(&body), Some((255, 0)));
        assert_eq!(end_request_status(&[0u8; 4]), None);
    }

    #[test]
    fn header_names_become_cgi_environment_names() {
        let mut out = Vec::new();
        http_param_name("X-Forwarded-For", &mut out);
        assert_eq!(out, b"HTTP_X_FORWARDED_FOR");
        out.clear();
        http_param_name("user-agent", &mut out);
        assert_eq!(out, b"HTTP_USER_AGENT");
    }
}

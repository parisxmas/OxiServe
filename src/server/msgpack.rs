//! Minimal MessagePack encoder for the OxiDB log sink.
//!
//! Only the types a log record actually contains — string-keyed maps, strings,
//! unsigned integers and floats. Written by hand rather than pulled in as a
//! dependency: the subset is small, it keeps the log path free of `serde`
//! machinery, and encoding happens per request so the exact byte cost matters.
//!
//! OxiDB's MessagePack ingest (`OXIDB_MSGPACK_PORT`) is the cheapest of its
//! three UDP paths — compact on the wire and, unlike the GELF one, it does not
//! build a BTree index per field, which is the right trade for an append-only
//! log stream.

/// Writes a map header for `n` entries.
pub fn map_header(out: &mut Vec<u8>, n: usize) {
    if n < 16 {
        out.push(0x80 | n as u8); // fixmap
    } else if n <= u16::MAX as usize {
        out.push(0xde); // map16
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdf); // map32
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
}

pub fn write_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len();
    if n < 32 {
        out.push(0xa0 | n as u8); // fixstr
    } else if n <= u8::MAX as usize {
        out.push(0xd9); // str8
        out.push(n as u8);
    } else if n <= u16::MAX as usize {
        out.push(0xda); // str16
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdb); // str32
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(b);
}

pub fn write_uint(out: &mut Vec<u8>, v: u64) {
    if v < 128 {
        out.push(v as u8); // positive fixint
    } else if v <= u8::MAX as u64 {
        out.push(0xcc);
        out.push(v as u8);
    } else if v <= u16::MAX as u64 {
        out.push(0xcd);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u32::MAX as u64 {
        out.push(0xce);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

pub fn write_f64(out: &mut Vec<u8>, v: f64) {
    out.push(0xcb);
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes a value, choosing the narrowest sensible encoding.
///
/// Log fields arrive as text, but `$status` and `$body_bytes_sent` are far
/// more useful to a query engine as numbers than as strings — so a field that
/// is entirely digits is written as an integer, and one that parses as a
/// decimal (`$request_time`) as a float.
pub fn write_auto(out: &mut Vec<u8>, s: &str) {
    // A leading zero is significant in an identifier, so "007" stays a string.
    let numeric = !s.is_empty()
        && s.len() <= 19
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if numeric {
        if let Ok(v) = s.parse::<u64>() {
            write_uint(out, v);
            return;
        }
    }
    if s.contains('.') && s.len() <= 24 {
        if let Ok(v) = s.parse::<f64>() {
            // Reject things like an IP address, which parses as neither.
            if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') && s.matches('.').count() == 1 {
                write_f64(out, v);
                return;
            }
        }
    }
    write_str(out, s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixmap_and_larger_headers() {
        let mut o = Vec::new();
        map_header(&mut o, 3);
        assert_eq!(o, vec![0x83]);

        o.clear();
        map_header(&mut o, 20);
        assert_eq!(o, vec![0xde, 0x00, 0x14]);
    }

    #[test]
    fn string_encodings_by_length() {
        let mut o = Vec::new();
        write_str(&mut o, "ab");
        assert_eq!(o, vec![0xa2, b'a', b'b'], "fixstr");

        o.clear();
        write_str(&mut o, &"x".repeat(40));
        assert_eq!(&o[..2], &[0xd9, 40], "str8");

        o.clear();
        write_str(&mut o, &"x".repeat(300));
        assert_eq!(&o[..1], &[0xda], "str16");
        assert_eq!(u16::from_be_bytes([o[1], o[2]]), 300);
    }

    #[test]
    fn integer_encodings_by_magnitude() {
        let cases: &[(u64, u8)] = &[(0, 0x00), (127, 0x7f), (200, 0xcc), (5000, 0xcd)];
        for (v, first) in cases {
            let mut o = Vec::new();
            write_uint(&mut o, *v);
            assert_eq!(o[0], *first, "encoding for {v}");
        }
        let mut o = Vec::new();
        write_uint(&mut o, u64::MAX);
        assert_eq!(o[0], 0xcf);
        assert_eq!(o.len(), 9);
    }

    #[test]
    fn numeric_fields_become_numbers() {
        // $status and $body_bytes_sent are far more useful queryable as ints.
        let mut o = Vec::new();
        write_auto(&mut o, "200");
        assert_eq!(o, vec![0xcc, 200], "status must encode as an integer");

        o.clear();
        write_auto(&mut o, "0");
        assert_eq!(o, vec![0x00]);
    }

    #[test]
    fn decimals_become_floats() {
        let mut o = Vec::new();
        write_auto(&mut o, "0.125");
        assert_eq!(o[0], 0xcb, "$request_time must encode as a float");
        assert_eq!(f64::from_be_bytes(o[1..9].try_into().unwrap()), 0.125);
    }

    #[test]
    fn things_that_only_look_numeric_stay_strings() {
        // An IP has three dots; a leading zero is significant; a version has
        // two dots. None of these should be silently turned into a number.
        for s in ["127.0.0.1", "007", "1.2.3", "", "12a"] {
            let mut o = Vec::new();
            write_auto(&mut o, s);
            assert!(
                o[0] & 0xe0 == 0xa0 || o[0] == 0xd9 || o[0] == 0xda,
                "{s:?} must stay a string, got first byte {:#04x}", o[0]
            );
        }
    }

    #[test]
    fn a_full_record_round_trips_through_a_reference_decoder() {
        // Hand-decode the map to prove the bytes are well-formed.
        let mut o = Vec::new();
        map_header(&mut o, 2);
        write_str(&mut o, "status");
        write_auto(&mut o, "404");
        write_str(&mut o, "uri");
        write_auto(&mut o, "/missing");

        assert_eq!(o[0], 0x82, "two-entry fixmap");
        let mut i = 1;
        // key "status"
        assert_eq!(o[i], 0xa6);
        assert_eq!(&o[i + 1..i + 7], b"status");
        i += 7;
        // value 404 as uint16
        assert_eq!(o[i], 0xcd);
        assert_eq!(u16::from_be_bytes([o[i + 1], o[i + 2]]), 404);
        i += 3;
        // key "uri"
        assert_eq!(o[i], 0xa3);
        assert_eq!(&o[i + 1..i + 4], b"uri");
        i += 4;
        // value "/missing"
        assert_eq!(o[i], 0xa8);
        assert_eq!(&o[i + 1..], b"/missing");
    }
}

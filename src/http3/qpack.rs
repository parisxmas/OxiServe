//! QPACK field compression (RFC 9204).
//!
//! # Why there is no dynamic table
//!
//! QPACK is HPACK re-cut for a transport that can deliver streams out of
//! order. That reordering is the whole reason the specification is as large as
//! it is: a field section that references the dynamic table cannot be decoded
//! until the insertions it depends on have arrived on a *different* stream, so
//! a conforming implementation needs blocked-stream accounting, a Required
//! Insert Count, section acknowledgements on the decoder stream, and a
//! deadlock-avoidance story for all of it.
//!
//! Setting `SETTINGS_QPACK_MAX_TABLE_CAPACITY` to 0 removes that entire
//! machine, and it is a conformant configuration rather than a shortcut: RFC
//! 9204 section 3.2.2 forbids a peer from sending an insertion once the
//! capacity it was given is zero, so a legal client cannot produce a field
//! section we would fail to decode. What it costs is compression on repeated
//! request headers — the static table still covers the common ones — and what
//! it buys is that no field section here can ever block on another stream.
//!
//! This is the same trade [`crate::http2::hpack::Encoder`] already makes in
//! the other direction, and for the same reason: the two ends disagreeing
//! about table state is a whole class of bug that not having a table cannot
//! have.
//!
//! # What is shared with HPACK
//!
//! The prefixed-integer coding is literally HPACK's, and RFC 9204 section 4.1
//! says so; [`int`](crate::http2::hpack::int) and
//! [`write_int`](crate::http2::hpack::write_int) are reused rather than
//! re-derived. The Huffman table is also the one from RFC 7541 appendix B, so
//! [`crate::http2::huffman`] is reused whole. What differs is the static table
//! and the field-line opcodes, which is what this module is.

use crate::http2::hpack::{int, write_int, HpackError};
use crate::http2::huffman;

/// One decoded field. Shared with HPACK because it is the same pair of strings
/// and the handler seam downstream takes exactly one shape.
pub use crate::http2::hpack::Header;

/// Longest single name or value we will decode, matching the HPACK limit.
const MAX_STRING: usize = 32 * 1024;

/// Per-field overhead in the size accounting of RFC 9114 section 4.2.2, which
/// is what `SETTINGS_MAX_FIELD_SECTION_SIZE` is measured in.
const FIELD_OVERHEAD: usize = 32;

/// A field section we could not decode. Carries the HTTP/3 error code to close
/// with; every one of these is fatal to the connection, because QPACK state is
/// per connection and a failed decode means we no longer know where we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QpackError(pub u64);

impl From<HpackError> for QpackError {
    fn from(_: HpackError) -> QpackError {
        QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED)
    }
}

/// RFC 9204 appendix A. Unlike HPACK's, this table is zero-indexed.
#[rustfmt::skip]
const STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

// ---------------------------------------------------------------------------
// Encoding

/// Writes the Encoded Field Section Prefix.
///
/// Required Insert Count and Delta Base, both zero: with no dynamic table
/// there is nothing to wait for and nothing to index against, so the prefix is
/// two zero bytes on every section we send. Separate from [`encode`] to mirror
/// [`crate::http2::hpack::Encoder::begin_block`] — the prefix belongs at the
/// start of the section and nowhere else.
pub fn begin_section(out: &mut Vec<u8>) {
    out.push(0x00); // Required Insert Count = 0
    out.push(0x00); // S = 0, Delta Base = 0
}

/// Appends one field line. Call [`begin_section`] first.
pub fn encode(name: &str, value: &str, out: &mut Vec<u8>) {
    // Indexed Field Line, static: `1` `T=1` then a 6-bit index. One byte for
    // anything the table holds outright.
    if let Some(i) = STATIC.iter().position(|(n, v)| *n == name && *v == value) {
        write_int(i as u64, 6, 0xc0, out);
        return;
    }
    match STATIC.iter().position(|(n, _)| *n == name) {
        // Literal Field Line with Name Reference: `01` `N=0` `T=1`, 4-bit index.
        Some(i) => write_int(i as u64, 4, 0x50, out),
        // Literal Field Line with Literal Name: `001` `N=0` then `H` and a
        // 3-bit length, which `write_string` fills in.
        None => write_string(name.as_bytes(), 3, 0x20, out),
    }
    write_string(value.as_bytes(), 7, 0x00, out);
}

/// A string literal: an `H` bit immediately above a `prefix`-bit length.
///
/// QPACK varies the prefix width by position — 3 bits for a literal field name,
/// 7 for a value — which is the one place its string coding differs from
/// HPACK's.
fn write_string(s: &[u8], prefix: u32, flags: u8, out: &mut Vec<u8>) {
    let huff = 1u8 << prefix;
    // Huffman only when it actually helps; for short ASCII it often does not,
    // and paying to encode something that then grows is worse than sending it
    // raw.
    let hlen = huffman::encoded_len(s);
    if hlen < s.len() {
        write_int(hlen as u64, prefix, flags | huff, out);
        huffman::encode(s, out);
    } else {
        write_int(s.len() as u64, prefix, flags, out);
        out.extend_from_slice(s);
    }
}

// ---------------------------------------------------------------------------
// Decoding

/// Decodes a complete field section.
///
/// `max_section` is the `SETTINGS_MAX_FIELD_SECTION_SIZE` we advertised,
/// enforced as it decodes rather than afterwards so an oversized section costs
/// the memory of the fields read so far and not the whole of it.
pub fn decode(buf: &[u8], max_section: usize) -> Result<Vec<Header>, QpackError> {
    let mut rest = read_prefix(buf)?;
    let mut out = Vec::with_capacity(16);
    let mut size = 0usize;

    while !rest.is_empty() {
        let b = rest[0];
        let h = if b & 0x80 != 0 {
            // Indexed Field Line. T is bit 6: set means the static table.
            if b & 0x40 == 0 {
                return Err(dynamic_reference());
            }
            let (i, r) = int(rest, 6)?;
            rest = r;
            let (n, v) = static_at(i)?;
            Header { name: n.to_string(), value: v.to_string() }
        } else if b & 0x40 != 0 {
            // Literal Field Line with Name Reference. T is bit 4.
            if b & 0x10 == 0 {
                return Err(dynamic_reference());
            }
            let (i, r) = int(rest, 4)?;
            let (name, _) = static_at(i)?;
            let (value, r) = read_string(r, 7)?;
            rest = r;
            Header { name: name.to_string(), value }
        } else if b & 0x20 != 0 {
            // Literal Field Line with Literal Name.
            let (name, r) = read_string(rest, 3)?;
            let (value, r) = read_string(r, 7)?;
            rest = r;
            Header { name, value }
        } else {
            // `0001xxxx` is an Indexed Field Line with Post-Base Index and
            // `0000xxxx` a literal against one: both are dynamic-table
            // references, which a peer told capacity 0 may not send.
            return Err(dynamic_reference());
        };

        size += h.name.len() + h.value.len() + FIELD_OVERHEAD;
        if size > max_section {
            // Not a compression failure — the peer encoded it correctly, we
            // simply refuse to hold it. RFC 9114 section 4.2.2.
            return Err(QpackError(super::frame::code::EXCESSIVE_LOAD));
        }
        out.push(h);
    }
    Ok(out)
}

/// Reads the two-integer section prefix and returns the field lines after it.
fn read_prefix(buf: &[u8]) -> Result<&[u8], QpackError> {
    let (required_insert_count, rest) = int(buf, 8)?;
    // Anything non-zero claims the section depends on dynamic table entries
    // that, having advertised a capacity of zero, we know cannot exist.
    if required_insert_count != 0 {
        return Err(dynamic_reference());
    }
    // Delta Base is read and discarded: with no dynamic table the base is
    // always zero, but a peer is still entitled to encode the field.
    let (_, rest) = int(rest, 7)?;
    Ok(rest)
}

fn static_at(i: u64) -> Result<(&'static str, &'static str), QpackError> {
    STATIC
        .get(i as usize)
        .copied()
        .ok_or(QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED))
}

/// A reference to the dynamic table. Legal QPACK in general, impossible here.
fn dynamic_reference() -> QpackError {
    QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED)
}

fn read_string(buf: &[u8], prefix: u32) -> Result<(String, &[u8]), QpackError> {
    let first = *buf.first().ok_or(QpackError(
        super::frame::code::QPACK_DECOMPRESSION_FAILED,
    ))?;
    let huffman_coded = first & (1 << prefix) != 0;
    let (len, rest) = int(buf, prefix)?;
    let len = len as usize;
    // A declared length past the end is malformed, not merely large: the
    // section is complete by the time it is decoded, so no later bytes can
    // supply what is missing.
    if rest.len() < len {
        return Err(QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED));
    }
    let (raw, rest) = rest.split_at(len);

    let bytes = if huffman_coded {
        let mut o = Vec::with_capacity(len * 2);
        huffman::decode(raw, MAX_STRING, &mut o)
            .map_err(|_| QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED))?;
        o
    } else {
        raw.to_vec()
    };
    // Everything downstream — routing, logging, variables — is `str`. A field
    // that is not UTF-8 is rejected rather than lossily repaired, because a
    // repaired header is one the client never sent.
    String::from_utf8(bytes)
        .map_err(|_| QpackError(super::frame::code::QPACK_DECOMPRESSION_FAILED))
        .map(|s| (s, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(fields: &[(&str, &str)]) -> Vec<Header> {
        let mut buf = Vec::new();
        begin_section(&mut buf);
        for (n, v) in fields {
            encode(n, v, &mut buf);
        }
        decode(&buf, 1 << 20).expect("our own output must decode")
    }

    fn expect(fields: &[(&str, &str)]) -> Vec<Header> {
        fields
            .iter()
            .map(|(n, v)| Header { name: n.to_string(), value: v.to_string() })
            .collect()
    }

    #[test]
    fn the_static_table_matches_the_rfc_at_its_edges() {
        // Spot-checks at both ends and either side of the 62/63 boundary,
        // where the table stops being ordered by name. An off-by-one here
        // would silently rewrite headers rather than fail.
        assert_eq!(STATIC.len(), 99);
        assert_eq!(STATIC[0], (":authority", ""));
        assert_eq!(STATIC[1], (":path", "/"));
        assert_eq!(STATIC[17], (":method", "GET"));
        assert_eq!(STATIC[25], (":status", "200"));
        assert_eq!(STATIC[62], ("x-xss-protection", "1; mode=block"));
        assert_eq!(STATIC[63], (":status", "100"));
        assert_eq!(STATIC[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn a_full_static_match_is_one_byte_after_the_prefix() {
        let mut buf = Vec::new();
        begin_section(&mut buf);
        encode(":method", "GET", &mut buf);
        // Two prefix bytes, then `11` and the 6-bit index 17.
        assert_eq!(buf, vec![0x00, 0x00, 0xc0 | 17]);
        assert_eq!(decode(&buf, 1 << 20).unwrap(), expect(&[(":method", "GET")]));
    }

    /// RFC 9204 appendix B.1, whose Huffman bytes are the ones RFC 7541
    /// appendix C.4.1 gives for the same string.
    ///
    /// Round-tripping our own output proves we are self-consistent, which is
    /// exactly what a wrong static index or a misplaced opcode bit would also
    /// be. This is the check that our bytes are the *specification's* bytes.
    #[test]
    fn the_rfc_9204_b1_vector_matches_byte_for_byte() {
        const B1: &[u8] = &[
            0x00, 0x00, // Required Insert Count = 0, Delta Base = 0
            0x50, // literal, name reference, static index 0 (:authority)
            0x8c, // value: Huffman coded, length 12
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];

        let mut ours = Vec::new();
        begin_section(&mut ours);
        encode(":authority", "www.example.com", &mut ours);
        assert_eq!(ours, B1, "our encoding must be the RFC's");

        assert_eq!(
            decode(B1, 1 << 20).unwrap(),
            expect(&[(":authority", "www.example.com")]),
            "and the RFC's must be ours"
        );
    }

    #[test]
    fn a_name_only_match_indexes_the_name_and_spells_the_value() {
        let out = roundtrip(&[(":status", "418")]);
        assert_eq!(out, expect(&[(":status", "418")]));
    }

    #[test]
    fn a_wholly_unknown_field_round_trips_as_two_literals() {
        let out = roundtrip(&[("x-oxiserve-custom", "some value")]);
        assert_eq!(out, expect(&[("x-oxiserve-custom", "some value")]));
    }

    #[test]
    fn a_realistic_request_round_trips() {
        let fields = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/index.html"),
            ("user-agent", "Mozilla/5.0 (a fairly long value to force huffman)"),
            ("accept", "*/*"),
            ("accept-encoding", "gzip, deflate, br"),
            ("cookie", "session=abc123"),
        ];
        assert_eq!(roundtrip(&fields), expect(&fields));
    }

    #[test]
    fn a_realistic_response_round_trips() {
        let fields = [
            (":status", "200"),
            ("content-type", "text/html; charset=utf-8"),
            ("content-length", "1234"),
            ("server", "oxiserve"),
            ("date", "Mon, 07 Aug 2026 12:00:00 GMT"),
        ];
        assert_eq!(roundtrip(&fields), expect(&fields));
    }

    #[test]
    fn empty_values_and_long_values_survive() {
        let long = "x".repeat(4096);
        let fields = [("x-empty", ""), ("x-long", long.as_str())];
        assert_eq!(roundtrip(&fields), expect(&fields));
    }

    #[test]
    fn huffman_is_used_only_when_it_shortens() {
        // A run of one repeated letter compresses well.
        let mut a = Vec::new();
        begin_section(&mut a);
        encode("x-a", &"a".repeat(64), &mut a);
        assert!(a.len() < 64, "expected huffman to shrink this, got {}", a.len());

        // Bytes with long codes do not, and must be sent raw rather than
        // grown. 0x00 costs 13 bits in the RFC 7541 table.
        let raw: String = std::char::from_u32(0).unwrap().to_string().repeat(16);
        let mut b = Vec::new();
        begin_section(&mut b);
        encode("x-b", &raw, &mut b);
        assert_eq!(
            decode(&b, 1 << 20).unwrap(),
            expect(&[("x-b", raw.as_str())]),
            "the incompressible value must survive verbatim"
        );
    }

    // ---- rejections ------------------------------------------------------

    #[test]
    fn a_dynamic_table_reference_is_refused() {
        // Indexed Field Line with T=0: legal QPACK, impossible against the
        // capacity of 0 we advertise, so it must be diagnosed rather than
        // mis-indexed into the static table.
        let indexed_dynamic = vec![0x00, 0x00, 0x80];
        assert_eq!(
            decode(&indexed_dynamic, 1 << 20),
            Err(QpackError(super::super::frame::code::QPACK_DECOMPRESSION_FAILED))
        );

        // Literal with a dynamic name reference: `01` with T=0.
        let literal_dynamic = vec![0x00, 0x00, 0x40, 0x00];
        assert!(decode(&literal_dynamic, 1 << 20).is_err());

        // Post-Base index, `0001xxxx`.
        let post_base = vec![0x00, 0x00, 0x10];
        assert!(decode(&post_base, 1 << 20).is_err());
    }

    #[test]
    fn a_nonzero_required_insert_count_is_refused() {
        // The section claims to depend on insertions that cannot exist.
        let buf = vec![0x01, 0x00, 0xc0 | 17];
        assert_eq!(
            decode(&buf, 1 << 20),
            Err(QpackError(super::super::frame::code::QPACK_DECOMPRESSION_FAILED))
        );
    }

    #[test]
    fn an_out_of_range_static_index_is_refused() {
        // Index 99 is one past the end of the table.
        let mut buf = vec![0x00, 0x00];
        write_int(99, 6, 0xc0, &mut buf);
        assert!(decode(&buf, 1 << 20).is_err());
    }

    #[test]
    fn a_truncated_string_is_refused() {
        // Declares a 10-byte value and supplies three.
        let mut buf = vec![0x00, 0x00];
        write_int(25, 4, 0x50, &mut buf); // name ref :status
        write_int(10, 7, 0x00, &mut buf);
        buf.extend_from_slice(b"abc");
        assert!(decode(&buf, 1 << 20).is_err());
    }

    #[test]
    fn a_non_utf8_field_is_refused_rather_than_repaired() {
        let mut buf = vec![0x00, 0x00];
        write_int(25, 4, 0x50, &mut buf);
        write_int(2, 7, 0x00, &mut buf);
        buf.extend_from_slice(&[0xff, 0xfe]);
        assert!(decode(&buf, 1 << 20).is_err());
    }

    #[test]
    fn an_oversized_section_is_refused_by_the_advertised_limit() {
        let mut buf = Vec::new();
        begin_section(&mut buf);
        for i in 0..100 {
            encode(&format!("x-header-{i}"), &"v".repeat(100), &mut buf);
        }
        // Each field is name + value + 32, so 100 of them is far past this.
        assert_eq!(
            decode(&buf, 1024),
            Err(QpackError(super::super::frame::code::EXCESSIVE_LOAD)),
            "the limit we advertise has to be the limit we enforce"
        );
        // The same bytes are fine when we said we would take them.
        assert!(decode(&buf, 1 << 20).is_ok());
    }

    #[test]
    fn an_empty_section_decodes_to_no_fields() {
        let mut buf = Vec::new();
        begin_section(&mut buf);
        assert_eq!(decode(&buf, 1 << 20).unwrap(), Vec::new());
    }

    #[test]
    fn a_section_with_no_prefix_at_all_is_refused() {
        assert!(decode(&[], 1 << 20).is_err(), "the prefix is not optional");
    }
}

//! HTTP/3 framing and QUIC variable-length integers (RFC 9114 section 7,
//! RFC 9000 section 16).
//!
//! Like [`super::super::http2::frame`], this module does the framing and
//! nothing else: it holds no connection state and makes no decisions about
//! stream lifecycles. That belongs to [`super::conn`].
//!
//! # What changes from HTTP/2
//!
//! HTTP/2's frame header is nine bytes at a fixed offset, so a reader always
//! knows how much to wait for. HTTP/3's is two varints — type and length —
//! each between one and eight bytes, so even the header arrives incrementally.
//! Every read here therefore returns `Ok(None)` for "not yet", never a partial
//! parse, and the caller keeps the bytes and asks again.
//!
//! There is also no stream multiplexing to do. QUIC gives each request its own
//! stream, so the concurrency HTTP/2 spent 1,300 lines of `conn.rs` on — stream
//! states, flow-control windows, CONTINUATION reassembly — is the transport's
//! problem now, not ours.

/// Frame types on a request or control stream, RFC 9114 section 11.2.1.
pub mod kind {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;
}

/// Unidirectional stream types, RFC 9114 section 11.2.4.
pub mod stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
}

/// SETTINGS identifiers, RFC 9114 section 11.2.2.
pub mod setting {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
}

/// Error codes, RFC 9114 section 8.1 and RFC 9204 section 6.
pub mod code {
    pub const NO_ERROR: u64 = 0x0100;
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
    pub const INTERNAL_ERROR: u64 = 0x0102;
    pub const STREAM_CREATION_ERROR: u64 = 0x0103;
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    pub const FRAME_UNEXPECTED: u64 = 0x0105;
    pub const FRAME_ERROR: u64 = 0x0106;
    pub const EXCESSIVE_LOAD: u64 = 0x0107;
    pub const ID_ERROR: u64 = 0x0108;
    pub const SETTINGS_ERROR: u64 = 0x0109;
    pub const MISSING_SETTINGS: u64 = 0x010a;
    pub const REQUEST_INCOMPLETE: u64 = 0x010d;
    pub const MESSAGE_ERROR: u64 = 0x010e;
    pub const VERSION_FALLBACK: u64 = 0x0110;
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
}

/// A malformed frame. Every one of these is fatal to the connection: unlike
/// HTTP/2, where a bad frame on one stream can be answered with RST_STREAM,
/// a length that does not line up desynchronises the stream permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameError(pub u64);

/// The largest varint QUIC can express: 2^62 - 1.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Bytes `v` occupies on the wire.
pub fn varint_len(v: u64) -> usize {
    match v {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// Appends `v` in the shortest form that holds it.
///
/// The encoding is not required to be minimal — a decoder must accept a padded
/// one — but emitting the shortest form is free here and keeps our own output
/// comparable byte-for-byte in tests.
pub fn put_varint(v: u64, out: &mut Vec<u8>) {
    debug_assert!(v <= VARINT_MAX, "varint {v} exceeds 2^62-1");
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Reads a varint from the front of `buf`.
///
/// `Ok(None)` means the buffer is short — the two most significant bits of the
/// first byte declare a width that has not arrived yet — and the caller should
/// keep what it has and read more. It is never an error, because on a QUIC
/// stream more bytes are always a possibility until the peer closes it.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    // The two length bits are not part of the value.
    let mut v = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        v = (v << 8) | *b as u64;
    }
    Some((v, len))
}

/// A frame's type and payload length, with the header size that produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub kind: u64,
    pub len: u64,
    /// Bytes the two varints occupied, so the caller can advance past them.
    pub head_len: usize,
}

/// Reads a frame header. `Ok(None)` means "incomplete, ask again".
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, FrameError> {
    let Some((kind, a)) = get_varint(buf) else {
        return Ok(None);
    };
    let Some((len, b)) = get_varint(&buf[a..]) else {
        return Ok(None);
    };
    // The HTTP/2 frame types that have no HTTP/3 meaning are not merely
    // unknown — RFC 9114 section 11.2.1 reserves them precisely so that an
    // HTTP/2 frame arriving here is diagnosed instead of silently skipped as
    // an extension.
    if is_reserved_h2(kind) {
        return Err(FrameError(code::FRAME_UNEXPECTED));
    }
    Ok(Some(Head { kind, len, head_len: a + b }))
}

/// The frame types RFC 9114 reserves because HTTP/2 used them.
pub fn is_reserved_h2(kind: u64) -> bool {
    matches!(kind, 0x02 | 0x06 | 0x08 | 0x09)
}

/// Reserved "grease" identifiers of the form `0x1f * N + 0x21`.
///
/// Peers emit these deliberately, as settings and as frames, to catch
/// implementations that only tolerate the identifiers they know. Both must be
/// ignored, which is the entire point of recognising them.
pub fn is_grease(v: u64) -> bool {
    v >= 0x21 && (v - 0x21) % 0x1f == 0
}

/// Writes a frame header followed by `payload`.
pub fn put_frame(kind: u64, payload: &[u8], out: &mut Vec<u8>) {
    put_varint(kind, out);
    put_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

/// Writes just a `DATA` header, for a body streamed rather than held.
pub fn put_data_head(len: u64, out: &mut Vec<u8>) {
    put_varint(kind::DATA, out);
    put_varint(len, out);
}

/// The settings we send and the ones we understand receiving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
    pub max_field_section_size: u64,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            // Zero is what makes the QPACK dynamic table legitimately absent
            // rather than unimplemented: a peer that is told the capacity is
            // zero may not send an insertion, so the encoder stream carries
            // nothing we would have to apply. See `super::qpack`.
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            // Mirrors the HTTP/1 and HTTP/2 header limits, so one oversized
            // request head is refused the same way whatever it arrives over.
            max_field_section_size: 64 * 1024,
        }
    }
}

impl Settings {
    /// Encodes the SETTINGS payload (not the frame header).
    pub fn encode(&self, out: &mut Vec<u8>) {
        for (id, v) in [
            (setting::QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity),
            (setting::QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams),
            (setting::MAX_FIELD_SECTION_SIZE, self.max_field_section_size),
        ] {
            put_varint(id, out);
            put_varint(v, out);
        }
    }

    /// Decodes a complete SETTINGS payload.
    pub fn decode(mut buf: &[u8]) -> Result<Settings, FrameError> {
        let mut s = Settings::default();
        // A peer that sends nothing is not the same as a peer that agrees with
        // our defaults, but the effect is identical and RFC 9114 says an
        // omitted setting keeps its initial value.
        while !buf.is_empty() {
            let (id, n) = get_varint(buf).ok_or(FrameError(code::SETTINGS_ERROR))?;
            buf = &buf[n..];
            let (v, n) = get_varint(buf).ok_or(FrameError(code::SETTINGS_ERROR))?;
            buf = &buf[n..];
            // The HTTP/2 settings identifiers are reserved here for the same
            // reason the frame types are, and carry a *different* error code
            // than an unknown one: this is a peer speaking the wrong protocol.
            if matches!(id, 0x02..=0x05) {
                return Err(FrameError(code::SETTINGS_ERROR));
            }
            match id {
                setting::QPACK_MAX_TABLE_CAPACITY => s.qpack_max_table_capacity = v,
                setting::QPACK_BLOCKED_STREAMS => s.qpack_blocked_streams = v,
                setting::MAX_FIELD_SECTION_SIZE => s.max_field_section_size = v,
                // Unknown and grease alike: ignored on purpose.
                _ => {}
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_width() {
        // One value per width, plus the boundaries where the width changes.
        for v in [0u64, 1, 0x3e, 0x3f, 0x40, 0x3ffe, 0x3fff, 0x4000, 0x3fff_fffe,
                  0x3fff_ffff, 0x4000_0000, VARINT_MAX]
        {
            let mut out = Vec::new();
            put_varint(v, &mut out);
            assert_eq!(out.len(), varint_len(v), "width disagrees for {v}");
            assert_eq!(get_varint(&out), Some((v, out.len())), "round trip failed for {v}");
        }
    }

    #[test]
    fn varint_widths_are_the_shortest_that_fit() {
        assert_eq!(varint_len(0x3f), 1);
        assert_eq!(varint_len(0x40), 2, "the 6-bit form is full at 0x3f");
        assert_eq!(varint_len(0x3fff), 2);
        assert_eq!(varint_len(0x4000), 4);
        assert_eq!(varint_len(0x3fff_ffff), 4);
        assert_eq!(varint_len(0x4000_0000), 8);
    }

    /// RFC 9000 appendix A.1 gives these exact encodings.
    #[test]
    fn the_rfc_sample_encodings_decode() {
        assert_eq!(get_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
                   Some((151_288_809_941_952_652, 8)));
        assert_eq!(get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(get_varint(&[0x25]), Some((37, 1)));
        // The same value in a longer-than-necessary form must still decode:
        // minimality is a rule for encoders, not a rule decoders may enforce.
        assert_eq!(get_varint(&[0x40, 0x25]), Some((37, 2)));
    }

    #[test]
    fn a_short_buffer_is_incomplete_not_invalid() {
        // The first byte promises eight; only three arrived.
        assert_eq!(get_varint(&[0xc2, 0x19, 0x7c]), None);
        assert_eq!(get_varint(&[]), None);
        // And the frame reader reports the same thing, rather than guessing.
        assert_eq!(parse_head(&[0x01]), Ok(None), "type read, length missing");
        assert_eq!(parse_head(&[]), Ok(None));
    }

    #[test]
    fn frame_heads_round_trip() {
        let mut out = Vec::new();
        put_frame(kind::HEADERS, b"payload", &mut out);
        let h = parse_head(&out).unwrap().expect("complete");
        assert_eq!(h.kind, kind::HEADERS);
        assert_eq!(h.len, 7);
        assert_eq!(&out[h.head_len..], b"payload");
    }

    #[test]
    fn the_http2_frame_types_are_rejected_not_skipped() {
        // An HTTP/2 speaker on an HTTP/3 connection should be told, not
        // silently tolerated as an unknown extension.
        for kind in [0x02u64, 0x06, 0x08, 0x09] {
            let mut out = Vec::new();
            put_frame(kind, b"", &mut out);
            assert_eq!(
                parse_head(&out),
                Err(FrameError(code::FRAME_UNEXPECTED)),
                "reserved type {kind:#x} must be a connection error"
            );
        }
    }

    #[test]
    fn unknown_frame_types_are_readable_so_they_can_be_skipped() {
        // The rule for a type we do not know is to skip its payload, which
        // means the header still has to parse.
        let mut out = Vec::new();
        put_frame(0x1f * 3 + 0x21, b"greased", &mut out);
        let h = parse_head(&out).unwrap().expect("complete");
        assert!(is_grease(h.kind));
        assert_eq!(h.len, 7);
    }

    #[test]
    fn grease_identifiers_are_recognised_and_ordinary_ones_are_not() {
        assert!(is_grease(0x21));
        assert!(is_grease(0x21 + 0x1f));
        assert!(is_grease(0x1f * 1000 + 0x21));
        assert!(!is_grease(kind::DATA));
        assert!(!is_grease(kind::SETTINGS));
        assert!(!is_grease(0x22));
    }

    #[test]
    fn settings_round_trip() {
        let s = Settings {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: 32 * 1024,
        };
        let mut out = Vec::new();
        s.encode(&mut out);
        assert_eq!(Settings::decode(&out), Ok(s));
    }

    #[test]
    fn unknown_settings_are_ignored_and_http2_ones_are_refused() {
        let mut out = Vec::new();
        put_varint(0x1f * 7 + 0x21, &mut out); // grease
        put_varint(12345, &mut out);
        put_varint(setting::MAX_FIELD_SECTION_SIZE, &mut out);
        put_varint(4096, &mut out);
        let s = Settings::decode(&out).expect("grease must be ignored, not fatal");
        assert_eq!(s.max_field_section_size, 4096);

        // ENABLE_PUSH, MAX_CONCURRENT_STREAMS and friends: reserved.
        for id in [0x02u64, 0x03, 0x04, 0x05] {
            let mut out = Vec::new();
            put_varint(id, &mut out);
            put_varint(1, &mut out);
            assert_eq!(Settings::decode(&out), Err(FrameError(code::SETTINGS_ERROR)));
        }
    }

    #[test]
    fn a_truncated_settings_payload_is_an_error() {
        // An identifier with no value: the frame said it was complete, so
        // unlike a stream read this cannot be "ask again".
        let mut out = Vec::new();
        put_varint(setting::MAX_FIELD_SECTION_SIZE, &mut out);
        assert_eq!(Settings::decode(&out), Err(FrameError(code::SETTINGS_ERROR)));
    }

    #[test]
    fn defaults_disable_the_qpack_dynamic_table() {
        // Load-bearing: the decoder is written on the assumption that a peer
        // cannot legally send an insertion, and this is what tells it so.
        assert_eq!(Settings::default().qpack_max_table_capacity, 0);
        assert_eq!(Settings::default().qpack_blocked_streams, 0);
    }
}

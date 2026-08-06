//! HTTP/2 framing (RFC 9113 section 4-6).
//!
//! Every frame is a 9-byte header and a payload. This module does the framing
//! and nothing else — it knows how to read a header, strip padding and encode
//! the small fixed-shape frames, but it holds no connection state and makes no
//! decisions about stream lifecycles. That belongs to [`super::conn`].

/// The fixed frame header size.
pub const HEADER_LEN: usize = 9;

/// The default and minimum `SETTINGS_MAX_FRAME_SIZE`.
pub const DEFAULT_MAX_FRAME: u32 = 16_384;

/// The largest `SETTINGS_MAX_FRAME_SIZE` a peer may negotiate.
pub const MAX_FRAME_LIMIT: u32 = 16_777_215;

/// The initial flow-control window for a stream and for the connection.
pub const DEFAULT_WINDOW: i64 = 65_535;

/// A window may never exceed this; going past it is a flow-control error.
pub const MAX_WINDOW: i64 = 2_147_483_647;

pub mod kind {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

pub mod flag {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1; // same bit, different frame types
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// RFC 9113 section 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Code {
    NoError = 0x0,
    Protocol = 0x1,
    Internal = 0x2,
    FlowControl = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSize = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    Compression = 0x9,
    Connect = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

pub mod setting {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// The connection preface every client sends first (RFC 9113 section 3.4).
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub len: u32,
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
}

impl Head {
    /// Parses a 9-byte frame header.
    pub fn parse(b: &[u8; HEADER_LEN]) -> Head {
        Head {
            len: u32::from_be_bytes([0, b[0], b[1], b[2]]),
            kind: b[3],
            flags: b[4],
            // The top bit is reserved and RFC 9113 section 4.1 says to ignore
            // it on receipt — not to reject the frame.
            stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        }
    }

    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes()[1..]);
        out.push(self.kind);
        out.push(self.flags);
        out.extend_from_slice(&self.stream.to_be_bytes());
    }
}

/// Writes a frame header followed by `payload`.
pub fn write_frame(kind: u8, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
    Head { len: payload.len() as u32, kind, flags, stream }.write(out);
    out.extend_from_slice(payload);
}

/// Strips the padding from a DATA or HEADERS payload.
///
/// Returns `None` when the pad length is at least the payload length. RFC 9113
/// section 6.1 calls that a connection error specifically: the padding would
/// have to eat its own length byte, so treating it as "no data" would let a
/// peer smuggle a frame past a length check.
pub fn unpad(payload: &[u8], padded: bool) -> Option<&[u8]> {
    if !padded {
        return Some(payload);
    }
    let pad = *payload.first()? as usize;
    let rest = &payload[1..];
    if pad > rest.len() {
        return None;
    }
    Some(&rest[..rest.len() - pad])
}

/// Builds a GOAWAY frame.
pub fn goaway(last_stream: u32, code: Code, debug: &str, out: &mut Vec<u8>) {
    let mut p = Vec::with_capacity(8 + debug.len());
    p.extend_from_slice(&last_stream.to_be_bytes());
    p.extend_from_slice(&(code as u32).to_be_bytes());
    p.extend_from_slice(debug.as_bytes());
    write_frame(kind::GOAWAY, 0, 0, &p, out);
}

/// Builds a RST_STREAM frame.
pub fn rst(stream: u32, code: Code, out: &mut Vec<u8>) {
    write_frame(kind::RST_STREAM, 0, stream, &(code as u32).to_be_bytes(), out);
}

/// Builds a WINDOW_UPDATE frame.
pub fn window_update(stream: u32, increment: u32, out: &mut Vec<u8>) {
    write_frame(kind::WINDOW_UPDATE, 0, stream, &increment.to_be_bytes(), out);
}

/// Builds a SETTINGS frame from `(id, value)` pairs.
pub fn settings(pairs: &[(u16, u32)], out: &mut Vec<u8>) {
    let mut p = Vec::with_capacity(pairs.len() * 6);
    for (id, v) in pairs {
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&v.to_be_bytes());
    }
    write_frame(kind::SETTINGS, 0, 0, &p, out);
}

pub fn settings_ack(out: &mut Vec<u8>) {
    write_frame(kind::SETTINGS, flag::ACK, 0, &[], out);
}

/// Reads a big-endian u32 from the front of a payload.
pub fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips() {
        let h = Head { len: 1234, kind: kind::DATA, flags: flag::END_STREAM, stream: 7 };
        let mut out = Vec::new();
        h.write(&mut out);
        assert_eq!(out.len(), HEADER_LEN);
        let back = Head::parse(&out[..HEADER_LEN].try_into().unwrap());
        assert_eq!(back, h);
    }

    #[test]
    fn the_reserved_stream_bit_is_ignored_not_rejected() {
        // RFC 9113 section 4.1. A peer that sets it is not making an error we
        // are allowed to fail on, and refusing would break interop for no gain.
        let bytes = [0, 0, 0, kind::DATA, 0, 0x80, 0, 0, 5];
        assert_eq!(Head::parse(&bytes).stream, 5);
    }

    #[test]
    fn padding_is_stripped() {
        // pad length 3, then "abc", then 3 pad bytes.
        let p = [3u8, b'a', b'b', b'c', 0, 0, 0];
        assert_eq!(unpad(&p, true).unwrap(), b"abc");
        assert_eq!(unpad(&p, false).unwrap(), &p[..]);
    }

    #[test]
    fn padding_that_would_eat_its_own_length_byte_is_refused() {
        // RFC 9113 section 6.1 makes this a connection error. Silently
        // returning an empty slice would let a peer hide a frame from any
        // length accounting we do.
        assert_eq!(unpad(&[5u8, b'a'], true), None);
        assert_eq!(unpad(&[1u8], true), None);
        assert_eq!(unpad(&[], true), None);
        // Exactly consuming the payload is legal: zero data, all padding.
        assert_eq!(unpad(&[2u8, 0, 0], true).unwrap(), b"");
    }

    #[test]
    fn goaway_carries_the_last_stream_and_code() {
        let mut out = Vec::new();
        goaway(9, Code::Protocol, "bad", &mut out);
        let h = Head::parse(&out[..HEADER_LEN].try_into().unwrap());
        assert_eq!(h.kind, kind::GOAWAY);
        assert_eq!(h.stream, 0, "GOAWAY is always on stream 0");
        assert_eq!(u32_at(&out[HEADER_LEN..], 0).unwrap(), 9);
        assert_eq!(u32_at(&out[HEADER_LEN..], 4).unwrap(), Code::Protocol as u32);
        assert_eq!(&out[HEADER_LEN + 8..], b"bad");
    }

    #[test]
    fn settings_pairs_are_six_bytes_each() {
        let mut out = Vec::new();
        settings(&[(setting::MAX_FRAME_SIZE, 16384), (setting::ENABLE_PUSH, 0)], &mut out);
        let h = Head::parse(&out[..HEADER_LEN].try_into().unwrap());
        assert_eq!(h.len, 12);
        assert_eq!(h.flags, 0, "a settings frame we send is never an ack");
    }

    #[test]
    fn u32_at_refuses_to_read_past_the_end() {
        assert_eq!(u32_at(&[0, 0, 0], 0), None);
        assert_eq!(u32_at(&[0, 0, 0, 1], 0), Some(1));
        assert_eq!(u32_at(&[0, 0, 0, 1], 1), None);
    }
}

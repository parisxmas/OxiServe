//! RFC 7541 Huffman coding for HPACK string literals.
//!
//! HPACK compresses header strings with a fixed canonical Huffman code — one
//! table, no per-connection state, so both sides agree without negotiating.
//! Decoding runs on input an unauthenticated peer chose, so it is written to
//! refuse rather than guess: an oversized decode, an EOS symbol in the stream,
//! or malformed padding are all errors, never a best effort.

/// `(code, bit length)` for symbols 0..=255 plus EOS at index 256.
const TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The EOS symbol. RFC 7541 section 5.2 requires a decoder to treat its
/// appearance in an encoded string as a decoding error, so it is never a
/// symbol we emit.
const EOS: usize = 256;

/// Encoded length in bytes, so a caller can decide whether Huffman is even
/// worth it before building the output.
pub fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input.iter().map(|&b| TABLE[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

/// Appends the Huffman encoding of `input` to `out`.
pub fn encode(input: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut n = 0u32; // bits held in `acc`
    for &b in input {
        let (code, len) = TABLE[b as usize];
        acc = (acc << len) | code as u64;
        n += len as u32;
        while n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    if n > 0 {
        // Pad with the EOS prefix, which is all ones. A decoder is required to
        // treat any other padding as an error, so this is not a free choice.
        let pad = 8 - n;
        out.push((((acc << pad) | ((1u64 << pad) - 1)) & 0xff) as u8);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HuffmanError;

/// Decodes a Huffman-coded string.
///
/// `limit` caps the output. A short encoded string can expand to many times
/// its length (the shortest code is 5 bits), so without a cap a small header
/// frame could be made to allocate without bound — the decompression-bomb
/// shape that HPACK is otherwise prone to.
pub fn decode(input: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), HuffmanError> {
    let tree = tree();
    let mut node = 0u16;
    let mut consumed_bits = 0u32;

    for &byte in input {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            let next = tree[node as usize].child[bit as usize];
            if next == NONE {
                return Err(HuffmanError);
            }
            node = next;
            let n = &tree[node as usize];
            if let Some(sym) = n.symbol {
                if sym as usize == EOS {
                    // An explicit EOS inside the string, which RFC 7541
                    // forbids: a peer that sends one is trying to see what we
                    // do with it.
                    return Err(HuffmanError);
                }
                if out.len() >= limit {
                    return Err(HuffmanError);
                }
                out.push(sym as u8);
                node = 0;
                consumed_bits = 0;
                continue;
            }
            consumed_bits += 1;
        }
    }

    // Whatever is left must be padding: at most 7 bits, and all ones. Longer
    // padding means a symbol was dropped; padding that is not the EOS prefix
    // means the encoder was doing something other than padding, and either way
    // accepting it would let two encodings mean the same header.
    if consumed_bits > 7 {
        return Err(HuffmanError);
    }
    if consumed_bits > 0 && !is_all_ones_prefix(node) {
        return Err(HuffmanError);
    }
    Ok(())
}

const NONE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Node {
    child: [u16; 2],
    symbol: Option<u16>,
}

/// The decoding tree, built once from [`TABLE`].
///
/// Built lazily rather than written out as a literal: a hand-transcribed tree
/// would be one more place for a typo that only shows up as a corrupted
/// header, and the RFC test vectors only validate the code table.
fn tree() -> &'static [Node] {
    use std::sync::OnceLock;
    static TREE: OnceLock<Vec<Node>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut nodes = vec![Node { child: [NONE, NONE], symbol: None }];
        for (sym, &(code, len)) in TABLE.iter().enumerate() {
            let mut cur = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                if nodes[cur].child[bit] == NONE {
                    nodes.push(Node { child: [NONE, NONE], symbol: None });
                    let idx = (nodes.len() - 1) as u16;
                    nodes[cur].child[bit] = idx;
                }
                cur = nodes[cur].child[bit] as usize;
            }
            nodes[cur].symbol = Some(sym as u16);
        }
        nodes
    })
}

/// True when the path from the root to `node` is all 1 bits — the only legal
/// padding, since it is a prefix of EOS.
fn is_all_ones_prefix(node: u16) -> bool {
    let tree = tree();
    let mut cur = 0u16;
    loop {
        if cur == node {
            return true;
        }
        let next = tree[cur as usize].child[1];
        if next == NONE {
            return false;
        }
        cur = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode(s, &mut v);
        v
    }

    fn dec(b: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut v = Vec::new();
        decode(b, 4096, &mut v)?;
        Ok(v)
    }

    /// RFC 7541 Appendix C.4 gives these encodings explicitly. They are the
    /// only real check that the 257-entry table above was transcribed
    /// correctly — a round trip would agree with itself even if every code
    /// were wrong.
    #[test]
    fn rfc_7541_test_vectors() {
        for (plain, hex) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("private", "aec3771a4b"),
            ("Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"),
            ("https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"),
        ] {
            let want: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(enc(plain.as_bytes()), want, "encoding {plain:?}");
            assert_eq!(dec(&want).unwrap(), plain.as_bytes(), "decoding {plain:?}");
        }
    }

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(dec(&enc(&all)).unwrap(), all);
        for b in 0..=255u8 {
            assert_eq!(dec(&enc(&[b])).unwrap(), vec![b], "byte {b}");
        }
    }

    #[test]
    fn encoded_len_matches_what_encode_produces() {
        for s in [&b""[..], b"a", b"www.example.com", b"\xff\xfe\x00", b"GET /index.html"] {
            assert_eq!(encoded_len(s), enc(s).len(), "for {s:?}");
        }
    }

    #[test]
    fn an_empty_string_encodes_to_nothing() {
        assert_eq!(enc(b""), Vec::<u8>::new());
        assert_eq!(dec(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn an_explicit_eos_is_a_decoding_error() {
        // RFC 7541 section 5.2 makes this mandatory. Accepting it would give
        // two encodings for the same header, which is exactly the ambiguity a
        // request smuggler looks for.
        let mut v = Vec::new();
        encode(b"a", &mut v);
        v.clear();
        // EOS is 30 bits of 1s followed by padding.
        v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(dec(&v), Err(HuffmanError));
    }

    #[test]
    fn padding_must_be_short_and_all_ones() {
        // "a" is 5 bits (0x3 << 3 | 0b111 = 0x1f), so one byte with all-ones
        // padding. Anything longer than 7 bits of leftover means a dropped
        // symbol.
        assert_eq!(dec(&[0x1f]).unwrap(), b"a");
        // Zero padding is not the EOS prefix.
        assert_eq!(dec(&[0x18]), Err(HuffmanError));
        // A whole byte of padding: more than 7 bits left over.
        assert_eq!(dec(&[0x1f, 0xff]), Err(HuffmanError));
    }

    #[test]
    fn the_output_limit_is_enforced() {
        // The shortest code is 5 bits, so encoded input can expand about 1.6x.
        // Without a cap a small frame could drive an unbounded allocation.
        let long = vec![b'0'; 1000];
        let encoded = enc(&long);
        let mut out = Vec::new();
        assert_eq!(decode(&encoded, 100, &mut out), Err(HuffmanError));
        let mut out = Vec::new();
        assert!(decode(&encoded, 1000, &mut out).is_ok());
    }
}

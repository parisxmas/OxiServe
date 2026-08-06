//! HPACK (RFC 7541): header compression for HTTP/2.
//!
//! HPACK is stateful in a way HTTP/1 headers never were — both ends keep a
//! dynamic table, and a header can be sent as a single index into it. That
//! makes decoding cheap and also makes it dangerous: the peer controls how
//! much state we keep and how much a small frame expands into. Three limits
//! bound that, and all three are enforced here rather than left to the caller:
//! the dynamic table's byte size, the decoded header list size, and the length
//! of any single string.
//!
//! A decoding error is fatal to the whole connection, not just one stream.
//! The tables would be out of sync afterwards, so every later frame would
//! decode to something neither end agreed on — RFC 7541 section 4.4 requires
//! the connection to go away.

use super::huffman;

/// RFC 7541 Appendix A. Index 0 is unused, so entry `i` sits at `STATIC[i-1]`.
#[rustfmt::skip]
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// RFC 7541 section 4.1: an entry costs its name and value plus 32 bytes of
/// notional overhead, so a table full of empty headers still has a bound.
const ENTRY_OVERHEAD: usize = 32;

/// Cap on a single decoded string. Generous next to any real header, small
/// enough that one cannot be used to force a large allocation on its own.
const MAX_STRING: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum HpackError {
    /// Malformed input: a bad index, a truncated field, an illegal integer.
    /// Fatal to the connection — the tables are now out of sync.
    Compression,
    /// The peer respected the wire format but exceeded a limit we set.
    TooLarge,
}

/// One decoded header. Owned, because the dynamic table it may have come from
/// can be evicted by the very next field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// The decoder's half of the shared state.
pub struct Decoder {
    /// Most recent first, which is the order indices count in.
    dynamic: std::collections::VecDeque<Header>,
    size: usize,
    /// Current limit, which the peer may lower with a dynamic table size
    /// update and we may lower via SETTINGS.
    max_size: usize,
    /// The value we advertised. A size update above this is a protocol error:
    /// the peer would be claiming more state than we agreed to keep.
    settings_max: usize,
}

impl Decoder {
    pub fn new(max_size: usize) -> Decoder {
        Decoder {
            dynamic: std::collections::VecDeque::new(),
            size: 0,
            max_size,
            settings_max: max_size,
        }
    }

    /// Applies a new `SETTINGS_HEADER_TABLE_SIZE` we are advertising.
    pub fn set_max_size(&mut self, n: usize) {
        self.settings_max = n;
        if self.max_size > n {
            self.max_size = n;
            self.evict();
        }
    }

    /// Decodes one header block into `out`.
    ///
    /// `max_list` bounds the total decoded size, counted the same way the
    /// table is (name + value + 32 per header). Without it a handful of
    /// one-byte indexed fields could expand into megabytes of header list —
    /// the HPACK bomb.
    pub fn decode(
        &mut self,
        mut buf: &[u8],
        max_list: usize,
        out: &mut Vec<Header>,
    ) -> Result<(), HpackError> {
        let mut listed = 0usize;
        // RFC 7541 section 4.2: a size update may only appear at the start of
        // a block. Allowing one later would give two encodings for the same
        // header list, and h2spec checks it.
        let mut seen_field = false;
        while let Some(&first) = buf.first() {
            if first & 0x80 != 0 {
                // 1xxxxxxx — indexed header field.
                let (idx, rest) = int(buf, 7)?;
                buf = rest;
                let h = self.lookup(idx)?;
                listed = charge(listed, &h, max_list)?;
                out.push(h);
                seen_field = true;
            } else if first & 0x40 != 0 {
                // 01xxxxxx — literal, and the peer wants it in the table.
                let (idx, rest) = int(buf, 6)?;
                let (h, rest) = self.literal(idx, rest)?;
                buf = rest;
                listed = charge(listed, &h, max_list)?;
                self.insert(h.clone());
                out.push(h);
                seen_field = true;
            } else if first & 0x20 != 0 {
                // 001xxxxx — dynamic table size update.
                if seen_field {
                    return Err(HpackError::Compression);
                }
                let (n, rest) = int(buf, 5)?;
                buf = rest;
                let n = n as usize;
                // The peer may shrink the table freely, but growing it past
                // what we advertised would mean holding state we never agreed
                // to. RFC 7541 section 6.3 makes that a decoding error.
                if n > self.settings_max {
                    return Err(HpackError::Compression);
                }
                self.max_size = n;
                self.evict();
            } else {
                // 0000xxxx never-indexed, or 0001xxxx without indexing. Both
                // decode identically; the difference only matters to a proxy
                // deciding what it may re-compress, and we never put a
                // never-indexed field into a table.
                let (idx, rest) = int(buf, 4)?;
                let (h, rest) = self.literal(idx, rest)?;
                buf = rest;
                listed = charge(listed, &h, max_list)?;
                out.push(h);
                seen_field = true;
            }
        }
        Ok(())
    }

    /// Reads a literal field's name (indexed or inline) and its value.
    fn literal<'a>(&self, idx: u64, buf: &'a [u8]) -> Result<(Header, &'a [u8]), HpackError> {
        let (name, buf) = if idx == 0 {
            let (n, rest) = string(buf)?;
            (n, rest)
        } else {
            (self.lookup(idx)?.name, buf)
        };
        let (value, buf) = string(buf)?;
        Ok((Header { name, value }, buf))
    }

    /// Resolves an index across the static table and then the dynamic one.
    fn lookup(&self, idx: u64) -> Result<Header, HpackError> {
        // Index 0 is not a header field; RFC 7541 section 6.1 forbids it.
        if idx == 0 {
            return Err(HpackError::Compression);
        }
        let i = idx as usize;
        if i <= STATIC.len() {
            let (n, v) = STATIC[i - 1];
            return Ok(Header { name: n.to_string(), value: v.to_string() });
        }
        self.dynamic
            .get(i - STATIC.len() - 1)
            .cloned()
            .ok_or(HpackError::Compression)
    }

    fn insert(&mut self, h: Header) {
        let cost = entry_size(&h);
        // RFC 7541 section 4.4: an entry larger than the whole table is not an
        // error — it empties the table and is simply not added.
        if cost > self.max_size {
            self.dynamic.clear();
            self.size = 0;
            return;
        }
        self.size += cost;
        self.dynamic.push_front(h);
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.dynamic.pop_back() {
                Some(h) => self.size -= entry_size(&h),
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
    }

    #[cfg(test)]
    fn table_size(&self) -> usize {
        self.size
    }
}

fn entry_size(h: &Header) -> usize {
    h.name.len() + h.value.len() + ENTRY_OVERHEAD
}

/// Adds a header to the running list total, refusing once it passes the cap.
fn charge(listed: usize, h: &Header, max: usize) -> Result<usize, HpackError> {
    let n = listed.saturating_add(entry_size(h));
    if n > max {
        return Err(HpackError::TooLarge);
    }
    Ok(n)
}

/// RFC 7541 section 5.1 prefixed integer.
///
/// `prefix` is how many bits of the first byte belong to the number. The
/// continuation is 7 bits per byte, and it is capped: a peer can otherwise
/// send an arbitrarily long run of continuation bytes, and a naive decoder
/// either overflows or spins.
fn int(buf: &[u8], prefix: u32) -> Result<(u64, &[u8]), HpackError> {
    let mask = (1u64 << prefix) - 1;
    let first = *buf.first().ok_or(HpackError::Compression)? as u64 & mask;
    if first < mask {
        return Ok((first, &buf[1..]));
    }
    let mut value = mask;
    let mut shift = 0u32;
    let mut i = 1;
    loop {
        let b = *buf.get(i).ok_or(HpackError::Compression)? as u64;
        i += 1;
        // Ten continuation bytes would already exceed u64; refusing at 63 bits
        // of shift keeps the arithmetic honest without a wrapping surprise.
        if shift >= 63 {
            return Err(HpackError::Compression);
        }
        value = value
            .checked_add((b & 0x7f) << shift)
            .ok_or(HpackError::Compression)?;
        if b & 0x80 == 0 {
            return Ok((value, &buf[i..]));
        }
        shift += 7;
    }
}

/// RFC 7541 section 5.2 string literal: a length-prefixed run of bytes, either
/// raw or Huffman coded.
fn string(buf: &[u8]) -> Result<(String, &[u8]), HpackError> {
    let huffman_coded = buf.first().ok_or(HpackError::Compression)? & 0x80 != 0;
    let (len, rest) = int(buf, 7)?;
    let len = len as usize;
    // A declared length reaching past the end of the block is malformed, not
    // merely large: there is no string there to read, and no later frame can
    // supply one because a header block is complete by the time it is decoded.
    // Reporting it as "too large" downgraded a connection error to a stream
    // reset, which is what h2spec 5.2.3 catches.
    if rest.len() < len {
        return Err(HpackError::Compression);
    }
    let (raw, rest) = rest.split_at(len);

    let bytes = if huffman_coded {
        let mut out = Vec::with_capacity(len * 2);
        huffman::decode(raw, MAX_STRING, &mut out).map_err(|_| HpackError::Compression)?;
        out
    } else {
        raw.to_vec()
    };
    // Header names and values are byte strings on the wire, but everything
    // downstream — routing, logging, variables — is `str`. A value that is not
    // UTF-8 is rejected rather than lossily repaired, because a repaired
    // header is one the client never sent.
    String::from_utf8(bytes).map_err(|_| HpackError::Compression).map(|s| (s, rest))
}

// ---------------------------------------------------------------------------

/// The encoder.
///
/// Deliberately simple: it indexes from the static table where it can and
/// otherwise emits a literal *without* indexing, so it keeps no dynamic table
/// of its own. That gives up some compression on repeated custom response
/// headers and buys back a per-connection allocation, an eviction policy, and
/// a class of bug where the two ends disagree about table state. Response
/// headers repeat far less than request headers do, which is what makes the
/// trade cheap.
pub struct Encoder {
    /// What the peer will let us store. Tracked so the size update we emit is
    /// legal, even though we never index dynamically.
    peer_max: usize,
    announced: bool,
}

impl Encoder {
    pub fn new(peer_max: usize) -> Encoder {
        Encoder { peer_max, announced: false }
    }

    pub fn set_peer_max(&mut self, n: usize) {
        if n != self.peer_max {
            self.peer_max = n;
            self.announced = false;
        }
    }

    /// Starts a header block, emitting a dynamic table size update if one is
    /// pending.
    ///
    /// Separate from [`Encoder::encode`] because RFC 7541 section 4.2 requires
    /// a size update to appear at the *start* of a block. Emitting it lazily
    /// from `encode` looked tidier until a SETTINGS frame arriving between two
    /// fields of the same block would have planted it in the middle — a
    /// compression error that kills the connection.
    pub fn begin_block(&mut self, out: &mut Vec<u8>) {
        if !self.announced {
            // Tell the peer we keep nothing. Without this it must assume the
            // default 4096 and reserve for it.
            self.announced = true;
            write_int(0, 5, 0x20, out);
        }
    }

    /// Appends an encoded header field. Call [`Encoder::begin_block`] first.
    pub fn encode(&mut self, name: &str, value: &str, out: &mut Vec<u8>) {
        // A full static match is one byte; a name-only match saves the name.
        if let Some(i) = STATIC.iter().position(|(n, v)| *n == name && *v == value) {
            write_int(i as u64 + 1, 7, 0x80, out);
            return;
        }
        match STATIC.iter().position(|(n, _)| *n == name) {
            Some(i) => write_int(i as u64 + 1, 4, 0x00, out),
            None => {
                out.push(0x00);
                write_string(name.as_bytes(), out);
            }
        }
        write_string(value.as_bytes(), out);
    }
}

fn write_int(mut v: u64, prefix: u32, flags: u8, out: &mut Vec<u8>) {
    let mask = (1u64 << prefix) - 1;
    if v < mask {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | mask as u8);
    v -= mask;
    while v >= 0x80 {
        out.push(((v & 0x7f) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_string(s: &[u8], out: &mut Vec<u8>) {
    // Huffman only when it actually helps. For short ASCII values it often
    // does not, and paying to encode something that then grows is worse than
    // sending it raw.
    let hlen = huffman::encoded_len(s);
    if hlen < s.len() {
        write_int(hlen as u64, 7, 0x80, out);
        huffman::encode(s, out);
    } else {
        write_int(s.len() as u64, 7, 0x00, out);
        out.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode_all(d: &mut Decoder, bytes: &[u8]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        d.decode(bytes, 1 << 20, &mut out).expect("decode");
        out.into_iter().map(|h| (h.name, h.value)).collect()
    }

    /// RFC 7541 Appendix C.3: three requests on one connection, no Huffman.
    /// The point of the sequence is that later requests depend on dynamic
    /// table state the earlier ones created, so it catches eviction and
    /// indexing bugs a single-block test cannot.
    #[test]
    fn rfc_7541_request_sequence_without_huffman() {
        let mut d = Decoder::new(4096);

        let first = decode_all(&mut d, &hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"));
        assert_eq!(
            first,
            [
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
        assert_eq!(d.table_size(), 57);

        let second = decode_all(&mut d, &hex("8286 84be 5808 6e6f 2d63 6163 6865"));
        assert_eq!(
            second,
            [
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ]
        );
        assert_eq!(d.table_size(), 110);

        let third = decode_all(
            &mut d,
            &hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
        );
        assert_eq!(
            third,
            [
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/index.html".into()),
                (":authority".into(), "www.example.com".into()),
                ("custom-key".into(), "custom-value".into()),
            ]
        );
        assert_eq!(d.table_size(), 164);
    }

    /// RFC 7541 Appendix C.4: the same sequence Huffman coded, which also
    /// exercises the Huffman decoder through the HPACK path.
    #[test]
    fn rfc_7541_request_sequence_with_huffman() {
        let mut d = Decoder::new(4096);
        let first = decode_all(&mut d, &hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"));
        assert_eq!(first.last().unwrap().1, "www.example.com");
        let second = decode_all(&mut d, &hex("8286 84be 5886 a8eb 1064 9cbf"));
        assert_eq!(second.last().unwrap(), &("cache-control".into(), "no-cache".into()));
        let third = decode_all(
            &mut d,
            &hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"),
        );
        assert_eq!(third.last().unwrap(), &("custom-key".into(), "custom-value".into()));
    }

    /// RFC 7541 Appendix C.5/C.6: responses with a table small enough that
    /// eviction actually happens mid-sequence.
    #[test]
    fn eviction_follows_the_rfc_response_sequence() {
        let mut d = Decoder::new(256);
        let first = decode_all(
            &mut d,
            &hex(
                "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
                 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
                 6c65 2e63 6f6d",
            ),
        );
        assert_eq!(first[0], (":status".into(), "302".into()));
        assert_eq!(d.table_size(), 222);

        let second = decode_all(&mut d, &hex("4803 3330 37c1 c0bf"));
        assert_eq!(second[0], (":status".into(), "307".into()));
        // The 302 entry was pushed out to make room.
        assert_eq!(d.table_size(), 222);
    }

    #[test]
    fn index_zero_is_rejected() {
        // Not a header field per RFC 7541 section 6.1, and a decoder that
        // treated it as one would read outside the static table.
        let mut d = Decoder::new(4096);
        let mut out = Vec::new();
        assert_eq!(d.decode(&[0x80], 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn an_out_of_range_index_is_rejected() {
        let mut d = Decoder::new(4096);
        let mut out = Vec::new();
        // 62 is the first dynamic slot, and the table is empty.
        assert_eq!(d.decode(&[0xbe], 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn a_truncated_field_is_rejected_rather_than_padded() {
        let mut d = Decoder::new(4096);
        // Literal with a declared 15-byte name and only 3 bytes present.
        let mut out = Vec::new();
        assert_eq!(
            d.decode(&hex("40 0f 61 62 63"), 1 << 20, &mut out),
            Err(HpackError::Compression)
        );
    }

    #[test]
    fn an_endless_integer_continuation_is_refused() {
        // Without a bound this either overflows or loops on input the peer
        // fully controls.
        let mut d = Decoder::new(4096);
        let mut bytes = vec![0xff, 0xff];
        bytes.extend(std::iter::repeat(0x80).take(64));
        bytes.push(0x00);
        let mut out = Vec::new();
        assert_eq!(d.decode(&bytes, 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn a_size_update_above_what_we_advertised_is_a_protocol_error() {
        // Otherwise the peer decides how much state we keep.
        let mut d = Decoder::new(4096);
        let mut out = Vec::new();
        // 001 prefix, value 8192.
        let mut b = Vec::new();
        write_int(8192, 5, 0x20, &mut b);
        assert_eq!(d.decode(&b, 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn a_size_update_after_a_field_is_a_decoding_error() {
        // RFC 7541 section 4.2 puts size updates at the start of a block.
        // Accepting one later would give two encodings for the same header
        // list, which is the ambiguity HPACK is otherwise careful to avoid.
        let mut d = Decoder::new(4096);
        let mut b = hex("82"); // :method GET
        write_int(0, 5, 0x20, &mut b);
        let mut out = Vec::new();
        assert_eq!(d.decode(&b, 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn a_size_update_within_the_limit_shrinks_and_evicts() {
        let mut d = Decoder::new(4096);
        decode_all(&mut d, &hex("4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"));
        assert!(d.table_size() > 0);
        let mut b = Vec::new();
        write_int(0, 5, 0x20, &mut b);
        let mut out = Vec::new();
        d.decode(&b, 1 << 20, &mut out).unwrap();
        assert_eq!(d.table_size(), 0);
    }

    #[test]
    fn a_header_list_bomb_is_refused() {
        // Sixty-two one-byte indexed fields would decode to a large header
        // list from a tiny frame. The cap is what stops it, and it must fire
        // before the allocation, not after.
        let mut d = Decoder::new(4096);
        decode_all(&mut d, &hex("4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"));
        let bomb = vec![0xbeu8; 4096]; // repeat the dynamic entry
        let mut out = Vec::new();
        assert_eq!(d.decode(&bomb, 8192, &mut out), Err(HpackError::TooLarge));
    }

    #[test]
    fn an_entry_too_big_for_the_table_empties_it_without_erroring() {
        // RFC 7541 section 4.4 is explicit that this is not an error.
        let mut d = Decoder::new(64);
        decode_all(&mut d, &hex("4003 6162 6303 7879 7a")); // small, fits
        assert!(d.table_size() > 0);
        let mut block = vec![0x40, 0x20];
        block.extend(std::iter::repeat(b'a').take(0x20));
        block.push(0x20);
        block.extend(std::iter::repeat(b'b').take(0x20));
        let mut out = Vec::new();
        d.decode(&block, 1 << 20, &mut out).unwrap();
        assert_eq!(d.table_size(), 0, "the oversized entry must clear the table");
    }

    #[test]
    fn a_non_utf8_value_is_rejected_rather_than_repaired() {
        // Everything downstream is `str`. Lossy decoding would hand routing
        // and logging a header the client never sent.
        let mut d = Decoder::new(4096);
        let mut out = Vec::new();
        assert_eq!(
            d.decode(&hex("40 03 61 62 63 02 ff fe"), 1 << 20, &mut out),
            Err(HpackError::Compression)
        );
    }

    /// h2spec 5.2.3, byte for byte. The value declares a length of 622462
    /// inside a thirteen-byte block. Malformed, not merely large — and the
    /// difference decides whether the connection dies or one stream does.
    #[test]
    fn h2spec_5_2_3_is_a_connection_level_decoding_error() {
        let mut d = Decoder::new(4096);
        let rep = hex("0085f2b24a87fffffffd25427f");
        let mut out = Vec::new();
        assert_eq!(d.decode(&rep, 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn a_huffman_string_reaching_the_eos_symbol_is_a_decoding_error() {
        // Thirty one-bits *is* EOS, which RFC 7541 section 5.2 forbids inside
        // a string — it must not be read as a long run of padding.
        let mut d = Decoder::new(4096);
        let mut block = vec![0x00, 0x06];
        block.extend_from_slice(b"x-test");
        block.push(0x87); // huffman, length 7
        block.extend_from_slice(&[0xff; 7]);
        let mut out = Vec::new();
        assert_eq!(d.decode(&block, 1 << 20, &mut out), Err(HpackError::Compression));
    }

    #[test]
    fn what_we_encode_decodes_back() {
        let mut e = Encoder::new(4096);
        let mut d = Decoder::new(4096);
        let headers = [
            (":status", "200"),
            ("content-type", "text/html; charset=utf-8"),
            ("content-length", "1234"),
            ("server", "oxiserve"),
            ("x-custom-header", "a value with spaces"),
            ("etag", "\"deadbeef\""),
            ("set-cookie", "a=1; Path=/; HttpOnly"),
        ];
        let mut buf = Vec::new();
        for (n, v) in headers {
            e.encode(n, v, &mut buf);
        }
        let mut out = Vec::new();
        d.decode(&buf, 1 << 20, &mut out).unwrap();
        let got: Vec<(String, String)> = out.into_iter().map(|h| (h.name, h.value)).collect();
        let want: Vec<(String, String)> =
            headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_full_static_match_costs_one_byte() {
        let mut e = Encoder::new(4096);
        let mut buf = Vec::new();
        e.encode(":status", "200", &mut buf);
        assert_eq!(buf, vec![0x88]);
    }

    #[test]
    fn the_size_update_leads_the_first_block_and_only_that_one() {
        let mut e = Encoder::new(4096);
        let mut a = Vec::new();
        e.begin_block(&mut a);
        e.encode(":status", "200", &mut a);
        assert_eq!(a, vec![0x20, 0x88], "the first block announces an empty table");

        let mut b = Vec::new();
        e.begin_block(&mut b);
        e.encode(":status", "200", &mut b);
        assert_eq!(b, vec![0x88], "later blocks must not repeat it");
    }

    #[test]
    fn encoding_never_indexes_so_the_peer_needs_no_table() {
        // The same header must produce the same bytes every time: if it did
        // not, we would be relying on table state we do not keep.
        let mut e = Encoder::new(4096);
        let mut warm = Vec::new();
        e.begin_block(&mut warm);

        let mut a = Vec::new();
        e.encode("x-thing", "value", &mut a);
        let mut b = Vec::new();
        e.encode("x-thing", "value", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn a_settings_change_mid_block_cannot_plant_an_update_in_the_middle() {
        // The failure this guards against kills the connection: a size update
        // is only legal at the start of a header block.
        let mut e = Encoder::new(4096);
        let mut block = Vec::new();
        e.begin_block(&mut block);
        e.encode(":status", "200", &mut block);
        e.set_peer_max(8192); // a SETTINGS frame arrives right here
        e.encode("server", "oxiserve", &mut block);

        let mut d = Decoder::new(4096);
        let mut out = Vec::new();
        d.decode(&block, 1 << 20, &mut out).expect("the block must stay decodable");
        assert_eq!(out.len(), 2);
    }
}

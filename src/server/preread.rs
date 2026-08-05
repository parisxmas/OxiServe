//! `ssl_preread` — reading a TLS ClientHello without terminating TLS.
//!
//! The point is to route on SNI while staying a byte pipe: we look at the
//! first handshake message, learn which host the client *intends* to talk to,
//! pick a backend, and then hand over every byte we read — including the ones
//! we inspected — untouched. No key, no certificate, no decryption; the
//! backend still sees a pristine handshake and completes TLS itself. That is
//! what lets one port front many TLS services, and it is one of the remaining
//! HAProxy gaps in [ADR-0001].
//!
//! Everything here parses bytes an unauthenticated peer chose, before any
//! trust exists, so the module is written to one rule: **no indexing and no
//! arithmetic on a length that has not been checked against what we actually
//! hold.** Every read goes through [`Cur`], which returns `None` rather than
//! panicking, and every `None` is a decision to stop — never a default value.
//! `fuzz/fuzz_targets/tls_preread.rs` drives [`parse`] with arbitrary bytes,
//! asserting that a prefix never parses to a different answer than the whole.
//!
//! [ADR-0001]: ../../docs/decisions/0001-load-balancer-scope.md

/// Result of looking at the bytes read so far.
#[derive(Debug, PartialEq, Eq)]
pub enum Preread {
    /// A complete ClientHello was parsed.
    Hello(Hello),
    /// Might still become a ClientHello; read more and ask again.
    Incomplete,
    /// Definitely not one — either the leading byte rules out TLS, or the
    /// structure is malformed. Both mean the same thing to the caller: stop
    /// reading and proxy the connection blind.
    NotTls,
}

/// What a ClientHello tells us.
///
/// Owned rather than borrowed from the read buffer. A ClientHello may arrive
/// split across TLS records, and then no field has a contiguous home in the
/// buffer to borrow from — the earlier attempt to keep slices meant hunting
/// for the value's bytes back in the original buffer, which finds *a* match
/// rather than *the* field. One small allocation per TLS connection is
/// nothing next to the handshake it precedes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hello {
    /// SNI, or empty when the client sent none. Matches
    /// `$ssl_preread_server_name`.
    pub server_name: String,
    /// ALPN protocol identifiers in the order offered.
    pub alpn: Vec<String>,
    /// The highest version the client offers, named as nginx names it:
    /// `TLSv1.3`, `TLSv1.2`, `TLSv1.1`, `TLSv1`, `SSLv3`. Empty if
    /// unrecognised.
    pub protocol: &'static str,
}

impl Hello {
    /// `$ssl_preread_alpn_protocols` — nginx joins them with commas.
    pub fn alpn_list(&self) -> String {
        self.alpn.join(",")
    }
}

const REC_HANDSHAKE: u8 = 0x16;
const MSG_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// A TLS record body may not exceed 2^14 bytes. A larger length field is a
/// broken or hostile peer, not a big handshake.
const MAX_RECORD: usize = 16384;

/// Parses `buf` as the start of a TLS connection.
///
/// `buf` is everything read so far, starting at the first byte the client
/// sent. Call it again with more bytes on [`Preread::Incomplete`].
pub fn parse(buf: &[u8]) -> Preread {
    // Cheapest possible rejection, and the one that matters most: a plain
    // protocol must not be made to wait for bytes it has no reason to send.
    // SMTP, MySQL and PostgreSQL all expect the *server* to speak first, so
    // blocking here would deadlock those connections rather than delay them.
    match buf.first() {
        None => return Preread::Incomplete,
        Some(&REC_HANDSHAKE) => {}
        Some(_) => return Preread::NotTls,
    }

    let parts = match records(buf) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // One record is the overwhelmingly common case and costs no copy.
    match parts.as_slice() {
        [one] => handshake(one).unwrap_or(Preread::Incomplete),
        many => handshake(&many.concat()).unwrap_or(Preread::Incomplete),
    }
}

/// Walks TLS records, collecting handshake payloads until they add up to a
/// whole message.
fn records(buf: &[u8]) -> Result<Vec<&[u8]>, Preread> {
    let mut c = Cur::new(buf);
    let mut parts: Vec<&[u8]> = Vec::new();

    loop {
        let Some(kind) = c.u8() else { return Err(Preread::Incomplete) };
        if kind != REC_HANDSHAKE {
            // Mid-stream, a non-handshake record means this was never the
            // handshake we took it for.
            return Err(Preread::NotTls);
        }
        // Legacy record version. Every TLS version — including 1.3, which
        // pins this field at 3,1 for middlebox compatibility — has major 3.
        let Some(major) = c.u8() else { return Err(Preread::Incomplete) };
        if c.u8().is_none() {
            return Err(Preread::Incomplete); // minor, unused
        }
        if major != 3 {
            return Err(Preread::NotTls);
        }
        let Some(len) = c.u16() else { return Err(Preread::Incomplete) };
        let len = len as usize;
        if len == 0 || len > MAX_RECORD {
            return Err(Preread::NotTls);
        }
        let Some(payload) = c.take(len) else { return Err(Preread::Incomplete) };
        parts.push(payload);

        let total: usize = parts.iter().map(|p| p.len()).sum();
        match declared_len(&parts) {
            // The message is all here.
            Some(need) if total >= need => return Ok(parts),
            // Either the 4-byte handshake header has not arrived yet, or the
            // declared length reaches past what we hold: another record must
            // follow.
            _ => {}
        }
        if c.remaining() == 0 {
            return Err(Preread::Incomplete);
        }
    }
}

/// Total bytes the handshake message claims to occupy, header included,
/// reading the 4-byte header across however many record payloads it spans.
fn declared_len(parts: &[&[u8]]) -> Option<usize> {
    let mut head = [0u8; 4];
    let mut n = 0;
    for p in parts {
        for &b in *p {
            head[n] = b;
            n += 1;
            if n == 4 {
                return Some(u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize + 4);
            }
        }
    }
    None
}

/// Parses the handshake message itself.
///
/// `None` means "truncated, come back with more". A structurally impossible
/// message returns `Some(NotTls)` instead: no amount of extra data would
/// repair it, so waiting would only stall the connection until the preread
/// timeout fires.
fn handshake(b: &[u8]) -> Option<Preread> {
    let mut c = Cur::new(b);
    if c.u8()? != MSG_CLIENT_HELLO {
        // A handshake that does not open with a ClientHello is not a client
        // opening a connection to us.
        return Some(Preread::NotTls);
    }
    let len = c.u24()? as usize;
    let body = c.take(len)?;
    let mut c = Cur::new(body);

    // legacy_version — the pre-1.3 way of announcing a version, and still the
    // only signal when supported_versions is absent.
    let legacy = c.u16()?;
    c.take(32)?; // random
    let sid_len = c.u8()? as usize;
    c.take(sid_len)?; // legacy_session_id, non-empty on resumption
    let cs_len = c.u16()? as usize;
    // Cipher suites come in pairs; an odd length cannot be repaired.
    if cs_len % 2 != 0 {
        return Some(Preread::NotTls);
    }
    c.take(cs_len)?;
    let comp_len = c.u8()? as usize;
    c.take(comp_len)?;

    let mut out = Hello { protocol: version_name(legacy), ..Hello::default() };

    // Extensions are optional: SSLv3 and early TLS 1.0 clients send none, and
    // such a client simply has no SNI to route on.
    if c.remaining() == 0 {
        return Some(Preread::Hello(out));
    }
    let ext_len = c.u16()? as usize;
    let exts = c.take(ext_len)?;
    let mut c = Cur::new(exts);

    while c.remaining() > 0 {
        let ty = c.u16()?;
        let len = c.u16()? as usize;
        let data = c.take(len)?;
        match ty {
            EXT_SERVER_NAME => {
                if let Some(n) = server_name(data) {
                    out.server_name = n.to_string();
                }
            }
            EXT_ALPN => {
                if let Some(list) = alpn(data) {
                    out.alpn = list;
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                // TLS 1.3 pins legacy_version at 1.2 and puts the truth here,
                // so this overrides rather than supplements.
                if let Some(v) = best_version(data) {
                    out.protocol = v;
                }
            }
            _ => {}
        }
    }
    Some(Preread::Hello(out))
}

/// RFC 6066 `ServerNameList`. Only `host_name` (type 0) is defined, and the
/// list may not repeat a type, so the first entry is the answer.
fn server_name(data: &[u8]) -> Option<&str> {
    let mut c = Cur::new(data);
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;
    let mut c = Cur::new(list);
    while c.remaining() > 0 {
        let ty = c.u8()?;
        let len = c.u16()? as usize;
        let name = c.take(len)?;
        if ty == 0 {
            // A hostname that is not UTF-8 is not a hostname. Decoding it
            // lossily would produce a routing key the client never sent, and
            // that key would go on to select a backend.
            return std::str::from_utf8(name).ok().filter(|s| !s.is_empty());
        }
    }
    None
}

/// RFC 7301 `ProtocolNameList`.
fn alpn(data: &[u8]) -> Option<Vec<String>> {
    let mut c = Cur::new(data);
    let list_len = c.u16()? as usize;
    let list = c.take(list_len)?;
    let mut c = Cur::new(list);
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let len = c.u8()? as usize;
        let p = c.take(len)?;
        // `ProtocolName` is `opaque<1..2^8-1>`: zero-length is not a protocol
        // the client offered. Keeping it would put a stray comma into
        // `$ssl_preread_alpn_protocols`, changing the string a `map` routes
        // on. Found by fuzzing.
        if p.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(p) {
            out.push(s.to_string());
        }
    }
    Some(out)
}

/// RFC 8446 `supported_versions`: the client's whole list. Ordered best-first
/// by convention but not by requirement, so take the maximum.
fn best_version(data: &[u8]) -> Option<&'static str> {
    let mut c = Cur::new(data);
    let len = c.u8()? as usize;
    if len % 2 != 0 {
        return None;
    }
    let list = c.take(len)?;
    let mut c = Cur::new(list);
    let mut best = 0u16;
    while c.remaining() > 0 {
        let v = c.u16()?;
        // GREASE values are deliberate garbage clients send to catch servers
        // that fail to ignore unknown versions. Taking the plain maximum
        // would report 0xdada as the protocol.
        if is_grease(v) {
            continue;
        }
        if v > best {
            best = v;
        }
    }
    let name = version_name(best);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// RFC 8701 reserves the sixteen values `0x0a0a`, `0x1a1a`, … `0xfafa`.
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

fn version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => "",
    }
}

/// A bounds-checked forward cursor. Every accessor returns `None` instead of
/// panicking, which is the whole safety argument of this module.
struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, i: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len() - self.i
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        // Written as a comparison against the remainder rather than
        // `self.i + n <= len`, which a hostile length could overflow.
        if n > self.remaining() {
            return None;
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        let s = self.take(3)?;
        Some(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello so the tests read as intent rather than hex.
    #[derive(Default)]
    struct Build {
        sni: Option<&'static str>,
        alpn: Vec<&'static str>,
        versions: Vec<u16>,
        legacy: Option<u16>,
        session_id: usize,
        no_extensions: bool,
    }

    impl Build {
        fn new() -> Build {
            Build::default()
        }
        fn sni(mut self, s: &'static str) -> Build {
            self.sni = Some(s);
            self
        }
        fn alpn(mut self, p: &[&'static str]) -> Build {
            self.alpn = p.to_vec();
            self
        }
        fn versions(mut self, v: &[u16]) -> Build {
            self.versions = v.to_vec();
            self
        }
        fn legacy(mut self, v: u16) -> Build {
            self.legacy = Some(v);
            self
        }
        fn session_id(mut self, n: usize) -> Build {
            self.session_id = n;
            self
        }
        fn without_extensions(mut self) -> Build {
            self.no_extensions = true;
            self
        }

        fn body(&self) -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&self.legacy.unwrap_or(0x0303).to_be_bytes());
            b.extend_from_slice(&[0x11; 32]); // random
            b.push(self.session_id as u8);
            b.extend(std::iter::repeat(0xab).take(self.session_id));
            b.extend_from_slice(&2u16.to_be_bytes()); // one cipher suite
            b.extend_from_slice(&[0x13, 0x01]);
            b.push(1); // one compression method
            b.push(0);
            if self.no_extensions {
                return b;
            }
            let mut ex = Vec::new();
            if let Some(s) = self.sni {
                ex.extend_from_slice(&ext(EXT_SERVER_NAME, &sni_data(s.as_bytes())));
            }
            if !self.alpn.is_empty() {
                let mut d = Vec::new();
                for p in &self.alpn {
                    d.push(p.len() as u8);
                    d.extend_from_slice(p.as_bytes());
                }
                ex.extend_from_slice(&ext(EXT_ALPN, &with_u16_len(&d)));
            }
            if !self.versions.is_empty() {
                let mut d = vec![(self.versions.len() * 2) as u8];
                for v in &self.versions {
                    d.extend_from_slice(&v.to_be_bytes());
                }
                ex.extend_from_slice(&ext(EXT_SUPPORTED_VERSIONS, &d));
            }
            b.extend_from_slice(&(ex.len() as u16).to_be_bytes());
            b.extend_from_slice(&ex);
            b
        }

        /// The handshake message, without record framing.
        fn handshake(&self) -> Vec<u8> {
            wrap_handshake(&self.body())
        }

        /// Wrapped in one record, as every real client sends it.
        fn build(&self) -> Vec<u8> {
            record(&self.handshake())
        }

        /// Split across two records at `at` — which a hostile peer may do.
        fn build_split(&self, at: usize) -> Vec<u8> {
            let h = self.handshake();
            let mut out = record(&h[..at]);
            out.extend_from_slice(&record(&h[at..]));
            out
        }
    }

    fn with_u16_len(d: &[u8]) -> Vec<u8> {
        let mut out = (d.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(d);
        out
    }

    fn sni_data(name: &[u8]) -> Vec<u8> {
        let mut entry = vec![0u8]; // host_name
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        with_u16_len(&entry)
    }

    fn ext(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut out = ty.to_be_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn wrap_handshake(body: &[u8]) -> Vec<u8> {
        let mut h = vec![MSG_CLIENT_HELLO];
        h.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        h.extend_from_slice(body);
        h
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![REC_HANDSHAKE, 3, 1];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    fn hello(buf: &[u8]) -> Hello {
        match parse(buf) {
            Preread::Hello(h) => h,
            other => panic!("expected a ClientHello, got {other:?}"),
        }
    }

    #[test]
    fn sni_is_extracted() {
        assert_eq!(hello(&Build::new().sni("api.example.com").build()).server_name, "api.example.com");
    }

    #[test]
    fn a_hello_without_sni_yields_an_empty_name() {
        assert_eq!(hello(&Build::new().build()).server_name, "");
    }

    #[test]
    fn alpn_is_extracted_in_the_order_offered() {
        let h = hello(&Build::new().sni("x.test").alpn(&["h2", "http/1.1"]).build());
        assert_eq!(h.alpn, ["h2", "http/1.1"]);
        assert_eq!(h.alpn_list(), "h2,http/1.1");
    }

    #[test]
    fn supported_versions_overrides_the_legacy_field() {
        // A TLS 1.3 client is required to write 1.2 in legacy_version, so
        // reading that field alone would under-report every modern client.
        let h = hello(&Build::new().legacy(0x0303).versions(&[0x0304, 0x0303]).build());
        assert_eq!(h.protocol, "TLSv1.3");
    }

    #[test]
    fn legacy_version_is_used_when_supported_versions_is_absent() {
        for (v, name) in
            [(0x0301u16, "TLSv1"), (0x0302, "TLSv1.1"), (0x0303, "TLSv1.2"), (0x0300, "SSLv3")]
        {
            assert_eq!(hello(&Build::new().legacy(v).build()).protocol, name, "legacy {v:#06x}");
        }
    }

    #[test]
    fn grease_versions_are_ignored() {
        // Clients send deliberate garbage here to catch servers that fail to
        // ignore unknown values. A plain maximum would report 0xdada.
        assert_eq!(hello(&Build::new().versions(&[0xdada, 0x0304, 0x0303]).build()).protocol, "TLSv1.3");
    }

    #[test]
    fn a_hello_with_no_extensions_at_all_still_parses() {
        // SSLv3 and early TLS 1.0 clients send none. Requiring the extensions
        // length would reject them instead of routing them to a default.
        let h = hello(&Build::new().legacy(0x0300).without_extensions().build());
        assert_eq!(h.protocol, "SSLv3");
        assert_eq!(h.server_name, "");
    }

    #[test]
    fn a_long_session_id_does_not_shift_the_parse() {
        // Resumption fills this in; a parser that assumed it empty would read
        // the cipher-suite length out of the middle of the session id.
        assert_eq!(hello(&Build::new().session_id(32).sni("resumed.x").build()).server_name, "resumed.x");
    }

    #[test]
    fn a_hello_split_across_records_is_reassembled() {
        let b = Build::new().sni("split.example.com").alpn(&["h2"]);
        // Split partway through, past where the SNI begins, so neither record
        // holds the field intact.
        let h = hello(&b.build_split(60));
        assert_eq!(h.server_name, "split.example.com");
        assert_eq!(h.alpn, ["h2"]);
    }

    #[test]
    fn a_hello_split_at_every_offset_reassembles_identically() {
        // The fragmentation boundary must not change the answer — including
        // when it lands inside the 4-byte handshake header, where the length
        // itself has to be read across records.
        let b = Build::new().sni("frag.example.com").alpn(&["h2", "http/1.1"]);
        let whole = hello(&b.build());
        let len = b.handshake().len();
        for at in 1..len {
            assert_eq!(hello(&b.build_split(at)), whole, "split at {at} changed the parse");
        }
    }

    #[test]
    fn every_truncation_of_a_valid_hello_asks_for_more_rather_than_guessing() {
        // The property that matters for a network parser: a prefix must never
        // produce an answer. Reporting an SNI from half a message would route
        // on data the client had not finished sending.
        let b = Build::new().sni("api.example.com").alpn(&["h2"]).build();
        for n in 1..b.len() {
            assert_eq!(parse(&b[..n]), Preread::Incomplete, "{n}-byte prefix of {}", b.len());
        }
        assert!(matches!(parse(&b), Preread::Hello(_)));
    }

    #[test]
    fn non_tls_traffic_is_rejected_on_the_very_first_byte() {
        // Correctness, not just speed: protocols where the server speaks first
        // would deadlock if we waited for a handshake never coming.
        for s in [&b"GET / HTTP/1.1\r\n"[..], b"HELO mail.example.com\r\n", b"\x00\x00\x00\x08\x04"] {
            assert_eq!(parse(s), Preread::NotTls, "{:?}", &s[..4.min(s.len())]);
        }
    }

    #[test]
    fn an_empty_buffer_is_incomplete_not_a_decision() {
        assert_eq!(parse(&[]), Preread::Incomplete);
    }

    #[test]
    fn structural_nonsense_is_rejected_rather_than_awaited() {
        // No further byte could make any of these valid, so waiting would
        // stall the connection until the preread timeout fires.
        assert_eq!(parse(&[REC_HANDSHAKE, 3, 1, 0xff, 0xff]), Preread::NotTls, "oversized record");
        assert_eq!(parse(&[REC_HANDSHAKE, 3, 1, 0, 0]), Preread::NotTls, "zero-length record");
        assert_eq!(parse(&[REC_HANDSHAKE, 9, 1, 0, 5, 1, 2, 3, 4, 5]), Preread::NotTls, "bad major");
        // A ServerHello arriving where a client should be.
        assert_eq!(parse(&record(&[0x02, 0, 0, 1, 0])), Preread::NotTls, "not a ClientHello");
    }

    #[test]
    fn a_length_field_that_overruns_its_container_is_not_believed() {
        // Claim a 64 KB extensions block inside a small record. The parser
        // must refuse; it must never read past the record it was handed.
        let mut body = Build::new().body();
        let n = body.len();
        body[n - 2..].copy_from_slice(&0xffffu16.to_be_bytes());
        assert!(!matches!(parse(&record(&wrap_handshake(&body))), Preread::Hello(_)));
    }

    #[test]
    fn an_odd_cipher_suite_length_is_refused() {
        let mut body = Build::new().body();
        // The cipher-suite length sits after version(2) + random(32) + sid(1).
        body[35..37].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(parse(&record(&wrap_handshake(&body))), Preread::NotTls);
    }

    #[test]
    fn a_non_utf8_sni_is_dropped_rather_than_repaired() {
        // A routing key built from lossily-decoded bytes is a key the client
        // never sent, and it would go on to select a backend.
        let mut body = Build::new().without_extensions().body();
        let ex = ext(EXT_SERVER_NAME, &sni_data(&[0xff, 0xfe]));
        body.extend_from_slice(&(ex.len() as u16).to_be_bytes());
        body.extend_from_slice(&ex);
        assert_eq!(hello(&record(&wrap_handshake(&body))).server_name, "");
    }

    #[test]
    fn empty_alpn_entries_are_dropped() {
        // Regression, found by fuzzing. An entry of length zero is malformed
        // per RFC 7301, and carrying it through would render
        // `$ssl_preread_alpn_protocols` as ",h2" — a routing key describing a
        // protocol list the client never sent.
        let mut body = Build::new().without_extensions().body();
        let list = [0u8, 2, b'h', b'2', 0];
        let ex = ext(EXT_ALPN, &with_u16_len(&list));
        body.extend_from_slice(&(ex.len() as u16).to_be_bytes());
        body.extend_from_slice(&ex);
        let h = hello(&record(&wrap_handshake(&body)));
        assert_eq!(h.alpn, ["h2"]);
        assert_eq!(h.alpn_list(), "h2");
    }

    #[test]
    fn unknown_and_grease_extensions_are_skipped() {
        // Real ClientHellos are full of extensions we do not care about, plus
        // GREASE ones with deliberately unassigned types.
        let mut body = Build::new().without_extensions().body();
        let mut ex = ext(0x0a0a, &[1, 2, 3]);
        ex.extend_from_slice(&ext(0x7fff, &[]));
        ex.extend_from_slice(&ext(EXT_SERVER_NAME, &sni_data(b"host.test")));
        body.extend_from_slice(&(ex.len() as u16).to_be_bytes());
        body.extend_from_slice(&ex);
        assert_eq!(hello(&record(&wrap_handshake(&body))).server_name, "host.test");
    }
}

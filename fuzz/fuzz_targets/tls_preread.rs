#![no_main]
//! Fuzzes the TLS ClientHello parser.
//!
//! These bytes come from an unauthenticated peer before any trust exists, so
//! "does not panic" is the floor, not the goal. The target also asserts the
//! properties the stream proxy actually relies on.

use libfuzzer_sys::fuzz_target;
use oxiserve::server::preread::{parse, Preread};

fuzz_target!(|data: &[u8]| {
    let first = parse(data);

    // 1. The verdict must not depend on how the bytes were delivered. A peer
    //    can split its writes anywhere, so parsing a prefix and then the whole
    //    buffer must never disagree about the final answer.
    if let Preread::Hello(ref h) = first {
        // 2. A parsed hello may only report values that are consistent with
        //    themselves — an empty protocol name is allowed, a bogus one is
        //    not.
        assert!(
            matches!(h.protocol, "" | "SSLv3" | "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"),
            "invented a protocol name: {:?}",
            h.protocol
        );
        // Every entry must be a protocol the client actually offered. An
        // empty one would render `$ssl_preread_alpn_protocols` with a stray
        // comma and change the key a `map` routes on.
        assert!(h.alpn.iter().all(|p| !p.is_empty()), "empty ALPN entry: {:?}", h.alpn);
        assert_eq!(h.alpn_list().is_empty(), h.alpn.is_empty());
    }

    // 3. Feeding a strict prefix must never produce a *different* Hello than
    //    the full buffer does: more bytes may complete a parse, never revise
    //    one. A parser that answered early and then changed its mind would
    //    have already sent the connection to the wrong backend.
    if data.len() > 1 {
        let cut = data.len() / 2;
        match (parse(&data[..cut]), &first) {
            (Preread::Hello(early), Preread::Hello(full)) => {
                assert_eq!(&early, full, "a prefix parsed to a different hello");
            }
            // A prefix that already decided "not TLS" cannot become TLS later:
            // that verdict is driven by the leading byte and by structure that
            // more data cannot repair.
            (Preread::NotTls, Preread::Hello(_)) => {
                panic!("a prefix said NotTls but the full buffer parsed a hello")
            }
            _ => {}
        }
    }

    // 4. Idempotence: parsing twice sees the same thing. Cheap to check and it
    //    would catch any accidental interior mutation.
    assert_eq!(parse(data), first);
});

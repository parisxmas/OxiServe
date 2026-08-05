#![no_main]
//! The cache entry decoder, fed arbitrary bytes.
//!
//! Cache files are attacker-influenced in a weaker but real sense: their
//! content comes from upstream responses, and a corrupted or truncated file on
//! disk must never take the server down or be served for the wrong key.
use libfuzzer_sys::fuzz_target;
use oxiserve::server::cache;

fuzz_target!(|data: &[u8]| {
    // Decoding under one key must never panic.
    if let Ok(d) = cache::decode_entry(data, "/the/key") {
        assert!(d.body.len() <= data.len(), "body longer than the file it came from");
        // A successful decode means the stored key matched, so decoding the
        // same bytes under a DIFFERENT key must be refused. This is what stops
        // a digest collision serving one URL's response for another.
        assert_eq!(
            cache::decode_entry(data, "/a/different/key"),
            Err(cache::DecodeError::KeyMismatch),
            "an entry decoded under the wrong key"
        );
    }
    // Every truncation of a valid-looking file must also be handled.
    if data.len() > 4 {
        let _ = cache::decode_entry(&data[..data.len() / 2], "/the/key");
    }
});

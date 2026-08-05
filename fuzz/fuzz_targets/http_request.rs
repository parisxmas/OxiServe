#![no_main]
//! The request parser, fed arbitrary bytes.
//!
//! This is the one parser that reads straight off a hostile socket, so it must
//! never panic, never hang, and never report a framing it did not actually
//! see. The assertions below encode the framing invariants that request
//! smuggling attacks exist to break.
use libfuzzer_sys::fuzz_target;
use oxiserve::http::request::{Body, ParseResult, Req};

fuzz_target!(|data: &[u8]| {
    let mut req = Req::new();
    match req.parse(data, 96) {
        ParseResult::Complete => {
            // A complete parse must have consumed a real prefix of the input.
            assert!(req.head_len <= data.len(), "head_len past end of input");
            assert!(req.head_len > 0, "complete parse consumed nothing");

            // Every recorded range must be inside the buffer, or a later
            // slice() would panic on a live connection.
            for h in &req.headers {
                assert!(h.name.end <= data.len() && h.value.end <= data.len());
                assert!(h.name.start <= h.name.end && h.value.start <= h.value.end);
            }
            assert!(req.target.end <= data.len());
            assert!(req.path.end <= data.len());
            assert!(req.query.end <= data.len());

            // Chunked and Content-Length must never both be accepted: that
            // ambiguity is the request-smuggling primitive.
            if req.body == Body::Chunked {
                let has_cl = req.headers.iter().any(|h| {
                    data[h.name.clone()].eq_ignore_ascii_case(b"content-length")
                });
                assert!(!has_cl, "accepted both Transfer-Encoding and Content-Length");
            }

            // Accessors must not panic on anything that parsed.
            let _ = req.path_str(data);
            let _ = req.query_str(data);
            let _ = req.target_str(data);
            let _ = req.host(data);
            let _ = req.accepts_gzip(data);
        }
        ParseResult::Partial | ParseResult::Error(_) => {}
    }
});

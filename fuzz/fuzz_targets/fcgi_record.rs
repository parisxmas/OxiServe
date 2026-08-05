#![no_main]
//! FastCGI record parsing. The bytes come from the application (php-fpm), so a
//! compromised or simply buggy backend must not be able to crash the server.
use libfuzzer_sys::fuzz_target;
use oxiserve::server::fcgi_proto as p;

fuzz_target!(|data: &[u8]| {
    // Walk the stream the way the real reader does.
    let mut off = 0usize;
    let mut guard = 0;
    while off < data.len() && guard < 10_000 {
        guard += 1;
        match p::parse_record(&data[off..]) {
            Ok(rec) => {
                assert!(rec.total > 0, "a zero-length record would loop forever");
                assert!(off + rec.total <= data.len(), "record claims to run past the buffer");
                assert!(rec.body.len() <= rec.total, "body larger than the record");
                off += rec.total;
            }
            Err(_) => break,
        }
    }
});

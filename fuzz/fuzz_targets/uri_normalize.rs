#![no_main]
//! URI normalisation — the boundary that decides whether a request can escape
//! the document root. A single missed case here is a path traversal.
use libfuzzer_sys::fuzz_target;
use oxiserve::http::uri;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (path, _query) = uri::split_query(s);

    if let Ok(norm) = uri::normalize(path) {
        // Whatever comes out is joined onto the document root, so these are
        // the properties that make that join safe.
        assert!(norm.starts_with('/'), "normalised path must be absolute: {norm:?}");
        assert!(!norm.contains('\0'), "NUL survived normalisation: {norm:?}");
        assert!(
            !norm.split('/').any(|seg| seg == ".." || seg == "."),
            "dot segment survived normalisation: {norm:?}"
        );
        assert!(!norm.contains("//"), "empty segment survived: {norm:?}");

        // Idempotence, but only where it is actually meaningful.
        //
        // Decoding is one-way by design: `/50%2525.html` decodes to
        // `/50%25.html`, and feeding THAT back in would decode again and give a
        // third answer. nginx behaves the same way and normalises exactly once
        // per request, which is what OxiServe does (a single call site in
        // conn.rs), so re-decoding is not a property the server relies on.
        //
        // When the output contains no `%`, though, a second pass must be a
        // no-op — that is a real invariant, and it is the assertion that caught
        // the UTF-8 corruption bug: mangled multi-byte characters changed on
        // every pass.
        if !norm.contains('%') {
            let again = uri::normalize(&norm).expect("a %-free normal path must re-normalise");
            assert_eq!(again, norm, "normalisation is not idempotent");
        }
    }
});

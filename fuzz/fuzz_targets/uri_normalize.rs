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

        // Normalisation must be idempotent: re-normalising must not change it,
        // or a second pass anywhere in the pipeline could produce a different
        // path than the one that was security-checked.
        let again = uri::normalize(&norm).expect("re-normalising a normal path must succeed");
        assert_eq!(again, norm, "normalisation is not idempotent");
    }
});

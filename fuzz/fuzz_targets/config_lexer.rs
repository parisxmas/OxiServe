#![no_main]
//! The nginx config lexer. Lower risk than the others — a config is trusted
//! input — but a panic here is still a startup crash on a typo, and the
//! quoting rules are subtle enough to be worth fuzzing.
use libfuzzer_sys::fuzz_target;
use oxiserve::config::lexer;
use std::path::Path;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let file: Arc<Path> = Arc::from(Path::new("<fuzz>"));
    let _ = lexer::tokenize(s, &file);
});

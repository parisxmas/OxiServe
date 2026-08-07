//! Link configuration for the optional `modsecurity` feature.
//!
//! Nothing here runs for a default build: without the feature the crate has no
//! C dependency at all, which is what keeps the released static musl binary a
//! single file. See `src/waf.rs` for why libmodsecurity is linked directly
//! rather than nginx's module for it being loaded.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MODSECURITY_LIB_DIR");

    // Features reach a build script as CARGO_FEATURE_<NAME>, which is more
    // dependable across cargo versions than cfg! inside the script itself.
    if std::env::var_os("CARGO_FEATURE_MODSECURITY").is_none() {
        return;
    }

    // An explicit path wins: a cross build, or a libmodsecurity compiled from
    // source, will not be in any of the guesses below.
    if let Some(dir) = std::env::var_os("MODSECURITY_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir.to_string_lossy());
    } else {
        // Homebrew and the upstream ./configure default. Distribution packages
        // land in the linker's default path and need no search entry, so a
        // miss here is not an error — the link step reports it if it matters.
        for dir in ["/opt/homebrew/opt/modsecurity/lib", "/usr/local/modsecurity/lib"] {
            if std::path::Path::new(dir).is_dir() {
                println!("cargo:rustc-link-search=native={dir}");
            }
        }
    }

    println!("cargo:rustc-link-lib=modsecurity");
}

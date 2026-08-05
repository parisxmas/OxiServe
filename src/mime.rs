//! Built-in MIME table, matching the defaults nginx ships in `mime.types`.
//!
//! A config's own `types { }` block is layered on top of this, so an
//! `include mime.types;` that resolves to the stock file is a no-op rather
//! than a difference in behaviour.

use crate::config::model::MimeTypes;

/// (mime type, extensions)
const DEFAULTS: &[(&str, &[&str])] = &[
    ("text/html", &["html", "htm", "shtml"]),
    ("text/css", &["css"]),
    ("text/xml", &["xml"]),
    ("text/plain", &["txt"]),
    ("text/markdown", &["md"]),
    ("text/vnd.wap.wml", &["wml"]),
    ("text/mathml", &["mml"]),
    ("image/gif", &["gif"]),
    ("image/jpeg", &["jpeg", "jpg"]),
    ("image/png", &["png"]),
    ("image/webp", &["webp"]),
    ("image/avif", &["avif"]),
    ("image/tiff", &["tif", "tiff"]),
    ("image/svg+xml", &["svg", "svgz"]),
    ("image/x-icon", &["ico"]),
    ("image/vnd.microsoft.icon", &["cur"]),
    ("image/x-ms-bmp", &["bmp"]),
    ("image/vnd.wap.wbmp", &["wbmp"]),
    ("image/x-jng", &["jng"]),
    ("application/javascript", &["js"]),
    ("application/json", &["json"]),
    ("application/ld+json", &["jsonld"]),
    ("application/manifest+json", &["webmanifest"]),
    ("application/wasm", &["wasm"]),
    ("application/atom+xml", &["atom"]),
    ("application/rss+xml", &["rss"]),
    ("application/pdf", &["pdf"]),
    ("application/postscript", &["ps", "eps", "ai"]),
    ("application/rtf", &["rtf"]),
    ("application/zip", &["zip"]),
    ("application/gzip", &["gz"]),
    ("application/x-7z-compressed", &["7z"]),
    ("application/x-rar-compressed", &["rar"]),
    ("application/x-bzip2", &["bz2"]),
    ("application/x-tar", &["tar"]),
    ("application/java-archive", &["jar", "war", "ear"]),
    ("application/x-x509-ca-cert", &["der", "pem", "crt"]),
    ("application/octet-stream", &["bin", "exe", "dll", "deb", "dmg", "iso", "img", "msi", "msp", "msm"]),
    ("application/vnd.ms-excel", &["xls"]),
    ("application/vnd.ms-powerpoint", &["ppt"]),
    ("application/msword", &["doc"]),
    (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        &["docx"],
    ),
    (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        &["xlsx"],
    ),
    (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        &["pptx"],
    ),
    ("font/woff", &["woff"]),
    ("font/woff2", &["woff2"]),
    ("font/ttf", &["ttf"]),
    ("font/otf", &["otf"]),
    ("application/vnd.ms-fontobject", &["eot"]),
    ("audio/midi", &["mid", "midi", "kar"]),
    ("audio/mpeg", &["mp3"]),
    ("audio/ogg", &["ogg", "opus"]),
    ("audio/x-m4a", &["m4a"]),
    ("audio/wav", &["wav"]),
    ("audio/flac", &["flac"]),
    ("video/mp4", &["mp4"]),
    ("video/mpeg", &["mpeg", "mpg"]),
    ("video/quicktime", &["mov"]),
    ("video/webm", &["webm"]),
    ("video/x-flv", &["flv"]),
    ("video/x-msvideo", &["avi"]),
    ("video/x-matroska", &["mkv"]),
    ("video/mp2t", &["ts"]),
    ("application/vnd.apple.mpegurl", &["m3u8"]),
];

pub fn load_defaults(m: &mut MimeTypes) {
    for (ty, exts) in DEFAULTS {
        for e in *exts {
            m.insert(e, ty);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_types_resolve() {
        let mut m = MimeTypes::default();
        load_defaults(&mut m);
        assert_eq!(&**m.lookup("/a/index.html").unwrap(), "text/html");
        assert_eq!(&**m.lookup("/x.css").unwrap(), "text/css");
        assert_eq!(&**m.lookup("/x.woff2").unwrap(), "font/woff2");
        assert!(m.lookup("/README").is_none());
    }
}

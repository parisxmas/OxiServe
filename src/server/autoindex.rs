//! Directory listings for `autoindex on`.
//!
//! The output mirrors nginx's HTML listing closely enough that scrapers and
//! directory-index clients written against nginx keep working.

use std::path::Path;

use super::ctx::Ctx;
use super::reply::{Body, Reply};
use crate::http::response::Resp;
use crate::http::uri::{encode_path, escape_html};

/// nginx pads the displayed name to this width before the date column.
const NAME_WIDTH: usize = 50;

pub async fn render(ctx: &mut Ctx<'_>, dir: &Path) -> Result<Reply, u16> {
    let mut entries: Vec<(String, bool, u64, std::time::SystemTime)> = Vec::new();

    let rd = std::fs::read_dir(dir).map_err(|e| super::files::io_status(&e))?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // nginx hides dotfiles from listings.
        if name.starts_with('.') {
            continue;
        }
        let Ok(m) = e.metadata() else { continue };
        entries.push((
            name,
            m.is_dir(),
            m.len(),
            m.modified().unwrap_or(std::time::UNIX_EPOCH),
        ));
    }
    // Directories first, then names — the ordering nginx produces.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut h = String::with_capacity(1024 + entries.len() * 128);
    let mut title = String::new();
    escape_html(&ctx.uri, &mut title);

    h.push_str("<html>\r\n<head><title>Index of ");
    h.push_str(&title);
    h.push_str("</title></head>\r\n<body>\r\n<h1>Index of ");
    h.push_str(&title);
    h.push_str("</h1><hr><pre><a href=\"../\">../</a>\r\n");

    for (name, is_dir, size, mtime) in &entries {
        let mut href = String::new();
        encode_path(name, &mut href);
        if *is_dir {
            href.push('/');
        }

        let mut display = String::new();
        escape_html(name, &mut display);
        if *is_dir {
            display.push('/');
        }

        h.push_str("<a href=\"");
        h.push_str(&href);
        h.push_str("\">");
        // nginx truncates long names with an ellipsis rather than wrapping.
        if display.chars().count() > NAME_WIDTH {
            let truncated: String = display.chars().take(NAME_WIDTH - 3).collect();
            h.push_str(&truncated);
            h.push_str("..&gt;");
        } else {
            h.push_str(&display);
        }
        h.push_str("</a>");

        let shown = display.chars().count().min(NAME_WIDTH);
        for _ in shown..NAME_WIDTH + 1 {
            h.push(' ');
        }

        h.push_str(&crate::http::date::http_date(*mtime).replace("GMT", "").trim_end().to_string());
        h.push_str("  ");
        if *is_dir {
            h.push_str("                   -");
        } else {
            let s = size.to_string();
            for _ in s.len()..20 {
                h.push(' ');
            }
            h.push_str(&s);
        }
        h.push_str("\r\n");
    }

    h.push_str("</pre><hr></body>\r\n</html>\r\n");

    let mut resp = Resp::new();
    let charset = ctx
        .server
        .core
        .charset
        .as_deref()
        .unwrap_or("utf-8");
    resp.header("Content-Type", &format!("text/html; charset={charset}"));
    Ok(Reply::new(resp, Body::Bytes(h.into_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_escaped_in_both_href_and_text() {
        // A file literally named `a<b>&c "d"` must not break out of either
        // the attribute or the text node.
        let mut href = String::new();
        encode_path("a<b>&c \"d\"", &mut href);
        assert!(!href.contains('<'));
        assert!(!href.contains('"'));

        let mut text = String::new();
        escape_html("a<b>&c \"d\"", &mut text);
        assert_eq!(text, "a&lt;b&gt;&amp;c &quot;d&quot;");
    }
}

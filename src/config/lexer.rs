//! Tokenizer for the nginx configuration grammar.
//!
//! nginx's own lexer (`ngx_conf_read_token`) is character driven with a handful
//! of quoting rules. We reproduce them here rather than approximating, because
//! real-world configs lean on the corners: `"` and `'` quoting, backslash
//! escapes inside quotes, `#` comments that stop at a newline, and tokens that
//! butt directly against `;` / `{` / `}` without whitespace.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// A bare or quoted word. Quotes and escapes are already resolved.
    Word(String),
    /// `{`
    Open,
    /// `}`
    Close,
    /// `;`
    Semi,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
    /// True when the word arrived in quotes. nginx uses this to decide whether
    /// a token is eligible for variable expansion in a few directives.
    pub quoted: bool,
}

#[derive(Debug)]
pub struct LexError {
    pub msg: String,
    pub line: u32,
    pub file: Arc<Path>,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {}:{}", self.msg, self.file.display(), self.line)
    }
}

impl std::error::Error for LexError {}

pub fn tokenize(src: &str, file: &Arc<Path>) -> Result<Vec<Token>, LexError> {
    Lexer {
        b: src.as_bytes(),
        i: 0,
        line: 1,
        file: file.clone(),
    }
    .run()
}

struct Lexer<'a> {
    b: &'a [u8],
    i: usize,
    line: u32,
    file: Arc<Path>,
}

impl<'a> Lexer<'a> {
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, LexError> {
        Err(LexError {
            msg: msg.into(),
            line: self.line,
            file: self.file.clone(),
        })
    }

    fn run(mut self) -> Result<Vec<Token>, LexError> {
        let mut out = Vec::new();
        loop {
            self.skip_trivia();
            if self.i >= self.b.len() {
                return Ok(out);
            }
            let line = self.line;
            match self.b[self.i] {
                b'{' => {
                    self.i += 1;
                    out.push(Token { tok: Tok::Open, line, quoted: false });
                }
                b'}' => {
                    self.i += 1;
                    out.push(Token { tok: Tok::Close, line, quoted: false });
                }
                b';' => {
                    self.i += 1;
                    out.push(Token { tok: Tok::Semi, line, quoted: false });
                }
                b'"' | b'\'' => {
                    let q = self.b[self.i];
                    let w = self.quoted_word(q)?;
                    out.push(Token { tok: Tok::Word(w), line, quoted: true });
                }
                _ => {
                    let w = self.bare_word()?;
                    out.push(Token { tok: Tok::Word(w), line, quoted: false });
                }
            }
        }
    }

    fn skip_trivia(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'\n' => {
                    self.line += 1;
                    self.i += 1;
                }
                b' ' | b'\t' | b'\r' => self.i += 1,
                b'#' => {
                    while self.i < self.b.len() && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// Reads a `"`/`'` delimited word. A backslash suppresses the special
    /// meaning of the following byte during scanning; the byte pair is then
    /// resolved by [`unescape`].
    fn quoted_word(&mut self, quote: u8) -> Result<String, LexError> {
        self.i += 1; // opening quote
        let start = self.i;
        loop {
            if self.i >= self.b.len() {
                return self.err("unterminated quoted string");
            }
            let c = self.b[self.i];
            if c == b'\\' && self.i + 1 < self.b.len() {
                if self.b[self.i + 1] == b'\n' {
                    self.line += 1;
                }
                self.i += 2;
                continue;
            }
            if c == quote {
                let raw = &self.b[start..self.i];
                self.i += 1;
                // nginx requires a delimiter after a closing quote.
                if self.i < self.b.len() && !is_delim(self.b[self.i]) {
                    return self.err("unexpected character after quoted string");
                }
                return Ok(unescape(raw));
            }
            if c == b'\n' {
                self.line += 1;
            }
            self.i += 1;
        }
    }

    /// Reads an unquoted word, stopping at whitespace or any of `;{}`.
    /// A backslash prevents the next byte from terminating the word.
    fn bare_word(&mut self) -> Result<String, LexError> {
        let start = self.i;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c == b'\\' && self.i + 1 < self.b.len() {
                self.i += 2;
                continue;
            }
            if is_delim(c) {
                break;
            }
            self.i += 1;
        }
        if self.i == start {
            return self.err(format!("unexpected character '{}'", self.b[self.i] as char));
        }
        Ok(unescape(&self.b[start..self.i]))
    }
}

/// Resolves backslash escapes exactly as nginx's `ngx_conf_read_token` does.
///
/// Only `\"`, `\'` and `\\` drop the backslash, and only `\t`, `\r`, `\n`
/// become control characters. **Every other** `\x` keeps both bytes — which is
/// why `location ~ \.php$` reaches the regex engine with its backslash intact
/// rather than silently degrading to "any character".
fn unescape(raw: &[u8]) -> String {
    if !raw.contains(&b'\\') {
        return raw.iter().map(|&c| c as char).collect();
    }
    let mut s = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' && i + 1 < raw.len() {
            match raw[i + 1] {
                b'"' | b'\'' | b'\\' => {
                    s.push(raw[i + 1] as char);
                    i += 2;
                    continue;
                }
                b't' => {
                    s.push('\t');
                    i += 2;
                    continue;
                }
                b'r' => {
                    s.push('\r');
                    i += 2;
                    continue;
                }
                b'n' => {
                    s.push('\n');
                    i += 2;
                    continue;
                }
                // Anything else: the backslash is data, and so is the byte
                // after it. Fall through and copy this byte only.
                _ => {}
            }
        }
        s.push(raw[i] as char);
        i += 1;
    }
    s
}

#[inline]
fn is_delim(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{' | b'}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(s: &str) -> Vec<Tok> {
        let p: Arc<Path> = Arc::from(Path::new("<test>"));
        tokenize(s, &p).unwrap().into_iter().map(|t| t.tok).collect()
    }

    fn words(s: &str) -> Vec<String> {
        lex(s)
            .into_iter()
            .filter_map(|t| match t {
                Tok::Word(w) => Some(w),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn simple_directive() {
        assert_eq!(
            lex("worker_processes auto;"),
            vec![
                Tok::Word("worker_processes".into()),
                Tok::Word("auto".into()),
                Tok::Semi
            ]
        );
    }

    #[test]
    fn comments_are_skipped() {
        assert_eq!(words("# a comment\nfoo bar; # trailing\n"), ["foo", "bar"]);
    }

    #[test]
    fn hash_inside_quotes_is_literal() {
        assert_eq!(words(r#"add_header X "a#b";"#), ["add_header", "X", "a#b"]);
    }

    #[test]
    fn tokens_may_abut_delimiters() {
        assert_eq!(
            lex("location /{return 404;}"),
            vec![
                Tok::Word("location".into()),
                Tok::Word("/".into()),
                Tok::Open,
                Tok::Word("return".into()),
                Tok::Word("404".into()),
                Tok::Semi,
                Tok::Close,
            ]
        );
    }

    #[test]
    fn quote_and_backslash_escapes_are_resolved() {
        assert_eq!(words(r#"a "x\"y" 'p\'q';"#), ["a", "x\"y", "p'q"]);
        assert_eq!(words(r#"a "x\\y";"#), ["a", r"x\y"]);
    }

    #[test]
    fn control_escapes_become_control_characters() {
        assert_eq!(words(r#"log_format m "a\tb\r\n";"#), ["log_format", "m", "a\tb\r\n"]);
    }

    // nginx keeps the backslash for every escape it does not recognise. If we
    // stripped it, `\.` in a location regex would become "any character" and
    // silently match more than the config author asked for.
    #[test]
    fn unrecognised_escapes_keep_their_backslash() {
        assert_eq!(words(r"location ~ \.php$;"), ["location", "~", r"\.php$"]);
        assert_eq!(words(r"a b\;c;"), ["a", r"b\;c"]);
        assert_eq!(words(r#"a "\d+";"#), ["a", r"\d+"]);
    }

    #[test]
    fn backslash_hides_a_delimiter_from_the_scanner() {
        // The `\;` must not end the directive.
        assert_eq!(
            lex(r"a b\;c;"),
            vec![Tok::Word("a".into()), Tok::Word(r"b\;c".into()), Tok::Semi]
        );
    }

    #[test]
    fn log_format_spanning_lines() {
        let w = words("log_format main '$remote_addr'\n  '$request';");
        assert_eq!(w, ["log_format", "main", "$remote_addr", "$request"]);
    }

    #[test]
    fn unterminated_quote_is_an_error() {
        let p: Arc<Path> = Arc::from(Path::new("<test>"));
        assert!(tokenize("foo \"bar;", &p).is_err());
    }
}

//! Parses a token stream into nginx's directive tree, expanding `include`
//! along the way.
//!
//! The AST is deliberately untyped: every directive is a name plus arguments
//! plus an optional block. That is exactly nginx's own model, and it means an
//! unknown directive is a *representable* thing we can report precisely rather
//! than a parse failure.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::lexer::{tokenize, Tok, Token};

#[derive(Debug, Clone)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub block: Option<Vec<Directive>>,
    pub line: u32,
    pub file: Arc<Path>,
}

impl Directive {
    pub fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(|s| s.as_str())
    }

    /// `file:line` prefix used in every diagnostic we emit.
    pub fn loc(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }

    pub fn children(&self) -> &[Directive] {
        self.block.as_deref().unwrap_or(&[])
    }

    /// First child block directive with the given name.
    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.children().iter().find(|d| d.name == name)
    }

    pub fn find_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Directive> {
        self.children().iter().filter(move |d| d.name == name)
    }
}

#[derive(Debug)]
pub struct ParseError {
    pub msg: String,
    pub line: u32,
    pub file: Arc<Path>,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {}:{}", self.msg, self.file.display(), self.line)
    }
}

impl std::error::Error for ParseError {}

/// Parses `path` and every file it includes, returning the top-level directives.
pub fn parse_file(path: &Path) -> Result<Vec<Directive>, ParseError> {
    let mut seen = HashSet::new();
    parse_file_inner(path, &mut seen, 0)
}

/// nginx does not enforce an include depth limit, but a config that includes
/// itself through a glob would otherwise spin forever.
const MAX_INCLUDE_DEPTH: usize = 32;

fn parse_file_inner(
    path: &Path,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<Vec<Directive>, ParseError> {
    let file: Arc<Path> = Arc::from(path);
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    if depth > MAX_INCLUDE_DEPTH {
        return Err(ParseError {
            msg: "include nesting too deep (cycle?)".into(),
            line: 0,
            file,
        });
    }
    if !seen.insert(canon) {
        // Same file reached twice on this branch: almost certainly a cycle.
        return Err(ParseError {
            msg: format!("recursive include of {}", path.display()),
            line: 0,
            file,
        });
    }

    let src = std::fs::read_to_string(path).map_err(|e| ParseError {
        msg: format!("cannot read config: {e}"),
        line: 0,
        file: file.clone(),
    })?;

    let tokens = tokenize(&src, &file).map_err(|e| ParseError {
        msg: e.msg,
        line: e.line,
        file: e.file,
    })?;

    let mut p = Parser {
        t: &tokens,
        i: 0,
        file: file.clone(),
        base: path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        seen,
        depth,
    };
    let out = p.block(true)?;
    p.seen.remove(&path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    Ok(out)
}

struct Parser<'a> {
    t: &'a [Token],
    i: usize,
    file: Arc<Path>,
    base: PathBuf,
    seen: &'a mut HashSet<PathBuf>,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn line(&self) -> u32 {
        self.t
            .get(self.i)
            .or_else(|| self.t.last())
            .map(|t| t.line)
            .unwrap_or(0)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            msg: msg.into(),
            line: self.line(),
            file: self.file.clone(),
        })
    }

    /// Parses directives until `}` (or EOF at the top level).
    fn block(&mut self, top: bool) -> Result<Vec<Directive>, ParseError> {
        let mut out = Vec::new();
        loop {
            let Some(t) = self.t.get(self.i) else {
                if top {
                    return Ok(out);
                }
                return self.err("unexpected end of file, expecting \"}\"");
            };

            match &t.tok {
                Tok::Close => {
                    if top {
                        return self.err("unexpected \"}\"");
                    }
                    self.i += 1;
                    return Ok(out);
                }
                Tok::Semi => return self.err("unexpected \";\""),
                Tok::Open => return self.err("unexpected \"{\""),
                Tok::Word(_) => {
                    let d = self.directive()?;
                    // `include` splices the included file's directives in place.
                    if d.name == "include" && d.block.is_none() {
                        out.extend(self.expand_include(&d)?);
                    } else {
                        out.push(d);
                    }
                }
            }
        }
    }

    fn directive(&mut self) -> Result<Directive, ParseError> {
        let line = self.line();
        let Tok::Word(name) = self.t[self.i].tok.clone() else {
            return self.err("expected directive name");
        };
        self.i += 1;

        let mut args = Vec::new();
        loop {
            let Some(t) = self.t.get(self.i) else {
                return self.err(format!("unexpected end of file, expecting \";\" or \"}}\" after \"{name}\""));
            };
            match &t.tok {
                Tok::Word(w) => {
                    args.push(w.clone());
                    self.i += 1;
                }
                Tok::Semi => {
                    self.i += 1;
                    return Ok(Directive { name, args, block: None, line, file: self.file.clone() });
                }
                Tok::Open => {
                    self.i += 1;
                    let block = self.block(false)?;
                    return Ok(Directive { name, args, block: Some(block), line, file: self.file.clone() });
                }
                Tok::Close => {
                    return self.err(format!("directive \"{name}\" is not terminated by \";\""));
                }
            }
        }
    }

    fn expand_include(&mut self, d: &Directive) -> Result<Vec<Directive>, ParseError> {
        if d.args.len() != 1 {
            return Err(ParseError {
                msg: "invalid number of arguments in \"include\" directive".into(),
                line: d.line,
                file: d.file.clone(),
            });
        }
        let pat = &d.args[0];
        let abs = if Path::new(pat).is_absolute() {
            PathBuf::from(pat)
        } else {
            self.base.join(pat)
        };
        let pat_str = abs.to_string_lossy().to_string();

        // A literal path must exist; a glob that matches nothing is not an
        // error, which is how nginx behaves for `include conf.d/*.conf`.
        let is_glob = pat_str.contains(['*', '?', '[']);
        let mut paths: Vec<PathBuf> = if is_glob {
            let g = glob::glob(&pat_str).map_err(|e| ParseError {
                msg: format!("bad include pattern: {e}"),
                line: d.line,
                file: d.file.clone(),
            })?;
            g.filter_map(Result::ok).collect()
        } else {
            vec![abs]
        };
        paths.sort();

        let mut out = Vec::new();
        for p in paths {
            let sub = parse_file_inner(&p, self.seen, self.depth + 1).map_err(|e| {
                // Point at the include site when the included file itself is
                // missing; keep the inner location for real syntax errors.
                if e.line == 0 && e.msg.starts_with("cannot read") {
                    ParseError {
                        msg: format!("{} (included here)", e.msg),
                        line: d.line,
                        file: d.file.clone(),
                    }
                } else {
                    e
                }
            })?;
            out.extend(sub);
        }
        Ok(out)
    }
}

/// Renders the tree back to nginx syntax — this is what `oxiserve -T` prints.
pub fn dump(dirs: &[Directive], indent: usize, out: &mut String) {
    for d in dirs {
        for _ in 0..indent {
            out.push_str("    ");
        }
        out.push_str(&d.name);
        for a in &d.args {
            out.push(' ');
            if a.is_empty() || a.contains(|c: char| c.is_whitespace() || c == ';' || c == '{' || c == '}') {
                out.push('"');
                out.push_str(&a.replace('\\', "\\\\").replace('"', "\\\""));
                out.push('"');
            } else {
                out.push_str(a);
            }
        }
        match &d.block {
            Some(b) => {
                out.push_str(" {\n");
                dump(b, indent + 1, out);
                for _ in 0..indent {
                    out.push_str("    ");
                }
                out.push_str("}\n");
            }
            None => out.push_str(";\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::lexer::tokenize;

    fn parse(src: &str) -> Result<Vec<Directive>, ParseError> {
        let file: Arc<Path> = Arc::from(Path::new("<test>"));
        let tokens = tokenize(src, &file).unwrap();
        let mut seen = HashSet::new();
        let mut p = Parser {
            t: &tokens,
            i: 0,
            file,
            base: PathBuf::from("."),
            seen: &mut seen,
            depth: 0,
        };
        p.block(true)
    }

    #[test]
    fn nested_blocks() {
        let d = parse("http { server { listen 80; location / { return 204; } } }").unwrap();
        assert_eq!(d.len(), 1);
        let srv = &d[0].children()[0];
        assert_eq!(srv.name, "server");
        let loc = srv.find("location").unwrap();
        assert_eq!(loc.args, ["/"]);
        assert_eq!(loc.children()[0].name, "return");
    }

    #[test]
    fn multiple_args_and_locations() {
        let d = parse("server { server_name a.com *.a.com; location = /x { } location ~ \\.php$ { } }").unwrap();
        let s = &d[0];
        assert_eq!(s.find("server_name").unwrap().args, ["a.com", "*.a.com"]);
        let locs: Vec<_> = s.find_all("location").collect();
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[0].args, ["=", "/x"]);
        assert_eq!(locs[1].args, ["~", "\\.php$"]);
    }

    #[test]
    fn unterminated_directive_is_an_error() {
        let e = parse("server { listen 80 }").unwrap_err();
        assert!(e.msg.contains("not terminated"), "{}", e.msg);
    }

    #[test]
    fn unbalanced_brace_is_an_error() {
        assert!(parse("http { server {").is_err());
        assert!(parse("http { } }").is_err());
    }

    #[test]
    fn dump_roundtrips() {
        let src = "http { server { listen 80; location / { return 204; } } }";
        let d = parse(src).unwrap();
        let mut s = String::new();
        dump(&d, 0, &mut s);
        let d2 = parse(&s).unwrap();
        let mut s2 = String::new();
        dump(&d2, 0, &mut s2);
        assert_eq!(s, s2);
        assert!(s.contains("listen 80;"), "{s}");
    }
}

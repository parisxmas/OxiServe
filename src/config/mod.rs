//! nginx configuration: lexing, parsing, and lowering to the runtime model.
//!
//! ```text
//!   nginx.conf ──lexer──> tokens ──ast──> Directive tree ──build──> Config
//! ```
//!
//! The `Directive` tree stays untyped and faithful to the file (so `-T` can
//! print it back), while [`model::Config`] is fully resolved for the request
//! path.

pub mod ast;
pub mod build;
pub mod lexer;
pub mod model;
pub mod vars;

use std::path::{Path, PathBuf};

pub use model::Config;

#[derive(Debug)]
pub enum LoadError {
    Parse(ast::ParseError),
    Build(build::BuildError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(e) => write!(f, "{e}"),
            LoadError::Build(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Parses and lowers a config file. `prefix` resolves relative paths, matching
/// nginx's `-p` option.
pub fn load(path: &Path, prefix: PathBuf) -> Result<Config, LoadError> {
    let tree = ast::parse_file(path).map_err(LoadError::Parse)?;
    build::Builder::new(prefix)
        .build(&tree)
        .map_err(LoadError::Build)
}

/// Parses a config and renders it back to nginx syntax (`nginx -T`).
pub fn dump(path: &Path) -> Result<String, LoadError> {
    let tree = ast::parse_file(path).map_err(LoadError::Parse)?;
    let mut s = String::new();
    ast::dump(&tree, 0, &mut s);
    Ok(s)
}

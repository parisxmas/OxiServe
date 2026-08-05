//! OxiServe command line, deliberately nginx-compatible.
//!
//! `-c`, `-p`, `-t`, `-T`, `-v`, `-V` behave as an nginx operator expects, so
//! existing deployment scripts and health checks keep working.

use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "\
oxiserve — an nginx-configuration-compatible web server

Usage: oxiserve [options]

  -c FILE    configuration file (default: <prefix>/conf/oxiserve.conf)
  -p PATH    prefix for relative paths in the configuration (default: .)
  -t         test the configuration and exit
  -T         test the configuration, print it, and exit
  -q         suppress non-error messages during configuration testing
  -v         print version and exit
  -V         print version and build configuration, then exit
  -h         this message
";

struct Args {
    conf: Option<PathBuf>,
    prefix: PathBuf,
    test: bool,
    dump: bool,
    quiet: bool,
}

fn main() -> ExitCode {
    let mut args = Args {
        conf: None,
        prefix: PathBuf::from("."),
        test: false,
        dump: false,
        quiet: false,
    };

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" => match it.next() {
                Some(v) => args.conf = Some(PathBuf::from(v)),
                None => return fail("option \"-c\" requires a file name"),
            },
            "-p" => match it.next() {
                Some(v) => args.prefix = PathBuf::from(v),
                None => return fail("option \"-p\" requires a directory name"),
            },
            "-t" => args.test = true,
            "-T" => {
                args.test = true;
                args.dump = true;
            }
            "-q" => args.quiet = true,
            "-v" => {
                println!("oxiserve version: oxiserve/{}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "-V" => {
                println!("oxiserve version: oxiserve/{}", env!("CARGO_PKG_VERSION"));
                println!("built with rustc (edition 2021)");
                println!("configure arguments: --with-http_ssl_module --with-http_gzip_module");
                return ExitCode::SUCCESS;
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("invalid option: \"{other}\"")),
        }
    }

    let conf = args
        .conf
        .unwrap_or_else(|| args.prefix.join("conf/oxiserve.conf"));

    if !conf.exists() {
        return fail(&format!(
            "open() \"{}\" failed (2: No such file or directory)",
            conf.display()
        ));
    }

    let cfg = match oxiserve::config::load(&conf, args.prefix.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("oxiserve: [emerg] {e}");
            eprintln!(
                "oxiserve: configuration file {} test failed",
                conf.display()
            );
            return ExitCode::FAILURE;
        }
    };

    // Unimplemented directives are warnings, not errors: a config that mostly
    // works should start, with the gaps named precisely.
    if !cfg.unsupported.is_empty() && !args.quiet {
        for u in &cfg.unsupported {
            eprintln!("oxiserve: [warn] {u}");
        }
    }

    if args.test {
        if args.dump {
            match oxiserve::config::dump(&conf) {
                Ok(s) => print!("{s}"),
                Err(e) => {
                    eprintln!("oxiserve: [emerg] {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        if !args.quiet {
            eprintln!(
                "oxiserve: the configuration file {} syntax is ok",
                conf.display()
            );
            eprintln!(
                "oxiserve: configuration file {} test is successful",
                conf.display()
            );
        }
        return ExitCode::SUCCESS;
    }

    if let Err(e) = oxiserve::server::run(cfg) {
        eprintln!("oxiserve: [emerg] {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("oxiserve: {msg}");
    ExitCode::FAILURE
}

//! Transport abstraction over TCP and Unix domain sockets.
//!
//! Both appear on both sides of the server: a listener can be `listen 80` or
//! `listen unix:/run/oxiserve.sock`, and an upstream can be `127.0.0.1:9000`
//! or `unix:/run/php-fpm.sock` — the latter being php-fpm's default packaging
//! on every mainstream distribution.
//!
//! The enum is a thin dispatch layer: it forwards `AsyncRead`/`AsyncWrite` to
//! whichever socket it holds, so nothing above this module needs to care.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use super::conn::RawStream;

/// An accepted client connection, or a connection out to an upstream.
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    /// Connects to an upstream given nginx's address syntax.
    ///
    /// `unix:/path/to.sock` selects a Unix socket; anything else is
    /// `host:port`.
    pub async fn connect(addr: &str) -> io::Result<Stream> {
        match addr.strip_prefix("unix:") {
            Some(path) => UnixStream::connect(path).await.map(Stream::Unix),
            None => {
                let s = TcpStream::connect(addr).await?;
                // Nagle would add latency to the small writes that dominate
                // proxy and FastCGI request heads.
                let _ = s.set_nodelay(true);
                Ok(Stream::Tcp(s))
            }
        }
    }
}

impl Stream {
    /// True when the socket looks usable for a new request.
    ///
    /// A pooled connection may have been closed by the peer while it sat idle.
    /// A non-blocking read distinguishes the three cases: `WouldBlock` means
    /// alive with nothing pending (what we want), `Ok(0)` means the peer
    /// closed, and any actual bytes mean leftover data from a previous
    /// exchange — a connection we must not reuse either way.
    pub fn is_reusable(&self) -> bool {
        let mut probe = [0u8; 1];
        let r = match self {
            Stream::Tcp(s) => s.try_read(&mut probe),
            Stream::Unix(s) => s.try_read(&mut probe),
        };
        matches!(&r, Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Unix(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Tcp(s) => s.is_write_vectored(),
            Stream::Unix(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl RawStream for Stream {
    fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Stream::Tcp(s) => Some(s),
            // `sendfile(2)` to a Unix socket is possible on Linux, but a Unix
            // listener is almost always fronted by another proxy on the same
            // host, where the copy is not the bottleneck. Falling back to the
            // ordinary write path keeps one code path honest.
            Stream::Unix(_) => None,
        }
    }
}

/// A bound listening socket.
pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub async fn accept(&self) -> io::Result<(Stream, Option<std::net::SocketAddr>)> {
        match self {
            Listener::Tcp(l) => {
                let (s, peer) = l.accept().await?;
                Ok((Stream::Tcp(s), Some(peer)))
            }
            // A Unix peer has no address; nginx reports `$remote_addr` as
            // "unix:" for these, which `Ctx` handles via `remote == None`.
            Listener::Unix(l) => {
                let (s, _) = l.accept().await?;
                Ok((Stream::Unix(s), None))
            }
        }
    }
}

/// Removes a stale socket file left behind by an unclean shutdown.
///
/// `bind` on an existing path fails with `EADDRINUSE` even when nothing is
/// listening, so nginx and every other server unlink first. Only a socket file
/// is ever removed — pointing `listen unix:` at a regular file must not delete
/// it.
pub fn unlink_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::metadata(path) {
        Ok(md) => {
            use std::os::unix::fs::FileTypeExt;
            if md.file_type().is_socket() {
                std::fs::remove_file(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("oxiserve-transport-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn missing_path_is_not_an_error() {
        let p = scratch("absent.sock");
        let _ = std::fs::remove_file(&p);
        assert!(unlink_stale_socket(&p).is_ok());
    }

    #[test]
    fn stale_socket_is_removed() {
        let p = scratch("stale.sock");
        let _ = std::fs::remove_file(&p);
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        drop(l); // the file outlives the listener
        assert!(p.exists());
        unlink_stale_socket(&p).unwrap();
        assert!(!p.exists(), "a stale socket file must be unlinked");
    }

    #[test]
    fn a_regular_file_is_never_deleted() {
        // Guards against `listen unix:/etc/passwd` destroying data.
        let p = scratch("important.txt");
        std::fs::write(&p, b"do not delete me").unwrap();
        assert!(unlink_stale_socket(&p).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"do not delete me");
    }
}

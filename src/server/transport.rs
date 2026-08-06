//! Transport abstraction over TCP and Unix domain sockets.
//!
//! Both appear on both sides of the server: a listener can be `listen 80` or
//! `listen unix:/run/oxiserve.sock`, and an upstream can be `127.0.0.1:9000`
//! or `unix:/run/php-fpm.sock` — the latter being php-fpm's default packaging
//! on every mainstream distribution.
//!
//! The enum is a thin dispatch layer: it forwards `AsyncRead`/`AsyncWrite` to
//! whichever socket it holds, so nothing above this module needs to care.
//!
//! Accepted TCP sockets start [`Stream::Pending`]: accepted, but not yet
//! registered with the reactor. Registering costs an `epoll_ctl` on the way in
//! and another when the socket drops, and a connection that arrives with its
//! request already buffered — the common case under load — needs neither. The
//! first syscall that would block upgrades the socket in place, so a slow or
//! keep-alive connection ends up exactly where it would have been anyway.
//! Measured against nginx, those two syscalls were the whole of our
//! per-connection deficit on connection-churn workloads.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use super::conn::RawStream;

/// An accepted client connection, or a connection out to an upstream.
pub enum Stream {
    Tcp(TcpStream),
    /// Accepted and non-blocking, but not registered with the reactor. Becomes
    /// [`Stream::Tcp`] the moment a syscall would block. `Option` only so the
    /// socket can be moved out through `&mut self` during the upgrade; it is
    /// never `None` outside that moment.
    Pending(Option<std::net::TcpStream>),
    Unix(UnixStream),
}

impl Stream {
    /// Registers a pending socket with the reactor.
    ///
    /// Called when a syscall reports it would block, because from that point
    /// on we need the reactor to tell us when to try again. Everything
    /// buffered has already been consumed by the caller, so nothing is lost in
    /// the handover.
    fn register(&mut self) -> io::Result<()> {
        if let Stream::Pending(slot) = self {
            let std = slot.take().expect("a pending socket always holds one");
            *self = Stream::Tcp(TcpStream::from_std(std)?);
        }
        Ok(())
    }

    /// Registers if needed and returns the reactor-backed socket.
    ///
    /// `sendfile(2)` parks the task when the send buffer fills, which needs
    /// the reactor — so the fast path ends here for a large response, which is
    /// exactly where the two saved syscalls stop mattering.
    pub fn as_registered_tcp(&mut self) -> Option<&TcpStream> {
        if matches!(self, Stream::Pending(_)) && self.register().is_err() {
            return None;
        }
        match self {
            Stream::Tcp(s) => Some(s),
            _ => None,
        }
    }
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
    /// Applies `tcp_nodelay`.
    ///
    /// Not inheritable from the listening socket on Linux, so it costs one
    /// `setsockopt` per connection here exactly as it does in nginx. Handled
    /// on the enum because an accepted socket is not a `tokio::net::TcpStream`
    /// yet — matching on that variant silently stopped applying it.
    pub fn set_nodelay(&self, on: bool) {
        let _ = match self {
            Stream::Tcp(s) => s.set_nodelay(on),
            Stream::Pending(s) => s.as_ref().expect("present").set_nodelay(on),
            Stream::Unix(_) => Ok(()),
        };
    }

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
            // Only ever set on accepted client sockets, never on the pooled
            // upstream connections this probes.
            Stream::Pending(_) => return false,
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
        let me = self.get_mut();
        if let Stream::Pending(slot) = me {
            use std::io::Read;
            // Free in practice: every caller reaches `AsyncReadExt::read`
            // with an already-initialised slice, so `ReadBuf` has nothing
            // left to zero. It keeps this path out of `unsafe` entirely.
            let dst = buf.initialize_unfilled();
            match slot.as_mut().expect("present").read(dst) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // Nothing buffered, so from here on we need the reactor.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = me.register() {
                        return Poll::Ready(Err(e));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        match me {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Pending(_) => unreachable!("registered above"),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if let Stream::Pending(slot) = me {
            use std::io::Write;
            match slot.as_mut().expect("present").write(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                // The send buffer is full, so the rest of this response needs
                // the reactor to tell us when there is room.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = me.register() {
                        return Poll::Ready(Err(e));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        match me {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Pending(_) => unreachable!("registered above"),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Vectored writes go through the reactor rather than getting their own
        // fast path: they are used for proxy and FastCGI request heads, not
        // for the short client responses this optimisation is about.
        if let Err(e) = me.register() {
            return Poll::Ready(Err(e));
        }
        match me {
            Stream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Unix(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Pending(_) => unreachable!("registered above"),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Tcp(s) => s.is_write_vectored(),
            // Not yet registered, so report the same answer the socket will
            // give once it is: a `TcpStream` is always vectored-capable.
            Stream::Pending(_) => true,
            Stream::Unix(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me {
            // Nothing is buffered in user space, so there is nothing to flush
            // and no reason to register a socket just to say so.
            Stream::Pending(_) => Poll::Ready(Ok(())),
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if let Stream::Pending(slot) = me {
            // Shut the write side down directly. Registering with the reactor
            // purely to close would reintroduce both syscalls this exists to
            // avoid.
            let r = slot.as_mut().expect("present").shutdown(std::net::Shutdown::Write);
            return Poll::Ready(match r {
                Ok(()) => Ok(()),
                // The peer closed first; nothing left to shut down.
                Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
                Err(e) => Err(e),
            });
        }
        match me {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Pending(_) => unreachable!("handled above"),
        }
    }
}

impl RawStream for Stream {
    fn as_tcp(&mut self) -> Option<&TcpStream> {
        if matches!(self, Stream::Pending(_)) {
            return self.as_registered_tcp();
        }
        match self {
            Stream::Tcp(s) => Some(s),
            // `sendfile(2)` to a Unix socket is possible on Linux, but a Unix
            // listener is almost always fronted by another proxy on the same
            // host, where the copy is not the bottleneck. Falling back to the
            // ordinary write path keeps one code path honest.
            Stream::Unix(_) => None,
            Stream::Pending(_) => unreachable!("registered above"),
        }
    }
}

/// A bound listening socket.
///
/// The TCP side is an [`AsyncFd`] over a plain `std` listener rather than
/// `tokio::net::TcpListener`, because tokio's `accept` registers every
/// accepted socket with the reactor before handing it over. Going through
/// readiness ourselves lets the accepted socket stay unregistered — see
/// [`Stream::Pending`].
pub enum Listener {
    Tcp(AsyncFd<std::net::TcpListener>),
    Unix(UnixListener),
}

impl Listener {
    pub async fn accept(&self) -> io::Result<(Stream, Option<std::net::SocketAddr>)> {
        match self {
            Listener::Tcp(l) => {
                // Accepted through the listener's readiness but handed back
                // *unregistered*: `TcpListener::accept` would register the new
                // socket with the reactor immediately, and most connections
                // never need it. See [`Stream::Pending`].
                loop {
                    // Try the accept before consulting the reactor at all.
                    // Under load there is almost always a connection already
                    // queued, and the readiness bookkeeping is pure overhead
                    // when the answer is "yes, take one".
                    match accept_nonblocking(l.get_ref()) {
                        Ok((s, peer)) => return Ok((Stream::Pending(Some(s)), peer)),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                    // Genuinely empty. Tell the reactor the readiness we were
                    // holding is used up, or it hands back the same stale
                    // "readable" and this spins.
                    let mut guard = l.readable().await?;
                    guard.clear_ready();
                }
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

/// Accepts a connection, non-blocking from the moment it exists.
///
/// On Linux `accept4` sets `SOCK_NONBLOCK` as part of the accept.
/// `std::net::TcpListener::accept` cannot ask for that, so it costs an extra
/// `ioctl(FIONBIO)` per connection — a measurable fraction of the syscalls a
/// short connection costs. Elsewhere there is no `accept4` and the extra call
/// is unavoidable.
#[cfg(target_os = "linux")]
fn accept_nonblocking(
    l: &std::net::TcpListener,
) -> io::Result<(std::net::TcpStream, Option<std::net::SocketAddr>)> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `storage` is large enough for any address family the kernel can
    // return and `len` says so. The returned descriptor is handed straight to
    // `TcpStream`, which owns it from then on, so it is closed exactly once.
    let fd = unsafe {
        libc::accept4(
            l.as_raw_fd(),
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut len,
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    // SAFETY: the kernel just filled `storage` and wrote the used length into
    // `len`.
    let peer = unsafe { socket2::SockAddr::new(storage, len) }.as_socket();
    Ok((sock, peer))
}

#[cfg(not(target_os = "linux"))]
fn accept_nonblocking(
    l: &std::net::TcpListener,
) -> io::Result<(std::net::TcpStream, Option<std::net::SocketAddr>)> {
    let (s, peer) = l.accept()?;
    s.set_nonblocking(true)?;
    Ok((s, Some(peer)))
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

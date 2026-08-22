//! Concrete stream types shared by every backend.
//!
//! These are enum wrappers rather than trait objects because callers need
//! capabilities a `Box<dyn AsyncRead + AsyncWrite>` cannot provide:
//! [`VsockStream::dup_fd`] requires a raw file descriptor and
//! [`VsockListener::try_accept`] requires listener-specific non-blocking
//! accept semantics. Backends built on unix sockets (krun, mock) share the
//! `Unix` variants; the Virtualization.framework backend has its own.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::{UnixListener, UnixStream};

#[cfg(not(unix))]
compile_error!("virt stream support requires a Unix host");

/// A host-side connection to a guest vsock port.
pub struct VsockStream {
    inner: VsockStreamInner,
}

enum VsockStreamInner {
    Unix(UnixStream),
    #[cfg(target_os = "macos")]
    Vz(vz::device::VirtioSocketConnection),
}

impl VsockStream {
    pub fn from_unix_stream(stream: UnixStream) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(stream: vz::device::VirtioSocketConnection) -> Self {
        Self {
            inner: VsockStreamInner::Vz(stream),
        }
    }

    /// Guest-side source port, when the transport reports one.
    pub fn source_port(&self) -> Option<u32> {
        match &self.inner {
            VsockStreamInner::Unix(_) => None,
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Some(stream.source_port()),
        }
    }

    /// Guest-side destination port; `0` when the transport does not track it.
    pub fn destination_port(&self) -> u32 {
        match &self.inner {
            VsockStreamInner::Unix(_) => 0,
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => stream.destination_port(),
        }
    }

    /// Duplicate the underlying descriptor as an owned, non-blocking fd.
    pub fn dup_fd(&self) -> io::Result<OwnedFd> {
        match &self.inner {
            VsockStreamInner::Unix(stream) => duplicate_nonblocking_fd(stream),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => duplicate_nonblocking_fd(stream),
        }
    }
}

impl fmt::Debug for VsockStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockStream").finish_non_exhaustive()
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            VsockStreamInner::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            VsockStreamInner::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            VsockStreamInner::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            VsockStreamInner::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A host-side listener for guest-initiated vsock connections.
pub struct VsockListener {
    inner: VsockListenerInner,
}

enum VsockListenerInner {
    Unix(UnixListener),
    #[cfg(target_os = "macos")]
    Vz(vz::device::VirtioSocketListener),
}

impl VsockListener {
    pub fn from_unix_listener(listener: UnixListener) -> Self {
        Self {
            inner: VsockListenerInner::Unix(listener),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(listener: vz::device::VirtioSocketListener) -> Self {
        Self {
            inner: VsockListenerInner::Vz(listener),
        }
    }

    /// Wait for the next guest-initiated connection.
    pub async fn accept(&mut self) -> io::Result<VsockStream> {
        match &mut self.inner {
            VsockListenerInner::Unix(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| VsockStream::from_unix_stream(stream)),
            #[cfg(target_os = "macos")]
            VsockListenerInner::Vz(listener) => listener
                .accept()
                .await
                .map(VsockStream::from_vz)
                .map_err(io::Error::other),
        }
    }

    /// Accept a queued connection without waiting; `Ok(None)` when none is pending.
    pub fn try_accept(&mut self) -> io::Result<Option<VsockStream>> {
        match &mut self.inner {
            VsockListenerInner::Unix(listener) => {
                try_accept_unix(listener).map(|stream| stream.map(VsockStream::from_unix_stream))
            }
            #[cfg(target_os = "macos")]
            VsockListenerInner::Vz(listener) => listener
                .try_accept()
                .map(|stream| stream.map(VsockStream::from_vz))
                .map_err(io::Error::other),
        }
    }
}

impl fmt::Debug for VsockListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockListener").finish_non_exhaustive()
    }
}

/// Raw duplex byte stream to the guest serial device.
///
/// Consumed exclusively by the serial console pump; backends construct it from
/// whatever transport they have (file pair for krun, framework stream for vz,
/// in-process duplex pipe for the mock).
pub(crate) struct SerialDevice {
    inner: SerialDeviceInner,
}

enum SerialDeviceInner {
    #[allow(dead_code)] // constructed only by the Linux backend
    Pty(PtyFileStream),
    #[allow(dead_code)] // constructed only by the mock backend
    Duplex(DuplexStream),
    #[cfg(target_os = "macos")]
    Vz(vz::device::SerialPortStream),
}

impl SerialDevice {
    #[allow(dead_code)]
    pub(crate) fn from_pty_files(read: File, write: File) -> io::Result<Self> {
        Ok(Self {
            inner: SerialDeviceInner::Pty(PtyFileStream::new(read, write)?),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn from_duplex(stream: DuplexStream) -> Self {
        Self {
            inner: SerialDeviceInner::Duplex(stream),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(stream: vz::device::SerialPortStream) -> Self {
        Self {
            inner: SerialDeviceInner::Vz(stream),
        }
    }
}

impl fmt::Debug for SerialDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerialDevice").finish_non_exhaustive()
    }
}

impl AsyncRead for SerialDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            SerialDeviceInner::Pty(stream) => Pin::new(stream).poll_read(cx, buf),
            SerialDeviceInner::Duplex(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(target_os = "macos")]
            SerialDeviceInner::Vz(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SerialDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            SerialDeviceInner::Pty(stream) => Pin::new(stream).poll_write(cx, buf),
            SerialDeviceInner::Duplex(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(target_os = "macos")]
            SerialDeviceInner::Vz(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            SerialDeviceInner::Pty(stream) => Pin::new(stream).poll_flush(cx),
            SerialDeviceInner::Duplex(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "macos")]
            SerialDeviceInner::Vz(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            SerialDeviceInner::Pty(stream) => Pin::new(stream).poll_shutdown(cx),
            SerialDeviceInner::Duplex(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "macos")]
            SerialDeviceInner::Vz(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Non-blocking accept on a tokio listener without consuming its readiness.
fn try_accept_unix(listener: &UnixListener) -> io::Result<Option<UnixStream>> {
    use nix::errno::Errno;
    use nix::sys::socket::accept;

    match accept(listener.as_raw_fd()) {
        Ok(fd) => {
            let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            stream.set_nonblocking(true)?;
            UnixStream::from_std(stream).map(Some)
        }
        Err(Errno::EAGAIN) => Ok(None),
        Err(err) => Err(io::Error::other(err)),
    }
}

/// Async adapter over the krun console PTY master file pair.
#[derive(Debug)]
struct PtyFileStream {
    read: tokio::io::unix::AsyncFd<File>,
    write: tokio::io::unix::AsyncFd<File>,
}

impl PtyFileStream {
    fn new(read: File, write: File) -> io::Result<Self> {
        set_nonblocking(&read)?;
        set_nonblocking(&write)?;
        Ok(Self {
            read: tokio::io::unix::AsyncFd::new(read)?,
            write: tokio::io::unix::AsyncFd::new(write)?,
        })
    }
}

impl AsyncRead for PtyFileStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes =
            unsafe { &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };

        loop {
            let mut guard = ready!(self.read.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().read(bytes)) {
                Ok(Ok(n)) => {
                    unsafe {
                        buf.assume_init(n);
                    }
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                // Linux reports a closed PTY slave as EIO on the master.
                Ok(Err(err)) if pty_read_reached_eof(&err) => return Poll::Ready(Ok(())),
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for PtyFileStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.write.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.get_ref().flush()?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.get_ref().flush()?;
        shutdown_write(self.write.get_ref())?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "linux")]
fn pty_read_reached_eof(error: &io::Error) -> bool {
    error.raw_os_error() == Some(nix::errno::Errno::EIO as i32)
}

#[cfg(not(target_os = "linux"))]
fn pty_read_reached_eof(_error: &io::Error) -> bool {
    false
}

fn duplicate_nonblocking_fd<F: AsRawFd>(fd_owner: &F) -> io::Result<OwnedFd> {
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd_owner.as_raw_fd()) };
    let duplicated = nix::unistd::dup(borrowed).map_err(io::Error::other)?;
    let file = File::from(duplicated);
    set_nonblocking(&file)?;
    Ok(file.into())
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let flags =
        OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL).map_err(io::Error::other)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    let _ = fcntl(file, FcntlArg::F_SETFL(new_flags)).map_err(io::Error::other)?;
    Ok(())
}

fn shutdown_write<F: AsRawFd>(file: &F) -> io::Result<()> {
    match nix::sys::socket::shutdown(file.as_raw_fd(), nix::sys::socket::Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ENOTSOCK | nix::errno::Errno::ENOTCONN) => Ok(()),
        Err(err) => Err(io::Error::other(format!("shutdown(SHUT_WR) failed: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nix::libc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    use super::{SerialDevice, VsockListener, VsockStream};

    fn temp_socket_path(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        PathBuf::from("/tmp").join(format!("vmmon-{name}-{}-{now}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn dup_fd_returns_valid_nonblocking_descriptor() {
        let (mut left, right) = StdUnixStream::pair().expect("unix stream pair should be created");
        right
            .set_nonblocking(true)
            .expect("right stream should be nonblocking");

        let stream = UnixStream::from_std(right).expect("tokio unix stream should wrap std stream");
        let stream = VsockStream::from_unix_stream(stream);
        let duplicated = stream.dup_fd().expect("dup fd should succeed");

        let raw_flags = unsafe { libc::fcntl(duplicated.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(raw_flags, -1, "fcntl should succeed");
        assert_ne!(raw_flags & libc::O_NONBLOCK, 0, "fd should be nonblocking");

        let mut duplicated_stream = StdUnixStream::from(duplicated);
        left.write_all(b"ping").expect("write should succeed");

        let mut buf = [0u8; 4];
        loop {
            match duplicated_stream.read(&mut buf) {
                Ok(4) => break,
                Ok(_) => panic!("unexpected short read"),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("read should succeed: {err}"),
            }
        }

        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn unix_listener_accepts_vsock_streams() {
        let path = temp_socket_path("accept");
        let listener = UnixListener::bind(&path).expect("listener should bind");
        let mut listener = VsockListener::from_unix_listener(listener);

        let client = tokio::spawn(UnixStream::connect(path.clone()));
        let accepted = listener.accept().await.expect("accept should succeed");
        let _client = client
            .await
            .expect("client task should complete")
            .expect("client should connect");

        assert_eq!(accepted.destination_port(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn try_accept_returns_none_when_no_connection_is_pending() {
        let path = temp_socket_path("try-accept");
        let listener = UnixListener::bind(&path).expect("listener should bind");
        let mut listener = VsockListener::from_unix_listener(listener);

        assert!(listener
            .try_accept()
            .expect("try_accept should succeed")
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn duplex_serial_device_round_trips_bytes() {
        let (host_side, mut guest_side) = tokio::io::duplex(1024);
        let mut device = SerialDevice::from_duplex(host_side);

        guest_side
            .write_all(b"boot banner")
            .await
            .expect("guest write should succeed");

        let mut buf = [0u8; 11];
        device
            .read_exact(&mut buf)
            .await
            .expect("device read should succeed");
        assert_eq!(&buf, b"boot banner");

        device
            .write_all(b"input")
            .await
            .expect("device write should succeed");
        let mut echo = [0u8; 5];
        guest_side
            .read_exact(&mut echo)
            .await
            .expect("guest read should succeed");
        assert_eq!(&echo, b"input");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn closed_pty_slave_is_reported_as_serial_eof() {
        let pty = nix::pty::openpty(None, None).expect("create PTY");
        let master = File::from(pty.master);
        let write_master = master.try_clone().expect("clone PTY master");
        drop(pty.slave);
        let mut device = SerialDevice::from_pty_files(master, write_master).expect("wrap PTY");
        let mut buffer = [0_u8; 1];

        let read =
            tokio::time::timeout(std::time::Duration::from_secs(1), device.read(&mut buffer))
                .await
                .expect("PTY read resolves")
                .expect("closed PTY is EOF");

        assert_eq!(read, 0);
    }
}

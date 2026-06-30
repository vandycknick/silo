use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};

mod unix;
#[cfg(target_os = "macos")]
mod vz;

#[cfg(not(unix))]
compile_error!("virt stream support requires a Unix host");

enum VsockStreamInner {
    Unix(UnixStream),
    #[cfg(target_os = "macos")]
    Vz(vz::VzVsockConnection),
}

enum VsockListenerInner {
    #[cfg_attr(not(test), allow(dead_code))]
    Unix(UnixListener),
    #[cfg(target_os = "macos")]
    Vz(vz::VzVsockListener),
}

enum MachineSerialStreamInner {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Unix(unix::MachineSerialStreamInner),
    #[cfg(target_os = "macos")]
    Vz(vz::VzSerialStream),
}

pub struct VsockStream {
    inner: VsockStreamInner,
}

pub struct VsockListener {
    inner: VsockListenerInner,
}

pub(crate) struct MachineSerialStream {
    inner: MachineSerialStreamInner,
}

impl fmt::Debug for VsockStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockStream").finish_non_exhaustive()
    }
}

impl fmt::Debug for MachineSerialStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineSerialStream")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VsockListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockListener").finish_non_exhaustive()
    }
}

impl VsockStream {
    pub fn from_unix_stream(stream: UnixStream) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(stream: vz::VzVsockConnection) -> Self {
        Self {
            inner: VsockStreamInner::Vz(stream),
        }
    }

    pub fn source_port(&self) -> Option<u32> {
        match &self.inner {
            VsockStreamInner::Unix(_) => None,
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => Some(stream.source_port()),
        }
    }

    pub fn destination_port(&self) -> u32 {
        match &self.inner {
            VsockStreamInner::Unix(_) => 0,
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => stream.destination_port(),
        }
    }

    pub fn dup_fd(&self) -> io::Result<OwnedFd> {
        match &self.inner {
            VsockStreamInner::Unix(stream) => duplicate_nonblocking_fd(stream),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => duplicate_nonblocking_fd(stream),
        }
    }
}

impl VsockListener {
    pub fn from_unix_listener(listener: UnixListener) -> Self {
        Self {
            inner: VsockListenerInner::Unix(listener),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(listener: vz::VzVsockListener) -> Self {
        Self {
            inner: VsockListenerInner::Vz(listener),
        }
    }

    /// Wait for the next guest-initiated vsock connection.
    ///
    /// Returns the next available connection for this listener.
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

    /// Attempt to accept a queued connection without waiting.
    ///
    /// Returns `Ok(None)` if no connection is currently available.
    pub fn try_accept(&mut self) -> io::Result<Option<VsockStream>> {
        match &mut self.inner {
            VsockListenerInner::Unix(listener) => unix::try_accept_unix(listener)
                .map(|stream| stream.map(VsockStream::from_unix_stream)),
            #[cfg(target_os = "macos")]
            VsockListenerInner::Vz(listener) => listener
                .try_accept()
                .map(|stream| stream.map(VsockStream::from_vz))
                .map_err(io::Error::other),
        }
    }
}

impl MachineSerialStream {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn from_files(read: std::fs::File, write: std::fs::File) -> io::Result<Self> {
        Ok(Self {
            inner: MachineSerialStreamInner::Unix(unix::MachineSerialStreamInner::from_files(
                read, write,
            )?),
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(stream: vz::VzSerialStream) -> Self {
        Self {
            inner: MachineSerialStreamInner::Vz(stream),
        }
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

impl AsyncRead for MachineSerialStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            MachineSerialStreamInner::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(target_os = "macos")]
            MachineSerialStreamInner::Vz(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MachineSerialStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            MachineSerialStreamInner::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(target_os = "macos")]
            MachineSerialStreamInner::Vz(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            MachineSerialStreamInner::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(target_os = "macos")]
            MachineSerialStreamInner::Vz(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            MachineSerialStreamInner::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(target_os = "macos")]
            MachineSerialStreamInner::Vz(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

fn duplicate_nonblocking_fd<F>(fd_owner: &F) -> io::Result<OwnedFd>
where
    F: AsRawFd,
{
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd_owner.as_raw_fd()) };
    let duplicated = nix::unistd::dup(borrowed).map_err(io::Error::other)?;
    let file = std::fs::File::from(duplicated);
    set_nonblocking(&file)?;
    Ok(file.into())
}

fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let flags =
        OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL).map_err(io::Error::other)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    let _ = fcntl(file, FcntlArg::F_SETFL(new_flags)).map_err(io::Error::other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nix::libc;
    use tokio::net::{UnixListener, UnixStream};

    use crate::stream::{VsockListener, VsockStream};

    fn temp_socket_path(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        PathBuf::from("/tmp").join(format!("bv-{name}-{}-{now}.sock", std::process::id()))
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
}

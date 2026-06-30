use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream};

pub(crate) fn try_accept_unix(listener: &TokioUnixListener) -> io::Result<Option<TokioUnixStream>> {
    use nix::errno::Errno;
    use nix::sys::socket::accept;

    match accept(listener.as_raw_fd()) {
        Ok(fd) => {
            let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            stream.set_nonblocking(true)?;
            TokioUnixStream::from_std(stream).map(Some)
        }
        Err(Errno::EAGAIN) => Ok(None),
        Err(err) => Err(io::Error::other(err)),
    }
}

#[derive(Debug)]
struct SplitFileStream {
    read: tokio::io::unix::AsyncFd<File>,
    write: tokio::io::unix::AsyncFd<File>,
}

impl SplitFileStream {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn new(read: File, write: File) -> io::Result<Self> {
        crate::stream::set_nonblocking(&read)?;
        crate::stream::set_nonblocking(&write)?;
        Ok(Self {
            read: tokio::io::unix::AsyncFd::new(read)?,
            write: tokio::io::unix::AsyncFd::new(write)?,
        })
    }
}

impl AsyncRead for SplitFileStream {
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
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for SplitFileStream {
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

pub(crate) struct MachineSerialStreamInner {
    stream: SplitFileStream,
}

impl MachineSerialStreamInner {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn from_files(read: File, write: File) -> io::Result<Self> {
        Ok(Self {
            stream: SplitFileStream::new(read, write)?,
        })
    }
}

impl AsyncRead for MachineSerialStreamInner {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MachineSerialStreamInner {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn shutdown_write<F: AsRawFd>(file: &F) -> io::Result<()> {
    match nix::sys::socket::shutdown(file.as_raw_fd(), nix::sys::socket::Shutdown::Write) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ENOTSOCK | nix::errno::Errno::ENOTCONN) => Ok(()),
        Err(err) => Err(io::Error::other(format!("shutdown(SHUT_WR) failed: {err}"))),
    }
}

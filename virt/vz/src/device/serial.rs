use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{shutdown, Shutdown};
use nix::unistd::{dup, pipe};
use objc2::{rc::Retained, AllocAnyThread, ClassType};
use objc2_foundation::NSFileHandle;
use objc2_virtualization::{
    VZFileHandleSerialPortAttachment, VZSerialPortConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::VzError;

#[derive(Debug, Clone)]
pub struct SerialPortConfiguration {
    inner: Retained<VZVirtioConsoleDeviceSerialPortConfiguration>,
    host_read: Arc<OwnedFd>,
    host_write: Arc<OwnedFd>,
}

// SAFETY: The wrapper owns a retained configuration object and duplicated host pipe file
// descriptors. The public API only exposes immutable access plus host-side stream duplication.
unsafe impl Send for SerialPortConfiguration {}
// SAFETY: See above.
unsafe impl Sync for SerialPortConfiguration {}

impl SerialPortConfiguration {
    pub fn new() -> Self {
        Self::virtio_console()
    }

    pub fn virtio_console() -> Self {
        let (guest_read, host_write) = pipe().expect("create serial input pipe");
        let (host_read, guest_write) = pipe().expect("create serial output pipe");

        let inner = unsafe {
            let read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                guest_read.into_raw_fd(),
                true,
            );
            let write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                guest_write.into_raw_fd(),
                true,
            );
            let attachment =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&read_handle),
                    Some(&write_handle),
                );
            let inner = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            inner.setAttachment(Some(&attachment));
            inner
        };

        Self {
            inner,
            host_read: Arc::new(host_read),
            host_write: Arc::new(host_write),
        }
    }

    pub(crate) fn as_inner(&self) -> &VZSerialPortConfiguration {
        self.inner.as_super()
    }

    pub fn open_stream(&self) -> Result<SerialPortStream, VzError> {
        let input = dup(&*self.host_write)
            .map(std::fs::File::from)
            .map_err(|err| VzError::Backend(format!("duplicate serial guest input fd: {err}")))?;
        let output = dup(&*self.host_read)
            .map(std::fs::File::from)
            .map_err(|err| VzError::Backend(format!("duplicate serial guest output fd: {err}")))?;
        SerialPortStream::new(output, input).map_err(VzError::from)
    }
}

impl Default for SerialPortConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SerialPortStream {
    inner: SplitFdStream,
}

impl fmt::Debug for SerialPortStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SerialPortStream").finish_non_exhaustive()
    }
}

impl SerialPortStream {
    fn new(read: std::fs::File, write: std::fs::File) -> io::Result<Self> {
        Ok(Self {
            inner: SplitFdStream::new(read, write)?,
        })
    }
}

impl AsyncRead for SerialPortStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SerialPortStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct SplitFdStream {
    read: AsyncFd<std::fs::File>,
    write: AsyncFd<std::fs::File>,
}

impl SplitFdStream {
    fn new(read: std::fs::File, write: std::fs::File) -> io::Result<Self> {
        set_nonblocking(&read)?;
        set_nonblocking(&write)?;
        Ok(Self {
            read: AsyncFd::new(read)?,
            write: AsyncFd::new(write)?,
        })
    }
}

impl AsyncRead for SplitFdStream {
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
                    unsafe { buf.assume_init(n) };
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

impl AsyncWrite for SplitFdStream {
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.get_ref().flush()?;
        shutdown(self.write.get_ref().as_raw_fd(), Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}

pub(crate) fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    let _ = fcntl(file, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}

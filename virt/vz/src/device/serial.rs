use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{IntoRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{ready, Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
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
    host_write: Arc<Mutex<Option<OwnedFd>>>,
}

// SAFETY: The wrapper owns a retained configuration object and synchronized host pipe file
// descriptors. The public API only exposes immutable access plus host-side stream creation.
unsafe impl Send for SerialPortConfiguration {}
// SAFETY: See above.
unsafe impl Sync for SerialPortConfiguration {}

impl SerialPortConfiguration {
    pub fn new() -> Result<Self, VzError> {
        Self::virtio_console()
    }

    pub fn virtio_console() -> Result<Self, VzError> {
        let (guest_read, host_write) =
            pipe().map_err(|err| VzError::Backend(format!("create serial input pipe: {err}")))?;
        let (host_read, guest_write) =
            pipe().map_err(|err| VzError::Backend(format!("create serial output pipe: {err}")))?;

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

        Ok(Self {
            inner,
            host_read: Arc::new(host_read),
            host_write: Arc::new(Mutex::new(Some(host_write))),
        })
    }

    pub(crate) fn as_inner(&self) -> &VZSerialPortConfiguration {
        self.inner.as_super()
    }

    pub fn open_stream(&self) -> Result<SerialPortStream, VzError> {
        let output = dup(&*self.host_read)
            .map(std::fs::File::from)
            .map_err(|err| VzError::Backend(format!("duplicate serial guest output fd: {err}")))?;
        let input = self
            .host_write
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .map(std::fs::File::from)
            .ok_or_else(|| VzError::Backend("serial stream is already open".to_string()))?;
        SerialPortStream::new(output, input).map_err(VzError::from)
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
    write: Option<AsyncFd<std::fs::File>>,
}

impl SplitFdStream {
    fn new(read: std::fs::File, write: std::fs::File) -> io::Result<Self> {
        set_nonblocking(&read)?;
        set_nonblocking(&write)?;
        Ok(Self {
            read: AsyncFd::new(read)?,
            write: Some(AsyncFd::new(write)?),
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
        let Some(write) = self.get_mut().write.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        loop {
            let mut guard = ready!(write.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(match self.get_mut().write.as_ref() {
            Some(write) => write.get_ref().flush(),
            None => Ok(()),
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(write) = this.write.as_ref() else {
            return Poll::Ready(Ok(()));
        };
        write.get_ref().flush()?;
        this.write.take();
        Poll::Ready(Ok(()))
    }
}

pub(crate) fn set_nonblocking(file: &std::fs::File) -> io::Result<()> {
    let flags = OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL)?);
    let new_flags = flags | OFlag::O_NONBLOCK;
    let _ = fcntl(file, FcntlArg::F_SETFL(new_flags))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use nix::unistd::pipe;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::device::serial::SerialPortStream;

    fn file_pipe() -> (std::fs::File, std::fs::File) {
        let (read, write) = pipe().expect("create test pipe");
        (read.into(), write.into())
    }

    #[test]
    fn shutdown_closes_the_owned_writer_and_preserves_the_reader() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("build Tokio runtime");

        runtime.block_on(async {
            let (stream_read, mut guest_output) = file_pipe();
            let (mut guest_input, stream_write) = file_pipe();
            let mut stream =
                SerialPortStream::new(stream_read, stream_write).expect("open serial stream");

            stream
                .write_all(b"request")
                .await
                .expect("write serial input");
            let mut request = [0; 7];
            guest_input
                .read_exact(&mut request)
                .expect("read serial input");
            assert_eq!(&request, b"request");

            stream.shutdown().await.expect("shut down serial input");
            let mut eof = [0; 1];
            assert_eq!(guest_input.read(&mut eof).expect("read input EOF"), 0);

            guest_output
                .write_all(b"response")
                .expect("write serial output");
            let mut response = [0; 8];
            stream
                .read_exact(&mut response)
                .await
                .expect("read serial output after input shutdown");
            assert_eq!(&response, b"response");
        });
    }

    #[test]
    fn shutdown_is_idempotent_and_rejects_later_writes() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("build Tokio runtime");

        runtime.block_on(async {
            let (stream_read, _guest_output) = file_pipe();
            let (_guest_input, stream_write) = file_pipe();
            let mut stream =
                SerialPortStream::new(stream_read, stream_write).expect("open serial stream");

            stream.shutdown().await.expect("first serial shutdown");
            stream.shutdown().await.expect("repeated serial shutdown");
            let error = stream
                .write_all(b"after shutdown")
                .await
                .expect_err("write after shutdown must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        });
    }
}

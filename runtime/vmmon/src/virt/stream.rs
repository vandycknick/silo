//! Concrete stream types shared by every backend.
//!
//! These are enum wrappers rather than trait objects because callers need
//! capabilities a `Box<dyn AsyncRead + AsyncWrite>` cannot provide:
//! [`VsockStream::dup_fd`] requires a raw file descriptor and
//! [`VsockListener::try_accept`] requires listener-specific non-blocking
//! accept semantics. Backends built on unix sockets (krun, mock) share the
//! `Unix` variants; the Virtualization.framework backend has its own.
//!
//! Listener admission is enforced before a stream leaves this abstraction.
//! VZ reserves capacity in its synchronous framework callback and transports
//! the same lease into this common stream wrapper without double accounting.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{ready, Context, Poll};

#[cfg(target_os = "macos")]
use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;

use crate::virt::capacity::{VsockCapacity, VsockLease};
use crate::virt::error::VirtError;

#[cfg(not(unix))]
compile_error!("virt stream support requires a Unix host");

/// A host-side connection to a guest vsock port.
pub struct VsockStream {
    inner: VsockStreamInner,
    source_port: Option<u32>,
    destination_port: u32,
    _lease: Option<VsockLease>,
    _synthetic_source: Option<SyntheticPortLease>,
}

enum VsockStreamInner {
    Unix(UnixStream),
    #[cfg(target_os = "macos")]
    Vz(vz::device::VirtioSocketConnection),
}

impl VsockStream {
    pub(crate) fn from_unix_stream(
        stream: UnixStream,
        source_port: Option<u32>,
        destination_port: u32,
        lease: Option<VsockLease>,
    ) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
            source_port,
            destination_port,
            _lease: lease,
            _synthetic_source: None,
        }
    }

    pub(crate) fn from_synthetic_unix_stream(
        stream: UnixStream,
        source: SyntheticPortLease,
        destination_port: u32,
        lease: VsockLease,
    ) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
            source_port: Some(source.port()),
            destination_port,
            _lease: Some(lease),
            _synthetic_source: Some(source),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(
        stream: vz::device::VirtioSocketConnection,
        lease: Option<VsockLease>,
    ) -> Self {
        let source_port = stream.source_port();
        let destination_port = stream.destination_port();
        Self {
            inner: VsockStreamInner::Vz(stream),
            source_port: Some(source_port),
            destination_port,
            _lease: lease,
            _synthetic_source: None,
        }
    }

    /// Source endpoint port, when the backend reports or synthesizes one.
    pub fn source_port(&self) -> Option<u32> {
        self.source_port
    }

    /// Destination endpoint port for this connection.
    pub fn destination_port(&self) -> u32 {
        self.destination_port
    }

    pub(crate) fn owns_capacity(&self, capacity: &VsockCapacity) -> bool {
        self._lease
            .as_ref()
            .is_some_and(|lease| capacity.owns(lease))
    }

    /// Duplicate the underlying descriptor as an owned, non-blocking fd.
    pub fn dup_fd(&self) -> io::Result<OwnedFd> {
        match &self.inner {
            VsockStreamInner::Unix(stream) => duplicate_nonblocking_fd(stream),
            #[cfg(target_os = "macos")]
            VsockStreamInner::Vz(stream) => duplicate_nonblocking_fd(stream),
        }
    }

    fn attach_listener_lease(
        mut self,
        registered_port: u32,
        capacity: &VsockCapacity,
    ) -> Result<Self, VirtError> {
        if self.destination_port != registered_port {
            return Err(VirtError::Backend(format!(
                "backend accepted vsock destination {} on listener port {registered_port}",
                self.destination_port
            )));
        }
        match self._lease.as_ref() {
            Some(lease) if capacity.owns(lease) => Ok(self),
            Some(_) => Err(VirtError::Backend(
                "backend returned a vsock stream with a foreign capacity lease".to_string(),
            )),
            None => {
                self._lease = Some(capacity.reserve()?);
                Ok(self)
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn into_unix_stream(self) -> Result<UnixStream, VirtError> {
        let VsockStreamInner::Unix(stream) = self.inner;
        Ok(stream)
    }

    #[cfg(target_os = "macos")]
    fn into_unix_stream(self) -> Result<UnixStream, VirtError> {
        match self.inner {
            VsockStreamInner::Unix(stream) => Ok(stream),
            VsockStreamInner::Vz(_) => Err(VirtError::Backend(
                "synthetic source ports require a Unix stream".to_string(),
            )),
        }
    }
}

impl fmt::Debug for VsockStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockStream")
            .field("source_port", &self.source_port)
            .field("destination_port", &self.destination_port)
            .finish_non_exhaustive()
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

/// A retained registration for one host endpoint port.
///
/// Each accepted guest-initiated connection consumes capacity shared with all
/// host-initiated connections for the same machine. Dropping the listener also
/// drops the backend registration.
pub struct VsockListener {
    inner: VsockListenerInner,
    registered_port: u32,
    capacity: VsockCapacity,
    synthetic_sources: Option<SyntheticPortAllocator>,
    _cleanup: Option<ListenerCleanup>,
}

enum VsockListenerInner {
    Unix(UnixListener),
    #[cfg(target_os = "linux")]
    Krun(mpsc::Receiver<PendingUnixVsock>),
    #[cfg(target_os = "macos")]
    Vz {
        listener: vz::device::VirtioSocketListener,
        accepted_leases: Arc<Mutex<VecDeque<VsockLease>>>,
    },
}

#[cfg(target_os = "linux")]
pub(crate) struct PendingUnixVsock {
    pub(crate) stream: StdUnixStream,
    pub(crate) source_port: u32,
    pub(crate) destination_port: u32,
    pub(crate) lease: VsockLease,
    pub(crate) session_active: Arc<AtomicBool>,
}

struct ListenerCleanup(Option<Box<dyn FnOnce() + Send>>);

impl Drop for ListenerCleanup {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

impl VsockListener {
    pub(crate) fn from_unix_listener(
        listener: UnixListener,
        registered_port: u32,
        capacity: VsockCapacity,
    ) -> Self {
        Self {
            inner: VsockListenerInner::Unix(listener),
            registered_port,
            capacity,
            synthetic_sources: None,
            _cleanup: None,
        }
    }

    pub(crate) fn from_mock_unix_listener(
        listener: UnixListener,
        registered_port: u32,
        capacity: VsockCapacity,
        synthetic_sources: SyntheticPortAllocator,
    ) -> Self {
        Self {
            inner: VsockListenerInner::Unix(listener),
            registered_port,
            capacity,
            synthetic_sources: Some(synthetic_sources),
            _cleanup: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_krun_channel<F>(
        receiver: mpsc::Receiver<PendingUnixVsock>,
        registered_port: u32,
        capacity: VsockCapacity,
        cleanup: F,
    ) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            inner: VsockListenerInner::Krun(receiver),
            registered_port,
            capacity,
            synthetic_sources: None,
            _cleanup: Some(ListenerCleanup(Some(Box::new(cleanup)))),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_vz(
        listener: vz::device::VirtioSocketListener,
        registered_port: u32,
        capacity: VsockCapacity,
        accepted_leases: Arc<Mutex<VecDeque<VsockLease>>>,
    ) -> Self {
        Self {
            inner: VsockListenerInner::Vz {
                listener,
                accepted_leases,
            },
            registered_port,
            capacity,
            synthetic_sources: None,
            _cleanup: None,
        }
    }

    pub fn port(&self) -> u32 {
        self.registered_port
    }

    pub(crate) fn owns_capacity(&self, capacity: &VsockCapacity) -> bool {
        self.capacity.shares_limit_with(capacity)
    }

    /// Wait for the next guest-initiated connection.
    pub async fn accept(&mut self) -> Result<VsockStream, VirtError> {
        let stream = match &mut self.inner {
            VsockListenerInner::Unix(listener) => listener.accept().await.map(|(stream, _)| {
                VsockStream::from_unix_stream(stream, None, self.registered_port, None)
            })?,
            #[cfg(target_os = "linux")]
            VsockListenerInner::Krun(receiver) => loop {
                let pending = receiver.recv().await.ok_or_else(|| {
                    VirtError::Backend("krun vsock backend stopped while listening".to_string())
                })?;
                if pending.session_active.load(Ordering::Acquire) {
                    break VsockStream::from_unix_stream(
                        UnixStream::from_std(pending.stream)?,
                        Some(pending.source_port),
                        pending.destination_port,
                        Some(pending.lease),
                    );
                }
            },
            #[cfg(target_os = "macos")]
            VsockListenerInner::Vz {
                listener,
                accepted_leases,
            } => {
                let accepted = listener.accept().await;
                let lease = take_vz_accepted_lease(accepted_leases);
                match (accepted, lease) {
                    (Ok(stream), Some(lease)) => VsockStream::from_vz(stream, Some(lease)),
                    (Ok(_), None) => {
                        return Err(VirtError::Backend(
                            "VZ accepted a vsock connection without vmmon admission".to_string(),
                        ));
                    }
                    (Err(error), _) => return Err(io::Error::other(error).into()),
                }
            }
        };
        self.admit(stream)
    }

    /// Accept a queued connection without waiting; `Ok(None)` when none is pending.
    pub fn try_accept(&mut self) -> Result<Option<VsockStream>, VirtError> {
        let stream = match &mut self.inner {
            VsockListenerInner::Unix(listener) => try_accept_unix(listener)?.map(|stream| {
                VsockStream::from_unix_stream(stream, None, self.registered_port, None)
            }),
            #[cfg(target_os = "linux")]
            VsockListenerInner::Krun(receiver) => loop {
                match receiver.try_recv() {
                    Ok(pending) if pending.session_active.load(Ordering::Acquire) => {
                        break Some(VsockStream::from_unix_stream(
                            UnixStream::from_std(pending.stream)?,
                            Some(pending.source_port),
                            pending.destination_port,
                            Some(pending.lease),
                        ));
                    }
                    Ok(_) => continue,
                    Err(mpsc::error::TryRecvError::Empty) => break None,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err(VirtError::Backend(
                            "krun vsock backend stopped while listening".to_string(),
                        ));
                    }
                }
            },
            #[cfg(target_os = "macos")]
            VsockListenerInner::Vz {
                listener,
                accepted_leases,
            } => match listener.try_accept() {
                Ok(Some(stream)) => {
                    let lease = take_vz_accepted_lease(accepted_leases).ok_or_else(|| {
                        VirtError::Backend(
                            "VZ accepted a vsock connection without vmmon admission".to_string(),
                        )
                    })?;
                    Some(VsockStream::from_vz(stream, Some(lease)))
                }
                Ok(None) => None,
                Err(error) => {
                    let _ = take_vz_accepted_lease(accepted_leases);
                    return Err(io::Error::other(error).into());
                }
            },
        };
        stream.map(|stream| self.admit(stream)).transpose()
    }

    fn admit(&self, stream: VsockStream) -> Result<VsockStream, VirtError> {
        let Some(synthetic_sources) = self.synthetic_sources.as_ref() else {
            return stream.attach_listener_lease(self.registered_port, &self.capacity);
        };

        if stream.destination_port() != self.registered_port {
            return Err(VirtError::Backend(format!(
                "backend accepted vsock destination {} on listener port {}",
                stream.destination_port(),
                self.registered_port
            )));
        }
        let lease = self.capacity.reserve()?;
        let source = synthetic_sources.allocate()?;
        let stream = stream.into_unix_stream()?;
        Ok(VsockStream::from_synthetic_unix_stream(
            stream,
            source,
            self.registered_port,
            lease,
        ))
    }
}

#[cfg(target_os = "macos")]
fn take_vz_accepted_lease(accepted_leases: &Mutex<VecDeque<VsockLease>>) -> Option<VsockLease> {
    accepted_leases
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .pop_front()
}

impl fmt::Debug for VsockListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockListener")
            .field("registered_port", &self.registered_port)
            .finish_non_exhaustive()
    }
}

const SYNTHETIC_SOURCE_BASE: u32 = 1 << 30;
const SYNTHETIC_SOURCE_COUNT: usize = 1024;

/// Per-mock-machine deterministic high-range source ports for protocol tests.
#[derive(Clone, Debug)]
pub(crate) struct SyntheticPortAllocator {
    slots: Arc<Mutex<Vec<bool>>>,
}

impl SyntheticPortAllocator {
    pub(crate) fn new() -> Self {
        Self {
            slots: Arc::new(Mutex::new(vec![false; SYNTHETIC_SOURCE_COUNT])),
        }
    }

    pub(crate) fn allocate(&self) -> Result<SyntheticPortLease, VirtError> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let index = slots
            .iter()
            .position(|used| !used)
            .ok_or_else(|| VirtError::Backend("mock source port range exhausted".to_string()))?;
        slots[index] = true;
        drop(slots);
        Ok(SyntheticPortLease {
            slots: self.slots.clone(),
            index,
        })
    }
}

pub(crate) struct SyntheticPortLease {
    slots: Arc<Mutex<Vec<bool>>>,
    index: usize,
}

impl SyntheticPortLease {
    fn port(&self) -> u32 {
        SYNTHETIC_SOURCE_BASE + u32::try_from(self.index).map_or(0, |index| index)
    }
}

impl Drop for SyntheticPortLease {
    fn drop(&mut self) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = slots.get_mut(self.index) {
            *slot = false;
        }
    }
}

impl fmt::Debug for SyntheticPortLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntheticPortLease")
            .field("port", &self.port())
            .finish()
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

    use crate::virt::capacity::VsockCapacity;
    use crate::virt::stream::{
        SerialDevice, SyntheticPortAllocator, VsockListener, VsockStream, SYNTHETIC_SOURCE_BASE,
    };
    use crate::virt::VirtError;

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
        let stream = VsockStream::from_unix_stream(stream, None, 7000, None);
        let duplicated = stream.dup_fd().expect("dup fd should succeed");

        assert_eq!(stream.source_port(), None);
        assert_eq!(stream.destination_port(), 7000);

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
        let capacity = VsockCapacity::test_with_limit("listener", 1);
        let mut listener = VsockListener::from_unix_listener(listener, 7001, capacity);

        let client = tokio::spawn(UnixStream::connect(path.clone()));
        let accepted = listener.accept().await.expect("accept should succeed");
        let _client = client
            .await
            .expect("client task should complete")
            .expect("client should connect");

        assert_eq!(listener.port(), 7001);
        assert_eq!(accepted.source_port(), None);
        assert_eq!(accepted.destination_port(), 7001);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn try_accept_returns_none_when_no_connection_is_pending() {
        let path = temp_socket_path("try-accept");
        let listener = UnixListener::bind(&path).expect("listener should bind");
        let capacity = VsockCapacity::test_with_limit("listener", 1);
        let mut listener = VsockListener::from_unix_listener(listener, 7002, capacity);

        assert!(listener
            .try_accept()
            .expect("try_accept should succeed")
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn listener_rejects_overload_and_recovers_after_stream_drop() {
        let path = temp_socket_path("capacity");
        let listener = UnixListener::bind(&path).expect("listener should bind");
        let capacity = VsockCapacity::test_with_limit("listener-capacity", 1);
        let mut listener = VsockListener::from_unix_listener(listener, 7003, capacity.clone());

        let first_client = UnixStream::connect(&path).await.expect("first connect");
        let first = listener.accept().await.expect("first accept");
        assert_eq!(capacity.available_permits(), 0);

        let mut overloaded_client = UnixStream::connect(&path).await.expect("second connect");
        let error = listener
            .accept()
            .await
            .expect_err("second accept is rejected");
        assert!(matches!(
            error,
            VirtError::VsockCapacityExhausted { machine, limit }
                if machine == "listener-capacity" && limit == 1
        ));
        let mut byte = [0_u8; 1];
        assert_eq!(
            overloaded_client
                .read(&mut byte)
                .await
                .expect("rejected stream closes"),
            0
        );

        drop(first);
        drop(first_client);
        let _third_client = UnixStream::connect(&path).await.expect("third connect");
        let third = listener.accept().await.expect("capacity was released");
        assert_eq!(third.destination_port(), 7003);
        drop(third);
        assert_eq!(capacity.available_permits(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn synthetic_source_ports_are_bounded_unique_and_reused() {
        let allocator = SyntheticPortAllocator::new();
        let leases = (0..1024)
            .map(|_| allocator.allocate().expect("source port in range"))
            .collect::<Vec<_>>();
        let ports = leases.iter().map(|lease| lease.port()).collect::<Vec<_>>();

        assert_eq!(ports[0], SYNTHETIC_SOURCE_BASE);
        assert_eq!(ports[1023], SYNTHETIC_SOURCE_BASE + 1023);
        assert!(allocator.allocate().is_err());

        drop(leases);
        assert_eq!(
            allocator.allocate().expect("released source port").port(),
            SYNTHETIC_SOURCE_BASE
        );
    }

    #[tokio::test]
    async fn listener_does_not_double_account_an_existing_lease() {
        let (stream, _peer) = UnixStream::pair().expect("unix stream pair");
        let capacity = VsockCapacity::test_with_limit("existing-lease", 1);
        let lease = capacity.reserve().expect("reserve listener stream");
        let stream = VsockStream::from_unix_stream(stream, Some(8000), 7004, Some(lease));

        let stream = stream
            .attach_listener_lease(7004, &capacity)
            .expect("existing lease is retained");
        assert_eq!(capacity.available_permits(), 0);
        drop(stream);
        assert_eq!(capacity.available_permits(), 1);
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

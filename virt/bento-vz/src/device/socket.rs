use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use block2::StackBlock;
use nix::unistd::dup;
use objc2::{
    define_class, msg_send, rc::Retained, runtime::ProtocolObject, AllocAnyThread, ClassType,
    DefinedClass,
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol};
use objc2_virtualization::{
    VZSocketDevice, VZSocketDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtioSocketListener, VZVirtioSocketListenerDelegate,
    VZVirtualMachine,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::dispatch::{DispatchQueueExt, Queue};
use crate::error::VzError;

type ListenerRegistry = Arc<Mutex<HashMap<usize, HashSet<u32>>>>;
type ListenerDelegate = Retained<ProtocolObject<dyn VZVirtioSocketListenerDelegate>>;

struct VsockListenerDelegateIvars {
    sender: mpsc::UnboundedSender<Result<PendingConnection, VzError>>,
}

struct PendingConnection {
    fd: OwnedFd,
    source_port: u32,
    destination_port: u32,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "BentoVzVsockListenerDelegate"]
    #[ivars = VsockListenerDelegateIvars]
    struct VsockListenerDelegate;

    impl VsockListenerDelegate {
        #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
        unsafe fn listener_should_accept_new_connection(
            &self,
            _listener: &VZVirtioSocketListener,
            connection: &VZVirtioSocketConnection,
            _socket_device: &VZVirtioSocketDevice,
        ) -> bool {
            let file_descriptor = connection.fileDescriptor();
            let borrowed = BorrowedFd::borrow_raw(file_descriptor);
            let source_port = connection.sourcePort();
            let destination_port = connection.destinationPort();

            let result = dup(borrowed)
                .map_err(|err| VzError::Backend(format!("duplicate vsock fd: {err}")))
                .map(|fd| PendingConnection {
                    fd,
                    source_port,
                    destination_port,
                });

            match self.ivars().sender.send(result) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(error = %err, "dropping accepted vsock connection because listener is gone");
                    false
                }
            }
        }
    }

    unsafe impl NSObjectProtocol for VsockListenerDelegate {}
    unsafe impl VZVirtioSocketListenerDelegate for VsockListenerDelegate {}
);

impl VsockListenerDelegate {
    fn new_protocol_object(
        sender: mpsc::UnboundedSender<Result<PendingConnection, VzError>>,
    ) -> ListenerDelegate {
        let delegate = Self::alloc().set_ivars(VsockListenerDelegateIvars { sender });
        let delegate: Retained<Self> = unsafe { msg_send![super(delegate), init] };
        ProtocolObject::from_retained(delegate)
    }
}

#[allow(async_fn_in_trait)]
pub trait SocketDevice: Send + Sync {
    type Connection: AsyncRead + AsyncWrite + AsRawFd + Send + Unpin + 'static;

    type Listener;

    /// Connect to a guest vsock port.
    ///
    /// Requests a connection to the specified port in the guest.
    ///
    /// Returns a connection object on success. The connection contains a source
    /// port, a destination port, and a file descriptor that can be used to read
    /// and write data.
    async fn connect(&self, port: u32) -> Result<Self::Connection, VzError>;

    /// Register a host-side listener for a guest-accessible vsock port.
    ///
    /// The listener receives connections initiated by the guest for the
    /// specified port. Only one listener may be active for a given port on a
    /// device at a time.
    fn listen(&self, port: u32) -> Result<Self::Listener, VzError>;

    /// Remove a previously-registered host-side listener.
    ///
    /// After removal, new guest connections to the specified port are no longer
    /// accepted by the host.
    fn remove_listener(&self, port: u32) -> Result<(), VzError>;
}

#[derive(Debug, Clone)]
pub struct SocketDeviceConfiguration {
    inner: Retained<VZVirtioSocketDeviceConfiguration>,
}

impl SocketDeviceConfiguration {
    /// Create a new Virtio socket device configuration.
    pub fn new() -> Self {
        Self {
            inner: unsafe { VZVirtioSocketDeviceConfiguration::new() },
        }
    }

    pub(crate) fn as_inner(&self) -> &VZSocketDeviceConfiguration {
        self.inner.as_super()
    }
}

impl Default for SocketDeviceConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct VirtioSocketDevice {
    machine: Retained<VZVirtualMachine>,
    queue: Queue,
    index: usize,
    listeners: ListenerRegistry,
}

// SAFETY: The device is only touched via the VM's serial dispatch queue.
unsafe impl Send for VirtioSocketDevice {}
// SAFETY: See above.
unsafe impl Sync for VirtioSocketDevice {}

impl VirtioSocketDevice {
    pub(crate) fn new(
        machine: Retained<VZVirtualMachine>,
        queue: Queue,
        index: usize,
        listeners: ListenerRegistry,
    ) -> Self {
        Self {
            machine,
            queue,
            index,
            listeners,
        }
    }

    fn reserve_listener_port(&self, port: u32) -> Result<(), VzError> {
        let mut guard = self
            .listeners
            .lock()
            .map_err(|_| VzError::Backend("listener registry lock poisoned".to_string()))?;

        let ports = guard.entry(self.index).or_insert_with(HashSet::new);
        if !ports.insert(port) {
            return Err(VzError::Backend(format!(
                "listener already registered on port {port} for device {}",
                self.index
            )));
        }

        Ok(())
    }

    fn release_listener_port(&self, port: u32) -> Result<bool, VzError> {
        let mut guard = self
            .listeners
            .lock()
            .map_err(|_| VzError::Backend("listener registry lock poisoned".to_string()))?;

        let Some(ports) = guard.get_mut(&self.index) else {
            return Ok(false);
        };

        let removed = ports.remove(&port);
        if ports.is_empty() {
            guard.remove(&self.index);
        }

        Ok(removed)
    }

    fn unregister_listener(&self, port: u32, require_registered: bool) -> Result<(), VzError> {
        let removed = self.release_listener_port(port)?;
        if require_registered && !removed {
            return Err(VzError::Backend(format!(
                "no listener on port {port} for device {}",
                self.index
            )));
        }

        let machine = self.machine.clone();
        let index = self.index;
        let result = Arc::new(Mutex::new(Some(Ok(()))));
        let result_out = result.clone();

        self.queue.exec_block_sync(&StackBlock::new(move || unsafe {
            let devices = machine.socketDevices();
            if index >= devices.count() {
                *result_out
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Err(
                    VzError::Backend("socket device is no longer available".to_string()),
                ));
                return;
            }

            let device: Retained<VZSocketDevice> = devices.objectAtIndex(index);
            let Some(vsock) = device.downcast_ref::<VZVirtioSocketDevice>() else {
                *result_out
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Err(
                    VzError::Backend("socket device is not a virtio socket device".to_string()),
                ));
                return;
            };

            vsock.removeSocketListenerForPort(port);
        }));

        let result = result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| {
                VzError::Backend("failed to capture listener removal result".to_string())
            })?;

        result
    }
}

impl SocketDevice for VirtioSocketDevice {
    type Connection = VirtioSocketConnection;
    type Listener = VirtioSocketListener;

    async fn connect(&self, port: u32) -> Result<Self::Connection, VzError> {
        let machine = self.machine.clone();
        let queue = self.queue.clone();
        let index = self.index;
        let (sender, receiver) = oneshot::channel();
        let shared_sender = Arc::new(Mutex::new(Some(sender)));

        queue.exec_block_async(&StackBlock::new(move || unsafe {
            let completion_sender = shared_sender.clone();
            let devices = machine.socketDevices();
            if index >= devices.count() {
                send_completion_once(
                    &completion_sender,
                    Err(VzError::Backend(
                        "socket device is no longer available".to_string(),
                    )),
                );
                return;
            }

            let device: Retained<VZSocketDevice> = devices.objectAtIndex(index);
            let Some(vsock) = device.downcast_ref::<VZVirtioSocketDevice>() else {
                send_completion_once(
                    &completion_sender,
                    Err(VzError::Backend(
                        "socket device is not a virtio socket device".to_string(),
                    )),
                );
                return;
            };

            let completion_handler = StackBlock::new(
                move |connection: *mut VZVirtioSocketConnection, err: *mut NSError| {
                    let err = err.as_ref();
                    if let Some(error) = err {
                        send_completion_once(
                            &completion_sender,
                            Err(VzError::Backend(error.localizedDescription().to_string())),
                        );
                        return;
                    }

                    let Some(connection) = connection.as_ref() else {
                        send_completion_once(
                            &completion_sender,
                            Err(VzError::Backend(
                                "vsock connection completed without a connection object"
                                    .to_string(),
                            )),
                        );
                        return;
                    };

                    let file_descriptor = connection.fileDescriptor();
                    let borrowed = BorrowedFd::borrow_raw(file_descriptor);
                    let source_port = connection.sourcePort();
                    let result = dup(borrowed)
                        .map_err(|err| VzError::Backend(format!("duplicate vsock fd: {err}")))
                        .map(|fd| (fd, source_port, port));
                    send_completion_once(&completion_sender, result);
                },
            );

            vsock.connectToPort_completionHandler(port, &completion_handler);
        }));

        receiver
            .await
            .map_err(|_| {
                VzError::Backend(
                    "vsock completion channel closed before result was delivered".to_string(),
                )
            })?
            .and_then(|(fd, source_port, destination_port)| {
                VirtioSocketConnection::new(fd, source_port, destination_port)
            })
    }

    fn listen(&self, port: u32) -> Result<Self::Listener, VzError> {
        self.reserve_listener_port(port)?;

        let (sender, receiver) = mpsc::unbounded_channel();
        let delegate = VsockListenerDelegate::new_protocol_object(sender);
        let delegate_for_set = delegate.clone();

        let machine = self.machine.clone();
        let index = self.index;
        #[allow(clippy::arc_with_non_send_sync)]
        let listener_result = Arc::new(Mutex::new(None));
        let listener_result_out = listener_result.clone();

        self.queue.exec_block_sync(&StackBlock::new(move || unsafe {
            let devices = machine.socketDevices();
            let result = if index >= devices.count() {
                Err(VzError::Backend(
                    "socket device is no longer available".to_string(),
                ))
            } else {
                let device: Retained<VZSocketDevice> = devices.objectAtIndex(index);
                let Some(vsock) = device.downcast_ref::<VZVirtioSocketDevice>() else {
                    *listener_result_out
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Err(
                        VzError::Backend("socket device is not a virtio socket device".to_string()),
                    ));
                    return;
                };

                let listener = VZVirtioSocketListener::new();
                listener.setDelegate(Some(&*delegate_for_set));
                vsock.setSocketListener_forPort(&listener, port);
                Ok(listener)
            };

            *listener_result_out
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
        }));

        let listener = listener_result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| {
                VzError::Backend("failed to capture listener registration result".to_string())
            })?;

        let listener = match listener {
            Ok(listener) => listener,
            Err(err) => {
                let _ = self.release_listener_port(port);
                return Err(err);
            }
        };

        Ok(VirtioSocketListener {
            device: self.clone(),
            port,
            receiver,
            _listener: listener,
            _delegate: delegate,
        })
    }

    fn remove_listener(&self, port: u32) -> Result<(), VzError> {
        self.unregister_listener(port, true)
    }
}

pub struct VirtioSocketConnection {
    file: AsyncFd<std::fs::File>,
    source_port: u32,
    destination_port: u32,
}

impl fmt::Debug for VirtioSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioSocketConnection")
            .field("fd", &self.file.get_ref().as_raw_fd())
            .field("source_port", &self.source_port)
            .field("destination_port", &self.destination_port)
            .finish()
    }
}

impl VirtioSocketConnection {
    fn new(fd: OwnedFd, source_port: u32, destination_port: u32) -> Result<Self, VzError> {
        let file = std::fs::File::from(fd);
        super::serial::set_nonblocking(&file)?;
        Ok(Self {
            file: AsyncFd::new(file).map_err(VzError::from)?,
            source_port,
            destination_port,
        })
    }

    /// Return the source port assigned to this connection.
    ///
    /// This is the source port associated with the connection.
    pub fn source_port(&self) -> u32 {
        self.source_port
    }

    /// Return the destination port for this connection.
    ///
    /// This is the destination port associated with the connection.
    pub fn destination_port(&self) -> u32 {
        self.destination_port
    }
}

impl AsRawFd for VirtioSocketConnection {
    fn as_raw_fd(&self) -> RawFd {
        self.file.get_ref().as_raw_fd()
    }
}

impl AsyncRead for VirtioSocketConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes =
            unsafe { &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };

        loop {
            let mut guard = ready!(self.file.poll_read_ready(cx))?;
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

impl AsyncWrite for VirtioSocketConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.file.poll_write_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.file.get_ref().flush()?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.file.get_ref().flush()?;
        nix::sys::socket::shutdown(
            self.file.get_ref().as_raw_fd(),
            nix::sys::socket::Shutdown::Write,
        )
        .map_err(io::Error::from)?;
        Poll::Ready(Ok(()))
    }
}

/// The VirtioSocketListener structure represents a listener for the Virtio socket device.
///
/// This allows the host to accept connections initiated by the guest.
/// Use `accept()` to wait for and receive incoming connections.
///
/// # Example
///
/// ```rust,no_run
/// # use std::os::fd::AsRawFd;
/// # use bento_vz::device::SocketDevice;
/// # async fn example(device: &bento_vz::device::VirtioSocketDevice) -> Result<(), bento_vz::VzError> {
/// let mut listener = device.listen(1024)?;
///
/// loop {
///     let conn = listener.accept().await?;
///     println!("New connection from guest: fd={}", conn.as_raw_fd());
///     // Handle connection...
/// }
/// # }
/// ```
///
/// # Cleanup
///
/// When the listener is dropped, it automatically:
/// - Unregisters listener from the socket device
/// - Drops _listener
/// - Drops _delegate
///
/// See also [Apple's documentation](https://developer.apple.com/documentation/virtualization/vzvirtiosocketlistener?language=objc)
pub struct VirtioSocketListener {
    device: VirtioSocketDevice,
    port: u32,
    receiver: mpsc::UnboundedReceiver<Result<PendingConnection, VzError>>,
    _listener: Retained<VZVirtioSocketListener>,
    _delegate: ListenerDelegate,
}

// SAFETY: The Objective-C objects are only accessed from the main thread
// through Virtualization.framework's dispatch queue.
unsafe impl Send for VirtioSocketListener {}

impl fmt::Debug for VirtioSocketListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtioSocketListener")
            .field("port", &self.port)
            .field("device_index", &self.device.index)
            .finish()
    }
}

impl VirtioSocketListener {
    /// Return the host port this listener is bound to.
    pub fn port(&self) -> u32 {
        self.port
    }

    /// Wait for the next guest-initiated connection.
    ///
    /// Returns the next available connection for this listener.
    pub async fn accept(&mut self) -> Result<VirtioSocketConnection, VzError> {
        let accepted = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| VzError::Backend("listener closed".to_string()))??;
        VirtioSocketConnection::new(accepted.fd, accepted.source_port, accepted.destination_port)
    }

    /// Attempt to accept a queued connection without waiting.
    ///
    /// Returns `Ok(None)` if no connection is currently available.
    pub fn try_accept(&mut self) -> Result<Option<VirtioSocketConnection>, VzError> {
        match self.receiver.try_recv() {
            Ok(result) => {
                let accepted = result?;
                Ok(Some(VirtioSocketConnection::new(
                    accepted.fd,
                    accepted.source_port,
                    accepted.destination_port,
                )?))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(VzError::Backend("listener closed".to_string()))
            }
        }
    }
}

impl Drop for VirtioSocketListener {
    fn drop(&mut self) {
        if let Err(err) = self.device.unregister_listener(self.port, false) {
            tracing::debug!(port = self.port, error = %err, "failed to remove vsock listener during drop");
        }
    }
}

fn send_completion_once<T>(sender: &Arc<Mutex<Option<oneshot::Sender<T>>>>, value: T) {
    if let Some(sender) = sender.lock().ok().and_then(|mut guard| guard.take()) {
        let _ = sender.send(value);
    }
}

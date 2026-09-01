use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use block2::StackBlock;
use nix::unistd::dup;
use objc2::{
    define_class, msg_send, rc::Retained, runtime::ProtocolObject, AllocAnyThread, ClassType,
    DefinedClass, Message,
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

#[derive(Clone, Debug, Default)]
pub(crate) struct SocketListenerRegistry {
    entries: Arc<Mutex<HashMap<(usize, u32), u64>>>,
    next_generation: Arc<AtomicU64>,
    operation: Arc<Mutex<()>>,
}

/// Port metadata for a guest connection proposed by Virtualization.framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketConnectionRequest {
    source_port: u32,
    destination_port: u32,
}

impl SocketConnectionRequest {
    pub fn source_port(&self) -> u32 {
        self.source_port
    }

    pub fn destination_port(&self) -> u32 {
        self.destination_port
    }
}

type ShouldAcceptConnection = Arc<dyn Fn(SocketConnectionRequest) -> bool + Send + Sync + 'static>;

struct VsockListenerDelegateIvars {
    sender: mpsc::UnboundedSender<PendingConnection>,
    should_accept: ShouldAcceptConnection,
    queue: Queue,
}

struct PendingConnection {
    fd: OwnedFd,
    source_port: u32,
    destination_port: u32,
    connection: QueueRetained<VZVirtioSocketConnection>,
}

struct QueueRetained<T: Message + 'static> {
    pointer: usize,
    queue: Queue,
    marker: PhantomData<Retained<T>>,
}

impl<T: Message + 'static> QueueRetained<T> {
    fn new(value: Retained<T>, queue: Queue) -> Self {
        Self {
            pointer: Retained::into_raw(value) as usize,
            queue,
            marker: PhantomData,
        }
    }
}

impl<T: Message + 'static> Drop for QueueRetained<T> {
    fn drop(&mut self) {
        let pointer = self.pointer;
        self.queue
            .exec_block_async(&StackBlock::new(move || unsafe {
                if let Some(value) = Retained::from_raw(pointer as *mut T) {
                    drop(value);
                }
            }));
    }
}

// SAFETY: Tokio threads carry only a +1 raw retain token. Drop schedules the
// matching release on the VM queue, and the framework object is never accessed.
unsafe impl<T: Message + 'static> Send for QueueRetained<T> {}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "SiloVzVsockListenerDelegate"]
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
            let fd = match dup(borrowed) {
                Ok(fd) => fd,
                Err(err) => {
                    tracing::warn!(%err, "rejected VZ vsock connection whose fd could not be duplicated");
                    return false.into();
                }
            };
            let connection = QueueRetained::new(
                connection.retain(),
                self.ivars().queue.clone(),
            );
            let request = SocketConnectionRequest {
                source_port,
                destination_port,
            };
            match catch_unwind(AssertUnwindSafe(|| (self.ivars().should_accept)(request))) {
                Ok(true) => {}
                Ok(false) => return false.into(),
                Err(_) => {
                    tracing::warn!("rejected VZ vsock connection after acceptance hook panicked");
                    return false.into();
                }
            }
            let pending = PendingConnection {
                fd,
                source_port,
                destination_port,
                connection,
            };

            match self.ivars().sender.send(pending) {
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
        sender: mpsc::UnboundedSender<PendingConnection>,
        should_accept: ShouldAcceptConnection,
        queue: Queue,
    ) -> Retained<Self> {
        let delegate = Self::alloc().set_ivars(VsockListenerDelegateIvars {
            sender,
            should_accept,
            queue,
        });
        unsafe { msg_send![super(delegate), init] }
    }
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
    listeners: SocketListenerRegistry,
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
        listeners: SocketListenerRegistry,
    ) -> Self {
        Self {
            machine,
            queue,
            index,
            listeners,
        }
    }

    fn unregister_listener(&self, port: u32, generation: Option<u64>) -> Result<(), VzError> {
        let _operation = self
            .listeners
            .operation
            .lock()
            .map_err(|_| VzError::Backend("listener operation lock poisoned".to_string()))?;
        let should_remove = {
            let mut entries = self
                .listeners
                .entries
                .lock()
                .map_err(|_| VzError::Backend("listener registry lock poisoned".to_string()))?;
            let key = (self.index, port);
            match generation {
                Some(generation) if entries.get(&key) == Some(&generation) => {
                    entries.remove(&key);
                    true
                }
                Some(_) => false,
                None => {
                    entries.remove(&key);
                    true
                }
            }
        };
        if !should_remove {
            return Ok(());
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

impl VirtioSocketDevice {
    /// Connect to a guest vsock port.
    pub async fn connect(&self, port: u32) -> Result<VirtioSocketConnection, VzError> {
        let machine = self.machine.clone();
        let queue = self.queue.clone();
        let connection_queue = self.queue.clone();
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

            let connection_queue = connection_queue.clone();
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
                    let connection =
                        QueueRetained::new(connection.retain(), connection_queue.clone());
                    let result = dup(borrowed)
                        .map_err(|err| VzError::Backend(format!("duplicate vsock fd: {err}")))
                        .map(|fd| (fd, source_port, port, connection));
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
            .and_then(|(fd, source_port, destination_port, connection)| {
                VirtioSocketConnection::new(fd, source_port, destination_port, connection)
            })
    }

    /// Listen for guest connections to a host vsock port.
    ///
    /// `should_accept` is invoked synchronously on the VM queue for each proposed
    /// connection and must return promptly. Registering again replaces the
    /// existing listener on the port, matching Virtualization.framework.
    pub fn listen<F>(&self, port: u32, should_accept: F) -> Result<VirtioSocketListener, VzError>
    where
        F: Fn(SocketConnectionRequest) -> bool + Send + Sync + 'static,
    {
        let _operation = self
            .listeners
            .operation
            .lock()
            .map_err(|_| VzError::Backend("listener operation lock poisoned".to_string()))?;
        let generation = self
            .listeners
            .next_generation
            .fetch_add(1, Ordering::Relaxed);
        let should_accept: ShouldAcceptConnection = Arc::new(should_accept);

        let (sender, receiver) = mpsc::unbounded_channel();
        let machine = self.machine.clone();
        let retention_queue = self.queue.clone();
        let delegate_queue = self.queue.clone();
        let index = self.index;
        let listener_result = Arc::new(Mutex::new(None));
        let listener_result_out = listener_result.clone();

        self.queue.exec_block_sync(&StackBlock::new(move || unsafe {
            let delegate = VsockListenerDelegate::new_protocol_object(
                sender.clone(),
                should_accept.clone(),
                delegate_queue.clone(),
            );
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
                let protocol_delegate = ProtocolObject::from_ref(&*delegate);
                listener.setDelegate(Some(protocol_delegate));
                vsock.setSocketListener_forPort(&listener, port);
                Ok((
                    QueueRetained::new(listener, retention_queue.clone()),
                    QueueRetained::new(delegate, retention_queue.clone()),
                ))
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

        let (listener, delegate) = listener?;
        self.listeners
            .entries
            .lock()
            .map_err(|_| VzError::Backend("listener registry lock poisoned".to_string()))?
            .insert((self.index, port), generation);

        Ok(VirtioSocketListener {
            device: self.clone(),
            port,
            generation,
            receiver,
            _listener: listener,
            _delegate: delegate,
        })
    }

    /// Remove the listener at `port`, doing nothing if none is registered.
    pub fn remove_listener(&self, port: u32) -> Result<(), VzError> {
        self.unregister_listener(port, None)
    }
}

pub struct VirtioSocketConnection {
    file: AsyncFd<std::fs::File>,
    source_port: u32,
    destination_port: u32,
    _connection: QueueRetained<VZVirtioSocketConnection>,
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
    fn new(
        fd: OwnedFd,
        source_port: u32,
        destination_port: u32,
        connection: QueueRetained<VZVirtioSocketConnection>,
    ) -> Result<Self, VzError> {
        let file = std::fs::File::from(fd);
        super::serial::set_nonblocking(&file)?;
        Ok(Self {
            file: AsyncFd::new(file).map_err(VzError::from)?,
            source_port,
            destination_port,
            _connection: connection,
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
/// # async fn example(device: &vz::device::VirtioSocketDevice) -> Result<(), vz::VzError> {
/// let mut listener = device.listen(1024, |connection| {
///     connection.destination_port() == 1024
/// })?;
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
/// - Releases the listener and delegate on the VM queue
///
/// See also [Apple's documentation](https://developer.apple.com/documentation/virtualization/vzvirtiosocketlistener?language=objc)
pub struct VirtioSocketListener {
    device: VirtioSocketDevice,
    port: u32,
    generation: u64,
    receiver: mpsc::UnboundedReceiver<PendingConnection>,
    _listener: QueueRetained<VZVirtioSocketListener>,
    _delegate: QueueRetained<VsockListenerDelegate>,
}

// SAFETY: Objective-C ownership is represented by queue-retained tokens, and
// the device only accesses framework objects through the VM's serial queue.
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
            .ok_or_else(|| VzError::Backend("listener closed".to_string()))?;
        VirtioSocketConnection::new(
            accepted.fd,
            accepted.source_port,
            accepted.destination_port,
            accepted.connection,
        )
    }

    /// Attempt to accept a queued connection without waiting.
    ///
    /// Returns `Ok(None)` if no connection is currently available.
    pub fn try_accept(&mut self) -> Result<Option<VirtioSocketConnection>, VzError> {
        match self.receiver.try_recv() {
            Ok(accepted) => Ok(Some(VirtioSocketConnection::new(
                accepted.fd,
                accepted.source_port,
                accepted.destination_port,
                accepted.connection,
            )?)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(VzError::Backend("listener closed".to_string()))
            }
        }
    }
}

impl Drop for VirtioSocketListener {
    fn drop(&mut self) {
        if let Err(err) = self
            .device
            .unregister_listener(self.port, Some(self.generation))
        {
            tracing::debug!(port = self.port, error = %err, "failed to remove vsock listener during drop");
        }
    }
}

fn send_completion_once<T>(sender: &Arc<Mutex<Option<oneshot::Sender<T>>>>, value: T) {
    if let Some(sender) = sender.lock().ok().and_then(|mut guard| guard.take()) {
        let _ = sender.send(value);
    }
}

#[cfg(test)]
mod tests {
    use crate::device::SocketConnectionRequest;

    #[test]
    fn connection_request_exposes_port_metadata() {
        let request = SocketConnectionRequest {
            source_port: 4000,
            destination_port: 9000,
        };
        assert_eq!(request.source_port(), 4000);
        assert_eq!(request.destination_port(), 9000);
    }
}

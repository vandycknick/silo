use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use forward_spec::{
    encode_connect, parse_reply, Address, Reply, TargetLine, Token, MAX_TARGET_LINE_BYTES,
};
use futures::Stream;
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
use protocol::v1::guest_forward_service_server::GuestForwardService;
use protocol::v1::listen_event::Event;
use protocol::v1::{
    ActivationListener, ActivationListenerBound, ErrorCode, ErrorDetail, ListenEvent,
    ListenRequest, ListenerBound, ListenerFailed,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UnixListener};
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_vsock::{VsockAddr, VsockStream, VMADDR_CID_HOST};
use tonic::{Request, Response, Status};

const MAX_LISTEN_STREAMS: usize = 64;
const MAX_ACCEPTED_CONNECTIONS: usize = 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_UNIX_MODE: u32 = 0o600;

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedStream = Pin<Box<dyn AsyncStream>>;
type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send>>;
type ListenStream = Pin<Box<dyn Stream<Item = Result<ListenEvent, Status>> + Send + 'static>>;

trait ReturnConnector: Send + Sync + 'static {
    fn connect(&self) -> ConnectFuture;
}

#[derive(Clone, Copy)]
struct VsockReturnConnector;

impl ReturnConnector for VsockReturnConnector {
    fn connect(&self) -> ConnectFuture {
        Box::pin(async {
            VsockStream::connect(VsockAddr::new(
                VMADDR_CID_HOST,
                forward_spec::FORWARD_VSOCK_PORT,
            ))
            .await
            .map(|stream| Box::pin(stream) as BoxedStream)
        })
    }
}

enum ListenerOwner {
    Stream(tokio::sync::mpsc::Sender<Result<ListenEvent, Status>>),
    Activation { name: String },
}

struct ListenerControl {
    owner: ListenerOwner,
    shutdown: Option<watch::Receiver<bool>>,
    cancelled: watch::Receiver<bool>,
}

struct OwnedForwardTask {
    cancel: watch::Sender<bool>,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl OwnedForwardTask {
    fn cancel(&self) {
        self.cancel.send_replace(true);
    }
}

impl Drop for OwnedForwardTask {
    fn drop(&mut self) {
        self.cancel();
    }
}

// Handles stay owned until joined, including when the caller awaiting a reset
// is cancelled. A subsequent reset still observes actual cleanup completion.
#[derive(Default)]
struct ForwardRegistry {
    tasks: Vec<OwnedForwardTask>,
}

impl ForwardRegistry {
    async fn reap_finished(&mut self) -> Result<(), Status> {
        let mut index = 0;
        while index < self.tasks.len() {
            if self.tasks[index].task.is_finished() {
                let result = (&mut self.tasks[index].task).await;
                self.tasks.swap_remove(index);
                task_result(result)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    async fn drain(&mut self) -> Result<(), Status> {
        for task in &self.tasks {
            task.cancel();
        }
        let mut failure = None;
        while let Some(task) = self.tasks.last_mut() {
            let result = (&mut task.task).await;
            self.tasks.pop();
            if let Err(error) = task_result(result) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn task_result(result: Result<io::Result<()>, tokio::task::JoinError>) -> Result<(), Status> {
    result
        .map_err(|error| Status::internal(format!("forward task failed to drain: {error}")))?
        .map_err(|error| Status::internal(format!("forward cleanup failed: {error}")))
}

#[derive(Clone)]
pub(crate) struct GuestForwardServiceImpl {
    listen_capacity: Arc<Semaphore>,
    connection_capacity: Arc<Semaphore>,
    connector: Arc<dyn ReturnConnector>,
    supervisor: crate::pid1::ProcessSupervisor,
    runtime: Arc<crate::lifecycle::RuntimeContext>,
    registry: Arc<Mutex<ForwardRegistry>>,
}

impl GuestForwardServiceImpl {
    pub(crate) fn new(
        supervisor: crate::pid1::ProcessSupervisor,
        runtime: Arc<crate::lifecycle::RuntimeContext>,
    ) -> Self {
        Self {
            listen_capacity: Arc::new(Semaphore::new(MAX_LISTEN_STREAMS)),
            connection_capacity: Arc::new(Semaphore::new(MAX_ACCEPTED_CONNECTIONS)),
            connector: Arc::new(VsockReturnConnector),
            supervisor,
            runtime,
            registry: Arc::new(Mutex::new(ForwardRegistry::default())),
        }
    }

    #[cfg(test)]
    fn with_connector(connector: Arc<dyn ReturnConnector>) -> Self {
        Self {
            listen_capacity: Arc::new(Semaphore::new(MAX_LISTEN_STREAMS)),
            connection_capacity: Arc::new(Semaphore::new(MAX_ACCEPTED_CONNECTIONS)),
            connector,
            supervisor: crate::pid1::ProcessSupervisor::default(),
            runtime: crate::lifecycle::RuntimeContext::for_tests(),
            registry: Arc::new(Mutex::new(ForwardRegistry::default())),
        }
    }

    pub(crate) async fn reset_for_activation(&self) -> Result<(), Status> {
        self.registry.lock().await.drain().await
    }

    pub(crate) async fn register_activation(
        &self,
        registrations: &[ActivationListener],
    ) -> Result<Vec<ActivationListenerBound>, Status> {
        validate_activation_listeners(registrations)?;
        let mut registry = self.registry.lock().await;
        registry.reap_finished().await?;
        let mut bounds = Vec::with_capacity(registrations.len());
        for registration in registrations {
            let request = registration.registration.as_ref().ok_or_else(|| {
                Status::invalid_argument("activation listener registration is required")
            })?;
            let (token, address) = parse_request(request)?;
            let result = self
                .install_listener(
                    &mut registry,
                    address,
                    request.unix_mode,
                    token,
                    ListenerOwner::Activation {
                        name: registration.name.clone(),
                    },
                )
                .await;
            match result {
                Ok(bound) => bounds.push(ActivationListenerBound {
                    name: registration.name.clone(),
                    bound: Some(ListenerBound { address: bound }),
                }),
                Err(error) => {
                    // Partial destination registrations are not left live after
                    // a bind failure. The lifecycle owner records sticky failure.
                    registry.drain().await?;
                    return Err(error);
                }
            }
        }
        Ok(bounds)
    }

    async fn install_listener(
        &self,
        registry: &mut ForwardRegistry,
        address: Address,
        unix_mode: Option<u32>,
        token: Token,
        owner: ListenerOwner,
    ) -> Result<String, Status> {
        let worker = self
            .supervisor
            .admit_internal_writer()
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let permit = Arc::clone(&self.listen_capacity)
            .try_acquire_owned()
            .map_err(|_| {
                forward_status(
                    tonic::Code::ResourceExhausted,
                    ErrorCode::ForwardLimit,
                    "forward listener capacity is exhausted",
                )
            })?;
        let listener = OwnedListener::bind(address, unix_mode)
            .await
            .map_err(bind_status)?;
        let bound = listener.bound_address().to_string();
        if let ListenerOwner::Stream(sender) = &owner {
            sender
                .try_send(Ok(ListenEvent {
                    event: Some(Event::Bound(ListenerBound {
                        address: bound.clone(),
                    })),
                }))
                .map_err(|_| Status::internal("failed to initialize forward listener stream"))?;
        }
        let (cancel, cancelled) = watch::channel(false);
        let connection_capacity = Arc::clone(&self.connection_capacity);
        let connector = Arc::clone(&self.connector);
        let shutdown = self.supervisor.shutdown_receiver();
        let task = tokio::spawn(async move {
            let _worker = worker;
            run_listener(
                listener,
                token,
                permit,
                connection_capacity,
                connector,
                ListenerControl {
                    owner,
                    shutdown,
                    cancelled,
                },
            )
            .await
        });
        registry.tasks.push(OwnedForwardTask { cancel, task });
        Ok(bound)
    }

    pub(crate) async fn handle_dialer<S>(&self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let admission = self.runtime.admit_mutation().map_err(io::Error::other)?;
        let worker = self.supervisor.admit_internal_writer()?;
        let mut registry = self.registry.lock().await;
        registry.reap_finished().await.map_err(io::Error::other)?;
        let permit = Arc::clone(&self.connection_capacity)
            .try_acquire_owned()
            .map_err(|_| io::Error::other("forward connection capacity is exhausted"))?;
        let (cancel, mut cancelled) = watch::channel(false);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut shutdown = self.supervisor.shutdown_receiver();
        let task = tokio::spawn(async move {
            let _worker = worker;
            let _permit = permit;
            let mut sender = sender;
            let result = tokio::select! {
                biased;
                () = wait_shutdown(&mut shutdown) => Ok(()),
                () = wait_cancelled(&mut cancelled) => Ok(()),
                () = sender.closed() => Ok(()),
                result = crate::forward::dialer::handle(stream) => result,
            };
            let _ = sender.send(result);
            Ok(())
        });
        registry.tasks.push(OwnedForwardTask { cancel, task });
        drop(registry);
        drop(admission);
        receiver
            .await
            .map_err(|_| io::Error::other("forward dialer task stopped"))?
    }
}

#[tonic::async_trait]
impl GuestForwardService for GuestForwardServiceImpl {
    type ListenStream = ListenStream;

    async fn listen(
        &self,
        request: Request<ListenRequest>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        let _admission = self.runtime.admit_mutation()?;
        let request = request.into_inner();
        let (token, address) = parse_request(&request)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let mut registry = self.registry.lock().await;
        registry.reap_finished().await?;
        if let Err(error) = self
            .install_listener(
                &mut registry,
                address,
                request.unix_mode,
                token,
                ListenerOwner::Stream(sender),
            )
            .await
        {
            // Listen preserves its terminal bind-failure event contract.
            if error.code() == tonic::Code::ResourceExhausted
                || error.code() == tonic::Code::Unavailable
            {
                return Err(error);
            }
            let detail = protocol::decode_error_detail(error.details()).unwrap_or(ErrorDetail {
                code: Some(ErrorCode::AgentUnavailable as i32),
                retry_after: None,
            });
            let event = ListenEvent {
                event: Some(Event::Failed(ListenerFailed {
                    error: Some(detail),
                })),
            };
            return Ok(Response::new(Box::pin(tokio_stream::iter([Ok(event)]))));
        }

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

async fn wait_shutdown(shutdown: &mut Option<tokio::sync::watch::Receiver<bool>>) {
    match shutdown {
        Some(receiver) => {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    return;
                }
            }
        }
        None => std::future::pending().await,
    }
}

async fn wait_cancelled(cancelled: &mut watch::Receiver<bool>) {
    while !*cancelled.borrow() {
        if cancelled.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_owner_closed(owner: &ListenerOwner) {
    match owner {
        ListenerOwner::Stream(sender) => sender.closed().await,
        ListenerOwner::Activation { .. } => std::future::pending().await,
    }
}

fn parse_request(request: &ListenRequest) -> Result<(Token, Address), Status> {
    let invalid = |message: String| {
        forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            message,
        )
    };
    let token =
        Token::try_from(request.token.as_ref()).map_err(|error| invalid(error.to_string()))?;
    let address = request
        .listen
        .parse::<Address>()
        .map_err(|error| invalid(error.to_string()))?;
    validate_request(&address, request.unix_mode)?;
    Ok((token, address))
}

pub(crate) fn validate_activation_listeners(
    registrations: &[ActivationListener],
) -> Result<(), Status> {
    if registrations.len() > MAX_LISTEN_STREAMS {
        return Err(forward_status(
            tonic::Code::ResourceExhausted,
            ErrorCode::ForwardLimit,
            "too many activation listeners",
        ));
    }
    let mut names = HashSet::new();
    let mut addresses = HashSet::new();
    for registration in registrations {
        if registration.name.is_empty()
            || registration.name.len() > 128
            || !names.insert(registration.name.as_str())
        {
            return Err(Status::invalid_argument(
                "activation listener names must be unique and contain 1 through 128 bytes",
            ));
        }
        let request = registration.registration.as_ref().ok_or_else(|| {
            Status::invalid_argument("activation listener registration is required")
        })?;
        let (_, address) = parse_request(request)?;
        // Port zero allocates distinct ephemeral bindings; fixed endpoints must
        // be unique, including alternate textual spellings of the same address.
        if !matches!(&address, Address::Tcp(address) if address.port() == 0)
            && !addresses.insert(address.to_string())
        {
            return Err(Status::invalid_argument(
                "activation listener addresses must be unique",
            ));
        }
    }
    Ok(())
}

fn bind_status(error: io::Error) -> Status {
    let code = match error.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists => tonic::Code::AlreadyExists,
        io::ErrorKind::PermissionDenied => tonic::Code::PermissionDenied,
        _ => tonic::Code::Internal,
    };
    let detail = bind_error_detail(&error);
    protocol::status_with_error(
        code,
        ErrorCode::try_from(detail.code.unwrap_or(ErrorCode::AgentUnavailable as i32))
            .unwrap_or(ErrorCode::AgentUnavailable),
        error.to_string(),
        None,
    )
}

fn validate_request(address: &Address, unix_mode: Option<u32>) -> Result<(), Status> {
    if unix_mode.is_some_and(|mode| mode > 0o777) {
        return Err(forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            "unix_mode must contain only permission bits from 0000 through 0777",
        ));
    }
    match address {
        Address::Tcp(_) if unix_mode.is_some() => Err(forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            "unix_mode is valid only for a Unix listener",
        )),
        Address::Unix(path) if !path.is_absolute() => Err(forward_status(
            tonic::Code::InvalidArgument,
            ErrorCode::ForwardInvalid,
            "guest Unix listener path must be absolute",
        )),
        _ => Ok(()),
    }
}

async fn run_listener(
    listener: OwnedListener,
    token: Token,
    _permit: OwnedSemaphorePermit,
    connection_capacity: Arc<Semaphore>,
    connector: Arc<dyn ReturnConnector>,
    mut control: ListenerControl,
) -> io::Result<()> {
    let mut relays = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = wait_shutdown(&mut control.shutdown) => break,
            () = wait_cancelled(&mut control.cancelled) => break,
            () = wait_owner_closed(&control.owner) => break,
            accepted = listener.accept() => match accepted {
                Ok(mut client) => {
                    let permit = match Arc::clone(&connection_capacity).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    let connector = Arc::clone(&connector);
                    relays.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = relay_connection(&mut client, token, connector.as_ref()).await {
                            tracing::debug!(%error, "forward listener connection closed during setup or relay");
                        }
                    });
                }
                Err(error) => {
                    tracing::debug!(%error, "forward listener accept failed");
                    break;
                }
            },
            completed = relays.join_next(), if !relays.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "forward listener relay task failed");
                }
            }
        }
    }
    relays.abort_all();
    while relays.join_next().await.is_some() {}
    if let ListenerOwner::Activation { name } = &control.owner {
        tracing::debug!(%name, "activation-owned forward listener drained");
    }
    listener.close()
}

async fn relay_connection(
    client: &mut BoxedStream,
    token: Token,
    connector: &dyn ReturnConnector,
) -> io::Result<()> {
    let mut remote = tokio::time::timeout(SETUP_TIMEOUT, async {
        let mut remote = connector.connect().await?;
        remote
            .write_all(&encode_connect(&TargetLine::Token(token)).map_err(io::Error::other)?)
            .await?;
        let line = forward_spec::io::read_line(&mut remote, MAX_TARGET_LINE_BYTES)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        match parse_reply(&line) {
            Ok(Reply::Ok) => Ok(remote),
            Ok(Reply::Err(_)) | Err(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "forward return port rejected connection",
            )),
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "forward return setup timed out"))??;
    tokio::io::copy_bidirectional(client, &mut remote).await?;
    Ok(())
}

enum OwnedListener {
    Tcp {
        listener: TcpListener,
        address: std::net::SocketAddr,
    },
    Unix {
        listener: UnixListener,
        socket: OwnedUnixSocket,
    },
}

impl OwnedListener {
    async fn bind(address: Address, unix_mode: Option<u32>) -> io::Result<Self> {
        match address {
            Address::Tcp(address) => {
                let socket = if address.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                socket.set_reuseaddr(true)?;
                socket.bind(address)?;
                let listener = socket.listen(1024)?;
                let address = listener.local_addr()?;
                Ok(Self::Tcp { listener, address })
            }
            Address::Unix(path) => {
                remove_existing_socket(&path)?;
                let listener = UnixListener::bind(&path)?;
                if let Err(error) = fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(unix_mode.unwrap_or(DEFAULT_UNIX_MODE)),
                ) {
                    let _ = fs::remove_file(&path);
                    return Err(error);
                }
                let socket = OwnedUnixSocket::new(path)?;
                Ok(Self::Unix { listener, socket })
            }
        }
    }

    fn bound_address(&self) -> Address {
        match self {
            Self::Tcp { address, .. } => Address::Tcp(*address),
            Self::Unix { socket, .. } => Address::Unix(socket.path.clone()),
        }
    }

    async fn accept(&self) -> io::Result<BoxedStream> {
        match self {
            Self::Tcp { listener, .. } => listener
                .accept()
                .await
                .map(|(stream, _)| Box::pin(stream) as BoxedStream),
            Self::Unix { listener, .. } => listener
                .accept()
                .await
                .map(|(stream, _)| Box::pin(stream) as BoxedStream),
        }
    }

    fn close(self) -> io::Result<()> {
        match self {
            Self::Tcp { listener, .. } => {
                drop(listener);
                Ok(())
            }
            Self::Unix { listener, socket } => {
                drop(listener);
                socket.unlink()
            }
        }
    }
}

struct OwnedUnixSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedUnixSocket {
    fn new(path: PathBuf) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound Unix path is not a socket",
            ));
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn unlink(&self) -> io::Result<()> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            match fs::remove_file(&self.path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for OwnedUnixSocket {
    fn drop(&mut self) {
        if let Err(error) = self.unlink() {
            tracing::debug!(path = %self.path.display(), %error, "failed to clean up forward Unix listener");
        }
    }
}

fn remove_existing_socket(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let occupied = || {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "Unix listener {} is active or cannot be proven stale",
                        path.display()
                    ),
                )
            };
            let probe = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                None,
            )?;
            // Only a positively refused nonblocking connection proves staleness.
            // A full backlog or inaccessible socket must never be unlinked.
            if connect(probe.as_raw_fd(), &UnixAddr::new(path)?)
                != Err(nix::errno::Errno::ECONNREFUSED)
            {
                return Err(occupied());
            }
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(occupied());
            }
            fs::remove_file(path)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to replace non-socket path {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn bind_error_detail(error: &io::Error) -> ErrorDetail {
    let code = match error.kind() {
        io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists => ErrorCode::ForwardAddressInUse,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::Unsupported => ErrorCode::ForwardUnsupported,
        _ => ErrorCode::AgentUnavailable,
    };
    ErrorDetail {
        code: Some(code as i32),
        retry_after: None,
    }
}

fn forward_status(code: tonic::Code, error: ErrorCode, message: impl AsRef<str>) -> Status {
    protocol::status_with_error(code, error, message, None)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use protocol::v1::guest_forward_service_server::GuestForwardService;
    use protocol::v1::listen_event::Event;
    use protocol::v1::{ActivationListener, ListenRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tonic::{Code, Request};

    use crate::forward::listen::{
        BoxedStream, ConnectFuture, GuestForwardServiceImpl, ListenStream, ReturnConnector,
        MAX_ACCEPTED_CONNECTIONS, MAX_LISTEN_STREAMS,
    };

    // This connector uses a real local return-port socket, exercising the same
    // CONNECT authorization and relay implementation as the vsock transport.
    struct TcpReturnConnector(std::net::SocketAddr);

    impl ReturnConnector for TcpReturnConnector {
        fn connect(&self) -> ConnectFuture {
            let address = self.0;
            Box::pin(async move {
                tokio::net::TcpStream::connect(address)
                    .await
                    .map(|stream| Box::pin(stream) as BoxedStream)
            })
        }
    }

    fn activation_listener(name: &str, path: &std::path::Path, token: u8) -> ActivationListener {
        ActivationListener {
            name: name.to_string(),
            registration: Some(request(
                format!("unix:{}", path.display()),
                [token; 16],
                None,
            )),
        }
    }

    struct TestConnector {
        streams: Mutex<VecDeque<BoxedStream>>,
    }

    impl ReturnConnector for TestConnector {
        fn connect(&self) -> ConnectFuture {
            let stream = self.streams.lock().expect("connector lock").pop_front();
            Box::pin(async move {
                stream.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no test stream"))
            })
        }
    }

    fn connector(streams: Vec<BoxedStream>) -> Arc<TestConnector> {
        Arc::new(TestConnector {
            streams: Mutex::new(streams.into()),
        })
    }

    fn request<const N: usize>(
        listen: String,
        token: [u8; N],
        unix_mode: Option<u32>,
    ) -> ListenRequest {
        ListenRequest {
            listen,
            token: token.to_vec().into(),
            unix_mode,
        }
    }

    async fn bound_address(stream: &mut ListenStream) -> String {
        use futures::StreamExt;
        let event = stream
            .next()
            .await
            .expect("bound event")
            .expect("successful event");
        match event.event.expect("event body") {
            Event::Bound(bound) => bound.address,
            Event::Failed(_) => panic!("listener unexpectedly failed"),
        }
    }

    #[tokio::test]
    async fn shutdown_closes_actual_unix_listener_and_unlinks_before_writer_drain() {
        use futures::StreamExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("forward.sock");
        let supervisor = crate::pid1::ProcessSupervisor::default();
        let service = GuestForwardServiceImpl::new(
            supervisor.clone(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        let mut stream = service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [7; 16],
                None,
            )))
            .await
            .unwrap()
            .into_inner();
        let _ = bound_address(&mut stream).await;
        let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
        supervisor.begin_writer_shutdown().unwrap();
        supervisor.wait_internal_writers().await.unwrap();
        assert!(!path.exists());
        let mut byte = [0];
        let eof = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(eof, Ok(0) | Err(_)));
        assert!(service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [8; 16],
                None,
            )))
            .await
            .is_err());
        // The host's listen stream was deliberately not dropped to cause drain.
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn tcp_port_zero_returns_connections_with_exact_token_and_splices() {
        let (return_agent, mut return_host) = tokio::io::duplex(1024);
        let service = GuestForwardServiceImpl::with_connector(connector(vec![
            Box::pin(return_agent) as BoxedStream,
        ]));
        let mut stream = service
            .listen(Request::new(request(
                "tcp:127.0.0.1:0".to_string(),
                [0xab; 16],
                None,
            )))
            .await
            .expect("listen RPC")
            .into_inner();
        let address: std::net::SocketAddr = bound_address(&mut stream)
            .await
            .strip_prefix("tcp:")
            .expect("TCP prefix")
            .parse()
            .expect("bound socket address");
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect listener");
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            return_host.read_exact(&mut byte).await.expect("read token");
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        assert_eq!(line, b"CONNECT abababababababababababababababab\n");
        return_host.write_all(b"OK\n").await.expect("reply OK");
        client.write_all(b"guest").await.expect("write client");
        let mut payload = [0_u8; 5];
        return_host
            .read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"guest");
        return_host.write_all(b"host").await.expect("write return");
        client
            .read_exact(&mut payload[..4])
            .await
            .expect("read client payload");
        assert_eq!(&payload[..4], b"host");
    }

    #[tokio::test]
    async fn return_error_closes_accepted_connection() {
        let (return_agent, mut return_host) = tokio::io::duplex(1024);
        let service = GuestForwardServiceImpl::with_connector(connector(vec![
            Box::pin(return_agent) as BoxedStream,
        ]));
        let mut stream = service
            .listen(Request::new(request(
                "tcp:127.0.0.1:0".to_string(),
                [1; 16],
                None,
            )))
            .await
            .expect("listen RPC")
            .into_inner();
        let address: std::net::SocketAddr = bound_address(&mut stream)
            .await
            .strip_prefix("tcp:")
            .expect("TCP prefix")
            .parse()
            .expect("bound socket address");
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect listener");
        let _ = forward_spec::io::read_line(&mut return_host, 512)
            .await
            .expect("read token");
        return_host
            .write_all(b"ERR invalid\n")
            .await
            .expect("reject return");
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("read EOF"), 0);
    }

    #[tokio::test]
    async fn dropping_stream_closes_tcp_listener_and_accepted_connections() {
        let (return_agent, mut return_host) = tokio::io::duplex(1024);
        let service = GuestForwardServiceImpl::with_connector(connector(vec![
            Box::pin(return_agent) as BoxedStream,
        ]));
        let mut stream = service
            .listen(Request::new(request(
                "tcp:127.0.0.1:0".to_string(),
                [2; 16],
                None,
            )))
            .await
            .expect("listen RPC")
            .into_inner();
        let address: std::net::SocketAddr = bound_address(&mut stream)
            .await
            .strip_prefix("tcp:")
            .expect("TCP prefix")
            .parse()
            .expect("bound socket address");
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect listener");
        let _ = forward_spec::io::read_line(&mut return_host, 512)
            .await
            .expect("read token");
        return_host.write_all(b"OK\n").await.expect("reply OK");
        drop(stream);
        let mut byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("accepted connection close deadline")
            .expect("accepted connection read");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn unix_listener_refuses_a_live_socket_without_replacing_its_inode() {
        use futures::StreamExt;
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("live.sock");
        let _original = UnixListener::bind(&path).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let service = GuestForwardServiceImpl::new(
            crate::pid1::ProcessSupervisor::default(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        let mut stream = service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [7; 16],
                Some(0o666),
            )))
            .await
            .unwrap()
            .into_inner();
        let event = stream.next().await.unwrap().unwrap();
        let Some(Event::Failed(failed)) = event.event else {
            panic!("live socket must fail binding");
        };
        assert_eq!(
            failed.error.unwrap().code,
            Some(protocol::v1::ErrorCode::ForwardAddressInUse as i32)
        );
        assert!(stream.next().await.is_none());
        let preserved = fs::symlink_metadata(&path).unwrap();
        assert_eq!(preserved.ino(), metadata.ino());
        assert_eq!(
            preserved.permissions().mode(),
            metadata.permissions().mode()
        );
        assert_eq!(service.listen_capacity.available_permits(), 64);
    }

    #[tokio::test]
    async fn unix_mode_cleanup_and_inode_safe_replacement() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("forward.sock");
        let stale = UnixListener::bind(&path).expect("bind stale socket");
        drop(stale);
        let service = GuestForwardServiceImpl::with_connector(connector(Vec::new()));
        let mut stream = service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [3; 16],
                Some(0o666),
            )))
            .await
            .expect("listen RPC")
            .into_inner();
        assert_eq!(
            bound_address(&mut stream).await,
            format!("unix:{}", path.display())
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o666
        );
        fs::remove_file(&path).expect("remove owned socket");
        fs::write(&path, b"replacement").expect("write replacement");
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(fs::read(&path).expect("read replacement"), b"replacement");

        let cleanup_path = directory.path().join("cleanup.sock");
        let mut cleanup_stream = service
            .listen(Request::new(request(
                format!("unix:{}", cleanup_path.display()),
                [3; 16],
                None,
            )))
            .await
            .expect("listen cleanup RPC")
            .into_inner();
        let _ = bound_address(&mut cleanup_stream).await;
        drop(cleanup_stream);
        tokio::time::timeout(Duration::from_secs(1), async {
            while cleanup_path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Unix listener cleanup deadline");
    }

    #[tokio::test]
    async fn rejects_invalid_requests_and_sixty_fifth_stream() {
        let service = GuestForwardServiceImpl::with_connector(connector(Vec::new()));
        assert_eq!(service.listen_capacity.available_permits(), 64);
        assert_eq!(service.connection_capacity.available_permits(), 1024);
        for request in [
            request("unix:relative.sock".to_string(), [0; 16], None),
            request("tcp:127.0.0.1:0".to_string(), [0; 15], None),
            request("tcp:127.0.0.1:0".to_string(), [0; 16], Some(0o600)),
            request("unix:/tmp/x".to_string(), [0; 16], Some(0o1000)),
        ] {
            let error = match service.listen(Request::new(request)).await {
                Ok(_) => panic!("invalid request was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code(), Code::InvalidArgument);
        }

        let mut streams = Vec::new();
        for _ in 0..64 {
            streams.push(
                service
                    .listen(Request::new(request(
                        "tcp:127.0.0.1:0".to_string(),
                        [4; 16],
                        None,
                    )))
                    .await
                    .expect("admit listener")
                    .into_inner(),
            );
        }
        let error = match service
            .listen(Request::new(request(
                "tcp:127.0.0.1:0".to_string(),
                [4; 16],
                None,
            )))
            .await
        {
            Ok(_) => panic!("sixty-fifth listener was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), Code::ResourceExhausted);
        drop(streams);
    }

    #[tokio::test]
    async fn bind_failure_is_one_terminal_failed_event() {
        use futures::StreamExt;
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("not-a-socket");
        fs::write(&path, b"keep").expect("write regular file");
        let service = GuestForwardServiceImpl::with_connector(connector(Vec::new()));
        let mut stream = service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [5; 16],
                None,
            )))
            .await
            .expect("listen RPC")
            .into_inner();
        let event = stream.next().await.expect("failed event").expect("event");
        assert!(matches!(event.event, Some(Event::Failed(_))));
        assert!(stream.next().await.is_none());
        assert_eq!(fs::read(path).expect("regular file remains"), b"keep");
    }

    #[tokio::test]
    async fn activation_drains_inherited_stream_and_relays_before_named_rebind() {
        use futures::StreamExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("machine.sock");
        let return_port = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service = GuestForwardServiceImpl::with_connector(Arc::new(TcpReturnConnector(
            return_port.local_addr().unwrap(),
        )));
        let mut inherited = service
            .listen(Request::new(request(
                format!("unix:{}", path.display()),
                [1; 16],
                None,
            )))
            .await
            .unwrap()
            .into_inner();
        bound_address(&mut inherited).await;
        let mut old_client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (mut old_return, _) = return_port.accept().await.unwrap();
        assert_eq!(
            forward_spec::io::read_line(&mut old_return, 512)
                .await
                .unwrap(),
            b"CONNECT 01010101010101010101010101010101\n",
        );
        old_return.write_all(b"OK\n").await.unwrap();
        old_client.write_all(b"old").await.unwrap();
        let mut payload = [0; 3];
        old_return.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"old");

        service.reset_for_activation().await.unwrap();
        assert!(!path.exists());
        assert!(inherited.next().await.is_none());
        let mut byte = [0];
        assert_eq!(old_client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(old_return.read(&mut byte).await.unwrap(), 0);
        assert_eq!(
            service.connection_capacity.available_permits(),
            MAX_ACCEPTED_CONNECTIONS
        );
        assert_eq!(
            service.listen_capacity.available_permits(),
            MAX_LISTEN_STREAMS
        );

        let bounds = service
            .register_activation(&[activation_listener("machine", &path, 2)])
            .await
            .unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].name, "machine");
        assert_eq!(
            bounds[0].bound.as_ref().unwrap().address,
            format!("unix:{}", path.display()),
        );
        // No Listen response stream owns this destination listener.
        let mut new_client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (mut new_return, _) = return_port.accept().await.unwrap();
        assert_eq!(
            forward_spec::io::read_line(&mut new_return, 512)
                .await
                .unwrap(),
            b"CONNECT 02020202020202020202020202020202\n",
        );
        new_return.write_all(b"OK\n").await.unwrap();
        new_client.write_all(b"new").await.unwrap();
        new_return.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"new");
        service.reset_for_activation().await.unwrap();
        assert!(!path.exists());
        assert_eq!(new_client.read(&mut byte).await.unwrap(), 0);
        service.reset_for_activation().await.unwrap();
        assert!(service.register_activation(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn activation_bind_failure_drains_partial_bindings_and_preserves_conflict() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first.sock");
        let conflict = root.path().join("conflict.sock");
        let occupied = UnixListener::bind(&conflict).unwrap();
        let metadata = fs::symlink_metadata(&conflict).unwrap();
        let service = GuestForwardServiceImpl::new(
            crate::pid1::ProcessSupervisor::default(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        let error = service
            .register_activation(&[
                activation_listener("first", &first, 3),
                activation_listener("conflict", &conflict, 4),
            ])
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::AlreadyExists);
        assert_eq!(
            protocol::decode_error_detail(error.details()).unwrap().code,
            Some(protocol::v1::ErrorCode::ForwardAddressInUse as i32),
        );
        assert!(!first.exists());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::symlink_metadata(&conflict).unwrap().ino(),
            metadata.ino()
        );
        assert_eq!(
            service.listen_capacity.available_permits(),
            MAX_LISTEN_STREAMS
        );
        drop(occupied);
    }

    #[tokio::test]
    async fn activation_validation_rejects_invalid_registration_before_binding() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("never-bound.sock");
        let valid = activation_listener("one", &path, 5);
        let mut bad_token = valid.clone();
        bad_token.registration.as_mut().unwrap().token = vec![1; 15].into();
        let service = GuestForwardServiceImpl::new(
            crate::pid1::ProcessSupervisor::default(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        for registrations in [
            vec![valid.clone(), valid.clone()],
            vec![ActivationListener {
                name: String::new(),
                ..valid.clone()
            }],
            vec![ActivationListener {
                name: "x".repeat(129),
                ..valid.clone()
            }],
            vec![ActivationListener {
                name: "missing".to_string(),
                registration: None,
            }],
            vec![bad_token],
            vec![
                valid.clone(),
                ActivationListener {
                    name: "two".to_string(),
                    ..valid
                },
            ],
        ] {
            assert_eq!(
                service
                    .register_activation(&registrations)
                    .await
                    .unwrap_err()
                    .code(),
                Code::InvalidArgument,
            );
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    async fn activation_reset_drains_real_incoming_dialer_connection() {
        let service = GuestForwardServiceImpl::new(
            crate::pid1::ProcessSupervisor::default(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, incoming) = tokio::net::UnixStream::pair().unwrap();
        let forwards = service.clone();
        let task = tokio::spawn(async move { forwards.handle_dialer(incoming).await });
        client
            .write_all(format!("CONNECT tcp:{}\n", target.local_addr().unwrap()).as_bytes())
            .await
            .unwrap();
        let (mut target_stream, _) = target.accept().await.unwrap();
        assert_eq!(
            forward_spec::io::read_line(&mut client, 512).await.unwrap(),
            b"OK\n"
        );
        client.write_all(b"payload").await.unwrap();
        let mut payload = [0; 7];
        target_stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        service.reset_for_activation().await.unwrap();
        task.await.unwrap().unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(target_stream.read(&mut byte).await.unwrap(), 0);
        assert_eq!(
            service.connection_capacity.available_permits(),
            MAX_ACCEPTED_CONNECTIONS
        );
    }

    #[tokio::test]
    async fn shutdown_drains_activation_owned_named_listener_without_stream_drop() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("machine.sock");
        let supervisor = crate::pid1::ProcessSupervisor::default();
        let service = GuestForwardServiceImpl::new(
            supervisor.clone(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        service
            .register_activation(&[activation_listener("machine", &path, 6)])
            .await
            .unwrap();
        assert!(path.exists());
        supervisor.begin_writer_shutdown().unwrap();
        supervisor.wait_internal_writers().await.unwrap();
        assert!(!path.exists());
        service.reset_for_activation().await.unwrap();
        assert!(service
            .register_activation(&[activation_listener("machine", &path, 7)])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn activation_listener_lifetime_follows_last_shared_registry_owner() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("machine.sock");
        let service = GuestForwardServiceImpl::new(
            crate::pid1::ProcessSupervisor::default(),
            crate::lifecycle::RuntimeContext::for_tests(),
        );
        service
            .register_activation(&[activation_listener("machine", &path, 8)])
            .await
            .unwrap();
        let retained = service.clone();
        drop(service);
        assert!(path.exists());
        drop(retained);
        tokio::time::timeout(Duration::from_secs(1), async {
            while path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

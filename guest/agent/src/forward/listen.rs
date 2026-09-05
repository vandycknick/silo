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
    ErrorCode, ErrorDetail, ListenEvent, ListenRequest, ListenerBound, ListenerFailed,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UnixListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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

#[derive(Clone)]
pub(crate) struct GuestForwardServiceImpl {
    listen_capacity: Arc<Semaphore>,
    connection_capacity: Arc<Semaphore>,
    connector: Arc<dyn ReturnConnector>,
}

impl GuestForwardServiceImpl {
    pub(crate) fn new() -> Self {
        Self {
            listen_capacity: Arc::new(Semaphore::new(MAX_LISTEN_STREAMS)),
            connection_capacity: Arc::new(Semaphore::new(MAX_ACCEPTED_CONNECTIONS)),
            connector: Arc::new(VsockReturnConnector),
        }
    }

    #[cfg(test)]
    fn with_connector(connector: Arc<dyn ReturnConnector>) -> Self {
        Self {
            listen_capacity: Arc::new(Semaphore::new(MAX_LISTEN_STREAMS)),
            connection_capacity: Arc::new(Semaphore::new(MAX_ACCEPTED_CONNECTIONS)),
            connector,
        }
    }
}

#[tonic::async_trait]
impl GuestForwardService for GuestForwardServiceImpl {
    type ListenStream = ListenStream;

    async fn listen(
        &self,
        request: Request<ListenRequest>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        let permit = self
            .listen_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                forward_status(
                    tonic::Code::ResourceExhausted,
                    ErrorCode::ForwardLimit,
                    "forward listener capacity is exhausted",
                )
            })?;
        let request = request.into_inner();
        let token = Token::try_from(request.token.as_ref()).map_err(|error| {
            forward_status(
                tonic::Code::InvalidArgument,
                ErrorCode::ForwardInvalid,
                error.to_string(),
            )
        })?;
        let address = request.listen.parse::<Address>().map_err(|error| {
            forward_status(
                tonic::Code::InvalidArgument,
                ErrorCode::ForwardInvalid,
                error.to_string(),
            )
        })?;
        validate_request(&address, request.unix_mode)?;

        let listener = match OwnedListener::bind(address, request.unix_mode).await {
            Ok(listener) => listener,
            Err(error) => {
                let event = ListenEvent {
                    event: Some(Event::Failed(ListenerFailed {
                        error: Some(bind_error_detail(&error)),
                    })),
                };
                return Ok(Response::new(Box::pin(tokio_stream::iter([Ok(event)]))));
            }
        };
        let bound = listener.bound_address().to_string();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(Ok(ListenEvent {
                event: Some(Event::Bound(ListenerBound { address: bound })),
            }))
            .map_err(|_| Status::internal("failed to initialize forward listener stream"))?;
        let connection_capacity = Arc::clone(&self.connection_capacity);
        let connector = Arc::clone(&self.connector);
        tokio::spawn(async move {
            run_listener(
                listener,
                token,
                permit,
                connection_capacity,
                connector,
                sender,
            )
            .await;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
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
    sender: tokio::sync::mpsc::Sender<Result<ListenEvent, Status>>,
) {
    let mut relays = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = sender.closed() => break,
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
}

impl Drop for OwnedUnixSocket {
    fn drop(&mut self) {
        let matches = fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        });
        if matches {
            if let Err(error) = fs::remove_file(&self.path) {
                if error.kind() != io::ErrorKind::NotFound {
                    tracing::debug!(path = %self.path.display(), %error, "failed to clean up forward Unix listener");
                }
            }
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
    use protocol::v1::ListenRequest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tonic::{Code, Request};

    use crate::forward::listen::{
        BoxedStream, ConnectFuture, GuestForwardServiceImpl, ListenStream, ReturnConnector,
    };

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
        let service = GuestForwardServiceImpl::new();
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
}

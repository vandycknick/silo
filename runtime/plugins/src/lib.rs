use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use nix::cmsg_space;
use nix::errno::Errno;
use nix::sys::socket::{
    recvmsg, sendmsg, shutdown, ControlMessage, ControlMessageOwned, MsgFlags, Shutdown,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex, OnceCell};

const CONTROL_MAGIC: u32 = 0x4252_4b52;
const CONTROL_MESSAGE_MAX_BYTES: usize = 256;

static RUNTIME: OnceCell<Arc<PluginRuntime>> = OnceCell::const_new();

#[derive(Debug, Deserialize)]
pub struct StartupMessage {
    pub api_version: u32,
    pub vsock_endpoint: String,
    pub mode: String,
    pub port: u32,
    pub transport: PluginTransport,
    pub runtime_dir: String,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    pub fd: i32,
}

impl StartupMessage {
    fn expect_api_v1(&self) -> io::Result<()> {
        if self.api_version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported api_version {}", self.api_version),
            ));
        }
        if self.fd != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected fd 3, got {}", self.fd),
            ));
        }
        Ok(())
    }

    fn expect_connect(&self) -> io::Result<()> {
        self.expect_api_v1()?;
        if self.mode != "connect" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected connect mode, got {}", self.mode),
            ));
        }
        if self.transport != PluginTransport::BrokeredConnect {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "expected brokered_connect transport, got {}",
                    self.transport.as_str()
                ),
            ));
        }
        Ok(())
    }

    fn expect_listen(&self) -> io::Result<()> {
        self.expect_api_v1()?;
        if self.mode != "listen" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected listen mode, got {}", self.mode),
            ));
        }
        if self.transport != PluginTransport::ListenAccept {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "expected listen_accept transport, got {}",
                    self.transport.as_str()
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginTransport {
    BrokeredConnect,
    ListenAccept,
}

impl PluginTransport {
    fn as_str(self) -> &'static str {
        match self {
            Self::BrokeredConnect => "brokered_connect",
            Self::ListenAccept => "listen_accept",
        }
    }
}

impl Plugin {
    pub async fn init(name: &str) -> io::Result<Self> {
        let runtime = runtime().await?;
        emit_event(PluginEvent::Ready)?;
        Ok(Self {
            runtime,
            _name: name.to_string(),
        })
    }

    pub async fn connect(&self) -> io::Result<AsyncStream> {
        self.runtime.startup.expect_connect()?;

        let request_id = self.runtime.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.runtime.pending.lock().await.insert(request_id, tx);

        if let Err(err) = self
            .runtime
            .control
            .send_message(&ControlMessageKind::ConnectOpen { request_id }, None)
            .await
        {
            let _ = self.runtime.pending.lock().await.remove(&request_id);
            return Err(err);
        }

        let fd = rx.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "plugin control response channel closed",
            )
        })??;

        into_async_stream(fd)
    }

    pub async fn accept(&self) -> io::Result<AsyncStream> {
        self.runtime.startup.expect_listen()?;

        let mut incoming = self.runtime.incoming.lock().await;
        let fd = incoming.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "plugin control socket closed")
        })??;

        into_async_stream(fd)
    }

    pub fn fail(&self, message: &str) -> io::Result<()> {
        emit_event(PluginEvent::Failed { message })
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime.runtime_dir
    }

    pub fn socks_dir(&self) -> PathBuf {
        self.runtime.runtime_dir.join("socks")
    }

    pub fn config<T>(&self) -> io::Result<T>
    where
        T: DeserializeOwned,
    {
        let value = self.runtime.startup.config.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "plugin config is missing")
        })?;
        serde_json::from_value(value).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decode plugin config: {err}"),
            )
        })
    }

    pub fn vsock_endpoint(&self) -> &str {
        &self.runtime.startup.vsock_endpoint
    }

    pub fn port(&self) -> u32 {
        self.runtime.startup.port
    }
}

#[derive(Clone)]
pub struct Plugin {
    runtime: &'static PluginRuntime,
    _name: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum PluginEvent<'a> {
    Ready,
    Failed { message: &'a str },
}

fn emit_event(event: PluginEvent<'_>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, &event).map_err(io::Error::other)?;
    lock.write_all(b"\n")?;
    lock.flush()
}

async fn runtime() -> io::Result<&'static PluginRuntime> {
    Ok(RUNTIME.get_or_try_init(init_runtime).await?.as_ref())
}

async fn init_runtime() -> io::Result<Arc<PluginRuntime>> {
    let startup = read_startup_message()?;
    startup.expect_api_v1()?;

    let control = ControlSocket::from_fd(startup.fd)?;
    let runtime_dir = PathBuf::from(&startup.runtime_dir);
    let (incoming_tx, incoming_rx) = mpsc::channel(128);
    let runtime = PluginRuntime {
        startup,
        runtime_dir,
        control,
        pending: Mutex::new(HashMap::new()),
        next_request_id: AtomicU64::new(1),
        incoming: Mutex::new(incoming_rx),
    };
    let runtime = Arc::new(runtime);
    tokio::spawn(run_control_reader(Arc::clone(&runtime), incoming_tx));

    Ok(runtime)
}

struct PluginRuntime {
    startup: StartupMessage,
    runtime_dir: PathBuf,
    control: ControlSocket,
    pending: Mutex<HashMap<u64, oneshot::Sender<io::Result<OwnedFd>>>>,
    next_request_id: AtomicU64,
    incoming: Mutex<mpsc::Receiver<io::Result<OwnedFd>>>,
}

async fn run_control_reader(
    runtime: Arc<PluginRuntime>,
    incoming_tx: mpsc::Sender<io::Result<OwnedFd>>,
) {
    loop {
        let received = match runtime.control.recv_message().await {
            Ok(received) => received,
            Err(err) => {
                fail_all_pending(&runtime.pending, &err).await;
                let _ = incoming_tx.send(Err(clone_io_error(&err))).await;
                return;
            }
        };

        match received.message {
            ControlMessageKind::ConnectOpenOk { request_id } => {
                let Some(fd) = received.fd else {
                    fail_pending(
                        &runtime.pending,
                        request_id,
                        io::Error::new(io::ErrorKind::InvalidData, "connect_open_ok missing fd"),
                    )
                    .await;
                    continue;
                };
                satisfy_pending(&runtime.pending, request_id, Ok(fd)).await;
            }
            ControlMessageKind::ConnectOpenErr {
                request_id,
                message,
                retryable: _,
            } => {
                fail_pending(
                    &runtime.pending,
                    request_id,
                    io::Error::new(io::ErrorKind::ConnectionRefused, message),
                )
                .await;
            }
            ControlMessageKind::ListenIncoming { conn_id: _ } => {
                let Some(fd) = received.fd else {
                    let _ = incoming_tx
                        .send(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "listen_incoming missing fd",
                        )))
                        .await;
                    continue;
                };
                if incoming_tx.send(Ok(fd)).await.is_err() {
                    return;
                }
            }
            ControlMessageKind::ConnectOpen { request_id } => {
                fail_pending(
                    &runtime.pending,
                    request_id,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "plugin received unexpected connect_open request",
                    ),
                )
                .await;
            }
        }
    }
}

async fn satisfy_pending(
    pending: &Mutex<HashMap<u64, oneshot::Sender<io::Result<OwnedFd>>>>,
    request_id: u64,
    result: io::Result<OwnedFd>,
) {
    if let Some(tx) = pending.lock().await.remove(&request_id) {
        let _ = tx.send(result);
    }
}

async fn fail_pending(
    pending: &Mutex<HashMap<u64, oneshot::Sender<io::Result<OwnedFd>>>>,
    request_id: u64,
    err: io::Error,
) {
    satisfy_pending(pending, request_id, Err(err)).await;
}

async fn fail_all_pending(
    pending: &Mutex<HashMap<u64, oneshot::Sender<io::Result<OwnedFd>>>>,
    err: &io::Error,
) {
    let mut guard = pending.lock().await;
    let entries = std::mem::take(&mut *guard);
    drop(guard);

    for (_, tx) in entries {
        let _ = tx.send(Err(clone_io_error(err)));
    }
}

fn read_startup_message() -> io::Result<StartupMessage> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    serde_json::from_str(&line).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

struct ControlSocket {
    inner: AsyncFd<OwnedFd>,
}

struct ReceivedControlMessage {
    message: ControlMessageKind,
    fd: Option<OwnedFd>,
}

impl ControlSocket {
    fn from_fd(fd: RawFd) -> io::Result<Self> {
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(owned.as_raw_fd())?;
        Ok(Self {
            inner: AsyncFd::new(owned)?,
        })
    }

    async fn send_message(
        &self,
        message: &ControlMessageKind,
        fd: Option<&OwnedFd>,
    ) -> io::Result<()> {
        let payload = message.to_bytes()?;
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| send_message(inner.get_ref().as_raw_fd(), &payload, fd)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn recv_message(&self) -> io::Result<ReceivedControlMessage> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recv_message(inner.get_ref().as_raw_fd())) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

#[derive(Debug)]
enum ControlMessageKind {
    ConnectOpen {
        request_id: u64,
    },
    ConnectOpenOk {
        request_id: u64,
    },
    ConnectOpenErr {
        request_id: u64,
        retryable: bool,
        message: String,
    },
    ListenIncoming {
        conn_id: u64,
    },
}

impl ControlMessageKind {
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<ControlMessageFrameV1>());
        match self {
            Self::ConnectOpen { request_id } => {
                bytes.extend_from_slice(&CONTROL_MAGIC.to_ne_bytes());
                bytes.extend_from_slice(&1_u32.to_ne_bytes());
                bytes.extend_from_slice(&request_id.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
            }
            Self::ConnectOpenOk { request_id } => {
                bytes.extend_from_slice(&CONTROL_MAGIC.to_ne_bytes());
                bytes.extend_from_slice(&2_u32.to_ne_bytes());
                bytes.extend_from_slice(&request_id.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
            }
            Self::ConnectOpenErr {
                request_id,
                retryable,
                message,
            } => {
                let message_bytes = message.as_bytes();
                if message_bytes.len() > CONTROL_MESSAGE_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "control message exceeds max size",
                    ));
                }
                bytes.extend_from_slice(&CONTROL_MAGIC.to_ne_bytes());
                bytes.extend_from_slice(&3_u32.to_ne_bytes());
                bytes.extend_from_slice(&request_id.to_ne_bytes());
                bytes.extend_from_slice(&u32::from(*retryable).to_ne_bytes());
                bytes.extend_from_slice(&(message_bytes.len() as u32).to_ne_bytes());
                bytes.extend_from_slice(message_bytes);
            }
            Self::ListenIncoming { conn_id } => {
                bytes.extend_from_slice(&CONTROL_MAGIC.to_ne_bytes());
                bytes.extend_from_slice(&4_u32.to_ne_bytes());
                bytes.extend_from_slice(&conn_id.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
                bytes.extend_from_slice(&0_u32.to_ne_bytes());
            }
        }
        bytes.resize(std::mem::size_of::<ControlMessageFrameV1>(), 0);
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != std::mem::size_of::<ControlMessageFrameV1>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected control message size {}", bytes.len()),
            ));
        }

        let magic = u32::from_ne_bytes(bytes[0..4].try_into().expect("slice is four bytes"));
        if magic != CONTROL_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected control magic {magic:#x}"),
            ));
        }

        let kind = u32::from_ne_bytes(bytes[4..8].try_into().expect("slice is four bytes"));
        let id = u64::from_ne_bytes(bytes[8..16].try_into().expect("slice is eight bytes"));
        let flags = u32::from_ne_bytes(bytes[16..20].try_into().expect("slice is four bytes"));
        let message_len =
            u32::from_ne_bytes(bytes[20..24].try_into().expect("slice is four bytes")) as usize;

        if message_len > CONTROL_MESSAGE_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control message exceeded max size",
            ));
        }

        let message = String::from_utf8(bytes[24..24 + message_len].to_vec()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decode control message: {err}"),
            )
        })?;

        match kind {
            1 => Ok(Self::ConnectOpen { request_id: id }),
            2 => Ok(Self::ConnectOpenOk { request_id: id }),
            3 => Ok(Self::ConnectOpenErr {
                request_id: id,
                retryable: flags != 0,
                message,
            }),
            4 => Ok(Self::ListenIncoming { conn_id: id }),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown control message kind {kind}"),
            )),
        }
    }
}

#[repr(C)]
struct ControlMessageFrameV1 {
    magic: u32,
    kind: u32,
    id: u64,
    flags: u32,
    message_len: u32,
    message: [u8; CONTROL_MESSAGE_MAX_BYTES],
}

fn send_message(control: RawFd, payload: &[u8], fd: Option<&OwnedFd>) -> io::Result<()> {
    let iov = [std::io::IoSlice::new(payload)];
    let sent = match fd {
        Some(fd) => {
            let fds = [fd.as_raw_fd()];
            let cmsg = [ControlMessage::ScmRights(&fds)];
            sendmsg::<()>(control, &iov, &cmsg, MsgFlags::empty(), None)
        }
        None => sendmsg::<()>(control, &iov, &[], MsgFlags::empty(), None),
    }
    .map_err(nix_errno_to_io_error)?;

    if sent != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "short control write: sent {sent} of {} bytes",
                payload.len()
            ),
        ));
    }

    Ok(())
}

fn recv_message(control: RawFd) -> io::Result<ReceivedControlMessage> {
    let mut payload = vec![0_u8; std::mem::size_of::<ControlMessageFrameV1>()];
    let mut cmsg_buf = cmsg_space!([RawFd; 1]);

    let (bytes, received_fd) = {
        let mut iov = [std::io::IoSliceMut::new(&mut payload)];
        let msg = recvmsg::<()>(control, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
            .map_err(nix_errno_to_io_error)?;
        let mut received_fd = None;
        for cmsg in msg.cmsgs().map_err(nix_errno_to_io_error)? {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                received_fd = fds.into_iter().next();
            }
        }
        (msg.bytes, received_fd)
    };

    if bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control socket closed",
        ));
    }

    payload.truncate(bytes);
    let message = ControlMessageKind::from_bytes(&payload)?;
    let fd = received_fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(ReceivedControlMessage { message, fd })
}

fn clone_io_error(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), err.to_string())
}

fn nix_errno_to_io_error(err: Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn into_async_stream(fd: OwnedFd) -> io::Result<AsyncStream> {
    Ok(AsyncStream {
        inner: AsyncFd::new(File::from(fd))?,
    })
}

pub struct AsyncStream {
    inner: AsyncFd<File>,
}

impl AsyncRead for AsyncStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };

            let result = guard.try_io(|inner| {
                let unfilled = buf.initialize_unfilled();
                match inner.get_ref().read(unfilled) {
                    Ok(n) => {
                        buf.advance(n);
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            });

            match result {
                Ok(Ok(())) => return Poll::Ready(Ok(())),
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };

            let result = guard.try_io(|inner| inner.get_ref().write(buf));
            match result {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match shutdown(self.inner.get_ref().as_raw_fd(), Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(Errno::ENOTCONN) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(nix_errno_to_io_error(err))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream as StdUnixStream;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{into_async_stream, ControlMessageKind, CONTROL_MAGIC};

    #[tokio::test]
    async fn async_stream_reads_and_writes() {
        let (left, right) = StdUnixStream::pair().expect("unix stream pair should create");
        left.set_nonblocking(true)
            .expect("left stream should be nonblocking");
        right
            .set_nonblocking(true)
            .expect("right stream should be nonblocking");

        let fd = unsafe { OwnedFd::from_raw_fd(left.into_raw_fd()) };
        let mut stream = into_async_stream(fd).expect("async stream should wrap fd");
        let mut peer = right;

        stream
            .write_all(b"ping")
            .await
            .expect("write should succeed");
        let mut peer_buf = [0_u8; 4];
        peer.read_exact(&mut peer_buf)
            .expect("peer read should succeed");
        assert_eq!(&peer_buf, b"ping");

        peer.write_all(b"pong").expect("peer write should succeed");
        let mut read_buf = [0_u8; 4];
        stream
            .read_exact(&mut read_buf)
            .await
            .expect("read should succeed");
        assert_eq!(&read_buf, b"pong");
    }

    #[tokio::test]
    async fn async_stream_shutdown_closes_write_half() {
        let (left, right) = StdUnixStream::pair().expect("unix stream pair should create");
        left.set_nonblocking(true)
            .expect("left stream should be nonblocking");

        let fd = unsafe { OwnedFd::from_raw_fd(left.into_raw_fd()) };
        let mut stream = into_async_stream(fd).expect("async stream should wrap fd");
        let mut peer = right;

        stream.shutdown().await.expect("shutdown should succeed");

        let mut peer_buf = [0_u8; 1];
        let bytes = peer.read(&mut peer_buf).expect("peer read should succeed");
        assert_eq!(bytes, 0, "peer should observe EOF after shutdown");
    }

    #[test]
    fn control_message_round_trip() {
        let message = ControlMessageKind::ConnectOpenErr {
            request_id: 9,
            retryable: true,
            message: String::from("nope"),
        };
        let bytes = message.to_bytes().expect("encode control message");
        assert_eq!(
            bytes.len(),
            std::mem::size_of::<super::ControlMessageFrameV1>()
        );
        assert_eq!(
            u32::from_ne_bytes(bytes[0..4].try_into().expect("magic bytes")),
            CONTROL_MAGIC
        );
        let decoded = ControlMessageKind::from_bytes(&bytes).expect("decode control message");
        match decoded {
            ControlMessageKind::ConnectOpenErr {
                request_id,
                retryable,
                message,
            } => {
                assert_eq!(request_id, 9);
                assert!(retryable);
                assert_eq!(message, "nope");
            }
            _ => panic!("expected connect_open_err"),
        }
    }
}

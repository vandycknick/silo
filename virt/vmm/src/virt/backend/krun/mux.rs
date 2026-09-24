use std::collections::{HashSet, VecDeque};
use std::io::{self, IoSlice};
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::sys::socket::{
    sendmsg, socketpair, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};

use crate::virt::error::VirtError;
use crate::virt::stream::{KrunVsockSession, KrunVsockStreamGuard};

use crate::virt::backend::krun::{ConnectionRequest, KrunVsockRegistry};

const MAX_LINE_BYTES: usize = 64;
const MAX_FRAMES: usize = 2048;
const MAX_REQUEST_FRAMES: usize = MAX_FRAMES / 2;
const MAX_QUEUED_BYTES: usize = 128 * 1024;
const MAX_QUEUED_FDS: usize = 1024;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct KrunVsockMux {
    commands: mpsc::Sender<Command>,
    session: Arc<KrunVsockSession>,
    request_capacity: Arc<Semaphore>,
    cancellation_notify: Arc<Notify>,
}

pub(super) struct KrunVsockMuxTask(tokio::task::JoinHandle<()>);

enum Command {
    Connect {
        port: u32,
        fd: OwnedFd,
        deadline: Instant,
        sent: oneshot::Sender<io::Result<()>>,
        permit: OwnedSemaphorePermit,
    },
    Shutdown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Priority {
    Request,
    Reply,
}

struct OutboundFrame {
    bytes: Vec<u8>,
    offset: usize,
    fd: Option<OwnedFd>,
    deadline: Instant,
    priority: Priority,
    sent: Option<oneshot::Sender<io::Result<()>>>,
    _permit: Option<OwnedSemaphorePermit>,
}

#[derive(Default)]
struct InboundFrame {
    bytes: Vec<u8>,
    fd: Option<OwnedFd>,
    deadline: Option<Instant>,
}

struct Actor {
    control: AsyncFd<OwnedFd>,
    protected_identities: HashSet<UnixSocketIdentity>,
    commands: mpsc::Receiver<Command>,
    registry: KrunVsockRegistry,
    session: Arc<KrunVsockSession>,
    inbound: InboundFrame,
    current: Option<OutboundFrame>,
    replies: VecDeque<OutboundFrame>,
    requests: VecDeque<OutboundFrame>,
    queued_bytes: usize,
    queued_fds: usize,
    last_guest_id: u32,
    cancellation_notify: Arc<Notify>,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct UnixSocketIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

struct ConnectCancellation {
    notify: Arc<Notify>,
    armed: bool,
}

impl Drop for ConnectCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.notify.notify_one();
        }
    }
}

impl KrunVsockMux {
    pub(super) fn pair(
        registry: KrunVsockRegistry,
        session: Arc<KrunVsockSession>,
        protected_endpoints: &[BorrowedFd<'_>],
    ) -> io::Result<(Self, KrunVsockMuxTask, OwnedFd)> {
        let (parent, child) = new_socketpair()?;
        suppress_sigpipe(parent.as_raw_fd())?;
        let protected_identities = protected_endpoints
            .iter()
            .copied()
            .chain([parent.as_fd(), child.as_fd()])
            .map(unix_socket_identity)
            .collect::<io::Result<HashSet<_>>>()?;
        let control = AsyncFd::new(parent)?;
        let (sender, receiver) = mpsc::channel(MAX_REQUEST_FRAMES);
        let request_capacity = Arc::new(Semaphore::new(MAX_REQUEST_FRAMES));
        let cancellation_notify = Arc::new(Notify::new());
        let actor = Actor {
            control,
            protected_identities,
            commands: receiver,
            registry,
            session: session.clone(),
            inbound: InboundFrame::default(),
            current: None,
            replies: VecDeque::new(),
            requests: VecDeque::new(),
            queued_bytes: 0,
            queued_fds: 0,
            last_guest_id: 0,
            cancellation_notify: cancellation_notify.clone(),
        };
        let task = KrunVsockMuxTask(tokio::spawn(actor.run()));
        Ok((
            Self {
                commands: sender,
                session,
                request_capacity,
                cancellation_notify,
            },
            task,
            child,
        ))
    }

    pub(super) async fn connect(
        &self,
        port: u32,
        deadline: Instant,
    ) -> io::Result<(StdUnixStream, KrunVsockStreamGuard)> {
        if !self.session.is_active() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "krun vsock mux stopped",
            ));
        }
        let permit = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.request_capacity.clone().acquire_owned(),
        )
        .await
        .map_err(|_| timed_out("reserving krun vsock queue capacity"))?
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "krun vsock mux stopped"))?;
        let (host, helper) = new_socketpair()?;
        suppress_sigpipe(host.as_raw_fd())?;
        let (sent, received) = oneshot::channel();
        let mut cancellation = ConnectCancellation {
            notify: self.cancellation_notify.clone(),
            armed: true,
        };
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.commands.send(Command::Connect {
                port,
                fd: helper,
                deadline,
                sent,
                permit,
            }),
        )
        .await
        .map_err(|_| timed_out("queueing krun vsock request"))?
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "krun vsock mux stopped"))?;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received)
            .await
            .map_err(|_| timed_out("sending krun vsock request"))?
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "krun vsock mux stopped"))?;
        cancellation.armed = false;
        result?;
        let stream = StdUnixStream::from(host);
        let guard = self.session.track(stream.as_fd())?;
        Ok((stream, guard))
    }

    pub(super) async fn shutdown(&self) {
        self.session.shutdown();
        // Joining the actor has its own abort deadline, even if its queue is full.
        let _ = self.commands.try_send(Command::Shutdown);
    }

    #[cfg(test)]
    fn available_request_capacity(&self) -> usize {
        self.request_capacity.available_permits()
    }
}

impl KrunVsockMuxTask {
    pub(super) async fn join(mut self) -> Result<(), VirtError> {
        match tokio::time::timeout(Duration::from_secs(1), &mut self.0).await {
            Ok(result) => result.map_err(|error| {
                VirtError::Backend(format!("krun vsock mux task failed: {error}"))
            }),
            Err(_) => {
                self.0.abort();
                let _ = self.0.await;
                Err(VirtError::Backend(
                    "krun vsock mux cleanup timed out".to_string(),
                ))
            }
        }
    }
}

impl Actor {
    async fn run(mut self) {
        let result = self.run_inner().await;
        if let Err(error) = &result {
            tracing::warn!(%error, "krun vsock control channel stopped");
        }
        self.session.shutdown();
        self.registry.fence_session(&self.session);
        self.fail_queued();
    }

    async fn run_inner(&mut self) -> io::Result<()> {
        loop {
            self.discard_cancelled();
            self.expire()?;
            self.select_current();
            let wake = self.next_deadline();
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(Command::Connect { port, fd, deadline, sent, permit }) => {
                        self.enqueue(OutboundFrame {
                            bytes: format!("CONNECT {port}\n").into_bytes(),
                            offset: 0,
                            fd: Some(fd),
                            deadline,
                            priority: Priority::Request,
                            sent: Some(sent),
                            _permit: Some(permit),
                        })?;
                    }
                    Some(Command::Shutdown) | None => return Ok(()),
                },
                ready = self.control.readable() => {
                    let mut ready = ready?;
                    if let Ok(result) = ready.try_io(|inner| recv_one(inner.get_ref().as_raw_fd())) {
                        self.consume(result?)?;
                    }
                }
                ready = self.control.writable(), if self.current.is_some() => {
                    let mut ready = ready?;
                    if let Some(frame) = self.current.as_mut() {
                        let had_fd = frame.fd.is_some();
                        if let Ok(result) = ready.try_io(|inner| send_frame(inner.get_ref().as_raw_fd(), frame)) {
                            result?;
                            if had_fd && frame.fd.is_none() {
                                self.queued_fds -= 1;
                            }
                            if frame.offset == frame.bytes.len() {
                                if let Some(mut frame) = self.current.take() {
                                    self.queued_bytes -= frame.bytes.len();
                                    if let Some(sent) = frame.sent.take() {
                                        let _ = sent.send(Ok(()));
                                    }
                                }
                            }
                        }
                    }
                }
                _ = self.cancellation_notify.notified() => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
            }
        }
    }

    fn consume(&mut self, received: Option<(u8, Vec<OwnedFd>)>) -> io::Result<()> {
        let Some((byte, mut fds)) = received else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "krun vsock control EOF",
            ));
        };
        if self.inbound.bytes.is_empty() {
            self.inbound.deadline = Some(Instant::now() + FRAME_TIMEOUT);
            if fds.len() == 1 {
                self.inbound.fd = fds.pop();
            } else if !fds.is_empty() {
                return Err(protocol("control frame carried extra descriptors"));
            }
        } else if !fds.is_empty() {
            return Err(protocol(
                "descriptor was not attached to the first frame byte",
            ));
        }
        self.inbound.bytes.push(byte);
        if self.inbound.bytes.len() > MAX_LINE_BYTES {
            return Err(protocol("control line exceeded 64 bytes"));
        }
        if byte != b'\n' {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.inbound.bytes);
        let fd = self.inbound.fd.take();
        self.inbound.deadline = None;
        let request = parse_guest_connect(&bytes)?;
        if request.id <= self.last_guest_id {
            return Err(protocol("guest connection id was reused or reordered"));
        }
        self.last_guest_id = request.id;
        let fd = fd.ok_or_else(|| protocol("CONNECT omitted its descriptor"))?;
        validate_stream_fd(&fd)?;
        if self
            .protected_identities
            .contains(&unix_socket_identity(fd.as_fd())?)
        {
            return Err(protocol("CONNECT descriptor aliases a protected endpoint"));
        }
        if !self.can_enqueue(Priority::Reply, MAX_LINE_BYTES, false) {
            return Err(protocol("required reply capacity exhausted"));
        }
        let stream = StdUnixStream::from(fd);
        stream.set_nonblocking(true)?;
        let admitted = self
            .registry
            .connect_guest_stream(request, stream, self.session.clone())
            .is_ok();
        let verb = if admitted { "OK" } else { "REJECT" };
        self.enqueue(OutboundFrame {
            bytes: format!("{verb} {}\n", request.id).into_bytes(),
            offset: 0,
            fd: None,
            deadline: Instant::now() + FRAME_TIMEOUT,
            priority: Priority::Reply,
            sent: None,
            _permit: None,
        })
    }

    fn enqueue(&mut self, frame: OutboundFrame) -> io::Result<()> {
        if !self.can_enqueue(frame.priority, frame.bytes.len(), frame.fd.is_some()) {
            if let Some(sent) = frame.sent {
                let _ = sent.send(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "krun vsock control queue is full",
                )));
            }
            return if frame.priority == Priority::Reply {
                Err(protocol("required reply capacity exhausted"))
            } else {
                Ok(())
            };
        }
        self.queued_bytes += frame.bytes.len();
        self.queued_fds += usize::from(frame.fd.is_some());
        match frame.priority {
            Priority::Request => self.requests.push_back(frame),
            Priority::Reply => self.replies.push_back(frame),
        }
        Ok(())
    }

    fn can_enqueue(&self, priority: Priority, bytes: usize, has_fd: bool) -> bool {
        let frames = self.requests.len() + self.replies.len() + usize::from(self.current.is_some());
        let request_frames = self.requests.len()
            + usize::from(
                self.current
                    .as_ref()
                    .is_some_and(|f| f.priority == Priority::Request),
            );
        frames < MAX_FRAMES
            && (priority == Priority::Reply || request_frames < MAX_REQUEST_FRAMES)
            && self.queued_bytes + bytes <= MAX_QUEUED_BYTES
            && self.queued_fds + usize::from(has_fd) <= MAX_QUEUED_FDS
    }

    fn select_current(&mut self) {
        if self.current.is_none() {
            self.current = self
                .replies
                .pop_front()
                .or_else(|| self.requests.pop_front());
        }
    }

    fn discard_cancelled(&mut self) {
        if self.current.as_ref().is_some_and(|frame| {
            frame.offset == 0 && frame.sent.as_ref().is_some_and(oneshot::Sender::is_closed)
        }) {
            if let Some(frame) = self.current.take() {
                self.remove_accounted_frame(&frame);
            }
        }

        let mut requests = std::mem::take(&mut self.requests);
        while let Some(frame) = requests.pop_front() {
            if frame.sent.as_ref().is_some_and(oneshot::Sender::is_closed) {
                self.remove_accounted_frame(&frame);
            } else {
                self.requests.push_back(frame);
            }
        }
    }

    fn remove_accounted_frame(&mut self, frame: &OutboundFrame) {
        self.queued_bytes -= frame.bytes.len();
        self.queued_fds -= usize::from(frame.fd.is_some());
    }

    fn expire(&self) -> io::Result<()> {
        let now = Instant::now();
        if self
            .inbound
            .deadline
            .is_some_and(|deadline| deadline <= now)
            || self
                .current
                .as_ref()
                .is_some_and(|frame| frame.deadline <= now)
            || self.replies.iter().any(|frame| frame.deadline <= now)
            || self.requests.iter().any(|frame| frame.deadline <= now)
        {
            return Err(timed_out("completing krun vsock control frame"));
        }
        Ok(())
    }

    fn next_deadline(&self) -> Instant {
        self.inbound
            .deadline
            .into_iter()
            .chain(self.current.iter().map(|frame| frame.deadline))
            .chain(self.replies.iter().map(|frame| frame.deadline))
            .chain(self.requests.iter().map(|frame| frame.deadline))
            .min()
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))
    }

    fn fail_queued(&mut self) {
        for frame in self
            .current
            .take()
            .into_iter()
            .chain(self.replies.drain(..))
            .chain(self.requests.drain(..))
        {
            if let Some(sent) = frame.sent {
                let _ = sent.send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "krun vsock mux stopped",
                )));
            }
        }
    }
}

fn recv_one(fd: RawFd) -> io::Result<Option<(u8, Vec<OwnedFd>)>> {
    let mut byte = 0_u8;
    let mut iov = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    let mut ancillary = [0_usize; 16];
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = ancillary.as_mut_ptr().cast();
    header.msg_controllen = mem::size_of_val(&ancillary) as _;

    // nix hides control messages after MSG_CTRUNC, which would leak descriptors
    // already installed by the kernel. Raw recvmsg lets every received fd be owned.
    let received = loop {
        let result = unsafe { libc::recvmsg(fd, &mut header, recv_flags().bits()) };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if received == 0 {
        return Ok(None);
    }

    let truncated = header.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    let mut fds = Vec::new();
    let mut unknown_control = false;
    let mut control = unsafe { libc::CMSG_FIRSTHDR(&header) };
    while !control.is_null() {
        let current = unsafe { &*control };
        if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
            let header_len = unsafe { libc::CMSG_LEN(0) as usize };
            let message_len = current.cmsg_len as usize;
            if message_len < header_len {
                unknown_control = true;
                break;
            }
            let count = (message_len - header_len) / mem::size_of::<RawFd>();
            let data = unsafe { libc::CMSG_DATA(control).cast::<RawFd>() };
            for index in 0..count {
                let raw = unsafe { *data.add(index) };
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                set_cloexec(&owned)?;
                fds.push(owned);
            }
        } else {
            unknown_control = true;
        }
        control = unsafe { libc::CMSG_NXTHDR(&header, control) };
    }
    if unknown_control {
        return Err(protocol("unknown ancillary control message"));
    }
    if truncated {
        return Err(protocol("truncated control message"));
    }
    Ok(Some((byte, fds)))
}

fn send_frame(fd: RawFd, frame: &mut OutboundFrame) -> io::Result<()> {
    let iov = [IoSlice::new(&frame.bytes[frame.offset..])];
    let raw_fd = frame.fd.as_ref().map(AsRawFd::as_raw_fd);
    let rights = raw_fd.map(|raw| [raw]);
    let controls = rights
        .as_ref()
        .map(|raw| vec![ControlMessage::ScmRights(raw)])
        .unwrap_or_default();
    let written = sendmsg::<()>(fd, &iov, &controls, send_flags(), None).map_err(nix_io)?;
    if written == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "zero-length control write",
        ));
    }
    frame.offset += written;
    drop(frame.fd.take());
    Ok(())
}

fn parse_guest_connect(line: &[u8]) -> io::Result<ConnectionRequest> {
    let line = std::str::from_utf8(line).map_err(|_| protocol("control line is not ASCII"))?;
    let fields = line
        .strip_suffix('\n')
        .ok_or_else(|| protocol("control line is not terminated"))?
        .split(' ')
        .collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "CONNECT" {
        return Err(protocol("unexpected control verb"));
    }
    let id = parse_u32(fields[1])?;
    if id == 0 {
        return Err(protocol("connection id must be nonzero"));
    }
    Ok(ConnectionRequest {
        id,
        destination_port: parse_u32(fields[2])?,
        source_port: parse_u32(fields[3])?,
    })
}

fn parse_u32(value: &str) -> io::Result<u32> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(protocol("invalid decimal field"));
    }
    value.parse().map_err(|_| protocol("invalid decimal field"))
}

fn validate_stream_fd(fd: &OwnedFd) -> io::Result<()> {
    if nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::SockType)
        .map_err(io::Error::other)?
        != SockType::Stream
        || nix::sys::socket::getsockname::<nix::sys::socket::UnixAddr>(fd.as_raw_fd()).is_err()
    {
        return Err(protocol(
            "SCM_RIGHTS descriptor is not a Unix stream socket",
        ));
    }
    Ok(())
}

fn unix_socket_identity(fd: BorrowedFd<'_>) -> io::Result<UnixSocketIdentity> {
    let stat = nix::sys::stat::fstat(fd).map_err(io::Error::other)?;
    Ok(UnixSocketIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    let mut flags =
        FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).map_err(io::Error::other)?);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(flags)).map_err(io::Error::other)?;
    Ok(())
}

fn new_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (left, right) = socketpair(AddressFamily::Unix, SockType::Stream, None, socket_flags())?;
    set_nonblocking_cloexec(&left)?;
    set_nonblocking_cloexec(&right)?;
    Ok((left, right))
}

fn set_nonblocking_cloexec(fd: &OwnedFd) -> io::Result<()> {
    set_cloexec(fd)?;
    let mut flags =
        OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::other)?);
    flags.insert(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(io::Error::other)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn socket_flags() -> SockFlag {
    SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn socket_flags() -> SockFlag {
    SockFlag::empty()
}

#[cfg(target_os = "linux")]
fn recv_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn recv_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT
}

#[cfg(target_os = "linux")]
fn send_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
}

#[cfg(not(target_os = "linux"))]
fn send_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT
}

#[cfg(target_os = "macos")]
fn suppress_sigpipe(fd: RawFd) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // nix does not expose SO_NOSIGPIPE; Darwin requires it instead of MSG_NOSIGNAL.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn suppress_sigpipe(_: RawFd) -> io::Result<()> {
    Ok(())
}

fn protocol(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn timed_out(operation: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("timed out {operation}"))
}

fn nix_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::Duration;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};

    use crate::virt::backend::krun::mux::{parse_guest_connect, recv_one, KrunVsockMux};
    use crate::virt::backend::krun::KrunVsockRegistry;
    use crate::virt::capacity::{ListenerAdmissionClass, VsockCapacity};
    use crate::virt::stream::KrunVsockSession;

    #[test]
    fn parser_enforces_canonical_guest_connect() {
        let request = parse_guest_connect(b"CONNECT 1 7000 4000\n").expect("valid connect");
        assert_eq!(request.id, 1);
        assert_eq!(request.destination_port, 7000);
        assert_eq!(request.source_port, 4000);
        for malformed in [
            &b"CONNECT 01 7000 4000\n"[..],
            &b"CONNECT 0 7000 4000\n"[..],
            &b"CONNECT 1 7000\n"[..],
            &b"OK 1\n"[..],
        ] {
            assert!(parse_guest_connect(malformed).is_err());
        }
    }

    #[test]
    fn recvmsg_ties_rights_to_the_first_byte() {
        let (control, peer) = std::os::unix::net::UnixStream::pair().expect("control pair");
        control.set_nonblocking(true).expect("nonblocking control");
        let (data, _data_peer) = std::os::unix::net::UnixStream::pair().expect("data pair");
        let byte = [std::io::IoSlice::new(b"C")];
        sendmsg::<()>(
            peer.as_raw_fd(),
            &byte,
            &[ControlMessage::ScmRights(&[data.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .expect("send rights");

        let (received, fds) = recv_one(control.as_raw_fd())
            .expect("recvmsg")
            .expect("one byte");
        assert_eq!(received, b'C');
        assert_eq!(fds.len(), 1);
    }

    #[tokio::test]
    async fn guest_connect_rejects_control_socket_alias_without_leaking_capacity() {
        let registry = KrunVsockRegistry::default();
        let session = KrunVsockSession::new();
        let capacity = VsockCapacity::test_with_limit("mux-protected-control", 1);
        let mut listener = registry
            .register(
                7000,
                capacity.listener(ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let (mux, task, control) =
            KrunVsockMux::pair(registry, session.clone(), &[]).expect("mux pair");
        let mut control = std::os::unix::net::UnixStream::from(control);
        let alias = control.try_clone().expect("duplicate control endpoint");
        sendmsg::<()>(
            control.as_raw_fd(),
            &[std::io::IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[alias.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .expect("send control alias");
        control
            .write_all(b"ONNECT 1 7000 4000\n")
            .expect("complete connect frame");

        tokio::time::timeout(Duration::from_secs(1), task.join())
            .await
            .expect("protected alias should stop actor")
            .expect("join mux");
        assert!(!session.is_active());
        assert_eq!(capacity.available_permits(), 1);
        assert_eq!(
            mux.available_request_capacity(),
            crate::virt::backend::krun::mux::MAX_REQUEST_FRAMES
        );
        assert!(listener.try_accept().is_err());
        assert_eq!(
            nix::sys::socket::getsockopt(&control, nix::sys::socket::sockopt::SockType)
                .expect("original control owner remains open"),
            nix::sys::socket::SockType::Stream
        );
        assert_eq!(
            nix::sys::socket::getsockopt(&alias, nix::sys::socket::sockopt::SockType)
                .expect("control alias owner remains open"),
            nix::sys::socket::SockType::Stream
        );
    }

    #[tokio::test]
    async fn guest_connect_rejects_registered_socket_alias_without_closing_owner() {
        let registry = KrunVsockRegistry::default();
        let session = KrunVsockSession::new();
        let capacity = VsockCapacity::test_with_limit("mux-protected-stdio", 1);
        let mut listener = registry
            .register(
                7000,
                capacity.listener(ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let (mut stdio, mut stdio_peer) =
            std::os::unix::net::UnixStream::pair().expect("socket-backed stdio pair");
        let (mux, task, control) =
            KrunVsockMux::pair(registry, session.clone(), &[stdio.as_fd()]).expect("mux pair");
        let mut control = std::os::unix::net::UnixStream::from(control);
        let alias = stdio.try_clone().expect("duplicate registered endpoint");
        sendmsg::<()>(
            control.as_raw_fd(),
            &[std::io::IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[alias.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .expect("send registered endpoint alias");
        control
            .write_all(b"ONNECT 1 7000 4000\n")
            .expect("complete connect frame");

        tokio::time::timeout(Duration::from_secs(1), task.join())
            .await
            .expect("protected alias should stop actor")
            .expect("join mux");
        assert!(!session.is_active());
        assert_eq!(capacity.available_permits(), 1);
        assert_eq!(
            mux.available_request_capacity(),
            crate::virt::backend::krun::mux::MAX_REQUEST_FRAMES
        );
        assert!(listener.try_accept().is_err());
        stdio
            .write_all(b"x")
            .expect("registered endpoint owner remains open");
        let mut byte = [0_u8; 1];
        stdio_peer
            .read_exact(&mut byte)
            .expect("registered endpoint remains connected");
        assert_eq!(byte, *b"x");
    }

    #[tokio::test]
    async fn guest_connect_routes_real_passed_stream_and_replies() {
        let registry = KrunVsockRegistry::default();
        let session = KrunVsockSession::new();
        let capacity = VsockCapacity::test_with_limit("mux-route", 1);
        let mut listener = registry
            .register(
                7000,
                capacity.listener(ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let (mux, task, control) =
            KrunVsockMux::pair(registry, session.clone(), &[]).expect("mux pair");
        let mut control = std::os::unix::net::UnixStream::from(control);
        control
            .set_nonblocking(false)
            .expect("blocking test control");
        let (passed, mut data_peer) =
            std::os::unix::net::UnixStream::pair().expect("connection pair");
        sendmsg::<()>(
            control.as_raw_fd(),
            &[std::io::IoSlice::new(b"C")],
            &[ControlMessage::ScmRights(&[passed.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .expect("send first byte and rights");
        control
            .write_all(b"ONNECT 7 7000 4000\n")
            .expect("send fragmented line");
        data_peer
            .write_all(b"ping")
            .expect("pipeline data through passed fd");

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "guest connect was not routed, active={}",
                    session.is_active()
                )
            })
            .expect("accept routed stream");
        assert_eq!(accepted.source_port(), Some(4000));
        let (reply, control) = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || {
                let mut reply = [0_u8; 5];
                control
                    .read_exact(&mut reply)
                    .expect("read admission reply");
                (reply, control)
            }),
        )
        .await
        .expect("admission reply deadline")
        .expect("join reply reader");
        assert_eq!(&reply, b"OK 7\n");
        assert!(session.is_active(), "session fenced after admission reply");
        drop(passed);
        let mut payload = [0_u8; 4];
        let read_result = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read_exact(&mut accepted, &mut payload),
        )
        .await;
        if let Err(error) = read_result {
            panic!(
                "passed stream deadline: {error}, active={}",
                session.is_active()
            );
        }
        if let Err(error) = read_result.expect("checked timeout") {
            panic!(
                "read passed stream: {error}, active={}",
                session.is_active()
            );
        }
        assert_eq!(&payload, b"ping");
        tokio::io::AsyncWriteExt::write_all(&mut accepted, b"pong")
            .await
            .expect("write response through passed fd");
        let mut response = [0_u8; 4];
        data_peer
            .read_exact(&mut response)
            .expect("read response through passed fd");
        assert_eq!(&response, b"pong");

        tokio::time::timeout(Duration::from_secs(1), mux.shutdown())
            .await
            .expect("mux shutdown deadline");
        tokio::time::timeout(Duration::from_secs(1), task.join())
            .await
            .expect("mux join deadline")
            .expect("join mux");
        drop(control);
    }

    #[tokio::test]
    async fn control_only_eof_fences_session_and_closes_established_streams() {
        let session = KrunVsockSession::new();
        let registry = KrunVsockRegistry::default();
        let capacity = VsockCapacity::test_with_limit("control-eof", 1);
        let mut listener = registry
            .register(
                7000,
                capacity.listener(ListenerAdmissionClass::Internal),
                session.clone(),
            )
            .expect("register listener");
        let (pending, _pending_peer) =
            std::os::unix::net::UnixStream::pair().expect("pending pair");
        registry
            .connect_guest_stream(
                crate::virt::backend::krun::ConnectionRequest {
                    id: 1,
                    source_port: 4000,
                    destination_port: 7000,
                },
                pending,
                session.clone(),
            )
            .expect("queue pending stream");
        assert_eq!(capacity.available_permits(), 0);
        let (mux, task, control) =
            KrunVsockMux::pair(registry, session.clone(), &[]).expect("mux pair");
        let (tracked, mut peer) = std::os::unix::net::UnixStream::pair().expect("stream pair");
        let _guard = session
            .track(tracked.as_fd())
            .expect("track established stream");
        drop(control);

        tokio::time::timeout(Duration::from_secs(1), task.join())
            .await
            .expect("control EOF should stop actor")
            .expect("join mux");
        assert!(!session.is_active());
        assert_eq!(capacity.available_permits(), 1);
        assert!(listener.try_accept().is_err());
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("tracked stream EOF"), 0);
        drop(mux);
    }

    #[tokio::test]
    async fn host_connect_passes_one_shot_fd_and_preserves_data_order() {
        let session = KrunVsockSession::new();
        let (mux, task, control) =
            KrunVsockMux::pair(KrunVsockRegistry::default(), session, &[]).expect("mux pair");
        let helper = tokio::task::spawn_blocking(move || {
            let mut line = Vec::new();
            let mut data_fd = None;
            while !line.ends_with(b"\n") {
                match recv_one(control.as_raw_fd()) {
                    Ok(Some((byte, mut fds))) => {
                        line.push(byte);
                        if data_fd.is_none() {
                            data_fd = fds.pop();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    result => panic!("unexpected control receive: {result:?}"),
                }
            }
            assert_eq!(line, b"CONNECT 7000\n");
            let mut data = std::os::unix::net::UnixStream::from(data_fd.expect("passed fd"));
            data.set_nonblocking(false).expect("blocking data endpoint");
            data.write_all(b"OK 1073741824\npayload")
                .expect("ordered response and payload");
        });

        let (mut stream, _guard) = mux
            .connect(7000, std::time::Instant::now() + Duration::from_secs(1))
            .await
            .expect("connect request");
        stream.set_nonblocking(false).expect("blocking test stream");
        let response = tokio::task::spawn_blocking(move || {
            let mut bytes = [0_u8; 21];
            stream.read_exact(&mut bytes).expect("read ordered bytes");
            bytes
        })
        .await
        .expect("join data reader");
        assert_eq!(&response, b"OK 1073741824\npayload");
        helper.await.expect("join helper");
        mux.shutdown().await;
        task.join().await.expect("join mux");
    }

    #[tokio::test]
    async fn cancelled_connects_release_stalled_queue_descriptors_and_capacity() {
        let session = KrunVsockSession::new();
        let (mux, task, control) = KrunVsockMux::pair(KrunVsockRegistry::default(), session, &[])
            .expect("create stalled mux");
        nix::sys::socket::setsockopt(&control, nix::sys::socket::sockopt::RcvBuf, &1024)
            .expect("limit peer receive buffer");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let connects = (0..crate::virt::backend::krun::mux::MAX_REQUEST_FRAMES)
            .map(|port| {
                let mux = mux.clone();
                tokio::spawn(async move { mux.connect(port as u32 + 1, deadline).await })
            })
            .collect::<Vec<_>>();

        tokio::time::timeout(Duration::from_secs(1), async {
            while mux.available_request_capacity()
                == crate::virt::backend::krun::mux::MAX_REQUEST_FRAMES
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stalled peer should retain queued descriptors");
        for connect in &connects {
            connect.abort();
        }
        for connect in connects {
            let _ = connect.await;
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while mux.available_request_capacity()
                != crate::virt::backend::krun::mux::MAX_REQUEST_FRAMES
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled queue should release descriptors and capacity");

        mux.shutdown().await;
        drop(control);
        task.join().await.expect("join stalled mux");
    }

    #[test]
    fn sessions_are_never_reactivated_across_restarts() {
        let old = KrunVsockSession::new();
        old.shutdown();
        let replacement = KrunVsockSession::new();

        assert!(!old.is_active());
        assert!(replacement.is_active());
        assert!(!std::sync::Arc::ptr_eq(&old, &replacement));
    }
}

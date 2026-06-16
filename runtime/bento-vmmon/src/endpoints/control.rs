use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, MsgFlags};
use tokio::io::unix::AsyncFd;

const CONTROL_MAGIC: u32 = 0x4252_4b52;
const CONTROL_MESSAGE_MAX_BYTES: usize = 256;

pub(super) enum ControlMessageKind {
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

pub(super) struct BrokerControlSocket {
    inner: AsyncFd<OwnedFd>,
}

impl BrokerControlSocket {
    pub(super) fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    pub(super) async fn recv_message(&self) -> io::Result<ControlMessageKind> {
        let payload = loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| recv_broker_frame(inner.get_ref().as_raw_fd())) {
                Ok(result) => break result?,
                Err(_would_block) => continue,
            }
        };

        ControlMessageKind::from_bytes(&payload)
    }

    pub(super) async fn send_message(
        &self,
        message: &ControlMessageKind,
        fd: Option<&OwnedFd>,
    ) -> io::Result<()> {
        let payload = message.to_bytes()?;

        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| send_broker_frame(inner.get_ref().as_raw_fd(), &payload, fd))
            {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

pub(super) fn send_control_message(
    control: &OwnedFd,
    message: &ControlMessageKind,
    fd: Option<&OwnedFd>,
) -> io::Result<()> {
    let payload = message.to_bytes()?;
    send_broker_frame(control.as_raw_fd(), &payload, fd)
}

pub(super) fn control_message_name(message: &ControlMessageKind) -> &'static str {
    match message {
        ControlMessageKind::ConnectOpen { .. } => "connect_open",
        ControlMessageKind::ConnectOpenOk { .. } => "connect_open_ok",
        ControlMessageKind::ConnectOpenErr { .. } => "connect_open_err",
        ControlMessageKind::ListenIncoming { .. } => "listen_incoming",
    }
}

fn send_broker_frame(control: RawFd, payload: &[u8], fd: Option<&OwnedFd>) -> io::Result<()> {
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
            format!("short broker write: sent {sent} of {} bytes", payload.len()),
        ));
    }

    Ok(())
}

fn recv_broker_frame(control: RawFd) -> io::Result<Vec<u8>> {
    let mut payload = vec![0_u8; std::mem::size_of::<ControlMessageFrameV1>()];
    let bytes = {
        let mut iov = [std::io::IoSliceMut::new(&mut payload)];
        recvmsg::<()>(control, &mut iov, None, MsgFlags::empty())
            .map_err(nix_errno_to_io_error)?
            .bytes
    };
    if bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "broker socket closed",
        ));
    }

    payload.truncate(bytes);
    Ok(payload)
}

impl ControlMessageKind {
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
                        "control error message exceeds max size",
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

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(nix_errno_to_io_error)?;
    let mut flags = OFlag::from_bits_retain(flags);
    flags.insert(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(nix_errno_to_io_error)?;
    Ok(())
}

fn nix_errno_to_io_error(err: Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

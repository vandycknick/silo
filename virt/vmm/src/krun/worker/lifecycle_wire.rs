//! Framing for the private monitor↔worker lifecycle socket.
//!
//! One connected `AF_UNIX` stream pair per worker generation. Every frame is a
//! four-byte big-endian length followed by 1..=16 KiB of JSON encoding one
//! closed, tagged enum. This protocol carries no descriptors: any ancillary
//! data, including rights attached to later frame bytes or a truncated control
//! buffer, is a protocol failure after every received descriptor is closed.

use std::io;
use std::mem;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::krun::worker::wire::invalid;
use crate::virt::lifecycle::{
    CommandReport, CommandSequence, ControlObservation, InventoryObservation, LifecycleCommand,
    LifecycleRejection,
};

pub(crate) const PROTOCOL_VERSION: u32 = 1;
pub(crate) const MAX_FRAME: usize = 16 * 1024;

/// Monitor-side backend to worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ParentFrame {
    Command {
        sequence: CommandSequence,
        request_id: Uuid,
        command: LifecycleCommand,
    },
}

/// Worker to monitor-side backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerFrame {
    /// First frame: binds the protocol and the exact launch identity.
    Hello {
        version: u32,
        machine_id: Uuid,
        run_id: Uuid,
    },
    /// Admission (`Accepted`) and later the terminal result of a mutator.
    Report {
        report: CommandReport,
        control: ControlObservation,
    },
    /// Definitive refusal of one command before any native effect.
    Rejected {
        sequence: CommandSequence,
        rejection: LifecycleRejection,
        control: ControlObservation,
    },
    /// Answer to `GetControl`.
    Control {
        sequence: CommandSequence,
        target: Option<CommandReport>,
        control: ControlObservation,
        inventory: InventoryObservation,
    },
}

pub(crate) fn encode<T: Serialize>(frame: &T) -> io::Result<Vec<u8>> {
    crate::krun::worker::wire::encode(frame, MAX_FRAME)
}

/// Incremental frame assembly over arbitrary read boundaries.
#[derive(Default)]
pub(crate) struct FrameBuffer {
    bytes: Vec<u8>,
}

impl FrameBuffer {
    /// Whether an unfinished frame is buffered (bounded by a frame timeout).
    pub(crate) fn partial(&self) -> bool {
        !self.bytes.is_empty()
    }

    pub(crate) fn extend(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.bytes.len() + bytes.len() > 4 + MAX_FRAME + 4 + MAX_FRAME {
            return Err(invalid("lifecycle input exceeds the frame bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Remove and decode the next complete frame, if any.
    pub(crate) fn next<T: serde::de::DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        let Some(header) = self.bytes.get(..4) else {
            return Ok(None);
        };
        let mut length = [0; 4];
        length.copy_from_slice(header);
        let length = crate::krun::worker::wire::frame_length(length, MAX_FRAME)?;
        if self.bytes.len() < 4 + length {
            return Ok(None);
        }
        let frame = crate::krun::worker::wire::decode(&self.bytes[4..4 + length])?;
        self.bytes.drain(..4 + length);
        Ok(Some(frame))
    }
}

/// One `recvmsg` that never lets a descriptor survive. `Ok(0)` is EOF.
///
/// nix hides control messages after `MSG_CTRUNC`, which would leak descriptors
/// the kernel already installed, so raw `recvmsg` owns every received FD.
pub(crate) fn recv_without_rights(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let mut iov = nix::libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut ancillary = [0_usize; 16];
    // SAFETY: msghdr is plain data; every pointer below references live locals.
    let mut header: nix::libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = ancillary.as_mut_ptr().cast();
    header.msg_controllen = mem::size_of_val(&ancillary) as _;
    let received = loop {
        // SAFETY: header describes writable buffers owned by this frame.
        let result = unsafe { nix::libc::recvmsg(fd.as_raw_fd(), &mut header, recv_flags()) };
        if result >= 0 {
            break result as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let mut received_fds = Vec::new();
    let mut unknown = false;
    // SAFETY: the control buffer was filled by the kernel for this header.
    let mut control = unsafe { nix::libc::CMSG_FIRSTHDR(&header) };
    while !control.is_null() {
        // SAFETY: CMSG_FIRSTHDR/NXTHDR only return headers inside the buffer.
        let current = unsafe { &*control };
        if current.cmsg_level == nix::libc::SOL_SOCKET && current.cmsg_type == nix::libc::SCM_RIGHTS
        {
            // SAFETY: CMSG_LEN is a pure size computation.
            let header_len = unsafe { nix::libc::CMSG_LEN(0) } as usize;
            let message_len = current.cmsg_len as usize;
            if message_len < header_len {
                unknown = true;
                break;
            }
            let count = (message_len - header_len) / mem::size_of::<RawFd>();
            // SAFETY: the rights payload holds `count` installed descriptors.
            let data = unsafe { nix::libc::CMSG_DATA(control).cast::<RawFd>() };
            for index in 0..count {
                // SAFETY: each installed descriptor is owned exactly once here.
                let raw = unsafe { data.add(index).read_unaligned() };
                received_fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        } else {
            unknown = true;
        }
        // SAFETY: advancing within the same kernel-filled control buffer.
        control = unsafe { nix::libc::CMSG_NXTHDR(&header, control) };
    }
    let truncated = header.msg_flags & (nix::libc::MSG_CTRUNC | nix::libc::MSG_TRUNC) != 0;
    if !received_fds.is_empty() || unknown || truncated {
        drop(received_fds);
        return Err(invalid("lifecycle frame carried ancillary data"));
    }
    Ok(received)
}

#[cfg(target_os = "linux")]
fn recv_flags() -> nix::libc::c_int {
    nix::libc::MSG_CMSG_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn recv_flags() -> nix::libc::c_int {
    0
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use uuid::Uuid;

    use crate::krun::worker::lifecycle_wire::*;
    use crate::virt::lifecycle::{CommandSequence, LifecycleCommand, PausePurpose};

    fn command() -> ParentFrame {
        let operation = Uuid::new_v4();
        ParentFrame::Command {
            sequence: CommandSequence::new(1).expect("nonzero"),
            request_id: operation,
            command: LifecycleCommand::Pause {
                operation,
                purpose: PausePurpose::Initial,
                timeout: Duration::from_secs(5),
                clock_profile: None,
            },
        }
    }

    #[test]
    fn frames_reassemble_across_every_split_point() {
        let first = command();
        let second = command();
        let mut wire = encode(&first).expect("encode");
        wire.extend(encode(&second).expect("encode"));
        for split in 0..=wire.len() {
            let mut buffer = FrameBuffer::default();
            buffer.extend(&wire[..split]).expect("extend");
            let mut frames = Vec::new();
            while let Some(frame) = buffer.next::<ParentFrame>().expect("decode") {
                frames.push(frame);
            }
            buffer.extend(&wire[split..]).expect("extend");
            while let Some(frame) = buffer.next::<ParentFrame>().expect("decode") {
                frames.push(frame);
            }
            assert_eq!(frames, vec![first.clone(), second.clone()]);
            assert!(!buffer.partial());
        }
    }

    #[test]
    fn oversize_empty_unknown_and_trailing_fields_are_refused() {
        let mut buffer = FrameBuffer::default();
        buffer
            .extend(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .expect("header");
        assert!(buffer.next::<ParentFrame>().is_err());
        let mut buffer = FrameBuffer::default();
        buffer.extend(&0_u32.to_be_bytes()).expect("header");
        assert!(buffer.next::<ParentFrame>().is_err());
        for payload in [
            br#"{"frame":"shutdown"}"#.as_slice(),
            br#"{"frame":"command","sequence":1,"request_id":"6f1c2a43-55c6-4a07-8a49-4a1d3d4fd1f1","command":{"command":"get_control","target":null},"extra":1}"#,
            br#"{"frame":"command","sequence":0,"request_id":"6f1c2a43-55c6-4a07-8a49-4a1d3d4fd1f1","command":{"command":"get_control","target":null}}"#,
        ] {
            let mut buffer = FrameBuffer::default();
            buffer
                .extend(&(payload.len() as u32).to_be_bytes())
                .expect("header");
            buffer.extend(payload).expect("payload");
            assert!(buffer.next::<ParentFrame>().is_err(), "{payload:?}");
        }
        let large = WorkerFrame::Rejected {
            sequence: CommandSequence::new(1).expect("nonzero"),
            rejection: crate::virt::lifecycle::LifecycleRejection::Busy,
            control: crate::virt::lifecycle::ControlObservation::Unavailable {
                failure: crate::virt::lifecycle::NativeFailure {
                    kind: crate::virt::lifecycle::NativeFailureKind::Participant,
                    detail: Some("x".repeat(MAX_FRAME)),
                },
            },
        };
        assert!(
            encode(&large).is_err(),
            "encoder must enforce the frame bound"
        );
    }

    #[test]
    fn rights_on_any_frame_byte_are_closed_and_refused() {
        for attach_at in [0_usize, 3, 17] {
            let (sender, receiver) = UnixStream::pair().expect("pair");
            let frame = encode(&command()).expect("encode");
            let (prefix, suffix) = frame.split_at(attach_at);
            if !prefix.is_empty() {
                (&sender).write_all(prefix).expect("prefix");
            }
            // The pipe's read end is the passenger: once every copy is closed,
            // writes fail with EPIPE. A leaked received copy keeps it open.
            let (passenger, witness) = nix::unistd::pipe().expect("pipe");
            sendmsg::<()>(
                sender.as_raw_fd(),
                &[std::io::IoSlice::new(suffix)],
                &[ControlMessage::ScmRights(&[passenger.as_raw_fd()])],
                MsgFlags::empty(),
                None,
            )
            .expect("send rights");
            drop(passenger);
            let mut buffer = FrameBuffer::default();
            let mut chunk = [0_u8; 64];
            let refused = loop {
                match recv_without_rights(receiver.as_fd(), &mut chunk) {
                    Ok(0) => break false,
                    Ok(count) => buffer.extend(&chunk[..count]).expect("extend"),
                    Err(error) => {
                        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                        break true;
                    }
                }
            };
            assert!(refused, "rights at byte {attach_at} must be refused");
            assert_eq!(
                nix::unistd::write(&witness, b"x"),
                Err(nix::errno::Errno::EPIPE),
                "received descriptor at byte {attach_at} must be closed, not leaked"
            );
        }
    }

    #[test]
    fn plain_bytes_and_eof_pass_through() {
        let (sender, receiver) = UnixStream::pair().expect("pair");
        let expected = command();
        (&sender)
            .write_all(&encode(&expected).expect("encode"))
            .expect("write");
        drop(sender);
        let mut buffer = FrameBuffer::default();
        let mut chunk = [0_u8; 7];
        loop {
            let count = recv_without_rights(receiver.as_fd(), &mut chunk).expect("recv");
            if count == 0 {
                break;
            }
            buffer.extend(&chunk[..count]).expect("extend");
        }
        assert_eq!(
            buffer.next::<ParentFrame>().expect("decode"),
            Some(expected)
        );
    }
}

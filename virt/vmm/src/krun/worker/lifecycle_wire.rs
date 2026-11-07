//! Framing for the private monitor↔worker lifecycle socket.
//!
//! One connected `AF_UNIX` stream pair per worker generation. Every frame is a
//! four-byte big-endian length followed by 1..=16 KiB of JSON encoding one
//! closed, tagged enum.
//!
//! Descriptors travel only monitor→worker, only with the closed commands that
//! carry a fixed typed set ([`RightsKind`]), and only attached to the first
//! byte of their frame:
//!
//! ```text
//!   sendmsg([len0] + SCM_RIGHTS)   write([len1 len2 len3] payload…)
//!   recvmsg(1 byte, rights ≤ 5)    exact-length reads, any rights = failure
//! ```
//!
//! The worker reads one frame at a time and never past its end, so rights
//! cannot be confused between coalesced frames. Rights on any later byte, a
//! count other than the command's, unknown control data or truncation is a
//! protocol failure after every installed descriptor is closed. Worker→monitor
//! frames carry no descriptors at all.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::krun::worker::wire::invalid;
use crate::virt::lifecycle::{
    CaptureObservation, CommandReport, CommandSequence, ControlObservation, InventoryObservation,
    LifecycleCommand, LifecycleRejection, LifecycleRights,
};

pub(crate) const PROTOCOL_VERSION: u32 = 2;
/// Includes the bounded 1 TiB affected bitmap and exact native producer binding.
pub(crate) const MAX_FRAME: usize = vm_spec::capture::MAX_CAPTURE_RECORD_BYTES;
/// The largest typed descriptor set of any command.
pub(crate) const MAX_RIGHTS: usize = 5;

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
    /// Answer to `GetCapture`.
    Capture {
        sequence: CommandSequence,
        capture: CaptureObservation,
        control: ControlObservation,
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
pub(crate) fn recv_without_rights(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    recv_rights(fd, buffer, 0).map(|(count, _)| count)
}

/// One `recvmsg` owning every installed descriptor. More than `max` rights,
/// any other control message or truncation is refused after closing them all.
///
/// nix hides control messages after `MSG_CTRUNC`, which would leak descriptors
/// the kernel already installed, so raw `recvmsg` owns every received FD.
fn recv_rights(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    max: usize,
) -> io::Result<(usize, Vec<OwnedFd>)> {
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
    if received_fds.len() > max || unknown || truncated {
        drop(received_fds);
        return Err(invalid("lifecycle frame carried unexpected ancillary data"));
    }
    for received in &received_fds {
        set_cloexec(received)?;
    }
    Ok((received, received_fds))
}

/// Linux installs received rights CLOEXEC atomically (`MSG_CMSG_CLOEXEC`).
#[cfg(target_os = "linux")]
fn set_cloexec(_fd: &OwnedFd) -> io::Result<()> {
    Ok(())
}

/// Other hosts lack `MSG_CMSG_CLOEXEC`: set it before any use.
#[cfg(not(target_os = "linux"))]
fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

/// Read one monitor frame, never beyond its last byte. `Ok(None)` is a clean
/// EOF between frames. Rights are accepted only with the first byte and only
/// in the exact count the decoded command requires.
pub(crate) fn read_parent_frame(
    fd: BorrowedFd<'_>,
    frame_timeout: Duration,
) -> io::Result<Option<(ParentFrame, LifecycleRights)>> {
    let mut first = [0_u8; 1];
    let (count, descriptors) = recv_rights(fd, &mut first, MAX_RIGHTS)?;
    if count == 0 {
        if !descriptors.is_empty() {
            return Err(invalid("lifecycle rights without frame bytes"));
        }
        return Ok(None);
    }
    let deadline = Instant::now() + frame_timeout;
    let mut header = [first[0], 0, 0, 0];
    read_exact(fd, &mut header[1..], deadline)?;
    let length = crate::krun::worker::wire::frame_length(header, MAX_FRAME)?;
    let mut payload = vec![0_u8; length];
    read_exact(fd, &mut payload, deadline)?;
    let frame: ParentFrame = crate::krun::worker::wire::decode(&payload)?;
    let ParentFrame::Command { command, .. } = &frame;
    let rights = LifecycleRights::from_descriptors(command.rights(), descriptors)
        .ok_or_else(|| invalid("lifecycle rights do not match the command"))?;
    Ok(Some((frame, rights)))
}

/// Fill `buffer` exactly with rights-refusing reads before `deadline`.
fn read_exact(fd: BorrowedFd<'_>, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    let mut filled = 0;
    while filled < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(invalid("unfinished lifecycle frame timed out"));
        }
        let mut ready = [PollFd::new(fd, PollFlags::POLLIN)];
        match poll(
            &mut ready,
            PollTimeout::try_from(remaining).map_err(io::Error::other)?,
        ) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        let count = recv_without_rights(fd, &mut buffer[filled..])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "lifecycle endpoint closed inside a frame",
            ));
        }
        filled += count;
    }
    Ok(())
}

/// Send a frame's first byte with its descriptors. `Ok(0)` never happens for
/// a stream socket; `WouldBlock` leaves the rights unsent.
pub(crate) fn send_first_with_rights(
    fd: BorrowedFd<'_>,
    first: u8,
    descriptors: &[OwnedFd],
) -> io::Result<usize> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    let raw: Vec<RawFd> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = MsgFlags::empty();
    loop {
        match sendmsg::<()>(
            fd.as_raw_fd(),
            &[io::IoSlice::new(&[first])],
            &[ControlMessage::ScmRights(&raw)],
            flags,
            None,
        ) {
            Ok(sent) => return Ok(sent),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
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
    use crate::virt::lifecycle::{
        CommandSequence, LifecycleCommand, LifecycleRights, PausePurpose,
    };

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

    fn digest(byte: u8) -> crate::virt::lifecycle::Digest32 {
        crate::virt::lifecycle::Digest32([byte; 32])
    }

    fn prepare(sequence: u64) -> ParentFrame {
        use crate::virt::lifecycle::*;
        let operation = Uuid::new_v4();
        let identity = |inode| OutputIdentity { device: 1, inode };
        ParentFrame::Command {
            sequence: CommandSequence::new(sequence).expect("nonzero"),
            request_id: operation,
            command: LifecycleCommand::PrepareCapture {
                operation,
                preparation: CapturePreparation {
                    outputs: CaptureOutputIdentities {
                        execution: identity(1),
                        devices: identity(2),
                        ram: identity(3),
                        layout: identity(4),
                    },
                    pin: identity(5),
                    pause: CapturePauseSource::Acquire,
                    resume_policy: CaptureResumePolicy::ResumeIfAcquired,
                    binding: CaptureDigests {
                        silo_producer: digest(1),
                        profile: digest(2),
                        topology: digest(3),
                    },
                    policy: vm_spec::lifecycle::CapturePolicy::Full,
                    dirty_crossover_percent: 60,
                    baseline: None,
                },
                timeout: Duration::from_secs(5),
            },
        }
    }

    fn observe(sequence: u64) -> ParentFrame {
        ParentFrame::Command {
            sequence: CommandSequence::new(sequence).expect("nonzero"),
            request_id: Uuid::new_v4(),
            command: LifecycleCommand::GetControl { target: None },
        }
    }

    /// Pipe read ends as passengers: once every copy closes, writes to the
    /// witness fail with EPIPE, so a leaked received copy is observable.
    fn passengers(count: usize) -> (Vec<std::os::fd::OwnedFd>, Vec<std::os::fd::OwnedFd>) {
        (0..count)
            .map(|_| nix::unistd::pipe().expect("pipe"))
            .unzip()
    }

    fn all_closed(witnesses: &[std::os::fd::OwnedFd]) -> bool {
        witnesses
            .iter()
            .all(|witness| nix::unistd::write(witness, b"x") == Err(nix::errno::Errno::EPIPE))
    }

    #[test]
    fn rights_ride_only_the_first_byte_of_their_own_frame() {
        let (sender, receiver) = UnixStream::pair().expect("pair");
        let first = prepare(1);
        let second = observe(2);
        let bytes = encode(&first).expect("encode");
        let (fds, witnesses) = passengers(5);
        assert_eq!(
            send_first_with_rights(sender.as_fd(), bytes[0], &fds).expect("rights"),
            1
        );
        drop(fds);
        // The rest of the first frame and a whole second frame coalesce.
        let mut rest = bytes[1..].to_vec();
        rest.extend(encode(&second).expect("encode"));
        (&sender).write_all(&rest).expect("rest");
        let (frame, rights) = read_parent_frame(receiver.as_fd(), Duration::from_secs(5))
            .expect("first frame")
            .expect("not eof");
        assert_eq!(frame, first);
        assert!(matches!(rights, LifecycleRights::CaptureOutputs(_)));
        let (frame, rights) = read_parent_frame(receiver.as_fd(), Duration::from_secs(5))
            .expect("second frame")
            .expect("not eof");
        assert_eq!(frame, second);
        assert!(matches!(rights, LifecycleRights::None));
        assert!(
            !all_closed(&witnesses),
            "the worker owns the transferred set"
        );
        drop(rights);
        drop(frame);
        drop(sender);
        assert!(read_parent_frame(receiver.as_fd(), Duration::from_secs(5))
            .expect("clean eof")
            .is_none());
    }

    #[test]
    fn misplaced_miscounted_and_excess_rights_are_closed_and_refused() {
        type Case = (ParentFrame, usize, usize);
        let cases: [Case; 5] = [
            // Rights attached to a later frame byte.
            (prepare(1), 5, 2),
            (prepare(1), 5, 9),
            // Rights on a command that carries none.
            (observe(1), 1, 0),
            // Too few for the command.
            (prepare(1), 4, 0),
            // More than any command carries.
            (prepare(1), MAX_RIGHTS + 1, 0),
        ];
        for (frame, count, attach_at) in cases {
            let (sender, receiver) = UnixStream::pair().expect("pair");
            let bytes = encode(&frame).expect("encode");
            let (fds, witnesses) = passengers(count);
            (&sender).write_all(&bytes[..attach_at]).expect("prefix");
            send_first_with_rights(sender.as_fd(), bytes[attach_at], &fds).expect("rights");
            drop(fds);
            (&sender)
                .write_all(&bytes[attach_at + 1..])
                .expect("suffix");
            let error =
                read_parent_frame(receiver.as_fd(), Duration::from_secs(5)).expect_err("refused");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidData,
                "{count}@{attach_at}"
            );
            assert!(
                all_closed(&witnesses),
                "{count} rights at byte {attach_at} must be closed, not leaked"
            );
        }
    }

    #[test]
    fn truncated_frames_fail_and_never_wait_forever() {
        let (sender, receiver) = UnixStream::pair().expect("pair");
        let bytes = encode(&observe(1)).expect("encode");
        (&sender).write_all(&bytes[..6]).expect("partial");
        drop(sender);
        assert_eq!(
            read_parent_frame(receiver.as_fd(), Duration::from_secs(5))
                .expect_err("eof inside frame")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let (sender, receiver) = UnixStream::pair().expect("pair");
        (&sender).write_all(&bytes[..6]).expect("partial");
        assert_eq!(
            read_parent_frame(receiver.as_fd(), Duration::from_millis(50))
                .expect_err("stalled frame")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn one_tib_receipt_bitmap_and_exact_producer_fit_bounded_control_frame() {
        use crate::virt::lifecycle::{
            CaptureStateBinding, CommandOutcome, NativePauseGeneration, OutputReceipt,
        };
        use vm_spec::capture::{
            full_dirty_chunks, CaptureFullReason, CaptureMemoryStats, MAX_CAPTURE_RAM_BYTES,
            MAX_NATIVE_PRODUCER_BYTES,
        };
        let outcome = CommandOutcome::MemoryCaptured {
            binding: Box::new(CaptureStateBinding {
                native_producer: "\u{1}".repeat(MAX_NATIVE_PRODUCER_BYTES),
                silo_producer: digest(1),
                profile: digest(2),
                topology: digest(3),
                ram_layout: digest(4),
                source_run: Uuid::new_v4(),
                capture: Uuid::new_v4(),
                pause_generation: NativePauseGeneration::new(1).unwrap(),
            }),
            ram: OutputReceipt {
                device: 1,
                inode: 2,
                length: MAX_CAPTURE_RAM_BYTES,
            },
            layout: OutputReceipt {
                device: 1,
                inode: 3,
                length: 65536,
            },
            memory_generation: 1,
            writers_closed: true,
            mode: vm_spec::lifecycle::CapturePolicy::Full,
            baseline: None,
            full_reason: Some(CaptureFullReason::Requested),
            dirty_chunks: full_dirty_chunks(MAX_CAPTURE_RAM_BYTES).unwrap(),
            stats: Box::new(CaptureMemoryStats {
                logical_bytes: MAX_CAPTURE_RAM_BYTES,
                identity_bytes_hashed: MAX_CAPTURE_RAM_BYTES,
                whole_file_bytes_hashed: MAX_CAPTURE_RAM_BYTES,
                ..Default::default()
            }),
        };
        let bytes = encode(&outcome).unwrap();
        assert!(bytes.len() > 16 * 1024);
        assert!(bytes.len() <= MAX_FRAME + 4);
        let mut buffer = FrameBuffer::default();
        buffer.extend(&bytes).unwrap();
        assert_eq!(buffer.next::<CommandOutcome>().unwrap(), Some(outcome));
    }
}

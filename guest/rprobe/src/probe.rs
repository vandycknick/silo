#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Filesystems,
    DiagnosticPort,
    DataPort,
    RosettaMount,
    RosettaFile,
    Capture,
    FrameWrite,
    Poweroff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    System,
    Deadline,
    ZeroProgress,
    InvalidProgress,
    InvalidFrame,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeError {
    pub stage: Stage,
    pub kind: ErrorKind,
    pub errno: i32,
}

pub struct OwnedFailure<T> {
    stage: Stage,
    diagnostic: T,
}

impl<T> OwnedFailure<T> {
    pub const fn new(stage: Stage, diagnostic: T) -> Self {
        Self { stage, diagnostic }
    }

    pub fn diagnostic_mut(&mut self) -> &mut T {
        &mut self.diagnostic
    }

    pub fn into_parts(self) -> (Stage, T) {
        (self.stage, self.diagnostic)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteEvent {
    Written(usize),
    Interrupted,
    WouldBlock,
    System(i32),
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteAction {
    Continue,
    WaitWritable,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteProgress {
    total: usize,
    written: usize,
}

impl WriteProgress {
    pub const fn new(total: usize) -> Self {
        Self { total, written: 0 }
    }

    pub const fn written(self) -> usize {
        self.written
    }

    pub const fn remaining(self) -> usize {
        self.total - self.written
    }

    pub fn update(&mut self, event: WriteEvent) -> Result<WriteAction, ProbeError> {
        match event {
            WriteEvent::Written(0) => Err(error(ErrorKind::ZeroProgress, 0)),
            WriteEvent::Written(count) if count > self.remaining() => {
                Err(error(ErrorKind::InvalidProgress, 0))
            }
            WriteEvent::Written(count) => {
                self.written += count;
                if self.written == self.total {
                    Ok(WriteAction::Complete)
                } else {
                    Ok(WriteAction::Continue)
                }
            }
            WriteEvent::Interrupted => Ok(WriteAction::Continue),
            WriteEvent::WouldBlock => Ok(WriteAction::WaitWritable),
            WriteEvent::System(errno) => Err(error(ErrorKind::System, errno)),
            WriteEvent::Deadline => Err(error(ErrorKind::Deadline, 110)),
        }
    }
}

const fn error(kind: ErrorKind, errno: i32) -> ProbeError {
    ProbeError {
        stage: Stage::FrameWrite,
        kind,
        errno,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::probe::{ErrorKind, OwnedFailure, Stage, WriteAction, WriteEvent, WriteProgress};

    #[cfg(unix)]
    use std::io::{ErrorKind as IoErrorKind, Read, Write};
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[test]
    fn partial_writes_advance_the_source_offset() {
        let mut progress = WriteProgress::new(24);
        assert_eq!(
            progress.update(WriteEvent::Written(7)),
            Ok(WriteAction::Continue)
        );
        assert_eq!(progress.written(), 7);
        assert_eq!(progress.remaining(), 17);
        assert_eq!(
            progress.update(WriteEvent::Written(17)),
            Ok(WriteAction::Complete)
        );
        assert_eq!(progress.written(), 24);
    }

    #[test]
    fn interruption_retries_without_progress() {
        let mut progress = WriteProgress::new(1);
        assert_eq!(
            progress.update(WriteEvent::Interrupted),
            Ok(WriteAction::Continue)
        );
        assert_eq!(progress.written(), 0);
    }

    #[test]
    fn backpressure_waits_without_progress() {
        let mut progress = WriteProgress::new(1);
        assert_eq!(
            progress.update(WriteEvent::WouldBlock),
            Ok(WriteAction::WaitWritable)
        );
        assert_eq!(progress.written(), 0);
    }

    #[test]
    fn zero_and_excess_progress_fail_closed() {
        let mut zero = WriteProgress::new(1);
        assert_eq!(
            zero.update(WriteEvent::Written(0)).unwrap_err().kind,
            ErrorKind::ZeroProgress
        );

        let mut excess = WriteProgress::new(1);
        assert_eq!(
            excess.update(WriteEvent::Written(2)).unwrap_err().kind,
            ErrorKind::InvalidProgress
        );
    }

    #[test]
    fn deadline_and_system_errors_are_classified() {
        let mut progress = WriteProgress::new(1);
        let deadline = progress.update(WriteEvent::Deadline).unwrap_err();
        assert_eq!(deadline.stage, Stage::FrameWrite);
        assert_eq!(deadline.kind, ErrorKind::Deadline);
        assert_eq!(deadline.errno, 110);

        let system = progress.update(WriteEvent::System(32)).unwrap_err();
        assert_eq!(system.kind, ErrorKind::System);
        assert_eq!(system.errno, 32);
    }

    #[cfg(unix)]
    #[test]
    fn real_socketpair_exercises_partial_writes_backpressure_and_eof() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();

        let bytes = [0x5a; 31];
        let mut progress = WriteProgress::new(bytes.len());
        while progress.remaining() > 0 {
            let end = progress.written() + core::cmp::min(progress.remaining(), 7);
            let count = writer.write(&bytes[progress.written()..end]).unwrap();
            progress.update(WriteEvent::Written(count)).unwrap();
        }
        let mut received = [0; 31];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(received, bytes);

        let fill = [0u8; 8192];
        loop {
            match writer.write(&fill) {
                Ok(count) => assert!(count > 0),
                Err(error) if error.kind() == IoErrorKind::WouldBlock => break,
                Err(error) => panic!("unexpected socket fill error: {error}"),
            }
        }
        let mut blocked = WriteProgress::new(1);
        assert_eq!(
            blocked.update(WriteEvent::WouldBlock),
            Ok(WriteAction::WaitWritable)
        );

        drop(reader);
        let error = writer.write(&[1]).unwrap_err();
        let errno = error.raw_os_error().unwrap();
        assert_eq!(
            blocked.update(WriteEvent::System(errno)).unwrap_err().kind,
            ErrorKind::System
        );
    }

    #[cfg(unix)]
    #[test]
    fn owned_failure_retains_diagnostic_until_consumed() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        let mut failure = OwnedFailure::new(Stage::RosettaMount, writer);

        failure
            .diagnostic_mut()
            .write_all(b"synthetic diagnostic")
            .unwrap();
        let mut received = [0; 20];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"synthetic diagnostic");

        let (stage, writer) = failure.into_parts();
        assert_eq!(stage, Stage::RosettaMount);
        drop(writer);
        assert_eq!(reader.read(&mut [0u8; 1]).unwrap(), 0);
    }
}

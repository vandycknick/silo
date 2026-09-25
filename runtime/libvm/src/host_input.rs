//! Cancellable host input for interactive sessions and piped commands.
//!
//! Tokio's stdin uses an uncancellable blocking read. An outstanding read can
//! therefore keep runtime shutdown alive until the user presses Enter.

use std::fs::File;
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;

use nix::errno::Errno;
use nix::sys::select::{select, FdSet, FD_SETSIZE};

/// A demand-driven reader which does not change stdin's shared file flags.
///
/// This must be the only reader of the supplied descriptor. Drop it before
/// restoring terminal modes. Dropping cancels and joins its input thread,
/// including when the input producer remains open but sends no further bytes.
pub struct HostInput {
    requests: Option<SyncSender<()>>,
    results: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    cancel: UnixStream,
    worker: Option<JoinHandle<()>>,
    pending: bool,
    eof: bool,
}

impl HostInput {
    pub fn stdin() -> io::Result<Self> {
        Self::new(nix::unistd::dup(io::stdin()).map_err(io::Error::from)?)
    }

    fn new(input: OwnedFd) -> io::Result<Self> {
        let (cancel, wake) = UnixStream::pair()?;
        // nix's fd_set uses the platform's fixed FD_SETSIZE.
        if input.as_raw_fd() as usize >= FD_SETSIZE || wake.as_raw_fd() as usize >= FD_SETSIZE {
            return Err(io::Error::other(
                "host input descriptor exceeds select capacity",
            ));
        }
        let (requests, incoming) = mpsc::sync_channel(1);
        let (results, receiver) = tokio::sync::mpsc::channel(1);
        let worker = std::thread::Builder::new()
            .name("silo-host-input".to_string())
            .spawn(move || {
                let mut input = File::from(input);
                while incoming.recv().is_ok() {
                    let result = match read_input(&mut input, &wake) {
                        Ok(None) => break,
                        Ok(Some(bytes)) => Ok(bytes),
                        Err(error) => Err(error),
                    };
                    let finished = match &result {
                        Ok(bytes) => bytes.is_empty(),
                        Err(_) => true,
                    };
                    if results.blocking_send(result).is_err() || finished {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            results: receiver,
            cancel,
            worker: Some(worker),
            pending: false,
            eof: false,
        })
    }

    /// Returns a chunk, or an empty vector at EOF. Cancelling this future does
    /// not lose the outstanding read; the next call receives its result.
    pub async fn read(&mut self) -> io::Result<Vec<u8>> {
        if self.eof {
            return Ok(Vec::new());
        }
        if !self.pending {
            let request = self
                .requests
                .as_ref()
                .ok_or_else(|| io::Error::other("host input closed"))?;
            request
                .try_send(())
                .map_err(|_| io::Error::other("host input reader stopped"))?;
            self.pending = true;
        }
        let result = self.results.recv().await;
        self.pending = false;
        let bytes = result.ok_or_else(|| io::Error::other("host input reader stopped"))??;
        self.eof = bytes.is_empty();
        Ok(bytes)
    }
}

impl Drop for HostInput {
    fn drop(&mut self) {
        self.requests.take();
        self.results.close();
        let _ = self.cancel.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_input(input: &mut File, wake: &UnixStream) -> io::Result<Option<Vec<u8>>> {
    loop {
        let mut readable = FdSet::new();
        readable.insert(input.as_fd());
        readable.insert(wake.as_fd());
        // select, unlike poll, also handles /dev/tty on macOS.
        match select(None, &mut readable, None, None, None) {
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        if readable.contains(wake.as_fd()) {
            return Ok(None);
        }
        if readable.contains(input.as_fd()) {
            let mut buffer = vec![0; 8192];
            match input.read(&mut buffer) {
                Ok(read) => {
                    buffer.truncate(read);
                    return Ok(Some(buffer));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::host_input::HostInput;

    #[tokio::test]
    async fn cancelled_read_preserves_bytes_and_eof() {
        let (input, mut writer) = UnixStream::pair().expect("socket pair");
        let mut reader = HostInput::new(OwnedFd::from(input)).expect("reader");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reader.read())
                .await
                .is_err()
        );
        writer.write_all(b"hello").expect("write input");
        assert_eq!(reader.read().await.expect("read"), b"hello");
        drop(writer);
        assert!(reader.read().await.expect("EOF").is_empty());
        assert!(reader.read().await.expect("repeat EOF").is_empty());
    }

    #[test]
    fn runtime_exits_with_idle_pty_without_another_keystroke() {
        let pty = nix::pty::openpty(None, None).expect("PTY");
        let (finished, completion) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let mut input = HostInput::new(pty.slave).expect("reader");
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), input.read())
                        .await
                        .is_err()
                );
                drop(input);
            });
            drop(runtime);
            finished.send(()).expect("finished");
        });
        completion
            .recv_timeout(Duration::from_secs(2))
            .expect("shutdown must not wait for Enter");
        worker.join().expect("join");
        drop(pty.master);
    }

    #[tokio::test]
    async fn raw_pty_preserves_control_bytes_and_descriptor_flags() {
        use nix::fcntl::{fcntl, FcntlArg};
        use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, SetArg};

        let pty = nix::pty::openpty(None, None).expect("PTY");
        let mut modes = tcgetattr(&pty.slave).expect("terminal modes");
        cfmakeraw(&mut modes);
        tcsetattr(&pty.slave, SetArg::TCSANOW, &modes).expect("raw mode");
        let flags = fcntl(&pty.slave, FcntlArg::F_GETFL).expect("flags");
        let mut reader =
            HostInput::new(nix::unistd::dup(&pty.slave).expect("dup")).expect("reader");
        let mut master = std::fs::File::from(pty.master);
        master.write_all(b"exit\n\x03\x04").expect("keystrokes");
        let bytes = tokio::time::timeout(Duration::from_secs(2), reader.read())
            .await
            .expect("read deadline")
            .expect("read");
        assert_eq!(bytes, b"exit\n\x03\x04");
        drop(reader);
        assert_eq!(fcntl(&pty.slave, FcntlArg::F_GETFL).expect("flags"), flags);
        assert_eq!(tcgetattr(&pty.slave).expect("modes"), modes);
    }

    #[test]
    fn dropping_an_unused_reader_does_not_wait_for_input() {
        let (input, _writer) = UnixStream::pair().expect("socket pair");
        drop(HostInput::new(OwnedFd::from(input)).expect("reader"));
    }
}

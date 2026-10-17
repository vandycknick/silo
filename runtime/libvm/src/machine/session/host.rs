//! Host terminal policy for local SSH shells, never constructed for supplied I/O.
use std::os::fd::AsRawFd;

use tokio::sync::mpsc;

use crate::machine::session::guest_session_error;
use crate::machine::session::ssh::{SshShellControl, SshShellSignal};
use crate::LibVmError;

/// Embedding-owned local signals. Signal numbers are Linux guest numbers, not host numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentSignal {
    Hangup,
    Interrupt,
    Quit,
    Terminate,
    User1,
    User2,
    WindowChange,
}
impl AttachmentSignal {
    /// Converts the supported Linux signals, including WINCH as a local size query.
    pub fn from_linux(signal: u32) -> Option<Self> {
        match signal {
            1 => Some(Self::Hangup),
            2 => Some(Self::Interrupt),
            3 => Some(Self::Quit),
            15 => Some(Self::Terminate),
            10 => Some(Self::User1),
            12 => Some(Self::User2),
            28 => Some(Self::WindowChange),
            _ => None,
        }
    }
    fn control(self) -> SshShellControl {
        let signal = match self {
            Self::Hangup => SshShellSignal::Hup,
            Self::Interrupt => SshShellSignal::Int,
            Self::Quit => SshShellSignal::Quit,
            Self::Terminate => SshShellSignal::Term,
            Self::User1 => SshShellSignal::Usr1,
            Self::User2 => SshShellSignal::Usr2,
            Self::WindowChange => {
                let (columns, rows) = current_terminal_size();
                return SshShellControl::Resize {
                    rows: rows as u16,
                    columns: columns as u16,
                };
            }
        };
        SshShellControl::Signal(signal)
    }
}

pub(super) enum Signals {
    External(mpsc::Receiver<AttachmentSignal>),
    Host {
        resize: tokio::signal::unix::Signal,
        hup: tokio::signal::unix::Signal,
        int: tokio::signal::unix::Signal,
        quit: tokio::signal::unix::Signal,
        term: tokio::signal::unix::Signal,
    },
}
impl Signals {
    fn new(external: Option<mpsc::Receiver<AttachmentSignal>>) -> std::io::Result<Self> {
        if let Some(receiver) = external {
            return Ok(Self::External(receiver));
        }
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self::Host {
            resize: signal(SignalKind::window_change())?,
            hup: signal(SignalKind::hangup())?,
            int: signal(SignalKind::interrupt())?,
            quit: signal(SignalKind::quit())?,
            term: signal(SignalKind::terminate())?,
        })
    }
    pub(super) async fn recv(&mut self) -> Option<SshShellControl> {
        let event = match self {
            Self::External(receiver) => receiver.recv().await,
            Self::Host {
                resize,
                hup,
                int,
                quit,
                term,
            } => tokio::select! {
                v = resize.recv() => v.map(|_| AttachmentSignal::WindowChange),
                v = hup.recv() => v.map(|_| AttachmentSignal::Hangup),
                v = int.recv() => v.map(|_| AttachmentSignal::Interrupt),
                v = quit.recv() => v.map(|_| AttachmentSignal::Quit),
                v = term.recv() => v.map(|_| AttachmentSignal::Terminate),
            },
        };
        event.map(AttachmentSignal::control)
    }
}

pub(super) enum LocalInput {
    Bytes(Vec<u8>),
    Eof,
    Detach,
}

pub(super) struct LocalReader {
    // Field order is intentional: HostInput joins its worker before termios restoration.
    input: crate::host_input::HostInput,
    _terminal: utils::terminal::RawTerminalGuard,
    sequence: Vec<u8>,
    position: usize,
}
pub(super) struct LocalAdapter {
    reader: LocalReader,
    signals: Signals,
}
impl LocalAdapter {
    pub(super) fn new(
        reference: &str,
        sequence: Vec<u8>,
        signals: Option<mpsc::Receiver<AttachmentSignal>>,
    ) -> Result<Self, LibVmError> {
        let signals = Signals::new(signals)
            .map_err(|e| guest_session_error(reference, format!("listen for host signals: {e}")))?;
        let terminal = utils::terminal::RawTerminalGuard::new(std::io::stdin())
            .map_err(|e| guest_session_error(reference, format!("enable raw terminal: {e}")))?;
        let input = crate::host_input::HostInput::stdin()
            .map_err(|e| guest_session_error(reference, format!("open host input: {e}")))?;
        Ok(Self {
            reader: LocalReader {
                input,
                _terminal: terminal,
                sequence,
                position: 0,
            },
            signals,
        })
    }
    pub(super) fn into_parts(self) -> (LocalReader, Signals) {
        (self.reader, self.signals)
    }
}
impl LocalReader {
    pub(super) async fn read(&mut self) -> std::io::Result<LocalInput> {
        let bytes = self.input.read().await?;
        if bytes.is_empty() {
            return Ok(LocalInput::Eof);
        }
        if input_contains_detach_sequence(&bytes, &self.sequence, &mut self.position) {
            return Ok(LocalInput::Detach);
        }
        Ok(LocalInput::Bytes(bytes))
    }
}

pub(super) fn current_terminal_size() -> (u32, u32) {
    let stdout = std::io::stdout();
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // nix has no portable terminal-size query wrapping TIOCGWINSZ.
    if unsafe { libc::ioctl(stdout.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
        && size.ws_row > 0
    {
        (u32::from(size.ws_col), u32::from(size.ws_row))
    } else {
        (80, 24)
    }
}

pub(super) fn detach_sequence(spec: Option<&str>) -> Result<Vec<u8>, LibVmError> {
    let Some(spec) = spec else {
        return Ok(vec![0x1d]);
    };
    let mut sequence = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        let byte = if let Some(control) = part.strip_prefix("ctrl-") {
            match control {
                "]" => 0x1d,
                "[" => 0x1b,
                "\\" => 0x1c,
                "^" => 0x1e,
                "_" => 0x1f,
                "@" => 0,
                value if value.len() == 1 && value.as_bytes()[0].is_ascii_alphabetic() => {
                    value.as_bytes()[0].to_ascii_lowercase() - b'a' + 1
                }
                _ => {
                    return Err(guest_session_error(
                        "shell",
                        format!("invalid detach key {part:?}"),
                    ))
                }
            }
        } else if part.len() == 1 {
            part.as_bytes()[0]
        } else {
            return Err(guest_session_error(
                "shell",
                format!("invalid detach key {part:?}"),
            ));
        };
        sequence.push(byte);
    }
    if sequence.is_empty() {
        sequence.push(0x1d);
    }
    Ok(sequence)
}
fn input_contains_detach_sequence(data: &[u8], sequence: &[u8], position: &mut usize) -> bool {
    for byte in data {
        if *byte == sequence[*position] {
            *position += 1;
            if *position == sequence.len() {
                *position = 0;
                return true;
            }
        } else {
            *position = usize::from(*byte == sequence[0]);
        }
    }
    false
}

/// Flushes each local terminal write, including prompts without a newline.
pub(super) struct LocalOutput {
    stdout: tokio::io::Stdout,
    written: usize,
    flushing: bool,
}
impl LocalOutput {
    pub(super) fn new() -> Self {
        Self {
            stdout: tokio::io::stdout(),
            written: 0,
            flushing: false,
        }
    }
}
impl tokio::io::AsyncWrite for LocalOutput {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::pin::Pin;
        use std::task::Poll;
        let this = self.get_mut();
        if !this.flushing {
            match Pin::new(&mut this.stdout).poll_write(cx, bytes) {
                Poll::Ready(Ok(length)) => {
                    this.written = length;
                    this.flushing = true;
                }
                other => return other,
            }
        }
        match Pin::new(&mut this.stdout).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.flushing = false;
                Poll::Ready(Ok(this.written))
            }
            Poll::Ready(Err(error)) => {
                this.flushing = false;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use crate::machine::session::host::*;
    use std::time::Duration;

    #[test]
    fn detach_parser_and_incremental_match_preserve_local_policy() {
        assert_eq!(detach_sequence(None).unwrap(), [0x1d]);
        let sequence = detach_sequence(Some("ctrl-p,ctrl-q")).unwrap();
        assert_eq!(sequence, [0x10, 0x11]);
        let mut position = 0;
        assert!(!input_contains_detach_sequence(
            b"prefix\x10",
            &sequence,
            &mut position
        ));
        assert!(input_contains_detach_sequence(
            b"\x11suffix",
            &sequence,
            &mut position
        ));
        assert_eq!(position, 0);
        assert!(detach_sequence(Some("ctrl-1")).is_err());
        assert_eq!(
            detach_sequence(Some("ctrl-],ctrl-[,ctrl-\\,ctrl-^,ctrl-_,ctrl-@,X")).unwrap(),
            [0x1d, 0x1b, 0x1c, 0x1e, 0x1f, 0, b'X']
        );
    }
    #[tokio::test]
    async fn external_signals_translate_linux_user_signals_and_disable_on_close() {
        let (sender, receiver) = mpsc::channel(4);
        let mut signals = Signals::new(Some(receiver)).unwrap();
        sender.send(AttachmentSignal::User1).await.unwrap();
        sender.send(AttachmentSignal::User2).await.unwrap();
        assert_eq!(
            signals.recv().await,
            Some(SshShellControl::Signal(SshShellSignal::Usr1))
        );
        assert_eq!(
            signals.recv().await,
            Some(SshShellControl::Signal(SshShellSignal::Usr2))
        );
        sender.send(AttachmentSignal::WindowChange).await.unwrap();
        let (columns, rows) = current_terminal_size();
        assert_eq!(
            signals.recv().await,
            Some(SshShellControl::Resize {
                rows: rows as u16,
                columns: columns as u16
            })
        );
        drop(sender);
        assert_eq!(signals.recv().await, None);
    }
    #[test]
    fn local_adapter_restores_real_pty_after_detach_and_cancelled_read() {
        const CHILD: &str = "SILO_SSH_LOCAL_PTY_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let (_sender, receiver) = mpsc::channel(1);
                let adapter =
                    LocalAdapter::new("pty", detach_sequence(None).unwrap(), Some(receiver))
                        .unwrap();
                let (mut reader, _signals) = adapter.into_parts();
                if mode == "detach" {
                    assert!(matches!(
                        tokio::time::timeout(Duration::from_secs(2), reader.read())
                            .await
                            .unwrap()
                            .unwrap(),
                        LocalInput::Detach
                    ));
                } else {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(300), reader.read())
                            .await
                            .is_err()
                    );
                }
                drop(reader);
            });
            return;
        }
        use nix::pty::openpty;
        use nix::sys::termios::{tcgetattr, LocalFlags};
        use std::io::Write;
        for mode in ["detach", "cancel"] {
            let pty = openpty(None, None).unwrap();
            let original = tcgetattr(&pty.slave).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "machine::session::host::tests::local_adapter_restores_real_pty_after_detach_and_cancelled_read", "--nocapture"])
                .env(CHILD, mode)
                .stdin(std::process::Stdio::from(nix::unistd::dup(&pty.slave).unwrap()))
                .spawn().unwrap();
            let mut raw = false;
            for _ in 0..200 {
                if !tcgetattr(&pty.slave)
                    .unwrap()
                    .local_flags
                    .contains(LocalFlags::ICANON)
                {
                    raw = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(raw, "child did not enter raw mode");
            let mut input = std::fs::File::from(pty.master);
            if mode == "detach" {
                input.write_all(b"\x1d").unwrap();
                assert!(child.wait().unwrap().success());
            } else {
                assert!(child.wait().unwrap().success());
            }
            assert_eq!(tcgetattr(&pty.slave).unwrap(), original);
        }
    }
    #[test]
    fn local_signal_subscriptions_are_onstack_and_external_receiver_is_inert() {
        const CHILD: &str = "SILO_SSH_SIGNAL_ACTION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "machine::session::host::tests::local_signal_subscriptions_are_onstack_and_external_receiver_is_inert", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        use nix::sys::signal::{raise, Signal};
        fn action(signal: Signal) -> libc::sigaction {
            let mut action = unsafe { std::mem::zeroed() };
            // nix lacks a read-only sigaction query.
            assert_eq!(
                unsafe { libc::sigaction(signal as i32, std::ptr::null(), &mut action) },
                0
            );
            action
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let watched = [
                Signal::SIGHUP,
                Signal::SIGINT,
                Signal::SIGQUIT,
                Signal::SIGTERM,
                Signal::SIGWINCH,
            ];
            let untouched = [
                Signal::SIGUSR1,
                Signal::SIGUSR2,
                Signal::SIGURG,
                Signal::SIGPROF,
                Signal::SIGPIPE,
                Signal::SIGCHLD,
                Signal::SIGSEGV,
                Signal::SIGBUS,
                Signal::SIGFPE,
            ];
            let before = untouched.map(action);
            let snapshots = watched.map(action);
            let (sender, receiver) = mpsc::channel(1);
            let mut external = Signals::new(Some(receiver)).unwrap();
            sender.send(AttachmentSignal::Interrupt).await.unwrap();
            assert_eq!(
                external.recv().await,
                Some(SshShellControl::Signal(SshShellSignal::Int))
            );
            drop(sender);
            assert_eq!(external.recv().await, None);
            drop(external);
            for (signal, previous) in watched.into_iter().zip(snapshots) {
                let current = action(signal);
                assert_eq!(current.sa_sigaction, previous.sa_sigaction);
                assert_eq!(current.sa_flags, previous.sa_flags);
            }
            for _ in 0..3 {
                let mut signals = Signals::new(None).unwrap();
                for signal in watched {
                    assert_ne!(action(signal).sa_flags & libc::SA_ONSTACK, 0);
                }
                raise(Signal::SIGINT).unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), signals.recv())
                        .await
                        .unwrap(),
                    Some(SshShellControl::Signal(SshShellSignal::Int))
                );
                drop(signals);
                for (signal, previous) in untouched.into_iter().zip(before) {
                    let current = action(signal);
                    assert_eq!(current.sa_sigaction, previous.sa_sigaction);
                    assert_eq!(current.sa_flags, previous.sa_flags);
                }
            }
        });
    }
}

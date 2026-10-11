//! Unix raw-terminal ownership, shared by local interactive clients.

use std::io;
use std::os::fd::{AsFd, OwnedFd};

use nix::sys::termios::{self, SetArg, Termios};

/// Restores a terminal's original settings when dropped, including on error.
///
/// Owns a duplicated descriptor, so the caller may close its descriptor first.
/// Non-terminal descriptors are a no-op. This guard owns no input or signals;
/// callers must stop and join their input workers before dropping it.
#[derive(Debug)]
pub struct RawTerminalGuard {
    fd: OwnedFd,
    original: Option<Termios>,
}

impl RawTerminalGuard {
    /// Enables raw mode with `TCSAFLUSH`, or does nothing for a non-terminal.
    pub fn new(fd: impl AsFd) -> io::Result<Self> {
        let fd = fd.as_fd().try_clone_to_owned()?;
        match nix::unistd::isatty(&fd) {
            Ok(true) => {}
            Ok(false) | Err(nix::errno::Errno::ENOTTY) => {
                return Ok(Self { fd, original: None });
            }
            Err(error) => return Err(error.into()),
        }
        let original = termios::tcgetattr(&fd)?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&fd, SetArg::TCSAFLUSH, &raw)?;
        Ok(Self {
            fd,
            original: Some(original),
        })
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let _ = termios::tcsetattr(&self.fd, SetArg::TCSAFLUSH, original);
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::pty::openpty;
    use nix::sys::termios::{self, LocalFlags};

    use crate::terminal::RawTerminalGuard;

    #[test]
    fn raw_mode_restores_original_settings_after_scope_exit() {
        let pty = openpty(None, None).expect("open PTY");
        let original = termios::tcgetattr(&pty.slave).expect("original settings");
        {
            let _guard = RawTerminalGuard::new(&pty.slave).expect("raw mode");
            let actual = termios::tcgetattr(&pty.slave).expect("raw settings");
            let mut expected = original.clone();
            termios::cfmakeraw(&mut expected);
            assert_eq!(actual, expected);
            assert!(!actual
                .local_flags
                .intersects(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ISIG));
        }
        assert_eq!(termios::tcgetattr(&pty.slave).unwrap(), original);
    }

    #[test]
    fn error_exit_restores_terminal_even_after_original_descriptor_is_closed() {
        let pty = openpty(None, None).expect("open PTY");
        let observer = pty.slave.try_clone().expect("duplicate PTY");
        let original = termios::tcgetattr(&observer).unwrap();
        let fail = || -> std::io::Result<()> {
            let _guard = RawTerminalGuard::new(&pty.slave)?;
            drop(pty.slave);
            Err(std::io::Error::other("operation failed"))
        };
        assert!(fail().is_err());
        assert_eq!(termios::tcgetattr(&observer).unwrap(), original);
    }

    #[test]
    fn non_terminal_is_a_noop() {
        let (reader, writer) = nix::unistd::pipe().expect("pipe");
        let _guard = RawTerminalGuard::new(&reader).expect("non-terminal guard");
        nix::unistd::write(&writer, b"unchanged").expect("write pipe");
        let mut bytes = [0; 9];
        assert_eq!(nix::unistd::read(&reader, &mut bytes).unwrap(), 9);
        assert_eq!(&bytes, b"unchanged");
    }
}

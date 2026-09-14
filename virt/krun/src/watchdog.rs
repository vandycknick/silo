#![allow(
    dead_code,
    reason = "watchdog is compiled into both the library parent side and krun child side"
)]

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::thread;

use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::libc;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::stat::{fstat, SFlag};
use nix::unistd::pipe;

pub(crate) const ENV_WATCHDOG_FD: &str = "SILO_KRUN_WATCHDOG_FD";

#[derive(Debug)]
pub(crate) struct Keepalive {
    _write_fd: OwnedFd,
}

pub(crate) fn create() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;

    set_cloexec(read_fd.as_fd(), true)?;
    set_cloexec(write_fd.as_fd(), true)?;

    Ok((
        read_fd,
        Keepalive {
            _write_fd: write_fd,
        },
    ))
}

pub(crate) fn fd_env_value(fd: &OwnedFd) -> String {
    fd.as_raw_fd().to_string()
}

pub(crate) fn take_from_env() -> io::Result<Option<OwnedFd>> {
    let Some(value) = std::env::var_os(ENV_WATCHDOG_FD) else {
        return Ok(None);
    };
    take_from_value(&value).map(Some)
}

fn take_from_value(value: &std::ffi::OsStr) -> io::Result<OwnedFd> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "watchdog fd is not UTF-8"))?;
    let fd = value.parse::<RawFd>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid watchdog fd {value:?}: {error}"),
        )
    })?;
    if fd < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "watchdog fd must not alias standard input, output, or error",
        ));
    }
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let stat = fstat(borrowed).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watchdog fd {fd} is not open: {error}"),
        )
    })?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFIFO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watchdog fd {fd} is not a pipe"),
        ));
    }
    let status = OFlag::from_bits_truncate(fcntl(borrowed, FcntlArg::F_GETFL)?);
    if status.bits() & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watchdog fd {fd} is not a pipe read end"),
        ));
    }

    // SAFETY: validation above proves this non-stdio descriptor is open, and the
    // launcher transfers its sole ownership through the environment contract.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(read_fd.as_fd(), true)?;
    Ok(read_fd)
}

pub(crate) fn start(read_fd: OwnedFd) {
    if let Err(err) = thread::Builder::new()
        .name("krun-watchdog".to_string())
        .spawn(move || {
            wait_for_parent_death(read_fd.as_fd());
            tracing::warn!("krun parent process exited, shutting down helper");
            std::process::exit(0);
        })
    {
        tracing::warn!(error = %err, "failed to start krun watchdog");
    }
}

fn set_cloexec(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let mut flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    flags.set(FdFlag::FD_CLOEXEC, enabled);
    fcntl(fd, FcntlArg::F_SETFD(flags))?;
    Ok(())
}

fn wait_for_parent_death(fd: BorrowedFd<'_>) {
    let mut poll_fd = [PollFd::new(fd, PollFlags::POLLHUP)];
    loop {
        match poll(&mut poll_fd, PollTimeout::NONE) {
            Ok(count) if count > 0 => {
                if poll_fd[0]
                    .revents()
                    .is_some_and(|events| events.contains(PollFlags::POLLHUP))
                {
                    return;
                }
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(err) => {
                tracing::warn!(error = %err, "krun watchdog poll failed");
                return;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::watchdog::{create, take_from_value, wait_for_parent_death};

    #[test]
    fn watchdog_observes_closed_keepalive() {
        let (read_fd, keepalive) = create().expect("create watchdog pipe");
        let (sender, receiver) = mpsc::channel();

        std::thread::spawn(move || {
            wait_for_parent_death(read_fd.as_fd());
            sender.send(()).expect("send watchdog completion");
        });

        drop(keepalive);

        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("watchdog should observe closed keepalive");
    }

    #[test]
    fn inherited_watchdog_requires_owned_read_pipe_above_stdio() {
        assert!(take_from_value(std::ffi::OsStr::new("-1")).is_err());
        assert!(take_from_value(std::ffi::OsStr::new("0")).is_err());

        let file = std::fs::File::open("/dev/null").expect("open regular descriptor");
        assert!(take_from_value(std::ffi::OsStr::new(&file.as_raw_fd().to_string())).is_err());
        nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFD)
            .expect("invalid watchdog value must not close borrowed descriptor");

        let (read, _write) = nix::unistd::pipe().expect("create watchdog pipe");
        let raw = read.into_raw_fd();
        let owned =
            take_from_value(std::ffi::OsStr::new(&raw.to_string())).expect("adopt valid read pipe");
        assert_eq!(owned.as_raw_fd(), raw);
    }
}

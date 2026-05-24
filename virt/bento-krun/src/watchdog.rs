#![allow(
    dead_code,
    reason = "watchdog is compiled into both the library parent side and krun child side"
)]

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::thread;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::unistd::pipe;

pub(crate) const ENV_WATCHDOG_FD: &str = "BENTO_KRUN_WATCHDOG_FD";

#[derive(Debug)]
pub(crate) struct Keepalive {
    _write_fd: OwnedFd,
}

pub(crate) fn create() -> io::Result<(OwnedFd, Keepalive)> {
    let (read_fd, write_fd) = pipe()?;

    set_cloexec(read_fd.as_fd(), false)?;
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

pub(crate) fn start_from_env() {
    let Ok(fd) = std::env::var(ENV_WATCHDOG_FD) else {
        return;
    };
    let Ok(fd) = fd.parse::<RawFd>() else {
        tracing::warn!(value = %fd, "invalid krun watchdog fd");
        return;
    };

    // SAFETY: the parent passes this fd through exec by clearing FD_CLOEXEC on
    // the read end of the watchdog pipe and exporting its raw fd number.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fd) };
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
    use std::os::fd::AsFd;
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::watchdog::{create, wait_for_parent_death};

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
}

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{pidfd_open, pidfd_send_signal, PidfdFlags};

use crate::supervisor::process::{errno_to_io, pid_exists, rustix_pid, signal_pid};

#[derive(Debug)]
pub(crate) struct ProcessIdentity {
    pid: i32,
    started_at: Option<i64>,
    pidfd: Option<OwnedFd>,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        let Some(raw_pid) = rustix_pid(pid) else {
            return Ok(None);
        };

        match pidfd_open(raw_pid, PidfdFlags::empty()) {
            Ok(pidfd) => {
                let Some(started_at) = utils::process::start_time(pid)? else {
                    return Ok(None);
                };
                // A process keeps its number until it is reaped. A pidfd that is
                // still live after the read binds that birth identity to it.
                if pidfd_has_exited(&pidfd)? {
                    return Ok(None);
                }
                Ok(Some(Self {
                    pid,
                    started_at: Some(started_at),
                    pidfd: Some(pidfd),
                }))
            }
            Err(rustix::io::Errno::SRCH) => Ok(None),
            Err(_) if pid_exists(pid)? => {
                let Some(started_at) = utils::process::start_time(pid)? else {
                    return Ok(None);
                };
                Ok(Some(Self {
                    pid,
                    started_at: Some(started_at),
                    pidfd: None,
                }))
            }
            Err(_) => Ok(None),
        }
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        self.started_at
    }

    pub(crate) fn matches_started_at(&self, expected: Option<i64>) -> bool {
        self.started_at == expected
    }

    pub(crate) fn is_alive(&self) -> io::Result<bool> {
        match self.pidfd.as_ref() {
            Some(pidfd) => Ok(!pidfd_has_exited(pidfd)?),
            None => Ok(utils::process::start_time(self.pid)?
                .is_some_and(|started| Some(started) == self.started_at)),
        }
    }

    /// Sends `signal` to this exact process; `false` means it already exited.
    pub(crate) fn signal(&self, signal: Signal) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        let Some(pidfd) = self.pidfd.as_ref() else {
            // Without pidfd support the number can be reused between the
            // birth-identity check above and the numeric signal.
            return signal_pid(self.pid, signal);
        };
        let signal = rustix::process::Signal::from_named_raw(signal as i32).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unsupported process signal")
        })?;
        match pidfd_send_signal(pidfd, signal) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::SRCH) => Ok(false),
            Err(err) => Err(errno_to_io(err)),
        }
    }

    /// Sends `signal` to the process group this exact process leads; `false`
    /// means the leader already exited or does not lead its group.
    pub(crate) fn signal_process_group(&self, signal: Signal) -> io::Result<bool> {
        let group = match nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(self.pid))) {
            Ok(group) => group.as_raw(),
            Err(Errno::ESRCH) => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        // Liveness after the lookup binds that group to this process. Like the
        // numeric `kill(-pid)`, a non-leader's group is never signaled.
        if !self.is_alive()? || group != self.pid {
            return Ok(false);
        }
        if let Some(pidfd) = self.pidfd.as_ref() {
            // Neither rustix's pidfd_send_signal (no flags argument) nor nix
            // (no pidfd API) can request PIDFD_SIGNAL_PROCESS_GROUP.
            let sent = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    signal as libc::c_int,
                    std::ptr::null::<libc::siginfo_t>(),
                    libc::PIDFD_SIGNAL_PROCESS_GROUP,
                )
            };
            if sent == 0 {
                return Ok(true);
            }
            match Errno::last() {
                Errno::ESRCH => return Ok(false),
                // Kernels before 6.9 reject the flag. The live leader still
                // holds its group number, leaving only the check-to-kill window.
                Errno::EINVAL => {}
                err => return Err(err.into()),
            }
        }
        signal_pid(-self.pid, signal)
    }
}

fn pidfd_has_exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut fds = [PollFd::new(pidfd, PollFlags::IN)];

    match poll(&mut fds, Some(&timeout)) {
        Ok(ready) => Ok(ready > 0),
        Err(err) => Err(errno_to_io(err)),
    }
}

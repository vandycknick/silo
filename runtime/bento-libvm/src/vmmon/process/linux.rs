use std::io;
use std::os::fd::OwnedFd;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{pidfd_open, PidfdFlags};

use crate::vmmon::process::{errno_to_io, pid_exists, rustix_pid};

#[derive(Debug)]
pub(crate) struct ProcessIdentity {
    pid: i32,
    pidfd: Option<OwnedFd>,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        let Some(raw_pid) = rustix_pid(pid) else {
            return Ok(None);
        };

        match pidfd_open(raw_pid, PidfdFlags::empty()) {
            Ok(pidfd) => Ok(Some(Self {
                pid,
                pidfd: Some(pidfd),
            })),
            Err(rustix::io::Errno::SRCH) => Ok(None),
            Err(_) if pid_exists(pid)? => Ok(Some(Self { pid, pidfd: None })),
            Err(_) => Ok(None),
        }
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        None
    }

    pub(crate) fn matches_started_at(&self, _expected: Option<i64>) -> bool {
        true
    }

    pub(crate) fn is_alive(&self) -> io::Result<bool> {
        match self.pidfd.as_ref() {
            Some(pidfd) => Ok(!pidfd_has_exited(pidfd)?),
            None => pid_exists(self.pid),
        }
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

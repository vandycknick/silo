use std::io;
use std::os::fd::OwnedFd;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{pidfd_open, PidfdFlags};

use crate::supervisor::process::{errno_to_io, pid_exists, rustix_pid};

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
                if pidfd_has_exited(&pidfd)? {
                    return Ok(None);
                }
                let Some(started_at) = utils::process::start_time(pid)? else {
                    return Ok(None);
                };
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

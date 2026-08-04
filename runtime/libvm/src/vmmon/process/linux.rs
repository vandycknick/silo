use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{pidfd_open, PidfdFlags};

use crate::vmmon::process::{errno_to_io, pid_exists, rustix_pid};

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
            Ok(pidfd) => Ok(Some(Self {
                pid,
                started_at: process_started_at(pid)?,
                pidfd: Some(pidfd),
            })),
            Err(rustix::io::Errno::SRCH) => Ok(None),
            Err(_) if pid_exists(pid)? => Ok(Some(Self {
                pid,
                started_at: process_started_at(pid)?,
                pidfd: None,
            })),
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
            None => pid_exists(self.pid),
        }
    }
}

fn process_started_at(pid: i32) -> io::Result<Option<i64>> {
    let path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some((_, fields)) = stat.rsplit_once(") ") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse process stat {}", path.display()),
        ));
    };
    let started_at = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("process stat {} has no start time", path.display()),
            )
        })?
        .parse::<i64>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse process start time {}: {error}", path.display()),
            )
        })?;
    Ok(Some(started_at))
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

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::process::{pidfd_open, PidfdFlags};

use crate::vmmon::process::{errno_to_io, pid_exists, rustix_pid};

#[derive(Debug)]
pub(crate) struct ProcessIdentity {
    pid: i32,
    pidfd: Option<OwnedFd>,
    uid: u32,
    start_time: u64,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        let Some(raw_pid) = rustix_pid(pid) else {
            return Ok(None);
        };
        for _ in 0..3 {
            let Some(before) = proc_identity(pid)? else {
                return Ok(None);
            };
            match pidfd_open(raw_pid, PidfdFlags::empty()) {
                Ok(pidfd) => {
                    let Some(after) = proc_identity(pid)? else {
                        return Ok(None);
                    };
                    if before == after {
                        return Ok(Some(Self {
                            pid,
                            pidfd: Some(pidfd),
                            uid: after.uid,
                            start_time: after.start_time,
                        }));
                    }
                }
                Err(rustix::io::Errno::SRCH) => return Ok(None),
                Err(_) if pid_exists(pid)? => {
                    let Some(after) = proc_identity(pid)? else {
                        return Ok(None);
                    };
                    if before == after {
                        return Ok(Some(Self {
                            pid,
                            pidfd: None,
                            uid: after.uid,
                            start_time: after.start_time,
                        }));
                    }
                }
                Err(_) => return Ok(None),
            }
        }
        Ok(None)
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
            None => Ok(proc_identity(self.pid)?.is_some_and(|current| {
                current.uid == self.uid && current.start_time == self.start_time
            })),
        }
    }

    pub(crate) fn owned_by_effective_user(&self) -> bool {
        self.uid == nix::unistd::Uid::effective().as_raw()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcIdentity {
    uid: u32,
    start_time: u64,
}

fn proc_identity(pid: i32) -> io::Result<Option<ProcIdentity>> {
    let metadata = match std::fs::metadata(format!("/proc/{pid}")) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc pid stat"))?;
    let start_time = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process start time"))?
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    Ok(Some(ProcIdentity {
        uid: metadata.uid(),
        start_time,
    }))
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

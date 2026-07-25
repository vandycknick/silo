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
    started_at: i64,
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
                            started_at: after.started_at,
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
                            started_at: after.started_at,
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
        Some(self.started_at)
    }

    pub(crate) fn matches_started_at(&self, expected: Option<i64>) -> bool {
        expected.is_none_or(|expected| self.started_at == expected)
    }

    pub(crate) fn is_alive(&self) -> io::Result<bool> {
        match self.pidfd.as_ref() {
            Some(pidfd) => Ok(!pidfd_has_exited(pidfd)?),
            None => Ok(proc_identity(self.pid)?.is_some_and(|current| {
                current.uid == self.uid && current.start_time == self.start_time
            })),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcIdentity {
    uid: u32,
    start_time: u64,
    started_at: i64,
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
    let started_at = process_start_epoch_seconds(start_time)?;
    Ok(Some(ProcIdentity {
        uid: metadata.uid(),
        start_time,
        started_at,
    }))
}

fn process_start_epoch_seconds(start_time: u64) -> io::Result<i64> {
    let ticks_per_second = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .map_err(|err| io::Error::from_raw_os_error(err as i32))?
        .ok_or_else(|| io::Error::other("kernel did not report clock ticks per second"))?;
    let ticks_per_second = u64::try_from(ticks_per_second)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    if ticks_per_second == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel reported zero clock ticks per second",
        ));
    }

    let stat = std::fs::read_to_string("/proc/stat")?;
    let boot_time = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing /proc/stat btime"))?
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let started_at = boot_time
        .checked_add(start_time / ticks_per_second)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process start time overflow"))?;
    i64::try_from(started_at).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
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

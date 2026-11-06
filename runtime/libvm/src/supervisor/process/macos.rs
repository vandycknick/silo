use std::io;

use nix::sys::signal::Signal;

use crate::supervisor::process::{pid_exists, signal_pid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pid: i32,
    started_at: Option<i64>,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        if pid <= 0 || !pid_exists(pid)? {
            return Ok(None);
        }

        let Some(started_at) = utils::process::start_time(pid)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            pid,
            started_at: Some(started_at),
        }))
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
        let Some(current) = Self::for_pid(self.pid)? else {
            return Ok(false);
        };
        Ok(current.matches_started_at(self.started_at))
    }

    /// Darwin has no pidfd: the birth identity is checked before the numeric
    /// signal; `false` means the recorded process already exited.
    pub(crate) fn signal(&self, signal: Signal) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        signal_pid(self.pid, signal)
    }

    /// Signals the process group this recorded process leads.
    pub(crate) fn signal_process_group(&self, signal: Signal) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        signal_pid(-self.pid, signal)
    }
}

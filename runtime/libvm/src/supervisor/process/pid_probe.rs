use std::io;

use nix::sys::signal::Signal;

use crate::supervisor::process::{pid_exists, signal_pid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pid: i32,
}

impl ProcessIdentity {
    pub(crate) fn for_pid(pid: i32) -> io::Result<Option<Self>> {
        if pid <= 0 || !pid_exists(pid)? {
            return Ok(None);
        }

        Ok(Some(Self { pid }))
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
        pid_exists(self.pid)
    }

    /// This platform has no birth identity; only existence precedes the signal.
    pub(crate) fn signal(&self, signal: Signal) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        signal_pid(self.pid, signal)
    }

    /// Signals the process group this process leads.
    pub(crate) fn signal_process_group(&self, signal: Signal) -> io::Result<bool> {
        if !self.is_alive()? {
            return Ok(false);
        }
        signal_pid(-self.pid, signal)
    }
}

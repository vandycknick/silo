use std::time::{Duration, SystemTime};

use crate::machine::MachineData;

/// Default time libvm waits for vmmon to exit after a lifecycle action.
pub const DEFAULT_MACHINE_WAIT_TIMEOUT: Duration = Duration::from_secs(45);

/// Options for waiting on a machine run to exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineWaitOptions {
    timeout: Duration,
}

impl Default for MachineWaitOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_MACHINE_WAIT_TIMEOUT,
        }
    }
}

impl MachineWaitOptions {
    /// Creates wait options with libvm's default timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how long libvm waits for the current machine run to exit.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub(crate) fn timeout_value(self) -> Duration {
        self.timeout
    }
}

/// Options for gracefully stopping a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MachineStopOptions {
    wait: MachineWaitOptions,
}

impl MachineStopOptions {
    /// Creates stop options with libvm's default wait behavior.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how long libvm waits after requesting a graceful stop.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.wait = self.wait.timeout(timeout);
        self
    }

    pub(crate) fn wait_options(self) -> MachineWaitOptions {
        self.wait
    }
}

/// Options for forcefully stopping a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MachineKillOptions {
    wait: MachineWaitOptions,
}

impl MachineKillOptions {
    /// Creates kill options with libvm's default wait behavior.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets how long libvm waits after forcing the monitor to exit.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.wait = self.wait.timeout(timeout);
        self
    }

    pub(crate) fn wait_options(self) -> MachineWaitOptions {
        self.wait
    }
}

/// Result of observing a machine run exit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MachineExit {
    /// Machine snapshot after libvm reconciled the exited run.
    pub machine: MachineData,
    /// Run ID for the exited vmmon generation, when one was known.
    pub run_id: Option<String>,
    /// Time vmmon reported for the exit, when available.
    pub exited_at: Option<SystemTime>,
    /// High-level exit outcome.
    pub outcome: MachineExitOutcome,
}

/// High-level outcome for a machine run observed by `Machine::wait`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MachineExitOutcome {
    /// vmmon reported a clean exit.
    Clean,
    /// vmmon reported an error exit.
    Error {
        /// Optional error message reported by vmmon.
        message: Option<String>,
    },
    /// The machine was already stopped when wait started.
    AlreadyStopped,
    /// libvm forced the monitor to exit and no cleaner vmmon status was reported.
    Forced,
    /// The run exited but no matching vmmon exit status was available.
    Unknown,
}

impl MachineExit {
    pub(crate) fn already_stopped(machine: MachineData) -> Self {
        Self {
            machine,
            run_id: None,
            exited_at: None,
            outcome: MachineExitOutcome::AlreadyStopped,
        }
    }
}

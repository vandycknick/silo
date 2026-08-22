use std::fmt;
use std::time::{Duration, SystemTime};

use crate::machine::MachineData;

/// Default time libvm waits for vmmon to exit after a lifecycle action.
pub const DEFAULT_MACHINE_WAIT_TIMEOUT: Duration = Duration::from_secs(45);

/// Opaque identifier for one acknowledged machine run.
///
/// A run ID is issued by [`Machine::start`](crate::Machine::start) and can be
/// supplied to generation-checked lifecycle methods. It is distinct from a
/// machine ID. Its textual form can be parsed when transferring the token
/// across a process boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachineRunId(String);

impl MachineRunId {
    pub(crate) fn from_raw(value: String) -> Self {
        Self(value)
    }

    /// Returns the stable textual representation sent to vmmon for this run.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for MachineRunId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let run_id = uuid::Uuid::parse_str(value)?;
        Ok(Self(run_id.hyphenated().to_string()))
    }
}

impl fmt::Display for MachineRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Result of an acknowledged machine start.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MachineStart {
    /// Machine snapshot after vmmon acknowledged this start.
    pub machine: MachineData,
    /// Exact generation created by this start.
    pub run_id: MachineRunId,
}

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
    pub run_id: Option<MachineRunId>,
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

#[cfg(test)]
mod tests {
    use crate::MachineRunId;

    #[test]
    fn machine_run_id_round_trips_across_process_boundaries() {
        let value = "0198c783-cd1c-77c2-b66a-c06275f20d1f";
        let run_id = value.parse::<MachineRunId>().expect("parse run ID");

        assert_eq!(run_id.as_str(), value);
        assert_eq!(run_id.to_string(), value);
    }

    #[test]
    fn machine_run_id_rejects_invalid_values() {
        assert!("not-a-run-id".parse::<MachineRunId>().is_err());
    }
}

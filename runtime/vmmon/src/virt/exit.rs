//! Terminal backend results. Process observations never stand in for wait/reap.

use serde::{Deserialize, Serialize};

/// How far a backend got before it terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupStage {
    Spawned,
    Request,
    Admission,
    Build,
    Started,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ForceReason {
    Stop,
    Cancelled,
    StartupFailure,
    ProtocolFailure,
    GracefulTimeout,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VmOutcome {
    Clean,
    Forced,
    Failed(String),
}

/// Wait status of the process that ran the VMM, when the backend owns one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessExit {
    pub(crate) pid: u32,
    pub(crate) raw_status: i32,
    pub(crate) code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) core_dumped: bool,
}

/// Bounded tail of the VMM process's own stdout/stderr.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Diagnostic {
    pub(crate) tail: String,
    pub(crate) truncated: bool,
}

/// Backend-neutral terminal result of one VM generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmExit {
    pub(crate) outcome: VmOutcome,
    pub(crate) stage: StartupStage,
    pub(crate) force_reason: Option<ForceReason>,
    pub(crate) process: Option<ProcessExit>,
    pub(crate) diagnostic: Option<Diagnostic>,
}

impl VmExit {
    pub(crate) fn stopped(stage: StartupStage) -> Self {
        Self {
            outcome: VmOutcome::Clean,
            stage,
            force_reason: None,
            process: None,
            diagnostic: None,
        }
    }

    pub(crate) fn failed(stage: StartupStage, error: impl Into<String>) -> Self {
        Self {
            outcome: VmOutcome::Failed(error.into()),
            ..Self::stopped(stage)
        }
    }

    pub(crate) fn error(&self) -> Option<String> {
        match &self.outcome {
            VmOutcome::Failed(error) => Some(error.clone()),
            VmOutcome::Clean | VmOutcome::Forced => None,
        }
    }

    pub(crate) fn forced(&self) -> bool {
        self.outcome == VmOutcome::Forced
    }
}

#[cfg(test)]
mod tests {
    use crate::virt::exit::{StartupStage, VmExit, VmOutcome};

    #[test]
    fn only_failed_outcomes_carry_an_error() {
        let clean = VmExit::stopped(StartupStage::Started);
        assert_eq!(clean.error(), None);
        assert!(!clean.forced());

        let failed = VmExit::failed(StartupStage::Build, "host admission failed");
        assert_eq!(failed.error().as_deref(), Some("host admission failed"));
        assert!(!failed.forced());
        assert_eq!(failed.stage, StartupStage::Build);

        let forced = VmExit {
            outcome: VmOutcome::Forced,
            ..VmExit::stopped(StartupStage::Started)
        };
        assert_eq!(forced.error(), None);
        assert!(forced.forced());
    }
}

//! Terminal backend results. Process observations never stand in for wait/reap.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    Stopped,
    StoppedWithError(String),
    Worker(Box<WorkerExit>),
}

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
    OwnerClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerExit {
    pub(crate) pid: u32,
    pub(crate) raw_status: i32,
    pub(crate) code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) core_dumped: bool,
    pub(crate) stage: StartupStage,
    pub(crate) shutdown_requested: bool,
    pub(crate) force_reason: Option<ForceReason>,
    pub(crate) failure: Option<String>,
    pub(crate) diagnostic_tail: String,
    pub(crate) diagnostic_truncated: bool,
}

impl WorkerExit {
    pub(crate) fn forced(&self) -> bool {
        self.force_reason.is_some() && self.signal == Some(nix::libc::SIGKILL)
    }

    pub(crate) fn error(&self) -> Option<String> {
        if let Some(error) = &self.failure {
            return Some(error.clone());
        }
        if self.forced() || self.code == Some(0) {
            return None;
        }
        Some(match (self.code, self.signal) {
            (Some(code), _) => format!("krun exited with status code {code}"),
            (_, Some(signal)) => format!("krun exited after signal {signal}"),
            _ => format!("krun exited with unknown status {}", self.raw_status),
        })
    }
}

impl VmExit {
    pub(crate) fn error(&self) -> Option<String> {
        match self {
            Self::Stopped => None,
            Self::StoppedWithError(error) => Some(error.clone()),
            Self::Worker(worker) => worker.error(),
        }
    }

    pub(crate) fn forced(&self) -> bool {
        matches!(self, Self::Worker(worker) if worker.forced())
    }
}

#[cfg(test)]
mod tests {
    use crate::virt::exit::{ForceReason, StartupStage, VmExit, WorkerExit};

    fn report(
        code: Option<i32>,
        signal: Option<i32>,
        force_reason: Option<ForceReason>,
    ) -> WorkerExit {
        WorkerExit {
            pid: 123,
            raw_status: 0,
            code,
            signal,
            core_dumped: false,
            stage: StartupStage::Started,
            shutdown_requested: true,
            force_reason,
            failure: None,
            diagnostic_tail: String::new(),
            diagnostic_truncated: false,
        }
    }

    #[test]
    fn shutdown_intent_does_not_hide_crashes_or_nonzero_exits() {
        for signal in [nix::libc::SIGSEGV, nix::libc::SIGTERM, nix::libc::SIGKILL] {
            let exit = VmExit::Worker(Box::new(report(None, Some(signal), None)));
            assert!(!exit.forced());
            assert!(exit.error().is_some());
        }
        assert!(report(Some(127), None, Some(ForceReason::Stop))
            .error()
            .is_some());
        assert!(
            report(None, Some(nix::libc::SIGSEGV), Some(ForceReason::Stop))
                .error()
                .is_some()
        );
        assert!(report(Some(0), None, None).error().is_none());
    }

    #[test]
    fn force_requires_observed_sigkill_and_preserves_primary_startup_error() {
        let mut worker = report(
            None,
            Some(nix::libc::SIGKILL),
            Some(ForceReason::StartupFailure),
        );
        assert!(worker.forced());
        assert!(worker.error().is_none());
        worker.failure = Some("host admission failed".to_string());
        assert_eq!(worker.error().as_deref(), Some("host admission failed"));
        let encoded = serde_json::to_vec(&worker).expect("encode worker");
        assert_eq!(
            serde_json::from_slice::<WorkerExit>(&encoded).expect("decode worker"),
            worker
        );
    }
}

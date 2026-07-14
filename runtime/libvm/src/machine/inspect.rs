use std::collections::BTreeMap;
use std::path::PathBuf;

use protocol::v1::{
    AgentStatusState, GuestBootMode, GuestBootReport, HostAgent, HostStatus,
    ProvisionFailurePolicy, ProvisionOverallStatus, ProvisionReport, ProvisionStepReport,
    ProvisionStepStatus, VmState,
};
use vm_spec::VmSpec;

use crate::machine::MachineGuestConfig;
use crate::network::MachineNetworkConfig;
use crate::store::models::{MachineConfig, MachineRuntimeState};

/// Public machine snapshot returned by inspect and mutation operations.
///
/// `MachineData` is an owned read model, not a live handle and not a SQLite
/// storage model. It intentionally flattens persisted machine configuration,
/// reconciled lifecycle state, and best-effort vmmon telemetry so callers do not
/// depend on libvm's private `store::models` module.
///
/// Callers should treat this as a point-in-time snapshot. To perform lifecycle
/// operations or stream I/O, keep using the `Machine` handle that produced it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MachineData {
    /// Stable machine ID.
    pub id: String,
    /// Human-readable machine name.
    pub name: String,
    /// VM specification used to start the machine.
    pub spec: VmSpec,
    /// Directory containing this machine's persistent runtime files.
    pub machine_dir: PathBuf,
    /// Unix timestamp for when the machine was created.
    pub created_at: i64,
    /// Unix timestamp for the last configuration change.
    pub modified_at: i64,
    /// Image reference used to create the machine.
    pub image_ref: String,
    /// Requested root disk size in bytes, when explicitly configured.
    pub root_disk_size: Option<u64>,
    /// User-defined labels attached to the machine.
    pub labels: BTreeMap<String, String>,
    /// User-defined metadata attached to the machine.
    pub metadata: BTreeMap<String, String>,
    /// Desired network attachment recorded for the machine.
    pub network: MachineNetworkConfig,
    /// Durable guest behavior owned by libvm.
    pub guest: MachineGuestConfig,
    /// Reconciled lifecycle status for the machine.
    ///
    /// `Machine::inspect` always reconciles persisted state with the local vmmon
    /// process first. When vmmon is running it also attempts a best-effort vmmon
    /// inspect RPC to populate guest readiness and a human-readable message. A
    /// vmmon telemetry failure does not fail the whole inspect call; it is
    /// reported here as a non-ready running status message instead.
    pub status: MachineStatus,
    /// Latest guest boot report observed by vmmon, when the guest registered one.
    pub boot_report: Option<MachineBootReport>,
    /// Latest guest provisioning report observed by vmmon, when the guest registered one.
    pub provision_report: Option<MachineProvisionReport>,
    /// Unix timestamp for when the machine last started.
    pub started_at: Option<i64>,
    /// Last persisted runtime error, when present.
    pub last_error: Option<String>,
    /// Unix timestamp for the last runtime state change.
    pub updated_at: i64,
}

impl MachineData {
    pub(crate) fn from_models_with_status(
        config: MachineConfig,
        status: MachineStatus,
        boot_report: Option<MachineBootReport>,
        provision_report: Option<MachineProvisionReport>,
        started_at: Option<i64>,
        last_error: Option<String>,
        updated_at: i64,
    ) -> Self {
        Self {
            id: config.id.to_string(),
            name: config.name,
            spec: config.spec,
            machine_dir: config.machine_dir,
            created_at: config.created_at,
            modified_at: config.modified_at,
            image_ref: config.image_ref,
            root_disk_size: config.root_disk_size,
            labels: config.labels,
            metadata: config.metadata,
            network: config.network.into(),
            guest: config.guest,
            status,
            boot_report,
            provision_report,
            started_at,
            last_error,
            updated_at,
        }
    }

    /// Returns true when the persisted lifecycle state is running.
    pub fn is_running(&self) -> bool {
        self.status.is_running()
    }

    /// Returns the runtime trace log path for this machine.
    pub fn trace_log_path(&self) -> PathBuf {
        crate::paths::vmmon_trace_log_path_in(&self.machine_dir)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineBootReport {
    pub mode: MachineBootMode,
    pub requested_init: Option<String>,
    pub handoff_init_path: Option<String>,
    pub probed_init_paths: Vec<String>,
    pub agent_path: Option<String>,
    pub agent_pid: u32,
    pub agent_is_pid1: bool,
    pub message: Option<String>,
}

impl MachineBootReport {
    pub(crate) fn from_protocol(report: GuestBootReport) -> Self {
        Self {
            mode: MachineBootMode::from_protocol(report.mode.unwrap_or_default()),
            requested_init: non_empty_string(report.requested_init),
            handoff_init_path: non_empty_string(report.handoff_init_path),
            probed_init_paths: report.probed_init_paths,
            agent_path: non_empty_string(report.agent_path),
            agent_pid: report.agent_pid.unwrap_or_default(),
            agent_is_pid1: report.agent_is_pid1.unwrap_or_default(),
            message: non_empty_string(report.message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineBootMode {
    Unspecified,
    Standard,
    AgentPid1,
    InitChild,
}

impl MachineBootMode {
    fn from_protocol(value: i32) -> Self {
        match GuestBootMode::try_from(value).unwrap_or(GuestBootMode::Unspecified) {
            GuestBootMode::Unspecified => Self::Unspecified,
            GuestBootMode::Standard => Self::Standard,
            GuestBootMode::AgentPid1 => Self::AgentPid1,
            GuestBootMode::InitChild => Self::InitChild,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Standard => "standard",
            Self::AgentPid1 => "agent-pid1",
            Self::InitChild => "init-child",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineProvisionReport {
    pub status: MachineProvisionStatus,
    pub started_unix_ms: i64,
    pub finished_unix_ms: i64,
    pub duration_ms: u64,
    pub steps: Vec<MachineProvisionStepReport>,
    pub message: Option<String>,
}

impl MachineProvisionReport {
    pub(crate) fn from_protocol(report: ProvisionReport) -> Self {
        Self {
            status: MachineProvisionStatus::from_protocol(report.status.unwrap_or_default()),
            started_unix_ms: timestamp_millis(report.started_at),
            finished_unix_ms: timestamp_millis(report.finished_at),
            duration_ms: duration_millis(report.duration),
            steps: report
                .steps
                .into_iter()
                .map(MachineProvisionStepReport::from_protocol)
                .collect(),
            message: non_empty_string(report.message),
        }
    }

    pub fn failed_step_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.status == MachineProvisionStepStatus::Failed)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineProvisionStatus {
    Unspecified,
    Succeeded,
    Degraded,
    Skipped,
    FailedBoot,
}

impl MachineProvisionStatus {
    fn from_protocol(value: i32) -> Self {
        match ProvisionOverallStatus::try_from(value).unwrap_or(ProvisionOverallStatus::Unspecified)
        {
            ProvisionOverallStatus::Unspecified => Self::Unspecified,
            ProvisionOverallStatus::Succeeded => Self::Succeeded,
            ProvisionOverallStatus::Degraded => Self::Degraded,
            ProvisionOverallStatus::Skipped => Self::Skipped,
            ProvisionOverallStatus::FailedBoot => Self::FailedBoot,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Succeeded => "succeeded",
            Self::Degraded => "degraded",
            Self::Skipped => "skipped",
            Self::FailedBoot => "failed-boot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineProvisionStepReport {
    pub id: String,
    pub status: MachineProvisionStepStatus,
    pub failure_policy: MachineProvisionFailurePolicy,
    pub changed: bool,
    pub backend: Option<String>,
    pub duration_ms: u64,
    pub message: Option<String>,
    pub error_chain: Option<String>,
}

impl MachineProvisionStepReport {
    fn from_protocol(report: ProvisionStepReport) -> Self {
        Self {
            id: report.id.unwrap_or_default(),
            status: MachineProvisionStepStatus::from_protocol(report.status.unwrap_or_default()),
            failure_policy: MachineProvisionFailurePolicy::from_protocol(
                report.failure_policy.unwrap_or_default(),
            ),
            changed: report.changed.unwrap_or_default(),
            backend: non_empty_string(report.backend),
            duration_ms: duration_millis(report.duration),
            message: non_empty_string(report.message),
            error_chain: non_empty_string(report.error_chain),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineProvisionStepStatus {
    Unspecified,
    Succeeded,
    Failed,
    Skipped,
    Unsupported,
}

impl MachineProvisionStepStatus {
    fn from_protocol(value: i32) -> Self {
        match ProvisionStepStatus::try_from(value).unwrap_or(ProvisionStepStatus::Unspecified) {
            ProvisionStepStatus::Unspecified => Self::Unspecified,
            ProvisionStepStatus::Succeeded => Self::Succeeded,
            ProvisionStepStatus::Failed => Self::Failed,
            ProvisionStepStatus::Skipped => Self::Skipped,
            ProvisionStepStatus::Unsupported => Self::Unsupported,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineProvisionFailurePolicy {
    Unspecified,
    BestEffort,
    FailBoot,
}

impl MachineProvisionFailurePolicy {
    fn from_protocol(value: i32) -> Self {
        match ProvisionFailurePolicy::try_from(value).unwrap_or(ProvisionFailurePolicy::Unspecified)
        {
            ProvisionFailurePolicy::Unspecified => Self::Unspecified,
            ProvisionFailurePolicy::BestEffort => Self::BestEffort,
            ProvisionFailurePolicy::FailBoot => Self::FailBoot,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::BestEffort => "best-effort",
            Self::FailBoot => "fail-boot",
        }
    }
}

/// Reconciled public lifecycle status for a machine.
///
/// This is not the database state enum. The private store model records durable
/// lifecycle facts such as vmmon PID and run ID; `MachineStatus` is the public
/// view after libvm reconciles those facts with vmmon liveness and, when
/// possible, vmmon's inspect RPC.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineStatus {
    /// The machine is stopped.
    Stopped,
    /// vmmon is starting and has not reached a running state yet.
    Starting {
        /// Optional human-readable status detail.
        message: Option<String>,
    },
    /// vmmon is running.
    Running {
        /// True when the machine satisfies its configured readiness policy.
        ready: bool,
        /// True when vmmon reports the guest agent as ready.
        guest_ready: bool,
        /// Optional human-readable status detail.
        message: Option<String>,
    },
    /// vmmon is stopping.
    Stopping {
        /// Optional human-readable status detail.
        message: Option<String>,
    },
    /// The machine runtime is in an error state.
    Error {
        /// Optional human-readable error detail.
        message: Option<String>,
    },
}

impl MachineStatus {
    pub(crate) fn from_machine_state(
        state: MachineRuntimeState,
        last_error: Option<String>,
    ) -> Self {
        match state {
            MachineRuntimeState::Stopped => Self::Stopped,
            MachineRuntimeState::Starting => Self::Starting { message: None },
            MachineRuntimeState::Running => Self::Running {
                ready: false,
                guest_ready: false,
                message: None,
            },
            MachineRuntimeState::Stopping => Self::Stopping { message: None },
            MachineRuntimeState::Error => Self::Error {
                message: non_empty_message(last_error),
            },
        }
    }

    pub(crate) fn from_protocol(response: HostStatus) -> Self {
        let vm = response.vm.unwrap_or_default();
        let message = non_empty_message(vm.message);
        let guest_ready = agent_reports_ready(response.agent.as_ref());
        let ready = response
            .readiness
            .and_then(|readiness| readiness.ready)
            .unwrap_or(false);

        match VmState::try_from(vm.state.unwrap_or_default()).unwrap_or(VmState::Unspecified) {
            VmState::Stopped => Self::Stopped,
            VmState::Starting => Self::Starting { message },
            VmState::Running | VmState::Unspecified => Self::Running {
                ready,
                guest_ready,
                message,
            },
            VmState::Stopping => Self::Stopping { message },
            VmState::Failed => Self::Error { message },
        }
    }

    pub(crate) fn running_with_message(message: String) -> Self {
        Self::Running {
            ready: false,
            guest_ready: false,
            message: non_empty_message(Some(message)),
        }
    }

    /// Returns true when vmmon is running.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Returns true when the machine satisfies its configured readiness policy.
    pub fn ready(&self) -> bool {
        matches!(self, Self::Running { ready: true, .. })
    }

    /// Returns true when vmmon reports the guest agent as ready.
    pub fn guest_ready(&self) -> bool {
        matches!(
            self,
            Self::Running {
                guest_ready: true,
                ..
            }
        )
    }

    /// Returns a stable lowercase label for display and filtering.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting { .. } => "starting",
            Self::Running { .. } => "running",
            Self::Stopping { .. } => "stopping",
            Self::Error { .. } => "error",
        }
    }

    /// Returns an optional human-readable status detail.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Stopped => None,
            Self::Starting { message }
            | Self::Running { message, .. }
            | Self::Stopping { message }
            | Self::Error { message } => message.as_deref(),
        }
    }
}

impl From<MachineRuntimeState> for MachineStatus {
    fn from(value: MachineRuntimeState) -> Self {
        Self::from_machine_state(value, None)
    }
}

impl From<MachineStatus> for MachineRuntimeState {
    fn from(value: MachineStatus) -> Self {
        match value {
            MachineStatus::Stopped => Self::Stopped,
            MachineStatus::Starting { .. } => Self::Starting,
            MachineStatus::Running { .. } => Self::Running,
            MachineStatus::Stopping { .. } => Self::Stopping,
            MachineStatus::Error { .. } => Self::Error,
        }
    }
}

fn non_empty_message(message: Option<String>) -> Option<String> {
    message.and_then(|message| {
        let message = message.trim().to_string();
        if message.is_empty() {
            None
        } else {
            Some(message)
        }
    })
}

fn non_empty_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| non_empty_message(Some(value)))
}

fn timestamp_millis(timestamp: Option<prost_types::Timestamp>) -> i64 {
    timestamp
        .and_then(|timestamp| {
            timestamp
                .seconds
                .checked_mul(1_000)
                .and_then(|seconds| seconds.checked_add(i64::from(timestamp.nanos) / 1_000_000))
        })
        .unwrap_or_default()
}

fn duration_millis(duration: Option<prost_types::Duration>) -> u64 {
    duration
        .and_then(|duration| {
            let seconds = u64::try_from(duration.seconds).ok()?;
            let nanos = u32::try_from(duration.nanos).ok()?;
            if nanos >= 1_000_000_000 {
                return None;
            }
            seconds
                .checked_mul(1_000)
                .and_then(|millis| millis.checked_add(u64::from(nanos / 1_000_000)))
        })
        .unwrap_or_default()
}

fn agent_reports_ready(agent: Option<&HostAgent>) -> bool {
    let Some(HostAgent {
        mode: Some(protocol::v1::host_agent::Mode::Enabled(enabled)),
    }) = agent
    else {
        return false;
    };
    enabled
        .status
        .as_ref()
        .and_then(|status| status.report.as_ref())
        .and_then(|report| report.state)
        .and_then(|state| AgentStatusState::try_from(state).ok())
        .is_some_and(|state| state == AgentStatusState::Ready)
}

#[cfg(test)]
mod tests {
    use protocol::v1::{HostStatus, Readiness, VmSnapshot, VmState};

    use crate::machine::MachineStatus;

    #[test]
    fn disabled_agent_can_be_ready_without_guest_status() {
        let status = MachineStatus::from_protocol(HostStatus {
            vm: Some(VmSnapshot {
                state: Some(VmState::Running as i32),
                message: Some("instance ready (guest agent not required)".to_string()),
                ..VmSnapshot::default()
            }),
            readiness: Some(Readiness {
                ready: Some(true),
                ..Readiness::default()
            }),
            ..HostStatus::default()
        });

        assert!(status.ready());
        assert!(!status.guest_ready());
    }
}

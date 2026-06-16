use std::collections::BTreeMap;
use std::path::PathBuf;

use bento_protocol::v1::{InspectResponse, LifecycleState};
use bento_vm_spec::VmSpec;

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
    pub instance_dir: PathBuf,
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
    /// Reconciled lifecycle status for the machine.
    ///
    /// `Machine::inspect` always reconciles persisted state with the local vmmon
    /// process first. When vmmon is running it also attempts a best-effort vmmon
    /// inspect RPC to populate guest readiness and a human-readable message. A
    /// vmmon telemetry failure does not fail the whole inspect call; it is
    /// reported here as a non-ready running status message instead.
    pub status: MachineStatus,
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
        started_at: Option<i64>,
        last_error: Option<String>,
        updated_at: i64,
    ) -> Self {
        Self {
            id: config.id.to_string(),
            name: config.name,
            spec: config.spec,
            instance_dir: config.instance_dir,
            created_at: config.created_at,
            modified_at: config.modified_at,
            image_ref: config.image_ref,
            root_disk_size: config.root_disk_size,
            labels: config.labels,
            metadata: config.metadata,
            network: config.network.into(),
            status,
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
        crate::paths::vmmon_trace_log_path_in(&self.instance_dir)
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
                guest_ready: false,
                message: None,
            },
            MachineRuntimeState::Stopping => Self::Stopping { message: None },
            MachineRuntimeState::Error => Self::Error {
                message: non_empty_message(last_error),
            },
        }
    }

    pub(crate) fn from_protocol(response: InspectResponse) -> Self {
        let message = non_empty_message(Some(response.summary));
        let guest_ready = response.ready
            && matches!(
                LifecycleState::try_from(response.guest_state)
                    .unwrap_or(LifecycleState::Unspecified),
                LifecycleState::Running
            );

        match LifecycleState::try_from(response.vm_state).unwrap_or(LifecycleState::Unspecified) {
            LifecycleState::Stopped => Self::Stopped,
            LifecycleState::Starting => Self::Starting { message },
            LifecycleState::Running | LifecycleState::Unspecified => Self::Running {
                guest_ready,
                message,
            },
            LifecycleState::Stopping => Self::Stopping { message },
            LifecycleState::Error => Self::Error { message },
        }
    }

    pub(crate) fn running_with_message(message: String) -> Self {
        Self::Running {
            guest_ready: false,
            message: non_empty_message(Some(message)),
        }
    }

    /// Returns true when vmmon is running.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Returns true when the machine is running and the guest agent is ready.
    pub fn ready(&self) -> bool {
        self.guest_ready()
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

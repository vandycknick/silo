use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vm_spec::VmSpec;

use crate::lock_manager::LockId;

use super::{MachineId, MachineNetworkConfig};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Persisted machine configuration.
///
/// This is the durable create/update-time record. It is private to the crate and
/// is mapped to public `MachineData` snapshots before leaving libvm.
pub(crate) struct MachineConfig {
    pub id: MachineId,
    pub lock_id: LockId,
    pub name: String,
    pub spec: VmSpec,
    #[serde(alias = "instanceDir")]
    pub machine_dir: PathBuf,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk_size: Option<u64>,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub network: MachineNetworkConfig,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Persisted runtime state for a machine.
///
/// This stores vmmon run facts used for reconciliation, including PID,
/// platform birth time when available, and run ID. It is not exposed directly;
/// public callers see the reconciled `MachineStatus` view.
pub(crate) struct MachineState {
    pub machine_id: MachineId,
    pub status: MachineRuntimeState,
    pub vmmon_pid: Option<i32>,
    pub started_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Durable lifecycle state stored in `MachineState`.
pub(crate) enum MachineRuntimeState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl MachineRuntimeState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Error => "error",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "stopped" => Ok(Self::Stopped),
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "stopping" => Ok(Self::Stopping),
            "error" => Ok(Self::Error),
            other => Err(format!("unknown machine runtime state {other:?}")),
        }
    }

    pub(crate) fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::MachineRuntimeState;

    #[test]
    fn machine_runtime_state_round_trips_through_storage_string() {
        for state in [
            MachineRuntimeState::Stopped,
            MachineRuntimeState::Starting,
            MachineRuntimeState::Running,
            MachineRuntimeState::Stopping,
            MachineRuntimeState::Error,
        ] {
            assert_eq!(
                MachineRuntimeState::parse(state.as_str()).expect("parse runtime state"),
                state
            );
        }
    }

    #[test]
    fn machine_runtime_state_rejects_unknown_storage_string() {
        let err = MachineRuntimeState::parse("paused").expect_err("unknown state should fail");

        assert!(err.contains("unknown machine runtime state"));
    }
}

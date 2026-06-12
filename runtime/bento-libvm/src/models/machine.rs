use std::collections::BTreeMap;
use std::path::PathBuf;

use bento_vm_spec::VmSpec;
use serde::{Deserialize, Serialize};

use super::{MachineId, RequestedNetwork};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MachineConfig {
    pub id: MachineId,
    pub name: String,
    pub spec: VmSpec,
    pub instance_dir: PathBuf,
    pub created_at: i64,
    pub modified_at: i64,
    pub image_ref: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub network: RequestedNetwork,
}

impl MachineConfig {
    pub(crate) fn trace_log_path(&self) -> PathBuf {
        crate::paths::vmmon_trace_log_path_in(&self.instance_dir)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MachineState {
    pub machine_id: MachineId,
    pub status: MachineRuntimeState,
    pub vmmon_pid: Option<i32>,
    pub started_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

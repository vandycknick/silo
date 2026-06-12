use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bento_vm_spec::VmSpec;

use crate::models::{MachineConfig, MachineRuntimeState, MachineState};
use crate::network::RequestedNetwork;

#[derive(Debug, Clone)]
pub struct MachineInspect {
    config: MachineConfig,
    state: MachineState,
}

impl MachineInspect {
    pub(crate) fn from_model(config: MachineConfig, state: MachineState) -> Self {
        Self { config, state }
    }

    pub fn id(&self) -> String {
        self.config.id.to_string()
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn spec(&self) -> &VmSpec {
        &self.config.spec
    }

    pub fn instance_dir(&self) -> &Path {
        &self.config.instance_dir
    }

    pub fn created_at(&self) -> i64 {
        self.config.created_at
    }

    pub fn modified_at(&self) -> i64 {
        self.config.modified_at
    }

    pub fn image_ref(&self) -> &str {
        &self.config.image_ref
    }

    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.config.labels
    }

    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.config.metadata
    }

    pub fn network(&self) -> RequestedNetwork {
        RequestedNetwork::from_model(&self.config.network)
    }

    pub fn status(&self) -> MachineStatus {
        self.state.status.into()
    }

    pub fn is_running(&self) -> bool {
        self.status().is_running()
    }

    pub fn vmmon_pid(&self) -> Option<i32> {
        self.state.vmmon_pid
    }

    pub fn started_at(&self) -> Option<i64> {
        self.state.started_at
    }

    pub fn last_error(&self) -> Option<&str> {
        self.state.last_error.as_deref()
    }

    pub fn updated_at(&self) -> i64 {
        self.state.updated_at
    }

    pub fn trace_log_path(&self) -> PathBuf {
        self.config.trace_log_path()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl MachineStatus {
    pub fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }
}

impl From<MachineRuntimeState> for MachineStatus {
    fn from(value: MachineRuntimeState) -> Self {
        match value {
            MachineRuntimeState::Stopped => Self::Stopped,
            MachineRuntimeState::Starting => Self::Starting,
            MachineRuntimeState::Running => Self::Running,
            MachineRuntimeState::Stopping => Self::Stopping,
            MachineRuntimeState::Error => Self::Error,
        }
    }
}

impl From<MachineStatus> for MachineRuntimeState {
    fn from(value: MachineStatus) -> Self {
        match value {
            MachineStatus::Stopped => Self::Stopped,
            MachineStatus::Starting => Self::Starting,
            MachineStatus::Running => Self::Running,
            MachineStatus::Stopping => Self::Stopping,
            MachineStatus::Error => Self::Error,
        }
    }
}

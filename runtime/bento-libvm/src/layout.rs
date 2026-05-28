use std::ffi::OsString;
use std::path::{Path, PathBuf};

use bento_core::{InstanceFile, MachineId};

use crate::LibVmError;

pub const STATE_DB_FILE_NAME: &str = "state.db";
pub const CONFIG_FILE_NAME: &str = "config.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    data_dir: PathBuf,
}

impl Layout {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    pub fn from_env() -> Result<Self, LibVmError> {
        Ok(Self::new(resolve_default_data_dir()?))
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn state_db_path(&self) -> PathBuf {
        self.data_dir.join(STATE_DB_FILE_NAME)
    }

    pub fn instances_dir(&self) -> PathBuf {
        self.data_dir.join("instances")
    }

    pub fn instance_dir(&self, machine_id: MachineId) -> PathBuf {
        self.instances_dir().join(machine_id.to_string())
    }

    pub fn instance_config_path(&self, machine_id: MachineId) -> PathBuf {
        self.instance_dir(machine_id)
            .join(InstanceFile::Config.as_str())
    }

    pub fn monitor_pid_path(&self, machine_id: MachineId) -> PathBuf {
        self.instance_dir(machine_id)
            .join(InstanceFile::VmmonPid.as_str())
    }

    pub fn monitor_socket_path(&self, machine_id: MachineId) -> PathBuf {
        self.instance_dir(machine_id)
            .join(InstanceFile::VmmonSocket.as_str())
    }

    pub fn monitor_trace_path(&self, machine_id: MachineId) -> PathBuf {
        self.instance_dir(machine_id)
            .join(InstanceFile::VmmonTraceLog.as_str())
    }

    pub fn net_dir(&self) -> PathBuf {
        self.data_dir.join("net")
    }

    pub fn network_instance_dir(&self, network_id: &str) -> PathBuf {
        self.net_dir().join(network_id)
    }

    pub fn instance_network_link(&self, machine_id: MachineId) -> PathBuf {
        self.instance_dir(machine_id).join("net")
    }

    pub fn network_runtime_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("runtime.json")
    }

    pub fn network_policy_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("policy.json")
    }

    pub fn network_audit_log_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("audit.jsonl")
    }

    pub fn network_socket_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("netd.sock")
    }

    pub fn network_log_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("netd.log")
    }

    pub fn network_pid_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("netd.pid")
    }

    pub fn network_pcap_path(&self, network_id: &str) -> PathBuf {
        self.network_instance_dir(network_id).join("capture.pcap")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.instances_dir().join(".staging")
    }

    pub fn images_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }
}

pub fn resolve_config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    home.map(|h| h.join(".config/bento"))
}

pub fn resolve_default_data_dir() -> Result<PathBuf, LibVmError> {
    let home = env_absolute_path("HOME")?;
    let data_home = env_absolute_path("XDG_DATA_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".local/share")));

    resolve_data_dir_from(data_home)
}

fn resolve_data_dir_from(data_home: Option<PathBuf>) -> Result<PathBuf, LibVmError> {
    data_home
        .map(|path| path.join("bento"))
        .ok_or(LibVmError::DataDirUnavailable)
}

fn env_absolute_path(name: &'static str) -> Result<Option<PathBuf>, LibVmError> {
    match std::env::var_os(name) {
        Some(value) => absolute_path(name, value).map(Some),
        None => Ok(None),
    }
}

fn absolute_path(name: &'static str, value: OsString) -> Result<PathBuf, LibVmError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(LibVmError::RelativeEnvironmentPath { name, path })
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_data_dir_from, Layout};
    use bento_core::{InstanceFile, MachineId};
    use std::path::PathBuf;

    #[test]
    fn layout_uses_expected_subpaths() {
        let layout = Layout::new("/tmp/bento");
        let machine_id = MachineId::new();

        assert_eq!(layout.data_dir(), PathBuf::from("/tmp/bento").as_path());
        assert_eq!(layout.state_db_path(), PathBuf::from("/tmp/bento/state.db"));
        assert_eq!(
            layout.instances_dir(),
            PathBuf::from("/tmp/bento/instances")
        );
        assert_eq!(layout.images_dir(), PathBuf::from("/tmp/bento/images"));
        assert_eq!(
            layout.instance_dir(machine_id),
            PathBuf::from("/tmp/bento/instances").join(machine_id.to_string())
        );
        assert_eq!(
            layout.staging_dir(),
            PathBuf::from("/tmp/bento/instances/.staging")
        );
        assert_eq!(
            layout.instance_config_path(machine_id),
            PathBuf::from("/tmp/bento/instances")
                .join(machine_id.to_string())
                .join(InstanceFile::Config.as_str())
        );
        assert_eq!(
            layout.monitor_pid_path(machine_id),
            PathBuf::from("/tmp/bento/instances")
                .join(machine_id.to_string())
                .join(InstanceFile::VmmonPid.as_str())
        );
        assert_eq!(
            layout.monitor_socket_path(machine_id),
            PathBuf::from("/tmp/bento/instances")
                .join(machine_id.to_string())
                .join(InstanceFile::VmmonSocket.as_str())
        );
        assert_eq!(
            layout.monitor_trace_path(machine_id),
            PathBuf::from("/tmp/bento/instances")
                .join(machine_id.to_string())
                .join(InstanceFile::VmmonTraceLog.as_str())
        );
        assert_eq!(layout.net_dir(), PathBuf::from("/tmp/bento/net"));
        let network_id = "net123";
        assert_eq!(
            layout.network_instance_dir(network_id),
            PathBuf::from("/tmp/bento/net/net123")
        );
        assert_eq!(
            layout.instance_network_link(machine_id),
            PathBuf::from("/tmp/bento/instances")
                .join(machine_id.to_string())
                .join("net")
        );
        assert_eq!(
            layout.network_runtime_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/runtime.json")
        );
        assert_eq!(
            layout.network_policy_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/policy.json")
        );
        assert_eq!(
            layout.network_audit_log_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/audit.jsonl")
        );
        assert_eq!(
            layout.network_socket_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/netd.sock")
        );
        assert_eq!(
            layout.network_log_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/netd.log")
        );
        assert_eq!(
            layout.network_pid_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/netd.pid")
        );
        assert_eq!(
            layout.network_pcap_path(network_id),
            PathBuf::from("/tmp/bento/net/net123/capture.pcap")
        );
    }

    #[test]
    fn resolve_data_dir_appends_bento_to_data_home() {
        let xdg = PathBuf::from("/tmp/xdg-data-home");
        let data_dir = resolve_data_dir_from(Some(xdg.clone())).expect("resolve data dir");

        assert_eq!(data_dir, xdg.join("bento"));
    }
}

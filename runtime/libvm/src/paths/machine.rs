use std::path::{Path, PathBuf};

use crate::store::models::MachineId;

pub(super) const MACHINES_DIR_NAME: &str = "machines";
pub(super) const LOGS_DIR_NAME: &str = "logs";
pub(super) const NETWORK_DIR_NAME: &str = "network";
const VM_SPEC_FILE_NAME: &str = "config.json";
const VMMON_PID_FILE_NAME: &str = "vm.pid";
const VMMON_SOCKET_FILE_NAME: &str = "vm.sock";
pub(super) const VMMON_TRACE_LOG_FILE_NAME: &str = "vm.trace.log";
const VMMON_EXIT_STATUS_FILE_NAME: &str = "vm.exit.json";
pub(super) const SERIAL_LOG_FILE_NAME: &str = "serial.log";
pub(super) const EXEC_LOG_FILE_NAME: &str = "exec.log";
pub(crate) const NETWORK_SERVICE_LOG_FILE_NAME: &str = "netd.log";
pub(crate) const NETWORK_AUDIT_LOG_FILE_NAME: &str = "audit.jsonl";
const ROOT_DISK_FILE_NAME: &str = "rootfs.img";
const LEGACY_METADATA_CONFIG_FILE_NAME: &str = "metadata.json";
const COMPOSITE_INITRAMFS_FILE_NAME: &str = "initramfs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachinePaths {
    data_dir: PathBuf,
    run_dir: PathBuf,
    logs_dir: PathBuf,
}

impl MachinePaths {
    pub(crate) fn new(
        data_root: &Path,
        state_root: &Path,
        run_root: &Path,
        machine_id: MachineId,
    ) -> Self {
        let id = machine_id.to_string();
        Self {
            data_dir: data_root.join(MACHINES_DIR_NAME).join(&id),
            run_dir: run_root.join(MACHINES_DIR_NAME).join(&id),
            logs_dir: state_root
                .join(LOGS_DIR_NAME)
                .join(MACHINES_DIR_NAME)
                .join(id),
        }
    }

    pub(crate) fn machine_data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub(crate) fn dir(&self) -> &Path {
        self.machine_data_dir()
    }

    pub(crate) fn machine_run_dir(&self) -> &Path {
        &self.run_dir
    }

    #[cfg(test)]
    pub(crate) fn machine_logs_dir(&self) -> &Path {
        &self.logs_dir
    }

    pub(crate) fn vm_spec_path(&self) -> PathBuf {
        vm_spec_path_in(&self.data_dir)
    }

    pub(crate) fn metadata_config_path(&self) -> PathBuf {
        self.data_dir.join(LEGACY_METADATA_CONFIG_FILE_NAME)
    }

    pub(crate) fn composite_initramfs_path(&self) -> PathBuf {
        self.data_dir.join(COMPOSITE_INITRAMFS_FILE_NAME)
    }

    pub(crate) fn vmmon_pid_path(&self) -> PathBuf {
        self.run_dir.join(VMMON_PID_FILE_NAME)
    }

    pub(crate) fn vmmon_socket_path(&self) -> PathBuf {
        self.run_dir.join(VMMON_SOCKET_FILE_NAME)
    }

    pub(crate) fn vm_trace_log_path(&self) -> PathBuf {
        self.logs_dir.join(VMMON_TRACE_LOG_FILE_NAME)
    }

    pub(crate) fn vmmon_exit_status_path(&self) -> PathBuf {
        self.logs_dir.join(VMMON_EXIT_STATUS_FILE_NAME)
    }

    pub(crate) fn serial_log_path(&self) -> PathBuf {
        self.logs_dir.join(SERIAL_LOG_FILE_NAME)
    }

    #[cfg(test)]
    pub(crate) fn exec_log_path(&self) -> PathBuf {
        self.logs_dir.join(EXEC_LOG_FILE_NAME)
    }

    #[cfg(test)]
    pub(crate) fn exec_log_archive_path(&self, generation: u8) -> PathBuf {
        self.logs_dir
            .join(format!("{EXEC_LOG_FILE_NAME}.{generation}"))
    }

    pub(crate) fn network_logs_dir(&self) -> PathBuf {
        self.logs_dir.join(NETWORK_DIR_NAME)
    }

    pub(crate) fn network_service_log_path(&self) -> PathBuf {
        self.network_logs_dir().join(NETWORK_SERVICE_LOG_FILE_NAME)
    }

    #[cfg(test)]
    pub(crate) fn network_audit_log_path(&self) -> PathBuf {
        self.network_logs_dir().join(NETWORK_AUDIT_LOG_FILE_NAME)
    }
}

pub(crate) fn root_disk_relative_path() -> PathBuf {
    PathBuf::from(ROOT_DISK_FILE_NAME)
}

pub(crate) fn vm_spec_path_in(dir: &Path) -> PathBuf {
    dir.join(VM_SPEC_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::paths::{root_disk_relative_path, MachinePaths};
    use crate::store::models::MachineId;
    use uuid::Uuid;

    #[test]
    fn machine_paths_use_expected_filenames() {
        let machine_id = MachineId::from_uuid(
            Uuid::parse_str("9a31c13b-7d4d-4e08-bcca-43edbeacf49f").expect("machine id"),
        );
        let paths = MachinePaths::new(
            PathBuf::from("/tmp/silo").as_path(),
            PathBuf::from("/tmp/silo-state").as_path(),
            PathBuf::from("/tmp/silo-run").as_path(),
            machine_id,
        );
        let id = machine_id.to_string();

        assert_eq!(
            paths.vm_spec_path(),
            PathBuf::from("/tmp/silo/machines")
                .join(&id)
                .join("config.json")
        );
        assert_eq!(
            paths.metadata_config_path(),
            PathBuf::from("/tmp/silo/machines")
                .join(&id)
                .join("metadata.json")
        );
        assert_eq!(
            paths.composite_initramfs_path(),
            PathBuf::from("/tmp/silo/machines")
                .join(&id)
                .join("initramfs")
        );
        assert_eq!(
            paths.vmmon_pid_path(),
            PathBuf::from("/tmp/silo-run/machines")
                .join(&id)
                .join("vm.pid")
        );
        assert_eq!(
            paths.vmmon_socket_path(),
            PathBuf::from("/tmp/silo-run/machines")
                .join(&id)
                .join("vm.sock")
        );
        assert_eq!(
            paths.vm_trace_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("vm.trace.log")
        );
        assert_eq!(
            paths.vmmon_exit_status_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("vm.exit.json")
        );
        assert_eq!(
            paths.serial_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("serial.log")
        );
        assert_eq!(
            paths.exec_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("exec.log")
        );
        assert_eq!(
            paths.exec_log_archive_path(3),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("exec.log.3")
        );
        assert_eq!(
            paths.network_service_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("network/netd.log")
        );
        assert_eq!(
            paths.network_audit_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(&id)
                .join("network/audit.jsonl")
        );
        assert_eq!(root_disk_relative_path(), PathBuf::from("rootfs.img"));
    }
}

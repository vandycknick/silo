use std::path::{Path, PathBuf};

const VM_SPEC_FILE_NAME: &str = "config.json";
const VMMON_PID_FILE_NAME: &str = "vm.pid";
const VMMON_SOCKET_FILE_NAME: &str = "vm.sock";
const VMMON_TRACE_LOG_FILE_NAME: &str = "vm.trace.log";
const VMMON_EXIT_STATUS_FILE_NAME: &str = "vm.exit.json";
const SERIAL_LOG_FILE_NAME: &str = "serial.log";
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
        data_dir: impl Into<PathBuf>,
        run_dir: impl Into<PathBuf>,
        logs_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            run_dir: run_dir.into(),
            logs_dir: logs_dir.into(),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.data_dir
    }

    pub(crate) fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub(crate) fn logs_dir(&self) -> &Path {
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

    pub(crate) fn vmmon_trace_log_path(&self) -> PathBuf {
        vmmon_trace_log_path_in(&self.logs_dir)
    }

    pub(crate) fn vmmon_exit_status_path(&self) -> PathBuf {
        self.logs_dir.join(VMMON_EXIT_STATUS_FILE_NAME)
    }

    pub(crate) fn serial_log_path(&self) -> PathBuf {
        self.logs_dir.join(SERIAL_LOG_FILE_NAME)
    }
}

pub(crate) fn root_disk_relative_path() -> PathBuf {
    PathBuf::from(ROOT_DISK_FILE_NAME)
}

pub(crate) fn vm_spec_path_in(dir: &Path) -> PathBuf {
    dir.join(VM_SPEC_FILE_NAME)
}

pub(crate) fn vmmon_trace_log_path_in(dir: &Path) -> PathBuf {
    dir.join(VMMON_TRACE_LOG_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::paths::{root_disk_relative_path, MachinePaths};

    #[test]
    fn machine_paths_use_expected_filenames() {
        let paths = MachinePaths::new(
            "/tmp/silo/machines/test",
            "/tmp/silo-run/machines/test",
            "/tmp/silo-state/logs/machines/test",
        );

        assert_eq!(
            paths.vm_spec_path(),
            PathBuf::from("/tmp/silo/machines/test/config.json")
        );
        assert_eq!(
            paths.metadata_config_path(),
            PathBuf::from("/tmp/silo/machines/test/metadata.json")
        );
        assert_eq!(
            paths.composite_initramfs_path(),
            PathBuf::from("/tmp/silo/machines/test/initramfs")
        );
        assert_eq!(
            paths.vmmon_pid_path(),
            PathBuf::from("/tmp/silo-run/machines/test/vm.pid")
        );
        assert_eq!(
            paths.vmmon_socket_path(),
            PathBuf::from("/tmp/silo-run/machines/test/vm.sock")
        );
        assert_eq!(
            paths.vmmon_trace_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines/test/vm.trace.log")
        );
        assert_eq!(
            paths.vmmon_exit_status_path(),
            PathBuf::from("/tmp/silo-state/logs/machines/test/vm.exit.json")
        );
        assert_eq!(
            paths.serial_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines/test/serial.log")
        );
        assert_eq!(root_disk_relative_path(), PathBuf::from("rootfs.img"));
    }
}

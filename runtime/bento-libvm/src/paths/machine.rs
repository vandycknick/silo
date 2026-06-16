use std::path::{Path, PathBuf};

const VM_SPEC_FILE_NAME: &str = "config.json";
const VMMON_PID_FILE_NAME: &str = "vm.pid";
const VMMON_SOCKET_FILE_NAME: &str = "vm.sock";
const VMMON_TRACE_LOG_FILE_NAME: &str = "vm.trace.log";
const VMMON_EXIT_STATUS_FILE_NAME: &str = "vm.exit.json";
const SERIAL_LOG_FILE_NAME: &str = "serial.log";
const ROOT_DISK_FILE_NAME: &str = "rootfs.img";
const METADATA_CONFIG_FILE_NAME: &str = "metadata.json";
const NETWORK_LINK_NAME: &str = "net";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachinePaths {
    dir: PathBuf,
}

impl MachinePaths {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn vm_spec_path(&self) -> PathBuf {
        vm_spec_path_in(&self.dir)
    }

    pub(crate) fn metadata_config_path(&self) -> PathBuf {
        metadata_config_path_in(&self.dir)
    }

    pub(crate) fn root_disk_path(&self) -> PathBuf {
        self.dir.join(ROOT_DISK_FILE_NAME)
    }

    pub(crate) fn vmmon_pid_path(&self) -> PathBuf {
        self.dir.join(VMMON_PID_FILE_NAME)
    }

    pub(crate) fn vmmon_socket_path(&self) -> PathBuf {
        self.dir.join(VMMON_SOCKET_FILE_NAME)
    }

    pub(crate) fn vmmon_trace_log_path(&self) -> PathBuf {
        vmmon_trace_log_path_in(&self.dir)
    }

    pub(crate) fn vmmon_exit_status_path(&self) -> PathBuf {
        self.dir.join(VMMON_EXIT_STATUS_FILE_NAME)
    }

    pub(crate) fn serial_log_path(&self) -> PathBuf {
        self.dir.join(SERIAL_LOG_FILE_NAME)
    }

    pub(crate) fn network_link(&self) -> PathBuf {
        self.dir.join(NETWORK_LINK_NAME)
    }
}

pub(crate) fn root_disk_relative_path() -> PathBuf {
    PathBuf::from(ROOT_DISK_FILE_NAME)
}

pub(crate) fn vm_spec_path_in(dir: &Path) -> PathBuf {
    dir.join(VM_SPEC_FILE_NAME)
}

pub(crate) fn metadata_config_path_in(dir: &Path) -> PathBuf {
    dir.join(METADATA_CONFIG_FILE_NAME)
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
        let paths = MachinePaths::new("/tmp/bento/machines/test");

        assert_eq!(
            paths.vm_spec_path(),
            PathBuf::from("/tmp/bento/machines/test/config.json")
        );
        assert_eq!(
            paths.metadata_config_path(),
            PathBuf::from("/tmp/bento/machines/test/metadata.json")
        );
        assert_eq!(
            paths.root_disk_path(),
            PathBuf::from("/tmp/bento/machines/test/rootfs.img")
        );
        assert_eq!(
            paths.vmmon_pid_path(),
            PathBuf::from("/tmp/bento/machines/test/vm.pid")
        );
        assert_eq!(
            paths.vmmon_socket_path(),
            PathBuf::from("/tmp/bento/machines/test/vm.sock")
        );
        assert_eq!(
            paths.vmmon_trace_log_path(),
            PathBuf::from("/tmp/bento/machines/test/vm.trace.log")
        );
        assert_eq!(
            paths.vmmon_exit_status_path(),
            PathBuf::from("/tmp/bento/machines/test/vm.exit.json")
        );
        assert_eq!(
            paths.serial_log_path(),
            PathBuf::from("/tmp/bento/machines/test/serial.log")
        );
        assert_eq!(
            paths.network_link(),
            PathBuf::from("/tmp/bento/machines/test/net")
        );
        assert_eq!(root_disk_relative_path(), PathBuf::from("rootfs.img"));
    }
}

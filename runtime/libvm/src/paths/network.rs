use std::path::{Path, PathBuf};

const SOCKET_FILE_NAME: &str = "netd.sock";
const LOG_FILE_NAME: &str = "netd.log";
const PID_FILE_NAME: &str = "netd.pid";
const PCAP_FILE_NAME: &str = "capture.pcap";
const POLICY_FILE_NAME: &str = "network-policy.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkPaths {
    run_dir: PathBuf,
    logs_dir: PathBuf,
}

impl NetworkPaths {
    pub(crate) fn new(run_dir: impl Into<PathBuf>, logs_dir: impl Into<PathBuf>) -> Self {
        Self {
            run_dir: run_dir.into(),
            logs_dir: logs_dir.into(),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.run_dir
    }

    pub(crate) fn logs_dir(&self) -> &Path {
        &self.logs_dir
    }

    pub(crate) fn socket_path(&self) -> PathBuf {
        self.run_dir.join(SOCKET_FILE_NAME)
    }

    pub(crate) fn log_path(&self) -> PathBuf {
        self.logs_dir.join(LOG_FILE_NAME)
    }

    pub(crate) fn pid_path(&self) -> PathBuf {
        self.run_dir.join(PID_FILE_NAME)
    }

    pub(crate) fn pcap_path(&self) -> PathBuf {
        self.run_dir.join(PCAP_FILE_NAME)
    }

    pub(crate) fn policy_path(&self) -> PathBuf {
        self.run_dir.join(POLICY_FILE_NAME)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::paths::network::NetworkPaths;

    #[test]
    fn network_paths_use_expected_filenames() {
        let paths = NetworkPaths::new(
            "/tmp/silo-run/networks/net123",
            "/tmp/silo-state/logs/networks/net123",
        );

        assert_eq!(
            paths.socket_path(),
            PathBuf::from("/tmp/silo-run/networks/net123/netd.sock")
        );
        assert_eq!(
            paths.log_path(),
            PathBuf::from("/tmp/silo-state/logs/networks/net123/netd.log")
        );
        assert_eq!(
            paths.pid_path(),
            PathBuf::from("/tmp/silo-run/networks/net123/netd.pid")
        );
        assert_eq!(
            paths.pcap_path(),
            PathBuf::from("/tmp/silo-run/networks/net123/capture.pcap")
        );
        assert_eq!(
            paths.policy_path(),
            PathBuf::from("/tmp/silo-run/networks/net123/network-policy.json")
        );
    }
}

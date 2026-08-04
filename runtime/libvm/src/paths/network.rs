use std::path::{Component, Path, PathBuf};

pub(super) const NETWORKS_DIR_NAME: &str = "networks";
const SOCKET_FILE_NAME: &str = "netd.sock";
pub(crate) const PID_FILE_NAME: &str = "netd.pid";
pub(crate) const PCAP_FILE_NAME: &str = "capture.pcap";
const POLICY_FILE_NAME: &str = "network-policy.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkPaths {
    run_dir: PathBuf,
}

impl NetworkPaths {
    pub(crate) fn new(run_root: &Path, network_id: &str) -> Result<Self, String> {
        let mut components = Path::new(network_id).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(format!(
                "network instance id {network_id:?} is not a single path component"
            ));
        }

        Ok(Self {
            run_dir: run_root.join(NETWORKS_DIR_NAME).join(network_id),
        })
    }

    pub(crate) fn runtime_dir(&self) -> &Path {
        &self.run_dir
    }

    pub(crate) fn socket_path(&self) -> PathBuf {
        self.run_dir.join(SOCKET_FILE_NAME)
    }

    #[cfg(test)]
    pub(crate) fn pid_path(&self) -> PathBuf {
        self.run_dir.join(PID_FILE_NAME)
    }

    #[cfg(test)]
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
        let paths = NetworkPaths::new(PathBuf::from("/tmp/silo-run").as_path(), "net123")
            .expect("network paths");

        assert_eq!(
            paths.socket_path(),
            PathBuf::from("/tmp/silo-run/networks/net123/netd.sock")
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

    #[test]
    fn network_paths_reject_non_component_ids() {
        for id in ["", ".", "..", "nested/id", "/absolute"] {
            assert!(
                NetworkPaths::new(PathBuf::from("/tmp/silo-run").as_path(), id).is_err(),
                "network id {id:?} should be rejected"
            );
        }
    }
}

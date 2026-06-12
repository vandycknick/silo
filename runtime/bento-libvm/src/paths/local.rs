use std::path::{Path, PathBuf};

use crate::paths::defaults::resolve_default_data_dir;
use crate::paths::machine::MachinePaths;
use crate::paths::network::NetworkPaths;
use crate::{LibVmError, MachineId};

const STATE_DB_FILE_NAME: &str = "state.db";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRoots {
    data_dir: PathBuf,
    state_db_path: PathBuf,
    instances_dir: PathBuf,
    images_dir: PathBuf,
    net_dir: PathBuf,
}

impl LocalRoots {
    pub(crate) fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            state_db_path: data_dir.join(STATE_DB_FILE_NAME),
            instances_dir: data_dir.join("instances"),
            images_dir: data_dir.join("images"),
            net_dir: data_dir.join("net"),
            data_dir,
        }
    }

    pub(crate) fn from_parts(
        data_dir: impl Into<PathBuf>,
        state_db_path: impl Into<PathBuf>,
        instances_dir: impl Into<PathBuf>,
        images_dir: impl Into<PathBuf>,
        net_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            state_db_path: state_db_path.into(),
            instances_dir: instances_dir.into(),
            images_dir: images_dir.into(),
            net_dir: net_dir.into(),
        }
    }

    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub(crate) fn state_db_path(&self) -> &Path {
        &self.state_db_path
    }

    pub(crate) fn instances_dir(&self) -> &Path {
        &self.instances_dir
    }

    pub(crate) fn images_dir(&self) -> &Path {
        &self.images_dir
    }

    pub(crate) fn net_dir(&self) -> &Path {
        &self.net_dir
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalPaths {
    roots: LocalRoots,
}

impl LocalPaths {
    pub(crate) fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self::from_roots(LocalRoots::new(data_dir))
    }

    pub(crate) fn from_env() -> Result<Self, LibVmError> {
        Ok(Self::new(resolve_default_data_dir()?))
    }

    pub(crate) fn from_roots(roots: LocalRoots) -> Self {
        Self { roots }
    }

    pub(crate) fn roots(&self) -> &LocalRoots {
        &self.roots
    }

    pub(crate) fn data_dir(&self) -> &Path {
        self.roots.data_dir()
    }

    pub(crate) fn state_db_path(&self) -> &Path {
        self.roots.state_db_path()
    }

    pub(crate) fn instances_dir(&self) -> &Path {
        self.roots.instances_dir()
    }

    pub(crate) fn images_dir(&self) -> &Path {
        self.roots.images_dir()
    }

    pub(crate) fn net_dir(&self) -> &Path {
        self.roots.net_dir()
    }

    pub(crate) fn machine(&self, machine_id: MachineId) -> MachinePaths {
        MachinePaths::new(self.instances_dir().join(machine_id.to_string()))
    }

    pub(crate) fn network(&self, network_id: &str) -> NetworkPaths {
        NetworkPaths::new(self.net_dir().join(network_id))
    }

    pub(crate) fn staging_dir(&self) -> PathBuf {
        self.instances_dir().join(".staging")
    }

    pub(crate) fn assets_dir(&self) -> PathBuf {
        self.data_dir().join("assets")
    }

    pub(crate) fn keys_dir(&self) -> PathBuf {
        self.data_dir().join("keys")
    }

    pub(crate) fn secret_store_path(&self) -> PathBuf {
        self.data_dir().join("secrets.json")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{LocalPaths, LocalRoots};
    use crate::MachineId;

    #[test]
    fn local_roots_derive_expected_subpaths() {
        let roots = LocalRoots::new("/tmp/bento");

        assert_eq!(roots.data_dir(), PathBuf::from("/tmp/bento").as_path());
        assert_eq!(roots.state_db_path(), PathBuf::from("/tmp/bento/state.db"));
        assert_eq!(roots.instances_dir(), PathBuf::from("/tmp/bento/instances"));
        assert_eq!(roots.images_dir(), PathBuf::from("/tmp/bento/images"));
        assert_eq!(roots.net_dir(), PathBuf::from("/tmp/bento/net"));
    }

    #[test]
    fn local_paths_build_machine_and_network_paths() {
        let paths = LocalPaths::new("/tmp/bento");
        let machine_id = MachineId::new();
        let machine = paths.machine(machine_id);
        let network = paths.network("net123");

        assert_eq!(
            paths.staging_dir(),
            PathBuf::from("/tmp/bento/instances/.staging")
        );
        assert_eq!(paths.assets_dir(), PathBuf::from("/tmp/bento/assets"));
        assert_eq!(paths.keys_dir(), PathBuf::from("/tmp/bento/keys"));
        assert_eq!(
            paths.secret_store_path(),
            PathBuf::from("/tmp/bento/secrets.json")
        );
        assert_eq!(
            machine.dir(),
            PathBuf::from("/tmp/bento/instances").join(machine_id.to_string())
        );
        assert_eq!(network.dir(), PathBuf::from("/tmp/bento/net/net123"));
    }
}

use std::path::{Path, PathBuf};

use crate::paths::defaults::{resolve_default_data_dir, resolve_default_run_dir};
use crate::paths::machine::MachinePaths;
use crate::paths::network::NetworkPaths;
use crate::store::models::MachineId;
use crate::LibVmError;

const STATE_DB_FILE_NAME: &str = "state.db";
const MACHINES_DIR_NAME: &str = "machines";
const IMAGES_DIR_NAME: &str = "images";
const NET_DIR_NAME: &str = "net";
const LOCKS_DIR_NAME: &str = "locks";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRoots {
    data_root: PathBuf,
    run_root: PathBuf,
    image_root: PathBuf,
}

impl LocalRoots {
    #[cfg(test)]
    pub(crate) fn new(data_root: impl Into<PathBuf>) -> Self {
        let data_root = data_root.into();
        let run_root = data_root.join("run");
        let image_root = data_root.join(IMAGES_DIR_NAME);
        Self::with_roots(data_root, run_root, image_root)
    }

    pub(crate) fn with_roots(
        data_root: impl Into<PathBuf>,
        run_root: impl Into<PathBuf>,
        image_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            data_root: data_root.into(),
            run_root: run_root.into(),
            image_root: image_root.into(),
        }
    }

    pub(crate) fn from_env() -> Result<Self, LibVmError> {
        let data_root = resolve_default_data_dir()?;
        let run_root = resolve_default_run_dir(&data_root)?;
        let image_root = data_root.join(IMAGES_DIR_NAME);
        Ok(Self::with_roots(data_root, run_root, image_root))
    }

    pub(crate) fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub(crate) fn data_dir(&self) -> &Path {
        self.data_root()
    }

    pub(crate) fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub(crate) fn image_root(&self) -> &Path {
        &self.image_root
    }

    pub(crate) fn state_db_path(&self) -> PathBuf {
        self.data_root.join(STATE_DB_FILE_NAME)
    }

    pub(crate) fn machines_dir(&self) -> PathBuf {
        self.data_root.join(MACHINES_DIR_NAME)
    }

    pub(crate) fn images_dir(&self) -> PathBuf {
        self.image_root().to_path_buf()
    }

    pub(crate) fn net_dir(&self) -> PathBuf {
        self.run_root().join(NET_DIR_NAME)
    }

    pub(crate) fn locks_dir(&self) -> PathBuf {
        self.run_root().join(LOCKS_DIR_NAME)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalPaths {
    roots: LocalRoots,
    state_db_path: PathBuf,
    machines_dir: PathBuf,
    images_dir: PathBuf,
    net_dir: PathBuf,
    locks_dir: PathBuf,
}

impl LocalPaths {
    #[cfg(test)]
    pub(crate) fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self::from_roots(LocalRoots::new(data_dir))
    }

    pub(crate) fn from_env() -> Result<Self, LibVmError> {
        Ok(Self::from_roots(LocalRoots::from_env()?))
    }

    pub(crate) fn from_roots(roots: LocalRoots) -> Self {
        let state_db_path = roots.state_db_path();
        let machines_dir = roots.machines_dir();
        let images_dir = roots.images_dir();
        let net_dir = roots.net_dir();
        let locks_dir = roots.locks_dir();

        Self {
            roots,
            state_db_path,
            machines_dir,
            images_dir,
            net_dir,
            locks_dir,
        }
    }

    #[cfg(test)]
    pub(crate) fn roots(&self) -> &LocalRoots {
        &self.roots
    }

    pub(crate) fn data_dir(&self) -> &Path {
        self.roots.data_dir()
    }

    pub(crate) fn state_db_path(&self) -> &Path {
        &self.state_db_path
    }

    pub(crate) fn machines_dir(&self) -> &Path {
        &self.machines_dir
    }

    pub(crate) fn images_dir(&self) -> &Path {
        &self.images_dir
    }

    pub(crate) fn net_dir(&self) -> &Path {
        &self.net_dir
    }

    pub(crate) fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub(crate) fn machine(&self, machine_id: MachineId) -> MachinePaths {
        MachinePaths::new(self.machines_dir().join(machine_id.to_string()))
    }

    pub(crate) fn network(&self, network_id: &str) -> NetworkPaths {
        NetworkPaths::new(self.net_dir().join(network_id))
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

    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::MachineId;

    #[test]
    fn local_roots_derive_expected_subpaths() {
        let roots = LocalRoots::new("/tmp/bento");

        assert_eq!(roots.data_dir(), PathBuf::from("/tmp/bento").as_path());
        assert_eq!(roots.data_root(), PathBuf::from("/tmp/bento").as_path());
        assert_eq!(roots.run_root(), PathBuf::from("/tmp/bento/run").as_path());
        assert_eq!(
            roots.image_root(),
            PathBuf::from("/tmp/bento/images").as_path()
        );
        assert_eq!(roots.state_db_path(), PathBuf::from("/tmp/bento/state.db"));
        assert_eq!(roots.machines_dir(), PathBuf::from("/tmp/bento/machines"));
        assert_eq!(roots.images_dir(), PathBuf::from("/tmp/bento/images"));
        assert_eq!(roots.net_dir(), PathBuf::from("/tmp/bento/run/net"));
        assert_eq!(roots.locks_dir(), PathBuf::from("/tmp/bento/run/locks"));
    }

    #[test]
    fn local_roots_use_explicit_run_and_image_roots() {
        let roots =
            LocalRoots::with_roots("/tmp/bento", "/run/user/501/bento", "/var/lib/bento/images");

        assert_eq!(roots.data_dir(), PathBuf::from("/tmp/bento").as_path());
        assert_eq!(
            roots.run_root(),
            PathBuf::from("/run/user/501/bento").as_path()
        );
        assert_eq!(
            roots.image_root(),
            PathBuf::from("/var/lib/bento/images").as_path()
        );
        assert_eq!(roots.state_db_path(), PathBuf::from("/tmp/bento/state.db"));
        assert_eq!(roots.machines_dir(), PathBuf::from("/tmp/bento/machines"));
        assert_eq!(roots.images_dir(), PathBuf::from("/var/lib/bento/images"));
        assert_eq!(roots.net_dir(), PathBuf::from("/run/user/501/bento/net"));
        assert_eq!(
            roots.locks_dir(),
            PathBuf::from("/run/user/501/bento/locks")
        );
    }

    #[test]
    fn local_paths_build_machine_and_network_paths() {
        let paths = LocalPaths::new("/tmp/bento");
        let machine_id = MachineId::new();
        let machine = paths.machine(machine_id);
        let network = paths.network("net123");

        assert_eq!(paths.assets_dir(), PathBuf::from("/tmp/bento/assets"));
        assert_eq!(paths.keys_dir(), PathBuf::from("/tmp/bento/keys"));
        assert_eq!(
            paths.secret_store_path(),
            PathBuf::from("/tmp/bento/secrets.json")
        );
        assert_eq!(
            machine.dir(),
            PathBuf::from("/tmp/bento/machines").join(machine_id.to_string())
        );
        assert_eq!(paths.locks_dir(), PathBuf::from("/tmp/bento/run/locks"));
        assert_eq!(network.dir(), PathBuf::from("/tmp/bento/run/net/net123"));
    }
}

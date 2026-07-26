use std::path::{Path, PathBuf};

use crate::paths::defaults::{
    ensure_run_root, resolve_default_data_dir, resolve_default_run_dir, resolve_default_state_dir,
};
use crate::paths::machine::MachinePaths;
use crate::paths::network::NetworkPaths;
use crate::store::models::MachineId;
use crate::LibVmError;

const STATE_DB_FILE_NAME: &str = "state.db";
const MACHINES_DIR_NAME: &str = "machines";
const IMAGES_DIR_NAME: &str = "images";
const NETWORKS_DIR_NAME: &str = "networks";
const LOCKS_DIR_NAME: &str = "locks";
const LOGS_DIR_NAME: &str = "logs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRoots {
    data_root: PathBuf,
    state_root: PathBuf,
    run_root: PathBuf,
    image_root: PathBuf,
}

impl LocalRoots {
    #[cfg(test)]
    pub(crate) fn new(data_root: impl Into<PathBuf>) -> Self {
        let data_root = data_root.into();
        let state_root = sibling_test_root(&data_root, "state");
        let run_root = sibling_test_root(&data_root, "run");
        let image_root = data_root.join(IMAGES_DIR_NAME);
        Self::with_roots(data_root, state_root, run_root, image_root)
    }

    pub(crate) fn with_roots(
        data_root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        run_root: impl Into<PathBuf>,
        image_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            data_root: data_root.into(),
            state_root: state_root.into(),
            run_root: run_root.into(),
            image_root: image_root.into(),
        }
    }

    pub(crate) fn from_env() -> Result<Self, LibVmError> {
        let data_root = resolve_default_data_dir()?;
        let state_root = resolve_default_state_dir()?;
        let run_root = resolve_default_run_dir()?;
        ensure_run_root(&run_root)?;
        let image_root = data_root.join(IMAGES_DIR_NAME);
        Ok(Self::with_roots(
            data_root, state_root, run_root, image_root,
        ))
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

    pub(crate) fn state_root(&self) -> &Path {
        &self.state_root
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
        self.run_root().join(NETWORKS_DIR_NAME)
    }

    pub(crate) fn locks_dir(&self) -> PathBuf {
        self.run_root().join(LOCKS_DIR_NAME)
    }
}

#[cfg(test)]
fn sibling_test_root(data_root: &Path, kind: &str) -> PathBuf {
    let parent = data_root.parent().unwrap_or_else(|| Path::new("/tmp"));
    let name = data_root
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("silo"));
    parent.join(format!("{}-{kind}", name.to_string_lossy()))
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
        let id = machine_id.to_string();
        MachinePaths::new(
            self.machines_dir().join(&id),
            self.roots.run_root().join(MACHINES_DIR_NAME).join(&id),
            self.roots
                .state_root()
                .join(LOGS_DIR_NAME)
                .join(MACHINES_DIR_NAME)
                .join(id),
        )
    }

    pub(crate) fn network(&self, network_id: &str) -> NetworkPaths {
        NetworkPaths::new(
            self.net_dir().join(network_id),
            self.roots
                .state_root()
                .join(LOGS_DIR_NAME)
                .join(NETWORKS_DIR_NAME)
                .join(network_id),
        )
    }

    pub(crate) fn keys_dir(&self) -> PathBuf {
        self.data_dir().join("keys")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::paths::{LocalPaths, LocalRoots};
    use crate::store::models::MachineId;

    #[test]
    fn local_roots_derive_expected_subpaths() {
        let roots = LocalRoots::new("/tmp/silo");

        assert_eq!(roots.data_dir(), PathBuf::from("/tmp/silo").as_path());
        assert_eq!(roots.data_root(), PathBuf::from("/tmp/silo").as_path());
        assert_eq!(roots.run_root(), PathBuf::from("/tmp/silo-run").as_path());
        assert_eq!(
            roots.state_root(),
            PathBuf::from("/tmp/silo-state").as_path()
        );
        assert_eq!(
            roots.image_root(),
            PathBuf::from("/tmp/silo/images").as_path()
        );
        assert_eq!(roots.state_db_path(), PathBuf::from("/tmp/silo/state.db"));
        assert_eq!(roots.machines_dir(), PathBuf::from("/tmp/silo/machines"));
        assert_eq!(roots.images_dir(), PathBuf::from("/tmp/silo/images"));
        assert_eq!(roots.net_dir(), PathBuf::from("/tmp/silo-run/networks"));
        assert_eq!(roots.locks_dir(), PathBuf::from("/tmp/silo-run/locks"));
    }

    #[test]
    fn local_roots_use_explicit_run_and_image_roots() {
        let roots = LocalRoots::with_roots(
            "/tmp/silo",
            "/var/lib/silo/state",
            "/run/user/501/silo",
            "/var/lib/silo/images",
        );

        assert_eq!(roots.data_dir(), PathBuf::from("/tmp/silo").as_path());
        assert_eq!(
            roots.state_root(),
            PathBuf::from("/var/lib/silo/state").as_path()
        );
        assert_eq!(
            roots.run_root(),
            PathBuf::from("/run/user/501/silo").as_path()
        );
        assert_eq!(
            roots.image_root(),
            PathBuf::from("/var/lib/silo/images").as_path()
        );
        assert_eq!(roots.state_db_path(), PathBuf::from("/tmp/silo/state.db"));
        assert_eq!(roots.machines_dir(), PathBuf::from("/tmp/silo/machines"));
        assert_eq!(roots.images_dir(), PathBuf::from("/var/lib/silo/images"));
        assert_eq!(
            roots.net_dir(),
            PathBuf::from("/run/user/501/silo/networks")
        );
        assert_eq!(roots.locks_dir(), PathBuf::from("/run/user/501/silo/locks"));
    }

    #[test]
    fn local_paths_build_machine_and_network_paths() {
        let paths = LocalPaths::new("/tmp/silo");
        let machine_id = MachineId::new();
        let machine = paths.machine(machine_id);
        let network = paths.network("net123");

        assert_eq!(paths.keys_dir(), PathBuf::from("/tmp/silo/keys"));
        assert_eq!(
            machine.dir(),
            PathBuf::from("/tmp/silo/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.run_dir(),
            PathBuf::from("/tmp/silo-run/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.logs_dir(),
            PathBuf::from("/tmp/silo-state/logs/machines").join(machine_id.to_string())
        );
        assert_eq!(paths.locks_dir(), PathBuf::from("/tmp/silo-run/locks"));
        assert_eq!(
            network.dir(),
            PathBuf::from("/tmp/silo-run/networks/net123")
        );
        assert_eq!(
            network.logs_dir(),
            PathBuf::from("/tmp/silo-state/logs/networks/net123")
        );
    }

    #[test]
    fn default_socket_paths_fit_unix_socket_limits() {
        let uid = nix::unistd::geteuid().as_raw();
        let roots = LocalRoots::with_roots(
            format!("/tmp/silo-data-{uid}"),
            format!("/tmp/silo-state-{uid}"),
            format!("/tmp/silo-{uid}"),
            format!("/tmp/silo-images-{uid}"),
        );
        let paths = LocalPaths::from_roots(roots);
        let machine_socket = paths.machine(MachineId::new()).vmmon_socket_path();
        let network_socket = paths.network(&MachineId::new().to_string()).socket_path();

        assert!(machine_socket.as_os_str().len() < 104);
        assert!(network_socket.as_os_str().len() < 104);
    }
}

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::paths::defaults::{
    ensure_run_root, resolve_default_data_dir, resolve_default_run_dir, resolve_default_state_dir,
};
use crate::paths::machine::{
    MachinePaths, EXEC_LOG_FILE_NAME, LOGS_DIR_NAME, MACHINES_DIR_NAME,
    NETWORK_AUDIT_LOG_FILE_NAME, NETWORK_DIR_NAME, NETWORK_SERVICE_LOG_FILE_NAME,
    SERIAL_LOG_FILE_NAME, VMMON_TRACE_LOG_FILE_NAME,
};
use crate::paths::network::{NetworkPaths, NETWORKS_DIR_NAME};
use crate::paths::OwnedDirectory;
use crate::store::models::MachineId;
use crate::LibVmError;

const STATE_DB_FILE_NAME: &str = "state.db";
const IMAGES_DIR_NAME: &str = "images";
const LOCKS_DIR_NAME: &str = "locks";

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

    #[cfg(test)]
    pub(crate) fn machines_dir(&self) -> PathBuf {
        self.data_root.join(MACHINES_DIR_NAME)
    }

    pub(crate) fn images_dir(&self) -> PathBuf {
        self.image_root().to_path_buf()
    }

    #[cfg(test)]
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
    images_dir: PathBuf,
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
        let images_dir = roots.images_dir();
        let locks_dir = roots.locks_dir();

        Self {
            roots,
            state_db_path,
            images_dir,
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

    pub(crate) fn images_dir(&self) -> &Path {
        &self.images_dir
    }

    pub(crate) fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub(crate) fn machine(&self, machine_id: MachineId) -> MachinePaths {
        MachinePaths::new(
            self.roots.data_root(),
            self.roots.state_root(),
            self.roots.run_root(),
            machine_id,
        )
    }

    pub(crate) fn network(&self, network_id: &str) -> Result<NetworkPaths, LibVmError> {
        NetworkPaths::new(self.roots.run_root(), network_id).map_err(|message| {
            LibVmError::StateDecode {
                field: "network_instance_id",
                message,
            }
        })
    }

    pub(crate) fn ensure_machine_run_dir(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        let root = OwnedDirectory::open_root(self.roots.run_root())?;
        root.ensure_dir(MACHINES_DIR_NAME)?
            .ensure_dir(&machine_id.to_string())?;
        Ok(())
    }

    /// Creates a machine data directory and returns its validated containing directory.
    pub(crate) fn create_machine_data_dir(
        &self,
        machine_id: MachineId,
    ) -> Result<OwnedDirectory, LibVmError> {
        let root = OwnedDirectory::open_root(self.roots.data_root())?;
        let machines = root.ensure_dir(MACHINES_DIR_NAME)?;
        if machines.create_dir(&machine_id.to_string())?.is_none() {
            return Err(LibVmError::MachineIdAlreadyExists {
                id: machine_id.to_string(),
            });
        }
        Ok(machines)
    }

    pub(crate) fn ensure_machine_logs_dir(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        self.machine_logs_tree(machine_id)?;
        Ok(())
    }

    pub(crate) fn machine_logs_directory(
        &self,
        machine_id: MachineId,
    ) -> Result<OwnedDirectory, LibVmError> {
        self.machine_logs_tree(machine_id)
    }

    pub(crate) fn ensure_machine_network_logs_dir(
        &self,
        machine_id: MachineId,
    ) -> Result<OwnedDirectory, LibVmError> {
        self.machine_logs_tree(machine_id)?
            .ensure_dir(NETWORK_DIR_NAME)
    }

    pub(crate) fn ensure_network_run_dir(
        &self,
        network_id: &str,
    ) -> Result<OwnedDirectory, LibVmError> {
        let network = self.network(network_id)?;
        let name = network
            .runtime_dir()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| LibVmError::StateDecode {
                field: "network_instance_id",
                message: format!("network instance id {network_id:?} is not valid UTF-8"),
            })?;
        let root = OwnedDirectory::open_root(self.roots.run_root())?;
        root.ensure_dir(NETWORKS_DIR_NAME)?.ensure_dir(name)
    }

    pub(crate) fn remove_machine_run_tree(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        remove_owned_child(
            self.roots.run_root(),
            MACHINES_DIR_NAME,
            &machine_id.to_string(),
        )
    }

    pub(crate) fn remove_network_run_tree(&self, network_id: &str) -> Result<(), LibVmError> {
        let network = self.network(network_id)?;
        let name = network
            .runtime_dir()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| LibVmError::StateDecode {
                field: "network_instance_id",
                message: format!("network instance id {network_id:?} is not valid UTF-8"),
            })?;
        remove_owned_child(self.roots.run_root(), NETWORKS_DIR_NAME, name)
    }

    pub(crate) fn remove_machine_logs_tree(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        let root = OwnedDirectory::open_root(self.roots.state_root())?;
        let Some(logs) = root.open_dir(LOGS_DIR_NAME)? else {
            return Ok(());
        };
        let Some(machines) = logs.open_dir(MACHINES_DIR_NAME)? else {
            return Ok(());
        };
        machines.remove_tree(&machine_id.to_string())
    }

    pub(crate) fn open_vm_trace_log(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<File>, LibVmError> {
        self.open_machine_log(machine_id, false, VMMON_TRACE_LOG_FILE_NAME)
    }

    pub(crate) fn open_serial_log(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<File>, LibVmError> {
        self.open_machine_log(machine_id, false, SERIAL_LOG_FILE_NAME)
    }

    pub(crate) fn open_exec_log(&self, machine_id: MachineId) -> Result<Option<File>, LibVmError> {
        self.open_machine_log(machine_id, false, EXEC_LOG_FILE_NAME)
    }

    pub(crate) fn open_exec_log_archive(
        &self,
        machine_id: MachineId,
        generation: u8,
    ) -> Result<Option<File>, LibVmError> {
        let name = match generation {
            1 => "exec.log.1",
            2 => "exec.log.2",
            3 => "exec.log.3",
            _ => {
                return Err(LibVmError::StateDecode {
                    field: "exec_log_generation",
                    message: format!("unsupported exec log archive generation {generation}"),
                })
            }
        };
        self.open_machine_log(machine_id, false, name)
    }

    pub(crate) fn open_network_service_log(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<File>, LibVmError> {
        self.open_machine_log(machine_id, true, NETWORK_SERVICE_LOG_FILE_NAME)
    }

    pub(crate) fn open_network_audit_log(
        &self,
        machine_id: MachineId,
    ) -> Result<Option<File>, LibVmError> {
        self.open_machine_log(machine_id, true, NETWORK_AUDIT_LOG_FILE_NAME)
    }

    fn open_machine_log(
        &self,
        machine_id: MachineId,
        network: bool,
        name: &str,
    ) -> Result<Option<File>, LibVmError> {
        let Some(root) = OwnedDirectory::open_existing_root(self.roots.state_root())? else {
            return Ok(None);
        };
        let Some(logs) = root.open_dir(LOGS_DIR_NAME)? else {
            return Ok(None);
        };
        let Some(machines) = logs.open_dir(MACHINES_DIR_NAME)? else {
            return Ok(None);
        };
        let Some(machine) = machines.open_dir(&machine_id.to_string())? else {
            return Ok(None);
        };
        let directory = if network {
            let Some(network) = machine.open_dir(NETWORK_DIR_NAME)? else {
                return Ok(None);
            };
            network
        } else {
            machine
        };
        directory.open_file(name)
    }

    pub(crate) fn remove_machine_data_tree(&self, machine_id: MachineId) -> Result<(), LibVmError> {
        remove_owned_child(
            self.roots.data_root(),
            MACHINES_DIR_NAME,
            &machine_id.to_string(),
        )
    }

    fn machine_logs_tree(&self, machine_id: MachineId) -> Result<OwnedDirectory, LibVmError> {
        let root = OwnedDirectory::open_root(self.roots.state_root())?;
        root.ensure_dir(LOGS_DIR_NAME)?
            .ensure_dir(MACHINES_DIR_NAME)?
            .ensure_dir(&machine_id.to_string())
    }

    pub(crate) fn keys_dir(&self) -> PathBuf {
        self.data_dir().join("keys")
    }
}

fn remove_owned_child(root_path: &Path, owner: &str, child: &str) -> Result<(), LibVmError> {
    let root = OwnedDirectory::open_root(root_path)?;
    let Some(owner) = root.open_dir(owner)? else {
        return Ok(());
    };
    owner.remove_tree(child)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
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
        let network = paths.network("net123").expect("network paths");

        assert_eq!(paths.keys_dir(), PathBuf::from("/tmp/silo/keys"));
        assert_eq!(
            machine.dir(),
            PathBuf::from("/tmp/silo/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.machine_run_dir(),
            PathBuf::from("/tmp/silo-run/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.machine_logs_dir(),
            PathBuf::from("/tmp/silo-state/logs/machines").join(machine_id.to_string())
        );
        assert_eq!(
            machine.network_service_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(machine_id.to_string())
                .join("network/netd.log")
        );
        assert_eq!(
            machine.network_audit_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(machine_id.to_string())
                .join("network/audit.jsonl")
        );
        assert_eq!(
            machine.exec_log_path(),
            PathBuf::from("/tmp/silo-state/logs/machines")
                .join(machine_id.to_string())
                .join("exec.log")
        );
        assert_eq!(paths.locks_dir(), PathBuf::from("/tmp/silo-run/locks"));
        assert_eq!(
            network.runtime_dir(),
            PathBuf::from("/tmp/silo-run/networks/net123")
        );
    }

    #[test]
    fn machine_log_ownership_is_stable_across_network_instances() {
        let paths = LocalPaths::new("/tmp/silo");
        let machine_id = MachineId::new();
        let machine_logs = paths.machine(machine_id).machine_logs_dir().to_path_buf();

        let first = paths.network("first-network").expect("first network paths");
        let second = paths
            .network("second-network")
            .expect("second network paths");

        assert_ne!(first.runtime_dir(), second.runtime_dir());
        assert_eq!(paths.machine(machine_id).machine_logs_dir(), machine_logs);
        assert!(!machine_logs.starts_with(paths.roots().run_root()));
    }

    #[test]
    fn machine_paths_cannot_collide_through_display_names() {
        let paths = LocalPaths::new("/tmp/silo");
        let first = paths.machine(MachineId::new());
        let second = paths.machine(MachineId::new());

        assert_ne!(first.machine_data_dir(), second.machine_data_dir());
        assert_ne!(first.machine_logs_dir(), second.machine_logs_dir());
        assert_ne!(first.machine_run_dir(), second.machine_run_dir());
    }

    #[test]
    fn machine_data_directory_creation_rejects_symlinked_parents_and_children() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let paths = LocalPaths::new(temp.path().join("data"));
        let external = temp.path().join("external");
        std::fs::create_dir(&external).expect("create external directory");
        std::fs::create_dir_all(paths.data_dir()).expect("create data root");
        symlink(&external, paths.roots().machines_dir()).expect("create machines symlink");

        let error = paths
            .create_machine_data_dir(MachineId::new())
            .err()
            .expect("machines symlink must be rejected");
        assert!(error.to_string().contains("machines"));
        assert!(std::fs::read_dir(&external)
            .expect("read external directory")
            .next()
            .is_none());
        std::fs::remove_file(paths.roots().machines_dir()).expect("remove machines symlink");

        std::fs::create_dir(paths.roots().machines_dir()).expect("create machines directory");
        std::fs::set_permissions(
            paths.roots().machines_dir(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("secure machines directory");
        let id = MachineId::new();
        symlink(&external, paths.roots().machines_dir().join(id.to_string()))
            .expect("create machine symlink");

        let error = paths
            .create_machine_data_dir(id)
            .err()
            .expect("machine symlink must be rejected");
        assert!(error.to_string().contains(&id.to_string()));
        assert!(std::fs::read_dir(&external)
            .expect("read external directory")
            .next()
            .is_none());
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
        let network_socket = paths
            .network(&MachineId::new().to_string())
            .expect("network paths")
            .socket_path();

        assert!(machine_socket.as_os_str().len() < 104);
        assert!(network_socket.as_os_str().len() < 104);
    }
}

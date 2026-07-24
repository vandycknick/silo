use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use crate::lock_manager::{LockGuard, LockManager};
use crate::runtime::RuntimeConfig;
use crate::store::models::{DbConfig, MachineRuntimeState, NetworkInstance};
use crate::store::{ConfigStore, MachineStore, NetworkStore, Store};
use crate::vmmon::process::ProcessIdentity;
use crate::LibVmError;

const MACHINE_DURABLE_FILES: &[&str] = &["vm.trace.log", "serial.log", "vm.exit.json"];
const MACHINE_EPHEMERAL_FILES: &[&str] = &["vm.pid", "vm.sock", "net"];
const NETWORK_EPHEMERAL_FILES: &[&str] = &["netd.sock", "netd.pid", "network-policy.json"];

pub(crate) async fn migrate_runtime_roots(
    config: &RuntimeConfig,
    store: &Store,
    stored: DbConfig,
    state_db_path: &Path,
) -> Result<DbConfig, LibVmError> {
    if stored.state_migration_complete {
        return Ok(stored);
    }

    let (_, proposed_state_root, _) =
        config.resolve_legacy_migration_roots(&stored, state_db_path)?;
    let stored = if stored.state_root.is_none() {
        store
            .claim_state_root(&proposed_state_root.display().to_string())
            .await?
    } else {
        stored
    };
    let (data_root, state_root, legacy_run_root) =
        config.resolve_legacy_migration_roots(&stored, state_db_path)?;
    fs::create_dir_all(&state_root)?;
    let _migration_lock = migration_lock(&state_root)?;
    let stored = store
        .db_config()
        .await?
        .ok_or(LibVmError::StateDatabaseConfigMismatch {
            field: "db_config.row_count",
            expected: "1".to_string(),
            actual: "0".to_string(),
        })?;
    if stored.state_migration_complete {
        return Ok(stored);
    }

    let machines = store.list_machine_configs().await?;
    let _machine_locks = lock_legacy_machines(&legacy_run_root, &machines)?;
    let networks = store.list_network_instances().await?;

    for machine in &machines {
        let state = store.machine_state(machine.id).await?;
        if let Some(state) = state {
            let potentially_active = matches!(
                state.status,
                MachineRuntimeState::Starting
                    | MachineRuntimeState::Running
                    | MachineRuntimeState::Stopping
            );
            if potentially_active && process_is_active(state.vmmon_pid, state.started_at)? {
                return Err(LibVmError::RuntimePathMigrationActive {
                    component: format!("machine {:?}", machine.name),
                });
            }
        }

        let legacy_pid = machine.machine_dir.join("vm.pid");
        if pid_file_is_active(&legacy_pid)? {
            return Err(LibVmError::RuntimePathMigrationActive {
                component: format!("machine {:?}", machine.name),
            });
        }
    }
    if let Some(machine_dir) = first_active_legacy_machine_dir(&data_root)? {
        return Err(LibVmError::RuntimePathMigrationActive {
            component: format!("machine directory {}", machine_dir.display()),
        });
    }

    for network in &networks {
        let runtime_dir = validated_network_runtime_dir(network, &legacy_run_root)?;
        if network_process_is_active(network)? {
            return Err(LibVmError::RuntimePathMigrationActive {
                component: format!("network {:?}", network.id),
            });
        }
        if pid_file_is_active(&runtime_dir.join("netd.pid"))? {
            return Err(LibVmError::RuntimePathMigrationActive {
                component: format!("network {:?}", network.id),
            });
        }
    }
    if let Some(network_dir) = first_active_legacy_network_dir(&legacy_run_root)? {
        return Err(LibVmError::RuntimePathMigrationActive {
            component: format!("network directory {}", network_dir.display()),
        });
    }

    migrate_machine_files(&data_root, &state_root)?;
    migrate_network_files(&legacy_run_root, &state_root, &networks)?;

    for network in &networks {
        store.remove_network_instance(&network.id).await?;
    }

    store.complete_state_root_migration().await
}

struct MigrationLock {
    _file: Flock<File>,
}

fn migration_lock(state_root: &Path) -> Result<MigrationLock, LibVmError> {
    let path = state_root.join(".runtime-path-migration.lock");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    loop {
        match Flock::lock(file, FlockArg::LockExclusive) {
            Ok(file) => return Ok(MigrationLock { _file: file }),
            Err((returned, Errno::EINTR)) => file = returned,
            Err((_, err)) => return Err(io::Error::from_raw_os_error(err as i32).into()),
        }
    }
}

fn lock_legacy_machines(
    legacy_run_root: &Path,
    machines: &[crate::store::models::MachineConfig],
) -> Result<Vec<LockGuard>, LibVmError> {
    let manager = LockManager::open(legacy_run_root.join("locks"))?;
    let mut lock_ids = machines
        .iter()
        .map(|machine| machine.lock_id)
        .collect::<Vec<_>>();
    lock_ids.sort_unstable();
    lock_ids
        .into_iter()
        .map(|lock_id| manager.retrieve(lock_id).lock().map_err(Into::into))
        .collect()
}

fn first_active_legacy_machine_dir(
    data_root: &Path,
) -> Result<Option<std::path::PathBuf>, LibVmError> {
    let machines_dir = data_root.join("machines");
    let entries = match fs::read_dir(machines_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() && pid_file_is_active(&entry.path().join("vm.pid"))? {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn first_active_legacy_network_dir(
    legacy_run_root: &Path,
) -> Result<Option<std::path::PathBuf>, LibVmError> {
    for directory_name in ["net", "networks"] {
        let entries = match fs::read_dir(legacy_run_root.join(directory_name)) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() && pid_file_is_active(&entry.path().join("netd.pid"))? {
                return Ok(Some(entry.path()));
            }
        }
    }
    Ok(None)
}

fn process_is_active(pid: Option<i32>, started_at: Option<i64>) -> Result<bool, LibVmError> {
    let Some(pid) = pid else {
        return Ok(false);
    };
    let Some(identity) = ProcessIdentity::for_pid(pid)? else {
        return Ok(false);
    };
    Ok(identity.owned_by_effective_user()
        && identity.matches_started_at(started_at)
        && identity.is_alive()?)
}

fn pid_file_is_active(path: &Path) -> Result<bool, LibVmError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };
    let pid = contents.trim().parse::<i32>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse pid from {}: {err}", path.display()),
        )
    })?;
    process_is_active(Some(pid), None)
}

fn network_process_is_active(network: &NetworkInstance) -> Result<bool, LibVmError> {
    let state: serde_json::Value =
        serde_json::from_str(&network.driver_state_json).map_err(|err| {
            LibVmError::StateDecode {
                field: "network_instances.driver_state_json",
                message: err.to_string(),
            }
        })?;
    let Some(pid) = state.get("helper_pid").and_then(serde_json::Value::as_i64) else {
        return Err(LibVmError::StateDecode {
            field: "network_instances.driver_state_json.helper_pid",
            message: format!("network {:?} has no integer helper_pid", network.id),
        });
    };
    let pid = i32::try_from(pid).map_err(|err| LibVmError::StateDecode {
        field: "network_instances.driver_state_json.helper_pid",
        message: err.to_string(),
    })?;
    process_is_active(Some(pid), None)
}

fn validated_network_runtime_dir(
    network: &NetworkInstance,
    legacy_run_root: &Path,
) -> Result<std::path::PathBuf, LibVmError> {
    let path = Path::new(&network.runtime_dir);
    if !path.is_absolute() {
        return Err(LibVmError::StateDecode {
            field: "network_instances.runtime_dir",
            message: format!("network {:?} runtime path is not absolute", network.id),
        });
    }
    let path = crate::runtime::normalize_absolute_path(path);
    let legacy_run_root = crate::runtime::normalize_absolute_path(legacy_run_root);
    let in_legacy_network_root = ["net", "networks"]
        .iter()
        .map(|name| legacy_run_root.join(name))
        .any(|root| path.starts_with(root));
    if !in_legacy_network_root {
        return Err(LibVmError::StateDecode {
            field: "network_instances.runtime_dir",
            message: format!(
                "network {:?} runtime path {} is outside legacy run root {}",
                network.id,
                path.display(),
                legacy_run_root.display()
            ),
        });
    }
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LibVmError::StateDecode {
                field: "network_instances.runtime_dir",
                message: format!(
                    "network {:?} runtime path is not a real directory: {}",
                    network.id,
                    path.display()
                ),
            });
        }
    }
    Ok(path)
}

fn migrate_machine_files(data_root: &Path, state_root: &Path) -> Result<(), LibVmError> {
    let machines_dir = data_root.join("machines");
    let entries = match fs::read_dir(&machines_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let source_dir = entry.path();
        let destination_dir = state_root.join("logs/machines").join(entry.file_name());
        for file_name in MACHINE_DURABLE_FILES {
            move_durable_file(
                &source_dir.join(file_name),
                &destination_dir.join(file_name),
                state_root,
            )?;
        }
        for file_name in MACHINE_EPHEMERAL_FILES {
            remove_path_if_exists(&source_dir.join(file_name))?;
        }
    }
    Ok(())
}

fn migrate_network_files(
    legacy_run_root: &Path,
    state_root: &Path,
    networks: &[NetworkInstance],
) -> Result<(), LibVmError> {
    for network in networks {
        let source_dir = validated_network_runtime_dir(network, legacy_run_root)?;
        migrate_network_directory(
            &source_dir,
            &state_root.join("logs/networks").join(&network.id),
            state_root,
        )?;
    }

    for directory_name in ["net", "networks"] {
        let root = legacy_run_root.join(directory_name);
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                migrate_network_directory(
                    &entry.path(),
                    &state_root.join("logs/networks").join(entry.file_name()),
                    state_root,
                )?;
            }
        }
    }
    Ok(())
}

fn migrate_network_directory(
    source_dir: &Path,
    destination_dir: &Path,
    state_root: &Path,
) -> Result<(), LibVmError> {
    move_durable_file(
        &source_dir.join("netd.log"),
        &destination_dir.join("netd.log"),
        state_root,
    )?;
    for file_name in NETWORK_EPHEMERAL_FILES {
        remove_path_if_exists(&source_dir.join(file_name))?;
    }
    Ok(())
}

fn move_durable_file(
    source: &Path,
    destination: &Path,
    state_root: &Path,
) -> Result<(), LibVmError> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "migration source is not a regular file: {}",
                    source.display()
                ),
            )
            .into())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            if files_equal(source, destination)? {
                fs::remove_file(source)?;
                return Ok(());
            }
            return Err(LibVmError::RuntimePathMigrationCollision {
                source_path: source.to_path_buf(),
                destination_path: destination.to_path_buf(),
            });
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "migration destination is not a regular file: {}",
                    destination.display()
                ),
            )
            .into())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "migration destination has no parent: {}",
                destination.display()
            ),
        )
    })?;
    fs::create_dir_all(state_root)?;
    fs::create_dir_all(parent)?;
    let canonical_root = fs::canonicalize(state_root)?;
    let canonical_parent = fs::canonicalize(parent)?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "migration destination parent {} escapes state root {}",
                parent.display(),
                state_root.display()
            ),
        )
        .into());
    }
    match fs::rename(source, destination) {
        Ok(()) => {
            sync_directory(parent)?;
            return Ok(());
        }
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {}
        Err(err) => return Err(err.into()),
    }

    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "migration destination has no file name",
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.migrate-{}",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = copy_durable_file(source, &temporary, destination, parent);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn copy_durable_file(
    source: &Path,
    temporary: &Path,
    destination: &Path,
    parent: &Path,
) -> Result<(), LibVmError> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)?;
    io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    fs::rename(temporary, destination)?;
    sync_directory(parent)?;
    fs::remove_file(source)?;
    Ok(())
}

fn files_equal(left: &Path, right: &Path) -> Result<bool, LibVmError> {
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut left_buffer = [0_u8; 8192];
    let mut right_buffer = [0_u8; 8192];
    loop {
        let left_count = left.read(&mut left_buffer)?;
        let right_count = right.read(&mut right_buffer)?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), LibVmError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), LibVmError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use crate::paths::LocalRoots;
    use crate::runtime::migration::{migrate_runtime_roots, move_durable_file};
    use crate::store::models::DbConfig;
    use crate::store::{ConfigStore, Store};
    use crate::LibVmError;
    use crate::RuntimeConfig;

    fn legacy_config(roots: &LocalRoots) -> DbConfig {
        let mut legacy = DbConfig::from_roots(roots);
        legacy.legacy_run_root = Some(roots.run_root().display().to_string());
        legacy.state_root = None;
        legacy.state_migration_complete = false;
        legacy
    }

    #[test]
    fn durable_move_is_retry_safe() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let source = temp.path().join("source.log");
        let destination = temp.path().join("state/destination.log");
        std::fs::write(&source, b"log contents").expect("write source");

        move_durable_file(&source, &destination, temp.path()).expect("move source");
        assert!(!source.exists());
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"log contents"
        );

        std::fs::write(&source, b"log contents").expect("recreate source");
        move_durable_file(&source, &destination, temp.path()).expect("retry move");
        assert!(!source.exists());
    }

    #[test]
    fn durable_move_rejects_conflicting_destination() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let source = temp.path().join("source.log");
        let destination = temp.path().join("destination.log");
        std::fs::write(&source, b"source").expect("write source");
        std::fs::write(&destination, b"destination").expect("write destination");

        let error =
            move_durable_file(&source, &destination, temp.path()).expect_err("collision must fail");
        assert!(matches!(
            error,
            LibVmError::RuntimePathMigrationCollision { .. }
        ));
        assert_eq!(std::fs::read(source).expect("source remains"), b"source");
    }

    #[test]
    fn durable_move_rejects_symlinked_source() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let target = temp.path().join("target.log");
        let source = temp.path().join("source.log");
        let destination = temp.path().join("state/destination.log");
        std::fs::write(&target, b"target").expect("write target");
        symlink(&target, &source).expect("create source symlink");

        move_durable_file(&source, &destination, temp.path())
            .expect_err("source symlink must fail");

        assert_eq!(std::fs::read(target).expect("target remains"), b"target");
        assert!(source.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn durable_move_rejects_destination_parent_escape() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let state_root = temp.path().join("state");
        let outside = temp.path().join("outside");
        let source = temp.path().join("source.log");
        std::fs::create_dir(&state_root).expect("create state root");
        std::fs::create_dir(&outside).expect("create outside dir");
        symlink(&outside, state_root.join("logs")).expect("create parent symlink");
        std::fs::write(&source, b"source").expect("write source");

        move_durable_file(
            &source,
            &state_root.join("logs/destination.log"),
            &state_root,
        )
        .expect_err("destination escape must fail");

        assert_eq!(std::fs::read(source).expect("source remains"), b"source");
        assert!(!outside.join("destination.log").exists());
    }

    #[tokio::test]
    async fn legacy_root_migration_moves_durable_files_and_keeps_capture() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let run_root = temp.path().join("legacy-run");
        let image_root = temp.path().join("images");
        let state_root = temp.path().join("state");
        std::fs::create_dir(&run_root).expect("create run root");
        std::fs::set_permissions(
            &run_root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("set run permissions");
        let roots = LocalRoots::with_roots(&data_root, &run_root, &image_root, &state_root);
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("open store");
        let legacy = legacy_config(&roots);
        let legacy = store
            .read_or_seed_db_config(&legacy)
            .await
            .expect("seed legacy config");

        let machine_dir = data_root.join("machines/orphan");
        std::fs::create_dir_all(&machine_dir).expect("create machine dir");
        std::fs::write(machine_dir.join("vm.trace.log"), b"trace").expect("write trace");
        std::fs::write(machine_dir.join("serial.log"), b"serial").expect("write serial");
        std::fs::write(machine_dir.join("vm.exit.json"), b"exit").expect("write exit");
        std::fs::write(machine_dir.join("vm.pid"), b"99999999").expect("write stale pid");

        let network_dir = run_root.join("net/orphan-network");
        std::fs::create_dir_all(&network_dir).expect("create network dir");
        std::fs::write(network_dir.join("netd.log"), b"netd").expect("write netd log");
        std::fs::write(network_dir.join("capture.pcap"), b"capture").expect("write capture");

        let config = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("new-run"))
            .with_image_root(&image_root)
            .with_state_root(&state_root);
        let migrated = migrate_runtime_roots(&config, &store, legacy, &data_root.join("state.db"))
            .await
            .expect("migrate roots");

        assert_eq!(migrated.state_root, Some(state_root.display().to_string()));
        assert_eq!(
            migrated.legacy_run_root,
            Some(run_root.display().to_string())
        );
        assert_eq!(
            std::fs::read(state_root.join("logs/machines/orphan/vm.trace.log"))
                .expect("read migrated trace"),
            b"trace"
        );
        assert_eq!(
            std::fs::read(state_root.join("logs/networks/orphan-network/netd.log"))
                .expect("read migrated network log"),
            b"netd"
        );
        assert!(network_dir.join("capture.pcap").exists());
        assert!(!machine_dir.join("vm.pid").exists());
    }

    #[tokio::test]
    async fn legacy_root_migration_refuses_a_live_pidfile() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let run_root = temp.path().join("legacy-run");
        let image_root = temp.path().join("images");
        let state_root = temp.path().join("state");
        std::fs::create_dir(&run_root).expect("create run root");
        let roots = LocalRoots::with_roots(&data_root, &run_root, &image_root, &state_root);
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("open store");
        let legacy = legacy_config(&roots);
        let legacy = store
            .read_or_seed_db_config(&legacy)
            .await
            .expect("seed legacy config");
        let machine_dir = data_root.join("machines/orphan");
        std::fs::create_dir_all(&machine_dir).expect("create machine dir");
        std::fs::write(machine_dir.join("vm.pid"), std::process::id().to_string())
            .expect("write live pid");

        let config = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("new-run"))
            .with_image_root(&image_root)
            .with_state_root(&state_root);
        let error = migrate_runtime_roots(&config, &store, legacy, &data_root.join("state.db"))
            .await
            .expect_err("live process must block migration");

        assert!(matches!(
            error,
            LibVmError::RuntimePathMigrationActive { .. }
        ));
        let stored = store
            .db_config()
            .await
            .expect("read config")
            .expect("stored config");
        assert_eq!(stored.state_root, Some(state_root.display().to_string()));
        assert!(!stored.state_migration_complete);
    }

    #[tokio::test]
    async fn legacy_root_migration_refuses_an_orphaned_live_network() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let run_root = temp.path().join("legacy-run");
        let image_root = temp.path().join("images");
        let state_root = temp.path().join("state");
        std::fs::create_dir(&run_root).expect("create run root");
        let roots = LocalRoots::with_roots(&data_root, &run_root, &image_root, &state_root);
        let store = Store::open(&data_root.join("state.db"))
            .await
            .expect("open store");
        let legacy = legacy_config(&roots);
        let legacy = store
            .read_or_seed_db_config(&legacy)
            .await
            .expect("seed legacy config");
        let network_dir = run_root.join("net/orphan");
        std::fs::create_dir_all(&network_dir).expect("create network dir");
        std::fs::write(network_dir.join("netd.pid"), std::process::id().to_string())
            .expect("write live pid");
        std::fs::write(network_dir.join("netd.log"), b"active").expect("write log");

        let config = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("new-run"))
            .with_image_root(&image_root)
            .with_state_root(&state_root);
        let error = migrate_runtime_roots(&config, &store, legacy, &data_root.join("state.db"))
            .await
            .expect_err("live orphaned network must block migration");

        assert!(matches!(
            error,
            LibVmError::RuntimePathMigrationActive { .. }
        ));
        assert!(network_dir.join("netd.log").exists());
        assert!(network_dir.join("netd.pid").exists());
    }

    #[tokio::test]
    async fn concurrent_migration_claims_exactly_one_state_root() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let data_root = temp.path().join("data");
        let run_root = temp.path().join("legacy-run");
        let image_root = temp.path().join("images");
        let state_a = temp.path().join("state-a");
        let state_b = temp.path().join("state-b");
        std::fs::create_dir(&run_root).expect("create run root");
        let roots = LocalRoots::with_roots(&data_root, &run_root, &image_root, &state_a);
        let store_a = Store::open(&data_root.join("state.db"))
            .await
            .expect("open first store");
        let legacy = legacy_config(&roots);
        let legacy = store_a
            .read_or_seed_db_config(&legacy)
            .await
            .expect("seed legacy config");
        let store_b = Store::open(&data_root.join("state.db"))
            .await
            .expect("open second store");
        let machine_dir = data_root.join("machines/orphan");
        std::fs::create_dir_all(&machine_dir).expect("create machine dir");
        std::fs::write(machine_dir.join("vm.trace.log"), b"trace").expect("write trace");

        let config_a = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("new-run-a"))
            .with_image_root(&image_root)
            .with_state_root(&state_a);
        let config_b = RuntimeConfig::local(&data_root)
            .with_run_root(temp.path().join("new-run-b"))
            .with_image_root(&image_root)
            .with_state_root(&state_b);
        let state_db = data_root.join("state.db");
        let (result_a, result_b) = tokio::join!(
            migrate_runtime_roots(&config_a, &store_a, legacy.clone(), &state_db),
            migrate_runtime_roots(&config_b, &store_b, legacy, &state_db),
        );

        assert_ne!(result_a.is_ok(), result_b.is_ok());
        let stored = store_a
            .db_config()
            .await
            .expect("read config")
            .expect("stored config");
        assert!(stored.state_migration_complete);
        assert_eq!(stored.legacy_run_root, Some(run_root.display().to_string()));
        let claimed = std::path::PathBuf::from(stored.state_root.expect("state root"));
        let unclaimed = if claimed == state_a { state_b } else { state_a };
        assert_eq!(
            std::fs::read(claimed.join("logs/machines/orphan/vm.trace.log"))
                .expect("read claimed trace"),
            b"trace"
        );
        assert!(!unclaimed.join("logs/machines/orphan/vm.trace.log").exists());
    }
}

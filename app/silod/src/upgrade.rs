//! In-place system image upgrades, owned entirely by the running silod.
//!
//! ```text
//!  check ──► qualify (throwaway VM, engine keeps serving)
//!              │
//!              ▼
//!  stop active VM ──► pending record ──► back up data disk ──► candidate VM
//!                                                                  │
//!               recover ◄── any failure ◄── validate candidate ◄───┘
//!                  │                              │ passes
//!                  ▼                              ▼
//!          previous VM active            commit (complete) ──► Ready ──► finalize
//! ```
//!
//! A crash at any point leaves a record `recover` or `finalize` can act on at the
//! next start.
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{ExecutionResult, ImagePullPolicy, MachineData, MachineReadinessOutcome};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{DesiredSystem, ResolvedSystemConfig};
use crate::engine::READY_TIMEOUT;
use crate::paths::SystemPaths;
use crate::provision::{is_installation_machine, is_live, validate_installation, validate_machine};
use crate::record::DaemonRecord;
use crate::runtime::SystemRuntime;
use crate::storage::validate_data_image;
use crate::supervisor::append_log;

const QUALIFICATION_PREFIX: &str = "silo-system-qualification-";

/// Only facts needed to undo an upgrade. VM status and image metadata stay in libvm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpgradeRecord {
    pub(crate) operation_id: Uuid,
    pub(crate) previous_machine_id: String,
    pub(crate) previous_config: ResolvedSystemConfig,
    pub(crate) previous_configured_image: String,
    pub(crate) candidate_machine_id: Option<String>,
    pub(crate) backup_size: Option<u64>,
    /// The candidate passed validation and is the active VM. It becomes permanent
    /// (`finalize`) once it reaches Ready under the supervisor.
    pub(crate) complete: bool,
}

impl UpgradeRecord {
    pub(crate) fn validate(&self, state: &DaemonRecord) -> eyre::Result<()> {
        if self.previous_machine_id.is_empty()
            || self.previous_config.data_size_bytes != state.data_size_bytes
            || self
                .backup_size
                .is_some_and(|size| size != state.data_size_bytes)
            || (self.backup_size.is_none() && self.candidate_machine_id.is_some())
            || (self.complete
                && (self.candidate_machine_id != state.machine_id
                    || self.candidate_machine_id.is_none()))
            || self
                .candidate_machine_id
                .as_ref()
                .is_some_and(|id| *id == self.previous_machine_id)
        {
            bail!("upgrade recovery record does not match this installation");
        }
        Ok(())
    }

    fn restored_state(&self, state: &DaemonRecord) -> DaemonRecord {
        let mut restored = state.clone();
        restored.machine_id = Some(self.previous_machine_id.clone());
        restored.config = self.previous_config.clone();
        restored.configured_image = self.previous_configured_image.clone();
        restored.upgrade = None;
        restored
    }

    fn candidate_name(&self) -> String {
        format!("silo-system-upgrade-{}", self.operation_id.simple())
    }

    fn backup_path(&self, paths: &SystemPaths) -> PathBuf {
        paths
            .backups()
            .join(format!("data-{}.img", self.operation_id))
    }
}

/// Resolves `reference` and returns it when it names a different manifest than
/// `active` runs. A tag is asked of the registry; a digest cannot change.
pub(crate) async fn check(
    runtime: &mut SystemRuntime,
    reference: &str,
    active: &MachineData,
) -> eyre::Result<Option<libvm::ResolvedOciImage>> {
    let policy = if reference.contains("@sha256:") {
        ImagePullPolicy::IfMissing
    } else {
        ImagePullPolicy::Always
    };
    let image = runtime
        .resolve_image(reference, policy)
        .await
        .with_context(|| format!("check {reference} for a newer system image"))?;
    let current = active
        .rootfs
        .as_ref()
        .and_then(|rootfs| rootfs.selected_manifest_digest.as_deref());
    if current == Some(image.manifest_digest.as_str()) {
        return Ok(None);
    }
    validate_target(&image)?;
    Ok(Some(image))
}

/// Boots `image` against a throwaway data disk and validates it, without touching
/// the active VM. Cancelling this future can leave a qualification VM behind;
/// [`remove_abandoned_qualifications`] reclaims it.
pub(crate) async fn qualify(
    runtime: &mut SystemRuntime,
    paths: &SystemPaths,
    desired: &DesiredSystem,
    image: libvm::ResolvedOciImage,
) -> eyre::Result<()> {
    let config = ResolvedSystemConfig {
        image: image.selected_reference.clone(),
        ..desired.config.clone()
    };
    qualify_candidate_image(runtime, paths, &config, image).await
}

/// Replaces the stopped active VM with one built from `image`, committing only once
/// the candidate validates. On error the recorded transaction is left for
/// [`recover`].
pub(crate) async fn replace(
    runtime: &mut SystemRuntime,
    paths: &SystemPaths,
    desired: &DesiredSystem,
    image: libvm::ResolvedOciImage,
) -> eyre::Result<()> {
    let mut state = DaemonRecord::load(paths)?
        .ok_or_else(|| eyre::eyre!("the system installation record is missing"))?;
    if state.upgrade.is_some() {
        bail!("a previous system image upgrade has not been finalized");
    }
    let target_config = ResolvedSystemConfig {
        image: image.selected_reference.clone(),
        ..desired.config.clone()
    };
    validate_installation(&state, &target_config)?;
    let old_id = state.machine_id()?.to_string();
    let old_machine = runtime.inspect_machine(&old_id).await?;
    validate_machine(&old_machine, &state, &paths.data_image())?;
    ensure_machine_stopped(runtime, &old_id).await?;

    let mut pending = UpgradeRecord {
        operation_id: Uuid::new_v4(),
        previous_machine_id: old_id,
        previous_config: state.config.clone(),
        previous_configured_image: state.configured_image.clone(),
        candidate_machine_id: None,
        backup_size: None,
        complete: false,
    };
    state.upgrade = Some(pending.clone());
    state.save(paths)?;

    validate_data_image(
        &paths.data_image(),
        state.data_size_bytes,
        state.installation_id,
        state.data_uuid,
    )?;
    let backup_path = pending.backup_path(paths);
    std::fs::create_dir_all(paths.backups())?;
    let backup_size = sparse_copy(&paths.data_image(), &backup_path)?;
    validate_data_image(
        &backup_path,
        state.data_size_bytes,
        state.installation_id,
        state.data_uuid,
    )?;
    pending.backup_size = Some(backup_size);
    state.upgrade = Some(pending.clone());
    state.save(paths)?;

    let candidate_name = pending.candidate_name();
    runtime.ensure_name_available(&candidate_name).await?;
    let candidate = runtime
        .create_system_machine(
            &candidate_name,
            &target_config,
            state.installation_id,
            &paths.data_image(),
            image,
        )
        .await?;
    pending.candidate_machine_id = Some(candidate.id.clone());
    state.upgrade = Some(pending.clone());
    state.save(paths)?;
    validate_candidate(runtime, &candidate.id, state.data_uuid, &target_config).await?;

    state.machine_id = Some(candidate.id);
    state.config = target_config;
    state.configured_image = desired.image.clone();
    pending.complete = true;
    state.upgrade = Some(pending);
    state.save(paths)
}

/// Makes a committed upgrade permanent: removes the previous VM and the data backup.
/// Without a committed upgrade this does nothing.
pub(crate) async fn finalize(runtime: &mut SystemRuntime, paths: &SystemPaths) -> eyre::Result<()> {
    let Some(mut state) = DaemonRecord::load(paths)? else {
        return Ok(());
    };
    let Some(record) = state.upgrade.clone().filter(|upgrade| upgrade.complete) else {
        return Ok(());
    };
    match runtime.inspect_machine(&record.previous_machine_id).await {
        Ok(previous) => {
            if !is_installation_machine(&previous, state.installation_id) {
                bail!("previous system VM is not owned by this installation");
            }
            ensure_machine_stopped(runtime, &previous.id).await?;
            runtime.remove_machine(&previous.id).await?;
        }
        Err(error)
            if error
                .downcast_ref::<libvm::LibVmError>()
                .is_some_and(|error| {
                    matches!(error, libvm::LibVmError::MachineNotFound { .. })
                }) => {}
        Err(error) => return Err(error),
    }
    remove_backup(&record.backup_path(paths))?;
    state.upgrade = None;
    state.save(paths)
}

/// Restores the VM, configuration, and engine data from before the recorded
/// upgrade, whether it was interrupted or committed but never became Ready.
pub(crate) async fn recover(runtime: &mut SystemRuntime, paths: &SystemPaths) -> eyre::Result<()> {
    let state = DaemonRecord::load(paths)?
        .ok_or_else(|| eyre::eyre!("the system installation record is missing"))?;
    let record = state
        .upgrade
        .as_ref()
        .ok_or_else(|| eyre::eyre!("there is no recorded system image upgrade to recover"))?;
    record.validate(&state)?;
    // Creation may have finished just before a crash prevented recording the ID.
    let candidate = match &record.candidate_machine_id {
        Some(id) => Some(runtime.inspect_machine(id).await?),
        None => {
            let mut candidates = runtime
                .list_machines()
                .await?
                .into_iter()
                .filter(|machine| {
                    machine.name == record.candidate_name()
                        && is_installation_machine(machine, state.installation_id)
                });
            let candidate = candidates.next();
            if candidates.next().is_some() {
                bail!(
                    "multiple upgrade candidates match this operation; refusing ambiguous recovery"
                );
            }
            candidate
        }
    };
    if let Some(candidate) = &candidate {
        if !is_installation_machine(candidate, state.installation_id) {
            bail!("upgrade candidate is not owned by this installation");
        }
        ensure_machine_stopped(runtime, &candidate.id).await?;
    }
    let restored = record.restored_state(&state);
    let old_id = &record.previous_machine_id;
    let old_machine = runtime.inspect_machine(old_id).await?;
    validate_machine(&old_machine, &restored, &paths.data_image())?;
    ensure_machine_stopped(runtime, old_id).await?;
    if let Some(size) = record.backup_size {
        let backup = record.backup_path(paths);
        validate_data_image(&backup, size, state.installation_id, state.data_uuid)?;
        append_log(
            paths,
            "restoring engine data from the pre-upgrade backup; later writes are discarded",
        )?;
        restore_backup(&backup, &paths.data_image())?;
        validate_data_image(
            &paths.data_image(),
            state.data_size_bytes,
            state.installation_id,
            state.data_uuid,
        )?;
    } else if candidate.is_some() {
        bail!("incomplete backup unexpectedly has a candidate machine; refusing recovery");
    }
    restored.save(paths)?;
    if let Some(candidate) = candidate {
        if let Err(error) = runtime.remove_machine(&candidate.id).await {
            append_log(
                paths,
                &format!(
                    "could not remove stopped upgrade candidate {}: {error:#}",
                    candidate.id
                ),
            )?;
        }
    }
    remove_backup(&record.backup_path(paths))
}

fn remove_backup(path: &Path) -> eyre::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove the pre-upgrade data backup"),
    }
}

/// Removes qualification VMs and their throwaway disks left by a cancelled or
/// crashed qualification.
pub(crate) async fn remove_abandoned_qualifications(
    runtime: &mut SystemRuntime,
    paths: &SystemPaths,
) -> eyre::Result<()> {
    for machine in runtime.list_machines().await? {
        if machine.name.starts_with(QUALIFICATION_PREFIX)
            && silod_spec::labels::is_system_managed(&machine.labels)
        {
            ensure_machine_stopped(runtime, &machine.id).await?;
            runtime.remove_machine(&machine.id).await?;
        }
    }
    let entries = match std::fs::read_dir(paths.run_root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("upgrade-qualification-"))
        {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

async fn qualify_candidate_image(
    runtime: &mut SystemRuntime,
    paths: &SystemPaths,
    config: &ResolvedSystemConfig,
    image: libvm::ResolvedOciImage,
) -> eyre::Result<()> {
    std::fs::create_dir_all(paths.run_root())?;
    let installation_id = Uuid::new_v4();
    let temporary = paths.run_root().join(format!(
        "upgrade-qualification-{}",
        installation_id.simple()
    ));
    std::fs::create_dir(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    }
    let data_uuid = Uuid::new_v4();
    let data_image = temporary.join("data.img");
    crate::storage::ensure_data_image(&data_image, 512 * 1024 * 1024, installation_id, data_uuid)?;
    let mut qualification_config = config.clone();
    qualification_config.docker_socket = temporary.join("docker.sock");
    let name = format!("{QUALIFICATION_PREFIX}{}", installation_id.simple());
    runtime.ensure_name_available(&name).await?;
    let candidate = runtime
        .create_system_machine(
            &name,
            &qualification_config,
            installation_id,
            &data_image,
            image,
        )
        .await?;
    let validation =
        validate_candidate(runtime, &candidate.id, data_uuid, &qualification_config).await;
    let removal = runtime.remove_machine(&candidate.id).await;
    if let Err(error) = removal {
        validation?;
        return Err(error).with_context(|| {
            format!(
                "remove qualification candidate; disposable disk retained at {}",
                temporary.display()
            )
        });
    }
    validation?;
    std::fs::remove_dir_all(&temporary)?;
    Ok(())
}

fn validate_target(image: &libvm::ResolvedOciImage) -> eyre::Result<()> {
    let expected_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => bail!("unsupported host architecture {architecture}"),
    };
    if image.platform.os != "linux" || image.platform.architecture != expected_arch {
        bail!("resolved system image platform is incompatible with this host");
    }
    let labels = image
        .config
        .labels
        .as_ref()
        .ok_or_else(|| eyre::eyre!("system image has no compatibility labels"))?;
    for (name, expected) in [
        ("io.silo.system.schema", "1"),
        ("io.silo.system.activation-contract", "1"),
        ("io.silo.system.data-layout", "1"),
        ("io.silo.system.engine", "docker"),
    ] {
        if labels.get(name).map(String::as_str) != Some(expected) {
            bail!("system image compatibility label {name} must be {expected:?}");
        }
    }
    Ok(())
}

async fn validate_candidate(
    runtime: &mut SystemRuntime,
    machine_id: &str,
    data_uuid: Uuid,
    config: &ResolvedSystemConfig,
) -> eyre::Result<()> {
    let machine = runtime.machine(machine_id).await?;
    let machine_data = machine.inspect().await?;
    let options = libvm::MachineStartOptions::new();
    let run_id = machine.start_with_options(options).await?.run_id;
    let validation = async {
        let readiness = machine.wait_ready(READY_TIMEOUT).await?;
        if readiness.outcome != MachineReadinessOutcome::Ready {
            bail!(
                "candidate guest readiness ended with {:?}",
                readiness.outcome
            );
        }
        validate_guest_manifest(&machine).await?;
        crate::engine::activate(&machine, config, &machine_data.spec, data_uuid).await?;
        crate::engine::wait_docker_socket(&config.docker_socket, READY_TIMEOUT).await
    }
    .await;
    crate::engine::stop_engine(&machine).await;
    let stopped = machine.stop_run(run_id).await;
    validation?;
    stopped?;
    Ok(())
}

async fn validate_guest_manifest(machine: &crate::runtime::SystemMachine) -> eyre::Result<()> {
    let output = machine
        .exec_with_input(
            "/usr/bin/cat",
            &["/usr/lib/silo-system/manifest.json"],
            "root",
            Vec::new(),
            Duration::from_secs(10),
        )
        .await?;
    if !matches!(output.result(), ExecutionResult::Exited { code: Some(0) }) {
        bail!("candidate compatibility manifest could not be read");
    }
    let manifest: serde_json::Value = serde_json::from_slice(output.stdout_bytes())?;
    let expected_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => bail!("unsupported host architecture {architecture}"),
    };
    for (pointer, expected) in [
        ("/engine", "docker"),
        ("/storage", "containerd-snapshotter"),
        ("/architecture", expected_arch),
        ("/qualified_silo", ">=0.1.0 <0.2.0"),
        ("/versions/docker", "5:29.8.0-1~debian.13~trixie"),
        ("/versions/containerd", "2.3.5-1~debian.13~trixie"),
    ] {
        if manifest
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            != Some(expected)
        {
            bail!("candidate compatibility manifest {pointer} is unsupported");
        }
    }
    for (pointer, expected) in [
        ("/schema", 1),
        ("/activation_contract", 1),
        ("/publication_contract", 1),
        ("/data_layout", 1),
    ] {
        if manifest
            .pointer(pointer)
            .and_then(serde_json::Value::as_u64)
            != Some(expected)
        {
            bail!("candidate compatibility manifest {pointer} is unsupported");
        }
    }
    Ok(())
}

async fn ensure_machine_stopped(runtime: &mut SystemRuntime, id: &str) -> eyre::Result<()> {
    if is_live(&runtime.inspect_machine(id).await?) {
        runtime
            .stop_system_machine(id, Duration::from_secs(60))
            .await?;
    }
    if is_live(&runtime.inspect_machine(id).await?) {
        bail!("machine {id} still has a live monitor after shutdown");
    }
    Ok(())
}

fn sparse_copy(source_path: &Path, destination_path: &Path) -> eyre::Result<u64> {
    let parent = destination_path
        .parent()
        .ok_or_else(|| eyre::eyre!("backup path has no parent"))?;
    let filesystem = nix::sys::statvfs::statvfs(parent)?;
    // fsblkcnt_t is u32 on macOS and u64 on Linux.
    #[allow(clippy::useless_conversion)]
    let available =
        u64::from(filesystem.blocks_available()).saturating_mul(filesystem.fragment_size());
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    let required = std::fs::metadata(source_path)?.blocks().saturating_mul(512);
    if available < required.saturating_add(required / 10) {
        bail!(
            "insufficient backup space: need approximately {} bytes, {} available",
            required,
            available
        );
    }
    let temporary = destination_path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let mut source = File::open(source_path)?;
    let length = source.metadata()?.len();
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut destination = options.open(&temporary)?;
    destination.set_len(length)?;
    let mut position = 0_i64;
    while position < i64::try_from(length)? {
        let data = match nix::unistd::lseek(&source, position, nix::unistd::Whence::SeekData) {
            Ok(offset) => offset,
            Err(nix::errno::Errno::ENXIO) => break,
            Err(error) => return Err(error).context("locate allocated data in engine disk"),
        };
        let hole = nix::unistd::lseek(&source, data, nix::unistd::Whence::SeekHole)?;
        source.seek(std::io::SeekFrom::Start(u64::try_from(data)?))?;
        destination.seek(std::io::SeekFrom::Start(u64::try_from(data)?))?;
        let copied = std::io::copy(
            &mut std::io::Read::by_ref(&mut source).take(u64::try_from(hole - data)?),
            &mut destination,
        )?;
        if copied != u64::try_from(hole - data)? {
            bail!("short write while backing up engine disk");
        }
        position = hole;
    }
    destination.flush()?;
    destination.sync_all()?;
    std::fs::rename(&temporary, destination_path)?;
    File::open(parent)?.sync_all()?;
    Ok(length)
}

fn restore_backup(backup: &Path, data: &Path) -> eyre::Result<()> {
    let temporary = data.with_extension(format!("restore-{}.tmp", Uuid::new_v4()));
    sparse_copy(backup, &temporary)?;
    std::fs::rename(&temporary, data)?;
    let parent = data
        .parent()
        .ok_or_else(|| eyre::eyre!("data path has no parent"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::record::tests::fixture;
    use crate::record::DaemonRecord;
    use crate::upgrade::{restore_backup, sparse_copy, UpgradeRecord};

    #[test]
    fn upgrade_recovery_is_committed_with_the_active_vm_reference() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, mut state) = fixture(temp.path());
        state.machine_id = Some("old-vm".to_string());
        let mut operation = UpgradeRecord {
            operation_id: uuid::Uuid::new_v4(),
            previous_machine_id: "old-vm".to_string(),
            previous_config: state.config.clone(),
            previous_configured_image: state.configured_image.clone(),
            candidate_machine_id: None,
            backup_size: None,
            complete: false,
        };
        for stage in 0..4 {
            match stage {
                1 => operation.backup_size = Some(state.data_size_bytes),
                2 => operation.candidate_machine_id = Some("new-vm".to_string()),
                3 => {
                    operation.complete = true;
                    state.machine_id = Some("new-vm".to_string());
                }
                _ => {}
            }
            state.upgrade = Some(operation.clone());
            state.save(&paths).expect("commit operation");
            let loaded = DaemonRecord::load(&paths).expect("reload").expect("state");
            assert_eq!(loaded, state);
            assert_eq!(
                loaded
                    .upgrade
                    .as_ref()
                    .is_some_and(|upgrade| upgrade.complete),
                stage == 3
            );
        }
        operation
            .restored_state(&state)
            .save(&paths)
            .expect("restore old state");
        let restored = DaemonRecord::load(&paths).expect("reload").expect("state");
        assert_eq!(restored.machine_id().expect("VM"), "old-vm");
        assert!(restored.upgrade.is_none());
    }

    #[test]
    fn inconsistent_recovery_state_is_rejected_before_writing() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, mut state) = fixture(temp.path());
        state.machine_id = Some("old-vm".to_string());
        state.save(&paths).expect("initial state");
        let valid = UpgradeRecord {
            operation_id: uuid::Uuid::new_v4(),
            previous_machine_id: "old-vm".to_string(),
            previous_config: state.config.clone(),
            previous_configured_image: state.configured_image.clone(),
            candidate_machine_id: None,
            backup_size: None,
            complete: false,
        };
        for case in 0..6 {
            let mut invalid = valid.clone();
            match case {
                0 => invalid.previous_machine_id.clear(),
                1 => invalid.previous_config.data_size_bytes += 1,
                2 => invalid.backup_size = Some(state.data_size_bytes + 1),
                3 => invalid.candidate_machine_id = Some("new-vm".to_string()),
                4 => invalid.complete = true,
                _ => {
                    invalid.backup_size = Some(state.data_size_bytes);
                    invalid.candidate_machine_id = Some("old-vm".to_string());
                }
            }
            state.upgrade = Some(invalid);
            assert!(state.save(&paths).is_err(), "case {case}");
            assert!(DaemonRecord::load(&paths)
                .expect("load unchanged state")
                .expect("state")
                .upgrade
                .is_none());
        }
    }

    #[test]
    fn restoring_backup_replaces_data_but_preserves_the_backup() {
        let temp = tempfile::tempdir().expect("temp");
        let data = temp.path().join("data.img");
        let backup = temp.path().join("backup.img");
        std::fs::write(&backup, b"before upgrade").expect("backup");
        std::fs::write(&data, b"after upgrade").expect("data");
        restore_backup(&backup, &data).expect("restore");
        assert_eq!(std::fs::read(&data).expect("data"), b"before upgrade");
        assert_eq!(std::fs::read(&backup).expect("backup"), b"before upgrade");
    }

    #[test]
    fn sparse_backup_preserves_length_and_allocated_data() {
        let temp = tempfile::tempdir().expect("temp");
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let mut file = std::fs::File::create(&source).expect("source");
        file.set_len(16 * 1024 * 1024).expect("sparse length");
        use std::io::{Seek as _, Write as _};
        file.seek(std::io::SeekFrom::Start(8 * 1024 * 1024))
            .expect("seek");
        file.write_all(b"engine-data").expect("write");
        file.sync_all().expect("sync");
        sparse_copy(&source, &destination).expect("backup");
        assert_eq!(
            std::fs::metadata(&destination).expect("metadata").len(),
            16 * 1024 * 1024
        );
        let bytes = std::fs::read(&destination).expect("read");
        assert_eq!(
            &bytes[8 * 1024 * 1024..8 * 1024 * 1024 + 11],
            b"engine-data"
        );
    }
}

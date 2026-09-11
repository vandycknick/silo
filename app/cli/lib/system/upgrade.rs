use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eyre::{bail, Context as _};
use libvm::{ExecutionResult, ImageProgressSender, MachineReadinessOutcome, MachineStatus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::AppApi;
use crate::system::config::ResolvedSystemConfig;
use crate::system::record::{
    load_record, write_record, InstallationRecord, SystemPaths, SystemRecord,
};
use crate::system::service::{OperationLock, Registration};
use crate::system::storage::validate_data_image;
use crate::system::supervisor::{LifetimeLock, READY_TIMEOUT};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UpgradeStep {
    BackingUp,
    BackupComplete,
    CandidateCreated,
    RecordsCommitted,
    Validated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpgradeRecord {
    schema: u32,
    operation_id: Uuid,
    step: UpgradeStep,
    old_system: SystemRecord,
    old_installation: InstallationRecord,
    old_registration: Registration,
    target_reference: String,
    target_digest: String,
    old_run_id: Option<String>,
    candidate_machine_id: Option<String>,
    candidate_run_id: Option<String>,
    data_path: PathBuf,
    data_uuid: Uuid,
    backup_path: PathBuf,
    backup_size: Option<u64>,
    backup_complete: bool,
    service_was_enabled: bool,
}

pub(crate) async fn upgrade(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: ResolvedSystemConfig,
    image: &str,
) -> eyre::Result<()> {
    let _operation = OperationLock::acquire(&paths.operation_lock())?;
    if paths.upgrade().exists() {
        bail!("an upgrade is already pending; run `silo daemon upgrade --recover`");
    }
    let old_system = load_required::<SystemRecord>(&paths.system_record(), "system record")?;
    let old_installation =
        load_required::<InstallationRecord>(&paths.installation(), "installation record")?;
    let old_registration = crate::system::service::load_registration(&paths.registration())?;

    let (progress, _receiver) = ImageProgressSender::channel(1);
    let source = api.resolve_system_image(image, progress).await?;
    validate_target(&source)?;
    if source.image.manifest_digest == old_system.image_digest {
        return Ok(());
    }
    let target_reference = source.image.selected_reference.clone();
    let target_digest = source.image.manifest_digest.clone();
    let target_config = config.with_image(target_reference.clone())?;
    qualify_candidate_image(api, paths, &target_config, source.image.clone()).await?;
    let service_was_enabled = crate::system::service::is_enabled()?;
    let old_machine = api.inspect_machine(&old_system.active_machine_id).await?;
    let old_run_id = if matches!(
        old_machine.status,
        MachineStatus::Running { .. }
            | MachineStatus::Starting { .. }
            | MachineStatus::Stopping { .. }
    ) {
        Some(
            api.machine(&old_system.active_machine_id)
                .await?
                .current_run_id()
                .await?
                .to_string(),
        )
    } else {
        None
    };

    let backup_dir = paths.daemon_data().join("backups");
    std::fs::create_dir_all(&backup_dir)?;
    let operation_id = Uuid::new_v4();
    let backup_path = backup_dir.join(format!("data-{operation_id}.img"));
    let mut pending = UpgradeRecord {
        schema: 1,
        operation_id,
        step: UpgradeStep::BackingUp,
        old_system: old_system.clone(),
        old_installation: old_installation.clone(),
        old_registration: old_registration.clone(),
        target_reference: target_reference.clone(),
        target_digest: target_digest.clone(),
        old_run_id,
        candidate_machine_id: None,
        candidate_run_id: None,
        data_path: paths.data_image(),
        data_uuid: old_installation.data_uuid,
        backup_path: backup_path.clone(),
        backup_size: None,
        backup_complete: false,
        service_was_enabled,
    };
    write_record(&paths.upgrade(), &pending)?;

    crate::system::service::stop_locked(&old_registration)?;
    let lifetime = match acquire_lifetime(paths, Duration::from_secs(90)) {
        Ok(lifetime) => lifetime,
        Err(error) => {
            rollback_before_backup(paths, &old_registration, service_was_enabled)?;
            return Err(error);
        }
    };
    if let Err(error) = ensure_machine_stopped(api, &old_system.active_machine_id).await {
        drop(lifetime);
        rollback_before_backup(paths, &old_registration, service_was_enabled)?;
        return Err(error);
    }
    if let Err(error) = validate_data_image(
        &paths.data_image(),
        old_installation.data_size_bytes,
        old_installation.installation_id,
        old_installation.data_uuid,
    ) {
        drop(lifetime);
        rollback_before_backup(paths, &old_registration, service_was_enabled)?;
        return Err(error);
    }

    let backup_size = sparse_copy(&paths.data_image(), &backup_path)?;
    validate_data_image(
        &backup_path,
        old_installation.data_size_bytes,
        old_installation.installation_id,
        old_installation.data_uuid,
    )?;
    pending.step = UpgradeStep::BackupComplete;
    pending.backup_size = Some(backup_size);
    pending.backup_complete = true;
    write_record(&paths.upgrade(), &pending)?;

    let candidate_name = format!(
        "silo-system-upgrade-{}",
        &operation_id.simple().to_string()[..12]
    );
    api.ensure_name_available(&candidate_name).await?;
    let candidate = api
        .create_system_machine(
            &candidate_name,
            &target_config,
            old_installation.installation_id,
            &paths.data_image(),
            source,
        )
        .await?;
    pending.candidate_machine_id = Some(candidate.id.clone());
    pending.step = UpgradeStep::CandidateCreated;
    write_record(&paths.upgrade(), &pending)?;

    let new_system = SystemRecord {
        schema: 1,
        installation_id: old_system.installation_id,
        engine: old_system.engine.clone(),
        active_machine_id: candidate.id,
        image_reference: target_reference,
        image_digest: target_digest,
        data_uuid: old_system.data_uuid,
        data_layout: old_system.data_layout,
        config_identity: target_config.identity.clone(),
    };
    let mut new_installation = old_installation;
    new_installation.config = target_config.clone();
    let mut new_registration = old_registration;
    new_registration.config = target_config.clone();
    write_record(&paths.system_record(), &new_system)?;
    write_record(&paths.installation(), &new_installation)?;
    write_record(&paths.registration(), &new_registration)?;
    pending.step = UpgradeStep::RecordsCommitted;
    write_record(&paths.upgrade(), &pending)?;

    validate_committed_candidate(api, &new_system, &target_config, |run_id| {
        pending.candidate_run_id = Some(run_id.to_string());
        write_record(&paths.upgrade(), &pending)
    })
    .await?;
    pending.step = UpgradeStep::Validated;
    write_record(&paths.upgrade(), &pending)?;
    replace_completed_record(paths, &pending)?;
    drop(lifetime);

    if service_was_enabled {
        crate::system::service::start_locked(&new_registration)?;
        crate::system::service::wait_ready_locked(paths, Duration::from_secs(120))?;
    }
    Ok(())
}

pub(crate) async fn recover(api: &mut AppApi, paths: &SystemPaths) -> eyre::Result<()> {
    let _operation = OperationLock::acquire(&paths.operation_lock())?;
    let (pending_path, record) = if let Some(record) = load_record(&paths.upgrade())? {
        (paths.upgrade(), record)
    } else if let Some(record) = load_record(&paths.completed_upgrade())? {
        (paths.completed_upgrade(), record)
    } else {
        bail!("there is no recorded system image upgrade to recover");
    };
    let record: UpgradeRecord = record;
    validate_recovery_record(paths, &record)?;
    crate::system::service::stop_locked(&record.old_registration)?;
    let lifetime = acquire_lifetime(paths, Duration::from_secs(90))?;
    if let Some(candidate) = &record.candidate_machine_id {
        ensure_machine_stopped(api, candidate).await?;
    }
    ensure_machine_stopped(api, &record.old_system.active_machine_id).await?;
    if !record.backup_complete {
        if record.candidate_machine_id.is_some() {
            bail!("incomplete backup unexpectedly records a candidate machine; refusing ambiguous recovery");
        }
        write_record(&paths.system_record(), &record.old_system)?;
        write_record(&paths.installation(), &record.old_installation)?;
        write_record(&paths.registration(), &record.old_registration)?;
        std::fs::remove_file(pending_path)?;
        drop(lifetime);
        restore_service_if_enabled(&record.old_registration, record.service_was_enabled)?;
        return Ok(());
    }
    eprintln!("warning: recovery restores engine data to the pre-upgrade backup and discards all later writes");
    validate_data_image(
        &record.backup_path,
        record.old_installation.data_size_bytes,
        record.old_installation.installation_id,
        record.data_uuid,
    )?;
    restore_backup(&record.backup_path, &record.data_path)?;
    validate_data_image(
        &record.data_path,
        record.old_installation.data_size_bytes,
        record.old_installation.installation_id,
        record.data_uuid,
    )?;
    write_record(&paths.system_record(), &record.old_system)?;
    write_record(&paths.installation(), &record.old_installation)?;
    write_record(&paths.registration(), &record.old_registration)?;
    std::fs::remove_file(pending_path)?;
    if let Some(candidate) = &record.candidate_machine_id {
        if let Err(error) = api.remove_machine(candidate, false).await {
            eprintln!("warning: recovered data but could not remove stopped upgrade candidate {candidate}: {error:#}");
        }
    }
    drop(lifetime);
    restore_service_if_enabled(&record.old_registration, record.service_was_enabled)?;
    Ok(())
}

async fn qualify_candidate_image(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: &ResolvedSystemConfig,
    image: libvm::ResolvedOciImage,
) -> eyre::Result<()> {
    std::fs::create_dir_all(&paths.run_root)?;
    let installation_id = Uuid::new_v4();
    let temporary = paths.run_root.join(format!(
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
    crate::system::storage::ensure_data_image(
        &data_image,
        512 * 1024 * 1024,
        installation_id,
        data_uuid,
    )?;
    let mut qualification_config = config.clone();
    qualification_config.docker_socket = temporary.join("docker.sock");
    let name = format!(
        "silo-system-qualification-{}",
        &installation_id.simple().to_string()[..12]
    );
    api.ensure_name_available(&name).await?;
    let candidate = api
        .create_system_machine(
            &name,
            &qualification_config,
            installation_id,
            &data_image,
            crate::api::types::SystemImageResolution { image },
        )
        .await?;
    let record = SystemRecord {
        schema: 1,
        installation_id,
        engine: "docker".to_string(),
        active_machine_id: candidate.id.clone(),
        image_reference: config.image.clone(),
        image_digest: candidate
            .rootfs
            .as_ref()
            .and_then(|rootfs| rootfs.selected_manifest_digest.clone())
            .ok_or_else(|| eyre::eyre!("qualification candidate has no image digest"))?,
        data_uuid,
        data_layout: 1,
        config_identity: qualification_config.identity.clone(),
    };
    let validation =
        validate_committed_candidate(api, &record, &qualification_config, |_| Ok(())).await;
    let removal = api.remove_machine(&candidate.id, false).await;
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

fn restore_service_if_enabled(registration: &Registration, enabled: bool) -> eyre::Result<()> {
    if enabled {
        crate::system::service::start_locked(registration)?;
    }
    Ok(())
}

fn rollback_before_backup(
    paths: &SystemPaths,
    registration: &Registration,
    enabled: bool,
) -> eyre::Result<()> {
    std::fs::remove_file(paths.upgrade())?;
    File::open(paths.daemon_data())?.sync_all()?;
    restore_service_if_enabled(registration, enabled)
}

fn validate_target(source: &crate::api::types::SystemImageResolution) -> eyre::Result<()> {
    let expected_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => bail!("unsupported host architecture {architecture}"),
    };
    if source.image.platform.os != "linux" || source.image.platform.architecture != expected_arch {
        bail!("resolved system image platform is incompatible with this host");
    }
    let labels = source
        .image
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

async fn validate_committed_candidate(
    api: &mut AppApi,
    record: &SystemRecord,
    config: &ResolvedSystemConfig,
    on_started: impl FnOnce(&libvm::MachineRunId) -> eyre::Result<()>,
) -> eyre::Result<()> {
    let machine = api.machine(&record.active_machine_id).await?;
    let options = api.machine_start_options(&machine, false).await?;
    let run_id = machine.start_with_options(options).await?.run_id;
    let validation = async {
        on_started(&run_id)?;
        let readiness = machine.wait_ready(READY_TIMEOUT).await?;
        if readiness.outcome != MachineReadinessOutcome::Ready {
            bail!(
                "candidate guest readiness ended with {:?}",
                readiness.outcome
            );
        }
        validate_guest_manifest(&machine).await?;
        crate::system::supervisor::activate(&machine, config, record.data_uuid).await?;
        crate::system::supervisor::probe_docker_socket(&config.docker_socket)
    }
    .await;
    let _ = machine
        .exec_with_input(
            "/usr/bin/systemctl",
            &["stop", "silo-system-docker.target"],
            "root",
            Vec::new(),
            Duration::from_secs(30),
        )
        .await;
    let stopped = machine.stop_run(run_id).await;
    validation?;
    stopped?;
    Ok(())
}

fn validate_recovery_record(paths: &SystemPaths, record: &UpgradeRecord) -> eyre::Result<()> {
    if record.schema != 1
        || record.data_path != paths.data_image()
        || record.old_system.installation_id != record.old_installation.installation_id
        || record.old_system.data_uuid != record.data_uuid
        || record.old_installation.data_uuid != record.data_uuid
    {
        bail!("upgrade recovery record does not match this installation");
    }
    if record.target_reference.is_empty()
        || !record.target_digest.starts_with("sha256:")
        || (record.backup_complete == (record.step == UpgradeStep::BackingUp))
        || (record.candidate_run_id.is_some() && record.candidate_machine_id.is_none())
    {
        bail!("upgrade recovery record has inconsistent operation state");
    }
    let backup_root = paths.daemon_data().join("backups");
    if record.backup_path.parent() != Some(backup_root.as_path()) {
        bail!("upgrade backup path is outside the installation backup directory");
    }
    let expected_backup = format!("data-{}.img", record.operation_id);
    if record
        .backup_path
        .file_name()
        .and_then(|name| name.to_str())
        != Some(&expected_backup)
    {
        bail!("upgrade backup identity does not match its operation");
    }
    for run_id in [&record.old_run_id, &record.candidate_run_id]
        .into_iter()
        .flatten()
    {
        run_id
            .parse::<libvm::MachineRunId>()
            .with_context(|| format!("invalid recorded monitor generation {run_id:?}"))?;
    }
    Ok(())
}

async fn validate_guest_manifest(machine: &crate::api::machine::AppMachine) -> eyre::Result<()> {
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

async fn ensure_machine_stopped(api: &mut AppApi, id: &str) -> eyre::Result<()> {
    let machine = api.inspect_machine(id).await?;
    if matches!(
        machine.status,
        MachineStatus::Running { .. }
            | MachineStatus::Starting { .. }
            | MachineStatus::Stopping { .. }
    ) {
        api.stop_machine(id, false, Duration::from_secs(60)).await?;
    }
    let machine = api.inspect_machine(id).await?;
    if matches!(
        machine.status,
        MachineStatus::Running { .. }
            | MachineStatus::Starting { .. }
            | MachineStatus::Stopping { .. }
    ) {
        bail!("machine {id} still has a live monitor after shutdown");
    }
    Ok(())
}

fn acquire_lifetime(paths: &SystemPaths, timeout: Duration) -> eyre::Result<LifetimeLock> {
    let deadline = Instant::now() + timeout;
    loop {
        match LifetimeLock::acquire(&paths.lifetime_lock()) {
            Ok(lock) => return Ok(lock),
            Err(error)
                if Instant::now() < deadline
                    && error.to_string().contains("another Silo system daemon") =>
            {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(error) => return Err(error),
        }
    }
}

fn sparse_copy(source_path: &Path, destination_path: &Path) -> eyre::Result<u64> {
    let parent = destination_path
        .parent()
        .ok_or_else(|| eyre::eyre!("backup path has no parent"))?;
    let filesystem = nix::sys::statvfs::statvfs(parent)?;
    let available = filesystem
        .blocks_available()
        .saturating_mul(filesystem.fragment_size());
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

fn replace_completed_record(paths: &SystemPaths, record: &UpgradeRecord) -> eyre::Result<()> {
    write_record(&paths.completed_upgrade(), record)?;
    std::fs::remove_file(paths.upgrade())?;
    File::open(paths.daemon_data())?.sync_all()?;
    Ok(())
}

fn load_required<T: serde::de::DeserializeOwned>(path: &Path, name: &str) -> eyre::Result<T> {
    load_record(path)?.ok_or_else(|| eyre::eyre!("{name} is missing: {}", path.display()))
}

pub(crate) fn is_pending_candidate(paths: &SystemPaths, machine_id: &str) -> eyre::Result<bool> {
    let Some(record) = load_record::<UpgradeRecord>(&paths.upgrade())? else {
        return Ok(false);
    };
    Ok(record.candidate_machine_id.as_deref() == Some(machine_id))
}

#[cfg(test)]
mod tests {
    use crate::system::upgrade::sparse_copy;

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

use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{ImageProgressSender, MachineData, MachineStatus, Memory};
use uuid::Uuid;

use crate::api::AppApi;
use crate::system::config::ResolvedSystemConfig;
use crate::system::ownership::is_matching_managed_candidate;
use crate::system::record::{DaemonRecord, SystemPaths};
use crate::system::storage::{ensure_data_image, validate_data_image};

pub(crate) async fn ensure_system_machine(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: ResolvedSystemConfig,
) -> eyre::Result<(DaemonRecord, MachineData)> {
    let mut installation = prepare_installation(paths, &config)?;
    let machine = match find_system_machine(api, paths, installation.installation_id).await? {
        Some(machine) => {
            validate_machine(&machine, &installation, &paths.data_image())?;
            if installation.machine_id.is_none() && installation.configured_image != config.image {
                // A previous first start may have created the VM before recording its ID.
                // Keep that VM addressable by upgrade rather than silently adopting a
                // different image after a default change.
                installation.machine_id = Some(machine.id.clone());
                installation.config.image = installation.configured_image.clone();
                installation.save(paths)?;
                bail!("an interrupted setup already created a system VM with the previous image; run `silo daemon upgrade`");
            }
            reconcile_system_hardware(api, machine, &config).await?
        }
        None => {
            api.ensure_name_available(crate::system::SYSTEM_MACHINE_NAME)
                .await?;
            let (progress, _receiver) = ImageProgressSender::channel(1);
            let source = api
                .resolve_system_image(&config.image, progress)
                .await
                .context("could not fetch the system image")?;
            api.create_system_machine(
                crate::system::SYSTEM_MACHINE_NAME,
                &config,
                installation.installation_id,
                &paths.data_image(),
                source,
            )
            .await?
        }
    };
    validate_machine(&machine, &installation, &paths.data_image())?;
    if installation.machine_id.is_none() {
        installation.configured_image = config.image.clone();
    }
    installation.machine_id = Some(machine.id.clone());
    if hardware_matches(&machine, &config) {
        installation.config = config;
    }
    installation.save(paths)?;
    Ok((installation, machine))
}

pub(crate) fn prepare_installation(
    paths: &SystemPaths,
    config: &ResolvedSystemConfig,
) -> eyre::Result<DaemonRecord> {
    let installation = match DaemonRecord::load(paths)? {
        Some(record) => {
            validate_installation(&record, config)?;
            if record.machine_id.is_some() && record.config.image != config.image {
                bail!("system image changes require `silo daemon upgrade`");
            }
            record
        }
        None => {
            let record = DaemonRecord::new(paths, config.clone())?;
            record.save(paths)?;
            record
        }
    };

    let prepare_data = if installation.machine_id.is_some() {
        validate_data_image
    } else {
        ensure_data_image
    };
    prepare_data(
        &paths.data_image(),
        installation.data_size_bytes,
        installation.installation_id,
        installation.data_uuid,
    )?;

    Ok(installation)
}

/// The settings the daemon may change between starts: CPUs, memory, and Rosetta.
#[derive(Debug, PartialEq, Eq)]
struct SystemHardware {
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    rosetta: Option<bool>,
}

impl SystemHardware {
    fn of_machine(machine: &MachineData) -> Self {
        let hardware = machine.spec.hardware.as_ref();
        Self {
            cpus: hardware.and_then(|hardware| hardware.cpus),
            memory_mib: hardware.and_then(|hardware| hardware.memory),
            rosetta: Some(
                hardware
                    .and_then(|hardware| hardware.rosetta)
                    .unwrap_or(false),
            ),
        }
    }

    fn of_config(config: &ResolvedSystemConfig) -> Self {
        Self {
            cpus: Some(config.cpus),
            memory_mib: u32::try_from(config.memory_bytes / (1024 * 1024)).ok(),
            rosetta: config.rosetta_explicit.then_some(config.rosetta),
        }
    }
}

fn hardware_matches(machine: &MachineData, config: &ResolvedSystemConfig) -> bool {
    let current = SystemHardware::of_machine(machine);
    let desired = SystemHardware::of_config(config);
    current.cpus == desired.cpus
        && current.memory_mib == desired.memory_mib
        && desired
            .rosetta
            .is_none_or(|rosetta| current.rosetta == Some(rosetta))
}

/// Applies CPU, memory, and Rosetta settings to a stopped system machine so config or
/// default changes take effect on the next start. A running machine keeps its current
/// settings until it stops; the daemon stops it on `down`.
async fn reconcile_system_hardware(
    api: &mut AppApi,
    machine: MachineData,
    config: &ResolvedSystemConfig,
) -> eyre::Result<MachineData> {
    let current = SystemHardware::of_machine(&machine);
    let desired = SystemHardware::of_config(config);
    if hardware_matches(&machine, config)
        || matches!(
            machine.status,
            MachineStatus::Running { .. }
                | MachineStatus::Starting { .. }
                | MachineStatus::Stopping { .. }
        )
    {
        return Ok(machine);
    }
    let mut update = libvm::MachineUpdate::new();
    if current.cpus != desired.cpus {
        update = update.cpus(config.cpus);
    }
    if current.memory_mib != desired.memory_mib {
        update = update.memory(Memory::bytes(config.memory_bytes));
    }
    if let Some(rosetta) = desired.rosetta {
        if current.rosetta != Some(rosetta) {
            update = update.rosetta(rosetta);
        }
    }
    api.update_system_machine(&machine.id, update)
        .await
        .context("apply resource settings to the system machine")
}

/// Finds the machine owned by this installation: the recorded active machine, or,
/// before a system record exists, the single machine carrying this installation's
/// management labels (a creation that was interrupted before the record was written).
pub(crate) async fn find_system_machine(
    api: &mut AppApi,
    paths: &SystemPaths,
    installation_id: Uuid,
) -> eyre::Result<Option<MachineData>> {
    if let Some(record) = DaemonRecord::load(paths)? {
        if let Some(id) = record.machine_id {
            let machine = api.inspect_machine(&id).await.with_context(|| {
                format!("recorded system machine {id} is missing; refusing to create a replacement")
            })?;
            if !is_matching_managed_candidate(&machine, installation_id) {
                bail!("recorded machine is not owned by this system installation");
            }
            return Ok(Some(machine));
        }
    }
    let mut candidates: Vec<_> = api
        .list_machines()
        .await?
        .into_iter()
        .filter(|machine| is_matching_managed_candidate(machine, installation_id))
        .collect();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => bail!(
            "multiple unrecorded system machines match installation {installation_id}; remove ambiguity manually"
        ),
    }
}

/// Gracefully stops this installation's system machine if it is running, whether or
/// not the daemon got as far as recording it. Returns the machine ID it acted on.
pub(crate) async fn stop_system_machine(
    api: &mut AppApi,
    paths: &SystemPaths,
    installation_id: Uuid,
    timeout: Duration,
) -> eyre::Result<Option<String>> {
    let Some(machine) = find_system_machine(api, paths, installation_id).await? else {
        return Ok(None);
    };
    if matches!(
        machine.status,
        MachineStatus::Running { .. }
            | MachineStatus::Starting { .. }
            | MachineStatus::Stopping { .. }
    ) {
        api.stop_system_machine(&machine.id, timeout).await?;
    }
    Ok(Some(machine.id))
}

pub(crate) fn validate_installation(
    record: &DaemonRecord,
    config: &ResolvedSystemConfig,
) -> eyre::Result<()> {
    if record.schema != 1 || record.data_layout != 1 {
        bail!("unsupported system installation record");
    }
    if record.data_size_bytes != config.data_size_bytes {
        bail!("changing daemon data-size is not supported");
    }
    if record.config.shares != config.shares {
        bail!("changing system shares after first creation is not supported");
    }
    record.require_no_pending_upgrade()?;
    if record.config.docker_socket != config.docker_socket
        || record.config.publish_bind != config.publish_bind
    {
        bail!("existing system endpoint/publication configuration differs; run daemon down and restore the recorded configuration");
    }
    Ok(())
}

pub(crate) fn validate_machine(
    machine: &MachineData,
    record: &DaemonRecord,
    data_image: &std::path::Path,
) -> eyre::Result<()> {
    if !is_matching_managed_candidate(machine, record.installation_id)
        || record
            .machine_id
            .as_ref()
            .is_some_and(|id| *id != machine.id)
    {
        bail!("recorded machine is not owned by this system installation");
    }
    let disks = machine
        .spec
        .storage
        .as_ref()
        .map(|storage| storage.disks.as_slice())
        .unwrap_or_default();
    // The machine's own root disk is recorded as a relative path inside its data
    // directory; every other attachment must be the installation data image.
    let attached: Vec<_> = disks
        .iter()
        .filter(|disk| disk.path.is_absolute())
        .collect();
    let valid_attachment = match attached.as_slice() {
        [disk] => attachment_matches_data_image(&disk.path, disk.read_only, data_image)?,
        _ => false,
    };
    if !valid_attachment {
        bail!(
            "recorded system machine does not attach the installation data image {} read-write",
            data_image.display()
        );
    }
    Ok(())
}

fn attachment_matches_data_image(
    attached_path: &Path,
    read_only: bool,
    data_image: &Path,
) -> eyre::Result<bool> {
    if read_only {
        return Ok(false);
    }
    let attached_path = std::fs::canonicalize(attached_path)
        .with_context(|| format!("resolve attached data image {}", attached_path.display()))?;
    let data_image = std::fs::canonicalize(data_image)
        .with_context(|| format!("resolve installation data image {}", data_image.display()))?;
    Ok(attached_path == data_image)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use crate::system::config::SystemConfig;
    use crate::system::provision::{
        attachment_matches_data_image, validate_installation, SystemHardware,
    };
    use crate::system::record::DaemonRecord;

    #[test]
    fn persisted_data_and_share_changes_fail_closed() {
        let home = tempfile::tempdir().expect("home");
        let config: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem: {}\n").expect("config");
        let resolved = config
            .resolve(home.path(), home.path(), None)
            .expect("resolve");
        let root = home.path().to_path_buf();
        let paths = crate::system::record::SystemPaths::new(root.clone(), root.clone(), root);
        let record = DaemonRecord::new(&paths, resolved.clone()).expect("state");
        assert!(validate_installation(&record, &resolved).is_ok());
        let mut changed = resolved;
        changed.data_size_bytes += 1;
        assert!(validate_installation(&record, &changed).is_err());
    }

    #[test]
    fn interrupted_setup_accepts_a_new_default_without_replacing_its_data_disk() {
        use crate::system::provision::prepare_installation;
        use std::os::unix::fs::MetadataExt as _;
        let temp = tempfile::tempdir().expect("temp");
        let (paths, state) = crate::system::record::tests::fixture(temp.path());
        state.save(&paths).expect("initial identity");
        let initial = prepare_installation(&paths, &state.config).expect("prepare storage");
        let inode = std::fs::metadata(paths.data_image()).expect("disk").ino();
        let mut changed = state.config.clone();
        changed.image = "registry.example/system@sha256:new".to_string();
        let mut resumed = prepare_installation(&paths, &changed).expect("resume incomplete setup");
        assert_eq!(initial.installation_id, resumed.installation_id);
        assert_eq!(initial.data_uuid, resumed.data_uuid);
        assert_eq!(
            inode,
            std::fs::metadata(paths.data_image()).expect("disk").ino()
        );
        resumed.machine_id = Some("already-created".to_string());
        resumed.save(&paths).expect("record VM");
        assert!(prepare_installation(&paths, &changed)
            .expect_err("existing VM needs upgrade")
            .to_string()
            .contains("silo daemon upgrade"));
        assert_eq!(
            inode,
            std::fs::metadata(paths.data_image()).expect("disk").ino()
        );
    }

    #[test]
    fn provisioned_installation_never_recreates_a_missing_data_disk() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, mut state) = crate::system::record::tests::fixture(temp.path());
        state.machine_id = Some("existing-vm".to_string());
        state.save(&paths).expect("state");
        assert!(crate::system::provision::prepare_installation(&paths, &state.config).is_err());
        assert!(!paths.data_image().exists());
    }

    #[test]
    fn data_attachment_accepts_only_the_same_existing_writable_image_through_an_alias() {
        let temp = tempfile::tempdir_in("/tmp").expect("tempdir");
        let actual = temp.path().join("actual");
        std::fs::create_dir(&actual).expect("actual directory");
        let data_image = actual.join("data.img");
        std::fs::write(&data_image, b"data").expect("data image");
        let other_image = actual.join("other.img");
        std::fs::write(&other_image, b"other").expect("other image");

        let alias = temp.path().join("alias");
        symlink(&actual, &alias).expect("data directory alias");
        let wrong_alias = temp.path().join("wrong-alias.img");
        symlink(&other_image, &wrong_alias).expect("wrong image alias");

        assert!(
            attachment_matches_data_image(&alias.join("data.img"), false, &data_image)
                .expect("compare aliased image")
        );
        assert!(
            !attachment_matches_data_image(&other_image, false, &data_image)
                .expect("compare different image")
        );
        assert!(
            !attachment_matches_data_image(&wrong_alias, false, &data_image)
                .expect("compare wrong symlink target")
        );
        assert!(
            !attachment_matches_data_image(&alias.join("data.img"), true, &data_image)
                .expect("reject read-only image")
        );
        assert!(attachment_matches_data_image(
            &temp.path().join("missing.img"),
            false,
            &data_image
        )
        .is_err());
    }

    #[test]
    fn implicit_krun_rosetta_default_is_not_a_persisted_hardware_update() {
        let home = tempfile::tempdir().expect("home");
        let config: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nbackend: krun\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        let resolved = config
            .resolve(home.path(), home.path(), None)
            .expect("resolve");

        assert!(!resolved.rosetta);
        assert_eq!(SystemHardware::of_config(&resolved).rosetta, None);
    }

    #[test]
    fn explicit_rosetta_intent_is_a_hardware_update() {
        let config: crate::system::config::ResolvedSystemConfig =
            serde_json::from_value(serde_json::json!({
                "schema": 1,
                "engine": "docker",
                "image": "registry.example/system@sha256:test",
                "cpus": 2,
                "memory_bytes": 1073741824,
                "root_size_bytes": 1073741824,
                "data_size_bytes": 1073741824,
                "shares": [],
                "publish_bind": "any",
                "docker_socket": "/tmp/silo.sock",
                "backend": "vz",
                "rosetta": true,
                "rosetta_explicit": true
            }))
            .expect("resolved config");

        assert!(config.rosetta_explicit);
        assert_eq!(SystemHardware::of_config(&config).rosetta, Some(true));
    }
}

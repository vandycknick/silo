use std::path::Path;
use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{ImagePullPolicy, MachineData, MachineStatus, Memory};
use uuid::Uuid;

use crate::config::{DesiredSystem, ResolvedSystemConfig};
use crate::paths::SystemPaths;
use crate::record::DaemonRecord;
use crate::runtime::SystemRuntime;
use crate::storage::{ensure_data_image, validate_data_image};

pub(crate) const SYSTEM_MACHINE_NAME: &str = "silo-system";

pub(crate) async fn ensure_system_machine(
    runtime: &mut SystemRuntime,
    paths: &SystemPaths,
    desired: &DesiredSystem,
) -> eyre::Result<(DaemonRecord, MachineData)> {
    let config = &desired.config;
    let mut installation = prepare_installation(paths, config)?;
    let machine = match find_system_machine(runtime, &installation).await? {
        // A machine found before its ID was recorded keeps the image it was
        // created with; the update check moves it to `desired.image` later.
        Some(machine) => {
            validate_machine(&machine, &installation, &paths.data_image())?;
            reconcile_system_hardware(runtime, machine, config).await?
        }
        None => {
            runtime.ensure_name_available(SYSTEM_MACHINE_NAME).await?;
            let image = runtime
                .resolve_image(&desired.image, ImagePullPolicy::IfMissing)
                .await
                .context("could not fetch the system image")?;
            installation.configured_image = desired.image.clone();
            installation.config.image = image.selected_reference.clone();
            runtime
                .create_system_machine(
                    SYSTEM_MACHINE_NAME,
                    config,
                    installation.installation_id,
                    &paths.data_image(),
                    image,
                )
                .await?
        }
    };
    validate_machine(&machine, &installation, &paths.data_image())?;
    installation.machine_id = Some(machine.id.clone());
    if hardware_matches(&machine, config) {
        installation.config = ResolvedSystemConfig {
            image: installation.config.image.clone(),
            ..config.clone()
        };
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
            record
        }
        None => {
            let record = DaemonRecord::new(config.clone());
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
    runtime: &mut SystemRuntime,
    machine: MachineData,
    config: &ResolvedSystemConfig,
) -> eyre::Result<MachineData> {
    let current = SystemHardware::of_machine(&machine);
    let desired = SystemHardware::of_config(config);
    if hardware_matches(&machine, config) || is_live(&machine) {
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
    runtime
        .update_system_machine(&machine.id, update)
        .await
        .context("apply resource settings to the system machine")
}

/// Finds the machine owned by this installation: the recorded active machine, or,
/// before one is recorded, the single machine carrying this installation's
/// management labels (a creation that was interrupted before the record was written).
pub(crate) async fn find_system_machine(
    runtime: &mut SystemRuntime,
    record: &DaemonRecord,
) -> eyre::Result<Option<MachineData>> {
    if let Some(id) = &record.machine_id {
        let machine = runtime.inspect_machine(id).await.with_context(|| {
            format!("recorded system machine {id} is missing; refusing to create a replacement")
        })?;
        if !is_installation_machine(&machine, record.installation_id) {
            bail!("recorded machine is not owned by this system installation");
        }
        return Ok(Some(machine));
    }
    let mut candidates: Vec<_> = runtime
        .list_machines()
        .await?
        .into_iter()
        .filter(|machine| {
            machine.name == SYSTEM_MACHINE_NAME
                && is_installation_machine(machine, record.installation_id)
        })
        .collect();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => bail!(
            "multiple unrecorded system machines match installation {}; remove ambiguity manually",
            record.installation_id
        ),
    }
}

/// Gracefully stops this installation's system machine if it is running, whether or
/// not the daemon got as far as recording it. Returns the machine ID it acted on.
pub(crate) async fn stop_system_machine(
    runtime: &mut SystemRuntime,
    record: &DaemonRecord,
    timeout: Duration,
) -> eyre::Result<Option<String>> {
    let Some(machine) = find_system_machine(runtime, record).await? else {
        return Ok(None);
    };
    if is_live(&machine) {
        runtime.stop_system_machine(&machine.id, timeout).await?;
    }
    Ok(Some(machine.id))
}

pub(crate) fn is_live(machine: &MachineData) -> bool {
    matches!(
        machine.status,
        MachineStatus::Running { .. }
            | MachineStatus::Starting { .. }
            | MachineStatus::Stopping { .. }
    )
}

/// Whether libvm labels mark `machine` as belonging to this installation.
pub(crate) fn is_installation_machine(machine: &MachineData, installation_id: Uuid) -> bool {
    installation_labels_match(&machine.labels, installation_id)
}

fn installation_labels_match(
    labels: &std::collections::BTreeMap<String, String>,
    installation_id: Uuid,
) -> bool {
    silod_spec::labels::is_system_managed(labels)
        && labels.get(silod_spec::labels::INSTALLATION_LABEL) == Some(&installation_id.to_string())
}

/// Rejects changes the installation cannot absorb: its data disk, the shares and
/// endpoint the engine was activated with, and the publication policy.
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
    if record.config.docker_socket != config.docker_socket
        || record.config.publish_bind != config.publish_bind
    {
        bail!("changing the system Docker endpoint or publish bind after first creation is not supported");
    }
    Ok(())
}

pub(crate) fn validate_machine(
    machine: &MachineData,
    record: &DaemonRecord,
    data_image: &std::path::Path,
) -> eyre::Result<()> {
    if !is_installation_machine(machine, record.installation_id)
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

    use crate::provision::{
        attachment_matches_data_image, installation_labels_match, prepare_installation,
        validate_installation, SystemHardware,
    };
    use crate::record::tests::fixture;

    #[test]
    fn persisted_data_share_and_endpoint_changes_fail_closed() {
        let temp = tempfile::tempdir().expect("temp");
        let (_paths, record) = fixture(temp.path());
        assert!(validate_installation(&record, &record.config).is_ok());
        let mut changed = record.config.clone();
        changed.data_size_bytes += 1;
        assert!(validate_installation(&record, &changed).is_err());
        let mut changed = record.config.clone();
        changed.shares.clear();
        assert!(validate_installation(&record, &changed).is_err());
        let mut changed = record.config.clone();
        changed.publish_bind = libvm::PublishBind::Loopback;
        assert!(validate_installation(&record, &changed).is_err());
        let mut changed = record.config.clone();
        changed.image = "registry.example/system:other".into();
        changed.cpus += 1;
        assert!(validate_installation(&record, &changed).is_ok());
    }

    #[test]
    fn interrupted_setup_and_image_changes_keep_the_data_disk() {
        use std::os::unix::fs::MetadataExt as _;
        let temp = tempfile::tempdir().expect("temp");
        let (paths, state) = fixture(temp.path());
        state.save(&paths).expect("initial identity");
        let initial = prepare_installation(&paths, &state.config).expect("prepare storage");
        let inode = std::fs::metadata(paths.data_image()).expect("disk").ino();
        let mut changed = state.config.clone();
        changed.image = "registry.example/system@sha256:new".to_string();
        let mut resumed = prepare_installation(&paths, &changed).expect("resume incomplete setup");
        assert_eq!(initial.installation_id, resumed.installation_id);
        assert_eq!(initial.data_uuid, resumed.data_uuid);
        resumed.machine_id = Some("already-created".to_string());
        resumed.save(&paths).expect("record VM");
        // An image change on a provisioned installation is an upgrade, not an error.
        prepare_installation(&paths, &changed).expect("image change is upgraded later");
        assert_eq!(
            inode,
            std::fs::metadata(paths.data_image()).expect("disk").ino()
        );
    }

    #[test]
    fn provisioned_installation_never_recreates_a_missing_data_disk() {
        let temp = tempfile::tempdir().expect("temp");
        let (paths, mut state) = fixture(temp.path());
        state.machine_id = Some("existing-vm".to_string());
        state.save(&paths).expect("state");
        assert!(prepare_installation(&paths, &state.config).is_err());
        assert!(!paths.data_image().exists());
    }

    #[test]
    fn installation_ownership_requires_both_labels() {
        use silod_spec::labels::{INSTALLATION_LABEL, MANAGED_ROLE, MANAGED_ROLE_LABEL};
        let installation = uuid::Uuid::new_v4();
        let labels = |entries: &[(&str, String)]| {
            entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.clone()))
                .collect()
        };
        let role = (MANAGED_ROLE_LABEL, MANAGED_ROLE.to_string());
        let owned = (INSTALLATION_LABEL, installation.to_string());
        let other = (INSTALLATION_LABEL, uuid::Uuid::new_v4().to_string());
        assert!(installation_labels_match(
            &labels(&[role.clone(), owned.clone()]),
            installation
        ));
        assert!(!installation_labels_match(
            &labels(&[role.clone(), other]),
            installation
        ));
        assert!(!installation_labels_match(&labels(&[owned]), installation));
        assert!(!installation_labels_match(&labels(&[role]), installation));
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
        let temp = tempfile::tempdir().expect("temp");
        let (_paths, record) = fixture(temp.path());
        assert!(!record.config.rosetta);
        assert_eq!(SystemHardware::of_config(&record.config).rosetta, None);
    }

    #[test]
    fn explicit_rosetta_intent_is_a_hardware_update() {
        let temp = tempfile::tempdir().expect("temp");
        let (_paths, mut record) = fixture(temp.path());
        record.config.rosetta = true;
        record.config.rosetta_explicit = true;
        assert_eq!(
            SystemHardware::of_config(&record.config).rosetta,
            Some(true)
        );
    }
}

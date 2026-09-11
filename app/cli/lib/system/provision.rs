use std::time::Duration;

use eyre::{bail, Context as _};
use libvm::{ImageProgressSender, MachineData, MachineStatus, Memory};
use uuid::Uuid;

use crate::api::AppApi;
use crate::system::config::ResolvedSystemConfig;
use crate::system::ownership::is_matching_managed_candidate;
use crate::system::record::{
    load_record, write_record, InstallationRecord, SystemPaths, SystemRecord,
};
use crate::system::storage::{ensure_data_image, validate_data_image};

pub(crate) async fn ensure_system_machine(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: ResolvedSystemConfig,
) -> eyre::Result<(SystemRecord, MachineData)> {
    let installation = prepare_installation(paths, &config)?;

    ensure_system_machine_for_installation(api, paths, config, installation).await
}

pub(crate) fn prepare_installation(
    paths: &SystemPaths,
    config: &ResolvedSystemConfig,
) -> eyre::Result<InstallationRecord> {
    let installation = match load_record::<InstallationRecord>(&paths.installation())? {
        Some(record) => {
            validate_installation(&record, config)?;
            record
        }
        None => {
            let record = InstallationRecord {
                schema: 1,
                installation_id: Uuid::new_v4(),
                data_uuid: Uuid::new_v4(),
                data_layout: 1,
                data_size_bytes: config.data_size_bytes,
                configured_image: config.image.clone(),
                config: config.clone(),
            };
            write_record(&paths.installation(), &record)?;
            record
        }
    };

    ensure_data_image(
        &paths.data_image(),
        installation.data_size_bytes,
        installation.installation_id,
        installation.data_uuid,
    )?;

    Ok(installation)
}

async fn ensure_system_machine_for_installation(
    api: &mut AppApi,
    paths: &SystemPaths,
    config: ResolvedSystemConfig,
    installation: InstallationRecord,
) -> eyre::Result<(SystemRecord, MachineData)> {
    if let Some(mut record) = load_record::<SystemRecord>(&paths.system_record())? {
        validate_system_record(&record, &installation)?;
        let machine = api
            .inspect_machine(&record.active_machine_id)
            .await
            .with_context(|| {
                format!(
                    "recorded system machine {} is missing; refusing to create a replacement",
                    record.active_machine_id
                )
            })?;
        validate_machine(&machine, &record, &paths.data_image())?;
        let machine = reconcile_system_hardware(api, machine, &config).await?;
        if hardware_matches(&machine, &config) {
            // The machine now carries the configured resources; record the configuration
            // they came from so later starts compare against the right baseline.
            if installation.config != config {
                let mut installation = installation;
                installation.config = config.clone();
                write_record(&paths.installation(), &installation)?;
            }
            if record.config_identity != config.identity {
                record.config_identity = config.identity.clone();
                write_record(&paths.system_record(), &record)?;
            }
        }
        return Ok((record, machine));
    }

    let candidates: Vec<_> = api
        .list_machines()
        .await?
        .into_iter()
        .filter(|machine| is_matching_managed_candidate(machine, installation.installation_id))
        .collect();
    let machine = match candidates.as_slice() {
        [] => {
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
        [machine] => reconcile_system_hardware(api, machine.clone(), &config).await?,
        _ => bail!(
            "multiple unrecorded system machines match installation {}; remove ambiguity manually",
            installation.installation_id
        ),
    };
    let rootfs = machine
        .rootfs
        .as_ref()
        .ok_or_else(|| eyre::eyre!("system machine has no durable rootfs identity"))?;
    let record = SystemRecord {
        schema: 1,
        installation_id: installation.installation_id,
        engine: "docker".to_string(),
        active_machine_id: machine.id.clone(),
        image_reference: rootfs
            .selected_reference
            .clone()
            .unwrap_or_else(|| rootfs.requested_reference.clone()),
        image_digest: rootfs
            .selected_manifest_digest
            .clone()
            .ok_or_else(|| eyre::eyre!("system image did not resolve to an immutable digest"))?,
        data_uuid: installation.data_uuid,
        data_layout: installation.data_layout,
        config_identity: config.identity.clone(),
    };
    validate_machine(&machine, &record, &paths.data_image())?;
    write_record(&paths.system_record(), &record)?;
    Ok((record, machine))
}

/// The resource settings the daemon may change between starts: CPUs, memory, Rosetta.
#[derive(Debug, PartialEq, Eq)]
struct SystemHardware {
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    rosetta: bool,
}

impl SystemHardware {
    fn of_machine(machine: &MachineData) -> Self {
        let hardware = machine.spec.hardware.as_ref();
        Self {
            cpus: hardware.and_then(|hardware| hardware.cpus),
            memory_mib: hardware.and_then(|hardware| hardware.memory),
            rosetta: hardware
                .and_then(|hardware| hardware.rosetta)
                .unwrap_or(false),
        }
    }

    fn of_config(config: &ResolvedSystemConfig) -> Self {
        Self {
            cpus: Some(config.cpus),
            memory_mib: u32::try_from(config.memory_bytes / (1024 * 1024)).ok(),
            rosetta: config.rosetta,
        }
    }
}

fn hardware_matches(machine: &MachineData, config: &ResolvedSystemConfig) -> bool {
    SystemHardware::of_machine(machine) == SystemHardware::of_config(config)
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
    if current == desired
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
    if current.rosetta != desired.rosetta {
        update = update.rosetta(config.rosetta);
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
    if let Some(record) = load_record::<SystemRecord>(&paths.system_record())? {
        return match api.inspect_machine(&record.active_machine_id).await {
            Ok(machine) => Ok(Some(machine)),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "recorded system machine {} is missing",
                    record.active_machine_id
                )
            }),
        };
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

fn validate_installation(
    record: &InstallationRecord,
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
    if record.config.image != config.image {
        bail!("system image changes require `silo daemon upgrade --image ...`");
    }
    if record.config.docker_socket != config.docker_socket
        || record.config.publish_bind != config.publish_bind
    {
        bail!("existing system endpoint/publication configuration differs; run daemon down and restore the recorded configuration");
    }
    Ok(())
}

fn validate_system_record(
    record: &SystemRecord,
    installation: &InstallationRecord,
) -> eyre::Result<()> {
    if record.schema != 1
        || record.installation_id != installation.installation_id
        || record.data_uuid != installation.data_uuid
        || record.data_layout != installation.data_layout
    {
        bail!("system record does not match installation/data identity");
    }
    Ok(())
}

fn validate_machine(
    machine: &MachineData,
    record: &SystemRecord,
    data_image: &std::path::Path,
) -> eyre::Result<()> {
    if !is_matching_managed_candidate(machine, record.installation_id)
        || machine.id != record.active_machine_id
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
    match attached.as_slice() {
        [disk] if disk.path == data_image && !disk.read_only => {}
        _ => bail!(
            "recorded system machine does not attach the installation data image {} read-write",
            data_image.display()
        ),
    }
    validate_data_image(
        data_image,
        std::fs::metadata(data_image)?.len(),
        record.installation_id,
        record.data_uuid,
    )
}

#[cfg(test)]
mod tests {
    use crate::system::config::SystemConfig;
    use crate::system::provision::validate_installation;
    use crate::system::record::InstallationRecord;

    #[test]
    fn persisted_data_and_share_changes_fail_closed() {
        let home = tempfile::tempdir().expect("home");
        let config: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem: {}\n").expect("config");
        let resolved = config.resolve(home.path(), None).expect("resolve");
        let record = InstallationRecord {
            schema: 1,
            installation_id: uuid::Uuid::new_v4(),
            data_uuid: uuid::Uuid::new_v4(),
            data_layout: 1,
            data_size_bytes: resolved.data_size_bytes,
            configured_image: resolved.image.clone(),
            config: resolved.clone(),
        };
        assert!(validate_installation(&record, &resolved).is_ok());
        let mut changed = resolved;
        changed.data_size_bytes += 1;
        assert!(validate_installation(&record, &changed).is_err());
    }
}

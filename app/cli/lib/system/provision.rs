use eyre::{bail, Context as _};
use libvm::{ImageProgressSender, MachineData};
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
    if let Some(record) = load_record::<SystemRecord>(&paths.system_record())? {
        validate_system_record(&record, &installation, &config)?;
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
            let source = api.resolve_system_image(&config.image, progress).await?;
            api.create_system_machine(
                crate::system::SYSTEM_MACHINE_NAME,
                &config,
                installation.installation_id,
                &paths.data_image(),
                source,
            )
            .await?
        }
        [machine] => machine.clone(),
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
    config: &ResolvedSystemConfig,
) -> eyre::Result<()> {
    if record.schema != 1
        || record.installation_id != installation.installation_id
        || record.data_uuid != installation.data_uuid
        || record.data_layout != installation.data_layout
    {
        bail!("system record does not match installation/data identity");
    }
    if record.config_identity != config.identity
        && (installation.config.cpus != config.cpus
            || installation.config.memory_bytes != config.memory_bytes)
    {
        bail!(
            "system resources changed; stop the daemon before applying supported resource updates"
        );
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
    if disks.len() != 1 || disks[0].path != data_image || disks[0].read_only {
        bail!("recorded system machine does not attach the installation data image read-write");
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

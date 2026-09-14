use std::path::PathBuf;

use eyre::bail;
use libvm::MachineData;

use crate::system::record::{load_record, SystemRecord};
use crate::system::{INSTALLATION_LABEL, MANAGED_ROLE, MANAGED_ROLE_LABEL};

pub(crate) fn guard_ordinary_mutation(machine: &MachineData) -> eyre::Result<()> {
    let Some(record) = load_default_system_record()? else {
        return Ok(());
    };
    if machine.id == record.active_machine_id {
        bail!("machine {:?} is managed by the Silo system daemon; use `silo daemon down`, `upgrade`, or system configuration instead", machine.name);
    }
    if crate::system::upgrade::is_pending_candidate(&default_system_paths()?, &machine.id)? {
        bail!("machine {:?} belongs to a pending system image upgrade; run `silo daemon upgrade --recover`", machine.name);
    }
    Ok(())
}

pub(crate) fn guard_ordinary_machine_id(machine_id: &str) -> eyre::Result<()> {
    let Some(record) = load_default_system_record()? else {
        return Ok(());
    };
    if machine_id == record.active_machine_id {
        bail!("machine {machine_id:?} is managed by the Silo system daemon; use `silo daemon down` instead");
    }
    if crate::system::upgrade::is_pending_candidate(&default_system_paths()?, machine_id)? {
        bail!("machine {machine_id:?} belongs to a pending system image upgrade; run `silo daemon upgrade --recover`");
    }
    Ok(())
}

/// Returns the persisted backend policy only when `machine_id` is the active machine
/// owned by this daemon installation. Shell environment is deliberately irrelevant.
pub(crate) fn managed_system_backend(
    machine_id: &str,
) -> eyre::Result<Option<crate::system::config::SystemBackend>> {
    managed_system_backend_at(machine_id, &default_system_paths()?)
}

fn managed_system_backend_at(
    machine_id: &str,
    paths: &crate::system::record::SystemPaths,
) -> eyre::Result<Option<crate::system::config::SystemBackend>> {
    let Some(record) = load_record::<SystemRecord>(&paths.system_record())? else {
        return Ok(None);
    };
    if record.active_machine_id != machine_id {
        return Ok(None);
    }

    if let Some(registration) =
        crate::system::service::load_optional_registration(&paths.registration())?
    {
        if registration.installation_id != record.installation_id {
            bail!("daemon registration does not match the active system machine installation");
        }
        return Ok(Some(registration.config.backend));
    }

    let installation =
        load_record::<crate::system::record::InstallationRecord>(&paths.installation())?
            .ok_or_else(|| {
                eyre::eyre!("active system machine has no installation configuration")
            })?;
    if installation.installation_id != record.installation_id {
        bail!("system installation does not match the active system machine");
    }
    Ok(Some(installation.config.backend))
}

pub(crate) fn is_matching_managed_candidate(
    machine: &MachineData,
    installation_id: uuid::Uuid,
) -> bool {
    labels_match(&machine.labels, installation_id)
}

fn labels_match(
    labels: &std::collections::BTreeMap<String, String>,
    installation_id: uuid::Uuid,
) -> bool {
    labels.get(MANAGED_ROLE_LABEL).map(String::as_str) == Some(MANAGED_ROLE)
        && labels.get(INSTALLATION_LABEL) == Some(&installation_id.to_string())
}

fn load_default_system_record() -> eyre::Result<Option<SystemRecord>> {
    let data = xdg_root("XDG_DATA_HOME", ".local/share")?.join("silo/daemon/system.json");
    load_record(&data)
}

pub(crate) fn default_system_paths() -> eyre::Result<crate::system::record::SystemPaths> {
    let config = xdg_root("XDG_CONFIG_HOME", ".config")?.join("silo");
    let data = xdg_root("XDG_DATA_HOME", ".local/share")?.join("silo");
    let state = xdg_root("XDG_STATE_HOME", ".local/state")?.join("silo");
    // libvm unpacks images under the data root by default. Mirror that so the roots
    // recorded for the native service match the state database that ordinary CLI use
    // created; the service itself runs without the shell's XDG environment.
    let image = data.join("images");
    let run = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(value) => absolute("XDG_RUNTIME_DIR", value)?.join("silo"),
        None => PathBuf::from(format!("/tmp/silo-{}", nix::unistd::geteuid().as_raw())),
    };
    Ok(crate::system::record::SystemPaths::new(
        config, data, state, run, image,
    ))
}

fn xdg_root(name: &'static str, fallback: &str) -> eyre::Result<PathBuf> {
    if let Some(value) = std::env::var_os(name) {
        return absolute(name, value);
    }
    let home = std::env::var_os("HOME")
        .ok_or_else(|| eyre::eyre!("HOME is required to resolve {name}"))?;
    Ok(absolute("HOME", home)?.join(fallback))
}

fn absolute(name: &'static str, value: std::ffi::OsString) -> eyre::Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!(
            "environment variable {name} must be absolute: {}",
            path.display()
        );
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::system::ownership::{labels_match, managed_system_backend_at};
    use crate::system::record::{write_record, InstallationRecord, SystemPaths, SystemRecord};
    use crate::system::{INSTALLATION_LABEL, MANAGED_ROLE, MANAGED_ROLE_LABEL};

    #[test]
    fn candidate_requires_both_unspoofable_record_values() {
        let installation = uuid::Uuid::new_v4();
        let mut labels = BTreeMap::new();
        assert!(!labels_match(&labels, installation));
        labels = BTreeMap::from([
            (MANAGED_ROLE_LABEL.to_string(), MANAGED_ROLE.to_string()),
            (INSTALLATION_LABEL.to_string(), installation.to_string()),
        ]);
        assert!(labels_match(&labels, installation));
    }

    #[test]
    fn managed_backend_comes_from_persisted_system_identity() {
        let temp = tempfile::tempdir().expect("temp");
        let paths = SystemPaths::new(
            temp.path().join("config"),
            temp.path().join("data"),
            temp.path().join("state"),
            temp.path().join("run"),
            temp.path().join("images"),
        );
        let home = temp.path().join("home");
        std::fs::create_dir(&home).expect("home");
        let config: crate::system::config::SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nbackend: krun\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        let resolved = config.resolve(&home, None).expect("resolve");
        let installation_id = uuid::Uuid::new_v4();
        let data_uuid = uuid::Uuid::new_v4();
        write_record(
            &paths.installation(),
            &InstallationRecord {
                schema: 1,
                installation_id,
                data_uuid,
                data_layout: 1,
                data_size_bytes: resolved.data_size_bytes,
                configured_image: resolved.image.clone(),
                config: resolved,
            },
        )
        .expect("installation");
        write_record(
            &paths.system_record(),
            &SystemRecord {
                schema: 1,
                installation_id,
                engine: "docker".to_string(),
                active_machine_id: "system-machine".to_string(),
                image_reference: "image".to_string(),
                image_digest: "digest".to_string(),
                data_uuid,
                data_layout: 1,
                config_identity: "identity".to_string(),
            },
        )
        .expect("system record");

        assert_eq!(
            managed_system_backend_at("system-machine", &paths).expect("managed backend"),
            Some(crate::system::config::SystemBackend::Krun)
        );
        assert_eq!(
            managed_system_backend_at("ordinary-machine", &paths).expect("ordinary backend"),
            None
        );
    }
}

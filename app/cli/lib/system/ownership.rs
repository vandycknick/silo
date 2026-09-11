use std::path::{Path, PathBuf};

use eyre::{bail, Context as _};
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
    Ok(())
}

pub(crate) fn guard_ordinary_machine_id(machine_id: &str) -> eyre::Result<()> {
    let Some(record) = load_default_system_record()? else {
        return Ok(());
    };
    if machine_id == record.active_machine_id {
        bail!("machine {machine_id:?} is managed by the Silo system daemon; use `silo daemon down` instead");
    }
    Ok(())
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
    let run = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(value) => absolute("XDG_RUNTIME_DIR", value)?.join("silo"),
        None => PathBuf::from(format!("/tmp/silo-{}", nix::unistd::geteuid().as_raw())),
    };
    Ok(crate::system::record::SystemPaths::new(
        config, data, state, run,
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

pub(crate) fn require_local_path(path: &Path) -> eyre::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::system::ownership::labels_match;
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
}

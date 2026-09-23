use eyre::bail;
use libvm::MachineData;

use crate::system::record::DaemonRecord;
use crate::system::{INSTALLATION_LABEL, MANAGED_ROLE, MANAGED_ROLE_LABEL};

pub(crate) fn guard_ordinary_mutation(machine: &MachineData) -> eyre::Result<()> {
    if let Some(state) = DaemonRecord::load(&default_system_paths()?)? {
        if is_matching_managed_candidate(machine, state.installation_id)
            || state.owns_machine(&machine.id)
        {
            bail!("machine {:?} is managed by the Silo system daemon; use `silo daemon down` or `upgrade` instead", machine.name);
        }
    }
    Ok(())
}

pub(crate) fn guard_ordinary_machine_id(machine_id: &str) -> eyre::Result<()> {
    if let Some(state) = DaemonRecord::load(&default_system_paths()?)? {
        if state.owns_machine(machine_id) {
            bail!("machine {machine_id:?} is managed by the Silo system daemon; use `silo daemon down` or `upgrade` instead");
        }
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

pub(crate) fn default_system_paths() -> eyre::Result<crate::system::record::SystemPaths> {
    // The native service runs without the shell's environment, so it records the
    // resolved config directory and home instead of re-resolving them.
    let host = libvm::HostPaths::from_env()?;
    Ok(crate::system::record::SystemPaths::new(
        host.config_dir().to_path_buf(),
        host.home().to_path_buf(),
        libvm::HostPaths::run_root(),
    ))
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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use libvm::{MachineData, MachineNetworkConfig, MachineStatus};
use serde::Serialize;
use vm_spec::VmSpec;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MachineView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) state: &'static str,
    pub(crate) default: bool,
    pub(crate) profile: Option<String>,
    pub(crate) image: String,
    pub(crate) network: MachineNetworkConfig,
    pub(crate) created_at: i64,
    pub(crate) modified_at: i64,
    pub(crate) started_at: Option<i64>,
    pub(crate) updated_at: i64,
    pub(crate) root_disk_size: Option<u64>,
    pub(crate) resources: MachineResourcesView,
    pub(crate) guest: MachineGuestView,
    pub(crate) ready: bool,
    pub(crate) summary: Option<String>,
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) dir: PathBuf,
    pub(crate) spec: VmSpec,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MachineResourcesView {
    pub(crate) cpus: u8,
    pub(crate) memory_mib: u32,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MachineGuestView {
    pub(crate) status: String,
    pub(crate) ready: bool,
    pub(crate) settings: MachineGuestSettingsView,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MachineGuestSettingsView {
    pub(crate) bootstrap: bool,
    pub(crate) initramfs_present: bool,
}

impl MachineView {
    pub(crate) fn new(data: &MachineData, default: bool) -> Self {
        let hardware = data.spec.hardware.as_ref();
        let summary = data.status.message().map(str::to_string);

        Self {
            id: data.id.clone(),
            name: data.name.clone(),
            state: state_label(&data.status),
            default,
            profile: data.metadata.get(PROFILE_METADATA_KEY).cloned(),
            image: data.image_ref.clone(),
            network: data.network.clone(),
            created_at: data.created_at,
            modified_at: data.modified_at,
            started_at: data.started_at,
            updated_at: data.updated_at,
            root_disk_size: data.root_disk_size,
            resources: MachineResourcesView {
                cpus: hardware.and_then(|hardware| hardware.cpus).unwrap_or(1),
                memory_mib: hardware.and_then(|hardware| hardware.memory).unwrap_or(512),
            },
            guest: MachineGuestView {
                status: data.status.label().to_string(),
                ready: data.status.guest_ready(),
                settings: guest_settings(&data.spec, &data.machine_dir),
            },
            ready: data.status.ready(),
            summary,
            labels: data.labels.clone(),
            metadata: data.metadata.clone(),
            dir: data.machine_dir.clone(),
            spec: data.spec.clone(),
        }
    }
}

pub(crate) fn state_label(state: &MachineStatus) -> &'static str {
    state.label()
}

fn guest_settings(spec: &VmSpec, machine_dir: &Path) -> MachineGuestSettingsView {
    MachineGuestSettingsView {
        bootstrap: spec
            .boot
            .as_ref()
            .and_then(|boot| boot.userdata.as_deref())
            .is_some(),
        initramfs_present: initramfs_path_exists(spec, machine_dir),
    }
}

fn initramfs_path_exists(spec: &VmSpec, machine_dir: &Path) -> bool {
    let Some(initramfs) = spec
        .boot
        .as_ref()
        .and_then(|boot| boot.kernel.as_ref())
        .and_then(|kernel| kernel.initramfs.as_deref())
    else {
        return false;
    };

    if initramfs.is_absolute() {
        initramfs.is_file()
    } else {
        machine_dir.join(initramfs).is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::state_label;
    use libvm::MachineStatus;

    #[test]
    fn labels_machine_states() {
        assert_eq!(state_label(&MachineStatus::Stopped), "stopped");
        assert_eq!(
            state_label(&MachineStatus::Starting { message: None }),
            "starting"
        );
        assert_eq!(
            state_label(&MachineStatus::Running {
                guest_ready: false,
                message: None,
            }),
            "running"
        );
        assert_eq!(
            state_label(&MachineStatus::Stopping { message: None }),
            "stopping"
        );
        assert_eq!(
            state_label(&MachineStatus::Error { message: None }),
            "error"
        );
    }
}

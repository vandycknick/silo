use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use libvm::{
    MachineAgent, MachineBootReport, MachineData, MachineNetworkConfig, MachineProvisionReport,
    MachineStatus, MachineUserConfig,
};
use serde::Serialize;
use vm_spec::VmSpec;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Debug, Clone, Serialize)]
pub struct MachineView {
    pub id: String,
    pub name: String,
    pub state: &'static str,
    pub default: bool,
    pub profile: Option<String>,
    pub image: String,
    pub network: MachineNetworkConfig,
    pub created_at: i64,
    pub modified_at: i64,
    pub started_at: Option<i64>,
    pub updated_at: i64,
    pub root_disk_size: Option<u64>,
    pub resources: MachineResourcesView,
    pub guest: MachineGuestView,
    pub ready: bool,
    pub summary: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub dir: PathBuf,
    pub spec: VmSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineResourcesView {
    pub cpus: u8,
    pub memory_mib: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineGuestView {
    pub status: String,
    pub ready: bool,
    pub settings: MachineGuestSettingsView,
    pub boot: Option<MachineGuestBootReportView>,
    pub provision: Option<MachineGuestProvisionReportView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineGuestSettingsView {
    pub bootstrap: bool,
    pub initramfs_present: bool,
    pub agent: String,
    pub agent_path: Option<PathBuf>,
    pub user: Option<MachineUserConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineGuestBootReportView {
    pub mode: String,
    pub requested_init: Option<String>,
    pub handoff_init_path: Option<String>,
    pub agent_pid: u32,
    pub agent_is_pid1: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineGuestProvisionReportView {
    pub status: String,
    pub step_count: usize,
    pub failed_step_count: usize,
    pub duration_ms: u64,
    pub message: Option<String>,
}

impl MachineView {
    pub fn new(data: &MachineData, default: bool) -> Self {
        let hardware = data.spec.hardware.as_ref();
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
                settings: guest_settings(data),
                boot: data
                    .boot_report
                    .as_ref()
                    .map(MachineGuestBootReportView::new),
                provision: data
                    .provision_report
                    .as_ref()
                    .map(MachineGuestProvisionReportView::new),
            },
            ready: data.status.ready(),
            summary: data.status.message().map(str::to_string),
            labels: data.labels.clone(),
            metadata: data.metadata.clone(),
            dir: data.machine_dir.clone(),
            spec: data.spec.clone(),
        }
    }
}

impl MachineGuestBootReportView {
    fn new(report: &MachineBootReport) -> Self {
        Self {
            mode: report.mode.label().to_string(),
            requested_init: report.requested_init.clone(),
            handoff_init_path: report.handoff_init_path.clone(),
            agent_pid: report.agent_pid,
            agent_is_pid1: report.agent_is_pid1,
            message: report.message.clone(),
        }
    }
}

impl MachineGuestProvisionReportView {
    fn new(report: &MachineProvisionReport) -> Self {
        Self {
            status: report.status.label().to_string(),
            step_count: report.steps.len(),
            failed_step_count: report.failed_step_count(),
            duration_ms: report.duration_ms,
            message: report.message.clone(),
        }
    }
}

pub fn state_label(state: &MachineStatus) -> &'static str {
    state.label()
}

fn guest_settings(data: &MachineData) -> MachineGuestSettingsView {
    let (agent, agent_path) = match &data.guest.agent {
        MachineAgent::Default => ("default", None),
        MachineAgent::Custom { path } => ("custom", Some(path.clone())),
        MachineAgent::Disabled => ("disabled", None),
        _ => ("unknown", None),
    };
    MachineGuestSettingsView {
        bootstrap: data
            .spec
            .boot
            .as_ref()
            .and_then(|boot| boot.userdata.as_deref())
            .is_some(),
        initramfs_present: initramfs_path_exists(&data.spec, &data.machine_dir),
        agent: agent.to_string(),
        agent_path,
        user: data.guest.user.clone(),
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

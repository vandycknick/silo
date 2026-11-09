use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use libvm::{
    ImageSourceKind, MachineAgent, MachineBootReport, MachineData, MachineNetworkConfig,
    MachineProvisionReport, MachineRetention, MachineRootfs, MachineStatus, MachineUserConfig,
    ProcessConfig,
};
use serde::Serialize;
use vm_spec::VmSpec;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum InventoryView {
    Available(Box<MachineView>),
    Unavailable {
        id: String,
        name: String,
        state: &'static str,
        observation: libvm::MachineObservation,
        issues: Vec<libvm::MachineIssue>,
    },
}

impl InventoryView {
    pub fn new(entry: &libvm::MachineInventoryEntry, default: bool) -> Self {
        match &entry.data {
            Some(data) => Self::Available(Box::new(MachineView::new(data, default))),
            None => Self::Unavailable {
                id: entry.id.clone(),
                name: entry.name.clone(),
                state: "unknown",
                observation: libvm::MachineObservation::Unavailable,
                issues: entry.issues.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineView {
    pub id: String,
    pub name: String,
    pub state: &'static str,
    pub durability: libvm::MachineDurability,
    pub observation: libvm::MachineObservation,
    pub last_known_state: Option<&'static str>,
    pub issues: Vec<libvm::MachineIssue>,
    pub last_error: Option<String>,
    pub run_id: Option<String>,
    /// Observed terminal storage result; read-only inspection need not persist it.
    pub storage_stop_outcome: Option<libvm::StorageStopOutcome>,
    pub live: Option<vm_spec::live::LiveMachineReport>,
    pub prospective_live: Option<vm_spec::live::LiveHostReport>,
    pub lifecycle: Option<libvm::MachineLifecycle>,
    pub default: bool,
    pub template_name: Option<String>,
    pub retention: String,
    pub process: ProcessConfig,
    pub rootfs: Option<MachineRootfsView>,
    pub agent_mode: String,
    pub image: String,
    pub network: MachineNetworkConfig,
    pub tailscale: Option<libvm::MachineTailscale>,
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
    /// Pinned direct-boot meaning; start never switches bundles implicitly.
    pub boot: Option<MachineBootView>,
}

/// The machine's pinned boot bundle and platform, plus a newer locally
/// admitted packaged bundle when one exists. Observation only, no mutation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineBootView {
    pub platform: String,
    pub kernel_architecture: String,
    pub translation: String,
    /// Explicit Rosetta intent; absent is no intent, false is an explicit disable.
    pub rosetta_intent: Option<bool>,
    pub root: String,
    pub root_filesystem: String,
    pub bundle: Option<String>,
    pub kernel: Option<String>,
    pub base_initramfs: Option<String>,
    pub agent: Option<String>,
    pub abi: Option<String>,
    pub packaged_replacement: Option<String>,
}

impl MachineBootView {
    fn new(data: &MachineData) -> Option<Self> {
        let libvm::BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            binding,
            root_selector,
            root_filesystem,
            translation,
            ..
        } = data.boot_profile.as_ref()?
        else {
            return None;
        };
        let architecture = |value: &libvm::GuestArchitecture| match value {
            libvm::GuestArchitecture::Amd64 => "amd64",
            libvm::GuestArchitecture::Arm64 => "arm64",
        };
        let mut platform = format!("linux/{}", architecture(&userspace_platform.architecture));
        if let Some(variant) = &userspace_platform.variant {
            platform.push('/');
            platform.push_str(variant);
        }
        let (bundle, kernel, base_initramfs, agent, abi) = match binding {
            libvm::BootBinding::Pinned {
                kernel,
                base_initramfs,
                agent,
                abi,
                ..
            } => (
                binding.digest().ok().map(|digest| digest.to_string()),
                Some(kernel.to_string()),
                Some(base_initramfs.to_string()),
                agent.map(|agent| agent.to_string()),
                Some(abi.clone()),
            ),
            libvm::BootBinding::RuntimeSelected => (None, None, None, None, None),
        };
        Some(Self {
            platform,
            kernel_architecture: architecture(kernel_architecture).to_string(),
            translation: match translation {
                libvm::Translation::None => "none",
                libvm::Translation::Rosetta => "rosetta",
            }
            .to_string(),
            rosetta_intent: data
                .spec
                .hardware
                .as_ref()
                .and_then(|hardware| hardware.rosetta),
            root: match root_selector {
                libvm::RootSelector::ManagedOverlay => "managed-overlay".to_string(),
                libvm::RootSelector::WholeDisk => "whole-disk".to_string(),
                libvm::RootSelector::GptPartition { guid } => format!("gpt:{guid}"),
                libvm::RootSelector::MbrPartition { number } => format!("mbr:{number}"),
            },
            root_filesystem: match root_filesystem {
                libvm::RootFilesystem::Ext4 => "ext4",
            }
            .to_string(),
            bundle,
            kernel,
            base_initramfs,
            agent,
            abi,
            packaged_replacement: data.boot_replacement.map(|digest| digest.to_string()),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineResourcesView {
    pub cpus: u8,
    pub memory_mib: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineRootfsView {
    pub source_kind: String,
    pub requested_reference: String,
    pub selected_reference: Option<String>,
    pub selected_manifest_digest: Option<String>,
    pub config_digest: Option<String>,
    pub image_id: Option<String>,
    pub root_disk_path: PathBuf,
    pub root_disk_size_bytes: u64,
    pub created_at: i64,
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
            tailscale: data.tailscale.clone(),
            name: data.name.clone(),
            state: if data.observation == libvm::MachineObservation::Observed {
                state_label(&data.status)
            } else {
                "unknown"
            },
            durability: data.durability,
            observation: data.observation,
            last_known_state: (data.observation == libvm::MachineObservation::LastKnown)
                .then(|| state_label(&data.status)),
            issues: data.issues.clone(),
            last_error: data.last_error.clone(),
            run_id: data.run_id.as_ref().map(ToString::to_string),
            storage_stop_outcome: data.storage_stop_outcome,
            live: data.live.clone(),
            prospective_live: data.prospective_live.clone(),
            lifecycle: data.lifecycle.clone(),
            default,
            template_name: data.template_name.clone(),
            retention: retention_label(data.retention).to_string(),
            process: data.process.clone(),
            rootfs: data.rootfs.as_ref().map(MachineRootfsView::new),
            agent_mode: agent_label(data.agent_mode.as_ref()).to_string(),
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
            boot: MachineBootView::new(data),
        }
    }
}

impl MachineRootfsView {
    fn new(rootfs: &MachineRootfs) -> Self {
        Self {
            source_kind: image_source_kind_label(rootfs.source_kind).to_string(),
            requested_reference: rootfs.requested_reference.clone(),
            selected_reference: rootfs.selected_reference.clone(),
            selected_manifest_digest: rootfs.selected_manifest_digest.clone(),
            config_digest: rootfs.config_digest.clone(),
            image_id: rootfs.image_id.clone(),
            root_disk_path: rootfs.root_disk_path.clone(),
            root_disk_size_bytes: rootfs.root_disk_size_bytes,
            created_at: rootfs.created_at,
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

pub fn retention_label(retention: MachineRetention) -> &'static str {
    match retention {
        MachineRetention::Persistent => "persistent",
        MachineRetention::Ephemeral => "ephemeral",
    }
}

pub fn agent_label(agent: Option<&MachineAgent>) -> &'static str {
    match agent {
        Some(MachineAgent::Default) => "default",
        Some(MachineAgent::Custom { .. }) => "custom",
        Some(MachineAgent::Disabled) => "disabled",
        Some(_) | None => "unknown",
    }
}

fn image_source_kind_label(source: ImageSourceKind) -> &'static str {
    match source {
        ImageSourceKind::Oci => "oci",
        ImageSourceKind::Disk => "disk",
        ImageSourceKind::Managed => "managed",
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
    use libvm::{MachineAgent, MachineRetention};

    use crate::view::{agent_label, retention_label};

    #[test]
    fn unavailable_inventory_preserves_identity_and_diagnostics_in_json() {
        let entry = libvm::MachineInventoryEntry {
            id: "broken-id".into(),
            name: "broken".into(),
            data: None,
            issues: vec![libvm::MachineIssue {
                component: libvm::MachineIssueComponent::Configuration,
                message: "cannot decode configuration".into(),
            }],
        };
        let value = serde_json::to_value(crate::view::InventoryView::new(&entry, false))
            .expect("serialize");
        assert_eq!(value["state"], "unknown");
        assert_eq!(value["name"], "broken");
        assert_eq!(value["observation"], "unavailable");
        assert_eq!(value["issues"][0]["component"], "configuration");
        assert!(value.get("resources").is_none());
    }

    #[test]
    fn machine_view_serializes_machine_durability() {
        let mut data = libvm::MachineData::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "dev".into(),
            vm_spec::VmSpec::current(),
        );
        assert_eq!(data.durability, libvm::MachineDurability::Durable);
        for (durability, expected) in [
            (libvm::MachineDurability::Durable, "durable"),
            (libvm::MachineDurability::Constructed, "constructed"),
        ] {
            data.durability = durability;
            let view = crate::view::MachineView::new(&data, false);
            assert_eq!(view.durability, durability);
            let value = serde_json::to_value(&view).expect("serialize machine view");
            assert_eq!(value["durability"], expected);
            let entry = libvm::MachineInventoryEntry {
                id: data.id.clone(),
                name: data.name.clone(),
                data: Some(data.clone()),
                issues: Vec::new(),
            };
            let value = serde_json::to_value(crate::view::InventoryView::new(&entry, false))
                .expect("serialize info inventory view");
            assert_eq!(value["durability"], expected);
        }
    }

    #[test]
    fn labels_persisted_machine_lifecycle_fields() {
        assert_eq!(retention_label(MachineRetention::Ephemeral), "ephemeral");
        assert_eq!(retention_label(MachineRetention::Persistent), "persistent");
        assert_eq!(agent_label(Some(&MachineAgent::Default)), "default");
        assert_eq!(agent_label(Some(&MachineAgent::Disabled)), "disabled");
    }

    #[test]
    fn pinned_bundle_platform_and_replacement_are_visible() {
        let digest = |byte: &str| -> libvm::storage::identity::ObjectDigest {
            format!("sha256:{}", byte.repeat(32)).parse().unwrap()
        };
        let binding = libvm::BootBinding::Pinned {
            kernel: digest("01"),
            base_initramfs: digest("02"),
            agent: Some(digest("03")),
            architecture: libvm::GuestArchitecture::Arm64,
            abi: "silo-direct-v1".into(),
        };
        let mut data = libvm::MachineData::new(
            "00000000-0000-4000-8000-000000000001".into(),
            "dev".into(),
            vm_spec::VmSpec::current(),
        );
        data.boot_profile = Some(libvm::BootProfile::LinuxDirect {
            userspace_platform: libvm::LinuxPlatform {
                architecture: libvm::GuestArchitecture::Amd64,
                variant: None,
            },
            kernel_architecture: libvm::GuestArchitecture::Arm64,
            command_line_policy: libvm::DirectCommandLinePolicy::SiloDirectV1,
            binding: binding.clone(),
            root_selector: libvm::RootSelector::MbrPartition { number: 2 },
            root_filesystem: libvm::RootFilesystem::Ext4,
            translation: libvm::Translation::Rosetta,
        });
        data.boot_replacement = Some(digest("04"));
        let boot = crate::view::MachineView::new(&data, false)
            .boot
            .expect("pinned boot view");
        assert_eq!(boot.platform, "linux/amd64");
        assert_eq!(boot.kernel_architecture, "arm64");
        assert_eq!(boot.translation, "rosetta");
        assert_eq!(boot.root, "mbr:2");
        assert_eq!(boot.bundle, Some(binding.digest().unwrap().to_string()));
        assert_eq!(boot.agent, Some(digest("03").to_string()));
        assert_eq!(boot.packaged_replacement, Some(digest("04").to_string()));
    }
}

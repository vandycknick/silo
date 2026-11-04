use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use vm_spec::{DiskGeometry, DiskRole};

use crate::storage::identity::{ImageId, LowerResultId, ObjectDigest, SnapshotId, StreamId};
use crate::LibVmError;

/// A machine-owned path, relative to its private directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PathBuf", into = "PathBuf")]
pub struct PrivatePath(PathBuf);

impl PrivatePath {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, LibVmError> {
        let path = path.into();
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(LibVmError::InvalidStorageRecord {
                record: "private-path",
                message: format!("{} is not a relative private path", path.display()),
            });
        }
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl TryFrom<PathBuf> for PrivatePath {
    type Error = LibVmError;
    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}
impl From<PrivatePath> for PathBuf {
    fn from(path: PrivatePath) -> Self {
        path.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum MachineRoot {
    /// `initial_content` describes creation bytes only, never the current
    /// mutable disk after a run or resize.
    OpaqueRaw {
        path: PrivatePath,
        geometry: DiskGeometry,
        layout: RawLayout,
        initial_content: Option<StreamId>,
    },
    LinuxOverlay {
        lower: OverlayLower,
        upper: PrivatePath,
        upper_uuid: uuid::Uuid,
        capacity: u64,
        ext4_profile: Ext4Profile,
        overlay_profile: OverlayProfile,
        temporary_directory: TemporaryDirectoryPolicy,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RawLayout {
    WholeDisk,
    Partitioned { table: PartitionTable },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionTable {
    Gpt,
    Mbr,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OverlayLower {
    FlatExt4 {
        stream: StreamId,
        geometry: DiskGeometry,
        filesystem_uuid: uuid::Uuid,
    },
    ErofsComposition {
        record: LowerResultId,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ext4Profile {
    SiloUpperExt4V1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverlayProfile {
    SiloOverlayV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProfile {
    OpaqueRawV1,
    LinuxOverlayV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendRequirement {
    RawBlock,
    KrunOverlay,
}
/// Explicit persistent selection for the final root's temporary directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TemporaryDirectoryPolicy {
    DiskBacked,
    Tmpfs { capacity_bytes: u64 },
}

impl TemporaryDirectoryPolicy {
    pub fn validate(self) -> Result<(), LibVmError> {
        let wire = match self {
            Self::DiskBacked => rootfs_spec::TemporaryDirectory::DiskBacked,
            Self::Tmpfs { capacity_bytes } => {
                rootfs_spec::TemporaryDirectory::Tmpfs { capacity_bytes }
            }
        };
        wire.validate().map_err(|error| invalid(error.to_string()))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootFileRole {
    Kernel,
    BaseInitramfs,
    Agent,
    HardwareModel,
    MachineIdentifier,
    AuxiliaryStorage,
    EfiVariables,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskOwnership {
    ManagedWritable,
    ManagedReadOnly,
    External,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageStopOutcome {
    Clean,
    Forced,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuestArchitecture {
    Amd64,
    Arm64,
}

impl GuestArchitecture {
    fn parse(value: &str) -> Result<Self, LibVmError> {
        match value {
            "amd64" | "x86_64" => Ok(Self::Amd64),
            "arm64" | "aarch64" => Ok(Self::Arm64),
            _ => Err(invalid(format!("unsupported guest architecture {value:?}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxPlatform {
    pub architecture: GuestArchitecture,
    pub variant: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectCommandLinePolicy {
    SiloDirectV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Translation {
    None,
    Rosetta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RootSelector {
    ManagedOverlay,
    WholeDisk,
    GptPartition { guid: uuid::Uuid },
    MbrPartition { number: u8 },
}

/// Runtime-selected local boot assets are not claimed to be content-pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BootBinding {
    RuntimeSelected,
    Pinned {
        kernel: ObjectDigest,
        base_initramfs: ObjectDigest,
        agent: Option<ObjectDigest>,
        architecture: GuestArchitecture,
        abi: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BootProfile {
    LinuxDirect {
        userspace_platform: LinuxPlatform,
        kernel_architecture: GuestArchitecture,
        command_line_policy: DirectCommandLinePolicy,
        binding: BootBinding,
        root_selector: RootSelector,
        translation: Translation,
    },
    LinuxEfi {
        architecture: GuestArchitecture,
        firmware: EfiFirmware,
        variable_store: PrivatePath,
    },
    MacOs {
        hardware_model: PrivatePath,
        machine_identifier: PrivatePath,
        auxiliary_storage: PrivatePath,
        compatibility: String,
    },
}

impl BootProfile {
    pub fn validate(&self) -> Result<(), LibVmError> {
        if let Self::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            translation,
            binding,
            ..
        } = self
        {
            let translated = matches!(
                (
                    userspace_platform.architecture,
                    kernel_architecture,
                    translation
                ),
                (
                    GuestArchitecture::Amd64,
                    GuestArchitecture::Arm64,
                    Translation::Rosetta
                )
            );
            if !translated
                && (userspace_platform.architecture != *kernel_architecture
                    || *translation != Translation::None)
            {
                return Err(invalid("inconsistent userspace, kernel and translation"));
            }
            if let BootBinding::Pinned {
                architecture, abi, ..
            } = binding
            {
                if architecture != kernel_architecture || abi.is_empty() {
                    return Err(invalid("boot bundle architecture or ABI does not match"));
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EfiFirmware {
    VzEfi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IncludedDisk {
    pub id: uuid::Uuid,
    pub role: DiskRole,
    pub order: u32,
    pub storage: DiskStorage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DiskStorage {
    ManagedWritable {
        path: PrivatePath,
        geometry: DiskGeometry,
    },
    ManagedReadOnly {
        stream: StreamId,
        geometry: DiskGeometry,
    },
}

impl DiskStorage {
    pub fn ownership(&self) -> DiskOwnership {
        match self {
            Self::ManagedWritable { .. } => DiskOwnership::ManagedWritable,
            Self::ManagedReadOnly { .. } => DiskOwnership::ManagedReadOnly,
        }
    }
}

/// A local mapping derived from the authoritative VM specification, not an
/// owned disk or a self-contained artifact dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ExternalResource {
    Disk {
        role: DiskRole,
        order: usize,
        path: PathBuf,
        read_only: bool,
    },
    Share {
        source: PathBuf,
        tag: String,
        read_only: bool,
    },
}

impl ExternalResource {
    pub(crate) fn from_spec(spec: &vm_spec::VmSpec) -> Vec<Self> {
        let mut resources = Vec::new();
        if let Some(storage) = &spec.storage {
            resources.extend(
                storage
                    .disks
                    .iter()
                    .enumerate()
                    .filter(|(_, disk)| disk.role == DiskRole::Data)
                    .map(|(order, disk)| Self::Disk {
                        role: disk.role,
                        order,
                        path: disk.path.clone(),
                        read_only: disk.read_only,
                    }),
            );
        }
        resources.extend(spec.mounts.iter().map(|mount| Self::Share {
            source: mount.source.clone(),
            tag: mount.tag.clone(),
            read_only: mount.read_only,
        }));
        resources
    }
}

/// Durable storage meaning, independent of source provenance and launch files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineStorageRecord {
    pub schema: u32,
    pub root: MachineRoot,
    pub boot: BootProfile,
    pub profile: StorageProfile,
    pub backend: BackendRequirement,
    pub disks: Vec<IncludedDisk>,
    pub external_requirements: Vec<crate::ExternalResourceRequirement>,
    pub storage_generation: u64,
    pub ownership_epoch: u64,
    pub stop_outcome: StorageStopOutcome,
    pub relocation_operation: Option<uuid::Uuid>,
    pub fence: Option<FenceRecord>,
    pub operation: Option<StorageOperationRecord>,
    pub image: Option<ImageId>,
    pub snapshot: Option<SnapshotId>,
}

impl MachineStorageRecord {
    pub(crate) fn opaque_raw(
        path: PrivatePath,
        length: u64,
        platform: &oci::Platform,
    ) -> Result<Self, LibVmError> {
        if platform.os != "linux" {
            return Err(invalid("direct boot requires Linux userspace"));
        }
        let userspace = GuestArchitecture::parse(&platform.architecture)?;
        let kernel = GuestArchitecture::parse(std::env::consts::ARCH)?;
        let translation = match (userspace, kernel) {
            (GuestArchitecture::Amd64, GuestArchitecture::Arm64) if cfg!(target_os = "macos") => {
                Translation::Rosetta
            }
            (left, right) if left == right => Translation::None,
            _ => {
                return Err(invalid(
                    "userspace and kernel architectures have no admitted translation",
                ))
            }
        };
        let record = Self {
            schema: 1,
            root: MachineRoot::OpaqueRaw {
                path,
                geometry: DiskGeometry {
                    length,
                    logical_sector_size: 512,
                },
                layout: RawLayout::WholeDisk,
                initial_content: None,
            },
            boot: BootProfile::LinuxDirect {
                userspace_platform: LinuxPlatform {
                    architecture: userspace,
                    variant: platform.variant.clone(),
                },
                kernel_architecture: kernel,
                command_line_policy: DirectCommandLinePolicy::SiloDirectV1,
                binding: BootBinding::RuntimeSelected,
                root_selector: RootSelector::WholeDisk,
                translation,
            },
            profile: StorageProfile::OpaqueRawV1,
            backend: BackendRequirement::RawBlock,
            disks: Vec::new(),
            external_requirements: Vec::new(),
            storage_generation: 0,
            ownership_epoch: 0,
            stop_outcome: StorageStopOutcome::Unknown,
            relocation_operation: None,
            fence: None,
            operation: None,
            image: None,
            snapshot: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn decode(json: &str) -> Result<Self, LibVmError> {
        crate::storage::limits::Resource::MetadataPageBytes
            .check(json.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        let record: Self =
            serde_json::from_str(json).map_err(|error| LibVmError::InvalidStorageRecord {
                record: "machine-storage",
                message: error.to_string(),
            })?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), LibVmError> {
        if self.schema != 1 {
            return Err(invalid("unsupported machine storage schema"));
        }
        for value in [self.storage_generation, self.ownership_epoch] {
            crate::storage::limits::Resource::JsonInteger
                .check(value)
                .map_err(crate::storage::StorageError::from)?;
        }
        validate_root(&self.root)?;
        for (index, requirement) in self.external_requirements.iter().enumerate() {
            requirement.validate()?;
            if self.external_requirements[..index]
                .iter()
                .any(|other| other.resource == requirement.resource)
            {
                return Err(invalid("duplicate external resource requirement"));
            }
        }
        let combination = match (&self.root, &self.boot, self.profile, self.backend) {
            (
                MachineRoot::OpaqueRaw { layout, .. },
                BootProfile::LinuxDirect { root_selector, .. },
                StorageProfile::OpaqueRawV1,
                BackendRequirement::RawBlock,
            ) => matches!(
                (layout, root_selector),
                (RawLayout::WholeDisk, RootSelector::WholeDisk)
                    | (
                        RawLayout::Partitioned {
                            table: PartitionTable::Gpt
                        },
                        RootSelector::GptPartition { .. }
                    )
                    | (
                        RawLayout::Partitioned {
                            table: PartitionTable::Mbr
                        },
                        RootSelector::MbrPartition { number: 1..=4 }
                    )
            ),
            (
                MachineRoot::OpaqueRaw { .. },
                BootProfile::LinuxEfi { .. } | BootProfile::MacOs { .. },
                StorageProfile::OpaqueRawV1,
                BackendRequirement::RawBlock,
            ) => true,
            (
                MachineRoot::LinuxOverlay { .. },
                BootProfile::LinuxDirect {
                    root_selector: RootSelector::ManagedOverlay,
                    ..
                },
                StorageProfile::LinuxOverlayV1,
                BackendRequirement::KrunOverlay,
            ) => true,
            _ => false,
        };
        if !combination {
            return Err(invalid("inconsistent root, boot, profile and backend"));
        }
        self.boot.validate()?;
        let root_disk_count = if matches!(self.root, MachineRoot::LinuxOverlay { .. }) {
            2u32
        } else {
            1u32
        };
        crate::storage::limits::Resource::IncludedDisks
            .sum([u64::from(root_disk_count), self.disks.len() as u64])
            .map_err(crate::storage::StorageError::from)?;
        for (index, disk) in self.disks.iter().enumerate() {
            let geometry = match &disk.storage {
                DiskStorage::ManagedWritable { geometry, .. }
                | DiskStorage::ManagedReadOnly { geometry, .. } => geometry,
            };
            validate_geometry(geometry)?;
            if disk.id.is_nil()
                || disk.role != DiskRole::Data
                || disk.order < root_disk_count
                || self.disks[..index]
                    .iter()
                    .any(|other| other.id == disk.id || other.order == disk.order)
            {
                return Err(invalid(
                    "included disk roles, IDs and ordinals must be unique",
                ));
            }
        }
        if let Some(operation) = &self.operation {
            if operation.id.is_nil() {
                return Err(invalid("operation ID is nil"));
            }
            if operation.ownership_epoch != self.ownership_epoch {
                return Err(invalid(
                    "operation ownership epoch does not match machine storage",
                ));
            }
        }
        if let Some(id) = self.relocation_operation {
            if !self.operation.as_ref().is_some_and(|operation| {
                operation.id == id && operation.kind == StorageOperationKind::Relocate
            }) {
                return Err(invalid("relocation operation has no matching typed record"));
            }
        }
        if let Some(fence) = &self.fence {
            let operation = self
                .operation
                .as_ref()
                .ok_or_else(|| invalid("fence has no matching operation record"))?;
            if self.relocation_operation != Some(fence.operation)
                || self.ownership_epoch != fence.ownership_epoch
                || operation.id != fence.operation
                || operation.kind != StorageOperationKind::Relocate
                || !matches!(
                    (fence.state, operation.state),
                    (
                        FenceState::Prepared,
                        StorageOperationState::Prepared | StorageOperationState::Staging
                    ) | (FenceState::Committed, StorageOperationState::Committed)
                        | (FenceState::Released, StorageOperationState::Aborted)
                )
            {
                return Err(invalid(
                    "fence does not match relocation operation and ownership epoch",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_for_machine(&self, machine: uuid::Uuid) -> Result<(), LibVmError> {
        self.validate()?;
        if self
            .operation
            .as_ref()
            .and_then(|operation| operation.machine_id)
            .is_some_and(|id| id != machine)
        {
            return Err(invalid(
                "operation machine ID differs from its storage owner",
            ));
        }
        Ok(())
    }
}

fn validate_root(root: &MachineRoot) -> Result<(), LibVmError> {
    match root {
        MachineRoot::OpaqueRaw { geometry, .. } => validate_geometry(geometry)?,
        MachineRoot::LinuxOverlay {
            lower,
            upper_uuid,
            capacity,
            temporary_directory,
            ..
        } => {
            crate::storage::limits::validate_upper_length(*capacity)
                .map_err(crate::storage::StorageError::from)?;
            temporary_directory.validate()?;
            if upper_uuid.is_nil() {
                return Err(invalid("upper filesystem UUID must not be nil"));
            }
            if let OverlayLower::FlatExt4 {
                geometry,
                filesystem_uuid,
                ..
            } = lower
            {
                validate_geometry(geometry)?;
                if filesystem_uuid.is_nil() || filesystem_uuid == upper_uuid {
                    return Err(invalid(
                        "root filesystem UUIDs must be nonzero and distinct",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_geometry(geometry: &DiskGeometry) -> Result<(), LibVmError> {
    if geometry.logical_sector_size != 512 {
        return Err(invalid("only 512-byte logical sectors are admitted"));
    }
    crate::storage::limits::validate_disk_length(geometry.length)
        .map_err(crate::storage::StorageError::from)?;
    Ok(())
}

fn invalid(message: impl Into<String>) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "machine-storage",
        message: message.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageOperationKind {
    Import,
    Convert,
    Snapshot,
    Fork,
    Relocate,
    UpdateBootAssets,
    Launch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageOperationState {
    Prepared,
    Staging,
    Committed,
    Aborted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageOperationRecord {
    pub id: uuid::Uuid,
    pub kind: StorageOperationKind,
    pub state: StorageOperationState,
    pub machine_id: Option<uuid::Uuid>,
    pub ownership_epoch: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FenceState {
    Prepared,
    Committed,
    Released,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FenceRecord {
    pub operation: uuid::Uuid,
    pub ownership_epoch: u64,
    pub state: FenceState,
}

#[cfg(test)]
mod tests {
    use crate::store::models::storage::{MachineStorageRecord, PrivatePath};
    use crate::LibVmError;

    #[test]
    fn invalid_closed_variants_and_combinations_are_typed_errors() {
        let record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let value = serde_json::to_value(&record).unwrap();
        for (field, invalid) in [
            ("root", serde_json::json!({"kind":"legacy"})),
            ("boot", serde_json::json!({"kind":"bios"})),
            ("backend", serde_json::json!("other")),
            ("profile", serde_json::json!("other")),
            ("stopOutcome", serde_json::json!("coherent")),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(matches!(
                MachineStorageRecord::decode(&changed.to_string()),
                Err(LibVmError::InvalidStorageRecord { .. })
            ));
        }
        let mut changed = value;
        changed["backend"] = serde_json::json!("krun-overlay");
        assert!(MachineStorageRecord::decode(&changed.to_string()).is_err());
    }

    #[test]
    fn private_paths_reject_escape_and_absolute_names() {
        for path in [
            "",
            "/root.raw",
            "../root.raw",
            "a/../root.raw",
            "./root.raw",
        ] {
            assert!(PrivatePath::new(path).is_err(), "{path}");
        }
        assert!(PrivatePath::new("storage/1/root.raw").is_ok());
    }

    #[test]
    fn fresh_raw_admission_requires_real_geometry_and_closed_platforms() {
        let platform = oci::Platform::host().unwrap();
        for length in [0, 1, 511, 513, (1_u64 << 40) + 512] {
            assert!(MachineStorageRecord::opaque_raw(
                PrivatePath::new("root.raw").unwrap(),
                length,
                &platform
            )
            .is_err());
        }
        let mut other = platform.clone();
        other.os = "darwin".to_string();
        assert!(MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &other
        )
        .is_err());
        other.os = "linux".to_string();
        other.architecture = "mips64".to_string();
        assert!(MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &other
        )
        .is_err());
        let mut record =
            MachineStorageRecord::opaque_raw(PrivatePath::new("root.raw").unwrap(), 512, &platform)
                .unwrap();
        record.schema = 2;
        assert!(record.validate().is_err());
    }

    #[test]
    fn partition_selectors_match_the_recorded_table_and_primary_range() {
        use crate::{BootProfile, MachineRoot, PartitionTable, RawLayout, RootSelector};
        let mut record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        if let MachineRoot::OpaqueRaw { layout, .. } = &mut record.root {
            *layout = RawLayout::Partitioned {
                table: PartitionTable::Mbr,
            };
        }
        for number in [0, 5, 255] {
            if let BootProfile::LinuxDirect { root_selector, .. } = &mut record.boot {
                *root_selector = RootSelector::MbrPartition { number };
            }
            assert!(record.validate().is_err());
        }
        if let BootProfile::LinuxDirect { root_selector, .. } = &mut record.boot {
            *root_selector = RootSelector::MbrPartition { number: 4 };
        }
        record.validate().unwrap();
        if let MachineRoot::OpaqueRaw { layout, .. } = &mut record.root {
            *layout = RawLayout::Partitioned {
                table: PartitionTable::Gpt,
            };
        }
        assert!(record.validate().is_err());
    }

    #[test]
    fn embedded_operations_and_fences_validate_identity_epoch_and_closed_states() {
        use crate::{
            FenceRecord, FenceState, StorageOperationKind, StorageOperationRecord,
            StorageOperationState,
        };
        let mut record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let operation = uuid::Uuid::new_v4();
        let machine = uuid::Uuid::new_v4();
        record.operation = Some(StorageOperationRecord {
            id: operation,
            kind: StorageOperationKind::Relocate,
            state: StorageOperationState::Prepared,
            machine_id: Some(machine),
            ownership_epoch: 0,
        });
        record.relocation_operation = Some(operation);
        record.fence = Some(FenceRecord {
            operation,
            ownership_epoch: 0,
            state: FenceState::Prepared,
        });
        record.validate_for_machine(machine).unwrap();
        assert!(record.validate_for_machine(uuid::Uuid::new_v4()).is_err());
        let value = serde_json::to_value(&record).unwrap();
        for pointer in ["/operation/kind", "/operation/state", "/fence/state"] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::json!("unsupported");
            assert!(matches!(
                MachineStorageRecord::decode(&changed.to_string()),
                Err(LibVmError::InvalidStorageRecord { .. })
            ));
        }
        record.ownership_epoch = 1;
        assert!(record.validate().is_err());
        record.ownership_epoch = 0;
        record.fence.as_mut().unwrap().operation = uuid::Uuid::new_v4();
        assert!(record.validate().is_err());
    }

    #[test]
    fn included_disks_distinguish_private_writers_from_immutable_streams() {
        use crate::{DiskOwnership, DiskStorage, IncludedDisk};
        use vm_spec::{DiskGeometry, DiskRole};
        let stream = crate::storage::stream::StreamHasher::new()
            .hash_reader(std::io::Cursor::new([0x64; 512]))
            .unwrap()
            .id();
        let mut record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let disk = IncludedDisk {
            id: uuid::Uuid::new_v4(),
            role: DiskRole::Data,
            order: 1,
            storage: DiskStorage::ManagedReadOnly {
                stream,
                geometry: DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
            },
        };
        assert_eq!(disk.storage.ownership(), DiskOwnership::ManagedReadOnly);
        record.disks.push(disk.clone());
        record.validate().unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value["disks"][0]["storage"]["kind"] = serde_json::json!("external");
        assert!(matches!(
            MachineStorageRecord::decode(&value.to_string()),
            Err(LibVmError::InvalidStorageRecord { .. })
        ));
        record.disks.push(disk);
        assert!(record.validate().is_err());
        record.disks.pop();
        record.disks[0].storage = DiskStorage::ManagedWritable {
            path: PrivatePath::new("disks/data.raw").unwrap(),
            geometry: DiskGeometry {
                length: 512,
                logical_sector_size: 512,
            },
        };
        assert_eq!(
            record.disks[0].storage.ownership(),
            DiskOwnership::ManagedWritable
        );
        record.validate().unwrap();
        record.disks[0].role = DiskRole::RootUpper;
        assert!(record.validate().is_err());
    }

    #[test]
    fn data_discovery_uses_semantic_role_even_at_index_zero() {
        use crate::store::models::storage::ExternalResource;
        use vm_spec::{BlockId, Disk, DiskFormat, DiskGeometry, DiskRole, Storage, VmSpec};
        let disk = |role, serial| Disk {
            path: format!("{serial}.raw").into(),
            role,
            format: if role == DiskRole::RootLower {
                DiskFormat::Vmdk
            } else {
                DiskFormat::Raw
            },
            geometry: DiskGeometry {
                length: 64 << 20,
                logical_sector_size: 512,
            },
            block_id: BlockId::new(serial).unwrap(),
            read_only: role == DiskRole::RootLower,
        };
        let spec = VmSpec {
            storage: Some(Storage {
                disks: vec![
                    disk(DiskRole::Data, "data-first"),
                    disk(DiskRole::RootLower, "silo-root-lower"),
                    disk(DiskRole::RootUpper, "silo-root-upper"),
                    disk(DiskRole::Data, "data-last"),
                ],
            }),
            ..VmSpec::current()
        };
        let resources = ExternalResource::from_spec(&spec);
        assert_eq!(resources.len(), 2);
        assert!(
            matches!(&resources[0], ExternalResource::Disk { role: DiskRole::Data, order: 0, path, .. } if path == std::path::Path::new("data-first.raw"))
        );
        assert!(matches!(
            &resources[1],
            ExternalResource::Disk {
                role: DiskRole::Data,
                order: 3,
                ..
            }
        ));
    }

    #[test]
    fn shared_root_codec_encoder_is_independently_valid_json() {
        let bootstrap_fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/overlay.json"
        ));
        let observation_fixture = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/observation.json"
        ));
        let mut output = [0; 4096];
        let bootstrap = rootfs_spec::decode_bootstrap(bootstrap_fixture).unwrap();
        let length = rootfs_spec::encode_bootstrap(&bootstrap, &mut output).unwrap();
        let independent: serde_json::Value = serde_json::from_slice(&output[..length]).unwrap();
        assert_eq!(
            independent,
            serde_json::from_slice::<serde_json::Value>(bootstrap_fixture).unwrap()
        );
        let observation = rootfs_spec::decode_observation(observation_fixture).unwrap();
        let length = rootfs_spec::encode_observation(&observation, &mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output[..length]).unwrap(),
            serde_json::from_slice::<serde_json::Value>(observation_fixture).unwrap()
        );
        for input in [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../specs/rootfs-spec/fixtures/invalid-duplicate.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../specs/rootfs-spec/fixtures/invalid-unknown.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../specs/rootfs-spec/fixtures/invalid-old-schema.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../specs/rootfs-spec/fixtures/invalid-integer.json"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../specs/rootfs-spec/fixtures/invalid-uuid.json"
            )),
        ] {
            serde_json::from_slice::<serde_json::Value>(input)
                .expect("negative contract fixtures are valid JSON");
            assert!(rootfs_spec::decode_bootstrap(input).is_err());
        }
    }

    #[test]
    fn independent_host_json_cannot_bypass_closed_root_contract() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/overlay.json"
        ));
        let fixture: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        for pointer in [
            "/schemaVersion",
            "/root/kind",
            "/root/discovery",
            "/root/lower",
            "/root/upper",
            "/root/upperProfile",
            "/root/overlayProfile",
            "/root/renderingAbi",
            "/root/temporaryDirectory",
            "/root/lower/serial",
            "/root/lower/lengthBytes",
            "/root/lower/logicalSectorSize",
            "/root/lower/readOnly",
            "/root/lower/filesystem",
            "/root/lower/filesystemUuid",
            "/root/upper/serial",
            "/root/upper/lengthBytes",
            "/root/upper/logicalSectorSize",
            "/root/upper/readOnly",
            "/root/upper/filesystem",
            "/root/upper/filesystemUuid",
        ] {
            let mut missing = fixture.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            missing
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                rootfs_spec::decode_bootstrap(&serde_json::to_vec(&missing).unwrap()).is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            ("/root/lower/readOnly", serde_json::json!(false)),
            ("/root/upper/readOnly", serde_json::json!(true)),
            ("/root/lower/serial", serde_json::json!("silo-root-upper")),
            ("/root/lower/lengthBytes", serde_json::json!(513)),
            (
                "/root/upper/lengthBytes",
                serde_json::json!((64u64 << 20) - 4096),
            ),
            (
                "/root/upper/lengthBytes",
                serde_json::json!((1u64 << 40) + 4096),
            ),
            ("/root/lower/logicalSectorSize", serde_json::json!(4096)),
            (
                "/root/upper/filesystemUuid",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            (
                "/root/temporaryDirectory",
                serde_json::json!({"kind":"tmpfs","capacityBytes":0}),
            ),
            (
                "/root/temporaryDirectory",
                serde_json::json!({"kind":"disk-backed","capacityBytes":4096}),
            ),
        ] {
            let mut invalid = fixture.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                rootfs_spec::decode_bootstrap(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut tmpfs = fixture;
        tmpfs["root"]["temporaryDirectory"] =
            serde_json::json!({"kind":"tmpfs","capacityBytes":4096});
        let parsed = rootfs_spec::decode_bootstrap(&serde_json::to_vec(&tmpfs).unwrap()).unwrap();
        let rootfs_spec::Root::FlatOverlay(root) = parsed.root else {
            panic!("overlay");
        };
        assert_eq!(
            root.temporary_directory,
            rootfs_spec::TemporaryDirectory::Tmpfs {
                capacity_bytes: 4096
            }
        );
    }

    #[test]
    fn flat_lower_and_temporary_policy_are_required_semantic_fields() {
        use crate::store::models::storage::{
            BackendRequirement, BootProfile, MachineRoot, OverlayLower, RootSelector,
            StorageProfile, TemporaryDirectoryPolicy,
        };
        let mut record = MachineStorageRecord::opaque_raw(
            PrivatePath::new("root.raw").unwrap(),
            64 << 20,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let stream = crate::storage::stream::StreamHasher::new()
            .hash_reader(std::io::Cursor::new([0; 512]))
            .unwrap()
            .id();
        record.root = MachineRoot::LinuxOverlay {
            lower: OverlayLower::FlatExt4 {
                stream,
                geometry: vm_spec::DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
                filesystem_uuid: uuid::Uuid::new_v4(),
            },
            upper: PrivatePath::new("upper.raw").unwrap(),
            upper_uuid: uuid::Uuid::new_v4(),
            capacity: 64 << 20,
            ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
            overlay_profile: crate::OverlayProfile::SiloOverlayV1,
            temporary_directory: TemporaryDirectoryPolicy::DiskBacked,
        };
        record.profile = StorageProfile::LinuxOverlayV1;
        record.backend = BackendRequirement::KrunOverlay;
        if let BootProfile::LinuxDirect { root_selector, .. } = &mut record.boot {
            *root_selector = RootSelector::ManagedOverlay;
        }
        record.validate().unwrap();
        let value = serde_json::to_value(&record).unwrap();
        for (parent, field) in [
            ("/root", "temporaryDirectory"),
            ("/root/lower", "geometry"),
            ("/root/lower", "filesystemUuid"),
        ] {
            let mut missing = value.clone();
            missing
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                MachineStorageRecord::decode(&missing.to_string()).is_err(),
                "{field}"
            );
        }
        assert!(TemporaryDirectoryPolicy::Tmpfs { capacity_bytes: 1 }
            .validate()
            .is_err());
        record.disks.push(crate::IncludedDisk {
            id: uuid::Uuid::new_v4(),
            role: vm_spec::DiskRole::Data,
            order: 1,
            storage: crate::DiskStorage::ManagedWritable {
                path: PrivatePath::new("data.raw").unwrap(),
                geometry: vm_spec::DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
            },
        });
        assert!(
            record.validate().is_err(),
            "Data ordinal cannot overlap the upper"
        );
        record.disks[0].order = 2;
        record.validate().unwrap();
    }

    #[test]
    fn independent_observation_json_rejects_missing_fields_and_false_accounting() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/observation.json"
        ));
        let fixture: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        for key in [
            "schemaVersion",
            "root",
            "lowerDevice",
            "upperDevice",
            "upperFilesystemBytes",
            "unusableTailBytes",
            "effectiveOverlayProfile",
        ] {
            let mut missing = fixture.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(
                rootfs_spec::decode_observation(&serde_json::to_vec(&missing).unwrap()).is_err(),
                "{key}"
            );
        }
        let invalid = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/invalid-observation-tail.json"
        ));
        serde_json::from_slice::<serde_json::Value>(invalid)
            .expect("independent valid JSON negative observation");
        assert!(rootfs_spec::decode_observation(invalid).is_err());
        let mut duplicate_device = fixture;
        duplicate_device["upperDevice"] = duplicate_device["lowerDevice"].clone();
        assert!(
            rootfs_spec::decode_observation(&serde_json::to_vec(&duplicate_device).unwrap())
                .is_err()
        );
    }

    #[test]
    fn raw_and_tmpfs_encoder_branches_are_independently_valid_json() {
        let raw: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/raw.json"
        )))
        .unwrap();
        let overlay: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/overlay.json"
        )))
        .unwrap();
        let mut tmpfs = overlay.clone();
        tmpfs["root"]["temporaryDirectory"] =
            serde_json::json!({"kind":"tmpfs","capacityBytes":4096});
        let mut output = [0; 4096];
        for expected in [raw, overlay, tmpfs] {
            let typed =
                rootfs_spec::decode_bootstrap(&serde_json::to_vec(&expected).unwrap()).unwrap();
            let length = rootfs_spec::encode_bootstrap(&typed, &mut output).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output[..length]).unwrap(),
                expected
            );
        }
        let observation: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/rootfs-spec/fixtures/observation.json"
        )))
        .unwrap();
        for policy in [
            serde_json::json!({"kind":"disk-backed"}),
            serde_json::json!({"kind":"tmpfs","capacityBytes":4096}),
        ] {
            let mut expected = observation.clone();
            expected["root"]["temporaryDirectory"] = policy;
            let typed =
                rootfs_spec::decode_observation(&serde_json::to_vec(&expected).unwrap()).unwrap();
            let length = rootfs_spec::encode_observation(&typed, &mut output).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&output[..length]).unwrap(),
                expected
            );
        }
    }
}

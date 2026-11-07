//! Exact stopped-storage operations. The blocking owner outlives its requester.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::machine::root_storage::invalid;
use crate::paths::OwnedDirectory;
use crate::runtime::boot_assets::{
    capture_boot, preflight_captured_boot, BootSelectionContext, CaptureLane,
};
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::store::models::snapshot::{
    SnapshotCaptureKind, SnapshotDisk, SnapshotKind, SnapshotPurpose, SnapshotRecord, SnapshotRoot,
    SnapshotStream,
};
use crate::store::models::{MachineConfig, MachineId};
use crate::store::snapshot_store::publish_map;
use crate::store::{MachineStore, Store};
use crate::{
    BootBinding, BootProfile, DiskStorage, LibVmError, Machine, MachineAgent, MachineGuestConfig,
    MachineRef, MachineRetention, MachineRoot, MachineStorageRecord, ProcessConfig, Runtime,
    RuntimeConfig, SnapshotInfo, SnapshotRef, SnapshotStore, StorageStopOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExternalResourceKey {
    Disk { order: u32 },
    Share { tag: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalResourceRequirement {
    pub resource: ExternalResourceKey,
    pub read_only: bool,
}

impl ExternalResourceRequirement {
    pub fn validate(&self) -> Result<(), LibVmError> {
        match &self.resource {
            ExternalResourceKey::Disk { order } if *order == 0 || *order >= 16 => Err(invalid(
                "external Data disk ordinal is outside the attachment bound",
            )),
            ExternalResourceKey::Share { tag } if tag.trim().is_empty() || tag.contains('\0') => {
                Err(invalid("external share tag is invalid"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalResourceMapping {
    pub resource: ExternalResourceKey,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExternalResourcePolicy {
    #[default]
    Reject,
    RequireMappings,
    Map {
        mappings: Vec<ExternalResourceMapping>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ForkOptions {
    pub name: Option<String>,
    pub external_resources: ExternalResourcePolicy,
}
#[derive(Debug, Clone, Default)]
pub struct SnapshotOptions {
    pub name: Option<String>,
    pub external_resources: ExternalResourcePolicy,
}

/// Fraction of configured RAM reserved for this child's private writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PrivateWriteAllowance(u8);

impl Default for PrivateWriteAllowance {
    fn default() -> Self {
        Self(25)
    }
}

impl TryFrom<u32> for PrivateWriteAllowance {
    type Error = LibVmError;

    fn try_from(percent: u32) -> Result<Self, Self::Error> {
        if percent > 100 {
            return Err(invalid(
                "private-write allowance must be between 0 and 100 percent",
            ));
        }
        Ok(Self(percent as u8))
    }
}

impl From<PrivateWriteAllowance> for u32 {
    fn from(value: PrivateWriteAllowance) -> Self {
        u32::from(value.0)
    }
}

impl PrivateWriteAllowance {
    pub(crate) fn reservation(self, bytes: u64, granule: u64) -> Result<u64, LibVmError> {
        if granule == 0 || !granule.is_power_of_two() {
            return Err(invalid("invalid native RAM granule"));
        }
        // Widen before multiplication so even the largest input cannot wrap.
        let bytes = (u128::from(bytes) * u128::from(self.0)).div_ceil(100);
        let rounded = bytes.div_ceil(u128::from(granule)) * u128::from(granule);
        u64::try_from(rounded).map_err(|_| invalid("restore private-write reservation overflow"))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreMemoryPolicy {
    #[default]
    Reserved,
    AllowOvercommit,
}

/// Per-child admission intent, retained for the lifetime of the restore run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreResourcePolicy {
    pub private_write_allowance: PrivateWriteAllowance,
    pub memory: RestoreMemoryPolicy,
}
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    pub name: Option<String>,
    pub external_resources: ExternalResourcePolicy,
    pub activation_hook: Option<vm_spec::restore::RestoreHook>,
    pub resources: RestoreResourcePolicy,
}

/// Configured semantics only. Host identity, run state and secret scopes are absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotConfiguration {
    pub spec: vm_spec::VmSpec,
    pub retention: MachineRetention,
    pub process: ProcessConfig,
    pub template_name: Option<String>,
    pub agent_mode: Option<MachineAgent>,
    pub guest: MachineGuestConfig,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub(crate) network: crate::store::models::MachineNetworkConfig,
}

impl SnapshotConfiguration {
    pub(crate) fn capture(config: &MachineConfig) -> Result<Self, LibVmError> {
        let mut spec = config.spec.clone();
        // Paths identify configured selection only until capture. The retained
        // bundle is the child's boot authority, not a source-private pathname.
        if let Some(kernel) = spec.boot.as_mut().and_then(|boot| boot.kernel.as_mut()) {
            kernel.path = None;
            kernel.initramfs = None;
        }
        if let Some(disks) = spec.storage.as_mut() {
            for (order, disk) in disks.disks.iter_mut().enumerate() {
                disk.path = PathBuf::from(format!("captured-disk-{order}"));
                let serial = match disk.role {
                    vm_spec::DiskRole::Root => "silo-root".to_owned(),
                    vm_spec::DiskRole::RootLower => "silo-root-lower".to_owned(),
                    vm_spec::DiskRole::RootUpper => "silo-root-upper".to_owned(),
                    vm_spec::DiskRole::Data => format!("silo-data-{order}"),
                };
                disk.block_id = vm_spec::BlockId::new(serial).map_err(invalid)?;
            }
        }
        for mount in &mut spec.mounts {
            mount.source = PathBuf::from("required-external-share");
        }
        let pin_agent = |agent: &MachineAgent| match agent {
            MachineAgent::Custom { .. } => MachineAgent::Custom {
                path: PathBuf::from("captured-agent"),
            },
            other => other.clone(),
        };
        let mut guest = config.guest.clone();
        guest.agent = pin_agent(&guest.agent);
        Ok(Self {
            spec,
            retention: config.retention,
            process: config.process.clone(),
            template_name: config.template_name.clone(),
            agent_mode: config.agent_mode.as_ref().map(pin_agent),
            guest,
            labels: config.labels.clone(),
            metadata: config.metadata.clone(),
            network: config.network.clone(),
        })
    }
}

/// Read-only admission before writable Runtime initialization. Locks repeat it.
pub async fn preflight_stopped(
    config: &RuntimeConfig,
    reference: &MachineRef,
    snapshot: bool,
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    if snapshot {
        validate_snapshot_policy(policy)?;
    }
    let roots = config.observation_roots()?;
    let observer =
        crate::store::observation::ObservationStore::open(&roots.state_db_path()).await?;
    let result = async {
        let (machine, state) = observer.lookup(reference).await?;
        let storage = observer.machine_storage(machine.id).await?;
        validate_managed_attachments(&machine.spec, &storage)?;
        validate_capture_shape(&storage, snapshot, StoppedAdmission::Ordinary)?;
        check_policy(&external_requirements(&machine.spec, &storage)?, policy)?;
        if let Some(pid) = state.vmm_pid {
            if let Some(identity) = crate::supervisor::process::ProcessIdentity::for_pid(pid)? {
                if identity.is_alive()? {
                    return Err(LibVmError::MachineAlreadyRunning {
                        reference: machine.name,
                    });
                }
            }
        }
        preflight_boot(config, &storage, &machine.spec, &machine.guest.agent).await
    }
    .await;
    let closed = observer.close().await;
    result.and(closed)
}

pub async fn preflight_restore_snapshot(
    config: &RuntimeConfig,
    reference: &SnapshotRef,
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    if !crate::LiveObservationReader::open(config)?.catalog_exists()? {
        crate::require_host_live_operation(
            &crate::LiveCapabilityQuery::open(config)?
                .host_report()
                .await?,
            vm_spec::live::LiveOperation::Restore,
        )?;
    }
    let record = crate::store::snapshot_store::observe_snapshot_record(config, reference).await?;
    if matches!(record.capture, SnapshotCaptureKind::LiveExecution { .. }) {
        return crate::machine::restore::preflight_execution(config, &record, policy).await;
    }
    check_policy(&record.external_requirements, policy)?;
    let storage = storage_from_snapshot(&record)?;
    preflight_boot(
        config,
        &storage,
        &record.configuration.spec,
        &record.configuration.guest.agent,
    )
    .await
}

async fn preflight_boot(
    config: &RuntimeConfig,
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
    agent: &MachineAgent,
) -> Result<(), LibVmError> {
    let config = config.clone();
    let storage = storage.clone();
    let spec = spec.clone();
    let agent = agent.clone();
    tokio::task::spawn_blocking(move || {
        let components = config.resolve_components()?;
        let selection = crate::runtime::capabilities::ResolvedBackendSelection::resolve(
            config.virt_backend.as_ref(),
        )?;
        crate::runtime::boot_assets::validate_captured_boot_lane(
            &storage,
            selection.backend,
            CaptureLane::Stopped,
        )?;
        let pool = StoragePool::open_existing(&config.resolve_home()?.join("images"))?
            .ok_or_else(|| invalid("source immutable pool is missing"))?;
        crate::runtime::boot_assets::preflight_boot_selection(
            &storage,
            &spec,
            &agent,
            BootSelectionContext {
                pool: &pool,
                default_kernel: components.kernel(),
                default_initramfs: components.initramfs(),
                default_agent: components.agent(),
                native_executable: components.supervisor(),
                backend: selection.backend,
            },
            CaptureLane::Stopped,
        )
    })
    .await?
}

impl Machine {
    pub async fn fork_stopped(&self, options: ForkOptions) -> Result<Machine, LibVmError> {
        let runtime = self.runtime().clone();
        let machine_id = self.machine_id();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(fork_owned(runtime, machine_id, options))
        })
        .await?
    }

    pub async fn snapshot_stopped(
        &self,
        options: SnapshotOptions,
    ) -> Result<SnapshotInfo, LibVmError> {
        let runtime = self.runtime().clone();
        let machine_id = self.machine_id();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(snapshot_owned(runtime, machine_id, options))
        })
        .await?
    }
}

impl Runtime {
    pub async fn restore_snapshot(
        &self,
        reference: SnapshotRef,
        options: RestoreOptions,
    ) -> Result<Machine, LibVmError> {
        let runtime = self.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(restore_owned(runtime, reference, options))
        })
        .await?
    }
}

pub(crate) struct StoppedStorageGuard {
    pub(crate) config: MachineConfig,
    pub(crate) storage: MachineStorageRecord,
    pub(crate) files: Vec<FencedSource>,
    _lifecycle: crate::lock_manager::LockGuard,
    _disks: Vec<StorageLock>,
    _lifetime: Option<crate::lock_manager::MachineLifetimeLock>,
}

/// Whose stopped boundary is being admitted. Ordinary copies require plain
/// ownership; a handoff cut requires exactly its own durable reservation,
/// which the ownership ledger wrote under this same lifecycle lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoppedAdmission {
    Ordinary,
    Handoff(crate::handoff::types::OperationId),
}

/// An exact private inode held under the source machine's storage fences.
/// It carries no content authority, so a streaming copy scans it.
pub(crate) struct FencedSource {
    pub(crate) path: crate::PrivatePath,
    pub(crate) file: File,
    pub(crate) length: u64,
}

/// One writable role of a constructed child and the authority its bytes carry.
pub(crate) enum PrivateSource {
    Fenced(FencedSource),
    /// A byte-authenticated inode whose map the completed copy must reproduce.
    Authenticated {
        path: crate::PrivatePath,
        stream: crate::storage::stream::AuthenticatedStream,
    },
}

impl PrivateSource {
    pub(crate) fn path(&self) -> &crate::PrivatePath {
        match self {
            Self::Fenced(source) => &source.path,
            Self::Authenticated { path, .. } => path,
        }
    }

    pub(crate) fn file(&self) -> &File {
        match self {
            Self::Fenced(source) => &source.file,
            Self::Authenticated { stream, .. } => stream.file(),
        }
    }

    pub(crate) fn length(&self) -> u64 {
        match self {
            Self::Fenced(source) => source.length,
            Self::Authenticated { stream, .. } => stream.length(),
        }
    }

    pub(crate) fn copy_source(&self) -> crate::machine::root_disk::CopySource<'_> {
        match self {
            Self::Fenced(source) => crate::machine::root_disk::CopySource::Unscanned {
                file: &source.file,
                length: source.length,
            },
            Self::Authenticated { stream, .. } => {
                crate::machine::root_disk::CopySource::Authenticated(stream)
            }
        }
    }
}

pub(crate) async fn admit_stopped(
    runtime: &Runtime,
    id: MachineId,
    snapshot: bool,
    policy: &ExternalResourcePolicy,
    admission: StoppedAdmission,
) -> Result<StoppedStorageGuard, LibVmError> {
    let (lifecycle, config) = runtime.lock_machine_config(id).await?;
    runtime.validate_machine_data_dir(&config)?;
    let initial_storage = runtime.machine_storage_record(id).await?;
    validate_capture_shape(&initial_storage, snapshot, admission)?;
    validate_managed_attachments(&config.spec, &initial_storage)?;
    check_policy(
        &external_requirements(&config.spec, &initial_storage)?,
        policy,
    )?;
    runtime
        .preflight_stopped_generation_locked(&config, &initial_storage)
        .await?;
    runtime.preflight_captured_lane(&initial_storage, CaptureLane::Stopped)?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let store = runtime.native_store()?;
    let context = runtime.captured_boot_context(&pool, &store, Uuid::nil());
    preflight_captured_boot(
        &initial_storage,
        &config.spec,
        &config.guest.agent,
        &context,
        CaptureLane::Stopped,
    )?;
    let mut ids = initial_storage
        .disks
        .iter()
        .map(|disk| disk.id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    let mut disk_locks = Vec::with_capacity(ids.len());
    if !ids.is_empty() {
        let lock_directory = OwnedDirectory::open_root(&runtime.local_home().join("locks"))?
            .ensure_dir("managed-disks")?;
        for disk in ids {
            disk_locks.push(crate::storage::locks::blocking(
                &lock_directory,
                &format!("{disk}.lock"),
                nix::fcntl::FlockArg::LockExclusive,
            )?);
        }
    }
    // Probe the existing launch lifetime without creating runtime state. An
    // offline writer owns the same lifecycle lock; launch retains this flock.
    let lifetime_path = runtime.machine_paths(id).vmm_lock_path();
    let lifetime = match std::fs::symlink_metadata(&lifetime_path) {
        Ok(metadata) if metadata.is_file() => Some(
            crate::lock_manager::MachineLifetimeLock::try_acquire(&lifetime_path)?.ok_or_else(
                || LibVmError::MachineAlreadyRunning {
                    reference: config.name.clone(),
                },
            )?,
        ),
        Ok(_) => return Err(invalid("generation lifetime fence is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    runtime.ensure_no_live_vmm_generation(&config).await?;
    let status = runtime.reconcile_machine_runtime_locked(&config).await?;
    if status.is_active() || !store.launch_storage_operations(id).await?.is_empty() {
        return Err(LibVmError::MachineAlreadyRunning {
            reference: config.name.clone(),
        });
    }
    let mut storage = runtime.machine_storage_record(id).await?;
    storage.disks.sort_by_key(|disk| disk.order);
    validate_capture_shape(&storage, snapshot, admission)?;
    let directory = OwnedDirectory::open_existing_root(&config.machine_dir)?
        .ok_or_else(|| invalid("source machine directory is missing"))?;
    let mut files = Vec::with_capacity(storage.disks.len() + 1);
    let (path, length) = root_private(&storage);
    let root_source = open_private(&directory, path, length)?;
    validate_upper_metadata(&storage, &root_source.file)?;
    files.push(root_source);
    for disk in &storage.disks {
        if let DiskStorage::ManagedWritable { path, geometry } = &disk.storage {
            files.push(open_private(&directory, path, geometry.length)?);
        }
    }
    let mut writable_inodes = BTreeSet::new();
    for source in &files {
        let metadata = source.file.metadata()?;
        if !writable_inodes.insert((metadata.dev(), metadata.ino())) {
            return Err(invalid(
                "one private inode appears in multiple writable roles",
            ));
        }
    }
    Ok(StoppedStorageGuard {
        config,
        storage,
        files,
        _lifecycle: lifecycle,
        _disks: disk_locks,
        _lifetime: lifetime,
    })
}

pub(crate) fn validate_capture_shape(
    storage: &MachineStorageRecord,
    snapshot: bool,
    admission: StoppedAdmission,
) -> Result<(), LibVmError> {
    storage.validate()?;
    let admitted = match admission {
        StoppedAdmission::Ordinary => storage.ownership.is_owned(),
        StoppedAdmission::Handoff(operation) => {
            storage.ownership == crate::MachineOwnership::Reserved { operation }
        }
    };
    if storage.operation.is_some() || !admitted {
        return Err(invalid(
            "storage has an unresolved offline operation or ownership fence",
        ));
    }
    match &storage.root {
        MachineRoot::OpaqueRaw { .. } => {}
        MachineRoot::LinuxOverlay {
            lower: crate::OverlayLower::FlatExt4 { .. },
            ..
        } if !snapshot => {}
        MachineRoot::LinuxOverlay { .. } if snapshot => {
            return Err(LibVmError::FlatOverlayPublicationUnsupported)
        }
        _ => return Err(invalid("root family is not admitted for stopped copying")),
    }
    if !matches!(storage.boot, BootProfile::LinuxDirect { .. }) {
        return Err(invalid(
            "stopped capture requires an admitted Linux direct boot profile",
        ));
    }
    Ok(())
}

pub(crate) fn validate_managed_attachments(
    spec: &vm_spec::VmSpec,
    storage: &MachineStorageRecord,
) -> Result<(), LibVmError> {
    spec.validate().map_err(invalid)?;
    crate::machine::root_storage::validate_spec(storage, spec)?;
    for included in &storage.disks {
        let disk = spec
            .storage
            .as_ref()
            .and_then(|disks| disks.disks.get(included.order as usize))
            .ok_or_else(|| invalid("managed Data ordinal is absent from configured attachments"))?;
        let (geometry, read_only) = match &included.storage {
            DiskStorage::ManagedWritable { geometry, .. } => (geometry, false),
            DiskStorage::ManagedReadOnly { geometry, .. } => (geometry, true),
        };
        if disk.role != vm_spec::DiskRole::Data
            || disk.format != vm_spec::DiskFormat::Raw
            || &disk.geometry != geometry
            || disk.read_only != read_only
        {
            return Err(invalid(
                "managed Data role, geometry, format or access contradicts configuration",
            ));
        }
    }
    Ok(())
}

fn validate_upper_metadata(storage: &MachineStorageRecord, file: &File) -> Result<(), LibVmError> {
    let MachineRoot::LinuxOverlay {
        upper_uuid,
        capacity,
        ..
    } = &storage.root
    else {
        return Ok(());
    };
    let mut bytes = [0u8; 1024];
    file.read_exact_at(&mut bytes, 1024)?;
    let word = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    let profile = rootfs_spec::upper_geometry::FEATURE_INCOMPAT;
    if bytes[56..58] != [0x53, 0xef]
        || &bytes[104..120] != upper_uuid.as_bytes()
        || word(24) != 2
        || word(96) & !4 != profile
        || word(92) & !rootfs_spec::upper_geometry::FEATURE_COMPAT != 0
        || word(100) & !rootfs_spec::upper_geometry::FEATURE_RO_COMPAT != 0
        || word(4) as u64 * 4096 > *capacity
        || word(4) == 0
        || word(336) != 0
    {
        return Err(invalid(
            "stopped upper metadata does not match its admitted profile and UUID",
        ));
    }
    // EXT4_FEATURE_INCOMPAT_RECOVER is deliberately permitted. Never replay,
    // repair or clear the dirty journal while admitting an exact capture.
    Ok(())
}

pub(crate) fn root_private(storage: &MachineStorageRecord) -> (&crate::PrivatePath, u64) {
    match &storage.root {
        MachineRoot::OpaqueRaw { path, geometry, .. } => (path, geometry.length),
        MachineRoot::LinuxOverlay {
            upper, capacity, ..
        } => (upper, *capacity),
    }
}

pub(crate) fn open_private(
    directory: &OwnedDirectory,
    path: &crate::PrivatePath,
    length: u64,
) -> Result<FencedSource, LibVmError> {
    let mut parent = directory.try_clone()?;
    let mut components = path.as_path().components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(invalid("invalid private component"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| invalid("private component is not UTF-8"))?;
        if components.peek().is_some() {
            parent = parent
                .open_dir(name)?
                .ok_or_else(|| invalid("private parent is missing"))?;
        } else {
            let file = parent
                .open_file(name)?
                .ok_or_else(|| invalid("private source is missing"))?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != length
            {
                return Err(invalid(
                    "private source type, owner, mode, links or geometry is invalid",
                ));
            }
            return Ok(FencedSource {
                path: path.clone(),
                file,
                length,
            });
        }
    }
    Err(invalid("empty private path"))
}

fn validate_snapshot_policy(policy: &ExternalResourcePolicy) -> Result<(), LibVmError> {
    if matches!(policy, ExternalResourcePolicy::Map { .. }) {
        return Err(invalid("snapshot creation accepts omission-as-requirements, not destination mappings; map resources during fork or restore"));
    }
    Ok(())
}

pub(crate) fn external_requirements(
    spec: &vm_spec::VmSpec,
    storage: &MachineStorageRecord,
) -> Result<Vec<ExternalResourceRequirement>, LibVmError> {
    let mut requirements = storage.external_requirements.clone();
    if let Some(disks) = &spec.storage {
        for (order, disk) in disks.disks.iter().enumerate() {
            if disk.role == vm_spec::DiskRole::Data
                && !storage
                    .disks
                    .iter()
                    .any(|managed| managed.order as usize == order)
            {
                let requirement = ExternalResourceRequirement {
                    resource: ExternalResourceKey::Disk {
                        order: order as u32,
                    },
                    read_only: disk.read_only,
                };
                if !requirements
                    .iter()
                    .any(|other| other.resource == requirement.resource)
                {
                    requirements.push(requirement);
                }
            }
        }
    }
    for mount in &spec.mounts {
        let requirement = ExternalResourceRequirement {
            resource: ExternalResourceKey::Share {
                tag: mount.tag.clone(),
            },
            read_only: mount.read_only,
        };
        if !requirements
            .iter()
            .any(|other| other.resource == requirement.resource)
        {
            requirements.push(requirement);
        }
    }
    for requirement in &requirements {
        requirement.validate()?;
        let access = match &requirement.resource {
            ExternalResourceKey::Disk { order } => spec
                .storage
                .as_ref()
                .and_then(|disks| disks.disks.get(*order as usize))
                .filter(|disk| disk.role == vm_spec::DiskRole::Data)
                .filter(|_| !storage.disks.iter().any(|managed| managed.order == *order))
                .map(|disk| disk.read_only),
            ExternalResourceKey::Share { tag } => spec
                .mounts
                .iter()
                .find(|mount| &mount.tag == tag)
                .map(|mount| mount.read_only),
        };
        if access != Some(requirement.read_only) {
            return Err(invalid(
                "external requirement contradicts configured resource ownership or access",
            ));
        }
    }
    Ok(requirements)
}

pub(crate) fn check_policy(
    requirements: &[ExternalResourceRequirement],
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    match policy {
        ExternalResourcePolicy::Reject if !requirements.is_empty() => Err(invalid(
            "external resources require explicit omission-as-requirements or destination mappings",
        )),
        ExternalResourcePolicy::Map { mappings } => {
            let mut seen = BTreeSet::new();
            for mapping in mappings {
                if !seen.insert(&mapping.resource)
                    || !requirements
                        .iter()
                        .any(|required| required.resource == mapping.resource)
                    || !mapping.path.is_absolute()
                    || mapping.path.as_os_str().as_encoded_bytes().contains(&0)
                {
                    return Err(invalid("external mapping is duplicate, undeclared or not an absolute destination path"));
                }
            }
            if mappings.len() != requirements.len() {
                return Err(invalid(
                    "every required external resource must have exactly one destination mapping",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn apply_resources(
    configuration: &mut SnapshotConfiguration,
    requirements: &[ExternalResourceRequirement],
    policy: &ExternalResourcePolicy,
) -> Result<Vec<ExternalResourceRequirement>, LibVmError> {
    check_policy(requirements, policy)?;
    for requirement in requirements {
        let path = match policy {
            ExternalResourcePolicy::Map { mappings } => mappings
                .iter()
                .find(|mapping| mapping.resource == requirement.resource)
                .map(|mapping| mapping.path.clone())
                .ok_or_else(|| invalid("required mapping disappeared"))?,
            _ => match &requirement.resource {
                ExternalResourceKey::Disk { order } => {
                    PathBuf::from(format!("captured-disk-{order}"))
                }
                ExternalResourceKey::Share { .. } => PathBuf::from("required-external-share"),
            },
        };
        match &requirement.resource {
            ExternalResourceKey::Disk { order } => {
                let disk = configuration
                    .spec
                    .storage
                    .as_mut()
                    .and_then(|storage| storage.disks.get_mut(*order as usize))
                    .ok_or_else(|| invalid("required external disk ordinal is missing"))?;
                if disk.role != vm_spec::DiskRole::Data || disk.read_only != requirement.read_only {
                    return Err(invalid(
                        "external disk declaration contradicts configuration",
                    ));
                }
                disk.path = path;
            }
            ExternalResourceKey::Share { tag } => {
                let mount = configuration
                    .spec
                    .mounts
                    .iter_mut()
                    .find(|mount| &mount.tag == tag)
                    .ok_or_else(|| invalid("required external share is missing"))?;
                if mount.read_only != requirement.read_only {
                    return Err(invalid(
                        "external share declaration contradicts configuration",
                    ));
                }
                mount.source = path;
            }
        }
    }
    Ok(if matches!(policy, ExternalResourcePolicy::Map { .. }) {
        Vec::new()
    } else {
        requirements.to_vec()
    })
}

async fn fork_owned(
    runtime: Runtime,
    id: MachineId,
    options: ForkOptions,
) -> Result<Machine, LibVmError> {
    runtime.require_recoverable_child_scopes()?;
    if let Some(name) = &options.name {
        crate::machine::reference::validate_new_machine_name(name)?;
    }
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(&runtime, options.name.as_deref()).await?;
    let mut source = admit_stopped(
        &runtime,
        id,
        false,
        &options.external_resources,
        StoppedAdmission::Ordinary,
    )
    .await?;
    let store = runtime.native_store()?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let (streams, objects) = crate::store::cache_paths::storage_pool_dependencies(&source.storage)?;
    let streams = streams.into_iter().collect::<Vec<_>>();
    let objects = objects.into_iter().collect::<Vec<_>>();
    let (operation_id, lease) = store
        .begin_stopped_operation("fork", &streams, &objects)
        .await?;
    let mut staging = OperationStaging::new(&pool, operation_id, &lease)?;
    for file in &source.files {
        file.file.sync_all()?;
    }
    let mut storage = source.storage;
    storage.boot = capture_boot(
        &storage,
        &source.config.spec,
        &source.config.guest.agent,
        runtime.captured_boot_context(&pool, &store, operation_id),
        CaptureLane::Stopped,
    )
    .await?;
    let mut configuration = SnapshotConfiguration::capture(&source.config)?;
    storage.external_requirements = apply_resources(
        &mut configuration,
        &external_requirements(&source.config.spec, &storage)?,
        &options.external_resources,
    )?;
    reset_child_storage(&mut storage);
    let files = std::mem::take(&mut source.files)
        .into_iter()
        .map(PrivateSource::Fenced)
        .collect();
    let config = crate::machine::builder::publish_stopped_child(
        &runtime,
        name,
        configuration,
        storage,
        files,
        operation_id,
    )
    .await?;
    staging.cleanup()?;
    store.finish_stopped_operation(operation_id).await?;
    drop(lease);
    Ok(Machine::new(runtime, config.id))
}

async fn snapshot_owned(
    runtime: Runtime,
    id: MachineId,
    options: SnapshotOptions,
) -> Result<SnapshotInfo, LibVmError> {
    validate_snapshot_policy(&options.external_resources)?;
    if let Some(name) = &options.name {
        crate::store::snapshot_store::validate_alias(name)?;
    }
    let _names = runtime.lock_machine_names().await?;
    let mut source = admit_stopped(
        &runtime,
        id,
        true,
        &options.external_resources,
        StoppedAdmission::Ordinary,
    )
    .await?;
    let store = runtime.native_store()?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let (streams, objects) = crate::store::cache_paths::storage_pool_dependencies(&source.storage)?;
    let streams = streams.into_iter().collect::<Vec<_>>();
    let objects = objects.into_iter().collect::<Vec<_>>();
    let (operation_id, lease) = store
        .begin_stopped_operation("snapshot", &streams, &objects)
        .await?;
    let mut staging = OperationStaging::new(&pool, operation_id, &lease)?;
    for file in &source.files {
        file.file.sync_all()?;
    }
    let boot = capture_boot(
        &source.storage,
        &source.config.spec,
        &source.config.guest.agent,
        runtime.captured_boot_context(&pool, &store, operation_id),
        CaptureLane::Stopped,
    )
    .await?;
    let requirements = external_requirements(&source.config.spec, &source.storage)?;
    let mut configuration = SnapshotConfiguration::capture(&source.config)?;
    apply_resources(
        &mut configuration,
        &requirements,
        &ExternalResourcePolicy::RequireMappings,
    )?;
    let mut published = Vec::with_capacity(source.files.len());
    for file in std::mem::take(&mut source.files) {
        published.push(publish_private_stream(&pool, &store, operation_id, file).await?);
    }
    let mut writable = published.into_iter();
    let root_content = writable
        .next()
        .ok_or_else(|| invalid("capture has no private root"))?;
    let MachineRoot::OpaqueRaw {
        geometry, layout, ..
    } = &source.storage.root
    else {
        return Err(LibVmError::FlatOverlayPublicationUnsupported);
    };
    let mut disks = Vec::with_capacity(source.storage.disks.len());
    for disk in &source.storage.disks {
        let (content, geometry, is_writable) = match &disk.storage {
            DiskStorage::ManagedWritable { geometry, .. } => (
                writable
                    .next()
                    .ok_or_else(|| invalid("missing writable disk capture"))?,
                *geometry,
                true,
            ),
            DiskStorage::ManagedReadOnly { stream, geometry } => {
                let authenticated = open_immutable_stream(&pool, stream, geometry.length)?;
                let content = publish_map(&pool, &store, operation_id, authenticated.map()).await?;
                (content, *geometry, false)
            }
        };
        disks.push(SnapshotDisk {
            role: disk.role,
            order: disk.order,
            writable: is_writable,
            content,
            geometry,
        });
    }
    let record = SnapshotRecord {
        schema: 1,
        kind: SnapshotKind::Snapshot,
        capture: SnapshotCaptureKind::StoppedStorage {
            stop_outcome: source.storage.stop_outcome,
        },
        purpose: SnapshotPurpose::Checkpoint,
        root: SnapshotRoot {
            profile: crate::store::models::snapshot::SnapshotRootProfile::OpaqueRaw,
            stream: root_content,
            geometry: *geometry,
            layout: layout.clone(),
        },
        disks,
        platform_files: Vec::new(),
        configuration,
        boot,
        external_requirements: requirements,
    };
    let snapshots = SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let info = snapshots
        .publish(&record, operation_id, options.name.as_deref())
        .await?;
    staging.cleanup()?;
    store.finish_stopped_operation(operation_id).await?;
    drop(lease);
    Ok(info)
}

async fn publish_private_stream(
    pool: &StoragePool,
    store: &Store,
    operation: Uuid,
    source: FencedSource,
) -> Result<SnapshotStream, LibVmError> {
    let (stream, roots) = pool.publish_stream_file_for_catalog(source.file, source.length)?;
    store
        .pin_published_storage_dependencies(operation, &[stream.id], &[])
        .await?;
    drop(roots);
    publish_map(pool, store, operation, &stream.map).await
}

fn reset_child_storage(storage: &mut MachineStorageRecord) {
    storage.storage_generation = 0;
    storage.ownership_epoch = 0;
    storage.stop_outcome = StorageStopOutcome::Unknown;
    storage.ownership = crate::MachineOwnership::Owned;
    storage.operation = None;
    storage.image = None;
    storage.snapshot = None;
    for disk in &mut storage.disks {
        disk.id = Uuid::new_v4();
    }
}

fn storage_from_snapshot(record: &SnapshotRecord) -> Result<MachineStorageRecord, LibVmError> {
    if matches!(record.capture, SnapshotCaptureKind::LiveExecution { .. }) {
        return Err(LibVmError::LiveOperationUnsupported {
            operation: vm_spec::live::LiveOperation::Restore,
            backend: vm_spec::live::LiveBackend::Krun,
            lane: vm_spec::live::LiveLane::NotApplicable,
            reason: vm_spec::live::LiveUnsupportedReason::new(
                vm_spec::live::LiveReasonCode::NotDelivered,
            ),
        });
    }
    let mut storage = MachineStorageRecord {
        schema: 1,
        root: MachineRoot::OpaqueRaw {
            path: crate::PrivatePath::new("root.raw")?,
            geometry: record.root.geometry,
            layout: record.root.layout.clone(),
            initial_content: Some(record.root.stream.stream),
        },
        boot: record.boot.clone(),
        profile: crate::StorageProfile::OpaqueRawV1,
        backend: crate::BackendRequirement::RawBlock,
        disks: record
            .disks
            .iter()
            .map(|disk| {
                Ok(crate::IncludedDisk {
                    id: Uuid::new_v4(),
                    role: disk.role,
                    order: disk.order,
                    storage: if disk.writable {
                        DiskStorage::ManagedWritable {
                            path: crate::PrivatePath::new(format!("disk-{}.raw", disk.order))?,
                            geometry: disk.geometry,
                        }
                    } else {
                        DiskStorage::ManagedReadOnly {
                            stream: disk.content.stream,
                            geometry: disk.geometry,
                        }
                    },
                })
            })
            .collect::<Result<_, LibVmError>>()?,
        external_requirements: record.external_requirements.clone(),
        storage_generation: 0,
        ownership_epoch: 0,
        stop_outcome: StorageStopOutcome::Unknown,
        ownership: crate::MachineOwnership::Owned,
        operation: None,
        image: None,
        snapshot: None,
    };
    reset_child_storage(&mut storage);
    validate_capture_shape(&storage, true, StoppedAdmission::Ordinary)?;
    if !matches!(
        storage.boot,
        BootProfile::LinuxDirect {
            binding: BootBinding::Pinned { .. },
            ..
        }
    ) {
        return Err(invalid(
            "snapshot does not retain an exact pinned boot closure",
        ));
    }
    Ok(storage)
}

async fn restore_owned(
    runtime: Runtime,
    reference: SnapshotRef,
    options: RestoreOptions,
) -> Result<Machine, LibVmError> {
    runtime.require_recoverable_child_scopes()?;
    if let Some(name) = &options.name {
        crate::machine::reference::validate_new_machine_name(name)?;
    }
    let store = runtime.native_store()?;
    // Read catalog metadata only: no artifact object is opened before consume
    // registers its retained operation. Unsupported policy/lane fails first.
    let preview = crate::store::observation::ObservationStore::existing(&store)
        .snapshot_record(&reference)
        .await?;
    if matches!(preview.capture, SnapshotCaptureKind::LiveExecution { .. }) {
        return crate::machine::restore::restore_owned(runtime, reference, options, preview).await;
    }
    if options.activation_hook.is_some() {
        return Err(invalid(
            "activation hooks require a live execution checkpoint",
        ));
    }
    if options.resources != RestoreResourcePolicy::default() {
        return Err(invalid(
            "restore resource policies require a live execution checkpoint",
        ));
    }
    check_policy(&preview.external_requirements, &options.external_resources)?;
    runtime.preflight_captured_lane(&storage_from_snapshot(&preview)?, CaptureLane::Stopped)?;
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(&runtime, options.name.as_deref()).await?;
    let snapshots = SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let mut consumer = snapshots.consume(&reference).await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let mut staging = OperationStaging::new(&pool, consumer.operation_id, &consumer.lease)?;
    tracing::debug!(snapshot = %consumer.info.id, operation = %consumer.operation_id, "restoring stopped snapshot");
    let mut storage = storage_from_snapshot(&consumer.record)?;
    let mut configuration = consumer.record.configuration.clone();
    storage.external_requirements = apply_resources(
        &mut configuration,
        &consumer.record.external_requirements,
        &options.external_resources,
    )?;
    preflight_captured_boot(
        &storage,
        &configuration.spec,
        &configuration.guest.agent,
        &runtime.captured_boot_context(&pool, &store, consumer.operation_id),
        CaptureLane::Stopped,
    )?;
    let writable = consumer
        .record
        .disks
        .iter()
        .filter(|disk| disk.writable)
        .count() as u64;
    // Held authenticated closure descriptors stay open while every private
    // source gets its own descriptor.
    crate::storage::limits::preflight_fd_budget(consumer.retained_descriptors() + 1 + writable)
        .map_err(crate::storage::StorageError::from)?;
    let mut sources = vec![PrivateSource::Authenticated {
        path: crate::PrivatePath::new("root.raw")?,
        stream: consumer.open_copy_source(
            &pool,
            &consumer.record.root.stream.stream,
            consumer.record.root.geometry.length,
        )?,
    }];
    for disk in &consumer.record.disks {
        if disk.writable {
            sources.push(PrivateSource::Authenticated {
                path: crate::PrivatePath::new(format!("disk-{}.raw", disk.order))?,
                stream: consumer.open_copy_source(
                    &pool,
                    &disk.content.stream,
                    disk.geometry.length,
                )?,
            });
        }
    }
    consumer.release_closure();
    for source in &sources {
        source.file().sync_all()?;
    }
    let config = crate::machine::builder::publish_stopped_child(
        &runtime,
        name,
        configuration,
        storage,
        sources,
        consumer.operation_id,
    )
    .await?;
    staging.cleanup()?;
    let operation = consumer.operation_id;
    store.finish_stopped_operation(operation).await?;
    drop(consumer);
    Ok(Machine::new(runtime, config.id))
}

pub(crate) struct OperationStaging {
    parent: OwnedDirectory,
    name: String,
    _paths: crate::storage::pool::OperationPaths,
    cleaned: bool,
}

impl OperationStaging {
    pub(crate) fn new(
        pool: &StoragePool,
        operation: Uuid,
        lease: &StorageLock,
    ) -> Result<Self, LibVmError> {
        let paths = pool.create_operation_with_lease(operation, lease.duplicate()?)?;
        let parent = paths
            .temporary
            .parent()
            .ok_or_else(|| invalid("operation staging has no parent"))?;
        let parent = OwnedDirectory::open_existing_root(parent)?
            .ok_or_else(|| invalid("operation staging parent disappeared"))?;
        Ok(Self {
            parent,
            name: operation.to_string(),
            _paths: paths,
            cleaned: false,
        })
    }
    pub(crate) fn directory(&self) -> Result<OwnedDirectory, LibVmError> {
        self.parent
            .open_dir(&self.name)?
            .ok_or_else(|| invalid("operation staging disappeared"))
    }

    fn cleanup(&mut self) -> Result<(), LibVmError> {
        if !self.cleaned {
            self.parent.remove_tree(&self.name)?;
            self.parent.sync()?;
            self.cleaned = true;
        }
        Ok(())
    }
}

impl Drop for OperationStaging {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(operation = %self.name, %error, "remove stopped operation staging");
        }
    }
}

pub(crate) fn open_immutable_stream(
    pool: &StoragePool,
    stream: &crate::storage::identity::StreamId,
    length: u64,
) -> Result<crate::storage::stream::AuthenticatedStream, LibVmError> {
    let file = crate::storage::stream::open_regular_source(&pool.stream_path(stream))?;
    let metadata = file.metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != length
    {
        return Err(invalid(
            "immutable Data backing has invalid owner, mode, links or geometry",
        ));
    }
    // Binds the map to this descriptor's fingerprint before and after scanning.
    let authenticated = crate::storage::stream::StreamHasher::new().authenticate(file, length)?;
    if authenticated.map().id() != *stream {
        return Err(invalid(
            "immutable stream backing does not match its authenticated identity",
        ));
    }
    Ok(authenticated)
}

/// Rebuild private/read-only attachment paths from semantic ownership, never
/// from the parent's persisted launch descriptor or source pathname.
pub(crate) fn project_child_disks(
    spec: &mut vm_spec::VmSpec,
    storage: &MachineStorageRecord,
    images_dir: &Path,
) -> Result<(), LibVmError> {
    let disks = spec
        .storage
        .as_mut()
        .ok_or_else(|| invalid("captured configuration has no disk attachments"))?;
    let root_count = if matches!(storage.root, MachineRoot::LinuxOverlay { .. }) {
        2
    } else {
        1
    };
    for (order, disk) in disks.disks.iter_mut().enumerate() {
        match disk.role {
            vm_spec::DiskRole::Root => {
                let MachineRoot::OpaqueRaw { path, geometry, .. } = &storage.root else {
                    return Err(invalid("raw root attachment contradicts captured root"));
                };
                disk.path = path.as_path().to_path_buf();
                disk.geometry = *geometry;
            }
            vm_spec::DiskRole::RootUpper => {
                let MachineRoot::LinuxOverlay {
                    upper, capacity, ..
                } = &storage.root
                else {
                    return Err(invalid("upper attachment contradicts captured root"));
                };
                disk.path = upper.as_path().to_path_buf();
                disk.geometry.length = *capacity;
            }
            vm_spec::DiskRole::RootLower => disk.path = PathBuf::from("lower.vmdk"),
            vm_spec::DiskRole::Data => {
                if let Some(managed) = storage
                    .disks
                    .iter()
                    .find(|managed| managed.order as usize == order)
                {
                    let (path, geometry, read_only) = match &managed.storage {
                        DiskStorage::ManagedWritable { path, geometry } => {
                            (path.as_path().to_path_buf(), *geometry, false)
                        }
                        DiskStorage::ManagedReadOnly { stream, geometry } => (
                            images_dir.join("streams/sha256").join(stream.hex()),
                            *geometry,
                            true,
                        ),
                    };
                    disk.path = path;
                    disk.geometry = geometry;
                    disk.read_only = read_only;
                    disk.block_id =
                        vm_spec::BlockId::new(format!("silo-data-{}", order - root_count))
                            .map_err(invalid)?;
                }
            }
        }
    }
    spec.validate().map_err(invalid)
}

#[cfg(test)]
mod tests {
    use crate::machine::stopped::{
        check_policy, ExternalResourceKey, ExternalResourceMapping, ExternalResourcePolicy,
        ExternalResourceRequirement,
    };
    #[cfg(target_os = "linux")]
    use test_utils::direct_kernel::host_kernel;

    #[test]
    fn stopped_external_policy_requires_explicit_complete_destination_mapping() {
        let requirements = [ExternalResourceRequirement {
            resource: ExternalResourceKey::Disk { order: 1 },
            read_only: false,
        }];
        assert!(check_policy(&requirements, &ExternalResourcePolicy::Reject).is_err());
        assert!(check_policy(&requirements, &ExternalResourcePolicy::RequireMappings).is_ok());
        assert!(check_policy(
            &requirements,
            &ExternalResourcePolicy::Map { mappings: vec![] }
        )
        .is_err());
        let mapping = ExternalResourceMapping {
            resource: requirements[0].resource.clone(),
            path: "/destination/data.raw".into(),
        };
        assert!(check_policy(
            &requirements,
            &ExternalResourcePolicy::Map {
                mappings: vec![mapping.clone()]
            }
        )
        .is_ok());
        assert!(check_policy(
            &requirements,
            &ExternalResourcePolicy::Map {
                mappings: vec![mapping.clone(), mapping]
            }
        )
        .is_err());
    }

    #[test]
    fn snapshot_creation_rejects_destination_mapping_policy() {
        assert!(
            crate::machine::stopped::validate_snapshot_policy(&ExternalResourcePolicy::Map {
                mappings: Vec::new()
            },)
            .is_err()
        );
        assert!(crate::machine::stopped::validate_snapshot_policy(
            &ExternalResourcePolicy::RequireMappings,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn snapshot_map_preflight_refuses_before_catalog_or_runtime_creation() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("absent-home");
        let config = crate::RuntimeConfig::local(&home);
        let result = crate::preflight_stopped(
            &config,
            &crate::MachineRef::parse("source").unwrap(),
            true,
            &ExternalResourcePolicy::Map {
                mappings: Vec::new(),
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::LibVmError::InvalidStorageRecord { .. })
        ));
        assert!(!home.exists());
    }

    #[cfg(target_os = "linux")]
    async fn raw_source(name: &str) -> (tempfile::TempDir, crate::Runtime, crate::Machine) {
        let home = tempfile::tempdir().unwrap();
        let disk = home.path().join("input.raw");
        use std::os::unix::fs::PermissionsExt;
        disk_image::ext4::Formatter::new(&disk, 4096, 64 * 1024 * 1024)
            .unwrap()
            .close()
            .unwrap();
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(home.path().join("silo")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        std::fs::create_dir_all(runtime.asset_directory()).unwrap();
        let kernel = runtime.asset_directory().join("kernel-default");
        let init = runtime.asset_directory().join("initramfs");
        std::fs::write(&kernel, host_kernel("exact configured kernel bytes")).unwrap();
        std::fs::write(&init, b"exact configured base-init bytes").unwrap();
        for asset in [&kernel, &init] {
            std::fs::set_permissions(asset, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut image = crate::ImageSource::disk(&disk);
        if let crate::ImageSource::Disk(request) = &mut image {
            let crate::DiskImportBoot::LinuxDirect { assets, .. } = &mut request.boot;
            *assets = crate::BootAssetSelection::Files {
                kernel,
                base_initramfs: init,
                agent: None,
            };
        }
        let machine = runtime
            .machine()
            .name(name)
            .image_source(image)
            .create()
            .await
            .unwrap();
        (home, runtime, machine)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stopped_child_secret_scope_override_refuses_before_effects_but_provider_is_preserved()
    {
        let (home, runtime, source) = raw_source("source").await;
        let provider_runtime = runtime
            .clone()
            .with_secret_provider(crate::HostCommand::new(
                "/configured/destination-secret-provider",
            ));
        let configured_source = crate::Machine::new(provider_runtime, source.machine_id());
        configured_source
            .fork_stopped(crate::ForkOptions {
                name: Some("provider-child".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let store = runtime.native_store().unwrap();
        store.recover_image_cache().await.unwrap();
        let before_operations = store.storage_operation_count().await.unwrap();
        let before_source = runtime
            .machine_config(source.machine_id())
            .await
            .unwrap()
            .unwrap();
        let before_machines = std::fs::read_dir(before_source.machine_dir.parent().unwrap())
            .unwrap()
            .count();
        let external = home.path().join("external-secret-store");
        let overridden = runtime
            .clone()
            .with_secret_store(std::sync::Arc::new(silo_secrets::FileStore::new(&external)));
        let overridden_source = crate::Machine::new(overridden.clone(), source.machine_id());
        let fork = overridden_source
            .fork_stopped(crate::ForkOptions {
                name: Some("refused-child".into()),
                ..Default::default()
            })
            .await;
        let restore = overridden
            .restore_snapshot(
                crate::SnapshotRef::Image("not-opened".into()),
                crate::RestoreOptions {
                    name: Some("refused-restore".into()),
                    ..Default::default()
                },
            )
            .await;
        for result in [fork, restore] {
            assert!(
                matches!(result, Err(crate::LibVmError::InvalidStorageRecord { ref message, .. })
                if message.contains("secret scopes"))
            );
        }
        assert_eq!(
            store.storage_operation_count().await.unwrap(),
            before_operations
        );
        assert_eq!(
            runtime
                .machine_config(source.machine_id())
                .await
                .unwrap()
                .unwrap(),
            before_source
        );
        assert_eq!(
            std::fs::read_dir(before_source.machine_dir.parent().unwrap())
                .unwrap()
                .count(),
            before_machines
        );
        assert!(!external.exists());
        assert!(runtime
            .machine_config_by_name("refused-child")
            .await
            .unwrap()
            .is_none());
        assert!(runtime
            .machine_config_by_name("refused-restore")
            .await
            .unwrap()
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stopped_fork_preserves_configured_process_and_managed_data_without_parent_paths() {
        use crate::store::MachineStore;
        use crate::{DiskStorage, ForkOptions, IncludedDisk, PrivatePath, StorageStopOutcome};
        use sha2::Digest;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (_home, runtime, source) = raw_source("source").await;
        let mut config = runtime
            .machine_config(source.machine_id())
            .await
            .unwrap()
            .unwrap();
        let mut storage = runtime
            .machine_storage_record(source.machine_id())
            .await
            .unwrap();
        let root_before =
            sha2::Sha256::digest(std::fs::read(config.machine_dir.join("root.raw")).unwrap());
        let data = config.machine_dir.join("data.raw");
        std::fs::write(&data, [0x91; 1024]).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o600)).unwrap();
        config.spec.storage.as_mut().unwrap().disks.push(
            crate::machine::root_storage::disk(
                "data.raw",
                vm_spec::DiskRole::Data,
                1024,
                "silo-data-0".into(),
            )
            .unwrap(),
        );
        storage.disks.push(IncludedDisk {
            id: uuid::Uuid::new_v4(),
            role: vm_spec::DiskRole::Data,
            order: 1,
            storage: DiskStorage::ManagedWritable {
                path: PrivatePath::new("data.raw").unwrap(),
                geometry: vm_spec::DiskGeometry {
                    length: 1024,
                    logical_sector_size: 512,
                },
            },
        });
        config.process.entrypoint = None;
        config.process.command = Some(Vec::new());
        config
            .process
            .environment
            .insert("秘密".into(), "credential bytes are not sanitized".into());
        config.process.working_directory = "/work".into();
        config.metadata.insert("é".into(), "value".into());
        runtime
            .native_store()
            .unwrap()
            .save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        let store = runtime.native_store().unwrap();
        let operations_before = store.storage_operation_count().await.unwrap();
        let mut contradictory = storage.clone();
        contradictory
            .external_requirements
            .push(ExternalResourceRequirement {
                resource: ExternalResourceKey::Disk { order: 1 },
                read_only: false,
            });
        store
            .save_machine_config_with_storage(&config, &contradictory)
            .await
            .unwrap();
        assert!(source
            .fork_stopped(ForkOptions {
                name: Some("not-created".into()),
                external_resources: ExternalResourcePolicy::RequireMappings,
            })
            .await
            .is_err());
        assert_eq!(
            store.storage_operation_count().await.unwrap(),
            operations_before
        );
        assert!(runtime
            .machine_config_by_name("not-created")
            .await
            .unwrap()
            .is_none());
        store
            .save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        let child = source
            .fork_stopped(ForkOptions {
                name: Some("child".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let child_config = runtime
            .machine_config(child.machine_id())
            .await
            .unwrap()
            .unwrap();
        let child_storage = runtime
            .machine_storage_record(child.machine_id())
            .await
            .unwrap();
        assert_ne!(config.id, child_config.id);
        assert_ne!(config.lock_id, child_config.lock_id);
        assert_eq!(config.process, child_config.process);
        assert_eq!(config.metadata, child_config.metadata);
        assert_eq!(
            sha2::Sha256::digest(std::fs::read(child_config.machine_dir.join("root.raw")).unwrap()),
            root_before
        );
        assert_eq!(child_storage.stop_outcome, StorageStopOutcome::Unknown);
        assert!(runtime
            .native_store()
            .unwrap()
            .machine_state(child.machine_id())
            .await
            .unwrap()
            .unwrap()
            .run_id
            .is_none());
        let DiskStorage::ManagedWritable { path, .. } = &child_storage.disks[0].storage else {
            panic!("writable Data");
        };
        let copied = child_config.machine_dir.join(path.as_path());
        assert_eq!(std::fs::read(&copied).unwrap(), [0x91; 1024]);
        assert_ne!(
            std::fs::metadata(&data).unwrap().ino(),
            std::fs::metadata(&copied).unwrap().ino()
        );
        assert_ne!(storage.disks[0].id, child_storage.disks[0].id);
        assert_eq!(
            sha2::Sha256::digest(std::fs::read(config.machine_dir.join("root.raw")).unwrap()),
            root_before
        );
        assert!(matches!(
            child_storage.boot,
            crate::BootProfile::LinuxDirect {
                binding: crate::BootBinding::Pinned { .. },
                ..
            }
        ));
        assert_eq!(
            child_config.spec.storage.as_ref().unwrap().disks[1].path,
            path.as_path()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stopped_sql_rejection_cleans_only_owned_uncommitted_child() {
        use sha2::Digest;
        let (_home, runtime, source) = raw_source("source").await;
        let source_config = runtime
            .machine_config(source.machine_id())
            .await
            .unwrap()
            .unwrap();
        let root_before = sha2::Sha256::digest(
            std::fs::read(source_config.machine_dir.join("root.raw")).unwrap(),
        );
        let machines = source_config.machine_dir.parent().unwrap();
        runtime.native_store().unwrap().execute_test_sql(
            "CREATE TRIGGER reject_stopped_child BEFORE INSERT ON machine_config WHEN NEW.name='rejected' BEGIN SELECT RAISE(ABORT,'real stopped child SQL rejection'); END",
        ).await.unwrap();
        let result = source
            .fork_stopped(crate::ForkOptions {
                name: Some("rejected".into()),
                ..Default::default()
            })
            .await;
        assert!(result.is_err());
        assert!(runtime
            .machine_config_by_name("rejected")
            .await
            .unwrap()
            .is_none());
        runtime
            .native_store()
            .unwrap()
            .recover_image_cache()
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(machines).unwrap().count(), 1);
        assert_eq!(
            sha2::Sha256::digest(
                std::fs::read(source_config.machine_dir.join("root.raw")).unwrap()
            ),
            root_before
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stopped_private_source_rejects_fifo_symlink_and_hardlinks_without_mutation() {
        use crate::machine::stopped::open_private;
        use crate::paths::OwnedDirectory;
        use crate::PrivatePath;
        use std::os::unix::fs::{symlink, PermissionsExt};
        let home = tempfile::tempdir().unwrap();
        let directory = OwnedDirectory::open_root(&home.path().join("private")).unwrap();
        let file = directory.path().join("disk.raw");
        std::fs::write(&file, [0x55; 512]).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        nix::unistd::mkfifo(
            &directory.path().join("fifo"),
            nix::sys::stat::Mode::S_IRUSR,
        )
        .unwrap();
        symlink(&file, directory.path().join("symlink")).unwrap();
        std::fs::hard_link(&file, directory.path().join("hardlink")).unwrap();
        for name in ["fifo", "symlink", "hardlink", "disk.raw"] {
            assert!(open_private(&directory, &PrivatePath::new(name).unwrap(), 512).is_err());
        }
        assert_eq!(std::fs::read(&file).unwrap(), [0x55; 512]);
    }
}

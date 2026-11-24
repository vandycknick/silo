//! Exact stopped-storage operations. The blocking owner outlives its requester.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::machine::live_operations::{
    report_progress, LiveOperationProgress, LiveOperationProgressSender,
};
use crate::machine::root_storage::invalid;
use crate::paths::OwnedDirectory;
use crate::runtime::boot_assets::{
    capture_boot, preflight_captured_boot, BootSelectionContext, CaptureLane,
};
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::store::models::snapshot::{
    SnapshotDisk, SnapshotKind, SnapshotMemoryState, SnapshotRecord, SnapshotRoot,
    SnapshotRootProfile, SnapshotStream,
};
use crate::store::models::{MachineConfig, MachineId};
use crate::store::snapshot_store::{publish_map, SnapshotStore};
use crate::store::{MachineStore, Store};
use crate::{
    BootBinding, BootProfile, DiskStorage, LibVmError, Machine, MachineAgent, MachineGuestConfig,
    MachineRef, MachineRetention, MachineRoot, MachineStorageRecord, ProcessConfig, PullPolicy,
    Runtime, RuntimeConfig, SnapshotInfo, SnapshotRef, StorageStopOutcome,
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

/// Caller choices for `Runtime::snapshot`.
///
/// ```text
///   machine   memory=false               memory=true
///   stopped   disks                      MemorySnapshotRequiresRunningMachine
///   running   SnapshotRequiresStopped…   RAM, CPU and device state + disks
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotOptions {
    /// Optional local name for the snapshot.
    pub name: Option<String>,
    /// Include RAM, CPU and device state of a running (or user-paused)
    /// machine. Without memory the machine must be stopped.
    pub memory: bool,
    /// With memory: never resume after the capture. A user-owned pause is
    /// always preserved.
    pub preserve: bool,
    /// With memory: incremental or full capture (default incremental).
    pub capture_policy: Option<vm_spec::lifecycle::CapturePolicy>,
    /// With memory: dirty-page share (1..=60, default 60) above which an
    /// incremental capture copies all RAM.
    pub dirty_crossover_percent: Option<u8>,
    /// Without memory: record external disks and shares as requirements that
    /// restore must map, instead of refusing the snapshot.
    pub external_requirements: bool,
}

impl SnapshotOptions {
    fn validate(&self) -> Result<(), LibVmError> {
        let refused = |message: &str| {
            Err(LibVmError::InvalidRequest {
                message: message.to_owned(),
            })
        };
        if let Some(name) = &self.name {
            crate::store::names::validate_name(name)?;
        }
        if self.memory {
            if self.external_requirements {
                return refused("external requirements apply to snapshots without memory");
            }
        } else if self.preserve
            || self.capture_policy.is_some()
            || self.dirty_crossover_percent.is_some()
        {
            return refused(
                "preserve, capture policy and dirty crossover apply to snapshots with memory",
            );
        }
        Ok(())
    }

    fn memory_options(&self) -> crate::LiveSnapshotOptions {
        let defaults = crate::LiveSnapshotOptions::default();
        crate::LiveSnapshotOptions {
            name: self.name.clone(),
            resume_policy: if self.preserve {
                vm_spec::lifecycle::CaptureResumePolicy::Preserve
            } else {
                defaults.resume_policy
            },
            policy: self.capture_policy.unwrap_or(defaults.policy),
            dirty_crossover_percent: self
                .dirty_crossover_percent
                .unwrap_or(defaults.dirty_crossover_percent),
        }
    }

    fn external_resources(&self) -> ExternalResourcePolicy {
        if self.external_requirements {
            ExternalResourcePolicy::RequireMappings
        } else {
            ExternalResourcePolicy::Reject
        }
    }
}

/// The snapshot `Runtime::snapshot` published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreatedSnapshot {
    pub snapshot: SnapshotInfo,
    /// The memory capture; absent for a snapshot without memory.
    pub capture: Option<crate::LiveCaptureSummary>,
    /// Another snapshot took the requested name first; this snapshot was
    /// kept without it.
    pub naming_outcome: Option<crate::CaptureNamingOutcome>,
}

impl CreatedSnapshot {
    /// Report a lost name race as an error. The snapshot itself is kept.
    pub fn require_requested_name(&self) -> Result<(), LibVmError> {
        if let Some(crate::CaptureNamingOutcome::NameConflict { name }) = &self.naming_outcome {
            return Err(LibVmError::CaptureNameConflict {
                name: name.clone(),
                snapshot: self.snapshot.id,
            });
        }
        Ok(())
    }
}

/// What `Runtime::restore` turns into a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreSource {
    /// A local snapshot: name, pulled reference (short references expand via
    /// `search_registries`), id or unique id prefix. Never pulls.
    Local(SnapshotRef),
    /// A reference resolved like `silo restore REF`: local name first, then
    /// stored `search_registries` expansions, a unique id prefix, then a
    /// registry pull according to `RestoreOptions::pull`.
    Registry(String),
}

#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// Name of the restored machine.
    pub name: Option<String>,
    /// When `RestoreSource::Registry` contacts a registry.
    pub pull: PullPolicy,
    /// Restore a snapshot with memory as a stopped machine from its disks
    /// only: RAM is discarded and the guest boots, possibly replaying its
    /// filesystem journal. No effect on a snapshot without memory.
    pub without_memory: bool,
    /// Runs in the guest after a snapshot with memory resumes.
    pub activation_hook: Option<vm_spec::restore::RestoreHook>,
    pub external_resources: ExternalResourcePolicy,
}

impl RestoreOptions {
    fn validate(&self) -> Result<(), LibVmError> {
        if self.without_memory && self.activation_hook.is_some() {
            return Err(LibVmError::InvalidRequest {
                message: "an activation hook requires restoring memory; drop --without-memory"
                    .to_owned(),
            });
        }
        if let Some(name) = &self.name {
            crate::machine::reference::validate_new_machine_name(name)?;
        }
        Ok(())
    }
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
    #[serde(default)]
    pub secret_scope: crate::SecretScopePolicy,
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
            secret_scope: config.secret_scope,
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
    crate::LiveObservationReader::open(config)?
        .require_machine_exists(reference)
        .await?;
    let roots = config.observation_roots()?;
    let observer =
        crate::store::observation::ObservationStore::open(&roots.state_db_path()).await?;
    let result = async {
        let (machine, state) = observer.lookup(reference).await?;
        if observer.has_hibernation(machine.id).await? {
            return Err(LibVmError::HibernatedStartFirst {
                reference: machine.name,
            });
        }
        let storage = observer.machine_storage(machine.id).await?;
        validate_managed_attachments(&machine.spec, &storage)?;
        validate_capture_shape(&storage, StoppedAdmission::Ordinary)?;
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

/// Observe restore admission before writable initialization. Reuse the
/// runtime's capability query when initialized; a config-only caller supplies
/// its discovery query without opening a runtime or catalog for mutation.
pub async fn preflight_restore_snapshot(
    config: &RuntimeConfig,
    query: &crate::LiveCapabilityQuery,
    reference: &SnapshotRef,
    options: &RestoreOptions,
) -> Result<(), LibVmError> {
    options.validate()?;
    let policy = &options.external_resources;
    let record = crate::store::snapshot_store::observe_snapshot_record(config, reference).await?;
    let memory = matches!(record.memory, SnapshotMemoryState::Included { .. });
    if memory && !options.without_memory {
        return crate::machine::restore::preflight_execution(query, &record, policy).await;
    }
    check_policy(&record.external_requirements, policy)?;
    let storage = if memory {
        crate::machine::restore::storage_from_snapshot(&record, record.id()?)?
    } else {
        storage_from_snapshot(&record)?
    };
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
}

impl Runtime {
    /// Snapshot `machine`. Without memory the machine must be stopped and
    /// its disks are captured; with memory it must be running (or
    /// user-paused) and RAM, CPU and device state are captured as well.
    /// `progress` reports the memory capture.
    pub async fn snapshot(
        &self,
        machine: &MachineRef,
        options: SnapshotOptions,
        progress: Option<LiveOperationProgressSender>,
    ) -> Result<CreatedSnapshot, LibVmError> {
        options.validate()?;
        let machine = self.get_machine(machine).await?;
        let config = self
            .resolve_machine_config(&MachineRef::id(machine.machine_id()))
            .await?;
        crate::machine::hibernate::fence(
            self,
            &config,
            crate::machine::hibernate::HibernateRemedy::Start,
        )
        .await?;
        if options.memory {
            let observation = match machine.observe_live().await {
                Ok(observation) => observation,
                Err(LibVmError::MachineNotRunning { reference }) => {
                    return Err(LibVmError::MemorySnapshotRequiresRunningMachine { reference })
                }
                Err(error) => return Err(error),
            };
            let captured = machine
                .snapshot_memory(&observation, options.memory_options(), progress)
                .await?;
            return Ok(CreatedSnapshot {
                snapshot: captured.snapshot,
                capture: Some(captured.capture),
                naming_outcome: captured.naming_outcome,
            });
        }
        let runtime = self.clone();
        let machine_id = machine.machine_id();
        let handle = tokio::runtime::Handle::current();
        let snapshot = tokio::task::spawn_blocking(move || {
            handle.block_on(snapshot_owned(runtime, machine_id, options))
        })
        .await?
        .map_err(|error| match error {
            LibVmError::MachineAlreadyRunning { reference } => {
                LibVmError::SnapshotRequiresStoppedMachine { reference }
            }
            error => error,
        })?;
        Ok(CreatedSnapshot {
            snapshot,
            capture: None,
            naming_outcome: None,
        })
    }

    /// Turn a snapshot into a new machine: a snapshot with memory resumes
    /// running (unless `without_memory`), one without memory restores a
    /// stopped machine. A registry reference is pulled when missing; an
    /// image is refused with a `silo create` hint.
    pub async fn restore(
        &self,
        source: RestoreSource,
        options: RestoreOptions,
        progress: Option<LiveOperationProgressSender>,
    ) -> Result<Machine, LibVmError> {
        options.validate()?;
        // Refuse before resolution: a refused restore must not pull.
        self.require_recoverable_child_scopes()?;
        let snapshot = self.resolve_restore_source(source, options.pull).await?;
        report_progress(progress.as_ref(), LiveOperationProgress::Admitting);
        let runtime = self.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let result = handle.block_on(restore_owned(
                runtime,
                SnapshotRef::Id(snapshot),
                options,
                progress.as_ref(),
            ));
            if result.is_ok() {
                report_progress(progress.as_ref(), LiveOperationProgress::Done);
            }
            result
        })
        .await?
    }

    async fn resolve_restore_source(
        &self,
        source: RestoreSource,
        pull: PullPolicy,
    ) -> Result<crate::SnapshotId, LibVmError> {
        let (input, pull) = match source {
            RestoreSource::Local(reference) => (reference.to_string(), PullPolicy::Never),
            RestoreSource::Registry(reference) => (reference, pull),
        };
        // A missing local name is not permission to pull a Docker library image.
        // Qualified registry paths retain the caller's explicit pull policy.
        let pull = if input.contains('/') {
            pull
        } else {
            PullPolicy::Never
        };
        let resolution = {
            let store = self.native_store()?;
            let mut connection = store.pool.acquire().await?;
            crate::resolve::resolve(
                &mut connection,
                self.registry_policy(),
                &input,
                crate::resolve::Kind::Snapshot,
                pull,
            )
            .await?
        };
        match resolution {
            crate::resolve::Resolution::Local(crate::resolve::LocalMatch {
                record: crate::resolve::LocalRecord::Snapshot(id),
                ..
            }) => Ok(id),
            crate::resolve::Resolution::Local(_) => {
                Err(LibVmError::ImageIsNotASnapshot { reference: input })
            }
            crate::resolve::Resolution::Remote(reference) => {
                match self.images().acquire_snapshot_artifact(reference).await {
                    Ok(snapshot) => Ok(snapshot.id),
                    Err(LibVmError::Image { reference, source }) => {
                        Err(LibVmError::SnapshotPullFailed {
                            reference: input,
                            message: format!("pulling {reference} failed: {source}"),
                        })
                    }
                    Err(LibVmError::ImageReferenceRejected { reference, message }) => {
                        Err(LibVmError::SnapshotPullFailed {
                            reference: input,
                            message: format!("pulling {reference} failed: {message}"),
                        })
                    }
                    Err(error) => Err(error),
                }
            }
        }
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
/// which the ownership ledger wrote under this same lifecycle lock. A raw
/// export is an ordinary-ownership, host-only read: it never launches or
/// captures, so it skips only captured lane and boot qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoppedAdmission {
    Ordinary,
    Handoff(crate::handoff::types::OperationId),
    RawExport,
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
    Owned {
        path: crate::PrivatePath,
        file: File,
        length: u64,
        fingerprint: crate::storage::identity_file::SourceFingerprint,
    },
    /// A recorded stream map whose chunks the streaming copy checks while writing.
    Authenticated {
        path: crate::PrivatePath,
        stream: crate::storage::stream::AuthenticatedStream,
    },
}

impl PrivateSource {
    pub(crate) fn path(&self) -> &crate::PrivatePath {
        match self {
            Self::Fenced(source) => &source.path,
            Self::Authenticated { path, .. } | Self::Owned { path, .. } => path,
        }
    }

    pub(crate) fn file(&self) -> &File {
        match self {
            Self::Fenced(source) => &source.file,
            Self::Owned { file, .. } => file,
            Self::Authenticated { stream, .. } => stream.file(),
        }
    }

    pub(crate) fn length(&self) -> u64 {
        match self {
            Self::Fenced(source) => source.length,
            Self::Owned { length, .. } => *length,
            Self::Authenticated { stream, .. } => stream.length(),
        }
    }

    pub(crate) fn prepare(
        self,
        directory: OwnedDirectory,
        name: &str,
        qualification: &mut crate::machine::root_disk::CopyQualification,
        writeback: crate::storage::stream::CopyWriteback,
    ) -> Result<crate::machine::root_disk::PreparedPrivateCopy, LibVmError> {
        use crate::machine::root_disk::{copy_private, CopySource};
        let copy = match self {
            Self::Owned {
                file,
                length,
                fingerprint,
                ..
            } => copy_private(
                CopySource::Owned {
                    file: &file,
                    length,
                    fingerprint,
                },
                directory,
                name,
                qualification,
                writeback,
            )?,
            Self::Fenced(source) => copy_private(
                CopySource::Unscanned {
                    file: &source.file,
                    length: source.length,
                },
                directory,
                name,
                qualification,
                writeback,
            )?,
            Self::Authenticated { stream, .. } => copy_private(
                CopySource::Authenticated(&stream),
                directory,
                name,
                qualification,
                writeback,
            )?,
        };
        Ok(copy)
    }
}

fn private_copy_source(
    pool: &StoragePool,
    storage: &MachineStorageRecord,
    seeds: &[vm_spec::capture::DiskTrackingSeed],
    source: FencedSource,
    lease: &StorageLock,
) -> Result<PrivateSource, LibVmError> {
    let fingerprint =
        crate::storage::identity_file::SourceFingerprint::new(&source.file.metadata()?);
    let baseline = storage.disk_baselines.iter().find(|baseline| {
        baseline.fingerprint == fingerprint && seeds.iter().any(|seed| seed == &baseline.seed)
    });
    let Some(baseline) = baseline else {
        return Ok(PrivateSource::Fenced(source));
    };
    let map = pool.load_map(
        baseline.map,
        vm_spec::stream_map::StreamRole::Disk,
        pool.map_authority(std::sync::Arc::new(lease.duplicate()?))?,
    )?;
    let stream = crate::storage::stream::AuthenticatedStream::from_verified_fingerprint(
        source.file,
        std::sync::Arc::new(map),
        baseline.fingerprint,
    )?;
    Ok(PrivateSource::Authenticated {
        path: source.path,
        stream,
    })
}

pub(crate) async fn admit_stopped(
    runtime: &Runtime,
    id: MachineId,
    policy: &ExternalResourcePolicy,
    admission: StoppedAdmission,
) -> Result<StoppedStorageGuard, LibVmError> {
    let (lifecycle, config) = runtime.lock_machine_config(id).await?;
    crate::machine::hibernate::fence(
        runtime,
        &config,
        match admission {
            StoppedAdmission::Ordinary => crate::machine::hibernate::HibernateRemedy::Start,
            StoppedAdmission::RawExport | StoppedAdmission::Handoff(_) => {
                crate::machine::hibernate::HibernateRemedy::Stop
            }
        },
    )
    .await?;
    runtime.validate_machine_data_dir(&config)?;
    let initial_storage = runtime.machine_storage_record(id).await?;
    validate_capture_shape(&initial_storage, admission)?;
    validate_managed_attachments(&config.spec, &initial_storage)?;
    check_policy(
        &external_requirements(&config.spec, &initial_storage)?,
        policy,
    )?;
    runtime
        .preflight_stopped_generation_locked(&config, &initial_storage)
        .await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let store = runtime.native_store()?;
    if admission != StoppedAdmission::RawExport {
        runtime.preflight_captured_lane(&initial_storage, CaptureLane::Stopped)?;
        let context = runtime.captured_boot_context(&pool, &store, Uuid::nil());
        preflight_captured_boot(
            &initial_storage,
            &config.spec,
            &config.guest.agent,
            &context,
            CaptureLane::Stopped,
        )?;
    }
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
    validate_capture_shape(&storage, admission)?;
    let directory = OwnedDirectory::open_existing_root(&config.machine_dir)?
        .ok_or_else(|| invalid("source machine directory is missing"))?;
    let mut files = Vec::with_capacity(storage.disks.len() + 1);
    let (path, length) = root_private(&storage);
    let root_source = open_private(&directory, path, length)?;
    validate_upper_metadata(&storage, &root_source.file).map_err(|error| match admission {
        // An export reads the upper as data: an incompatible layout is an
        // unsupported export, never a storage-record defect to repair.
        StoppedAdmission::RawExport => LibVmError::RawExportUnsupported {
            reason: error.to_string(),
        },
        StoppedAdmission::Ordinary | StoppedAdmission::Handoff(_) => error,
    })?;
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

/// Opaque raw and layered overlay roots are both admitted for exact stopped
/// copies, snapshots and exports. Captures additionally require a Linux
/// direct boot; an export reports its own typed boot refusal.
pub(crate) fn validate_capture_shape(
    storage: &MachineStorageRecord,
    admission: StoppedAdmission,
) -> Result<(), LibVmError> {
    storage.validate()?;
    let admitted = match admission {
        StoppedAdmission::Ordinary | StoppedAdmission::RawExport => storage.ownership.is_owned(),
        StoppedAdmission::Handoff(operation) => {
            storage.ownership == crate::MachineOwnership::Reserved { operation }
        }
    };
    if storage.operation.is_some() || !admitted {
        return Err(invalid(
            "storage has an unresolved offline operation or ownership fence",
        ));
    }
    if admission != StoppedAdmission::RawExport
        && !matches!(storage.boot, BootProfile::LinuxDirect { .. })
    {
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
    crate::machine::root_storage::validate_upper_file(file, *upper_uuid, *capacity)
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
        &options.external_resources,
        StoppedAdmission::Ordinary,
    )
    .await?;
    let store = runtime.native_store()?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let closure = stopped_closure(&store, &source.storage).await?;
    let (operation_id, lease) = store
        .begin_stopped_operation("fork", &closure.streams, &closure.objects)
        .await?;
    store
        .pin_operation_lowers(operation_id, &closure.lowers)
        .await?;
    let mut staging = OperationStaging::new(&pool, operation_id, &lease)?;
    for file in &source.files {
        file.file.sync_all()?;
    }
    let seeds = crate::machine::root_storage::launch_disk_seeds(
        &source.storage,
        &source.config.machine_dir,
        runtime.local_images_dir(),
    )?;
    let files = std::mem::take(&mut source.files)
        .into_iter()
        .map(|file| private_copy_source(&pool, &source.storage, &seeds, file, &lease))
        .collect::<Result<Vec<_>, _>>()?;
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
    let policy = options.external_resources();
    let _names = runtime.lock_machine_names().await?;
    let mut source = admit_stopped(&runtime, id, &policy, StoppedAdmission::Ordinary).await?;
    let store = runtime.native_store()?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let closure = stopped_closure(&store, &source.storage).await?;
    let (operation_id, lease) = store
        .begin_stopped_operation("snapshot", &closure.streams, &closure.objects)
        .await?;
    store
        .pin_operation_lowers(operation_id, &closure.lowers)
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
    let seeds = crate::machine::root_storage::launch_disk_seeds(
        &source.storage,
        &source.config.machine_dir,
        runtime.local_images_dir(),
    )?;
    let mut published = Vec::with_capacity(source.files.len());
    for file in std::mem::take(&mut source.files) {
        let source = private_copy_source(&pool, &source.storage, &seeds, file, &lease)?;
        published.push(publish_private_stream(&pool, &store, operation_id, source).await?);
    }
    let mut writable = published.into_iter();
    let root_content = writable
        .next()
        .ok_or_else(|| invalid("capture has no private root"))?;
    let (profile, geometry, layout) = match (&source.storage.root, closure.graph) {
        (
            MachineRoot::OpaqueRaw {
                geometry, layout, ..
            },
            None,
        ) => (SnapshotRootProfile::OpaqueRaw, *geometry, layout.clone()),
        (
            MachineRoot::LinuxOverlay {
                lower,
                upper_uuid,
                capacity,
                ext4_profile,
                overlay_profile,
                temporary_directory,
                ..
            },
            Some(graph),
        ) => (
            SnapshotRootProfile::LinuxOverlay {
                lower: Box::new(graph),
                lower_geometry: lower.geometry(),
                lower_filesystem_uuid: lower.filesystem_uuid(),
                upper_uuid: *upper_uuid,
                ext4_profile: *ext4_profile,
                overlay_profile: *overlay_profile,
                temporary_directory: *temporary_directory,
            },
            vm_spec::DiskGeometry {
                length: *capacity,
                logical_sector_size: 512,
            },
            crate::RawLayout::WholeDisk,
        ),
        _ => {
            return Err(invalid(
                "stopped root contradicts its retained lower closure",
            ))
        }
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
                let authenticated =
                    open_immutable_stream(&store, operation_id, stream, geometry.length).await?;
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
        memory: SnapshotMemoryState::None {
            stop_outcome: source.storage.stop_outcome,
        },
        root: SnapshotRoot {
            profile,
            stream: root_content,
            geometry,
            layout,
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

/// Pool closure a stopped operation pins before reading any source byte: the
/// machine's own edges plus, for a layered root, the retained composition and
/// every object/stream of its exact graph (published snapshots require each
/// one operation-pinned).
struct StoppedClosure {
    streams: Vec<crate::storage::identity::StreamId>,
    objects: Vec<crate::storage::identity::ObjectDigest>,
    lowers: Vec<crate::storage::identity::LowerResultId>,
    graph: Option<crate::store::models::snapshot::SnapshotComposition>,
}

async fn stopped_closure(
    store: &Store,
    storage: &MachineStorageRecord,
) -> Result<StoppedClosure, LibVmError> {
    let crate::store::cache_paths::PoolDependencies {
        mut streams,
        mut objects,
        lowers,
    } = crate::store::cache_paths::storage_pool_dependencies(storage)?;
    let graph = match &storage.root {
        MachineRoot::OpaqueRaw { .. } => None,
        MachineRoot::LinuxOverlay { lower, .. } => {
            let layers = crate::store::layer_store::LayerStore::from_store(store.clone());
            let retained = layers.retained_composition(lower.record()).await?;
            retained.check_lower(lower)?;
            crate::machine::root_storage::check_lower_platform(
                &retained.recipe.platform,
                &storage.boot,
            )?;
            let graph = layers.snapshot_composition(lower.record()).await?;
            if graph.result != lower.record() || graph.record != retained.record_digest {
                return Err(invalid("lower graph differs from its retained composition"));
            }
            for layer in &graph.layers {
                streams.insert(layer.pack.stream);
                objects.insert(layer.pack.map);
            }
            objects.extend(graph.objects());
            Some(graph)
        }
    };
    Ok(StoppedClosure {
        streams: streams.into_iter().collect(),
        objects: objects.into_iter().collect(),
        lowers: lowers.into_iter().collect(),
        graph,
    })
}

async fn publish_private_stream(
    pool: &StoragePool,
    store: &Store,
    operation: Uuid,
    source: PrivateSource,
) -> Result<SnapshotStream, LibVmError> {
    match source {
        PrivateSource::Owned { .. } => Err(invalid(
            "local fork cut is not an identified snapshot; snapshot the child first",
        )),
        PrivateSource::Fenced(source) => {
            let (stream, roots) =
                pool.publish_stream_file_for_catalog(source.file, source.length)?;
            store
                .pin_published_storage_dependencies(operation, &[stream.id], &[])
                .await?;
            let content = publish_map(pool, store, operation, &stream.map).await?;
            drop(roots);
            Ok(content)
        }
        PrivateSource::Authenticated { stream, .. } => {
            if crate::storage::identity_file::SourceFingerprint::new(&stream.file().metadata()?)
                != stream.fingerprint()
            {
                return Err(invalid(
                    "stopped baseline source changed before publication",
                ));
            }
            let dedup_roots = pool.lock_roots_shared()?;
            let receipt = match std::fs::symlink_metadata(pool.stream_path(&stream.map().id())) {
                Ok(_) => {
                    let content = SnapshotStream {
                        stream: stream.map().id(),
                        map: crate::storage::identity::ObjectDigest::from_sha256(
                            *stream.map().id().as_bytes(),
                        ),
                        length: stream.length(),
                        chunk_size: stream.map().chunk_size().bytes(),
                    };
                    store
                        .pin_published_storage_dependencies(
                            operation,
                            &[content.stream],
                            &[content.map],
                        )
                        .await?;
                    Some(
                        store
                            .authenticate_local_stream(operation, &content)
                            .await?
                            .fingerprint(),
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            drop(dedup_roots);
            let (publication, roots) = pool.publish_sealed_stream_for_catalog(
                stream.file(),
                stream.map(),
                receipt,
                crate::storage::pool::SealedStreamPublicationMode::CopyAllowed,
            )?;
            store
                .pin_published_storage_dependencies(operation, &[publication.map().id()], &[])
                .await?;
            let content = publish_map(pool, store, operation, publication.map()).await?;
            SnapshotStore::from_store(std::sync::Arc::new(store.clone()))
                .seed_map_receipt(&content, &publication)
                .await?;
            drop(roots);
            Ok(content)
        }
    }
}

fn reset_child_storage(storage: &mut MachineStorageRecord) {
    storage.disk_baselines.clear();
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
    if matches!(record.memory, SnapshotMemoryState::Included { .. }) {
        return Err(LibVmError::LiveOperationUnsupported {
            operation: vm_spec::live::LiveOperation::Restore,
            backend: vm_spec::live::LiveBackend::Krun,
            lane: vm_spec::live::LiveLane::NotApplicable,
            reason: vm_spec::live::LiveUnsupportedReason::new(
                vm_spec::live::LiveReasonCode::NotDelivered,
            ),
        });
    }
    let StoppedRoot {
        root,
        profile,
        backend,
    } = stopped_root(record)?;
    let mut storage = MachineStorageRecord {
        schema: 1,
        root,
        boot: record.boot.clone(),
        profile,
        backend,
        disk_baselines: Vec::new(),
        ram_identity: crate::store::models::storage::ContentIdentityState::Unknown,
        disk_identities: Vec::new(),
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
    storage.bind_disk_identity_inventory(&record.configuration.spec);
    validate_capture_shape(&storage, StoppedAdmission::Ordinary)?;
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

struct StoppedRoot {
    root: MachineRoot,
    profile: crate::StorageProfile,
    backend: crate::BackendRequirement,
}

/// The child root of a stopped snapshot. A layered lower keeps the exact
/// composition identity of its graph; geometry/UUID remain derived claims
/// that the record validation already checked against the graph.
fn stopped_root(record: &SnapshotRecord) -> Result<StoppedRoot, LibVmError> {
    Ok(match &record.root.profile {
        SnapshotRootProfile::OpaqueRaw => StoppedRoot {
            root: MachineRoot::OpaqueRaw {
                path: crate::PrivatePath::new("root.raw")?,
                geometry: record.root.geometry,
                layout: record.root.layout.clone(),
                initial_content: Some(record.root.stream.stream),
            },
            profile: crate::StorageProfile::OpaqueRawV1,
            backend: crate::BackendRequirement::RawBlock,
        },
        SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            lower_filesystem_uuid,
            upper_uuid,
            ext4_profile,
            overlay_profile,
            temporary_directory,
        } => StoppedRoot {
            root: MachineRoot::LinuxOverlay {
                lower: crate::OverlayLower::ErofsComposition {
                    record: lower.result,
                    geometry: *lower_geometry,
                    filesystem_uuid: *lower_filesystem_uuid,
                },
                upper: crate::PrivatePath::new("upper.raw")?,
                upper_uuid: *upper_uuid,
                capacity: record.root.geometry.length,
                ext4_profile: *ext4_profile,
                overlay_profile: *overlay_profile,
                temporary_directory: *temporary_directory,
            },
            profile: crate::StorageProfile::LinuxOverlayV1,
            backend: crate::BackendRequirement::KrunOverlay,
        },
    })
}

async fn restore_owned(
    runtime: Runtime,
    reference: SnapshotRef,
    options: RestoreOptions,
    progress: Option<&LiveOperationProgressSender>,
) -> Result<Machine, LibVmError> {
    runtime.require_recoverable_child_scopes()?;
    let store = runtime.native_store()?;
    // Read catalog metadata only: no artifact object is opened before consume
    // registers its retained operation. Unsupported policy/lane fails first.
    let preview = crate::store::observation::ObservationStore::existing(&store)
        .snapshot_record(&reference)
        .await?;
    let memory = matches!(preview.memory, SnapshotMemoryState::Included { .. });
    if memory && !options.without_memory {
        return crate::machine::restore::restore_owned(
            runtime, reference, options, preview, progress,
        )
        .await;
    }
    if options.activation_hook.is_some() {
        return Err(LibVmError::InvalidRequest {
            message: "an activation hook requires a snapshot with memory".to_owned(),
        });
    }
    let recovery = memory && options.without_memory;
    check_policy(&preview.external_requirements, &options.external_resources)?;
    let preview_storage = if recovery {
        crate::machine::restore::storage_from_snapshot(&preview, preview.id()?)?
    } else {
        storage_from_snapshot(&preview)?
    };
    runtime.preflight_captured_lane(&preview_storage, CaptureLane::Stopped)?;
    report_progress(progress, LiveOperationProgress::PreparingChildStorage);
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(&runtime, options.name.as_deref()).await?;
    let snapshots = SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let mut consumer = if recovery {
        snapshots.consume_disks(&reference).await?
    } else {
        snapshots.consume(&reference).await?
    };
    if consumer.record != preview {
        return Err(invalid("snapshot changed after restore preflight"));
    }
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let mut staging = OperationStaging::new(&pool, consumer.operation_id, &consumer.lease)?;
    // A retained layered lower is re-registered from the authenticated,
    // exact-loaded snapshot graph and pinned under the consumer before the
    // child (whose root names it) can be published.
    if let Some(lower) = consumer.record.lower() {
        let layers = crate::store::layer_store::LayerStore::from_store(store.clone());
        let id = layers
            .publish_snapshot_composition(consumer.operation_id, lower)
            .await?;
        let retained = layers.retained_composition(id).await?;
        crate::machine::root_storage::check_lower_platform(
            &retained.recipe.platform,
            &consumer.record.boot,
        )?;
    }
    tracing::debug!(snapshot = %consumer.info.id, operation = %consumer.operation_id, "restoring stopped snapshot");
    let mut storage = preview_storage;
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
        path: crate::PrivatePath::new(match storage.root {
            MachineRoot::OpaqueRaw { .. } => "root.raw",
            _ => "upper.raw",
        })?,
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
    durability: crate::MachineDurability,
}

impl OperationStaging {
    pub(crate) fn new(
        pool: &StoragePool,
        operation: Uuid,
        lease: &StorageLock,
    ) -> Result<Self, LibVmError> {
        Self::new_with_durability(pool, operation, lease, crate::MachineDurability::Durable)
    }

    pub(crate) fn new_deferred(
        pool: &StoragePool,
        operation: Uuid,
        lease: &StorageLock,
    ) -> Result<Self, LibVmError> {
        Self::new_with_durability(
            pool,
            operation,
            lease,
            crate::MachineDurability::Constructed,
        )
    }

    fn new_with_durability(
        pool: &StoragePool,
        operation: Uuid,
        lease: &StorageLock,
        durability: crate::MachineDurability,
    ) -> Result<Self, LibVmError> {
        let paths = if durability == crate::MachineDurability::Constructed {
            pool.create_operation_with_lease_deferred(operation, lease.duplicate()?)?
        } else {
            pool.create_operation_with_lease(operation, lease.duplicate()?)?
        };
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
            durability,
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
            if self.durability == crate::MachineDurability::Durable {
                self.parent.sync()?;
            }
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

pub(crate) async fn open_immutable_stream(
    store: &Store,
    operation: Uuid,
    stream: &crate::storage::identity::StreamId,
    length: u64,
) -> Result<crate::storage::stream::AuthenticatedStream, LibVmError> {
    store
        .authenticate_local_stream(
            operation,
            &SnapshotStream {
                stream: *stream,
                map: crate::storage::identity::ObjectDigest::from_sha256(*stream.as_bytes()),
                length,
                chunk_size: vm_spec::stream_map::ChunkSize::DISK.bytes(),
            },
        )
        .await
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
            .restore(
                crate::RestoreSource::Local(crate::SnapshotRef::Name("not-opened".into())),
                crate::RestoreOptions {
                    name: Some("refused-restore".into()),
                    ..Default::default()
                },
                None,
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
        storage.bind_disk_identity_inventory(&config.spec);
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
        assert_eq!(child_storage.disk_baselines.len(), 2);
        let seeds = crate::machine::root_storage::launch_disk_seeds(
            &child_storage,
            &child_config.machine_dir,
            runtime.local_images_dir(),
        )
        .unwrap();
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].role, vm_spec::DiskRole::Root);
        assert_eq!(seeds[1].role, vm_spec::DiskRole::Data);
        assert_ne!(seeds[0].epoch, seeds[1].epoch);
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

    #[tokio::test]
    async fn stopped_copy_inherits_disk_root_and_nodes_without_payload_reads() {
        use crate::machine::stopped::{private_copy_source, FencedSource, PrivateSource};
        use crate::storage::stream::StreamHasher;
        use vm_spec::stream_map::ChunkSize;

        let temporary = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(temporary.path());
        let store = crate::store::Store::new(&paths).await.unwrap();
        let pool = crate::storage::pool::StoragePool::open(paths.images_dir()).unwrap();
        let directory =
            crate::paths::OwnedDirectory::open_root(&temporary.path().join("private")).unwrap();
        directory.write_file("root.raw", &[0x41; 512]).unwrap();
        let path = directory.path().join("root.raw");
        let file = std::fs::File::open(&path).unwrap();
        let map = StreamHasher::new(ChunkSize::DISK)
            .hash_open_file(&file, 512)
            .unwrap()
            .map;
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let disk = crate::machine::root_storage::disk(
            "root.raw",
            vm_spec::DiskRole::Root,
            512,
            "root".into(),
        )
        .unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("fork", &[], &[])
            .await
            .unwrap();
        let roots = crate::machine::root_storage::seed_disk(
            &mut storage,
            &pool,
            directory.path(),
            0,
            &disk,
            &file,
            &map,
        )
        .unwrap();
        store
            .admit_published_map_root(operation, &map)
            .await
            .unwrap();
        drop(roots);
        let (publication, publication_roots) = pool
            .publish_sealed_stream_for_catalog(
                &file,
                &map,
                None,
                crate::storage::pool::SealedStreamPublicationMode::CopyAllowed,
            )
            .unwrap();
        let content = crate::store::snapshot_store::publish_map(&pool, &store, operation, &map)
            .await
            .unwrap();
        crate::store::snapshot_store::SnapshotStore::from_store(std::sync::Arc::new(store.clone()))
            .seed_map_receipt(&content, &publication)
            .await
            .unwrap();
        drop(publication_roots);
        #[cfg(target_os = "linux")]
        let reads = crate::store::snapshot_store::tests::watch_stream_reads(&path);
        #[cfg(target_os = "linux")]
        let pool_reads =
            crate::store::snapshot_store::tests::watch_stream_reads(&pool.stream_path(&map.id()));
        let seeds = crate::machine::root_storage::launch_disk_seeds(
            &storage,
            directory.path(),
            paths.images_dir(),
        )
        .unwrap();
        let source = private_copy_source(
            &pool,
            &storage,
            &seeds,
            FencedSource {
                path: crate::PrivatePath::new("root.raw").unwrap(),
                file,
                length: 512,
            },
            &lease,
        )
        .unwrap();
        let PrivateSource::Authenticated { stream, .. } = source else {
            panic!("ready stopped baseline was not inherited");
        };
        assert_eq!(stream.map().id(), map.id());
        assert_eq!(stream.map().chunk_size(), ChunkSize::DISK);
        assert_eq!(stream.map().root().tree_digest(), map.root().tree_digest());
        assert_eq!(stream.map().lookup(0).unwrap(), map.lookup(0).unwrap());
        #[cfg(target_os = "linux")]
        assert!(!crate::store::snapshot_store::tests::observed_stream_read(
            &reads
        ));
        let published = crate::machine::stopped::publish_private_stream(
            &pool,
            &store,
            operation,
            PrivateSource::Authenticated {
                path: crate::PrivatePath::new("root.raw").unwrap(),
                stream,
            },
        )
        .await
        .unwrap();
        assert_eq!(published, content);
        #[cfg(target_os = "linux")]
        {
            assert!(!crate::store::snapshot_store::tests::observed_stream_read(
                &reads
            ));
            assert!(!crate::store::snapshot_store::tests::observed_stream_read(
                &pool_reads
            ));
        }
        store.finish_stopped_operation(operation).await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stopped_fork_never_inherits_external_mapping_identity_even_for_the_same_path() {
        use crate::store::models::storage::ContentIdentityState;
        use crate::store::MachineStore;
        use std::os::unix::fs::PermissionsExt;

        let (home, runtime, source) = raw_source("external-identity-parent").await;
        let external = home.path().join("external.raw");
        let replacement = home.path().join("replacement.raw");
        for (path, byte) in [(&external, 0x31), (&replacement, 0x72)] {
            std::fs::write(path, [byte; 512]).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut config = runtime
            .machine_config(source.machine_id())
            .await
            .unwrap()
            .unwrap();
        config.spec.storage.as_mut().unwrap().disks.push(
            crate::machine::root_storage::disk(
                &external,
                vm_spec::DiskRole::Data,
                512,
                "source-external".into(),
            )
            .unwrap(),
        );
        let mut storage = runtime
            .machine_storage_record(source.machine_id())
            .await
            .unwrap();
        storage.bind_disk_identity_inventory(&config.spec);
        let map = crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_file(&external)
            .unwrap();
        storage.disk_identities[1].identity = ContentIdentityState::Identified {
            root: map.root().id(),
        };
        let store = runtime.native_store().unwrap();
        store
            .save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        for (name, path) in [("same-external", external), ("new-external", replacement)] {
            let child = source
                .fork_stopped(crate::ForkOptions {
                    name: Some(name.into()),
                    external_resources: ExternalResourcePolicy::Map {
                        mappings: vec![ExternalResourceMapping {
                            resource: ExternalResourceKey::Disk { order: 1 },
                            path: path.clone(),
                        }],
                    },
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
            assert_eq!(
                child_config.spec.storage.as_ref().unwrap().disks[1].path,
                path
            );
            assert_eq!(
                child_storage.disk_identities[1].identity,
                ContentIdentityState::Unknown
            );
            assert!(child_storage
                .disk_baselines
                .iter()
                .all(|baseline| baseline.seed.attachment_index != 1));
            child_storage
                .validate_disk_identity_inventory(&child_config.spec)
                .unwrap();
        }
        assert_eq!(
            runtime
                .machine_storage_record(source.machine_id())
                .await
                .unwrap(),
            storage
        );
    }

    /// A runtime over an acquisition destination, with `registry.example`
    /// as its only search registry. The host never resolves, so any pull
    /// fails: success proves the local copy was used.
    async fn acquired_runtime(store: std::sync::Arc<crate::store::Store>) -> crate::Runtime {
        let paths = crate::paths::LocalPaths::new(store.home_path().to_path_buf());
        let components = crate::runtime::components::test_components(paths.home());
        crate::Runtime::from_store(
            paths,
            store,
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::new(
                crate::RegistryAction::Allow,
                vec!["registry.example".into()],
                Vec::new(),
            )
            .unwrap(),
            components,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn registry_restore_reuses_the_acquired_snapshot_without_pulling() {
        use crate::image::transport::tests::{
            home, index_digest, stage, stopped_export, transfer, verify, REFERENCE,
        };
        let (_temp, _lease, prepared) = stopped_export().await;
        let good = transfer(&prepared.graph, &prepared.payloads());
        let (_destination_temp, destination) = home().await;
        let verified = verify(&good, stage(&destination, &good).await, index_digest(&good))
            .await
            .unwrap();
        let committed = crate::store::artifact_store::commit_imported_artifact(
            verified,
            REFERENCE.into(),
            None,
        )
        .await
        .unwrap();
        let crate::image::transport::AcquiredContent::Snapshot(acquired) = &committed.content
        else {
            panic!("snapshot artifact committed another kind");
        };
        let id = acquired.id;
        drop(committed);
        let runtime = acquired_runtime(destination.clone()).await;
        for (input, pull) in [
            (REFERENCE, crate::PullPolicy::IfMissing),
            ("team/vm:v1", crate::PullPolicy::IfMissing),
            ("team/vm:v1", crate::PullPolicy::Never),
        ] {
            assert_eq!(
                runtime
                    .resolve_restore_source(crate::RestoreSource::Registry(input.into()), pull)
                    .await
                    .unwrap(),
                id,
                "{input} {pull:?}"
            );
        }
        // A local source never pulls, even for a registry reference.
        assert_eq!(
            runtime
                .resolve_restore_source(
                    crate::RestoreSource::Local(crate::SnapshotRef::Name(REFERENCE.into())),
                    crate::PullPolicy::Always,
                )
                .await
                .unwrap(),
            id
        );
        let acquisitions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM managed_artifact_acquisition")
                .fetch_one(&destination.pool)
                .await
                .unwrap();
        assert_eq!(acquisitions, 1);
    }

    #[tokio::test]
    async fn registry_restore_of_an_acquired_image_names_the_create_command() {
        use crate::image::transport::tests::{
            export, home, index_digest, stage, transfer, verify, REFERENCE,
        };
        let (temp, images, record, operation, lease) =
            crate::store::stored_image_store::tests::fixture().await;
        let info = images
            .publish_owned(record, operation, lease, None, Vec::new(), None)
            .await
            .unwrap();
        let source = std::sync::Arc::new(
            crate::store::Store::new(&crate::paths::LocalPaths::new(temp.path().join("home")))
                .await
                .unwrap(),
        );
        let prepared = export(
            source,
            crate::image::transport::export::ExportSource::Image(Box::new(
                images.consume(info.id).await.unwrap(),
            )),
            oci::vm_artifact::codec::ChunkEncoding::Zstd,
        )
        .await;
        let good = transfer(&prepared.graph, &prepared.payloads());
        let (_destination_temp, destination) = home().await;
        let verified = verify(&good, stage(&destination, &good).await, index_digest(&good))
            .await
            .unwrap();
        drop(
            crate::store::artifact_store::commit_imported_artifact(
                verified,
                REFERENCE.into(),
                None,
            )
            .await
            .unwrap(),
        );
        let runtime = acquired_runtime(destination).await;
        for input in [REFERENCE, "team/vm:v1"] {
            let error = runtime
                .restore(
                    crate::RestoreSource::Registry(input.into()),
                    crate::RestoreOptions::default(),
                    None,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&error, crate::LibVmError::ImageIsNotASnapshot { reference } if reference == input),
                "{input}: {error:?}"
            );
            assert!(error
                .to_string()
                .contains(&format!("use `silo create {input}`")));
        }
    }

    // Boot capture is admitted only on the Linux krun lane
    // (boot_assets::validate_captured_boot_lane), and memory snapshots need live capture.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restore_without_memory_turns_a_memory_snapshot_into_a_stopped_machine() {
        use crate::store::MachineStore;
        let fixture = crate::store::capture::tests::fixture_with_retention(
            crate::MachineRetention::Ephemeral,
        )
        .await;
        assert_eq!(
            fixture.reservation.record.configuration.retention,
            crate::MachineRetention::Ephemeral
        );
        let runtime = crate::store::capture::tests::capture_runtime(&fixture.snapshots).await;
        let (sealed, _) = crate::store::capture::tests::seal(&fixture);
        let info = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                sealed.path(),
                fixture.reservation.record.name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(info.memory, crate::SnapshotMemory::Included);
        let hook = vm_spec::restore::RestoreHook {
            argv: vec!["/bin/true".into()],
            environment: Vec::new(),
            working_directory: "/".into(),
            timeout_ms: 1000,
        };
        let refused = runtime
            .restore(
                crate::RestoreSource::Local(crate::SnapshotRef::Id(info.id)),
                crate::RestoreOptions {
                    name: Some("hooked".into()),
                    without_memory: true,
                    activation_hook: Some(hook),
                    ..Default::default()
                },
                None,
            )
            .await;
        assert!(
            matches!(refused, Err(crate::LibVmError::InvalidRequest { .. })),
            "{refused:?}"
        );
        let machine = runtime
            .restore(
                crate::RestoreSource::Local(crate::SnapshotRef::Id(info.id)),
                crate::RestoreOptions {
                    name: Some("recovered".into()),
                    without_memory: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let store = runtime.native_store().unwrap();
        assert_eq!(
            store
                .machine_config(machine.machine_id())
                .await
                .unwrap()
                .unwrap()
                .retention,
            crate::MachineRetention::Persistent
        );
        let state = store
            .machine_state(machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            state.status,
            crate::store::models::MachineRuntimeState::Stopped
        );
        assert_eq!(state.run_id, None);
        let storage = store
            .machine_storage(machine.machine_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(storage.snapshot, Some(info.id));
        assert!(store
            .machine_config_by_name("hooked")
            .await
            .unwrap()
            .is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn memory_snapshot_of_a_stopped_machine_names_the_running_requirement() {
        let (_home, runtime, source) = raw_source("stopped-source").await;
        let result = runtime
            .snapshot(
                &crate::MachineRef::id(source.machine_id()),
                crate::SnapshotOptions {
                    memory: true,
                    ..Default::default()
                },
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(crate::LibVmError::MemorySnapshotRequiresRunningMachine { .. })
            ),
            "{result:?}"
        );
        assert!(runtime.snapshots().list().await.unwrap().is_empty());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restore_preflight_resolves_local_kinds_without_registry_contacts() {
        let (home, runtime, _source) = raw_source("preflight-source").await;
        let registry = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        registry.set_nonblocking(true).unwrap();
        let policy = crate::RegistryPolicy::new(
            crate::RegistryAction::Allow,
            vec![registry.local_addr().unwrap().to_string()],
            Vec::new(),
        )
        .unwrap();
        let store = runtime.native_store().unwrap();
        let image = runtime.images().list().await.unwrap().remove(0).id();
        let expanded = policy.candidates("image-expanded").unwrap()[0].to_string();
        for name in ["image-only", "hello", &expanded] {
            sqlx::query("INSERT INTO image_name(name,stored_image_id,updated_at) VALUES(?1,?2,0)")
                .bind(name)
                .bind(image.to_string())
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let snapshot = runtime
            .snapshot(
                &crate::MachineRef::parse("preflight-source").unwrap(),
                crate::SnapshotOptions {
                    name: Some("hello".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        crate::store::snapshot_store::insert_name(
            &mut store.pool.acquire().await.unwrap(),
            "snapshot-only",
            snapshot.snapshot.id,
        )
        .await
        .unwrap();
        let config = crate::RuntimeConfig::local(home.path().join("silo"))
            .with_runtime_components(crate::runtime::components::test_components(home.path()))
            .with_registry_policy(policy);
        let query = crate::LiveCapabilityQuery::open(&config).unwrap();
        let options = crate::RestoreOptions::default();
        let image_id = image.to_string();
        for reference in ["image-only", "image-expanded", &image_id, &image_id[7..15]] {
            let error = crate::preflight_restore_snapshot(
                &config,
                &query,
                &reference.parse().unwrap(),
                &options,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, crate::LibVmError::ImageIsNotASnapshot { reference: actual }
                    if actual == reference),
                "{reference}: {error:?}"
            );
        }
        let error = crate::preflight_restore_snapshot(
            &config,
            &query,
            &"unknown-local-name".parse().unwrap(),
            &options,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::SnapshotNotFound { reference } if reference == "unknown-local-name"
        ));
        for reference in ["snapshot-only", "hello"] {
            crate::preflight_restore_snapshot(
                &config,
                &query,
                &reference.parse().unwrap(),
                &options,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            registry.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn restore_preflight_absent_home_is_not_found_without_initialization() {
        let home = tempfile::tempdir().unwrap();
        let absent = home.path().join("absent");
        let config = crate::RuntimeConfig::local(&absent)
            .with_runtime_components(crate::runtime::components::test_components(home.path()));
        let query = crate::LiveCapabilityQuery::open(&config).unwrap();
        let error = crate::preflight_restore_snapshot(
            &config,
            &query,
            &"missing".parse().unwrap(),
            &crate::RestoreOptions {
                without_memory: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::SnapshotNotFound { reference } if reference == "missing"
        ));
        assert!(!absent.exists());
    }

    #[tokio::test]
    async fn restore_missing_bare_name_never_pulls_even_with_always() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(temporary.path().join("home"));
        let store = std::sync::Arc::new(crate::store::Store::new(&paths).await.unwrap());
        let runtime = acquired_runtime(store.clone()).await;
        for policy in [
            crate::PullPolicy::IfMissing,
            crate::PullPolicy::Always,
            crate::PullPolicy::Never,
        ] {
            let error = runtime
                .resolve_restore_source(
                    crate::RestoreSource::Registry("nonexistent".into()),
                    policy,
                )
                .await
                .unwrap_err();
            assert!(
                matches!(error, crate::LibVmError::SnapshotNotFound { reference } if reference == "nonexistent")
            );
        }
        let acquisitions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM managed_artifact_acquisition")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(acquisitions, 0);
    }

    #[test]
    fn restore_name_validation_preserves_machine_name_rule() {
        let error = crate::RestoreOptions {
            name: Some("wr-anon1.8g".into()),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert!(
            matches!(error, crate::LibVmError::InvalidMachineName { name, .. } if name == "wr-anon1.8g")
        );
    }
    #[tokio::test]
    async fn qualified_restore_pull_failure_reports_snapshot_reference_and_cause() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(temporary.path().join("home"));
        let store = std::sync::Arc::new(crate::store::Store::new(&paths).await.unwrap());
        let components = crate::runtime::components::test_components(paths.home());
        let runtime = crate::Runtime::from_store(
            paths,
            store,
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::new(
                crate::RegistryAction::Deny,
                vec!["registry.example".into()],
                Vec::new(),
            )
            .unwrap(),
            components,
            None,
        )
        .await
        .unwrap();
        let expanded = runtime
            .registry_policy()
            .candidates("team/nonexistent")
            .unwrap()[0]
            .to_string();
        let error = runtime
            .resolve_restore_source(
                crate::RestoreSource::Registry("team/nonexistent".into()),
                crate::PullPolicy::Always,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&error, crate::LibVmError::SnapshotPullFailed { reference, message }
            if reference == "team/nonexistent" && message.contains(&expanded) && message.contains("denied")),
            "{error:?}"
        );
    }
}

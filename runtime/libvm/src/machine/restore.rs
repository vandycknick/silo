//! Snapshots with memory have their own constructor. No ordinary start, root
//! repair, resize, bootstrap execution or fallback is part of this path.
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use vm_spec::capture::{CaptureConfiguration, Sha256Digest};
use vm_spec::live::{LiveHostReport, LiveOperation};
use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

use crate::machine::lifecycle::{
    finish_failed_start, started_run_monitor, FailedStartState, FailedStartStorage,
};
use crate::machine::live_operations::{
    report_progress, LiveOperationProgress, LiveOperationProgressSender,
};
use crate::machine::root_storage::invalid;
use crate::machine::stopped::PrivateSource;
use crate::storage::pool::StoragePool;
use crate::storage::vmdk::{LowerBacking, LowerOccurrence};
use crate::store::models::snapshot::{SnapshotMemoryState, SnapshotRecord, SnapshotRootProfile};
use crate::store::restore::RestoreIntent;
use crate::store::snapshot_store::SnapshotStore;
use crate::supervisor::launch::{install_child_inheritance, RestoreLaunch};
use crate::{
    DiskStorage, ExternalResourcePolicy, LibVmError, Machine, MachineRoot, MachineStorageRecord,
    RestoreOptions, Runtime, SnapshotRef,
};

pub(crate) async fn preflight_execution(
    query: &crate::LiveCapabilityQuery,
    record: &SnapshotRecord,
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    crate::require_host_live_operation(&query.host_report().await?, LiveOperation::Restore)?;
    validate_profile(record, policy)?;
    Ok(())
}

fn validate_profile(
    record: &SnapshotRecord,
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    record.validate()?;
    if !matches!(record.memory, SnapshotMemoryState::Included { .. }) {
        return Err(invalid("execution restore requires a snapshot with memory"));
    }
    if !record.external_requirements.is_empty() || !matches!(policy, ExternalResourcePolicy::Reject)
    {
        return Err(invalid("the admitted live profile has no external resources; destination mappings cannot widen its authority"));
    }
    if !record.configuration.guest.agent.enabled() {
        return Err(invalid(
            "execution restore requires the captured managed agent",
        ));
    }
    if !matches!(
        record.boot,
        crate::BootProfile::LinuxDirect {
            binding: crate::BootBinding::Pinned { agent: Some(_), .. },
            ..
        }
    ) {
        return Err(invalid("execution restore requires exact pinned kernel, initramfs and managed-agent provenance"));
    }
    Ok(())
}

pub(crate) async fn restore_owned(
    runtime: Runtime,
    reference: SnapshotRef,
    options: RestoreOptions,
    preview: SnapshotRecord,
    progress: Option<&LiveOperationProgressSender>,
) -> Result<Machine, LibVmError> {
    // Repeat the observation-only gate before a consumer, name lock or budget.
    let host_report = runtime.live_capabilities().await?;
    crate::require_host_live_operation(&host_report, LiveOperation::Restore)?;
    validate_profile(&preview, &options.external_resources)?;
    if let Some(hook) = &options.activation_hook {
        hook.validate().map_err(invalid)?;
    }
    let store = runtime.native_store()?;
    let snapshots = SnapshotStore::from_store(Arc::new(store.clone()));
    let consumer = snapshots.consume_shape(&reference).await?;
    report_progress(progress, LiveOperationProgress::PreparingChildStorage);
    let result = async {
        let shape = snapshots.prepare_restore_shape(&consumer).await?;
        if consumer.record != preview {
            return Err(invalid(
                "snapshot name changed between preflight and verification",
            ));
        }
        restore_consumer(
            &runtime,
            &snapshots,
            &consumer,
            options,
            progress,
            host_report,
            shape,
        )
        .await
    }
    .await;
    drop(consumer);
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let cleanup = store.retire_abandoned_storage_operations(&pool).await;
    match (result, cleanup) {
        (result, Ok(_)) => result,
        (Err(primary), Err(cleanup)) => Err(LibVmError::MachineStartCleanupFailed {
            primary: primary.to_string(),
            cleanup: cleanup.to_string(),
        }),
        (Ok(machine), Err(cleanup)) => Err(LibVmError::MachineStartCleanupFailed {
            primary: format!(
                "restore activated child {}, but verification owner retirement is incomplete",
                machine.machine_id()
            ),
            cleanup: cleanup.to_string(),
        }),
    }
}

async fn restore_consumer(
    runtime: &Runtime,
    snapshots: &SnapshotStore,
    consumer: &crate::store::snapshot_store::SnapshotConsumer,
    options: RestoreOptions,
    progress: Option<&LiveOperationProgressSender>,
    host_report: LiveHostReport,
    inspection_shape: crate::store::snapshot_store::RestoreInspectionShape,
) -> Result<Machine, LibVmError> {
    let shape = inspection_shape.shape();
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let evidence = snapshots.restore_evidence(consumer, &pool)?.evidence;
    let execution = match &consumer.record.memory {
        SnapshotMemoryState::Included { execution } => execution,
        _ => return Err(invalid("snapshot memory changed")),
    };
    let transfer_roles = 5 + if matches!(
        consumer.record.root.profile,
        SnapshotRootProfile::LinuxOverlay { .. }
    ) {
        2
    } else {
        0
    };
    // Byte authentication retains closure descriptors through private copy.
    crate::storage::limits::preflight_fd_budget(
        3 * transfer_roles
            + 3 * consumer.record.disks.len() as u64
            + 32
            + shape.retained_descriptors(),
    )
    .map_err(crate::storage::StorageError::from)?;
    let ram = shape.open_stream(&pool, &execution.memory.stream, execution.memory.length)?;
    let map_stage = crate::machine::stopped::OperationStaging::new_deferred(
        &pool,
        consumer.operation_id,
        &consumer.lease,
    )?;
    let ram_map = execution.memory.map;
    let ram_map_file = shape.open_object(&pool, &ram_map)?;
    let objects = [
        ram,
        shape.open_object(&pool, &execution.layout)?,
        shape.open_object(&pool, &execution.execution)?,
        shape.open_object(&pool, &execution.devices)?,
        ram_map_file,
    ];
    let lower_inputs = prepare_lower(&pool, consumer, map_stage, shape)?;
    let request = snapshot_restore_request(
        runtime,
        consumer,
        evidence,
        &objects,
        lower_inputs.as_ref(),
        options.activation_hook,
    )?;
    let network = !matches!(
        consumer.record.configuration.network,
        crate::store::models::MachineNetworkConfig::None
    );
    let images = runtime.local_images_dir().to_path_buf();
    let shape = tokio::task::spawn_blocking(move || inspection_shape.complete(&images));
    let (inspection, shape) = tokio::try_join!(
        inspect(runtime.supervisor().executable(), &request, network),
        async { shape.await? },
    )?;
    if inspection.lane != host_report.lane {
        return Err(invalid(
            "native restore inspection lane differs from the selected host capability report",
        ));
    }
    let storage = storage_from_snapshot(&consumer.record, consumer.info.id)?;
    crate::store::operation_store::preflight_launch_storage(
        &storage,
        &consumer.record.configuration.spec,
    )?;
    let transfer_roles = request.objects.len() as u64
        + request
            .lowers
            .iter()
            .map(|lower| 1 + lower.extents.len() as u64)
            .sum::<u64>();
    let native_records = lower_inputs
        .as_ref()
        .map_or(0, |lower| lower.native_records);
    let descriptor_peak = (3 * transfer_roles).max(native_records + transfer_roles)
        + 3 * request.configuration.attachments.len() as u64
        + 32
        + shape.retained_descriptors();
    // Charge the closure authentication and construction descriptor sets
    // together until their deterministic join.
    crate::storage::limits::preflight_fd_budget(descriptor_peak)
        .map_err(crate::storage::StorageError::from)?;
    // Copy against structurally verified maps while full byte authentication
    // runs concurrently. Both must succeed before publication.
    let sources = snapshot_private_sources(&pool, &consumer.record, &shape, &storage)?;
    let disk_peak = restore_disk_peak(runtime.local_images_dir(), &sources, &consumer.record)?;
    let resources = snapshots
        .reserve_restore_resources(consumer, disk_peak, descriptor_peak)
        .await?;
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(runtime, options.name.as_deref()).await?;
    let run = Uuid::new_v4();
    let intent = RestoreIntent {
        source: crate::store::restore::RestoreIdentity::Snapshot {
            id: consumer.info.id,
        },
        consumer_operation: consumer.operation_id,
        request: request.clone(),
        resources,
        inspection,
        network_attachment: network,
    };
    execute_prepared(
        runtime,
        PreparedRestore {
            configuration: consumer.record.configuration.clone(),
            storage,
            sources,
            intent,
            request,
            objects: objects.into(),
            lower_inputs,
            shared_qualification: None,
            authentication: Some(RestoreAuthentication::new(snapshots.clone(), shape)),
        },
        name,
        run,
        Some(_names),
        progress,
        (1, 1),
    )
    .await
}

fn snapshot_private_sources(
    pool: &StoragePool,
    record: &SnapshotRecord,
    shape: &crate::store::snapshot_store::ShapeVerifiedClosure,
    storage: &MachineStorageRecord,
) -> Result<Vec<PrivateSource>, LibVmError> {
    let mut sources = vec![PrivateSource::Authenticated {
        path: crate::PrivatePath::new(match &storage.root {
            MachineRoot::OpaqueRaw { .. } => "root.raw",
            _ => "upper.raw",
        })?,
        stream: shape.open_copy_source(
            pool,
            &record.root.stream.stream,
            record.root.geometry.length,
        )?,
    }];
    for disk in &record.disks {
        if disk.writable {
            sources.push(PrivateSource::Authenticated {
                path: crate::PrivatePath::new(format!("disk-{}.raw", disk.order))?,
                stream: shape.open_copy_source(pool, &disk.content.stream, disk.geometry.length)?,
            });
        }
    }
    Ok(sources)
}

pub(crate) fn snapshot_restore_request(
    runtime: &Runtime,
    consumer: &crate::store::snapshot_store::SnapshotConsumer,
    evidence: vm_spec::capture::CaptureEvidence,
    objects: &[File; 5],
    lower_inputs: Option<&LowerInputs>,
    hook: Option<crate::RestoreHook>,
) -> Result<RestoreRequest, LibVmError> {
    let SnapshotMemoryState::Included { execution } = &consumer.record.memory else {
        return Err(invalid("snapshot memory changed"));
    };
    let digests = [
        Sha256Digest::from_bytes(*execution.memory.stream.as_bytes()),
        Sha256Digest::from_bytes(*execution.layout.as_bytes()),
        Sha256Digest::from_bytes(*execution.execution.as_bytes()),
        Sha256Digest::from_bytes(*execution.devices.as_bytes()),
        Sha256Digest::from_bytes(*execution.memory.map.as_bytes()),
    ];
    let mut descriptors = Vec::with_capacity(objects.len());
    for ((file, role), identity) in objects.iter().zip(RestoreObjectRole::ALL).zip(digests) {
        let metadata = file.metadata()?;
        if metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(invalid(
                "restore state backing lost its immutable pool identity",
            ));
        }
        descriptors.push(RestoreObject {
            role,
            fd: file.as_raw_fd(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
            length: metadata.len(),
            authority: vm_spec::restore::RestoreObjectAuthority::Identified { identity },
        });
    }
    let freeze_operation_id = evidence
        .freeze_operation_id
        .clone()
        .ok_or_else(|| invalid("capture seal omitted the frozen operation identity"))?;
    let request = RestoreRequest {
        purpose: vm_spec::restore::ActivationPurpose::Clone,
        disk_tracking_seeds: Vec::new(),
        map_node_store: Some(
            runtime
                .local_images_dir()
                .join("objects/sha256")
                .to_str()
                .ok_or_else(|| invalid("restore map node store path is not UTF-8"))?
                .to_owned(),
        ),
        version: vm_spec::restore::RESTORE_REQUEST_VERSION,
        authority: vm_spec::restore::RestoreAuthority::IdentifiedSnapshot {
            snapshot: Sha256Digest::from_bytes(*consumer.info.id.as_bytes()),
            evidence: Box::new(evidence),
        },
        activation_id: vm_spec::lifecycle::LiveId::parse(&Uuid::new_v4().to_string())
            .map_err(invalid)?,
        freeze_operation_id,
        start_paused: true,
        configuration: CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
            .map_err(invalid)?,
        objects: descriptors,
        lowers: lower_inputs
            .map(|lower| vec![lower.request.clone()])
            .unwrap_or_default(),
        network: None,
        ssh_trusted_ca: None,
        hook,
    };
    request.validate_for_inspection().map_err(invalid)?;
    Ok(request)
}

struct PreparedRestore {
    configuration: crate::SnapshotConfiguration,
    storage: MachineStorageRecord,
    sources: Vec<PrivateSource>,
    intent: RestoreIntent,
    request: RestoreRequest,
    objects: Vec<File>,
    lower_inputs: Option<LowerInputs>,
    authentication: Option<RestoreAuthentication>,
    shared_qualification: Option<Arc<crate::machine::root_disk::SharedCopyQualification>>,
}

pub(crate) struct RestoreAuthentication {
    snapshots: SnapshotStore,
    shape: crate::store::snapshot_store::ShapeVerifiedClosure,
}

impl RestoreAuthentication {
    pub(crate) fn new(
        snapshots: SnapshotStore,
        shape: crate::store::snapshot_store::ShapeVerifiedClosure,
    ) -> Self {
        Self { snapshots, shape }
    }

    pub(crate) async fn authenticate(self) -> Result<(), LibVmError> {
        self.snapshots
            .authenticate_closure_bytes(self.shape)
            .await?;
        Ok(())
    }
}

/// Both snapshot and local-cut restore use this exact construction, generation
/// handoff, activation and failed-start cleanup path.
async fn execute_prepared(
    runtime: &Runtime,
    prepared: PreparedRestore,
    name: String,
    run: Uuid,
    names: Option<File>,
    progress: Option<&LiveOperationProgressSender>,
    child: (usize, usize),
) -> Result<Machine, LibVmError> {
    let PreparedRestore {
        configuration,
        storage,
        sources,
        intent,
        request,
        objects,
        lower_inputs,
        authentication,
        shared_qualification,
    } = prepared;
    let store = runtime.native_store()?;
    let snapshots = SnapshotStore::from_store(Arc::new(store.clone()));
    store
        .persist_restore_construction(&crate::store::restore::RestoreConstruction {
            run_id: run,
            name: name.clone(),
            intent: intent.clone(),
        })
        .await?;
    let (config, mut durability) = crate::machine::builder::publish_restored_child(
        runtime,
        crate::machine::builder::ChildConstruction {
            name,
            configuration,
            storage,
            sources,
            operation_id: intent.consumer_operation,
            shared_qualification,
        },
        run,
        authentication,
    )
    .await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let consumer_lease = pool.existing_lease(intent.consumer_operation)?;
    durability.files.push(consumer_lease.durability_file()?);
    durability.launch_directories.push(pool.lease_directory()?);
    store
        .child_event(intent.consumer_operation, "prepared")
        .await?;
    drop(names);
    let (lock, config) = runtime.lock_machine_config(config.id).await?;
    let storage = runtime.machine_storage_record(config.id).await?;
    if let Some(lower) = &lower_inputs {
        let destination = crate::paths::OwnedDirectory::open_existing_root(&config.machine_dir)?
            .ok_or_else(|| invalid("restore child disappeared before lower handoff"))?;
        crate::storage::pool::rename_component_no_replace(
            &lower.directory,
            "lower.vmdk",
            &destination,
            "lower.vmdk",
        )?;
        if let Some(descriptor) = lower.files.first() {
            durability.files.push(descriptor.try_clone()?);
        }
    }
    let lease = snapshots
        .register_restore_generation(&config, run, &storage, &intent)
        .await?;
    // Generation registration copies all consumer roots in the same transaction.
    // Keep the old OFD until that commit, including an uncertain result.
    store
        .finish_stopped_operation(intent.consumer_operation)
        .await?;
    let mut launch = RestoreLaunch {
        request,
        objects,
        lowers: lower_inputs.map(|lower| lower.files).unwrap_or_default(),
    };
    if let Some(progress) = progress {
        progress.send(LiveOperationProgress::StartingChild {
            index: child.0,
            total: child.1,
            name: config.name.clone(),
        });
    }
    let startup = launch_restored(
        runtime,
        &config,
        run,
        &storage,
        &mut launch,
        &lease,
        &mut durability,
    )
    .await;
    let durability = durability.spawn();
    let machine_id = config.id;
    let result = async {
        let (_lock, config, result, _lifetime) = match startup {
            Ok((pending, lifetime)) => {
                report_progress(progress, LiveOperationProgress::WaitingForAgent);
                let (lock, config, result) =
                    await_restored_start(runtime, config.id, run, lock, pending).await?;
                (lock, config, result, Some(lifetime))
            }
            Err(error) => (lock, config, Err(error), None),
        };
        let result = async {
            result?;
            let run_id = run.to_string();
            let monitor = started_run_monitor(runtime, &config, &run_id, lease.operation_id())?;
            let started = monitor
                .started_at()
                .ok_or_else(|| invalid("restored monitor has no stable generation"))?;
            runtime
                .mark_machine_monitor_ready(config.id, run_id, monitor.pid(), started)
                .await
        }
        .await;
        match result {
            Ok(()) => {
                store
                    .child_event(intent.consumer_operation, "running")
                    .await?;
                Ok(Machine::new(runtime.clone(), config.id))
            }
            Err(error) => {
                // Failed-start cleanup can delete the child and its monitor/live
                // records. Retain the exact run's original failure before that
                // destructive boundary; cleanup uncertainty remains independent.
                let error = match store
                    .record_fork_child_failure(config.id, run, &error)
                    .await
                {
                    Ok(()) => error,
                    Err(retain) => LibVmError::MachineStartCleanupFailed {
                        primary: error.to_string(),
                        cleanup: format!("retain fork restore failure: {retain}"),
                    },
                };
                let error = finish_failed_start(
                    runtime,
                    &config,
                    &run.to_string(),
                    Some(FailedStartState::Error),
                    None,
                    FailedStartStorage { lease, lower: None },
                    error,
                )
                .await;
                // A failed or uncertain cleanup retains the exact generation and its
                // charges in the journal. No new run or ordinary start is attempted.
                Err(error)
            }
        }
    }
    .await;
    // Running is recorded before waiting, preserving the activation measurement.
    // A failed persistence barrier leaves a Running child constructed, rather
    // than turning successful activation into a failed-start cleanup.
    if let Err(error) = durability.await {
        tracing::warn!(machine = %machine_id, %error, "child durability task failed");
    }
    result
}

/// Wait without mutation authority, then authenticate the durable generation
/// again before either readiness or failed-start cleanup may mutate it.
pub(crate) async fn await_restored_start(
    runtime: &Runtime,
    machine_id: crate::store::models::MachineId,
    run: Uuid,
    lock: crate::lock_manager::LockGuard,
    pending: crate::supervisor::launch::PendingStartup,
) -> Result<
    (
        crate::lock_manager::LockGuard,
        crate::store::models::MachineConfig,
        Result<(), LibVmError>,
    ),
    LibVmError,
> {
    // Handoff has transferred lifetime/storage ownership to the monitor and
    // published this run. Stop must not queue behind activation's startup wait.
    drop(lock);
    let result = pending.wait().await;
    let (lock, current) = runtime.lock_machine_config(machine_id).await?;
    let state = runtime.machine_state(current.id).await?;
    let run_id = run.to_string();
    if state.run_id.as_deref() != Some(run_id.as_str()) {
        return Err(LibVmError::MachineStaleGeneration {
            reference: current.name,
            requested: crate::MachineRunId::from_raw(run_id),
            current: state.run_id.map(crate::MachineRunId::from_raw),
        });
    }
    if state.status == crate::store::models::MachineRuntimeState::ActivationFailed {
        // This exact run still owns failed activation cleanup, never readiness,
        // even if its pipe acknowledgement raced the stop-only observation.
        // Prefer the authenticated lifecycle diagnostic if the startup pipe was
        // lost or only reported a transport error.
        let result = match state.last_error {
            Some(message) => Err(std::io::Error::other(message).into()),
            None => result.and(Err(invalid("restored activation failed before readiness"))),
        };
        return Ok((lock, current, result));
    }
    if !matches!(
        state.status,
        crate::store::models::MachineRuntimeState::Restoring
            | crate::store::models::MachineRuntimeState::Activating
            | crate::store::models::MachineRuntimeState::Starting
            | crate::store::models::MachineRuntimeState::Running
    ) {
        // Concurrent stop owns terminal reconciliation. A late startup
        // acknowledgement must not revive a stopped run.
        return result.and(Err(LibVmError::MachineNotRunning {
            reference: current.name,
        }));
    }
    Ok((lock, current, result))
}

pub(crate) fn project_restore_disks(
    spec: &mut vm_spec::VmSpec,
    storage: &MachineStorageRecord,
    images: &Path,
) -> Result<(), LibVmError> {
    let captured = CaptureConfiguration::from_spec(spec).map_err(invalid)?;
    crate::machine::stopped::project_child_disks(spec, storage, images)?;
    for (disk, attachment) in spec
        .storage
        .iter_mut()
        .flat_map(|storage| &mut storage.disks)
        .zip(&captured.attachments)
    {
        disk.block_id = attachment.block_id.clone();
    }
    if CaptureConfiguration::from_spec(spec).map_err(invalid)? != captured {
        return Err(invalid(
            "restore destination projection changed captured device pins",
        ));
    }
    Ok(())
}

pub(crate) struct LowerInputs {
    request: vm_spec::restore::RestoreLower,
    files: Vec<File>,
    native_records: u64,
    directory: crate::paths::OwnedDirectory,
    _stage: crate::machine::stopped::OperationStaging,
}

fn prepare_lower(
    pool: &StoragePool,
    consumer: &crate::store::snapshot_store::SnapshotConsumer,
    stage: crate::machine::stopped::OperationStaging,
    shape: &crate::store::snapshot_store::ShapeVerifiedClosure,
) -> Result<Option<LowerInputs>, LibVmError> {
    let SnapshotRootProfile::LinuxOverlay {
        lower,
        lower_geometry,
        ..
    } = &consumer.record.root.profile
    else {
        return Ok(None);
    };
    // Bind lower inputs to the shape-held inodes. Full authentication joins
    // private copying before the child is published.
    let mut occurrences = Vec::with_capacity(lower.layers.len() + 1);
    occurrences.push(pool.lower_object_occurrence(&lower.fsmeta)?);
    for layer in &lower.layers {
        occurrences.push(pool.lower_occurrence(&layer.pack.stream)?);
    }
    let verified = verify_lower_shape(
        &occurrences,
        lower_geometry.length,
        &consumer.record.configuration,
        |backing, length| match backing {
            LowerBacking::Stream(stream) => {
                let file = shape.open_stream(pool, &stream, length)?;
                let fingerprint =
                    crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?);
                Ok((file, fingerprint))
            }
            LowerBacking::Object(object) => {
                let file = shape.open_object(pool, &object)?;
                let fingerprint =
                    crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?);
                Ok((file, fingerprint))
            }
        },
    )?;
    prepare_lower_descriptor(&verified, stage).map(Some)
}

struct VerifiedBacking {
    file: File,
    fingerprint: crate::storage::identity_file::SourceFingerprint,
    path: std::path::PathBuf,
    length: u64,
}

pub(crate) struct VerifiedLower {
    descriptor: String,
    backings: Vec<VerifiedBacking>,
    block_id: vm_spec::BlockId,
    native_records: u64,
}

/// Admit the generated descriptor over `occurrences` (fsmeta first, then
/// every pack occurrence) and bind each unique nonempty backing to a held
/// authenticated descriptor of exactly that pool inode.
fn verify_lower_shape(
    occurrences: &[LowerOccurrence],
    length: u64,
    configuration: &crate::SnapshotConfiguration,
    held: impl Fn(
        LowerBacking,
        u64,
    ) -> Result<(File, crate::storage::identity_file::SourceFingerprint), LibVmError>,
) -> Result<VerifiedLower, LibVmError> {
    let plan = crate::storage::vmdk::FlatLowerPlan::new(occurrences)?;
    if plan.logical_length() != length {
        return Err(invalid(
            "verified lower occurrences differ from the captured geometry",
        ));
    }
    let data = configuration
        .spec
        .storage
        .iter()
        .flat_map(|storage| &storage.disks)
        .filter(|disk| disk.role == vm_spec::DiskRole::Data)
        .count() as u64;
    let admitted = plan.preflight(data)?;
    let unique = admitted.unique_occurrences().count() as u64;
    crate::storage::limits::preflight_fd_budget(admitted.record_count() + 5 + unique)
        .map_err(crate::storage::StorageError::from)?;
    let mut backings = Vec::with_capacity(unique as usize);
    for occurrence in admitted.unique_occurrences() {
        let (file, fingerprint) = held(occurrence.backing(), occurrence.length())?;
        let metadata = file.metadata()?;
        let pooled = std::fs::symlink_metadata(occurrence.path())?;
        if crate::storage::identity_file::SourceFingerprint::new(&metadata) != fingerprint
            || metadata.len() != occurrence.length()
            || metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || (metadata.dev(), metadata.ino()) != (pooled.dev(), pooled.ino())
        {
            return Err(invalid("verified lower backing lost its immutable inode"));
        }
        backings.push(VerifiedBacking {
            file,
            fingerprint,
            path: occurrence.path().to_path_buf(),
            length: occurrence.length(),
        });
    }
    let block_id = configuration
        .spec
        .storage
        .iter()
        .flat_map(|storage| &storage.disks)
        .find(|disk| disk.role == vm_spec::DiskRole::RootLower)
        .ok_or_else(|| invalid("captured lower attachment missing"))?
        .block_id
        .clone();
    Ok(VerifiedLower {
        descriptor: admitted.descriptor()?,
        backings,
        block_id,
        native_records: admitted.record_count(),
    })
}

/// The cut operation pins the retained composition. Held local validation
/// authority binds each immutable backing through descriptor handoff.
pub(crate) fn verify_local_lower(
    pool: &StoragePool,
    storage: &MachineStorageRecord,
    configuration: &crate::SnapshotConfiguration,
    lower: Option<&crate::store::composition_store::LaunchLower>,
) -> Result<Option<VerifiedLower>, LibVmError> {
    match (&storage.root, lower) {
        (MachineRoot::LinuxOverlay { lower: root, .. }, Some(launch)) => {
            launch.retained.check_lower(root)?;
            crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)?
                .preflight(0)?
                .verify_composition(pool, &launch.validation)?;
            verify_lower_shape(
                &launch.occurrences,
                root.geometry().length,
                configuration,
                |backing, _length| launch.held_backing(backing),
            )
            .map(Some)
        }
        (MachineRoot::LinuxOverlay { .. }, None) => {
            Err(invalid("fork lower has no leased retained composition"))
        }
        (MachineRoot::OpaqueRaw { .. }, _) => Ok(None),
    }
}

fn prepare_lower_descriptor(
    verified: &VerifiedLower,
    stage: crate::machine::stopped::OperationStaging,
) -> Result<LowerInputs, LibVmError> {
    for backing in &verified.backings {
        if crate::storage::identity_file::SourceFingerprint::new(&backing.file.metadata()?)
            != backing.fingerprint
        {
            return Err(invalid("verified lower changed before descriptor handoff"));
        }
    }
    let directory = stage.directory()?;
    directory.write_file_atomic_deferred("lower.vmdk", verified.descriptor.as_bytes())?;
    let descriptor = directory
        .open_file("lower.vmdk")?
        .ok_or_else(|| invalid("restore lower descriptor disappeared"))?;
    nix::sys::stat::fchmod(&descriptor, nix::sys::stat::Mode::S_IRUSR)
        .map_err(std::io::Error::from)?;
    let descriptor_stat = descriptor.metadata()?;
    let mut files = Vec::with_capacity(verified.backings.len() + 1);
    let mut extents = Vec::with_capacity(verified.backings.len());
    for backing in &verified.backings {
        let file = backing.file.try_clone()?;
        let stat = file.metadata()?;
        extents.push(vm_spec::restore::RestoreExtent {
            path: backing
                .path
                .to_str()
                .ok_or_else(|| invalid("lower path is not UTF-8"))?
                .into(),
            fd: file.as_raw_fd(),
            file_device: stat.dev(),
            file_inode: stat.ino(),
            length: backing.length,
        });
        files.push(file);
    }
    let request = vm_spec::restore::RestoreLower {
        block_id: verified.block_id.clone(),
        descriptor: vm_spec::restore::RestoreDescriptor {
            fd: descriptor.as_raw_fd(),
            file_device: descriptor_stat.dev(),
            file_inode: descriptor_stat.ino(),
            length: descriptor_stat.len(),
        },
        extents,
    };
    files.insert(0, descriptor);
    Ok(LowerInputs {
        request,
        files,
        native_records: verified.native_records,
        directory,
        _stage: stage,
    })
}

pub(crate) fn storage_from_snapshot(
    record: &SnapshotRecord,
    snapshot: crate::storage::identity::SnapshotId,
) -> Result<MachineStorageRecord, LibVmError> {
    let (root, profile, backend) = match &record.root.profile {
        SnapshotRootProfile::OpaqueRaw => (
            MachineRoot::OpaqueRaw {
                path: crate::PrivatePath::new("root.raw")?,
                geometry: record.root.geometry,
                layout: record.root.layout.clone(),
                initial_content: Some(record.root.stream.stream),
            },
            crate::StorageProfile::OpaqueRawV1,
            crate::BackendRequirement::RawBlock,
        ),
        SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            lower_filesystem_uuid,
            upper_uuid,
            ext4_profile,
            overlay_profile,
            temporary_directory,
        } => (
            MachineRoot::LinuxOverlay {
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
            crate::StorageProfile::LinuxOverlayV1,
            crate::BackendRequirement::KrunOverlay,
        ),
    };
    let mut storage = MachineStorageRecord {
        schema: 1,
        root,
        boot: record.boot.clone(),
        profile,
        backend,
        disk_baselines: Vec::new(),
        ram_identity: match &record.memory {
            SnapshotMemoryState::Included { execution } => {
                crate::store::models::storage::ContentIdentityState::Identified {
                    root: Sha256Digest::from_bytes(*execution.memory.stream.as_bytes()),
                }
            }
            _ => crate::store::models::storage::ContentIdentityState::Unknown,
        },
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
        external_requirements: Vec::new(),
        storage_generation: 0,
        ownership_epoch: 0,
        stop_outcome: crate::StorageStopOutcome::Unknown,
        ownership: crate::MachineOwnership::Owned,
        operation: None,
        image: None,
        snapshot: Some(snapshot),
    };
    storage.bind_disk_identity_inventory(&record.configuration.spec);
    storage.validate()?;
    Ok(storage)
}

fn restore_disk_peak(
    images_dir: &Path,
    sources: &[PrivateSource],
    record: &SnapshotRecord,
) -> Result<u64, LibVmError> {
    let mut required = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
    for source in sources {
        required = required
            .checked_add(
                source
                    .file()
                    .metadata()?
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| invalid("restore disk allocation overflow"))?,
            )
            .ok_or_else(|| invalid("restore disk peak overflow"))?;
    }
    if let crate::BootProfile::LinuxDirect {
        binding:
            crate::BootBinding::Pinned {
                base_initramfs,
                kernel,
                agent,
                ..
            },
        ..
    } = &record.boot
    {
        let pool = StoragePool::open(images_dir)?;
        for object in [base_initramfs, kernel].into_iter().chain(agent.iter()) {
            required = required
                .checked_add(std::fs::metadata(pool.object_path(object))?.len())
                .ok_or_else(|| invalid("restore provenance peak overflow"))?;
        }
    }
    Ok(required)
}

pub(crate) fn publish_restore_launch_files(
    paths: &crate::paths::MachinePaths,
    spec: &vm_spec::VmSpec,
    base: crate::initramfs_overlay::CompositeBase<'_>,
    agent: Option<(crate::initramfs_overlay::CompositeAgent<'_>, &[u8])>,
    durability: &mut crate::machine::builder::ChildDurability,
) -> Result<(), LibVmError> {
    let composite = crate::initramfs_overlay::write_composite(
        base,
        agent,
        None,
        &paths.composite_initramfs_path(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    durability.files.push(composite);
    durability.files.push(
        crate::supervisor::write_launch_spec(&paths.vm_spec_path(), spec)
            .map_err(|error| invalid(error.to_string()))?,
    );
    Ok(())
}

fn bind_restore_disk_tracking(
    runtime: &Runtime,
    config: &crate::store::models::MachineConfig,
    storage: &MachineStorageRecord,
    request: &mut RestoreRequest,
) -> Result<(), LibVmError> {
    request.disk_tracking_seeds = crate::machine::root_storage::launch_disk_seeds(
        storage,
        &config.machine_dir,
        runtime.local_images_dir(),
    )?;
    request.validate().map_err(invalid)
}

/// Reuse the existing machine's immutable lower descriptor and held pool
/// backings. No disk cloning or child publication belongs to same-machine wake.
pub(crate) async fn hibernation_lower(
    runtime: &Runtime,
    config: &crate::store::models::MachineConfig,
    lease: &crate::store::operation_store::LaunchStorageLease,
) -> Result<(Vec<vm_spec::restore::RestoreLower>, Vec<File>), LibVmError> {
    let storage = lease.storage_record();
    if !matches!(storage.root, MachineRoot::LinuxOverlay { .. }) {
        return Ok((Vec::new(), Vec::new()));
    }
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let held = crate::store::layer_store::LayerStore::from_store(runtime.native_store()?)
        .launch_lower(lease, storage)
        .await?;
    let configuration = crate::SnapshotConfiguration::capture(config)?;
    let verified = verify_local_lower(&pool, storage, &configuration, Some(&held))?
        .ok_or_else(|| invalid("saved machine lower is missing"))?;
    let disk = config
        .spec
        .storage
        .iter()
        .flat_map(|storage| &storage.disks)
        .find(|disk| disk.role == vm_spec::DiskRole::RootLower)
        .ok_or_else(|| invalid("saved machine lower attachment is missing"))?;
    let path = if disk.path.is_absolute() {
        disk.path.clone()
    } else {
        config.machine_dir.join(&disk.path)
    };
    let descriptor = crate::storage::stream::open_regular_source(&path)?;
    let mut text = String::new();
    (&descriptor)
        .take((verified.descriptor.len() + 1) as u64)
        .read_to_string(&mut text)?;
    if text != verified.descriptor {
        return Err(invalid("saved machine lower descriptor was changed"));
    }
    let metadata = descriptor.metadata()?;
    let mut files = vec![descriptor];
    let mut extents = Vec::with_capacity(verified.backings.len());
    for backing in &verified.backings {
        let file = backing.file.try_clone()?;
        let stat = file.metadata()?;
        extents.push(vm_spec::restore::RestoreExtent {
            path: backing
                .path
                .to_str()
                .ok_or_else(|| invalid("lower path is not UTF-8"))?
                .into(),
            fd: file.as_raw_fd(),
            file_device: stat.dev(),
            file_inode: stat.ino(),
            length: backing.length,
        });
        files.push(file);
    }
    Ok((
        vec![vm_spec::restore::RestoreLower {
            block_id: verified.block_id,
            descriptor: vm_spec::restore::RestoreDescriptor {
                fd: files[0].as_raw_fd(),
                file_device: metadata.dev(),
                file_inode: metadata.ino(),
                length: metadata.len(),
            },
            extents,
        }],
        files,
    ))
}

async fn launch_restored(
    runtime: &Runtime,
    config: &crate::store::models::MachineConfig,
    run: Uuid,
    storage: &MachineStorageRecord,
    restore: &mut RestoreLaunch,
    lease: &crate::store::operation_store::LaunchStorageLease,
    durability: &mut crate::machine::builder::ChildDurability,
) -> Result<
    (
        crate::supervisor::launch::PendingStartup,
        crate::lock_manager::MachineLifetimeLock,
    ),
    LibVmError,
> {
    let paths = runtime.machine_paths(config.id);
    let directories = runtime.local_paths().child_launch_directories(config.id)?;
    durability
        .launch_directories
        .extend(directories.directories);
    durability.launch_parents.extend(directories.parents);
    let lifetime = crate::lock_manager::MachineLifetimeLock::try_acquire(&paths.vmm_lock_path())?
        .ok_or_else(|| LibVmError::MachineAlreadyRunning {
        reference: config.name.clone(),
    })?;
    let mut secrets = runtime.resolve_machine_secrets(
        config,
        &run.to_string(),
        &crate::EgressCredentials::default(),
    )?;
    let network = runtime
        .prepare_machine_network(
            config,
            &run.to_string(),
            &secrets,
            crate::MachineDurability::Constructed,
        )
        .await?;
    if let crate::network::VmmNetworkAttachment::UnixDatagram { path, .. } = &network {
        let directory = crate::paths::OwnedDirectory::open_existing_root(
            path.parent()
                .ok_or_else(|| invalid("network socket has no parent"))?,
        )?
        .ok_or_else(|| invalid("network runtime disappeared"))?;
        if let Some(policy) = directory.open_file("network-policy.json")? {
            durability.files.push(policy);
        }
        let parent = crate::paths::OwnedDirectory::open_existing_root(
            directory
                .path()
                .parent()
                .ok_or_else(|| invalid("network runtime has no parent"))?,
        )?
        .ok_or_else(|| invalid("network runtime parent disappeared"))?;
        let logs = crate::paths::OwnedDirectory::open_existing_root(&paths.network_logs_dir())?
            .ok_or_else(|| invalid("network logs disappeared"))?;
        durability
            .launch_directories
            .extend([directory, parent, logs]);
    }
    secrets.infrastructure.clear();
    restore.request.ssh_trusted_ca = Some(
        secrets
            .ssh_trusted_ca
            .take()
            .ok_or_else(|| invalid("restore destination has no authorized SSH CA"))?,
    );
    restore.request.network = match &network {
        crate::network::VmmNetworkAttachment::None => None,
        crate::network::VmmNetworkAttachment::UnixDatagram { mac, ipv4, dns, .. } => {
            Some(vm_spec::restore::RestoreNetwork {
                mac: mac.clone(),
                ipv4: ipv4.address,
                prefix_length: ipv4.prefix_length,
                gateway: ipv4.gateway,
                dns_servers: dns.servers.clone(),
                dns_search: dns.search.clone(),
            })
        }
    };
    bind_restore_disk_tracking(runtime, config, storage, &mut restore.request)?;
    runtime
        .native_store()?
        .bind_restore_activation(lease.operation_id(), &restore.request)
        .await?;
    let mut spec = config.spec.clone();
    for disk in spec
        .storage
        .iter_mut()
        .flat_map(|storage| &mut storage.disks)
    {
        if !disk.path.is_absolute() {
            disk.path = config.machine_dir.join(&disk.path);
        }
    }
    // These are exact pinned provenance bytes. Native build_restored never
    // loads them, and no cold guest configuration/provisioning is replayed.
    let (base, agent) = if let crate::BootProfile::LinuxDirect {
        binding:
            crate::BootBinding::Pinned {
                kernel,
                base_initramfs,
                agent: Some(agent),
                ..
            },
        ..
    } = &storage.boot
    {
        let pool = StoragePool::open(runtime.local_images_dir())?;
        let boot = spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
            .ok_or_else(|| invalid("captured kernel configuration missing"))?;
        boot.path = Some(pool.object_path(kernel));
        boot.initramfs = Some(paths.composite_initramfs_path());
        let base =
            crate::owned_boot_assets::OwnedBootAsset::open(&pool.object_path(base_initramfs))
                .map_err(|error| invalid(error.to_string()))?;
        let binary = crate::owned_boot_assets::OwnedBootAsset::open(&pool.object_path(agent))
            .map_err(|error| invalid(error.to_string()))?;
        if base.digest().map_err(|error| invalid(error.to_string()))? != *base_initramfs.as_bytes()
            || binary
                .digest()
                .map_err(|error| invalid(error.to_string()))?
                != *agent.as_bytes()
        {
            return Err(invalid(
                "restore provenance changed after closure verification",
            ));
        }
        (base, binary)
    } else {
        return Err(invalid("restore requires pinned direct-boot provenance"));
    };
    if CaptureConfiguration::from_spec(&spec).map_err(invalid)? != restore.request.configuration {
        return Err(invalid(
            "destination launch changed captured execution pins",
        ));
    }
    let shutdown = crate::guest_agent::storage_shutdown_context(
        &Uuid::from(config.id).to_string(),
        &run.to_string(),
        &spec,
        crate::runtime::boot_assets::effective_boot(storage, &spec, runtime.effective_backend())?
            .rosetta,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let provenance = crate::guest_agent::build_config(crate::guest_agent::GuestAgentConfigInput {
        machine_name: &config.name,
        spec: &spec,
        environment: &config.process.environment,
        network: &network,
        resize_rootfs: false,
        user: config.guest.user.as_ref(),
        ssh_trusted_ca: restore
            .request
            .ssh_trusted_ca
            .as_deref()
            .ok_or_else(|| invalid("restore destination SSH CA missing"))?,
        tls_certificate: secrets.tls_certificate.as_deref(),
        storage_shutdown: &shutdown,
    })
    .map_err(|error| invalid(error.to_string()))?;
    let provenance = serde_json::to_vec(&provenance).map_err(|error| invalid(error.to_string()))?;
    publish_restore_launch_files(
        &paths,
        &spec,
        crate::initramfs_overlay::CompositeBase::Retained(&base),
        Some((
            crate::initramfs_overlay::CompositeAgent::Retained(&agent),
            &provenance,
        )),
        durability,
    )?;
    let logs = crate::paths::OwnedDirectory::open_existing_root(
        paths
            .serial_log_path()
            .parent()
            .ok_or_else(|| invalid("serial log has no parent"))?,
    )?
    .ok_or_else(|| invalid("child log directory disappeared"))?;
    let (file_device, file_inode) = lease.file_identity()?;
    let run_id = run.to_string();
    let pidfile = paths.vmm_pid_path();
    let exit_status = paths.vmm_exit_status_path();
    let config_path = paths.vm_spec_path();
    let socket = paths.vmm_socket_path();
    let serial = paths.serial_log_path();
    let trace = paths.vm_trace_log_path();
    let launch = crate::supervisor::VmmLaunch {
        machine_id: config.id,
        name: &config.name,
        machine_dir: &config.machine_dir,
        machine_runtime_dir: paths.machine_run_dir(),
        pidfile: &pidfile,
        exit_status: &exit_status,
        config: &config_path,
        socket: &socket,
        serial_log: &serial,
        trace_log: &trace,
        network: &network,
        run_id: &run_id,
        exit_command: None,
        agent_enabled: true,
        rosetta_intent: crate::supervisor::start_request::VmmRosettaIntent::Disabled {},
        asset_directory: runtime.asset_directory().to_path_buf(),
        startup_command: None,
        machine_log_dir: &logs,
        machine_lock: &lifetime,
        storage_lease: lease.lock(),
        storage_lease_binding: protocol::shutdown::StorageLeaseBinding {
            operation_id: lease.operation_id().to_string(),
            file_device,
            file_inode,
        },
        storage_shutdown: &shutdown,
        disk_tracking_seeds: restore.request.disk_tracking_seeds.clone(),
        restore: Some(restore),
    };
    runtime
        .mark_launch_storage_admitted(lease.operation_id())
        .await?;
    let pending = runtime.supervisor().spawn(&launch, None).await?;
    Ok((pending, lifetime))
}

fn restore_authority_name(authority: &vm_spec::restore::RestoreAuthority) -> String {
    match authority {
        vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { snapshot, .. } => {
            snapshot.to_string()
        }
        vm_spec::restore::RestoreAuthority::OwnedLocalCut { cut } => {
            format!("fork:{}", cut.capture_id)
        }
        vm_spec::restore::RestoreAuthority::Hibernation { cut } => {
            format!("hibernation:{}", cut.save_id)
        }
    }
}

fn inspection_refusal(
    restore: &RestoreRequest,
    pin: &str,
    expected: &str,
    actual: impl Into<String>,
) -> LibVmError {
    LibVmError::SnapshotPortability {
        snapshot: restore_authority_name(&restore.authority),
        refusal: Box::new(vm_spec::restore::RestorePortabilityRefusal::new(
            pin,
            expected,
            actual.into().replace('\0', "\\0"),
        )),
    }
}

pub(crate) fn inspection_request(
    restore: RestoreRequest,
    network: bool,
) -> Result<vm_spec::restore::RestoreInspectionRequest, LibVmError> {
    let request = vm_spec::restore::RestoreInspectionRequest {
        version: vm_spec::restore::RESTORE_INSPECTION_VERSION,
        restore,
        network,
    };
    request.validate().map_err(|error| {
        inspection_refusal(
            &request.restore,
            "inspection.request",
            "a valid current-schema restore inspection request",
            error,
        )
    })?;
    Ok(request)
}

pub(crate) async fn inspect(
    executable: &Path,
    restore: &RestoreRequest,
    network: bool,
) -> Result<vm_spec::restore::RestoreInspectionReport, LibVmError> {
    let request = inspection_request(restore.clone(), network)?;
    let bytes = serde_json::to_vec(&request).map_err(|error| {
        inspection_refusal(
            restore,
            "inspection.request",
            "a serializable restore inspection request",
            error.to_string(),
        )
    })?;
    if bytes.len() >= vm_spec::restore::MAX_RESTORE_INSPECTION_BYTES {
        return Err(inspection_refusal(
            restore,
            "inspection.request",
            "a request within the restore inspection control-record bound",
            format!("{} encoded bytes", bytes.len()),
        ));
    }
    let mut command = Command::new(executable);
    command
        .arg("inspect-restore")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let descriptors: Vec<_> = restore
        .objects
        .iter()
        .map(|object| Some(object.fd))
        .chain(restore.lowers.iter().flat_map(|lower| {
            std::iter::once(Some(lower.descriptor.fd))
                .chain(lower.extents.iter().map(|extent| Some(extent.fd)))
        }))
        .collect();
    install_child_inheritance(&mut command, descriptors).map_err(|error| {
        inspection_refusal(
            restore,
            "inspection.descriptors",
            "inheritable restore input descriptors",
            error.to_string(),
        )
    })?;
    let mut child = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            inspection_refusal(
                restore,
                "inspection.process",
                "a running native restore inspector",
                error.to_string(),
            )
        })?;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(inspection_refusal(
            restore,
            "inspection.process",
            "native restore inspection input and output pipes",
            "native inspection pipes are unavailable",
        ));
    };
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let write = async {
            stdin.write_all(&bytes).await?;
            stdin.write_all(b"\n").await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        tokio::try_join!(
            write,
            bounded_output(
                stdout,
                vm_spec::restore::MAX_RESTORE_INSPECTION_REPORT_BYTES as u64
            ),
            bounded_output(stderr, 16 << 10),
            child.wait()
        )
    })
    .await;
    let (_, stdout, stderr, status) = match result {
        Ok(Ok(result)) => result,
        other => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(inspection_refusal(
                restore,
                "inspection.process",
                "completed native restore inspection within 30 seconds",
                format!("native restore inspection failed: {other:?}"),
            ));
        }
    };
    if !status.success() {
        if stdout.ends_with(b"\n") && !stdout[..stdout.len().saturating_sub(1)].contains(&b'\n') {
            if let Ok(failure) =
                serde_json::from_slice::<vm_spec::restore::RestoreInspectionFailure>(&stdout)
            {
                failure.validate().map_err(|error| {
                    inspection_refusal(
                        restore,
                        "inspection.refusal",
                        "a valid current-schema native restore refusal",
                        error,
                    )
                })?;
                return Err(LibVmError::SnapshotPortability {
                    snapshot: restore_authority_name(&restore.authority),
                    refusal: Box::new(failure.refusal),
                });
            }
        }
        return Err(inspection_refusal(
            restore,
            "inspection.process",
            "successful native inspection or a typed restore refusal",
            format!(
                "native restore inspection failed without a typed refusal ({status}): {}",
                String::from_utf8_lossy(&stderr)
            ),
        ));
    }
    if !stdout.ends_with(b"\n") || stdout[..stdout.len().saturating_sub(1)].contains(&b'\n') {
        return Err(inspection_refusal(
            restore,
            "inspection.report",
            "one bounded native restore inspection report",
            "native restore inspection did not return one bounded report",
        ));
    }
    let report: vm_spec::restore::RestoreInspectionReport = serde_json::from_slice(&stdout)
        .map_err(|error| {
            inspection_refusal(
                restore,
                "inspection.report",
                "a valid native restore inspection report",
                error.to_string(),
            )
        })?;
    if let Some(refusal) = report.portability_refusal(&request) {
        refusal.validate().map_err(|error| {
            inspection_refusal(
                restore,
                "inspection.refusal",
                "a valid restore portability refusal",
                error,
            )
        })?;
        return Err(LibVmError::SnapshotPortability {
            snapshot: restore_authority_name(&restore.authority),
            refusal: Box::new(refusal),
        });
    }
    report.validate_against(&bytes, &request).map_err(|error| {
        inspection_refusal(
            restore,
            "inspection.binding",
            "a native inspection report admitting these exact restore inputs",
            error,
        )
    })?;
    Ok(report)
}

async fn bounded_output(
    reader: impl tokio::io::AsyncRead + Unpin,
    limit: u64,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("inspection output exceeded bound"));
    }
    Ok(bytes)
}

pub(crate) struct VerifiedForkRestore {
    cut: crate::store::fork::VerifiedRestoreCut,
    lane: vm_spec::live::LiveLane,
    shared_qualification: Arc<crate::machine::root_disk::SharedCopyQualification>,
}

pub(crate) async fn prepare_fork_restore(
    runtime: &Runtime,
    cut: crate::store::fork::VerifiedRestoreCut,
) -> Result<VerifiedForkRestore, LibVmError> {
    let host = runtime.live_capabilities().await?;
    crate::require_host_live_operation(&host, LiveOperation::Restore)?;
    let shared_qualification = Arc::new(crate::machine::root_disk::SharedCopyQualification::new(
        cut.directory(),
    )?);
    Ok(VerifiedForkRestore {
        cut,
        lane: host.lane,
        shared_qualification,
    })
}

struct ForkChildInputs {
    configuration: crate::SnapshotConfiguration,
    storage: MachineStorageRecord,
    sources: Vec<PrivateSource>,
    request: RestoreRequest,
    objects: Vec<File>,
    lower_inputs: Option<LowerInputs>,
    _consumer_lease: crate::storage::locks::StorageLock,
}

fn prepare_fork_child_inputs(
    runtime: &Runtime,
    cut: &crate::store::fork::VerifiedRestoreCut,
    child: &crate::store::fork::ForkChildIdentity,
    options: &crate::LiveForkChild,
) -> Result<ForkChildInputs, LibVmError> {
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let consumer_lease = pool.existing_lease(child.consumer_id)?;
    let configuration = crate::machine::live_fork::project_destination(
        &cut.record.configuration,
        &options.destination,
    )?;
    let mut storage = cut.record.storage.clone();
    let mut sources = Vec::new();
    for disk in &mut storage.disks {
        disk.id = Uuid::new_v4();
    }
    for disk in &cut.record.plan.disks {
        let role = vm_spec::capture::CaptureRole::Disk(disk.name.clone());
        let attachment = cut
            .record
            .plan
            .configuration
            .attachments
            .get(disk.attachment_index as usize)
            .ok_or_else(|| invalid("fork disk attachment missing"))?;
        let path = crate::PrivatePath::new(match attachment.role {
            vm_spec::DiskRole::Root => "root.raw".into(),
            vm_spec::DiskRole::RootUpper => "upper.raw".into(),
            vm_spec::DiskRole::Data => format!("disk-{}.raw", disk.attachment_index),
            vm_spec::DiskRole::RootLower => return Err(invalid("fork lower cannot be writable")),
        })?;
        if attachment.role == vm_spec::DiskRole::Data {
            if let Some(target) = storage
                .disks
                .iter_mut()
                .find(|target| target.order == disk.attachment_index)
            {
                target.storage = DiskStorage::ManagedWritable {
                    path: path.clone(),
                    geometry: attachment.geometry,
                };
            } else {
                storage.disks.push(crate::IncludedDisk {
                    id: Uuid::new_v4(),
                    role: attachment.role,
                    order: disk.attachment_index,
                    storage: DiskStorage::ManagedWritable {
                        path: path.clone(),
                        geometry: attachment.geometry,
                    },
                });
            }
        }
        let file = cut.reopen_role(&role)?;
        let fingerprint = crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?);
        if file.metadata()?.len() != disk.length {
            return Err(invalid("fork cut disk geometry differs from its plan"));
        }
        sources.push(PrivateSource::Owned {
            path,
            file,
            length: disk.length,
            fingerprint,
        });
    }
    // The constructor expects root first, then the remaining private roles.
    sources.sort_by_key(|source| {
        if matches!(
            source.path().as_path().to_str(),
            Some("root.raw" | "upper.raw")
        ) {
            0
        } else {
            1
        }
    });
    for source in cut.pool_streams.values() {
        if crate::storage::identity_file::SourceFingerprint::new(&source.file().metadata()?)
            != source.fingerprint()
        {
            return Err(invalid(
                "authenticated fork pool stream changed before handoff",
            ));
        }
    }
    let lower_inputs = cut
        .lower
        .as_ref()
        .map(|lower| {
            let stage = crate::machine::stopped::OperationStaging::new_deferred(
                &pool,
                child.consumer_id,
                &consumer_lease,
            )?;
            prepare_lower_descriptor(lower, stage)
        })
        .transpose()?;
    let mut files = Vec::with_capacity(4);
    let mut descriptors = Vec::with_capacity(4);
    for role in [
        RestoreObjectRole::Ram,
        RestoreObjectRole::Layout,
        RestoreObjectRole::Execution,
        RestoreObjectRole::Devices,
    ] {
        let index = cut
            .record
            .files
            .iter()
            .position(|file| file.role == role.capture_role())
            .ok_or_else(|| invalid("fork restore object missing"))?;
        let identity = &cut.record.files[index];
        let file = cut.reopen_role(&role.capture_role())?;
        let metadata = file.metadata()?;
        if crate::storage::identity_file::SourceFingerprint::new(&metadata) != identity.fingerprint
            || metadata.mode() & 0o7777 != 0o400
        {
            return Err(invalid("shared fork cut inode changed"));
        }
        descriptors.push(RestoreObject {
            role,
            fd: file.as_raw_fd(),
            file_device: identity.device,
            file_inode: identity.inode,
            length: identity.length,
            authority: vm_spec::restore::RestoreObjectAuthority::Owned {
                fingerprint: identity.fingerprint.to_capture(),
            },
        });
        files.push(file);
    }
    let request = RestoreRequest {
        purpose: vm_spec::restore::ActivationPurpose::Clone,
        disk_tracking_seeds: Vec::new(),
        map_node_store: None,
        version: vm_spec::restore::RESTORE_REQUEST_VERSION,
        authority: vm_spec::restore::RestoreAuthority::OwnedLocalCut {
            cut: Box::new(cut.record.restore_evidence()?),
        },
        activation_id: vm_spec::lifecycle::LiveId::parse(&child.activation_id.to_string())
            .map_err(invalid)?,
        freeze_operation_id: cut.record.evidence.freeze_operation_id.clone(),
        start_paused: true,
        configuration: cut.record.plan.configuration.clone(),
        objects: descriptors,
        lowers: lower_inputs
            .as_ref()
            .map(|lower| vec![lower.request.clone()])
            .unwrap_or_default(),
        network: None,
        ssh_trusted_ca: None,
        hook: options.activation_hook.clone(),
    };
    request.validate_for_inspection().map_err(invalid)?;
    Ok(ForkChildInputs {
        configuration,
        storage,
        sources,
        request,
        objects: files,
        lower_inputs,
        _consumer_lease: consumer_lease,
    })
}

pub(crate) async fn restore_reserved_fork_child(
    runtime: &Runtime,
    prepared: Arc<VerifiedForkRestore>,
    child: crate::store::fork::ForkChildIdentity,
    options: crate::LiveForkChild,
    progress: Option<&LiveOperationProgressSender>,
    total: usize,
) -> Result<Machine, LibVmError> {
    let ForkChildInputs {
        configuration,
        storage,
        sources,
        request,
        objects: files,
        lower_inputs,
        _consumer_lease,
    } = prepare_fork_child_inputs(runtime, &prepared.cut, &child, &options)?;
    let store = runtime.native_store()?;
    let cut = &prepared.cut;
    let network = !matches!(
        configuration.network,
        crate::store::models::MachineNetworkConfig::None
    );
    let inspection = inspect(runtime.supervisor().executable(), &request, network).await?;
    if inspection.lane != prepared.lane {
        return Err(invalid(
            "fork restore native inspection lane differs from the selected host capability report",
        ));
    }
    let intent = RestoreIntent {
        source: crate::store::restore::RestoreIdentity::LocalCut {
            id: cut.record.cut_id,
        },
        consumer_operation: child.consumer_id,
        request: request.clone(),
        resources: store.fork_child_charge(child.consumer_id).await?,
        inspection,
        network_attachment: network,
    };
    let index = child.result.index as usize + 1;
    execute_prepared(
        runtime,
        PreparedRestore {
            configuration,
            storage,
            sources,
            intent,
            request,
            objects: files,
            lower_inputs,
            authentication: None,
            shared_qualification: Some(Arc::clone(&prepared.shared_qualification)),
        },
        child.result.name,
        Uuid::parse_str(child.result.run_id.as_str())
            .map_err(|error| invalid(error.to_string()))?,
        None,
        progress,
        (index, total),
    )
    .await
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::storage::stream::whole_file_sha256;

    pub(crate) async fn assert_real_snapshot_child_requests(
        runtime: &crate::Runtime,
        snapshots: &crate::store::snapshot_store::SnapshotStore,
        snapshot: crate::SnapshotId,
        count: usize,
    ) {
        use crate::machine::restore::{
            bind_restore_disk_tracking, prepare_lower, snapshot_private_sources,
            snapshot_restore_request, storage_from_snapshot, RestoreAuthentication,
        };
        use crate::store::MachineStore;
        let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir()).unwrap();
        let store = runtime.native_store().unwrap();
        let mut inodes = std::collections::BTreeSet::new();
        for index in 0..count {
            let consumer = snapshots
                .consume_shape(&crate::SnapshotRef::Id(snapshot))
                .await
                .unwrap();
            let shape = snapshots
                .prepare_restore_shape(&consumer)
                .await
                .unwrap()
                .complete(runtime.local_images_dir())
                .unwrap();
            let crate::store::models::snapshot::SnapshotMemoryState::Included { execution } =
                &consumer.record.memory
            else {
                panic!("execution snapshot required");
            };
            let objects = [
                shape
                    .open_stream(&pool, &execution.memory.stream, execution.memory.length)
                    .unwrap(),
                shape.open_object(&pool, &execution.layout).unwrap(),
                shape.open_object(&pool, &execution.execution).unwrap(),
                shape.open_object(&pool, &execution.devices).unwrap(),
                shape.open_object(&pool, &execution.memory.map).unwrap(),
            ];
            let stage = crate::machine::stopped::OperationStaging::new_deferred(
                &pool,
                consumer.operation_id,
                &consumer.lease,
            )
            .unwrap();
            let lower = prepare_lower(&pool, &consumer, stage, &shape).unwrap();
            let evidence = snapshots
                .restore_evidence(&consumer, &pool)
                .unwrap()
                .evidence;
            let mut request = snapshot_restore_request(
                runtime,
                &consumer,
                evidence,
                &objects,
                lower.as_ref(),
                None,
            )
            .unwrap();
            let inspection =
                crate::machine::restore::inspection_request(request.clone(), false).unwrap();
            inspection.validate().unwrap();
            let storage = storage_from_snapshot(&consumer.record, snapshot).unwrap();
            let sources =
                snapshot_private_sources(&pool, &consumer.record, &shape, &storage).unwrap();
            let disk_peak = crate::machine::restore::restore_disk_peak(
                runtime.local_images_dir(),
                &sources,
                &consumer.record,
            )
            .unwrap();
            let resources = snapshots
                .reserve_restore_resources(&consumer, disk_peak, 64)
                .await
                .unwrap();
            let intent = crate::store::restore::RestoreIntent {
                source: crate::store::restore::RestoreIdentity::Snapshot { id: snapshot },
                consumer_operation: consumer.operation_id,
                request: request.clone(),
                resources,
                inspection: inspection_report(&inspection),
                network_attachment: false,
            };
            intent.validate().unwrap();
            let run = uuid::Uuid::new_v4();
            let name = format!("snapshot-child-{index}");
            store
                .persist_restore_construction(&crate::store::restore::RestoreConstruction {
                    run_id: run,
                    name: name.clone(),
                    intent: intent.clone(),
                })
                .await
                .unwrap();
            let (config, durability) = crate::machine::builder::publish_restored_child(
                runtime,
                crate::machine::builder::ChildConstruction {
                    name,
                    configuration: consumer.record.configuration.clone(),
                    storage,
                    sources,
                    operation_id: consumer.operation_id,
                    shared_qualification: None,
                },
                run,
                Some(RestoreAuthentication::new(snapshots.clone(), shape)),
            )
            .await
            .unwrap();
            assert_eq!(config.retention, crate::MachineRetention::Persistent);
            assert_eq!(
                store
                    .machine_config(config.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .retention,
                crate::MachineRetention::Persistent
            );
            durability.spawn().await.unwrap().unwrap();
            let storage = store.machine_storage(config.id).await.unwrap().unwrap();
            let lease = snapshots
                .register_restore_generation(&config, run, &storage, &intent)
                .await
                .unwrap();
            bind_restore_disk_tracking(runtime, &config, &storage, &mut request).unwrap();
            request.ssh_trusted_ca = Some("host-construction-public-ca".into());
            request.validate().unwrap();
            assert_inspection_binding(&intent, &request);
            store
                .bind_restore_activation(lease.operation_id(), &request)
                .await
                .unwrap();
            assert_eq!(
                request.disk_tracking_seeds.len(),
                request
                    .configuration
                    .attachments
                    .iter()
                    .filter(|disk| !disk.read_only)
                    .count()
            );
            for seed in &request.disk_tracking_seeds {
                assert!(seed.baseline.is_some());
                assert!(inodes.insert((seed.file_device, seed.file_inode)));
            }
            assert_transfer_descriptors(
                request,
                objects.into(),
                lower.map(|lower| lower.files).unwrap_or_default(),
            );
        }
    }

    fn assert_inspection_binding(
        intent: &crate::store::restore::RestoreIntent,
        request: &vm_spec::restore::RestoreRequest,
    ) {
        let mut activated = intent.clone();
        activated.request = request.clone();
        activated.validate().unwrap();
        activated.request.activation_id =
            vm_spec::lifecycle::LiveId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        activated.request.validate().unwrap();
        assert!(
            activated.validate().is_err(),
            "only destination resources may change after inspection"
        );
    }

    fn assert_transfer_descriptors(
        request: vm_spec::restore::RestoreRequest,
        objects: Vec<std::fs::File>,
        lowers: Vec<std::fs::File>,
    ) {
        let mut launch = crate::supervisor::launch::RestoreLaunch {
            request,
            objects,
            lowers,
        };
        let descriptors = launch.transfer_descriptors().unwrap();
        assert_eq!(
            descriptors.len(),
            launch.objects.len() + launch.lowers.len()
        );
        let file = launch.objects.pop().unwrap();
        assert!(launch.transfer_descriptors().is_err());
        launch.objects.push(file);
        launch.objects.swap(0, 1);
        assert!(launch.transfer_descriptors().is_err());
    }

    pub(crate) async fn assert_real_fork_child_requests(
        runtime: &crate::Runtime,
        snapshots: &crate::store::snapshot_store::SnapshotStore,
        operation: uuid::Uuid,
        child_count: usize,
    ) -> Vec<(
        crate::store::models::MachineConfig,
        crate::store::operation_store::LaunchStorageLease,
    )> {
        use crate::machine::restore::{
            bind_restore_disk_tracking, prepare_fork_child_inputs, ForkChildInputs,
        };
        use crate::store::MachineStore;

        let store = runtime.native_store().unwrap();
        let cut = store.open_local_cut(operation).await.unwrap();
        store.bind_fork_resources(&cut).await.unwrap();
        let options = store.fork_options(operation).await.unwrap();
        let children = store.fork_children(operation).await.unwrap();
        assert_eq!(children.len(), child_count);
        let mut writable_inodes = std::collections::BTreeSet::new();
        let mut constructed = Vec::new();
        for child in children {
            let option = &options.children[child.result.index as usize];
            let ForkChildInputs {
                configuration,
                storage,
                sources,
                mut request,
                objects: _objects,
                lower_inputs: _lower_inputs,
                _consumer_lease,
            } = prepare_fork_child_inputs(runtime, &cut, &child, option).unwrap();
            assert!(request.disk_tracking_seeds.is_empty());
            request.validate_for_inspection().unwrap();
            assert!(request
                .validate()
                .unwrap_err()
                .contains("destination seed count"));
            let inspection =
                crate::machine::restore::inspection_request(request.clone(), false).unwrap();
            let intent = crate::store::restore::RestoreIntent {
                source: crate::store::restore::RestoreIdentity::LocalCut {
                    id: cut.record.cut_id,
                },
                consumer_operation: child.consumer_id,
                request: request.clone(),
                resources: store.fork_child_charge(child.consumer_id).await.unwrap(),
                inspection: inspection_report(&inspection),
                network_attachment: false,
            };
            intent.validate().unwrap();
            let run = uuid::Uuid::parse_str(child.result.run_id.as_str()).unwrap();
            store
                .persist_restore_construction(&crate::store::restore::RestoreConstruction {
                    run_id: run,
                    name: child.result.name.clone(),
                    intent: intent.clone(),
                })
                .await
                .unwrap();
            let (config, durability) = crate::machine::builder::publish_restored_child(
                runtime,
                crate::machine::builder::ChildConstruction {
                    name: child.result.name.clone(),
                    configuration,
                    storage,
                    sources,
                    operation_id: child.consumer_id,
                    shared_qualification: None,
                },
                run,
                None,
            )
            .await
            .unwrap();
            assert_eq!(config.retention, crate::MachineRetention::Persistent);
            assert_eq!(
                store
                    .machine_config(config.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .retention,
                crate::MachineRetention::Persistent
            );
            durability.spawn().await.unwrap().unwrap();
            assert_eq!(config.id, child.result.machine_id);
            let storage = store.machine_storage(config.id).await.unwrap().unwrap();
            let lease = snapshots
                .register_restore_generation(&config, run, &storage, &intent)
                .await
                .unwrap();
            bind_restore_disk_tracking(runtime, &config, &storage, &mut request).unwrap();
            request.ssh_trusted_ca = Some("host-construction-public-ca".into());
            store
                .bind_restore_activation(lease.operation_id(), &request)
                .await
                .unwrap();
            store
                .mark_launch_storage_admitted(lease.operation_id())
                .await
                .unwrap();
            request.validate().unwrap();
            assert_inspection_binding(&intent, &request);
            assert_eq!(
                vm_spec::capture::CaptureConfiguration::from_spec(&config.spec).unwrap(),
                request.configuration
            );
            let encoded = serde_json::to_vec(&request).unwrap();
            let decoded: vm_spec::restore::RestoreRequest =
                serde_json::from_slice(&encoded).unwrap();
            decoded.validate().unwrap();
            for seed in &request.disk_tracking_seeds {
                assert!(seed.baseline.is_none());
                assert!(
                    writable_inodes.insert((seed.file_device, seed.file_inode)),
                    "siblings must not share writable disk inodes"
                );
                assert!(
                    !cut.record.files.iter().any(|member| {
                        member.device == seed.file_device && member.inode == seed.file_inode
                    }),
                    "a child must not write its owned cut"
                );
            }
            assert!(snapshots.list().await.unwrap().is_empty());
            assert_transfer_descriptors(
                request,
                _objects,
                _lower_inputs.map(|lower| lower.files).unwrap_or_default(),
            );
            constructed.push((config, lease));
        }
        constructed
    }

    pub(crate) fn inspection_report(
        request: &vm_spec::restore::RestoreInspectionRequest,
    ) -> vm_spec::restore::RestoreInspectionReport {
        use vm_spec::restore::{
            RestoreAdmittedDevice, RestoreAuthority, RestoreInspectionReport,
            RestoreInspectionRequestBinding,
        };
        let bytes = serde_json::to_vec(request).unwrap();
        let binding = request.restore.authority.binding().unwrap();
        RestoreInspectionReport {
            version: vm_spec::restore::RESTORE_INSPECTION_VERSION,
            request: match &request.restore.authority {
                RestoreAuthority::IdentifiedSnapshot { .. } => {
                    RestoreInspectionRequestBinding::Identified {
                        sha256: vm_spec::capture::Sha256Digest::of_bytes(&bytes),
                    }
                }
                RestoreAuthority::OwnedLocalCut { .. } | RestoreAuthority::Hibernation { .. } => {
                    RestoreInspectionRequestBinding::OwnedLocalCut {
                        request: String::from_utf8(bytes).unwrap(),
                    }
                }
            },
            authority: request.restore.authority.reference(),
            live_state_schema: binding.live_state_schema.clone(),
            architecture: binding.architecture.clone(),
            lane: vm_spec::live::LiveLane::KvmX86_64,
            cpu_count: u32::from(request.restore.configuration.cpus),
            ram_bytes: request.restore.configuration.ram_bytes(),
            devices: request
                .expected_device_identities()
                .enumerate()
                .map(|(index, (id, kind))| RestoreAdmittedDevice {
                    configured_id: id.into(),
                    kind,
                    address: (index as u64 + 1) * 4096,
                    irq: index as u32 + 1,
                })
                .collect(),
        }
    }

    #[test]
    fn restore_full_byte_hash_preserves_descriptor_position_for_receiver() {
        use std::io::{Seek, Write};
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"snapshot state").unwrap();
        let expected = vm_spec::capture::Sha256Digest::of_bytes(b"snapshot state");
        assert_eq!(whole_file_sha256(&file).unwrap(), expected);
        assert_eq!(
            file.stream_position().unwrap(),
            b"snapshot state".len() as u64
        );
    }

    fn snapshot() -> crate::store::models::snapshot::SnapshotRecord {
        use crate::storage::identity::ObjectDigest;
        let stream = format!("sha256:{}", "01".repeat(32)).parse().unwrap();
        crate::store::models::snapshot::tests::record(
            stream,
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        )
    }

    #[test]
    fn standalone_restore_reserves_sparse_disk_allocation_and_boot_objects() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;

        use crate::machine::restore::restore_disk_peak;
        use crate::machine::stopped::PrivateSource;
        use crate::storage::stream::{AuthenticatedStream, StreamHasher};

        let temporary = tempfile::tempdir().unwrap();
        let images = temporary.path().join("images");
        let pool = crate::storage::pool::StoragePool::open(&images).unwrap();
        let kernel = temporary.path().join("kernel");
        std::fs::write(&kernel, b"kernel").unwrap();
        pool.publish_object(&kernel).unwrap();
        let source = temporary.path().join("upper.raw");
        let mut file = std::fs::File::create(&source).unwrap();
        let length = 100 << 30;
        file.set_len(length).unwrap();
        file.write_all(&[0x51; 512]).unwrap();
        file.sync_all().unwrap();
        let allocated = file.metadata().unwrap().blocks().checked_mul(512).unwrap();
        assert!(allocated > 0 && allocated < length / 1000);
        let map = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_file(&source)
            .unwrap();
        let sources = [PrivateSource::Authenticated {
            path: crate::PrivatePath::new("upper.raw").unwrap(),
            stream: AuthenticatedStream::from_receipt(std::fs::File::open(&source).unwrap(), map)
                .unwrap(),
        }];
        assert_eq!(
            restore_disk_peak(&images, &sources, &snapshot()).unwrap(),
            vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + allocated + 2 * b"kernel".len() as u64
        );
    }

    fn attachment(role: vm_spec::DiskRole, id: &str, read_only: bool) -> vm_spec::Disk {
        vm_spec::Disk {
            path: "captured".into(),
            role,
            format: if role == vm_spec::DiskRole::RootLower {
                vm_spec::DiskFormat::Vmdk
            } else {
                vm_spec::DiskFormat::Raw
            },
            geometry: vm_spec::DiskGeometry {
                length: 512,
                logical_sector_size: 512,
            },
            block_id: vm_spec::BlockId::new(id).unwrap(),
            read_only,
        }
    }

    #[test]
    fn portability_refusal_preserves_exact_pin_and_snapshot() {
        let refusal = vm_spec::restore::RestorePortabilityRefusal {
            pin: "cpu.cpuid".into(),
            expected: "leaf 0x7 subleaf 0: ebx.avx2".into(),
            actual: "destination leaf 0x7 subleaf 0 lacks ebx.avx2".into(),
            stage: "restore-preflight".into(),
        };
        refusal.validate().unwrap();
        let error = crate::LibVmError::SnapshotPortability {
            snapshot: "sha256:captured-snapshot".into(),
            refusal: Box::new(refusal),
        };
        let message = error.to_string();
        assert!(message.contains("cpu.cpuid"));
        assert!(message.contains("restore-preflight"));
        assert!(message.contains("leaf 0x7 subleaf 0"));
        assert!(message.contains("sha256:captured-snapshot"));
        assert!(message.contains("no execution child was started"));
    }

    #[test]
    fn restore_projects_raw_and_data_paths_without_rewriting_source_device_pins() {
        use crate::machine::restore::{project_restore_disks, storage_from_snapshot};
        use crate::store::models::snapshot::SnapshotDisk;
        let mut record = snapshot();
        record.configuration.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                attachment(vm_spec::DiskRole::Root, "saved-root", false),
                attachment(vm_spec::DiskRole::Data, "saved-writable", false),
                attachment(vm_spec::DiskRole::Data, "saved-readonly", true),
            ],
        });
        record.disks = (1..=2)
            .map(|order| SnapshotDisk {
                role: vm_spec::DiskRole::Data,
                order,
                writable: order == 1,
                content: record.root.stream.clone(),
                geometry: record.root.geometry,
            })
            .collect();
        let snapshot = format!("sha256:{}", "02".repeat(32)).parse().unwrap();
        let storage = storage_from_snapshot(&record, snapshot).unwrap();
        let mut spec = record.configuration.spec.clone();
        let pins = vm_spec::capture::CaptureConfiguration::from_spec(&spec).unwrap();
        project_restore_disks(
            &mut spec,
            &storage,
            std::path::Path::new("/retained/images"),
        )
        .unwrap();
        assert_eq!(
            vm_spec::capture::CaptureConfiguration::from_spec(&spec).unwrap(),
            pins
        );
        let disks = &spec.storage.unwrap().disks;
        assert_eq!(disks[0].path, std::path::Path::new("root.raw"));
        assert_eq!(disks[1].path, std::path::Path::new("disk-1.raw"));
        assert!(disks[2].path.starts_with("/retained/images/streams/sha256"));
        let mut changed = storage;
        if let crate::DiskStorage::ManagedWritable { geometry, .. } = &mut changed.disks[0].storage
        {
            geometry.length *= 2;
        }
        assert!(project_restore_disks(
            &mut record.configuration.spec,
            &changed,
            std::path::Path::new("/retained/images")
        )
        .is_err());
    }

    #[test]
    fn restore_projects_overlay_without_flattening_or_changing_guest_filesystem_identities() {
        use crate::machine::restore::{project_restore_disks, storage_from_snapshot};
        use crate::store::models::snapshot::SnapshotRootProfile;
        let mut record = snapshot();
        let lower_uuid = uuid::Uuid::new_v4();
        let upper_uuid = uuid::Uuid::new_v4();
        let lower = crate::store::models::snapshot::tests::composition();
        let lower_geometry = vm_spec::DiskGeometry {
            length: 8192,
            logical_sector_size: 512,
        };
        record.root.geometry.length = 64 << 20;
        record.root.stream.length = 64 << 20;
        record.root.profile = SnapshotRootProfile::LinuxOverlay {
            lower: Box::new(lower),
            lower_geometry,
            lower_filesystem_uuid: lower_uuid,
            upper_uuid,
            ext4_profile: crate::Ext4Profile::SiloUpperExt4V1,
            overlay_profile: crate::OverlayProfile::SiloOverlayV1,
            temporary_directory: crate::TemporaryDirectoryPolicy::DiskBacked,
        };
        if let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut record.boot {
            *root_selector = crate::RootSelector::ManagedOverlay;
        }
        record.configuration.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                attachment(vm_spec::DiskRole::RootLower, "silo-root-lower", true),
                attachment(vm_spec::DiskRole::RootUpper, "silo-root-upper", false),
            ],
        });
        record.configuration.spec.storage.as_mut().unwrap().disks[0].geometry = lower_geometry;
        record.configuration.spec.storage.as_mut().unwrap().disks[1].geometry =
            record.root.geometry;
        let snapshot = format!("sha256:{}", "03".repeat(32)).parse().unwrap();
        let storage = storage_from_snapshot(&record, snapshot).unwrap();
        let crate::MachineRoot::LinuxOverlay {
            lower:
                crate::OverlayLower::ErofsComposition {
                    record: restored,
                    geometry,
                    filesystem_uuid,
                },
            upper_uuid: actual_upper,
            ..
        } = &storage.root
        else {
            panic!("wrong restored root");
        };
        // The child inherits the exact lower identity; nothing is flattened.
        assert_eq!(*restored, record.lower().unwrap().result);
        assert_eq!(*geometry, lower_geometry);
        assert_eq!(*filesystem_uuid, lower_uuid);
        assert_eq!(*actual_upper, upper_uuid);
        let mut spec = record.configuration.spec.clone();
        let pins = vm_spec::capture::CaptureConfiguration::from_spec(&spec).unwrap();
        project_restore_disks(
            &mut spec,
            &storage,
            std::path::Path::new("/retained/images"),
        )
        .unwrap();
        assert_eq!(
            vm_spec::capture::CaptureConfiguration::from_spec(&spec).unwrap(),
            pins
        );
        let disks = spec.storage.unwrap().disks;
        assert_eq!(disks[0].format, vm_spec::DiskFormat::Vmdk);
        assert!(disks[0].read_only);
        assert_eq!(disks[0].path, std::path::Path::new("lower.vmdk"));
        assert_eq!(disks[1].path, std::path::Path::new("upper.raw"));
    }

    async fn owned_inspection_fixture() -> (
        crate::store::capture::tests::Fixture,
        Vec<std::fs::File>,
        vm_spec::restore::RestoreRequest,
    ) {
        use std::os::fd::AsRawFd;
        use vm_spec::restore::{RestoreAuthority, RestoreObject, RestoreObjectAuthority};

        let fixture = crate::store::capture::tests::fork_fixture().await;
        let (directory, cut) = crate::store::capture::tests::seal_owned(&fixture);
        let mut files = Vec::new();
        let objects = vm_spec::restore::RestoreObjectRole::ALL[..4]
            .iter()
            .copied()
            .map(|role| {
                let member = cut
                    .members
                    .iter()
                    .find(|member| member.role == role.capture_role())
                    .unwrap();
                let file = std::fs::File::open(directory.path().join(member.role.relative_path()))
                    .unwrap();
                let object = RestoreObject {
                    role,
                    fd: file.as_raw_fd(),
                    file_device: member.fingerprint.device,
                    file_inode: member.fingerprint.inode,
                    length: member.fingerprint.length,
                    authority: RestoreObjectAuthority::Owned {
                        fingerprint: member.fingerprint.clone(),
                    },
                };
                files.push(file);
                object
            })
            .collect();
        let request = vm_spec::restore::RestoreRequest {
            purpose: vm_spec::restore::ActivationPurpose::Clone,
            version: vm_spec::restore::RESTORE_REQUEST_VERSION,
            activation_id: cut.capture_id.clone(),
            freeze_operation_id: cut.freeze_operation_id.clone(),
            start_paused: true,
            configuration: cut.configuration.clone(),
            authority: RestoreAuthority::OwnedLocalCut { cut: Box::new(cut) },
            disk_tracking_seeds: Vec::new(),
            map_node_store: None,
            objects,
            lowers: Vec::new(),
            network: None,
            ssh_trusted_ca: None,
            hook: None,
        };
        request.validate_for_inspection().unwrap();
        (fixture, files, request)
    }

    #[tokio::test]
    async fn inspection_sender_uses_current_schema_and_validates_before_spawn() {
        use crate::machine::restore::{inspect, inspection_request};

        let (_fixture, _files, mut request) = owned_inspection_fixture().await;
        let outbound = inspection_request(request.clone(), false).unwrap();
        assert_eq!(
            outbound.version,
            vm_spec::restore::RESTORE_INSPECTION_VERSION
        );
        let bytes = serde_json::to_vec(&outbound).unwrap();
        let decoded: vm_spec::restore::RestoreInspectionRequest =
            serde_json::from_slice(&bytes).unwrap();
        decoded.validate().unwrap();

        request.version = 0;
        // This real file cannot execute. The request error must precede spawn.
        let executable = tempfile::NamedTempFile::new().unwrap();
        let error = inspect(executable.path(), &request, false)
            .await
            .unwrap_err();
        let crate::LibVmError::SnapshotPortability { refusal, .. } = error else {
            panic!("inspection request failure must be a restore-preflight refusal");
        };
        refusal.validate().unwrap();
        assert_eq!(refusal.stage, "restore-preflight");
        assert_eq!(refusal.pin, "inspection.request");
    }

    #[tokio::test]
    async fn inspection_runs_monitor_path_and_preserves_native_refusal() {
        use std::process::Command;

        use vm_spec::restore::{
            RestoreInspectionFailure, RestorePortabilityRefusal, RESTORE_INSPECTION_VERSION,
        };

        let (_fixture, _files, request) = owned_inspection_fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("silo-vmm");
        let failure = RestoreInspectionFailure {
            version: RESTORE_INSPECTION_VERSION,
            refusal: RestorePortabilityRefusal::new("architecture", "x86_64", "aarch64"),
        };
        std::fs::write(
            directory.path().join("refusal.json"),
            format!("{}\n", serde_json::to_string(&failure).unwrap()),
        )
        .unwrap();
        let script = r#"#!/bin/sh
test "$#" -eq 1 && test "$1" = inspect-restore || exit 2
/bin/cat >/dev/null && /bin/cat "${0%/*}/refusal.json" || exit 3
exit 1"#;
        // Stage in a separate process so concurrent forks cannot hold a writable handle.
        assert!(Command::new("/bin/sh")
            .args(["-c", r#"printf '%s\n' "$2" > "$1" && chmod 700 "$1""#])
            .arg("stage-monitor")
            .arg(&executable)
            .arg(script)
            .status()
            .unwrap()
            .success());
        let error = crate::machine::restore::inspect(&executable, &request, false)
            .await
            .unwrap_err();
        let crate::LibVmError::SnapshotPortability { snapshot, refusal } = error else {
            panic!("native inspection refusal must be a restore-preflight refusal");
        };
        refusal.validate().unwrap();
        assert!(snapshot.starts_with("fork:"));
        assert_eq!(*refusal, failure.refusal);
    }
}

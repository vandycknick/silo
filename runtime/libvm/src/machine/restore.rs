//! Execution checkpoints have their own constructor. No ordinary start, root
//! repair, resize, bootstrap execution or fallback is part of this path.
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use vm_spec::capture::{CaptureConfiguration, Sha256Digest};
use vm_spec::live::{LiveHostReport, LiveOperation};
use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

use crate::machine::lifecycle::{finish_failed_start, started_run_monitor, FailedStartState};
use crate::machine::root_storage::invalid;
use crate::machine::stopped::PrivateSource;
use crate::storage::pool::StoragePool;
use crate::storage::vmdk::{LowerBacking, LowerOccurrence};
use crate::store::models::snapshot::{SnapshotCaptureKind, SnapshotRecord, SnapshotRootProfile};
use crate::store::restore::RestoreIntent;
use crate::supervisor::launch::{install_child_inheritance, RestoreLaunch};
use crate::{
    DiskStorage, ExternalResourcePolicy, LibVmError, Machine, MachineRoot, MachineStorageRecord,
    RestoreOptions, Runtime, SnapshotRef, SnapshotStore,
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
    if !matches!(record.capture, SnapshotCaptureKind::LiveExecution { .. }) {
        return Err(invalid("execution restore requires a live checkpoint"));
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
    let result = async {
        let shape = snapshots.prepare_restore_shape(&consumer).await?;
        restore_consumer(
            &runtime,
            &snapshots,
            &consumer,
            options,
            preview,
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
    preview: SnapshotRecord,
    host_report: LiveHostReport,
    inspection_shape: crate::store::snapshot_store::RestoreInspectionShape,
) -> Result<Machine, LibVmError> {
    let shape = inspection_shape.shape();
    if consumer.record != preview {
        return Err(invalid(
            "checkpoint alias changed between preflight and verification",
        ));
    }
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let evidence = snapshots.restore_evidence(consumer, &pool)?.evidence;
    let execution = match &consumer.record.capture {
        SnapshotCaptureKind::LiveExecution { execution } => execution,
        _ => return Err(invalid("checkpoint capture kind changed")),
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
    let ram_map_bytes = shape
        .stream_map(&execution.memory.stream)?
        .canonical_bytes()?;
    let map_stage = crate::machine::stopped::OperationStaging::new_deferred(
        &pool,
        consumer.operation_id,
        &consumer.lease,
    )?;
    let map_input = crate::store::snapshot_store::RecordInput::new(
        runtime.local_images_dir(),
        consumer.operation_id,
        &ram_map_bytes,
    )?;
    let (ram_map, roots) = pool.publish_object_for_catalog(&map_input.path())?;
    store_ram_map_pin(runtime, consumer.operation_id, ram_map.digest).await?;
    drop(roots);
    let objects = [
        ram,
        shape.open_object(&pool, &execution.layout)?,
        shape.open_object(&pool, &execution.execution)?,
        shape.open_object(&pool, &execution.devices)?,
        pool.open_object(&ram_map.digest)?,
    ];
    let digests = [
        Sha256Digest::from_bytes(*execution.memory.stream.as_bytes()),
        Sha256Digest::from_bytes(*execution.layout.as_bytes()),
        Sha256Digest::from_bytes(*execution.execution.as_bytes()),
        Sha256Digest::from_bytes(*execution.devices.as_bytes()),
        Sha256Digest::from_bytes(*ram_map.digest.as_bytes()),
    ];
    let mut descriptors = Vec::with_capacity(5);
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
            identity,
        });
    }
    let lower_inputs = prepare_lower(&pool, consumer, map_stage, shape)?;
    let request = RestoreRequest {
        version: vm_spec::restore::RESTORE_REQUEST_VERSION,
        checkpoint: Sha256Digest::from_bytes(*consumer.info.id.as_bytes()),
        activation_id: vm_spec::lifecycle::LiveId::parse(&Uuid::new_v4().to_string())
            .map_err(invalid)?,
        freeze_operation_id: evidence
            .freeze_operation_id
            .clone()
            .ok_or_else(|| invalid("capture seal omitted the frozen operation identity"))?,
        start_paused: true,
        configuration: CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
            .map_err(invalid)?,
        evidence,
        objects: descriptors
            .try_into()
            .map_err(|_| invalid("restore requires exactly five descriptors"))?,
        lowers: lower_inputs
            .as_ref()
            .map(|lower| vec![lower.request.clone()])
            .unwrap_or_default(),
        network: None,
        ssh_trusted_ca: None,
        hook: options.activation_hook,
    };
    request.validate().map_err(invalid)?;
    let executable =
        crate::storage::stream::open_regular_source(runtime.supervisor().executable())?;
    let executable_identity =
        crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?);
    let network = !matches!(
        consumer.record.configuration.network,
        crate::store::models::MachineNetworkConfig::None
    );
    let inspected_executable = runtime
        .live_capability_query()
        .held_executable_digest(&executable)
        .await?;
    let images = runtime.local_images_dir().to_path_buf();
    let shape = tokio::task::spawn_blocking(move || inspection_shape.complete(&images));
    let (inspection, shape) = tokio::try_join!(inspect(&executable, &request, network), async {
        shape.await?
    },)?;
    if inspection.lane != host_report.lane {
        return Err(invalid(
            "native restore inspection lane differs from the selected host capability report",
        ));
    }
    if crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?)
        != executable_identity
    {
        return Err(invalid(
            "selected monitor executable changed during native inspection",
        ));
    }
    let storage = storage_from_snapshot(&consumer.record, consumer.info.id)?;
    crate::store::operation_store::preflight_launch_storage(
        &storage,
        &consumer.record.configuration.spec,
    )?;
    // The restored child roots its lower by identity. Register the exact
    // checkpoint graph (authenticated, exact-loaded) under the consumer.
    if let Some(lower) = consumer.record.lower() {
        crate::store::layer_store::LayerStore::from_store(runtime.native_store()?)
            .publish_snapshot_composition(consumer.operation_id, lower)
            .await?;
    }
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
    let mut sources = vec![PrivateSource::Authenticated {
        path: crate::PrivatePath::new(match &storage.root {
            MachineRoot::OpaqueRaw { .. } => "root.raw",
            _ => "upper.raw",
        })?,
        stream: shape.open_copy_source(
            &pool,
            &consumer.record.root.stream.stream,
            consumer.record.root.geometry.length,
        )?,
    }];
    for disk in &consumer.record.disks {
        if disk.writable {
            sources.push(PrivateSource::Authenticated {
                path: crate::PrivatePath::new(format!("disk-{}.raw", disk.order))?,
                stream: shape.open_copy_source(
                    &pool,
                    &disk.content.stream,
                    disk.geometry.length,
                )?,
            });
        }
    }
    let disk_peak = restore_disk_peak(runtime, &sources, &consumer.record)?;
    let memory = snapshots
        .reserve_restore_resources(
            consumer,
            &request,
            disk_peak,
            descriptor_peak,
            options.resources,
        )
        .await?;
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(runtime, options.name.as_deref()).await?;
    let run = Uuid::new_v4();
    let intent = RestoreIntent {
        checkpoint: crate::store::restore::RestoreIdentity::Snapshot {
            id: consumer.info.id,
        },
        consumer_operation: consumer.operation_id,
        request: request.clone(),
        memory,
        inspected_executable,
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
            objects,
            executable,
            executable_identity,
            lower_inputs,
            shared_qualification: None,
            authentication: Some(RestoreAuthentication::new(snapshots.clone(), shape)),
        },
        name,
        run,
        Some(_names),
    )
    .await
}

struct PreparedRestore {
    configuration: crate::SnapshotConfiguration,
    storage: MachineStorageRecord,
    sources: Vec<PrivateSource>,
    intent: RestoreIntent,
    request: RestoreRequest,
    objects: [File; 5],
    executable: File,
    executable_identity: crate::storage::identity_file::SourceFingerprint,
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
) -> Result<Machine, LibVmError> {
    let PreparedRestore {
        configuration,
        storage,
        sources,
        intent,
        request,
        objects,
        executable,
        executable_identity,
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
        executable,
        executable_identity,
        lowers: lower_inputs.map(|lower| lower.files).unwrap_or_default(),
    };
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
                    lease,
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

struct LowerInputs {
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

/// Lower of a local cut: the cut operation pins the retained composition;
/// every backing is authenticated here (streams by map, fsmeta by streaming
/// whole-byte SHA-256) and held through descriptor handoff.
pub(crate) fn verify_local_lower(
    pool: &StoragePool,
    storage: &MachineStorageRecord,
    configuration: &crate::SnapshotConfiguration,
    lower: Option<&crate::store::composition_store::LaunchLower>,
) -> Result<Option<VerifiedLower>, LibVmError> {
    match (&storage.root, lower) {
        (MachineRoot::LinuxOverlay { lower: root, .. }, Some(launch)) => {
            launch.retained.check_lower(root)?;
            verify_lower_shape(
                &launch.occurrences,
                root.geometry().length,
                configuration,
                |backing, length| match backing {
                    LowerBacking::Stream(stream) => {
                        let authenticated =
                            crate::machine::stopped::open_immutable_stream(pool, &stream, length)?;
                        Ok((
                            authenticated.file().try_clone()?,
                            authenticated.fingerprint(),
                        ))
                    }
                    LowerBacking::Object(object) => {
                        let file = pool.verify_object(&object)?;
                        let fingerprint = crate::storage::identity_file::SourceFingerprint::new(
                            &file.metadata()?,
                        );
                        Ok((file, fingerprint))
                    }
                },
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
    checkpoint: crate::storage::identity::SnapshotId,
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
    let storage = MachineStorageRecord {
        schema: 1,
        root,
        boot: record.boot.clone(),
        profile,
        backend,
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
        snapshot: Some(checkpoint),
    };
    storage.validate()?;
    Ok(storage)
}

fn restore_disk_peak(
    runtime: &Runtime,
    sources: &[PrivateSource],
    record: &SnapshotRecord,
) -> Result<u64, LibVmError> {
    let mut required = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
    for source in sources {
        required = required
            .checked_add(source.length())
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
        let pool = StoragePool::open(runtime.local_images_dir())?;
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
    let composite = crate::initramfs_overlay::write_composite_deferred(
        base,
        agent,
        &paths.composite_initramfs_path(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    durability.files.push(composite);
    durability.files.push(
        crate::supervisor::write_launch_spec_deferred(&paths.vm_spec_path(), spec)
            .map_err(|error| invalid(error.to_string()))?,
    );
    Ok(())
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
    restore.request.validate().map_err(invalid)?;
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
            crate::boot_qualification::QualifiedAsset::open(&pool.object_path(base_initramfs))
                .map_err(|error| invalid(error.to_string()))?;
        let binary = crate::boot_qualification::QualifiedAsset::open(&pool.object_path(agent))
            .map_err(|error| invalid(error.to_string()))?;
        if base.digest() != *base_initramfs.as_bytes() || binary.digest() != *agent.as_bytes() {
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
        qualification: None,
        storage_lease: lease.lock(),
        storage_lease_binding: protocol::shutdown::StorageLeaseBinding {
            operation_id: lease.operation_id().to_string(),
            file_device,
            file_inode,
        },
        storage_shutdown: &shutdown,
        restore: Some(restore),
    };
    runtime
        .mark_launch_storage_admitted(lease.operation_id())
        .await?;
    let pending = runtime.supervisor().spawn(&launch).await?;
    Ok((pending, lifetime))
}

async fn store_ram_map_pin(
    runtime: &Runtime,
    operation: Uuid,
    digest: crate::storage::identity::ObjectDigest,
) -> Result<(), LibVmError> {
    runtime
        .native_store()?
        .pin_published_storage_dependencies(operation, &[], &[digest])
        .await
}

async fn inspect(
    executable: &File,
    restore: &RestoreRequest,
    network: bool,
) -> Result<vm_spec::restore::RestoreInspectionReport, LibVmError> {
    let request = vm_spec::restore::RestoreInspectionRequest {
        version: 1,
        restore: restore.clone(),
        network,
    };
    let bytes = serde_json::to_vec(&request).map_err(|error| invalid(error.to_string()))?;
    if bytes.len() >= 1 << 20 {
        return Err(invalid("restore inspection request exceeds 1 MiB"));
    }
    let mut command = pinned_command(executable);
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
    install_child_inheritance(&mut command, descriptors)?;
    let mut child = tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()?;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(invalid("native inspection pipes are unavailable"));
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
            bounded_output(stdout, 1 << 20),
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
            return Err(invalid(format!(
                "native restore inspection failed: {other:?}"
            )));
        }
    };
    if !status.success() {
        if stdout.ends_with(b"\n") && !stdout[..stdout.len().saturating_sub(1)].contains(&b'\n') {
            if let Ok(failure) =
                serde_json::from_slice::<vm_spec::restore::RestoreInspectionFailure>(&stdout)
            {
                failure.validate().map_err(invalid)?;
                return Err(LibVmError::CheckpointPortability {
                    checkpoint: restore.checkpoint.to_string(),
                    refusal: Box::new(failure.refusal),
                });
            }
        }
        return Err(invalid(format!(
            "native restore inspection failed without a typed refusal: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    if !stdout.ends_with(b"\n") || stdout[..stdout.len().saturating_sub(1)].contains(&b'\n') {
        return Err(invalid(
            "native restore inspection did not return one bounded report",
        ));
    }
    let report: vm_spec::restore::RestoreInspectionReport =
        serde_json::from_slice(&stdout).map_err(|error| invalid(error.to_string()))?;
    if let Some(refusal) = report.portability_refusal(&request) {
        refusal.validate().map_err(invalid)?;
        return Err(LibVmError::CheckpointPortability {
            checkpoint: restore.checkpoint.to_string(),
            refusal: Box::new(refusal),
        });
    }
    report.validate_against(&bytes, &request).map_err(invalid)?;
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

fn pinned_command(executable: &File) -> std::process::Command {
    let root = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::process::Command::new(Path::new(root).join(executable.as_fd().as_raw_fd().to_string()))
}

pub(crate) struct VerifiedForkRestore {
    cut: crate::store::fork::VerifiedRestoreCut,
    executable: File,
    executable_identity: crate::storage::identity_file::SourceFingerprint,
    inspected_executable: crate::storage::identity::ObjectDigest,
    lane: vm_spec::live::LiveLane,
    shared_qualification: Arc<crate::machine::root_disk::SharedCopyQualification>,
}

pub(crate) async fn prepare_fork_restore(
    runtime: &Runtime,
    cut: crate::store::fork::VerifiedRestoreCut,
) -> Result<VerifiedForkRestore, LibVmError> {
    let host = runtime.live_capabilities().await?;
    crate::require_host_live_operation(&host, LiveOperation::Restore)?;
    let executable =
        crate::storage::stream::open_regular_source(runtime.supervisor().executable())?;
    let executable_identity =
        crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?);
    let inspected_executable = runtime
        .live_capability_query()
        .held_executable_digest(&executable)
        .await?;
    if crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?)
        != executable_identity
    {
        return Err(invalid(
            "fork monitor executable changed during authentication",
        ));
    }
    let shared_qualification = Arc::new(crate::machine::root_disk::SharedCopyQualification::new(
        cut.directory(),
    )?);
    Ok(VerifiedForkRestore {
        cut,
        executable,
        executable_identity,
        inspected_executable,
        lane: host.lane,
        shared_qualification,
    })
}

pub(crate) async fn restore_reserved_fork_child(
    runtime: &Runtime,
    prepared: Arc<VerifiedForkRestore>,
    child: crate::store::fork::ForkChildIdentity,
    options: crate::LiveForkChild,
) -> Result<Machine, LibVmError> {
    let cut = &prepared.cut;
    let store = runtime.native_store()?;
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
        // An independent descriptor sharing the cut's seal-derived map.
        let stream = cut.reopen_disk(&role)?;
        if stream.length() != disk.length {
            return Err(invalid("fork cut disk geometry differs from its plan"));
        }
        sources.push(PrivateSource::Authenticated { path, stream });
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
    let mut files = Vec::with_capacity(5);
    let mut descriptors = Vec::with_capacity(5);
    for role in RestoreObjectRole::ALL {
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
            identity: identity.identity,
        });
        files.push(file);
    }
    let request = RestoreRequest {
        version: vm_spec::restore::RESTORE_REQUEST_VERSION,
        checkpoint: cut.record.cut_id,
        activation_id: vm_spec::lifecycle::LiveId::parse(&child.activation_id.to_string())
            .map_err(invalid)?,
        freeze_operation_id: cut
            .record
            .evidence
            .freeze_operation_id
            .clone()
            .ok_or_else(|| invalid("fork freeze operation missing"))?,
        start_paused: true,
        configuration: cut.record.plan.configuration.clone(),
        evidence: cut.record.evidence.clone(),
        objects: descriptors
            .try_into()
            .map_err(|_| invalid("fork restore needs five objects"))?,
        lowers: lower_inputs
            .as_ref()
            .map(|lower| vec![lower.request.clone()])
            .unwrap_or_default(),
        network: None,
        ssh_trusted_ca: None,
        hook: options.activation_hook,
    };
    request.validate().map_err(invalid)?;
    let executable = prepared.executable.try_clone()?;
    let executable_identity = prepared.executable_identity;
    let inspected_executable = prepared.inspected_executable;
    let network = !matches!(
        configuration.network,
        crate::store::models::MachineNetworkConfig::None
    );
    let inspection = inspect(&executable, &request, network).await?;
    if inspection.lane != prepared.lane
        || crate::storage::identity_file::SourceFingerprint::new(&executable.metadata()?)
            != executable_identity
    {
        return Err(invalid("fork restore native inspection identity changed"));
    }
    let intent = RestoreIntent {
        checkpoint: crate::store::restore::RestoreIdentity::LocalCut {
            id: cut.record.cut_id,
        },
        consumer_operation: child.consumer_id,
        request: request.clone(),
        memory: store.fork_child_charge(child.consumer_id).await?,
        inspected_executable,
        inspection,
        network_attachment: network,
    };
    execute_prepared(
        runtime,
        PreparedRestore {
            configuration,
            storage,
            sources,
            intent,
            request,
            objects: files
                .try_into()
                .map_err(|_| invalid("fork restore needs five files"))?,
            executable,
            executable_identity,
            lower_inputs,
            authentication: None,
            shared_qualification: Some(Arc::clone(&prepared.shared_qualification)),
        },
        child.result.name,
        Uuid::parse_str(child.result.run_id.as_str())
            .map_err(|error| invalid(error.to_string()))?,
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::storage::stream::whole_file_sha256;
    #[test]
    fn restore_full_byte_hash_preserves_descriptor_position_for_receiver() {
        use std::io::{Seek, Write};
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"checkpoint state").unwrap();
        let expected = vm_spec::capture::Sha256Digest::of_bytes(b"checkpoint state");
        assert_eq!(whole_file_sha256(&file).unwrap(), expected);
        assert_eq!(
            file.stream_position().unwrap(),
            b"checkpoint state".len() as u64
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
    fn portability_refusal_preserves_exact_pin_and_checkpoint() {
        let refusal = vm_spec::restore::RestorePortabilityRefusal {
            pin: "cpu.cpuid".into(),
            expected: "leaf 0x7 subleaf 0: ebx.avx2".into(),
            actual: "destination leaf 0x7 subleaf 0 lacks ebx.avx2".into(),
            stage: "restore-preflight".into(),
        };
        refusal.validate().unwrap();
        let error = crate::LibVmError::CheckpointPortability {
            checkpoint: "sha256:captured-checkpoint".into(),
            refusal: Box::new(refusal),
        };
        let message = error.to_string();
        assert!(message.contains("cpu.cpuid"));
        assert!(message.contains("restore-preflight"));
        assert!(message.contains("leaf 0x7 subleaf 0"));
        assert!(message.contains("sha256:captured-checkpoint"));
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
        let checkpoint = format!("sha256:{}", "02".repeat(32)).parse().unwrap();
        let storage = storage_from_snapshot(&record, checkpoint).unwrap();
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
        let checkpoint = format!("sha256:{}", "03".repeat(32)).parse().unwrap();
        let storage = storage_from_snapshot(&record, checkpoint).unwrap();
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
}

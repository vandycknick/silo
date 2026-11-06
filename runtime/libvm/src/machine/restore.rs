//! Execution checkpoints have their own constructor. No ordinary start, root
//! repair, resize, bootstrap execution or fallback is part of this path.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use vm_spec::capture::{CaptureConfiguration, Sha256Digest};
use vm_spec::live::{LiveHostReport, LiveOperation};
use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

use crate::machine::lifecycle::{finish_failed_start, started_run_monitor, FailedStartState};
use crate::machine::root_storage::invalid;
use crate::machine::stopped::{open_immutable_stream, PrivateSource};
use crate::storage::pool::StoragePool;
use crate::store::models::snapshot::{SnapshotCaptureKind, SnapshotRecord, SnapshotRootProfile};
use crate::store::restore::RestoreIntent;
use crate::supervisor::launch::{install_child_inheritance, RestoreLaunch};
use crate::{
    DiskStorage, ExternalResourcePolicy, LibVmError, Machine, MachineRoot, MachineStorageRecord,
    RestoreOptions, Runtime, RuntimeConfig, SnapshotRef, SnapshotStore,
};

pub(crate) async fn preflight_execution(
    config: &RuntimeConfig,
    record: &SnapshotRecord,
    policy: &ExternalResourcePolicy,
) -> Result<(), LibVmError> {
    crate::require_host_live_operation(
        &crate::LiveCapabilityQuery::open(config)?
            .host_report()
            .await?,
        LiveOperation::Restore,
    )?;
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
    let consumer = snapshots.consume(&reference).await?;
    let result = restore_consumer(
        &runtime,
        &snapshots,
        &consumer,
        options,
        preview,
        host_report,
    )
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
) -> Result<Machine, LibVmError> {
    let store = runtime.native_store()?;
    if consumer.record != preview {
        return Err(invalid(
            "checkpoint alias changed between preflight and verification",
        ));
    }
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let evidence = snapshots.restore_evidence(consumer, &pool)?;
    let execution = match &consumer.record.capture {
        SnapshotCaptureKind::LiveExecution { execution } => execution,
        _ => return Err(invalid("checkpoint capture kind changed")),
    };
    let transfer_roles = 4 + if matches!(
        consumer.record.root.profile,
        SnapshotRootProfile::LinuxOverlay { .. }
    ) {
        2
    } else {
        0
    };
    crate::storage::limits::preflight_fd_budget(
        3 * transfer_roles + 3 * consumer.record.disks.len() as u64 + 32,
    )
    .map_err(crate::storage::StorageError::from)?;
    let objects = [
        open_immutable_stream(&pool, &execution.memory.stream, execution.memory.length)?.file,
        crate::storage::stream::open_regular_source(&pool.object_path(&execution.layout))?,
        crate::storage::stream::open_regular_source(&pool.object_path(&execution.execution))?,
        crate::storage::stream::open_regular_source(&pool.object_path(&execution.devices))?,
    ];
    let mut descriptors = Vec::with_capacity(4);
    for (file, role) in objects.iter().zip(RestoreObjectRole::ALL) {
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
            sha256: hash_file(file)?,
        });
    }
    let lower_inputs = prepare_lower(&pool, consumer)?;
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
            .map_err(|_| invalid("restore requires exactly four descriptors"))?,
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
    let inspected_executable =
        crate::storage::identity::ObjectDigest::from_sha256(*hash_file(&executable)?.as_bytes());
    let inspection = inspect(&executable, &request, network).await?;
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
        runtime.local_images_dir(),
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
    crate::storage::limits::preflight_fd_budget(
        (3 * transfer_roles).max(native_records + transfer_roles)
            + 3 * request.configuration.attachments.len() as u64
            + 32,
    )
    .map_err(crate::storage::StorageError::from)?;
    let mut sources = vec![PrivateSource {
        path: crate::PrivatePath::new(match &storage.root {
            MachineRoot::OpaqueRaw { .. } => "root.raw",
            _ => "upper.raw",
        })?,
        file: open_immutable_stream(
            &pool,
            &consumer.record.root.stream.stream,
            consumer.record.root.geometry.length,
        )?
        .file,
        length: consumer.record.root.geometry.length,
    }];
    for disk in &consumer.record.disks {
        if disk.writable {
            sources.push(PrivateSource {
                path: crate::PrivatePath::new(format!("disk-{}.raw", disk.order))?,
                file: open_immutable_stream(&pool, &disk.content.stream, disk.geometry.length)?
                    .file,
                length: disk.geometry.length,
            });
        }
    }
    let disk_peak = restore_disk_peak(runtime, &sources, &consumer.record)?;
    let memory = snapshots
        .reserve_restore_resources(
            consumer,
            &request,
            &runtime.local_home().join("machines"),
            disk_peak,
            options.resources,
        )
        .await?;
    let _names = runtime.lock_machine_names().await?;
    let name =
        crate::machine::builder::stopped_child_name(runtime, options.name.as_deref()).await?;
    let run = Uuid::new_v4();
    let intent = RestoreIntent {
        checkpoint: consumer.info.id,
        consumer_operation: consumer.operation_id,
        request: request.clone(),
        memory,
        inspected_executable,
        inspection,
        network_attachment: network,
    };
    store
        .persist_restore_construction(&crate::store::restore::RestoreConstruction {
            run_id: run,
            name: name.clone(),
            intent: intent.clone(),
        })
        .await?;
    let config = crate::machine::builder::publish_restored_child(
        runtime,
        name,
        consumer.record.configuration.clone(),
        storage,
        sources,
        consumer.operation_id,
        run,
    )
    .await?;
    drop(_names);
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
        destination.sync()?;
        lower.directory.sync()?;
    }
    let lease = snapshots
        .register_restore_generation(&config, run, &storage, &intent)
        .await?;
    // Generation registration copies all consumer roots in the same transaction.
    // Keep the old OFD until that commit, including an uncertain result.
    store
        .finish_stopped_operation(consumer.operation_id)
        .await?;
    let mut launch = RestoreLaunch {
        request,
        objects,
        executable,
        executable_identity,
        lowers: lower_inputs.map(|lower| lower.files).unwrap_or_default(),
    };
    let startup = launch_restored(runtime, &config, run, &storage, &mut launch, &lease).await;
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
        Ok(()) => Ok(Machine::new(runtime.clone(), config.id)),
        Err(error) => {
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
        return Ok((
            lock,
            current,
            result.and(Err(invalid("restored activation failed before readiness"))),
        ));
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
) -> Result<Option<LowerInputs>, LibVmError> {
    let SnapshotRootProfile::LinuxOverlay {
        lower,
        lower_geometry,
        lower_filesystem_uuid,
        ..
    } = &consumer.record.root.profile
    else {
        return Ok(None);
    };
    let occurrence = pool.lower_occurrence(&lower.stream)?;
    if occurrence.length() != lower_geometry.length
        || crate::machine::root_storage::filesystem_uuid(occurrence.path())?
            != *lower_filesystem_uuid
    {
        return Err(invalid(
            "authenticated lower differs from the captured geometry or filesystem",
        ));
    }
    let extent_path = occurrence.path().to_path_buf();
    let occurrences = [occurrence];
    let plan = crate::storage::vmdk::FlatLowerPlan::new(&occurrences)?;
    let admitted = plan.preflight(consumer.record.disks.len() as u64)?;
    crate::storage::limits::preflight_fd_budget(admitted.record_count() + 6)
        .map_err(crate::storage::StorageError::from)?;
    admitted.verify(pool)?;
    let stage = crate::machine::stopped::OperationStaging::new(
        pool,
        consumer.operation_id,
        &consumer.lease,
    )?;
    let directory = stage.directory()?;
    directory.write_file("lower.vmdk", admitted.descriptor()?.as_bytes())?;
    let descriptor = directory
        .open_file("lower.vmdk")?
        .ok_or_else(|| invalid("restore lower descriptor disappeared"))?;
    nix::sys::stat::fchmod(&descriptor, nix::sys::stat::Mode::S_IRUSR)
        .map_err(std::io::Error::from)?;
    descriptor.sync_all()?;
    let backing = open_immutable_stream(pool, &lower.stream, lower.length)?.file;
    let descriptor_stat = descriptor.metadata()?;
    let backing_stat = backing.metadata()?;
    let block_id = consumer
        .record
        .configuration
        .spec
        .storage
        .iter()
        .flat_map(|storage| &storage.disks)
        .find(|disk| disk.role == vm_spec::DiskRole::RootLower)
        .ok_or_else(|| invalid("captured lower attachment missing"))?
        .block_id
        .clone();
    Ok(Some(LowerInputs {
        request: vm_spec::restore::RestoreLower {
            block_id,
            descriptor: vm_spec::restore::RestoreDescriptor {
                fd: descriptor.as_raw_fd(),
                file_device: descriptor_stat.dev(),
                file_inode: descriptor_stat.ino(),
                length: descriptor_stat.len(),
            },
            extents: vec![vm_spec::restore::RestoreExtent {
                path: extent_path
                    .to_str()
                    .ok_or_else(|| invalid("lower extent path is not UTF-8"))?
                    .to_owned(),
                fd: backing.as_raw_fd(),
                file_device: backing_stat.dev(),
                file_inode: backing_stat.ino(),
                length: backing_stat.len(),
            }],
        },
        files: vec![descriptor, backing],
        native_records: admitted.record_count(),
        directory,
        _stage: stage,
    }))
}

fn storage_from_snapshot(
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
                lower: crate::OverlayLower::FlatExt4 {
                    stream: lower.stream,
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
        relocation_operation: None,
        fence: None,
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
            .checked_add(source.length)
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

async fn launch_restored(
    runtime: &Runtime,
    config: &crate::store::models::MachineConfig,
    run: Uuid,
    storage: &MachineStorageRecord,
    restore: &mut RestoreLaunch,
    lease: &crate::store::operation_store::LaunchStorageLease,
) -> Result<
    (
        crate::supervisor::launch::PendingStartup,
        crate::lock_manager::MachineLifetimeLock,
    ),
    LibVmError,
> {
    let paths = runtime.machine_paths(config.id);
    runtime.ensure_machine_runtime_directories(config.id)?;
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
        .prepare_machine_network(config, &run.to_string(), &secrets)
        .await?;
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
    crate::initramfs_overlay::write_composite(
        crate::initramfs_overlay::CompositeBase::Retained(&base),
        Some((
            crate::initramfs_overlay::CompositeAgent::Retained(&agent),
            &provenance,
        )),
        None,
        &paths.composite_initramfs_path(),
    )
    .map_err(|error| invalid(error.to_string()))?;
    crate::supervisor::write_launch_spec(&paths.vm_spec_path(), &spec)
        .map_err(|error| invalid(error.to_string()))?;
    let logs = runtime.local_paths().machine_logs_directory(config.id)?;
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

fn hash_file(file: &File) -> Result<Sha256Digest, LibVmError> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 << 10];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
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
    let mut child = tokio::process::Command::from(command).spawn()?;
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
        return Err(invalid(format!(
            "native restore compatibility refused: {}",
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

#[cfg(test)]
mod tests {
    use crate::machine::restore::hash_file;
    #[test]
    fn restore_full_byte_hash_preserves_descriptor_position_for_receiver() {
        use std::io::{Seek, Write};
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"checkpoint state").unwrap();
        let expected = vm_spec::capture::Sha256Digest::of_bytes(b"checkpoint state");
        assert_eq!(hash_file(&file).unwrap(), expected);
        assert_eq!(file.stream_position().unwrap(), 0);
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
        let lower = record.root.stream.clone();
        let lower_geometry = record.root.geometry;
        record.root.geometry.length = 64 << 20;
        record.root.stream.length = 64 << 20;
        record.root.profile = SnapshotRootProfile::LinuxOverlay {
            lower,
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
        record.configuration.spec.storage.as_mut().unwrap().disks[1].geometry =
            record.root.geometry;
        let checkpoint = format!("sha256:{}", "03".repeat(32)).parse().unwrap();
        let storage = storage_from_snapshot(&record, checkpoint).unwrap();
        let crate::MachineRoot::LinuxOverlay {
            lower: crate::OverlayLower::FlatExt4 {
                filesystem_uuid, ..
            },
            upper_uuid: actual_upper,
            ..
        } = &storage.root
        else {
            panic!("wrong restored root");
        };
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

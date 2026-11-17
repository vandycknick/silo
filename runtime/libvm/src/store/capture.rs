//! Capture storage ownership extends the existing operation journal and pool.
//! It never drives monitor lifecycle commands or infers continuation from exit.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use vm_spec::capture::{
    CaptureDiskCopy, CaptureDiskName, CaptureDiskPlan, CaptureEvidence, CaptureInventoryEntry,
    CaptureLaunchLease, CapturePlan, CaptureReadOnlyInput, CaptureRole, Sha256Digest,
};
use vm_spec::lifecycle::LiveId;

use crate::paths::OwnedDirectory;
use crate::storage::identity::ObjectDigest;
use crate::storage::identity_file::SourceFingerprint;
use crate::storage::limits::Resource;
use crate::storage::pool::{PublicationLockPolicy, SealedStreamPublicationMode, StoragePool};
use crate::storage::StorageError;
use crate::store::models::snapshot::{
    invalid, SnapshotCaptureKind, SnapshotCompatibilityProfile, SnapshotDisk, SnapshotExecution,
    SnapshotKind, SnapshotPurpose, SnapshotRecord, SnapshotRoot, SnapshotRootProfile,
};
use crate::store::models::MachineId;
use crate::store::snapshot_store::{
    CaptureRecord, CaptureReservation, CaptureReservationRequest, CaptureSourceOutcome,
    CaptureSpaceCharge, CaptureState, SnapshotInfo, SnapshotRef, SnapshotStore,
};
use crate::store::{MachineStore, Store};
use crate::{BootBinding, BootProfile, DiskStorage, LibVmError, MachineRoot, RawLayout};

impl SnapshotStore {
    pub(crate) async fn accept_live_disk_baselines(
        &self,
        record: &CaptureRecord,
    ) -> Result<(), LibVmError> {
        let this = self.clone();
        let mut record = record.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async move {
                if record.evidence.is_none() {
                    if let Some(operation) = record.fork_operation_id {
                        if let Some(cut) = this.store.local_cut(operation).await? {
                            record.evidence = Some(
                                String::from_utf8(cut.evidence.canonical_bytes().map_err(invalid)?)
                                    .map_err(invalid)?,
                            );
                        }
                    }
                }
                if record.evidence.is_none() {
                    let directory = capture_directory(&this.store, &record)?
                        .ok_or_else(|| invalid("accepted capture staging disappeared"))?;
                    settle_capture_seal(&directory)?;
                    let mut verified = validate_receipt(&directory, &record)?;
                    verified.admit_maps(&this.store, record.capture_id).await?;
                    verified.retain_disk_baselines(
                        &crate::paths::machine_data_dir_in(
                            this.store.home_path(),
                            record.machine_id,
                        ),
                        &record.plan,
                    )?;
                    record.evidence =
                        Some(String::from_utf8(verified.evidence_bytes).map_err(invalid)?);
                }
                let evidence = CaptureEvidence::decode(
                    record
                        .evidence
                        .as_deref()
                        .ok_or_else(|| invalid("accepted capture evidence is missing"))?
                        .as_bytes(),
                )
                .map_err(invalid)?;
                let memory = evidence
                    .memory
                    .as_ref()
                    .ok_or_else(|| invalid("accepted RAM identity is missing"))?;
                this.store.accept_capture_disk_baselines(&record).await?;
                this.store
                    .retain_memory_baseline(
                        record.launch_operation_id,
                        ObjectDigest::from_sha256(*memory.ram_stream.as_bytes()),
                    )
                    .await
            })
        })
        .await?
    }

    /// Plans, pins and reserves the complete peak before the monitor may freeze.
    /// Detached blocking ownership retains the lease/catalog on waiter loss.
    pub(crate) async fn reserve_capture(
        &self,
        request: &CaptureReservationRequest,
    ) -> Result<CaptureReservation, LibVmError> {
        let this = self.clone();
        let request = request.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || runtime.block_on(this.reserve_capture_owned(request)))
            .await?
    }

    async fn reserve_capture_owned(
        &self,
        request: CaptureReservationRequest,
    ) -> Result<CaptureReservation, LibVmError> {
        if request.capture_id.is_nil()
            || request.run_id.is_nil()
            || Uuid::from(request.machine_id).is_nil()
        {
            return Err(invalid(
                "capture reservation requires nonnil exact identities",
            ));
        }
        Resource::CapturedRamBytes
            .check(request.configuration.ram_bytes())
            .map_err(StorageError::from)?;
        if !(1..=60).contains(&request.dirty_crossover_percent) {
            return Err(invalid("dirty crossover percent must be between 1 and 60"));
        }
        let mut logical = request.configuration.ram_bytes();
        for attachment in &request.configuration.attachments {
            logical = logical
                .checked_add(attachment.geometry.length)
                .ok_or_else(|| invalid("capture logical closure overflow"))?;
        }
        Resource::ArtifactStreamBytes
            .check(logical)
            .map_err(StorageError::from)?;
        if let Some(alias) = &request.alias {
            crate::store::snapshot_store::validate_alias(alias)?;
        }
        request.configuration.validate().map_err(invalid)?;
        let pool = StoragePool::open(&self.store.images_dir)?;
        if let Some(record) = self.capture_reservation(request.capture_id).await? {
            if record.request != request {
                return Err(invalid("capture reservation replay changed its inputs"));
            }
            let lease = pool.existing_lease(record.capture_id)?;
            if record.state == CaptureState::Reserved && !record.dispatch_attempted {
                self.store.reserve_capture_inventory(&record, None).await?;
            }
            check_lease(&self.store, &pool, record.capture_id, &lease).await?;
            return Ok(CaptureReservation {
                record,
                _lease: lease,
            });
        }
        crate::storage::limits::preflight_fd_budget(capture_descriptor_budget(
            &request.configuration,
        )?)
        .map_err(StorageError::from)?;
        let config = self
            .store
            .machine_config(request.machine_id)
            .await?
            .ok_or_else(|| invalid("capture source configuration is missing"))?;
        let storage = self
            .store
            .machine_storage(request.machine_id)
            .await?
            .ok_or_else(|| invalid("capture source storage is missing"))?;
        let launch = self
            .store
            .launch_storage_operations(request.machine_id)
            .await?
            .into_iter()
            .find(|launch| launch.run_id == request.run_id && launch.admitted)
            .ok_or_else(|| invalid("capture has no admitted exact-run launch owner"))?;
        if !storage.matches_launch_storage(&launch.storage)
            || storage.operation.is_some()
            || !storage.ownership.is_owned()
        {
            return Err(invalid(
                "capture source generation changed or has an unresolved operation",
            ));
        }
        if launch.disks.len() != request.configuration.attachments.len()
            || launch
                .disks
                .iter()
                .zip(&request.configuration.attachments)
                .any(|(disk, attachment)| {
                    disk.block_id != attachment.block_id
                        || disk.role != attachment.role
                        || disk.geometry != attachment.geometry
                        || disk.read_only != attachment.read_only
                        || disk.format != attachment.format
                })
        {
            return Err(invalid(
                "capture configuration differs from retained launch attachments",
            ));
        }
        let (device, inode) = pool.operation_lease_identity(launch.operation_id)?;
        let machine = open_machine(&self.store, request.machine_id)?;
        let images = OwnedDirectory::open_existing_root(&self.store.images_dir)?
            .ok_or_else(|| invalid("pool directory is missing"))?;
        let machine_stat = nix::sys::stat::fstat(machine.fd()).map_err(std::io::Error::from)?;
        let images_stat = nix::sys::stat::fstat(images.fd()).map_err(std::io::Error::from)?;
        let mut stage = request
            .configuration
            .ram_bytes()
            .checked_add(vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
            .ok_or_else(|| invalid("capture budget overflow"))?;
        let map_bytes = capture_map_budget(&request.configuration)?;
        let changes_bytes = request
            .configuration
            .ram_bytes()
            .div_ceil(vm_spec::stream_map::ChunkSize::RAM.bytes())
            .checked_mul(56)
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or_else(|| invalid("RAM changes budget overflow"))?;
        stage = stage
            .checked_add(map_bytes)
            .and_then(|bytes| bytes.checked_add(changes_bytes))
            .ok_or_else(|| invalid("capture metadata staging overflow"))?;
        let fork_operation_id = self.store.fork_for_capture(request.capture_id).await?;
        let local_fork = fork_operation_id.is_some();
        let clone_publication = !local_fork
            && machine_stat.st_dev == images_stat.st_dev
            && pool.qualify_capture_clone(&machine).unwrap_or(false);
        let mut publication_clones = BTreeSet::new();
        if clone_publication {
            publication_clones.insert(CaptureRole::Ram.relative_path());
        }
        let mut publication =
            publication_stream_bytes(request.configuration.ram_bytes(), clone_publication)
                .checked_add(2 * vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
                .and_then(|bytes| bytes.checked_add(2 * map_bytes))
                .and_then(|bytes| bytes.checked_add(changes_bytes))
                .ok_or_else(|| invalid("capture publication budget overflow"))?;
        let mut disks = Vec::new();
        let mut disk_allocations = BTreeMap::new();
        let mut read_only_inputs = Vec::new();
        let mut source_inodes = Vec::new();
        for (index, attachment) in request.configuration.attachments.iter().enumerate() {
            Resource::VirtualDiskBytes
                .check(attachment.geometry.length)
                .map_err(StorageError::from)?;
            if attachment.read_only {
                read_only_inputs.push(CaptureReadOnlyInput {
                    attachment_index: index as u32,
                    block_id: attachment.block_id.clone(),
                    identity: read_only_identity(&storage, index as u32, attachment.role)?,
                });
            } else {
                let external_writable = attachment.role == vm_spec::DiskRole::Data
                    && !storage
                        .disks
                        .iter()
                        .any(|disk| disk.order as usize == index);
                let source = if external_writable {
                    let launched = launch
                        .disks
                        .get(index)
                        .ok_or_else(|| invalid("external writable launch attachment is missing"))?;
                    let path = if launched.path.is_absolute() {
                        launched.path.clone()
                    } else {
                        machine.path().join(&launched.path)
                    };
                    crate::storage::stream::open_regular_source(&path)?
                } else {
                    open_relative(
                        &machine,
                        writable_path(&storage, index as u32, attachment.role)?,
                    )?
                };
                let metadata = source.metadata()?;
                if metadata.len() != attachment.geometry.length || metadata.nlink() != 1 {
                    return Err(invalid(
                        "capture source geometry or writable hardlink policy violated",
                    ));
                }
                let identity = (metadata.dev(), metadata.ino());
                if source_inodes.contains(&identity) {
                    return Err(invalid("capture writable source roles alias one inode"));
                }
                source_inodes.push(identity);
                let allocated = metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| invalid("capture allocation overflow"))?;
                disk_allocations.insert(index as u32, allocated);
                stage = stage
                    .checked_add(allocated)
                    .ok_or_else(|| invalid("capture staging overflow"))?;
                // Growth after this allocation sample can still fail capture
                // cleanly. Clone-priced publication forbids a copy fallback.
                let name = match attachment.role {
                    vm_spec::DiskRole::Root => "silo-root".into(),
                    vm_spec::DiskRole::RootUpper => "silo-root-upper".into(),
                    vm_spec::DiskRole::Data => format!("silo-data-{index}"),
                    vm_spec::DiskRole::RootLower => {
                        return Err(invalid("overlay lower must be immutable and read-only"))
                    }
                };
                let role = CaptureRole::Disk(CaptureDiskName::new(name.clone()).map_err(invalid)?)
                    .relative_path();
                // Publication reads the staged copy on the machine filesystem,
                // not this attachment's possibly external source filesystem.
                let clone = clone_publication;
                if clone {
                    publication_clones.insert(role);
                }
                publication = publication
                    .checked_add(publication_stream_bytes(allocated, clone))
                    .ok_or_else(|| invalid("capture publication overflow"))?;
                disks.push(CaptureDiskPlan {
                    name: CaptureDiskName::new(name).map_err(invalid)?,
                    attachment_index: index as u32,
                    block_id: attachment.block_id.clone(),
                    length: metadata.len(),
                    tracking_eligible: !external_writable,
                    baseline_map: storage.disk_baselines.iter().find(|baseline| {
                        !external_writable && matches!(baseline.state, crate::store::models::storage::DiskBaselineState::Running { run_id, seeded: true } if run_id == request.run_id)
                            && baseline.storage_generation == storage.storage_generation
                            && baseline.seed.attachment_index == index as u32
                            && baseline.seed.block_id == attachment.block_id
                            && baseline.seed.file_device == metadata.dev()
                            && baseline.seed.file_inode == metadata.ino()
                            && baseline.seed.length == metadata.len()
                    }).map(|baseline| crate::machine::root_storage::baseline_map_path(
                        &vm_spec::capture::Sha256Digest::from_bytes(*baseline.map.as_bytes()))
                        .map(|path| machine.path().join(path.as_path()).to_string_lossy().into_owned()))
                        .transpose()?,
                    copy: CaptureDiskCopy::Copy,
                });
            }
        }
        if local_fork && machine_stat.st_dev == images_stat.st_dev {
            // A local cut is renamed into the operation namespace. No durable
            // stream/object publication or second RAM materialization occurs.
            publication = 0;
        }
        let reservation_bytes = stage
            .checked_add(publication)
            .ok_or_else(|| invalid("capture peak overflow"))?;
        let ram = request.configuration.ram_bytes();
        let plan = CapturePlan {
            map_node_store: Some(
                self.store
                    .images_dir
                    .join("objects/sha256")
                    .to_string_lossy()
                    .into_owned(),
            ),
            version: vm_spec::capture::CAPTURE_RECORD_VERSION,
            machine_id: LiveId::parse(&Uuid::from(request.machine_id).to_string())
                .map_err(invalid)?,
            run_id: LiveId::parse(&request.run_id.to_string()).map_err(invalid)?,
            capture_id: LiveId::parse(&request.capture_id.to_string()).map_err(invalid)?,
            configuration: request.configuration.clone(),
            configuration_digest: request.configuration.digest().map_err(invalid)?,
            policy: request.policy,
            dirty_crossover_percent: request.dirty_crossover_percent,
            resume_policy: request.resume_policy,
            pause: request.pause.clone(),
            ram_bytes: ram,
            disks,
            read_only_inputs,
            reservation: vm_spec::capture::CaptureReservation {
                storage_operation_id: LiveId::parse(&request.capture_id.to_string())
                    .map_err(invalid)?,
                launch_lease: CaptureLaunchLease {
                    operation_id: LiveId::parse(&launch.operation_id.to_string())
                        .map_err(invalid)?,
                    device,
                    inode,
                },
                staging_bytes: stage,
            },
        };
        plan.validate().map_err(invalid)?;
        let configuration = crate::machine::stopped::SnapshotConfiguration::capture(&config)?;
        let mut disk_charges = vec![CaptureSpaceCharge {
            device: machine_stat.st_dev as u64,
            bytes: stage,
        }];
        if machine_stat.st_dev == images_stat.st_dev {
            disk_charges
                .first_mut()
                .ok_or_else(|| invalid("capture staging charge is missing"))?
                .bytes = reservation_bytes;
        } else {
            disk_charges.push(CaptureSpaceCharge {
                device: images_stat.st_dev as u64,
                bytes: publication,
            });
        }
        let mut record = CaptureRecord {
            capture_id: request.capture_id,
            fork_operation_id,
            machine_id: request.machine_id,
            run_id: request.run_id,
            launch_operation_id: launch.operation_id,
            alias: request.alias.clone(),
            request,
            plan,
            state: CaptureState::Reserved,
            source_outcome: None,
            naming_outcome: None,
            configuration,
            storage,
            disk_charges,
            publication_clones,
            disk_allocations,
            reservation_bytes,
            candidate: None,
            captured_boot: None,
            source_inodes,
            evidence: None,
            discard: None,
            dispatch_attempted: false,
        };
        // Keep exact native block identities in live content; only host paths are projected.
        record.configuration.spec.storage = Some(vm_spec::Storage {
            disks: launch
                .disks
                .iter()
                .enumerate()
                .map(|(order, launched)| {
                    let mut disk = launched.clone();
                    disk.path = format!("captured-disk-{order}").into();
                    disk
                })
                .collect(),
        });
        record.configuration.spec.hardware = Some(vm_spec::Hardware {
            cpus: Some(record.plan.configuration.cpus),
            memory: Some(record.plan.configuration.memory_mib),
            nested_virtualization: Some(record.plan.configuration.nested_virtualization),
            rosetta: Some(record.plan.configuration.rosetta),
        });
        if let Some(kernel) = record
            .configuration
            .spec
            .boot
            .as_mut()
            .and_then(|boot| boot.kernel.as_mut())
        {
            kernel.cmdline = record.plan.configuration.kernel_cmdline.clone();
        }
        let lease = pool.lease(record.capture_id)?;
        self.store
            .reserve_capture_inventory(&record, Some(&lease))
            .await?;
        let tmp = images
            .open_dir("tmp")?
            .ok_or_else(|| invalid("pool staging directory is missing"))?;
        tmp.ensure_dir(&record.capture_id.to_string())?;
        tmp.sync()?;
        Ok(CaptureReservation {
            record,
            _lease: lease,
        })
    }

    pub(crate) async fn capture_reservation(
        &self,
        capture: Uuid,
    ) -> Result<Option<CaptureRecord>, LibVmError> {
        let json = sqlx::query_scalar::<_, String>("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(capture.to_string()).fetch_optional(&self.store.pool).await?;
        let record = json.as_deref().map(decode_record).transpose()?;
        if record
            .as_ref()
            .is_some_and(|record| record.capture_id != capture)
        {
            return Err(invalid("capture operation index contradiction"));
        }
        Ok(record)
    }

    pub(crate) async fn pending_captures(
        &self,
        machine: Option<MachineId>,
    ) -> Result<Vec<CaptureRecord>, LibVmError> {
        let mut cursor = String::new();
        let mut records = Vec::new();
        loop {
            let rows = sqlx::query("SELECT operation_id,CASE WHEN json_valid(record_json,8) THEN json(record_json) ELSE '{}' END AS record_json FROM storage_operation WHERE kind='capture' AND state='staging' AND operation_id>?1 AND (?2 IS NULL OR machine_id=?2) ORDER BY operation_id LIMIT 256").bind(&cursor).bind(machine.map(|id| id.to_string())).fetch_all(&self.store.pool).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.try_get("operation_id")?;
                let record = match decode_record(&row.try_get::<String, _>("record_json")?) {
                    Ok(record) => record,
                    Err(error) => {
                        tracing::warn!(capture = %cursor, %error, "corrupt capture retained; unrelated captures can reconcile");
                        continue;
                    }
                };
                if record.capture_id.to_string() != cursor {
                    tracing::warn!(capture = %cursor, "capture operation index contradicts its retained plan");
                    continue;
                }
                if !matches!(
                    record.state,
                    CaptureState::Released { .. }
                        | CaptureState::ReleasedLocal { .. }
                        | CaptureState::Abandoned
                ) {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    pub(crate) async fn bind_capture_boot(
        &self,
        capture: Uuid,
        boot: BootProfile,
    ) -> Result<(), LibVmError> {
        boot.validate()?;
        if !matches!(
            boot,
            BootProfile::LinuxDirect {
                binding: BootBinding::Pinned { .. },
                ..
            }
        ) {
            return Err(invalid("capture requires a pinned exact boot closure"));
        }
        self.update_capture(capture, move |record| {
            if let Some(existing) = &record.captured_boot {
                if existing != &boot {
                    return Err(invalid("capture boot binding is immutable"));
                }
            } else if record.state != CaptureState::Reserved {
                return Err(invalid("capture boot binding must precede submission"));
            }
            record.captured_boot = Some(boot);
            Ok(())
        })
        .await?;
        self.store.refine_capture_boot_inventory(capture).await
    }

    pub(crate) async fn record_capture_source(
        &self,
        capture: Uuid,
        source: CaptureSourceOutcome,
    ) -> Result<(), LibVmError> {
        self.update_capture(capture, move |record| {
            match &source {
                CaptureSourceOutcome::Known { record: outcome } => {
                    outcome.validate().map_err(invalid)?;
                    let evidence = record.evidence.as_deref().map(|bytes| CaptureEvidence::decode(bytes.as_bytes())).transpose().map_err(invalid)?;
                    if let Some(evidence) = evidence { outcome.validate_against(&evidence).map_err(invalid)?; }
                    if Uuid::parse_str(outcome.capture_id.as_str()).map_err(invalid)? != record.capture_id
                        || Uuid::parse_str(outcome.machine_id.as_str()).map_err(invalid)? != Uuid::from(record.machine_id)
                        || Uuid::parse_str(outcome.run_id.as_str()).map_err(invalid)? != record.run_id {
                        return Err(invalid("capture source record belongs to another operation"));
                    }
                    if outcome.source_outcome == vm_spec::capture::CaptureSourceOutcome::Resumed
                        && (record.plan.resume_policy != vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired || !matches!(record.plan.pause, vm_spec::capture::CapturePauseAuthority::Acquire)) {
                        return Err(invalid("capture source resumed contrary to its pause ownership policy"));
                    }
                }
                CaptureSourceOutcome::Observed { continuation } => {
                    continuation.validate().map_err(invalid)?;
                    if !continuation.is_terminal() { return Err(invalid("only terminal source continuation can be persisted")); }
                    let token = match continuation {
                        vm_spec::capture::CaptureContinuation::Resumed { consumed_token, .. } => {
                            if record.plan.resume_policy != vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired || !matches!(record.plan.pause, vm_spec::capture::CapturePauseAuthority::Acquire) {
                                return Err(invalid("capture observation resumed a preserved or borrowed pause"));
                            }
                            Some(consumed_token)
                        }
                        vm_spec::capture::CaptureContinuation::Preserved { preserved } => Some(&preserved.token),
                        vm_spec::capture::CaptureContinuation::Unchanged if record.evidence.is_some() => return Err(invalid("a sealed capture cannot have unchanged source continuation")),
                        _ => None,
                    };
                    if token.is_some_and(|token| token.machine_id != record.plan.machine_id || token.run_id != record.plan.run_id) {
                        return Err(invalid("capture continuation belongs to another source generation"));
                    }
                }
                CaptureSourceOutcome::Unknown => {}
            }
            if let Some(existing) = &record.source_outcome {
                if existing != &source && !source_upgrade_matches(existing, &source) { return Err(invalid("capture source outcome is immutable or contradicts its durable observation")); }
            }
            record.source_outcome = Some(source);
            Ok(())
        }).await
    }

    pub(crate) async fn finish_capture_release(
        &self,
        capture: Uuid,
        baseline_retained: bool,
    ) -> Result<(), LibVmError> {
        self.update_capture(capture, move |record| {
            record.state = match record.state {
                CaptureState::Published { snapshot } => CaptureState::Released {
                    snapshot: Some(snapshot),
                },
                CaptureState::Abandoned if !baseline_retained => {
                    CaptureState::Released { snapshot: None }
                }
                CaptureState::Abandoned => CaptureState::Abandoned,
                CaptureState::Released { snapshot } => CaptureState::Released { snapshot },
                CaptureState::Local { cut } | CaptureState::ReleasedLocal { cut } => {
                    CaptureState::ReleasedLocal { cut }
                }
                _ => {
                    return Err(invalid(
                        "capture release requires publication or explicit abandonment",
                    ))
                }
            };
            Ok(())
        })
        .await?;
        self.store.release_unused_capture_inventory(capture).await
    }

    /// Caller must first reconcile no submission or positively ended generation.
    /// A surviving coherent seal can never be discarded by abandonment.
    pub(crate) async fn abandon_capture(&self, capture: Uuid) -> Result<(), LibVmError> {
        let record = self
            .capture_reservation(capture)
            .await?
            .ok_or_else(|| invalid("capture reservation is missing"))?;
        if let Some(directory) = capture_directory(&self.store, &record)? {
            if let Some(bytes) = read_optional(
                &directory,
                vm_spec::capture::CAPTURE_EVIDENCE_FILE,
                vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
            )? {
                let evidence = CaptureEvidence::decode(&bytes).map_err(invalid)?;
                if evidence.is_sealed() {
                    return Err(invalid(
                        "coherent sealed capture must be published, never abandoned",
                    ));
                }
            }
        }
        let intent = self
            .store
            .live_command_record(record.machine_id, record.run_id, capture)
            .await?;
        let no_submission =
            record.never_submitted(intent.as_ref().and_then(|intent| intent.result.as_ref()));
        let source_exists = self
            .store
            .machine_config(record.machine_id)
            .await?
            .is_some();
        let source = if no_submission && source_exists {
            CaptureSourceOutcome::Observed {
                continuation: vm_spec::capture::CaptureContinuation::Unchanged,
            }
        } else {
            CaptureSourceOutcome::Unknown
        };
        self.update_capture(capture, move |record| {
            if record.evidence.is_some()
                || !matches!(
                    record.state,
                    CaptureState::Reserved | CaptureState::Abandoned
                )
            {
                return Err(invalid("sealed capture cannot be abandoned"));
            }
            record.state = CaptureState::Abandoned;
            if record.source_outcome.is_none() {
                record.source_outcome = Some(source);
            }
            Ok(())
        })
        .await?;
        self.store.release_unused_capture_inventory(capture).await
    }

    pub(crate) async fn machine_capture_retained(
        &self,
        machine: MachineId,
    ) -> Result<bool, LibVmError> {
        let this = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || runtime.block_on(async {
            let pool = StoragePool::open(&this.store.images_dir)?;
            let _roots = pool.lock_roots()?;
            let rows = sqlx::query_scalar::<_, String>("SELECT json(record_json) FROM storage_operation WHERE kind='capture' AND machine_id=?1")
                .bind(machine.to_string()).fetch_all(&this.store.pool).await?;
            for json in rows {
                let capture = decode_record(&json)?;
                if !matches!(capture.state, CaptureState::Released { .. } | CaptureState::ReleasedLocal { .. } | CaptureState::Abandoned) { return Ok(true); }
                let Some(own) = pool.try_exclusive_lease(capture.capture_id)? else { return Ok(true); };
                let Some(launch) = pool.try_exclusive_lease(capture.launch_operation_id)? else { return Ok(true); };
                check_lease(&this.store, &pool, capture.capture_id, &own).await?;
                if launch.file_identity()? != (capture.plan.reservation.launch_lease.device, capture.plan.reservation.launch_lease.inode) { return Err(invalid("capture launch lease inode changed")); }
            }
            Ok(false)
        })).await?
    }

    pub(crate) async fn update_capture<F>(&self, capture: Uuid, update: F) -> Result<(), LibVmError>
    where
        F: FnOnce(&mut CaptureRecord) -> Result<(), LibVmError> + Send + 'static,
    {
        let this = self.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                let pool = StoragePool::open(&this.store.images_dir)?;
                let _roots = pool.lock_roots()?;
                let mut tx = this.store.pool.begin_with("BEGIN IMMEDIATE").await?;
                update_capture_in_transaction(&mut tx, capture, update).await?;
                tx.commit().await?;
                Ok(())
            })
        })
        .await?
    }

    pub(crate) async fn publish_capture(
        &self,
        capture: Uuid,
        staging_dir: &Path,
        name: Option<String>,
        lock_policy: PublicationLockPolicy,
    ) -> Result<SnapshotInfo, LibVmError> {
        let this = self.clone();
        let staging = staging_dir.to_path_buf();
        let runtime = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            runtime.block_on(this.publish_capture_owned(capture, &staging, name, lock_policy))
        })
        .await?;
        match result {
            Err(LibVmError::Storage(StorageError::Io(error)))
                if error.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32)
                    || matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Unsupported
                    ) =>
            {
                Err(StorageError::CapturePublicationDeferred {
                    capture,
                    reason: format!("filesystem {}: {error}", self.store.images_dir.display()),
                }
                .into())
            }
            result => result,
        }
    }

    async fn publish_capture_owned(
        &self,
        capture: Uuid,
        staging_dir: &Path,
        name: Option<String>,
        lock_policy: PublicationLockPolicy,
    ) -> Result<SnapshotInfo, LibVmError> {
        let pool = StoragePool::open(&self.store.images_dir)?
            .defer_publications()
            .with_publication_lock_policy(lock_policy);
        let _publisher = pool.lock_publication(&capture_publication_key(capture))?;
        let record = self
            .capture_reservation(capture)
            .await?
            .ok_or_else(|| invalid("capture reservation is missing"))?;
        if record.alias != name {
            return Err(invalid(
                "capture publication alias differs from durable intent",
            ));
        }
        let expected = crate::paths::machine_data_dir_in(self.store.home_path(), record.machine_id)
            .join(record.plan.directory());
        if staging_dir != expected {
            return Err(invalid(
                "capture publication staging differs from registered relative location",
            ));
        }
        if let CaptureState::Published { snapshot }
        | CaptureState::Released {
            snapshot: Some(snapshot),
        } = record.state
        {
            self.store.checkpoint_catalog().await?;
            return self.inspect(&SnapshotRef::Id(snapshot)).await;
        }
        if matches!(
            record.state,
            CaptureState::Abandoned | CaptureState::Released { .. }
        ) || record.discard.is_some()
        {
            return Err(invalid("abandoned capture cannot publish"));
        }
        // The per-capture publisher owns all copying, not merely final insertion.
        let lease = pool.existing_lease(capture)?;
        check_lease(&self.store, &pool, capture, &lease).await?;
        #[cfg(test)]
        if let Some(hook) = &self.store.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::Preparing)?;
        }
        let directory = capture_directory(&self.store, &record)?
            .ok_or_else(|| invalid("capture staging is missing"))?;
        settle_capture_seal(&directory)?;
        // Sealed is persisted before the first pool publication. A replay must
        // authenticate staging again instead of trusting prior clone provenance.
        let authentication = if record.state == CaptureState::Reserved {
            CaptureAuthentication::Publication
        } else {
            CaptureAuthentication::Bytes
        };
        let mut verified = verify_capture(&directory, &record, authentication)?;
        let mut publication = 2 * vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        publication = publication
            .checked_add(staged_node_charge(&directory, true)?)
            .ok_or_else(|| invalid("capture node publication budget overflow"))?;
        let mut publication_clones = BTreeSet::new();
        let source_device = nix::sys::stat::fstat(directory.fd())
            .map_err(std::io::Error::from)?
            .st_dev as u64;
        let mut clone_publication = None;
        for payload in &verified.files {
            match payload.role {
                CaptureRole::Ram | CaptureRole::Disk(_) => {
                    let map = match &payload.role {
                        CaptureRole::Ram => &verified.ram_map,
                        _ => match &payload.bytes {
                            VerifiedBytes::Stream(stream) => stream.map(),
                            _ => return Err(invalid("sealed disk has no canonical map")),
                        },
                    };
                    let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)")
                        .bind(capture.to_string()).bind(map.id().to_string()).fetch_one(&self.store.pool).await?;
                    if pinned && pool.stream_path(&map.id()).try_exists()? {
                        if pool.verify_stream(&map.id())? != *map {
                            return Err(invalid(
                                "pinned publication stream differs from sealed map",
                            ));
                        }
                        continue;
                    }
                    let metadata = payload.file().metadata()?;
                    let clone = metadata.dev() == source_device
                        && *clone_publication.get_or_insert_with(|| {
                            pool.qualify_capture_clone(&directory).unwrap_or(false)
                        });
                    if clone {
                        publication_clones.insert(payload.role.relative_path());
                    }
                    let bound = if payload.role == CaptureRole::Ram {
                        record.plan.ram_bytes
                    } else {
                        metadata
                            .blocks()
                            .checked_mul(512)
                            .ok_or_else(|| invalid("publication allocation overflow"))?
                    };
                    publication = publication
                        .checked_add(publication_stream_bytes(bound, clone))
                        .ok_or_else(|| invalid("publication budget overflow"))?;
                }
                CaptureRole::RamMap | CaptureRole::DiskMap(_) => {
                    publication = publication
                        .checked_add(MAP_NODE_RESERVE_BYTES)
                        .ok_or_else(|| invalid("publication map budget overflow"))?;
                }
                CaptureRole::RamChanges => {
                    publication = publication
                        .checked_add(payload.length)
                        .ok_or_else(|| invalid("RAM changes publication overflow"))?;
                }
                _ => {}
            }
        }
        let boot = record
            .captured_boot
            .clone()
            .ok_or_else(|| invalid("capture has no retained exact boot closure"))?;
        let evidence_bytes = String::from_utf8(verified.evidence_bytes.clone()).map_err(invalid)?;
        self.update_capture(capture, move |record| {
            if !matches!(record.state, CaptureState::Reserved | CaptureState::Sealed) {
                return Err(invalid(
                    "capture publication cannot regress its durable state",
                ));
            }
            if record
                .evidence
                .as_ref()
                .is_some_and(|existing| existing != &evidence_bytes)
            {
                return Err(invalid("capture seal changed after authentication"));
            }
            record.evidence = Some(evidence_bytes);
            record.state = CaptureState::Sealed;
            Ok(())
        })
        .await?;
        self.store
            .reserve_capture_publication(&record, publication)
            .await?;
        verified.admit_maps(&self.store, capture).await?;
        verified.retain_disk_baselines(
            &crate::paths::machine_data_dir_in(self.store.home_path(), record.machine_id),
            &record.plan,
        )?;
        let mut streams = BTreeMap::new();
        let mut objects = BTreeMap::new();
        for payload in &verified.files {
            payload.recheck()?;
            match payload.role {
                CaptureRole::Ram | CaptureRole::Disk(_) => {
                    let map = match &payload.role {
                        CaptureRole::Ram => &verified.ram_map,
                        _ => match &payload.bytes {
                            VerifiedBytes::Stream(stream) => stream.map(),
                            _ => return Err(invalid("sealed disk has no canonical map")),
                        },
                    };
                    let receipt = match std::fs::symlink_metadata(pool.stream_path(&map.id())) {
                        Ok(metadata) => {
                            let fingerprint = SourceFingerprint::new(&metadata);
                            let [dev, ino, len, mode, ctime_sec, ctime_nsec] =
                                fingerprint.verification_key();
                            let matches: bool = sqlx::query_scalar(
                                "SELECT EXISTS(SELECT 1 FROM verified_object WHERE stream_sha256=?1 AND dev=?2 AND ino=?3 AND len=?4 AND mode=?5 AND ctime_sec=?6 AND ctime_nsec=?7)",
                            )
                            .bind(map.id().to_string()).bind(dev).bind(ino).bind(len).bind(mode)
                            .bind(ctime_sec).bind(ctime_nsec).fetch_one(&self.store.pool).await?;
                            matches.then_some(fingerprint)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    };
                    let (publication, roots) = pool.publish_admitted_stream_for_catalog(
                        payload.file(),
                        map,
                        receipt,
                        if publication_clones.contains(&payload.role.relative_path()) {
                            SealedStreamPublicationMode::CloneRequired
                        } else {
                            SealedStreamPublicationMode::CopyAllowed
                        },
                    )?;
                    let id = publication.map().id();
                    tracing::debug!(
                        bytes_read = publication.scan_stats().bytes_read,
                        logical_bytes_hashed = publication.scan_stats().logical_bytes_hashed,
                        role = ?payload.role,
                        "published sealed stream"
                    );
                    self.store
                        .pin_published_storage_dependencies(capture, &[id], &[])
                        .await?;
                    drop(roots);
                    let content = crate::store::snapshot_store::publish_map(
                        &pool,
                        &self.store,
                        capture,
                        publication.map(),
                    )
                    .await?;
                    streams.insert(payload.role.relative_path(), content);
                    if authentication == CaptureAuthentication::Publication {
                        verified.publications.insert(id, publication);
                    }
                }
                CaptureRole::Execution
                | CaptureRole::Devices
                | CaptureRole::Layout
                | CaptureRole::RamChanges => {
                    let (published, roots) = pool.publish_object_file_for_catalog(
                        payload.file().try_clone()?,
                        &directory.path().join(payload.role.relative_path()),
                    )?;
                    self.store
                        .pin_published_storage_dependencies(capture, &[], &[published.digest])
                        .await?;
                    drop(roots);
                    objects.insert(payload.role.relative_path(), published.digest);
                }
                CaptureRole::RamMap | CaptureRole::DiskMap(_) => {}
            }
            payload.recheck()?;
        }
        // Exact evidence bytes are retained separately from content identity.
        let evidence_input = new_input(&self.store, capture, "evidence", &verified.evidence_bytes)?;
        let (evidence, roots) = pool.publish_object_for_catalog(&evidence_input)?;
        self.store
            .pin_published_storage_dependencies(capture, &[], &[evidence.digest])
            .await?;
        drop(roots);
        let mut immutable = BTreeMap::new();
        let mut lower_graph = None;
        for input in &record.plan.read_only_inputs {
            let attachment = record
                .plan
                .configuration
                .attachments
                .get(input.attachment_index as usize)
                .ok_or_else(|| invalid("read-only input attachment is absent"))?;
            if attachment.role == vm_spec::DiskRole::RootLower {
                lower_graph = Some(
                    self.capture_lower_graph(capture, &record, input, attachment, &boot)
                        .await?,
                );
                continue;
            }
            let stream: crate::storage::identity::StreamId =
                input.identity.parse().map_err(invalid)?;
            let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)")
                .bind(capture.to_string()).bind(input.identity.clone()).fetch_one(&self.store.pool).await?;
            if !pinned {
                return Err(invalid(
                    "read-only capture input was not pinned before access",
                ));
            }
            let content = crate::store::models::snapshot::SnapshotStream {
                stream,
                map: ObjectDigest::from_sha256(*stream.as_bytes()),
                length: attachment.geometry.length,
                chunk_size: vm_spec::stream_map::ChunkSize::DISK.bytes(),
            };
            let authenticated = self
                .store
                .authenticate_local_stream(capture, &content)
                .await?;
            let map = authenticated.map();
            if map.length() != attachment.geometry.length {
                return Err(invalid("read-only input geometry changed"));
            }
            immutable.insert(
                input.attachment_index,
                crate::store::snapshot_store::publish_map(&pool, &self.store, capture, map).await?,
            );
        }
        let root_index = if matches!(record.storage.root, MachineRoot::LinuxOverlay { .. }) {
            1
        } else {
            0
        };
        let root_disk = record
            .plan
            .disks
            .iter()
            .find(|disk| disk.attachment_index == root_index)
            .ok_or_else(|| invalid("capture has no writable root role"))?;
        let root_stream = streams
            .remove(&CaptureRole::Disk(root_disk.name.clone()).relative_path())
            .ok_or_else(|| invalid("capture root output is missing"))?;
        let (profile, layout, geometry) = match &record.storage.root {
            MachineRoot::OpaqueRaw {
                geometry, layout, ..
            } => (SnapshotRootProfile::OpaqueRaw, layout.clone(), *geometry),
            MachineRoot::LinuxOverlay {
                lower: root_lower,
                upper_uuid,
                ext4_profile,
                overlay_profile,
                temporary_directory,
                capacity,
                ..
            } => {
                let lower = lower_graph
                    .take()
                    .ok_or_else(|| invalid("overlay lower input is missing"))?;
                (
                    SnapshotRootProfile::LinuxOverlay {
                        lower: Box::new(lower),
                        lower_geometry: root_lower.geometry(),
                        lower_filesystem_uuid: root_lower.filesystem_uuid(),
                        upper_uuid: *upper_uuid,
                        ext4_profile: *ext4_profile,
                        overlay_profile: *overlay_profile,
                        temporary_directory: *temporary_directory,
                    },
                    RawLayout::WholeDisk,
                    vm_spec::DiskGeometry {
                        length: *capacity,
                        logical_sector_size: 512,
                    },
                )
            }
        };
        let mut disks = Vec::new();
        for (order, attachment) in record
            .plan
            .configuration
            .attachments
            .iter()
            .enumerate()
            .filter(|(_, attachment)| attachment.role == vm_spec::DiskRole::Data)
        {
            let content = if attachment.read_only {
                immutable
                    .remove(&(order as u32))
                    .ok_or_else(|| invalid("read-only data disk closure is missing"))?
            } else {
                let disk = record
                    .plan
                    .disks
                    .iter()
                    .find(|disk| disk.attachment_index as usize == order)
                    .ok_or_else(|| invalid("captured data disk plan is missing"))?;
                streams
                    .remove(&CaptureRole::Disk(disk.name.clone()).relative_path())
                    .ok_or_else(|| invalid("captured data disk output is missing"))?
            };
            disks.push(SnapshotDisk {
                role: attachment.role,
                order: order as u32,
                writable: !attachment.read_only,
                content,
                geometry: attachment.geometry,
            });
        }
        let memory = streams
            .remove(&CaptureRole::Ram.relative_path())
            .ok_or_else(|| invalid("capture RAM stream is missing"))?;
        let memory_evidence = verified
            .evidence
            .memory
            .as_ref()
            .ok_or_else(|| invalid("capture RAM evidence is missing"))?;
        if memory.stream.as_bytes() != memory_evidence.ram_stream.as_bytes() {
            return Err(invalid("capture RAM canonical identity mismatch"));
        }
        if !streams.is_empty() || !immutable.is_empty() || lower_graph.is_some() {
            return Err(invalid("capture has unconsumed stream roles"));
        }
        let take = |role: CaptureRole| {
            objects
                .get(&role.relative_path())
                .copied()
                .ok_or_else(|| invalid("capture state object is missing"))
        };
        let snapshot = SnapshotRecord {
            schema: 2,
            kind: SnapshotKind::Snapshot,
            purpose: SnapshotPurpose::Checkpoint,
            capture: SnapshotCaptureKind::LiveExecution {
                execution: Box::new(SnapshotExecution {
                    memory,
                    layout: take(CaptureRole::Layout)?,
                    execution: take(CaptureRole::Execution)?,
                    devices: take(CaptureRole::Devices)?,
                    compatibility_profile: SnapshotCompatibilityProfile {
                        live_state_schema: memory_evidence.binding.live_state_schema.clone(),
                        architecture: memory_evidence.binding.architecture.clone(),
                        profile: ObjectDigest::from_sha256(
                            *memory_evidence.binding.profile.as_bytes(),
                        ),
                        topology: ObjectDigest::from_sha256(
                            *memory_evidence.binding.topology.as_bytes(),
                        ),
                        ram_layout: ObjectDigest::from_sha256(
                            *memory_evidence.binding.ram_layout.as_bytes(),
                        ),
                    },
                }),
            },
            root: SnapshotRoot {
                profile,
                stream: root_stream,
                geometry,
                layout,
            },
            disks,
            platform_files: Vec::new(),
            configuration: record.configuration.clone(),
            boot,
            external_requirements: Vec::new(),
        };
        snapshot.validate()?;
        for file in &verified.files {
            file.recheck()?;
        }
        verified.recheck_directory(&directory)?;
        let current = capture_directory(&self.store, &record)?
            .ok_or_else(|| invalid("capture directory disappeared before publication"))?;
        verified.recheck_directory(&current)?;
        #[cfg(test)]
        if let Some(hook) = &self.store.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::AfterObject)?;
        }
        let result = self
            .publish_authenticated(
                &snapshot,
                capture,
                name.as_deref(),
                Some(&verified),
                lock_policy,
            )
            .await?;
        self.store.complete_capture_peak(&record).await?;
        drop(lease);
        Ok(result)
    }
}

impl SnapshotStore {
    /// The exact retained graph of a capture's layered lower. The capture
    /// inherited the launch's lower pin; the graph's objects and pack streams
    /// (already rooted by that composition) are pinned to the capture so its
    /// publication closure is complete. No pack byte is read.
    async fn capture_lower_graph(
        &self,
        capture: Uuid,
        record: &CaptureRecord,
        input: &CaptureReadOnlyInput,
        attachment: &vm_spec::capture::CaptureAttachment,
        boot: &BootProfile,
    ) -> Result<crate::store::models::snapshot::SnapshotComposition, LibVmError> {
        let MachineRoot::LinuxOverlay {
            lower: root_lower, ..
        } = &record.storage.root
        else {
            return Err(invalid("captured lower input has no layered root"));
        };
        let lower: crate::storage::identity::LowerResultId =
            input.identity.parse().map_err(invalid)?;
        if input.attachment_index != 0
            || lower != root_lower.record()
            || attachment.geometry.length != root_lower.geometry().length
        {
            return Err(invalid(
                "captured lower input differs from its retained root identity",
            ));
        }
        let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_lower WHERE operation_id=?1 AND lower_id=?2)")
            .bind(capture.to_string()).bind(lower.to_string()).fetch_one(&self.store.pool).await?;
        if !pinned {
            return Err(invalid("captured lower was not pinned before access"));
        }
        let layers = crate::store::layer_store::LayerStore::from_store((*self.store).clone());
        let retained = layers.retained_composition(lower).await?;
        retained.check_lower(root_lower)?;
        crate::machine::root_storage::check_lower_platform(&retained.recipe.platform, boot)?;
        let graph = layers.snapshot_composition(lower).await?;
        if graph.result != lower || graph.record != retained.record_digest {
            return Err(invalid(
                "captured lower graph differs from its retained result",
            ));
        }
        let mut streams = Vec::with_capacity(graph.layers.len());
        let mut objects = graph.objects().collect::<Vec<_>>();
        for layer in &graph.layers {
            streams.push(layer.pack.stream);
            objects.push(layer.pack.map);
        }
        self.store
            .pin_published_storage_dependencies(capture, &streams, &objects)
            .await?;
        Ok(graph)
    }
}

pub(crate) fn decode_record(json: &str) -> Result<CaptureRecord, LibVmError> {
    if json.len() > 2 * vm_spec::capture::MAX_CAPTURE_RECORD_BYTES + (4 << 20) {
        return Err(invalid(
            "capture catalog record exceeds its control-record bound",
        ));
    }
    let record: CaptureRecord = serde_json::from_str(json).map_err(invalid)?;
    record.plan.validate().map_err(invalid)?;
    record
        .storage
        .validate_for_machine(record.machine_id.into())?;
    let maps = capture_map_budget(&record.plan.configuration)?;
    let changes = record
        .plan
        .ram_bytes
        .div_ceil(vm_spec::stream_map::ChunkSize::RAM.bytes())
        .checked_mul(56)
        .and_then(|bytes| bytes.checked_add(16))
        .ok_or_else(|| invalid("RAM changes budget overflow"))?;
    let expected_staging = record.disk_allocations.values().try_fold(
        record
            .plan
            .ram_bytes
            .checked_add(vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
            .and_then(|bytes| bytes.checked_add(maps))
            .and_then(|bytes| bytes.checked_add(changes))
            .ok_or_else(|| invalid("capture staging overflow"))?,
        |bytes, allocated| {
            bytes
                .checked_add(*allocated)
                .ok_or_else(|| invalid("capture staging overflow"))
        },
    )?;
    let expected_publication =
        if record.fork_operation_id.is_some() && record.disk_charges.len() == 1 {
            0
        } else {
            let maps = capture_map_budget(&record.plan.configuration)?;
            let mut bytes = publication_stream_bytes(
                record.plan.ram_bytes,
                record
                    .publication_clones
                    .contains(&CaptureRole::Ram.relative_path()),
            )
            .checked_add(2 * vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
            .and_then(|bytes| bytes.checked_add(2 * maps))
            .and_then(|bytes| bytes.checked_add(changes))
            .ok_or_else(|| invalid("capture publication overflow"))?;
            for disk in &record.plan.disks {
                let allocated = record
                    .disk_allocations
                    .get(&disk.attachment_index)
                    .ok_or_else(|| invalid("capture disk allocation is missing"))?;
                bytes = bytes
                    .checked_add(publication_stream_bytes(
                        *allocated,
                        record
                            .publication_clones
                            .contains(&CaptureRole::Disk(disk.name.clone()).relative_path()),
                    ))
                    .ok_or_else(|| invalid("capture publication overflow"))?;
            }
            bytes
        };
    if let Some(operation) = record.fork_operation_id {
        if operation.is_nil() || operation == record.capture_id {
            return Err(invalid("capture fork operation identity is invalid"));
        }
    }
    if record.request.configuration != record.plan.configuration
        || record.request.policy != record.plan.policy
        || record.request.resume_policy != record.plan.resume_policy
        || record.request.pause != record.plan.pause
        || record.disk_allocations.len() != record.plan.disks.len()
        || record
            .plan
            .disks
            .iter()
            .any(|disk| !record.disk_allocations.contains_key(&disk.attachment_index))
        || record.plan.reservation.staging_bytes != expected_staging
        || record.disk_charges.is_empty()
        || record.disk_charges.len() > 2
        || record
            .disk_charges
            .iter()
            .map(|charge| charge.device)
            .collect::<BTreeSet<_>>()
            .len()
            != record.disk_charges.len()
        || record
            .disk_charges
            .iter()
            .try_fold(0u64, |total, charge| total.checked_add(charge.bytes))
            != Some(record.reservation_bytes)
        || record.reservation_bytes < record.plan.reservation.staging_bytes
        || expected_staging.checked_add(expected_publication) != Some(record.reservation_bytes)
        || record.publication_clones.iter().any(|role| {
            let disk = role
                .strip_prefix("disks/")
                .and_then(|name| name.strip_suffix(".raw"));
            role != vm_spec::capture::CAPTURE_RAM_FILE
                && !record
                    .plan
                    .disks
                    .iter()
                    .any(|planned| disk == Some(planned.name.as_str()))
        })
    {
        return Err(invalid(
            "capture reservation charges or immutable request contradict the plan",
        ));
    }
    if let Some(boot) = &record.captured_boot {
        boot.validate()?;
    }
    match &record.state {
        CaptureState::Reserved
        | CaptureState::Abandoned
        | CaptureState::Released { snapshot: None }
            if record.evidence.is_some() || record.candidate.is_some() =>
        {
            return Err(invalid(
                "unsealed capture state contains a sealed candidate",
            ))
        }
        CaptureState::Sealed
        | CaptureState::Local { .. }
        | CaptureState::ReleasedLocal { .. }
        | CaptureState::Published { .. }
        | CaptureState::Released { snapshot: Some(_) }
            if record.evidence.is_none() =>
        {
            return Err(invalid(
                "sealed capture state is missing its immutable evidence",
            ))
        }
        _ => {}
    }
    match record.state {
        CaptureState::Published { snapshot }
        | CaptureState::Released {
            snapshot: Some(snapshot),
        } if record.candidate != Some(snapshot) => {
            return Err(invalid(
                "capture publication identity contradicts its candidate",
            ))
        }
        _ => {}
    }
    if let Some(crate::store::snapshot_store::CaptureNamingOutcome::AliasConflict { alias }) =
        &record.naming_outcome
    {
        if record.alias.as_ref() != Some(alias)
            || !matches!(
                record.state,
                CaptureState::Published { .. } | CaptureState::Released { snapshot: Some(_) }
            )
        {
            return Err(invalid(
                "capture naming outcome contradicts publication intent",
            ));
        }
    }
    if let Some(bytes) = &record.evidence {
        let evidence = CaptureEvidence::decode(bytes.as_bytes()).map_err(invalid)?;
        evidence
            .validate_against_plan(
                &record.plan,
                &Sha256Digest::of_bytes(&record.plan.canonical_bytes().map_err(invalid)?),
            )
            .map_err(invalid)?;
        if !evidence.is_sealed() {
            return Err(invalid(
                "capture operation retained a diagnostic record as a seal",
            ));
        }
    }
    if record.capture_id.is_nil()
        || record.run_id.is_nil()
        || Uuid::parse_str(record.plan.capture_id.as_str()).map_err(invalid)? != record.capture_id
        || Uuid::parse_str(record.plan.machine_id.as_str()).map_err(invalid)?
            != Uuid::from(record.machine_id)
        || Uuid::parse_str(record.plan.run_id.as_str()).map_err(invalid)? != record.run_id
        || Uuid::parse_str(record.plan.reservation.storage_operation_id.as_str())
            .map_err(invalid)?
            != record.capture_id
        || Uuid::parse_str(record.plan.reservation.launch_lease.operation_id.as_str())
            .map_err(invalid)?
            != record.launch_operation_id
        || record.request.capture_id != record.capture_id
        || record.request.machine_id != record.machine_id
        || record.request.run_id != record.run_id
        || record.request.alias != record.alias
    {
        return Err(invalid("capture record identity contradiction"));
    }
    Ok(record)
}

pub(crate) fn capture_publication_key(capture: Uuid) -> ObjectDigest {
    let mut key = Sha256::new();
    key.update(b"silo:capture-publication:v1\0");
    key.update(capture.as_bytes());
    ObjectDigest::from_sha256(key.finalize().into())
}

pub(crate) fn encode_record(record: &CaptureRecord) -> Result<String, LibVmError> {
    let json = serde_json::to_string(record).map_err(invalid)?;
    decode_record(&json)?;
    Ok(json)
}
fn publication_stream_bytes(copy_bound: u64, clone_required: bool) -> u64 {
    if clone_required {
        vm_spec::capture::CAPTURE_CLONE_RESERVE_BYTES
    } else {
        copy_bound
    }
}

// Covers a rounded node object plus its catalog node and positional edge rows.
const MAP_NODE_RESERVE_BYTES: u64 = 8192;
const MAP_CATALOG_ROW_RESERVE_BYTES: u64 = 512;

fn capture_map_budget(
    configuration: &vm_spec::capture::CaptureConfiguration,
) -> Result<u64, LibVmError> {
    std::iter::once((
        configuration.ram_bytes(),
        vm_spec::stream_map::ChunkSize::RAM,
    ))
    .chain(
        configuration
            .attachments
            .iter()
            .map(|disk| (disk.geometry.length, vm_spec::stream_map::ChunkSize::DISK)),
    )
    .try_fold(0u64, |total, (length, profile)| {
        vm_spec::stream_map::worst_case_node_count(length, profile)
            .map_err(invalid)?
            .checked_add(1)
            .and_then(|nodes| nodes.checked_mul(MAP_NODE_RESERVE_BYTES))
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or_else(|| invalid("capture map budget overflow"))
    })
}

pub(crate) fn capture_descriptor_budget(
    configuration: &vm_spec::capture::CaptureConfiguration,
) -> Result<u64, LibVmError> {
    // Includes the changes file, root files, shared node batch and pool capability.
    (configuration.attachments.len() as u64)
        .checked_mul(3)
        .and_then(|descriptors| descriptors.checked_add(20))
        .ok_or_else(|| invalid("capture descriptor budget overflow"))
}

pub(crate) fn staged_node_bytes(directory: &OwnedDirectory) -> Result<u64, LibVmError> {
    staged_node_charge(directory, false)
}

fn staged_node_charge(directory: &OwnedDirectory, catalog: bool) -> Result<u64, LibVmError> {
    let Some(nodes) = directory.open_dir("map-nodes")? else {
        return Ok(0);
    };
    let mut entries = nix::dir::Dir::openat(
        nodes.fd(),
        ".",
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut total = 0u64;
    for entry in entries.iter() {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name().to_str().map_err(invalid)?;
        if name == "." || name == ".." {
            continue;
        }
        let file = nodes
            .open_file(name)?
            .ok_or_else(|| invalid("staged map node disappeared"))?;
        let metadata = file.metadata()?;
        let mut bytes = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| invalid("staged map allocation overflow"))?;
        if catalog {
            let length = usize::try_from(metadata.len()).map_err(invalid)?;
            let mut buffer = [0; vm_spec::stream_map::MAX_NODE_BYTES];
            let encoded = buffer
                .get_mut(..length)
                .ok_or_else(|| invalid("staged map node exceeds its format bound"))?;
            std::os::unix::fs::FileExt::read_exact_at(&file, encoded, 0)?;
            let height = if encoded.starts_with(b"silo:stream-map:leaf:v2\n") {
                0
            } else {
                *encoded
                    .get(26)
                    .ok_or_else(|| invalid("staged branch is truncated"))?
            };
            let node = vm_spec::stream_map::StreamNode::decode(encoded, height).map_err(invalid)?;
            let edges = if height == 0 {
                0
            } else {
                node.entries().count() as u64
            };
            bytes = edges
                .checked_add(1)
                .and_then(|rows| rows.checked_mul(MAP_CATALOG_ROW_RESERVE_BYTES))
                .and_then(|catalog| bytes.checked_add(catalog))
                .ok_or_else(|| invalid("map catalog allocation overflow"))?;
        }
        total = total
            .checked_add(bytes)
            .ok_or_else(|| invalid("staged map allocation overflow"))?;
    }
    Ok(total)
}

pub(crate) fn stage_map_nodes(
    directory: &OwnedDirectory,
    map: &crate::storage::map::AuthenticatedMap,
) -> Result<(), LibVmError> {
    let nodes = directory.ensure_dir_deferred("map-nodes")?;
    for node in map.nodes() {
        let node = node?;
        nodes.write_file(&node.digest.hex(), &node.bytes)?;
    }
    Ok(())
}

pub(crate) async fn register_capture(
    connection: &mut sqlx::SqliteConnection,
    record: &CaptureRecord,
    lease_device: u64,
    lease_inode: u64,
) -> Result<(), LibVmError> {
    if let Some(alias) = &record.alias {
        crate::store::managed_image_store::check_alias_available(connection, alias, None).await?;
    }
    let current: Option<String> =
        sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
            .bind(record.machine_id.to_string())
            .fetch_optional(&mut *connection)
            .await?;
    if current
        .as_deref()
        .map(crate::MachineStorageRecord::decode)
        .transpose()?
        .as_ref()
        != Some(&record.storage)
    {
        return Err(invalid(
            "capture source storage changed before reservation commit",
        ));
    }
    let launch_present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='launch' AND machine_id=?2 AND run_id=?3 AND state='prepared')")
        .bind(record.launch_operation_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_one(&mut *connection).await?;
    if !launch_present {
        return Err(invalid(
            "capture launch owner retired before reservation commit",
        ));
    }
    let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND machine_id=?1 AND run_id=?2 AND state='staging')")
        .bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_one(&mut *connection).await?;
    if busy {
        return Err(invalid("the source run already has an unresolved capture"));
    }
    sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,record_json) VALUES(?1,1,'capture','staging',?2,?3,?4,?5,?6,jsonb(?7))")
        .bind(record.capture_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).bind(i64::try_from(record.storage.storage_generation).map_err(invalid)?).bind(lease_device.to_string()).bind(lease_inode.to_string()).bind(encode_record(record)?).execute(&mut *connection).await?;
    for statement in [
        "INSERT INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2",
        "INSERT INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2",
        "INSERT INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2",
        "INSERT INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2",
    ] {
        sqlx::query(statement)
            .bind(record.capture_id.to_string()).bind(record.launch_operation_id.to_string()).execute(&mut *connection).await?;
    }
    sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) SELECT ?1,root_digest FROM storage_operation_memory_baseline WHERE operation_id=?2")
        .bind(record.capture_id.to_string()).bind(record.launch_operation_id.to_string())
        .execute(&mut *connection).await?;
    Ok(())
}

pub(crate) async fn write_record(
    connection: &mut sqlx::SqliteConnection,
    record: &CaptureRecord,
) -> Result<(), LibVmError> {
    let state = if matches!(
        record.state,
        CaptureState::Released { .. } | CaptureState::ReleasedLocal { .. }
    ) {
        "committed"
    } else if record.state == CaptureState::Abandoned {
        "aborted"
    } else {
        "staging"
    };
    let result = sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2),state=?3 WHERE operation_id=?1 AND kind='capture' AND state<>'cleaning'").bind(record.capture_id.to_string()).bind(encode_record(record)?).bind(state).execute(connection).await?;
    if result.rows_affected() != 1 {
        return Err(invalid("capture storage owner disappeared"));
    }
    Ok(())
}

async fn update_capture_in_transaction(
    connection: &mut sqlx::SqliteConnection,
    capture: Uuid,
    update: impl FnOnce(&mut CaptureRecord) -> Result<(), LibVmError>,
) -> Result<(), LibVmError> {
    let json: String = sqlx::query_scalar(
        "SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'",
    )
    .bind(capture.to_string())
    .fetch_one(&mut *connection)
    .await?;
    let mut record = decode_record(&json)?;
    update(&mut record)?;
    write_record(connection, &record).await?;
    if let Some(source) = &record.source_outcome {
        let parent: Option<(String, String)> = sqlx::query_as(
            "SELECT operation_id,json(result_json) FROM live_fork WHERE capture_id=?1",
        )
        .bind(capture.to_string())
        .fetch_optional(&mut *connection)
        .await?;
        if let Some((operation, json)) = parent {
            let mut result: crate::LiveForkResult = serde_json::from_str(&json).map_err(invalid)?;
            let mut outcome = crate::machine::live_fork::source_outcome(source);
            if record.evidence.is_none()
                && (matches!(outcome, crate::ForkSourceOutcome::Resumed)
                    || (matches!(outcome, crate::ForkSourceOutcome::Preserved)
                        && matches!(
                            record.plan.pause,
                            vm_spec::capture::CapturePauseAuthority::Borrow { .. }
                        )))
            {
                outcome = crate::ForkSourceOutcome::Unchanged;
            }
            result.source = outcome;
            sqlx::query("UPDATE live_fork SET result_json=jsonb(?2) WHERE operation_id=?1")
                .bind(&operation)
                .bind(serde_json::to_string(&result).map_err(invalid)?)
                .execute(&mut *connection)
                .await?;
            sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,phase,monotonic_ns) VALUES(?1,'source_settled',?2)")
                .bind(operation)
                .bind(crate::machine::live_fork::monotonic_ns()?)
                .execute(&mut *connection)
                .await?;
        }
    }
    Ok(())
}

async fn check_lease(
    store: &Store,
    pool: &StoragePool,
    operation: Uuid,
    lease: &crate::storage::locks::StorageLock,
) -> Result<(), LibVmError> {
    let row = sqlx::query("SELECT file_device,file_inode FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(operation.to_string()).fetch_one(&store.pool).await?;
    let expected = (
        row.try_get::<String, _>("file_device")?,
        row.try_get::<String, _>("file_inode")?,
    );
    let identity = lease.file_identity()?;
    if expected != (identity.0.to_string(), identity.1.to_string())
        || pool.operation_lease_identity(operation)? != identity
    {
        return Err(invalid("capture lease inode changed"));
    }
    Ok(())
}

fn open_machine(store: &Store, machine: MachineId) -> Result<OwnedDirectory, LibVmError> {
    let home = OwnedDirectory::open_existing_root(store.home_path())?
        .ok_or_else(|| invalid("home is missing"))?;
    let machines = home
        .open_dir("machines")?
        .ok_or_else(|| invalid("machine namespace is missing"))?;
    machines
        .open_dir(&machine.to_string())?
        .ok_or_else(|| invalid("capture source directory is missing"))
}

fn capture_directory(
    store: &Store,
    record: &CaptureRecord,
) -> Result<Option<OwnedDirectory>, LibVmError> {
    let machine = open_machine(store, record.machine_id)?;
    let Some(captures) = machine.open_dir(vm_spec::capture::CAPTURES_DIRECTORY)? else {
        return Ok(None);
    };
    captures.open_dir(&record.capture_id.to_string())
}

pub(crate) fn writable_path(
    storage: &crate::MachineStorageRecord,
    order: u32,
    role: vm_spec::DiskRole,
) -> Result<&Path, LibVmError> {
    match (&storage.root, role) {
        (MachineRoot::OpaqueRaw { path, .. }, vm_spec::DiskRole::Root) if order == 0 => {
            Ok(path.as_path())
        }
        (MachineRoot::LinuxOverlay { upper, .. }, vm_spec::DiskRole::RootUpper) if order == 1 => {
            Ok(upper.as_path())
        }
        (_, vm_spec::DiskRole::Data) => storage
            .disks
            .iter()
            .find_map(|disk| {
                if disk.order == order {
                    match &disk.storage {
                        DiskStorage::ManagedWritable { path, .. } => Some(path.as_path()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| invalid("writable attachment lacks managed private storage")),
        _ => Err(invalid(
            "writable attachment differs from managed root roles",
        )),
    }
}

/// The canonical identity a capture plan binds for one read-only attachment:
/// the retained composition `LowerResultId` of a layered lower, or the
/// managed stream of a read-only Data disk.
fn read_only_identity(
    storage: &crate::MachineStorageRecord,
    order: u32,
    role: vm_spec::DiskRole,
) -> Result<String, LibVmError> {
    match (&storage.root, role) {
        (MachineRoot::LinuxOverlay { lower, .. }, vm_spec::DiskRole::RootLower) if order == 0 => {
            Ok(lower.record().to_string())
        }
        (_, vm_spec::DiskRole::Data) => storage
            .disks
            .iter()
            .find_map(|disk| {
                if disk.order == order {
                    match &disk.storage {
                        DiskStorage::ManagedReadOnly { stream, .. } => Some(stream.to_string()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| invalid("read-only attachment lacks immutable managed identity")),
        _ => Err(invalid(
            "read-only attachment has no admitted immutable identity",
        )),
    }
}

fn open_relative(root: &OwnedDirectory, path: &Path) -> Result<File, LibVmError> {
    let mut directory = root.try_clone()?;
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid("capture role path is not relative and normal"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| invalid("capture role path is not UTF-8"))?;
        if components.peek().is_none() {
            return directory
                .open_file(name)?
                .ok_or_else(|| invalid("capture role file is missing"));
        }
        directory = directory
            .open_dir(name)?
            .ok_or_else(|| invalid("capture role parent is missing"))?;
    }
    Err(invalid("capture role path is empty"))
}

fn new_input(
    store: &Store,
    capture: Uuid,
    prefix: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, LibVmError> {
    let images = OwnedDirectory::open_existing_root(&store.images_dir)?
        .ok_or_else(|| invalid("pool root is missing"))?;
    let temporary = images
        .open_dir("tmp")?
        .ok_or_else(|| invalid("pool staging is missing"))?;
    let operation = temporary
        .open_dir(&capture.to_string())?
        .ok_or_else(|| invalid("capture operation staging is missing"))?;
    let name = format!("{prefix}-{}", Uuid::new_v4());
    operation.write_file(&name, bytes)?;
    Ok(operation.path().join(name))
}

fn source_upgrade_matches(existing: &CaptureSourceOutcome, source: &CaptureSourceOutcome) -> bool {
    let (CaptureSourceOutcome::Observed { continuation }, CaptureSourceOutcome::Known { record }) =
        (existing, source)
    else {
        return false;
    };
    match (continuation, record.source_outcome) {
        (
            vm_spec::capture::CaptureContinuation::Resumed { consumed_token, .. },
            vm_spec::capture::CaptureSourceOutcome::Resumed,
        ) => consumed_token == &record.pause_token,
        (
            vm_spec::capture::CaptureContinuation::Preserved { preserved },
            vm_spec::capture::CaptureSourceOutcome::Preserved,
        ) => record.current_pause.as_ref() == Some(&preserved.token),
        (
            vm_spec::capture::CaptureContinuation::ResumeFailed { .. },
            vm_spec::capture::CaptureSourceOutcome::ResumeFailed,
        ) => true,
        _ => false,
    }
}

/// Finish only the monitor's exact two-name seal publication window.
/// Callers hold the operation's publisher lock and checked capture lease.
/// Both opens retain OwnedDirectory's private regular-file ownership checks;
/// every verifier still requires a singleton after settlement.
fn settle_capture_seal(directory: &OwnedDirectory) -> Result<(), LibVmError> {
    use vm_spec::capture::{CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE};

    let Some(file) = directory.open_file(CAPTURE_EVIDENCE_FILE)? else {
        return Ok(());
    };
    let metadata = file.metadata()?;
    if metadata.nlink() == 1 {
        return Ok(());
    }
    if metadata.nlink() != 2 {
        return Err(invalid("capture seal has foreign links"));
    }
    let temporary = directory
        .open_file(CAPTURE_EVIDENCE_TEMPORARY_FILE)?
        .ok_or_else(|| invalid("capture seal's second link is not its owned temporary"))?;
    let temporary_metadata = temporary.metadata()?;
    if (metadata.dev(), metadata.ino()) != (temporary_metadata.dev(), temporary_metadata.ino())
        || temporary_metadata.nlink() != 2
    {
        return Err(invalid(
            "capture seal temporary does not hold its two-link inode",
        ));
    }
    match nix::unistd::unlinkat(
        directory.fd(),
        CAPTURE_EVIDENCE_TEMPORARY_FILE,
        nix::unistd::UnlinkatFlags::NoRemoveDir,
    ) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    if file.metadata()?.nlink() != 1 {
        return Err(invalid("capture seal did not settle to a single link"));
    }
    Ok(())
}

fn read_optional(
    directory: &OwnedDirectory,
    name: &str,
    maximum: u64,
) -> Result<Option<Vec<u8>>, LibVmError> {
    let Some(mut file) = directory.open_file(name)? else {
        return Ok(None);
    };
    if file.metadata()?.nlink() != 1 || file.metadata()?.len() > maximum {
        return Err(invalid(
            "capture control record exceeds bounds or aliases another name",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("capture control record grew past its bound"));
    }
    Ok(Some(bytes))
}

/// Each verification lane's reusable whole-digest read buffer.
const AUTHENTICATION_BUFFER_BYTES: usize = 1 << 20;
/// Explicit stack of the one extra verification thread. Its body is a fixed
/// read/hash loop over heap scratch: no recursion and no large stack arrays.
const AUTHENTICATION_LANE_STACK_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureAuthentication {
    Receipt,
    /// First-attempt publication retains owned producer maps and clone provenance.
    Publication,
    Bytes,
}

/// Held capture roles, with stream-map authority kept distinct from byte digests.
enum VerifiedBytes {
    Digest {
        file: File,
        fingerprint: SourceFingerprint,
    },
    /// Bytes bound to a canonical map, authenticated or trusted from the receipt.
    Stream(crate::storage::stream::AuthenticatedStream),
}

struct VerifiedPayload {
    role: CaptureRole,
    length: u64,
    bytes: VerifiedBytes,
}
impl VerifiedPayload {
    fn file(&self) -> &File {
        match &self.bytes {
            VerifiedBytes::Digest { file, .. } => file,
            VerifiedBytes::Stream(stream) => stream.file(),
        }
    }

    fn fingerprint(&self) -> SourceFingerprint {
        match &self.bytes {
            VerifiedBytes::Digest { fingerprint, .. } => *fingerprint,
            VerifiedBytes::Stream(stream) => stream.fingerprint(),
        }
    }

    fn recheck(&self) -> Result<(), LibVmError> {
        if SourceFingerprint::new(&self.file().metadata()?) != self.fingerprint() {
            return Err(invalid("authenticated staged capture bytes changed"));
        }
        Ok(())
    }
}
pub(crate) struct VerifiedCapture {
    evidence: CaptureEvidence,
    evidence_bytes: Vec<u8>,
    files: Vec<VerifiedPayload>,
    ram_map: crate::storage::map::AuthenticatedMap,
    publications:
        BTreeMap<crate::storage::identity::StreamId, crate::storage::pool::SealedStreamPublication>,
    directory_identity: (u64, u64),
    control_fingerprints: Vec<(&'static str, SourceFingerprint)>,
}
impl VerifiedCapture {
    async fn admit_maps(&mut self, store: &Store, operation: Uuid) -> Result<(), LibVmError> {
        let mut maps = vec![&self.ram_map];
        for payload in &self.files {
            if let VerifiedBytes::Stream(stream) = &payload.bytes {
                if matches!(payload.role, CaptureRole::Disk(_)) {
                    maps.push(stream.map());
                }
            }
        }
        let retained = store.admit_published_map_roots(operation, &maps).await?;
        drop(maps);
        let mut retained = retained.into_iter().map(|map| map.into_map());
        self.ram_map = retained
            .next()
            .ok_or_else(|| invalid("RAM root admission returned no retained map"))?;
        for payload in &mut self.files {
            if matches!(payload.role, CaptureRole::Disk(_)) {
                if let VerifiedBytes::Stream(stream) = &payload.bytes {
                    let map = retained
                        .next()
                        .ok_or_else(|| invalid("disk root admission returned no retained map"))?;
                    payload.bytes = VerifiedBytes::Stream(
                        crate::storage::stream::AuthenticatedStream::from_verified_fingerprint(
                            stream.file().try_clone()?,
                            std::sync::Arc::new(map),
                            stream.fingerprint(),
                        )?,
                    );
                }
            }
        }
        Ok(())
    }

    fn retain_disk_baselines(
        &self,
        machine_dir: &Path,
        plan: &CapturePlan,
    ) -> Result<(), LibVmError> {
        for payload in &self.files {
            if let CaptureRole::Disk(name) = &payload.role {
                if !plan
                    .disks
                    .iter()
                    .any(|disk| &disk.name == name && disk.tracking_eligible)
                {
                    continue;
                }
                if let VerifiedBytes::Stream(stream) = &payload.bytes {
                    crate::machine::root_storage::retain_admitted_disk_map(
                        machine_dir,
                        stream.map(),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn publications(
        &self,
    ) -> &BTreeMap<crate::storage::identity::StreamId, crate::storage::pool::SealedStreamPublication>
    {
        &self.publications
    }

    pub(crate) fn recheck_registered(
        &self,
        store: &Store,
        capture: Uuid,
    ) -> Result<(), LibVmError> {
        if Uuid::parse_str(self.evidence.capture_id.as_str()).map_err(invalid)? != capture {
            return Err(invalid(
                "publication verification belongs to another capture",
            ));
        }
        let machine = open_machine(
            store,
            self.evidence.machine_id.as_str().parse().map_err(invalid)?,
        )?;
        let captures = machine
            .open_dir("captures")?
            .ok_or_else(|| invalid("capture namespace disappeared"))?;
        let directory = captures
            .open_dir(self.evidence.capture_id.as_str())?
            .ok_or_else(|| invalid("capture directory disappeared"))?;
        let stat = nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?;
        if (stat.st_dev as u64, stat.st_ino as u64) != self.directory_identity {
            return Err(invalid("registered capture directory was replaced"));
        }
        for payload in &self.files {
            payload.recheck()?;
            let file = open_relative(&directory, Path::new(&payload.role.relative_path()))?;
            if file.metadata()?.nlink() != 1
                || SourceFingerprint::new(&file.metadata()?) != payload.fingerprint()
            {
                return Err(invalid(
                    "registered capture payload changed before catalog commit",
                ));
            }
        }
        for (name, fingerprint) in &self.control_fingerprints {
            let file = directory
                .open_file(name)?
                .ok_or_else(|| invalid("capture control record disappeared"))?;
            if file.metadata()?.nlink() != 1
                || SourceFingerprint::new(&file.metadata()?) != *fingerprint
            {
                return Err(invalid(
                    "capture control record changed before catalog commit",
                ));
            }
        }
        Ok(())
    }
    fn recheck_directory(&self, directory: &OwnedDirectory) -> Result<(), LibVmError> {
        let stat = nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?;
        if (stat.st_dev as u64, stat.st_ino as u64) != self.directory_identity {
            return Err(invalid("capture staging directory changed"));
        }
        for payload in &self.files {
            let current = open_relative(directory, Path::new(&payload.role.relative_path()))?;
            if current.metadata()?.nlink() != 1
                || SourceFingerprint::new(&current.metadata()?) != payload.fingerprint()
            {
                return Err(invalid(
                    "capture role pathname no longer names its authenticated inode",
                ));
            }
        }
        let evidence = read_optional(
            directory,
            vm_spec::capture::CAPTURE_EVIDENCE_FILE,
            vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
        )?
        .ok_or_else(|| invalid("capture evidence disappeared"))?;
        let request = read_optional(
            directory,
            vm_spec::capture::CAPTURE_REQUEST_FILE,
            vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
        )?
        .ok_or_else(|| invalid("capture request disappeared"))?;
        if evidence != self.evidence_bytes
            || Sha256Digest::of_bytes(&request) != self.evidence.request_digest
        {
            return Err(invalid(
                "capture control records changed before publication",
            ));
        }
        Ok(())
    }
}

pub(crate) fn staged_map(
    directory: &OwnedDirectory,
    plan: &CapturePlan,
    bytes: &[u8],
    role: vm_spec::stream_map::StreamRole,
) -> Result<crate::storage::map::AuthenticatedMap, LibVmError> {
    let root = vm_spec::stream_map::StreamRoot::decode(bytes).map_err(invalid)?;
    let nodes = plan
        .map_node_store
        .as_deref()
        .ok_or_else(|| invalid("capture map node capability is missing"))?;
    let images = Path::new(nodes)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid("capture map node capability has no pool root"))?;
    let pool = StoragePool::open_existing(images)?
        .ok_or_else(|| invalid("capture map pool disappeared"))?;
    let operation =
        Uuid::parse_str(plan.reservation.storage_operation_id.as_str()).map_err(invalid)?;
    let authority = pool.map_authority(std::sync::Arc::new(pool.existing_lease(operation)?))?;
    let writer = match directory.open_dir("map-nodes")? {
        Some(nodes) => crate::storage::map::MapNodeWriter::adopt_directory(nodes.path())?,
        None => crate::storage::map::MapNodeWriter::new()?,
    };
    Ok(writer
        .with_authority(authority)
        .finish(root, role, None)?
        .into_map())
}

fn validate_ram_changes(
    file: &File,
    memory: &vm_spec::capture::CaptureMemoryEvidence,
    map: &crate::storage::map::AuthenticatedMap,
) -> Result<(), LibVmError> {
    if memory.identity_chunk_bytes as u64 != map.chunk_size().bytes() {
        return Err(invalid("RAM change profile differs from its root"));
    }
    let mut input = file;
    input.seek(SeekFrom::Start(0))?;
    let mut present = (memory.changes.coverage == vm_spec::capture::CaptureRamCoverage::Full)
        .then(|| map.present_chunks());
    let mut nodes = map.node_source();
    for change in vm_spec::capture::RamChangeReader::new(input, map.length(), &memory.changes)? {
        match change? {
            vm_spec::capture::CaptureRamChange::Data { index, digest } => {
                let matches = if let Some(present) = &mut present {
                    present
                        .next()
                        .transpose()?
                        .is_some_and(|chunk| chunk.index == index && chunk.digest == digest)
                } else {
                    map.root()
                        .lookup(index, &mut nodes)
                        .map_err(StorageError::from)?
                        == vm_spec::stream_map::Chunk::Data(digest)
                };
                if !matches {
                    return Err(invalid("RAM change digest differs from sealed root"));
                }
            }
            vm_spec::capture::CaptureRamChange::Zero { first_index, count } => {
                if map
                    .root()
                    .zero_range_changes(first_index, count, &mut nodes)
                    .map_err(StorageError::from)?
                    .next()
                    .transpose()
                    .map_err(StorageError::from)?
                    .is_some()
                {
                    return Err(invalid("RAM zero change differs from sealed root"));
                }
            }
        }
    }
    if let Some(mut present) = present {
        if present.next().transpose()?.is_some() {
            return Err(invalid("full RAM changes omit nonzero root entries"));
        }
    }
    Ok(())
}

/// Validate the coherent monitor receipt without reading stream payload bytes.
pub(crate) fn validate_receipt(
    directory: &OwnedDirectory,
    record: &CaptureRecord,
) -> Result<VerifiedCapture, LibVmError> {
    verify_capture(directory, record, CaptureAuthentication::Receipt)
}

#[cfg(test)]
/// Independent full-byte oracle for capture corruption tests.
pub(crate) fn verify_capture_bytes(
    directory: &OwnedDirectory,
    record: &CaptureRecord,
) -> Result<VerifiedCapture, LibVmError> {
    verify_capture(directory, record, CaptureAuthentication::Bytes)
}

fn verify_capture(
    directory: &OwnedDirectory,
    record: &CaptureRecord,
    authentication: CaptureAuthentication,
) -> Result<VerifiedCapture, LibVmError> {
    let request = read_optional(
        directory,
        vm_spec::capture::CAPTURE_REQUEST_FILE,
        vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
    )?
    .ok_or_else(|| invalid("capture request is missing"))?;
    if CapturePlan::decode(&request).map_err(invalid)? != record.plan
        || request != record.plan.canonical_bytes().map_err(invalid)?
    {
        return Err(invalid("capture request differs from durable plan"));
    }
    let evidence_bytes = read_optional(
        directory,
        vm_spec::capture::CAPTURE_EVIDENCE_FILE,
        vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
    )?
    .ok_or_else(|| invalid("capture seal is missing"))?;
    let evidence = CaptureEvidence::decode(&evidence_bytes).map_err(invalid)?;
    evidence
        .validate_against_plan(&record.plan, &Sha256Digest::of_bytes(&request))
        .map_err(invalid)?;
    if !evidence.is_sealed() {
        return Err(invalid("diagnostic capture record is not a coherent seal"));
    }
    let expected = record
        .plan
        .roles()
        .into_iter()
        .map(|role| role.relative_path())
        .collect::<BTreeSet<_>>();
    let mut top = BTreeSet::from([
        vm_spec::capture::CAPTURE_REQUEST_FILE.to_owned(),
        vm_spec::capture::CAPTURE_EVIDENCE_FILE.to_owned(),
    ]);
    for path in &expected {
        top.insert(
            path.split('/')
                .next()
                .ok_or_else(|| invalid("empty capture role"))?
                .to_owned(),
        );
    }
    top.insert(vm_spec::capture::CAPTURE_SOURCE_FILE.to_owned());
    top.insert(vm_spec::capture::CAPTURE_SOURCE_TEMPORARY_FILE.to_owned());
    top.insert(vm_spec::capture::CAPTURE_CUT_FILE.to_owned());
    top.insert(vm_spec::capture::CAPTURE_CUT_TEMPORARY_FILE.to_owned());
    top.insert("map-nodes".to_owned());
    check_entries(directory, &top)?;
    let disk_names = record
        .plan
        .disks
        .iter()
        .flat_map(|disk| {
            [
                disk.name.file_name(),
                format!("{}.root", disk.name.as_str()),
            ]
        })
        .collect();
    if let Some(disks) = directory.open_dir("disks")? {
        check_entries(&disks, &disk_names)?;
    }
    let stat = nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?;
    // Admit every role before any payload byte is read: geometry, hardlink,
    // cross-role alias, writable-source alias and format bounds. All role
    // descriptors open here are the ones the result retains, so the peak
    // descriptor count equals the former end-of-loop count.
    let mut identities = BTreeSet::new();
    let mut admitted = Vec::with_capacity(evidence.inventory.len());
    for entry in &evidence.inventory {
        let file = open_relative(directory, Path::new(&entry.role.relative_path()))?;
        let metadata = file.metadata()?;
        if metadata.len() != entry.length
            || metadata.nlink() != 1
            || !identities.insert((metadata.dev(), metadata.ino()))
            || record
                .source_inodes
                .contains(&(metadata.dev(), metadata.ino()))
        {
            return Err(invalid(
                "capture output geometry, alias or hardlink violation",
            ));
        }
        let maximum = match entry.role {
            CaptureRole::Execution => crate::store::capture_native::MAX_EXECUTION_BYTES,
            CaptureRole::Devices => crate::store::capture_native::MAX_DEVICE_BYTES,
            CaptureRole::Layout => 65536,
            CaptureRole::Ram => record.plan.ram_bytes,
            CaptureRole::RamMap | CaptureRole::DiskMap(_) => {
                vm_spec::stream_map::MAX_ROOT_BYTES as u64
            }
            CaptureRole::RamChanges => record
                .plan
                .ram_bytes
                .div_ceil(vm_spec::stream_map::ChunkSize::RAM.bytes())
                .checked_mul(56)
                .and_then(|bytes| bytes.checked_add(16))
                .ok_or_else(|| invalid("RAM changes bound overflow"))?,
            CaptureRole::Disk(_) => Resource::VirtualDiskBytes.maximum(),
        };
        if entry.length > maximum {
            return Err(invalid("capture payload exceeds its role's format bound"));
        }
        admitted.push(AdmittedPayload {
            entry,
            fingerprint: SourceFingerprint::new(&metadata),
            file,
        });
    }
    let ram_index = admitted
        .iter()
        .position(|payload| payload.entry.role == CaptureRole::Ram)
        .ok_or_else(|| invalid("RAM role is missing"))?;
    let ram = admitted.remove(ram_index);
    let mut files = if authentication == CaptureAuthentication::Bytes {
        let (ram, mut files) = authenticate_lanes(
            move |stop| {
                let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
                verify_payload(ram, authentication, &mut buffer, &mut None, stop)
            },
            |stop| {
                let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
                let mut hasher = None;
                let mut files = Vec::with_capacity(admitted.len() + 1);
                for payload in admitted {
                    match verify_payload(payload, authentication, &mut buffer, &mut hasher, stop)? {
                        Some(payload) => files.push(payload),
                        None => return Ok(None),
                    }
                }
                Ok(Some(files))
            },
        )?;
        files.insert(ram_index, ram);
        files
    } else {
        admitted.insert(ram_index, ram);
        let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
        let stop = AtomicBool::new(false);
        let mut hasher = None;
        admitted
            .into_iter()
            .map(|payload| {
                verify_payload(payload, authentication, &mut buffer, &mut hasher, &stop)?
                    .ok_or_else(|| invalid("receipt validation was interrupted"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let layout = files
        .iter()
        .find(|file| file.role == CaptureRole::Layout)
        .ok_or_else(|| invalid("RAM layout role is missing"))?;
    let mut bytes = Vec::new();
    let mut layout_file = layout.file().try_clone()?;
    layout_file.seek(SeekFrom::Start(0))?;
    layout_file.take(65537).read_to_end(&mut bytes)?;
    let memory = evidence
        .memory
        .as_ref()
        .ok_or_else(|| invalid("RAM geometry evidence is missing"))?;
    let map_payload = files
        .iter()
        .find(|file| file.role == CaptureRole::RamMap)
        .ok_or_else(|| invalid("complete RAM map role is missing"))?;
    let mut map_bytes = Vec::new();
    let mut map_file = map_payload.file().try_clone()?;
    map_file.seek(SeekFrom::Start(0))?;
    map_file
        .take(map_payload.length + 1)
        .read_to_end(&mut map_bytes)?;
    let ram_map = staged_map(
        directory,
        &record.plan,
        &map_bytes,
        vm_spec::stream_map::StreamRole::Ram,
    )?;
    if ram_map.length() != memory.packed_length
        || ram_map.id().as_bytes() != memory.ram_stream.as_bytes()
        || ram_map.canonical_bytes()? != map_bytes
    {
        return Err(invalid(
            "complete RAM map differs from sealed memory identity",
        ));
    }
    let changes = files
        .iter()
        .find(|file| file.role == CaptureRole::RamChanges)
        .ok_or_else(|| invalid("RAM changes role is missing"))?;
    validate_ram_changes(changes.file(), memory, &ram_map)?;
    for index in 0..files.len() {
        let payload = &files[index];
        let entry = evidence
            .inventory
            .iter()
            .find(|entry| entry.role == payload.role)
            .ok_or_else(|| invalid("stream inventory role is missing"))?;
        let name = match &payload.role {
            CaptureRole::Ram => {
                if payload.length != ram_map.length()
                    || Some(Sha256Digest::from_bytes(*ram_map.id().as_bytes())) != entry.identity
                {
                    return Err(invalid("RAM receipt identity differs from its stream root"));
                }
                continue;
            }
            CaptureRole::Disk(name) => name,
            _ => continue,
        };
        let map_payload = files
            .iter()
            .find(|file| file.role == CaptureRole::DiskMap(name.clone()))
            .ok_or_else(|| invalid("disk map role is missing"))?;
        let mut bytes = Vec::new();
        let mut input = map_payload.file();
        input.seek(SeekFrom::Start(0))?;
        input.take(map_payload.length + 1).read_to_end(&mut bytes)?;
        let root = vm_spec::stream_map::StreamRoot::decode(&bytes).map_err(invalid)?;
        let map = ram_map.with_root(root, vm_spec::stream_map::StreamRole::Disk)?;
        if map.length() != payload.length
            || Some(Sha256Digest::from_bytes(*map.id().as_bytes())) != entry.identity
            || map.canonical_bytes()? != bytes
        {
            return Err(invalid(
                "stream receipt identity differs from its stream root",
            ));
        }
        if !matches!(payload.bytes, VerifiedBytes::Stream(_)) {
            let stream = crate::storage::stream::AuthenticatedStream::from_receipt(
                payload.file().try_clone()?,
                map,
            )?;
            if stream.fingerprint() != payload.fingerprint() {
                return Err(invalid(
                    "sealed disk changed while binding its producer map",
                ));
            }
            files[index].bytes = VerifiedBytes::Stream(stream);
        }
    }
    let layout = validate_layout(&bytes, memory, record.plan.ram_bytes)?;
    if memory.binding.ram_layout != Sha256Digest::of_bytes(&bytes)
        || memory.binding.topology != record.plan.configuration_digest
    {
        return Err(invalid(
            "native capture binding differs from admitted layout or configuration",
        ));
    }
    let execution = files
        .iter()
        .find(|file| file.role == CaptureRole::Execution)
        .ok_or_else(|| invalid("execution role is missing"))?;
    let devices = files
        .iter()
        .find(|file| file.role == CaptureRole::Devices)
        .ok_or_else(|| invalid("device role is missing"))?;
    crate::store::capture_native::verify_headers(
        execution.file(),
        devices.file(),
        &memory.binding,
        &record.plan.configuration,
        &layout,
    )?;
    let mut control_fingerprints = Vec::with_capacity(2);
    for name in [
        vm_spec::capture::CAPTURE_REQUEST_FILE,
        vm_spec::capture::CAPTURE_EVIDENCE_FILE,
    ] {
        let file = directory
            .open_file(name)?
            .ok_or_else(|| invalid("capture control record disappeared"))?;
        control_fingerprints.push((name, SourceFingerprint::new(&file.metadata()?)));
    }
    Ok(VerifiedCapture {
        evidence,
        evidence_bytes,
        ram_map,
        publications: BTreeMap::new(),
        files,
        directory_identity: (stat.st_dev as u64, stat.st_ino as u64),
        control_fingerprints,
    })
}

/// One admitted, still unhashed role: the exact inode later results retain.
struct AdmittedPayload<'a> {
    entry: &'a CaptureInventoryEntry,
    file: File,
    fingerprint: SourceFingerprint,
}

/// Authenticate one admitted role. `Ok(None)` means the sibling lane failed
/// first and this lane stopped before accepting anything.
fn verify_payload(
    payload: AdmittedPayload<'_>,
    authentication: CaptureAuthentication,
    buffer: &mut [u8],
    hasher: &mut Option<(
        vm_spec::stream_map::ChunkSize,
        crate::storage::stream::StreamHasher,
    )>,
    stop: &AtomicBool,
) -> Result<Option<VerifiedPayload>, LibVmError> {
    let AdmittedPayload {
        entry,
        file,
        fingerprint,
    } = payload;
    if stop.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let bytes = match (&entry.role, authentication) {
        (CaptureRole::Disk(_) | CaptureRole::Ram, CaptureAuthentication::Bytes) => {
            let profile = if entry.role == CaptureRole::Ram {
                vm_spec::stream_map::ChunkSize::RAM
            } else {
                vm_spec::stream_map::ChunkSize::DISK
            };
            if hasher.as_ref().is_some_and(|(size, _)| *size != profile) {
                *hasher = None;
            }
            let (_, scanner) = hasher.get_or_insert_with(|| {
                (profile, crate::storage::stream::StreamHasher::new(profile))
            });
            let stream = scanner.authenticate(file, entry.length)?;
            if Some(Sha256Digest::from_bytes(*stream.map().id().as_bytes())) != entry.identity {
                return Err(invalid("capture staged stream identity mismatch"));
            }
            if stream.fingerprint() != fingerprint {
                return Err(invalid("authenticated staged capture bytes changed"));
            }
            VerifiedBytes::Stream(stream)
        }
        (
            CaptureRole::Disk(_) | CaptureRole::Ram,
            CaptureAuthentication::Receipt | CaptureAuthentication::Publication,
        ) => VerifiedBytes::Digest { file, fingerprint },
        _ => {
            let mut hash = Sha256::new();
            let mut input = &file;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                let count = input.read(buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            let digest: [u8; 32] = hash.finalize().into();
            if Some(Sha256Digest::from_bytes(digest)) != entry.sha256 {
                return Err(invalid("capture staged payload digest mismatch"));
            }
            VerifiedBytes::Digest { file, fingerprint }
        }
    };
    let payload = VerifiedPayload {
        role: entry.role.clone(),
        length: entry.length,
        bytes,
    };
    payload.recheck()?;
    Ok(Some(payload))
}

/// Run RAM authentication on one bounded extra thread while the caller
/// authenticates every other role, then reduce deterministically.
///
/// ```text
///   caller ──spawn(stack 1 MiB)──► RAM lane ──────────────┐
///     │                         (checks stop before scan) │
///     └─► other roles, in order ──► join ◄─────────────────┘
///                                    │
///                      both owners finished; only now return
/// ```
///
/// A lane that fails, or unwinds, sets `stop` through its guard; its sibling
/// returns `Ok(None)` at its next read or role boundary. Canonical stream
/// scans have no stop hook and run to their admitted length. The scoped thread
/// is joined on every path, including the caller lane unwinding, so no lane
/// outlives the descriptors, staging directory or lease the caller owns.
/// A genuine error wins over a stop; with two, the caller lane's is reported.
fn authenticate_lanes<R: Send, O>(
    ram: impl FnOnce(&AtomicBool) -> Result<Option<R>, LibVmError> + Send,
    other: impl FnOnce(&AtomicBool) -> Result<Option<O>, LibVmError>,
) -> Result<(R, O), LibVmError> {
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| -> Result<(R, O), LibVmError> {
        let stop = &stop;
        let lane = std::thread::Builder::new()
            .stack_size(AUTHENTICATION_LANE_STACK_BYTES)
            .spawn_scoped(scope, move || run_lane(stop, ram))?;
        let other = run_lane(stop, other);
        let ram = lane
            .join()
            .map_err(|_| std::io::Error::other("RAM authentication lane panicked"))?;
        match (other, ram) {
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(Some(other)), Ok(Some(ram))) => Ok((ram, other)),
            _ => Err(invalid(
                "capture authentication lane stopped without a failure",
            )),
        }
    })
}

/// Run one lane under a guard that stops its sibling unless the lane
/// returned `Ok`: an error return and an unwind both release the sibling.
fn run_lane<T>(
    stop: &AtomicBool,
    lane: impl FnOnce(&AtomicBool) -> Result<T, LibVmError>,
) -> Result<T, LibVmError> {
    let mut guard = StopSiblingUnlessOk {
        stop,
        succeeded: false,
    };
    let result = lane(stop);
    guard.succeeded = result.is_ok();
    result
}

struct StopSiblingUnlessOk<'a> {
    stop: &'a AtomicBool,
    succeeded: bool,
}

impl Drop for StopSiblingUnlessOk<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.stop.store(true, Ordering::Relaxed);
        }
    }
}

fn check_entries(
    directory: &OwnedDirectory,
    expected: &BTreeSet<String>,
) -> Result<(), LibVmError> {
    let mut entries = nix::dir::Dir::openat(
        directory.fd(),
        ".",
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut count = 0;
    for entry in entries.iter() {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name().to_str().map_err(invalid)?;
        if name == "." || name == ".." {
            continue;
        }
        count += 1;
        if count > expected.len() || !expected.contains(name) {
            return Err(invalid("capture directory contains an undeclared output"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Layout {
    pub(crate) architecture: String,
    kind: String,
    magic: String,
    packed_length: u64,
    pub(crate) page_granule: u32,
    pub(crate) regions: Vec<Region>,
    schema: u32,
    topology: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Region {
    pub(crate) guest_physical_address: u64,
    pub(crate) length: u64,
    stream_offset: u64,
}
pub(crate) fn validate_layout(
    bytes: &[u8],
    memory: &vm_spec::capture::CaptureMemoryEvidence,
    admitted: u64,
) -> Result<Layout, LibVmError> {
    if bytes.len() > 65536 {
        return Err(invalid("RAM layout exceeds its metadata bound"));
    }
    let value = crate::store::models::snapshot::decode_identity_value(bytes)?;
    let layout: Layout = serde_json::from_value(value).map_err(invalid)?;
    if layout.schema != 1
        || layout.kind != "ram-layout"
        || layout.magic != "KRUNRAML"
        || !matches!(layout.architecture.as_str(), "x86_64" | "aarch64")
        || !layout.topology.is_object()
        || layout.packed_length != memory.packed_length
        || layout.packed_length > admitted
        || layout.page_granule != memory.page_granule
        || layout.page_granule == 0
        || !layout.page_granule.is_power_of_two()
        || layout.regions.is_empty()
        || layout.regions.len() > 512
        || layout.regions.len() != memory.regions as usize
    {
        return Err(invalid("RAM layout and captured geometry disagree"));
    }
    let topology = layout
        .topology
        .as_object()
        .ok_or_else(|| invalid("RAM topology is not an object"))?;
    let keys = if layout.architecture == "x86_64" {
        [
            "firmwareAddress",
            "initrdAddress",
            "ramAboveGap",
            "ramBelowGap",
            "ramLastAddress",
            "shmStartAddress",
        ]
    } else {
        [
            "fdtAddress",
            "firmwareAddress",
            "initrdAddress",
            "ramLastAddress",
            "ramStartAddress",
            "shmStartAddress",
        ]
    };
    if topology.len() != keys.len()
        || keys.iter().any(|key| {
            topology
                .get(*key)
                .and_then(serde_json::Value::as_u64)
                .is_none()
        })
    {
        return Err(invalid(
            "RAM topology is not the closed native architecture record",
        ));
    }
    let granule = u64::from(layout.page_granule);
    let mut end = 0u64;
    let mut offset = 0u64;
    for region in &layout.regions {
        if region.length == 0
            || region.guest_physical_address < end
            || region.stream_offset != offset
            || !region.guest_physical_address.is_multiple_of(granule)
            || !region.length.is_multiple_of(granule)
            || !region.stream_offset.is_multiple_of(granule)
        {
            return Err(invalid(
                "RAM layout has overlap, gap, misalignment or empty region",
            ));
        }
        end = region
            .guest_physical_address
            .checked_add(region.length)
            .ok_or_else(|| invalid("RAM guest address overflow"))?;
        offset = offset
            .checked_add(region.length)
            .ok_or_else(|| invalid("RAM stream offset overflow"))?;
    }
    if offset != layout.packed_length {
        return Err(invalid(
            "RAM layout does not cover the complete packed stream",
        ));
    }
    Ok(layout)
}

impl SnapshotStore {
    /// Accept the monitor's structural receipt and retain its immutable cut.
    /// Stream bytes are first authenticated while constructing private copies.
    pub(crate) async fn retain_local_capture(
        &self,
        capture: Uuid,
        lock_policy: PublicationLockPolicy,
    ) -> Result<
        (
            crate::store::fork::LocalCut,
            Option<crate::store::fork::AuthenticatedCutDisks>,
        ),
        LibVmError,
    > {
        let this = self.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || handle.block_on(async move {
            let operation = this.store.fork_for_capture(capture).await?.ok_or_else(|| invalid("local capture has no fork owner"))?;
            let record = this.capture_reservation(capture).await?.ok_or_else(|| invalid("local capture reservation disappeared"))?;
            let pool = StoragePool::open(&this.store.images_dir)?.with_publication_lock_policy(lock_policy);
            let publication=ObjectDigest::of_bytes(format!("silo:local-cut:{operation}").as_bytes());
            let _publisher=pool.lock_publication(&publication)?;
            let _lease = pool.existing_lease(capture)?;
            check_lease(&this.store,&pool,capture,&_lease).await?;
            let source = capture_directory(&this.store, &record)?.ok_or_else(|| invalid("local capture source disappeared"))?;
            let mut verified_disks = Vec::new();
            let mut cut = match this.store.local_cut(operation).await? {
                Some(cut) => cut,
                None => {
                    settle_capture_seal(&source)?;
                    let mut verified = validate_receipt(&source, &record)?;
                    verified.recheck_registered(&this.store, capture)?;
                    verified.admit_maps(&this.store, capture).await?;
                    verified.retain_disk_baselines(&crate::paths::machine_data_dir_in(this.store.home_path(), record.machine_id), &record.plan)?;
                    let mut storage = record.storage.clone();
                    storage.disk_baselines.clear();
                    storage.boot = record.captured_boot.clone().ok_or_else(|| invalid("local capture has no pinned boot closure"))?;
                    storage.snapshot = None;
                    storage.image = None;
                    storage.storage_generation = 0;
                    storage.ownership_epoch = 0;
                    storage.stop_outcome = crate::StorageStopOutcome::Unknown;
                    storage.operation = None;
                    storage.ownership = crate::MachineOwnership::Owned;
                    if let MachineRoot::OpaqueRaw { initial_content, .. } = &mut storage.root { *initial_content = None; }
                    let files=verified.files.iter().map(|file| {
                        let metadata=file.file().metadata()?;
                        let entry=verified.evidence.inventory.iter().find(|entry| entry.role==file.role).ok_or_else(|| invalid("verified role missing from evidence"))?;
                        Ok(crate::store::fork::LocalCutFile {role:file.role.clone(),device:metadata.dev(),inode:metadata.ino(),length:file.length,identity:entry.identity.or(entry.sha256).ok_or_else(|| invalid("capture role identity is missing"))?,fingerprint:SourceFingerprint::new(&metadata)})
                    }).collect::<Result<Vec<_>,LibVmError>>()?;
                    let source_ram=files.iter().find(|file| file.role==CaptureRole::Ram).cloned().ok_or_else(|| invalid("verified cut has no RAM role"))?;
                    let mut cut=crate::store::fork::LocalCut {
                        operation_id:operation,capture_id:capture,cut_id:Sha256Digest::from_bytes([0;32]),
                        evidence:verified.evidence.clone(),plan:record.plan.clone(),configuration:record.configuration.clone(),storage,
                        files,source_ram,relocated:false,
                    };
                    cut.cut_id = cut.identity()?;
                    let _roots = pool.lock_roots()?;
                    let mut tx = this.store.pool.begin_with("BEGIN IMMEDIATE").await?;
                    sqlx::query("INSERT INTO local_cut(cut_id,operation_id,record_json) VALUES(?1,?2,jsonb(?3))").bind(cut.cut_id.to_string()).bind(operation.to_string()).bind(serde_json::to_string(&cut).map_err(invalid)?).execute(&mut *tx).await?;
                    sqlx::query("INSERT INTO storage_operation_cut(operation_id,cut_id) VALUES(?1,?2)").bind(operation.to_string()).bind(cut.cut_id.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_cut(operation_id,cut_id) VALUES(?1,?2)").bind(capture.to_string()).bind(cut.cut_id.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    sqlx::query("DELETE FROM storage_operation_object WHERE operation_id=?1 AND object_digest<>?3 AND object_digest IN (SELECT root_digest FROM storage_operation_memory_baseline WHERE operation_id=?2)")
                        .bind(operation.to_string()).bind(record.launch_operation_id.to_string())
                        .bind(ObjectDigest::from_sha256(*verified.ram_map.id().as_bytes()).to_string())
                        .execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    tx.commit().await?;
                    // Only the disks' held inodes and maps outlive verification;
                    // state-role descriptors close here exactly as before.
                    let authority = pool.map_authority(std::sync::Arc::new(pool.existing_lease(operation)?))?;
                    for payload in verified.files {
                        if matches!(payload.role, CaptureRole::Disk(_)) {
                            if let VerifiedBytes::Stream(stream) = payload.bytes {
                                let map = crate::storage::map::AuthenticatedMap::from_admitted_root(
                                    *stream.map().root(), vm_spec::stream_map::StreamRole::Disk, authority.clone(),
                                )?;
                                let transferred = crate::storage::stream::AuthenticatedStream::from_verified_fingerprint(
                                    stream.file().try_clone()?, std::sync::Arc::new(map), stream.fingerprint(),
                                )?;
                                verified_disks.push((payload.role, transferred));
                            }
                        }
                    }
                    cut
                }
            };
            let mut relocated_disks = Vec::new();
            if !cut.relocated {
                let images = OwnedDirectory::open_existing_root(&this.store.images_dir)?.ok_or_else(|| invalid("pool disappeared"))?;
                let source_device = nix::sys::stat::fstat(source.fd()).map_err(std::io::Error::from)?.st_dev;
                let pool_device = nix::sys::stat::fstat(images.fd()).map_err(std::io::Error::from)?.st_dev;
                if source_device != pool_device {
                    this.store.reserve_capture_publication(&record, record.reservation_bytes - record.plan.reservation.staging_bytes).await?;
                }
                let tmp = images.open_dir("tmp")?.ok_or_else(|| invalid("pool tmp disappeared"))?;
                let owner = tmp.ensure_dir_deferred(&operation.to_string())?;
                let destination = owner.ensure_dir_deferred("cut")?;
                destination.ensure_dir_deferred("disks")?;
                let mut qualification = crate::machine::root_disk::CopyQualification::new(1);
                for index in 0..cut.files.len() {
                    let payload=&mut cut.files[index];
                    let mut carrier = verified_disks.iter().position(|(role,_)| role==&payload.role).map(|position| verified_disks.swap_remove(position).1);
                    if payload.role == CaptureRole::Ram {
                        let root = ObjectDigest::from_sha256(*payload.identity.as_bytes());
                        let authority = pool.map_authority(std::sync::Arc::new(pool.existing_lease(operation)?))?;
                        let map = pool.load_map(root, vm_spec::stream_map::StreamRole::Ram, authority)?;
                        let file = match source.open_capture_payload(vm_spec::capture::CAPTURE_RAM_FILE)? {
                            Some(file) => file,
                            None => destination.open_capture_payload(vm_spec::capture::CAPTURE_RAM_FILE)?
                                .ok_or_else(|| invalid("relocation lost its RAM source and destination"))?,
                        };
                        carrier = Some(crate::storage::stream::AuthenticatedStream::from_receipt(file, map)?);
                    }
                    let relative = payload.role.relative_path();
                    let (source_parent,destination_parent,name) = match relative.split_once('/') {
                        Some((parent,name)) => (source.open_dir(parent)?.ok_or_else(|| invalid("capture role parent missing"))?, destination.ensure_dir_deferred(parent)?, name),
                        None => (source.try_clone()?, destination.try_clone()?, relative.as_str()),
                    };
                    if let Some(existing) = destination_parent.open_capture_payload(name)? {
                        let metadata = existing.metadata()?;
                        if metadata.dev() != payload.device || metadata.ino() != payload.inode {
                            // An interrupted cross-device copy has no committed inode.
                            // Recopy the still-owned source, authenticating while writing.
                            let source_file = source_parent.open_capture_payload(name)?
                                .ok_or_else(|| invalid("interrupted relocation lost its source"))?;
                            if !payload.fingerprint.same_contents_after_metadata_change(&source_file.metadata()?) {
                                return Err(invalid("interrupted relocation source changed"));
                            }
                            nix::unistd::unlinkat(destination_parent.fd(), name, nix::unistd::UnlinkatFlags::NoRemoveDir)
                                .map_err(std::io::Error::from)?;
                        }
                    }
                    if destination_parent.open_capture_payload(name)?.is_none() {
                        let file = source_parent.open_capture_payload(name)?.ok_or_else(|| invalid("both local cut role locations are missing"))?;
                        let metadata = file.metadata()?;
                        let source_unchanged = SourceFingerprint::new(&metadata) == payload.fingerprint;
                        // An interrupted chmod preserves the receipt's content fingerprint.
                        let chmod_interrupted = metadata.mode() & 0o7777 == 0o400
                            && payload.fingerprint.same_contents_after_metadata_change(&metadata);
                        if (!source_unchanged && !chmod_interrupted)
                            || carrier.as_ref().is_some_and(|held| held.fingerprint() != payload.fingerprint)
                        {
                            return Err(invalid("local cut source fingerprint changed"));
                        }
                        if metadata.dev() == nix::sys::stat::fstat(destination_parent.fd()).map_err(std::io::Error::from)?.st_dev as u64 {
                            if metadata.mode() & 0o7777 == 0o600 {
                                nix::sys::stat::fchmod(&file, nix::sys::stat::Mode::S_IRUSR)
                                    .map_err(std::io::Error::from)?;
                            }
                            crate::storage::pool::rename_component_no_replace(&source_parent,name,&destination_parent,name)?;
                        } else {
                            let temporary=format!(".relocating-{}",Uuid::new_v4());
                            let copy_source = match &carrier {
                                Some(held) => crate::machine::root_disk::CopySource::Authenticated(held),
                                None => crate::machine::root_disk::CopySource::Unscanned { file: &file, length: payload.length },
                            };
                            let copied = crate::machine::root_disk::copy_private(copy_source,destination_parent.try_clone()?,&temporary,&mut qualification,crate::storage::stream::CopyWriteback::Buffered).map_err(|error| invalid(error.to_string()))?;
                            if matches!(payload.role, CaptureRole::Ram | CaptureRole::Disk(_)) {
                                if copied.verification().is_none_or(|scan| scan.stream.as_bytes() != payload.identity.as_bytes()) {
                                    return Err(invalid("relocation copy differs from receipt identity"));
                                }
                            } else if crate::storage::stream::whole_file_sha256(copied.file())? != payload.identity {
                                return Err(invalid("relocation state copy differs from receipt digest"));
                            }
                            carrier = None;
                            nix::sys::stat::fchmod(copied.file(), nix::sys::stat::Mode::S_IRUSR)
                                .map_err(std::io::Error::from)?;
                            let entry = nix::sys::stat::fstatat(
                                destination_parent.fd(), temporary.as_str(),
                                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                            ).map_err(std::io::Error::from)?;
                            let metadata = copied.file().metadata()?;
                            if entry.st_dev as u64 != metadata.dev()
                                || entry.st_ino as u64 != metadata.ino()
                                || metadata.nlink() != 1
                            {
                                return Err(invalid("owned relocation copy entry was replaced or linked"));
                            }
                            crate::storage::pool::rename_component_no_replace(
                                &destination_parent, &temporary, &destination_parent, name,
                            )?;
                            payload.fingerprint = SourceFingerprint::new(&copied.file().metadata()?);
                            copied.retain();
                        }
                    }
                    let final_file=destination_parent.open_capture_payload(name)?.ok_or_else(|| invalid("local cut role disappeared"))?;
                    let mut metadata=final_file.metadata()?;
                    if metadata.mode()&0o7777==0o600 {
                        nix::sys::stat::fchmod(&final_file,nix::sys::stat::Mode::S_IRUSR).map_err(std::io::Error::from)?;
                        metadata=final_file.metadata()?;
                    }
                    if metadata.len() != payload.length || metadata.nlink()!=1 || metadata.mode() & 0o7777 != 0o400 { return Err(invalid("relocated local cut role is not immutable")); }
                    let unchanged = payload.fingerprint.same_contents_after_metadata_change(&metadata);
                    // The carrier held this exact inode since seal verification; the
                    // owned rename and 0600->0400 chmod changed only its ctime.
                    let held_inode = carrier.as_ref().map(|held| held.file().metadata()).transpose()?.map(|held| (held.dev(),held.ino()));
                    carrier = match carrier.take() {
                        Some(mut held) if unchanged && held_inode==Some((metadata.dev(),metadata.ino())) => { held.refresh_after_owned_metadata_change()?; Some(held) }
                        _ => None,
                    };
                    if !unchanged {
                        return Err(invalid("relocated local cut fingerprint differs from receipt"));
                    }
                    if carrier.as_ref().is_some_and(|held| held.fingerprint()!=SourceFingerprint::new(&metadata)) {
                        return Err(invalid("relocated local cut disk changed during relocation"));
                    }
                    payload.device=metadata.dev(); payload.inode=metadata.ino();
                    payload.fingerprint=SourceFingerprint::new(&metadata);
                    if matches!(payload.role, CaptureRole::Disk(_)) {
                        if let Some(held) = carrier {
                            relocated_disks.push((cut.files[index].role.clone(), held));
                        }
                    }
                }
                for (name, bytes) in [
                    (vm_spec::capture::CAPTURE_REQUEST_FILE, record.plan.canonical_bytes().map_err(invalid)?),
                    (vm_spec::capture::CAPTURE_EVIDENCE_FILE, cut.evidence.canonical_bytes().map_err(invalid)?),
                ] {
                    destination.write_file_atomic_deferred(name, &bytes)?;
                }
                cut.relocated=true;
            }
            let evidence = String::from_utf8(cut.evidence.canonical_bytes().map_err(invalid)?).map_err(invalid)?;
            let cut_id = cut.cut_id;
            {
                let _roots = pool.lock_roots()?;
                let mut tx = this.store.pool.begin_with("BEGIN IMMEDIATE").await?;
                sqlx::query("UPDATE local_cut SET record_json=jsonb(?2) WHERE operation_id=?1")
                    .bind(operation.to_string())
                    .bind(serde_json::to_string(&cut).map_err(invalid)?)
                    .execute(&mut *tx)
                    .await?;
                update_capture_in_transaction(&mut tx, capture, move |record| {
                    record.evidence = Some(evidence);
                    record.state = match record.state {
                        CaptureState::ReleasedLocal { cut } if cut == cut_id => CaptureState::ReleasedLocal { cut },
                        CaptureState::Local { cut } if cut == cut_id => CaptureState::Local { cut },
                        CaptureState::Reserved | CaptureState::Sealed => CaptureState::Local { cut: cut_id },
                        _ => return Err(invalid("local cut cannot replace another capture disposition")),
                    };
                    Ok(())
                }).await?;
                let json: String = sqlx::query_scalar(
                    "SELECT json(result_json) FROM live_fork WHERE operation_id=?1",
                )
                .bind(operation.to_string())
                .fetch_one(&mut *tx)
                .await?;
                let mut result: crate::LiveForkResult = serde_json::from_str(&json).map_err(invalid)?;
                result.capture = crate::ForkCaptureOutcome::Sealed { cut_id };
                if result.stage != crate::ForkStage::Finished {
                    result.stage = crate::ForkStage::Restoring;
                }
                result.children.clear();
                sqlx::query("UPDATE live_fork SET result_json=jsonb(?2) WHERE operation_id=?1")
                    .bind(operation.to_string())
                    .bind(serde_json::to_string(&result).map_err(invalid)?)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,phase,monotonic_ns) VALUES(?1,'seal_authenticated',?2)")
                    .bind(operation.to_string())
                    .bind(crate::machine::live_fork::monotonic_ns()?)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
            let disks = (!relocated_disks.is_empty()).then(|| crate::store::fork::AuthenticatedCutDisks::new(operation, cut_id, relocated_disks));
            this.store.complete_capture_peak(&record).await?;
            Ok((cut, disks))
        })).await?
    }
}
impl Store {
    pub(crate) async fn require_capture_dispatch(
        &self,
        command: &vm_spec::lifecycle::CaptureCommand,
    ) -> Result<(), LibVmError> {
        let capture = Uuid::parse_str(command.plan.capture_id.as_str()).map_err(invalid)?;
        // The caller holds the source machine lock through dispatch. Cancellation
        // takes the same lock before committing its durable fence.
        if let Some(operation) = self.fork_for_capture(capture).await? {
            let fork = self
                .fork_result(operation)
                .await?
                .ok_or_else(|| invalid("fork capture owner disappeared"))?;
            if fork.cancellation_requested
                || !matches!(fork.capture, crate::ForkCaptureOutcome::Pending)
            {
                return Err(invalid("fork no longer authorizes capture dispatch"));
            }
        }
        let json:String=sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(capture.to_string()).fetch_one(&self.pool).await?;
        let record = decode_record(&json)?;
        if record.plan != command.plan
            || record.state != CaptureState::Reserved
            || record.discard.is_some()
        {
            return Err(invalid(
                "a sealed or retired capture can never be recaptured",
            ));
        }
        self.reserve_capture_inventory(&record, None).await?;
        SnapshotStore::from_store(std::sync::Arc::new(self.clone()))
            .update_capture(capture, |record| {
                record.dispatch_attempted = true;
                Ok(())
            })
            .await
    }
}

impl Store {
    /// Find a release receipt only for the capture's exact machine and run.
    pub(crate) async fn capture_release_receipt_json(
        &self,
        machine: MachineId,
        run: Uuid,
        capture: &LiveId,
    ) -> Result<Option<String>, LibVmError> {
        Ok(sqlx::query_scalar("SELECT json(result_json) FROM live_command WHERE machine_id=?1 AND run_id=?2 AND json_extract(result_json,'$.command')='releaseCapture' AND json_extract(result_json,'$.outcome')='released' AND json_extract(result_json,'$.released.operationId')=?3 LIMIT 1")
            .bind(machine.to_string())
            .bind(run.to_string())
            .bind(capture.as_str())
            .fetch_optional(&self.pool)
            .await?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::num::NonZeroU64;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::Arc;

    use uuid::Uuid;
    use vm_spec::capture::{
        CaptureConfiguration, CaptureEvidence, CaptureInventoryEntry, CaptureMemoryEvidence,
        CapturePauseAuthority, CapturePauseDisposition, CaptureRecordOutcome, CaptureRole,
        CaptureStateBinding, Sha256Digest,
    };
    use vm_spec::lifecycle::{CapturePolicy, CaptureResumePolicy, LiveId, PauseOwner, PauseToken};

    use crate::lock_manager::LockId;
    use crate::paths::{LocalPaths, OwnedDirectory};
    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::StoragePool;
    use crate::storage::stream::StreamHasher;
    use crate::store::capture::{
        authenticate_lanes, capture_directory, validate_layout, verify_capture, verify_payload,
        AdmittedPayload, CaptureAuthentication, VerifiedBytes, VerifiedPayload,
        AUTHENTICATION_BUFFER_BYTES,
    };

    use crate::store::models::snapshot::SnapshotCaptureKind;
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::operation_store::LaunchStorageLease;
    use crate::store::snapshot_store::{
        CaptureReservation, CaptureReservationRequest, CaptureSourceOutcome, CaptureState,
        SnapshotCaptureKindName, SnapshotRef, SnapshotStore,
    };
    use crate::store::{MachineStore, Store};

    pub(crate) struct Fixture {
        _temporary: tempfile::TempDir,
        pub(crate) snapshots: SnapshotStore,
        config: MachineConfig,
        pub(crate) reservation: CaptureReservation,
        pub(crate) launch: LaunchStorageLease,
    }

    pub(crate) async fn fixture() -> Fixture {
        fixture_with_external_data(false).await
    }

    async fn fixture_with_external_data(include_data: bool) -> Fixture {
        fixture_source(include_data, false, CapturePolicy::Full).await
    }

    pub(crate) async fn fork_fixture() -> Fixture {
        fixture_source(false, true, CapturePolicy::Full).await
    }

    #[tokio::test]
    async fn fork_cancellation_fences_initial_capture_dispatch_and_replay() {
        let fixture = fork_fixture().await;
        let store = &fixture.snapshots.store;
        let record = &fixture.reservation.record;
        let operation = store
            .fork_for_capture(record.capture_id)
            .await
            .unwrap()
            .unwrap();
        let command = vm_spec::lifecycle::CaptureCommand {
            envelope: vm_spec::lifecycle::LiveCommandEnvelope {
                machine_id: record.plan.machine_id.clone(),
                run_id: vm_spec::lifecycle::LiveId::parse(&record.run_id.to_string()).unwrap(),
                request_id: record.plan.capture_id.clone(),
            },
            plan: record.plan.clone(),
        };
        store.require_capture_dispatch(&command).await.unwrap();
        store
            .update_fork(operation, |fork| {
                fork.cancellation_requested = true;
                Ok(())
            })
            .await
            .unwrap();
        for _ in 0..2 {
            let error = store.require_capture_dispatch(&command).await.unwrap_err();
            assert!(error
                .to_string()
                .contains("fork no longer authorizes capture dispatch"));
        }
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(record.capture_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Reserved,
        );
    }

    #[tokio::test]
    async fn shared_fork_preparation_failure_retires_unsubmitted_children_and_budget() {
        let fixture = fork_fixture().await;
        seal(&fixture);
        let store = &fixture.snapshots.store;
        let capture = fixture.reservation.record.capture_id;
        let operation = store.fork_for_capture(capture).await.unwrap().unwrap();
        let (_, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let cut = store.open_local_cut(operation, retained).await.unwrap();
        store.bind_fork_resources(&cut).await.unwrap();
        let before = store.fork_result(operation).await.unwrap().unwrap();
        let children = store.fork_children(operation).await.unwrap();
        let error =
            crate::machine::root_storage::invalid("monitor executable authentication failed");
        crate::machine::live_fork::fail_shared_preparation(store, operation, &error)
            .await
            .unwrap();
        let result = store.fork_result(operation).await.unwrap().unwrap();
        assert_eq!(result.source, before.source);
        assert_eq!(result.capture, before.capture);
        for child in &result.children {
            assert!(matches!(
                &child.outcome,
                crate::ForkChildOutcome::Failed {
                    phase: crate::ForkFailurePhase::Construction,
                    diagnostic,
                } if diagnostic.as_str().contains("monitor executable authentication failed")
            ));
        }
        let pool = StoragePool::open(&store.images_dir).unwrap();
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        store
            .release_unsubmitted_fork_budget(operation)
            .await
            .unwrap();
        for child in children {
            assert!(!store
                .fork_child_storage_operations_retained(child.consumer_id, child.launch_id)
                .await
                .unwrap());
            assert!(store
                .reserved_fork_machine(child.consumer_id, &child.result.name)
                .await
                .unwrap()
                .is_none());
        }
        let inventory: crate::store::restore::CaptureBudgetInventory =
            serde_json::from_str(&store.capture_budget_document(operation).await.unwrap()).unwrap();
        assert!(inventory.pending.is_empty());
        assert!(inventory.bound.is_empty());
    }

    async fn fixture_source(include_data: bool, fork: bool, policy: CapturePolicy) -> Fixture {
        fixture_source_with_disk_length(include_data, fork, policy, 512).await
    }

    pub(crate) async fn fixture_source_with_disk_length(
        include_data: bool,
        fork: bool,
        policy: CapturePolicy,
        disk_length: u64,
    ) -> Fixture {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let parent = paths.create_machine_data_dir(id).unwrap();
        let directory = parent.open_dir(&id.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x51; 512]).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(directory.path().join("root.raw"))
            .unwrap()
            .set_len(disk_length)
            .unwrap();
        let mut spec = vm_spec::VmSpec::current();
        spec.hardware = Some(vm_spec::Hardware {
            cpus: Some(1),
            memory: Some(1),
            nested_virtualization: Some(false),
            rosetta: Some(false),
        });
        spec.storage = Some(vm_spec::Storage {
            disks: vec![vm_spec::Disk {
                path: "root.raw".into(),
                role: vm_spec::DiskRole::Root,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: disk_length,
                    logical_sector_size: 512,
                },
                block_id: vm_spec::BlockId::new("exact-native-root-id").unwrap(),
                read_only: false,
            }],
        });
        if include_data {
            let external = OwnedDirectory::open_root(&temporary.path().join("external")).unwrap();
            external.write_file("data.raw", &[0x51; 512]).unwrap();
            spec.storage.as_mut().unwrap().disks.push(vm_spec::Disk {
                path: external.path().join("data.raw"),
                role: vm_spec::DiskRole::Data,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
                block_id: vm_spec::BlockId::new("external-data-serial").unwrap(),
                read_only: false,
            });
        }
        let config = MachineConfig {
            secret_scope: crate::SecretScopePolicy::default(),
            id,
            lock_id: LockId::from(0),
            name: "checkpoint-source".into(),
            spec,
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            guest: crate::MachineGuestConfig::default(),
            machine_dir: directory.path().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network: MachineNetworkConfig::default(),
        };
        let run = Uuid::new_v4();
        let state = MachineState {
            machine_id: id,
            status: MachineRuntimeState::Running,
            vmm_pid: None,
            started_at: None,
            run_id: Some(run.to_string()),
            last_error: None,
            updated_at: 1,
        };
        store.add_machine(&config, &state).await.unwrap();
        let mut storage = store.machine_storage(id).await.unwrap().unwrap();
        if let crate::MachineRoot::OpaqueRaw { geometry, .. } = &mut storage.root {
            geometry.length = disk_length;
        }
        let file = std::fs::File::open(directory.path().join("root.raw")).unwrap();
        let map = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_open_file(&file, disk_length)
            .unwrap()
            .map;
        let baseline_roots = crate::machine::root_storage::seed_disk(
            &mut storage,
            &StoragePool::open(&store.images_dir).unwrap(),
            directory.path(),
            0,
            &config.spec.storage.as_ref().unwrap().disks[0],
            &file,
            &map,
        )
        .unwrap();
        store
            .save_machine_config_with_storage(&config, &storage)
            .await
            .unwrap();
        drop(baseline_roots);
        let launch = store
            .register_launch_storage(id, run, &storage, &config.spec)
            .await
            .unwrap();
        store
            .mark_launch_storage_admitted(launch.operation_id())
            .await
            .unwrap();
        let snapshots = SnapshotStore::from_store(Arc::new(store));
        let request = CaptureReservationRequest {
            machine_id: id,
            run_id: run,
            capture_id: Uuid::new_v4(),
            configuration: CaptureConfiguration::from_spec(&config.spec).unwrap(),
            alias: if fork {
                None
            } else {
                Some("checkpoint".into())
            },
            policy,
            dirty_crossover_percent: 60,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseAuthority::Acquire,
        };
        if fork {
            let options = crate::store::fork::tests::options(&["fork-first", "fork-second"]);
            let observed = crate::store::fork::tests::observation(id, run);
            drop(
                snapshots
                    .store
                    .admit_fork(id, &observed, &options, request.capture_id)
                    .await
                    .unwrap(),
            );
        }
        let reservation = snapshots.reserve_capture(&request).await.unwrap();
        snapshots
            .bind_capture_boot(request.capture_id, storage.boot.clone())
            .await
            .unwrap();
        Fixture {
            _temporary: temporary,
            snapshots,
            config,
            reservation,
            launch,
        }
    }

    // Only the public header is constructed here. Opaque bytes deliberately
    // carry no claim of native restore validity or a successful hypervisor cut.
    fn native_header_fixture(
        execution: bool,
        binding: &CaptureStateBinding,
        plan: &vm_spec::capture::CapturePlan,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(if execution { b"KRUNEXEC" } else { b"KRUNDEVS" });
        bytes.extend_from_slice(&1u16.to_le_bytes());
        if execution {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.push(1);
        }
        bytes.extend_from_slice(&(binding.live_state_schema.len() as u32).to_le_bytes());
        bytes.extend_from_slice(binding.live_state_schema.as_bytes());
        bytes.extend_from_slice(&(binding.architecture.len() as u32).to_le_bytes());
        bytes.extend_from_slice(binding.architecture.as_bytes());
        for digest in [binding.profile, binding.topology, binding.ram_layout] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(
            Uuid::parse_str(binding.source_run.as_str())
                .unwrap()
                .as_bytes(),
        );
        bytes.extend_from_slice(&binding.pause_generation.get().to_le_bytes());
        bytes.extend_from_slice(
            Uuid::parse_str(binding.capture.as_str())
                .unwrap()
                .as_bytes(),
        );
        if execution {
            bytes.extend_from_slice(&u32::from(plan.configuration.cpus).to_le_bytes());
            for index in 0..plan.configuration.cpus {
                bytes.push(index);
                bytes.extend_from_slice(&u64::from(index).to_le_bytes());
            }
            bytes.extend_from_slice(&4096u32.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&4096u64.to_le_bytes());
            bytes.extend_from_slice(&(plan.configuration.attachments.len() as u32).to_le_bytes());
            for (index, attachment) in plan.configuration.attachments.iter().enumerate() {
                bytes.extend_from_slice(&2u32.to_le_bytes());
                bytes.extend_from_slice(&(attachment.block_id.as_str().len() as u32).to_le_bytes());
                bytes.extend_from_slice(attachment.block_id.as_str().as_bytes());
                bytes.extend_from_slice(&(0x1000 + index as u64 * 0x1000).to_le_bytes());
                bytes.extend_from_slice(&(5 + index as u32).to_le_bytes());
            }
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(
                b"opaque hypervisor payload, not validated by the header reader",
            );
        } else {
            bytes.extend_from_slice(&(plan.configuration.attachments.len() as u32).to_le_bytes());
            for (index, attachment) in plan.configuration.attachments.iter().enumerate() {
                let id = attachment.block_id.as_str().as_bytes();
                bytes.extend_from_slice(&(id.len() as u32).to_le_bytes());
                bytes.extend_from_slice(id);
                bytes.extend_from_slice(&2u32.to_le_bytes());
                bytes.extend_from_slice(&5u32.to_le_bytes());
                bytes.extend_from_slice(b"block");
                bytes.extend_from_slice(&(0x1000 + index as u64 * 0x1000).to_le_bytes());
                bytes.extend_from_slice(&(5 + index as u32).to_le_bytes());
                bytes.extend_from_slice(&[0; 16 + 28 + 1]);
                bytes.extend_from_slice(&0u32.to_le_bytes());
                let payload = b"opaque device payload";
                bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                bytes.extend_from_slice(payload);
            }
        }
        bytes
    }

    pub(crate) fn seal(fixture: &Fixture) -> (OwnedDirectory, CaptureEvidence) {
        let record = &fixture.reservation.record;
        let machine = OwnedDirectory::open_existing_root(&fixture.config.machine_dir)
            .unwrap()
            .unwrap();
        let captures = machine.ensure_dir("captures").unwrap();
        let directory = captures.ensure_dir(&record.capture_id.to_string()).unwrap();
        let disks = directory.ensure_dir("disks").unwrap();
        let request = record.plan.canonical_bytes().unwrap();
        directory.write_file("request.json", &request).unwrap();
        let layout = serde_json::to_vec(&serde_json::json!({
            "architecture": "x86_64", "kind": "ram-layout", "magic": "KRUNRAML", "packedLength": 4096, "pageGranule": 4096,
            "regions": [{"guestPhysicalAddress": 0, "length": 4096, "streamOffset": 0}],
            "schema": 1, "topology": {"firmwareAddress": 0, "initrdAddress": 0, "ramAboveGap": 0, "ramBelowGap": 4096, "ramLastAddress": 4095, "shmStartAddress": 0}
        })).unwrap();
        let ram = vec![0x32; 4096];
        let ram_map = StreamHasher::new(vm_spec::stream_map::ChunkSize::RAM)
            .hash_reader(Cursor::new(&ram))
            .unwrap();
        let ram_map_bytes = ram_map.canonical_bytes().unwrap();
        let binding = CaptureStateBinding {
            live_state_schema: "silo.live-state/1".into(),
            architecture: "x86_64".into(),
            profile: Sha256Digest::of_bytes(b"profile"),
            topology: record.plan.configuration_digest,
            ram_layout: Sha256Digest::of_bytes(&layout),
            source_run: record.plan.run_id.clone(),
            pause_generation: NonZeroU64::new(1).unwrap(),
            capture: record.plan.capture_id.clone(),
        };
        let native_execution = native_header_fixture(true, &binding, &record.plan);
        let native_devices = native_header_fixture(false, &binding, &record.plan);
        let mut inventory = Vec::new();
        let disk_map = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_reader(Cursor::new([0x51; 512]))
            .unwrap();
        let disk_map_bytes = disk_map.canonical_bytes().unwrap();
        crate::store::capture::stage_map_nodes(&directory, &ram_map).unwrap();
        crate::store::capture::stage_map_nodes(&directory, &disk_map).unwrap();
        let mut changes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0".to_vec();
        changes.extend_from_slice(&0u64.to_le_bytes());
        changes.extend_from_slice(&1u64.to_le_bytes());
        changes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        changes.extend_from_slice(Sha256Digest::of_bytes(&ram).as_bytes());
        for role in record.plan.roles() {
            let bytes: &[u8] = match &role {
                CaptureRole::Execution => &native_execution,
                CaptureRole::Devices => &native_devices,
                CaptureRole::Ram => &ram,
                CaptureRole::Layout => &layout,
                CaptureRole::RamMap => &ram_map_bytes,
                CaptureRole::RamChanges => &changes,
                CaptureRole::Disk(_) => &[0x51; 512],
                CaptureRole::DiskMap(_) => &disk_map_bytes,
            };
            match &role {
                CaptureRole::Disk(name) => disks.write_file(&name.file_name(), bytes).unwrap(),
                CaptureRole::DiskMap(name) => disks
                    .write_file(&format!("{}.root", name.as_str()), bytes)
                    .unwrap(),
                _ => directory.write_file(&role.relative_path(), bytes).unwrap(),
            }
            inventory.push(CaptureInventoryEntry {
                role: role.clone(),
                length: bytes.len() as u64,
                sha256: if matches!(role, CaptureRole::Ram | CaptureRole::Disk(_)) {
                    None
                } else {
                    Some(Sha256Digest::of_bytes(bytes))
                },
                identity: match &role {
                    CaptureRole::Ram => Some(Sha256Digest::from_bytes(*ram_map.id().as_bytes())),
                    CaptureRole::Disk(_) => {
                        Some(Sha256Digest::from_bytes(*disk_map.id().as_bytes()))
                    }
                    _ => None,
                },
            });
        }
        let evidence = CaptureEvidence {
            disk_stats: Vec::new(),
            disk_tracking_receipts: Vec::new(),
            version: vm_spec::capture::CAPTURE_RECORD_VERSION,
            machine_id: record.plan.machine_id.clone(),
            run_id: record.plan.run_id.clone(),
            capture_id: record.plan.capture_id.clone(),
            pause_token: Some(PauseToken {
                machine_id: record.plan.machine_id.clone(),
                run_id: record.plan.run_id.clone(),
                generation: NonZeroU64::new(1).unwrap(),
                owner: PauseOwner::Capture {
                    operation_id: record.plan.capture_id.clone(),
                },
            }),
            pause_disposition: Some(CapturePauseDisposition::Acquired),
            freeze_epoch: NonZeroU64::new(1),
            freeze_operation_id: Some(record.plan.capture_id.clone()),
            configuration_digest: record.plan.configuration_digest,
            request_digest: Sha256Digest::of_bytes(&request),
            memory: Some(CaptureMemoryEvidence {
                packed_length: 4096,
                page_granule: 4096,
                regions: 1,
                ram_stream: Sha256Digest::from_bytes(*ram_map.id().as_bytes()),
                binding,
                mode: CapturePolicy::Full,
                baseline: None,
                full_reason: Some(match record.plan.policy {
                    CapturePolicy::Full => vm_spec::capture::CaptureFullReason::Requested,
                    CapturePolicy::Incremental => vm_spec::capture::CaptureFullReason::NoBaseline,
                }),
                identity_chunk_bytes: 1 << 16,
                changes: vm_spec::capture::CaptureRamChanges {
                    byte_len: changes.len() as u64,
                    sha256: Sha256Digest::of_bytes(&changes),
                    record_count: 1,
                    coverage: vm_spec::capture::CaptureRamCoverage::Full,
                    baseline_stream: None,
                },
                stats: vm_spec::capture::CaptureMemoryStats {
                    logical_bytes: 4096,
                    live_bytes_read: 4096,
                    full_bytes_written: 4096,
                    identity_bytes_hashed: 4096,
                    whole_file_bytes_hashed: 0,
                    ..Default::default()
                },
            }),
            inventory,
            started_at_unix_ms: 1,
            completed_at_unix_ms: 2,
            capture_outcome: CaptureRecordOutcome::Coherent,
            error: None,
            workloads_frozen: true,
            vcpus_paused: true,
            devices_quiesced: true,
            host_writers_drained: true,
            host_flush_completed: true,
            disk_copies_sealed: true,
            memory_state_sealed: true,
        };
        evidence
            .validate_against_plan(&record.plan, &Sha256Digest::of_bytes(&request))
            .unwrap();
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        (directory, evidence)
    }

    #[tokio::test]
    async fn sparse_capture_reserves_allocated_disk_bytes_for_staging_and_publication() {
        let length = 100 << 30;
        let fixture =
            fixture_source_with_disk_length(false, false, CapturePolicy::Full, length).await;
        let metadata = std::fs::metadata(fixture.config.machine_dir.join("root.raw")).unwrap();
        let allocated = metadata.blocks().checked_mul(512).unwrap();
        assert_eq!(metadata.len(), length);
        assert!(allocated > 0 && allocated < length / 1000);
        let record = &fixture.reservation.record;
        let maps = crate::store::capture::capture_map_budget(&record.plan.configuration).unwrap();
        let changes = record
            .plan
            .ram_bytes
            .div_ceil(vm_spec::stream_map::ChunkSize::RAM.bytes())
            * 56
            + 16;
        let state = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        assert_eq!(
            record.plan.reservation.staging_bytes,
            record.plan.ram_bytes + allocated + state + maps + changes
        );
        assert_eq!(
            record.reservation_bytes,
            record.plan.ram_bytes
                + allocated
                + state
                + maps
                + changes
                + crate::store::capture::publication_stream_bytes(
                    record.plan.ram_bytes,
                    record
                        .publication_clones
                        .contains(&CaptureRole::Ram.relative_path())
                )
                + crate::store::capture::publication_stream_bytes(
                    allocated,
                    record.publication_clones.contains(
                        &CaptureRole::Disk(record.plan.disks[0].name.clone()).relative_path()
                    )
                )
                + 2 * state
                + 2 * maps
                + changes
        );
        assert_eq!(record.disk_charges.len(), 1);
        assert_eq!(record.disk_charges[0].bytes, record.reservation_bytes);
        assert_eq!(record.disk_allocations[&0], allocated);
        assert_eq!(
            crate::store::capture::decode_record(
                &crate::store::capture::encode_record(record).unwrap()
            )
            .unwrap()
            .disk_allocations,
            record.disk_allocations
        );
    }

    #[tokio::test]
    async fn capture_disk_allocations_reject_missing_foreign_overflowing_and_changed_samples() {
        use crate::store::capture::encode_record;

        let fixture = fixture_with_external_data(true).await;
        let original = &fixture.reservation.record;
        for fault in ["missing", "foreign", "overflow", "changed"] {
            let mut record = original.clone();
            match fault {
                "missing" => {
                    record.disk_allocations.remove(&0);
                }
                "foreign" => {
                    let bytes = record.disk_allocations.remove(&0).unwrap();
                    record.disk_allocations.insert(99, bytes);
                }
                "overflow" => {
                    record.disk_allocations.insert(0, u64::MAX);
                }
                "changed" => {
                    *record.disk_allocations.get_mut(&0).unwrap() += 512;
                }
                _ => unreachable!(),
            }
            assert!(encode_record(&record).is_err(), "{fault}");
        }
    }

    #[tokio::test]
    async fn capture_validation_matches_plain_and_fork_ownership() {
        use crate::store::capture::{decode_record, encode_record};

        for fork in [false, true] {
            let fixture = if fork {
                fork_fixture().await
            } else {
                fixture().await
            };
            let mut record = fixture.reservation.record.clone();
            assert!(decode_record(&encode_record(&record).unwrap()).is_ok());
            record.fork_operation_id = if fork { None } else { Some(Uuid::new_v4()) };
            let error = fixture
                .snapshots
                .store
                .reserve_capture_inventory(&record, None)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("capture fork owner contradicts its reservation"),
                "{error}"
            );
            let error = fixture
                .snapshots
                .store
                .complete_capture_peak(&record)
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("capture fork owner contradicts its reservation"),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn paused_capture_persists_resolved_preserve_policy_for_snapshots_and_forks() {
        use crate::machine::live::MachineLiveObservation;
        use vm_spec::lifecycle::{
            CurrentPause, LiveLifecycle, PauseOwner, PauseToken, VmLifecycleState,
        };

        for fork in [false, true] {
            let fixture = fixture().await;
            let mut request = fixture.reservation.record.request.clone();
            fixture
                .snapshots
                .abandon_capture(request.capture_id)
                .await
                .unwrap();
            request.capture_id = Uuid::new_v4();
            request.alias = None;
            let base = crate::store::fork::tests::observation(request.machine_id, request.run_id);
            let mut report = base.report().clone();
            report.live.capture = vm_spec::live::LiveCapability {
                native: true,
                availability: vm_spec::live::LiveAvailability::Supported,
            };
            let current = CurrentPause {
                operation_id: LiveId::parse(&Uuid::new_v4().to_string()).unwrap(),
                token: PauseToken {
                    machine_id: LiveId::parse(&Uuid::from(request.machine_id).to_string()).unwrap(),
                    run_id: LiveId::parse(&request.run_id.to_string()).unwrap(),
                    generation: NonZeroU64::new(3).unwrap(),
                    owner: PauseOwner::User,
                },
                freeze_epoch: NonZeroU64::new(4).unwrap(),
            };
            let observation = MachineLiveObservation::for_test(
                report,
                VmLifecycleState::Paused,
                LiveLifecycle {
                    current_pause: Some(current.clone()),
                    ..Default::default()
                },
            );
            let (pause, resume_policy) =
                crate::machine::live_capture::admission(&observation, request.resume_policy)
                    .unwrap();
            assert_eq!(request.resume_policy, CaptureResumePolicy::ResumeIfAcquired);
            assert_eq!(resume_policy, CaptureResumePolicy::Preserve);
            request.pause = pause;
            request.resume_policy = resume_policy;
            let _fork_owner = if fork {
                let options = crate::store::fork::tests::options(&["borrowed-pause-child"]);
                let (result, owner) = fixture
                    .snapshots
                    .store
                    .admit_fork(
                        request.machine_id,
                        &observation,
                        &options,
                        request.capture_id,
                    )
                    .await
                    .unwrap();
                assert_eq!(result.resume_policy, CaptureResumePolicy::Preserve);
                assert_eq!(
                    fixture
                        .snapshots
                        .store
                        .fork_options(options.operation_id)
                        .await
                        .unwrap(),
                    options,
                );
                assert_eq!(
                    fixture
                        .snapshots
                        .store
                        .fork_result(options.operation_id)
                        .await
                        .unwrap()
                        .unwrap(),
                    result,
                );
                Some(owner)
            } else {
                None
            };
            let _reservation = fixture.snapshots.reserve_capture(&request).await.unwrap();
            let stored = fixture
                .snapshots
                .capture_reservation(request.capture_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.plan.resume_policy, CaptureResumePolicy::Preserve);
            assert_eq!(
                stored.plan.pause,
                CapturePauseAuthority::Borrow {
                    pause_operation_id: current.operation_id,
                    token: current.token,
                },
            );
            stored.plan.validate().unwrap();
            let mut invalid = stored.plan;
            invalid.resume_policy = CaptureResumePolicy::ResumeIfAcquired;
            assert!(invalid.validate().is_err());
        }
    }

    #[tokio::test]
    async fn checkpoint_reservation_replay_pins_exact_launch_and_rejects_changed_intent() {
        let fixture = fixture().await;
        let request = fixture.reservation.record.request.clone();
        let replay = fixture.snapshots.reserve_capture(&request).await.unwrap();
        assert_eq!(replay.record.plan, fixture.reservation.record.plan);
        assert_eq!(
            replay._lease.file_identity().unwrap(),
            fixture.reservation._lease.file_identity().unwrap()
        );
        assert_eq!(
            replay
                .record
                .plan
                .reservation
                .launch_lease
                .operation_id
                .to_string(),
            fixture.launch.operation_id().to_string()
        );
        assert!(replay.record.reservation_bytes > replay.record.plan.reservation.staging_bytes);
        assert_eq!(
            replay
                .record
                .configuration
                .spec
                .storage
                .as_ref()
                .unwrap()
                .disks[0]
                .block_id
                .as_str(),
            "exact-native-root-id"
        );
        let mut changed = request;
        changed.resume_policy = CaptureResumePolicy::Preserve;
        assert!(fixture.snapshots.reserve_capture(&changed).await.is_err());
        assert!(fixture
            .snapshots
            .machine_capture_retained(fixture.config.id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn restore_consumer_uses_authenticated_local_seal_without_source_request_paths() {
        let fixture = fixture_with_external_data(true).await;
        let (directory, _) = seal(&fixture);
        let result = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let mut consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(result.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join(vm_spec::capture::CAPTURE_REQUEST_FILE),
        )
        .unwrap();
        let evidence = fixture
            .snapshots
            .restore_evidence(&consumer, &pool)
            .unwrap();
        assert_eq!(
            evidence.evidence.freeze_operation_id.as_ref(),
            Some(&fixture.reservation.record.plan.capture_id)
        );
        assert_eq!(
            consumer
                .record
                .configuration
                .spec
                .storage
                .as_ref()
                .unwrap()
                .disks[1]
                .block_id
                .as_str(),
            "external-data-serial"
        );
        let saved = consumer.record.configuration.spec.clone();
        consumer
            .record
            .configuration
            .spec
            .hardware
            .as_mut()
            .unwrap()
            .cpus = Some(7);
        assert!(fixture
            .snapshots
            .restore_evidence(&consumer, &pool)
            .is_err());
        consumer.record.configuration.spec = saved;
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &mut consumer.record.capture
        else {
            panic!("execution checkpoint");
        };
        execution
            .compatibility_profile
            .live_state_schema
            .push_str("-different");
        assert!(fixture
            .snapshots
            .restore_evidence(&consumer, &pool)
            .is_err());
        consumer.info.provenance.clear();
        assert!(fixture
            .snapshots
            .restore_evidence(&consumer, &pool)
            .is_err());
    }

    #[tokio::test]
    async fn restore_corrupt_closure_retires_failed_verification_consumer_roots() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let result = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let record =
            crate::store::observation::ObservationStore::existing(&fixture.snapshots.store)
                .snapshot_record(&SnapshotRef::Id(result.id))
                .await
                .unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            record.capture
        else {
            panic!("execution checkpoint");
        };
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        let path = pool.object_path(&execution.devices);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            &path,
            b"corrupt native state, never submitted to native code",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(fixture
            .snapshots
            .consume(&SnapshotRef::Id(result.id))
            .await
            .is_err());
        let imports: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_operation WHERE kind='import'")
                .fetch_one(&fixture.snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(
            imports, 0,
            "failed byte authentication leaked an operation root"
        );
        let reservations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM restore_resource_reservation")
                .fetch_one(&fixture.snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(reservations, 0);
    }

    #[tokio::test]
    async fn checkpoint_seal_publication_survives_source_alias_loss_and_retains_provenance() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let result = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(result.capture_kind, SnapshotCaptureKindName::LiveExecution);
        assert_eq!(result.provenance.len(), 1);
        let evidence_digest = result.provenance[0].evidence_digest;
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(result.id))
            .await
            .unwrap();
        assert_eq!(consumer.record.boot, fixture.launch.storage_record().boot);
        let boot_objects = crate::store::cache_paths::storage_pool_dependencies(
            &fixture.reservation.record.storage,
        )
        .unwrap()
        .objects;
        assert!(!boot_objects.is_empty());
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("not execution");
        };
        let memory = execution.memory.stream;
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        assert_ne!(
            std::fs::metadata(pool.stream_path(&memory)).unwrap().ino(),
            std::fs::metadata(directory.path().join("memory.ram"))
                .unwrap()
                .ino()
        );
        let retry = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(retry, result);
        fixture
            .snapshots
            .record_capture_source(capture, CaptureSourceOutcome::Unknown)
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        assert!(fixture
            .snapshots
            .machine_capture_retained(fixture.config.id)
            .await
            .unwrap());
        let snapshots = fixture.snapshots.clone();
        let config = fixture.config.clone();
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        drop(fixture.reservation);
        drop(fixture.launch);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_none());
        assert!(pool.verify_object(&evidence_digest).is_ok());
        let consumer = snapshots
            .consume(&SnapshotRef::Id(result.id))
            .await
            .unwrap();
        snapshots.remove_alias("checkpoint").await.unwrap();
        snapshots
            .release_retention(&SnapshotRef::Id(result.id))
            .await
            .unwrap();
        let launches = snapshots
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap();
        assert_eq!(launches.len(), 1);
        let launch = &launches[0];
        let mut stopped = snapshots
            .store
            .machine_state(config.id)
            .await
            .unwrap()
            .unwrap();
        stopped.status = MachineRuntimeState::Stopped;
        stopped.run_id = None;
        stopped.updated_at = 2;
        // Closing the fixture's OFD does not reconcile its admitted launch.
        assert!(snapshots
            .store
            .try_retire_launch_storage(
                launch.operation_id,
                launch.run_id,
                launch.storage_generation,
                &stopped,
                crate::StorageStopOutcome::Unknown,
            )
            .await
            .unwrap());
        assert!(snapshots
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
        snapshots.store.remove_machine(&config).await.unwrap();
        std::fs::remove_dir_all(&config.machine_dir).unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(pool.verify_stream(&memory).is_ok());
        assert!(pool.verify_object(&evidence_digest).is_ok());
        for object in &boot_objects {
            assert!(pool.verify_object(object).is_ok());
        }
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&memory).exists());
        assert!(!pool.object_path(&evidence_digest).exists());
        for object in &boot_objects {
            assert!(!pool.object_path(object).exists());
        }
    }

    #[tokio::test]
    async fn checkpoint_unreconciled_capture_survives_generic_recovery_after_owner_loss() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let snapshots = fixture.snapshots.clone();
        let alias = fixture.reservation.record.alias.clone();
        drop(fixture.reservation);
        drop(fixture.launch);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_some());
        assert!(directory.path().join("memory.ram").exists());
        assert!(snapshots
            .publish_capture(
                capture,
                directory.path(),
                alias,
                crate::storage::pool::PublicationLockPolicy::Wait
            )
            .await
            .is_ok());
        assert!(snapshots.abandon_capture(capture).await.is_err());
    }

    #[tokio::test]
    async fn checkpoint_recovery_settles_owned_seal_temporary_before_publication() {
        use vm_spec::capture::{CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE};

        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let final_path = directory.path().join(CAPTURE_EVIDENCE_FILE);
        let temporary_path = directory.path().join(CAPTURE_EVIDENCE_TEMPORARY_FILE);
        std::fs::hard_link(&final_path, &temporary_path).unwrap();
        let before = std::fs::metadata(&final_path).unwrap();
        assert_eq!(before.nlink(), 2);
        let capture = fixture.reservation.record.capture_id;
        let snapshots = fixture.snapshots.clone();
        let alias = fixture.reservation.record.alias.clone();
        drop(fixture.reservation);
        drop(fixture.launch);
        snapshots.store.recover_image_cache().await.unwrap();

        let published = snapshots
            .publish_capture(
                capture,
                directory.path(),
                alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let after = std::fs::metadata(&final_path).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.nlink(), 1);
        assert!(!temporary_path.exists());
        assert_eq!(
            std::fs::read(&final_path).unwrap(),
            evidence.canonical_bytes().unwrap()
        );
        assert_eq!(published.provenance.len(), 1);
        assert_eq!(
            published.provenance[0].evidence_digest,
            ObjectDigest::of_bytes(&evidence.canonical_bytes().unwrap())
        );
        assert!(snapshots
            .inspect(&SnapshotRef::Id(published.id))
            .await
            .is_ok());
        assert_eq!(
            snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    alias,
                    crate::storage::pool::PublicationLockPolicy::Wait
                )
                .await
                .unwrap(),
            published
        );
    }

    #[tokio::test]
    async fn fork_seal_settles_owned_temporary_before_local_retention() {
        use vm_spec::capture::{CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE};

        let fixture = fork_fixture().await;
        let (directory, evidence) = seal(&fixture);
        let final_path = directory.path().join(CAPTURE_EVIDENCE_FILE);
        let temporary_path = directory.path().join(CAPTURE_EVIDENCE_TEMPORARY_FILE);
        std::fs::hard_link(&final_path, &temporary_path).unwrap();
        assert_eq!(std::fs::metadata(&final_path).unwrap().nlink(), 2);

        let (cut, _) = fixture
            .snapshots
            .retain_local_capture(
                fixture.reservation.record.capture_id,
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(cut.evidence, evidence);
        assert_eq!(std::fs::metadata(&final_path).unwrap().nlink(), 1);
        assert!(!temporary_path.exists());
        assert!(fixture.snapshots.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkpoint_recovery_refuses_foreign_seal_links_without_removing_names() {
        use vm_spec::capture::{CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE};

        for fault in [
            "different-name",
            "different-directory",
            "wrong-temporary",
            "third-link",
        ] {
            let fixture = fixture().await;
            let (directory, evidence) = seal(&fixture);
            let final_path = directory.path().join(CAPTURE_EVIDENCE_FILE);
            let temporary_path = directory.path().join(CAPTURE_EVIDENCE_TEMPORARY_FILE);
            let extra_path = match fault {
                "different-directory" => fixture
                    .config
                    .machine_dir
                    .join(CAPTURE_EVIDENCE_TEMPORARY_FILE),
                "third-link" => {
                    std::fs::hard_link(&final_path, &temporary_path).unwrap();
                    fixture.config.machine_dir.join("foreign-seal")
                }
                _ => directory.path().join("foreign-seal"),
            };
            std::fs::hard_link(&final_path, &extra_path).unwrap();
            if fault == "wrong-temporary" {
                directory
                    .write_file(CAPTURE_EVIDENCE_TEMPORARY_FILE, b"foreign temporary")
                    .unwrap();
            }
            let before = std::fs::metadata(&final_path).unwrap();
            let capture = fixture.reservation.record.capture_id;
            let snapshots = fixture.snapshots.clone();
            let alias = fixture.reservation.record.alias.clone();
            drop(fixture.reservation);
            drop(fixture.launch);
            snapshots.store.recover_image_cache().await.unwrap();

            assert!(
                snapshots
                    .publish_capture(
                        capture,
                        directory.path(),
                        alias,
                        crate::storage::pool::PublicationLockPolicy::Wait
                    )
                    .await
                    .is_err(),
                "{fault}"
            );
            let after = std::fs::metadata(&final_path).unwrap();
            assert_eq!(
                (after.dev(), after.ino()),
                (before.dev(), before.ino()),
                "{fault}"
            );
            assert_eq!(after.nlink(), before.nlink(), "{fault}");
            assert_eq!(
                std::fs::metadata(&extra_path).unwrap().ino(),
                before.ino(),
                "{fault}"
            );
            assert_eq!(
                std::fs::read(&final_path).unwrap(),
                evidence.canonical_bytes().unwrap(),
                "{fault}"
            );
            match fault {
                "wrong-temporary" => assert_eq!(
                    std::fs::read(&temporary_path).unwrap(),
                    b"foreign temporary"
                ),
                "third-link" => assert_eq!(std::fs::metadata(&temporary_path).unwrap().nlink(), 3),
                _ => assert!(!temporary_path.exists(), "{fault}"),
            }
            assert!(snapshots.list().await.unwrap().is_empty(), "{fault}");
            assert!(
                snapshots
                    .capture_reservation(capture)
                    .await
                    .unwrap()
                    .is_some(),
                "{fault}"
            );
        }
    }

    #[tokio::test]
    async fn checkpoint_recovery_keeps_request_control_record_singleton() {
        use vm_spec::capture::CAPTURE_REQUEST_FILE;

        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let request = directory.path().join(CAPTURE_REQUEST_FILE);
        let extra = fixture.config.machine_dir.join("foreign-request");
        std::fs::hard_link(&request, &extra).unwrap();
        assert!(fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .is_err());
        assert_eq!(std::fs::metadata(request).unwrap().nlink(), 2);
        assert!(extra.exists());
        assert!(fixture.snapshots.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn checkpoint_native_binding_changes_exact_objects_not_compatibility_or_disk_identity() {
        let mut fixture = fixture().await;
        let (first_directory, _) = seal(&fixture);
        let first_capture = fixture.reservation.record.capture_id;
        let first = fixture
            .snapshots
            .publish_capture(
                first_capture,
                first_directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(first_capture, true)
            .await
            .unwrap();
        let mut request = fixture.reservation.record.request.clone();
        request.capture_id = Uuid::new_v4();
        request.alias = Some("checkpoint-two".into());
        let replacement = fixture.snapshots.reserve_capture(&request).await.unwrap();
        let boot = fixture
            .snapshots
            .capture_reservation(first_capture)
            .await
            .unwrap()
            .unwrap()
            .captured_boot
            .unwrap();
        let crate::BootProfile::LinuxDirect {
            binding:
                binding @ crate::BootBinding::Pinned {
                    kernel,
                    base_initramfs,
                    agent,
                    ..
                },
            ..
        } = &boot
        else {
            panic!("boot");
        };
        let mut objects = vec![*kernel, *base_initramfs];
        objects.extend(agent.iter().copied());
        objects.push(binding.digest().unwrap());
        fixture
            .snapshots
            .store
            .pin_published_storage_dependencies(request.capture_id, &[], &objects)
            .await
            .unwrap();
        fixture
            .snapshots
            .bind_capture_boot(request.capture_id, boot)
            .await
            .unwrap();
        fixture.reservation = replacement;
        let (second_directory, _) = seal(&fixture);
        let second = fixture
            .snapshots
            .publish_capture(
                request.capture_id,
                second_directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(first.provenance.len(), 1);
        assert_eq!(second.provenance.len(), 1);
        let first_record = fixture
            .snapshots
            .consume(&SnapshotRef::Id(first.id))
            .await
            .unwrap();
        let second_record = fixture
            .snapshots
            .consume(&SnapshotRef::Id(second.id))
            .await
            .unwrap();
        assert_eq!(first_record.record.root, second_record.record.root);
        assert_eq!(
            first_record.record.configuration,
            second_record.record.configuration
        );
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution {
            execution: first_execution,
        } = &first_record.record.capture
        else {
            panic!("execution");
        };
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution {
            execution: second_execution,
        } = &second_record.record.capture
        else {
            panic!("execution");
        };
        assert_eq!(first_execution.memory, second_execution.memory);
        assert_eq!(
            first_execution.compatibility_profile,
            second_execution.compatibility_profile
        );
        assert_ne!(first_execution.execution, second_execution.execution);
        assert_ne!(first_execution.devices, second_execution.devices);
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(first_capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Released {
                snapshot: Some(first.id)
            }
        );
    }

    #[tokio::test]
    async fn checkpoint_valid_seal_remains_publishable_when_source_continuation_fails() {
        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let result = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let source = vm_spec::capture::CaptureSourceRecord {
            version: vm_spec::capture::CAPTURE_RECORD_VERSION,
            machine_id: evidence.machine_id,
            run_id: evidence.run_id,
            capture_id: evidence.capture_id,
            pause_token: evidence.pause_token.unwrap(),
            source_outcome: vm_spec::capture::CaptureSourceOutcome::ResumeFailed,
            error: Some(vm_spec::lifecycle::Diagnostic::new(
                "source continuation failed",
            )),
            current_pause: None,
            completed_at_unix_ms: 3,
        };
        fixture
            .snapshots
            .record_capture_source(
                capture,
                CaptureSourceOutcome::Known {
                    record: source.clone(),
                },
            )
            .await
            .unwrap();
        let retained = fixture
            .snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.state,
            CaptureState::Published {
                snapshot: result.id
            }
        );
        assert_eq!(
            retained.source_outcome,
            Some(CaptureSourceOutcome::Known { record: source })
        );
        assert!(fixture
            .snapshots
            .inspect(&SnapshotRef::Id(result.id))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn checkpoint_verification_rejects_changed_bytes_unlisted_files_hardlinks_and_symlinks() {
        for fault in ["bytes", "extra", "hardlink", "symlink", "request"] {
            let fixture = fixture().await;
            let (directory, _) = seal(&fixture);
            match fault {
                "bytes" => directory.write_file("memory.ram", &[0x77; 4096]).unwrap(),
                "extra" => directory.write_file("unlisted", b"not admitted").unwrap(),
                "hardlink" => std::fs::hard_link(
                    directory.path().join("memory.ram"),
                    fixture.config.machine_dir.join("alias"),
                )
                .unwrap(),
                "symlink" => {
                    std::fs::remove_file(directory.path().join("memory.ram")).unwrap();
                    std::os::unix::fs::symlink(
                        fixture.config.machine_dir.join("root.raw"),
                        directory.path().join("memory.ram"),
                    )
                    .unwrap();
                }
                _ => directory.write_file("request.json", b"{}").unwrap(),
            }
            {
                let disks = CaptureAuthentication::Bytes;
                assert!(
                    verify_capture(&directory, &fixture.reservation.record, disks).is_err(),
                    "{fault} {disks:?}"
                );
            }
            assert!(fixture.snapshots.list().await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn checkpoint_native_headers_reject_corruption_foreign_bindings_and_geometry_even_with_valid_sha(
    ) {
        let schema_len = "silo.live-state/1".len();
        let architecture_len = "x86_64".len();
        let execution_binding = 19 + schema_len + 4 + architecture_len;
        let devices_binding = execution_binding - 5;
        for (fault, role, offset) in [
            ("execution-version", CaptureRole::Execution, 8),
            ("execution-abi", CaptureRole::Execution, 10),
            ("execution-lane", CaptureRole::Execution, 14),
            ("schema", CaptureRole::Execution, 19),
            ("architecture", CaptureRole::Execution, 23 + schema_len),
            ("profile", CaptureRole::Execution, execution_binding),
            ("topology", CaptureRole::Execution, execution_binding + 32),
            (
                "layout-binding",
                CaptureRole::Execution,
                execution_binding + 64,
            ),
            ("source-run", CaptureRole::Execution, execution_binding + 96),
            (
                "pause-generation",
                CaptureRole::Execution,
                execution_binding + 112,
            ),
            (
                "capture-id",
                CaptureRole::Execution,
                execution_binding + 120,
            ),
            ("cpu-count", CaptureRole::Execution, execution_binding + 136),
            (
                "page-granule",
                CaptureRole::Execution,
                execution_binding + 149,
            ),
            (
                "guest-region",
                CaptureRole::Execution,
                execution_binding + 157,
            ),
            ("block-id", CaptureRole::Execution, execution_binding + 185),
            ("devices-version", CaptureRole::Devices, 8),
            ("devices-profile", CaptureRole::Devices, devices_binding),
            ("devices-count", CaptureRole::Devices, devices_binding + 136),
            ("truncated", CaptureRole::Execution, 0),
        ] {
            let fixture = fixture().await;
            let (directory, mut evidence) = seal(&fixture);
            {
                let disks = CaptureAuthentication::Bytes;
                assert!(verify_capture(&directory, &fixture.reservation.record, disks).is_ok());
            }
            let mut bytes = std::fs::read(directory.path().join(role.relative_path())).unwrap();
            if fault == "truncated" {
                bytes.truncate(20);
            } else {
                bytes[offset] ^= 0x40;
            }
            directory.write_file(&role.relative_path(), &bytes).unwrap();
            let entry = evidence
                .inventory
                .iter_mut()
                .find(|entry| entry.role == role)
                .unwrap();
            entry.length = bytes.len() as u64;
            entry.sha256 = Some(Sha256Digest::of_bytes(&bytes));
            directory
                .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
                .unwrap();
            {
                let disks = CaptureAuthentication::Bytes;
                assert!(
                    verify_capture(&directory, &fixture.reservation.record, disks).is_err(),
                    "{fault} {disks:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn checkpoint_rejects_consistent_foreign_native_layout_and_topology() {
        for fault in ["topology", "layout-binding", "layout-bytes"] {
            let fixture = fixture().await;
            let (directory, mut evidence) = seal(&fixture);
            if fault == "layout-bytes" {
                let path = directory.path().join("memory-layout.json");
                let mut layout: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                layout["topology"]["initrdAddress"] = serde_json::json!(4096);
                let bytes = serde_json::to_vec(&layout).unwrap();
                directory.write_file("memory-layout.json", &bytes).unwrap();
            } else {
                let binding = &mut evidence.memory.as_mut().unwrap().binding;
                if fault == "topology" {
                    binding.topology = Sha256Digest::of_bytes(b"foreign topology");
                } else {
                    binding.ram_layout = Sha256Digest::of_bytes(b"foreign layout");
                }
                for (execution, role) in [
                    (true, CaptureRole::Execution),
                    (false, CaptureRole::Devices),
                ] {
                    let bytes =
                        native_header_fixture(execution, binding, &fixture.reservation.record.plan);
                    directory.write_file(&role.relative_path(), &bytes).unwrap();
                }
            }
            for entry in &mut evidence.inventory {
                let bytes =
                    std::fs::read(directory.path().join(entry.role.relative_path())).unwrap();
                entry.length = bytes.len() as u64;
                if entry.sha256.is_some() {
                    entry.sha256 = Some(Sha256Digest::of_bytes(&bytes));
                }
            }
            directory
                .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
                .unwrap();
            {
                let disks = CaptureAuthentication::Bytes;
                assert!(
                    verify_capture(&directory, &fixture.reservation.record, disks).is_err(),
                    "{fault} {disks:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn checkpoint_lanes_keep_inventory_order_and_held_inodes_and_reject_either_lane() {
        let sealed = fixture().await;
        let record = &sealed.reservation.record;
        let (directory, evidence) = seal(&sealed);
        {
            let disks = CaptureAuthentication::Bytes;
            let verified = verify_capture(&directory, record, disks).unwrap();
            assert_eq!(
                verified
                    .files
                    .iter()
                    .map(|payload| payload.role.clone())
                    .collect::<Vec<_>>(),
                evidence
                    .inventory
                    .iter()
                    .map(|entry| entry.role.clone())
                    .collect::<Vec<_>>(),
                "{disks:?}"
            );
            for payload in &verified.files {
                let held = payload.file().metadata().unwrap();
                let named =
                    std::fs::metadata(directory.path().join(payload.role.relative_path())).unwrap();
                assert_eq!((held.dev(), held.ino()), (named.dev(), named.ino()));
                assert_eq!(payload.length, held.len());
                assert_eq!(
                    matches!(payload.bytes, VerifiedBytes::Stream(_)),
                    matches!(payload.role, CaptureRole::Ram | CaptureRole::Disk(_)),
                    "{disks:?} {:?}",
                    payload.role
                );
            }
        }
        let disk = evidence
            .inventory
            .iter()
            .find(|entry| matches!(entry.role, CaptureRole::Disk(_)))
            .unwrap()
            .role
            .relative_path();
        // Same-length corruption in the RAM lane, the other lane, or both.
        for fault in ["ram", "disk", "execution", "ram-and-disk"] {
            let fixture = fixture().await;
            let (directory, _) = seal(&fixture);
            if fault.starts_with("ram") {
                directory.write_file("memory.ram", &[0x77; 4096]).unwrap();
            }
            if fault.ends_with("disk") {
                std::fs::write(directory.path().join(&disk), [0x52; 512]).unwrap();
            }
            if fault == "execution" {
                let path = CaptureRole::Execution.relative_path();
                let mut bytes = std::fs::read(directory.path().join(&path)).unwrap();
                bytes[0] ^= 0x40;
                directory.write_file(&path, &bytes).unwrap();
            }
            {
                let disks = CaptureAuthentication::Bytes;
                let error = verify_capture(&directory, &fixture.reservation.record, disks)
                    .err()
                    .unwrap();
                assert!(
                    error.to_string().contains(if fault == "execution" {
                        "capture staged payload digest mismatch"
                    } else {
                        "capture staged stream identity mismatch"
                    }),
                    "{fault} {disks:?}: {error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn checkpoint_rejects_the_writable_source_inode_as_a_staged_role_before_hashing() {
        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let disk = evidence
            .inventory
            .iter()
            .find(|entry| matches!(entry.role, CaptureRole::Disk(_)))
            .unwrap();
        // The live source has exactly the sealed disk bytes, so only the
        // source-inode alias check, not a digest, can refuse it.
        let source = fixture.config.machine_dir.join("root.raw");
        assert_eq!(
            Some(Sha256Digest::from_bytes(
                *StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
                    .hash_reader(Cursor::new(std::fs::read(&source).unwrap()))
                    .unwrap()
                    .id()
                    .as_bytes()
            )),
            disk.identity
        );
        std::fs::rename(&source, directory.path().join(disk.role.relative_path())).unwrap();
        {
            let disks = CaptureAuthentication::Bytes;
            let error = verify_capture(&directory, &fixture.reservation.record, disks)
                .err()
                .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("capture output geometry, alias or hardlink violation"),
                "{disks:?}: {error}"
            );
        }
    }

    /// Bounded wait for the sibling's stop request; never hangs a test.
    fn wait_for_stop(stop: &std::sync::atomic::AtomicBool) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        true
    }

    #[cfg(target_os = "linux")]
    fn admit<'a>(entry: &'a CaptureInventoryEntry, path: &std::path::Path) -> AdmittedPayload<'a> {
        let file = std::fs::File::open(path).unwrap();
        AdmittedPayload {
            entry,
            fingerprint: crate::storage::identity_file::SourceFingerprint::new(
                &file.metadata().unwrap(),
            ),
            file,
        }
    }

    #[cfg(target_os = "linux")]
    fn descriptors_to(path: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| std::fs::read_link(entry.path()).ok().as_deref() == Some(path))
            .count()
    }

    /// A valid RAM role owned by its lane, plus a tampered execution role.
    #[cfg(target_os = "linux")]
    fn lane_payloads(
        temporary: &tempfile::TempDir,
    ) -> (
        std::path::PathBuf,
        CaptureInventoryEntry,
        std::path::PathBuf,
        CaptureInventoryEntry,
    ) {
        let ram_path = temporary.path().join("memory.ram");
        std::fs::write(&ram_path, [0x32; 4096]).unwrap();
        let ram_path = std::fs::canonicalize(ram_path).unwrap();
        let execution_path = temporary.path().join("execution.state");
        std::fs::write(&execution_path, b"tampered").unwrap();
        let ram = CaptureInventoryEntry {
            role: CaptureRole::Ram,
            length: 4096,
            sha256: None,
            identity: Some(Sha256Digest::from_bytes(
                *StreamHasher::new(vm_spec::stream_map::ChunkSize::RAM)
                    .hash_reader(Cursor::new([0x32; 4096]))
                    .unwrap()
                    .id()
                    .as_bytes(),
            )),
        };
        let execution = CaptureInventoryEntry {
            role: CaptureRole::Execution,
            length: 8,
            sha256: Some(Sha256Digest::of_bytes(b"original")),
            identity: None,
        };
        (ram_path, ram, execution_path, execution)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_lane_failure_stops_and_joins_the_ram_owner_before_returning() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temporary = tempfile::tempdir().unwrap();
        let (ram_path, ram_entry, execution_path, execution_entry) = lane_payloads(&temporary);
        let ram = admit(&ram_entry, &ram_path);
        assert_eq!(descriptors_to(&ram_path), 1);
        let saw_stop = AtomicBool::new(false);
        let stopped = AtomicBool::new(false);
        let error = authenticate_lanes(
            |stop| {
                // Valid RAM bytes: only the sibling's failure can stop them.
                saw_stop.store(wait_for_stop(stop), Ordering::SeqCst);
                let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
                let result = verify_payload(
                    ram,
                    CaptureAuthentication::Bytes,
                    &mut buffer,
                    &mut None,
                    stop,
                );
                stopped.store(matches!(result, Ok(None)), Ordering::SeqCst);
                result
            },
            |stop| {
                let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
                verify_payload(
                    admit(&execution_entry, &execution_path),
                    CaptureAuthentication::Bytes,
                    &mut buffer,
                    &mut None,
                    stop,
                )
            },
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("capture staged payload digest mismatch"));
        assert!(saw_stop.load(Ordering::SeqCst));
        assert!(stopped.load(Ordering::SeqCst));
        // Joined before return: the RAM owner's descriptor is already closed.
        assert_eq!(descriptors_to(&ram_path), 0);
    }

    #[test]
    fn checkpoint_ram_lane_unwind_stops_the_sibling_and_is_a_typed_join_error() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let saw_stop = AtomicBool::new(false);
        let result = authenticate_lanes::<(), ()>(
            |_| panic!("injected RAM lane fault"),
            |stop| {
                saw_stop.store(wait_for_stop(stop), Ordering::SeqCst);
                Ok(Some(()))
            },
        );
        assert!(matches!(result, Err(crate::LibVmError::Io(_))));
        assert!(saw_stop.load(Ordering::SeqCst));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_caller_lane_unwind_stops_and_joins_the_ram_owner() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let temporary = tempfile::tempdir().unwrap();
        let (ram_path, ram_entry, _, _) = lane_payloads(&temporary);
        let ram = admit(&ram_entry, &ram_path);
        assert_eq!(descriptors_to(&ram_path), 1);
        let saw_stop = AtomicBool::new(false);
        let stopped = AtomicBool::new(false);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            authenticate_lanes::<VerifiedPayload, ()>(
                |stop| {
                    saw_stop.store(wait_for_stop(stop), Ordering::SeqCst);
                    let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
                    let result = verify_payload(
                        ram,
                        CaptureAuthentication::Bytes,
                        &mut buffer,
                        &mut None,
                        stop,
                    );
                    stopped.store(matches!(result, Ok(None)), Ordering::SeqCst);
                    result
                },
                |_| panic!("injected caller lane fault"),
            )
        }));
        assert!(unwound.is_err());
        assert!(saw_stop.load(Ordering::SeqCst));
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(descriptors_to(&ram_path), 0);
    }

    #[tokio::test]
    async fn checkpoint_cleanup_stabilizes_authority_before_detaching_capture() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let mut reader = fixture.snapshots.store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        drop(fixture.reservation);
        drop(fixture.launch);
        let recovery = fixture.snapshots.store.recover_image_cache().await.unwrap();
        assert!(recovery.checkpoint_deferred(), "{recovery:?}");
        let cleaning: String =
            sqlx::query_scalar("SELECT state FROM storage_operation WHERE operation_id=?1")
                .bind(capture.to_string())
                .fetch_one(&fixture.snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(cleaning, "cleaning");
        let reopened = crate::store::Store::open(&fixture.snapshots.store.home.join("state.db"))
            .await
            .unwrap();
        assert!(reopened
            .recover_image_cache()
            .await
            .unwrap()
            .checkpoint_deferred());
        assert!(directory.path().exists());
        let archive = fixture
            .snapshots
            .store
            .home
            .join("capture-evidence")
            .join(capture.to_string());
        assert!(archive.join("owner.json").is_file());
        assert_eq!(
            std::fs::read(archive.join("vm.capture.json")).unwrap(),
            std::fs::read(directory.path().join("vm.capture.json")).unwrap()
        );
        reader.rollback().await.unwrap();
        fixture.snapshots.store.recover_image_cache().await.unwrap();
        assert!(!directory.path().exists());
    }

    #[tokio::test]
    async fn checkpoint_native_baseline_lease_defers_terminal_capture_retirement() {
        let fixture = fixture().await;
        let capture = fixture.reservation.record.capture_id;
        let inherited = fixture.launch.lock().duplicate().unwrap();
        fixture
            .snapshots
            .update_capture(capture, |record| {
                record.dispatch_attempted = true;
                Ok(())
            })
            .await
            .unwrap();
        fixture.snapshots.abandon_capture(capture).await.unwrap();
        let snapshots = fixture.snapshots.clone();
        let machine = fixture.config.id;
        drop(fixture.reservation);
        drop(fixture.launch);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_some());
        assert!(snapshots.machine_capture_retained(machine).await.unwrap());
        drop(inherited);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_none());
        assert!(!snapshots.machine_capture_retained(machine).await.unwrap());
    }

    #[tokio::test]
    async fn checkpoint_dropped_publication_waiter_retains_its_copy_owner() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let name = fixture.reservation.record.alias.clone();
        let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::Preparing, false);
        let mut worker = fixture.snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let publisher = SnapshotStore::from_store(Arc::new(worker));
        let staging = directory.path().to_path_buf();
        let alias = name.clone();
        drop(fixture.reservation);
        let waiter = tokio::spawn(async move {
            publisher
                .publish_capture(
                    capture,
                    &staging,
                    alias,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        assert!(
            pool.try_exclusive_lease(capture).unwrap().is_none(),
            "detached publisher still owns output lifetime"
        );
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Reserved
        );
        release.send(()).unwrap();
        let published = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                name,
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Published {
                snapshot: published.id
            }
        );
        assert_eq!(published.provenance[0].capture_id, capture);
    }

    #[tokio::test]
    async fn checkpoint_cleanup_recovers_each_namespace_interruption_without_losing_evidence() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        for point in [
            WorkerPoint::CandidateAuthorized,
            WorkerPoint::CandidateDetached,
            WorkerPoint::CandidateRemoved,
        ] {
            let fixture = fixture().await;
            let (directory, evidence) = seal(&fixture);
            let capture = fixture.reservation.record.capture_id;
            let published = fixture
                .snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    fixture.reservation.record.alias.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .unwrap();
            fixture
                .snapshots
                .finish_capture_release(capture, true)
                .await
                .unwrap();
            let charges = fixture.reservation.record.disk_charges.clone();
            let (hook, _entered, _release) = WorkerHook::new(point, true);
            let mut worker = fixture.snapshots.store.as_ref().clone();
            worker.layer_hook = Some(hook);
            drop(fixture.reservation);
            drop(fixture.launch);
            assert!(worker.recover_image_cache().await.is_err());
            let retained = fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.disk_charges, charges);
            let state: String =
                sqlx::query_scalar("SELECT state FROM storage_operation WHERE operation_id=?1")
                    .bind(capture.to_string())
                    .fetch_one(&worker.pool)
                    .await
                    .unwrap();
            assert_eq!(state, "cleaning");
            fixture.snapshots.store.recover_image_cache().await.unwrap();
            assert!(!directory.path().exists());
            assert!(fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .is_none());
            let archive = worker
                .home
                .join("capture-evidence")
                .join(capture.to_string());
            assert_eq!(
                std::fs::read(archive.join("vm.capture.json")).unwrap(),
                evidence.canonical_bytes().unwrap()
            );
            assert!(fixture
                .snapshots
                .store
                .machine_config(fixture.config.id)
                .await
                .unwrap()
                .is_some());
            let snapshot = fixture
                .snapshots
                .consume(&SnapshotRef::Id(published.id))
                .await
                .unwrap();
            assert_eq!(snapshot.record.id().unwrap(), published.id);
        }
    }

    #[tokio::test]
    async fn checkpoint_concurrent_publication_joins_and_retry_converges_before_cleanup() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let name = fixture.reservation.record.alias.clone();
        let (first, second) = tokio::join!(
            fixture.snapshots.publish_capture(
                capture,
                directory.path(),
                name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait
            ),
            fixture.snapshots.publish_capture(
                capture,
                directory.path(),
                name.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait
            )
        );
        let published = first.unwrap();
        assert_eq!(published, second.unwrap());
        assert_eq!(
            fixture
                .snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    name.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait
                )
                .await
                .unwrap(),
            published
        );
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    name,
                    crate::storage::pool::PublicationLockPolicy::Wait
                )
                .await
                .unwrap(),
            published
        );
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Released {
                snapshot: Some(published.id)
            }
        );
        let inherited = fixture.launch.lock().duplicate().unwrap();
        let snapshots = fixture.snapshots.clone();
        let machine = fixture.config.id;
        drop(fixture.reservation);
        drop(fixture.launch);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(
            directory.path().exists(),
            "native baseline still owns staging"
        );
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_some());
        drop(inherited);
        let mut sharing = fixture.config.clone();
        sharing.spec.mounts.push(vm_spec::Mount {
            source: sharing.machine_dir.clone(),
            tag: "capture-owner-share".into(),
            read_only: true,
        });
        snapshots.store.save_machine_config(&sharing).await.unwrap();
        let deferred = snapshots.store.recover_image_cache().await.unwrap();
        assert!(deferred.deferred.iter().any(|reason| matches!(
            reason,
            crate::store::models::CacheCleanupDeferral::ExternalDependency { .. }
        )));
        assert!(
            directory.path().exists(),
            "explicit ancestor share still pins staging"
        );
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_some());
        snapshots
            .store
            .save_machine_config(&fixture.config)
            .await
            .unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!directory.path().exists(), "terminal staging was reclaimed");
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_none());
        assert!(snapshots
            .store
            .machine_config(machine)
            .await
            .unwrap()
            .is_some());
        let retained = snapshots
            .consume(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        assert_eq!(retained.record.id().unwrap(), published.id);
    }

    #[tokio::test]
    async fn checkpoint_layout_validation_rejects_overlap_gap_alignment_and_overflow() {
        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let memory = evidence.memory.unwrap();
        let bytes = std::fs::read(directory.path().join("memory-layout.json")).unwrap();
        validate_layout(&bytes, &memory, 1 << 20).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, replacement) in [
            ("streamOffset", 4096u64),
            ("guestPhysicalAddress", 1),
            ("length", 0),
            ("length", u64::MAX),
        ] {
            let mut changed = value.clone();
            changed["regions"][0][field] = serde_json::json!(replacement);
            assert!(
                validate_layout(&serde_json::to_vec(&changed).unwrap(), &memory, 1 << 20).is_err()
            );
        }
        let mut changed = value;
        changed["regions"] = serde_json::json!([
            {"guestPhysicalAddress": 0, "length": 4096, "streamOffset": 0},
            {"guestPhysicalAddress": 0, "length": 4096, "streamOffset": 4096}
        ]);
        let mut memory = memory;
        memory.packed_length = 8192;
        memory.regions = 2;
        changed["packedLength"] = serde_json::json!(8192);
        assert!(validate_layout(&serde_json::to_vec(&changed).unwrap(), &memory, 1 << 20).is_err());
        assert!(
            capture_directory(&fixture.snapshots.store, &fixture.reservation.record)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn checkpoint_includes_external_writable_data_and_preserves_native_serials() {
        let fixture = fixture_with_external_data(true).await;
        let (directory, _) = seal(&fixture);
        let data = &fixture.config.spec.storage.as_ref().unwrap().disks[1];
        std::fs::remove_file(&data.path).unwrap();
        let capture = fixture.reservation.record.capture_id;
        let result = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(result.id))
            .await
            .unwrap();
        assert_eq!(consumer.record.disks.len(), 1);
        assert!(consumer.record.disks[0].writable);
        assert_eq!(
            consumer
                .record
                .configuration
                .spec
                .storage
                .as_ref()
                .unwrap()
                .disks[1]
                .block_id
                .as_str(),
            "external-data-serial"
        );
        assert_eq!(
            fixture.reservation.record.plan.disks[1].name.as_str(),
            "silo-data-1"
        );
    }

    #[tokio::test]
    async fn checkpoint_rejects_oversized_ram_before_registering_a_reservation() {
        let fixture = fixture().await;
        let mut request = fixture.reservation.record.request.clone();
        request.capture_id = Uuid::new_v4();
        request.configuration.memory_mib = (1 << 20) + 1;
        assert!(matches!(
            fixture.snapshots.reserve_capture(&request).await,
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::Bound(_)
            ))
        ));
        assert!(fixture
            .snapshots
            .capture_reservation(request.capture_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn capture_result_release_does_not_claim_native_baseline_retirement() {
        let fixture = fixture().await;
        let capture = fixture.reservation.record.capture_id;
        fixture.snapshots.abandon_capture(capture).await.unwrap();
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        assert!(
            matches!(
                fixture
                    .snapshots
                    .capture_reservation(capture)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                CaptureState::Abandoned
            ),
            "retained native RAM must remain guarded by the exact source run lease"
        );
        fixture
            .snapshots
            .finish_capture_release(capture, false)
            .await
            .unwrap();
        assert!(matches!(fixture.snapshots.capture_reservation(capture).await.unwrap().unwrap().state,CaptureState::Released {snapshot:None}),"only positive no-baseline proof may release the failed capture while its source is live");
    }

    #[tokio::test]
    async fn fork_local_cut_keeps_one_ram_inode_without_snapshot_publication_and_rejects_mutation()
    {
        use std::os::unix::fs::FileExt;
        let fixture = fork_fixture().await;
        let (staging, evidence) = seal(&fixture);
        let original = staging
            .open_file("memory.ram")
            .unwrap()
            .unwrap()
            .metadata()
            .unwrap();
        let capture = fixture.reservation.record.capture_id;
        let operation = fixture
            .snapshots
            .store
            .fork_for_capture(capture)
            .await
            .unwrap()
            .unwrap();
        let (cut, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        assert_eq!(cut.evidence, evidence);
        assert!(staging.open_file("memory.ram").unwrap().is_none());
        assert!(
            staging
                .open_file(vm_spec::capture::CAPTURE_REQUEST_FILE)
                .unwrap()
                .is_some(),
            "monitor controls stay in the source namespace"
        );
        let ram = cut
            .files
            .iter()
            .find(|file| file.role == CaptureRole::Ram)
            .unwrap();
        assert_eq!((ram.device, ram.inode), (original.dev(), original.ino()));
        assert_eq!(
            cut.storage.snapshot, None,
            "a local cut is never a fabricated SnapshotId"
        );
        let published: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_snapshot")
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(published, 0);
        let held = fixture
            .snapshots
            .store
            .open_local_cut(operation, retained)
            .await
            .unwrap();
        let index = held
            .record
            .files
            .iter()
            .position(|file| file.role == CaptureRole::Ram)
            .unwrap();
        let file = held.held_file(index).unwrap();
        assert_eq!(file.metadata().unwrap().ino(), original.ino());
        {
            use std::io::{Seek, SeekFrom};
            let mut first = held.reopen_role(&CaptureRole::Ram).unwrap();
            let mut second = held.reopen_role(&CaptureRole::Ram).unwrap();
            first.seek(SeekFrom::Start(7)).unwrap();
            assert_eq!(
                second.stream_position().unwrap(),
                0,
                "parallel children must not share seek position"
            );
            assert_eq!(
                second.metadata().unwrap().ino(),
                original.ino(),
                "independent descriptions retain the same RAM inode"
            );
        }
        nix::sys::stat::fchmod(
            file,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let path = fixture
            .snapshots
            .store
            .images_dir
            .join("tmp")
            .join(operation.to_string())
            .join("cut/memory.ram");
        let writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        writer.write_at(&[0x7a], 0).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        nix::sys::stat::fchmod(file, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(
            fixture
                .snapshots
                .store
                .open_local_cut(operation, None)
                .await
                .is_err(),
            "same inode and length cannot hide modified sealed bytes"
        );
        assert!(
            held.reopen_role(&CaptureRole::Ram).is_err(),
            "handoff refuses mutation even through the already pinned directory"
        );
    }

    #[tokio::test]
    async fn fork_seal_recovery_reconciles_metadata_after_relocation_commit_without_recapture() {
        let fixture = fork_fixture().await;
        seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let operation = fixture
            .snapshots
            .store
            .fork_for_capture(capture)
            .await
            .unwrap()
            .unwrap();
        let (original, _) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        fixture
            .snapshots
            .update_capture(capture, |record| {
                record.state = CaptureState::Sealed;
                Ok(())
            })
            .await
            .unwrap();
        fixture
            .snapshots
            .store
            .update_fork(operation, |result| {
                result.capture = crate::ForkCaptureOutcome::Pending;
                result.stage = crate::ForkStage::Capturing;
                Ok(())
            })
            .await
            .unwrap();
        let (recovered, recovered_disks) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        assert_eq!(recovered, original);
        assert!(
            recovered_disks.is_none(),
            "recovery that did not observe relocation holds no disk map authority"
        );
        let parent = fixture
            .snapshots
            .store
            .fork_result(operation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            parent.capture,
            crate::ForkCaptureOutcome::Sealed {
                cut_id: original.cut_id
            }
        );
        assert!(matches!(
            fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Local { .. }
        ));
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM fork_event WHERE operation_id=?1 AND phase='seal_authenticated'",
        )
        .bind(operation.to_string())
        .fetch_one(&fixture.snapshots.store.pool)
        .await
        .unwrap();
        assert_eq!(events, 1);
    }

    #[tokio::test]
    async fn fork_cut_and_batch_charges_survive_source_removal_and_independent_slot_retirement() {
        let fixture = fork_fixture().await;
        let (_, evidence) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let operation = fixture
            .snapshots
            .store
            .fork_for_capture(capture)
            .await
            .unwrap()
            .unwrap();
        let (cut, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let held = fixture
            .snapshots
            .store
            .open_local_cut(operation, retained)
            .await
            .unwrap();
        fixture
            .snapshots
            .store
            .bind_fork_resources(&held)
            .await
            .unwrap();
        let inode = cut
            .files
            .iter()
            .find(|file| file.role == CaptureRole::Ram)
            .unwrap()
            .inode;
        let path = fixture
            .snapshots
            .store
            .images_dir
            .join("tmp")
            .join(operation.to_string())
            .join("cut/memory.ram");
        fixture
            .snapshots
            .record_capture_source(
                capture,
                CaptureSourceOutcome::Observed {
                    continuation: vm_spec::capture::CaptureContinuation::Resumed {
                        consumed_token: evidence.pause_token.unwrap(),
                        thawed_epoch: evidence.freeze_epoch.unwrap(),
                    },
                },
            )
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        let store = fixture.snapshots.store.clone();
        let snapshots = fixture.snapshots.clone();
        drop(held);
        drop(fixture.reservation);
        store.recover_image_cache().await.unwrap();
        assert!(
            snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .is_some(),
            "the exact source launch lease still owns its baseline"
        );
        drop(fixture.launch);
        store.recover_image_cache().await.unwrap();
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_none());
        store.remove_machine(&fixture.config).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        let before: crate::store::restore::CaptureBudgetInventory =
            serde_json::from_str(&store.capture_budget_document(operation).await.unwrap()).unwrap();
        assert_eq!(before.bound.len(), 2);
        assert!(
            before.capture_disks.is_empty(),
            "retired source released its disk peak"
        );
        store
            .set_fork_child(
                operation,
                0,
                crate::ForkChildOutcome::Abandoned {
                    diagnostic: crate::machine::live_fork::diagnostic("unsubmitted"),
                },
            )
            .await
            .unwrap();
        store.recover_image_cache().await.unwrap();
        let after: crate::store::restore::CaptureBudgetInventory =
            serde_json::from_str(&store.capture_budget_document(operation).await.unwrap()).unwrap();
        assert_eq!(after.bound.len(), 1);
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        store
            .set_fork_child(
                operation,
                1,
                crate::ForkChildOutcome::Abandoned {
                    diagnostic: crate::machine::live_fork::diagnostic("unsubmitted"),
                },
            )
            .await
            .unwrap();
        store
            .update_fork(operation, |result| {
                result.stage = crate::ForkStage::Finished;
                Ok(())
            })
            .await
            .unwrap();
        store.recover_image_cache().await.unwrap();
        assert!(
            !path.parent().unwrap().parent().unwrap().exists(),
            "one sweep retires the last slot, parent root and cut directory"
        );
        assert_eq!(
            store
                .fork_result(operation)
                .await
                .unwrap()
                .unwrap()
                .children
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn fork_retention_shares_seal_derived_disk_maps_with_independent_child_descriptors() {
        use std::io::{Seek, SeekFrom};
        let fixture = fork_fixture().await;
        seal(&fixture);
        let store = &fixture.snapshots.store;
        let capture = fixture.reservation.record.capture_id;
        let operation = store.fork_for_capture(capture).await.unwrap().unwrap();
        let (cut, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let retained = retained.expect("seal verification derived the writable disk maps");
        let expected = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_reader(&[0x51; 512][..])
            .unwrap();
        let disks = cut
            .files
            .iter()
            .filter(|file| matches!(file.role, CaptureRole::Disk(_)))
            .map(|file| file.role.clone())
            .collect::<Vec<_>>();
        assert!(!disks.is_empty());
        assert!(
            store
                .open_local_cut(
                    operation,
                    Some(crate::store::fork::AuthenticatedCutDisks::new(
                        uuid::Uuid::new_v4(),
                        cut.cut_id,
                        Vec::new(),
                    )),
                )
                .await
                .is_err(),
            "another operation's authentication never binds this cut"
        );
        let held = store
            .open_local_cut(operation, Some(retained))
            .await
            .unwrap();
        assert!(held.reopen_disk(&CaptureRole::Ram).is_err());
        for role in &disks {
            let first = held.reopen_disk(role).unwrap();
            let second = held.reopen_disk(role).unwrap();
            assert_eq!(*first.map(), expected);
            assert_eq!(*second.map(), expected);
            let mut first_file = first.file();
            first_file.seek(SeekFrom::Start(9)).unwrap();
            let mut second_file = second.file();
            assert_eq!(
                second_file.stream_position().unwrap(),
                0,
                "children never share a disk open-file description"
            );
        }
        drop(held);
        // Reopening after owner loss recovers the recorded canonical disk map.
        let recovered = store.open_local_cut(operation, None).await.unwrap();
        for role in &disks {
            assert_eq!(*recovered.reopen_disk(role).unwrap().map(), expected);
        }
    }

    #[tokio::test]
    async fn fork_cut_disk_authority_rejects_bytes_changed_behind_a_rewritten_fingerprint() {
        use std::os::unix::fs::FileExt;
        let fixture = fork_fixture().await;
        seal(&fixture);
        let store = &fixture.snapshots.store;
        let capture = fixture.reservation.record.capture_id;
        let operation = store.fork_for_capture(capture).await.unwrap().unwrap();
        let (_, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let mut record = store.local_cut(operation).await.unwrap().unwrap();
        let index = record
            .files
            .iter()
            .position(|file| matches!(file.role, CaptureRole::Disk(_)))
            .unwrap();
        let path = store
            .images_dir
            .join("tmp")
            .join(operation.to_string())
            .join("cut")
            .join(record.files[index].role.relative_path());
        let file = std::fs::File::open(&path).unwrap();
        nix::sys::stat::fchmod(
            &file,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        // Same inode and length; only bytes inside the authenticated map change.
        writer.write_at(&[0x52], 100).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        nix::sys::stat::fchmod(&file, nix::sys::stat::Mode::S_IRUSR).unwrap();
        // Model an uncertain relocation whose persisted identity names the
        // changed inode: only content authentication can still refuse it.
        record.files[index].fingerprint =
            crate::storage::identity_file::SourceFingerprint::new(&file.metadata().unwrap());
        sqlx::query("UPDATE local_cut SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation.to_string())
            .bind(serde_json::to_string(&record).unwrap())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store.open_local_cut(operation, retained).await.is_err(),
            "a held map never binds an inode whose fingerprint moved after sealing"
        );
        let recovered = store.open_local_cut(operation, None).await.unwrap();
        let disk = recovered.reopen_disk(&record.files[index].role).unwrap();
        let private = tempfile::tempfile().unwrap();
        assert!(
            StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
                .copy_authenticated(&disk, &private)
                .is_err(),
            "first byte use checks the receipt map, not the rewritten fingerprint"
        );
    }

    #[tokio::test]
    async fn incremental_complete_map_publishes_without_parent_retention() {
        let fixture = fixture_source(false, false, CapturePolicy::Incremental).await;
        let (directory, mut evidence) = seal(&fixture);
        let memory = evidence.memory.as_mut().unwrap();
        memory.mode = CapturePolicy::Incremental;
        memory.baseline = Some(Sha256Digest::of_bytes(b"unretained predecessor stream"));
        memory.full_reason = None;
        memory.stats.full_bytes_written = 0;
        memory.stats.overlay_bytes_written = memory.packed_length;
        let mut changes = std::fs::read(
            directory
                .path()
                .join(CaptureRole::RamChanges.relative_path()),
        )
        .unwrap();
        changes[11] = 1;
        memory.changes.coverage = vm_spec::capture::CaptureRamCoverage::Incremental;
        memory.changes.baseline_stream = memory.baseline;
        memory.changes.sha256 = Sha256Digest::of_bytes(&changes);
        directory
            .write_file(&CaptureRole::RamChanges.relative_path(), &changes)
            .unwrap();
        evidence
            .inventory
            .iter_mut()
            .find(|entry| entry.role == CaptureRole::RamChanges)
            .unwrap()
            .sha256 = Some(Sha256Digest::of_bytes(&changes));
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        let published = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("live checkpoint required");
        };
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        let ram = consumer
            .open_stream(&pool, &execution.memory.stream, execution.memory.length)
            .unwrap();
        assert_eq!(ram.metadata().unwrap().len(), 4096);
        assert_eq!(
            consumer
                .authenticated_stream(&execution.memory.stream, 4096)
                .unwrap()
                .map()
                .present_chunks()
                .count(),
            1
        );
        assert_eq!(
            fixture
                .snapshots
                .restore_evidence(&consumer, &pool)
                .unwrap()
                .evidence
                .memory
                .unwrap()
                .mode,
            CapturePolicy::Incremental
        );
    }

    #[tokio::test]
    async fn sealed_complete_ram_map_corruption_refuses_before_publication() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        directory
            .write_file(&CaptureRole::RamMap.relative_path(), b"{}")
            .unwrap();
        assert!(fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .is_err());
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(fixture.reservation.record.capture_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Reserved
        );
    }

    #[tokio::test]
    async fn disk_recovery_authenticates_storage_without_opening_captured_ram() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let published = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        let record = consumer.record.clone();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &record.capture
        else {
            panic!("live checkpoint required");
        };
        drop(consumer);
        std::fs::remove_file(pool.stream_path(&execution.memory.stream)).unwrap();
        assert!(fixture
            .snapshots
            .consume(&SnapshotRef::Id(published.id))
            .await
            .is_err());
        let recovered = fixture
            .snapshots
            .consume_disks(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        let storage =
            crate::machine::restore::storage_from_snapshot(&record, published.id).unwrap();
        assert_eq!(storage.stop_outcome, crate::StorageStopOutcome::Unknown);
        assert_eq!(storage.snapshot, Some(published.id));
        assert_eq!(storage.boot, record.boot);
        let source = recovered
            .open_copy_source(
                &pool,
                &record.root.stream.stream,
                record.root.geometry.length,
            )
            .unwrap();
        let private = tempfile::tempfile().unwrap();
        let mut hasher = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK);
        hasher.copy_authenticated(&source, &private).unwrap();
        use std::os::unix::fs::FileExt;
        private.write_all_at(b"private child", 0).unwrap();
        let source_bytes = std::fs::read(pool.stream_path(&record.root.stream.stream)).unwrap();
        assert_eq!(source_bytes, vec![0x51; 512]);
        let path = pool.stream_path(&record.root.stream.stream);
        drop(recovered);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![0x52; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(fixture
            .snapshots
            .consume_disks(&SnapshotRef::Id(published.id))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn checkpoint_refuses_contradictory_ram_receipt_before_publication() {
        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let mut document = serde_json::to_value(&evidence).unwrap();
        let ram = document["inventory"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["role"] == "memory.ram")
            .unwrap();
        ram["identity"] = serde_json::json!(Sha256Digest::of_bytes(b"contradictory RAM inventory"));
        directory
            .write_file(
                vm_spec::capture::CAPTURE_EVIDENCE_FILE,
                &serde_json::to_vec(&document).unwrap(),
            )
            .unwrap();
        let error = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::InvalidStorageRecord {
                record: "snapshot",
                ..
            }
        ));
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(fixture.reservation.record.capture_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Reserved
        );
    }

    #[tokio::test]
    async fn fork_relocation_recovers_all_moved_payloads_before_the_journal_commit() {
        for interrupted_chmod in [false, true] {
            let fixture = fork_fixture().await;
            let (source, evidence) = seal(&fixture);
            let store = &fixture.snapshots.store;
            let capture = fixture.reservation.record.capture_id;
            let operation = store.fork_for_capture(capture).await.unwrap().unwrap();
            // Abort the real SQLite ownership update after the filesystem work.
            // No per-role journal update may occur before all roles have moved.
            sqlx::query(
                "CREATE TRIGGER interrupt_local_cut_commit BEFORE UPDATE ON local_cut \
                 BEGIN SELECT RAISE(ABORT,'injected relocation journal failure'); END",
            )
            .execute(&store.pool)
            .await
            .unwrap();
            let error = fixture
                .snapshots
                .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
                .await
                .err()
                .expect("the relocation ownership commit must fail");
            assert!(error
                .to_string()
                .contains("injected relocation journal failure"));
            let journal = store.local_cut(operation).await.unwrap().unwrap();
            assert!(!journal.relocated);
            assert_eq!(journal.evidence, evidence);
            let destination = store
                .images_dir
                .join("tmp")
                .join(operation.to_string())
                .join("cut");
            for payload in &journal.files {
                let relative = payload.role.relative_path();
                assert!(!source.path().join(&relative).exists());
                let metadata = std::fs::metadata(destination.join(&relative)).unwrap();
                assert_eq!(
                    (metadata.dev(), metadata.ino()),
                    (payload.device, payload.inode)
                );
                assert_eq!(metadata.mode() & 0o7777, 0o400);
            }
            assert_eq!(
                fixture
                    .snapshots
                    .capture_reservation(capture)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                CaptureState::Reserved,
            );
            assert_eq!(
                store.fork_result(operation).await.unwrap().unwrap().capture,
                crate::ForkCaptureOutcome::Pending,
            );
            let events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM fork_event WHERE operation_id=?1 AND phase='seal_authenticated'",
            )
            .bind(operation.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
            assert_eq!(events, 0);
            if interrupted_chmod {
                // Also cover death after a source's chmod/fsync but before its
                // rename: restart must accept its 0400 name, then authenticate.
                let relative = journal.files[0].role.relative_path();
                std::fs::rename(destination.join(&relative), source.path().join(&relative))
                    .unwrap();
            }
            sqlx::query("DROP TRIGGER interrupt_local_cut_commit")
                .execute(&store.pool)
                .await
                .unwrap();
            let (recovered, disks) = fixture
                .snapshots
                .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
                .await
                .unwrap();
            assert!(recovered.relocated);
            assert_eq!(recovered.cut_id, journal.cut_id);
            assert_eq!(recovered.evidence, evidence);
            for payload in &recovered.files {
                let relative = payload.role.relative_path();
                assert!(!source.path().join(&relative).exists());
                let file = std::fs::File::open(destination.join(&relative)).unwrap();
                let identity = if matches!(payload.role, CaptureRole::Ram | CaptureRole::Disk(_)) {
                    Sha256Digest::from_bytes(
                        *StreamHasher::new(if payload.role == CaptureRole::Ram {
                            vm_spec::stream_map::ChunkSize::RAM
                        } else {
                            vm_spec::stream_map::ChunkSize::DISK
                        })
                        .authenticate(file, payload.length)
                        .unwrap()
                        .map()
                        .id()
                        .as_bytes(),
                    )
                } else {
                    crate::storage::stream::whole_file_sha256(&file).unwrap()
                };
                assert_eq!(identity, payload.identity);
            }
            let opened = store.open_local_cut(operation, disks).await.unwrap();
            assert_eq!(opened.record, recovered);
            assert_eq!(
                fixture
                    .snapshots
                    .capture_reservation(capture)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                CaptureState::Local {
                    cut: recovered.cut_id
                },
            );
            assert_eq!(
                store.fork_result(operation).await.unwrap().unwrap().capture,
                crate::ForkCaptureOutcome::Sealed {
                    cut_id: recovered.cut_id
                },
            );
            let events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM fork_event WHERE operation_id=?1 AND phase='seal_authenticated'",
            )
            .bind(operation.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
            assert_eq!(events, 1);
        }
    }

    #[tokio::test]
    async fn fork_receipt_refuses_wrong_chunk_count_identity_and_missing_role() {
        for fault in ["chunk-count", "stream-identity", "missing-role"] {
            let fixture = fork_fixture().await;
            let (directory, evidence) = seal(&fixture);
            let mut document = serde_json::to_value(&evidence).unwrap();
            match fault {
                "chunk-count" => {
                    document["memory"]["chunkDigests"] = serde_json::json!([]);
                }
                "stream-identity" => {
                    let entry = document["inventory"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|entry| {
                            entry["role"]
                                .as_str()
                                .is_some_and(|role| role.ends_with(".raw"))
                        })
                        .unwrap();
                    entry["identity"] =
                        serde_json::json!(Sha256Digest::of_bytes(b"not the recorded chunks"));
                }
                "missing-role" => {
                    document["inventory"].as_array_mut().unwrap().pop();
                }
                _ => unreachable!(),
            }
            directory
                .write_file(
                    vm_spec::capture::CAPTURE_EVIDENCE_FILE,
                    &serde_json::to_vec(&document).unwrap(),
                )
                .unwrap();
            let error = fixture
                .snapshots
                .retain_local_capture(
                    fixture.reservation.record.capture_id,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .err()
                .expect("invalid structural receipts must be refused");
            assert!(
                matches!(
                    error,
                    crate::LibVmError::InvalidStorageRecord {
                        record: "snapshot",
                        ..
                    }
                ),
                "{fault}: {error}"
            );
            let cuts: i64 = sqlx::query_scalar("SELECT count(*) FROM local_cut")
                .fetch_one(&fixture.snapshots.store.pool)
                .await
                .unwrap();
            assert_eq!(cuts, 0, "{fault} must not create a cut root");
        }
    }

    #[test]
    fn receipt_stream_admission_accepts_descriptors_that_cannot_read_bytes() {
        for role in [
            CaptureRole::Ram,
            CaptureRole::Disk(vm_spec::capture::CaptureDiskName::new("root").unwrap()),
        ] {
            let temporary = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(temporary.path(), [0x51; 512]).unwrap();
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(temporary.path())
                .unwrap();
            let entry = CaptureInventoryEntry {
                role,
                length: 512,
                sha256: None,
                identity: Some(Sha256Digest::from_bytes(
                    *StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
                        .hash_reader(Cursor::new([0x51; 512]))
                        .unwrap()
                        .id()
                        .as_bytes(),
                )),
            };
            let payload = AdmittedPayload {
                entry: &entry,
                fingerprint: crate::storage::identity_file::SourceFingerprint::new(
                    &file.metadata().unwrap(),
                ),
                file,
            };
            let verified = verify_payload(
                payload,
                CaptureAuthentication::Receipt,
                &mut [0; 32],
                &mut None,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
            let mut input = verified.file();
            assert!(
                std::io::Read::read(&mut input, &mut [0]).is_err(),
                "the held stream descriptor is genuinely unreadable"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fork_retains_receipt_without_stream_authentication_or_descriptor_leaks() {
        let fixture = fork_fixture().await;
        let (directory, evidence) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        for entry in evidence
            .inventory
            .iter()
            .filter(|entry| matches!(entry.role, CaptureRole::Ram | CaptureRole::Disk(_)))
        {
            let path = directory.path().join(entry.role.relative_path());
            assert_eq!(descriptors_to(&path), 0);
            std::fs::write(path, vec![0xa7; entry.length as usize]).unwrap();
        }
        assert!(
            crate::store::capture::verify_capture_bytes(&directory, &fixture.reservation.record)
                .is_err(),
            "the original receipt does not authenticate these bytes"
        );
        let (cut, disks) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let destination = fixture
            .snapshots
            .store
            .images_dir
            .join("tmp")
            .join(cut.operation_id.to_string())
            .join("cut");
        for entry in &cut.files {
            assert_eq!(
                descriptors_to(&destination.join(entry.role.relative_path())),
                usize::from(matches!(entry.role, CaptureRole::Disk(_)))
            );
        }
        let roots: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_operation_cut WHERE cut_id=?1")
                .bind(cut.cut_id.to_string())
                .fetch_one(&fixture.snapshots.store.pool)
                .await
                .unwrap();
        assert_eq!(roots, 2, "both capture and fork leases retain the cut");
        drop(disks);
        for entry in &cut.files {
            assert_eq!(
                descriptors_to(&destination.join(entry.role.relative_path())),
                0
            );
        }
    }

    async fn publish_fixture(fixture: &Fixture) -> crate::SnapshotInfo {
        let (directory, _) = seal(fixture);
        fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap()
    }

    async fn release_fixture(fixture: &Fixture) {
        let capture = fixture.reservation.record.capture_id;
        fixture
            .snapshots
            .record_capture_source(capture, CaptureSourceOutcome::Unknown)
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
    }

    async fn reserve_next_fixture(fixture: &mut Fixture, alias: &str) {
        let mut request = fixture.reservation.record.request.clone();
        request.capture_id = Uuid::new_v4();
        request.alias = Some(alias.into());
        fixture.reservation = fixture.snapshots.reserve_capture(&request).await.unwrap();
        fixture
            .snapshots
            .bind_capture_boot(
                request.capture_id,
                fixture.launch.storage_record().boot.clone(),
            )
            .await
            .unwrap();
    }

    async fn bind_fixture_alias(
        snapshots: &SnapshotStore,
        alias: &str,
        target: crate::storage::identity::SnapshotId,
    ) {
        let mut tx = snapshots
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        crate::store::managed_image_store::insert_alias(
            &mut tx,
            alias,
            crate::image::import_types::ManagedSourceId::Snapshot(target),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn capture_runtime(snapshots: &SnapshotStore) -> crate::Runtime {
        let paths = LocalPaths::new(snapshots.store.home_path().to_path_buf());
        let components = crate::runtime::components::test_components(paths.home());
        crate::Runtime::from_store(
            paths,
            snapshots.store.clone(),
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
            components,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn capture_admission_refuses_taken_alias_without_rows_pins_budget_or_staging() {
        let fixture = fixture().await;
        let original = publish_fixture(&fixture).await;
        bind_fixture_alias(&fixture.snapshots, "checkpoint", original.id).await;
        bind_fixture_alias(&fixture.snapshots, "checkpoint", original.id).await;
        // Exact replay still joins its own reservation after its alias is bound.
        let replay = fixture
            .snapshots
            .reserve_capture(&fixture.reservation.record.request)
            .await
            .unwrap();
        assert_eq!(
            replay.record.capture_id,
            fixture.reservation.record.capture_id
        );
        drop(replay);
        release_fixture(&fixture).await;

        // A second admitted machine shares the same alias namespace.
        let paths = LocalPaths::new(fixture.snapshots.store.home_path().to_path_buf());
        let mut other = fixture.config.clone();
        other.id = MachineId::new();
        other.name = "other-capture-source".into();
        let parent = paths.create_machine_data_dir(other.id).unwrap();
        let directory = parent.open_dir(&other.id.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x51; 512]).unwrap();
        other.machine_dir = directory.path().to_path_buf();
        let mut state = fixture
            .snapshots
            .store
            .machine_state(fixture.config.id)
            .await
            .unwrap()
            .unwrap();
        state.machine_id = other.id;
        let run = Uuid::new_v4();
        state.run_id = Some(run.to_string());
        fixture
            .snapshots
            .store
            .add_machine(&other, &state)
            .await
            .unwrap();
        let storage = fixture
            .snapshots
            .store
            .machine_storage(other.id)
            .await
            .unwrap()
            .unwrap();
        let launch = fixture
            .snapshots
            .store
            .register_launch_storage(other.id, run, &storage, &other.spec)
            .await
            .unwrap();
        fixture
            .snapshots
            .store
            .mark_launch_storage_admitted(launch.operation_id())
            .await
            .unwrap();

        for (machine, run) in [
            (fixture.config.id, fixture.reservation.record.run_id),
            (other.id, run),
        ] {
            let mut request = fixture.reservation.record.request.clone();
            request.capture_id = Uuid::new_v4();
            request.machine_id = machine;
            request.run_id = run;
            let error = match fixture.snapshots.reserve_capture(&request).await {
                Ok(_) => panic!("occupied capture alias admitted"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                crate::LibVmError::ImageAliasConflict { alias } if alias == "checkpoint"
            ));
            for query in [
                "SELECT count(*) FROM storage_operation WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_stream WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_object WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_layer WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_lower WHERE operation_id=?1",
                "SELECT count(*) FROM capture_resource_reservation WHERE operation_id=?1",
            ] {
                let count: i64 = sqlx::query_scalar(query)
                    .bind(request.capture_id.to_string())
                    .fetch_one(&fixture.snapshots.store.pool)
                    .await
                    .unwrap();
                assert_eq!(count, 0, "{query}");
            }
            assert!(!fixture
                .snapshots
                .store
                .images_dir
                .join("tmp")
                .join(request.capture_id.to_string())
                .exists());
            assert!(!crate::paths::machine_data_dir_in(
                fixture.snapshots.store.home_path(),
                machine
            )
            .join("captures")
            .join(request.capture_id.to_string())
            .exists());
        }
        assert_eq!(
            fixture
                .snapshots
                .inspect(&SnapshotRef::Image("checkpoint".into()))
                .await
                .unwrap()
                .id,
            original.id
        );
    }

    #[tokio::test]
    async fn capture_alias_race_retains_unaliased_checkpoint_and_publication_replays_skip_bytes() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        let mut fixture = fixture().await;
        let original = publish_fixture(&fixture).await;
        release_fixture(&fixture).await;
        reserve_next_fixture(&mut fixture, "racing").await;
        bind_fixture_alias(&fixture.snapshots, "racing", original.id).await;
        let captured = publish_fixture(&fixture).await;
        assert_ne!(captured.id, original.id);
        assert!(captured.retained);
        assert!(captured.aliases.is_empty());
        let capture = fixture.reservation.record.capture_id;
        let record = fixture
            .snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.state,
            CaptureState::Published {
                snapshot: captured.id
            }
        );
        assert_eq!(
            record.naming_outcome,
            Some(crate::CaptureNamingOutcome::AliasConflict {
                alias: "racing".into()
            })
        );
        assert_eq!(record.alias.as_deref(), Some("racing"));
        assert_eq!(captured.provenance[0].capture_id, capture);
        assert_eq!(
            fixture
                .snapshots
                .inspect(&SnapshotRef::Image("racing".into()))
                .await
                .unwrap()
                .id,
            original.id
        );

        let (hook, mut entered, _release) = WorkerHook::new(WorkerPoint::Preparing, true);
        let mut worker = fixture.snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let snapshots = SnapshotStore::from_store(Arc::new(worker));
        let staging = fixture.config.machine_dir.join(record.plan.directory());
        assert_eq!(
            snapshots
                .publish_capture(
                    capture,
                    &staging,
                    record.alias.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait
                )
                .await
                .unwrap(),
            captured
        );
        assert!(
            entered.try_recv().is_err(),
            "Published replay reached byte preparation"
        );
        let mut state = fixture
            .snapshots
            .store
            .machine_state(fixture.config.id)
            .await
            .unwrap()
            .unwrap();
        let running = state.clone();
        state.status = MachineRuntimeState::Stopped;
        state.run_id = None;
        snapshots.store.save_machine_state(&state).await.unwrap();
        let runtime = capture_runtime(&snapshots).await;
        let result = crate::Machine::new(runtime, fixture.config.id)
            .complete_capture(capture)
            .await
            .unwrap();
        assert!(result.capture.released);
        assert_eq!(result.snapshot.id, captured.id);
        assert!(matches!(
            result.require_requested_name(),
            Err(crate::LibVmError::CaptureAliasConflict { alias, checkpoint })
                if alias == "racing" && checkpoint == captured.id
        ));
        assert!(snapshots.pending_captures(None).await.unwrap().is_empty());
        assert_eq!(
            snapshots
                .publish_capture(
                    capture,
                    &staging,
                    record.alias.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait
                )
                .await
                .unwrap(),
            captured
        );
        assert!(
            entered.try_recv().is_err(),
            "Released replay reached byte preparation"
        );
        // Removing the competing binding cannot make replay acquire the name.
        snapshots.remove_alias("racing").await.unwrap();
        assert!(snapshots
            .publish_capture(
                capture,
                &staging,
                record.alias,
                crate::storage::pool::PublicationLockPolicy::Wait
            )
            .await
            .unwrap()
            .aliases
            .is_empty());
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap()
            .naming_outcome
            .is_some());
        snapshots.store.save_machine_state(&running).await.unwrap();
        reserve_next_fixture(&mut fixture, "retry").await;
    }

    #[tokio::test]
    async fn capture_reconciliation_repairs_persisted_sealed_alias_conflict_once() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        let mut fixture = fixture().await;
        let original = publish_fixture(&fixture).await;
        release_fixture(&fixture).await;
        reserve_next_fixture(&mut fixture, "stuck").await;
        let prepared = publish_fixture(&fixture).await;
        let capture = fixture.reservation.record.capture_id;
        let mut record = fixture
            .snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        // Recreate the pre-fix commit boundary: authenticated/pinned outputs
        // and candidate survive, but snapshot, alias and provenance rolled back.
        let mut tx = fixture
            .snapshots
            .store
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .unwrap();
        sqlx::query("DELETE FROM image_alias WHERE name='stuck'")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM storage_snapshot WHERE id=?1")
            .bind(prepared.id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        record.state = CaptureState::Sealed;
        crate::store::capture::write_record(&mut tx, &record)
            .await
            .unwrap();
        // The owner's existing record predates the optional naming result.
        sqlx::query("UPDATE storage_operation SET record_json=jsonb_remove(record_json,'$.namingOutcome') WHERE operation_id=?1")
            .bind(capture.to_string()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        bind_fixture_alias(&fixture.snapshots, "stuck", original.id).await;
        let mut state = fixture
            .snapshots
            .store
            .machine_state(fixture.config.id)
            .await
            .unwrap()
            .unwrap();
        state.status = MachineRuntimeState::Stopped;
        state.run_id = None;
        fixture
            .snapshots
            .store
            .save_machine_state(&state)
            .await
            .unwrap();

        let reopened = SnapshotStore::open(fixture.snapshots.store.home_path())
            .await
            .unwrap();
        let runtime = capture_runtime(&reopened).await;
        runtime.reconcile_captures().await.unwrap();
        let repaired = reopened
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            repaired.state,
            CaptureState::Released {
                snapshot: Some(prepared.id)
            }
        );
        assert_eq!(
            repaired.naming_outcome,
            Some(crate::CaptureNamingOutcome::AliasConflict {
                alias: "stuck".into()
            })
        );
        assert!(reopened.pending_captures(None).await.unwrap().is_empty());
        assert_eq!(
            reopened
                .inspect(&SnapshotRef::Image("stuck".into()))
                .await
                .unwrap()
                .id,
            original.id
        );
        let retained = reopened
            .inspect(&SnapshotRef::Id(prepared.id))
            .await
            .unwrap();
        assert!(retained.retained && retained.aliases.is_empty());
        assert_eq!(retained.provenance[0].capture_id, capture);

        let (hook, mut entered, _release) = WorkerHook::new(WorkerPoint::Preparing, true);
        let mut worker = reopened.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let snapshots = SnapshotStore::from_store(Arc::new(worker));
        let runtime = capture_runtime(&snapshots).await;
        runtime.reconcile_captures().await.unwrap();
        assert!(
            entered.try_recv().is_err(),
            "terminal capture was re-authenticated"
        );
        state.status = MachineRuntimeState::Running;
        state.run_id = Some(record.run_id.to_string());
        snapshots.store.save_machine_state(&state).await.unwrap();
        reserve_next_fixture(&mut fixture, "after-repair").await;
    }

    #[tokio::test]
    async fn capture_alias_sql_failure_is_not_a_naming_conflict() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        sqlx::raw_sql("CREATE TRIGGER reject_capture_alias BEFORE INSERT ON image_alias BEGIN SELECT RAISE(ABORT,'capture alias SQL failure'); END;")
            .execute(&fixture.snapshots.store.pool).await.unwrap();
        let capture = fixture.reservation.record.capture_id;
        let error = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("capture alias SQL failure"));
        let record = fixture
            .snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, CaptureState::Sealed);
        assert!(record.naming_outcome.is_none());
        let snapshots: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_snapshot")
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(snapshots, 0);
    }

    #[tokio::test]
    async fn capture_admission_refuses_alias_owned_by_managed_image() {
        let fixture = fixture().await;
        let snapshot = publish_fixture(&fixture).await;
        release_fixture(&fixture).await;
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(snapshot.id))
            .await
            .unwrap();
        let record = crate::ImageRecord {
            schema: 2,
            kind: crate::ImageRecordKind::Image,
            root: consumer.record.root.clone(),
            boot: consumer.record.boot.clone(),
            process: crate::ProcessConfig::default(),
        };
        let (streams, objects) = record.content_dependencies().unwrap();
        let (operation, lease) = fixture
            .snapshots
            .store
            .begin_stopped_operation(
                "import",
                &streams.into_iter().collect::<Vec<_>>(),
                &objects.into_iter().collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        pool.create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let images = crate::store::managed_image_store::ManagedImageStore::from_store(
            fixture.snapshots.store.clone(),
        );
        let image = images
            .publish_owned(
                record,
                operation,
                lease,
                Some("managed".into()),
                Vec::new(),
                None,
            )
            .await
            .unwrap();
        let mut request = fixture.reservation.record.request.clone();
        request.capture_id = Uuid::new_v4();
        request.alias = Some("managed".into());
        let error = match fixture.snapshots.reserve_capture(&request).await {
            Ok(_) => panic!("managed-image alias admitted for a new capture"),
            Err(error) => error,
        };
        assert!(
            matches!(error, crate::LibVmError::ImageAliasConflict { alias } if alias == "managed")
        );
        assert!(fixture
            .snapshots
            .capture_reservation(request.capture_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            images
                .resolve(&crate::image::import_types::ManagedSourceRef::Alias(
                    "managed".into()
                ))
                .await
                .unwrap(),
            crate::image::import_types::ManagedSourceId::Image(image.id),
        );
        fixture
            .snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        fixture
            .snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pending_captures_ignores_terminal_history_before_decoding() {
        let fixture = fixture().await;
        publish_fixture(&fixture).await;
        release_fixture(&fixture).await;
        // A terminal row is not recovery input, even if its historical JSON
        // cannot be decoded. This distinguishes SQL selection from post-filtering.
        sqlx::query("UPDATE storage_operation SET record_json=jsonb('{}') WHERE operation_id=?1")
            .bind(fixture.reservation.record.capture_id.to_string())
            .execute(&fixture.snapshots.store.pool)
            .await
            .unwrap();
        assert!(fixture
            .snapshots
            .pending_captures(None)
            .await
            .unwrap()
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sealed_stream_publication_carries_maps_without_payload_rereads() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};
        use crate::store::models::snapshot::SnapshotCaptureKind;
        use crate::store::snapshot_store::tests::{observed_stream_read, watch_stream_reads};

        let fixture = fixture().await;
        let (directory, evidence) = seal(&fixture);
        let streams = evidence
            .inventory
            .iter()
            .filter(|entry| matches!(entry.role, CaptureRole::Ram | CaptureRole::Disk(_)))
            .map(|entry| {
                let staged = directory.path().join(entry.role.relative_path());
                let watcher = watch_stream_reads(&staged);
                let id = crate::storage::identity::StreamId::from_sha256(
                    *entry.identity.unwrap().as_bytes(),
                );
                (id, entry.role.clone(), staged, watcher)
            })
            .collect::<Vec<_>>();
        let receipt = verify_capture(
            &directory,
            &fixture.reservation.record,
            CaptureAuthentication::Publication,
        )
        .unwrap();
        for (_, role, path, watcher) in &streams {
            assert!(
                !observed_stream_read(watcher),
                "producer receipt must not scan {role:?} at {}",
                path.display()
            );
        }
        drop(receipt);

        let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::AfterObject, false);
        let mut worker = fixture.snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let publisher = SnapshotStore::from_store(Arc::new(worker));
        let capture = fixture.reservation.record.capture_id;
        let staging = directory.path().to_path_buf();
        let alias = fixture.reservation.record.alias.clone();
        let waiter = tokio::spawn(async move {
            publisher
                .publish_capture(
                    capture,
                    &staging,
                    alias,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        // Linux vfs_clone_file_range emits IN_ACCESS for FICLONE itself.
        // Pool scan_stats measure publication payload reads; access watches
        // can only exclude scans before and after the clone/copy interval.
        for (_, _, _, watcher) in &streams {
            let _ = observed_stream_read(watcher);
        }
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        let id = crate::storage::identity::StreamId::from_sha256(
            *evidence.memory.as_ref().unwrap().ram_stream.as_bytes(),
        );
        let output_watchers = streams
            .iter()
            .map(|(stream, role, _, _)| {
                let path = pool.stream_path(stream);
                let watcher = watch_stream_reads(&path);
                (role, path, watcher)
            })
            .collect::<Vec<_>>();
        release.send(()).unwrap();
        let published = waiter.await.unwrap().unwrap();
        for (_, role, path, watcher) in &streams {
            assert!(
                !observed_stream_read(watcher),
                "post-publication source scan of {role:?} at {}",
                path.display()
            );
        }
        for (role, path, watcher) in &output_watchers {
            assert!(
                !observed_stream_read(watcher),
                "closure must consume {role:?} capability at {}",
                path.display()
            );
        }
        let consumer = fixture
            .snapshots
            .consume_shape(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        let SnapshotCaptureKind::LiveExecution { execution } = &consumer.record.capture else {
            panic!("live checkpoint");
        };
        assert_eq!(execution.memory.stream, id);
        assert_eq!(
            std::fs::read(pool.stream_path(&id)).unwrap(),
            vec![0x32; 4096]
        );
    }

    #[tokio::test]
    async fn ram_publication_refuses_staged_swap_after_publication_proof() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};

        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::AfterObject, false);
        let mut worker = fixture.snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let publisher = SnapshotStore::from_store(Arc::new(worker));
        let capture = fixture.reservation.record.capture_id;
        let staging = directory.path().to_path_buf();
        let alias = fixture.reservation.record.alias.clone();
        let waiter = tokio::spawn(async move {
            publisher
                .publish_capture(
                    capture,
                    &staging,
                    alias,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        let path = directory.path().join(CaptureRole::Ram.relative_path());
        std::fs::rename(&path, directory.path().join("replaced-ram")).unwrap();
        std::fs::write(&path, vec![0x32; 4096]).unwrap();
        release.send(()).unwrap();
        assert!(
            waiter.await.unwrap().is_err(),
            "even identical replacement bytes are not the held staged inode"
        );
        let snapshots: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_snapshot")
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(snapshots, 0);
    }

    #[tokio::test]
    async fn interrupted_ram_publication_reauthenticates_staging_on_replay() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};

        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::AfterObject, false);
        let mut worker = fixture.snapshots.store.as_ref().clone();
        worker.layer_hook = Some(hook);
        let publisher = SnapshotStore::from_store(Arc::new(worker));
        let capture = fixture.reservation.record.capture_id;
        let staging = directory.path().to_path_buf();
        let alias = fixture.reservation.record.alias.clone();
        let waiter = tokio::spawn(async move {
            publisher
                .publish_capture(
                    capture,
                    &staging,
                    alias,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.recv())
            .await
            .unwrap()
            .unwrap();
        drop(release);
        assert!(waiter.await.unwrap().is_err());
        let path = directory.path().join(CaptureRole::Ram.relative_path());
        std::fs::write(&path, vec![0xa7; 4096]).unwrap();
        assert!(
            fixture
                .snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    fixture.reservation.record.alias.clone(),
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .is_err(),
            "a previous in-memory proof cannot authorize replay"
        );
        std::fs::write(&path, vec![0x32; 4096]).unwrap();
        let published = fixture
            .snapshots
            .publish_capture(
                capture,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap()
                .state,
            CaptureState::Published {
                snapshot: published.id
            },
        );
    }
    fn disk_baseline_receipt(
        record: &crate::store::snapshot_store::CaptureRecord,
    ) -> vm_spec::capture::DiskTrackingReceipt {
        use vm_spec::capture::{DiskGenerationToken, DiskTrackingReceipt, DISK_TRACKING_VERSION};
        let seed = record.storage.disk_baselines[0].seed.clone();
        DiskTrackingReceipt {
            version: DISK_TRACKING_VERSION,
            seed: seed.clone(),
            token: DiskGenerationToken {
                capture_id: record.plan.capture_id.clone(),
                pause_generation: 1,
                epoch: seed.epoch.clone(),
                generation: 1,
                file_device: seed.file_device,
                file_inode: seed.file_inode,
            },
            runs: Vec::new(),
            dirty_chunks: 0,
            total_chunks: seed.length.div_ceil(seed.chunk_size),
            invalid_reason: None,
        }
    }

    #[tokio::test]
    async fn disk_baseline_lifecycle_is_durable_and_restart_is_conservative() {
        use crate::store::models::storage::DiskBaselineState;
        use std::os::unix::fs::FileExt;
        let fixture = fixture().await;
        let store = &fixture.snapshots.store;
        let mut record = fixture.reservation.record.clone();
        let initial = store
            .machine_storage(record.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(initial.disk_baselines[0].state, DiskBaselineState::Running { run_id, seeded: true } if run_id == record.run_id)
        );
        assert!(record.plan.disks[0].baseline_map.is_some());
        assert!(crate::machine::root_storage::launch_disk_seeds(
            &initial,
            &fixture.config.machine_dir,
            &store.images_dir,
        )
        .unwrap()
        .is_empty());
        let reopened = Store::new(&crate::paths::LocalPaths::new(store.home_path()))
            .await
            .unwrap();
        assert_eq!(
            reopened
                .machine_storage(record.machine_id)
                .await
                .unwrap()
                .unwrap()
                .disk_baselines,
            initial.disk_baselines
        );
        let (directory, mut evidence) = seal(&fixture);
        let seed = initial.disk_baselines[0].seed.clone();
        evidence
            .disk_tracking_receipts
            .push(disk_baseline_receipt(&record));
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        let mut verified =
            verify_capture(&directory, &record, CaptureAuthentication::Publication).unwrap();
        verified.admit_maps(store, record.capture_id).await.unwrap();
        verified
            .retain_disk_baselines(&fixture.config.machine_dir, &record.plan)
            .unwrap();
        assert_eq!(
            store
                .machine_storage(record.machine_id)
                .await
                .unwrap()
                .unwrap()
                .disk_baselines,
            initial.disk_baselines,
            "failed or cancelled candidate cannot replace its predecessor"
        );
        std::fs::File::options()
            .write(true)
            .open(fixture.config.machine_dir.join("root.raw"))
            .unwrap()
            .write_all_at(b"post-cut", 0)
            .unwrap();
        record.evidence = Some(String::from_utf8(evidence.canonical_bytes().unwrap()).unwrap());
        store.accept_capture_disk_baselines(&record).await.unwrap();
        let accepted = store
            .machine_storage(record.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.disk_baselines[0].generation, 1);
        assert_eq!(accepted.disk_baselines[0].seed.epoch, seed.epoch);
        assert!(
            matches!(accepted.disk_baselines[0].state, DiskBaselineState::Running { run_id, seeded: true } if run_id == record.run_id)
        );
        fixture
            .snapshots
            .publish_capture(
                record.capture_id,
                directory.path(),
                record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(record.capture_id, true)
            .await
            .unwrap();
        let mut repeat = record.request.clone();
        repeat.capture_id = Uuid::new_v4();
        repeat.alias = Some("checkpoint-repeat".into());
        let next_capture = fixture.snapshots.reserve_capture(&repeat).await.unwrap();
        assert!(next_capture.record.plan.disks[0].tracking_eligible);
        assert_eq!(
            next_capture.record.plan.disks[0]
                .baseline_map
                .as_ref()
                .unwrap(),
            &fixture
                .config
                .machine_dir
                .join(
                    crate::machine::root_storage::baseline_map_path(&Sha256Digest::from_bytes(
                        *accepted.disk_baselines[0].map.as_bytes()
                    ))
                    .unwrap()
                    .as_path()
                )
                .to_string_lossy()
                .into_owned()
        );
        fixture
            .snapshots
            .abandon_capture(repeat.capture_id)
            .await
            .unwrap();
        let operation = fixture.launch.operation_id();
        drop(fixture.launch);
        let stopped = MachineState {
            machine_id: record.machine_id,
            status: MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: Some(record.run_id.to_string()),
            last_error: None,
            updated_at: 3,
        };
        assert!(store
            .try_retire_launch_storage(
                operation,
                record.run_id,
                0,
                &stopped,
                crate::StorageStopOutcome::Clean
            )
            .await
            .unwrap());
        let ended = store
            .machine_storage(record.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            ended.disk_baselines[0].state,
            DiskBaselineState::Invalid
        ));
        assert!(crate::machine::root_storage::launch_disk_seeds(
            &ended,
            &fixture.config.machine_dir,
            &store.images_dir,
        )
        .unwrap()
        .is_empty());
        let next = store
            .register_launch_storage(
                record.machine_id,
                Uuid::new_v4(),
                &ended,
                &fixture.config.spec,
            )
            .await
            .unwrap();
        store
            .mark_launch_storage_admitted(next.operation_id())
            .await
            .unwrap();
        assert!(store
            .machine_storage(record.machine_id)
            .await
            .unwrap()
            .unwrap()
            .disk_baselines
            .is_empty());
    }

    #[tokio::test]
    async fn disk_baseline_schema_requires_explicit_array_and_invalidation_is_durable() {
        use crate::store::models::storage::DiskBaselineState;
        let fixture = fixture().await;
        let store = &fixture.snapshots.store;
        for query in [
            "UPDATE machine_storage SET record_json=jsonb(json_set(record_json,'$.diskBaselines',NULL)) WHERE machine_id=?1",
            "UPDATE machine_storage SET record_json=jsonb(json_set(record_json,'$.diskBaselines',jsonb('{}'))) WHERE machine_id=?1",
            "UPDATE machine_storage SET record_json=jsonb(json_set(record_json,'$.diskBaselines',jsonb('null'))) WHERE machine_id=?1",
        ] {
            assert!(sqlx::query(query)
                .bind(fixture.config.id.to_string())
                .execute(&store.pool)
                .await
                .is_err());
        }
        assert!(sqlx::query("UPDATE machine_storage SET record_json=jsonb(json_remove(record_json,'$.diskBaselines')) WHERE machine_id=?1")
            .bind(fixture.config.id.to_string()).execute(&store.pool).await.is_err());
        store
            .invalidate_machine_disk_baselines(fixture.config.id)
            .await
            .unwrap();
        let reopened = Store::new(&crate::paths::LocalPaths::new(store.home_path()))
            .await
            .unwrap();
        assert!(matches!(
            reopened
                .machine_storage(fixture.config.id)
                .await
                .unwrap()
                .unwrap()
                .disk_baselines[0]
                .state,
            DiskBaselineState::Invalid
        ));
    }
    #[tokio::test]
    async fn external_writable_disks_remain_capturable_but_never_tracking_eligible() {
        let fixture = fixture_with_external_data(true).await;
        let disks = &fixture.reservation.record.plan.disks;
        assert_eq!(disks.len(), 2);
        assert!(disks[0].tracking_eligible);
        assert!(!disks[1].tracking_eligible);
        assert!(disks[1].baseline_map.is_none());
        assert_eq!(fixture.reservation.record.storage.disk_baselines.len(), 1);
        let (directory, _) = seal(&fixture);
        fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn disk_baseline_crash_between_admission_and_stop_never_reuses_ready() {
        use crate::store::models::storage::DiskBaselineState;
        const HOME: &str = "SILO_DISK_TRACKING_CRASH_HOME";
        const MACHINE: &str = "SILO_DISK_TRACKING_CRASH_MACHINE";
        if let Ok(home) = std::env::var(HOME) {
            let store = Store::new(&LocalPaths::new(home)).await.unwrap();
            let machine: MachineId = std::env::var(MACHINE).unwrap().parse().unwrap();
            let config = store.machine_config(machine).await.unwrap().unwrap();
            let storage = store.machine_storage(machine).await.unwrap().unwrap();
            let run = Uuid::new_v4();
            let launch = store
                .register_launch_storage(machine, run, &storage, &config.spec)
                .await
                .unwrap();
            store
                .save_machine_state(&MachineState {
                    machine_id: machine,
                    status: MachineRuntimeState::Starting,
                    vmm_pid: None,
                    started_at: None,
                    run_id: Some(run.to_string()),
                    last_error: None,
                    updated_at: 4,
                })
                .await
                .unwrap();
            store
                .mark_launch_storage_admitted(launch.operation_id())
                .await
                .unwrap();
            std::process::exit(77);
        }
        let fixture = fixture().await;
        let store = &fixture.snapshots.store;
        let original = &fixture.reservation.record;
        let operation = fixture.launch.operation_id();
        drop(fixture.launch);
        let stopped = MachineState {
            machine_id: original.machine_id,
            status: MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: Some(original.run_id.to_string()),
            last_error: None,
            updated_at: 3,
        };
        assert!(store
            .try_retire_launch_storage(
                operation,
                original.run_id,
                0,
                &stopped,
                crate::StorageStopOutcome::Clean
            )
            .await
            .unwrap());
        let mut storage = store
            .machine_storage(original.machine_id)
            .await
            .unwrap()
            .unwrap();
        let file = std::fs::File::open(fixture.config.machine_dir.join("root.raw")).unwrap();
        let map = StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_open_file(&file, 512)
            .unwrap()
            .map;
        let baseline_roots = crate::machine::root_storage::seed_disk(
            &mut storage,
            &StoragePool::open(&store.images_dir).unwrap(),
            &fixture.config.machine_dir,
            0,
            &fixture.config.spec.storage.as_ref().unwrap().disks[0],
            &file,
            &map,
        )
        .unwrap();
        store
            .save_machine_config_with_storage(&fixture.config, &storage)
            .await
            .unwrap();
        drop(baseline_roots);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::capture::tests::disk_baseline_crash_between_admission_and_stop_never_reuses_ready", "--nocapture"])
            .env(HOME, store.home_path()).env(MACHINE, original.machine_id.to_string()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let crashed = store
            .machine_storage(original.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            crashed.disk_baselines[0].state,
            DiskBaselineState::Running { seeded: true, .. }
        ));
        assert!(crate::machine::root_storage::launch_disk_seeds(
            &crashed,
            &fixture.config.machine_dir,
            &store.images_dir,
        )
        .unwrap()
        .is_empty());
        let launches = store
            .launch_storage_operations(original.machine_id)
            .await
            .unwrap();
        assert_eq!(launches.len(), 1);
        let mut stopped = stopped;
        stopped.run_id = Some(launches[0].run_id.to_string());
        assert!(store
            .try_retire_launch_storage(
                launches[0].operation_id,
                launches[0].run_id,
                0,
                &stopped,
                crate::StorageStopOutcome::Unknown
            )
            .await
            .unwrap());
        let restart = store
            .machine_storage(original.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            restart.disk_baselines[0].state,
            DiskBaselineState::Invalid
        ));
        assert!(crate::machine::root_storage::launch_disk_seeds(
            &restart,
            &fixture.config.machine_dir,
            &store.images_dir,
        )
        .unwrap()
        .is_empty());
    }
    #[tokio::test]
    async fn disk_baseline_acceptance_survives_snapshot_publication_failure() {
        let fixture = fixture().await;
        let record = &fixture.reservation.record;
        let store = &fixture.snapshots.store;
        let (directory, mut evidence) = seal(&fixture);
        evidence
            .disk_tracking_receipts
            .push(disk_baseline_receipt(record));
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        sqlx::query("CREATE TRIGGER reject_capture_publication BEFORE UPDATE ON storage_operation WHEN NEW.kind='capture' BEGIN SELECT RAISE(ABORT,'publication interrupted'); END")
            .execute(&store.pool).await.unwrap();
        assert!(fixture
            .snapshots
            .publish_capture(
                record.capture_id,
                directory.path(),
                record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait
            )
            .await
            .is_err());
        assert!(fixture.snapshots.list().await.unwrap().is_empty());
        assert!(fixture
            .snapshots
            .capture_reservation(record.capture_id)
            .await
            .unwrap()
            .unwrap()
            .evidence
            .is_none());
        fixture
            .snapshots
            .accept_live_disk_baselines(record)
            .await
            .unwrap();
        let accepted = store
            .machine_storage(record.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.disk_baselines[0].generation, 1);
        assert_eq!(
            accepted.disk_baselines[0].seed.epoch,
            evidence.disk_tracking_receipts[0].seed.epoch
        );
    }
    fn free_capture_bytes(store: &Store) -> u64 {
        let directory = OwnedDirectory::open_existing_root(&store.images_dir)
            .unwrap()
            .unwrap();
        let stat = nix::sys::statvfs::fstatvfs(directory.fd()).unwrap();
        stat.blocks_available()
            .checked_mul(stat.fragment_size())
            .unwrap()
    }

    async fn change_import_credit(store: &Store, operation: Uuid, bytes: u64, descriptors: u64) {
        let directory = crate::store::restore::budget_directory(store).unwrap();
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let mut inventory: crate::store::restore::CaptureBudgetInventory =
            serde_json::from_str(&json).unwrap();
        inventory.capture_disks[0].bytes = bytes;
        inventory.descriptors = descriptors;
        inventory.descriptor_owner =
            (descriptors != 0).then(|| crate::store::restore::DescriptorOwner::current().unwrap());
        let json = serde_json::to_string(&inventory).unwrap();
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(&json)
        .execute(&store.pool)
        .await
        .unwrap();
        let state = std::fs::metadata(store.home_path().join("state.db")).unwrap();
        directory
            .write_file_atomic(
                &format!("{}-{}-{operation}.json", state.dev(), state.ino()),
                json.as_bytes(),
            )
            .unwrap();
    }

    async fn import_credit_owner(store: &Store) -> (Uuid, crate::storage::locks::StorageLock) {
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        store.reserve_import_space(operation, 1).await.unwrap();
        (operation, lease)
    }

    async fn mark_fixture_stopped(store: &Store, machine: MachineId) {
        use protocol::shutdown::{StorageHolder, StorageHolderRecord, StorageHolderRole};
        for operation in store.launch_storage_operations(machine).await.unwrap() {
            let pool = StoragePool::open(&store.images_dir).unwrap();
            let lease = pool.existing_lease(operation.operation_id).unwrap();
            let mut holder = std::process::Command::new("sleep")
                .arg("60")
                .stdin(std::process::Stdio::from(lease.durability_file().unwrap()))
                .spawn()
                .unwrap();
            let pid = i32::try_from(holder.id()).unwrap();
            let started_at = utils::process::start_time(pid).unwrap().unwrap();
            let record = StorageHolderRecord {
                schema_version: 1,
                machine_id: Uuid::from(machine).to_string(),
                run_id: operation.run_id.to_string(),
                operation_id: operation.operation_id.to_string(),
                holders: vec![StorageHolder {
                    role: StorageHolderRole::Monitor,
                    pid: holder.id(),
                    started_at: u64::try_from(started_at).unwrap(),
                }],
            };
            let paths = LocalPaths::new(store.home_path().to_path_buf());
            paths.ensure_machine_run_dir(machine).unwrap();
            let path = paths.machine(machine).vmm_storage_holder_path();
            let directory = OwnedDirectory::open_existing_root(path.parent().unwrap())
                .unwrap()
                .unwrap();
            directory
                .write_file("vm.storage-holder.json", &record.encode().unwrap())
                .unwrap();
            holder.kill().unwrap();
            holder.wait().unwrap();
        }
        let mut state = store.machine_state(machine).await.unwrap().unwrap();
        state.status = MachineRuntimeState::Stopped;
        state.vmm_pid = None;
        state.run_id = None;
        store.save_machine_state(&state).await.unwrap();
    }

    #[tokio::test]
    async fn budget_and_descriptor_refusal_leave_no_capture_ownership_and_allow_removal() {
        for descriptors in [false, true] {
            let Fixture {
                _temporary,
                snapshots,
                config,
                reservation,
                launch,
            } = fixture().await;
            let mut request = reservation.record.request.clone();
            snapshots.abandon_capture(request.capture_id).await.unwrap();
            drop(reservation);
            let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
            snapshots
                .store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            assert!(snapshots
                .pending_captures(Some(config.id))
                .await
                .unwrap()
                .is_empty());
            let (owner, _credit) = import_credit_owner(&snapshots.store).await;
            let (_, hard) =
                nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
            change_import_credit(
                &snapshots.store,
                owner,
                if descriptors {
                    1
                } else {
                    free_capture_bytes(&snapshots.store)
                },
                if descriptors { hard } else { 0 },
            )
            .await;
            request.capture_id = Uuid::new_v4();
            request.alias = None;
            let error = match snapshots.reserve_capture(&request).await {
                Ok(_) => panic!("capture was admitted without capacity"),
                Err(error) => error,
            };
            assert!(
                if descriptors {
                    error.to_string().contains("file descriptor budget")
                } else {
                    error.to_string().contains("pre-freeze admission")
                },
                "{error}"
            );
            for statement in [
                "SELECT count(*) FROM storage_operation WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_stream WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_object WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_layer WHERE operation_id=?1",
                "SELECT count(*) FROM storage_operation_lower WHERE operation_id=?1",
                "SELECT count(*) FROM capture_resource_reservation WHERE operation_id=?1",
            ] {
                let count: i64 = sqlx::query_scalar(statement)
                    .bind(request.capture_id.to_string())
                    .fetch_one(&snapshots.store.pool)
                    .await
                    .unwrap();
                assert_eq!(count, 0, "{statement}");
            }
            let commands: i64 =
                sqlx::query_scalar("SELECT count(*) FROM live_command WHERE request_id=?1")
                    .bind(request.capture_id.to_string())
                    .fetch_one(&snapshots.store.pool)
                    .await
                    .unwrap();
            assert_eq!(commands, 0);
            assert!(!config
                .machine_dir
                .join(request.capture_id.to_string())
                .exists());
            assert!(!config
                .machine_dir
                .join("captures")
                .join(request.capture_id.to_string())
                .exists());
            assert!(!snapshots
                .store
                .images_dir
                .join("tmp")
                .join(request.capture_id.to_string())
                .exists());
            drop(launch);
            mark_fixture_stopped(&snapshots.store, config.id).await;
            let runtime = capture_runtime(&snapshots).await;
            runtime
                .get_machine(&crate::MachineRef::id(config.id))
                .await
                .unwrap()
                .remove_force()
                .await
                .unwrap();
            assert!(runtime.list_machines().await.unwrap().is_empty());
        }
    }

    async fn journal_fixture_capture(
        store: &Store,
        record: &crate::store::snapshot_store::CaptureRecord,
    ) -> crate::store::live_store::LiveCommandIntent {
        use vm_spec::lifecycle::{CaptureCommand, LiveCommand, LiveCommandEnvelope};
        use vm_spec::live::{
            LiveBackend, LiveCapabilityVector, LiveLane, LiveMachineReport, LiveReasonCode,
            LiveScope,
        };
        let intent = crate::store::live_store::LiveCommandIntent {
            report: LiveMachineReport {
                schema_version: 1,
                scope: LiveScope::Machine,
                machine_id: record.plan.machine_id.to_string(),
                run_id: record.run_id.to_string(),
                monitor_id: Uuid::new_v4().to_string(),
                backend: LiveBackend::Krun,
                lane: LiveLane::KvmX86_64,
                topology_revision: 1,
                live: LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered),
            },
            command: LiveCommand::Capture(Box::new(CaptureCommand {
                envelope: LiveCommandEnvelope {
                    machine_id: record.plan.machine_id.clone(),
                    run_id: record.plan.run_id.clone(),
                    request_id: record.plan.capture_id.clone(),
                },
                plan: record.plan.clone(),
            })),
        };
        sqlx::query("INSERT INTO live_command(machine_id,run_id,request_id,monitor_id,input_json) VALUES(?1,?2,?3,?4,jsonb(?5))")
            .bind(record.machine_id.to_string()).bind(record.run_id.to_string()).bind(record.capture_id.to_string()).bind(&intent.report.monitor_id)
            .bind(serde_json::to_string(&intent).unwrap()).execute(&store.pool).await.unwrap();
        intent
    }

    #[tokio::test]
    async fn interrupted_first_dispatch_retires_without_rpc_or_fresh_capacity() {
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture().await;
        let record = reservation.record.clone();
        journal_fixture_capture(&snapshots.store, &record).await;
        let (owner, _credit) = import_credit_owner(&snapshots.store).await;
        change_import_credit(
            &snapshots.store,
            owner,
            free_capture_bytes(&snapshots.store) + (64 << 20),
            0,
        )
        .await;
        drop(reservation);
        let runtime = capture_runtime(&snapshots).await;
        runtime.reconcile_captures().await.unwrap();
        let command = snapshots
            .store
            .live_command_record(config.id, record.run_id, record.capture_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            command.result,
            Some(vm_spec::lifecycle::LiveCommandResult::Capture(
                vm_spec::lifecycle::CaptureOutcome::Rejected { .. }
            ))
        ));
        assert!(snapshots
            .pending_captures(Some(config.id))
            .await
            .unwrap()
            .is_empty());
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        snapshots
            .store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert!(snapshots
            .capture_reservation(record.capture_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            snapshots
                .store
                .machine_state(config.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MachineRuntimeState::Running
        );
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dispatch_capacity_refusal_is_terminal_without_a_monitor_endpoint_or_replay() {
        use vm_spec::lifecycle::{LiveCommand, LiveCommandResult};
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture().await;
        let record = reservation.record.clone();
        let intent = journal_fixture_capture(&snapshots.store, &record).await;
        let report = intent.report.clone();
        let (owner, _credit) = import_credit_owner(&snapshots.store).await;
        change_import_credit(
            &snapshots.store,
            owner,
            free_capture_bytes(&snapshots.store),
            0,
        )
        .await;
        let runtime = capture_runtime(&snapshots).await;
        let machine = runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap();
        let result = machine.send_prepared(intent.clone()).await.unwrap();
        assert!(
            matches!(&result, LiveCommandResult::Capture(vm_spec::lifecycle::CaptureOutcome::Rejected { rejection }) if rejection.to_string().contains("dispatch refusal before send"))
        );
        let observation = crate::machine::live::MachineLiveObservation::for_test(
            report,
            vm_spec::lifecycle::VmLifecycleState::Running,
            vm_spec::lifecycle::LiveLifecycle::default(),
        );
        assert_eq!(
            machine
                .live_command(&observation, intent.command.clone())
                .await
                .unwrap(),
            result
        );
        assert!(
            !snapshots
                .capture_reservation(record.capture_id)
                .await
                .unwrap()
                .unwrap()
                .dispatch_attempted
        );
        assert!(snapshots
            .pending_captures(Some(config.id))
            .await
            .unwrap()
            .is_empty());
        // A durable attempt fence instead denotes an uncertain earlier send.
        // A new local capacity failure must not invent a terminal RPC outcome.
        change_import_credit(&snapshots.store, owner, 1, 0).await;
        let mut request = record.request.clone();
        request.capture_id = Uuid::new_v4();
        request.alias = None;
        let uncertain = snapshots.reserve_capture(&request).await.unwrap();
        let mut uncertain_intent = intent;
        if let LiveCommand::Capture(command) = &mut uncertain_intent.command {
            command.plan = uncertain.record.plan.clone();
            command.envelope.request_id = uncertain.record.plan.capture_id.clone();
        }
        sqlx::query("INSERT INTO live_command(machine_id,run_id,request_id,monitor_id,input_json) VALUES(?1,?2,?3,?4,jsonb(?5))")
            .bind(config.id.to_string()).bind(record.run_id.to_string()).bind(request.capture_id.to_string()).bind(&uncertain_intent.report.monitor_id)
            .bind(serde_json::to_string(&uncertain_intent).unwrap()).execute(&snapshots.store.pool).await.unwrap();
        if let LiveCommand::Capture(command) = &uncertain_intent.command {
            snapshots
                .store
                .require_capture_dispatch(command)
                .await
                .unwrap();
        }
        change_import_credit(
            &snapshots.store,
            owner,
            free_capture_bytes(&snapshots.store) + (1 << 20),
            0,
        )
        .await;
        assert!(machine
            .send_prepared(uncertain_intent)
            .await
            .unwrap_err()
            .to_string()
            .contains("dispatch refusal"));
        assert!(snapshots
            .store
            .live_command_record(config.id, record.run_id, request.capture_id)
            .await
            .unwrap()
            .unwrap()
            .result
            .is_none());
        drop(uncertain);
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        machine.remove_force().await.unwrap();
    }

    #[tokio::test]
    async fn sealed_publication_admits_only_remaining_credit() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config: _,
            reservation,
            launch,
        } = fixture;
        let record = reservation.record.clone();
        drop(reservation);
        drop(launch);
        let (owner, _credit) = import_credit_owner(&snapshots.store).await;
        let publication = record.reservation_bytes - record.plan.reservation.staging_bytes;
        change_import_credit(
            &snapshots.store,
            owner,
            free_capture_bytes(&snapshots.store) - publication - (8 << 20),
            0,
        )
        .await;
        let snapshot = snapshots
            .publish_capture(
                record.capture_id,
                directory.path(),
                record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        snapshots
            .verify(&SnapshotRef::Id(snapshot.id))
            .await
            .unwrap();
        assert!(directory.path().exists());
    }

    #[tokio::test]
    async fn maintenance_open_lists_and_force_removes_a_publication_deferred_capture() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let capture = reservation.record.capture_id;
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        let (owner, _credit) = import_credit_owner(&snapshots.store).await;
        change_import_credit(
            &snapshots.store,
            owner,
            free_capture_bytes(&snapshots.store),
            0,
        )
        .await;
        let reopened = SnapshotStore::open(snapshots.store.home_path())
            .await
            .unwrap();
        let runtime = capture_runtime(&reopened).await;
        runtime.recover_maintenance().await.unwrap();
        assert_eq!(runtime.list_machines().await.unwrap().len(), 1);
        assert!(reopened.list().await.unwrap().is_empty());
        assert!(directory.path().exists());
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .unwrap();
        assert!(runtime.list_machines().await.unwrap().is_empty());
        assert!(!directory.path().exists());
        assert!(!snapshots
            .store
            .home_path()
            .join("capture-evidence")
            .join(capture.to_string())
            .exists());
        assert!(reopened.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn published_snapshot_survives_forced_source_removal_and_verifies() {
        let fixture = fixture().await;
        let snapshot = publish_fixture(&fixture).await;
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let capture = reservation.record.capture_id;
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        let before = snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap();
        let after = snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, before.state);
        assert_eq!(after.evidence, before.evidence);
        assert!(after.discard.is_none());
        let runtime = capture_runtime(&snapshots).await;
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .unwrap();
        snapshots
            .verify(&SnapshotRef::Id(snapshot.id))
            .await
            .unwrap();
        assert_eq!(
            snapshots
                .inspect(&SnapshotRef::Id(snapshot.id))
                .await
                .unwrap()
                .id,
            snapshot.id
        );
    }

    #[tokio::test]
    async fn forced_discard_refuses_capture_and_accepted_baseline_holders() {
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture().await;
        let capture = reservation.record.capture_id;
        let error = snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("active lease"), "{error}");
        drop(reservation);
        let error = snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("accepted baseline holder"),
            "{error}"
        );
        assert!(snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .is_some());
        drop(launch);
    }

    #[tokio::test]
    async fn forced_discard_refuses_unrelocated_fork_children_but_preserves_relocated_cuts() {
        for local_cut in [false, true] {
            let fixture = fork_fixture().await;
            let capture = fixture.reservation.record.capture_id;
            let operation = fixture.reservation.record.fork_operation_id.unwrap();
            if local_cut {
                seal(&fixture);
                fixture
                    .snapshots
                    .retain_local_capture(
                        capture,
                        crate::storage::pool::PublicationLockPolicy::Wait,
                    )
                    .await
                    .unwrap();
            }
            let Fixture {
                _temporary,
                snapshots,
                config,
                reservation,
                launch,
            } = fixture;
            drop(reservation);
            drop(launch);
            if local_cut {
                let before = snapshots
                    .capture_reservation(capture)
                    .await
                    .unwrap()
                    .unwrap();
                snapshots
                    .store
                    .discard_machine_captures(config.id)
                    .await
                    .unwrap();
                assert_eq!(
                    snapshots
                        .capture_reservation(capture)
                        .await
                        .unwrap()
                        .unwrap()
                        .state,
                    before.state
                );
                assert!(snapshots
                    .store
                    .open_local_cut(operation, None)
                    .await
                    .is_ok());
            } else {
                let error = snapshots
                    .store
                    .discard_machine_captures(config.id)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        &error,
                        crate::LibVmError::CaptureRemovalDependency { capture_id, dependency }
                            if *capture_id == capture && dependency.contains("fork-first")
                    ),
                    "{error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn forced_child_then_source_removal_preserves_independent_fork_cut_and_retires_all_owners(
    ) {
        use crate::machine::stopped::PrivateSource;

        let fixture = fork_fixture().await;
        seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let operation = fixture.reservation.record.fork_operation_id.unwrap();
        let (cut, retained) = fixture
            .snapshots
            .retain_local_capture(capture, crate::storage::pool::PublicationLockPolicy::Wait)
            .await
            .unwrap();
        let store = fixture.snapshots.store.clone();
        let held = store.open_local_cut(operation, retained).await.unwrap();
        store.bind_fork_resources(&held).await.unwrap();
        let runtime = capture_runtime(&fixture.snapshots).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let children = store.fork_children(operation).await.unwrap();
        let root = cut.plan.disks[0].name.clone();
        let mut constructed = Vec::new();
        for child in children {
            // Exercise the real private-copy constructor and real consumer OFD,
            // without claiming that opaque fixture state can boot a VM.
            let lease = pool.existing_lease(child.consumer_id).unwrap();
            let config = crate::machine::builder::publish_stopped_child(
                &runtime,
                child.result.name.clone(),
                cut.configuration.clone(),
                cut.storage.clone(),
                vec![PrivateSource::Authenticated {
                    path: crate::PrivatePath::new("root.raw").unwrap(),
                    stream: held.reopen_disk(&CaptureRole::Disk(root.clone())).unwrap(),
                }],
                child.consumer_id,
            )
            .await
            .unwrap();
            assert_eq!(config.id, child.result.machine_id);
            assert_eq!(
                std::fs::read(config.machine_dir.join("root.raw")).unwrap(),
                [0x51; 512]
            );
            constructed.push((child, config, lease));
        }
        let survivor = constructed[1].1.machine_dir.join("root.raw");
        let source = fixture.config.clone();
        let Fixture {
            _temporary,
            reservation,
            launch,
            ..
        } = fixture;
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&store, source.id).await;
        for (index, (child, config, lease)) in constructed.into_iter().enumerate() {
            runtime
                .get_machine(&crate::MachineRef::id(config.id))
                .await
                .unwrap()
                .remove_force()
                .await
                .unwrap();
            assert!(!config.machine_dir.exists());
            drop(lease);
            store
                .finish_stopped_operation(child.consumer_id)
                .await
                .unwrap();
            store
                .set_fork_child(
                    operation,
                    child.result.index,
                    crate::ForkChildOutcome::Abandoned {
                        diagnostic: crate::machine::live_fork::diagnostic(
                            "store-level child removed",
                        ),
                    },
                )
                .await
                .unwrap();
            store
                .release_abandoned_fork_name(operation, child.result.index)
                .await
                .unwrap();
            if index == 0 {
                assert_eq!(
                    std::fs::read(source.machine_dir.join("root.raw")).unwrap(),
                    [0x51; 512]
                );
                runtime
                    .get_machine(&crate::MachineRef::id(source.id))
                    .await
                    .unwrap()
                    .remove_force()
                    .await
                    .unwrap();
                assert!(!source.machine_dir.exists());
                assert_eq!(std::fs::read(&survivor).unwrap(), [0x51; 512]);
                assert!(store.open_local_cut(operation, None).await.is_ok());
            }
        }
        drop(held);
        store
            .update_fork(operation, |result| {
                result.stage = crate::ForkStage::Finished;
                Ok(())
            })
            .await
            .unwrap();
        store.recover_image_cache().await.unwrap();
        assert!(runtime.list_machines().await.unwrap().is_empty());
        for query in [
            "SELECT count(*) FROM storage_operation",
            "SELECT count(*) FROM capture_resource_reservation",
            "SELECT count(*) FROM restore_resource_reservation",
            "SELECT count(*) FROM storage_operation_stream",
            "SELECT count(*) FROM storage_operation_object",
            "SELECT count(*) FROM storage_operation_layer",
            "SELECT count(*) FROM storage_operation_lower",
            "SELECT count(*) FROM storage_operation_cut",
            "SELECT count(*) FROM local_cut",
        ] {
            let count: i64 = sqlx::query_scalar(query)
                .fetch_one(&store.pool)
                .await
                .unwrap();
            assert_eq!(count, 0, "{query}");
        }
        assert!(std::fs::read_dir(store.images_dir.join("tmp"))
            .unwrap()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn forced_discard_rejects_replaced_staging_inode_after_its_durable_fence() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let mut record = reservation.record.clone();
        let parent = OwnedDirectory::open_existing_root(directory.path().parent().unwrap())
            .unwrap()
            .unwrap();
        let parent_stat = nix::sys::stat::fstat(parent.fd()).unwrap();
        let stat = nix::sys::stat::fstat(directory.fd()).unwrap();
        record.discard = Some(crate::store::snapshot_store::CaptureDiscard {
            parent: Some((parent_stat.st_dev as u64, parent_stat.st_ino as u64)),
            directory: Some((stat.st_dev as u64, stat.st_ino as u64 + 1)),
        });
        sqlx::query("UPDATE storage_operation SET state='cleaning',record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(record.capture_id.to_string()).bind(crate::store::capture::encode_record(&record).unwrap()).execute(&snapshots.store.pool).await.unwrap();
        drop(reservation);
        drop(launch);
        let error = snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("inode was replaced"), "{error}");
        assert!(directory
            .open_file(vm_spec::capture::CAPTURE_RAM_FILE)
            .unwrap()
            .is_some());
    }

    #[test]
    fn clone_and_copy_publication_arithmetic_keeps_logical_ram_once_on_clones() {
        let ram = 30 << 30;
        let disk = 1 << 30;
        let state = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        let metadata = vm_spec::capture::CAPTURE_CLONE_RESERVE_BYTES;
        let stage = ram + disk + state;
        let clone_peak = stage
            + crate::store::capture::publication_stream_bytes(ram, true)
            + crate::store::capture::publication_stream_bytes(disk, true)
            + 2 * state;
        assert_eq!(clone_peak, ram + disk + 3 * state + 2 * metadata);
        let copy_peak = stage
            + crate::store::capture::publication_stream_bytes(ram, false)
            + crate::store::capture::publication_stream_bytes(disk, false)
            + 2 * state;
        assert_eq!(copy_peak, stage + ram + disk + 2 * state);
        assert!(clone_peak < 32 << 30);
    }

    #[tokio::test]
    async fn publisher_lock_defers_recovery_and_refuses_forced_discard() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let record = reservation.record.clone();
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let _publisher = pool
            .lock_publication(&crate::store::capture::capture_publication_key(
                record.capture_id,
            ))
            .unwrap();
        let error = snapshots
            .publish_capture(
                record.capture_id,
                directory.path(),
                record.alias,
                crate::storage::pool::PublicationLockPolicy::Defer,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::Storage(crate::storage::StorageError::PublicationBusy { .. })
        ));
        let runtime = capture_runtime(&snapshots).await;
        runtime.recover_maintenance().await.unwrap();
        assert_eq!(runtime.list_machines().await.unwrap().len(), 1);
        let error = runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("publisher is active"), "{error}");
        assert!(directory.path().exists());
        assert!(snapshots.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn forced_discard_restarts_partial_quarantine_deletion_without_an_archive() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let mut record = reservation.record.clone();
        let parent = OwnedDirectory::open_existing_root(directory.path().parent().unwrap())
            .unwrap()
            .unwrap();
        let p = nix::sys::stat::fstat(parent.fd()).unwrap();
        let d = nix::sys::stat::fstat(directory.fd()).unwrap();
        record.discard = Some(crate::store::snapshot_store::CaptureDiscard {
            parent: Some((p.st_dev as u64, p.st_ino as u64)),
            directory: Some((d.st_dev as u64, d.st_ino as u64)),
        });
        sqlx::query("UPDATE storage_operation SET state='cleaning',record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(record.capture_id.to_string()).bind(crate::store::capture::encode_record(&record).unwrap()).execute(&snapshots.store.pool).await.unwrap();
        crate::storage::pool::rename_component_no_replace(
            &parent,
            &record.capture_id.to_string(),
            &parent,
            &format!(".retiring-{}", record.capture_id),
        )
        .unwrap();
        nix::unistd::unlinkat(
            directory.fd(),
            vm_spec::capture::CAPTURE_RAM_FILE,
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .unwrap();
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        let reopened = SnapshotStore::open(snapshots.store.home_path())
            .await
            .unwrap();
        assert!(reopened
            .capture_reservation(record.capture_id)
            .await
            .unwrap()
            .is_none());
        assert!(!parent
            .path()
            .join(format!(".retiring-{}", record.capture_id))
            .exists());
        assert!(!snapshots
            .store
            .home_path()
            .join("capture-evidence")
            .join(record.capture_id.to_string())
            .exists());
        let runtime = capture_runtime(&reopened).await;
        runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn forced_discard_control_write_failure_preserves_staging_for_retry() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let staged_nodes = directory.path().join("map-nodes");
        assert!(std::fs::read_dir(&staged_nodes).unwrap().next().is_some());
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let capture = reservation.record.capture_id;
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        sqlx::raw_sql("CREATE TRIGGER refuse_discard BEFORE UPDATE OF record_json ON storage_operation WHEN NEW.state='cleaning' BEGIN SELECT RAISE(ABORT,'control write unavailable'); END;")
            .execute(&snapshots.store.pool).await.unwrap();
        let error = snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("control write unavailable"),
            "{error}"
        );
        assert!(directory
            .open_file(vm_spec::capture::CAPTURE_RAM_FILE)
            .unwrap()
            .is_some());
        assert!(!snapshots
            .store
            .home_path()
            .join("capture-evidence")
            .join(capture.to_string())
            .exists());
        sqlx::raw_sql("DROP TRIGGER refuse_discard;")
            .execute(&snapshots.store.pool)
            .await
            .unwrap();
        snapshots
            .store
            .discard_machine_captures(config.id)
            .await
            .unwrap();
        assert!(!directory.path().exists());
        assert!(!staged_nodes.exists());
    }

    #[tokio::test]
    async fn corrupt_capture_is_refused_individually_without_blocking_maintenance_or_listing() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let Fixture {
            _temporary,
            snapshots,
            config,
            reservation,
            launch,
        } = fixture;
        let capture = reservation.record.capture_id;
        drop(reservation);
        drop(launch);
        mark_fixture_stopped(&snapshots.store, config.id).await;
        sqlx::query("UPDATE storage_operation SET record_json=jsonb_set(record_json,'$.reservationBytes',0) WHERE operation_id=?1")
            .bind(capture.to_string()).execute(&snapshots.store.pool).await.unwrap();
        let reopened = SnapshotStore::open(snapshots.store.home_path())
            .await
            .unwrap();
        let runtime = capture_runtime(&reopened).await;
        runtime.recover_maintenance().await.unwrap();
        assert_eq!(runtime.list_machines().await.unwrap().len(), 1);
        assert!(reopened.capture_reservation(capture).await.is_err());
        assert!(runtime
            .get_machine(&crate::MachineRef::id(config.id))
            .await
            .unwrap()
            .remove_force()
            .await
            .is_err());
        assert!(directory.path().exists());
    }

    #[tokio::test]
    async fn live_full_incremental_and_unchanged_roots_publish_both_profiles() {
        use vm_spec::stream_map::{
            Chunk, ChunkChange, ChunkSize, NodeSource, StreamRole, MAX_NODE_BYTES,
        };

        let mut fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let first = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let accepted = fixture
            .snapshots
            .capture_reservation(fixture.reservation.record.capture_id)
            .await
            .unwrap()
            .unwrap();
        fixture
            .snapshots
            .accept_live_disk_baselines(&accepted)
            .await
            .unwrap();
        fixture
            .snapshots
            .finish_capture_release(accepted.capture_id, true)
            .await
            .unwrap();
        let pool = StoragePool::open(&fixture.snapshots.store.images_dir).unwrap();
        let first_consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(first.id))
            .await
            .unwrap();
        let SnapshotCaptureKind::LiveExecution { execution } = &first_consumer.record.capture
        else {
            panic!("live execution checkpoint required");
        };
        let authority = pool
            .map_authority(Arc::new(
                pool.existing_lease(first_consumer.operation_id).unwrap(),
            ))
            .unwrap();
        let mut ram = pool
            .load_map(execution.memory.map, StreamRole::Ram, authority.clone())
            .unwrap();
        let mut disk = pool
            .load_map(
                first_consumer.record.root.stream.map,
                StreamRole::Disk,
                authority,
            )
            .unwrap();
        assert_eq!(ram.chunk_size(), ChunkSize::RAM);
        assert_eq!(disk.chunk_size(), ChunkSize::DISK);

        for changed in [true, false] {
            let before: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM stream_map_object WHERE height IS NOT NULL",
            )
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
            let mut request = fixture.reservation.record.request.clone();
            request.capture_id = Uuid::new_v4();
            request.policy = CapturePolicy::Incremental;
            request.alias = None;
            fixture.reservation = fixture.snapshots.reserve_capture(&request).await.unwrap();
            fixture
                .snapshots
                .bind_capture_boot(request.capture_id, first_consumer.record.boot.clone())
                .await
                .unwrap();
            let (directory, mut evidence) = seal(&fixture);
            directory.remove_tree("map-nodes").unwrap();
            let nodes = directory.ensure_dir("map-nodes").unwrap();
            let ram_bytes = [0x66; 4096];
            let disk_bytes = [0x77; 512];
            let mut ram_writer = crate::storage::map::MapNodeWriter::new().unwrap();
            let ram_update = ram
                .update_sorted(
                    changed.then_some(Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(Sha256Digest::of_bytes(&ram_bytes)),
                    })),
                    &mut ram_writer,
                )
                .unwrap();
            let mut disk_writer = crate::storage::map::MapNodeWriter::new().unwrap();
            let disk_update = disk
                .update_sorted(
                    changed.then_some(Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(Sha256Digest::of_bytes(&disk_bytes)),
                    })),
                    &mut disk_writer,
                )
                .unwrap();
            let new_nodes = ram_update.new_nodes().len() + disk_update.new_nodes().len();
            assert!(new_nodes <= 10);
            if !changed {
                assert_eq!(new_nodes, 0);
                assert_eq!(ram_update.map, ram);
                assert_eq!(disk_update.map, disk);
            }
            for produced in [&ram_update, &disk_update] {
                let mut source = produced.map.node_source();
                let mut scratch = [0; MAX_NODE_BYTES];
                for digest in produced.new_nodes() {
                    let length = source
                        .read_node(Sha256Digest::from_bytes(*digest.as_bytes()), &mut scratch)
                        .unwrap();
                    nodes.write_file(&digest.hex(), &scratch[..length]).unwrap();
                }
            }
            let disk_role =
                CaptureRole::Disk(fixture.reservation.record.plan.disks[0].name.clone());
            directory
                .write_file(&CaptureRole::Ram.relative_path(), &ram_bytes)
                .unwrap();
            let disks = directory.open_dir("disks").unwrap().unwrap();
            disks
                .write_file(
                    &fixture.reservation.record.plan.disks[0].name.file_name(),
                    &disk_bytes,
                )
                .unwrap();
            let ram_root = ram_update.map.canonical_bytes().unwrap();
            let disk_root = disk_update.map.canonical_bytes().unwrap();
            directory
                .write_file(&CaptureRole::RamMap.relative_path(), &ram_root)
                .unwrap();
            disks
                .write_file(
                    &format!(
                        "{}.root",
                        fixture.reservation.record.plan.disks[0].name.as_str()
                    ),
                    &disk_root,
                )
                .unwrap();
            let mut changes = b"KRUNRAM\0\x01\0\x10\x01\0\0\0\0".to_vec();
            if changed {
                changes.extend_from_slice(&0u64.to_le_bytes());
                changes.extend_from_slice(&1u64.to_le_bytes());
                changes.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
                changes.extend_from_slice(Sha256Digest::of_bytes(&ram_bytes).as_bytes());
            }
            directory
                .write_file(&CaptureRole::RamChanges.relative_path(), &changes)
                .unwrap();
            let memory = evidence.memory.as_mut().unwrap();
            memory.ram_stream = ram_update.map.root().id();
            memory.mode = CapturePolicy::Incremental;
            memory.baseline = Some(ram.root().id());
            memory.full_reason = None;
            memory.stats.full_bytes_written = 0;
            memory.stats.overlay_bytes_written = if changed { 4096 } else { 0 };
            memory.stats.identity_bytes_hashed = if changed { 4096 } else { 0 };
            memory.changes = vm_spec::capture::CaptureRamChanges {
                byte_len: changes.len() as u64,
                sha256: Sha256Digest::of_bytes(&changes),
                record_count: u64::from(changed),
                coverage: vm_spec::capture::CaptureRamCoverage::Incremental,
                baseline_stream: memory.baseline,
            };
            for entry in &mut evidence.inventory {
                if entry.role == CaptureRole::Ram {
                    entry.identity = Some(ram_update.map.root().id());
                } else if entry.role == disk_role {
                    entry.identity = Some(disk_update.map.root().id());
                } else {
                    let bytes = match entry.role {
                        CaptureRole::RamMap => Some(ram_root.as_slice()),
                        CaptureRole::DiskMap(_) => Some(disk_root.as_slice()),
                        CaptureRole::RamChanges => Some(changes.as_slice()),
                        _ => None,
                    };
                    if let Some(bytes) = bytes {
                        entry.length = bytes.len() as u64;
                        entry.sha256 = Some(Sha256Digest::of_bytes(bytes));
                    }
                }
            }
            directory
                .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
                .unwrap();
            let published = fixture
                .snapshots
                .publish_capture(
                    request.capture_id,
                    directory.path(),
                    None,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .unwrap();
            let accepted = fixture
                .snapshots
                .capture_reservation(request.capture_id)
                .await
                .unwrap()
                .unwrap();
            fixture
                .snapshots
                .accept_live_disk_baselines(&accepted)
                .await
                .unwrap();
            let retained: String = sqlx::query_scalar(
                "SELECT root_digest FROM storage_operation_memory_baseline WHERE operation_id=?1",
            )
            .bind(accepted.launch_operation_id.to_string())
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
            assert_eq!(
                retained,
                ObjectDigest::from_sha256(*ram_update.map.id().as_bytes()).to_string()
            );
            let consumer = fixture
                .snapshots
                .consume(&SnapshotRef::Id(published.id))
                .await
                .unwrap();
            let SnapshotCaptureKind::LiveExecution { execution } = &consumer.record.capture else {
                panic!("live execution checkpoint required");
            };
            assert_eq!(execution.memory.chunk_size, ChunkSize::RAM.bytes());
            assert_eq!(
                consumer.record.root.stream.chunk_size,
                ChunkSize::DISK.bytes()
            );
            assert_eq!(execution.memory.stream, ram_update.map.id());
            assert_eq!(consumer.record.root.stream.stream, disk_update.map.id());
            let after: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM stream_map_object WHERE height IS NOT NULL",
            )
            .fetch_one(&fixture.snapshots.store.pool)
            .await
            .unwrap();
            if !changed {
                assert_eq!(after, before);
            }
            assert_eq!(std::fs::read_dir(nodes.path()).unwrap().count(), new_nodes);
            let authority = pool
                .map_authority(Arc::new(
                    pool.existing_lease(consumer.operation_id).unwrap(),
                ))
                .unwrap();
            ram = pool
                .load_map(execution.memory.map, StreamRole::Ram, authority.clone())
                .unwrap();
            disk = pool
                .load_map(consumer.record.root.stream.map, StreamRole::Disk, authority)
                .unwrap();
            fixture
                .snapshots
                .finish_capture_release(request.capture_id, true)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn capture_recovers_process_loss_after_node_publication_before_admission() {
        const HOME: &str = "SILO_MAP_ADMISSION_CRASH_HOME";
        const CAPTURE: &str = "SILO_MAP_ADMISSION_CRASH_CAPTURE";
        if let Ok(home) = std::env::var(HOME) {
            let snapshots = SnapshotStore::open(Path::new(&home)).await.unwrap();
            let capture = Uuid::parse_str(&std::env::var(CAPTURE).unwrap()).unwrap();
            let record = snapshots
                .capture_reservation(capture)
                .await
                .unwrap()
                .unwrap();
            let directory = capture_directory(&snapshots.store, &record)
                .unwrap()
                .unwrap();
            let error = snapshots
                .publish_capture(
                    capture,
                    directory.path(),
                    record.alias,
                    crate::storage::pool::PublicationLockPolicy::Wait,
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("interrupted map admission"));
            std::process::exit(77);
        }
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        sqlx::raw_sql("CREATE TRIGGER interrupt_map_admission BEFORE INSERT ON stream_map_root BEGIN SELECT RAISE(ABORT,'interrupted map admission'); END")
            .execute(&fixture.snapshots.store.pool).await.unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "store::capture::tests::capture_recovers_process_loss_after_node_publication_before_admission", "--nocapture"])
            .env(HOME, fixture.snapshots.store.home_path()).env(CAPTURE, capture.to_string())
            .status().unwrap();
        assert_eq!(status.code(), Some(77));
        let record = fixture
            .snapshots
            .capture_reservation(capture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, CaptureState::Sealed);
        assert!(directory.path().join("map-nodes").is_dir());
        sqlx::raw_sql("DROP TRIGGER interrupt_map_admission")
            .execute(&fixture.snapshots.store.pool)
            .await
            .unwrap();
        let reopened = SnapshotStore::open(fixture.snapshots.store.home_path())
            .await
            .unwrap();
        let published = reopened
            .publish_capture(
                capture,
                directory.path(),
                record.alias,
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        reopened
            .finish_capture_release(capture, false)
            .await
            .unwrap();
        drop(fixture.reservation);
        drop(fixture.launch);
        reopened.store.recover_image_cache().await.unwrap();
        assert!(!directory.path().exists());
        let consumer = reopened
            .consume(&SnapshotRef::Id(published.id))
            .await
            .unwrap();
        let SnapshotCaptureKind::LiveExecution { execution } = &consumer.record.capture else {
            panic!("live execution checkpoint required");
        };
        let pool = StoragePool::open(&reopened.store.images_dir).unwrap();
        assert_eq!(
            std::fs::read(pool.stream_path(&execution.memory.stream)).unwrap(),
            [0x32; 4096]
        );
        assert_eq!(
            std::fs::read(pool.stream_path(&consumer.record.root.stream.stream)).unwrap(),
            [0x51; 512]
        );
    }

    #[tokio::test]
    async fn full_capture_changes_cannot_omit_a_nonzero_root_entry() {
        let fixture = fixture().await;
        let (directory, mut evidence) = seal(&fixture);
        let changes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0";
        directory
            .write_file(&CaptureRole::RamChanges.relative_path(), changes)
            .unwrap();
        let memory = evidence.memory.as_mut().unwrap();
        memory.changes.byte_len = changes.len() as u64;
        memory.changes.record_count = 0;
        memory.changes.sha256 = Sha256Digest::of_bytes(changes);
        memory.stats.identity_bytes_hashed = 0;
        let entry = evidence
            .inventory
            .iter_mut()
            .find(|entry| entry.role == CaptureRole::RamChanges)
            .unwrap();
        entry.length = changes.len() as u64;
        entry.sha256 = Some(Sha256Digest::of_bytes(changes));
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        let error = verify_capture(
            &directory,
            &fixture.reservation.record,
            CaptureAuthentication::Receipt,
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("full RAM changes omit nonzero root entries"));
    }
}

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
use crate::storage::pool::StoragePool;
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
            self.store.reserve_capture_inventory(&record).await?;
            check_lease(&self.store, &pool, record.capture_id, &lease).await?;
            return Ok(CaptureReservation {
                record,
                _lease: lease,
            });
        }
        crate::storage::limits::preflight_fd_budget(
            request.configuration.attachments.len() as u64 * 3 + 12,
        )
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
        if storage != launch.storage || storage.operation.is_some() || !storage.ownership.is_owned()
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
        let map_bytes = std::iter::once(request.configuration.ram_bytes())
            .chain(
                request
                    .configuration
                    .attachments
                    .iter()
                    .map(|attachment| attachment.geometry.length),
            )
            .try_fold(0u64, |total, length| {
                let chunks = length.div_ceil(crate::storage::limits::CHUNK_SIZE as u64);
                let pages = chunks.div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
                total
                    .checked_add(
                        chunks
                            .checked_mul(74)
                            .ok_or_else(|| invalid("capture map budget overflow"))?,
                    )
                    .and_then(|total| total.checked_add(pages * 330 + 256))
                    .ok_or_else(|| invalid("capture map budget overflow"))
            })?;
        // Retain staged state, pool state, bounded map pages and their inputs
        // simultaneously. Neither metadata nor publication is charged as a clone.
        let mut publication = request
            .configuration
            .ram_bytes()
            .checked_add(2 * vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
            .and_then(|bytes| bytes.checked_add(2 * map_bytes))
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
                let source = if attachment.role == vm_spec::DiskRole::Data
                    && !storage
                        .disks
                        .iter()
                        .any(|disk| disk.order as usize == index)
                {
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
                // Pool publication sparsely copies the sealed staging allocation.
                // Guest growth before sealing can underestimate this peak: ENOSPC
                // fails the whole capture under ADR 0021's failure table, via
                // LiveCoordinator::stage_disks/unwind and libvm's abandon_failed;
                // operation_store's CaptureCleanup removes staging after release.
                publication = publication
                    .checked_add(allocated)
                    .ok_or_else(|| invalid("capture publication overflow"))?;
                let name = match attachment.role {
                    vm_spec::DiskRole::Root => "silo-root".into(),
                    vm_spec::DiskRole::RootUpper => "silo-root-upper".into(),
                    vm_spec::DiskRole::Data => format!("silo-data-{index}"),
                    vm_spec::DiskRole::RootLower => {
                        return Err(invalid("overlay lower must be immutable and read-only"))
                    }
                };
                disks.push(CaptureDiskPlan {
                    name: CaptureDiskName::new(name).map_err(invalid)?,
                    attachment_index: index as u32,
                    block_id: attachment.block_id.clone(),
                    length: metadata.len(),
                    copy: CaptureDiskCopy::Copy,
                });
            }
        }
        let fork_operation_id = self.store.fork_for_capture(request.capture_id).await?;
        let local_fork = fork_operation_id.is_some();
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
            version: 1,
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
            disk_allocations,
            reservation_bytes,
            reservation_memory_bytes: if local_fork {
                ram.checked_mul(if machine_stat.st_dev != images_stat.st_dev {
                    2
                } else {
                    1
                })
                .and_then(|bytes| bytes.checked_add(CAPTURE_SCRATCH_BYTES))
                .ok_or_else(|| invalid("capture memory budget overflow"))?
            } else {
                CAPTURE_SCRATCH_BYTES
            },
            candidate: None,
            captured_boot: None,
            source_inodes,
            evidence: None,
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
        let (lease_device, lease_inode) = lease.file_identity()?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Replays racing this producer join the original immutable reservation.
        if let Some(json) = sqlx::query_scalar::<_, String>("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(record.capture_id.to_string()).fetch_optional(&mut *tx).await? {
            let existing = decode_record(&json)?;
            if existing.request != record.request { return Err(invalid("capture reservation replay conflict")); }
            tx.commit().await?;
            drop(_roots);
            self.store.reserve_capture_inventory(&existing).await?;
            return Ok(CaptureReservation { record: existing, _lease: lease });
        }
        if let Some(alias) = &record.alias {
            crate::store::managed_image_store::check_alias_available(&mut tx, alias, None).await?;
        }
        let current: Option<String> =
            sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
                .bind(record.machine_id.to_string())
                .fetch_optional(&mut *tx)
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
        let launch_present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='launch' AND machine_id=?2 AND run_id=?3 AND state='prepared')").bind(launch.operation_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_one(&mut *tx).await?;
        if !launch_present {
            return Err(invalid(
                "capture launch owner retired before reservation commit",
            ));
        }
        let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND machine_id=?1 AND run_id=?2 AND state='staging')")
            .bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_one(&mut *tx).await?;
        if busy {
            return Err(invalid("the source run already has an unresolved capture"));
        }
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,record_json) VALUES(?1,1,'capture','staging',?2,?3,?4,?5,?6,jsonb(?7))")
            .bind(record.capture_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).bind(i64::try_from(record.storage.storage_generation).map_err(invalid)?).bind(lease_device.to_string()).bind(lease_inode.to_string()).bind(encode_record(&record)?).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        drop(_roots);
        self.store.reserve_capture_inventory(&record).await?;
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
            let rows = sqlx::query("SELECT operation_id,json(record_json) AS record_json FROM storage_operation WHERE kind='capture' AND state='staging' AND operation_id>?1 AND (?2 IS NULL OR machine_id=?2) ORDER BY operation_id LIMIT 256").bind(&cursor).bind(machine.map(|id| id.to_string())).fetch_all(&self.store.pool).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.try_get("operation_id")?;
                let record = decode_record(&row.try_get::<String, _>("record_json")?)?;
                if record.capture_id.to_string() != cursor {
                    return Err(invalid("capture operation index contradiction"));
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
        let no_submission = intent.as_ref().is_none_or(|intent| {
            matches!(
                intent.result,
                Some(vm_spec::lifecycle::LiveCommandResult::Capture(
                    vm_spec::lifecycle::CaptureOutcome::Rejected { .. }
                ))
            )
        });
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
    ) -> Result<SnapshotInfo, LibVmError> {
        let this = self.clone();
        let staging = staging_dir.to_path_buf();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(this.publish_capture_owned(capture, &staging, name))
        })
        .await?
    }

    async fn publish_capture_owned(
        &self,
        capture: Uuid,
        staging_dir: &Path,
        name: Option<String>,
    ) -> Result<SnapshotInfo, LibVmError> {
        let pool = StoragePool::open(&self.store.images_dir)?;
        let mut key = Sha256::new();
        key.update(b"silo:capture-publication:v1\0");
        key.update(capture.as_bytes());
        let _publisher =
            pool.lock_publication(&ObjectDigest::from_sha256(key.finalize().into()))?;
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
        ) {
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
        let verified = verify_capture_bytes(&directory, &record)?;
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
        let mut streams = BTreeMap::new();
        let mut objects = BTreeMap::new();
        for payload in &verified.files {
            payload.recheck()?;
            match payload.role {
                CaptureRole::Ram => {
                    let (id, roots) =
                        pool.publish_sealed_ram_for_catalog(payload.file(), &verified.ram_map)?;
                    self.store
                        .pin_published_storage_dependencies(capture, &[id], &[])
                        .await?;
                    drop(roots);
                    let content = crate::store::snapshot_store::publish_map(
                        &pool,
                        &self.store,
                        capture,
                        &verified.ram_map,
                    )
                    .await?;
                    streams.insert(payload.role.relative_path(), content);
                }
                CaptureRole::Disk(_) => {
                    let (published, roots) = pool.publish_stream_file_for_catalog(
                        payload.file().try_clone()?,
                        payload.length,
                    )?;
                    self.store
                        .pin_published_storage_dependencies(capture, &[published.id], &[])
                        .await?;
                    drop(roots);
                    let content = crate::store::snapshot_store::publish_map(
                        &pool,
                        &self.store,
                        capture,
                        &published.map,
                    )
                    .await?;
                    streams.insert(payload.role.relative_path(), content);
                }
                CaptureRole::Execution | CaptureRole::Devices | CaptureRole::Layout => {
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
            let stream = input.identity.parse().map_err(invalid)?;
            let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)")
                .bind(capture.to_string()).bind(input.identity.clone()).fetch_one(&self.store.pool).await?;
            if !pinned {
                return Err(invalid(
                    "read-only capture input was not pinned before access",
                ));
            }
            let map = pool.verify_stream(&stream)?;
            if map.length() != attachment.geometry.length {
                return Err(invalid("read-only input geometry changed"));
            }
            immutable.insert(
                input.attachment_index,
                crate::store::snapshot_store::publish_map(&pool, &self.store, capture, &map)
                    .await?,
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
            schema: 1,
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
        let result = self
            .publish_authenticated(&snapshot, capture, name.as_deref(), Some(&verified))
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
            objects.extend(layer.pack.map_pages.iter().copied());
        }
        self.store
            .pin_published_storage_dependencies(capture, &streams, &objects)
            .await?;
        Ok(graph)
    }
}

pub(crate) fn decode_record(json: &str) -> Result<CaptureRecord, LibVmError> {
    Resource::MetadataPageBytes
        .check(json.len() as u64)
        .map_err(StorageError::from)?;
    let record: CaptureRecord = serde_json::from_str(json).map_err(invalid)?;
    record.plan.validate().map_err(invalid)?;
    record
        .storage
        .validate_for_machine(record.machine_id.into())?;
    let expected_staging = record.disk_allocations.values().try_fold(
        record
            .plan
            .ram_bytes
            .checked_add(vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
            .ok_or_else(|| invalid("capture staging overflow"))?,
        |bytes, allocated| {
            bytes
                .checked_add(*allocated)
                .ok_or_else(|| invalid("capture staging overflow"))
        },
    )?;
    let expected_memory = if let Some(operation) = record.fork_operation_id {
        if operation.is_nil() || operation == record.capture_id {
            return Err(invalid("capture fork operation identity is invalid"));
        }
        record
            .plan
            .ram_bytes
            .checked_mul(if record.disk_charges.len() == 2 { 2 } else { 1 })
            .and_then(|bytes| bytes.checked_add(CAPTURE_SCRATCH_BYTES))
            .ok_or_else(|| invalid("capture memory budget overflow"))?
    } else {
        CAPTURE_SCRATCH_BYTES
    };
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
        || record.reservation_memory_bytes != expected_memory
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

pub(crate) fn encode_record(record: &CaptureRecord) -> Result<String, LibVmError> {
    let json = serde_json::to_string(record).map_err(invalid)?;
    decode_record(&json)?;
    Ok(json)
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

fn writable_path(
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

pub(crate) fn available_memory() -> Result<u64, LibVmError> {
    #[cfg(target_os = "linux")]
    {
        let mut text = String::new();
        File::open("/proc/meminfo")?
            .take(64 << 10)
            .read_to_string(&mut text)?;
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))
            .ok_or_else(|| invalid("kernel omitted MemAvailable"))?;
        let mut fields = value.split_whitespace();
        let bytes = fields
            .next()
            .ok_or_else(|| invalid("empty MemAvailable"))?
            .parse::<u64>()
            .map_err(invalid)?
            .checked_mul(1024)
            .ok_or_else(|| invalid("MemAvailable overflow"))?;
        if fields.next() != Some("kB") || fields.next().is_some() {
            return Err(invalid("malformed MemAvailable"));
        }
        Ok(bytes)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/bin/vm_stat").output()?;
        if !output.status.success() {
            return Err(invalid("host memory accounting query failed"));
        }
        let text = std::str::from_utf8(&output.stdout).map_err(invalid)?;
        let first = text
            .lines()
            .next()
            .ok_or_else(|| invalid("empty host memory accounting"))?;
        let granule = first
            .split("page size of ")
            .nth(1)
            .and_then(|part| part.split_whitespace().next())
            .ok_or_else(|| invalid("host memory page size missing"))?
            .parse::<u64>()
            .map_err(invalid)?;
        let mut pages = 0u64;
        for label in ["Pages free:", "Pages inactive:", "Pages speculative:"] {
            let count = text
                .lines()
                .find_map(|line| line.strip_prefix(label))
                .ok_or_else(|| invalid("host memory accounting field missing"))?
                .trim()
                .trim_end_matches('.')
                .parse::<u64>()
                .map_err(invalid)?;
            pages = pages
                .checked_add(count)
                .ok_or_else(|| invalid("host page accounting overflow"))?;
        }
        pages
            .checked_mul(granule)
            .ok_or_else(|| invalid("host memory accounting overflow"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(invalid(
            "capture memory accounting is unavailable on this host",
        ))
    }
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
/// The second verification lane's input-independent allocations: its read
/// buffer and full stack mapping (which on glibc also hosts the thread's TCB
/// and static TLS). Monitor staging verification adds the same two bounds.
/// The two stages never overlap: libvm verifies only the coherent seal the
/// monitor writes after joining its own lanes, so one delta covers either.
/// Remaining fixed-size thread bookkeeping (std `Thread`/packet `Arc`s, the
/// moved closure and a fixed-size result) is input-independent metadata of
/// the general capture scratch, not of this delta.
const CAPTURE_VERIFICATION_LANE_BYTES: u64 =
    (AUTHENTICATION_BUFFER_BYTES + AUTHENTICATION_LANE_STACK_BYTES) as u64;
/// At 1 TiB, five simultaneous decoded maps cost at most 20.625 MiB
/// (retained/candidate monitor maps and manager codec/adapter ownership), and
/// one bounded canonical encoding costs under 9.3 MiB. Reserve the rounded
/// bound separately from byte-copy buffers and verification lane scratch.
const CAPTURE_RAM_MAP_SCRATCH_BYTES: u64 = 32 << 20;
/// Charged before staging: byte-copy scratch, complete map ownership and the
/// explicit second verification lane. No full map enters a control record.
pub(crate) const CAPTURE_SCRATCH_BYTES: u64 =
    (16 << 20) + CAPTURE_RAM_MAP_SCRATCH_BYTES + CAPTURE_VERIFICATION_LANE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureAuthentication {
    Receipt,
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
    ram_map: crate::storage::stream::StreamMap,
    directory_identity: (u64, u64),
    control_fingerprints: Vec<(&'static str, SourceFingerprint)>,
}
impl VerifiedCapture {
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

/// Validate the coherent monitor receipt without reading stream payload bytes.
pub(crate) fn validate_receipt(
    directory: &OwnedDirectory,
    record: &CaptureRecord,
) -> Result<VerifiedCapture, LibVmError> {
    verify_capture(directory, record, CaptureAuthentication::Receipt)
}

/// Fully authenticate stream chunks at publication, export or handoff.
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
    check_entries(directory, &top)?;
    let disk_names = record
        .plan
        .disks
        .iter()
        .flat_map(|disk| {
            [
                disk.name.file_name(),
                format!("{}.map.json", disk.name.as_str()),
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
            CaptureRole::RamMap => {
                (vm_spec::capture::MAX_CAPTURE_RAM_BYTES
                    .div_ceil(crate::storage::limits::CHUNK_SIZE as u64)
                    * 74)
                    + 256
            }
            CaptureRole::DiskMap(_) => {
                (vm_spec::capture::MAX_STREAM_BYTES / vm_spec::capture::STREAM_CHUNK_BYTES) * 74
                    + 256
            }
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
        admitted
            .into_iter()
            .map(|payload| {
                verify_payload(payload, authentication, &mut buffer, &mut None, &stop)?
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
    let ram_map = crate::storage::stream::StreamMap::decode(&map_bytes)?;
    if ram_map.length() != memory.packed_length
        || ram_map.id().as_bytes() != memory.ram_stream.as_bytes()
        || ram_map.canonical_bytes()? != map_bytes
    {
        return Err(invalid(
            "complete RAM map differs from sealed memory identity",
        ));
    }
    if memory.chunk_digests.len() != ram_map.chunks().len() {
        return Err(invalid("RAM receipt chunk count differs from complete map"));
    }
    for (index, (digest, chunk)) in memory
        .chunk_digests
        .iter()
        .zip(ram_map.chunks())
        .enumerate()
    {
        let affected = memory
            .dirty_chunks
            .get(index / 8)
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0);
        let expected = match chunk {
            crate::storage::stream::Chunk::Zero => None,
            crate::storage::stream::Chunk::Data(digest) => {
                Some(Sha256Digest::from_bytes(*digest.as_bytes()))
            }
        };
        if (affected && *digest != expected) || (!affected && digest.is_some()) {
            return Err(invalid("RAM receipt chunks differ from complete map"));
        }
    }
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
                    return Err(invalid(
                        "RAM receipt identity differs from recorded chunk list",
                    ));
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
        let map = crate::storage::stream::StreamMap::decode(&bytes)?;
        if map.length() != payload.length
            || Some(Sha256Digest::from_bytes(*map.id().as_bytes())) != entry.identity
            || map.canonical_bytes()? != bytes
        {
            return Err(invalid(
                "stream receipt identity differs from recorded chunk list",
            ));
        }
        if !matches!(payload.bytes, VerifiedBytes::Stream(_)) {
            let stream = crate::storage::stream::AuthenticatedStream::from_receipt(
                payload.file().try_clone()?,
                map,
            )?;
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
    hasher: &mut Option<crate::storage::stream::StreamHasher>,
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
            let stream = hasher
                .get_or_insert_with(crate::storage::stream::StreamHasher::new)
                .authenticate(file, entry.length)?;
            if Some(Sha256Digest::from_bytes(*stream.map().id().as_bytes())) != entry.identity {
                return Err(invalid("capture staged stream identity mismatch"));
            }
            if stream.fingerprint() != fingerprint {
                return Err(invalid("authenticated staged capture bytes changed"));
            }
            VerifiedBytes::Stream(stream)
        }
        (CaptureRole::Disk(_) | CaptureRole::Ram, CaptureAuthentication::Receipt) => {
            VerifiedBytes::Digest { file, fingerprint }
        }
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
            let pool = StoragePool::open(&this.store.images_dir)?;
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
                    let verified = validate_receipt(&source, &record)?;
                    verified.recheck_registered(&this.store, capture)?;
                    let mut storage = record.storage.clone();
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
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(operation.to_string()).bind(capture.to_string()).execute(&mut *tx).await?;
                    tx.commit().await?;
                    // Only the disks' held inodes and maps outlive verification;
                    // state-role descriptors close here exactly as before.
                    for payload in verified.files {
                        if matches!(payload.role, CaptureRole::Disk(_)) {
                            if let VerifiedBytes::Stream(stream) = payload.bytes {
                                verified_disks.push((payload.role, stream));
                            }
                        }
                    }
                    cut
                }
            };
            let mut relocated_disks = Vec::new();
            if !cut.relocated {
                let images = OwnedDirectory::open_existing_root(&this.store.images_dir)?.ok_or_else(|| invalid("pool disappeared"))?;
                let tmp = images.open_dir("tmp")?.ok_or_else(|| invalid("pool tmp disappeared"))?;
                let owner = tmp.ensure_dir_deferred(&operation.to_string())?;
                let destination = owner.ensure_dir_deferred("cut")?;
                destination.ensure_dir_deferred("disks")?;
                let mut qualification = crate::machine::root_disk::CopyQualification::new(1);
                for index in 0..cut.files.len() {
                    let payload=&mut cut.files[index];
                    let mut carrier = verified_disks.iter().position(|(role,_)| role==&payload.role).map(|position| verified_disks.swap_remove(position).1);
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
                    if let Some(held) = carrier {
                        relocated_disks.push((cut.files[index].role.clone(), held));
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
        if record.plan != command.plan || record.state != CaptureState::Reserved {
            return Err(invalid(
                "a sealed or retired capture can never be recaptured",
            ));
        }
        self.reserve_capture_inventory(&record).await
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
    use std::sync::Arc;

    use uuid::Uuid;
    use vm_spec::capture::{
        CaptureConfiguration, CaptureEvidence, CaptureInventoryEntry, CaptureMemoryEvidence,
        CapturePauseAuthority, CapturePauseDisposition, CaptureRecordOutcome, CaptureRole,
        CaptureStateBinding, Sha256Digest,
    };
    use vm_spec::lifecycle::{CapturePolicy, CaptureResumePolicy, PauseOwner, PauseToken};

    use crate::lock_manager::LockId;
    use crate::paths::{LocalPaths, OwnedDirectory};
    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::StoragePool;
    use crate::storage::stream::StreamHasher;
    use crate::store::capture::{
        authenticate_lanes, capture_directory, validate_layout, verify_capture, verify_payload,
        AdmittedPayload, CaptureAuthentication, VerifiedBytes, VerifiedPayload,
        AUTHENTICATION_BUFFER_BYTES, CAPTURE_SCRATCH_BYTES,
    };

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
        launch: LaunchStorageLease,
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
            .retain_local_capture(capture)
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
        let storage = store.machine_storage(id).await.unwrap().unwrap();
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
        let ram_map = StreamHasher::new().hash_reader(Cursor::new(&ram)).unwrap();
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
        let disk_map = StreamHasher::new()
            .hash_reader(Cursor::new([0x51; 512]))
            .unwrap();
        let disk_map_bytes = disk_map.canonical_bytes().unwrap();
        for role in record.plan.roles() {
            let bytes: &[u8] = match &role {
                CaptureRole::Execution => &native_execution,
                CaptureRole::Devices => &native_devices,
                CaptureRole::Ram => &ram,
                CaptureRole::Layout => &layout,
                CaptureRole::RamMap => &ram_map_bytes,
                CaptureRole::Disk(_) => &[0x51; 512],
                CaptureRole::DiskMap(_) => &disk_map_bytes,
            };
            match &role {
                CaptureRole::Disk(name) => disks.write_file(&name.file_name(), bytes).unwrap(),
                CaptureRole::DiskMap(name) => disks
                    .write_file(&format!("{}.map.json", name.as_str()), bytes)
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
            version: 1,
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
                dirty_chunks: vec![1],
                chunk_digests: vec![Some(Sha256Digest::of_bytes(&ram))],
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
        let maps = [record.plan.ram_bytes, length]
            .into_iter()
            .map(|bytes| {
                let chunks = bytes.div_ceil(crate::storage::limits::CHUNK_SIZE as u64);
                let pages = chunks.div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
                chunks * 74 + pages * 330 + 256
            })
            .sum::<u64>();
        let state = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        assert_eq!(
            record.plan.reservation.staging_bytes,
            record.plan.ram_bytes + allocated + state
        );
        assert_eq!(
            record.reservation_bytes,
            2 * (record.plan.ram_bytes + allocated) + 3 * state + 2 * maps
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
    async fn capture_memory_validation_matches_plain_and_fork_ownership() {
        use crate::store::capture::{decode_record, encode_record};

        for fork in [false, true] {
            let fixture = if fork {
                fork_fixture().await
            } else {
                fixture().await
            };
            let mut record = fixture.reservation.record.clone();
            assert!(decode_record(&encode_record(&record).unwrap()).is_ok());
            record.reservation_memory_bytes = if fork {
                CAPTURE_SCRATCH_BYTES
            } else {
                record.plan.ram_bytes + CAPTURE_SCRATCH_BYTES
            };
            assert!(encode_record(&record).is_err());
            record = fixture.reservation.record.clone();
            record.fork_operation_id = if fork { None } else { Some(Uuid::new_v4()) };
            let error = fixture
                .snapshots
                .store
                .reserve_capture_inventory(&record)
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
            sqlx::query_scalar("SELECT count(*) FROM restore_memory_reservation")
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
            .publish_capture(capture, directory.path(), alias)
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
            .publish_capture(capture, directory.path(), alias.clone())
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
                .publish_capture(capture, directory.path(), alias)
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
            .retain_local_capture(fixture.reservation.record.capture_id)
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
                    .publish_capture(capture, directory.path(), alias)
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
            )
            .await
            .unwrap();
        let source = vm_spec::capture::CaptureSourceRecord {
            version: 1,
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

    #[test]
    fn complete_ram_map_peak_is_charged_at_the_one_tib_boundary() {
        let chunks = vm_spec::capture::MAX_CAPTURE_RAM_BYTES
            .div_ceil(crate::storage::limits::CHUNK_SIZE as u64);
        let decoded = 5 * chunks * std::mem::size_of::<Option<Sha256Digest>>() as u64;
        let encoded = chunks * 74 + 256;
        assert!(decoded + encoded <= crate::store::capture::CAPTURE_RAM_MAP_SCRATCH_BYTES);
    }

    #[tokio::test]
    async fn checkpoint_lanes_keep_inventory_order_and_held_inodes_and_reject_either_lane() {
        let sealed = fixture().await;
        let record = &sealed.reservation.record;
        // Complete map ownership and the second lane are charged before effects.
        assert_eq!(CAPTURE_SCRATCH_BYTES, 50 << 20);
        assert_eq!(record.reservation_memory_bytes, CAPTURE_SCRATCH_BYTES);
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
                *StreamHasher::new()
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
                *StreamHasher::new()
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
        let waiter =
            tokio::spawn(async move { publisher.publish_capture(capture, &staging, alias).await });
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
            .publish_capture(capture, directory.path(), name)
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
    async fn checkpoint_concurrent_publication_joins_and_release_survives_staging_cleanup() {
        let fixture = fixture().await;
        let (directory, _) = seal(&fixture);
        let capture = fixture.reservation.record.capture_id;
        let name = fixture.reservation.record.alias.clone();
        let (first, second) = tokio::join!(
            fixture
                .snapshots
                .publish_capture(capture, directory.path(), name.clone()),
            fixture
                .snapshots
                .publish_capture(capture, directory.path(), name.clone())
        );
        let published = first.unwrap();
        assert_eq!(published, second.unwrap());
        fixture
            .snapshots
            .finish_capture_release(capture, true)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .snapshots
                .publish_capture(capture, directory.path(), name)
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
            .retain_local_capture(capture)
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
            .retain_local_capture(capture)
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
            .retain_local_capture(capture)
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
            .retain_local_capture(capture)
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
            before.baseline.is_none(),
            "retired source owns no remaining baseline charge"
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
            .retain_local_capture(capture)
            .await
            .unwrap();
        let retained = retained.expect("seal verification derived the writable disk maps");
        let expected = StreamHasher::new().hash_reader(&[0x51; 512][..]).unwrap();
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
            .retain_local_capture(capture)
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
            StreamHasher::new()
                .copy_authenticated(&disk, &private)
                .is_err(),
            "first byte use checks the receipt map, not the rewritten fingerprint"
        );
    }

    #[tokio::test]
    async fn incremental_complete_map_publishes_without_parent_retention() {
        let fixture = fixture_source(false, false, CapturePolicy::Incremental).await;
        assert_eq!(
            fixture.reservation.record.reservation_memory_bytes,
            CAPTURE_SCRATCH_BYTES
        );
        let inventory: crate::store::restore::CaptureBudgetInventory = serde_json::from_str(
            &fixture
                .snapshots
                .store
                .capture_budget_document(fixture.reservation.record.capture_id)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(inventory.capture_memory, CAPTURE_SCRATCH_BYTES);
        assert!(inventory.baseline.is_none());
        let (directory, mut evidence) = seal(&fixture);
        let memory = evidence.memory.as_mut().unwrap();
        memory.mode = CapturePolicy::Incremental;
        memory.baseline = Some(Sha256Digest::of_bytes(b"unretained predecessor stream"));
        memory.full_reason = None;
        memory.stats.full_bytes_written = 0;
        memory.stats.overlay_bytes_written = memory.packed_length;
        directory
            .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
            .unwrap();
        let published = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
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
                .chunks()
                .len(),
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
        let mut hasher = StreamHasher::new();
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
                .retain_local_capture(capture)
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
                .retain_local_capture(capture)
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
                        *StreamHasher::new()
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
                .retain_local_capture(fixture.reservation.record.capture_id)
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
                    *StreamHasher::new()
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
            .retain_local_capture(capture)
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
                .publish_capture(capture, &staging, record.alias.clone())
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
                .publish_capture(capture, &staging, record.alias.clone())
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
            .publish_capture(capture, &staging, record.alias)
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
            schema: 1,
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
}

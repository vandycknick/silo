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
use crate::{
    BootBinding, BootProfile, DiskStorage, LibVmError, MachineRoot, OverlayLower, RawLayout,
};

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
        if request.policy != vm_spec::lifecycle::CapturePolicy::Full {
            return Err(invalid("only full capture is delivered"));
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
        if storage != launch.storage
            || storage.operation.is_some()
            || storage.fence.is_some()
            || storage.relocation_operation.is_some()
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
        let mut read_only_inputs = Vec::new();
        let mut source_inodes = Vec::new();
        for (index, attachment) in request.configuration.attachments.iter().enumerate() {
            Resource::VirtualDiskBytes
                .check(attachment.geometry.length)
                .map_err(StorageError::from)?;
            if attachment.read_only {
                let stream = read_only_identity(&storage, index as u32, attachment.role)?;
                read_only_inputs.push(CaptureReadOnlyInput {
                    attachment_index: index as u32,
                    block_id: attachment.block_id.clone(),
                    identity: stream.to_string(),
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
                stage = stage
                    .checked_add(
                        metadata
                            .blocks()
                            .checked_mul(512)
                            .ok_or_else(|| invalid("capture allocation overflow"))?,
                    )
                    .ok_or_else(|| invalid("capture staging overflow"))?;
                // Pool publication uses an independently verified sparse copy.
                // Reserve its conservative logical bound, not clone metadata.
                publication = publication
                    .checked_add(metadata.len())
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
        let local_fork = self
            .store
            .fork_for_capture(request.capture_id)
            .await?
            .is_some();
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
            machine_id: request.machine_id,
            run_id: request.run_id,
            launch_operation_id: launch.operation_id,
            alias: request.alias.clone(),
            request,
            plan,
            state: CaptureState::Reserved,
            source_outcome: None,
            configuration,
            storage,
            disk_charges,
            reservation_bytes,
            reservation_memory_bytes: ram
                .checked_mul(if local_fork && machine_stat.st_dev != images_stat.st_dev {
                    2
                } else {
                    1
                })
                .and_then(|bytes| bytes.checked_add(CAPTURE_SCRATCH_BYTES))
                .ok_or_else(|| invalid("capture memory budget overflow"))?,
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
            let rows = sqlx::query("SELECT operation_id,json(record_json) AS record_json FROM storage_operation WHERE kind='capture' AND operation_id>?1 AND (?2 IS NULL OR machine_id=?2) ORDER BY operation_id LIMIT 256").bind(&cursor).bind(machine.map(|id| id.to_string())).fetch_all(&self.store.pool).await?;
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
        tokio::task::spawn_blocking(move || runtime.block_on(async {
            let pool = StoragePool::open(&this.store.images_dir)?;
            let _roots = pool.lock_roots()?;
            let mut tx = this.store.pool.begin_with("BEGIN IMMEDIATE").await?;
            let json: String = sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(capture.to_string()).fetch_one(&mut *tx).await?;
            let mut record = decode_record(&json)?;
            update(&mut record)?;
            write_record(&mut tx, &record).await?;
            if let Some(source)=&record.source_outcome {
                let parent:Option<(String,String)>=sqlx::query_as("SELECT operation_id,json(result_json) FROM live_fork WHERE capture_id=?1").bind(capture.to_string()).fetch_optional(&mut *tx).await?;
                if let Some((operation,json))=parent {
                    let mut result:crate::LiveForkResult=serde_json::from_str(&json).map_err(invalid)?;
                    let mut outcome=crate::machine::live_fork::source_outcome(source);
                    if record.evidence.is_none() && (matches!(outcome,crate::ForkSourceOutcome::Resumed) || (matches!(outcome,crate::ForkSourceOutcome::Preserved) && matches!(record.plan.pause,vm_spec::capture::CapturePauseAuthority::Borrow{..}))) {outcome=crate::ForkSourceOutcome::Unchanged;}
                    result.source=outcome;
                    sqlx::query("UPDATE live_fork SET result_json=jsonb(?2) WHERE operation_id=?1").bind(&operation).bind(serde_json::to_string(&result).map_err(invalid)?).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,phase,monotonic_ns) VALUES(?1,'source_settled',?2)").bind(operation).bind(crate::machine::live_fork::monotonic_ns()?).execute(&mut *tx).await?;
                }
            }
            tx.commit().await?;
            Ok(())
        })).await?
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
        let verified = verify_capture(&directory, &record, DiskAuthentication::WholeDigest)?;
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
                CaptureRole::Ram | CaptureRole::Disk(_) => {
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
        for input in &record.plan.read_only_inputs {
            let stream = input.identity.parse().map_err(invalid)?;
            let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)")
                .bind(capture.to_string()).bind(input.identity.clone()).fetch_one(&self.store.pool).await?;
            if !pinned {
                return Err(invalid(
                    "read-only capture input was not pinned before access",
                ));
            }
            let map = pool.verify_stream(&stream)?;
            let attachment = record
                .plan
                .configuration
                .attachments
                .get(input.attachment_index as usize)
                .ok_or_else(|| invalid("read-only input attachment is absent"))?;
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
                lower:
                    OverlayLower::FlatExt4 {
                        geometry,
                        filesystem_uuid,
                        ..
                    },
                upper_uuid,
                ext4_profile,
                overlay_profile,
                temporary_directory,
                capacity,
                ..
            } => {
                let lower = immutable
                    .remove(&0)
                    .ok_or_else(|| invalid("overlay lower input is missing"))?;
                (
                    SnapshotRootProfile::LinuxOverlay {
                        lower,
                        lower_geometry: *geometry,
                        lower_filesystem_uuid: *filesystem_uuid,
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
            _ => return Err(invalid("capture root lacks an admitted immutable closure")),
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
        if !streams.is_empty() || !immutable.is_empty() {
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
                        native_producer: memory_evidence.binding.native_producer.clone(),
                        silo_producer: ObjectDigest::from_sha256(
                            *memory_evidence.binding.silo_producer.as_bytes(),
                        ),
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
        self.store.complete_capture_peak(capture).await?;
        drop(lease);
        Ok(result)
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
    if record.request.configuration != record.plan.configuration
        || record.request.policy != record.plan.policy
        || record.request.resume_policy != record.plan.resume_policy
        || record.request.pause != record.plan.pause
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
        || record.reservation_memory_bytes < record.plan.ram_bytes
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

fn read_only_identity(
    storage: &crate::MachineStorageRecord,
    order: u32,
    role: vm_spec::DiskRole,
) -> Result<crate::storage::identity::StreamId, LibVmError> {
    match (&storage.root, role) {
        (
            MachineRoot::LinuxOverlay {
                lower: OverlayLower::FlatExt4 { stream, .. },
                ..
            },
            vm_spec::DiskRole::RootLower,
        ) if order == 0 => Ok(*stream),
        (_, vm_spec::DiskRole::Data) => storage
            .disks
            .iter()
            .find_map(|disk| {
                if disk.order == order {
                    match &disk.storage {
                        DiskStorage::ManagedReadOnly { stream, .. } => Some(*stream),
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
/// Capture-operation memory beyond RAM, charged at reservation before any
/// staging or verification effect: the general 16 MiB capture scratch plus
/// the explicit second-lane delta.
const CAPTURE_SCRATCH_BYTES: u64 = (16 << 20) + CAPTURE_VERIFICATION_LANE_BYTES;

/// Whether seal verification also derives canonical maps for writable disks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskAuthentication {
    /// Snapshot publication scans each disk again while copying it into the pool.
    WholeDigest,
    /// Local fork children copy the retained cut. Each disk map comes from the
    /// same traversal that measures its evidence-bound whole-byte digest.
    WithStreamMap,
}

/// Exact staged bytes whose whole-byte SHA-256 equals the evidence inventory.
enum VerifiedBytes {
    Digest {
        file: File,
        fingerprint: SourceFingerprint,
    },
    /// The same digest relation, plus the canonical map of those bytes.
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

fn verify_capture(
    directory: &OwnedDirectory,
    record: &CaptureRecord,
    disks: DiskAuthentication,
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
        .map(|disk| disk.name.file_name())
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
    let (ram, mut files) = authenticate_lanes(
        move |stop| {
            let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
            verify_payload(ram, disks, &mut buffer, &mut None, stop)
        },
        |stop| {
            let mut buffer = vec![0u8; AUTHENTICATION_BUFFER_BYTES];
            let mut hasher = None;
            let mut files = Vec::with_capacity(admitted.len() + 1);
            for payload in admitted {
                match verify_payload(payload, disks, &mut buffer, &mut hasher, stop)? {
                    Some(payload) => files.push(payload),
                    None => return Ok(None),
                }
            }
            Ok(Some(files))
        },
    )?;
    // Deterministic reduction: exactly the evidence inventory order.
    files.insert(ram_index, ram);
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
        &record.plan,
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
    disks: DiskAuthentication,
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
    let bytes = match (&entry.role, disks) {
        (CaptureRole::Disk(_), DiskAuthentication::WithStreamMap) => {
            // One traversal yields both the evidence digest and the map;
            // the map is admitted only after that digest matches.
            let (stream, digest) = hasher
                .get_or_insert_with(crate::storage::stream::StreamHasher::new)
                .authenticate_with_sha256(file, entry.length)?;
            if digest != entry.sha256 {
                return Err(invalid("capture staged payload digest mismatch"));
            }
            if stream.fingerprint() != fingerprint {
                return Err(invalid("authenticated staged capture bytes changed"));
            }
            VerifiedBytes::Stream(stream)
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
            if &digest != entry.sha256.as_bytes() {
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
///     │                              (polls stop per read) │
///     └─► other roles, in order ──► join ◄─────────────────┘
///                                    │
///                      both owners finished; only now return
/// ```
///
/// A lane that fails, or unwinds, sets `stop` through its guard; its sibling
/// returns `Ok(None)` at its next read or role boundary. A streamed disk map
/// pass has no stop hook and runs to its admitted length. The scoped thread
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
fn validate_layout(
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
    /// Authenticate once, then move immutable payloads without moving the
    /// monitor-owned control namespace. The journal precedes every relocation.
    ///
    /// Writable disks verified by this call keep their held inode and map
    /// through an owned same-filesystem rename. A cross-filesystem copy or a
    /// relocation this call did not observe is authenticated again, deriving
    /// the map in the same traversal as the evidence digest. The returned
    /// disks belong to the caller's fork operation, never to a shared cache.
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
                    let verified = verify_capture(&source, &record, DiskAuthentication::WithStreamMap)?;
                    verified.recheck_registered(&this.store, capture)?;
                    let mut storage = record.storage.clone();
                    storage.boot = record.captured_boot.clone().ok_or_else(|| invalid("local capture has no pinned boot closure"))?;
                    storage.snapshot = None;
                    storage.image = None;
                    storage.storage_generation = 0;
                    storage.ownership_epoch = 0;
                    storage.stop_outcome = crate::StorageStopOutcome::Unknown;
                    storage.operation = None;
                    storage.fence = None;
                    storage.relocation_operation = None;
                    if let MachineRoot::OpaqueRaw { initial_content, .. } = &mut storage.root { *initial_content = None; }
                    let files=verified.files.iter().map(|file| {
                        let metadata=file.file().metadata()?;
                        let entry=verified.evidence.inventory.iter().find(|entry| entry.role==file.role).ok_or_else(|| invalid("verified role missing from evidence"))?;
                        Ok(crate::store::fork::LocalCutFile {role:file.role.clone(),device:metadata.dev(),inode:metadata.ino(),length:file.length,sha256:entry.sha256,fingerprint:SourceFingerprint::new(&metadata)})
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
                    tx.commit().await?;
                    // Only the disks' held inodes and maps outlive verification;
                    // state-role descriptors close here exactly as before.
                    for payload in verified.files {
                        if let VerifiedBytes::Stream(stream) = payload.bytes {
                            verified_disks.push((payload.role, stream));
                        }
                    }
                    cut
                }
            };
            let mut relocated_disks = Vec::new();
            if !cut.relocated {
                let images = OwnedDirectory::open_existing_root(&this.store.images_dir)?.ok_or_else(|| invalid("pool disappeared"))?;
                let tmp = images.open_dir("tmp")?.ok_or_else(|| invalid("pool tmp disappeared"))?;
                let owner = tmp.ensure_dir(&operation.to_string())?;
                let destination = owner.ensure_dir("cut")?;
                destination.ensure_dir("disks")?;
                let mut qualification = crate::machine::root_disk::CopyQualification::new(1);
                let mut hasher = None;
                for index in 0..cut.files.len() {
                    let payload=&mut cut.files[index];
                    let mut carrier = verified_disks.iter().position(|(role,_)| role==&payload.role).map(|position| verified_disks.swap_remove(position).1);
                    let mut moved=false;
                    let relative = payload.role.relative_path();
                    let (source_parent,destination_parent,name) = match relative.split_once('/') {
                        Some((parent,name)) => (source.open_dir(parent)?.ok_or_else(|| invalid("capture role parent missing"))?, destination.ensure_dir(parent)?, name),
                        None => (source.try_clone()?, destination.try_clone()?, relative.as_str()),
                    };
                    if destination_parent.open_capture_payload(name)?.is_none() {
                        let file = source_parent.open_file(name)?.ok_or_else(|| invalid("both local cut role locations are missing"))?;
                        let metadata = file.metadata()?;
                        if SourceFingerprint::new(&metadata)!=payload.fingerprint || carrier.as_ref().is_some_and(|held| held.fingerprint()!=payload.fingerprint) { return Err(invalid("local cut source fingerprint changed")); }
                        if metadata.dev() == nix::sys::stat::fstat(destination_parent.fd()).map_err(std::io::Error::from)?.st_dev as u64 {
                            crate::storage::pool::rename_component_no_replace(&source_parent,name,&destination_parent,name)?;
                        } else {
                            let temporary=format!(".relocating-{}",Uuid::new_v4());
                            let copy_source = match &carrier {
                                Some(held) => crate::machine::root_disk::CopySource::Authenticated(held),
                                None => crate::machine::root_disk::CopySource::Unscanned { file: &file, length: payload.length },
                            };
                            let mut copied = crate::machine::root_disk::copy_private(copy_source,destination_parent.try_clone()?,&temporary,&mut qualification).map_err(|error| invalid(error.to_string()))?;
                            // A new inode: only full authentication below may vouch for it.
                            carrier = None;
                            copied.publish(destination_parent.try_clone()?,name).map_err(|error| invalid(error.to_string()))?;
                            copied.retain();
                            let final_file = destination_parent.open_file(name)?.ok_or_else(|| invalid("relocated local cut disappeared"))?;
                            nix::sys::stat::fchmod(&final_file,nix::sys::stat::Mode::S_IRUSR).map_err(std::io::Error::from)?;
                            final_file.sync_all()?;
                        }
                        destination_parent.sync()?;
                        source_parent.sync()?;
                        moved=true;
                    }
                    let final_file=destination_parent.open_capture_payload(name)?.ok_or_else(|| invalid("local cut role disappeared"))?;
                    let mut metadata=final_file.metadata()?;
                    if metadata.mode()&0o7777==0o600 {
                        nix::sys::stat::fchmod(&final_file,nix::sys::stat::Mode::S_IRUSR).map_err(std::io::Error::from)?;
                        final_file.sync_all()?;
                        metadata=final_file.metadata()?;
                    }
                    if metadata.len() != payload.length || metadata.nlink()!=1 || metadata.mode() & 0o7777 != 0o400 { return Err(invalid("relocated local cut role is not immutable")); }
                    // Recovery may see a copied destination before its identity
                    // commit, and a cross-filesystem copy is a new inode.
                    // Authenticate that one copy before accepting it.
                    let unchanged = if moved { payload.fingerprint.same_contents_after_metadata_change(&metadata) } else { SourceFingerprint::new(&metadata)==payload.fingerprint };
                    // The carrier held this exact inode since seal verification; the
                    // owned rename and 0600->0400 chmod changed only its ctime.
                    let held_inode = carrier.as_ref().map(|held| held.file().metadata()).transpose()?.map(|held| (held.dev(),held.ino()));
                    carrier = match carrier.take() {
                        Some(mut held) if unchanged && held_inode==Some((metadata.dev(),metadata.ino())) => { held.refresh_after_owned_metadata_change()?; Some(held) }
                        _ => None,
                    };
                    if !unchanged {
                        if matches!(payload.role, CaptureRole::Disk(_)) {
                            let (stream, digest) = hasher.get_or_insert_with(crate::storage::stream::StreamHasher::new).authenticate_with_sha256(final_file,payload.length)?;
                            if digest != payload.sha256 || stream.fingerprint()!=SourceFingerprint::new(&metadata) {
                                return Err(invalid("relocated local cut digest mismatch"));
                            }
                            carrier = Some(stream);
                        } else if crate::machine::restore::hash_file(&final_file)? != payload.sha256 {
                            return Err(invalid("relocated local cut digest mismatch"));
                        }
                    }
                    if carrier.as_ref().is_some_and(|held| held.fingerprint()!=SourceFingerprint::new(&metadata)) {
                        return Err(invalid("relocated local cut disk changed during relocation"));
                    }
                    payload.device=metadata.dev(); payload.inode=metadata.ino();
                    payload.fingerprint=SourceFingerprint::new(&metadata);
                    sqlx::query("UPDATE local_cut SET record_json=jsonb(?2) WHERE operation_id=?1").bind(operation.to_string()).bind(serde_json::to_string(&cut).map_err(invalid)?).execute(&this.store.pool).await?;
                    if let Some(held) = carrier {
                        relocated_disks.push((cut.files[index].role.clone(), held));
                    }
                }
                destination.write_file_atomic(vm_spec::capture::CAPTURE_REQUEST_FILE,&record.plan.canonical_bytes().map_err(invalid)?)?;
                destination.write_file_atomic(vm_spec::capture::CAPTURE_EVIDENCE_FILE,&cut.evidence.canonical_bytes().map_err(invalid)?)?;
                destination.sync()?;
                cut.relocated=true;
                sqlx::query("UPDATE local_cut SET record_json=jsonb(?2) WHERE operation_id=?1").bind(operation.to_string()).bind(serde_json::to_string(&cut).map_err(invalid)?).execute(&this.store.pool).await?;
            }
                let evidence = String::from_utf8(cut.evidence.canonical_bytes().map_err(invalid)?).map_err(invalid)?;
                let cut_id=cut.cut_id;
            this.update_capture(capture,move |record| {
                record.evidence=Some(evidence);
                record.state=match record.state {
                    CaptureState::ReleasedLocal { cut } if cut==cut_id=>CaptureState::ReleasedLocal {cut},
                    CaptureState::Local {cut} if cut==cut_id=>CaptureState::Local {cut},
                    CaptureState::Reserved|CaptureState::Sealed=>CaptureState::Local {cut:cut_id},
                    _=>return Err(invalid("local cut cannot replace another capture disposition")),
                };
                Ok(())
            }).await?;
            this.store.update_fork(operation,move |result| { result.capture=crate::ForkCaptureOutcome::Sealed { cut_id }; if result.stage!=crate::ForkStage::Finished {result.stage=crate::ForkStage::Restoring;} Ok(()) }).await?;
                this.store.fork_event(operation,None,"seal_authenticated").await?;
                this.store.complete_capture_peak(capture).await?;
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
mod tests {
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
        AdmittedPayload, DiskAuthentication, VerifiedBytes, VerifiedPayload,
        AUTHENTICATION_BUFFER_BYTES, CAPTURE_SCRATCH_BYTES,
    };

    const DISK_MODES: [DiskAuthentication; 2] = [
        DiskAuthentication::WholeDigest,
        DiskAuthentication::WithStreamMap,
    ];
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::operation_store::LaunchStorageLease;
    use crate::store::snapshot_store::{
        CaptureReservation, CaptureReservationRequest, CaptureSourceOutcome, CaptureState,
        SnapshotCaptureKindName, SnapshotRef, SnapshotStore,
    };
    use crate::store::{MachineStore, Store};

    struct Fixture {
        _temporary: tempfile::TempDir,
        snapshots: SnapshotStore,
        config: MachineConfig,
        reservation: CaptureReservation,
        launch: LaunchStorageLease,
    }

    async fn fixture() -> Fixture {
        fixture_with_external_data(false).await
    }

    async fn fixture_with_external_data(include_data: bool) -> Fixture {
        fixture_source(include_data, false).await
    }

    async fn fork_fixture() -> Fixture {
        fixture_source(false, true).await
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

    async fn fixture_source(include_data: bool, fork: bool) -> Fixture {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let id = MachineId::new();
        let parent = paths.create_machine_data_dir(id).unwrap();
        let directory = parent.open_dir(&id.to_string()).unwrap().unwrap();
        directory.write_file("root.raw", &[0x51; 512]).unwrap();
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
                    length: 512,
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
            policy: CapturePolicy::Full,
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
        bytes.extend_from_slice(&(binding.native_producer.len() as u32).to_le_bytes());
        bytes.extend_from_slice(binding.native_producer.as_bytes());
        for digest in [
            binding.silo_producer,
            binding.profile,
            binding.topology,
            binding.ram_layout,
        ] {
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

    fn seal(fixture: &Fixture) -> (OwnedDirectory, CaptureEvidence) {
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
            "architecture": "x86_64", "kind": "ram-layout", "packedLength": 4096, "pageGranule": 4096,
            "regions": [{"guestPhysicalAddress": 0, "length": 4096, "streamOffset": 0}],
            "schema": 1, "topology": {"firmwareAddress": 0, "initrdAddress": 0, "ramAboveGap": 0, "ramBelowGap": 4096, "ramLastAddress": 4095, "shmStartAddress": 0}
        })).unwrap();
        let ram = vec![0x32; 4096];
        let ram_map = StreamHasher::new().hash_reader(Cursor::new(&ram)).unwrap();
        let binding = CaptureStateBinding {
            native_producer: "unit-file-format".into(),
            silo_producer: Sha256Digest::of_bytes(b"silo"),
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
        for role in record.plan.roles() {
            let bytes: &[u8] = match &role {
                CaptureRole::Execution => &native_execution,
                CaptureRole::Devices => &native_devices,
                CaptureRole::Ram => &ram,
                CaptureRole::Layout => &layout,
                CaptureRole::Disk(_) => &[0x51; 512],
            };
            match &role {
                CaptureRole::Disk(name) => disks.write_file(&name.file_name(), bytes).unwrap(),
                _ => directory.write_file(&role.relative_path(), bytes).unwrap(),
            }
            inventory.push(CaptureInventoryEntry {
                role,
                length: bytes.len() as u64,
                sha256: Sha256Digest::of_bytes(bytes),
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
            evidence.freeze_operation_id.as_ref(),
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
            .unwrap_err()
            .to_string()
            .contains("captured configuration"));
        consumer.record.configuration.spec = saved;
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &mut consumer.record.capture
        else {
            panic!("execution checkpoint");
        };
        execution
            .compatibility_profile
            .native_producer
            .push_str("-different");
        assert!(fixture
            .snapshots
            .restore_evidence(&consumer, &pool)
            .unwrap_err()
            .to_string()
            .contains("native producer"));
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
        let (_, boot_objects) = crate::store::cache_paths::storage_pool_dependencies(
            &fixture.reservation.record.storage,
        )
        .unwrap();
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
            for disks in DISK_MODES {
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
        let producer_len = "unit-file-format".len();
        for (fault, role, offset) in [
            ("execution-version", CaptureRole::Execution, 8),
            ("execution-abi", CaptureRole::Execution, 10),
            ("execution-lane", CaptureRole::Execution, 14),
            ("producer", CaptureRole::Execution, 19),
            ("silo-producer", CaptureRole::Execution, 19 + producer_len),
            ("profile", CaptureRole::Execution, 51 + producer_len),
            ("topology", CaptureRole::Execution, 83 + producer_len),
            ("layout-binding", CaptureRole::Execution, 115 + producer_len),
            ("source-run", CaptureRole::Execution, 147 + producer_len),
            (
                "pause-generation",
                CaptureRole::Execution,
                163 + producer_len,
            ),
            ("capture-id", CaptureRole::Execution, 171 + producer_len),
            ("cpu-count", CaptureRole::Execution, 187 + producer_len),
            ("page-granule", CaptureRole::Execution, 200 + producer_len),
            ("guest-region", CaptureRole::Execution, 208 + producer_len),
            ("block-id", CaptureRole::Execution, 236 + producer_len),
            ("devices-version", CaptureRole::Devices, 8),
            ("devices-profile", CaptureRole::Devices, 46 + producer_len),
            ("devices-count", CaptureRole::Devices, 182 + producer_len),
            ("truncated", CaptureRole::Execution, 0),
        ] {
            let fixture = fixture().await;
            let (directory, mut evidence) = seal(&fixture);
            for disks in DISK_MODES {
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
            entry.sha256 = Sha256Digest::of_bytes(&bytes);
            directory
                .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
                .unwrap();
            for disks in DISK_MODES {
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
                entry.sha256 = Sha256Digest::of_bytes(&bytes);
            }
            directory
                .write_file("vm.capture.json", &evidence.canonical_bytes().unwrap())
                .unwrap();
            for disks in DISK_MODES {
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
        // The second verification lane is charged explicitly before effects.
        assert_eq!(CAPTURE_SCRATCH_BYTES, 18 << 20);
        assert_eq!(
            record.reservation_memory_bytes,
            record.plan.ram_bytes + CAPTURE_SCRATCH_BYTES
        );
        let (directory, evidence) = seal(&sealed);
        for disks in DISK_MODES {
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
                    disks == DiskAuthentication::WithStreamMap
                        && matches!(payload.role, CaptureRole::Disk(_)),
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
            for disks in DISK_MODES {
                let error = verify_capture(&directory, &fixture.reservation.record, disks)
                    .err()
                    .unwrap();
                assert!(
                    error
                        .to_string()
                        .contains("capture staged payload digest mismatch"),
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
            Sha256Digest::of_bytes(&std::fs::read(&source).unwrap()),
            disk.sha256
        );
        std::fs::rename(&source, directory.path().join(disk.role.relative_path())).unwrap();
        for disks in DISK_MODES {
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
            sha256: Sha256Digest::of_bytes(&[0x32; 4096]),
        };
        let execution = CaptureInventoryEntry {
            role: CaptureRole::Execution,
            length: 8,
            sha256: Sha256Digest::of_bytes(b"original"),
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
                    DiskAuthentication::WithStreamMap,
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
                    DiskAuthentication::WithStreamMap,
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
                        DiskAuthentication::WholeDigest,
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
        // Restart or another process: no retained carrier, so each disk is
        // authenticated again against its evidence digest, deriving the map.
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
        assert!(
            store.open_local_cut(operation, None).await.is_err(),
            "fallback authentication checks the evidence digest, not the record"
        );
    }

    #[tokio::test]
    async fn measured_ram_sha_rejects_self_hash_valid_contradictory_capture_inventory() {
        use std::os::fd::AsRawFd;

        use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

        let fixture = fixture().await;
        let (directory, mut evidence) = seal(&fixture);
        let info = fixture
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
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("fixture is an execution checkpoint");
        };
        let memory = execution.memory.clone();
        let (ram, measured) = consumer
            .open_ram(&pool, &memory.stream, memory.length)
            .unwrap();
        let files = [
            ram,
            consumer.open_object(&pool, &execution.layout).unwrap(),
            consumer.open_object(&pool, &execution.execution).unwrap(),
            consumer.open_object(&pool, &execution.devices).unwrap(),
        ];
        let digests = [
            measured,
            Sha256Digest::from_bytes(*execution.layout.as_bytes()),
            Sha256Digest::from_bytes(*execution.execution.as_bytes()),
            Sha256Digest::from_bytes(*execution.devices.as_bytes()),
        ];
        let objects: Vec<_> = files
            .iter()
            .zip(RestoreObjectRole::ALL)
            .zip(digests)
            .map(|((file, role), sha256)| {
                let metadata = file.metadata().unwrap();
                RestoreObject {
                    role,
                    fd: file.as_raw_fd(),
                    file_device: metadata.dev(),
                    file_inode: metadata.ino(),
                    length: metadata.len(),
                    sha256,
                }
            })
            .collect();
        let mut request = RestoreRequest {
            version: vm_spec::restore::RESTORE_REQUEST_VERSION,
            checkpoint: Sha256Digest::from_bytes(*info.id.as_bytes()),
            activation_id: vm_spec::lifecycle::LiveId::parse(&Uuid::new_v4().to_string()).unwrap(),
            freeze_operation_id: evidence.freeze_operation_id.clone().unwrap(),
            start_paused: true,
            configuration: CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
                .unwrap(),
            evidence: fixture
                .snapshots
                .restore_evidence(&consumer, &pool)
                .unwrap(),
            objects: objects.try_into().unwrap(),
            lowers: Vec::new(),
            network: None,
            ssh_trusted_ca: None,
            hook: None,
        };
        request.validate().unwrap();
        let inventory = evidence
            .inventory
            .iter_mut()
            .find(|entry| entry.role == CaptureRole::Ram)
            .unwrap();
        inventory.sha256 = Sha256Digest::of_bytes(b"contradictory RAM inventory");
        assert_ne!(measured, inventory.sha256);
        assert!(evidence.is_sealed());
        let bytes = evidence.canonical_bytes().unwrap();
        let input = fixture
            ._temporary
            .path()
            .join("contradictory-evidence.json");
        std::fs::write(&input, &bytes).unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&input).unwrap();
        assert_eq!(object.digest, ObjectDigest::of_bytes(&bytes));
        // Deliberately construct a hostile, internally self-hash-valid catalog
        // state. Supported publication never replaces immutable provenance.
        let mut tx = fixture.snapshots.store.pool.begin().await.unwrap();
        sqlx::query("DELETE FROM snapshot_capture_provenance WHERE capture_id=?1")
            .bind(fixture.reservation.record.capture_id.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO snapshot_capture_provenance(capture_id,snapshot_id,evidence_digest,evidence_bytes) VALUES(?1,?2,?3,?4)")
            .bind(fixture.reservation.record.capture_id.to_string())
            .bind(info.id.to_string())
            .bind(object.digest.to_string())
            .bind(&bytes)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(roots);
        let contradictory = fixture
            .snapshots
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        request.evidence = fixture
            .snapshots
            .restore_evidence(&contradictory, &pool)
            .unwrap();
        assert_eq!(request.evidence, evidence);
        let (ram, measured_again) = contradictory
            .open_ram(&pool, &memory.stream, memory.length)
            .unwrap();
        assert_eq!(measured_again, measured);
        assert_eq!(
            measured_again,
            crate::machine::restore::hash_file(&ram).unwrap()
        );
        let metadata = ram.metadata().unwrap();
        request.objects[0] = RestoreObject {
            role: RestoreObjectRole::Ram,
            fd: ram.as_raw_fd(),
            file_device: metadata.dev(),
            file_inode: metadata.ino(),
            length: metadata.len(),
            sha256: measured_again,
        };
        assert_eq!(
            request.validate().unwrap_err(),
            "restore object identity differs from the captured cut"
        );
    }
}

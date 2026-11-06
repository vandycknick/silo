//! Capture storage ownership extends the existing operation journal and pool.
//! It never drives monitor lifecycle commands or infers continuation from exit.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use vm_spec::capture::{
    CaptureDiskCopy, CaptureDiskName, CaptureDiskPlan, CaptureEvidence, CaptureLaunchLease,
    CapturePlan, CaptureReadOnlyInput, CaptureRole, Sha256Digest,
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
                .checked_add(16 << 20)
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
        let mut available_disks =
            BTreeMap::from([(machine_stat.st_dev as u64, available_disk(&machine)?)]);
        if machine_stat.st_dev != images_stat.st_dev {
            available_disks.insert(images_stat.st_dev as u64, available_disk(&images)?);
        }
        let available_memory = available_memory()?;
        let lease = pool.lease(record.capture_id)?;
        let (lease_device, lease_inode) = lease.file_identity()?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Replays racing this producer join the original immutable reservation.
        if let Some(json) = sqlx::query_scalar::<_, String>("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(record.capture_id.to_string()).fetch_optional(&mut *tx).await? {
            let existing = decode_record(&json)?;
            if existing.request != record.request { return Err(invalid("capture reservation replay conflict")); }
            tx.commit().await?;
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
        let mut disk_charges = BTreeMap::<u64, u64>::new();
        let mut memory_charge = 0u64;
        let mut cursor = String::new();
        loop {
            let rows = sqlx::query("SELECT operation_id,json(record_json) AS record_json FROM storage_operation WHERE kind='capture' AND operation_id>?1 ORDER BY operation_id LIMIT 256")
                .bind(&cursor).fetch_all(&mut *tx).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.try_get("operation_id")?;
                let existing = decode_record(&row.try_get::<String, _>("record_json")?)?;
                for charge in &existing.disk_charges {
                    let total = disk_charges.entry(charge.device).or_default();
                    *total = total
                        .checked_add(charge.bytes)
                        .ok_or_else(|| invalid("capture disk reservation overflow"))?;
                }
                memory_charge = memory_charge
                    .checked_add(existing.reservation_memory_bytes)
                    .ok_or_else(|| invalid("capture RAM reservation overflow"))?;
            }
        }
        for charge in &record.disk_charges {
            let available = available_disks
                .get(&charge.device)
                .copied()
                .ok_or_else(|| invalid("capture destination device lacks resource accounting"))?;
            let outstanding = disk_charges
                .get(&charge.device)
                .copied()
                .unwrap_or_default();
            budget("disk", charge.bytes, available.saturating_sub(outstanding))?;
        }
        budget(
            "RAM",
            record.reservation_memory_bytes,
            available_memory.saturating_sub(memory_charge),
        )?;
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,record_json) VALUES(?1,1,'capture','staging',?2,?3,?4,?5,?6,jsonb(?7))")
            .bind(record.capture_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).bind(i64::try_from(record.storage.storage_generation).map_err(invalid)?).bind(lease_device.to_string()).bind(lease_inode.to_string()).bind(encode_record(&record)?).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(record.capture_id.to_string()).bind(launch.operation_id.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        drop(_roots);
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
                    CaptureState::Released { .. } | CaptureState::Abandoned
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
        .await
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

    pub(crate) async fn finish_capture_release(&self, capture: Uuid) -> Result<(), LibVmError> {
        self.update_capture(capture, |record| {
            record.state = match record.state {
                CaptureState::Published { snapshot } => CaptureState::Released {
                    snapshot: Some(snapshot),
                },
                CaptureState::Abandoned => CaptureState::Released { snapshot: None },
                CaptureState::Released { snapshot } => CaptureState::Released { snapshot },
                _ => {
                    return Err(invalid(
                        "capture release requires publication or explicit abandonment",
                    ))
                }
            };
            Ok(())
        })
        .await
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
        self.update_capture(capture, |record| {
            if record.evidence.is_some()
                || !matches!(
                    record.state,
                    CaptureState::Reserved | CaptureState::Abandoned
                )
            {
                return Err(invalid("sealed capture cannot be abandoned"));
            }
            record.state = CaptureState::Abandoned;
            Ok(())
        })
        .await
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
                if !matches!(capture.state, CaptureState::Released { .. } | CaptureState::Abandoned) { return Ok(true); }
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
        let verified = verify_capture(&directory, &record)?;
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
                        payload.file.try_clone()?,
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
                        published.map,
                    )
                    .await?;
                    streams.insert(payload.role.relative_path(), content);
                }
                CaptureRole::Execution | CaptureRole::Devices | CaptureRole::Layout => {
                    let (published, roots) = pool.publish_object_file_for_catalog(
                        payload.file.try_clone()?,
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
    let state = if matches!(record.state, CaptureState::Released { .. }) {
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

fn available_disk(directory: &OwnedDirectory) -> Result<u64, LibVmError> {
    let stat = nix::sys::statvfs::fstatvfs(directory.fd()).map_err(std::io::Error::from)?;
    stat.blocks_available()
        .checked_mul(stat.fragment_size())
        .ok_or_else(|| invalid("filesystem free-space overflow"))
}

fn available_memory() -> Result<u64, LibVmError> {
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

fn budget(resource: &'static str, required: u64, available: u64) -> Result<(), LibVmError> {
    if required > available {
        return Err(StorageError::CaptureBudget {
            resource,
            required,
            available,
        }
        .into());
    }
    Ok(())
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

struct VerifiedPayload {
    role: CaptureRole,
    file: File,
    length: u64,
    fingerprint: SourceFingerprint,
}
impl VerifiedPayload {
    fn recheck(&self) -> Result<(), LibVmError> {
        if SourceFingerprint::new(&self.file.metadata()?) != self.fingerprint {
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
                || SourceFingerprint::new(&file.metadata()?) != payload.fingerprint
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
                || SourceFingerprint::new(&current.metadata()?) != payload.fingerprint
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
    let mut identities = BTreeSet::new();
    let mut files = Vec::with_capacity(evidence.inventory.len());
    let mut buffer = vec![0u8; 1 << 20];
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
        let fingerprint = SourceFingerprint::new(&metadata);
        let mut hash = Sha256::new();
        let mut input = &file;
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        let digest: [u8; 32] = hash.finalize().into();
        if &digest != entry.sha256.as_bytes() {
            return Err(invalid("capture staged payload digest mismatch"));
        }
        let payload = VerifiedPayload {
            role: entry.role.clone(),
            file,
            length: entry.length,
            fingerprint,
        };
        payload.recheck()?;
        files.push(payload);
    }
    let layout = files
        .iter()
        .find(|file| file.role == CaptureRole::Layout)
        .ok_or_else(|| invalid("RAM layout role is missing"))?;
    let mut bytes = Vec::new();
    let mut layout_file = layout.file.try_clone()?;
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
        &execution.file,
        &devices.file,
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
    use crate::store::capture::{budget, capture_directory, validate_layout, verify_capture};
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
            alias: Some("checkpoint".into()),
            policy: CapturePolicy::Full,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseAuthority::Acquire,
        };
        let reservation = snapshots.reserve_capture(&request).await.unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let boot_input = temporary.path().join("boot");
        std::fs::write(&boot_input, b"retained boot bytes").unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&boot_input).unwrap();
        snapshots
            .store
            .pin_published_storage_dependencies(request.capture_id, &[], &[object.digest])
            .await
            .unwrap();
        drop(roots);
        let boot = crate::store::models::snapshot::tests::record(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            ObjectDigest::of_bytes(b"map"),
            object.digest,
        )
        .boot;
        snapshots
            .bind_capture_boot(request.capture_id, boot)
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
            .finish_capture_release(capture)
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
        snapshots.store.remove_machine(&config).await.unwrap();
        std::fs::remove_dir_all(&config.machine_dir).unwrap();
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(pool.verify_stream(&memory).is_ok());
        assert!(pool.verify_object(&evidence_digest).is_ok());
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        snapshots.store.recover_image_cache().await.unwrap();
        assert!(!pool.stream_path(&memory).exists());
        assert!(!pool.object_path(&evidence_digest).exists());
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
            .finish_capture_release(first_capture)
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
                crate::BootBinding::Pinned {
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
            assert!(
                verify_capture(&directory, &fixture.reservation.record).is_err(),
                "{fault}"
            );
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
            assert!(verify_capture(&directory, &fixture.reservation.record).is_ok());
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
            assert!(
                verify_capture(&directory, &fixture.reservation.record).is_err(),
                "{fault}"
            );
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
            assert!(
                verify_capture(&directory, &fixture.reservation.record).is_err(),
                "{fault}"
            );
        }
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
                .finish_capture_release(capture)
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
            .finish_capture_release(capture)
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

    #[test]
    fn checkpoint_budget_errors_distinguish_required_and_available_resources() {
        assert!(budget("disk", 100, 100).is_ok());
        assert!(matches!(
            budget("RAM", 101, 100),
            Err(crate::LibVmError::Storage(
                crate::storage::StorageError::CaptureBudget {
                    resource: "RAM",
                    required: 101,
                    available: 100
                }
            ))
        ));
    }
}

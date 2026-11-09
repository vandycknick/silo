//! Restore reservations belong to the existing operation journal. A generation
//! keeps the whole verification closure, not just the machine's disk roots.
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use uuid::Uuid;

use crate::storage::identity::SnapshotId;
use crate::store::models::snapshot::invalid;
use crate::store::operation_store::LaunchStorageLease;
use crate::store::snapshot_store::{SnapshotConsumer, SnapshotStore};
use crate::{LibVmError, MachineStorageRecord};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum RestoreIdentity {
    Snapshot { id: SnapshotId },
    LocalCut { id: vm_spec::capture::Sha256Digest },
}

impl RestoreIdentity {
    pub(crate) fn digest(&self) -> &[u8; 32] {
        match self {
            Self::Snapshot { id } => id.as_bytes(),
            Self::LocalCut { id } => id.as_bytes(),
        }
    }
    pub(crate) fn snapshot(&self) -> Option<SnapshotId> {
        match self {
            Self::Snapshot { id } => Some(*id),
            Self::LocalCut { .. } => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreIntent {
    pub checkpoint: RestoreIdentity,
    pub consumer_operation: Uuid,
    pub request: vm_spec::restore::RestoreRequest,
    pub memory: RestoreMemoryCharge,
    pub inspected_executable: crate::storage::identity::ObjectDigest,
    pub inspection: vm_spec::restore::RestoreInspectionReport,
    pub network_attachment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreConstruction {
    pub run_id: Uuid,
    pub name: String,
    pub intent: RestoreIntent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DescriptorOwner {
    pid: i32,
    started_at: i64,
}

impl DescriptorOwner {
    fn current() -> Result<Self, LibVmError> {
        let pid = i32::try_from(std::process::id()).map_err(invalid)?;
        let started_at = utils::process::start_time(pid)?
            .ok_or_else(|| invalid("manager process birth identity is unavailable"))?;
        Ok(Self { pid, started_at })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreMemoryCharge {
    pub baseline_device: u64,
    pub baseline_inode: u64,
    pub baseline_bytes: u64,
    pub configured_bytes: u64,
    pub granule: u64,
    pub private_bytes: u64,
    pub overhead_bytes: u64,
    pub policy: crate::RestoreResourcePolicy,
    pub disk_device: u64,
    pub disk_bytes: u64,
    pub construction_complete: bool,
    pub descriptor_owner: Option<DescriptorOwner>,
    pub descriptors: u64,
}

impl RestoreMemoryCharge {
    fn validate(&self) -> Result<(), LibVmError> {
        validate_descriptor_charge(self.descriptor_owner, self.descriptors)?;
        if self.baseline_inode == 0
            || self.baseline_bytes == 0
            || self.baseline_bytes > self.configured_bytes
            || self.configured_bytes > vm_spec::capture::MAX_CAPTURE_RAM_BYTES
            || self.granule == 0
            || !self.granule.is_power_of_two()
            || self.private_bytes
                != self
                    .policy
                    .private_write_allowance
                    .reservation(self.configured_bytes, self.granule)?
            || self.overhead_bytes
                != self.configured_bytes.div_ceil(512)
                    + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
            || (if self.construction_complete {
                self.disk_bytes != 0
            } else {
                self.disk_bytes < vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
            })
        {
            return Err(invalid(
                "restore resource reservation is malformed or undercharged",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingForkCharge {
    pub consumer_id: Uuid,
    pub configured_bytes: u64,
    pub private_bytes: u64,
    pub overhead_bytes: u64,
    pub disk_device: u64,
    pub disk_bytes: u64,
    pub policy: crate::RestoreResourcePolicy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum CaptureBaseline {
    Pending { capture_id: Uuid, bytes: u64 },
    Bound { device: u64, inode: u64, bytes: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureBudgetInventory {
    pub capture_id: Uuid,
    pub capture_memory: u64,
    pub baseline: Option<CaptureBaseline>,
    pub capture_disks: Vec<crate::store::snapshot_store::CaptureSpaceCharge>,
    pub pending: Vec<PendingForkCharge>,
    pub bound: Vec<RestoreMemoryCharge>,
    pub descriptor_owner: Option<DescriptorOwner>,
    pub descriptors: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BudgetDocument {
    Restore(RestoreMemoryCharge),
    Capture(CaptureBudgetInventory),
}
#[derive(Default)]
struct RestoreBudget {
    memory: u64,
    baselines: std::collections::BTreeMap<(u64, u64), u64>,
    disks: std::collections::BTreeMap<u64, u64>,
    manager: Option<DescriptorOwner>,
    descriptors: u64,
}

impl RestoreBudget {
    fn add(&mut self, charge: &RestoreMemoryCharge) -> Result<(), LibVmError> {
        charge.validate()?;
        self.add_descriptors(charge.descriptor_owner, charge.descriptors)?;
        self.memory = self
            .memory
            .checked_add(charge.private_bytes)
            .and_then(|n| n.checked_add(charge.overhead_bytes))
            .ok_or_else(|| invalid("restore memory reservation overflow"))?;
        match self
            .baselines
            .entry((charge.baseline_device, charge.baseline_inode))
        {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(charge.baseline_bytes);
                self.memory = self
                    .memory
                    .checked_add(charge.baseline_bytes)
                    .ok_or_else(|| invalid("restore baseline charge overflow"))?;
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if *entry.get() != charge.baseline_bytes =>
            {
                return Err(invalid(
                    "one restore baseline inode has contradictory lengths",
                ));
            }
            _ => {}
        }
        let disk = self.disks.entry(charge.disk_device).or_default();
        *disk = disk
            .checked_add(charge.disk_bytes)
            .ok_or_else(|| invalid("restore disk reservation overflow"))?;
        Ok(())
    }

    fn read(directory: &crate::paths::OwnedDirectory) -> Result<Self, LibVmError> {
        Self::read_except(directory, None)
    }

    fn read_except(
        directory: &crate::paths::OwnedDirectory,
        excluded: Option<&str>,
    ) -> Result<Self, LibVmError> {
        let mut budget = Self {
            manager: Some(DescriptorOwner::current()?),
            ..Self::default()
        };
        let mut bytes = Vec::new();
        for name in budget_entries(directory)? {
            if excluded == Some(name.as_str()) {
                continue;
            }
            let file = directory
                .open_file(&name)?
                .ok_or_else(|| invalid("restore budget record disappeared"))?;
            bytes.clear();
            file.take((16 << 20) + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 16 << 20 {
                return Err(invalid("resource budget inventory exceeds 16 MiB"));
            }
            match serde_json::from_slice::<BudgetDocument>(&bytes).map_err(invalid)? {
                BudgetDocument::Restore(charge) => budget.add(&charge)?,
                BudgetDocument::Capture(inventory) => budget.add_capture(&inventory)?,
            }
        }
        Ok(budget)
    }

    fn add_capture(&mut self, inventory: &CaptureBudgetInventory) -> Result<(), LibVmError> {
        self.add_descriptors(inventory.descriptor_owner, inventory.descriptors)?;
        if inventory.capture_id.is_nil() {
            return Err(invalid("capture budget identity is nil"));
        }
        self.memory = self
            .memory
            .checked_add(inventory.capture_memory)
            .ok_or_else(|| invalid("capture budget overflow"))?;
        match inventory.baseline {
            Some(CaptureBaseline::Pending { capture_id, bytes }) => {
                if capture_id != inventory.capture_id
                    || bytes == 0
                    || bytes > vm_spec::capture::MAX_CAPTURE_RAM_BYTES
                {
                    return Err(invalid("pending capture baseline identity is malformed"));
                }
                self.memory = self
                    .memory
                    .checked_add(bytes)
                    .ok_or_else(|| invalid("pending capture baseline overflow"))?;
            }
            Some(CaptureBaseline::Bound {
                device,
                inode,
                bytes,
            }) => {
                if inode == 0 || bytes == 0 || bytes > vm_spec::capture::MAX_CAPTURE_RAM_BYTES {
                    return Err(invalid("capture baseline identity is invalid"));
                }
                match self.baselines.entry((device, inode)) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(bytes);
                        self.memory = self
                            .memory
                            .checked_add(bytes)
                            .ok_or_else(|| invalid("capture baseline overflow"))?;
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if *entry.get() != bytes =>
                    {
                        return Err(invalid(
                            "capture baseline geometry contradicts a generation",
                        ))
                    }
                    _ => {}
                }
            }
            None => {}
        }
        for disk in &inventory.capture_disks {
            let total = self.disks.entry(disk.device).or_default();
            *total = total
                .checked_add(disk.bytes)
                .ok_or_else(|| invalid("capture disk budget overflow"))?;
        }
        for child in &inventory.pending {
            if child.consumer_id.is_nil()
                || child.configured_bytes == 0
                || child.configured_bytes > vm_spec::capture::MAX_CAPTURE_RAM_BYTES
                || child.private_bytes
                    != child
                        .policy
                        .private_write_allowance
                        .reservation(child.configured_bytes, 65536)?
                || child.overhead_bytes
                    != child.configured_bytes.div_ceil(512)
                        + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
                || child.disk_bytes < vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
            {
                return Err(invalid("pending fork reservation is malformed"));
            }
            self.memory = self
                .memory
                .checked_add(child.private_bytes)
                .and_then(|n| n.checked_add(child.overhead_bytes))
                .ok_or_else(|| invalid("fork memory budget overflow"))?;
            let total = self.disks.entry(child.disk_device).or_default();
            *total = total
                .checked_add(child.disk_bytes)
                .ok_or_else(|| invalid("fork disk budget overflow"))?;
        }
        for child in &inventory.bound {
            self.add(child)?;
        }
        Ok(())
    }

    fn add_descriptors(
        &mut self,
        owner: Option<DescriptorOwner>,
        count: u64,
    ) -> Result<(), LibVmError> {
        validate_descriptor_charge(owner, count)?;
        if owner.is_some() && owner == self.manager {
            self.descriptors = self
                .descriptors
                .checked_add(count)
                .ok_or_else(|| invalid("manager descriptor reservations overflow"))?;
        }
        Ok(())
    }

    fn admit_descriptors(&self) -> Result<(), LibVmError> {
        crate::storage::limits::preflight_fd_budget(self.descriptors)
            .map_err(crate::storage::StorageError::from)?;
        Ok(())
    }

    fn admit_memory(
        &self,
        policy: crate::RestoreMemoryPolicy,
        available: u64,
    ) -> Result<(), LibVmError> {
        if self.memory > available {
            if policy == crate::RestoreMemoryPolicy::Reserved {
                return Err(crate::storage::StorageError::RestoreBudget {
                    resource: "RAM",
                    required: self.memory,
                    available,
                }
                .into());
            }
            tracing::warn!(
                required = self.memory,
                available,
                "explicit restore memory overcommit"
            );
        }
        Ok(())
    }
}

impl RestoreIntent {
    pub(crate) fn validate(&self) -> Result<(), LibVmError> {
        self.request.validate().map_err(invalid)?;
        self.memory.validate()?;
        let mut inspected = self.request.clone();
        inspected.network = None;
        inspected.ssh_trusted_ca = None;
        let inspected = vm_spec::restore::RestoreInspectionRequest {
            version: 1,
            restore: inspected,
            network: self.network_attachment,
        };
        let bytes = serde_json::to_vec(&inspected).map_err(invalid)?;
        self.inspection
            .validate_against(&bytes, &inspected)
            .map_err(invalid)?;
        let ram = &self.request.objects[0];
        if self.consumer_operation.is_nil()
            || self.checkpoint.digest() != self.request.checkpoint.as_bytes()
            || self.memory.baseline_device != ram.file_device
            || self.memory.baseline_inode != ram.file_inode
            || self.memory.baseline_bytes != ram.length
            || self.memory.configured_bytes != self.request.configuration.ram_bytes()
        {
            return Err(invalid(
                "restore intent contradicts authenticated RAM or checkpoint",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct AuthenticatedRestoreCapture {
    pub(crate) evidence: vm_spec::capture::CaptureEvidence,
    _authority: RestoreCaptureAuthority,
}

#[derive(Debug)]
enum RestoreCaptureAuthority {
    LocalCapture,
    ApprovedImport,
}

pub(crate) fn authenticate_imported_captures(
    pool: &crate::storage::pool::StoragePool,
    record: &crate::store::models::snapshot::SnapshotRecord,
    snapshot: SnapshotId,
    refs: &[crate::store::artifact_store::ImportedCaptureRef],
) -> Result<Vec<vm_spec::capture::CaptureEvidence>, LibVmError> {
    let mut evidence = Vec::with_capacity(refs.len());
    for capture in refs {
        let receipt_bytes = pool.read_object(
            &capture.receipt_digest,
            crate::storage::limits::Resource::MetadataPageBytes.maximum(),
        )?;
        let receipt = crate::image::transport::trust::AcquisitionReceipt::decode(&receipt_bytes)?;
        if receipt.canonical_bytes()? != receipt_bytes
            || receipt.index_digest != capture.index_digest
        {
            return Err(invalid(
                "restore receipt does not approve the selected immutable index",
            ));
        }
        let wrapper = pool.read_object(
            &capture.provenance_digest,
            crate::storage::limits::Resource::MetadataPageBytes.maximum(),
        )?;
        let bytes = pool.read_object(
            &capture.evidence_digest,
            vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
        )?;
        let verified = crate::image::transport::provenance::verify_portable_binding(
            record, snapshot, &wrapper, &bytes,
        )?;
        evidence.push(verified.evidence);
    }
    Ok(evidence)
}

impl SnapshotStore {
    /// Select matching authenticated authority, never the first provenance row.
    /// Every catalog candidate is checked, including rows after the selection.
    pub(crate) fn restore_evidence(
        &self,
        consumer: &SnapshotConsumer,
        pool: &crate::storage::pool::StoragePool,
    ) -> Result<AuthenticatedRestoreCapture, LibVmError> {
        let configuration =
            vm_spec::capture::CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
                .map_err(invalid)?;
        let execution = match &consumer.record.capture {
            crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } => {
                execution
            }
            _ => return Err(invalid("execution restore requires a live checkpoint")),
        };
        let mut selected = None;
        for provenance in &consumer.info.provenance {
            pool.verify_object(&provenance.evidence_digest)?;
            let bytes = pool.read_object(
                &provenance.evidence_digest,
                vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
            )?;
            let evidence = vm_spec::capture::CaptureEvidence::decode(&bytes).map_err(invalid)?;
            let memory = evidence
                .memory
                .as_ref()
                .ok_or_else(|| invalid("capture seal has no RAM binding"))?;
            let pins = [
                (evidence.is_sealed(), "coherent seal"),
                (
                    Uuid::parse_str(evidence.machine_id.as_str()).ok()
                        == Some(provenance.machine_id)
                        && Uuid::parse_str(evidence.run_id.as_str()).ok()
                            == Some(provenance.run_id)
                        && Uuid::parse_str(evidence.capture_id.as_str()).ok()
                            == Some(provenance.capture_id),
                    "source machine/run/capture identity",
                ),
                (
                    evidence.configuration_digest == configuration.digest().map_err(invalid)?,
                    "captured configuration",
                ),
                (
                    memory.ram_stream.as_bytes() == execution.memory.stream.as_bytes()
                        && memory.packed_length == execution.memory.length,
                    "RAM stream/geometry",
                ),
                (
                    memory.binding.native_producer
                        == execution.compatibility_profile.native_producer,
                    "native producer",
                ),
                (
                    memory.binding.silo_producer.as_bytes()
                        == execution.compatibility_profile.silo_producer.as_bytes(),
                    "Silo producer",
                ),
                (
                    memory.binding.profile.as_bytes()
                        == execution.compatibility_profile.profile.as_bytes(),
                    "CPU/clock profile",
                ),
                (
                    memory.binding.topology.as_bytes()
                        == execution.compatibility_profile.topology.as_bytes(),
                    "device topology",
                ),
                (
                    memory.binding.ram_layout.as_bytes()
                        == execution.compatibility_profile.ram_layout.as_bytes(),
                    "RAM layout",
                ),
            ];
            if pins.into_iter().all(|(admitted, _)| admitted) && selected.is_none() {
                selected = Some(AuthenticatedRestoreCapture {
                    evidence,
                    _authority: RestoreCaptureAuthority::LocalCapture,
                });
            }
        }
        let imported = authenticate_imported_captures(
            pool,
            &consumer.record,
            consumer.info.id,
            consumer.imported_provenance(),
        )?;
        if selected.is_none() {
            if let Some(evidence) = imported.into_iter().next() {
                selected = Some(AuthenticatedRestoreCapture {
                    evidence,
                    _authority: RestoreCaptureAuthority::ApprovedImport,
                });
            }
        }
        selected.ok_or_else(|| {
            invalid("execution checkpoint lacks an authorized matching capture provenance")
        })
    }

    pub(crate) async fn register_restore_generation(
        &self,
        config: &crate::store::models::MachineConfig,
        run: Uuid,
        storage: &MachineStorageRecord,
        intent: &RestoreIntent,
    ) -> Result<LaunchStorageLease, LibVmError> {
        self.store
            .register_launch_storage_inner(config.id, run, storage, &config.spec, Some(intent))
            .await
    }

    #[allow(clippy::unnecessary_cast)]
    pub(crate) async fn reserve_restore_resources(
        &self,
        consumer: &SnapshotConsumer,
        request: &vm_spec::restore::RestoreRequest,
        disk_peak: u64,
        descriptor_peak: u64,
        policy: crate::RestoreResourcePolicy,
    ) -> Result<RestoreMemoryCharge, LibVmError> {
        let ram = &request.objects[0];
        let bytes = request.configuration.ram_bytes();
        let granule = u64::from(
            request
                .evidence
                .memory
                .as_ref()
                .ok_or_else(|| invalid("missing RAM granule"))?
                .page_granule,
        );
        if granule == 0 || !granule.is_power_of_two() {
            return Err(invalid("invalid native RAM granule"));
        }
        // Imported checkpoints can be restored before this home has ever owned a
        // machine. Create only the private container, not a child or disk, before
        // measuring and reserving space on its actual filesystem.
        let home = crate::paths::OwnedDirectory::open_existing_root(&self.store.home)?
            .ok_or_else(|| invalid("restore destination home disappeared"))?;
        let disk = home.ensure_dir("machines")?;
        let disk_stat = nix::sys::stat::fstat(disk.fd()).map_err(std::io::Error::from)?;
        let charge = RestoreMemoryCharge {
            baseline_device: ram.file_device,
            baseline_inode: ram.file_inode,
            baseline_bytes: ram.length,
            configured_bytes: bytes,
            granule,
            private_bytes: policy.private_write_allowance.reservation(bytes, granule)?,
            // A separate conservative page-table plus bounded native-state
            // allowance. This is reservation policy, not a measured RSS claim.
            overhead_bytes: bytes.div_ceil(512) + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
            policy,
            disk_device: disk_stat.st_dev as u64,
            disk_bytes: disk_peak,
            construction_complete: false,
            descriptor_owner: Some(DescriptorOwner::current()?),
            descriptors: descriptor_peak,
        };
        self.store
            .reserve_restore_charge(
                consumer.operation_id,
                &charge,
                &disk,
                &budget_directory(&self.store)?,
            )
            .await?;
        Ok(charge)
    }
}

impl crate::store::Store {
    async fn reserve_restore_charge(
        &self,
        operation: Uuid,
        charge: &RestoreMemoryCharge,
        disk: &crate::paths::OwnedDirectory,
        directory: &crate::paths::OwnedDirectory,
    ) -> Result<(), LibVmError> {
        self.reserve_restore_charge_with(operation, charge, disk, directory, |_| {})
            .await
    }

    async fn reserve_restore_charge_with(
        &self,
        operation: Uuid,
        charge: &RestoreMemoryCharge,
        disk: &crate::paths::OwnedDirectory,
        directory: &crate::paths::OwnedDirectory,
        checkpoint: impl FnMut(crate::paths::AtomicWritePhase),
    ) -> Result<(), LibVmError> {
        let _admission = crate::storage::locks::blocking(
            directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let mut budget = RestoreBudget::read(directory)?;
        budget.add(charge)?;
        budget.admit_descriptors()?;
        budget.admit_memory(
            charge.policy.memory,
            crate::store::capture::available_memory()?,
        )?;
        let disk_required = budget
            .disks
            .get(&charge.disk_device)
            .copied()
            .unwrap_or_default();
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).map_err(std::io::Error::from)?;
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .ok_or_else(|| invalid("restore disk availability overflow"))?;
        if disk_required > available {
            return Err(crate::storage::StorageError::RestoreBudget {
                resource: "disk",
                required: disk_required,
                available,
            }
            .into());
        }
        let json = serde_json::to_string(charge).map_err(invalid)?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO restore_memory_reservation(operation_id,budget_id,charge_json) VALUES(?1,?1,jsonb(?2))")
            .bind(operation.to_string()).bind(&json).execute(&mut *tx).await?;
        publish_budget(
            tx,
            directory,
            &budget_name(self, operation)?,
            &json,
            checkpoint,
        )
        .await?;
        Ok(())
    }
}

impl crate::store::Store {
    /// Import and private-copy peaks share capture/restore's existing cross-home
    /// disk ledger. The real producer owns the registered operation's OFD.
    pub(crate) async fn reserve_import_space(
        &self,
        operation: Uuid,
        bytes: u64,
    ) -> Result<(), LibVmError> {
        let disk = crate::paths::OwnedDirectory::open_existing_root(&self.images_dir)?
            .ok_or_else(|| invalid("import pool is missing"))?;
        self.reserve_copy_space(operation, bytes, &disk).await
    }

    pub(crate) async fn reserve_copy_space(
        &self,
        operation: Uuid,
        bytes: u64,
        disk: &crate::paths::OwnedDirectory,
    ) -> Result<(), LibVmError> {
        if operation.is_nil() || bytes == 0 {
            return Err(invalid(
                "copy space requires an exact owner and nonzero charge",
            ));
        }
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let stat = nix::sys::stat::fstat(disk.fd()).map_err(std::io::Error::from)?;
        let inventory = CaptureBudgetInventory {
            capture_id: operation,
            capture_memory: 0,
            baseline: None,
            capture_disks: vec![crate::store::snapshot_store::CaptureSpaceCharge {
                device: stat.st_dev as u64,
                bytes,
            }],
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: None,
            descriptors: 0,
        };
        let mut budget = RestoreBudget::read(&directory)?;
        budget.add_capture(&inventory)?;
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).map_err(std::io::Error::from)?;
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .ok_or_else(|| invalid("copy disk availability overflow"))?;
        let required = budget
            .disks
            .get(&(stat.st_dev as u64))
            .copied()
            .unwrap_or_default();
        if required > available {
            return Err(crate::image::import::DiskImportError::Capacity {
                required,
                available,
            }
            .into());
        }
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='import' AND state='staging')",
        )
        .bind(operation.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            return Err(invalid("copy space has no staging operation owner"));
        }
        sqlx::query(
            "INSERT INTO capture_resource_reservation(operation_id,charge_json) VALUES(?1,jsonb(?2))",
        )
        .bind(operation.to_string())
        .bind(&json)
        .execute(&mut *tx)
        .await?;
        publish_budget(
            tx,
            &directory,
            &budget_name(self, operation)?,
            &json,
            |_| {},
        )
        .await
    }

    /// Called after the producer has stopped using all simultaneous copies.
    /// SQL-first removal is conservative on interruption: reconciliation removes
    /// the old ledger entry only after the journal confirms release/retirement.
    pub(crate) async fn release_import_space(&self, operation: Uuid) -> Result<(), LibVmError> {
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        sqlx::query(
            "DELETE FROM capture_resource_reservation WHERE operation_id=?1 AND EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='import')",
        )
        .bind(operation.to_string())
        .execute(&self.pool)
        .await?;
        directory.remove_tree(&budget_name(self, operation)?)?;
        directory.sync()?;
        Ok(())
    }
}

/// A single authenticated user authority coordinates all of its runtime homes.
/// No user-owned file is represented as host-global or cross-user authority.
fn budget_directory(
    store: &crate::store::Store,
) -> Result<crate::paths::OwnedDirectory, LibVmError> {
    // Unit owners use real, isolated ledgers; cross-home tests explicitly pass
    // the same directory. Production always uses the same-euid authority below.
    #[cfg(test)]
    if let Some(directory) = &store.resource_budget_directory {
        return crate::paths::OwnedDirectory::open_root(directory);
    }
    let _ = store;
    let parent = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    crate::paths::OwnedDirectory::open_root(&Path::new(parent).join(format!(
        "silo-restore-budget-{}",
        nix::unistd::geteuid().as_raw()
    )))
}

fn budget_prefix(store: &crate::store::Store) -> Result<String, LibVmError> {
    // Path stat never opens another SQLite descriptor (which could release its
    // process-wide POSIX locks). The inode survives home relocation.
    let stat = std::fs::metadata(store.home.join("state.db"))?;
    Ok(format!("{}-{}-", stat.dev(), stat.ino()))
}

fn budget_name(store: &crate::store::Store, operation: Uuid) -> Result<String, LibVmError> {
    Ok(format!("{}{operation}.json", budget_prefix(store)?))
}

/// SQL owns the reservation before publication. An interrupted initial publish
/// has no child yet; an interrupted release retains the old conservative charge.
async fn publish_budget(
    tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    directory: &crate::paths::OwnedDirectory,
    name: &str,
    json: &str,
    checkpoint: impl FnMut(crate::paths::AtomicWritePhase),
) -> Result<(), LibVmError> {
    tx.commit().await?;
    directory.write_file_atomic_with(name, json.as_bytes(), checkpoint)
}

fn budget_entries(directory: &crate::paths::OwnedDirectory) -> Result<Vec<String>, LibVmError> {
    let mut names = Vec::new();
    let entries = nix::dir::Dir::openat(
        directory.fd(),
        ".",
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    for entry in entries.into_iter() {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name().to_str().map_err(invalid)?;
        if matches!(name, "." | ".." | "admission.lock") {
            continue;
        }
        if name == ".atomic-write" {
            // All publishers hold admission.lock. A staging directory visible
            // here contains only abandoned, non-authoritative writes.
            directory
                .open_dir(name)?
                .ok_or_else(|| invalid("restore budget staging disappeared"))?;
            directory.remove_tree(name)?;
            directory.sync()?;
            continue;
        }
        if !name.ends_with(".json") || names.len() >= 65_536 {
            return Err(invalid(
                "restore budget inventory is invalid or exceeds its bound",
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

impl crate::store::Store {
    pub(crate) async fn persist_restore_construction(
        &self,
        construction: &RestoreConstruction,
    ) -> Result<(), LibVmError> {
        construction.intent.validate()?;
        crate::validate_new_machine_name(&construction.name)?;
        if construction.run_id.is_nil() {
            return Err(invalid("restore construction has no exact run"));
        }
        let json = serde_json::to_string(construction).map_err(invalid)?;
        crate::storage::limits::Resource::MetadataPageBytes
            .check(json.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        let result = sqlx::query("UPDATE restore_memory_reservation SET construction_json=jsonb(?2) WHERE operation_id=?1 AND construction_json IS NULL")
            .bind(construction.intent.consumer_operation.to_string())
            .bind(json).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(invalid("restore construction reservation changed"));
        }
        Ok(())
    }

    async fn complete_restore_construction(
        &self,
        operation: Uuid,
        run: Uuid,
    ) -> Result<(), LibVmError> {
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row: Option<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT json(o.record_json),r.budget_id,r.batch_id FROM storage_operation o JOIN restore_memory_reservation r ON r.operation_id=o.operation_id JOIN machine_state s ON s.machine_id=o.machine_id WHERE o.operation_id=?1 AND o.run_id=?2 AND o.kind='launch' AND s.status='running' AND json_extract(s.state_json,'$.runId')=?2"
        ).bind(operation.to_string()).bind(run.to_string()).fetch_optional(&mut *tx).await?;
        let Some((json, budget_id, batch)) = row else {
            return Ok(());
        };
        let mut record: crate::store::operation_store::RetainedStorageOperation =
            serde_json::from_str(&json).map_err(invalid)?;
        if !record.admitted {
            return Err(invalid(
                "unsubmitted restore has no startup completion receipt",
            ));
        }
        let intent = record
            .restore
            .as_mut()
            .ok_or_else(|| invalid("restore completion has no execution intent"))?;
        intent.memory.construction_complete = true;
        intent.memory.disk_bytes = 0;
        intent.memory.descriptor_owner = None;
        intent.memory.descriptors = 0;
        let charge = serde_json::to_string(&intent.memory).map_err(invalid)?;
        let encoded = crate::store::operation_store::encode(&record)?;
        sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation.to_string())
            .bind(encoded)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE restore_memory_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(&charge)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        // Batch reductions accumulate SQL-first. The outer reconciliation
        // publishes one complete inventory, not N quadratic aggregate rewrites.
        if batch.is_none() {
            directory.write_file_atomic(
                &budget_name(self, Uuid::parse_str(&budget_id).map_err(invalid)?)?,
                charge.as_bytes(),
            )?;
        }
        Ok(())
    }

    /// Reconcile quota only from the existing journal's startup/retirement
    /// receipts, never from a PID or flock observation alone.
    pub(crate) async fn reconcile_restore_budget(&self) -> Result<(), LibVmError> {
        // Running for this exact run follows completed activation. Release only
        // construction disk peak; mapping/private-write charges remain owned.
        loop {
            let completed: Vec<(String, String)> = sqlx::query_as(
                "SELECT o.operation_id,o.run_id FROM storage_operation o JOIN restore_memory_reservation r ON r.operation_id=o.operation_id JOIN machine_state s ON s.machine_id=o.machine_id WHERE o.kind='launch' AND json_extract(o.record_json,'$.restore') IS NOT NULL AND json_extract(o.record_json,'$.restore.memory.constructionComplete')=0 AND s.status='running' AND json_extract(s.state_json,'$.runId')=o.run_id ORDER BY o.operation_id LIMIT 256"
            ).fetch_all(&self.pool).await?;
            if completed.is_empty() {
                break;
            }
            for (operation, run) in completed {
                self.complete_restore_construction(
                    Uuid::parse_str(&operation).map_err(invalid)?,
                    Uuid::parse_str(&run).map_err(invalid)?,
                )
                .await?;
            }
        }
        self.reconcile_restore_budget_in(&budget_directory(self)?)
            .await
    }

    async fn reconcile_restore_budget_in(
        &self,
        directory: &crate::paths::OwnedDirectory,
    ) -> Result<(), LibVmError> {
        let _admission = crate::storage::locks::blocking(
            directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let prefix = budget_prefix(self)?;
        let mut authoritative = std::collections::BTreeSet::new();
        let standalone:Vec<(String,String)>=sqlx::query_as("SELECT budget_id,json(charge_json) FROM restore_memory_reservation WHERE batch_id IS NULL").fetch_all(&self.pool).await?;
        for (id, json) in standalone {
            let charge: RestoreMemoryCharge = serde_json::from_str(&json).map_err(invalid)?;
            charge.validate()?;
            let name = budget_name(self, Uuid::parse_str(&id).map_err(invalid)?)?;
            directory.write_file_atomic(&name, json.as_bytes())?;
            authoritative.insert(name);
        }
        let captures: Vec<String> =
            sqlx::query_scalar("SELECT operation_id FROM capture_resource_reservation")
                .fetch_all(&self.pool)
                .await?;
        for id in captures {
            let operation = Uuid::parse_str(&id).map_err(invalid)?;
            let json = self.capture_budget_document(operation).await?;
            let name = budget_name(self, operation)?;
            directory.write_file_atomic(&name, json.as_bytes())?;
            authoritative.insert(name);
        }
        for name in budget_entries(directory)? {
            if name.starts_with(&prefix) && !authoritative.contains(&name) {
                directory.remove_tree(&name)?;
            }
        }
        directory.sync()?;
        Ok(())
    }

    pub(crate) async fn bind_restore_activation(
        &self,
        operation: Uuid,
        request: &vm_spec::restore::RestoreRequest,
    ) -> Result<(), LibVmError> {
        request.validate().map_err(invalid)?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: String = sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='launch'")
            .bind(operation.to_string()).fetch_one(&mut *tx).await?;
        let mut record: crate::store::operation_store::RetainedStorageOperation =
            serde_json::from_str(&json).map_err(invalid)?;
        if record.admitted {
            return Err(invalid("restore launch is already submitted"));
        }
        let intent = record
            .restore
            .as_mut()
            .ok_or_else(|| invalid("generation has no restore intent"))?;
        if intent.network_attachment != request.network.is_some()
            || request.ssh_trusted_ca.is_none()
        {
            return Err(invalid(
                "restore destination activation bindings are incomplete",
            ));
        }
        let mut expected = intent.request.clone();
        expected.network = request.network.clone();
        expected.ssh_trusted_ca = request.ssh_trusted_ca.clone();
        if &expected != request {
            return Err(invalid("activation changed authenticated restore inputs"));
        }
        intent.request = request.clone();
        intent.validate()?;
        sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation.to_string())
            .bind(crate::store::operation_store::encode(&record)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

impl crate::store::Store {
    /// Shared cross-home admission. No capture command can precede successful
    /// publication of this complete inventory under the restore admission lock.
    pub(crate) async fn reserve_capture_inventory(
        &self,
        record: &crate::store::snapshot_store::CaptureRecord,
    ) -> Result<(), LibVmError> {
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let fork = self.fork_for_capture(record.capture_id).await?;
        let owner = fork.unwrap_or(record.capture_id);
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(json) = existing {
            return self
                .replay_capture_inventory(owner, &directory, &json)
                .await;
        }
        let mut inventory = CaptureBudgetInventory {
            capture_id: record.capture_id,
            capture_memory: record
                .reservation_memory_bytes
                .checked_sub(record.plan.ram_bytes)
                .ok_or_else(|| invalid("capture scratch reservation underflow"))?,
            baseline: Some(CaptureBaseline::Pending {
                capture_id: record.capture_id,
                bytes: record.plan.ram_bytes,
            }),
            capture_disks: record.disk_charges.clone(),
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: Some(DescriptorOwner::current()?),
            descriptors: record.plan.configuration.attachments.len() as u64 * 3 + 12,
        };
        let mut policy = crate::RestoreMemoryPolicy::Reserved;
        if let Some(operation) = fork {
            let options = self.fork_options(operation).await?;
            policy = options.resources.memory;
            let parent =
                crate::paths::OwnedDirectory::open_existing_root(&self.home.join("machines"))?
                    .ok_or_else(|| invalid("fork destination parent missing"))?;
            let stat = nix::sys::stat::fstat(parent.fd()).map_err(std::io::Error::from)?;
            let mut disk = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
            for attachment in &record.plan.configuration.attachments {
                if !attachment.read_only {
                    disk = disk
                        .checked_add(attachment.geometry.length)
                        .ok_or_else(|| invalid("fork disk peak overflow"))?;
                }
            }
            // Retain the exact pinned boot provenance once per destination.
            let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
            if let crate::BootProfile::LinuxDirect {
                binding:
                    crate::BootBinding::Pinned {
                        kernel,
                        base_initramfs,
                        agent,
                        ..
                    },
                ..
            } = &record.storage.boot
            {
                for object in [kernel, base_initramfs].into_iter().chain(agent.iter()) {
                    disk = disk
                        .checked_add(std::fs::metadata(pool.object_path(object))?.len())
                        .ok_or_else(|| invalid("fork boot peak overflow"))?;
                }
            }
            let configured = record.plan.ram_bytes;
            for child in self.fork_children(operation).await? {
                inventory.pending.push(PendingForkCharge {
                    consumer_id: child.consumer_id,
                    configured_bytes: configured,
                    private_bytes: options
                        .resources
                        .private_write_allowance
                        .reservation(configured, 65536)?,
                    overhead_bytes: configured.div_ceil(512)
                        + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
                    disk_device: stat.st_dev as u64,
                    disk_bytes: disk,
                    policy: options.resources,
                });
            }
            let roles = record.plan.configuration.attachments.len() as u64;
            let (transfer_roles, native_records) = match &record.storage.root {
                crate::MachineRoot::LinuxOverlay { lower, .. } => {
                    let launch = crate::store::layer_store::LayerStore::from_store(self.clone())
                        .launch_lower(lower)
                        .await?;
                    let plan = crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)?
                        .preflight(roles)?;
                    // State roles, the generated descriptor and each unique
                    // nonempty backing (fsmeta object and pack streams).
                    (
                        5 + plan.unique_occurrences().count() as u64,
                        plan.record_count(),
                    )
                }
                _ => (4, 0),
            };
            let per_child = (3 * transfer_roles)
                .max(native_records + transfer_roles)
                .checked_add(3 * roles + 32)
                .ok_or_else(|| invalid("fork FD peak overflow"))?;
            let fds = (options.children.len() as u64)
                .checked_mul(per_child)
                .and_then(|n| n.checked_add(3 * roles + 32))
                .ok_or_else(|| invalid("fork FD peak overflow"))?;
            inventory.descriptors = fds;
        }
        let mut budget = RestoreBudget::read(&directory)?;
        budget.add_capture(&inventory)?;
        budget.admit_descriptors()?;
        budget.admit_memory(policy, crate::store::capture::available_memory()?)?;
        for path in [&self.images_dir, &self.home.join("machines")] {
            let disk = crate::paths::OwnedDirectory::open_existing_root(path)?
                .ok_or_else(|| invalid("capture budget filesystem disappeared"))?;
            let stat = nix::sys::stat::fstat(disk.fd()).map_err(std::io::Error::from)?;
            let filesystem =
                nix::sys::statvfs::fstatvfs(disk.fd()).map_err(std::io::Error::from)?;
            let available = filesystem
                .blocks_available()
                .checked_mul(filesystem.fragment_size())
                .ok_or_else(|| invalid("capture free space overflow"))?;
            let required = budget
                .disks
                .get(&(stat.st_dev as u64))
                .copied()
                .unwrap_or_default();
            if required > available {
                return Err(crate::storage::StorageError::RestoreBudget {
                    resource: "disk",
                    required,
                    available,
                }
                .into());
            }
        }
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO capture_resource_reservation(operation_id,charge_json) VALUES(?1,jsonb(?2))").bind(owner.to_string()).bind(&json).execute(&mut *tx).await?;
        if let Some(operation) = fork {
            sqlx::query("UPDATE live_fork SET admission_complete=1 WHERE operation_id=?1")
                .bind(operation.to_string())
                .execute(&mut *tx)
                .await?;
        }
        publish_budget(tx, &directory, &budget_name(self, owner)?, &json, |_| {}).await?;
        if let Some(operation) = fork {
            self.fork_event(operation, None, "admission_committed")
                .await?;
        }
        Ok(())
    }

    /// The caller holds admission.lock. Replay transfers only the manager-local
    /// FD charge; RAM, disk, and resource policy remain durably reserved.
    async fn replay_capture_inventory(
        &self,
        owner: Uuid,
        directory: &crate::paths::OwnedDirectory,
        existing: &str,
    ) -> Result<(), LibVmError> {
        let mut retained: CaptureBudgetInventory =
            serde_json::from_str(existing).map_err(invalid)?;
        let mut inventory: CaptureBudgetInventory =
            serde_json::from_str(&self.capture_budget_document(owner).await?).map_err(invalid)?;
        validate_descriptor_charge(retained.descriptor_owner, retained.descriptors)?;
        if inventory.descriptors != 0 {
            inventory.descriptor_owner = Some(DescriptorOwner::current()?);
        }
        retained.descriptor_owner = inventory.descriptor_owner;
        retained.descriptors = inventory.descriptors;
        let name = budget_name(self, owner)?;
        // Replace this operation's old ledger entry, including on same-birth
        // replay, rather than counting the reservation twice.
        let mut budget = RestoreBudget::read_except(directory, Some(&name))?;
        budget.add_capture(&inventory)?;
        budget.admit_descriptors()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(serde_json::to_string(&retained).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        publish_budget(tx, directory, &name, &json, |_| {}).await
    }

    pub(crate) async fn capture_budget_document(&self, owner: Uuid) -> Result<String, LibVmError> {
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_one(&self.pool)
        .await?;
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        let retained:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind IN ('capture','import'))").bind(inventory.capture_id.to_string()).fetch_one(&self.pool).await?;
        if !retained {
            inventory.capture_memory = 0;
            inventory.baseline = None;
            inventory.capture_disks.clear();
        }
        let rows:Vec<String>=sqlx::query_scalar("SELECT json(charge_json) FROM restore_memory_reservation WHERE batch_id=?1 ORDER BY budget_id").bind(owner.to_string()).fetch_all(&self.pool).await?;
        inventory.bound = rows
            .iter()
            .map(|json| serde_json::from_str(json).map_err(invalid))
            .collect::<Result<_, _>>()?;
        if owner != inventory.capture_id {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM live_fork_child WHERE operation_id=?1 AND json_extract(result_json,'$.outcome.kind') IN ('pending','constructing','activating'))").bind(owner.to_string()).fetch_one(&self.pool).await?;
            if !active {
                inventory.descriptor_owner = None;
                inventory.descriptors = 0;
            }
        }
        serde_json::to_string(&inventory).map_err(invalid)
    }

    pub(crate) async fn bind_fork_resources(
        &self,
        cut: &crate::store::fork::VerifiedRestoreCut,
    ) -> Result<(), LibVmError> {
        let operation = cut.record.operation_id;
        let options = self.fork_options(operation).await?;
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&mut *tx)
        .await?;
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        let memory = cut
            .record
            .evidence
            .memory
            .as_ref()
            .ok_or_else(|| invalid("fork cut lacks RAM evidence"))?;
        let ram = cut
            .record
            .files
            .iter()
            .find(|file| file.role == vm_spec::capture::CaptureRole::Ram)
            .ok_or_else(|| invalid("fork cut lacks RAM role"))?;
        for pending in &inventory.pending {
            let lease = pool.lease_deferred(pending.consumer_id)?;
            let (device, inode) = lease.file_identity()?;
            sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'import','staging',?2,?3,jsonb('{}'))").bind(pending.consumer_id.to_string()).bind(device.to_string()).bind(inode.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_cut(operation_id,cut_id) SELECT ?1,cut_id FROM storage_operation_cut WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            let granule = u64::from(memory.page_granule);
            if !(4096..=65536).contains(&granule)
                || !granule.is_power_of_two()
                || options
                    .resources
                    .private_write_allowance
                    .reservation(pending.configured_bytes, granule)?
                    > pending.private_bytes
            {
                return Err(invalid(
                    "sealed RAM granule exceeds the admitted private-memory reservation",
                ));
            }
            let charge = RestoreMemoryCharge {
                baseline_device: ram.device,
                baseline_inode: ram.inode,
                baseline_bytes: ram.length,
                configured_bytes: pending.configured_bytes,
                granule,
                private_bytes: options
                    .resources
                    .private_write_allowance
                    .reservation(pending.configured_bytes, granule)?,
                overhead_bytes: pending.overhead_bytes,
                policy: options.resources,
                disk_device: pending.disk_device,
                disk_bytes: pending.disk_bytes,
                construction_complete: false,
                descriptor_owner: None,
                descriptors: 0,
            };
            charge.validate()?;
            sqlx::query("INSERT INTO restore_memory_reservation(operation_id,budget_id,charge_json,batch_id) VALUES(?1,?1,jsonb(?2),?3)").bind(pending.consumer_id.to_string()).bind(serde_json::to_string(&charge).map_err(invalid)?).bind(operation.to_string()).execute(&mut *tx).await?;
        }
        inventory.pending.clear();
        // Capture scratch remains separate; the final RAM baseline is charged
        // once by the inode-deduplicated generation charges.
        inventory.capture_memory = 16 << 20;
        inventory.baseline = Some(CaptureBaseline::Bound {
            device: cut.record.source_ram.device,
            inode: cut.record.source_ram.inode,
            bytes: cut.record.source_ram.length,
        });
        inventory.capture_disks.clear();
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(serde_json::to_string(&inventory).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let json = self.capture_budget_document(operation).await?;
        directory.write_file_atomic_deferred(&budget_name(self, operation)?, json.as_bytes())?;
        Ok(())
    }

    pub(crate) async fn fork_child_charge(
        &self,
        consumer: Uuid,
    ) -> Result<RestoreMemoryCharge, LibVmError> {
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_memory_reservation WHERE operation_id=?1",
        )
        .bind(consumer.to_string())
        .fetch_one(&self.pool)
        .await?;
        let charge: RestoreMemoryCharge = serde_json::from_str(&json).map_err(invalid)?;
        charge.validate()?;
        Ok(charge)
    }
}

impl crate::store::Store {
    pub(crate) async fn complete_capture_peak(&self, capture: Uuid) -> Result<(), LibVmError> {
        let owner = self.fork_for_capture(capture).await?.unwrap_or(capture);
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: Option<String> = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(json) = json else {
            return Err(invalid(
                "sealed capture lost its authoritative resource inventory",
            ));
        };
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        inventory.capture_disks.clear();
        if owner == capture {
            inventory.descriptor_owner = None;
            inventory.descriptors = 0;
        }
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(serde_json::to_string(&inventory).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        directory.write_file_atomic(
            &budget_name(self, owner)?,
            self.capture_budget_document(owner).await?.as_bytes(),
        )?;
        Ok(())
    }

    pub(crate) async fn refine_capture_boot_inventory(
        &self,
        capture: Uuid,
    ) -> Result<(), LibVmError> {
        let Some(owner) = self.fork_for_capture(capture).await? else {
            return Ok(());
        };
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let json:String=sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(capture.to_string()).fetch_one(&self.pool).await?;
        let record = crate::store::capture::decode_record(&json)?;
        let boot = record
            .captured_boot
            .as_ref()
            .ok_or_else(|| invalid("fork boot inventory is not pinned"))?;
        let mut peak = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        for attachment in &record.plan.configuration.attachments {
            if !attachment.read_only {
                peak = peak
                    .checked_add(attachment.geometry.length)
                    .ok_or_else(|| invalid("fork disk peak overflow"))?;
            }
        }
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        if let crate::BootProfile::LinuxDirect {
            binding:
                crate::BootBinding::Pinned {
                    kernel,
                    base_initramfs,
                    agent,
                    ..
                },
            ..
        } = boot
        {
            for object in [kernel, base_initramfs].into_iter().chain(agent.iter()) {
                peak = peak
                    .checked_add(std::fs::metadata(pool.object_path(object))?.len())
                    .ok_or_else(|| invalid("fork boot peak overflow"))?;
            }
        }
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_one(&self.pool)
        .await?;
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        let mut budget = RestoreBudget::read(&directory)?;
        let mut changed = false;
        for child in &mut inventory.pending {
            if peak > child.disk_bytes {
                let charge = budget.disks.entry(child.disk_device).or_default();
                *charge = charge
                    .checked_add(peak - child.disk_bytes)
                    .ok_or_else(|| invalid("fork boot reservation overflow"))?;
                child.disk_bytes = peak;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        let disk = crate::paths::OwnedDirectory::open_existing_root(&self.home.join("machines"))?
            .ok_or_else(|| invalid("fork destination disappeared"))?;
        let stat = nix::sys::stat::fstat(disk.fd()).map_err(std::io::Error::from)?;
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).map_err(std::io::Error::from)?;
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .ok_or_else(|| invalid("fork disk availability overflow"))?;
        let required = budget
            .disks
            .get(&(stat.st_dev as u64))
            .copied()
            .unwrap_or_default();
        if required > available {
            return Err(crate::storage::StorageError::RestoreBudget {
                resource: "disk",
                required,
                available,
            }
            .into());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(serde_json::to_string(&inventory).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        directory.write_file_atomic(
            &budget_name(self, owner)?,
            self.capture_budget_document(owner).await?.as_bytes(),
        )?;
        Ok(())
    }
}

fn validate_descriptor_charge(
    owner: Option<DescriptorOwner>,
    count: u64,
) -> Result<(), LibVmError> {
    if owner.is_some() != (count != 0)
        || owner.is_some_and(|owner| owner.pid <= 0 || owner.started_at <= 0)
    {
        return Err(invalid(
            "manager descriptor reservation has no exact process owner",
        ));
    }
    Ok(())
}

impl crate::store::Store {
    /// Only a fenced never-submitted/refused command or an explicit native
    /// release of a failed cut permits this reduction while the source lives.
    pub(crate) async fn release_unused_capture_inventory(
        &self,
        capture: Uuid,
    ) -> Result<(), LibVmError> {
        let json:Option<String>=sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture'").bind(capture.to_string()).fetch_optional(&self.pool).await?;
        let Some(json) = json else {
            return Ok(());
        };
        let record = crate::store::capture::decode_record(&json)?;
        if record.evidence.is_some()
            || !matches!(
                record.state,
                crate::store::snapshot_store::CaptureState::Abandoned
                    | crate::store::snapshot_store::CaptureState::Released { snapshot: None }
            )
        {
            return Ok(());
        }
        let intent = self
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
        if !no_submission
            && !matches!(
                record.state,
                crate::store::snapshot_store::CaptureState::Released { snapshot: None }
            )
        {
            return Ok(());
        }
        let owner = self.fork_for_capture(capture).await?.unwrap_or(capture);
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: Option<String> = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(json) = json else {
            return Ok(());
        };
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        let bound: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM restore_memory_reservation WHERE batch_id=?1)",
        )
        .bind(owner.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if bound || !inventory.bound.is_empty() {
            return Err(invalid(
                "unsubmitted capture contradicts bound child generations",
            ));
        }
        inventory.capture_memory = 0;
        inventory.baseline = None;
        inventory.capture_disks.clear();
        inventory.descriptor_owner = None;
        inventory.descriptors = 0;
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(serde_json::to_string(&inventory).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        directory.write_file_atomic(
            &budget_name(self, owner)?,
            self.capture_budget_document(owner).await?.as_bytes(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::restore::{RestoreBudget, RestoreMemoryCharge};

    struct CheckpointRequestFixture {
        capture: crate::store::capture::tests::Fixture,
        consumer: crate::store::snapshot_store::SnapshotConsumer,
        request: vm_spec::restore::RestoreRequest,
        _files: [std::fs::File; 5],
    }

    async fn checkpoint_request_fixture() -> CheckpointRequestFixture {
        use crate::storage::pool::StoragePool;
        use crate::store::capture::tests::{fixture, seal};
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        use vm_spec::capture::{CaptureConfiguration, Sha256Digest};
        use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

        let fixture = fixture().await;
        let snapshots = &fixture.snapshots;
        let (sealed, sealed_evidence) = seal(&fixture);
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                sealed.path(),
                fixture.reservation.record.alias.clone(),
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume(&crate::SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("fixture must be an execution checkpoint");
        };
        let ram = consumer
            .open_stream(&pool, &execution.memory.stream, execution.memory.length)
            .unwrap();
        let files = [
            ram,
            pool.open_object(&execution.layout).unwrap(),
            pool.open_object(&execution.execution).unwrap(),
            pool.open_object(&execution.devices).unwrap(),
            std::fs::File::open(sealed.path().join(vm_spec::capture::CAPTURE_RAM_MAP_FILE))
                .unwrap(),
        ];
        let digests = [
            Sha256Digest::from_bytes(*execution.memory.stream.as_bytes()),
            Sha256Digest::from_bytes(*execution.layout.as_bytes()),
            Sha256Digest::from_bytes(*execution.execution.as_bytes()),
            Sha256Digest::from_bytes(*execution.devices.as_bytes()),
            sealed_evidence
                .inventory
                .iter()
                .find(|entry| entry.role == vm_spec::capture::CaptureRole::RamMap)
                .unwrap()
                .sha256
                .unwrap(),
        ];
        let objects: Vec<_> = files
            .iter()
            .zip(RestoreObjectRole::ALL)
            .zip(digests)
            .map(|((file, role), identity)| {
                let metadata = file.metadata().unwrap();
                RestoreObject {
                    role,
                    fd: file.as_raw_fd(),
                    file_device: metadata.dev(),
                    file_inode: metadata.ino(),
                    length: metadata.len(),
                    identity,
                }
            })
            .collect();
        let evidence = snapshots
            .restore_evidence(&consumer, &pool)
            .unwrap()
            .evidence;
        let request = RestoreRequest {
            version: vm_spec::restore::RESTORE_REQUEST_VERSION,
            checkpoint: Sha256Digest::from_bytes(*info.id.as_bytes()),
            activation_id: vm_spec::lifecycle::LiveId::parse(&uuid::Uuid::new_v4().to_string())
                .unwrap(),
            freeze_operation_id: evidence.freeze_operation_id.clone().unwrap(),
            start_paused: true,
            configuration: CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
                .unwrap(),
            evidence,
            objects: objects.try_into().unwrap(),
            lowers: Vec::new(),
            network: None,
            ssh_trusted_ca: None,
            hook: None,
        };
        request.validate().unwrap();
        CheckpointRequestFixture {
            capture: fixture,
            consumer,
            request,
            _files: files,
        }
    }

    #[tokio::test]
    async fn restore_consumer_initializes_first_machine_parent_without_bypassing_admission() {
        use crate::storage::pool::StoragePool;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let CheckpointRequestFixture {
            capture: fixture,
            consumer,
            request,
            _files,
        } = checkpoint_request_fixture().await;
        let snapshots = &fixture.snapshots;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let policy = crate::RestoreResourcePolicy {
            memory: crate::RestoreMemoryPolicy::AllowOvercommit,
            ..Default::default()
        };
        let disk_peak = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + 512;

        // Keep the source intact but unavailable at the destination path. Every
        // restore input is now authenticated in the pool, as after acquisition.
        let machines = snapshots.store.home.join("machines");
        let source = snapshots.store.home.join("captured-source");
        std::fs::rename(&machines, &source).unwrap();
        let external = tempfile::tempdir().unwrap();
        symlink(external.path(), &machines).unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, &request, disk_peak, 32, policy)
            .await
            .is_err());
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
        std::fs::remove_file(&machines).unwrap();
        std::fs::write(&machines, b"not a directory").unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, &request, disk_peak, 32, policy)
            .await
            .is_err());
        std::fs::remove_file(&machines).unwrap();
        std::fs::create_dir(&machines).unwrap();
        std::fs::set_permissions(&machines, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, &request, disk_peak, 32, policy)
            .await
            .is_err());
        assert_eq!(std::fs::metadata(&machines).unwrap().mode() & 0o7777, 0o755);
        std::fs::remove_dir(&machines).unwrap();

        let error = snapshots
            .reserve_restore_resources(&consumer, &request, u64::MAX / 2, 32, policy)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::Storage(crate::storage::StorageError::RestoreBudget {
                resource: "disk",
                ..
            })
        ));
        let metadata = std::fs::metadata(&machines).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert!(std::fs::read_dir(&machines).unwrap().next().is_none());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_memory_reservation")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "unsafe paths and disk refusal publish no charge");

        let charge = snapshots
            .reserve_restore_resources(&consumer, &request, disk_peak, 32, policy)
            .await
            .unwrap();
        assert_eq!(charge.disk_device, metadata.dev());
        assert_eq!(charge.disk_bytes, disk_peak);
        assert_eq!(std::fs::metadata(&machines).unwrap().ino(), metadata.ino());
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_memory_reservation WHERE operation_id=?1",
        )
        .bind(consumer.operation_id.to_string())
        .fetch_one(&snapshots.store.pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RestoreMemoryCharge>(&json).unwrap(),
            charge
        );
        std::fs::remove_dir(&machines).unwrap();
        std::fs::rename(&source, &machines).unwrap();
        snapshots
            .store
            .finish_stopped_operation(consumer.operation_id)
            .await
            .unwrap();
        drop(consumer);
        snapshots
            .store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        snapshots.store.reconcile_restore_budget().await.unwrap();
    }

    #[tokio::test]
    async fn import_capacity_is_shared_and_detached_workers_keep_their_charge_until_recovery() {
        use crate::paths::{LocalPaths, OwnedDirectory};
        use crate::store::restore::{budget_directory, CaptureBudgetInventory};
        use crate::store::Store;

        let temporary = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temporary.path().join("home")))
            .await
            .unwrap();
        let _pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
        let disk = OwnedDirectory::open_existing_root(&store.images_dir)
            .unwrap()
            .unwrap();
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).unwrap();
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .unwrap();
        // Real capacity, no test admission override or allocation of a huge
        // payload: either charge fits, but their simultaneous peak cannot.
        let bytes = available / 4 * 3;
        assert!(bytes > 0);
        let (outcomes_tx, mut outcomes) = tokio::sync::mpsc::channel(2);
        let (done_tx, mut done) = tokio::sync::mpsc::channel(2);
        let mut workers = Vec::new();
        let mut releases = Vec::new();
        let mut operations = Vec::new();
        for _ in 0..2 {
            let (operation, lease) = store
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            operations.push(operation);
            let owner = store.clone();
            let outcomes = outcomes_tx.clone();
            let done = done_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            releases.push(release_tx);
            let runtime = tokio::runtime::Handle::current();
            workers.push(tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    let result = runtime.block_on(owner.reserve_import_space(operation, bytes));
                    runtime
                        .block_on(outcomes.send((operation, result)))
                        .unwrap();
                    release_rx.recv().unwrap();
                    // Process/worker loss deliberately leaves the durable
                    // reservation, exactly as an interrupted import does.
                    drop(lease);
                    runtime.block_on(done.send(())).unwrap();
                })
                .await
                .unwrap();
            }));
        }
        let first = outcomes.recv().await.unwrap();
        let second = outcomes.recv().await.unwrap();
        let (winner, refusal) = match (first, second) {
            ((winner, Ok(())), (_, Err(error))) | ((_, Err(error)), (winner, Ok(()))) => {
                (winner, error)
            }
            other => panic!("expected one admitted owner and one capacity refusal: {other:?}"),
        };
        assert!(matches!(
            refusal,
            crate::LibVmError::DiskImport(error)
                if matches!(*error, crate::DiskImportError::Capacity { required, available }
                    if required == bytes * 2 && required > available)
        ));
        let winner_index = operations.iter().position(|id| *id == winner).unwrap();
        workers[winner_index].abort();
        store.recover_image_cache().await.unwrap();
        store.reconcile_restore_budget().await.unwrap();
        let document = store.capture_budget_document(winner).await.unwrap();
        let inventory: CaptureBudgetInventory = serde_json::from_str(&document).unwrap();
        assert_eq!(inventory.capture_disks.len(), 1);
        assert_eq!(inventory.capture_disks[0].bytes, bytes);
        let ledger = budget_directory(&store).unwrap();
        assert_eq!(
            RestoreBudget::read(&ledger)
                .unwrap()
                .disks
                .values()
                .sum::<u64>(),
            bytes,
            "recovery must not release a live detached blocking owner's reservation"
        );
        for release in releases {
            release.send(()).unwrap();
        }
        done.recv().await.unwrap();
        done.recv().await.unwrap();
        store.recover_image_cache().await.unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM capture_resource_reservation")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0);
        assert!(RestoreBudget::read(&ledger).unwrap().disks.is_empty());
        for worker in workers {
            let _ = worker.await;
        }
    }

    #[tokio::test]
    async fn import_capacity_refusal_and_completion_leave_no_reservation() {
        use crate::paths::LocalPaths;
        use crate::store::restore::budget_directory;
        use crate::store::Store;

        let temporary = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temporary.path().join("home")))
            .await
            .unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let result = store.reserve_import_space(operation, u64::MAX).await;
        assert!(matches!(
            result,
            Err(crate::LibVmError::DiskImport(error))
                if matches!(*error, crate::DiskImportError::Capacity { required: u64::MAX, .. })
        ));
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM capture_resource_reservation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "refused admission never owns capacity");
        store
            .reserve_import_space(operation, 1 << 20)
            .await
            .unwrap();
        store.release_import_space(operation).await.unwrap();
        let ledger = budget_directory(&store).unwrap();
        assert!(RestoreBudget::read(&ledger).unwrap().disks.is_empty());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM capture_resource_reservation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    fn charge(inode: u64, disk_device: u64) -> RestoreMemoryCharge {
        let bytes = 1 << 20;
        RestoreMemoryCharge {
            baseline_device: 1,
            baseline_inode: inode,
            baseline_bytes: bytes,
            configured_bytes: bytes,
            granule: 4096,
            private_bytes: bytes / 4,
            overhead_bytes: bytes.div_ceil(512) + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
            policy: Default::default(),
            disk_device,
            disk_bytes: vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
            construction_complete: false,
            descriptor_owner: None,
            descriptors: 0,
        }
    }

    fn capture_inventory(
        input: &RestoreMemoryCharge,
    ) -> crate::store::restore::CaptureBudgetInventory {
        crate::store::restore::CaptureBudgetInventory {
            capture_id: uuid::Uuid::new_v4(),
            capture_memory: 16 << 20,
            baseline: Some(crate::store::restore::CaptureBaseline::Bound {
                device: input.baseline_device,
                inode: input.baseline_inode,
                bytes: input.baseline_bytes,
            }),
            capture_disks: Vec::new(),
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: None,
            descriptors: 0,
        }
    }

    #[tokio::test]
    async fn capture_replay_rebinds_manager_birth_and_refuses_fd_exhaustion_before_publication() {
        use crate::paths::OwnedDirectory;
        use crate::store::restore::{CaptureBudgetInventory, DescriptorOwner, PendingForkCharge};

        let root = tempfile::tempdir().unwrap();
        let home = OwnedDirectory::open_root(&root.path().join("home")).unwrap();
        let ledger = OwnedDirectory::open_root(&root.path().join("ledger")).unwrap();
        let store = crate::store::Store::open(&home.path().join("state.db"))
            .await
            .unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        sqlx::query("UPDATE storage_operation SET kind='capture' WHERE operation_id=?1")
            .bind(operation.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let current = DescriptorOwner::current().unwrap();
        let previous = DescriptorOwner {
            pid: current.pid,
            started_at: current.started_at + 1,
        };
        let input = charge(10, 3);
        let mut inventory = capture_inventory(&input);
        inventory.capture_id = operation;
        inventory.descriptor_owner = Some(previous);
        inventory.descriptors = 1;
        inventory.pending.push(PendingForkCharge {
            consumer_id: uuid::Uuid::new_v4(),
            configured_bytes: input.configured_bytes,
            private_bytes: input.private_bytes,
            overhead_bytes: input.overhead_bytes,
            disk_device: input.disk_device,
            disk_bytes: input.disk_bytes,
            policy: crate::RestoreResourcePolicy {
                memory: crate::RestoreMemoryPolicy::AllowOvercommit,
                ..input.policy
            },
        });
        let name = crate::store::restore::budget_name(&store, operation).unwrap();
        let _admission = crate::storage::locks::blocking(
            &ledger,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let json = serde_json::to_string(&inventory).unwrap();
        sqlx::query("INSERT INTO capture_resource_reservation(operation_id,charge_json) VALUES(?1,jsonb(?2))")
            .bind(operation.to_string())
            .bind(&json)
            .execute(&store.pool)
            .await
            .unwrap();
        ledger.write_file_atomic(&name, json.as_bytes()).unwrap();
        let before = RestoreBudget::read(&ledger).unwrap();
        assert_eq!(
            before.descriptors, 0,
            "a different birth does not own this manager's FDs"
        );
        store
            .replay_capture_inventory(operation, &ledger, &json)
            .await
            .unwrap();
        let persisted: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        inventory.descriptor_owner = Some(current);
        let expected = serde_json::to_value(&inventory).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&persisted).unwrap(),
            expected
        );
        let published: CaptureBudgetInventory =
            serde_json::from_reader(ledger.open_file(&name).unwrap().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(published).unwrap(), expected);
        let after = RestoreBudget::read(&ledger).unwrap();
        assert_eq!(after.descriptors, 1);
        assert_eq!(after.memory, before.memory);
        assert_eq!(after.disks, before.disks);

        // A same-birth replay at the exact limit must replace its old charge.
        // Counting it twice would refuse admission (or overflow) here.
        let (_, hard) =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE).unwrap();
        inventory.descriptors = hard - crate::storage::limits::FD_RESERVED_OVERHEAD;
        let full = serde_json::to_string(&inventory).unwrap();
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(&full)
        .execute(&store.pool)
        .await
        .unwrap();
        ledger.write_file_atomic(&name, full.as_bytes()).unwrap();
        store
            .replay_capture_inventory(operation, &ledger, &full)
            .await
            .unwrap();
        assert_eq!(
            RestoreBudget::read(&ledger).unwrap().descriptors,
            inventory.descriptors
        );

        // Even explicit RAM overcommit cannot bypass this manager's FD limit.
        // Exceed the hard limit, since production admission may raise the soft limit.
        inventory.descriptor_owner = Some(previous);
        inventory.descriptors = hard
            .saturating_sub(crate::storage::limits::FD_RESERVED_OVERHEAD)
            .saturating_add(1);
        let refused = serde_json::to_string(&inventory).unwrap();
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(&refused)
        .execute(&store.pool)
        .await
        .unwrap();
        ledger.write_file_atomic(&name, refused.as_bytes()).unwrap();
        let error = store
            .replay_capture_inventory(operation, &ledger, &refused)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("file descriptor budget"),
            "{error}"
        );
        let unchanged: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        let expected = serde_json::to_value(&inventory).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&unchanged).unwrap(),
            expected
        );
        let published: CaptureBudgetInventory =
            serde_json::from_reader(ledger.open_file(&name).unwrap().unwrap()).unwrap();
        assert_eq!(serde_json::to_value(published).unwrap(), expected);
        assert_eq!(RestoreBudget::read(&ledger).unwrap().descriptors, 0);
        store.close().await;
    }

    #[test]
    fn fork_batch_transfer_preserves_shared_admission_without_reacquiring_child_capacity() {
        use crate::store::restore::PendingForkCharge;
        let input = charge(10, 3);
        let mut inventory = capture_inventory(&input);
        inventory.pending = (0..17)
            .map(|_| PendingForkCharge {
                consumer_id: uuid::Uuid::new_v4(),
                configured_bytes: input.configured_bytes,
                private_bytes: input
                    .policy
                    .private_write_allowance
                    .reservation(input.configured_bytes, 65536)
                    .unwrap(),
                overhead_bytes: input.overhead_bytes,
                disk_device: input.disk_device,
                disk_bytes: input.disk_bytes,
                policy: input.policy,
            })
            .collect();
        let mut admitted = RestoreBudget::default();
        admitted.add_capture(&inventory).unwrap();
        inventory.pending.clear();
        inventory.bound = vec![input.clone(); 17];
        let mut bound = RestoreBudget::default();
        bound.add_capture(&inventory).unwrap();
        assert_eq!(bound.memory, admitted.memory);
        assert_eq!(bound.disks, admitted.disks);
        assert_eq!(bound.baselines.len(), 1);
        inventory.bound.pop();
        let mut retired = RestoreBudget::default();
        retired.add_capture(&inventory).unwrap();
        assert_eq!(
            bound.memory - retired.memory,
            input.private_bytes + input.overhead_bytes
        );
        assert_eq!(
            retired.baselines.len(),
            1,
            "source and remaining children still own the baseline"
        );
    }

    #[test]
    fn capture_and_standalone_restore_share_one_baseline_and_cross_device_copies_charge_two() {
        let input = charge(10, 3);
        let inventory = capture_inventory(&input);
        let mut shared = RestoreBudget::default();
        shared.add_capture(&inventory).unwrap();
        shared.add(&input).unwrap();
        assert_eq!(
            shared.memory,
            inventory.capture_memory
                + input.baseline_bytes
                + input.private_bytes
                + input.overhead_bytes
        );
        let mut copied = input.clone();
        copied.baseline_device += 1;
        shared.add(&copied).unwrap();
        assert_eq!(shared.baselines.len(), 2);
        assert_eq!(
            shared.memory,
            inventory.capture_memory
                + 2 * (input.baseline_bytes + input.private_bytes + input.overhead_bytes)
        );
        let mut source_gone = RestoreBudget::default();
        source_gone.add(&input).unwrap();
        assert_eq!(
            source_gone.baselines.len(),
            1,
            "a child owns its baseline independently of the source"
        );
    }

    #[test]
    fn pending_fork_inventory_rejects_undercharge_and_unknown_baseline_identity() {
        use crate::store::restore::{CaptureBaseline, PendingForkCharge};
        let input = charge(10, 3);
        let mut inventory = capture_inventory(&input);
        inventory.pending.push(PendingForkCharge {
            consumer_id: uuid::Uuid::new_v4(),
            configured_bytes: input.configured_bytes,
            private_bytes: input.private_bytes - 1,
            overhead_bytes: input.overhead_bytes,
            disk_device: input.disk_device,
            disk_bytes: input.disk_bytes,
            policy: input.policy,
        });
        assert!(RestoreBudget::default().add_capture(&inventory).is_err());
        inventory.pending.clear();
        inventory.baseline = Some(CaptureBaseline::Pending {
            capture_id: uuid::Uuid::new_v4(),
            bytes: input.baseline_bytes,
        });
        assert!(RestoreBudget::default().add_capture(&inventory).is_err());
        inventory.baseline = Some(CaptureBaseline::Bound {
            device: 1,
            inode: 0,
            bytes: input.baseline_bytes,
        });
        assert!(RestoreBudget::default().add_capture(&inventory).is_err());
    }

    #[test]
    fn descriptor_budget_is_scoped_to_the_exact_manager_birth_not_all_homes() {
        let owner = crate::store::restore::DescriptorOwner::current().unwrap();
        let mut inventory = capture_inventory(&charge(10, 3));
        inventory.descriptor_owner = Some(owner);
        inventory.descriptors = 100;
        let mut manager = RestoreBudget {
            manager: Some(owner),
            ..RestoreBudget::default()
        };
        manager.add_capture(&inventory).unwrap();
        assert_eq!(manager.descriptors, 100);
        inventory.descriptor_owner = Some(crate::store::restore::DescriptorOwner {
            pid: owner.pid,
            started_at: owner.started_at.checked_add(1).unwrap(),
        });
        manager.add_capture(&inventory).unwrap();
        assert_eq!(
            manager.descriptors, 100,
            "a reused PID or another manager does not consume this process's RLIMIT"
        );
        inventory.descriptor_owner = None;
        assert!(
            manager.add_capture(&inventory).is_err(),
            "unowned descriptor reservations are invalid"
        );
    }

    #[test]
    fn restore_started_releases_construction_peak_without_releasing_mapping_memory() {
        let mut input = charge(10, 3);
        let mut before = RestoreBudget::default();
        before.add(&input).unwrap();
        input.construction_complete = true;
        input.disk_bytes = 0;
        let mut after = RestoreBudget::default();
        after.add(&input).unwrap();
        assert_eq!(before.memory, after.memory);
        assert_eq!(after.disks[&3], 0);
        input.construction_complete = false;
        assert!(input.validate().is_err());
    }

    #[test]
    fn restore_budget_charges_shared_baseline_once_and_private_writes_per_generation() {
        let input = charge(10, 3);
        let mut budget = RestoreBudget::default();
        budget.add(&input).unwrap();
        budget.add(&input).unwrap();
        assert_eq!(
            budget.memory,
            input.baseline_bytes + 2 * (input.private_bytes + input.overhead_bytes)
        );
        assert_eq!(budget.disks[&3], 2 * input.disk_bytes);
        let other = charge(11, 4);
        budget.add(&other).unwrap();
        assert_eq!(
            budget.memory,
            2 * input.baseline_bytes + 3 * (input.private_bytes + input.overhead_bytes)
        );
        assert_eq!(budget.disks[&4], other.disk_bytes);
    }

    #[test]
    fn restore_budget_rejects_undercharge_and_replaced_baseline_geometry() {
        let input = charge(10, 3);
        let mut changed = input.clone();
        changed.private_bytes -= 1;
        assert!(RestoreBudget::default().add(&changed).is_err());
        changed = input.clone();
        changed.baseline_bytes -= 4096;
        let mut budget = RestoreBudget::default();
        budget.add(&input).unwrap();
        assert!(budget.add(&changed).is_err());
    }

    #[test]
    fn restore_budget_rejects_arithmetic_overflow() {
        let mut input = charge(10, 3);
        input.disk_bytes = u64::MAX;
        let mut budget = RestoreBudget::default();
        budget.add(&input).unwrap();
        assert!(budget.add(&input).is_err());
    }

    #[test]
    fn restore_private_reservation_rounds_up_without_undercharging() {
        for percent in [0, 1, 25, 33, 99, 100] {
            let allowance = crate::PrivateWriteAllowance::try_from(percent).unwrap();
            for bytes in [0_u64, 1, 4096, (1 << 20) + 1, 1 << 40] {
                let charge = allowance.reservation(bytes, 4096).unwrap();
                assert!(
                    u128::from(charge) >= (u128::from(bytes) * u128::from(percent)).div_ceil(100)
                );
                assert_eq!(charge % 4096, 0);
                assert!(
                    u128::from(charge)
                        < (u128::from(bytes) * u128::from(percent)).div_ceil(100) + 4096
                );
            }
        }
        assert!(crate::PrivateWriteAllowance::try_from(101).is_err());
        assert!(crate::PrivateWriteAllowance::try_from(u32::MAX).is_err());
        let allowance = crate::PrivateWriteAllowance::try_from(100).unwrap();
        assert!(allowance.reservation(u64::MAX, 4096).is_err());
        assert!(allowance.reservation(1, 0).is_err());
        assert!(allowance.reservation(1, 3).is_err());
    }

    #[test]
    fn restore_memory_overcommit_requires_explicit_policy_and_keeps_all_charges() {
        let input = charge(10, 3);
        assert_eq!(u32::from(input.policy.private_write_allowance), 25);
        assert_eq!(input.policy.memory, crate::RestoreMemoryPolicy::Reserved);
        let mut budget = RestoreBudget::default();
        budget.add(&input).unwrap();
        let required = budget.memory;
        assert!(budget
            .admit_memory(input.policy.memory, required - 1)
            .is_err());
        budget.admit_memory(input.policy.memory, required).unwrap();
        budget
            .admit_memory(crate::RestoreMemoryPolicy::AllowOvercommit, 0)
            .unwrap();
        assert_eq!(budget.memory, required);
        assert_eq!(budget.disks[&3], input.disk_bytes);
    }

    fn backed_charge(
        root: &std::path::Path,
        disk: &crate::paths::OwnedDirectory,
    ) -> RestoreMemoryCharge {
        use std::os::unix::fs::MetadataExt;
        let ram = std::fs::metadata(root.join("ram")).unwrap();
        let mut input = charge(ram.ino(), std::fs::metadata(disk.path()).unwrap().dev());
        input.baseline_device = ram.dev();
        input.baseline_bytes = ram.len();
        input
    }

    #[tokio::test]
    async fn restore_policy_survives_journal_reconciliation_and_never_bypasses_disk_admission() {
        use crate::paths::OwnedDirectory;
        let root = tempfile::tempdir().unwrap();
        let home = OwnedDirectory::open_root(&root.path().join("home")).unwrap();
        std::fs::File::create(root.path().join("ram"))
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        let ledger = OwnedDirectory::open_root(&root.path().join("ledger")).unwrap();
        let store = crate::store::Store::open(&home.path().join("state.db"))
            .await
            .unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let mut input = backed_charge(root.path(), &home);
        input.policy = crate::RestoreResourcePolicy {
            private_write_allowance: crate::PrivateWriteAllowance::try_from(33).unwrap(),
            memory: crate::RestoreMemoryPolicy::AllowOvercommit,
        };
        input.private_bytes = input
            .policy
            .private_write_allowance
            .reservation(input.configured_bytes, input.granule)
            .unwrap();
        store
            .reserve_restore_charge(operation, &input, &home, &ledger)
            .await
            .unwrap();
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_memory_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RestoreMemoryCharge>(&json).unwrap(),
            input
        );
        let name = crate::store::restore::budget_name(&store, operation).unwrap();
        // Reconciliation restores the authoritative journal policy, not defaults.
        ledger
            .write_file_atomic(
                &name,
                &serde_json::to_vec(&charge(input.baseline_inode, input.disk_device)).unwrap(),
            )
            .unwrap();
        store.reconcile_restore_budget_in(&ledger).await.unwrap();
        let restored: RestoreMemoryCharge =
            serde_json::from_reader(ledger.open_file(&name).unwrap().unwrap()).unwrap();
        assert_eq!(restored, input);
        restored.validate().unwrap();
        let mut malformed = serde_json::to_value(&restored).unwrap();
        malformed["policy"]["privateWriteAllowance"] = serde_json::json!(101);
        assert!(serde_json::from_value::<RestoreMemoryCharge>(malformed).is_err());
        let mut undercharged = input.clone();
        undercharged.private_bytes -= 4096;
        assert!(undercharged.validate().is_err());
        let (other, _other_lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        input.disk_bytes = u64::MAX - vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES;
        let error = store
            .reserve_restore_charge(other, &input, &home, &ledger)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("disk"), "{error}");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_memory_reservation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            count, 1,
            "disk refusal must precede reservation publication"
        );
        store.close().await;
    }

    struct CrashWriter(std::process::Child);

    impl Drop for CrashWriter {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn restore_budget_crash_writer() {
        use crate::paths::{AtomicWritePhase, OwnedDirectory};
        use std::io::Write;
        let Some(root) = std::env::var_os("SILO_RESTORE_BUDGET_CRASH_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let boundary = std::env::var("SILO_RESTORE_BUDGET_CRASH_BOUNDARY").unwrap();
        let phase = match boundary.as_str() {
            "staged" => AtomicWritePhase::Staged,
            "synced" => AtomicWritePhase::Synced,
            "published" => AtomicWritePhase::Published,
            _ => panic!("unknown boundary"),
        };
        let home = OwnedDirectory::open_root(&root.join("home-a")).unwrap();
        let ledger = OwnedDirectory::open_root(&root.join("ledger")).unwrap();
        let store = crate::store::Store::open(&home.path().join("state.db"))
            .await
            .unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let mut input = backed_charge(&root, &home);
        let checkpoint = |observed| {
            if observed == phase {
                let mut ready =
                    std::os::unix::net::UnixStream::connect(root.join("ready.sock")).unwrap();
                ready.write_all(&[1]).unwrap();
                loop {
                    std::thread::park();
                }
            }
        };
        if std::env::var("SILO_RESTORE_BUDGET_CRASH_UPDATE").unwrap() == "yes" {
            store
                .reserve_restore_charge(operation, &input, &home, &ledger)
                .await
                .unwrap();
            let _admission = crate::storage::locks::blocking(
                &ledger,
                "admission.lock",
                nix::fcntl::FlockArg::LockExclusive,
            )
            .unwrap();
            input.construction_complete = true;
            input.disk_bytes = 0;
            let json = serde_json::to_string(&input).unwrap();
            // Exercise the completion ordering: SQL releases construction peak
            // first, then the same atomic publisher replaces the old full charge.
            let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
            sqlx::query(
                "UPDATE restore_memory_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
            )
            .bind(operation.to_string())
            .bind(&json)
            .execute(&mut *tx)
            .await
            .unwrap();
            crate::store::restore::publish_budget(
                tx,
                &ledger,
                &crate::store::restore::budget_name(&store, operation).unwrap(),
                &json,
                checkpoint,
            )
            .await
            .unwrap();
        } else {
            store
                .reserve_restore_charge_with(operation, &input, &home, &ledger, checkpoint)
                .await
                .unwrap();
        }
        panic!("writer did not stop at requested publication boundary");
    }

    #[tokio::test]
    async fn interrupted_restore_budget_publication_admits_other_home_without_crashed_home_recovery(
    ) {
        use crate::paths::OwnedDirectory;
        use std::io::Read;
        for update in [false, true] {
            for boundary in ["staged", "synced", "published"] {
                let root = tempfile::tempdir().unwrap();
                std::fs::File::create(root.path().join("ram"))
                    .unwrap()
                    .set_len(1 << 20)
                    .unwrap();
                let home = OwnedDirectory::open_root(&root.path().join("home-b")).unwrap();
                let ledger = OwnedDirectory::open_root(&root.path().join("ledger")).unwrap();
                let store = crate::store::Store::open(&home.path().join("state.db"))
                    .await
                    .unwrap();
                let listener =
                    std::os::unix::net::UnixListener::bind(root.path().join("ready.sock")).unwrap();
                listener.set_nonblocking(true).unwrap();
                let mut child = CrashWriter(
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "store::restore::tests::restore_budget_crash_writer",
                            "--nocapture",
                        ])
                        .env("SILO_RESTORE_BUDGET_CRASH_ROOT", root.path())
                        .env("SILO_RESTORE_BUDGET_CRASH_BOUNDARY", boundary)
                        .env(
                            "SILO_RESTORE_BUDGET_CRASH_UPDATE",
                            if update { "yes" } else { "no" },
                        )
                        .spawn()
                        .unwrap(),
                );
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
                let mut ready = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                child.0.try_wait().unwrap().is_none(),
                                "writer exited before {update}/{boundary}"
                            );
                            assert!(
                                std::time::Instant::now() < deadline,
                                "writer missed boundary"
                            );
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("readiness accept: {error}"),
                    }
                };
                ready
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut byte = [0];
                ready.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [1]);
                child.0.kill().unwrap();
                assert!(!child.0.wait().unwrap().success());
                let input = backed_charge(root.path(), &home);
                let visible = update || boundary == "published";
                let before = {
                    let _admission = crate::storage::locks::blocking(
                        &ledger,
                        "admission.lock",
                        nix::fcntl::FlockArg::LockExclusive,
                    )
                    .unwrap();
                    RestoreBudget::read(&ledger).unwrap()
                };
                assert_eq!(
                    before.memory,
                    if visible {
                        input.baseline_bytes + input.private_bytes + input.overhead_bytes
                    } else {
                        0
                    }
                );
                let old_disk = if update && boundary != "published" {
                    input.disk_bytes
                } else if update || !visible {
                    0
                } else {
                    input.disk_bytes
                };
                assert_eq!(
                    before
                        .disks
                        .get(&input.disk_device)
                        .copied()
                        .unwrap_or_default(),
                    old_disk
                );
                assert!(
                    !ledger.path().join(".atomic-write").exists(),
                    "abandoned staging must be reclaimed"
                );
                // Home A is intentionally never opened again. This is a real
                // home B journal reservation through the production admission path.
                let (operation, _lease) = store
                    .begin_stopped_operation("import", &[], &[])
                    .await
                    .unwrap();
                store
                    .reserve_restore_charge(operation, &input, &home, &ledger)
                    .await
                    .unwrap();
                store.reconcile_restore_budget_in(&ledger).await.unwrap();
                let after = {
                    let _admission = crate::storage::locks::blocking(
                        &ledger,
                        "admission.lock",
                        nix::fcntl::FlockArg::LockExclusive,
                    )
                    .unwrap();
                    RestoreBudget::read(&ledger).unwrap()
                };
                assert_eq!(
                    after.memory,
                    input.baseline_bytes
                        + (1 + u64::from(visible)) * (input.private_bytes + input.overhead_bytes)
                );
                assert_eq!(after.disks[&input.disk_device], old_disk + input.disk_bytes);
                store.close().await;
            }
        }
    }

    #[test]
    fn restore_budget_never_ignores_malformed_authoritative_records() {
        let root = tempfile::tempdir().unwrap();
        let ledger = crate::paths::OwnedDirectory::open_root(&root.path().join("ledger")).unwrap();
        ledger.write_file_atomic("broken.json", b"{").unwrap();
        assert!(RestoreBudget::read(&ledger).is_err());
        ledger.remove_tree("broken.json").unwrap();
        ledger.write_file_atomic("unknown", b"{}").unwrap();
        assert!(RestoreBudget::read(&ledger).is_err());
    }
    #[tokio::test]
    async fn corrupt_ram_restore_reports_authentication_and_rolls_back_child_and_reservation() {
        use crate::machine::builder::{publish_restored_child, ChildConstruction};
        use crate::machine::restore::{storage_from_snapshot, RestoreAuthentication};
        use crate::machine::stopped::{FencedSource, PrivateSource};
        use crate::storage::pool::StoragePool;
        use crate::store::snapshot_store::SnapshotConsumer;
        use std::os::unix::fs::{FileExt, PermissionsExt};

        let CheckpointRequestFixture {
            capture: fixture,
            consumer: initial_consumer,
            request,
            _files,
        } = checkpoint_request_fixture().await;
        let snapshots = &fixture.snapshots;
        let reference = crate::SnapshotRef::Id(initial_consumer.info.id);
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &initial_consumer.record.capture
        else {
            panic!("fixture must be an execution checkpoint");
        };
        let ram_path = pool.stream_path(&execution.memory.stream);
        drop(initial_consumer);
        snapshots
            .store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();

        let reader = std::fs::File::open(&ram_path).unwrap();
        let mut first = [0];
        reader.read_exact_at(&mut first, 0).unwrap();
        std::fs::set_permissions(&ram_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&ram_path)
            .unwrap();
        writer.write_all_at(&[first[0] ^ 1], 0).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        std::fs::set_permissions(&ram_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let paths = crate::paths::LocalPaths::new(snapshots.store.home.clone());
        let runtime = crate::Runtime::from_store(
            paths.clone(),
            snapshots.store.clone(),
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
            crate::runtime::components::test_components(paths.home()),
            None,
        )
        .await
        .unwrap();
        let machines = snapshots.store.home.join("machines");
        let before = std::fs::read_dir(&machines)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();

        for fail_copy in [false, true] {
            let consumer: SnapshotConsumer = snapshots.consume_shape(&reference).await.unwrap();
            let shape = snapshots.verify_closure_shape(&consumer).await.unwrap();
            let root = &consumer.record.root;
            let stream = shape
                .open_copy_source(&pool, &root.stream.stream, root.geometry.length)
                .unwrap();
            let path = crate::PrivatePath::new("root.raw").unwrap();
            let source = if fail_copy {
                // Force a real construction error as well. The authentication
                // error must still win the scoped join deterministically.
                PrivateSource::Fenced(FencedSource {
                    path,
                    file: stream.file().try_clone().unwrap(),
                    length: stream.length() + 512,
                })
            } else {
                PrivateSource::Authenticated { path, stream }
            };
            let descriptor_peak = 64 + shape.retained_descriptors();
            snapshots
                .reserve_restore_resources(
                    &consumer,
                    &request,
                    vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + root.geometry.length,
                    descriptor_peak,
                    crate::RestoreResourcePolicy {
                        memory: crate::RestoreMemoryPolicy::AllowOvercommit,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let operation = consumer.operation_id;
            let name = format!("corrupt-ram-child-{fail_copy}");
            let result = publish_restored_child(
                &runtime,
                ChildConstruction {
                    name: name.clone(),
                    configuration: consumer.record.configuration.clone(),
                    storage: storage_from_snapshot(&consumer.record, consumer.info.id).unwrap(),
                    sources: vec![source],
                    operation_id: operation,
                    shared_qualification: None,
                },
                uuid::Uuid::new_v4(),
                Some(RestoreAuthentication::new(snapshots.clone(), shape)),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("corrupt RAM must reject construction"),
            };
            assert!(
                matches!(&error, crate::LibVmError::Storage(crate::storage::StorageError::ContentMismatch(path)) if path == &ram_path),
                "restore must report RAM authentication, not copying: {error:?}",
            );
            drop(consumer);
            snapshots
                .store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            let after = std::fs::read_dir(&machines)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                after, before,
                "failed authentication leaked a private child tree"
            );
            let children: i64 =
                sqlx::query_scalar("SELECT count(*) FROM machine_config WHERE name=?1")
                    .bind(name)
                    .fetch_one(&snapshots.store.pool)
                    .await
                    .unwrap();
            assert_eq!(children, 0);
            let retained: i64 = sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM storage_operation WHERE operation_id=?1) +
                        (SELECT count(*) FROM restore_memory_reservation WHERE operation_id=?1)",
            )
            .bind(operation.to_string())
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
            assert_eq!(
                retained, 0,
                "failed construction retained its owner or reservation"
            );
        }
    }
}

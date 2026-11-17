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
    LocalCut { id: Uuid },
}

impl RestoreIdentity {
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
    pub resources: RestoreResourceCharge,
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
    pub(crate) fn current() -> Result<Self, LibVmError> {
        let pid = i32::try_from(std::process::id()).map_err(invalid)?;
        let started_at = utils::process::start_time(pid)?
            .ok_or_else(|| invalid("manager process birth identity is unavailable"))?;
        Ok(Self { pid, started_at })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreResourceCharge {
    pub disk_device: u64,
    pub disk_bytes: u64,
    pub construction_complete: bool,
    pub descriptor_owner: Option<DescriptorOwner>,
    pub descriptors: u64,
}

impl RestoreResourceCharge {
    fn validate(&self) -> Result<(), LibVmError> {
        validate_descriptor_charge(self.descriptor_owner, self.descriptors)?;
        if (self.construction_complete && self.disk_bytes != 0)
            || (!self.construction_complete
                && self.disk_bytes < vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES)
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
    pub disk_device: u64,
    pub disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BoundForkCharge {
    pub consumer_id: Uuid,
    pub resources: RestoreResourceCharge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureBudgetInventory {
    pub capture_id: Uuid,
    pub capture_disks: Vec<crate::store::snapshot_store::CaptureSpaceCharge>,
    pub pending: Vec<PendingForkCharge>,
    pub bound: Vec<BoundForkCharge>,
    pub descriptor_owner: Option<DescriptorOwner>,
    pub descriptors: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BudgetDocument {
    Restore(RestoreResourceCharge),
    Capture(CaptureBudgetInventory),
}
#[derive(Default)]
struct RestoreBudget {
    disks: std::collections::BTreeMap<u64, u64>,
    manager: Option<DescriptorOwner>,
    descriptors: u64,
}

impl RestoreBudget {
    fn add(&mut self, charge: &RestoreResourceCharge) -> Result<(), LibVmError> {
        charge.validate()?;
        self.add_descriptors(charge.descriptor_owner, charge.descriptors)?;
        let disk = self.disks.entry(charge.disk_device).or_default();
        *disk = disk
            .checked_add(charge.disk_bytes)
            .ok_or_else(|| invalid("restore disk reservation overflow"))?;
        Ok(())
    }

    fn read(
        store: &crate::store::Store,
        directory: &crate::paths::OwnedDirectory,
    ) -> Result<Self, LibVmError> {
        Self::read_except(store, directory, None)
    }

    fn read_except(
        store: &crate::store::Store,
        directory: &crate::paths::OwnedDirectory,
        excluded: Option<&str>,
    ) -> Result<Self, LibVmError> {
        let entries = reclaim_budget_orphans(store, directory)?;
        let mut budget = Self {
            manager: Some(DescriptorOwner::current()?),
            ..Self::default()
        };
        let mut bytes = Vec::new();
        let mut homes = std::collections::BTreeMap::new();
        for name in entries {
            if excluded == Some(name.as_str()) {
                continue;
            }
            let owners = budget_live_owners(directory, &name, &mut homes)
                .map_err(|error| budget_document_error(directory, &name, error))?;
            if !owners.producer
                && !owners.capture
                && !owners.native_capture
                && owners.children.is_empty()
            {
                continue;
            }
            let file = directory
                .open_file(&name)?
                .ok_or_else(|| invalid("restore budget record disappeared"))?;
            bytes.clear();
            file.take((16 << 20) + 1).read_to_end(&mut bytes)?;
            let admission = if bytes.len() > 16 << 20 {
                Err(invalid("resource budget inventory exceeds 16 MiB"))
            } else {
                serde_json::from_slice::<BudgetDocument>(&bytes)
                    .map_err(invalid)
                    .and_then(|document| match document {
                        BudgetDocument::Restore(charge) => budget.add(&charge),
                        BudgetDocument::Capture(mut inventory) => {
                            if !owners.producer {
                                inventory.pending.clear();
                                if !owners.capture && !owners.native_capture {
                                    inventory.capture_disks.clear();
                                }
                                if !owners.capture {
                                    inventory.descriptor_owner = None;
                                    inventory.descriptors = 0;
                                }
                                inventory
                                    .bound
                                    .retain(|child| owners.children.contains(&child.consumer_id));
                            }
                            budget.add_capture(&inventory)
                        }
                    })
            };
            admission.map_err(|error| budget_document_error(directory, &name, error))?;
        }
        Ok(budget)
    }

    fn add_capture(&mut self, inventory: &CaptureBudgetInventory) -> Result<(), LibVmError> {
        self.add_descriptors(inventory.descriptor_owner, inventory.descriptors)?;
        if inventory.capture_id.is_nil() {
            return Err(invalid("capture budget identity is nil"));
        }
        for disk in &inventory.capture_disks {
            let total = self.disks.entry(disk.device).or_default();
            *total = total
                .checked_add(disk.bytes)
                .ok_or_else(|| invalid("capture disk budget overflow"))?;
        }
        for child in &inventory.pending {
            if child.consumer_id.is_nil()
                || child.disk_bytes < vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
            {
                return Err(invalid("pending fork reservation is malformed"));
            }
            let total = self.disks.entry(child.disk_device).or_default();
            *total = total
                .checked_add(child.disk_bytes)
                .ok_or_else(|| invalid("fork disk budget overflow"))?;
        }
        for child in &inventory.bound {
            if child.consumer_id.is_nil() {
                return Err(invalid("bound fork reservation has no consumer"));
            }
            self.add(&child.resources)?;
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
}

impl RestoreIntent {
    pub(crate) fn validate(&self) -> Result<(), LibVmError> {
        if self.request.ssh_trusted_ca.is_some() {
            self.request.validate().map_err(invalid)?;
        } else {
            self.request.validate_for_inspection().map_err(invalid)?;
        }
        self.resources.validate()?;
        let mut inspected = self.request.clone();
        inspected.network = None;
        inspected.ssh_trusted_ca = None;
        // Inspection precedes allocation and therefore cannot bind child inodes.
        inspected.disk_tracking_seeds.clear();
        let inspected =
            crate::machine::restore::inspection_request(inspected, self.network_attachment)?;
        let bytes = serde_json::to_vec(&inspected).map_err(invalid)?;
        self.inspection
            .validate_against(&bytes, &inspected)
            .map_err(invalid)?;
        let authority_matches = match (&self.checkpoint, &self.request.authority) {
            (
                RestoreIdentity::Snapshot { id },
                vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { checkpoint, .. },
            ) => id.as_bytes() == checkpoint.as_bytes(),
            (
                RestoreIdentity::LocalCut { id },
                vm_spec::restore::RestoreAuthority::OwnedLocalCut { cut },
            ) => id.to_string() == cut.capture_id.as_str(),
            _ => false,
        };
        if self.consumer_operation.is_nil() || !authority_matches {
            return Err(invalid("restore intent contradicts checkpoint identity"));
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
                    memory.binding.live_state_schema
                        == execution.compatibility_profile.live_state_schema,
                    "live state schema",
                ),
                (
                    memory.binding.architecture == execution.compatibility_profile.architecture,
                    "architecture",
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

    pub(crate) async fn reserve_restore_resources(
        &self,
        consumer: &SnapshotConsumer,
        disk_peak: u64,
        descriptor_peak: u64,
    ) -> Result<RestoreResourceCharge, LibVmError> {
        // Imported checkpoints can be restored before this home has ever owned a
        // machine. Create only the private container, not a child or disk, before
        // measuring and reserving space on its actual filesystem.
        let home = crate::paths::OwnedDirectory::open_existing_root(&self.store.home)?
            .ok_or_else(|| invalid("restore destination home disappeared"))?;
        let disk = home.ensure_dir("machines")?;
        let disk_stat = nix::sys::stat::fstat(disk.fd()).map_err(std::io::Error::from)?;
        #[cfg(target_os = "macos")]
        let disk_device = disk_stat.st_dev as u64;
        #[cfg(not(target_os = "macos"))]
        let disk_device = disk_stat.st_dev;
        let charge = RestoreResourceCharge {
            disk_device,
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
        charge: &RestoreResourceCharge,
        disk: &crate::paths::OwnedDirectory,
        directory: &crate::paths::OwnedDirectory,
    ) -> Result<(), LibVmError> {
        self.reserve_restore_charge_with(operation, charge, disk, directory, |_| {})
            .await
    }

    async fn reserve_restore_charge_with(
        &self,
        operation: Uuid,
        charge: &RestoreResourceCharge,
        disk: &crate::paths::OwnedDirectory,
        directory: &crate::paths::OwnedDirectory,
        checkpoint: impl FnMut(crate::paths::AtomicWritePhase),
    ) -> Result<(), LibVmError> {
        let _admission = crate::storage::locks::blocking(
            directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let mut budget = RestoreBudget::read(self, directory)?;
        budget.add(charge)?;
        budget.admit_descriptors()?;
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
            return Err(crate::storage::StorageError::RestoreDiskBudget {
                required: disk_required,
                available,
            }
            .into());
        }
        let json = serde_json::to_string(charge).map_err(invalid)?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO restore_resource_reservation(operation_id,budget_id,charge_json) VALUES(?1,?1,jsonb(?2))")
            .bind(operation.to_string()).bind(&json).execute(&mut *tx).await?;
        publish_budget(
            self,
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
            capture_disks: vec![crate::store::snapshot_store::CaptureSpaceCharge {
                device: stat.st_dev as u64,
                bytes,
            }],
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: None,
            descriptors: 0,
        };
        let mut budget = RestoreBudget::read(self, &directory)?;
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
            self,
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
pub(crate) fn budget_directory(
    store: &crate::store::Store,
) -> Result<crate::paths::OwnedDirectory, LibVmError> {
    // Test-linked public stores and CLI subprocesses must share only their
    // fixture home's ledger. Cross-home tests explicitly select one directory.
    #[cfg(any(test, feature = "test-isolated-resource-budget"))]
    if let Some(directory) = &store.resource_budget_directory {
        return crate::paths::OwnedDirectory::open_root(directory);
    }
    let _ = store;
    crate::paths::OwnedDirectory::open_root(&user_budget_directory_path())
}

fn user_budget_directory_path() -> std::path::PathBuf {
    let parent = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    Path::new(parent).join(format!(
        "silo-resource-budget-{}",
        nix::unistd::geteuid().as_raw()
    ))
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetHomeAnchor {
    schema: u32,
    home: std::path::PathBuf,
    state_device: u64,
    state_inode: u64,
    leases: std::collections::BTreeMap<String, Vec<BudgetLeaseOwner>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BudgetLeaseOwner {
    operation: Uuid,
    device: u64,
    inode: u64,
    scope: BudgetLeaseScope,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum BudgetLeaseScope {
    Producer,
    Capture,
    NativeCapture,
    Child { consumer_id: Uuid },
}

#[derive(sqlx::FromRow)]
struct BudgetLeaseRow {
    budget: String,
    operation: String,
    device: String,
    inode: String,
    scope: i64,
    consumer: Option<String>,
}

/// The caller holds admission.lock, including when no charges remain.
pub(crate) async fn write_budget_anchor(
    store: &crate::store::Store,
    directory: &crate::paths::OwnedDirectory,
) -> Result<(), LibVmError> {
    let home = std::fs::canonicalize(&store.home)?;
    let state = std::fs::metadata(home.join("state.db"))?;
    let mut leases = std::collections::BTreeMap::<String, Vec<BudgetLeaseOwner>>::new();
    // Resolve aliases in our own journal, never open another home's SQLite
    // database. Native writers inherit launch leases, so caller death alone
    // cannot make an in-flight capture or restore look idle.
    let rows = sqlx::query_as::<_, BudgetLeaseRow>(
        "SELECT r.budget_id AS budget,o.operation_id AS operation,
                o.file_device AS device,o.file_inode AS inode,-1 AS scope,NULL AS consumer
         FROM restore_resource_reservation r JOIN storage_operation o ON o.operation_id=r.operation_id
         WHERE r.batch_id IS NULL
         UNION
         SELECT c.operation_id,o.operation_id,o.file_device,o.file_inode,-1,NULL
         FROM capture_resource_reservation c JOIN storage_operation o ON o.operation_id=c.operation_id
         UNION
         SELECT c.operation_id,o.operation_id,o.file_device,o.file_inode,-2,NULL
         FROM capture_resource_reservation c JOIN storage_operation o
         ON o.operation_id=json_extract(c.charge_json,'$.captureId')
         UNION
         SELECT c.operation_id,l.operation_id,l.file_device,l.file_inode,-3,NULL
         FROM capture_resource_reservation c
         JOIN storage_operation s ON s.operation_id=json_extract(c.charge_json,'$.captureId') AND s.kind='capture'
         JOIN storage_operation l ON l.operation_id=json_extract(s.record_json,'$.launchOperationId')
         WHERE json_array_length(c.charge_json,'$.captureDisks')>0
         UNION
         SELECT r.batch_id,o.operation_id,o.file_device,o.file_inode,0,r.budget_id
         FROM restore_resource_reservation r JOIN storage_operation o ON o.operation_id=r.operation_id
         WHERE r.batch_id IS NOT NULL",
    )
    .fetch_all(&store.pool)
    .await?;
    for row in rows {
        let name = budget_name(store, Uuid::parse_str(&row.budget).map_err(invalid)?)?;
        let scope = match row.scope {
            -1 => BudgetLeaseScope::Producer,
            -2 => BudgetLeaseScope::Capture,
            -3 => BudgetLeaseScope::NativeCapture,
            0 => BudgetLeaseScope::Child {
                consumer_id: Uuid::parse_str(
                    row.consumer
                        .as_deref()
                        .ok_or_else(|| invalid("bound resource lease has no consumer"))?,
                )
                .map_err(invalid)?,
            },
            _ => return Err(invalid("unknown resource budget lease scope")),
        };
        leases.entry(name).or_default().push(BudgetLeaseOwner {
            operation: Uuid::parse_str(&row.operation).map_err(invalid)?,
            device: row.device.parse::<u64>().map_err(invalid)?,
            inode: row.inode.parse::<u64>().map_err(invalid)?,
            scope,
        });
    }
    let anchor = BudgetHomeAnchor {
        schema: 2,
        home,
        state_device: state.dev(),
        state_inode: state.ino(),
        leases,
    };
    let name = format!("{}-{}-home.json", anchor.state_device, anchor.state_inode);
    let bytes = serde_json::to_vec(&anchor).map_err(invalid)?;
    if read_budget_file(directory, &name)?.as_deref() == Some(bytes.as_slice()) {
        // Atomic publication syncs the file before rename. Reconfirm its
        // directory entry after an interrupted writer, but do not replace an
        // identical anchor merely because a charge amount changed.
        return directory.sync();
    }
    directory.write_file_atomic(&name, &bytes)
}

fn budget_file_prefix(name: &str) -> Result<&str, LibVmError> {
    let mut parts = name.splitn(3, '-');
    parts
        .next()
        .ok_or_else(|| invalid("resource budget device is missing"))?
        .parse::<u64>()
        .map_err(invalid)?;
    parts
        .next()
        .ok_or_else(|| invalid("resource budget inode is missing"))?
        .parse::<u64>()
        .map_err(invalid)?;
    let suffix = parts
        .next()
        .ok_or_else(|| invalid("resource budget owner is missing"))?;
    Ok(&name[..name.len() - suffix.len()])
}

fn read_budget_file(
    directory: &crate::paths::OwnedDirectory,
    name: &str,
) -> Result<Option<Vec<u8>>, LibVmError> {
    let Some(file) = directory.open_file(name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take((16 << 20) + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn budget_document_error(
    directory: &crate::paths::OwnedDirectory,
    name: &str,
    error: LibVmError,
) -> LibVmError {
    let anchor = budget_file_prefix(name)
        .and_then(|prefix| {
            read_budget_file(directory, &format!("{prefix}home.json"))?
                .ok_or_else(|| invalid("resource budget home anchor is missing"))
        })
        .and_then(|bytes| serde_json::from_slice::<BudgetHomeAnchor>(&bytes).map_err(invalid));
    let owner = match anchor {
        Ok(anchor) => format!("Silo home {}", anchor.home.display()),
        Err(_) => format!("home owning ledger record {name}"),
    };
    invalid(format!(
        "resource budget record {name} for {owner} is malformed: {error}; remove that home, or delete its stale budget files under {}",
        directory.path().display(),
    ))
}

fn budget_home_is_live(directory: &crate::paths::OwnedDirectory, prefix: &str) -> bool {
    let Ok(Some(bytes)) = read_budget_file(directory, &format!("{prefix}home.json")) else {
        return false;
    };
    // An anchor only proves existence; a charge is authority. A malformed
    // anchor cannot prove liveness, but malformed charges of live homes refuse
    // admission rather than silently releasing an authoritative reservation.
    let Ok(anchor) = serde_json::from_slice::<BudgetHomeAnchor>(&bytes) else {
        return false;
    };
    if bytes.len() > 16 << 20
        || anchor.schema != 2
        || !anchor.home.is_absolute()
        || prefix != format!("{}-{}-", anchor.state_device, anchor.state_inode)
    {
        return false;
    }
    std::fs::metadata(anchor.home.join("state.db"))
        .is_ok_and(|state| state.dev() == anchor.state_device && state.ino() == anchor.state_inode)
}

#[derive(Default)]
struct BudgetLiveOwners {
    producer: bool,
    capture: bool,
    native_capture: bool,
    children: std::collections::BTreeSet<Uuid>,
}

/// A free lease stops admission charges, not journal ownership. Native capture
/// writers and each bound child retain only their own peaks, never abandoned
/// siblings' reservations. The caller holds admission.lock.
fn budget_live_owners(
    directory: &crate::paths::OwnedDirectory,
    name: &str,
    homes: &mut std::collections::BTreeMap<String, Option<BudgetHomeAnchor>>,
) -> Result<BudgetLiveOwners, LibVmError> {
    let unknown = || BudgetLiveOwners {
        producer: true,
        ..BudgetLiveOwners::default()
    };
    let prefix = budget_file_prefix(name)?;
    let anchor = match homes.entry(prefix.to_owned()) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => {
            let anchor = read_budget_file(directory, &format!("{prefix}home.json"))?
                .map(|bytes| serde_json::from_slice::<BudgetHomeAnchor>(&bytes).map_err(invalid))
                .transpose()?;
            entry.insert(anchor)
        }
    };
    let Some(anchor) = anchor else {
        return Ok(unknown());
    };
    let Some(owners) = anchor.leases.get(name) else {
        // Missing evidence cannot authorize release of a published charge.
        return Ok(unknown());
    };
    let mut live = BudgetLiveOwners::default();
    let leases =
        crate::paths::OwnedDirectory::open_existing_root(&anchor.home.join("images/locks/leases"))?
            .ok_or_else(|| invalid("resource budget operation leases are missing"))?;
    for owner in owners {
        let file = leases
            .open_file(&format!("{}.lease", owner.operation))?
            .ok_or_else(|| invalid("resource budget operation lease is missing"))?;
        let state = file.metadata()?;
        if (state.dev(), state.ino()) != (owner.device, owner.inode) {
            return Err(invalid("resource budget operation lease inode changed"));
        }
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(probe) => drop(probe),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => match owner.scope {
                BudgetLeaseScope::Producer => live.producer = true,
                BudgetLeaseScope::Capture => live.capture = true,
                BudgetLeaseScope::NativeCapture => live.native_capture = true,
                BudgetLeaseScope::Child { consumer_id } => {
                    live.children.insert(consumer_id);
                }
            },
            Err((_, error)) => return Err(std::io::Error::from(error).into()),
        }
    }
    Ok(live)
}

/// Every ledger reader calls this while holding admission.lock.
fn reclaim_budget_orphans(
    store: &crate::store::Store,
    directory: &crate::paths::OwnedDirectory,
) -> Result<Vec<String>, LibVmError> {
    let own_prefix = budget_prefix(store)?;
    let mut homes = std::collections::BTreeMap::<String, Vec<String>>::new();
    for name in budget_files(directory)? {
        homes
            .entry(budget_file_prefix(&name)?.to_owned())
            .or_default()
            .push(name);
    }
    let mut live = Vec::new();
    for (prefix, names) in homes {
        if prefix == own_prefix || budget_home_is_live(directory, &prefix) {
            live.extend(
                names
                    .into_iter()
                    .filter(|name| !name.ends_with("-home.json")),
            );
            continue;
        }
        let mut released = RestoreBudget::default();
        let mut charges = 0;
        let mut malformed_charges = 0;
        for name in &names {
            if !name.ends_with("-home.json") {
                charges += 1;
                let result = match read_budget_file(directory, name) {
                    Ok(Some(bytes)) if bytes.len() <= 16 << 20 => {
                        match serde_json::from_slice::<BudgetDocument>(&bytes) {
                            Ok(BudgetDocument::Restore(charge)) => released.add(&charge),
                            Ok(BudgetDocument::Capture(inventory)) => {
                                released.add_capture(&inventory)
                            }
                            Err(error) => Err(invalid(error)),
                        }
                    }
                    _ => Err(invalid(
                        "orphan resource budget record is unreadable or oversized",
                    )),
                };
                if result.is_err() {
                    malformed_charges += 1;
                }
            }
            directory.remove_tree(name)?;
        }
        directory.sync()?;
        // Corrupt orphan charges cannot veto reclamation or supply an exact
        // released-byte total. Report unknown rather than inventing a zero.
        let disk_bytes = (malformed_charges == 0).then(|| {
            released
                .disks
                .values()
                .map(|bytes| u128::from(*bytes))
                .sum::<u128>()
        });
        tracing::debug!(
            %prefix,
            entries = names.len(),
            charges,
            malformed_charges,
            ?disk_bytes,
            "reclaimed resource budget for a missing home"
        );
    }
    Ok(live)
}

/// SQL owns the reservation before publication. An interrupted initial publish
/// has no child yet; an interrupted release retains the old conservative charge.
async fn publish_budget(
    store: &crate::store::Store,
    tx: sqlx::Transaction<'_, sqlx::Sqlite>,
    directory: &crate::paths::OwnedDirectory,
    name: &str,
    json: &str,
    checkpoint: impl FnMut(crate::paths::AtomicWritePhase),
) -> Result<(), LibVmError> {
    tx.commit().await?;
    write_budget_anchor(store, directory).await?;
    directory.write_file_atomic_with(name, json.as_bytes(), checkpoint)
}

fn budget_files(directory: &crate::paths::OwnedDirectory) -> Result<Vec<String>, LibVmError> {
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

fn budget_entries(directory: &crate::paths::OwnedDirectory) -> Result<Vec<String>, LibVmError> {
    Ok(budget_files(directory)?
        .into_iter()
        .filter(|name| !name.ends_with("-home.json"))
        .collect())
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
        if json.len() > crate::store::operation_store::MAX_RESTORE_LAUNCH_RECORD_BYTES {
            return Err(invalid(
                "restore construction exceeds its control-record bound",
            ));
        }
        let result = sqlx::query("UPDATE restore_resource_reservation SET construction_json=jsonb(?2) WHERE operation_id=?1 AND construction_json IS NULL")
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
            "SELECT json(o.record_json),r.budget_id,r.batch_id FROM storage_operation o JOIN restore_resource_reservation r ON r.operation_id=o.operation_id JOIN machine_state s ON s.machine_id=o.machine_id WHERE o.operation_id=?1 AND o.run_id=?2 AND o.kind='launch' AND s.status='running' AND json_extract(s.state_json,'$.runId')=?2"
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
        intent.resources.construction_complete = true;
        intent.resources.disk_bytes = 0;
        intent.resources.descriptor_owner = None;
        intent.resources.descriptors = 0;
        let charge = serde_json::to_string(&intent.resources).map_err(invalid)?;
        let encoded = crate::store::operation_store::encode(&record)?;
        sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation.to_string())
            .bind(encoded)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE restore_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .bind(&charge)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        // Batch reductions accumulate SQL-first. The outer reconciliation
        // publishes one complete inventory, not N quadratic aggregate rewrites.
        if batch.is_none() {
            write_budget_anchor(self, &directory).await?;
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
                "SELECT o.operation_id,o.run_id FROM storage_operation o JOIN restore_resource_reservation r ON r.operation_id=o.operation_id JOIN machine_state s ON s.machine_id=o.machine_id WHERE o.kind='launch' AND json_extract(o.record_json,'$.restore') IS NOT NULL AND json_extract(o.record_json,'$.restore.resources.constructionComplete')=0 AND s.status='running' AND json_extract(s.state_json,'$.runId')=o.run_id ORDER BY o.operation_id LIMIT 256"
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
        write_budget_anchor(self, directory).await?;
        let mut authoritative = std::collections::BTreeSet::new();
        let standalone:Vec<(String,String)>=sqlx::query_as("SELECT budget_id,json(charge_json) FROM restore_resource_reservation WHERE batch_id IS NULL").fetch_all(&self.pool).await?;
        for (id, json) in standalone {
            let charge: RestoreResourceCharge = serde_json::from_str(&json).map_err(invalid)?;
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
        expected.disk_tracking_seeds = request.disk_tracking_seeds.clone();
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

fn fork_disk_peak(
    record: &crate::store::snapshot_store::CaptureRecord,
    boot: &crate::BootProfile,
    pool: &crate::storage::pool::StoragePool,
) -> Result<u64, LibVmError> {
    // Use the same source allocation sample as capture staging, including on
    // replay and boot refinement. A child's private copy preserves sparsity.
    let mut peak = record.disk_allocations.values().try_fold(
        vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
        |bytes, allocated| {
            bytes
                .checked_add(*allocated)
                .ok_or_else(|| invalid("fork disk peak overflow"))
        },
    )?;
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
    Ok(peak)
}

impl crate::store::Store {
    /// Replace allocated staging credit with only future publication writes.
    pub(crate) async fn reserve_capture_publication(
        &self,
        record: &crate::store::snapshot_store::CaptureRecord,
        bytes: u64,
    ) -> Result<(), LibVmError> {
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let owner = record.fork_operation_id.unwrap_or(record.capture_id);
        let json = self.capture_budget_document(owner).await?;
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        if inventory.descriptors != 0 {
            inventory.descriptor_owner = Some(DescriptorOwner::current()?);
        }
        let pool = crate::paths::OwnedDirectory::open_existing_root(&self.images_dir)?
            .ok_or_else(|| invalid("publication filesystem disappeared"))?;
        let device = nix::sys::stat::fstat(pool.fd())
            .map_err(std::io::Error::from)?
            .st_dev as u64;
        inventory.capture_disks =
            vec![crate::store::snapshot_store::CaptureSpaceCharge { device, bytes }];
        let name = budget_name(self, owner)?;
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(&json)
        .execute(&mut *tx)
        .await?;
        publish_budget(self, tx, &directory, &name, &json, |_| {}).await?;
        let mut budget = RestoreBudget::read_except(self, &directory, Some(&name))?;
        budget.add_capture(&inventory)?;
        budget.admit_descriptors()?;
        self.admit_capture_disks(&budget, "publication deferred", Some(record), Some(bytes))
    }

    /// Shared cross-home admission. No capture command can precede successful
    /// publication of this complete inventory under the restore admission lock.
    pub(crate) async fn reserve_capture_inventory(
        &self,
        record: &crate::store::snapshot_store::CaptureRecord,
        initial_lease: Option<&crate::storage::locks::StorageLock>,
    ) -> Result<(), LibVmError> {
        let directory = budget_directory(self)?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let fork = self.fork_for_capture(record.capture_id).await?;
        if fork != record.fork_operation_id {
            return Err(invalid("capture fork owner contradicts its reservation"));
        }
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
            capture_disks: record.disk_charges.clone(),
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: Some(DescriptorOwner::current()?),
            descriptors: crate::store::capture::capture_descriptor_budget(
                &record.plan.configuration,
            )?,
        };
        if let Some(operation) = fork {
            let options = self.fork_options(operation).await?;
            let parent =
                crate::paths::OwnedDirectory::open_existing_root(&self.home.join("machines"))?
                    .ok_or_else(|| invalid("fork destination parent missing"))?;
            let stat = nix::sys::stat::fstat(parent.fd()).map_err(std::io::Error::from)?;
            let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
            let disk = fork_disk_peak(record, &record.storage.boot, &pool)?;
            for child in self.fork_children(operation).await? {
                inventory.pending.push(PendingForkCharge {
                    consumer_id: child.consumer_id,
                    disk_device: stat.st_dev as u64,
                    disk_bytes: disk,
                });
            }
            let roles = record.plan.configuration.attachments.len() as u64;
            let (transfer_roles, native_records) = match &record.storage.root {
                crate::MachineRoot::LinuxOverlay { lower, .. } => {
                    let launch = crate::store::layer_store::LayerStore::from_store(self.clone())
                        .hold_lower(lower)
                        .await?;
                    let plan = crate::storage::vmdk::FlatLowerPlan::new(&launch.occurrences)?
                        .preflight(roles)?;
                    // State roles, the generated descriptor and each unique
                    // nonempty backing (fsmeta object and pack streams).
                    (
                        6 + plan.unique_occurrences().count() as u64,
                        plan.record_count(),
                    )
                }
                _ => (5, 0),
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
        let mut budget = RestoreBudget::read(self, &directory)?;
        budget.add_capture(&inventory)?;
        budget.admit_descriptors()?;
        self.admit_capture_disks(&budget, "pre-freeze admission", Some(record), None)?;
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let registered: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='capture')")
            .bind(record.capture_id.to_string()).fetch_one(&mut *tx).await?;
        if !registered {
            let lease = initial_lease
                .ok_or_else(|| invalid("capture registration requires its held lease"))?;
            let (device, inode) = lease.file_identity()?;
            if pool.operation_lease_identity(record.capture_id)? != (device, inode) {
                return Err(invalid(
                    "capture lease inode changed before admission commit",
                ));
            }
            crate::store::capture::register_capture(&mut tx, record, device, inode).await?;
        }
        sqlx::query("INSERT INTO capture_resource_reservation(operation_id,charge_json) VALUES(?1,jsonb(?2))").bind(owner.to_string()).bind(&json).execute(&mut *tx).await?;
        if let Some(operation) = fork {
            sqlx::query("UPDATE live_fork SET admission_complete=1 WHERE operation_id=?1")
                .bind(operation.to_string())
                .execute(&mut *tx)
                .await?;
        }
        publish_budget(
            self,
            tx,
            &directory,
            &budget_name(self, owner)?,
            &json,
            |_| {},
        )
        .await?;
        if let Some(operation) = fork {
            self.fork_event(operation, None, "admission_committed")
                .await?;
        }
        Ok(())
    }

    fn admit_capture_disks(
        &self,
        budget: &RestoreBudget,
        phase: &'static str,
        record: Option<&crate::store::snapshot_store::CaptureRecord>,
        remaining: Option<u64>,
    ) -> Result<(), LibVmError> {
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
                let device = stat.st_dev as u64;
                let staging_here = remaining.is_none()
                    && record.is_some_and(|record| {
                        record
                            .disk_charges
                            .first()
                            .is_some_and(|charge| charge.device == device)
                    });
                let ram_staging = if staging_here {
                    record.map(|record| record.plan.ram_bytes).unwrap_or(0)
                } else {
                    0
                };
                let disk_staging = if staging_here {
                    record
                        .map(|record| record.disk_allocations.values().sum())
                        .unwrap_or(0)
                } else {
                    0
                };
                let own = match remaining {
                    Some(bytes)
                        if record.is_some_and(|record| {
                            record
                                .disk_charges
                                .last()
                                .is_some_and(|charge| charge.device == device)
                        }) =>
                    {
                        bytes
                    }
                    Some(_) => 0,
                    None => record
                        .map(|record| {
                            record
                                .disk_charges
                                .iter()
                                .filter(|charge| charge.device == device)
                                .map(|charge| charge.bytes)
                                .sum::<u64>()
                        })
                        .unwrap_or(0),
                };
                let reserves = if staging_here {
                    vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
                } else {
                    0
                };
                return Err(crate::storage::StorageError::CaptureDiskBudget {
                    phase,
                    filesystem: path.to_path_buf(),
                    required,
                    available,
                    ram_staging,
                    disk_staging,
                    publication: own.saturating_sub(ram_staging + disk_staging + reserves),
                    reserves,
                    other: required.saturating_sub(own),
                }
                .into());
            }
        }
        Ok(())
    }

    /// The caller holds admission.lock. A resumed publisher must re-admit disk
    /// peaks as well as manager-local descriptors before it can write again.
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
        let mut budget = RestoreBudget::read_except(self, directory, Some(&name))?;
        budget.add_capture(&inventory)?;
        budget.admit_descriptors()?;
        let json: Option<String> = sqlx::query_scalar("SELECT json(record_json) FROM storage_operation WHERE operation_id=?1 AND kind='capture' AND json_type(record_json,'$.plan')='object'")
            .bind(inventory.capture_id.to_string()).fetch_optional(&self.pool).await?;
        let record = json
            .as_deref()
            .map(crate::store::capture::decode_record)
            .transpose()?;
        self.admit_capture_disks(&budget, "dispatch refusal", record.as_ref(), None)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .bind(serde_json::to_string(&retained).map_err(invalid)?)
        .execute(&mut *tx)
        .await?;
        let json = serde_json::to_string(&inventory).map_err(invalid)?;
        publish_budget(self, tx, directory, &name, &json, |_| {}).await
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
            inventory.capture_disks.clear();
        }
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT budget_id,json(charge_json) FROM restore_resource_reservation WHERE batch_id=?1 ORDER BY budget_id",
        )
        .bind(owner.to_string())
        .fetch_all(&self.pool)
        .await?;
        inventory.bound = rows
            .iter()
            .map(|(id, json)| {
                Ok(BoundForkCharge {
                    consumer_id: Uuid::parse_str(id).map_err(invalid)?,
                    resources: serde_json::from_str(json).map_err(invalid)?,
                })
            })
            .collect::<Result<_, LibVmError>>()?;
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
        for pending in &inventory.pending {
            let lease = pool.lease_deferred(pending.consumer_id)?;
            let (device, inode) = lease.file_identity()?;
            sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'import','staging',?2,?3,jsonb('{}'))").bind(pending.consumer_id.to_string()).bind(device.to_string()).bind(inode.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO storage_operation_cut(operation_id,cut_id) SELECT ?1,cut_id FROM storage_operation_cut WHERE operation_id=?2").bind(pending.consumer_id.to_string()).bind(operation.to_string()).execute(&mut *tx).await?;
            let charge = RestoreResourceCharge {
                disk_device: pending.disk_device,
                disk_bytes: pending.disk_bytes,
                construction_complete: false,
                descriptor_owner: None,
                descriptors: 0,
            };
            charge.validate()?;
            sqlx::query("INSERT INTO restore_resource_reservation(operation_id,budget_id,charge_json,batch_id) VALUES(?1,?1,jsonb(?2),?3)").bind(pending.consumer_id.to_string()).bind(serde_json::to_string(&charge).map_err(invalid)?).bind(operation.to_string()).execute(&mut *tx).await?;
        }
        inventory.pending.clear();
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
        write_budget_anchor(self, &directory).await?;
        directory.write_file_atomic_deferred(&budget_name(self, operation)?, json.as_bytes())?;
        Ok(())
    }

    pub(crate) async fn fork_child_charge(
        &self,
        consumer: Uuid,
    ) -> Result<RestoreResourceCharge, LibVmError> {
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_resource_reservation WHERE operation_id=?1",
        )
        .bind(consumer.to_string())
        .fetch_one(&self.pool)
        .await?;
        let charge: RestoreResourceCharge = serde_json::from_str(&json).map_err(invalid)?;
        charge.validate()?;
        Ok(charge)
    }
}

impl crate::store::Store {
    pub(crate) async fn complete_capture_peak(
        &self,
        record: &crate::store::snapshot_store::CaptureRecord,
    ) -> Result<(), LibVmError> {
        let capture = record.capture_id;
        let fork = self.fork_for_capture(capture).await?;
        if fork != record.fork_operation_id {
            return Err(invalid("capture fork owner contradicts its reservation"));
        }
        let owner = fork.unwrap_or(capture);
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
        write_budget_anchor(self, &directory).await?;
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
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let peak = fork_disk_peak(&record, boot, &pool)?;
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(owner.to_string())
        .fetch_one(&self.pool)
        .await?;
        let mut inventory: CaptureBudgetInventory = serde_json::from_str(&json).map_err(invalid)?;
        let mut budget = RestoreBudget::read(self, &directory)?;
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
            return Err(crate::storage::StorageError::RestoreDiskBudget {
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
        write_budget_anchor(self, &directory).await?;
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
        let no_submission =
            record.never_submitted(intent.as_ref().and_then(|intent| intent.result.as_ref()));
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
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
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
            "SELECT EXISTS(SELECT 1 FROM restore_resource_reservation WHERE batch_id=?1)",
        )
        .bind(owner.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if bound || !inventory.bound.is_empty() {
            return Err(invalid(
                "unsubmitted capture contradicts bound child generations",
            ));
        }
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
        if no_submission {
            for statement in [
                "DELETE FROM storage_operation_stream WHERE operation_id=?1",
                "DELETE FROM storage_operation_object WHERE operation_id=?1",
                "DELETE FROM storage_operation_layer WHERE operation_id=?1",
                "DELETE FROM storage_operation_lower WHERE operation_id=?1",
            ] {
                sqlx::query(statement)
                    .bind(capture.to_string())
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        write_budget_anchor(self, &directory).await?;
        directory.write_file_atomic(
            &budget_name(self, owner)?,
            self.capture_budget_document(owner).await?.as_bytes(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::restore::{RestoreBudget, RestoreResourceCharge};
    use crate::store::MachineStore;

    #[test]
    fn resource_only_ledger_uses_a_distinct_namespace() {
        let path = crate::store::restore::user_budget_directory_path();
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(
            path.file_name().unwrap(),
            std::ffi::OsStr::new(&format!("silo-resource-budget-{uid}"))
        );
        let old_path = path.with_file_name(format!("silo-restore-budget-{uid}"));
        assert_ne!(path, old_path);
    }

    struct CheckpointRequestFixture {
        capture: crate::store::capture::tests::Fixture,
        consumer: crate::store::snapshot_store::SnapshotConsumer,
        request: vm_spec::restore::RestoreRequest,
        _files: [std::fs::File; 5],
    }

    async fn checkpoint_request_fixture() -> CheckpointRequestFixture {
        use crate::storage::pool::StoragePool;
        use crate::store::capture::tests::{fixture, seal};

        let fixture = fixture().await;
        let snapshots = &fixture.snapshots;
        let (sealed, _) = seal(&fixture);
        let info = snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                sealed.path(),
                fixture.reservation.record.alias.clone(),
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap();
        let consumer = snapshots
            .consume_shape(&crate::SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let inspection = snapshots.prepare_restore_shape(&consumer).await.unwrap();
        let shape = inspection.shape();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("fixture must be an execution checkpoint");
        };
        let files = [
            shape
                .open_stream(&pool, &execution.memory.stream, execution.memory.length)
                .unwrap(),
            shape.open_object(&pool, &execution.layout).unwrap(),
            shape.open_object(&pool, &execution.execution).unwrap(),
            shape.open_object(&pool, &execution.devices).unwrap(),
            shape.open_object(&pool, &execution.memory.map).unwrap(),
        ];
        let evidence = snapshots
            .restore_evidence(&consumer, &pool)
            .unwrap()
            .evidence;
        let runtime = crate::store::capture::tests::capture_runtime(snapshots).await;
        let request = crate::machine::restore::snapshot_restore_request(
            &runtime, &consumer, evidence, &files, None, None,
        )
        .unwrap();
        CheckpointRequestFixture {
            capture: fixture,
            consumer,
            request,
            _files: files,
        }
    }

    #[tokio::test]
    async fn captured_root_graph_enters_restore_admission_through_production_shape() {
        use std::os::unix::fs::MetadataExt;
        use vm_spec::stream_map::StreamRole;

        let CheckpointRequestFixture {
            capture: fixture,
            consumer,
            request,
            _files,
        } = checkpoint_request_fixture().await;
        let snapshots = &fixture.snapshots;
        let pool = crate::storage::pool::StoragePool::open(&snapshots.store.images_dir).unwrap();
        let crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } =
            &consumer.record.capture
        else {
            panic!("execution checkpoint required");
        };
        let root_file = pool.open_object(&execution.memory.map).unwrap();
        let expected = root_file.metadata().unwrap();
        let transferred = _files[4].metadata().unwrap();
        assert_eq!(
            (transferred.dev(), transferred.ino()),
            (expected.dev(), expected.ino())
        );
        assert_eq!(
            request.objects[4].authority,
            vm_spec::restore::RestoreObjectAuthority::Identified {
                identity: vm_spec::capture::Sha256Digest::from_bytes(
                    *execution.memory.map.as_bytes()
                ),
            }
        );
        assert_eq!(request.objects[4].length, expected.len());
        for (root, role) in [
            (execution.memory.map, StreamRole::Ram),
            (consumer.record.root.stream.map, StreamRole::Disk),
        ] {
            let authority = pool
                .map_authority(std::sync::Arc::new(
                    pool.existing_lease(consumer.operation_id).unwrap(),
                ))
                .unwrap();
            let map = pool.load_map(root, role, authority).unwrap();
            let mut nodes = 0;
            for node in map.nodes() {
                let node = node.unwrap();
                assert!(pool.verify_object(&node.digest).is_ok());
                nodes += 1;
            }
            assert!(nodes > 0);
        }
        let vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { evidence, .. } =
            &request.authority
        else {
            panic!("snapshot authority required");
        };
        let changes = &evidence.memory.as_ref().unwrap().changes;
        let digest =
            crate::storage::identity::ObjectDigest::from_sha256(*changes.sha256.as_bytes());
        assert_eq!(
            pool.open_object(&digest).unwrap().metadata().unwrap().len(),
            changes.byte_len
        );
        let charge = snapshots
            .reserve_restore_resources(
                &consumer,
                vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES
                    + consumer.record.root.geometry.length,
                64,
            )
            .await
            .unwrap();
        assert_eq!(charge.descriptors, 64);
        let operation = consumer.operation_id;
        snapshots
            .store
            .finish_stopped_operation(operation)
            .await
            .unwrap();
        drop(consumer);
        snapshots
            .store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM restore_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&snapshots.store.pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn restore_consumer_initializes_first_machine_parent_without_bypassing_admission() {
        use crate::storage::pool::StoragePool;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let CheckpointRequestFixture {
            capture: fixture,
            consumer,
            request: _request,
            _files,
        } = checkpoint_request_fixture().await;
        let snapshots = &fixture.snapshots;
        let pool = StoragePool::open(&snapshots.store.images_dir).unwrap();
        let disk_peak = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + 512;

        // Keep the source intact but unavailable at the destination path. Every
        // restore input is now authenticated in the pool, as after acquisition.
        let machines = snapshots.store.home.join("machines");
        let source = snapshots.store.home.join("captured-source");
        std::fs::rename(&machines, &source).unwrap();
        let external = tempfile::tempdir().unwrap();
        symlink(external.path(), &machines).unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, disk_peak, 32)
            .await
            .is_err());
        assert!(std::fs::read_dir(external.path()).unwrap().next().is_none());
        std::fs::remove_file(&machines).unwrap();
        std::fs::write(&machines, b"not a directory").unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, disk_peak, 32)
            .await
            .is_err());
        std::fs::remove_file(&machines).unwrap();
        std::fs::create_dir(&machines).unwrap();
        std::fs::set_permissions(&machines, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(snapshots
            .reserve_restore_resources(&consumer, disk_peak, 32)
            .await
            .is_err());
        assert_eq!(std::fs::metadata(&machines).unwrap().mode() & 0o7777, 0o755);
        std::fs::remove_dir(&machines).unwrap();

        let error = snapshots
            .reserve_restore_resources(&consumer, u64::MAX / 2, 32)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::Storage(crate::storage::StorageError::RestoreDiskBudget { .. })
        ));
        let metadata = std::fs::metadata(&machines).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert!(std::fs::read_dir(&machines).unwrap().next().is_none());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_resource_reservation")
            .fetch_one(&snapshots.store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "unsafe paths and disk refusal publish no charge");

        let charge = snapshots
            .reserve_restore_resources(&consumer, disk_peak, 32)
            .await
            .unwrap();
        assert_eq!(charge.disk_device, metadata.dev());
        assert_eq!(charge.disk_bytes, disk_peak);
        assert_eq!(std::fs::metadata(&machines).unwrap().ino(), metadata.ino());
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_resource_reservation WHERE operation_id=?1",
        )
        .bind(consumer.operation_id.to_string())
        .fetch_one(&snapshots.store.pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RestoreResourceCharge>(&json).unwrap(),
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
            RestoreBudget::read(&store, &ledger)
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
        assert!(RestoreBudget::read(&store, &ledger)
            .unwrap()
            .disks
            .is_empty());
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
        assert!(RestoreBudget::read(&store, &ledger)
            .unwrap()
            .disks
            .is_empty());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM capture_resource_reservation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }

    fn charge(disk_device: u64) -> RestoreResourceCharge {
        RestoreResourceCharge {
            disk_device,
            disk_bytes: vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
            construction_complete: false,
            descriptor_owner: None,
            descriptors: 0,
        }
    }

    fn capture_inventory() -> crate::store::restore::CaptureBudgetInventory {
        crate::store::restore::CaptureBudgetInventory {
            capture_id: uuid::Uuid::new_v4(),
            capture_disks: Vec::new(),
            pending: Vec::new(),
            bound: Vec::new(),
            descriptor_owner: None,
            descriptors: 0,
        }
    }

    #[test]
    fn resource_documents_exclude_ram_and_reject_stale_ram_fields() {
        use crate::store::restore::{BudgetDocument, PendingForkCharge};

        let restore = serde_json::to_value(charge(3)).unwrap();
        assert_eq!(restore.as_object().unwrap().len(), 5);
        for field in [
            "baselineDevice",
            "baselineInode",
            "baselineBytes",
            "configuredBytes",
            "granule",
            "privateBytes",
            "overheadBytes",
            "policy",
        ] {
            let mut stale = restore.clone();
            stale[field] = serde_json::json!(1);
            assert!(
                serde_json::from_value::<BudgetDocument>(stale).is_err(),
                "{field}"
            );
        }
        let capture = serde_json::to_value(capture_inventory()).unwrap();
        assert_eq!(capture.as_object().unwrap().len(), 6);
        for field in ["captureMemory", "baseline"] {
            let mut stale = capture.clone();
            stale[field] = serde_json::json!(null);
            assert!(
                serde_json::from_value::<BudgetDocument>(stale).is_err(),
                "{field}"
            );
        }
        let pending = PendingForkCharge {
            consumer_id: uuid::Uuid::new_v4(),
            disk_device: 3,
            disk_bytes: vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
        };
        let pending = serde_json::to_value(pending).unwrap();
        assert_eq!(pending.as_object().unwrap().len(), 3);
        for field in ["configuredBytes", "privateBytes", "overheadBytes", "policy"] {
            let mut stale = pending.clone();
            stale[field] = serde_json::json!(1);
            assert!(
                serde_json::from_value::<PendingForkCharge>(stale).is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn sparse_fork_children_use_planned_allocations_through_boot_refinement_and_replay() {
        use std::os::unix::fs::{FileExt, MetadataExt};

        use crate::store::capture::tests::fixture_source_with_disk_length;
        use crate::store::restore::{budget_directory, CaptureBudgetInventory};

        let length = 100 << 30;
        let fixture = fixture_source_with_disk_length(
            true,
            true,
            vm_spec::lifecycle::CapturePolicy::Full,
            length,
        )
        .await;
        let store = &fixture.snapshots.store;
        let record = &fixture.reservation.record;
        let operation = record.fork_operation_id.unwrap();
        let _manager = crate::storage::pool::StoragePool::open(&store.images_dir)
            .unwrap()
            .existing_lease(operation)
            .unwrap();
        let root_path = crate::paths::machine_data_dir_in(store.home_path(), record.machine_id)
            .join("root.raw");
        let root = std::fs::OpenOptions::new()
            .write(true)
            .open(root_path)
            .unwrap();
        let metadata = root.metadata().unwrap();
        let root_bytes = metadata.blocks().checked_mul(512).unwrap();
        assert_eq!(metadata.len(), length);
        assert!(root_bytes > 0 && root_bytes < length / 1000);
        let launches = store
            .launch_storage_operations(record.machine_id)
            .await
            .unwrap();
        let launch = launches
            .iter()
            .find(|launch| launch.operation_id == record.launch_operation_id)
            .unwrap();
        let data_bytes = std::fs::metadata(&launch.disks[1].path)
            .unwrap()
            .blocks()
            .checked_mul(512)
            .unwrap();
        assert_eq!(record.disk_allocations.len(), 2);
        assert_eq!(record.disk_allocations[&0], root_bytes);
        assert_eq!(record.disk_allocations[&1], data_bytes);
        let mut expected = vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + root_bytes + data_bytes;
        let pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
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
                expected += std::fs::metadata(pool.object_path(object)).unwrap().len();
            }
        }
        let ledger = budget_directory(store).unwrap();
        let mut before = None;
        for _ in 0..2 {
            store.reserve_capture_inventory(record, None).await.unwrap();
            let inventory: CaptureBudgetInventory =
                serde_json::from_str(&store.capture_budget_document(operation).await.unwrap())
                    .unwrap();
            assert_eq!(inventory.pending.len(), 2);
            for child in &inventory.pending {
                assert_eq!(child.disk_bytes, expected);
            }
            let disks = RestoreBudget::read(store, &ledger).unwrap().disks;
            if let Some(before) = &before {
                assert_eq!(&disks, before);
            }
            before = Some(disks);
            root.write_all_at(&[0x52; 4096], length / 2).unwrap();
            root.sync_all().unwrap();
            assert!(root.metadata().unwrap().blocks() * 512 > root_bytes);
            store
                .refine_capture_boot_inventory(record.capture_id)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn plain_capture_reserves_disk_and_descriptors_through_replay() {
        use crate::store::restore::{budget_directory, budget_name, CaptureBudgetInventory};

        let fixture = crate::store::capture::tests::fixture().await;
        let store = &fixture.snapshots.store;
        let record = &fixture.reservation.record;
        assert!(record.fork_operation_id.is_none());
        let ledger = budget_directory(store).unwrap();
        for _ in 0..2 {
            store.reserve_capture_inventory(record, None).await.unwrap();
            let inventory: CaptureBudgetInventory = serde_json::from_reader(
                ledger
                    .open_file(&budget_name(store, record.capture_id).unwrap())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert!(inventory.pending.is_empty());
            assert!(inventory.bound.is_empty());
            let mut budget = RestoreBudget::default();
            budget.add_capture(&inventory).unwrap();
        }
        store.complete_capture_peak(record).await.unwrap();
        let inventory: CaptureBudgetInventory = serde_json::from_str(
            &store
                .capture_budget_document(record.capture_id)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(inventory.capture_disks.is_empty());
    }

    #[tokio::test]
    async fn native_capture_writer_keeps_disk_but_not_dead_publishers_descriptors() {
        use crate::store::restore::budget_directory;

        let fixture = crate::store::capture::tests::fixture().await;
        let store = fixture.snapshots.store.clone();
        let ledger = budget_directory(&store).unwrap();
        let expected = fixture
            .reservation
            .record
            .disk_charges
            .iter()
            .map(|disk| disk.bytes)
            .sum::<u64>();
        drop(fixture.reservation);
        let _admission = crate::storage::locks::blocking(
            &ledger,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let budget = RestoreBudget::read(&store, &ledger).unwrap();
        assert!(expected > 0);
        assert_eq!(budget.disks.values().sum::<u64>(), expected);
        assert_eq!(budget.descriptors, 0);
        drop(fixture.launch);
        let budget = RestoreBudget::read(&store, &ledger).unwrap();
        assert!(budget.disks.is_empty());
        assert_eq!(budget.descriptors, 0);
        assert!(store.home.join("state.db").exists());
    }

    #[tokio::test]
    async fn live_bound_fork_child_does_not_keep_abandoned_siblings_charged() {
        use crate::store::restore::{budget_directory, CaptureBudgetInventory};

        let fixture = crate::store::capture::tests::fork_fixture().await;
        let store = fixture.snapshots.store.clone();
        let record = fixture.reservation.record.clone();
        let operation = record.fork_operation_id.unwrap();
        crate::store::capture::tests::seal_owned(&fixture);
        fixture
            .snapshots
            .retain_local_capture(record.capture_id)
            .await
            .unwrap();
        let cut = store.open_local_cut(operation).await.unwrap();
        store.bind_fork_resources(&cut).await.unwrap();
        let inventory: CaptureBudgetInventory =
            serde_json::from_str(&store.capture_budget_document(operation).await.unwrap()).unwrap();
        assert_eq!(inventory.bound.len(), 2);
        let survivor = &inventory.bound[1];
        let pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
        let child = pool.existing_lease(survivor.consumer_id).unwrap();
        drop(cut);
        drop(fixture.reservation);
        drop(fixture.launch);
        let ledger = budget_directory(&store).unwrap();
        let _admission = crate::storage::locks::blocking(
            &ledger,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let budget = RestoreBudget::read(&store, &ledger).unwrap();
        assert_eq!(
            budget.disks.values().sum::<u64>(),
            survivor.resources.disk_bytes
        );
        assert_eq!(budget.descriptors, 0);
        // A SQL-first retirement can leave the old aggregate document visible.
        // Consumer identity, not its old vector position, binds each lease.
        sqlx::query("DELETE FROM restore_resource_reservation WHERE budget_id=?1")
            .bind(inventory.bound[0].consumer_id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        crate::store::restore::write_budget_anchor(&store, &ledger)
            .await
            .unwrap();
        let budget = RestoreBudget::read(&store, &ledger).unwrap();
        assert_eq!(
            budget.disks.values().sum::<u64>(),
            survivor.resources.disk_bytes
        );
        drop(child);
        assert!(RestoreBudget::read(&store, &ledger)
            .unwrap()
            .disks
            .is_empty());
    }

    #[tokio::test]
    async fn resumed_capture_publication_readmits_disk_before_writing() {
        use crate::paths::{LocalPaths, OwnedDirectory};
        use crate::store::restore::budget_directory;

        let fixture = crate::store::capture::tests::fixture().await;
        let (sealed, _) = crate::store::capture::tests::seal(&fixture);
        let snapshots = fixture.snapshots.clone();
        let record = fixture.reservation.record.clone();
        let ledger = budget_directory(&snapshots.store).unwrap();
        drop(fixture.reservation);
        drop(fixture.launch);
        {
            let _admission = crate::storage::locks::blocking(
                &ledger,
                "admission.lock",
                nix::fcntl::FlockArg::LockExclusive,
            )
            .unwrap();
            assert!(RestoreBudget::read(&snapshots.store, &ledger)
                .unwrap()
                .disks
                .is_empty());
        }
        let other_home = tempfile::tempdir().unwrap();
        let mut other = crate::store::Store::new(&LocalPaths::new(other_home.path()))
            .await
            .unwrap();
        other.resource_budget_directory = Some(ledger.path().to_path_buf());
        let (operation, _lease) = other
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let disk = OwnedDirectory::open_existing_root(&other.images_dir)
            .unwrap()
            .unwrap();
        let filesystem = nix::sys::statvfs::fstatvfs(disk.fd()).unwrap();
        let available = filesystem
            .blocks_available()
            .checked_mul(filesystem.fragment_size())
            .unwrap();
        let peak = record
            .disk_charges
            .iter()
            .map(|disk| disk.bytes)
            .sum::<u64>();
        assert!(peak > 0);
        other
            .reserve_import_space(operation, available.checked_sub(peak / 2).unwrap())
            .await
            .unwrap();
        let error = snapshots
            .publish_capture(
                record.capture_id,
                sealed.path(),
                record.alias,
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::Storage(crate::storage::StorageError::CaptureDiskBudget {
                phase: "publication deferred",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn live_fork_capture_reserves_each_child_disk_through_binding() {
        use crate::store::restore::{budget_directory, budget_name, CaptureBudgetInventory};

        let fixture = crate::store::capture::tests::fork_fixture().await;
        let store = &fixture.snapshots.store;
        let record = &fixture.reservation.record;
        let operation = record.fork_operation_id.unwrap();
        let _manager = crate::storage::pool::StoragePool::open(&store.images_dir)
            .unwrap()
            .existing_lease(operation)
            .unwrap();
        let ledger = budget_directory(store).unwrap();
        for _ in 0..2 {
            store.reserve_capture_inventory(record, None).await.unwrap();
            let inventory: CaptureBudgetInventory = serde_json::from_reader(
                ledger
                    .open_file(&budget_name(store, operation).unwrap())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(inventory.pending.len(), 2);
        }
        crate::store::capture::tests::seal_owned(&fixture);
        fixture
            .snapshots
            .retain_local_capture(record.capture_id)
            .await
            .unwrap();
        let cut = store.open_local_cut(operation).await.unwrap();
        store.bind_fork_resources(&cut).await.unwrap();
        let inventory: CaptureBudgetInventory =
            serde_json::from_str(&store.capture_budget_document(operation).await.unwrap()).unwrap();
        assert!(inventory.pending.is_empty());
        assert_eq!(inventory.bound.len(), 2);
        let pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
        let expected_disk =
            crate::store::restore::fork_disk_peak(record, &record.storage.boot, &pool).unwrap();
        for child in &inventory.bound {
            assert_eq!(child.resources.disk_bytes, expected_disk);
        }
        let children = inventory
            .bound
            .iter()
            .map(|child| child.resources.disk_bytes)
            .sum::<u64>();
        let budget = RestoreBudget::read(store, &ledger).unwrap();
        assert_eq!(budget.disks.values().sum::<u64>(), children);
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
        let _machines = OwnedDirectory::open_root(&store.home.join("machines")).unwrap();
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
        let input = backed_charge(&home);
        let mut inventory = capture_inventory();
        inventory.capture_id = operation;
        inventory.descriptor_owner = Some(previous);
        inventory.descriptors = 1;
        inventory.pending.push(PendingForkCharge {
            consumer_id: uuid::Uuid::new_v4(),
            disk_device: input.disk_device,
            disk_bytes: input.disk_bytes,
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
        let before = RestoreBudget::read(&store, &ledger).unwrap();
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
        let after = RestoreBudget::read(&store, &ledger).unwrap();
        assert_eq!(after.descriptors, 1);
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
            RestoreBudget::read(&store, &ledger).unwrap().descriptors,
            inventory.descriptors
        );

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
        assert_eq!(RestoreBudget::read(&store, &ledger).unwrap().descriptors, 0);
        store.close().await;
    }

    #[test]
    fn fork_batch_transfer_preserves_shared_admission_without_reacquiring_child_capacity() {
        use crate::store::restore::PendingForkCharge;
        let input = charge(3);
        let mut inventory = capture_inventory();
        inventory.pending = (0..17)
            .map(|_| PendingForkCharge {
                consumer_id: uuid::Uuid::new_v4(),
                disk_device: input.disk_device,
                disk_bytes: input.disk_bytes,
            })
            .collect();
        let mut admitted = RestoreBudget::default();
        admitted.add_capture(&inventory).unwrap();
        inventory.pending.clear();
        inventory.bound = (0..17)
            .map(|_| crate::store::restore::BoundForkCharge {
                consumer_id: uuid::Uuid::new_v4(),
                resources: input.clone(),
            })
            .collect();
        let mut bound = RestoreBudget::default();
        bound.add_capture(&inventory).unwrap();
        assert_eq!(bound.disks, admitted.disks);
        inventory.bound.pop();
        let mut retired = RestoreBudget::default();
        retired.add_capture(&inventory).unwrap();
        assert_eq!(bound.disks[&3] - retired.disks[&3], input.disk_bytes);
    }

    #[test]
    fn pending_fork_inventory_rejects_disk_undercharge_and_nil_identity() {
        use crate::store::restore::PendingForkCharge;
        let input = charge(3);
        let mut inventory = capture_inventory();
        inventory.pending.push(PendingForkCharge {
            consumer_id: uuid::Uuid::new_v4(),
            disk_device: input.disk_device,
            disk_bytes: input.disk_bytes - 1,
        });
        assert!(RestoreBudget::default().add_capture(&inventory).is_err());
        inventory.pending[0].disk_bytes = input.disk_bytes;
        inventory.pending[0].consumer_id = uuid::Uuid::nil();
        assert!(RestoreBudget::default().add_capture(&inventory).is_err());
    }

    #[test]
    fn descriptor_budget_is_scoped_to_the_exact_manager_birth_not_all_homes() {
        let owner = crate::store::restore::DescriptorOwner::current().unwrap();
        let mut inventory = capture_inventory();
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
    fn restore_started_releases_construction_peak() {
        let mut input = charge(3);
        let mut before = RestoreBudget::default();
        before.add(&input).unwrap();
        assert_eq!(before.disks[&3], input.disk_bytes);
        input.construction_complete = true;
        input.disk_bytes = 0;
        let mut after = RestoreBudget::default();
        after.add(&input).unwrap();
        assert_eq!(after.disks[&3], 0);
        input.construction_complete = false;
        assert!(input.validate().is_err());
    }

    #[test]
    fn restore_budget_rejects_arithmetic_overflow() {
        let mut input = charge(3);
        input.disk_bytes = u64::MAX;
        let mut budget = RestoreBudget::default();
        budget.add(&input).unwrap();
        assert!(budget.add(&input).is_err());
    }

    fn backed_charge(disk: &crate::paths::OwnedDirectory) -> RestoreResourceCharge {
        use std::os::unix::fs::MetadataExt;

        charge(std::fs::metadata(disk.path()).unwrap().dev())
    }

    #[tokio::test]
    async fn restore_charge_survives_journal_reconciliation_and_disk_admission() {
        use crate::paths::OwnedDirectory;
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
        let mut input = backed_charge(&home);
        store
            .reserve_restore_charge(operation, &input, &home, &ledger)
            .await
            .unwrap();
        let json: String = sqlx::query_scalar(
            "SELECT json(charge_json) FROM restore_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<RestoreResourceCharge>(&json).unwrap(),
            input
        );
        let name = crate::store::restore::budget_name(&store, operation).unwrap();
        // Reconciliation restores the authoritative journal charge.
        ledger
            .write_file_atomic(
                &name,
                &serde_json::to_vec(&charge(input.disk_device + 1)).unwrap(),
            )
            .unwrap();
        store.reconcile_restore_budget_in(&ledger).await.unwrap();
        let restored: RestoreResourceCharge =
            serde_json::from_reader(ledger.open_file(&name).unwrap().unwrap()).unwrap();
        assert_eq!(restored, input);
        restored.validate().unwrap();
        let mut malformed = serde_json::to_value(&restored).unwrap();
        malformed["privateBytes"] = serde_json::json!(4096);
        assert!(serde_json::from_value::<RestoreResourceCharge>(malformed).is_err());
        let mut undercharged = input.clone();
        undercharged.disk_bytes -= 1;
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
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_resource_reservation")
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
        let mut input = backed_charge(&home);
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
                "UPDATE restore_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1",
            )
            .bind(operation.to_string())
            .bind(&json)
            .execute(&mut *tx)
            .await
            .unwrap();
            crate::store::restore::publish_budget(
                &store,
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
                let input = backed_charge(&home);
                let before = {
                    let _admission = crate::storage::locks::blocking(
                        &ledger,
                        "admission.lock",
                        nix::fcntl::FlockArg::LockExclusive,
                    )
                    .unwrap();
                    RestoreBudget::read(&store, &ledger).unwrap()
                };
                let old_disk = 0;
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
                    RestoreBudget::read(&store, &ledger).unwrap()
                };
                assert_eq!(after.disks[&input.disk_device], old_disk + input.disk_bytes);
                store.close().await;
            }
        }
    }

    struct CrossHomeBudgetFixture {
        root: tempfile::TempDir,
        a: crate::store::Store,
        b: crate::store::Store,
        ledger: crate::paths::OwnedDirectory,
        input: RestoreResourceCharge,
        operation: uuid::Uuid,
        lease: Option<crate::storage::locks::StorageLock>,
        b_leases: std::cell::RefCell<Vec<crate::storage::locks::StorageLock>>,
    }

    impl CrossHomeBudgetFixture {
        async fn new() -> Self {
            use crate::paths::OwnedDirectory;

            let root = tempfile::tempdir().unwrap();
            let home_a = OwnedDirectory::open_root(&root.path().join("home-a")).unwrap();
            let home_b = OwnedDirectory::open_root(&root.path().join("home-b")).unwrap();
            let ledger = OwnedDirectory::open_root(&root.path().join("ledger")).unwrap();
            let mut a = crate::store::Store::open(&home_a.path().join("state.db"))
                .await
                .unwrap();
            let mut b = crate::store::Store::open(&home_b.path().join("state.db"))
                .await
                .unwrap();
            a.resource_budget_directory = Some(ledger.path().to_path_buf());
            b.resource_budget_directory = Some(ledger.path().to_path_buf());
            a.reconcile_restore_budget().await.unwrap();
            b.reconcile_restore_budget().await.unwrap();
            let mut input = backed_charge(&home_a);
            input.descriptor_owner =
                Some(crate::store::restore::DescriptorOwner::current().unwrap());
            input.descriptors = 8;
            let (operation, lease) = a.begin_stopped_operation("import", &[], &[]).await.unwrap();
            a.reserve_restore_charge(operation, &input, &home_a, &ledger)
                .await
                .unwrap();
            Self {
                root,
                a,
                b,
                ledger,
                input,
                operation,
                lease: Some(lease),
                b_leases: std::cell::RefCell::new(Vec::new()),
            }
        }

        async fn admit_b(&self) {
            let home = crate::paths::OwnedDirectory::open_existing_root(&self.b.home)
                .unwrap()
                .unwrap();
            let (operation, lease) = self
                .b
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            self.b
                .reserve_restore_charge(operation, &self.input, &home, &self.ledger)
                .await
                .unwrap();
            self.b_leases.borrow_mut().push(lease);
        }

        fn read_b(&self) -> RestoreBudget {
            let _admission = crate::storage::locks::blocking(
                &self.ledger,
                "admission.lock",
                nix::fcntl::FlockArg::LockExclusive,
            )
            .unwrap();
            RestoreBudget::read(&self.b, &self.ledger).unwrap()
        }

        fn assert_reclaimed(&self, prefix: &str) {
            assert!(
                std::fs::read_dir(self.ledger.path())
                    .unwrap()
                    .all(|entry| !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(prefix)),
                "reclamation must remove both charges and the home anchor"
            );
            let budget = self.read_b();
            assert_eq!(budget.disks[&self.input.disk_device], self.input.disk_bytes);
        }
    }

    #[tokio::test]
    async fn abandoned_existing_home_releases_admission_without_retiring_its_journal() {
        let mut fixture = CrossHomeBudgetFixture::new().await;
        let name = crate::store::restore::budget_name(&fixture.a, fixture.operation).unwrap();
        let before = fixture.read_b();
        assert_eq!(
            before.disks[&fixture.input.disk_device],
            fixture.input.disk_bytes
        );
        assert_eq!(before.descriptors, fixture.input.descriptors);
        fixture.a.pool.close().await;
        drop(fixture.lease.take());
        fixture.admit_b().await;
        let after = fixture.read_b();
        assert_eq!(
            after.disks[&fixture.input.disk_device],
            fixture.input.disk_bytes
        );
        assert_eq!(after.descriptors, fixture.input.descriptors);
        assert!(fixture.a.home.join("state.db").exists());
        assert!(fixture.ledger.path().join(&name).exists());

        let mut recovered = crate::store::Store::open(&fixture.a.home.join("state.db"))
            .await
            .unwrap();
        recovered.resource_budget_directory = Some(fixture.ledger.path().to_path_buf());
        recovered.reconcile_restore_budget().await.unwrap();
        let retained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM restore_resource_reservation WHERE budget_id=?1",
        )
        .bind(fixture.operation.to_string())
        .fetch_one(&recovered.pool)
        .await
        .unwrap();
        assert_eq!(retained, 0);
        assert!(!fixture.ledger.path().join(name).exists());
        recovered.close().await;
    }

    #[tokio::test]
    async fn inherited_operation_lease_keeps_admission_until_its_final_descriptor_closes() {
        let mut fixture = CrossHomeBudgetFixture::new().await;
        let inherited = fixture.lease.as_ref().unwrap().duplicate().unwrap();
        drop(fixture.lease.take());
        fixture.a.pool.close().await;
        assert_eq!(
            fixture.read_b().disks[&fixture.input.disk_device],
            fixture.input.disk_bytes
        );
        drop(inherited);
        let budget = fixture.read_b();
        assert!(budget.disks.is_empty());
        assert_eq!(budget.descriptors, 0);
    }

    #[tokio::test]
    async fn abandoned_import_inventory_is_ignored_without_reopening_its_home() {
        let fixture = CrossHomeBudgetFixture::new().await;
        let (operation, lease) = fixture
            .a
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .a
            .reserve_import_space(operation, 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            fixture.read_b().disks[&fixture.input.disk_device],
            fixture.input.disk_bytes + (1 << 20)
        );
        drop(lease);
        let budget = fixture.read_b();
        assert_eq!(
            budget.disks[&fixture.input.disk_device],
            fixture.input.disk_bytes
        );
        let retained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&fixture.a.pool)
        .await
        .unwrap();
        assert_eq!(
            retained, 1,
            "admission does not retire another home's journal"
        );
    }

    #[tokio::test]
    async fn resource_budget_refuses_replaced_lease_inodes() {
        let fixture = CrossHomeBudgetFixture::new().await;
        let pool = crate::storage::pool::StoragePool::open(&fixture.a.images_dir).unwrap();
        let path = fixture
            .a
            .images_dir
            .join("locks/leases")
            .join(format!("{}.lease", fixture.operation));
        std::fs::rename(&path, path.with_extension("saved")).unwrap();
        let _replacement = pool.lease(fixture.operation).unwrap();
        let _admission = crate::storage::locks::blocking(
            &fixture.ledger,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        let error = RestoreBudget::read(&fixture.b, &fixture.ledger)
            .err()
            .unwrap();
        assert!(error.to_string().contains("lease inode changed"), "{error}");
    }

    #[tokio::test]
    async fn restore_budget_reclaims_deleted_home_at_other_home_admission() {
        let fixture = CrossHomeBudgetFixture::new().await;
        let prefix = crate::store::restore::budget_prefix(&fixture.a).unwrap();
        // Multiple records, including a capture inventory, belong to one home.
        let (operation, _lease) = fixture
            .a
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        fixture
            .a
            .reserve_import_space(operation, 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            crate::store::restore::budget_entries(&fixture.ledger)
                .unwrap()
                .iter()
                .filter(|name| name.starts_with(&prefix))
                .count(),
            2
        );
        fixture.a.pool.close().await;
        std::fs::remove_dir_all(&fixture.a.home).unwrap();
        fixture.admit_b().await;
        fixture.assert_reclaimed(&prefix);
    }

    #[tokio::test]
    async fn restore_budget_counts_other_live_home_without_its_manager_running() {
        let fixture = CrossHomeBudgetFixture::new().await;
        let prefix = crate::store::restore::budget_prefix(&fixture.a).unwrap();
        fixture.a.pool.close().await;
        fixture.admit_b().await;
        let budget = fixture.read_b();
        assert_eq!(
            budget.disks[&fixture.input.disk_device],
            2 * fixture.input.disk_bytes
        );
        assert!(fixture
            .ledger
            .path()
            .join(format!("{prefix}home.json"))
            .exists());
        assert!(fixture
            .ledger
            .path()
            .join(format!("{prefix}{}.json", fixture.operation))
            .exists());
    }

    #[tokio::test]
    async fn restore_budget_reclaims_anchor_path_with_replaced_database() {
        use std::os::unix::fs::MetadataExt;

        let fixture = CrossHomeBudgetFixture::new().await;
        let prefix = crate::store::restore::budget_prefix(&fixture.a).unwrap();
        let previous = std::fs::metadata(fixture.a.home.join("state.db")).unwrap();
        fixture.a.pool.close().await;
        std::fs::rename(&fixture.a.home, fixture.root.path().join("previous-home")).unwrap();
        let replacement = crate::store::Store::open(&fixture.a.home.join("state.db"))
            .await
            .unwrap();
        let current = std::fs::metadata(replacement.home.join("state.db")).unwrap();
        assert_ne!(
            (previous.dev(), previous.ino()),
            (current.dev(), current.ino())
        );
        fixture.admit_b().await;
        fixture.assert_reclaimed(&prefix);
        replacement.close().await;
    }

    #[tokio::test]
    async fn restore_budget_reclaims_charges_without_a_home_anchor() {
        let fixture = CrossHomeBudgetFixture::new().await;
        let prefix = crate::store::restore::budget_prefix(&fixture.a).unwrap();
        fixture
            .ledger
            .remove_tree(&format!("{prefix}home.json"))
            .unwrap();
        let name = crate::store::restore::budget_name(&fixture.a, fixture.operation).unwrap();
        fixture.ledger.write_file_atomic(&name, b"{").unwrap();
        fixture.admit_b().await;
        fixture.assert_reclaimed(&prefix);
    }

    #[tokio::test]
    async fn restore_budget_reclaims_malformed_or_unsupported_home_anchors() {
        for bytes in [
            b"{".as_slice(),
            br#"{"schema":2,"home":"/","stateDevice":1,"stateInode":1}"#,
        ] {
            let fixture = CrossHomeBudgetFixture::new().await;
            let prefix = crate::store::restore::budget_prefix(&fixture.a).unwrap();
            fixture
                .ledger
                .write_file_atomic(&format!("{prefix}home.json"), bytes)
                .unwrap();
            fixture.admit_b().await;
            fixture.assert_reclaimed(&prefix);
        }
    }

    #[tokio::test]
    async fn restore_budget_refuses_malformed_or_stale_ram_charge_with_owning_home_guidance() {
        for stale_ram in [false, true] {
            let fixture = CrossHomeBudgetFixture::new().await;
            let name = crate::store::restore::budget_name(&fixture.a, fixture.operation).unwrap();
            let bytes = if stale_ram {
                let mut stale = serde_json::to_value(&fixture.input).unwrap();
                stale["baselineBytes"] = serde_json::json!(1 << 20);
                serde_json::to_vec(&stale).unwrap()
            } else {
                b"{".to_vec()
            };
            fixture.ledger.write_file_atomic(&name, &bytes).unwrap();
            let (operation, _lease) = fixture
                .b
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            let home = crate::paths::OwnedDirectory::open_existing_root(&fixture.b.home)
                .unwrap()
                .unwrap();
            let error = fixture
                .b
                .reserve_restore_charge(operation, &fixture.input, &home, &fixture.ledger)
                .await
                .unwrap_err()
                .to_string();
            let owning_home = std::fs::canonicalize(&fixture.a.home).unwrap();
            assert!(
                error.contains(&owning_home.display().to_string()),
                "{error}"
            );
            assert!(
                error.contains(&fixture.ledger.path().display().to_string()),
                "{error}"
            );
            assert!(error.contains("is malformed"), "{error}");
            assert!(error.contains("remove that home"), "{error}");
            assert!(error.contains("delete its stale budget files"), "{error}");
            assert_eq!(
                std::fs::read(fixture.ledger.path().join(name)).unwrap(),
                bytes
            );
        }
    }

    #[tokio::test]
    async fn restore_budget_reconciliation_refreshes_moved_home_anchor() {
        use crate::store::restore::{budget_prefix, BudgetHomeAnchor};

        let fixture = CrossHomeBudgetFixture::new().await;
        let prefix = budget_prefix(&fixture.a).unwrap();
        fixture.a.pool.close().await;
        let moved_path = fixture.root.path().join("moved-home");
        std::fs::rename(&fixture.a.home, &moved_path).unwrap();
        let mut moved = crate::store::Store::open(&moved_path.join("state.db"))
            .await
            .unwrap();
        moved.resource_budget_directory = Some(fixture.ledger.path().to_path_buf());
        moved.reconcile_restore_budget().await.unwrap();
        assert_eq!(budget_prefix(&moved).unwrap(), prefix);
        let anchor: BudgetHomeAnchor = serde_json::from_reader(
            fixture
                .ledger
                .open_file(&format!("{prefix}home.json"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(anchor.home, std::fs::canonicalize(moved_path).unwrap());
        fixture.admit_b().await;
        assert_eq!(
            fixture.read_b().disks[&fixture.input.disk_device],
            2 * fixture.input.disk_bytes
        );
        moved.close().await;
    }

    #[tokio::test]
    async fn restore_budget_open_publishes_anchor_without_an_image_pool() {
        use crate::store::restore::{budget_directory, budget_prefix, BudgetHomeAnchor};
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&root.path().join("state.db"))
            .await
            .unwrap();
        assert!(!store.images_dir.exists());
        let ledger = budget_directory(&store).unwrap();
        let anchor: BudgetHomeAnchor = serde_json::from_reader(
            ledger
                .open_file(&format!("{}home.json", budget_prefix(&store).unwrap()))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let state = std::fs::metadata(store.home.join("state.db")).unwrap();
        assert_eq!(anchor.schema, 2);
        assert_eq!(anchor.home, std::fs::canonicalize(&store.home).unwrap());
        assert_eq!(
            (anchor.state_device, anchor.state_inode),
            (state.dev(), state.ino())
        );
        store.close().await;
    }

    #[tokio::test]
    async fn restore_budget_reconciliation_removes_inherited_own_prefix_from_sql() {
        use crate::store::restore::{budget_name, budget_prefix, BudgetHomeAnchor};
        use std::os::unix::fs::MetadataExt;

        let fixture = CrossHomeBudgetFixture::new().await;
        let stale = budget_name(&fixture.b, uuid::Uuid::new_v4()).unwrap();
        fixture
            .ledger
            .write_file_atomic(&stale, &serde_json::to_vec(&fixture.input).unwrap())
            .unwrap();
        let state = std::fs::metadata(fixture.b.home.join("state.db")).unwrap();
        let anchor_name = format!("{}home.json", budget_prefix(&fixture.b).unwrap());
        let inherited = BudgetHomeAnchor {
            schema: 2,
            home: fixture.root.path().join("deleted-home"),
            state_device: state.dev(),
            state_inode: state.ino(),
            leases: std::collections::BTreeMap::new(),
        };
        fixture
            .ledger
            .write_file_atomic(&anchor_name, &serde_json::to_vec(&inherited).unwrap())
            .unwrap();
        fixture.b.reconcile_restore_budget().await.unwrap();
        assert!(!fixture.ledger.path().join(stale).exists());
        let refreshed: BudgetHomeAnchor =
            serde_json::from_reader(fixture.ledger.open_file(&anchor_name).unwrap().unwrap())
                .unwrap();
        assert_eq!(
            refreshed.home,
            std::fs::canonicalize(&fixture.b.home).unwrap()
        );
        fixture.admit_b().await;
        assert_eq!(
            fixture.read_b().disks[&fixture.input.disk_device],
            2 * fixture.input.disk_bytes
        );
    }

    #[tokio::test]
    async fn restore_budget_never_ignores_malformed_authoritative_records() {
        use crate::store::restore::{budget_directory, budget_name};

        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&root.path().join("state.db"))
            .await
            .unwrap();
        let ledger = budget_directory(&store).unwrap();
        let name = budget_name(&store, uuid::Uuid::new_v4()).unwrap();
        let _admission = crate::storage::locks::blocking(
            &ledger,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )
        .unwrap();
        ledger.write_file_atomic(&name, b"{").unwrap();
        assert!(RestoreBudget::read(&store, &ledger).is_err());
        ledger.remove_tree(&name).unwrap();
        ledger.write_file_atomic("unknown", b"{}").unwrap();
        assert!(RestoreBudget::read(&store, &ledger).is_err());
        store.close().await;
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
            request: _request,
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
        let ram_stream = execution.memory.stream;
        let ram_length = execution.memory.length;
        let expected = vm_spec::stream_map::Chunk::Data(vm_spec::capture::Sha256Digest::of_bytes(
            &std::fs::read(&ram_path).unwrap(),
        ));
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
        let authentication_error = crate::storage::stream::ExpectedMapError::ChunkMismatch {
            role: vm_spec::stream_map::StreamRole::Ram,
            stream: ram_stream,
            chunk_size: vm_spec::stream_map::ChunkSize::RAM,
            index: 0,
            start: 0,
            end: ram_length,
            expected,
            actual: vm_spec::stream_map::Chunk::Data(vm_spec::capture::Sha256Digest::of_bytes(
                &std::fs::read(&ram_path).unwrap(),
            )),
        };
        let expected_diagnostic = format!("stream {ram_stream}: {authentication_error}");
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
                let fenced = FencedSource {
                    path,
                    file: stream.file().try_clone().unwrap(),
                    length: stream.length() + 512,
                };
                // The fenced input must not keep a second consumer map lease alive.
                drop(stream);
                PrivateSource::Fenced(fenced)
            } else {
                PrivateSource::Authenticated { path, stream }
            };
            let descriptor_peak = 64 + shape.retained_descriptors();
            snapshots
                .reserve_restore_resources(
                    &consumer,
                    vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + root.geometry.length,
                    descriptor_peak,
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
                matches!(&error, crate::LibVmError::InvalidStorageRecord { record: "snapshot", message } if message == &expected_diagnostic),
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
                        (SELECT count(*) FROM restore_resource_reservation WHERE operation_id=?1)",
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

    #[tokio::test]
    async fn publication_credit_resize_preserves_the_unchanged_lease_anchor_inode() {
        use std::os::unix::fs::MetadataExt;
        let fixture = crate::store::capture::tests::fixture().await;
        let store = &fixture.snapshots.store;
        let ledger = crate::store::restore::budget_directory(store).unwrap();
        let name = format!(
            "{}home.json",
            crate::store::restore::budget_prefix(store).unwrap()
        );
        let held = ledger.open_file(&name).unwrap().unwrap();
        let before = std::fs::read(ledger.path().join(&name)).unwrap();
        let record = &fixture.reservation.record;
        store
            .reserve_capture_publication(
                record,
                record.reservation_bytes - record.plan.reservation.staging_bytes,
            )
            .await
            .unwrap();
        let after = ledger.open_file(&name).unwrap().unwrap();
        assert_eq!(
            after.metadata().unwrap().ino(),
            held.metadata().unwrap().ino()
        );
        assert_eq!(std::fs::read(ledger.path().join(&name)).unwrap(), before);
        // Releasing native staging ownership really changes the anchor and
        // must still publish a replacement for cross-home lease accounting.
        fixture
            .snapshots
            .abandon_capture(record.capture_id)
            .await
            .unwrap();
        let released = ledger.open_file(&name).unwrap().unwrap();
        assert_ne!(
            released.metadata().unwrap().ino(),
            held.metadata().unwrap().ino()
        );
        assert_ne!(std::fs::read(ledger.path().join(&name)).unwrap(), before);
    }
}

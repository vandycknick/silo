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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RestoreIntent {
    pub checkpoint: SnapshotId,
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
}

impl RestoreMemoryCharge {
    fn validate(&self) -> Result<(), LibVmError> {
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

#[derive(Default)]
struct RestoreBudget {
    memory: u64,
    baselines: std::collections::BTreeMap<(u64, u64), u64>,
    disks: std::collections::BTreeMap<u64, u64>,
}

impl RestoreBudget {
    fn add(&mut self, charge: &RestoreMemoryCharge) -> Result<(), LibVmError> {
        charge.validate()?;
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
        let mut budget = Self::default();
        let mut bytes = Vec::new();
        for name in budget_entries(directory)? {
            let file = directory
                .open_file(&name)?
                .ok_or_else(|| invalid("restore budget record disappeared"))?;
            bytes.clear();
            file.take((64 << 10) + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 << 10 {
                return Err(invalid("restore budget record exceeds 64 KiB"));
            }
            let charge: RestoreMemoryCharge = serde_json::from_slice(&bytes).map_err(invalid)?;
            budget.add(&charge)?;
        }
        Ok(budget)
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
            || self.checkpoint.as_bytes() != self.request.checkpoint.as_bytes()
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

impl SnapshotStore {
    /// Only catalog-authenticated local capture provenance grants executable
    /// authority here. Hash-valid bytes without that provenance are not enough.
    pub(crate) fn restore_evidence(
        &self,
        consumer: &SnapshotConsumer,
        pool: &crate::storage::pool::StoragePool,
    ) -> Result<vm_spec::capture::CaptureEvidence, LibVmError> {
        let configuration =
            vm_spec::capture::CaptureConfiguration::from_spec(&consumer.record.configuration.spec)
                .map_err(invalid)?;
        let execution = match &consumer.record.capture {
            crate::store::models::snapshot::SnapshotCaptureKind::LiveExecution { execution } => {
                execution
            }
            _ => return Err(invalid("execution restore requires a live checkpoint")),
        };
        if let Some(provenance) = consumer.info.provenance.first() {
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
            if let Some((_, pin)) = pins.into_iter().find(|(admitted, _)| !*admitted) {
                return Err(invalid(format!("restore compatibility pin {pin} differs from authenticated local capture provenance")));
            }
            return Ok(evidence);
        }
        Err(invalid(
            "execution checkpoint lacks authenticated local capture provenance",
        ))
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
        disk_parent: &Path,
        disk_peak: u64,
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
        let disk = crate::paths::OwnedDirectory::open_existing_root(disk_parent)?
            .ok_or_else(|| invalid("restore destination parent disappeared"))?;
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
        };
        self.store
            .reserve_restore_charge(consumer.operation_id, &charge, &disk, &budget_directory()?)
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

/// A single authenticated user authority coordinates all of its runtime homes.
/// No user-owned file is represented as host-global or cross-user authority.
fn budget_directory() -> Result<crate::paths::OwnedDirectory, LibVmError> {
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
        let directory = budget_directory()?;
        let _admission = crate::storage::locks::blocking(
            &directory,
            "admission.lock",
            nix::fcntl::FlockArg::LockExclusive,
        )?;
        let pool = crate::storage::pool::StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT json(o.record_json),r.budget_id FROM storage_operation o JOIN restore_memory_reservation r ON r.operation_id=o.operation_id JOIN machine_state s ON s.machine_id=o.machine_id WHERE o.operation_id=?1 AND o.run_id=?2 AND o.kind='launch' AND s.status='running' AND json_extract(s.state_json,'$.runId')=?2"
        ).bind(operation.to_string()).bind(run.to_string()).fetch_optional(&mut *tx).await?;
        let Some((json, budget_id)) = row else {
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
        publish_budget(
            tx,
            &directory,
            &budget_name(self, Uuid::parse_str(&budget_id).map_err(invalid)?)?,
            &charge,
            |_| {},
        )
        .await?;
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
        self.reconcile_restore_budget_in(&budget_directory()?).await
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
        for name in budget_entries(directory)? {
            let Some(id) = name
                .strip_prefix(&prefix)
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            let operation = Uuid::parse_str(id).map_err(invalid)?;
            let retained: Option<String> = sqlx::query_scalar(
                "SELECT json(charge_json) FROM restore_memory_reservation WHERE budget_id=?1",
            )
            .bind(operation.to_string())
            .fetch_optional(&self.pool)
            .await?;
            if let Some(charge) = retained {
                let decoded: RestoreMemoryCharge =
                    serde_json::from_str(&charge).map_err(invalid)?;
                decoded.validate()?;
                directory.write_file_atomic(&name, charge.as_bytes())?;
            } else {
                let generation: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE kind='launch' AND json_extract(record_json,'$.restore.consumerOperation')=?1)")
                    .bind(operation.to_string()).fetch_one(&self.pool).await?;
                if generation {
                    return Err(invalid("restore generation lost its quota owner"));
                }
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

#[cfg(test)]
mod tests {
    use crate::store::restore::{RestoreBudget, RestoreMemoryCharge};

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
        }
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
}

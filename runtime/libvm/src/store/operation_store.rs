//! Durable closure pins are independent of machine rows and close-only OFD leases.
//! Registration is short; slow readers retain the returned lease outside roots.
use std::io::Read;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::storage::identity::StreamId;
use crate::storage::locks::StorageLock;
use crate::storage::pool::StoragePool;
use crate::store::models::{MachineId, MachineState};
use crate::store::Store;
use crate::{LibVmError, MachineStorageRecord, StorageStopOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RetainedStorageOperation {
    pub operation_id: Uuid,
    pub machine_id: MachineId,
    pub run_id: Uuid,
    pub storage_generation: u64,
    pub admitted: bool,
    pub storage: MachineStorageRecord,
    pub disks: Vec<vm_spec::Disk>,
    pub external_resources: Vec<crate::ExternalResource>,
    pub restore: Option<crate::store::restore::RestoreIntent>,
}

pub(crate) struct LaunchStorageLease {
    record: RetainedStorageOperation,
    lease: StorageLock,
    directory: crate::paths::OwnedDirectory,
}
impl std::fmt::Debug for LaunchStorageLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchStorageLease")
            .field("operation_id", &self.record.operation_id)
            .finish_non_exhaustive()
    }
}
impl LaunchStorageLease {
    pub(crate) fn durability_directory(&self) -> &crate::paths::OwnedDirectory {
        &self.directory
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        self.record.operation_id
    }
    pub(crate) fn storage_record(&self) -> &MachineStorageRecord {
        &self.record.storage
    }
    pub(crate) fn lock(&self) -> &StorageLock {
        &self.lease
    }
    pub(crate) fn file_identity(&self) -> std::io::Result<(u64, u64)> {
        self.lease.file_identity()
    }
}

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "storage-operation",
        message: message.to_string(),
    }
}
fn validate_record(record: &RetainedStorageOperation) -> Result<(), LibVmError> {
    record
        .storage
        .validate_for_machine(record.machine_id.into())?;
    vm_spec::Storage::validate_disks(&record.disks).map_err(invalid)?;
    if record.operation_id.is_nil()
        || record.run_id.is_nil()
        || Uuid::from(record.machine_id).is_nil()
        || record.storage_generation != record.storage.storage_generation
    {
        return Err(invalid("invalid exact generation identity"));
    }
    if let Some(restore) = &record.restore {
        restore.validate()?;
        if record.storage.snapshot != restore.checkpoint.snapshot()
            || (record.admitted
                && (restore.request.ssh_trusted_ca.is_none()
                    || restore.network_attachment != restore.request.network.is_some()))
        {
            return Err(invalid(
                "restore generation provenance or activation binding is incomplete",
            ));
        }
        if record.disks.len() != restore.request.configuration.attachments.len()
            || record
                .disks
                .iter()
                .zip(&restore.request.configuration.attachments)
                .any(|(disk, attachment)| {
                    disk.block_id != attachment.block_id
                        || disk.role != attachment.role
                        || disk.format != attachment.format
                        || disk.geometry != attachment.geometry
                        || disk.read_only != attachment.read_only
                })
        {
            return Err(invalid(
                "restore generation attachments differ from the captured configuration",
            ));
        }
    }
    for resource in &record.external_resources {
        let path = match resource {
            crate::ExternalResource::Disk { path, .. } => path,
            crate::ExternalResource::Share { source, .. } => source,
        };
        if !path.is_absolute() {
            return Err(invalid("retained external resource is not absolute"));
        }
    }
    Ok(())
}
pub(crate) fn encode(record: &RetainedStorageOperation) -> Result<String, LibVmError> {
    validate_record(record)?;
    let json = serde_json::to_string(record).map_err(|error| invalid(error.to_string()))?;
    crate::storage::limits::Resource::MetadataPageBytes
        .check(json.len() as u64)
        .map_err(crate::storage::StorageError::from)?;
    Ok(json)
}
fn decode(row: &sqlx::sqlite::SqliteRow) -> Result<RetainedStorageOperation, LibVmError> {
    let json: String = row.try_get("record_json")?;
    crate::storage::limits::Resource::MetadataPageBytes
        .check(json.len() as u64)
        .map_err(crate::storage::StorageError::from)?;
    let record: RetainedStorageOperation =
        serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
    validate_record(&record)?;
    let id: String = row.try_get("operation_id")?;
    let machine: String = row.try_get("machine_id")?;
    let run: String = row.try_get("run_id")?;
    let generation: i64 = row.try_get("storage_generation")?;
    let schema: i64 = row.try_get("schema")?;
    let kind: String = row.try_get("kind")?;
    let state: String = row.try_get("state")?;
    if schema != 1
        || kind != "launch"
        || state != "prepared"
        || id != record.operation_id.to_string()
        || machine != record.machine_id.to_string()
        || run != record.run_id.to_string()
        || u64::try_from(generation).ok() != Some(record.storage_generation)
    {
        return Err(invalid("indexed operation identity contradicts its record"));
    }
    Ok(record)
}
const SELECT_LAUNCH_BY_OPERATION: &str = "SELECT operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,CASE WHEN json_valid(record_json,8) THEN json(record_json) ELSE '{}' END AS record_json FROM storage_operation WHERE kind='launch' AND operation_id=?1";
const SELECT_LAUNCH_BY_MACHINE: &str = "SELECT operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,CASE WHEN json_valid(record_json,8) THEN json(record_json) ELSE '{}' END AS record_json FROM storage_operation WHERE kind='launch' AND machine_id=?1 ORDER BY operation_id";

fn validate_lease_identity(
    row: &sqlx::sqlite::SqliteRow,
    lease: &StorageLock,
) -> Result<(), LibVmError> {
    validate_lease_metadata(row, lease.file_identity()?)
}

fn validate_lease_metadata(
    row: &sqlx::sqlite::SqliteRow,
    (device, inode): (u64, u64),
) -> Result<(), LibVmError> {
    let expected_device: String = row.try_get("file_device")?;
    let expected_inode: String = row.try_get("file_inode")?;
    if expected_device != device.to_string() || expected_inode != inode.to_string() {
        return Err(invalid("stable operation lease inode was replaced"));
    }
    Ok(())
}

/// Record-local launch admission. The layered lower's VMDK resource preflight
/// needs its leased retained occurrences and runs in `root_storage::prepare`
/// before any descriptor is encoded or backing opened.
pub(crate) fn preflight_launch_storage(
    storage: &MachineStorageRecord,
    spec: &vm_spec::VmSpec,
) -> Result<(), LibVmError> {
    storage.validate()?;
    if let Some(disks) = &spec.storage {
        disks.validate().map_err(invalid)?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoppedCommitCandidate {
    candidate_machine_id: Option<MachineId>,
    candidate_snapshot_id: Option<crate::storage::identity::SnapshotId>,
    candidate_image_id: Option<crate::storage::identity::ImageId>,
    candidate_index_digest: Option<crate::storage::identity::ObjectDigest>,
    directory: Option<CandidateDirectory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateDirectory {
    device: String,
    inode: String,
}

#[allow(clippy::unnecessary_cast)]
fn directory_identity(directory: &crate::paths::OwnedDirectory) -> Result<(u64, u64), LibVmError> {
    let stat = nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?;
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

fn commit_candidate(json: &str) -> Result<StoppedCommitCandidate, LibVmError> {
    let candidate: StoppedCommitCandidate = serde_json::from_str(json).map_err(invalid)?;
    if let Some(directory) = &candidate.directory {
        for value in [&directory.device, &directory.inode] {
            if value.parse::<u64>().map_err(invalid)?.to_string() != *value {
                return Err(invalid(
                    "candidate directory identity is not canonical decimal",
                ));
            }
        }
    }
    if candidate.candidate_index_digest.is_some() && candidate.candidate_machine_id.is_some() {
        return Err(invalid(
            "artifact acquisition index cannot authorize a machine directory",
        ));
    }
    match (
        &candidate.candidate_machine_id,
        &candidate.candidate_snapshot_id,
        &candidate.candidate_image_id,
        &candidate.directory,
    ) {
        (Some(machine), None, None, Some(_)) if !Uuid::from(*machine).is_nil() => Ok(candidate),
        (None, Some(_), None, None) | (None, None, Some(_), None) => Ok(candidate),
        _ => Err(invalid("committing operation must name exactly one result")),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootUpdateCandidate {
    machine_id: MachineId,
    generation: u64,
    bundle: crate::storage::identity::ObjectDigest,
}

fn boot_update_candidate(json: &str) -> Result<BootUpdateCandidate, LibVmError> {
    let candidate: BootUpdateCandidate = serde_json::from_str(json).map_err(invalid)?;
    if Uuid::from(candidate.machine_id).is_nil() || candidate.generation == 0 {
        return Err(invalid(
            "boot update candidate requires machine and target generation",
        ));
    }
    crate::storage::limits::Resource::JsonInteger
        .check(candidate.generation)
        .map_err(crate::storage::StorageError::from)?;
    Ok(candidate)
}

/// A cleanup namespace is operation-owned, not a mutable machine slot. The
/// cleaning catalog root fences new external references until durable removal.
struct MachineCleanup {
    parent: Option<crate::paths::OwnedDirectory>,
    source_name: String,
    quarantine_name: String,
    expected: (u64, u64),
    #[cfg(test)]
    hook: Option<std::sync::Arc<crate::store::layer_store::tests::WorkerHook>>,
}

impl MachineCleanup {
    /// Called with roots held, after the cleaning transition has committed.
    /// This is one atomic detach, never recursive work or directory fsync.
    fn detach(&self) -> Result<(), LibVmError> {
        let Some(parent) = &self.parent else {
            return Ok(());
        };
        let source = parent.open_dir(&self.source_name)?;
        let quarantine = parent.open_dir(&self.quarantine_name)?;
        if source.is_some() && quarantine.is_some() {
            return Err(invalid("both source and cleanup quarantine are occupied"));
        }
        if let Some(directory) = source {
            if directory_identity(&directory)? != self.expected {
                return Err(invalid("stopped destination directory was replaced"));
            }
            crate::storage::pool::rename_component_no_replace(
                parent,
                &self.source_name,
                parent,
                &self.quarantine_name,
            )?;
        } else if let Some(directory) = quarantine {
            if directory_identity(&directory)? != self.expected {
                return Err(invalid("cleanup quarantine directory was replaced"));
            }
        }
        Ok(())
    }

    /// The blocking worker retains the exclusive operation OFD and catalog.
    /// No root lock or SQL transaction survives into recursive removal/sync.
    fn remove(&self, home: &std::path::Path) -> Result<(), LibVmError> {
        if let Some(parent) = &self.parent {
            if let Some(directory) = parent.open_dir(&self.quarantine_name)? {
                if directory_identity(&directory)? != self.expected {
                    return Err(invalid("cleanup quarantine directory was replaced"));
                }
                #[cfg(test)]
                if let Some(hook) = &self.hook {
                    hook.hit(
                        crate::store::layer_store::tests::WorkerPoint::CandidateDirectoryVerified,
                    )?;
                }
                parent.remove_open_tree(&self.quarantine_name, &directory)?;
                drop(directory);
            }
            parent.sync()?;
        } else {
            crate::paths::OwnedDirectory::open_existing_root(home)?
                .ok_or_else(|| invalid("candidate catalog home disappeared"))?
                .sync()?;
        }
        Ok(())
    }

    fn recheck_absence(&self) -> Result<(), LibVmError> {
        if let Some(parent) = &self.parent {
            let current = crate::paths::OwnedDirectory::open_existing_root(parent.path())?
                .ok_or_else(|| invalid("candidate parent disappeared during cleanup"))?;
            if directory_identity(&current)? != directory_identity(parent)? {
                return Err(invalid("candidate parent was replaced during cleanup"));
            }
            if parent.open_dir(&self.source_name)?.is_some()
                || parent.open_dir(&self.quarantine_name)?.is_some()
            {
                return Err(invalid("candidate namespace changed during cleanup"));
            }
        }
        Ok(())
    }
}

/// Text evidence is outside both the source machine and the disposable staging
/// namespace. The owner file is linked last, before cleanup authorization.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaptureCleanupOwner {
    schema: u32,
    record: crate::store::snapshot_store::CaptureRecord,
    parent: Option<CandidateDirectory>,
    directory: Option<CandidateDirectory>,
}

struct CaptureCleanup {
    tree: MachineCleanup,
    archive: crate::paths::OwnedDirectory,
    owner: CaptureCleanupOwner,
    saved: bool,
}

fn recorded_directory(
    directory: &crate::paths::OwnedDirectory,
) -> Result<CandidateDirectory, LibVmError> {
    let (device, inode) = directory_identity(directory)?;
    Ok(CandidateDirectory {
        device: device.to_string(),
        inode: inode.to_string(),
    })
}

fn read_cleanup_text(
    directory: &crate::paths::OwnedDirectory,
    name: &str,
    maximum: u64,
) -> Result<Option<Vec<u8>>, LibVmError> {
    let Some(file) = directory.open_file(name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid(format!(
            "capture diagnostic {name} exceeds its bound"
        )));
    }
    Ok(Some(bytes))
}

fn capture_cleanup_parent(
    home: &crate::paths::OwnedDirectory,
    machine: MachineId,
) -> Result<Option<crate::paths::OwnedDirectory>, LibVmError> {
    if let Some(machines) = home.open_dir("machines")? {
        if let Some(machine) = machines.open_dir(&machine.to_string())? {
            return machine.open_dir(vm_spec::capture::CAPTURES_DIRECTORY);
        }
    }
    Ok(None)
}

impl CaptureCleanup {
    fn prepare(
        store: &Store,
        record: &crate::store::snapshot_store::CaptureRecord,
        cleaning: bool,
    ) -> Result<Self, LibVmError> {
        let home = crate::paths::OwnedDirectory::open_existing_root(&store.home)?
            .ok_or_else(|| invalid("capture catalog home disappeared"))?;
        let archive = home
            .ensure_dir("capture-evidence")?
            .ensure_dir(&record.capture_id.to_string())?;
        let parent = capture_cleanup_parent(&home, record.machine_id)?;
        let source_name = record.capture_id.to_string();
        let quarantine_name = format!(".retiring-{}", record.capture_id);
        let source = parent
            .as_ref()
            .map(|p| p.open_dir(&source_name))
            .transpose()?
            .flatten();
        let quarantine = parent
            .as_ref()
            .map(|p| p.open_dir(&quarantine_name))
            .transpose()?
            .flatten();
        if source.is_some() && quarantine.is_some() {
            return Err(invalid("both capture staging names are occupied"));
        }
        if !cleaning && quarantine.is_some() {
            return Err(invalid("unowned capture cleanup quarantine"));
        }
        let saved = read_cleanup_text(
            &archive,
            "owner.json",
            crate::storage::limits::Resource::MetadataPageBytes.maximum() * 2,
        )?;
        let owner = match &saved {
            Some(bytes) => {
                let owner: CaptureCleanupOwner = serde_json::from_slice(bytes).map_err(invalid)?;
                // Release/source observation can advance before the cleaning
                // fence commits. They cannot change staging ownership or its
                // immutable plan, and must not strand an already saved archive.
                if owner.schema != 1
                    || owner.record.capture_id != record.capture_id
                    || owner.record.machine_id != record.machine_id
                    || owner.record.run_id != record.run_id
                    || owner.record.launch_operation_id != record.launch_operation_id
                    || owner.record.plan != record.plan
                    || owner.record.candidate != record.candidate
                    || owner.record.evidence != record.evidence
                {
                    return Err(invalid(
                        "capture cleanup authority contradicts terminal record",
                    ));
                }
                owner
            }
            None if cleaning => {
                return Err(invalid("capture cleanup has no durable evidence owner"))
            }
            None => CaptureCleanupOwner {
                schema: 1,
                record: record.clone(),
                parent: parent.as_ref().map(recorded_directory).transpose()?,
                directory: source.as_ref().map(recorded_directory).transpose()?,
            },
        };
        if parent.as_ref().map(recorded_directory).transpose()? != owner.parent {
            return Err(invalid("capture staging parent was replaced"));
        }
        for directory in source.iter().chain(quarantine.iter()) {
            if Some(recorded_directory(directory)?) != owner.directory {
                return Err(invalid("capture staging directory was replaced"));
            }
        }
        let expected = owner
            .directory
            .as_ref()
            .map(|directory| {
                Ok::<_, LibVmError>((
                    directory.device.parse::<u64>().map_err(invalid)?,
                    directory.inode.parse::<u64>().map_err(invalid)?,
                ))
            })
            .transpose()?
            .unwrap_or((0, 0));
        Ok(Self {
            tree: MachineCleanup {
                parent,
                source_name,
                quarantine_name,
                expected,
                #[cfg(test)]
                hook: store.layer_hook.clone(),
            },
            archive,
            owner,
            saved: saved.is_some(),
        })
    }

    fn paths(&self, home: &std::path::Path) -> Vec<std::path::PathBuf> {
        let parent = crate::paths::machine_data_dir_in(home, self.owner.record.machine_id)
            .join(vm_spec::capture::CAPTURES_DIRECTORY);
        vec![
            parent.join(&self.tree.source_name),
            parent.join(&self.tree.quarantine_name),
        ]
    }

    /// Preserve exact diagnostic bytes, including malformed failure records.
    /// Oversized or unsafe evidence fails closed without deleting bulk data.
    fn preserve_evidence(&self) -> Result<(), LibVmError> {
        if self.saved {
            return self.archive.sync();
        }
        if let Some(parent) = &self.tree.parent {
            if let Some(source) = parent.open_dir(&self.tree.source_name)? {
                if directory_identity(&source)? != self.tree.expected {
                    return Err(invalid("capture staging changed before evidence retention"));
                }
                for name in [
                    "request.json",
                    "vm.capture.json",
                    "vm.capture-source.json",
                    "memory-layout.json",
                ] {
                    if let Some(bytes) = read_cleanup_text(
                        &source,
                        name,
                        crate::storage::limits::Resource::MetadataPageBytes.maximum(),
                    )? {
                        self.archive.write_file(name, &bytes)?;
                    }
                }
            } else if self.owner.directory.is_some() {
                return Err(invalid(
                    "capture staging disappeared before evidence retention",
                ));
            }
        }
        let bytes = serde_json::to_vec(&self.owner).map_err(invalid)?;
        if bytes.len() as u64 > crate::storage::limits::Resource::MetadataPageBytes.maximum() * 2 {
            return Err(invalid("capture cleanup owner exceeds its bound"));
        }
        let temporary = format!(".owner-{}", Uuid::new_v4());
        self.archive.write_file(&temporary, &bytes)?;
        crate::storage::pool::rename_component_no_replace(
            &self.archive,
            &temporary,
            &self.archive,
            "owner.json",
        )?;
        self.archive.sync()?;
        Ok(())
    }

    fn recheck_absence(&self, home: &std::path::Path) -> Result<(), LibVmError> {
        let home = crate::paths::OwnedDirectory::open_existing_root(home)?
            .ok_or_else(|| invalid("capture catalog home disappeared"))?;
        let parent = capture_cleanup_parent(&home, self.owner.record.machine_id)?;
        if parent.as_ref().map(recorded_directory).transpose()? != self.owner.parent {
            return Err(invalid("capture staging parent changed during cleanup"));
        }
        self.tree.recheck_absence()
    }
}

impl Store {
    pub(crate) async fn check_cleaning_dependencies(
        &self,
        connection: &mut sqlx::SqliteConnection,
        paths: &crate::store::cache_paths::ConfigurationPaths,
    ) -> Result<(), LibVmError> {
        let rows = sqlx::query("SELECT operation_id,kind,json(record_json) AS record_json FROM storage_operation WHERE state='cleaning'")
            .fetch_all(connection).await?;
        for row in rows {
            let operation: Uuid = row
                .try_get::<String, _>("operation_id")?
                .parse()
                .map_err(invalid)?;
            let capture_staging = row.try_get::<String, _>("kind")? == "capture";
            let (source, quarantine) = if capture_staging {
                let capture = crate::store::capture::decode_record(
                    &row.try_get::<String, _>("record_json")?,
                )?;
                let parent = paths
                    .machines
                    .join(capture.machine_id.to_string())
                    .join(vm_spec::capture::CAPTURES_DIRECTORY);
                (
                    parent.join(operation.to_string()),
                    parent.join(format!(".retiring-{operation}")),
                )
            } else {
                let candidate = commit_candidate(&row.try_get::<String, _>("record_json")?)?;
                let machine = candidate
                    .candidate_machine_id
                    .ok_or_else(|| invalid("cleanup root has no machine candidate"))?;
                (
                    paths.machines.join(machine.to_string()),
                    paths.machines.join(format!(".retiring-{operation}")),
                )
            };
            for (resource, directory) in paths.resources.iter().skip(usize::from(capture_staging)) {
                if [&source, &quarantine].iter().any(|candidate| {
                    resource.starts_with(candidate)
                        || (*directory && candidate.starts_with(resource))
                }) {
                    return Err(LibVmError::CacheDependency {
                        machine: format!("cleanup operation {operation}"),
                        path: resource.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Register the complete consumed closure before any artifact byte is read.
    /// The original close-only shared OFD moves into the real blocking owner.
    pub(crate) async fn begin_stopped_operation(
        &self,
        kind: &str,
        streams: &[StreamId],
        objects: &[crate::storage::identity::ObjectDigest],
    ) -> Result<(Uuid, StorageLock), LibVmError> {
        if !matches!(
            kind,
            "snapshot" | "fork" | "import" | "update-boot-assets" | "raw-export"
        ) {
            return Err(invalid("unsupported stopped operation kind"));
        }
        let id = Uuid::new_v4();
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let lease = pool.lease(id)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::insert_stopped_operation(&mut tx, id, kind, &lease, streams, objects).await?;
        tx.commit().await?;
        Ok((id, lease))
    }

    pub(crate) async fn insert_stopped_operation(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        id: Uuid,
        kind: &str,
        lease: &StorageLock,
        streams: &[StreamId],
        objects: &[crate::storage::identity::ObjectDigest],
    ) -> Result<(), LibVmError> {
        if id.is_nil()
            || !matches!(
                kind,
                "snapshot" | "fork" | "import" | "update-boot-assets" | "raw-export"
            )
        {
            return Err(invalid("invalid stopped operation"));
        }
        let (device, inode) = lease.file_identity()?;
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,?2,'staging',?3,?4,jsonb('{}'))")
            .bind(id.to_string()).bind(kind).bind(device.to_string()).bind(inode.to_string()).execute(&mut **tx).await?;
        for stream in streams {
            insert_stream(tx, id, stream).await?;
        }
        for object in objects {
            sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) VALUES(?1,?2)")
                .bind(id.to_string()).bind(object.to_string()).execute(&mut **tx).await?;
        }
        Ok(())
    }

    /// Record destination authority before a possibly uncertain machine commit.
    pub(crate) async fn preserve_stopped_operation(
        &self,
        id: Uuid,
        destination: MachineId,
    ) -> Result<(), LibVmError> {
        if Uuid::from(destination).is_nil() {
            return Err(invalid("nil stopped destination"));
        }
        let path = crate::paths::machine_data_dir_in(&self.home, destination);
        let directory = crate::paths::OwnedDirectory::open_existing_root(&path)?
            .ok_or_else(|| invalid("stopped destination directory is absent"))?;
        let (device, inode) = directory_identity(&directory)?;
        self.preserve_stopped_candidate(
            id,
            &serde_json::json!({
                "candidateMachineId": destination,
                "directory": {"device": device.to_string(), "inode": inode.to_string()},
            })
            .to_string(),
        )
        .await
    }

    pub(crate) async fn preserve_snapshot_operation(
        &self,
        id: Uuid,
        destination: crate::storage::identity::SnapshotId,
    ) -> Result<(), LibVmError> {
        self.preserve_stopped_candidate(
            id,
            &serde_json::json!({"candidateSnapshotId": destination}).to_string(),
        )
        .await
    }

    pub(crate) async fn preserve_image_operation(
        &self,
        id: Uuid,
        destination: crate::storage::identity::ImageId,
    ) -> Result<(), LibVmError> {
        self.preserve_stopped_candidate(
            id,
            &serde_json::json!({"candidateImageId": destination}).to_string(),
        )
        .await
    }

    pub(crate) async fn preserve_imported_operation(
        &self,
        id: Uuid,
        target: crate::image::import_types::ManagedSourceId,
        index: crate::storage::identity::ObjectDigest,
    ) -> Result<(), LibVmError> {
        let json = match target {
            crate::image::import_types::ManagedSourceId::Image(id) => {
                serde_json::json!({"candidateImageId":id,"candidateIndexDigest":index})
            }
            crate::image::import_types::ManagedSourceId::Snapshot(id) => {
                serde_json::json!({"candidateSnapshotId":id,"candidateIndexDigest":index})
            }
        };
        self.preserve_stopped_candidate(id, &json.to_string()).await
    }

    /// Existing machine update authority is never destination-directory cleanup
    /// authority. Retain the precise target for uncertain atomic storage saves.
    pub(crate) async fn preserve_boot_update_operation(
        &self,
        operation: Uuid,
        machine: MachineId,
        generation: u64,
        bundle: crate::storage::identity::ObjectDigest,
    ) -> Result<(), LibVmError> {
        let json = serde_json::to_string(&BootUpdateCandidate {
            machine_id: machine,
            generation,
            bundle,
        })
        .map_err(invalid)?;
        boot_update_candidate(&json)?;
        crate::store::snapshot_store::require_operation_closure(
            self,
            operation,
            &std::collections::BTreeSet::new(),
            &std::collections::BTreeSet::from([bundle]),
            None,
        )
        .await?;
        let pool = StoragePool::open(&self.images_dir)?;
        let binding = crate::BootBinding::decode(&pool.read_object(
            &bundle,
            crate::storage::limits::Resource::MetadataPageBytes.maximum(),
        )?)?;
        if binding.digest()? != bundle {
            return Err(invalid("boot update bundle identity contradiction"));
        }
        let _roots = pool.lock_roots()?;
        let changed = sqlx::query("UPDATE storage_operation SET state='committing',machine_id=?2,storage_generation=?3,record_json=jsonb(?4) WHERE operation_id=?1 AND kind='update-boot-assets' AND state='staging'")
            .bind(operation.to_string()).bind(machine.to_string()).bind(i64::try_from(generation).map_err(invalid)?).bind(json).execute(&self.pool).await?;
        if changed.rows_affected() != 1 {
            return Err(invalid("boot update operation is not staging"));
        }
        Ok(())
    }

    async fn retire_boot_update_operations(&self, pool: &StoragePool) -> Result<(), LibVmError> {
        let mut cursor = String::new();
        loop {
            let rows = sqlx::query("SELECT operation_id,state,json(record_json) AS record_json FROM storage_operation WHERE kind='update-boot-assets' AND operation_id>?1 ORDER BY operation_id LIMIT 256")
                .bind(&cursor).fetch_all(&self.pool).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.try_get("operation_id")?;
                let operation = cursor.parse().map_err(invalid)?;
                let state: String = row.try_get("state")?;
                let json: String = row.try_get("record_json")?;
                let candidate = if state == "committing" {
                    Some(boot_update_candidate(&json)?)
                } else {
                    None
                };
                // Metadata authentication, including bundle hashing, stays
                // outside roots and the write transaction.
                let observed: Option<String> = if let Some(candidate) = &candidate {
                    let bytes: Option<String> = sqlx::query_scalar(
                        "SELECT CAST(record_json AS TEXT) FROM machine_storage WHERE machine_id=?1",
                    )
                    .bind(candidate.machine_id.to_string())
                    .fetch_optional(&self.pool)
                    .await?;
                    if let Some(bytes) = &bytes {
                        let storage = MachineStorageRecord::decode(bytes)?;
                        if storage.storage_generation < candidate.generation.saturating_sub(1) {
                            return Err(invalid(
                                "boot update recovery found an older unrelated generation",
                            ));
                        }
                        if storage.storage_generation == candidate.generation {
                            let crate::BootProfile::LinuxDirect { binding, .. } = &storage.boot
                            else {
                                return Err(invalid("boot update committed a different profile"));
                            };
                            if binding.digest()? != candidate.bundle {
                                return Err(invalid(
                                    "boot update committed a contradictory bundle",
                                ));
                            }
                        }
                    }
                    bytes
                } else {
                    None
                };
                let _roots = pool.lock_roots()?;
                let Some(lease) = pool.try_exclusive_lease(operation)? else {
                    continue;
                };
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                let current = sqlx::query("SELECT state,json(record_json) AS record_json,file_device,file_inode FROM storage_operation WHERE operation_id=?1 AND kind='update-boot-assets'")
                    .bind(operation.to_string()).fetch_optional(&mut *tx).await?;
                let Some(current) = current else {
                    tx.commit().await?;
                    continue;
                };
                validate_lease_identity(&current, &lease)?;
                if current.try_get::<String, _>("state")? != state
                    || current.try_get::<String, _>("record_json")? != json
                {
                    tx.commit().await?;
                    continue;
                }
                if let Some(candidate) = candidate {
                    let actual: Option<String> = sqlx::query_scalar(
                        "SELECT CAST(record_json AS TEXT) FROM machine_storage WHERE machine_id=?1",
                    )
                    .bind(candidate.machine_id.to_string())
                    .fetch_optional(&mut *tx)
                    .await?;
                    if actual != observed {
                        tx.commit().await?;
                        continue;
                    }
                }
                sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                    .bind(operation.to_string())
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        Ok(())
    }

    async fn preserve_stopped_candidate(&self, id: Uuid, json: &str) -> Result<(), LibVmError> {
        let candidate = commit_candidate(json)?;
        let snapshot = candidate.candidate_snapshot_id.is_some();
        let image = candidate.candidate_image_id.is_some();
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let result = sqlx::query("UPDATE storage_operation SET state='committing',record_json=jsonb(?2) WHERE operation_id=?1 AND ((?3 AND kind IN ('snapshot','import')) OR (?4 AND kind IN ('import','convert')) OR (NOT ?3 AND NOT ?4 AND kind IN ('fork','import'))) AND state='staging'")
            .bind(id.to_string()).bind(json).bind(snapshot).bind(image).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(invalid("stopped operation is not staging"));
        }
        Ok(())
    }

    async fn prepare_stopped_machine_cleanup(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        operation: Uuid,
        state: &str,
        machine: MachineId,
        candidate: &CandidateDirectory,
    ) -> Result<Option<MachineCleanup>, LibVmError> {
        let path = crate::paths::machine_data_dir_in(&self.home, machine);
        let parent_path = path
            .parent()
            .ok_or_else(|| invalid("candidate has no parent"))?;
        let parent = crate::paths::OwnedDirectory::open_existing_root(parent_path)?;
        let source_name = machine.to_string();
        let quarantine_name = format!(".retiring-{operation}");
        let directory = match &parent {
            Some(parent) => parent.open_dir(&source_name)?,
            None => None,
        };
        let quarantine = match &parent {
            Some(parent) => parent.open_dir(&quarantine_name)?,
            None => None,
        };
        let expected = (
            candidate.device.parse::<u64>().map_err(invalid)?,
            candidate.inode.parse::<u64>().map_err(invalid)?,
        );
        for directory in directory.iter().chain(quarantine.iter()) {
            if directory_identity(directory)? != expected {
                return Err(invalid(
                    "stopped candidate or cleanup quarantine was replaced",
                ));
            }
        }
        if directory.is_some() && quarantine.is_some() {
            return Err(invalid("both stopped candidate names are occupied"));
        }
        if state == "committing" && quarantine.is_some() {
            return Err(invalid("unowned cleanup quarantine collision"));
        }
        let committed = sqlx::query(
            "SELECT id,name,json(config_json) AS config_json FROM machine_config WHERE id=?1",
        )
        .bind(machine.to_string())
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(row) = committed {
            if state == "cleaning" {
                return Err(invalid(
                    "cleanup candidate acquired a committed machine root",
                ));
            }
            let crate::store::row::DbMachineConfig(config) =
                crate::store::row::DbMachineConfig::from_row_in(&row, &self.home)?;
            if config.id != machine || directory.is_none() {
                return Err(invalid(
                    "committed stopped destination identity is inconsistent",
                ));
            }
            let json = sqlx::query_scalar::<_, String>(
                "SELECT json(record_json) FROM machine_storage WHERE machine_id=?1",
            )
            .bind(machine.to_string())
            .fetch_one(&mut **tx)
            .await?;
            MachineStorageRecord::decode(&json)?.validate_for_machine(machine.into())?;
            let construction: Option<String> = sqlx::query_scalar("SELECT json(construction_json) FROM restore_memory_reservation WHERE operation_id=?1 AND construction_json IS NOT NULL")
                .bind(operation.to_string()).fetch_optional(&mut **tx).await?;
            let construction = construction
                .as_deref()
                .map(serde_json::from_str::<crate::store::restore::RestoreConstruction>)
                .transpose()
                .map_err(invalid)?;
            let launched: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE kind='launch' AND machine_id=?1)")
                .bind(machine.to_string()).fetch_one(&mut **tx).await?;
            let runtime = sqlx::query_as::<_, crate::store::row::DbMachineState>("SELECT machine_id,status,json(state_json) AS state_json FROM machine_state WHERE machine_id=?1")
                .bind(machine.to_string()).fetch_optional(&mut **tx).await?;
            let never_submitted = config.image_ref == "execution-restore"
                && !launched
                && construction.as_ref().is_some_and(|construction| {
                    runtime
                        .as_ref()
                        .is_some_and(|crate::store::row::DbMachineState(state)| {
                            state.status == crate::store::models::MachineRuntimeState::Restoring
                                && state.vmm_pid.is_none()
                                && state
                                    .run_id
                                    .as_deref()
                                    .and_then(|run| Uuid::parse_str(run).ok())
                                    == Some(construction.run_id)
                        })
                });
            if !never_submitted {
                return Ok(None);
            }
            // Generation registration always precedes submission. Retire a
            // never-submitted child through the existing cleanup quarantine.
            sqlx::query("DELETE FROM machine_config WHERE id=?1")
                .bind(machine.to_string())
                .execute(&mut **tx)
                .await?;
        }
        let quarantine_path = parent_path.join(&quarantine_name);
        crate::store::ensure_cache_paths_unreferenced(tx, &[path, quarantine_path], &self.home)
            .await?;
        sqlx::query("UPDATE storage_operation SET state='cleaning' WHERE operation_id=?1 AND state IN ('committing','cleaning')")
            .bind(operation.to_string()).execute(&mut **tx).await?;
        Ok(Some(MachineCleanup {
            parent,
            source_name,
            quarantine_name,
            expected,
            #[cfg(test)]
            hook: self.layer_hook.clone(),
        }))
    }

    /// Completion is metadata only. Dependencies are retired by the existing
    /// collector after the original OFD and every inherited duplicate close.
    pub(crate) async fn finish_stopped_operation(&self, id: Uuid) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let result = sqlx::query("UPDATE storage_operation SET state='committed',record_json=jsonb('{}') WHERE operation_id=?1 AND kind IN ('snapshot','fork','import','update-boot-assets','raw-export') AND state IN ('staging','committing','committed')")
            .bind(id.to_string()).execute(&self.pool).await?;
        if result.rows_affected() != 1 {
            return Err(invalid("stopped operation is not active"));
        }
        Ok(())
    }

    pub(crate) async fn begin_storage_operation_inner(
        &self,
        operation_id: Uuid,
    ) -> Result<StorageLock, LibVmError> {
        if operation_id.is_nil() {
            return Err(invalid("storage operation ID is nil"));
        }
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let lease = pool.lease(operation_id)?;
        let (device, inode) = lease.file_identity()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'convert','staging',?2,?3,jsonb('{}'))")
            .bind(operation_id.to_string()).bind(device.to_string()).bind(inode.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(lease)
    }

    /// The producer owns the returned publication roots guard through this
    /// transaction. A staging row alone never roots unregistered outputs.
    pub(crate) async fn pin_published_storage_dependencies(
        &self,
        operation_id: Uuid,
        streams: &[StreamId],
        objects: &[crate::storage::identity::ObjectDigest],
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND schema=1 AND kind IN ('convert','snapshot','capture','fork','import','relocate','update-boot-assets','raw-export') AND state='staging')")
            .bind(operation_id.to_string()).fetch_one(&mut *tx).await?;
        if !active {
            return Err(invalid(
                "published dependency has no active registered operation",
            ));
        }
        for stream in streams {
            insert_stream(&mut tx, operation_id, stream).await?;
        }
        for object in objects {
            sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) VALUES(?1,?2)")
                .bind(operation_id.to_string()).bind(object.to_string()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Called only by the existing blocking GC owners, before either collector
    /// walks bytes. Retire pins of abandoned non-launch producers first.
    pub(crate) async fn retire_abandoned_storage_operations(
        &self,
        pool: &StoragePool,
    ) -> Result<crate::store::models::CacheRecoveryReport, LibVmError> {
        self.check_operation_recovery(pool).await?;
        self.retire_boot_update_operations(pool).await?;
        let mut report = crate::store::models::CacheRecoveryReport::default();
        let mut cursor = String::new();
        loop {
            let ids = sqlx::query_scalar::<_,String>("SELECT operation_id FROM storage_operation WHERE operation_id>?1 ORDER BY operation_id LIMIT 256").bind(&cursor).fetch_all(&self.pool).await?;
            if ids.is_empty() {
                break;
            }
            for operation in ids {
                cursor = operation;
                let id = Uuid::parse_str(&cursor).map_err(|error| invalid(error.to_string()))?;
                let _roots = pool.lock_roots()?;
                let Some(_lease) = pool.try_exclusive_lease(id)? else {
                    report
                        .deferred
                        .push(crate::store::models::CacheCleanupDeferral::ActiveLease {
                            operation_id: id,
                        });
                    continue;
                };
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                // A vanished producer lease says nothing about the peer's
                // decision. Preserve every payload root until durable resolution.
                let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM handoff_operation WHERE operation_id=?1 AND terminal=0)")
                    .bind(&cursor).fetch_one(&mut *tx).await?;
                if unresolved {
                    tx.commit().await?;
                    continue;
                }
                let row = sqlx::query("SELECT kind,state,json(record_json) AS record_json,file_device,file_inode FROM storage_operation WHERE operation_id=?1").bind(&cursor).fetch_optional(&mut *tx).await?;
                if let Some(row) = row {
                    validate_lease_identity(&row, &_lease)?;
                    let kind: String = row.try_get("kind")?;
                    let state: String = row.try_get("state")?;
                    if matches!(kind.as_str(), "live-fork" | "update-boot-assets") {
                        // Retire parents after all producers in this sweep.
                        // Otherwise UUID ordering would require a second prune.
                        tx.commit().await?;
                        continue;
                    }
                    if kind == "import" {
                        // A recorded failure forbids resubmission. Once its
                        // consumer lease is exclusive, the reserved name must
                        // not prevent retirement and terminal reconciliation.
                        let reserved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM live_fork_child WHERE consumer_id=?1 AND name_reserved=1 AND failure_json IS NULL)").bind(&cursor).fetch_one(&mut *tx).await?;
                        if reserved {
                            tx.commit().await?;
                            continue;
                        }
                    }
                    if kind == "capture" {
                        let capture = crate::store::capture::decode_record(
                            &row.try_get::<String, _>("record_json")?,
                        )?;
                        if !matches!(
                            capture.state,
                            crate::store::snapshot_store::CaptureState::Released { .. }
                                | crate::store::snapshot_store::CaptureState::ReleasedLocal { .. }
                                | crate::store::snapshot_store::CaptureState::Abandoned
                        ) {
                            tx.commit().await?;
                            continue;
                        }
                        let fork_owned: bool = sqlx::query_scalar(
                            "SELECT EXISTS(SELECT 1 FROM live_fork WHERE capture_id=?1)",
                        )
                        .bind(capture.capture_id.to_string())
                        .fetch_one(&mut *tx)
                        .await?;
                        let intent:Option<(Option<String>,)>=sqlx::query_as("SELECT json(result_json) FROM live_command WHERE machine_id=?1 AND run_id=?2 AND request_id=?3").bind(capture.machine_id.to_string()).bind(capture.run_id.to_string()).bind(capture.capture_id.to_string()).fetch_optional(&mut *tx).await?;
                        let never_submitted = match intent {
                            None => true,
                            Some((Some(json),)) => matches!(
                                serde_json::from_str::<vm_spec::lifecycle::LiveCommandResult>(
                                    &json
                                )
                                .map_err(invalid)?,
                                vm_spec::lifecycle::LiveCommandResult::Capture(
                                    vm_spec::lifecycle::CaptureOutcome::Rejected { .. }
                                )
                            ),
                            Some((None,)) => false,
                        };
                        let unchanged = matches!(
                            capture.source_outcome,
                            Some(
                                crate::store::snapshot_store::CaptureSourceOutcome::Observed {
                                    continuation: vm_spec::capture::CaptureContinuation::Unchanged
                                }
                            )
                        );
                        let unused = fork_owned
                            && capture.evidence.is_none()
                            && (matches!(
                                capture.state,
                                crate::store::snapshot_store::CaptureState::Released {
                                    snapshot: None
                                }
                            ) || (never_submitted && unchanged));
                        let launch_lease = if unused {
                            None
                        } else {
                            let Some(lease) =
                                pool.try_exclusive_lease(capture.launch_operation_id)?
                            else {
                                report.deferred.push(
                                    crate::store::models::CacheCleanupDeferral::ActiveLease {
                                        operation_id: capture.launch_operation_id,
                                    },
                                );
                                tx.commit().await?;
                                continue;
                            };
                            Some(lease)
                        };
                        if let Some(launch_lease) = &launch_lease {
                            if launch_lease.file_identity()?
                                != (
                                    capture.plan.reservation.launch_lease.device,
                                    capture.plan.reservation.launch_lease.inode,
                                )
                            {
                                return Err(invalid("capture generation lease was replaced"));
                            }
                        }
                        // An inherited baseline needs both exclusive OFDs.
                        // A fenced no-cut fork instead has positive no-use proof.
                        tx.commit().await?;
                        drop(_roots);
                        let cleanup = CaptureCleanup::prepare(self, &capture, state == "cleaning")?;
                        cleanup.preserve_evidence()?;
                        let _roots = pool.lock_roots()?;
                        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                        let current = sqlx::query("SELECT state,json(record_json) AS record_json,file_device,file_inode FROM storage_operation WHERE operation_id=?1 AND kind='capture'")
                            .bind(&cursor).fetch_one(&mut *tx).await?;
                        validate_lease_identity(&current, &_lease)?;
                        if crate::store::capture::decode_record(
                            &current.try_get::<String, _>("record_json")?,
                        )? != capture
                        {
                            return Err(invalid("terminal capture changed before cleanup"));
                        }
                        crate::store::cache_paths::ensure_capture_paths_unreferenced(
                            &mut tx,
                            &cleanup.paths(&self.home),
                            &self.home,
                        )
                        .await?;
                        sqlx::query("UPDATE storage_operation SET state='cleaning' WHERE operation_id=?1 AND kind='capture'")
                            .bind(&cursor).execute(&mut *tx).await?;
                        tx.commit().await?;
                        self.checkpoint_catalog().await?;
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateAuthorized,
                            )?;
                        }
                        cleanup.tree.detach()?;
                        drop(_roots);
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateDetached,
                            )?;
                        }
                        cleanup.tree.remove(&self.home)?;
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateRemoved,
                            )?;
                        }
                        let _roots = pool.lock_roots()?;
                        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                        let current = sqlx::query("SELECT state,json(record_json) AS record_json,file_device,file_inode FROM storage_operation WHERE operation_id=?1 AND kind='capture'")
                            .bind(&cursor).fetch_one(&mut *tx).await?;
                        validate_lease_identity(&current, &_lease)?;
                        if current.try_get::<String, _>("state")? != "cleaning"
                            || crate::store::capture::decode_record(
                                &current.try_get::<String, _>("record_json")?,
                            )? != capture
                        {
                            return Err(invalid("terminal capture changed during cleanup"));
                        }
                        crate::store::cache_paths::ensure_capture_paths_unreferenced(
                            &mut tx,
                            &cleanup.paths(&self.home),
                            &self.home,
                        )
                        .await?;
                        cleanup.recheck_absence(&self.home)?;
                        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                            .bind(&cursor)
                            .execute(&mut *tx)
                            .await?;
                        if let Some(snapshot) = capture.candidate {
                            sqlx::query("DELETE FROM storage_snapshot WHERE id=?1 AND retained=0 AND NOT EXISTS(SELECT 1 FROM image_alias WHERE snapshot_id=?1) AND NOT EXISTS(SELECT 1 FROM storage_operation WHERE kind='capture' AND json_extract(record_json,'$.candidate')=?1)")
                                .bind(snapshot.to_string()).execute(&mut *tx).await?;
                        }
                        tx.commit().await?;
                        continue;
                    }
                    let mut removed_machine = None;
                    if matches!(state.as_str(), "committing" | "cleaning") {
                        let candidate =
                            commit_candidate(&row.try_get::<String, _>("record_json")?)?;
                        if let (Some(machine), Some(directory)) =
                            (candidate.candidate_machine_id, candidate.directory.as_ref())
                        {
                            if let Some(cleanup) = self
                                .prepare_stopped_machine_cleanup(
                                    &mut tx, id, &state, machine, directory,
                                )
                                .await?
                            {
                                removed_machine = Some((machine, cleanup));
                            }
                        }
                        // Image/snapshot candidates contain only immutable pool
                        // output. Presence and absence both reconcile safely;
                        // neither grants private destination cleanup authority.
                    }
                    if let Some((machine, cleanup)) = removed_machine {
                        let candidate_json: String = row.try_get("record_json")?;
                        tx.commit().await?;
                        self.checkpoint_catalog().await?;
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateAuthorized,
                            )?;
                        }
                        // Commit cleaning authority before the atomic detach.
                        // A crash rediscovers either canonical or quarantine name.
                        cleanup.detach()?;
                        drop(_roots);
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateDetached,
                            )?;
                        }
                        cleanup.remove(&self.home)?;
                        #[cfg(test)]
                        if let Some(hook) = &self.layer_hook {
                            hook.hit(
                                crate::store::layer_store::tests::WorkerPoint::CandidateRemoved,
                            )?;
                        }
                        // FileStore owns a separate blocking lock; the exclusive
                        // operation OFD and catalog remain ours outside roots.
                        crate::ssh_ca::delete_scope(
                            &silo_secrets::FileStore::new(&self.home),
                            machine,
                        )
                        .map_err(std::io::Error::other)?;
                        let _roots = pool.lock_roots()?;
                        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                        let current = sqlx::query("SELECT state,json(record_json) AS record_json,file_device,file_inode FROM storage_operation WHERE operation_id=?1")
                            .bind(id.to_string()).fetch_one(&mut *tx).await?;
                        validate_lease_identity(&current, &_lease)?;
                        if current.try_get::<String, _>("state")? != "cleaning"
                            || current.try_get::<String, _>("record_json")? != candidate_json
                        {
                            return Err(invalid(
                                "candidate changed during scoped credential cleanup",
                            ));
                        }
                        let appeared: bool = sqlx::query_scalar(
                            "SELECT EXISTS(SELECT 1 FROM machine_config WHERE id=?1)",
                        )
                        .bind(machine.to_string())
                        .fetch_one(&mut *tx)
                        .await?;
                        if appeared {
                            return Err(invalid(
                                "uncommitted candidate acquired a machine root during cleanup",
                            ));
                        }
                        cleanup.recheck_absence()?;
                        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                            .bind(id.to_string())
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        continue;
                    }
                    // An exclusive lease alone never reconciles a launch.
                    if kind != "launch" {
                        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                            .bind(&cursor)
                            .execute(&mut *tx)
                            .await?;
                    }
                }
                tx.commit().await?;
            }
        }
        self.retire_finished_fork_roots(pool).await?;
        self.reconcile_restore_budget().await?;
        Ok(report)
    }

    pub(crate) async fn register_launch_storage_inner(
        &self,
        machine_id: MachineId,
        run_id: Uuid,
        storage: &MachineStorageRecord,
        spec: &vm_spec::VmSpec,
        restore: Option<&crate::store::restore::RestoreIntent>,
    ) -> Result<LaunchStorageLease, LibVmError> {
        storage.validate_for_machine(machine_id.into())?;
        storage.ownership.ensure_owned(machine_id)?;
        preflight_launch_storage(storage, spec)?;
        let machine_directory = crate::paths::machine_data_dir_in(&self.home, machine_id);
        if !machine_directory.is_absolute() {
            return Err(invalid("machine directory is not absolute"));
        }
        let mut external_resources = crate::ExternalResource::from_spec(spec);
        for resource in &mut external_resources {
            let path = match resource {
                crate::ExternalResource::Disk { path, .. } => path,
                crate::ExternalResource::Share { source, .. } => source,
            };
            if !path.is_absolute() {
                *path = machine_directory.join(&*path);
            }
        }
        let record = RetainedStorageOperation {
            operation_id: Uuid::new_v4(),
            machine_id,
            run_id,
            storage_generation: storage.storage_generation,
            admitted: false,
            storage: storage.clone(),
            disks: spec
                .storage
                .as_ref()
                .map(|storage| storage.disks.clone())
                .unwrap_or_default(),
            external_resources,
            restore: restore.cloned(),
        };
        let json = encode(&record)?;
        let generation = i64::try_from(record.storage_generation)
            .map_err(|_| invalid("storage generation exceeds SQL range"))?;
        let crate::store::cache_paths::PoolDependencies {
            streams,
            objects,
            lowers,
        } = crate::store::cache_paths::storage_pool_dependencies(storage)?;
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let lease = pool.lease_deferred(record.operation_id)?;
        let directory = pool.lease_directory()?;
        let (device, inode) = lease.file_identity()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if restore.is_some() {
            let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_state WHERE machine_id=?1 AND status='restoring' AND json_extract(state_json,'$.runId')=?2)").bind(machine_id.to_string()).bind(run_id.to_string()).fetch_one(&mut *tx).await?;
            if !current {
                return Err(invalid(
                    "restore construction lost its exact unpublished lifecycle generation",
                ));
            }
        }
        let current: Option<String> =
            sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
                .bind(machine_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if current
            .as_deref()
            .map(MachineStorageRecord::decode)
            .transpose()?
            .as_ref()
            != Some(storage)
        {
            return Err(invalid(
                "machine storage changed before operation registration",
            ));
        }
        let row = sqlx::query(
            "SELECT id,name,json(config_json) AS config_json FROM machine_config WHERE id=?1",
        )
        .bind(machine_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        let crate::store::row::DbMachineConfig(current_config) =
            crate::store::row::DbMachineConfig::from_row_in(&row, &self.home)?;
        if &current_config.spec != spec {
            return Err(invalid(
                "machine attachments changed before operation registration",
            ));
        }
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,record_json) VALUES(?1,1,'launch','prepared',?2,?3,?4,?5,?6,jsonb(?7))")
            .bind(record.operation_id.to_string()).bind(machine_id.to_string()).bind(run_id.to_string()).bind(generation).bind(device.to_string()).bind(inode.to_string()).bind(json).execute(&mut *tx).await?;
        for stream in streams {
            insert_stream(&mut tx, record.operation_id, &stream).await?;
            // Reuse semantic layer dependencies. No parsing of generated VMDK paths.
            sqlx::query("INSERT OR IGNORE INTO storage_operation_layer(operation_id,result_id) SELECT ?1,id FROM layer_result WHERE pack_stream=?2")
                .bind(record.operation_id.to_string()).bind(stream.to_string()).execute(&mut *tx).await?;
        }
        for object in objects {
            sqlx::query(
                "INSERT INTO storage_operation_object(operation_id,object_digest) VALUES(?1,?2)",
            )
            .bind(record.operation_id.to_string())
            .bind(object.to_string())
            .execute(&mut *tx)
            .await?;
        }
        // The launch generation roots its layered lower (and through it every
        // layer, pack stream and fsmeta object) until its retirement.
        for lower in lowers {
            sqlx::query("INSERT INTO storage_operation_lower(operation_id,lower_id) VALUES(?1,?2)")
                .bind(record.operation_id.to_string())
                .bind(lower.to_string())
                .execute(&mut *tx)
                .await?;
        }
        if let Some(restore) = restore {
            restore.validate()?;
            let consumer: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND kind='import')")
                .bind(restore.consumer_operation.to_string()).fetch_one(&mut *tx).await?;
            if !consumer {
                return Err(invalid(
                    "restore verification consumer disappeared before generation handoff",
                ));
            }
            sqlx::query("INSERT OR IGNORE INTO storage_operation_stream(operation_id,stream_id) SELECT ?1,stream_id FROM storage_operation_stream WHERE operation_id=?2")
                .bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT OR IGNORE INTO storage_operation_object(operation_id,object_digest) SELECT ?1,object_digest FROM storage_operation_object WHERE operation_id=?2")
                .bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            let charged:String=sqlx::query_scalar("SELECT json(charge_json) FROM restore_memory_reservation WHERE operation_id=?1 AND construction_json IS NOT NULL").bind(restore.consumer_operation.to_string()).fetch_one(&mut *tx).await?;
            let charged: crate::store::restore::RestoreMemoryCharge =
                serde_json::from_str(&charged).map_err(invalid)?;
            if charged != restore.memory {
                return Err(invalid(
                    "generation transfer changed its pre-admitted resource charge",
                ));
            }
            let reservation = sqlx::query("UPDATE restore_memory_reservation SET operation_id=?1 WHERE operation_id=?2 AND construction_json IS NOT NULL")
                .bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            if reservation.rows_affected() != 1 {
                return Err(invalid(
                    "restore generation handoff lost its exact construction budget owner",
                ));
            }
            sqlx::query("INSERT OR IGNORE INTO storage_operation_layer(operation_id,result_id) SELECT ?1,result_id FROM storage_operation_layer WHERE operation_id=?2").bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT OR IGNORE INTO storage_operation_lower(operation_id,lower_id) SELECT ?1,lower_id FROM storage_operation_lower WHERE operation_id=?2").bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            sqlx::query("INSERT OR IGNORE INTO storage_operation_cut(operation_id,cut_id) SELECT ?1,cut_id FROM storage_operation_cut WHERE operation_id=?2").bind(record.operation_id.to_string()).bind(restore.consumer_operation.to_string()).execute(&mut *tx).await?;
            if let crate::store::restore::RestoreIdentity::LocalCut { id } = &restore.checkpoint {
                let child:Option<(String,i64,String,String)>=sqlx::query_as("SELECT c.operation_id,c.child_index,c.machine_id,c.run_id FROM live_fork_child c JOIN live_fork f ON f.operation_id=c.operation_id JOIN local_cut l ON l.operation_id=f.operation_id WHERE c.consumer_id=?1 AND c.launch_id IS NULL AND c.name_reserved=1 AND l.cut_id=?2 AND json_extract(f.result_json,'$.cancellationRequested')=0 AND f.admission_complete=1").bind(restore.consumer_operation.to_string()).bind(id.to_string()).fetch_optional(&mut *tx).await?;
                let Some((parent, index, machine, run)) = child else {
                    return Err(invalid(
                        "fork child generation handoff was cancelled or lost its reserved identity",
                    ));
                };
                if machine != machine_id.to_string() || run != run_id.to_string() {
                    return Err(invalid(
                        "fork child generation changed reserved machine/run identity",
                    ));
                }
                sqlx::query("UPDATE live_fork_child SET launch_id=?3 WHERE operation_id=?1 AND child_index=?2 AND launch_id IS NULL").bind(parent).bind(index).bind(record.operation_id.to_string()).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
        Ok(LaunchStorageLease {
            record,
            lease,
            directory,
        })
    }

    pub(crate) async fn mark_launch_storage_admitted_inner(
        &self,
        operation_id: Uuid,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(SELECT_LAUNCH_BY_OPERATION)
            .bind(operation_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| invalid("launch operation disappeared"))?;
        let mut record = decode(&row)?;
        if !record.admitted {
            if record.restore.is_some() {
                let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_state WHERE machine_id=?1 AND status IN ('restoring','activating','starting') AND json_extract(state_json,'$.runId')=?2)").bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_one(&mut *tx).await?;
                if !current {
                    return Err(invalid(
                        "restore launch was stopped or superseded before submission",
                    ));
                }
            }
            if let Some(restore) = &record.restore {
                if matches!(
                    restore.checkpoint,
                    crate::store::restore::RestoreIdentity::LocalCut { .. }
                ) {
                    let row:Option<(String,i64,bool,String)>=sqlx::query_as("SELECT c.operation_id,c.child_index,json_extract(f.result_json,'$.cancellationRequested'),json(c.result_json) FROM live_fork_child c JOIN live_fork f ON f.operation_id=c.operation_id WHERE c.launch_id=?1 AND c.machine_id=?2 AND c.run_id=?3 AND c.submitted=0").bind(operation_id.to_string()).bind(record.machine_id.to_string()).bind(record.run_id.to_string()).fetch_optional(&mut *tx).await?;
                    let Some((parent, index, cancelled, json)) = row else {
                        return Err(invalid("fork launch lost its exact unsubmitted child slot"));
                    };
                    if cancelled {
                        return Err(invalid("fork cancellation fences an unsubmitted launch"));
                    }
                    let mut child: crate::ForkChildResult =
                        serde_json::from_str(&json).map_err(invalid)?;
                    child.outcome = crate::ForkChildOutcome::Activating;
                    sqlx::query("UPDATE live_fork_child SET submitted=1,result_json=jsonb(?3) WHERE operation_id=?1 AND child_index=?2").bind(&parent).bind(index).bind(serde_json::to_string(&child).map_err(invalid)?).execute(&mut *tx).await?;
                    sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,child_index,phase,monotonic_ns) VALUES(?1,?2,'activating',?3)").bind(parent).bind(index).bind(crate::machine::live_fork::monotonic_ns()?).execute(&mut *tx).await?;
                }
            }
        }
        record.admitted = true;
        sqlx::query("UPDATE storage_operation SET record_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation_id.to_string())
            .bind(encode(&record)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn launch_storage_operations_inner(
        &self,
        machine_id: MachineId,
    ) -> Result<Vec<RetainedStorageOperation>, LibVmError> {
        sqlx::query(SELECT_LAUNCH_BY_MACHINE)
            .bind(machine_id.to_string())
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(decode)
            .collect()
    }

    /// Holder terminality is a lifecycle prerequisite, not inferred from flock.
    pub(crate) async fn try_retire_launch_storage_inner(
        &self,
        operation_id: Uuid,
        run_id: Uuid,
        generation: u64,
        next_state: &MachineState,
        outcome: StorageStopOutcome,
    ) -> Result<bool, LibVmError> {
        if !matches!(
            next_state.status,
            crate::store::models::MachineRuntimeState::Stopped
                | crate::store::models::MachineRuntimeState::Error
        ) {
            return Err(invalid(
                "operation retirement requires a terminal lifecycle state",
            ));
        }
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let Some(_lease) = pool.try_exclusive_lease(operation_id)? else {
            return Ok(false);
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(SELECT_LAUNCH_BY_OPERATION)
            .bind(operation_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| invalid("launch operation disappeared before reconciliation"))?;
        validate_lease_identity(&row, &_lease)?;
        let record = decode(&row)?;
        if record.machine_id != next_state.machine_id
            || record.run_id != run_id
            || record.storage_generation != generation
        {
            return Err(invalid(
                "reconciliation does not match exact launch generation",
            ));
        }
        let current_state = sqlx::query_as::<_,crate::store::row::DbMachineState>("SELECT machine_id,status,json(state_json) AS state_json FROM machine_state WHERE machine_id=?1")
            .bind(next_state.machine_id.to_string()).fetch_optional(&mut *tx).await?;
        if current_state.is_some_and(|crate::store::row::DbMachineState(state)| {
            state
                .run_id
                .as_deref()
                .is_some_and(|current| Uuid::parse_str(current).ok() != Some(run_id))
        }) {
            return Err(invalid("another runtime generation owns the machine state"));
        }
        let json: String =
            sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
                .bind(next_state.machine_id.to_string())
                .fetch_one(&mut *tx)
                .await?;
        let mut storage = MachineStorageRecord::decode(&json)?;
        if storage.storage_generation != generation {
            return Err(invalid("machine generation changed before reconciliation"));
        }
        storage.stop_outcome = outcome;
        Self::write_machine_storage(&mut tx, next_state.machine_id, &storage).await?;
        sqlx::query("INSERT INTO machine_state(machine_id,status,state_json) VALUES(?1,?2,jsonb(?3)) ON CONFLICT(machine_id) DO UPDATE SET status=excluded.status,state_json=excluded.state_json")
            .bind(next_state.machine_id.to_string()).bind(next_state.status.as_str()).bind(Self::serialize("machine_state.state_json",next_state)?).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
            .bind(operation_id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        drop(_roots);
        self.reconcile_restore_budget().await?;
        Ok(true)
    }

    /// Inventory discovery is outside roots; each coordinated metadata batch is
    /// bounded and performs only nonblocking lease probes.
    pub(crate) async fn check_operation_recovery(
        &self,
        pool: &StoragePool,
    ) -> Result<(), LibVmError> {
        let mut ids = pool.scan_leases()?;
        loop {
            let batch = ids.by_ref().take(256).collect::<Result<Vec<_>, _>>()?;
            if batch.is_empty() {
                break;
            }
            let _roots = pool.lock_roots()?;
            for id in batch {
                let known: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1)",
                )
                .bind(id.to_string())
                .fetch_one(&self.pool)
                .await?;
                if !known && pool.try_exclusive_lease(id)?.is_none() {
                    return Err(invalid(format!(
                        "busy lease {id} has no understood operation root"
                    )));
                }
            }
        }
        let mut cursor = String::new();
        loop {
            let operations = sqlx::query_scalar::<_,String>("SELECT operation_id FROM storage_operation WHERE operation_id>?1 ORDER BY operation_id LIMIT 256")
                .bind(&cursor).fetch_all(&self.pool).await?;
            if operations.is_empty() {
                break;
            }
            let _roots = pool.lock_roots()?;
            for operation in operations {
                cursor = operation;
                let row = sqlx::query("SELECT operation_id,schema,kind,state,machine_id,run_id,storage_generation,file_device,file_inode,CASE WHEN json_valid(record_json,8) THEN json(record_json) ELSE '{}' END AS record_json FROM storage_operation WHERE operation_id=?1")
                    .bind(&cursor).fetch_optional(&self.pool).await?;
                let Some(row) = row else { continue };
                let id = Uuid::parse_str(&cursor).map_err(|error| invalid(error.to_string()))?;
                let schema: i64 = row.try_get("schema")?;
                let kind: String = row.try_get("kind")?;
                let state: String = row.try_get("state")?;
                if schema != 1 {
                    return Err(invalid("unsupported operation schema"));
                }
                match kind.as_str() {
                    "launch" => {
                        decode(&row)?;
                    }
                    "capture" => {
                        let capture = crate::store::capture::decode_record(
                            &row.try_get::<String, _>("record_json")?,
                        )?;
                        if capture.capture_id != id
                            || row.try_get::<String, _>("machine_id")?
                                != capture.machine_id.to_string()
                            || row.try_get::<String, _>("run_id")? != capture.run_id.to_string()
                            || row.try_get::<i64, _>("storage_generation")?
                                != i64::try_from(capture.storage.storage_generation)
                                    .map_err(invalid)?
                            || !matches!(
                                state.as_str(),
                                "staging" | "committed" | "aborted" | "cleaning"
                            )
                        {
                            return Err(invalid(
                                "capture indexed identity contradicts retained plan",
                            ));
                        }
                        if state == "cleaning"
                            && !matches!(
                                capture.state,
                                crate::store::snapshot_store::CaptureState::Released { .. }
                                    | crate::store::snapshot_store::CaptureState::ReleasedLocal { .. }
                                    | crate::store::snapshot_store::CaptureState::Abandoned
                            )
                        {
                            return Err(invalid("nonterminal capture has cleanup authority"));
                        }
                    }
                    "update-boot-assets" if state == "committing" => {
                        let candidate =
                            boot_update_candidate(&row.try_get::<String, _>("record_json")?)?;
                        if row.try_get::<String, _>("machine_id")?
                            != candidate.machine_id.to_string()
                            || row.try_get::<i64, _>("storage_generation")?
                                != i64::try_from(candidate.generation).map_err(invalid)?
                        {
                            return Err(invalid("boot update candidate contradicts indexed owner"));
                        }
                    }
                    "live-fork" | "convert" | "snapshot" | "fork" | "import" | "relocate"
                    | "update-boot-assets" | "raw-export"
                        if matches!(state.as_str(), "staging" | "committed") =>
                    {
                        let json: String = row.try_get("record_json")?;
                        if json != "{}" {
                            return Err(invalid("malformed staging operation"));
                        }
                    }
                    "convert" | "snapshot" | "fork" | "import"
                        if matches!(state.as_str(), "committing" | "cleaning") =>
                    {
                        let candidate =
                            commit_candidate(&row.try_get::<String, _>("record_json")?)?;
                        if candidate.candidate_snapshot_id.is_some()
                            && !matches!(kind.as_str(), "snapshot" | "import")
                            || kind == "snapshot" && candidate.candidate_snapshot_id.is_none()
                            || candidate.candidate_index_digest.is_some() && kind != "import"
                        {
                            return Err(invalid(
                                "operation kind contradicts its snapshot candidate",
                            ));
                        }
                        if candidate.candidate_image_id.is_some()
                            && !matches!(kind.as_str(), "import" | "convert")
                            || kind == "convert" && candidate.candidate_image_id.is_none()
                        {
                            return Err(invalid("operation kind contradicts its image candidate"));
                        }
                        if state == "cleaning" && candidate.candidate_machine_id.is_none() {
                            return Err(invalid("only a machine candidate can enter cleanup"));
                        }
                    }
                    _ => return Err(invalid("unsupported operation root")),
                }
                validate_lease_metadata(&row, pool.operation_lease_identity(id)?)?;
                if let Some(probe) = pool.try_exclusive_lease(id)? {
                    validate_lease_identity(&row, &probe)?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) async fn insert_stream(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    operation_id: Uuid,
    stream: &StreamId,
) -> Result<(), LibVmError> {
    sqlx::query(
        "INSERT OR IGNORE INTO storage_operation_stream(operation_id,stream_id) VALUES(?1,?2)",
    )
    .bind(operation_id.to_string())
    .bind(stream.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::paths::LocalPaths;
    use crate::storage::pool::StoragePool;
    use crate::store::operation_store::{
        directory_identity, read_cleanup_text, validate_lease_identity, validate_lease_metadata,
        MachineCleanup,
    };
    use crate::store::Store;

    #[test]
    fn image_candidates_are_exactly_one_typed_result_without_directory_authority() {
        let image = crate::storage::identity::ImageId::from_sha256([1; 32]);
        let snapshot = crate::storage::identity::SnapshotId::from_sha256([1; 32]);
        let valid = serde_json::json!({"candidateImageId": image}).to_string();
        let candidate = crate::store::operation_store::commit_candidate(&valid).unwrap();
        assert_eq!(candidate.candidate_image_id, Some(image));
        assert!(candidate.candidate_machine_id.is_none());
        for value in [
            serde_json::json!({"candidateImageId": image, "candidateSnapshotId": snapshot}),
            serde_json::json!({"candidateImageId": image, "directory": {"device": "1", "inode": "2"}}),
            serde_json::json!({}),
        ] {
            assert!(crate::store::operation_store::commit_candidate(&value.to_string()).is_err());
        }
    }

    #[tokio::test]
    async fn stopped_cleanup_stabilizes_authority_before_detaching_machine() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("fork", &[], &[])
            .await
            .unwrap();
        let machine = crate::MachineId::new();
        let directory = crate::paths::machine_data_dir_in(&store.home, machine);
        let machines =
            crate::paths::OwnedDirectory::open_root(&store.home.join("machines")).unwrap();
        machines
            .ensure_dir(&machine.to_string())
            .unwrap()
            .write_file("root.raw", b"private candidate")
            .unwrap();
        store
            .preserve_stopped_operation(operation, machine)
            .await
            .unwrap();
        let mut reader = store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_operation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        drop(lease);
        let error = store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("catalog WAL checkpoint is incomplete"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(directory.join("root.raw")).unwrap(),
            b"private candidate"
        );
        reader.rollback().await.unwrap();
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert!(!directory.exists());
    }

    #[tokio::test]
    async fn abandoned_boot_update_never_grants_machine_directory_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("update-boot-assets", &[], &[])
            .await
            .unwrap();
        pool.create_operation_with_lease(operation, lease.duplicate().unwrap())
            .unwrap();
        let object = crate::storage::identity::ObjectDigest::of_bytes(b"kernel");
        let binding = crate::BootBinding::Pinned {
            kernel: object,
            base_initramfs: object,
            agent: None,
            architecture: crate::GuestArchitecture::Amd64,
            abi: crate::runtime::boot_assets::DIRECT_BOOT_ABI.into(),
        };
        let input = crate::store::snapshot_store::RecordInput::new(
            &store.images_dir,
            operation,
            &binding.canonical_bytes().unwrap(),
        )
        .unwrap();
        let (bundle, roots) = pool.publish_object_for_catalog(&input.path()).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[bundle.digest])
            .await
            .unwrap();
        drop(roots);
        let machine = crate::store::models::MachineId::from(uuid::Uuid::new_v4());
        let directory = crate::paths::machine_data_dir_in(&store.home, machine);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("root.raw"),
            b"unrelated existing machine data",
        )
        .unwrap();
        store
            .preserve_boot_update_operation(operation, machine, 1, bundle.digest)
            .await
            .unwrap();
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert!(pool.try_exclusive_lease(operation).unwrap().is_none());
        drop(lease);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let retained: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1)",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!retained);
        assert_eq!(
            std::fs::read(directory.join("root.raw")).unwrap(),
            b"unrelated existing machine data"
        );
    }

    #[tokio::test]
    async fn stopped_retirement_rejects_exclusive_replacement_ofd_after_pathname_aba() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, original) = store
            .begin_stopped_operation("fork", &[], &[])
            .await
            .unwrap();
        let input = temp.path().join("object");
        std::fs::write(&input, b"retained while the original worker owns its OFD").unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&input).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[object.digest])
            .await
            .unwrap();
        drop(roots);
        let canonical = store
            .images_dir
            .join("locks/leases")
            .join(format!("{operation}.lease"));
        let saved_original = canonical.with_extension("original");
        let saved_replacement = canonical.with_extension("replacement");
        std::fs::rename(&canonical, &saved_original).unwrap();
        drop(pool.lease(operation).unwrap());
        let replacement_exclusive = pool.try_exclusive_lease(operation).unwrap().unwrap();
        assert_ne!(
            original.file_identity().unwrap(),
            replacement_exclusive.file_identity().unwrap()
        );
        std::fs::rename(&canonical, &saved_replacement).unwrap();
        std::fs::rename(&saved_original, &canonical).unwrap();
        let row = sqlx::query(
            "SELECT file_device,file_inode FROM storage_operation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        // The restored pathname looks correct, but it is not the acquired EX OFD.
        validate_lease_metadata(&row, pool.operation_lease_identity(operation).unwrap()).unwrap();
        assert!(validate_lease_identity(&row, &replacement_exclusive).is_err());
        validate_lease_identity(&row, &original).unwrap();
        assert!(pool.try_exclusive_lease(operation).unwrap().is_none());
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let pinned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_object WHERE operation_id=?1 AND object_digest=?2)")
            .bind(operation.to_string()).bind(object.digest.to_string()).fetch_one(&store.pool).await.unwrap();
        assert!(pinned);
        assert!(pool.verify_object(&object.digest).is_ok());
        drop((replacement_exclusive, original));
    }

    #[test]
    fn capture_cleanup_diagnostic_read_is_bounded_exact_and_no_follow() {
        let temp = tempfile::tempdir().unwrap();
        let directory =
            crate::paths::OwnedDirectory::open_root(&temp.path().join("evidence")).unwrap();
        let malformed = b"{failed capture diagnostic, not valid JSON\n";
        directory.write_file("vm.capture.json", malformed).unwrap();
        assert_eq!(
            read_cleanup_text(&directory, "vm.capture.json", malformed.len() as u64).unwrap(),
            Some(malformed.to_vec())
        );
        assert!(
            read_cleanup_text(&directory, "vm.capture.json", malformed.len() as u64 - 1).is_err()
        );
        assert!(read_cleanup_text(&directory, "missing.json", 16)
            .unwrap()
            .is_none());
        std::os::unix::fs::symlink(
            directory.path().join("vm.capture.json"),
            directory.path().join("vm.capture-source.json"),
        )
        .unwrap();
        assert!(read_cleanup_text(&directory, "vm.capture-source.json", 1024).is_err());
        assert_eq!(
            std::fs::read(directory.path().join("vm.capture.json")).unwrap(),
            malformed
        );
    }

    #[test]
    fn capture_cleanup_resumes_after_detach_and_removes_only_owned_staging() {
        let temp = tempfile::tempdir().unwrap();
        let parent =
            crate::paths::OwnedDirectory::open_root(&temp.path().join("captures")).unwrap();
        let source = parent.ensure_dir("capture").unwrap();
        source
            .write_file("memory.ram", b"disposable staging RAM")
            .unwrap();
        let persistent = parent.ensure_dir("another-capture").unwrap();
        persistent
            .write_file("memory.ram", b"live baseline")
            .unwrap();
        let expected = directory_identity(&source).unwrap();
        let make_cleanup = || MachineCleanup {
            parent: Some(parent.try_clone().unwrap()),
            source_name: "capture".into(),
            quarantine_name: ".retiring-capture".into(),
            expected,
            hook: None,
        };
        make_cleanup().detach().unwrap();
        assert!(!source.path().exists());
        assert!(parent.path().join(".retiring-capture/memory.ram").exists());
        let restarted = make_cleanup();
        restarted.detach().unwrap();
        restarted.remove(temp.path()).unwrap();
        restarted.recheck_absence().unwrap();
        // Repeating removal after a crash between parent fsync and SQL retirement
        // is safe, but does not remove any other capture's baseline.
        restarted.remove(temp.path()).unwrap();
        assert_eq!(
            std::fs::read(persistent.path().join("memory.ram")).unwrap(),
            b"live baseline"
        );
    }

    #[test]
    fn capture_cleanup_refuses_replacement_and_reoccupied_names() {
        let temp = tempfile::tempdir().unwrap();
        let parent =
            crate::paths::OwnedDirectory::open_root(&temp.path().join("captures")).unwrap();
        let source = parent.ensure_dir("capture").unwrap();
        source.write_file("memory.ram", b"original").unwrap();
        let cleanup = MachineCleanup {
            parent: Some(parent.try_clone().unwrap()),
            source_name: "capture".into(),
            quarantine_name: ".retiring-capture".into(),
            expected: directory_identity(&source).unwrap(),
            hook: None,
        };
        std::fs::rename(source.path(), parent.path().join("saved-original")).unwrap();
        let replacement = parent.ensure_dir("capture").unwrap();
        replacement
            .write_file("memory.ram", b"replacement must survive")
            .unwrap();
        assert!(cleanup.detach().is_err());
        assert_eq!(
            std::fs::read(replacement.path().join("memory.ram")).unwrap(),
            b"replacement must survive"
        );
        parent.remove_open_tree("capture", &replacement).unwrap();
        std::fs::rename(parent.path().join("saved-original"), source.path()).unwrap();
        cleanup.detach().unwrap();
        let reoccupied = parent.ensure_dir("capture").unwrap();
        assert!(cleanup.detach().is_err());
        cleanup.remove(temp.path()).unwrap();
        assert!(cleanup.recheck_absence().is_err());
        assert!(reoccupied.path().exists());
    }
}

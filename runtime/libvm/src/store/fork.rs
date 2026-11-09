//! Durable fork identities, independent outcomes and operation-owned local cuts.
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use vm_spec::capture::{CaptureEvidence, CaptureRole, Sha256Digest};

use crate::machine::live::MachineLiveObservation;
use crate::machine::live_fork::{
    ForkCaptureOutcome, ForkChildOutcome, ForkChildResult, ForkFailurePhase, ForkSourceOutcome,
    ForkStage, LiveForkOptions, LiveForkResult,
};
use crate::machine::root_storage::invalid;
use crate::storage::pool::StoragePool;
use crate::store::models::MachineId;
use crate::store::Store;
use crate::{LibVmError, MachineStorageRecord, SnapshotConfiguration};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ForkChildIdentity {
    pub result: ForkChildResult,
    pub activation_id: Uuid,
    pub consumer_id: Uuid,
    pub launch_id: Option<Uuid>,
    pub submitted: bool,
    pub failure: Option<ForkChildFailure>,
}

/// The observed restore failure survives deletion of the failed child, while
/// its public outcome remains recovery-pending until ownership is retired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ForkChildFailure {
    pub phase: ForkFailurePhase,
    pub diagnostic: vm_spec::lifecycle::Diagnostic,
}

impl ForkChildFailure {
    pub(crate) fn outcome(&self) -> ForkChildOutcome {
        ForkChildOutcome::Failed {
            phase: self.phase,
            diagnostic: self.diagnostic.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalCutFile {
    pub role: CaptureRole,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub identity: Sha256Digest,
    pub fingerprint: crate::storage::identity_file::SourceFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalCut {
    pub operation_id: Uuid,
    pub capture_id: Uuid,
    pub cut_id: Sha256Digest,
    pub evidence: CaptureEvidence,
    pub plan: vm_spec::capture::CapturePlan,
    pub configuration: SnapshotConfiguration,
    pub storage: MachineStorageRecord,
    pub source_ram: LocalCutFile,
    pub files: Vec<LocalCutFile>,
    pub relocated: bool,
}

/// Receipt-bound writable disk maps held through this operation's relocation.
/// Each child's streaming copy authenticates its chunks on first use.
pub(crate) struct AuthenticatedCutDisks {
    operation_id: Uuid,
    cut_id: Sha256Digest,
    disks: Vec<(CaptureRole, crate::storage::stream::AuthenticatedStream)>,
}

impl AuthenticatedCutDisks {
    pub(crate) fn new(
        operation_id: Uuid,
        cut_id: Sha256Digest,
        disks: Vec<(CaptureRole, crate::storage::stream::AuthenticatedStream)>,
    ) -> Self {
        Self {
            operation_id,
            cut_id,
            disks,
        }
    }
}

/// One held descriptor per cut role, parallel to `LocalCut::files`.
enum HeldCutRole {
    State(File),
    /// Writable disks also carry their canonical map, shared by every child.
    Disk(crate::storage::stream::AuthenticatedStream),
}

impl HeldCutRole {
    fn file(&self) -> &File {
        match self {
            Self::State(file) => file,
            Self::Disk(stream) => stream.file(),
        }
    }
}

pub(crate) struct VerifiedRestoreCut {
    pub record: LocalCut,
    held: Vec<HeldCutRole>,
    directory: crate::paths::OwnedDirectory,
    pub _lease: crate::storage::locks::StorageLock,
    pub pool_streams: std::collections::BTreeMap<
        crate::storage::identity::StreamId,
        crate::storage::stream::AuthenticatedStream,
    >,
    pub lower: Option<crate::machine::restore::VerifiedLower>,
}
impl VerifiedRestoreCut {
    pub(crate) fn directory(&self) -> &crate::paths::OwnedDirectory {
        &self.directory
    }

    /// The held descriptor of one role, parallel to `record.files`.
    #[cfg(test)]
    pub(crate) fn held_file(&self, index: usize) -> Option<&File> {
        self.held.get(index).map(HeldCutRole::file)
    }

    /// Reopen through the pinned owned directory, not through evidence paths.
    /// Each child gets an independent open-file description: sparse-copy seeks
    /// and native metadata readers cannot disturb another child's descriptor.
    pub(crate) fn reopen_role(&self, role: &CaptureRole) -> Result<File, LibVmError> {
        self.open_role(self.role_index(role)?)
    }

    /// An independent descriptor of one writable cut disk, bound to the map
    /// the seal verification derived. Children share that map, never clone it.
    pub(crate) fn reopen_disk(
        &self,
        role: &CaptureRole,
    ) -> Result<crate::storage::stream::AuthenticatedStream, LibVmError> {
        let index = self.role_index(role)?;
        let HeldCutRole::Disk(held) = &self.held[index] else {
            return Err(invalid("local cut role is not a writable disk"));
        };
        Ok(held.reopen(self.open_role(index)?)?)
    }

    fn role_index(&self, role: &CaptureRole) -> Result<usize, LibVmError> {
        self.record
            .files
            .iter()
            .position(|file| &file.role == role)
            .filter(|index| *index < self.held.len())
            .ok_or_else(|| invalid("local cut role missing"))
    }

    fn open_role(&self, index: usize) -> Result<File, LibVmError> {
        let identity = &self.record.files[index];
        let relative = identity.role.relative_path();
        let file = match relative.split_once('/') {
            Some((parent, name)) => self
                .directory
                .open_dir(parent)?
                .ok_or_else(|| invalid("local cut role parent missing"))?
                .open_immutable_file(name)?,
            None => self.directory.open_immutable_file(&relative)?,
        }
        .ok_or_else(|| invalid("local cut role missing"))?;
        if crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?)
            != identity.fingerprint
            || crate::storage::identity_file::SourceFingerprint::new(
                &self.held[index].file().metadata()?,
            ) != identity.fingerprint
        {
            return Err(invalid("local cut role was replaced or modified"));
        }
        Ok(file)
    }
}

impl LocalCut {
    pub(crate) fn identity(&self) -> Result<Sha256Digest, LibVmError> {
        let inventory = self
            .files
            .iter()
            .map(|file| (&file.role, file.length, file.identity))
            .collect::<Vec<_>>();
        let mut bytes = b"silo:local-fork-cut:v1\0".to_vec();
        bytes.extend(
            serde_json::to_vec(&(
                self.operation_id,
                self.capture_id,
                &self.plan,
                &self.evidence,
                &self.configuration,
                &self.storage,
                inventory,
            ))
            .map_err(|error| invalid(error.to_string()))?,
        );
        Ok(Sha256Digest::of_bytes(&bytes))
    }
}

impl Store {
    pub(crate) async fn fork_result(
        &self,
        operation: Uuid,
    ) -> Result<Option<LiveForkResult>, LibVmError> {
        let row:Option<(String,String,String,String)>=sqlx::query_as("SELECT json(result_json),json(request_json),json(observation_json),capture_id FROM live_fork WHERE operation_id=?1").bind(operation.to_string()).fetch_optional(&self.pool).await?;
        let Some((json, request, observation, capture)) = row else {
            return Ok(None);
        };
        let mut result: LiveForkResult =
            serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
        let options: LiveForkOptions =
            serde_json::from_str(&request).map_err(|error| invalid(error.to_string()))?;
        let observation: vm_spec::live::LiveMachineReport =
            serde_json::from_str(&observation).map_err(|error| invalid(error.to_string()))?;
        options.validate()?;
        observation.validate().map_err(invalid)?;
        let rows=sqlx::query("SELECT child_index,name,machine_id,run_id,json(result_json) AS result_json FROM live_fork_child WHERE operation_id=?1 ORDER BY child_index").bind(operation.to_string()).fetch_all(&self.pool).await?;
        let mut machines = std::collections::BTreeSet::new();
        let mut runs = std::collections::BTreeSet::new();
        result.children = rows
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                let child: ForkChildResult =
                    serde_json::from_str(&row.try_get::<String, _>("result_json")?)
                        .map_err(|error| invalid(error.to_string()))?;
                if child.index as usize != index
                    || row.try_get::<i64, _>("child_index")? != i64::from(child.index)
                    || child.name != row.try_get::<String, _>("name")?
                    || child.machine_id.to_string() != row.try_get::<String, _>("machine_id")?
                    || child.run_id.as_str() != row.try_get::<String, _>("run_id")?
                    || options
                        .children
                        .get(index)
                        .is_none_or(|option| option.name != child.name)
                    || child.machine_id == result.source_machine_id
                    || Uuid::from(child.machine_id).is_nil()
                    || Uuid::parse_str(child.run_id.as_str())
                        .map_err(|error| invalid(error.to_string()))?
                        .is_nil()
                    || !machines.insert(child.machine_id)
                    || !runs.insert(child.run_id.to_string())
                {
                    return Err(invalid("fork child journal identity contradiction"));
                }
                Ok(child)
            })
            .collect::<Result<_, LibVmError>>()?;
        for child in &mut result.children {
            if let Some(durability) = self.machine_durability(child.machine_id).await? {
                child.durability = Some(durability);
            }
        }
        if operation.is_nil()
            || result.operation_id != operation
            || options.operation_id != operation
            || result.resources != options.resources
            || result.children.len() != options.children.len()
            || result.capture_id.as_str() != capture
            || Uuid::from(result.source_machine_id).to_string() != observation.machine_id
            || result.source_run_id.as_str() != observation.run_id
        {
            return Err(invalid("fork request/result identity contradiction"));
        }
        Ok(Some(result))
    }

    pub(crate) async fn fork_for_capture(&self, capture: Uuid) -> Result<Option<Uuid>, LibVmError> {
        let id: Option<String> =
            sqlx::query_scalar("SELECT operation_id FROM live_fork WHERE capture_id=?1")
                .bind(capture.to_string())
                .fetch_optional(&self.pool)
                .await?;
        id.map(|id| Uuid::parse_str(&id).map_err(|error| invalid(error.to_string())))
            .transpose()
    }

    pub(crate) async fn fork_options(
        &self,
        operation: Uuid,
    ) -> Result<LiveForkOptions, LibVmError> {
        let json: String =
            sqlx::query_scalar("SELECT json(request_json) FROM live_fork WHERE operation_id=?1")
                .bind(operation.to_string())
                .fetch_one(&self.pool)
                .await?;
        let options: LiveForkOptions =
            serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
        options.validate()?;
        if options.operation_id != operation {
            return Err(invalid("fork request identity contradiction"));
        }
        Ok(options)
    }

    pub(crate) async fn admit_fork(
        &self,
        source: MachineId,
        observation: &MachineLiveObservation,
        options: &LiveForkOptions,
        capture: Uuid,
    ) -> Result<(LiveForkResult, crate::storage::locks::StorageLock), LibVmError> {
        options.validate()?;
        if capture.is_nil() || capture == options.operation_id {
            return Err(invalid(
                "fork capture and operation require distinct nonnil identities",
            ));
        }
        let run: crate::MachineRunId = observation
            .report()
            .run_id
            .parse()
            .map_err(|error: uuid::Error| invalid(error.to_string()))?;
        observation.report().validate().map_err(invalid)?;
        if observation.report().machine_id != Uuid::from(source).to_string() {
            return Err(invalid("fork observation belongs to another source"));
        }
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT json(request_json),json(result_json) FROM live_fork WHERE operation_id=?1",
        )
        .bind(options.operation_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((request, result)) = existing {
            let prior: LiveForkOptions =
                serde_json::from_str(&request).map_err(|error| invalid(error.to_string()))?;
            let result: LiveForkResult =
                serde_json::from_str(&result).map_err(|error| invalid(error.to_string()))?;
            if &prior != options
                || result.source_machine_id != source
                || result.source_run_id != run
            {
                return Err(invalid(
                    "fork operation identity conflicts with its immutable request",
                ));
            }
            tx.commit().await?;
            let lease = pool.existing_lease(options.operation_id)?;
            self.validate_fork_lease(options.operation_id, &lease)
                .await?;
            return Ok((
                self.fork_result(options.operation_id)
                    .await?
                    .ok_or_else(|| invalid("fork result disappeared"))?,
                lease,
            ));
        }
        let lease = pool.lease(options.operation_id)?;
        let (device, inode) = lease.file_identity()?;
        let mut children = Vec::with_capacity(options.children.len());
        for (index, child) in options.children.iter().enumerate() {
            let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_config WHERE name=?1 UNION ALL SELECT 1 FROM live_fork_child WHERE name=?1 AND name_reserved=1)").bind(&child.name).fetch_one(&mut *tx).await?;
            if occupied {
                return Err(crate::LibVmError::MachineAlreadyExists {
                    name: child.name.clone(),
                });
            }
            let result = ForkChildResult {
                index: u32::try_from(index).map_err(|error| invalid(error.to_string()))?,
                name: child.name.clone(),
                machine_id: MachineId::new(),
                run_id: Uuid::new_v4()
                    .to_string()
                    .parse()
                    .map_err(|error: uuid::Error| invalid(error.to_string()))?,
                outcome: ForkChildOutcome::Pending,
                durability: None,
            };
            children.push(result);
        }
        let result = LiveForkResult {
            operation_id: options.operation_id,
            source_machine_id: source,
            source_run_id: run,
            capture_id: vm_spec::lifecycle::LiveId::parse(&capture.to_string()).map_err(invalid)?,
            stage: ForkStage::Admitted,
            cancellation_requested: false,
            capture: ForkCaptureOutcome::Pending,
            source: ForkSourceOutcome::Pending,
            resources: options.resources,
            children,
        };
        let mut header = result.clone();
        header.children.clear();
        sqlx::query("INSERT INTO live_fork(operation_id,capture_id,cancellation_id,request_json,observation_json,result_json) VALUES(?1,?2,?6,jsonb(?3),jsonb(?4),jsonb(?5))").bind(options.operation_id.to_string()).bind(capture.to_string()).bind(serde_json::to_string(options).map_err(|error| invalid(error.to_string()))?).bind(serde_json::to_string(observation.report()).map_err(|error| invalid(error.to_string()))?).bind(serde_json::to_string(&header).map_err(|error| invalid(error.to_string()))?).bind(Uuid::new_v4().to_string()).execute(&mut *tx).await?;
        for child in &result.children {
            sqlx::query("INSERT INTO live_fork_child(operation_id,child_index,name,machine_id,run_id,activation_id,consumer_id,result_json) VALUES(?1,?2,?3,?4,?5,?6,?7,jsonb(?8))")
                .bind(options.operation_id.to_string()).bind(i64::from(child.index)).bind(&child.name).bind(child.machine_id.to_string()).bind(child.run_id.to_string()).bind(Uuid::new_v4().to_string()).bind(Uuid::new_v4().to_string()).bind(serde_json::to_string(child).map_err(|error| invalid(error.to_string()))?).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'live-fork','staging',?2,?3,jsonb('{}'))").bind(options.operation_id.to_string()).bind(device.to_string()).bind(inode.to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok((result, lease))
    }

    pub(crate) async fn update_fork<F>(&self, operation: Uuid, update: F) -> Result<(), LibVmError>
    where
        F: FnOnce(&mut LiveForkResult) -> Result<(), LibVmError>,
    {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: String =
            sqlx::query_scalar("SELECT json(result_json) FROM live_fork WHERE operation_id=?1")
                .bind(operation.to_string())
                .fetch_one(&mut *tx)
                .await?;
        let mut result: LiveForkResult =
            serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
        update(&mut result)?;
        result.children.clear();
        sqlx::query("UPDATE live_fork SET result_json=jsonb(?2) WHERE operation_id=?1")
            .bind(operation.to_string())
            .bind(serde_json::to_string(&result).map_err(|error| invalid(error.to_string()))?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn fork_children(
        &self,
        operation: Uuid,
    ) -> Result<Vec<ForkChildIdentity>, LibVmError> {
        let rows = sqlx::query("SELECT json(result_json) AS result_json,activation_id,consumer_id,launch_id,submitted,json(failure_json) AS failure_json FROM live_fork_child WHERE operation_id=?1 ORDER BY child_index").bind(operation.to_string()).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(ForkChildIdentity {
                    result: serde_json::from_str(&row.try_get::<String, _>("result_json")?)
                        .map_err(|error| invalid(error.to_string()))?,
                    activation_id: Uuid::parse_str(&row.try_get::<String, _>("activation_id")?)
                        .map_err(|error| invalid(error.to_string()))?,
                    consumer_id: Uuid::parse_str(&row.try_get::<String, _>("consumer_id")?)
                        .map_err(|error| invalid(error.to_string()))?,
                    launch_id: row
                        .try_get::<Option<String>, _>("launch_id")?
                        .map(|id| Uuid::parse_str(&id).map_err(|error| invalid(error.to_string())))
                        .transpose()?,
                    submitted: row.try_get("submitted")?,
                    failure: row
                        .try_get::<Option<String>, _>("failure_json")?
                        .map(|json| {
                            serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))
                        })
                        .transpose()?,
                })
            })
            .collect()
    }

    /// First observed failure wins. The durable submission fence distinguishes
    /// construction from activation; ordinary snapshot restores have no slot.
    pub(crate) async fn record_fork_child_failure(
        &self,
        machine: MachineId,
        run: Uuid,
        error: &LibVmError,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let submitted: Option<bool> = sqlx::query_scalar(
            "SELECT submitted FROM live_fork_child WHERE machine_id=?1 AND run_id=?2",
        )
        .bind(machine.to_string())
        .bind(run.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(submitted) = submitted else {
            return Ok(());
        };
        let failure = ForkChildFailure {
            phase: if submitted {
                ForkFailurePhase::Activation
            } else {
                ForkFailurePhase::Construction
            },
            diagnostic: crate::machine::live_fork::diagnostic(error),
        };
        sqlx::query("UPDATE live_fork_child SET failure_json=jsonb(?3) WHERE machine_id=?1 AND run_id=?2 AND failure_json IS NULL AND json_extract(result_json,'$.outcome.kind')!='running'")
            .bind(machine.to_string())
            .bind(run.to_string())
            .bind(serde_json::to_string(&failure).map_err(|error| invalid(error.to_string()))?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn set_fork_child(
        &self,
        operation: Uuid,
        index: u32,
        outcome: ForkChildOutcome,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let json: String = sqlx::query_scalar("SELECT json(result_json) FROM live_fork_child WHERE operation_id=?1 AND child_index=?2").bind(operation.to_string()).bind(i64::from(index)).fetch_one(&mut *tx).await?;
        let mut child: ForkChildResult =
            serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
        // Running is a historical completion receipt, not current liveness.
        if child.outcome != ForkChildOutcome::Running {
            child.outcome = outcome;
        }
        let terminal = matches!(
            child.outcome,
            ForkChildOutcome::Running
                | ForkChildOutcome::Cancelled
                | ForkChildOutcome::Failed { .. }
                | ForkChildOutcome::Abandoned { .. }
        );
        sqlx::query("UPDATE live_fork_child SET result_json=jsonb(?3),name_reserved=CASE WHEN ?4 THEN 0 ELSE name_reserved END WHERE operation_id=?1 AND child_index=?2").bind(operation.to_string()).bind(i64::from(index)).bind(serde_json::to_string(&child).map_err(|error| invalid(error.to_string()))?).bind(terminal).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn local_cut(&self, operation: Uuid) -> Result<Option<LocalCut>, LibVmError> {
        let json: Option<String> =
            sqlx::query_scalar("SELECT json(record_json) FROM local_cut WHERE operation_id=?1")
                .bind(operation.to_string())
                .fetch_optional(&self.pool)
                .await?;
        json.as_deref()
            .map(|json| {
                let record: LocalCut =
                    serde_json::from_str(json).map_err(|error| invalid(error.to_string()))?;
                if record.operation_id != operation || record.identity()? != record.cut_id {
                    return Err(invalid("local cut identity contradiction"));
                }
                record.plan.validate().map_err(invalid)?;
                record
                    .evidence
                    .validate_against_plan(
                        &record.plan,
                        &Sha256Digest::of_bytes(&record.plan.canonical_bytes().map_err(invalid)?),
                    )
                    .map_err(invalid)?;
                record.storage.validate()?;
                let ram = record
                    .files
                    .iter()
                    .find(|file| file.role == CaptureRole::Ram)
                    .ok_or_else(|| invalid("local cut RAM role missing"))?;
                if record.source_ram.role != CaptureRole::Ram
                    || record.source_ram.inode == 0
                    || record.source_ram.length != ram.length
                    || record.source_ram.identity != ram.identity
                {
                    return Err(invalid(
                        "local cut source/final RAM identities contradict the seal",
                    ));
                }
                if record.capture_id.to_string() != record.plan.capture_id.as_str()
                    || record.storage.snapshot.is_some()
                    || record.files.len() != record.evidence.inventory.len()
                    || record
                        .files
                        .iter()
                        .zip(&record.evidence.inventory)
                        .any(|(file, entry)| {
                            file.role != entry.role
                                || file.length != entry.length
                                || Some(file.identity) != entry.identity.or(entry.sha256)
                                || file.inode == 0
                        })
                {
                    return Err(invalid(
                        "local cut role inventory contradicts authenticated capture",
                    ));
                }
                Ok(record)
            })
            .transpose()
    }
}

impl Store {
    pub(crate) async fn fork_event(
        &self,
        operation: Uuid,
        index: Option<u32>,
        phase: &str,
    ) -> Result<(), LibVmError> {
        let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
            .map_err(std::io::Error::from)?;
        let ns = now
            .tv_sec()
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(now.tv_nsec()))
            .ok_or_else(|| invalid("fork clock overflow"))?;
        sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,child_index,phase,monotonic_ns) VALUES(?1,?2,?3,?4)").bind(operation.to_string()).bind(index.map(i64::from)).bind(phase).bind(ns).execute(&self.pool).await?;
        Ok(())
    }

    /// Reopen the structurally accepted receipt and its immutable role inodes.
    /// Stream bytes are authenticated while constructing each private child.
    pub(crate) async fn open_local_cut(
        &self,
        operation: Uuid,
        retained: Option<AuthenticatedCutDisks>,
    ) -> Result<VerifiedRestoreCut, LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let lease = pool.existing_lease(operation)?;
        self.validate_fork_lease(operation, &lease).await?;
        let record = self
            .local_cut(operation)
            .await?
            .ok_or_else(|| invalid("fork has no authenticated local cut"))?;
        if !record.relocated {
            return Err(invalid("fork cut relocation remains incomplete"));
        }
        drop(_roots);
        let mut retained = match retained {
            Some(retained)
                if retained.operation_id == operation && retained.cut_id == record.cut_id =>
            {
                retained.disks
            }
            Some(_) => {
                return Err(invalid(
                    "retained cut authentication belongs to another operation or cut",
                ))
            }
            None => Vec::new(),
        };
        let directory = crate::paths::OwnedDirectory::open_existing_root(
            &self
                .images_dir
                .join("tmp")
                .join(operation.to_string())
                .join("cut"),
        )?
        .ok_or_else(|| invalid("fork cut directory missing"))?;
        let mut held = Vec::with_capacity(record.files.len());
        for role in &record.files {
            let relative = role.role.relative_path();
            let file = match relative.split_once('/') {
                Some((parent, name)) => directory
                    .open_dir(parent)?
                    .ok_or_else(|| invalid("local cut role parent missing"))?
                    .open_immutable_file(name)?,
                None => directory.open_immutable_file(&relative)?,
            }
            .ok_or_else(|| invalid("local cut role missing"))?;
            let metadata = file.metadata()?;
            if crate::storage::identity_file::SourceFingerprint::new(&metadata) != role.fingerprint
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o400
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                return Err(invalid("local cut immutable inode identity changed"));
            }
            if !matches!(role.role, CaptureRole::Disk(_)) {
                held.push(HeldCutRole::State(file));
                continue;
            }
            let stream = match retained.iter().position(|(disk, _)| disk == &role.role) {
                Some(index) => {
                    let (_, authenticated) = retained.swap_remove(index);
                    if authenticated.fingerprint() != role.fingerprint {
                        return Err(invalid(
                            "retained cut disk authentication differs from the relocated inode",
                        ));
                    }
                    // Checks the held and fresh descriptors, then shares the map.
                    authenticated.reopen(file)?
                }
                None => {
                    let map_role = match &role.role {
                        CaptureRole::Disk(name) => CaptureRole::DiskMap(name.clone()),
                        _ => return Err(invalid("local cut disk role is invalid")),
                    };
                    let map_entry = record
                        .files
                        .iter()
                        .find(|entry| entry.role == map_role)
                        .ok_or_else(|| invalid("local cut disk map is missing"))?;
                    let relative = map_role.relative_path();
                    let (parent, name) = relative
                        .split_once('/')
                        .ok_or_else(|| invalid("local cut disk map path is invalid"))?;
                    let map_file = directory
                        .open_dir(parent)?
                        .ok_or_else(|| invalid("local cut disk map parent is missing"))?
                        .open_immutable_file(name)?
                        .ok_or_else(|| invalid("local cut disk map is missing"))?;
                    if crate::storage::identity_file::SourceFingerprint::new(&map_file.metadata()?)
                        != map_entry.fingerprint
                    {
                        return Err(invalid("local cut disk map inode changed"));
                    }
                    let mut bytes = Vec::new();
                    std::io::Read::take(&map_file, map_entry.length + 1).read_to_end(&mut bytes)?;
                    if Sha256Digest::of_bytes(&bytes) != map_entry.identity {
                        return Err(invalid("local cut disk map digest differs from receipt"));
                    }
                    let map = crate::storage::stream::StreamMap::decode(&bytes)?;
                    if map.length() != role.length
                        || map.id().as_bytes() != role.identity.as_bytes()
                        || map.canonical_bytes()? != bytes
                    {
                        return Err(invalid("local cut disk identity differs from receipt"));
                    }
                    crate::storage::stream::AuthenticatedStream::from_receipt(file, map)?
                }
            };
            held.push(HeldCutRole::Disk(stream));
        }
        if !retained.is_empty() {
            return Err(invalid(
                "retained cut authentication names a role outside the cut",
            ));
        }
        let mut pool_streams: std::collections::BTreeMap<
            crate::storage::identity::StreamId,
            crate::storage::stream::AuthenticatedStream,
        > = std::collections::BTreeMap::new();
        let mut launch_lower = None;
        for input in &record.plan.read_only_inputs {
            let attachment = record
                .plan
                .configuration
                .attachments
                .get(input.attachment_index as usize)
                .ok_or_else(|| invalid("local cut read-only attachment index is missing"))?;
            if attachment.role == vm_spec::DiskRole::RootLower {
                // The layered lower is bound by its composition identity; its
                // occurrences are leased and authenticated by verify_local_lower.
                let crate::MachineRoot::LinuxOverlay { lower, .. } = &record.storage.root else {
                    return Err(invalid("local cut lower input has no layered root"));
                };
                if launch_lower.is_some() || input.identity != lower.record().to_string() {
                    return Err(invalid(
                        "local cut lower input differs from its retained root identity",
                    ));
                }
                let pinned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_lower WHERE operation_id=?1 AND lower_id=?2)").bind(operation.to_string()).bind(lower.record().to_string()).fetch_one(&self.pool).await?;
                if !pinned {
                    return Err(invalid("local cut lower lost its dependency root"));
                }
                launch_lower = Some(
                    crate::store::layer_store::LayerStore::from_store(self.clone())
                        .launch_lower(lower)
                        .await?,
                );
                continue;
            }
            let stream: crate::storage::identity::StreamId = input.identity.parse().map_err(
                |error: crate::storage::identity::IdentityError| invalid(error.to_string()),
            )?;
            let pinned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE operation_id=?1 AND stream_id=?2)").bind(operation.to_string()).bind(stream.to_string()).fetch_one(&self.pool).await?;
            if !pinned {
                return Err(invalid(
                    "local cut read-only input lost its dependency root",
                ));
            }
            let length = attachment.geometry.length;
            match pool_streams.entry(stream) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(crate::machine::stopped::open_immutable_stream(
                        &pool, &stream, length,
                    )?);
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get().length() != length =>
                {
                    return Err(invalid(
                        "local cut read-only input has conflicting geometry",
                    ))
                }
                _ => {}
            }
        }
        let lower = crate::machine::restore::verify_local_lower(
            &pool,
            &record.storage,
            &record.configuration,
            launch_lower.as_ref(),
        )?;
        Ok(VerifiedRestoreCut {
            record,
            held,
            directory,
            _lease: lease,
            pool_streams,
            lower,
        })
    }
}

impl Store {
    pub(crate) async fn reserved_fork_machine(
        &self,
        consumer: Uuid,
        name: &str,
    ) -> Result<Option<MachineId>, LibVmError> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT machine_id,name FROM live_fork_child WHERE consumer_id=?1 AND name_reserved=1",
        )
        .bind(consumer.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(id, reserved)| {
            if reserved != name {
                return Err(invalid("fork child constructor changed its reserved name"));
            }
            id.parse::<MachineId>()
                .map_err(|error| invalid(error.to_string()))
        })
        .transpose()
    }

    pub(crate) async fn child_event(&self, consumer: Uuid, phase: &str) -> Result<(), LibVmError> {
        let row: Option<(String, i64)> = sqlx::query_as(
            "SELECT operation_id,child_index FROM live_fork_child WHERE consumer_id=?1",
        )
        .bind(consumer.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if let Some((operation, index)) = row {
            let operation =
                Uuid::parse_str(&operation).map_err(|error| invalid(error.to_string()))?;
            let index = u32::try_from(index).map_err(|error| invalid(error.to_string()))?;
            match phase {
                "activating" => {
                    self.set_fork_child(operation, index, ForkChildOutcome::Activating)
                        .await?
                }
                "running" => {
                    self.set_fork_child(operation, index, ForkChildOutcome::Running)
                        .await?
                }
                "prepared" => {
                    sqlx::query("UPDATE live_fork_child SET result_json=jsonb_set(result_json,'$.durability',(SELECT durability FROM machine_config WHERE id=live_fork_child.machine_id)) WHERE operation_id=?1 AND child_index=?2")
                        .bind(operation.to_string()).bind(i64::from(index))
                        .execute(&self.pool).await?;
                }
                "durable" => {
                    sqlx::query("UPDATE live_fork_child SET result_json=jsonb_set(result_json,'$.durability','durable') WHERE operation_id=?1 AND child_index=?2")
                        .bind(operation.to_string()).bind(i64::from(index))
                        .execute(&self.pool).await?;
                }
                _ => {}
            }
            self.fork_event(operation, Some(index), phase).await?;
        }
        Ok(())
    }
}

impl Store {
    pub(crate) async fn release_unsubmitted_fork_budget(
        &self,
        operation: Uuid,
    ) -> Result<(), LibVmError> {
        let json: Option<String> = sqlx::query_scalar(
            "SELECT json(charge_json) FROM capture_resource_reservation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(json) = json {
            let mut inventory: crate::store::restore::CaptureBudgetInventory =
                serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
            let children = self.fork_children(operation).await?;
            inventory.pending.retain(|pending| {
                children.iter().any(|child| {
                    child.consumer_id == pending.consumer_id
                        && matches!(
                            child.result.outcome,
                            ForkChildOutcome::Pending
                                | ForkChildOutcome::Constructing
                                | ForkChildOutcome::Activating
                                | ForkChildOutcome::RecoveryPending { .. }
                        )
                })
            });
            inventory.descriptor_owner = None;
            inventory.descriptors = 0;
            sqlx::query("UPDATE capture_resource_reservation SET charge_json=jsonb(?2) WHERE operation_id=?1").bind(operation.to_string()).bind(serde_json::to_string(&inventory).map_err(|error| invalid(error.to_string()))?).execute(&self.pool).await?;
        }
        self.reconcile_restore_budget().await
    }
}

impl Store {
    pub(crate) async fn validate_fork_lease(
        &self,
        operation: Uuid,
        lease: &crate::storage::locks::StorageLock,
    ) -> Result<(), LibVmError> {
        let (device,inode):(String,String)=sqlx::query_as("SELECT file_device,file_inode FROM storage_operation WHERE operation_id=?1 AND kind='live-fork'").bind(operation.to_string()).fetch_one(&self.pool).await?;
        if lease.file_identity()?
            != (
                device
                    .parse()
                    .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?,
                inode
                    .parse()
                    .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?,
            )
        {
            return Err(invalid("fork operation lease inode was replaced"));
        }
        Ok(())
    }
}

impl Store {
    pub(crate) async fn retire_finished_fork_roots(
        &self,
        pool: &StoragePool,
    ) -> Result<(), LibVmError> {
        let mut cursor = String::new();
        loop {
            let operations:Vec<String>=sqlx::query_scalar("SELECT operation_id FROM storage_operation WHERE kind='live-fork' AND operation_id>?1 ORDER BY operation_id LIMIT 256").bind(&cursor).fetch_all(&self.pool).await?;
            if operations.is_empty() {
                break;
            }
            for operation in operations {
                cursor = operation;
                let operation =
                    Uuid::parse_str(&cursor).map_err(|error| invalid(error.to_string()))?;
                let _roots = pool.lock_roots()?;
                let Some(lease) = pool.try_exclusive_lease(operation)? else {
                    continue;
                };
                self.validate_fork_lease(operation, &lease).await?;
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                let finished:bool=sqlx::query_scalar("SELECT json_extract(result_json,'$.stage')='finished' FROM live_fork WHERE operation_id=?1").bind(&cursor).fetch_one(&mut *tx).await?;
                let dependent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation o JOIN live_fork f ON o.operation_id=f.capture_id WHERE f.operation_id=?1 UNION ALL SELECT 1 FROM live_fork_child c JOIN storage_operation o ON o.operation_id=c.consumer_id OR o.operation_id=c.launch_id OR (o.machine_id=c.machine_id AND o.run_id=c.run_id) WHERE c.operation_id=?1 UNION ALL SELECT 1 FROM live_fork_child WHERE operation_id=?1 AND name_reserved=1 UNION ALL SELECT 1 FROM storage_operation_cut d JOIN local_cut l ON l.cut_id=d.cut_id WHERE l.operation_id=?1 AND d.operation_id!=?1)").bind(&cursor).fetch_one(&mut *tx).await?;
                let constructed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM live_fork_child c JOIN machine_config m ON m.id=c.machine_id WHERE c.operation_id=?1 AND m.durability='constructed')")
                    .bind(&cursor).fetch_one(&mut *tx).await?;
                if !finished || dependent || constructed {
                    tx.commit().await?;
                    continue;
                }
                crate::store::ensure_cache_paths_unreferenced(
                    &mut tx,
                    &[self.images_dir.join("tmp").join(&cursor)],
                    &self.home,
                )
                .await?;
                sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                    .bind(&cursor)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("DELETE FROM local_cut WHERE operation_id=?1")
                    .bind(&cursor)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        Ok(())
    }
}

impl Store {
    pub(crate) async fn fork_cancellation_id(&self, operation: Uuid) -> Result<Uuid, LibVmError> {
        let id: String =
            sqlx::query_scalar("SELECT cancellation_id FROM live_fork WHERE operation_id=?1")
                .bind(operation.to_string())
                .fetch_one(&self.pool)
                .await?;
        let id = Uuid::parse_str(&id).map_err(|error| invalid(error.to_string()))?;
        if id.is_nil() {
            return Err(invalid("fork cancellation identity is nil"));
        }
        Ok(id)
    }
}

impl Store {
    /// Preserve the API entry timestamp rather than sampling after admission.
    pub(crate) async fn record_fork_api_entered(
        &self,
        operation: Uuid,
        entered: i64,
    ) -> Result<(), LibVmError> {
        sqlx::query("INSERT OR IGNORE INTO fork_event(operation_id,phase,monotonic_ns) VALUES(?1,'api_entered',?2)")
            .bind(operation.to_string())
            .bind(entered)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Only these exact operation identities can retain the child's ownership.
    pub(crate) async fn fork_child_storage_operations_retained(
        &self,
        consumer: Uuid,
        launch: Option<Uuid>,
    ) -> Result<bool, LibVmError> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 OR operation_id=?2)")
            .bind(consumer.to_string())
            .bind(launch.map(|id| id.to_string()))
            .fetch_one(&self.pool)
            .await?)
    }

    /// Caller holds exclusive parent and consumer leases and has checked the
    /// exact generation's holder. Releasing the name permits consumer cleanup;
    /// the outcome and resource charges remain pending until cleanup completes.
    pub(crate) async fn release_abandoned_fork_name(
        &self,
        operation: Uuid,
        index: u32,
    ) -> Result<(), LibVmError> {
        sqlx::query("UPDATE live_fork_child SET name_reserved=0 WHERE operation_id=?1 AND child_index=?2 AND submitted=0 AND launch_id IS NULL AND NOT EXISTS(SELECT 1 FROM storage_operation o WHERE o.kind='launch' AND o.machine_id=live_fork_child.machine_id AND o.run_id=live_fork_child.run_id)")
            .bind(operation.to_string())
            .bind(i64::from(index))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn forks_requiring_reconciliation(&self) -> Result<Vec<String>, LibVmError> {
        Ok(sqlx::query_scalar("SELECT f.operation_id FROM live_fork f WHERE json_extract(f.result_json,'$.stage')!='finished' OR EXISTS(SELECT 1 FROM live_fork_child c WHERE c.operation_id=f.operation_id AND json_extract(c.result_json,'$.outcome.kind')='recovery-pending') ORDER BY f.operation_id")
            .fetch_all(&self.pool)
            .await?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::machine::live::MachineLiveObservation;
    use crate::paths::LocalPaths;
    use crate::store::models::MachineId;
    use crate::store::{ImageStore, Store};
    use crate::{
        ForkCaptureOutcome, ForkChildOutcome, ForkDestination, ForkSourceOutcome, ForkStage,
        LiveForkChild, LiveForkOptions,
    };
    use uuid::Uuid;

    #[tokio::test]
    async fn fork_recovery_retires_unsubmitted_import_only_after_worker_lease_ends() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = crate::Runtime::open(
            LocalPaths::new(temporary.path().join("home")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let store = runtime.native_store().unwrap();
        let source = MachineId::new();
        let request = options(&["interrupted"]);
        let (_, owner) = store
            .admit_fork(
                source,
                &observation(source, Uuid::new_v4()),
                &request,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        let child = store
            .fork_children(request.operation_id)
            .await
            .unwrap()
            .remove(0);
        let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir()).unwrap();
        let worker = pool.lease(child.consumer_id).unwrap();
        let (device, inode) = worker.file_identity().unwrap();
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'import','staging',?2,?3,jsonb('{}'))")
            .bind(child.consumer_id.to_string()).bind(device.to_string()).bind(inode.to_string())
            .execute(&store.pool).await.unwrap();
        store
            .set_fork_child(request.operation_id, 0, ForkChildOutcome::Constructing)
            .await
            .unwrap();
        store
            .update_fork(request.operation_id, |result| {
                result.capture = ForkCaptureOutcome::Sealed {
                    cut_id: vm_spec::capture::Sha256Digest::of_bytes(b"sealed cut"),
                };
                result.source = ForkSourceOutcome::Resumed;
                Ok(())
            })
            .await
            .unwrap();
        drop(owner);
        let pending = runtime.inspect_fork(request.operation_id).await.unwrap();
        assert!(matches!(
            pending.children[0].outcome,
            ForkChildOutcome::RecoveryPending { .. }
        ));
        assert!(store
            .fork_child_storage_operations_retained(child.consumer_id, None)
            .await
            .unwrap());
        let reserved: bool =
            sqlx::query_scalar("SELECT name_reserved FROM live_fork_child WHERE operation_id=?1")
                .bind(request.operation_id.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(reserved);
        drop(worker);
        let settled = runtime.inspect_fork(request.operation_id).await.unwrap();
        assert!(matches!(
            settled.children[0].outcome,
            ForkChildOutcome::Abandoned { .. }
        ));
        assert!(!store
            .fork_child_storage_operations_retained(child.consumer_id, None)
            .await
            .unwrap());
        assert_eq!(settled.children[0].machine_id, child.result.machine_id);
        assert_eq!(settled.stage, ForkStage::Finished);
    }

    pub(crate) fn options(names: &[&str]) -> LiveForkOptions {
        LiveForkOptions {
            operation_id: Uuid::new_v4(),
            children: names
                .iter()
                .map(|name| LiveForkChild {
                    name: (*name).into(),
                    activation_hook: None,
                    destination: ForkDestination::default(),
                })
                .collect(),
            max_children: crate::DEFAULT_LIVE_FORK_MAX_CHILDREN,
            resume_policy: vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired,
            policy: vm_spec::lifecycle::CapturePolicy::Full,
            dirty_crossover_percent: 60,
            resources: crate::RestoreResourcePolicy::default(),
        }
    }

    pub(crate) fn observation(machine: MachineId, run: Uuid) -> MachineLiveObservation {
        MachineLiveObservation::for_test(
            vm_spec::live::LiveMachineReport {
                schema_version: 1,
                scope: vm_spec::live::LiveScope::Machine,
                machine_id: Uuid::from(machine).to_string(),
                run_id: run.to_string(),
                monitor_id: Uuid::new_v4().to_string(),
                backend: vm_spec::live::LiveBackend::Krun,
                lane: vm_spec::live::LiveLane::KvmX86_64,
                topology_revision: 1,
                live: vm_spec::live::LiveCapabilityVector::all_unsupported(
                    vm_spec::live::LiveReasonCode::LaneNotQualified,
                ),
            },
            vm_spec::lifecycle::VmLifecycleState::Running,
            vm_spec::lifecycle::LiveLifecycle::default(),
        )
    }

    #[tokio::test]
    async fn fork_journal_replay_preserves_all_preselected_identities_and_rejects_changed_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let source = MachineId::new();
        let observed = observation(source, Uuid::new_v4());
        let request = options(&["first", "second"]);
        let capture = Uuid::new_v4();
        let (first, owner) = store
            .admit_fork(source, &observed, &request, capture)
            .await
            .unwrap();
        assert_eq!(first.children.len(), 2);
        assert_eq!(first.children[0].name, "first");
        assert_eq!(first.children[1].name, "second");
        assert_ne!(first.children[0].machine_id, first.children[1].machine_id);
        assert_ne!(first.children[0].run_id, first.children[1].run_id);
        let (replay, _replay_owner) = store
            .admit_fork(source, &observed, &request, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(first, replay);
        let mut changed = request.clone();
        changed.max_children = std::num::NonZeroU32::new(32).unwrap();
        assert!(store
            .admit_fork(source, &observed, &changed, Uuid::new_v4())
            .await
            .is_err());
        assert!(store
            .admit_fork(MachineId::new(), &observed, &request, Uuid::new_v4())
            .await
            .is_err());
        assert_eq!(
            store
                .fork_result(request.operation_id)
                .await
                .unwrap()
                .unwrap(),
            first
        );
        for child in &first.children {
            assert!(!store
                .home
                .join("machines")
                .join(child.machine_id.to_string())
                .exists());
        }
        store
            .validate_fork_lease(request.operation_id, &owner)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fork_name_reservations_are_atomic_and_fence_ordinary_creators() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let source = MachineId::new();
        let observed = observation(source, Uuid::new_v4());
        let first = options(&["first", "second"]);
        let (_, owner) = store
            .admit_fork(source, &observed, &first, Uuid::new_v4())
            .await
            .unwrap();
        let conflicting = options(&["free-name", "second"]);
        assert!(store
            .admit_fork(source, &observed, &conflicting, Uuid::new_v4())
            .await
            .is_err());
        assert!(store
            .fork_result(conflicting.operation_id)
            .await
            .unwrap()
            .is_none());
        let free_name: i64 =
            sqlx::query_scalar("SELECT count(*) FROM live_fork_child WHERE name='free-name'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(free_name, 0, "an entire competing batch must roll back");
        let insert = sqlx::query(
            "INSERT INTO machine_config(id,name,config_json) VALUES(?1,'first',jsonb('{}'))",
        )
        .bind(MachineId::new().to_string())
        .execute(&store.pool)
        .await;
        assert!(
            insert.is_err(),
            "ordinary constructors cannot steal reserved names"
        );
        store
            .set_fork_child(
                first.operation_id,
                0,
                ForkChildOutcome::Abandoned {
                    diagnostic: crate::machine::live_fork::diagnostic("never submitted"),
                },
            )
            .await
            .unwrap();
        let replacement = options(&["first"]);
        let _replacement = store
            .admit_fork(source, &observed, &replacement, Uuid::new_v4())
            .await
            .unwrap();
        drop(owner);
    }

    #[tokio::test]
    async fn store_open_preserves_nonterminal_fork_without_manager_lease_and_one_prune_retires_finished_root(
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let store = Store::new(&paths).await.unwrap();
        let source = MachineId::new();
        let request = options(&["first", "second"]);
        let (accepted, owner) = store
            .admit_fork(
                source,
                &observation(source, Uuid::new_v4()),
                &request,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        let pool = crate::storage::pool::StoragePool::open(&store.images_dir).unwrap();
        let directory = crate::paths::OwnedDirectory::open_existing_root(&store.images_dir)
            .unwrap()
            .unwrap()
            .open_dir("tmp")
            .unwrap()
            .unwrap()
            .ensure_dir(&request.operation_id.to_string())
            .unwrap();
        directory
            .write_file("request.json", b"operation metadata")
            .unwrap();
        let workspace = directory.path().to_path_buf();
        drop(owner);
        drop(directory);
        drop(pool);
        store.close().await;
        let recovered = Store::open(&paths.state_db_path()).await.unwrap();
        assert_eq!(
            std::fs::read(workspace.join("request.json")).unwrap(),
            b"operation metadata"
        );
        assert_eq!(
            recovered
                .fork_result(request.operation_id)
                .await
                .unwrap()
                .unwrap(),
            accepted
        );
        for child in &accepted.children {
            recovered
                .set_fork_child(
                    request.operation_id,
                    child.index,
                    ForkChildOutcome::Abandoned {
                        diagnostic: crate::machine::live_fork::diagnostic("never submitted"),
                    },
                )
                .await
                .unwrap();
        }
        recovered
            .update_fork(request.operation_id, |result| {
                result.capture = ForkCaptureOutcome::Abandoned {
                    diagnostic: crate::machine::live_fork::diagnostic("never submitted"),
                };
                result.source = ForkSourceOutcome::Unchanged;
                result.stage = ForkStage::Finished;
                Ok(())
            })
            .await
            .unwrap();
        recovered.prune_images().await.unwrap();
        assert!(!workspace.exists());
        let roots: i64 =
            sqlx::query_scalar("SELECT count(*) FROM storage_operation WHERE operation_id=?1")
                .bind(request.operation_id.to_string())
                .fetch_one(&recovered.pool)
                .await
                .unwrap();
        assert_eq!(roots, 0);
        assert_eq!(
            recovered
                .fork_result(request.operation_id)
                .await
                .unwrap()
                .unwrap()
                .stage,
            ForkStage::Finished,
            "results outlive operation roots and the source"
        );
    }

    #[tokio::test]
    async fn fork_running_receipt_is_not_overwritten_by_late_cancellation() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temporary.path().join("home")))
            .await
            .unwrap();
        let source = MachineId::new();
        let request = options(&["first", "second"]);
        let (_, owner) = store
            .admit_fork(
                source,
                &observation(source, Uuid::new_v4()),
                &request,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        store
            .set_fork_child(request.operation_id, 0, ForkChildOutcome::Running)
            .await
            .unwrap();
        store
            .update_fork(request.operation_id, |result| {
                result.cancellation_requested = true;
                Ok(())
            })
            .await
            .unwrap();
        store
            .set_fork_child(request.operation_id, 0, ForkChildOutcome::Cancelled)
            .await
            .unwrap();
        store
            .set_fork_child(request.operation_id, 1, ForkChildOutcome::Cancelled)
            .await
            .unwrap();
        let result = store
            .fork_result(request.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.children[0].outcome, ForkChildOutcome::Running);
        assert_eq!(result.children[1].outcome, ForkChildOutcome::Cancelled);
        drop(owner);
    }

    #[tokio::test]
    async fn fork_activation_failure_survives_cleanup_and_keeps_running_siblings() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path().join("home"));
        let runtime = crate::Runtime::open(paths, crate::RuntimeNetworkingConfig::default())
            .await
            .unwrap();
        let store = runtime.native_store().unwrap();
        let source = MachineId::new();
        let request = options(&["fork-a", "fork-b", "fork-c", "fork-d"]);
        let (accepted, owner) = store
            .admit_fork(
                source,
                &observation(source, Uuid::new_v4()),
                &request,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        let operation = request.operation_id;
        let failed = &accepted.children[2];
        let run = Uuid::parse_str(failed.run_id.as_str()).unwrap();
        let original = crate::LibVmError::Io(std::io::Error::other(
            "restore activation failed: stage=exposure code=handshake-failed: activation hook exited exit status: 7",
        ));
        // Only this preselected machine/run may retain the failure.
        store
            .record_fork_child_failure(failed.machine_id, Uuid::new_v4(), &original)
            .await
            .unwrap();
        assert!(store.fork_children(operation).await.unwrap()[2]
            .failure
            .is_none());
        let launch = Uuid::new_v4();
        sqlx::query("UPDATE live_fork_child SET launch_id=?2,submitted=1 WHERE operation_id=?1 AND child_index=2")
            .bind(operation.to_string())
            .bind(launch.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        store
            .record_fork_child_failure(failed.machine_id, run, &original)
            .await
            .unwrap();
        // Later cleanup failures must not replace the original diagnostic.
        store
            .record_fork_child_failure(
                failed.machine_id,
                run,
                &crate::LibVmError::Io(std::io::Error::other("cleanup transport lost")),
            )
            .await
            .unwrap();
        let child = store.fork_children(operation).await.unwrap().remove(2);
        let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir()).unwrap();
        let consumer = pool.lease(child.consumer_id).unwrap();
        let (device, inode) = consumer.file_identity().unwrap();
        sqlx::query("INSERT INTO storage_operation(operation_id,schema,kind,state,file_device,file_inode,record_json) VALUES(?1,1,'import','committed',?2,?3,jsonb('{}'))")
            .bind(child.consumer_id.to_string())
            .bind(device.to_string())
            .bind(inode.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        for sibling in [0, 1, 3] {
            store
                .set_fork_child(operation, sibling, ForkChildOutcome::Running)
                .await
                .unwrap();
        }
        store
            .set_fork_child(
                operation,
                2,
                ForkChildOutcome::RecoveryPending {
                    diagnostic: crate::machine::live_fork::diagnostic("cleanup still owns run"),
                },
            )
            .await
            .unwrap();
        store
            .update_fork(operation, |result| {
                result.capture = ForkCaptureOutcome::Sealed {
                    cut_id: vm_spec::capture::Sha256Digest::of_bytes(b"sealed cut"),
                };
                result.source = ForkSourceOutcome::Resumed;
                result.stage = ForkStage::Settling;
                Ok(())
            })
            .await
            .unwrap();
        drop(owner);
        let pending = runtime.inspect_fork(operation).await.unwrap();
        assert!(matches!(
            pending.children[2].outcome,
            ForkChildOutcome::RecoveryPending { .. }
        ));
        assert!(store
            .fork_child_storage_operations_retained(child.consumer_id, Some(launch))
            .await
            .unwrap());
        drop(consumer);
        let settled = runtime.inspect_fork(operation).await.unwrap();
        assert_eq!(settled.children[2].name, "fork-c");
        assert_eq!(settled.children[2].machine_id, failed.machine_id);
        assert_eq!(settled.children[2].run_id, failed.run_id);
        assert_eq!(
            settled.children[2].outcome,
            ForkChildOutcome::Failed {
                phase: crate::ForkFailurePhase::Activation,
                diagnostic: crate::machine::live_fork::diagnostic(original),
            }
        );
        for sibling in [0, 1, 3] {
            assert_eq!(settled.children[sibling].outcome, ForkChildOutcome::Running);
        }
        assert_eq!(settled.stage, ForkStage::Finished);
        assert_eq!(settled.source, ForkSourceOutcome::Resumed);
        assert_eq!(runtime.inspect_fork(operation).await.unwrap(), settled);
    }

    #[tokio::test]
    async fn fork_recovery_distinguishes_observed_construction_failure_from_lost_manager() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = crate::Runtime::open(
            LocalPaths::new(temporary.path().join("home")),
            crate::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let store = runtime.native_store().unwrap();
        let source = MachineId::new();
        let request = options(&["construction-failed", "lost-receipt"]);
        let (accepted, owner) = store
            .admit_fork(
                source,
                &observation(source, Uuid::new_v4()),
                &request,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        // Generation registration alone is not activation submission.
        sqlx::query(
            "UPDATE live_fork_child SET launch_id=?2 WHERE operation_id=?1 AND child_index=0",
        )
        .bind(request.operation_id.to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(&store.pool)
        .await
        .unwrap();
        let original = crate::LibVmError::Io(std::io::Error::other("é".repeat(4096)));
        store
            .record_fork_child_failure(
                accepted.children[0].machine_id,
                Uuid::parse_str(accepted.children[0].run_id.as_str()).unwrap(),
                &original,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE live_fork_child SET launch_id=?2,submitted=1 WHERE operation_id=?1 AND child_index=1")
            .bind(request.operation_id.to_string())
            .bind(Uuid::new_v4().to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        store
            .update_fork(request.operation_id, |result| {
                result.capture = ForkCaptureOutcome::Sealed {
                    cut_id: vm_spec::capture::Sha256Digest::of_bytes(b"sealed cut"),
                };
                result.source = ForkSourceOutcome::Resumed;
                Ok(())
            })
            .await
            .unwrap();
        drop(owner);
        let result = runtime.inspect_fork(request.operation_id).await.unwrap();
        let diagnostic = crate::machine::live_fork::diagnostic(original);
        assert_eq!(
            diagnostic.as_str().len(),
            vm_spec::lifecycle::MAX_LIFECYCLE_DIAGNOSTIC_BYTES
        );
        assert_eq!(
            result.children[0].outcome,
            ForkChildOutcome::Failed {
                phase: crate::ForkFailurePhase::Construction,
                diagnostic,
            }
        );
        assert!(matches!(
            result.children[1].outcome,
            ForkChildOutcome::Abandoned { .. }
        ));
    }
}

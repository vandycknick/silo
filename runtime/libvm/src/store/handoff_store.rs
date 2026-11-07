//! SQLite-backed two-party ownership decisions. No lease or timeout decides an outcome.
use crate::handoff::types::*;
use crate::store::Store;
use crate::{LibVmError, MachineId, MachineOwnership, MachineStorageRecord};
use sqlx::{Sqlite, Transaction};

fn conflict(operation: OperationId) -> LibVmError {
    HandoffError::OperationConflict { operation }.into()
}
fn missing(operation: OperationId) -> LibVmError {
    HandoffError::UnknownOperation { operation }.into()
}

async fn read(
    tx: &mut Transaction<'_, Sqlite>,
    operation: OperationId,
) -> Result<Option<HandoffRecord>, LibVmError> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT json(record_json) FROM handoff_operation WHERE operation_id=?1")
            .bind(operation.to_string())
            .fetch_optional(&mut **tx)
            .await?;
    json.map(|json| {
        let record = HandoffRecord::decode(&json)?;
        if record.intent.operation != operation {
            return Err(conflict(operation));
        }
        Ok(record)
    })
    .transpose()
}
async fn write(
    tx: &mut Transaction<'_, Sqlite>,
    record: &HandoffRecord,
    insert: bool,
) -> Result<(), LibVmError> {
    record.validate()?;
    let json = serde_json::to_string(record).map_err(|error| LibVmError::StateDecode {
        field: "handoff_operation.record_json",
        message: error.to_string(),
    })?;
    crate::storage::limits::Resource::MetadataPageBytes
        .check(json.len() as u64)
        .map_err(crate::storage::StorageError::from)?;
    let role = match record.role {
        HandoffRole::Source => "source",
        HandoffRole::Destination => "destination",
    };
    let mode = match record.intent.mode {
        HandoffMode::Fork => "fork",
        HandoffMode::Relocate => "relocate",
    };
    let phase = match record.phase {
        HandoffPhase::Intended => "intended",
        HandoffPhase::Reserved => "reserved",
        HandoffPhase::Captured => "captured",
        HandoffPhase::Fenced => "fenced",
        HandoffPhase::Receiving => "receiving",
        HandoffPhase::Prepared => "prepared",
        HandoffPhase::Committed => "committed",
        HandoffPhase::Aborted => "aborted",
    };
    if insert {
        sqlx::query("INSERT INTO handoff_operation(operation_id,schema,role,mode,source_machine,destination_machine,phase,terminal,record_json,source_runtime,destination_runtime,from_epoch,next_epoch) VALUES(?1,1,?2,?3,?4,?5,?6,?7,jsonb(?8),?9,?10,?11,?12)")
            .bind(record.intent.operation.to_string()).bind(role).bind(mode).bind(record.intent.source_machine.to_string()).bind(record.intent.destination_machine.to_string()).bind(phase).bind(record.phase.is_terminal()).bind(json)
            .bind(record.intent.source_runtime.to_string()).bind(record.intent.destination_runtime.to_string())
            .bind(record.intent.from_epoch.get() as i64).bind(record.intent.destination_epoch()?.get() as i64)
            .execute(&mut **tx).await.map_err(|error| {
                if error.as_database_error().is_some_and(|error| error.is_unique_violation()) { conflict(record.intent.operation) } else { error.into() }
            })?;
    } else {
        let changed = sqlx::query("UPDATE handoff_operation SET phase=?1,terminal=?2,record_json=jsonb(?3) WHERE operation_id=?4 AND terminal=0")
            .bind(phase).bind(record.phase.is_terminal()).bind(json).bind(record.intent.operation.to_string()).execute(&mut **tx).await?;
        if changed.rows_affected() != 1 {
            return Err(HandoffError::InvalidState.into());
        }
    }
    Ok(())
}
async fn storage(
    tx: &mut Transaction<'_, Sqlite>,
    machine: MachineId,
) -> Result<Option<MachineStorageRecord>, LibVmError> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT json(record_json) FROM machine_storage WHERE machine_id=?1")
            .bind(machine.to_string())
            .fetch_optional(&mut **tx)
            .await?;
    json.map(|json| MachineStorageRecord::decode(&json))
        .transpose()
}
async fn require_stopped(
    tx: &mut Transaction<'_, Sqlite>,
    machine: MachineId,
    allow_error: bool,
) -> Result<(), LibVmError> {
    let stopped:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_state WHERE machine_id=?1 AND (status='stopped' OR (?2 AND status='error'))) AND NOT EXISTS(SELECT 1 FROM storage_operation WHERE machine_id=?1 AND kind='launch')")
        .bind(machine.to_string()).bind(allow_error).fetch_one(&mut **tx).await?;
    if !stopped {
        return Err(HandoffError::InvalidState.into());
    }
    Ok(())
}
fn check(
    record: &HandoffRecord,
    intent: &HandoffIntent,
    role: HandoffRole,
) -> Result<(), LibVmError> {
    if record.intent != *intent || record.role != role {
        return Err(conflict(intent.operation));
    }
    Ok(())
}
fn fresh(intent: &HandoffIntent, role: HandoffRole) -> HandoffRecord {
    HandoffRecord {
        schema: 1,
        role,
        intent: intent.clone(),
        binding: None,
        phase: if role == HandoffRole::Source {
            HandoffPhase::Reserved
        } else {
            HandoffPhase::Receiving
        },
        prepared: None,
        authorization: None,
        terminal: None,
    }
}
async fn check_collision(
    tx: &mut Transaction<'_, Sqlite>,
    intent: &HandoffIntent,
) -> Result<(), LibVmError> {
    let existing: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_config WHERE id=?1)")
            .bind(intent.destination_machine.to_string())
            .fetch_one(&mut **tx)
            .await?;
    if !existing {
        return Ok(());
    }
    let previous =
        storage(tx, intent.destination_machine)
            .await?
            .ok_or(HandoffError::MachineIdConflict {
                machine: intent.destination_machine,
            })?;
    match (&previous.ownership, intent.mode) {
        (
            MachineOwnership::Relocated {
                successor_runtime,
                successor_epoch,
                ..
            },
            HandoffMode::Relocate,
        ) if *successor_runtime == intent.source_runtime
            && *successor_epoch == intent.from_epoch =>
        {
            Ok(())
        }
        (MachineOwnership::Relocated { .. }, _) => Err(HandoffError::ReturnOwnerMismatch {
            machine: intent.destination_machine,
        }
        .into()),
        _ => Err(HandoffError::MachineIdConflict {
            machine: intent.destination_machine,
        }
        .into()),
    }
}

impl Store {
    pub(crate) async fn runtime_id(&self) -> Result<RuntimeId, LibVmError> {
        let value: String = sqlx::query_scalar("SELECT runtime_id FROM db_config WHERE id=1")
            .fetch_one(&self.pool)
            .await?;
        let id = uuid::Uuid::parse_str(&value).map_err(|_| HandoffError::InvalidIdentity)?;
        Ok(RuntimeId::new(id)?)
    }
    async fn handoff_participant(
        &self,
        intent: &HandoffIntent,
        role: HandoffRole,
    ) -> Result<(), LibVmError> {
        intent.validate()?;
        let expected = if role == HandoffRole::Source {
            intent.source_runtime
        } else {
            intent.destination_runtime
        };
        if self.runtime_id().await? != expected {
            return Err(HandoffError::WrongRuntime.into());
        }
        Ok(())
    }
    pub(crate) async fn get_handoff(
        &self,
        operation: OperationId,
    ) -> Result<Option<HandoffRecord>, LibVmError> {
        let mut tx = self.pool.begin().await?;
        let record = read(&mut tx, operation).await?;
        tx.commit().await?;
        Ok(record)
    }
    /// Persist approved intent and its GC identity while the machine may run.
    pub(crate) async fn begin_handoff_source(
        &self,
        intent: &HandoffIntent,
    ) -> Result<HandoffRecord, LibVmError> {
        self.handoff_participant(intent, HandoffRole::Source)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(record) = read(&mut tx, intent.operation).await? {
            check(&record, intent, HandoffRole::Source)?;
            tx.commit().await?;
            return Ok(record);
        }
        let current = storage(&mut tx, intent.source_machine)
            .await?
            .ok_or(HandoffError::AdmissionStale)?;
        current.ownership.ensure_owned(intent.source_machine)?;
        if current.ownership_epoch != intent.from_epoch.get() || current.operation.is_some() {
            return Err(HandoffError::AdmissionStale.into());
        }
        let mut record = fresh(intent, HandoffRole::Source);
        record.phase = HandoffPhase::Intended;
        write(&mut tx, &record, true).await?;
        tx.commit().await?;
        Ok(record)
    }
    /// Caller holds the source lifecycle lock before beginning this transition.
    pub(crate) async fn reserve_handoff_source(
        &self,
        intent: &HandoffIntent,
    ) -> Result<HandoffRecord, LibVmError> {
        self.handoff_participant(intent, HandoffRole::Source)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing = read(&mut tx, intent.operation).await?;
        if let Some(record) = &existing {
            check(record, intent, HandoffRole::Source)?;
            if record.phase != HandoffPhase::Intended {
                tx.commit().await?;
                return Ok(record.clone());
            }
        }
        let mut current = storage(&mut tx, intent.source_machine)
            .await?
            .ok_or(HandoffError::AdmissionStale)?;
        current.ownership.ensure_owned(intent.source_machine)?;
        if current.ownership_epoch != intent.from_epoch.get() || current.operation.is_some() {
            return Err(HandoffError::AdmissionStale.into());
        }
        current.ownership = MachineOwnership::Reserved {
            operation: intent.operation,
        };
        Self::write_machine_storage(&mut tx, intent.source_machine, &current).await?;
        let record = fresh(intent, HandoffRole::Source);
        write(&mut tx, &record, existing.is_none()).await?;
        tx.commit().await?;
        Ok(record)
    }
    pub(crate) async fn receive_handoff(
        &self,
        intent: &HandoffIntent,
    ) -> Result<HandoffRecord, LibVmError> {
        self.handoff_participant(intent, HandoffRole::Destination)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(record) = read(&mut tx, intent.operation).await? {
            check(&record, intent, HandoffRole::Destination)?;
            if record.phase == HandoffPhase::Aborted {
                return Err(HandoffError::OperationAborted {
                    operation: intent.operation,
                }
                .into());
            }
            tx.commit().await?;
            return Ok(record);
        }
        check_collision(&mut tx, intent).await?;
        let record = fresh(intent, HandoffRole::Destination);
        write(&mut tx, &record, true).await?;
        tx.commit().await?;
        Ok(record)
    }
    pub(crate) async fn bind_handoff_capture(
        &self,
        binding: &HandoffBinding,
    ) -> Result<HandoffRecord, LibVmError> {
        self.bind_handoff(binding, HandoffRole::Source).await
    }
    pub(crate) async fn offer_handoff_capture(
        &self,
        binding: &HandoffBinding,
    ) -> Result<HandoffRecord, LibVmError> {
        self.bind_handoff(binding, HandoffRole::Destination).await
    }
    async fn bind_handoff(
        &self,
        binding: &HandoffBinding,
        role: HandoffRole,
    ) -> Result<HandoffRecord, LibVmError> {
        self.handoff_participant(&binding.intent, role).await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = read(&mut tx, binding.intent.operation)
            .await?
            .ok_or_else(|| missing(binding.intent.operation))?;
        check(&record, &binding.intent, role)?;
        if record.phase == HandoffPhase::Aborted {
            return Err(HandoffError::OperationAborted {
                operation: binding.intent.operation,
            }
            .into());
        }
        if let Some(previous) = &record.binding {
            if previous != binding {
                return Err(HandoffError::ReceiptMismatch.into());
            }
            tx.commit().await?;
            return Ok(record);
        }
        if role == HandoffRole::Source {
            let current = storage(&mut tx, binding.intent.source_machine)
                .await?
                .ok_or(HandoffError::AdmissionStale)?;
            if current.ownership
                != (MachineOwnership::Reserved {
                    operation: binding.intent.operation,
                })
                || current.ownership_epoch != binding.intent.from_epoch.get()
            {
                return Err(HandoffError::AdmissionStale.into());
            }
            require_stopped(&mut tx, binding.intent.source_machine, true).await?;
            record.phase = HandoffPhase::Captured;
        } else {
            check_collision(&mut tx, &binding.intent).await?;
        }
        record.binding = Some(binding.clone());
        write(&mut tx, &record, false).await?;
        tx.commit().await?;
        Ok(record)
    }
    /// Files and dependency pins must already be durable under this operation.
    pub(crate) async fn prepare_handoff_destination(
        &self,
        binding: &HandoffBinding,
    ) -> Result<PreparedReceipt, LibVmError> {
        self.handoff_participant(&binding.intent, HandoffRole::Destination)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = read(&mut tx, binding.intent.operation)
            .await?
            .ok_or_else(|| missing(binding.intent.operation))?;
        check(&record, &binding.intent, HandoffRole::Destination)?;
        if record.binding.as_ref() != Some(binding) {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        if record.phase == HandoffPhase::Aborted {
            return Err(HandoffError::OperationAborted {
                operation: binding.intent.operation,
            }
            .into());
        }
        if let Some(receipt) = &record.prepared {
            let receipt = receipt.clone();
            tx.commit().await?;
            return Ok(receipt);
        }
        if record.phase != HandoffPhase::Receiving {
            return Err(HandoffError::InvalidState.into());
        }
        check_collision(&mut tx, &binding.intent).await?;
        let receipt = PreparedReceipt {
            binding: binding.clone(),
            receipt_id: uuid::Uuid::new_v4(),
        };
        record.prepared = Some(receipt.clone());
        record.phase = HandoffPhase::Prepared;
        write(&mut tx, &record, false).await?;
        tx.commit().await?;
        Ok(receipt)
    }
    pub(crate) async fn fence_handoff_source(
        &self,
        prepared: &PreparedReceipt,
    ) -> Result<CommitAuthorization, LibVmError> {
        let intent = &prepared.binding.intent;
        self.handoff_participant(intent, HandoffRole::Source)
            .await?;
        if prepared.receipt_id.is_nil() {
            return Err(HandoffError::InvalidIdentity.into());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = read(&mut tx, intent.operation)
            .await?
            .ok_or_else(|| missing(intent.operation))?;
        check(&record, intent, HandoffRole::Source)?;
        if record.binding.as_ref() != Some(&prepared.binding)
            || record
                .prepared
                .as_ref()
                .is_some_and(|value| value != prepared)
        {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        if record.phase == HandoffPhase::Aborted {
            return Err(HandoffError::OperationAborted {
                operation: intent.operation,
            }
            .into());
        }
        if let Some(auth) = &record.authorization {
            let auth = auth.clone();
            tx.commit().await?;
            return Ok(auth);
        }
        if record.phase != HandoffPhase::Captured {
            return Err(HandoffError::InvalidState.into());
        }
        let mut current = storage(&mut tx, intent.source_machine)
            .await?
            .ok_or(HandoffError::AdmissionStale)?;
        if current.ownership
            != (MachineOwnership::Reserved {
                operation: intent.operation,
            })
            || current.ownership_epoch != intent.from_epoch.get()
        {
            return Err(HandoffError::AdmissionStale.into());
        }
        require_stopped(&mut tx, intent.source_machine, true).await?;
        // Fork authorization also records a durable stop reservation, but never advances source ownership.
        if intent.mode == HandoffMode::Relocate {
            current.ownership = MachineOwnership::Fenced {
                operation: intent.operation,
                destination_runtime: intent.destination_runtime,
                next_epoch: intent.destination_epoch()?,
            };
            Self::write_machine_storage(&mut tx, intent.source_machine, &current).await?;
        }
        let authorization = CommitAuthorization {
            prepared: prepared.clone(),
            nonce: uuid::Uuid::new_v4(),
        };
        record.prepared = Some(prepared.clone());
        record.authorization = Some(authorization.clone());
        record.phase = HandoffPhase::Fenced;
        write(&mut tx, &record, false).await?;
        tx.commit().await?;
        Ok(authorization)
    }
    pub(crate) async fn abort_handoff_destination(
        &self,
        intent: &HandoffIntent,
    ) -> Result<TerminalReceipt, LibVmError> {
        self.handoff_participant(intent, HandoffRole::Destination)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let previous = read(&mut tx, intent.operation).await?;
        let insert = previous.is_none();
        let mut record = previous.unwrap_or_else(|| fresh(intent, HandoffRole::Destination));
        check(&record, intent, HandoffRole::Destination)?;
        if let Some(receipt) = record.terminal {
            tx.commit().await?;
            return Ok(receipt);
        }
        let receipt = TerminalReceipt {
            intent: intent.clone(),
            binding: record.binding.clone(),
            decision: HandoffDecision::Aborted,
            authorization: None,
        };
        record.phase = HandoffPhase::Aborted;
        record.terminal = Some(receipt.clone());
        write(&mut tx, &record, insert).await?;
        tx.commit().await?;
        Ok(receipt)
    }
    pub(crate) async fn resolve_handoff_source(
        &self,
        receipt: &TerminalReceipt,
    ) -> Result<HandoffRecord, LibVmError> {
        receipt.validate()?;
        let intent = &receipt.intent;
        self.handoff_participant(intent, HandoffRole::Source)
            .await?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = read(&mut tx, intent.operation)
            .await?
            .ok_or_else(|| missing(intent.operation))?;
        check(&record, intent, HandoffRole::Source)?;
        if let Some(previous) = &record.terminal {
            if previous != receipt {
                return Err(HandoffError::ReceiptMismatch.into());
            }
            tx.commit().await?;
            return Ok(record);
        }
        if receipt
            .binding
            .as_ref()
            .is_some_and(|binding| record.binding.as_ref() != Some(binding))
        {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        if record.phase == HandoffPhase::Intended {
            if receipt.decision != HandoffDecision::Aborted {
                return Err(HandoffError::ReceiptMismatch.into());
            }
            record.phase = HandoffPhase::Aborted;
            record.terminal = Some(receipt.clone());
            write(&mut tx, &record, false).await?;
            tx.commit().await?;
            return Ok(record);
        }
        let mut current = storage(&mut tx, intent.source_machine)
            .await?
            .ok_or(HandoffError::AdmissionStale)?;
        let reserved = MachineOwnership::Reserved {
            operation: intent.operation,
        };
        let fenced = MachineOwnership::Fenced {
            operation: intent.operation,
            destination_runtime: intent.destination_runtime,
            next_epoch: intent.destination_epoch()?,
        };
        if current.ownership_epoch != intent.from_epoch.get()
            || (current.ownership != reserved && current.ownership != fenced)
        {
            return Err(HandoffError::AdmissionStale.into());
        }
        match receipt.decision {
            HandoffDecision::Committed => {
                if record.authorization != receipt.authorization
                    || record.phase != HandoffPhase::Fenced
                    || record.binding != receipt.binding
                {
                    return Err(HandoffError::ReceiptMismatch.into());
                }
                current.ownership = if intent.mode == HandoffMode::Relocate {
                    MachineOwnership::Relocated {
                        operation: intent.operation,
                        successor_runtime: intent.destination_runtime,
                        successor_epoch: intent.destination_epoch()?,
                    }
                } else {
                    MachineOwnership::Owned
                };
                record.phase = HandoffPhase::Committed;
            }
            HandoffDecision::Aborted => {
                current.ownership = MachineOwnership::Owned;
                record.phase = HandoffPhase::Aborted;
            }
        }
        record.terminal = Some(receipt.clone());
        Self::write_machine_storage(&mut tx, intent.source_machine, &current).await?;
        write(&mut tx, &record, false).await?;
        tx.commit().await?;
        Ok(record)
    }
    /// Holds BEGIN IMMEDIATE from collision admission through complete publication.
    pub(crate) async fn begin_handoff_destination_commit(
        &self,
        authorization: &CommitAuthorization,
    ) -> Result<HandoffDestinationCommit<'_>, LibVmError> {
        let intent = &authorization.prepared.binding.intent;
        self.handoff_participant(intent, HandoffRole::Destination)
            .await?;
        if authorization.nonce.is_nil() || authorization.prepared.receipt_id.is_nil() {
            return Err(HandoffError::InvalidIdentity.into());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let record = read(&mut tx, intent.operation)
            .await?
            .ok_or_else(|| missing(intent.operation))?;
        check(&record, intent, HandoffRole::Destination)?;
        if record.phase == HandoffPhase::Aborted {
            return Err(HandoffError::OperationAborted {
                operation: intent.operation,
            }
            .into());
        }
        if record.prepared.as_ref() != Some(&authorization.prepared) {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        if let Some(terminal) = &record.terminal {
            if terminal.authorization.as_ref() != Some(authorization) {
                return Err(HandoffError::ReceiptMismatch.into());
            }
        } else {
            if record.phase != HandoffPhase::Prepared {
                return Err(HandoffError::InvalidState.into());
            }
            check_collision(&mut tx, intent).await?;
        }
        Ok(HandoffDestinationCommit {
            tx,
            record,
            authorization: authorization.clone(),
        })
    }
}

pub(crate) struct HandoffDestinationCommit<'a> {
    tx: Transaction<'a, Sqlite>,
    record: HandoffRecord,
    authorization: CommitAuthorization,
}
impl<'a> HandoffDestinationCommit<'a> {
    pub(crate) fn terminal_receipt(&self) -> Option<&TerminalReceipt> {
        self.record.terminal.as_ref()
    }
    pub(crate) fn transaction(&mut self) -> Result<&mut Transaction<'a, Sqlite>, LibVmError> {
        if self.record.terminal.is_some() {
            return Err(HandoffError::InvalidState.into());
        }
        Ok(&mut self.tx)
    }
    pub(crate) async fn commit(mut self) -> Result<TerminalReceipt, LibVmError> {
        if let Some(receipt) = self.record.terminal {
            self.tx.commit().await?;
            return Ok(receipt);
        }
        let intent = &self.record.intent;
        let published = storage(&mut self.tx, intent.destination_machine)
            .await?
            .ok_or(HandoffError::InvalidState)?;
        require_stopped(&mut self.tx, intent.destination_machine, false).await?;
        if !published.ownership.is_owned()
            || published.ownership_epoch != intent.destination_epoch()?.get()
            || published.operation.is_some()
        {
            return Err(HandoffError::InvalidState.into());
        }
        let receipt = TerminalReceipt {
            intent: intent.clone(),
            binding: self.record.binding.clone(),
            decision: HandoffDecision::Committed,
            authorization: Some(self.authorization.clone()),
        };
        self.record.phase = HandoffPhase::Committed;
        self.record.authorization = Some(self.authorization);
        self.record.terminal = Some(receipt.clone());
        write(&mut self.tx, &self.record, false).await?;
        self.tx.commit().await?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use crate::handoff::types::*;
    use crate::store::models::{
        MachineConfig, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::{MachineStore, Store};
    use crate::{MachineId, MachineOwnership};

    async fn catalog() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::LocalPaths::new(dir.path());
        let store = Store::new(&paths).await.unwrap();
        (dir, store)
    }
    fn config(store: &Store, id: MachineId) -> MachineConfig {
        MachineConfig {
            id,
            lock_id: crate::lock_manager::LockId::from(0),
            name: "handoff-test".into(),
            spec: vm_spec::VmSpec::current(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            machine_dir: crate::paths::machine_data_dir_in(store.home_path(), id),
            created_at: 1,
            modified_at: 1,
            image_ref: String::new(),
            root_disk_size: None,
            labels: Default::default(),
            metadata: Default::default(),
            network: MachineNetworkConfig::default(),
            guest: crate::machine::MachineGuestConfig::default(),
        }
    }
    fn state(id: MachineId) -> MachineState {
        MachineState {
            machine_id: id,
            status: MachineRuntimeState::Stopped,
            vmm_pid: None,
            started_at: None,
            run_id: None,
            last_error: None,
            updated_at: 1,
        }
    }
    async fn seed(store: &Store, id: MachineId) {
        store
            .add_machine(&config(store, id), &state(id))
            .await
            .unwrap();
    }
    async fn new_intent(
        source: &Store,
        destination: &Store,
        machine: MachineId,
        epoch: u64,
    ) -> HandoffIntent {
        HandoffIntent {
            operation: OperationId::new(uuid::Uuid::new_v4()).unwrap(),
            mode: HandoffMode::Relocate,
            source_runtime: source.runtime_id().await.unwrap(),
            destination_runtime: destination.runtime_id().await.unwrap(),
            source_machine: machine,
            destination_machine: machine,
            from_epoch: OwnershipEpoch::new(epoch).unwrap(),
            intent_digest: crate::storage::identity::ObjectDigest::of_bytes(
                b"approved immutable intent",
            ),
            approved_plan_digest: crate::storage::identity::ObjectDigest::of_bytes(
                b"approved complete plan",
            ),
        }
    }
    fn binding(intent: &HandoffIntent) -> HandoffBinding {
        HandoffBinding {
            intent: intent.clone(),
            capture: CaptureId::new(uuid::Uuid::new_v4()).unwrap(),
            capture_manifest_digest: crate::storage::identity::ObjectDigest::of_bytes(
                b"sealed stopped cut",
            ),
        }
    }
    async fn prepared(
        source: &Store,
        destination: &Store,
        intent: &HandoffIntent,
    ) -> PreparedReceipt {
        source.reserve_handoff_source(intent).await.unwrap();
        destination.receive_handoff(intent).await.unwrap();
        let binding = binding(intent);
        source.bind_handoff_capture(&binding).await.unwrap();
        destination.offer_handoff_capture(&binding).await.unwrap();
        destination
            .prepare_handoff_destination(&binding)
            .await
            .unwrap()
    }
    async fn publish(
        store: &Store,
        auth: &CommitAuthorization,
        intent: &HandoffIntent,
    ) -> TerminalReceipt {
        let config = config(store, intent.destination_machine);
        let state = state(config.id);
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let _boot = store.pin_test_boot(&mut storage).await.unwrap();
        storage.ownership_epoch = intent.destination_epoch().unwrap().get();
        let mut commit = store.begin_handoff_destination_commit(auth).await.unwrap();
        assert!(commit.terminal_receipt().is_none());
        let tx = commit.transaction().unwrap();
        sqlx::query("INSERT INTO machine_config(id,name,config_json) VALUES(?1,?2,jsonb(?3)) ON CONFLICT(id) DO UPDATE SET name=excluded.name,config_json=excluded.config_json")
            .bind(config.id.to_string()).bind(&config.name).bind(serde_json::to_string(&config).unwrap()).execute(&mut **tx).await.unwrap();
        sqlx::query("INSERT INTO machine_state(machine_id,status,state_json) VALUES(?1,'stopped',jsonb(?2)) ON CONFLICT(machine_id) DO UPDATE SET status=excluded.status,state_json=excluded.state_json")
            .bind(config.id.to_string()).bind(serde_json::to_string(&state).unwrap()).execute(&mut **tx).await.unwrap();
        Store::write_machine_storage(tx, config.id, &storage)
            .await
            .unwrap();
        commit.commit().await.unwrap()
    }

    #[tokio::test]
    async fn runtime_identity_is_persistent_distinct_and_immutable() {
        let (dir, a) = catalog().await;
        let (_other, b) = catalog().await;
        let id = a.runtime_id().await.unwrap();
        assert_ne!(id, b.runtime_id().await.unwrap());
        assert!(sqlx::query("UPDATE db_config SET runtime_id=?1")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&a.pool)
            .await
            .is_err());
        a.close().await;
        let paths = crate::paths::LocalPaths::new(dir.path());
        let reopened = Store::new(&paths).await.unwrap();
        assert_eq!(id, reopened.runtime_id().await.unwrap());
        assert!(RuntimeId::new(uuid::Uuid::nil()).is_err());
        assert!(OwnershipEpoch::new(9_007_199_254_740_991)
            .unwrap()
            .next()
            .is_err());
    }

    #[tokio::test]
    async fn lost_decisions_and_repeated_direct_return_preserve_historical_authority() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let mut history = Vec::new();
        for epoch in 0..3 {
            let (source, destination) = if epoch % 2 == 0 { (&a, &b) } else { (&b, &a) };
            let intent = new_intent(source, destination, machine, epoch).await;
            let prepared = prepared(source, destination, &intent).await;
            assert_eq!(
                destination
                    .prepare_handoff_destination(&prepared.binding)
                    .await
                    .unwrap(),
                prepared
            );
            assert_eq!(
                source.reserve_handoff_source(&intent).await.unwrap().phase,
                HandoffPhase::Captured
            );
            let auth = source.fence_handoff_source(&prepared).await.unwrap();
            assert_eq!(source.fence_handoff_source(&prepared).await.unwrap(), auth);
            assert!(!source
                .machine_storage(machine)
                .await
                .unwrap()
                .unwrap()
                .ownership
                .is_owned());
            let committed = publish(destination, &auth, &intent).await;
            // Treat the committed response as lost: source remains fenced.
            assert!(matches!(
                source
                    .machine_storage(machine)
                    .await
                    .unwrap()
                    .unwrap()
                    .ownership,
                MachineOwnership::Fenced { .. }
            ));
            let replay = destination
                .begin_handoff_destination_commit(&auth)
                .await
                .unwrap();
            assert_eq!(replay.terminal_receipt(), Some(&committed));
            assert_eq!(replay.commit().await.unwrap(), committed);
            assert_eq!(
                destination
                    .abort_handoff_destination(&intent)
                    .await
                    .unwrap(),
                committed
            );
            source.resolve_handoff_source(&committed).await.unwrap();
            let retained: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM machine_object_dependency WHERE machine_id=?1",
            )
            .bind(machine.to_string())
            .fetch_one(&source.pool)
            .await
            .unwrap();
            assert_eq!(
                retained, 0,
                "terminal prior-owner metadata is not a bulk root"
            );
            assert_eq!(
                destination
                    .machine_storage(machine)
                    .await
                    .unwrap()
                    .unwrap()
                    .ownership_epoch,
                epoch + 1
            );
            history.push((intent, prepared, auth, committed));
            for (old_intent, old_prepared, old_auth, old_terminal) in &history {
                let (old_source, old_destination) =
                    if old_intent.source_runtime == a.runtime_id().await.unwrap() {
                        (&a, &b)
                    } else {
                        (&b, &a)
                    };
                let before_a = a.machine_storage(machine).await.unwrap();
                let before_b = b.machine_storage(machine).await.unwrap();
                assert_eq!(
                    old_source.fence_handoff_source(old_prepared).await.unwrap(),
                    *old_auth
                );
                assert_eq!(
                    old_destination
                        .begin_handoff_destination_commit(old_auth)
                        .await
                        .unwrap()
                        .commit()
                        .await
                        .unwrap(),
                    *old_terminal
                );
                old_source
                    .resolve_handoff_source(old_terminal)
                    .await
                    .unwrap();
                assert_eq!(
                    old_destination
                        .abort_handoff_destination(old_intent)
                        .await
                        .unwrap(),
                    *old_terminal
                );
                assert_eq!(a.machine_storage(machine).await.unwrap(), before_a);
                assert_eq!(b.machine_storage(machine).await.unwrap(), before_b);
            }
        }
    }

    #[tokio::test]
    async fn abort_tombstone_rejects_reordered_offer_prepare_commit_and_changed_intent() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        a.reserve_handoff_source(&intent).await.unwrap();
        let cut = binding(&intent);
        a.bind_handoff_capture(&cut).await.unwrap();
        // Abort arrives before receiving/capture, creating durable negative authority.
        let aborted = b.abort_handoff_destination(&intent).await.unwrap();
        assert_eq!(b.abort_handoff_destination(&intent).await.unwrap(), aborted);
        assert!(b.receive_handoff(&intent).await.is_err());
        assert!(b.offer_handoff_capture(&cut).await.is_err());
        assert!(b.prepare_handoff_destination(&cut).await.is_err());
        let delayed = CommitAuthorization {
            prepared: PreparedReceipt {
                binding: cut,
                receipt_id: uuid::Uuid::new_v4(),
            },
            nonce: uuid::Uuid::new_v4(),
        };
        assert!(b.begin_handoff_destination_commit(&delayed).await.is_err());
        a.resolve_handoff_source(&aborted).await.unwrap();
        assert!(a
            .machine_storage(machine)
            .await
            .unwrap()
            .unwrap()
            .ownership
            .is_owned());
        assert!(a.bind_handoff_capture(&binding(&intent)).await.is_err());
        let mut changed = intent.clone();
        changed.approved_plan_digest =
            crate::storage::identity::ObjectDigest::of_bytes(b"unapproved replacement");
        assert!(a.reserve_handoff_source(&changed).await.is_err());
        assert!(b.abort_handoff_destination(&changed).await.is_err());
        // A stale abort cannot clear a later reservation.
        let next = new_intent(&a, &b, machine, 0).await;
        a.reserve_handoff_source(&next).await.unwrap();
        a.resolve_handoff_source(&aborted).await.unwrap();
        assert_eq!(
            a.machine_storage(machine).await.unwrap().unwrap().ownership,
            MachineOwnership::Reserved {
                operation: next.operation
            }
        );
    }

    #[tokio::test]
    async fn abort_wins_prepared_commit_race_and_restart_preserves_fence() {
        let (adir, a) = catalog().await;
        let (bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        let prepared = prepared(&a, &b, &intent).await;
        let auth = a.fence_handoff_source(&prepared).await.unwrap();
        // A dropped publication transaction cannot publish a decision.
        drop(b.begin_handoff_destination_commit(&auth).await.unwrap());
        assert_eq!(
            b.get_handoff(intent.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            HandoffPhase::Prepared
        );
        a.close().await;
        b.close().await;
        let a = Store::new(&crate::paths::LocalPaths::new(adir.path()))
            .await
            .unwrap();
        let b = Store::new(&crate::paths::LocalPaths::new(bdir.path()))
            .await
            .unwrap();
        assert!(a
            .machine_storage(machine)
            .await
            .unwrap()
            .unwrap()
            .ownership
            .ensure_owned(machine)
            .is_err());
        let aborted = b.abort_handoff_destination(&intent).await.unwrap();
        assert!(b.begin_handoff_destination_commit(&auth).await.is_err());
        a.resolve_handoff_source(&aborted).await.unwrap();
        assert!(a
            .machine_storage(machine)
            .await
            .unwrap()
            .unwrap()
            .ownership
            .is_owned());
    }

    #[tokio::test]
    async fn nonterminal_roots_survive_gc_and_terminal_ledgers_survive_machine_deletion() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        a.reserve_handoff_source(&intent).await.unwrap();
        let lease = a
            .begin_storage_operation_inner(intent.operation.as_uuid())
            .await
            .unwrap();
        sqlx::query("UPDATE storage_operation SET kind='relocate' WHERE operation_id=?1")
            .bind(intent.operation.to_string())
            .execute(&a.pool)
            .await
            .unwrap();
        let pool = crate::storage::pool::StoragePool::open(a.images_path()).unwrap();
        let operation_paths = pool
            .create_operation_with_lease(intent.operation.as_uuid(), lease.duplicate().unwrap())
            .unwrap();
        let input = crate::store::snapshot_store::RecordInput::new(
            a.images_path(),
            intent.operation.as_uuid(),
            b"exact captured closure",
        )
        .unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&input.path()).unwrap();
        a.pin_published_storage_dependencies(intent.operation.as_uuid(), &[], &[object.digest])
            .await
            .unwrap();
        drop(roots);
        drop(operation_paths);
        drop(lease);
        a.retire_abandoned_storage_operations(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_operation")
                .fetch_one(&a.pool)
                .await
                .unwrap(),
            1
        );
        assert!(pool.verify_object(&object.digest).is_ok());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM storage_operation_object WHERE operation_id=?1"
            )
            .bind(intent.operation.to_string())
            .fetch_one(&a.pool)
            .await
            .unwrap(),
            1
        );
        assert!(
            sqlx::query("DELETE FROM storage_operation WHERE operation_id=?1")
                .bind(intent.operation.to_string())
                .execute(&a.pool)
                .await
                .is_err()
        );
        let aborted = b.abort_handoff_destination(&intent).await.unwrap();
        a.resolve_handoff_source(&aborted).await.unwrap();
        a.retire_abandoned_storage_operations(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_operation")
                .fetch_one(&a.pool)
                .await
                .unwrap(),
            0
        );
        a.remove_machine(&config(&a, machine)).await.unwrap();
        assert_eq!(
            a.get_handoff(intent.operation)
                .await
                .unwrap()
                .unwrap()
                .terminal,
            Some(aborted)
        );
        assert!(sqlx::query("DELETE FROM handoff_operation")
            .execute(&a.pool)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn reserved_owned_and_unrelated_return_collisions_fail_closed() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let (_cdir, c) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        seed(&b, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        assert!(b.receive_handoff(&intent).await.is_err());
        a.reserve_handoff_source(&intent).await.unwrap();
        assert!(a.save_machine_config(&config(&a, machine)).await.is_err());
        assert!(a.remove_machine(&config(&a, machine)).await.is_err());
        let another = new_intent(&a, &c, machine, 0).await;
        assert!(a.reserve_handoff_source(&another).await.is_err());
        let mut changed = intent.clone();
        changed.source_runtime = changed.destination_runtime;
        assert!(changed.validate().is_err());
    }

    #[tokio::test]
    async fn intended_plan_is_durable_without_reserving_and_abort_cannot_touch_later_owner() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let first = new_intent(&a, &b, machine, 0).await;
        let record = a.begin_handoff_source(&first).await.unwrap();
        assert_eq!(record.phase, HandoffPhase::Intended);
        assert_eq!(a.begin_handoff_source(&first).await.unwrap(), record);
        assert!(a
            .machine_storage(machine)
            .await
            .unwrap()
            .unwrap()
            .ownership
            .is_owned());
        assert_eq!(
            a.reserve_handoff_source(&first).await.unwrap().phase,
            HandoffPhase::Reserved
        );
        let aborted = b.abort_handoff_destination(&first).await.unwrap();
        a.resolve_handoff_source(&aborted).await.unwrap();
        let second = new_intent(&a, &b, machine, 0).await;
        a.begin_handoff_source(&second).await.unwrap();
        let second_abort = b.abort_handoff_destination(&second).await.unwrap();
        a.resolve_handoff_source(&second_abort).await.unwrap();
        assert!(a
            .machine_storage(machine)
            .await
            .unwrap()
            .unwrap()
            .ownership
            .is_owned());
        let third = new_intent(&a, &b, machine, 0).await;
        a.reserve_handoff_source(&third).await.unwrap();
        a.resolve_handoff_source(&second_abort).await.unwrap();
        assert_eq!(
            a.machine_storage(machine).await.unwrap().unwrap().ownership,
            MachineOwnership::Reserved {
                operation: third.operation
            }
        );
    }

    #[tokio::test]
    async fn unresolved_prior_owner_and_multihop_return_are_not_collision_exceptions() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let (_cdir, c) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let first = new_intent(&a, &b, machine, 0).await;
        let prepared = prepared(&a, &b, &first).await;
        let auth = a.fence_handoff_source(&prepared).await.unwrap();
        let receipt = publish(&b, &auth, &first).await;
        let return_intent = new_intent(&b, &a, machine, 1).await;
        assert!(a.receive_handoff(&return_intent).await.is_err());
        a.resolve_handoff_source(&receipt).await.unwrap();
        a.receive_handoff(&return_intent).await.unwrap();
        let aborted = a.abort_handoff_destination(&return_intent).await.unwrap();
        assert_eq!(aborted.decision, HandoffDecision::Aborted);
        assert!(matches!(
            a.machine_storage(machine).await.unwrap().unwrap().ownership,
            MachineOwnership::Relocated { .. }
        ));
        let indirect = new_intent(&c, &a, machine, 2).await;
        assert!(a.receive_handoff(&indirect).await.is_err());
        assert!(a.remove_machine(&config(&a, machine)).await.is_err());
    }

    #[tokio::test]
    async fn fork_commit_uses_new_identity_and_never_advances_source_epoch() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let mut intent = new_intent(&a, &b, machine, 0).await;
        intent.mode = HandoffMode::Fork;
        intent.destination_machine = MachineId::new();
        let prepared = prepared(&a, &b, &intent).await;
        let auth = a.fence_handoff_source(&prepared).await.unwrap();
        assert!(matches!(
            a.machine_storage(machine).await.unwrap().unwrap().ownership,
            MachineOwnership::Reserved { .. }
        ));
        let receipt = publish(&b, &auth, &intent).await;
        a.resolve_handoff_source(&receipt).await.unwrap();
        let source = a.machine_storage(machine).await.unwrap().unwrap();
        let destination = b
            .machine_storage(intent.destination_machine)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source.ownership_epoch, 0);
        assert_eq!(destination.ownership_epoch, 0);
        assert!(source.ownership.is_owned());
        assert!(destination.ownership.is_owned());
        assert!(b.machine_storage(machine).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn capture_and_prepared_binding_are_immutable_and_failed_commit_is_atomic() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        let prepared = prepared(&a, &b, &intent).await;
        let mut changed = prepared.clone();
        changed.binding.capture = CaptureId::new(uuid::Uuid::new_v4()).unwrap();
        assert!(a.bind_handoff_capture(&changed.binding).await.is_err());
        assert!(b.offer_handoff_capture(&changed.binding).await.is_err());
        assert!(a.fence_handoff_source(&changed).await.is_err());
        changed = prepared.clone();
        changed.binding.intent.approved_plan_digest =
            crate::storage::identity::ObjectDigest::of_bytes(b"changed plan");
        assert!(a.fence_handoff_source(&changed).await.is_err());
        let auth = a.fence_handoff_source(&prepared).await.unwrap();
        // No machine publication: commit refuses and its decision rolls back.
        assert!(b
            .begin_handoff_destination_commit(&auth)
            .await
            .unwrap()
            .commit()
            .await
            .is_err());
        assert_eq!(
            b.get_handoff(intent.operation)
                .await
                .unwrap()
                .unwrap()
                .phase,
            HandoffPhase::Prepared
        );
        assert!(b.machine_storage(machine).await.unwrap().is_none());
        let mut changed = auth.clone();
        changed.prepared.receipt_id = uuid::Uuid::new_v4();
        assert!(b.begin_handoff_destination_commit(&changed).await.is_err());
        let receipt = publish(&b, &auth, &intent).await;
        let durable = b.get_handoff(intent.operation).await.unwrap().unwrap();
        let durable = serde_json::to_value(&durable).unwrap();
        for pointer in [
            "/terminal/authorization/nonce",
            "/terminal/binding/capture",
            "/authorization/nonce",
            "/prepared/receiptId",
        ] {
            let mut contradictory = durable.clone();
            *contradictory.pointer_mut(pointer).unwrap() = serde_json::json!(uuid::Uuid::new_v4());
            assert!(
                HandoffRecord::decode(&contradictory.to_string()).is_err(),
                "contradictory durable record at {pointer}"
            );
        }
        changed = auth.clone();
        changed.nonce = uuid::Uuid::new_v4();
        assert!(b.begin_handoff_destination_commit(&changed).await.is_err());
        a.resolve_handoff_source(&receipt).await.unwrap();
        assert!(
            sqlx::query("UPDATE handoff_operation SET terminal=0,phase='receiving'")
                .execute(&b.pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn competing_commit_and_abort_have_one_durable_winner() {
        let (_adir, a) = catalog().await;
        let (_bdir, b) = catalog().await;
        let machine = MachineId::new();
        seed(&a, machine).await;
        let intent = new_intent(&a, &b, machine, 0).await;
        let prepared = prepared(&a, &b, &intent).await;
        let auth = a.fence_handoff_source(&prepared).await.unwrap();
        let config = config(&b, machine);
        let state = state(machine);
        let mut storage = crate::MachineStorageRecord::opaque_raw(
            crate::PrivatePath::new("root.raw").unwrap(),
            512,
            &oci::Platform::host().unwrap(),
        )
        .unwrap();
        let _boot = b.pin_test_boot(&mut storage).await.unwrap();
        storage.ownership_epoch = 1;
        let commit = async {
            let mut publication = b.begin_handoff_destination_commit(&auth).await?;
            if let Some(terminal) = publication.terminal_receipt() {
                return Ok::<_, crate::LibVmError>(terminal.clone());
            }
            let tx = publication.transaction()?;
            sqlx::query("INSERT INTO machine_config(id,name,config_json) VALUES(?1,?2,jsonb(?3))")
                .bind(machine.to_string())
                .bind(&config.name)
                .bind(serde_json::to_string(&config).unwrap())
                .execute(&mut **tx)
                .await?;
            sqlx::query("INSERT INTO machine_state(machine_id,status,state_json) VALUES(?1,'stopped',jsonb(?2))")
                .bind(machine.to_string()).bind(serde_json::to_string(&state).unwrap()).execute(&mut **tx).await?;
            Store::write_machine_storage(tx, machine, &storage).await?;
            publication.commit().await
        };
        let (commit, abort) = tokio::join!(commit, b.abort_handoff_destination(&intent));
        let abort = abort.unwrap();
        match abort.decision {
            HandoffDecision::Committed => assert_eq!(commit.unwrap(), abort),
            HandoffDecision::Aborted => {
                assert!(commit.is_err());
                assert!(b.machine_config(machine).await.unwrap().is_none());
            }
        }
        a.resolve_handoff_source(&abort).await.unwrap();
        let source = a.machine_storage(machine).await.unwrap().unwrap();
        let destination = b.machine_storage(machine).await.unwrap();
        assert_eq!(
            usize::from(source.ownership.is_owned())
                + usize::from(destination.is_some_and(|record| record.ownership.is_owned())),
            1
        );
        assert_eq!(b.abort_handoff_destination(&intent).await.unwrap(), abort);
    }
}

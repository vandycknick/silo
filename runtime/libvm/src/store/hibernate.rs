//! Private saved execution authority and its transactional lifecycle (ADR 0023).
//!
//! Callers hold the machine lifecycle lock. They sync captured files, writable
//! disks and directories before commit, and prove exact process terminality
//! before releasing a wake or retiring a launch. A durability-pending error
//! means the transaction committed but its checkpoint did not complete: keep
//! execution parked and reconcile the catalog, never resume or authorize it.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use uuid::Uuid;
use vm_spec::hibernate::HibernateCut;
use vm_spec::restore::RestoreNetwork;

use crate::paths::OwnedDirectory;
use crate::storage::pool::StoragePool;
use crate::store::models::{MachineId, MachineRuntimeState, MachineState};
use crate::store::row::DbMachineState;
use crate::store::Store;
use crate::LibVmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HibernatePhase {
    Saving,
    Available,
    Waking,
    Discarding,
}

impl HibernatePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Saving => "saving",
            Self::Available => "available",
            Self::Waking => "waking",
            Self::Discarding => "discarding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HibernatePriorState {
    Running,
    Paused,
}

impl HibernatePriorState {
    fn runtime(self) -> MachineRuntimeState {
        match self {
            Self::Running => MachineRuntimeState::Running,
            Self::Paused => MachineRuntimeState::Paused,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HibernateBegin {
    pub save_id: Uuid,
    pub machine_id: MachineId,
    pub ended_run_id: Uuid,
    pub launch_operation_id: Uuid,
    pub storage_generation: u64,
    /// Exact effective launch specification, not a newly provisioned cold boot.
    pub launch_spec: vm_spec::VmSpec,
    /// Preserve the actual guest address, routes and DNS across subnet changes.
    pub effective_network: Option<RestoreNetwork>,
    /// The retained host trust must still match before a wake may execute.
    pub ssh_trusted_ca: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HibernateRecord {
    pub begin: HibernateBegin,
    pub phase: HibernatePhase,
    pub prior_state: MachineState,
    pub cut: Option<HibernateCut>,
    pub memory: Option<vm_spec::capture::HibernateMemoryReceipt>,
    pub new_run_id: Option<Uuid>,
    pub created_at: i64,
    pub updated_at: i64,
    pub available_at: Option<i64>,
    pub allocated_size: u64,
}

fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "machine-hibernation",
        message: message.to_string(),
    }
}

async fn read_record(
    connection: &mut SqliteConnection,
    machine: MachineId,
) -> Result<Option<HibernateRecord>, LibVmError> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT json(record_json) FROM machine_hibernation WHERE machine_id=?1")
            .bind(machine.to_string())
            .fetch_optional(connection)
            .await?;
    json.map(|json| serde_json::from_str(&json).map_err(invalid))
        .transpose()
}

async fn require_record(
    connection: &mut SqliteConnection,
    machine: MachineId,
    save: Uuid,
    phase: HibernatePhase,
) -> Result<HibernateRecord, LibVmError> {
    let record = read_record(connection, machine).await?.ok_or_else(|| {
        invalid("saved state is no longer available; inspect the machine before retrying")
    })?;
    if record.begin.save_id != save || record.phase != phase {
        return Err(invalid(
            "saved state changed or another operation owns it; inspect the machine before retrying",
        ));
    }
    Ok(record)
}

async fn write_record(
    connection: &mut SqliteConnection,
    record: &HibernateRecord,
) -> Result<(), LibVmError> {
    let allocated = i64::try_from(record.allocated_size).map_err(invalid)?;
    let json = serde_json::to_string(record).map_err(invalid)?;
    sqlx::query("INSERT INTO machine_hibernation(machine_id,save_id,ended_run_id,phase,new_run_id,created_at,updated_at,allocated_size,record_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,jsonb(?9)) ON CONFLICT(machine_id) DO UPDATE SET phase=excluded.phase,new_run_id=excluded.new_run_id,updated_at=excluded.updated_at,allocated_size=excluded.allocated_size,record_json=excluded.record_json")
        .bind(record.begin.machine_id.to_string()).bind(record.begin.save_id.to_string()).bind(record.begin.ended_run_id.to_string())
        .bind(record.phase.as_str()).bind(record.new_run_id.map(|id| id.to_string())).bind(record.created_at).bind(record.updated_at).bind(allocated).bind(json).execute(connection).await?;
    Ok(())
}

async fn read_state(
    connection: &mut SqliteConnection,
    machine: MachineId,
) -> Result<MachineState, LibVmError> {
    let DbMachineState(state) = sqlx::query_as("SELECT machine_id,status,json(state_json) AS state_json FROM machine_state WHERE machine_id=?1")
        .bind(machine.to_string()).fetch_one(connection).await?;
    Ok(state)
}

async fn write_state(
    connection: &mut SqliteConnection,
    state: &MachineState,
) -> Result<(), LibVmError> {
    sqlx::query("UPDATE machine_state SET status=?2,state_json=jsonb(?3) WHERE machine_id=?1")
        .bind(state.machine_id.to_string())
        .bind(state.status.as_str())
        .bind(serde_json::to_string(state).map_err(invalid)?)
        .execute(connection)
        .await?;
    Ok(())
}

fn set_state(state: &mut MachineState, status: MachineRuntimeState, run: Option<Uuid>) {
    state.status = status;
    state.run_id = run.map(|id| id.to_string());
    state.vmm_pid = None;
    state.started_at = None;
    state.last_error = None;
    state.updated_at = chrono::Utc::now().timestamp();
}

impl Store {
    pub(crate) fn hibernation_directory(&self, machine: MachineId, save: Uuid) -> PathBuf {
        crate::paths::machine_data_dir_in(&self.home, machine)
            .join("hibernation")
            .join(save.to_string())
    }

    pub(crate) async fn machine_hibernation(
        &self,
        machine: MachineId,
    ) -> Result<Option<HibernateRecord>, LibVmError> {
        read_record(&mut *self.pool.acquire().await?, machine).await
    }

    /// Presence, including saving/discarding, fences offline disk mutation.
    pub(crate) async fn has_hibernation(&self, machine: MachineId) -> Result<bool, LibVmError> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM machine_hibernation WHERE machine_id=?1)",
        )
        .bind(machine.to_string())
        .fetch_one(&self.pool)
        .await?)
    }

    /// A consumed save's mapping root identifies the run after its row is gone.
    pub(crate) async fn run_has_hibernation_memory(
        &self,
        machine: MachineId,
        run: Uuid,
    ) -> Result<bool, LibVmError> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_hibernation h JOIN storage_operation o ON o.operation_id=h.operation_id WHERE o.machine_id=?1 AND o.run_id=?2 AND h.role='ram-mapping')")
            .bind(machine.to_string()).bind(run.to_string()).fetch_one(&self.pool).await?)
    }

    /// Available rows also need recovery: the old run might not yet be reaped.
    pub(crate) async fn hibernations_needing_recovery(
        &self,
    ) -> Result<Vec<HibernateRecord>, LibVmError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT json(record_json) FROM machine_hibernation ORDER BY machine_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|json| serde_json::from_str(json).map_err(invalid))
            .collect()
    }

    pub(crate) async fn begin_hibernation(
        &self,
        begin: &HibernateBegin,
    ) -> Result<HibernateRecord, LibVmError> {
        if begin.save_id.is_nil()
            || begin.ended_run_id.is_nil()
            || begin.launch_operation_id.is_nil()
        {
            return Err(invalid(
                "saved state requires a machine and a running generation",
            ));
        }
        if let Some(network) = &begin.effective_network {
            network.validate().map_err(invalid)?;
        }
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if read_record(&mut tx, begin.machine_id).await?.is_some() {
            return Err(invalid(
                "machine already has saved state; wake or stop it before hibernating again",
            ));
        }
        let state = read_state(&mut tx, begin.machine_id).await?;
        if !matches!(
            state.status,
            MachineRuntimeState::Running | MachineRuntimeState::Paused
        ) || state.run_id.as_deref() != Some(begin.ended_run_id.to_string().as_str())
        {
            return Err(invalid(
                "machine is not running or paused; start it before hibernating",
            ));
        }
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND machine_id=?2 AND run_id=?3 AND storage_generation=?4 AND kind='launch' AND state IN ('prepared','staging','committing')) AND NOT EXISTS(SELECT 1 FROM live_operation WHERE machine_id=?2 AND terminal=0)")
            .bind(begin.launch_operation_id.to_string()).bind(begin.machine_id.to_string()).bind(begin.ended_run_id.to_string()).bind(i64::try_from(begin.storage_generation).map_err(invalid)?).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(invalid("machine's run changed or another operation is in progress; retry after it completes"));
        }
        crate::store::capture::ensure_capture_available(
            &mut tx,
            begin.machine_id,
            begin.ended_run_id,
            begin.save_id,
        )
        .await?;
        let now = chrono::Utc::now().timestamp();
        let record = HibernateRecord {
            begin: begin.clone(),
            phase: HibernatePhase::Saving,
            prior_state: state.clone(),
            cut: None,
            memory: None,
            new_run_id: None,
            created_at: now,
            updated_at: now,
            available_at: None,
            allocated_size: 0,
        };
        write_record(&mut tx, &record).await?;
        let mut saving = state;
        saving.status = MachineRuntimeState::Hibernating;
        saving.updated_at = now;
        write_state(&mut tx, &saving).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// Caller seals and syncs files/disks/directories first. Success permits
    /// ending the parked old worker without shutdown, resume or thaw.
    pub(crate) async fn commit_hibernation_available(
        &self,
        machine: MachineId,
        save: Uuid,
        cut: &HibernateCut,
        memory: &vm_spec::capture::HibernateMemoryReceipt,
        allocated_size: u64,
    ) -> Result<(), LibVmError> {
        cut.validate().map_err(invalid)?;
        memory.validate().map_err(invalid)?;
        if memory.stats.logical_bytes != cut.packed_length {
            return Err(invalid(
                "saved memory receipt differs from the execution save",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = require_record(&mut tx, machine, save, HibernatePhase::Saving).await?;
        if cut.machine_id.as_str() != Uuid::from(machine).to_string()
            || cut.save_id.as_str() != save.to_string()
            || cut.ended_run_id.as_str() != record.begin.ended_run_id.to_string()
            || cut.configuration
                != vm_spec::capture::CaptureConfiguration::from_spec(&record.begin.launch_spec)
                    .map_err(invalid)?
            || cut.saved_files.iter().any(|file| {
                file.file.path.parent() != Some(self.hibernation_directory(machine, save).as_path())
            })
        {
            return Err(invalid(
                "saved execution files do not belong to this machine and run; retry hibernate",
            ));
        }
        let mut state = read_state(&mut tx, machine).await?;
        if state.status != MachineRuntimeState::Hibernating
            || state.run_id.as_deref() != Some(record.begin.ended_run_id.to_string().as_str())
        {
            return Err(invalid(
                "machine changed while saving; inspect it before retrying",
            ));
        }
        record.phase = HibernatePhase::Available;
        record.cut = Some(cut.clone());
        record.memory = Some(memory.clone());
        record.allocated_size = allocated_size;
        record.updated_at = chrono::Utc::now().timestamp();
        record.available_at = Some(record.updated_at);
        write_record(&mut tx, &record).await?;
        // Retain the exact old run until the lifecycle owner proves it terminal.
        state.status = MachineRuntimeState::Hibernated;
        state.updated_at = record.updated_at;
        write_state(&mut tx, &state).await?;
        tx.commit().await?;
        self.checkpoint_catalog().await
    }

    /// Compensate an unaccepted save before allowing the exact parked source to
    /// resume. The caller has observed that the monitor did not commit release.
    /// A retired old launch or any wake claim makes compensation impossible.
    pub(crate) async fn abort_hibernation_available(
        &self,
        machine: MachineId,
        save: Uuid,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let record = require_record(&mut tx, machine, save, HibernatePhase::Available).await?;
        let state = read_state(&mut tx, machine).await?;
        let old: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND machine_id=?2 AND run_id=?3 AND storage_generation=?4 AND kind='launch')")
            .bind(record.begin.launch_operation_id.to_string()).bind(machine.to_string())
            .bind(record.begin.ended_run_id.to_string())
            .bind(i64::try_from(record.begin.storage_generation).map_err(invalid)?)
            .fetch_one(&mut *tx).await?;
        if !old
            || state.status != MachineRuntimeState::Hibernated
            || state.run_id != record.prior_state.run_id
            || record.new_run_id.is_some()
        {
            return Err(invalid("the saved run can no longer return to its prior state; inspect the machine before retrying"));
        }
        let mut prior = record.prior_state;
        prior.updated_at = chrono::Utc::now().timestamp();
        write_state(&mut tx, &prior).await?;
        sqlx::query("DELETE FROM machine_hibernation WHERE machine_id=?1 AND save_id=?2")
            .bind(machine.to_string())
            .bind(save.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn abort_hibernation_saving(
        &self,
        machine: MachineId,
        save: Uuid,
        prior: HibernatePriorState,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let record = require_record(&mut tx, machine, save, HibernatePhase::Saving).await?;
        if record.prior_state.status != prior.runtime() {
            return Err(invalid("saved operation's original running state differs; inspect the machine before retrying"));
        }
        let state = read_state(&mut tx, machine).await?;
        if state.status != MachineRuntimeState::Hibernating
            || state.run_id != record.prior_state.run_id
        {
            return Err(invalid(
                "machine changed while saving; inspect it before retrying",
            ));
        }
        let mut restored = record.prior_state;
        restored.updated_at = chrono::Utc::now().timestamp();
        write_state(&mut tx, &restored).await?;
        sqlx::query("DELETE FROM machine_hibernation WHERE machine_id=?1")
            .bind(machine.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn claim_hibernation_wake(
        &self,
        machine: MachineId,
        save: Uuid,
        run: Uuid,
    ) -> Result<HibernateRecord, LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = require_record(&mut tx, machine, save, HibernatePhase::Available).await?;
        let mut state = read_state(&mut tx, machine).await?;
        if run.is_nil()
            || run == record.begin.ended_run_id
            || state.status != MachineRuntimeState::Hibernated
        {
            return Err(invalid(
                "machine cannot wake in its current state; inspect it before retrying",
            ));
        }
        // The old launch must have retired under exact-holder terminal proof.
        let old: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1)",
        )
        .bind(record.begin.launch_operation_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if old {
            return Err(invalid(
                "machine is still finishing hibernate; retry after its processes end",
            ));
        }
        record.phase = HibernatePhase::Waking;
        record.new_run_id = Some(run);
        record.updated_at = chrono::Utc::now().timestamp();
        write_record(&mut tx, &record).await?;
        set_state(&mut state, MachineRuntimeState::Restoring, Some(run));
        write_state(&mut tx, &state).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// Call only after the new, still-parked holders have been reaped.
    pub(crate) async fn release_hibernation_wake(
        &self,
        machine: MachineId,
        save: Uuid,
        run: Uuid,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = require_record(&mut tx, machine, save, HibernatePhase::Waking).await?;
        let mut state = read_state(&mut tx, machine).await?;
        if record.new_run_id != Some(run)
            || state.status != MachineRuntimeState::Restoring
            || state.run_id.as_deref() != Some(run.to_string().as_str())
        {
            return Err(invalid(
                "wake attempt changed; inspect the machine before retrying",
            ));
        }
        let launches: Vec<(String, String, String)> = sqlx::query_as("SELECT operation_id,file_device,file_inode FROM storage_operation WHERE machine_id=?1 AND run_id=?2 AND kind='launch'")
            .bind(machine.to_string()).bind(run.to_string()).fetch_all(&mut *tx).await?;
        let mut terminal_leases = Vec::with_capacity(launches.len());
        for (launch, device, inode) in &launches {
            let launch = Uuid::parse_str(launch).map_err(invalid)?;
            let lease = pool.try_exclusive_lease(launch)?.ok_or_else(|| {
                invalid(
                    "wake processes still hold their files; wait for them to end before retrying",
                )
            })?;
            let actual = lease.file_identity()?;
            if actual
                != (
                    device.parse::<u64>().map_err(invalid)?,
                    inode.parse::<u64>().map_err(invalid)?,
                )
            {
                return Err(invalid(
                    "wake file ownership changed; inspect the machine before retrying",
                ));
            }
            terminal_leases.push(lease);
        }
        sqlx::query(
            "DELETE FROM storage_operation WHERE machine_id=?1 AND run_id=?2 AND kind='launch'",
        )
        .bind(machine.to_string())
        .bind(run.to_string())
        .execute(&mut *tx)
        .await?;
        record.phase = HibernatePhase::Available;
        record.new_run_id = None;
        record.updated_at = chrono::Utc::now().timestamp();
        write_record(&mut tx, &record).await?;
        set_state(&mut state, MachineRuntimeState::Hibernated, None);
        write_state(&mut tx, &state).await?;
        tx.commit().await?;
        drop(_roots);
        self.reconcile_restore_budget().await
    }

    /// Installs both RAM roots before removing resume authority. Success, including
    /// the completed checkpoint, is required before sending ConsumeAuthorization.
    pub(crate) async fn consume_hibernation(
        &self,
        machine: MachineId,
        save: Uuid,
        run: Uuid,
        launch: Uuid,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _lease = pool.existing_lease(launch)?;
        let (device, inode) = _lease.file_identity()?;
        let _roots = pool.lock_roots()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let record = require_record(&mut tx, machine, save, HibernatePhase::Waking).await?;
        let mut state = read_state(&mut tx, machine).await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND machine_id=?2 AND run_id=?3 AND storage_generation=?4 AND kind='launch' AND state IN ('prepared','staging','committing') AND file_device=?5 AND file_inode=?6)")
            .bind(launch.to_string()).bind(machine.to_string()).bind(run.to_string()).bind(i64::try_from(record.begin.storage_generation).map_err(invalid)?).bind(device.to_string()).bind(inode.to_string()).fetch_one(&mut *tx).await?;
        if !valid
            || record.new_run_id != Some(run)
            || state.status != MachineRuntimeState::Restoring
            || state.run_id.as_deref() != Some(run.to_string().as_str())
        {
            return Err(invalid(
                "wake attempt changed before execution; inspect the machine before retrying",
            ));
        }
        sqlx::query("INSERT INTO storage_operation_hibernation(operation_id,machine_id,save_id,role) VALUES(?1,?2,?3,'ram-mapping'),(?1,?2,?3,'ram-baseline')")
            .bind(launch.to_string()).bind(machine.to_string()).bind(save.to_string()).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM machine_hibernation WHERE machine_id=?1")
            .bind(machine.to_string())
            .execute(&mut *tx)
            .await?;
        state.status = MachineRuntimeState::Activating;
        state.updated_at = chrono::Utc::now().timestamp();
        write_state(&mut tx, &state).await?;
        tx.commit().await?;
        drop(_roots);
        self.checkpoint_catalog().await
    }

    /// All prior holders must be terminal. Saving is aborted, never discarded;
    /// waking must be released before a discard can be admitted.
    pub(crate) async fn begin_hibernation_discard(
        &self,
        machine: MachineId,
        save: Uuid,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut record = require_record(&mut tx, machine, save, HibernatePhase::Available).await?;
        let state = read_state(&mut tx, machine).await?;
        let old: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1)",
        )
        .bind(record.begin.launch_operation_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if state.status != MachineRuntimeState::Hibernated || old {
            return Err(invalid("machine is still finishing hibernate; wait for its processes to end before stopping"));
        }
        record.phase = HibernatePhase::Discarding;
        record.updated_at = chrono::Utc::now().timestamp();
        write_record(&mut tx, &record).await?;
        tx.commit().await?;
        self.checkpoint_catalog().await
    }

    /// Delete payloads only after begin-discard's durability barrier. The row
    /// remains the cleanup root until the caller finishes that deletion.
    pub(crate) async fn finish_hibernation_discard(
        &self,
        machine: MachineId,
        save: Uuid,
    ) -> Result<(), LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        require_record(&mut tx, machine, save, HibernatePhase::Discarding).await?;
        let mut state = read_state(&mut tx, machine).await?;
        if state.status != MachineRuntimeState::Hibernated {
            return Err(invalid(
                "machine changed while stopping; inspect it before retrying",
            ));
        }
        set_state(&mut state, MachineRuntimeState::Stopped, None);
        write_state(&mut tx, &state).await?;
        sqlx::query("DELETE FROM machine_hibernation WHERE machine_id=?1")
            .bind(machine.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Machine-private saves are not pool objects. Extend ordinary orphan
    /// recovery to this subtree without ever importing files as resume authority.
    pub(crate) async fn recover_hibernation_files(
        &self,
    ) -> Result<Option<crate::store::models::CacheCleanupDeferral>, LibVmError> {
        let machines: Vec<String> = sqlx::query_scalar("SELECT id FROM machine_config ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let pool = StoragePool::open(&self.images_dir)?;
        for machine in machines {
            let machine = MachineId::from(Uuid::parse_str(&machine).map_err(invalid)?);
            if let Some(deferred) = self
                .recover_machine_hibernation_files(machine, &pool)
                .await?
            {
                return Ok(Some(deferred));
            }
        }
        Ok(None)
    }

    pub(crate) async fn recover_machine_hibernation_files(
        &self,
        machine: MachineId,
        pool: &StoragePool,
    ) -> Result<Option<crate::store::models::CacheCleanupDeferral>, LibVmError> {
        let path = crate::paths::machine_data_dir_in(&self.home, machine).join("hibernation");
        let Some(parent) = OwnedDirectory::open_existing_root(&path)? else {
            return Ok(None);
        };
        let mut entries = nix::dir::Dir::openat(
            parent.fd(),
            ".",
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        for entry in entries.iter() {
            let entry = entry.map_err(std::io::Error::from)?;
            let Some(save) = entry
                .file_name()
                .to_str()
                .ok()
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            let _roots = pool.lock_roots()?;
            let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM machine_hibernation WHERE machine_id=?1 AND save_id=?2) OR EXISTS(SELECT 1 FROM storage_operation_hibernation WHERE machine_id=?1 AND save_id=?2)")
                .bind(machine.to_string()).bind(save.to_string()).fetch_one(&self.pool).await?;
            if retained {
                continue;
            }
            // Keep roots through negative authority's barrier and unlink.
            if let Some(deferred) = self.try_checkpoint_catalog().await?.deferral() {
                return Ok(Some(deferred));
            }
            if let Some(child) = parent.open_dir(&save.to_string())? {
                parent.remove_open_tree(&save.to_string(), &child)?;
                parent.sync()?;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::time::Duration;

    use uuid::Uuid;
    use vm_spec::capture::{CaptureConfiguration, CaptureStateBinding, Sha256Digest};
    use vm_spec::hibernate::{
        HibernateCut, HibernateDiskBinding, HibernateSavedFile, HibernateSavedFileRole,
        HIBERNATE_CUT_VERSION,
    };
    use vm_spec::lifecycle::LiveId;

    use crate::paths::{LocalPaths, OwnedDirectory};
    use crate::storage::hibernate_file::HibernateFileCheck;
    use crate::store::hibernate::{HibernateBegin, HibernatePhase, HibernatePriorState};
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig, MachineRuntimeState, MachineState,
    };
    use crate::store::operation_store::LaunchStorageLease;
    use crate::store::{MachineStore, Store};

    struct Fixture {
        _temporary: tempfile::TempDir,
        store: Store,
        begin: HibernateBegin,
        cut: HibernateCut,
        launch: Option<LaunchStorageLease>,
    }

    fn live(id: Uuid) -> LiveId {
        LiveId::parse(&id.to_string()).unwrap()
    }

    impl Fixture {
        async fn new(prior: MachineRuntimeState) -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let paths = LocalPaths::new(temporary.path().join("home"));
            let store = Store::new(&paths).await.unwrap();
            let machine = MachineId::new();
            let parent = paths.create_machine_data_dir(machine).unwrap();
            let directory = parent.open_dir(&machine.to_string()).unwrap().unwrap();
            directory.write_file("root.raw", &[0x51; 4096]).unwrap();
            let mut spec = vm_spec::VmSpec::current();
            spec.hardware = Some(vm_spec::Hardware {
                cpus: Some(1),
                memory: Some(1),
                nested_virtualization: Some(false),
                rosetta: Some(false),
            });
            let block_id = vm_spec::BlockId::new("root").unwrap();
            spec.storage = Some(vm_spec::Storage {
                disks: vec![vm_spec::Disk {
                    path: "root.raw".into(),
                    role: vm_spec::DiskRole::Root,
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 4096,
                        logical_sector_size: 512,
                    },
                    block_id: block_id.clone(),
                    read_only: false,
                }],
            });
            let config = MachineConfig {
                secret_scope: crate::SecretScopePolicy::default(),
                id: machine,
                lock_id: crate::lock_manager::LockId::from(0),
                name: "hibernate-source".into(),
                spec: spec.clone(),
                retention: crate::MachineRetention::default(),
                process: crate::ProcessConfig::default(),
                template_name: None,
                agent_mode: None,
                guest: crate::MachineGuestConfig {
                    agent: crate::MachineAgent::Disabled,
                    ..Default::default()
                },
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
                machine_id: machine,
                status: prior,
                vmm_pid: None,
                started_at: None,
                run_id: Some(run.to_string()),
                last_error: None,
                updated_at: 1,
            };
            store.add_machine(&config, &state).await.unwrap();
            let storage = store.machine_storage(machine).await.unwrap().unwrap();
            let launch = store
                .register_launch_storage(machine, run, &storage, &spec)
                .await
                .unwrap();
            let begin = HibernateBegin {
                save_id: Uuid::new_v4(),
                machine_id: machine,
                ended_run_id: run,
                launch_operation_id: launch.operation_id(),
                storage_generation: storage.storage_generation,
                launch_spec: spec,
                effective_network: None,
                ssh_trusted_ca: ssh_key::PrivateKey::from(
                    ssh_key::private::Ed25519Keypair::from_seed(&[5; 32]),
                )
                .public_key()
                .to_openssh()
                .unwrap(),
            };
            let configuration = CaptureConfiguration::from_spec(&begin.launch_spec).unwrap();
            let packed_length = configuration.ram_bytes();
            let saved = directory
                .ensure_dir("hibernation")
                .unwrap()
                .ensure_dir(&begin.save_id.to_string())
                .unwrap();
            let saved_files = [
                (HibernateSavedFileRole::Memory, "memory.ram", packed_length),
                (
                    HibernateSavedFileRole::MemoryLayout,
                    "memory-layout.json",
                    16,
                ),
                (
                    HibernateSavedFileRole::ExecutionState,
                    "execution.state",
                    16,
                ),
                (HibernateSavedFileRole::DeviceState, "devices.state", 16),
            ]
            .map(|(role, name, size)| {
                let file = saved
                    .publish_file_deferred(name, nix::sys::stat::Mode::S_IRUSR, |file| {
                        file.set_len(size)?;
                        Ok(())
                    })
                    .unwrap();
                file.sync_all().unwrap();
                HibernateSavedFile {
                    role,
                    file: HibernateFileCheck::capture(&saved.path().join(name), &file)
                        .unwrap()
                        .binding()
                        .clone(),
                }
            });
            let disk_path = directory.path().join("root.raw");
            let disk = std::fs::File::open(&disk_path).unwrap();
            let cut = HibernateCut {
                version: HIBERNATE_CUT_VERSION,
                save_id: live(begin.save_id),
                machine_id: live(machine.into()),
                ended_run_id: live(run),
                freeze_operation_id: live(Uuid::new_v4()),
                freeze_epoch: NonZeroU64::new(1).unwrap(),
                configuration,
                binding: CaptureStateBinding {
                    live_state_schema: "test-v1".into(),
                    architecture: "x86_64".into(),
                    profile: Sha256Digest::of_bytes(b"profile"),
                    topology: Sha256Digest::of_bytes(b"topology"),
                    ram_layout: Sha256Digest::of_bytes(b"layout"),
                    source_run: live(run),
                    pause_generation: NonZeroU64::new(1).unwrap(),
                    capture: live(begin.save_id),
                },
                materialization_generation: NonZeroU64::new(1).unwrap(),
                predecessor_generation: 0,
                packed_length,
                page_granule: 4096,
                regions: 1,
                saved_files,
                writable_disks: vec![HibernateDiskBinding {
                    role: vm_spec::DiskRole::Root,
                    attachment_index: 0,
                    block_id,
                    file: HibernateFileCheck::capture(&disk_path, &disk)
                        .unwrap()
                        .binding()
                        .clone(),
                }],
            };
            Self {
                _temporary: temporary,
                store,
                begin,
                cut,
                launch: Some(launch),
            }
        }

        async fn begin(&self) {
            self.store.begin_hibernation(&self.begin).await.unwrap();
        }

        fn memory(&self) -> vm_spec::capture::HibernateMemoryReceipt {
            vm_spec::capture::HibernateMemoryReceipt {
                mode: vm_spec::lifecycle::CapturePolicy::Full,
                full_reason: Some(vm_spec::capture::CaptureFullReason::NoBaseline),
                stats: vm_spec::capture::CaptureMemoryStats {
                    logical_bytes: self.cut.packed_length,
                    ..Default::default()
                },
            }
        }

        async fn available(&self) {
            self.store
                .commit_hibernation_available(
                    self.begin.machine_id,
                    self.begin.save_id,
                    &self.cut,
                    &self.memory(),
                    16384,
                )
                .await
                .unwrap();
        }

        async fn retire_old(&mut self) {
            drop(self.launch.take());
            let mut state = self
                .store
                .machine_state(self.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            state.vmm_pid = None;
            state.started_at = None;
            state.run_id = None;
            assert!(self
                .store
                .try_retire_launch_storage_inner(
                    self.begin.launch_operation_id,
                    self.begin.ended_run_id,
                    self.begin.storage_generation,
                    &state,
                    crate::StorageStopOutcome::Unknown
                )
                .await
                .unwrap());
        }

        async fn wake_launch(&self, run: Uuid) -> LaunchStorageLease {
            let storage = self
                .store
                .machine_storage(self.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            self.store
                .register_launch_storage(
                    self.begin.machine_id,
                    run,
                    &storage,
                    &self.begin.launch_spec,
                )
                .await
                .unwrap()
        }

        async fn assert_state(&self, status: MachineRuntimeState, phase: Option<HibernatePhase>) {
            assert_eq!(
                self.store
                    .machine_state(self.begin.machine_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                status
            );
            assert_eq!(
                self.store
                    .machine_hibernation(self.begin.machine_id)
                    .await
                    .unwrap()
                    .map(|row| row.phase),
                phase
            );
        }
    }

    #[tokio::test]
    async fn hibernation_abort_restores_running_and_paused_and_enforces_one_row() {
        for (status, prior, wrong) in [
            (
                MachineRuntimeState::Running,
                HibernatePriorState::Running,
                HibernatePriorState::Paused,
            ),
            (
                MachineRuntimeState::Paused,
                HibernatePriorState::Paused,
                HibernatePriorState::Running,
            ),
        ] {
            let f = Fixture::new(status).await;
            f.begin().await;
            f.assert_state(
                MachineRuntimeState::Hibernating,
                Some(HibernatePhase::Saving),
            )
            .await;
            let mut duplicate = f.begin.clone();
            duplicate.save_id = Uuid::new_v4();
            assert!(f.store.begin_hibernation(&duplicate).await.is_err());
            assert!(sqlx::query("INSERT INTO machine_hibernation SELECT * FROM machine_hibernation WHERE machine_id=?1")
                .bind(f.begin.machine_id.to_string()).execute(&f.store.pool).await.is_err());
            assert!(f
                .store
                .abort_hibernation_saving(f.begin.machine_id, f.begin.save_id, wrong)
                .await
                .is_err());
            assert_eq!(
                f.store.hibernations_needing_recovery().await.unwrap().len(),
                1
            );
            f.store.recover_pending_image_cache().await.unwrap();
            assert!(f.cut.saved_files[0].file.path.is_file());
            f.store
                .abort_hibernation_saving(f.begin.machine_id, f.begin.save_id, prior)
                .await
                .unwrap();
            f.assert_state(status, None).await;
            f.store.recover_pending_image_cache().await.unwrap();
            assert!(!f.cut.saved_files[0].file.path.exists());
        }
    }

    #[tokio::test]
    async fn hibernation_commit_is_atomic_and_checkpointed() {
        let f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.store.execute_test_sql("CREATE TRIGGER reject_hibernated BEFORE UPDATE ON machine_state WHEN NEW.status='hibernated' BEGIN SELECT RAISE(ABORT,'atomicity probe'); END;").await.unwrap();
        assert!(f
            .store
            .commit_hibernation_available(
                f.begin.machine_id,
                f.begin.save_id,
                &f.cut,
                &f.memory(),
                16384
            )
            .await
            .is_err());
        f.assert_state(
            MachineRuntimeState::Hibernating,
            Some(HibernatePhase::Saving),
        )
        .await;
        f.store
            .execute_test_sql("DROP TRIGGER reject_hibernated")
            .await
            .unwrap();
        f.store.checkpoint_catalog().await.unwrap();
        let mut reader = f.store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM machine_hibernation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let memory = f.memory();
        let commit = f.store.commit_hibernation_available(
            f.begin.machine_id,
            f.begin.save_id,
            &f.cut,
            &memory,
            16384,
        );
        tokio::pin!(commit);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut commit)
                .await
                .is_err()
        );
        // Other connections observe the state and phase together even while the
        // completed-checkpoint boundary is waiting on this pinned reader.
        f.assert_state(
            MachineRuntimeState::Hibernated,
            Some(HibernatePhase::Available),
        )
        .await;
        reader.rollback().await.unwrap();
        commit.await.unwrap();
        let (busy, logged, checkpointed): (i64, i64, i64) =
            sqlx::query_as("PRAGMA wal_checkpoint(PASSIVE)")
                .fetch_one(&f.store.pool)
                .await
                .unwrap();
        assert_eq!(busy, 0);
        assert_eq!(logged, checkpointed);
    }

    #[tokio::test]
    async fn hibernation_release_preserves_files_and_allows_another_wake() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        assert!(f
            .store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, Uuid::new_v4())
            .await
            .is_err());
        f.retire_old().await;
        let run = Uuid::new_v4();
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .unwrap();
        let launch = f.wake_launch(run).await;
        assert!(f
            .store
            .release_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .is_err());
        drop(launch);
        f.store
            .release_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .unwrap();
        f.assert_state(
            MachineRuntimeState::Hibernated,
            Some(HibernatePhase::Available),
        )
        .await;
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(f
            .cut
            .saved_files
            .iter()
            .all(|saved| saved.file.path.is_file()));
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, Uuid::new_v4())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn hibernation_consume_checkpoints_and_roots_memory_until_ordinary_run_retirement() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        let run = Uuid::new_v4();
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .unwrap();
        let launch = f.wake_launch(run).await;
        let operation = launch.operation_id();
        assert!(f
            .store
            .consume_hibernation(
                f.begin.machine_id,
                f.begin.save_id,
                Uuid::new_v4(),
                operation
            )
            .await
            .is_err());
        assert!(f
            .store
            .consume_hibernation(f.begin.machine_id, Uuid::new_v4(), run, operation)
            .await
            .is_err());
        f.assert_state(MachineRuntimeState::Restoring, Some(HibernatePhase::Waking))
            .await;
        f.store.checkpoint_catalog().await.unwrap();
        let mut reader = f.store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM machine_hibernation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let consume =
            f.store
                .consume_hibernation(f.begin.machine_id, f.begin.save_id, run, operation);
        tokio::pin!(consume);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut consume)
                .await
                .is_err()
        );
        f.assert_state(MachineRuntimeState::Activating, None).await;
        reader.rollback().await.unwrap();
        consume.await.unwrap();
        assert!(!f.store.has_hibernation(f.begin.machine_id).await.unwrap());
        let roles: Vec<String> = sqlx::query_scalar(
            "SELECT role FROM storage_operation_hibernation WHERE operation_id=?1 ORDER BY role",
        )
        .bind(operation.to_string())
        .fetch_all(&f.store.pool)
        .await
        .unwrap();
        assert_eq!(roles, ["ram-baseline", "ram-mapping"]);
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(f.cut.saved_files[0].file.path.is_file());
        // A new identified baseline drops only the byte-baseline role.
        let file = std::fs::File::open(&f.cut.saved_files[0].file.path).unwrap();
        let map = crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::RAM)
            .hash_open_file(&file, f.cut.packed_length)
            .unwrap()
            .map;
        f.store
            .admit_published_map_root(operation, &map)
            .await
            .unwrap();
        f.store
            .retain_memory_baseline(
                operation,
                crate::storage::identity::ObjectDigest::from_sha256(*map.id().as_bytes()),
            )
            .await
            .unwrap();
        let roles: Vec<String> = sqlx::query_scalar(
            "SELECT role FROM storage_operation_hibernation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_all(&f.store.pool)
        .await
        .unwrap();
        assert_eq!(roles, ["ram-mapping"]);
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(f.cut.saved_files[0].file.path.is_file());
        drop(map);
        drop(launch);
        let mut state = f
            .store
            .machine_state(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        state.status = MachineRuntimeState::Stopped;
        state.run_id = None;
        assert!(f
            .store
            .try_retire_launch_storage_inner(
                operation,
                run,
                f.begin.storage_generation,
                &state,
                crate::StorageStopOutcome::Unknown
            )
            .await
            .unwrap());
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(!f.cut.saved_files[0].file.path.exists());
    }

    #[tokio::test]
    async fn hibernation_discard_roots_until_finish_and_removal_cascades() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        f.store.checkpoint_catalog().await.unwrap();
        let mut reader = f.store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM machine_hibernation")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let discard = f
            .store
            .begin_hibernation_discard(f.begin.machine_id, f.begin.save_id);
        tokio::pin!(discard);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut discard)
                .await
                .is_err()
        );
        f.assert_state(
            MachineRuntimeState::Hibernated,
            Some(HibernatePhase::Discarding),
        )
        .await;
        reader.rollback().await.unwrap();
        discard.await.unwrap();
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(f.cut.saved_files[0].file.path.is_file());
        f.store
            .finish_hibernation_discard(f.begin.machine_id, f.begin.save_id)
            .await
            .unwrap();
        f.assert_state(MachineRuntimeState::Stopped, None).await;
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(!f.cut.saved_files[0].file.path.exists());

        let f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        sqlx::query("DELETE FROM machine_config WHERE id=?1")
            .bind(f.begin.machine_id.to_string())
            .execute(&f.store.pool)
            .await
            .unwrap();
        assert!(!f.store.has_hibernation(f.begin.machine_id).await.unwrap());
    }

    #[tokio::test]
    async fn hibernation_every_illegal_phase_move_is_refused() {
        for phase in [
            HibernatePhase::Saving,
            HibernatePhase::Available,
            HibernatePhase::Waking,
            HibernatePhase::Discarding,
        ] {
            let mut f = Fixture::new(MachineRuntimeState::Running).await;
            let machine = f.begin.machine_id;
            let save = f.begin.save_id;
            let run = Uuid::new_v4();
            f.begin().await;
            if phase != HibernatePhase::Saving {
                f.available().await;
                f.retire_old().await;
            }
            if phase == HibernatePhase::Waking {
                f.store
                    .claim_hibernation_wake(machine, save, run)
                    .await
                    .unwrap();
            }
            if phase == HibernatePhase::Discarding {
                f.store
                    .begin_hibernation_discard(machine, save)
                    .await
                    .unwrap();
            }
            assert!(f.store.begin_hibernation(&f.begin).await.is_err());
            if phase != HibernatePhase::Saving {
                assert!(f
                    .store
                    .commit_hibernation_available(machine, save, &f.cut, &f.memory(), 0)
                    .await
                    .is_err());
                assert!(f
                    .store
                    .abort_hibernation_saving(machine, save, HibernatePriorState::Running)
                    .await
                    .is_err());
            }
            if phase != HibernatePhase::Available {
                assert!(f
                    .store
                    .claim_hibernation_wake(machine, save, Uuid::new_v4())
                    .await
                    .is_err());
                assert!(f
                    .store
                    .begin_hibernation_discard(machine, save)
                    .await
                    .is_err());
            }
            if phase != HibernatePhase::Waking {
                assert!(f
                    .store
                    .release_hibernation_wake(machine, save, run)
                    .await
                    .is_err());
                assert!(f
                    .store
                    .consume_hibernation(machine, save, run, Uuid::new_v4())
                    .await
                    .is_err());
            } else {
                assert!(f
                    .store
                    .release_hibernation_wake(machine, save, Uuid::new_v4())
                    .await
                    .is_err());
            }
            if phase != HibernatePhase::Discarding {
                assert!(f
                    .store
                    .finish_hibernation_discard(machine, save)
                    .await
                    .is_err());
            }
            assert!(f
                .store
                .abort_hibernation_saving(machine, Uuid::new_v4(), HibernatePriorState::Running)
                .await
                .is_err());
            assert_eq!(
                f.store
                    .machine_hibernation(machine)
                    .await
                    .unwrap()
                    .unwrap()
                    .phase,
                phase
            );
        }
    }

    #[tokio::test]
    async fn hibernation_owned_cut_handoff_releases_only_byte_baseline() {
        use crate::store::snapshot_store::{CaptureReservationRequest, SnapshotStore};
        use std::sync::Arc;
        use vm_spec::capture::CapturePauseAuthority;
        use vm_spec::lifecycle::{CapturePolicy, CaptureResumePolicy};

        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        let machine = f.begin.machine_id;
        let run = Uuid::new_v4();
        f.store
            .claim_hibernation_wake(machine, f.begin.save_id, run)
            .await
            .unwrap();
        let launch = f.wake_launch(run).await;
        let operation = launch.operation_id();
        f.store
            .consume_hibernation(machine, f.begin.save_id, run, operation)
            .await
            .unwrap();
        f.store
            .mark_launch_storage_admitted(operation)
            .await
            .unwrap();
        let mut state = f.store.machine_state(machine).await.unwrap().unwrap();
        state.status = MachineRuntimeState::Running;
        f.store.save_machine_state(&state).await.unwrap();
        let config = f.store.machine_config(machine).await.unwrap().unwrap();
        let storage = f.store.machine_storage(machine).await.unwrap().unwrap();
        let snapshots = SnapshotStore::from_store(Arc::new(f.store.clone()));
        let request = CaptureReservationRequest {
            machine_id: machine,
            run_id: run,
            capture_id: Uuid::new_v4(),
            configuration: CaptureConfiguration::from_spec(&config.spec).unwrap(),
            name: None,
            policy: CapturePolicy::Full,
            dirty_crossover_percent: 60,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseAuthority::Acquire,
        };
        let options = crate::store::fork::tests::options(&["after-wake"]);
        let observation = crate::store::fork::tests::observation(machine, run);
        drop(
            f.store
                .admit_fork(machine, &observation, &options, request.capture_id)
                .await
                .unwrap(),
        );
        let reservation = snapshots.reserve_capture(&request).await.unwrap();
        snapshots
            .bind_capture_boot(request.capture_id, storage.boot)
            .await
            .unwrap();
        let memory_path = f.cut.saved_files[0].file.path.clone();
        let capture_fixture = crate::store::capture::tests::Fixture {
            _temporary: f._temporary,
            snapshots,
            config,
            reservation,
            launch,
        };
        crate::store::capture::tests::seal_owned(&capture_fixture);
        capture_fixture
            .snapshots
            .retain_local_capture(request.capture_id)
            .await
            .unwrap();
        let roles: Vec<String> = sqlx::query_scalar(
            "SELECT role FROM storage_operation_hibernation WHERE operation_id=?1",
        )
        .bind(operation.to_string())
        .fetch_all(&f.store.pool)
        .await
        .unwrap();
        assert_eq!(roles, ["ram-mapping"]);
        f.store.recover_pending_image_cache().await.unwrap();
        assert!(memory_path.is_file());
    }

    async fn lifecycle_runtime(f: &Fixture) -> crate::Runtime {
        let paths = LocalPaths::new(f.store.home_path().to_path_buf());
        let components = crate::runtime::components::test_components(paths.home());
        crate::Runtime::from_store(
            paths,
            std::sync::Arc::new(f.store.clone()),
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::default(),
            components,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn hibernation_lifecycle_recovery_retires_available_without_deleting_saved_files() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        drop(f.launch.take());
        let runtime = lifecycle_runtime(&f).await;
        let config = f
            .store
            .machine_config(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        let machine_directory = OwnedDirectory::open_existing_root(&config.machine_dir)
            .unwrap()
            .unwrap();
        let captures = machine_directory
            .ensure_dir(vm_spec::capture::CAPTURES_DIRECTORY)
            .unwrap();
        captures
            .ensure_dir(&f.begin.save_id.to_string())
            .unwrap()
            .write_file("record.json", b"interrupted")
            .unwrap();
        let status = runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(status.state, MachineRuntimeState::Hibernated);
        assert!(f
            .store
            .launch_storage_operations(f.begin.machine_id)
            .await
            .unwrap()
            .is_empty());
        assert!(f
            .cut
            .saved_files
            .iter()
            .all(|saved| saved.file.path.is_file()));
        let state = f
            .store
            .machine_state(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.run_id, None);
        assert!(!config
            .machine_dir
            .join(vm_spec::capture::CAPTURES_DIRECTORY)
            .join(f.begin.save_id.to_string())
            .exists());
        let data = runtime.machine_inspect_data(config).await.unwrap();
        assert_eq!(data.hibernation.unwrap().saved_state_bytes, 16384);
    }

    #[tokio::test]
    async fn hibernation_lifecycle_discard_is_idempotent_at_each_crash_boundary() {
        for boundary in 0..3 {
            let mut f = Fixture::new(MachineRuntimeState::Running).await;
            f.begin().await;
            f.available().await;
            f.retire_old().await;
            let runtime = lifecycle_runtime(&f).await;
            let config = f
                .store
                .machine_config(f.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            if boundary > 0 {
                f.store
                    .begin_hibernation_discard(config.id, f.begin.save_id)
                    .await
                    .unwrap();
            }
            if boundary > 1 {
                let parent =
                    OwnedDirectory::open_existing_root(&config.machine_dir.join("hibernation"))
                        .unwrap()
                        .unwrap();
                let directory = parent
                    .open_dir(&f.begin.save_id.to_string())
                    .unwrap()
                    .unwrap();
                parent
                    .remove_open_tree(&f.begin.save_id.to_string(), &directory)
                    .unwrap();
                parent.sync().unwrap();
            }
            assert!(crate::machine::hibernate::discard_locked(&runtime, &config)
                .await
                .unwrap());
            assert!(
                !crate::machine::hibernate::discard_locked(&runtime, &config)
                    .await
                    .unwrap()
            );
            assert!(!f.store.has_hibernation(config.id).await.unwrap());
            assert_eq!(
                f.store
                    .machine_state(config.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MachineRuntimeState::Stopped
            );
            assert!(!f
                .store
                .hibernation_directory(config.id, f.begin.save_id)
                .exists());
        }
    }

    #[tokio::test]
    async fn hibernation_lifecycle_saving_dead_run_aborts_before_ordinary_reconciliation() {
        for prior in [MachineRuntimeState::Running, MachineRuntimeState::Paused] {
            let mut f = Fixture::new(prior).await;
            f.begin().await;
            drop(f.launch.take());
            let runtime = lifecycle_runtime(&f).await;
            let config = f
                .store
                .machine_config(f.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            let machine_directory = OwnedDirectory::open_existing_root(&config.machine_dir)
                .unwrap()
                .unwrap();
            let captures = machine_directory
                .ensure_dir(vm_spec::capture::CAPTURES_DIRECTORY)
                .unwrap();
            captures
                .ensure_dir(&f.begin.save_id.to_string())
                .unwrap()
                .write_file("request.json", b"partial")
                .unwrap();
            runtime
                .reconcile_machine_runtime_locked(&config)
                .await
                .unwrap();
            assert!(!f.store.has_hibernation(config.id).await.unwrap());
            assert!(!f
                .store
                .hibernation_directory(config.id, f.begin.save_id)
                .exists());
            assert!(!config
                .machine_dir
                .join(vm_spec::capture::CAPTURES_DIRECTORY)
                .join(f.begin.save_id.to_string())
                .exists());
            assert!(f
                .store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .is_empty());
        }
    }

    #[tokio::test]
    async fn hibernation_lifecycle_abandoned_wake_returns_to_available() {
        let mut f = Fixture::new(MachineRuntimeState::Paused).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        let run = Uuid::new_v4();
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .unwrap();
        let launch = f.wake_launch(run).await;
        drop(launch);
        let runtime = lifecycle_runtime(&f).await;
        let config = f
            .store
            .machine_config(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(
            f.store
                .machine_hibernation(config.id)
                .await
                .unwrap()
                .unwrap()
                .phase,
            HibernatePhase::Available
        );
        assert_eq!(
            f.store
                .machine_state(config.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MachineRuntimeState::Hibernated
        );
        assert!(f
            .cut
            .saved_files
            .iter()
            .all(|saved| saved.file.path.is_file()));
    }

    #[tokio::test]
    async fn hibernation_lifecycle_wake_refuses_missing_changed_files_and_disks_retryably() {
        use crate::storage::hibernate_file::HibernateUnusableReason;
        use std::os::unix::fs::PermissionsExt;
        for (which, expected) in [
            (0, HibernateUnusableReason::FilesMissing),
            (1, HibernateUnusableReason::FilesChanged),
            (2, HibernateUnusableReason::DisksChanged),
        ] {
            let mut f = Fixture::new(MachineRuntimeState::Running).await;
            f.begin().await;
            f.available().await;
            f.retire_old().await;
            match which {
                0 => std::fs::remove_file(&f.cut.saved_files[0].file.path).unwrap(),
                1 => std::fs::set_permissions(
                    &f.cut.saved_files[0].file.path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap(),
                _ => std::fs::write(&f.cut.writable_disks[0].file.path, [0x52; 4096]).unwrap(),
            }
            let runtime = lifecycle_runtime(&f).await;
            let config = f
                .store
                .machine_config(f.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            let machine = crate::Machine::new(runtime.clone(), config.id);
            for _ in 0..2 {
                let record = f
                    .store
                    .machine_hibernation(config.id)
                    .await
                    .unwrap()
                    .unwrap();
                let error = machine.wake_locked(&config, record).await.unwrap_err();
                assert!(
                    matches!(error, crate::LibVmError::HibernateUnusable { reason, .. } if reason == expected),
                    "{error}"
                );
                assert_eq!(
                    f.store
                        .machine_state(config.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .status,
                    MachineRuntimeState::Hibernated
                );
                assert_eq!(
                    f.store
                        .machine_hibernation(config.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .phase,
                    HibernatePhase::Available
                );
                assert!(f
                    .store
                    .launch_storage_operations(config.id)
                    .await
                    .unwrap()
                    .is_empty());
            }
        }
    }

    #[tokio::test]
    async fn hibernation_lifecycle_storage_fence_covers_all_phases_before_mutation() {
        use crate::machine::hibernate::{fence, HibernateRemedy};
        use crate::machine::stopped::{admit_stopped, StoppedAdmission};
        for phase in [
            HibernatePhase::Saving,
            HibernatePhase::Available,
            HibernatePhase::Waking,
            HibernatePhase::Discarding,
        ] {
            let mut f = Fixture::new(MachineRuntimeState::Running).await;
            f.begin().await;
            if phase != HibernatePhase::Saving {
                f.available().await;
                f.retire_old().await;
                match phase {
                    HibernatePhase::Waking => {
                        f.store
                            .claim_hibernation_wake(
                                f.begin.machine_id,
                                f.begin.save_id,
                                Uuid::new_v4(),
                            )
                            .await
                            .unwrap();
                    }
                    HibernatePhase::Discarding => f
                        .store
                        .begin_hibernation_discard(f.begin.machine_id, f.begin.save_id)
                        .await
                        .unwrap(),
                    _ => {}
                }
            }
            let runtime = lifecycle_runtime(&f).await;
            let mut config = f
                .store
                .machine_config(f.begin.machine_id)
                .await
                .unwrap()
                .unwrap();
            let before = std::fs::read(&f.cut.writable_disks[0].file.path).unwrap();
            let configuration = serde_json::to_vec(&config).unwrap();
            assert!(matches!(
                fence(&runtime, &config, HibernateRemedy::Start).await,
                Err(crate::LibVmError::HibernatedStartFirst { .. })
            ));
            assert!(matches!(
                fence(&runtime, &config, HibernateRemedy::Stop).await,
                Err(crate::LibVmError::HibernatedStopFirst { .. })
            ));
            for (admission, start) in [
                (StoppedAdmission::Ordinary, true),
                (StoppedAdmission::RawExport, false),
                (
                    StoppedAdmission::Handoff(
                        crate::handoff::types::OperationId::new(Uuid::new_v4()).unwrap(),
                    ),
                    false,
                ),
            ] {
                let error = match admit_stopped(
                    &runtime,
                    config.id,
                    &crate::ExternalResourcePolicy::Reject,
                    admission,
                )
                .await
                {
                    Ok(_) => panic!("saved state admitted stopped storage"),
                    Err(error) => error,
                };
                assert!(
                    matches!(
                        (&error, start),
                        (crate::LibVmError::HibernatedStartFirst { .. }, true)
                            | (crate::LibVmError::HibernatedStopFirst { .. }, false)
                    ),
                    "{error}"
                );
            }
            let mut storage = f.store.machine_storage(config.id).await.unwrap().unwrap();
            assert!(matches!(
                runtime
                    .admit_cold_launch_storage(&mut config, &mut storage)
                    .await,
                Err(crate::LibVmError::HibernatedStopFirst { .. })
            ));
            let machine = crate::Machine::new(runtime.clone(), config.id);
            assert!(matches!(
                machine.update(crate::MachineUpdate::new().cpus(2)).await,
                Err(crate::LibVmError::HibernatedStopFirst { .. })
            ));
            assert!(matches!(
                machine.replace_config(config.spec.clone()).await,
                Err(crate::LibVmError::HibernatedStopFirst { .. })
            ));
            assert!(matches!(
                machine.set_network(|network| network.none()).await,
                Err(crate::LibVmError::HibernatedStopFirst { .. })
            ));
            assert!(matches!(
                runtime
                    .snapshot(
                        &crate::MachineRef::id(config.id),
                        crate::SnapshotOptions::default(),
                        None
                    )
                    .await,
                Err(crate::LibVmError::HibernatedStartFirst { .. })
            ));
            assert_eq!(
                std::fs::read(&f.cut.writable_disks[0].file.path).unwrap(),
                before
            );
            assert_eq!(
                serde_json::to_vec(&f.store.machine_config(config.id).await.unwrap().unwrap())
                    .unwrap(),
                configuration
            );
        }
    }

    #[tokio::test]
    async fn hibernation_lifecycle_force_stop_discards_without_inspecting_saved_files() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        std::fs::remove_file(&f.cut.saved_files[0].file.path).unwrap();
        let runtime = lifecycle_runtime(&f).await;
        let machine = crate::Machine::new(runtime, f.begin.machine_id);
        let exit = machine.kill().await.unwrap();
        assert_eq!(exit.machine.status.label(), "stopped");
        assert!(!f.store.has_hibernation(f.begin.machine_id).await.unwrap());
    }

    #[tokio::test]
    async fn hibernation_lifecycle_stop_unusable_save_discards_with_typed_warning() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        std::fs::remove_file(&f.cut.saved_files[0].file.path).unwrap();
        let runtime = lifecycle_runtime(&f).await;
        let machine = crate::Machine::new(runtime, f.begin.machine_id);
        let outcome = machine.stop().await.unwrap();
        assert_eq!(outcome.machine.status.label(), "stopped");
        assert!(matches!(
            outcome.warning,
            Some(crate::MachineStopWarning::SavedStateUnusable {
                reason: crate::storage::hibernate_file::HibernateUnusableReason::FilesMissing
            })
        ));
        assert!(!f.store.has_hibernation(f.begin.machine_id).await.unwrap());
    }

    #[tokio::test]
    async fn hibernation_lifecycle_inspection_never_recovers_or_wakes() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        drop(f.launch.take());
        let runtime = lifecycle_runtime(&f).await;
        let config = f
            .store
            .machine_config(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        let before = f
            .store
            .machine_hibernation(config.id)
            .await
            .unwrap()
            .unwrap();
        for _ in 0..2 {
            let data = runtime.machine_inspect_data(config.clone()).await.unwrap();
            assert_eq!(data.status.label(), "hibernated");
        }
        assert_eq!(
            f.store
                .machine_hibernation(config.id)
                .await
                .unwrap()
                .unwrap(),
            before
        );
        assert_eq!(
            f.store
                .launch_storage_operations(config.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn hibernation_compensation_restores_only_the_unretired_source() {
        for prior in [MachineRuntimeState::Running, MachineRuntimeState::Paused] {
            let f = Fixture::new(prior).await;
            f.begin().await;
            assert!(f
                .store
                .abort_hibernation_available(f.begin.machine_id, f.begin.save_id)
                .await
                .is_err());
            f.available().await;
            f.store
                .abort_hibernation_available(f.begin.machine_id, f.begin.save_id)
                .await
                .unwrap();
            assert!(!f.store.has_hibernation(f.begin.machine_id).await.unwrap());
            assert_eq!(
                f.store
                    .machine_state(f.begin.machine_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                prior
            );
            assert!(f
                .cut
                .saved_files
                .iter()
                .all(|saved| saved.file.path.is_file()));
        }
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        assert!(f
            .store
            .abort_hibernation_available(f.begin.machine_id, f.begin.save_id)
            .await
            .is_err());
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, Uuid::new_v4())
            .await
            .unwrap();
        assert!(f
            .store
            .abort_hibernation_available(f.begin.machine_id, f.begin.save_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hibernation_recovery_never_signals_reused_holder_pid() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        drop(f.launch.take());
        let runtime = lifecycle_runtime(&f).await;
        let config = f
            .store
            .machine_config(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        runtime
            .ensure_machine_runtime_directories(config.id)
            .unwrap();
        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let identity =
            crate::supervisor::process::ProcessIdentity::for_pid(i32::try_from(pid).unwrap())
                .unwrap()
                .unwrap();
        let birth = u64::try_from(identity.started_at().unwrap()).unwrap();
        let holder = protocol::shutdown::StorageHolderRecord {
            schema_version: 1,
            machine_id: Uuid::from(config.id).to_string(),
            run_id: f.begin.ended_run_id.to_string(),
            operation_id: f.begin.launch_operation_id.to_string(),
            holders: vec![protocol::shutdown::StorageHolder {
                role: protocol::shutdown::StorageHolderRole::Monitor,
                pid,
                started_at: birth + 1,
            }],
        };
        let paths = runtime.machine_paths(config.id);
        let name = paths.vmm_storage_holder_path();
        let directory = OwnedDirectory::open_existing_root(paths.machine_run_dir())
            .unwrap()
            .unwrap();
        directory
            .write_file(
                name.file_name().unwrap().to_str().unwrap(),
                &holder.encode().unwrap(),
            )
            .unwrap();
        let state = runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(state.state, MachineRuntimeState::Hibernated);
        assert!(identity.is_alive().unwrap());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }

    #[tokio::test]
    async fn hibernation_lifecycle_postconsume_run_loss_stops_and_deletes_unrooted_memory() {
        let mut f = Fixture::new(MachineRuntimeState::Running).await;
        f.begin().await;
        f.available().await;
        f.retire_old().await;
        let run = Uuid::new_v4();
        f.store
            .claim_hibernation_wake(f.begin.machine_id, f.begin.save_id, run)
            .await
            .unwrap();
        let launch = f.wake_launch(run).await;
        f.store
            .consume_hibernation(
                f.begin.machine_id,
                f.begin.save_id,
                run,
                launch.operation_id(),
            )
            .await
            .unwrap();
        assert!(f
            .store
            .run_has_hibernation_memory(f.begin.machine_id, run)
            .await
            .unwrap());
        drop(launch);
        let runtime = lifecycle_runtime(&f).await;
        let config = f
            .store
            .machine_config(f.begin.machine_id)
            .await
            .unwrap()
            .unwrap();
        let state = runtime
            .reconcile_machine_runtime_locked(&config)
            .await
            .unwrap();
        assert_eq!(state.state, MachineRuntimeState::Stopped);
        assert!(!f.store.has_hibernation(config.id).await.unwrap());
        assert!(f
            .store
            .launch_storage_operations(config.id)
            .await
            .unwrap()
            .is_empty());
        assert!(!f
            .store
            .hibernation_directory(config.id, f.begin.save_id)
            .exists());
    }
}

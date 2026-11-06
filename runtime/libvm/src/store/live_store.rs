//! Durable command intent and current exact-monitor projection.
//!
//! No transaction in this module crosses monitor I/O. Terminal responses are
//! immutable history; only a fresh status observation supplies current authority.
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use vm_spec::lifecycle::{
    LiveCommand, LiveCommandResult, LiveLifecycle, LiveOperationRecord, VmLifecycleState,
};
use vm_spec::live::LiveMachineReport;

use crate::store::models::{MachineId, MachineState};
use crate::store::row::DbMachineState;
use crate::store::Store;
use crate::LibVmError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LiveCommandIntent {
    pub report: LiveMachineReport,
    pub command: LiveCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineLifecycle {
    pub report: LiveMachineReport,
    pub state: VmLifecycleState,
    pub lifecycle: LiveLifecycle,
    pub operation: Option<LiveOperationRecord>,
}

#[derive(Debug, Clone)]
pub(crate) struct RetainedLiveCommand {
    pub intent: LiveCommandIntent,
    pub result: Option<LiveCommandResult>,
}

fn invalid(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveProtocol {
        message: message.into(),
    }
}

impl Store {
    pub(crate) async fn live_command_record(
        &self,
        machine_id: MachineId,
        run_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<RetainedLiveCommand>, LibVmError> {
        let row = sqlx::query("SELECT monitor_id,json(input_json) AS input_json,json(result_json) AS result_json FROM live_command WHERE machine_id=?1 AND run_id=?2 AND request_id=?3")
            .bind(machine_id.to_string()).bind(run_id.to_string()).bind(request_id.to_string()).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let intent: LiveCommandIntent =
                serde_json::from_str(&row.try_get::<String, _>("input_json")?)
                    .map_err(|error| invalid(error.to_string()))?;
            let envelope = intent.command.envelope();
            if envelope.machine_id.as_str() != Uuid::from(machine_id).to_string()
                || envelope.run_id.as_str() != run_id.to_string()
                || envelope.request_id.as_str() != request_id.to_string()
                || intent.report.monitor_id != row.try_get::<String, _>("monitor_id")?
            {
                return Err(invalid("retained command differs from indexed identity"));
            }
            let result = row
                .try_get::<Option<String>, _>("result_json")?
                .map(|json| serde_json::from_str(&json).map_err(|error| invalid(error.to_string())))
                .transpose()?;
            Ok(RetainedLiveCommand { intent, result })
        })
        .transpose()
    }

    pub(crate) async fn prepare_live_command(
        &self,
        machine_id: MachineId,
        run_id: Uuid,
        request_id: Uuid,
        intent: &LiveCommandIntent,
    ) -> Result<RetainedLiveCommand, LibVmError> {
        if let LiveCommand::Capture(capture) = &intent.command {
            capture.validate_plan().map_err(invalid)?;
        }
        let envelope = intent.command.envelope();
        if envelope.machine_id.as_str() != Uuid::from(machine_id).to_string()
            || envelope.run_id.as_str() != run_id.to_string()
            || envelope.request_id.as_str() != request_id.to_string()
            || intent.report.machine_id != Uuid::from(machine_id).to_string()
            || intent.report.run_id != run_id.to_string()
        {
            return Err(invalid(
                "live command intent differs from its indexed identity",
            ));
        }
        intent.report.validate().map_err(invalid)?;
        let input = serde_json::to_string(intent).map_err(|error| invalid(error.to_string()))?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let state = sqlx::query_as::<_, DbMachineState>(
            "SELECT machine_id, status, json(state_json) AS state_json FROM machine_state WHERE machine_id = ?1",
        ).bind(machine_id.to_string()).fetch_optional(&mut *tx).await?
            .ok_or_else(|| invalid("live command has no machine state"))?.0;
        #[cfg(test)]
        if let Some(hook) = &self.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::Preparing)?;
        }
        if state.run_id.as_deref() != Some(run_id.to_string().as_str()) || state.vmm_pid.is_none() {
            return Err(invalid("live command run is no longer current"));
        }
        let foreign_monitor: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM live_run WHERE machine_id=?1 AND run_id=?2 AND monitor_id<>?3 UNION ALL SELECT 1 FROM live_command WHERE machine_id=?1 AND run_id=?2 AND monitor_id<>?3)")
            .bind(machine_id.to_string()).bind(run_id.to_string()).bind(&intent.report.monitor_id).fetch_one(&mut *tx).await?;
        if foreign_monitor {
            return Err(invalid(
                "live command monitor differs from retained run ownership",
            ));
        }
        let existing = sqlx::query(
            "SELECT monitor_id, json(input_json) AS input_json, json(result_json) AS result_json FROM live_command WHERE machine_id=?1 AND run_id=?2 AND request_id=?3",
        ).bind(machine_id.to_string()).bind(run_id.to_string()).bind(request_id.to_string())
            .fetch_optional(&mut *tx).await?;
        if let Some(row) = existing {
            let stored: LiveCommandIntent =
                serde_json::from_str(&row.try_get::<String, _>("input_json")?)
                    .map_err(|error| invalid(error.to_string()))?;
            if stored.command != intent.command
                || stored.report.monitor_id != intent.report.monitor_id
                || stored.report.topology_revision != intent.report.topology_revision
                || row.try_get::<String, _>("monitor_id")? != intent.report.monitor_id
            {
                return Err(invalid(
                    "live request identity conflicts with persisted inputs",
                ));
            }
            let result = row
                .try_get::<Option<String>, _>("result_json")?
                .map(|json| serde_json::from_str(&json).map_err(|error| invalid(error.to_string())))
                .transpose()?;
            tx.commit().await?;
            return Ok(RetainedLiveCommand {
                intent: stored,
                result,
            });
        }
        sqlx::query("INSERT INTO live_command(machine_id,run_id,request_id,monitor_id,input_json) VALUES(?1,?2,?3,?4,jsonb(?5))")
            .bind(machine_id.to_string()).bind(run_id.to_string()).bind(request_id.to_string())
            .bind(&intent.report.monitor_id).bind(input).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(RetainedLiveCommand {
            intent: intent.clone(),
            result: None,
        })
    }

    pub(crate) async fn pending_live_commands(
        &self,
        machine_id: MachineId,
        run_id: Uuid,
        monitor_id: &str,
    ) -> Result<Vec<RetainedLiveCommand>, LibVmError> {
        let rows = sqlx::query("SELECT json(input_json) AS input_json FROM live_command WHERE machine_id=?1 AND run_id=?2 AND monitor_id=?3 AND result_json IS NULL ORDER BY rowid")
            .bind(machine_id.to_string()).bind(run_id.to_string()).bind(monitor_id)
            .fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                let intent: LiveCommandIntent =
                    serde_json::from_str(&row.try_get::<String, _>("input_json")?)
                        .map_err(|error| invalid(error.to_string()))?;
                let envelope = intent.command.envelope();
                if envelope.machine_id.as_str() != Uuid::from(machine_id).to_string()
                    || envelope.run_id.as_str() != run_id.to_string()
                    || intent.report.monitor_id != monitor_id
                {
                    return Err(invalid("persisted pending live command binding is corrupt"));
                }
                Ok(RetainedLiveCommand {
                    intent,
                    result: None,
                })
            })
            .collect()
    }

    /// Save history and current authority together, but never let a response from
    /// an ended monitor overwrite a replacement run or a stop already requested.
    pub(crate) async fn complete_live_command(
        &self,
        machine_id: MachineId,
        run_id: Uuid,
        request_id: Uuid,
        monitor_id: &str,
        result: &LiveCommandResult,
        projection: Option<(&MachineLifecycle, &MachineState)>,
    ) -> Result<bool, LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing: Option<Option<String>> = sqlx::query_scalar("SELECT json(result_json) FROM live_command WHERE machine_id=?1 AND run_id=?2 AND request_id=?3 AND monitor_id=?4")
            .bind(machine_id.to_string()).bind(run_id.to_string()).bind(request_id.to_string()).bind(monitor_id)
            .fetch_optional(&mut *tx).await?;
        #[cfg(test)]
        if let Some(hook) = &self.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::Preparing)?;
        }
        match existing {
            None => return Err(invalid("live response has no matching durable intent")),
            Some(Some(json)) => {
                let previous: LiveCommandResult =
                    serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
                if &previous != result {
                    return Err(invalid("monitor changed a retained live command result"));
                }
            }
            Some(None) => {
                sqlx::query("UPDATE live_command SET result_json=jsonb(?5) WHERE machine_id=?1 AND run_id=?2 AND request_id=?3 AND monitor_id=?4 AND result_json IS NULL")
                    .bind(machine_id.to_string()).bind(run_id.to_string()).bind(request_id.to_string()).bind(monitor_id)
                    .bind(serde_json::to_string(result).map_err(|error| invalid(error.to_string()))?)
                    .execute(&mut *tx).await?;
            }
        }
        let operation = match result {
            LiveCommandResult::GetOperation(
                vm_spec::lifecycle::GetOperationOutcome::Observation { observation },
            ) => Some(&observation.operation),
            LiveCommandResult::CancelOperation(
                vm_spec::lifecycle::CancelOperationOutcome::Completed { completed },
            ) => Some(&completed.operation),
            LiveCommandResult::CancelOperation(
                vm_spec::lifecycle::CancelOperationOutcome::Failed { failed },
            ) => Some(&failed.operation),
            _ => None,
        };
        if let Some(operation) = operation {
            operation.validate().map_err(invalid)?;
            let previous: Option<String> = sqlx::query_scalar("SELECT json(record_json) FROM live_operation WHERE machine_id=?1 AND run_id=?2 AND operation_id=?3")
                .bind(machine_id.to_string()).bind(run_id.to_string()).bind(operation.operation_id.as_str()).fetch_optional(&mut *tx).await?;
            let previous: Option<LiveOperationRecord> = previous
                .map(|json| serde_json::from_str(&json).map_err(|error| invalid(error.to_string())))
                .transpose()?;
            let terminal = operation.status() != vm_spec::lifecycle::OperationStatus::InProgress;
            let retained_terminal = previous
                .as_ref()
                .is_some_and(|old| old.status() != vm_spec::lifecycle::OperationStatus::InProgress);
            if retained_terminal && terminal && previous.as_ref() != Some(operation) {
                return Err(invalid(
                    "monitor changed the original terminal operation outcome",
                ));
            }
            if !retained_terminal {
                sqlx::query("INSERT INTO live_operation(machine_id,run_id,monitor_id,operation_id,terminal,record_json) VALUES(?1,?2,?3,?4,?5,jsonb(?6)) ON CONFLICT(machine_id,run_id,operation_id) DO UPDATE SET terminal=excluded.terminal,record_json=excluded.record_json")
                    .bind(machine_id.to_string()).bind(run_id.to_string()).bind(monitor_id).bind(operation.operation_id.as_str()).bind(terminal)
                    .bind(serde_json::to_string(operation).map_err(|error| invalid(error.to_string()))?).execute(&mut *tx).await?;
            }
        }
        if projection.is_some_and(|(current, _)| {
            current.report.monitor_id != monitor_id || current.report.run_id != run_id.to_string()
        }) {
            return Err(invalid(
                "response projection belongs to another monitor/run",
            ));
        }
        let applied = match projection {
            Some((projection, next)) => {
                Self::write_live_projection(&mut tx, machine_id, projection, next).await?
            }
            None => false,
        };
        tx.commit().await?;
        Ok(applied)
    }

    pub(crate) async fn save_live_projection(
        &self,
        machine_id: MachineId,
        projection: &MachineLifecycle,
        next: &MachineState,
    ) -> Result<bool, LibVmError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        #[cfg(test)]
        if let Some(hook) = &self.layer_hook {
            hook.hit(crate::store::layer_store::tests::WorkerPoint::Preparing)?;
        }
        let applied = Self::write_live_projection(&mut tx, machine_id, projection, next).await?;
        tx.commit().await?;
        Ok(applied)
    }

    async fn write_live_projection(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        machine_id: MachineId,
        projection: &MachineLifecycle,
        next: &MachineState,
    ) -> Result<bool, LibVmError> {
        projection.report.validate().map_err(invalid)?;
        projection
            .lifecycle
            .validate_for(projection.state)
            .map_err(invalid)?;
        if next.machine_id != machine_id
            || projection.report.machine_id != Uuid::from(machine_id).to_string()
            || next.run_id.as_deref() != Some(projection.report.run_id.as_str())
        {
            return Err(invalid(
                "live projection differs from exact monitor/run binding",
            ));
        }
        let current = sqlx::query_as::<_, DbMachineState>("SELECT machine_id,status,json(state_json) AS state_json FROM machine_state WHERE machine_id=?1")
            .bind(machine_id.to_string()).fetch_optional(&mut **tx).await?.map(|row| row.0);
        if !current.as_ref().is_some_and(|current| {
            current.run_id == next.run_id
                && current.vmm_pid.is_some()
                && current.vmm_pid == next.vmm_pid
                && current.started_at == next.started_at
                && current.status != crate::store::models::MachineRuntimeState::Stopping
        }) {
            return Ok(false);
        }
        let monitor: Option<String> =
            sqlx::query_scalar("SELECT monitor_id FROM live_run WHERE machine_id=?1 AND run_id=?2")
                .bind(machine_id.to_string())
                .bind(&projection.report.run_id)
                .fetch_optional(&mut **tx)
                .await?;
        if monitor
            .as_ref()
            .is_some_and(|monitor| monitor != &projection.report.monitor_id)
        {
            return Err(invalid("monitor identity changed within a live run"));
        }
        sqlx::query("INSERT INTO live_run(machine_id,run_id,monitor_id,projection_json) VALUES(?1,?2,?3,jsonb(?4)) ON CONFLICT(machine_id) DO UPDATE SET run_id=excluded.run_id,monitor_id=excluded.monitor_id,projection_json=excluded.projection_json")
            .bind(machine_id.to_string()).bind(&projection.report.run_id).bind(&projection.report.monitor_id)
            .bind(serde_json::to_string(projection).map_err(|error| invalid(error.to_string()))?)
            .execute(&mut **tx).await?;
        sqlx::query("UPDATE machine_state SET status=?2,state_json=jsonb(?3) WHERE machine_id=?1")
            .bind(machine_id.to_string())
            .bind(next.status.as_str())
            .bind(serde_json::to_string(next).map_err(|error| invalid(error.to_string()))?)
            .execute(&mut **tx)
            .await?;
        Ok(true)
    }

    pub(crate) async fn live_operation(
        &self,
        machine_id: MachineId,
        run_id: &str,
        monitor_id: &str,
        operation_id: &vm_spec::lifecycle::LiveId,
    ) -> Result<Option<LiveOperationRecord>, LibVmError> {
        let json: Option<String> = sqlx::query_scalar("SELECT json(record_json) FROM live_operation WHERE machine_id=?1 AND run_id=?2 AND monitor_id=?3 AND operation_id=?4")
            .bind(machine_id.to_string()).bind(run_id).bind(monitor_id).bind(operation_id.as_str()).fetch_optional(&self.pool).await?;
        json.map(|json| {
            let operation: LiveOperationRecord =
                serde_json::from_str(&json).map_err(|error| invalid(error.to_string()))?;
            operation.validate().map_err(invalid)?;
            if &operation.operation_id != operation_id {
                return Err(invalid("operation differs from indexed identity"));
            }
            Ok(operation)
        })
        .transpose()
    }

    #[cfg(test)]
    pub(crate) async fn live_projection(
        &self,
        machine_id: MachineId,
        run_id: &str,
    ) -> Result<Option<MachineLifecycle>, LibVmError> {
        let row = sqlx::query("SELECT monitor_id,json(projection_json) AS projection_json FROM live_run WHERE machine_id=?1 AND run_id=?2")
            .bind(machine_id.to_string()).bind(run_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            let projection: MachineLifecycle =
                serde_json::from_str(&row.try_get::<String, _>("projection_json")?)
                    .map_err(|error| invalid(error.to_string()))?;
            if projection.report.machine_id != Uuid::from(machine_id).to_string()
                || projection.report.run_id != run_id
                || projection.report.monitor_id != row.try_get::<String, _>("monitor_id")?
            {
                return Err(invalid("persisted live projection binding is corrupt"));
            }
            Ok(projection)
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use crate::store::live_store::{LiveCommandIntent, MachineLifecycle};
    use crate::store::models::{MachineConfig, MachineId, MachineRuntimeState, MachineState};
    use crate::store::{MachineStore, Store};
    use std::num::NonZeroU64;
    use uuid::Uuid;
    use vm_spec::lifecycle::*;
    use vm_spec::live::*;

    fn id(value: Uuid) -> LiveId {
        LiveId::parse(&value.to_string()).unwrap()
    }
    async fn fixture() -> (tempfile::TempDir, Store, MachineState, LiveCommandIntent) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db")).await.unwrap();
        let machine = MachineId::new();
        let run = Uuid::new_v4();
        let state = MachineState {
            machine_id: machine,
            status: MachineRuntimeState::Running,
            vmm_pid: Some(123),
            started_at: Some(10),
            run_id: Some(run.to_string()),
            last_error: None,
            updated_at: 10,
        };
        let config = MachineConfig {
            id: machine,
            lock_id: crate::lock_manager::LockId::from(1),
            name: "pause-store".into(),
            spec: vm_spec::VmSpec::current(),
            retention: crate::MachineRetention::Persistent,
            process: Default::default(),
            template_name: None,
            agent_mode: None,
            guest: Default::default(),
            machine_dir: dir.path().join("machines").join(machine.to_string()),
            created_at: 1,
            modified_at: 1,
            image_ref: "disk".into(),
            root_disk_size: None,
            labels: Default::default(),
            metadata: Default::default(),
            network: Default::default(),
        };
        store.add_machine(&config, &state).await.unwrap();
        let intent = LiveCommandIntent {
            report: LiveMachineReport {
                schema_version: 1,
                scope: LiveScope::Machine,
                machine_id: Uuid::from(machine).to_string(),
                run_id: run.to_string(),
                monitor_id: Uuid::new_v4().to_string(),
                backend: LiveBackend::Mock,
                lane: LiveLane::NotApplicable,
                topology_revision: 1,
                live: LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered),
            },
            command: LiveCommand::Pause(PauseCommand {
                envelope: LiveCommandEnvelope {
                    machine_id: id(machine.into()),
                    run_id: id(run),
                    request_id: id(Uuid::new_v4()),
                },
            }),
        };
        (dir, store, state, intent)
    }
    fn receipt(intent: &LiveCommandIntent) -> LiveCommandResult {
        LiveCommandResult::Pause(PauseOutcome::Accepted {
            receipt: LiveOperationReceipt {
                operation_id: intent.command.envelope().request_id.clone(),
                kind: OperationKind::Pause,
                state: VmLifecycleState::Pausing,
            },
        })
    }
    fn paused(intent: &LiveCommandIntent, generation: u64) -> MachineLifecycle {
        MachineLifecycle {
            report: intent.report.clone(),
            state: VmLifecycleState::Paused,
            lifecycle: LiveLifecycle {
                current_pause: Some(CurrentPause {
                    token: PauseToken {
                        machine_id: intent.command.envelope().machine_id.clone(),
                        run_id: intent.command.envelope().run_id.clone(),
                        generation: NonZeroU64::new(generation).unwrap(),
                        owner: PauseOwner::User,
                    },
                    operation_id: intent.command.envelope().request_id.clone(),
                    freeze_epoch: NonZeroU64::new(generation).unwrap(),
                }),
                ..Default::default()
            },
            operation: None,
        }
    }
    fn identities(intent: &LiveCommandIntent) -> (Uuid, Uuid) {
        (
            Uuid::parse_str(intent.command.envelope().run_id.as_str()).unwrap(),
            Uuid::parse_str(intent.command.envelope().request_id.as_str()).unwrap(),
        )
    }

    #[tokio::test]
    async fn live_writes_reserve_the_writer_before_reading_current_authority() {
        use crate::store::layer_store::tests::{WorkerHook, WorkerPoint};

        #[derive(Clone, Copy, Debug)]
        enum Write {
            Intent,
            Result,
            Projection,
        }
        for write in [Write::Intent, Write::Result, Write::Projection] {
            let (_dir, mut store, state, intent) = fixture().await;
            let (run, request) = identities(&intent);
            if !matches!(write, Write::Intent) {
                store
                    .prepare_live_command(state.machine_id, run, request, &intent)
                    .await
                    .unwrap();
            }
            let current = paused(&intent, 1);
            let next =
                crate::machine::live_operations::project_machine_state(state.clone(), &current);
            let mut contender = store.pool.acquire().await.unwrap();
            sqlx::query("PRAGMA busy_timeout=0")
                .execute(&mut *contender)
                .await
                .unwrap();
            let (hook, mut entered, release) = WorkerHook::new(WorkerPoint::Preparing, false);
            store.layer_hook = Some(hook);
            let worker = store.clone();
            let worker_intent = intent.clone();
            let worker_current = current.clone();
            let worker_next = next.clone();
            let machine = state.machine_id;
            let handle = tokio::runtime::Handle::current();
            let operation = tokio::task::spawn_blocking(move || {
                handle.block_on(async move {
                    match write {
                        Write::Intent => worker
                            .prepare_live_command(machine, run, request, &worker_intent)
                            .await
                            .map(|_| ()),
                        Write::Result => worker
                            .complete_live_command(
                                machine,
                                run,
                                request,
                                &worker_intent.report.monitor_id,
                                &receipt(&worker_intent),
                                None,
                            )
                            .await
                            .map(|_| ()),
                        Write::Projection => worker
                            .save_live_projection(machine, &worker_current, &worker_next)
                            .await
                            .map(|_| ()),
                    }
                })
            });
            entered.recv().await.unwrap();
            let competing_write = sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut *contender)
                .await;
            // Always release the worker, including when exercising the old
            // deferred transaction, which incorrectly lets this writer in.
            release.send(()).unwrap();
            let completed = operation.await.unwrap();
            if competing_write.is_ok() {
                sqlx::query("ROLLBACK")
                    .execute(&mut *contender)
                    .await
                    .unwrap();
            }
            assert!(
                matches!(&competing_write, Err(sqlx::Error::Database(error))
                    if error.code().as_deref() == Some("5")),
                "{write:?} failed to exclude a concurrent catalog writer: {competing_write:?}"
            );
            completed.unwrap();
            let retained = store
                .live_command_record(machine, run, request)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.intent, intent);
            match write {
                Write::Intent => assert_eq!(retained.result, None),
                Write::Result => assert_eq!(retained.result, Some(receipt(&intent))),
                Write::Projection => {
                    assert_eq!(
                        store
                            .live_projection(machine, &run.to_string())
                            .await
                            .unwrap(),
                        Some(current)
                    );
                    assert_eq!(store.machine_state(machine).await.unwrap(), Some(next));
                }
            }
        }
    }

    #[tokio::test]
    async fn pause_intent_survives_close_reopen_and_response_is_immutable() {
        let (dir, store, state, intent) = fixture().await;
        let (run, request) = identities(&intent);
        store
            .prepare_live_command(state.machine_id, run, request, &intent)
            .await
            .unwrap();
        store.close().await;
        let store = Store::open(&dir.path().join("state.db")).await.unwrap();
        let pending = store
            .pending_live_commands(state.machine_id, run, &intent.report.monitor_id)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].intent, intent);
        assert_eq!(pending[0].result, None);
        let mut conflict = intent.clone();
        conflict.command = LiveCommand::GetOperation(GetOperationCommand {
            envelope: intent.command.envelope().clone(),
            operation_id: id(Uuid::new_v4()),
        });
        assert!(store
            .prepare_live_command(state.machine_id, run, request, &conflict)
            .await
            .is_err());
        let result = receipt(&intent);
        store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &result,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .prepare_live_command(state.machine_id, run, request, &intent)
                .await
                .unwrap()
                .result,
            Some(result.clone())
        );
        let altered = LiveCommandResult::rejected(
            LiveCommandKind::Pause,
            LiveRejection::new(
                LiveRejectionReason::InvalidState,
                VmLifecycleState::Paused,
                "changed",
            ),
        );
        assert!(store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &altered,
                None
            )
            .await
            .is_err());
        assert_eq!(
            store
                .live_command_record(state.machine_id, run, request)
                .await
                .unwrap()
                .unwrap()
                .result,
            Some(result)
        );
        assert!(store
            .pending_live_commands(state.machine_id, run, &intent.report.monitor_id)
            .await
            .unwrap()
            .is_empty());
        store.close().await;
    }

    #[tokio::test]
    async fn pause_result_and_current_authority_commit_atomically_and_stop_wins() {
        let (_dir, store, state, intent) = fixture().await;
        let (run, request) = identities(&intent);
        store
            .prepare_live_command(state.machine_id, run, request, &intent)
            .await
            .unwrap();
        let current = paused(&intent, 1);
        let next = crate::machine::live_operations::project_machine_state(state.clone(), &current);
        store.execute_test_sql("CREATE TRIGGER reject_pause_projection BEFORE INSERT ON live_run BEGIN SELECT RAISE(ABORT,'projection failure'); END").await.unwrap();
        assert!(store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &receipt(&intent),
                Some((&current, &next))
            )
            .await
            .is_err());
        assert_eq!(
            store
                .live_command_record(state.machine_id, run, request)
                .await
                .unwrap()
                .unwrap()
                .result,
            None
        );
        assert_eq!(
            store
                .machine_state(state.machine_id)
                .await
                .unwrap()
                .unwrap(),
            state
        );
        store
            .execute_test_sql("DROP TRIGGER reject_pause_projection")
            .await
            .unwrap();
        assert!(store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &receipt(&intent),
                Some((&current, &next))
            )
            .await
            .unwrap());
        let mut stopping = next.clone();
        stopping.status = MachineRuntimeState::Stopping;
        store.save_machine_state(&stopping).await.unwrap();
        let recovered = paused(&intent, 2);
        let late = crate::machine::live_operations::project_machine_state(next, &recovered);
        assert!(!store
            .save_live_projection(state.machine_id, &recovered, &late)
            .await
            .unwrap());
        assert_eq!(
            store
                .machine_state(state.machine_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MachineRuntimeState::Stopping
        );
        assert!(store
            .live_projection(state.machine_id, &run.to_string())
            .await
            .unwrap()
            .is_none());
        store.close().await;
    }

    #[tokio::test]
    async fn pause_old_response_never_overwrites_new_run_or_foreign_monitor() {
        let (_dir, store, state, intent) = fixture().await;
        let (run, request) = identities(&intent);
        store
            .prepare_live_command(state.machine_id, run, request, &intent)
            .await
            .unwrap();
        let current = paused(&intent, 1);
        let next = crate::machine::live_operations::project_machine_state(state.clone(), &current);
        let mut replacement = state.clone();
        replacement.run_id = Some(Uuid::new_v4().to_string());
        replacement.vmm_pid = Some(456);
        store.save_machine_state(&replacement).await.unwrap();
        assert!(!store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &receipt(&intent),
                Some((&current, &next))
            )
            .await
            .unwrap());
        assert_eq!(
            store
                .machine_state(state.machine_id)
                .await
                .unwrap()
                .unwrap(),
            replacement
        );
        assert!(store
            .live_projection(state.machine_id, &run.to_string())
            .await
            .unwrap()
            .is_none());
        store.save_machine_state(&state).await.unwrap();
        store
            .save_live_projection(state.machine_id, &current, &next)
            .await
            .unwrap();
        let mut foreign = current.clone();
        foreign.report.monitor_id = Uuid::new_v4().to_string();
        assert!(store
            .save_live_projection(state.machine_id, &foreign, &next)
            .await
            .is_err());
        store.close().await;
    }

    #[tokio::test]
    async fn pause_terminal_establishment_remains_original_when_recovery_replaces_current_token() {
        let (_dir, store, state, intent) = fixture().await;
        let (run, pause_id) = identities(&intent);
        let original = paused(&intent, 1);
        let token = original
            .lifecycle
            .current_pause
            .as_ref()
            .unwrap()
            .token
            .clone();
        let operation = LiveOperationRecord {
            operation_id: id(pause_id),
            kind: OperationKind::Pause,
            outcome: OperationOutcome::Succeeded {
                pause: PauseEstablished {
                    token,
                    freeze_epoch: NonZeroU64::new(1).unwrap(),
                    guest: GuestFreezeObservation {
                        state: GuestLifecycleState::Frozen,
                        freeze_epoch: NonZeroU64::new(1),
                        workload_roots: vec!["/workloads".into()],
                        observed_frozen_roots: vec!["/workloads".into()],
                        rollback_succeeded: None,
                        failure: None,
                    },
                    capture_eligible: true,
                },
            },
        };
        let mut query = intent.clone();
        let request = Uuid::new_v4();
        let mut envelope = intent.command.envelope().clone();
        envelope.request_id = id(request);
        query.command = LiveCommand::GetOperation(GetOperationCommand {
            envelope,
            operation_id: operation.operation_id.clone(),
        });
        store
            .prepare_live_command(state.machine_id, run, request, &query)
            .await
            .unwrap();
        let result = LiveCommandResult::GetOperation(GetOperationOutcome::Observation {
            observation: OperationObservation {
                operation: operation.clone(),
                state: VmLifecycleState::Paused,
                current_pause: original.lifecycle.current_pause.clone(),
                activity: None,
                capture: None,
            },
        });
        let next = crate::machine::live_operations::project_machine_state(state.clone(), &original);
        store
            .complete_live_command(
                state.machine_id,
                run,
                request,
                &intent.report.monitor_id,
                &result,
                Some((&original, &next)),
            )
            .await
            .unwrap();
        let recovered = paused(&intent, 2);
        let next = crate::machine::live_operations::project_machine_state(next, &recovered);
        store
            .save_live_projection(state.machine_id, &recovered, &next)
            .await
            .unwrap();
        assert_eq!(
            store
                .live_operation(
                    state.machine_id,
                    &run.to_string(),
                    &intent.report.monitor_id,
                    &operation.operation_id
                )
                .await
                .unwrap(),
            Some(operation)
        );
        assert_eq!(
            store
                .live_projection(state.machine_id, &run.to_string())
                .await
                .unwrap()
                .unwrap()
                .lifecycle
                .current_pause
                .unwrap()
                .token
                .generation
                .get(),
            2
        );
        assert_eq!(
            store
                .live_command_record(state.machine_id, run, request)
                .await
                .unwrap()
                .unwrap()
                .result,
            Some(result)
        );
        store.close().await;
    }
}

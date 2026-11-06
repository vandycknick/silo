use std::time::Duration;

use uuid::Uuid;
use vm_spec::lifecycle::{
    CancelOperationCommand, GetOperationCommand, GetOperationOutcome, LiveCommand,
    LiveCommandEnvelope, LiveCommandResult, LiveId, LiveStage, OperationOutcome, PauseCommand,
    PauseOutcome, ResumeCommand, ResumeOutcome, VmLifecycleState,
};
use vm_spec::live::LiveOperation;

use crate::machine::live::{require_live_operation, MachineLiveObservation};
use crate::machine::{Machine, MachineRef};
use crate::store::live_store::{LiveCommandIntent, MachineLifecycle};
use crate::store::models::{MachineConfig, MachineRuntimeState, MachineState};
use crate::store::Store;
use crate::{LibVmError, Runtime};

fn protocol(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveProtocol {
        message: message.into(),
    }
}
fn id(value: &str) -> Result<LiveId, LibVmError> {
    LiveId::parse(value).map_err(protocol)
}
fn uuid(value: &LiveId) -> Result<Uuid, LibVmError> {
    Uuid::parse_str(value.as_str()).map_err(|error| protocol(error.to_string()))
}

pub(crate) fn envelope(
    observation: &MachineLiveObservation,
    request_id: Uuid,
) -> Result<LiveCommandEnvelope, LibVmError> {
    if request_id.is_nil() {
        return Err(protocol("nil lifecycle request identity"));
    }
    Ok(LiveCommandEnvelope {
        machine_id: id(&observation.report().machine_id)?,
        run_id: id(&observation.report().run_id)?,
        request_id: id(&request_id.to_string())?,
    })
}

pub(crate) fn projection(
    observation: &MachineLiveObservation,
) -> Result<MachineLifecycle, LibVmError> {
    let state = observation.state()?;
    let lifecycle = observation.lifecycle()?;
    lifecycle.validate_for(state).map_err(protocol)?;
    if let Some(pause) = &lifecycle.current_pause {
        if pause.token.machine_id.as_str() != observation.report().machine_id
            || pause.token.run_id.as_str() != observation.report().run_id
        {
            return Err(protocol("current pause belongs to another machine/run"));
        }
    }
    Ok(MachineLifecycle {
        report: observation.report().clone(),
        state,
        lifecycle,
        operation: None,
    })
}

pub(crate) fn project_machine_state(
    mut state: MachineState,
    current: &MachineLifecycle,
) -> MachineState {
    state.status = match current.state {
        VmLifecycleState::Starting => MachineRuntimeState::Starting,
        VmLifecycleState::Running => MachineRuntimeState::Running,
        VmLifecycleState::Stopping => MachineRuntimeState::Stopping,
        VmLifecycleState::Stopped => MachineRuntimeState::Stopped,
        VmLifecycleState::Failed | VmLifecycleState::Error => MachineRuntimeState::Error,
        VmLifecycleState::Pausing => MachineRuntimeState::Pausing,
        VmLifecycleState::Paused => MachineRuntimeState::Paused,
        VmLifecycleState::Capturing => MachineRuntimeState::Capturing,
        VmLifecycleState::Restoring => MachineRuntimeState::Restoring,
        VmLifecycleState::Activating => MachineRuntimeState::Activating,
        VmLifecycleState::ActivationFailed => MachineRuntimeState::ActivationFailed,
    };
    state.last_error = current.lifecycle.error.as_ref().map(ToString::to_string);
    state.updated_at = chrono::Utc::now().timestamp();
    state
}

impl Machine {
    /// Submit a caller-chosen identity through the durable manager journal.
    /// Exact retries recover the original response, not a replacement command.
    /// A NEW Capture is only created by [`Machine::submit_capture`], which
    /// registers its reservation and plan first; raw input can only replay it.
    pub async fn live_command(
        &self,
        observation: &MachineLiveObservation,
        command: LiveCommand,
    ) -> Result<LiveCommandResult, LibVmError> {
        if let LiveCommand::Capture(capture) = &command {
            capture.validate_plan().map_err(protocol)?;
        }
        if observation.report().machine_id != Uuid::from(self.machine_id()).to_string() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".into(),
            });
        }
        if command.envelope().machine_id.as_str() != Uuid::from(self.machine_id()).to_string()
            || command.envelope().run_id.as_str() != observation.report().run_id
        {
            return Err(protocol(
                "live command differs from its admission observation",
            ));
        }
        let runtime = self.runtime();
        let store = runtime.native_store()?;
        let e = command.envelope();
        let existing = store
            .live_command_record(self.machine_id(), uuid(&e.run_id)?, uuid(&e.request_id)?)
            .await?;
        if let Some(existing) = &existing {
            if existing.intent.report.monitor_id != observation.report().monitor_id {
                return Err(protocol(
                    "retained lifecycle command belongs to another monitor",
                ));
            }
            if existing.intent.command != command {
                return Ok(LiveCommandResult::rejected(
                    command.kind(),
                    vm_spec::lifecycle::LiveRejection::new(
                        vm_spec::lifecycle::LiveRejectionReason::RequestConflict,
                        observation.state()?,
                        "request identity conflicts with persisted inputs",
                    ),
                ));
            }
            if let Some(result) = &existing.result {
                return Ok(result.clone());
            }
        } else {
            if matches!(command, LiveCommand::Capture(_)) {
                return Err(protocol(
                    "a new capture must be reserved and journaled through submit_capture",
                ));
            }
            if let Some(rejection) = require_new_command(observation, &command)? {
                return Ok(rejection);
            }
        }
        let prepared = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let fresh = runtime.observe_live(&MachineRef::id(config.id)).await?;
            require_same_observation(observation, &fresh)?;
            if existing.is_none() {
                if let Some(rejection) = require_new_command(&fresh, &command)? {
                    return Ok(rejection);
                }
            }
            let intent =
                existing
                    .map(|record| record.intent)
                    .unwrap_or_else(|| LiveCommandIntent {
                        report: observation.report().clone(),
                        command,
                    });
            let e = intent.command.envelope();
            store
                .prepare_live_command(config.id, uuid(&e.run_id)?, uuid(&e.request_id)?, &intent)
                .await?
        };
        if let Some(result) = prepared.result {
            return Ok(result);
        }
        self.send_prepared(prepared.intent).await
    }

    /// Send an already durable intent and persist its exact result. No
    /// transaction or machine lock spans the monitor round trip.
    pub(crate) async fn send_prepared(
        &self,
        intent: LiveCommandIntent,
    ) -> Result<LiveCommandResult, LibVmError> {
        let runtime = self.runtime();
        let store = runtime.native_store()?;
        let result = runtime
            .supervisor()
            .client(self.machine_id())
            .lifecycle(intent.command.clone())
            .await
            .map_err(|error| {
                protocol(format!(
                    "lifecycle outcome uncertain; original request {} retained: {error}",
                    intent.command.envelope().request_id
                ))
            })?;
        let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
        save_result(runtime, &store, &config, &intent, &result).await?;
        Ok(result)
    }

    pub async fn pause_with_request(
        &self,
        observation: &MachineLiveObservation,
        request_id: Uuid,
    ) -> Result<LiveCommandResult, LibVmError> {
        self.live_command(
            observation,
            LiveCommand::Pause(PauseCommand {
                envelope: envelope(observation, request_id)?,
            }),
        )
        .await
    }

    pub async fn resume_with_request(
        &self,
        observation: &MachineLiveObservation,
        request_id: Uuid,
    ) -> Result<LiveCommandResult, LibVmError> {
        let current = observation
            .lifecycle()?
            .current_pause
            .ok_or_else(|| protocol("machine has no current pause authority"))?;
        self.live_command(
            observation,
            LiveCommand::Resume(ResumeCommand {
                envelope: envelope(observation, request_id)?,
                operation_id: current.operation_id,
                token: current.token,
            }),
        )
        .await
    }

    pub async fn get_operation(
        &self,
        observation: &MachineLiveObservation,
        request_id: Uuid,
        operation_id: LiveId,
    ) -> Result<LiveCommandResult, LibVmError> {
        self.live_command(
            observation,
            LiveCommand::GetOperation(GetOperationCommand {
                envelope: envelope(observation, request_id)?,
                operation_id,
            }),
        )
        .await
    }

    pub async fn cancel_operation(
        &self,
        observation: &MachineLiveObservation,
        request_id: Uuid,
        operation_id: LiveId,
    ) -> Result<LiveCommandResult, LibVmError> {
        self.live_command(
            observation,
            LiveCommand::CancelOperation(CancelOperationCommand {
                envelope: envelope(observation, request_id)?,
                operation_id,
            }),
        )
        .await
    }

    pub async fn resume(
        &self,
        observation: &MachineLiveObservation,
    ) -> Result<MachineLifecycle, LibVmError> {
        let pending = self
            .pending_command(observation, vm_spec::lifecycle::LiveCommandKind::Resume)
            .await?;
        let result = if let Some(command) = pending {
            if fenced_failure(observation)? {
                return Err(protocol(
                    "resume outcome uncertain in fenced failure; inspect operation or stop",
                ));
            }
            self.live_command(observation, command).await?
        } else {
            self.resume_with_request(observation, Uuid::new_v4())
                .await?
        };
        match result {
            LiveCommandResult::Resume(ResumeOutcome::Resumed { .. }) => {
                projection(&self.observe_live().await?)
            }
            LiveCommandResult::Resume(ResumeOutcome::Failed { failed }) => Err(protocol(format!(
                "{}; recovered state {}",
                failed.cause, failed.state
            ))),
            result => Err(result_error(&result)),
        }
    }

    pub(crate) async fn pause_and_wait(
        &self,
        observation: &MachineLiveObservation,
    ) -> Result<MachineLifecycle, LibVmError> {
        if observation.report().machine_id != Uuid::from(self.machine_id()).to_string() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".into(),
            });
        }
        observation.require_pause_submission()?;
        let pending = self
            .pending_command(observation, vm_spec::lifecycle::LiveCommandKind::Pause)
            .await?;
        let request_id = pending
            .as_ref()
            .map(|command| uuid(&command.envelope().request_id))
            .transpose()?
            .unwrap_or_else(Uuid::new_v4);
        let operation_id = id(&request_id.to_string())?;
        if pending.is_none() || !fenced_failure(observation)? {
            match self.pause_with_request(observation, request_id).await? {
                LiveCommandResult::Pause(PauseOutcome::Accepted { .. }) => {}
                result => return Err(result_error(&result)),
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let fresh = self.observe_live().await?;
            require_same_observation(observation, &fresh)?;
            match self
                .get_operation(&fresh, Uuid::new_v4(), operation_id.clone())
                .await?
            {
                LiveCommandResult::GetOperation(GetOperationOutcome::Observation {
                    observation: observed,
                }) => match observed.operation.outcome.clone() {
                    OperationOutcome::Succeeded { .. } => {
                        let mut current = projection(&self.observe_live().await?)?;
                        current.operation = Some(observed.operation);
                        return Ok(current);
                    }
                    OperationOutcome::Failed { failure } => {
                        return Err(protocol(failure.to_string()))
                    }
                    OperationOutcome::CaptureSealed { .. } => {
                        return Err(protocol("pause operation returned a capture seal"))
                    }
                    OperationOutcome::InProgress => {}
                },
                result => return Err(result_error(&result)),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(protocol(format!(
                    "pause {operation_id} remains pending; operation retained, not cancelled"
                )));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn pending_command(
        &self,
        observation: &MachineLiveObservation,
        kind: vm_spec::lifecycle::LiveCommandKind,
    ) -> Result<Option<LiveCommand>, LibVmError> {
        if observation.report().machine_id != Uuid::from(self.machine_id()).to_string() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".into(),
            });
        }
        let run = Uuid::parse_str(&observation.report().run_id)
            .map_err(|error| protocol(error.to_string()))?;
        Ok(self
            .runtime()
            .native_store()?
            .pending_live_commands(self.machine_id(), run, &observation.report().monitor_id)
            .await?
            .into_iter()
            .find(|record| record.intent.command.kind() == kind)
            .map(|record| record.intent.command))
    }

    /// Reconcile only retained identities against this generation, then
    /// advance this machine's retained captures (publish valid seals, settle
    /// continuation facts). This never creates a replacement Pause or Capture
    /// and never applies a manager-loss resume policy.
    pub async fn reconcile_live(&self) -> Result<MachineLifecycle, LibVmError> {
        let runtime = self.runtime();
        {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            reconcile(runtime, &config).await?;
        }
        crate::machine::live_capture::reconcile_captures(runtime, Some(self.machine_id())).await?;
        projection(&self.observe_live().await?)
    }
}

fn fenced_failure(observation: &MachineLiveObservation) -> Result<bool, LibVmError> {
    Ok(observation.state()? == VmLifecycleState::Error
        || observation
            .lifecycle()?
            .activity
            .as_ref()
            .is_some_and(|activity| activity.stage == LiveStage::PauseFailed))
}

/// Only NEW Pause and Capture are capability gated. Releasing, observing,
/// cancelling or resuming retained authority never depends on a fresh vector.
fn require_new_command(
    observation: &MachineLiveObservation,
    command: &LiveCommand,
) -> Result<Option<LiveCommandResult>, LibVmError> {
    match command {
        LiveCommand::Pause(_) => require_live_operation(observation, LiveOperation::Pause)?,
        LiveCommand::Capture(_) => require_live_operation(observation, LiveOperation::Capture)?,
        _ => {}
    }
    let state = observation.state()?;
    Ok((!state.admits(command.kind())).then(|| {
        LiveCommandResult::rejected(
            command.kind(),
            vm_spec::lifecycle::LiveRejection::new(
                vm_spec::lifecycle::LiveRejectionReason::InvalidState,
                state,
                "command is not admitted in the observed lifecycle state",
            ),
        )
    }))
}

pub(crate) fn result_error(result: &LiveCommandResult) -> LibVmError {
    protocol(
        result
            .rejection()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unexpected lifecycle command result".into()),
    )
}

pub(crate) fn require_same_observation(
    expected: &MachineLiveObservation,
    fresh: &MachineLiveObservation,
) -> Result<(), LibVmError> {
    let a = expected.report();
    let b = fresh.report();
    if a.machine_id != b.machine_id
        || a.run_id != b.run_id
        || a.monitor_id != b.monitor_id
        || a.backend != b.backend
        || a.lane != b.lane
        || a.topology_revision != b.topology_revision
    {
        return Err(protocol(
            "machine/run/monitor/topology changed since capability admission",
        ));
    }
    Ok(())
}

pub(crate) async fn save_result(
    runtime: &Runtime,
    store: &Store,
    config: &MachineConfig,
    intent: &LiveCommandIntent,
    result: &LiveCommandResult,
) -> Result<(), LibVmError> {
    if result.kind() != intent.command.kind() {
        return Err(protocol("monitor returned another command's response"));
    }
    result.validate().map_err(protocol)?;
    let mut current = match runtime.observe_live(&MachineRef::id(config.id)).await {
        Ok(observation)
            if observation.report().run_id == intent.report.run_id
                && observation.report().monitor_id == intent.report.monitor_id =>
        {
            Some(projection(&observation)?)
        }
        _ => None,
    };
    if let Some(current) = &mut current {
        current.operation = match result {
            LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) => {
                Some(observation.operation.clone())
            }
            LiveCommandResult::CancelOperation(
                vm_spec::lifecycle::CancelOperationOutcome::Completed { completed },
            ) => Some(completed.operation.clone()),
            LiveCommandResult::CancelOperation(
                vm_spec::lifecycle::CancelOperationOutcome::Failed { failed },
            ) => Some(failed.operation.clone()),
            _ => None,
        };
    }
    let state = runtime.machine_state(config.id).await?;
    let next = current
        .as_ref()
        .map(|current| project_machine_state(state, current));
    let e = intent.command.envelope();
    store
        .complete_live_command(
            config.id,
            uuid(&e.run_id)?,
            uuid(&e.request_id)?,
            &intent.report.monitor_id,
            result,
            current.as_ref().zip(next.as_ref()),
        )
        .await?;
    Ok(())
}

/// Called under the existing machine lock. Reconnect never invents a Pause,
/// resumes a user pause, or retries fenced Error / failed-Pausing work.
pub(crate) async fn reconcile(runtime: &Runtime, config: &MachineConfig) -> Result<(), LibVmError> {
    let fresh = runtime.observe_live(&MachineRef::id(config.id)).await?;
    let current = projection(&fresh)?;
    let store = runtime.native_store()?;
    let run =
        Uuid::parse_str(&fresh.report().run_id).map_err(|error| protocol(error.to_string()))?;
    let state = runtime.machine_state(config.id).await?;
    let next = project_machine_state(state, &current);
    store
        .save_live_projection(config.id, &current, &next)
        .await?;
    let fenced = fenced_failure(&fresh)?;
    for retained in store
        .pending_live_commands(config.id, run, &fresh.report().monitor_id)
        .await?
    {
        if retained.intent.report.topology_revision != fresh.report().topology_revision {
            continue;
        }
        if !matches!(retained.intent.command, LiveCommand::GetOperation(_)) {
            let command = LiveCommand::GetOperation(GetOperationCommand {
                envelope: envelope(&fresh, Uuid::new_v4())?,
                operation_id: retained.intent.command.target_operation_id().clone(),
            });
            let intent = LiveCommandIntent {
                report: fresh.report().clone(),
                command,
            };
            let e = intent.command.envelope();
            store
                .prepare_live_command(config.id, uuid(&e.run_id)?, uuid(&e.request_id)?, &intent)
                .await?;
            let result = runtime
                .supervisor()
                .client(config.id)
                .lifecycle(intent.command.clone())
                .await
                .map_err(|error| {
                    protocol(format!("operation reconciliation observation: {error}"))
                })?;
            save_result(runtime, &store, config, &intent, &result).await?;
        }
        let latest = runtime.observe_live(&MachineRef::id(config.id)).await?;
        if (fenced || fenced_failure(&latest)?)
            && !matches!(retained.intent.command, LiveCommand::GetOperation(_))
        {
            continue;
        }
        let result = runtime
            .supervisor()
            .client(config.id)
            .lifecycle(retained.intent.command.clone())
            .await
            .map_err(|error| {
                protocol(format!(
                    "retained lifecycle request reconciliation: {error}"
                ))
            })?;
        save_result(runtime, &store, config, &retained.intent, &result).await?;
    }
    Ok(())
}

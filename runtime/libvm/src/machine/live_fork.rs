//! One authenticated local cut, a durable batch journal and independent launches.
use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vm_spec::capture::Sha256Digest;
use vm_spec::lifecycle::{CaptureResumePolicy, Diagnostic, LiveId};

use crate::machine::live::MachineLiveObservation;
use crate::machine::root_storage::invalid;
use crate::store::MachineStore;
use crate::{GuestPublish, LibVmError, Machine, MachineId, MachineRunId, RestoreHook, Runtime};

pub const DEFAULT_LIVE_FORK_MAX_CHILDREN: NonZeroU32 = NonZeroU32::MIN.saturating_add(15);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveForkOptions {
    pub operation_id: Uuid,
    pub children: Vec<LiveForkChild>,
    pub max_children: NonZeroU32,
    pub resume_policy: CaptureResumePolicy,
    pub policy: vm_spec::lifecycle::CapturePolicy,
    pub dirty_crossover_percent: u8,
}

impl LiveForkOptions {
    fn capture_options(&self) -> crate::LiveSnapshotOptions {
        crate::LiveSnapshotOptions {
            name: None,
            resume_policy: self.resume_policy,
            policy: self.policy,
            dirty_crossover_percent: self.dirty_crossover_percent,
        }
    }

    pub fn validate(&self) -> Result<(), LibVmError> {
        self.capture_options().validate()?;
        let refused = |message: &str| LibVmError::LiveFork {
            operation_id: self.operation_id.to_string(),
            message: message.into(),
        };
        if self.operation_id.is_nil()
            || self.children.is_empty()
            || self.children.len() > self.max_children.get() as usize
        {
            return Err(refused(
                "live fork requires a nonnil operation ID and 1..maxChildren children",
            ));
        }
        let mut names = BTreeSet::new();
        for child in &self.children {
            crate::validate_new_machine_name(&child.name)?;
            if !names.insert(&child.name) {
                return Err(refused("live fork child names must be unique"));
            }
            if let Some(hook) = &child.activation_hook {
                hook.validate().map_err(|error| refused(&error))?;
            }
            forward_spec::validate_forwards(&child.destination.forwards, Some("vsock.sock"))
                .map_err(|error| refused(&error.to_string()))?;
        }
        crate::storage::limits::Resource::MetadataPageBytes
            .check(
                serde_json::to_vec(self)
                    .map_err(|error| invalid(error.to_string()))?
                    .len() as u64,
            )
            .map_err(crate::storage::StorageError::from)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveForkChild {
    pub name: String,
    pub activation_hook: Option<RestoreHook>,
    #[serde(default)]
    pub destination: ForkDestination,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkDestination {
    #[serde(default)]
    pub forwards: Vec<forward_spec::Forward>,
    #[serde(default)]
    pub guest_publish: Option<GuestPublish>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveForkResult {
    pub operation_id: Uuid,
    pub source_machine_id: MachineId,
    pub source_run_id: MachineRunId,
    pub capture_id: LiveId,
    /// Effective continuation policy resolved from source pause ownership at admission.
    pub resume_policy: CaptureResumePolicy,
    pub stage: ForkStage,
    pub cancellation_requested: bool,
    pub capture: ForkCaptureOutcome,
    pub source: ForkSourceOutcome,
    pub children: Vec<ForkChildResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForkStage {
    Admitted,
    Capturing,
    Restoring,
    Settling,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ForkCaptureOutcome {
    Pending,
    Sealed { cut_id: Sha256Digest },
    Failed { diagnostic: Diagnostic },
    Abandoned { diagnostic: Diagnostic },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ForkSourceOutcome {
    Pending,
    Unchanged,
    Resumed,
    Preserved,
    ResumeFailed { diagnostic: Diagnostic },
    Unknown { diagnostic: Diagnostic },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkChildResult {
    pub index: u32,
    pub name: String,
    pub machine_id: MachineId,
    pub run_id: MachineRunId,
    pub outcome: ForkChildOutcome,
    /// Absent until construction has produced a machine record.
    pub durability: Option<crate::MachineDurability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ForkChildOutcome {
    Pending,
    Constructing,
    Activating,
    Running,
    Failed {
        phase: ForkFailurePhase,
        diagnostic: Diagnostic,
    },
    Cancelled,
    Abandoned {
        diagnostic: Diagnostic,
    },
    RecoveryPending {
        diagnostic: Diagnostic,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForkFailurePhase {
    Capture,
    Construction,
    Activation,
    Cleanup,
}

pub(crate) fn diagnostic(message: impl std::fmt::Display) -> Diagnostic {
    Diagnostic::new(message.to_string())
}

/// Destination authority is a projection, never a clone of source host grants.
pub(crate) fn project_destination(
    source: &crate::SnapshotConfiguration,
    destination: &ForkDestination,
) -> Result<crate::SnapshotConfiguration, LibVmError> {
    let mut configuration = source.clone();
    configuration.spec.mounts.clear();
    configuration.spec.forwards = destination.forwards.clone();
    configuration.network = match &source.network {
        crate::store::models::MachineNetworkConfig::None => {
            if destination.guest_publish.is_some() {
                return Err(invalid(
                    "fork cannot add a NIC to a captured no-network machine",
                ));
            }
            crate::store::models::MachineNetworkConfig::None
        }
        crate::store::models::MachineNetworkConfig::Private { .. }
        | crate::store::models::MachineNetworkConfig::Named { .. } => {
            crate::store::models::MachineNetworkConfig::Private {
                policy: None,
                publish: destination.guest_publish.map(|publish| {
                    crate::store::models::GuestPublish {
                        bind: match publish.bind {
                            crate::PublishBind::Loopback => {
                                crate::store::models::PublishBind::Loopback
                            }
                            crate::PublishBind::Any => crate::store::models::PublishBind::Any,
                        },
                    }
                }),
            }
        }
    };
    Ok(configuration)
}

fn fork_error(operation: Uuid, error: impl std::fmt::Display) -> LibVmError {
    LibVmError::LiveFork {
        operation_id: operation.to_string(),
        message: error.to_string(),
    }
}

impl Machine {
    pub async fn fork_live(
        &self,
        observation: &MachineLiveObservation,
        mut options: LiveForkOptions,
    ) -> Result<LiveForkResult, LibVmError> {
        let entered = monotonic_ns()?;
        if observation.report().machine_id != Uuid::from(self.machine_id()).to_string() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".into(),
            });
        }
        options.validate()?;
        options.policy = crate::machine::live_capture::resolve_policy(options.policy, observation);
        if let Some(existing) = self
            .runtime()
            .native_store()?
            .fork_result(options.operation_id)
            .await?
        {
            if self
                .runtime()
                .native_store()?
                .fork_options(options.operation_id)
                .await?
                != options
                || existing.source_machine_id != self.machine_id()
                || existing.source_run_id.as_str() != observation.report().run_id
            {
                return Err(fork_error(
                    options.operation_id,
                    "operation ID conflicts with immutable fork inputs",
                ));
            }
            return Ok(existing);
        }
        self.runtime().require_recoverable_child_scopes()?;
        crate::require_live_operation(observation, vm_spec::live::LiveOperation::Fork)?;
        crate::require_host_live_operation(
            &self.runtime().live_capabilities().await?,
            vm_spec::live::LiveOperation::Restore,
        )?;
        crate::machine::live_capture::admission(observation, options.resume_policy)?;
        let runtime = self.runtime().clone();
        let machine = self.machine_id();
        let observation = observation.clone();
        let operation = options.operation_id;
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            handle.block_on(create_fork(runtime, machine, observation, options, entered))
        })
        .await
        .map_err(|error| fork_error(operation, error))?
        .map_err(|error| fork_error(operation, error))
    }
}

pub(crate) fn monotonic_ns() -> Result<i64, LibVmError> {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .map_err(std::io::Error::from)?;
    now.tv_sec()
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(now.tv_nsec()))
        .ok_or_else(|| invalid("fork clock overflow"))
}

async fn create_fork(
    runtime: Runtime,
    machine: MachineId,
    observation: MachineLiveObservation,
    mut options: LiveForkOptions,
    entered: i64,
) -> Result<LiveForkResult, LibVmError> {
    let store = runtime.native_store()?;
    let operation = options.operation_id;
    let (result, _lease) = {
        let _names = runtime.lock_machine_names().await?;
        let (_lock, config) = runtime.lock_machine_config(machine).await?;
        if let Some(existing) = store.fork_result(operation).await? {
            if store.fork_options(operation).await? != options
                || existing.source_machine_id != machine
                || existing.source_run_id.as_str() != observation.report().run_id
            {
                return Err(fork_error(
                    operation,
                    "operation ID conflicts with immutable fork inputs",
                ));
            }
            return Ok(existing);
        }
        let fresh = runtime
            .observe_live(&crate::MachineRef::id(machine))
            .await?;
        crate::machine::live_operations::require_same_observation(&observation, &fresh)?;
        crate::require_live_operation(&fresh, vm_spec::live::LiveOperation::Fork)?;
        options.policy = crate::machine::live_capture::resolve_policy(options.policy, &fresh);
        crate::machine::live_capture::admission(&fresh, options.resume_policy)?;
        let storage = runtime.machine_storage_record(machine).await?;
        if !config.spec.mounts.is_empty() || !storage.external_requirements.is_empty() {
            return Err(fork_error(
                operation,
                "fork profile cannot inherit host shares or external disk authority",
            ));
        }
        runtime
            .validate_machine_network_config(&config.network)
            .await?;
        let configuration = crate::SnapshotConfiguration::capture(&config)?;
        for child in &options.children {
            let destination = project_destination(&configuration, &child.destination)?;
            runtime
                .validate_machine_network_config(&destination.network)
                .await?;
            runtime.validate_tailscale_vsock(&destination.network, &destination.spec)?;
        }
        store
            .admit_fork(machine, &fresh, &options, Uuid::new_v4())
            .await
            .map_err(|error| fork_error(operation, error))?
    };
    store
        .record_fork_api_entered(operation, entered)
        .await
        .map_err(|error| fork_error(operation, error))?;
    let capture = Uuid::parse_str(result.capture_id.as_str())
        .map_err(|error| fork_error(operation, error))?;
    let source = Machine::new(runtime.clone(), machine);
    if store
        .fork_result(operation)
        .await?
        .is_some_and(|result| result.cancellation_requested)
    {
        settle_unsubmitted(&runtime, operation, true).await?;
        store
            .update_fork(operation, |result| {
                result.capture = ForkCaptureOutcome::Abandoned {
                    diagnostic: diagnostic("cancelled before capture submission"),
                };
                result.source = ForkSourceOutcome::Unchanged;
                result.stage = ForkStage::Finished;
                Ok(())
            })
            .await?;
        return runtime.inspect_fork(operation).await;
    }
    let mut capture_options = options.capture_options();
    capture_options.resume_policy = result.resume_policy;
    match source
        .submit_capture(&observation, capture, capture_options)
        .await
    {
        Ok(vm_spec::lifecycle::LiveCommandResult::Capture(
            vm_spec::lifecycle::CaptureOutcome::Accepted { .. },
        )) => {
            store
                .update_fork(operation, |result| {
                    if matches!(result.capture, ForkCaptureOutcome::Pending) {
                        result.stage = ForkStage::Capturing;
                    }
                    Ok(())
                })
                .await?;
            store
                .fork_event(operation, None, "capture_submitted")
                .await?;
        }
        Ok(result) => {
            fail_capture(
                &runtime,
                operation,
                diagnostic(format!("capture submission refused: {result:?}")),
                true,
            )
            .await?;
            return store
                .fork_result(operation)
                .await?
                .ok_or_else(|| fork_error(operation, "admitted result disappeared"));
        }
        Err(error) => {
            let run = Uuid::parse_str(observation.report().run_id.as_str())
                .map_err(|error| invalid(error.to_string()))?;
            if store
                .live_command_record(machine, run, capture)
                .await?
                .is_none()
            {
                fail_capture(&runtime, operation, diagnostic(&error), true).await?;
                let result = store
                    .fork_result(operation)
                    .await?
                    .ok_or_else(|| fork_error(operation, "admitted result disappeared"))?;
                if !matches!(result.capture, ForkCaptureOutcome::Pending) {
                    return Ok(result);
                }
            }
            // A lost receipt does not prove refusal. Retained capture intent is
            // reconciled by the same ID, never replaced with another capture.
            tracing::warn!(%operation,%error,"fork capture submission retained for reconciliation");
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    let mut launches = tokio::task::JoinSet::new();
    let mut launched = false;
    // Disk authentication from this loop's own seal retention survives Pending
    // iterations until the cut is opened; nothing else may hold it.
    let mut retained = None;
    loop {
        let current = store
            .fork_result(operation)
            .await?
            .ok_or_else(|| fork_error(operation, "fork result disappeared"))?;
        if current.cancellation_requested && !launched {
            cancel_source_capture(&runtime, &current).await?;
        }
        match crate::machine::live_capture::advance(&runtime, machine, capture, &mut retained).await
        {
            Ok(crate::machine::live_capture::CaptureProgress::Abandoned(reason)) => {
                fail_capture(&runtime, operation, diagnostic(reason), false).await?;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%operation,%error,"fork capture reconciliation retains exact ownership");
            }
        }
        if !launched
            && store
                .local_cut(operation)
                .await?
                .is_some_and(|cut| cut.relocated)
        {
            let cut = store.open_local_cut(operation, retained.take()).await?;
            if let Err(error) = store.bind_fork_resources(&cut).await {
                for child in store.fork_children(operation).await? {
                    if matches!(child.result.outcome, ForkChildOutcome::Pending) {
                        store
                            .set_fork_child(
                                operation,
                                child.result.index,
                                ForkChildOutcome::RecoveryPending {
                                    diagnostic: diagnostic(&error),
                                },
                            )
                            .await?;
                    }
                }
                store
                    .update_fork(operation, |result| {
                        result.stage = ForkStage::Settling;
                        Ok(())
                    })
                    .await?;
                settle_source(&runtime, operation).await?;
                return store
                    .fork_result(operation)
                    .await?
                    .ok_or_else(|| fork_error(operation, "admitted result disappeared"));
            }
            let cut = match crate::machine::restore::prepare_fork_restore(&runtime, cut).await {
                Ok(cut) => std::sync::Arc::new(cut),
                Err(error) => {
                    fail_shared_preparation(&store, operation, &error).await?;
                    // No child can be submitted after shared preparation fails.
                    // The normal reconciliation pass retires unused consumers
                    // and budget before settling the parent.
                    launched = true;
                    continue;
                }
            };
            launched = true;
            for child in store.fork_children(operation).await? {
                let current = store
                    .fork_result(operation)
                    .await?
                    .ok_or_else(|| fork_error(operation, "fork result disappeared"))?;
                if current.cancellation_requested {
                    store
                        .set_fork_child(operation, child.result.index, ForkChildOutcome::Cancelled)
                        .await?;
                    continue;
                }
                let child_options = options
                    .children
                    .get(child.result.index as usize)
                    .cloned()
                    .ok_or_else(|| fork_error(operation, "child request index changed"))?;
                let child_runtime = runtime.clone();
                let cut = cut.clone();
                let handle = tokio::runtime::Handle::current();
                launches.spawn_blocking(move || {
                    handle.block_on(async move {
                        let store = child_runtime.native_store()?;
                        let index = child.result.index;
                        let machine = child.result.machine_id;
                        let run = Uuid::parse_str(child.result.run_id.as_str())
                            .map_err(|error| invalid(error.to_string()))?;
                        store
                            .set_fork_child(operation, index, ForkChildOutcome::Constructing)
                            .await?;
                        store
                            .fork_event(operation, Some(index), "constructing")
                            .await?;
                        match crate::machine::restore::restore_reserved_fork_child(
                            &child_runtime,
                            cut,
                            child,
                            child_options,
                        )
                        .await
                        {
                            Ok(_) => {
                                store
                                    .set_fork_child(operation, index, ForkChildOutcome::Running)
                                    .await?;
                                store.fork_event(operation, Some(index), "running").await?;
                            }
                            Err(error) => {
                                store
                                    .record_fork_child_failure(machine, run, &error)
                                    .await?;
                                store
                                    .set_fork_child(
                                        operation,
                                        index,
                                        ForkChildOutcome::RecoveryPending {
                                            diagnostic: diagnostic(error),
                                        },
                                    )
                                    .await?;
                            }
                        }
                        Ok::<(), LibVmError>(())
                    })
                });
            }
        }
        while let Some(completed) = launches.try_join_next() {
            if let Err(error) = completed {
                tracing::warn!(%operation,%error,"fork child task retained for recovery");
            }
        }
        settle_source(&runtime, operation).await?;
        if launches.is_empty() && launched {
            reconcile_children(&runtime, operation, false).await?;
        }
        finish_if_settled(&runtime, operation).await?;
        let result = store
            .fork_result(operation)
            .await?
            .ok_or_else(|| fork_error(operation, "fork result disappeared"))?;
        if launches.is_empty()
            && (result.stage == ForkStage::Finished || tokio::time::Instant::now() >= deadline)
        {
            return Ok(result);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

impl Runtime {
    pub async fn inspect_fork(&self, operation: Uuid) -> Result<LiveForkResult, LibVmError> {
        let store = self.native_store()?;
        let result = store
            .fork_result(operation)
            .await
            .map_err(|error| fork_error(operation, error))?
            .ok_or_else(|| LibVmError::LiveForkNotFound {
                operation_id: operation.to_string(),
            })?;
        if result.stage != ForkStage::Finished
            || result
                .children
                .iter()
                .any(|child| matches!(child.outcome, ForkChildOutcome::RecoveryPending { .. }))
        {
            reconcile_one(self, operation)
                .await
                .map_err(|error| fork_error(operation, error))?;
        }
        store
            .fork_result(operation)
            .await?
            .ok_or_else(|| LibVmError::LiveForkNotFound {
                operation_id: operation.to_string(),
            })
    }

    pub async fn cancel_fork(&self, operation: Uuid) -> Result<LiveForkResult, LibVmError> {
        let store = self.native_store()?;
        let existing =
            store
                .fork_result(operation)
                .await?
                .ok_or_else(|| LibVmError::LiveForkNotFound {
                    operation_id: operation.to_string(),
                })?;
        // Serialize the durable cancellation fence with capture dispatch.
        // A removed source cannot dispatch, but its fork must remain cancellable.
        let source_lock = match self.lock_machine_config(existing.source_machine_id).await {
            Ok((lock, _)) => Some(lock),
            Err(LibVmError::MachineNotFound { .. }) => None,
            Err(error) => return Err(error),
        };
        store
            .update_fork(operation, |result| {
                result.cancellation_requested = true;
                Ok(())
            })
            .await
            .map_err(|error| fork_error(operation, error))?;
        drop(source_lock);
        let result = store
            .fork_result(operation)
            .await?
            .ok_or_else(|| fork_error(operation, "cancelled fork result disappeared"))?;
        cancel_source_capture(self, &result).await?;
        self.inspect_fork(operation).await
    }
}

async fn cancel_source_capture(
    runtime: &Runtime,
    result: &LiveForkResult,
) -> Result<(), LibVmError> {
    if !matches!(result.capture, ForkCaptureOutcome::Pending) {
        return Ok(());
    }
    let capture =
        Uuid::parse_str(result.capture_id.as_str()).map_err(|error| invalid(error.to_string()))?;
    let store = runtime.native_store()?;
    let run = Uuid::parse_str(result.source_run_id.as_str())
        .map_err(|error| invalid(error.to_string()))?;
    if store
        .live_command_record(result.source_machine_id, run, capture)
        .await?
        .is_none()
    {
        return Ok(());
    }
    if let Ok(observation) = runtime
        .observe_live(&crate::MachineRef::id(result.source_machine_id))
        .await
    {
        if observation.report().run_id == result.source_run_id.as_str() {
            let source = Machine::new(runtime.clone(), result.source_machine_id);
            let request = store.fork_cancellation_id(result.operation_id).await?;
            let retained = store
                .live_command_record(result.source_machine_id, run, request)
                .await?;
            let cancellation = match retained {
                Some(retained) => {
                    source
                        .live_command(&observation, retained.intent.command)
                        .await
                }
                None => {
                    source
                        .cancel_operation(&observation, request, result.capture_id.clone())
                        .await
                }
            };
            if let Err(error) = cancellation {
                tracing::warn!(operation=%result.operation_id,%error,"capture cancellation intent remains retained");
            }
        }
    }
    Ok(())
}

async fn settle_unsubmitted(
    runtime: &Runtime,
    operation: Uuid,
    cancelled: bool,
) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    for child in store.fork_children(operation).await? {
        if child.launch_id.is_none() && matches!(child.result.outcome, ForkChildOutcome::Pending) {
            store.set_fork_child(operation,child.result.index,if cancelled { ForkChildOutcome::Cancelled } else { ForkChildOutcome::Abandoned { diagnostic:diagnostic("manager ended before child submission; this reserved run will never be retried") } }).await?;
        }
    }
    store.release_unsubmitted_fork_budget(operation).await
}

async fn fail_capture(
    runtime: &Runtime,
    operation: Uuid,
    cause: Diagnostic,
    unchanged: bool,
) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let current = store
        .fork_result(operation)
        .await?
        .ok_or_else(|| fork_error(operation, "fork disappeared"))?;
    if matches!(current.capture, ForkCaptureOutcome::Sealed { .. }) {
        return Err(fork_error(
            operation,
            "an authenticated cut cannot become capture failure",
        ));
    }
    let capture =
        Uuid::parse_str(current.capture_id.as_str()).map_err(|error| invalid(error.to_string()))?;
    let snapshots = crate::SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let mut source_lock = None;
    let source_exists = runtime
        .machine_config(current.source_machine_id)
        .await?
        .is_some();
    if unchanged && source_exists {
        let (lock, _) = runtime
            .lock_machine_config(current.source_machine_id)
            .await?;
        source_lock = Some(lock);
        let run = Uuid::parse_str(current.source_run_id.as_str())
            .map_err(|error| invalid(error.to_string()))?;
        let intent = store
            .live_command_record(current.source_machine_id, run, capture)
            .await?;
        if intent.as_ref().is_some_and(|intent| {
            !matches!(
                intent.result,
                Some(vm_spec::lifecycle::LiveCommandResult::Capture(
                    vm_spec::lifecycle::CaptureOutcome::Rejected { .. }
                ))
            )
        }) {
            return Ok(());
        }
    }
    store
        .update_fork(operation, |result| {
            result.capture = if unchanged && result.cancellation_requested {
                ForkCaptureOutcome::Abandoned {
                    diagnostic: cause.clone(),
                }
            } else {
                ForkCaptureOutcome::Failed {
                    diagnostic: cause.clone(),
                }
            };
            result.stage = ForkStage::Settling;
            if unchanged && matches!(result.source, ForkSourceOutcome::Pending) {
                result.source = if source_exists {
                    ForkSourceOutcome::Unchanged
                } else {
                    ForkSourceOutcome::Unknown {
                        diagnostic: diagnostic("source ended without a retained capture admission"),
                    }
                };
            }
            Ok(())
        })
        .await?;
    if unchanged {
        if let Some(record) = snapshots.capture_reservation(capture).await? {
            if matches!(
                record.state,
                crate::store::snapshot_store::CaptureState::Reserved
                    | crate::store::snapshot_store::CaptureState::Abandoned
            ) {
                snapshots.abandon_capture(capture).await?;
            }
        }
    }
    drop(source_lock);
    for child in &current.children {
        if matches!(child.outcome, ForkChildOutcome::Pending) {
            let outcome = if current.cancellation_requested {
                ForkChildOutcome::Cancelled
            } else {
                ForkChildOutcome::Failed {
                    phase: ForkFailurePhase::Capture,
                    diagnostic: cause.clone(),
                }
            };
            store
                .set_fork_child(operation, child.index, outcome)
                .await?;
        }
    }
    settle_source(runtime, operation).await?;
    store.release_unsubmitted_fork_budget(operation).await?;
    finish_if_settled(runtime, operation).await
}

pub(crate) fn source_outcome(
    outcome: &crate::store::snapshot_store::CaptureSourceOutcome,
) -> ForkSourceOutcome {
    use crate::store::snapshot_store::CaptureSourceOutcome;
    use vm_spec::capture::CaptureContinuation;
    match outcome {
        CaptureSourceOutcome::Known { record } => match record.source_outcome {
            vm_spec::capture::CaptureSourceOutcome::Resumed => ForkSourceOutcome::Resumed,
            vm_spec::capture::CaptureSourceOutcome::Preserved => ForkSourceOutcome::Preserved,
            vm_spec::capture::CaptureSourceOutcome::ResumeFailed => {
                ForkSourceOutcome::ResumeFailed {
                    diagnostic: record
                        .error
                        .clone()
                        .unwrap_or_else(|| diagnostic("source resume failed")),
                }
            }
        },
        CaptureSourceOutcome::Observed { continuation } => match continuation {
            CaptureContinuation::Pending => ForkSourceOutcome::Pending,
            CaptureContinuation::Unchanged => ForkSourceOutcome::Unchanged,
            CaptureContinuation::Resumed { .. } => ForkSourceOutcome::Resumed,
            CaptureContinuation::Preserved { .. } => ForkSourceOutcome::Preserved,
            CaptureContinuation::ResumeFailed { failure, .. } => ForkSourceOutcome::ResumeFailed {
                diagnostic: diagnostic(failure),
            },
        },
        CaptureSourceOutcome::Unknown => ForkSourceOutcome::Unknown {
            diagnostic: diagnostic("exact source generation ended without a continuation receipt"),
        },
    }
}

async fn settle_source(runtime: &Runtime, operation: Uuid) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let result = store
        .fork_result(operation)
        .await?
        .ok_or_else(|| fork_error(operation, "fork disappeared"))?;
    if !matches!(result.source, ForkSourceOutcome::Pending) {
        return Ok(());
    }
    let snapshots = crate::SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let capture =
        Uuid::parse_str(result.capture_id.as_str()).map_err(|error| invalid(error.to_string()))?;
    if let Some(record) = snapshots.capture_reservation(capture).await? {
        if let Some(outcome) = &record.source_outcome {
            let outcome = source_outcome(outcome);
            store
                .update_fork(operation, |result| {
                    result.source = outcome;
                    Ok(())
                })
                .await?;
            store.fork_event(operation, None, "source_settled").await?;
        } else if matches!(
            record.state,
            crate::store::snapshot_store::CaptureState::Abandoned
        ) {
            // Abandonment follows terminal continuation or positive run death.
            store
                .update_fork(operation, |result| {
                    result.source = ForkSourceOutcome::Unknown {
                        diagnostic: diagnostic(
                            "capture generation retired without a retained continuation",
                        ),
                    };
                    Ok(())
                })
                .await?;
            store.fork_event(operation, None, "source_settled").await?;
        }
    }
    Ok(())
}

/// Shared preparation failed before any child launch could be submitted.
pub(crate) async fn fail_shared_preparation(
    store: &crate::store::Store,
    operation: Uuid,
    error: &LibVmError,
) -> Result<(), LibVmError> {
    for child in store.fork_children(operation).await? {
        if child.launch_id.is_none() && matches!(child.result.outcome, ForkChildOutcome::Pending) {
            store
                .set_fork_child(
                    operation,
                    child.result.index,
                    ForkChildOutcome::Failed {
                        phase: ForkFailurePhase::Construction,
                        diagnostic: diagnostic(error),
                    },
                )
                .await?;
        }
    }
    Ok(())
}

async fn reconcile_children(
    runtime: &Runtime,
    operation: Uuid,
    abandon: bool,
) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir())?;
    if abandon {
        // Recovery owns the parent exclusively. A separate consumer lease can
        // still belong to a detached worker, so prove it ended before allowing
        // its reserved import to be collected.
        for child in store.fork_children(operation).await? {
            if child.launch_id.is_some() || child.submitted {
                continue;
            }
            if !store
                .fork_child_storage_operations_retained(child.consumer_id, None)
                .await?
            {
                continue;
            }
            let Some(_consumer) = pool.try_exclusive_lease(child.consumer_id)? else {
                continue;
            };
            let holder = crate::supervisor::storage_holder::read(
                &runtime
                    .machine_paths(child.result.machine_id)
                    .vmm_storage_holder_path(),
            )?;
            if holder
                .as_ref()
                .map(crate::supervisor::storage_holder::all_terminal)
                .transpose()?
                .is_some_and(|terminal| !terminal)
            {
                continue;
            }
            store
                .release_abandoned_fork_name(operation, child.result.index)
                .await?;
        }
    }
    if let Err(error) = store.retire_abandoned_storage_operations(&pool).await {
        tracing::warn!(%operation,%error,"fork cleanup retains its exact journal owners");
        for child in store.fork_children(operation).await? {
            if matches!(child.result.outcome, ForkChildOutcome::Running) {
                continue;
            }
            let retained = store
                .fork_child_storage_operations_retained(child.consumer_id, child.launch_id)
                .await?;
            if retained {
                store
                    .set_fork_child(
                        operation,
                        child.result.index,
                        ForkChildOutcome::RecoveryPending {
                            diagnostic: diagnostic(&error),
                        },
                    )
                    .await?;
            }
        }
    }
    let parent = store
        .fork_result(operation)
        .await?
        .ok_or_else(|| fork_error(operation, "fork disappeared"))?;
    for child in store.fork_children(operation).await? {
        if matches!(
            child.result.outcome,
            ForkChildOutcome::Running
                | ForkChildOutcome::Cancelled
                | ForkChildOutcome::Abandoned { .. }
                | ForkChildOutcome::Failed { .. }
        ) {
            continue;
        }
        let holder = crate::supervisor::storage_holder::read(
            &runtime
                .machine_paths(child.result.machine_id)
                .vmm_storage_holder_path(),
        )?;
        let holder_active = holder
            .as_ref()
            .map(crate::supervisor::storage_holder::all_terminal)
            .transpose()?
            .is_some_and(|terminal| !terminal);
        if child.launch_id.is_none() {
            let indexed = store
                .launch_storage_operations(child.result.machine_id)
                .await?
                .iter()
                .any(|run| run.run_id.to_string() == child.result.run_id.as_str());
            let retained = store
                .fork_child_storage_operations_retained(child.consumer_id, child.launch_id)
                .await?;
            if indexed || holder_active || retained {
                store
                    .set_fork_child(
                        operation,
                        child.result.index,
                        ForkChildOutcome::RecoveryPending {
                            diagnostic: diagnostic(
                                "an unlinked exact generation or holder still owns execution",
                            ),
                        },
                    )
                    .await?;
                continue;
            }
            if abandon || !matches!(child.result.outcome, ForkChildOutcome::Pending) {
                let outcome = if let Some(failure) = &child.failure {
                    failure.outcome()
                } else if parent.cancellation_requested {
                    ForkChildOutcome::Cancelled
                } else if !abandon {
                    let cause = match &child.result.outcome {
                        ForkChildOutcome::RecoveryPending { diagnostic } => diagnostic.clone(),
                        _ => diagnostic("child construction did not complete"),
                    };
                    ForkChildOutcome::Failed {
                        phase: ForkFailurePhase::Construction,
                        diagnostic: cause,
                    }
                } else {
                    ForkChildOutcome::Abandoned {
                        diagnostic: diagnostic(
                            "construction was never submitted; reserved identities are retired",
                        ),
                    }
                };
                store
                    .set_fork_child(operation, child.result.index, outcome)
                    .await?;
            }
            continue;
        }
        let Some(config) = runtime.machine_config(child.result.machine_id).await? else {
            let retained = store
                .fork_child_storage_operations_retained(child.consumer_id, child.launch_id)
                .await?;
            store
                .set_fork_child(
                    operation,
                    child.result.index,
                    if retained || holder_active {
                        ForkChildOutcome::RecoveryPending {
                            diagnostic: diagnostic(
                                "retained generation has no observable machine configuration",
                            ),
                        }
                    } else if let Some(failure) = &child.failure {
                        failure.outcome()
                    } else {
                        ForkChildOutcome::Abandoned {
                            diagnostic: diagnostic(
                                "exact generation positively retired without a Running receipt",
                            ),
                        }
                    },
                )
                .await?;
            continue;
        };
        let (_lock, current) = runtime.lock_machine_config(config.id).await?;
        if let Err(error) = runtime.reconcile_machine_runtime_locked(&current).await {
            store
                .set_fork_child(
                    operation,
                    child.result.index,
                    ForkChildOutcome::RecoveryPending {
                        diagnostic: diagnostic(error),
                    },
                )
                .await?;
            continue;
        }
        let state = runtime.machine_state(config.id).await?;
        let exact = state.run_id.as_deref() == Some(child.result.run_id.as_str());
        let retained = store
            .fork_child_storage_operations_retained(child.consumer_id, child.launch_id)
            .await?;
        let outcome = if exact && state.status == crate::store::models::MachineRuntimeState::Running
        {
            store
                .fork_event(operation, Some(child.result.index), "running")
                .await?;
            ForkChildOutcome::Running
        } else if exact && (state.status.is_live() || state.vmm_pid.is_some()) {
            ForkChildOutcome::RecoveryPending {
                diagnostic: diagnostic(
                    "exact submitted generation still owns activation or cleanup",
                ),
            }
        } else if retained {
            ForkChildOutcome::RecoveryPending {
                diagnostic: diagnostic("exact child cleanup still retains generation ownership"),
            }
        } else {
            if let Some(failure) = &child.failure {
                failure.outcome()
            } else if parent.cancellation_requested && !child.submitted {
                ForkChildOutcome::Cancelled
            } else {
                ForkChildOutcome::Failed {
                    phase: ForkFailurePhase::Activation,
                    diagnostic: diagnostic(
                        "exact child generation ended without authenticated Running completion",
                    ),
                }
            }
        };
        store
            .set_fork_child(operation, child.result.index, outcome)
            .await?;
    }
    if let Err(error) = store.release_unsubmitted_fork_budget(operation).await {
        tracing::warn!(%operation,%error,"fork budget reductions remain conservative");
    }
    Ok(())
}

async fn finish_if_settled(runtime: &Runtime, operation: Uuid) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let result = store
        .fork_result(operation)
        .await?
        .ok_or_else(|| fork_error(operation, "fork disappeared"))?;
    let children_settled = result.children.iter().all(|child| {
        !matches!(
            child.outcome,
            ForkChildOutcome::Pending
                | ForkChildOutcome::Constructing
                | ForkChildOutcome::Activating
        )
    });
    let snapshots = crate::SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    let capture =
        Uuid::parse_str(result.capture_id.as_str()).map_err(|error| invalid(error.to_string()))?;
    let release_settled = snapshots
        .capture_reservation(capture)
        .await?
        .is_none_or(|capture| {
            matches!(
                capture.state,
                crate::store::snapshot_store::CaptureState::ReleasedLocal { .. }
                    | crate::store::snapshot_store::CaptureState::Released { .. }
                    | crate::store::snapshot_store::CaptureState::Abandoned
            )
        });
    if children_settled {
        if let Err(error) = store.reconcile_restore_budget().await {
            tracing::warn!(%operation,%error,"fork retains pending budget publication");
            store
                .update_fork(operation, |result| {
                    result.stage = ForkStage::Settling;
                    Ok(())
                })
                .await?;
            return Ok(());
        }
    }
    if children_settled
        && release_settled
        && !matches!(result.capture, ForkCaptureOutcome::Pending)
        && !matches!(result.source, ForkSourceOutcome::Pending)
    {
        store
            .update_fork(operation, |result| {
                result.stage = ForkStage::Finished;
                Ok(())
            })
            .await?;
        store.fork_event(operation, None, "finished").await?;
    } else if children_settled {
        store
            .update_fork(operation, |result| {
                result.stage = ForkStage::Settling;
                Ok(())
            })
            .await?;
    }
    Ok(())
}

async fn reconcile_one(runtime: &Runtime, operation: Uuid) -> Result<(), LibVmError> {
    let store = runtime.native_store()?;
    let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir())?;
    let Some(_owner) = pool.try_exclusive_lease(operation)? else {
        return Ok(());
    };
    store.validate_fork_lease(operation, &_owner).await?;
    let result = store
        .fork_result(operation)
        .await?
        .ok_or_else(|| fork_error(operation, "fork disappeared"))?;
    let capture =
        Uuid::parse_str(result.capture_id.as_str()).map_err(|error| invalid(error.to_string()))?;
    let snapshots = crate::SnapshotStore::from_store(std::sync::Arc::new(store.clone()));
    if snapshots.capture_reservation(capture).await?.is_some() {
        // Recovery settles children; it never opens the cut, so any disk
        // authentication retained here is released immediately.
        match crate::machine::live_capture::advance(
            runtime,
            result.source_machine_id,
            capture,
            &mut None,
        )
        .await
        {
            Ok(crate::machine::live_capture::CaptureProgress::Abandoned(reason)) => {
                fail_capture(runtime, operation, diagnostic(reason), false).await?
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%operation,%error,"fork recovery retains capture ownership")
            }
        }
    } else if matches!(result.capture, ForkCaptureOutcome::Pending) {
        fail_capture(
            runtime,
            operation,
            diagnostic("manager ended before capture admission completed"),
            true,
        )
        .await?;
    }
    reconcile_children(runtime, operation, true).await?;
    settle_unsubmitted(runtime, operation, result.cancellation_requested).await?;
    settle_source(runtime, operation).await?;
    finish_if_settled(runtime, operation).await
}

pub(crate) async fn reconcile_forks(runtime: &Runtime) -> Result<(), LibVmError> {
    let Some(store) = runtime.optional_native_store() else {
        return Ok(());
    };
    let operations = store.forks_requiring_reconciliation().await?;
    for operation in operations {
        let operation = Uuid::parse_str(&operation).map_err(|error| invalid(error.to_string()))?;
        if let Err(error) = reconcile_one(runtime, operation).await {
            tracing::warn!(%operation,%error,"fork recovery retains uncertain roots and charges");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::machine::live_fork::{project_destination, ForkDestination};

    #[test]
    fn fork_capture_request_has_no_checkpoint_alias() {
        let options = crate::store::fork::tests::options(&["child"]);
        let capture = options.capture_options();
        assert_eq!(capture.name, None);
        assert_eq!(capture.resume_policy, options.resume_policy);
        assert_eq!(capture.policy, options.policy);
        assert_eq!(
            capture.dirty_crossover_percent,
            options.dirty_crossover_percent
        );
    }

    #[test]
    fn fork_options_validate_default_limit_duplicates_and_explicit_larger_batches() {
        let mut options = crate::store::fork::tests::options(&["child"]);
        options.validate().unwrap();
        options.operation_id = uuid::Uuid::nil();
        assert!(options.validate().is_err());
        options.operation_id = uuid::Uuid::new_v4();
        options.children.clear();
        assert!(options.validate().is_err());
        options.children = crate::store::fork::tests::options(&["same", "same"]).children;
        assert!(options.validate().is_err());
        let child = crate::store::fork::tests::options(&["child"])
            .children
            .remove(0);
        options.children = (0..17)
            .map(|index| {
                let mut child = child.clone();
                child.name = format!("child-{index}");
                child
            })
            .collect();
        assert!(options.validate().is_err());
        options.max_children = std::num::NonZeroU32::new(17).unwrap();
        options.validate().unwrap();
    }

    fn configuration() -> crate::SnapshotConfiguration {
        crate::SnapshotConfiguration {
            secret_scope: crate::SecretScopePolicy::default(),
            spec: vm_spec::VmSpec::current(),
            retention: crate::MachineRetention::Persistent,
            process: crate::ProcessConfig::default(),
            template_name: None,
            agent_mode: None,
            guest: crate::MachineGuestConfig::default(),
            labels: Default::default(),
            metadata: Default::default(),
            network: crate::store::models::MachineNetworkConfig::Private {
                policy: None,
                publish: Some(crate::store::models::GuestPublish {
                    bind: crate::store::models::PublishBind::Any,
                }),
            },
        }
    }

    #[test]
    fn fork_destination_strips_host_grants_without_changing_guest_network_shape() {
        use crate::store::models::MachineNetworkConfig;
        let mut source = configuration();
        source.spec.mounts.push(vm_spec::Mount {
            source: "/host/private".into(),
            tag: "/private".into(),
            read_only: true,
        });
        source.spec.forwards.push(forward_spec::Forward::new(
            "host:tcp:8080".parse().unwrap(),
            "guest:tcp:80".parse().unwrap(),
        ));
        let destination = project_destination(&source, &ForkDestination::default()).unwrap();
        assert!(destination.spec.mounts.is_empty());
        assert!(destination.spec.forwards.is_empty());
        assert_eq!(
            destination.network,
            MachineNetworkConfig::Private {
                policy: None,
                publish: None
            }
        );
        assert!(
            !source.spec.mounts.is_empty(),
            "projection never edits source authority"
        );
        source.network = MachineNetworkConfig::Named {
            name: "source-network".into(),
        };
        assert_eq!(
            project_destination(&source, &ForkDestination::default())
                .unwrap()
                .network,
            MachineNetworkConfig::Private {
                policy: None,
                publish: None
            }
        );
        source.network = MachineNetworkConfig::None;
        let explicit = ForkDestination {
            forwards: Vec::new(),
            guest_publish: Some(crate::GuestPublish {
                bind: crate::PublishBind::Loopback,
            }),
        };
        assert!(
            project_destination(&source, &explicit).is_err(),
            "destination authority cannot add an uncaptured NIC"
        );
        assert_eq!(
            project_destination(&source, &ForkDestination::default())
                .unwrap()
                .network,
            MachineNetworkConfig::None
        );
    }
}

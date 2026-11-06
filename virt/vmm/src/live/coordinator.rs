//! One run-owned coordinator for ADR 0021 Pause/Resume/Cancel and Capture.
//! It owns the public state projection and ordering; the guest owns workload
//! freeze/thaw and the worker owns native pause and capture authority. States
//! are published only from positive barriers, never from transport success.
//!
//! ```text
//!  Running ─Pause─► Pausing[drain → freeze(e) → native pause] ─token─► Paused
//!     ▲                 │ freeze fails: rollback thaw + readiness ─► Running | Error
//!     │                 │ native fails: Pausing[pause-failed] ─Cancel─► rollback ─► thaw ─► Running | Error
//!     │
//!  Paused ─Resume─► Pausing[native ClockOnly → handshake → thaw(e) → readiness] ─► Running
//!                       │ thaw lost: freeze(e+1) → native pause ─► Paused (new token) | Error
//!
//!  Running|Paused ─Capture─► Capturing[see `capture`] ─► Running | Paused | Error
//! ```
//!
//! Stop closes native mutator submission, then seals the gate and the
//! journal: no later native mutator is enqueued and no continuation publishes.
#[path = "capture.rs"]
pub(crate) mod capture;

use std::future::Future;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use protocol::v1::{
    AgentStatus, ExpectedGuestIdentity, FreezeRef, FreezeWorkloadsRequest, GetAgentStatusRequest,
    GuestLifecycleStatus, ThawRequest,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vm_spec::lifecycle::{
    CancelCompleted, CancelFailed, CancelOperationOutcome, CurrentPause, Diagnostic,
    GuestFreezeObservation, GuestLifecycleState, LiveActivity, LiveCommand, LiveCommandKind,
    LiveCommandResult, LiveFailure, LiveFailureCode, LiveId, LiveLifecycle, LiveRejectionReason,
    LiveStage, OperationOutcome, PauseEstablished, PauseOwner, PauseToken, ResumeCompleted,
    ResumeFailed, ResumeOutcome, VmLifecycleState,
};
use vm_spec::live::{
    LiveAvailability, LiveCapability, LiveDeviceSubject, LiveOperation, LiveOperationUnsupported,
    LiveReasonCode, LiveUnsupportedReason,
};

use crate::live::gate::{DrainError, LiveGate};
use crate::live::journal::{
    AdmissionView, Admitted, Answer, Eligibility, Journal, Phase, ResultReceiver,
};
use crate::state::{InstanceStore, LiveSnapshot, LiveTransition, ReadyAgentIdentity, StoreError};
use crate::virt::lifecycle::{
    BlockBacking, CommandOutcome, CommandState, ControlObservation, InventoryObservation,
    LifecycleCommand, LifecycleError, LifecycleRejection, LifecycleRequest, LifecycleUncertainty,
    NativeControl, NativeFailure, NativePauseGeneration, ObservedClockProfile, PausePurpose,
    ProviderDevice, ResumeStage, VirtioKind,
};
use crate::virt::VirtualMachine;

/// Guest lifecycle RPC deadline (the agent's own 1..=5000 ms bound).
const GUEST_DEADLINE_MS: u32 = 5000;
const RETRY_DELAY: Duration = Duration::from_millis(200);
const NATIVE_TRANSPORT_RETRIES: u32 = 3;

/// Bounded stage budgets. Operation deadlines are fixed at stage entry and
/// never renewed by retries or suspended by a pause.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LiveTimeouts {
    pub(crate) drain: Duration,
    pub(crate) guest_stage: Duration,
    pub(crate) native: Duration,
    pub(crate) handshake: Duration,
    pub(crate) readiness: Duration,
}

impl Default for LiveTimeouts {
    fn default() -> Self {
        Self {
            drain: Duration::from_secs(10),
            guest_stage: Duration::from_secs(15),
            native: Duration::from_secs(30),
            handshake: Duration::from_secs(30),
            readiness: Duration::from_secs(60),
        }
    }
}

/// How stop must terminate the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopMode {
    /// Running and idle: the existing orderly guest shutdown applies.
    Graceful,
    /// Held by a live lifecycle (paused, fenced, frozen or busy): terminate
    /// through the backend owner; never resume or thaw to stop.
    Terminate,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LiveError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("live command result was abandoned")]
    Abandoned,
}

struct Inner {
    journal: Journal,
    /// Identity existing sessions stay bound to while the lifecycle holds
    /// the machine; also the exact identity every guest call expects.
    held: Option<ReadyAgentIdentity>,
    /// Native execution is positively parked: set by an established (or
    /// recovered, or retained) native pause and cleared only by a positive
    /// native release or a terminal non-paused outcome. Every projection
    /// carries it, so agent staleness stays suspended through ResumeNative.
    parked: bool,
}

pub(crate) struct LiveCoordinator {
    machine_uuid: Uuid,
    run_uuid: Uuid,
    inner: Mutex<Inner>,
    store: Arc<InstanceStore>,
    machine: VirtualMachine,
    gate: Arc<LiveGate>,
    stop: CancellationToken,
    timeouts: LiveTimeouts,
    /// Present when this run can bind capture plans.
    capture: Option<Arc<crate::live::coordinator::capture::CaptureContext>>,
}

/// Why a guest call produced no positive acknowledgement.
enum GuestError {
    /// The guest processed and refused, or reported a non-positive state.
    Refused(LiveFailure),
    /// No definitive answer before the stage deadline.
    Unknown(LiveFailure),
    Stopped,
}

#[derive(Clone, Copy)]
enum StatusBarrier {
    ResumeHandshake,
    Readiness,
}

impl StatusBarrier {
    fn stage(self) -> LiveStage {
        match self {
            Self::ResumeHandshake => LiveStage::ResumeHandshake,
            Self::Readiness => LiveStage::Readiness,
        }
    }

    fn failure(self, message: impl Into<String>) -> LiveFailure {
        let code = match self {
            Self::ResumeHandshake => LiveFailureCode::HandshakeFailed,
            Self::Readiness => LiveFailureCode::ReadinessFailed,
        };
        failure(code, self.stage(), message)
    }
}

/// Outcome of continuing a natively released source to Running.
enum Continued {
    Running,
    /// The thaw was lost and recovery established NEW user authority; it is
    /// not yet published.
    Recovered {
        current: CurrentPause,
        cause: LiveFailure,
    },
    Failed {
        cause: LiveFailure,
        recovery: Option<LiveFailure>,
    },
    Stopped,
}

enum NativeError {
    Rejected(LifecycleRejection),
    WorkerLost(String),
    Uncertain(String),
    Unsupported(String),
    Stopped,
}

impl NativeError {
    fn describe(&self) -> String {
        match self {
            Self::Rejected(rejection) => format!("native rejected: {rejection}"),
            Self::WorkerLost(detail) => format!("worker lost: {detail}"),
            Self::Uncertain(detail) => format!("native completion unknown: {detail}"),
            Self::Unsupported(detail) => format!("native lifecycle unsupported: {detail}"),
            Self::Stopped => "monitor is stopping".into(),
        }
    }

    fn code(&self, otherwise: LiveFailureCode) -> LiveFailureCode {
        match self {
            Self::WorkerLost(_) => LiveFailureCode::WorkerLost,
            Self::Uncertain(_) => LiveFailureCode::NativeUncertain,
            Self::Stopped => LiveFailureCode::Stopped,
            Self::Rejected(_) | Self::Unsupported(_) => otherwise,
        }
    }
}

fn wire_uuid(id: &LiveId) -> Uuid {
    // LiveId is validated canonical; a nil fallback is refused by every peer.
    Uuid::parse_str(id.as_str()).unwrap_or(Uuid::nil())
}

fn failure(code: LiveFailureCode, stage: LiveStage, message: impl Into<String>) -> LiveFailure {
    LiveFailure::new(code, stage, message)
}

fn native_detail(failure: &NativeFailure) -> String {
    failure.to_string()
}

fn transport_code(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Cancelled
            | tonic::Code::Unknown
            | tonic::Code::Aborted
            | tonic::Code::ResourceExhausted
    )
}

pub(crate) fn guest_observation(
    status: &GuestLifecycleStatus,
) -> Result<GuestFreezeObservation, String> {
    let state = protocol::v1::GuestLifecycleState::try_from(status.state)
        .map_err(|_| "unknown guest lifecycle state".to_string())
        .and_then(GuestLifecycleState::try_from)?;
    let observation = GuestFreezeObservation {
        state,
        freeze_epoch: status
            .freeze_ref
            .as_ref()
            .and_then(|reference| reference.freeze_epoch)
            .and_then(NonZeroU64::new),
        workload_roots: status.workload_roots.clone(),
        observed_frozen_roots: status.observed_frozen_roots.clone(),
        rollback_succeeded: status.rollback_succeeded,
        failure: status.failure.clone().map(Diagnostic::new),
    };
    observation.validate()?;
    Ok(observation)
}

/// A unary response is proof only for the held source identity.
/// Keep the full envelope on the ordinary observation path, which also checks
/// agent-version continuity and does not grant readiness while fenced.
fn observe_status_barrier(
    store: &InstanceStore,
    identity: &ReadyAgentIdentity,
    status: AgentStatus,
    barrier: StatusBarrier,
) -> Result<(), GuestError> {
    let invalid = |message: String| GuestError::Refused(barrier.failure(message));
    let returned = status
        .identity
        .as_ref()
        .ok_or_else(|| invalid("guest status has no identity".into()))?;
    let parse = |value: Option<&str>| {
        value
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| invalid("guest status identity has a missing or invalid UUID".into()))
    };
    let observed = ReadyAgentIdentity {
        instance_id: parse(returned.instance_id.as_deref())?,
        boot_id: parse(returned.boot_id.as_deref())?,
    };
    if &observed != identity {
        return Err(GuestError::Refused(failure(
            LiveFailureCode::GuestIdentityMismatch,
            barrier.stage(),
            "guest agent identity changed across a source resume",
        )));
    }
    store
        .observe_status(status, crate::guest::STATUS_FRESHNESS)
        .map_err(|error| invalid(error.to_string()))
}

/// Native provider inventory admission: every live device must be a
/// classified virtio provider, every block provider Raw-backed or a
/// read-only VMDK (the flat lower, captured by identity). A capture
/// additionally refuses the devices ADR 0021 names, before any freeze.
pub(crate) fn inventory_rejection(
    control: &ControlObservation,
    inventory: Option<&InventoryObservation>,
    capture: bool,
) -> Option<LiveDeviceSubject> {
    let profile = |profile: &str| {
        Some(LiveDeviceSubject::GuestProfile {
            profile: profile.to_string(),
        })
    };
    let expected = if capture {
        // A capture runs on a Running source or borrows an exact user pause.
        matches!(
            control,
            ControlObservation::Observed {
                control: NativeControl::Running | NativeControl::Paused { .. }
            }
        )
    } else {
        matches!(
            control,
            ControlObservation::Observed {
                control: NativeControl::Running
            }
        )
    };
    if !expected {
        return profile("native-control-not-running");
    }
    let Some(InventoryObservation::Observed { providers, .. }) = inventory else {
        return profile("native-provider-inventory-unavailable");
    };
    for provider in providers {
        match &provider.device {
            ProviderDevice::Unrecognized { .. }
            | ProviderDevice::Virtio {
                kind: VirtioKind::Other,
                ..
            } => return profile("native-provider-unrecognized"),
            ProviderDevice::Virtio {
                kind: VirtioKind::Block,
                ..
            } => {
                let admitted = match provider.block_backing {
                    Some(BlockBacking::Raw) => true,
                    Some(BlockBacking::Vmdk) => provider.block_read_only == Some(true),
                    None => false,
                };
                if !admitted {
                    return profile("native-block-backing-unsupported");
                }
            }
            ProviderDevice::Virtio {
                kind: VirtioKind::Fs,
                ..
            } if capture => return Some(LiveDeviceSubject::Virtiofs),
            ProviderDevice::Virtio {
                kind: VirtioKind::Gpu,
                ..
            } if capture => return Some(LiveDeviceSubject::Gpu),
            ProviderDevice::Virtio {
                kind: VirtioKind::Input,
                ..
            } if capture => return profile("native-input-device"),
            ProviderDevice::Virtio { .. } => {}
        }
    }
    None
}

impl LiveCoordinator {
    pub(crate) fn new(
        machine_uuid: Uuid,
        run_uuid: Uuid,
        store: Arc<InstanceStore>,
        machine: VirtualMachine,
        gate: Arc<LiveGate>,
        timeouts: LiveTimeouts,
        capture: Option<crate::live::coordinator::capture::CaptureContext>,
    ) -> Result<Arc<Self>, String> {
        let machine_id = LiveId::parse(&machine_uuid.hyphenated().to_string())?;
        let run_id = LiveId::parse(&run_uuid.hyphenated().to_string())?;
        Ok(Arc::new(Self {
            machine_uuid,
            run_uuid,
            inner: Mutex::new(Inner {
                journal: Journal::new(machine_id, run_id),
                held: None,
                parked: false,
            }),
            store,
            machine,
            gate,
            stop: CancellationToken::new(),
            timeouts,
            capture: capture.map(Arc::new),
        }))
    }

    pub(crate) fn gate(&self) -> &Arc<LiveGate> {
        &self.gate
    }

    /// The exact binding a test plan must carry for this run.
    #[cfg(test)]
    pub(crate) fn capture_binding_for_tests(&self) -> Option<crate::live::journal::CaptureBinding> {
        self.capture.as_ref().map(|context| context.binding())
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Every critical section leaves Inner consistent before any await.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Seal admission and every continuation, then report how to stop.
    ///
    /// The native submission fence closes first and under the journal lock,
    /// before any await of the shutdown path: a mutator the worker admits was
    /// enqueued before stop began, and one refused by the fence observes
    /// `stopped` as soon as it takes this lock.
    pub(crate) fn begin_stop(&self) -> StopMode {
        let mut inner = self.lock();
        self.machine.close_lifecycle_admission();
        inner.journal.stopped = true;
        self.stop.cancel();
        self.gate.seal();
        match self.store.live_snapshot() {
            Ok(snapshot)
                if matches!(
                    snapshot.state,
                    VmLifecycleState::Running | VmLifecycleState::Starting
                ) =>
            {
                StopMode::Graceful
            }
            _ => StopMode::Terminate,
        }
    }

    /// Admit and run one live command. A dropped caller never cancels work.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        command: LiveCommand,
    ) -> Result<LiveCommandResult, LiveError> {
        let mut eligibility = Eligibility::Unchecked;
        loop {
            let admitted = self.admit(&command, eligibility.clone())?;
            match admitted {
                Admitted::Answer(Answer::Ready(result)) => return Ok(result),
                Admitted::Answer(Answer::Wait(receiver)) | Admitted::Joined { receiver } => {
                    return wait(receiver).await
                }
                Admitted::CheckNative => {
                    eligibility = self.check_native(&command.envelope().request_id).await?;
                }
                Admitted::CheckCapture => {
                    let LiveCommand::Capture(capture) = &command else {
                        return Err(LiveError::Abandoned);
                    };
                    eligibility = self.check_capture(&capture.plan).await?;
                }
                Admitted::Pause { operation } => {
                    let coordinator = self.clone();
                    tokio::spawn(async move { coordinator.run_pause(operation).await });
                    // The receipt is the journaled answer for this request.
                    eligibility = Eligibility::Eligible;
                }
                Admitted::Capture {
                    operation,
                    borrowed,
                } => {
                    let coordinator = self.clone();
                    tokio::spawn(async move { coordinator.run_capture(operation, borrowed).await });
                    eligibility = Eligibility::Eligible;
                }
                Admitted::Resume {
                    request,
                    current,
                    receiver,
                } => {
                    let LiveCommand::Resume(resume) = &command else {
                        return Err(LiveError::Abandoned);
                    };
                    let coordinator = self.clone();
                    let token = resume.token.clone();
                    tokio::spawn(
                        async move { coordinator.run_resume(request, current, token).await },
                    );
                    return wait(receiver).await;
                }
                Admitted::CancelFailedPause {
                    request,
                    operation,
                    receiver,
                } => {
                    let coordinator = self.clone();
                    tokio::spawn(
                        async move { coordinator.run_cancel_failed(request, operation).await },
                    );
                    return wait(receiver).await;
                }
                Admitted::Release {
                    request,
                    operation,
                    disposition,
                    receiver,
                } => {
                    let coordinator = self.clone();
                    tokio::spawn(async move {
                        coordinator
                            .run_release(request, operation, disposition)
                            .await
                    });
                    return wait(receiver).await;
                }
            }
        }
    }

    fn admission_view(&self, snapshot: &LiveSnapshot) -> AdmissionView {
        let unsupported =
            |operation: LiveOperation, reason: LiveUnsupportedReason| LiveOperationUnsupported {
                operation,
                backend: snapshot.backend,
                lane: snapshot.lane,
                reason,
            };
        let availability = |operation: LiveOperation, capability: &LiveCapability| match &capability
            .availability
        {
            LiveAvailability::Supported => Ok(()),
            LiveAvailability::Unsupported { reason } => Err(unsupported(operation, reason.clone())),
        };
        let capture = match (
            &self.capture,
            availability(LiveOperation::Capture, &snapshot.live.capture),
        ) {
            (Some(_), capture) => capture,
            // A run that cannot bind a plan (no managed launch lease or no
            // valid configuration projection) never delivers capture.
            (None, _) => Err(unsupported(
                LiveOperation::Capture,
                LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
            )),
        };
        AdmissionView {
            state: snapshot.state,
            lifecycle: snapshot.lifecycle.clone(),
            pause: availability(LiveOperation::Pause, &snapshot.live.pause),
            capture,
            // Phase 14 delivers full capture only.
            incremental: unsupported(
                LiveOperation::Incremental,
                LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
            ),
            capture_binding: self.capture.as_ref().map(|context| context.binding()),
            guest_ready: snapshot.ready_identity.is_some() && snapshot.guest_rejection.is_none(),
        }
    }

    fn admit(
        &self,
        command: &LiveCommand,
        eligibility: Eligibility,
    ) -> Result<Admitted, LiveError> {
        let mut inner = self.lock();
        let snapshot = self.store.live_snapshot()?;
        let view = self.admission_view(&snapshot);
        let admitted = inner.journal.admit(command, &view, eligibility);
        match &admitted {
            Admitted::Pause { operation } => {
                // Close synchronously with acceptance: nothing slips between.
                self.gate.close();
                inner.held = snapshot.ready_identity.clone();
                let activity = activity(
                    operation,
                    operation,
                    LiveCommandKind::Pause,
                    LiveStage::MonitorDrain,
                );
                self.publish(
                    &inner,
                    VmLifecycleState::Pausing,
                    Some(activity),
                    None,
                    false,
                    "pausing",
                )?;
                tracing::info!(operation = %operation, "live pause admitted; fences closed");
            }
            Admitted::Capture {
                operation,
                borrowed,
            } => {
                // A running source is fenced synchronously with acceptance; a
                // borrowed user pause is already fenced, frozen and parked.
                if borrowed.is_none() {
                    self.gate.close();
                    inner.held = snapshot.ready_identity.clone();
                }
                let activity = activity(
                    operation,
                    operation,
                    LiveCommandKind::Capture,
                    LiveStage::CapturePrepare,
                );
                self.publish(
                    &inner,
                    VmLifecycleState::Capturing,
                    Some(activity),
                    None,
                    false,
                    "capturing",
                )?;
                tracing::info!(operation = %operation, borrowed = borrowed.is_some(), "live capture admitted");
            }
            Admitted::Resume {
                request, current, ..
            } => {
                // Native still holds the exact pause until the resume reports
                // a positive release: busy Pausing keeps the parked interval.
                let activity = activity(
                    &current.operation_id,
                    request,
                    LiveCommandKind::Resume,
                    LiveStage::ResumeNative,
                );
                self.publish(
                    &inner,
                    VmLifecycleState::Pausing,
                    Some(activity),
                    None,
                    false,
                    "resuming",
                )?;
                tracing::info!(request = %request, generation = current.token.generation.get(), "live resume admitted");
            }
            Admitted::CancelFailedPause {
                request, operation, ..
            } => {
                let activity = activity(
                    operation,
                    request,
                    LiveCommandKind::CancelOperation,
                    LiveStage::CancelNative,
                );
                self.publish(
                    &inner,
                    VmLifecycleState::Pausing,
                    Some(activity),
                    None,
                    false,
                    "cancelling pause",
                )?;
                tracing::info!(request = %request, operation = %operation, "live pause cancellation admitted");
            }
            _ => {}
        }
        Ok(admitted)
    }

    /// Publish a projection under the coordinator lock. Returns false once
    /// stop has taken over. Only Pausing/Paused/Capturing may carry the
    /// held identity and the parked interval.
    fn publish(
        &self,
        inner: &Inner,
        state: VmLifecycleState,
        activity: Option<LiveActivity>,
        error: Option<LiveFailure>,
        readiness_probe: bool,
        message: &str,
    ) -> Result<bool, StoreError> {
        if inner.journal.stopped {
            return Ok(false);
        }
        let holding = matches!(
            state,
            VmLifecycleState::Pausing | VmLifecycleState::Paused | VmLifecycleState::Capturing
        );
        let current_pause = (state == VmLifecycleState::Paused)
            .then(|| inner.journal.current.clone())
            .flatten();
        self.store.publish_live(LiveTransition {
            state,
            lifecycle: LiveLifecycle {
                current_pause,
                activity,
                error,
            },
            message: message.to_string(),
            held_identity: holding.then(|| inner.held.clone()).flatten(),
            parked: holding && inner.parked,
            readiness_probe,
        })
    }

    /// Active stage projection: Capturing for capture work (including its
    /// source continuation), Pausing for every other lifecycle command.
    fn publish_stage(
        &self,
        operation: &LiveId,
        request: &LiveId,
        command: LiveCommandKind,
        stage: LiveStage,
        readiness_probe: bool,
    ) {
        let inner = self.lock();
        let activity = activity(operation, request, command, stage);
        let state = if command == LiveCommandKind::Capture {
            VmLifecycleState::Capturing
        } else {
            VmLifecycleState::Pausing
        };
        if let Err(error) = self.publish(
            &inner,
            state,
            Some(activity),
            None,
            readiness_probe,
            stage.as_str(),
        ) {
            tracing::error!(%error, %stage, "failed to publish live stage");
        }
    }

    /// Native provider inventory of the exact run, observed outside the lock.
    async fn native_inventory(&self, request: &LiveId, capture: bool) -> Option<LiveDeviceSubject> {
        let profile = |profile: &str| {
            Some(LiveDeviceSubject::GuestProfile {
                profile: profile.to_string(),
            })
        };
        let response = tokio::select! {
            response = self.machine.lifecycle(LifecycleRequest {
                machine_id: self.machine_uuid,
                run_id: self.run_uuid,
                request_id: wire_uuid(request),
                command: LifecycleCommand::GetControl { target: None },
            }) => response,
            () = self.stop.cancelled() => return profile("native-control-not-running"),
        };
        match response {
            Ok(response) => {
                if let Some(InventoryObservation::Unavailable { failure }) = &response.inventory {
                    tracing::warn!(
                        ?failure,
                        "native provider inventory unavailable for live admission"
                    );
                }
                inventory_rejection(&response.control, response.inventory.as_ref(), capture)
            }
            Err(LifecycleError::Unsupported { .. }) => profile("native-lifecycle-unsupported"),
            Err(error) => {
                tracing::warn!(%error, "native lifecycle control unavailable for live admission");
                profile("native-lifecycle-unavailable")
            }
        }
    }

    fn device_rejection(
        &self,
        operation: LiveOperation,
        subject: LiveDeviceSubject,
    ) -> Result<Eligibility, LiveError> {
        let snapshot = self.store.live_snapshot()?;
        Ok(Eligibility::Rejected(
            LiveRejectionReason::Unsupported {
                unsupported: LiveOperationUnsupported {
                    operation,
                    backend: snapshot.backend,
                    lane: snapshot.lane,
                    reason: LiveUnsupportedReason::device(subject.clone()),
                },
            },
            format!("{operation} rejected before freeze: device {subject}"),
        ))
    }

    async fn check_native(&self, request: &LiveId) -> Result<Eligibility, LiveError> {
        match self.native_inventory(request, false).await {
            None => Ok(Eligibility::Eligible),
            Some(subject) => self.device_rejection(LiveOperation::Pause, subject),
        }
    }

    // ---------------------------------------------------------------- pause

    async fn run_pause(self: Arc<Self>, operation: LiveId) {
        let (cancel, identity) = {
            let inner = self.lock();
            (
                inner
                    .journal
                    .operation(&operation)
                    .map(|operation| operation.cancel.clone()),
                inner.held.clone(),
            )
        };
        let (Some(cancel), Some(identity)) = (cancel, identity) else {
            let cause = failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::Admission,
                "pause admitted without a held guest identity",
            );
            self.settle_running(&operation, cause);
            return;
        };

        let drain_deadline = tokio::time::Instant::now() + self.timeouts.drain;
        match self.gate.drain(drain_deadline).await {
            Ok(()) => {}
            Err(DrainError::Sealed) => return self.settle_stopped(&operation),
            Err(DrainError::TimedOut { outstanding }) => {
                return self.settle_running(
                    &operation,
                    failure(
                        LiveFailureCode::DrainTimedOut,
                        LiveStage::MonitorDrain,
                        format!(
                            "{outstanding} admitted session/mutation operations did not settle"
                        ),
                    ),
                );
            }
        }
        if cancel.is_cancelled() {
            return self.settle_running(&operation, cancelled(LiveStage::MonitorDrain));
        }

        // Positive guest profile, re-checked immediately before Freeze.
        let snapshot = match self.store.live_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.settle_running(
                    &operation,
                    failure(
                        LiveFailureCode::GuestUnavailable,
                        LiveStage::GuestFreeze,
                        error.to_string(),
                    ),
                )
            }
        };
        if let Some(rejection) = snapshot.guest_rejection {
            return self.settle_running(
                &operation,
                failure(
                    LiveFailureCode::GuestUnavailable,
                    LiveStage::GuestFreeze,
                    rejection,
                ),
            );
        }
        if snapshot.observed_identity.as_ref() != Some(&identity) {
            return self.settle_running(
                &operation,
                failure(
                    LiveFailureCode::GuestIdentityMismatch,
                    LiveStage::GuestFreeze,
                    "guest identity changed after pause admission",
                ),
            );
        }
        let Some(epoch) = self.allocate_epoch(&operation, &snapshot) else {
            return self.settle_running(
                &operation,
                failure(
                    LiveFailureCode::FreezeFailed,
                    LiveStage::GuestFreeze,
                    "freeze epoch exhausted",
                ),
            );
        };
        self.publish_stage(
            &operation,
            &operation,
            LiveCommandKind::Pause,
            LiveStage::GuestFreeze,
            false,
        );
        let reference = self.freeze_ref(&operation, epoch);
        let (frozen, clock_profile) = match self
            .guest_freeze(&identity, &reference, LiveStage::GuestFreeze)
            .await
        {
            Ok(frozen) => frozen,
            Err(GuestError::Stopped) => return self.settle_stopped(&operation),
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                return self
                    .rollback_pause(&operation, &operation, &identity, &reference, cause)
                    .await;
            }
        };
        if cancel.is_cancelled() {
            return self
                .rollback_pause(
                    &operation,
                    &operation,
                    &identity,
                    &reference,
                    cancelled(LiveStage::NativePause),
                )
                .await;
        }

        self.publish_stage(
            &operation,
            &operation,
            LiveCommandKind::Pause,
            LiveStage::NativePause,
            false,
        );
        let request = self.native_request(
            &operation,
            LifecycleCommand::Pause {
                operation: wire_uuid(&operation),
                purpose: PausePurpose::Initial,
                timeout: self.timeouts.native,
                clock_profile,
            },
        );
        let mut pause = Box::pin(self.native(request));
        let result = tokio::select! {
            result = &mut pause => result,
            () = cancel.cancelled() => {
                // Cancel admitted while native pause is pending: settle both.
                let cancel_request = self.first_cancel_request(&operation);
                let cancel_call = self.native(self.native_request(
                    &cancel_request,
                    LifecycleCommand::CancelPause {
                        operation: wire_uuid(&operation),
                        timeout: self.timeouts.native,
                    },
                ));
                let (pause_result, cancel_result) = tokio::join!(pause, cancel_call);
                if let Ok(outcome) = &pause_result {
                    tracing::info!(operation = %operation, ?outcome, "native pause settled during cancellation");
                }
                return self
                    .settle_cancel(&operation, &cancel_request, &identity, &reference, cancel_result)
                    .await;
            }
        };
        match result {
            Ok(CommandOutcome::Paused { pause: native }) => {
                // Linearization point: publication versus admitted cancel.
                let cancel_admitted = {
                    let mut inner = self.lock();
                    let admitted = cancel.is_cancelled();
                    if !admitted {
                        self.publish_paused(
                            &mut inner,
                            &operation,
                            native.generation,
                            epoch,
                            frozen,
                        );
                    }
                    admitted
                };
                if cancel_admitted {
                    // Never publish: the worker consumes the completed,
                    // unpublished token through its clock-correct resume.
                    let cancel_request = self.first_cancel_request(&operation);
                    let cancel_result = self
                        .native(self.native_request(
                            &cancel_request,
                            LifecycleCommand::CancelPause {
                                operation: wire_uuid(&operation),
                                timeout: self.timeouts.native,
                            },
                        ))
                        .await;
                    self.settle_cancel(
                        &operation,
                        &cancel_request,
                        &identity,
                        &reference,
                        cancel_result,
                    )
                    .await;
                }
            }
            Ok(CommandOutcome::PauseFailed { failure: native }) => {
                self.failed_pausing(
                    &operation,
                    &identity,
                    &reference,
                    failure(
                        LiveFailureCode::NativePauseFailed,
                        LiveStage::NativePause,
                        native_detail(&native),
                    ),
                )
                .await;
            }
            Ok(outcome) => {
                self.failed_pausing(
                    &operation,
                    &identity,
                    &reference,
                    failure(
                        LiveFailureCode::NativeUncertain,
                        LiveStage::NativePause,
                        format!("unexpected native pause outcome {outcome:?}"),
                    ),
                )
                .await;
            }
            Err(NativeError::Stopped) => self.settle_stopped(&operation),
            Err(error @ NativeError::WorkerLost(_)) => {
                let cause = failure(
                    LiveFailureCode::WorkerLost,
                    LiveStage::NativePause,
                    error.describe(),
                );
                self.settle_error(&operation, Some(cause.clone()), cause);
            }
            Err(error) => {
                let code = error.code(LiveFailureCode::NativePauseFailed);
                self.failed_pausing(
                    &operation,
                    &identity,
                    &reference,
                    failure(code, LiveStage::NativePause, error.describe()),
                )
                .await;
            }
        }
    }

    fn publish_paused(
        &self,
        inner: &mut Inner,
        operation: &LiveId,
        generation: NativePauseGeneration,
        epoch: NonZeroU64,
        frozen: GuestFreezeObservation,
    ) {
        let Some(generation) = NonZeroU64::new(generation.get()) else {
            return;
        };
        let token = PauseToken {
            machine_id: inner.journal.machine_id().clone(),
            run_id: inner.journal.run_id().clone(),
            generation,
            owner: PauseOwner::User,
        };
        inner.journal.current = Some(CurrentPause {
            token: token.clone(),
            operation_id: operation.clone(),
            freeze_epoch: epoch,
        });
        if let Some(record) = inner.journal.operation_mut(operation) {
            record.record.outcome = OperationOutcome::Succeeded {
                pause: PauseEstablished {
                    token,
                    freeze_epoch: epoch,
                    guest: frozen,
                    capture_eligible: true,
                },
            };
            record.phase = Phase::Settled;
        }
        inner.parked = true;
        match self.publish(inner, VmLifecycleState::Paused, None, None, false, "paused") {
            Ok(true) => {
                tracing::info!(operation = %operation, generation = generation.get(), "machine paused")
            }
            Ok(false) => {
                tracing::info!(operation = %operation, "pause established after stop; not published")
            }
            Err(error) => tracing::error!(%error, "failed to publish paused state"),
        }
    }

    fn first_cancel_request(&self, operation: &LiveId) -> LiveId {
        let inner = self.lock();
        inner
            .journal
            .peek_cancel_request(operation)
            .unwrap_or_else(|| operation.clone())
    }

    /// Failed Pausing: no token, fenced; only Cancel or stop leave it.
    async fn failed_pausing(
        &self,
        operation: &LiveId,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        cause: LiveFailure,
    ) {
        let cancel_now = {
            let mut inner = self.lock();
            let cancelled = inner
                .journal
                .operation(operation)
                .is_some_and(|record| record.cancel.is_cancelled());
            if let Some(record) = inner.journal.operation_mut(operation) {
                record.record.outcome = OperationOutcome::Failed {
                    failure: cause.clone(),
                };
                record.phase = if cancelled {
                    Phase::Cancelling
                } else {
                    Phase::FailedPausing
                };
            }
            if !cancelled {
                let activity = activity(
                    operation,
                    operation,
                    LiveCommandKind::Pause,
                    LiveStage::PauseFailed,
                );
                if let Err(error) = self.publish(
                    &inner,
                    VmLifecycleState::Pausing,
                    Some(activity),
                    None,
                    false,
                    "pause failed; fenced until cancel or stop",
                ) {
                    tracing::error!(%error, "failed to publish failed pausing");
                }
            }
            cancelled
        };
        tracing::warn!(operation = %operation, cause = %cause, "native pause failed");
        if cancel_now {
            let cancel_request = self.first_cancel_request(operation);
            let result = self
                .native(self.native_request(
                    &cancel_request,
                    LifecycleCommand::CancelPause {
                        operation: wire_uuid(operation),
                        timeout: self.timeouts.native,
                    },
                ))
                .await;
            self.settle_cancel(operation, &cancel_request, identity, reference, result)
                .await;
        }
    }

    async fn run_cancel_failed(self: Arc<Self>, request: LiveId, operation: LiveId) {
        let (identity, epoch) = {
            let inner = self.lock();
            (
                inner.held.clone(),
                inner
                    .journal
                    .operation(&operation)
                    .and_then(|record| record.freeze_epoch),
            )
        };
        let (Some(identity), Some(epoch)) = (identity, epoch) else {
            let cause = failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::CancelNative,
                "failed pause has no held guest identity or freeze epoch",
            );
            return self.settle_error(&operation, None, cause);
        };
        let reference = self.freeze_ref(&operation, epoch);
        let result = self
            .native(self.native_request(
                &request,
                LifecycleCommand::CancelPause {
                    operation: wire_uuid(&operation),
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        self.settle_cancel(&operation, &request, &identity, &reference, result)
            .await;
    }

    /// Native rollback settled (or not): thaw, readiness, then Running.
    async fn settle_cancel(
        &self,
        operation: &LiveId,
        request: &LiveId,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        result: Result<CommandOutcome, NativeError>,
    ) {
        let settled = match result {
            Ok(CommandOutcome::CancelSettled { settlement }) => {
                tracing::info!(operation = %operation, ?settlement, "native pause cancellation settled");
                Ok(())
            }
            Ok(CommandOutcome::CancelFailed {
                stage,
                failure: native,
            }) => Err(failure(
                LiveFailureCode::NativeRollbackFailed,
                LiveStage::CancelNative,
                format!("{stage:?}: {}", native_detail(&native)),
            )),
            // The worker never accepted the pause: no native effect to undo.
            Err(NativeError::Rejected(LifecycleRejection::UnknownTarget)) => Ok(()),
            Err(NativeError::Stopped) => return self.settle_stopped(operation),
            Err(error) => {
                let code = error.code(LiveFailureCode::NativeRollbackFailed);
                Err(failure(code, LiveStage::CancelNative, error.describe()))
            }
            Ok(outcome) => Err(failure(
                LiveFailureCode::NativeUncertain,
                LiveStage::CancelNative,
                format!("unexpected native cancel outcome {outcome:?}"),
            )),
        };
        if let Err(cause) = settled {
            return self.settle_error(operation, Some(cancelled(LiveStage::CancelNative)), cause);
        }
        self.publish_stage(
            operation,
            request,
            LiveCommandKind::CancelOperation,
            LiveStage::CancelThaw,
            false,
        );
        match self
            .rollback_thaw(identity, reference, LiveStage::CancelThaw)
            .await
        {
            Ok(thawed_at) => {
                self.publish_stage(
                    operation,
                    request,
                    LiveCommandKind::CancelOperation,
                    LiveStage::Readiness,
                    true,
                );
                match self.await_readiness(thawed_at, identity).await {
                    Ok(()) => self.settle_running(operation, cancelled(LiveStage::CancelNative)),
                    Err(GuestError::Stopped) => self.settle_stopped(operation),
                    Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => self
                        .settle_error(operation, Some(cancelled(LiveStage::CancelNative)), cause),
                }
            }
            Err(GuestError::Stopped) => self.settle_stopped(operation),
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                self.settle_error(operation, Some(cancelled(LiveStage::CancelNative)), cause)
            }
        }
    }

    /// Freeze did not establish: thaw exactly what may be frozen, require
    /// readiness, then Running; a failed rollback is a fenced Error.
    async fn rollback_pause(
        &self,
        operation: &LiveId,
        request: &LiveId,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        cause: LiveFailure,
    ) {
        tracing::warn!(operation = %operation, cause = %cause, "pause rolling back guest freeze");
        self.publish_stage(
            operation,
            request,
            LiveCommandKind::Pause,
            LiveStage::RollbackThaw,
            false,
        );
        match self
            .rollback_thaw(identity, reference, LiveStage::RollbackThaw)
            .await
        {
            Ok(thawed_at) => {
                self.publish_stage(
                    operation,
                    request,
                    LiveCommandKind::Pause,
                    LiveStage::Readiness,
                    true,
                );
                match self.await_readiness(thawed_at, identity).await {
                    Ok(()) => self.settle_running(operation, cause),
                    Err(GuestError::Stopped) => self.settle_stopped(operation),
                    Err(GuestError::Refused(error) | GuestError::Unknown(error)) => {
                        self.settle_error(operation, Some(cause), error)
                    }
                }
            }
            Err(GuestError::Stopped) => self.settle_stopped(operation),
            Err(GuestError::Refused(error) | GuestError::Unknown(error)) => {
                self.settle_error(operation, Some(cause), error)
            }
        }
    }

    /// Pause operation ends Running: record its failure, reopen fences last.
    fn settle_running(&self, operation: &LiveId, cause: LiveFailure) {
        let mut inner = self.lock();
        let record = self.finish_operation(&mut inner, operation, cause);
        inner.held = None;
        inner.journal.current = None;
        inner.parked = false;
        let published = match self.publish(
            &inner,
            VmLifecycleState::Running,
            None,
            None,
            false,
            "running",
        ) {
            Ok(published) => published,
            Err(error) => {
                tracing::error!(%error, "failed to publish running state");
                false
            }
        };
        if published {
            self.gate.reopen();
        }
        let state = if published {
            VmLifecycleState::Running
        } else {
            VmLifecycleState::Stopping
        };
        for request in inner.journal.take_cancel_requests(operation) {
            let result = if published {
                LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed {
                    completed: CancelCompleted {
                        effective: true,
                        operation: record.clone(),
                        state,
                    },
                })
            } else {
                stopped_cancel(record.clone())
            };
            inner.journal.complete(&request, result);
        }
        tracing::info!(operation = %operation, published, "pause operation ended running");
    }

    /// Fenced Error: only stop leaves it.
    fn settle_error(&self, operation: &LiveId, primary: Option<LiveFailure>, cause: LiveFailure) {
        let mut inner = self.lock();
        let record = self.finish_operation(
            &mut inner,
            operation,
            primary.unwrap_or_else(|| cause.clone()),
        );
        inner.held = None;
        inner.journal.current = None;
        inner.parked = false;
        if let Err(error) = self.publish(
            &inner,
            VmLifecycleState::Error,
            None,
            Some(cause.clone()),
            false,
            "live lifecycle error; fenced until stop",
        ) {
            tracing::error!(%error, "failed to publish error state");
        }
        for request in inner.journal.take_cancel_requests(operation) {
            let result = LiveCommandResult::CancelOperation(CancelOperationOutcome::Failed {
                failed: CancelFailed {
                    cause: cause.clone(),
                    operation: record.clone(),
                    state: VmLifecycleState::Error,
                },
            });
            inner.journal.complete(&request, result);
        }
        tracing::error!(operation = %operation, cause = %cause, "machine entered live Error");
    }

    fn settle_stopped(&self, operation: &LiveId) {
        let mut inner = self.lock();
        let record = self.finish_operation(
            &mut inner,
            operation,
            failure(
                LiveFailureCode::Stopped,
                LiveStage::Admission,
                "monitor is stopping",
            ),
        );
        for request in inner.journal.take_cancel_requests(operation) {
            inner
                .journal
                .complete(&request, stopped_cancel(record.clone()));
        }
    }

    /// An unfinished operation fails with `cause`; a finished one keeps its
    /// original terminal outcome.
    fn finish_operation(
        &self,
        inner: &mut Inner,
        operation: &LiveId,
        cause: LiveFailure,
    ) -> vm_spec::lifecycle::LiveOperationRecord {
        match inner.journal.operation_mut(operation) {
            Some(record) => {
                if record.record.outcome == OperationOutcome::InProgress {
                    record.record.outcome = OperationOutcome::Failed { failure: cause };
                }
                record.phase = Phase::Settled;
                record.record.clone()
            }
            None => vm_spec::lifecycle::LiveOperationRecord {
                operation_id: operation.clone(),
                kind: vm_spec::lifecycle::OperationKind::Pause,
                outcome: OperationOutcome::Failed { failure: cause },
            },
        }
    }

    // --------------------------------------------------------------- resume

    async fn run_resume(
        self: Arc<Self>,
        request: LiveId,
        current: CurrentPause,
        requested: PauseToken,
    ) {
        let identity = self.lock().held.clone();
        let Some(identity) = identity else {
            let cause = failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::ResumeNative,
                "resume without a held guest identity",
            );
            return self.resume_error(&request, &requested, cause, None);
        };
        let operation = current.operation_id.clone();
        let Some(generation) = NativePauseGeneration::new(current.token.generation.get()) else {
            let cause = failure(
                LiveFailureCode::NativeResumeFailed,
                LiveStage::ResumeNative,
                "zero generation",
            );
            return self.resume_error(&request, &requested, cause, None);
        };
        let result = self
            .native(self.native_request(
                &request,
                LifecycleCommand::Resume {
                    operation: wire_uuid(&operation),
                    generation,
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::Resumed { clock }) => {
                tracing::info!(request = %request, sequence = clock.sequence, acknowledged_ms = clock.acknowledged_within.as_millis(), "native ClockOnly resume acknowledged");
                // Positive release: the next projection ends the parked
                // interval and agent staleness resumes from here.
                self.lock().parked = false;
            }
            Ok(CommandOutcome::ResumeFailed {
                stage,
                failure: native,
                pause_retained: true,
            }) => {
                let cause = failure(
                    resume_code(stage),
                    LiveStage::ResumeNative,
                    native_detail(&native),
                );
                return self.resume_retained(&request, &requested, current, cause);
            }
            Ok(CommandOutcome::ResumeFailed {
                stage,
                failure: native,
                pause_retained: false,
            }) => {
                let cause = failure(
                    resume_code(stage),
                    resume_stage(stage),
                    native_detail(&native),
                );
                return self.resume_error(&request, &requested, cause, None);
            }
            Err(NativeError::Rejected(LifecycleRejection::Busy | LifecycleRejection::NotReady)) => {
                let cause = failure(
                    LiveFailureCode::NativeResumeFailed,
                    LiveStage::ResumeNative,
                    "native lifecycle owner refused the resume without effect",
                );
                return self.resume_retained(&request, &requested, current, cause);
            }
            Err(NativeError::Stopped) => return self.resume_stopped(&request, &requested),
            Err(error) => {
                let code = error.code(LiveFailureCode::NativeResumeFailed);
                let cause = failure(code, LiveStage::ResumeNative, error.describe());
                return self.resume_error(&request, &requested, cause, None);
            }
            Ok(outcome) => {
                let cause = failure(
                    LiveFailureCode::NativeUncertain,
                    LiveStage::ResumeNative,
                    format!("unexpected native resume outcome {outcome:?}"),
                );
                return self.resume_error(&request, &requested, cause, None);
            }
        }
        match self
            .continue_released(
                &operation,
                &request,
                LiveCommandKind::Resume,
                &request,
                &identity,
                current.freeze_epoch,
                generation,
            )
            .await
        {
            Continued::Running => self.resume_running(&request, &requested, current.freeze_epoch),
            Continued::Recovered { current, cause } => {
                self.resume_recovered(&request, &requested, current, cause)
            }
            Continued::Failed { cause, recovery } => {
                self.resume_error(&request, &requested, cause, recovery)
            }
            Continued::Stopped => self.resume_stopped(&request, &requested),
        }
    }

    /// After a positive native release of the exact pause of `operation`:
    /// same-identity transport re-handshake, exact Thaw of `epoch`, then
    /// readiness. A lost thaw re-freezes at the next epoch and establishes a
    /// NEW native pause (request `recovery_request`); nothing is published
    /// here, so the caller owns the final transition.
    #[allow(clippy::too_many_arguments)]
    async fn continue_released(
        &self,
        operation: &LiveId,
        request: &LiveId,
        command: LiveCommandKind,
        recovery_request: &LiveId,
        identity: &ReadyAgentIdentity,
        epoch: NonZeroU64,
        consumed: NativePauseGeneration,
    ) -> Continued {
        // Request a new identity-bearing status only after confirmed native
        // release, rather than waiting for an unsolicited watch heartbeat.
        self.publish_stage(
            operation,
            request,
            command,
            LiveStage::ResumeHandshake,
            false,
        );
        match self.guest_handshake(identity).await {
            Ok(()) => {}
            Err(GuestError::Stopped) => return Continued::Stopped,
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                return Continued::Failed {
                    cause,
                    recovery: None,
                }
            }
        }

        self.publish_stage(operation, request, command, LiveStage::ResumeThaw, false);
        let reference = self.freeze_ref(operation, epoch);
        let deadline = tokio::time::Instant::now() + self.timeouts.guest_stage;
        match self
            .guest_thaw(identity, &reference, false, LiveStage::ResumeThaw, deadline)
            .await
        {
            Ok(_) => {
                let thawed_at = Instant::now();
                self.publish_stage(operation, request, command, LiveStage::Readiness, true);
                match self.await_readiness(thawed_at, identity).await {
                    Ok(()) => Continued::Running,
                    Err(GuestError::Stopped) => Continued::Stopped,
                    Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                        Continued::Failed {
                            cause,
                            recovery: None,
                        }
                    }
                }
            }
            Err(GuestError::Stopped) => Continued::Stopped,
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                let lost = failure(
                    LiveFailureCode::ThawUnacknowledged,
                    LiveStage::ResumeThaw,
                    cause
                        .message
                        .as_ref()
                        .map_or("thaw not acknowledged", Diagnostic::as_str)
                        .to_string(),
                );
                self.recover_lost_thaw(
                    operation,
                    request,
                    command,
                    recovery_request,
                    identity,
                    consumed,
                    lost,
                )
                .await
            }
        }
    }

    /// Lost thaw: exact next-epoch freeze, then a NEW native pause; only then
    /// recovered authority. Anything else is fenced Error.
    #[allow(clippy::too_many_arguments)]
    async fn recover_lost_thaw(
        &self,
        operation: &LiveId,
        request: &LiveId,
        command: LiveCommandKind,
        recovery_request: &LiveId,
        identity: &ReadyAgentIdentity,
        consumed: NativePauseGeneration,
        cause: LiveFailure,
    ) -> Continued {
        tracing::warn!(request = %request, cause = %cause, "thaw acknowledgement lost; re-freezing");
        self.publish_stage(
            operation,
            request,
            command,
            LiveStage::RecoveryFreeze,
            false,
        );
        let snapshot = self.store.live_snapshot().ok();
        let epoch = {
            let mut inner = self.lock();
            let observed = snapshot.as_ref().and_then(observed_epoch);
            inner.journal.next_epoch(observed)
        };
        let Some(epoch) = epoch else {
            let recovery = failure(
                LiveFailureCode::RecoveryFreezeFailed,
                LiveStage::RecoveryFreeze,
                "freeze epoch exhausted",
            );
            return Continued::Failed {
                cause,
                recovery: Some(recovery),
            };
        };
        let reference = self.freeze_ref(operation, epoch);
        let (frozen, clock_profile) = match self
            .guest_freeze(identity, &reference, LiveStage::RecoveryFreeze)
            .await
        {
            Ok(frozen) => frozen,
            Err(GuestError::Stopped) => return Continued::Stopped,
            Err(GuestError::Refused(error) | GuestError::Unknown(error)) => {
                let recovery = LiveFailure {
                    code: LiveFailureCode::RecoveryFreezeFailed,
                    ..error
                };
                return Continued::Failed {
                    cause,
                    recovery: Some(recovery),
                };
            }
        };
        self.publish_stage(operation, request, command, LiveStage::RecoveryPause, false);
        let result = self
            .native(self.native_request(
                recovery_request,
                LifecycleCommand::Pause {
                    operation: wire_uuid(operation),
                    purpose: PausePurpose::Recovery { consumed },
                    timeout: self.timeouts.native,
                    clock_profile,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::Paused { pause: native })
                if native.generation.get() > consumed.get() =>
            {
                let Some(generation) = NonZeroU64::new(native.generation.get()) else {
                    return Continued::Failed {
                        cause,
                        recovery: Some(failure(
                            LiveFailureCode::RecoveryPauseFailed,
                            LiveStage::RecoveryPause,
                            "recovery pause reported a zero generation",
                        )),
                    };
                };
                let inner = self.lock();
                let token = PauseToken {
                    machine_id: inner.journal.machine_id().clone(),
                    run_id: inner.journal.run_id().clone(),
                    generation,
                    owner: PauseOwner::User,
                };
                tracing::info!(request = %request, generation = generation.get(), epoch = epoch.get(), observed = ?frozen.observed_frozen_roots, "recovered paused with new authority");
                Continued::Recovered {
                    current: CurrentPause {
                        token,
                        operation_id: operation.clone(),
                        freeze_epoch: epoch,
                    },
                    cause,
                }
            }
            Ok(outcome) => Continued::Failed {
                cause,
                recovery: Some(failure(
                    LiveFailureCode::RecoveryPauseFailed,
                    LiveStage::RecoveryPause,
                    format!("recovery native pause did not establish new authority: {outcome:?}"),
                )),
            },
            Err(NativeError::Stopped) => Continued::Stopped,
            Err(error) => Continued::Failed {
                cause,
                recovery: Some(failure(
                    error.code(LiveFailureCode::RecoveryPauseFailed),
                    LiveStage::RecoveryPause,
                    error.describe(),
                )),
            },
        }
    }

    /// Lost-thaw recovery established NEW user authority: publish Paused.
    fn resume_recovered(
        &self,
        request: &LiveId,
        requested: &PauseToken,
        recovered: CurrentPause,
        cause: LiveFailure,
    ) {
        let mut inner = self.lock();
        inner.journal.current = Some(recovered.clone());
        inner.parked = true;
        let published = matches!(
            self.publish(
                &inner,
                VmLifecycleState::Paused,
                None,
                None,
                false,
                "paused after lost-thaw recovery"
            ),
            Ok(true)
        );
        let result = if published {
            ResumeFailed {
                cause,
                state: VmLifecycleState::Paused,
                current_pause: Some(recovered),
                recovery_failure: None,
                requested_token: requested.clone(),
            }
        } else {
            inner.journal.current = None;
            stopped_resume(requested)
        };
        inner.journal.complete(
            request,
            LiveCommandResult::Resume(ResumeOutcome::Failed { failed: result }),
        );
    }

    fn resume_running(&self, request: &LiveId, requested: &PauseToken, epoch: NonZeroU64) {
        let mut inner = self.lock();
        inner.held = None;
        inner.journal.current = None;
        inner.parked = false;
        let published = matches!(
            self.publish(
                &inner,
                VmLifecycleState::Running,
                None,
                None,
                false,
                "running"
            ),
            Ok(true)
        );
        let result = if published {
            self.gate.reopen();
            tracing::info!(request = %request, "machine resumed");
            ResumeOutcome::Resumed {
                resumed: ResumeCompleted {
                    consumed_token: requested.clone(),
                    thawed_epoch: epoch,
                },
            }
        } else {
            ResumeOutcome::Failed {
                failed: stopped_resume(requested),
            }
        };
        inner
            .journal
            .complete(request, LiveCommandResult::Resume(result));
    }

    /// Native kept the exact pause parked: the same authority stays current
    /// and so does the parked interval.
    fn resume_retained(
        &self,
        request: &LiveId,
        requested: &PauseToken,
        current: CurrentPause,
        cause: LiveFailure,
    ) {
        let mut inner = self.lock();
        inner.journal.current = Some(current.clone());
        inner.parked = true;
        let published = matches!(
            self.publish(
                &inner,
                VmLifecycleState::Paused,
                None,
                None,
                false,
                "paused; resume failed without releasing"
            ),
            Ok(true)
        );
        let failed = if published {
            ResumeFailed {
                cause,
                state: VmLifecycleState::Paused,
                current_pause: Some(current),
                recovery_failure: None,
                requested_token: requested.clone(),
            }
        } else {
            inner.journal.current = None;
            stopped_resume(requested)
        };
        inner.journal.complete(
            request,
            LiveCommandResult::Resume(ResumeOutcome::Failed { failed }),
        );
    }

    fn resume_error(
        &self,
        request: &LiveId,
        requested: &PauseToken,
        cause: LiveFailure,
        recovery_failure: Option<LiveFailure>,
    ) {
        let mut inner = self.lock();
        inner.held = None;
        inner.journal.current = None;
        inner.parked = false;
        let error = recovery_failure.clone().unwrap_or_else(|| cause.clone());
        let published = matches!(
            self.publish(
                &inner,
                VmLifecycleState::Error,
                None,
                Some(error.clone()),
                false,
                "live lifecycle error; fenced until stop"
            ),
            Ok(true)
        );
        let failed = if published {
            tracing::error!(request = %request, cause = %error, "resume entered live Error");
            ResumeFailed {
                cause,
                state: VmLifecycleState::Error,
                current_pause: None,
                recovery_failure,
                requested_token: requested.clone(),
            }
        } else {
            stopped_resume(requested)
        };
        inner.journal.complete(
            request,
            LiveCommandResult::Resume(ResumeOutcome::Failed { failed }),
        );
    }

    fn resume_stopped(&self, request: &LiveId, requested: &PauseToken) {
        let mut inner = self.lock();
        inner.journal.current = None;
        inner.parked = false;
        inner.journal.complete(
            request,
            LiveCommandResult::Resume(ResumeOutcome::Failed {
                failed: stopped_resume(requested),
            }),
        );
    }

    // ---------------------------------------------------------------- guest

    fn freeze_ref(&self, operation: &LiveId, epoch: NonZeroU64) -> FreezeRef {
        FreezeRef {
            machine_id: self.machine_uuid.hyphenated().to_string(),
            run_id: self.run_uuid.hyphenated().to_string(),
            operation_id: operation.as_str().to_string(),
            freeze_epoch: Some(epoch.get()),
        }
    }

    fn expected(&self, identity: &ReadyAgentIdentity) -> ExpectedGuestIdentity {
        ExpectedGuestIdentity {
            machine_id: self.machine_uuid.hyphenated().to_string(),
            run_id: self.run_uuid.hyphenated().to_string(),
            agent_instance_id: identity.instance_id.hyphenated().to_string(),
            boot_id: identity.boot_id.hyphenated().to_string(),
        }
    }

    fn allocate_epoch(&self, operation: &LiveId, snapshot: &LiveSnapshot) -> Option<NonZeroU64> {
        let mut inner = self.lock();
        let epoch = inner.journal.next_epoch(observed_epoch(snapshot))?;
        if let Some(record) = inner.journal.operation_mut(operation) {
            record.freeze_epoch = Some(epoch);
        }
        Some(epoch)
    }

    /// Exact FreezeWorkloads. Identical retries (including deadline_ms) join
    /// the guest's in-flight work; only a definitive answer decides.
    async fn guest_freeze(
        &self,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        stage: LiveStage,
    ) -> Result<(GuestFreezeObservation, Option<ObservedClockProfile>), GuestError> {
        let request = FreezeWorkloadsRequest {
            expected: Some(self.expected(identity)),
            freeze_ref: Some(reference.clone()),
            deadline_ms: Some(GUEST_DEADLINE_MS),
        };
        let deadline = tokio::time::Instant::now() + self.timeouts.guest_stage;
        let epoch = reference.freeze_epoch.and_then(NonZeroU64::new);
        let mut last: Option<LiveFailure> = None;
        loop {
            if self.stop.is_cancelled() {
                return Err(GuestError::Stopped);
            }
            let attempt = self.guest_call(deadline, |mut client| {
                let request = request.clone();
                async move { client.freeze_workloads(request).await }
            });
            match attempt.await {
                GuestCall::Stopped => return Err(GuestError::Stopped),
                GuestCall::Response(response) => {
                    let status = response.into_inner().status.unwrap_or_default();
                    let observation = guest_observation(&status).map_err(|error| {
                        GuestError::Refused(failure(LiveFailureCode::FreezeFailed, stage, error))
                    })?;
                    let matches_ref = status.freeze_ref.as_ref() == Some(reference);
                    if let (true, Some(epoch)) = (matches_ref, epoch) {
                        if observation.positively_frozen(epoch) {
                            let profile = status
                                .clock_profile
                                .as_ref()
                                .map(ObservedClockProfile::from_guest)
                                .transpose()
                                .map_err(|error| {
                                    GuestError::Refused(failure(
                                        LiveFailureCode::FreezeFailed,
                                        stage,
                                        format!("{error:?}"),
                                    ))
                                })?;
                            if profile
                                .as_ref()
                                .is_some_and(|profile| profile.boot_id != identity.boot_id)
                            {
                                return Err(GuestError::Refused(failure(
                                    LiveFailureCode::GuestIdentityMismatch,
                                    stage,
                                    "clock profile belongs to another guest boot",
                                )));
                            }
                            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                            if self.machine.backend_kind() == crate::virt::BackendKind::Krun
                                && profile.is_none()
                            {
                                return Err(GuestError::Refused(failure(
                                    LiveFailureCode::FreezeFailed,
                                    stage,
                                    status
                                        .clock_profile_unavailable_reason
                                        .as_deref()
                                        .unwrap_or("guest clock profile is missing"),
                                )));
                            }
                            return Ok((observation, profile));
                        }
                    }
                    let code = match observation.state {
                        GuestLifecycleState::Faulted => LiveFailureCode::ThawFailed,
                        _ => LiveFailureCode::FreezeFailed,
                    };
                    let message = observation
                        .failure
                        .as_ref()
                        .map_or(
                            "guest did not report the exact frozen set",
                            Diagnostic::as_str,
                        )
                        .to_string();
                    return Err(GuestError::Refused(
                        failure(code, stage, message).with_guest(observation),
                    ));
                }
                GuestCall::Refused(status) => {
                    // Busy (an earlier thaw still settling) or a definitive
                    // refusal: retry the identical request inside the budget.
                    last = Some(failure(
                        LiveFailureCode::FreezeFailed,
                        stage,
                        status.message(),
                    ));
                }
                GuestCall::Transport(message) => {
                    last = Some(failure(LiveFailureCode::FreezeTimedOut, stage, message));
                }
                GuestCall::Expired => {
                    let cause = last.unwrap_or_else(|| {
                        failure(
                            LiveFailureCode::FreezeTimedOut,
                            stage,
                            "freeze not acknowledged before its deadline",
                        )
                    });
                    return Err(match cause.code {
                        LiveFailureCode::FreezeFailed => GuestError::Refused(cause),
                        _ => GuestError::Unknown(cause),
                    });
                }
            }
            self.retry_pause(deadline).await;
        }
    }

    /// Exact Thaw with identical retries; Ok only on the Thawed ack of this
    /// reference.
    async fn guest_thaw(
        &self,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        rollback: bool,
        stage: LiveStage,
        deadline: tokio::time::Instant,
    ) -> Result<GuestFreezeObservation, GuestError> {
        let request = ThawRequest {
            expected: Some(self.expected(identity)),
            freeze_ref: Some(reference.clone()),
            rollback,
            deadline_ms: Some(GUEST_DEADLINE_MS),
        };
        let mut last: Option<LiveFailure> = None;
        loop {
            if self.stop.is_cancelled() {
                return Err(GuestError::Stopped);
            }
            let attempt = self.guest_call(deadline, |mut client| {
                let request = request.clone();
                async move { client.thaw(request).await }
            });
            match attempt.await {
                GuestCall::Stopped => return Err(GuestError::Stopped),
                GuestCall::Response(response) => {
                    let status = response.into_inner().status.unwrap_or_default();
                    let observation = guest_observation(&status).map_err(|error| {
                        GuestError::Refused(failure(LiveFailureCode::ThawFailed, stage, error))
                    })?;
                    if status.freeze_ref.as_ref() == Some(reference)
                        && observation.state == GuestLifecycleState::Thawed
                    {
                        return Ok(observation);
                    }
                    return Err(GuestError::Refused(
                        failure(
                            LiveFailureCode::ThawFailed,
                            stage,
                            "guest did not acknowledge the exact thaw",
                        )
                        .with_guest(observation),
                    ));
                }
                GuestCall::Refused(status) => {
                    return Err(GuestError::Refused(failure(
                        LiveFailureCode::ThawFailed,
                        stage,
                        status.message(),
                    )));
                }
                GuestCall::Transport(message) => {
                    last = Some(failure(LiveFailureCode::ThawUnacknowledged, stage, message));
                }
                GuestCall::Expired => {
                    return Err(GuestError::Unknown(last.unwrap_or_else(|| {
                        failure(
                            LiveFailureCode::ThawUnacknowledged,
                            stage,
                            "thaw not acknowledged before its deadline",
                        )
                    })));
                }
            }
            self.retry_pause(deadline).await;
        }
    }

    /// Rollback thaw after an unestablished freeze. A definitive refusal is
    /// accepted only when the guest positively shows it never adopted this
    /// reference and nothing is frozen.
    async fn rollback_thaw(
        &self,
        identity: &ReadyAgentIdentity,
        reference: &FreezeRef,
        stage: LiveStage,
    ) -> Result<Instant, GuestError> {
        let deadline = tokio::time::Instant::now() + self.timeouts.guest_stage;
        match self
            .guest_thaw(identity, reference, true, stage, deadline)
            .await
        {
            Ok(_) => Ok(Instant::now()),
            Err(GuestError::Refused(cause)) => {
                let status = self.guest_status(deadline).await?;
                let adopted = status.freeze_ref.as_ref() == Some(reference);
                let quiescent = matches!(
                    protocol::v1::GuestLifecycleState::try_from(status.state),
                    Ok(protocol::v1::GuestLifecycleState::Running
                        | protocol::v1::GuestLifecycleState::Thawed
                        | protocol::v1::GuestLifecycleState::Unspecified)
                );
                if !adopted && quiescent && status.observed_frozen_roots.is_empty() {
                    Ok(Instant::now())
                } else {
                    Err(GuestError::Refused(cause))
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn guest_status(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<GuestLifecycleStatus, GuestError> {
        loop {
            let attempt = self.guest_call(deadline, |mut client| async move {
                client.get_status(GetAgentStatusRequest {}).await
            });
            match attempt.await {
                GuestCall::Stopped => return Err(GuestError::Stopped),
                GuestCall::Response(response) => {
                    return response
                        .into_inner()
                        .report
                        .and_then(|report| report.lifecycle)
                        .ok_or_else(|| {
                            GuestError::Refused(failure(
                                LiveFailureCode::GuestUnavailable,
                                LiveStage::RollbackThaw,
                                "guest status has no lifecycle",
                            ))
                        });
                }
                GuestCall::Refused(status) => {
                    return Err(GuestError::Refused(failure(
                        LiveFailureCode::GuestUnavailable,
                        LiveStage::RollbackThaw,
                        status.message(),
                    )))
                }
                GuestCall::Transport(_) => {}
                GuestCall::Expired => {
                    return Err(GuestError::Unknown(failure(
                        LiveFailureCode::GuestUnavailable,
                        LiveStage::RollbackThaw,
                        "guest status unavailable",
                    )))
                }
            }
            self.retry_pause(deadline).await;
        }
    }

    /// Sleep before a retry; the next attempt observes expiry or stop.
    async fn retry_pause(&self, deadline: tokio::time::Instant) {
        tokio::select! {
            () = tokio::time::sleep(RETRY_DELAY) => {}
            () = tokio::time::sleep_until(deadline) => {}
            () = self.stop.cancelled() => {}
        }
    }

    async fn guest_call<T, F, Fut>(&self, deadline: tokio::time::Instant, call: F) -> GuestCall<T>
    where
        F: FnOnce(
            protocol::v1::guest_agent_service_client::GuestAgentServiceClient<
                tonic::transport::Channel,
            >,
        ) -> Fut,
        Fut: Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        if tokio::time::Instant::now() >= deadline {
            return GuestCall::Expired;
        }
        let attempt = async {
            let channel = crate::guest::connect(&self.machine).await?;
            call(crate::guest::agent_client(channel)).await
        };
        tokio::select! {
            () = self.stop.cancelled() => GuestCall::Stopped,
            result = tokio::time::timeout_at(deadline, attempt) => match result {
                Err(_) => GuestCall::Expired,
                Ok(Ok(response)) => GuestCall::Response(response),
                Ok(Err(status)) if transport_code(status.code()) => {
                    GuestCall::Transport(status.message().to_string())
                }
                Ok(Err(status)) => GuestCall::Refused(status),
            },
        }
    }

    async fn guest_handshake(&self, identity: &ReadyAgentIdentity) -> Result<(), GuestError> {
        let deadline = tokio::time::Instant::now() + self.timeouts.handshake;
        self.request_status_barrier(identity, StatusBarrier::ResumeHandshake, deadline)
            .await
    }

    /// Request and observe a fresh identity-validated status inside the
    /// caller's fixed stage budget, using a new control connection per attempt.
    async fn request_status_barrier(
        &self,
        identity: &ReadyAgentIdentity,
        barrier: StatusBarrier,
        deadline: tokio::time::Instant,
    ) -> Result<(), GuestError> {
        loop {
            if self.stop.is_cancelled() {
                return Err(GuestError::Stopped);
            }
            // guest_call establishes a new control connection for every attempt.
            let attempt = self.guest_call(deadline, |mut client| async move {
                client.get_status(GetAgentStatusRequest {}).await
            });
            match attempt.await {
                GuestCall::Stopped => return Err(GuestError::Stopped),
                GuestCall::Response(response) => {
                    return observe_status_barrier(
                        &self.store,
                        identity,
                        response.into_inner(),
                        barrier,
                    );
                }
                GuestCall::Refused(status) => {
                    return Err(GuestError::Refused(barrier.failure(status.message())));
                }
                GuestCall::Transport(_) => {}
                GuestCall::Expired => {
                    return Err(GuestError::Unknown(
                        barrier.failure("guest status was not refreshed before its deadline"),
                    ));
                }
            }
            self.retry_pause(deadline).await;
        }
    }

    /// Guest readiness prerequisites from receipts after `since`, evaluated
    /// while still fenced. Public readiness stays false until Running.
    async fn await_readiness(
        &self,
        since: Instant,
        identity: &ReadyAgentIdentity,
    ) -> Result<(), GuestError> {
        let deadline = tokio::time::Instant::now() + self.timeouts.readiness;
        // The Thaw-emitted watch report can precede its RPC response and
        // therefore `since`. Request a new receipt after that exact successful
        // thaw instead of waiting for an unsolicited heartbeat. This consumes
        // the readiness budget and does not replace any Ready prerequisites.
        self.request_status_barrier(identity, StatusBarrier::Readiness, deadline)
            .await?;
        let mut changes = self.store.subscribe();
        loop {
            match self.store.status_identity_since(since) {
                Ok(Some(observed)) if &observed != identity => {
                    return Err(GuestError::Refused(failure(
                        LiveFailureCode::GuestIdentityMismatch,
                        LiveStage::Readiness,
                        "guest agent identity changed before readiness",
                    )))
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(GuestError::Refused(failure(
                        LiveFailureCode::ReadinessFailed,
                        LiveStage::Readiness,
                        error.to_string(),
                    )))
                }
            }
            match self.store.prospective_readiness(since) {
                Ok((true, _)) => return Ok(()),
                Ok((false, _)) => {}
                Err(error) => {
                    return Err(GuestError::Refused(failure(
                        LiveFailureCode::ReadinessFailed,
                        LiveStage::Readiness,
                        error.to_string(),
                    )))
                }
            }
            tokio::select! {
                () = self.stop.cancelled() => return Err(GuestError::Stopped),
                () = tokio::time::sleep_until(deadline) => {
                    let reason = self
                        .store
                        .prospective_readiness(since)
                        .map(|(_, reason)| format!("{reason:?}"))
                        .unwrap_or_default();
                    return Err(GuestError::Unknown(failure(
                        LiveFailureCode::ReadinessFailed,
                        LiveStage::Readiness,
                        format!("guest readiness was not re-established before its deadline ({reason})"),
                    )));
                }
                changed = changes.changed() => if changed.is_err() {
                    return Err(GuestError::Stopped);
                },
            }
        }
    }

    // --------------------------------------------------------------- native

    fn native_request(&self, request: &LiveId, command: LifecycleCommand) -> LifecycleRequest {
        LifecycleRequest {
            machine_id: self.machine_uuid,
            run_id: self.run_uuid,
            request_id: wire_uuid(request),
            command,
        }
    }

    /// A `Stopping` refusal after stop began is the stop fence itself, not a
    /// native failure. `begin_stop` closes the fence under the journal lock,
    /// so a fenced refusal always observes `stopped` here.
    fn native_rejection(&self, rejection: LifecycleRejection) -> NativeError {
        if rejection == LifecycleRejection::Stopping && self.lock().journal.stopped {
            NativeError::Stopped
        } else {
            NativeError::Rejected(rejection)
        }
    }

    /// One native command to a terminal outcome. `Accepted` and transport
    /// uncertainty re-issue the identical request, which joins the retained
    /// worker command: never a second native effect. Stop is polled first,
    /// and `begin_stop`'s submission fence refuses any enqueue after it.
    async fn native(&self, request: LifecycleRequest) -> Result<CommandOutcome, NativeError> {
        let mut transport_failures = 0;
        loop {
            let response = tokio::select! {
                biased;
                () = self.stop.cancelled() => return Err(NativeError::Stopped),
                response = self.machine.lifecycle(request.clone()) => response,
            };
            match response {
                Ok(response) => match response.command.map(|report| report.state) {
                    Some(CommandState::Completed { outcome }) => return Ok(outcome),
                    Some(CommandState::Accepted) => {}
                    None => {
                        return Err(NativeError::Uncertain(
                            "native report omitted the command".into(),
                        ))
                    }
                },
                Err(LifecycleError::Rejected(rejection)) => {
                    return Err(self.native_rejection(rejection))
                }
                Err(LifecycleError::Unsupported { backend }) => {
                    return Err(NativeError::Unsupported(backend.to_string()))
                }
                Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost)) => {
                    return Err(NativeError::WorkerLost(
                        "worker lifecycle owner is gone".into(),
                    ))
                }
                Err(LifecycleError::Unknown(uncertainty)) => {
                    transport_failures += 1;
                    if transport_failures >= NATIVE_TRANSPORT_RETRIES {
                        return Err(NativeError::Uncertain(uncertainty.to_string()));
                    }
                    tokio::select! {
                        () = self.stop.cancelled() => return Err(NativeError::Stopped),
                        () = tokio::time::sleep(RETRY_DELAY) => {}
                    }
                }
            }
        }
    }
}

enum GuestCall<T> {
    Response(tonic::Response<T>),
    Refused(tonic::Status),
    Transport(String),
    Expired,
    Stopped,
}

async fn wait(mut receiver: ResultReceiver) -> Result<LiveCommandResult, LiveError> {
    let result = receiver
        .wait_for(Option::is_some)
        .await
        .map_err(|_| LiveError::Abandoned)?;
    result.clone().ok_or(LiveError::Abandoned)
}

fn activity(
    operation: &LiveId,
    request: &LiveId,
    command: LiveCommandKind,
    stage: LiveStage,
) -> LiveActivity {
    LiveActivity {
        operation_id: operation.clone(),
        request_id: request.clone(),
        command,
        stage,
    }
}

fn cancelled(stage: LiveStage) -> LiveFailure {
    failure(LiveFailureCode::Cancelled, stage, "pause cancelled")
}

fn observed_epoch(snapshot: &LiveSnapshot) -> Option<NonZeroU64> {
    snapshot
        .guest_lifecycle
        .as_ref()
        .and_then(|status| status.freeze_ref.as_ref())
        .and_then(|reference| reference.freeze_epoch)
        .and_then(NonZeroU64::new)
}

fn resume_code(stage: ResumeStage) -> LiveFailureCode {
    match stage {
        ResumeStage::PrepareClock | ResumeStage::ClockAcknowledgement => {
            LiveFailureCode::ClockGenerationFailed
        }
        ResumeStage::Release => LiveFailureCode::NativeResumeFailed,
    }
}

fn resume_stage(stage: ResumeStage) -> LiveStage {
    match stage {
        ResumeStage::PrepareClock | ResumeStage::Release => LiveStage::ResumeNative,
        ResumeStage::ClockAcknowledgement => LiveStage::ResumeClock,
    }
}

fn stopped_resume(requested: &PauseToken) -> ResumeFailed {
    ResumeFailed {
        cause: failure(
            LiveFailureCode::Stopped,
            LiveStage::Admission,
            "stop preempted the resume",
        ),
        state: VmLifecycleState::Stopping,
        current_pause: None,
        recovery_failure: None,
        requested_token: requested.clone(),
    }
}

fn stopped_cancel(record: vm_spec::lifecycle::LiveOperationRecord) -> LiveCommandResult {
    LiveCommandResult::CancelOperation(CancelOperationOutcome::Failed {
        failed: CancelFailed {
            cause: failure(
                LiveFailureCode::Stopped,
                LiveStage::Admission,
                "stop preempted the cancellation",
            ),
            operation: record,
            state: VmLifecycleState::Stopping,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use protocol::v1::{AgentIdentity, AgentStatus, AgentStatusReport, AgentStatusState, VmState};
    use uuid::Uuid;
    use vm_spec::lifecycle::{LiveFailureCode, LiveStage};

    use crate::live::coordinator::{observe_status_barrier, GuestError, StatusBarrier};
    use crate::state::{new_instance_store, InstanceStore, ReadyAgentIdentity};

    fn source() -> (InstanceStore, ReadyAgentIdentity, AgentStatus) {
        let identity = ReadyAgentIdentity {
            instance_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
        };
        let status = AgentStatus {
            identity: Some(AgentIdentity {
                instance_id: Some(identity.instance_id.to_string()),
                boot_id: Some(identity.boot_id.to_string()),
                version: Some("source-agent".into()),
            }),
            report: Some(AgentStatusReport {
                observed_at: Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                state: Some(AgentStatusState::Ready as i32),
                ..AgentStatusReport::default()
            }),
        };
        let store = new_instance_store(Uuid::new_v4().to_string(), "handshake".into(), true);
        store
            .observe_status(status.clone(), Duration::from_secs(60))
            .unwrap();
        store.set_vm_state(VmState::Pausing, "resume").unwrap();
        (store, identity, status)
    }

    fn refused(error: GuestError, expected: LiveFailureCode, barrier: StatusBarrier) {
        let GuestError::Refused(failure) = error else {
            panic!("status barrier must fail definitively");
        };
        assert_eq!(failure.code, expected);
        assert_eq!(failure.stage, barrier.stage());
    }

    #[test]
    fn handshake_observes_full_status_without_granting_readiness() {
        let (store, identity, status) = source();
        let since = Instant::now();
        assert!(
            observe_status_barrier(&store, &identity, status, StatusBarrier::ResumeHandshake,)
                .is_ok()
        );
        assert_eq!(store.status_identity_since(since).unwrap(), Some(identity));
        assert_eq!(
            store.status().unwrap().readiness.unwrap().ready,
            Some(false)
        );
        // The handshake cannot satisfy a subsequent post-thaw receipt boundary.
        assert!(!store.prospective_readiness(Instant::now()).unwrap().0);
    }

    #[test]
    fn post_thaw_status_refresh_requires_new_receipt_and_ready_without_unfencing() {
        let (store, identity, mut status) = source();
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        status.report.as_mut().unwrap().lifecycle = Some(protocol::v1::GuestLifecycleStatus {
            state: protocol::v1::GuestLifecycleState::Thawed as i32,
            freeze_ref: Some(protocol::v1::FreezeRef {
                machine_id: machine_id.clone(),
                run_id: run_id.clone(),
                operation_id: Uuid::new_v4().to_string(),
                freeze_epoch: Some(1),
            }),
            machine_id,
            run_id,
            ..protocol::v1::GuestLifecycleStatus::default()
        });
        // The watch already delivered the thaw transition before its RPC
        // response. Neither that receipt nor the handshake can cross `since`.
        store
            .observe_status(status.clone(), crate::guest::STATUS_FRESHNESS)
            .unwrap();
        let since = Instant::now();
        assert_eq!(store.status_identity_since(since).unwrap(), None);
        assert!(!store.prospective_readiness(since).unwrap().0);

        let mut starting = status.clone();
        starting.report.as_mut().unwrap().state = Some(AgentStatusState::Starting as i32);
        assert!(
            observe_status_barrier(&store, &identity, starting, StatusBarrier::Readiness).is_ok()
        );
        assert_eq!(
            store.status_identity_since(since).unwrap(),
            Some(identity.clone())
        );
        assert!(!store.prospective_readiness(since).unwrap().0);

        assert!(
            observe_status_barrier(&store, &identity, status, StatusBarrier::Readiness).is_ok()
        );
        assert!(store.prospective_readiness(since).unwrap().0);
        assert_eq!(
            store.status().unwrap().readiness.unwrap().ready,
            Some(false),
            "fresh Ready testimony cannot grant public readiness while fenced"
        );
        assert!(store.live_snapshot().unwrap().ready_identity.is_none());
    }

    #[test]
    fn status_barriers_refuse_replaced_instance_or_boot_without_observing_it() {
        for barrier in [StatusBarrier::ResumeHandshake, StatusBarrier::Readiness] {
            for replace_boot in [false, true] {
                let (store, identity, mut status) = source();
                let returned = status.identity.as_mut().unwrap();
                if replace_boot {
                    returned.boot_id = Some(Uuid::new_v4().to_string());
                } else {
                    returned.instance_id = Some(Uuid::new_v4().to_string());
                }
                let since = Instant::now();
                refused(
                    observe_status_barrier(&store, &identity, status, barrier)
                        .err()
                        .unwrap(),
                    LiveFailureCode::GuestIdentityMismatch,
                    barrier,
                );
                assert_eq!(store.status_identity_since(since).unwrap(), None);
                assert_eq!(
                    store.live_snapshot().unwrap().observed_identity,
                    Some(identity)
                );
            }
        }
    }

    #[test]
    fn status_barriers_reject_missing_or_malformed_envelope_and_version_change() {
        let (store, identity, valid) = source();
        let mut cases = Vec::new();
        let mut status = valid.clone();
        status.identity = None;
        cases.push(status);
        let mut status = valid.clone();
        status.identity.as_mut().unwrap().instance_id = None;
        cases.push(status);
        let mut status = valid.clone();
        status.identity.as_mut().unwrap().boot_id = Some("not-a-uuid".into());
        cases.push(status);
        let mut status = valid.clone();
        status.identity.as_mut().unwrap().version = None;
        cases.push(status);
        let mut status = valid.clone();
        status.identity.as_mut().unwrap().version = Some("changed-agent".into());
        cases.push(status);
        let mut status = valid.clone();
        status.report = None;
        cases.push(status);
        let mut status = valid.clone();
        status.report.as_mut().unwrap().observed_at = None;
        cases.push(status);
        let mut status = valid.clone();
        status
            .report
            .as_mut()
            .unwrap()
            .observed_at
            .as_mut()
            .unwrap()
            .nanos = -1;
        cases.push(status);
        let mut status = valid.clone();
        status.report.as_mut().unwrap().state = Some(i32::MAX);
        cases.push(status);
        let mut status = valid;
        status.report.as_mut().unwrap().code = Some("INVALID_READY_CODE".into());
        cases.push(status);

        for barrier in [StatusBarrier::ResumeHandshake, StatusBarrier::Readiness] {
            for status in &cases {
                let since = Instant::now();
                let code = match barrier {
                    StatusBarrier::ResumeHandshake => LiveFailureCode::HandshakeFailed,
                    StatusBarrier::Readiness => LiveFailureCode::ReadinessFailed,
                };
                refused(
                    observe_status_barrier(&store, &identity, status.clone(), barrier)
                        .err()
                        .unwrap(),
                    code,
                    barrier,
                );
                assert_eq!(store.status_identity_since(since).unwrap(), None);
                assert_eq!(
                    store.live_snapshot().unwrap().observed_identity,
                    Some(identity.clone())
                );
            }
        }
    }

    #[cfg(feature = "mock-backend")]
    fn disconnected_source(
        handshake: Duration,
    ) -> (
        std::sync::Arc<crate::live::coordinator::LiveCoordinator>,
        ReadyAgentIdentity,
    ) {
        let (store, identity, _) = source();
        let config = crate::virt::VmConfig::builder("disconnected-source")
            .base_directory("/tmp")
            .kernel(std::path::Path::new("/mock-kernel"))
            .build();
        // Never started: the real connection path returns NotRunning, without
        // a scripted RPC response, filesystem fixture or native worker.
        let machine =
            crate::virt::VirtualMachine::with_backend(crate::virt::BackendKind::Mock, config)
                .unwrap();
        let coordinator = crate::live::coordinator::LiveCoordinator::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            std::sync::Arc::new(store),
            machine,
            crate::live::gate::LiveGate::new(),
            crate::live::coordinator::LiveTimeouts {
                handshake,
                readiness: handshake,
                ..crate::live::coordinator::LiveTimeouts::default()
            },
            None,
        )
        .unwrap();
        (coordinator, identity)
    }

    #[cfg(feature = "mock-backend")]
    #[tokio::test]
    async fn handshake_transport_failure_expires_despite_cached_status() {
        let (coordinator, identity) = disconnected_source(Duration::from_millis(30));
        let since = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            coordinator.guest_handshake(&identity),
        )
        .await
        .expect("transport retries must retain the original handshake deadline");
        let Err(GuestError::Unknown(failure)) = result else {
            panic!("cached status cannot replace a fresh control response");
        };
        assert_eq!(failure.code, LiveFailureCode::HandshakeFailed);
        assert_eq!(failure.stage, LiveStage::ResumeHandshake);
        assert_eq!(
            coordinator.store.status_identity_since(since).unwrap(),
            None
        );
    }

    #[cfg(feature = "mock-backend")]
    #[tokio::test]
    async fn handshake_stop_cancels_transport_retry() {
        let (coordinator, identity) = disconnected_source(Duration::from_secs(60));
        let pending = coordinator.guest_handshake(&identity);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
        coordinator.begin_stop();
        let result = tokio::time::timeout(Duration::from_secs(1), &mut pending)
            .await
            .expect("stop must interrupt the handshake's retry wait");
        assert!(matches!(result, Err(GuestError::Stopped)));
        assert!(!coordinator.gate.is_open());
    }

    #[cfg(feature = "mock-backend")]
    #[tokio::test]
    async fn post_thaw_readiness_refresh_expires_despite_cached_ready_status() {
        let (coordinator, identity) = disconnected_source(Duration::from_millis(30));
        coordinator.gate.close();
        let since = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            coordinator.await_readiness(since, &identity),
        )
        .await
        .expect("status retries must consume the original readiness deadline");
        let Err(GuestError::Unknown(failure)) = result else {
            panic!("cached readiness cannot replace a fresh post-thaw response");
        };
        assert_eq!(failure.code, LiveFailureCode::ReadinessFailed);
        assert_eq!(failure.stage, LiveStage::Readiness);
        assert_eq!(
            coordinator.store.status_identity_since(since).unwrap(),
            None
        );
        assert!(!coordinator.gate.is_open());
    }

    #[cfg(feature = "mock-backend")]
    #[tokio::test]
    async fn post_thaw_readiness_refresh_stop_cancels_transport_retry() {
        let (coordinator, identity) = disconnected_source(Duration::from_secs(60));
        let pending = coordinator.await_readiness(Instant::now(), &identity);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut pending)
                .await
                .is_err()
        );
        coordinator.begin_stop();
        let result = tokio::time::timeout(Duration::from_secs(1), &mut pending)
            .await
            .expect("stop must interrupt the post-thaw status retry");
        assert!(matches!(result, Err(GuestError::Stopped)));
        assert!(!coordinator.gate.is_open());
    }
}

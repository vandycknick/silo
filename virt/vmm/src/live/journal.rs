//! Run-lifetime request journal and operation table. Pure and synchronous: it
//! decides admission (replay, conflict, capability, ADR 0021 matrix, target
//! and token checks) and records results. The coordinator performs effects.
//!
//! Admission order for one request:
//!
//! ```text
//!   foreign machine/run ─► reject, never journaled
//!   same request ID ─────► identical inputs: stored result (or join pending)
//!                          different inputs: request-conflict, not journaled
//!   stopping ─────────────► monitor-stopping
//!   capability ───────────► new Pause / Capture / ReleaseCapture only
//!   matrix ───────────────► VmLifecycleState::admits
//!   target/token ─────────► operation, ownership and exact current token
//!   capture plan ─────────► plan, policy, binding, pause authority, preflight
//! ```
//!
//! A capture operation's phases:
//!
//! ```text
//!   Pipeline ─(cancel joins, wins before Sealing)─► Sealing ─► Continuing ─► Settled
//!      └── unsealed failure/cancel: continuation runs, then Settled
//! ```
use std::collections::HashMap;
use std::num::NonZeroU64;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vm_spec::capture::{
    CaptureConfiguration, CaptureContinuation, CaptureEvidenceReference, CaptureLaunchLease,
    CaptureObservation, CapturePauseAuthority, CapturePlan, CaptureReleaseDisposition,
    CaptureReleaseState, CaptureReleased, Sha256Digest,
};
use vm_spec::lifecycle::{
    CancelCompleted, CancelOperationOutcome, CaptureCommand, CaptureOutcome, CapturePolicy,
    CurrentPause, GetOperationOutcome, LiveCommand, LiveCommandKind, LiveCommandResult, LiveId,
    LiveLifecycle, LiveOperationReceipt, LiveOperationRecord, LiveRejection, LiveRejectionReason,
    OperationKind, OperationObservation, OperationOutcome, PauseOutcome, ReleaseCaptureCommand,
    ReleaseCaptureOutcome, ResumeCommand, VmLifecycleState,
};
use vm_spec::live::LiveOperationUnsupported;

pub(crate) type ResultSender = watch::Sender<Option<LiveCommandResult>>;
pub(crate) type ResultReceiver = watch::Receiver<Option<LiveCommandResult>>;

/// What a caller receives for a request.
// Replies stay inline: admission should not allocate a box just to return a result.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum Answer {
    Ready(LiveCommandResult),
    Wait(ResultReceiver),
}

/// This run's capture identity: what an admitted plan must bind exactly.
#[derive(Debug, Clone)]
pub(crate) struct CaptureBinding {
    pub(crate) configuration: CaptureConfiguration,
    pub(crate) configuration_digest: Sha256Digest,
    pub(crate) launch: CaptureLaunchLease,
}

/// Current monitor facts needed for admission.
#[derive(Debug, Clone)]
pub(crate) struct AdmissionView {
    pub(crate) state: VmLifecycleState,
    pub(crate) lifecycle: LiveLifecycle,
    /// `Err` with the live vector's exact reason when Pause is unsupported.
    pub(crate) pause: Result<(), LiveOperationUnsupported>,
    /// `Err` with the live vector's exact reason when Capture is unsupported.
    pub(crate) capture: Result<(), LiveOperationUnsupported>,
    /// Exact incremental capability admission for this build/lane.
    pub(crate) incremental: Result<(), LiveOperationUnsupported>,
    /// Present whenever the monitor can bind a capture plan.
    pub(crate) capture_binding: Option<CaptureBinding>,
    /// Fresh, ready, exact guest identity is present.
    pub(crate) guest_ready: bool,
}

/// Asynchronous preflight verdict for a new Pause or Capture, decided
/// outside the lock (native inventory, held sources, reservation).
#[derive(Debug, Clone)]
pub(crate) enum Eligibility {
    Unchecked,
    Eligible,
    Rejected(LiveRejectionReason, String),
}

#[allow(clippy::large_enum_variant)] // Preserve the inline Answer through admission.
#[derive(Debug)]
pub(crate) enum Admitted {
    Answer(Answer),
    /// A new Pause passed every synchronous check; query native inventory and
    /// admit again with the verdict.
    CheckNative,
    /// A new Capture passed every synchronous check; run its preflight and
    /// admit again with the verdict.
    CheckCapture,
    /// New Pause operation (operation ID = request ID) recorded in progress.
    Pause {
        operation: LiveId,
    },
    /// New Capture operation (capture ID = request ID) recorded in progress.
    /// `borrowed` is the exact user pause it binds without changing it.
    Capture {
        operation: LiveId,
        borrowed: Option<CurrentPause>,
    },
    /// The current authority was taken for this Resume.
    Resume {
        request: LiveId,
        current: CurrentPause,
        receiver: ResultReceiver,
    },
    /// The in-flight operation owner completes this request.
    Joined {
        receiver: ResultReceiver,
    },
    /// A failed Pausing operation needs native rollback and thaw.
    CancelFailedPause {
        request: LiveId,
        operation: LiveId,
        receiver: ResultReceiver,
    },
    /// The first release of a finished capture: release native ownership.
    Release {
        request: LiveId,
        operation: LiveId,
        disposition: CaptureReleaseDisposition,
        receiver: ResultReceiver,
    },
}

// Completed results dominate the retained journal; avoid an allocation per result.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum Stored {
    Done(LiveCommandResult),
    Pending(ResultSender),
}

#[derive(Debug)]
struct Entry {
    command: LiveCommand,
    stored: Stored,
}

/// Where an operation stands, independent of its public record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The operation pipeline task owns it.
    Pipeline,
    /// Failed Pausing: only cancel or stop leaves it.
    FailedPausing,
    /// A cancellation task owns it.
    Cancelling,
    /// The capture seal commit is in progress; cancel waits for its outcome.
    Sealing,
    /// The capture outcome is final; its source continuation is still running.
    Continuing,
    /// Finished; cancel has no effect.
    Settled,
}

/// What the worker may retain for one capture. Only a definitive answer
/// proves absence: an unanswered preparation may own every output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerPreparation {
    /// Never submitted, definitively refused, or reconciled as unknown to
    /// the worker: no worker owner exists.
    Absent,
    /// The worker reported the capture prepared and retains its owners.
    Prepared,
    /// Possibly admitted without a definitive answer: the worker may own the
    /// outputs and pin until exact observation resolves it.
    Uncertain,
}

/// Capture-specific facts, separate from the immutable operation record.
#[derive(Debug)]
pub(crate) struct CaptureFacts {
    pub(crate) plan: CapturePlan,
    pub(crate) continuation: CaptureContinuation,
    pub(crate) release: CaptureReleaseState,
    pub(crate) evidence: Option<CaptureEvidenceReference>,
    pub(crate) source_record: Option<Sha256Digest>,
    /// What the worker may retain for this operation; release resolves it.
    pub(crate) worker: WorkerPreparation,
    release_requests: Vec<LiveId>,
}

impl CaptureFacts {
    fn observation(&self) -> CaptureObservation {
        CaptureObservation {
            continuation: self.continuation.clone(),
            release: self.release.clone(),
            evidence: self.evidence.clone(),
            source_record_sha256: self.source_record,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Operation {
    pub(crate) record: LiveOperationRecord,
    pub(crate) freeze_epoch: Option<NonZeroU64>,
    pub(crate) phase: Phase,
    pub(crate) cancel: CancellationToken,
    cancel_requests: Vec<LiveId>,
    pub(crate) capture: Option<CaptureFacts>,
}

#[derive(Debug)]
pub(crate) struct Journal {
    machine_id: LiveId,
    run_id: LiveId,
    requests: HashMap<LiveId, Entry>,
    operations: HashMap<LiveId, Operation>,
    /// Current pause authority (also projected to status while Paused).
    pub(crate) current: Option<CurrentPause>,
    last_epoch: Option<NonZeroU64>,
    pub(crate) stopped: bool,
}

impl Journal {
    pub(crate) fn new(machine_id: LiveId, run_id: LiveId) -> Self {
        Self {
            machine_id,
            run_id,
            requests: HashMap::new(),
            operations: HashMap::new(),
            current: None,
            last_epoch: None,
            stopped: false,
        }
    }

    pub(crate) fn machine_id(&self) -> &LiveId {
        &self.machine_id
    }

    pub(crate) fn run_id(&self) -> &LiveId {
        &self.run_id
    }

    pub(crate) fn operation(&self, operation: &LiveId) -> Option<&Operation> {
        self.operations.get(operation)
    }

    pub(crate) fn operation_mut(&mut self, operation: &LiveId) -> Option<&mut Operation> {
        self.operations.get_mut(operation)
    }

    pub(crate) fn capture_mut(&mut self, operation: &LiveId) -> Option<&mut CaptureFacts> {
        self.operations
            .get_mut(operation)
            .and_then(|operation| operation.capture.as_mut())
    }

    /// Allocate the exact next guest freeze epoch. Epochs strictly increase
    /// across operations and recovery and never wrap.
    pub(crate) fn next_epoch(&mut self, observed: Option<NonZeroU64>) -> Option<NonZeroU64> {
        let base = self.last_epoch.max(observed).map_or(0, NonZeroU64::get);
        let next = NonZeroU64::new(base.checked_add(1)?)?;
        self.last_epoch = Some(next);
        Some(next)
    }

    pub(crate) fn admit(
        &mut self,
        command: &LiveCommand,
        view: &AdmissionView,
        eligibility: Eligibility,
    ) -> Admitted {
        let envelope = command.envelope();
        let kind = command.kind();
        if envelope.machine_id != self.machine_id {
            return Admitted::Answer(Answer::Ready(rejected(
                kind,
                LiveRejectionReason::WrongMachine,
                view.state,
                "command targets another machine",
            )));
        }
        if envelope.run_id != self.run_id {
            return Admitted::Answer(Answer::Ready(rejected(
                kind,
                LiveRejectionReason::WrongRun,
                view.state,
                "command targets another run",
            )));
        }
        let request = envelope.request_id.clone();
        if let Some(entry) = self.requests.get(&request) {
            if &entry.command != command {
                return Admitted::Answer(Answer::Ready(rejected(
                    kind,
                    LiveRejectionReason::RequestConflict,
                    view.state,
                    "request ID is already bound to different inputs",
                )));
            }
            return Admitted::Answer(match &entry.stored {
                Stored::Done(result) => Answer::Ready(result.clone()),
                Stored::Pending(sender) => Answer::Wait(sender.subscribe()),
            });
        }
        if self.stopped || view.state.is_stopping_or_terminal() {
            return self.reject(
                command,
                LiveRejectionReason::MonitorStopping,
                view.state,
                "monitor is stopping",
            );
        }
        let capability = match kind {
            LiveCommandKind::Pause => view.pause.as_ref().err(),
            LiveCommandKind::Capture | LiveCommandKind::ReleaseCapture => {
                view.capture.as_ref().err()
            }
            LiveCommandKind::Resume
            | LiveCommandKind::GetOperation
            | LiveCommandKind::CancelOperation => None,
        };
        if let Some(unsupported) = capability {
            return self.reject(
                command,
                LiveRejectionReason::Unsupported {
                    unsupported: unsupported.clone(),
                },
                view.state,
                format!("{kind} is unsupported for this machine"),
            );
        }
        if !view.state.admits(kind) {
            return self.reject(
                command,
                LiveRejectionReason::InvalidState,
                view.state,
                format!("{kind} is not admitted while {}", view.state),
            );
        }
        match command {
            LiveCommand::Pause(_) => self.admit_pause(command, view, eligibility),
            LiveCommand::Resume(resume) => self.admit_resume(command, resume, view),
            LiveCommand::CancelOperation(cancel) => {
                self.admit_cancel(command, &cancel.operation_id, view)
            }
            LiveCommand::GetOperation(get) => self.observe(command, &get.operation_id, view),
            LiveCommand::Capture(capture) => {
                self.admit_capture(command, capture, view, eligibility)
            }
            LiveCommand::ReleaseCapture(release) => self.admit_release(command, release, view),
        }
    }

    fn admit_pause(
        &mut self,
        command: &LiveCommand,
        view: &AdmissionView,
        eligibility: Eligibility,
    ) -> Admitted {
        if !view.guest_ready {
            return self.reject(
                command,
                LiveRejectionReason::InvalidState,
                view.state,
                "guest agent is not ready",
            );
        }
        match eligibility {
            Eligibility::Unchecked => return Admitted::CheckNative,
            Eligibility::Rejected(reason, message) => {
                return self.reject(command, reason, view.state, message);
            }
            Eligibility::Eligible => {}
        }
        let operation = command.envelope().request_id.clone();
        self.insert_operation(&operation, OperationKind::Pause, None);
        self.record(
            command,
            LiveCommandResult::Pause(PauseOutcome::Accepted {
                receipt: LiveOperationReceipt {
                    operation_id: operation.clone(),
                    kind: OperationKind::Pause,
                    state: VmLifecycleState::Pausing,
                },
            }),
        );
        Admitted::Pause { operation }
    }

    fn insert_operation(
        &mut self,
        operation: &LiveId,
        kind: OperationKind,
        capture: Option<CaptureFacts>,
    ) {
        self.operations.insert(
            operation.clone(),
            Operation {
                record: LiveOperationRecord {
                    operation_id: operation.clone(),
                    kind,
                    outcome: OperationOutcome::InProgress,
                },
                freeze_epoch: None,
                phase: Phase::Pipeline,
                cancel: CancellationToken::new(),
                cancel_requests: Vec::new(),
                capture,
            },
        );
    }

    /// ADR 0021 `Capture`/`Admission`: every refusal precedes any freeze or
    /// allocation and leaves the machine unchanged.
    fn admit_capture(
        &mut self,
        command: &LiveCommand,
        capture: &CaptureCommand,
        view: &AdmissionView,
        eligibility: Eligibility,
    ) -> Admitted {
        if let Err(message) = capture.validate_plan() {
            return self.reject(
                command,
                LiveRejectionReason::InvalidPlan,
                view.state,
                message,
            );
        }
        let plan = &capture.plan;
        if plan.policy == CapturePolicy::Incremental {
            if let Err(unsupported) = &view.incremental {
                return self.reject(
                    command,
                    LiveRejectionReason::Unsupported {
                        unsupported: unsupported.clone(),
                    },
                    view.state,
                    "incremental capture is not qualified",
                );
            }
        }
        let Some(binding) = &view.capture_binding else {
            return self.reject(
                command,
                LiveRejectionReason::InvalidPlan,
                view.state,
                "this run has no capture binding",
            );
        };
        if plan.configuration_digest != binding.configuration_digest
            || plan.configuration != binding.configuration
        {
            return self.reject(
                command,
                LiveRejectionReason::ConfigurationMismatch,
                view.state,
                "capture plan configuration and attachment inventory differ from this launch",
            );
        }
        if plan.reservation.launch_lease != binding.launch {
            return self.reject(
                command,
                LiveRejectionReason::InvalidPlan,
                view.state,
                "capture plan is bound to another launch storage lease",
            );
        }
        let borrowed = match (&plan.pause, view.state) {
            (CapturePauseAuthority::Acquire, VmLifecycleState::Running) => {
                if !view.guest_ready {
                    return self.reject(
                        command,
                        LiveRejectionReason::InvalidState,
                        view.state,
                        "guest agent is not ready",
                    );
                }
                None
            }
            (
                CapturePauseAuthority::Borrow {
                    pause_operation_id,
                    token,
                },
                VmLifecycleState::Paused,
            ) => {
                let Some(current) = self.current.clone() else {
                    return self.reject(
                        command,
                        LiveRejectionReason::InvalidState,
                        view.state,
                        "no current user pause to borrow",
                    );
                };
                if &current.operation_id != pause_operation_id {
                    return self.reject(
                        command,
                        LiveRejectionReason::WrongTarget,
                        view.state,
                        "borrowed pause operation does not own the current pause",
                    );
                }
                if token.generation < current.token.generation {
                    return self.reject(
                        command,
                        LiveRejectionReason::StaleToken,
                        view.state,
                        "borrowed pause token was consumed or superseded",
                    );
                }
                if token != &current.token {
                    return self.reject(
                        command,
                        LiveRejectionReason::ForeignToken,
                        view.state,
                        "borrowed pause token does not match the current authority",
                    );
                }
                Some(current)
            }
            (CapturePauseAuthority::Acquire, _) => {
                return self.reject(
                    command,
                    LiveRejectionReason::InvalidState,
                    view.state,
                    "a paused source is captured only by borrowing its user pause",
                )
            }
            (CapturePauseAuthority::Borrow { .. }, _) => {
                return self.reject(
                    command,
                    LiveRejectionReason::InvalidState,
                    view.state,
                    "a running source has no user pause to borrow",
                )
            }
        };
        match eligibility {
            Eligibility::Unchecked => return Admitted::CheckCapture,
            Eligibility::Rejected(reason, message) => {
                return self.reject(command, reason, view.state, message);
            }
            Eligibility::Eligible => {}
        }
        let operation = command.envelope().request_id.clone();
        self.insert_operation(
            &operation,
            OperationKind::Capture,
            Some(CaptureFacts {
                plan: plan.clone(),
                continuation: CaptureContinuation::Pending,
                release: CaptureReleaseState::Retained,
                evidence: None,
                source_record: None,
                worker: WorkerPreparation::Absent,
                release_requests: Vec::new(),
            }),
        );
        if let (Some(borrowed), Some(record)) = (&borrowed, self.operations.get_mut(&operation)) {
            record.freeze_epoch = Some(borrowed.freeze_epoch);
        }
        self.record(
            command,
            LiveCommandResult::Capture(CaptureOutcome::Accepted {
                receipt: LiveOperationReceipt {
                    operation_id: operation.clone(),
                    kind: OperationKind::Capture,
                    state: VmLifecycleState::Capturing,
                },
            }),
        );
        Admitted::Capture {
            operation,
            borrowed,
        }
    }

    fn admit_release(
        &mut self,
        command: &LiveCommand,
        release: &ReleaseCaptureCommand,
        view: &AdmissionView,
    ) -> Admitted {
        let request = command.envelope().request_id.clone();
        let Some(operation) = self.operations.get(&release.operation_id) else {
            return self.reject(
                command,
                LiveRejectionReason::OperationNotFound,
                view.state,
                "release target operation is unknown in this run",
            );
        };
        let Some(facts) = operation.capture.as_ref() else {
            return self.reject(
                command,
                LiveRejectionReason::WrongTarget,
                view.state,
                "release target is not a capture operation",
            );
        };
        if operation.phase != Phase::Settled {
            return self.reject(
                command,
                LiveRejectionReason::ContinuationPending,
                view.state,
                "the capture or its source continuation has not finished",
            );
        }
        if let CaptureReleaseState::Released {
            disposition,
            baseline_retained,
        } = &facts.release
        {
            let result = LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released {
                released: CaptureReleased {
                    operation_id: release.operation_id.clone(),
                    disposition: *disposition,
                    baseline_retained: *baseline_retained,
                    state: view.state,
                },
            });
            self.record(command, result.clone());
            return Admitted::Answer(Answer::Ready(result));
        }
        let first = facts.release_requests.is_empty();
        let receiver = self.pending(command);
        if let Some(facts) = self.capture_mut(&release.operation_id) {
            facts.release_requests.push(request.clone());
        }
        if first {
            Admitted::Release {
                request,
                operation: release.operation_id.clone(),
                disposition: release.disposition,
                receiver,
            }
        } else {
            Admitted::Joined { receiver }
        }
    }

    fn admit_resume(
        &mut self,
        command: &LiveCommand,
        resume: &ResumeCommand,
        view: &AdmissionView,
    ) -> Admitted {
        if !self.operations.contains_key(&resume.operation_id) {
            return self.reject(
                command,
                LiveRejectionReason::OperationNotFound,
                view.state,
                "resume target operation is unknown in this run",
            );
        }
        let Some(current) = self.current.clone() else {
            return self.reject(
                command,
                LiveRejectionReason::InvalidState,
                view.state,
                "no current pause authority",
            );
        };
        let token = &resume.token;
        if token.machine_id != self.machine_id || token.run_id != self.run_id {
            return self.reject(
                command,
                LiveRejectionReason::ForeignToken,
                view.state,
                "pause token belongs to another machine or run",
            );
        }
        // The owner is the Pause, or the preserving Capture it transferred to.
        if current.operation_id != resume.operation_id {
            return self.reject(
                command,
                LiveRejectionReason::WrongTarget,
                view.state,
                "target operation does not own the current pause",
            );
        }
        if token.generation < current.token.generation {
            return self.reject(
                command,
                LiveRejectionReason::StaleToken,
                view.state,
                "pause token was consumed or superseded",
            );
        }
        if token != &current.token {
            return self.reject(
                command,
                LiveRejectionReason::ForeignToken,
                view.state,
                "pause token does not match the current authority",
            );
        }
        let request = command.envelope().request_id.clone();
        let receiver = self.pending(command);
        self.current = None;
        Admitted::Resume {
            request,
            current,
            receiver,
        }
    }

    fn admit_cancel(
        &mut self,
        command: &LiveCommand,
        target: &LiveId,
        view: &AdmissionView,
    ) -> Admitted {
        let request = command.envelope().request_id.clone();
        let Some(operation) = self.operations.get(target) else {
            return self.reject(
                command,
                LiveRejectionReason::OperationNotFound,
                view.state,
                "cancel target operation is unknown in this run",
            );
        };
        match operation.phase {
            // Finished, or a sealed capture continuing its source: never
            // interrupted; the unchanged record is returned.
            Phase::Settled | Phase::Continuing => {
                let result =
                    LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed {
                        completed: CancelCompleted {
                            effective: false,
                            operation: operation.record.clone(),
                            state: view.state,
                        },
                    });
                self.record(command, result.clone());
                Admitted::Answer(Answer::Ready(result))
            }
            Phase::Pipeline | Phase::Cancelling | Phase::Sealing => {
                let receiver = self.pending(command);
                if let Some(operation) = self.operations.get_mut(target) {
                    operation.cancel_requests.push(request);
                    operation.cancel.cancel();
                    tracing::info!(
                        operation = %target,
                        request = %command.envelope().request_id,
                        "live cancellation admitted"
                    );
                }
                Admitted::Joined { receiver }
            }
            Phase::FailedPausing => {
                let receiver = self.pending(command);
                if let Some(operation) = self.operations.get_mut(target) {
                    operation.cancel_requests.push(request.clone());
                    operation.cancel.cancel();
                    operation.phase = Phase::Cancelling;
                }
                Admitted::CancelFailedPause {
                    request,
                    operation: target.clone(),
                    receiver,
                }
            }
        }
    }

    fn observe(
        &mut self,
        command: &LiveCommand,
        target: &LiveId,
        view: &AdmissionView,
    ) -> Admitted {
        let Some(operation) = self.operations.get(target) else {
            return self.reject(
                command,
                LiveRejectionReason::OperationNotFound,
                view.state,
                "operation is unknown in this run",
            );
        };
        let result = LiveCommandResult::GetOperation(GetOperationOutcome::Observation {
            observation: OperationObservation {
                operation: operation.record.clone(),
                state: view.state,
                current_pause: view.lifecycle.current_pause.clone(),
                activity: view.lifecycle.activity.clone(),
                capture: operation.capture.as_ref().map(CaptureFacts::observation),
            },
        });
        self.record(command, result.clone());
        Admitted::Answer(Answer::Ready(result))
    }

    fn reject(
        &mut self,
        command: &LiveCommand,
        reason: LiveRejectionReason,
        state: VmLifecycleState,
        message: impl Into<String>,
    ) -> Admitted {
        let result = rejected(command.kind(), reason, state, message);
        self.record(command, result.clone());
        Admitted::Answer(Answer::Ready(result))
    }

    fn record(&mut self, command: &LiveCommand, result: LiveCommandResult) {
        self.requests.insert(
            command.envelope().request_id.clone(),
            Entry {
                command: command.clone(),
                stored: Stored::Done(result),
            },
        );
    }

    fn pending(&mut self, command: &LiveCommand) -> ResultReceiver {
        let (sender, receiver) = watch::channel(None);
        self.requests.insert(
            command.envelope().request_id.clone(),
            Entry {
                command: command.clone(),
                stored: Stored::Pending(sender),
            },
        );
        receiver
    }

    /// Publish a pending request's final result; it is retained for the run.
    pub(crate) fn complete(&mut self, request: &LiveId, result: LiveCommandResult) {
        let Some(entry) = self.requests.get_mut(request) else {
            return;
        };
        if let Stored::Pending(sender) = &entry.stored {
            sender.send_replace(Some(result.clone()));
        }
        entry.stored = Stored::Done(result);
    }

    /// The first cancellation request of `operation`: its identity drives
    /// the single native CancelPause.
    pub(crate) fn peek_cancel_request(&self, operation: &LiveId) -> Option<LiveId> {
        self.operations
            .get(operation)
            .and_then(|operation| operation.cancel_requests.first().cloned())
    }

    /// Requests waiting on the cancellation of `operation`.
    pub(crate) fn take_cancel_requests(&mut self, operation: &LiveId) -> Vec<LiveId> {
        self.operations
            .get_mut(operation)
            .map(|operation| std::mem::take(&mut operation.cancel_requests))
            .unwrap_or_default()
    }

    /// Requests waiting on the release of `operation`.
    pub(crate) fn take_release_requests(&mut self, operation: &LiveId) -> Vec<LiveId> {
        self.capture_mut(operation)
            .map(|facts| std::mem::take(&mut facts.release_requests))
            .unwrap_or_default()
    }
}

pub(crate) fn rejected(
    kind: LiveCommandKind,
    reason: LiveRejectionReason,
    state: VmLifecycleState,
    message: impl Into<String>,
) -> LiveCommandResult {
    LiveCommandResult::rejected(kind, LiveRejection::new(reason, state, message))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use vm_spec::capture::{
        CaptureConfiguration, CaptureContinuation, CaptureLaunchLease, CapturePauseAuthority,
        CapturePlan, CaptureReleaseDisposition, CaptureReleaseState, CaptureReservation,
        CAPTURE_RECORD_VERSION,
    };
    use vm_spec::lifecycle::{
        CancelOperationCommand, CancelOperationOutcome, CaptureCommand, CaptureOutcome,
        CapturePolicy, CaptureResumePolicy, CurrentPause, GetOperationCommand, GetOperationOutcome,
        LiveCommand, LiveCommandEnvelope, LiveCommandKind, LiveCommandResult, LiveId,
        LiveLifecycle, LiveRejectionCode, LiveRejectionReason, OperationKind, OperationOutcome,
        PauseCommand, PauseOutcome, PauseOwner, PauseToken, ReleaseCaptureCommand,
        ReleaseCaptureOutcome, ResumeCommand, VmLifecycleState,
    };
    use vm_spec::live::{
        LiveBackend, LiveLane, LiveOperation, LiveOperationUnsupported, LiveReasonCode,
        LiveUnsupportedReason,
    };

    use crate::live::journal::{
        AdmissionView, Admitted, Answer, CaptureBinding, Eligibility, Journal, Phase,
    };

    fn id(last: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-0000000000{last:02x}")).unwrap()
    }

    const MACHINE: u8 = 1;
    const RUN: u8 = 2;
    const PAUSE: u8 = 0x10;
    const CAPTURE: u8 = 0x30;

    fn envelope(request: u8) -> LiveCommandEnvelope {
        LiveCommandEnvelope {
            machine_id: id(MACHINE),
            run_id: id(RUN),
            request_id: id(request),
        }
    }

    fn token(generation: u64) -> PauseToken {
        PauseToken {
            machine_id: id(MACHINE),
            run_id: id(RUN),
            generation: NonZeroU64::new(generation).unwrap(),
            owner: PauseOwner::User,
        }
    }

    fn unsupported(operation: LiveOperation, code: LiveReasonCode) -> LiveOperationUnsupported {
        LiveOperationUnsupported {
            operation,
            backend: LiveBackend::Krun,
            lane: LiveLane::KvmX86_64,
            reason: LiveUnsupportedReason::new(code),
        }
    }

    fn binding() -> CaptureBinding {
        let configuration = CaptureConfiguration::from_spec(&vm_spec::VmSpec::current()).unwrap();
        CaptureBinding {
            configuration_digest: configuration.digest().unwrap(),
            configuration,
            launch: CaptureLaunchLease {
                operation_id: id(0x7a),
                device: 3,
                inode: 4,
            },
        }
    }

    fn view(state: VmLifecycleState) -> AdmissionView {
        AdmissionView {
            state,
            lifecycle: LiveLifecycle::default(),
            pause: Ok(()),
            capture: Ok(()),
            incremental: Err(unsupported(
                LiveOperation::Incremental,
                LiveReasonCode::NotDelivered,
            )),
            capture_binding: Some(binding()),
            guest_ready: true,
        }
    }

    fn plan(request: u8, pause: CapturePauseAuthority) -> CapturePlan {
        let binding = binding();
        CapturePlan {
            version: CAPTURE_RECORD_VERSION,
            machine_id: id(MACHINE),
            run_id: id(RUN),
            capture_id: id(request),
            ram_bytes: binding.configuration.ram_bytes(),
            configuration_digest: binding.configuration_digest,
            configuration: binding.configuration,
            policy: CapturePolicy::Full,
            dirty_crossover_percent: 60,
            resume_policy: match pause {
                CapturePauseAuthority::Acquire => CaptureResumePolicy::ResumeIfAcquired,
                CapturePauseAuthority::Borrow { .. } => CaptureResumePolicy::Preserve,
            },
            pause,
            disks: Vec::new(),
            read_only_inputs: Vec::new(),
            reservation: CaptureReservation {
                storage_operation_id: id(0x7b),
                launch_lease: binding.launch,
                staging_bytes: 1 << 40,
            },
        }
    }

    fn capture_command(request: u8, pause: CapturePauseAuthority) -> LiveCommand {
        LiveCommand::Capture(Box::new(CaptureCommand {
            envelope: envelope(request),
            plan: plan(request, pause),
        }))
    }

    fn borrow() -> CapturePauseAuthority {
        CapturePauseAuthority::Borrow {
            pause_operation_id: id(PAUSE),
            token: token(1),
        }
    }

    fn command(kind: LiveCommandKind, request: u8, target: u8) -> LiveCommand {
        let envelope = envelope(request);
        match kind {
            LiveCommandKind::Pause => LiveCommand::Pause(PauseCommand { envelope }),
            LiveCommandKind::Resume => LiveCommand::Resume(ResumeCommand {
                envelope,
                operation_id: id(target),
                token: token(1),
            }),
            LiveCommandKind::GetOperation => LiveCommand::GetOperation(GetOperationCommand {
                envelope,
                operation_id: id(target),
            }),
            LiveCommandKind::CancelOperation => {
                LiveCommand::CancelOperation(CancelOperationCommand {
                    envelope,
                    operation_id: id(target),
                })
            }
            LiveCommandKind::Capture => capture_command(request, borrow()),
            LiveCommandKind::ReleaseCapture => LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope,
                operation_id: id(target),
                disposition: CaptureReleaseDisposition::Published,
            }),
        }
    }

    fn rejection(admitted: &Admitted) -> Option<LiveRejectionCode> {
        match admitted {
            Admitted::Answer(Answer::Ready(result)) => {
                result.rejection().map(|rejection| rejection.reason.code())
            }
            _ => None,
        }
    }

    fn ready(admitted: Admitted) -> LiveCommandResult {
        match admitted {
            Admitted::Answer(Answer::Ready(result)) => result,
            other => panic!("expected a ready answer, got {other:?}"),
        }
    }

    /// A journal holding one pause operation shaped for `state`: in progress
    /// while pausing, succeeded with current authority while paused.
    fn seeded(state: VmLifecycleState) -> Journal {
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        let admitted = journal.admit(
            &command(LiveCommandKind::Pause, PAUSE, 0),
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        );
        assert!(matches!(admitted, Admitted::Pause { .. }));
        let operation = journal.operation_mut(&id(PAUSE)).unwrap();
        if state != VmLifecycleState::Pausing {
            operation.phase = Phase::Settled;
            operation.freeze_epoch = NonZeroU64::new(1);
        }
        if state == VmLifecycleState::Paused {
            journal.current = Some(CurrentPause {
                token: token(1),
                operation_id: id(PAUSE),
                freeze_epoch: NonZeroU64::new(1).unwrap(),
            });
        }
        journal
    }

    /// Paused journal with an admitted borrowing capture in `phase`.
    fn captured(phase: Phase) -> Journal {
        let mut journal = seeded(VmLifecycleState::Paused);
        let admitted = journal.admit(
            &capture_command(CAPTURE, borrow()),
            &view(VmLifecycleState::Paused),
            Eligibility::Eligible,
        );
        assert!(matches!(
            admitted,
            Admitted::Capture {
                borrowed: Some(_),
                ..
            }
        ));
        journal.operation_mut(&id(CAPTURE)).unwrap().phase = phase;
        journal
    }

    #[test]
    fn every_state_and_command_follows_the_single_admission_matrix() {
        for state in VmLifecycleState::ALL {
            for kind in LiveCommandKind::ALL {
                let mut journal = seeded(*state);
                let admitted = journal.admit(
                    &command(*kind, 0x40, PAUSE),
                    &view(*state),
                    Eligibility::Eligible,
                );
                let expected = if state.is_stopping_or_terminal() {
                    Some(LiveRejectionCode::MonitorStopping)
                } else if !state.admits(*kind) {
                    Some(LiveRejectionCode::InvalidState)
                } else if *kind == LiveCommandKind::ReleaseCapture {
                    // Admitted state; the pause target is not a capture.
                    Some(LiveRejectionCode::WrongTarget)
                } else if *kind == LiveCommandKind::Capture && *state == VmLifecycleState::Running {
                    // The matrix admits it; a running source has nothing to borrow.
                    Some(LiveRejectionCode::InvalidState)
                } else {
                    None
                };
                assert_eq!(rejection(&admitted), expected, "{state} x {kind}");
                if expected.is_none() {
                    let shape_matches = match kind {
                        LiveCommandKind::Pause => matches!(admitted, Admitted::Pause { .. }),
                        LiveCommandKind::Resume => matches!(admitted, Admitted::Resume { .. }),
                        LiveCommandKind::CancelOperation => matches!(
                            admitted,
                            Admitted::Joined { .. } | Admitted::Answer(Answer::Ready(_))
                        ),
                        LiveCommandKind::GetOperation => {
                            matches!(admitted, Admitted::Answer(Answer::Ready(_)))
                        }
                        LiveCommandKind::Capture => {
                            matches!(admitted, Admitted::Capture { .. })
                        }
                        LiveCommandKind::ReleaseCapture => false,
                    };
                    assert!(shape_matches, "{state} x {kind}: {admitted:?}");
                }
            }
        }
    }

    #[test]
    fn replay_precedes_state_admission_and_conflicts_are_not_journaled() {
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        let pause = command(LiveCommandKind::Pause, PAUSE, 0);
        let first = journal.admit(
            &pause,
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        );
        assert!(matches!(first, Admitted::Pause { .. }));
        // Lost response retried after the machine paused: same receipt.
        let replay = ready(journal.admit(
            &pause,
            &view(VmLifecycleState::Paused),
            Eligibility::Unchecked,
        ));
        assert!(matches!(
            replay,
            LiveCommandResult::Pause(PauseOutcome::Accepted { ref receipt })
                if receipt.operation_id == id(PAUSE) && receipt.state == VmLifecycleState::Pausing
        ));
        // Same request ID, different inputs: conflict even where the new
        // command would be state-invalid; the original stays retained.
        for kind in [
            LiveCommandKind::GetOperation,
            LiveCommandKind::Resume,
            LiveCommandKind::CancelOperation,
            LiveCommandKind::Capture,
            LiveCommandKind::ReleaseCapture,
        ] {
            let conflicting = command(kind, PAUSE, PAUSE);
            let conflict = journal.admit(
                &conflicting,
                &view(VmLifecycleState::Stopped),
                Eligibility::Eligible,
            );
            assert_eq!(
                rejection(&conflict),
                Some(LiveRejectionCode::RequestConflict)
            );
        }
        assert_eq!(
            ready(journal.admit(
                &pause,
                &view(VmLifecycleState::Running),
                Eligibility::Eligible
            )),
            replay
        );
        // A rejected request also replays its result for identical inputs.
        let rejected = command(LiveCommandKind::Resume, 0x41, PAUSE);
        let first = ready(journal.admit(
            &rejected,
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        ));
        assert_eq!(
            first.rejection().unwrap().reason,
            LiveRejectionReason::InvalidState
        );
        assert_eq!(
            ready(journal.admit(
                &rejected,
                &view(VmLifecycleState::Paused),
                Eligibility::Eligible
            )),
            first
        );
    }

    #[test]
    fn foreign_machine_or_run_is_rejected_without_touching_run_local_ids() {
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        let mut foreign = command(LiveCommandKind::Pause, PAUSE, 0);
        let LiveCommand::Pause(pause) = &mut foreign else {
            unreachable!()
        };
        pause.envelope.run_id = id(0x77);
        let admitted = journal.admit(
            &foreign,
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        );
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::WrongRun));
        if let LiveCommand::Pause(pause) = &mut foreign {
            pause.envelope.machine_id = id(0x78);
        }
        let admitted = journal.admit(
            &foreign,
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        );
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::WrongMachine));
        // The same request ID is still free for this run.
        let own = command(LiveCommandKind::Pause, PAUSE, 0);
        assert!(matches!(
            journal.admit(
                &own,
                &view(VmLifecycleState::Running),
                Eligibility::Eligible
            ),
            Admitted::Pause { .. }
        ));
    }

    #[test]
    fn new_pause_requires_capability_guest_and_native_inventory() {
        let pause = |request| command(LiveCommandKind::Pause, request, 0);
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        let mut unsupported_view = view(VmLifecycleState::Running);
        let reason = unsupported(LiveOperation::Pause, LiveReasonCode::BuildExcluded);
        unsupported_view.pause = Err(reason.clone());
        let result = ready(journal.admit(&pause(0x20), &unsupported_view, Eligibility::Eligible));
        assert_eq!(
            result.rejection().unwrap().reason,
            LiveRejectionReason::Unsupported {
                unsupported: reason
            }
        );

        let mut not_ready = view(VmLifecycleState::Running);
        not_ready.guest_ready = false;
        let admitted = journal.admit(&pause(0x21), &not_ready, Eligibility::Eligible);
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::InvalidState));

        // Native inventory is queried outside the lock: not journaled until decided.
        assert!(matches!(
            journal.admit(
                &pause(0x22),
                &view(VmLifecycleState::Running),
                Eligibility::Unchecked
            ),
            Admitted::CheckNative
        ));
        let profile = unsupported(LiveOperation::Pause, LiveReasonCode::DeviceProfileRejected);
        let rejected = ready(journal.admit(
            &pause(0x22),
            &view(VmLifecycleState::Running),
            Eligibility::Rejected(
                LiveRejectionReason::Unsupported {
                    unsupported: profile.clone(),
                },
                "inventory".into(),
            ),
        ));
        assert_eq!(
            rejected.rejection().unwrap().reason,
            LiveRejectionReason::Unsupported {
                unsupported: profile
            }
        );
        assert!(journal.operation(&id(0x22)).is_none());
    }

    #[test]
    fn capture_refusals_precede_every_effect_and_name_their_reason() {
        let running = view(VmLifecycleState::Running);
        let paused = view(VmLifecycleState::Paused);
        let acquire = |request| capture_command(request, CapturePauseAuthority::Acquire);
        let mutate = |request, change: &dyn Fn(&mut CapturePlan)| {
            let mut command = acquire(request);
            if let LiveCommand::Capture(capture) = &mut command {
                change(&mut capture.plan);
            }
            command
        };
        let mut journal = seeded(VmLifecycleState::Paused);
        let cases: Vec<(LiveCommand, AdmissionView, LiveRejectionCode)> = vec![
            // Capability gate first, with the vector's reason.
            (
                acquire(0x80),
                AdmissionView {
                    capture: Err(unsupported(
                        LiveOperation::Capture,
                        LiveReasonCode::BuildExcluded,
                    )),
                    ..running.clone()
                },
                LiveRejectionCode::Unsupported,
            ),
            // Plan correlated with another request ID.
            (
                mutate(0x81, &|plan| plan.capture_id = id(0x99)),
                running.clone(),
                LiveRejectionCode::InvalidPlan,
            ),
            // Semantically invalid plan (RAM bytes do not match memory).
            (
                mutate(0x82, &|plan| plan.ram_bytes += 4096),
                running.clone(),
                LiveRejectionCode::InvalidPlan,
            ),
            // Incremental is not delivered.
            (
                mutate(0x83, &|plan| plan.policy = CapturePolicy::Incremental),
                running.clone(),
                LiveRejectionCode::Unsupported,
            ),
            // Valid plan for another configuration.
            (
                mutate(0x84, &|plan| {
                    plan.configuration.cpus = 7;
                    plan.configuration_digest = plan.configuration.digest().unwrap();
                }),
                running.clone(),
                LiveRejectionCode::ConfigurationMismatch,
            ),
            // Valid plan bound to another launch lease.
            (
                mutate(0x85, &|plan| plan.reservation.launch_lease.inode = 99),
                running.clone(),
                LiveRejectionCode::InvalidPlan,
            ),
            // A paused source cannot be acquired again.
            (
                acquire(0x86),
                paused.clone(),
                LiveRejectionCode::InvalidState,
            ),
            // Borrowing a stale or foreign token.
            (
                capture_command(
                    0x87,
                    CapturePauseAuthority::Borrow {
                        pause_operation_id: id(PAUSE),
                        token: token(2),
                    },
                ),
                paused.clone(),
                LiveRejectionCode::ForeignToken,
            ),
            (
                capture_command(
                    0x88,
                    CapturePauseAuthority::Borrow {
                        pause_operation_id: id(0x55),
                        token: token(1),
                    },
                ),
                paused.clone(),
                LiveRejectionCode::WrongTarget,
            ),
            // Guest not ready for a capture that must freeze.
            (
                acquire(0x89),
                AdmissionView {
                    guest_ready: false,
                    ..running.clone()
                },
                LiveRejectionCode::InvalidState,
            ),
        ];
        for (command, view, expected) in cases {
            let admitted = journal.admit(&command, &view, Eligibility::Eligible);
            assert_eq!(rejection(&admitted), Some(expected), "{command:?}");
            assert!(
                journal.current.is_some(),
                "a refused capture keeps the pause"
            );
            assert!(journal.operation(&command.envelope().request_id).is_none());
        }

        // Preflight runs outside the lock; its refusal is typed and journaled.
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        assert!(matches!(
            journal.admit(&acquire(0x90), &running, Eligibility::Unchecked),
            Admitted::CheckCapture
        ));
        let refused = ready(journal.admit(
            &acquire(0x90),
            &running,
            Eligibility::Rejected(
                LiveRejectionReason::ConfigurationMismatch,
                "writable attachment 0 has no held source".into(),
            ),
        ));
        assert_eq!(
            refused.rejection().unwrap().reason,
            LiveRejectionReason::ConfigurationMismatch
        );
        assert!(journal.operation(&id(0x90)).is_none());
        assert_eq!(
            ready(journal.admit(&acquire(0x90), &running, Eligibility::Unchecked)),
            refused,
            "the refusal replays"
        );
    }

    #[test]
    fn admitted_capture_records_a_receipt_and_keeps_the_borrowed_pause() {
        let mut journal = seeded(VmLifecycleState::Paused);
        let capture = capture_command(CAPTURE, borrow());
        let Admitted::Capture {
            operation,
            borrowed,
        } = journal.admit(
            &capture,
            &view(VmLifecycleState::Paused),
            Eligibility::Eligible,
        )
        else {
            panic!("capture admitted");
        };
        assert_eq!(operation, id(CAPTURE));
        assert_eq!(
            borrowed
                .as_ref()
                .map(|current| current.operation_id.clone()),
            Some(id(PAUSE))
        );
        assert!(
            journal.current.is_some(),
            "the user pause is borrowed, not consumed"
        );
        let record = &journal.operation(&id(CAPTURE)).unwrap().record;
        assert_eq!(record.kind, OperationKind::Capture);
        assert_eq!(record.outcome, OperationOutcome::InProgress);
        let replay = ready(journal.admit(
            &capture,
            &view(VmLifecycleState::Capturing),
            Eligibility::Unchecked,
        ));
        assert!(matches!(
            replay,
            LiveCommandResult::Capture(CaptureOutcome::Accepted { ref receipt })
                if receipt.state == VmLifecycleState::Capturing
        ));
        // Resume is refused by the matrix while capturing.
        let resume = journal.admit(
            &LiveCommand::Resume(ResumeCommand {
                envelope: envelope(0x91),
                operation_id: id(PAUSE),
                token: token(1),
            }),
            &view(VmLifecycleState::Capturing),
            Eligibility::Eligible,
        );
        assert_eq!(rejection(&resume), Some(LiveRejectionCode::InvalidState));
        // Observation carries capture facts and pending continuation.
        let observed = ready(journal.admit(
            &command(LiveCommandKind::GetOperation, 0x92, CAPTURE),
            &view(VmLifecycleState::Capturing),
            Eligibility::Eligible,
        ));
        let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) =
            observed
        else {
            panic!("observation");
        };
        let facts = observation.capture.expect("capture facts");
        assert_eq!(facts.continuation, CaptureContinuation::Pending);
        assert_eq!(facts.release, CaptureReleaseState::Retained);
    }

    #[test]
    fn capture_cancel_joins_before_the_seal_and_never_interrupts_continuation() {
        let cancel = |request| command(LiveCommandKind::CancelOperation, request, CAPTURE);
        let capturing = view(VmLifecycleState::Capturing);
        for phase in [Phase::Pipeline, Phase::Sealing] {
            let mut journal = captured(phase);
            assert!(matches!(
                journal.admit(&cancel(0xa0), &capturing, Eligibility::Eligible),
                Admitted::Joined { .. }
            ));
            assert!(journal
                .operation(&id(CAPTURE))
                .unwrap()
                .cancel
                .is_cancelled());
            assert_eq!(journal.take_cancel_requests(&id(CAPTURE)), vec![id(0xa0)]);
        }
        for phase in [Phase::Continuing, Phase::Settled] {
            let mut journal = captured(phase);
            let result = ready(journal.admit(&cancel(0xa1), &capturing, Eligibility::Eligible));
            let LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed { completed }) =
                result
            else {
                panic!("finished capture cancel is a no-op");
            };
            assert!(!completed.effective);
            assert!(!journal
                .operation(&id(CAPTURE))
                .unwrap()
                .cancel
                .is_cancelled());
        }
    }

    #[test]
    fn release_waits_for_continuation_and_is_idempotent() {
        let release = |request, disposition| {
            LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope: envelope(request),
                operation_id: id(CAPTURE),
                disposition,
            })
        };
        let paused = view(VmLifecycleState::Paused);
        let mut journal = captured(Phase::Continuing);
        let pending = journal.admit(
            &release(0xb0, CaptureReleaseDisposition::Published),
            &paused,
            Eligibility::Eligible,
        );
        assert_eq!(
            rejection(&pending),
            Some(LiveRejectionCode::ContinuationPending)
        );

        journal.operation_mut(&id(CAPTURE)).unwrap().phase = Phase::Settled;
        let Admitted::Release {
            request,
            operation,
            disposition,
            ..
        } = journal.admit(
            &release(0xb1, CaptureReleaseDisposition::Published),
            &paused,
            Eligibility::Eligible,
        )
        else {
            panic!("first release owns native release");
        };
        assert_eq!((request, operation), (id(0xb1), id(CAPTURE)));
        assert_eq!(disposition, CaptureReleaseDisposition::Published);
        assert!(matches!(
            journal.admit(
                &release(0xb2, CaptureReleaseDisposition::Published),
                &paused,
                Eligibility::Eligible
            ),
            Admitted::Joined { .. }
        ));
        assert_eq!(
            journal.take_release_requests(&id(CAPTURE)),
            vec![id(0xb1), id(0xb2)]
        );
        journal.capture_mut(&id(CAPTURE)).unwrap().release = CaptureReleaseState::Released {
            disposition: CaptureReleaseDisposition::Published,
            baseline_retained: true,
        };
        let again = ready(journal.admit(
            &release(0xb3, CaptureReleaseDisposition::Abandoned),
            &paused,
            Eligibility::Eligible,
        ));
        let LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released { released }) = again
        else {
            panic!("idempotent release");
        };
        assert_eq!(released.disposition, CaptureReleaseDisposition::Published);
        assert!(released.baseline_retained);
        // A pause target is never released.
        let wrong = journal.admit(
            &LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope: envelope(0xb4),
                operation_id: id(PAUSE),
                disposition: CaptureReleaseDisposition::Abandoned,
            }),
            &paused,
            Eligibility::Eligible,
        );
        assert_eq!(rejection(&wrong), Some(LiveRejectionCode::WrongTarget));
    }

    #[test]
    fn resume_validates_exact_current_authority() {
        let resume = |request: u8, target: u8, token: PauseToken| {
            LiveCommand::Resume(ResumeCommand {
                envelope: envelope(request),
                operation_id: id(target),
                token,
            })
        };
        let paused = view(VmLifecycleState::Paused);
        let mut journal = seeded(VmLifecycleState::Paused);
        journal.current.as_mut().unwrap().token.generation = NonZeroU64::new(3).unwrap();
        let cases = [
            (
                resume(0x50, 0x55, token(3)),
                LiveRejectionCode::OperationNotFound,
            ),
            (resume(0x51, PAUSE, token(2)), LiveRejectionCode::StaleToken),
            (
                resume(0x52, PAUSE, token(4)),
                LiveRejectionCode::ForeignToken,
            ),
            (
                resume(
                    0x53,
                    PAUSE,
                    PauseToken {
                        run_id: id(0x66),
                        ..token(3)
                    },
                ),
                LiveRejectionCode::ForeignToken,
            ),
            (
                resume(
                    0x54,
                    PAUSE,
                    PauseToken {
                        owner: PauseOwner::Capture {
                            operation_id: id(PAUSE),
                        },
                        ..token(3)
                    },
                ),
                LiveRejectionCode::ForeignToken,
            ),
        ];
        for (command, expected) in cases {
            let admitted = journal.admit(&command, &paused, Eligibility::Eligible);
            assert_eq!(rejection(&admitted), Some(expected), "{command:?}");
            assert!(
                journal.current.is_some(),
                "a refused resume releases nothing"
            );
        }
        let admitted = journal.admit(
            &resume(0x56, PAUSE, token(3)),
            &paused,
            Eligibility::Eligible,
        );
        let Admitted::Resume { current, .. } = admitted else {
            panic!("exact token resumes")
        };
        assert_eq!(current.token, token(3));
        assert!(
            journal.current.is_none(),
            "authority is taken by the resume"
        );
        // A second distinct resume finds no authority.
        let again = journal.admit(
            &resume(0x57, PAUSE, token(3)),
            &paused,
            Eligibility::Eligible,
        );
        assert_eq!(rejection(&again), Some(LiveRejectionCode::InvalidState));
    }

    #[test]
    fn resume_after_a_preserving_capture_targets_the_capture() {
        let mut journal = captured(Phase::Settled);
        // An acquired preserve transfers authority to the capture operation.
        journal.current = Some(CurrentPause {
            token: token(2),
            operation_id: id(CAPTURE),
            freeze_epoch: NonZeroU64::new(2).unwrap(),
        });
        let paused = view(VmLifecycleState::Paused);
        let resume = |request, target| {
            LiveCommand::Resume(ResumeCommand {
                envelope: envelope(request),
                operation_id: id(target),
                token: token(2),
            })
        };
        assert_eq!(
            rejection(&journal.admit(&resume(0xc0, PAUSE), &paused, Eligibility::Eligible)),
            Some(LiveRejectionCode::WrongTarget)
        );
        assert!(matches!(
            journal.admit(&resume(0xc1, CAPTURE), &paused, Eligibility::Eligible),
            Admitted::Resume { .. }
        ));
    }

    #[test]
    fn cancel_follows_operation_phase_and_never_touches_finished_operations() {
        let pausing = view(VmLifecycleState::Pausing);
        let cancel = |request| command(LiveCommandKind::CancelOperation, request, PAUSE);

        // In-flight pipeline: signalled, joined.
        let mut journal = seeded(VmLifecycleState::Pausing);
        assert!(matches!(
            journal.admit(&cancel(0x60), &pausing, Eligibility::Eligible),
            Admitted::Joined { .. }
        ));
        assert!(journal.operation(&id(PAUSE)).unwrap().cancel.is_cancelled());
        assert_eq!(journal.peek_cancel_request(&id(PAUSE)), Some(id(0x60)));

        // Failed Pausing: first cancel owns rollback, later ones join.
        let mut journal = seeded(VmLifecycleState::Pausing);
        journal.operation_mut(&id(PAUSE)).unwrap().phase = Phase::FailedPausing;
        assert!(matches!(
            journal.admit(&cancel(0x61), &pausing, Eligibility::Eligible),
            Admitted::CancelFailedPause { .. }
        ));
        assert_eq!(
            journal.operation(&id(PAUSE)).unwrap().phase,
            Phase::Cancelling
        );
        let Admitted::Joined { receiver } =
            journal.admit(&cancel(0x62), &pausing, Eligibility::Eligible)
        else {
            panic!("second cancel joins");
        };
        assert_eq!(
            journal.take_cancel_requests(&id(PAUSE)),
            vec![id(0x61), id(0x62)]
        );
        let outcome = ready(journal.admit(
            &cancel(0x63),
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        ));
        assert_eq!(
            outcome.rejection().unwrap().reason,
            LiveRejectionReason::InvalidState
        );
        let done = LiveCommandResult::CancelOperation(CancelOperationOutcome::Rejected {
            rejection: outcome.rejection().unwrap().clone(),
        });
        journal.complete(&id(0x62), done.clone());
        assert_eq!(receiver.borrow().clone(), Some(done));

        // Finished pause while Pausing (busy resume): no effect, unchanged.
        let mut journal = seeded(VmLifecycleState::Paused);
        let before = journal.operation(&id(PAUSE)).unwrap().record.clone();
        let result = ready(journal.admit(&cancel(0x64), &pausing, Eligibility::Eligible));
        let LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed { completed }) =
            result
        else {
            panic!("finished operation cancel is a no-op");
        };
        assert!(!completed.effective);
        assert_eq!(completed.operation, before);
        assert!(journal.current.is_some());
    }

    #[test]
    fn get_operation_replays_the_captured_observation() {
        let mut journal = seeded(VmLifecycleState::Pausing);
        let get = command(LiveCommandKind::GetOperation, 0x70, PAUSE);
        let first = ready(journal.admit(
            &get,
            &view(VmLifecycleState::Pausing),
            Eligibility::Eligible,
        ));
        journal.operation_mut(&id(PAUSE)).unwrap().record.outcome = OperationOutcome::Failed {
            failure: vm_spec::lifecycle::LiveFailure::new(
                vm_spec::lifecycle::LiveFailureCode::Cancelled,
                vm_spec::lifecycle::LiveStage::MonitorDrain,
                "cancelled",
            ),
        };
        let replay = ready(journal.admit(
            &get,
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        ));
        assert_eq!(replay, first);
        let fresh = ready(journal.admit(
            &command(LiveCommandKind::GetOperation, 0x71, PAUSE),
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        ));
        let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) =
            fresh
        else {
            panic!("observation");
        };
        assert!(matches!(
            observation.operation.outcome,
            OperationOutcome::Failed { .. }
        ));
        assert!(
            observation.capture.is_none(),
            "a pause has no capture facts"
        );
        let unknown = journal.admit(
            &command(LiveCommandKind::GetOperation, 0x72, 0x73),
            &view(VmLifecycleState::Running),
            Eligibility::Eligible,
        );
        assert_eq!(
            rejection(&unknown),
            Some(LiveRejectionCode::OperationNotFound)
        );
    }

    #[test]
    fn freeze_epochs_strictly_increase_across_operations_and_never_wrap() {
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        assert_eq!(journal.next_epoch(None), NonZeroU64::new(1));
        assert_eq!(journal.next_epoch(None), NonZeroU64::new(2));
        // A guest that already advanced (earlier run state) moves us past it.
        assert_eq!(journal.next_epoch(NonZeroU64::new(7)), NonZeroU64::new(8));
        // An older observation never moves the epoch backwards.
        assert_eq!(journal.next_epoch(NonZeroU64::new(3)), NonZeroU64::new(9));
        assert_eq!(journal.next_epoch(NonZeroU64::new(u64::MAX)), None);
    }
}

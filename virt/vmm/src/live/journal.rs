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
//! ```
use std::collections::HashMap;
use std::num::NonZeroU64;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vm_spec::lifecycle::{
    CancelCompleted, CancelOperationOutcome, CurrentPause, GetOperationOutcome, LiveCommand,
    LiveCommandKind, LiveCommandResult, LiveId, LiveLifecycle, LiveOperationReceipt,
    LiveOperationRecord, LiveRejection, LiveRejectionReason, OperationKind, OperationObservation,
    OperationOutcome, PauseOutcome, ResumeCommand, VmLifecycleState,
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

/// Current monitor facts needed for admission.
#[derive(Debug, Clone)]
pub(crate) struct AdmissionView {
    pub(crate) state: VmLifecycleState,
    pub(crate) lifecycle: LiveLifecycle,
    /// `Err` with the live vector's exact reason when Pause is unsupported.
    pub(crate) pause: Result<(), LiveOperationUnsupported>,
    /// Capture/ReleaseCapture are not delivered in this phase.
    pub(crate) capture: LiveOperationUnsupported,
    /// Fresh, ready, exact guest identity is present.
    pub(crate) guest_ready: bool,
}

/// Native inventory verdict for a new Pause, queried outside the lock.
#[derive(Debug, Clone)]
pub(crate) enum NativeEligibility {
    Unchecked,
    Eligible,
    Rejected(LiveOperationUnsupported),
}

#[allow(clippy::large_enum_variant)] // Preserve the inline Answer through admission.
#[derive(Debug)]
pub(crate) enum Admitted {
    Answer(Answer),
    /// A new Pause passed every synchronous check; query native inventory and
    /// admit again with the verdict.
    CheckNative,
    /// New Pause operation (operation ID = request ID) recorded in progress.
    Pause {
        operation: LiveId,
    },
    /// The current authority was taken for this Resume.
    Resume {
        request: LiveId,
        current: CurrentPause,
        receiver: ResultReceiver,
    },
    /// The in-flight pause pipeline was signalled; it completes this request.
    CancelJoined {
        receiver: ResultReceiver,
    },
    /// A failed Pausing operation needs native rollback and thaw.
    CancelFailedPause {
        request: LiveId,
        operation: LiveId,
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

/// Where a Pause operation stands, independent of its public record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The pause pipeline task owns it.
    Pipeline,
    /// Failed Pausing: only cancel or stop leaves it.
    FailedPausing,
    /// A cancellation task owns it.
    Cancelling,
    /// Finished; cancel has no effect.
    Settled,
}

#[derive(Debug)]
pub(crate) struct Operation {
    pub(crate) record: LiveOperationRecord,
    pub(crate) freeze_epoch: Option<NonZeroU64>,
    pub(crate) phase: Phase,
    pub(crate) cancel: CancellationToken,
    cancel_requests: Vec<LiveId>,
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
        native: NativeEligibility,
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
        match kind {
            LiveCommandKind::Pause => {
                if let Err(unsupported) = &view.pause {
                    return self.reject(
                        command,
                        LiveRejectionReason::Unsupported {
                            unsupported: unsupported.clone(),
                        },
                        view.state,
                        "pause is unsupported for this machine",
                    );
                }
            }
            LiveCommandKind::Capture | LiveCommandKind::ReleaseCapture => {
                return self.reject(
                    command,
                    LiveRejectionReason::Unsupported {
                        unsupported: view.capture.clone(),
                    },
                    view.state,
                    "capture is not delivered",
                );
            }
            LiveCommandKind::Resume
            | LiveCommandKind::GetOperation
            | LiveCommandKind::CancelOperation => {}
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
            LiveCommand::Pause(_) => self.admit_pause(command, view, native),
            LiveCommand::Resume(resume) => self.admit_resume(command, resume, view),
            LiveCommand::CancelOperation(cancel) => {
                self.admit_cancel(command, &cancel.operation_id, view)
            }
            LiveCommand::GetOperation(get) => self.observe(command, &get.operation_id, view),
            LiveCommand::Capture(_) | LiveCommand::ReleaseCapture(_) => self.reject(
                command,
                LiveRejectionReason::Unsupported {
                    unsupported: view.capture.clone(),
                },
                view.state,
                "capture is not delivered",
            ),
        }
    }

    fn admit_pause(
        &mut self,
        command: &LiveCommand,
        view: &AdmissionView,
        native: NativeEligibility,
    ) -> Admitted {
        if !view.guest_ready {
            return self.reject(
                command,
                LiveRejectionReason::InvalidState,
                view.state,
                "guest agent is not ready",
            );
        }
        match native {
            NativeEligibility::Unchecked => return Admitted::CheckNative,
            NativeEligibility::Rejected(unsupported) => {
                return self.reject(
                    command,
                    LiveRejectionReason::Unsupported { unsupported },
                    view.state,
                    "native live provider inventory is not supported",
                );
            }
            NativeEligibility::Eligible => {}
        }
        let operation = command.envelope().request_id.clone();
        self.operations.insert(
            operation.clone(),
            Operation {
                record: LiveOperationRecord {
                    operation_id: operation.clone(),
                    kind: OperationKind::Pause,
                    outcome: OperationOutcome::InProgress,
                },
                freeze_epoch: None,
                phase: Phase::Pipeline,
                cancel: CancellationToken::new(),
                cancel_requests: Vec::new(),
            },
        );
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

    fn admit_resume(
        &mut self,
        command: &LiveCommand,
        resume: &ResumeCommand,
        view: &AdmissionView,
    ) -> Admitted {
        let Some(operation) = self.operations.get(&resume.operation_id) else {
            return self.reject(
                command,
                LiveRejectionReason::OperationNotFound,
                view.state,
                "resume target operation is unknown in this run",
            );
        };
        if operation.record.kind != OperationKind::Pause {
            return self.reject(
                command,
                LiveRejectionReason::WrongTarget,
                view.state,
                "resume target is not a pause operation",
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
        if operation.record.kind != OperationKind::Pause {
            return self.reject(
                command,
                LiveRejectionReason::WrongTarget,
                view.state,
                "cancel target is not a pause operation",
            );
        }
        match operation.phase {
            Phase::Settled => {
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
            Phase::Pipeline | Phase::Cancelling => {
                let receiver = self.pending(command);
                if let Some(operation) = self.operations.get_mut(target) {
                    operation.cancel_requests.push(request);
                    operation.cancel.cancel();
                }
                Admitted::CancelJoined { receiver }
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

    use vm_spec::lifecycle::{
        CancelOperationCommand, CancelOperationOutcome, CaptureCommand, CapturePolicy,
        CaptureResumePolicy, CurrentPause, GetOperationCommand, GetOperationOutcome, LiveCommand,
        LiveCommandEnvelope, LiveCommandKind, LiveCommandResult, LiveId, LiveLifecycle,
        LiveRejectionCode, LiveRejectionReason, OperationOutcome, PauseCommand, PauseOutcome,
        PauseOwner, PauseToken, ReleaseCaptureCommand, ResumeCommand, VmLifecycleState,
    };
    use vm_spec::live::{
        LiveBackend, LiveLane, LiveOperation, LiveOperationUnsupported, LiveReasonCode,
        LiveUnsupportedReason,
    };

    use crate::live::journal::{
        AdmissionView, Admitted, Answer, Journal, NativeEligibility, Phase,
    };

    fn id(last: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-0000000000{last:02x}")).unwrap()
    }

    const MACHINE: u8 = 1;
    const RUN: u8 = 2;
    const PAUSE: u8 = 0x10;

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

    fn view(state: VmLifecycleState) -> AdmissionView {
        AdmissionView {
            state,
            lifecycle: LiveLifecycle::default(),
            pause: Ok(()),
            capture: unsupported(LiveOperation::Capture, LiveReasonCode::NotDelivered),
            guest_ready: true,
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
            LiveCommandKind::Capture => LiveCommand::Capture(CaptureCommand {
                envelope,
                expected_configuration_digest: "sha256:digest".into(),
                policy: CapturePolicy::Full,
                resume_policy: CaptureResumePolicy::Preserve,
            }),
            LiveCommandKind::ReleaseCapture => LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
                envelope,
                operation_id: id(target),
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
            NativeEligibility::Eligible,
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

    #[test]
    fn every_state_and_command_follows_the_single_admission_matrix() {
        for state in VmLifecycleState::ALL {
            for kind in LiveCommandKind::ALL {
                let mut journal = seeded(*state);
                let admitted = journal.admit(
                    &command(*kind, 0x40, PAUSE),
                    &view(*state),
                    NativeEligibility::Eligible,
                );
                let expected = if state.is_stopping_or_terminal() {
                    Some(LiveRejectionCode::MonitorStopping)
                } else if matches!(
                    kind,
                    LiveCommandKind::Capture | LiveCommandKind::ReleaseCapture
                ) {
                    Some(LiveRejectionCode::Unsupported)
                } else if !state.admits(*kind) {
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
                            Admitted::CancelJoined { .. } | Admitted::Answer(Answer::Ready(_))
                        ),
                        LiveCommandKind::GetOperation => {
                            matches!(admitted, Admitted::Answer(Answer::Ready(_)))
                        }
                        LiveCommandKind::Capture | LiveCommandKind::ReleaseCapture => false,
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
            NativeEligibility::Eligible,
        );
        assert!(matches!(first, Admitted::Pause { .. }));
        // Lost response retried after the machine paused: same receipt.
        let replay = ready(journal.admit(
            &pause,
            &view(VmLifecycleState::Paused),
            NativeEligibility::Unchecked,
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
        ] {
            let conflicting = command(kind, PAUSE, PAUSE);
            let conflict = journal.admit(
                &conflicting,
                &view(VmLifecycleState::Stopped),
                NativeEligibility::Eligible,
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
                NativeEligibility::Eligible
            )),
            replay
        );
        // A rejected request also replays its result for identical inputs.
        let rejected = command(LiveCommandKind::Resume, 0x41, PAUSE);
        let first = ready(journal.admit(
            &rejected,
            &view(VmLifecycleState::Running),
            NativeEligibility::Eligible,
        ));
        assert_eq!(
            first.rejection().unwrap().reason,
            LiveRejectionReason::InvalidState
        );
        assert_eq!(
            ready(journal.admit(
                &rejected,
                &view(VmLifecycleState::Paused),
                NativeEligibility::Eligible
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
            NativeEligibility::Eligible,
        );
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::WrongRun));
        pause_machine(&mut foreign, id(0x78));
        let admitted = journal.admit(
            &foreign,
            &view(VmLifecycleState::Running),
            NativeEligibility::Eligible,
        );
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::WrongMachine));
        // The same request ID is still free for this run.
        let own = command(LiveCommandKind::Pause, PAUSE, 0);
        assert!(matches!(
            journal.admit(
                &own,
                &view(VmLifecycleState::Running),
                NativeEligibility::Eligible
            ),
            Admitted::Pause { .. }
        ));
    }

    fn pause_machine(command: &mut LiveCommand, machine: LiveId) {
        if let LiveCommand::Pause(pause) = command {
            pause.envelope.machine_id = machine;
        }
    }

    #[test]
    fn new_pause_requires_capability_guest_and_native_inventory() {
        let pause = |request| command(LiveCommandKind::Pause, request, 0);
        let mut journal = Journal::new(id(MACHINE), id(RUN));
        let mut unsupported_view = view(VmLifecycleState::Running);
        let reason = unsupported(LiveOperation::Pause, LiveReasonCode::LaneNotQualified);
        unsupported_view.pause = Err(reason.clone());
        let result =
            ready(journal.admit(&pause(0x20), &unsupported_view, NativeEligibility::Eligible));
        assert_eq!(
            result.rejection().unwrap().reason,
            LiveRejectionReason::Unsupported {
                unsupported: reason
            }
        );

        let mut not_ready = view(VmLifecycleState::Running);
        not_ready.guest_ready = false;
        let admitted = journal.admit(&pause(0x21), &not_ready, NativeEligibility::Eligible);
        assert_eq!(rejection(&admitted), Some(LiveRejectionCode::InvalidState));

        // Native inventory is queried outside the lock: not journaled until decided.
        assert!(matches!(
            journal.admit(
                &pause(0x22),
                &view(VmLifecycleState::Running),
                NativeEligibility::Unchecked
            ),
            Admitted::CheckNative
        ));
        let profile = unsupported(LiveOperation::Pause, LiveReasonCode::DeviceProfileRejected);
        let rejected = ready(journal.admit(
            &pause(0x22),
            &view(VmLifecycleState::Running),
            NativeEligibility::Rejected(profile.clone()),
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
    fn capture_and_release_are_typed_not_delivered_without_effects() {
        let mut journal = seeded(VmLifecycleState::Paused);
        for kind in [LiveCommandKind::Capture, LiveCommandKind::ReleaseCapture] {
            let result = ready(journal.admit(
                &command(kind, 0x30 + kind as u8, PAUSE),
                &view(VmLifecycleState::Paused),
                NativeEligibility::Eligible,
            ));
            let LiveRejectionReason::Unsupported { unsupported } =
                &result.rejection().unwrap().reason
            else {
                panic!("capture must be unsupported");
            };
            assert_eq!(unsupported.reason.code, LiveReasonCode::NotDelivered);
            assert_eq!(result.kind(), kind);
        }
        assert!(
            journal.current.is_some(),
            "capture must not consume the pause"
        );
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
            let admitted = journal.admit(&command, &paused, NativeEligibility::Eligible);
            assert_eq!(rejection(&admitted), Some(expected), "{command:?}");
            assert!(
                journal.current.is_some(),
                "a refused resume releases nothing"
            );
        }
        let admitted = journal.admit(
            &resume(0x56, PAUSE, token(3)),
            &paused,
            NativeEligibility::Eligible,
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
            NativeEligibility::Eligible,
        );
        assert_eq!(rejection(&again), Some(LiveRejectionCode::InvalidState));
    }

    #[test]
    fn cancel_follows_operation_phase_and_never_touches_finished_operations() {
        let pausing = view(VmLifecycleState::Pausing);
        let cancel = |request| command(LiveCommandKind::CancelOperation, request, PAUSE);

        // In-flight pipeline: signalled, joined.
        let mut journal = seeded(VmLifecycleState::Pausing);
        assert!(matches!(
            journal.admit(&cancel(0x60), &pausing, NativeEligibility::Eligible),
            Admitted::CancelJoined { .. }
        ));
        assert!(journal.operation(&id(PAUSE)).unwrap().cancel.is_cancelled());
        assert_eq!(journal.peek_cancel_request(&id(PAUSE)), Some(id(0x60)));

        // Failed Pausing: first cancel owns rollback, later ones join.
        let mut journal = seeded(VmLifecycleState::Pausing);
        journal.operation_mut(&id(PAUSE)).unwrap().phase = Phase::FailedPausing;
        assert!(matches!(
            journal.admit(&cancel(0x61), &pausing, NativeEligibility::Eligible),
            Admitted::CancelFailedPause { .. }
        ));
        assert_eq!(
            journal.operation(&id(PAUSE)).unwrap().phase,
            Phase::Cancelling
        );
        let Admitted::CancelJoined { receiver } =
            journal.admit(&cancel(0x62), &pausing, NativeEligibility::Eligible)
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
            NativeEligibility::Eligible,
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
        let result = ready(journal.admit(&cancel(0x64), &pausing, NativeEligibility::Eligible));
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
            NativeEligibility::Eligible,
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
            NativeEligibility::Eligible,
        ));
        assert_eq!(replay, first);
        let fresh = ready(journal.admit(
            &command(LiveCommandKind::GetOperation, 0x71, PAUSE),
            &view(VmLifecycleState::Running),
            NativeEligibility::Eligible,
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
        let unknown = journal.admit(
            &command(LiveCommandKind::GetOperation, 0x72, 0x73),
            &view(VmLifecycleState::Running),
            NativeEligibility::Eligible,
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

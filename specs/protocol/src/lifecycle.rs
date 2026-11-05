//! Strict live-command conversions. Missing, unknown or UNSPECIFIED data is a
//! protocol error; decoded values are validated before use.
use std::num::NonZeroU64;

use crate::v1 as wire;
use vm_spec::lifecycle as domain;

fn required<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing lifecycle field {field}"))
}

fn id(value: Option<String>, field: &str) -> Result<domain::LiveId, String> {
    domain::LiveId::try_from(required(value, field)?).map_err(|error| format!("{field}: {error}"))
}

fn nonzero(value: Option<u64>, field: &str) -> Result<NonZeroU64, String> {
    NonZeroU64::new(required(value, field)?).ok_or_else(|| format!("{field} must be nonzero"))
}

fn diagnostic(value: Option<String>) -> Result<Option<domain::Diagnostic>, String> {
    value.map(domain::Diagnostic::try_from).transpose()
}

fn read_enum<W, D>(value: Option<i32>, field: &str) -> Result<D, String>
where
    W: TryFrom<i32>,
    D: TryFrom<W, Error = String>,
{
    let wire = W::try_from(required(value, field)?).map_err(|_| format!("unknown {field}"))?;
    D::try_from(wire).map_err(|error| format!("{field}: {error}"))
}

macro_rules! wire_enum {
    ($domain:ident <=> $wire:ident { $($variant:ident = $wire_variant:ident),+ $(,)? }) => {
        impl From<domain::$domain> for wire::$wire {
            fn from(value: domain::$domain) -> Self {
                match value { $(domain::$domain::$variant => Self::$wire_variant),+ }
            }
        }
        impl TryFrom<wire::$wire> for domain::$domain {
            type Error = String;
            fn try_from(value: wire::$wire) -> Result<Self, String> {
                match value {
                    $(wire::$wire::$wire_variant => Ok(Self::$variant),)+
                    wire::$wire::Unspecified => Err(concat!("unspecified ", stringify!($wire)).into()),
                }
            }
        }
    };
}

fn number<W: Into<i32>>(value: W) -> Option<i32> {
    Some(value.into())
}

wire_enum!(VmLifecycleState <=> VmState {
    Starting = Starting,
    Running = Running,
    Stopping = Stopping,
    Stopped = Stopped,
    Failed = Failed,
    Pausing = Pausing,
    Paused = Paused,
    Capturing = Capturing,
    Restoring = Restoring,
    Activating = Activating,
    ActivationFailed = ActivationFailed,
    Error = Error,
});
wire_enum!(LiveCommandKind <=> LiveCommandKind {
    Pause = Pause,
    Resume = Resume,
    GetOperation = GetOperation,
    CancelOperation = CancelOperation,
    Capture = Capture,
    ReleaseCapture = ReleaseCapture,
});
wire_enum!(OperationKind <=> OperationKind { Pause = Pause, Capture = Capture });
wire_enum!(OperationStatus <=> OperationStatus {
    InProgress = InProgress,
    Succeeded = Succeeded,
    Failed = Failed,
});
wire_enum!(CapturePolicy <=> CapturePolicy { Full = Full, Incremental = Incremental });
wire_enum!(CaptureResumePolicy <=> CaptureResumePolicy {
    ResumeIfAcquired = ResumeIfAcquired,
    Preserve = Preserve,
});
wire_enum!(LiveStage <=> LiveStage {
    MonitorDrain = MonitorDrain,
    GuestFreeze = GuestFreeze,
    NativePause = NativePause,
    PauseFailed = PauseFailed,
    RollbackThaw = RollbackThaw,
    CancelNative = CancelNative,
    CancelThaw = CancelThaw,
    ResumeNative = ResumeNative,
    ResumeClock = ResumeClock,
    ResumeHandshake = ResumeHandshake,
    ResumeThaw = ResumeThaw,
    Readiness = Readiness,
    RecoveryFreeze = RecoveryFreeze,
    RecoveryPause = RecoveryPause,
    Admission = Admission,
});
wire_enum!(LiveFailureCode <=> LiveFailureCode {
    DrainTimedOut = DrainTimedOut,
    GuestUnavailable = GuestUnavailable,
    GuestIdentityMismatch = GuestIdentityMismatch,
    FreezeFailed = FreezeFailed,
    FreezeTimedOut = FreezeTimedOut,
    NativePauseFailed = NativePauseFailed,
    NativeUncertain = NativeUncertain,
    Cancelled = Cancelled,
    NativeRollbackFailed = NativeRollbackFailed,
    ThawFailed = ThawFailed,
    ThawUnacknowledged = ThawUnacknowledged,
    NativeResumeFailed = NativeResumeFailed,
    ClockGenerationFailed = ClockGenerationFailed,
    HandshakeFailed = HandshakeFailed,
    ReadinessFailed = ReadinessFailed,
    RecoveryFreezeFailed = RecoveryFreezeFailed,
    RecoveryPauseFailed = RecoveryPauseFailed,
    WorkerLost = WorkerLost,
    Stopped = Stopped,
    DeadlineExceeded = DeadlineExceeded,
});
wire_enum!(LiveRejectionCode <=> LiveRejectionCode {
    WrongMachine = WrongMachine,
    WrongRun = WrongRun,
    RequestConflict = RequestConflict,
    InvalidState = InvalidState,
    OperationNotFound = OperationNotFound,
    StaleToken = StaleToken,
    ForeignToken = ForeignToken,
    Unsupported = Unsupported,
    WrongTarget = WrongTarget,
    MonitorStopping = MonitorStopping,
});
wire_enum!(GuestLifecycleState <=> GuestLifecycleState {
    Running = Running,
    Freezing = Freezing,
    Frozen = Frozen,
    Activating = Activating,
    ActivatedFrozen = ActivatedFrozen,
    Thawing = Thawing,
    Thawed = Thawed,
    FreezeFailed = FreezeFailed,
    ActivationFailed = ActivationFailed,
    Faulted = Faulted,
});

/// Decode a raw wire VmState number.
pub fn vm_state_from_wire(value: Option<i32>) -> Result<domain::VmLifecycleState, String> {
    read_enum::<wire::VmState, _>(value, "vm.state")
}

impl From<domain::LiveCommandEnvelope> for wire::LiveCommandEnvelope {
    fn from(value: domain::LiveCommandEnvelope) -> Self {
        Self {
            machine_id: Some(value.machine_id.into()),
            run_id: Some(value.run_id.into()),
            request_id: Some(value.request_id.into()),
        }
    }
}
impl TryFrom<wire::LiveCommandEnvelope> for domain::LiveCommandEnvelope {
    type Error = String;
    fn try_from(value: wire::LiveCommandEnvelope) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: id(value.machine_id, "envelope.machineId")?,
            run_id: id(value.run_id, "envelope.runId")?,
            request_id: id(value.request_id, "envelope.requestId")?,
        })
    }
}

fn envelope(
    value: Option<wire::LiveCommandEnvelope>,
) -> Result<domain::LiveCommandEnvelope, String> {
    required(value, "envelope")?.try_into()
}

impl From<domain::PauseOwner> for wire::PauseOwner {
    fn from(value: domain::PauseOwner) -> Self {
        use wire::pause_owner::Owner;
        Self {
            owner: Some(match value {
                domain::PauseOwner::User => Owner::User(()),
                domain::PauseOwner::Capture { operation_id } => {
                    Owner::CaptureOperationId(operation_id.into())
                }
            }),
        }
    }
}
impl TryFrom<wire::PauseOwner> for domain::PauseOwner {
    type Error = String;
    fn try_from(value: wire::PauseOwner) -> Result<Self, Self::Error> {
        use wire::pause_owner::Owner;
        Ok(match required(value.owner, "owner")? {
            Owner::User(()) => Self::User,
            Owner::CaptureOperationId(operation_id) => Self::Capture {
                operation_id: id(Some(operation_id), "owner.captureOperationId")?,
            },
        })
    }
}

impl From<domain::PauseToken> for wire::PauseToken {
    fn from(value: domain::PauseToken) -> Self {
        Self {
            machine_id: Some(value.machine_id.into()),
            run_id: Some(value.run_id.into()),
            generation: Some(value.generation.get()),
            owner: Some(value.owner.into()),
        }
    }
}
impl TryFrom<wire::PauseToken> for domain::PauseToken {
    type Error = String;
    fn try_from(value: wire::PauseToken) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: id(value.machine_id, "token.machineId")?,
            run_id: id(value.run_id, "token.runId")?,
            generation: nonzero(value.generation, "token.generation")?,
            owner: required(value.owner, "token.owner")?.try_into()?,
        })
    }
}

impl From<domain::CurrentPause> for wire::CurrentPause {
    fn from(value: domain::CurrentPause) -> Self {
        Self {
            token: Some(value.token.into()),
            operation_id: Some(value.operation_id.into()),
            freeze_epoch: Some(value.freeze_epoch.get()),
        }
    }
}
impl TryFrom<wire::CurrentPause> for domain::CurrentPause {
    type Error = String;
    fn try_from(value: wire::CurrentPause) -> Result<Self, Self::Error> {
        Ok(Self {
            token: required(value.token, "currentPause.token")?.try_into()?,
            operation_id: id(value.operation_id, "currentPause.operationId")?,
            freeze_epoch: nonzero(value.freeze_epoch, "currentPause.freezeEpoch")?,
        })
    }
}

impl From<domain::GuestFreezeObservation> for wire::GuestFreezeObservation {
    fn from(value: domain::GuestFreezeObservation) -> Self {
        Self {
            state: number(wire::GuestLifecycleState::from(value.state)),
            freeze_epoch: value.freeze_epoch.map(NonZeroU64::get),
            workload_roots: value.workload_roots,
            observed_frozen_roots: value.observed_frozen_roots,
            rollback_succeeded: value.rollback_succeeded,
            failure: value.failure.map(Into::into),
        }
    }
}
impl TryFrom<wire::GuestFreezeObservation> for domain::GuestFreezeObservation {
    type Error = String;
    fn try_from(value: wire::GuestFreezeObservation) -> Result<Self, Self::Error> {
        let observation = Self {
            state: read_enum::<wire::GuestLifecycleState, _>(value.state, "guest.state")?,
            freeze_epoch: value
                .freeze_epoch
                .map(|epoch| NonZeroU64::new(epoch).ok_or("guest.freezeEpoch must be nonzero"))
                .transpose()?,
            workload_roots: value.workload_roots,
            observed_frozen_roots: value.observed_frozen_roots,
            rollback_succeeded: value.rollback_succeeded,
            failure: diagnostic(value.failure)?,
        };
        observation.validate()?;
        Ok(observation)
    }
}

impl From<domain::PauseEstablished> for wire::PauseEstablished {
    fn from(value: domain::PauseEstablished) -> Self {
        Self {
            token: Some(value.token.into()),
            freeze_epoch: Some(value.freeze_epoch.get()),
            guest: Some(value.guest.into()),
            capture_eligible: Some(value.capture_eligible),
        }
    }
}
impl TryFrom<wire::PauseEstablished> for domain::PauseEstablished {
    type Error = String;
    fn try_from(value: wire::PauseEstablished) -> Result<Self, Self::Error> {
        Ok(Self {
            token: required(value.token, "pause.token")?.try_into()?,
            freeze_epoch: nonzero(value.freeze_epoch, "pause.freezeEpoch")?,
            guest: required(value.guest, "pause.guest")?.try_into()?,
            capture_eligible: required(value.capture_eligible, "pause.captureEligible")?,
        })
    }
}

impl From<domain::LiveFailure> for wire::LiveFailure {
    fn from(value: domain::LiveFailure) -> Self {
        Self {
            code: number(wire::LiveFailureCode::from(value.code)),
            stage: number(wire::LiveStage::from(value.stage)),
            message: value.message.map(Into::into),
            guest: value.guest.map(Into::into),
        }
    }
}
impl TryFrom<wire::LiveFailure> for domain::LiveFailure {
    type Error = String;
    fn try_from(value: wire::LiveFailure) -> Result<Self, Self::Error> {
        let failure = Self {
            code: read_enum::<wire::LiveFailureCode, _>(value.code, "failure.code")?,
            stage: read_enum::<wire::LiveStage, _>(value.stage, "failure.stage")?,
            message: diagnostic(value.message)?,
            guest: value.guest.map(TryInto::try_into).transpose()?,
        };
        failure.validate()?;
        Ok(failure)
    }
}

impl From<domain::LiveOperationRecord> for wire::LiveOperationRecord {
    fn from(value: domain::LiveOperationRecord) -> Self {
        use wire::live_operation_record::Result as WireResult;
        let status = value.status();
        Self {
            operation_id: Some(value.operation_id.into()),
            kind: number(wire::OperationKind::from(value.kind)),
            status: number(wire::OperationStatus::from(status)),
            result: match value.outcome {
                domain::OperationOutcome::InProgress => None,
                domain::OperationOutcome::Succeeded { pause } => {
                    Some(WireResult::Pause(pause.into()))
                }
                domain::OperationOutcome::Failed { failure } => {
                    Some(WireResult::Failure(failure.into()))
                }
            },
        }
    }
}
impl TryFrom<wire::LiveOperationRecord> for domain::LiveOperationRecord {
    type Error = String;
    fn try_from(value: wire::LiveOperationRecord) -> Result<Self, Self::Error> {
        use wire::live_operation_record::Result as WireResult;
        let status: domain::OperationStatus =
            read_enum::<wire::OperationStatus, _>(value.status, "operation.status")?;
        let outcome = match (status, value.result) {
            (domain::OperationStatus::InProgress, None) => domain::OperationOutcome::InProgress,
            (domain::OperationStatus::Succeeded, Some(WireResult::Pause(pause))) => {
                domain::OperationOutcome::Succeeded {
                    pause: pause.try_into()?,
                }
            }
            (domain::OperationStatus::Failed, Some(WireResult::Failure(failure))) => {
                domain::OperationOutcome::Failed {
                    failure: failure.try_into()?,
                }
            }
            _ => return Err("operation status does not match its result".into()),
        };
        let record = Self {
            operation_id: id(value.operation_id, "operation.operationId")?,
            kind: read_enum::<wire::OperationKind, _>(value.kind, "operation.kind")?,
            outcome,
        };
        record.validate()?;
        Ok(record)
    }
}

impl From<domain::LiveActivity> for wire::LiveActivity {
    fn from(value: domain::LiveActivity) -> Self {
        Self {
            operation_id: Some(value.operation_id.into()),
            request_id: Some(value.request_id.into()),
            command: number(wire::LiveCommandKind::from(value.command)),
            stage: number(wire::LiveStage::from(value.stage)),
        }
    }
}
impl TryFrom<wire::LiveActivity> for domain::LiveActivity {
    type Error = String;
    fn try_from(value: wire::LiveActivity) -> Result<Self, Self::Error> {
        Ok(Self {
            operation_id: id(value.operation_id, "activity.operationId")?,
            request_id: id(value.request_id, "activity.requestId")?,
            command: read_enum::<wire::LiveCommandKind, _>(value.command, "activity.command")?,
            stage: read_enum::<wire::LiveStage, _>(value.stage, "activity.stage")?,
        })
    }
}

impl From<domain::LiveLifecycle> for wire::LiveLifecycle {
    fn from(value: domain::LiveLifecycle) -> Self {
        Self {
            current_pause: value.current_pause.map(Into::into),
            activity: value.activity.map(Into::into),
            error: value.error.map(Into::into),
        }
    }
}
impl TryFrom<wire::LiveLifecycle> for domain::LiveLifecycle {
    type Error = String;
    fn try_from(value: wire::LiveLifecycle) -> Result<Self, Self::Error> {
        Ok(Self {
            current_pause: value.current_pause.map(TryInto::try_into).transpose()?,
            activity: value.activity.map(TryInto::try_into).transpose()?,
            error: value.error.map(TryInto::try_into).transpose()?,
        })
    }
}

/// Decode and validate the lifecycle projection of a monitor status against
/// its VM state.
pub fn status_lifecycle(
    status: &wire::HostStatus,
) -> Result<(domain::VmLifecycleState, domain::LiveLifecycle), String> {
    let state = vm_state_from_wire(status.vm.as_ref().and_then(|vm| vm.state))?;
    let lifecycle: domain::LiveLifecycle =
        required(status.lifecycle.clone(), "lifecycle")?.try_into()?;
    lifecycle.validate_for(state)?;
    Ok((state, lifecycle))
}

impl TryFrom<domain::LiveRejection> for wire::LiveRejection {
    type Error = String;
    fn try_from(value: domain::LiveRejection) -> Result<Self, Self::Error> {
        let code = value.reason.code();
        let unsupported = match value.reason {
            domain::LiveRejectionReason::Unsupported { unsupported } => {
                Some(unsupported.try_into()?)
            }
            _ => None,
        };
        Ok(Self {
            code: number(wire::LiveRejectionCode::from(code)),
            state: number(wire::VmState::from(value.state)),
            unsupported,
            message: value.message.map(Into::into),
        })
    }
}
impl TryFrom<wire::LiveRejection> for domain::LiveRejection {
    type Error = String;
    fn try_from(value: wire::LiveRejection) -> Result<Self, Self::Error> {
        use domain::LiveRejectionCode as Code;
        use domain::LiveRejectionReason as Reason;
        let code: Code = read_enum::<wire::LiveRejectionCode, _>(value.code, "rejection.code")?;
        let reason = match (code, value.unsupported) {
            (Code::Unsupported, Some(unsupported)) => Reason::Unsupported {
                unsupported: unsupported.try_into()?,
            },
            (Code::Unsupported, None) => {
                return Err("unsupported rejection requires its reason".into())
            }
            (_, Some(_)) => return Err("only an unsupported rejection carries a reason".into()),
            (Code::WrongMachine, None) => Reason::WrongMachine,
            (Code::WrongRun, None) => Reason::WrongRun,
            (Code::RequestConflict, None) => Reason::RequestConflict,
            (Code::InvalidState, None) => Reason::InvalidState,
            (Code::OperationNotFound, None) => Reason::OperationNotFound,
            (Code::StaleToken, None) => Reason::StaleToken,
            (Code::ForeignToken, None) => Reason::ForeignToken,
            (Code::WrongTarget, None) => Reason::WrongTarget,
            (Code::MonitorStopping, None) => Reason::MonitorStopping,
        };
        let rejection = Self {
            reason,
            state: read_enum::<wire::VmState, _>(value.state, "rejection.state")?,
            message: diagnostic(value.message)?,
        };
        rejection.validate()?;
        Ok(rejection)
    }
}

impl From<domain::LiveOperationReceipt> for wire::LiveOperationReceipt {
    fn from(value: domain::LiveOperationReceipt) -> Self {
        Self {
            operation_id: Some(value.operation_id.into()),
            kind: number(wire::OperationKind::from(value.kind)),
            state: number(wire::VmState::from(value.state)),
        }
    }
}
impl TryFrom<wire::LiveOperationReceipt> for domain::LiveOperationReceipt {
    type Error = String;
    fn try_from(value: wire::LiveOperationReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            operation_id: id(value.operation_id, "receipt.operationId")?,
            kind: read_enum::<wire::OperationKind, _>(value.kind, "receipt.kind")?,
            state: read_enum::<wire::VmState, _>(value.state, "receipt.state")?,
        })
    }
}

// Requests.

impl From<domain::PauseCommand> for wire::PauseRequest {
    fn from(value: domain::PauseCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
        }
    }
}
impl TryFrom<wire::PauseRequest> for domain::PauseCommand {
    type Error = String;
    fn try_from(value: wire::PauseRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            envelope: envelope(value.envelope)?,
        })
    }
}

impl From<domain::ResumeCommand> for wire::ResumeRequest {
    fn from(value: domain::ResumeCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
            operation_id: Some(value.operation_id.into()),
            token: Some(value.token.into()),
        }
    }
}
impl TryFrom<wire::ResumeRequest> for domain::ResumeCommand {
    type Error = String;
    fn try_from(value: wire::ResumeRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            envelope: envelope(value.envelope)?,
            operation_id: id(value.operation_id, "operationId")?,
            token: required(value.token, "token")?.try_into()?,
        })
    }
}

impl From<domain::GetOperationCommand> for wire::GetOperationRequest {
    fn from(value: domain::GetOperationCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
            operation_id: Some(value.operation_id.into()),
        }
    }
}
impl TryFrom<wire::GetOperationRequest> for domain::GetOperationCommand {
    type Error = String;
    fn try_from(value: wire::GetOperationRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            envelope: envelope(value.envelope)?,
            operation_id: id(value.operation_id, "operationId")?,
        })
    }
}

impl From<domain::CancelOperationCommand> for wire::CancelOperationRequest {
    fn from(value: domain::CancelOperationCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
            operation_id: Some(value.operation_id.into()),
        }
    }
}
impl TryFrom<wire::CancelOperationRequest> for domain::CancelOperationCommand {
    type Error = String;
    fn try_from(value: wire::CancelOperationRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            envelope: envelope(value.envelope)?,
            operation_id: id(value.operation_id, "operationId")?,
        })
    }
}

impl From<domain::CaptureCommand> for wire::CaptureRequest {
    fn from(value: domain::CaptureCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
            expected_configuration_digest: Some(value.expected_configuration_digest),
            policy: number(wire::CapturePolicy::from(value.policy)),
            resume_policy: number(wire::CaptureResumePolicy::from(value.resume_policy)),
        }
    }
}
impl TryFrom<wire::CaptureRequest> for domain::CaptureCommand {
    type Error = String;
    fn try_from(value: wire::CaptureRequest) -> Result<Self, Self::Error> {
        let command = Self {
            envelope: envelope(value.envelope)?,
            expected_configuration_digest: required(
                value.expected_configuration_digest,
                "expectedConfigurationDigest",
            )?,
            policy: read_enum::<wire::CapturePolicy, _>(value.policy, "policy")?,
            resume_policy: read_enum::<wire::CaptureResumePolicy, _>(
                value.resume_policy,
                "resumePolicy",
            )?,
        };
        domain::LiveCommand::Capture(command.clone()).validate()?;
        Ok(command)
    }
}

impl From<domain::ReleaseCaptureCommand> for wire::ReleaseCaptureRequest {
    fn from(value: domain::ReleaseCaptureCommand) -> Self {
        Self {
            envelope: Some(value.envelope.into()),
            operation_id: Some(value.operation_id.into()),
        }
    }
}
impl TryFrom<wire::ReleaseCaptureRequest> for domain::ReleaseCaptureCommand {
    type Error = String;
    fn try_from(value: wire::ReleaseCaptureRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            envelope: envelope(value.envelope)?,
            operation_id: id(value.operation_id, "operationId")?,
        })
    }
}

// Responses.

impl TryFrom<domain::PauseOutcome> for wire::PauseResponse {
    type Error = String;
    fn try_from(value: domain::PauseOutcome) -> Result<Self, Self::Error> {
        use wire::pause_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::PauseOutcome::Accepted { receipt } => Outcome::Accepted(receipt.into()),
                domain::PauseOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::PauseResponse> for domain::PauseOutcome {
    type Error = String;
    fn try_from(value: wire::PauseResponse) -> Result<Self, Self::Error> {
        use wire::pause_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Accepted(receipt) => Self::Accepted {
                receipt: receipt.try_into()?,
            },
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

impl TryFrom<domain::CaptureOutcome> for wire::CaptureResponse {
    type Error = String;
    fn try_from(value: domain::CaptureOutcome) -> Result<Self, Self::Error> {
        use wire::capture_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::CaptureOutcome::Accepted { receipt } => Outcome::Accepted(receipt.into()),
                domain::CaptureOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::CaptureResponse> for domain::CaptureOutcome {
    type Error = String;
    fn try_from(value: wire::CaptureResponse) -> Result<Self, Self::Error> {
        use wire::capture_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Accepted(receipt) => Self::Accepted {
                receipt: receipt.try_into()?,
            },
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

impl TryFrom<domain::ResumeOutcome> for wire::ResumeResponse {
    type Error = String;
    fn try_from(value: domain::ResumeOutcome) -> Result<Self, Self::Error> {
        use wire::resume_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::ResumeOutcome::Resumed { resumed } => {
                    Outcome::Resumed(wire::ResumeCompleted {
                        consumed_token: Some(resumed.consumed_token.into()),
                        thawed_epoch: Some(resumed.thawed_epoch.get()),
                    })
                }
                domain::ResumeOutcome::Failed { failed } => {
                    failed.validate()?;
                    Outcome::Failed(wire::ResumeFailed {
                        cause: Some(failed.cause.into()),
                        state: number(wire::VmState::from(failed.state)),
                        current_pause: failed.current_pause.map(Into::into),
                        recovery_failure: failed.recovery_failure.map(Into::into),
                        requested_token: Some(failed.requested_token.into()),
                    })
                }
                domain::ResumeOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::ResumeResponse> for domain::ResumeOutcome {
    type Error = String;
    fn try_from(value: wire::ResumeResponse) -> Result<Self, Self::Error> {
        use wire::resume_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Resumed(resumed) => Self::Resumed {
                resumed: domain::ResumeCompleted {
                    consumed_token: required(resumed.consumed_token, "resumed.consumedToken")?
                        .try_into()?,
                    thawed_epoch: nonzero(resumed.thawed_epoch, "resumed.thawedEpoch")?,
                },
            },
            Outcome::Failed(failed) => {
                let failed = domain::ResumeFailed {
                    cause: required(failed.cause, "failed.cause")?.try_into()?,
                    state: read_enum::<wire::VmState, _>(failed.state, "failed.state")?,
                    current_pause: failed.current_pause.map(TryInto::try_into).transpose()?,
                    recovery_failure: failed.recovery_failure.map(TryInto::try_into).transpose()?,
                    requested_token: required(failed.requested_token, "failed.requestedToken")?
                        .try_into()?,
                };
                failed.validate()?;
                Self::Failed { failed }
            }
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

impl From<domain::OperationObservation> for wire::OperationObservation {
    fn from(value: domain::OperationObservation) -> Self {
        Self {
            operation: Some(value.operation.into()),
            state: number(wire::VmState::from(value.state)),
            current_pause: value.current_pause.map(Into::into),
            activity: value.activity.map(Into::into),
        }
    }
}
impl TryFrom<wire::OperationObservation> for domain::OperationObservation {
    type Error = String;
    fn try_from(value: wire::OperationObservation) -> Result<Self, Self::Error> {
        let observation = Self {
            operation: required(value.operation, "observation.operation")?.try_into()?,
            state: read_enum::<wire::VmState, _>(value.state, "observation.state")?,
            current_pause: value.current_pause.map(TryInto::try_into).transpose()?,
            activity: value.activity.map(TryInto::try_into).transpose()?,
        };
        domain::LiveLifecycle {
            current_pause: observation.current_pause.clone(),
            activity: observation.activity.clone(),
            error: None,
        }
        .validate_for(match observation.state {
            // Error carries its cause only in status; presence of pause and
            // activity is still exact.
            domain::VmLifecycleState::Error => domain::VmLifecycleState::Running,
            state => state,
        })?;
        Ok(observation)
    }
}

impl TryFrom<domain::GetOperationOutcome> for wire::GetOperationResponse {
    type Error = String;
    fn try_from(value: domain::GetOperationOutcome) -> Result<Self, Self::Error> {
        use wire::get_operation_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::GetOperationOutcome::Observation { observation } => {
                    Outcome::Observation(observation.into())
                }
                domain::GetOperationOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::GetOperationResponse> for domain::GetOperationOutcome {
    type Error = String;
    fn try_from(value: wire::GetOperationResponse) -> Result<Self, Self::Error> {
        use wire::get_operation_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Observation(observation) => Self::Observation {
                observation: observation.try_into()?,
            },
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

impl TryFrom<domain::CancelOperationOutcome> for wire::CancelOperationResponse {
    type Error = String;
    fn try_from(value: domain::CancelOperationOutcome) -> Result<Self, Self::Error> {
        use wire::cancel_operation_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::CancelOperationOutcome::Completed { completed } => {
                    Outcome::Completed(wire::CancelCompleted {
                        effective: Some(completed.effective),
                        operation: Some(completed.operation.into()),
                        state: number(wire::VmState::from(completed.state)),
                    })
                }
                domain::CancelOperationOutcome::Failed { failed } => {
                    Outcome::Failed(wire::CancelFailed {
                        cause: Some(failed.cause.into()),
                        operation: Some(failed.operation.into()),
                        state: number(wire::VmState::from(failed.state)),
                    })
                }
                domain::CancelOperationOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::CancelOperationResponse> for domain::CancelOperationOutcome {
    type Error = String;
    fn try_from(value: wire::CancelOperationResponse) -> Result<Self, Self::Error> {
        use wire::cancel_operation_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Completed(completed) => Self::Completed {
                completed: domain::CancelCompleted {
                    effective: required(completed.effective, "completed.effective")?,
                    operation: required(completed.operation, "completed.operation")?.try_into()?,
                    state: read_enum::<wire::VmState, _>(completed.state, "completed.state")?,
                },
            },
            Outcome::Failed(failed) => Self::Failed {
                failed: domain::CancelFailed {
                    cause: required(failed.cause, "failed.cause")?.try_into()?,
                    operation: required(failed.operation, "failed.operation")?.try_into()?,
                    state: read_enum::<wire::VmState, _>(failed.state, "failed.state")?,
                },
            },
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

impl TryFrom<domain::ReleaseCaptureOutcome> for wire::ReleaseCaptureResponse {
    type Error = String;
    fn try_from(value: domain::ReleaseCaptureOutcome) -> Result<Self, Self::Error> {
        use wire::release_capture_response::Outcome;
        Ok(Self {
            outcome: Some(match value {
                domain::ReleaseCaptureOutcome::Rejected { rejection } => {
                    Outcome::Rejected(rejection.try_into()?)
                }
            }),
        })
    }
}
impl TryFrom<wire::ReleaseCaptureResponse> for domain::ReleaseCaptureOutcome {
    type Error = String;
    fn try_from(value: wire::ReleaseCaptureResponse) -> Result<Self, Self::Error> {
        use wire::release_capture_response::Outcome;
        Ok(match required(value.outcome, "outcome")? {
            Outcome::Rejected(rejection) => Self::Rejected {
                rejection: rejection.try_into()?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use crate::v1 as wire;
    use vm_spec::lifecycle as domain;

    fn id(last: u8) -> domain::LiveId {
        domain::LiveId::parse(&format!("00000000-0000-4000-8000-0000000000{last:02x}")).unwrap()
    }

    fn envelope() -> domain::LiveCommandEnvelope {
        domain::LiveCommandEnvelope {
            machine_id: id(1),
            run_id: id(2),
            request_id: id(3),
        }
    }

    fn token(generation: u64) -> domain::PauseToken {
        domain::PauseToken {
            machine_id: id(1),
            run_id: id(2),
            generation: NonZeroU64::new(generation).unwrap(),
            owner: domain::PauseOwner::User,
        }
    }

    fn established() -> domain::PauseEstablished {
        domain::PauseEstablished {
            token: token(1),
            freeze_epoch: NonZeroU64::new(1).unwrap(),
            guest: domain::GuestFreezeObservation {
                state: domain::GuestLifecycleState::Frozen,
                freeze_epoch: NonZeroU64::new(1),
                workload_roots: vec!["/sys/fs/cgroup/silo/workload".into()],
                observed_frozen_roots: vec!["/sys/fs/cgroup/silo/workload".into()],
                rollback_succeeded: None,
                failure: None,
            },
            capture_eligible: true,
        }
    }

    #[test]
    fn every_wire_enum_roundtrips_and_rejects_unspecified() {
        for state in domain::VmLifecycleState::ALL {
            let wire = wire::VmState::from(*state);
            assert_eq!(domain::VmLifecycleState::try_from(wire).unwrap(), *state);
        }
        assert!(domain::VmLifecycleState::try_from(wire::VmState::Unspecified).is_err());
        assert!(crate::lifecycle::vm_state_from_wire(Some(999)).is_err());
        assert!(crate::lifecycle::vm_state_from_wire(None).is_err());
        for stage in domain::LiveStage::ALL {
            assert_eq!(
                domain::LiveStage::try_from(wire::LiveStage::from(*stage)).unwrap(),
                *stage
            );
        }
        for code in domain::LiveFailureCode::ALL {
            assert_eq!(
                domain::LiveFailureCode::try_from(wire::LiveFailureCode::from(*code)).unwrap(),
                *code
            );
        }
        for code in domain::LiveRejectionCode::ALL {
            assert_eq!(
                domain::LiveRejectionCode::try_from(wire::LiveRejectionCode::from(*code)).unwrap(),
                *code
            );
        }
        for state in domain::GuestLifecycleState::ALL {
            assert_eq!(
                domain::GuestLifecycleState::try_from(wire::GuestLifecycleState::from(*state))
                    .unwrap(),
                *state
            );
        }
    }

    #[test]
    fn requests_roundtrip_and_reject_missing_or_nil_identity() {
        let resume = domain::ResumeCommand {
            envelope: envelope(),
            operation_id: id(3),
            token: token(4),
        };
        let encoded = wire::ResumeRequest::from(resume.clone());
        assert_eq!(
            domain::ResumeCommand::try_from(encoded.clone()).unwrap(),
            resume
        );
        let mut missing = encoded.clone();
        missing.token = None;
        assert!(domain::ResumeCommand::try_from(missing).is_err());
        let mut zero = encoded.clone();
        zero.token.as_mut().unwrap().generation = Some(0);
        assert!(domain::ResumeCommand::try_from(zero).is_err());
        let mut nil = encoded;
        nil.envelope.as_mut().unwrap().run_id = Some("00000000-0000-0000-0000-000000000000".into());
        assert!(domain::ResumeCommand::try_from(nil).is_err());
        assert!(domain::PauseCommand::try_from(wire::PauseRequest { envelope: None }).is_err());
        let capture = wire::CaptureRequest {
            envelope: Some(envelope().into()),
            expected_configuration_digest: Some(String::new()),
            policy: Some(wire::CapturePolicy::Full as i32),
            resume_policy: Some(wire::CaptureResumePolicy::Preserve as i32),
        };
        assert!(domain::CaptureCommand::try_from(capture).is_err());
    }

    #[test]
    fn operation_status_must_match_its_result() {
        let record = domain::LiveOperationRecord {
            operation_id: id(3),
            kind: domain::OperationKind::Pause,
            outcome: domain::OperationOutcome::Succeeded {
                pause: established(),
            },
        };
        let encoded = wire::LiveOperationRecord::from(record.clone());
        assert_eq!(
            domain::LiveOperationRecord::try_from(encoded.clone()).unwrap(),
            record
        );
        let mut mismatched = encoded.clone();
        mismatched.status = Some(wire::OperationStatus::InProgress as i32);
        assert!(domain::LiveOperationRecord::try_from(mismatched).is_err());
        let mut failed_without_cause = encoded;
        failed_without_cause.status = Some(wire::OperationStatus::Failed as i32);
        assert!(domain::LiveOperationRecord::try_from(failed_without_cause).is_err());
    }

    #[test]
    fn rejection_carries_unsupported_reason_exactly_when_unsupported() {
        let unsupported = vm_spec::live::LiveOperationUnsupported {
            operation: vm_spec::live::LiveOperation::Capture,
            backend: vm_spec::live::LiveBackend::Krun,
            lane: vm_spec::live::LiveLane::KvmX86_64,
            reason: vm_spec::live::LiveUnsupportedReason::new(
                vm_spec::live::LiveReasonCode::NotDelivered,
            ),
        };
        let rejection = domain::LiveRejection::new(
            domain::LiveRejectionReason::Unsupported {
                unsupported: unsupported.clone(),
            },
            domain::VmLifecycleState::Running,
            "capture not delivered",
        );
        let encoded = wire::LiveRejection::try_from(rejection.clone()).unwrap();
        assert_eq!(
            domain::LiveRejection::try_from(encoded.clone()).unwrap(),
            rejection
        );
        let mut missing = encoded.clone();
        missing.unsupported = None;
        assert!(domain::LiveRejection::try_from(missing).is_err());
        let mut extra = encoded;
        extra.code = Some(wire::LiveRejectionCode::InvalidState as i32);
        assert!(domain::LiveRejection::try_from(extra).is_err());
    }

    #[test]
    fn resume_outcomes_roundtrip_with_separate_current_authority() {
        let failed = domain::ResumeOutcome::Failed {
            failed: domain::ResumeFailed {
                cause: domain::LiveFailure::new(
                    domain::LiveFailureCode::ThawUnacknowledged,
                    domain::LiveStage::ResumeThaw,
                    "thaw ack lost",
                ),
                state: domain::VmLifecycleState::Paused,
                current_pause: Some(domain::CurrentPause {
                    token: token(2),
                    operation_id: id(3),
                    freeze_epoch: NonZeroU64::new(2).unwrap(),
                }),
                recovery_failure: None,
                requested_token: token(1),
            },
        };
        let encoded = wire::ResumeResponse::try_from(failed.clone()).unwrap();
        assert_eq!(
            domain::ResumeOutcome::try_from(encoded.clone()).unwrap(),
            failed
        );
        let mut stale = encoded;
        let wire::resume_response::Outcome::Failed(inner) = stale.outcome.as_mut().unwrap() else {
            panic!("failed outcome");
        };
        inner
            .current_pause
            .as_mut()
            .unwrap()
            .token
            .as_mut()
            .unwrap()
            .generation = Some(1);
        inner
            .current_pause
            .as_mut()
            .unwrap()
            .token
            .as_mut()
            .unwrap()
            .owner = Some(
            domain::PauseOwner::Capture {
                operation_id: id(9),
            }
            .into(),
        );
        assert!(domain::ResumeOutcome::try_from(stale).is_err());
    }

    #[test]
    fn status_lifecycle_presence_follows_state() {
        let mut status = wire::HostStatus {
            vm: Some(wire::VmSnapshot {
                state: Some(wire::VmState::Paused as i32),
                ..Default::default()
            }),
            lifecycle: Some(wire::LiveLifecycle::default()),
            ..Default::default()
        };
        assert!(crate::lifecycle::status_lifecycle(&status).is_err());
        status.lifecycle = Some(
            domain::LiveLifecycle {
                current_pause: Some(domain::CurrentPause {
                    token: token(1),
                    operation_id: id(3),
                    freeze_epoch: NonZeroU64::new(1).unwrap(),
                }),
                ..Default::default()
            }
            .into(),
        );
        let (state, lifecycle) = crate::lifecycle::status_lifecycle(&status).unwrap();
        assert_eq!(state, domain::VmLifecycleState::Paused);
        assert!(lifecycle.current_pause.is_some());
        status.lifecycle = None;
        assert!(crate::lifecycle::status_lifecycle(&status).is_err());
    }
}

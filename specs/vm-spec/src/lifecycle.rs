//! Typed live-command contract shared by the monitor (authority) and libvm
//! (durable journal). Invalid states are unrepresentable where practical; the
//! remaining cross-field rules are enforced by `validate` and by the strict
//! protocol conversions.
use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::live::LiveOperationUnsupported;

/// Upper bound for one diagnostic carried by a lifecycle result.
pub const MAX_LIFECYCLE_DIAGNOSTIC_BYTES: usize = 4096;
/// Upper bound for guest workload root lists carried in results.
pub const MAX_WORKLOAD_ROOTS: usize = 64;
/// Upper bound for one guest workload root path.
pub const MAX_WORKLOAD_ROOT_BYTES: usize = 4095;

/// Canonical lowercase, hyphenated, non-nil UUID text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LiveId(String);

impl LiveId {
    pub fn parse(value: &str) -> Result<Self, String> {
        Self::try_from(value.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LiveId {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical = value.len() == 36
            && value != "00000000-0000-0000-0000-000000000000"
            && value.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                }
            });
        if canonical {
            Ok(Self(value))
        } else {
            Err("live identifier must be a canonical lowercase non-nil UUID".into())
        }
    }
}

impl From<LiveId> for String {
    fn from(value: LiveId) -> Self {
        value.0
    }
}

impl fmt::Display for LiveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Bounded UTF-8 diagnostic. Construction truncates at a character boundary;
/// decoding an oversized value is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Diagnostic(String);

impl Diagnostic {
    pub fn new(value: impl Into<String>) -> Self {
        let mut value = value.into();
        if value.len() > MAX_LIFECYCLE_DIAGNOSTIC_BYTES {
            let mut end = MAX_LIFECYCLE_DIAGNOSTIC_BYTES;
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            value.truncate(end);
        }
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Diagnostic {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > MAX_LIFECYCLE_DIAGNOSTIC_BYTES {
            return Err("lifecycle diagnostic exceeds its bound".into());
        }
        Ok(Self(value))
    }
}

impl From<Diagnostic> for String {
    fn from(value: Diagnostic) -> Self {
        value.0
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! lifecycle_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $text)] $variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
        }
    };
}

lifecycle_enum!(
    /// Monitor machine state, the full ADR 0021 matrix plus the existing
    /// startup/terminal states. `Error` is live, fenced and process-owned;
    /// `Failed` is the existing terminal failure.
    VmLifecycleState {
        Starting => "starting",
        Running => "running",
        Stopping => "stopping",
        Stopped => "stopped",
        Failed => "failed",
        Pausing => "pausing",
        Paused => "paused",
        Capturing => "capturing",
        Restoring => "restoring",
        Activating => "activating",
        ActivationFailed => "activation-failed",
        Error => "error",
    }
);

lifecycle_enum!(LiveCommandKind {
    Pause => "pause",
    Resume => "resume",
    GetOperation => "get-operation",
    CancelOperation => "cancel-operation",
    Capture => "capture",
    ReleaseCapture => "release-capture",
});

lifecycle_enum!(OperationKind {
    Pause => "pause",
    Capture => "capture",
});

lifecycle_enum!(OperationStatus {
    InProgress => "in-progress",
    Succeeded => "succeeded",
    Failed => "failed",
});

lifecycle_enum!(CapturePolicy {
    Full => "full",
    Incremental => "incremental",
});

lifecycle_enum!(CaptureResumePolicy {
    ResumeIfAcquired => "resume-if-acquired",
    Preserve => "preserve",
});

lifecycle_enum!(
    /// Internal coordinator stage. Every stage except `PauseFailed` is active
    /// work; `PauseFailed` is a failed `Pausing` awaiting cancel or stop.
    LiveStage {
        MonitorDrain => "monitor-drain",
        GuestFreeze => "guest-freeze",
        NativePause => "native-pause",
        PauseFailed => "pause-failed",
        RollbackThaw => "rollback-thaw",
        CancelNative => "cancel-native",
        CancelThaw => "cancel-thaw",
        ResumeNative => "resume-native",
        ResumeClock => "resume-clock",
        ResumeHandshake => "resume-handshake",
        ResumeThaw => "resume-thaw",
        Readiness => "readiness",
        RecoveryFreeze => "recovery-freeze",
        RecoveryPause => "recovery-pause",
        Admission => "admission",
    }
);

lifecycle_enum!(LiveFailureCode {
    DrainTimedOut => "drain-timed-out",
    GuestUnavailable => "guest-unavailable",
    GuestIdentityMismatch => "guest-identity-mismatch",
    FreezeFailed => "freeze-failed",
    FreezeTimedOut => "freeze-timed-out",
    NativePauseFailed => "native-pause-failed",
    NativeUncertain => "native-uncertain",
    Cancelled => "cancelled",
    NativeRollbackFailed => "native-rollback-failed",
    ThawFailed => "thaw-failed",
    ThawUnacknowledged => "thaw-unacknowledged",
    NativeResumeFailed => "native-resume-failed",
    ClockGenerationFailed => "clock-generation-failed",
    HandshakeFailed => "handshake-failed",
    ReadinessFailed => "readiness-failed",
    RecoveryFreezeFailed => "recovery-freeze-failed",
    RecoveryPauseFailed => "recovery-pause-failed",
    WorkerLost => "worker-lost",
    Stopped => "stopped",
    DeadlineExceeded => "deadline-exceeded",
});

lifecycle_enum!(LiveRejectionCode {
    WrongMachine => "wrong-machine",
    WrongRun => "wrong-run",
    RequestConflict => "request-conflict",
    InvalidState => "invalid-state",
    OperationNotFound => "operation-not-found",
    StaleToken => "stale-token",
    ForeignToken => "foreign-token",
    Unsupported => "unsupported",
    WrongTarget => "wrong-target",
    MonitorStopping => "monitor-stopping",
});

lifecycle_enum!(GuestLifecycleState {
    Running => "running",
    Freezing => "freezing",
    Frozen => "frozen",
    Activating => "activating",
    ActivatedFrozen => "activated-frozen",
    Thawing => "thawing",
    Thawed => "thawed",
    FreezeFailed => "freeze-failed",
    ActivationFailed => "activation-failed",
    Faulted => "faulted",
});

impl VmLifecycleState {
    /// ADR 0021 `Command and state matrix`: the single admission table for
    /// NEW requests. Exact replays never re-enter it, and capability refusal
    /// precedes it. Startup and terminal states admit no live command.
    pub const fn admits(self, command: LiveCommandKind) -> bool {
        use LiveCommandKind as C;
        match self {
            Self::Running => matches!(
                command,
                C::Pause | C::Capture | C::GetOperation | C::ReleaseCapture
            ),
            Self::Pausing => matches!(command, C::GetOperation | C::CancelOperation),
            Self::Paused => matches!(
                command,
                C::Resume | C::Capture | C::GetOperation | C::ReleaseCapture
            ),
            Self::Capturing => matches!(command, C::GetOperation | C::CancelOperation),
            Self::Restoring | Self::Activating => matches!(command, C::GetOperation),
            Self::ActivationFailed | Self::Error => {
                matches!(command, C::GetOperation | C::ReleaseCapture)
            }
            Self::Starting | Self::Stopping | Self::Stopped | Self::Failed => false,
        }
    }

    /// Readiness can be true only while running.
    pub const fn readiness_eligible(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Stopping or terminal: live commands report `monitor-stopping`.
    pub const fn is_stopping_or_terminal(self) -> bool {
        matches!(self, Self::Stopping | Self::Stopped | Self::Failed)
    }
}

/// Common envelope of every live command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveCommandEnvelope {
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub request_id: LiveId,
}

/// Who holds a pause. Public `Pause` only creates `User`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum PauseOwner {
    User,
    Capture { operation_id: LiveId },
}

/// Public pause authority projection. The opaque native token never leaves
/// the worker; `generation` names the exact retained native authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PauseToken {
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub generation: NonZeroU64,
    pub owner: PauseOwner,
}

/// Current authority, never historical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentPause {
    pub token: PauseToken,
    /// The operation that owns the token (the original Pause, later Capture).
    pub operation_id: LiveId,
    pub freeze_epoch: NonZeroU64,
}

/// Exact guest lifecycle acknowledgement relevant to a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestFreezeObservation {
    pub state: GuestLifecycleState,
    pub freeze_epoch: Option<NonZeroU64>,
    pub workload_roots: Vec<String>,
    pub observed_frozen_roots: Vec<String>,
    pub rollback_succeeded: Option<bool>,
    pub failure: Option<Diagnostic>,
}

impl GuestFreezeObservation {
    pub fn validate(&self) -> Result<(), String> {
        for roots in [&self.workload_roots, &self.observed_frozen_roots] {
            if roots.len() > MAX_WORKLOAD_ROOTS {
                return Err("too many guest workload roots".into());
            }
            if roots
                .iter()
                .any(|root| root.is_empty() || root.len() > MAX_WORKLOAD_ROOT_BYTES)
            {
                return Err("invalid guest workload root".into());
            }
        }
        Ok(())
    }

    /// Positive kernel freeze evidence: Frozen with every requested root
    /// observed frozen.
    pub fn positively_frozen(&self, epoch: NonZeroU64) -> bool {
        self.state == GuestLifecycleState::Frozen
            && self.freeze_epoch == Some(epoch)
            && !self.workload_roots.is_empty()
            && self.workload_roots == self.observed_frozen_roots
    }
}

/// Original terminal success of a Pause. Immutable for the run lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PauseEstablished {
    pub token: PauseToken,
    pub freeze_epoch: NonZeroU64,
    pub guest: GuestFreezeObservation,
    pub capture_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveFailure {
    pub code: LiveFailureCode,
    pub stage: LiveStage,
    pub message: Option<Diagnostic>,
    pub guest: Option<GuestFreezeObservation>,
}

impl LiveFailure {
    pub fn new(code: LiveFailureCode, stage: LiveStage, message: impl Into<String>) -> Self {
        Self {
            code,
            stage,
            message: Some(Diagnostic::new(message)),
            guest: None,
        }
    }

    pub fn with_guest(mut self, guest: GuestFreezeObservation) -> Self {
        self.guest = Some(guest);
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        self.guest
            .as_ref()
            .map_or(Ok(()), GuestFreezeObservation::validate)
    }
}

impl fmt::Display for LiveFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} during {}", self.code, self.stage)?;
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status", deny_unknown_fields)]
pub enum OperationOutcome {
    InProgress,
    Succeeded { pause: PauseEstablished },
    Failed { failure: LiveFailure },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveOperationRecord {
    pub operation_id: LiveId,
    pub kind: OperationKind,
    pub outcome: OperationOutcome,
}

impl LiveOperationRecord {
    pub fn status(&self) -> OperationStatus {
        match self.outcome {
            OperationOutcome::InProgress => OperationStatus::InProgress,
            OperationOutcome::Succeeded { .. } => OperationStatus::Succeeded,
            OperationOutcome::Failed { .. } => OperationStatus::Failed,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match &self.outcome {
            OperationOutcome::InProgress => Ok(()),
            OperationOutcome::Succeeded { pause } => {
                if self.kind != OperationKind::Pause {
                    return Err("only a pause operation succeeds with pause evidence".into());
                }
                pause.guest.validate()
            }
            OperationOutcome::Failed { failure } => failure.validate(),
        }
    }
}

/// Active or failed-Pausing detail, present only in `Pausing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveActivity {
    pub operation_id: LiveId,
    pub request_id: LiveId,
    pub command: LiveCommandKind,
    pub stage: LiveStage,
}

/// Lifecycle projection carried by monitor status.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveLifecycle {
    pub current_pause: Option<CurrentPause>,
    pub activity: Option<LiveActivity>,
    pub error: Option<LiveFailure>,
}

impl LiveLifecycle {
    /// Presence rules: current pause iff Paused, activity iff Pausing,
    /// error iff Error.
    pub fn validate_for(&self, state: VmLifecycleState) -> Result<(), String> {
        if self.current_pause.is_some() != (state == VmLifecycleState::Paused) {
            return Err("current pause is present exactly while paused".into());
        }
        if self.activity.is_some() != (state == VmLifecycleState::Pausing) {
            return Err("lifecycle activity is present exactly while pausing".into());
        }
        if self.error.is_some() != (state == VmLifecycleState::Error) {
            return Err("lifecycle error is present exactly in the error state".into());
        }
        self.error.as_ref().map_or(Ok(()), LiveFailure::validate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "code", deny_unknown_fields)]
pub enum LiveRejectionReason {
    WrongMachine,
    WrongRun,
    RequestConflict,
    InvalidState,
    OperationNotFound,
    StaleToken,
    ForeignToken,
    Unsupported {
        unsupported: LiveOperationUnsupported,
    },
    WrongTarget,
    MonitorStopping,
}

impl LiveRejectionReason {
    pub fn code(&self) -> LiveRejectionCode {
        match self {
            Self::WrongMachine => LiveRejectionCode::WrongMachine,
            Self::WrongRun => LiveRejectionCode::WrongRun,
            Self::RequestConflict => LiveRejectionCode::RequestConflict,
            Self::InvalidState => LiveRejectionCode::InvalidState,
            Self::OperationNotFound => LiveRejectionCode::OperationNotFound,
            Self::StaleToken => LiveRejectionCode::StaleToken,
            Self::ForeignToken => LiveRejectionCode::ForeignToken,
            Self::Unsupported { .. } => LiveRejectionCode::Unsupported,
            Self::WrongTarget => LiveRejectionCode::WrongTarget,
            Self::MonitorStopping => LiveRejectionCode::MonitorStopping,
        }
    }
}

/// Typed refusal without effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveRejection {
    pub reason: LiveRejectionReason,
    /// The state used for admission.
    pub state: VmLifecycleState,
    pub message: Option<Diagnostic>,
}

impl LiveRejection {
    pub fn new(
        reason: LiveRejectionReason,
        state: VmLifecycleState,
        message: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            state,
            message: Some(Diagnostic::new(message)),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match &self.reason {
            LiveRejectionReason::Unsupported { unsupported } => unsupported.validate(),
            _ => Ok(()),
        }
    }
}

impl fmt::Display for LiveRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            LiveRejectionReason::Unsupported { unsupported } => write!(f, "{unsupported}")?,
            reason => write!(f, "{} in state {}", reason.code(), self.state)?,
        }
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PauseCommand {
    pub envelope: LiveCommandEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeCommand {
    pub envelope: LiveCommandEnvelope,
    pub operation_id: LiveId,
    pub token: PauseToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetOperationCommand {
    pub envelope: LiveCommandEnvelope,
    pub operation_id: LiveId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelOperationCommand {
    pub envelope: LiveCommandEnvelope,
    pub operation_id: LiveId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureCommand {
    pub envelope: LiveCommandEnvelope,
    pub expected_configuration_digest: String,
    pub policy: CapturePolicy,
    pub resume_policy: CaptureResumePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseCaptureCommand {
    pub envelope: LiveCommandEnvelope,
    pub operation_id: LiveId,
}

/// One complete typed live request. Equality is the replay/conflict oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "command", deny_unknown_fields)]
pub enum LiveCommand {
    Pause(PauseCommand),
    Resume(ResumeCommand),
    GetOperation(GetOperationCommand),
    CancelOperation(CancelOperationCommand),
    Capture(CaptureCommand),
    ReleaseCapture(ReleaseCaptureCommand),
}

impl LiveCommand {
    pub fn envelope(&self) -> &LiveCommandEnvelope {
        match self {
            Self::Pause(command) => &command.envelope,
            Self::Resume(command) => &command.envelope,
            Self::GetOperation(command) => &command.envelope,
            Self::CancelOperation(command) => &command.envelope,
            Self::Capture(command) => &command.envelope,
            Self::ReleaseCapture(command) => &command.envelope,
        }
    }

    /// The operation this command names. Pause and Capture create the
    /// operation whose ID is their request ID.
    pub fn target_operation_id(&self) -> &LiveId {
        match self {
            Self::Pause(command) => &command.envelope.request_id,
            Self::Capture(command) => &command.envelope.request_id,
            Self::Resume(command) => &command.operation_id,
            Self::GetOperation(command) => &command.operation_id,
            Self::CancelOperation(command) => &command.operation_id,
            Self::ReleaseCapture(command) => &command.operation_id,
        }
    }

    pub fn kind(&self) -> LiveCommandKind {
        match self {
            Self::Pause(_) => LiveCommandKind::Pause,
            Self::Resume(_) => LiveCommandKind::Resume,
            Self::GetOperation(_) => LiveCommandKind::GetOperation,
            Self::CancelOperation(_) => LiveCommandKind::CancelOperation,
            Self::Capture(_) => LiveCommandKind::Capture,
            Self::ReleaseCapture(_) => LiveCommandKind::ReleaseCapture,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Capture(command) => {
                let digest = &command.expected_configuration_digest;
                if digest.is_empty()
                    || digest.len() > 256
                    || !digest.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(
                        "expected configuration digest must be 1..256 printable ASCII bytes".into(),
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveOperationReceipt {
    pub operation_id: LiveId,
    pub kind: OperationKind,
    pub state: VmLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum PauseOutcome {
    Accepted { receipt: LiveOperationReceipt },
    Rejected { rejection: LiveRejection },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum CaptureOutcome {
    Accepted { receipt: LiveOperationReceipt },
    Rejected { rejection: LiveRejection },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeCompleted {
    pub consumed_token: PauseToken,
    pub thawed_epoch: NonZeroU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResumeFailed {
    pub cause: LiveFailure,
    /// Paused, Error, or stopping when stop preempted the continuation.
    pub state: VmLifecycleState,
    /// Authority current at completion when Paused: the requested token when
    /// native kept it parked (not consumed), or NEW authority established by
    /// lost-thaw recovery (strictly newer generation).
    pub current_pause: Option<CurrentPause>,
    /// Recovery's own failure when it could not establish new authority.
    pub recovery_failure: Option<LiveFailure>,
    /// The token this Resume named.
    pub requested_token: PauseToken,
}

impl ResumeFailed {
    pub fn validate(&self) -> Result<(), String> {
        self.cause.validate()?;
        match (self.state, &self.current_pause, &self.recovery_failure) {
            (VmLifecycleState::Paused, Some(current), None) => {
                let requested = &self.requested_token;
                if current.token.generation == requested.generation && &current.token != requested {
                    return Err("retained pause must be exactly the requested token".into());
                }
                if current.token.generation < requested.generation {
                    return Err("current pause cannot be older than the requested token".into());
                }
                Ok(())
            }
            (state, None, failure)
                if state == VmLifecycleState::Error || state.is_stopping_or_terminal() =>
            {
                failure.as_ref().map_or(Ok(()), LiveFailure::validate)
            }
            _ => Err(
                "resume failure must end paused with current authority, in error or stopping"
                    .into(),
            ),
        }
    }
}

// Keep bounded control replies inline rather than allocating an extra box per reply.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum ResumeOutcome {
    Resumed { resumed: ResumeCompleted },
    Failed { failed: ResumeFailed },
    Rejected { rejection: LiveRejection },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationObservation {
    pub operation: LiveOperationRecord,
    pub state: VmLifecycleState,
    pub current_pause: Option<CurrentPause>,
    pub activity: Option<LiveActivity>,
}

// Observations are the normal result; boxing adds an allocation to every status query.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum GetOperationOutcome {
    Observation { observation: OperationObservation },
    Rejected { rejection: LiveRejection },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelCompleted {
    /// False: a finished operation, returned unchanged without effects.
    pub effective: bool,
    pub operation: LiveOperationRecord,
    pub state: VmLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelFailed {
    /// Cleanup failure; the target keeps its own primary failure.
    pub cause: LiveFailure,
    pub operation: LiveOperationRecord,
    pub state: VmLifecycleState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum CancelOperationOutcome {
    Completed { completed: CancelCompleted },
    Failed { failed: CancelFailed },
    Rejected { rejection: LiveRejection },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum ReleaseCaptureOutcome {
    Rejected { rejection: LiveRejection },
}

/// One complete typed live result; mirrors the six response oneofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "command", deny_unknown_fields)]
pub enum LiveCommandResult {
    Pause(PauseOutcome),
    Resume(ResumeOutcome),
    GetOperation(GetOperationOutcome),
    CancelOperation(CancelOperationOutcome),
    Capture(CaptureOutcome),
    ReleaseCapture(ReleaseCaptureOutcome),
}

impl LiveCommandResult {
    pub fn kind(&self) -> LiveCommandKind {
        match self {
            Self::Pause(_) => LiveCommandKind::Pause,
            Self::Resume(_) => LiveCommandKind::Resume,
            Self::GetOperation(_) => LiveCommandKind::GetOperation,
            Self::CancelOperation(_) => LiveCommandKind::CancelOperation,
            Self::Capture(_) => LiveCommandKind::Capture,
            Self::ReleaseCapture(_) => LiveCommandKind::ReleaseCapture,
        }
    }

    pub fn rejection(&self) -> Option<&LiveRejection> {
        match self {
            Self::Pause(PauseOutcome::Rejected { rejection })
            | Self::Capture(CaptureOutcome::Rejected { rejection })
            | Self::Resume(ResumeOutcome::Rejected { rejection })
            | Self::GetOperation(GetOperationOutcome::Rejected { rejection })
            | Self::CancelOperation(CancelOperationOutcome::Rejected { rejection })
            | Self::ReleaseCapture(ReleaseCaptureOutcome::Rejected { rejection }) => {
                Some(rejection)
            }
            _ => None,
        }
    }

    pub fn rejected(kind: LiveCommandKind, rejection: LiveRejection) -> Self {
        match kind {
            LiveCommandKind::Pause => Self::Pause(PauseOutcome::Rejected { rejection }),
            LiveCommandKind::Resume => Self::Resume(ResumeOutcome::Rejected { rejection }),
            LiveCommandKind::GetOperation => {
                Self::GetOperation(GetOperationOutcome::Rejected { rejection })
            }
            LiveCommandKind::CancelOperation => {
                Self::CancelOperation(CancelOperationOutcome::Rejected { rejection })
            }
            LiveCommandKind::Capture => Self::Capture(CaptureOutcome::Rejected { rejection }),
            LiveCommandKind::ReleaseCapture => {
                Self::ReleaseCapture(ReleaseCaptureOutcome::Rejected { rejection })
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(rejection) = self.rejection() {
            return rejection.validate();
        }
        match self {
            Self::Resume(ResumeOutcome::Failed { failed }) => failed.validate(),
            Self::GetOperation(GetOperationOutcome::Observation { observation }) => {
                observation.operation.validate()
            }
            Self::CancelOperation(CancelOperationOutcome::Completed { completed }) => {
                completed.operation.validate()
            }
            Self::CancelOperation(CancelOperationOutcome::Failed { failed }) => {
                failed.cause.validate()?;
                failed.operation.validate()
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lifecycle::*;

    #[test]
    fn matrix_matches_adr_0021_rows() {
        use LiveCommandKind as C;
        use VmLifecycleState as S;
        let rows: &[(S, &[C])] = &[
            (
                S::Running,
                &[C::Pause, C::Capture, C::GetOperation, C::ReleaseCapture],
            ),
            (S::Pausing, &[C::GetOperation, C::CancelOperation]),
            (
                S::Paused,
                &[C::Resume, C::Capture, C::GetOperation, C::ReleaseCapture],
            ),
            (S::Capturing, &[C::GetOperation, C::CancelOperation]),
            (S::Restoring, &[C::GetOperation]),
            (S::Activating, &[C::GetOperation]),
            (S::ActivationFailed, &[C::GetOperation, C::ReleaseCapture]),
            (S::Error, &[C::GetOperation, C::ReleaseCapture]),
            (S::Starting, &[]),
            (S::Stopping, &[]),
            (S::Stopped, &[]),
            (S::Failed, &[]),
        ];
        assert_eq!(rows.len(), S::ALL.len());
        for (state, admitted) in rows {
            for command in C::ALL {
                assert_eq!(
                    state.admits(*command),
                    admitted.contains(command),
                    "{state} x {command}"
                );
            }
            assert_eq!(state.readiness_eligible(), *state == S::Running);
        }
    }

    #[test]
    fn identifiers_are_canonical_non_nil() {
        assert!(LiveId::parse("00000000-0000-4000-8000-000000000001").is_ok());
        for invalid in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-00000000000A",
            "{00000000-0000-4000-8000-000000000001}",
            "00000000000040008000000000000001",
        ] {
            assert!(LiveId::parse(invalid).is_err(), "{invalid}");
            assert!(serde_json::from_value::<LiveId>(serde_json::json!(invalid)).is_err());
        }
    }

    #[test]
    fn diagnostics_truncate_on_construction_and_reject_oversized_decode() {
        let long = "é".repeat(MAX_LIFECYCLE_DIAGNOSTIC_BYTES);
        let diagnostic = Diagnostic::new(long.clone());
        assert!(diagnostic.as_str().len() <= MAX_LIFECYCLE_DIAGNOSTIC_BYTES);
        assert!(serde_json::from_value::<Diagnostic>(serde_json::json!(long)).is_err());
    }

    fn id(last: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-0000000000{last:02x}")).unwrap()
    }

    fn token(generation: u64) -> PauseToken {
        PauseToken {
            machine_id: id(1),
            run_id: id(2),
            generation: NonZeroU64::new(generation).unwrap(),
            owner: PauseOwner::User,
        }
    }

    #[test]
    fn command_identity_and_strict_json_roundtrip() {
        let envelope = LiveCommandEnvelope {
            machine_id: id(1),
            run_id: id(2),
            request_id: id(3),
        };
        let resume = LiveCommand::Resume(ResumeCommand {
            envelope: envelope.clone(),
            operation_id: id(4),
            token: token(1),
        });
        assert_eq!(resume.kind(), LiveCommandKind::Resume);
        assert_eq!(resume.target_operation_id(), &id(4));
        let pause = LiveCommand::Pause(PauseCommand { envelope });
        assert_eq!(pause.target_operation_id(), &id(3));
        for command in [resume, pause] {
            let value = serde_json::to_value(&command).unwrap();
            assert_eq!(
                serde_json::from_value::<LiveCommand>(value.clone()).unwrap(),
                command
            );
            let mut unknown = value;
            unknown["extra"] = serde_json::json!(1);
            assert!(serde_json::from_value::<LiveCommand>(unknown).is_err());
        }
    }

    #[test]
    fn lifecycle_presence_rules_follow_state() {
        let paused = LiveLifecycle {
            current_pause: Some(CurrentPause {
                token: token(1),
                operation_id: id(3),
                freeze_epoch: NonZeroU64::new(1).unwrap(),
            }),
            ..LiveLifecycle::default()
        };
        assert!(paused.validate_for(VmLifecycleState::Paused).is_ok());
        assert!(paused.validate_for(VmLifecycleState::Running).is_err());
        assert!(LiveLifecycle::default()
            .validate_for(VmLifecycleState::Running)
            .is_ok());
        assert!(LiveLifecycle::default()
            .validate_for(VmLifecycleState::Pausing)
            .is_err());
        assert!(LiveLifecycle::default()
            .validate_for(VmLifecycleState::Error)
            .is_err());
    }

    #[test]
    fn resume_failure_authority_is_retained_exact_or_strictly_newer() {
        let failure = LiveFailure::new(
            LiveFailureCode::ThawUnacknowledged,
            LiveStage::ResumeThaw,
            "thaw lost",
        );
        let paused = |current: PauseToken| ResumeFailed {
            cause: failure.clone(),
            state: VmLifecycleState::Paused,
            current_pause: Some(CurrentPause {
                token: current,
                operation_id: id(3),
                freeze_epoch: NonZeroU64::new(2).unwrap(),
            }),
            recovery_failure: None,
            requested_token: token(2),
        };
        assert!(paused(token(3)).validate().is_ok());
        assert!(paused(token(2)).validate().is_ok());
        assert!(paused(token(1)).validate().is_err());
        let mut foreign = token(2);
        foreign.owner = PauseOwner::Capture {
            operation_id: id(9),
        };
        assert!(paused(foreign).validate().is_err());
        let running = ResumeFailed {
            state: VmLifecycleState::Running,
            current_pause: None,
            ..paused(token(3))
        };
        assert!(running.validate().is_err());
        let error_with_authority = ResumeFailed {
            state: VmLifecycleState::Error,
            ..paused(token(3))
        };
        assert!(error_with_authority.validate().is_err());
    }
}

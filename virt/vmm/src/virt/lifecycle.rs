//! Native lifecycle seam between the monitor coordinator and the backend.
//!
//! The monitor owns public operations, guest freeze/thaw and state projection.
//! The backend owns the native pause authority: opaque native tokens and
//! generation tickets never leave the worker. Requests are journaled by
//! [`CommandKey`] for the backend's (run's) lifetime, so a dropped caller wait
//! never cancels accepted native work and an identical retry joins it.
//!
//! ```text
//!  monitor ── lifecycle(request) ──► backend client ══ framed socket ══► worker
//!                                     (sequence)                         (native
//!  monitor ◄── report/ control ───── backend client ◄═════════════════   owner)
//! ```

use std::num::NonZeroU64;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bounded diagnostic text carried in native failures.
pub const MAX_FAILURE_DETAIL: usize = 1024;
/// Smallest and largest native lifecycle command budget.
pub const MIN_LIFECYCLE_TIMEOUT: Duration = Duration::from_millis(1);
pub const MAX_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRequest {
    pub machine_id: Uuid,
    pub run_id: Uuid,
    pub request_id: Uuid,
    pub command: LifecycleCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleCommand {
    /// Establish a native User pause owned by public operation `operation`.
    Pause {
        operation: Uuid,
        purpose: PausePurpose,
        #[serde(with = "millis")]
        timeout: Duration,
        clock_profile: Option<ObservedClockProfile>,
    },
    /// Consume the exact current native pause of `operation` through a resident
    /// ClockOnly generation. Completes only on its acknowledgement.
    Resume {
        operation: Uuid,
        generation: NativePauseGeneration,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Settle the unfinished, failed or unpublished native pause of
    /// `operation` back to Running.
    CancelPause {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Observe native control and, optionally, one retained command.
    GetControl { target: Option<CommandKey> },
}

impl LifecycleCommand {
    /// The journal kind of a mutating command; `None` for observations.
    pub fn kind(&self) -> Option<CommandKind> {
        match self {
            Self::Pause { .. } => Some(CommandKind::Pause),
            Self::Resume { .. } => Some(CommandKind::Resume),
            Self::CancelPause { .. } => Some(CommandKind::CancelPause),
            Self::GetControl { .. } => None,
        }
    }

    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Pause { operation, .. }
            | Self::Resume { operation, .. }
            | Self::CancelPause { operation, .. } => Some(*operation),
            Self::GetControl { .. } => None,
        }
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Pause { timeout, .. }
            | Self::Resume { timeout, .. }
            | Self::CancelPause { timeout, .. } => Some(*timeout),
            Self::GetControl { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum PausePurpose {
    /// First pause of a public operation: `request_id == operation`.
    Initial,
    /// Lost-thaw recovery inside the Resume request that released `consumed`.
    Recovery { consumed: NativePauseGeneration },
}

/// Positive same-boot observations required for the native retired-PIT profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedClockProfile {
    pub boot_id: Uuid,
    pub kernel_identity: String,
    pub clocksource: ObservedClocksource,
    pub online_clockevents: Vec<ObservedClockevent>,
    pub broadcast: ObservedBroadcastClockevent,
    pub modules: ObservedModules,
    pub no_speaker_consumers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedClocksource {
    Tsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedClockevent {
    pub cpu: u32,
    pub device: ObservedClockeventDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedClockeventDevice {
    LapicDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ObservedBroadcastClockevent {
    NoDevice,
    NonPit { device: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedModules {
    ProcModules,
    BuiltInDisabled,
}

impl ObservedClockProfile {
    pub fn from_guest(
        profile: &protocol::v1::GuestClockProfile,
    ) -> Result<Self, LifecycleRejection> {
        use protocol::v1::{
            GuestBroadcastClockeventKind, GuestClockeventDevice, GuestClocksource,
            GuestModulesEvidence,
        };
        let invalid = || LifecycleRejection::InvalidRequest(InvalidRequest::ClockProfile);
        if profile.clocksource != GuestClocksource::Tsc as i32
            || profile.kernel_identity.len() > 4096
            || profile.broadcast_device.len() > 256
        {
            return Err(invalid());
        }
        let broadcast = match GuestBroadcastClockeventKind::try_from(profile.broadcast_kind) {
            Ok(GuestBroadcastClockeventKind::NoDevice) if profile.broadcast_device.is_empty() => {
                ObservedBroadcastClockevent::NoDevice
            }
            Ok(GuestBroadcastClockeventKind::NonPit) => ObservedBroadcastClockevent::NonPit {
                device: profile.broadcast_device.clone(),
            },
            _ => return Err(invalid()),
        };
        let modules = match GuestModulesEvidence::try_from(profile.modules) {
            Ok(GuestModulesEvidence::ProcModules) => ObservedModules::ProcModules,
            Ok(GuestModulesEvidence::BuiltInDisabled) => ObservedModules::BuiltInDisabled,
            _ => return Err(invalid()),
        };
        if profile.online_clockevents.len() > 4096 {
            return Err(invalid());
        }
        let online_clockevents = profile
            .online_clockevents
            .iter()
            .map(|event| {
                if event.device != GuestClockeventDevice::LapicDeadline as i32 {
                    return Err(invalid());
                }
                Ok(ObservedClockevent {
                    cpu: event.cpu,
                    device: ObservedClockeventDevice::LapicDeadline,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let observed = Self {
            boot_id: Uuid::parse_str(&profile.boot_id).map_err(|_| invalid())?,
            kernel_identity: profile.kernel_identity.clone(),
            clocksource: ObservedClocksource::Tsc,
            online_clockevents,
            broadcast,
            modules,
            no_speaker_consumers: profile.no_speaker_consumers,
        };
        observed.validate()?;
        Ok(observed)
    }

    pub fn validate(&self) -> Result<(), LifecycleRejection> {
        let ordered = self
            .online_clockevents
            .windows(2)
            .all(|pair| pair[0].cpu < pair[1].cpu);
        let broadcast_valid = match &self.broadcast {
            ObservedBroadcastClockevent::NoDevice => true,
            ObservedBroadcastClockevent::NonPit { device } => {
                !device.is_empty()
                    && device.len() <= 256
                    && device.trim() == device
                    && !device.contains(char::is_whitespace)
                    && !device
                        .as_bytes()
                        .windows(3)
                        .any(|name| name.eq_ignore_ascii_case(b"pit"))
            }
        };
        if self.boot_id.is_nil()
            || self.kernel_identity.trim().is_empty()
            || self.kernel_identity.len() > 4096
            || self.kernel_identity.contains('\0')
            || self.online_clockevents.is_empty()
            || self.online_clockevents.len() > 4096
            || !ordered
            || !broadcast_valid
            || !self.no_speaker_consumers
        {
            return Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::ClockProfile,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Pause,
    Resume,
    CancelPause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandKey {
    pub request_id: Uuid,
    pub kind: CommandKind,
}

macro_rules! nonzero_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub fn new(value: u64) -> Option<Self> {
                NonZeroU64::new(value).map(Self)
            }

            pub fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

nonzero_id!(
    /// Exact native pause token generation, strictly increasing within a run.
    NativePauseGeneration
);
nonzero_id!(
    /// Worker-allocated native operation identity (diagnostic only).
    NativeOperation
);
nonzero_id!(
    /// Backend-allocated checked transport identity of one command.
    CommandSequence
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleResponse {
    /// Native control observed with this report.
    pub control: ControlObservation,
    /// `None` only for `GetControl { target: None }`.
    pub command: Option<CommandReport>,
    /// Fresh native provider inventory; present only for `GetControl`.
    pub inventory: Option<InventoryObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "observation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlObservation {
    Observed { control: NativeControl },
    Unavailable { failure: NativeFailure },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeControl {
    Running,
    Pausing {
        operation: NativeOperation,
        failed: bool,
    },
    /// Every vCPU is positively parked behind the native pause barrier.
    Paused {
        generation: NativePauseGeneration,
        owner: NativePauseOwner,
    },
    Resuming {
        operation: NativeOperation,
    },
    RollingBack {
        operation: NativeOperation,
    },
    RestorePrepared,
    FailedFenced,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePauseOwner {
    User,
    Capture,
}

/// Native live provider inventory, enumerated from the native owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "observation", rename_all = "snake_case", deny_unknown_fields)]
pub enum InventoryObservation {
    Observed {
        providers: Vec<NativeProvider>,
        memory_tracking: Option<MemoryTracking>,
    },
    /// Includes a live device without a state provider: native fails closed.
    Unavailable { failure: NativeFailure },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProvider {
    pub device: ProviderDevice,
    /// Configured attachment identity (block ID for disks).
    pub configured_id: String,
    pub address: u64,
    pub irq: u32,
    pub activation_fenced: Option<bool>,
    /// Backing format of a block provider, joined from the launch it built.
    pub block_backing: Option<BlockBacking>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "device", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderDevice {
    Virtio {
        device_id: u32,
        kind: VirtioKind,
    },
    /// A native device type this build cannot classify; never admissible.
    Unrecognized {
        description: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtioKind {
    Net,
    Block,
    Console,
    Rng,
    Balloon,
    Gpu,
    Input,
    Vsock,
    Fs,
    Generation,
    Other,
}

impl VirtioKind {
    pub fn from_device_id(device_id: u32) -> Self {
        match device_id {
            1 => Self::Net,
            2 => Self::Block,
            3 => Self::Console,
            4 => Self::Rng,
            5 => Self::Balloon,
            16 => Self::Gpu,
            18 => Self::Input,
            19 => Self::Vsock,
            26 => Self::Fs,
            0x5347 => Self::Generation,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockBacking {
    Raw,
    Vmdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTracking {
    Disabled,
    Capture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReport {
    pub key: CommandKey,
    pub sequence: CommandSequence,
    /// Public target operation.
    pub operation: Uuid,
    pub state: CommandState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandState {
    /// Admitted; the worker owns its native work and has no terminal result yet.
    Accepted,
    Completed {
        outcome: CommandOutcome,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandOutcome {
    /// Complete native barrier; the token is retained in the worker.
    Paused { pause: NativePause },
    /// No token. Native control distinguishes failed Pausing from Running.
    PauseFailed { failure: NativeFailure },
    /// Cancellation was admitted first; no token was published.
    PauseWithdrawn,
    /// Released and the exact ClockOnly request was acknowledged in time.
    Resumed { clock: ClockOnlyReceipt },
    /// `pause_retained`: native is still Paused with the same generation.
    ResumeFailed {
        stage: ResumeStage,
        failure: NativeFailure,
        pause_retained: bool,
    },
    /// Native is back to Running.
    CancelSettled { settlement: CancelSettlement },
    CancelFailed {
        stage: CancelStage,
        failure: NativeFailure,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePause {
    pub generation: NativePauseGeneration,
    pub owner: NativePauseOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockOnlyReceipt {
    /// Generation request sequence published to the guest driver.
    pub sequence: u64,
    /// Request flags: always the native SYNC_CLOCK | CLOCK_ONLY pair.
    pub flags: u32,
    /// From release submission to the guest driver's acknowledgement.
    #[serde(with = "millis")]
    pub acknowledged_within: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", rename_all = "snake_case", deny_unknown_fields)]
pub enum CancelSettlement {
    /// The pause never took native effect.
    NoNativeEffect,
    RolledBack,
    /// The native pause completed; its token was consumed by a ClockOnly resume.
    ConsumedCompletedPause {
        clock: ClockOnlyReceipt,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeStage {
    PrepareClock,
    Release,
    ClockAcknowledgement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub enum CancelStage {
    Rollback,
    ConsumeCompletedPause { resume: ResumeStage },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFailure {
    pub kind: NativeFailureKind,
    pub detail: Option<String>,
}

impl NativeFailure {
    pub fn new(kind: NativeFailureKind) -> Self {
        Self { kind, detail: None }
    }

    pub fn with_detail(kind: NativeFailureKind, detail: impl std::fmt::Display) -> Self {
        Self {
            kind,
            detail: Some(bounded(detail.to_string())),
        }
    }
}

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "native {:?}: {detail}", self.kind),
            None => write!(f, "native {:?}", self.kind),
        }
    }
}

fn bounded(mut text: String) -> String {
    if text.len() > MAX_FAILURE_DETAIL {
        let mut end = MAX_FAILURE_DETAIL;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "generation", rename_all = "snake_case")]
pub enum NativeFailureKind {
    Deadline,
    CallerTimeout,
    OwnerUnavailable,
    WakeUnknown,
    Busy,
    InvalidToken,
    InvalidOperation,
    Exhausted,
    Unsupported,
    Participant,
    Memory,
    DirtyMemory,
    FailedFenced,
    Generation(GenerationFailureKind),
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationFailureKind {
    Deadline,
    DriverError,
    InvalidStatus,
    Notification,
    Reset,
    Stopped,
    Release,
    Poisoned,
    /// A native generation failure this build cannot classify.
    Unrecognized,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    /// Definitive: this request caused no native effect.
    #[error("native lifecycle request rejected: {0}")]
    Rejected(LifecycleRejection),
    /// Completion unknown: replay the same request or query with GetControl.
    #[error("native lifecycle completion unknown: {0}")]
    Unknown(LifecycleUncertainty),
    /// Only the macOS Virtualization.framework backend lacks native lifecycle
    /// authority; every other platform backend never constructs this.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    #[error("backend {backend} has no native lifecycle control")]
    Unsupported { backend: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "rejection", content = "reason", rename_all = "snake_case")]
pub enum LifecycleRejection {
    #[error("request belongs to another machine or run")]
    WrongRun,
    #[error("invalid request: {0}")]
    InvalidRequest(InvalidRequest),
    #[error("request identity is already bound to different inputs")]
    RequestConflict,
    #[error("unknown target command")]
    UnknownTarget,
    #[error("no current native pause for the operation")]
    NoCurrentPause,
    #[error("pause generation is not the current native pause")]
    StaleGeneration,
    #[error("another native pause is active")]
    PauseActive,
    #[error("target pause is not cancellable")]
    NotCancellable,
    #[error("another native lifecycle command is in flight")]
    Busy,
    #[error("worker lifecycle endpoint is not ready")]
    NotReady,
    #[error("machine is stopping")]
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum InvalidRequest {
    #[error("identities must be non-nil")]
    NilIdentity,
    #[error("timeout outside the supported range")]
    Timeout,
    #[error("an initial pause must use its operation as request identity")]
    InitialRequestIdentity,
    #[error("a recovery pause cannot use its operation as request identity")]
    RecoveryRequestIdentity,
    #[error("invalid or incomplete observed guest clock profile")]
    ClockProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleUncertainty {
    #[error("worker lifecycle owner is gone")]
    WorkerLost,
    #[error("worker lifecycle protocol failure: {0}")]
    Protocol(String),
    #[error("worker lifecycle transport failure: {0}")]
    Transport(String),
}

impl LifecycleRequest {
    /// Shape validation shared by every backend before any effect.
    pub fn validate(&self) -> Result<(), LifecycleRejection> {
        let invalid = |reason| Err(LifecycleRejection::InvalidRequest(reason));
        if self.machine_id.is_nil() || self.run_id.is_nil() || self.request_id.is_nil() {
            return invalid(InvalidRequest::NilIdentity);
        }
        if self
            .command
            .operation()
            .is_some_and(|operation| operation.is_nil())
            || matches!(
                &self.command,
                LifecycleCommand::GetControl { target: Some(target) } if target.request_id.is_nil()
            )
        {
            return invalid(InvalidRequest::NilIdentity);
        }
        if self.command.timeout().is_some_and(|timeout| {
            !(MIN_LIFECYCLE_TIMEOUT..=MAX_LIFECYCLE_TIMEOUT).contains(&timeout)
        }) {
            return invalid(InvalidRequest::Timeout);
        }
        if let LifecycleCommand::Pause {
            operation,
            purpose,
            clock_profile,
            ..
        } = &self.command
        {
            match purpose {
                PausePurpose::Initial if *operation != self.request_id => {
                    return invalid(InvalidRequest::InitialRequestIdentity)
                }
                PausePurpose::Recovery { .. } if *operation == self.request_id => {
                    return invalid(InvalidRequest::RecoveryRequestIdentity)
                }
                _ => {}
            }
            if let Some(profile) = clock_profile {
                profile.validate()?;
            }
        }
        Ok(())
    }
}

/// Durations travel as integral milliseconds; sub-millisecond parts are refused.
pub(crate) mod millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let millis = u64::try_from(value.as_millis())
            .map_err(|_| serde::ser::Error::custom("duration exceeds u64 milliseconds"))?;
        if Duration::from_millis(millis) != *value {
            return Err(serde::ser::Error::custom(
                "duration is not integral milliseconds",
            ));
        }
        serializer.serialize_u64(millis)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use uuid::Uuid;

    use crate::virt::lifecycle::*;

    fn request(command: LifecycleCommand, request_id: Uuid) -> LifecycleRequest {
        LifecycleRequest {
            machine_id: Uuid::new_v4(),
            run_id: Uuid::new_v4(),
            request_id,
            command,
        }
    }

    #[test]
    fn shape_validation_refuses_nil_identities_bad_budgets_and_purpose_misuse() {
        let operation = Uuid::new_v4();
        let pause = |purpose, timeout| LifecycleCommand::Pause {
            operation,
            purpose,
            timeout,
            clock_profile: None,
        };
        let generation = NativePauseGeneration::new(3).expect("nonzero");
        let ok = Duration::from_secs(5);
        assert_eq!(
            request(pause(PausePurpose::Initial, ok), operation).validate(),
            Ok(())
        );
        let mut nil = request(pause(PausePurpose::Initial, ok), operation);
        nil.run_id = Uuid::nil();
        assert_eq!(
            nil.validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::NilIdentity
            ))
        );
        for timeout in [
            Duration::ZERO,
            MAX_LIFECYCLE_TIMEOUT + Duration::from_millis(1),
        ] {
            assert_eq!(
                request(pause(PausePurpose::Initial, timeout), operation).validate(),
                Err(LifecycleRejection::InvalidRequest(InvalidRequest::Timeout))
            );
        }
        assert_eq!(
            request(pause(PausePurpose::Initial, ok), Uuid::new_v4()).validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::InitialRequestIdentity
            ))
        );
        assert_eq!(
            request(
                pause(
                    PausePurpose::Recovery {
                        consumed: generation
                    },
                    ok
                ),
                operation
            )
            .validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::RecoveryRequestIdentity
            ))
        );
        assert_eq!(
            request(
                LifecycleCommand::GetControl {
                    target: Some(CommandKey {
                        request_id: Uuid::nil(),
                        kind: CommandKind::Pause,
                    }),
                },
                Uuid::new_v4(),
            )
            .validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::NilIdentity
            ))
        );
    }

    #[test]
    fn identities_are_nonzero_and_durations_are_integral_milliseconds() {
        assert!(NativePauseGeneration::new(0).is_none());
        assert!(serde_json::from_str::<NativePauseGeneration>("0").is_err());
        let receipt = ClockOnlyReceipt {
            sequence: 4,
            flags: 3,
            acknowledged_within: Duration::from_millis(17),
        };
        let encoded = serde_json::to_string(&receipt).expect("encode");
        assert_eq!(
            serde_json::from_str::<ClockOnlyReceipt>(&encoded).expect("decode"),
            receipt
        );
        let fractional = ClockOnlyReceipt {
            acknowledged_within: Duration::from_micros(1500),
            ..receipt
        };
        assert!(serde_json::to_string(&fractional).is_err());
    }

    #[test]
    fn failure_detail_is_bounded_on_a_character_boundary() {
        let failure = NativeFailure::with_detail(NativeFailureKind::Participant, "é".repeat(4096));
        let detail = failure.detail.expect("detail");
        assert!(detail.len() <= MAX_FAILURE_DETAIL);
        assert!(detail.chars().all(|c| c == 'é'));
    }

    #[test]
    fn guest_clock_profile_requires_complete_typed_positive_evidence() {
        use protocol::v1::{
            GuestBroadcastClockeventKind, GuestClockProfile, GuestClockeventDevice,
            GuestClocksource, GuestModulesEvidence, GuestOnlineClockevent,
        };
        let profile = GuestClockProfile {
            boot_id: Uuid::new_v4().to_string(),
            kernel_identity: "Linux version observed-test-kernel\n".into(),
            clocksource: GuestClocksource::Tsc as i32,
            online_clockevents: vec![
                GuestOnlineClockevent {
                    cpu: 0,
                    device: GuestClockeventDevice::LapicDeadline as i32,
                },
                GuestOnlineClockevent {
                    cpu: 2,
                    device: GuestClockeventDevice::LapicDeadline as i32,
                },
            ],
            broadcast_kind: GuestBroadcastClockeventKind::NoDevice as i32,
            broadcast_device: String::new(),
            modules: GuestModulesEvidence::BuiltInDisabled as i32,
            no_speaker_consumers: true,
        };
        let observed = ObservedClockProfile::from_guest(&profile).expect("actual positive profile");
        assert_eq!(observed.boot_id.to_string(), profile.boot_id);
        for invalid in [
            GuestClockProfile {
                boot_id: Uuid::nil().to_string(),
                ..profile.clone()
            },
            GuestClockProfile {
                kernel_identity: String::new(),
                ..profile.clone()
            },
            GuestClockProfile {
                clocksource: 0,
                ..profile.clone()
            },
            GuestClockProfile {
                online_clockevents: Vec::new(),
                ..profile.clone()
            },
            GuestClockProfile {
                online_clockevents: vec![
                    GuestOnlineClockevent {
                        cpu: 0,
                        device: GuestClockeventDevice::LapicDeadline as i32,
                    },
                    GuestOnlineClockevent {
                        cpu: 0,
                        device: GuestClockeventDevice::LapicDeadline as i32,
                    },
                ],
                ..profile.clone()
            },
            GuestClockProfile {
                broadcast_kind: 0,
                ..profile.clone()
            },
            GuestClockProfile {
                broadcast_kind: GuestBroadcastClockeventKind::NonPit as i32,
                broadcast_device: "pit".into(),
                ..profile.clone()
            },
            GuestClockProfile {
                broadcast_device: "unbound".into(),
                ..profile.clone()
            },
            GuestClockProfile {
                modules: 0,
                ..profile.clone()
            },
            GuestClockProfile {
                no_speaker_consumers: false,
                ..profile.clone()
            },
        ] {
            assert!(
                ObservedClockProfile::from_guest(&invalid).is_err(),
                "{invalid:?}"
            );
        }
        let operation = Uuid::new_v4();
        let command = LifecycleCommand::Pause {
            operation,
            purpose: PausePurpose::Initial,
            timeout: Duration::from_secs(1),
            clock_profile: Some(observed),
        };
        let bytes = serde_json::to_vec(&command).expect("encode actual profile");
        assert_eq!(
            serde_json::from_slice::<LifecycleCommand>(&bytes).expect("decode"),
            command
        );
        assert!(request(command, operation).validate().is_ok());
    }
}

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
    /// Validate and retain the five capture descriptors before any freeze.
    /// Carries [`LifecycleRights::CaptureOutputs`].
    PrepareCapture {
        operation: Uuid,
        preparation: CapturePreparation,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Exact-token native flush of every writable attachment.
    FlushCapture {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Move the prepared execution and device outputs into native capture.
    CaptureExecution {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Move the prepared RAM and layout outputs into a full native RAM capture.
    CaptureMemory {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Accept the sealed RAM/layout as the native baseline. Legal only after
    /// the durable seal. Carries [`LifecycleRights::SealedMemory`].
    AcceptCapture {
        operation: Uuid,
        ram: OutputIdentity,
        layout: OutputIdentity,
        /// ADR 0014 RAM StreamId, not a whole-file digest.
        stream: Digest32,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Resolve an unsealed capture and close every output owner.
    AbandonCapture {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Continue the source after the capture resolved.
    ContinueCapture {
        operation: Uuid,
        continuation: CaptureContinuation,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Release the resolved native capture result.
    ReleaseCapture {
        operation: Uuid,
        #[serde(with = "millis")]
        timeout: Duration,
    },
    /// Observe one capture; never waits on native mutators.
    GetCapture { operation: Uuid },
}

impl LifecycleCommand {
    /// The journal kind of a mutating command; `None` for observations.
    pub fn kind(&self) -> Option<CommandKind> {
        match self {
            Self::Pause { .. } => Some(CommandKind::Pause),
            Self::Resume { .. } => Some(CommandKind::Resume),
            Self::CancelPause { .. } => Some(CommandKind::CancelPause),
            Self::PrepareCapture { .. } => Some(CommandKind::PrepareCapture),
            Self::FlushCapture { .. } => Some(CommandKind::FlushCapture),
            Self::CaptureExecution { .. } => Some(CommandKind::CaptureExecution),
            Self::CaptureMemory { .. } => Some(CommandKind::CaptureMemory),
            Self::AcceptCapture { .. } => Some(CommandKind::AcceptCapture),
            Self::AbandonCapture { .. } => Some(CommandKind::AbandonCapture),
            Self::ContinueCapture { .. } => Some(CommandKind::ContinueCapture),
            Self::ReleaseCapture { .. } => Some(CommandKind::ReleaseCapture),
            Self::GetControl { .. } | Self::GetCapture { .. } => None,
        }
    }

    pub fn operation(&self) -> Option<Uuid> {
        match self {
            Self::Pause { operation, .. }
            | Self::Resume { operation, .. }
            | Self::CancelPause { operation, .. }
            | Self::PrepareCapture { operation, .. }
            | Self::FlushCapture { operation, .. }
            | Self::CaptureExecution { operation, .. }
            | Self::CaptureMemory { operation, .. }
            | Self::AcceptCapture { operation, .. }
            | Self::AbandonCapture { operation, .. }
            | Self::ContinueCapture { operation, .. }
            | Self::ReleaseCapture { operation, .. }
            | Self::GetCapture { operation } => Some(*operation),
            Self::GetControl { .. } => None,
        }
    }

    pub fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Pause { timeout, .. }
            | Self::Resume { timeout, .. }
            | Self::CancelPause { timeout, .. }
            | Self::PrepareCapture { timeout, .. }
            | Self::FlushCapture { timeout, .. }
            | Self::CaptureExecution { timeout, .. }
            | Self::CaptureMemory { timeout, .. }
            | Self::AcceptCapture { timeout, .. }
            | Self::AbandonCapture { timeout, .. }
            | Self::ContinueCapture { timeout, .. }
            | Self::ReleaseCapture { timeout, .. } => Some(*timeout),
            Self::GetControl { .. } | Self::GetCapture { .. } => None,
        }
    }

    /// The fixed descriptor set this command must carry.
    pub fn rights(&self) -> RightsKind {
        match self {
            Self::PrepareCapture { .. } => RightsKind::CaptureOutputs,
            Self::AcceptCapture { .. } => RightsKind::SealedMemory,
            _ => RightsKind::None,
        }
    }

    /// Capture stages that exist once per capture and therefore use the
    /// capture (operation) identity as their request identity.
    fn capture_stage(&self) -> bool {
        matches!(
            self,
            Self::PrepareCapture { .. }
                | Self::FlushCapture { .. }
                | Self::CaptureExecution { .. }
                | Self::CaptureMemory { .. }
                | Self::AcceptCapture { .. }
                | Self::Pause {
                    purpose: PausePurpose::Capture,
                    ..
                }
        )
    }
}

/// The fixed, typed descriptor set of one command; never a generic list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightsKind {
    None,
    /// execution, devices, ram, layout, pin: five descriptors in this order.
    CaptureOutputs,
    /// ram, layout: two read-only descriptors in this order.
    SealedMemory,
}

impl RightsKind {
    pub fn count(self) -> usize {
        match self {
            Self::None => 0,
            Self::CaptureOutputs => 5,
            Self::SealedMemory => 2,
        }
    }
}

/// Owned descriptors transferred with one rights-bearing command. Callers pass
/// duplicates and keep their own copies until the command's terminal report.
#[derive(Debug)]
pub enum LifecycleRights {
    None,
    CaptureOutputs(CaptureOutputFiles),
    SealedMemory(SealedMemoryFiles),
}

#[derive(Debug)]
pub struct CaptureOutputFiles {
    pub execution: std::fs::File,
    pub devices: std::fs::File,
    pub ram: std::fs::File,
    pub layout: std::fs::File,
    /// Capture-lifetime storage lease (the run's launch lease duplicate).
    pub pin: std::fs::File,
}

#[derive(Debug)]
pub struct SealedMemoryFiles {
    pub ram: std::fs::File,
    pub layout: std::fs::File,
}

impl LifecycleRights {
    pub fn kind(&self) -> RightsKind {
        match self {
            Self::None => RightsKind::None,
            Self::CaptureOutputs(_) => RightsKind::CaptureOutputs,
            Self::SealedMemory(_) => RightsKind::SealedMemory,
        }
    }

    /// Kind and actual descriptor identities must equal the command's
    /// declarations. Checked before any frame; no effect on refusal.
    pub fn check(&self, command: &LifecycleCommand) -> Result<(), LifecycleRejection> {
        let mismatch = || {
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::CaptureRights,
            ))
        };
        if self.kind() != command.rights() {
            return mismatch();
        }
        let same = |file: &std::fs::File, expected: OutputIdentity| {
            OutputIdentity::of(file).is_ok_and(|actual| actual == expected)
        };
        let matches = match (self, command) {
            (Self::None, _) => true,
            (Self::CaptureOutputs(files), LifecycleCommand::PrepareCapture { preparation, .. }) => {
                let outputs = &preparation.outputs;
                same(&files.execution, outputs.execution)
                    && same(&files.devices, outputs.devices)
                    && same(&files.ram, outputs.ram)
                    && same(&files.layout, outputs.layout)
                    && same(&files.pin, preparation.pin)
            }
            (Self::SealedMemory(files), LifecycleCommand::AcceptCapture { ram, layout, .. }) => {
                same(&files.ram, *ram) && same(&files.layout, *layout)
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            mismatch()
        }
    }

    /// Descriptors in their fixed wire order.
    pub(crate) fn into_descriptors(self) -> Vec<std::os::fd::OwnedFd> {
        match self {
            Self::None => Vec::new(),
            Self::CaptureOutputs(files) => vec![
                files.execution.into(),
                files.devices.into(),
                files.ram.into(),
                files.layout.into(),
                files.pin.into(),
            ],
            Self::SealedMemory(files) => vec![files.ram.into(), files.layout.into()],
        }
    }

    /// Rebuild the typed set from received descriptors in wire order.
    pub(crate) fn from_descriptors(
        kind: RightsKind,
        descriptors: Vec<std::os::fd::OwnedFd>,
    ) -> Option<Self> {
        if descriptors.len() != kind.count() {
            return None;
        }
        let mut files = descriptors.into_iter().map(std::fs::File::from);
        let mut next = || files.next();
        Some(match kind {
            RightsKind::None => Self::None,
            RightsKind::CaptureOutputs => Self::CaptureOutputs(CaptureOutputFiles {
                execution: next()?,
                devices: next()?,
                ram: next()?,
                layout: next()?,
                pin: next()?,
            }),
            RightsKind::SealedMemory => Self::SealedMemory(SealedMemoryFiles {
                ram: next()?,
                layout: next()?,
            }),
        })
    }
}

/// Device and inode of one opened file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputIdentity {
    pub device: u64,
    pub inode: u64,
}

impl OutputIdentity {
    pub fn of(file: &impl std::os::fd::AsFd) -> std::io::Result<Self> {
        let stat = nix::sys::stat::fstat(file.as_fd())?;
        Ok(Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureOutputIdentities {
    pub execution: OutputIdentity,
    pub devices: OutputIdentity,
    pub ram: OutputIdentity,
    pub layout: OutputIdentity,
}

impl CaptureOutputIdentities {
    pub fn roles(&self) -> [(OutputRole, OutputIdentity); 4] {
        [
            (OutputRole::Execution, self.execution),
            (OutputRole::Devices, self.devices),
            (OutputRole::Ram, self.ram),
            (OutputRole::Layout, self.layout),
        ]
    }
}

/// The complete immutable worker-side capture plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePreparation {
    pub outputs: CaptureOutputIdentities,
    /// Identity of the capture-lifetime storage lease descriptor.
    pub pin: OutputIdentity,
    pub pause: CapturePauseSource,
    pub resume_policy: CaptureResumePolicy,
    pub binding: CaptureDigests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapturePauseSource {
    /// The capture establishes its own native Capture-owned pause.
    Acquire,
    /// Bind the exact current published User pause without changing it.
    Borrow {
        operation: Uuid,
        generation: NativePauseGeneration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureResumePolicy {
    ResumeIfAcquired,
    Preserve,
}

/// Trusted monitor digests bound into the native StateBinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDigests {
    pub silo_producer: Digest32,
    pub profile: Digest32,
    pub topology: Digest32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureContinuation {
    /// ClockOnly resume of the exact capture-owned pause.
    Resume,
    /// Transfer the capture-owned pause to User ownership (borrowed: unchanged).
    Preserve,
}

/// 32 raw bytes; 64 lowercase hexadecimal characters on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
}

impl std::fmt::Display for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Digest32 {
    type Err = &'static str;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err("digest must be 64 hexadecimal characters");
        }
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("digest must be lowercase hexadecimal"),
        };
        let mut digest = [0; 32];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            digest[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(digest))
    }
}

impl Serialize for Digest32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum PausePurpose {
    /// First pause of a public operation: `request_id == operation`.
    Initial,
    /// Lost-thaw recovery inside the Resume request that released `consumed`.
    Recovery { consumed: NativePauseGeneration },
    /// Native Capture-owned pause of a prepared Acquire capture:
    /// `request_id == operation == capture`.
    Capture,
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
    PrepareCapture,
    FlushCapture,
    CaptureExecution,
    CaptureMemory,
    AcceptCapture,
    AbandonCapture,
    ContinueCapture,
    ReleaseCapture,
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
    /// Capture facts; present only for `GetCapture`.
    pub capture: Option<CaptureObservation>,
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
    /// Read-only attachment of a block provider, joined from the launch.
    pub block_read_only: Option<bool>,
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
    Paused {
        pause: NativePause,
    },
    /// No token. Native control distinguishes failed Pausing from Running.
    PauseFailed {
        failure: NativeFailure,
    },
    /// Cancellation was admitted first; no token was published.
    PauseWithdrawn,
    /// Released and the exact ClockOnly request was acknowledged in time.
    Resumed {
        clock: ClockOnlyReceipt,
    },
    /// `pause_retained`: native is still Paused with the same generation.
    ResumeFailed {
        stage: ResumeStage,
        failure: NativeFailure,
        pause_retained: bool,
    },
    /// Native is back to Running.
    CancelSettled {
        settlement: CancelSettlement,
    },
    CancelFailed {
        stage: CancelStage,
        failure: NativeFailure,
    },
    /// The five descriptors are validated and retained by the worker.
    CapturePrepared {
        outputs: CaptureOutputIdentities,
        pin: OutputIdentity,
    },
    /// Exact-token native flush; the attachments the native owner flushed.
    CaptureFlushed {
        pause: NativePause,
        attachments: Vec<FlushedAttachment>,
    },
    /// Both execution writers are closed by native before this report.
    ExecutionCaptured {
        /// Boxed: keeps every retained command state small.
        binding: Box<CaptureStateBinding>,
        execution: OutputReceipt,
        devices: OutputReceipt,
    },
    /// Full RAM candidate; native closed both writers when `writers_closed`.
    MemoryCaptured {
        binding: Box<CaptureStateBinding>,
        ram: OutputReceipt,
        layout: OutputReceipt,
        memory_generation: u64,
        writers_closed: bool,
    },
    CaptureAccepted {
        memory_generation: u64,
    },
    /// Native candidate resolved and every output owner closed.
    CaptureAbandoned,
    /// Current pause authority of the capture operation, owner User.
    CapturePreserved {
        pause: NativePause,
    },
    CaptureReleased {
        baseline_retained: bool,
    },
    CaptureFailed {
        stage: CaptureStage,
        failure: NativeFailure,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStage {
    Flush,
    Execution,
    Memory,
    Accept,
    Abandon,
    Preserve,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlushedAttachment {
    pub configured_id: String,
    pub address: u64,
    pub irq: u32,
}

/// One native-written output as native observed it after closing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputReceipt {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
}

impl OutputReceipt {
    pub fn identity(&self) -> OutputIdentity {
        OutputIdentity {
            device: self.device,
            inode: self.inode,
        }
    }
}

/// The exact native StateBinding of one capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureStateBinding {
    pub native_producer: String,
    pub silo_producer: Digest32,
    pub profile: Digest32,
    pub topology: Digest32,
    /// SHA-256 of the native canonical RAM layout bytes.
    pub ram_layout: Digest32,
    pub source_run: Uuid,
    pub capture: Uuid,
    pub pause_generation: NativePauseGeneration,
}

/// Worker-retained capture facts, derived from retained native authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureObservation {
    pub operation: Uuid,
    pub progress: CaptureProgress,
    pub pause: CapturePauseObservation,
    pub outputs: CaptureOutputHolders,
    pub pin: PinHolder,
    pub evidence: CaptureNativeEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "progress", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureProgress {
    Prepared,
    Paused,
    Flushed,
    ExecutionPending,
    ExecutionCaptured,
    MemoryPending,
    CandidateComplete,
    Accepted,
    Abandoned,
    Failed {
        stage: CaptureStage,
        failure: NativeFailure,
    },
    Released,
}

impl CaptureProgress {
    /// No native candidate remains to accept or abandon.
    pub fn resolved(&self) -> bool {
        matches!(self, Self::Accepted | Self::Abandoned | Self::Released)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePauseObservation {
    pub origin: CapturePauseOrigin,
    /// The pause the capture was cut under (historical once transferred).
    pub cut: Option<NativePause>,
    /// The capture operation's current native pause authority, if any.
    pub current: Option<NativePause>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapturePauseOrigin {
    Acquired,
    Borrowed { operation: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureOutputHolders {
    pub execution: OutputHolder,
    pub devices: OutputHolder,
    pub ram: OutputHolder,
    pub layout: OutputHolder,
}

impl CaptureOutputHolders {
    pub fn all_closed(&self) -> bool {
        [self.execution, self.devices, self.ram, self.layout]
            .iter()
            .all(|holder| *holder == OutputHolder::Closed)
    }
}

/// Who holds a writable output descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputHolder {
    /// Validated and retained by the worker, unused.
    Prepared,
    /// Moved into native capture (pending work or a retained native failure).
    Native,
    /// No writer remains in the worker or native.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinHolder {
    /// Retained for the capture's lifetime.
    Capture,
    /// Retained as the source-baseline pin after release of an accepted capture.
    Baseline,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureNativeEvidence {
    /// The exact cut token completed the native whole-machine barrier: every
    /// vCPU parked, devices quiesced, host memory writers drained.
    pub pause_completed: bool,
    /// The exact-token flush receipt is retained.
    pub flush_completed: bool,
    /// Execution and device receipts retained; native closed both writers.
    pub execution_sealed: bool,
    /// RAM receipt reports closed writers and no worker writer remains.
    pub memory_sealed: bool,
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
    /// A capture pause completed first under `preserve`: retained, not resumed.
    RetainedCompletedPause {
        pause: NativePause,
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
    #[error("another capture is unresolved in this run")]
    CaptureActive,
    #[error("unknown capture")]
    UnknownCapture,
    #[error("command is not legal at the capture's current stage")]
    CaptureStage,
    #[error("native capture work is still pending")]
    CapturePending,
    #[error("capture is not resolved")]
    CaptureUnresolved,
    #[error("the pause is owned by an unresolved capture")]
    CaptureOwned,
    #[error("a borrowed user pause is never resumed by its capture")]
    BorrowedPause,
    #[error("capture descriptor refused: {0}")]
    CaptureOutputs(OutputProblem),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("{role:?} {problem:?}")]
pub struct OutputProblem {
    pub role: OutputRole,
    pub problem: OutputDefect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRole {
    Execution,
    Devices,
    Ram,
    Layout,
    Pin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDefect {
    NotRegular,
    Owner,
    Mode,
    Links,
    Access,
    Append,
    DirectIo,
    PathOnly,
    CloseOnExec,
    NotEmpty,
    Identity,
    Alias,
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
    #[error("a capture stage must use its capture as request identity")]
    CaptureRequestIdentity,
    #[error("descriptor set does not match the command")]
    CaptureRights,
    #[error("a borrowed user pause requires the preserve resume policy")]
    CapturePolicy,
    #[error("capture binding digests must be nonzero")]
    CaptureBinding,
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
        if self.command.capture_stage() && self.command.operation() != Some(self.request_id) {
            return invalid(InvalidRequest::CaptureRequestIdentity);
        }
        if let LifecycleCommand::PrepareCapture { preparation, .. } = &self.command {
            if let CapturePauseSource::Borrow { operation, .. } = preparation.pause {
                if operation.is_nil() {
                    return invalid(InvalidRequest::NilIdentity);
                }
                if preparation.resume_policy != CaptureResumePolicy::Preserve {
                    return invalid(InvalidRequest::CapturePolicy);
                }
            }
            let digests = preparation.binding;
            if digests.silo_producer.is_zero()
                || digests.profile.is_zero()
                || digests.topology.is_zero()
            {
                return invalid(InvalidRequest::CaptureBinding);
            }
        }
        if let LifecycleCommand::AcceptCapture { stream, .. } = &self.command {
            if stream.is_zero() {
                return invalid(InvalidRequest::CaptureBinding);
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

    fn preparation(
        pause: CapturePauseSource,
        resume_policy: CaptureResumePolicy,
    ) -> CapturePreparation {
        let identity = |inode| OutputIdentity { device: 7, inode };
        CapturePreparation {
            outputs: CaptureOutputIdentities {
                execution: identity(1),
                devices: identity(2),
                ram: identity(3),
                layout: identity(4),
            },
            pin: identity(5),
            pause,
            resume_policy,
            binding: CaptureDigests {
                silo_producer: Digest32([1; 32]),
                profile: Digest32([2; 32]),
                topology: Digest32([3; 32]),
            },
        }
    }

    #[test]
    fn digests_travel_as_exact_lowercase_hex() {
        let digest = Digest32([0xab; 32]);
        let encoded = serde_json::to_string(&digest).expect("encode");
        assert_eq!(encoded, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(
            serde_json::from_str::<Digest32>(&encoded).expect("decode"),
            digest
        );
        for invalid in [
            format!("\"{}\"", "AB".repeat(32)),
            format!("\"{}\"", "ab".repeat(31)),
            format!("\"{}0\"", "ab".repeat(32)),
            format!("\"{}zz\"", "ab".repeat(31)),
            "[1,2,3]".to_string(),
        ] {
            assert!(
                serde_json::from_str::<Digest32>(&invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn capture_stages_bind_their_capture_identity_and_policy() {
        let operation = Uuid::new_v4();
        let ok = Duration::from_secs(5);
        let prepare = |preparation| LifecycleCommand::PrepareCapture {
            operation,
            preparation,
            timeout: ok,
        };
        let acquire = preparation(
            CapturePauseSource::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        );
        let command = prepare(acquire.clone());
        let bytes = serde_json::to_vec(&command).expect("encode");
        assert_eq!(
            serde_json::from_slice::<LifecycleCommand>(&bytes).expect("decode"),
            command
        );
        assert_eq!(request(command.clone(), operation).validate(), Ok(()));
        assert_eq!(command.rights(), RightsKind::CaptureOutputs);
        assert_eq!(RightsKind::CaptureOutputs.count(), 5);
        for stage in [
            command,
            LifecycleCommand::Pause {
                operation,
                purpose: PausePurpose::Capture,
                timeout: ok,
                clock_profile: None,
            },
            LifecycleCommand::FlushCapture {
                operation,
                timeout: ok,
            },
            LifecycleCommand::CaptureExecution {
                operation,
                timeout: ok,
            },
            LifecycleCommand::CaptureMemory {
                operation,
                timeout: ok,
            },
        ] {
            assert_eq!(
                request(stage, Uuid::new_v4()).validate(),
                Err(LifecycleRejection::InvalidRequest(
                    InvalidRequest::CaptureRequestIdentity
                ))
            );
        }
        // Cancellation and release requests carry their own identities.
        for command in [
            LifecycleCommand::AbandonCapture {
                operation,
                timeout: ok,
            },
            LifecycleCommand::ReleaseCapture {
                operation,
                timeout: ok,
            },
            LifecycleCommand::ContinueCapture {
                operation,
                continuation: CaptureContinuation::Resume,
                timeout: ok,
            },
        ] {
            assert_eq!(command.rights(), RightsKind::None);
            assert_eq!(request(command, Uuid::new_v4()).validate(), Ok(()));
        }
        let borrow = CapturePauseSource::Borrow {
            operation: Uuid::new_v4(),
            generation: NativePauseGeneration::new(2).expect("nonzero"),
        };
        assert_eq!(
            request(
                prepare(preparation(borrow, CaptureResumePolicy::ResumeIfAcquired)),
                operation
            )
            .validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::CapturePolicy
            ))
        );
        assert_eq!(
            request(
                prepare(preparation(borrow, CaptureResumePolicy::Preserve)),
                operation
            )
            .validate(),
            Ok(())
        );
        let mut zero = acquire;
        zero.binding.topology = Digest32([0; 32]);
        assert_eq!(
            request(prepare(zero), operation).validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::CaptureBinding
            ))
        );
        let accept = LifecycleCommand::AcceptCapture {
            operation,
            ram: OutputIdentity {
                device: 1,
                inode: 2,
            },
            layout: OutputIdentity {
                device: 1,
                inode: 3,
            },
            stream: Digest32([0; 32]),
            timeout: ok,
        };
        assert_eq!(accept.rights(), RightsKind::SealedMemory);
        assert_eq!(
            request(accept, operation).validate(),
            Err(LifecycleRejection::InvalidRequest(
                InvalidRequest::CaptureBinding
            ))
        );
        let get = LifecycleCommand::GetCapture { operation };
        assert_eq!((get.kind(), get.timeout()), (None, None));
    }

    #[test]
    fn rights_must_match_the_command_kind_and_declared_identities() {
        let directory = std::env::temp_dir().join(format!("rights-{:x}", rand::random::<u64>()));
        std::fs::create_dir(&directory).expect("dir");
        let file = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .expect("file")
        };
        let files = ["execution", "devices", "ram", "layout", "pin"].map(file);
        let id = |index: usize| OutputIdentity::of(&files[index]).expect("identity");
        let operation = Uuid::new_v4();
        let mut preparation =
            preparation(CapturePauseSource::Acquire, CaptureResumePolicy::Preserve);
        preparation.outputs = CaptureOutputIdentities {
            execution: id(0),
            devices: id(1),
            ram: id(2),
            layout: id(3),
        };
        preparation.pin = id(4);
        let command = LifecycleCommand::PrepareCapture {
            operation,
            preparation,
            timeout: Duration::from_secs(1),
        };
        let rights = |order: [usize; 5]| {
            let dup = |index: usize| files[index].try_clone().expect("dup");
            LifecycleRights::CaptureOutputs(CaptureOutputFiles {
                execution: dup(order[0]),
                devices: dup(order[1]),
                ram: dup(order[2]),
                layout: dup(order[3]),
                pin: dup(order[4]),
            })
        };
        assert_eq!(rights([0, 1, 2, 3, 4]).check(&command), Ok(()));
        let mismatch = Err(LifecycleRejection::InvalidRequest(
            InvalidRequest::CaptureRights,
        ));
        assert_eq!(rights([1, 0, 2, 3, 4]).check(&command), mismatch);
        assert_eq!(LifecycleRights::None.check(&command), mismatch);
        assert_eq!(
            rights([0, 1, 2, 3, 4]).check(&LifecycleCommand::GetControl { target: None }),
            mismatch
        );
        let descriptors = rights([0, 1, 2, 3, 4]).into_descriptors();
        assert_eq!(descriptors.len(), 5);
        let rebuilt = LifecycleRights::from_descriptors(RightsKind::CaptureOutputs, descriptors)
            .expect("five descriptors");
        assert_eq!(rebuilt.check(&command), Ok(()), "wire order is fixed");
        assert!(LifecycleRights::from_descriptors(RightsKind::SealedMemory, Vec::new()).is_none());
        std::fs::remove_dir_all(&directory).expect("cleanup");
    }
}

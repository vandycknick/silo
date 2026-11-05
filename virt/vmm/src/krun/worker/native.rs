//! The libkrun native lifecycle authority behind the worker lifecycle socket.

use std::collections::HashMap;
use std::time::Instant;

use libkrun::control::{ControlFailure, ControlState, OperationId, PauseOwner, PauseToken};
use libkrun::live::{
    GenerationKind, GenerationObservation, GenerationTicket, LiveError, StoppedOwner, TrackingMode,
};

use crate::krun::engine::Control;
use crate::krun::worker::lifecycle::{GenerationPoll, NativeLifecycle, NativeState};
use crate::virt::lifecycle::{
    BlockBacking, GenerationFailureKind, InventoryObservation, MemoryTracking, NativeFailure,
    NativeFailureKind, NativeOperation, NativePauseOwner, NativeProvider, ObservedClockProfile,
    ProviderDevice, VirtioKind,
};

pub(crate) struct KrunNative {
    control: Control,
    /// Backing format of every block attachment the worker built, by block ID.
    block_backings: HashMap<String, BlockBacking>,
}

impl KrunNative {
    pub(crate) fn new(control: Control, config: &crate::krun::KrunConfig) -> Self {
        let block_backings = config
            .disks
            .iter()
            .map(|disk| {
                (
                    disk.block_id.as_str().to_string(),
                    match disk.format {
                        vm_spec::DiskFormat::Raw => BlockBacking::Raw,
                        vm_spec::DiskFormat::Vmdk => BlockBacking::Vmdk,
                    },
                )
            })
            .collect();
        Self {
            control,
            block_backings,
        }
    }
}

impl NativeLifecycle for KrunNative {
    type Token = PauseToken;
    type Ticket = GenerationTicket;

    fn pause(
        &self,
        operation: NativeOperation,
        profile_operation: NativeOperation,
        clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    ) -> Result<PauseToken, NativeFailure> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.control
                .set_capture_profile(
                    capture_profile(clock_profile)?,
                    OperationId(profile_operation.get()),
                    deadline,
                )
                .map_err(live_failure)?;
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let _ = (profile_operation, clock_profile);
        self.control
            .pause(PauseOwner::User, OperationId(operation.get()), deadline)
            .map_err(control_failure)
    }

    fn cancel_pause(
        &self,
        pausing: NativeOperation,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .cancel_pause(
                OperationId(pausing.get()),
                OperationId(operation.get()),
                deadline,
            )
            .map_err(control_failure)
    }

    fn prepare_clock_only(
        &self,
        token: &PauseToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<GenerationTicket, NativeFailure> {
        self.control
            .prepare_generation(
                StoppedOwner::Paused(token),
                GenerationKind::ClockOnly,
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)
    }

    fn resume_generation(
        &self,
        token: PauseToken,
        ticket: &GenerationTicket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .resume_generation(token, ticket, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }

    fn poll_generation(
        &self,
        ticket: &GenerationTicket,
        deadline: Instant,
    ) -> Result<GenerationPoll, NativeFailure> {
        Ok(
            match self
                .control
                .poll_generation(ticket, deadline)
                .map_err(live_failure)?
            {
                GenerationObservation::Pending => GenerationPoll::Pending,
                GenerationObservation::Acknowledged(receipt) => GenerationPoll::Acknowledged {
                    completed_at: receipt.completed_at,
                },
                GenerationObservation::Failed(failure) => {
                    GenerationPoll::Failed(generation_failure(&format!("{failure:?}")))
                }
            },
        )
    }

    fn ticket_request(&self, ticket: &GenerationTicket) -> (u64, u32) {
        let request = ticket.request();
        (request.sequence, request.flags)
    }

    fn control_state(&self, deadline: Instant) -> Result<NativeState<PauseToken>, NativeFailure> {
        Ok(
            match self
                .control
                .control_state(deadline)
                .map_err(control_failure)?
            {
                ControlState::Running => NativeState::Running,
                ControlState::Pausing { key, failed } => NativeState::Pausing {
                    operation: key.operation.0,
                    failed,
                },
                ControlState::Paused(token) => NativeState::Paused(token),
                ControlState::RestorePrepared { .. } => NativeState::RestorePrepared,
                ControlState::Resuming { key } => NativeState::Resuming {
                    operation: key.operation.0,
                },
                ControlState::RollingBack { key } => NativeState::RollingBack {
                    operation: key.operation.0,
                },
                ControlState::FailedFenced => NativeState::FailedFenced,
                ControlState::Stopping => NativeState::Stopping,
                ControlState::Stopped => NativeState::Stopped,
            },
        )
    }

    fn inventory(&self, deadline: Instant) -> InventoryObservation {
        let snapshot = match self.control.live_snapshot(deadline) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return InventoryObservation::Unavailable {
                    failure: live_failure(error),
                }
            }
        };
        let providers = snapshot
            .providers
            .iter()
            .map(|provider| {
                let device = provider_device(&provider.attachment.device_type.to_string());
                let block_backing = match device {
                    ProviderDevice::Virtio {
                        kind: VirtioKind::Block,
                        ..
                    } => self
                        .block_backings
                        .get(&provider.attachment.configured_id)
                        .copied(),
                    _ => None,
                };
                NativeProvider {
                    device,
                    configured_id: provider.attachment.configured_id.clone(),
                    address: provider.attachment.address,
                    irq: provider.attachment.irq,
                    activation_fenced: provider.activation_fenced,
                    block_backing,
                }
            })
            .collect();
        InventoryObservation::Observed {
            providers,
            memory_tracking: snapshot.tracking.map(|tracking| match tracking {
                TrackingMode::Disabled => MemoryTracking::Disabled,
                TrackingMode::Capture => MemoryTracking::Capture,
            }),
        }
    }

    fn token_generation(&self, token: &PauseToken) -> u64 {
        token.generation().0
    }

    fn token_owner(&self, token: &PauseToken) -> NativePauseOwner {
        match token.owner() {
            PauseOwner::User => NativePauseOwner::User,
            PauseOwner::Capture => NativePauseOwner::Capture,
        }
    }
}

/// libkrun exposes the device type only through its display form
/// (`Virtio(<id>)`); anything else is unrecognized and never admissible.
fn provider_device(description: &str) -> ProviderDevice {
    match description
        .strip_prefix("Virtio(")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|id| id.parse::<u32>().ok())
    {
        Some(device_id) => ProviderDevice::Virtio {
            device_id,
            kind: VirtioKind::from_device_id(device_id),
        },
        None => ProviderDevice::Unrecognized {
            description: description.chars().take(64).collect(),
        },
    }
}

/// The native generation failure type is not re-exported; its debug form is
/// its closed variant name.
fn generation_failure(name: &str) -> GenerationFailureKind {
    match name {
        "Deadline" => GenerationFailureKind::Deadline,
        "DriverError" => GenerationFailureKind::DriverError,
        "InvalidStatus" => GenerationFailureKind::InvalidStatus,
        "Notification" => GenerationFailureKind::Notification,
        "Reset" => GenerationFailureKind::Reset,
        "Stopped" => GenerationFailureKind::Stopped,
        "Release" => GenerationFailureKind::Release,
        "Poisoned" => GenerationFailureKind::Poisoned,
        _ => GenerationFailureKind::Unrecognized,
    }
}

pub(crate) fn control_failure(failure: ControlFailure) -> NativeFailure {
    use NativeFailureKind as K;
    match failure {
        ControlFailure::Deadline => NativeFailure::new(K::Deadline),
        ControlFailure::CallerTimeout => NativeFailure::new(K::CallerTimeout),
        ControlFailure::OwnerUnavailable => NativeFailure::new(K::OwnerUnavailable),
        ControlFailure::WakeUnknown(detail) => NativeFailure::with_detail(K::WakeUnknown, detail),
        ControlFailure::Busy => NativeFailure::new(K::Busy),
        ControlFailure::InvalidToken => NativeFailure::new(K::InvalidToken),
        ControlFailure::InvalidOperation => NativeFailure::new(K::InvalidOperation),
        ControlFailure::Exhausted => NativeFailure::new(K::Exhausted),
        ControlFailure::Unsupported(detail) => NativeFailure::with_detail(K::Unsupported, detail),
        ControlFailure::Participant(detail) => NativeFailure::with_detail(K::Participant, detail),
        ControlFailure::Memory(error) => {
            NativeFailure::with_detail(K::Memory, format!("{error:?}"))
        }
        ControlFailure::DirtyMemory(error) => {
            NativeFailure::with_detail(K::DirtyMemory, format!("{error:?}"))
        }
        ControlFailure::FailedFenced => NativeFailure::new(K::FailedFenced),
    }
}

fn live_failure(error: LiveError) -> NativeFailure {
    match error {
        LiveError::Control(failure) => control_failure(failure),
        LiveError::Operation { cause, .. } => live_failure(cause.as_ref().clone()),
        other => NativeFailure::with_detail(NativeFailureKind::Participant, other),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn capture_profile(
    observed: Option<ObservedClockProfile>,
) -> Result<libkrun::live::KvmCaptureProfile, NativeFailure> {
    let profile = observed.ok_or_else(|| {
        NativeFailure::with_detail(
            NativeFailureKind::Unsupported,
            "same-boot guest clock profile is required",
        )
    })?;
    profile.validate().map_err(|error| {
        NativeFailure::with_detail(NativeFailureKind::Unsupported, error.to_string())
    })?;
    Ok(libkrun::live::KvmCaptureProfile::RetiredLinuxPit {
        kernel_identity: profile.kernel_identity,
        clocksource_tsc: true,
        all_online_clockevents_deadline: true,
        broadcast_uses_pit: false,
        speaker_or_counter_consumer: false,
    })
}

#[cfg(test)]
mod tests {
    use crate::krun::worker::native::{generation_failure, provider_device};
    use crate::virt::lifecycle::{GenerationFailureKind, ProviderDevice, VirtioKind};

    #[test]
    fn native_device_descriptions_classify_or_fail_closed() {
        assert_eq!(
            provider_device("Virtio(2)"),
            ProviderDevice::Virtio {
                device_id: 2,
                kind: VirtioKind::Block
            }
        );
        assert_eq!(
            provider_device("Virtio(21319)"),
            ProviderDevice::Virtio {
                device_id: 0x5347,
                kind: VirtioKind::Generation
            }
        );
        assert_eq!(
            provider_device("Virtio(99)"),
            ProviderDevice::Virtio {
                device_id: 99,
                kind: VirtioKind::Other
            }
        );
        for description in ["Gpio", "Virtio(-1)", "Virtio(2", "virtio(2)"] {
            assert!(matches!(
                provider_device(description),
                ProviderDevice::Unrecognized { .. }
            ));
        }
        assert_eq!(
            generation_failure("Release"),
            GenerationFailureKind::Release
        );
        assert_eq!(
            generation_failure("SomethingNew"),
            GenerationFailureKind::Unrecognized
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn native_profile_requires_positive_observations_without_diagnostic_defaults() {
        use crate::krun::worker::native::capture_profile;
        use crate::virt::lifecycle::{
            NativeFailureKind, ObservedBroadcastClockevent, ObservedClockProfile,
            ObservedClockevent, ObservedClockeventDevice, ObservedClocksource, ObservedModules,
        };
        assert_eq!(
            capture_profile(None).expect_err("missing evidence").kind,
            NativeFailureKind::Unsupported
        );
        let profile = ObservedClockProfile {
            boot_id: uuid::Uuid::new_v4(),
            kernel_identity: "Linux version observed-unit-kernel\n".into(),
            clocksource: ObservedClocksource::Tsc,
            online_clockevents: vec![ObservedClockevent {
                cpu: 0,
                device: ObservedClockeventDevice::LapicDeadline,
            }],
            broadcast: ObservedBroadcastClockevent::NoDevice,
            modules: ObservedModules::BuiltInDisabled,
            no_speaker_consumers: true,
        };
        let native = capture_profile(Some(profile.clone())).expect("observed");
        assert!(
            matches!(native, libkrun::live::KvmCaptureProfile::RetiredLinuxPit {
            kernel_identity, clocksource_tsc: true, all_online_clockevents_deadline: true,
            broadcast_uses_pit: false, speaker_or_counter_consumer: false,
        } if kernel_identity == profile.kernel_identity)
        );
        let invalid = ObservedClockProfile {
            no_speaker_consumers: false,
            ..profile
        };
        assert_eq!(
            capture_profile(Some(invalid)).expect_err("consumer").kind,
            NativeFailureKind::Unsupported
        );
    }
}

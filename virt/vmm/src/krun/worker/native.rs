//! The libkrun native lifecycle authority behind the worker lifecycle socket.

use std::collections::HashMap;
use std::fs::File;
use std::time::Instant;

use libkrun::control::{ControlFailure, ControlState, OperationId, PauseOwner, PauseToken};
use libkrun::live::{
    BaselineImage, CaptureId, CaptureStatus, CaptureTicket, CompletedCapture,
    ExecutionCaptureReceipt, ExecutionOutputs, GenerationKind, GenerationObservation,
    GenerationTicket, LiveError, MemoryCaptureRequest, MemoryOutputs, RamImageAuthentication,
    StateBinding, StoppedOwner, TrackingMode,
};
use sha2::Digest;
use uuid::Uuid;

use crate::krun::engine::Control;
use crate::krun::worker::lifecycle::{
    ExecutionCapture, FreshRequest, GenerationPoll, MemoryCapture, NativeCaptureStatus,
    NativeExposure, NativeLifecycle, NativeState,
};
use crate::virt::lifecycle::{
    BlockBacking, CaptureStage, CaptureStateBinding, Digest32, FlushedAttachment,
    GenerationFailureKind, InventoryObservation, MemoryTracking, NativeFailure, NativeFailureKind,
    NativeOperation, NativePauseGeneration, NativePauseOwner, NativeProvider, ObservedClockProfile,
    OutputIdentity, OutputReceipt, ProviderDevice, VirtioKind,
};

pub(crate) struct KrunNative {
    control: Control,
    /// Backing format and read-only attachment of every block the worker
    /// built, by block ID.
    blocks: HashMap<String, (BlockBacking, bool)>,
    /// Launch raw disk handles and the launch storage lease.
    protected: Vec<OutputIdentity>,
}

impl KrunNative {
    pub(crate) fn new(control: Control, config: &crate::krun::KrunConfig) -> Self {
        let blocks = config
            .disks
            .iter()
            .map(|disk| {
                (
                    disk.block_id.as_str().to_string(),
                    (
                        match disk.format {
                            vm_spec::DiskFormat::Raw => BlockBacking::Raw,
                            vm_spec::DiskFormat::Vmdk => BlockBacking::Vmdk,
                        },
                        disk.read_only,
                    ),
                )
            })
            .collect();
        let context = &config.storage_context;
        let protected = context
            .raw_handles
            .iter()
            .map(|handle| OutputIdentity {
                device: handle.device,
                inode: handle.inode,
            })
            .chain(std::iter::once(OutputIdentity {
                device: context.storage_lease.file_device,
                inode: context.storage_lease.file_inode,
            }))
            .collect();
        Self {
            control,
            blocks,
            protected,
        }
    }
}

#[cfg(all(
    feature = "restore-irq-probe",
    target_os = "linux",
    target_arch = "x86_64"
))]
impl KrunNative {
    /// Candidate-only native IRQ witness call under a worker-allocated
    /// native operation; admission belongs to the lifecycle journal.
    pub(crate) fn irq_probe(
        &self,
        request: libkrun::live::irq_probe::ProbeRequest,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<libkrun::live::irq_probe::ProbeObservation, NativeFailure> {
        self.control
            .irq_probe(request, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }
}

impl NativeLifecycle for KrunNative {
    type Token = PauseToken;
    type Ticket = GenerationTicket;
    type Capture = CaptureTicket;
    type Restore = libkrun::live::restore::RestoreToken;

    fn pause(
        &self,
        owner: NativePauseOwner,
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
        let owner = match owner {
            NativePauseOwner::User => PauseOwner::User,
            NativePauseOwner::Capture => PauseOwner::Capture,
        };
        self.control
            .pause(owner, OperationId(operation.get()), deadline)
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
                let block = match device {
                    ProviderDevice::Virtio {
                        kind: VirtioKind::Block,
                        ..
                    } => self.blocks.get(&provider.attachment.configured_id).copied(),
                    _ => None,
                };
                NativeProvider {
                    device,
                    configured_id: provider.attachment.configured_id.clone(),
                    address: provider.attachment.address,
                    irq: provider.attachment.irq,
                    activation_fenced: provider.activation_fenced,
                    block_backing: block.map(|(backing, _)| backing),
                    block_read_only: block.map(|(_, read_only)| read_only),
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

    fn protected_identities(&self) -> Vec<OutputIdentity> {
        self.protected.clone()
    }

    /// A `restore-irq-probe` candidate binds captures to native's explicit
    /// diagnostic producer, the exact one its envelopes carry. It is never
    /// the ordinary producer, so no normal build restores or relabels it.
    fn native_producer(&self) -> Result<String, NativeFailure> {
        #[cfg(all(
            feature = "restore-irq-probe",
            target_os = "linux",
            target_arch = "x86_64"
        ))]
        {
            libkrun::capabilities::diagnostic_execution_producer()
                .map_err(|error| NativeFailure::with_detail(NativeFailureKind::Unsupported, error))
        }
        #[cfg(not(all(
            feature = "restore-irq-probe",
            target_os = "linux",
            target_arch = "x86_64"
        )))]
        {
            libkrun::capabilities::compiled_live_build()
                .execution_producer()
                .map_err(|error| NativeFailure::with_detail(NativeFailureKind::Unsupported, error))
        }
    }

    fn ram_layout_digest(&self, deadline: Instant) -> Result<Digest32, NativeFailure> {
        let layout = self.control.ram_layout(deadline).map_err(live_failure)?;
        Ok(Digest32(
            sha2::Sha256::digest(layout.canonical_bytes()).into(),
        ))
    }

    fn flush_capture(
        &self,
        token: &PauseToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<Vec<FlushedAttachment>, NativeFailure> {
        let receipt = self
            .control
            .flush_writable_disks(token, OperationId(operation.get()), deadline)
            .map_err(live_failure)?;
        if receipt.pause != *token {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::InvalidToken,
                "flush receipt names another pause",
            ));
        }
        Ok(receipt
            .attachments
            .into_iter()
            .map(|attachment| FlushedAttachment {
                configured_id: attachment.configured_id,
                address: attachment.address,
                irq: attachment.irq,
            })
            .collect())
    }

    fn capture_execution(
        &self,
        token: &PauseToken,
        binding: &CaptureStateBinding,
        execution: File,
        devices: File,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<ExecutionCapture<CaptureTicket>, NativeFailure> {
        let native = state_binding(binding);
        let receipt = self
            .control
            .capture_execution(
                token,
                native.clone(),
                ExecutionOutputs { execution, devices },
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)?;
        execution_capture(&receipt, &native)
    }

    fn capture_memory(
        &self,
        capture: &CaptureTicket,
        ram: File,
        layout: File,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<MemoryCapture, NativeFailure> {
        let completed = self
            .control
            .capture_memory(
                capture,
                MemoryCaptureRequest {
                    baseline: None,
                    full_at_dirty_percent: 0,
                },
                MemoryOutputs { ram, layout },
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)?;
        memory_capture(&completed)
    }

    fn capture_status(
        &self,
        capture: Uuid,
        deadline: Instant,
    ) -> Result<NativeCaptureStatus<CaptureTicket>, NativeFailure> {
        let status = self
            .control
            .capture_status(CaptureId::new(*capture.as_bytes()), deadline)
            .map_err(live_failure)?;
        // Every arm extracts resource-free facts; a failed status's error,
        // which can own RAM output files, is dropped right here.
        Ok(match status {
            CaptureStatus::ExecutionPending(ticket) => {
                NativeCaptureStatus::ExecutionPending(ticket)
            }
            CaptureStatus::ExecutionComplete(receipt) => {
                let native = receipt.execution.binding.clone();
                NativeCaptureStatus::ExecutionComplete(execution_capture(&receipt, &native)?)
            }
            CaptureStatus::MemoryPending(ticket) => NativeCaptureStatus::MemoryPending(ticket),
            CaptureStatus::CandidateComplete(completed) => NativeCaptureStatus::CandidateComplete {
                ticket: completed.ticket.clone(),
                memory: memory_capture(&completed)?,
            },
            CaptureStatus::Accepted { ticket, baseline } => NativeCaptureStatus::Accepted {
                ticket,
                memory_generation: baseline.memory_generation(),
            },
            CaptureStatus::Abandoned(ticket) => NativeCaptureStatus::Abandoned(ticket),
            CaptureStatus::Failed {
                ticket,
                stage,
                cause,
            } => NativeCaptureStatus::Failed {
                ticket,
                stage: match stage {
                    libkrun::live::CaptureStage::Execution => CaptureStage::Execution,
                    libkrun::live::CaptureStage::Memory => CaptureStage::Memory,
                    libkrun::live::CaptureStage::Accept => CaptureStage::Accept,
                },
                failure: live_failure(cause),
            },
            CaptureStatus::Released => NativeCaptureStatus::Released,
        })
    }

    fn accept_capture(
        &self,
        capture: &CaptureTicket,
        binding: &CaptureStateBinding,
        ram: File,
        layout: File,
        stream: Digest32,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<u64, NativeFailure> {
        let baseline = self
            .control
            .accept_baseline(
                capture,
                BaselineImage {
                    ram,
                    layout,
                    authentication: RamImageAuthentication {
                        state: state_binding(binding),
                        stream: stream.0,
                    },
                },
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)?;
        Ok(baseline.memory_generation())
    }

    fn abandon_capture(
        &self,
        capture: &CaptureTicket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .abandon_capture(capture, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }

    fn release_capture(
        &self,
        capture: Uuid,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .release_capture(
                CaptureId::new(*capture.as_bytes()),
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)
    }

    fn preserve_pause(
        &self,
        token: PauseToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<PauseToken, NativeFailure> {
        self.control
            .preserve_pause(token, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }

    fn prepare_fresh(
        &self,
        restore: &libkrun::live::restore::RestoreToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(GenerationTicket, FreshRequest), NativeFailure> {
        let ticket = self
            .control
            .prepare_generation(
                StoppedOwner::Restore(restore),
                GenerationKind::FreshIdentity,
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)?;
        let request = ticket.request();
        Ok((
            ticket,
            FreshRequest {
                sequence: request.sequence,
                identity: request.id,
                flags: request.flags,
            },
        ))
    }

    fn resume_restored(
        &self,
        restore: &libkrun::live::restore::RestoreToken,
        ticket: &GenerationTicket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .resume_restored(restore, ticket, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }

    fn release_activation(
        &self,
        restore: &libkrun::live::restore::RestoreToken,
        ticket: &GenerationTicket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        self.control
            .release_activation_fences(restore, ticket, OperationId(operation.get()), deadline)
            .map_err(live_failure)
    }

    fn activation_exposure(
        &self,
        _restore: &libkrun::live::restore::RestoreToken,
        deadline: Instant,
    ) -> Result<NativeExposure, NativeFailure> {
        let snapshot = self.control.live_snapshot(deadline).map_err(live_failure)?;
        Ok(native_exposure(&snapshot))
    }

    fn park_restored(
        &self,
        _restore: &libkrun::live::restore::RestoreToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<PauseToken, NativeFailure> {
        // A restored machine carries its restored execution profile, so the
        // park needs no fresh guest clock observation.
        self.control
            .pause(PauseOwner::User, OperationId(operation.get()), deadline)
            .map_err(control_failure)
    }
}

/// Network and vsock providers carry the activation fence; each must report
/// an effective fence. Other providers are not activation-fenced.
fn native_exposure(snapshot: &libkrun::live::LiveSnapshot) -> NativeExposure {
    let providers_fenced = snapshot.providers.iter().all(|provider| {
        match provider_device(&provider.attachment.device_type.to_string()) {
            ProviderDevice::Virtio {
                kind: VirtioKind::Net | VirtioKind::Vsock,
                ..
            } => provider.activation_fenced == Some(true),
            ProviderDevice::Virtio { .. } => true,
            ProviderDevice::Unrecognized { .. } => false,
        }
    });
    NativeExposure {
        released: snapshot.activation_released,
        failed: snapshot.activation_failed,
        providers_fenced,
    }
}

fn state_binding(binding: &CaptureStateBinding) -> StateBinding {
    StateBinding {
        native_producer: binding.native_producer.clone(),
        silo_producer: binding.silo_producer.0,
        profile: binding.profile.0,
        topology: binding.topology.0,
        ram_layout: binding.ram_layout.0,
        source_run: *binding.source_run.as_bytes(),
        pause_generation: binding.pause_generation.get(),
        capture: *binding.capture.as_bytes(),
    }
}

fn capture_binding(native: &StateBinding) -> Result<CaptureStateBinding, NativeFailure> {
    let pause_generation =
        NativePauseGeneration::new(native.pause_generation).ok_or_else(|| {
            NativeFailure::with_detail(NativeFailureKind::Unexpected, "binding generation zero")
        })?;
    Ok(CaptureStateBinding {
        native_producer: native.native_producer.clone(),
        silo_producer: Digest32(native.silo_producer),
        profile: Digest32(native.profile),
        topology: Digest32(native.topology),
        ram_layout: Digest32(native.ram_layout),
        source_run: Uuid::from_bytes(native.source_run),
        capture: Uuid::from_bytes(native.capture),
        pause_generation,
    })
}

/// Both receipts must carry the exact binding the capture was submitted with.
fn execution_capture(
    receipt: &ExecutionCaptureReceipt,
    binding: &StateBinding,
) -> Result<ExecutionCapture<CaptureTicket>, NativeFailure> {
    if receipt.execution.binding != *binding
        || receipt.devices.binding != *binding
        || receipt.execution.role != libkrun::live::OutputRole::Execution
        || receipt.devices.role != libkrun::live::OutputRole::Devices
    {
        return Err(NativeFailure::with_detail(
            NativeFailureKind::Unexpected,
            "native execution receipt differs from the submitted binding",
        ));
    }
    let output = |receipt: &libkrun::live::OutputReceipt| OutputReceipt {
        device: receipt.device,
        inode: receipt.inode,
        length: receipt.length,
    };
    Ok(ExecutionCapture {
        ticket: receipt.ticket.clone(),
        execution: output(&receipt.execution),
        devices: output(&receipt.devices),
    })
}

fn memory_capture(completed: &CompletedCapture) -> Result<MemoryCapture, NativeFailure> {
    if completed.ram.mode() != libkrun::live::RamCaptureMode::Full {
        return Err(NativeFailure::with_detail(
            NativeFailureKind::Unexpected,
            "native RAM candidate is not a full capture",
        ));
    }
    let [ram, layout] = completed
        .ram
        .output_identities()
        .map(|(device, inode, length)| OutputReceipt {
            device,
            inode,
            length,
        });
    Ok(MemoryCapture {
        binding: Box::new(capture_binding(completed.ram.binding())?),
        ram,
        layout,
        memory_generation: completed.memory_generation,
        writers_closed: completed.ram.writers_closed(),
    })
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

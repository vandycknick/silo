//! The libkrun native lifecycle authority behind the worker lifecycle socket.

use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;
use std::time::Instant;

use libkrun::control::{ControlFailure, ControlState, OperationId, PauseOwner, PauseToken};
use libkrun::live::{
    BaselineImage, CaptureId, CaptureStatus, CaptureTicket, CompletedCapture, DirtyEffect,
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
    baseline: Mutex<Option<NativeBaseline>>,
    accepting: Mutex<Option<(Uuid, Digest32, Digest32)>>,
}

struct NativeBaseline {
    token: Option<libkrun::live::BaselineToken>,
    stream: Digest32,
    layout: Digest32,
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
            baseline: Mutex::new(None),
            accepting: Mutex::new(None),
        }
    }

    /// Verified restore authority only; the native child token already predates
    /// state installation writes. Looking it up later never resets its union.
    pub(crate) fn inherit_baseline(mut self, stream: Digest32, layout: Digest32) -> Self {
        self.baseline = Mutex::new(Some(NativeBaseline {
            token: None,
            stream,
            layout,
        }));
        self
    }

    fn baseline_stream(&self) -> Option<vm_spec::capture::Sha256Digest> {
        self.baseline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(|baseline| vm_spec::capture::Sha256Digest::from_bytes(baseline.stream.0))
    }
}

fn memory_capture_request(
    policy: vm_spec::lifecycle::CapturePolicy,
    dirty_crossover_percent: u8,
    baseline: Option<libkrun::live::BaselineToken>,
) -> MemoryCaptureRequest {
    MemoryCaptureRequest {
        baseline,
        // A missing baseline is still an incremental request: libkrun reports
        // NoBaseline, not Requested, when it selects the initial full capture.
        full_at_dirty_percent: match policy {
            vm_spec::lifecycle::CapturePolicy::Full => 0,
            vm_spec::lifecycle::CapturePolicy::Incremental => dirty_crossover_percent,
        },
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
        recovery_operation: NativeOperation,
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
        match self
            .control
            .pause(owner, OperationId(operation.get()), deadline)
        {
            Ok(token) => Ok(token),
            Err(failure) if recoverable_memory_cut(&failure) => self
                .control
                .recover_memory_cut(
                    OperationId(operation.get()),
                    OperationId(recovery_operation.get()),
                    deadline,
                )
                .map_err(live_failure),
            Err(failure) => Err(control_failure(failure)),
        }
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

    fn live_state_schema(&self) -> Result<String, NativeFailure> {
        Ok(libkrun::capabilities::LIVE_STATE_SCHEMA.to_string())
    }

    fn architecture(&self) -> &'static str {
        std::env::consts::ARCH
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

    #[allow(clippy::too_many_arguments)]
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
        preparation: &crate::virt::lifecycle::CapturePreparation,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<MemoryCapture, NativeFailure> {
        let mut baseline = self
            .baseline
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(baseline) = baseline.as_mut() {
            if baseline.token.is_none() {
                baseline.token = self.control.baseline(deadline).map_err(live_failure)?;
            }
        }
        let layout_digest = self.ram_layout_digest(deadline)?;
        let token = baseline
            .as_ref()
            .filter(|baseline| {
                preparation.baseline == Some(baseline.stream) && baseline.layout == layout_digest
            })
            .and_then(|baseline| baseline.token.clone());
        let stream = baseline
            .as_ref()
            .map(|baseline| vm_spec::capture::Sha256Digest::from_bytes(baseline.stream.0));
        let completed = self
            .control
            .capture_memory(
                capture,
                memory_capture_request(
                    preparation.policy,
                    preparation.dirty_crossover_percent,
                    token,
                ),
                MemoryOutputs { ram, layout },
                OperationId(operation.get()),
                deadline,
            )
            .map_err(live_failure)?;
        memory_capture(&completed, stream)
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
                memory: memory_capture(&completed, self.baseline_stream())?,
            },
            CaptureStatus::Accepted { ticket, baseline } => {
                let mut accepting = self
                    .accepting
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if accepting
                    .as_ref()
                    .is_some_and(|(pending, _, _)| *pending == capture)
                {
                    if let Some((_, stream, layout)) = accepting.take() {
                        *self
                            .baseline
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = Some(NativeBaseline {
                            token: Some(baseline.clone()),
                            stream,
                            layout,
                        });
                    }
                }
                NativeCaptureStatus::Accepted {
                    ticket,
                    memory_generation: baseline.memory_generation(),
                }
            }
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
        *self
            .accepting
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some((binding.capture, stream, binding.ram_layout));
        let result = self.control.accept_baseline(
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
        );
        let baseline = match result {
            Ok(baseline) => baseline,
            Err(error) => match self
                .control
                .capture_status(CaptureId::new(*binding.capture.as_bytes()), deadline)
            {
                Ok(CaptureStatus::Accepted { baseline, .. }) => baseline,
                _ => return Err(live_failure(error)),
            },
        };
        *self
            .baseline
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(NativeBaseline {
            token: Some(baseline.clone()),
            stream,
            layout: binding.ram_layout,
        });
        self.accepting
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
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
        live_state_schema: binding.live_state_schema.clone(),
        architecture: binding.architecture.clone(),
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
        live_state_schema: native.live_state_schema.clone(),
        architecture: native.architecture.clone(),
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

fn memory_capture(
    completed: &CompletedCapture,
    baseline: Option<vm_spec::capture::Sha256Digest>,
) -> Result<MemoryCapture, NativeFailure> {
    use vm_spec::capture::{CaptureFullReason, CaptureMemoryStats, STREAM_CHUNK_BYTES};
    use vm_spec::lifecycle::CapturePolicy;
    let mode = match completed.ram.mode() {
        libkrun::live::RamCaptureMode::Full => CapturePolicy::Full,
        libkrun::live::RamCaptureMode::Incremental => CapturePolicy::Incremental,
    };
    let full_reason = completed.full_reason.map(|reason| match reason {
        libkrun::live::FullCaptureReason::Requested => CaptureFullReason::Requested,
        libkrun::live::FullCaptureReason::NoBaseline => CaptureFullReason::NoBaseline,
        libkrun::live::FullCaptureReason::BaselineToken => CaptureFullReason::BaselineToken,
        libkrun::live::FullCaptureReason::CoverageLost => CaptureFullReason::CoverageLost,
        libkrun::live::FullCaptureReason::DirtyCrossover => CaptureFullReason::DirtyCrossover,
    });
    let chunks = completed.ram.packed_len().div_ceil(STREAM_CHUNK_BYTES) as usize;
    if completed.ram.packed_len() == 0
        || completed.ram.packed_len() > vm_spec::capture::MAX_CAPTURE_RAM_BYTES
    {
        return Err(NativeFailure::with_detail(
            NativeFailureKind::Unexpected,
            "native RAM length is outside its bound",
        ));
    }
    let mut dirty_chunks = vec![0u8; chunks.div_ceil(8)];
    let mut identity_bytes_hashed = 0;
    for index in completed.ram.affected_chunks() {
        if index >= chunks {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::Unexpected,
                "native affected chunk is outside RAM",
            ));
        }
        dirty_chunks[index / 8] |= 1 << (index % 8);
        identity_bytes_hashed += (completed.ram.packed_len() - index as u64 * STREAM_CHUNK_BYTES)
            .min(STREAM_CHUNK_BYTES);
    }
    if completed.ram.chunk_digests().len() != chunks {
        return Err(NativeFailure::with_detail(
            NativeFailureKind::Unexpected,
            "native chunk digest count does not match RAM",
        ));
    }
    let stats = completed.ram.stats();
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
        mode,
        baseline: if mode == CapturePolicy::Incremental {
            baseline
        } else {
            None
        },
        full_reason,
        dirty_chunks,
        chunk_digests: completed
            .ram
            .chunk_digests()
            .iter()
            .map(|digest| digest.map(vm_spec::capture::Sha256Digest::from_bytes))
            .collect(),
        stats: Box::new(CaptureMemoryStats {
            seed_method: match stats.seed_method {
                libkrun::live::RamSeedMethod::Clone => vm_spec::capture::CaptureSeedMethod::Clone,
                libkrun::live::RamSeedMethod::Rebuild => {
                    vm_spec::capture::CaptureSeedMethod::Rebuild
                }
            },
            logical_bytes: stats.logical_bytes,
            live_bytes_read: stats.live_bytes_read,
            baseline_bytes_read: stats.baseline_bytes_read,
            baseline_bytes_written: stats.baseline_bytes_written,
            overlay_bytes_written: stats.overlay_bytes_written,
            full_bytes_written: stats.full_bytes_written,
            layout_bytes_written: stats.layout_bytes_written,
            baseline_hole_bytes: stats.baseline_hole_bytes,
            zero_bytes_omitted: stats.zero_bytes_omitted,
            explicit_zero_bytes_written: stats.explicit_zero_bytes_written,
            extent_queries: stats.extent_queries,
            identity_bytes_hashed,
            ..CaptureMemoryStats::default()
        }),
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

/// Recovery reconciles a retained cut, not a second pause attempt. Native
/// authenticates the failed operation and keeps coverage invalid until FULL
/// acceptance; pre-effect refusals and unrelated failures keep their policy.
fn recoverable_memory_cut(failure: &ControlFailure) -> bool {
    matches!(
        failure,
        ControlFailure::DirtyMemory(error) if error.effect != DirtyEffect::PreEffectRefusal
    )
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
    use crate::krun::worker::native::{
        generation_failure, provider_device, recoverable_memory_cut,
    };
    use crate::virt::lifecycle::{GenerationFailureKind, ProviderDevice, VirtioKind};

    #[test]
    fn first_capture_keeps_native_no_baseline_fallback_instead_of_forcing_full() {
        use vm_spec::lifecycle::CapturePolicy;

        let request = crate::krun::worker::native::memory_capture_request(
            CapturePolicy::Incremental,
            60,
            None,
        );
        assert!(request.baseline.is_none());
        assert_eq!(request.full_at_dirty_percent, 60);
        let full =
            crate::krun::worker::native::memory_capture_request(CapturePolicy::Full, 60, None);
        assert!(full.baseline.is_none());
        assert_eq!(full.full_at_dirty_percent, 0);
    }

    #[test]
    fn memory_cut_recovery_selects_only_typed_uncertain_dirty_failures() {
        use libkrun::control::ControlFailure;
        use libkrun::live::{DirtyEffect, DirtyFailure, DirtyLocation, DirtyOperation};

        for effect in [
            DirtyEffect::PreEffectRefusal,
            DirtyEffect::CoverageLost,
            DirtyEffect::ProtectionUnknown,
        ] {
            let failure = ControlFailure::DirtyMemory(DirtyFailure {
                operation: DirtyOperation::Collect,
                location: DirtyLocation::Slot(0),
                native_code: 5,
                effect,
            });
            assert_eq!(
                recoverable_memory_cut(&failure),
                effect != DirtyEffect::PreEffectRefusal
            );
        }
        for failure in [
            ControlFailure::Deadline,
            ControlFailure::CallerTimeout,
            ControlFailure::OwnerUnavailable,
            ControlFailure::WakeUnknown("DirtyMemory CoverageLost".into()),
            ControlFailure::Busy,
            ControlFailure::InvalidToken,
            ControlFailure::InvalidOperation,
            ControlFailure::Exhausted,
            ControlFailure::Unsupported("DirtyMemory CoverageLost".into()),
            ControlFailure::Participant("DirtyMemory CoverageLost".into()),
            ControlFailure::FailedFenced,
        ] {
            assert!(!recoverable_memory_cut(&failure), "{failure:?}");
        }
    }

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

//! Scenario native lifecycle owner for the in-process mock backend.
//!
//! It models the libkrun control owner's observable contract, not its
//! internals: pause admission only from Running, strictly increasing native
//! operations, one opaque run-bound token per pause generation carrying its
//! owner, explicit cancellation through rollback, ClockOnly release whose
//! acknowledgement arrives separately, and whole-machine capture with real
//! files: execution/device outputs and the full RAM image are written to the
//! actual descriptors and closed before every terminal reply, except that a
//! failed RAM write keeps its files until abandonment, like native error
//! objects. Failures and latencies are scripted by
//! [`test_utils::LifecycleScenario`]. The worker lifecycle server runs over it
//! unchanged, so its linearization, ownership and recovery logic is exercised
//! here.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sha2::Digest;
use test_utils::{
    BlockBackingScenario, LifecycleScenario, MemoryTrackingScenario, NativeCancelResult,
    NativeCancelStep, NativeCaptureResult, NativeCaptureStep, NativePauseResult, NativePauseStep,
    NativePreserveResult, NativePreserveStep, NativeResumeResult, NativeResumeStep,
};
use uuid::Uuid;

use crate::krun::worker::lifecycle::{
    ExecutionCapture, FreshRequest, GenerationPoll, MemoryCapture, NativeCaptureStatus,
    NativeExposure, NativeLifecycle, NativeState, CLOCK_ONLY_FLAGS,
};
use crate::virt::lifecycle::{
    BlockBacking, CaptureStage, CaptureStateBinding, Digest32, FlushedAttachment,
    GenerationFailureKind, InventoryObservation, MemoryTracking, NativeFailure, NativeFailureKind,
    NativeOperation, NativePauseOwner, NativeProvider, ObservedClockProfile, OutputIdentity,
    OutputReceipt, ProviderDevice, VirtioKind,
};

/// The modeled native execution-state producer.
pub(crate) const SCENARIO_PRODUCER: &str = "silo-scenario-native;execution-v1";
const PAGE: u64 = 4096;
const WRITE_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioToken {
    run: u64,
    generation: u64,
    owner: NativePauseOwner,
}

#[derive(Debug)]
pub(crate) struct ScenarioTicket {
    run: u64,
    sequence: u64,
}

/// Opaque run-bound capture ticket bound to its cut token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioCapture {
    run: u64,
    sequence: u64,
    id: Uuid,
    pause: ScenarioToken,
}

#[derive(Clone)]
pub(crate) struct ScenarioNative {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ScenarioNative {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScenarioNative").finish_non_exhaustive()
    }
}

struct Inner {
    run: u64,
    /// Configured vCPUs, the envelope's canonical CPU topology.
    cpus: u8,
    scenario: Option<LifecycleScenario>,
    model: Mutex<Model>,
    changed: Condvar,
}

struct Model {
    control: NativeState<ScenarioToken>,
    last_operation: u64,
    generation: u64,
    sequence: u64,
    /// Set when a rollback is accepted for the barrier in progress.
    cancelled: bool,
    ticket: Option<Ticket>,
    pause_steps: VecDeque<NativePauseStep>,
    cancel_steps: VecDeque<NativeCancelStep>,
    resume_steps: VecDeque<NativeResumeStep>,
    execution_steps: VecDeque<NativeCaptureStep>,
    memory_steps: VecDeque<NativeCaptureStep>,
    preserve_steps: VecDeque<NativePreserveStep>,
    captures: HashMap<Uuid, Capture>,
    released: HashSet<Uuid>,
    next_capture: u64,
    memory_generation: u64,
    stopped: bool,
}

struct Ticket {
    sequence: u64,
    step: NativeResumeStep,
    deadline: Instant,
    acknowledged_at: Option<Instant>,
    failed_at: Option<(Instant, GenerationFailureKind)>,
}

struct Capture {
    ticket: ScenarioCapture,
    binding: CaptureStateBinding,
    state: CaptureState,
    execution: ExecutionCapture<ScenarioCapture>,
    memory: Option<MemoryCapture>,
    /// A failed RAM write owns its outputs until abandonment.
    retained: Option<(File, File)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureState {
    ExecutionComplete,
    CandidateComplete,
    Accepted(u64),
    Abandoned,
    Failed(CaptureStage, NativeFailure),
}

impl CaptureState {
    fn resolved(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::Abandoned)
    }
}

fn participant(detail: &str) -> NativeFailure {
    NativeFailure::with_detail(NativeFailureKind::Participant, detail)
}

impl ScenarioNative {
    pub(crate) fn new(scenario: Option<LifecycleScenario>, cpus: u8) -> Self {
        let steps = |scenario: &LifecycleScenario| {
            (
                scenario.native_pause.iter().cloned().collect(),
                scenario.native_cancel.iter().cloned().collect(),
                scenario.native_resume.iter().cloned().collect(),
                scenario.capture.execution.iter().cloned().collect(),
                scenario.capture.memory.iter().cloned().collect(),
                scenario.capture.preserve.iter().cloned().collect(),
            )
        };
        let (
            pause_steps,
            cancel_steps,
            resume_steps,
            execution_steps,
            memory_steps,
            preserve_steps,
        ) = scenario.as_ref().map(steps).unwrap_or_default();
        Self {
            inner: Arc::new(Inner {
                run: rand::random(),
                cpus: cpus.max(1),
                scenario,
                model: Mutex::new(Model {
                    control: NativeState::Running,
                    last_operation: 0,
                    generation: 0,
                    sequence: 0,
                    cancelled: false,
                    ticket: None,
                    pause_steps,
                    cancel_steps,
                    resume_steps,
                    execution_steps,
                    memory_steps,
                    preserve_steps,
                    captures: HashMap::new(),
                    released: HashSet::new(),
                    next_capture: 0,
                    memory_generation: 0,
                    stopped: false,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    /// The process ended: native control is gone, blocked callers return and
    /// every native-retained output closes with it.
    pub(crate) fn stop(&self) {
        let mut model = self.lock();
        model.stopped = true;
        model.control = NativeState::Stopped;
        for capture in model.captures.values_mut() {
            capture.retained = None;
        }
        drop(model);
        self.inner.changed.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, Model> {
        self.inner
            .model
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn entry(&self, deadline: Instant) -> Result<MutexGuard<'_, Model>, NativeFailure> {
        let model = self.lock();
        if model.stopped {
            return Err(NativeFailure::new(NativeFailureKind::OwnerUnavailable));
        }
        if Instant::now() >= deadline {
            return Err(NativeFailure::new(NativeFailureKind::Deadline));
        }
        Ok(model)
    }

    /// Native profile admission, before any reservation or state change.
    /// Read-only VMDK lowers quiesce like raw disks; writable VMDK cannot.
    fn admission(&self) -> Result<(), NativeFailure> {
        let Some(scenario) = &self.inner.scenario else {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::Unsupported,
                "scenario carries no native lifecycle evidence",
            ));
        };
        if scenario.memory_tracking == MemoryTrackingScenario::Disabled {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::Unsupported,
                "runtime memory was excluded at construction",
            ));
        }
        if let Some(provider) = scenario.providers.iter().find(|provider| {
            provider.missing_state_provider
                || (provider.block_backing == Some(BlockBackingScenario::Vmdk)
                    && !provider.read_only)
        }) {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::Unsupported,
                format!("provider {} cannot quiesce", provider.configured_id),
            ));
        }
        Ok(())
    }

    /// Wait on the model until `ready` or `until`; `Err` if the owner stopped.
    fn wait<'a>(
        &'a self,
        mut model: MutexGuard<'a, Model>,
        until: Instant,
        ready: impl Fn(&Model) -> bool,
    ) -> Result<MutexGuard<'a, Model>, NativeFailure> {
        loop {
            if model.stopped {
                return Err(NativeFailure::new(NativeFailureKind::OwnerUnavailable));
            }
            let now = Instant::now();
            if ready(&model) || now >= until {
                return Ok(model);
            }
            model = self
                .inner
                .changed
                .wait_timeout(model, until - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn token(&self, model: &Model, owner: NativePauseOwner) -> ScenarioToken {
        ScenarioToken {
            run: self.inner.run,
            generation: model.generation,
            owner,
        }
    }

    fn ram_bytes(&self) -> u64 {
        self.inner
            .scenario
            .as_ref()
            .map_or(PAGE, |scenario| scenario.capture.ram_bytes)
    }

    /// The modeled native canonical layout: one region covering all RAM.
    fn layout_bytes(&self) -> Vec<u8> {
        let length = self.ram_bytes();
        format!(
            "{{\"architecture\":\"x86_64\",\"kind\":\"ram-layout\",\"packedLength\":{length},\
             \"pageGranule\":{PAGE},\"regions\":[{{\"guestPhysicalAddress\":0,\"length\":{length},\
             \"streamOffset\":0}}],\"schema\":1,\"topology\":{{\"firmwareAddress\":0,\
             \"initrdAddress\":{length},\"ramAboveGap\":0,\"ramBelowGap\":{length},\
             \"ramLastAddress\":{length},\"shmStartAddress\":4294967296}}}}"
        )
        .into_bytes()
    }

    /// The capture whose ticket is exactly `ticket`, under its current cut.
    fn capture<'a>(
        &self,
        model: &'a mut Model,
        ticket: &ScenarioCapture,
    ) -> Result<&'a mut Capture, NativeFailure> {
        if ticket.run != self.inner.run || !current_token(model, &ticket.pause) {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        model
            .captures
            .get_mut(&ticket.id)
            .filter(|capture| capture.ticket == *ticket)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::InvalidToken))
    }

    /// Every live virtio attachment `(kind, configured id, address, irq)` in
    /// native transport (address) order, as the inventory reports it.
    fn attachments(&self) -> Vec<(u32, String, u64, u32)> {
        self.inner
            .scenario
            .as_ref()
            .map(|scenario| {
                scenario
                    .providers
                    .iter()
                    .enumerate()
                    .map(|(index, provider)| {
                        (
                            provider.device_id,
                            provider.configured_id.clone(),
                            0xd000_0000 + 0x1000 * index as u64,
                            5 + index as u32,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The native v1 public KRUNEXEC header (KVM x86 lane) in the native
    /// little-endian state codec, followed by an explicitly opaque scenario
    /// payload in place of hypervisor state.
    fn execution_envelope(&self, binding: &CaptureStateBinding) -> Vec<u8> {
        let mut out = Encoder::default();
        out.fixed(b"KRUNEXEC");
        out.u16(1);
        out.u32(1);
        out.u8(1);
        out.binding(binding);
        out.u32(u32::from(self.inner.cpus));
        for cpu in 0..self.inner.cpus {
            out.u8(cpu);
            out.u64(u64::from(cpu));
        }
        out.u32(PAGE as u32);
        out.u32(1);
        out.u64(0);
        out.u64(self.ram_bytes());
        let attachments = self.attachments();
        out.u32(attachments.len() as u32);
        for (kind, id, address, irq) in &attachments {
            out.u32(*kind);
            out.bytes(id.as_bytes());
            out.u64(*address);
            out.u32(*irq);
        }
        out.u32(attachments.len() as u32);
        for (_, _, address, irq) in &attachments {
            out.u32(*irq);
            out.u32(1);
            out.u64(*address);
        }
        out.fixed(b"scenario-opaque-vm-and-vcpu-state-v1");
        out.0
    }

    /// The native v1 public KRUNDEVS envelope with one record per attachment
    /// in the native record layout, zero transport state, empty payloads.
    fn device_envelope(&self, binding: &CaptureStateBinding) -> Vec<u8> {
        let mut out = Encoder::default();
        out.fixed(b"KRUNDEVS");
        out.u16(1);
        out.binding(binding);
        let attachments = self.attachments();
        out.u32(attachments.len() as u32);
        for (kind, id, address, irq) in &attachments {
            out.bytes(id.as_bytes());
            out.u32(*kind);
            out.bytes(b"scenario");
            out.u64(*address);
            out.u32(*irq);
            out.u64(0);
            out.u64(0);
            for _ in 0..7 {
                out.u32(0);
            }
            out.u8(0);
            out.u32(0);
            out.bytes(&[]);
        }
        out.0
    }
}

/// The native `utils::state` little-endian writer subset the public
/// envelope headers use: fixed bytes, integers and u32-counted byte strings.
#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn fixed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn u8(&mut self, value: u8) {
        self.fixed(&[value]);
    }
    fn u16(&mut self, value: u16) {
        self.fixed(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.fixed(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.fixed(&value.to_le_bytes());
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.u32(bytes.len() as u32);
        self.fixed(bytes);
    }
    /// Native `StateBinding` encoding order.
    fn binding(&mut self, binding: &CaptureStateBinding) {
        self.bytes(binding.native_producer.as_bytes());
        for digest in [
            &binding.silo_producer,
            &binding.profile,
            &binding.topology,
            &binding.ram_layout,
        ] {
            self.fixed(&digest.0);
        }
        self.fixed(binding.source_run.as_bytes());
        self.u64(binding.pause_generation.get());
        self.fixed(binding.capture.as_bytes());
    }
}

fn reserve(model: &mut Model, operation: NativeOperation) -> Result<(), NativeFailure> {
    if operation.get() <= model.last_operation {
        return Err(NativeFailure::new(NativeFailureKind::InvalidOperation));
    }
    model.last_operation = operation.get();
    Ok(())
}

fn current_token(model: &Model, token: &ScenarioToken) -> bool {
    matches!(&model.control, NativeState::Paused(current) if current == token)
}

fn step(steps: &mut VecDeque<NativeCaptureStep>) -> NativeCaptureStep {
    steps.pop_front().unwrap_or(NativeCaptureStep {
        delay_ms: 0,
        result: NativeCaptureResult::Complete,
    })
}

/// Native output preflight: regular, writable, empty and distinct.
fn empty_output(file: &File) -> Result<OutputIdentity, NativeFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| participant(&format!("output metadata: {error}")))?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(participant("native output is not an empty regular file"));
    }
    Ok(OutputIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn write_all_at(file: &File, bytes: &[u8], offset: u64) -> Result<(), NativeFailure> {
    file.write_all_at(bytes, offset)
        .map_err(|error| participant(&format!("native output write: {error}")))
}

fn receipt(file: &File) -> Result<OutputReceipt, NativeFailure> {
    file.sync_all()
        .map_err(|error| participant(&format!("native output sync: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| participant(&format!("output metadata: {error}")))?;
    Ok(OutputReceipt {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    })
}

/// Deterministic guest RAM content, written in bounded chunks.
fn write_ram(file: &File, length: u64) -> Result<(), NativeFailure> {
    let mut chunk = vec![0_u8; WRITE_CHUNK];
    let mut offset = 0;
    while offset < length {
        let count = usize::try_from((length - offset).min(WRITE_CHUNK as u64))
            .map_err(|_| participant("RAM chunk size"))?;
        for (index, byte) in chunk[..count].iter_mut().enumerate() {
            let page = (offset + index as u64) / PAGE;
            *byte = (page % 251) as u8 ^ (index as u8);
        }
        write_all_at(file, &chunk[..count], offset)?;
        offset += count as u64;
    }
    Ok(())
}

impl NativeLifecycle for ScenarioNative {
    type Token = ScenarioToken;
    type Ticket = ScenarioTicket;
    type Capture = ScenarioCapture;
    // The scenario backend never launches a restore: no restore authority
    // can exist, so no restore behavior is modeled or invented.
    type Restore = std::convert::Infallible;

    fn pause(
        &self,
        owner: NativePauseOwner,
        operation: NativeOperation,
        _profile_operation: NativeOperation,
        _recovery_operation: NativeOperation,
        _clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    ) -> Result<ScenarioToken, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !matches!(model.control, NativeState::Running) {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        self.admission()?;
        let step = model.pause_steps.pop_front().unwrap_or(NativePauseStep {
            delay_ms: 0,
            result: NativePauseResult::Complete,
        });
        if step.result == NativePauseResult::Reject {
            return Err(NativeFailure::with_detail(
                NativeFailureKind::Unsupported,
                "scripted native pause admission rejection",
            ));
        }
        reserve(&mut model, operation)?;
        model.generation = model
            .generation
            .checked_add(1)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::Exhausted))?;
        model.control = NativeState::Pausing {
            operation: operation.get(),
            failed: false,
        };
        model.cancelled = false;
        let completes = match step.result {
            NativePauseResult::Hang => deadline,
            _ => (Instant::now() + Duration::from_millis(step.delay_ms)).min(deadline),
        };
        let mut model = self.wait(model, completes, |model| model.cancelled)?;
        if model.cancelled {
            return Err(participant("pause explicitly cancelled"));
        }
        if step.result == NativePauseResult::Hang || Instant::now() >= deadline {
            model.control = NativeState::Pausing {
                operation: operation.get(),
                failed: true,
            };
            return Err(NativeFailure::new(NativeFailureKind::Deadline));
        }
        let token = self.token(&model, owner);
        match step.result {
            NativePauseResult::Fail => {
                model.control = NativeState::Pausing {
                    operation: operation.get(),
                    failed: true,
                };
                Err(participant("scripted native barrier failure"))
            }
            NativePauseResult::LoseReply => {
                model.control = NativeState::Paused(token);
                Err(NativeFailure::new(NativeFailureKind::CallerTimeout))
            }
            NativePauseResult::Complete | NativePauseResult::Reject | NativePauseResult::Hang => {
                model.control = NativeState::Paused(token.clone());
                Ok(token)
            }
        }
    }

    fn cancel_pause(
        &self,
        pausing: NativeOperation,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !matches!(model.control, NativeState::Pausing { operation: current, .. } if current == pausing.get())
        {
            return Err(NativeFailure::new(NativeFailureKind::InvalidOperation));
        }
        reserve(&mut model, operation)?;
        model.control = NativeState::RollingBack {
            operation: operation.get(),
        };
        model.cancelled = true;
        let step = model.cancel_steps.pop_front().unwrap_or(NativeCancelStep {
            delay_ms: 0,
            result: NativeCancelResult::Complete,
        });
        self.inner.changed.notify_all();
        let settles = Instant::now() + Duration::from_millis(step.delay_ms);
        let mut model = self.wait(model, settles, |_| false)?;
        match step.result {
            NativeCancelResult::Complete => {
                model.control = NativeState::Running;
                Ok(())
            }
            NativeCancelResult::Fail => {
                model.control = NativeState::FailedFenced;
                Err(participant("scripted native rollback failure"))
            }
        }
    }

    fn prepare_clock_only(
        &self,
        token: &ScenarioToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<ScenarioTicket, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !current_token(&model, token) {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        // Native refuses to release a cut whose capture is unresolved.
        if model
            .captures
            .values()
            .any(|capture| !capture.state.resolved())
        {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        reserve(&mut model, operation)?;
        let step = model.resume_steps.pop_front().unwrap_or(NativeResumeStep {
            delay_ms: 0,
            result: NativeResumeResult::Complete,
            clock_delay_ms: 0,
        });
        if step.result == NativeResumeResult::PrepareFail {
            return Err(participant("scripted generation preparation failure"));
        }
        model.sequence = model
            .sequence
            .checked_add(1)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::Exhausted))?;
        let sequence = model.sequence;
        model.ticket = Some(Ticket {
            sequence,
            step,
            deadline,
            acknowledged_at: None,
            failed_at: None,
        });
        Ok(ScenarioTicket {
            run: self.inner.run,
            sequence,
        })
    }

    fn resume_generation(
        &self,
        token: ScenarioToken,
        ticket: &ScenarioTicket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        let mut model = self.entry(deadline)?;
        let step = match &model.ticket {
            Some(current)
                if ticket.run == self.inner.run && current.sequence == ticket.sequence =>
            {
                current.step.clone()
            }
            _ => return Err(NativeFailure::new(NativeFailureKind::InvalidToken)),
        };
        if !current_token(&model, &token) {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        reserve(&mut model, operation)?;
        model.control = NativeState::Resuming {
            operation: operation.get(),
        };
        let released = Instant::now() + Duration::from_millis(step.delay_ms);
        let mut model = self.wait(model, released.min(deadline), |_| false)?;
        if released > deadline || step.result == NativeResumeResult::ReleaseFail {
            model.control = NativeState::FailedFenced;
            if let Some(ticket) = model.ticket.as_mut() {
                ticket.failed_at = Some((Instant::now(), GenerationFailureKind::Release));
            }
            return Err(if released > deadline {
                NativeFailure::new(NativeFailureKind::Deadline)
            } else {
                participant("scripted native release failure")
            });
        }
        model.control = NativeState::Running;
        let now = Instant::now();
        let acknowledged = now + Duration::from_millis(step.clock_delay_ms);
        if let Some(ticket) = model.ticket.as_mut() {
            match step.result {
                NativeResumeResult::Complete | NativeResumeResult::LoseReply => {
                    ticket.acknowledged_at = Some(acknowledged)
                }
                NativeResumeResult::ClockFail => {
                    ticket.failed_at = Some((acknowledged, GenerationFailureKind::DriverError))
                }
                NativeResumeResult::ClockTimeout
                | NativeResumeResult::PrepareFail
                | NativeResumeResult::ReleaseFail => {}
            }
        }
        if step.result == NativeResumeResult::LoseReply {
            return Err(NativeFailure::new(NativeFailureKind::CallerTimeout));
        }
        Ok(())
    }

    fn poll_generation(
        &self,
        ticket: &ScenarioTicket,
        deadline: Instant,
    ) -> Result<GenerationPoll, NativeFailure> {
        let model = self.entry(deadline)?;
        let current = model
            .ticket
            .as_ref()
            .filter(|current| ticket.run == self.inner.run && current.sequence == ticket.sequence)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::InvalidToken))?;
        let now = Instant::now();
        Ok(match (current.acknowledged_at, current.failed_at) {
            (Some(at), _) if at <= now && at < current.deadline => {
                GenerationPoll::Acknowledged { completed_at: at }
            }
            (_, Some((at, kind))) if at <= now => GenerationPoll::Failed(kind),
            _ if now >= current.deadline => GenerationPoll::Failed(GenerationFailureKind::Deadline),
            _ => GenerationPoll::Pending,
        })
    }

    fn ticket_request(&self, ticket: &ScenarioTicket) -> (u64, u32) {
        (ticket.sequence, CLOCK_ONLY_FLAGS)
    }

    fn control_state(
        &self,
        _deadline: Instant,
    ) -> Result<NativeState<ScenarioToken>, NativeFailure> {
        // Status is answered even after the deadline, like native Status.
        Ok(self.lock().control.clone())
    }

    fn inventory(&self, _deadline: Instant) -> InventoryObservation {
        let Some(scenario) = &self.inner.scenario else {
            return InventoryObservation::Unavailable {
                failure: NativeFailure::with_detail(
                    NativeFailureKind::Unsupported,
                    "scenario carries no native lifecycle evidence",
                ),
            };
        };
        if scenario
            .providers
            .iter()
            .any(|provider| provider.missing_state_provider)
        {
            return InventoryObservation::Unavailable {
                failure: NativeFailure::new(NativeFailureKind::FailedFenced),
            };
        }
        let providers = scenario
            .providers
            .iter()
            .enumerate()
            .map(|(index, provider)| NativeProvider {
                device: ProviderDevice::Virtio {
                    device_id: provider.device_id,
                    kind: VirtioKind::from_device_id(provider.device_id),
                },
                configured_id: provider.configured_id.clone(),
                address: 0xd000_0000 + 0x1000 * index as u64,
                irq: 5 + index as u32,
                activation_fenced: provider.activation_fenced,
                block_backing: provider.block_backing.map(|backing| match backing {
                    BlockBackingScenario::Raw => BlockBacking::Raw,
                    BlockBackingScenario::Vmdk => BlockBacking::Vmdk,
                }),
                block_read_only: provider.block_backing.map(|_| provider.read_only),
            })
            .collect();
        InventoryObservation::Observed {
            providers,
            memory_tracking: Some(match scenario.memory_tracking {
                MemoryTrackingScenario::Disabled => MemoryTracking::Disabled,
                MemoryTrackingScenario::Capture => MemoryTracking::Capture,
            }),
        }
    }

    fn token_generation(&self, token: &ScenarioToken) -> u64 {
        token.generation
    }

    fn token_owner(&self, token: &ScenarioToken) -> NativePauseOwner {
        token.owner
    }

    fn protected_identities(&self) -> Vec<OutputIdentity> {
        Vec::new()
    }

    fn native_producer(&self) -> Result<String, NativeFailure> {
        Ok(SCENARIO_PRODUCER.to_string())
    }

    fn ram_layout_digest(&self, deadline: Instant) -> Result<Digest32, NativeFailure> {
        drop(self.entry(deadline)?);
        Ok(Digest32(sha2::Sha256::digest(self.layout_bytes()).into()))
    }

    fn flush_capture(
        &self,
        token: &ScenarioToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<Vec<FlushedAttachment>, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !current_token(&model, token) {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        reserve(&mut model, operation)?;
        // Native reports every quiesced attachment identity, not only disks.
        Ok(self
            .attachments()
            .into_iter()
            .map(|(_, configured_id, address, irq)| FlushedAttachment {
                configured_id,
                address,
                irq,
            })
            .collect())
    }

    fn capture_execution(
        &self,
        token: &ScenarioToken,
        binding: &CaptureStateBinding,
        execution: File,
        devices: File,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<ExecutionCapture<ScenarioCapture>, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !current_token(&model, token) || binding.pause_generation.get() != token.generation {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        if binding.native_producer != SCENARIO_PRODUCER
            || binding.ram_layout.0 != <[u8; 32]>::from(sha2::Sha256::digest(self.layout_bytes()))
        {
            return Err(participant(
                "capture binding conflicts with the native owner",
            ));
        }
        if model
            .captures
            .values()
            .any(|capture| !capture.state.resolved())
        {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        if model.captures.contains_key(&binding.capture)
            || model.released.contains(&binding.capture)
        {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        let identities = [empty_output(&execution)?, empty_output(&devices)?];
        if identities[0] == identities[1] {
            return Err(participant("execution outputs alias"));
        }
        reserve(&mut model, operation)?;
        let step = step(&mut model.execution_steps);
        let mut model = self.wait(
            model,
            (Instant::now() + Duration::from_millis(step.delay_ms)).min(deadline),
            |_| false,
        )?;
        model.next_capture += 1;
        let ticket = ScenarioCapture {
            run: self.inner.run,
            sequence: model.next_capture,
            id: binding.capture,
            pause: token.clone(),
        };
        let written = (|| {
            write_all_at(&execution, &self.execution_envelope(binding), 0)?;
            write_all_at(&devices, &self.device_envelope(binding), 0)?;
            Ok::<_, NativeFailure>((receipt(&execution)?, receipt(&devices)?))
        })();
        // Closure of both descriptors precedes every terminal reply.
        drop((execution, devices));
        let (state, result) = match (step.result, written) {
            (_, Err(failure)) => (
                CaptureState::Failed(CaptureStage::Execution, failure.clone()),
                Err(failure),
            ),
            (NativeCaptureResult::Fail, Ok(_)) => {
                let failure = participant("scripted execution capture failure");
                (
                    CaptureState::Failed(CaptureStage::Execution, failure.clone()),
                    Err(failure),
                )
            }
            (result, Ok((execution, devices))) => {
                let receipt = ExecutionCapture {
                    ticket: ticket.clone(),
                    execution,
                    devices,
                };
                let reply = if result == NativeCaptureResult::LoseReply {
                    Err(NativeFailure::new(NativeFailureKind::CallerTimeout))
                } else {
                    Ok(receipt.clone())
                };
                model.captures.insert(
                    binding.capture,
                    Capture {
                        ticket,
                        binding: binding.clone(),
                        state: CaptureState::ExecutionComplete,
                        execution: receipt,
                        memory: None,
                        retained: None,
                    },
                );
                return reply;
            }
        };
        model.captures.insert(
            binding.capture,
            Capture {
                ticket: ticket.clone(),
                binding: binding.clone(),
                state,
                execution: ExecutionCapture {
                    ticket,
                    execution: OutputReceipt {
                        device: identities[0].device,
                        inode: identities[0].inode,
                        length: 0,
                    },
                    devices: OutputReceipt {
                        device: identities[1].device,
                        inode: identities[1].inode,
                        length: 0,
                    },
                },
                memory: None,
                retained: None,
            },
        );
        result
    }

    fn capture_memory(
        &self,
        capture: &ScenarioCapture,
        ram: File,
        layout: File,
        _preparation: &crate::virt::lifecycle::CapturePreparation,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<MemoryCapture, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if self.capture(&mut model, capture)?.state != CaptureState::ExecutionComplete {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        let identities = [empty_output(&ram)?, empty_output(&layout)?];
        if identities[0] == identities[1] {
            return Err(participant("RAM outputs alias"));
        }
        reserve(&mut model, operation)?;
        let step = step(&mut model.memory_steps);
        let mut model = self.wait(
            model,
            (Instant::now() + Duration::from_millis(step.delay_ms)).min(deadline),
            |_| false,
        )?;
        let length = self.ram_bytes();
        let layout_bytes = self.layout_bytes();
        if step.result == NativeCaptureResult::Fail {
            // A partial image: the failure retains both writers.
            let partial = write_ram(&ram, (length / 2).max(PAGE).min(length));
            let failure = match partial {
                Ok(()) => participant("scripted RAM image write failure (ENOSPC)"),
                Err(failure) => failure,
            };
            let entry = self.capture(&mut model, capture)?;
            entry.state = CaptureState::Failed(CaptureStage::Memory, failure.clone());
            entry.retained = Some((ram, layout));
            return Err(failure);
        }
        let written = write_ram(&ram, length)
            .and_then(|()| write_all_at(&layout, &layout_bytes, 0))
            .and_then(|()| Ok((receipt(&ram)?, receipt(&layout)?)));
        let (ram_receipt, layout_receipt) = match written {
            Ok(receipts) => receipts,
            Err(failure) => {
                let entry = self.capture(&mut model, capture)?;
                entry.state = CaptureState::Failed(CaptureStage::Memory, failure.clone());
                entry.retained = Some((ram, layout));
                return Err(failure);
            }
        };
        // Completion follows closure of both RAM outputs.
        drop((ram, layout));
        model.memory_generation += 1;
        let memory_generation = model.memory_generation;
        let entry = self.capture(&mut model, capture)?;
        let memory = MemoryCapture {
            binding: Box::new(entry.binding.clone()),
            ram: ram_receipt,
            layout: layout_receipt,
            memory_generation,
            writers_closed: true,
            mode: vm_spec::lifecycle::CapturePolicy::Full,
            baseline: None,
            full_reason: Some(vm_spec::capture::CaptureFullReason::Requested),
            dirty_chunks: vm_spec::capture::full_dirty_chunks(length)
                .map_err(|error| participant(&error))?,
            stats: vm_spec::capture::CaptureMemoryStats {
                logical_bytes: length,
                live_bytes_read: length,
                full_bytes_written: length,
                layout_bytes_written: layout_bytes.len() as u64,
                ..Default::default()
            },
        };
        entry.memory = Some(memory.clone());
        entry.state = CaptureState::CandidateComplete;
        if step.result == NativeCaptureResult::LoseReply {
            return Err(NativeFailure::new(NativeFailureKind::CallerTimeout));
        }
        Ok(memory)
    }

    fn capture_status(
        &self,
        capture: Uuid,
        _deadline: Instant,
    ) -> Result<NativeCaptureStatus<ScenarioCapture>, NativeFailure> {
        let model = self.lock();
        if model.released.contains(&capture) {
            return Ok(NativeCaptureStatus::Released);
        }
        let entry = model
            .captures
            .get(&capture)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::InvalidToken))?;
        let ticket = entry.ticket.clone();
        Ok(match &entry.state {
            CaptureState::ExecutionComplete => {
                NativeCaptureStatus::ExecutionComplete(entry.execution.clone())
            }
            CaptureState::CandidateComplete => match &entry.memory {
                Some(memory) => NativeCaptureStatus::CandidateComplete {
                    ticket,
                    memory: memory.clone(),
                },
                None => return Err(participant("candidate without a receipt")),
            },
            CaptureState::Accepted(memory_generation) => NativeCaptureStatus::Accepted {
                ticket,
                memory_generation: *memory_generation,
            },
            CaptureState::Abandoned => NativeCaptureStatus::Abandoned(ticket),
            CaptureState::Failed(stage, failure) => NativeCaptureStatus::Failed {
                ticket,
                stage: *stage,
                failure: failure.clone(),
            },
        })
    }

    fn accept_capture(
        &self,
        capture: &ScenarioCapture,
        binding: &CaptureStateBinding,
        ram: File,
        layout: File,
        stream: Digest32,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<u64, NativeFailure> {
        use nix::fcntl::{fcntl, FcntlArg, OFlag};
        let mut model = self.entry(deadline)?;
        let entry = self.capture(&mut model, capture)?;
        if let CaptureState::Accepted(memory_generation) = entry.state {
            return Ok(memory_generation);
        }
        let memory = match (&entry.state, &entry.memory) {
            (CaptureState::CandidateComplete, Some(memory)) => memory.clone(),
            _ => return Err(NativeFailure::new(NativeFailureKind::Busy)),
        };
        if *binding != entry.binding || stream.is_zero() {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        for (file, expected) in [(&ram, memory.ram), (&layout, memory.layout)] {
            let observed = receipt_of(file)?;
            let flags = OFlag::from_bits_retain(
                fcntl(file, FcntlArg::F_GETFL)
                    .map_err(|error| participant(&format!("sealed access: {error}")))?,
            );
            if observed != expected || flags & OFlag::O_ACCMODE != OFlag::O_RDONLY {
                return Err(participant("sealed RAM image differs from the candidate"));
            }
        }
        reserve(&mut model, operation)?;
        let entry = self.capture(&mut model, capture)?;
        entry.state = CaptureState::Accepted(memory.memory_generation);
        Ok(memory.memory_generation)
    }

    fn abandon_capture(
        &self,
        capture: &ScenarioCapture,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        let mut model = self.entry(deadline)?;
        let entry = self.capture(&mut model, capture)?;
        match entry.state {
            CaptureState::Abandoned => return Ok(()),
            CaptureState::Accepted(_) => return Err(NativeFailure::new(NativeFailureKind::Busy)),
            _ => {}
        }
        reserve(&mut model, operation)?;
        let entry = self.capture(&mut model, capture)?;
        entry.retained = None;
        entry.memory = None;
        entry.state = CaptureState::Abandoned;
        Ok(())
    }

    fn release_capture(
        &self,
        capture: Uuid,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure> {
        let mut model = self.entry(deadline)?;
        if model.released.contains(&capture) {
            return Ok(());
        }
        let resolved = model
            .captures
            .get(&capture)
            .ok_or_else(|| NativeFailure::new(NativeFailureKind::InvalidToken))?
            .state
            .resolved();
        if !resolved {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        reserve(&mut model, operation)?;
        model.captures.remove(&capture);
        model.released.insert(capture);
        Ok(())
    }

    fn preserve_pause(
        &self,
        token: ScenarioToken,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<ScenarioToken, NativeFailure> {
        let mut model = self.entry(deadline)?;
        if !current_token(&model, &token) {
            return Err(NativeFailure::new(NativeFailureKind::InvalidToken));
        }
        if model
            .captures
            .values()
            .any(|capture| !capture.state.resolved())
        {
            return Err(NativeFailure::new(NativeFailureKind::Busy));
        }
        let step = model
            .preserve_steps
            .pop_front()
            .unwrap_or(NativePreserveStep {
                result: NativePreserveResult::Complete,
            });
        if step.result == NativePreserveResult::Fail {
            return Err(participant("scripted native preserve failure"));
        }
        reserve(&mut model, operation)?;
        // Ownership changes under the same cut; the generation does not.
        let preserved = ScenarioToken {
            owner: NativePauseOwner::User,
            ..token
        };
        model.control = NativeState::Paused(preserved.clone());
        Ok(preserved)
    }

    fn prepare_fresh(
        &self,
        restore: &std::convert::Infallible,
        _operation: NativeOperation,
        _deadline: Instant,
    ) -> Result<(ScenarioTicket, FreshRequest), NativeFailure> {
        match *restore {}
    }

    fn resume_restored(
        &self,
        restore: &std::convert::Infallible,
        _ticket: &ScenarioTicket,
        _operation: NativeOperation,
        _deadline: Instant,
    ) -> Result<(), NativeFailure> {
        match *restore {}
    }

    fn release_activation(
        &self,
        restore: &std::convert::Infallible,
        _ticket: &ScenarioTicket,
        _operation: NativeOperation,
        _deadline: Instant,
    ) -> Result<(), NativeFailure> {
        match *restore {}
    }

    fn activation_exposure(
        &self,
        restore: &std::convert::Infallible,
        _deadline: Instant,
    ) -> Result<NativeExposure, NativeFailure> {
        match *restore {}
    }

    fn park_restored(
        &self,
        restore: &std::convert::Infallible,
        _operation: NativeOperation,
        _deadline: Instant,
    ) -> Result<ScenarioToken, NativeFailure> {
        match *restore {}
    }
}

fn receipt_of(file: &File) -> Result<OutputReceipt, NativeFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| participant(&format!("sealed metadata: {error}")))?;
    Ok(OutputReceipt {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
    })
}

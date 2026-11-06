//! Worker side of the lifecycle socket: the retained native command owner.
//!
//! ```text
//!            one reader thread (never calls native)
//!   socket ──► admission under the journal lock ──► handler thread per command
//!                     │                                  │ blocking native calls
//!                     └── pause slot linearizes ◄────────┘ publication vs cancel
//! ```
//!
//! Every native mutator receives a fresh, strictly increasing native
//! operation. Opaque native tokens, generation tickets and capture tickets
//! never leave this module. Only CancelPause may run while its target Pause is
//! still pending.
//!
//! A capture owns its five descriptors from PrepareCapture on:
//!
//! ```text
//!   Prepared ──Pause{Capture}──► Paused ──Flush──► Flushed ──Execution──► ExecutionCaptured
//!      │  (Borrow: already paused) ─────┘                                     │ Memory
//!      └──────────── AbandonCapture ◄──── Failed ◄────────────── CandidateComplete
//!                         │                                           │ Accept (after seal)
//!                     Abandoned ──Release──► Released ◄──Release── Accepted
//! ```
//!
//! Output holders move Prepared → Native → Closed. Native closes successful
//! outputs before its terminal reply; a failed RAM write keeps its files in
//! native error objects until abandonment. The worker converts every native
//! error to a bounded [`NativeFailure`] at once, so it never retains a writer.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::krun::worker::lifecycle_wire::{self, ParentFrame, WorkerFrame, PROTOCOL_VERSION};
use crate::virt::lifecycle::{
    CancelSettlement, CancelStage, CaptureContinuation, CaptureDigests, CaptureNativeEvidence,
    CaptureObservation, CaptureOutputHolders, CaptureOutputIdentities, CapturePauseObservation,
    CapturePauseOrigin, CapturePauseSource, CapturePreparation, CaptureProgress,
    CaptureResumePolicy, CaptureStage, CaptureStateBinding, ClockOnlyReceipt, CommandKey,
    CommandKind, CommandOutcome, CommandReport, CommandSequence, CommandState, ControlObservation,
    Digest32, FlushedAttachment, GenerationFailureKind, InventoryObservation, LifecycleCommand,
    LifecycleRejection, LifecycleRequest, LifecycleRights, NativeControl, NativeFailure,
    NativeFailureKind, NativeOperation, NativePause, NativePauseGeneration, NativePauseOwner,
    ObservedClockProfile, OutputDefect, OutputHolder, OutputIdentity, OutputProblem, OutputReceipt,
    OutputRole, PausePurpose, PinHolder, ResumeStage,
};

/// Native ClockOnly generation requests carry SYNC_CLOCK | CLOCK_ONLY.
pub(crate) const CLOCK_ONLY_FLAGS: u32 = 1 | 2;
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const OBSERVATION_BUDGET: Duration = Duration::from_secs(1);
const RECONCILE_GRACE: Duration = Duration::from_secs(5);
const RECONCILE_INTERVAL: Duration = Duration::from_millis(5);
const CLOCK_POLL_INTERVAL: Duration = Duration::from_millis(2);
/// Observation/rejection handler threads; beyond this the reader answers
/// without a native observation.
const MAX_LIGHT_HANDLERS: usize = 8;

/// Native control as observed by the worker, keeping the opaque token.
#[derive(Debug, Clone)]
pub(crate) enum NativeState<T> {
    Running,
    Pausing { operation: u64, failed: bool },
    Paused(T),
    Resuming { operation: u64 },
    RollingBack { operation: u64 },
    RestorePrepared,
    FailedFenced,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationPoll {
    Pending,
    Acknowledged { completed_at: Instant },
    Failed(GenerationFailureKind),
}

/// A native execution receipt with its opaque capture ticket.
#[derive(Debug, Clone)]
pub(crate) struct ExecutionCapture<C> {
    pub(crate) ticket: C,
    pub(crate) execution: OutputReceipt,
    pub(crate) devices: OutputReceipt,
}

/// A native full-RAM candidate receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryCapture {
    pub(crate) binding: Box<CaptureStateBinding>,
    pub(crate) ram: OutputReceipt,
    pub(crate) layout: OutputReceipt,
    pub(crate) memory_generation: u64,
    pub(crate) writers_closed: bool,
}

/// Native capture status, already free of resource-bearing errors.
#[derive(Debug, Clone)]
pub(crate) enum NativeCaptureStatus<C> {
    ExecutionPending(C),
    ExecutionComplete(ExecutionCapture<C>),
    MemoryPending(C),
    CandidateComplete {
        ticket: C,
        memory: MemoryCapture,
    },
    Accepted {
        ticket: C,
        memory_generation: u64,
    },
    Abandoned(C),
    Failed {
        ticket: C,
        stage: CaptureStage,
        failure: NativeFailure,
    },
    Released,
}

/// The blocking native lifecycle authority. The real worker implements it over
/// libkrun; the scenario backend implements a modeled native owner.
pub(crate) trait NativeLifecycle: Send + Sync + 'static {
    type Token: Clone + Send + 'static;
    type Ticket: Send + 'static;
    type Capture: Clone + Send + 'static;

    fn pause(
        &self,
        owner: NativePauseOwner,
        operation: NativeOperation,
        profile_operation: NativeOperation,
        clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    ) -> Result<Self::Token, NativeFailure>;
    fn cancel_pause(
        &self,
        pausing: NativeOperation,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure>;
    fn prepare_clock_only(
        &self,
        token: &Self::Token,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<Self::Ticket, NativeFailure>;
    fn resume_generation(
        &self,
        token: Self::Token,
        ticket: &Self::Ticket,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure>;
    fn poll_generation(
        &self,
        ticket: &Self::Ticket,
        deadline: Instant,
    ) -> Result<GenerationPoll, NativeFailure>;
    /// `(sequence, flags)` of the published generation request.
    fn ticket_request(&self, ticket: &Self::Ticket) -> (u64, u32);
    fn control_state(&self, deadline: Instant) -> Result<NativeState<Self::Token>, NativeFailure>;
    fn inventory(&self, deadline: Instant) -> InventoryObservation;
    fn token_generation(&self, token: &Self::Token) -> u64;
    fn token_owner(&self, token: &Self::Token) -> NativePauseOwner;

    /// Identities no capture output may alias: launch disks and the launch
    /// storage lease. Native additionally refuses RAM backings and baselines.
    fn protected_identities(&self) -> Vec<OutputIdentity>;
    /// Exact native execution-state producer of this build.
    fn native_producer(&self) -> Result<String, NativeFailure>;
    /// SHA-256 of the native canonical RAM layout bytes.
    fn ram_layout_digest(&self, deadline: Instant) -> Result<Digest32, NativeFailure>;
    fn flush_capture(
        &self,
        token: &Self::Token,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<Vec<FlushedAttachment>, NativeFailure>;
    #[allow(clippy::too_many_arguments)]
    fn capture_execution(
        &self,
        token: &Self::Token,
        binding: &CaptureStateBinding,
        execution: File,
        devices: File,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<ExecutionCapture<Self::Capture>, NativeFailure>;
    /// Always a full capture: no baseline, no dirty crossover.
    fn capture_memory(
        &self,
        capture: &Self::Capture,
        ram: File,
        layout: File,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<MemoryCapture, NativeFailure>;
    fn capture_status(
        &self,
        capture: Uuid,
        deadline: Instant,
    ) -> Result<NativeCaptureStatus<Self::Capture>, NativeFailure>;
    #[allow(clippy::too_many_arguments)]
    fn accept_capture(
        &self,
        capture: &Self::Capture,
        binding: &CaptureStateBinding,
        ram: File,
        layout: File,
        stream: Digest32,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<u64, NativeFailure>;
    fn abandon_capture(
        &self,
        capture: &Self::Capture,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure>;
    fn release_capture(
        &self,
        capture: Uuid,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<(), NativeFailure>;
    /// Transfer a completed Capture-owned pause to User ownership.
    fn preserve_pause(
        &self,
        token: Self::Token,
        operation: NativeOperation,
        deadline: Instant,
    ) -> Result<Self::Token, NativeFailure>;
}

/// Exact launch identity bound by the Hello frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) machine_id: Uuid,
    pub(crate) run_id: Uuid,
}

/// Called once when control is lost: EOF, protocol violation or write failure.
pub(crate) type FatalHandler = Box<dyn Fn(&str) + Send + Sync>;

/// Start serving one connected lifecycle endpoint. Never blocks the caller,
/// so it is safe from the native pre-run callback.
pub(crate) fn serve<N: NativeLifecycle>(
    endpoint: OwnedFd,
    binding: Binding,
    native: N,
    on_fatal: FatalHandler,
) -> std::io::Result<()> {
    let socket = UnixStream::from(endpoint);
    socket.set_nonblocking(false)?;
    let writer = socket.try_clone()?;
    writer.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let shared = Arc::new(Shared {
        native,
        binding,
        journal: Mutex::new(Journal::default()),
        settled: Condvar::new(),
        writer: Mutex::new(writer),
        light: AtomicUsize::new(0),
        failed: AtomicBool::new(false),
        on_fatal,
    });
    std::thread::Builder::new()
        .name("krun-lifecycle".to_string())
        .spawn(move || {
            let hello = WorkerFrame::Hello {
                version: PROTOCOL_VERSION,
                machine_id: binding.machine_id,
                run_id: binding.run_id,
            };
            if shared.send(&hello) {
                if let Err(error) = shared.read_loop(&socket) {
                    shared.fatal(&error.to_string());
                }
            }
        })
        .map(drop)
}

struct Shared<N: NativeLifecycle> {
    native: N,
    binding: Binding,
    journal: Mutex<Journal<N::Token, N::Capture>>,
    settled: Condvar,
    writer: Mutex<UnixStream>,
    light: AtomicUsize,
    failed: AtomicBool,
    on_fatal: FatalHandler,
}

struct Journal<T, C> {
    last_sequence: u64,
    last_native: u64,
    /// Retained for the run lifetime: commands are few and compact.
    commands: HashMap<CommandKey, Entry>,
    slot: Option<PauseSlot<T>>,
    /// The single non-cancel mutator in flight.
    mutator: Option<CommandSequence>,
    canceller: Option<CommandSequence>,
    /// Every capture of this run, retained for the run lifetime.
    captures: HashMap<Uuid, CaptureRecord<C>>,
    /// The capture whose accepted RAM is the current native baseline.
    baseline_owner: Option<Uuid>,
    /// Source-baseline pin of a released accepted capture.
    baseline_pin: Option<(Uuid, File)>,
    /// Advanced by every command admission and completion and by every
    /// applied native status observation. A status observed outside the
    /// lock applies only at the revision it was taken from.
    revision: u64,
}

impl<T, C> Default for Journal<T, C> {
    fn default() -> Self {
        Self {
            last_sequence: 0,
            last_native: 0,
            commands: HashMap::new(),
            slot: None,
            mutator: None,
            canceller: None,
            captures: HashMap::new(),
            baseline_owner: None,
            baseline_pin: None,
            revision: 0,
        }
    }
}

impl<T, C> Journal<T, C> {
    fn unresolved_capture(&self) -> bool {
        self.captures
            .values()
            .any(|record| !record.progress.resolved())
    }

    /// An unresolved capture borrowing the published pause of `operation`.
    fn borrowed_by_capture(&self, operation: Uuid) -> bool {
        self.captures.values().any(|record| {
            !record.progress.resolved()
                && record.origin == CapturePauseOrigin::Borrowed { operation }
        })
    }

    /// Retain one admitted command; admission changes the journal revision.
    fn admit_command(&mut self, key: CommandKey, entry: Entry) {
        self.commands.insert(key, entry);
        self.advance();
    }

    /// Record a command's terminal outcome and free its mutator or canceller
    /// slot; completion changes the journal revision.
    fn complete_command(
        &mut self,
        key: CommandKey,
        sequence: CommandSequence,
        outcome: &CommandOutcome,
    ) {
        if let Some(entry) = self.commands.get_mut(&key) {
            entry.state = CommandState::Completed {
                outcome: outcome.clone(),
            };
        }
        if self.mutator == Some(sequence) {
            self.mutator = None;
        }
        if self.canceller == Some(sequence) {
            self.canceller = None;
        }
        self.advance();
    }

    fn advance(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /// The revision at which `capture` awaits native work with no mutator in
    /// flight: the only state a native status observation may refresh.
    fn pending_revision(&self, capture: Uuid) -> Option<u64> {
        let pending = self.mutator.is_none()
            && self.captures.get(&capture).is_some_and(|record| {
                matches!(
                    record.progress,
                    CaptureProgress::ExecutionPending | CaptureProgress::MemoryPending
                )
            });
        pending.then_some(self.revision)
    }

    /// Apply a status observed outside the lock only if the journal is still
    /// at the observed pending revision. A command that admitted, completed
    /// or resolved the capture in between (abandon, release, a concurrent
    /// refresh) makes the old observation stale: it is dropped, never
    /// allowed to regress a resolved record.
    fn apply_observed(
        &mut self,
        capture: Uuid,
        revision: u64,
        status: NativeCaptureStatus<C>,
    ) -> bool {
        if self.pending_revision(capture) != Some(revision) {
            return false;
        }
        let Some(record) = self.captures.get_mut(&capture) else {
            return false;
        };
        apply_status(record, status);
        self.advance();
        true
    }
}

struct Entry {
    sequence: CommandSequence,
    command: LifecycleCommand,
    state: CommandState,
}

/// The run's current (or last) native pause and its public operation.
struct PauseSlot<T> {
    operation: Uuid,
    native: NativeOperation,
    /// Resume policy of a capture-owned pause; `None` for a User pause.
    capture: Option<CaptureResumePolicy>,
    phase: PausePhase<T>,
}

enum PausePhase<T> {
    /// Native pause submitted; `cancel` once CancelPause was admitted first.
    Pending {
        cancel: bool,
    },
    /// Native failed Pausing (or uncertain); rollback required.
    Failed,
    /// Never took native effect; native stayed Running.
    NoEffect,
    /// Native control is fenced; only stop can proceed.
    Fenced,
    Paused {
        token: T,
        generation: NativePauseGeneration,
        published: bool,
    },
    /// A Resume, CancelPause or Preserve is consuming the token.
    Releasing,
    Consumed {
        generation: NativePauseGeneration,
        by_resume: bool,
    },
    RolledBack,
}

impl<T> PausePhase<T> {
    fn settled_running(&self) -> bool {
        matches!(
            self,
            Self::NoEffect | Self::RolledBack | Self::Consumed { .. }
        )
    }
}

/// The worker's whole retained view of one capture.
struct CaptureRecord<C> {
    preparation: CapturePreparation,
    origin: CapturePauseOrigin,
    progress: CaptureProgress,
    outputs: PreparedOutputs,
    holders: CaptureOutputHolders,
    pin: Option<File>,
    pin_holder: PinHolder,
    cut: Option<NativePause>,
    flushed: bool,
    binding: Option<CaptureStateBinding>,
    ticket: Option<C>,
    execution: Option<(OutputReceipt, OutputReceipt)>,
    memory: Option<MemoryCapture>,
    accepted: bool,
}

#[derive(Default)]
struct PreparedOutputs {
    execution: Option<File>,
    devices: Option<File>,
    ram: Option<File>,
    layout: Option<File>,
}

impl<C> CaptureRecord<C> {
    /// Drop every prepared writer the worker still holds.
    fn close_prepared(&mut self) {
        self.outputs = PreparedOutputs::default();
        for holder in [
            &mut self.holders.execution,
            &mut self.holders.devices,
            &mut self.holders.ram,
            &mut self.holders.layout,
        ] {
            if *holder == OutputHolder::Prepared {
                *holder = OutputHolder::Closed;
            }
        }
    }

    fn fail(&mut self, stage: CaptureStage, failure: &NativeFailure) -> CommandOutcome {
        self.progress = CaptureProgress::Failed {
            stage,
            failure: failure.clone(),
        };
        CommandOutcome::CaptureFailed {
            stage,
            failure: failure.clone(),
        }
    }
}

/// Native outcome of the pause call, classified against native control.
enum PauseResult<T> {
    Token(T),
    Failed(NativeFailure),
    NoEffect(NativeFailure),
    Fenced(NativeFailure),
}

struct ConsumeFailure {
    stage: ResumeStage,
    failure: NativeFailure,
    retained: bool,
}

enum Mutation {
    Pause {
        operation: Uuid,
        purpose: PausePurpose,
        timeout: Duration,
        clock_profile: Option<ObservedClockProfile>,
    },
    Resume {
        operation: Uuid,
        generation: NativePauseGeneration,
        timeout: Duration,
    },
    Cancel {
        operation: Uuid,
        timeout: Duration,
    },
}

enum Admitted<T, C> {
    Run(Admission<T, C>),
    /// Settled at admission without native work.
    Settled(CommandOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observe {
    Native,
    /// Observation capacity is exhausted: answer without a native call.
    Saturated,
}

enum Admission<T, C> {
    Pause {
        owner: NativePauseOwner,
        native: NativeOperation,
        profile_operation: NativeOperation,
        clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    },
    Resume {
        token: T,
        generation: NativePauseGeneration,
        deadline: Instant,
    },
    Cancel {
        start: CancelStart<T>,
        deadline: Instant,
    },
    Flush {
        capture: Uuid,
        token: T,
        deadline: Instant,
    },
    Execution {
        capture: Uuid,
        token: T,
        generation: NativePauseGeneration,
        digests: CaptureDigests,
        execution: File,
        devices: File,
        deadline: Instant,
    },
    Memory {
        capture: Uuid,
        ticket: C,
        ram: File,
        layout: File,
        deadline: Instant,
    },
    Accept {
        capture: Uuid,
        ticket: C,
        binding: CaptureStateBinding,
        ram: File,
        layout: File,
        stream: Digest32,
        deadline: Instant,
    },
    Abandon {
        capture: Uuid,
        ticket: C,
        deadline: Instant,
    },
    Preserve {
        token: T,
        generation: NativePauseGeneration,
        deadline: Instant,
    },
    Release {
        capture: Uuid,
        native: bool,
        deadline: Instant,
    },
}

enum CancelStart<T> {
    Pending {
        pause: NativeOperation,
    },
    Failed {
        pause: NativeOperation,
    },
    Paused {
        token: T,
        generation: NativePauseGeneration,
    },
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<N: NativeLifecycle> Shared<N> {
    fn fatal(&self, reason: &str) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            (self.on_fatal)(reason);
        }
    }

    fn send(&self, frame: &WorkerFrame) -> bool {
        let result =
            lifecycle_wire::encode(frame).and_then(|bytes| lock(&self.writer).write_all(&bytes));
        match result {
            Ok(()) => true,
            Err(error) => {
                self.fatal(&format!("lifecycle write failed: {error}"));
                false
            }
        }
    }

    fn read_loop(self: &Arc<Self>, socket: &UnixStream) -> std::io::Result<()> {
        loop {
            if self.failed.load(Ordering::Acquire) {
                return Ok(());
            }
            match lifecycle_wire::read_parent_frame(socket.as_fd(), FRAME_TIMEOUT)? {
                Some((frame, rights)) => self.dispatch(frame, rights)?,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "lifecycle endpoint closed by the monitor",
                    ))
                }
            }
        }
    }

    fn dispatch(
        self: &Arc<Self>,
        frame: ParentFrame,
        rights: LifecycleRights,
    ) -> std::io::Result<()> {
        let ParentFrame::Command {
            sequence,
            request_id,
            command,
        } = frame;
        {
            let mut journal = lock(&self.journal);
            if sequence.get() <= journal.last_sequence {
                return Err(crate::krun::worker::wire::invalid(
                    "lifecycle command sequence was reused or reordered",
                ));
            }
            journal.last_sequence = sequence.get();
        }
        let request = LifecycleRequest {
            machine_id: self.binding.machine_id,
            run_id: self.binding.run_id,
            request_id,
            command,
        };
        if let Err(rejection) = request.validate() {
            self.reject(sequence, rejection);
            return Ok(());
        }
        let command = request.command;
        let (kind, operation, mutation) = match command.clone() {
            LifecycleCommand::GetControl { target } => {
                self.observe(sequence, target);
                return Ok(());
            }
            LifecycleCommand::GetCapture { operation } => {
                self.observe_capture(sequence, operation);
                return Ok(());
            }
            LifecycleCommand::Pause {
                operation,
                purpose,
                timeout,
                clock_profile,
            } => (
                CommandKind::Pause,
                operation,
                Mutation::Pause {
                    operation,
                    purpose,
                    timeout,
                    clock_profile,
                },
            ),
            LifecycleCommand::Resume {
                operation,
                generation,
                timeout,
            } => (
                CommandKind::Resume,
                operation,
                Mutation::Resume {
                    operation,
                    generation,
                    timeout,
                },
            ),
            LifecycleCommand::CancelPause { operation, timeout } => (
                CommandKind::CancelPause,
                operation,
                Mutation::Cancel { operation, timeout },
            ),
            capture => {
                let (Some(kind), Some(operation)) = (capture.kind(), capture.operation()) else {
                    return Err(crate::krun::worker::wire::invalid(
                        "lifecycle capture command without identity",
                    ));
                };
                let key = CommandKey { request_id, kind };
                let admitted = self.admit_capture(sequence, key, capture, rights);
                self.start(sequence, key, operation, admitted);
                return Ok(());
            }
        };
        let key = CommandKey { request_id, kind };
        let admitted = self.admit(sequence, key, command, mutation);
        self.start(sequence, key, operation, admitted);
        Ok(())
    }

    fn start(
        self: &Arc<Self>,
        sequence: CommandSequence,
        key: CommandKey,
        operation: Uuid,
        admitted: Result<Admitted<N::Token, N::Capture>, LifecycleRejection>,
    ) {
        match admitted {
            Ok(Admitted::Run(admission)) => self.spawn_mutator(sequence, key, operation, admission),
            Ok(Admitted::Settled(outcome)) => self.spawn_light(move |shared, observe| {
                let control = shared.control(observe);
                shared.send(&WorkerFrame::Report {
                    report: CommandReport {
                        key,
                        sequence,
                        operation,
                        state: CommandState::Completed { outcome },
                    },
                    control,
                });
            }),
            Err(rejection) => self.reject(sequence, rejection),
        }
    }

    /// Admission is serialized here; no native call happens under this lock.
    fn admit(
        &self,
        sequence: CommandSequence,
        key: CommandKey,
        command: LifecycleCommand,
        mutation: Mutation,
    ) -> Result<Admitted<N::Token, N::Capture>, LifecycleRejection> {
        let mut journal = lock(&self.journal);
        if journal.commands.contains_key(&key) {
            // The backend joins identical retries; a repeated key is a conflict.
            return Err(LifecycleRejection::RequestConflict);
        }
        let now = Instant::now();
        let admitted = match mutation {
            Mutation::Pause {
                operation,
                purpose,
                timeout,
                clock_profile,
            } => {
                if journal.mutator.is_some() || journal.canceller.is_some() {
                    return Err(LifecycleRejection::Busy);
                }
                let mut capture = None;
                match (&journal.slot, purpose) {
                    (_, PausePurpose::Initial) if journal.unresolved_capture() => {
                        return Err(LifecycleRejection::CaptureActive)
                    }
                    (None, PausePurpose::Initial) => {}
                    (Some(slot), PausePurpose::Initial) if slot.phase.settled_running() => {}
                    (Some(_), PausePurpose::Initial) => {
                        return Err(LifecycleRejection::PauseActive)
                    }
                    (slot, PausePurpose::Capture) => {
                        let record = journal
                            .captures
                            .get(&operation)
                            .ok_or(LifecycleRejection::UnknownCapture)?;
                        if record.origin != CapturePauseOrigin::Acquired
                            || record.progress != CaptureProgress::Prepared
                        {
                            return Err(LifecycleRejection::CaptureStage);
                        }
                        if slot
                            .as_ref()
                            .is_some_and(|slot| !slot.phase.settled_running())
                        {
                            return Err(LifecycleRejection::PauseActive);
                        }
                        capture = Some(record.preparation.resume_policy);
                    }
                    (Some(slot), PausePurpose::Recovery { consumed }) => match slot.phase {
                        PausePhase::Consumed {
                            generation,
                            by_resume: true,
                        } if slot.operation == operation && generation == consumed => {}
                        PausePhase::Consumed { .. } if slot.operation == operation => {
                            return Err(LifecycleRejection::StaleGeneration)
                        }
                        _ if slot.phase.settled_running() => {
                            return Err(LifecycleRejection::NoCurrentPause)
                        }
                        _ => return Err(LifecycleRejection::PauseActive),
                    },
                    (None, PausePurpose::Recovery { .. }) => {
                        return Err(LifecycleRejection::NoCurrentPause)
                    }
                }
                let profile_operation = next_native(&mut journal)?;
                let native = next_native(&mut journal)?;
                journal.slot = Some(PauseSlot {
                    operation,
                    native,
                    capture,
                    phase: PausePhase::Pending { cancel: false },
                });
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Pause {
                    owner: if capture.is_some() {
                        NativePauseOwner::Capture
                    } else {
                        NativePauseOwner::User
                    },
                    native,
                    profile_operation,
                    clock_profile,
                    deadline: now + timeout,
                })
            }
            Mutation::Resume {
                operation,
                generation,
                timeout,
            } => {
                if journal.mutator.is_some() || journal.canceller.is_some() {
                    return Err(LifecycleRejection::Busy);
                }
                if journal.borrowed_by_capture(operation) {
                    return Err(LifecycleRejection::CaptureActive);
                }
                let slot = journal
                    .slot
                    .as_mut()
                    .filter(|slot| slot.operation == operation)
                    .ok_or(LifecycleRejection::NoCurrentPause)?;
                if slot.capture.is_some() {
                    return Err(LifecycleRejection::CaptureOwned);
                }
                let token = match &slot.phase {
                    PausePhase::Paused {
                        token,
                        generation: current,
                        published: true,
                    } if *current == generation => token.clone(),
                    PausePhase::Paused {
                        published: true, ..
                    }
                    | PausePhase::Consumed { .. } => {
                        return Err(LifecycleRejection::StaleGeneration)
                    }
                    _ => return Err(LifecycleRejection::NoCurrentPause),
                };
                slot.phase = PausePhase::Releasing;
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Resume {
                    token,
                    generation,
                    deadline: now + timeout,
                })
            }
            Mutation::Cancel { operation, timeout } => {
                if journal.canceller.is_some() {
                    return Err(LifecycleRejection::Busy);
                }
                let slot = journal
                    .slot
                    .as_mut()
                    .filter(|slot| slot.operation == operation)
                    .ok_or(LifecycleRejection::NoCurrentPause)?;
                let start = match &mut slot.phase {
                    PausePhase::Pending { cancel } => {
                        *cancel = true;
                        Some(CancelStart::Pending { pause: slot.native })
                    }
                    // Never cancels an active Resume or an already settled pause.
                    PausePhase::Fenced
                    | PausePhase::Releasing
                    | PausePhase::Consumed { .. }
                    | PausePhase::RolledBack => return Err(LifecycleRejection::NotCancellable),
                    // A settled phase with the mutator still recorded is only the
                    // pause finishing its report: cancellation linearizes after it.
                    PausePhase::Failed => Some(CancelStart::Failed { pause: slot.native }),
                    PausePhase::NoEffect => None,
                    // A published capture pause is settled by its capture
                    // (AbandonCapture + ContinueCapture), never by cancellation.
                    PausePhase::Paused {
                        published: true, ..
                    } if slot.capture.is_some() => return Err(LifecycleRejection::NotCancellable),
                    PausePhase::Paused {
                        token, generation, ..
                    } => {
                        let start = CancelStart::Paused {
                            token: token.clone(),
                            generation: *generation,
                        };
                        slot.phase = PausePhase::Releasing;
                        Some(start)
                    }
                };
                let Some(start) = start else {
                    let outcome = CommandOutcome::CancelSettled {
                        settlement: CancelSettlement::NoNativeEffect,
                    };
                    journal.admit_command(
                        key,
                        Entry {
                            sequence,
                            command,
                            state: CommandState::Completed {
                                outcome: outcome.clone(),
                            },
                        },
                    );
                    return Ok(Admitted::Settled(outcome));
                };
                journal.canceller = Some(sequence);
                Admitted::Run(Admission::Cancel {
                    start,
                    deadline: now + timeout,
                })
            }
        };
        journal.admit_command(
            key,
            Entry {
                sequence,
                command,
                state: CommandState::Accepted,
            },
        );
        Ok(admitted)
    }

    /// Capture stage admission; serialized with every other mutator.
    fn admit_capture(
        &self,
        sequence: CommandSequence,
        key: CommandKey,
        command: LifecycleCommand,
        rights: LifecycleRights,
    ) -> Result<Admitted<N::Token, N::Capture>, LifecycleRejection> {
        let mut journal = lock(&self.journal);
        if journal.commands.contains_key(&key) {
            return Err(LifecycleRejection::RequestConflict);
        }
        if journal.mutator.is_some() || journal.canceller.is_some() {
            return Err(LifecycleRejection::Busy);
        }
        let now = Instant::now();
        let admitted = match (&command, rights) {
            (
                LifecycleCommand::PrepareCapture {
                    operation,
                    preparation,
                    ..
                },
                LifecycleRights::CaptureOutputs(files),
            ) => {
                if journal.captures.contains_key(operation) {
                    return Err(LifecycleRejection::RequestConflict);
                }
                if journal.unresolved_capture() {
                    return Err(LifecycleRejection::CaptureActive);
                }
                let (origin, cut) = match preparation.pause {
                    CapturePauseSource::Acquire => {
                        if journal
                            .slot
                            .as_ref()
                            .is_some_and(|slot| !slot.phase.settled_running())
                        {
                            return Err(LifecycleRejection::PauseActive);
                        }
                        (CapturePauseOrigin::Acquired, None)
                    }
                    CapturePauseSource::Borrow {
                        operation: pause,
                        generation,
                    } => {
                        let slot = journal
                            .slot
                            .as_ref()
                            .filter(|slot| slot.operation == pause && slot.capture.is_none())
                            .ok_or(LifecycleRejection::NoCurrentPause)?;
                        match &slot.phase {
                            PausePhase::Paused {
                                token,
                                generation: current,
                                published: true,
                            } if *current == generation
                                && self.native.token_owner(token) == NativePauseOwner::User => {}
                            PausePhase::Paused {
                                published: true, ..
                            } => return Err(LifecycleRejection::StaleGeneration),
                            _ => return Err(LifecycleRejection::NoCurrentPause),
                        }
                        (
                            CapturePauseOrigin::Borrowed { operation: pause },
                            Some(NativePause {
                                generation,
                                owner: NativePauseOwner::User,
                            }),
                        )
                    }
                };
                let mut excluded = self.native.protected_identities();
                for record in journal.captures.values() {
                    excluded.extend(record.preparation.outputs.roles().map(|(_, id)| id));
                }
                validate_outputs(&files, preparation, &excluded)
                    .map_err(LifecycleRejection::CaptureOutputs)?;
                journal.captures.insert(
                    *operation,
                    CaptureRecord {
                        preparation: preparation.clone(),
                        origin,
                        progress: CaptureProgress::Prepared,
                        outputs: PreparedOutputs {
                            execution: Some(files.execution),
                            devices: Some(files.devices),
                            ram: Some(files.ram),
                            layout: Some(files.layout),
                        },
                        holders: CaptureOutputHolders {
                            execution: OutputHolder::Prepared,
                            devices: OutputHolder::Prepared,
                            ram: OutputHolder::Prepared,
                            layout: OutputHolder::Prepared,
                        },
                        pin: Some(files.pin),
                        pin_holder: PinHolder::Capture,
                        cut,
                        flushed: false,
                        binding: None,
                        ticket: None,
                        execution: None,
                        memory: None,
                        accepted: false,
                    },
                );
                Admitted::Settled(CommandOutcome::CapturePrepared {
                    outputs: preparation.outputs,
                    pin: preparation.pin,
                })
            }
            (LifecycleCommand::FlushCapture { operation, timeout }, LifecycleRights::None) => {
                let record = capture_record(&journal, *operation)?;
                let ready = match record.origin {
                    CapturePauseOrigin::Acquired => record.progress == CaptureProgress::Paused,
                    CapturePauseOrigin::Borrowed { .. } => {
                        record.progress == CaptureProgress::Prepared
                    }
                };
                if !ready {
                    return Err(LifecycleRejection::CaptureStage);
                }
                let (token, _) = self.capture_token(&journal, *operation)?;
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Flush {
                    capture: *operation,
                    token,
                    deadline: now + *timeout,
                })
            }
            (LifecycleCommand::CaptureExecution { operation, timeout }, LifecycleRights::None) => {
                if capture_record(&journal, *operation)?.progress != CaptureProgress::Flushed {
                    return Err(LifecycleRejection::CaptureStage);
                }
                let (token, generation) = self.capture_token(&journal, *operation)?;
                let record = capture_record_mut(&mut journal, *operation)?;
                let (Some(execution), Some(devices)) = (
                    record.outputs.execution.take(),
                    record.outputs.devices.take(),
                ) else {
                    return Err(LifecycleRejection::CaptureStage);
                };
                record.holders.execution = OutputHolder::Native;
                record.holders.devices = OutputHolder::Native;
                record.progress = CaptureProgress::ExecutionPending;
                let digests = record.preparation.binding;
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Execution {
                    capture: *operation,
                    token,
                    generation,
                    digests,
                    execution,
                    devices,
                    deadline: now + *timeout,
                })
            }
            (LifecycleCommand::CaptureMemory { operation, timeout }, LifecycleRights::None) => {
                let record = capture_record_mut(&mut journal, *operation)?;
                let ticket = match (&record.progress, &record.ticket) {
                    (CaptureProgress::ExecutionCaptured, Some(ticket)) => ticket.clone(),
                    _ => return Err(LifecycleRejection::CaptureStage),
                };
                let (Some(ram), Some(layout)) =
                    (record.outputs.ram.take(), record.outputs.layout.take())
                else {
                    return Err(LifecycleRejection::CaptureStage);
                };
                record.holders.ram = OutputHolder::Native;
                record.holders.layout = OutputHolder::Native;
                record.progress = CaptureProgress::MemoryPending;
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Memory {
                    capture: *operation,
                    ticket,
                    ram,
                    layout,
                    deadline: now + *timeout,
                })
            }
            (
                LifecycleCommand::AcceptCapture {
                    operation,
                    ram: ram_identity,
                    layout: layout_identity,
                    stream,
                    timeout,
                },
                LifecycleRights::SealedMemory(files),
            ) => {
                let record = capture_record(&journal, *operation)?;
                let (ticket, memory, binding) = match (
                    &record.progress,
                    &record.ticket,
                    &record.memory,
                    &record.binding,
                ) {
                    (
                        CaptureProgress::CandidateComplete,
                        Some(ticket),
                        Some(memory),
                        Some(binding),
                    ) => (ticket.clone(), memory, binding.clone()),
                    _ => return Err(LifecycleRejection::CaptureStage),
                };
                for (role, declared, receipt) in [
                    (OutputRole::Ram, *ram_identity, memory.ram),
                    (OutputRole::Layout, *layout_identity, memory.layout),
                ] {
                    if declared != receipt.identity() {
                        return Err(LifecycleRejection::CaptureOutputs(OutputProblem {
                            role,
                            problem: OutputDefect::Identity,
                        }));
                    }
                }
                validate_sealed(&files.ram, OutputRole::Ram, memory.ram)
                    .and_then(|()| {
                        validate_sealed(&files.layout, OutputRole::Layout, memory.layout)
                    })
                    .map_err(LifecycleRejection::CaptureOutputs)?;
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Accept {
                    capture: *operation,
                    ticket,
                    binding,
                    ram: files.ram,
                    layout: files.layout,
                    stream: *stream,
                    deadline: now + *timeout,
                })
            }
            (LifecycleCommand::AbandonCapture { operation, timeout }, LifecycleRights::None) => {
                let record = capture_record_mut(&mut journal, *operation)?;
                match (record.progress.clone(), record.ticket.clone()) {
                    (CaptureProgress::Abandoned, _) => {
                        Admitted::Settled(CommandOutcome::CaptureAbandoned)
                    }
                    (CaptureProgress::Accepted | CaptureProgress::Released, _) => {
                        return Err(LifecycleRejection::CaptureStage)
                    }
                    // Pending native work without a ticket is only possible
                    // while its stage mutator still runs (Busy above).
                    (CaptureProgress::ExecutionPending | CaptureProgress::MemoryPending, None) => {
                        return Err(LifecycleRejection::CapturePending)
                    }
                    (_, None) => {
                        // Native never registered this capture: no native owner.
                        record.close_prepared();
                        record.progress = CaptureProgress::Abandoned;
                        Admitted::Settled(CommandOutcome::CaptureAbandoned)
                    }
                    (_, Some(ticket)) => {
                        journal.mutator = Some(sequence);
                        Admitted::Run(Admission::Abandon {
                            capture: *operation,
                            ticket,
                            deadline: now + *timeout,
                        })
                    }
                }
            }
            (
                LifecycleCommand::ContinueCapture {
                    operation,
                    continuation,
                    timeout,
                },
                LifecycleRights::None,
            ) => {
                let record = capture_record(&journal, *operation)?;
                if !record.progress.resolved() {
                    return Err(LifecycleRejection::CaptureUnresolved);
                }
                let origin = record.origin;
                match (origin, continuation) {
                    (CapturePauseOrigin::Borrowed { .. }, CaptureContinuation::Resume) => {
                        return Err(LifecycleRejection::BorrowedPause)
                    }
                    (
                        CapturePauseOrigin::Borrowed { operation: pause },
                        CaptureContinuation::Preserve,
                    ) => {
                        // The borrowed User pause stays exactly as it is.
                        let current = journal
                            .slot
                            .as_ref()
                            .filter(|slot| slot.operation == pause && slot.capture.is_none())
                            .and_then(|slot| match &slot.phase {
                                PausePhase::Paused {
                                    token,
                                    generation,
                                    published: true,
                                } => Some(NativePause {
                                    generation: *generation,
                                    owner: self.native.token_owner(token),
                                }),
                                _ => None,
                            })
                            .ok_or(LifecycleRejection::NoCurrentPause)?;
                        Admitted::Settled(CommandOutcome::CapturePreserved { pause: current })
                    }
                    (CapturePauseOrigin::Acquired, continuation) => {
                        let slot = journal
                            .slot
                            .as_mut()
                            .filter(|slot| slot.operation == *operation)
                            .ok_or(LifecycleRejection::NoCurrentPause)?;
                        let (token, generation) = match &slot.phase {
                            PausePhase::Paused {
                                token,
                                generation,
                                published: true,
                            } => (token.clone(), *generation),
                            _ => return Err(LifecycleRejection::NoCurrentPause),
                        };
                        if slot.capture.is_none() {
                            // Already transferred to User: report that authority.
                            match continuation {
                                CaptureContinuation::Preserve => {
                                    Admitted::Settled(CommandOutcome::CapturePreserved {
                                        pause: NativePause {
                                            generation,
                                            owner: self.native.token_owner(&token),
                                        },
                                    })
                                }
                                CaptureContinuation::Resume => {
                                    return Err(LifecycleRejection::StaleGeneration)
                                }
                            }
                        } else {
                            slot.phase = PausePhase::Releasing;
                            journal.mutator = Some(sequence);
                            let deadline = now + *timeout;
                            Admitted::Run(match continuation {
                                CaptureContinuation::Resume => Admission::Resume {
                                    token,
                                    generation,
                                    deadline,
                                },
                                CaptureContinuation::Preserve => Admission::Preserve {
                                    token,
                                    generation,
                                    deadline,
                                },
                            })
                        }
                    }
                }
            }
            (LifecycleCommand::ReleaseCapture { operation, timeout }, LifecycleRights::None) => {
                let record = capture_record(&journal, *operation)?;
                let (progress, native, retained) = (
                    record.progress.clone(),
                    record.ticket.is_some(),
                    record.pin_holder == PinHolder::Baseline,
                );
                match progress {
                    CaptureProgress::Released => {
                        Admitted::Settled(CommandOutcome::CaptureReleased {
                            baseline_retained: retained,
                        })
                    }
                    CaptureProgress::Accepted | CaptureProgress::Abandoned => {
                        journal.mutator = Some(sequence);
                        Admitted::Run(Admission::Release {
                            capture: *operation,
                            native,
                            deadline: now + *timeout,
                        })
                    }
                    _ => return Err(LifecycleRejection::CaptureUnresolved),
                }
            }
            // The reader already matched the descriptor kind to the command.
            _ => {
                return Err(LifecycleRejection::InvalidRequest(
                    crate::virt::lifecycle::InvalidRequest::CaptureRights,
                ))
            }
        };
        let state = match &admitted {
            Admitted::Settled(outcome) => CommandState::Completed {
                outcome: outcome.clone(),
            },
            Admitted::Run(_) => CommandState::Accepted,
        };
        journal.admit_command(
            key,
            Entry {
                sequence,
                command,
                state,
            },
        );
        Ok(admitted)
    }

    /// The exact pause a capture stage runs under.
    fn capture_token(
        &self,
        journal: &Journal<N::Token, N::Capture>,
        capture: Uuid,
    ) -> Result<(N::Token, NativePauseGeneration), LifecycleRejection> {
        let record = capture_record(journal, capture)?;
        let (operation, capture_owned) = match record.origin {
            CapturePauseOrigin::Acquired => (capture, true),
            CapturePauseOrigin::Borrowed { operation } => (operation, false),
        };
        let slot = journal
            .slot
            .as_ref()
            .filter(|slot| slot.operation == operation && slot.capture.is_some() == capture_owned)
            .ok_or(LifecycleRejection::NoCurrentPause)?;
        match &slot.phase {
            PausePhase::Paused {
                token,
                generation,
                published: true,
            } if record.cut.is_some_and(|cut| cut.generation == *generation) => {
                Ok((token.clone(), *generation))
            }
            PausePhase::Paused { .. } => Err(LifecycleRejection::StaleGeneration),
            _ => Err(LifecycleRejection::NoCurrentPause),
        }
    }

    fn spawn_mutator(
        self: &Arc<Self>,
        sequence: CommandSequence,
        key: CommandKey,
        operation: Uuid,
        admission: Admission<N::Token, N::Capture>,
    ) {
        let shared = self.clone();
        let spawned = std::thread::Builder::new()
            .name("krun-lifecycle-command".to_string())
            .spawn(move || {
                let control = shared.control(Observe::Native);
                shared.send(&WorkerFrame::Report {
                    report: CommandReport {
                        key,
                        sequence,
                        operation,
                        state: CommandState::Accepted,
                    },
                    control,
                });
                let outcome = match admission {
                    Admission::Pause {
                        owner,
                        native,
                        profile_operation,
                        clock_profile,
                        deadline,
                    } => {
                        shared.run_pause(owner, native, profile_operation, clock_profile, deadline)
                    }
                    Admission::Resume {
                        token,
                        generation,
                        deadline,
                    } => shared.run_resume(token, generation, deadline),
                    Admission::Cancel { start, deadline } => shared.run_cancel(start, deadline),
                    Admission::Flush {
                        capture,
                        token,
                        deadline,
                    } => shared.run_flush(capture, token, deadline),
                    Admission::Execution {
                        capture,
                        token,
                        generation,
                        digests,
                        execution,
                        devices,
                        deadline,
                    } => shared.run_execution(
                        capture, token, generation, digests, execution, devices, deadline,
                    ),
                    Admission::Memory {
                        capture,
                        ticket,
                        ram,
                        layout,
                        deadline,
                    } => shared.run_memory(capture, ticket, ram, layout, deadline),
                    Admission::Accept {
                        capture,
                        ticket,
                        binding,
                        ram,
                        layout,
                        stream,
                        deadline,
                    } => shared.run_accept(capture, ticket, binding, ram, layout, stream, deadline),
                    Admission::Abandon {
                        capture,
                        ticket,
                        deadline,
                    } => shared.run_abandon(capture, ticket, deadline),
                    Admission::Preserve {
                        token,
                        generation,
                        deadline,
                    } => shared.run_preserve(token, generation, deadline),
                    Admission::Release {
                        capture,
                        native,
                        deadline,
                    } => shared.run_release(capture, native, deadline),
                };
                shared.complete(key, sequence, operation, outcome);
            });
        if let Err(error) = spawned {
            // Admitted work that cannot run would leave retained ownership state
            // lying. Losing control is terminal, never an implicit resume.
            self.fatal(&format!("cannot start lifecycle command: {error}"));
        }
    }

    fn complete(
        &self,
        key: CommandKey,
        sequence: CommandSequence,
        operation: Uuid,
        outcome: CommandOutcome,
    ) {
        lock(&self.journal).complete_command(key, sequence, &outcome);
        self.settled.notify_all();
        let control = self.control(Observe::Native);
        self.send(&WorkerFrame::Report {
            report: CommandReport {
                key,
                sequence,
                operation,
                state: CommandState::Completed { outcome },
            },
            control,
        });
    }

    fn reject(self: &Arc<Self>, sequence: CommandSequence, rejection: LifecycleRejection) {
        self.spawn_light(move |shared, observe| {
            let control = shared.control(observe);
            shared.send(&WorkerFrame::Rejected {
                sequence,
                rejection,
                control,
            });
        });
    }

    fn observe(self: &Arc<Self>, sequence: CommandSequence, target: Option<CommandKey>) {
        let report = match target {
            None => None,
            Some(key) => {
                let journal = lock(&self.journal);
                let Some(entry) = journal.commands.get(&key) else {
                    drop(journal);
                    self.reject(sequence, LifecycleRejection::UnknownTarget);
                    return;
                };
                Some(CommandReport {
                    key,
                    sequence: entry.sequence,
                    operation: entry.command.operation().unwrap_or_default(),
                    state: entry.state.clone(),
                })
            }
        };
        self.spawn_light(move |shared, observe| {
            let control = shared.control(observe);
            let inventory = match observe {
                Observe::Native => shared.native.inventory(Instant::now() + OBSERVATION_BUDGET),
                Observe::Saturated => InventoryObservation::Unavailable {
                    failure: saturated(),
                },
            };
            shared.send(&WorkerFrame::Control {
                sequence,
                target: report,
                control,
                inventory,
            });
        });
    }

    /// Report one capture. A pending native stage is refreshed from native
    /// status first, unless another mutator owns the capture right now.
    fn observe_capture(self: &Arc<Self>, sequence: CommandSequence, operation: Uuid) {
        if !lock(&self.journal).captures.contains_key(&operation) {
            self.reject(sequence, LifecycleRejection::UnknownCapture);
            return;
        }
        self.spawn_light(move |shared, observe| {
            if observe == Observe::Native {
                shared.refresh_pending(operation);
            }
            let capture = {
                let journal = lock(&shared.journal);
                journal
                    .captures
                    .get(&operation)
                    .map(|record| shared.observation(&journal, operation, record))
            };
            let control = shared.control(observe);
            match capture {
                Some(capture) => {
                    shared.send(&WorkerFrame::Capture {
                        sequence,
                        capture,
                        control,
                    });
                }
                None => {
                    shared.send(&WorkerFrame::Rejected {
                        sequence,
                        rejection: LifecycleRejection::UnknownCapture,
                        control,
                    });
                }
            }
        });
    }

    /// Refresh a pending capture from native status. The query runs outside
    /// the journal lock, so its result applies only if the journal is still
    /// at the revision observed before it.
    fn refresh_pending(&self, operation: Uuid) {
        let Some(revision) = lock(&self.journal).pending_revision(operation) else {
            return;
        };
        let Ok(status) = self
            .native
            .capture_status(operation, Instant::now() + OBSERVATION_BUDGET)
        else {
            return;
        };
        if !lock(&self.journal).apply_observed(operation, revision, status) {
            tracing::debug!(%operation, "discarded a stale native capture observation");
        }
    }

    fn observation(
        &self,
        journal: &Journal<N::Token, N::Capture>,
        operation: Uuid,
        record: &CaptureRecord<N::Capture>,
    ) -> CaptureObservation {
        let pause_operation = match record.origin {
            CapturePauseOrigin::Acquired => operation,
            CapturePauseOrigin::Borrowed { operation } => operation,
        };
        let current = journal
            .slot
            .as_ref()
            .filter(|slot| slot.operation == pause_operation)
            .and_then(|slot| match &slot.phase {
                PausePhase::Paused {
                    token, generation, ..
                } => Some(NativePause {
                    generation: *generation,
                    owner: self.native.token_owner(token),
                }),
                _ => None,
            });
        let holders = record.holders;
        let memory_sealed = record.memory.as_ref().is_some_and(|memory| {
            memory.writers_closed
                && holders.ram == OutputHolder::Closed
                && holders.layout == OutputHolder::Closed
        }) && matches!(
            record.progress,
            CaptureProgress::CandidateComplete
                | CaptureProgress::Accepted
                | CaptureProgress::Released
        );
        CaptureObservation {
            operation,
            progress: record.progress.clone(),
            pause: CapturePauseObservation {
                origin: record.origin,
                cut: record.cut,
                current,
            },
            outputs: holders,
            pin: record.pin_holder,
            evidence: CaptureNativeEvidence {
                pause_completed: record.cut.is_some(),
                flush_completed: record.flushed,
                execution_sealed: record.execution.is_some()
                    && holders.execution == OutputHolder::Closed
                    && holders.devices == OutputHolder::Closed,
                memory_sealed,
            },
        }
    }

    /// Bounded observation threads. When saturated the reader answers itself
    /// without touching native control, so it never blocks on native work.
    fn spawn_light<F>(self: &Arc<Self>, work: F)
    where
        F: FnOnce(&Shared<N>, Observe) + Send + 'static,
    {
        if self.light.fetch_add(1, Ordering::AcqRel) < MAX_LIGHT_HANDLERS {
            let shared = self.clone();
            let (sender, receiver) = std::sync::mpsc::sync_channel::<F>(1);
            let spawned = std::thread::Builder::new()
                .name("krun-lifecycle-observe".to_string())
                .spawn(move || {
                    if let Ok(work) = receiver.recv() {
                        work(shared.as_ref(), Observe::Native);
                    }
                    shared.light.fetch_sub(1, Ordering::AcqRel);
                });
            match spawned {
                Ok(_) => {
                    if let Err(std::sync::mpsc::SendError(work)) = sender.send(work) {
                        work(self.as_ref(), Observe::Saturated);
                    }
                }
                Err(_) => {
                    self.light.fetch_sub(1, Ordering::AcqRel);
                    work(self.as_ref(), Observe::Saturated);
                }
            }
            return;
        }
        self.light.fetch_sub(1, Ordering::AcqRel);
        work(self.as_ref(), Observe::Saturated);
    }

    fn control(&self, observe: Observe) -> ControlObservation {
        if observe == Observe::Saturated {
            return ControlObservation::Unavailable {
                failure: saturated(),
            };
        }
        match self
            .native
            .control_state(Instant::now() + OBSERVATION_BUDGET)
        {
            Ok(state) => match self.project(state) {
                Some(control) => ControlObservation::Observed { control },
                None => ControlObservation::Unavailable {
                    failure: NativeFailure::with_detail(
                        NativeFailureKind::Unexpected,
                        "native control reported a zero identity",
                    ),
                },
            },
            Err(failure) => ControlObservation::Unavailable { failure },
        }
    }

    fn project(&self, state: NativeState<N::Token>) -> Option<NativeControl> {
        Some(match state {
            NativeState::Running => NativeControl::Running,
            NativeState::Pausing { operation, failed } => NativeControl::Pausing {
                operation: NativeOperation::new(operation)?,
                failed,
            },
            NativeState::Paused(token) => NativeControl::Paused {
                generation: NativePauseGeneration::new(self.native.token_generation(&token))?,
                owner: self.native.token_owner(&token),
            },
            NativeState::Resuming { operation } => NativeControl::Resuming {
                operation: NativeOperation::new(operation)?,
            },
            NativeState::RollingBack { operation } => NativeControl::RollingBack {
                operation: NativeOperation::new(operation)?,
            },
            NativeState::RestorePrepared => NativeControl::RestorePrepared,
            NativeState::FailedFenced => NativeControl::FailedFenced,
            NativeState::Stopping => NativeControl::Stopping,
            NativeState::Stopped => NativeControl::Stopped,
        })
    }

    fn native_operation(&self) -> Result<NativeOperation, NativeFailure> {
        next_native(&mut lock(&self.journal))
            .map_err(|_| NativeFailure::new(NativeFailureKind::Exhausted))
    }

    fn run_pause(
        &self,
        owner: NativePauseOwner,
        native: NativeOperation,
        profile_operation: NativeOperation,
        clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    ) -> CommandOutcome {
        let result =
            match self
                .native
                .pause(owner, native, profile_operation, clock_profile, deadline)
            {
                Ok(token) => PauseResult::Token(token),
                Err(failure) => self.classify_pause_failure(native, failure, deadline),
            };
        let mut journal = lock(&self.journal);
        let Some(slot) = journal.slot.as_mut() else {
            return CommandOutcome::PauseFailed {
                failure: NativeFailure::with_detail(
                    NativeFailureKind::Unexpected,
                    "pause slot disappeared",
                ),
            };
        };
        let cancel = matches!(slot.phase, PausePhase::Pending { cancel: true });
        let (phase, outcome) = match result {
            PauseResult::Token(token) => {
                match NativePauseGeneration::new(self.native.token_generation(&token)) {
                    Some(generation) if self.native.token_owner(&token) == owner => {
                        // Linearization point: publication versus admitted cancel.
                        let outcome = if cancel {
                            CommandOutcome::PauseWithdrawn
                        } else {
                            CommandOutcome::Paused {
                                pause: NativePause { generation, owner },
                            }
                        };
                        (
                            PausePhase::Paused {
                                token,
                                generation,
                                published: !cancel,
                            },
                            outcome,
                        )
                    }
                    Some(_) => (
                        PausePhase::Fenced,
                        CommandOutcome::PauseFailed {
                            failure: NativeFailure::with_detail(
                                NativeFailureKind::Unexpected,
                                "native pause token has a foreign owner",
                            ),
                        },
                    ),
                    None => (
                        PausePhase::Fenced,
                        CommandOutcome::PauseFailed {
                            failure: NativeFailure::with_detail(
                                NativeFailureKind::Unexpected,
                                "native pause token has generation zero",
                            ),
                        },
                    ),
                }
            }
            PauseResult::Failed(failure) => (
                PausePhase::Failed,
                withdrawn_or(cancel, CommandOutcome::PauseFailed { failure }),
            ),
            PauseResult::NoEffect(failure) => (
                PausePhase::NoEffect,
                withdrawn_or(cancel, CommandOutcome::PauseFailed { failure }),
            ),
            PauseResult::Fenced(failure) => {
                (PausePhase::Fenced, CommandOutcome::PauseFailed { failure })
            }
        };
        slot.phase = phase;
        let capture = slot.capture.map(|_| slot.operation);
        if let (Some(capture), CommandOutcome::Paused { pause }) = (capture, &outcome) {
            mark_capture_paused(&mut journal, capture, *pause);
        }
        outcome
    }

    /// Classify a failed or uncertain native pause through actual control
    /// state. A lost reply is reconciled, never treated as no effect.
    fn classify_pause_failure(
        &self,
        native: NativeOperation,
        failure: NativeFailure,
        deadline: Instant,
    ) -> PauseResult<N::Token> {
        let limit = deadline.max(Instant::now()) + RECONCILE_GRACE;
        loop {
            match self
                .native
                .control_state(Instant::now() + OBSERVATION_BUDGET)
            {
                Ok(NativeState::Paused(token)) => return PauseResult::Token(token),
                Ok(NativeState::Pausing {
                    operation,
                    failed: false,
                }) if operation == native.get() && Instant::now() < limit => {}
                Ok(NativeState::Pausing { operation, .. }) if operation == native.get() => {
                    return PauseResult::Failed(failure)
                }
                Ok(NativeState::RollingBack { .. }) => return PauseResult::Failed(failure),
                Ok(NativeState::Running) => return PauseResult::NoEffect(failure),
                Ok(NativeState::FailedFenced | NativeState::Stopping | NativeState::Stopped) => {
                    return PauseResult::Fenced(failure)
                }
                Ok(_) => return PauseResult::Failed(failure),
                Err(_) if Instant::now() < limit => {}
                Err(_) => return PauseResult::Failed(failure),
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
    }

    fn run_resume(
        &self,
        token: N::Token,
        generation: NativePauseGeneration,
        deadline: Instant,
    ) -> CommandOutcome {
        let result = self.consume(token.clone(), generation, deadline);
        let mut journal = lock(&self.journal);
        match result {
            Ok(clock) => {
                set_phase(
                    &mut journal,
                    PausePhase::Consumed {
                        generation,
                        by_resume: true,
                    },
                );
                CommandOutcome::Resumed { clock }
            }
            Err(failure) => {
                set_phase(
                    &mut journal,
                    if failure.retained {
                        PausePhase::Paused {
                            token,
                            generation,
                            published: true,
                        }
                    } else if failure.stage == ResumeStage::ClockAcknowledgement {
                        PausePhase::Consumed {
                            generation,
                            by_resume: true,
                        }
                    } else {
                        PausePhase::Fenced
                    },
                );
                CommandOutcome::ResumeFailed {
                    stage: failure.stage,
                    failure: failure.failure,
                    pause_retained: failure.retained,
                }
            }
        }
    }

    fn run_cancel(&self, start: CancelStart<N::Token>, deadline: Instant) -> CommandOutcome {
        match start {
            CancelStart::Paused { token, generation } => {
                self.settle_completed(token, generation, deadline)
            }
            CancelStart::Failed { pause } => self.cancel_rollback(pause, deadline),
            CancelStart::Pending { pause } => {
                let rollback = self
                    .native_operation()
                    .and_then(|operation| self.native.cancel_pause(pause, operation, deadline));
                // The pause thread classifies its own result first; cancellation
                // decides only after the slot left Pending.
                let mut journal = lock(&self.journal);
                while matches!(
                    journal.slot.as_ref().map(|slot| &slot.phase),
                    Some(PausePhase::Pending { .. })
                ) {
                    journal = self
                        .settled
                        .wait(journal)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                let phase = journal.slot.as_ref().map(|slot| match &slot.phase {
                    PausePhase::Paused {
                        token, generation, ..
                    } => Some((token.clone(), *generation)),
                    _ => None,
                });
                let settled = journal
                    .slot
                    .as_ref()
                    .is_some_and(|slot| matches!(slot.phase, PausePhase::NoEffect));
                let fenced = journal
                    .slot
                    .as_ref()
                    .is_some_and(|slot| matches!(slot.phase, PausePhase::Fenced));
                match (rollback, phase) {
                    (_, Some(Some((token, generation)))) => {
                        set_phase(&mut journal, PausePhase::Releasing);
                        drop(journal);
                        self.settle_completed(token, generation, deadline)
                    }
                    (Ok(()), _) => {
                        set_phase(&mut journal, PausePhase::RolledBack);
                        CommandOutcome::CancelSettled {
                            settlement: CancelSettlement::RolledBack,
                        }
                    }
                    (Err(_), _) if settled => CommandOutcome::CancelSettled {
                        settlement: CancelSettlement::NoNativeEffect,
                    },
                    (Err(failure), _) if fenced => CommandOutcome::CancelFailed {
                        stage: CancelStage::Rollback,
                        failure,
                    },
                    (Err(failure), _) => {
                        drop(journal);
                        self.settle_rollback(failure, deadline)
                    }
                }
            }
        }
    }

    /// A completed but unpublished pause meets an admitted cancellation. A
    /// capture pause under `preserve` is retained for its capture; every other
    /// pause is consumed through the ClockOnly path.
    fn settle_completed(
        &self,
        token: N::Token,
        generation: NativePauseGeneration,
        deadline: Instant,
    ) -> CommandOutcome {
        {
            let mut journal = lock(&self.journal);
            let preserve = journal.slot.as_ref().and_then(|slot| {
                (slot.capture == Some(CaptureResumePolicy::Preserve)).then_some(slot.operation)
            });
            if let Some(capture) = preserve {
                let pause = NativePause {
                    generation,
                    owner: self.native.token_owner(&token),
                };
                set_phase(
                    &mut journal,
                    PausePhase::Paused {
                        token,
                        generation,
                        published: true,
                    },
                );
                mark_capture_paused(&mut journal, capture, pause);
                return CommandOutcome::CancelSettled {
                    settlement: CancelSettlement::RetainedCompletedPause { pause },
                };
            }
        }
        self.cancel_consume(token, generation, deadline)
    }

    fn cancel_rollback(&self, pause: NativeOperation, deadline: Instant) -> CommandOutcome {
        match self
            .native_operation()
            .and_then(|operation| self.native.cancel_pause(pause, operation, deadline))
        {
            Ok(()) => {
                set_phase(&mut lock(&self.journal), PausePhase::RolledBack);
                CommandOutcome::CancelSettled {
                    settlement: CancelSettlement::RolledBack,
                }
            }
            Err(failure) => self.settle_rollback(failure, deadline),
        }
    }

    /// Reconcile an uncertain or failed rollback through native control.
    fn settle_rollback(&self, failure: NativeFailure, deadline: Instant) -> CommandOutcome {
        let limit = deadline.max(Instant::now()) + RECONCILE_GRACE;
        loop {
            match self
                .native
                .control_state(Instant::now() + OBSERVATION_BUDGET)
            {
                Ok(NativeState::Running) => {
                    set_phase(&mut lock(&self.journal), PausePhase::RolledBack);
                    return CommandOutcome::CancelSettled {
                        settlement: CancelSettlement::RolledBack,
                    };
                }
                Ok(NativeState::RollingBack { .. }) | Err(_) if Instant::now() < limit => {}
                Ok(NativeState::FailedFenced | NativeState::Stopping | NativeState::Stopped) => {
                    set_phase(&mut lock(&self.journal), PausePhase::Fenced);
                    return CommandOutcome::CancelFailed {
                        stage: CancelStage::Rollback,
                        failure,
                    };
                }
                _ => {
                    set_phase(&mut lock(&self.journal), PausePhase::Failed);
                    return CommandOutcome::CancelFailed {
                        stage: CancelStage::Rollback,
                        failure,
                    };
                }
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
    }

    fn cancel_consume(
        &self,
        token: N::Token,
        generation: NativePauseGeneration,
        deadline: Instant,
    ) -> CommandOutcome {
        match self.consume(token.clone(), generation, deadline) {
            Ok(clock) => {
                set_phase(
                    &mut lock(&self.journal),
                    PausePhase::Consumed {
                        generation,
                        by_resume: false,
                    },
                );
                CommandOutcome::CancelSettled {
                    settlement: CancelSettlement::ConsumedCompletedPause { clock },
                }
            }
            Err(failure) => {
                set_phase(
                    &mut lock(&self.journal),
                    if failure.retained {
                        PausePhase::Paused {
                            token,
                            generation,
                            published: false,
                        }
                    } else if failure.stage == ResumeStage::ClockAcknowledgement {
                        PausePhase::Consumed {
                            generation,
                            by_resume: false,
                        }
                    } else {
                        PausePhase::Fenced
                    },
                );
                CommandOutcome::CancelFailed {
                    stage: CancelStage::ConsumeCompletedPause {
                        resume: failure.stage,
                    },
                    failure: failure.failure,
                }
            }
        }
    }

    /// Release the exact token through an explicit ClockOnly ticket, then
    /// require the guest driver's acknowledgement before the deadline. CPU
    /// release alone is never a completed resume.
    fn consume(
        &self,
        token: N::Token,
        generation: NativePauseGeneration,
        deadline: Instant,
    ) -> Result<ClockOnlyReceipt, ConsumeFailure> {
        let prepare = self
            .native_operation()
            .and_then(|operation| self.native.prepare_clock_only(&token, operation, deadline));
        let ticket = match prepare {
            Ok(ticket) => ticket,
            Err(failure) => {
                return Err(ConsumeFailure {
                    stage: ResumeStage::PrepareClock,
                    failure,
                    retained: self.still_paused(generation),
                })
            }
        };
        let (sequence, flags) = self.native.ticket_request(&ticket);
        if flags != CLOCK_ONLY_FLAGS {
            return Err(ConsumeFailure {
                stage: ResumeStage::PrepareClock,
                failure: NativeFailure::with_detail(
                    NativeFailureKind::Unexpected,
                    format!("native generation request is not ClockOnly (flags {flags:#x})"),
                ),
                retained: self.still_paused(generation),
            });
        }
        let submitted = Instant::now();
        let release = self.native_operation().and_then(|operation| {
            self.native
                .resume_generation(token, &ticket, operation, deadline)
        });
        if let Err(failure) = release {
            let released = self.settle_release(generation, deadline);
            match released {
                Some(true) => {}
                Some(false) => {
                    return Err(ConsumeFailure {
                        stage: ResumeStage::Release,
                        failure,
                        retained: true,
                    })
                }
                None => {
                    return Err(ConsumeFailure {
                        stage: ResumeStage::Release,
                        failure,
                        retained: false,
                    })
                }
            }
        }
        loop {
            let poll = if Instant::now() >= deadline {
                Ok(GenerationPoll::Failed(GenerationFailureKind::Deadline))
            } else {
                self.native.poll_generation(&ticket, deadline)
            };
            match poll {
                Ok(GenerationPoll::Acknowledged { completed_at }) => {
                    // Whole milliseconds keep the receipt exactly representable.
                    let elapsed = completed_at.saturating_duration_since(submitted);
                    let acknowledged_within = Duration::from_millis(
                        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                    );
                    return Ok(ClockOnlyReceipt {
                        sequence,
                        flags,
                        acknowledged_within,
                    });
                }
                Ok(GenerationPoll::Failed(kind)) => {
                    return Err(ConsumeFailure {
                        stage: ResumeStage::ClockAcknowledgement,
                        failure: NativeFailure::new(NativeFailureKind::Generation(kind)),
                        retained: false,
                    })
                }
                Ok(GenerationPoll::Pending) => {}
                Err(_) if Instant::now() < deadline => {}
                Err(failure) => {
                    return Err(ConsumeFailure {
                        stage: ResumeStage::ClockAcknowledgement,
                        failure,
                        retained: false,
                    })
                }
            }
            std::thread::sleep(CLOCK_POLL_INTERVAL);
        }
    }

    fn still_paused(&self, generation: NativePauseGeneration) -> bool {
        matches!(
            self.native.control_state(Instant::now() + OBSERVATION_BUDGET),
            Ok(NativeState::Paused(token)) if self.native.token_generation(&token) == generation.get()
        )
    }

    /// After a failed or uncertain release: `Some(true)` released to Running,
    /// `Some(false)` still Paused with the same generation, `None` otherwise.
    fn settle_release(&self, generation: NativePauseGeneration, deadline: Instant) -> Option<bool> {
        let limit = deadline.max(Instant::now()) + RECONCILE_GRACE;
        loop {
            match self
                .native
                .control_state(Instant::now() + OBSERVATION_BUDGET)
            {
                Ok(NativeState::Running) => return Some(true),
                Ok(NativeState::Paused(token)) => {
                    return (self.native.token_generation(&token) == generation.get())
                        .then_some(false)
                }
                Ok(NativeState::Resuming { .. }) | Err(_) if Instant::now() < limit => {}
                _ => return None,
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
    }

    // ------------------------------------------------------------- capture

    /// Apply `update` to one capture record under the journal lock.
    fn with_capture<R>(
        &self,
        capture: Uuid,
        update: impl FnOnce(&mut CaptureRecord<N::Capture>) -> R,
    ) -> Option<R> {
        lock(&self.journal).captures.get_mut(&capture).map(update)
    }

    fn missing_capture() -> CommandOutcome {
        CommandOutcome::CaptureFailed {
            stage: CaptureStage::Execution,
            failure: NativeFailure::with_detail(
                NativeFailureKind::Unexpected,
                "capture record disappeared",
            ),
        }
    }

    /// Poll native capture status while `pending` holds, bounded by the
    /// command deadline plus the reconciliation grace.
    fn reconcile_capture(
        &self,
        capture: Uuid,
        deadline: Instant,
        pending: impl Fn(&NativeCaptureStatus<N::Capture>) -> bool,
    ) -> Result<NativeCaptureStatus<N::Capture>, NativeFailure> {
        let limit = deadline.max(Instant::now()) + RECONCILE_GRACE;
        loop {
            match self
                .native
                .capture_status(capture, Instant::now() + OBSERVATION_BUDGET)
            {
                Ok(status) if pending(&status) && Instant::now() < limit => {}
                Ok(status) => return Ok(status),
                // Native never registered the capture: nothing to await.
                Err(failure) if failure.kind == NativeFailureKind::InvalidToken => {
                    return Err(failure)
                }
                Err(_) if Instant::now() < limit => {}
                Err(failure) => return Err(failure),
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
    }

    fn run_flush(&self, capture: Uuid, token: N::Token, deadline: Instant) -> CommandOutcome {
        let result = self
            .native_operation()
            .and_then(|operation| self.native.flush_capture(&token, operation, deadline));
        self.with_capture(capture, |record| match (result, record.cut) {
            (Ok(attachments), Some(pause)) => {
                record.flushed = true;
                record.progress = CaptureProgress::Flushed;
                CommandOutcome::CaptureFlushed { pause, attachments }
            }
            (Ok(_), None) => record.fail(
                CaptureStage::Flush,
                &NativeFailure::with_detail(NativeFailureKind::Unexpected, "capture has no cut"),
            ),
            (Err(failure), _) => record.fail(CaptureStage::Flush, &failure),
        })
        .unwrap_or_else(Self::missing_capture)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_execution(
        &self,
        capture: Uuid,
        token: N::Token,
        generation: NativePauseGeneration,
        digests: CaptureDigests,
        execution: File,
        devices: File,
        deadline: Instant,
    ) -> CommandOutcome {
        let binding = self.native.native_producer().and_then(|native_producer| {
            Ok(CaptureStateBinding {
                native_producer,
                silo_producer: digests.silo_producer,
                profile: digests.profile,
                topology: digests.topology,
                ram_layout: self.native.ram_layout_digest(deadline)?,
                source_run: self.binding.run_id,
                capture,
                pause_generation: generation,
            })
        });
        let binding = match binding {
            Ok(binding) => binding,
            Err(failure) => {
                // Never submitted: the worker closes both writers itself.
                drop((execution, devices));
                return self
                    .with_capture(capture, |record| {
                        record.holders.execution = OutputHolder::Closed;
                        record.holders.devices = OutputHolder::Closed;
                        record.fail(CaptureStage::Execution, &failure)
                    })
                    .unwrap_or_else(Self::missing_capture);
            }
        };
        self.with_capture(capture, |record| record.binding = Some(binding.clone()));
        let result = self.native_operation().and_then(|operation| {
            self.native
                .capture_execution(&token, &binding, execution, devices, operation, deadline)
        });
        let status = match result {
            Ok(receipt) => Ok(NativeCaptureStatus::ExecutionComplete(receipt)),
            Err(failure) => match self.reconcile_capture(capture, deadline, |status| {
                matches!(status, NativeCaptureStatus::ExecutionPending(_))
            }) {
                Ok(status @ NativeCaptureStatus::ExecutionComplete(_)) => Ok(status),
                observed => Err((failure, observed)),
            },
        };
        self.with_capture(capture, |record| match status {
            Ok(status) => {
                apply_status(record, status);
                match (&record.progress, &record.execution) {
                    (CaptureProgress::ExecutionCaptured, Some((execution, devices))) => {
                        CommandOutcome::ExecutionCaptured {
                            binding: Box::new(binding.clone()),
                            execution: *execution,
                            devices: *devices,
                        }
                    }
                    (CaptureProgress::Failed { stage, failure }, _) => {
                        CommandOutcome::CaptureFailed {
                            stage: *stage,
                            failure: failure.clone(),
                        }
                    }
                    _ => record.fail(
                        CaptureStage::Execution,
                        &NativeFailure::with_detail(
                            NativeFailureKind::Unexpected,
                            "execution receipt was not retained",
                        ),
                    ),
                }
            }
            Err((failure, observed)) => {
                match observed {
                    // Pending stays native-owned; a terminal failure closed both.
                    Ok(status) => apply_status(record, status),
                    // Native never registered the request: its outputs were
                    // dropped with the refused request.
                    Err(status) if status.kind == NativeFailureKind::InvalidToken => {
                        record.holders.execution = OutputHolder::Closed;
                        record.holders.devices = OutputHolder::Closed;
                    }
                    // Unknown: native may still own both writers.
                    Err(_) => {}
                }
                pending_or_failed(record, CaptureStage::Execution, failure)
            }
        })
        .unwrap_or_else(Self::missing_capture)
    }

    fn run_memory(
        &self,
        capture: Uuid,
        ticket: N::Capture,
        ram: File,
        layout: File,
        deadline: Instant,
    ) -> CommandOutcome {
        let result = self.native_operation().and_then(|operation| {
            self.native
                .capture_memory(&ticket, ram, layout, operation, deadline)
        });
        let status = match result {
            Ok(memory) => Ok(NativeCaptureStatus::CandidateComplete { ticket, memory }),
            Err(failure) => match self.reconcile_capture(capture, deadline, |status| {
                matches!(status, NativeCaptureStatus::MemoryPending(_))
            }) {
                Ok(status @ NativeCaptureStatus::CandidateComplete { .. }) => Ok(status),
                Ok(status) => Err((failure, Some(status))),
                Err(_) => Err((failure, None)),
            },
        };
        self.with_capture(capture, |record| match status {
            Ok(status) => {
                apply_status(record, status);
                match (&record.progress, &record.memory) {
                    (CaptureProgress::CandidateComplete, Some(memory)) => {
                        CommandOutcome::MemoryCaptured {
                            binding: memory.binding.clone(),
                            ram: memory.ram,
                            layout: memory.layout,
                            memory_generation: memory.memory_generation,
                            writers_closed: memory.writers_closed,
                        }
                    }
                    (CaptureProgress::Failed { stage, failure }, _) => {
                        CommandOutcome::CaptureFailed {
                            stage: *stage,
                            failure: failure.clone(),
                        }
                    }
                    _ => record.fail(
                        CaptureStage::Memory,
                        &NativeFailure::with_detail(
                            NativeFailureKind::Unexpected,
                            "memory receipt was not retained",
                        ),
                    ),
                }
            }
            Err((failure, status)) => {
                match status {
                    // Admission refused: native dropped the outputs with the
                    // request and the execution candidate is unchanged.
                    Some(NativeCaptureStatus::ExecutionComplete(_)) => {
                        record.holders.ram = OutputHolder::Closed;
                        record.holders.layout = OutputHolder::Closed;
                    }
                    // Pending, or a failed write retaining its files natively.
                    Some(status) => apply_status(record, status),
                    // Unknown: native may still hold them.
                    None => {}
                }
                pending_or_failed(record, CaptureStage::Memory, failure)
            }
        })
        .unwrap_or_else(Self::missing_capture)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_accept(
        &self,
        capture: Uuid,
        ticket: N::Capture,
        binding: CaptureStateBinding,
        ram: File,
        layout: File,
        stream: Digest32,
        deadline: Instant,
    ) -> CommandOutcome {
        let result = self.native_operation().and_then(|operation| {
            self.native
                .accept_capture(&ticket, &binding, ram, layout, stream, operation, deadline)
        });
        let accepted = match result {
            Ok(memory_generation) => Ok(memory_generation),
            Err(failure) => match self.reconcile_capture(capture, deadline, |_| false) {
                Ok(NativeCaptureStatus::Accepted {
                    memory_generation, ..
                }) => Ok(memory_generation),
                _ => Err(failure),
            },
        };
        let mut journal = lock(&self.journal);
        match accepted {
            Ok(memory_generation) => {
                // The new baseline replaces any earlier one natively.
                if journal
                    .baseline_pin
                    .as_ref()
                    .is_some_and(|(owner, _)| *owner != capture)
                {
                    if let Some((owner, _)) = journal.baseline_pin.take() {
                        if let Some(previous) = journal.captures.get_mut(&owner) {
                            previous.pin_holder = PinHolder::Released;
                        }
                    }
                }
                journal.baseline_owner = Some(capture);
                match journal.captures.get_mut(&capture) {
                    Some(record) => {
                        record.accepted = true;
                        record.progress = CaptureProgress::Accepted;
                        CommandOutcome::CaptureAccepted { memory_generation }
                    }
                    None => Self::missing_capture(),
                }
            }
            // The candidate stays complete: abandonment remains possible.
            Err(failure) => CommandOutcome::CaptureFailed {
                stage: CaptureStage::Accept,
                failure,
            },
        }
    }

    fn run_abandon(&self, capture: Uuid, ticket: N::Capture, deadline: Instant) -> CommandOutcome {
        // Native refuses to abandon unfinished work: await its terminality
        // within this command's own deadline, never interrupting it.
        let pending = |record: &CaptureRecord<N::Capture>| {
            matches!(
                record.progress,
                CaptureProgress::ExecutionPending | CaptureProgress::MemoryPending
            )
        };
        while self.with_capture(capture, |record| pending(record)) == Some(true) {
            if Instant::now() >= deadline {
                return CommandOutcome::CaptureFailed {
                    stage: CaptureStage::Abandon,
                    failure: NativeFailure::with_detail(
                        NativeFailureKind::Deadline,
                        "native capture work is still pending",
                    ),
                };
            }
            if let Ok(status) = self
                .native
                .capture_status(capture, Instant::now() + OBSERVATION_BUDGET)
            {
                self.with_capture(capture, |record| apply_status(record, status));
            }
            std::thread::sleep(RECONCILE_INTERVAL);
        }
        let result = self
            .native_operation()
            .and_then(|operation| self.native.abandon_capture(&ticket, operation, deadline));
        let result = match result {
            Ok(()) => Ok(()),
            Err(failure) => match self.reconcile_capture(capture, deadline, |_| false) {
                Ok(NativeCaptureStatus::Abandoned(_)) => Ok(()),
                _ => Err(failure),
            },
        };
        self.with_capture(capture, |record| match result {
            Ok(()) => {
                // Native dropped every retained failure owner with the candidate.
                record.close_prepared();
                record.holders = CaptureOutputHolders {
                    execution: OutputHolder::Closed,
                    devices: OutputHolder::Closed,
                    ram: OutputHolder::Closed,
                    layout: OutputHolder::Closed,
                };
                record.progress = CaptureProgress::Abandoned;
                CommandOutcome::CaptureAbandoned
            }
            Err(failure) => CommandOutcome::CaptureFailed {
                stage: CaptureStage::Abandon,
                failure,
            },
        })
        .unwrap_or_else(Self::missing_capture)
    }

    fn run_preserve(
        &self,
        token: N::Token,
        generation: NativePauseGeneration,
        deadline: Instant,
    ) -> CommandOutcome {
        let result = self.native_operation().and_then(|operation| {
            self.native
                .preserve_pause(token.clone(), operation, deadline)
        });
        // A lost reply is reconciled through actual native control.
        let result = match result {
            Ok(preserved) => Ok(preserved),
            Err(failure) => match self
                .native
                .control_state(Instant::now() + OBSERVATION_BUDGET)
            {
                Ok(NativeState::Paused(current))
                    if self.native.token_owner(&current) == NativePauseOwner::User
                        && self.native.token_generation(&current) == generation.get() =>
                {
                    Ok(current)
                }
                Ok(NativeState::Paused(current))
                    if self.native.token_generation(&current) == generation.get() =>
                {
                    Err((failure, true))
                }
                _ => Err((failure, false)),
            },
        };
        let mut journal = lock(&self.journal);
        match result {
            Ok(preserved) => {
                let owner = self.native.token_owner(&preserved);
                match NativePauseGeneration::new(self.native.token_generation(&preserved)) {
                    Some(current) if owner == NativePauseOwner::User => {
                        if let Some(slot) = journal.slot.as_mut() {
                            slot.capture = None;
                            slot.phase = PausePhase::Paused {
                                token: preserved,
                                generation: current,
                                published: true,
                            };
                        }
                        CommandOutcome::CapturePreserved {
                            pause: NativePause {
                                generation: current,
                                owner,
                            },
                        }
                    }
                    _ => {
                        set_phase(&mut journal, PausePhase::Fenced);
                        CommandOutcome::CaptureFailed {
                            stage: CaptureStage::Preserve,
                            failure: NativeFailure::with_detail(
                                NativeFailureKind::Unexpected,
                                "native preserve returned a foreign token",
                            ),
                        }
                    }
                }
            }
            Err((failure, retained)) => {
                set_phase(
                    &mut journal,
                    if retained {
                        PausePhase::Paused {
                            token,
                            generation,
                            published: true,
                        }
                    } else {
                        PausePhase::Fenced
                    },
                );
                CommandOutcome::CaptureFailed {
                    stage: CaptureStage::Preserve,
                    failure,
                }
            }
        }
    }

    fn run_release(&self, capture: Uuid, native: bool, deadline: Instant) -> CommandOutcome {
        let result = if native {
            match self
                .native_operation()
                .and_then(|operation| self.native.release_capture(capture, operation, deadline))
            {
                Ok(()) => Ok(()),
                Err(failure) => match self.reconcile_capture(capture, deadline, |_| false) {
                    Ok(NativeCaptureStatus::Released) => Ok(()),
                    _ => Err(failure),
                },
            }
        } else {
            Ok(())
        };
        let mut journal = lock(&self.journal);
        let baseline = journal.baseline_owner == Some(capture);
        let Some(record) = journal.captures.get_mut(&capture) else {
            return Self::missing_capture();
        };
        if let Err(failure) = result {
            return CommandOutcome::CaptureFailed {
                stage: CaptureStage::Release,
                failure,
            };
        }
        record.progress = CaptureProgress::Released;
        record.close_prepared();
        let pin = record.pin.take();
        let retained = record.accepted && baseline && pin.is_some();
        record.pin_holder = if retained {
            PinHolder::Baseline
        } else {
            PinHolder::Released
        };
        match pin {
            // Native keeps the accepted staging RAM as its baseline.
            Some(pin) if retained => journal.baseline_pin = Some((capture, pin)),
            _ => {}
        }
        CommandOutcome::CaptureReleased {
            baseline_retained: retained,
        }
    }
}

fn capture_record<T, C>(
    journal: &Journal<T, C>,
    capture: Uuid,
) -> Result<&CaptureRecord<C>, LifecycleRejection> {
    journal
        .captures
        .get(&capture)
        .ok_or(LifecycleRejection::UnknownCapture)
}

fn capture_record_mut<T, C>(
    journal: &mut Journal<T, C>,
    capture: Uuid,
) -> Result<&mut CaptureRecord<C>, LifecycleRejection> {
    journal
        .captures
        .get_mut(&capture)
        .ok_or(LifecycleRejection::UnknownCapture)
}

fn mark_capture_paused<T, C>(journal: &mut Journal<T, C>, capture: Uuid, pause: NativePause) {
    if let Some(record) = journal.captures.get_mut(&capture) {
        if record.progress == CaptureProgress::Prepared {
            record.progress = CaptureProgress::Paused;
            record.cut = Some(pause);
        }
    }
}

/// Classify a failed stage call after reconciliation: still-pending native
/// work stays pending (native owns its outputs), a native terminal failure
/// keeps its own detail, anything else records the call's failure.
fn pending_or_failed<C>(
    record: &mut CaptureRecord<C>,
    stage: CaptureStage,
    failure: NativeFailure,
) -> CommandOutcome {
    match &record.progress {
        CaptureProgress::ExecutionPending | CaptureProgress::MemoryPending => {}
        CaptureProgress::Failed {
            stage: failed,
            failure: native,
        } if *failed == stage => {
            return CommandOutcome::CaptureFailed {
                stage,
                failure: native.clone(),
            }
        }
        _ => {
            record.progress = CaptureProgress::Failed {
                stage,
                failure: failure.clone(),
            }
        }
    }
    CommandOutcome::CaptureFailed { stage, failure }
}

/// Apply an observed native status to a record awaiting native work. Native
/// closes outputs before every terminal status except a failed RAM write,
/// which keeps its files until abandonment.
fn apply_status<C>(record: &mut CaptureRecord<C>, status: NativeCaptureStatus<C>) {
    match status {
        NativeCaptureStatus::ExecutionPending(ticket) => {
            record.ticket = Some(ticket);
            record.progress = CaptureProgress::ExecutionPending;
        }
        NativeCaptureStatus::ExecutionComplete(receipt) => {
            record.holders.execution = OutputHolder::Closed;
            record.holders.devices = OutputHolder::Closed;
            let outputs = record.preparation.outputs;
            record.ticket = Some(receipt.ticket);
            if receipt.execution.identity() != outputs.execution
                || receipt.devices.identity() != outputs.devices
            {
                record.progress = CaptureProgress::Failed {
                    stage: CaptureStage::Execution,
                    failure: NativeFailure::with_detail(
                        NativeFailureKind::Unexpected,
                        "native execution receipt names foreign outputs",
                    ),
                };
                return;
            }
            record.execution = Some((receipt.execution, receipt.devices));
            if matches!(
                record.progress,
                CaptureProgress::ExecutionPending | CaptureProgress::Flushed
            ) {
                record.progress = CaptureProgress::ExecutionCaptured;
            }
        }
        NativeCaptureStatus::MemoryPending(ticket) => {
            record.ticket = Some(ticket);
            record.progress = CaptureProgress::MemoryPending;
        }
        NativeCaptureStatus::CandidateComplete { ticket, memory } => {
            record.ticket = Some(ticket);
            let outputs = record.preparation.outputs;
            if memory.writers_closed {
                record.holders.ram = OutputHolder::Closed;
                record.holders.layout = OutputHolder::Closed;
            }
            let problem = if !memory.writers_closed {
                Some("native RAM writers are still open")
            } else if memory.ram.identity() != outputs.ram
                || memory.layout.identity() != outputs.layout
            {
                Some("native RAM receipt names foreign outputs")
            } else if record.binding.as_ref() != Some(memory.binding.as_ref()) {
                Some("native RAM binding differs from the execution binding")
            } else {
                None
            };
            if let Some(problem) = problem {
                record.progress = CaptureProgress::Failed {
                    stage: CaptureStage::Memory,
                    failure: NativeFailure::with_detail(NativeFailureKind::Unexpected, problem),
                };
                return;
            }
            record.memory = Some(memory);
            record.progress = CaptureProgress::CandidateComplete;
        }
        NativeCaptureStatus::Failed {
            ticket,
            stage,
            failure,
        } => {
            record.ticket = Some(ticket);
            match stage {
                CaptureStage::Execution => {
                    record.holders.execution = OutputHolder::Closed;
                    record.holders.devices = OutputHolder::Closed;
                }
                // A failed RAM write retains its files natively.
                CaptureStage::Memory => {
                    record.holders.ram = OutputHolder::Native;
                    record.holders.layout = OutputHolder::Native;
                }
                _ => {}
            }
            record.progress = CaptureProgress::Failed { stage, failure };
        }
        // Terminal states are recorded by their own commands.
        NativeCaptureStatus::Accepted { ticket, .. } | NativeCaptureStatus::Abandoned(ticket) => {
            record.ticket = Some(ticket);
        }
        NativeCaptureStatus::Released => {}
    }
}

/// Whole-set preflight of the five capture descriptors before any freeze.
fn validate_outputs(
    files: &crate::virt::lifecycle::CaptureOutputFiles,
    preparation: &CapturePreparation,
    excluded: &[OutputIdentity],
) -> Result<(), OutputProblem> {
    let declared: CaptureOutputIdentities = preparation.outputs;
    let outputs = [
        (OutputRole::Execution, &files.execution, declared.execution),
        (OutputRole::Devices, &files.devices, declared.devices),
        (OutputRole::Ram, &files.ram, declared.ram),
        (OutputRole::Layout, &files.layout, declared.layout),
    ];
    let mut seen = Vec::with_capacity(5);
    for (role, file, identity) in outputs {
        let actual = inspect(file, role, true)?;
        if actual != identity {
            return Err(OutputProblem {
                role,
                problem: OutputDefect::Identity,
            });
        }
        if seen.contains(&actual) || actual == preparation.pin || excluded.contains(&actual) {
            return Err(OutputProblem {
                role,
                problem: OutputDefect::Alias,
            });
        }
        seen.push(actual);
    }
    if inspect(&files.pin, OutputRole::Pin, false)? != preparation.pin {
        return Err(OutputProblem {
            role: OutputRole::Pin,
            problem: OutputDefect::Identity,
        });
    }
    Ok(())
}

/// One private writable output (`output`) or the capture lease (`!output`):
/// regular, ours, 0600, single link, `O_RDWR` without append/direct/path-only.
/// Outputs are additionally CLOEXEC and empty.
fn inspect(file: &File, role: OutputRole, output: bool) -> Result<OutputIdentity, OutputProblem> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::sys::stat::{fstat, SFlag};
    let problem = |problem| OutputProblem { role, problem };
    let stat = fstat(file.as_fd()).map_err(|_| problem(OutputDefect::NotRegular))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(problem(OutputDefect::NotRegular));
    }
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| problem(OutputDefect::Access))?,
    );
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_PATH) {
        return Err(problem(OutputDefect::PathOnly));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() {
        return Err(problem(OutputDefect::Owner));
    }
    if stat.st_mode & 0o7777 != 0o600 {
        return Err(problem(OutputDefect::Mode));
    }
    if stat.st_nlink != 1 {
        return Err(problem(OutputDefect::Links));
    }
    if flags & OFlag::O_ACCMODE != OFlag::O_RDWR {
        return Err(problem(OutputDefect::Access));
    }
    if flags.contains(OFlag::O_APPEND) {
        return Err(problem(OutputDefect::Append));
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_DIRECT) {
        return Err(problem(OutputDefect::DirectIo));
    }
    if output {
        let descriptor = FdFlag::from_bits_retain(
            fcntl(file, FcntlArg::F_GETFD).map_err(|_| problem(OutputDefect::CloseOnExec))?,
        );
        if !descriptor.contains(FdFlag::FD_CLOEXEC) {
            return Err(problem(OutputDefect::CloseOnExec));
        }
        if stat.st_size != 0 {
            return Err(problem(OutputDefect::NotEmpty));
        }
    }
    Ok(OutputIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

/// The sealed read-only RAM or layout: the exact receipt inode, unchanged
/// length, read-only CLOEXEC access.
fn validate_sealed(
    file: &File,
    role: OutputRole,
    receipt: OutputReceipt,
) -> Result<(), OutputProblem> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
    use nix::sys::stat::{fstat, SFlag};
    let problem = |problem| OutputProblem { role, problem };
    let stat = fstat(file.as_fd()).map_err(|_| problem(OutputDefect::NotRegular))?;
    if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT != SFlag::S_IFREG {
        return Err(problem(OutputDefect::NotRegular));
    }
    if stat.st_dev as u64 != receipt.device
        || stat.st_ino as u64 != receipt.inode
        || stat.st_size as u64 != receipt.length
    {
        return Err(problem(OutputDefect::Identity));
    }
    let flags = OFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFL).map_err(|_| problem(OutputDefect::Access))?,
    );
    if flags & OFlag::O_ACCMODE != OFlag::O_RDONLY {
        return Err(problem(OutputDefect::Access));
    }
    let descriptor = FdFlag::from_bits_retain(
        fcntl(file, FcntlArg::F_GETFD).map_err(|_| problem(OutputDefect::CloseOnExec))?,
    );
    if !descriptor.contains(FdFlag::FD_CLOEXEC) {
        return Err(problem(OutputDefect::CloseOnExec));
    }
    Ok(())
}

fn withdrawn_or(cancel: bool, outcome: CommandOutcome) -> CommandOutcome {
    if cancel {
        CommandOutcome::PauseWithdrawn
    } else {
        outcome
    }
}

fn set_phase<T, C>(journal: &mut Journal<T, C>, phase: PausePhase<T>) {
    if let Some(slot) = journal.slot.as_mut() {
        slot.phase = phase;
    }
}

fn next_native<T, C>(journal: &mut Journal<T, C>) -> Result<NativeOperation, LifecycleRejection> {
    let next = journal
        .last_native
        .checked_add(1)
        .and_then(NativeOperation::new)
        .ok_or(LifecycleRejection::Busy)?;
    journal.last_native = next.get();
    Ok(next)
}

fn saturated() -> NativeFailure {
    NativeFailure::with_detail(
        NativeFailureKind::Busy,
        "lifecycle observation capacity exhausted",
    )
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::krun::worker::lifecycle::{
        CaptureRecord, Entry, Journal, MemoryCapture, NativeCaptureStatus, PreparedOutputs,
    };
    use crate::virt::lifecycle::{
        CaptureDigests, CaptureOutputHolders, CaptureOutputIdentities, CapturePauseOrigin,
        CapturePauseSource, CapturePreparation, CaptureProgress, CaptureResumePolicy,
        CaptureStateBinding, CommandKey, CommandOutcome, CommandSequence, CommandState, Digest32,
        LifecycleCommand, NativePause, NativePauseGeneration, NativePauseOwner, OutputHolder,
        OutputIdentity, OutputReceipt, PinHolder,
    };

    const TICKET: u32 = 7;

    fn receipt(inode: u64) -> OutputReceipt {
        OutputReceipt {
            device: 1,
            inode,
            length: 4096,
        }
    }

    fn generation() -> NativePauseGeneration {
        NativePauseGeneration::new(1).expect("nonzero")
    }

    fn binding(capture: Uuid) -> CaptureStateBinding {
        CaptureStateBinding {
            native_producer: "native".into(),
            silo_producer: Digest32([1; 32]),
            profile: Digest32([2; 32]),
            topology: Digest32([3; 32]),
            ram_layout: Digest32([4; 32]),
            source_run: Uuid::new_v4(),
            capture,
            pause_generation: generation(),
        }
    }

    /// A capture whose full-RAM write is still pending natively after its
    /// stage command reported: only an observation or a command changes it.
    fn memory_pending(journal: &mut Journal<(), u32>, capture: Uuid) -> CaptureStateBinding {
        let identity = |inode| OutputIdentity { device: 1, inode };
        let binding = binding(capture);
        journal.captures.insert(
            capture,
            CaptureRecord {
                preparation: CapturePreparation {
                    outputs: CaptureOutputIdentities {
                        execution: identity(1),
                        devices: identity(2),
                        ram: identity(3),
                        layout: identity(4),
                    },
                    pin: identity(5),
                    pause: CapturePauseSource::Acquire,
                    resume_policy: CaptureResumePolicy::ResumeIfAcquired,
                    binding: CaptureDigests {
                        silo_producer: Digest32([1; 32]),
                        profile: Digest32([2; 32]),
                        topology: Digest32([3; 32]),
                    },
                },
                origin: CapturePauseOrigin::Acquired,
                progress: CaptureProgress::MemoryPending,
                outputs: PreparedOutputs::default(),
                holders: CaptureOutputHolders {
                    execution: OutputHolder::Closed,
                    devices: OutputHolder::Closed,
                    ram: OutputHolder::Native,
                    layout: OutputHolder::Native,
                },
                pin: None,
                pin_holder: PinHolder::Capture,
                cut: Some(NativePause {
                    generation: generation(),
                    owner: NativePauseOwner::Capture,
                }),
                flushed: true,
                binding: Some(binding.clone()),
                ticket: Some(TICKET),
                execution: Some((receipt(1), receipt(2))),
                memory: None,
                accepted: false,
            },
        );
        binding
    }

    fn candidate(binding: &CaptureStateBinding) -> NativeCaptureStatus<u32> {
        NativeCaptureStatus::CandidateComplete {
            ticket: TICKET,
            memory: MemoryCapture {
                binding: Box::new(binding.clone()),
                ram: receipt(3),
                layout: receipt(4),
                memory_generation: 1,
                writers_closed: true,
            },
        }
    }

    fn progress(journal: &Journal<(), u32>, capture: Uuid) -> CaptureProgress {
        journal.captures[&capture].progress.clone()
    }

    /// Admit and run one mutator against `capture` the way stage admission
    /// and its handler do, leaving `resolved` behind.
    fn resolve(
        journal: &mut Journal<(), u32>,
        capture: Uuid,
        sequence: u64,
        command: LifecycleCommand,
        resolved: CaptureProgress,
        outcome: CommandOutcome,
    ) {
        let sequence = CommandSequence::new(sequence).expect("nonzero");
        let key = CommandKey {
            request_id: Uuid::new_v4(),
            kind: command.kind().expect("mutator"),
        };
        journal.mutator = Some(sequence);
        journal.admit_command(
            key,
            Entry {
                sequence,
                command,
                state: CommandState::Accepted,
            },
        );
        assert_eq!(
            journal.pending_revision(capture),
            None,
            "a running mutator owns the capture: no refresh starts"
        );
        let record = journal.captures.get_mut(&capture).expect("record");
        record.close_prepared();
        record.progress = resolved;
        journal.complete_command(key, sequence, &outcome);
        assert!(journal.mutator.is_none());
    }

    #[test]
    fn a_current_observation_installs_the_native_candidate() {
        let mut journal = Journal::default();
        let capture = Uuid::new_v4();
        let binding = memory_pending(&mut journal, capture);
        let revision = journal.pending_revision(capture).expect("pending");
        assert!(journal.apply_observed(capture, revision, candidate(&binding)));
        assert_eq!(
            progress(&journal, capture),
            CaptureProgress::CandidateComplete
        );
        assert_eq!(
            journal.pending_revision(capture),
            None,
            "a complete candidate is never refreshed again"
        );
    }

    #[test]
    fn a_delayed_observation_never_regresses_an_abandoned_or_released_capture() {
        let abandon = |capture| LifecycleCommand::AbandonCapture {
            operation: capture,
            timeout: std::time::Duration::from_secs(5),
        };
        let release = |capture| LifecycleCommand::ReleaseCapture {
            operation: capture,
            timeout: std::time::Duration::from_secs(5),
        };
        let mut journal = Journal::default();
        let capture = Uuid::new_v4();
        let binding = memory_pending(&mut journal, capture);
        // The observer reads the pending revision, then queries native
        // outside the lock; meanwhile abandon is admitted and completes.
        let observed = journal.pending_revision(capture).expect("pending");
        resolve(
            &mut journal,
            capture,
            1,
            abandon(capture),
            CaptureProgress::Abandoned,
            CommandOutcome::CaptureAbandoned,
        );
        assert!(
            !journal.apply_observed(capture, observed, candidate(&binding)),
            "the observation predates the abandonment"
        );
        assert_eq!(progress(&journal, capture), CaptureProgress::Abandoned);

        // The same holds across release, and for an observation taken
        // before the abandonment that is delivered after both commands.
        resolve(
            &mut journal,
            capture,
            2,
            release(capture),
            CaptureProgress::Released,
            CommandOutcome::CaptureReleased {
                baseline_retained: false,
            },
        );
        assert!(!journal.apply_observed(capture, observed, candidate(&binding)));
        assert!(!journal.apply_observed(
            capture,
            observed,
            NativeCaptureStatus::MemoryPending(TICKET)
        ));
        assert_eq!(progress(&journal, capture), CaptureProgress::Released);
        assert_eq!(journal.pending_revision(capture), None);
    }

    #[test]
    fn of_two_concurrent_observations_only_the_first_applies() {
        let mut journal = Journal::default();
        let capture = Uuid::new_v4();
        let binding = memory_pending(&mut journal, capture);
        let first = journal.pending_revision(capture).expect("pending");
        let second = journal.pending_revision(capture).expect("pending");
        assert!(journal.apply_observed(capture, first, candidate(&binding)));
        // The slower observation saw native still writing RAM; it must not
        // turn the complete candidate back into pending work.
        assert!(!journal.apply_observed(
            capture,
            second,
            NativeCaptureStatus::MemoryPending(TICKET)
        ));
        assert_eq!(
            progress(&journal, capture),
            CaptureProgress::CandidateComplete
        );
    }
}

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
//! operation. Opaque native tokens and generation tickets never leave this
//! module. Only CancelPause may run while its target Pause is still pending.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::krun::worker::lifecycle_wire::{
    self, FrameBuffer, ParentFrame, WorkerFrame, PROTOCOL_VERSION,
};
use crate::virt::lifecycle::{
    CancelSettlement, CancelStage, ClockOnlyReceipt, CommandKey, CommandKind, CommandOutcome,
    CommandReport, CommandSequence, CommandState, ControlObservation, GenerationFailureKind,
    InventoryObservation, LifecycleCommand, LifecycleRejection, LifecycleRequest, NativeControl,
    NativeFailure, NativeFailureKind, NativeOperation, NativePause, NativePauseGeneration,
    NativePauseOwner, ObservedClockProfile, PausePurpose, ResumeStage,
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

/// The blocking native lifecycle authority. The real worker implements it over
/// libkrun; the scenario backend implements a modeled native owner.
pub(crate) trait NativeLifecycle: Send + Sync + 'static {
    type Token: Clone + Send + 'static;
    type Ticket: Send + 'static;

    fn pause(
        &self,
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
    journal: Mutex<Journal<N::Token>>,
    settled: Condvar,
    writer: Mutex<UnixStream>,
    light: AtomicUsize,
    failed: AtomicBool,
    on_fatal: FatalHandler,
}

struct Journal<T> {
    last_sequence: u64,
    last_native: u64,
    /// Retained for the run lifetime: commands are few and compact.
    commands: HashMap<CommandKey, Entry>,
    slot: Option<PauseSlot<T>>,
    /// The single non-cancel mutator in flight.
    mutator: Option<CommandSequence>,
    canceller: Option<CommandSequence>,
}

impl<T> Default for Journal<T> {
    fn default() -> Self {
        Self {
            last_sequence: 0,
            last_native: 0,
            commands: HashMap::new(),
            slot: None,
            mutator: None,
            canceller: None,
        }
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
    /// A Resume or CancelPause is consuming the token.
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

enum Admitted<T> {
    Run(Admission<T>),
    /// Settled at admission without native work.
    Settled(CommandOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Observe {
    Native,
    /// Observation capacity is exhausted: answer without a native call.
    Saturated,
}

enum Admission<T> {
    Pause {
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
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        let mut buffer = FrameBuffer::default();
        let mut chunk = [0_u8; 4096];
        let mut partial_since: Option<Instant> = None;
        loop {
            if self.failed.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(since) = partial_since {
                let remaining = FRAME_TIMEOUT.saturating_sub(since.elapsed());
                if remaining.is_zero() {
                    return Err(crate::krun::worker::wire::invalid(
                        "unfinished lifecycle frame timed out",
                    ));
                }
                let mut ready = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
                match poll(
                    &mut ready,
                    PollTimeout::try_from(remaining).map_err(std::io::Error::other)?,
                ) {
                    Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                    Ok(_) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let count = lifecycle_wire::recv_without_rights(socket.as_fd(), &mut chunk)?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "lifecycle endpoint closed by the monitor",
                ));
            }
            buffer.extend(&chunk[..count])?;
            while let Some(frame) = buffer.next::<ParentFrame>()? {
                self.dispatch(frame)?;
            }
            partial_since = match (buffer.partial(), partial_since) {
                (true, Some(since)) => Some(since),
                (true, None) => Some(Instant::now()),
                (false, _) => None,
            };
        }
    }

    fn dispatch(self: &Arc<Self>, frame: ParentFrame) -> std::io::Result<()> {
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
        };
        let key = CommandKey { request_id, kind };
        match self.admit(sequence, key, command, mutation) {
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
        Ok(())
    }

    /// Admission is serialized here; no native call happens under this lock.
    fn admit(
        &self,
        sequence: CommandSequence,
        key: CommandKey,
        command: LifecycleCommand,
        mutation: Mutation,
    ) -> Result<Admitted<N::Token>, LifecycleRejection> {
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
                match (&journal.slot, purpose) {
                    (None, PausePurpose::Initial) => {}
                    (Some(slot), PausePurpose::Initial) if slot.phase.settled_running() => {}
                    (Some(_), PausePurpose::Initial) => {
                        return Err(LifecycleRejection::PauseActive)
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
                    phase: PausePhase::Pending { cancel: false },
                });
                journal.mutator = Some(sequence);
                Admitted::Run(Admission::Pause {
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
                let slot = journal
                    .slot
                    .as_mut()
                    .filter(|slot| slot.operation == operation)
                    .ok_or(LifecycleRejection::NoCurrentPause)?;
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
                    journal.commands.insert(
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
        journal.commands.insert(
            key,
            Entry {
                sequence,
                command,
                state: CommandState::Accepted,
            },
        );
        Ok(admitted)
    }

    fn spawn_mutator(
        self: &Arc<Self>,
        sequence: CommandSequence,
        key: CommandKey,
        operation: Uuid,
        admission: Admission<N::Token>,
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
                        native,
                        profile_operation,
                        clock_profile,
                        deadline,
                    } => shared.run_pause(native, profile_operation, clock_profile, deadline),
                    Admission::Resume {
                        token,
                        generation,
                        deadline,
                    } => shared.run_resume(token, generation, deadline),
                    Admission::Cancel { start, deadline } => shared.run_cancel(start, deadline),
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
        {
            let mut journal = lock(&self.journal);
            if let Some(entry) = journal.commands.get_mut(&key) {
                entry.state = CommandState::Completed {
                    outcome: outcome.clone(),
                };
            }
            if journal.mutator == Some(sequence) {
                journal.mutator = None;
            }
            if journal.canceller == Some(sequence) {
                journal.canceller = None;
            }
        }
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
        native: NativeOperation,
        profile_operation: NativeOperation,
        clock_profile: Option<ObservedClockProfile>,
        deadline: Instant,
    ) -> CommandOutcome {
        let result = match self
            .native
            .pause(native, profile_operation, clock_profile, deadline)
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
                    Some(generation) => {
                        let owner = self.native.token_owner(&token);
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
                self.cancel_consume(token, generation, deadline)
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
                        self.cancel_consume(token, generation, deadline)
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
}

fn withdrawn_or(cancel: bool, outcome: CommandOutcome) -> CommandOutcome {
    if cancel {
        CommandOutcome::PauseWithdrawn
    } else {
        outcome
    }
}

fn set_phase<T>(journal: &mut Journal<T>, phase: PausePhase<T>) {
    if let Some(slot) = journal.slot.as_mut() {
        slot.phase = phase;
    }
}

fn next_native<T>(journal: &mut Journal<T>) -> Result<NativeOperation, LifecycleRejection> {
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

//! Scenario native lifecycle owner for the in-process mock backend.
//!
//! It models the libkrun control owner's observable contract, not its
//! internals: pause admission only from Running, strictly increasing native
//! operations, one opaque run-bound token per pause generation, explicit
//! cancellation through rollback, and ClockOnly release whose acknowledgement
//! arrives separately. Failures and latencies are scripted by
//! [`test_utils::LifecycleScenario`]. The worker lifecycle server runs over
//! it unchanged, so its linearization and recovery logic is exercised here.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use test_utils::{
    BlockBackingScenario, LifecycleScenario, MemoryTrackingScenario, NativeCancelResult,
    NativeCancelStep, NativePauseResult, NativePauseStep, NativeResumeResult, NativeResumeStep,
};

use crate::krun::worker::lifecycle::{
    GenerationPoll, NativeLifecycle, NativeState, CLOCK_ONLY_FLAGS,
};
use crate::virt::lifecycle::{
    BlockBacking, GenerationFailureKind, InventoryObservation, MemoryTracking, NativeFailure,
    NativeFailureKind, NativeOperation, NativePauseOwner, NativeProvider, ObservedClockProfile,
    ProviderDevice, VirtioKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioToken {
    run: u64,
    generation: u64,
}

#[derive(Debug)]
pub(crate) struct ScenarioTicket {
    run: u64,
    sequence: u64,
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
    stopped: bool,
}

struct Ticket {
    sequence: u64,
    step: NativeResumeStep,
    deadline: Instant,
    acknowledged_at: Option<Instant>,
    failed_at: Option<(Instant, GenerationFailureKind)>,
}

fn participant(detail: &str) -> NativeFailure {
    NativeFailure::with_detail(NativeFailureKind::Participant, detail)
}

impl ScenarioNative {
    pub(crate) fn new(scenario: Option<LifecycleScenario>) -> Self {
        let (pause_steps, cancel_steps, resume_steps) = scenario
            .as_ref()
            .map(|scenario| {
                (
                    scenario.native_pause.iter().cloned().collect(),
                    scenario.native_cancel.iter().cloned().collect(),
                    scenario.native_resume.iter().cloned().collect(),
                )
            })
            .unwrap_or_default();
        Self {
            inner: Arc::new(Inner {
                run: rand::random(),
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
                    stopped: false,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    /// The process ended: native control is gone and blocked callers return.
    pub(crate) fn stop(&self) {
        let mut model = self.lock();
        model.stopped = true;
        model.control = NativeState::Stopped;
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
                || provider.block_backing == Some(BlockBackingScenario::Vmdk)
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

    fn token(&self, model: &Model) -> ScenarioToken {
        ScenarioToken {
            run: self.inner.run,
            generation: model.generation,
        }
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

impl NativeLifecycle for ScenarioNative {
    type Token = ScenarioToken;
    type Ticket = ScenarioTicket;

    fn pause(
        &self,
        operation: NativeOperation,
        _profile_operation: NativeOperation,
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
        let token = self.token(&model);
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

    fn token_owner(&self, _token: &ScenarioToken) -> NativePauseOwner {
        NativePauseOwner::User
    }
}

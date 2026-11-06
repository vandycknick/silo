use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use prost_types::Timestamp;
use protocol::v1::{
    AgentConnection, AgentConnectionState, AgentIdentity, AgentMetricReport, AgentMetrics,
    AgentMetricsObservation, AgentStatus, AgentStatusObservation, AgentStatusReport,
    AgentStatusState, DisabledAgent, EnabledAgent, Freshness, HostAgent, HostMemoryReclaim,
    HostMetrics, HostStatus, MonitorSnapshot, Readiness, ReadinessReason, StaleReason, VmSnapshot,
    VmState,
};
use tokio::sync::watch;
use vm_spec::lifecycle::{LiveLifecycle, VmLifecycleState};
use vm_spec::live::{
    LiveBackend, LiveCapabilityVector, LiveLane, LiveMachineReport, LiveScope, LIVE_SCHEMA_VERSION,
};

pub(crate) struct RunLiveProfile {
    pub(crate) run_id: String,
    pub(crate) backend: LiveBackend,
    pub(crate) lane: LiveLane,
    pub(crate) live: LiveCapabilityVector,
}

const TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;
const SSH_VERIFICATION_VALIDITY: Duration = Duration::from_secs(65);
const SSH_VERIFICATION_PENDING: &str = "SSH listener verification pending";

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("silo-vmm state lock is poisoned")]
    Poisoned,
    #[error("invalid agent observation: {0}")]
    Validation(String),
    #[error("agent protocol error: {0}")]
    Protocol(String),
    #[error("agent metrics identity does not match the current status identity")]
    IdentityMismatch,
    #[error("unable to calculate observation freshness deadline")]
    Clock,
    #[error("SSH verification epoch exhausted")]
    SshEpochExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Ready,
    Terminal,
    TimedOut,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadyAgentIdentity {
    pub(crate) instance_id: uuid::Uuid,
    pub(crate) boot_id: uuid::Uuid,
}

/// Host-owned identity of one eligible listener. Epochs prevent A→B→A races.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SshVerificationTarget {
    pub(crate) epoch: u64,
    pub(crate) identity: ReadyAgentIdentity,
    pub(crate) backend: String,
    pub(crate) port: u32,
    pub(crate) host_public_key: String,
}

#[derive(Debug, Clone)]
enum SshVerificationOutcome {
    Pending,
    Verified { deadline: Instant },
    Failed(String),
}

#[derive(Debug, Clone)]
struct SshVerification {
    target: Arc<SshVerificationTarget>,
    outcome: SshVerificationOutcome,
}

#[derive(Debug, Clone)]
struct Observation<T> {
    received_at: SystemTime,
    received: Instant,
    stale_at: SystemTime,
    deadline: Instant,
    value: T,
}

/// Atomic live-lifecycle projection published by the coordinator.
#[derive(Debug, Clone)]
pub(crate) struct LiveTransition {
    pub(crate) state: VmLifecycleState,
    pub(crate) lifecycle: LiveLifecycle,
    pub(crate) message: String,
    /// Identity existing sessions stay bound to while the lifecycle holds a
    /// non-Running state. Cleared on Running and Error.
    pub(crate) held_identity: Option<ReadyAgentIdentity>,
    /// Native execution is positively parked: agent staleness is suspended.
    pub(crate) parked: bool,
    /// Evaluate guest readiness prerequisites (incl. SSH) while still fenced.
    pub(crate) readiness_probe: bool,
}

/// Read-only lifecycle admission view.
#[derive(Debug, Clone)]
pub(crate) struct LiveSnapshot {
    pub(crate) state: VmLifecycleState,
    pub(crate) lifecycle: LiveLifecycle,
    pub(crate) ready_identity: Option<ReadyAgentIdentity>,
    pub(crate) observed_identity: Option<ReadyAgentIdentity>,
    /// Baseline narrowed by the current guest evidence.
    pub(crate) live: LiveCapabilityVector,
    pub(crate) guest_rejection: Option<&'static str>,
    pub(crate) backend: LiveBackend,
    pub(crate) lane: LiveLane,
    /// Most recent guest lifecycle status from the current identity.
    pub(crate) guest_lifecycle: Option<protocol::v1::GuestLifecycleStatus>,
}

#[derive(Debug, Clone)]
struct State {
    machine_id: String,
    name: String,
    actual_backend: String,
    monitor_id: String,
    live: LiveMachineReport,
    vm_state: VmState,
    vm_changed_at: SystemTime,
    running_since: Option<SystemTime>,
    vm_code: Option<String>,
    vm_message: Option<String>,
    agent_enabled: bool,
    connection: AgentConnection,
    identity: Option<AgentIdentity>,
    status: Option<Observation<AgentStatusReport>>,
    metrics: Option<Observation<(String, AgentMetricReport)>>,
    host_memory_reclaim: Option<HostMemoryReclaim>,
    agent_services: Vec<String>,
    stopping: bool,
    last_log_snapshot: Option<StateLogSnapshot>,
    ssh_epoch: u64,
    ssh_verification: Option<SshVerification>,
    live_lifecycle: LiveLifecycle,
    held_identity: Option<ReadyAgentIdentity>,
    parked_since: Option<Instant>,
    readiness_probe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateLogSnapshot {
    machine_id: String,
    name: String,
    vm_state: VmState,
    vm_message: Option<String>,
    connection_state: Option<AgentConnectionState>,
    connection_message: Option<String>,
    agent_instance_id: Option<String>,
    agent_version: Option<String>,
    agent_boot_id: Option<String>,
    agent_status: Option<AgentStatusState>,
    agent_code: Option<String>,
    agent_message: Option<String>,
    ready: bool,
    readiness_reason: ReadinessReason,
    session_identity: Option<ReadyAgentIdentity>,
}

#[derive(Debug)]
pub(crate) struct InstanceStore {
    state: Mutex<State>,
    generation: watch::Sender<u64>,
    identity_reset: watch::Sender<u64>,
    ready_agent_identity: watch::Sender<Option<ReadyAgentIdentity>>,
}

impl InstanceStore {
    pub(crate) fn new(
        machine_id: String,
        name: String,
        agent_enabled: bool,
        profile: RunLiveProfile,
    ) -> Result<Self, StoreError> {
        let now = SystemTime::now();
        let (generation, _) = watch::channel(0);
        let (identity_reset, _) = watch::channel(0);
        let (ready_agent_identity, _) = watch::channel(None);
        let monitor_id = uuid::Uuid::new_v4().to_string();
        let live = LiveMachineReport {
            schema_version: LIVE_SCHEMA_VERSION,
            scope: LiveScope::Machine,
            machine_id: machine_id.clone(),
            run_id: profile.run_id,
            monitor_id: monitor_id.clone(),
            backend: profile.backend,
            lane: profile.lane,
            topology_revision: 1,
            live: profile.live,
        };
        live.validate().map_err(StoreError::Validation)?;
        let mut state = State {
            machine_id,
            name,
            actual_backend: profile.backend.as_str().to_string(),
            monitor_id,
            live,
            vm_state: VmState::Starting,
            vm_changed_at: now,
            running_since: None,
            vm_code: None,
            vm_message: Some("vm starting".to_string()),
            agent_enabled,
            connection: AgentConnection {
                state: Some(AgentConnectionState::Connecting as i32),
                ..AgentConnection::default()
            },
            identity: None,
            status: None,
            metrics: None,
            host_memory_reclaim: None,
            agent_services: Vec::new(),
            stopping: false,
            last_log_snapshot: None,
            ssh_epoch: 0,
            ssh_verification: None,
            live_lifecycle: LiveLifecycle::default(),
            held_identity: None,
            parked_since: None,
            readiness_probe: false,
        };
        state.last_log_snapshot = Some(state_log_snapshot(&state, Instant::now()));
        Ok(Self {
            state: Mutex::new(state),
            generation,
            identity_reset,
            ready_agent_identity,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    pub(crate) fn subscribe_identity_reset(&self) -> watch::Receiver<u64> {
        self.identity_reset.subscribe()
    }

    pub(crate) fn ready_agent_identity(&self) -> Result<ReadyAgentIdentity, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Poisoned)
            .and_then(|state| {
                ready_agent_identity(&state, Instant::now()).ok_or_else(|| {
                    StoreError::Protocol("a ready guest agent identity is required".to_string())
                })
            })
    }

    /// Shutdown is also needed for a responsive agent whose workloads or SSH
    /// are not ready. Bind to the observed identity, not the readiness policy.
    pub(crate) fn shutdown_agent_identity(&self) -> Result<ReadyAgentIdentity, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        identity_from_state(&state).ok_or_else(|| {
            StoreError::Protocol("an observed guest agent identity is required".to_string())
        })
    }

    pub(crate) fn is_stopping(&self) -> Result<bool, StoreError> {
        self.state
            .lock()
            .map(|state| state.stopping)
            .map_err(|_| StoreError::Poisoned)
    }

    pub(crate) fn subscribe_ready_agent_identity(
        &self,
    ) -> watch::Receiver<Option<ReadyAgentIdentity>> {
        self.ready_agent_identity.subscribe()
    }

    pub(crate) fn status(&self) -> Result<HostStatus, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Poisoned)
            .and_then(|state| project_status(&state, Instant::now(), SystemTime::now()))
    }

    pub(crate) fn metrics(&self) -> Result<HostMetrics, StoreError> {
        self.state
            .lock()
            .map(|state| project_metrics(&state, Instant::now(), SystemTime::now()))
            .map_err(|_| StoreError::Poisoned)
    }

    pub(crate) fn readiness(&self) -> Result<WaitOutcome, StoreError> {
        self.state
            .lock()
            .map(|state| readiness(&state, Instant::now()))
            .map_err(|_| StoreError::Poisoned)
    }

    pub(crate) fn ssh_verification_target(
        &self,
    ) -> Result<Option<Arc<SshVerificationTarget>>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state
            .ssh_verification
            .as_ref()
            .filter(|verification| ssh_target_matches(&state, &verification.target, Instant::now()))
            .map(|verification| Arc::clone(&verification.target)))
    }

    pub(crate) fn complete_ssh_verification(
        &self,
        target: &SshVerificationTarget,
        result: Result<(), String>,
    ) -> Result<(), StoreError> {
        self.mutate_if(|state| {
            let now = Instant::now();
            if !state.ssh_verification.as_ref().is_some_and(|verification| {
                verification.target.as_ref() == target && ssh_target_matches(state, target, now)
            }) {
                return Ok(false);
            }
            let outcome = match result {
                Ok(()) => SshVerificationOutcome::Verified {
                    deadline: now
                        .checked_add(SSH_VERIFICATION_VALIDITY)
                        .ok_or(StoreError::Clock)?,
                },
                Err(message) => SshVerificationOutcome::Failed(truncate(
                    message,
                    protocol::MAX_DIAGNOSTIC_BYTES,
                )),
            };
            let Some(verification) = state.ssh_verification.as_mut() else {
                return Ok(false);
            };
            verification.outcome = outcome;
            Ok(true)
        })
    }

    pub(crate) fn has_identity(&self) -> Result<bool, StoreError> {
        self.state
            .lock()
            .map(|state| state.identity.is_some())
            .map_err(|_| StoreError::Poisoned)
    }

    pub(crate) fn agent_instance_id(&self) -> Result<Option<String>, StoreError> {
        self.state
            .lock()
            .map(|state| {
                state
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.instance_id.clone())
            })
            .map_err(|_| StoreError::Poisoned)
    }

    pub(crate) fn set_vm_state(
        &self,
        vm_state: VmState,
        message: impl Into<String>,
    ) -> Result<(), StoreError> {
        self.mutate(|state| {
            let now = SystemTime::now();
            state.vm_state = vm_state;
            state.vm_changed_at = now;
            state.vm_message = Some(truncate(message.into(), protocol::MAX_DIAGNOSTIC_BYTES));
            if vm_state == VmState::Running && state.running_since.is_none() {
                state.running_since = Some(now);
            }
            state.stopping = matches!(
                vm_state,
                VmState::Stopping | VmState::Stopped | VmState::Failed
            );
            if state.stopping {
                // Stop never resumes: the pause authority ends with the run.
                state.live_lifecycle = LiveLifecycle::default();
                state.held_identity = None;
                state.readiness_probe = false;
                unpark(state, Instant::now());
            }
            Ok(())
        })
    }

    /// Publish one lifecycle transition atomically. Refused (Ok(false)) once
    /// the monitor is stopping, so a late continuation cannot reopen anything.
    pub(crate) fn publish_live(&self, transition: LiveTransition) -> Result<bool, StoreError> {
        transition
            .lifecycle
            .validate_for(transition.state)
            .map_err(StoreError::Validation)?;
        if transition.state.is_stopping_or_terminal()
            || transition.state == VmLifecycleState::Starting
        {
            return Err(StoreError::Validation(
                "live transitions never publish startup or terminal states".into(),
            ));
        }
        let mut published = false;
        self.mutate_if(|state| {
            if state.stopping {
                return Ok(false);
            }
            let now = Instant::now();
            match (transition.parked, state.parked_since) {
                (true, None) => state.parked_since = Some(now),
                (false, Some(_)) => unpark(state, now),
                _ => {}
            }
            let changed_at = SystemTime::now();
            state.vm_state = transition.state.into();
            state.vm_changed_at = changed_at;
            state.vm_message = Some(truncate(transition.message, protocol::MAX_DIAGNOSTIC_BYTES));
            state.live_lifecycle = transition.lifecycle;
            state.held_identity = transition.held_identity;
            state.readiness_probe = transition.readiness_probe;
            published = true;
            Ok(true)
        })?;
        Ok(published)
    }

    pub(crate) fn live_snapshot(&self) -> Result<LiveSnapshot, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        let now = Instant::now();
        let lifecycle_state =
            VmLifecycleState::try_from(state.vm_state).map_err(StoreError::Validation)?;
        let guest_rejection = guest_rejection(&state, now);
        Ok(LiveSnapshot {
            state: lifecycle_state,
            lifecycle: state.live_lifecycle.clone(),
            ready_identity: ready_agent_identity(&state, now),
            observed_identity: identity_from_state(&state),
            live: crate::capabilities::narrow_for_guest(state.live.live.clone(), guest_rejection),
            guest_rejection,
            backend: state.live.backend,
            lane: state.live.lane,
            guest_lifecycle: state
                .status
                .as_ref()
                .and_then(|status| status.value.lifecycle.clone()),
        })
    }

    /// Start of the positive native park suspending agent staleness, if any.
    /// One uninterrupted interval keeps the same start.
    #[cfg(test)]
    pub(crate) fn parked_since(&self) -> Option<Instant> {
        self.state.lock().expect("instance store lock").parked_since
    }

    /// The exact identity, if a status receipt from it arrived strictly after
    /// `since` (the transport re-handshake after native release).
    pub(crate) fn status_identity_since(
        &self,
        since: Instant,
    ) -> Result<Option<ReadyAgentIdentity>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state
            .status
            .as_ref()
            .filter(|status| status.received > since)
            .and_then(|_| identity_from_state(&state)))
    }

    /// Guest readiness prerequisites evaluated as if Running, from receipts
    /// strictly after `since`. Public readiness stays false outside Running.
    pub(crate) fn prospective_readiness(
        &self,
        since: Instant,
    ) -> Result<(bool, ReadinessReason), StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
        let now = Instant::now();
        if state
            .status
            .as_ref()
            .is_some_and(|status| status.received <= since)
            && state.agent_enabled
        {
            return Ok((false, ReadinessReason::AgentStatusStale));
        }
        Ok(running_readiness(&state, now))
    }

    /// Records the latest host memory reclaim report from the backend.
    pub(crate) fn set_host_memory_reclaim(
        &self,
        report: HostMemoryReclaim,
    ) -> Result<(), StoreError> {
        self.mutate(|state| {
            state.host_memory_reclaim = Some(report);
            Ok(())
        })
    }

    pub(crate) fn agent_connecting(&self) -> Result<(), StoreError> {
        self.mutate(|state| {
            if state.agent_enabled {
                state.connection.state = Some(AgentConnectionState::Connecting as i32);
            }
            Ok(())
        })
    }

    pub(crate) fn agent_failure(&self, message: impl Into<String>) -> Result<(), StoreError> {
        self.mutate(|state| {
            if state.agent_enabled {
                state.connection.state = Some(AgentConnectionState::Unresponsive as i32);
                state.connection.last_failure_at = Some(timestamp(SystemTime::now()));
                state.connection.message =
                    Some(truncate(message.into(), protocol::MAX_DIAGNOSTIC_BYTES));
            }
            Ok(())
        })
    }

    pub(crate) fn observe_status(
        &self,
        status: AgentStatus,
        freshness: Duration,
    ) -> Result<(), StoreError> {
        validate_status(&status)?;
        let identity = status
            .identity
            .clone()
            .ok_or_else(|| StoreError::Validation("identity is required".to_string()))?;
        let report = status
            .report
            .ok_or_else(|| StoreError::Validation("report is required".to_string()))?;
        // Keep the guest report intact, but never consume its kex_verified testimony.
        let observation = observation(report, freshness)?;

        self.mutate(|state| {
            // A new receipt cannot revive evidence whose previous receipt expired.
            let now = Instant::now();
            if state
                .status
                .as_ref()
                .is_some_and(|status| !observation_live(state, status.deadline, now))
            {
                invalidate_ssh_verification(state)?;
            }
            if let Some(current) = &state.identity {
                if current.instance_id != identity.instance_id
                    || current.boot_id != identity.boot_id
                {
                    // A new agent instance or boot supersedes every old observation.
                    state.status = None;
                    state.metrics = None;
                    state.agent_services = known_agent_services();
                } else if current.version != identity.version {
                    return Err(StoreError::Protocol(
                        "agent version changed without an instance replacement".to_string(),
                    ));
                }
            }
            let received_at = observation.received_at;
            if state.identity.is_none() {
                state.agent_services = known_agent_services();
            }
            state.identity = Some(identity);
            state.connection.state = Some(AgentConnectionState::Responsive as i32);
            state.connection.last_success_at = Some(timestamp(received_at));
            state.connection.code = None;
            state.connection.message = None;
            state.status = Some(observation);
            Ok(())
        })
    }

    pub(crate) fn observe_metrics(
        &self,
        metrics: AgentMetrics,
        freshness: Duration,
    ) -> Result<(), StoreError> {
        validate_metrics(&metrics)?;
        let instance_id = metrics
            .agent_instance_id
            .clone()
            .ok_or_else(|| StoreError::Validation("agent_instance_id is required".to_string()))?;
        let report = metrics
            .report
            .ok_or_else(|| StoreError::Validation("report is required".to_string()))?;
        let observation = observation((instance_id.clone(), report), freshness)?;

        let (result, before, after) = {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
            let before = state
                .last_log_snapshot
                .clone()
                .unwrap_or_else(|| state_log_snapshot(&state, Instant::now()));
            let Some(identity) = &state.identity else {
                return Err(StoreError::Protocol(
                    "metrics arrived before a current status identity".to_string(),
                ));
            };
            let result = if identity.instance_id.as_deref() != Some(instance_id.as_str()) {
                // Let the status stream establish the replacement identity before metrics resume.
                state.identity = None;
                state.status = None;
                state.metrics = None;
                state.agent_services.clear();
                invalidate_ssh_verification(&mut state)?;
                Err(StoreError::IdentityMismatch)
            } else {
                state.metrics = Some(observation);
                Ok(())
            };
            let after = state_log_snapshot(&state, Instant::now());
            state.last_log_snapshot = Some(after.clone());
            (result, before, after)
        };
        if matches!(result, Err(StoreError::IdentityMismatch)) {
            self.ready_agent_identity
                .send_replace(ready_agent_identity_from_snapshot(&after));
            self.generation
                .send_modify(|generation| *generation = generation.wrapping_add(1));
            self.identity_reset
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        log_state_changes(&before, &after);
        result
    }

    fn mutate(
        &self,
        update: impl FnOnce(&mut State) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.mutate_if(|state| {
            update(state)?;
            Ok(true)
        })
    }

    fn mutate_if(
        &self,
        update: impl FnOnce(&mut State) -> Result<bool, StoreError>,
    ) -> Result<(), StoreError> {
        let (before, after) = {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
            let before = state
                .last_log_snapshot
                .clone()
                .unwrap_or_else(|| state_log_snapshot(&state, Instant::now()));
            if !update(&mut state)? {
                return Ok(());
            }
            refresh_ssh_verification(&mut state, Instant::now())?;
            let after = state_log_snapshot(&state, Instant::now());
            state.last_log_snapshot = Some(after.clone());
            (before, after)
        };
        self.ready_agent_identity
            .send_replace(ready_agent_identity_from_snapshot(&after));
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        log_state_changes(&before, &after);
        Ok(())
    }

    pub(crate) fn set_forward_service(
        &self,
        identity: ReadyAgentIdentity,
        serving: bool,
    ) -> Result<(), StoreError> {
        self.mutate(|state| {
            let Some(current) = &state.identity else {
                return Ok(());
            };
            let current_instance = current
                .instance_id
                .as_deref()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            let current_boot = current
                .boot_id
                .as_deref()
                .and_then(|value| uuid::Uuid::parse_str(value).ok());
            if current_instance != Some(identity.instance_id)
                || current_boot != Some(identity.boot_id)
            {
                return Ok(());
            }
            state.agent_services = known_agent_services();
            if serving {
                state
                    .agent_services
                    .push("silo.v1.GuestForwardService".to_string());
            }
            Ok(())
        })
    }
}

fn known_agent_services() -> Vec<String> {
    [
        "silo.v1.GuestAgentService",
        "silo.v1.GuestFilesystemService",
        "silo.v1.GuestProcessService",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Identity existing sessions are bound to: the ready identity, or while a
/// live lifecycle holds the machine, the identity held at its admission as
/// long as no other identity was observed. `None` means sessions are lost.
fn ready_agent_identity_from_snapshot(snapshot: &StateLogSnapshot) -> Option<ReadyAgentIdentity> {
    snapshot.session_identity.clone()
}

fn session_identity(state: &State, now: Instant) -> Option<ReadyAgentIdentity> {
    if let Some(ready) = ready_agent_identity(state, now) {
        return Some(ready);
    }
    let held = state.held_identity.as_ref()?;
    if !matches!(
        state.vm_state,
        VmState::Pausing | VmState::Paused | VmState::Capturing
    ) {
        return None;
    }
    match identity_from_state(state) {
        Some(observed) if &observed != held => None,
        _ => Some(held.clone()),
    }
}

/// Extends retained receipts by the parked interval so suspended staleness
/// resumes from where it stopped. Expired receipts stay expired.
fn unpark(state: &mut State, now: Instant) {
    let Some(since) = state.parked_since.take() else {
        return;
    };
    let parked = now.saturating_duration_since(since);
    if let Some(status) = state.status.as_mut() {
        extend(status, since, parked);
    }
    if let Some(metrics) = state.metrics.as_mut() {
        extend(metrics, since, parked);
    }
}

fn extend<T>(observation: &mut Observation<T>, since: Instant, parked: Duration) {
    if observation.deadline <= since {
        return;
    }
    if let (Some(deadline), Some(stale_at)) = (
        observation.deadline.checked_add(parked),
        observation.stale_at.checked_add(parked),
    ) {
        observation.deadline = deadline;
        observation.stale_at = stale_at;
    }
}

/// Receipt freshness with staleness suspended only while natively parked.
fn observation_live(state: &State, deadline: Instant, now: Instant) -> bool {
    deadline > now || state.parked_since.is_some_and(|since| deadline > since)
}

/// Positive guest live evidence for a new pause, or the rejection profile.
fn guest_rejection(state: &State, now: Instant) -> Option<&'static str> {
    if !state.agent_enabled {
        return Some("guest-agent-disabled");
    }
    let Some(status) = state.status.as_ref() else {
        return Some("guest-agent-unavailable");
    };
    if identity_from_state(state).is_none() {
        return Some("guest-agent-unavailable");
    }
    if state.stopping || !observation_live(state, status.deadline, now) {
        return Some("guest-status-stale");
    }
    let report = &status.value;
    let pid1 = report.boot.as_ref().is_some_and(|boot| {
        boot.mode == Some(protocol::v1::GuestBootMode::AgentPid1 as i32)
            && boot.agent_is_pid1 == Some(true)
    });
    if !pid1 {
        return Some("guest-not-agent-pid1");
    }
    let Some(lifecycle) = report.lifecycle.as_ref() else {
        return Some("guest-lifecycle-unreported");
    };
    if lifecycle.unsupported_reason.is_some() || lifecycle.workload_roots.is_empty() {
        return Some("guest-containment-unsupported");
    }
    if lifecycle.generation_driver_ready != Some(true) {
        return Some("guest-generation-driver-missing");
    }
    if (!lifecycle.machine_id.is_empty() && lifecycle.machine_id != state.machine_id)
        || (!lifecycle.run_id.is_empty() && lifecycle.run_id != state.live.run_id)
    {
        return Some("guest-lifecycle-identity-mismatch");
    }
    None
}

fn ready_agent_identity(state: &State, now: Instant) -> Option<ReadyAgentIdentity> {
    if !readiness_detail(state, now).0 {
        return None;
    }
    identity_from_state(state)
}

fn identity_from_state(state: &State) -> Option<ReadyAgentIdentity> {
    let identity = state.identity.as_ref()?;
    Some(ReadyAgentIdentity {
        instance_id: uuid::Uuid::parse_str(identity.instance_id.as_deref()?).ok()?,
        boot_id: uuid::Uuid::parse_str(identity.boot_id.as_deref()?).ok()?,
    })
}

fn eligible_ssh(state: &State, now: Instant) -> Option<&protocol::v1::SshListenerReport> {
    if !state.agent_enabled
        || !(state.vm_state == VmState::Running || state.readiness_probe)
        || state.stopping
        || state.connection.state != Some(AgentConnectionState::Responsive as i32)
    {
        return None;
    }
    let status = state.status.as_ref()?;
    if status.deadline <= now || status.value.state != Some(AgentStatusState::Ready as i32) {
        return None;
    }
    status.value.ssh.as_ref().filter(|ssh| ssh.config_verified)
}

fn ssh_target_matches(state: &State, target: &SshVerificationTarget, now: Instant) -> bool {
    state.ssh_epoch == target.epoch
        && identity_from_state(state).as_ref() == Some(&target.identity)
        && eligible_ssh(state, now).is_some_and(|ssh| {
            ssh.backend == target.backend
                && ssh.port == target.port
                && ssh.host_public_key == target.host_public_key
        })
}

fn invalidate_ssh_verification(state: &mut State) -> Result<(), StoreError> {
    if state.ssh_verification.is_some() {
        state.ssh_epoch = state
            .ssh_epoch
            .checked_add(1)
            .ok_or(StoreError::SshEpochExhausted)?;
        state.ssh_verification = None;
    }
    Ok(())
}

fn refresh_ssh_verification(state: &mut State, now: Instant) -> Result<(), StoreError> {
    if state
        .ssh_verification
        .as_ref()
        .is_some_and(|verification| ssh_target_matches(state, &verification.target, now))
    {
        return Ok(());
    }
    invalidate_ssh_verification(state)?;
    let Some(ssh) = eligible_ssh(state, now) else {
        return Ok(());
    };
    let Some(identity) = identity_from_state(state) else {
        return Ok(());
    };
    let epoch = state
        .ssh_epoch
        .checked_add(1)
        .ok_or(StoreError::SshEpochExhausted)?;
    let target = Arc::new(SshVerificationTarget {
        epoch,
        identity,
        backend: ssh.backend.clone(),
        port: ssh.port,
        host_public_key: ssh.host_public_key.clone(),
    });
    state.ssh_epoch = epoch;
    state.ssh_verification = Some(SshVerification {
        target,
        outcome: SshVerificationOutcome::Pending,
    });
    Ok(())
}

/// Borrow the guest report, overriding only host-derived SSH readiness.
struct EffectiveStatus<'a> {
    state: Option<i32>,
    code: Option<&'a str>,
    message: Option<&'a str>,
    kex_verified: bool,
}

fn effective_status<'a>(
    state: &'a State,
    report: &'a AgentStatusReport,
    now: Instant,
) -> EffectiveStatus<'a> {
    let verification = state
        .ssh_verification
        .as_ref()
        .filter(|verification| ssh_target_matches(state, &verification.target, now));
    let kex_verified = verification.is_some_and(|verification| {
        matches!(verification.outcome, SshVerificationOutcome::Verified { deadline } if deadline > now)
    });
    if report.state == Some(AgentStatusState::Ready as i32) && report.ssh.is_some() && !kex_verified
    {
        let message = match verification.map(|verification| &verification.outcome) {
            Some(SshVerificationOutcome::Failed(message)) => message.as_str(),
            _ => SSH_VERIFICATION_PENDING,
        };
        EffectiveStatus {
            state: Some(AgentStatusState::Starting as i32),
            code: Some("SSH_NOT_READY"),
            message: Some(message),
            kex_verified,
        }
    } else {
        EffectiveStatus {
            state: report.state,
            code: report.code.as_deref(),
            message: report.message.as_deref(),
            kex_verified,
        }
    }
}

#[cfg(test)]
pub(crate) fn new_instance_store(
    machine_id: String,
    name: String,
    agent_enabled: bool,
) -> InstanceStore {
    new_instance_store_with_backend(machine_id, name, agent_enabled, "mock".to_string())
}

#[cfg(test)]
pub(crate) fn new_instance_store_with_backend(
    machine_id: String,
    name: String,
    agent_enabled: bool,
    actual_backend: String,
) -> InstanceStore {
    let backend = match actual_backend.as_str() {
        "krun" => LiveBackend::Krun,
        "vz" => LiveBackend::Vz,
        _ => LiveBackend::Mock,
    };
    let lane = if backend == LiveBackend::Krun {
        LiveLane::KvmX86_64
    } else {
        LiveLane::NotApplicable
    };
    InstanceStore::new(
        machine_id,
        name,
        agent_enabled,
        RunLiveProfile {
            run_id: uuid::Uuid::new_v4().to_string(),
            backend,
            lane,
            live: LiveCapabilityVector::all_unsupported(if backend == LiveBackend::Krun {
                vm_spec::live::LiveReasonCode::NotDelivered
            } else {
                vm_spec::live::LiveReasonCode::BackendExcluded
            }),
        },
    )
    .expect("valid test state")
}

fn observation<T>(value: T, freshness: Duration) -> Result<Observation<T>, StoreError> {
    let received_at = SystemTime::now();
    let stale_at = received_at
        .checked_add(freshness)
        .ok_or(StoreError::Clock)?;
    let received = Instant::now();
    let deadline = received.checked_add(freshness).ok_or(StoreError::Clock)?;
    Ok(Observation {
        received_at,
        received,
        stale_at,
        deadline,
        value,
    })
}

fn state_log_snapshot(state: &State, now: Instant) -> StateLogSnapshot {
    let (ready, readiness_reason) = readiness_detail(state, now);
    let identity = state.identity.as_ref();
    let report = state
        .status
        .as_ref()
        .map(|status| effective_status(state, &status.value, now));
    StateLogSnapshot {
        machine_id: state.machine_id.clone(),
        name: state.name.clone(),
        vm_state: state.vm_state,
        vm_message: state.vm_message.clone(),
        connection_state: state
            .connection
            .state
            .and_then(|value| AgentConnectionState::try_from(value).ok()),
        connection_message: state.connection.message.clone(),
        agent_instance_id: identity.and_then(|identity| identity.instance_id.clone()),
        agent_version: identity.and_then(|identity| identity.version.clone()),
        agent_boot_id: identity.and_then(|identity| identity.boot_id.clone()),
        agent_status: report
            .as_ref()
            .and_then(|report| report.state)
            .and_then(|value| AgentStatusState::try_from(value).ok()),
        agent_code: report
            .as_ref()
            .and_then(|report| report.code.map(str::to_owned)),
        agent_message: report
            .as_ref()
            .and_then(|report| report.message.map(str::to_owned)),
        ready,
        readiness_reason,
        session_identity: session_identity(state, now),
    }
}

fn log_state_changes(before: &StateLogSnapshot, after: &StateLogSnapshot) {
    if before.vm_state != after.vm_state || before.vm_message != after.vm_message {
        tracing::info!(
            instance = %after.name,
            machine_id = %after.machine_id,
            previous = ?before.vm_state,
            current = ?after.vm_state,
            message = ?after.vm_message,
            "vm state changed"
        );
    }

    if before.connection_state != after.connection_state {
        match (before.connection_state, after.connection_state) {
            (_, Some(AgentConnectionState::Responsive)) => tracing::info!(
                instance = %after.name,
                machine_id = %after.machine_id,
                agent_instance_id = ?after.agent_instance_id,
                agent_version = ?after.agent_version,
                agent_boot_id = ?after.agent_boot_id,
                "guest agent became responsive"
            ),
            (Some(AgentConnectionState::Responsive), _) => tracing::warn!(
                instance = %after.name,
                machine_id = %after.machine_id,
                previous = ?before.connection_state,
                current = ?after.connection_state,
                message = ?after.connection_message,
                "guest agent connection lost"
            ),
            _ => tracing::debug!(
                instance = %after.name,
                machine_id = %after.machine_id,
                previous = ?before.connection_state,
                current = ?after.connection_state,
                message = ?after.connection_message,
                "guest agent connection state changed"
            ),
        }
    }

    let identity_changed = before.agent_instance_id != after.agent_instance_id
        || before.agent_version != after.agent_version
        || before.agent_boot_id != after.agent_boot_id;
    if before.agent_instance_id.is_some() && identity_changed {
        tracing::info!(
            instance = %after.name,
            machine_id = %after.machine_id,
            previous_agent_instance_id = ?before.agent_instance_id,
            agent_instance_id = ?after.agent_instance_id,
            agent_version = ?after.agent_version,
            agent_boot_id = ?after.agent_boot_id,
            "guest agent identity changed"
        );
    }

    if before.agent_status != after.agent_status
        || before.agent_code != after.agent_code
        || before.agent_message != after.agent_message
    {
        tracing::info!(
            instance = %after.name,
            machine_id = %after.machine_id,
            previous = ?before.agent_status,
            current = ?after.agent_status,
            code = ?after.agent_code,
            message = ?after.agent_message,
            "guest agent status changed"
        );
    }

    if before.ready != after.ready || before.readiness_reason != after.readiness_reason {
        tracing::info!(
            instance = %after.name,
            machine_id = %after.machine_id,
            previous_ready = before.ready,
            ready = after.ready,
            previous_reason = ?before.readiness_reason,
            reason = ?after.readiness_reason,
            "silo-vmm readiness changed"
        );
    }
}

fn validate_status(status: &AgentStatus) -> Result<(), StoreError> {
    let identity = status
        .identity
        .as_ref()
        .ok_or_else(|| invalid("identity is required"))?;
    validate_identity(identity)?;
    let report = status
        .report
        .as_ref()
        .ok_or_else(|| invalid("report is required"))?;
    validate_status_report(report)
}

fn validate_identity(identity: &AgentIdentity) -> Result<(), StoreError> {
    for (field, value) in [
        ("instance_id", &identity.instance_id),
        ("boot_id", &identity.boot_id),
    ] {
        let value = required(field, value, 36)?;
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| invalid(&format!("{field} must be a UUID")))?;
        if parsed.hyphenated().to_string() != value {
            return Err(invalid(&format!(
                "{field} must be a canonical lowercase UUID"
            )));
        }
    }
    required("version", &identity.version, protocol::MAX_INFO_BYTES)?;
    Ok(())
}

fn validate_status_report(report: &AgentStatusReport) -> Result<(), StoreError> {
    if let Some(ssh) = &report.ssh {
        if !matches!(
            ssh.backend.as_str(),
            "native" | "openssh" | "systemd-openssh"
        ) || ssh.port != 22
            || !ssh.config_verified
            || russh::keys::PublicKey::from_openssh(&ssh.host_public_key).is_err()
        {
            return Err(invalid("invalid SSH listener descriptor"));
        }
    }
    validate_timestamp("status.observed_at", report.observed_at.as_ref())?;
    let state = required_enum::<AgentStatusState>("status.state", report.state)?;
    optional("status.code", &report.code, protocol::MAX_CODE_BYTES)?;
    optional(
        "status.message",
        &report.message,
        protocol::MAX_DIAGNOSTIC_BYTES,
    )?;
    match state {
        AgentStatusState::Starting => match (&report.code, &report.message) {
            (None, None) => {}
            (Some(_), Some(_)) => {
                required("status.code", &report.code, protocol::MAX_CODE_BYTES)?;
                required(
                    "status.message",
                    &report.message,
                    protocol::MAX_DIAGNOSTIC_BYTES,
                )?;
            }
            _ => {
                return Err(invalid(
                    "starting status code and message must both be present or both be absent",
                ));
            }
        },
        AgentStatusState::Ready => {
            if report.code.is_some() || report.message.is_some() {
                return Err(invalid("ready status must not contain code or message"));
            }
        }
        AgentStatusState::Failed => {
            required("status.code", &report.code, protocol::MAX_CODE_BYTES)?;
            required(
                "status.message",
                &report.message,
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?;
        }
        AgentStatusState::Unspecified => return Err(invalid("status.state must be specified")),
    }
    if let Some(system) = &report.system {
        for (field, value) in [
            ("system.kernel_version", &system.kernel_version),
            ("system.os_name", &system.os_name),
            ("system.os_version", &system.os_version),
            ("system.architecture", &system.architecture),
            ("system.hostname", &system.hostname),
        ] {
            optional(field, value, protocol::MAX_INFO_BYTES)?;
        }
        if system.ip_addresses.len() > protocol::MAX_AGENT_IP_ADDRESSES {
            return Err(invalid(
                "system.ip_addresses exceeds the maximum cardinality",
            ));
        }
        for address in &system.ip_addresses {
            text(
                "system.ip_addresses",
                address,
                protocol::MAX_INFO_BYTES,
                true,
            )?;
            let parsed = address
                .parse::<std::net::IpAddr>()
                .map_err(|_| invalid("system.ip_addresses contains an invalid IP address"))?;
            if parsed.to_string() != *address {
                return Err(invalid(
                    "system.ip_addresses must use canonical textual representation",
                ));
            }
        }
    }
    if let Some(boot) = &report.boot {
        let mode = required_enum::<protocol::v1::GuestBootMode>("boot.mode", boot.mode)?;
        if mode == protocol::v1::GuestBootMode::Unspecified {
            return Err(invalid("boot.mode must be specified"));
        }
        for (field, value) in [
            ("boot.requested_init", &boot.requested_init),
            ("boot.handoff_init_path", &boot.handoff_init_path),
            ("boot.agent_path", &boot.agent_path),
            ("boot.message", &boot.message),
        ] {
            optional(field, value, protocol::MAX_INFO_BYTES)?;
        }
        if boot.probed_init_paths.len() > protocol::MAX_PROBED_INIT_PATHS {
            return Err(invalid(
                "boot.probed_init_paths exceeds the maximum cardinality",
            ));
        }
        for path in &boot.probed_init_paths {
            text(
                "boot.probed_init_paths",
                path,
                protocol::MAX_PATH_BYTES,
                true,
            )?;
        }
    }
    if let Some(provisioning) = &report.provisioning {
        let overall = required_enum::<protocol::v1::ProvisionOverallStatus>(
            "provisioning.status",
            provisioning.status,
        )?;
        if overall == protocol::v1::ProvisionOverallStatus::Unspecified {
            return Err(invalid("provisioning.status must be specified"));
        }
        let started =
            validate_timestamp("provisioning.started_at", provisioning.started_at.as_ref())?;
        let finished = validate_timestamp(
            "provisioning.finished_at",
            provisioning.finished_at.as_ref(),
        )?;
        if finished < started {
            return Err(invalid(
                "provisioning.finished_at precedes provisioning.started_at",
            ));
        }
        validate_duration("provisioning.duration", provisioning.duration.as_ref())?;
        optional(
            "provisioning.message",
            &provisioning.message,
            protocol::MAX_DIAGNOSTIC_BYTES,
        )?;
        if provisioning.steps.len() > protocol::MAX_PROVISIONING_STEPS {
            return Err(invalid(
                "provisioning.steps exceeds the maximum cardinality",
            ));
        }
        let mut ids = HashSet::new();
        for step in &provisioning.steps {
            let id = required("provisioning.steps.id", &step.id, protocol::MAX_INFO_BYTES)?;
            if !ids.insert(id) {
                return Err(invalid("provisioning step IDs must be unique"));
            }
            let state = required_enum::<protocol::v1::ProvisionStepStatus>(
                "provisioning.steps.status",
                step.status,
            )?;
            let policy = required_enum::<protocol::v1::ProvisionFailurePolicy>(
                "provisioning.steps.failure_policy",
                step.failure_policy,
            )?;
            if matches!(state, protocol::v1::ProvisionStepStatus::Unspecified)
                || matches!(policy, protocol::v1::ProvisionFailurePolicy::Unspecified)
            {
                return Err(invalid("provisioning step enums must be specified"));
            }
            for (field, value) in [
                ("provisioning.steps.backend", &step.backend),
                ("provisioning.steps.message", &step.message),
                ("provisioning.steps.error_chain", &step.error_chain),
            ] {
                optional(field, value, protocol::MAX_DIAGNOSTIC_BYTES)?;
            }
            validate_duration("provisioning.steps.duration", step.duration.as_ref())?;
        }
    }
    Ok(())
}

fn validate_metrics(metrics: &AgentMetrics) -> Result<(), StoreError> {
    required("agent_instance_id", &metrics.agent_instance_id, 36).and_then(|value| {
        uuid::Uuid::parse_str(value).map_err(|_| invalid("agent_instance_id must be a UUID"))
    })?;
    let report = metrics
        .report
        .as_ref()
        .ok_or_else(|| invalid("report is required"))?;
    validate_timestamp("metrics.observed_at", report.observed_at.as_ref())?;
    let snapshot = report
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("metrics.snapshot is required"))?;
    if let Some(root) = &snapshot.root_storage {
        protocol::validate_root_storage_metrics(root).map_err(|error| invalid(&error))?;
    }
    if let Some(memory) = &snapshot.memory {
        let total = memory
            .total_bytes
            .ok_or_else(|| invalid("metrics.memory.total_bytes is required"))?;
        let available = memory
            .available_bytes
            .ok_or_else(|| invalid("metrics.memory.available_bytes is required"))?;
        if available > total {
            return Err(invalid(
                "metrics.memory.available_bytes exceeds total_bytes",
            ));
        }
    }
    if let Some(cpu) = &snapshot.cpu {
        if cpu.logical_cpu_count.unwrap_or_default() == 0 {
            return Err(invalid("metrics.cpu.logical_cpu_count must be positive"));
        }
        for (field, value) in [
            ("user_seconds", cpu.user_seconds),
            ("nice_seconds", cpu.nice_seconds),
            ("system_seconds", cpu.system_seconds),
            ("idle_seconds", cpu.idle_seconds),
            ("iowait_seconds", cpu.iowait_seconds),
            ("irq_seconds", cpu.irq_seconds),
            ("softirq_seconds", cpu.softirq_seconds),
            ("steal_seconds", cpu.steal_seconds),
        ] {
            finite_nonnegative(&format!("metrics.cpu.{field}"), value)?;
        }
    }
    if let Some(load) = &snapshot.load_average {
        for (field, value) in [
            ("one_minute", load.one_minute),
            ("five_minutes", load.five_minutes),
            ("fifteen_minutes", load.fifteen_minutes),
        ] {
            finite_nonnegative(&format!("metrics.load_average.{field}"), value)?;
        }
    }
    if snapshot.uptime_seconds.is_some() {
        finite_nonnegative("metrics.uptime_seconds", snapshot.uptime_seconds)?;
    }
    validate_named_metrics(
        "filesystems",
        &snapshot.filesystems,
        |metric| metric.mount_point.as_deref(),
        |metric| {
            optional(
                "metrics.filesystems.filesystem_type",
                &metric.filesystem_type,
                protocol::MAX_INFO_BYTES,
            )?;
            totals(
                "metrics.filesystems",
                metric.total_bytes,
                metric.used_bytes,
                metric.available_bytes,
            )
        },
    )?;
    validate_named_metrics(
        "network_interfaces",
        &snapshot.network_interfaces,
        |metric| metric.name.as_deref(),
        |metric| {
            optional(
                "metrics.network_interfaces.mac",
                &metric.mac,
                protocol::MAX_INFO_BYTES,
            )?;
            if let Some(mac) = &metric.mac {
                validate_mac(mac)?;
            }
            if metric.receive_bytes.is_none() || metric.transmit_bytes.is_none() {
                return Err(invalid(
                    "metrics.network_interfaces byte counters are required",
                ));
            }
            Ok(())
        },
    )?;
    validate_named_metrics(
        "block_devices",
        &snapshot.block_devices,
        |metric| metric.name.as_deref(),
        |metric| {
            for (field, value) in [
                ("read_bytes", metric.read_bytes),
                ("read_operations", metric.read_operations),
                ("write_bytes", metric.write_bytes),
                ("write_operations", metric.write_operations),
                ("in_flight_operations", metric.in_flight_operations),
            ] {
                if value.is_none() {
                    return Err(invalid(&format!(
                        "metrics.block_devices.{field} is required"
                    )));
                }
            }
            Ok(())
        },
    )
}

fn validate_named_metrics<T>(
    kind: &str,
    values: &[T],
    name: impl Fn(&T) -> Option<&str>,
    validate: impl Fn(&T) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    if values.len() > protocol::MAX_METRIC_ARRAY_ENTRIES {
        return Err(invalid(&format!(
            "metrics.{kind} exceeds the maximum cardinality"
        )));
    }
    let mut names = HashSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        let name =
            name(value).ok_or_else(|| invalid(&format!("metrics.{kind}.name is required")))?;
        text(
            &format!("metrics.{kind}.name"),
            name,
            protocol::MAX_INFO_BYTES,
            true,
        )?;
        if !names.insert(name) {
            return Err(invalid(&format!("metrics.{kind} names must be unique")));
        }
        if previous.is_some_and(|previous| previous.as_bytes() >= name.as_bytes()) {
            return Err(invalid(&format!("metrics.{kind} must be sorted by name")));
        }
        previous = Some(name);
        validate(value)?;
    }
    Ok(())
}

fn validate_mac(value: &str) -> Result<(), StoreError> {
    let mut parts = value.split(':');
    for _ in 0..6 {
        let part = parts
            .next()
            .ok_or_else(|| invalid("metrics.network_interfaces.mac is invalid"))?;
        if part.len() != 2
            || !part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(
                "metrics.network_interfaces.mac must be canonical lowercase hexadecimal",
            ));
        }
    }
    if parts.next().is_some() {
        return Err(invalid("metrics.network_interfaces.mac is invalid"));
    }
    Ok(())
}

fn totals(
    field: &str,
    total: Option<u64>,
    used: Option<u64>,
    available: Option<u64>,
) -> Result<(), StoreError> {
    let total = total.ok_or_else(|| invalid(&format!("{field}.total_bytes is required")))?;
    let used = used.ok_or_else(|| invalid(&format!("{field}.used_bytes is required")))?;
    let available =
        available.ok_or_else(|| invalid(&format!("{field}.available_bytes is required")))?;
    if used.checked_add(available).is_none_or(|sum| sum > total) {
        return Err(invalid(&format!(
            "{field} used_bytes plus available_bytes exceeds total_bytes"
        )));
    }
    Ok(())
}

fn finite_nonnegative(field: &str, value: Option<f64>) -> Result<(), StoreError> {
    let value = value.ok_or_else(|| invalid(&format!("{field} is required")))?;
    if !value.is_finite() || value < 0.0 {
        return Err(invalid(&format!("{field} must be finite and nonnegative")));
    }
    Ok(())
}

fn required_enum<T>(field: &str, value: Option<i32>) -> Result<T, StoreError>
where
    T: TryFrom<i32>,
{
    T::try_from(value.ok_or_else(|| invalid(&format!("{field} is required")))?)
        .map_err(|_| invalid(&format!("{field} is invalid")))
}

fn validate_timestamp(field: &str, value: Option<&Timestamp>) -> Result<i128, StoreError> {
    let value = value.ok_or_else(|| invalid(&format!("{field} is required")))?;
    if !(TIMESTAMP_MIN_SECONDS..=TIMESTAMP_MAX_SECONDS).contains(&value.seconds)
        || !(0..1_000_000_000).contains(&value.nanos)
    {
        return Err(invalid(&format!("{field} is invalid")));
    }
    Ok(i128::from(value.seconds) * 1_000_000_000 + i128::from(value.nanos))
}

fn validate_duration(field: &str, value: Option<&prost_types::Duration>) -> Result<(), StoreError> {
    let value = value.ok_or_else(|| invalid(&format!("{field} is required")))?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(invalid(&format!("{field} is invalid")));
    }
    Ok(())
}

fn required<'a>(
    field: &str,
    value: &'a Option<String>,
    maximum: usize,
) -> Result<&'a str, StoreError> {
    let value = value
        .as_deref()
        .ok_or_else(|| invalid(&format!("{field} is required")))?;
    text(field, value, maximum, true)?;
    Ok(value)
}

fn optional(field: &str, value: &Option<String>, maximum: usize) -> Result<(), StoreError> {
    if let Some(value) = value {
        text(field, value, maximum, false)?;
    }
    Ok(())
}

fn text(field: &str, value: &str, maximum: usize, nonempty: bool) -> Result<(), StoreError> {
    if (nonempty && value.is_empty()) || value.len() > maximum {
        return Err(invalid(&format!("{field} has an invalid length")));
    }
    Ok(())
}

fn invalid(message: &str) -> StoreError {
    StoreError::Validation(message.to_string())
}

fn truncate(value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn readiness(state: &State, now: Instant) -> WaitOutcome {
    if matches!(state.vm_state, VmState::Stopped | VmState::Failed) {
        return WaitOutcome::Terminal;
    }
    let ready = readiness_detail(state, now).0;
    if ready {
        WaitOutcome::Ready
    } else {
        WaitOutcome::TimedOut
    }
}

fn project_status(
    state: &State,
    now: Instant,
    observed_at: SystemTime,
) -> Result<HostStatus, StoreError> {
    let mut live = state.live.clone();
    live.live = crate::capabilities::narrow_for_guest(live.live, guest_rejection(state, now));
    let live = live.try_into().map_err(StoreError::Validation)?;
    let (ready, reason) = readiness_detail(state, now);
    let agent = if state.agent_enabled {
        HostAgent {
            mode: Some(protocol::v1::host_agent::Mode::Enabled(EnabledAgent {
                connection: Some(state.connection.clone()),
                identity: state.identity.clone(),
                status: state
                    .status
                    .as_ref()
                    .map(|status| status_observation(state, status, now)),
                services: state.agent_services.clone(),
            })),
        }
    } else {
        HostAgent {
            mode: Some(protocol::v1::host_agent::Mode::Disabled(DisabledAgent {})),
        }
    };
    Ok(HostStatus {
        run_id: Some(state.live.run_id.clone()),
        live: Some(live),
        machine_id: Some(state.machine_id.clone()),
        name: Some(state.name.clone()),
        monitor: Some(MonitorSnapshot {
            instance_id: Some(state.monitor_id.clone()),
            observed_at: Some(timestamp(observed_at)),
        }),
        vm: Some(VmSnapshot {
            state: Some(state.vm_state as i32),
            state_changed_at: Some(timestamp(state.vm_changed_at)),
            running_since: state.running_since.map(timestamp),
            code: state.vm_code.clone(),
            message: state.vm_message.clone(),
        }),
        readiness: Some(Readiness {
            ready: Some(ready),
            reason: Some(reason as i32),
        }),
        agent: Some(agent),
        lifecycle: Some(state.live_lifecycle.clone().into()),
    })
}

fn project_metrics(state: &State, now: Instant, observed_at: SystemTime) -> HostMetrics {
    HostMetrics {
        machine_id: Some(state.machine_id.clone()),
        name: Some(state.name.clone()),
        monitor: Some(MonitorSnapshot {
            instance_id: Some(state.monitor_id.clone()),
            observed_at: Some(timestamp(observed_at)),
        }),
        metrics: state
            .metrics
            .as_ref()
            .map(|metrics| AgentMetricsObservation {
                agent_instance_id: Some(metrics.value.0.clone()),
                received_at: Some(timestamp(metrics.received_at)),
                stale_at: Some(timestamp(metrics.stale_at)),
                freshness: Some(freshness(state, metrics.deadline, now) as i32),
                stale_reason: stale_reason(state, metrics.deadline, now)
                    .map(|reason| reason as i32),
                report: Some(metrics.value.1.clone()),
            }),
        actual_backend: Some(state.actual_backend.clone()),
        host_memory_reclaim: state.host_memory_reclaim.clone(),
    }
}

fn status_observation(
    state: &State,
    status: &Observation<AgentStatusReport>,
    now: Instant,
) -> AgentStatusObservation {
    let effective = effective_status(state, &status.value, now);
    let mut report = status.value.clone();
    report.state = effective.state;
    report.code = effective.code.map(str::to_owned);
    report.message = effective.message.map(str::to_owned);
    if let Some(ssh) = &mut report.ssh {
        ssh.kex_verified = effective.kex_verified;
    }
    AgentStatusObservation {
        received_at: Some(timestamp(status.received_at)),
        stale_at: Some(timestamp(status.stale_at)),
        freshness: Some(freshness(state, status.deadline, now) as i32),
        stale_reason: stale_reason(state, status.deadline, now).map(|reason| reason as i32),
        report: Some(report),
    }
}

fn freshness(state: &State, deadline: Instant, now: Instant) -> Freshness {
    if !state.stopping && observation_live(state, deadline, now) {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}
fn stale_reason(state: &State, deadline: Instant, now: Instant) -> Option<StaleReason> {
    (!matches!(freshness(state, deadline, now), Freshness::Fresh)).then_some(if state.stopping {
        StaleReason::MonitorStopping
    } else {
        StaleReason::ReceiptAge
    })
}

fn readiness_detail(state: &State, now: Instant) -> (bool, ReadinessReason) {
    match state.vm_state {
        VmState::Starting | VmState::Unspecified => (false, ReadinessReason::VmStarting),
        VmState::Stopping => (false, ReadinessReason::VmStopping),
        VmState::Stopped => (false, ReadinessReason::VmStopped),
        VmState::Failed => (false, ReadinessReason::VmFailed),
        VmState::Pausing => (false, ReadinessReason::VmPausing),
        VmState::Paused => (false, ReadinessReason::VmPaused),
        VmState::Capturing => (false, ReadinessReason::VmCapturing),
        VmState::Restoring => (false, ReadinessReason::VmRestoring),
        VmState::Activating => (false, ReadinessReason::VmActivating),
        VmState::ActivationFailed => (false, ReadinessReason::VmActivationFailed),
        VmState::Error => (false, ReadinessReason::VmError),
        VmState::Running => running_readiness(state, now),
    }
}

/// Readiness of a running machine: agent evidence and host-verified SSH.
fn running_readiness(state: &State, now: Instant) -> (bool, ReadinessReason) {
    if !state.agent_enabled {
        return (true, ReadinessReason::AgentNotRequired);
    }
    match &state.status {
        Some(status) if state.stopping || status.deadline <= now => {
            (false, ReadinessReason::AgentStatusStale)
        }
        Some(status) => match effective_status(state, &status.value, now)
            .state
            .and_then(|value| AgentStatusState::try_from(value).ok())
        {
            Some(AgentStatusState::Starting) => (false, ReadinessReason::GuestStarting),
            Some(AgentStatusState::Failed) => (false, ReadinessReason::GuestFailed),
            Some(AgentStatusState::Ready) => (true, ReadinessReason::GuestReportedReady),
            _ => (false, ReadinessReason::AgentUnavailable),
        },
        None => (false, ReadinessReason::AgentUnavailable),
    }
}

fn timestamp(time: SystemTime) -> Timestamp {
    time.into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn stale_ready_report_is_retained_but_current_readiness_is_false() {
        let store = crate::state::new_instance_store(
            uuid::Uuid::new_v4().to_string(),
            "stale-test".into(),
            true,
        );
        store
            .set_vm_state(protocol::v1::VmState::Running, "running")
            .unwrap();
        store
            .observe_status(
                ready_status(&uuid::Uuid::new_v4().to_string()),
                std::time::Duration::ZERO,
            )
            .unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.readiness.unwrap().ready, Some(false));
        let Some(protocol::v1::host_agent::Mode::Enabled(agent)) = status.agent.unwrap().mode
        else {
            panic!("enabled agent");
        };
        let observation = agent.status.unwrap();
        assert_eq!(
            observation.freshness,
            Some(protocol::v1::Freshness::Stale as i32)
        );
        assert_eq!(
            observation.report.unwrap().state,
            Some(protocol::v1::AgentStatusState::Ready as i32)
        );
    }
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use protocol::v1::{
        AgentIdentity, AgentStatus, AgentStatusReport, AgentStatusState, ReadinessReason, VmState,
    };

    use crate::state::{
        new_instance_store, InstanceStore, RunLiveProfile, StateLogSnapshot, StoreError,
        WaitOutcome,
    };
    use protocol::v1::Freshness;
    use vm_spec::lifecycle::{LiveLifecycle, VmLifecycleState};
    use vm_spec::live::{LiveBackend, LiveCapabilityVector, LiveLane, LiveMachineReport};

    fn ready_status(instance: &str) -> AgentStatus {
        AgentStatus {
            identity: Some(AgentIdentity {
                instance_id: Some(instance.to_string()),
                version: Some("test".to_string()),
                boot_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
            }),
            report: Some(AgentStatusReport {
                observed_at: Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                state: Some(AgentStatusState::Ready as i32),
                ..AgentStatusReport::default()
            }),
        }
    }

    #[test]
    fn ssh_readiness_requires_valid_configuration_and_actual_kex() {
        let mut report = ready_status("test").report.unwrap();
        let key = russh::keys::PrivateKey::from(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]),
        );
        report.ssh = Some(protocol::v1::SshListenerReport {
            backend: "native".into(),
            port: 22,
            host_public_key: key.public_key().to_openssh().unwrap(),
            config_verified: true,
            kex_verified: false,
        });
        assert!(crate::state::validate_status_report(&report).is_ok());
        report.state = Some(AgentStatusState::Starting as i32);
        assert!(crate::state::validate_status_report(&report).is_ok());
        report.ssh.as_mut().unwrap().kex_verified = true;
        report.state = Some(AgentStatusState::Ready as i32);
        assert!(crate::state::validate_status_report(&report).is_ok());
        report.ssh.as_mut().unwrap().config_verified = false;
        assert!(crate::state::validate_status_report(&report).is_err());
        report.ssh.as_mut().unwrap().config_verified = true;
        report.ssh.as_mut().unwrap().backend = "unsupported".into();
        assert!(crate::state::validate_status_report(&report).is_err());
        report.ssh.as_mut().unwrap().backend = "native".into();
        report.ssh.as_mut().unwrap().port = 23;
        assert!(crate::state::validate_status_report(&report).is_err());
        report.ssh.as_mut().unwrap().port = 22;
        report.ssh.as_mut().unwrap().host_public_key = "corrupt".into();
        assert!(crate::state::validate_status_report(&report).is_err());
    }

    const SSH_INSTANCE: &str = "00000000-0000-4000-8000-000000000002";

    fn ssh_status(seed: u8) -> AgentStatus {
        let mut status = ready_status(SSH_INSTANCE);
        let key = russh::keys::PrivateKey::from(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]),
        );
        status.report.as_mut().unwrap().ssh = Some(protocol::v1::SshListenerReport {
            backend: "openssh".into(),
            port: 22,
            host_public_key: key.public_key().to_openssh().unwrap(),
            config_verified: true,
            // Deliberately untrusted guest testimony.
            kex_verified: true,
        });
        status
    }

    fn ssh_store() -> InstanceStore {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "ssh-test".into(), true);
        store.set_vm_state(VmState::Running, "running").unwrap();
        store
            .observe_status(ssh_status(1), Duration::from_secs(300))
            .unwrap();
        store
    }

    fn projected_report(store: &InstanceStore) -> AgentStatusReport {
        let status = store.status().unwrap();
        let Some(protocol::v1::host_agent::Mode::Enabled(agent)) = status.agent.unwrap().mode
        else {
            panic!("enabled agent required");
        };
        agent.status.unwrap().report.unwrap()
    }

    fn metrics_for(instance: &str) -> protocol::v1::AgentMetrics {
        protocol::v1::AgentMetrics {
            agent_instance_id: Some(instance.into()),
            report: Some(protocol::v1::AgentMetricReport {
                observed_at: Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                snapshot: Some(protocol::v1::MetricSnapshot::default()),
            }),
        }
    }

    #[test]
    fn host_evidence_controls_every_readiness_projection_and_notifications() {
        let store = ssh_store();
        let target = store.ssh_verification_target().unwrap().unwrap();
        let mut generation = store.subscribe();
        let mut identity = store.subscribe_ready_agent_identity();
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        assert!(store.ready_agent_identity().is_err());
        assert!(identity.borrow().is_none());
        let pending = projected_report(&store);
        assert_eq!(pending.state, Some(AgentStatusState::Starting as i32));
        assert_eq!(pending.code.as_deref(), Some("SSH_NOT_READY"));
        assert_eq!(
            pending.message.as_deref(),
            Some(crate::state::SSH_VERIFICATION_PENDING)
        );
        assert!(!pending.ssh.unwrap().kex_verified);
        assert_eq!(
            logged_snapshot(&store).agent_status,
            Some(AgentStatusState::Starting)
        );
        let mut unverified_guest = ssh_status(1);
        unverified_guest
            .report
            .as_mut()
            .unwrap()
            .ssh
            .as_mut()
            .unwrap()
            .kex_verified = false;
        store
            .observe_status(unverified_guest, Duration::from_secs(300))
            .unwrap();
        assert!(Arc::ptr_eq(
            &target,
            &store.ssh_verification_target().unwrap().unwrap()
        ));
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);

        store.complete_ssh_verification(&target, Ok(())).unwrap();
        assert!(generation.has_changed().unwrap());
        generation.borrow_and_update();
        assert!(identity.has_changed().unwrap());
        assert_eq!(
            identity.borrow_and_update().as_ref(),
            Some(&target.identity)
        );
        assert_eq!(store.ready_agent_identity().unwrap(), target.identity);
        assert_eq!(store.readiness().unwrap(), WaitOutcome::Ready);
        let verified = projected_report(&store);
        assert_eq!(verified.state, Some(AgentStatusState::Ready as i32));
        assert!(verified.ssh.unwrap().kex_verified);
        assert!(logged_snapshot(&store).ready);

        let error = "é".repeat(protocol::MAX_DIAGNOSTIC_BYTES);
        store
            .complete_ssh_verification(&target, Err(error))
            .unwrap();
        let failed = projected_report(&store);
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        assert!(!failed.ssh.unwrap().kex_verified);
        assert!(failed.message.unwrap().len() <= protocol::MAX_DIAGNOSTIC_BYTES);
        assert!(identity.borrow().is_none());
        store
            .observe_status(ssh_status(1), Duration::from_secs(300))
            .unwrap();
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        assert_eq!(
            projected_report(&store).code.as_deref(),
            Some("SSH_NOT_READY")
        );
    }

    #[test]
    fn verification_completion_preserves_guest_receipts_and_metrics() {
        let store = ssh_store();
        store
            .observe_metrics(metrics_for(SSH_INSTANCE), Duration::from_secs(300))
            .unwrap();
        let before = store.state.lock().expect("state lock").clone();
        let target = store.ssh_verification_target().unwrap().unwrap();
        store.complete_ssh_verification(&target, Ok(())).unwrap();
        store
            .complete_ssh_verification(&target, Err("probe failed".into()))
            .unwrap();
        let after = store.state.lock().expect("state lock");
        let old = before.status.as_ref().unwrap();
        let new = after.status.as_ref().unwrap();
        assert_eq!(old.value, new.value);
        assert_eq!(old.received_at, new.received_at);
        assert_eq!(old.stale_at, new.stale_at);
        assert_eq!(old.deadline, new.deadline);
        assert_eq!(before.connection, after.connection);
        let old = before.metrics.as_ref().unwrap();
        let new = after.metrics.as_ref().unwrap();
        assert_eq!(old.value, new.value);
        assert_eq!(old.received_at, new.received_at);
        assert_eq!(old.stale_at, new.stale_at);
        assert_eq!(old.deadline, new.deadline);
    }

    #[test]
    fn identical_heartbeats_and_metrics_reuse_target_and_do_not_renew_evidence() {
        let store = ssh_store();
        let target = store.ssh_verification_target().unwrap().unwrap();
        store.complete_ssh_verification(&target, Ok(())).unwrap();
        let deadline = {
            let state = store.state.lock().expect("state lock");
            let crate::state::SshVerificationOutcome::Verified { deadline } =
                state.ssh_verification.as_ref().unwrap().outcome
            else {
                panic!("verified");
            };
            deadline
        };
        let mut heartbeat = ssh_status(1);
        heartbeat
            .report
            .as_mut()
            .unwrap()
            .observed_at
            .as_mut()
            .unwrap()
            .seconds = 2;
        heartbeat
            .report
            .as_mut()
            .unwrap()
            .ssh
            .as_mut()
            .unwrap()
            .kex_verified = false;
        store
            .observe_status(heartbeat, Duration::from_secs(300))
            .unwrap();
        store
            .observe_metrics(metrics_for(SSH_INSTANCE), Duration::from_secs(300))
            .unwrap();
        assert!(Arc::ptr_eq(
            &target,
            &store.ssh_verification_target().unwrap().unwrap()
        ));
        let state = store.state.lock().expect("state lock");
        assert!(crate::state::readiness_detail(&state, deadline - Duration::from_nanos(1)).0);
        assert!(!crate::state::readiness_detail(&state, deadline).0);
        assert_eq!(
            crate::state::readiness(&state, deadline),
            WaitOutcome::TimedOut
        );
        assert!(!crate::state::state_log_snapshot(&state, deadline).ready);
        assert!(crate::state::ready_agent_identity(&state, deadline).is_none());
        let report =
            crate::state::status_observation(&state, state.status.as_ref().unwrap(), deadline)
                .report
                .unwrap();
        assert_eq!(report.code.as_deref(), Some("SSH_NOT_READY"));
        assert!(!report.ssh.unwrap().kex_verified);
        let crate::state::SshVerificationOutcome::Verified {
            deadline: unchanged,
        } = state.ssh_verification.as_ref().unwrap().outcome
        else {
            panic!("verified");
        };
        assert_eq!(unchanged, deadline);
    }

    #[test]
    fn listener_and_identity_replacements_reject_old_completions_including_a_b_a() {
        let store = ssh_store();
        let original = store.ssh_verification_target().unwrap().unwrap();
        store.complete_ssh_verification(&original, Ok(())).unwrap();
        for replacement in [
            ssh_status(2),
            {
                let mut status = ssh_status(1);
                status
                    .report
                    .as_mut()
                    .unwrap()
                    .ssh
                    .as_mut()
                    .unwrap()
                    .backend = "native".into();
                status
            },
            {
                let mut status = ssh_status(1);
                status.identity.as_mut().unwrap().boot_id =
                    Some("00000000-0000-4000-8000-000000000003".into());
                status
            },
            {
                let mut status = ssh_status(1);
                status.identity.as_mut().unwrap().instance_id =
                    Some("00000000-0000-4000-8000-000000000003".into());
                status
            },
            ssh_status(1),
        ] {
            let prior = store.ssh_verification_target().unwrap().unwrap();
            store
                .observe_status(replacement, Duration::from_secs(300))
                .unwrap();
            let current = store.ssh_verification_target().unwrap().unwrap();
            assert!(current.epoch > prior.epoch);
            let generation = store.subscribe();
            store.complete_ssh_verification(&original, Ok(())).unwrap();
            store.complete_ssh_verification(&prior, Ok(())).unwrap();
            assert!(!generation.has_changed().unwrap());
            assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        }
    }

    #[test]
    fn ineligible_transitions_revoke_evidence_without_repeated_epoch_churn() {
        for transition in 0..7 {
            let store = ssh_store();
            let target = store.ssh_verification_target().unwrap().unwrap();
            store.complete_ssh_verification(&target, Ok(())).unwrap();
            match transition {
                0 => store.agent_failure("connection lost").unwrap(),
                1 => store.agent_connecting().unwrap(),
                2 => store.set_vm_state(VmState::Stopping, "stopping").unwrap(),
                3 => {
                    let mut status = ssh_status(1);
                    status.report.as_mut().unwrap().ssh = None;
                    store
                        .observe_status(status, Duration::from_secs(300))
                        .unwrap();
                    // The generic no-SSH status contract is unchanged.
                    assert_eq!(store.readiness().unwrap(), WaitOutcome::Ready);
                }
                4 | 5 => {
                    let mut status = ssh_status(1);
                    let report = status.report.as_mut().unwrap();
                    report.state = Some(if transition == 4 {
                        AgentStatusState::Starting
                    } else {
                        AgentStatusState::Failed
                    } as i32);
                    report.code = Some("GUEST_DIAGNOSTIC".into());
                    report.message = Some("preserve the raw diagnostic".into());
                    store
                        .observe_status(status, Duration::from_secs(300))
                        .unwrap();
                    let projected = projected_report(&store);
                    assert_eq!(projected.code, Some("GUEST_DIAGNOSTIC".into()));
                    assert_eq!(
                        projected.message,
                        Some("preserve the raw diagnostic".into())
                    );
                }
                6 => assert!(matches!(
                    store.observe_metrics(
                        metrics_for("00000000-0000-4000-8000-000000000003"),
                        Duration::from_secs(300),
                    ),
                    Err(StoreError::IdentityMismatch)
                )),
                _ => unreachable!(),
            }
            assert!(store.ssh_verification_target().unwrap().is_none());
            let generation = store.subscribe();
            store.complete_ssh_verification(&target, Ok(())).unwrap();
            assert!(!generation.has_changed().unwrap());
            let epoch = store.state.lock().expect("state lock").ssh_epoch;
            store.agent_connecting().unwrap();
            store.agent_failure("still unavailable").unwrap();
            assert_eq!(store.state.lock().expect("state lock").ssh_epoch, epoch);
        }
    }

    #[test]
    fn expired_status_cannot_be_revived_by_completion_or_a_new_receipt() {
        let store = ssh_store();
        let target = store.ssh_verification_target().unwrap().unwrap();
        store.complete_ssh_verification(&target, Ok(())).unwrap();
        store
            .state
            .lock()
            .expect("state lock")
            .status
            .as_mut()
            .unwrap()
            .deadline = Instant::now();
        assert!(store.ssh_verification_target().unwrap().is_none());
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        let generation = store.subscribe();
        store.complete_ssh_verification(&target, Ok(())).unwrap();
        assert!(!generation.has_changed().unwrap());
        store
            .observe_status(ssh_status(1), Duration::from_secs(300))
            .unwrap();
        let replacement = store.ssh_verification_target().unwrap().unwrap();
        assert!(replacement.epoch > target.epoch);
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
    }

    #[test]
    fn epoch_exhaustion_is_an_error_not_wrapping_or_reusing_evidence() {
        let store = ssh_store();
        store.state.lock().expect("state lock").ssh_epoch = u64::MAX;
        assert!(matches!(
            store.agent_failure("invalidate"),
            Err(StoreError::SshEpochExhausted)
        ));
        assert!(store.ssh_verification_target().unwrap().is_none());
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
    }

    fn logged_snapshot(store: &InstanceStore) -> StateLogSnapshot {
        store
            .state
            .lock()
            .expect("state lock")
            .last_log_snapshot
            .clone()
            .expect("logged state snapshot")
    }

    #[tokio::test]
    async fn ready_status_wakes_generation_waiters() {
        let store = Arc::new(new_instance_store(
            uuid::Uuid::new_v4().to_string(),
            "test".to_string(),
            true,
        ));
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        let mut generation = store.subscribe();
        let waiting_store = store.clone();
        let waiter = tokio::spawn(async move {
            generation
                .changed()
                .await
                .expect("state generation changes");
            waiting_store.readiness().expect("readiness")
        });
        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000002"),
                Duration::from_secs(15),
            )
            .expect("valid status");
        assert_eq!(waiter.await.expect("waiter joins"), WaitOutcome::Ready);
    }

    #[test]
    fn logging_snapshot_ignores_heartbeat_refreshes() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000002"),
                Duration::from_secs(15),
            )
            .expect("first status");
        let first = logged_snapshot(&store);

        let mut heartbeat = ready_status("00000000-0000-4000-8000-000000000002");
        heartbeat
            .report
            .as_mut()
            .expect("status report")
            .observed_at = Some(prost_types::Timestamp {
            seconds: 2,
            nanos: 0,
        });
        store
            .observe_status(heartbeat, Duration::from_secs(15))
            .expect("heartbeat status");

        assert_eq!(logged_snapshot(&store), first);
    }

    #[test]
    fn logging_snapshot_tracks_guest_status_and_readiness() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        let mut starting = ready_status("00000000-0000-4000-8000-000000000002");
        starting.report.as_mut().expect("status report").state =
            Some(AgentStatusState::Starting as i32);
        store
            .observe_status(starting, Duration::from_secs(15))
            .expect("starting status");
        let starting = logged_snapshot(&store);
        assert_eq!(starting.agent_status, Some(AgentStatusState::Starting));
        assert!(!starting.ready);
        assert_eq!(starting.readiness_reason, ReadinessReason::GuestStarting);

        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000002"),
                Duration::from_secs(15),
            )
            .expect("ready status");
        let ready = logged_snapshot(&store);
        assert_eq!(ready.agent_status, Some(AgentStatusState::Ready));
        assert!(ready.ready);
        assert_eq!(ready.readiness_reason, ReadinessReason::GuestReportedReady);
    }

    #[test]
    fn logging_snapshot_records_time_derived_staleness_on_next_mutation() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000002"),
                Duration::from_secs(15),
            )
            .expect("ready status");
        assert!(logged_snapshot(&store).ready);

        store
            .state
            .lock()
            .expect("state lock")
            .status
            .as_mut()
            .expect("status observation")
            .deadline = Instant::now();
        store
            .agent_failure("status stream became silent")
            .expect("failure");

        let stale = logged_snapshot(&store);
        assert!(!stale.ready);
        assert_eq!(stale.readiness_reason, ReadinessReason::AgentStatusStale);
    }

    #[test]
    fn identity_replacement_clears_retained_metrics() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000002"),
                Duration::from_secs(15),
            )
            .expect("status");
        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000003"),
                Duration::from_secs(15),
            )
            .expect("replacement");
        assert!(store.metrics().expect("metrics").metrics.is_none());
    }

    #[test]
    fn capability_cache_is_identity_scoped_and_does_not_change_readiness() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        let instance = "00000000-0000-4000-8000-000000000002";
        store
            .observe_status(ready_status(instance), Duration::from_secs(15))
            .expect("ready status");
        let before = store.readiness().expect("readiness before capability");
        let identity = store.ready_agent_identity().expect("ready identity");
        store
            .set_forward_service(identity, true)
            .expect("cache forward service");

        let status = store.status().expect("status with services");
        let services = match status.agent.expect("agent").mode.expect("agent mode") {
            protocol::v1::host_agent::Mode::Enabled(enabled) => enabled.services,
            protocol::v1::host_agent::Mode::Disabled(_) => panic!("agent unexpectedly disabled"),
        };
        assert_eq!(
            services,
            [
                "silo.v1.GuestAgentService",
                "silo.v1.GuestFilesystemService",
                "silo.v1.GuestProcessService",
                "silo.v1.GuestForwardService",
            ]
        );
        assert_eq!(
            store.readiness().expect("readiness after capability"),
            before
        );

        store
            .observe_status(
                ready_status("00000000-0000-4000-8000-000000000003"),
                Duration::from_secs(15),
            )
            .expect("replacement identity");
        let status = store.status().expect("replacement status");
        let services = match status.agent.expect("agent").mode.expect("agent mode") {
            protocol::v1::host_agent::Mode::Enabled(enabled) => enabled.services,
            protocol::v1::host_agent::Mode::Disabled(_) => panic!("agent unexpectedly disabled"),
        };
        assert!(!services.contains(&"silo.v1.GuestForwardService".to_string()));
    }

    #[tokio::test]
    async fn ready_identity_subscription_observes_instance_and_boot_replacement() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("vm state");
        let mut identity = store.subscribe_ready_agent_identity();
        let instance = "00000000-0000-4000-8000-000000000002";
        store
            .observe_status(ready_status(instance), Duration::from_secs(15))
            .expect("first identity");
        identity
            .changed()
            .await
            .expect("first identity notification");
        let first = identity
            .borrow_and_update()
            .clone()
            .expect("first identity");

        let mut boot_replacement = ready_status(instance);
        boot_replacement
            .identity
            .as_mut()
            .expect("identity")
            .boot_id = Some("00000000-0000-4000-8000-000000000004".to_string());
        store
            .observe_status(boot_replacement, Duration::from_secs(15))
            .expect("boot replacement");
        identity
            .changed()
            .await
            .expect("boot replacement notification");
        let replacement = identity
            .borrow_and_update()
            .clone()
            .expect("replacement identity");
        assert_eq!(first.instance_id, replacement.instance_id);
        assert_ne!(first.boot_id, replacement.boot_id);
    }

    #[test]
    fn invalid_observation_is_not_a_poisoned_store() {
        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        let error = store
            .observe_status(AgentStatus::default(), Duration::from_secs(15))
            .expect_err("invalid status");
        assert!(matches!(error, StoreError::Validation(_)));
        assert!(store.status().is_ok());
    }

    #[test]
    fn starting_detail_pair_and_partial_metrics_are_valid() {
        let mut status = ready_status("00000000-0000-4000-8000-000000000002");
        let report = status.report.as_mut().expect("report");
        report.state = Some(AgentStatusState::Starting as i32);
        report.code = Some("STARTING".to_string());
        report.message = Some("agent starting".to_string());

        let store = new_instance_store(uuid::Uuid::new_v4().to_string(), "test".to_string(), true);
        store
            .observe_status(status, Duration::from_secs(15))
            .expect("starting status");
        store
            .observe_metrics(
                protocol::v1::AgentMetrics {
                    agent_instance_id: Some("00000000-0000-4000-8000-000000000002".to_string()),
                    report: Some(protocol::v1::AgentMetricReport {
                        observed_at: Some(prost_types::Timestamp {
                            seconds: 1,
                            nanos: 0,
                        }),
                        snapshot: Some(protocol::v1::MetricSnapshot::default()),
                    }),
                },
                Duration::from_secs(15),
            )
            .expect("partial metrics");
    }

    #[test]
    fn metrics_report_the_backend_that_created_the_monitor() {
        let store = crate::state::new_instance_store_with_backend(
            uuid::Uuid::new_v4().to_string(),
            "test".to_string(),
            true,
            "krun".to_string(),
        );
        assert_eq!(
            store.metrics().expect("metrics").actual_backend.as_deref(),
            Some("krun")
        );
    }

    #[test]
    fn capabilities_store_rejects_nil_identity_and_invalid_outbound_evidence() {
        let valid = uuid::Uuid::new_v4().to_string();
        let nil = uuid::Uuid::nil().to_string();
        for (machine_id, run_id) in [(&nil, &valid), (&valid, &nil)] {
            let result = crate::state::InstanceStore::new(
                machine_id.clone(),
                "invalid".into(),
                false,
                crate::state::RunLiveProfile {
                    run_id: run_id.clone(),
                    backend: vm_spec::live::LiveBackend::Mock,
                    lane: vm_spec::live::LiveLane::NotApplicable,
                    live: vm_spec::live::LiveCapabilityVector::all_unsupported(
                        vm_spec::live::LiveReasonCode::BackendExcluded,
                    ),
                },
            );
            assert!(matches!(result, Err(StoreError::Validation(_))));
        }
        let store = new_instance_store(valid, "outbound".into(), false);
        store.state.lock().expect("state").live.run_id = nil;
        assert!(matches!(store.status(), Err(StoreError::Validation(_))));
    }

    #[test]
    fn capabilities_live_status_preserves_actual_run_across_state_changes() {
        let machine_id = uuid::Uuid::new_v4().to_string();
        let run_id = uuid::Uuid::new_v4().to_string();
        let mut live = vm_spec::live::LiveCapabilityVector::all_unsupported(
            vm_spec::live::LiveReasonCode::BackendExcluded,
        );
        live.pause = vm_spec::live::LiveCapability {
            native: true,
            availability: vm_spec::live::LiveAvailability::Supported,
        };
        let store = crate::state::InstanceStore::new(
            machine_id.clone(),
            "actual-run".into(),
            false,
            crate::state::RunLiveProfile {
                run_id: run_id.clone(),
                backend: vm_spec::live::LiveBackend::Mock,
                lane: vm_spec::live::LiveLane::HvfArm64,
                live: live.clone(),
            },
        )
        .expect("valid state");
        let initial = store.status().expect("initial");
        let evidence =
            vm_spec::live::LiveMachineReport::try_from(initial.live.expect("mandatory live"))
                .expect("valid report");
        assert_eq!(evidence.machine_id, machine_id);
        assert_eq!(evidence.run_id, run_id);
        assert!(evidence.live.pause.native);
        assert_eq!(
            evidence.live.pause.availability,
            vm_spec::live::LiveAvailability::Unsupported {
                reason: vm_spec::live::LiveUnsupportedReason::device(
                    vm_spec::live::LiveDeviceSubject::GuestProfile {
                        profile: "guest-agent-disabled".into(),
                    },
                ),
            },
        );
        assert_eq!(evidence.live.capture, live.capture);
        assert_eq!(evidence.backend, vm_spec::live::LiveBackend::Mock);
        store
            .set_vm_state(VmState::Running, "running")
            .expect("running");
        store
            .set_vm_state(VmState::Stopped, "stopped")
            .expect("stopped");
        let terminal = store.status().expect("terminal");
        assert_eq!(
            vm_spec::live::LiveMachineReport::try_from(terminal.live.expect("live"))
                .expect("report"),
            evidence
        );
        assert_eq!(
            store.metrics().expect("metrics").actual_backend.as_deref(),
            Some("mock")
        );
    }
    fn root_metrics() -> protocol::v1::RootStorageMetrics {
        use protocol::v1::{
            RootStorageKind, RootStorageMetrics, TemporaryDirectoryKind, TemporaryDirectoryMetrics,
        };
        RootStorageMetrics {
            kind: Some(RootStorageKind::LinuxFlatOverlayV1 as i32),
            upper_profile: Some("silo-upper-ext4-v1".into()),
            upper_uuid: Some("12345678-1234-4234-8234-123456789abc".into()),
            upper_backing_bytes: Some(67_112_960),
            upper_filesystem_bytes: Some(67_108_864),
            unusable_tail_bytes: Some(4096),
            filesystem_overhead_bytes: Some(5_668_864),
            upper_usable_bytes: Some(61_440_000),
            upper_used_bytes: Some(53_248_000),
            upper_free_bytes: Some(8_192_000),
            upper_available_bytes: Some(4_096_000),
            upper_total_inodes: Some(8192),
            upper_free_inodes: Some(0),
            upper_available_inodes: Some(0),
            shared_lower_logical_bytes: Some(268_435_456),
            temporary_directory: Some(TemporaryDirectoryMetrics {
                kind: Some(TemporaryDirectoryKind::Upper as i32),
                capacity_bytes: Some(61_440_000),
                used_bytes: Some(53_248_000),
                free_bytes: Some(8_192_000),
                available_bytes: Some(4_096_000),
                persistent: Some(true),
                memory_charged: Some(false),
            }),
        }
    }

    #[test]
    fn root_metrics_relay_preserves_exact_payload_and_existing_staleness() {
        let instance = "00000000-0000-4000-8000-000000000002";
        for freshness in [Duration::ZERO, Duration::from_secs(300)] {
            let store = new_instance_store(
                uuid::Uuid::new_v4().to_string(),
                "root-metrics".into(),
                true,
            );
            store.set_vm_state(VmState::Running, "running").unwrap();
            store
                .observe_status(ready_status(instance), Duration::from_secs(300))
                .unwrap();
            let mut metrics = metrics_for(instance);
            let root = root_metrics();
            metrics
                .report
                .as_mut()
                .unwrap()
                .snapshot
                .as_mut()
                .unwrap()
                .root_storage = Some(root.clone());
            store.observe_metrics(metrics.clone(), freshness).unwrap();
            let observation = store.metrics().unwrap().metrics.unwrap();
            assert_eq!(observation.agent_instance_id.as_deref(), Some(instance));
            assert_eq!(observation.report, metrics.report);
            assert_eq!(
                observation.report.unwrap().snapshot.unwrap().root_storage,
                Some(root)
            );
            assert_eq!(
                observation.freshness,
                Some(if freshness.is_zero() {
                    protocol::v1::Freshness::Stale as i32
                } else {
                    protocol::v1::Freshness::Fresh as i32
                })
            );
        }
    }

    #[test]
    fn root_metrics_relay_rejects_invalid_payload_without_replacing_last_observation() {
        let instance = "00000000-0000-4000-8000-000000000002";
        let store = new_instance_store(
            uuid::Uuid::new_v4().to_string(),
            "root-metrics".into(),
            true,
        );
        store
            .observe_status(ready_status(instance), Duration::from_secs(300))
            .unwrap();
        let valid = metrics_for(instance);
        store
            .observe_metrics(valid.clone(), Duration::from_secs(300))
            .unwrap();
        let mut invalid = valid.clone();
        let mut root = root_metrics();
        root.upper_used_bytes = Some(u64::MAX);
        invalid
            .report
            .as_mut()
            .unwrap()
            .snapshot
            .as_mut()
            .unwrap()
            .root_storage = Some(root);
        assert!(matches!(
            store.observe_metrics(invalid, Duration::from_secs(300)),
            Err(StoreError::Validation(_))
        ));
        assert_eq!(
            store.metrics().unwrap().metrics.unwrap().report,
            valid.report
        );
    }

    fn live_status(instance: &str, driver_ready: Option<bool>) -> AgentStatus {
        let mut status = ready_status(instance);
        let report = status.report.as_mut().unwrap();
        report.boot = Some(protocol::v1::GuestBootReport {
            mode: Some(protocol::v1::GuestBootMode::AgentPid1 as i32),
            agent_is_pid1: Some(true),
            ..Default::default()
        });
        report.lifecycle = Some(protocol::v1::GuestLifecycleStatus {
            state: protocol::v1::GuestLifecycleState::Running as i32,
            workload_roots: vec!["/sys/fs/cgroup/silo-workloads".into()],
            generation_driver_ready: driver_ready,
            ..Default::default()
        });
        status
    }

    fn live_store() -> InstanceStore {
        let mut live =
            LiveCapabilityVector::all_unsupported(vm_spec::live::LiveReasonCode::NotDelivered);
        live.pause = vm_spec::live::LiveCapability {
            native: true,
            availability: vm_spec::live::LiveAvailability::Supported,
        };
        let store = InstanceStore::new(
            uuid::Uuid::new_v4().to_string(),
            "live".into(),
            true,
            RunLiveProfile {
                run_id: uuid::Uuid::new_v4().to_string(),
                backend: LiveBackend::Mock,
                lane: LiveLane::NotApplicable,
                live,
            },
        )
        .unwrap();
        store.set_vm_state(VmState::Running, "running").unwrap();
        store
    }

    fn paused_transition(store: &InstanceStore, parked: bool) -> crate::state::LiveTransition {
        let identity = store.live_snapshot().unwrap().observed_identity;
        let snapshot = store.status().unwrap();
        let id =
            |value: Option<String>| vm_spec::lifecycle::LiveId::parse(&value.unwrap()).unwrap();
        let token = vm_spec::lifecycle::PauseToken {
            machine_id: id(snapshot.machine_id.clone()),
            run_id: id(snapshot.run_id.clone()),
            generation: std::num::NonZeroU64::new(1).unwrap(),
            owner: vm_spec::lifecycle::PauseOwner::User,
        };
        crate::state::LiveTransition {
            state: VmLifecycleState::Paused,
            lifecycle: LiveLifecycle {
                current_pause: Some(vm_spec::lifecycle::CurrentPause {
                    token,
                    operation_id: id(Some(uuid::Uuid::new_v4().to_string())),
                    freeze_epoch: std::num::NonZeroU64::new(1).unwrap(),
                }),
                ..LiveLifecycle::default()
            },
            message: "paused".into(),
            held_identity: identity,
            parked,
            readiness_probe: false,
        }
    }

    #[test]
    fn live_guest_profile_narrows_status_and_admission_from_the_baseline() {
        let store = live_store();
        let rejection = |store: &InstanceStore| store.live_snapshot().unwrap().guest_rejection;
        assert_eq!(rejection(&store), Some("guest-agent-unavailable"));
        let instance = "00000000-0000-4000-8000-000000000002";
        store
            .observe_status(ready_status(instance), Duration::from_secs(15))
            .unwrap();
        assert_eq!(rejection(&store), Some("guest-not-agent-pid1"));
        store
            .observe_status(live_status(instance, Some(false)), Duration::from_secs(15))
            .unwrap();
        assert_eq!(rejection(&store), Some("guest-generation-driver-missing"));
        let status = store.status().unwrap();
        let live = LiveMachineReport::try_from(status.live.unwrap()).unwrap();
        assert!(matches!(
            live.live.pause.availability,
            vm_spec::live::LiveAvailability::Unsupported { ref reason }
                if reason.code == vm_spec::live::LiveReasonCode::DeviceProfileRejected
        ));
        // Positive evidence widens back to the baseline, never beyond it.
        store
            .observe_status(live_status(instance, Some(true)), Duration::from_secs(15))
            .unwrap();
        assert_eq!(rejection(&store), None);
        let live = LiveMachineReport::try_from(store.status().unwrap().live.unwrap()).unwrap();
        assert_eq!(
            live.live.pause.availability,
            vm_spec::live::LiveAvailability::Supported
        );
        assert!(matches!(
            live.live.capture.availability,
            vm_spec::live::LiveAvailability::Unsupported { ref reason }
                if reason.code == vm_spec::live::LiveReasonCode::NotDelivered
        ));
    }

    #[test]
    fn live_states_keep_readiness_false_and_project_lifecycle() {
        let store = live_store();
        store
            .observe_status(
                live_status("00000000-0000-4000-8000-000000000002", Some(true)),
                Duration::from_secs(15),
            )
            .unwrap();
        assert_eq!(store.readiness().unwrap(), WaitOutcome::Ready);
        assert!(store.publish_live(paused_transition(&store, true)).unwrap());
        let status = store.status().unwrap();
        let readiness = status.readiness.unwrap();
        assert_eq!(readiness.ready, Some(false));
        assert_eq!(readiness.reason, Some(ReadinessReason::VmPaused as i32));
        let (state, lifecycle) = protocol::lifecycle::status_lifecycle(&status).unwrap();
        assert_eq!(state, VmLifecycleState::Paused);
        assert!(lifecycle.current_pause.is_some());
        assert_eq!(store.readiness().unwrap(), WaitOutcome::TimedOut);
        // Presence rules are enforced on publication.
        let mut invalid = paused_transition(&store, true);
        invalid.lifecycle.current_pause = None;
        assert!(store.publish_live(invalid).is_err());
        let mut terminal = paused_transition(&store, false);
        terminal.state = VmLifecycleState::Stopped;
        assert!(store.publish_live(terminal).is_err());
    }

    #[tokio::test]
    async fn live_held_identity_keeps_sessions_and_stop_clears_authority() {
        let store = live_store();
        let instance = "00000000-0000-4000-8000-000000000002";
        store
            .observe_status(live_status(instance, Some(true)), Duration::from_secs(15))
            .unwrap();
        let mut sessions = store.subscribe_ready_agent_identity();
        let ready = store.ready_agent_identity().unwrap();
        assert!(store.publish_live(paused_transition(&store, true)).unwrap());
        assert_eq!(sessions.borrow_and_update().clone(), Some(ready.clone()));
        assert!(
            store.ready_agent_identity().is_err(),
            "new sessions need readiness"
        );
        // A different agent instance ends the held binding.
        store
            .observe_status(
                live_status("00000000-0000-4000-8000-000000000009", Some(true)),
                Duration::from_secs(15),
            )
            .unwrap();
        assert_eq!(sessions.borrow_and_update().clone(), None);
        // Stop never keeps pause authority and refuses later continuations.
        store.set_vm_state(VmState::Stopping, "stop").unwrap();
        let (state, lifecycle) =
            protocol::lifecycle::status_lifecycle(&store.status().unwrap()).unwrap();
        assert_eq!(state, VmLifecycleState::Stopping);
        assert_eq!(lifecycle, LiveLifecycle::default());
        assert!(!store.publish_live(paused_transition(&store, true)).unwrap());
        assert_eq!(
            store.status().unwrap().vm.unwrap().state,
            Some(VmState::Stopping as i32)
        );
    }

    #[tokio::test]
    async fn live_parked_interval_suspends_agent_staleness_and_resumes_after_release() {
        let store = live_store();
        store
            .observe_status(
                live_status("00000000-0000-4000-8000-000000000002", Some(true)),
                Duration::from_millis(200),
            )
            .unwrap();
        let fresh = |store: &InstanceStore| {
            let status = store.status().unwrap();
            let Some(protocol::v1::host_agent::Mode::Enabled(agent)) = status.agent.unwrap().mode
            else {
                panic!("agent enabled");
            };
            agent.status.unwrap().freshness == Some(Freshness::Fresh as i32)
        };
        assert!(store.publish_live(paused_transition(&store, true)).unwrap());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(fresh(&store), "parked interval suspends staleness");
        assert_eq!(store.live_snapshot().unwrap().guest_rejection, None);
        // Release: the remaining freshness budget continues, then expires.
        let mut releasing = paused_transition(&store, false);
        releasing.state = VmLifecycleState::Pausing;
        releasing.lifecycle = LiveLifecycle {
            activity: Some(vm_spec::lifecycle::LiveActivity {
                operation_id: vm_spec::lifecycle::LiveId::parse(
                    "00000000-0000-4000-8000-000000000010",
                )
                .unwrap(),
                request_id: vm_spec::lifecycle::LiveId::parse(
                    "00000000-0000-4000-8000-000000000011",
                )
                .unwrap(),
                command: vm_spec::lifecycle::LiveCommandKind::Resume,
                stage: vm_spec::lifecycle::LiveStage::ResumeHandshake,
            }),
            ..LiveLifecycle::default()
        };
        assert!(store.publish_live(releasing).unwrap());
        assert!(fresh(&store), "remaining budget survives the release");
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!fresh(&store), "staleness resumes after release");
        assert_eq!(
            store.live_snapshot().unwrap().guest_rejection,
            Some("guest-status-stale")
        );
    }
}

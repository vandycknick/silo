use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use prost_types::Timestamp;
use protocol::v1::{
    AgentConnection, AgentConnectionState, AgentIdentity, AgentMetricReport, AgentMetrics,
    AgentMetricsObservation, AgentStatus, AgentStatusObservation, AgentStatusReport,
    AgentStatusState, DisabledAgent, EnabledAgent, Freshness, HostAgent, HostMetrics, HostStatus,
    MonitorSnapshot, Readiness, ReadinessReason, StaleReason, VmSnapshot, VmState,
};
use tokio::sync::watch;

const TIMESTAMP_MIN_SECONDS: i64 = -62_135_596_800;
const TIMESTAMP_MAX_SECONDS: i64 = 253_402_300_799;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("vmmon state lock is poisoned")]
    Poisoned,
    #[error("invalid agent observation: {0}")]
    Validation(String),
    #[error("agent protocol error: {0}")]
    Protocol(String),
    #[error("agent metrics identity does not match the current status identity")]
    IdentityMismatch,
    #[error("unable to calculate observation freshness deadline")]
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Ready,
    Terminal,
    TimedOut,
}

#[derive(Debug, Clone)]
struct Observation<T> {
    received_at: SystemTime,
    stale_at: SystemTime,
    deadline: Instant,
    value: T,
}

#[derive(Debug, Clone)]
struct State {
    machine_id: String,
    name: String,
    monitor_id: String,
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
    stopping: bool,
    last_log_snapshot: Option<StateLogSnapshot>,
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
}

#[derive(Debug)]
pub(crate) struct InstanceStore {
    state: Mutex<State>,
    generation: watch::Sender<u64>,
    identity_reset: watch::Sender<u64>,
}

impl InstanceStore {
    pub(crate) fn new(machine_id: String, name: String, agent_enabled: bool) -> Self {
        let now = SystemTime::now();
        let (generation, _) = watch::channel(0);
        let (identity_reset, _) = watch::channel(0);
        let mut state = State {
            machine_id,
            name,
            monitor_id: uuid::Uuid::new_v4().to_string(),
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
            stopping: false,
            last_log_snapshot: None,
        };
        state.last_log_snapshot = Some(state_log_snapshot(&state, Instant::now()));
        Self {
            state: Mutex::new(state),
            generation,
            identity_reset,
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    pub(crate) fn subscribe_identity_reset(&self) -> watch::Receiver<u64> {
        self.identity_reset.subscribe()
    }

    pub(crate) fn status(&self) -> Result<HostStatus, StoreError> {
        self.state
            .lock()
            .map(|state| project_status(&state, Instant::now(), SystemTime::now()))
            .map_err(|_| StoreError::Poisoned)
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

    pub(crate) fn has_identity(&self) -> Result<bool, StoreError> {
        self.state
            .lock()
            .map(|state| state.identity.is_some())
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
        let observation = observation(report, freshness)?;

        self.mutate(|state| {
            if let Some(current) = &state.identity {
                if current.instance_id != identity.instance_id {
                    // A new agent instance supersedes every observation from the old one.
                    state.status = None;
                    state.metrics = None;
                } else if current.version != identity.version || current.boot_id != identity.boot_id
                {
                    return Err(StoreError::Protocol(
                        "agent version or boot ID changed without an instance replacement"
                            .to_string(),
                    ));
                }
            }
            let received_at = observation.received_at;
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
        let (before, after) = {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
            let before = state
                .last_log_snapshot
                .clone()
                .unwrap_or_else(|| state_log_snapshot(&state, Instant::now()));
            update(&mut state)?;
            let after = state_log_snapshot(&state, Instant::now());
            state.last_log_snapshot = Some(after.clone());
            (before, after)
        };
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        log_state_changes(&before, &after);
        Ok(())
    }
}

pub(crate) fn new_instance_store(
    machine_id: String,
    name: String,
    agent_enabled: bool,
) -> InstanceStore {
    InstanceStore::new(machine_id, name, agent_enabled)
}

fn observation<T>(value: T, freshness: Duration) -> Result<Observation<T>, StoreError> {
    let received_at = SystemTime::now();
    let stale_at = received_at
        .checked_add(freshness)
        .ok_or(StoreError::Clock)?;
    let deadline = Instant::now()
        .checked_add(freshness)
        .ok_or(StoreError::Clock)?;
    Ok(Observation {
        received_at,
        stale_at,
        deadline,
        value,
    })
}

fn state_log_snapshot(state: &State, now: Instant) -> StateLogSnapshot {
    let (ready, readiness_reason) = readiness_detail(state, now);
    let identity = state.identity.as_ref();
    let report = state.status.as_ref().map(|status| &status.value);
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
            .and_then(|report| report.state)
            .and_then(|value| AgentStatusState::try_from(value).ok()),
        agent_code: report.and_then(|report| report.code.clone()),
        agent_message: report.and_then(|report| report.message.clone()),
        ready,
        readiness_reason,
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
            "vmmon readiness changed"
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
    let ready = state.vm_state == VmState::Running
        && (!state.agent_enabled
            || state.status.as_ref().is_some_and(|status| {
                !state.stopping
                    && status.deadline > now
                    && status.value.state == Some(AgentStatusState::Ready as i32)
            }));
    if ready {
        WaitOutcome::Ready
    } else {
        WaitOutcome::TimedOut
    }
}

fn project_status(state: &State, now: Instant, observed_at: SystemTime) -> HostStatus {
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
            })),
        }
    } else {
        HostAgent {
            mode: Some(protocol::v1::host_agent::Mode::Disabled(DisabledAgent {})),
        }
    };
    HostStatus {
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
    }
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
    }
}

fn status_observation(
    state: &State,
    status: &Observation<AgentStatusReport>,
    now: Instant,
) -> AgentStatusObservation {
    AgentStatusObservation {
        received_at: Some(timestamp(status.received_at)),
        stale_at: Some(timestamp(status.stale_at)),
        freshness: Some(freshness(state, status.deadline, now) as i32),
        stale_reason: stale_reason(state, status.deadline, now).map(|reason| reason as i32),
        report: Some(status.value.clone()),
    }
}

fn freshness(state: &State, deadline: Instant, now: Instant) -> Freshness {
    if !state.stopping && deadline > now {
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
        VmState::Running if !state.agent_enabled => (true, ReadinessReason::AgentNotRequired),
        VmState::Running => match &state.status {
            Some(status) if state.stopping || status.deadline <= now => {
                (false, ReadinessReason::AgentStatusStale)
            }
            Some(status) if status.value.state == Some(AgentStatusState::Starting as i32) => {
                (false, ReadinessReason::GuestStarting)
            }
            Some(status) if status.value.state == Some(AgentStatusState::Failed as i32) => {
                (false, ReadinessReason::GuestFailed)
            }
            Some(status) if status.value.state == Some(AgentStatusState::Ready as i32) => {
                (true, ReadinessReason::GuestReportedReady)
            }
            _ => (false, ReadinessReason::AgentUnavailable),
        },
    }
}

fn timestamp(time: SystemTime) -> Timestamp {
    time.into()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use protocol::v1::{
        AgentIdentity, AgentStatus, AgentStatusReport, AgentStatusState, ReadinessReason, VmState,
    };

    use crate::state::{
        new_instance_store, InstanceStore, StateLogSnapshot, StoreError, WaitOutcome,
    };

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
            "machine-1".to_string(),
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
        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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
        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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
        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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
        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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
    fn invalid_observation_is_not_a_poisoned_store() {
        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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

        let store = new_instance_store("machine-1".to_string(), "test".to_string(), true);
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
}

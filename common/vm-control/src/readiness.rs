use crate::{
    duration_from_wire, duration_to_wire, invalid, required, validate_uuid, ConversionError,
};
use silod_spec::daemon::v1 as w;
pub fn system_time_to_wire(
    v: std::time::SystemTime,
) -> Result<prost_types::Timestamp, ConversionError> {
    let d = match v.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            return Ok(prost_types::Timestamp {
                seconds: d
                    .as_secs()
                    .try_into()
                    .map_err(|_| invalid("timestamp", "overflow"))?,
                nanos: d.subsec_nanos() as i32,
            })
        }
        Err(e) => e.duration(),
    };
    let seconds = i64::try_from(d.as_secs()).map_err(|_| invalid("timestamp", "overflow"))?;
    Ok(if d.subsec_nanos() == 0 {
        prost_types::Timestamp {
            seconds: -seconds,
            nanos: 0,
        }
    } else {
        prost_types::Timestamp {
            seconds: seconds
                .checked_neg()
                .and_then(|v| v.checked_sub(1))
                .ok_or_else(|| invalid("timestamp", "overflow"))?,
            nanos: (1_000_000_000 - d.subsec_nanos()) as i32,
        }
    })
}
pub fn system_time_from_wire(
    v: prost_types::Timestamp,
) -> Result<std::time::SystemTime, ConversionError> {
    if !(0..1_000_000_000).contains(&v.nanos) || !(-62135596800..=253402300799).contains(&v.seconds)
    {
        return Err(invalid("timestamp", "invalid timestamp"));
    }
    if v.seconds >= 0 {
        std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::new(v.seconds as u64, v.nanos as u32))
    } else {
        let seconds = v.seconds.unsigned_abs();
        let d = if v.nanos == 0 {
            std::time::Duration::new(seconds, 0)
        } else {
            std::time::Duration::new(seconds - 1, 1_000_000_000 - v.nanos as u32)
        };
        std::time::UNIX_EPOCH.checked_sub(d)
    }
    .ok_or_else(|| invalid("timestamp", "overflow"))
}
fn vm_state_to(v: libvm::MachineVmState) -> i32 {
    match v {
        libvm::MachineVmState::Starting => 1,
        libvm::MachineVmState::Running => 2,
        libvm::MachineVmState::Stopping => 3,
        libvm::MachineVmState::Stopped => 4,
        libvm::MachineVmState::Failed => 5,
    }
}
fn vm_state_from(v: i32) -> Result<libvm::MachineVmState, ConversionError> {
    match v {
        1 => Ok(libvm::MachineVmState::Starting),
        2 => Ok(libvm::MachineVmState::Running),
        3 => Ok(libvm::MachineVmState::Stopping),
        4 => Ok(libvm::MachineVmState::Stopped),
        5 => Ok(libvm::MachineVmState::Failed),
        _ => Err(invalid("vm_state", "invalid enum")),
    }
}
fn readiness_reason_to(v: libvm::MachineReadinessReason) -> i32 {
    match v {
        libvm::MachineReadinessReason::VmStarting => 1,
        libvm::MachineReadinessReason::VmStopping => 2,
        libvm::MachineReadinessReason::VmStopped => 3,
        libvm::MachineReadinessReason::VmFailed => 4,
        libvm::MachineReadinessReason::AgentNotRequired => 5,
        libvm::MachineReadinessReason::AgentUnavailable => 6,
        libvm::MachineReadinessReason::AgentStatusStale => 7,
        libvm::MachineReadinessReason::GuestStarting => 8,
        libvm::MachineReadinessReason::GuestFailed => 9,
        libvm::MachineReadinessReason::GuestReportedReady => 10,
    }
}
fn readiness_reason_from(v: i32) -> Result<libvm::MachineReadinessReason, ConversionError> {
    match v {
        1 => Ok(libvm::MachineReadinessReason::VmStarting),
        2 => Ok(libvm::MachineReadinessReason::VmStopping),
        3 => Ok(libvm::MachineReadinessReason::VmStopped),
        4 => Ok(libvm::MachineReadinessReason::VmFailed),
        5 => Ok(libvm::MachineReadinessReason::AgentNotRequired),
        6 => Ok(libvm::MachineReadinessReason::AgentUnavailable),
        7 => Ok(libvm::MachineReadinessReason::AgentStatusStale),
        8 => Ok(libvm::MachineReadinessReason::GuestStarting),
        9 => Ok(libvm::MachineReadinessReason::GuestFailed),
        10 => Ok(libvm::MachineReadinessReason::GuestReportedReady),
        _ => Err(invalid("readiness_reason", "invalid enum")),
    }
}
fn connection_state_to(v: libvm::MachineAgentConnectionState) -> i32 {
    match v {
        libvm::MachineAgentConnectionState::Connecting => 1,
        libvm::MachineAgentConnectionState::Responsive => 2,
        libvm::MachineAgentConnectionState::Unresponsive => 3,
    }
}
fn connection_state_from(v: i32) -> Result<libvm::MachineAgentConnectionState, ConversionError> {
    match v {
        1 => Ok(libvm::MachineAgentConnectionState::Connecting),
        2 => Ok(libvm::MachineAgentConnectionState::Responsive),
        3 => Ok(libvm::MachineAgentConnectionState::Unresponsive),
        _ => Err(invalid("connection_state", "invalid enum")),
    }
}
fn freshness_to(v: libvm::MachineFreshness) -> i32 {
    match v {
        libvm::MachineFreshness::Fresh => 1,
        libvm::MachineFreshness::Stale => 2,
    }
}
fn freshness_from(v: i32) -> Result<libvm::MachineFreshness, ConversionError> {
    match v {
        1 => Ok(libvm::MachineFreshness::Fresh),
        2 => Ok(libvm::MachineFreshness::Stale),
        _ => Err(invalid("freshness", "invalid enum")),
    }
}
fn stale_reason_to(v: libvm::MachineStaleReason) -> i32 {
    match v {
        libvm::MachineStaleReason::ReceiptAge => 1,
        libvm::MachineStaleReason::MonitorStopping => 2,
    }
}
fn stale_reason_from(v: i32) -> Result<libvm::MachineStaleReason, ConversionError> {
    match v {
        1 => Ok(libvm::MachineStaleReason::ReceiptAge),
        2 => Ok(libvm::MachineStaleReason::MonitorStopping),
        _ => Err(invalid("stale_reason", "invalid enum")),
    }
}
fn agent_state_to(v: libvm::MachineAgentStatusState) -> i32 {
    match v {
        libvm::MachineAgentStatusState::Starting => 1,
        libvm::MachineAgentStatusState::Ready => 2,
        libvm::MachineAgentStatusState::Failed => 3,
    }
}
fn agent_state_from(v: i32) -> Result<libvm::MachineAgentStatusState, ConversionError> {
    match v {
        1 => Ok(libvm::MachineAgentStatusState::Starting),
        2 => Ok(libvm::MachineAgentStatusState::Ready),
        3 => Ok(libvm::MachineAgentStatusState::Failed),
        _ => Err(invalid("agent_state", "invalid enum")),
    }
}
fn ssh_backend_to(v: libvm::MachineSshBackend) -> i32 {
    match v {
        libvm::MachineSshBackend::Native => 1,
        libvm::MachineSshBackend::OpenSsh => 2,
        libvm::MachineSshBackend::SystemdOpenSsh => 3,
    }
}
fn ssh_backend_from(v: i32) -> Result<libvm::MachineSshBackend, ConversionError> {
    match v {
        1 => Ok(libvm::MachineSshBackend::Native),
        2 => Ok(libvm::MachineSshBackend::OpenSsh),
        3 => Ok(libvm::MachineSshBackend::SystemdOpenSsh),
        _ => Err(invalid("ssh_backend", "invalid enum")),
    }
}
fn guest_boot_mode_to(v: libvm::MachineGuestBootMode) -> i32 {
    match v {
        libvm::MachineGuestBootMode::Standard => 1,
        libvm::MachineGuestBootMode::AgentPid1 => 2,
        libvm::MachineGuestBootMode::InitChild => 3,
    }
}
fn guest_boot_mode_from(v: i32) -> Result<libvm::MachineGuestBootMode, ConversionError> {
    match v {
        1 => Ok(libvm::MachineGuestBootMode::Standard),
        2 => Ok(libvm::MachineGuestBootMode::AgentPid1),
        3 => Ok(libvm::MachineGuestBootMode::InitChild),
        _ => Err(invalid("guest_boot_mode", "invalid enum")),
    }
}
fn provision_state_to(v: libvm::MachineProvisionOverallStatus) -> i32 {
    match v {
        libvm::MachineProvisionOverallStatus::Succeeded => 1,
        libvm::MachineProvisionOverallStatus::Degraded => 2,
        libvm::MachineProvisionOverallStatus::Skipped => 3,
        libvm::MachineProvisionOverallStatus::FailedBoot => 4,
    }
}
fn provision_state_from(v: i32) -> Result<libvm::MachineProvisionOverallStatus, ConversionError> {
    match v {
        1 => Ok(libvm::MachineProvisionOverallStatus::Succeeded),
        2 => Ok(libvm::MachineProvisionOverallStatus::Degraded),
        3 => Ok(libvm::MachineProvisionOverallStatus::Skipped),
        4 => Ok(libvm::MachineProvisionOverallStatus::FailedBoot),
        _ => Err(invalid("provision_state", "invalid enum")),
    }
}
fn step_state_to(v: libvm::MachineAgentProvisionStepStatus) -> i32 {
    match v {
        libvm::MachineAgentProvisionStepStatus::Succeeded => 1,
        libvm::MachineAgentProvisionStepStatus::Failed => 2,
        libvm::MachineAgentProvisionStepStatus::Skipped => 3,
        libvm::MachineAgentProvisionStepStatus::Unsupported => 4,
    }
}
fn step_state_from(v: i32) -> Result<libvm::MachineAgentProvisionStepStatus, ConversionError> {
    match v {
        1 => Ok(libvm::MachineAgentProvisionStepStatus::Succeeded),
        2 => Ok(libvm::MachineAgentProvisionStepStatus::Failed),
        3 => Ok(libvm::MachineAgentProvisionStepStatus::Skipped),
        4 => Ok(libvm::MachineAgentProvisionStepStatus::Unsupported),
        _ => Err(invalid("step_state", "invalid enum")),
    }
}
fn failure_policy_to(v: libvm::MachineAgentProvisionFailurePolicy) -> i32 {
    match v {
        libvm::MachineAgentProvisionFailurePolicy::BestEffort => 1,
        libvm::MachineAgentProvisionFailurePolicy::FailBoot => 2,
    }
}
fn failure_policy_from(
    v: i32,
) -> Result<libvm::MachineAgentProvisionFailurePolicy, ConversionError> {
    match v {
        1 => Ok(libvm::MachineAgentProvisionFailurePolicy::BestEffort),
        2 => Ok(libvm::MachineAgentProvisionFailurePolicy::FailBoot),
        _ => Err(invalid("failure_policy", "invalid enum")),
    }
}
fn monitor_to_wire(
    v: &libvm::MachineMonitorSnapshot,
) -> Result<w::MonitorSnapshot, ConversionError> {
    Ok(w::MonitorSnapshot {
        instance_id: v.instance_id.clone(),
        observed_at: Some(system_time_to_wire(v.observed_at)?),
    })
}
fn monitor_from_wire(
    v: w::MonitorSnapshot,
) -> Result<libvm::MachineMonitorSnapshot, ConversionError> {
    Ok(libvm::MachineMonitorSnapshot {
        instance_id: v.instance_id,
        observed_at: system_time_from_wire(required(v.observed_at, "monitor.observed_at")?)?,
    })
}
fn vm_to_wire(v: &libvm::MachineVmSnapshot) -> Result<w::VmSnapshot, ConversionError> {
    Ok(w::VmSnapshot {
        state: vm_state_to(v.state),
        state_changed_at: Some(system_time_to_wire(v.state_changed_at)?),
        running_since: v.running_since.map(system_time_to_wire).transpose()?,
        code: v.code.clone(),
        message: v.message.clone(),
    })
}
fn vm_from_wire(v: w::VmSnapshot) -> Result<libvm::MachineVmSnapshot, ConversionError> {
    Ok(libvm::MachineVmSnapshot {
        state: vm_state_from(v.state)?,
        state_changed_at: system_time_from_wire(required(
            v.state_changed_at,
            "vm.state_changed_at",
        )?)?,
        running_since: v.running_since.map(system_time_from_wire).transpose()?,
        code: v.code,
        message: v.message,
    })
}
fn readiness_state_to_wire(
    v: &libvm::MachineReadinessState,
) -> Result<w::ReadinessState, ConversionError> {
    Ok(w::ReadinessState {
        ready: v.ready,
        reason: readiness_reason_to(v.reason),
    })
}
fn readiness_state_from_wire(
    v: w::ReadinessState,
) -> Result<libvm::MachineReadinessState, ConversionError> {
    Ok(libvm::MachineReadinessState {
        ready: v.ready,
        reason: readiness_reason_from(v.reason)?,
    })
}
fn connection_to_wire(
    v: &libvm::MachineAgentConnection,
) -> Result<w::AgentConnection, ConversionError> {
    Ok(w::AgentConnection {
        state: connection_state_to(v.state),
        last_success_at: v.last_success_at.map(system_time_to_wire).transpose()?,
        last_failure_at: v.last_failure_at.map(system_time_to_wire).transpose()?,
        code: v.code.clone(),
        message: v.message.clone(),
    })
}
fn connection_from_wire(
    v: w::AgentConnection,
) -> Result<libvm::MachineAgentConnection, ConversionError> {
    Ok(libvm::MachineAgentConnection {
        state: connection_state_from(v.state)?,
        last_success_at: v.last_success_at.map(system_time_from_wire).transpose()?,
        last_failure_at: v.last_failure_at.map(system_time_from_wire).transpose()?,
        code: v.code,
        message: v.message,
    })
}
fn identity_to_wire(v: &libvm::MachineAgentIdentity) -> Result<w::AgentIdentity, ConversionError> {
    Ok(w::AgentIdentity {
        instance_id: v.instance_id.clone(),
        version: v.version.clone(),
        boot_id: v.boot_id.clone(),
    })
}
fn identity_from_wire(v: w::AgentIdentity) -> Result<libvm::MachineAgentIdentity, ConversionError> {
    Ok(libvm::MachineAgentIdentity {
        instance_id: v.instance_id,
        version: v.version,
        boot_id: v.boot_id,
    })
}
fn system_to_wire(v: &libvm::MachineSystemInfo) -> Result<w::SystemInfo, ConversionError> {
    Ok(w::SystemInfo {
        kernel_version: v.kernel_version.clone(),
        os_name: v.os_name.clone(),
        os_version: v.os_version.clone(),
        architecture: v.architecture.clone(),
        hostname: v.hostname.clone(),
        ip_addresses: v.ip_addresses.clone(),
    })
}
fn system_from_wire(v: w::SystemInfo) -> Result<libvm::MachineSystemInfo, ConversionError> {
    Ok(libvm::MachineSystemInfo {
        kernel_version: v.kernel_version,
        os_name: v.os_name,
        os_version: v.os_version,
        architecture: v.architecture,
        hostname: v.hostname,
        ip_addresses: v.ip_addresses,
    })
}
fn ssh_to_wire(
    v: &libvm::MachineSshListenerReport,
) -> Result<w::SshListenerReport, ConversionError> {
    Ok(w::SshListenerReport {
        backend: ssh_backend_to(v.backend),
        port: v.port,
        host_public_key: v.host_public_key.clone(),
        config_verified: v.config_verified,
        kex_verified: v.kex_verified,
    })
}
fn ssh_from_wire(
    v: w::SshListenerReport,
) -> Result<libvm::MachineSshListenerReport, ConversionError> {
    Ok(libvm::MachineSshListenerReport {
        backend: ssh_backend_from(v.backend)?,
        port: v.port,
        host_public_key: v.host_public_key,
        config_verified: v.config_verified,
        kex_verified: v.kex_verified,
    })
}
fn guest_boot_to_wire(v: &libvm::MachineGuestBootReport) -> Result<w::BootReport, ConversionError> {
    Ok(w::BootReport {
        mode: guest_boot_mode_to(v.mode),
        requested_init: v.requested_init.clone(),
        handoff_init_path: v.handoff_init_path.clone(),
        probed_init_paths: v.probed_init_paths.clone(),
        agent_path: v.agent_path.clone(),
        message: v.message.clone(),
        agent_pid: v.agent_pid,
        agent_is_pid1: v.agent_is_pid1,
    })
}
fn guest_boot_from_wire(
    v: w::BootReport,
) -> Result<libvm::MachineGuestBootReport, ConversionError> {
    Ok(libvm::MachineGuestBootReport {
        mode: guest_boot_mode_from(v.mode)?,
        requested_init: v.requested_init,
        handoff_init_path: v.handoff_init_path,
        probed_init_paths: v.probed_init_paths,
        agent_path: v.agent_path,
        message: v.message,
        agent_pid: v.agent_pid,
        agent_is_pid1: v.agent_is_pid1,
    })
}
fn step_to_wire(
    v: &libvm::MachineAgentProvisioningStepReport,
) -> Result<w::ProvisionStepReport, ConversionError> {
    Ok(w::ProvisionStepReport {
        id: v.id.clone(),
        status: step_state_to(v.status),
        failure_policy: failure_policy_to(v.failure_policy),
        changed: v.changed,
        backend: v.backend.clone(),
        message: v.message.clone(),
        error_chain: v.error_chain.clone(),
        duration: Some(duration_to_wire(v.duration)?),
    })
}
fn step_from_wire(
    v: w::ProvisionStepReport,
) -> Result<libvm::MachineAgentProvisioningStepReport, ConversionError> {
    Ok(libvm::MachineAgentProvisioningStepReport {
        id: v.id,
        status: step_state_from(v.status)?,
        failure_policy: failure_policy_from(v.failure_policy)?,
        changed: v.changed,
        backend: v.backend,
        message: v.message,
        error_chain: v.error_chain,
        duration: duration_from_wire(required(v.duration, "step.duration")?)?,
    })
}
fn provision_to_wire(
    v: &libvm::MachineProvisioningReport,
) -> Result<w::GuestProvisionReport, ConversionError> {
    Ok(w::GuestProvisionReport {
        status: provision_state_to(v.status),
        started_at: Some(system_time_to_wire(v.started_at)?),
        finished_at: Some(system_time_to_wire(v.finished_at)?),
        duration: Some(duration_to_wire(v.duration)?),
        message: v.message.clone(),
        steps: v.steps.iter().map(step_to_wire).collect::<Result<_, _>>()?,
    })
}
fn provision_from_wire(
    v: w::GuestProvisionReport,
) -> Result<libvm::MachineProvisioningReport, ConversionError> {
    Ok(libvm::MachineProvisioningReport {
        status: provision_state_from(v.status)?,
        started_at: system_time_from_wire(required(v.started_at, "provision.started_at")?)?,
        finished_at: system_time_from_wire(required(v.finished_at, "provision.finished_at")?)?,
        duration: duration_from_wire(required(v.duration, "provision.duration")?)?,
        message: v.message,
        steps: v
            .steps
            .into_iter()
            .map(step_from_wire)
            .collect::<Result<_, _>>()?,
    })
}
fn report_to_wire(
    v: &libvm::MachineAgentStatusReport,
) -> Result<w::AgentStatusReport, ConversionError> {
    Ok(w::AgentStatusReport {
        observed_at: Some(system_time_to_wire(v.observed_at)?),
        state: agent_state_to(v.state),
        code: v.code.clone(),
        message: v.message.clone(),
        system: v.system.as_ref().map(system_to_wire).transpose()?,
        boot: v.boot.as_ref().map(guest_boot_to_wire).transpose()?,
        provisioning: v.provisioning.as_ref().map(provision_to_wire).transpose()?,
        ssh: v.ssh.as_ref().map(ssh_to_wire).transpose()?,
    })
}
fn report_from_wire(
    v: w::AgentStatusReport,
) -> Result<libvm::MachineAgentStatusReport, ConversionError> {
    Ok(libvm::MachineAgentStatusReport {
        observed_at: system_time_from_wire(required(v.observed_at, "agent.observed_at")?)?,
        state: agent_state_from(v.state)?,
        code: v.code,
        message: v.message,
        system: v.system.map(system_from_wire).transpose()?,
        boot: v.boot.map(guest_boot_from_wire).transpose()?,
        provisioning: v.provisioning.map(provision_from_wire).transpose()?,
        ssh: v.ssh.map(ssh_from_wire).transpose()?,
    })
}
fn observation_to_wire(
    v: &libvm::MachineAgentStatusObservation,
) -> Result<w::AgentStatusObservation, ConversionError> {
    Ok(w::AgentStatusObservation {
        received_at: Some(system_time_to_wire(v.received_at)?),
        stale_at: Some(system_time_to_wire(v.stale_at)?),
        freshness: freshness_to(v.freshness),
        stale_reason: v.stale_reason.map(stale_reason_to),
        report: Some(report_to_wire(&v.report)?),
    })
}
fn observation_from_wire(
    v: w::AgentStatusObservation,
) -> Result<libvm::MachineAgentStatusObservation, ConversionError> {
    Ok(libvm::MachineAgentStatusObservation {
        received_at: system_time_from_wire(required(v.received_at, "agent.received_at")?)?,
        stale_at: system_time_from_wire(required(v.stale_at, "agent.stale_at")?)?,
        freshness: freshness_from(v.freshness)?,
        stale_reason: v.stale_reason.map(stale_reason_from).transpose()?,
        report: report_from_wire(required(v.report, "agent.report")?)?,
    })
}
fn enabled_to_wire(v: &libvm::MachineEnabledAgent) -> Result<w::EnabledAgent, ConversionError> {
    Ok(w::EnabledAgent {
        connection: Some(connection_to_wire(&v.connection)?),
        identity: v.identity.as_ref().map(identity_to_wire).transpose()?,
        status: v.status.as_ref().map(observation_to_wire).transpose()?,
        services: v.services.clone(),
    })
}
fn enabled_from_wire(v: w::EnabledAgent) -> Result<libvm::MachineEnabledAgent, ConversionError> {
    Ok(libvm::MachineEnabledAgent {
        connection: connection_from_wire(required(v.connection, "agent.connection")?)?,
        identity: v.identity.map(identity_from_wire).transpose()?,
        status: v.status.map(observation_from_wire).transpose()?,
        services: v.services,
    })
}
fn agent_to_wire(v: &libvm::MachineAgentStatus) -> Result<w::AgentStatus, ConversionError> {
    Ok(w::AgentStatus {
        status: Some(match v {
            libvm::MachineAgentStatus::Disabled => w::agent_status::Status::Disabled(()),
            libvm::MachineAgentStatus::Enabled(v) => {
                w::agent_status::Status::Enabled(Box::new(enabled_to_wire(v)?))
            }
        }),
    })
}
fn agent_from_wire(v: w::AgentStatus) -> Result<libvm::MachineAgentStatus, ConversionError> {
    Ok(match required(v.status, "agent.status")? {
        w::agent_status::Status::Disabled(()) => libvm::MachineAgentStatus::Disabled,
        w::agent_status::Status::Enabled(v) => {
            libvm::MachineAgentStatus::Enabled(Box::new(enabled_from_wire(*v)?))
        }
    })
}
pub fn monitor_status_to_wire(
    v: &libvm::MachineMonitorStatus,
) -> Result<w::MonitorStatus, ConversionError> {
    Ok(w::MonitorStatus {
        machine_id: v.machine_id.clone(),
        run_id: v.run_id.as_ref().map(ToString::to_string),
        name: v.name.clone(),
        monitor: Some(monitor_to_wire(&v.monitor)?),
        vm: Some(vm_to_wire(&v.vm)?),
        readiness: Some(readiness_state_to_wire(&v.readiness)?),
        agent: Some(agent_to_wire(&v.agent)?),
    })
}
pub fn monitor_status_from_wire(
    v: w::MonitorStatus,
) -> Result<libvm::MachineMonitorStatus, ConversionError> {
    validate_uuid(&v.machine_id, "monitor.machine_id")?;
    Ok(libvm::MachineMonitorStatus {
        machine_id: v.machine_id,
        run_id: v
            .run_id
            .map(|v| v.parse().map_err(|_| invalid("run_id", "invalid UUID")))
            .transpose()?,
        name: v.name,
        monitor: monitor_from_wire(required(v.monitor, "monitor")?)?,
        vm: vm_from_wire(required(v.vm, "vm")?)?,
        readiness: readiness_state_from_wire(required(v.readiness, "readiness")?)?,
        agent: agent_from_wire(required(v.agent, "agent")?)?,
    })
}
pub fn readiness_to_wire(
    v: &libvm::MachineReadiness,
) -> Result<w::MachineReadiness, ConversionError> {
    Ok(w::MachineReadiness {
        outcome: match v.outcome {
            libvm::MachineReadinessOutcome::Ready => 1,
            libvm::MachineReadinessOutcome::Terminal => 2,
            libvm::MachineReadinessOutcome::TimedOut => 3,
        },
        data: None,
        status: Some(monitor_status_to_wire(&v.status)?),
    })
}
pub fn readiness_from_wire(
    v: w::MachineReadiness,
) -> Result<libvm::MachineReadiness, ConversionError> {
    Ok(libvm::MachineReadiness {
        outcome: match v.outcome {
            1 => libvm::MachineReadinessOutcome::Ready,
            2 => libvm::MachineReadinessOutcome::Terminal,
            3 => libvm::MachineReadinessOutcome::TimedOut,
            _ => return Err(invalid("readiness.outcome", "invalid enum")),
        },
        status: monitor_status_from_wire(required(v.status, "readiness.status")?)?,
    })
}

use crate::snapshots::{millis_from_wire, timestamp_millis};
use crate::{duration_from_wire, duration_to_wire, invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;
fn boot_to(v: libvm::MachineBootMode) -> i32 {
    match v {
        libvm::MachineBootMode::Unspecified => 0,
        libvm::MachineBootMode::Standard => 1,
        libvm::MachineBootMode::AgentPid1 => 2,
        libvm::MachineBootMode::InitChild => 3,
    }
}
fn boot_from(v: i32) -> Result<libvm::MachineBootMode, ConversionError> {
    match v {
        0 => Ok(libvm::MachineBootMode::Unspecified),
        1 => Ok(libvm::MachineBootMode::Standard),
        2 => Ok(libvm::MachineBootMode::AgentPid1),
        3 => Ok(libvm::MachineBootMode::InitChild),
        _ => Err(invalid("boot", "invalid enum")),
    }
}
fn provision_status_to(v: libvm::MachineProvisionStatus) -> i32 {
    match v {
        libvm::MachineProvisionStatus::Unspecified => 0,
        libvm::MachineProvisionStatus::Succeeded => 1,
        libvm::MachineProvisionStatus::Degraded => 2,
        libvm::MachineProvisionStatus::Skipped => 3,
        libvm::MachineProvisionStatus::FailedBoot => 4,
    }
}
fn provision_status_from(v: i32) -> Result<libvm::MachineProvisionStatus, ConversionError> {
    match v {
        0 => Ok(libvm::MachineProvisionStatus::Unspecified),
        1 => Ok(libvm::MachineProvisionStatus::Succeeded),
        2 => Ok(libvm::MachineProvisionStatus::Degraded),
        3 => Ok(libvm::MachineProvisionStatus::Skipped),
        4 => Ok(libvm::MachineProvisionStatus::FailedBoot),
        _ => Err(invalid("provision_status", "invalid enum")),
    }
}
fn step_status_to(v: libvm::MachineProvisionStepStatus) -> i32 {
    match v {
        libvm::MachineProvisionStepStatus::Unspecified => 0,
        libvm::MachineProvisionStepStatus::Succeeded => 1,
        libvm::MachineProvisionStepStatus::Failed => 2,
        libvm::MachineProvisionStepStatus::Skipped => 3,
        libvm::MachineProvisionStepStatus::Unsupported => 4,
    }
}
fn step_status_from(v: i32) -> Result<libvm::MachineProvisionStepStatus, ConversionError> {
    match v {
        0 => Ok(libvm::MachineProvisionStepStatus::Unspecified),
        1 => Ok(libvm::MachineProvisionStepStatus::Succeeded),
        2 => Ok(libvm::MachineProvisionStepStatus::Failed),
        3 => Ok(libvm::MachineProvisionStepStatus::Skipped),
        4 => Ok(libvm::MachineProvisionStepStatus::Unsupported),
        _ => Err(invalid("step_status", "invalid enum")),
    }
}
fn failure_policy_to(v: libvm::MachineProvisionFailurePolicy) -> i32 {
    match v {
        libvm::MachineProvisionFailurePolicy::Unspecified => 0,
        libvm::MachineProvisionFailurePolicy::BestEffort => 1,
        libvm::MachineProvisionFailurePolicy::FailBoot => 2,
    }
}
fn failure_policy_from(v: i32) -> Result<libvm::MachineProvisionFailurePolicy, ConversionError> {
    match v {
        0 => Ok(libvm::MachineProvisionFailurePolicy::Unspecified),
        1 => Ok(libvm::MachineProvisionFailurePolicy::BestEffort),
        2 => Ok(libvm::MachineProvisionFailurePolicy::FailBoot),
        _ => Err(invalid("failure_policy", "invalid enum")),
    }
}
pub fn boot_to_wire(v: &libvm::MachineBootReport) -> w::BootReport {
    w::BootReport {
        mode: boot_to(v.mode),
        requested_init: v.requested_init.clone(),
        handoff_init_path: v.handoff_init_path.clone(),
        probed_init_paths: v.probed_init_paths.clone(),
        agent_path: v.agent_path.clone(),
        agent_pid: v.agent_pid,
        agent_is_pid1: v.agent_is_pid1,
        message: v.message.clone(),
    }
}
pub fn boot_from_wire(v: w::BootReport) -> Result<libvm::MachineBootReport, ConversionError> {
    Ok(libvm::MachineBootReport {
        mode: boot_from(v.mode)?,
        requested_init: v.requested_init,
        handoff_init_path: v.handoff_init_path,
        probed_init_paths: v.probed_init_paths,
        agent_path: v.agent_path,
        agent_pid: v.agent_pid,
        agent_is_pid1: v.agent_is_pid1,
        message: v.message,
    })
}
pub fn provision_to_wire(
    v: &libvm::MachineProvisionReport,
) -> Result<w::ProvisionReport, ConversionError> {
    Ok(w::ProvisionReport {
        status: provision_status_to(v.status),
        started_at: Some(timestamp_millis(v.started_unix_ms)),
        finished_at: Some(timestamp_millis(v.finished_unix_ms)),
        duration: Some(duration_to_wire(std::time::Duration::from_millis(
            v.duration_ms,
        ))?),
        steps: v
            .steps
            .iter()
            .map(|v| {
                Ok(w::ProvisionStepReport {
                    id: v.id.clone(),
                    status: step_status_to(v.status),
                    failure_policy: failure_policy_to(v.failure_policy),
                    changed: v.changed,
                    backend: v.backend.clone(),
                    duration: Some(duration_to_wire(std::time::Duration::from_millis(
                        v.duration_ms,
                    ))?),
                    message: v.message.clone(),
                    error_chain: v.error_chain.clone(),
                })
            })
            .collect::<Result<_, ConversionError>>()?,
        message: v.message.clone(),
    })
}
fn duration_ms(v: Option<prost_types::Duration>) -> Result<u64, ConversionError> {
    let v = duration_from_wire(required(v, "duration")?)?;
    if v.subsec_nanos() % 1_000_000 != 0 {
        return Err(invalid("duration", "not whole milliseconds"));
    }
    v.as_millis()
        .try_into()
        .map_err(|_| invalid("duration", "overflow"))
}
pub fn provision_from_wire(
    v: w::ProvisionReport,
) -> Result<libvm::MachineProvisionReport, ConversionError> {
    Ok(libvm::MachineProvisionReport {
        status: provision_status_from(v.status)?,
        started_unix_ms: millis_from_wire(v.started_at, "provision.started_at")?,
        finished_unix_ms: millis_from_wire(v.finished_at, "provision.finished_at")?,
        duration_ms: duration_ms(v.duration)?,
        steps: v
            .steps
            .into_iter()
            .map(|v| {
                Ok(libvm::MachineProvisionStepReport {
                    id: v.id,
                    status: step_status_from(v.status)?,
                    failure_policy: failure_policy_from(v.failure_policy)?,
                    changed: v.changed,
                    backend: v.backend,
                    duration_ms: duration_ms(v.duration)?,
                    message: v.message,
                    error_chain: v.error_chain,
                })
            })
            .collect::<Result<_, ConversionError>>()?,
        message: v.message,
    })
}

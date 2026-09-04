use libvm::{
    MachineAgent, MachineBootReport, MachineData, MachineNetworkConfig, MachineProvisionReport,
    MachineProvisionStepReport, MachineRootfs, MachineStatus,
};
use serde_json::{json, Value};

pub fn machine_data(data: MachineData) -> Value {
    json!({
        "id": data.id,
        "name": data.name,
        "machine_dir": data.machine_dir.display().to_string(),
        "created_at_unix_ms": data.created_at,
        "modified_at_unix_ms": data.modified_at,
        "image_ref": data.image_ref,
        "retention": match data.retention {
            libvm::MachineRetention::Persistent => "persistent",
            libvm::MachineRetention::Ephemeral => "ephemeral",
        },
        "process": {
            "entrypoint": data.process.entrypoint,
            "command": data.process.command,
            "environment": data.process.environment,
            "working_directory": data.process.working_directory,
            "user": data.process.user,
        },
        "template_name": data.template_name,
        "agent_mode": data.agent_mode.map(machine_agent),
        "rootfs": data.rootfs.map(machine_rootfs),
        "root_disk_size_bytes": data.root_disk_size,
        "labels": data.labels,
        "metadata": data.metadata,
        "network": machine_network(data.network),
        "forwards": data.spec.forwards,
        "vsock": data.spec.vsock,
        "agent": machine_agent(data.guest.agent),
        "status": machine_status(data.status),
        "boot_report": data.boot_report.map(boot_report),
        "provision_report": data.provision_report.map(provision_report),
        "started_at_unix_ms": data.started_at,
        "last_error": data.last_error,
        "updated_at_unix_ms": data.updated_at,
    })
}

fn machine_agent(agent: MachineAgent) -> Value {
    match agent {
        MachineAgent::Default => json!({"mode": "default"}),
        MachineAgent::Custom { path } => {
            json!({"mode": "custom", "path": path.display().to_string()})
        }
        MachineAgent::Disabled => json!({"mode": "disabled"}),
        _ => json!({"mode": "unknown"}),
    }
}

fn machine_rootfs(rootfs: MachineRootfs) -> Value {
    json!({
        "source_kind": match rootfs.source_kind {
            libvm::ImageSourceKind::Oci => "oci",
            libvm::ImageSourceKind::Disk => "disk",
        },
        "requested_reference": rootfs.requested_reference,
        "selected_reference": rootfs.selected_reference,
        "selected_manifest_digest": rootfs.selected_manifest_digest,
        "config_digest": rootfs.config_digest,
        "image_id": rootfs.image_id,
        "root_disk_path": rootfs.root_disk_path.display().to_string(),
        "root_disk_size_bytes": rootfs.root_disk_size_bytes,
        "created_at_unix_ms": rootfs.created_at,
    })
}

fn machine_network(network: MachineNetworkConfig) -> Value {
    match network {
        MachineNetworkConfig::Private { policy, publish } => json!({
            "publish": publish,
            "kind": "private",
            "policy_json": policy.and_then(|policy| serde_json::to_string(&policy.normalized()).ok()),
        }),
        MachineNetworkConfig::None => json!({"kind": "none"}),
        MachineNetworkConfig::Named { name } => json!({"kind": "named", "name": name}),
        _ => json!({"kind": "unknown"}),
    }
}

fn machine_status(status: MachineStatus) -> Value {
    match status {
        MachineStatus::Stopped => json!({"kind": "stopped"}),
        MachineStatus::Starting { message } => json!({"kind": "starting", "message": message}),
        MachineStatus::Running {
            ready,
            guest_ready,
            message,
        } => json!({
            "kind": "running",
            "ready": ready,
            "guest_ready": guest_ready,
            "message": message,
        }),
        MachineStatus::Stopping { message } => json!({"kind": "stopping", "message": message}),
        MachineStatus::Error { message } => json!({"kind": "error", "message": message}),
        _ => json!({"kind": "unknown"}),
    }
}

fn boot_report(report: MachineBootReport) -> Value {
    json!({
        "mode": report.mode.label(),
        "requested_init": report.requested_init,
        "handoff_init_path": report.handoff_init_path,
        "probed_init_paths": report.probed_init_paths,
        "agent_path": report.agent_path,
        "agent_pid": report.agent_pid,
        "agent_is_pid1": report.agent_is_pid1,
        "message": report.message,
    })
}

fn provision_report(report: MachineProvisionReport) -> Value {
    json!({
        "status": report.status.label(),
        "started_at_unix_ms": report.started_unix_ms,
        "finished_at_unix_ms": report.finished_unix_ms,
        "duration_ms": report.duration_ms,
        "steps": report.steps.into_iter().map(provision_step).collect::<Vec<_>>(),
        "message": report.message,
    })
}

fn provision_step(report: MachineProvisionStepReport) -> Value {
    json!({
        "id": report.id,
        "status": report.status.label(),
        "failure_policy": report.failure_policy.label(),
        "changed": report.changed,
        "backend": report.backend,
        "duration_ms": report.duration_ms,
        "message": report.message,
        "error_chain": report.error_chain,
    })
}

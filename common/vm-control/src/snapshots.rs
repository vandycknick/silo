use crate::values::*;
use crate::{invalid, path_from_wire, path_to_wire, required, validate_uuid, ConversionError};
use silod_spec::daemon::v1 as w;
pub fn timestamp(v: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: v,
        nanos: 0,
    }
}
pub fn timestamp_seconds(
    v: Option<prost_types::Timestamp>,
    field: &'static str,
) -> Result<i64, ConversionError> {
    let v = required(v, field)?;
    if v.nanos != 0 || !(-62135596800..=253402300799).contains(&v.seconds) {
        return Err(invalid(field, "invalid whole-second timestamp"));
    }
    Ok(v.seconds)
}
pub fn timestamp_millis(v: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: v.div_euclid(1000),
        nanos: (v.rem_euclid(1000) * 1_000_000) as i32,
    }
}
pub fn millis_from_wire(
    v: Option<prost_types::Timestamp>,
    field: &'static str,
) -> Result<i64, ConversionError> {
    let v = required(v, field)?;
    if !(0..1_000_000_000).contains(&v.nanos) || v.nanos % 1_000_000 != 0 {
        return Err(invalid(field, "invalid millisecond timestamp"));
    }
    v.seconds
        .checked_mul(1000)
        .and_then(|s| s.checked_add(v.nanos as i64 / 1_000_000))
        .ok_or_else(|| invalid(field, "overflow"))
}
pub fn status_to_wire(v: &libvm::MachineStatus) -> Result<w::MachineStatus, ConversionError> {
    use w::machine_status::Status;
    Ok(w::MachineStatus {
        status: Some(match v {
            libvm::MachineStatus::Stopped => Status::Stopped(()),
            libvm::MachineStatus::Starting { message } => Status::Starting(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Running {
                ready,
                guest_ready,
                message,
            } => Status::Running(w::RunningStatus {
                ready: *ready,
                guest_ready: *guest_ready,
                message: message.clone(),
            }),
            libvm::MachineStatus::Stopping { message } => Status::Stopping(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Error { message } => Status::Error(w::LifecycleDetail {
                message: message.clone(),
            }),
            _ => return Err(invalid("status", "unsupported native variant")),
        }),
    })
}
pub fn status_from_wire(v: w::MachineStatus) -> Result<libvm::MachineStatus, ConversionError> {
    use w::machine_status::Status;
    Ok(match required(v.status, "status")? {
        Status::Stopped(()) => libvm::MachineStatus::Stopped,
        Status::Starting(v) => libvm::MachineStatus::Starting { message: v.message },
        Status::Running(v) => libvm::MachineStatus::Running {
            ready: v.ready,
            guest_ready: v.guest_ready,
            message: v.message,
        },
        Status::Stopping(v) => libvm::MachineStatus::Stopping { message: v.message },
        Status::Error(v) => libvm::MachineStatus::Error { message: v.message },
    })
}
pub fn issue_to_wire(v: &libvm::MachineIssue) -> w::MachineIssue {
    w::MachineIssue {
        component: match v.component {
            libvm::MachineIssueComponent::Lifecycle => 1,
            libvm::MachineIssueComponent::Telemetry => 2,
            libvm::MachineIssueComponent::Network => 3,
            libvm::MachineIssueComponent::Rootfs => 4,
            libvm::MachineIssueComponent::Configuration => 5,
        },
        message: v.message.clone(),
    }
}
pub fn issue_from_wire(v: w::MachineIssue) -> Result<libvm::MachineIssue, ConversionError> {
    Ok(libvm::MachineIssue {
        component: match v.component {
            1 => libvm::MachineIssueComponent::Lifecycle,
            2 => libvm::MachineIssueComponent::Telemetry,
            3 => libvm::MachineIssueComponent::Network,
            4 => libvm::MachineIssueComponent::Rootfs,
            5 => libvm::MachineIssueComponent::Configuration,
            _ => return Err(invalid("issue.component", "invalid enum")),
        },
        message: v.message,
    })
}
fn rootfs_to_wire(v: &libvm::MachineRootfs) -> Result<w::Rootfs, ConversionError> {
    Ok(w::Rootfs {
        source_kind: match v.source_kind {
            libvm::ImageSourceKind::Oci => 1,
            libvm::ImageSourceKind::Disk => 2,
        },
        requested_reference: v.requested_reference.clone(),
        selected_reference: v.selected_reference.clone(),
        manifest_digest: v.selected_manifest_digest.clone(),
        config_digest: v.config_digest.clone(),
        image_id: v.image_id.clone(),
        root_disk_path: path_to_wire(&v.root_disk_path),
        root_disk_size_bytes: v.root_disk_size_bytes,
        created_at: Some(timestamp(v.created_at)),
    })
}
fn rootfs_from_wire(v: w::Rootfs) -> Result<libvm::MachineRootfs, ConversionError> {
    let mut out = libvm::MachineRootfs::new(
        match v.source_kind {
            1 => libvm::ImageSourceKind::Oci,
            2 => libvm::ImageSourceKind::Disk,
            _ => return Err(invalid("rootfs.source_kind", "invalid enum")),
        },
        v.requested_reference,
        path_from_wire(v.root_disk_path)?,
        v.root_disk_size_bytes,
        timestamp_seconds(v.created_at, "rootfs.created_at")?,
    );
    out.selected_reference = v.selected_reference;
    out.selected_manifest_digest = v.manifest_digest;
    out.config_digest = v.config_digest;
    out.image_id = v.image_id;
    Ok(out)
}
pub fn snapshot_to_wire(v: &libvm::MachineData) -> Result<w::MachineSnapshot, ConversionError> {
    Ok(w::MachineSnapshot {
        id: v.id.clone(),
        name: v.name.clone(),
        spec: Some(crate::spec::spec_to_wire(&v.spec)),
        retention: retention_to_wire(v.retention),
        process: Some(process_to_wire(&v.process)),
        template_name: v.template_name.clone(),
        agent_mode: v.agent_mode.as_ref().map(agent_to_wire).transpose()?,
        machine_dir: path_to_wire(&v.machine_dir),
        created_at: Some(timestamp(v.created_at)),
        modified_at: Some(timestamp(v.modified_at)),
        image_ref: v.image_ref.clone(),
        rootfs: v.rootfs.as_ref().map(rootfs_to_wire).transpose()?,
        root_disk_size: v.root_disk_size,
        labels: v.labels.clone(),
        metadata: v.metadata.clone(),
        network: Some(network_to_wire(&v.network)?),
        tailscale: v.tailscale.as_ref().map(|v| w::MachineTailscale {
            state_dir: path_to_wire(&v.state_dir),
            hostname: v.hostname.clone(),
            ephemeral: v.ephemeral,
        }),
        guest: Some(guest_to_wire(&v.guest)?),
        status: Some(status_to_wire(&v.status)?),
        observation: match v.observation {
            libvm::MachineObservation::Observed => 1,
            libvm::MachineObservation::LastKnown => 2,
            libvm::MachineObservation::Unavailable => 3,
        },
        issues: v.issues.iter().map(issue_to_wire).collect(),
        run_id: v.run_id.as_ref().map(ToString::to_string),
        boot_report: v.boot_report.as_ref().map(crate::reports::boot_to_wire),
        provision_report: v
            .provision_report
            .as_ref()
            .map(crate::reports::provision_to_wire)
            .transpose()?,
        started_at: v.started_at.map(timestamp),
        last_error: v.last_error.clone(),
        updated_at: Some(timestamp(v.updated_at)),
        network_observation: None,
    })
}
pub fn snapshot_from_wire(v: w::MachineSnapshot) -> Result<libvm::MachineData, ConversionError> {
    validate_uuid(&v.id, "machine.id")?;
    let mut out = libvm::MachineData::new(
        v.id,
        v.name,
        crate::spec::spec_from_wire(required(v.spec, "machine.spec")?)?,
    );
    out.retention = retention_from_wire(v.retention)?;
    out.process = process_from_wire(required(v.process, "machine.process")?);
    out.template_name = v.template_name;
    out.agent_mode = v.agent_mode.map(agent_from_wire).transpose()?;
    out.machine_dir = path_from_wire(v.machine_dir)?;
    out.created_at = timestamp_seconds(v.created_at, "machine.created_at")?;
    out.modified_at = timestamp_seconds(v.modified_at, "machine.modified_at")?;
    out.image_ref = v.image_ref;
    out.rootfs = v.rootfs.map(rootfs_from_wire).transpose()?;
    out.root_disk_size = v.root_disk_size;
    out.labels = v.labels;
    out.metadata = v.metadata;
    out.network = network_from_wire(required(v.network, "machine.network")?)?;
    out.tailscale = v
        .tailscale
        .map(|v| {
            Ok::<_, ConversionError>(libvm::MachineTailscale {
                state_dir: path_from_wire(v.state_dir)?,
                hostname: v.hostname,
                ephemeral: v.ephemeral,
            })
        })
        .transpose()?;
    out.guest = guest_from_wire(required(v.guest, "machine.guest")?)?;
    out.status = status_from_wire(required(v.status, "machine.status")?)?;
    out.observation = match v.observation {
        1 => libvm::MachineObservation::Observed,
        2 => libvm::MachineObservation::LastKnown,
        3 => libvm::MachineObservation::Unavailable,
        _ => return Err(invalid("observation", "invalid enum")),
    };
    out.issues = v
        .issues
        .into_iter()
        .map(issue_from_wire)
        .collect::<Result<_, _>>()?;
    out.run_id = v
        .run_id
        .map(|v| v.parse().map_err(|_| invalid("run_id", "invalid UUID")))
        .transpose()?;
    out.boot_report = v
        .boot_report
        .map(crate::reports::boot_from_wire)
        .transpose()?;
    out.provision_report = v
        .provision_report
        .map(crate::reports::provision_from_wire)
        .transpose()?;
    out.started_at = v
        .started_at
        .map(|v| timestamp_seconds(Some(v), "started_at"))
        .transpose()?;
    out.last_error = v.last_error;
    out.updated_at = timestamp_seconds(v.updated_at, "updated_at")?;
    Ok(out)
}
pub fn inventory_to_wire(
    v: &libvm::MachineInventoryEntry,
) -> Result<w::MachineInventoryEntry, ConversionError> {
    Ok(w::MachineInventoryEntry {
        id: v.id.clone(),
        name: v.name.clone(),
        data: v.data.as_ref().map(snapshot_to_wire).transpose()?,
        issues: v.issues.iter().map(issue_to_wire).collect(),
    })
}
pub fn inventory_from_wire(
    v: w::MachineInventoryEntry,
) -> Result<libvm::MachineInventoryEntry, ConversionError> {
    validate_uuid(&v.id, "inventory.id")?;
    let data = v.data.map(snapshot_from_wire).transpose()?;
    if data
        .as_ref()
        .is_some_and(|x| x.id != v.id || x.name != v.name)
    {
        return Err(invalid("inventory.data", "identity mismatch"));
    }
    Ok(libvm::MachineInventoryEntry {
        id: v.id,
        name: v.name,
        data,
        issues: v
            .issues
            .into_iter()
            .map(issue_from_wire)
            .collect::<Result<_, _>>()?,
    })
}

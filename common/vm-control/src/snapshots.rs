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
            libvm::MachineStatus::Pausing { message } => Status::Pausing(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Paused { message } => Status::Paused(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Capturing { message } => Status::Capturing(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Restoring { message } => Status::Restoring(w::LifecycleDetail {
                message: message.clone(),
            }),
            libvm::MachineStatus::Activating { message } => {
                Status::Activating(w::LifecycleDetail {
                    message: message.clone(),
                })
            }
            libvm::MachineStatus::ActivationFailed { message } => {
                Status::ActivationFailed(w::LifecycleDetail {
                    message: message.clone(),
                })
            }
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
        Status::Pausing(v) => libvm::MachineStatus::Pausing { message: v.message },
        Status::Paused(v) => libvm::MachineStatus::Paused { message: v.message },
        Status::Capturing(v) => libvm::MachineStatus::Capturing { message: v.message },
        Status::Restoring(v) => libvm::MachineStatus::Restoring { message: v.message },
        Status::Activating(v) => libvm::MachineStatus::Activating { message: v.message },
        Status::ActivationFailed(v) => {
            libvm::MachineStatus::ActivationFailed { message: v.message }
        }
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
            libvm::ImageSourceKind::Managed => 3,
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
            3 => libvm::ImageSourceKind::Managed,
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
fn storage_stop_outcome_to_wire(v: libvm::StorageStopOutcome) -> w::StorageStopOutcome {
    match v {
        libvm::StorageStopOutcome::Clean => w::StorageStopOutcome::Clean,
        libvm::StorageStopOutcome::Forced => w::StorageStopOutcome::Forced,
        libvm::StorageStopOutcome::Unknown => w::StorageStopOutcome::Unknown,
    }
}
fn storage_stop_outcome_from_wire(v: i32) -> Result<libvm::StorageStopOutcome, ConversionError> {
    match w::StorageStopOutcome::try_from(v) {
        Ok(w::StorageStopOutcome::Clean) => Ok(libvm::StorageStopOutcome::Clean),
        Ok(w::StorageStopOutcome::Forced) => Ok(libvm::StorageStopOutcome::Forced),
        Ok(w::StorageStopOutcome::Unknown) => Ok(libvm::StorageStopOutcome::Unknown),
        Ok(w::StorageStopOutcome::Unspecified) | Err(_) => {
            Err(invalid("machine.storage_stop_outcome", "invalid enum"))
        }
    }
}
pub fn snapshot_to_wire(v: &libvm::MachineData) -> Result<w::MachineSnapshot, ConversionError> {
    if v.live.is_some() && v.prospective_live.is_some() {
        return Err(invalid(
            "machine.live_evidence",
            "run and prospective evidence are exclusive",
        ));
    }
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
        lifecycle: v
            .lifecycle
            .as_ref()
            .map(crate::pause::projection_to_wire)
            .transpose()?,
        live: v
            .live
            .as_ref()
            .map(crate::live::machine_to_wire)
            .transpose()?,
        prospective_live: v
            .prospective_live
            .as_ref()
            .map(crate::live::host_to_wire)
            .transpose()?,
        live_evidence: Some(if v.live.is_some() {
            1
        } else if v.prospective_live.is_some() {
            2
        } else {
            3
        }),
        captures: v
            .captures
            .iter()
            .map(crate::capture::machine_capture_to_wire)
            .collect::<Result<_, _>>()?,
        boot: crate::boot::machine_boot_to_wire(
            v.boot_profile.as_ref(),
            v.boot_replacement.as_ref(),
        )?,
        storage_stop_outcome: v
            .storage_stop_outcome
            .map(|outcome| storage_stop_outcome_to_wire(outcome) as i32),
    })
}
pub fn snapshot_from_wire(v: w::MachineSnapshot) -> Result<libvm::MachineData, ConversionError> {
    match (
        required(v.live_evidence, "machine.live_evidence")?,
        v.live.is_some(),
        v.prospective_live.is_some(),
    ) {
        (1, true, false) | (2, false, true) | (3, false, false) => {}
        _ => {
            return Err(invalid(
                "machine.live_evidence",
                "invalid evidence discriminator/payload",
            ))
        }
    }
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
    out.live = v.live.map(crate::live::machine_from_wire).transpose()?;
    out.lifecycle = v
        .lifecycle
        .map(crate::pause::projection_from_wire)
        .transpose()?;
    if let Some(lifecycle) = &out.lifecycle {
        if !crate::live::same_machine_identity(&lifecycle.report.machine_id, &out.id)
            || out.run_id.as_ref().map(ToString::to_string).as_deref()
                != Some(lifecycle.report.run_id.as_str())
        {
            return Err(invalid("machine.lifecycle", "projection identity mismatch"));
        }
    }
    out.prospective_live = v
        .prospective_live
        .map(crate::live::host_from_wire)
        .transpose()?;
    if v.captures.len() > 4096 {
        return Err(invalid("machine.captures", "too many retained captures"));
    }
    out.captures = v
        .captures
        .into_iter()
        .map(crate::capture::machine_capture_from_wire)
        .collect::<Result<_, _>>()?;
    (out.boot_profile, out.boot_replacement) = crate::boot::machine_boot_from_wire(v.boot)?;
    out.storage_stop_outcome = v
        .storage_stop_outcome
        .map(storage_stop_outcome_from_wire)
        .transpose()?;
    if let Some(live) = &out.live {
        if !crate::live::same_machine_identity(&live.machine_id, &out.id)
            || Some(live.run_id.as_str())
                != out.run_id.as_ref().map(|run| run.to_string()).as_deref()
        {
            return Err(invalid("machine.live", "report identity mismatch"));
        }
    }
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

pub fn verification_to_wire(
    result: Result<&libvm::SnapshotVerificationReport, &libvm::SnapshotVerificationError>,
) -> w::SnapshotVerificationResult {
    use w::snapshot_verification_result::Result as Wire;
    w::SnapshotVerificationResult {
        result: Some(match result {
            Ok(report) => Wire::Report(w::SnapshotVerificationReport {
                snapshot: report.snapshot.to_string(),
                streams: report.streams,
                bytes: report.bytes,
            }),
            Err(error) => Wire::Error(verification_error_to_wire(error)),
        }),
    }
}

pub fn verification_from_wire(
    value: w::SnapshotVerificationResult,
) -> Result<Result<libvm::SnapshotVerificationReport, libvm::LibVmError>, ConversionError> {
    use w::snapshot_verification_result::Result as Wire;
    Ok(match required(value.result, "verification.result")? {
        Wire::Report(report) => Ok(libvm::SnapshotVerificationReport {
            snapshot: report
                .snapshot
                .parse()
                .map_err(|_| invalid("verification.snapshot", "invalid snapshot identity"))?,
            streams: report.streams,
            bytes: report.bytes,
        }),
        Wire::Error(error) => Err(libvm::LibVmError::SnapshotVerification(
            verification_error_from_wire(error)?,
        )),
    })
}

fn verification_role_to_wire(
    role: &libvm::SnapshotVerificationRole,
) -> (w::SnapshotVerificationRole, Option<u32>) {
    use libvm::SnapshotVerificationRole as Native;
    use w::SnapshotVerificationRole as Wire;
    match role {
        Native::Ram => (Wire::Ram, None),
        Native::Layout => (Wire::Layout, None),
        Native::Execution => (Wire::Execution, None),
        Native::Devices => (Wire::Devices, None),
        Native::RootDisk => (Wire::RootDisk, None),
        Native::DataDisk { order } => (Wire::DataDisk, Some(*order)),
        Native::Dependency => (Wire::Dependency, None),
    }
}

fn verification_role_from_wire(
    role: i32,
    order: Option<u32>,
) -> Result<libvm::SnapshotVerificationRole, ConversionError> {
    use libvm::SnapshotVerificationRole as Native;
    use w::SnapshotVerificationRole as Wire;
    let role = Wire::try_from(role).map_err(|_| invalid("verification.role", "unknown role"))?;
    if order.is_some() && role != Wire::DataDisk {
        return Err(invalid(
            "verification.disk_order",
            "only data disks have an order",
        ));
    }
    Ok(match role {
        Wire::Ram => Native::Ram,
        Wire::Layout => Native::Layout,
        Wire::Execution => Native::Execution,
        Wire::Devices => Native::Devices,
        Wire::RootDisk => Native::RootDisk,
        Wire::DataDisk => Native::DataDisk {
            order: required(order, "verification.disk_order")?,
        },
        Wire::Dependency => Native::Dependency,
        Wire::Unspecified => return Err(invalid("verification.role", "missing role")),
    })
}

fn verification_chunk_to_wire(chunk: libvm::storage::stream::Chunk) -> w::VerificationChunk {
    use libvm::storage::stream::Chunk;
    use w::verification_chunk::Identity;
    w::VerificationChunk {
        identity: Some(match chunk {
            Chunk::Zero => Identity::Zero(()),
            Chunk::Data(digest) => Identity::Data(digest.to_string()),
        }),
    }
}

fn verification_chunk_from_wire(
    chunk: w::VerificationChunk,
) -> Result<libvm::storage::stream::Chunk, ConversionError> {
    use libvm::storage::stream::Chunk;
    use w::verification_chunk::Identity;
    Ok(
        match required(chunk.identity, "verification.chunk.identity")? {
            Identity::Zero(()) => Chunk::Zero,
            Identity::Data(digest) => Chunk::Data(
                digest
                    .parse()
                    .map_err(|_| invalid("verification.chunk.data", "invalid object identity"))?,
            ),
        },
    )
}

fn verification_error_to_wire(
    error: &libvm::SnapshotVerificationError,
) -> w::SnapshotVerificationError {
    use libvm::{
        SnapshotStructuralFailure as Failure, SnapshotVerificationError as Native,
        SnapshotVerificationMember as Member,
    };
    use w::snapshot_structural_failure::Failure as WireFailure;
    use w::snapshot_verification_error::Error as Wire;
    let (role, error) = match error {
        Native::Structural {
            role,
            member,
            failure,
        } => {
            let member = match member {
                Member::Stream(id) => {
                    w::snapshot_verification_member::Member::Stream(id.to_string())
                }
                Member::Object(id) => {
                    w::snapshot_verification_member::Member::Object(id.to_string())
                }
            };
            let failure = match failure {
                Failure::Missing => WireFailure::Missing(()),
                Failure::Truncated { expected, actual } => {
                    WireFailure::Truncated(w::VerificationLengths {
                        expected: *expected,
                        actual: *actual,
                    })
                }
                Failure::Length { expected, actual } => {
                    WireFailure::Length(w::VerificationLengths {
                        expected: *expected,
                        actual: *actual,
                    })
                }
                Failure::Writable { mode } => WireFailure::Writable(*mode),
                Failure::Replaced => WireFailure::Replaced(()),
                Failure::Invalid { message } => WireFailure::Invalid(message.clone()),
            };
            (
                role,
                Wire::Structural(w::SnapshotStructuralError {
                    member: Some(w::SnapshotVerificationMember {
                        member: Some(member),
                    }),
                    failure: Some(w::SnapshotStructuralFailure {
                        failure: Some(failure),
                    }),
                }),
            )
        }
        Native::ChunkMismatch {
            role,
            stream,
            index,
            start,
            end,
            expected,
            actual,
        } => (
            role,
            Wire::Chunk(w::SnapshotChunkMismatch {
                stream: stream.to_string(),
                index: *index,
                start: *start,
                end: *end,
                expected: Some(verification_chunk_to_wire(**expected)),
                actual: Some(verification_chunk_to_wire(**actual)),
            }),
        ),
        Native::ObjectMismatch {
            role,
            object,
            length,
            actual,
        } => (
            role,
            Wire::Object(w::SnapshotObjectMismatch {
                object: object.to_string(),
                length: *length,
                actual: actual.to_string(),
            }),
        ),
    };
    let (role, disk_order) = verification_role_to_wire(role);
    w::SnapshotVerificationError {
        role: role.into(),
        disk_order,
        error: Some(error),
    }
}

fn verification_error_from_wire(
    error: w::SnapshotVerificationError,
) -> Result<libvm::SnapshotVerificationError, ConversionError> {
    use libvm::{
        SnapshotStructuralFailure as Failure, SnapshotVerificationError as Native,
        SnapshotVerificationMember as Member,
    };
    use w::snapshot_structural_failure::Failure as WireFailure;
    use w::snapshot_verification_error::Error as Wire;
    let role = verification_role_from_wire(error.role, error.disk_order)?;
    Ok(match required(error.error, "verification.error")? {
        Wire::Structural(error) => {
            let member = required(error.member, "verification.member")?;
            let member = match required(member.member, "verification.member.identity")? {
                w::snapshot_verification_member::Member::Stream(id) => {
                    Member::Stream(id.parse().map_err(|_| {
                        invalid("verification.member.stream", "invalid stream identity")
                    })?)
                }
                w::snapshot_verification_member::Member::Object(id) => {
                    Member::Object(id.parse().map_err(|_| {
                        invalid("verification.member.object", "invalid object identity")
                    })?)
                }
            };
            let failure = required(error.failure, "verification.failure")?;
            let failure = match required(failure.failure, "verification.failure.kind")? {
                WireFailure::Missing(()) => Failure::Missing,
                WireFailure::Truncated(lengths) => Failure::Truncated {
                    expected: lengths.expected,
                    actual: lengths.actual,
                },
                WireFailure::Length(lengths) => Failure::Length {
                    expected: lengths.expected,
                    actual: lengths.actual,
                },
                WireFailure::Writable(mode) => Failure::Writable { mode },
                WireFailure::Replaced(()) => Failure::Replaced,
                WireFailure::Invalid(message) => Failure::Invalid { message },
            };
            Native::Structural {
                role,
                member,
                failure,
            }
        }
        Wire::Chunk(error) => {
            if error.start >= error.end {
                return Err(invalid(
                    "verification.chunk.range",
                    "expected a nonempty byte range",
                ));
            }
            Native::ChunkMismatch {
                role,
                stream: error
                    .stream
                    .parse()
                    .map_err(|_| invalid("verification.stream", "invalid stream identity"))?,
                index: error.index,
                start: error.start,
                end: error.end,
                expected: Box::new(verification_chunk_from_wire(required(
                    error.expected,
                    "verification.expected",
                )?)?),
                actual: Box::new(verification_chunk_from_wire(required(
                    error.actual,
                    "verification.actual",
                )?)?),
            }
        }
        Wire::Object(error) => Native::ObjectMismatch {
            role,
            object: error
                .object
                .parse()
                .map_err(|_| invalid("verification.object", "invalid object identity"))?,
            length: error.length,
            actual: error
                .actual
                .parse()
                .map_err(|_| invalid("verification.actual", "invalid object identity"))?,
        },
    })
}

#[cfg(test)]
mod tests {
    use crate::snapshots::{verification_from_wire, verification_to_wire};
    use libvm::storage::identity::{ObjectDigest, StreamId};
    use libvm::storage::stream::Chunk;
    use libvm::{
        LibVmError, SnapshotStructuralFailure, SnapshotVerificationError,
        SnapshotVerificationMember, SnapshotVerificationReport, SnapshotVerificationRole,
    };
    use prost::Message;
    use silod_spec::daemon::v1 as w;

    fn digest() -> ObjectDigest {
        format!("sha256:{}", "a".repeat(64)).parse().unwrap()
    }

    fn stream() -> StreamId {
        format!("sha256:{}", "b".repeat(64)).parse().unwrap()
    }

    fn roundtrip(error: &SnapshotVerificationError) {
        let wire = verification_to_wire(Err(error));
        let encoded = wire.encode_to_vec();
        let wire = w::SnapshotVerificationResult::decode(encoded.as_slice()).unwrap();
        let result = verification_from_wire(wire).unwrap().unwrap_err();
        let LibVmError::SnapshotVerification(actual) = result else {
            panic!("expected a typed verification error");
        };
        assert_eq!(format!("{actual:?}"), format!("{error:?}"));
    }

    #[test]
    fn snapshot_verification_report_roundtrips() {
        for (streams, bytes) in [(0, 0), (14, 30_u64 << 30), (u64::MAX, u64::MAX)] {
            let report = SnapshotVerificationReport {
                snapshot: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
                streams,
                bytes,
            };
            let wire = verification_to_wire(Ok(&report));
            let encoded = wire.encode_to_vec();
            let wire = w::SnapshotVerificationResult::decode(encoded.as_slice()).unwrap();
            assert_eq!(verification_from_wire(wire).unwrap().unwrap(), report);
        }
    }

    #[test]
    fn snapshot_verification_errors_roundtrip_all_roles_and_members() {
        for role in [
            SnapshotVerificationRole::Ram,
            SnapshotVerificationRole::Layout,
            SnapshotVerificationRole::Execution,
            SnapshotVerificationRole::Devices,
            SnapshotVerificationRole::RootDisk,
            SnapshotVerificationRole::DataDisk { order: 0 },
            SnapshotVerificationRole::DataDisk { order: u32::MAX },
            SnapshotVerificationRole::Dependency,
        ] {
            for (expected, actual) in [
                (Chunk::Zero, Chunk::Data(digest())),
                (Chunk::Data(digest()), Chunk::Zero),
            ] {
                roundtrip(&SnapshotVerificationError::ChunkMismatch {
                    role: role.clone(),
                    stream: stream(),
                    index: 2,
                    start: 16_777_216,
                    end: 25_165_824,
                    expected: Box::new(expected),
                    actual: Box::new(actual),
                });
            }
            roundtrip(&SnapshotVerificationError::ObjectMismatch {
                role: role.clone(),
                object: digest(),
                length: 4096,
                actual: format!("sha256:{}", "d".repeat(64)).parse().unwrap(),
            });
            for member in [
                SnapshotVerificationMember::Stream(stream()),
                SnapshotVerificationMember::Object(digest()),
            ] {
                for failure in [
                    SnapshotStructuralFailure::Missing,
                    SnapshotStructuralFailure::Truncated {
                        expected: 4096,
                        actual: 512,
                    },
                    SnapshotStructuralFailure::Length {
                        expected: 4096,
                        actual: 8192,
                    },
                    SnapshotStructuralFailure::Writable { mode: 0o600 },
                    SnapshotStructuralFailure::Replaced,
                    SnapshotStructuralFailure::Invalid {
                        message: "not a regular file".into(),
                    },
                ] {
                    roundtrip(&SnapshotVerificationError::Structural {
                        role: role.clone(),
                        member,
                        failure,
                    });
                }
            }
        }
    }

    #[test]
    fn snapshot_verification_wire_rejects_missing_or_malformed_fields() {
        use w::snapshot_verification_result::Result as Wire;
        assert!(verification_from_wire(w::SnapshotVerificationResult { result: None }).is_err());
        assert!(verification_from_wire(w::SnapshotVerificationResult {
            result: Some(Wire::Report(w::SnapshotVerificationReport {
                snapshot: "not a snapshot identity".into(),
                streams: 0,
                bytes: 0,
            })),
        })
        .is_err());
        let error = SnapshotVerificationError::ChunkMismatch {
            role: SnapshotVerificationRole::Ram,
            stream: stream(),
            index: 0,
            start: 0,
            end: 512,
            expected: Box::new(Chunk::Zero),
            actual: Box::new(Chunk::Data(digest())),
        };
        let Some(Wire::Error(base)) = verification_to_wire(Err(&error)).result else {
            panic!("expected wire error");
        };
        for role in [0, i32::MAX] {
            let mut value = base.clone();
            value.role = role;
            assert!(verification_from_wire(w::SnapshotVerificationResult {
                result: Some(Wire::Error(value)),
            })
            .is_err());
        }
        let mut extra_order = base.clone();
        extra_order.disk_order = Some(1);
        let mut missing_order = base.clone();
        missing_order.role = w::SnapshotVerificationRole::DataDisk.into();
        let mut missing_error = base.clone();
        missing_error.error = None;
        for value in [extra_order, missing_order, missing_error] {
            assert!(verification_from_wire(w::SnapshotVerificationResult {
                result: Some(Wire::Error(value)),
            })
            .is_err());
        }
        let Some(w::snapshot_verification_error::Error::Chunk(chunk)) = base.error.clone() else {
            panic!("expected chunk error");
        };
        let mut missing_expected = chunk.clone();
        missing_expected.expected = None;
        let mut missing_actual = chunk.clone();
        missing_actual.actual = None;
        let mut invalid_stream = chunk.clone();
        invalid_stream.stream = "invalid".into();
        let mut empty_range = chunk.clone();
        empty_range.end = empty_range.start;
        let mut missing_identity = chunk.clone();
        missing_identity.actual = Some(w::VerificationChunk { identity: None });
        let mut invalid_identity = chunk;
        invalid_identity.actual = Some(w::VerificationChunk {
            identity: Some(w::verification_chunk::Identity::Data("invalid".into())),
        });
        for chunk in [
            missing_expected,
            missing_actual,
            invalid_stream,
            empty_range,
            missing_identity,
            invalid_identity,
        ] {
            let mut value = base.clone();
            value.error = Some(w::snapshot_verification_error::Error::Chunk(chunk));
            assert!(verification_from_wire(w::SnapshotVerificationResult {
                result: Some(Wire::Error(value)),
            })
            .is_err());
        }
    }
}

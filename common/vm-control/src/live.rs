//! Strict daemon-wire conversion. Reports are evidence, not admission witnesses.
use crate::{invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;
use vm_spec::live::*;

pub fn operation_to_wire(v: LiveOperation) -> i32 {
    match v {
        LiveOperation::Pause => 1,
        LiveOperation::Capture => 2,
        LiveOperation::Restore => 3,
        LiveOperation::Fork => 4,
        LiveOperation::Incremental => 5,
    }
}
pub fn operation_from_wire(v: i32) -> Result<LiveOperation, ConversionError> {
    match v {
        1 => Ok(LiveOperation::Pause),
        2 => Ok(LiveOperation::Capture),
        3 => Ok(LiveOperation::Restore),
        4 => Ok(LiveOperation::Fork),
        5 => Ok(LiveOperation::Incremental),
        _ => Err(invalid("live.operation", "unknown enum")),
    }
}
fn backend_to_wire(v: LiveBackend) -> i32 {
    match v {
        LiveBackend::Krun => 1,
        LiveBackend::Vz => 2,
        LiveBackend::Mock => 3,
    }
}
fn backend_from_wire(v: i32) -> Result<LiveBackend, ConversionError> {
    match v {
        1 => Ok(LiveBackend::Krun),
        2 => Ok(LiveBackend::Vz),
        3 => Ok(LiveBackend::Mock),
        _ => Err(invalid("live.backend", "unknown enum")),
    }
}
fn lane_to_wire(v: LiveLane) -> i32 {
    match v {
        LiveLane::KvmX86_64 => 1,
        LiveLane::KvmArm64GicV3 => 2,
        LiveLane::HvfArm64 => 3,
        LiveLane::NotApplicable => 4,
    }
}
fn lane_from_wire(v: i32) -> Result<LiveLane, ConversionError> {
    match v {
        1 => Ok(LiveLane::KvmX86_64),
        2 => Ok(LiveLane::KvmArm64GicV3),
        3 => Ok(LiveLane::HvfArm64),
        4 => Ok(LiveLane::NotApplicable),
        _ => Err(invalid("live.lane", "unknown enum")),
    }
}
fn scope_to_wire(v: LiveScope) -> i32 {
    match v {
        LiveScope::Host => 1,
        LiveScope::Machine => 2,
    }
}
fn scope_from_wire(v: i32) -> Result<LiveScope, ConversionError> {
    match v {
        1 => Ok(LiveScope::Host),
        2 => Ok(LiveScope::Machine),
        _ => Err(invalid("live.scope", "unknown enum")),
    }
}
fn reason_to_wire(v: &LiveUnsupportedReason) -> w::LiveUnsupportedReason {
    use w::live_device_subject::Subject;
    w::LiveUnsupportedReason {
        code: Some(match v.code {
            LiveReasonCode::BackendExcluded => 1,
            LiveReasonCode::HostOsBelowFloor => 2,
            LiveReasonCode::LaneNotQualified => 3,
            LiveReasonCode::HypervisorUnavailable => 4,
            LiveReasonCode::BuildExcluded => 5,
            LiveReasonCode::NotDelivered => 6,
            LiveReasonCode::DeviceProfileRejected => 7,
        }),
        subject: v.subject.as_ref().map(|v| w::LiveDeviceSubject {
            subject: Some(match v {
                LiveDeviceSubject::Virtiofs => Subject::Virtiofs(()),
                LiveDeviceSubject::Rosetta => Subject::Rosetta(()),
                LiveDeviceSubject::Tap => Subject::Tap(()),
                LiveDeviceSubject::Gpu => Subject::Gpu(()),
                LiveDeviceSubject::Nested => Subject::Nested(()),
                LiveDeviceSubject::Tee => Subject::Tee(()),
                LiveDeviceSubject::GuestProfile { profile } => {
                    Subject::GuestProfile(profile.clone())
                }
            }),
        }),
    }
}
fn reason_from_wire(v: w::LiveUnsupportedReason) -> Result<LiveUnsupportedReason, ConversionError> {
    use w::live_device_subject::Subject;
    let value = LiveUnsupportedReason {
        code: match required(v.code, "live.reason.code")? {
            1 => LiveReasonCode::BackendExcluded,
            2 => LiveReasonCode::HostOsBelowFloor,
            3 => LiveReasonCode::LaneNotQualified,
            4 => LiveReasonCode::HypervisorUnavailable,
            5 => LiveReasonCode::BuildExcluded,
            6 => LiveReasonCode::NotDelivered,
            7 => LiveReasonCode::DeviceProfileRejected,
            _ => return Err(invalid("live.reason.code", "unknown enum")),
        },
        subject: v
            .subject
            .map(|v| {
                Ok::<_, ConversionError>(match required(v.subject, "live.reason.subject")? {
                    Subject::Virtiofs(()) => LiveDeviceSubject::Virtiofs,
                    Subject::Rosetta(()) => LiveDeviceSubject::Rosetta,
                    Subject::Tap(()) => LiveDeviceSubject::Tap,
                    Subject::Gpu(()) => LiveDeviceSubject::Gpu,
                    Subject::Nested(()) => LiveDeviceSubject::Nested,
                    Subject::Tee(()) => LiveDeviceSubject::Tee,
                    Subject::GuestProfile(profile) => LiveDeviceSubject::GuestProfile { profile },
                })
            })
            .transpose()?,
    };
    value
        .validate()
        .map_err(|_| invalid("live.reason", "invalid capability evidence"))?;
    Ok(value)
}
fn capability_to_wire(v: &LiveCapability) -> w::LiveCapability {
    w::LiveCapability {
        native: Some(v.native),
        availability: Some(match &v.availability {
            LiveAvailability::Supported => w::live_capability::Availability::Supported(()),
            LiveAvailability::Unsupported { reason } => {
                w::live_capability::Availability::Unsupported(reason_to_wire(reason))
            }
        }),
    }
}
fn capability_from_wire(v: w::LiveCapability) -> Result<LiveCapability, ConversionError> {
    let value = LiveCapability {
        native: required(v.native, "live.native")?,
        availability: match required(v.availability, "live.availability")? {
            w::live_capability::Availability::Supported(()) => LiveAvailability::Supported,
            w::live_capability::Availability::Unsupported(reason) => {
                LiveAvailability::Unsupported {
                    reason: reason_from_wire(reason)?,
                }
            }
        },
    };
    value
        .validate()
        .map_err(|_| invalid("live.capability", "invalid native/availability combination"))?;
    Ok(value)
}
fn vector_to_wire(v: &LiveCapabilityVector) -> w::LiveCapabilityVector {
    w::LiveCapabilityVector {
        pause: Some(capability_to_wire(&v.pause)),
        capture: Some(capability_to_wire(&v.capture)),
        restore: Some(capability_to_wire(&v.restore)),
        fork: Some(capability_to_wire(&v.fork)),
        incremental: Some(capability_to_wire(&v.incremental)),
    }
}
fn vector_from_wire(v: w::LiveCapabilityVector) -> Result<LiveCapabilityVector, ConversionError> {
    Ok(LiveCapabilityVector {
        pause: capability_from_wire(required(v.pause, "live.pause")?)?,
        capture: capability_from_wire(required(v.capture, "live.capture")?)?,
        restore: capability_from_wire(required(v.restore, "live.restore")?)?,
        fork: capability_from_wire(required(v.fork, "live.fork")?)?,
        incremental: capability_from_wire(required(v.incremental, "live.incremental")?)?,
    })
}
pub fn host_to_wire(v: &LiveHostReport) -> Result<w::LiveHostReport, ConversionError> {
    v.validate()
        .map_err(|_| invalid("live.host", "invalid capability evidence"))?;
    Ok(w::LiveHostReport {
        schema_version: Some(v.schema_version),
        scope: Some(scope_to_wire(v.scope)),
        backend: Some(backend_to_wire(v.backend)),
        lane: Some(lane_to_wire(v.lane)),
        live: Some(vector_to_wire(&v.live)),
        build_identity: Some(v.build_identity.clone()),
        qualification_identity: Some(v.qualification_identity.clone()),
        scenario_digest: v.scenario_digest.clone(),
    })
}
pub fn host_from_wire(v: w::LiveHostReport) -> Result<LiveHostReport, ConversionError> {
    let value = LiveHostReport {
        schema_version: required(v.schema_version, "live.schema_version")?,
        scope: scope_from_wire(required(v.scope, "live.scope")?)?,
        backend: backend_from_wire(required(v.backend, "live.backend")?)?,
        lane: lane_from_wire(required(v.lane, "live.lane")?)?,
        live: vector_from_wire(required(v.live, "live.vector")?)?,
        build_identity: required(v.build_identity, "live.build_identity")?,
        qualification_identity: required(v.qualification_identity, "live.qualification_identity")?,
        scenario_digest: v.scenario_digest,
    };
    value
        .validate()
        .map_err(|_| invalid("live.host", "invalid capability evidence"))?;
    Ok(value)
}
pub fn machine_to_wire(v: &LiveMachineReport) -> Result<w::LiveMachineReport, ConversionError> {
    v.validate()
        .map_err(|_| invalid("live.machine", "invalid capability evidence"))?;
    Ok(w::LiveMachineReport {
        schema_version: Some(v.schema_version),
        scope: Some(scope_to_wire(v.scope)),
        machine_id: Some(v.machine_id.clone()),
        run_id: Some(v.run_id.clone()),
        monitor_id: Some(v.monitor_id.clone()),
        backend: Some(backend_to_wire(v.backend)),
        lane: Some(lane_to_wire(v.lane)),
        topology_revision: Some(v.topology_revision),
        live: Some(vector_to_wire(&v.live)),
    })
}
pub fn machine_from_wire(v: w::LiveMachineReport) -> Result<LiveMachineReport, ConversionError> {
    let value = LiveMachineReport {
        schema_version: required(v.schema_version, "live.schema_version")?,
        scope: scope_from_wire(required(v.scope, "live.scope")?)?,
        machine_id: required(v.machine_id, "live.machine_id")?,
        run_id: required(v.run_id, "live.run_id")?,
        monitor_id: required(v.monitor_id, "live.monitor_id")?,
        backend: backend_from_wire(required(v.backend, "live.backend")?)?,
        lane: lane_from_wire(required(v.lane, "live.lane")?)?,
        topology_revision: required(v.topology_revision, "live.topology_revision")?,
        live: vector_from_wire(required(v.live, "live.vector")?)?,
    };
    value
        .validate()
        .map_err(|_| invalid("live.machine", "invalid capability evidence"))?;
    Ok(value)
}
pub fn unsupported_to_wire(
    v: &LiveOperationUnsupported,
) -> Result<w::LiveOperationUnsupported, ConversionError> {
    v.validate()
        .map_err(|_| invalid("live.unsupported", "invalid capability evidence"))?;
    Ok(w::LiveOperationUnsupported {
        operation: Some(operation_to_wire(v.operation)),
        backend: Some(backend_to_wire(v.backend)),
        lane: Some(lane_to_wire(v.lane)),
        reason: Some(reason_to_wire(&v.reason)),
    })
}
pub fn unsupported_from_wire(
    v: w::LiveOperationUnsupported,
) -> Result<LiveOperationUnsupported, ConversionError> {
    let value = LiveOperationUnsupported {
        operation: operation_from_wire(required(v.operation, "live.operation")?)?,
        backend: backend_from_wire(required(v.backend, "live.backend")?)?,
        lane: lane_from_wire(required(v.lane, "live.lane")?)?,
        reason: reason_from_wire(required(v.reason, "live.reason")?)?,
    };
    value
        .validate()
        .map_err(|_| invalid("live.unsupported", "invalid capability evidence"))?;
    Ok(value)
}

/// Compare durable machine IDs with report IDs by UUID value. Live reports
/// retain their own strict canonical-format validation.
pub fn same_machine_identity(left: &str, right: &str) -> bool {
    match (uuid::Uuid::parse_str(left), uuid::Uuid::parse_str(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub fn validate_daemon_status(value: &w::DaemonStatus) -> Result<(), ConversionError> {
    if value.live_schema_version != Some(1) {
        return Err(invalid(
            "daemon.live_schema_version",
            "missing or unsupported live status contract",
        ));
    }
    for report in [&value.manager_live, &value.appliance_live]
        .into_iter()
        .flatten()
    {
        host_from_wire(report.clone())?;
    }
    if let Some(system) = &value.system {
        if system.live_schema_version != Some(1) {
            return Err(invalid(
                "system.live_schema_version",
                "missing or unsupported live status contract",
            ));
        }
        if let Some(report) = &system.prospective_live {
            host_from_wire(report.clone())?;
        }
        if let Some(report) = &system.live {
            let report = machine_from_wire(report.clone())?;
            if !system
                .machine_id
                .as_deref()
                .is_some_and(|machine_id| same_machine_identity(machine_id, &report.machine_id))
                || system.run_id.as_deref() != Some(report.run_id.as_str())
            {
                return Err(invalid("system.live", "machine/run identity mismatch"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::live::{
        capability_from_wire, host_from_wire, host_to_wire, unsupported_from_wire,
        unsupported_to_wire, validate_daemon_status,
    };
    use silod_spec::daemon::v1 as w;
    use vm_spec::live::*;
    fn host() -> LiveHostReport {
        LiveHostReport {
            schema_version: 1,
            scope: LiveScope::Host,
            backend: LiveBackend::Vz,
            lane: LiveLane::NotApplicable,
            live: LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded),
            build_identity: "test-build".into(),
            qualification_identity: "test-unqualified".into(),
            scenario_digest: None,
        }
    }
    #[test]
    fn host_roundtrip_preserves_all_five_operations() {
        let report = host();
        assert_eq!(
            host_from_wire(host_to_wire(&report).unwrap()).unwrap(),
            report
        );
    }
    #[test]
    fn mandatory_and_unknown_wire_fields_fail_closed() {
        let valid = host_to_wire(&host()).unwrap();
        let mut wire = valid.clone();
        wire.backend = Some(99);
        assert!(host_from_wire(wire).is_err());
        let mut wire = valid.clone();
        wire.live.as_mut().unwrap().incremental = None;
        assert!(host_from_wire(wire).is_err());
        let mut wire = valid.clone();
        wire.live.as_mut().unwrap().pause.as_mut().unwrap().native = None;
        assert!(host_from_wire(wire).is_err());
        let mut wire = valid;
        wire.scope = Some(2);
        assert!(host_from_wire(wire).is_err());
    }
    #[test]
    fn typed_device_subject_is_required_and_bounded() {
        let value = LiveOperationUnsupported {
            operation: LiveOperation::Capture,
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
        };
        assert_eq!(
            unsupported_from_wire(unsupported_to_wire(&value).unwrap()).unwrap(),
            value
        );
        let mut wire = unsupported_to_wire(&value).unwrap();
        wire.reason.as_mut().unwrap().subject = None;
        assert!(unsupported_from_wire(wire).is_err());
        let mut missing_subject = value.clone();
        missing_subject.reason.subject = None;
        assert!(unsupported_to_wire(&missing_subject).is_err());
        let mut unexpected_subject = value.clone();
        unexpected_subject.reason.code = LiveReasonCode::NotDelivered;
        assert!(unsupported_to_wire(&unexpected_subject).is_err());
        let mut invalid_backend = value.clone();
        invalid_backend.backend = LiveBackend::Vz;
        assert!(unsupported_to_wire(&invalid_backend).is_err());
        let mut invalid_profile = value;
        invalid_profile.reason = LiveUnsupportedReason::device(LiveDeviceSubject::GuestProfile {
            profile: "invalid\nprofile".into(),
        });
        assert!(unsupported_to_wire(&invalid_profile).is_err());
    }

    #[test]
    fn status_requires_new_contract_even_when_discovery_is_unavailable() {
        let mut status = w::DaemonStatus::default();
        assert!(validate_daemon_status(&status).is_err());
        status.live_schema_version = Some(1);
        assert!(validate_daemon_status(&status).is_ok());
        status.manager_live = Some(host_to_wire(&host()).unwrap());
        assert!(validate_daemon_status(&status).is_ok());
        status.system = Some(w::SystemStatus::default());
        assert!(validate_daemon_status(&status).is_err());
        status.system.as_mut().unwrap().live_schema_version = Some(1);
        assert!(validate_daemon_status(&status).is_ok());
        status
            .manager_live
            .as_mut()
            .unwrap()
            .live
            .as_mut()
            .unwrap()
            .restore = None;
        assert!(validate_daemon_status(&status).is_err());
    }

    #[test]
    fn supported_without_native_and_host_device_rejection_are_invalid() {
        let capability = w::LiveCapability {
            native: Some(false),
            availability: Some(w::live_capability::Availability::Supported(())),
        };
        assert!(capability_from_wire(capability).is_err());
        let mut host = host();
        host.backend = LiveBackend::Mock;
        host.live.pause.availability = LiveAvailability::Unsupported {
            reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
        };
        assert!(host_to_wire(&host).is_err());
    }

    #[test]
    fn appliance_wire_status_matches_uuid_value_without_relaxing_report_format() {
        let report = LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "12345678-1234-4234-8234-123456789abc".into(),
            run_id: "22345678-1234-4234-8234-123456789abc".into(),
            monitor_id: "32345678-1234-4234-8234-123456789abc".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded),
        };
        let mut status = w::DaemonStatus {
            live_schema_version: Some(1),
            system: Some(w::SystemStatus {
                live_schema_version: Some(1),
                machine_id: Some("12345678123442348234123456789abc".into()),
                run_id: Some(report.run_id.clone()),
                live: Some(crate::live::machine_to_wire(&report).unwrap()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_daemon_status(&status).is_ok());
        status.system.as_mut().unwrap().machine_id =
            Some("42345678123442348234123456789abc".into());
        assert!(validate_daemon_status(&status).is_err());
        status.system.as_mut().unwrap().machine_id =
            Some("12345678123442348234123456789abc".into());
        status
            .system
            .as_mut()
            .unwrap()
            .live
            .as_mut()
            .unwrap()
            .machine_id = Some("12345678123442348234123456789abc".into());
        assert!(validate_daemon_status(&status).is_err());
    }
}

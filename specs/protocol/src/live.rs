//! Strict monitor capability conversions. Missing/unknown data is a protocol error.
use crate::v1 as wire;
use vm_spec::live as domain;

fn required<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing live field {field}"))
}

trait WireNumber {
    fn wire_number(self) -> i32;
}

macro_rules! enum_conversion {
    ($name:ident { $($variant:ident = $number:literal),+ $(,)? }) => {
        impl WireNumber for domain::$name {
            fn wire_number(self) -> i32 {
                match self { $(Self::$variant => $number),+ }
            }
        }
        impl TryFrom<wire::$name> for domain::$name {
            type Error = String;
            fn try_from(value: wire::$name) -> Result<Self, Self::Error> {
                match value as i32 { $($number => Ok(Self::$variant)),+, _ => Err(concat!("unknown/unspecified ", stringify!($name)).into()) }
            }
        }
    };
}

enum_conversion!(LiveOperation { Pause = 1, Capture = 2, Restore = 3, Fork = 4, Incremental = 5 });
enum_conversion!(LiveBackend { Krun = 1, Vz = 2, Mock = 3 });
enum_conversion!(LiveLane { KvmX86_64 = 1, KvmArm64GicV3 = 2, HvfArm64 = 3, NotApplicable = 4 });
enum_conversion!(LiveScope { Host = 1, Machine = 2 });
enum_conversion!(LiveReasonCode { BackendExcluded = 1, HostOsBelowFloor = 2, LaneNotQualified = 3, HypervisorUnavailable = 4, BuildExcluded = 5, NotDelivered = 6, DeviceProfileRejected = 7 });

macro_rules! read_enum {
    ($value:expr, $name:ident, $field:literal) => {
        domain::$name::try_from(
            wire::$name::try_from(required($value, $field)?)
                .map_err(|_| concat!("unknown ", $field).to_owned())?,
        )?
    };
}

fn encode_subject(value: domain::LiveDeviceSubject) -> wire::LiveDeviceSubject {
    use wire::live_device_subject::Subject;
    let subject = match value {
        domain::LiveDeviceSubject::Virtiofs => Subject::Virtiofs(()),
        domain::LiveDeviceSubject::Rosetta => Subject::Rosetta(()),
        domain::LiveDeviceSubject::Tap => Subject::Tap(()),
        domain::LiveDeviceSubject::Gpu => Subject::Gpu(()),
        domain::LiveDeviceSubject::Nested => Subject::Nested(()),
        domain::LiveDeviceSubject::Tee => Subject::Tee(()),
        domain::LiveDeviceSubject::GuestProfile { profile } => Subject::GuestProfile(profile),
    };
    wire::LiveDeviceSubject {
        subject: Some(subject),
    }
}
impl TryFrom<domain::LiveDeviceSubject> for wire::LiveDeviceSubject {
    type Error = String;
    fn try_from(value: domain::LiveDeviceSubject) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(encode_subject(value))
    }
}
impl TryFrom<wire::LiveDeviceSubject> for domain::LiveDeviceSubject {
    type Error = String;
    fn try_from(value: wire::LiveDeviceSubject) -> Result<Self, Self::Error> {
        use wire::live_device_subject::Subject;
        let subject = match required(value.subject, "subject")? {
            Subject::Virtiofs(()) => Self::Virtiofs,
            Subject::Rosetta(()) => Self::Rosetta,
            Subject::Tap(()) => Self::Tap,
            Subject::Gpu(()) => Self::Gpu,
            Subject::Nested(()) => Self::Nested,
            Subject::Tee(()) => Self::Tee,
            Subject::GuestProfile(profile) => Self::GuestProfile { profile },
        };
        subject.validate()?;
        Ok(subject)
    }
}
fn encode_reason(value: domain::LiveUnsupportedReason) -> wire::LiveUnsupportedReason {
    wire::LiveUnsupportedReason {
        code: Some(value.code.wire_number()),
        subject: value.subject.map(encode_subject),
    }
}
impl TryFrom<domain::LiveUnsupportedReason> for wire::LiveUnsupportedReason {
    type Error = String;
    fn try_from(value: domain::LiveUnsupportedReason) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(encode_reason(value))
    }
}
impl TryFrom<wire::LiveUnsupportedReason> for domain::LiveUnsupportedReason {
    type Error = String;
    fn try_from(value: wire::LiveUnsupportedReason) -> Result<Self, Self::Error> {
        let reason = Self {
            code: read_enum!(value.code, LiveReasonCode, "reason.code"),
            subject: value.subject.map(TryInto::try_into).transpose()?,
        };
        reason.validate()?;
        Ok(reason)
    }
}
fn encode_capability(value: domain::LiveCapability) -> wire::LiveCapability {
    wire::LiveCapability {
        native: Some(value.native),
        availability: Some(match value.availability {
            domain::LiveAvailability::Supported => {
                wire::live_capability::Availability::Supported(())
            }
            domain::LiveAvailability::Unsupported { reason } => {
                wire::live_capability::Availability::Unsupported(encode_reason(reason))
            }
        }),
    }
}
impl TryFrom<domain::LiveCapability> for wire::LiveCapability {
    type Error = String;
    fn try_from(value: domain::LiveCapability) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(encode_capability(value))
    }
}
impl TryFrom<wire::LiveCapability> for domain::LiveCapability {
    type Error = String;
    fn try_from(value: wire::LiveCapability) -> Result<Self, Self::Error> {
        let capability = Self {
            native: required(value.native, "native")?,
            availability: match required(value.availability, "availability")? {
                wire::live_capability::Availability::Supported(()) => {
                    domain::LiveAvailability::Supported
                }
                wire::live_capability::Availability::Unsupported(reason) => {
                    domain::LiveAvailability::Unsupported {
                        reason: reason.try_into()?,
                    }
                }
            },
        };
        capability.validate()?;
        Ok(capability)
    }
}
fn encode_vector(value: domain::LiveCapabilityVector) -> wire::LiveCapabilityVector {
    wire::LiveCapabilityVector {
        pause: Some(encode_capability(value.pause)),
        capture: Some(encode_capability(value.capture)),
        restore: Some(encode_capability(value.restore)),
        fork: Some(encode_capability(value.fork)),
        incremental: Some(encode_capability(value.incremental)),
    }
}
impl TryFrom<domain::LiveCapabilityVector> for wire::LiveCapabilityVector {
    type Error = String;
    fn try_from(value: domain::LiveCapabilityVector) -> Result<Self, Self::Error> {
        value.validate(domain::LiveScope::Machine)?;
        Ok(encode_vector(value))
    }
}
impl TryFrom<wire::LiveCapabilityVector> for domain::LiveCapabilityVector {
    type Error = String;
    fn try_from(value: wire::LiveCapabilityVector) -> Result<Self, Self::Error> {
        Ok(Self {
            pause: required(value.pause, "pause")?.try_into()?,
            capture: required(value.capture, "capture")?.try_into()?,
            restore: required(value.restore, "restore")?.try_into()?,
            fork: required(value.fork, "fork")?.try_into()?,
            incremental: required(value.incremental, "incremental")?.try_into()?,
        })
    }
}
impl TryFrom<domain::LiveHostReport> for wire::LiveHostReport {
    type Error = String;
    fn try_from(value: domain::LiveHostReport) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            schema_version: Some(value.schema_version),
            scope: Some(value.scope.wire_number()),
            backend: Some(value.backend.wire_number()),
            lane: Some(value.lane.wire_number()),
            live: Some(encode_vector(value.live)),
            build_identity: Some(value.build_identity),
            qualification_identity: Some(value.qualification_identity),
            scenario_digest: value.scenario_digest,
        })
    }
}
impl TryFrom<wire::LiveHostReport> for domain::LiveHostReport {
    type Error = String;
    fn try_from(value: wire::LiveHostReport) -> Result<Self, Self::Error> {
        let report = Self {
            schema_version: required(value.schema_version, "schemaVersion")?,
            scope: read_enum!(value.scope, LiveScope, "scope"),
            backend: read_enum!(value.backend, LiveBackend, "backend"),
            lane: read_enum!(value.lane, LiveLane, "lane"),
            live: required(value.live, "live")?.try_into()?,
            build_identity: required(value.build_identity, "buildIdentity")?,
            qualification_identity: required(
                value.qualification_identity,
                "qualificationIdentity",
            )?,
            scenario_digest: value.scenario_digest,
        };
        report.validate()?;
        Ok(report)
    }
}
impl TryFrom<domain::LiveMachineReport> for wire::LiveMachineReport {
    type Error = String;
    fn try_from(value: domain::LiveMachineReport) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            schema_version: Some(value.schema_version),
            scope: Some(value.scope.wire_number()),
            machine_id: Some(value.machine_id),
            run_id: Some(value.run_id),
            monitor_id: Some(value.monitor_id),
            backend: Some(value.backend.wire_number()),
            lane: Some(value.lane.wire_number()),
            topology_revision: Some(value.topology_revision),
            live: Some(encode_vector(value.live)),
        })
    }
}
impl TryFrom<wire::LiveMachineReport> for domain::LiveMachineReport {
    type Error = String;
    fn try_from(value: wire::LiveMachineReport) -> Result<Self, Self::Error> {
        let report = Self {
            schema_version: required(value.schema_version, "schemaVersion")?,
            scope: read_enum!(value.scope, LiveScope, "scope"),
            machine_id: required(value.machine_id, "machineId")?,
            run_id: required(value.run_id, "runId")?,
            monitor_id: required(value.monitor_id, "monitorId")?,
            backend: read_enum!(value.backend, LiveBackend, "backend"),
            lane: read_enum!(value.lane, LiveLane, "lane"),
            topology_revision: required(value.topology_revision, "topologyRevision")?,
            live: required(value.live, "live")?.try_into()?,
        };
        report.validate()?;
        Ok(report)
    }
}
impl TryFrom<domain::LiveOperationUnsupported> for wire::LiveOperationUnsupported {
    type Error = String;
    fn try_from(value: domain::LiveOperationUnsupported) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            operation: Some(value.operation.wire_number()),
            backend: Some(value.backend.wire_number()),
            lane: Some(value.lane.wire_number()),
            reason: Some(encode_reason(value.reason)),
        })
    }
}
impl TryFrom<wire::LiveOperationUnsupported> for domain::LiveOperationUnsupported {
    type Error = String;
    fn try_from(value: wire::LiveOperationUnsupported) -> Result<Self, Self::Error> {
        let refusal = Self {
            operation: read_enum!(value.operation, LiveOperation, "operation"),
            backend: read_enum!(value.backend, LiveBackend, "backend"),
            lane: read_enum!(value.lane, LiveLane, "lane"),
            reason: required(value.reason, "reason")?.try_into()?,
        };
        refusal.validate()?;
        Ok(refusal)
    }
}

#[cfg(test)]
mod tests {
    use crate::v1 as wire;
    use vm_spec::live as domain;

    fn host() -> domain::LiveHostReport {
        domain::LiveHostReport {
            schema_version: 1,
            scope: domain::LiveScope::Host,
            backend: domain::LiveBackend::Krun,
            lane: domain::LiveLane::KvmX86_64,
            live: domain::LiveCapabilityVector::all_unsupported(
                domain::LiveReasonCode::NotDelivered,
            ),
            build_identity: "revision".into(),
            qualification_identity: "empty".into(),
            scenario_digest: None,
        }
    }
    #[test]
    fn live_capabilities_wire_is_strict() {
        let report = host();
        let wire: wire::LiveHostReport = report.clone().try_into().unwrap();
        assert_eq!(
            domain::LiveHostReport::try_from(wire.clone()).unwrap(),
            report
        );
        let mut invalid = wire.clone();
        invalid.backend = Some(999);
        assert!(domain::LiveHostReport::try_from(invalid).is_err());
        let mut invalid = wire.clone();
        invalid.lane = Some(0);
        assert!(domain::LiveHostReport::try_from(invalid).is_err());
        let mut invalid = wire.clone();
        invalid.live.as_mut().unwrap().incremental = None;
        assert!(domain::LiveHostReport::try_from(invalid).is_err());
        let mut invalid = wire;
        invalid
            .live
            .as_mut()
            .unwrap()
            .pause
            .as_mut()
            .unwrap()
            .native = None;
        assert!(domain::LiveHostReport::try_from(invalid).is_err());
        assert!(domain::LiveCapability::try_from(wire::LiveCapability {
            native: Some(false),
            availability: Some(wire::live_capability::Availability::Supported(())),
        })
        .is_err());
    }
    #[test]
    fn live_capabilities_refusal_roundtrip() {
        let reasons = [
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::BackendExcluded),
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::HostOsBelowFloor),
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::LaneNotQualified),
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::HypervisorUnavailable),
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::BuildExcluded),
            domain::LiveUnsupportedReason::new(domain::LiveReasonCode::NotDelivered),
            domain::LiveUnsupportedReason::device(domain::LiveDeviceSubject::GuestProfile {
                profile: "linux-test".into(),
            }),
        ];
        for operation in domain::LiveOperation::ALL {
            for reason in &reasons {
                let refusal = domain::LiveOperationUnsupported {
                    operation,
                    backend: domain::LiveBackend::Mock,
                    lane: domain::LiveLane::NotApplicable,
                    reason: reason.clone(),
                };
                let encoded: wire::LiveOperationUnsupported = refusal.clone().try_into().unwrap();
                assert_eq!(
                    domain::LiveOperationUnsupported::try_from(encoded).unwrap(),
                    refusal
                );
            }
        }
        assert!(domain::LiveOperationUnsupported::try_from(
            wire::LiveOperationUnsupported::default()
        )
        .is_err());
    }

    #[test]
    fn live_capabilities_outbound_conversion_rejects_mutation() {
        let mut report = host();
        report.live.pause.availability = domain::LiveAvailability::Supported;
        assert!(wire::LiveCapability::try_from(report.live.pause.clone()).is_err());
        assert!(wire::LiveHostReport::try_from(report).is_err());
        let mut report = host();
        report.backend = domain::LiveBackend::Vz;
        report.lane = domain::LiveLane::NotApplicable;
        assert!(wire::LiveHostReport::try_from(report.clone()).is_err());
        report.live =
            domain::LiveCapabilityVector::all_unsupported(domain::LiveReasonCode::BackendExcluded);
        assert!(wire::LiveHostReport::try_from(report.clone()).is_ok());
        report.lane = domain::LiveLane::KvmX86_64;
        assert!(wire::LiveHostReport::try_from(report).is_err());

        let mut machine = domain::LiveMachineReport {
            schema_version: 1,
            scope: domain::LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: domain::LiveBackend::Mock,
            lane: domain::LiveLane::NotApplicable,
            topology_revision: 1,
            live: host().live,
        };
        assert!(wire::LiveMachineReport::try_from(machine.clone()).is_ok());
        machine.topology_revision = 0;
        assert!(wire::LiveMachineReport::try_from(machine.clone()).is_err());
        machine.topology_revision = 1;
        let reason =
            domain::LiveUnsupportedReason::device(domain::LiveDeviceSubject::GuestProfile {
                profile: "invalid profile".into(),
            });
        machine.live.capture.availability = domain::LiveAvailability::Unsupported {
            reason: reason.clone(),
        };
        assert!(wire::LiveMachineReport::try_from(machine).is_err());
        let refusal = domain::LiveOperationUnsupported {
            operation: domain::LiveOperation::Capture,
            backend: domain::LiveBackend::Mock,
            lane: domain::LiveLane::NotApplicable,
            reason,
        };
        assert!(wire::LiveOperationUnsupported::try_from(refusal).is_err());

        let positive = domain::LiveCapability {
            native: true,
            availability: domain::LiveAvailability::Supported,
        };
        let mut report = host();
        report.backend = domain::LiveBackend::Mock;
        report.live = domain::LiveCapabilityVector {
            pause: positive.clone(),
            capture: positive.clone(),
            restore: positive.clone(),
            fork: positive.clone(),
            incremental: positive,
        };
        assert!(wire::LiveHostReport::try_from(report).is_ok());
    }
}

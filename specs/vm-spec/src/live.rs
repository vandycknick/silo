//! Shared live-operation evidence. Reports describe scope, never authorize execution.
use std::fmt;

use serde::ser::{Error as _, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const LIVE_SCHEMA_VERSION: u32 = 1;

macro_rules! named_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name { $(#[serde(rename = $text)] $variant),+ }
        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
        }
    };
}

named_enum!(LiveOperation { Pause => "pause", Capture => "capture", Restore => "restore", Fork => "fork", Incremental => "incremental" });
named_enum!(LiveBackend { Krun => "krun", Vz => "vz", Mock => "mock" });
named_enum!(LiveLane { KvmX86_64 => "kvm-x86_64", KvmArm64GicV3 => "kvm-arm64-gicv3", HvfArm64 => "hvf-arm64", NotApplicable => "not-applicable" });
named_enum!(LiveScope { Host => "host", Machine => "machine" });
named_enum!(LiveReasonCode {
    BackendExcluded => "backend-excluded",
    HostOsBelowFloor => "host-os-below-floor",
    HypervisorUnavailable => "hypervisor-unavailable",
    BuildExcluded => "build-excluded",
    NotDelivered => "not-delivered",
    DeviceProfileRejected => "device-profile-rejected"
});

impl LiveOperation {
    pub const ALL: [Self; 5] = [
        Self::Pause,
        Self::Capture,
        Self::Restore,
        Self::Fork,
        Self::Incremental,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    deny_unknown_fields,
    try_from = "RawDeviceSubject"
)]
pub enum LiveDeviceSubject {
    Virtiofs,
    Rosetta,
    Tap,
    Gpu,
    Nested,
    Tee,
    GuestProfile { profile: String },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawDeviceSubject {
    Virtiofs {},
    Rosetta {},
    Tap {},
    Gpu {},
    Nested {},
    Tee {},
    GuestProfile { profile: String },
}

impl TryFrom<RawDeviceSubject> for LiveDeviceSubject {
    type Error = String;
    fn try_from(raw: RawDeviceSubject) -> Result<Self, Self::Error> {
        let subject = match raw {
            RawDeviceSubject::Virtiofs {} => Self::Virtiofs,
            RawDeviceSubject::Rosetta {} => Self::Rosetta,
            RawDeviceSubject::Tap {} => Self::Tap,
            RawDeviceSubject::Gpu {} => Self::Gpu,
            RawDeviceSubject::Nested {} => Self::Nested,
            RawDeviceSubject::Tee {} => Self::Tee,
            RawDeviceSubject::GuestProfile { profile } => Self::GuestProfile { profile },
        };
        subject.validate()?;
        Ok(subject)
    }
}

impl LiveDeviceSubject {
    pub fn validate(&self) -> Result<(), String> {
        if let Self::GuestProfile { profile } = self {
            if profile.is_empty()
                || profile.len() > 128
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err("guest profile must be an ASCII identifier of 1..128 bytes".into());
            }
        }
        Ok(())
    }
}

impl fmt::Display for LiveDeviceSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Virtiofs => f.write_str("virtiofs"),
            Self::Rosetta => f.write_str("rosetta"),
            Self::Tap => f.write_str("tap"),
            Self::Gpu => f.write_str("gpu"),
            Self::Nested => f.write_str("nested"),
            Self::Tee => f.write_str("tee"),
            Self::GuestProfile { profile } => write!(f, "guest-profile:{profile}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RawUnsupportedReason"
)]
pub struct LiveUnsupportedReason {
    pub code: LiveReasonCode,
    pub subject: Option<LiveDeviceSubject>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawUnsupportedReason {
    code: LiveReasonCode,
    subject: Option<LiveDeviceSubject>,
}

impl TryFrom<RawUnsupportedReason> for LiveUnsupportedReason {
    type Error = String;
    fn try_from(raw: RawUnsupportedReason) -> Result<Self, Self::Error> {
        let value = Self {
            code: raw.code,
            subject: raw.subject,
        };
        value.validate()?;
        Ok(value)
    }
}

impl LiveUnsupportedReason {
    pub fn new(code: LiveReasonCode) -> Self {
        Self {
            code,
            subject: None,
        }
    }
    pub fn device(subject: LiveDeviceSubject) -> Self {
        Self {
            code: LiveReasonCode::DeviceProfileRejected,
            subject: Some(subject),
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        match (self.code, &self.subject) {
            (LiveReasonCode::DeviceProfileRejected, Some(subject)) => subject.validate(),
            (LiveReasonCode::DeviceProfileRejected, None) => {
                Err("device-profile-rejected requires a subject".into())
            }
            (_, Some(_)) => Err("only device-profile-rejected may name a subject".into()),
            (_, None) => Ok(()),
        }
    }
}

impl fmt::Display for LiveUnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(subject) = &self.subject {
            write!(f, " (subject={subject})")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    deny_unknown_fields,
    from = "RawAvailability"
)]
pub enum LiveAvailability {
    Supported,
    Unsupported { reason: LiveUnsupportedReason },
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum RawAvailability {
    Supported {},
    Unsupported { reason: LiveUnsupportedReason },
}

impl From<RawAvailability> for LiveAvailability {
    fn from(raw: RawAvailability) -> Self {
        match raw {
            RawAvailability::Supported {} => Self::Supported,
            RawAvailability::Unsupported { reason } => Self::Unsupported { reason },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RawCapability"
)]
pub struct LiveCapability {
    pub native: bool,
    pub availability: LiveAvailability,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCapability {
    native: bool,
    availability: LiveAvailability,
}

impl TryFrom<RawCapability> for LiveCapability {
    type Error = String;
    fn try_from(raw: RawCapability) -> Result<Self, Self::Error> {
        let capability = Self {
            native: raw.native,
            availability: raw.availability,
        };
        capability.validate()?;
        Ok(capability)
    }
}

impl LiveCapability {
    pub fn unsupported(code: LiveReasonCode) -> Self {
        Self {
            native: false,
            availability: LiveAvailability::Unsupported {
                reason: LiveUnsupportedReason::new(code),
            },
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        match &self.availability {
            LiveAvailability::Supported if !self.native => {
                Err("supported availability requires the native primitive".into())
            }
            LiveAvailability::Unsupported { reason } => reason.validate(),
            LiveAvailability::Supported => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveCapabilityVector {
    pub pause: LiveCapability,
    pub capture: LiveCapability,
    pub restore: LiveCapability,
    pub fork: LiveCapability,
    pub incremental: LiveCapability,
}

impl LiveCapabilityVector {
    pub fn all_unsupported(code: LiveReasonCode) -> Self {
        Self {
            pause: LiveCapability::unsupported(code),
            capture: LiveCapability::unsupported(code),
            restore: LiveCapability::unsupported(code),
            fork: LiveCapability::unsupported(code),
            incremental: LiveCapability::unsupported(code),
        }
    }
    pub fn get(&self, operation: LiveOperation) -> &LiveCapability {
        match operation {
            LiveOperation::Pause => &self.pause,
            LiveOperation::Capture => &self.capture,
            LiveOperation::Restore => &self.restore,
            LiveOperation::Fork => &self.fork,
            LiveOperation::Incremental => &self.incremental,
        }
    }
    pub fn validate(&self, scope: LiveScope) -> Result<(), String> {
        for operation in LiveOperation::ALL {
            self.get(operation).validate()?;
            if let LiveAvailability::Unsupported { reason } = &self.get(operation).availability {
                if scope == LiveScope::Host && reason.code == LiveReasonCode::DeviceProfileRejected
                {
                    return Err("host report cannot reject a machine device/profile".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RawHostReport"
)]
pub struct LiveHostReport {
    pub schema_version: u32,
    pub scope: LiveScope,
    pub backend: LiveBackend,
    pub lane: LiveLane,
    pub live: LiveCapabilityVector,
    pub build_identity: String,
    pub scenario_digest: Option<String>,
}

fn required_option<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawHostReport {
    schema_version: u32,
    scope: LiveScope,
    backend: LiveBackend,
    lane: LiveLane,
    live: LiveCapabilityVector,
    build_identity: String,
    #[serde(deserialize_with = "required_option")]
    scenario_digest: Option<String>,
}

impl TryFrom<RawHostReport> for LiveHostReport {
    type Error = String;
    fn try_from(raw: RawHostReport) -> Result<Self, Self::Error> {
        let value = Self {
            schema_version: raw.schema_version,
            scope: raw.scope,
            backend: raw.backend,
            lane: raw.lane,
            live: raw.live,
            build_identity: raw.build_identity,
            scenario_digest: raw.scenario_digest,
        };
        value.validate()?;
        Ok(value)
    }
}

impl LiveHostReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LIVE_SCHEMA_VERSION || self.scope != LiveScope::Host {
            return Err("invalid host report schema/scope".into());
        }
        validate_identity(&self.build_identity)?;
        if let Some(digest) = &self.scenario_digest {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("scenario digest must be lowercase SHA256 hex".into());
            }
            if self.backend != LiveBackend::Mock {
                return Err("only mock may report a scenario digest".into());
            }
        }
        validate_backend(self.backend, self.lane, &self.live)?;
        self.live.validate(self.scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RawMachineReport"
)]
pub struct LiveMachineReport {
    pub schema_version: u32,
    pub scope: LiveScope,
    pub machine_id: String,
    pub run_id: String,
    pub monitor_id: String,
    pub backend: LiveBackend,
    pub lane: LiveLane,
    pub topology_revision: u64,
    pub live: LiveCapabilityVector,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawMachineReport {
    schema_version: u32,
    scope: LiveScope,
    machine_id: String,
    run_id: String,
    monitor_id: String,
    backend: LiveBackend,
    lane: LiveLane,
    topology_revision: u64,
    live: LiveCapabilityVector,
}

impl TryFrom<RawMachineReport> for LiveMachineReport {
    type Error = String;
    fn try_from(raw: RawMachineReport) -> Result<Self, Self::Error> {
        let value = Self {
            schema_version: raw.schema_version,
            scope: raw.scope,
            machine_id: raw.machine_id,
            run_id: raw.run_id,
            monitor_id: raw.monitor_id,
            backend: raw.backend,
            lane: raw.lane,
            topology_revision: raw.topology_revision,
            live: raw.live,
        };
        value.validate()?;
        Ok(value)
    }
}

impl LiveMachineReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LIVE_SCHEMA_VERSION || self.scope != LiveScope::Machine {
            return Err("invalid machine report schema/scope".into());
        }
        for (name, value) in [
            ("machineId", &self.machine_id),
            ("runId", &self.run_id),
            ("monitorId", &self.monitor_id),
        ] {
            if !canonical_uuid(value) {
                return Err(format!("{name} must be a canonical non-nil UUID"));
            }
        }
        if self.topology_revision == 0 {
            return Err("topologyRevision must be nonzero".into());
        }
        validate_backend(self.backend, self.lane, &self.live)?;
        self.live.validate(self.scope)
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn validate_identity(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("build identity must be 1..256 printable ASCII bytes".into());
    }
    Ok(())
}

fn validate_backend(
    backend: LiveBackend,
    lane: LiveLane,
    live: &LiveCapabilityVector,
) -> Result<(), String> {
    match backend {
        LiveBackend::Krun if lane == LiveLane::NotApplicable => {
            return Err("krun requires an explicit native lane".into())
        }
        LiveBackend::Vz => {
            if lane != LiveLane::NotApplicable {
                return Err("vz lane must be not-applicable".into());
            }
            for operation in LiveOperation::ALL {
                let capability = live.get(operation);
                if capability.native
                    || !matches!(&capability.availability, LiveAvailability::Unsupported { reason } if reason.code == LiveReasonCode::BackendExcluded && reason.subject.is_none())
                {
                    return Err("vz operations must be native-false/backend-excluded".into());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "RawOperationUnsupported"
)]
pub struct LiveOperationUnsupported {
    pub operation: LiveOperation,
    pub backend: LiveBackend,
    pub lane: LiveLane,
    pub reason: LiveUnsupportedReason,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawOperationUnsupported {
    operation: LiveOperation,
    backend: LiveBackend,
    lane: LiveLane,
    reason: LiveUnsupportedReason,
}

impl TryFrom<RawOperationUnsupported> for LiveOperationUnsupported {
    type Error = String;
    fn try_from(raw: RawOperationUnsupported) -> Result<Self, Self::Error> {
        let value = Self {
            operation: raw.operation,
            backend: raw.backend,
            lane: raw.lane,
            reason: raw.reason,
        };
        value.validate()?;
        Ok(value)
    }
}

impl LiveOperationUnsupported {
    pub fn validate(&self) -> Result<(), String> {
        self.reason.validate()?;
        if self.backend == LiveBackend::Vz
            && (self.lane != LiveLane::NotApplicable
                || self.reason.code != LiveReasonCode::BackendExcluded)
        {
            return Err("vz refusal must be backend-excluded/not-applicable".into());
        }
        if self.backend == LiveBackend::Krun && self.lane == LiveLane::NotApplicable {
            return Err("krun refusal requires a native lane".into());
        }
        Ok(())
    }
}

impl fmt::Display for LiveOperationUnsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} unsupported: {} (backend={}, lane={})",
            self.operation, self.reason, self.backend, self.lane
        )
    }
}
impl std::error::Error for LiveOperationUnsupported {}

impl Serialize for LiveDeviceSubject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let (kind, profile) = match self {
            Self::Virtiofs => ("virtiofs", None),
            Self::Rosetta => ("rosetta", None),
            Self::Tap => ("tap", None),
            Self::Gpu => ("gpu", None),
            Self::Nested => ("nested", None),
            Self::Tee => ("tee", None),
            Self::GuestProfile { profile } => ("guest-profile", Some(profile)),
        };
        let mut value = serializer
            .serialize_struct("LiveDeviceSubject", if profile.is_some() { 2 } else { 1 })?;
        value.serialize_field("kind", kind)?;
        if let Some(profile) = profile {
            value.serialize_field("profile", profile)?;
        }
        value.end()
    }
}

impl Serialize for LiveUnsupportedReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("LiveUnsupportedReason", 2)?;
        value.serialize_field("code", &self.code)?;
        value.serialize_field("subject", &self.subject)?;
        value.end()
    }
}

impl Serialize for LiveCapability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("LiveCapability", 2)?;
        value.serialize_field("native", &self.native)?;
        value.serialize_field("availability", &self.availability)?;
        value.end()
    }
}

impl Serialize for LiveHostReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("LiveHostReport", 7)?;
        value.serialize_field("schemaVersion", &self.schema_version)?;
        value.serialize_field("scope", &self.scope)?;
        value.serialize_field("backend", &self.backend)?;
        value.serialize_field("lane", &self.lane)?;
        value.serialize_field("live", &self.live)?;
        value.serialize_field("buildIdentity", &self.build_identity)?;
        value.serialize_field("scenarioDigest", &self.scenario_digest)?;
        value.end()
    }
}

impl Serialize for LiveMachineReport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("LiveMachineReport", 9)?;
        value.serialize_field("schemaVersion", &self.schema_version)?;
        value.serialize_field("scope", &self.scope)?;
        value.serialize_field("machineId", &self.machine_id)?;
        value.serialize_field("runId", &self.run_id)?;
        value.serialize_field("monitorId", &self.monitor_id)?;
        value.serialize_field("backend", &self.backend)?;
        value.serialize_field("lane", &self.lane)?;
        value.serialize_field("topologyRevision", &self.topology_revision)?;
        value.serialize_field("live", &self.live)?;
        value.end()
    }
}

impl Serialize for LiveOperationUnsupported {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(S::Error::custom)?;
        let mut value = serializer.serialize_struct("LiveOperationUnsupported", 4)?;
        value.serialize_field("operation", &self.operation)?;
        value.serialize_field("backend", &self.backend)?;
        value.serialize_field("lane", &self.lane)?;
        value.serialize_field("reason", &self.reason)?;
        value.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::live::*;

    fn host() -> LiveHostReport {
        LiveHostReport {
            schema_version: 1,
            scope: LiveScope::Host,
            backend: LiveBackend::Krun,
            lane: LiveLane::KvmX86_64,
            live: LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered),
            build_identity: "test-revision".into(),
            scenario_digest: None,
        }
    }

    #[test]
    fn live_capabilities_host_strict_roundtrip() {
        let report = host();
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(
            serde_json::from_value::<LiveHostReport>(value.clone()).unwrap(),
            report
        );
        for field in [
            "schemaVersion",
            "scope",
            "backend",
            "lane",
            "live",
            "buildIdentity",
            "scenarioDigest",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<LiveHostReport>(missing).is_err(),
                "accepted missing {field}"
            );
        }
        for field in ["pause", "capture", "restore", "fork", "incremental"] {
            let mut missing = value.clone();
            missing["live"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<LiveHostReport>(missing).is_err());
        }
        let mut unknown = value;
        unknown["unknown"] = true.into();
        assert!(serde_json::from_value::<LiveHostReport>(unknown).is_err());
    }

    #[test]
    fn live_capabilities_scope_and_subject_validation() {
        let mut report = host();
        report.live.pause.availability = LiveAvailability::Unsupported {
            reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
        };
        assert!(report.validate().is_err());
        for code in [
            LiveReasonCode::BackendExcluded,
            LiveReasonCode::HostOsBelowFloor,
            LiveReasonCode::HypervisorUnavailable,
            LiveReasonCode::BuildExcluded,
            LiveReasonCode::NotDelivered,
        ] {
            let reason = LiveUnsupportedReason::new(code);
            assert!(reason.validate().is_ok());
            let mut invalid = reason;
            invalid.subject = Some(LiveDeviceSubject::Tap);
            assert!(invalid.validate().is_err());
        }
        assert!(
            LiveUnsupportedReason::new(LiveReasonCode::DeviceProfileRejected)
                .validate()
                .is_err()
        );
        assert!(
            LiveUnsupportedReason::device(LiveDeviceSubject::GuestProfile { profile: "".into() })
                .validate()
                .is_err()
        );
        assert!(serde_json::from_str::<LiveAvailability>(
            r#"{"status":"supported","reason":{"code":"not-delivered"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<LiveDeviceSubject>(
            r#"{"kind":"guest-profile","profile":""}"#
        )
        .is_err());
        let mut invalid_native = host();
        invalid_native.live.pause.availability = LiveAvailability::Supported;
        assert!(invalid_native.validate().is_err());
    }

    #[test]
    fn live_capabilities_machine_fences_are_mandatory() {
        let report = LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: host().live,
        };
        let value = serde_json::to_value(&report).unwrap();
        for field in ["machineId", "runId", "monitorId", "topologyRevision"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<LiveMachineReport>(missing).is_err());
        }
        let mut invalid = value;
        invalid["topologyRevision"] = 0.into();
        assert!(serde_json::from_value::<LiveMachineReport>(invalid).is_err());
    }

    #[test]
    fn live_capabilities_json_emission_rejects_mutated_models() {
        let mut report = host();
        report.live.pause.availability = LiveAvailability::Supported;
        assert!(serde_json::to_vec(&report).is_err());
        assert!(serde_json::to_vec(&report.live.pause).is_err());
        report = host();
        report.backend = LiveBackend::Vz;
        report.lane = LiveLane::NotApplicable;
        assert!(serde_json::to_vec(&report).is_err());
        report.live = LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded);
        assert!(serde_json::to_vec(&report).is_ok());
        report.lane = LiveLane::KvmX86_64;
        assert!(serde_json::to_vec(&report).is_err());

        let mut machine = LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: host().live,
        };
        assert!(serde_json::to_vec(&machine).is_ok());
        machine.topology_revision = 0;
        assert!(serde_json::to_vec(&machine).is_err());
        machine.topology_revision = 1;
        let invalid_reason = LiveUnsupportedReason::device(LiveDeviceSubject::GuestProfile {
            profile: "invalid profile".into(),
        });
        machine.live.capture.availability = LiveAvailability::Unsupported {
            reason: invalid_reason.clone(),
        };
        assert!(serde_json::to_vec(&machine).is_err());
        let refusal = LiveOperationUnsupported {
            operation: LiveOperation::Capture,
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            reason: invalid_reason,
        };
        assert!(serde_json::to_vec(&refusal).is_err());

        let positive = LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        };
        report = host();
        report.backend = LiveBackend::Mock;
        report.live = LiveCapabilityVector {
            pause: positive.clone(),
            capture: positive.clone(),
            restore: positive.clone(),
            fork: positive.clone(),
            incremental: positive,
        };
        assert!(serde_json::to_vec(&report).is_ok());
    }

    #[test]
    fn live_capabilities_tagged_unit_variants_reject_extra_fields() {
        let supported = serde_json::json!({"status": "supported"});
        let availability: LiveAvailability = serde_json::from_value(supported.clone()).unwrap();
        assert_eq!(availability, LiveAvailability::Supported);
        assert_eq!(serde_json::to_value(availability).unwrap(), supported);
        let mut host_payload = serde_json::to_value(host()).unwrap();
        host_payload["live"]["pause"] = serde_json::json!({
            "native": true,
            "availability": {"status": "supported", "reason": {"code": "not-delivered"}},
        });
        assert!(serde_json::from_value::<LiveHostReport>(host_payload).is_err());

        let machine = LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: host().live,
        };
        let machine_payload = serde_json::to_value(machine).unwrap();
        for kind in ["virtiofs", "rosetta", "tap", "gpu", "nested", "tee"] {
            let subject = serde_json::json!({"kind": kind});
            let parsed: LiveDeviceSubject = serde_json::from_value(subject.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), subject);
            for extra in ["profile", "unexpected"] {
                let mut invalid_subject = subject.clone();
                invalid_subject[extra] = "unexpected".into();
                assert!(
                    serde_json::from_value::<LiveDeviceSubject>(invalid_subject.clone()).is_err(),
                    "{kind}/{extra}"
                );
                let mut invalid_machine = machine_payload.clone();
                invalid_machine["live"]["pause"]["availability"] = serde_json::json!({
                    "status": "unsupported",
                    "reason": {"code": "device-profile-rejected", "subject": invalid_subject},
                });
                assert!(
                    serde_json::from_value::<LiveMachineReport>(invalid_machine).is_err(),
                    "machine consumer accepted {kind}/{extra}"
                );
            }
        }
    }
}

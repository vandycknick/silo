//! Machine-less discovery and the live evidence retained for an actual run.
//!
//! Production policy is compiled, not installation state. Scenario grants only
//! exercise the existing scenario backend's transport, never a native lane.
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use clap::Parser;
use libkrun::api::capabilities as native;
use sha2::{Digest, Sha256};
use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveCapability, LiveCapabilityVector, LiveDeviceSubject,
    LiveHostReport, LiveLane, LiveOperation, LiveReasonCode, LiveScope, LiveUnsupportedReason,
    LIVE_SCHEMA_VERSION,
};

pub(crate) const MAX_SCENARIO_BYTES: usize = 1024 * 1024;
/// Implemented end to end in this build. Delivery alone never supports an
/// operation: the lane still needs its qualification grant.
const DELIVERED: &[LiveOperation] = &[
    LiveOperation::Pause,
    LiveOperation::Capture,
    LiveOperation::Restore,
    LiveOperation::Fork,
];

#[derive(Debug, Parser)]
#[command(name = "silo-vmm capabilities")]
struct QueryArgs {
    #[arg(long, value_parser = ["krun", "vz", "mock"])]
    backend: String,
    #[arg(long)]
    scenario: Option<PathBuf>,
    #[arg(long, required = true)]
    json: bool,
}

/// Called after private worker dispatch, before any launch initialization.
pub(crate) fn dispatch() -> Option<eyre::Result<()>> {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("capabilities")) {
        return None;
    }
    Some((|| {
        let args = QueryArgs::try_parse_from(std::env::args_os().skip(1))?;
        eyre::ensure!(args.json, "capability query requires --json");
        let backend = parse_backend(&args.backend)?;
        let selection = ResolvedSelection::from_query(backend, args.scenario.as_deref())?;
        let report = selection.host_report()?;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer(&mut stdout, &report)?;
        writeln!(stdout)?;
        Ok(())
    })())
}

pub(crate) fn scenario_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

pub(crate) fn validate_scenario_bytes(bytes: &[u8], expected_digest: &str) -> eyre::Result<()> {
    eyre::ensure!(
        bytes.len() <= MAX_SCENARIO_BYTES,
        "scenario exceeds {MAX_SCENARIO_BYTES} bytes"
    );
    eyre::ensure!(
        scenario_digest(bytes) == expected_digest,
        "scenario digest does not match frozen bytes"
    );
    Ok(())
}

fn read_scenario(path: &std::path::Path) -> eyre::Result<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)?;
    eyre::ensure!(file.metadata()?.is_file(), "scenario is not a regular file");
    let mut bytes = Vec::new();
    file.take((MAX_SCENARIO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    eyre::ensure!(
        bytes.len() <= MAX_SCENARIO_BYTES,
        "scenario exceeds {MAX_SCENARIO_BYTES} bytes"
    );
    Ok(String::from_utf8(bytes)?)
}

fn parse_backend(value: &str) -> eyre::Result<LiveBackend> {
    match value {
        "krun" => Ok(LiveBackend::Krun),
        "vz" => Ok(LiveBackend::Vz),
        "mock" => Ok(LiveBackend::Mock),
        _ => Err(eyre::eyre!("unknown backend {value:?}")),
    }
}

/// One immutable selection supplies both live evidence and backend construction.
pub(crate) struct ResolvedSelection {
    backend: LiveBackend,
    scenario_digest: Option<String>,
    #[cfg(feature = "mock-backend")]
    scenario: Option<std::sync::Arc<test_utils::Scenario>>,
}

impl ResolvedSelection {
    fn from_query(backend: LiveBackend, path: Option<&std::path::Path>) -> eyre::Result<Self> {
        eyre::ensure!(
            backend == LiveBackend::Mock || path.is_none(),
            "only mock accepts --scenario"
        );
        let json = path.map(read_scenario).transpose()?;
        Self::from_bytes(backend, json.as_deref())
    }

    fn from_bytes(backend: LiveBackend, json: Option<&str>) -> eyre::Result<Self> {
        eyre::ensure!(
            backend == LiveBackend::Mock || json.is_none(),
            "only mock accepts a scenario"
        );
        #[cfg(not(feature = "mock-backend"))]
        eyre::ensure!(
            backend != LiveBackend::Mock,
            "silo-vmm was built without the mock-backend feature"
        );
        if let Some(json) = json {
            eyre::ensure!(
                json.len() <= MAX_SCENARIO_BYTES,
                "scenario exceeds {MAX_SCENARIO_BYTES} bytes"
            );
        }
        #[cfg(feature = "mock-backend")]
        let scenario = if backend == LiveBackend::Mock {
            let scenario = json
                .map(test_utils::Scenario::from_json)
                .transpose()?
                .unwrap_or_default();
            if let Some(live) = &scenario.live {
                live.validate().map_err(eyre::Report::msg)?;
            }
            Some(std::sync::Arc::new(scenario))
        } else {
            None
        };
        Ok(Self {
            backend,
            scenario_digest: json.map(|json| scenario_digest(json.as_bytes())),
            #[cfg(feature = "mock-backend")]
            scenario,
        })
    }

    pub(crate) fn from_start(
        request: Option<&crate::start_request::VirtBackendRequest>,
    ) -> eyre::Result<Self> {
        if let Some(request) = request {
            crate::start_request::validate_backend_request(request)?;
        }
        let backend = request
            .map(|request| parse_backend(&request.kind))
            .transpose()?
            .unwrap_or(LiveBackend::Krun);
        let json = request.and_then(|request| request.scenario_json.as_deref());
        Self::from_bytes(backend, json)
    }

    pub(crate) fn backend_kind(&self) -> eyre::Result<crate::virt::BackendKind> {
        let backend = match self.backend {
            LiveBackend::Krun => crate::virt::BackendKind::Krun,
            LiveBackend::Vz => crate::virt::BackendKind::Vz,
            #[cfg(feature = "mock-backend")]
            LiveBackend::Mock => crate::virt::BackendKind::Mock,
            #[cfg(not(feature = "mock-backend"))]
            LiveBackend::Mock => return Err(eyre::eyre!("mock backend is not compiled")),
        };
        eyre::ensure!(
            crate::virt::BackendKind::compiled().contains(&backend),
            "backend {backend} is not compiled into this silo-vmm binary"
        );
        Ok(backend)
    }

    #[cfg(feature = "mock-backend")]
    pub(crate) fn configure_mock(&self, config: &mut crate::virt::VmConfig) {
        if let Some(scenario) = &self.scenario {
            config.set_resolved_mock_scenario(scenario.clone());
        }
    }

    pub(crate) fn host_report(&self) -> eyre::Result<LiveHostReport> {
        let build = compiled_build();
        let qualification_identity = build.qualification_identity()?;
        let qualification_ready = build.qualification_ready();
        // Only the selected native backend may touch its machine-less host API.
        let native_report = (self.backend == LiveBackend::Krun).then(native::query_live_host);
        let lane = native_report
            .as_ref()
            .map(|report| native_lane(report.lane))
            .transpose()?
            .unwrap_or(LiveLane::NotApplicable);
        let operations = native_report.as_ref().map(|report| &report.operations);
        let host = native_report
            .as_ref()
            .map(native_host_admission)
            .unwrap_or_else(HostAdmission::not_evaluated);
        let live = evaluate_vector(|operation| EvaluationFacts {
            backend_allowed: self.backend == LiveBackend::Krun,
            native: operations.is_some_and(|operations| native_primitive(operation, operations)),
            delivered: DELIVERED.contains(&operation),
            qualified: qualification_matches(
                &qualification_identity,
                qualification_ready,
                lane,
                operation,
                QUALIFICATIONS,
            ),
            host,
        })?;
        #[cfg(feature = "mock-backend")]
        let (lane, live) = match self
            .scenario
            .as_ref()
            .and_then(|scenario| scenario.live.as_ref())
        {
            Some(grant) => (grant.lane, grant.host.clone()),
            None => (lane, live),
        };
        let report = LiveHostReport {
            schema_version: LIVE_SCHEMA_VERSION,
            scope: LiveScope::Host,
            backend: self.backend,
            lane,
            live,
            build_identity: build.public_identity(),
            qualification_identity,
            scenario_digest: self.scenario_digest.clone(),
        };
        report.validate().map_err(eyre::Report::msg)?;
        Ok(report)
    }

    pub(crate) fn machine_vector(
        &self,
        host: LiveCapabilityVector,
        config: &crate::virt::VmConfig,
    ) -> LiveCapabilityVector {
        #[cfg(feature = "mock-backend")]
        let live = self
            .scenario
            .as_ref()
            .and_then(|scenario| scenario.live.as_ref())
            .and_then(|live| live.machine.clone())
            .unwrap_or(host);
        #[cfg(not(feature = "mock-backend"))]
        let live = host;
        narrow(live, EffectiveProfile::from_config(config).rejection())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("native capability query reports no admitted live lane for this build")]
struct UnsupportedNativeLane;

fn native_lane(lane: native::NativeLane) -> Result<LiveLane, UnsupportedNativeLane> {
    // Preserve native feature/inventory exclusions. The current public schema
    // requires an explicit lane for krun, so an unsupported lane is a typed
    // discovery refusal, never an invented candidate or NotApplicable report.
    match lane {
        native::NativeLane::KvmX86_64 => Ok(LiveLane::KvmX86_64),
        native::NativeLane::KvmArm64GicV3 => Ok(LiveLane::KvmArm64GicV3),
        native::NativeLane::HvfArm64GicV3 => Ok(LiveLane::HvfArm64),
        native::NativeLane::Unsupported => Err(UnsupportedNativeLane),
    }
}

fn vector(mut capability: impl FnMut(LiveOperation) -> LiveCapability) -> LiveCapabilityVector {
    LiveCapabilityVector {
        pause: capability(LiveOperation::Pause),
        capture: capability(LiveOperation::Capture),
        restore: capability(LiveOperation::Restore),
        fork: capability(LiveOperation::Fork),
        incremental: capability(LiveOperation::Incremental),
    }
}

/// Parent observations and linked dependency-local facts remain separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BuildIdentity<'a> {
    revision: &'a str,
    target: &'a str,
    profile: &'a str,
    declared_features: &'a str,
    source_kind: &'a str,
    source_root: &'a str,
    source_state: &'a str,
    source_content: &'a str,
    native_build: Option<&'a native::NativeBuildFacts>,
}

impl BuildIdentity<'_> {
    fn qualification_ready(&self) -> bool {
        let Some(build) = self.native_build else {
            return false;
        };
        build.binding_complete()
            && build.control_abi.is_some()
            && self.source_content.len() == 64
            && self
                .source_content
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && match self.source_kind {
                "path" => self.source_state == "clean" && !self.source_root.is_empty(),
                "git" => self.source_state == "revision-bound",
                _ => false,
            }
            && build.packages.iter().all(|package| {
                package.target == Some(self.target)
                    && package.source.clean_revision() == Some(self.revision)
                    && (self.source_kind != "path" || package.source.root == Some(self.source_root))
            })
    }

    fn public_identity(&self) -> String {
        format!(
            "v2:{}:{}:{}:content={}:inputs={}",
            self.source_kind, self.source_state, self.revision, self.source_content, self.profile
        )
    }

    fn qualification_identity(&self) -> eyre::Result<String> {
        use std::fmt::Write as _;
        let native = native_build_digest(self.native_build)?;
        let mut hash = Sha256::new();
        hash.update(b"silo-qualification-binding-v2\0");
        for field in [
            self.revision,
            self.target,
            self.profile,
            self.declared_features,
            self.source_kind,
            self.source_root,
            self.source_state,
            self.source_content,
            &native,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let mut binding = String::with_capacity(64);
        for byte in hash.finalize() {
            write!(binding, "{byte:02x}")?;
        }
        Ok(format!(
            "v2:native={native}:binding={binding}:eligible={}",
            self.qualification_ready()
        ))
    }
}

/// Stream native canonical observations directly into the digest, including
/// unknown fields. The public schema stays bounded and never loses partial facts.
fn native_build_digest(build: Option<&native::NativeBuildFacts>) -> eyre::Result<String> {
    use std::fmt::Write as _;
    struct HashWriter(Sha256);
    impl std::fmt::Write for HashWriter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0.update(value.as_bytes());
            Ok(())
        }
    }
    let Some(build) = build else {
        return Ok("unobserved".into());
    };
    let mut output = HashWriter(Sha256::new());
    write!(
        output,
        "silo-native-build-v1;query={};control={:?};backend={:?};arch={:?};",
        build.query_abi, build.control_abi, build.backend, build.architecture
    )?;
    for package in build.packages {
        package.write_canonical(&mut output)?;
    }
    let mut digest = String::with_capacity(64);
    for byte in output.0.finalize() {
        write!(digest, "{byte:02x}")?;
    }
    Ok(digest)
}

fn compiled_build() -> BuildIdentity<'static> {
    BuildIdentity {
        revision: env!("SILO_LIBKRUN_REVISION"),
        target: env!("SILO_BUILD_TARGET"),
        profile: env!("SILO_BUILD_INPUT_FINGERPRINT"),
        declared_features: env!("SILO_DECLARED_FEATURES_FINGERPRINT"),
        source_kind: env!("SILO_LIBKRUN_SOURCE_KIND"),
        source_root: env!("SILO_LIBKRUN_SOURCE_ROOT"),
        source_state: env!("SILO_LIBKRUN_SOURCE_STATE"),
        source_content: env!("SILO_LIBKRUN_SOURCE_CONTENT"),
        native_build: Some(native::compiled_live_build()),
    }
}

/// The Silo producer bound into every captured execution state: this
/// compiled monitor's qualification identity (libkrun revision, build
/// inputs, native build facts), so restore admits only the exact producer.
pub(crate) fn capture_producer() -> eyre::Result<[u8; 32]> {
    let identity = compiled_build().qualification_identity()?;
    let mut hash = Sha256::new();
    hash.update(b"silo-capture-producer-v1\0");
    hash.update((identity.len() as u64).to_be_bytes());
    hash.update(identity.as_bytes());
    Ok(hash.finalize().into())
}

struct Qualification<'a> {
    binding: &'a str,
    lane: LiveLane,
    operations: &'a [LiveOperation],
    evidence: &'a str,
}

// Supervisor-verified real CLI/guest pause, ClockOnly resume and paused stop.
const QUALIFICATIONS: &[Qualification<'static>] = &[Qualification {
    binding: "v2:native=9cf385b61cb89d00324047c75453d541ea0c57c6bbdbc5803b2331513316cf04:binding=c63be6ffdc486400258719cc3b29be5461ec8dc76574787186ea5499ca8ee836:eligible=true",
    lane: LiveLane::KvmX86_64,
    operations: &[LiveOperation::Pause],
    evidence: "phase-17/pause-candidate-final.xml; exact release CLI/guest pause, resume, paused stop and profile refusal",
}];

fn qualification_matches(
    binding: &str,
    eligible: bool,
    lane: LiveLane,
    operation: LiveOperation,
    records: &[Qualification<'_>],
) -> bool {
    if records.is_empty() || !eligible {
        return false;
    }
    records.iter().any(|record| {
        record.binding == binding
            && record.lane == lane
            && record.operations.contains(&operation)
            && !record.evidence.is_empty()
    })
}

fn native_primitive(operation: LiveOperation, operations: &native::NativeLiveOperations) -> bool {
    match operation {
        LiveOperation::Pause => operations.pause,
        LiveOperation::Capture => operations.capture,
        LiveOperation::Restore => operations.restore,
        LiveOperation::Fork => operations.fork,
        LiveOperation::Incremental => operations.incremental,
    }
    .is_supported()
}

fn observed_host_check(value: native::Observation<()>) -> HostCheck {
    match value {
        native::Observation::Observed(()) => HostCheck::Passed,
        native::Observation::Unavailable(_) => HostCheck::Failed,
        native::Observation::NotEvaluated | native::Observation::NotApplicable => {
            HostCheck::NotEvaluated
        }
    }
}

fn kvm_host_admission(
    prerequisites: native::KvmPrerequisites,
    gic_model: Option<native::Observation<()>>,
) -> HostAdmission {
    let hypervisor = match prerequisites {
        native::KvmPrerequisites::SystemQueriesAvailable => HostCheck::Passed,
        native::KvmPrerequisites::Unavailable(_)
        | native::KvmPrerequisites::ApiMismatch { .. }
        | native::KvmPrerequisites::MissingCapability(_) => HostCheck::Failed,
        native::KvmPrerequisites::Incomplete | native::KvmPrerequisites::NotApplicable => {
            HostCheck::NotEvaluated
        }
    };
    HostAdmission {
        os_floor: HostCheck::Passed, // KVM uses API/extensions, not a kernel-version floor.
        hypervisor,
        lane: gic_model.map(observed_host_check).unwrap_or(hypervisor),
    }
}

fn native_host_admission(report: &native::NativeHostReport) -> HostAdmission {
    match report.lane {
        native::NativeLane::KvmX86_64 => kvm_host_admission(report.kvm_prerequisites, None),
        native::NativeLane::KvmArm64GicV3 => {
            kvm_host_admission(report.kvm_prerequisites, Some(report.kvm.gic_model))
        }
        native::NativeLane::HvfArm64GicV3 => HostAdmission {
            os_floor: HostCheck::NotEvaluated,
            hypervisor: observed_host_check(report.hvf.vm_admission),
            lane: observed_host_check(report.hvf.gic_model),
        },
        native::NativeLane::Unsupported => HostAdmission::not_evaluated(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostCheck {
    NotEvaluated,
    Passed,
    Failed,
}

impl From<Option<bool>> for HostCheck {
    fn from(result: Option<bool>) -> Self {
        match result {
            None => Self::NotEvaluated,
            Some(true) => Self::Passed,
            Some(false) => Self::Failed,
        }
    }
}

#[derive(Clone, Copy)]
struct HostAdmission {
    os_floor: HostCheck,
    hypervisor: HostCheck,
    lane: HostCheck,
}

impl HostAdmission {
    fn not_evaluated() -> Self {
        Self {
            os_floor: None.into(),
            hypervisor: None.into(),
            lane: None.into(),
        }
    }
}

/// Four independent product facts. Unknown host admission never becomes support.
#[derive(Clone, Copy)]
struct EvaluationFacts {
    backend_allowed: bool,
    native: bool,
    delivered: bool,
    qualified: bool,
    host: HostAdmission,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("required host capability checks were not evaluated")]
struct EvaluationIncomplete;

fn evaluate_vector(
    mut facts: impl FnMut(LiveOperation) -> EvaluationFacts,
) -> Result<LiveCapabilityVector, EvaluationIncomplete> {
    Ok(LiveCapabilityVector {
        pause: evaluate(facts(LiveOperation::Pause))?,
        capture: evaluate(facts(LiveOperation::Capture))?,
        restore: evaluate(facts(LiveOperation::Restore))?,
        fork: evaluate(facts(LiveOperation::Fork))?,
        incremental: evaluate(facts(LiveOperation::Incremental))?,
    })
}

fn evaluate(facts: EvaluationFacts) -> Result<LiveCapability, EvaluationIncomplete> {
    let reason = if !facts.backend_allowed {
        Some(LiveReasonCode::BackendExcluded)
    } else if !facts.delivered {
        Some(LiveReasonCode::NotDelivered)
    } else if !facts.native {
        Some(LiveReasonCode::BuildExcluded)
    } else if matches!(facts.host.os_floor, HostCheck::NotEvaluated) {
        return Err(EvaluationIncomplete);
    } else if matches!(facts.host.os_floor, HostCheck::Failed) {
        Some(LiveReasonCode::HostOsBelowFloor)
    } else if matches!(facts.host.hypervisor, HostCheck::NotEvaluated) {
        return Err(EvaluationIncomplete);
    } else if matches!(facts.host.hypervisor, HostCheck::Failed) {
        Some(LiveReasonCode::HypervisorUnavailable)
    } else if matches!(facts.host.lane, HostCheck::NotEvaluated) {
        return Err(EvaluationIncomplete);
    } else if matches!(facts.host.lane, HostCheck::Failed) || !facts.qualified {
        Some(LiveReasonCode::LaneNotQualified)
    } else {
        None
    };
    Ok(LiveCapability {
        native: facts.native,
        availability: match reason {
            Some(code) => LiveAvailability::Unsupported {
                reason: LiveUnsupportedReason::new(code),
            },
            None => LiveAvailability::Supported,
        },
    })
}

#[derive(Default)]
struct EffectiveProfile {
    virtiofs: bool,
    rosetta: bool,
    tap: bool,
    gpu: bool,
    nested: bool,
    tee: bool,
    guest_rejection: Option<String>,
}

impl EffectiveProfile {
    fn from_config(config: &crate::virt::VmConfig) -> Self {
        Self {
            virtiofs: !config.mounts().is_empty(),
            rosetta: !matches!(config.rosetta(), crate::virt::RosettaIntent::Disabled)
                || config.krun().prepared_rosetta.is_some(),
            nested: config.nested_virtualization(),
            // VmConfig's only network is UnixDatagram and it has no GPU/TEE
            // attachment APIs. Never infer one of these from a requested spec.
            tap: false,
            gpu: false,
            tee: false,
            guest_rejection: config
                .kernel_path()
                .is_none()
                .then(|| "missing-linux-kernel".into()),
        }
    }

    fn rejection(self) -> Option<LiveDeviceSubject> {
        if self.virtiofs {
            Some(LiveDeviceSubject::Virtiofs)
        } else if self.rosetta {
            Some(LiveDeviceSubject::Rosetta)
        } else if self.tap {
            Some(LiveDeviceSubject::Tap)
        } else if self.gpu {
            Some(LiveDeviceSubject::Gpu)
        } else if self.nested {
            Some(LiveDeviceSubject::Nested)
        } else if self.tee {
            Some(LiveDeviceSubject::Tee)
        } else {
            self.guest_rejection
                .map(|profile| LiveDeviceSubject::GuestProfile { profile })
        }
    }
}

/// The state owner supplies a rejection unless fresh, exact guest identity,
/// containment and the bound generation driver have all been observed.
/// Always narrow the original machine vector, never a prior narrowed result.
pub(crate) fn narrow_for_guest(
    live: LiveCapabilityVector,
    rejection: Option<&str>,
) -> LiveCapabilityVector {
    narrow(
        live,
        rejection.map(|profile| LiveDeviceSubject::GuestProfile {
            profile: profile.to_owned(),
        }),
    )
}

fn narrow(live: LiveCapabilityVector, subject: Option<LiveDeviceSubject>) -> LiveCapabilityVector {
    vector(|operation| {
        let mut capability = live.get(operation).clone();
        if matches!(capability.availability, LiveAvailability::Supported) {
            if let Some(subject) = &subject {
                capability.availability = LiveAvailability::Unsupported {
                    reason: LiveUnsupportedReason::device(subject.clone()),
                };
            }
        }
        capability
    })
}

#[cfg(test)]
mod tests {
    use crate::capabilities::*;

    fn qualification_matches(
        build: &BuildIdentity<'_>,
        lane: LiveLane,
        operation: LiveOperation,
        records: &[Qualification<'_>],
    ) -> bool {
        crate::capabilities::qualification_matches(
            &build
                .qualification_identity()
                .expect("canonical build binding"),
            build.qualification_ready(),
            lane,
            operation,
            records,
        )
    }

    fn admitted() -> HostAdmission {
        HostAdmission {
            os_floor: HostCheck::Passed,
            hypervisor: HostCheck::Passed,
            lane: HostCheck::Passed,
        }
    }

    #[test]
    fn capabilities_four_facts_are_independent() {
        for bits in 0..16 {
            let capability = evaluate(EvaluationFacts {
                backend_allowed: true,
                native: bits & 1 != 0,
                delivered: bits & 2 != 0,
                qualified: bits & 4 != 0,
                host: if bits & 8 != 0 {
                    admitted()
                } else {
                    HostAdmission {
                        hypervisor: HostCheck::Failed,
                        ..admitted()
                    }
                },
            })
            .expect("all host facts evaluated");
            assert_eq!(capability.native, bits & 1 != 0);
            assert_eq!(
                capability.availability == LiveAvailability::Supported,
                bits == 15
            );
        }
    }

    #[test]
    fn capabilities_reason_precedence_and_every_closed_reason() {
        let base = EvaluationFacts {
            backend_allowed: true,
            native: true,
            delivered: true,
            qualified: true,
            host: admitted(),
        };
        let cases = [
            (
                EvaluationFacts {
                    backend_allowed: false,
                    delivered: false,
                    native: false,
                    ..base
                },
                LiveReasonCode::BackendExcluded,
            ),
            (
                EvaluationFacts {
                    delivered: false,
                    native: false,
                    ..base
                },
                LiveReasonCode::NotDelivered,
            ),
            (
                EvaluationFacts {
                    native: false,
                    host: HostAdmission::not_evaluated(),
                    ..base
                },
                LiveReasonCode::BuildExcluded,
            ),
            (
                EvaluationFacts {
                    host: HostAdmission {
                        os_floor: HostCheck::Failed,
                        hypervisor: HostCheck::Failed,
                        lane: HostCheck::Failed,
                    },
                    ..base
                },
                LiveReasonCode::HostOsBelowFloor,
            ),
            (
                EvaluationFacts {
                    host: HostAdmission {
                        hypervisor: HostCheck::Failed,
                        ..admitted()
                    },
                    ..base
                },
                LiveReasonCode::HypervisorUnavailable,
            ),
            (
                EvaluationFacts {
                    qualified: false,
                    ..base
                },
                LiveReasonCode::LaneNotQualified,
            ),
            (
                EvaluationFacts {
                    host: HostAdmission {
                        lane: HostCheck::Failed,
                        ..admitted()
                    },
                    ..base
                },
                LiveReasonCode::LaneNotQualified,
            ),
        ];
        for (facts, code) in cases {
            assert_eq!(
                evaluate(facts).expect("evaluated").availability,
                LiveAvailability::Unsupported {
                    reason: LiveUnsupportedReason::new(code)
                }
            );
        }
        assert_eq!(
            evaluate(EvaluationFacts {
                host: HostAdmission::not_evaluated(),
                ..base
            }),
            Err(EvaluationIncomplete)
        );
        let narrowed = narrow(
            vector(|_| evaluate(base).expect("evaluated")),
            Some(LiveDeviceSubject::Virtiofs),
        );
        assert_eq!(
            narrowed.pause.availability,
            LiveAvailability::Unsupported {
                reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs)
            }
        );
    }

    const fn known_native_build() -> native::NativeBuildFacts {
        const SETTINGS: &[(&str, Option<&str>)] = &[
            ("TARGET", Some("target")),
            ("HOST", Some("host")),
            ("OPT_LEVEL", Some("2")),
            ("DEBUG", Some("false")),
            ("PROFILE", Some("release")),
            ("CARGO_CFG_TARGET_ARCH", Some("x86_64")),
            ("CARGO_CFG_TARGET_OS", Some("linux")),
            ("CARGO_CFG_TARGET_ENDIAN", Some("little")),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", Some("64")),
            ("CARGO_CFG_TARGET_ENV", Some("gnu")),
            ("CARGO_CFG_TARGET_FEATURE", Some("")),
            ("CARGO_ENCODED_RUSTFLAGS", Some("")),
        ];
        const BASE: native::PackageBuildFacts = native::PackageBuildFacts {
            name: "libkrun",
            version: "1",
            target: Some("target"),
            features: Some(&[]),
            settings: SETTINGS,
            settings_observed: true,
            rustc_version: Some("rustc"),
            source: native::SourceProvenance {
                root: Some("/native"),
                revision: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                worktree: native::WorktreeState::Clean,
            },
        };
        const PACKAGES: &[native::PackageBuildFacts] = &[
            BASE,
            native::PackageBuildFacts {
                name: "krun-arch",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-arch-gen",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-devices",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-kernel",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-polly",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-utils",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-smbios",
                ..BASE
            },
            native::PackageBuildFacts {
                name: "krun-cpuid",
                ..BASE
            },
        ];
        native::NativeBuildFacts {
            query_abi: native::LIVE_QUERY_ABI,
            control_abi: Some(1),
            backend: native::NativeBackend::Kvm,
            architecture: native::NativeArchitecture::X86_64,
            packages: PACKAGES,
        }
    }

    fn known_build(native: &native::NativeBuildFacts) -> BuildIdentity<'_> {
        BuildIdentity {
            revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            target: "target",
            profile: "parent-inputs",
            declared_features: "declared-inputs",
            source_kind: "path",
            source_root: "/native",
            source_state: "clean",
            source_content: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            native_build: Some(native),
        }
    }

    #[test]
    fn capabilities_qualification_matches_every_build_input() {
        let native = known_native_build();
        let build = known_build(&native);
        let records = [Qualification {
            binding: &build
                .qualification_identity()
                .expect("canonical build binding"),
            lane: LiveLane::KvmX86_64,
            operations: &[LiveOperation::Pause],
            evidence: "unit-evidence",
        }];
        assert!(qualification_matches(
            &build,
            LiveLane::KvmX86_64,
            LiveOperation::Pause,
            &records
        ));
        for changed in [
            BuildIdentity {
                revision: "other",
                ..build
            },
            BuildIdentity {
                target: "other",
                ..build
            },
            BuildIdentity {
                profile: "other",
                ..build
            },
            BuildIdentity {
                declared_features: "other",
                ..build
            },
            BuildIdentity {
                source_content: "other",
                ..build
            },
            BuildIdentity {
                source_root: "/other",
                ..build
            },
            BuildIdentity {
                source_state: "dirty",
                ..build
            },
            BuildIdentity {
                source_state: "unknown",
                ..build
            },
            BuildIdentity {
                source_kind: "unknown",
                ..build
            },
            BuildIdentity {
                native_build: None,
                ..build
            },
        ] {
            assert!(!qualification_matches(
                &changed,
                LiveLane::KvmX86_64,
                LiveOperation::Pause,
                &records
            ));
        }
        assert!(!qualification_matches(
            &build,
            LiveLane::HvfArm64,
            LiveOperation::Pause,
            &records
        ));
        assert!(!qualification_matches(
            &build,
            LiveLane::KvmX86_64,
            LiveOperation::Capture,
            &records
        ));
        let no_evidence = [Qualification {
            binding: &build
                .qualification_identity()
                .expect("canonical build binding"),
            lane: LiveLane::KvmX86_64,
            operations: &[LiveOperation::Pause],
            evidence: "",
        }];
        assert!(!qualification_matches(
            &build,
            LiveLane::KvmX86_64,
            LiveOperation::Pause,
            &no_evidence
        ));
        let git = BuildIdentity {
            source_kind: "git",
            source_root: "",
            source_state: "revision-bound",
            ..build
        };
        assert!(git.qualification_ready());
    }

    const fn partial_packages(case: usize) -> [native::PackageBuildFacts; 9] {
        let baseline = known_native_build();
        let mut packages = [baseline.packages[0]; 9];
        let mut index = 0;
        while index < packages.len() {
            packages[index] = baseline.packages[index];
            index += 1;
        }
        match case {
            0 => packages[0].features = None,
            1 => packages[0].settings = &[],
            2 => packages[0].settings_observed = false,
            3 => packages[0].source.worktree = native::WorktreeState::Dirty,
            4 => packages[0].source.worktree = native::WorktreeState::Unknown,
            5 => packages[0].source.revision = None,
            6 => packages[0].features = Some(&["CARGO_FEATURE_BLK"]),
            8 => packages[2].features = Some(&["CARGO_FEATURE_TEE"]),
            9 => packages[2].features = Some(&["CARGO_FEATURE_AMD_SEV"]),
            10 => packages[2].features = Some(&["CARGO_FEATURE_TDX"]),
            11 => packages[2].features = Some(&["CARGO_FEATURE_AWS_NITRO"]),
            _ => packages[0].rustc_version = Some("another-rustc"),
        }
        packages
    }

    #[test]
    fn capabilities_authoritative_native_lane_preserves_exclusions_and_unknown_inventory() {
        for (native, public) in [
            (native::NativeLane::KvmX86_64, LiveLane::KvmX86_64),
            (native::NativeLane::KvmArm64GicV3, LiveLane::KvmArm64GicV3),
            (native::NativeLane::HvfArm64GicV3, LiveLane::HvfArm64),
        ] {
            assert_eq!(native_lane(native), Ok(public));
        }
        const EXCLUDED: &[&[native::PackageBuildFacts]] = &[
            &partial_packages(8),
            &partial_packages(9),
            &partial_packages(10),
            &partial_packages(11),
            &partial_packages(0),
            &[],
        ];
        for packages in EXCLUDED {
            let build = native::NativeBuildFacts {
                packages,
                ..known_native_build()
            };
            assert_eq!(build.backend, native::NativeBackend::Kvm);
            assert_eq!(build.architecture, native::NativeArchitecture::X86_64);
            let lane = native::NativeLane::from_build(&build);
            assert_eq!(lane, native::NativeLane::Unsupported);
            assert_eq!(native_lane(lane), Err(UnsupportedNativeLane));
        }
    }

    #[test]
    fn capabilities_partial_native_facts_never_qualify_even_matching_records() {
        const PARTIAL: &[[native::PackageBuildFacts; 9]] = &[
            partial_packages(0),
            partial_packages(1),
            partial_packages(2),
            partial_packages(3),
            partial_packages(4),
            partial_packages(5),
        ];
        let baseline = known_native_build();
        let variants = [
            native::NativeBuildFacts {
                query_abi: 0,
                ..known_native_build()
            },
            native::NativeBuildFacts {
                control_abi: None,
                ..known_native_build()
            },
        ];
        for native in
            variants
                .into_iter()
                .chain(PARTIAL.iter().map(|packages| native::NativeBuildFacts {
                    packages,
                    ..known_native_build()
                }))
        {
            let build = known_build(&native);
            let records = [Qualification {
                binding: &build
                    .qualification_identity()
                    .expect("canonical build binding"),
                lane: LiveLane::KvmX86_64,
                operations: &LiveOperation::ALL,
                evidence: "cannot-override-partial-facts",
            }];
            assert!(!build.qualification_ready());
            assert!(!qualification_matches(
                &build,
                LiveLane::KvmX86_64,
                LiveOperation::Pause,
                &records
            ));
            assert_ne!(
                native_build_digest(Some(&native)).expect("canonical partial facts"),
                native_build_digest(Some(&baseline)).expect("canonical complete facts")
            );
        }
    }

    #[test]
    fn capabilities_binding_digest_changes_with_native_facts_and_path_content() {
        const ALTERNATE: &[[native::PackageBuildFacts; 9]] =
            &[partial_packages(6), partial_packages(7)];
        let native = known_native_build();
        let baseline = known_build(&native);
        let identity = baseline
            .qualification_identity()
            .expect("baseline identity");
        let records = [Qualification {
            binding: &identity,
            lane: LiveLane::KvmX86_64,
            operations: &LiveOperation::ALL,
            evidence: "unit-evidence",
        }];
        for packages in ALTERNATE {
            let changed = native::NativeBuildFacts {
                packages,
                ..known_native_build()
            };
            let build = known_build(&changed);
            assert!(build.qualification_ready());
            assert_ne!(
                build
                    .qualification_identity()
                    .expect("changed native binding"),
                identity
            );
            assert!(!qualification_matches(
                &build,
                LiveLane::KvmX86_64,
                LiveOperation::Pause,
                &records
            ));
        }
        for changed in [
            BuildIdentity {
                source_content: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ..baseline
            },
            BuildIdentity {
                source_state: "dirty",
                ..baseline
            },
            BuildIdentity {
                profile: "other-profile",
                ..baseline
            },
            BuildIdentity {
                declared_features: "other-declaration",
                ..baseline
            },
        ] {
            assert_ne!(
                changed.qualification_identity().expect("changed binding"),
                identity
            );
        }
    }

    #[test]
    fn capabilities_linked_native_facts_are_observed_without_host_access() {
        let compiled = compiled_build();
        assert_eq!(compiled.native_build, Some(native::compiled_live_build()));
        assert_eq!(native::compiled_live_build().query_abi, 1);
        let records = [Qualification {
            binding: &compiled
                .qualification_identity()
                .expect("canonical build binding"),
            lane: LiveLane::KvmX86_64,
            operations: &LiveOperation::ALL,
            evidence: "not-production-evidence",
        }];
        let lane = native::NativeLane::from_build(native::compiled_live_build());
        let operations = native::NativeLiveOperations::for_lane(lane);
        for operation in LiveOperation::ALL {
            assert_eq!(
                native_primitive(operation, &operations),
                lane == native::NativeLane::KvmX86_64
                    || (operation == LiveOperation::Pause
                        && lane != native::NativeLane::Unsupported)
            );
            assert!(!qualification_matches(
                &compiled,
                LiveLane::KvmX86_64,
                operation,
                QUALIFICATIONS
            ));
            assert_eq!(
                qualification_matches(&compiled, LiveLane::KvmX86_64, operation, &records),
                compiled.qualification_ready()
            );
        }
        let identity = compiled
            .qualification_identity()
            .expect("canonical identity");
        assert!(!identity.contains("native=unobserved"));
        assert!(identity.len() <= 256);
        assert!(compiled.public_identity().len() <= 256);
    }

    #[test]
    fn capabilities_native_host_reducer_keeps_unknowns_and_public_delivery_precedence() {
        let unknown = kvm_host_admission(
            native::KvmPrerequisites::Incomplete,
            Some(native::Observation::NotEvaluated),
        );
        assert_eq!(unknown.hypervisor, HostCheck::NotEvaluated);
        assert_eq!(unknown.lane, HostCheck::NotEvaluated);
        let arm = kvm_host_admission(
            native::KvmPrerequisites::SystemQueriesAvailable,
            Some(native::Observation::NotEvaluated),
        );
        assert_eq!(arm.hypervisor, HostCheck::Passed);
        assert_eq!(arm.lane, HostCheck::NotEvaluated);
        let denied = native::NativeQueryError {
            operation: native::QueryOperation::OpenKvm,
            raw_os_error: Some(13),
            kind: std::io::ErrorKind::PermissionDenied,
        };
        for prerequisites in [
            native::KvmPrerequisites::Unavailable(denied),
            native::KvmPrerequisites::ApiMismatch {
                observed: 11,
                required: 12,
            },
            native::KvmPrerequisites::MissingCapability(native::KvmCapability::ImmediateExit),
        ] {
            let host = kvm_host_admission(prerequisites, None);
            assert_eq!(host.hypervisor, HostCheck::Failed);
            assert_eq!(
                evaluate(EvaluationFacts {
                    backend_allowed: true,
                    native: false,
                    delivered: false,
                    qualified: false,
                    host,
                })
                .expect("undelivered public result")
                .availability,
                LiveAvailability::Unsupported {
                    reason: LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
                }
            );
        }
        assert_eq!(
            observed_host_check(native::Observation::NotApplicable),
            HostCheck::NotEvaluated
        );
        assert_eq!(
            observed_host_check(native::Observation::Unavailable(denied)),
            HostCheck::Failed
        );
        assert_eq!(
            observed_host_check(native::Observation::Observed(())),
            HostCheck::Passed
        );
    }

    #[test]
    fn capabilities_native_operation_mapping_does_not_conflate_operations_or_lanes() {
        for lane in [
            native::NativeLane::KvmX86_64,
            native::NativeLane::KvmArm64GicV3,
            native::NativeLane::HvfArm64GicV3,
            native::NativeLane::Unsupported,
        ] {
            let operations = native::NativeLiveOperations::for_lane(lane);
            for operation in LiveOperation::ALL {
                assert_eq!(
                    native_primitive(operation, &operations),
                    lane == native::NativeLane::KvmX86_64
                        || (operation == LiveOperation::Pause
                            && lane != native::NativeLane::Unsupported)
                );
            }
        }
        for selected in LiveOperation::ALL {
            let mut operations =
                native::NativeLiveOperations::for_lane(native::NativeLane::Unsupported);
            let supported = native::NativeOperationSupport::Supported;
            match selected {
                LiveOperation::Pause => operations.pause = supported,
                LiveOperation::Capture => operations.capture = supported,
                LiveOperation::Restore => operations.restore = supported,
                LiveOperation::Fork => operations.fork = supported,
                LiveOperation::Incremental => operations.incremental = supported,
            }
            for operation in LiveOperation::ALL {
                assert_eq!(
                    native_primitive(operation, &operations),
                    operation == selected
                );
            }
        }
    }

    #[test]
    fn capabilities_native_primitives_do_not_grant_public_admission() {
        let compiled = compiled_build();
        for lane in [
            native::NativeLane::KvmX86_64,
            native::NativeLane::KvmArm64GicV3,
            native::NativeLane::HvfArm64GicV3,
        ] {
            let operations = native::NativeLiveOperations::for_lane(lane);
            for operation in LiveOperation::ALL {
                let native = native_primitive(operation, &operations);
                if !native {
                    continue;
                }
                let qualified = qualification_matches(
                    &compiled,
                    native_lane(lane).expect("recognized native lane"),
                    operation,
                    &[],
                );
                assert!(!qualified);
                for host in [admitted(), HostAdmission::not_evaluated()] {
                    let capability = evaluate(EvaluationFacts {
                        backend_allowed: true,
                        native,
                        delivered: false,
                        qualified,
                        host,
                    })
                    .expect("delivery refusal precedes host admission");
                    assert!(capability.native);
                    assert_eq!(
                        capability.availability,
                        LiveAvailability::Unsupported {
                            reason: LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
                        }
                    );
                }
                assert_eq!(
                    evaluate(EvaluationFacts {
                        backend_allowed: true,
                        native,
                        delivered: true,
                        qualified,
                        host: admitted(),
                    })
                    .expect("known host is still unqualified")
                    .availability,
                    LiveAvailability::Unsupported {
                        reason: LiveUnsupportedReason::new(LiveReasonCode::LaneNotQualified),
                    }
                );
            }
        }
    }

    #[test]
    fn capabilities_effective_profiles_only_narrow_support() {
        let profiles = [
            (
                EffectiveProfile {
                    virtiofs: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Virtiofs,
            ),
            (
                EffectiveProfile {
                    rosetta: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Rosetta,
            ),
            (
                EffectiveProfile {
                    tap: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Tap,
            ),
            (
                EffectiveProfile {
                    gpu: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Gpu,
            ),
            (
                EffectiveProfile {
                    nested: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Nested,
            ),
            (
                EffectiveProfile {
                    tee: true,
                    ..Default::default()
                },
                LiveDeviceSubject::Tee,
            ),
            (
                EffectiveProfile {
                    guest_rejection: Some("other-guest".into()),
                    ..Default::default()
                },
                LiveDeviceSubject::GuestProfile {
                    profile: "other-guest".into(),
                },
            ),
        ];
        for (profile, subject) in profiles {
            let subject_actual = profile.rejection();
            assert_eq!(subject_actual, Some(subject.clone()));
            let supported = vector(|_| LiveCapability {
                native: true,
                availability: LiveAvailability::Supported,
            });
            for operation in LiveOperation::ALL {
                assert_eq!(
                    narrow(supported.clone(), subject_actual.clone())
                        .get(operation)
                        .availability,
                    LiveAvailability::Unsupported {
                        reason: LiveUnsupportedReason::device(subject.clone())
                    }
                );
            }
            let refused = LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered);
            assert_eq!(narrow(refused.clone(), subject_actual), refused);
        }
        let config = crate::virt::VmConfig::builder("profile")
            .kernel("kernel")
            .mount(crate::virt::SharedDirectory {
                host_path: PathBuf::from("share"),
                tag: "ro".into(),
                read_only: true,
            })
            .build();
        assert_eq!(
            EffectiveProfile::from_config(&config).rejection(),
            Some(LiveDeviceSubject::Virtiofs)
        );
    }

    #[test]
    fn guest_admission_preserves_native_and_existing_refusal() {
        let mut baseline = LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered);
        baseline.pause = LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        };
        let rejected = narrow_for_guest(baseline.clone(), Some("generation-driver-unobserved"));
        assert!(rejected.pause.native);
        assert_eq!(
            rejected.pause.availability,
            LiveAvailability::Unsupported {
                reason: LiveUnsupportedReason::device(LiveDeviceSubject::GuestProfile {
                    profile: "generation-driver-unobserved".into(),
                }),
            }
        );
        assert_eq!(rejected.capture, baseline.capture);
        assert_eq!(narrow_for_guest(rejected.clone(), None), rejected);
        assert_eq!(narrow_for_guest(baseline.clone(), None), baseline);
    }

    #[test]
    fn capabilities_scenario_digest_and_bound() {
        assert_eq!(
            scenario_digest(b"{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert!(validate_scenario_bytes(b"{}", &scenario_digest(b"{}")).is_ok());
        assert!(validate_scenario_bytes(b"{}", &scenario_digest(b"{ }")).is_err());
        let large = vec![b' '; MAX_SCENARIO_BYTES + 1];
        assert!(validate_scenario_bytes(&large, &scenario_digest(&large)).is_err());
    }

    #[cfg(feature = "mock-backend")]
    #[test]
    fn capabilities_start_consumes_exact_frozen_scenario_without_rereading_path() {
        let host = vector(|_| LiveCapability {
            native: true,
            availability: LiveAvailability::Supported,
        });
        let scenario = test_utils::Scenario {
            live: Some(test_utils::LiveScenario {
                lane: LiveLane::HvfArm64,
                host: host.clone(),
                machine: None,
            }),
            forward: test_utils::ForwardScenario {
                park_timeout_ms: Some(123),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = scenario.to_json();
        let request = crate::start_request::VirtBackendRequest {
            kind: "mock".into(),
            scenario: Some(PathBuf::from("/does-not-exist/frozen-scenario.json")),
            scenario_digest: Some(scenario_digest(json.as_bytes())),
            scenario_json: Some(json),
        };
        let selected = ResolvedSelection::from_start(Some(&request)).expect("frozen selection");
        let report = selected.host_report().expect("host report");
        assert_eq!(report.backend, LiveBackend::Mock);
        assert_eq!(report.lane, LiveLane::HvfArm64);
        assert_eq!(report.live, host);
        assert_eq!(report.scenario_digest, request.scenario_digest);
        let mut config = crate::virt::VmConfig::builder("scenario")
            .kernel("kernel")
            .build();
        selected.configure_mock(&mut config);
        assert_eq!(config.park_timeout(), std::time::Duration::from_millis(123));
        assert_eq!(selected.machine_vector(report.live, &config), host);
        assert_eq!(config.mock().resolved_scenario.as_deref(), Some(&scenario));
        for missing in 0..3 {
            let mut incomplete = request.clone();
            match missing {
                0 => incomplete.scenario = None,
                1 => incomplete.scenario_json = None,
                _ => incomplete.scenario_digest = None,
            }
            assert!(ResolvedSelection::from_start(Some(&incomplete)).is_err());
        }
        let mut mismatched = request;
        mismatched.scenario_json = Some("{}".into());
        assert!(ResolvedSelection::from_start(Some(&mismatched)).is_err());
    }
}

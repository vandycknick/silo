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
/// Implemented end to end in this build.
const DELIVERED: &[LiveOperation] = &[
    LiveOperation::Pause,
    LiveOperation::Capture,
    LiveOperation::Restore,
    LiveOperation::Fork,
    LiveOperation::Incremental,
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
        "scenario exceeds {}",
        utils::format_storage_size(MAX_SCENARIO_BYTES as u64)
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
        "scenario exceeds {}",
        utils::format_storage_size(MAX_SCENARIO_BYTES as u64)
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
                "scenario exceeds {}",
                utils::format_storage_size(MAX_SCENARIO_BYTES as u64)
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
        let build_identity = build_identity();
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
            build_identity,
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

/// Informational monitor identity, not a state-format compatibility gate.
fn build_identity() -> String {
    format!(
        "v1:silo:{}:{}",
        env!("SILO_BUILD_TARGET"),
        env!("CARGO_PKG_VERSION")
    )
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

/// Independent product facts. Unknown host admission never becomes support.
#[derive(Clone, Copy)]
struct EvaluationFacts {
    backend_allowed: bool,
    native: bool,
    delivered: bool,
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
    } else if matches!(facts.host.lane, HostCheck::Failed) {
        Some(LiveReasonCode::HypervisorUnavailable)
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

    fn admitted() -> HostAdmission {
        HostAdmission {
            os_floor: HostCheck::Passed,
            hypervisor: HostCheck::Passed,
            lane: HostCheck::Passed,
        }
    }

    #[test]
    fn capabilities_native_delivery_and_host_admission_are_independent() {
        for bits in 0..8 {
            let capability = evaluate(EvaluationFacts {
                backend_allowed: true,
                native: bits & 1 != 0,
                delivered: bits & 2 != 0,
                host: if bits & 4 != 0 {
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
                bits == 7
            );
        }
    }

    #[test]
    fn capabilities_reason_precedence_and_every_closed_reason() {
        let base = EvaluationFacts {
            backend_allowed: true,
            native: true,
            delivered: true,
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
                    host: HostAdmission {
                        lane: HostCheck::Failed,
                        ..admitted()
                    },
                    ..base
                },
                LiveReasonCode::HypervisorUnavailable,
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

    #[test]
    fn capabilities_native_lanes_and_monitor_identity_are_not_source_bound() {
        for (native, public) in [
            (native::NativeLane::KvmX86_64, LiveLane::KvmX86_64),
            (native::NativeLane::KvmArm64GicV3, LiveLane::KvmArm64GicV3),
            (native::NativeLane::HvfArm64GicV3, LiveLane::HvfArm64),
        ] {
            assert_eq!(native_lane(native), Ok(public));
        }
        assert_eq!(
            native_lane(native::NativeLane::Unsupported),
            Err(UnsupportedNativeLane)
        );
        assert_eq!(
            build_identity(),
            format!(
                "v1:silo:{}:{}",
                env!("SILO_BUILD_TARGET"),
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(native::LIVE_STATE_SCHEMA, "silo.live-state/1");
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
    fn capabilities_native_primitives_support_delivered_operations_on_admitted_hosts() {
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
                for host in [admitted(), HostAdmission::not_evaluated()] {
                    let capability = evaluate(EvaluationFacts {
                        backend_allowed: true,
                        native,
                        delivered: false,
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
                        host: admitted(),
                    })
                    .expect("known host supports native operation")
                    .availability,
                    LiveAvailability::Supported
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

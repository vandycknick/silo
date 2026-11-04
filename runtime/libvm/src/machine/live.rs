//! Read-only run observation followed by pure, resource-free admission.
use std::path::PathBuf;

use vm_spec::live::{
    LiveAvailability, LiveMachineReport, LiveOperation, LiveReasonCode, LiveUnsupportedReason,
};

use crate::machine::{Machine, MachineRef, MachineRunId};
use crate::paths::LocalPaths;
use crate::runtime::RuntimeConfig;
use crate::store::models::{MachineConfig, MachineId, MachineState};
use crate::store::observation::ObservationStore;
use crate::LibVmError;

/// Evidence for exactly one observed monitor/run. No public constructor or
/// deserializer can turn a generic machine/host report into this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLiveObservation {
    machine_id: MachineId,
    report: LiveMachineReport,
}

impl MachineLiveObservation {
    pub fn report(&self) -> &LiveMachineReport {
        &self.report
    }
}

#[derive(Debug, Clone)]
pub struct LiveObservationReader {
    paths: LocalPaths,
    catalog: PathBuf,
}

impl LiveObservationReader {
    pub fn open(config: &RuntimeConfig) -> Result<Self, LibVmError> {
        let roots = config.observation_roots()?;
        let catalog = roots.state_db_path();
        Ok(Self {
            paths: LocalPaths::from_roots(roots),
            catalog,
        })
    }

    pub fn catalog_exists(&self) -> Result<bool, LibVmError> {
        match std::fs::symlink_metadata(&self.catalog) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(LibVmError::LiveObservation {
                reference: self.catalog.display().to_string(),
                message: error.to_string(),
            }),
        }
    }

    pub async fn observe(
        &self,
        reference: &MachineRef,
    ) -> Result<MachineLiveObservation, LibVmError> {
        let store = ObservationStore::open(&self.catalog).await?;
        let result = store.lookup(reference).await;
        store.close().await?;
        let (config, state) = result?;
        observe_run(&self.paths, config, state).await
    }
}

pub(crate) async fn observe_run(
    paths: &LocalPaths,
    config: MachineConfig,
    state: MachineState,
) -> Result<MachineLiveObservation, LibVmError> {
    if !state.status.is_running() {
        return Err(LibVmError::MachineNotRunning {
            reference: config.name,
        });
    }
    let run = state
        .run_id
        .as_deref()
        .ok_or_else(|| observation(&config.name, "catalog has no exact run identity"))?;
    validate_uuid(run).map_err(|message| observation(&config.name, message))?;
    let response = crate::supervisor::VmmClient::new(paths.machine(config.id).vmm_socket_path())
        .status()
        .await
        .map_err(|error| observation(&config.name, error.to_string()))?;
    let report = report_from_status(&response)?;
    bind_run(config.id, &config.name, run, report)
}

fn bind_run(
    machine_id: MachineId,
    reference: &str,
    expected_run: &str,
    report: LiveMachineReport,
) -> Result<MachineLiveObservation, LibVmError> {
    let reported_machine = report
        .machine_id
        .parse::<MachineId>()
        .map_err(|_| protocol("live report has invalid machine_id"))?;
    if reported_machine != machine_id {
        return Err(observation(reference, "monitor belongs to another machine"));
    }
    if report.run_id != expected_run {
        return Err(LibVmError::MachineStaleGeneration {
            reference: reference.to_string(),
            requested: MachineRunId::from_raw(expected_run.to_string()),
            current: Some(MachineRunId::from_raw(report.run_id)),
        });
    }
    Ok(MachineLiveObservation { machine_id, report })
}

/// Mandatory wire conversion and equality with the outer run fence. Kept
/// separate from catalog observation so inspect/stream conversions share it.
pub(crate) fn report_from_status(
    status: &protocol::v1::HostStatus,
) -> Result<LiveMachineReport, LibVmError> {
    let report: LiveMachineReport = status
        .live
        .clone()
        .ok_or_else(|| protocol("status.live is missing"))?
        .try_into()
        .map_err(protocol)?;
    report.validate().map_err(protocol)?;
    let machine = status
        .machine_id
        .as_deref()
        .ok_or_else(|| protocol("status.machine_id is missing"))?;
    let run = status
        .run_id
        .as_deref()
        .ok_or_else(|| protocol("status.run_id is missing"))?;
    let monitor = status
        .monitor
        .as_ref()
        .and_then(|monitor| monitor.instance_id.as_deref())
        .ok_or_else(|| protocol("status.monitor.instance_id is missing"))?;
    for (field, value) in [
        ("machine_id", machine),
        ("run_id", run),
        ("monitor.instance_id", monitor),
    ] {
        validate_uuid(value)
            .map_err(|message| protocol(format!("invalid status.{field}: {message}")))?;
    }
    if report.machine_id != machine || report.run_id != run || report.monitor_id != monitor {
        return Err(protocol(
            "live report differs from outer machine/run/monitor identity",
        ));
    }
    Ok(report)
}

pub fn require_live_operation(
    observation: &MachineLiveObservation,
    operation: LiveOperation,
) -> Result<(), LibVmError> {
    let report = observation.report();
    let reason = match &report.live.get(operation).availability {
        LiveAvailability::Unsupported { reason } => reason.clone(),
        LiveAvailability::Supported => LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
    };
    Err(LibVmError::LiveOperationUnsupported {
        operation,
        backend: report.backend,
        lane: report.lane,
        reason,
    })
}

impl Machine {
    pub async fn observe_live(&self) -> Result<MachineLiveObservation, LibVmError> {
        self.runtime()
            .observe_live(&MachineRef::id(self.machine_id()))
            .await
    }

    pub async fn pause(&self, observation: &MachineLiveObservation) -> Result<(), LibVmError> {
        self.require_exact_live(observation, LiveOperation::Pause)
    }

    pub async fn capture(&self, observation: &MachineLiveObservation) -> Result<(), LibVmError> {
        if observation.machine_id == self.machine_id()
            && matches!(
                self.runtime()
                    .machine_storage_record(self.machine_id())
                    .await?
                    .root,
                crate::MachineRoot::LinuxOverlay {
                    lower: crate::OverlayLower::FlatExt4 { .. },
                    ..
                }
            )
        {
            return Err(LibVmError::FlatOverlayPublicationUnsupported);
        }
        self.require_exact_live(observation, LiveOperation::Capture)
    }

    pub async fn fork_execution(
        &self,
        observation: &MachineLiveObservation,
        _name: Option<&str>,
    ) -> Result<(), LibVmError> {
        if observation.machine_id == self.machine_id()
            && matches!(
                self.runtime()
                    .machine_storage_record(self.machine_id())
                    .await?
                    .root,
                crate::MachineRoot::LinuxOverlay {
                    lower: crate::OverlayLower::FlatExt4 { .. },
                    ..
                }
            )
        {
            return Err(LibVmError::FlatOverlayPublicationUnsupported);
        }
        self.require_exact_live(observation, LiveOperation::Fork)
    }

    fn require_exact_live(
        &self,
        observation: &MachineLiveObservation,
        operation: LiveOperation,
    ) -> Result<(), LibVmError> {
        if observation.machine_id != self.machine_id() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".to_string(),
            });
        }
        require_live_operation(observation, operation)
    }
}

fn validate_uuid(value: &str) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(value).map_err(|error| error.to_string())?;
    if id.is_nil() || id.to_string() != value {
        return Err("run identity must be a canonical non-nil UUID".to_string());
    }
    Ok(())
}
fn observation(reference: &str, message: impl Into<String>) -> LibVmError {
    LibVmError::LiveObservation {
        reference: reference.to_string(),
        message: message.into(),
    }
}
fn protocol(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveProtocol {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::live::{bind_run, require_live_operation};
    use crate::LibVmError;
    use vm_spec::live::{
        LiveAvailability, LiveBackend, LiveCapabilityVector, LiveDeviceSubject, LiveLane,
        LiveMachineReport, LiveOperation, LiveReasonCode, LiveScope, LiveUnsupportedReason,
    };

    fn report() -> LiveMachineReport {
        LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            monitor_id: uuid::Uuid::new_v4().to_string(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live: LiveCapabilityVector::all_unsupported(LiveReasonCode::BackendExcluded),
        }
    }

    #[test]
    fn live_capabilities_catalog_snapshot_generation_is_not_retried_or_guessed() {
        let report = report();
        let expected = uuid::Uuid::new_v4().to_string();
        let actual = report.run_id.clone();
        let error = bind_run(
            report.machine_id.parse().unwrap(),
            "machine",
            &expected,
            report,
        )
        .unwrap_err();
        match error {
            LibVmError::MachineStaleGeneration {
                requested, current, ..
            } => {
                assert_eq!(requested.as_str(), expected);
                assert_eq!(current.unwrap().as_str(), actual);
            }
            error => panic!("wrong generation error: {error}"),
        }
    }

    #[test]
    fn live_capabilities_pure_refusal_preserves_subject_and_manager_delivery() {
        let mut report = report();
        report.live.pause.availability = LiveAvailability::Unsupported {
            reason: LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
        };
        report.live.capture.availability = LiveAvailability::Supported;
        report.live.capture.native = true;
        let observed = bind_run(
            report.machine_id.parse().unwrap(),
            "machine",
            &report.run_id.clone(),
            report,
        )
        .unwrap();
        for (operation, code, subject) in [
            (
                LiveOperation::Pause,
                LiveReasonCode::DeviceProfileRejected,
                Some(LiveDeviceSubject::Virtiofs),
            ),
            (LiveOperation::Capture, LiveReasonCode::NotDelivered, None),
        ] {
            match require_live_operation(&observed, operation).unwrap_err() {
                LibVmError::LiveOperationUnsupported {
                    operation: actual,
                    backend,
                    reason,
                    ..
                } => {
                    assert_eq!(actual, operation);
                    assert_eq!(backend, LiveBackend::Mock);
                    assert_eq!(reason.code, code);
                    assert_eq!(reason.subject, subject);
                }
                error => panic!("wrong refusal: {error}"),
            }
        }
    }
}

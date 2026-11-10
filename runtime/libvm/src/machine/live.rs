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
#[derive(Debug, Clone)]
pub struct MachineLiveObservation {
    machine_id: MachineId,
    report: LiveMachineReport,
    status: protocol::v1::HostStatus,
    pending_pause: bool,
}

impl MachineLiveObservation {
    pub fn report(&self) -> &LiveMachineReport {
        &self.report
    }

    pub(crate) fn machine_id(&self) -> MachineId {
        self.machine_id
    }

    /// New Pause requires capability admission; reconnecting an already durable
    /// exact Pause intent must not be stranded by a narrowed guest vector.
    pub fn require_pause_submission(&self) -> Result<(), LibVmError> {
        if self.pending_pause {
            Ok(())
        } else {
            require_live_operation(self, LiveOperation::Pause)
        }
    }

    pub(crate) fn with_pending_pause(
        mut self,
        pending: Option<crate::store::live_store::LiveCommandIntent>,
    ) -> Self {
        self.pending_pause = pending.is_some_and(|pending| {
            matches!(pending.command, vm_spec::lifecycle::LiveCommand::Pause(_))
                && pending.command.envelope().machine_id.as_str() == self.report.machine_id
                && pending.command.envelope().run_id.as_str() == self.report.run_id
                && pending.report.monitor_id == self.report.monitor_id
                && pending.report.topology_revision == self.report.topology_revision
        });
        self
    }

    pub fn lifecycle(&self) -> Result<vm_spec::lifecycle::LiveLifecycle, LibVmError> {
        self.status
            .lifecycle
            .clone()
            .ok_or_else(|| protocol("status.lifecycle is missing"))?
            .try_into()
            .map_err(protocol)
    }

    pub fn state(&self) -> Result<vm_spec::lifecycle::VmLifecycleState, LibVmError> {
        let state = self
            .status
            .vm
            .as_ref()
            .and_then(|vm| vm.state)
            .ok_or_else(|| protocol("status.vm.state is missing"))?;
        protocol::lifecycle::vm_state_from_wire(Some(state)).map_err(protocol)
    }

    /// Hypervisor-free admission fixture: exact report plus wire state and
    /// lifecycle, exactly as a monitor status carries them.
    #[cfg(test)]
    pub(crate) fn for_test(
        report: LiveMachineReport,
        state: vm_spec::lifecycle::VmLifecycleState,
        lifecycle: vm_spec::lifecycle::LiveLifecycle,
    ) -> Self {
        let machine_id = report.machine_id.parse().expect("test machine identity");
        Self {
            machine_id,
            status: protocol::v1::HostStatus {
                vm: Some(protocol::v1::VmSnapshot {
                    state: Some(protocol::v1::VmState::from(state) as i32),
                    ..Default::default()
                }),
                lifecycle: Some(lifecycle.into()),
                ..Default::default()
            },
            report,
            pending_pause: false,
        }
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
        let result = async {
            let (config, state) = store.lookup(reference).await?;
            let pending = store
                .pending_pause(config.id, state.run_id.as_deref())
                .await?;
            Ok::<_, LibVmError>((config, state, pending))
        }
        .await;
        store.close().await?;
        let (config, state, pending) = result?;
        Ok(observe_run(&self.paths, config, state)
            .await?
            .with_pending_pause(pending))
    }
}

pub(crate) async fn observe_run(
    paths: &LocalPaths,
    config: MachineConfig,
    state: MachineState,
) -> Result<MachineLiveObservation, LibVmError> {
    if !state.status.is_live() && state.vmm_pid.is_none() {
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
    let mut observation = bind_run(config.id, &config.name, run, report)?;
    observation.status = response;
    observation
        .lifecycle()?
        .validate_for(observation.state()?)
        .map_err(protocol)?;
    Ok(observation)
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
    Ok(MachineLiveObservation {
        machine_id,
        report,
        status: Default::default(),
        pending_pause: false,
    })
}

pub(crate) fn projection_from_status(
    status: &protocol::v1::HostStatus,
) -> Result<crate::MachineLifecycle, LibVmError> {
    let report = report_from_status(status)?;
    let machine_id = report
        .machine_id
        .parse()
        .map_err(|_| protocol("invalid lifecycle machine identity"))?;
    crate::machine::live_operations::projection(&MachineLiveObservation {
        machine_id,
        report,
        status: status.clone(),
        pending_pause: false,
    })
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

/// Manager admission for source-run Pause, Capture, Fork and Incremental commands. Restore
/// has a separate checkpoint-construction entrypoint. The monitor vector
/// remains the capability authority.
pub fn require_live_operation(
    observation: &MachineLiveObservation,
    operation: LiveOperation,
) -> Result<(), LibVmError> {
    let report = observation.report();
    let reason = match &report.live.get(operation).availability {
        LiveAvailability::Unsupported { reason } => reason.clone(),
        LiveAvailability::Supported
            if matches!(
                operation,
                LiveOperation::Pause
                    | LiveOperation::Capture
                    | LiveOperation::Fork
                    | LiveOperation::Incremental
            ) =>
        {
            return Ok(())
        }
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

    pub async fn pause(
        &self,
        observation: &MachineLiveObservation,
    ) -> Result<crate::MachineLifecycle, LibVmError> {
        self.pause_and_wait(observation).await
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
        report.live.fork.availability = LiveAvailability::Supported;
        report.live.fork.native = true;
        report.live.restore.availability = LiveAvailability::Supported;
        report.live.restore.native = true;
        report.live.incremental.availability = LiveAvailability::Supported;
        report.live.incremental.native = true;
        let observed = bind_run(
            report.machine_id.parse().unwrap(),
            "machine",
            &report.run_id.clone(),
            report,
        )
        .unwrap();
        // The monitor's Supported capture bit is admitted by the manager.
        assert!(require_live_operation(&observed, LiveOperation::Capture).is_ok());
        assert!(require_live_operation(&observed, LiveOperation::Incremental).is_ok());
        for (operation, code, subject) in [
            (
                LiveOperation::Pause,
                LiveReasonCode::DeviceProfileRejected,
                Some(LiveDeviceSubject::Virtiofs),
            ),
            (LiveOperation::Restore, LiveReasonCode::NotDelivered, None),
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
    #[test]
    fn pause_recovery_witness_never_grants_a_new_pause_or_foreign_monitor() {
        use vm_spec::lifecycle::{LiveCommand, LiveCommandEnvelope, LiveId, PauseCommand};
        let report = report();
        let mut observed = bind_run(
            report.machine_id.parse().unwrap(),
            "machine",
            &report.run_id.clone(),
            report.clone(),
        )
        .unwrap();
        let intent = crate::store::live_store::LiveCommandIntent {
            report: report.clone(),
            command: LiveCommand::Pause(PauseCommand {
                envelope: LiveCommandEnvelope {
                    machine_id: LiveId::parse(&report.machine_id).unwrap(),
                    run_id: LiveId::parse(&report.run_id).unwrap(),
                    request_id: LiveId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
                },
            }),
        };
        observed = observed.with_pending_pause(Some(intent.clone()));
        assert!(observed.require_pause_submission().is_ok());
        assert!(require_live_operation(&observed, LiveOperation::Pause).is_err());
        let mut foreign = intent;
        foreign.report.monitor_id = uuid::Uuid::new_v4().to_string();
        observed = observed.with_pending_pause(Some(foreign));
        assert!(observed.require_pause_submission().is_err());
    }
}

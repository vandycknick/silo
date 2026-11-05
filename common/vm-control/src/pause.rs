//! Strict pause authority and historical-result transport, without JSON envelopes.
use crate::{invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;
use std::num::NonZeroU64;
use vm_spec::lifecycle as d;

macro_rules! enumeration {
    ($to:ident, $from:ident, $domain:ident, $wire:ident, [$($variant:ident),+ $(,)?]) => {
        fn $to(value: d::$domain) -> i32 {
            match value { $(d::$domain::$variant => w::$wire::$variant as i32),+ }
        }
        fn $from(value: i32) -> Result<d::$domain, ConversionError> {
            match w::$wire::try_from(value) {
                $(Ok(w::$wire::$variant) => Ok(d::$domain::$variant),)+
                _ => Err(invalid("lifecycle.enum", "unknown or unspecified enum")),
            }
        }
    };
}
enumeration!(
    state_to,
    state_from,
    VmLifecycleState,
    VmState,
    [
        Starting,
        Running,
        Stopping,
        Stopped,
        Failed,
        Pausing,
        Paused,
        Capturing,
        Restoring,
        Activating,
        ActivationFailed,
        Error
    ]
);
enumeration!(
    stage_to,
    stage_from,
    LiveStage,
    LiveStage,
    [
        MonitorDrain,
        GuestFreeze,
        NativePause,
        PauseFailed,
        RollbackThaw,
        CancelNative,
        CancelThaw,
        ResumeNative,
        ResumeClock,
        ResumeHandshake,
        ResumeThaw,
        Readiness,
        RecoveryFreeze,
        RecoveryPause,
        Admission
    ]
);
enumeration!(
    command_to,
    command_from,
    LiveCommandKind,
    LiveCommandKind,
    [
        Pause,
        Resume,
        GetOperation,
        CancelOperation,
        Capture,
        ReleaseCapture
    ]
);
enumeration!(
    failure_code_to,
    failure_code_from,
    LiveFailureCode,
    LiveFailureCode,
    [
        DrainTimedOut,
        GuestUnavailable,
        GuestIdentityMismatch,
        FreezeFailed,
        FreezeTimedOut,
        NativePauseFailed,
        NativeUncertain,
        Cancelled,
        NativeRollbackFailed,
        ThawFailed,
        ThawUnacknowledged,
        NativeResumeFailed,
        ClockGenerationFailed,
        HandshakeFailed,
        ReadinessFailed,
        RecoveryFreezeFailed,
        RecoveryPauseFailed,
        WorkerLost,
        Stopped,
        DeadlineExceeded
    ]
);
enumeration!(
    guest_state_to,
    guest_state_from,
    GuestLifecycleState,
    GuestLifecycleState,
    [
        Running,
        Freezing,
        Frozen,
        Activating,
        ActivatedFrozen,
        Thawing,
        Thawed,
        FreezeFailed,
        ActivationFailed,
        Faulted
    ]
);
enumeration!(
    operation_kind_to,
    operation_kind_from,
    OperationKind,
    OperationKind,
    [Pause, Capture]
);
fn id(value: String) -> Result<d::LiveId, ConversionError> {
    d::LiveId::parse(&value).map_err(|_| invalid("lifecycle.id", "noncanonical or nil UUID"))
}
fn nonzero(value: u64) -> Result<NonZeroU64, ConversionError> {
    NonZeroU64::new(value)
        .ok_or_else(|| invalid("lifecycle.generation", "zero generation or epoch"))
}
fn diagnostic(value: Option<String>) -> Result<Option<d::Diagnostic>, ConversionError> {
    value
        .map(|value| {
            value
                .try_into()
                .map_err(|_| invalid("lifecycle.diagnostic", "oversized diagnostic"))
        })
        .transpose()
}
fn token_to(value: &d::PauseToken) -> w::PauseToken {
    w::PauseToken {
        machine_id: value.machine_id.to_string(),
        run_id: value.run_id.to_string(),
        generation: value.generation.get(),
        owner: Some(w::PauseOwner {
            owner: Some(match &value.owner {
                d::PauseOwner::User => w::pause_owner::Owner::User(()),
                d::PauseOwner::Capture { operation_id } => {
                    w::pause_owner::Owner::CaptureOperationId(operation_id.to_string())
                }
            }),
        }),
    }
}
fn token_from(value: w::PauseToken) -> Result<d::PauseToken, ConversionError> {
    Ok(d::PauseToken {
        machine_id: id(value.machine_id)?,
        run_id: id(value.run_id)?,
        generation: nonzero(value.generation)?,
        owner: match required(
            required(value.owner, "pause.owner")?.owner,
            "pause.owner.kind",
        )? {
            w::pause_owner::Owner::User(()) => d::PauseOwner::User,
            w::pause_owner::Owner::CaptureOperationId(value) => d::PauseOwner::Capture {
                operation_id: id(value)?,
            },
        },
    })
}
fn current_to(value: &d::CurrentPause) -> w::CurrentPause {
    w::CurrentPause {
        token: Some(token_to(&value.token)),
        operation_id: value.operation_id.to_string(),
        freeze_epoch: value.freeze_epoch.get(),
    }
}
fn current_from(value: w::CurrentPause) -> Result<d::CurrentPause, ConversionError> {
    Ok(d::CurrentPause {
        token: token_from(required(value.token, "pause.token")?)?,
        operation_id: id(value.operation_id)?,
        freeze_epoch: nonzero(value.freeze_epoch)?,
    })
}
fn guest_to(value: &d::GuestFreezeObservation) -> w::GuestFreezeObservation {
    w::GuestFreezeObservation {
        state: guest_state_to(value.state),
        freeze_epoch: value.freeze_epoch.map(NonZeroU64::get),
        workload_roots: value.workload_roots.clone(),
        observed_frozen_roots: value.observed_frozen_roots.clone(),
        rollback_succeeded: value.rollback_succeeded,
        failure: value.failure.as_ref().map(ToString::to_string),
    }
}
fn guest_from(
    value: w::GuestFreezeObservation,
) -> Result<d::GuestFreezeObservation, ConversionError> {
    let result = d::GuestFreezeObservation {
        state: guest_state_from(value.state)?,
        freeze_epoch: value.freeze_epoch.map(nonzero).transpose()?,
        workload_roots: value.workload_roots,
        observed_frozen_roots: value.observed_frozen_roots,
        rollback_succeeded: value.rollback_succeeded,
        failure: diagnostic(value.failure)?,
    };
    result
        .validate()
        .map_err(|_| invalid("lifecycle.guest", "invalid freeze observation"))?;
    Ok(result)
}
fn failure_to(value: &d::LiveFailure) -> w::LiveFailure {
    w::LiveFailure {
        code: failure_code_to(value.code),
        stage: stage_to(value.stage),
        message: value.message.as_ref().map(ToString::to_string),
        guest: value.guest.as_ref().map(guest_to),
    }
}
fn failure_from(value: w::LiveFailure) -> Result<d::LiveFailure, ConversionError> {
    Ok(d::LiveFailure {
        code: failure_code_from(value.code)?,
        stage: stage_from(value.stage)?,
        message: diagnostic(value.message)?,
        guest: value.guest.map(guest_from).transpose()?,
    })
}
pub fn lifecycle_to_wire(value: &d::LiveLifecycle) -> w::LiveLifecycle {
    w::LiveLifecycle {
        current_pause: value.current_pause.as_ref().map(current_to),
        activity: value.activity.as_ref().map(|value| w::LiveActivity {
            operation_id: value.operation_id.to_string(),
            request_id: value.request_id.to_string(),
            command: command_to(value.command),
            stage: stage_to(value.stage),
        }),
        error: value.error.as_ref().map(failure_to),
    }
}
pub fn lifecycle_from_wire(value: w::LiveLifecycle) -> Result<d::LiveLifecycle, ConversionError> {
    Ok(d::LiveLifecycle {
        current_pause: value.current_pause.map(current_from).transpose()?,
        activity: value
            .activity
            .map(|value| {
                Ok::<_, ConversionError>(d::LiveActivity {
                    operation_id: id(value.operation_id)?,
                    request_id: id(value.request_id)?,
                    command: command_from(value.command)?,
                    stage: stage_from(value.stage)?,
                })
            })
            .transpose()?,
        error: value.error.map(failure_from).transpose()?,
    })
}
fn operation_to(value: &d::LiveOperationRecord) -> w::LiveOperationRecord {
    w::LiveOperationRecord {
        operation_id: value.operation_id.to_string(),
        kind: operation_kind_to(value.kind),
        outcome: Some(match &value.outcome {
            d::OperationOutcome::InProgress => w::live_operation_record::Outcome::InProgress(()),
            d::OperationOutcome::Failed { failure } => {
                w::live_operation_record::Outcome::Failed(failure_to(failure))
            }
            d::OperationOutcome::Succeeded { pause } => {
                w::live_operation_record::Outcome::Succeeded(w::PauseEstablished {
                    token: Some(token_to(&pause.token)),
                    freeze_epoch: pause.freeze_epoch.get(),
                    guest: Some(guest_to(&pause.guest)),
                    capture_eligible: pause.capture_eligible,
                })
            }
        }),
    }
}
fn operation_from(
    value: w::LiveOperationRecord,
) -> Result<d::LiveOperationRecord, ConversionError> {
    let result = d::LiveOperationRecord {
        operation_id: id(value.operation_id)?,
        kind: operation_kind_from(value.kind)?,
        outcome: match required(value.outcome, "operation.outcome")? {
            w::live_operation_record::Outcome::InProgress(()) => d::OperationOutcome::InProgress,
            w::live_operation_record::Outcome::Failed(value) => d::OperationOutcome::Failed {
                failure: failure_from(value)?,
            },
            w::live_operation_record::Outcome::Succeeded(value) => d::OperationOutcome::Succeeded {
                pause: d::PauseEstablished {
                    token: token_from(required(value.token, "operation.token")?)?,
                    freeze_epoch: nonzero(value.freeze_epoch)?,
                    guest: guest_from(required(value.guest, "operation.guest")?)?,
                    capture_eligible: value.capture_eligible,
                },
            },
        },
    };
    result
        .validate()
        .map_err(|_| invalid("operation", "invalid operation result"))?;
    Ok(result)
}
pub fn projection_to_wire(
    value: &libvm::MachineLifecycle,
) -> Result<w::MachineLifecycle, ConversionError> {
    validate_projection(value)?;
    Ok(w::MachineLifecycle {
        report: Some(crate::live::machine_to_wire(&value.report)?),
        state: state_to(value.state),
        lifecycle: Some(lifecycle_to_wire(&value.lifecycle)),
        operation: value.operation.as_ref().map(operation_to),
    })
}
pub fn projection_from_wire(
    value: w::MachineLifecycle,
) -> Result<libvm::MachineLifecycle, ConversionError> {
    let result = libvm::MachineLifecycle {
        report: crate::live::machine_from_wire(required(value.report, "lifecycle.report")?)?,
        state: state_from(value.state)?,
        lifecycle: lifecycle_from_wire(required(value.lifecycle, "lifecycle")?)?,
        operation: value.operation.map(operation_from).transpose()?,
    };
    validate_projection(&result)?;
    Ok(result)
}
fn validate_projection(value: &libvm::MachineLifecycle) -> Result<(), ConversionError> {
    value
        .report
        .validate()
        .map_err(|_| invalid("lifecycle.report", "invalid evidence"))?;
    value
        .lifecycle
        .validate_for(value.state)
        .map_err(|_| invalid("lifecycle", "invalid state projection"))?;
    if let Some(pause) = &value.lifecycle.current_pause {
        if pause.token.machine_id.as_str() != value.report.machine_id
            || pause.token.run_id.as_str() != value.report.run_id
        {
            return Err(invalid("lifecycle.pause", "foreign token"));
        }
    }
    if let Some(operation) = &value.operation {
        operation
            .validate()
            .map_err(|_| invalid("lifecycle.operation", "invalid operation"))?;
    }
    Ok(())
}

pub(crate) fn validate_monitor_lifecycle(
    lifecycle: &d::LiveLifecycle,
    state: i32,
    ready: bool,
    report: &vm_spec::live::LiveMachineReport,
) -> Result<(), ConversionError> {
    let state = state_from(state)?;
    lifecycle
        .validate_for(state)
        .map_err(|_| invalid("monitor.lifecycle", "inconsistent state projection"))?;
    if ready && !state.readiness_eligible() {
        return Err(invalid("monitor.readiness", "ready outside Running"));
    }
    if let Some(pause) = &lifecycle.current_pause {
        if pause.token.machine_id.as_str() != report.machine_id
            || pause.token.run_id.as_str() != report.run_id
        {
            return Err(invalid("monitor.lifecycle", "foreign pause token"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pause::*;
    #[test]
    fn pause_daemon_preserves_historical_and_current_authority_and_rejects_foreign() {
        let machine = d::LiveId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let run = d::LiveId::parse("22222222-2222-4222-8222-222222222222").unwrap();
        let operation = d::LiveId::parse("33333333-3333-4333-8333-333333333333").unwrap();
        let original = d::PauseToken {
            machine_id: machine.clone(),
            run_id: run.clone(),
            generation: NonZeroU64::new(1).unwrap(),
            owner: d::PauseOwner::User,
        };
        let mut current = original.clone();
        current.generation = NonZeroU64::new(2).unwrap();
        let value = libvm::MachineLifecycle {
            report: vm_spec::live::LiveMachineReport {
                schema_version: 1,
                scope: vm_spec::live::LiveScope::Machine,
                machine_id: machine.to_string(),
                run_id: run.to_string(),
                monitor_id: "44444444-4444-4444-8444-444444444444".into(),
                backend: vm_spec::live::LiveBackend::Mock,
                lane: vm_spec::live::LiveLane::NotApplicable,
                topology_revision: 1,
                live: vm_spec::live::LiveCapabilityVector::all_unsupported(
                    vm_spec::live::LiveReasonCode::NotDelivered,
                ),
            },
            state: d::VmLifecycleState::Paused,
            lifecycle: d::LiveLifecycle {
                current_pause: Some(d::CurrentPause {
                    token: current,
                    operation_id: operation.clone(),
                    freeze_epoch: NonZeroU64::new(2).unwrap(),
                }),
                ..Default::default()
            },
            operation: Some(d::LiveOperationRecord {
                operation_id: operation,
                kind: d::OperationKind::Pause,
                outcome: d::OperationOutcome::Succeeded {
                    pause: d::PauseEstablished {
                        token: original,
                        freeze_epoch: NonZeroU64::new(1).unwrap(),
                        guest: d::GuestFreezeObservation {
                            state: d::GuestLifecycleState::Frozen,
                            freeze_epoch: NonZeroU64::new(1),
                            workload_roots: vec!["/workloads".into()],
                            observed_frozen_roots: vec!["/workloads".into()],
                            rollback_succeeded: None,
                            failure: None,
                        },
                        capture_eligible: true,
                    },
                },
            }),
        };
        assert_eq!(
            projection_from_wire(projection_to_wire(&value).unwrap()).unwrap(),
            value
        );
        let mut foreign = projection_to_wire(&value).unwrap();
        foreign
            .lifecycle
            .as_mut()
            .unwrap()
            .current_pause
            .as_mut()
            .unwrap()
            .token
            .as_mut()
            .unwrap()
            .run_id = "55555555-5555-4555-8555-555555555555".into();
        assert!(projection_from_wire(foreign).is_err());
        let mut absent = projection_to_wire(&value).unwrap();
        absent.lifecycle.as_mut().unwrap().current_pause = None;
        assert!(projection_from_wire(absent).is_err());
    }
    #[test]
    fn pause_daemon_lifecycle_enum_and_boundary_validation() {
        for state in d::VmLifecycleState::ALL {
            assert_eq!(state_from(state_to(*state)).unwrap(), *state);
        }
        for stage in d::LiveStage::ALL {
            assert_eq!(stage_from(stage_to(*stage)).unwrap(), *stage);
        }
        for code in d::LiveFailureCode::ALL {
            assert_eq!(failure_code_from(failure_code_to(*code)).unwrap(), *code);
        }
        assert!(state_from(0).is_err());
        assert!(stage_from(i32::MAX).is_err());
        assert!(nonzero(0).is_err());
        assert!(id("00000000-0000-0000-0000-000000000000".into()).is_err());
    }
}

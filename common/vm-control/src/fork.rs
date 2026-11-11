//! Strict daemon transport of live fork operations. The caller-selected
//! operation UUID is the exact replay key, and every accepted result names
//! each requested child with its reserved identities, in request order.
use std::collections::HashSet;
use std::num::NonZeroU32;

use libvm::{
    ForkCaptureOutcome, ForkChildOutcome, ForkChildResult, ForkDestination, ForkFailurePhase,
    ForkSourceOutcome, ForkStage, LiveForkChild, LiveForkOptions, LiveForkResult,
};
use silod_spec::daemon::v1 as w;
use vm_spec::capture::Sha256Digest;
use vm_spec::lifecycle::{Diagnostic, LiveId};

use crate::{invalid, required, ConversionError};

/// Canonical lowercase hyphenated, non-nil UUID text.
fn canonical_uuid(value: &str, field: &'static str) -> Result<uuid::Uuid, ConversionError> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| invalid(field, "invalid UUID"))?;
    if id.is_nil() || id.hyphenated().to_string() != value {
        return Err(invalid(field, "noncanonical or nil UUID"));
    }
    Ok(id)
}

fn uuid_to_wire(value: uuid::Uuid, field: &'static str) -> Result<String, ConversionError> {
    if value.is_nil() {
        return Err(invalid(field, "nil UUID"));
    }
    Ok(value.hyphenated().to_string())
}

fn machine_id(value: &str, field: &'static str) -> Result<libvm::MachineId, ConversionError> {
    let id: libvm::MachineId = value
        .parse()
        .map_err(|_| invalid(field, "invalid machine identity"))?;
    if uuid::Uuid::from(id).is_nil() || id.to_string() != value {
        return Err(invalid(field, "noncanonical or nil machine identity"));
    }
    Ok(id)
}

fn run_id(value: &str, field: &'static str) -> Result<libvm::MachineRunId, ConversionError> {
    canonical_uuid(value, field)?;
    value
        .parse()
        .map_err(|_| invalid(field, "invalid run identity"))
}

fn diagnostic(value: String, field: &'static str) -> Result<Diagnostic, ConversionError> {
    Diagnostic::try_from(value).map_err(|_| invalid(field, "oversized diagnostic"))
}

fn child_name(value: &str) -> Result<(), ConversionError> {
    libvm::validate_new_machine_name(value)
        .map_err(|_| invalid("fork.child.name", "invalid machine name"))
}

pub fn operation_to_wire(value: uuid::Uuid) -> Result<w::ForkOperationRef, ConversionError> {
    Ok(w::ForkOperationRef {
        operation_id: uuid_to_wire(value, "fork.operation_id")?,
    })
}

pub fn operation_from_wire(value: w::ForkOperationRef) -> Result<uuid::Uuid, ConversionError> {
    canonical_uuid(&value.operation_id, "fork.operation_id")
}

fn destination_to_wire(value: &ForkDestination) -> w::ForkDestination {
    w::ForkDestination {
        forwards: value
            .forwards
            .iter()
            .map(crate::values::forward_to_wire)
            .collect(),
        guest_publish: value
            .guest_publish
            .map(|publish| crate::values::publish_to_wire(publish.bind)),
    }
}

fn destination_from_wire(value: w::ForkDestination) -> Result<ForkDestination, ConversionError> {
    Ok(ForkDestination {
        forwards: value
            .forwards
            .into_iter()
            .map(crate::values::forward_from_wire)
            .collect::<Result<_, _>>()?,
        guest_publish: value
            .guest_publish
            .map(|bind| {
                crate::values::publish_from_wire(bind).map(|bind| libvm::GuestPublish { bind })
            })
            .transpose()?,
    })
}

fn child_to_wire(value: &LiveForkChild) -> Result<w::LiveForkChild, ConversionError> {
    Ok(w::LiveForkChild {
        name: value.name.clone(),
        activation_hook: value
            .activation_hook
            .as_ref()
            .map(crate::stopped::hook_to_wire)
            .transpose()?,
        destination: Some(destination_to_wire(&value.destination)),
    })
}

fn child_from_wire(value: w::LiveForkChild) -> Result<LiveForkChild, ConversionError> {
    child_name(&value.name)?;
    Ok(LiveForkChild {
        name: value.name,
        activation_hook: value
            .activation_hook
            .map(crate::stopped::hook_from_wire)
            .transpose()?,
        destination: destination_from_wire(required(value.destination, "fork.child.destination")?)?,
    })
}

/// Encodes a live fork request. The encoded value is decoded again so a
/// sender can never emit what a receiver would reject.
pub fn request_to_wire(
    machine: &libvm::MachineRef,
    value: &LiveForkOptions,
) -> Result<w::LiveForkRequest, ConversionError> {
    let request = w::LiveForkRequest {
        machine: Some(crate::lifecycle::reference_to_wire(machine)?),
        operation_id: uuid_to_wire(value.operation_id, "fork.operation_id")?,
        children: value
            .children
            .iter()
            .map(child_to_wire)
            .collect::<Result<_, _>>()?,
        max_children: value.max_children.get(),
        resume_policy: crate::capture::resume_policy_to_wire(value.resume_policy),
        policy: crate::capture::policy_to_wire(value.policy),
        dirty_crossover_percent: u32::from(value.dirty_crossover_percent),
    };
    request_from_wire(request.clone())?;
    Ok(request)
}

pub fn request_from_wire(
    value: w::LiveForkRequest,
) -> Result<(libvm::MachineRef, LiveForkOptions), ConversionError> {
    let machine = crate::lifecycle::reference_from_wire(required(value.machine, "fork.machine")?)?;
    let max_children = NonZeroU32::new(value.max_children)
        .ok_or_else(|| invalid("fork.max_children", "expected a nonzero maximum"))?;
    if value.children.is_empty() {
        return Err(invalid("fork.children", "expected at least one child"));
    }
    if u32::try_from(value.children.len()).map_or(true, |count| count > max_children.get()) {
        return Err(invalid(
            "fork.children",
            "child count exceeds the explicit maximum",
        ));
    }
    let children = value
        .children
        .into_iter()
        .map(child_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let mut names = HashSet::with_capacity(children.len());
    if !children
        .iter()
        .all(|child| names.insert(child.name.as_str()))
    {
        return Err(invalid("fork.children", "duplicate child name"));
    }
    let options = LiveForkOptions {
        operation_id: canonical_uuid(&value.operation_id, "fork.operation_id")?,
        children,
        max_children,
        resume_policy: crate::capture::resume_policy_from_wire(value.resume_policy)?,
        policy: crate::capture::policy_from_wire(value.policy)?,
        dirty_crossover_percent: crate::capture::crossover_from_wire(
            value.dirty_crossover_percent,
        )?,
    };
    options
        .validate()
        .map_err(|_| invalid("fork.options", "invalid live fork options"))?;
    Ok((machine, options))
}

fn stage_to_wire(value: ForkStage) -> i32 {
    (match value {
        ForkStage::Admitted => w::ForkStage::Admitted,
        ForkStage::Capturing => w::ForkStage::Capturing,
        ForkStage::Restoring => w::ForkStage::Restoring,
        ForkStage::Settling => w::ForkStage::Settling,
        ForkStage::Finished => w::ForkStage::Finished,
    }) as i32
}

fn stage_from_wire(value: i32) -> Result<ForkStage, ConversionError> {
    match w::ForkStage::try_from(value) {
        Ok(w::ForkStage::Admitted) => Ok(ForkStage::Admitted),
        Ok(w::ForkStage::Capturing) => Ok(ForkStage::Capturing),
        Ok(w::ForkStage::Restoring) => Ok(ForkStage::Restoring),
        Ok(w::ForkStage::Settling) => Ok(ForkStage::Settling),
        Ok(w::ForkStage::Finished) => Ok(ForkStage::Finished),
        _ => Err(invalid("fork.stage", "unknown or unspecified enum")),
    }
}

fn phase_to_wire(value: ForkFailurePhase) -> i32 {
    (match value {
        ForkFailurePhase::Capture => w::ForkFailurePhase::Capture,
        ForkFailurePhase::Construction => w::ForkFailurePhase::Construction,
        ForkFailurePhase::Activation => w::ForkFailurePhase::Activation,
        ForkFailurePhase::Cleanup => w::ForkFailurePhase::Cleanup,
    }) as i32
}

fn phase_from_wire(value: i32) -> Result<ForkFailurePhase, ConversionError> {
    match w::ForkFailurePhase::try_from(value) {
        Ok(w::ForkFailurePhase::Capture) => Ok(ForkFailurePhase::Capture),
        Ok(w::ForkFailurePhase::Construction) => Ok(ForkFailurePhase::Construction),
        Ok(w::ForkFailurePhase::Activation) => Ok(ForkFailurePhase::Activation),
        Ok(w::ForkFailurePhase::Cleanup) => Ok(ForkFailurePhase::Cleanup),
        _ => Err(invalid(
            "fork.child.failure.phase",
            "unknown or unspecified enum",
        )),
    }
}

fn capture_to_wire(value: &ForkCaptureOutcome) -> w::ForkCaptureOutcome {
    use w::fork_capture_outcome::Outcome;
    w::ForkCaptureOutcome {
        outcome: Some(match value {
            ForkCaptureOutcome::Pending => Outcome::Pending(()),
            ForkCaptureOutcome::Sealed { cut_id } => Outcome::SealedCutId(cut_id.to_string()),
            ForkCaptureOutcome::Failed { diagnostic } => Outcome::Failed(diagnostic.to_string()),
            ForkCaptureOutcome::Abandoned { diagnostic } => {
                Outcome::Abandoned(diagnostic.to_string())
            }
        }),
    }
}

fn capture_from_wire(value: w::ForkCaptureOutcome) -> Result<ForkCaptureOutcome, ConversionError> {
    use w::fork_capture_outcome::Outcome;
    Ok(match required(value.outcome, "fork.capture.outcome")? {
        Outcome::Pending(()) => ForkCaptureOutcome::Pending,
        Outcome::SealedCutId(cut) => ForkCaptureOutcome::Sealed {
            cut_id: cut
                .parse::<Sha256Digest>()
                .map_err(|_| invalid("fork.capture.sealed_cut_id", "invalid cut digest"))?,
        },
        Outcome::Failed(value) => ForkCaptureOutcome::Failed {
            diagnostic: diagnostic(value, "fork.capture.failed")?,
        },
        Outcome::Abandoned(value) => ForkCaptureOutcome::Abandoned {
            diagnostic: diagnostic(value, "fork.capture.abandoned")?,
        },
    })
}

fn source_to_wire(value: &ForkSourceOutcome) -> w::ForkSourceOutcome {
    use w::fork_source_outcome::Outcome;
    w::ForkSourceOutcome {
        outcome: Some(match value {
            ForkSourceOutcome::Pending => Outcome::Pending(()),
            ForkSourceOutcome::Unchanged => Outcome::Unchanged(()),
            ForkSourceOutcome::Resumed => Outcome::Resumed(()),
            ForkSourceOutcome::Preserved => Outcome::Preserved(()),
            ForkSourceOutcome::ResumeFailed { diagnostic } => {
                Outcome::ResumeFailed(diagnostic.to_string())
            }
            ForkSourceOutcome::Unknown { diagnostic } => Outcome::Unknown(diagnostic.to_string()),
        }),
    }
}

fn source_from_wire(value: w::ForkSourceOutcome) -> Result<ForkSourceOutcome, ConversionError> {
    use w::fork_source_outcome::Outcome;
    Ok(match required(value.outcome, "fork.source.outcome")? {
        Outcome::Pending(()) => ForkSourceOutcome::Pending,
        Outcome::Unchanged(()) => ForkSourceOutcome::Unchanged,
        Outcome::Resumed(()) => ForkSourceOutcome::Resumed,
        Outcome::Preserved(()) => ForkSourceOutcome::Preserved,
        Outcome::ResumeFailed(value) => ForkSourceOutcome::ResumeFailed {
            diagnostic: diagnostic(value, "fork.source.resume_failed")?,
        },
        Outcome::Unknown(value) => ForkSourceOutcome::Unknown {
            diagnostic: diagnostic(value, "fork.source.unknown")?,
        },
    })
}

fn child_outcome_to_wire(value: &ForkChildOutcome) -> w::ForkChildOutcome {
    use w::fork_child_outcome::Outcome;
    w::ForkChildOutcome {
        outcome: Some(match value {
            ForkChildOutcome::Pending => Outcome::Pending(()),
            ForkChildOutcome::Constructing => Outcome::Constructing(()),
            ForkChildOutcome::Activating => Outcome::Activating(()),
            ForkChildOutcome::Running => Outcome::Running(()),
            ForkChildOutcome::Failed { phase, diagnostic } => {
                Outcome::Failed(w::ForkChildFailure {
                    phase: phase_to_wire(*phase),
                    diagnostic: diagnostic.to_string(),
                })
            }
            ForkChildOutcome::Cancelled => Outcome::Cancelled(()),
            ForkChildOutcome::Abandoned { diagnostic } => {
                Outcome::Abandoned(diagnostic.to_string())
            }
            ForkChildOutcome::RecoveryPending { diagnostic } => {
                Outcome::RecoveryPending(diagnostic.to_string())
            }
        }),
    }
}

fn child_outcome_from_wire(
    value: w::ForkChildOutcome,
) -> Result<ForkChildOutcome, ConversionError> {
    use w::fork_child_outcome::Outcome;
    Ok(match required(value.outcome, "fork.child.outcome")? {
        Outcome::Pending(()) => ForkChildOutcome::Pending,
        Outcome::Constructing(()) => ForkChildOutcome::Constructing,
        Outcome::Activating(()) => ForkChildOutcome::Activating,
        Outcome::Running(()) => ForkChildOutcome::Running,
        Outcome::Failed(failure) => ForkChildOutcome::Failed {
            phase: phase_from_wire(failure.phase)?,
            diagnostic: diagnostic(failure.diagnostic, "fork.child.failure.diagnostic")?,
        },
        Outcome::Cancelled(()) => ForkChildOutcome::Cancelled,
        Outcome::Abandoned(value) => ForkChildOutcome::Abandoned {
            diagnostic: diagnostic(value, "fork.child.abandoned")?,
        },
        Outcome::RecoveryPending(value) => ForkChildOutcome::RecoveryPending {
            diagnostic: diagnostic(value, "fork.child.recovery_pending")?,
        },
    })
}

fn child_result_to_wire(value: &ForkChildResult) -> w::ForkChildResult {
    w::ForkChildResult {
        index: value.index,
        name: value.name.clone(),
        machine_id: value.machine_id.to_string(),
        run_id: value.run_id.to_string(),
        outcome: Some(child_outcome_to_wire(&value.outcome)),
        durability: value.durability.map(|value| match value {
            libvm::MachineDurability::Constructed => w::MachineDurability::Constructed as i32,
            libvm::MachineDurability::Durable => w::MachineDurability::Durable as i32,
        }),
    }
}

fn child_result_from_wire(value: w::ForkChildResult) -> Result<ForkChildResult, ConversionError> {
    Ok(ForkChildResult {
        index: value.index,
        machine_id: machine_id(&value.machine_id, "fork.child.machine_id")?,
        run_id: run_id(&value.run_id, "fork.child.run_id")?,
        outcome: child_outcome_from_wire(required(value.outcome, "fork.child.outcome")?)?,
        name: value.name,
        durability: value
            .durability
            .map(|value| match w::MachineDurability::try_from(value) {
                Ok(w::MachineDurability::Constructed) => Ok(libvm::MachineDurability::Constructed),
                Ok(w::MachineDurability::Durable) => Ok(libvm::MachineDurability::Durable),
                _ => Err(invalid(
                    "fork.child.durability",
                    "unknown or unspecified durability",
                )),
            })
            .transpose()?,
    })
}

/// Structural and cross-field rules every accepted-operation result obeys,
/// on either transport. Result identities are reservations: they do not
/// claim that a machine directory exists.
pub fn validate_result(value: &LiveForkResult) -> Result<(), ConversionError> {
    if value.operation_id.is_nil() {
        return Err(invalid("fork.operation_id", "nil UUID"));
    }
    if uuid::Uuid::from(value.source_machine_id).is_nil() {
        return Err(invalid("fork.source_machine_id", "nil machine identity"));
    }
    canonical_uuid(value.source_run_id.as_str(), "fork.source_run_id")?;
    if value.children.is_empty() {
        return Err(invalid("fork.children", "expected at least one child"));
    }
    let finished = value.stage == ForkStage::Finished;
    if finished
        && (value.capture == ForkCaptureOutcome::Pending
            || value.source == ForkSourceOutcome::Pending)
    {
        return Err(invalid(
            "fork.stage",
            "a finished operation has settled capture and source outcomes",
        ));
    }
    let sealed = matches!(value.capture, ForkCaptureOutcome::Sealed { .. });
    let capture_failed = matches!(
        value.capture,
        ForkCaptureOutcome::Failed { .. } | ForkCaptureOutcome::Abandoned { .. }
    );
    let mut names = HashSet::with_capacity(value.children.len());
    let mut machines = HashSet::with_capacity(value.children.len() + 1);
    let mut runs = HashSet::with_capacity(value.children.len() + 1);
    machines.insert(value.source_machine_id);
    runs.insert(value.source_run_id.as_str());
    for (position, child) in value.children.iter().enumerate() {
        if usize::try_from(child.index).ok() != Some(position) {
            return Err(invalid(
                "fork.child.index",
                "expected contiguous indices in request order",
            ));
        }
        child_name(&child.name)?;
        canonical_uuid(child.run_id.as_str(), "fork.child.run_id")?;
        if uuid::Uuid::from(child.machine_id).is_nil() {
            return Err(invalid("fork.child.machine_id", "nil machine identity"));
        }
        if !names.insert(child.name.as_str()) {
            return Err(invalid("fork.child.name", "duplicate child name"));
        }
        if !machines.insert(child.machine_id) {
            return Err(invalid(
                "fork.child.machine_id",
                "duplicate or source machine identity",
            ));
        }
        if !runs.insert(child.run_id.as_str()) {
            return Err(invalid(
                "fork.child.run_id",
                "duplicate or source run identity",
            ));
        }
        match &child.outcome {
            ForkChildOutcome::Constructing
            | ForkChildOutcome::Activating
            | ForkChildOutcome::Running
            | ForkChildOutcome::Failed {
                phase:
                    ForkFailurePhase::Construction
                    | ForkFailurePhase::Activation
                    | ForkFailurePhase::Cleanup,
                ..
            } if !sealed => {
                return Err(invalid(
                    "fork.child.outcome",
                    "restoration requires a sealed cut",
                ))
            }
            ForkChildOutcome::Failed {
                phase: ForkFailurePhase::Capture,
                ..
            } if !capture_failed => {
                return Err(invalid(
                    "fork.child.outcome",
                    "a capture-phase failure requires a failed or abandoned capture",
                ))
            }
            ForkChildOutcome::Cancelled if !value.cancellation_requested => {
                return Err(invalid(
                    "fork.child.outcome",
                    "cancellation requires recorded cancellation intent",
                ))
            }
            ForkChildOutcome::Pending
            | ForkChildOutcome::Constructing
            | ForkChildOutcome::Activating
                if finished =>
            {
                return Err(invalid(
                    "fork.child.outcome",
                    "a finished operation has no child in progress",
                ))
            }
            _ => {}
        }
    }
    Ok(())
}

/// A creation result answers exactly this request: same operation, every
/// requested child by name in request order.
pub fn validate_creation(
    result: &LiveForkResult,
    request: &LiveForkOptions,
) -> Result<(), ConversionError> {
    validate_observation(result, request.operation_id)?;
    if result.children.len() != request.children.len()
        || !result
            .children
            .iter()
            .zip(&request.children)
            .all(|(result, request)| result.name == request.name)
    {
        return Err(invalid(
            "fork.children",
            "result does not name every requested child in request order",
        ));
    }
    Ok(())
}

/// An inspection or cancellation result belongs to the requested operation.
pub fn validate_observation(
    result: &LiveForkResult,
    operation_id: uuid::Uuid,
) -> Result<(), ConversionError> {
    validate_result(result)?;
    if result.operation_id != operation_id {
        return Err(invalid(
            "fork.operation_id",
            "result belongs to a different operation",
        ));
    }
    Ok(())
}

pub fn result_to_wire(value: &LiveForkResult) -> Result<w::LiveForkResult, ConversionError> {
    validate_result(value)?;
    Ok(w::LiveForkResult {
        operation_id: uuid_to_wire(value.operation_id, "fork.operation_id")?,
        source_machine_id: value.source_machine_id.to_string(),
        source_run_id: value.source_run_id.to_string(),
        capture_id: value.capture_id.to_string(),
        resume_policy: crate::capture::resume_policy_to_wire(value.resume_policy),
        stage: stage_to_wire(value.stage),
        cancellation_requested: value.cancellation_requested,
        capture: Some(capture_to_wire(&value.capture)),
        source: Some(source_to_wire(&value.source)),
        children: value.children.iter().map(child_result_to_wire).collect(),
    })
}

pub fn result_from_wire(value: w::LiveForkResult) -> Result<LiveForkResult, ConversionError> {
    let result = LiveForkResult {
        operation_id: canonical_uuid(&value.operation_id, "fork.operation_id")?,
        source_machine_id: machine_id(&value.source_machine_id, "fork.source_machine_id")?,
        source_run_id: run_id(&value.source_run_id, "fork.source_run_id")?,
        capture_id: LiveId::parse(&value.capture_id)
            .map_err(|_| invalid("fork.capture_id", "noncanonical or nil UUID"))?,
        resume_policy: crate::capture::resume_policy_from_wire(value.resume_policy)?,
        stage: stage_from_wire(value.stage)?,
        cancellation_requested: value.cancellation_requested,
        capture: capture_from_wire(required(value.capture, "fork.capture")?)?,
        source: source_from_wire(required(value.source, "fork.source")?)?,
        children: value
            .children
            .into_iter()
            .map(child_result_from_wire)
            .collect::<Result<_, _>>()?,
    };
    validate_result(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use libvm::{
        ForkCaptureOutcome, ForkChildOutcome, ForkChildResult, ForkDestination, ForkFailurePhase,
        ForkSourceOutcome, ForkStage, LiveForkChild, LiveForkOptions, LiveForkResult,
    };
    use silod_spec::daemon::v1 as w;
    use vm_spec::lifecycle::{CaptureResumePolicy, Diagnostic, LiveId};

    use crate::fork::{
        operation_from_wire, operation_to_wire, request_from_wire, request_to_wire,
        result_from_wire, result_to_wire, validate_creation, validate_observation,
    };

    const OPERATION: &str = "00000000-0000-4000-8000-0000000000aa";
    const CAPTURE: &str = "00000000-0000-4000-8000-0000000000bb";
    const SOURCE_RUN: &str = "00000000-0000-4000-8000-0000000000cc";
    const SOURCE: &str = "000000000000400080000000000000dd";

    fn machine(index: u8) -> libvm::MachineId {
        format!("00000000000040008000000000001{index:03}")
            .parse()
            .unwrap()
    }

    fn run(index: u8) -> libvm::MachineRunId {
        format!("00000000-0000-4000-8000-000000002{index:03}")
            .parse()
            .unwrap()
    }

    fn cut() -> vm_spec::capture::Sha256Digest {
        format!("sha256:{}", "e".repeat(64)).parse().unwrap()
    }

    fn options() -> LiveForkOptions {
        LiveForkOptions {
            operation_id: OPERATION.parse().unwrap(),
            policy: vm_spec::lifecycle::CapturePolicy::Full,
            dirty_crossover_percent: 60,
            children: vec![
                LiveForkChild {
                    name: "child-a".into(),
                    activation_hook: Some(libvm::RestoreHook {
                        argv: vec!["/bin/true".into()],
                        environment: vec![libvm::RestoreEnvironmentVariable {
                            name: "ROLE".into(),
                            value: "a".into(),
                        }],
                        working_directory: "/".into(),
                        timeout_ms: 30_000,
                    }),
                    destination: ForkDestination {
                        forwards: vec![libvm::Forward::new(
                            libvm::ForwardEndpoint::Host(libvm::ForwardAddress::Tcp(
                                "127.0.0.1:8080".parse().unwrap(),
                            )),
                            libvm::ForwardEndpoint::Guest(libvm::ForwardAddress::Tcp(
                                "127.0.0.1:80".parse().unwrap(),
                            )),
                        )],
                        guest_publish: Some(libvm::GuestPublish {
                            bind: libvm::PublishBind::Loopback,
                        }),
                    },
                },
                LiveForkChild {
                    name: "child-b".into(),
                    activation_hook: None,
                    destination: ForkDestination::default(),
                },
            ],
            max_children: NonZeroU32::new(16).unwrap(),
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
        }
    }

    fn reference() -> libvm::MachineRef {
        libvm::MachineRef::parse("source").unwrap()
    }

    fn child(index: u8, name: &str, outcome: ForkChildOutcome) -> ForkChildResult {
        ForkChildResult {
            index: u32::from(index),
            name: name.into(),
            machine_id: machine(index),
            run_id: run(index),
            outcome,
            durability: None,
        }
    }

    /// Child k failed after seal; siblings keep running and the source resumed.
    fn partial() -> LiveForkResult {
        LiveForkResult {
            operation_id: OPERATION.parse().unwrap(),
            source_machine_id: SOURCE.parse().unwrap(),
            source_run_id: SOURCE_RUN.parse().unwrap(),
            capture_id: LiveId::parse(CAPTURE).unwrap(),
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            stage: ForkStage::Finished,
            cancellation_requested: false,
            capture: ForkCaptureOutcome::Sealed { cut_id: cut() },
            source: ForkSourceOutcome::Resumed,
            children: vec![
                child(0, "child-a", ForkChildOutcome::Running),
                child(
                    1,
                    "child-b",
                    ForkChildOutcome::Failed {
                        phase: ForkFailurePhase::Activation,
                        diagnostic: Diagnostic::new("activation hook exited 1"),
                    },
                ),
            ],
        }
    }

    #[test]
    fn request_round_trips_every_child_destination_hook_and_policy() {
        let request = request_to_wire(&reference(), &options()).unwrap();
        assert_eq!(request.operation_id, OPERATION);
        assert_eq!(request.max_children, 16);
        let (machine, decoded) = request_from_wire(request).unwrap();
        assert_eq!(machine, reference());
        assert_eq!(decoded, options());
    }

    #[test]
    fn request_rejects_missing_invalid_duplicate_and_overflowing_children() {
        let valid = request_to_wire(&reference(), &options()).unwrap();
        let mut cases: Vec<(&str, w::LiveForkRequest)> = Vec::new();
        let mut case = valid.clone();
        case.machine = None;
        cases.push(("missing machine", case));
        let mut case = valid.clone();
        case.children.clear();
        cases.push(("no children", case));
        let mut case = valid.clone();
        case.max_children = 0;
        cases.push(("zero maximum", case));
        let mut case = valid.clone();
        case.max_children = 1;
        cases.push(("count above explicit maximum", case));
        let mut case = valid.clone();
        case.children[1].name = "child-a".into();
        cases.push(("duplicate name", case));
        let mut case = valid.clone();
        case.children[1].name = "../escape".into();
        cases.push(("invalid name", case));
        let mut case = valid.clone();
        case.children[1].destination = None;
        cases.push(("missing destination", case));
        let mut case = valid.clone();
        case.children[0].destination.as_mut().unwrap().guest_publish = Some(0);
        cases.push(("unspecified publish bind", case));
        let mut case = valid.clone();
        case.children[0]
            .activation_hook
            .as_mut()
            .unwrap()
            .timeout_ms = None;
        cases.push(("hook without timeout", case));
        let mut case = valid.clone();
        case.resume_policy = w::CaptureResumePolicy::Unspecified as i32;
        cases.push(("unspecified resume policy", case));
        for operation_id in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-0000000000AA",
            "00000000000040008000000000000aa",
        ] {
            let mut case = valid.clone();
            case.operation_id = operation_id.into();
            cases.push(("noncanonical operation", case));
        }
        for (label, case) in cases {
            assert!(request_from_wire(case).is_err(), "{label} accepted");
        }
        let mut nil = options();
        nil.operation_id = uuid::Uuid::nil();
        assert!(request_to_wire(&reference(), &nil).is_err());
    }

    #[test]
    fn operation_reference_is_canonical_and_non_nil() {
        let id: uuid::Uuid = OPERATION.parse().unwrap();
        assert_eq!(
            operation_from_wire(operation_to_wire(id).unwrap()).unwrap(),
            id
        );
        assert!(operation_to_wire(uuid::Uuid::nil()).is_err());
        assert!(operation_from_wire(w::ForkOperationRef {
            operation_id: OPERATION.to_uppercase(),
        })
        .is_err());
    }

    #[test]
    fn partial_result_round_trips_and_keeps_every_child_and_identity() {
        let result = partial();
        let wire = result_to_wire(&result).unwrap();
        assert_eq!(wire.children.len(), 2);
        assert_eq!(wire.children[1].machine_id, machine(1).to_string());
        assert_eq!(wire.children[1].run_id, run(1).to_string());
        let decoded = result_from_wire(wire).unwrap();
        assert_eq!(decoded, result);
        validate_creation(&decoded, &options()).unwrap();
        validate_observation(&decoded, OPERATION.parse().unwrap()).unwrap();
    }

    #[test]
    fn resolved_preserve_policy_round_trips_for_default_request() {
        let mut result = partial();
        result.resume_policy = CaptureResumePolicy::Preserve;
        result.source = ForkSourceOutcome::Preserved;
        let wire = result_to_wire(&result).unwrap();
        let decoded = result_from_wire(wire.clone()).unwrap();
        assert_eq!(decoded, result);
        assert_eq!(
            options().resume_policy,
            CaptureResumePolicy::ResumeIfAcquired
        );
        validate_creation(&decoded, &options()).unwrap();
        let mut invalid = wire;
        invalid.resume_policy = w::CaptureResumePolicy::Unspecified as i32;
        assert!(result_from_wire(invalid).is_err());
    }

    #[test]
    fn every_outcome_variant_round_trips() {
        let diagnostic = || Diagnostic::new("diagnostic");
        let mut result = partial();
        result.stage = ForkStage::Settling;
        result.cancellation_requested = true;
        let outcomes = [
            ForkChildOutcome::Pending,
            ForkChildOutcome::Constructing,
            ForkChildOutcome::Activating,
            ForkChildOutcome::Running,
            ForkChildOutcome::Failed {
                phase: ForkFailurePhase::Construction,
                diagnostic: diagnostic(),
            },
            ForkChildOutcome::Failed {
                phase: ForkFailurePhase::Cleanup,
                diagnostic: diagnostic(),
            },
            ForkChildOutcome::Cancelled,
            ForkChildOutcome::Abandoned {
                diagnostic: diagnostic(),
            },
            ForkChildOutcome::RecoveryPending {
                diagnostic: diagnostic(),
            },
        ];
        result.children = outcomes
            .into_iter()
            .enumerate()
            .map(|(index, outcome)| {
                let index = u8::try_from(index).unwrap();
                child(index, &format!("child-{index}"), outcome)
            })
            .collect();
        for source in [
            ForkSourceOutcome::Pending,
            ForkSourceOutcome::Unchanged,
            ForkSourceOutcome::Resumed,
            ForkSourceOutcome::Preserved,
            ForkSourceOutcome::ResumeFailed {
                diagnostic: diagnostic(),
            },
            ForkSourceOutcome::Unknown {
                diagnostic: diagnostic(),
            },
        ] {
            result.source = source;
            assert_eq!(
                result_from_wire(result_to_wire(&result).unwrap()).unwrap(),
                result
            );
        }
        let mut failed = partial();
        failed.capture = ForkCaptureOutcome::Failed {
            diagnostic: diagnostic(),
        };
        failed.source = ForkSourceOutcome::Unchanged;
        for child in &mut failed.children {
            child.outcome = ForkChildOutcome::Failed {
                phase: ForkFailurePhase::Capture,
                diagnostic: diagnostic(),
            };
        }
        assert_eq!(
            result_from_wire(result_to_wire(&failed).unwrap()).unwrap(),
            failed
        );
        failed.capture = ForkCaptureOutcome::Abandoned {
            diagnostic: diagnostic(),
        };
        assert_eq!(
            result_from_wire(result_to_wire(&failed).unwrap()).unwrap(),
            failed
        );
        let mut pending = partial();
        pending.stage = ForkStage::Admitted;
        pending.capture = ForkCaptureOutcome::Pending;
        pending.source = ForkSourceOutcome::Pending;
        for child in &mut pending.children {
            child.outcome = ForkChildOutcome::Pending;
        }
        for stage in [
            ForkStage::Admitted,
            ForkStage::Capturing,
            ForkStage::Restoring,
            ForkStage::Settling,
        ] {
            pending.stage = stage;
            assert_eq!(
                result_from_wire(result_to_wire(&pending).unwrap()).unwrap(),
                pending
            );
        }
    }

    #[test]
    fn result_rejects_missing_unknown_duplicate_and_inconsistent_wire() {
        let valid = result_to_wire(&partial()).unwrap();
        let mut cases: Vec<(&str, w::LiveForkResult)> = Vec::new();
        let mut case = valid.clone();
        case.capture = None;
        cases.push(("missing capture", case));
        let mut case = valid.clone();
        case.capture = Some(w::ForkCaptureOutcome { outcome: None });
        cases.push(("empty capture oneof", case));
        let mut case = valid.clone();
        case.source = Some(w::ForkSourceOutcome { outcome: None });
        cases.push(("empty source oneof", case));
        let mut case = valid.clone();
        case.children[0].outcome = None;
        cases.push(("missing child outcome", case));
        let mut case = valid.clone();
        case.children[0].outcome = Some(w::ForkChildOutcome { outcome: None });
        cases.push(("empty child oneof", case));
        let mut case = valid.clone();
        case.stage = w::ForkStage::Unspecified as i32;
        cases.push(("unspecified stage", case));
        let mut case = valid.clone();
        case.stage = 99;
        cases.push(("unknown stage", case));
        let mut case = valid.clone();
        case.children[0].durability = Some(w::MachineDurability::Unspecified as i32);
        cases.push(("unspecified durability", case));
        let mut case = valid.clone();
        case.children[0].durability = Some(99);
        cases.push(("unknown durability", case));
        let mut case = valid.clone();
        case.children[1].outcome = Some(w::ForkChildOutcome {
            outcome: Some(w::fork_child_outcome::Outcome::Failed(
                w::ForkChildFailure {
                    phase: 99,
                    diagnostic: "x".into(),
                },
            )),
        });
        cases.push(("unknown failure phase", case));
        let mut case = valid.clone();
        case.children[1].outcome = Some(w::ForkChildOutcome {
            outcome: Some(w::fork_child_outcome::Outcome::Abandoned("x".repeat(4097))),
        });
        cases.push(("oversized diagnostic", case));
        let mut case = valid.clone();
        case.children.clear();
        cases.push(("no children", case));
        let mut case = valid.clone();
        case.children[1].index = 0;
        cases.push(("duplicate index", case));
        let mut case = valid.clone();
        case.children.swap(0, 1);
        cases.push(("reordered children", case));
        let mut case = valid.clone();
        case.children[1].name = "child-a".into();
        cases.push(("duplicate child name", case));
        let mut case = valid.clone();
        case.children[1].machine_id = case.children[0].machine_id.clone();
        cases.push(("duplicate child machine", case));
        let mut case = valid.clone();
        case.children[1].machine_id = SOURCE.into();
        cases.push(("child reuses source machine", case));
        let mut case = valid.clone();
        case.children[1].run_id = case.children[0].run_id.clone();
        cases.push(("duplicate child run", case));
        let mut case = valid.clone();
        case.children[1].run_id = SOURCE_RUN.into();
        cases.push(("child reuses source run", case));
        let mut case = valid.clone();
        case.children[0].machine_id = "00000000-0000-4000-8000-000000001000".into();
        cases.push(("noncanonical machine", case));
        let mut case = valid.clone();
        case.children[0].run_id = "00000000000040008000000000002000".into();
        cases.push(("noncanonical run", case));
        let mut case = valid.clone();
        case.capture_id = "00000000-0000-0000-0000-000000000000".into();
        cases.push(("nil capture", case));
        let mut case = valid.clone();
        case.capture = Some(w::ForkCaptureOutcome {
            outcome: Some(w::fork_capture_outcome::Outcome::SealedCutId(
                "sha256:abc".into(),
            )),
        });
        cases.push(("invalid cut digest", case));
        let mut case = valid.clone();
        case.capture = Some(w::ForkCaptureOutcome {
            outcome: Some(w::fork_capture_outcome::Outcome::Pending(())),
        });
        case.stage = w::ForkStage::Restoring as i32;
        cases.push(("running child without sealed cut", case));
        let mut case = valid.clone();
        case.children[1].outcome = Some(w::ForkChildOutcome {
            outcome: Some(w::fork_child_outcome::Outcome::Failed(
                w::ForkChildFailure {
                    phase: w::ForkFailurePhase::Capture as i32,
                    diagnostic: "x".into(),
                },
            )),
        });
        cases.push(("capture failure with sealed cut", case));
        let mut case = valid.clone();
        case.children[1].outcome = Some(w::ForkChildOutcome {
            outcome: Some(w::fork_child_outcome::Outcome::Cancelled(())),
        });
        cases.push(("cancelled without intent", case));
        let mut case = valid.clone();
        case.children[1].outcome = Some(w::ForkChildOutcome {
            outcome: Some(w::fork_child_outcome::Outcome::Activating(())),
        });
        cases.push(("finished with child in progress", case));
        let mut case = valid.clone();
        case.source = Some(w::ForkSourceOutcome {
            outcome: Some(w::fork_source_outcome::Outcome::Pending(())),
        });
        cases.push(("finished with pending source", case));
        for (label, case) in cases {
            assert!(result_from_wire(case).is_err(), "{label} accepted");
        }
    }

    #[test]
    fn sender_refuses_inconsistent_results_and_clients_bind_them_to_requests() {
        let mut duplicate = partial();
        duplicate.children[1].name = "child-a".into();
        assert!(result_to_wire(&duplicate).is_err());
        let mut nil = partial();
        nil.operation_id = uuid::Uuid::nil();
        assert!(result_to_wire(&nil).is_err());

        let result = partial();
        let mut other = options();
        other.operation_id = "00000000-0000-4000-8000-0000000000ab".parse().unwrap();
        assert!(validate_creation(&result, &other).is_err());
        assert!(validate_observation(&result, other.operation_id).is_err());
        let mut fewer = options();
        fewer.children.pop();
        assert!(validate_creation(&result, &fewer).is_err());
        let mut renamed = options();
        renamed.children[1].name = "child-c".into();
        assert!(validate_creation(&result, &renamed).is_err());
    }

    #[test]
    fn child_durability_round_trips_independently_of_running_completion() {
        for durability in [
            None,
            Some(libvm::MachineDurability::Constructed),
            Some(libvm::MachineDurability::Durable),
        ] {
            let mut value = partial();
            value.children[0].outcome = ForkChildOutcome::Running;
            value.children[0].durability = durability;
            let wire = result_to_wire(&value).unwrap();
            assert_eq!(result_from_wire(wire).unwrap(), value);
        }
    }
}

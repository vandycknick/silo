use crate::{invalid, required, ConversionError};
use prost::Message;
use silod_spec::daemon::v1 as w;
pub fn launch_reason_to_wire(v: libvm::ExecutionLaunchFailureReason) -> i32 {
    match v {
        libvm::ExecutionLaunchFailureReason::Unspecified => 0,
        libvm::ExecutionLaunchFailureReason::CommandNotFound => 1,
        libvm::ExecutionLaunchFailureReason::InvalidProcessSpec => 2,
        libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotFound => 3,
        libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotDirectory => 4,
        libvm::ExecutionLaunchFailureReason::InvalidIdentity => 5,
        libvm::ExecutionLaunchFailureReason::IdentityNotFound => 6,
        libvm::ExecutionLaunchFailureReason::PermissionDenied => 7,
        libvm::ExecutionLaunchFailureReason::SpawnFailed => 8,
        libvm::ExecutionLaunchFailureReason::CancelledBeforeStart => 9,
    }
}
pub fn launch_reason_from_wire(
    v: i32,
) -> Result<libvm::ExecutionLaunchFailureReason, ConversionError> {
    match v {
        0 => Ok(libvm::ExecutionLaunchFailureReason::Unspecified),
        1 => Ok(libvm::ExecutionLaunchFailureReason::CommandNotFound),
        2 => Ok(libvm::ExecutionLaunchFailureReason::InvalidProcessSpec),
        3 => Ok(libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotFound),
        4 => Ok(libvm::ExecutionLaunchFailureReason::WorkingDirectoryNotDirectory),
        5 => Ok(libvm::ExecutionLaunchFailureReason::InvalidIdentity),
        6 => Ok(libvm::ExecutionLaunchFailureReason::IdentityNotFound),
        7 => Ok(libvm::ExecutionLaunchFailureReason::PermissionDenied),
        8 => Ok(libvm::ExecutionLaunchFailureReason::SpawnFailed),
        9 => Ok(libvm::ExecutionLaunchFailureReason::CancelledBeforeStart),
        _ => Err(invalid("launch_failure_reason", "invalid enum")),
    }
}
pub fn native_error_to_status(v: &libvm::LibVmError) -> tonic::Status {
    use libvm::LibVmError as E;
    let mut d = w::ErrorDetail {
        kind: 8,
        code: 7,
        safe_message: "native management operation failed".into(),
        native_variant: Some(v.variant().into()),
        ..Default::default()
    };
    let code = match v {
        E::MachineAlreadyRunning { reference } => {
            d.kind = 4;
            d.code = 1;
            d.reference = Some(reference.clone());
            d.safe_message = "machine is already running".into();
            tonic::Code::FailedPrecondition
        }
        E::MachineNotRunning { reference } => {
            d.kind = 4;
            d.code = 2;
            d.reference = Some(reference.clone());
            d.safe_message = "machine is not running".into();
            tonic::Code::FailedPrecondition
        }
        E::MachineStaleGeneration {
            reference,
            requested,
            current,
        } => {
            d.kind = 4;
            d.code = 3;
            d.reference = Some(reference.clone());
            d.expected_run = Some(requested.to_string());
            d.current_run = current.as_ref().map(ToString::to_string);
            d.safe_message = "machine run is no longer current".into();
            tonic::Code::FailedPrecondition
        }
        E::MonitorConnection { reference, .. } => {
            d.kind = 7;
            d.code = 4;
            d.reference = Some(reference.clone());
            d.safe_message = "monitor connection unavailable".into();
            tonic::Code::Unavailable
        }
        E::EntrypointLaunchFailed { failure } => {
            d.kind = 4;
            d.code = if failure.reason == libvm::ExecutionLaunchFailureReason::CommandNotFound {
                6
            } else {
                5
            };
            d.launch_failure_reason = Some(launch_reason_to_wire(failure.reason));
            d.safe_message = "guest entrypoint could not launch".into();
            tonic::Code::FailedPrecondition
        }
        E::MachineNotFound { reference } | E::ImageNotFound { reference } => {
            d.kind = 2;
            d.reference = Some(reference.clone());
            d.safe_message = "requested resource not found".into();
            tonic::Code::NotFound
        }
        E::MachineAlreadyExists { name } => {
            d.kind = 3;
            d.reference = Some(name.clone());
            d.safe_message = "machine name already exists".into();
            tonic::Code::AlreadyExists
        }
        E::MachineIdAlreadyExists { id } => {
            d.kind = 3;
            d.reference = Some(id.clone());
            d.safe_message = "machine ID already exists".into();
            tonic::Code::AlreadyExists
        }
        E::InvalidMachineName { .. }
        | E::InvalidMachineIdPrefix { .. }
        | E::InvalidCreateRequest { .. }
        | E::InvalidMachineUpdate { .. }
        | E::InvalidMachineConfig { .. }
        | E::ImagePullPolicyUnsupported { .. } => {
            d.kind = 1;
            d.safe_message = "invalid management request".into();
            tonic::Code::InvalidArgument
        }
        E::ImageInUse { .. } | E::AmbiguousIdPrefix { .. } | E::MissingNetworkSecrets { .. } => {
            d.kind = 4;
            d.safe_message = "native precondition not satisfied".into();
            tonic::Code::FailedPrecondition
        }
        E::MachineNameGenerationFailed { .. } => {
            d.kind = 5;
            d.safe_message = "machine name allocation exhausted".into();
            tonic::Code::ResourceExhausted
        }
        E::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            d.kind = 6;
            d.safe_message = "management operation denied".into();
            tonic::Code::PermissionDenied
        }
        E::NetworkRuntime { .. }
        | E::SecretResolution { .. }
        | E::RuntimeComponentsNotFound { .. } => {
            d.kind = 7;
            d.safe_message = "required native resource unavailable".into();
            tonic::Code::Unavailable
        }
        _ => tonic::Code::Internal,
    };
    tonic::Status::with_details(code, d.safe_message.clone(), d.encode_to_vec().into())
}
pub fn status_to_native_error(v: &tonic::Status) -> Result<libvm::LibVmError, ConversionError> {
    let d = w::ErrorDetail::decode(v.details())
        .map_err(|_| invalid("error.detail", "missing or malformed typed detail"))?;
    if !(1..=8).contains(&d.kind) {
        return Err(invalid("error.kind", "invalid enum"));
    }
    use libvm::LibVmError as E;
    Ok(match d.code {
        1 => E::MachineAlreadyRunning {
            reference: required(d.reference, "error.reference")?,
        },
        2 => E::MachineNotRunning {
            reference: required(d.reference, "error.reference")?,
        },
        3 => E::MachineStaleGeneration {
            reference: required(d.reference, "error.reference")?,
            requested: required(d.expected_run, "error.expected_run")?
                .parse()
                .map_err(|_| invalid("error.expected_run", "invalid UUID"))?,
            current: d
                .current_run
                .map(|v| {
                    v.parse()
                        .map_err(|_| invalid("error.current_run", "invalid UUID"))
                })
                .transpose()?,
        },
        4 => E::MonitorConnection {
            reference: required(d.reference, "error.reference")?,
            message: d.safe_message,
        },
        5 | 6 => {
            let reason = launch_reason_from_wire(required(
                d.launch_failure_reason,
                "error.launch_failure_reason",
            )?)?;
            if (d.code == 6) != (reason == libvm::ExecutionLaunchFailureReason::CommandNotFound) {
                return Err(invalid("error.code", "launch reason mismatch"));
            }
            E::EntrypointLaunchFailed {
                failure: libvm::ExecutionLaunchFailure {
                    reason,
                    message: Some(d.safe_message),
                },
            }
        }
        7 => match required(d.native_variant, "error.native_variant")?.as_str() {
            "MachineNotFound" => E::MachineNotFound {
                reference: required(d.reference, "error.reference")?,
            },
            "ImageNotFound" => E::ImageNotFound {
                reference: required(d.reference, "error.reference")?,
            },
            "MachineAlreadyExists" => E::MachineAlreadyExists {
                name: required(d.reference, "error.reference")?,
            },
            "MachineIdAlreadyExists" => E::MachineIdAlreadyExists {
                id: required(d.reference, "error.reference")?,
            },
            _ => {
                return Err(invalid(
                    "error.native_variant",
                    "retain original typed RPC status; native variant cannot be reconstructed",
                ))
            }
        },
        _ => return Err(invalid("error.code", "invalid enum")),
    })
}

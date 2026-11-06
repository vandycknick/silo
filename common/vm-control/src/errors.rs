use crate::{invalid, required, ConversionError};
use prost::Message;
use silod_spec::daemon::v1 as w;

const ERROR_DETAIL_TYPE: &str = "type.googleapis.com/silo.daemon.v1.ErrorDetail";

// google.rpc.Status is the standard grpc-status-details-bin envelope. Its
// schema is stable; prost-types already supplies the nested google.protobuf.Any.
#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

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
        E::LiveOperationUnsupported {
            operation,
            backend,
            lane,
            reason,
        } => {
            let value = vm_spec::live::LiveOperationUnsupported {
                operation: *operation,
                backend: *backend,
                lane: *lane,
                reason: reason.clone(),
            };
            let wire = match crate::live::unsupported_to_wire(&value) {
                Ok(wire) => wire,
                Err(error) => {
                    return native_error_to_status(&E::LiveProtocol {
                        message: error.to_string(),
                    })
                }
            };
            d.kind = 4;
            d.code = 8;
            d.safe_message = value.to_string();
            d.live_unsupported = Some(wire);
            tonic::Code::FailedPrecondition
        }
        E::LiveDiscovery { .. } => {
            d.kind = 7;
            d.safe_message = "live capability discovery unavailable".into();
            tonic::Code::Unavailable
        }
        E::LiveObservation { reference, .. } => {
            d.kind = 7;
            d.reference = Some(reference.clone());
            d.safe_message = "live machine observation unavailable".into();
            tonic::Code::Unavailable
        }
        E::LiveProtocol { .. } => {
            d.safe_message = "invalid live capability protocol evidence".into();
            tonic::Code::DataLoss
        }
        E::LiveCapture {
            capture_id,
            message,
        } => {
            d.kind = 4;
            d.reference = Some(capture_id.clone());
            d.safe_message = message.clone();
            tonic::Code::FailedPrecondition
        }
        E::LiveFork {
            operation_id,
            message,
        } => {
            d.kind = 4;
            d.reference = Some(operation_id.clone());
            d.safe_message = message.clone();
            tonic::Code::FailedPrecondition
        }
        E::LiveForkNotFound { operation_id } => {
            d.kind = 2;
            d.reference = Some(operation_id.clone());
            d.safe_message = "live fork operation not found".into();
            tonic::Code::NotFound
        }
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
        E::ImageReferenceRejected { reference, message } => {
            d.kind = 1;
            d.reference = Some(reference.clone());
            d.safe_message = message.clone();
            tonic::Code::InvalidArgument
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
    let rich = RpcStatus {
        code: code as i32,
        message: d.safe_message.clone(),
        details: vec![prost_types::Any {
            type_url: ERROR_DETAIL_TYPE.into(),
            value: d.encode_to_vec(),
        }],
    };
    let encoded = rich.encode_to_vec();
    tonic::Status::with_details(code, rich.message, encoded.into())
}
pub fn status_to_native_error(v: &tonic::Status) -> Result<libvm::LibVmError, ConversionError> {
    let rich = RpcStatus::decode(v.details())
        .map_err(|_| invalid("error.status", "missing or malformed rich status"))?;
    if rich.code != v.code() as i32 {
        return Err(invalid("error.status", "rich status code mismatch"));
    }
    let mut details = rich
        .details
        .into_iter()
        .filter(|detail| detail.type_url == ERROR_DETAIL_TYPE);
    let detail = details
        .next()
        .ok_or_else(|| invalid("error.detail", "missing typed detail"))?;
    if details.next().is_some() {
        return Err(invalid("error.detail", "ambiguous typed details"));
    }
    let d = w::ErrorDetail::decode(detail.value.as_slice())
        .map_err(|_| invalid("error.detail", "malformed typed detail"))?;
    if !(1..=8).contains(&d.kind) {
        return Err(invalid("error.kind", "invalid enum"));
    }
    use libvm::LibVmError as E;
    if d.code != 8 && d.live_unsupported.is_some() {
        return Err(invalid("error.live_unsupported", "unexpected live detail"));
    }
    Ok(match d.code {
        8 => {
            if v.code() != tonic::Code::FailedPrecondition || d.kind != 4 {
                return Err(invalid(
                    "error.live_unsupported",
                    "expected failed precondition/conflict",
                ));
            }
            let value = crate::live::unsupported_from_wire(required(
                d.live_unsupported,
                "error.live_unsupported",
            )?)?;
            E::LiveOperationUnsupported {
                operation: value.operation,
                backend: value.backend,
                lane: value.lane,
                reason: value.reason,
            }
        }
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
            "LiveDiscovery" if v.code() == tonic::Code::Unavailable && d.kind == 7 => {
                E::LiveDiscovery {
                    message: d.safe_message,
                }
            }
            "LiveObservation" if v.code() == tonic::Code::Unavailable && d.kind == 7 => {
                E::LiveObservation {
                    reference: required(d.reference, "error.reference")?,
                    message: d.safe_message,
                }
            }
            "LiveProtocol" if v.code() == tonic::Code::DataLoss && d.kind == 8 => E::LiveProtocol {
                message: d.safe_message,
            },
            "LiveCapture" if v.code() == tonic::Code::FailedPrecondition && d.kind == 4 => {
                E::LiveCapture {
                    capture_id: required(d.reference, "error.reference")?,
                    message: d.safe_message,
                }
            }
            "LiveFork" if v.code() == tonic::Code::FailedPrecondition && d.kind == 4 => {
                E::LiveFork {
                    operation_id: required(d.reference, "error.reference")?,
                    message: d.safe_message,
                }
            }
            "LiveForkNotFound" if v.code() == tonic::Code::NotFound && d.kind == 2 => {
                E::LiveForkNotFound {
                    operation_id: required(d.reference, "error.reference")?,
                }
            }
            "MachineNotFound" => E::MachineNotFound {
                reference: required(d.reference, "error.reference")?,
            },
            "ImageNotFound" => E::ImageNotFound {
                reference: required(d.reference, "error.reference")?,
            },
            "ImageReferenceRejected" => E::ImageReferenceRejected {
                reference: required(d.reference, "error.reference")?,
                message: d.safe_message,
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

#[cfg(test)]
mod tests {
    use crate::errors::{
        native_error_to_status, status_to_native_error, RpcStatus, ERROR_DETAIL_TYPE,
    };
    use prost::Message;
    use silod_spec::daemon::v1 as w;
    use vm_spec::live::*;

    #[test]
    fn live_failed_precondition_roundtrips_every_operation_reason_and_subject() {
        let reasons = [
            LiveUnsupportedReason::new(LiveReasonCode::BackendExcluded),
            LiveUnsupportedReason::new(LiveReasonCode::HostOsBelowFloor),
            LiveUnsupportedReason::new(LiveReasonCode::LaneNotQualified),
            LiveUnsupportedReason::new(LiveReasonCode::HypervisorUnavailable),
            LiveUnsupportedReason::new(LiveReasonCode::BuildExcluded),
            LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
            LiveUnsupportedReason::device(LiveDeviceSubject::Virtiofs),
            LiveUnsupportedReason::device(LiveDeviceSubject::Rosetta),
            LiveUnsupportedReason::device(LiveDeviceSubject::Tap),
            LiveUnsupportedReason::device(LiveDeviceSubject::Gpu),
            LiveUnsupportedReason::device(LiveDeviceSubject::Nested),
            LiveUnsupportedReason::device(LiveDeviceSubject::Tee),
            LiveUnsupportedReason::device(LiveDeviceSubject::GuestProfile {
                profile: "restricted-v1".into(),
            }),
        ];
        for operation in LiveOperation::ALL {
            for reason in &reasons {
                let input = libvm::LibVmError::LiveOperationUnsupported {
                    operation,
                    backend: LiveBackend::Mock,
                    lane: LiveLane::NotApplicable,
                    reason: reason.clone(),
                };
                let status = native_error_to_status(&input);
                assert_eq!(status.code(), tonic::Code::FailedPrecondition);
                match status_to_native_error(&status).unwrap() {
                    libvm::LibVmError::LiveOperationUnsupported {
                        operation: actual,
                        backend,
                        lane,
                        reason: actual_reason,
                    } => {
                        assert_eq!(actual, operation);
                        assert_eq!(backend, LiveBackend::Mock);
                        assert_eq!(lane, LiveLane::NotApplicable);
                        assert_eq!(&actual_reason, reason);
                    }
                    error => panic!("lost typed live refusal: {error:?}"),
                }
            }
        }
    }

    fn status(detail: w::ErrorDetail, code: tonic::Code) -> tonic::Status {
        let rich = RpcStatus {
            code: code as i32,
            message: "not interpreted".into(),
            details: vec![prost_types::Any {
                type_url: ERROR_DETAIL_TYPE.into(),
                value: detail.encode_to_vec(),
            }],
        };
        tonic::Status::with_details(code, "not interpreted", rich.encode_to_vec().into())
    }

    #[test]
    fn live_errors_require_typed_detail_and_correct_status_category() {
        let detail = w::ErrorDetail {
            kind: 4,
            code: 8,
            ..Default::default()
        };
        assert!(
            status_to_native_error(&status(detail.clone(), tonic::Code::FailedPrecondition))
                .is_err()
        );
        let mut detail = detail;
        detail.live_unsupported = Some(
            crate::live::unsupported_to_wire(&LiveOperationUnsupported {
                operation: LiveOperation::Pause,
                backend: LiveBackend::Vz,
                lane: LiveLane::NotApplicable,
                reason: LiveUnsupportedReason::new(LiveReasonCode::BackendExcluded),
            })
            .unwrap(),
        );
        assert!(
            status_to_native_error(&status(detail.clone(), tonic::Code::Unimplemented)).is_err()
        );
        detail.live_unsupported.as_mut().unwrap().operation = Some(999);
        assert!(status_to_native_error(&status(detail, tonic::Code::FailedPrecondition)).is_err());
        assert!(status_to_native_error(&tonic::Status::failed_precondition(
            "pause unsupported: backend-excluded"
        ))
        .is_err());
    }

    #[test]
    fn live_fork_errors_keep_operation_identity_and_category() {
        let operation = "00000000-0000-4000-8000-0000000000aa";
        let refusal = libvm::LibVmError::LiveFork {
            operation_id: operation.into(),
            message: "admission commit uncertain; recover by this operation ID".into(),
        };
        let refusal_status = native_error_to_status(&refusal);
        assert_eq!(refusal_status.code(), tonic::Code::FailedPrecondition);
        match status_to_native_error(&refusal_status).unwrap() {
            libvm::LibVmError::LiveFork {
                operation_id,
                message,
            } => {
                assert_eq!(operation_id, operation);
                assert_eq!(
                    message,
                    "admission commit uncertain; recover by this operation ID"
                );
            }
            error => panic!("lost typed fork error: {error:?}"),
        }
        let missing = libvm::LibVmError::LiveForkNotFound {
            operation_id: operation.into(),
        };
        let missing_status = native_error_to_status(&missing);
        assert_eq!(missing_status.code(), tonic::Code::NotFound);
        match status_to_native_error(&missing_status).unwrap() {
            libvm::LibVmError::LiveForkNotFound { operation_id } => {
                assert_eq!(operation_id, operation)
            }
            error => panic!("lost typed fork lookup error: {error:?}"),
        }
        let detail = w::ErrorDetail {
            kind: 4,
            code: 7,
            native_variant: Some("LiveForkNotFound".into()),
            reference: Some(operation.into()),
            ..Default::default()
        };
        assert!(status_to_native_error(&status(detail, tonic::Code::FailedPrecondition)).is_err());
    }

    #[test]
    fn invalid_outbound_live_refusal_becomes_typed_protocol_failure() {
        let invalid = libvm::LibVmError::LiveOperationUnsupported {
            operation: LiveOperation::Capture,
            backend: LiveBackend::Vz,
            lane: LiveLane::KvmX86_64,
            reason: LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
        };
        let status = native_error_to_status(&invalid);
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(matches!(
            status_to_native_error(&status).unwrap(),
            libvm::LibVmError::LiveProtocol { .. }
        ));
        let rich = RpcStatus::decode(status.details()).unwrap();
        let detail = w::ErrorDetail::decode(rich.details[0].value.as_slice()).unwrap();
        assert_eq!(detail.code, 7);
        assert!(detail.live_unsupported.is_none());
    }
}

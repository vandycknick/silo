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
        E::IncompatibleRootProfile { profile } => {
            d.kind = 4;
            d.code = 16;
            d.reference = Some(profile.clone());
            d.safe_message = v.to_string();
            tonic::Code::FailedPrecondition
        }
        E::CompositionAcquisitionRequired { lower, missing } => {
            d.kind = 2;
            d.code = 17;
            d.reference = Some(lower.to_string());
            d.safe_message = missing.clone();
            tonic::Code::FailedPrecondition
        }
        E::RawExportRecoveryRequired { reason } => {
            d.kind = 4;
            d.code = 18;
            d.safe_message = reason.clone();
            tonic::Code::FailedPrecondition
        }
        E::RawExportUnsupported { reason } => {
            d.kind = 4;
            d.code = 19;
            d.safe_message = reason.clone();
            tonic::Code::FailedPrecondition
        }
        E::CheckpointPortability {
            checkpoint,
            refusal,
        } => {
            if refusal.validate().is_err() {
                return native_error_to_status(&E::LiveProtocol {
                    message: "invalid checkpoint portability refusal".into(),
                });
            }
            d.kind = 4;
            d.code = 15;
            d.reference = Some(checkpoint.clone());
            d.safe_message = v.to_string();
            d.checkpoint_portability = Some(w::RestorePortabilityRefusal {
                pin: refusal.pin.clone(),
                expected: refusal.expected.clone(),
                actual: refusal.actual.clone(),
                stage: refusal.stage.clone(),
            });
            tonic::Code::FailedPrecondition
        }
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
        E::Handoff(error) => {
            use libvm::handoff::types::HandoffError as H;
            d.safe_message = error.to_string();
            match error {
                H::InvalidIdentity
                | H::SameRuntime
                | H::WrongRuntime
                | H::EpochExhausted
                | H::ReceiptMismatch => {
                    d.kind = 1;
                    tonic::Code::InvalidArgument
                }
                H::UnknownOperation { operation } => {
                    d.kind = 2;
                    d.reference = Some(operation.to_string());
                    tonic::Code::NotFound
                }
                H::MachineIdConflict { machine } => {
                    d.kind = 3;
                    d.reference = Some(machine.to_string());
                    tonic::Code::AlreadyExists
                }
                _ => {
                    d.kind = 4;
                    tonic::Code::FailedPrecondition
                }
            }
        }
        E::ArtifactInvalid { .. } | E::ArtifactWire(_) => {
            d.kind = 1;
            d.safe_message = "artifact integrity or semantic validation failed".into();
            tonic::Code::InvalidArgument
        }
        E::ArtifactTrustMismatch { .. } => {
            d.kind = 6;
            d.safe_message = "resolved artifact index differs from the approved digest".into();
            tonic::Code::PermissionDenied
        }
        E::ArtifactSignatureProviderUnavailable
        | E::CheckpointPublicationNotAcknowledged { .. } => {
            d.kind = 4;
            d.safe_message = v.to_string();
            tonic::Code::FailedPrecondition
        }
        E::BackendAdmissionRejected {
            source_family,
            root_profile,
            requirement,
            effective_backend,
            remedy,
        } => {
            d.kind = 4;
            d.code = 9;
            d.safe_message = v.to_string();
            d.backend_admission = Some(admission_to_wire(
                *source_family,
                *root_profile,
                *requirement,
                *effective_backend,
                *remedy,
            ));
            tonic::Code::FailedPrecondition
        }
        E::RootSelectionFailed(failure) => match root_selection_to_wire(failure) {
            Ok(wire) => {
                d.kind = 1;
                d.code = 10;
                d.safe_message = failure.reason.clone();
                d.root_selection = Some(wire);
                tonic::Code::InvalidArgument
            }
            Err(error) => {
                d.safe_message = format!("invalid root selection diagnostics: {error}");
                tonic::Code::Internal
            }
        },
        E::TranslationUnavailable { reason } => {
            d.kind = 4;
            d.code = 11;
            d.safe_message = reason.clone();
            tonic::Code::FailedPrecondition
        }
        E::BootBundleAbiUnsupported => {
            d.kind = 4;
            d.code = 14;
            d.safe_message = v.to_string();
            d.boot_bundle_abi = Some(w::BootBundleAbiUnsupported {});
            tonic::Code::FailedPrecondition
        }
        E::DirectKernelRejected(_) => {
            d.kind = 4;
            d.safe_message = v.to_string();
            tonic::Code::FailedPrecondition
        }
        E::BootAssetsAcquisitionRequired { missing } => {
            d.kind = 2;
            d.code = 12;
            d.reference = Some(missing.to_string());
            d.safe_message = v.to_string();
            tonic::Code::FailedPrecondition
        }
        E::DiskImport(failure) => match disk_import_to_wire(failure) {
            Some(wire) => {
                d.kind = 1;
                d.code = 13;
                d.safe_message = failure.to_string();
                d.disk_import = Some(wire);
                tonic::Code::InvalidArgument
            }
            None => {
                d.kind = 1;
                d.safe_message = failure.to_string();
                tonic::Code::InvalidArgument
            }
        },
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
    if (d.code != 8 && d.live_unsupported.is_some())
        || (d.code != 9 && d.backend_admission.is_some())
        || (d.code != 10 && d.root_selection.is_some())
        || (d.code != 13 && d.disk_import.is_some())
        || (d.code != 14 && d.boot_bundle_abi.is_some())
        || (d.code != 15 && d.checkpoint_portability.is_some())
    {
        return Err(invalid(
            "error.detail",
            "typed payload does not match the code",
        ));
    }
    let (status_code, detail_kind) = (v.code(), d.kind);
    let category = |code: tonic::Code, kind: i32, field: &'static str| {
        if status_code != code || detail_kind != kind {
            Err(invalid(field, "unexpected status category"))
        } else {
            Ok(())
        }
    };
    Ok(match d.code {
        16 => {
            category(tonic::Code::FailedPrecondition, 4, "error.root_profile")?;
            E::IncompatibleRootProfile {
                profile: required(d.reference, "error.reference")?,
            }
        }
        17 => {
            category(tonic::Code::FailedPrecondition, 2, "error.composition")?;
            E::CompositionAcquisitionRequired {
                lower: required(d.reference, "error.reference")?
                    .parse()
                    .map_err(|_| invalid("error.reference", "invalid lower result identity"))?,
                missing: d.safe_message,
            }
        }
        18 => {
            category(
                tonic::Code::FailedPrecondition,
                4,
                "error.raw_export_recovery",
            )?;
            E::RawExportRecoveryRequired {
                reason: d.safe_message,
            }
        }
        19 => {
            category(
                tonic::Code::FailedPrecondition,
                4,
                "error.raw_export_unsupported",
            )?;
            E::RawExportUnsupported {
                reason: d.safe_message,
            }
        }
        9 => {
            category(
                tonic::Code::FailedPrecondition,
                4,
                "error.backend_admission",
            )?;
            admission_from_wire(required(d.backend_admission, "error.backend_admission")?)?
        }
        10 => {
            category(tonic::Code::InvalidArgument, 1, "error.root_selection")?;
            E::RootSelectionFailed(Box::new(root_selection_from_wire(required(
                d.root_selection,
                "error.root_selection",
            )?)?))
        }
        11 => {
            category(tonic::Code::FailedPrecondition, 4, "error.translation")?;
            E::TranslationUnavailable {
                reason: d.safe_message,
            }
        }
        12 => {
            category(tonic::Code::FailedPrecondition, 2, "error.boot_assets")?;
            E::BootAssetsAcquisitionRequired {
                missing: crate::boot::digest_from_wire(
                    &required(d.reference, "error.reference")?,
                    "error.reference",
                )?,
            }
        }
        14 => {
            category(tonic::Code::FailedPrecondition, 4, "error.boot_bundle_abi")?;
            required(d.boot_bundle_abi, "error.boot_bundle_abi")?;
            E::BootBundleAbiUnsupported
        }
        15 => {
            category(
                tonic::Code::FailedPrecondition,
                4,
                "error.checkpoint_portability",
            )?;
            let value = required(d.checkpoint_portability, "error.checkpoint_portability")?;
            let refusal = vm_spec::restore::RestorePortabilityRefusal {
                pin: value.pin,
                expected: value.expected,
                actual: value.actual,
                stage: value.stage,
            };
            refusal.validate().map_err(|_| {
                invalid(
                    "error.checkpoint_portability",
                    "invalid portability refusal",
                )
            })?;
            E::CheckpointPortability {
                checkpoint: required(d.reference, "error.reference")?,
                refusal: Box::new(refusal),
            }
        }
        13 => {
            category(tonic::Code::InvalidArgument, 1, "error.disk_import")?;
            E::DiskImport(Box::new(disk_import_from_wire(required(
                d.disk_import,
                "error.disk_import",
            )?)?))
        }
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

/// Bounded by the partition parser: at most 128 GPT entries or 4 MBR slots.
const MAX_ROOT_CANDIDATES: usize = 128;
const MAX_REASON_BYTES: usize = 4096;

fn admission_to_wire(
    source_family: libvm::SourceFamily,
    root_profile: libvm::StorageProfile,
    requirement: libvm::BackendRequirement,
    effective_backend: vm_spec::live::LiveBackend,
    remedy: libvm::AdmissionRemedy,
) -> w::BackendAdmissionRejected {
    w::BackendAdmissionRejected {
        source_family: match source_family {
            libvm::SourceFamily::Oci => w::SourceFamily::Oci,
            libvm::SourceFamily::LocalDisk => w::SourceFamily::LocalDisk,
            libvm::SourceFamily::ManagedImage => w::SourceFamily::ManagedImage,
            libvm::SourceFamily::Snapshot => w::SourceFamily::Snapshot,
        } as i32,
        root_profile: match root_profile {
            libvm::StorageProfile::OpaqueRawV1 => w::StorageProfile::OpaqueRawV1,
            libvm::StorageProfile::LinuxOverlayV1 => w::StorageProfile::LinuxOverlayV1,
        } as i32,
        requirement: match requirement {
            libvm::BackendRequirement::RawBlock => w::BackendRequirement::RawBlock,
            libvm::BackendRequirement::KrunOverlay => w::BackendRequirement::KrunOverlay,
        } as i32,
        effective_backend: crate::live::backend_to_wire(effective_backend),
        remedy: match remedy {
            libvm::AdmissionRemedy::ExplicitOciToRawConversion => {
                w::AdmissionRemedy::ExplicitOciToRawConversion
            }
            libvm::AdmissionRemedy::UseKrun => w::AdmissionRemedy::UseKrun,
            libvm::AdmissionRemedy::UnsupportedBootProfile => {
                w::AdmissionRemedy::UnsupportedBootProfile
            }
        } as i32,
    }
}

fn admission_from_wire(
    value: w::BackendAdmissionRejected,
) -> Result<libvm::LibVmError, ConversionError> {
    Ok(libvm::LibVmError::BackendAdmissionRejected {
        source_family: match w::SourceFamily::try_from(value.source_family) {
            Ok(w::SourceFamily::Oci) => libvm::SourceFamily::Oci,
            Ok(w::SourceFamily::LocalDisk) => libvm::SourceFamily::LocalDisk,
            Ok(w::SourceFamily::ManagedImage) => libvm::SourceFamily::ManagedImage,
            Ok(w::SourceFamily::Snapshot) => libvm::SourceFamily::Snapshot,
            _ => return Err(invalid("error.source_family", "unknown source family")),
        },
        root_profile: match w::StorageProfile::try_from(value.root_profile) {
            Ok(w::StorageProfile::OpaqueRawV1) => libvm::StorageProfile::OpaqueRawV1,
            Ok(w::StorageProfile::LinuxOverlayV1) => libvm::StorageProfile::LinuxOverlayV1,
            _ => return Err(invalid("error.root_profile", "unknown storage profile")),
        },
        requirement: match w::BackendRequirement::try_from(value.requirement) {
            Ok(w::BackendRequirement::RawBlock) => libvm::BackendRequirement::RawBlock,
            Ok(w::BackendRequirement::KrunOverlay) => libvm::BackendRequirement::KrunOverlay,
            _ => return Err(invalid("error.requirement", "unknown backend requirement")),
        },
        effective_backend: crate::live::backend_from_wire(value.effective_backend)?,
        remedy: match w::AdmissionRemedy::try_from(value.remedy) {
            Ok(w::AdmissionRemedy::ExplicitOciToRawConversion) => {
                libvm::AdmissionRemedy::ExplicitOciToRawConversion
            }
            Ok(w::AdmissionRemedy::UseKrun) => libvm::AdmissionRemedy::UseKrun,
            Ok(w::AdmissionRemedy::UnsupportedBootProfile) => {
                libvm::AdmissionRemedy::UnsupportedBootProfile
            }
            _ => return Err(invalid("error.remedy", "unknown admission remedy")),
        },
    })
}

fn root_selection_to_wire(
    value: &libvm::RootSelectionFailed,
) -> Result<w::RootSelectionFailed, ConversionError> {
    if value.candidates.len() > MAX_ROOT_CANDIDATES || value.reason.len() > MAX_REASON_BYTES {
        return Err(invalid(
            "error.root_selection",
            "diagnostics exceed parser bounds",
        ));
    }
    Ok(w::RootSelectionFailed {
        requested: Some(crate::boot::import_root_to_wire(&value.requested)?),
        candidates: value
            .candidates
            .iter()
            .map(crate::boot::root_candidate_to_wire)
            .collect::<Result<_, _>>()?,
        reason: value.reason.clone(),
    })
}

fn root_selection_from_wire(
    value: w::RootSelectionFailed,
) -> Result<libvm::RootSelectionFailed, ConversionError> {
    if value.candidates.len() > MAX_ROOT_CANDIDATES || value.reason.len() > MAX_REASON_BYTES {
        return Err(invalid(
            "error.root_selection",
            "diagnostics exceed parser bounds",
        ));
    }
    Ok(libvm::RootSelectionFailed {
        requested: crate::boot::import_root_from_wire(required(
            value.requested,
            "error.root_selection.requested",
        )?)?,
        candidates: value
            .candidates
            .into_iter()
            .map(crate::boot::root_candidate_from_wire)
            .collect::<Result<_, _>>()?,
        reason: value.reason,
    })
}

fn container_to_wire(value: libvm::ForeignContainer) -> w::ForeignContainer {
    match value {
        libvm::ForeignContainer::Vmdk => w::ForeignContainer::Vmdk,
        libvm::ForeignContainer::Vhd => w::ForeignContainer::Vhd,
        libvm::ForeignContainer::Vhdx => w::ForeignContainer::Vhdx,
        libvm::ForeignContainer::Vdi => w::ForeignContainer::Vdi,
        libvm::ForeignContainer::Qed => w::ForeignContainer::Qed,
        libvm::ForeignContainer::Luks => w::ForeignContainer::Luks,
        libvm::ForeignContainer::Gzip => w::ForeignContainer::Gzip,
        libvm::ForeignContainer::Xz => w::ForeignContainer::Xz,
        libvm::ForeignContainer::Zstd => w::ForeignContainer::Zstd,
        libvm::ForeignContainer::Bzip2 => w::ForeignContainer::Bzip2,
    }
}

fn container_from_wire(value: i32) -> Result<libvm::ForeignContainer, ConversionError> {
    Ok(match w::ForeignContainer::try_from(value) {
        Ok(w::ForeignContainer::Vmdk) => libvm::ForeignContainer::Vmdk,
        Ok(w::ForeignContainer::Vhd) => libvm::ForeignContainer::Vhd,
        Ok(w::ForeignContainer::Vhdx) => libvm::ForeignContainer::Vhdx,
        Ok(w::ForeignContainer::Vdi) => libvm::ForeignContainer::Vdi,
        Ok(w::ForeignContainer::Qed) => libvm::ForeignContainer::Qed,
        Ok(w::ForeignContainer::Luks) => libvm::ForeignContainer::Luks,
        Ok(w::ForeignContainer::Gzip) => libvm::ForeignContainer::Gzip,
        Ok(w::ForeignContainer::Xz) => libvm::ForeignContainer::Xz,
        Ok(w::ForeignContainer::Zstd) => libvm::ForeignContainer::Zstd,
        Ok(w::ForeignContainer::Bzip2) => libvm::ForeignContainer::Bzip2,
        _ => return Err(invalid("error.disk_import.container", "unknown container")),
    })
}

/// Every admitted refusal keeps its typed failure kind; the source path (when
/// the failure has one) and unsupported-container identity are reconstructible.
/// A future native kind falls back to the generic native detail.
fn disk_import_to_wire(value: &libvm::DiskImportError) -> Option<w::DiskImportRejected> {
    use libvm::DiskImportError as D;
    use w::DiskImportFailure as F;
    let (failure, path, container) = match value {
        D::Open { path, .. } => (F::Open, Some(path), None),
        D::SymbolicLink { path } => (F::SymbolicLink, Some(path), None),
        D::NotRegularFile { path } => (F::NotRegularFile, Some(path), None),
        D::UnsupportedContainer { path, container } => {
            (F::UnsupportedContainer, Some(path), Some(*container))
        }
        D::RawGeometry { path, .. } => (F::RawGeometry, Some(path), None),
        D::Qcow2 { path, .. } => (F::Qcow2, Some(path), None),
        D::SourceChanged { path } => (F::SourceChanged, Some(path), None),
        D::PartitionTable(_) => (F::PartitionTable, None, None),
        D::DirectTable(_) => (F::DirectTable, None, None),
        D::RootFilesystem(_) => (F::RootFilesystem, None, None),
        D::OutputLength { .. } => (F::OutputLength, None, None),
        D::Read { path, .. } => (F::Read, Some(path), None),
        D::DecodedGeometry { .. } => (F::DecodedGeometry, None, None),
        _ => return None,
    };
    Some(w::DiskImportRejected {
        failure: failure as i32,
        path: path
            .map(|path| crate::path_to_wire(path))
            .unwrap_or_default(),
        container: container.map(|container| container_to_wire(container) as i32),
    })
}

/// Reconstructs refusals whose complete native meaning travels on the wire.
/// Failures carrying a native source error (qcow2, partition table, I/O) keep
/// their original RPC status instead of a fabricated source.
fn disk_import_from_wire(
    value: w::DiskImportRejected,
) -> Result<libvm::DiskImportError, ConversionError> {
    use libvm::DiskImportError as D;
    use w::DiskImportFailure as F;
    let failure = F::try_from(value.failure)
        .map_err(|_| invalid("error.disk_import.failure", "unknown failure"))?;
    if (failure == F::UnsupportedContainer) != value.container.is_some() {
        return Err(invalid(
            "error.disk_import.container",
            "container is present exactly for unsupported containers",
        ));
    }
    let path = || -> Result<std::path::PathBuf, ConversionError> {
        let path = crate::path_from_wire(value.path.clone())?;
        if !path.is_absolute() {
            return Err(invalid("error.disk_import.path", "must be absolute"));
        }
        Ok(path)
    };
    Ok(match failure {
        F::SymbolicLink => D::SymbolicLink { path: path()? },
        F::NotRegularFile => D::NotRegularFile { path: path()? },
        F::SourceChanged => D::SourceChanged { path: path()? },
        F::UnsupportedContainer => D::UnsupportedContainer {
            path: path()?,
            container: container_from_wire(required(
                value.container,
                "error.disk_import.container",
            )?)?,
        },
        F::Unspecified => return Err(invalid("error.disk_import.failure", "unknown failure")),
        F::Open
        | F::RawGeometry
        | F::Qcow2
        | F::PartitionTable
        | F::DirectTable
        | F::RootFilesystem
        | F::OutputLength
        | F::Read
        | F::DecodedGeometry => {
            return Err(invalid(
                "error.disk_import",
                "retain original typed RPC status; native source cannot be reconstructed",
            ))
        }
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
    fn portability_refusal_requires_preflight_stage_and_failed_precondition() {
        let detail = w::ErrorDetail {
            kind: 4,
            code: 15,
            reference: Some(format!("image:sha256:{}", "a".repeat(64))),
            checkpoint_portability: Some(w::RestorePortabilityRefusal {
                pin: "cpu".into(),
                expected: "captured-cpu".into(),
                actual: "unavailable".into(),
                stage: "restore-preflight".into(),
            }),
            ..Default::default()
        };
        assert!(matches!(
            status_to_native_error(&status(detail.clone(), tonic::Code::FailedPrecondition))
                .unwrap(),
            libvm::LibVmError::CheckpointPortability { .. }
        ));
        assert!(status_to_native_error(&status(detail.clone(), tonic::Code::Internal)).is_err());
        let mut wrong_stage = detail.clone();
        wrong_stage.checkpoint_portability.as_mut().unwrap().stage = "activation".into();
        assert!(
            status_to_native_error(&status(wrong_stage, tonic::Code::FailedPrecondition)).is_err()
        );
        let mut absent_pin = detail.clone();
        absent_pin
            .checkpoint_portability
            .as_mut()
            .unwrap()
            .pin
            .clear();
        assert!(
            status_to_native_error(&status(absent_pin, tonic::Code::FailedPrecondition)).is_err()
        );
        let mut absent_receipt = detail;
        absent_receipt.checkpoint_portability = None;
        assert!(
            status_to_native_error(&status(absent_receipt, tonic::Code::FailedPrecondition))
                .is_err()
        );
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

    #[test]
    fn admission_selection_translation_and_acquisition_refusals_stay_typed() {
        let admission = libvm::LibVmError::BackendAdmissionRejected {
            source_family: libvm::SourceFamily::Oci,
            root_profile: libvm::StorageProfile::OpaqueRawV1,
            requirement: libvm::BackendRequirement::RawBlock,
            effective_backend: LiveBackend::Vz,
            remedy: libvm::AdmissionRemedy::ExplicitOciToRawConversion,
        };
        let status_value = native_error_to_status(&admission);
        assert_eq!(status_value.code(), tonic::Code::FailedPrecondition);
        assert!(matches!(
            status_to_native_error(&status_value).unwrap(),
            libvm::LibVmError::BackendAdmissionRejected {
                source_family: libvm::SourceFamily::Oci,
                effective_backend: LiveBackend::Vz,
                remedy: libvm::AdmissionRemedy::ExplicitOciToRawConversion,
                ..
            }
        ));
        let failure = libvm::RootSelectionFailed {
            requested: libvm::ImportRootSelection::AutoGpt,
            candidates: vec![libvm::RootCandidate {
                selector: libvm::RootSelector::GptPartition {
                    guid: "01234567-89ab-cdef-0123-456789abcdef".parse().unwrap(),
                },
                first_lba: 2048,
                length_lbas: 2048,
                gpt_type: Some("4f68bce3-e8cd-4db1-96e7-fbcaf984b709".parse().unwrap()),
                mbr_type: None,
                attributes: 0,
            }],
            reason: "multiple root candidates".into(),
        };
        let status_value = native_error_to_status(&libvm::LibVmError::RootSelectionFailed(
            Box::new(failure.clone()),
        ));
        assert_eq!(status_value.code(), tonic::Code::InvalidArgument);
        match status_to_native_error(&status_value).unwrap() {
            libvm::LibVmError::RootSelectionFailed(actual) => assert_eq!(*actual, failure),
            error => panic!("lost typed candidates: {error:?}"),
        }
        let missing: libvm::storage::identity::ObjectDigest =
            format!("sha256:{}", "aa".repeat(32)).parse().unwrap();
        let status_value =
            native_error_to_status(&libvm::LibVmError::BootAssetsAcquisitionRequired { missing });
        assert!(matches!(
            status_to_native_error(&status_value).unwrap(),
            libvm::LibVmError::BootAssetsAcquisitionRequired { missing: actual } if actual == missing
        ));
        let status_value = native_error_to_status(&libvm::LibVmError::TranslationUnavailable {
            reason: "explicit --rosetta=false conflicts with amd64 userspace".into(),
        });
        assert!(matches!(
            status_to_native_error(&status_value).unwrap(),
            libvm::LibVmError::TranslationUnavailable { reason } if reason.contains("rosetta=false")
        ));

        let rejected = w::ErrorDetail {
            kind: 4,
            code: 9,
            backend_admission: Some(w::BackendAdmissionRejected {
                source_family: w::SourceFamily::Oci as i32,
                root_profile: w::StorageProfile::OpaqueRawV1 as i32,
                requirement: w::BackendRequirement::RawBlock as i32,
                effective_backend: 2,
                remedy: 0,
            }),
            ..Default::default()
        };
        assert!(
            status_to_native_error(&status(rejected.clone(), tonic::Code::FailedPrecondition))
                .is_err(),
            "unspecified remedy"
        );
        let mut wrong_category = rejected.clone();
        wrong_category.backend_admission.as_mut().unwrap().remedy = 1;
        assert!(status_to_native_error(&status(wrong_category, tonic::Code::Internal)).is_err());
        let mut stray = rejected;
        stray.code = 10;
        stray.kind = 1;
        assert!(status_to_native_error(&status(stray, tonic::Code::InvalidArgument)).is_err());
    }

    #[test]
    fn boot_bundle_abi_refusal_roundtrips_without_paths_or_asset_hashes() {
        let refusal = libvm::LibVmError::BootBundleAbiUnsupported;
        let status_value = native_error_to_status(&refusal);
        assert_eq!(status_value.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status_value.message(), refusal.to_string());
        assert!(status_value
            .message()
            .contains("select the packaged base initramfs"));
        assert!(matches!(
            status_to_native_error(&status_value).unwrap(),
            libvm::LibVmError::BootBundleAbiUnsupported
        ));
        let envelope = RpcStatus::decode(status_value.details()).unwrap();
        assert_eq!(envelope.details.len(), 1);
        let detail = w::ErrorDetail::decode(envelope.details[0].value.as_slice()).unwrap();
        assert_eq!(detail.kind, 4);
        assert_eq!(detail.code, 14);
        assert!(detail.reference.is_none());
        assert_eq!(detail.boot_bundle_abi.as_ref().unwrap().encoded_len(), 0);

        let mut missing_payload = detail.clone();
        missing_payload.boot_bundle_abi = None;
        assert!(
            status_to_native_error(&status(missing_payload, tonic::Code::FailedPrecondition,))
                .is_err()
        );
        assert!(status_to_native_error(&status(detail, tonic::Code::InvalidArgument)).is_err());
    }

    #[test]
    fn disk_import_refusals_keep_kind_path_and_container() {
        for error in [
            libvm::DiskImportError::SymbolicLink {
                path: "/images/link.raw".into(),
            },
            libvm::DiskImportError::UnsupportedContainer {
                path: "/images/disk.vmdk".into(),
                container: libvm::ForeignContainer::Vmdk,
            },
        ] {
            let status_value =
                native_error_to_status(&libvm::LibVmError::DiskImport(Box::new(error)));
            assert_eq!(status_value.code(), tonic::Code::InvalidArgument);
            assert!(matches!(
                status_to_native_error(&status_value).unwrap(),
                libvm::LibVmError::DiskImport(_)
            ));
        }
        let detail = w::ErrorDetail {
            kind: 1,
            code: 13,
            disk_import: Some(w::DiskImportRejected {
                failure: w::DiskImportFailure::SymbolicLink as i32,
                path: b"/images/link.raw".to_vec(),
                container: Some(w::ForeignContainer::Vmdk as i32),
            }),
            ..Default::default()
        };
        assert!(
            status_to_native_error(&status(detail, tonic::Code::InvalidArgument)).is_err(),
            "container only belongs to unsupported-container failures"
        );
    }
}

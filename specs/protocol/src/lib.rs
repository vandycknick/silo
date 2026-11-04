pub mod live;
pub mod shutdown;

#[allow(clippy::large_enum_variant)]
pub mod v1 {
    tonic::include_proto!("silo.v1");
}

/// Serialized `silo.v1` descriptors, without source locations.
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/silo-v1-descriptor.bin"));

pub const CHUNK_64_KIB: usize = 64 * 1024;
pub const STRUCTURED_16_MIB: usize = 16 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4095;
pub const MAX_FILENAME_BYTES: usize = 255;
pub const MAX_INFO_BYTES: usize = 1024;
pub const MAX_CODE_BYTES: usize = 128;
pub const MAX_DIAGNOSTIC_BYTES: usize = 4096;
pub const MAX_CURSOR_BYTES: usize = 8 * 1024;
pub const MAX_AGENT_IP_ADDRESSES: usize = 256;
pub const MAX_PROBED_INIT_PATHS: usize = 64;
pub const MAX_PROVISIONING_STEPS: usize = 256;
pub const MAX_METRIC_ARRAY_ENTRIES: usize = 1024;
pub const DEFAULT_DIRECTORY_PAGE_SIZE: u32 = 256;
pub const MAX_DIRECTORY_PAGE_SIZE: u32 = 1024;

pub const DEFAULT_GUEST_CONTROL_PORT: u32 = 1027;
pub const FORWARD_VSOCK_PORT: u32 = 1028;
pub const KERNEL_PARAM_GUEST_PORT: &str = "silo.guest.port";

pub fn guest_port_arg(port: u32) -> String {
    format!("{}={port}", KERNEL_PARAM_GUEST_PORT)
}

pub fn parse_guest_port_args<'a>(args: impl IntoIterator<Item = &'a str>) -> u32 {
    for arg in args {
        let Some(raw_port) = arg.strip_prefix(&format!("{}=", KERNEL_PARAM_GUEST_PORT)) else {
            continue;
        };

        let Ok(port) = raw_port.parse::<u32>() else {
            continue;
        };

        if (1..=u32::from(u16::MAX)).contains(&port) {
            return port;
        }
    }

    DEFAULT_GUEST_CONTROL_PORT
}

pub fn encode_error_detail(detail: &v1::ErrorDetail) -> Vec<u8> {
    prost::Message::encode_to_vec(detail)
}

pub fn decode_error_detail(bytes: &[u8]) -> Result<v1::ErrorDetail, prost::DecodeError> {
    prost::Message::decode(bytes)
}

pub fn encode_execution_event(event: &v1::ExecutionEvent) -> Vec<u8> {
    prost::Message::encode_length_delimited_to_vec(event)
}

pub fn decode_execution_event(bytes: &mut &[u8]) -> Result<v1::ExecutionEvent, prost::DecodeError> {
    prost::Message::decode_length_delimited(bytes)
}

pub fn reflection_descriptor_set(
    admitted_services: &[&str],
) -> Result<prost_types::FileDescriptorSet, prost::DecodeError> {
    let mut descriptors: prost_types::FileDescriptorSet =
        prost::Message::decode(FILE_DESCRIPTOR_SET)?;
    for file in &mut descriptors.file {
        let package = file.package.as_deref().unwrap_or_default();
        file.service.retain(|service| {
            service.name.as_deref().is_some_and(|name| {
                admitted_services
                    .iter()
                    .any(|admitted| *admitted == format!("{package}.{name}"))
            })
        });
    }
    Ok(descriptors)
}

/// Adds the stable Silo error detail to an application-generated status.
/// Transport-generated statuses are allowed to remain detail-free.
pub fn detailed_status(status: tonic::Status) -> tonic::Status {
    if !status.details().is_empty() {
        return status;
    }
    let code = match status.code() {
        tonic::Code::Cancelled => v1::ErrorCode::OperationCancelled,
        tonic::Code::InvalidArgument | tonic::Code::OutOfRange => v1::ErrorCode::InvalidRequest,
        tonic::Code::DeadlineExceeded => v1::ErrorCode::AgentTimeout,
        tonic::Code::NotFound => v1::ErrorCode::PathNotFound,
        tonic::Code::AlreadyExists | tonic::Code::Aborted => v1::ErrorCode::AlreadyExists,
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            v1::ErrorCode::PermissionDenied
        }
        tonic::Code::ResourceExhausted => v1::ErrorCode::ResourceExhausted,
        tonic::Code::FailedPrecondition => v1::ErrorCode::PreconditionFailed,
        tonic::Code::Unimplemented => v1::ErrorCode::Unsupported,
        tonic::Code::Unavailable => v1::ErrorCode::AgentUnavailable,
        tonic::Code::DataLoss => v1::ErrorCode::AgentProtocolError,
        tonic::Code::Internal | tonic::Code::Unknown | tonic::Code::Ok => v1::ErrorCode::Internal,
    };
    status_with_error(status.code(), code, status.message(), None)
}

pub fn status_with_error(
    grpc_code: tonic::Code,
    error_code: v1::ErrorCode,
    message: impl AsRef<str>,
    retry_after: Option<prost_types::Duration>,
) -> tonic::Status {
    let message = truncate_utf8(message.as_ref(), MAX_DIAGNOSTIC_BYTES);
    tonic::Status::with_details(
        grpc_code,
        message,
        encode_error_detail(&v1::ErrorDetail {
            code: Some(error_code as i32),
            retry_after,
        })
        .into(),
    )
}

fn truncate_utf8(value: &str, maximum: usize) -> String {
    let mut end = value.len().min(maximum);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Checks the current managed-root metric contract at both relay boundaries.
/// This validates observations, not upper geometry predictions or qualification.
pub fn validate_root_storage_metrics(value: &v1::RootStorageMetrics) -> Result<(), String> {
    let required = |field: &str, value: Option<u64>| {
        value.ok_or_else(|| format!("metrics.root_storage.{field} is required"))
    };
    if value.kind != Some(v1::RootStorageKind::LinuxFlatOverlayV1 as i32)
        || value.upper_profile.as_deref()
            != Some(rootfs_spec::UpperProfile::SiloUpperExt4V1.as_str())
    {
        return Err("metrics.root_storage kind/profile is invalid".to_string());
    }
    rootfs_spec::FilesystemUuid::parse(value.upper_uuid.as_deref().unwrap_or_default())
        .map_err(|error| format!("metrics.root_storage.upper_uuid is invalid: {error}"))?;
    let backing = required("upper_backing_bytes", value.upper_backing_bytes)?;
    rootfs_spec::upper_geometry::UpperCapacity::new(backing)
        .map_err(|error| format!("metrics.root_storage.upper_backing_bytes is invalid: {error}"))?;
    let filesystem = required("upper_filesystem_bytes", value.upper_filesystem_bytes)?;
    let tail = required("unusable_tail_bytes", value.unusable_tail_bytes)?;
    let overhead = required("filesystem_overhead_bytes", value.filesystem_overhead_bytes)?;
    let usable = required("upper_usable_bytes", value.upper_usable_bytes)?;
    let used = required("upper_used_bytes", value.upper_used_bytes)?;
    let free = required("upper_free_bytes", value.upper_free_bytes)?;
    let available = required("upper_available_bytes", value.upper_available_bytes)?;
    let total_inodes = required("upper_total_inodes", value.upper_total_inodes)?;
    let free_inodes = required("upper_free_inodes", value.upper_free_inodes)?;
    let available_inodes = required("upper_available_inodes", value.upper_available_inodes)?;
    let lower = required(
        "shared_lower_logical_bytes",
        value.shared_lower_logical_bytes,
    )?;
    vm_spec::DiskGeometry {
        length: lower,
        logical_sector_size: 512,
    }
    .validate()
    .map_err(|error| {
        format!("metrics.root_storage.shared_lower_logical_bytes is invalid: {error}")
    })?;
    if filesystem == 0
        || filesystem % u64::from(rootfs_spec::upper_geometry::BLOCK_SIZE) != 0
        || filesystem.checked_add(tail) != Some(backing)
        || usable.checked_add(overhead) != Some(filesystem)
        || used.checked_add(free) != Some(usable)
        || available > free
        || total_inodes == 0
        || free_inodes > total_inodes
        || available_inodes > free_inodes
    {
        return Err("metrics.root_storage accounting is inconsistent".to_string());
    }
    let temporary = value
        .temporary_directory
        .as_ref()
        .ok_or_else(|| "metrics.root_storage.temporary_directory is required".to_string())?;
    validate_temporary_directory_metrics(temporary)?;
    if temporary.kind == Some(v1::TemporaryDirectoryKind::Upper as i32)
        && temporary.capacity_bytes != Some(usable)
    {
        return Err("metrics.root_storage disk-backed /tmp must share upper capacity".to_string());
    }
    Ok(())
}

/// Validates actual `/tmp` accounting without inventing persistence for OTHER.
pub fn validate_temporary_directory_metrics(
    value: &v1::TemporaryDirectoryMetrics,
) -> Result<(), String> {
    let required = |field: &str, value: Option<u64>| {
        value.ok_or_else(|| format!("metrics.temporary_directory.{field} is required"))
    };
    let capacity = required("capacity_bytes", value.capacity_bytes)?;
    let used = required("used_bytes", value.used_bytes)?;
    let free = required("free_bytes", value.free_bytes)?;
    let available = required("available_bytes", value.available_bytes)?;
    if used.checked_add(free) != Some(capacity) || available > free {
        return Err("metrics.temporary_directory accounting is inconsistent".to_string());
    }
    let expected = match value
        .kind
        .and_then(|kind| v1::TemporaryDirectoryKind::try_from(kind).ok())
    {
        Some(v1::TemporaryDirectoryKind::Upper) => (Some(true), Some(false)),
        Some(v1::TemporaryDirectoryKind::Tmpfs) => (Some(false), Some(true)),
        Some(v1::TemporaryDirectoryKind::Other) => (None, None),
        _ => return Err("metrics.temporary_directory.kind is invalid".to_string()),
    };
    if (value.persistent, value.memory_charged) != expected {
        return Err(
            "metrics.temporary_directory persistence/memory charging is inconsistent".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use prost_types::FileDescriptorSet;

    use crate::{
        decode_error_detail, encode_error_detail, parse_guest_port_args, v1, CHUNK_64_KIB,
        DEFAULT_DIRECTORY_PAGE_SIZE, DEFAULT_GUEST_CONTROL_PORT, FILE_DESCRIPTOR_SET,
        FORWARD_VSOCK_PORT, MAX_AGENT_IP_ADDRESSES, MAX_CODE_BYTES, MAX_CURSOR_BYTES,
        MAX_DIAGNOSTIC_BYTES, MAX_DIRECTORY_PAGE_SIZE, MAX_FILENAME_BYTES, MAX_INFO_BYTES,
        MAX_METRIC_ARRAY_ENTRIES, MAX_PATH_BYTES, MAX_PROBED_INIT_PATHS, MAX_PROVISIONING_STEPS,
        STRUCTURED_16_MIB,
    };

    #[test]
    fn guest_port_args_parse_configured_port() {
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda", "silo.guest.port=7001"]),
            7001
        );
    }

    #[test]
    fn guest_port_args_fall_back_on_missing_or_invalid_port() {
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda"]),
            DEFAULT_GUEST_CONTROL_PORT
        );
        assert_eq!(
            parse_guest_port_args(["root=/dev/vda", "silo.guest.port=nope"]),
            DEFAULT_GUEST_CONTROL_PORT
        );
    }

    #[test]
    fn guest_port_args_reject_out_of_range_port() {
        assert_eq!(
            parse_guest_port_args(["silo.guest.port=0", "silo.guest.port=7001"]),
            7001
        );
        assert_eq!(
            parse_guest_port_args(["silo.guest.port=65536"]),
            DEFAULT_GUEST_CONTROL_PORT
        );
    }

    #[test]
    fn byte_chunks_use_bytes() {
        let chunk = v1::ByteChunk {
            data: Some(bytes::Bytes::from_static(b"chunk")),
        };
        assert_eq!(chunk.data.as_deref(), Some(b"chunk".as_slice()));
    }

    #[test]
    fn forward_tokens_use_bytes() {
        let token = bytes::Bytes::from_static(b"0123456789abcdef");
        assert_eq!(
            v1::ListenRequest {
                listen: "tcp:127.0.0.1:80".to_string(),
                token: token.clone(),
                unix_mode: None,
            }
            .token,
            token
        );
    }

    #[test]
    fn forward_descriptor_field_numbers_are_stable() {
        let descriptors =
            FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptors");
        let message = |name: &str| {
            descriptors
                .file
                .iter()
                .flat_map(|file| &file.message_type)
                .find(|message| message.name.as_deref() == Some(name))
                .expect("message in descriptor")
        };
        let fields = |name: &str| {
            message(name)
                .field
                .iter()
                .map(|field| {
                    (
                        field.name.as_deref().expect("field name"),
                        field.number.expect("field number"),
                    )
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(
            fields("ForwardStatus"),
            [
                ("forward", 1),
                ("direction", 2),
                ("scope", 3),
                ("state", 4),
                ("bound", 5),
                ("active_connections", 6),
                ("refused_connections", 7),
                ("error", 8),
            ]
        );
        assert!(fields("EnabledAgent").contains(&("services", 4)));
    }

    #[test]
    fn forward_error_codes_are_stable() {
        assert_eq!(v1::ErrorCode::ForwardInvalid as i32, 25);
        assert_eq!(v1::ErrorCode::ForwardAddressInUse as i32, 26);
        assert_eq!(v1::ErrorCode::ForwardUnsupported as i32, 27);
        assert_eq!(v1::ErrorCode::ForwardLimit as i32, 28);
    }

    #[test]
    fn forward_vsock_port_is_reserved() {
        assert_eq!(FORWARD_VSOCK_PORT, 1028);
        assert_ne!(FORWARD_VSOCK_PORT, DEFAULT_GUEST_CONTROL_PORT);
    }

    #[test]
    fn execution_binary_payloads_use_bytes() {
        let data = bytes::Bytes::from_static(b"payload");
        assert_eq!(v1::StdinData { data: data.clone() }.data, data);
        assert_eq!(v1::GuestProcessStdout { data: data.clone() }.data, data);
        assert_eq!(v1::GuestProcessStderr { data: data.clone() }.data, data);
        assert_eq!(
            v1::GuestProcessTerminalOutput { data: data.clone() }.data,
            data
        );
        assert_eq!(v1::ExecutionStdout { data: data.clone() }.data, data);
        assert_eq!(v1::ExecutionStderr { data: data.clone() }.data, data);
        assert_eq!(
            v1::ExecutionTerminalOutput { data: data.clone() }.data,
            data
        );
    }

    #[test]
    fn execute_methods_are_bidirectional() {
        let descriptors =
            FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptors");
        for name in ["VmExecutionService", "GuestProcessService"] {
            let service = descriptors
                .file
                .iter()
                .flat_map(|file| &file.service)
                .find(|service| service.name.as_deref() == Some(name))
                .expect("execution service in descriptor");
            let execute = service
                .method
                .iter()
                .find(|method| method.name.as_deref() == Some("Execute"))
                .expect("Execute method in descriptor");
            assert_eq!(execute.client_streaming, Some(true), "{name}.Execute");
            assert_eq!(execute.server_streaming, Some(true), "{name}.Execute");
        }
    }

    #[test]
    fn protocol_limits_match_the_wire_contract() {
        assert_eq!(CHUNK_64_KIB, 64 * 1024);
        assert_eq!(STRUCTURED_16_MIB, 16 * 1024 * 1024);
        assert_eq!(MAX_PATH_BYTES, 4095);
        assert_eq!(MAX_FILENAME_BYTES, 255);
        assert_eq!(MAX_INFO_BYTES, 1024);
        assert_eq!(MAX_CODE_BYTES, 128);
        assert_eq!(MAX_DIAGNOSTIC_BYTES, 4096);
        assert_eq!(MAX_CURSOR_BYTES, 8 * 1024);
        assert_eq!(MAX_AGENT_IP_ADDRESSES, 256);
        assert_eq!(MAX_PROBED_INIT_PATHS, 64);
        assert_eq!(MAX_PROVISIONING_STEPS, 256);
        assert_eq!(MAX_METRIC_ARRAY_ENTRIES, 1024);
        assert_eq!(DEFAULT_DIRECTORY_PAGE_SIZE, 256);
        assert_eq!(MAX_DIRECTORY_PAGE_SIZE, 1024);
    }

    #[test]
    fn error_detail_round_trips() {
        let detail = v1::ErrorDetail {
            code: Some(v1::ErrorCode::PathNotFound as i32),
            retry_after: Some(prost_types::Duration {
                seconds: 3,
                nanos: 0,
            }),
        };

        assert_eq!(
            decode_error_detail(&encode_error_detail(&detail)).expect("decode error"),
            detail
        );
    }

    #[test]
    fn application_statuses_receive_stable_details() {
        let status = crate::detailed_status(tonic::Status::not_found("missing"));
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(
            decode_error_detail(status.details())
                .expect("decode detail")
                .code,
            Some(v1::ErrorCode::PathNotFound as i32)
        );
    }

    #[test]
    fn reflection_descriptors_only_advertise_admitted_services() {
        let descriptors = crate::reflection_descriptor_set(&[
            "silo.v1.VmMonitorService",
            "silo.v1.GuestFilesystemService",
        ])
        .expect("filter descriptors");
        let services = descriptors
            .file
            .iter()
            .flat_map(|file| {
                let package = file.package.as_deref().unwrap_or_default();
                file.service.iter().filter_map(move |service| {
                    service
                        .name
                        .as_deref()
                        .map(|name| format!("{package}.{name}"))
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            services,
            ["silo.v1.GuestFilesystemService", "silo.v1.VmMonitorService"]
        );
    }
    fn root_metrics() -> v1::RootStorageMetrics {
        v1::RootStorageMetrics {
            kind: Some(v1::RootStorageKind::LinuxFlatOverlayV1 as i32),
            upper_profile: Some("silo-upper-ext4-v1".into()),
            upper_uuid: Some("12345678-1234-4234-8234-123456789abc".into()),
            upper_backing_bytes: Some(134_221_824),
            upper_filesystem_bytes: Some(134_217_728),
            unusable_tail_bytes: Some(4096),
            filesystem_overhead_bytes: Some(8_388_608),
            upper_usable_bytes: Some(125_829_120),
            upper_used_bytes: Some(83_886_080),
            upper_free_bytes: Some(41_943_040),
            upper_available_bytes: Some(33_554_432),
            upper_total_inodes: Some(8192),
            upper_free_inodes: Some(0),
            upper_available_inodes: Some(0),
            shared_lower_logical_bytes: Some(4_831_838_208),
            temporary_directory: Some(v1::TemporaryDirectoryMetrics {
                kind: Some(v1::TemporaryDirectoryKind::Tmpfs as i32),
                capacity_bytes: Some(1_048_576),
                used_bytes: Some(4096),
                free_bytes: Some(1_044_480),
                available_bytes: Some(1_044_480),
                persistent: Some(false),
                memory_charged: Some(true),
            }),
        }
    }

    #[test]
    fn root_metrics_wire_round_trip_preserves_tail_reserved_blocks_and_inode_exhaustion() {
        let metrics = root_metrics();
        crate::validate_root_storage_metrics(&metrics).unwrap();
        let decoded = v1::RootStorageMetrics::decode(metrics.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, metrics);
        assert_ne!(decoded.upper_free_bytes, decoded.upper_available_bytes);
        assert_eq!(decoded.upper_free_inodes, Some(0));
    }

    #[test]
    fn root_metrics_reject_missing_unknown_and_inconsistent_accounting() {
        let mutations: &[fn(&mut v1::RootStorageMetrics)] = &[
            |value| value.kind = None,
            |value| value.kind = Some(999),
            |value| value.upper_profile = Some("other".into()),
            |value| value.upper_uuid = Some("00000000-0000-0000-0000-000000000000".into()),
            |value| value.upper_uuid = Some("12345678-1234-4234-8234-123456789ABC".into()),
            |value| value.upper_backing_bytes = None,
            |value| value.upper_backing_bytes = Some(u64::MAX),
            |value| value.upper_filesystem_bytes = Some(0),
            |value| value.unusable_tail_bytes = Some(u64::MAX),
            |value| value.filesystem_overhead_bytes = Some(u64::MAX),
            |value| value.upper_used_bytes = Some(u64::MAX),
            |value| value.upper_free_bytes = Some(u64::MAX),
            |value| value.upper_available_bytes = value.upper_usable_bytes,
            |value| value.upper_total_inodes = Some(0),
            |value| value.upper_free_inodes = Some(8193),
            |value| value.upper_available_inodes = Some(1),
            |value| value.shared_lower_logical_bytes = Some(0),
            |value| value.shared_lower_logical_bytes = Some(513),
            |value| value.temporary_directory = None,
        ];
        for mutation in mutations {
            let mut metrics = root_metrics();
            mutation(&mut metrics);
            assert!(
                crate::validate_root_storage_metrics(&metrics).is_err(),
                "{metrics:?}"
            );
        }
    }

    #[test]
    fn temporary_metrics_reject_unknown_semantics_and_preserve_zero_free_capacity() {
        let mut temporary = root_metrics().temporary_directory.unwrap();
        temporary.used_bytes = temporary.capacity_bytes;
        temporary.free_bytes = Some(0);
        temporary.available_bytes = Some(0);
        crate::validate_temporary_directory_metrics(&temporary).unwrap();
        temporary.kind = Some(v1::TemporaryDirectoryKind::Other as i32);
        assert!(crate::validate_temporary_directory_metrics(&temporary).is_err());
        temporary.persistent = None;
        temporary.memory_charged = None;
        crate::validate_temporary_directory_metrics(&temporary).unwrap();
        temporary.kind = Some(999);
        assert!(crate::validate_temporary_directory_metrics(&temporary).is_err());
        temporary.kind = Some(v1::TemporaryDirectoryKind::Other as i32);
        temporary.used_bytes = Some(u64::MAX);
        temporary.free_bytes = Some(1);
        assert!(crate::validate_temporary_directory_metrics(&temporary).is_err());
    }

    #[test]
    fn disk_temporary_metrics_share_upper_capacity_not_additional_space() {
        let mut metrics = root_metrics();
        let temporary = metrics.temporary_directory.as_mut().unwrap();
        temporary.kind = Some(v1::TemporaryDirectoryKind::Upper as i32);
        temporary.persistent = Some(true);
        temporary.memory_charged = Some(false);
        assert!(crate::validate_root_storage_metrics(&metrics).is_err());
        let temporary = metrics.temporary_directory.as_mut().unwrap();
        temporary.capacity_bytes = metrics.upper_usable_bytes;
        temporary.used_bytes = metrics.upper_used_bytes;
        temporary.free_bytes = metrics.upper_free_bytes;
        temporary.available_bytes = metrics.upper_available_bytes;
        crate::validate_root_storage_metrics(&metrics).unwrap();
    }
    #[test]
    fn root_metrics_accept_inclusive_capacity_bounds_without_narrowing_tail_alignment() {
        use rootfs_spec::upper_geometry::{
            UpperCapacity, UpperGeometry, MAX_CAPACITY_BYTES, MIN_CAPACITY_BYTES,
        };
        for backing in [
            MIN_CAPACITY_BYTES,
            MIN_CAPACITY_BYTES + 4096,
            134_221_824,
            MAX_CAPACITY_BYTES,
        ] {
            let mut metrics = root_metrics();
            let geometry = UpperGeometry::for_capacity(UpperCapacity::new(backing).unwrap());
            let filesystem = geometry.filesystem_bytes;
            metrics.upper_backing_bytes = Some(backing);
            metrics.upper_filesystem_bytes = Some(filesystem);
            metrics.unusable_tail_bytes = Some(geometry.unusable_tail_bytes);
            metrics.filesystem_overhead_bytes = Some(4096);
            metrics.upper_usable_bytes = Some(filesystem - 4096);
            metrics.upper_used_bytes = Some(filesystem - 4096);
            metrics.upper_free_bytes = Some(0);
            metrics.upper_available_bytes = Some(0);
            crate::validate_root_storage_metrics(&metrics).unwrap();
        }
        for backing in [
            MIN_CAPACITY_BYTES - 4096,
            MAX_CAPACITY_BYTES + 4096,
            MIN_CAPACITY_BYTES + 1,
        ] {
            let mut metrics = root_metrics();
            metrics.upper_backing_bytes = Some(backing);
            assert!(crate::validate_root_storage_metrics(&metrics).is_err());
        }
    }
}

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

#[cfg(test)]
mod tests {
    use prost::Message;
    use prost_types::FileDescriptorSet;

    use crate::{
        decode_error_detail, encode_error_detail, parse_guest_port_args, v1, CHUNK_64_KIB,
        DEFAULT_DIRECTORY_PAGE_SIZE, DEFAULT_GUEST_CONTROL_PORT, FILE_DESCRIPTOR_SET,
        MAX_AGENT_IP_ADDRESSES, MAX_CODE_BYTES, MAX_CURSOR_BYTES, MAX_DIAGNOSTIC_BYTES,
        MAX_DIRECTORY_PAGE_SIZE, MAX_FILENAME_BYTES, MAX_INFO_BYTES, MAX_METRIC_ARRAY_ENTRIES,
        MAX_PATH_BYTES, MAX_PROBED_INIT_PATHS, MAX_PROVISIONING_STEPS, STRUCTURED_16_MIB,
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
    fn descriptor_inventory_is_complete_and_source_free() {
        let descriptors =
            FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("decode descriptors");
        let files: Vec<_> = descriptors
            .file
            .iter()
            .filter_map(|file| file.name.as_deref())
            .collect();
        assert!(files.contains(&"common.proto"));
        assert!(files.contains(&"errors.proto"));
        assert!(files.contains(&"filesystem.proto"));
        assert!(files.contains(&"guest.proto"));
        assert!(files.contains(&"vm_monitor.proto"));
        assert!(descriptors
            .file
            .iter()
            .all(|file| file.source_code_info.is_none()));

        let service_methods = |service_name: &str| {
            descriptors
                .file
                .iter()
                .flat_map(|file| &file.service)
                .find(|service| service.name.as_deref() == Some(service_name))
                .expect("service in descriptor")
                .method
                .iter()
                .filter_map(|method| method.name.as_deref())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            service_methods("VmMonitorService"),
            ["GetStatus", "WaitReady", "GetMetrics"]
        );
        assert_eq!(
            service_methods("VmAccessService"),
            ["OpenSsh", "OpenSerial"]
        );
        assert_eq!(
            service_methods("GuestAgentService"),
            ["GetStatus", "WatchStatus", "GetMetrics", "WatchMetrics"]
        );
        assert_eq!(
            service_methods("GuestFilesystemService"),
            [
                "GetEntry",
                "RemoveEntry",
                "DownloadFile",
                "UploadFile",
                "ListDirectory",
                "CreateDirectory"
            ]
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
}

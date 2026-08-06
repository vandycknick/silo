use std::io;

use serde::Serialize;
use uuid::Uuid;

pub(crate) const VMMON_START_REQUEST_VERSION: u32 = 1;
pub(crate) const VMMON_START_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonStartRequest {
    version: u32,
    machine_id: String,
    machine_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_command: Option<VmmonStartupCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonStartupCommand {
    pub(crate) execution_id: Uuid,
    pub(crate) process: VmmonProcessSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonProcessSpec {
    pub(crate) argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) working_directory: Option<String>,
    pub(crate) environment: Vec<VmmonEnvironmentVariable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VmmonEnvironmentVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl VmmonStartRequest {
    pub(crate) fn new(
        machine_id: impl Into<String>,
        machine_run_id: impl Into<String>,
        startup_command: Option<VmmonStartupCommand>,
    ) -> Self {
        Self {
            version: VMMON_START_REQUEST_VERSION,
            machine_id: machine_id.into(),
            machine_run_id: machine_run_id.into(),
            startup_command,
        }
    }
}

pub(crate) fn encode_start_request(request: &VmmonStartRequest) -> io::Result<Vec<u8>> {
    let mut encoded = serde_json::to_vec(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    encoded.push(b'\n');
    if encoded.len() > VMMON_START_REQUEST_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "vmmon start request is {} bytes; maximum is {} bytes including newline",
                encoded.len(),
                VMMON_START_REQUEST_MAX_BYTES
            ),
        ));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::vmmon::start_request::{
        encode_start_request, VmmonEnvironmentVariable, VmmonProcessSpec, VmmonStartRequest,
        VmmonStartupCommand, VMMON_START_REQUEST_MAX_BYTES,
    };

    #[test]
    fn idle_request_is_compact_newline_terminated_json() {
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        );
        assert_eq!(
            String::from_utf8(encode_start_request(&request).expect("encode request"))
                .expect("UTF-8 request"),
            "{\"version\":1,\"machineId\":\"01234567-89ab-cdef-0123-456789abcdef\",\"machineRunId\":\"9e7d6ad8-f804-4936-9633-1fd3df6bd7d3\"}\n"
        );
    }

    #[test]
    fn startup_request_preserves_exact_command_values() {
        let execution_id =
            Uuid::parse_str("ed1fe445-bfb7-4fca-a520-c67547d84410").expect("execution UUID");
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(VmmonStartupCommand {
                execution_id,
                process: VmmonProcessSpec {
                    argv: vec!["/usr/bin/tester".to_string(), "--all".to_string()],
                    working_directory: Some("/workspace".to_string()),
                    environment: vec![VmmonEnvironmentVariable {
                        name: "LANG".to_string(),
                        value: "C.UTF-8".to_string(),
                    }],
                    user: Some("1000:1000".to_string()),
                },
            }),
        );
        let encoded = encode_start_request(&request).expect("encode request");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded[..encoded.len() - 1]).expect("parse request");
        assert_eq!(
            value["startupCommand"]["executionId"],
            execution_id.to_string()
        );
        assert_eq!(value["startupCommand"]["process"]["argv"][1], "--all");
        assert!(value["startupCommand"]["process"].get("stdio").is_none());
    }

    #[test]
    fn encoded_limit_includes_the_terminating_newline() {
        let request = request_with_environment_value(String::new());
        let base = encode_start_request(&request)
            .expect("encode base request")
            .len();
        let exact =
            request_with_environment_value("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base));
        assert_eq!(
            encode_start_request(&exact)
                .expect("encode exact limit")
                .len(),
            VMMON_START_REQUEST_MAX_BYTES
        );
        let oversized =
            request_with_environment_value("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base + 1));
        assert!(encode_start_request(&oversized).is_err());
    }

    fn request_with_environment_value(value: String) -> VmmonStartRequest {
        VmmonStartRequest::new(
            Uuid::nil().to_string(),
            Uuid::nil().to_string(),
            Some(VmmonStartupCommand {
                execution_id: Uuid::nil(),
                process: VmmonProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![VmmonEnvironmentVariable {
                        name: "VALUE".to_string(),
                        value,
                    }],
                    user: None,
                },
            }),
        )
    }
}

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
    // Optional additive field within version 1; must stay schema-compatible
    // with vmmon's strict (deny_unknown_fields) reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    virt_backend: Option<VmmonVirtBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rosetta_intent: Option<VmmonRosettaIntent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_directory: Option<std::path::PathBuf>,
    startup_budget_ms: u64,
}

/// Explicit virtualization backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmonVirtBackend {
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scenario: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub(crate) enum VmmonRosettaIntent {
    Disabled {},
    Enabled {},
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
        let startup_budget_ms = if startup_command.is_some() {
            330_000
        } else {
            30_000
        };
        Self {
            version: VMMON_START_REQUEST_VERSION,
            machine_id: machine_id.into(),
            machine_run_id: machine_run_id.into(),
            startup_command,
            virt_backend: None,
            rosetta_intent: None,
            asset_directory: None,
            startup_budget_ms,
        }
    }

    pub(crate) fn with_virt_backend(mut self, virt_backend: Option<VmmonVirtBackend>) -> Self {
        self.virt_backend = virt_backend;
        self
    }

    pub(crate) fn with_rosetta_intent(mut self, intent: VmmonRosettaIntent) -> Self {
        self.rosetta_intent = match intent {
            VmmonRosettaIntent::Disabled {} => None,
            intent => Some(intent),
        };
        self
    }

    pub(crate) fn with_asset_directory(mut self, directory: std::path::PathBuf) -> Self {
        self.asset_directory = Some(directory);
        self
    }

    pub(crate) fn with_startup_budget(mut self, budget: std::time::Duration) -> Self {
        self.startup_budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
        self
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
        encode_start_request, VmmonEnvironmentVariable, VmmonProcessSpec, VmmonRosettaIntent,
        VmmonStartRequest, VmmonStartupCommand, VMMON_START_REQUEST_MAX_BYTES,
    };

    #[test]
    fn disabled_rosetta_carries_only_the_native_startup_budget_addition() {
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        )
        .with_rosetta_intent(VmmonRosettaIntent::Disabled {});
        assert_eq!(
            String::from_utf8(encode_start_request(&request).expect("encode request"))
                .expect("UTF-8 request"),
            "{\"version\":1,\"machineId\":\"01234567-89ab-cdef-0123-456789abcdef\",\"machineRunId\":\"9e7d6ad8-f804-4936-9633-1fd3df6bd7d3\",\"startupBudgetMs\":30000}\n"
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
        assert_eq!(value["startupBudgetMs"], 330_000);
    }

    #[test]
    fn start_request_has_no_host_reclaim_switch() {
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        );
        let encoded = encode_start_request(&request).expect("encode request");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded[..encoded.len() - 1]).expect("parse request");

        assert!(value.get("hostMemoryReclaim").is_none());
    }

    #[test]
    fn rosetta_intent_contains_no_backend_implementation_details() {
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        )
        .with_rosetta_intent(VmmonRosettaIntent::Enabled {});
        let encoded = encode_start_request(&request).expect("encode request");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded[..encoded.len() - 1]).expect("parse request");

        assert_eq!(value["rosettaIntent"]["mode"], "enabled");
        assert!(value["rosettaIntent"].get("profile").is_none());
        assert_eq!(
            value["rosettaIntent"].as_object().map(|value| value.len()),
            Some(1)
        );
    }

    #[test]
    fn runtime_asset_directory_is_generic_on_the_wire() {
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        )
        .with_rosetta_intent(VmmonRosettaIntent::Enabled {});
        let encoded = encode_start_request(&request).expect("encode request");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded[..encoded.len() - 1]).expect("parse request");

        assert_eq!(
            value["rosettaIntent"],
            serde_json::json!({"mode": "enabled"})
        );
        let request = request.with_asset_directory(std::path::PathBuf::from("/runtime/assets"));
        let value = serde_json::to_value(request).expect("serialize runtime directory");
        assert_eq!(value["assetDirectory"], "/runtime/assets");
        assert!(value.get("rosettaProbeAssets").is_none());
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

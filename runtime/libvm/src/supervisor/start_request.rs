use std::io;

use serde::Serialize;
use uuid::Uuid;

pub(crate) const VMM_START_REQUEST_VERSION: u32 = 1;
pub(crate) const VMM_START_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmStartRequest {
    version: u32,
    machine_id: String,
    machine_run_id: String,
    storage_lease: protocol::shutdown::StorageLeaseBinding,
    storage_shutdown: protocol::shutdown::StorageShutdownContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_command: Option<VmmStartupCommand>,
    // Runtime always sends its frozen prospective selection explicitly.
    #[serde(skip_serializing_if = "Option::is_none")]
    virt_backend: Option<VmmVirtBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rosetta_intent: Option<VmmRosettaIntent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_directory: Option<std::path::PathBuf>,
    startup_budget_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    restore: Option<vm_spec::restore::RestoreRequest>,
}

/// Explicit virtualization backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmVirtBackend {
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scenario: Option<std::path::PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scenario_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scenario_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub(crate) enum VmmRosettaIntent {
    Disabled {},
    Enabled {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmStartupCommand {
    pub(crate) execution_id: Uuid,
    pub(crate) process: VmmProcessSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VmmProcessSpec {
    pub(crate) argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) working_directory: Option<String>,
    pub(crate) environment: Vec<VmmEnvironmentVariable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VmmEnvironmentVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl VmmStartRequest {
    pub(crate) fn new(
        machine_id: impl Into<String>,
        machine_run_id: impl Into<String>,
        startup_command: Option<VmmStartupCommand>,
        storage_lease: protocol::shutdown::StorageLeaseBinding,
        storage_shutdown: protocol::shutdown::StorageShutdownContext,
    ) -> Self {
        let startup_budget_ms = if startup_command.is_some() {
            330_000
        } else {
            30_000
        };
        Self {
            version: VMM_START_REQUEST_VERSION,
            machine_id: machine_id.into(),
            machine_run_id: machine_run_id.into(),
            storage_lease,
            storage_shutdown,
            startup_command,
            virt_backend: None,
            rosetta_intent: None,
            asset_directory: None,
            startup_budget_ms,
            restore: None,
        }
    }

    pub(crate) fn with_virt_backend(mut self, virt_backend: Option<VmmVirtBackend>) -> Self {
        self.virt_backend = virt_backend;
        self
    }

    pub(crate) fn with_rosetta_intent(mut self, intent: VmmRosettaIntent) -> Self {
        self.rosetta_intent = match intent {
            VmmRosettaIntent::Disabled {} => None,
            intent => Some(intent),
        };
        self
    }

    pub(crate) fn with_asset_directory(mut self, directory: std::path::PathBuf) -> Self {
        self.asset_directory = Some(directory);
        self
    }

    pub(crate) fn with_restore(
        mut self,
        restore: Option<vm_spec::restore::RestoreRequest>,
    ) -> Self {
        self.restore = restore;
        self
    }

    pub(crate) fn with_startup_budget(mut self, budget: std::time::Duration) -> Self {
        self.startup_budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
        self
    }
}

pub(crate) fn encode_start_request(request: &VmmStartRequest) -> io::Result<Vec<u8>> {
    protocol::shutdown::validate_uuid(&request.machine_id)
        .and_then(|()| protocol::shutdown::validate_uuid(&request.machine_run_id))
        .and_then(|()| request.storage_lease.validate())
        .and_then(|()| {
            request
                .storage_shutdown
                .validate_binding(&request.machine_id, &request.machine_run_id)
        })
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    if let Some(restore) = &request.restore {
        restore
            .validate()
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
        if request.startup_command.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "restore cannot replay a startup command",
            ));
        }
    }
    let mut encoded = serde_json::to_vec(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    encoded.push(b'\n');
    if encoded.len() > VMM_START_REQUEST_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "silo-vmm start request is {}; maximum is {} including newline",
                utils::format_storage_size(encoded.len() as u64),
                utils::format_storage_size(VMM_START_REQUEST_MAX_BYTES as u64)
            ),
        ));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::supervisor::start_request::{
        encode_start_request, VmmEnvironmentVariable, VmmProcessSpec, VmmRosettaIntent,
        VmmStartRequest, VmmStartupCommand, VMM_START_REQUEST_MAX_BYTES,
    };

    fn lease() -> protocol::shutdown::StorageLeaseBinding {
        protocol::shutdown::StorageLeaseBinding {
            operation_id: "33333333-3333-4333-8333-333333333333".into(),
            file_device: 1,
            file_inode: 2,
        }
    }

    fn context() -> protocol::shutdown::StorageShutdownContext {
        protocol::shutdown::StorageShutdownContext {
            version: 1,
            machine_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            run_id: "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3".into(),
            manifest: protocol::shutdown::StorageManifest::Unsupported {
                reason: "fixture has no storage".into(),
            },
        }
    }
    #[test]
    fn start_request_carries_the_exact_trusted_launch_context() {
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
            lease(),
            context(),
        )
        .with_rosetta_intent(VmmRosettaIntent::Disabled {});
        let value = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(
            value["storageShutdown"],
            serde_json::to_value(context()).unwrap()
        );
        assert_eq!(
            value["storageLease"],
            serde_json::to_value(lease()).unwrap()
        );
        assert!(value.get("rosettaIntent").is_none());
    }

    #[test]
    fn startup_request_preserves_exact_command_values() {
        let execution_id =
            Uuid::parse_str("ed1fe445-bfb7-4fca-a520-c67547d84410").expect("execution UUID");
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(VmmStartupCommand {
                execution_id,
                process: VmmProcessSpec {
                    argv: vec!["/usr/bin/tester".to_string(), "--all".to_string()],
                    working_directory: Some("/workspace".to_string()),
                    environment: vec![VmmEnvironmentVariable {
                        name: "LANG".to_string(),
                        value: "C.UTF-8".to_string(),
                    }],
                    user: Some("1000:1000".to_string()),
                },
            }),
            lease(),
            context(),
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
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
            lease(),
            context(),
        );
        let encoded = encode_start_request(&request).expect("encode request");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded[..encoded.len() - 1]).expect("parse request");

        assert!(value.get("hostMemoryReclaim").is_none());
    }

    #[test]
    fn rosetta_intent_contains_no_backend_implementation_details() {
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
            lease(),
            context(),
        )
        .with_rosetta_intent(VmmRosettaIntent::Enabled {});
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
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
            lease(),
            context(),
        )
        .with_rosetta_intent(VmmRosettaIntent::Enabled {});
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
        let exact = request_with_environment_value("x".repeat(VMM_START_REQUEST_MAX_BYTES - base));
        assert_eq!(
            encode_start_request(&exact)
                .expect("encode exact limit")
                .len(),
            VMM_START_REQUEST_MAX_BYTES
        );
        let oversized =
            request_with_environment_value("x".repeat(VMM_START_REQUEST_MAX_BYTES - base + 1));
        assert!(encode_start_request(&oversized).is_err());
    }

    #[test]
    fn start_request_refuses_context_from_another_run_before_handoff() {
        let mut request = request_with_environment_value(String::new());
        request.storage_shutdown.run_id = Uuid::new_v4().to_string();
        assert_eq!(
            encode_start_request(&request).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        request.storage_shutdown = context();
        request.storage_lease.operation_id = Uuid::nil().to_string();
        assert_eq!(
            encode_start_request(&request).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    fn request_with_environment_value(value: String) -> VmmStartRequest {
        VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(VmmStartupCommand {
                execution_id: Uuid::nil(),
                process: VmmProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![VmmEnvironmentVariable {
                        name: "VALUE".to_string(),
                        value,
                    }],
                    user: None,
                },
            }),
            lease(),
            context(),
        )
    }
}

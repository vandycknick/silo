use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{FromRawFd, RawFd};

use serde::{Deserialize, Serialize};

pub(crate) const VMMON_START_REQUEST_VERSION: u32 = 1;
pub(crate) const VMMON_START_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VmmonStartRequest {
    version: u32,
    machine_id: String,
    machine_run_id: String,
    pub(crate) startup_command: Option<StartupCommand>,
    // Optional additive field within version 1: absent means the
    // platform-default backend. NEVER feature-gate this field — both sides of
    // the pipe must parse the same schema regardless of compiled features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) virt_backend: Option<VirtBackendRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rosetta_intent: Option<RosettaIntentRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) asset_directory: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    startup_budget_ms: Option<u64>,
}

/// Explicit virtualization backend selection carried in the start request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VirtBackendRequest {
    /// Backend name: "krun", "vz", or "mock".
    pub(crate) kind: String,
    /// Absolute path to a mock scenario file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scenario: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum RosettaIntentRequest {
    Disabled {},
    Enabled {},
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartupCommand {
    pub(crate) execution_id: String,
    pub(crate) process: StartupProcess,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartupProcess {
    pub(crate) argv: Vec<String>,
    pub(crate) working_directory: Option<String>,
    pub(crate) environment: Vec<StartupEnvironmentVariable>,
    pub(crate) user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartupEnvironmentVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

pub(crate) struct StartRequestPipe {
    file: Option<File>,
}

impl StartRequestPipe {
    pub(crate) fn from_fd(fd: Option<RawFd>) -> io::Result<Self> {
        match fd {
            Some(fd) => {
                crate::startup::set_cloexec(fd, true)?;
                let file = unsafe { File::from_raw_fd(fd) };
                Ok(Self { file: Some(file) })
            }
            None => Ok(Self { file: None }),
        }
    }

    pub(crate) async fn read(
        &mut self,
        expected_machine_id: &str,
        expected_machine_run_id: &str,
    ) -> io::Result<VmmonStartRequest> {
        let Some(file) = self.file.take() else {
            tracing::info!(
                event = "start_request_idle",
                "no inherited start request pipe; using foreground idle mode"
            );
            return validate_start_request(
                VmmonStartRequest {
                    version: VMMON_START_REQUEST_VERSION,
                    machine_id: expected_machine_id.to_string(),
                    machine_run_id: expected_machine_run_id.to_string(),
                    startup_command: None,
                    virt_backend: None,
                    rosetta_intent: None,
                    asset_directory: None,
                    startup_budget_ms: None,
                },
                expected_machine_id,
                expected_machine_run_id,
            );
        };
        tracing::info!(
            event = "start_request_wait",
            "waiting for vmmon start request"
        );
        let expected_machine_id = expected_machine_id.to_string();
        let expected_machine_run_id = expected_machine_run_id.to_string();
        let request = tokio::task::spawn_blocking(move || {
            read_start_request(file, &expected_machine_id, &expected_machine_run_id)
        })
        .await
        .map_err(|error| io::Error::other(format!("join start request reader: {error}")))??;
        tracing::info!(
            event = "start_request_accepted",
            startup_command = request.startup_command.is_some(),
            "vmmon start request accepted"
        );
        Ok(request)
    }
}

fn read_start_request(
    mut file: File,
    expected_machine_id: &str,
    expected_machine_run_id: &str,
) -> io::Result<VmmonStartRequest> {
    let mut encoded = Vec::new();
    file.by_ref()
        .take((VMMON_START_REQUEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    decode_start_request(&encoded, expected_machine_id, expected_machine_run_id)
}

fn decode_start_request(
    encoded: &[u8],
    expected_machine_id: &str,
    expected_machine_run_id: &str,
) -> io::Result<VmmonStartRequest> {
    if encoded.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vmmon start request is empty",
        ));
    }
    if encoded.len() > VMMON_START_REQUEST_MAX_BYTES {
        return Err(invalid_data(format!(
            "vmmon start request exceeds {} bytes",
            VMMON_START_REQUEST_MAX_BYTES
        )));
    }
    if encoded.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vmmon start request is not newline terminated",
        ));
    }
    if encoded[..encoded.len() - 1]
        .iter()
        .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(invalid_data(
            "vmmon start request contains a second record or embedded newline",
        ));
    }
    let request: VmmonStartRequest = serde_json::from_slice(&encoded[..encoded.len() - 1])
        .map_err(|error| invalid_data(format!("parse vmmon start request: {error}")))?;
    validate_start_request(request, expected_machine_id, expected_machine_run_id)
}

fn validate_start_request(
    request: VmmonStartRequest,
    expected_machine_id: &str,
    expected_machine_run_id: &str,
) -> io::Result<VmmonStartRequest> {
    if request.version != VMMON_START_REQUEST_VERSION {
        return Err(invalid_data(format!(
            "unsupported vmmon start request version {}",
            request.version
        )));
    }
    let machine_id = parse_uuid("machineId", &request.machine_id)?;
    let machine_run_id = parse_uuid("machineRunId", &request.machine_run_id)?;
    if machine_id != parse_uuid("expected machine ID", expected_machine_id)? {
        return Err(invalid_data(
            "vmmon start request machineId does not match --id",
        ));
    }
    if machine_run_id != parse_uuid("expected machine-run ID", expected_machine_run_id)? {
        return Err(invalid_data(
            "vmmon start request machineRunId does not match --run-id",
        ));
    }
    if let Some(command) = &request.startup_command {
        parse_uuid("startupCommand.executionId", &command.execution_id)?;
        validate_process(&command.process)?;
    }
    if let Some(backend) = &request.virt_backend {
        validate_backend_request(backend)?;
    }
    if request
        .startup_budget_ms
        .is_some_and(|budget| budget == 0 || budget > 420_000)
    {
        return Err(invalid_data("startupBudgetMs must be in 1..=420000"));
    }
    if request
        .asset_directory
        .as_ref()
        .is_some_and(|path| !path.is_absolute())
    {
        return Err(invalid_data("assetDirectory must be an absolute path"));
    }
    Ok(request)
}

impl VmmonStartRequest {
    pub(crate) fn effective_startup_budget_ms(&self) -> u64 {
        self.startup_budget_ms.unwrap_or_else(|| {
            if self.startup_command.is_some() {
                330_000
            } else {
                30_000
            }
        })
    }
}

fn validate_backend_request(backend: &VirtBackendRequest) -> io::Result<()> {
    match backend.kind.as_str() {
        "mock" => Ok(()),
        "krun" | "vz" if backend.scenario.is_none() => Ok(()),
        "krun" | "vz" => Err(invalid_data(format!(
            "vmmon start request backend {:?} cannot include a mock scenario",
            backend.kind
        ))),
        _ => Err(invalid_data(format!(
            "vmmon start request selected unknown virt backend {:?}",
            backend.kind
        ))),
    }
}

fn validate_process(process: &StartupProcess) -> io::Result<()> {
    if process.argv.is_empty() || process.argv.iter().any(|argument| argument.contains('\0')) {
        return Err(invalid_data(
            "startup command argv must be nonempty and contain no NUL bytes",
        ));
    }
    let mut names = HashSet::new();
    for variable in &process.environment {
        if !valid_environment_name(&variable.name)
            || variable.value.contains('\0')
            || !names.insert(&variable.name)
        {
            return Err(invalid_data(
                "startup command environment contains an invalid or duplicate variable",
            ));
        }
    }
    if process
        .working_directory
        .as_deref()
        .is_some_and(|directory| directory.contains('\0'))
    {
        return Err(invalid_data(
            "startup command workingDirectory contains a NUL byte",
        ));
    }
    if process
        .user
        .as_deref()
        .is_some_and(|user| user.is_empty() || user.contains('\0'))
    {
        return Err(invalid_data(
            "startup command user must be nonempty and contain no NUL bytes",
        ));
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
        })
}

fn parse_uuid(field: &str, value: &str) -> io::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(value)
        .map_err(|error| invalid_data(format!("{field} must be a UUID: {error}")))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::start_request::{
        decode_start_request, RosettaIntentRequest, StartRequestPipe,
        VMMON_START_REQUEST_MAX_BYTES, VMMON_START_REQUEST_VERSION,
    };

    #[tokio::test]
    async fn missing_inherited_pipe_is_explicit_idle_mode() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let mut pipe = StartRequestPipe::from_fd(None).expect("open idle start request");

        let request = pipe
            .read(&machine_id, &run_id)
            .await
            .expect("read idle request");

        assert_eq!(request.machine_id, machine_id);
        assert_eq!(request.machine_run_id, run_id);
        assert!(request.startup_command.is_none());
    }

    #[test]
    fn strict_reader_accepts_idle_and_startup_requests() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let execution_id = Uuid::new_v4().to_string();
        let encoded = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": execution_id,
                "process": {
                    "argv": ["/bin/echo", "hello world"],
                    "workingDirectory": "/workspace",
                    "environment": [{"name": "LANG", "value": "C.UTF-8"}],
                    "user": "1000:1000"
                }
            }
        }));

        let request = decode_start_request(&encoded, &machine_id, &run_id)
            .expect("decode valid startup request");
        assert_eq!(request.effective_startup_budget_ms(), 330_000);
        assert_eq!(
            request
                .startup_command
                .expect("startup command")
                .execution_id,
            execution_id
        );
    }

    #[test]
    fn legacy_requests_derive_budget_from_startup_command_presence() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let idle = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        }));
        let idle = decode_start_request(&idle, &machine_id, &run_id).expect("decode legacy idle");
        assert_eq!(idle.effective_startup_budget_ms(), 30_000);

        let startup = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": Uuid::new_v4().to_string(),
                "process": { "argv": ["true"], "environment": [] }
            }
        }));
        let startup =
            decode_start_request(&startup, &machine_id, &run_id).expect("decode legacy startup");
        assert_eq!(startup.effective_startup_budget_ms(), 330_000);
    }

    #[test]
    fn explicit_startup_budget_must_be_in_the_bounded_range() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        for budget in [0_u64, 420_001] {
            let encoded = encode(json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "startupBudgetMs": budget,
            }));
            assert!(decode_start_request(&encoded, &machine_id, &run_id).is_err());
        }

        let maximum = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupBudgetMs": 420_000,
        }));
        let maximum =
            decode_start_request(&maximum, &machine_id, &run_id).expect("accept maximum budget");
        assert_eq!(maximum.effective_startup_budget_ms(), 420_000);
    }

    #[test]
    fn strict_reader_rejects_removed_host_reclaim_switch() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let encoded = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "hostMemoryReclaim": "auto"
        }));

        assert!(decode_start_request(&encoded, &machine_id, &run_id).is_err());
    }

    #[test]
    fn strict_reader_accepts_only_the_versioned_rosetta_contract() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let request = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "rosettaIntent": { "mode": "enabled" },
            "assetDirectory": "/runtime/assets",
            "startupBudgetMs": 120000
        }));
        let decoded =
            decode_start_request(&request, &machine_id, &run_id).expect("accept Rosetta contract");
        assert_eq!(
            decoded.rosetta_intent,
            Some(RosettaIntentRequest::Enabled {})
        );
        assert_eq!(decoded.effective_startup_budget_ms(), 120_000);
        assert_eq!(
            decoded.asset_directory,
            Some(std::path::PathBuf::from("/runtime/assets"))
        );

        for (intent, expected) in [
            (
                json!({"mode": "disabled"}),
                RosettaIntentRequest::Disabled {},
            ),
            (json!({"mode": "enabled"}), RosettaIntentRequest::Enabled {}),
        ] {
            let encoded = encode(json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "rosettaIntent": intent
            }));
            let decoded = decode_start_request(&encoded, &machine_id, &run_id)
                .expect("accept explicit Rosetta intent");
            assert_eq!(decoded.rosetta_intent, Some(expected));
        }

        for intent in [
            json!({"mode": "krunCaptured", "profile": "future"}),
            json!({"mode": "krunCaptured", "profile": "capturedCompatibilityV1", "data": "00"}),
            json!({"mode": "future"}),
            json!({"mode": "vzNative"}),
            json!({"mode": "enabled", "profile": "capturedCompatibilityV1"}),
        ] {
            let invalid = encode(json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "rosettaIntent": intent
            }));
            assert!(decode_start_request(&invalid, &machine_id, &run_id).is_err());
        }
    }

    #[test]
    fn runtime_directory_must_be_absolute_and_probe_assets_are_not_a_launch_contract() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        for extra in [
            json!({"assetDirectory": "relative/assets"}),
            json!({"rosettaProbeAssets": {"kernel": "/rprobe"}}),
        ] {
            let mut request = json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
            });
            request
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(decode_start_request(&encode(request), &machine_id, &run_id).is_err());
        }
    }

    #[test]
    fn strict_reader_accepts_real_backends_only_without_mock_scenarios() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        for kind in ["krun", "vz"] {
            let request = encode(json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "virtBackend": { "kind": kind }
            }));
            decode_start_request(&request, &machine_id, &run_id).expect("accept real backend");

            let invalid = encode(json!({
                "version": VMMON_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "virtBackend": { "kind": kind, "scenario": "/tmp/mock.json" }
            }));
            assert!(decode_start_request(&invalid, &machine_id, &run_id).is_err());
        }
    }

    #[test]
    fn strict_reader_rejects_framing_and_schema_errors() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let idle = json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        });
        let valid = encode(idle.clone());
        assert!(decode_start_request(&[], &machine_id, &run_id).is_err());
        assert!(decode_start_request(&valid[..valid.len() - 1], &machine_id, &run_id).is_err());
        let mut second = valid.clone();
        second.extend_from_slice(b"{}\n");
        assert!(decode_start_request(&second, &machine_id, &run_id).is_err());
        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"x");
        assert!(decode_start_request(&trailing, &machine_id, &run_id).is_err());
        assert!(decode_start_request(b"{nope}\n", &machine_id, &run_id).is_err());

        let mut unknown = idle.clone();
        unknown["unexpected"] = json!(true);
        assert!(decode_start_request(&encode(unknown), &machine_id, &run_id).is_err());
        let mut unsupported = idle;
        unsupported["version"] = json!(VMMON_START_REQUEST_VERSION + 1);
        assert!(decode_start_request(&encode(unsupported), &machine_id, &run_id).is_err());

        let nested_unknown = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": Uuid::new_v4().to_string(),
                "process": {
                    "argv": ["true"],
                    "environment": [],
                    "unexpected": true
                }
            }
        }));
        assert!(decode_start_request(&nested_unknown, &machine_id, &run_id).is_err());
    }

    #[test]
    fn strict_reader_rejects_identity_mismatch_and_invalid_process() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let other = Uuid::new_v4().to_string();
        let idle = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        }));
        assert!(decode_start_request(&idle, &other, &run_id).is_err());
        assert!(decode_start_request(&idle, &machine_id, &other).is_err());

        let invalid_process = encode(json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": Uuid::new_v4().to_string(),
                "process": {
                    "argv": [],
                    "environment": []
                }
            }
        }));
        assert!(decode_start_request(&invalid_process, &machine_id, &run_id).is_err());
    }

    #[test]
    fn strict_reader_enforces_the_exact_framing_limit() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let base = json!({
            "version": VMMON_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": Uuid::new_v4().to_string(),
                "process": {
                    "argv": ["true"],
                    "environment": [{"name": "VALUE", "value": ""}]
                }
            }
        });
        let base_len = encode(base.clone()).len();
        let mut exact = base.clone();
        exact["startupCommand"]["process"]["environment"][0]["value"] =
            json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len));
        let exact = encode(exact);
        assert_eq!(exact.len(), VMMON_START_REQUEST_MAX_BYTES);
        decode_start_request(&exact, &machine_id, &run_id).expect("accept exact limit");

        let mut oversized = base;
        oversized["startupCommand"]["process"]["environment"][0]["value"] =
            json!("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len + 1));
        assert!(decode_start_request(&encode(oversized), &machine_id, &run_id).is_err());
    }

    fn encode(value: serde_json::Value) -> Vec<u8> {
        let mut encoded = serde_json::to_vec(&value).expect("encode JSON");
        encoded.push(b'\n');
        encoded
    }
}

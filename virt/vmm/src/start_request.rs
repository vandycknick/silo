use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};

use serde::{Deserialize, Serialize};

pub(crate) const VMM_START_REQUEST_VERSION: u32 = 1;
pub(crate) const VMM_START_REQUEST_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VmmStartRequest {
    version: u32,
    machine_id: String,
    machine_run_id: String,
    pub(crate) storage_lease: protocol::shutdown::StorageLeaseBinding,
    pub(crate) storage_shutdown: protocol::shutdown::StorageShutdownContext,
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
    /// ADR 0018 restore inputs: descriptor-only, capability-gated. Present
    /// only on a restore launch; never a cold-start modifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) restore: Option<vm_spec::restore::RestoreRequest>,
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
    /// Exact frozen scenario bytes, supplied by backend selection.
    pub(crate) scenario_json: Option<String>,
    /// Lowercase SHA-256 of scenario_json's UTF-8 bytes.
    pub(crate) scenario_digest: Option<String>,
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
    storage_lease: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

impl StartRequestPipe {
    pub(crate) fn from_fd(fd: Option<RawFd>) -> io::Result<Self> {
        match fd {
            Some(fd) => {
                crate::startup::set_cloexec(fd, true)?;
                let file = unsafe { File::from_raw_fd(fd) };
                Ok(Self {
                    file: Some(file),
                    storage_lease: None,
                })
            }
            None => Ok(Self {
                file: None,
                storage_lease: None,
            }),
        }
    }

    pub(crate) fn with_storage_lease(
        mut self,
        lease: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Self {
        self.storage_lease = Some(lease);
        self
    }

    pub(crate) fn storage_lease(&self) -> io::Result<std::sync::Arc<std::os::fd::OwnedFd>> {
        self.storage_lease
            .clone()
            .ok_or_else(|| invalid_data("missing inherited generation lease"))
    }

    pub(crate) async fn read(
        &mut self,
        expected_machine_id: &str,
        expected_machine_run_id: &str,
    ) -> io::Result<VmmStartRequest> {
        let Some(file) = self.file.take() else {
            return Err(invalid_data(
                "managed launch requires an inherited start request pipe",
            ));
        };
        tracing::info!(
            event = "start_request_wait",
            "waiting for silo-vmm start request"
        );
        use tokio::io::AsyncReadExt;
        let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(file.into())?;
        let mut encoded = Vec::new();
        reader
            .take((VMM_START_REQUEST_MAX_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .await?;
        let request = decode_start_request(&encoded, expected_machine_id, expected_machine_run_id)?;
        let lease = self.storage_lease()?;
        use std::os::fd::AsFd;
        let stat = nix::sys::stat::fstat(lease.as_fd())?;
        if stat.st_dev as u64 != request.storage_lease.file_device
            || stat.st_ino as u64 != request.storage_lease.file_inode
        {
            return Err(invalid_data(
                "storageLease does not match inherited generation lease",
            ));
        }
        tracing::info!(
            event = "start_request_accepted",
            startup_command = request.startup_command.is_some(),
            "silo-vmm start request accepted"
        );
        Ok(request)
    }
}

fn decode_start_request(
    encoded: &[u8],
    expected_machine_id: &str,
    expected_machine_run_id: &str,
) -> io::Result<VmmStartRequest> {
    if encoded.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "silo-vmm start request is empty",
        ));
    }
    if encoded.len() > VMM_START_REQUEST_MAX_BYTES {
        return Err(invalid_data(format!(
            "silo-vmm start request exceeds {} bytes",
            VMM_START_REQUEST_MAX_BYTES
        )));
    }
    if encoded.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "silo-vmm start request is not newline terminated",
        ));
    }
    if encoded[..encoded.len() - 1]
        .iter()
        .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(invalid_data(
            "silo-vmm start request contains a second record or embedded newline",
        ));
    }
    let request: VmmStartRequest = serde_json::from_slice(&encoded[..encoded.len() - 1])
        .map_err(|error| invalid_data(format!("parse silo-vmm start request: {error}")))?;
    validate_start_request(request, expected_machine_id, expected_machine_run_id)
}

fn validate_start_request(
    request: VmmStartRequest,
    expected_machine_id: &str,
    expected_machine_run_id: &str,
) -> io::Result<VmmStartRequest> {
    if request.version != VMM_START_REQUEST_VERSION {
        return Err(invalid_data(format!(
            "unsupported silo-vmm start request version {}",
            request.version
        )));
    }
    let machine_id = parse_uuid("machineId", &request.machine_id)?;
    let machine_run_id = parse_uuid("machineRunId", &request.machine_run_id)?;
    if machine_id != parse_uuid("expected machine ID", expected_machine_id)? {
        return Err(invalid_data(
            "silo-vmm start request machineId does not match --id",
        ));
    }
    if machine_run_id != parse_uuid("expected machine-run ID", expected_machine_run_id)? {
        return Err(invalid_data(
            "silo-vmm start request machineRunId does not match --run-id",
        ));
    }
    request.storage_lease.validate().map_err(invalid_data)?;
    request.storage_shutdown.validate().map_err(invalid_data)?;
    if request.storage_shutdown.machine_id != request.machine_id
        || request.storage_shutdown.run_id != request.machine_run_id
    {
        return Err(invalid_data(
            "storageShutdown identity does not match start request",
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
    if let Some(restore) = &request.restore {
        restore.validate().map_err(invalid_data)?;
        if request.startup_command.is_some() {
            return Err(invalid_data(
                "a restore launch continues the captured workload; it has no startup command",
            ));
        }
        if request
            .virt_backend
            .as_ref()
            .is_some_and(|backend| backend.kind != "krun")
        {
            return Err(invalid_data("restore requires the krun backend"));
        }
        if restore.evidence.machine_id.as_str() == request.machine_id
            || restore.evidence.run_id.as_str() == request.machine_run_id
        {
            return Err(invalid_data(
                "a restore launch needs a new machine and run identity",
            ));
        }
        destination_ssh_ca(restore.ssh_trusted_ca.as_deref())?;
    }
    Ok(request)
}

/// The guest's bound on one OpenSSH public key line.
const MAX_SSH_CA_BYTES: usize = 1024;

/// The destination's public SSH CA a restore launch hands the guest in
/// Activate: one OpenSSH Ed25519 public key line, admitted by the same rule
/// the guest applies. Only pre-allocation inspection may omit it.
pub(crate) fn destination_ssh_ca(value: Option<&str>) -> io::Result<&str> {
    let value =
        value.ok_or_else(|| invalid_data("a restore launch requires restore.sshTrustedCa"))?;
    if value.len() > MAX_SSH_CA_BYTES || value.trim().contains(['\n', '\r']) {
        return Err(invalid_data(
            "restore.sshTrustedCa must be one OpenSSH public key line of at most 1024 bytes",
        ));
    }
    let key = russh::keys::PublicKey::from_openssh(value)
        .map_err(|error| invalid_data(format!("restore.sshTrustedCa: {error}")))?;
    if key.algorithm() != russh::keys::ssh_key::Algorithm::Ed25519 {
        return Err(invalid_data("restore.sshTrustedCa must be an Ed25519 key"));
    }
    Ok(value)
}

impl VmmStartRequest {
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

pub(crate) fn validate_backend_request(backend: &VirtBackendRequest) -> io::Result<()> {
    match backend.kind.as_str() {
        "mock" => {
            match (&backend.scenario, &backend.scenario_json, &backend.scenario_digest) {
                (None, None, None) => Ok(()),
                (Some(path), Some(json), Some(digest)) if path.is_absolute() => {
                    crate::capabilities::validate_scenario_bytes(json.as_bytes(), digest)
                        .map_err(|error| invalid_data(error.to_string()))
                }
                _ => Err(invalid_data(
                    "mock scenario requires an absolute path, scenarioJson and matching scenarioDigest",
                )),
            }
        }
        "krun" | "vz"
            if backend.scenario.is_none()
                && backend.scenario_json.is_none()
                && backend.scenario_digest.is_none() =>
        {
            Ok(())
        }
        "krun" | "vz" => Err(invalid_data(format!(
            "silo-vmm start request backend {:?} cannot include a mock scenario",
            backend.kind
        ))),
        _ => Err(invalid_data(format!(
            "silo-vmm start request selected unknown virt backend {:?}",
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

pub(crate) fn parse_uuid(field: &str, value: &str) -> io::Result<uuid::Uuid> {
    let id = uuid::Uuid::parse_str(value)
        .map_err(|error| invalid_data(format!("{field} must be a UUID: {error}")))?;
    if id.is_nil() {
        return Err(invalid_data(format!("{field} must not be the nil UUID")));
    }
    Ok(id)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use crate::start_request::{
        decode_start_request, destination_ssh_ca, RosettaIntentRequest, StartRequestPipe,
        VMM_START_REQUEST_MAX_BYTES, VMM_START_REQUEST_VERSION,
    };

    #[tokio::test]
    async fn managed_start_requires_an_inherited_request_pipe() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let mut pipe = StartRequestPipe::from_fd(None).expect("construct missing-pipe input");
        assert!(pipe.read(&machine_id, &run_id).await.is_err());
    }

    #[test]
    fn strict_reader_accepts_idle_and_startup_requests() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let execution_id = Uuid::new_v4().to_string();
        let encoded = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
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
    fn current_requests_derive_budget_from_startup_command_presence() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let idle = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        }));
        let idle = decode_start_request(&idle, &machine_id, &run_id).expect("decode current idle");
        assert_eq!(idle.effective_startup_budget_ms(), 30_000);

        let startup = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "startupCommand": {
                "executionId": Uuid::new_v4().to_string(),
                "process": { "argv": ["true"], "environment": [] }
            }
        }));
        let startup =
            decode_start_request(&startup, &machine_id, &run_id).expect("decode current startup");
        assert_eq!(startup.effective_startup_budget_ms(), 330_000);
    }

    #[test]
    fn explicit_startup_budget_must_be_in_the_bounded_range() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        for budget in [0_u64, 420_001] {
            let encoded = encode(json!({
                "version": VMM_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "startupBudgetMs": budget,
            }));
            assert!(decode_start_request(&encoded, &machine_id, &run_id).is_err());
        }

        let maximum = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
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
            "version": VMM_START_REQUEST_VERSION,
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
            "version": VMM_START_REQUEST_VERSION,
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
                "version": VMM_START_REQUEST_VERSION,
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
                "version": VMM_START_REQUEST_VERSION,
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
                "version": VMM_START_REQUEST_VERSION,
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
                "version": VMM_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "virtBackend": { "kind": kind }
            }));
            decode_start_request(&request, &machine_id, &run_id).expect("accept real backend");

            let invalid = encode(json!({
                "version": VMM_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
                "virtBackend": { "kind": kind, "scenario": "/tmp/mock.json" }
            }));
            assert!(decode_start_request(&invalid, &machine_id, &run_id).is_err());
        }
    }

    #[test]
    fn capabilities_start_reader_rejects_matching_nil_machine_and_run_ids() {
        let nil = Uuid::nil().to_string();
        let valid = Uuid::new_v4().to_string();
        for (machine_id, run_id) in [(&nil, &valid), (&valid, &nil)] {
            let request = encode(json!({
                "version": VMM_START_REQUEST_VERSION,
                "machineId": machine_id,
                "machineRunId": run_id,
            }));
            let error =
                decode_start_request(&request, machine_id, run_id).expect_err("nil identity");
            assert!(
                error.to_string().contains("must not be the nil UUID"),
                "{error}"
            );
        }
    }

    #[test]
    fn capabilities_start_scenario_requires_exact_frozen_bytes_and_digest() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let json = "{ }";
        let valid = json!({
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
            "virtBackend": {
                "kind": "mock", "scenario": "/missing/source.json",
                "scenarioJson": json,
                "scenarioDigest": crate::capabilities::scenario_digest(json.as_bytes())
            }
        });
        decode_start_request(&encode(valid.clone()), &machine_id, &run_id)
            .expect("frozen bytes accepted");
        for field in ["scenario", "scenarioJson", "scenarioDigest"] {
            let mut missing = valid.clone();
            missing["virtBackend"]
                .as_object_mut()
                .expect("backend")
                .remove(field);
            assert!(decode_start_request(&encode(missing), &machine_id, &run_id).is_err());
        }
        let mut changed = valid.clone();
        changed["virtBackend"]["scenarioJson"] = json!("{}");
        assert!(decode_start_request(&encode(changed), &machine_id, &run_id).is_err());
        let mut relative = valid;
        relative["virtBackend"]["scenario"] = json!("relative.json");
        assert!(decode_start_request(&encode(relative), &machine_id, &run_id).is_err());
    }

    #[test]
    fn strict_reader_rejects_framing_and_schema_errors() {
        let machine_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let idle = json!({
            "version": VMM_START_REQUEST_VERSION,
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
        unsupported["version"] = json!(VMM_START_REQUEST_VERSION + 1);
        assert!(decode_start_request(&encode(unsupported), &machine_id, &run_id).is_err());

        let nested_unknown = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
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
            "version": VMM_START_REQUEST_VERSION,
            "machineId": machine_id,
            "machineRunId": run_id,
        }));
        assert!(decode_start_request(&idle, &other, &run_id).is_err());
        assert!(decode_start_request(&idle, &machine_id, &other).is_err());

        let invalid_process = encode(json!({
            "version": VMM_START_REQUEST_VERSION,
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
            "version": VMM_START_REQUEST_VERSION,
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
            json!("x".repeat(VMM_START_REQUEST_MAX_BYTES - base_len));
        let exact = encode(exact);
        assert_eq!(exact.len(), VMM_START_REQUEST_MAX_BYTES);
        decode_start_request(&exact, &machine_id, &run_id).expect("accept exact limit");

        let mut oversized = base;
        oversized["startupCommand"]["process"]["environment"][0]["value"] =
            json!("x".repeat(VMM_START_REQUEST_MAX_BYTES - base_len + 1));
        assert!(decode_start_request(&encode(oversized), &machine_id, &run_id).is_err());
    }

    fn encode(mut value: serde_json::Value) -> Vec<u8> {
        value["storageLease"] = json!({
            "operationId": "33333333-3333-4333-8333-333333333333",
            "fileDevice": 1, "fileInode": 1
        });
        value["storageShutdown"] = json!({
            "version": 1,
            "machineId": value["machineId"],
            "runId": value["machineRunId"],
            "manifest": {"kind": "unsupported", "reason": "unit fixture has no attachments"}
        });
        let mut encoded = serde_json::to_vec(&value).expect("encode JSON");
        encoded.push(b'\n');
        encoded
    }

    #[test]
    fn managed_request_requires_exact_current_storage_metadata() {
        let machine = Uuid::new_v4().to_string();
        let run = Uuid::new_v4().to_string();
        let encoded = encode(json!({"version":1,"machineId":machine,"machineRunId":run}));
        let current: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        for field in ["storageLease", "storageShutdown"] {
            let mut missing = current.clone();
            missing.as_object_mut().unwrap().remove(field);
            let mut bytes = serde_json::to_vec(&missing).unwrap();
            bytes.push(b'\n');
            assert!(decode_start_request(&bytes, &machine, &run).is_err());
        }
        for field in ["operationId", "fileDevice", "fileInode"] {
            let mut missing = current.clone();
            missing["storageLease"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            let mut bytes = serde_json::to_vec(&missing).unwrap();
            bytes.push(b'\n');
            assert!(decode_start_request(&bytes, &machine, &run).is_err());
        }
        let mut wrong = current;
        wrong["storageShutdown"]["runId"] = json!(Uuid::new_v4().to_string());
        let mut bytes = serde_json::to_vec(&wrong).unwrap();
        bytes.push(b'\n');
        assert!(decode_start_request(&bytes, &machine, &run).is_err());
    }

    #[test]
    fn restore_launch_admits_only_one_destination_ed25519_ca_line() {
        let private = russh::keys::PrivateKey::from(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[3; 32]),
        );
        let ed25519 = private.public_key().to_openssh().unwrap();
        assert_eq!(destination_ssh_ca(Some(&ed25519)).unwrap(), ed25519);
        // Only pre-allocation inspection may omit it; a launch never does.
        assert!(destination_ssh_ca(None).is_err());
        for invalid in [
            String::new(),
            "not a key".to_string(),
            format!("{ed25519}\n{ed25519}"),
            format!("{ed25519} {}", "c".repeat(1024)),
            // A private key is never trust.
            private
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        ] {
            assert!(destination_ssh_ca(Some(&invalid)).is_err(), "{invalid:?}");
        }
    }
}

//! Typed smoke-control DTOs and explicit conversions to and from the generated
//! guest protocol. Generated protobuf types do not implement serde; every wire
//! field crossing the JSON boundary is converted here by hand, verbatim.

use protocol::v1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    pub(crate) agent_instance_id: String,
    pub(crate) boot_id: String,
}

impl From<&v1::ExpectedGuestIdentity> for Identity {
    fn from(value: &v1::ExpectedGuestIdentity) -> Self {
        Self {
            machine_id: value.machine_id.clone(),
            run_id: value.run_id.clone(),
            agent_instance_id: value.agent_instance_id.clone(),
            boot_id: value.boot_id.clone(),
        }
    }
}

impl From<&Identity> for v1::ExpectedGuestIdentity {
    fn from(value: &Identity) -> Self {
        Self {
            machine_id: value.machine_id.clone(),
            run_id: value.run_id.clone(),
            agent_instance_id: value.agent_instance_id.clone(),
            boot_id: value.boot_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreezeRef {
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    pub(crate) operation_id: String,
    pub(crate) freeze_epoch: Option<u64>,
}

impl From<&v1::FreezeRef> for FreezeRef {
    fn from(value: &v1::FreezeRef) -> Self {
        Self {
            machine_id: value.machine_id.clone(),
            run_id: value.run_id.clone(),
            operation_id: value.operation_id.clone(),
            freeze_epoch: value.freeze_epoch,
        }
    }
}

impl From<&FreezeRef> for v1::FreezeRef {
    fn from(value: &FreezeRef) -> Self {
        Self {
            machine_id: value.machine_id.clone(),
            run_id: value.run_id.clone(),
            operation_id: value.operation_id.clone(),
            freeze_epoch: value.freeze_epoch,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LifecycleState {
    Unspecified,
    Running,
    Freezing,
    Frozen,
    Activating,
    ActivatedFrozen,
    Thawing,
    Thawed,
    FreezeFailed,
    ActivationFailed,
    Faulted,
}

impl LifecycleState {
    /// Maps a wire value; unknown numbers stay visible through `state_raw`.
    pub(crate) fn from_wire(value: i32) -> Option<Self> {
        use v1::GuestLifecycleState as Wire;
        Some(match Wire::try_from(value).ok()? {
            Wire::Unspecified => Self::Unspecified,
            Wire::Running => Self::Running,
            Wire::Freezing => Self::Freezing,
            Wire::Frozen => Self::Frozen,
            Wire::Activating => Self::Activating,
            Wire::ActivatedFrozen => Self::ActivatedFrozen,
            Wire::Thawing => Self::Thawing,
            Wire::Thawed => Self::Thawed,
            Wire::FreezeFailed => Self::FreezeFailed,
            Wire::ActivationFailed => Self::ActivationFailed,
            Wire::Faulted => Self::Faulted,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Lifecycle {
    pub(crate) state: Option<LifecycleState>,
    pub(crate) state_raw: i32,
    pub(crate) freeze_ref: Option<FreezeRef>,
    pub(crate) workload_roots: Vec<String>,
    pub(crate) observed_frozen_roots: Vec<String>,
    pub(crate) unsupported_reason: Option<String>,
    pub(crate) failure: Option<String>,
    pub(crate) rollback_succeeded: Option<bool>,
    pub(crate) machine_id: String,
    pub(crate) run_id: String,
    pub(crate) activation_id: Option<String>,
}

impl From<&v1::GuestLifecycleStatus> for Lifecycle {
    fn from(value: &v1::GuestLifecycleStatus) -> Self {
        Self {
            state: LifecycleState::from_wire(value.state),
            state_raw: value.state,
            freeze_ref: value.freeze_ref.as_ref().map(FreezeRef::from),
            workload_roots: value.workload_roots.clone(),
            observed_frozen_roots: value.observed_frozen_roots.clone(),
            unsupported_reason: value.unsupported_reason.clone(),
            failure: value.failure.clone(),
            rollback_succeeded: value.rollback_succeeded,
            machine_id: value.machine_id.clone(),
            run_id: value.run_id.clone(),
            activation_id: value.activation_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentIdentity {
    pub(crate) instance_id: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) boot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Boot {
    pub(crate) mode: Option<String>,
    pub(crate) requested_init: Option<String>,
    pub(crate) agent_path: Option<String>,
    pub(crate) agent_pid: Option<u32>,
    pub(crate) agent_is_pid1: Option<bool>,
    pub(crate) message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Ssh {
    pub(crate) backend: String,
    pub(crate) port: u32,
    pub(crate) host_public_key: String,
    pub(crate) config_verified: bool,
    pub(crate) kex_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct System {
    pub(crate) kernel_version: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) ip_addresses: Vec<String>,
}

/// Typed projection of `AgentStatus` plus its complete generated `Debug` value.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Status {
    pub(crate) identity: Option<AgentIdentity>,
    pub(crate) expected_identity: Option<Identity>,
    pub(crate) report_state: Option<String>,
    pub(crate) code: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) boot: Option<Boot>,
    pub(crate) ssh: Option<Ssh>,
    pub(crate) lifecycle: Option<Lifecycle>,
    pub(crate) system: Option<System>,
    pub(crate) provisioning_status: Option<String>,
    pub(crate) debug: String,
}

impl Status {
    pub(crate) fn ready(&self) -> bool {
        self.report_state.as_deref() == Some("ready")
    }
}

impl From<&v1::AgentStatus> for Status {
    fn from(value: &v1::AgentStatus) -> Self {
        let report = value.report.as_ref();
        let lifecycle = report.and_then(|report| report.lifecycle.as_ref());
        let expected_identity = match (value.identity.as_ref(), lifecycle) {
            (Some(identity), Some(lifecycle)) => {
                match (identity.instance_id.as_ref(), identity.boot_id.as_ref()) {
                    (Some(instance), Some(boot)) => Some(Identity {
                        machine_id: lifecycle.machine_id.clone(),
                        run_id: lifecycle.run_id.clone(),
                        agent_instance_id: instance.clone(),
                        boot_id: boot.clone(),
                    }),
                    _ => None,
                }
            }
            _ => None,
        };
        Self {
            identity: value.identity.as_ref().map(|identity| AgentIdentity {
                instance_id: identity.instance_id.clone(),
                version: identity.version.clone(),
                boot_id: identity.boot_id.clone(),
            }),
            expected_identity,
            report_state: report.and_then(|report| report.state).map(|state| {
                enum_name(
                    v1::AgentStatusState::try_from(state)
                        .ok()
                        .map(|value| value.as_str_name()),
                    "AGENT_STATUS_STATE_",
                    state,
                )
            }),
            code: report.and_then(|report| report.code.clone()),
            message: report.and_then(|report| report.message.clone()),
            boot: report
                .and_then(|report| report.boot.as_ref())
                .map(|boot| Boot {
                    mode: boot.mode.map(|mode| {
                        enum_name(
                            v1::GuestBootMode::try_from(mode)
                                .ok()
                                .map(|value| value.as_str_name()),
                            "GUEST_BOOT_MODE_",
                            mode,
                        )
                    }),
                    requested_init: boot.requested_init.clone(),
                    agent_path: boot.agent_path.clone(),
                    agent_pid: boot.agent_pid,
                    agent_is_pid1: boot.agent_is_pid1,
                    message: boot.message.clone(),
                }),
            ssh: report
                .and_then(|report| report.ssh.as_ref())
                .map(|ssh| Ssh {
                    backend: ssh.backend.clone(),
                    port: ssh.port,
                    host_public_key: ssh.host_public_key.clone(),
                    config_verified: ssh.config_verified,
                    kex_verified: ssh.kex_verified,
                }),
            lifecycle: lifecycle.map(Lifecycle::from),
            system: report
                .and_then(|report| report.system.as_ref())
                .map(|system| System {
                    kernel_version: system.kernel_version.clone(),
                    hostname: system.hostname.clone(),
                    ip_addresses: system.ip_addresses.clone(),
                }),
            provisioning_status: report
                .and_then(|report| report.provisioning.as_ref())
                .and_then(|provisioning| provisioning.status)
                .map(|status| {
                    enum_name(
                        v1::ProvisionOverallStatus::try_from(status)
                            .ok()
                            .map(|value| value.as_str_name()),
                        "PROVISION_OVERALL_STATUS_",
                        status,
                    )
                }),
            debug: format!("{value:?}"),
        }
    }
}

/// `AGENT_STATUS_STATE_READY` -> `ready`; unknown wire numbers stay explicit.
pub(crate) fn enum_name(name: Option<&str>, prefix: &str, raw: i32) -> String {
    match name {
        Some(name) => name
            .strip_prefix(prefix)
            .unwrap_or(name)
            .to_ascii_lowercase(),
        None => format!("unknown({raw})"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GrpcCode {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl From<tonic::Code> for GrpcCode {
    fn from(value: tonic::Code) -> Self {
        match value {
            tonic::Code::Ok => Self::Ok,
            tonic::Code::Cancelled => Self::Cancelled,
            tonic::Code::Unknown => Self::Unknown,
            tonic::Code::InvalidArgument => Self::InvalidArgument,
            tonic::Code::DeadlineExceeded => Self::DeadlineExceeded,
            tonic::Code::NotFound => Self::NotFound,
            tonic::Code::AlreadyExists => Self::AlreadyExists,
            tonic::Code::PermissionDenied => Self::PermissionDenied,
            tonic::Code::ResourceExhausted => Self::ResourceExhausted,
            tonic::Code::FailedPrecondition => Self::FailedPrecondition,
            tonic::Code::Aborted => Self::Aborted,
            tonic::Code::OutOfRange => Self::OutOfRange,
            tonic::Code::Unimplemented => Self::Unimplemented,
            tonic::Code::Internal => Self::Internal,
            tonic::Code::Unavailable => Self::Unavailable,
            tonic::Code::DataLoss => Self::DataLoss,
            tonic::Code::Unauthenticated => Self::Unauthenticated,
        }
    }
}

/// An actual typed gRPC failure, including the decoded Silo error detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RpcError {
    pub(crate) code: GrpcCode,
    pub(crate) message: String,
    pub(crate) error_code: Option<String>,
    pub(crate) details_hex: String,
}

impl From<&tonic::Status> for RpcError {
    fn from(status: &tonic::Status) -> Self {
        let error_code = if status.details().is_empty() {
            None
        } else {
            Some(match protocol::decode_error_detail(status.details()) {
                Ok(detail) => match detail.code {
                    Some(code) => v1::ErrorCode::try_from(code)
                        .map(|code| code.as_str_name().to_string())
                        .unwrap_or_else(|_| format!("unknown({code})")),
                    None => "absent".to_string(),
                },
                Err(error) => format!("undecodable({error})"),
            })
        };
        Self {
            code: status.code().into(),
            message: status.message().to_string(),
            error_code,
            details_hex: hex(status.details()),
        }
    }
}

/// A failed bounded observation: either the guest's real RPC status or a
/// harness bound/parse violation. Never conflated with each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Failure {
    Rpc(RpcError),
    Harness(String),
}

impl Failure {
    pub(crate) fn rpc(status: tonic::Status) -> Self {
        Self::Rpc(RpcError::from(&status))
    }
    pub(crate) fn harness(message: impl Into<String>) -> Self {
        Self::Harness(message.into())
    }
    pub(crate) fn not_found(&self) -> bool {
        matches!(self, Self::Rpc(error) if error.code == GrpcCode::NotFound)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExpectRpc {
    #[default]
    Ok,
    Any,
    Error(ExpectedError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedError {
    pub(crate) code: GrpcCode,
    #[serde(default)]
    pub(crate) message_contains: Option<String>,
    #[serde(default)]
    pub(crate) error_code: Option<String>,
}

impl ExpectRpc {
    /// Adds one `rpc_outcome` check comparing the actual outcome with the request.
    pub(crate) fn evaluate(&self, actual: Result<(), &RpcError>, checks: &mut Checks) {
        let (passed, detail) = match (self, actual) {
            (Self::Any, Ok(())) => (true, "ok accepted by any".to_string()),
            (Self::Any, Err(error)) => (true, format!("{:?} accepted by any", error.code)),
            (Self::Ok, Ok(())) => (true, "ok".to_string()),
            (Self::Ok, Err(error)) => (
                false,
                format!("expected ok, got {:?}: {}", error.code, error.message),
            ),
            (Self::Error(expected), Ok(())) => {
                (false, format!("expected {:?}, got ok", expected.code))
            }
            (Self::Error(expected), Err(error)) => {
                let passed = expected.code == error.code
                    && expected
                        .message_contains
                        .as_ref()
                        .is_none_or(|needle| error.message.contains(needle.as_str()))
                    && expected
                        .error_code
                        .as_ref()
                        .is_none_or(|code| error.error_code.as_ref() == Some(code));
                (
                    passed,
                    format!(
                        "expected {:?}/{:?}/{:?}, got {:?}/{:?}: {}",
                        expected.code,
                        expected.error_code,
                        expected.message_contains,
                        error.code,
                        error.error_code,
                        error.message
                    ),
                )
            }
        };
        checks.check("rpc_outcome", passed, detail);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Encoding {
    Utf8,
    Hex,
}

/// Exact observed bytes: UTF-8 when valid, otherwise lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Content {
    pub(crate) encoding: Encoding,
    pub(crate) data: String,
}

impl Content {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self {
                encoding: Encoding::Utf8,
                data: text.to_string(),
            },
            Err(_) => Self {
                encoding: Encoding::Hex,
                data: hex(bytes),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub(crate) name: String,
    pub(crate) passed: bool,
    pub(crate) detail: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Checks(Vec<Check>);

impl Checks {
    pub(crate) fn check(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.0.push(Check {
            name: name.to_string(),
            passed,
            detail: detail.into(),
        });
    }
    pub(crate) fn passed(&self) -> bool {
        self.0.iter().all(|check| check.passed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RpcOutcome {
    Ok,
    Error,
    Discarded,
}

/// Exact request/response record for one unary RPC.
#[derive(Debug, Serialize)]
pub(crate) struct RpcRecord<R> {
    pub(crate) outcome: RpcOutcome,
    pub(crate) started_monotonic_ns: u64,
    pub(crate) finished_monotonic_ns: u64,
    pub(crate) request_debug: String,
    pub(crate) response: Option<R>,
    pub(crate) response_debug: Option<String>,
    pub(crate) error: Option<RpcError>,
    pub(crate) discard: Option<Discard>,
}

impl<R> RpcRecord<R> {
    pub(crate) fn actual(&self) -> Option<Result<(), &RpcError>> {
        match (self.outcome, self.error.as_ref()) {
            (RpcOutcome::Ok, _) => Some(Ok(())),
            (RpcOutcome::Error, Some(error)) => Some(Err(error)),
            _ => None,
        }
    }
}

/// Evidence that a reply was intentionally dropped unread after an
/// independent observation of the guest-side terminal effect.
#[derive(Debug, Serialize)]
pub(crate) struct Discard {
    /// The guest-side effect was independently observed before discarding;
    /// false means the reply arrived first without it (still left unread).
    pub(crate) effect_observed: bool,
    pub(crate) observed: serde_json::Value,
    pub(crate) observed_monotonic_ns: u64,
    pub(crate) reply_task_finished_before_discard: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentVariable {
    pub(crate) name: String,
    pub(crate) value: String,
}

impl From<&EnvironmentVariable> for v1::EnvironmentVariable {
    fn from(value: &EnvironmentVariable) -> Self {
        Self {
            name: value.name.clone(),
            value: value.value.clone(),
        }
    }
}

/// Exactly the generated `ListenRequest`, with the token as hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenRegistration {
    pub(crate) listen: String,
    pub(crate) token_hex: String,
    #[serde(default)]
    pub(crate) unix_mode: Option<u32>,
}

impl ListenRegistration {
    pub(crate) fn to_wire(&self) -> eyre::Result<v1::ListenRequest> {
        Ok(v1::ListenRequest {
            listen: self.listen.clone(),
            token: unhex(&self.token_hex)?.into(),
            unix_mode: self.unix_mode,
        })
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

/// Strict lowercase/uppercase hex without separators.
pub(crate) fn unhex(text: &str) -> eyre::Result<Vec<u8>> {
    eyre::ensure!(text.len().is_multiple_of(2), "hex text has odd length");
    let digit = |byte: u8| -> eyre::Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => eyre::bail!("invalid hex digit"),
        }
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| match pair {
            [high, low] => Ok((digit(*high)? << 4) | digit(*low)?),
            _ => eyre::bail!("hex pair"),
        })
        .collect()
}

/// Host CLOCK_MONOTONIC in nanoseconds, comparable with Python
/// `time.monotonic_ns()` in the orchestrating smoke process.
pub(crate) fn monotonic_ns() -> eyre::Result<u64> {
    // nix exposes clock_gettime only behind its `time` feature, which silo-vmm
    // does not enable; this smoke example must not change dependency features.
    let mut value = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid, exclusively borrowed timespec for this call.
    let result = unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut value) };
    eyre::ensure!(
        result == 0,
        "CLOCK_MONOTONIC: {}",
        std::io::Error::last_os_error()
    );
    let seconds = u64::try_from(value.tv_sec)?;
    let nanos = u64::try_from(value.tv_nsec)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| eyre::eyre!("CLOCK_MONOTONIC overflow"))
}

#[cfg(test)]
mod tests {
    use crate::attach::dto::{
        enum_name, hex, unhex, Checks, Content, Encoding, ExpectRpc, ExpectedError, Failure,
        GrpcCode, LifecycleState, RpcError,
    };

    #[test]
    fn hex_round_trips_and_rejects_malformed_text() {
        let bytes = [0_u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(hex(&bytes), "00017f80ff");
        assert_eq!(unhex("00017F80ff").unwrap(), bytes);
        assert!(unhex("0").is_err());
        assert!(unhex("zz").is_err());
        assert!(unhex("").unwrap().is_empty());
    }

    #[test]
    fn content_keeps_exact_bytes() {
        assert_eq!(
            Content::new(b"tsc\n"),
            Content {
                encoding: Encoding::Utf8,
                data: "tsc\n".into()
            }
        );
        assert_eq!(
            Content::new(&[0xff, 0]),
            Content {
                encoding: Encoding::Hex,
                data: "ff00".into()
            }
        );
    }

    #[test]
    fn lifecycle_wire_mapping_is_total_for_known_values() {
        assert_eq!(
            LifecycleState::from_wire(protocol::v1::GuestLifecycleState::ActivatedFrozen as i32),
            Some(LifecycleState::ActivatedFrozen)
        );
        assert_eq!(LifecycleState::from_wire(99), None);
        assert_eq!(
            serde_json::to_string(&LifecycleState::ActivatedFrozen).unwrap(),
            "\"activated_frozen\""
        );
    }

    #[test]
    fn enum_names_are_stripped_and_unknown_values_explicit() {
        assert_eq!(
            enum_name(Some("AGENT_STATUS_STATE_READY"), "AGENT_STATUS_STATE_", 2),
            "ready"
        );
        assert_eq!(enum_name(None, "X_", 7), "unknown(7)");
    }

    #[test]
    fn rpc_error_decodes_actual_silo_detail() {
        let status = protocol::status_with_error(
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::CursorExpired,
            "cursor has expired",
            None,
        );
        let error = RpcError::from(&status);
        assert_eq!(error.code, GrpcCode::FailedPrecondition);
        assert_eq!(
            error.error_code.as_deref(),
            Some("ERROR_CODE_CURSOR_EXPIRED")
        );
        assert_eq!(error.message, "cursor has expired");
        assert!(!error.details_hex.is_empty());
        let plain = RpcError::from(&tonic::Status::unavailable("gone"));
        assert_eq!(plain.error_code, None);
        assert!(Failure::rpc(tonic::Status::not_found("x")).not_found());
        assert!(!Failure::harness("x").not_found());
    }

    #[test]
    fn expected_rpc_outcomes_are_strict() {
        let error = RpcError::from(&protocol::status_with_error(
            tonic::Code::AlreadyExists,
            protocol::v1::ErrorCode::AlreadyExists,
            "activation attempt is already bound to different input",
            None,
        ));
        let cases = [
            (ExpectRpc::Ok, Ok(()), true),
            (ExpectRpc::Ok, Err(&error), false),
            (ExpectRpc::Any, Err(&error), true),
            (
                ExpectRpc::Error(ExpectedError {
                    code: GrpcCode::AlreadyExists,
                    message_contains: Some("different input".into()),
                    error_code: Some("ERROR_CODE_ALREADY_EXISTS".into()),
                }),
                Err(&error),
                true,
            ),
            (
                ExpectRpc::Error(ExpectedError {
                    code: GrpcCode::FailedPrecondition,
                    message_contains: None,
                    error_code: None,
                }),
                Err(&error),
                false,
            ),
            (
                ExpectRpc::Error(ExpectedError {
                    code: GrpcCode::AlreadyExists,
                    message_contains: None,
                    error_code: None,
                }),
                Ok(()),
                false,
            ),
        ];
        for (expect, actual, passed) in cases {
            let mut checks = Checks::default();
            expect.evaluate(actual, &mut checks);
            assert_eq!(checks.passed(), passed, "{expect:?}");
        }
        let parsed: ExpectRpc = serde_json::from_str("\"ok\"").unwrap();
        assert_eq!(parsed, ExpectRpc::Ok);
        let parsed: ExpectRpc =
            serde_json::from_str(r#"{"error":{"code":"already_exists"}}"#).unwrap();
        assert!(matches!(parsed, ExpectRpc::Error(_)));
        assert!(serde_json::from_str::<ExpectRpc>(r#"{"error":{"code":"x","extra":1}}"#).is_err());
    }
}

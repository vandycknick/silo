use protocol::v1;

use crate::machine::{Machine, MachineRef};
use crate::vmmon::{forward_rpc_error, ForwardClientError, VmmonClientError};
use crate::LibVmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineForwardScope {
    Machine,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineForwardState {
    Pending,
    Active,
    Unsupported,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineForwardErrorDetail {
    Invalid,
    AddressInUse,
    Unsupported,
    Limit,
    PreconditionFailed,
    MonitorStopping,
    BackendUnavailable,
    Other(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineForwardStatus {
    pub forward: forward_spec::Forward,
    pub direction: forward_spec::Direction,
    pub scope: MachineForwardScope,
    pub state: MachineForwardState,
    pub bound: Option<forward_spec::Endpoint>,
    pub active_connections: u32,
    pub refused_connections: u32,
    pub error: Option<MachineForwardErrorDetail>,
}

#[derive(Debug)]
pub struct MachineForwardSession {
    reference: String,
    stream: tonic::Streaming<v1::ForwardStatus>,
}

impl MachineForwardSession {
    pub async fn next_status(&mut self) -> Result<Option<MachineForwardStatus>, LibVmError> {
        self.stream
            .message()
            .await
            .map_err(|status| rejected(self.reference.clone(), forward_rpc_error(status)))?
            .map(MachineForwardStatus::try_from)
            .transpose()
            .map_err(|reason| LibVmError::MonitorProtocol {
                reference: self.reference.clone(),
                message: reason,
            })
    }
}

impl Machine {
    pub async fn open_forward(
        &self,
        forward: forward_spec::Forward,
    ) -> Result<MachineForwardSession, LibVmError> {
        let config = self.running_config().await?;
        let stream = self
            .runtime()
            .vmmon()
            .client(self.machine_id())
            .open_forward(forward)
            .await
            .map_err(|error| map_client_error(config.name.clone(), error))?;
        Ok(MachineForwardSession {
            reference: config.name,
            stream,
        })
    }

    pub async fn list_forwards(&self) -> Result<Vec<MachineForwardStatus>, LibVmError> {
        let runtime = self.runtime();
        let config = runtime
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .list_forwards()
            .await
            .map_err(|error| map_client_error(config.name.clone(), error))?
            .into_iter()
            .map(MachineForwardStatus::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|message| LibVmError::MonitorProtocol {
                reference: config.name,
                message,
            })
    }
}

fn map_client_error(reference: String, error: VmmonClientError) -> LibVmError {
    match error {
        VmmonClientError::Connection(message) => {
            LibVmError::MonitorConnection { reference, message }
        }
        VmmonClientError::Protocol(message) => LibVmError::MonitorProtocol { reference, message },
        VmmonClientError::Forward(error) => rejected(reference, error),
    }
}

fn rejected(reference: String, error: ForwardClientError) -> LibVmError {
    LibVmError::ForwardRejected {
        reference,
        grpc_code: error.grpc_code,
        detail: error.detail.map(MachineForwardErrorDetail::from),
        reason: error.reason,
    }
}

impl TryFrom<v1::ForwardStatus> for MachineForwardStatus {
    type Error = String;

    fn try_from(value: v1::ForwardStatus) -> Result<Self, Self::Error> {
        let forward = value
            .forward
            .ok_or_else(|| "forward status is missing forward".to_string())?;
        let mode = forward
            .unix_mode
            .map(forward_spec::UnixMode::try_from)
            .transpose()
            .map_err(|error| format!("forward status has invalid Unix mode: {error}"))?;
        let forward =
            forward_spec::Forward {
                name: forward.name,
                listen: forward.listen.parse().map_err(|error| {
                    format!("forward status has invalid listen endpoint: {error}")
                })?,
                connect: forward.connect.parse().map_err(|error| {
                    format!("forward status has invalid connect endpoint: {error}")
                })?,
                mode,
            };
        let expected_direction = forward
            .direction()
            .map_err(|error| format!("forward status contains an invalid forward: {error}"))?;
        let direction = match required_enum::<v1::ForwardDirection>(value.direction, "direction")? {
            v1::ForwardDirection::Inbound => forward_spec::Direction::Inbound,
            v1::ForwardDirection::Outbound => forward_spec::Direction::Outbound,
            v1::ForwardDirection::Unspecified => {
                return Err("forward status has unspecified direction".to_string())
            }
        };
        if direction != expected_direction {
            return Err("forward status direction does not match its endpoints".to_string());
        }
        let scope = match required_enum::<v1::ForwardScope>(value.scope, "scope")? {
            v1::ForwardScope::Machine => MachineForwardScope::Machine,
            v1::ForwardScope::Session => MachineForwardScope::Session,
            v1::ForwardScope::Unspecified => {
                return Err("forward status has unspecified scope".to_string())
            }
        };
        let state = match required_enum::<v1::ForwardState>(value.state, "state")? {
            v1::ForwardState::Pending => MachineForwardState::Pending,
            v1::ForwardState::Active => MachineForwardState::Active,
            v1::ForwardState::Unsupported => MachineForwardState::Unsupported,
            v1::ForwardState::Closed => MachineForwardState::Closed,
            v1::ForwardState::Unspecified => {
                return Err("forward status has unspecified state".to_string())
            }
        };
        let bound = value
            .bound
            .map(|bound| bound.parse::<forward_spec::Endpoint>())
            .transpose()
            .map_err(|error| format!("forward status has invalid bound endpoint: {error}"))?;
        Ok(Self {
            forward,
            direction,
            scope,
            state,
            bound,
            active_connections: value
                .active_connections
                .ok_or_else(|| "forward status is missing active_connections".to_string())?,
            refused_connections: value
                .refused_connections
                .ok_or_else(|| "forward status is missing refused_connections".to_string())?,
            error: value
                .error
                .map(|error| {
                    error
                        .code
                        .map(MachineForwardErrorDetail::from)
                        .ok_or_else(|| "forward status error is missing its code".to_string())
                })
                .transpose()?,
        })
    }
}

fn required_enum<T>(value: Option<i32>, field: &str) -> Result<T, String>
where
    T: TryFrom<i32>,
{
    let value = value.ok_or_else(|| format!("forward status is missing {field}"))?;
    T::try_from(value).map_err(|_| format!("forward status has unknown {field} value {value}"))
}

impl From<i32> for MachineForwardErrorDetail {
    fn from(value: i32) -> Self {
        match v1::ErrorCode::try_from(value) {
            Ok(v1::ErrorCode::ForwardInvalid) => Self::Invalid,
            Ok(v1::ErrorCode::ForwardAddressInUse) => Self::AddressInUse,
            Ok(v1::ErrorCode::ForwardUnsupported) => Self::Unsupported,
            Ok(v1::ErrorCode::ForwardLimit) => Self::Limit,
            Ok(v1::ErrorCode::PreconditionFailed) => Self::PreconditionFailed,
            Ok(v1::ErrorCode::MonitorStopping) => Self::MonitorStopping,
            Ok(v1::ErrorCode::BackendUnavailable) => Self::BackendUnavailable,
            _ => Self::Other(value),
        }
    }
}

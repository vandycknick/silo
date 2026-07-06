use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use protocol::negotiate::{ClientUpgradeStreamError, Negotiate, RejectCode, Upgrade};
use protocol::v1::vm_monitor_service_client::VmMonitorServiceClient;
use protocol::v1::{
    InspectRequest, InspectResponse, PingRequest, PingResponse, WatchStatusRequest,
};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tonic::transport::Endpoint;
use tower::service_fn;

pub const DEFAULT_GUEST_READINESS_TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(Debug, Clone)]
pub(crate) struct VmmonClient {
    socket_path: PathBuf,
}

impl VmmonClient {
    pub(crate) fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub(crate) async fn wait_for_shell_with_timeout(
        &self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;

        loop {
            match probe_shell_once(&self.socket_path).await {
                Ok(()) => return Ok(()),
                Err(ProbeError::Retryable(message)) => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "timed out waiting {:?} for guest shell readiness via vm monitor (last error: {})",
                            timeout, message
                        ));
                    }

                    tokio::time::sleep(poll_interval).await;
                }
                Err(ProbeError::Fatal(message)) => return Err(message),
            }
        }
    }

    pub(crate) async fn wait_for_guest_running(&self, timeout: Duration) -> Result<(), String> {
        let stream = connect_vm_monitor_stream(&self.socket_path).await?;
        let mut client = vm_monitor_client(stream)
            .await
            .map_err(|err| format!("connect vm monitor rpc client: {err}"))?;

        let mut updates = client
            .watch_status(WatchStatusRequest {})
            .await
            .map_err(|err| format!("vm monitor watch_status rpc failed: {err}"))?
            .into_inner();

        let deadline = Instant::now() + timeout;
        let mut vm_running_seen = false;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "timed out after {:?} waiting for guest running event",
                    timeout
                ));
            }

            let update = tokio::time::timeout(remaining, updates.message())
                .await
                .map_err(|_| "timed out waiting for status updates".to_string())?
                .map_err(|err| format!("watch_status stream failed: {err}"))?;

            let Some(update) = update else {
                return Err("watch_status stream closed before guest became ready".to_string());
            };

            let source = protocol::v1::StatusSource::try_from(update.source)
                .unwrap_or(protocol::v1::StatusSource::Unspecified);
            let state = protocol::v1::LifecycleState::try_from(update.state)
                .unwrap_or(protocol::v1::LifecycleState::Unspecified);

            if source == protocol::v1::StatusSource::Vm {
                match state {
                    protocol::v1::LifecycleState::Running => vm_running_seen = true,
                    protocol::v1::LifecycleState::Stopped | protocol::v1::LifecycleState::Error => {
                        return Err(format!("vm entered {:?} before guest running event", state));
                    }
                    _ => {}
                }
            }

            if source == protocol::v1::StatusSource::Guest {
                match state {
                    protocol::v1::LifecycleState::Running if vm_running_seen => return Ok(()),
                    protocol::v1::LifecycleState::Running => {
                        return Err(
                            "received guest running event before vm running event".to_string()
                        )
                    }
                    protocol::v1::LifecycleState::Error => {
                        return Err(format!("guest readiness failed: {}", update.message));
                    }
                    _ => {}
                }
            }
        }
    }

    pub(crate) async fn inspect(&self) -> Result<InspectResponse, String> {
        let stream = connect_vm_monitor_stream(&self.socket_path).await?;
        let mut client = vm_monitor_client(stream)
            .await
            .map_err(|err| format!("connect vm monitor rpc client: {err}"))?;

        let response = client
            .inspect(InspectRequest {})
            .await
            .map_err(|err| format!("vm monitor inspect rpc failed: {err}"))?;

        Ok(response.into_inner())
    }

    pub(crate) async fn open_serial_stream(&self) -> Result<UnixStream, String> {
        connect_upgrade_stream(&self.socket_path, Upgrade::Serial, "serial").await
    }

    pub(crate) async fn open_shell_stream(&self) -> Result<UnixStream, String> {
        connect_upgrade_stream(&self.socket_path, Upgrade::Shell, "shell").await
    }
}

async fn connect_upgrade_stream(
    socket_path: &Path,
    upgrade: Upgrade,
    label: &str,
) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(socket_path).await.map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            format!(
                "vmmon_unreachable: control socket {} is missing, make sure the VM is running",
                socket_path.display()
            )
        } else {
            format!(
                "connect control socket failed: {} ({})",
                err,
                socket_path.display()
            )
        }
    })?;

    match Negotiate::client_upgrade_stream_v1(stream, upgrade).await {
        Ok(stream) => Ok(stream),
        Err(ClientUpgradeStreamError::Reject(reject)) => {
            Err(render_reject_error(reject.code, &reject.message))
        }
        Err(ClientUpgradeStreamError::Io(err)) => {
            Err(format!("negotiate {label} stream failed: {err}"))
        }
    }
}

enum ProbeError {
    Retryable(String),
    Fatal(String),
}

async fn probe_shell_once(socket_path: &Path) -> Result<(), ProbeError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| classify_io_error("connect Negotiate socket", err))?;

    match Negotiate::client_upgrade_stream_v1(stream, Upgrade::Api { api_version: 1 }).await {
        Ok(stream) => {
            let ping = call_vm_monitor_ping(stream).await?;
            if ping.ok {
                Ok(())
            } else {
                let message = if ping.message.is_empty() {
                    "vm monitor ping failed".to_string()
                } else {
                    ping.message
                };
                Err(ProbeError::Retryable(message))
            }
        }
        Err(ClientUpgradeStreamError::Io(err)) => {
            Err(classify_io_error("negotiate api stream", err))
        }
        Err(ClientUpgradeStreamError::Reject(reject)) => match reject.code {
            RejectCode::ServiceStarting | RejectCode::ServiceUnavailable => {
                Err(ProbeError::Retryable(format!(
                    "{}: {}",
                    reject_code_label(reject.code),
                    reject.message
                )))
            }
            _ => Err(ProbeError::Fatal(format!(
                "{}: {}",
                reject_code_label(reject.code),
                reject.message
            ))),
        },
    }
}

async fn call_vm_monitor_ping(stream: UnixStream) -> Result<PingResponse, ProbeError> {
    let mut client = vm_monitor_client(stream)
        .await
        .map_err(|err| ProbeError::Retryable(format!("connect vm monitor rpc client: {err}")))?;

    let response = client
        .ping(PingRequest {})
        .await
        .map_err(|err| ProbeError::Retryable(format!("vm monitor ping rpc failed: {err}")))?;

    Ok(response.into_inner())
}

async fn connect_vm_monitor_stream(socket_path: &Path) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|err| format!("connect Negotiate socket failed: {err}"))?;

    Negotiate::client_upgrade_stream_v1(stream, Upgrade::Api { api_version: 1 })
        .await
        .map_err(|err| match err {
            ClientUpgradeStreamError::Io(io_err) => {
                format!("negotiate api stream failed: {io_err}")
            }
            ClientUpgradeStreamError::Reject(reject) => {
                format!("{}: {}", reject_code_label(reject.code), reject.message)
            }
        })
}

async fn vm_monitor_client(
    stream: UnixStream,
) -> Result<VmMonitorServiceClient<tonic::transport::Channel>, tonic::transport::Error> {
    let stream_slot = Arc::new(Mutex::new(Some(stream)));
    let connector = service_fn(move |_| {
        let stream_slot = Arc::clone(&stream_slot);
        async move {
            let mut guard = stream_slot.lock().await;
            guard
                .take()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "vm monitor connector stream already consumed",
                    )
                })
                .map(TokioIo::new)
        }
    });

    let channel = Endpoint::from_static("http://vm-monitor.local")
        .connect_with_connector(connector)
        .await?;

    Ok(VmMonitorServiceClient::new(channel))
}

fn classify_io_error(context: &str, err: io::Error) -> ProbeError {
    let message = format!("{context} failed: {err}");

    if is_retryable_io_kind(err.kind()) {
        return ProbeError::Retryable(message);
    }

    ProbeError::Fatal(message)
}

fn is_retryable_io_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn reject_code_label(code: RejectCode) -> &'static str {
    match code {
        RejectCode::UnsupportedProtocol => "unsupported_protocol",
        RejectCode::UnsupportedUpgrade => "unsupported_upgrade",
        RejectCode::UnsupportedService => "unsupported_service",
        RejectCode::ServiceStarting => "service_starting",
        RejectCode::ServiceUnavailable => "service_unavailable",
        RejectCode::PermissionDenied => "permission_denied",
        RejectCode::AuthFailed => "auth_failed",
        RejectCode::Internal => "internal_error",
    }
}

fn render_reject_error(code: RejectCode, message: &str) -> String {
    match code {
        RejectCode::ServiceStarting => format!("service_starting: {message}"),
        RejectCode::ServiceUnavailable => {
            format!("service_unavailable: {message}. ensure the guest endpoint is running")
        }
        RejectCode::UnsupportedService => {
            format!("unknown_service: {message}. try a supported endpoint like 'shell'")
        }
        RejectCode::UnsupportedProtocol => {
            format!("unsupported_protocol: {message}. update silo/vmmon to matching versions")
        }
        RejectCode::UnsupportedUpgrade => format!("unsupported_upgrade: {message}"),
        RejectCode::PermissionDenied => format!("permission_denied: {message}"),
        RejectCode::AuthFailed => format!("auth_failed: {message}"),
        RejectCode::Internal => format!("internal_error: {message}"),
    }
}

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use protocol::v1::guest_filesystem_service_client::GuestFilesystemServiceClient;
use protocol::v1::vm_access_service_client::VmAccessServiceClient;
use protocol::v1::vm_monitor_service_client::VmMonitorServiceClient;
use protocol::v1::{
    CreateDirectoryRequest, DownloadFileRequest, GetEntryRequest, GetMetricsRequest,
    GetStatusRequest, HostMetrics, HostStatus, ListDirectoryRequest, RemoveEntryRequest,
    UploadFileRequest, WaitReadyRequest, WaitReadyResponse,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
use tower::service_fn;

use crate::machine::{MachineByteStream, MachineFileDownload};

pub const DEFAULT_GUEST_READINESS_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const FILE_RPC_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const ACCESS_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_READY_MARGIN: Duration = Duration::from_secs(5);

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

    pub(crate) async fn status(&self) -> Result<HostStatus, String> {
        let mut client = monitor_client(self.channel().await?);
        client
            .get_status(timed_request(GetStatusRequest {}, RPC_TIMEOUT))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("vm monitor get_status RPC failed", error))
    }

    pub(crate) async fn wait_ready(&self, timeout: Duration) -> Result<WaitReadyResponse, String> {
        let seconds = i64::try_from(timeout.as_secs())
            .map_err(|_| "guest readiness timeout is too large".to_string())?;
        let nanos = i32::try_from(timeout.subsec_nanos())
            .map_err(|_| "guest readiness timeout nanoseconds are invalid".to_string())?;
        let mut client = monitor_client(self.channel().await?);
        client
            .wait_ready(timed_request(
                WaitReadyRequest {
                    max_wait: Some(prost_types::Duration { seconds, nanos }),
                },
                timeout.saturating_add(WAIT_READY_MARGIN),
            ))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("vm monitor wait_ready RPC failed", error))
    }

    pub(crate) async fn metrics(&self) -> Result<HostMetrics, String> {
        let mut client = monitor_client(self.channel().await?);
        client
            .get_metrics(timed_request(GetMetricsRequest {}, RPC_TIMEOUT))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("vm monitor get_metrics RPC failed", error))
    }

    pub(crate) async fn get_entry(
        &self,
        request: GetEntryRequest,
    ) -> Result<protocol::v1::FilesystemEntry, String> {
        let mut client = filesystem_client(self.channel().await?);
        client
            .get_entry(timed_request(request, RPC_TIMEOUT))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("guest filesystem get_entry RPC failed", error))
    }

    pub(crate) async fn remove_entry(&self, request: RemoveEntryRequest) -> Result<(), String> {
        let mut client = filesystem_client(self.channel().await?);
        client
            .remove_entry(timed_request(request, RPC_TIMEOUT))
            .await
            .map(|_| ())
            .map_err(|error| rpc_error("guest filesystem remove_entry RPC failed", error))
    }

    pub(crate) async fn list_directory(
        &self,
        request: ListDirectoryRequest,
    ) -> Result<protocol::v1::DirectoryPage, String> {
        let mut client = filesystem_client(self.channel().await?);
        client
            .list_directory(timed_request(request, RPC_TIMEOUT))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("guest filesystem list_directory RPC failed", error))
    }

    pub(crate) async fn create_directory(
        &self,
        request: CreateDirectoryRequest,
    ) -> Result<protocol::v1::CreateDirectoryResponse, String> {
        let mut client = filesystem_client(self.channel().await?);
        client
            .create_directory(timed_request(request, RPC_TIMEOUT))
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("guest filesystem create_directory RPC failed", error))
    }

    pub(crate) async fn download_file(
        &self,
        request: DownloadFileRequest,
    ) -> Result<MachineFileDownload, String> {
        let mut client = filesystem_client(self.channel().await?);
        client
            .download_file(timed_request(request, FILE_RPC_TIMEOUT))
            .await
            .map(|response| MachineFileDownload::new(response.into_inner()))
            .map_err(|error| rpc_error("guest filesystem download_file RPC failed", error))
    }

    pub(crate) async fn upload_file(
        &self,
        requests: ReceiverStream<UploadFileRequest>,
    ) -> Result<protocol::v1::UploadFileResponse, String> {
        let mut client = filesystem_client(self.channel().await?);
        let request = timed_request(requests, FILE_RPC_TIMEOUT);
        client
            .upload_file(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|error| rpc_error("guest filesystem upload_file RPC failed", error))
    }

    pub(crate) async fn open_serial_stream(&self) -> Result<MachineByteStream, String> {
        let (tx, rx) = mpsc::channel(MachineByteStream::REQUEST_BUFFER);
        let mut client = access_client(self.channel().await?);
        tokio::time::timeout(
            ACCESS_SETUP_TIMEOUT,
            client.open_serial(ReceiverStream::new(rx)),
        )
        .await
        .map_err(|_| "open serial RPC setup timed out".to_string())?
        .map(|response| MachineByteStream::new(response.into_inner(), tx))
        .map_err(|error| rpc_error("open serial RPC failed", error))
    }

    pub(crate) async fn open_shell_stream(&self) -> Result<MachineByteStream, String> {
        let (tx, rx) = mpsc::channel(MachineByteStream::REQUEST_BUFFER);
        let mut client = access_client(self.channel().await?);
        tokio::time::timeout(
            ACCESS_SETUP_TIMEOUT,
            client.open_ssh(ReceiverStream::new(rx)),
        )
        .await
        .map_err(|_| "open SSH RPC setup timed out".to_string())?
        .map(|response| MachineByteStream::new(response.into_inner(), tx))
        .map_err(|error| rpc_error("open SSH RPC failed", error))
    }

    async fn channel(&self) -> Result<Channel, String> {
        let socket_path = self.socket_path.clone();
        let connector = service_fn(move |_| {
            let socket_path = socket_path.clone();
            async move {
                tokio::net::UnixStream::connect(&socket_path)
                    .await
                    .map(TokioIo::new)
                    .map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("connect vmmon socket {}: {error}", socket_path.display()),
                        )
                    })
            }
        });
        Endpoint::from_static("http://vm-monitor.local")
            .connect_timeout(Duration::from_secs(5))
            .connect_with_connector(connector)
            .await
            .map_err(|error| format!("connect vm monitor RPC client: {error}"))
    }
}

fn monitor_client(channel: Channel) -> VmMonitorServiceClient<Channel> {
    VmMonitorServiceClient::new(channel)
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
}

fn access_client(channel: Channel) -> VmAccessServiceClient<Channel> {
    VmAccessServiceClient::new(channel)
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
}

fn filesystem_client(channel: Channel) -> GuestFilesystemServiceClient<Channel> {
    GuestFilesystemServiceClient::new(channel)
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
}

fn timed_request<T>(message: T, timeout: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

fn rpc_error(context: &str, status: Status) -> String {
    let detail = protocol::decode_error_detail(status.details())
        .ok()
        .and_then(|detail| detail.code)
        .and_then(|code| protocol::v1::ErrorCode::try_from(code).ok())
        .filter(|code| *code != protocol::v1::ErrorCode::Unspecified)
        .map(|code| code.as_str_name().to_ascii_lowercase());
    match detail {
        Some(detail) => format!("{context}: {detail}: {}", status.message()),
        None => format!("{context}: {status}"),
    }
}

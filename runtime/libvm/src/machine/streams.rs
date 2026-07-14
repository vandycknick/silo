use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use protocol::v1::{
    self, CreateDirectoryRequest, DownloadFileRequest, GetEntryRequest, ListDirectoryRequest,
    RemoveEntryRequest, UploadFileHeader, UploadFileRequest,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tokio_util::sync::PollSender;
use tokio_util::task::AbortOnDropHandle;

use crate::machine::{Machine, MachineData, MachineRef};
use crate::store::models::MachineConfig;
use crate::LibVmError;

const PRODUCER_CHUNK_BYTES: usize = 32 * 1024;
const ACCEPTED_CHUNK_BYTES: usize = protocol::CHUNK_64_KIB;

enum UploadOutcome<R, P> {
    Rpc(R),
    Producer(P),
}

#[derive(Debug)]
pub struct MachineByteStream {
    reader: tonic::Streaming<v1::ByteChunk>,
    read_buffer: Bytes,
    writer: Option<PollSender<v1::ByteChunk>>,
}

impl MachineByteStream {
    pub(crate) const REQUEST_BUFFER: usize = 16;

    pub(crate) fn new(
        reader: tonic::Streaming<v1::ByteChunk>,
        writer: mpsc::Sender<v1::ByteChunk>,
    ) -> Self {
        Self {
            reader,
            read_buffer: Bytes::new(),
            writer: Some(PollSender::new(writer)),
        }
    }
}

fn poll_chunk(
    reader: &mut tonic::Streaming<v1::ByteChunk>,
    read_buffer: &mut Bytes,
    cx: &mut Context<'_>,
    buffer: &mut tokio::io::ReadBuf<'_>,
    label: &str,
) -> Poll<io::Result<()>> {
    loop {
        if !read_buffer.is_empty() {
            let len = read_buffer.len().min(buffer.remaining());
            buffer.put_slice(&read_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut *reader).poll_next(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
            Poll::Ready(Some(Ok(chunk))) => {
                let Some(data) = chunk.data else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{label} chunk is missing data"),
                    )));
                };
                if data.len() > ACCEPTED_CHUNK_BYTES {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{label} returned a {} byte chunk, maximum is {ACCEPTED_CHUNK_BYTES}",
                            data.len()
                        ),
                    )));
                }
                *read_buffer = data;
            }
        }
    }
}

impl AsyncRead for MachineByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        poll_chunk(
            &mut this.reader,
            &mut this.read_buffer,
            cx,
            buffer,
            "vmmon access",
        )
    }
}

impl AsyncWrite for MachineByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(writer) = self.writer.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vmmon request stream is closed",
            )));
        };
        match writer.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "vmmon request stream closed",
            ))),
            Poll::Ready(Ok(())) => {
                let len = data.len().min(PRODUCER_CHUNK_BYTES);
                writer
                    .send_item(v1::ByteChunk {
                        data: Some(Bytes::copy_from_slice(&data[..len])),
                    })
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "vmmon request stream closed")
                    })?;
                Poll::Ready(Ok(len))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.writer.take();
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub struct MachineFileDownload {
    reader: tonic::Streaming<v1::ByteChunk>,
    read_buffer: Bytes,
}
impl MachineFileDownload {
    pub(crate) fn new(reader: tonic::Streaming<v1::ByteChunk>) -> Self {
        Self {
            reader,
            read_buffer: Bytes::new(),
        }
    }
}
impl AsyncRead for MachineFileDownload {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        poll_chunk(
            &mut this.reader,
            &mut this.read_buffer,
            cx,
            buffer,
            "guest file download",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMonitorStatus {
    pub machine_id: String,
    pub name: String,
    pub monitor: MachineMonitorSnapshot,
    pub vm: MachineVmSnapshot,
    pub readiness: MachineReadinessState,
    pub agent: MachineAgentStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMonitorSnapshot {
    pub instance_id: String,
    pub observed_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineVmSnapshot {
    pub state: MachineVmState,
    pub state_changed_at: SystemTime,
    pub running_since: Option<SystemTime>,
    pub code: Option<String>,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineVmState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineReadinessState {
    pub ready: bool,
    pub reason: MachineReadinessReason,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineReadinessReason {
    VmStarting,
    VmStopping,
    VmStopped,
    VmFailed,
    AgentNotRequired,
    AgentUnavailable,
    AgentStatusStale,
    GuestStarting,
    GuestFailed,
    GuestReportedReady,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineAgentStatus {
    Disabled,
    Enabled(Box<MachineEnabledAgent>),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineEnabledAgent {
    pub connection: MachineAgentConnection,
    pub identity: Option<MachineAgentIdentity>,
    pub status: Option<MachineAgentStatusObservation>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAgentConnection {
    pub state: MachineAgentConnectionState,
    pub last_success_at: Option<SystemTime>,
    pub last_failure_at: Option<SystemTime>,
    pub code: Option<String>,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAgentConnectionState {
    Connecting,
    Responsive,
    Unresponsive,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAgentIdentity {
    pub instance_id: String,
    pub version: String,
    pub boot_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAgentStatusObservation {
    pub received_at: SystemTime,
    pub stale_at: SystemTime,
    pub freshness: MachineFreshness,
    pub stale_reason: Option<MachineStaleReason>,
    pub report: MachineAgentStatusReport,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineFreshness {
    Fresh,
    Stale,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineStaleReason {
    ReceiptAge,
    MonitorStopping,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAgentStatusReport {
    pub observed_at: SystemTime,
    pub state: MachineAgentStatusState,
    pub code: Option<String>,
    pub message: Option<String>,
    pub system: Option<MachineSystemInfo>,
    pub boot: Option<MachineGuestBootReport>,
    pub provisioning: Option<MachineProvisioningReport>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAgentStatusState {
    Starting,
    Ready,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSystemInfo {
    pub kernel_version: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub architecture: Option<String>,
    pub hostname: Option<String>,
    pub ip_addresses: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineGuestBootReport {
    pub mode: MachineGuestBootMode,
    pub requested_init: Option<String>,
    pub handoff_init_path: Option<String>,
    pub probed_init_paths: Vec<String>,
    pub agent_path: Option<String>,
    pub agent_pid: u32,
    pub agent_is_pid1: bool,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineGuestBootMode {
    Standard,
    AgentPid1,
    InitChild,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineProvisioningReport {
    pub status: MachineProvisionOverallStatus,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    pub duration: Duration,
    pub message: Option<String>,
    pub steps: Vec<MachineAgentProvisioningStepReport>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineProvisionOverallStatus {
    Succeeded,
    Degraded,
    Skipped,
    FailedBoot,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAgentProvisioningStepReport {
    pub id: String,
    pub status: MachineAgentProvisionStepStatus,
    pub failure_policy: MachineAgentProvisionFailurePolicy,
    pub changed: bool,
    pub backend: Option<String>,
    pub message: Option<String>,
    pub error_chain: Option<String>,
    pub duration: Duration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAgentProvisionStepStatus {
    Succeeded,
    Failed,
    Skipped,
    Unsupported,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAgentProvisionFailurePolicy {
    BestEffort,
    FailBoot,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MachineMetrics {
    pub machine_id: String,
    pub name: String,
    pub monitor: MachineMonitorSnapshot,
    pub metrics: Option<MachineAgentMetricsObservation>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct MachineAgentMetricsObservation {
    pub agent_instance_id: String,
    pub received_at: SystemTime,
    pub stale_at: SystemTime,
    pub freshness: MachineFreshness,
    pub stale_reason: Option<MachineStaleReason>,
    pub report: MachineAgentMetricReport,
}
#[derive(Debug, Clone, PartialEq)]
pub struct MachineAgentMetricReport {
    pub observed_at: SystemTime,
    pub snapshot: MachineMetricSnapshot,
}
#[derive(Debug, Clone, PartialEq)]
pub struct MachineMetricSnapshot {
    pub memory: Option<MachineMemoryMetrics>,
    pub cpu: Option<MachineCpuMetrics>,
    pub load_average: Option<MachineLoadAverageMetrics>,
    pub uptime_seconds: Option<f64>,
    pub filesystems: Vec<MachineFilesystemMetrics>,
    pub network_interfaces: Vec<MachineNetworkInterfaceMetrics>,
    pub block_devices: Vec<MachineBlockDeviceMetrics>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMemoryMetrics {
    pub total_bytes: u64,
    pub available_bytes: u64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct MachineCpuMetrics {
    pub logical_cpu_count: u32,
    pub user_seconds: f64,
    pub nice_seconds: f64,
    pub system_seconds: f64,
    pub idle_seconds: f64,
    pub iowait_seconds: f64,
    pub irq_seconds: f64,
    pub softirq_seconds: f64,
    pub steal_seconds: f64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct MachineLoadAverageMetrics {
    pub one_minute: f64,
    pub five_minutes: f64,
    pub fifteen_minutes: f64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFilesystemMetrics {
    pub mount_point: String,
    pub filesystem_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineNetworkInterfaceMetrics {
    pub name: String,
    pub mac: Option<String>,
    pub receive_bytes: u64,
    pub transmit_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineBlockDeviceMetrics {
    pub name: String,
    pub read_bytes: u64,
    pub read_operations: u64,
    pub write_bytes: u64,
    pub write_operations: u64,
    pub in_flight_operations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFileEntry {
    pub path: String,
    pub name: String,
    pub kind: MachineEntryKind,
    pub size_bytes: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub modified_at: SystemTime,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineEntryKind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineDirectoryPage {
    pub entries: Vec<MachineFileEntry>,
    pub next_cursor: Option<Bytes>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFileUploadOptions {
    pub path: String,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileWriteDisposition {
    Created,
    Replaced,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineDirectoryCreateDisposition {
    Created,
    AlreadyExists,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineReadiness {
    pub outcome: MachineReadinessOutcome,
    pub status: MachineMonitorStatus,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineReadinessOutcome {
    Ready,
    Terminal,
    TimedOut,
}

impl Machine {
    pub async fn inspect(&self) -> Result<MachineData, LibVmError> {
        let config = self
            .runtime()
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        self.runtime().machine_inspect_data(config).await
    }
    pub async fn monitor_status(&self) -> Result<MachineMonitorStatus, LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .status()
            .await
            .and_then(MachineMonitorStatus::try_from)
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn wait_ready(&self, timeout: Duration) -> Result<MachineReadiness, LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .wait_ready(timeout)
            .await
            .and_then(MachineReadiness::try_from)
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn metrics(&self) -> Result<MachineMetrics, LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .metrics()
            .await
            .and_then(MachineMetrics::try_from)
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn get_file_entry(
        &self,
        path: impl Into<String>,
    ) -> Result<MachineFileEntry, LibVmError> {
        let config = self.running_config().await?;
        let path = validate_path(path.into())?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .get_entry(GetEntryRequest { path: Some(path) })
            .await
            .and_then(MachineFileEntry::try_from)
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn remove_file_entry(
        &self,
        path: impl Into<String>,
        recursive: bool,
    ) -> Result<(), LibVmError> {
        let config = self.running_config().await?;
        let path = validate_path(path.into())?;
        reject_root(&path)?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .remove_entry(RemoveEntryRequest {
                path: Some(path),
                recursive: Some(recursive),
            })
            .await
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn list_directory(
        &self,
        path: impl Into<String>,
        limit: Option<u32>,
        cursor: Option<Bytes>,
    ) -> Result<MachineDirectoryPage, LibVmError> {
        let config = self.running_config().await?;
        let path = validate_path(path.into())?;
        validate_page(limit, cursor.as_deref())?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .list_directory(ListDirectoryRequest {
                path: Some(path),
                limit,
                cursor: cursor.map(|value| value.to_vec()),
            })
            .await
            .and_then(MachineDirectoryPage::try_from)
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn create_directory(
        &self,
        path: impl Into<String>,
        parents: bool,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<MachineDirectoryCreateDisposition, LibVmError> {
        let config = self.running_config().await?;
        let path = validate_path(path.into())?;
        reject_root(&path)?;
        validate_mode(mode)?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .create_directory(CreateDirectoryRequest {
                path: Some(path),
                parents: Some(parents),
                mode,
                uid,
                gid,
            })
            .await
            .and_then(|value| MachineDirectoryCreateDisposition::try_from(value.disposition))
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn download_file(
        &self,
        path: impl Into<String>,
    ) -> Result<MachineFileDownload, LibVmError> {
        let config = self.running_config().await?;
        let path = validate_path(path.into())?;
        reject_root(&path)?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .download_file(DownloadFileRequest { path: Some(path) })
            .await
            .map_err(|message| monitor_error(config.name, message))
    }
    pub async fn upload_file<R>(
        &self,
        options: MachineFileUploadOptions,
        reader: R,
    ) -> Result<FileWriteDisposition, LibVmError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let config = self.running_config().await?;
        let path = validate_path(options.path)?;
        reject_root(&path)?;
        validate_mode(options.mode)?;
        let (tx, rx) = mpsc::channel(16);
        let header = UploadFileHeader {
            path: Some(path),
            mode: options.mode,
            uid: options.uid,
            gid: options.gid,
        };
        let request_guard = tx.clone();
        let (producer, mut completion_rx) = spawn_upload_producer(tx, header, reader);
        let client = self.runtime().vmmon().client(self.machine_id());
        let mut rpc = Box::pin(client.upload_file(ReceiverStream::new(rx)));
        let outcome = tokio::select! {
            response = &mut rpc => UploadOutcome::Rpc(response),
            produced = &mut completion_rx => UploadOutcome::Producer(produced),
        };
        match outcome {
            UploadOutcome::Rpc(response) => {
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                response
                    .and_then(|value| FileWriteDisposition::try_from(value.disposition))
                    .map_err(|message| monitor_error(config.name, message))
            }
            UploadOutcome::Producer(Ok(Ok(()))) => {
                drop(request_guard);
                rpc.await
                    .and_then(|value| FileWriteDisposition::try_from(value.disposition))
                    .map_err(|message| monitor_error(config.name, message))
            }
            UploadOutcome::Producer(Ok(Err(error))) => {
                drop(rpc);
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                Err(LibVmError::Io(error))
            }
            UploadOutcome::Producer(Err(error)) => {
                drop(rpc);
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                Err(monitor_error(
                    config.name,
                    format!("upload producer failed: {error}"),
                ))
            }
        }
    }
    pub async fn open_serial_stream(&self) -> Result<MachineByteStream, LibVmError> {
        let config = self.running_config().await?;
        self.runtime()
            .vmmon()
            .client(self.machine_id())
            .open_serial_stream()
            .await
            .map_err(|message| monitor_error(config.name, message))
    }
    pub(crate) async fn open_shell_stream(&self) -> Result<MachineByteStream, LibVmError> {
        let config = self.running_config().await?;
        let client = self.runtime().vmmon().client(self.machine_id());
        client
            .open_shell_stream()
            .await
            .map_err(|message| monitor_error(config.name, message))
    }
    pub(crate) async fn running_config(&self) -> Result<MachineConfig, LibVmError> {
        let runtime = self.runtime();
        let config = runtime
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        if !runtime
            .reconcile_machine_runtime_best_effort(&config)
            .await?
            .is_running()
        {
            return Err(LibVmError::MachineNotRunning {
                reference: config.name,
            });
        }
        Ok(config)
    }
}

fn spawn_upload_producer<R>(
    tx: mpsc::Sender<UploadFileRequest>,
    header: UploadFileHeader,
    mut reader: R,
) -> (
    AbortOnDropHandle<()>,
    tokio::sync::oneshot::Receiver<Result<(), io::Error>>,
)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let producer = AbortOnDropHandle::new(tokio::spawn(async move {
        let result = async {
            tx.send(UploadFileRequest {
                payload: Some(v1::upload_file_request::Payload::Header(header)),
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "vmmon upload request stream closed",
                )
            })?;
            let mut buffer = BytesMut::zeroed(PRODUCER_CHUNK_BYTES);
            loop {
                let count = reader.read(&mut buffer).await?;
                if count == 0 {
                    return Ok::<(), io::Error>(());
                }
                tx.send(UploadFileRequest {
                    payload: Some(v1::upload_file_request::Payload::Chunk(v1::ByteChunk {
                        data: Some(Bytes::copy_from_slice(&buffer[..count])),
                    })),
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "vmmon upload request stream closed",
                    )
                })?;
            }
        }
        .await;
        match result {
            Ok(()) => {
                drop(tx);
                let _ = completion_tx.send(Ok(()));
            }
            Err(error) => {
                if completion_tx.send(Err(error)).is_ok() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }));
    (producer, completion_rx)
}

fn monitor_error(reference: String, message: String) -> LibVmError {
    LibVmError::MonitorProtocol { reference, message }
}
fn request_error(message: impl Into<String>) -> LibVmError {
    LibVmError::MonitorProtocol {
        reference: "request".to_string(),
        message: message.into(),
    }
}
fn validate_path(path: String) -> Result<String, LibVmError> {
    if path.is_empty()
        || path.len() > protocol::MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
    {
        return Err(request_error(format!(
            "path must be an absolute non-NUL UTF-8 string no longer than {} bytes",
            protocol::MAX_PATH_BYTES
        )));
    }
    if path != "/"
        && (path.ends_with('/')
            || path[1..].split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.len() > protocol::MAX_FILENAME_BYTES
            }))
    {
        return Err(request_error("path must use canonical absolute spelling"));
    }
    Ok(path)
}

fn reject_root(path: &str) -> Result<(), LibVmError> {
    if path == "/" {
        Err(request_error(
            "the root path is not valid for this operation",
        ))
    } else {
        Ok(())
    }
}
fn validate_mode(mode: Option<u32>) -> Result<(), LibVmError> {
    if mode.is_some_and(|value| value > 0o7777) {
        return Err(request_error(
            "mode must be a Unix permission value no greater than 0o7777",
        ));
    }
    Ok(())
}
fn validate_page(limit: Option<u32>, cursor: Option<&[u8]>) -> Result<(), LibVmError> {
    if limit.is_some_and(|value| value == 0 || value > protocol::MAX_DIRECTORY_PAGE_SIZE) {
        return Err(request_error(format!(
            "directory page limit must be between 1 and {}",
            protocol::MAX_DIRECTORY_PAGE_SIZE
        )));
    }
    if cursor.is_some_and(|value| value.len() > protocol::MAX_CURSOR_BYTES) {
        return Err(request_error(format!(
            "directory cursor must be no longer than {} bytes",
            protocol::MAX_CURSOR_BYTES
        )));
    }
    Ok(())
}
fn required<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("vmmon response is missing required {field}"))
}
fn required_text(value: Option<String>, field: &str, maximum: usize) -> Result<String, String> {
    let value = required(value, field)?;
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
        return Err(format!("vmmon response has invalid {field}"));
    }
    Ok(value)
}
fn optional_text(
    value: Option<String>,
    field: &str,
    maximum: usize,
) -> Result<Option<String>, String> {
    value
        .map(|value| {
            if value.len() > maximum || value.as_bytes().contains(&0) {
                Err(format!("vmmon response has invalid {field}"))
            } else {
                Ok(value)
            }
        })
        .transpose()
}
fn canonical_uuid(value: Option<String>, field: &str) -> Result<String, String> {
    let value = required_text(value, field, 36)?;
    let parsed = uuid::Uuid::parse_str(&value)
        .map_err(|_| format!("vmmon response has invalid {field} UUID"))?;
    if parsed.hyphenated().to_string() != value {
        return Err(format!("vmmon response has non-canonical {field} UUID"));
    }
    Ok(value)
}
fn required_duration(
    value: Option<prost_types::Duration>,
    field: &str,
) -> Result<Duration, String> {
    optional_duration(value, field)?
        .ok_or_else(|| format!("vmmon response is missing required {field}"))
}
fn finite_nonnegative(value: Option<f64>, field: &str) -> Result<f64, String> {
    let value = required(value, field)?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("vmmon response has invalid {field}"));
    }
    Ok(value)
}
fn validate_mac(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 17
        || !value.as_bytes().iter().enumerate().all(|(index, byte)| {
            (index + 1) % 3 == 0 && *byte == b':'
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
    {
        return Err(format!("vmmon response has invalid {field}"));
    }
    Ok(())
}
fn validate_paths(values: Vec<String>, field: &str, maximum: usize) -> Result<Vec<String>, String> {
    if values.len() > maximum {
        return Err(format!("vmmon response {field} exceeds maximum size"));
    }
    values
        .into_iter()
        .map(|value| required_text(Some(value), field, protocol::MAX_PATH_BYTES))
        .collect()
}
fn timestamp(value: Option<prost_types::Timestamp>, field: &str) -> Result<SystemTime, String> {
    let value = required(value, field)?;
    if !(-62_135_596_800..=253_402_300_799).contains(&value.seconds)
        || !(0..1_000_000_000).contains(&value.nanos)
    {
        return Err(format!("vmmon response has invalid {field}"));
    }
    if value.seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(value.seconds as u64, value.nanos as u32))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(value.seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(Duration::from_nanos(value.nanos as u64)))
    }
    .ok_or_else(|| format!("vmmon response has out-of-range {field}"))
}
fn optional_timestamp(
    value: Option<prost_types::Timestamp>,
    field: &str,
) -> Result<Option<SystemTime>, String> {
    value.map(|value| timestamp(Some(value), field)).transpose()
}
fn optional_duration(
    value: Option<prost_types::Duration>,
    field: &str,
) -> Result<Option<Duration>, String> {
    value
        .map(|value| {
            if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
                return Err(format!("vmmon response has invalid {field}"));
            }
            Ok(Duration::new(value.seconds as u64, value.nanos as u32))
        })
        .transpose()
}
fn enum_value<T>(value: i32, field: &str) -> Result<T, String>
where
    T: TryFrom<i32>,
{
    T::try_from(value).map_err(|_| format!("vmmon response has unknown {field} value {value}"))
}
macro_rules! protocol_enum { ($name:ident, $wire:ident => $public:ident, { $($source:ident => $target:ident),+ $(,)? }) => { fn $name(value: i32, field: &str) -> Result<$public, String> { match enum_value::<v1::$wire>(value, field)? { $(v1::$wire::$source => Ok($public::$target),)+ v1::$wire::Unspecified => Err(format!("vmmon response has unspecified {field}")), } } }; }
protocol_enum!(vm_state, VmState => MachineVmState, { Starting => Starting, Running => Running, Stopping => Stopping, Stopped => Stopped, Failed => Failed });
protocol_enum!(readiness_reason, ReadinessReason => MachineReadinessReason, { VmStarting => VmStarting, VmStopping => VmStopping, VmStopped => VmStopped, VmFailed => VmFailed, AgentNotRequired => AgentNotRequired, AgentUnavailable => AgentUnavailable, AgentStatusStale => AgentStatusStale, GuestStarting => GuestStarting, GuestFailed => GuestFailed, GuestReportedReady => GuestReportedReady });
protocol_enum!(connection_state, AgentConnectionState => MachineAgentConnectionState, { Connecting => Connecting, Responsive => Responsive, Unresponsive => Unresponsive });
protocol_enum!(freshness, Freshness => MachineFreshness, { Fresh => Fresh, Stale => Stale });
protocol_enum!(stale_reason, StaleReason => MachineStaleReason, { ReceiptAge => ReceiptAge, MonitorStopping => MonitorStopping });
protocol_enum!(agent_status_state, AgentStatusState => MachineAgentStatusState, { Starting => Starting, Ready => Ready, Failed => Failed });
protocol_enum!(boot_mode, GuestBootMode => MachineGuestBootMode, { Standard => Standard, AgentPid1 => AgentPid1, InitChild => InitChild });
protocol_enum!(provision_status, ProvisionOverallStatus => MachineProvisionOverallStatus, { Succeeded => Succeeded, Degraded => Degraded, Skipped => Skipped, FailedBoot => FailedBoot });
protocol_enum!(step_status, ProvisionStepStatus => MachineAgentProvisionStepStatus, { Succeeded => Succeeded, Failed => Failed, Skipped => Skipped, Unsupported => Unsupported });
protocol_enum!(failure_policy, ProvisionFailurePolicy => MachineAgentProvisionFailurePolicy, { BestEffort => BestEffort, FailBoot => FailBoot });

impl TryFrom<v1::HostStatus> for MachineMonitorStatus {
    type Error = String;
    fn try_from(value: v1::HostStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: canonical_uuid(value.machine_id, "machine_id")?,
            name: required_text(value.name, "name", protocol::MAX_INFO_BYTES)?,
            monitor: required(value.monitor, "monitor")?.try_into()?,
            vm: required(value.vm, "vm")?.try_into()?,
            readiness: required(value.readiness, "readiness")?.try_into()?,
            agent: required(value.agent, "agent")?.try_into()?,
        })
    }
}
impl TryFrom<v1::MonitorSnapshot> for MachineMonitorSnapshot {
    type Error = String;
    fn try_from(value: v1::MonitorSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            instance_id: canonical_uuid(value.instance_id, "monitor.instance_id")?,
            observed_at: timestamp(value.observed_at, "monitor.observed_at")?,
        })
    }
}
impl TryFrom<v1::VmSnapshot> for MachineVmSnapshot {
    type Error = String;
    fn try_from(value: v1::VmSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            state: vm_state(required(value.state, "vm.state")?, "vm.state")?,
            state_changed_at: timestamp(value.state_changed_at, "vm.state_changed_at")?,
            running_since: optional_timestamp(value.running_since, "vm.running_since")?,
            code: optional_text(value.code, "vm.code", protocol::MAX_CODE_BYTES)?,
            message: optional_text(value.message, "vm.message", protocol::MAX_DIAGNOSTIC_BYTES)?,
        })
    }
}
impl TryFrom<v1::Readiness> for MachineReadinessState {
    type Error = String;
    fn try_from(value: v1::Readiness) -> Result<Self, Self::Error> {
        Ok(Self {
            ready: required(value.ready, "readiness.ready")?,
            reason: readiness_reason(
                required(value.reason, "readiness.reason")?,
                "readiness.reason",
            )?,
        })
    }
}
impl TryFrom<v1::HostAgent> for MachineAgentStatus {
    type Error = String;
    fn try_from(value: v1::HostAgent) -> Result<Self, Self::Error> {
        match required(value.mode, "agent.mode")? {
            v1::host_agent::Mode::Disabled(_) => Ok(Self::Disabled),
            v1::host_agent::Mode::Enabled(value) => Ok(Self::Enabled(Box::new(value.try_into()?))),
        }
    }
}
impl TryFrom<v1::EnabledAgent> for MachineEnabledAgent {
    type Error = String;
    fn try_from(value: v1::EnabledAgent) -> Result<Self, Self::Error> {
        Ok(Self {
            connection: required(value.connection, "agent.connection")?.try_into()?,
            identity: value.identity.map(TryInto::try_into).transpose()?,
            status: value.status.map(TryInto::try_into).transpose()?,
        })
    }
}
impl TryFrom<v1::AgentConnection> for MachineAgentConnection {
    type Error = String;
    fn try_from(value: v1::AgentConnection) -> Result<Self, Self::Error> {
        Ok(Self {
            state: connection_state(
                required(value.state, "agent.connection.state")?,
                "agent.connection.state",
            )?,
            last_success_at: optional_timestamp(
                value.last_success_at,
                "agent.connection.last_success_at",
            )?,
            last_failure_at: optional_timestamp(
                value.last_failure_at,
                "agent.connection.last_failure_at",
            )?,
            code: optional_text(
                value.code,
                "agent.connection.code",
                protocol::MAX_CODE_BYTES,
            )?,
            message: optional_text(
                value.message,
                "agent.connection.message",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
        })
    }
}
impl TryFrom<v1::AgentIdentity> for MachineAgentIdentity {
    type Error = String;
    fn try_from(value: v1::AgentIdentity) -> Result<Self, Self::Error> {
        Ok(Self {
            instance_id: canonical_uuid(value.instance_id, "agent.identity.instance_id")?,
            version: required_text(
                value.version,
                "agent.identity.version",
                protocol::MAX_INFO_BYTES,
            )?,
            boot_id: canonical_uuid(value.boot_id, "agent.identity.boot_id")?,
        })
    }
}
impl TryFrom<v1::AgentStatusObservation> for MachineAgentStatusObservation {
    type Error = String;
    fn try_from(value: v1::AgentStatusObservation) -> Result<Self, Self::Error> {
        Ok(Self {
            received_at: timestamp(value.received_at, "agent.status.received_at")?,
            stale_at: timestamp(value.stale_at, "agent.status.stale_at")?,
            freshness: freshness(
                required(value.freshness, "agent.status.freshness")?,
                "agent.status.freshness",
            )?,
            stale_reason: value
                .stale_reason
                .map(|value| stale_reason(value, "agent.status.stale_reason"))
                .transpose()?,
            report: required(value.report, "agent.status.report")?.try_into()?,
        })
    }
}
impl TryFrom<v1::AgentStatusReport> for MachineAgentStatusReport {
    type Error = String;
    fn try_from(value: v1::AgentStatusReport) -> Result<Self, Self::Error> {
        Ok(Self {
            observed_at: timestamp(value.observed_at, "agent.status.report.observed_at")?,
            state: agent_status_state(
                required(value.state, "agent.status.report.state")?,
                "agent.status.report.state",
            )?,
            code: optional_text(
                value.code,
                "agent.status.report.code",
                protocol::MAX_CODE_BYTES,
            )?,
            message: optional_text(
                value.message,
                "agent.status.report.message",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
            system: value.system.map(TryInto::try_into).transpose()?,
            boot: value.boot.map(TryInto::try_into).transpose()?,
            provisioning: value.provisioning.map(TryInto::try_into).transpose()?,
        })
    }
}
impl TryFrom<v1::SystemInfo> for MachineSystemInfo {
    type Error = String;
    fn try_from(value: v1::SystemInfo) -> Result<Self, Self::Error> {
        if value.ip_addresses.len() > protocol::MAX_AGENT_IP_ADDRESSES {
            return Err("vmmon response system.ip_addresses exceeds maximum size".to_string());
        }
        let ip_addresses = value
            .ip_addresses
            .into_iter()
            .map(|address| {
                let address = required_text(
                    Some(address),
                    "system.ip_addresses",
                    protocol::MAX_INFO_BYTES,
                )?;
                let parsed = address
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| "vmmon response has invalid system.ip_addresses".to_string())?;
                if parsed.to_string() != address {
                    return Err("vmmon response has non-canonical system.ip_addresses".to_string());
                }
                Ok(address)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            kernel_version: optional_text(
                value.kernel_version,
                "system.kernel_version",
                protocol::MAX_INFO_BYTES,
            )?,
            os_name: optional_text(value.os_name, "system.os_name", protocol::MAX_INFO_BYTES)?,
            os_version: optional_text(
                value.os_version,
                "system.os_version",
                protocol::MAX_INFO_BYTES,
            )?,
            architecture: optional_text(
                value.architecture,
                "system.architecture",
                protocol::MAX_INFO_BYTES,
            )?,
            hostname: optional_text(value.hostname, "system.hostname", protocol::MAX_INFO_BYTES)?,
            ip_addresses,
        })
    }
}
impl TryFrom<v1::GuestBootReport> for MachineGuestBootReport {
    type Error = String;
    fn try_from(value: v1::GuestBootReport) -> Result<Self, Self::Error> {
        Ok(Self {
            mode: boot_mode(
                required(value.mode, "agent.status.report.boot.mode")?,
                "agent.status.report.boot.mode",
            )?,
            requested_init: optional_text(
                value.requested_init,
                "agent.status.report.boot.requested_init",
                protocol::MAX_PATH_BYTES,
            )?,
            handoff_init_path: optional_text(
                value.handoff_init_path,
                "agent.status.report.boot.handoff_init_path",
                protocol::MAX_PATH_BYTES,
            )?,
            probed_init_paths: validate_paths(
                value.probed_init_paths,
                "agent.status.report.boot.probed_init_paths",
                protocol::MAX_PROBED_INIT_PATHS,
            )?,
            agent_path: optional_text(
                value.agent_path,
                "agent.status.report.boot.agent_path",
                protocol::MAX_PATH_BYTES,
            )?,
            agent_pid: required(value.agent_pid, "agent.status.report.boot.agent_pid")?,
            agent_is_pid1: required(
                value.agent_is_pid1,
                "agent.status.report.boot.agent_is_pid1",
            )?,
            message: optional_text(
                value.message,
                "agent.status.report.boot.message",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
        })
    }
}
impl TryFrom<v1::ProvisionReport> for MachineProvisioningReport {
    type Error = String;
    fn try_from(value: v1::ProvisionReport) -> Result<Self, Self::Error> {
        if value.steps.len() > protocol::MAX_PROVISIONING_STEPS {
            return Err("vmmon response provisioning.steps exceeds maximum size".to_string());
        }
        let started_at = timestamp(
            value.started_at,
            "agent.status.report.provisioning.started_at",
        )?;
        let finished_at = timestamp(
            value.finished_at,
            "agent.status.report.provisioning.finished_at",
        )?;
        if finished_at < started_at {
            return Err("vmmon response provisioning finished_at precedes started_at".to_string());
        }
        let duration =
            required_duration(value.duration, "agent.status.report.provisioning.duration")?;
        let steps = value
            .steps
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<MachineAgentProvisioningStepReport>, _>>()?;
        if steps.windows(2).any(|values| values[0].id == values[1].id)
            || steps
                .iter()
                .enumerate()
                .any(|(index, step)| steps[..index].iter().any(|previous| previous.id == step.id))
        {
            return Err("vmmon response provisioning step IDs must be unique".to_string());
        }
        Ok(Self {
            status: provision_status(
                required(value.status, "agent.status.report.provisioning.status")?,
                "agent.status.report.provisioning.status",
            )?,
            started_at,
            finished_at,
            duration,
            message: optional_text(
                value.message,
                "agent.status.report.provisioning.message",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
            steps,
        })
    }
}
impl TryFrom<v1::ProvisionStepReport> for MachineAgentProvisioningStepReport {
    type Error = String;
    fn try_from(value: v1::ProvisionStepReport) -> Result<Self, Self::Error> {
        Ok(Self {
            id: required_text(
                value.id,
                "agent.status.report.provisioning.steps.id",
                protocol::MAX_INFO_BYTES,
            )?,
            status: step_status(
                required(
                    value.status,
                    "agent.status.report.provisioning.steps.status",
                )?,
                "agent.status.report.provisioning.steps.status",
            )?,
            failure_policy: failure_policy(
                required(
                    value.failure_policy,
                    "agent.status.report.provisioning.steps.failure_policy",
                )?,
                "agent.status.report.provisioning.steps.failure_policy",
            )?,
            changed: required(
                value.changed,
                "agent.status.report.provisioning.steps.changed",
            )?,
            backend: optional_text(
                value.backend,
                "agent.status.report.provisioning.steps.backend",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
            message: optional_text(
                value.message,
                "agent.status.report.provisioning.steps.message",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
            error_chain: optional_text(
                value.error_chain,
                "agent.status.report.provisioning.steps.error_chain",
                protocol::MAX_DIAGNOSTIC_BYTES,
            )?,
            duration: required_duration(
                value.duration,
                "agent.status.report.provisioning.steps.duration",
            )?,
        })
    }
}
impl TryFrom<v1::HostMetrics> for MachineMetrics {
    type Error = String;
    fn try_from(value: v1::HostMetrics) -> Result<Self, Self::Error> {
        Ok(Self {
            machine_id: canonical_uuid(value.machine_id, "machine_id")?,
            name: required_text(value.name, "name", protocol::MAX_INFO_BYTES)?,
            monitor: required(value.monitor, "monitor")?.try_into()?,
            metrics: value.metrics.map(TryInto::try_into).transpose()?,
        })
    }
}
impl TryFrom<v1::AgentMetricsObservation> for MachineAgentMetricsObservation {
    type Error = String;
    fn try_from(value: v1::AgentMetricsObservation) -> Result<Self, Self::Error> {
        Ok(Self {
            agent_instance_id: canonical_uuid(
                value.agent_instance_id,
                "metrics.agent_instance_id",
            )?,
            received_at: timestamp(value.received_at, "metrics.received_at")?,
            stale_at: timestamp(value.stale_at, "metrics.stale_at")?,
            freshness: freshness(
                required(value.freshness, "metrics.freshness")?,
                "metrics.freshness",
            )?,
            stale_reason: value
                .stale_reason
                .map(|value| stale_reason(value, "metrics.stale_reason"))
                .transpose()?,
            report: required(value.report, "metrics.report")?.try_into()?,
        })
    }
}
impl TryFrom<v1::AgentMetricReport> for MachineAgentMetricReport {
    type Error = String;
    fn try_from(value: v1::AgentMetricReport) -> Result<Self, Self::Error> {
        Ok(Self {
            observed_at: timestamp(value.observed_at, "metrics.report.observed_at")?,
            snapshot: required(value.snapshot, "metrics.report.snapshot")?.try_into()?,
        })
    }
}
impl TryFrom<v1::MetricSnapshot> for MachineMetricSnapshot {
    type Error = String;
    fn try_from(value: v1::MetricSnapshot) -> Result<Self, Self::Error> {
        if value.filesystems.len() > protocol::MAX_METRIC_ARRAY_ENTRIES
            || value.network_interfaces.len() > protocol::MAX_METRIC_ARRAY_ENTRIES
            || value.block_devices.len() > protocol::MAX_METRIC_ARRAY_ENTRIES
        {
            return Err("vmmon response metric array exceeds maximum size".to_string());
        }
        Ok(Self {
            memory: value.memory.map(TryInto::try_into).transpose()?,
            cpu: value.cpu.map(TryInto::try_into).transpose()?,
            load_average: value.load_average.map(TryInto::try_into).transpose()?,
            uptime_seconds: value
                .uptime_seconds
                .map(|value| finite_nonnegative(Some(value), "metrics.uptime_seconds"))
                .transpose()?,
            filesystems: value
                .filesystems
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            network_interfaces: value
                .network_interfaces
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            block_devices: value
                .block_devices
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}
impl TryFrom<v1::MemoryMetrics> for MachineMemoryMetrics {
    type Error = String;
    fn try_from(value: v1::MemoryMetrics) -> Result<Self, Self::Error> {
        let total_bytes = required(value.total_bytes, "metrics.memory.total_bytes")?;
        let available_bytes = required(value.available_bytes, "metrics.memory.available_bytes")?;
        if available_bytes > total_bytes {
            return Err(
                "vmmon response metrics.memory.available_bytes exceeds total_bytes".to_string(),
            );
        }
        Ok(Self {
            total_bytes,
            available_bytes,
        })
    }
}
impl TryFrom<v1::CpuMetrics> for MachineCpuMetrics {
    type Error = String;
    fn try_from(value: v1::CpuMetrics) -> Result<Self, Self::Error> {
        let logical_cpu_count = required(value.logical_cpu_count, "metrics.cpu.logical_cpu_count")?;
        if logical_cpu_count == 0 {
            return Err(
                "vmmon response metrics.cpu.logical_cpu_count must be positive".to_string(),
            );
        }
        Ok(Self {
            logical_cpu_count,
            user_seconds: finite_nonnegative(value.user_seconds, "metrics.cpu.user_seconds")?,
            nice_seconds: finite_nonnegative(value.nice_seconds, "metrics.cpu.nice_seconds")?,
            system_seconds: finite_nonnegative(value.system_seconds, "metrics.cpu.system_seconds")?,
            idle_seconds: finite_nonnegative(value.idle_seconds, "metrics.cpu.idle_seconds")?,
            iowait_seconds: finite_nonnegative(value.iowait_seconds, "metrics.cpu.iowait_seconds")?,
            irq_seconds: finite_nonnegative(value.irq_seconds, "metrics.cpu.irq_seconds")?,
            softirq_seconds: finite_nonnegative(
                value.softirq_seconds,
                "metrics.cpu.softirq_seconds",
            )?,
            steal_seconds: finite_nonnegative(value.steal_seconds, "metrics.cpu.steal_seconds")?,
        })
    }
}
impl TryFrom<v1::LoadAverageMetrics> for MachineLoadAverageMetrics {
    type Error = String;
    fn try_from(value: v1::LoadAverageMetrics) -> Result<Self, Self::Error> {
        Ok(Self {
            one_minute: finite_nonnegative(value.one_minute, "metrics.load_average.one_minute")?,
            five_minutes: finite_nonnegative(
                value.five_minutes,
                "metrics.load_average.five_minutes",
            )?,
            fifteen_minutes: finite_nonnegative(
                value.fifteen_minutes,
                "metrics.load_average.fifteen_minutes",
            )?,
        })
    }
}
impl TryFrom<v1::FilesystemMetrics> for MachineFilesystemMetrics {
    type Error = String;
    fn try_from(value: v1::FilesystemMetrics) -> Result<Self, Self::Error> {
        let total_bytes = required(value.total_bytes, "metrics.filesystems.total_bytes")?;
        let used_bytes = required(value.used_bytes, "metrics.filesystems.used_bytes")?;
        let available_bytes =
            required(value.available_bytes, "metrics.filesystems.available_bytes")?;
        if used_bytes
            .checked_add(available_bytes)
            .is_none_or(|sum| sum > total_bytes)
        {
            return Err("vmmon response metrics.filesystems totals are inconsistent".to_string());
        }
        Ok(Self {
            mount_point: required_text(
                value.mount_point,
                "metrics.filesystems.mount_point",
                protocol::MAX_PATH_BYTES,
            )?,
            filesystem_type: required_text(
                value.filesystem_type,
                "metrics.filesystems.filesystem_type",
                protocol::MAX_INFO_BYTES,
            )?,
            total_bytes,
            used_bytes,
            available_bytes,
        })
    }
}
impl TryFrom<v1::NetworkInterfaceMetrics> for MachineNetworkInterfaceMetrics {
    type Error = String;
    fn try_from(value: v1::NetworkInterfaceMetrics) -> Result<Self, Self::Error> {
        if let Some(mac) = value.mac.as_deref() {
            validate_mac(mac, "metrics.network_interfaces.mac")?;
        }
        Ok(Self {
            name: required_text(
                value.name,
                "metrics.network_interfaces.name",
                protocol::MAX_INFO_BYTES,
            )?,
            mac: optional_text(
                value.mac,
                "metrics.network_interfaces.mac",
                protocol::MAX_INFO_BYTES,
            )?,
            receive_bytes: required(
                value.receive_bytes,
                "metrics.network_interfaces.receive_bytes",
            )?,
            transmit_bytes: required(
                value.transmit_bytes,
                "metrics.network_interfaces.transmit_bytes",
            )?,
        })
    }
}
impl TryFrom<v1::BlockDeviceMetrics> for MachineBlockDeviceMetrics {
    type Error = String;
    fn try_from(value: v1::BlockDeviceMetrics) -> Result<Self, Self::Error> {
        Ok(Self {
            name: required_text(
                value.name,
                "metrics.block_devices.name",
                protocol::MAX_INFO_BYTES,
            )?,
            read_bytes: required(value.read_bytes, "metrics.block_devices.read_bytes")?,
            read_operations: required(
                value.read_operations,
                "metrics.block_devices.read_operations",
            )?,
            write_bytes: required(value.write_bytes, "metrics.block_devices.write_bytes")?,
            write_operations: required(
                value.write_operations,
                "metrics.block_devices.write_operations",
            )?,
            in_flight_operations: required(
                value.in_flight_operations,
                "metrics.block_devices.in_flight_operations",
            )?,
        })
    }
}
impl TryFrom<v1::FilesystemEntry> for MachineFileEntry {
    type Error = String;
    fn try_from(value: v1::FilesystemEntry) -> Result<Self, Self::Error> {
        let kind = match enum_value::<v1::FilesystemEntryKind>(
            required(value.kind, "filesystem entry.kind")?,
            "filesystem entry.kind",
        )? {
            v1::FilesystemEntryKind::File => MachineEntryKind::File,
            v1::FilesystemEntryKind::Directory => MachineEntryKind::Directory,
            v1::FilesystemEntryKind::Symlink => MachineEntryKind::Symlink,
            v1::FilesystemEntryKind::Fifo => MachineEntryKind::Fifo,
            v1::FilesystemEntryKind::Socket => MachineEntryKind::Socket,
            v1::FilesystemEntryKind::BlockDevice => MachineEntryKind::BlockDevice,
            v1::FilesystemEntryKind::CharacterDevice => MachineEntryKind::CharacterDevice,
            v1::FilesystemEntryKind::Unspecified => {
                return Err("vmmon response has unspecified filesystem entry.kind".to_string());
            }
        };
        Ok(Self {
            path: required(value.path, "filesystem entry.path")?,
            name: required(value.name, "filesystem entry.name")?,
            kind,
            size_bytes: required(value.size_bytes, "filesystem entry.size_bytes")?,
            mode: required(value.mode, "filesystem entry.mode")?,
            uid: required(value.uid, "filesystem entry.uid")?,
            gid: required(value.gid, "filesystem entry.gid")?,
            modified_at: timestamp(value.modified_at, "filesystem entry.modified_at")?,
        })
    }
}
impl TryFrom<v1::DirectoryPage> for MachineDirectoryPage {
    type Error = String;
    fn try_from(value: v1::DirectoryPage) -> Result<Self, Self::Error> {
        if value.entries.len() > protocol::MAX_DIRECTORY_PAGE_SIZE as usize {
            return Err("vmmon response directory page exceeds maximum size".to_string());
        }
        let next_cursor = value.next_cursor.map(Bytes::from);
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > protocol::MAX_CURSOR_BYTES)
        {
            return Err("vmmon response directory cursor exceeds maximum size".to_string());
        }
        Ok(Self {
            entries: value
                .entries
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            next_cursor,
        })
    }
}
impl TryFrom<Option<i32>> for MachineDirectoryCreateDisposition {
    type Error = String;
    fn try_from(value: Option<i32>) -> Result<Self, Self::Error> {
        match enum_value::<v1::DirectoryCreateDisposition>(
            required(value, "directory create disposition")?,
            "directory create disposition",
        )? {
            v1::DirectoryCreateDisposition::Created => Ok(Self::Created),
            v1::DirectoryCreateDisposition::AlreadyExists => Ok(Self::AlreadyExists),
            v1::DirectoryCreateDisposition::Unspecified => {
                Err("vmmon response has unspecified directory create disposition".to_string())
            }
        }
    }
}
impl TryFrom<Option<i32>> for FileWriteDisposition {
    type Error = String;
    fn try_from(value: Option<i32>) -> Result<Self, Self::Error> {
        match enum_value::<v1::FileWriteDisposition>(
            required(value, "file write disposition")?,
            "file write disposition",
        )? {
            v1::FileWriteDisposition::Created => Ok(Self::Created),
            v1::FileWriteDisposition::Replaced => Ok(Self::Replaced),
            v1::FileWriteDisposition::Unspecified => {
                Err("vmmon response has unspecified file write disposition".to_string())
            }
        }
    }
}
impl TryFrom<v1::WaitReadyResponse> for MachineReadiness {
    type Error = String;
    fn try_from(value: v1::WaitReadyResponse) -> Result<Self, Self::Error> {
        let outcome = match enum_value::<v1::WaitReadyOutcome>(
            required(value.outcome, "wait ready outcome")?,
            "wait ready outcome",
        )? {
            v1::WaitReadyOutcome::Ready => MachineReadinessOutcome::Ready,
            v1::WaitReadyOutcome::Terminal => MachineReadinessOutcome::Terminal,
            v1::WaitReadyOutcome::TimedOut => MachineReadinessOutcome::TimedOut,
            v1::WaitReadyOutcome::Unspecified => {
                return Err("vmmon response has unspecified wait ready outcome".to_string());
            }
        };
        Ok(Self {
            outcome,
            status: required(value.status, "wait ready status")?.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ErrorAfterChunk(bool);

    impl AsyncRead for ErrorAfterChunk {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0 {
                return Poll::Ready(Err(io::Error::other("source read failed")));
            }
            self.0 = true;
            buffer.put_slice(b"partial");
            Poll::Ready(Ok(()))
        }
    }

    fn timestamp() -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: 1,
            nanos: 2,
        }
    }

    fn status() -> v1::HostStatus {
        v1::HostStatus {
            machine_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
            name: Some("machine".to_string()),
            monitor: Some(v1::MonitorSnapshot {
                instance_id: Some("00000000-0000-4000-8000-000000000002".to_string()),
                observed_at: Some(timestamp()),
            }),
            vm: Some(v1::VmSnapshot {
                state: Some(v1::VmState::Running as i32),
                state_changed_at: Some(timestamp()),
                running_since: Some(timestamp()),
                code: Some("running".to_string()),
                message: Some("healthy".to_string()),
            }),
            readiness: Some(v1::Readiness {
                ready: Some(true),
                reason: Some(v1::ReadinessReason::GuestReportedReady as i32),
            }),
            agent: Some(v1::HostAgent {
                mode: Some(v1::host_agent::Mode::Enabled(v1::EnabledAgent {
                    connection: Some(v1::AgentConnection {
                        state: Some(v1::AgentConnectionState::Responsive as i32),
                        last_success_at: Some(timestamp()),
                        last_failure_at: Some(timestamp()),
                        code: Some("ok".to_string()),
                        message: Some("connected".to_string()),
                    }),
                    identity: Some(v1::AgentIdentity {
                        instance_id: Some("00000000-0000-4000-8000-000000000003".to_string()),
                        version: Some("1.0".to_string()),
                        boot_id: Some("00000000-0000-4000-8000-000000000004".to_string()),
                    }),
                    status: Some(v1::AgentStatusObservation {
                        received_at: Some(timestamp()),
                        stale_at: Some(timestamp()),
                        freshness: Some(v1::Freshness::Fresh as i32),
                        stale_reason: Some(v1::StaleReason::ReceiptAge as i32),
                        report: Some(v1::AgentStatusReport {
                            observed_at: Some(timestamp()),
                            state: Some(v1::AgentStatusState::Ready as i32),
                            code: Some("ready".to_string()),
                            message: Some("guest ready".to_string()),
                            system: Some(v1::SystemInfo {
                                hostname: Some("guest".to_string()),
                                ip_addresses: vec!["192.0.2.1".to_string()],
                                ..v1::SystemInfo::default()
                            }),
                            boot: Some(v1::GuestBootReport {
                                mode: Some(v1::GuestBootMode::Standard as i32),
                                agent_pid: Some(1),
                                agent_is_pid1: Some(true),
                                ..v1::GuestBootReport::default()
                            }),
                            provisioning: Some(v1::ProvisionReport {
                                status: Some(v1::ProvisionOverallStatus::Succeeded as i32),
                                started_at: Some(timestamp()),
                                finished_at: Some(timestamp()),
                                duration: Some(prost_types::Duration::default()),
                                steps: vec![v1::ProvisionStepReport {
                                    id: Some("step".to_string()),
                                    status: Some(v1::ProvisionStepStatus::Succeeded as i32),
                                    failure_policy: Some(
                                        v1::ProvisionFailurePolicy::BestEffort as i32,
                                    ),
                                    changed: Some(false),
                                    duration: Some(prost_types::Duration::default()),
                                    ..v1::ProvisionStepReport::default()
                                }],
                                ..v1::ProvisionReport::default()
                            }),
                        }),
                    }),
                })),
            }),
        }
    }

    #[test]
    fn filesystem_entries_require_complete_known_data() {
        assert!(MachineFileEntry::try_from(v1::FilesystemEntry::default()).is_err());
    }
    #[test]
    fn unknown_enum_is_rejected() {
        assert!(vm_state(99, "vm.state").is_err());
    }
    #[test]
    fn malformed_status_is_rejected() {
        assert!(MachineMonitorStatus::try_from(v1::HostStatus::default()).is_err());
    }
    #[test]
    fn status_rejects_missing_required_nested_fields() {
        let mut missing_vm_state = status();
        missing_vm_state.vm.as_mut().expect("vm").state = None;
        assert!(MachineMonitorStatus::try_from(missing_vm_state).is_err());

        let mut missing_connection = status();
        let Some(v1::host_agent::Mode::Enabled(agent)) = missing_connection
            .agent
            .as_mut()
            .expect("agent")
            .mode
            .as_mut()
        else {
            panic!("enabled agent")
        };
        agent.connection = None;
        assert!(MachineMonitorStatus::try_from(missing_connection).is_err());

        let mut missing_report = status();
        let Some(v1::host_agent::Mode::Enabled(agent)) =
            missing_report.agent.as_mut().expect("agent").mode.as_mut()
        else {
            panic!("enabled agent")
        };
        agent.status.as_mut().expect("status").report = None;
        assert!(MachineMonitorStatus::try_from(missing_report).is_err());
    }
    #[test]
    fn metrics_reject_missing_or_invalid_required_values() {
        assert!(MachineMetrics::try_from(v1::HostMetrics::default()).is_err());
        assert!(MachineMemoryMetrics::try_from(v1::MemoryMetrics {
            total_bytes: Some(1),
            available_bytes: Some(2),
        })
        .is_err());
        assert!(MachineCpuMetrics::try_from(v1::CpuMetrics {
            logical_cpu_count: Some(1),
            user_seconds: Some(f64::NAN),
            nice_seconds: Some(0.0),
            system_seconds: Some(0.0),
            idle_seconds: Some(0.0),
            iowait_seconds: Some(0.0),
            irq_seconds: Some(0.0),
            softirq_seconds: Some(0.0),
            steal_seconds: Some(0.0),
        })
        .is_err());
    }
    #[test]
    fn status_conversion_preserves_nested_agent_observation() {
        let converted = MachineMonitorStatus::try_from(status()).expect("valid status");
        assert_eq!(
            converted.monitor.instance_id,
            "00000000-0000-4000-8000-000000000002"
        );
        assert_eq!(converted.vm.state, MachineVmState::Running);
        let MachineAgentStatus::Enabled(agent) = converted.agent else {
            panic!("enabled agent")
        };
        assert_eq!(
            agent
                .identity
                .as_ref()
                .map(|identity| identity.boot_id.as_str()),
            Some("00000000-0000-4000-8000-000000000004")
        );
        assert_eq!(
            agent
                .status
                .map(|status| status.report)
                .and_then(|report| report.system)
                .and_then(|system| system.hostname)
                .as_deref(),
            Some("guest")
        );
    }
    #[test]
    fn metrics_conversion_preserves_every_snapshot_array() {
        let metrics = MachineMetrics::try_from(v1::HostMetrics {
            machine_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
            name: Some("machine".to_string()),
            monitor: Some(v1::MonitorSnapshot {
                instance_id: Some("00000000-0000-4000-8000-000000000002".to_string()),
                observed_at: Some(timestamp()),
            }),
            metrics: Some(v1::AgentMetricsObservation {
                received_at: Some(timestamp()),
                stale_at: Some(timestamp()),
                freshness: Some(v1::Freshness::Fresh as i32),
                stale_reason: None,
                report: Some(v1::AgentMetricReport {
                    observed_at: Some(timestamp()),
                    snapshot: Some(v1::MetricSnapshot {
                        memory: Some(v1::MemoryMetrics {
                            total_bytes: Some(2),
                            available_bytes: Some(2),
                        }),
                        cpu: Some(v1::CpuMetrics {
                            logical_cpu_count: Some(3),
                            user_seconds: Some(0.0),
                            nice_seconds: Some(0.0),
                            system_seconds: Some(0.0),
                            idle_seconds: Some(0.0),
                            iowait_seconds: Some(0.0),
                            irq_seconds: Some(0.0),
                            softirq_seconds: Some(0.0),
                            steal_seconds: Some(0.0),
                        }),
                        load_average: Some(v1::LoadAverageMetrics {
                            one_minute: Some(4.0),
                            five_minutes: Some(4.0),
                            fifteen_minutes: Some(4.0),
                        }),
                        uptime_seconds: Some(5.0),
                        filesystems: vec![v1::FilesystemMetrics {
                            mount_point: Some("/".to_string()),
                            filesystem_type: Some("ext4".to_string()),
                            total_bytes: Some(3),
                            used_bytes: Some(1),
                            available_bytes: Some(2),
                        }],
                        network_interfaces: vec![v1::NetworkInterfaceMetrics {
                            name: Some("eth0".to_string()),
                            mac: Some("00:11:22:33:44:55".to_string()),
                            receive_bytes: Some(1),
                            transmit_bytes: Some(2),
                        }],
                        block_devices: vec![v1::BlockDeviceMetrics {
                            name: Some("vda".to_string()),
                            read_bytes: Some(1),
                            read_operations: Some(2),
                            write_bytes: Some(3),
                            write_operations: Some(4),
                            in_flight_operations: Some(5),
                        }],
                    }),
                }),
                agent_instance_id: Some("00000000-0000-4000-8000-000000000003".to_string()),
            }),
        })
        .expect("valid metrics");
        let snapshot = metrics
            .metrics
            .map(|metrics| metrics.report.snapshot)
            .expect("snapshot");
        assert_eq!(
            snapshot.memory.map(|memory| memory.available_bytes),
            Some(2)
        );
        assert_eq!(snapshot.filesystems.len(), 1);
        assert_eq!(snapshot.network_interfaces.len(), 1);
        assert_eq!(snapshot.block_devices.len(), 1);
    }
    #[test]
    fn request_validation_rejects_invalid_values() {
        assert!(validate_path("relative".to_string()).is_err());
        assert!(validate_mode(Some(0o10_000)).is_err());
        assert!(validate_page(Some(0), None).is_err());
    }

    #[test]
    fn negative_timestamp_nanos_count_forward_from_the_second() {
        let converted = crate::machine::streams::timestamp(
            Some(prost_types::Timestamp {
                seconds: -1,
                nanos: 500_000_000,
            }),
            "test timestamp",
        )
        .expect("valid timestamp");

        assert_eq!(
            converted
                .duration_since(UNIX_EPOCH)
                .expect_err("timestamp precedes epoch")
                .duration(),
            Duration::from_millis(500)
        );
    }

    #[tokio::test]
    async fn failed_upload_producer_keeps_request_open_until_cancelled() {
        let (sender, mut receiver) = mpsc::channel(4);
        let (producer, completion) = spawn_upload_producer(
            sender,
            UploadFileHeader {
                path: Some("/file".to_string()),
                mode: None,
                uid: None,
                gid: None,
            },
            ErrorAfterChunk(false),
        );

        assert!(matches!(
            receiver.recv().await.and_then(|message| message.payload),
            Some(v1::upload_file_request::Payload::Header(_))
        ));
        assert!(matches!(
            receiver.recv().await.and_then(|message| message.payload),
            Some(v1::upload_file_request::Payload::Chunk(_))
        ));
        let error = completion
            .await
            .expect("producer reports completion")
            .expect_err("reader failure");
        assert_eq!(error.to_string(), "source read failed");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), receiver.recv())
                .await
                .is_err(),
            "failed producer must not signal a clean request EOF"
        );

        drop(producer);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .expect("aborted producer closes request stream")
                .is_none()
        );
    }
}

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use agent_spec::SSH_VSOCK_PORT;
use eyre::Context;
use futures::{Stream, StreamExt};
use protocol::v1::vm_access_service_server::{VmAccessService, VmAccessServiceServer};
use protocol::v1::vm_monitor_service_server::{VmMonitorService, VmMonitorServiceServer};
use protocol::v1::{
    ByteChunk, GetMetricsRequest, GetStatusRequest, HostMetrics, HostStatus, WaitReadyOutcome,
    WaitReadyRequest, WaitReadyResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use tonic_health::server::{health_reporter, HealthReporter};
use virt::{SerialAccess, SerialConsole, SerialStream, VirtualMachine};

use crate::context::{DaemonContext, RuntimeContext};
use crate::endpoints::start_endpoint_supervisor;
use crate::guest::spawn_guest_services;
use crate::startup::SyncReporter;
use crate::state::{InstanceStore, StoreError, WaitOutcome};

#[path = "filesystem.rs"]
mod filesystem;
use filesystem::FilesystemProxy;

const MAX_WAIT: Duration = Duration::from_secs(5 * 60);
const PRODUCED_CHUNK_BYTES: usize = 32 * 1024;
const ACCEPTED_CHUNK_BYTES: usize = 64 * 1024;
const BACKEND_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ServiceHandles {
    pub(crate) control_socket: JoinHandle<eyre::Result<()>>,
    pub(crate) guest_monitor: Option<JoinHandle<()>>,
    pub(crate) endpoint_supervisor: Option<JoinHandle<()>>,
    pub(crate) serial_log: JoinHandle<()>,
    pub(crate) health: HealthReporter,
    pub(crate) server_shutdown: CancellationToken,
}

#[derive(Clone)]
struct MonitorService {
    store: Arc<InstanceStore>,
    finite_capacity: Arc<Semaphore>,
    waiter_capacity: Arc<Semaphore>,
}

#[tonic::async_trait]
impl VmMonitorService for MonitorService {
    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<HostStatus>, Status> {
        let _permit = admission(&self.finite_capacity, "monitor finite RPC")?;
        Ok(Response::new(self.store.status().map_err(store_status)?))
    }

    async fn wait_ready(
        &self,
        request: Request<WaitReadyRequest>,
    ) -> Result<Response<WaitReadyResponse>, Status> {
        let _permit = admission(&self.waiter_capacity, "readiness waiter")?;
        let max_wait = parse_wait(request.into_inner().max_wait)?;
        let mut changed = self.store.subscribe();
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            let outcome = self.store.readiness().map_err(store_status)?;
            if outcome != WaitOutcome::TimedOut {
                return Ok(Response::new(wait_response(
                    outcome,
                    self.store.status().map_err(store_status)?,
                )));
            }
            match tokio::time::timeout_at(deadline, changed.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Err(protocol::detailed_status(Status::unavailable(
                        "monitor state notifications stopped",
                    )));
                }
                Err(_) => {
                    return Ok(Response::new(wait_response(
                        WaitOutcome::TimedOut,
                        self.store.status().map_err(store_status)?,
                    )));
                }
            }
        }
    }

    async fn get_metrics(
        &self,
        _: Request<GetMetricsRequest>,
    ) -> Result<Response<HostMetrics>, Status> {
        let _permit = admission(&self.finite_capacity, "monitor finite RPC")?;
        Ok(Response::new(self.store.metrics().map_err(store_status)?))
    }
}

#[derive(Clone)]
struct AccessService {
    machine: VirtualMachine,
    serial: Arc<SerialConsole>,
    shutdown: CancellationToken,
    ssh_capacity: Arc<Semaphore>,
}
type ChunkStream = Pin<Box<dyn Stream<Item = Result<ByteChunk, Status>> + Send>>;

#[tonic::async_trait]
impl VmAccessService for AccessService {
    type OpenSshStream = ChunkStream;
    type OpenSerialStream = ChunkStream;

    async fn open_ssh(
        &self,
        request: Request<tonic::Streaming<ByteChunk>>,
    ) -> Result<Response<Self::OpenSshStream>, Status> {
        if self.shutdown.is_cancelled() {
            return Err(protocol::status_with_error(
                tonic::Code::Unavailable,
                protocol::v1::ErrorCode::MonitorStopping,
                "monitor is stopping",
                None,
            ));
        }
        let permit = admission(&self.ssh_capacity, "SSH stream")?;
        // Acquiring the backend before responding keeps a successful RPC meaningful.
        let stream = tokio::time::timeout(
            BACKEND_SETUP_TIMEOUT,
            self.machine.connect_vsock(SSH_VSOCK_PORT),
        )
        .await
        .map_err(|_| {
            protocol::status_with_error(
                tonic::Code::DeadlineExceeded,
                protocol::v1::ErrorCode::AgentTimeout,
                "SSH backend setup timed out",
                None,
            )
        })?
        .map_err(|error| {
            protocol::status_with_error(
                tonic::Code::Unavailable,
                protocol::v1::ErrorCode::BackendUnavailable,
                format!("SSH backend unavailable: {error}"),
                None,
            )
        })?;
        Ok(Response::new(Box::pin(relay(
            stream,
            request.into_inner(),
            self.shutdown.clone(),
            permit,
        ))))
    }

    async fn open_serial(
        &self,
        request: Request<tonic::Streaming<ByteChunk>>,
    ) -> Result<Response<Self::OpenSerialStream>, Status> {
        if self.shutdown.is_cancelled() {
            return Err(protocol::status_with_error(
                tonic::Code::Unavailable,
                protocol::v1::ErrorCode::MonitorStopping,
                "monitor is stopping",
                None,
            ));
        }
        let stream = tokio::time::timeout(
            BACKEND_SETUP_TIMEOUT,
            self.serial.open_stream(SerialAccess::Interactive),
        )
        .await
        .map_err(|_| {
            protocol::status_with_error(
                tonic::Code::DeadlineExceeded,
                protocol::v1::ErrorCode::AgentTimeout,
                "serial backend setup timed out",
                None,
            )
        })?
        .map_err(|error| {
            protocol::status_with_error(
                tonic::Code::ResourceExhausted,
                protocol::v1::ErrorCode::SerialInUse,
                format!("serial backend unavailable: {error}"),
                None,
            )
        })?;
        Ok(Response::new(Box::pin(relay_serial(
            stream,
            request.into_inner(),
            self.shutdown.clone(),
        ))))
    }
}

impl ServiceHandles {
    pub(crate) async fn mark_stopping(&self) {
        for service in [
            "silo.v1.VmAccessService",
            "silo.v1.GuestFilesystemService",
            "grpc.reflection.v1.ServerReflection",
        ] {
            self.health
                .set_service_status(service, tonic_health::ServingStatus::NotServing)
                .await;
        }
    }

    pub(crate) async fn mark_not_serving(&self) {
        self.mark_stopping().await;
        self.health
            .set_service_status(
                "silo.v1.VmMonitorService",
                tonic_health::ServingStatus::NotServing,
            )
            .await;
        self.health
            .set_service_status("", tonic_health::ServingStatus::NotServing)
            .await;
    }
}

pub async fn start_services(
    runtime: &RuntimeContext,
    ctx: &DaemonContext,
    sync_reporter: &mut SyncReporter,
) -> eyre::Result<ServiceHandles> {
    let path = runtime.socket().to_path_buf();
    let listener = UnixListener::bind(&path).context(format!("bind socket {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .context(format!("set socket permissions {}", path.display()))?;
    let socket_owner_uid = std::fs::metadata(&path)
        .context(format!("read socket metadata {}", path.display()))?
        .uid();

    let (health, health_service) = health_reporter();
    health
        .set_serving::<VmMonitorServiceServer<MonitorService>>()
        .await;
    health
        .set_serving::<VmAccessServiceServer<AccessService>>()
        .await;
    health
        .set_serving::<protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer<
            FilesystemProxy,
        >>()
        .await;
    health
        .set_service_status(
            "grpc.reflection.v1.ServerReflection",
            tonic_health::ServingStatus::Serving,
        )
        .await;
    health
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    let reflection_descriptors = protocol::reflection_descriptor_set(&[
        "silo.v1.VmMonitorService",
        "silo.v1.VmAccessService",
        "silo.v1.GuestFilesystemService",
    ])
    .context("filter host gRPC reflection descriptors")?;
    let reflection = tonic_reflection::server::Builder::configure()
        .register_file_descriptor_set(reflection_descriptors)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .with_service_name("silo.v1.VmMonitorService")
        .with_service_name("silo.v1.VmAccessService")
        .with_service_name("silo.v1.GuestFilesystemService")
        .with_service_name("grpc.health.v1.Health")
        .with_service_name("grpc.reflection.v1.ServerReflection")
        .build_v1()
        .context("build gRPC reflection service")?;
    let server_shutdown = CancellationToken::new();
    let server_shutdown_signal = server_shutdown.clone();
    let monitor = MonitorService {
        store: ctx.store.clone(),
        finite_capacity: Arc::new(Semaphore::new(64)),
        waiter_capacity: Arc::new(Semaphore::new(64)),
    };
    let access = AccessService {
        machine: ctx.machine.clone(),
        serial: ctx.serial_console.clone(),
        shutdown: ctx.shutdown.clone(),
        ssh_capacity: Arc::new(Semaphore::new(32)),
    };
    let filesystem = FilesystemProxy::new(ctx.machine.clone(), ctx.shutdown.clone());
    let control_socket = tokio::spawn(async move {
        let monitor = VmMonitorServiceServer::new(monitor)
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let access = VmAccessServiceServer::new(access)
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let filesystem =
            protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer::new(
                filesystem,
            )
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let incoming = UnixListenerStream::new(listener).filter_map(move |connection| async move {
            match connection {
                Ok(stream) => match stream.peer_cred() {
                    Ok(credentials)
                        if peer_uid_authorized(socket_owner_uid, credentials.uid()) =>
                    {
                        tracing::debug!(
                            uid = credentials.uid(),
                            gid = credentials.gid(),
                            pid = ?credentials.pid(),
                            "accepted vmmon gRPC connection"
                        );
                        Some(Ok(stream))
                    }
                    Ok(credentials) => {
                        tracing::warn!(
                            uid = credentials.uid(),
                            expected_uid = socket_owner_uid,
                            "rejected vmmon gRPC connection from unauthorized UID"
                        );
                        None
                    }
                    Err(error) => {
                        tracing::warn!(%error, "rejected vmmon gRPC connection without peer credentials");
                        None
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "vmmon gRPC accept failed");
                    Some(Err(error))
                }
            }
        });
        tonic::transport::Server::builder()
            .trace_fn(|request| tracing::info_span!("grpc", method = %request.uri()))
            .add_service(health_service)
            .add_service(reflection)
            .add_service(monitor)
            .add_service(access)
            .add_service(filesystem)
            .serve_with_incoming_shutdown(incoming, server_shutdown_signal.cancelled())
            .await
            .map_err(eyre::Report::from)
    });

    let serial_log_path = runtime.serial_log().to_path_buf();
    let serial_console = ctx.serial_console.clone();
    let serial_log = tokio::spawn(async move {
        if let Err(error) = serial_console.stream_to_file(&serial_log_path).await {
            tracing::warn!(%error, path = %serial_log_path.display(), "serial log attachment failed");
        }
    });
    let guest_monitor = if ctx.guest_services_enabled {
        Some(spawn_guest_services(&ctx.machine, ctx.store.clone(), ctx.shutdown.clone()).await?)
    } else {
        None
    };
    let endpoint_supervisor = start_endpoint_supervisor(ctx.clone(), runtime.dir().to_path_buf());
    tracing::info!(
        socket = %path.display(),
        guest_services_enabled = ctx.guest_services_enabled,
        "vmmon gRPC control plane is serving"
    );
    sync_reporter.report_started()?;
    Ok(ServiceHandles {
        control_socket,
        guest_monitor,
        endpoint_supervisor,
        serial_log,
        health,
        server_shutdown,
    })
}

fn peer_uid_authorized(socket_owner_uid: u32, peer_uid: u32) -> bool {
    socket_owner_uid == peer_uid
}

fn relay<S, I>(
    stream: S,
    mut input: I,
    shutdown: CancellationToken,
    _permit: OwnedSemaphorePermit,
) -> ReceiverStream<Result<ByteChunk, Status>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    I: Stream<Item = Result<ByteChunk, Status>> + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let _permit = _permit;
        let (mut read, mut write) = tokio::io::split(stream);
        let mut input_task = Box::pin(async {
            while let Some(chunk) = input.next().await {
                let chunk = chunk?;
                let data = chunk.data.unwrap_or_default();
                if data.len() > ACCEPTED_CHUNK_BYTES {
                    return Err(protocol::detailed_status(Status::invalid_argument(
                        "access chunks may not exceed 64 KiB",
                    )));
                }
                if !data.is_empty() {
                    if let Err(error) = write.write_all(&data).await {
                        if clean_disconnect(&error) {
                            return Ok(());
                        }
                        return Err(protocol::detailed_status(Status::from(error)));
                    }
                }
            }
            match write.shutdown().await {
                Ok(()) => Ok(()),
                Err(error) if clean_disconnect(&error) => Ok(()),
                Err(error) => Err(protocol::detailed_status(Status::from(error))),
            }
        });
        let mut input_done = false;
        let mut buffer = [0_u8; PRODUCED_CHUNK_BYTES];
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tx.closed() => return,
                result = &mut input_task, if !input_done => match result {
                    Ok(()) => input_done = true,
                    Err(error) => {
                        let _ = tx.send(Err(protocol::detailed_status(error))).await;
                        return;
                    }
                },
                result = read.read(&mut buffer) => match result {
                    Ok(0) => return,
                    Ok(count) => {
                        if tx.send(Ok(ByteChunk {
                            data: Some(bytes::Bytes::copy_from_slice(&buffer[..count])),
                        })).await.is_err() {
                            return;
                        }
                    }
                    Err(error) if clean_disconnect(&error) => return,
                    Err(error) => {
                        let _ = tx
                            .send(Err(protocol::detailed_status(Status::from(error))))
                            .await;
                        return;
                    }
                },
            }
        }
    });
    ReceiverStream::new(rx)
}

fn relay_serial(
    mut serial: SerialStream,
    mut input: tonic::Streaming<ByteChunk>,
    shutdown: CancellationToken,
) -> ReceiverStream<Result<ByteChunk, Status>> {
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut input_closed = false;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tx.closed() => return,
                output = serial.read_output() => match output {
                    Ok(Some(data)) => {
                        for data in data.chunks(PRODUCED_CHUNK_BYTES) {
                            if tx.send(Ok(ByteChunk { data: Some(bytes::Bytes::copy_from_slice(data)) })).await.is_err() { return; }
                        }
                    }
                    Ok(None) => return,
                    Err(error) => { let _ = tx.send(Err(protocol::detailed_status(Status::from(error)))).await; return; }
                },
                message = input.next(), if !input_closed => match message {
                    Some(Ok(chunk)) => {
                        let data = chunk.data.unwrap_or_default();
                        if data.len() > ACCEPTED_CHUNK_BYTES { let _ = tx.send(Err(protocol::detailed_status(Status::invalid_argument("access chunks may not exceed 64 KiB")))).await; return; }
                        if !data.is_empty() {
                            if let Err(error) = serial.write_input(&data).await { let _ = tx.send(Err(protocol::detailed_status(Status::from(error)))).await; return; }
                        }
                    }
                    Some(Err(error)) => { let _ = tx.send(Err(error)).await; return; }
                    None => input_closed = true,
                },
            }
        }
    });
    ReceiverStream::new(rx)
}

fn clean_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

fn parse_wait(value: Option<prost_types::Duration>) -> Result<Duration, Status> {
    let value = value.ok_or_else(|| {
        protocol::detailed_status(Status::invalid_argument("max_wait is required"))
    })?;
    if value.seconds < 0 || value.nanos < 0 || value.nanos >= 1_000_000_000 {
        return Err(protocol::detailed_status(Status::invalid_argument(
            "max_wait must be positive",
        )));
    }
    let duration = Duration::new(value.seconds as u64, value.nanos as u32);
    if duration.is_zero() || duration > MAX_WAIT {
        return Err(protocol::detailed_status(Status::invalid_argument(
            "max_wait must be greater than zero and at most five minutes",
        )));
    }
    Ok(duration)
}

fn wait_response(outcome: WaitOutcome, status: HostStatus) -> WaitReadyResponse {
    let outcome = match outcome {
        WaitOutcome::Ready => WaitReadyOutcome::Ready,
        WaitOutcome::Terminal => WaitReadyOutcome::Terminal,
        WaitOutcome::TimedOut => WaitReadyOutcome::TimedOut,
    };
    WaitReadyResponse {
        outcome: Some(outcome as i32),
        status: Some(status),
    }
}

fn store_status(error: StoreError) -> Status {
    protocol::detailed_status(Status::internal(error.to_string()))
}

fn admission(capacity: &Arc<Semaphore>, resource: &str) -> Result<OwnedSemaphorePermit, Status> {
    capacity.clone().try_acquire_owned().map_err(|_| {
        protocol::status_with_error(
            tonic::Code::ResourceExhausted,
            protocol::v1::ErrorCode::ResourceExhausted,
            format!("{resource} capacity is exhausted"),
            None,
        )
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::StreamExt;
    use protocol::v1::ByteChunk;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::CancellationToken;

    use crate::services::{peer_uid_authorized, relay};

    #[test]
    fn socket_peer_must_match_its_owner() {
        assert!(peer_uid_authorized(501, 501));
        assert!(!peer_uid_authorized(501, 502));
    }

    #[tokio::test]
    async fn access_relay_preserves_output_after_request_half_close() {
        let (server, mut backend) = tokio::io::duplex(1024);
        let (input_tx, input_rx) = tokio::sync::mpsc::channel(2);
        let mut output = relay(
            server,
            ReceiverStream::new(input_rx),
            CancellationToken::new(),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .expect("relay permit"),
        );
        input_tx
            .send(Ok(ByteChunk {
                data: Some(Bytes::from_static(b"request")),
            }))
            .await
            .expect("send request");
        drop(input_tx);

        let backend_task = tokio::spawn(async move {
            let mut request = Vec::new();
            backend
                .read_to_end(&mut request)
                .await
                .expect("read half-closed request");
            backend
                .write_all(b"response after EOF")
                .await
                .expect("write response");
            backend.shutdown().await.expect("shutdown response");
            request
        });

        let mut response = Vec::new();
        while let Some(chunk) = output.next().await {
            response.extend_from_slice(&chunk.expect("valid output").data.expect("output data"));
        }
        assert_eq!(backend_task.await.expect("backend joins"), b"request");
        assert_eq!(response, b"response after EOF");
    }
}

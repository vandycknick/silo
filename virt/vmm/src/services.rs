use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::virt::{SerialConsole, SerialStream, VirtualMachine};
use agent_spec::SSH_VSOCK_PORT;
use eyre::Context;
use futures::{Stream, StreamExt};
use protocol::v1::vm_access_service_server::{VmAccessService, VmAccessServiceServer};
use protocol::v1::vm_execution_service_server::VmExecutionServiceServer;
use protocol::v1::vm_forward_service_server::VmForwardServiceServer;
use protocol::v1::vm_monitor_service_server::{VmMonitorService, VmMonitorServiceServer};
use protocol::v1::{
    ByteChunk, CancelOperationRequest, CancelOperationResponse, CaptureRequest, CaptureResponse,
    GetMetricsRequest, GetOperationRequest, GetOperationResponse, GetStatusRequest, HostMetrics,
    HostStatus, PauseRequest, PauseResponse, ReleaseCaptureRequest, ReleaseCaptureResponse,
    ResumeRequest, ResumeResponse, WaitReadyOutcome, WaitReadyRequest, WaitReadyResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use tonic_health::server::{health_reporter, HealthReporter};
use vm_spec::lifecycle::{LiveCommand, LiveCommandResult};

use crate::context::{DaemonContext, RuntimeContext};
use crate::execution::ExecutionService;
use crate::guest::spawn_guest_services;
use crate::live::coordinator::{LiveCoordinator, LiveError};
use crate::live::gate::{GateKind, GateRefusal, LiveGate};
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
    pub(crate) health: HealthReporter,
    pub(crate) server_shutdown: CancellationToken,
    pub(crate) startup_command: Option<JoinHandle<()>>,
    pub(crate) vsock_surface: Option<crate::vsock::VsockSurface>,
    pub(crate) forwards: Option<Arc<crate::forward::ForwardTable>>,
}

pub(crate) struct StartupGate {
    pub(crate) require_guest_ready: bool,
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) cancelled: CancellationToken,
    /// A restored machine: activated after the control-only guest service
    /// is up and before anything is exposed or `started` is reported.
    pub(crate) activation: Option<crate::restore::activation::Activation>,
}

#[derive(Clone)]
struct MonitorService {
    store: Arc<InstanceStore>,
    machine_run_id: String,
    finite_capacity: Arc<Semaphore>,
    waiter_capacity: Arc<Semaphore>,
    live: Arc<LiveCoordinator>,
}

impl MonitorService {
    /// Decode, run and encode one live command. A malformed request has no
    /// trustworthy identity and is INVALID_ARGUMENT; every well-formed one
    /// receives a typed body.
    async fn live_command<WireRequest, Command, WireResponse>(
        &self,
        request: WireRequest,
        capacity: &Arc<Semaphore>,
        wrap: fn(Command) -> LiveCommand,
        unwrap: fn(LiveCommandResult) -> Option<WireResponse>,
    ) -> Result<Response<WireResponse>, Status>
    where
        Command: TryFrom<WireRequest, Error = String>,
    {
        let _permit = admission(capacity, "live command")?;
        let command = Command::try_from(request).map_err(|error| {
            protocol::detailed_status(Status::invalid_argument(format!(
                "invalid live command: {error}"
            )))
        })?;
        let result = self.live.handle(wrap(command)).await.map_err(live_status)?;
        result
            .validate()
            .map_err(|error| Status::internal(format!("invalid live result: {error}")))?;
        unwrap(result)
            .map(Response::new)
            .ok_or_else(|| Status::internal("live result does not match its command"))
    }
}

fn live_status(error: LiveError) -> Status {
    protocol::detailed_status(Status::internal(error.to_string()))
}

fn encode<D, W: TryFrom<D, Error = String>>(value: D) -> Option<W> {
    match W::try_from(value) {
        Ok(wire) => Some(wire),
        Err(error) => {
            tracing::error!(%error, "live result failed strict encoding");
            None
        }
    }
}

impl MonitorService {
    fn status(&self) -> Result<HostStatus, Status> {
        let status = self.store.status().map_err(store_status)?;
        let live = status
            .live
            .as_ref()
            .ok_or_else(|| Status::internal("monitor live evidence missing"))?;
        if status.run_id.as_deref() != Some(self.machine_run_id.as_str())
            || live.run_id.as_deref() != Some(self.machine_run_id.as_str())
            || live.machine_id != status.machine_id
            || live.monitor_id
                != status
                    .monitor
                    .as_ref()
                    .and_then(|monitor| monitor.instance_id.clone())
        {
            return Err(Status::internal(
                "monitor live evidence does not match current run",
            ));
        }
        Ok(status)
    }
}

#[tonic::async_trait]
impl VmMonitorService for MonitorService {
    async fn get_status(
        &self,
        _: Request<GetStatusRequest>,
    ) -> Result<Response<HostStatus>, Status> {
        let _permit = admission(&self.finite_capacity, "monitor finite RPC")?;
        Ok(Response::new(self.status()?))
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
                return Ok(Response::new(wait_response(outcome, self.status()?)));
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
                        self.status()?,
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

    async fn pause(
        &self,
        request: Request<PauseRequest>,
    ) -> Result<Response<PauseResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.finite_capacity,
            LiveCommand::Pause,
            |result| match result {
                LiveCommandResult::Pause(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }

    async fn resume(
        &self,
        request: Request<ResumeRequest>,
    ) -> Result<Response<ResumeResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.waiter_capacity,
            LiveCommand::Resume,
            |result| match result {
                LiveCommandResult::Resume(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }

    async fn get_operation(
        &self,
        request: Request<GetOperationRequest>,
    ) -> Result<Response<GetOperationResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.finite_capacity,
            LiveCommand::GetOperation,
            |result| match result {
                LiveCommandResult::GetOperation(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }

    async fn cancel_operation(
        &self,
        request: Request<CancelOperationRequest>,
    ) -> Result<Response<CancelOperationResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.waiter_capacity,
            LiveCommand::CancelOperation,
            |result| match result {
                LiveCommandResult::CancelOperation(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }

    async fn capture(
        &self,
        request: Request<CaptureRequest>,
    ) -> Result<Response<CaptureResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.finite_capacity,
            |command| LiveCommand::Capture(Box::new(command)),
            |result| match result {
                LiveCommandResult::Capture(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }

    async fn release_capture(
        &self,
        request: Request<ReleaseCaptureRequest>,
    ) -> Result<Response<ReleaseCaptureResponse>, Status> {
        self.live_command(
            request.into_inner(),
            &self.waiter_capacity,
            LiveCommand::ReleaseCapture,
            |result| match result {
                LiveCommandResult::ReleaseCapture(outcome) => encode(outcome),
                _ => None,
            },
        )
        .await
    }
}

#[derive(Clone)]
struct AccessService {
    machine: VirtualMachine,
    serial: Arc<SerialConsole>,
    shutdown: CancellationToken,
    ssh_capacity: Arc<Semaphore>,
    gate: Arc<LiveGate>,
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
        let setup = self
            .gate
            .try_admit(GateKind::SshSession)
            .map_err(GateRefusal::status)?;
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
        .map_err(ssh_backend_status)?;
        drop(setup);
        Ok(Response::new(Box::pin(relay(
            stream,
            request.into_inner(),
            self.shutdown.clone(),
            permit,
            self.gate.clone(),
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
        let stream = tokio::time::timeout(BACKEND_SETUP_TIMEOUT, self.serial.open_stream())
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
            self.gate.clone(),
        ))))
    }
}

fn ssh_backend_status(error: crate::virt::VirtError) -> Status {
    match error {
        crate::virt::VirtError::VsockCapacityExhausted { .. } => {
            protocol::detailed_status(Status::resource_exhausted(error.to_string()))
        }
        error => protocol::status_with_error(
            tonic::Code::Unavailable,
            protocol::v1::ErrorCode::BackendUnavailable,
            format!("SSH backend unavailable: {error}"),
            None,
        ),
    }
}

impl ServiceHandles {
    pub(crate) async fn mark_stopping(&self) {
        if let Some(forwards) = &self.forwards {
            forwards.mark_stopping();
        }
        for service in [
            "silo.v1.VmAccessService",
            "silo.v1.VmExecutionService",
            "silo.v1.VmForwardService",
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
    startup_command: Option<crate::start_request::StartupCommand>,
    exec_log: Option<crate::exec_log::ExecLogWriter>,
    vsock_surface: Option<crate::vsock::VsockSurface>,
    sync_reporter: &mut SyncReporter,
    startup: StartupGate,
) -> eyre::Result<ServiceHandles> {
    let StartupGate {
        require_guest_ready,
        deadline: startup_deadline,
        cancelled: startup_cancel,
        activation,
    } = startup;
    ctx.machine.ensure_alive().await?;
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
        .set_serving::<VmExecutionServiceServer<ExecutionService>>()
        .await;
    health
        .set_serving::<VmForwardServiceServer<crate::forward::service::ForwardService>>()
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
        "silo.v1.VmExecutionService",
        "silo.v1.VmForwardService",
        "silo.v1.GuestFilesystemService",
    ])
    .context("filter host gRPC reflection descriptors")?;
    let reflection = tonic_reflection::server::Builder::configure()
        .register_file_descriptor_set(reflection_descriptors)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .with_service_name("silo.v1.VmMonitorService")
        .with_service_name("silo.v1.VmAccessService")
        .with_service_name("silo.v1.VmExecutionService")
        .with_service_name("silo.v1.VmForwardService")
        .with_service_name("silo.v1.GuestFilesystemService")
        .with_service_name("grpc.health.v1.Health")
        .with_service_name("grpc.reflection.v1.ServerReflection")
        .build_v1()
        .context("build gRPC reflection service")?;
    let server_shutdown = CancellationToken::new();
    let server_shutdown_signal = server_shutdown.clone();
    let monitor = MonitorService {
        store: ctx.store.clone(),
        machine_run_id: ctx.machine_run_id.to_string(),
        finite_capacity: Arc::new(Semaphore::new(64)),
        waiter_capacity: Arc::new(Semaphore::new(64)),
        live: ctx.live.clone(),
    };
    let access = AccessService {
        machine: ctx.machine.clone(),
        serial: ctx.serial_console.clone(),
        shutdown: ctx.shutdown.clone(),
        ssh_capacity: Arc::new(Semaphore::new(32)),
        gate: ctx.live.gate().clone(),
    };
    let execution = ExecutionService::new(ctx, exec_log.clone());
    let filesystem = FilesystemProxy::new(
        ctx.machine.clone(),
        ctx.shutdown.clone(),
        ctx.live.gate().clone(),
    );
    let forwards = crate::forward::service::ForwardService::new(ctx.forwards.clone());
    let mut control_socket = tokio::spawn(async move {
        let monitor = VmMonitorServiceServer::new(monitor)
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let access = VmAccessServiceServer::new(access)
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let execution = VmExecutionServiceServer::new(execution)
            .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
            .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
        let forwards = VmForwardServiceServer::new(forwards)
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
                        if crate::vsock::peer::peer_uid_authorized(socket_owner_uid, credentials.uid()) =>
                    {
                        tracing::debug!(
                            uid = credentials.uid(),
                            gid = credentials.gid(),
                            pid = ?credentials.pid(),
                            "accepted silo-vmm gRPC connection"
                        );
                        Some(Ok(stream))
                    }
                    Ok(credentials) => {
                        tracing::warn!(
                            uid = credentials.uid(),
                            expected_uid = socket_owner_uid,
                            "rejected silo-vmm gRPC connection from unauthorized UID"
                        );
                        None
                    }
                    Err(error) => {
                        tracing::warn!(%error, "rejected silo-vmm gRPC connection without peer credentials");
                        None
                    }
                },
                Err(error) => {
                    tracing::warn!(%error, "silo-vmm gRPC accept failed");
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
            .add_service(execution)
            .add_service(forwards)
            .add_service(filesystem)
            .serve_with_incoming_shutdown(incoming, server_shutdown_signal.cancelled())
            .await
            .map_err(eyre::Report::from)
    });

    let mut guest_monitor = if ctx.guest_services_enabled {
        let guest_start = tokio::select! {
            biased;
            exit = ctx.machine.wait() => Err(eyre::eyre!("primary VM exited during guest service startup: {exit:?}")),
            () = startup_cancel.cancelled() => Err(eyre::eyre!("guest service startup cancelled")),
            result = tokio::time::timeout_at(
                startup_deadline,
                spawn_guest_services(
                    &ctx.machine,
                    runtime.dir(),
                    ctx.store.clone(),
                    ctx.forwards.clone(),
                    ctx.shutdown.clone(),
                ),
            ) => match result {
                Ok(result) => result,
                Err(_) => Err(eyre::eyre!("guest service startup exceeded the original startup deadline")),
            },
        };
        match guest_start {
            Ok(task) => Some(task),
            Err(error) => {
                cleanup_failed_service_start(
                    &server_shutdown,
                    &mut control_socket,
                    &mut None,
                    &mut None,
                )
                .await;
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Some(activation) = activation {
        let activation_id = activation.activation_id();
        let activated = tokio::select! {
            biased;
            () = tokio::time::sleep_until(startup_deadline) => Err(eyre::eyre!(
                "restore activation exceeded the original startup deadline"
            )),
            result = activation.run(ctx, runtime.runtime_dir(), &startup_cancel, startup_deadline) => result,
        };
        match activated {
            Ok(crate::restore::activation::Activated::Running(surface)) => {
                // Native exposure is irreversible. Cold-start admission checks
                // cannot veto this committed activation; reporting loss instead
                // returns terminal uncertainty for the retained owner to reap.
                if let Some(exec_log) = &exec_log {
                    exec_log.generation(
                        &ctx.machine_id.hyphenated().to_string(),
                        &ctx.machine_run_id.hyphenated().to_string(),
                        "started",
                    );
                }
                if let Err(error) = sync_reporter.report_started() {
                    cleanup_failed_service_start(
                        &server_shutdown,
                        &mut control_socket,
                        &mut guest_monitor,
                        &mut None,
                    )
                    .await;
                    return Err(eyre::eyre!(
                        "restore exposure committed but startup reporting was lost: {error}"
                    ));
                }
                tracing::info!(activation = %activation_id, "restore activation started");
                return Ok(ServiceHandles {
                    control_socket,
                    guest_monitor,
                    health,
                    server_shutdown,
                    startup_command: None,
                    vsock_surface: surface,
                    forwards: Some(ctx.forwards.clone()),
                });
            }
            Ok(crate::restore::activation::Activated::Failed(message)) => {
                // Positively parked and fenced: the monitor stays up for
                // inspection and stop only, and the manager learns why.
                if let Err(error) = sync_reporter.report_failed(&message) {
                    cleanup_failed_service_start(
                        &server_shutdown,
                        &mut control_socket,
                        &mut guest_monitor,
                        &mut None,
                    )
                    .await;
                    return Err(eyre::eyre!(
                        "{message}; reporting the activation failure failed: {error}"
                    ));
                }
                return Ok(ServiceHandles {
                    control_socket,
                    guest_monitor,
                    health,
                    server_shutdown,
                    startup_command: None,
                    vsock_surface: None,
                    forwards: Some(ctx.forwards.clone()),
                });
            }
            Err(error) => {
                cleanup_failed_service_start(
                    &server_shutdown,
                    &mut control_socket,
                    &mut guest_monitor,
                    &mut None,
                )
                .await;
                return Err(error);
            }
        }
    }
    if require_guest_ready {
        if let Err(error) =
            wait_for_required_guest_ready(ctx, startup_deadline, &startup_cancel).await
        {
            cleanup_failed_service_start(
                &server_shutdown,
                &mut control_socket,
                &mut guest_monitor,
                &mut None,
            )
            .await;
            return Err(error);
        }
    }
    if let Some(exec_log) = &exec_log {
        exec_log.generation(
            &ctx.machine_id.hyphenated().to_string(),
            &ctx.machine_run_id.hyphenated().to_string(),
            "started",
        );
    }
    let startup_command = startup_command
        .map(|command| crate::execution::spawn_startup_command(ctx, command, exec_log));
    let mut startup_command = match startup_command {
        Some(crate::execution::StartupCommandHandle { task, started }) => {
            // Preserve a buffered typed launch failure before observing exit.
            // Successful Started still passes the final machine-alive fence.
            let started = tokio::select! {
                biased;
                result = tokio::time::timeout_at(startup_deadline, started) => match result {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(_)) => Err(eyre::eyre!("startup command supervisor ended before reporting Started")),
                    Err(_) => Err(eyre::eyre!("startup command launch exceeded the original startup deadline")),
                },
                exit = ctx.machine.wait() => Err(eyre::eyre!("primary VM exited before startup command readiness: {exit:?}")),
                () = startup_cancel.cancelled() => Err(eyre::eyre!("startup command launch cancelled")),
            };
            match started {
                Ok(Ok(())) => Some(task),
                Ok(Err(error)) => {
                    task.abort();
                    let _ = task.await;
                    if let crate::execution::StartupCommandStartError::LaunchFailed {
                        reason,
                        message,
                    } = &error
                    {
                        if let Err(report_error) = sync_reporter
                            .report_startup_command_launch_failed(*reason, Some(message))
                        {
                            tracing::warn!(%report_error, "failed to report startup command launch failure");
                        }
                    }
                    cleanup_failed_service_start(
                        &server_shutdown,
                        &mut control_socket,
                        &mut guest_monitor,
                        &mut None,
                    )
                    .await;
                    return Err(eyre::eyre!(
                        "startup command failed before Started: {error}"
                    ));
                }
                Err(error) => {
                    task.abort();
                    let _ = task.await;
                    cleanup_failed_service_start(
                        &server_shutdown,
                        &mut control_socket,
                        &mut guest_monitor,
                        &mut None,
                    )
                    .await;
                    return Err(error);
                }
            }
        }
        None => None,
    };
    tracing::info!(
        socket = %path.display(),
        guest_services_enabled = ctx.guest_services_enabled,
        "silo-vmm gRPC control plane is serving"
    );
    let ready = if startup_cancel.is_cancelled() {
        Err(eyre::eyre!(
            "startup cancelled before readiness publication"
        ))
    } else if tokio::time::Instant::now() >= startup_deadline {
        Err(eyre::eyre!(
            "startup deadline elapsed before readiness publication"
        ))
    } else {
        ctx.machine.ensure_alive().await.map_err(eyre::Report::from)
    };
    if let Err(error) = ready {
        cleanup_failed_service_start(
            &server_shutdown,
            &mut control_socket,
            &mut guest_monitor,
            &mut startup_command,
        )
        .await;
        return Err(error);
    }
    if let Err(error) = sync_reporter.report_started() {
        cleanup_failed_service_start(
            &server_shutdown,
            &mut control_socket,
            &mut guest_monitor,
            &mut startup_command,
        )
        .await;
        return Err(error.into());
    }
    Ok(ServiceHandles {
        control_socket,
        guest_monitor,
        health,
        server_shutdown,
        startup_command,
        vsock_surface,
        forwards: Some(ctx.forwards.clone()),
    })
}

async fn cleanup_failed_service_start(
    server_shutdown: &CancellationToken,
    control_socket: &mut JoinHandle<eyre::Result<()>>,
    guest_monitor: &mut Option<JoinHandle<()>>,
    startup_command: &mut Option<JoinHandle<()>>,
) {
    server_shutdown.cancel();
    if let Some(task) = startup_command.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = guest_monitor.take() {
        task.abort();
        let _ = task.await;
    }
    control_socket.abort();
    let _ = control_socket.await;
}

async fn wait_for_required_guest_ready(
    ctx: &DaemonContext,
    deadline: tokio::time::Instant,
    cancelled: &CancellationToken,
) -> eyre::Result<()> {
    let mut changed = ctx.store.subscribe();
    loop {
        ctx.machine.ensure_alive().await?;
        match ctx.store.readiness()? {
            WaitOutcome::Ready => return Ok(()),
            WaitOutcome::Terminal => {
                return Err(eyre::eyre!(
                    "required guest translation bootstrap or workload readiness failed"
                ));
            }
            WaitOutcome::TimedOut => {}
        }
        tokio::select! {
            result = tokio::time::timeout_at(deadline, changed.changed()) => {
                result
                    .map_err(|_| eyre::eyre!("required guest readiness timed out"))?
                    .map_err(|_| eyre::eyre!("required guest readiness owner stopped"))?;
            }
            exit = ctx.machine.wait() => {
                return Err(eyre::eyre!("primary VM exited before required guest readiness: {:?}", exit?));
            }
            () = cancelled.cancelled() => return Err(eyre::eyre!("required guest readiness cancelled")),
        }
    }
}

fn relay<S, I>(
    stream: S,
    mut input: I,
    shutdown: CancellationToken,
    _permit: OwnedSemaphorePermit,
    gate: Arc<LiveGate>,
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
                    // Session input waits while live fences hold the machine.
                    let _input = gate
                        .admit(GateKind::SessionInput)
                        .await
                        .map_err(GateRefusal::status)?;
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
    gate: Arc<LiveGate>,
) -> ReceiverStream<Result<ByteChunk, Status>> {
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut input_closed = false;
        // Input held while live fences are closed; output stays observable.
        let mut pending: Option<bytes::Bytes> = None;
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
                admitted = gate.admit(GateKind::SerialInput), if pending.is_some() => match admitted {
                    Ok(_input) => {
                        if let Some(data) = pending.take() {
                            if let Err(error) = serial.write_input(&data).await { let _ = tx.send(Err(protocol::detailed_status(Status::from(error)))).await; return; }
                        }
                    }
                    Err(refusal) => { let _ = tx.send(Err(refusal.status())).await; return; }
                },
                message = input.next(), if !input_closed && pending.is_none() => match message {
                    Some(Ok(chunk)) => {
                        let data = chunk.data.unwrap_or_default();
                        if data.len() > ACCEPTED_CHUNK_BYTES { let _ = tx.send(Err(protocol::detailed_status(Status::invalid_argument("access chunks may not exceed 64 KiB")))).await; return; }
                        if !data.is_empty() {
                            pending = Some(data);
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
    #[test]
    fn generic_status_fences_machine_and_run_before_guest_readiness() {
        let machine = uuid::Uuid::new_v4().to_string();
        let run = uuid::Uuid::new_v4().to_string();
        let store = std::sync::Arc::new(
            crate::state::InstanceStore::new(
                machine.clone(),
                "test".into(),
                true,
                crate::state::RunLiveProfile {
                    run_id: run.clone(),
                    backend: vm_spec::live::LiveBackend::Krun,
                    lane: vm_spec::live::LiveLane::KvmX86_64,
                    live: vm_spec::live::LiveCapabilityVector::all_unsupported(
                        vm_spec::live::LiveReasonCode::NotDelivered,
                    ),
                },
            )
            .expect("valid monitor state"),
        );
        let monitor = crate::services::MonitorService {
            live: idle_live(&store, &machine, &run),
            store,
            machine_run_id: run.clone(),
            finite_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            waiter_capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let status = monitor.status().unwrap();
        let live = vm_spec::live::LiveMachineReport::try_from(status.live.clone().expect("live"))
            .expect("valid live");
        assert_eq!(status.machine_id, Some(machine.clone()));
        assert_eq!(status.run_id, Some(run.clone()));
        assert_eq!(live.machine_id, machine);
        assert_eq!(live.run_id, run);
        assert_eq!(
            live.monitor_id,
            status
                .monitor
                .expect("monitor")
                .instance_id
                .expect("monitor id")
        );
        assert_eq!(status.readiness.unwrap().ready, Some(false));
    }
    use bytes::Bytes;
    use futures::StreamExt;
    use protocol::v1::ByteChunk;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::CancellationToken;

    use crate::services::{relay, ssh_backend_status};
    use crate::virt::VirtError;

    #[test]
    fn ssh_capacity_exhaustion_has_specific_rpc_mapping() {
        let exhausted = ssh_backend_status(VirtError::VsockCapacityExhausted {
            machine: "test".to_string(),
            limit: 1024,
        });
        let backend = ssh_backend_status(VirtError::Backend("offline".to_string()));

        assert_eq!(exhausted.code(), tonic::Code::ResourceExhausted);
        assert_eq!(backend.code(), tonic::Code::Unavailable);
        assert!(backend.message().contains("SSH backend unavailable"));
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
            crate::live::gate::LiveGate::new(),
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
    #[tokio::test]
    async fn access_relay_holds_session_input_while_fenced_and_keeps_output() {
        let (server, mut backend) = tokio::io::duplex(1024);
        let gate = crate::live::gate::LiveGate::new();
        gate.close();
        let (input_tx, input_rx) = tokio::sync::mpsc::channel(2);
        let mut output = relay(
            server,
            ReceiverStream::new(input_rx),
            CancellationToken::new(),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .expect("relay permit"),
            gate.clone(),
        );
        input_tx
            .send(Ok(ByteChunk {
                data: Some(Bytes::from_static(b"held")),
            }))
            .await
            .expect("send input");
        backend.write_all(b"out").await.expect("guest output");
        let chunk = output.next().await.expect("output").expect("chunk");
        assert_eq!(chunk.data.expect("data").as_ref(), b"out");
        let mut received = [0_u8; 4];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                backend.read_exact(&mut received)
            )
            .await
            .is_err(),
            "fenced input must not reach the guest"
        );
        assert!(gate.reopen());
        backend
            .read_exact(&mut received)
            .await
            .expect("input after reopen");
        assert_eq!(&received, b"held");
    }

    #[tokio::test]
    async fn root_metrics_rpc_relays_all_fields_inside_existing_observation_frame() {
        use protocol::v1::{
            vm_monitor_service_client::VmMonitorServiceClient,
            vm_monitor_service_server::VmMonitorServiceServer, AgentIdentity, AgentMetricReport,
            AgentMetrics, AgentStatus, AgentStatusReport, AgentStatusState, GetMetricsRequest,
            MetricSnapshot, RootStorageKind, RootStorageMetrics, TemporaryDirectoryKind,
            TemporaryDirectoryMetrics,
        };
        use std::sync::Arc;
        use std::time::Duration;

        let store = Arc::new(crate::state::new_instance_store(
            uuid::Uuid::new_v4().to_string(),
            "root-relay".into(),
            true,
        ));
        let instance = "00000000-0000-4000-8000-000000000002";
        let observed_at = prost_types::Timestamp {
            seconds: 1,
            nanos: 2,
        };
        store
            .observe_status(
                AgentStatus {
                    identity: Some(AgentIdentity {
                        instance_id: Some(instance.into()),
                        version: Some("test".into()),
                        boot_id: Some("00000000-0000-4000-8000-000000000003".into()),
                    }),
                    report: Some(AgentStatusReport {
                        observed_at: Some(observed_at),
                        state: Some(AgentStatusState::Ready as i32),
                        ..Default::default()
                    }),
                },
                Duration::from_secs(300),
            )
            .unwrap();
        let report = AgentMetricReport {
            observed_at: Some(observed_at),
            snapshot: Some(MetricSnapshot {
                root_storage: Some(RootStorageMetrics {
                    kind: Some(RootStorageKind::LinuxFlatOverlayV1 as i32),
                    upper_profile: Some("silo-upper-ext4-v1".into()),
                    upper_uuid: Some("12345678-1234-4234-8234-123456789abc".into()),
                    upper_backing_bytes: Some(67_112_960),
                    upper_filesystem_bytes: Some(67_108_864),
                    unusable_tail_bytes: Some(4096),
                    filesystem_overhead_bytes: Some(5_668_864),
                    upper_usable_bytes: Some(61_440_000),
                    upper_used_bytes: Some(53_248_000),
                    upper_free_bytes: Some(8_192_000),
                    upper_available_bytes: Some(4_096_000),
                    upper_total_inodes: Some(8192),
                    upper_free_inodes: Some(0),
                    upper_available_inodes: Some(0),
                    shared_lower_logical_bytes: Some(268_435_456),
                    temporary_directory: Some(TemporaryDirectoryMetrics {
                        kind: Some(TemporaryDirectoryKind::Tmpfs as i32),
                        capacity_bytes: Some(1_048_576),
                        used_bytes: Some(4096),
                        free_bytes: Some(1_044_480),
                        available_bytes: Some(1_044_480),
                        persistent: Some(false),
                        memory_charged: Some(true),
                    }),
                }),
                ..Default::default()
            }),
        };
        store
            .observe_metrics(
                AgentMetrics {
                    agent_instance_id: Some(instance.into()),
                    report: Some(report.clone()),
                },
                Duration::ZERO,
            )
            .unwrap();
        let run = uuid::Uuid::new_v4().to_string();
        let machine = store.status().unwrap().machine_id.unwrap();
        let service = crate::services::MonitorService {
            live: idle_live(&store, &machine, &run),
            store,
            machine_run_id: run,
            finite_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            waiter_capacity: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let stopped = shutdown.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(VmMonitorServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    stopped.cancelled_owned(),
                )
                .await
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2))
            .connect()
            .await
            .unwrap();
        let mut client = VmMonitorServiceClient::new(channel);
        let response = client.get_metrics(GetMetricsRequest {}).await;
        drop(client);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let observation = response.unwrap().into_inner().metrics.unwrap();
        assert_eq!(observation.agent_instance_id.as_deref(), Some(instance));
        assert_eq!(
            observation.freshness,
            Some(protocol::v1::Freshness::Stale as i32)
        );
        assert_eq!(
            observation.stale_reason,
            Some(protocol::v1::StaleReason::ReceiptAge as i32)
        );
        assert!(observation.received_at.is_some() && observation.stale_at.is_some());
        assert_eq!(observation.report, Some(report));
    }

    /// A coordinator over an unstarted scenario machine: enough for the
    /// admission paths that never reach the guest or native lifecycle.
    fn idle_live(
        store: &std::sync::Arc<crate::state::InstanceStore>,
        machine: &str,
        run: &str,
    ) -> std::sync::Arc<crate::live::coordinator::LiveCoordinator> {
        let root = std::path::Path::new("/tmp").join(format!(
            "sv-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config = crate::virt::VmConfig::builder("services-live")
            .base_directory(&root)
            .kernel(std::path::Path::new("/mock-kernel"))
            .build();
        let virtual_machine =
            crate::virt::VirtualMachine::with_backend(crate::virt::BackendKind::Mock, config)
                .expect("mock machine");
        crate::live::coordinator::LiveCoordinator::new(
            uuid::Uuid::parse_str(machine).expect("machine uuid"),
            uuid::Uuid::parse_str(run).expect("run uuid"),
            store.clone(),
            virtual_machine,
            crate::live::gate::LiveGate::new(),
            crate::live::coordinator::LiveTimeouts::default(),
            None,
        )
        .expect("coordinator")
    }

    #[tokio::test]
    async fn live_commands_cross_the_wire_strictly_typed() {
        use protocol::v1::{
            vm_monitor_service_client::VmMonitorServiceClient,
            vm_monitor_service_server::VmMonitorServiceServer, CaptureRequest, GetOperationRequest,
            LiveCommandEnvelope, PauseRequest, ReleaseCaptureRequest,
        };
        use std::sync::Arc;
        use std::time::Duration;
        use vm_spec::lifecycle::{
            CaptureOutcome, GetOperationOutcome, LiveRejectionCode, PauseOutcome,
            ReleaseCaptureOutcome, VmLifecycleState,
        };

        let machine = uuid::Uuid::new_v4().to_string();
        let run = uuid::Uuid::new_v4().to_string();
        let store = Arc::new(
            crate::state::InstanceStore::new(
                machine.clone(),
                "wire".into(),
                true,
                crate::state::RunLiveProfile {
                    run_id: run.clone(),
                    backend: vm_spec::live::LiveBackend::Krun,
                    lane: vm_spec::live::LiveLane::KvmX86_64,
                    live: vm_spec::live::LiveCapabilityVector::all_unsupported(
                        vm_spec::live::LiveReasonCode::NotDelivered,
                    ),
                },
            )
            .expect("valid monitor state"),
        );
        store
            .set_vm_state(protocol::v1::VmState::Running, "running")
            .unwrap();
        let service = crate::services::MonitorService {
            live: idle_live(&store, &machine, &run),
            store,
            machine_run_id: run.clone(),
            finite_capacity: Arc::new(tokio::sync::Semaphore::new(8)),
            waiter_capacity: Arc::new(tokio::sync::Semaphore::new(8)),
        };
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let stopped = shutdown.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(VmMonitorServiceServer::new(service))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    stopped.cancelled_owned(),
                )
                .await
        });
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .unwrap();
        let mut client = VmMonitorServiceClient::new(channel);
        let envelope = |run: &str| LiveCommandEnvelope {
            machine_id: Some(machine.clone()),
            run_id: Some(run.to_string()),
            request_id: Some(uuid::Uuid::new_v4().to_string()),
        };

        // Malformed envelope: no trustworthy identity, transport error.
        let mut malformed = envelope(&run);
        malformed.request_id = Some("00000000-0000-0000-0000-000000000000".into());
        let error = client
            .pause(PauseRequest {
                envelope: Some(malformed),
            })
            .await
            .expect_err("nil request id");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            client
                .pause(PauseRequest { envelope: None })
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );

        // Foreign run: typed rejection body.
        let foreign = client
            .pause(PauseRequest {
                envelope: Some(envelope(&uuid::Uuid::new_v4().to_string())),
            })
            .await
            .unwrap()
            .into_inner();
        let PauseOutcome::Rejected { rejection } = PauseOutcome::try_from(foreign).unwrap() else {
            panic!("foreign run is rejected");
        };
        assert_eq!(rejection.reason.code(), LiveRejectionCode::WrongRun);

        // Unsupported pause carries the live vector's exact typed reason.
        let unsupported = client
            .pause(PauseRequest {
                envelope: Some(envelope(&run)),
            })
            .await
            .unwrap()
            .into_inner();
        let PauseOutcome::Rejected { rejection } = PauseOutcome::try_from(unsupported).unwrap()
        else {
            panic!("unqualified pause is rejected");
        };
        assert_eq!(rejection.reason.code(), LiveRejectionCode::Unsupported);
        assert_eq!(rejection.state, VmLifecycleState::Running);

        let unknown = client
            .get_operation(GetOperationRequest {
                envelope: Some(envelope(&run)),
                operation_id: Some(uuid::Uuid::new_v4().to_string()),
            })
            .await
            .unwrap()
            .into_inner();
        let GetOperationOutcome::Rejected { rejection } =
            GetOperationOutcome::try_from(unknown).unwrap()
        else {
            panic!("unknown operation is typed");
        };
        assert_eq!(
            rejection.reason.code(),
            LiveRejectionCode::OperationNotFound
        );

        // A malformed (non-canonical) plan is a transport refusal, never a
        // journaled request.
        let malformed = client
            .capture(CaptureRequest {
                envelope: Some(envelope(&run)),
                plan: Some(b"{}".to_vec()),
            })
            .await;
        assert!(malformed.is_err());

        let capture_envelope = envelope(&run);
        let plan = {
            use vm_spec::capture::{
                CaptureConfiguration, CaptureLaunchLease, CapturePauseAuthority, CapturePlan,
                CaptureReservation, CAPTURE_RECORD_VERSION,
            };
            let id = |value: Option<&String>| {
                vm_spec::lifecycle::LiveId::parse(value.expect("identity")).expect("canonical")
            };
            let configuration =
                CaptureConfiguration::from_spec(&vm_spec::VmSpec::current()).expect("projection");
            CapturePlan {
                version: CAPTURE_RECORD_VERSION,
                machine_id: id(capture_envelope.machine_id.as_ref()),
                run_id: id(capture_envelope.run_id.as_ref()),
                capture_id: id(capture_envelope.request_id.as_ref()),
                configuration_digest: configuration.digest().expect("digest"),
                ram_bytes: configuration.ram_bytes(),
                configuration,
                policy: vm_spec::lifecycle::CapturePolicy::Full,
                resume_policy: vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired,
                pause: CapturePauseAuthority::Acquire,
                disks: Vec::new(),
                read_only_inputs: Vec::new(),
                reservation: CaptureReservation {
                    storage_operation_id: id(Some(&uuid::Uuid::new_v4().to_string())),
                    launch_lease: CaptureLaunchLease {
                        operation_id: id(Some(&uuid::Uuid::new_v4().to_string())),
                        device: 1,
                        inode: 1,
                    },
                    staging_bytes: 1 << 40,
                },
            }
        };
        let capture = client
            .capture(CaptureRequest {
                envelope: Some(capture_envelope),
                plan: Some(plan.canonical_bytes().expect("canonical plan")),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            CaptureOutcome::try_from(capture).unwrap(),
            CaptureOutcome::Rejected { rejection } if rejection.reason.code() == LiveRejectionCode::Unsupported
        ));
        let release = client
            .release_capture(ReleaseCaptureRequest {
                envelope: Some(envelope(&run)),
                operation_id: Some(uuid::Uuid::new_v4().to_string()),
                disposition: Some(protocol::v1::CaptureReleaseDisposition::Published as i32),
            })
            .await
            .unwrap()
            .into_inner();
        let ReleaseCaptureOutcome::Rejected { rejection } =
            ReleaseCaptureOutcome::try_from(release).unwrap()
        else {
            panic!("release on an unsupported machine is refused");
        };
        assert_eq!(rejection.reason.code(), LiveRejectionCode::Unsupported);

        drop(client);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

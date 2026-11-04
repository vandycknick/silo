use std::pin::Pin;
use std::time::Duration;

use eyre::Context;
use futures::{stream, Stream, StreamExt};
use prost_types::{Duration as ProtoDuration, Timestamp};
use protocol::v1::guest_agent_service_server::{GuestAgentService, GuestAgentServiceServer};
use protocol::v1::{
    AgentIdentity, AgentStatus, AgentStatusReport, AgentStatusState, GetAgentMetricsRequest,
    GetAgentStatusRequest, GuestBootReport, ProvisionReport, SyncClockRequest, SyncClockResponse,
    WatchAgentMetricsRequest, WatchAgentStatusRequest,
};
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};
use tonic::{Request, Response, Status};

use crate::filesystem::FilesystemService;
use crate::forward::listen::GuestForwardServiceImpl;
use crate::guest_process::GuestProcessServiceImpl;
use crate::host::info::get_system_info;
use crate::metrics;

type StatusStream = Pin<Box<dyn Stream<Item = Result<AgentStatus, Status>> + Send + 'static>>;
type MetricsStream =
    Pin<Box<dyn Stream<Item = Result<protocol::v1::AgentMetrics, Status>> + Send + 'static>>;

pub(crate) struct AgentServer {
    state: AgentState,
    shutdown: watch::Sender<bool>,
    admissions: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<eyre::Result<()>>>>,
    accept_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    health: Mutex<Option<tonic_health::server::HealthReporter>>,
    filesystem: FilesystemService,
    forwards: GuestForwardServiceImpl,
}

#[derive(Clone)]
struct AgentState {
    runtime: std::sync::Arc<crate::lifecycle::RuntimeContext>,
    lifecycle: std::sync::Arc<crate::lifecycle::Lifecycle>,
    process_supervisor: crate::pid1::ProcessSupervisor,
    status: watch::Sender<AgentStatus>,
    shutdown: watch::Sender<bool>,
    memory_reclaim: crate::memory_reclaim::MemoryReclaimStatus,
    orderly: std::sync::Arc<crate::orderly_shutdown::OrderlyShutdown>,
}

impl AgentServer {
    pub(crate) async fn start(
        port: u32,
        boot: GuestBootReport,
        process_supervisor: crate::pid1::ProcessSupervisor,
        memory_reclaim: crate::memory_reclaim::MemoryReclaimStatus,
        orderly: std::sync::Arc<crate::orderly_shutdown::OrderlyShutdown>,
        runtime: std::sync::Arc<crate::lifecycle::RuntimeContext>,
        workloads: crate::freezer::WorkloadController,
    ) -> eyre::Result<Self> {
        let identity = runtime.expected();
        let instance_id = identity.agent_instance_id;
        let boot_id = identity.boot_id;
        let starting = status(
            &instance_id,
            boot_id.clone(),
            AgentStatusState::Starting,
            boot,
            None,
            Some(("STARTING", "agent starting")),
        );
        let (sender, _) = watch::channel(starting);
        // Bind before provisioning so the host can observe startup progress.
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (admissions, _) = watch::channel(false);
        let filesystem = FilesystemService::new("/", runtime.clone());
        let forwards = GuestForwardServiceImpl::new(process_supervisor.clone(), runtime.clone());
        let lifecycle = crate::lifecycle::Lifecycle::new(
            runtime.clone(),
            workloads,
            process_supervisor.clone(),
            forwards.clone(),
        );
        let server = Self {
            state: AgentState {
                runtime,
                lifecycle,
                process_supervisor,
                status: sender,
                shutdown: admissions.clone(),
                memory_reclaim,
                orderly,
            },
            shutdown,
            admissions,
            task: Mutex::new(None),
            accept_task: Mutex::new(None),
            health: Mutex::new(None),
            filesystem,
            forwards,
        };
        server.serve(listener, shutdown_rx).await?;
        tracing::info!(port, "listening for guest gRPC vsock connections");
        Ok(server)
    }
    pub(crate) fn runtime(&self) -> std::sync::Arc<crate::lifecycle::RuntimeContext> {
        self.state.runtime.clone()
    }
    pub(crate) fn forwards(&self) -> GuestForwardServiceImpl {
        self.forwards.clone()
    }
    pub(crate) async fn set_network(
        &self,
        network: Option<crate::provision::network::AppliedNetwork>,
    ) {
        self.state.lifecycle.set_network(network).await;
    }

    async fn serve(
        &self,
        listener: VsockListener,
        shutdown_rx: watch::Receiver<bool>,
    ) -> eyre::Result<()> {
        let reflection_descriptors = protocol::reflection_descriptor_set(&[
            "silo.v1.GuestAgentService",
            "silo.v1.GuestFilesystemService",
            "silo.v1.GuestForwardService",
            "silo.v1.GuestProcessService",
        ])
        .context("filter guest gRPC reflection descriptors")?;
        let reflection = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(reflection_descriptors)
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .with_service_name("silo.v1.GuestAgentService")
            .with_service_name("silo.v1.GuestFilesystemService")
            .with_service_name("silo.v1.GuestForwardService")
            .with_service_name("silo.v1.GuestProcessService")
            .with_service_name("grpc.health.v1.Health")
            .with_service_name("grpc.reflection.v1.ServerReflection")
            .build_v1()
            .map_err(|error| eyre::eyre!("build gRPC reflection service: {error}"))?;
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<VsockConnection, std::io::Error>>(128);
        // Listener EOF must not shut down established HTTP/2 connections while
        // the orderly-shutdown stream waits for the actual storage worker.
        let incoming_keepalive = sender.clone();
        let accept_shutdown_rx = self.admissions.subscribe();
        let accept_task = tokio::spawn(async move {
            let mut incoming = listener.incoming();
            let mut shutdown_rx = accept_shutdown_rx;
            loop {
                tokio::select! {
                    connection = incoming.next() => match connection {
                        Some(Ok(stream)) if stream.peer_addr().is_ok_and(|address| address.cid() == VMADDR_CID_HOST) => {
                            tokio::select! {
                                biased;
                                _ = shutdown_rx.changed() => break,
                                result = sender.send(Ok(VsockConnection(stream))) => {
                                    if result.is_err() { break; }
                                }
                            }
                        }
                        Some(Ok(_)) => tracing::warn!("rejected non-host guest RPC vsock peer"),
                        Some(Err(error)) => tracing::warn!(%error, "guest RPC vsock accept failed"),
                        None => break,
                    },
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        *self.accept_task.lock().await = Some(accept_task);

        let service = AgentService {
            state: self.state.clone(),
            status_watches: std::sync::Arc::new(Semaphore::new(8)),
            metric_watches: std::sync::Arc::new(Semaphore::new(4)),
            clock_syncs: std::sync::Arc::new(Semaphore::new(1)),
        };
        let filesystem = self.filesystem.clone();
        let guest_process = GuestProcessServiceImpl::new(
            self.state.runtime.clone(),
            self.state.process_supervisor.clone(),
        );
        let guest_forward = self.forwards.clone();
        let (health, health_service) = tonic_health::server::health_reporter();
        health
            .set_serving::<GuestAgentServiceServer<AgentService>>()
            .await;
        health
            .set_serving::<protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer<FilesystemService>>()
            .await;
        health
            .set_serving::<protocol::v1::guest_forward_service_server::GuestForwardServiceServer<
                GuestForwardServiceImpl,
            >>()
            .await;
        health
            .set_serving::<protocol::v1::guest_process_service_server::GuestProcessServiceServer<
                GuestProcessServiceImpl,
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
        let task = tokio::spawn(async move {
            let _incoming_keepalive = incoming_keepalive;
            let agent = GuestAgentServiceServer::new(service)
                .max_decoding_message_size(protocol::shutdown::MAX_FRAME_BYTES)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let filesystem =
                protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer::new(
                    filesystem,
                )
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let guest_process =
                protocol::v1::guest_process_service_server::GuestProcessServiceServer::new(
                    guest_process,
                )
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let guest_forward =
                protocol::v1::guest_forward_service_server::GuestForwardServiceServer::new(
                    guest_forward,
                )
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let result = tonic::transport::Server::builder()
                .trace_fn(|request| tracing::info_span!("grpc", method = %request.uri()))
                .add_service(health_service)
                .add_service(reflection)
                .add_service(agent)
                .add_service(filesystem)
                .add_service(guest_forward)
                .add_service(guest_process)
                .serve_with_incoming_shutdown(ReceiverStream::new(receiver), async move {
                    let mut shutdown_rx = shutdown_rx;
                    while !*shutdown_rx.borrow() {
                        if shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
            result.map_err(|error| eyre::eyre!("guest RPC server stopped: {error}"))
        });
        *self.task.lock().await = Some(task);
        *self.health.lock().await = Some(health);
        Ok(())
    }

    pub(crate) fn stop_admissions(&self) {
        self.state.runtime.stop_admissions();
        self.filesystem.stop_admissions();
        self.admissions.send_replace(true);
    }

    /// Drain actual mutation owners, deliberately not the shutdown RPC/server.
    pub(crate) async fn drain_mutations(&self) -> eyre::Result<()> {
        self.filesystem.stop_admissions();
        if let Some(health) = self.health.lock().await.take() {
            for service in [
                "",
                "silo.v1.GuestAgentService",
                "silo.v1.GuestFilesystemService",
                "silo.v1.GuestForwardService",
                "silo.v1.GuestProcessService",
                "grpc.reflection.v1.ServerReflection",
            ] {
                health
                    .set_service_status(service, tonic_health::ServingStatus::NotServing)
                    .await;
            }
        }
        if let Some(task) = self.accept_task.lock().await.take() {
            task.await.context("join closed guest RPC listener")?;
        }
        self.filesystem.wait_idle().await
    }

    pub(crate) fn update(&self, boot: GuestBootReport, provision: ProvisionReport) {
        self.publish(
            AgentStatusState::Starting,
            boot,
            Some(provision),
            Some(("PROVISIONING_COMPLETE", "provisioning complete")),
        );
    }
    pub(crate) fn ready(
        &self,
        boot: GuestBootReport,
        provision: ProvisionReport,
        ssh: protocol::v1::SshListenerReport,
    ) {
        self.publish_with_ssh(
            AgentStatusState::Ready,
            boot,
            Some(provision),
            None,
            Some(ssh),
        );
    }
    pub(crate) fn fail(&self, message: impl Into<String>) {
        let current = self.state.status.borrow().clone();
        let boot = current
            .report
            .as_ref()
            .and_then(|report| report.boot.clone())
            .unwrap_or_default();
        let provision = current.report.and_then(|report| report.provisioning);
        let message = message.into();
        self.publish(
            AgentStatusState::Failed,
            boot,
            provision,
            Some(("AGENT_FAILURE", &message)),
        );
    }
    fn publish(
        &self,
        state: AgentStatusState,
        boot: GuestBootReport,
        provision: Option<ProvisionReport>,
        detail: Option<(&str, &str)>,
    ) {
        self.publish_with_ssh(state, boot, provision, detail, None);
    }
    fn publish_with_ssh(
        &self,
        state: AgentStatusState,
        boot: GuestBootReport,
        provision: Option<ProvisionReport>,
        detail: Option<(&str, &str)>,
        ssh: Option<protocol::v1::SshListenerReport>,
    ) {
        self.state
            .runtime
            .set_boot_ready(state == AgentStatusState::Ready);
        let boot_id = self
            .state
            .status
            .borrow()
            .identity
            .as_ref()
            .and_then(|identity| identity.boot_id.clone())
            .unwrap_or_default();
        let mut next = status(
            &self.state.runtime.instance_id(),
            boot_id,
            state,
            boot,
            provision,
            detail,
        );
        let current = self.state.status.borrow().clone();
        if let Some(report) = next.report.as_mut() {
            report.ssh = ssh;
        }
        if same_status_content(&current, &next) {
            return;
        }
        if let Some(report) = next.report.as_mut() {
            report.observed_at = Some(now());
        }
        self.state.status.send_replace(next);
    }
}

impl Drop for AgentServer {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        if let Ok(mut task) = self.task.try_lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}

struct VsockConnection(VsockStream);

impl tonic::transport::server::Connected for VsockConnection {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for VsockConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
    }
}

impl tokio::io::AsyncWrite for VsockConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buffer)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

fn status(
    instance_id: &str,
    boot_id: String,
    state: AgentStatusState,
    boot: GuestBootReport,
    provisioning: Option<ProvisionReport>,
    detail: Option<(&str, &str)>,
) -> AgentStatus {
    let (code, message) = match state {
        AgentStatusState::Ready => (None, None),
        AgentStatusState::Starting => detail
            .filter(|(code, message)| !code.is_empty() && !message.is_empty())
            .map_or((None, None), |(code, message)| {
                (Some(bounded_text(code)), Some(bounded_text(message)))
            }),
        AgentStatusState::Failed => {
            let (code, message) = detail.map_or(("AGENT_FAILURE", "agent failed"), |value| value);
            let code = if code.is_empty() {
                "AGENT_FAILURE"
            } else {
                code
            };
            let message = if message.is_empty() {
                "agent failed"
            } else {
                message
            };
            (Some(bounded_text(code)), Some(bounded_text(message)))
        }
        AgentStatusState::Unspecified => (None, None),
    };
    AgentStatus {
        identity: Some(AgentIdentity {
            instance_id: Some(instance_id.to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            boot_id: Some(boot_id),
        }),
        report: Some(AgentStatusReport {
            observed_at: Some(now()),
            state: Some(state as i32),
            code,
            message,
            system: get_system_info().ok(),
            boot: Some(boot),
            provisioning,
            ssh: None,
            lifecycle: None,
        }),
    }
}

const MAX_STATUS_DETAIL_BYTES: usize = 512;

fn bounded_text(value: &str) -> String {
    let mut end = value.len().min(MAX_STATUS_DETAIL_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn same_status_content(left: &AgentStatus, right: &AgentStatus) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    if let Some(report) = left.report.as_mut() {
        report.observed_at = None;
    }
    if let Some(report) = right.report.as_mut() {
        report.observed_at = None;
    }
    left == right
}

fn now() -> Timestamp {
    let value = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(value) => value,
        Err(_) => Duration::ZERO,
    };
    Timestamp {
        seconds: i64::try_from(value.as_secs()).map_or(i64::MAX, |seconds| seconds),
        nanos: value.subsec_nanos() as i32,
    }
}

async fn shutdown_exchange(
    mut input: impl Stream<Item = Result<protocol::v1::ShutdownHostFrame, Status>> + Unpin,
    identity: protocol::shutdown::ShutdownIdentity,
    mut completion: watch::Receiver<Option<protocol::v1::ShutdownCompleted>>,
    sender: &tokio::sync::mpsc::Sender<Result<protocol::v1::ShutdownGuestFrame, Status>>,
    guard: &crate::orderly_shutdown::ExchangeGuard,
) -> Result<(), Status> {
    use protocol::v1::shutdown_guest_frame::Payload;
    let frame = |payload| protocol::v1::ShutdownGuestFrame {
        identity: Some(protocol::shutdown::identity_to_proto(&identity)),
        payload: Some(payload),
    };
    let accepted = frame(Payload::Accepted(protocol::v1::ShutdownAccepted {
        authority: Some(protocol::v1::ShutdownAuthority::AgentPid1 as i32),
    }));
    sender
        .send(Ok(accepted))
        .await
        .map_err(|_| Status::cancelled("shutdown response disconnected"))?;
    let completed = loop {
        if let Some(completed) = completion.borrow().clone() {
            break completed;
        }
        tokio::select! {
            biased;
            _ = sender.closed() => return Err(Status::cancelled("shutdown response disconnected")),
            message = input.next() => {
                return Err(match message {
                    Some(Err(error)) => error,
                    Some(Ok(_)) => Status::failed_precondition("ALLOW_POWEROFF precedes COMPLETED"),
                    None => Status::cancelled("shutdown request disconnected"),
                });
            }
            changed = completion.changed() => {
                changed.map_err(|_| Status::unavailable("shutdown completion owner disappeared"))?;
            }
        }
    };
    let completed = frame(Payload::Completed(completed));
    protocol::shutdown::validate_guest_frame(&completed, &identity).map_err(Status::internal)?;
    sender
        .send(Ok(completed))
        .await
        .map_err(|_| Status::cancelled("shutdown response disconnected"))?;
    let receipt = tokio::time::timeout(Duration::from_secs(5), input.next())
        .await
        .map_err(|_| Status::deadline_exceeded("poweroff receipt deadline"))?
        .ok_or_else(|| Status::cancelled("shutdown request disconnected"))??;
    protocol::shutdown::validate_host_frame(&receipt, &identity)
        .map_err(Status::invalid_argument)?;
    if !matches!(
        receipt.payload,
        Some(protocol::v1::shutdown_host_frame::Payload::AllowPoweroff(_))
    ) {
        return Err(Status::failed_precondition(
            "only ALLOW_POWEROFF may follow COMPLETED",
        ));
    }
    guard.0.allow_poweroff(&identity)
}

#[derive(Clone)]
struct AgentService {
    state: AgentState,
    status_watches: std::sync::Arc<Semaphore>,
    metric_watches: std::sync::Arc<Semaphore>,
    clock_syncs: std::sync::Arc<Semaphore>,
}

#[tonic::async_trait]
impl GuestAgentService for AgentService {
    type WatchStatusStream = StatusStream;
    type WatchMetricsStream = MetricsStream;
    type OrderlyShutdownStream = Pin<
        Box<dyn Stream<Item = Result<protocol::v1::ShutdownGuestFrame, Status>> + Send + 'static>,
    >;

    async fn freeze_workloads(
        &self,
        request: Request<protocol::v1::FreezeWorkloadsRequest>,
    ) -> Result<Response<protocol::v1::FreezeWorkloadsResponse>, Status> {
        self.state
            .lifecycle
            .freeze(request.into_inner())
            .await
            .map(Response::new)
            .map_err(protocol::detailed_status)
    }
    async fn activate(
        &self,
        request: Request<protocol::v1::ActivateRequest>,
    ) -> Result<Response<protocol::v1::ActivateResponse>, Status> {
        self.state
            .lifecycle
            .activate(request.into_inner())
            .await
            .map(Response::new)
            .map_err(protocol::detailed_status)
    }
    async fn thaw(
        &self,
        request: Request<protocol::v1::ThawRequest>,
    ) -> Result<Response<protocol::v1::ThawResponse>, Status> {
        self.state
            .lifecycle
            .thaw(request.into_inner())
            .await
            .map(Response::new)
            .map_err(protocol::detailed_status)
    }
    async fn orderly_shutdown(
        &self,
        request: Request<tonic::Streaming<protocol::v1::ShutdownHostFrame>>,
    ) -> Result<Response<Self::OrderlyShutdownStream>, Status> {
        let mut input = request.into_inner();
        let begin = tokio::time::timeout(Duration::from_secs(5), input.message())
            .await
            .map_err(|_| Status::deadline_exceeded("shutdown BEGIN deadline"))??
            .ok_or_else(|| Status::invalid_argument("shutdown BEGIN required"))?;
        let identity = protocol::shutdown::identity_from_proto(
            begin
                .identity
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("shutdown identity required"))?,
        )
        .map_err(Status::invalid_argument)?;
        protocol::shutdown::validate_host_frame(&begin, &identity)
            .map_err(Status::invalid_argument)?;
        let Some(protocol::v1::shutdown_host_frame::Payload::Begin(begin)) = begin.payload else {
            return Err(Status::failed_precondition(
                "first shutdown frame must be BEGIN",
            ));
        };
        let manifest = protocol::shutdown::manifest_from_json(&begin.manifest_json)
            .map_err(Status::invalid_argument)?;
        if self
            .state
            .status
            .borrow()
            .report
            .as_ref()
            .and_then(|report| report.state)
            != Some(AgentStatusState::Ready as i32)
            || self
                .state
                .process_supervisor
                .shutdown_receiver()
                .is_some_and(|receiver| *receiver.borrow())
        {
            return Err(Status::failed_precondition(
                "guest is not ready or is already stopping",
            ));
        }
        self.state.runtime.admit_shutdown()?;
        let current = self.state.runtime.expected();
        let completion = match self.state.orderly.admit(
            identity.clone(),
            &manifest,
            &current.agent_instance_id,
            &current.boot_id,
            self.state.process_supervisor.is_active(),
        ) {
            Ok(completion) => completion,
            Err(error) => {
                self.state.runtime.cancel_shutdown_admission();
                return Err(error);
            }
        };
        let guard = crate::orderly_shutdown::ExchangeGuard(self.state.orderly.clone());
        self.state
            .process_supervisor
            .request_orderly_shutdown()
            .map_err(|error| Status::internal(error.to_string()))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            let result = shutdown_exchange(input, identity, completion, &sender, &guard).await;
            if let Err(error) = result {
                let _ = sender.try_send(Err(error));
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn get_status(
        &self,
        _: Request<GetAgentStatusRequest>,
    ) -> Result<Response<AgentStatus>, Status> {
        Ok(Response::new(
            self.state
                .runtime
                .project(self.state.status.borrow().clone()),
        ))
    }
    async fn watch_status(
        &self,
        request: Request<WatchAgentStatusRequest>,
    ) -> Result<Response<Self::WatchStatusStream>, Status> {
        let heartbeat = checked_interval(
            request.into_inner().heartbeat_interval,
            1,
            30,
            "heartbeat_interval",
        )?;
        let permit = admission(&self.status_watches, "status watch")?;
        let updates = self.state.status.subscribe();
        let timer = tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);
        let shutdown = self.state.shutdown.subscribe();
        let runtime = self.state.runtime.clone();
        let live = runtime.lifecycle.subscribe();
        // Both watches retain only the latest snapshot, never a stale queue.
        let stream = stream::unfold(
            (updates, live, timer, shutdown, true, permit, runtime),
            |(mut updates, mut live, mut timer, mut shutdown, initial, permit, runtime)| async move {
                if !initial {
                    tokio::select! {
                        changed = updates.changed() => { changed.ok()?; }
                        changed = live.changed() => { changed.ok()?; }
                        _ = timer.tick() => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() { return None; }
                        }
                    }
                }
                let snapshot = runtime.project(updates.borrow_and_update().clone());
                live.borrow_and_update();
                Some((
                    Ok(snapshot),
                    (updates, live, timer, shutdown, false, permit, runtime),
                ))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }
    async fn get_metrics(
        &self,
        _: Request<GetAgentMetricsRequest>,
    ) -> Result<Response<protocol::v1::AgentMetrics>, Status> {
        let worker = self
            .state
            .process_supervisor
            .admit_internal_writer()
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let instance_id = self.state.runtime.instance_id();
        let memory_reclaim = self.state.memory_reclaim.last();
        let mut report = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            metrics::collect(instance_id, memory_reclaim)
        })
        .await
        .map_err(|error| {
            protocol::detailed_status(Status::internal(format!("metrics task failed: {error}")))
        })?
        .map_err(|error| protocol::detailed_status(Status::internal(error)))?;
        report.agent_instance_id = Some(self.state.runtime.instance_id());
        Ok(Response::new(report))
    }
    async fn watch_metrics(
        &self,
        request: Request<WatchAgentMetricsRequest>,
    ) -> Result<Response<Self::WatchMetricsStream>, Status> {
        let worker = self
            .state
            .process_supervisor
            .admit_internal_writer()
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let interval = checked_interval(request.into_inner().interval, 1, 300, "interval")?;
        let permit = admission(&self.metric_watches, "metrics watch")?;
        let runtime = self.state.runtime.clone();
        let memory_reclaim_status = self.state.memory_reclaim.clone();
        let mut shutdown = self.state.shutdown.subscribe();
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                biased;
                () = rpc_stopped(&mut shutdown) => {}
                () = async move {
            loop {
                let report = tokio::task::spawn_blocking({
                    let instance_id = runtime.instance_id();
                    let memory_reclaim = memory_reclaim_status.last();
                    let worker = worker.clone();
                    move || {
                        let _worker = worker;
                        metrics::collect(instance_id, memory_reclaim)
                    }
                })
                .await
                .map_err(|error| protocol::detailed_status(Status::internal(error.to_string())))
                .and_then(|report| {
                    report.map(|mut report| {
                        report.agent_instance_id = Some(runtime.instance_id());
                        report
                    }).map_err(|error| protocol::detailed_status(Status::internal(error)))
                });
                if sender.send(report).await.is_err() {
                    break;
                }
                tokio::time::sleep(interval).await;
            }
                } => {}
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn sync_clock(
        &self,
        request: Request<SyncClockRequest>,
    ) -> Result<Response<SyncClockResponse>, Status> {
        let _worker = self
            .state
            .process_supervisor
            .admit_internal_writer()
            .map_err(|error| Status::unavailable(error.to_string()))?;
        let _permit = admission(&self.clock_syncs, "clock sync")?;
        let request = request.into_inner();
        let outcome =
            crate::clock::sync_realtime(request.host_time.as_ref()).map_err(
                |error| match error {
                    crate::clock::ClockSyncError::Missing
                    | crate::clock::ClockSyncError::Invalid(_) => {
                        protocol::detailed_status(Status::invalid_argument(error.to_string()))
                    }
                    crate::clock::ClockSyncError::Read(_)
                    | crate::clock::ClockSyncError::Set(_) => {
                        protocol::detailed_status(Status::internal(error.to_string()))
                    }
                },
            )?;
        Ok(Response::new(SyncClockResponse {
            offset: Some(crate::clock::offset_duration(outcome.offset_nanos)),
            stepped: outcome.stepped,
        }))
    }
}

async fn rpc_stopped(stopping: &mut watch::Receiver<bool>) {
    while !*stopping.borrow() {
        if stopping.changed().await.is_err() {
            return;
        }
    }
}

fn checked_interval(
    value: Option<ProtoDuration>,
    minimum: u64,
    maximum: u64,
    field: &str,
) -> Result<Duration, Status> {
    let value = value.ok_or_else(|| {
        protocol::detailed_status(Status::invalid_argument(format!("{field} is required")))
    })?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(protocol::detailed_status(Status::invalid_argument(
            format!(
                "{field} must be a valid positive duration from {minimum} through {maximum} seconds"
            ),
        )));
    }
    let duration = Duration::new(value.seconds as u64, value.nanos as u32);
    if duration < Duration::from_secs(minimum) || duration > Duration::from_secs(maximum) {
        return Err(protocol::detailed_status(Status::invalid_argument(
            format!("{field} must be from {minimum} through {maximum} seconds"),
        )));
    }
    Ok(duration)
}

fn admission(
    capacity: &std::sync::Arc<Semaphore>,
    resource: &str,
) -> Result<OwnedSemaphorePermit, Status> {
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
    use prost_types::Duration as ProtoDuration;

    fn exchange_fixture() -> (
        std::sync::Arc<crate::orderly_shutdown::OrderlyShutdown>,
        protocol::shutdown::ShutdownIdentity,
        tokio::sync::watch::Receiver<Option<protocol::v1::ShutdownCompleted>>,
    ) {
        let identity = protocol::shutdown::ShutdownIdentity {
            version: 1,
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            shutdown_id: uuid::Uuid::new_v4().to_string(),
            agent_instance_id: uuid::Uuid::new_v4().to_string(),
            boot_id: uuid::Uuid::new_v4().to_string(),
        };
        let owner = crate::orderly_shutdown::OrderlyShutdown::new(
            crate::lifecycle::RuntimeContext::from_identity(
                protocol::shutdown::StorageShutdownContext {
                    version: 1,
                    machine_id: identity.machine_id.clone(),
                    run_id: identity.run_id.clone(),
                    manifest: protocol::shutdown::StorageManifest::Unsupported {
                        reason: "state-machine unit inventory".into(),
                    },
                },
                identity.agent_instance_id.clone(),
                identity.boot_id.clone(),
            ),
        );
        let completion = owner
            .admit(
                identity.clone(),
                &owner.manifest(),
                &identity.agent_instance_id,
                &identity.boot_id,
                true,
            )
            .unwrap();
        (owner, identity, completion)
    }

    #[tokio::test]
    async fn shutdown_exchange_rejects_receipt_before_actual_completion() {
        let (owner, identity, completion) = exchange_fixture();
        let (input, incoming) = tokio::sync::mpsc::channel(1);
        let (output, mut outgoing) = tokio::sync::mpsc::channel(2);
        let exchange = tokio::spawn({
            let owner = owner.clone();
            let identity = identity.clone();
            async move {
                let guard = crate::orderly_shutdown::ExchangeGuard(owner);
                crate::rpc::shutdown_exchange(
                    tokio_stream::wrappers::ReceiverStream::new(incoming),
                    identity,
                    completion,
                    &output,
                    &guard,
                )
                .await
            }
        });
        assert!(matches!(
            outgoing.recv().await.unwrap().unwrap().payload,
            Some(protocol::v1::shutdown_guest_frame::Payload::Accepted(_))
        ));
        input
            .send(Ok(protocol::v1::ShutdownHostFrame {
                identity: Some(protocol::shutdown::identity_to_proto(&identity)),
                payload: Some(protocol::v1::shutdown_host_frame::Payload::AllowPoweroff(
                    protocol::v1::ShutdownAllowPoweroff {},
                )),
            }))
            .await
            .unwrap();
        assert_eq!(
            exchange.await.unwrap().unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        assert!(owner.allow_poweroff(&identity).is_err());
        // The disconnected RPC is not the owner of terminal cleanup.
        owner.complete_and_wait(Err(eyre::eyre!("writer failure")), None);
    }

    #[tokio::test]
    async fn shutdown_exchange_delivers_sticky_completion_before_receipt() {
        let (owner, identity, completion) = exchange_fixture();
        let (input, incoming) = tokio::sync::mpsc::channel(1);
        let (output, mut outgoing) = tokio::sync::mpsc::channel(2);
        let exchange = tokio::spawn({
            let owner = owner.clone();
            let identity = identity.clone();
            async move {
                let guard = crate::orderly_shutdown::ExchangeGuard(owner);
                crate::rpc::shutdown_exchange(
                    tokio_stream::wrappers::ReceiverStream::new(incoming),
                    identity,
                    completion,
                    &output,
                    &guard,
                )
                .await
            }
        });
        let accepted = outgoing.recv().await.unwrap().unwrap();
        protocol::shutdown::validate_guest_frame(&accepted, &identity).unwrap();
        assert!(matches!(
            accepted.payload,
            Some(protocol::v1::shutdown_guest_frame::Payload::Accepted(_))
        ));
        assert!(outgoing.try_recv().is_err());
        let worker = std::thread::spawn({
            let owner = owner.clone();
            move || owner.complete_and_wait(Err(eyre::eyre!("actual drain failed")), None)
        });
        let completed = outgoing.recv().await.unwrap().unwrap();
        protocol::shutdown::validate_guest_frame(&completed, &identity).unwrap();
        let Some(protocol::v1::shutdown_guest_frame::Payload::Completed(completed)) =
            completed.payload
        else {
            panic!("completion required");
        };
        assert_eq!(
            completed.result,
            Some(protocol::v1::ShutdownCompletionResult::Failed as i32)
        );
        assert_eq!(completed.diagnostic.as_deref(), Some("actual drain failed"));
        input
            .send(Ok(protocol::v1::ShutdownHostFrame {
                identity: Some(protocol::shutdown::identity_to_proto(&identity)),
                payload: Some(protocol::v1::shutdown_host_frame::Payload::AllowPoweroff(
                    protocol::v1::ShutdownAllowPoweroff {},
                )),
            }))
            .await
            .unwrap();
        exchange.await.unwrap().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn accepts_fractional_intervals_within_bounds() {
        let interval = crate::rpc::checked_interval(
            Some(ProtoDuration {
                seconds: 1,
                nanos: 500_000_000,
            }),
            1,
            30,
            "heartbeat_interval",
        )
        .expect("fractional duration");
        assert_eq!(interval, std::time::Duration::new(1, 500_000_000));
    }

    #[test]
    fn rejects_intervals_outside_bounds_or_with_invalid_nanos() {
        assert!(crate::rpc::checked_interval(
            Some(ProtoDuration {
                seconds: 0,
                nanos: 999_999_999,
            }),
            1,
            30,
            "heartbeat_interval",
        )
        .is_err());
        assert!(crate::rpc::checked_interval(
            Some(ProtoDuration {
                seconds: 1,
                nanos: 1_000_000_000,
            }),
            1,
            30,
            "heartbeat_interval",
        )
        .is_err());
    }
}

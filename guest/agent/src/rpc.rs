use std::pin::Pin;
use std::time::Duration;

use eyre::Context;
use futures::{stream, Stream, StreamExt};
use prost_types::{Duration as ProtoDuration, Timestamp};
use protocol::v1::guest_agent_service_server::{GuestAgentService, GuestAgentServiceServer};
use protocol::v1::{
    AgentIdentity, AgentStatus, AgentStatusReport, AgentStatusState, GetAgentMetricsRequest,
    GetAgentStatusRequest, GuestBootReport, ProvisionReport, WatchAgentMetricsRequest,
    WatchAgentStatusRequest,
};
use tokio::sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::filesystem::FilesystemService;
use crate::host::info::get_system_info;
use crate::metrics;

type StatusStream = Pin<Box<dyn Stream<Item = Result<AgentStatus, Status>> + Send + 'static>>;
type MetricsStream =
    Pin<Box<dyn Stream<Item = Result<protocol::v1::AgentMetrics, Status>> + Send + 'static>>;

pub(crate) struct AgentServer {
    state: AgentState,
    shutdown: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<eyre::Result<()>>>>,
    health: Mutex<Option<tonic_health::server::HealthReporter>>,
}

#[derive(Clone)]
struct AgentState {
    instance_id: String,
    status: watch::Sender<AgentStatus>,
    shutdown: watch::Sender<bool>,
}

impl AgentServer {
    pub(crate) async fn start(port: u32, boot: GuestBootReport) -> eyre::Result<Self> {
        let instance_id = Uuid::new_v4().to_string();
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .context("read Linux boot ID")?
            .trim()
            .to_string();
        Uuid::parse_str(&boot_id).context("parse Linux boot ID")?;
        let starting = status(
            &instance_id,
            boot_id,
            AgentStatusState::Starting,
            boot,
            None,
            Some(("STARTING", "agent starting")),
        );
        let (sender, _) = watch::channel(starting);
        // Bind before provisioning so the host can observe startup progress.
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let server = Self {
            state: AgentState {
                instance_id,
                status: sender,
                shutdown: shutdown.clone(),
            },
            shutdown,
            task: Mutex::new(None),
            health: Mutex::new(None),
        };
        server.serve(listener, shutdown_rx).await?;
        tracing::info!(port, "listening for guest gRPC vsock connections");
        Ok(server)
    }

    async fn serve(
        &self,
        listener: VsockListener,
        shutdown_rx: watch::Receiver<bool>,
    ) -> eyre::Result<()> {
        let reflection_descriptors = protocol::reflection_descriptor_set(&[
            "silo.v1.GuestAgentService",
            "silo.v1.GuestFilesystemService",
        ])
        .context("filter guest gRPC reflection descriptors")?;
        let reflection = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(reflection_descriptors)
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .with_service_name("silo.v1.GuestAgentService")
            .with_service_name("silo.v1.GuestFilesystemService")
            .with_service_name("grpc.health.v1.Health")
            .with_service_name("grpc.reflection.v1.ServerReflection")
            .build_v1()
            .map_err(|error| eyre::eyre!("build gRPC reflection service: {error}"))?;
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<VsockConnection, std::io::Error>>(128);
        let accept_shutdown_rx = shutdown_rx.clone();
        let accept_task = tokio::spawn(async move {
            let mut incoming = listener.incoming();
            let mut shutdown_rx = accept_shutdown_rx;
            loop {
                tokio::select! {
                    connection = incoming.next() => match connection {
                        Some(Ok(stream)) if stream.peer_addr().is_ok_and(|address| address.cid() == VMADDR_CID_HOST) => {
                            if sender.send(Ok(VsockConnection(stream))).await.is_err() {
                                break;
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

        let service = AgentService {
            state: self.state.clone(),
            status_watches: std::sync::Arc::new(Semaphore::new(8)),
            metric_watches: std::sync::Arc::new(Semaphore::new(4)),
        };
        let filesystem = FilesystemService::new("/", self.state.instance_id.clone());
        let (health, health_service) = tonic_health::server::health_reporter();
        health
            .set_serving::<GuestAgentServiceServer<AgentService>>()
            .await;
        health
            .set_serving::<protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer<FilesystemService>>()
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
            let agent = GuestAgentServiceServer::new(service)
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let filesystem =
                protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer::new(
                    filesystem,
                )
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
            let result = tonic::transport::Server::builder()
                .trace_fn(|request| tracing::info_span!("grpc", method = %request.uri()))
                .add_service(health_service)
                .add_service(reflection)
                .add_service(agent)
                .add_service(filesystem)
                .serve_with_incoming_shutdown(ReceiverStream::new(receiver), async move {
                    let mut shutdown_rx = shutdown_rx;
                    while !*shutdown_rx.borrow() {
                        if shutdown_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
            accept_task.abort();
            let _ = accept_task.await;
            result.map_err(|error| eyre::eyre!("guest RPC server stopped: {error}"))
        });
        *self.task.lock().await = Some(task);
        *self.health.lock().await = Some(health);
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> eyre::Result<()> {
        if let Some(health) = self.health.lock().await.take() {
            for service in [
                "",
                "silo.v1.GuestAgentService",
                "silo.v1.GuestFilesystemService",
                "grpc.reflection.v1.ServerReflection",
            ] {
                health
                    .set_service_status(service, tonic_health::ServingStatus::NotServing)
                    .await;
            }
        }
        self.shutdown.send_replace(true);
        match self.task.lock().await.take() {
            Some(mut task) => match tokio::time::timeout(Duration::from_secs(1), &mut task).await {
                Ok(result) => result.context("guest RPC server task panicked")?,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Ok(())
                }
            },
            None => Ok(()),
        }
    }

    pub(crate) fn update(&self, boot: GuestBootReport, provision: ProvisionReport) {
        self.publish(
            AgentStatusState::Starting,
            boot,
            Some(provision),
            Some(("PROVISIONING_COMPLETE", "provisioning complete")),
        );
    }
    pub(crate) fn ready(&self, boot: GuestBootReport, provision: ProvisionReport) {
        self.publish(AgentStatusState::Ready, boot, Some(provision), None);
    }
    pub(crate) fn fail(&self, message: impl Into<String>) {
        let current = self.state.status.borrow().clone();
        let boot = current
            .report
            .as_ref()
            .and_then(|report| report.boot.clone())
            .map_or_else(GuestBootReport::default, |boot| boot);
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
        let boot_id = self
            .state
            .status
            .borrow()
            .identity
            .as_ref()
            .and_then(|identity| identity.boot_id.clone())
            .map_or_else(String::new, |boot_id| boot_id);
        let mut next = status(
            &self.state.instance_id,
            boot_id,
            state,
            boot,
            provision,
            detail,
        );
        let current = self.state.status.borrow().clone();
        if same_status_content(&current, &next) {
            return;
        }
        next.report
            .as_mut()
            .map(|report| report.observed_at = Some(now()));
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

#[derive(Clone)]
struct AgentService {
    state: AgentState,
    status_watches: std::sync::Arc<Semaphore>,
    metric_watches: std::sync::Arc<Semaphore>,
}

#[tonic::async_trait]
impl GuestAgentService for AgentService {
    type WatchStatusStream = StatusStream;
    type WatchMetricsStream = MetricsStream;

    async fn get_status(
        &self,
        _: Request<GetAgentStatusRequest>,
    ) -> Result<Response<AgentStatus>, Status> {
        Ok(Response::new(self.state.status.borrow().clone()))
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
        // The watch receiver retains only the latest state, so slow clients cannot queue stale reports.
        let stream = stream::unfold(
            (updates, timer, shutdown, true, permit),
            |(mut updates, mut timer, mut shutdown, initial, permit)| async move {
                if initial {
                    let snapshot = updates.borrow_and_update().clone();
                    return Some((Ok(snapshot), (updates, timer, shutdown, false, permit)));
                }
                tokio::select! {
                    changed = updates.changed() => {
                        changed.ok()?;
                    }
                    _ = timer.tick() => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return None;
                        }
                    }
                }
                let snapshot = updates.borrow_and_update().clone();
                Some((Ok(snapshot), (updates, timer, shutdown, false, permit)))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }
    async fn get_metrics(
        &self,
        _: Request<GetAgentMetricsRequest>,
    ) -> Result<Response<protocol::v1::AgentMetrics>, Status> {
        let instance_id = self.state.instance_id.clone();
        let report = tokio::task::spawn_blocking(move || metrics::collect(instance_id))
            .await
            .map_err(|error| {
                protocol::detailed_status(Status::internal(format!("metrics task failed: {error}")))
            })?;
        Ok(Response::new(report))
    }
    async fn watch_metrics(
        &self,
        request: Request<WatchAgentMetricsRequest>,
    ) -> Result<Response<Self::WatchMetricsStream>, Status> {
        let interval = checked_interval(request.into_inner().interval, 1, 300, "interval")?;
        let permit = admission(&self.metric_watches, "metrics watch")?;
        let instance_id = self.state.instance_id.clone();
        let mut shutdown = self.state.shutdown.subscribe();
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            let _permit = permit;
            loop {
                let report = tokio::task::spawn_blocking({
                    let instance_id = instance_id.clone();
                    move || metrics::collect(instance_id)
                })
                .await
                .map_err(|error| protocol::detailed_status(Status::internal(error.to_string())));
                if sender.send(report).await.is_err() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
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

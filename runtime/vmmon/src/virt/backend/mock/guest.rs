//! The fake guest: in-process implementations of the gRPC services the real
//! `silo-agent` serves over vsock, plus the process execution sandbox.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::{stream, Stream};
use prost_types::Timestamp;
use protocol::v1::guest_agent_service_server::{GuestAgentService, GuestAgentServiceServer};
use protocol::v1::guest_filesystem_service_server::GuestFilesystemServiceServer;
use protocol::v1::guest_forward_service_server::{GuestForwardService, GuestForwardServiceServer};
use protocol::v1::guest_process_service_server::{GuestProcessService, GuestProcessServiceServer};
use protocol::v1::{
    guest_process_event, guest_process_input, AgentIdentity, AgentMetricReport, AgentMetrics,
    AgentStatus, AgentStatusReport, AgentStatusState, CpuMetrics, GetAgentMetricsRequest,
    GetAgentStatusRequest, GuestBootMode, GuestBootReport, GuestProcessEvent, GuestProcessExited,
    GuestProcessInput, GuestProcessLaunchFailed, GuestProcessSignaled, GuestProcessStarted,
    GuestProcessStderr, GuestProcessStdout, GuestProcessTerminalOutput, LaunchFailureReason,
    ListenEvent, ListenRequest, ListenerBound, ListenerFailed, LoadAverageMetrics, MemoryMetrics,
    MetricSnapshot, SystemInfo, WatchAgentMetricsRequest, WatchAgentStatusRequest,
};
use test_utils::Scenario;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::watch;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::server::Router;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

type StatusStream = Pin<Box<dyn Stream<Item = Result<AgentStatus, Status>> + Send + 'static>>;
type MetricsStream = Pin<Box<dyn Stream<Item = Result<AgentMetrics, Status>> + Send + 'static>>;
type EventStream = Pin<Box<dyn Stream<Item = Result<GuestProcessEvent, Status>> + Send + 'static>>;
type ListenStream = Pin<Box<dyn Stream<Item = Result<ListenEvent, Status>> + Send + 'static>>;

const MOCK_AGENT_VERSION: &str = "mock";
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(5);
const STDIO_CHUNK_BYTES: usize = 8192;

#[derive(Debug)]
pub(crate) struct MockGuest {
    scenario: Scenario,
    guest_root: PathBuf,
    identity: Mutex<Identity>,
    status: watch::Sender<AgentStatus>,
    /// Bumping this generation ends every open watch/event stream.
    stream_generation: watch::Sender<u64>,
}

#[derive(Debug, Clone)]
struct Identity {
    instance_id: String,
    boot_id: String,
}

impl MockGuest {
    pub(crate) fn new(scenario: Scenario, guest_root: PathBuf) -> Self {
        let identity = Identity {
            instance_id: scenario
                .agent
                .instance_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            boot_id: scenario
                .agent
                .boot_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        };
        let starting = agent_status(&identity, AgentStatusState::Starting);
        let (status, _) = watch::channel(starting);
        let (stream_generation, _) = watch::channel(0);
        Self {
            scenario,
            guest_root,
            identity: Mutex::new(identity),
            status,
            stream_generation,
        }
    }

    pub(crate) fn guest_root(&self) -> &Path {
        &self.guest_root
    }

    pub(crate) fn identity(&self) -> (String, String) {
        let identity = self.lock_identity();
        (identity.instance_id.clone(), identity.boot_id.clone())
    }

    /// Announce boot: publish Starting, then Ready after the scripted delay
    /// (unless the scenario keeps the agent unready), and arm the scripted
    /// restart.
    pub(crate) fn boot(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let guest = self.clone();
        let ready_delay = Duration::from_millis(guest.scenario.agent.ready_delay_ms.unwrap_or(0));
        let never_ready = guest.scenario.agent.never_ready;
        let restart_after = guest
            .scenario
            .agent
            .restart_after_ms
            .map(Duration::from_millis);
        tokio::spawn(async move {
            if !never_ready {
                tokio::time::sleep(ready_delay).await;
                if *shutdown.borrow() {
                    return;
                }
                guest.publish(AgentStatusState::Ready);
            }
            if let Some(restart_after) = restart_after {
                tokio::select! {
                    _ = tokio::time::sleep(restart_after) => guest.restart_agent(),
                    _ = shutdown.changed() => {}
                }
            }
        });
    }

    /// Mint a fresh agent instance id and re-announce readiness, simulating
    /// an in-place agent restart within the same guest boot.
    pub(crate) fn restart_agent(&self) {
        {
            let mut identity = self.lock_identity();
            identity.instance_id = Uuid::new_v4().to_string();
        }
        self.drop_streams();
        self.publish(AgentStatusState::Starting);
        self.publish(AgentStatusState::Ready);
    }

    /// End every open watch/event stream (forces clients to reconnect).
    pub(crate) fn drop_streams(&self) {
        self.stream_generation
            .send_modify(|generation| *generation += 1);
    }

    fn publish(&self, state: AgentStatusState) {
        let identity = self.lock_identity().clone();
        self.status.send_replace(agent_status(&identity, state));
    }

    fn lock_identity(&self) -> std::sync::MutexGuard<'_, Identity> {
        self.identity.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Assemble the tonic router serving the fake guest services.
pub(crate) async fn guest_router(guest: Arc<MockGuest>) -> Router {
    let agent = AgentService {
        guest: guest.clone(),
    };
    let process = ProcessService {
        guest: guest.clone(),
    };
    let filesystem = crate::virt::backend::mock::fs::MockFilesystemService::new(
        guest.guest_root().to_path_buf(),
        guest.scenario.filesystem.clone(),
    );
    let forward = (!guest.scenario.forward.unsupported).then(|| {
        GuestForwardServiceServer::new(ForwardService {
            guest: guest.clone(),
        })
    });

    let (health, health_service) = tonic_health::server::health_reporter();
    for service in [
        "silo.v1.GuestAgentService",
        "silo.v1.GuestFilesystemService",
        "silo.v1.GuestProcessService",
    ] {
        health
            .set_service_status(service, tonic_health::ServingStatus::Serving)
            .await;
    }
    if !guest.scenario.forward.unsupported {
        health
            .set_service_status(
                "silo.v1.GuestForwardService",
                tonic_health::ServingStatus::Serving,
            )
            .await;
    }

    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(
            GuestAgentServiceServer::new(agent)
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB),
        )
        .add_service(
            GuestProcessServiceServer::new(process)
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB),
        )
        .add_service(
            GuestFilesystemServiceServer::new(filesystem)
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB),
        )
        .add_optional_service(forward)
}

#[derive(Clone)]
struct ForwardService {
    guest: Arc<MockGuest>,
}

#[tonic::async_trait]
impl GuestForwardService for ForwardService {
    type ListenStream = ListenStream;

    async fn listen(
        &self,
        request: Request<ListenRequest>,
    ) -> Result<Response<Self::ListenStream>, Status> {
        let request = request.into_inner();
        let token = forward_spec::Token::try_from(request.token.as_ref())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let address = request
            .listen
            .parse::<forward_spec::Address>()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if request.unix_mode.is_some_and(|mode| mode > 0o777)
            || matches!(address, forward_spec::Address::Tcp(_)) && request.unix_mode.is_some()
            || matches!(&address, forward_spec::Address::Unix(path) if !path.is_absolute())
        {
            return Err(Status::invalid_argument(
                "invalid forward listen address or mode",
            ));
        }
        let listener = match MockForwardListener::bind(address, request.unix_mode).await {
            Ok(listener) => listener,
            Err(_error) => {
                let event = ListenEvent {
                    event: Some(protocol::v1::listen_event::Event::Failed(ListenerFailed {
                        error: Some(protocol::v1::ErrorDetail {
                            code: Some(protocol::v1::ErrorCode::ForwardAddressInUse as i32),
                            retry_after: None,
                        }),
                    })),
                };
                return Ok(Response::new(Box::pin(tokio_stream::iter([Ok(event)]))));
            }
        };
        let bound = listener.address().to_string();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Ok(ListenEvent {
                event: Some(protocol::v1::listen_event::Event::Bound(ListenerBound {
                    address: bound,
                })),
            }))
            .await
            .map_err(|_| Status::cancelled("forward listener cancelled"))?;
        let return_path = self
            .guest
            .guest_root
            .parent()
            .ok_or_else(|| Status::internal("mock guest root has no parent"))?
            .join(format!(".v_{}", forward_spec::FORWARD_VSOCK_PORT));
        let mut generation = self.guest.stream_generation.subscribe();
        tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = sender.closed() => break,
                    _ = generation.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(mut client) => {
                            let return_path = return_path.clone();
                            connections.spawn(async move {
                                let setup = tokio::time::timeout(Duration::from_secs(5), async {
                                    let mut remote = UnixStream::connect(return_path).await?;
                                    remote.write_all(&forward_spec::encode_connect(&forward_spec::TargetLine::Token(token))).await?;
                                    let line = forward_spec::io::read_line(&mut remote, forward_spec::MAX_TARGET_LINE_BYTES)
                                        .await
                                        .map_err(std::io::Error::other)?;
                                    if forward_spec::parse_reply(&line) != Ok(forward_spec::Reply::Ok) {
                                        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "return port rejected token"));
                                    }
                                    Ok::<_, std::io::Error>(remote)
                                }).await;
                                if let Ok(Ok(mut remote)) = setup {
                                    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
                                }
                            });
                        }
                        Err(_) => break,
                    },
                    completed = connections.join_next(), if !connections.is_empty() => {
                        let _ = completed;
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

enum MockForwardListener {
    Tcp(TcpListener, std::net::SocketAddr),
    Unix(UnixListener, MockUnixSocket),
}

struct MockUnixSocket(PathBuf);

impl MockForwardListener {
    async fn bind(address: forward_spec::Address, mode: Option<u32>) -> std::io::Result<Self> {
        match address {
            forward_spec::Address::Tcp(address) => {
                let listener = TcpListener::bind(address).await?;
                let bound = listener.local_addr()?;
                Ok(Self::Tcp(listener, bound))
            }
            forward_spec::Address::Unix(path) => {
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_socket() => {
                        std::fs::remove_file(&path)?
                    }
                    Ok(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "Unix listen path exists and is not a socket",
                        ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                let listener = UnixListener::bind(&path)?;
                std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(mode.unwrap_or(0o600)),
                )?;
                Ok(Self::Unix(listener, MockUnixSocket(path)))
            }
        }
    }

    fn address(&self) -> forward_spec::Address {
        match self {
            Self::Tcp(_, address) => forward_spec::Address::Tcp(*address),
            Self::Unix(_, socket) => forward_spec::Address::Unix(socket.0.clone()),
        }
    }

    async fn accept(&self) -> std::io::Result<Box<dyn MockForwardStream>> {
        match self {
            Self::Tcp(listener, _) => listener
                .accept()
                .await
                .map(|(stream, _)| Box::new(stream) as Box<dyn MockForwardStream>),
            Self::Unix(listener, _) => listener
                .accept()
                .await
                .map(|(stream, _)| Box::new(stream) as Box<dyn MockForwardStream>),
        }
    }
}

trait MockForwardStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> MockForwardStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl Drop for MockUnixSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn now() -> Timestamp {
    let value = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    Timestamp {
        seconds: i64::try_from(value.as_secs()).unwrap_or(i64::MAX),
        nanos: value.subsec_nanos() as i32,
    }
}

fn agent_status(identity: &Identity, state: AgentStatusState) -> AgentStatus {
    let (code, message) = match state {
        AgentStatusState::Starting => (
            Some("STARTING".to_string()),
            Some("agent starting".to_string()),
        ),
        _ => (None, None),
    };
    AgentStatus {
        identity: Some(AgentIdentity {
            instance_id: Some(identity.instance_id.clone()),
            version: Some(MOCK_AGENT_VERSION.to_string()),
            boot_id: Some(identity.boot_id.clone()),
        }),
        report: Some(AgentStatusReport {
            observed_at: Some(now()),
            state: Some(state as i32),
            code,
            message,
            system: Some(SystemInfo {
                kernel_version: Some("0.0.0-mock".to_string()),
                os_name: Some("mock-linux".to_string()),
                os_version: None,
                architecture: Some(std::env::consts::ARCH.to_string()),
                hostname: Some("mock-guest".to_string()),
                ip_addresses: Vec::new(),
            }),
            boot: Some(GuestBootReport {
                mode: Some(GuestBootMode::AgentPid1 as i32),
                agent_path: Some("/sbin/silo-agent".to_string()),
                agent_pid: Some(1),
                agent_is_pid1: Some(true),
                message: Some("mock guest boot".to_string()),
                ..GuestBootReport::default()
            }),
            provisioning: None,
        }),
    }
}

fn agent_metrics(instance_id: String) -> AgentMetrics {
    AgentMetrics {
        agent_instance_id: Some(instance_id),
        report: Some(AgentMetricReport {
            observed_at: Some(now()),
            snapshot: Some(MetricSnapshot {
                memory: Some(MemoryMetrics {
                    total_bytes: Some(2 * 1024 * 1024 * 1024),
                    available_bytes: Some(1024 * 1024 * 1024),
                }),
                cpu: Some(CpuMetrics {
                    logical_cpu_count: Some(2),
                    ..CpuMetrics::default()
                }),
                load_average: Some(LoadAverageMetrics {
                    one_minute: Some(0.1),
                    five_minutes: Some(0.1),
                    fifteen_minutes: Some(0.1),
                }),
                uptime_seconds: Some(1.0),
                filesystems: Vec::new(),
                network_interfaces: Vec::new(),
                block_devices: Vec::new(),
            }),
        }),
    }
}

fn requested_interval(value: Option<prost_types::Duration>, default: Duration) -> Duration {
    value
        .and_then(|value| {
            (value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos))
                .then(|| Duration::new(value.seconds as u64, value.nanos as u32))
        })
        .filter(|duration| !duration.is_zero())
        .unwrap_or(default)
}

#[derive(Clone)]
struct AgentService {
    guest: Arc<MockGuest>,
}

#[tonic::async_trait]
impl GuestAgentService for AgentService {
    type WatchStatusStream = StatusStream;
    type WatchMetricsStream = MetricsStream;

    async fn get_status(
        &self,
        _: Request<GetAgentStatusRequest>,
    ) -> Result<Response<AgentStatus>, Status> {
        Ok(Response::new(self.guest.status.borrow().clone()))
    }

    async fn watch_status(
        &self,
        request: Request<WatchAgentStatusRequest>,
    ) -> Result<Response<Self::WatchStatusStream>, Status> {
        let heartbeat =
            requested_interval(request.into_inner().heartbeat_interval, DEFAULT_HEARTBEAT);
        let updates = self.guest.status.subscribe();
        let generation = self.guest.stream_generation.subscribe();
        let deadline = self
            .guest
            .scenario
            .agent
            .drop_status_stream_after_ms
            .map(|ms| tokio::time::Instant::now() + Duration::from_millis(ms));
        let timer = tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);

        let stream = stream::unfold(
            (updates, timer, generation, true),
            move |(mut updates, mut timer, mut generation, initial)| async move {
                if initial {
                    let snapshot = updates.borrow_and_update().clone();
                    return Some((Ok(snapshot), (updates, timer, generation, false)));
                }
                tokio::select! {
                    changed = updates.changed() => {
                        changed.ok()?;
                    }
                    _ = timer.tick() => {}
                    _ = generation.changed() => return None,
                    _ = sleep_until_opt(deadline) => return None,
                }
                let snapshot = updates.borrow_and_update().clone();
                Some((Ok(snapshot), (updates, timer, generation, false)))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_metrics(
        &self,
        _: Request<GetAgentMetricsRequest>,
    ) -> Result<Response<AgentMetrics>, Status> {
        let (instance_id, _) = self.guest.identity();
        Ok(Response::new(agent_metrics(instance_id)))
    }

    async fn watch_metrics(
        &self,
        request: Request<WatchAgentMetricsRequest>,
    ) -> Result<Response<Self::WatchMetricsStream>, Status> {
        let interval = requested_interval(request.into_inner().interval, DEFAULT_HEARTBEAT);
        let guest = self.guest.clone();
        let mut generation = self.guest.stream_generation.subscribe();
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                let (instance_id, _) = guest.identity();
                if sender.send(Ok(agent_metrics(instance_id))).await.is_err() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = generation.changed() => break,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[derive(Clone)]
struct ProcessService {
    guest: Arc<MockGuest>,
}

#[tonic::async_trait]
impl GuestProcessService for ProcessService {
    type ExecuteStream = EventStream;

    async fn execute(
        &self,
        request: Request<Streaming<GuestProcessInput>>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let mut input = request.into_inner();
        let start = match input.next().await {
            Some(Ok(GuestProcessInput {
                message: Some(guest_process_input::Message::Start(start)),
            })) => start,
            Some(Ok(_)) => {
                return Err(protocol::detailed_status(Status::invalid_argument(
                    "first execute message must be start",
                )))
            }
            Some(Err(status)) => return Err(status),
            None => {
                return Err(protocol::detailed_status(Status::invalid_argument(
                    "execute stream closed before start",
                )))
            }
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<GuestProcessEvent, Status>>(64);
        let sender = EventSender {
            sender,
            remaining: self
                .guest
                .scenario
                .exec
                .drop_after_events
                .map(|limit| Arc::new(Mutex::new(limit))),
        };

        // Identity fencing, mirroring the real agent.
        let (instance_id, boot_id) = self.guest.identity();
        let launch_failure = if start.execution_id.is_empty()
            || start.expected_agent_instance_id.is_empty()
            || start.expected_agent_boot_id.is_empty()
        {
            Some((
                LaunchFailureReason::InvalidIdentity,
                "execution identity fields are required".to_string(),
            ))
        } else if start.expected_agent_instance_id != instance_id
            || start.expected_agent_boot_id != boot_id
        {
            Some((
                LaunchFailureReason::IdentityNotFound,
                "expected agent identity does not match the current agent".to_string(),
            ))
        } else {
            self.guest
                .scenario
                .exec
                .launch_failure
                .as_deref()
                .map(|reason| {
                    (
                        parse_launch_failure(reason),
                        format!("launch failed (scripted): {reason}"),
                    )
                })
        };

        if let Some((reason, message)) = launch_failure {
            sender.send(launch_failed_event(reason, message)).await;
            return Ok(Response::new(Box::pin(ReceiverStream::new(receiver))));
        }

        let guest = self.guest.clone();
        let generation = self.guest.stream_generation.subscribe();
        tokio::spawn(run_execution(guest, start, input, sender, generation));

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

/// Event sender that honors the scripted `dropAfterEvents` fault by closing
/// the channel (abruptly ending the stream) once the budget is exhausted.
#[derive(Clone)]
struct EventSender {
    sender: tokio::sync::mpsc::Sender<Result<GuestProcessEvent, Status>>,
    remaining: Option<Arc<Mutex<u32>>>,
}

impl EventSender {
    async fn send(&self, event: GuestProcessEvent) -> bool {
        if let Some(remaining) = &self.remaining {
            let mut remaining = remaining.lock().unwrap_or_else(PoisonError::into_inner);
            if *remaining == 0 {
                return false;
            }
            *remaining -= 1;
        }
        self.sender.send(Ok(event)).await.is_ok()
    }
}

fn launch_failed_event(reason: LaunchFailureReason, message: String) -> GuestProcessEvent {
    GuestProcessEvent {
        event: Some(guest_process_event::Event::LaunchFailed(
            GuestProcessLaunchFailed {
                reason: Some(reason as i32),
                message: Some(message),
            },
        )),
    }
}

fn parse_launch_failure(name: &str) -> LaunchFailureReason {
    match name.trim_start_matches("LAUNCH_FAILURE_REASON_") {
        "COMMAND_NOT_FOUND" => LaunchFailureReason::CommandNotFound,
        "INVALID_PROCESS_SPEC" => LaunchFailureReason::InvalidProcessSpec,
        "WORKING_DIRECTORY_NOT_FOUND" => LaunchFailureReason::WorkingDirectoryNotFound,
        "WORKING_DIRECTORY_NOT_DIRECTORY" => LaunchFailureReason::WorkingDirectoryNotDirectory,
        "INVALID_IDENTITY" => LaunchFailureReason::InvalidIdentity,
        "IDENTITY_NOT_FOUND" => LaunchFailureReason::IdentityNotFound,
        "PERMISSION_DENIED" => LaunchFailureReason::PermissionDenied,
        "SPAWN_FAILED" => LaunchFailureReason::SpawnFailed,
        "CANCELLED_BEFORE_START" => LaunchFailureReason::CancelledBeforeStart,
        _ => LaunchFailureReason::Unspecified,
    }
}

async fn run_execution(
    guest: Arc<MockGuest>,
    start: protocol::v1::StartGuestProcess,
    mut input: Streaming<GuestProcessInput>,
    events: EventSender,
    mut generation: watch::Receiver<u64>,
) {
    let Some(spec) = start.process else {
        events
            .send(launch_failed_event(
                LaunchFailureReason::InvalidProcessSpec,
                "process spec is required".to_string(),
            ))
            .await;
        return;
    };
    if spec.argv.is_empty() {
        events
            .send(launch_failed_event(
                LaunchFailureReason::InvalidProcessSpec,
                "argv must not be empty".to_string(),
            ))
            .await;
        return;
    }

    let is_pty = matches!(spec.stdio, Some(protocol::v1::process_spec::Stdio::Pty(_)));
    let wants_stdin = match &spec.stdio {
        Some(protocol::v1::process_spec::Stdio::Pipes(pipes)) => pipes.stdin,
        Some(protocol::v1::process_spec::Stdio::Pty(_)) => true,
        None => false,
    };

    // Map the guest working directory into the sandbox.
    let working_directory = match spec.working_directory.as_deref() {
        Some(path) => {
            let mapped = guest.guest_root().join(path.trim_start_matches('/'));
            if !mapped.is_dir() {
                events
                    .send(launch_failed_event(
                        LaunchFailureReason::WorkingDirectoryNotFound,
                        format!("working directory does not exist: {path}"),
                    ))
                    .await;
                return;
            }
            mapped
        }
        None => guest.guest_root().to_path_buf(),
    };

    let mut command = tokio::process::Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .current_dir(&working_directory)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &working_directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if wants_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .kill_on_drop(true);
    for variable in &spec.environment {
        command.env(&variable.name, &variable.value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            events
                .send(launch_failed_event(
                    LaunchFailureReason::CommandNotFound,
                    format!("command not found: {}", spec.argv[0]),
                ))
                .await;
            return;
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            events
                .send(launch_failed_event(
                    LaunchFailureReason::PermissionDenied,
                    format!("permission denied: {}", spec.argv[0]),
                ))
                .await;
            return;
        }
        Err(err) => {
            events
                .send(launch_failed_event(
                    LaunchFailureReason::SpawnFailed,
                    format!("spawn failed: {err}"),
                ))
                .await;
            return;
        }
    };

    if !events
        .send(GuestProcessEvent {
            event: Some(guest_process_event::Event::Started(GuestProcessStarted {})),
        })
        .await
    {
        let _ = child.start_kill();
        return;
    }

    let child_pid = child.id();
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    // Input pump: stdin data, close-stdin, signals. Resize is a no-op.
    let input_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(message) = input.next().await {
            let Ok(message) = message else { break };
            match message.message {
                Some(guest_process_input::Message::StdinData(data)) => {
                    if let Some(stdin) = stdin.as_mut() {
                        if stdin.write_all(&data.data).await.is_err() {
                            break;
                        }
                        let _ = stdin.flush().await;
                    }
                }
                Some(guest_process_input::Message::CloseStdin(_)) => {
                    stdin.take();
                }
                Some(guest_process_input::Message::SignalProcess(signal)) => {
                    if let (Some(pid), Some(signal)) = (child_pid, signal.signal) {
                        unsafe {
                            libc::kill(pid as i32, signal as i32);
                        }
                    }
                }
                Some(guest_process_input::Message::ResizePty(_)) => {}
                Some(guest_process_input::Message::Start(_)) | None => {}
            }
        }
    });

    // Output pumps.
    let stdout_events = events.clone();
    let stdout_task = tokio::spawn(async move {
        let Some(mut stdout) = stdout.take() else {
            return;
        };
        let mut buffer = [0u8; STDIO_CHUNK_BYTES];
        loop {
            match stdout.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    let event = if is_pty {
                        GuestProcessEvent {
                            event: Some(guest_process_event::Event::TerminalOutput(
                                GuestProcessTerminalOutput { data: data.into() },
                            )),
                        }
                    } else {
                        GuestProcessEvent {
                            event: Some(guest_process_event::Event::Stdout(GuestProcessStdout {
                                data: data.into(),
                            })),
                        }
                    };
                    if !stdout_events.send(event).await {
                        break;
                    }
                }
            }
        }
    });
    let stderr_events = events.clone();
    let stderr_task = tokio::spawn(async move {
        let Some(mut stderr) = stderr.take() else {
            return;
        };
        let mut buffer = [0u8; STDIO_CHUNK_BYTES];
        loop {
            match stderr.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    let event = if is_pty {
                        GuestProcessEvent {
                            event: Some(guest_process_event::Event::TerminalOutput(
                                GuestProcessTerminalOutput { data: data.into() },
                            )),
                        }
                    } else {
                        GuestProcessEvent {
                            event: Some(guest_process_event::Event::Stderr(GuestProcessStderr {
                                data: data.into(),
                            })),
                        }
                    };
                    if !stderr_events.send(event).await {
                        break;
                    }
                }
            }
        }
    });

    let status = tokio::select! {
        status = child.wait() => status,
        _ = generation.changed() => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            input_task.abort();
            return;
        }
    };

    let _ = tokio::join!(stdout_task, stderr_task);
    input_task.abort();

    match status {
        Ok(status) => {
            use std::os::unix::process::ExitStatusExt;
            let event = if let Some(signal) = status.signal() {
                GuestProcessEvent {
                    event: Some(guest_process_event::Event::Signaled(GuestProcessSignaled {
                        signal: Some(signal as u32),
                    })),
                }
            } else {
                GuestProcessEvent {
                    event: Some(guest_process_event::Event::Exited(GuestProcessExited {
                        code: status.code().map(|code| code as u32),
                    })),
                }
            };
            events.send(event).await;
        }
        Err(err) => {
            events
                .send(launch_failed_event(
                    LaunchFailureReason::SpawnFailed,
                    format!("wait failed: {err}"),
                ))
                .await;
        }
    }
}

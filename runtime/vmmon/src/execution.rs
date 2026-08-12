use std::collections::HashSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::virt::VirtualMachine;
use futures::Stream;
use protocol::v1::execute_input::Message as ExecuteMessage;
use protocol::v1::execution_event::Event as ExecutionEventKind;
use protocol::v1::guest_process_event::Event as GuestEventKind;
use protocol::v1::vm_execution_service_server::VmExecutionService;
use protocol::v1::{
    ExecutionAccepted, ExecutionEvent, ExecutionExited, ExecutionLaunchFailed, ExecutionLost,
    ExecutionSignaled, ExecutionStarted, ExecutionStderr, ExecutionStdout, ExecutionTerminalOutput,
    GuestProcessEvent, GuestProcessInput, LostReason, ProcessSpec, SignalProcess, StartExecution,
    StartGuestProcess,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::context::DaemonContext;
use crate::exec_log::{ExecLogSource, ExecLogWriter};
use crate::guest::process_client;
use crate::state::{InstanceStore, ReadyAgentIdentity};

mod startup;
pub(crate) use startup::{spawn_startup_command, StartupCommandHandle, StartupCommandStartError};

const EXECUTION_CAPACITY: usize = 64;
pub(super) const QUEUE_CAPACITY: usize = 64;
pub(super) const DISCONNECT_GRACE: Duration = Duration::from_secs(2);

type EventStream = Pin<Box<dyn Stream<Item = Result<ExecutionEvent, Status>> + Send + 'static>>;
type EventSender = mpsc::Sender<Result<ExecutionEvent, Status>>;

#[derive(Clone)]
pub(crate) struct ExecutionService {
    machine: VirtualMachine,
    machine_id: Uuid,
    machine_run_id: Uuid,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
    active: Arc<ActiveExecutions>,
    exec_log: Option<ExecLogWriter>,
}

impl ExecutionService {
    pub(crate) fn new(ctx: &DaemonContext, exec_log: Option<ExecLogWriter>) -> Self {
        Self {
            machine: ctx.machine.clone(),
            machine_id: ctx.machine_id,
            machine_run_id: ctx.machine_run_id,
            store: ctx.store.clone(),
            shutdown: ctx.shutdown.clone(),
            active: Arc::new(ActiveExecutions::new(EXECUTION_CAPACITY)),
            exec_log,
        }
    }

    fn validate_start(&self, start: &StartExecution) -> Result<(Uuid, ReadyAgentIdentity), Status> {
        if self.shutdown.is_cancelled() {
            return Err(stopping());
        }
        if self.store.is_stopping().map_err(store_status)? {
            return Err(stopping());
        }
        validate_identity_tuple(
            &start.machine_id,
            &start.machine_run_id,
            self.machine_id,
            self.machine_run_id,
        )?;
        let execution_id = parse_uuid("execution_id", &start.execution_id)?;
        let process = start
            .process
            .as_ref()
            .ok_or_else(|| invalid_request("process is required"))?;
        validate_process_spec(process)?;
        let agent = self
            .store
            .ready_agent_identity()
            .map_err(|_| unavailable_agent())?;
        Ok((execution_id, agent))
    }
}

#[tonic::async_trait]
impl VmExecutionService for ExecutionService {
    type ExecuteStream = EventStream;

    async fn execute(
        &self,
        request: Request<tonic::Streaming<protocol::v1::ExecuteInput>>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let mut input = request.into_inner();
        let first = input
            .message()
            .await
            .map_err(protocol::detailed_status)?
            .ok_or_else(|| invalid_request("the first Execute request must be StartExecution"))?;
        let ExecuteMessage::Start(start) = first
            .message
            .ok_or_else(|| invalid_request("the first Execute request must be StartExecution"))?
        else {
            return Err(invalid_request(
                "the first Execute request must be StartExecution",
            ));
        };
        let (execution_id, agent) = self.validate_start(&start)?;
        let lease = self.active.acquire(execution_id)?;
        let identity_changes = self.store.subscribe_ready_agent_identity();
        let (events, receiver) = mpsc::channel(QUEUE_CAPACITY);
        events
            .try_send(Ok(ExecutionEvent {
                event: Some(ExecutionEventKind::Accepted(ExecutionAccepted {})),
            }))
            .map_err(|_| {
                protocol::detailed_status(Status::internal("execution event queue closed"))
            })?;
        let cancellation = CancellationToken::new();
        tokio::spawn(run_execution(
            self.machine.clone(),
            self.store.clone(),
            self.shutdown.clone(),
            execution_id,
            agent,
            start.process,
            input,
            events,
            self.exec_log.clone(),
            cancellation.clone(),
            identity_changes,
            lease,
        ));
        Ok(Response::new(Box::pin(HostEventStream {
            receiver: ReceiverStream::new(receiver),
            cancellation,
        })))
    }
}

struct HostEventStream {
    receiver: ReceiverStream<Result<ExecutionEvent, Status>>,
    cancellation: CancellationToken,
}

impl Stream for HostEventStream {
    type Item = Result<ExecutionEvent, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl Drop for HostEventStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct ActiveExecutions {
    ids: Mutex<HashSet<Uuid>>,
    capacity: Arc<Semaphore>,
}

impl ActiveExecutions {
    fn new(capacity: usize) -> Self {
        Self {
            ids: Mutex::new(HashSet::new()),
            capacity: Arc::new(Semaphore::new(capacity)),
        }
    }

    fn acquire(self: &Arc<Self>, execution_id: Uuid) -> Result<ExecutionLease, Status> {
        let mut ids = self.lock_ids()?;
        if ids.contains(&execution_id) {
            return Err(already_exists());
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| exhausted())?;
        ids.insert(execution_id);
        Ok(ExecutionLease {
            active: self.clone(),
            execution_id,
            _permit: permit,
        })
    }

    fn lock_ids(&self) -> Result<std::sync::MutexGuard<'_, HashSet<Uuid>>, Status> {
        self.ids.lock().map_err(|_| {
            protocol::detailed_status(Status::internal("execution registry lock poisoned"))
        })
    }
}

struct ExecutionLease {
    active: Arc<ActiveExecutions>,
    execution_id: Uuid,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ExecutionLease {
    fn drop(&mut self) {
        if let Ok(mut ids) = self.active.ids.lock() {
            ids.remove(&self.execution_id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_execution(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
    execution_id: Uuid,
    expected_agent: ReadyAgentIdentity,
    process: Option<ProcessSpec>,
    mut input: tonic::Streaming<protocol::v1::ExecuteInput>,
    events: EventSender,
    exec_log: Option<ExecLogWriter>,
    cancellation: CancellationToken,
    mut identity_changes: tokio::sync::watch::Receiver<Option<ReadyAgentIdentity>>,
    _lease: ExecutionLease,
) {
    let current = match store.ready_agent_identity() {
        Ok(identity) => identity,
        Err(_) => {
            send_lost(
                &events,
                LostReason::AgentUnavailable,
                "guest agent is no longer ready",
            )
            .await;
            return;
        }
    };
    if let Some((reason, message)) = identity_loss(expected_agent.clone(), Some(current)) {
        send_lost(&events, reason, message).await;
        return;
    }
    let process = match process {
        Some(process) => process,
        None => {
            send_lost(
                &events,
                LostReason::GuestStreamLost,
                "execution process disappeared",
            )
            .await;
            return;
        }
    };
    let mut client = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        _ = shutdown.cancelled() => {
            send_lost(&events, LostReason::VmmonExited, "vmmon is stopping").await;
            return;
        }
        result = process_client(&machine) => match result {
            Ok(client) => client,
            Err(error) => {
                send_lost(&events, LostReason::AgentUnavailable, error.message()).await;
                return;
            }
        },
    };
    let (guest_inputs, guest_input_receiver) = mpsc::channel(QUEUE_CAPACITY);
    let start = GuestProcessInput {
        message: Some(protocol::v1::guest_process_input::Message::Start(
            StartGuestProcess {
                execution_id: execution_id.hyphenated().to_string(),
                expected_agent_instance_id: expected_agent.instance_id.hyphenated().to_string(),
                expected_agent_boot_id: expected_agent.boot_id.hyphenated().to_string(),
                process: Some(process),
            },
        )),
    };
    if guest_inputs.send(start).await.is_err() {
        send_lost(
            &events,
            LostReason::GuestStreamLost,
            "guest input stream closed",
        )
        .await;
        return;
    }
    let mut disconnect_term = match guest_inputs.clone().reserve_owned().await {
        Ok(permit) => Some(permit),
        Err(_) => {
            send_lost(
                &events,
                LostReason::GuestStreamLost,
                "guest input stream closed",
            )
            .await;
            return;
        }
    };
    let mut disconnect_kill = match guest_inputs.clone().reserve_owned().await {
        Ok(permit) => Some(permit),
        Err(_) => {
            send_lost(
                &events,
                LostReason::GuestStreamLost,
                "guest input stream closed",
            )
            .await;
            return;
        }
    };
    let response = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return,
        _ = shutdown.cancelled() => {
            send_lost(&events, LostReason::VmmonExited, "vmmon is stopping").await;
            return;
        }
        result = client.execute(Request::new(ReceiverStream::new(guest_input_receiver))) => match result {
            Ok(response) => response,
            Err(error) => {
                let (reason, message) = current_identity_loss(&store, &expected_agent)
                    .unwrap_or((LostReason::GuestStreamLost, error.message()));
                send_lost(&events, reason, message).await;
                return;
            }
        },
    };
    let mut guest_events = response.into_inner();
    let mut input_open = true;
    let mut guest_state = GuestEventState::default();
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                return;
            }
            _ = shutdown.cancelled() => {
                send_lost(&events, LostReason::VmmonExited, "vmmon is stopping").await;
                cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                return;
            }
            changed = identity_changes.changed() => {
                if changed.is_err() {
                    send_lost(&events, LostReason::AgentUnavailable, "guest identity notifications stopped").await;
                    cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                    return;
                }
                let current = identity_changes.borrow_and_update().clone();
                if let Some((reason, message)) = identity_loss(expected_agent.clone(), current) {
                    send_lost(&events, reason, message).await;
                    cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                    return;
                }
            }
            guest = guest_events.message() => match guest {
                Ok(Some(guest)) => match ensure_agent_generation(&expected_agent, &identity_changes)
                    .and_then(|()| {
                        log_guest_launch_failure(execution_id, &guest);
                        translate_event(guest, &mut guest_state).map_err(Status::unavailable)
                    }) {
                    Ok((event, terminal)) => {
                        log_execution_output(exec_log.as_ref(), execution_id, &event);
                        if events.send(Ok(event)).await.is_err() { return; }
                        if terminal { return; }
                    }
                    Err(error) => {
                        let current = identity_changes.borrow().clone();
                        if let Some((reason, message)) = identity_loss(expected_agent.clone(), current) {
                            send_lost(&events, reason, message).await;
                        } else {
                            send_lost(&events, LostReason::GuestStreamLost, error.message()).await;
                        }
                        return;
                    }
                },
                Ok(None) => {
                    send_lost(&events, LostReason::GuestStreamLost, "guest process stream ended before a terminal result").await;
                    return;
                }
                Err(error) => {
                    send_lost(&events, LostReason::GuestStreamLost, error.message()).await;
                    return;
                }
            },
            control = input.message(), if input_open => match control {
                Ok(Some(control)) => {
                    let current = identity_changes.borrow().clone();
                    if let Some((reason, message)) = identity_loss(expected_agent.clone(), current) {
                        send_lost(&events, reason, message).await;
                        cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                        return;
                    }
                    match guest_control(control) {
                    Ok(control) => match forward_guest_control(control, &guest_inputs, &cancellation, &shutdown).await {
                        Ok(()) => {}
                        Err(error) => {
                            let _ = events.send(Err(protocol::detailed_status(error))).await;
                            cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                            return;
                        }
                    },
                    Err(error) => {
                        let _ = events.send(Err(protocol::detailed_status(error))).await;
                        cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                        return;
                    }
                    }
                },
                Ok(None) if !guest_state.started => {
                    cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                    let _ = events.send(Ok(cancelled_before_start_event())).await;
                    return;
                }
                Ok(None) => input_open = false,
                Err(_) => {
                    cancel_guest(&mut disconnect_term, &mut disconnect_kill, &mut guest_events).await;
                    return;
                }
            }
        }
    }
}

fn cancelled_before_start_event() -> ExecutionEvent {
    ExecutionEvent {
        event: Some(ExecutionEventKind::LaunchFailed(ExecutionLaunchFailed {
            reason: Some(protocol::v1::LaunchFailureReason::CancelledBeforeStart as i32),
            message: Some("execution request closed before process start".to_string()),
        })),
    }
}

async fn forward_guest_control(
    control: GuestProcessInput,
    guest_inputs: &mpsc::Sender<GuestProcessInput>,
    cancellation: &CancellationToken,
    shutdown: &CancellationToken,
) -> Result<(), Status> {
    tokio::select! {
        result = guest_inputs.send(control) => result.map_err(|_| protocol::detailed_status(Status::unavailable("guest input stream closed"))),
        _ = cancellation.cancelled() => Err(Status::cancelled("execution client disconnected")),
        _ = shutdown.cancelled() => Err(stopping()),
    }
}

pub(super) fn ensure_agent_generation(
    expected: &ReadyAgentIdentity,
    current: &tokio::sync::watch::Receiver<Option<ReadyAgentIdentity>>,
) -> Result<(), Status> {
    if let Some((_, message)) = identity_loss(expected.clone(), current.borrow().clone()) {
        return Err(Status::unavailable(message));
    }
    Ok(())
}

fn current_identity_loss(
    store: &InstanceStore,
    expected: &ReadyAgentIdentity,
) -> Option<(LostReason, &'static str)> {
    match store.ready_agent_identity() {
        Ok(current) => identity_loss(expected.clone(), Some(current)),
        Err(_) => Some((
            LostReason::AgentUnavailable,
            "guest agent is no longer ready",
        )),
    }
}

fn guest_control(control: protocol::v1::ExecuteInput) -> Result<GuestProcessInput, Status> {
    let message = match control.message {
        Some(ExecuteMessage::StdinData(data)) => {
            if data.data.len() > protocol::CHUNK_64_KIB {
                return Err(invalid_request("stdin data exceeds 64 KiB"));
            }
            protocol::v1::guest_process_input::Message::StdinData(data)
        }
        Some(ExecuteMessage::CloseStdin(close)) => {
            protocol::v1::guest_process_input::Message::CloseStdin(close)
        }
        Some(ExecuteMessage::ResizePty(resize)) => {
            validate_terminal_size(resize.size.as_ref(), "PTY resize size")?;
            protocol::v1::guest_process_input::Message::ResizePty(resize)
        }
        Some(ExecuteMessage::SignalProcess(signal)) => {
            validate_signal(&signal)?;
            protocol::v1::guest_process_input::Message::SignalProcess(signal)
        }
        Some(ExecuteMessage::Start(_)) => {
            return Err(invalid_request(
                "StartExecution is only valid as the first Execute request",
            ));
        }
        None => return Err(invalid_request("Execute request message is required")),
    };
    Ok(GuestProcessInput {
        message: Some(message),
    })
}

fn validate_process_spec(process: &ProcessSpec) -> Result<(), Status> {
    if process.argv.is_empty() || process.argv.iter().any(|argument| argument.contains('\0')) {
        return Err(invalid_request(
            "argv must be nonempty and contain no NUL bytes",
        ));
    }
    let mut names = HashSet::new();
    for variable in &process.environment {
        let valid_name = !variable.name.is_empty()
            && variable.name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_'
                    || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
            });
        if !valid_name || variable.value.contains('\0') || !names.insert(&variable.name) {
            return Err(invalid_request("environment contains an invalid variable"));
        }
    }
    if process
        .working_directory
        .as_deref()
        .is_some_and(|path| path.contains('\0'))
    {
        return Err(invalid_request(
            "working directory must not contain NUL bytes",
        ));
    }
    if process
        .user
        .as_deref()
        .is_some_and(|user| user.is_empty() || user.contains('\0'))
    {
        return Err(invalid_request(
            "user must be nonempty and contain no NUL bytes",
        ));
    }
    match &process.stdio {
        Some(protocol::v1::process_spec::Stdio::Pipes(_)) => Ok(()),
        Some(protocol::v1::process_spec::Stdio::Pty(pty)) => {
            validate_terminal_size(pty.initial_size.as_ref(), "PTY initial size")?;
            if pty
                .terminal
                .as_deref()
                .is_some_and(|terminal| terminal.contains('\0'))
            {
                return Err(invalid_request("PTY terminal must not contain NUL bytes"));
            }
            Ok(())
        }
        None => Err(invalid_request("stdio mode is required")),
    }
}

pub(super) fn validate_terminal_size(
    size: Option<&protocol::v1::TerminalSize>,
    field: &str,
) -> Result<(), Status> {
    let size = size.ok_or_else(|| invalid_request(format!("{field} is required")))?;
    if !(1..=u32::from(u16::MAX)).contains(&size.columns)
        || !(1..=u32::from(u16::MAX)).contains(&size.rows)
    {
        return Err(invalid_request(format!(
            "{field} columns and rows must be from 1 through 65535"
        )));
    }
    Ok(())
}

pub(super) fn validate_signal(signal: &SignalProcess) -> Result<(), Status> {
    let raw = signal
        .signal
        .ok_or_else(|| invalid_request("a positive process signal is required"))?;
    if !(1..=64).contains(&raw) {
        return Err(invalid_request(
            "process signal must be a valid Linux signal number from 1 through 64",
        ));
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct GuestEventState {
    started: bool,
}

pub(super) fn translate_event(
    guest: GuestProcessEvent,
    state: &mut GuestEventState,
) -> Result<(ExecutionEvent, bool), &'static str> {
    let translated = match guest.event {
        Some(GuestEventKind::Started(_)) if !state.started => {
            state.started = true;
            (ExecutionEventKind::Started(ExecutionStarted {}), false)
        }
        Some(GuestEventKind::Started(_)) => return Err("guest process emitted duplicate Started"),
        Some(GuestEventKind::Stdout(stdout))
            if state.started && stdout.data.len() <= protocol::CHUNK_64_KIB =>
        {
            (
                ExecutionEventKind::Stdout(ExecutionStdout { data: stdout.data }),
                false,
            )
        }
        Some(GuestEventKind::Stdout(_)) if !state.started => {
            return Err("guest process emitted stdout before Started");
        }
        Some(GuestEventKind::Stdout(_)) => return Err("guest process stdout exceeds 64 KiB"),
        Some(GuestEventKind::Stderr(stderr))
            if state.started && stderr.data.len() <= protocol::CHUNK_64_KIB =>
        {
            (
                ExecutionEventKind::Stderr(ExecutionStderr { data: stderr.data }),
                false,
            )
        }
        Some(GuestEventKind::Stderr(_)) if !state.started => {
            return Err("guest process emitted stderr before Started");
        }
        Some(GuestEventKind::Stderr(_)) => return Err("guest process stderr exceeds 64 KiB"),
        Some(GuestEventKind::TerminalOutput(output))
            if state.started && output.data.len() <= protocol::CHUNK_64_KIB =>
        {
            (
                ExecutionEventKind::TerminalOutput(ExecutionTerminalOutput { data: output.data }),
                false,
            )
        }
        Some(GuestEventKind::TerminalOutput(_)) if !state.started => {
            return Err("guest process emitted terminal output before Started");
        }
        Some(GuestEventKind::TerminalOutput(_)) => {
            return Err("guest process terminal output exceeds 64 KiB");
        }
        Some(GuestEventKind::Exited(exited)) if state.started => (
            ExecutionEventKind::Exited(ExecutionExited { code: exited.code }),
            true,
        ),
        Some(GuestEventKind::Exited(_)) => return Err("guest process exited before Started"),
        Some(GuestEventKind::Signaled(signaled))
            if state.started
                && signaled
                    .signal
                    .is_some_and(|signal| (1..=64).contains(&signal)) =>
        {
            (
                ExecutionEventKind::Signaled(ExecutionSignaled {
                    signal: signaled.signal,
                }),
                true,
            )
        }
        Some(GuestEventKind::Signaled(_)) if !state.started => {
            return Err("guest process was signaled before Started");
        }
        Some(GuestEventKind::Signaled(_)) => return Err("guest process emitted an invalid signal"),
        Some(GuestEventKind::LaunchFailed(failure)) if !state.started => (
            ExecutionEventKind::LaunchFailed(ExecutionLaunchFailed {
                reason: failure.reason,
                message: failure.message,
            }),
            true,
        ),
        Some(GuestEventKind::LaunchFailed(_)) => {
            return Err("guest process emitted LaunchFailed after Started");
        }
        None => return Err("guest process event is missing its message"),
    };
    Ok((
        ExecutionEvent {
            event: Some(translated.0),
        },
        translated.1,
    ))
}

pub(super) fn log_guest_launch_failure(execution_id: Uuid, event: &GuestProcessEvent) {
    let Some(GuestEventKind::LaunchFailed(failure)) = &event.event else {
        return;
    };
    let reason = protocol::v1::LaunchFailureReason::try_from(failure.reason.unwrap_or_default())
        .unwrap_or(protocol::v1::LaunchFailureReason::Unspecified);
    tracing::warn!(
        execution_id = %execution_id,
        reason = ?reason,
        detail = failure.message.as_deref().unwrap_or("unspecified launch failure"),
        "guest process launch failure reported"
    );
}

pub(super) fn log_execution_output(
    exec_log: Option<&ExecLogWriter>,
    execution_id: Uuid,
    event: &ExecutionEvent,
) {
    let Some(exec_log) = exec_log else {
        return;
    };
    let Some((source, data)) = event.event.as_ref().and_then(|event| match event {
        ExecutionEventKind::Stdout(output) => Some((ExecLogSource::Stdout, output.data.as_ref())),
        ExecutionEventKind::Stderr(output) => Some((ExecLogSource::Stderr, output.data.as_ref())),
        ExecutionEventKind::TerminalOutput(output) => {
            Some((ExecLogSource::Output, output.data.as_ref()))
        }
        _ => None,
    }) else {
        return;
    };
    exec_log.write(source, execution_id, data);
}

async fn send_lost(events: &EventSender, reason: LostReason, message: impl AsRef<str>) {
    let _ = events
        .send(Ok(ExecutionEvent {
            event: Some(ExecutionEventKind::Lost(ExecutionLost {
                reason: Some(reason as i32),
                message: Some(message.as_ref().to_string()),
            })),
        }))
        .await;
}

pub(super) fn identity_loss(
    expected: ReadyAgentIdentity,
    current: Option<ReadyAgentIdentity>,
) -> Option<(LostReason, &'static str)> {
    match current {
        None => Some((
            LostReason::AgentUnavailable,
            "guest agent is no longer ready",
        )),
        Some(current) if current.instance_id != expected.instance_id => Some((
            LostReason::AgentInstanceReplaced,
            "guest agent instance was replaced",
        )),
        Some(current) if current.boot_id != expected.boot_id => {
            Some((LostReason::AgentBootReplaced, "guest boot was replaced"))
        }
        Some(_) => None,
    }
}

pub(super) async fn cancel_guest(
    disconnect_term: &mut Option<mpsc::OwnedPermit<GuestProcessInput>>,
    disconnect_kill: &mut Option<mpsc::OwnedPermit<GuestProcessInput>>,
    guest_events: &mut tonic::Streaming<GuestProcessEvent>,
) {
    let deadline = tokio::time::Instant::now() + DISCONNECT_GRACE;
    if let Some(permit) = disconnect_term.take() {
        permit.send(signal_input(libc::SIGTERM as u32));
    }
    if wait_for_terminal(guest_events, deadline).await {
        drain_guest(guest_events, deadline).await;
        return;
    }
    if let Some(permit) = disconnect_kill.take() {
        permit.send(signal_input(libc::SIGKILL as u32));
    }
    let kill_deadline = tokio::time::Instant::now() + DISCONNECT_GRACE;
    drain_guest(guest_events, kill_deadline).await;
}

fn signal_input(signal: u32) -> GuestProcessInput {
    GuestProcessInput {
        message: Some(protocol::v1::guest_process_input::Message::SignalProcess(
            SignalProcess {
                signal: Some(signal),
            },
        )),
    }
}

async fn wait_for_terminal(
    guest_events: &mut tonic::Streaming<GuestProcessEvent>,
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        let message = match tokio::time::timeout_at(deadline, guest_events.message()).await {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return false,
        };
        if matches!(
            message.event,
            Some(GuestEventKind::Exited(_))
                | Some(GuestEventKind::Signaled(_))
                | Some(GuestEventKind::LaunchFailed(_))
        ) {
            return true;
        }
    }
}

async fn drain_guest(
    guest_events: &mut tonic::Streaming<GuestProcessEvent>,
    deadline: tokio::time::Instant,
) {
    loop {
        match tokio::time::timeout_at(deadline, guest_events.message()).await {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return,
        }
    }
}

fn parse_uuid(field: &str, value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| invalid_request(format!("{field} must be a UUID")))
}

fn validate_identity_tuple(
    machine_id: &str,
    machine_run_id: &str,
    expected_machine_id: Uuid,
    expected_machine_run_id: Uuid,
) -> Result<(), Status> {
    if parse_uuid("machine_id", machine_id)? != expected_machine_id {
        return Err(protocol::detailed_status(Status::failed_precondition(
            "machine ID does not match this monitor",
        )));
    }
    if parse_uuid("machine_run_id", machine_run_id)? != expected_machine_run_id {
        return Err(protocol::detailed_status(Status::failed_precondition(
            "machine run ID does not match this monitor",
        )));
    }
    Ok(())
}

fn invalid_request(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::invalid_argument(message.into()))
}

fn unavailable_agent() -> Status {
    protocol::status_with_error(
        tonic::Code::FailedPrecondition,
        protocol::v1::ErrorCode::PreconditionFailed,
        "a ready guest agent is required for execution",
        None,
    )
}

fn store_status(_: crate::state::StoreError) -> Status {
    protocol::detailed_status(Status::internal("unable to read execution state"))
}

fn stopping() -> Status {
    protocol::status_with_error(
        tonic::Code::Unavailable,
        protocol::v1::ErrorCode::MonitorStopping,
        "monitor is stopping",
        None,
    )
}

fn already_exists() -> Status {
    protocol::status_with_error(
        tonic::Code::AlreadyExists,
        protocol::v1::ErrorCode::AlreadyExists,
        "an Execute call already owns this execution ID",
        None,
    )
}

fn exhausted() -> Status {
    protocol::status_with_error(
        tonic::Code::ResourceExhausted,
        protocol::v1::ErrorCode::ResourceExhausted,
        "execution capacity is exhausted",
        None,
    )
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use protocol::v1::execution_event::Event as ExecutionEventKind;
    use protocol::v1::guest_process_event::Event as GuestEventKind;
    use protocol::v1::{
        GuestProcessEvent, GuestProcessExited, GuestProcessStarted, GuestProcessStdout, PipeStdio,
        ProcessSpec, TerminalSize,
    };

    use crate::execution::{
        cancelled_before_start_event, guest_control, identity_loss, translate_event,
        validate_identity_tuple, validate_process_spec, ActiveExecutions, GuestEventState,
        HostEventStream,
    };
    use crate::state::ReadyAgentIdentity;

    #[test]
    fn identities_compare_as_uuids_not_strings() {
        let machine = uuid::Uuid::new_v4();
        let run = uuid::Uuid::new_v4();
        assert!(validate_identity_tuple(
            &machine.simple().to_string(),
            &run.hyphenated().to_string(),
            machine,
            run,
        )
        .is_ok());
        assert!(validate_identity_tuple(
            &uuid::Uuid::new_v4().to_string(),
            &run.to_string(),
            machine,
            run
        )
        .is_err());
    }

    #[test]
    fn process_and_controls_are_validated_at_host_boundary() {
        assert!(validate_process_spec(&ProcessSpec::default()).is_err());
        let pty = ProcessSpec {
            argv: vec!["/bin/true".to_string()],
            stdio: Some(protocol::v1::process_spec::Stdio::Pty(
                protocol::v1::PtyStdio {
                    initial_size: Some(TerminalSize {
                        columns: 0,
                        rows: 24,
                    }),
                    terminal: None,
                },
            )),
            ..ProcessSpec::default()
        };
        assert!(validate_process_spec(&pty).is_err());
        assert!(guest_control(protocol::v1::ExecuteInput::default()).is_err());
        assert!(guest_control(protocol::v1::ExecuteInput {
            message: Some(protocol::v1::execute_input::Message::StdinData(
                protocol::v1::StdinData {
                    data: Bytes::from(vec![0; protocol::CHUNK_64_KIB + 1]),
                }
            )),
        })
        .is_err());
        assert!(validate_process_spec(&ProcessSpec {
            argv: vec!["/bin/true".to_string()],
            stdio: Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio {
                stdin: false
            })),
            ..ProcessSpec::default()
        })
        .is_ok());
    }

    #[test]
    fn guest_events_translate_and_preserve_original_bytes() {
        let mut state = GuestEventState::default();
        translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Started(GuestProcessStarted {})),
            },
            &mut state,
        )
        .expect("translate started");
        let (stdout, terminal) = translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Stdout(GuestProcessStdout {
                    data: Bytes::from_static(b"one"),
                })),
            },
            &mut state,
        )
        .expect("translate stdout");
        assert!(!terminal);
        assert!(
            matches!(stdout.event, Some(ExecutionEventKind::Stdout(ref output)) if output.data == b"one".as_slice())
        );
        let (exited, terminal) = translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Exited(GuestProcessExited { code: Some(7) })),
            },
            &mut state,
        )
        .expect("translate exit");
        assert!(terminal);
        assert!(
            matches!(exited.event, Some(ExecutionEventKind::Exited(ref exit)) if exit.code == Some(7))
        );
    }

    #[test]
    fn guest_event_validation_rejects_output_before_started_and_oversized_chunks() {
        let mut state = GuestEventState::default();
        assert!(translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Stdout(GuestProcessStdout {
                    data: Bytes::from_static(b"early"),
                })),
            },
            &mut state,
        )
        .is_err());
        translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Started(GuestProcessStarted {})),
            },
            &mut state,
        )
        .expect("translate started");
        assert!(translate_event(
            GuestProcessEvent {
                event: Some(GuestEventKind::Stdout(GuestProcessStdout {
                    data: Bytes::from(vec![0; protocol::CHUNK_64_KIB + 1]),
                })),
            },
            &mut state,
        )
        .is_err());
    }

    #[test]
    fn closing_a_pending_execution_reports_cancelled_before_start() {
        let event = cancelled_before_start_event();

        assert!(matches!(
            event.event,
            Some(ExecutionEventKind::LaunchFailed(failure))
                if failure.reason == Some(protocol::v1::LaunchFailureReason::CancelledBeforeStart as i32)
        ));
    }

    #[test]
    fn active_registry_rejects_collisions_and_exhaustion() {
        let active = std::sync::Arc::new(ActiveExecutions::new(1));
        let id = uuid::Uuid::new_v4();
        let lease = active.acquire(id).expect("first lease");
        let collision = match active.acquire(id) {
            Ok(_) => panic!("collision should fail"),
            Err(error) => error,
        };
        assert_eq!(collision.code(), tonic::Code::AlreadyExists);
        let full = match active.acquire(uuid::Uuid::new_v4()) {
            Ok(_) => panic!("full registry should fail"),
            Err(error) => error,
        };
        assert_eq!(full.code(), tonic::Code::ResourceExhausted);
        drop(lease);
        assert!(active.acquire(id).is_ok());
    }

    #[test]
    fn dropped_output_stream_cancels_the_execution() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let stream = HostEventStream {
            receiver: tokio_stream::wrappers::ReceiverStream::new(receiver),
            cancellation: cancellation.clone(),
        };
        drop(stream);
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn identity_replacement_is_lost_with_a_specific_reason() {
        let expected = ReadyAgentIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: uuid::Uuid::new_v4(),
        };
        let replacement = ReadyAgentIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: expected.boot_id,
        };
        assert!(matches!(
            identity_loss(expected, Some(replacement)),
            Some((protocol::v1::LostReason::AgentInstanceReplaced, _))
        ));
    }
}

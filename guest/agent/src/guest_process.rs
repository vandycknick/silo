use std::collections::HashSet;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::Stream;
use nix::sys::signal::Signal;
use nix::unistd::{getgrouplist, Gid};
use protocol::v1::guest_process_event::Event;
use protocol::v1::guest_process_input::Message;
use protocol::v1::guest_process_service_server::GuestProcessService;
use protocol::v1::{
    GuestProcessEvent, GuestProcessExited, GuestProcessLaunchFailed, GuestProcessSignaled,
    GuestProcessStarted, GuestProcessStderr, GuestProcessStdout, GuestProcessTerminalOutput,
    LaunchFailureReason, PipeStdio, ProcessSpec, PtyStdio, ResizePty, SignalProcess,
    StartGuestProcess, StdinData, TerminalSize,
};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::pid1::{ChildGuard, ProcessSupervisor};
use crate::ssh::agent::{
    attach_pty_slave, open_process_pty, prepare_identity_child, prepare_pty_child,
    resize_process_pty, signal_process_group, valid_environment_name,
};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEFAULT_PTY_TERM: &str = "xterm-256color";
const QUEUE_CAPACITY: usize = 64;
const DISCONNECT_GRACE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

type EventStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<GuestProcessEvent, Status>> + Send + 'static>>;
type EventSender = mpsc::Sender<Result<GuestProcessEvent, Status>>;

struct ProcessEventStream {
    receiver: ReceiverStream<Result<GuestProcessEvent, Status>>,
    cancellation: watch::Sender<bool>,
}

impl Stream for ProcessEventStream {
    type Item = Result<GuestProcessEvent, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl Drop for ProcessEventStream {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
    }
}

#[derive(Clone)]
pub(crate) struct GuestProcessServiceImpl {
    instance_id: String,
    boot_id: String,
    process_supervisor: ProcessSupervisor,
    active_executions: Arc<Mutex<HashSet<Uuid>>>,
    capacity: Arc<Semaphore>,
}

impl GuestProcessServiceImpl {
    pub(crate) fn new(
        instance_id: String,
        boot_id: String,
        process_supervisor: ProcessSupervisor,
    ) -> Self {
        Self {
            instance_id,
            boot_id,
            process_supervisor,
            active_executions: Arc::new(Mutex::new(HashSet::new())),
            capacity: Arc::new(Semaphore::new(64)),
        }
    }
}

#[tonic::async_trait]
impl GuestProcessService for GuestProcessServiceImpl {
    type ExecuteStream = EventStream;

    async fn execute(
        &self,
        request: Request<tonic::Streaming<protocol::v1::GuestProcessInput>>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        let mut input = request.into_inner();
        let first = input
            .message()
            .await
            .map_err(protocol::detailed_status)?
            .ok_or_else(|| {
                invalid_request("the first Execute request must be StartGuestProcess")
            })?;
        let Message::Start(start) = first.message.ok_or_else(|| {
            invalid_request("the first Execute request must be StartGuestProcess")
        })?
        else {
            return Err(invalid_request(
                "the first Execute request must be StartGuestProcess",
            ));
        };

        let execution_id = self.validate_start(&start)?;
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| {
                protocol::status_with_error(
                    tonic::Code::ResourceExhausted,
                    protocol::v1::ErrorCode::ResourceExhausted,
                    "guest process execution capacity is full",
                    None,
                )
            })?;
        let execution =
            ExecutionLease::acquire(Arc::clone(&self.active_executions), execution_id, permit)?;
        let (events, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);

        let plan = match ProcessPlan::from_start(start) {
            Ok(plan) => plan,
            Err(failure) => {
                log_launch_failure(execution_id, &failure);
                let _ = events.try_send(Ok(failure.event()));
                drop(execution);
                tokio::spawn(drain_rejected_input(input, cancel_receiver));
                return Ok(Response::new(Box::pin(ProcessEventStream {
                    receiver: ReceiverStream::new(receiver),
                    cancellation: cancel,
                })));
            }
        };
        let (controls, control_receiver) = mpsc::channel(QUEUE_CAPACITY);
        let input_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                match input.message().await {
                    Ok(Some(control)) => {
                        if controls.send(control).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        tracing::debug!(error = %error, "guest process control stream was lost");
                        input_cancel.send_replace(true);
                        return;
                    }
                }
            }
        });

        let supervisor = self.process_supervisor.clone();
        tokio::spawn(async move {
            run_execution(
                plan,
                supervisor,
                control_receiver,
                events,
                cancel_receiver,
                execution,
            )
            .await;
        });

        Ok(Response::new(Box::pin(ProcessEventStream {
            receiver: ReceiverStream::new(receiver),
            cancellation: cancel,
        })))
    }
}

async fn drain_rejected_input(
    mut input: tonic::Streaming<protocol::v1::GuestProcessInput>,
    mut cancellation: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    return;
                }
            }
            message = input.message() => {
                if !matches!(message, Ok(Some(_))) {
                    return;
                }
            }
        }
    }
}

async fn run_execution(
    plan: ProcessPlan,
    supervisor: ProcessSupervisor,
    mut controls: mpsc::Receiver<protocol::v1::GuestProcessInput>,
    events: EventSender,
    mut cancellation: watch::Receiver<bool>,
    execution: ExecutionLease,
) {
    let mut spawn = tokio::task::spawn_blocking(move || spawn_process(plan, &supervisor));
    let mut controls_open = true;
    let mut deferred_control = None;
    let running = loop {
        tokio::select! {
            result = &mut spawn => break match result {
                Ok(result) => result,
                Err(error) => Err(LaunchFailure::spawn_failed(format!("process launch task failed: {error}"))),
            },
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    cancel_pending_launch(spawn).await;
                    return;
                }
            }
            control = controls.recv(), if controls_open && deferred_control.is_none() => match control {
                Some(control) => match prestart_control(control) {
                    Ok(PrestartControl::Signal) => {
                        let reason = LaunchFailure::new(
                            LaunchFailureReason::CancelledBeforeStart,
                            "process launch was cancelled before Started",
                        );
                        cancel_pending_launch(spawn).await;
                        let _ = events.send(Ok(reason.event())).await;
                        return;
                    }
                    Ok(PrestartControl::Deferred(control)) => {
                        deferred_control = Some(control);
                    }
                    Err(status) => {
                        let _ = events.send(Err(status)).await;
                        cancel_pending_launch(spawn).await;
                        return;
                    }
                },
                None => controls_open = false,
            },
        }
    };

    let running = match running {
        Ok(running) => running,
        Err(failure) => {
            log_launch_failure(execution.execution_id, &failure);
            let _ = events.send(Ok(failure.event())).await;
            return;
        }
    };
    if events
        .send(Ok(GuestProcessEvent {
            event: Some(Event::Started(GuestProcessStarted {})),
        }))
        .await
        .is_err()
    {
        let _ = tokio::task::spawn_blocking(move || {
            let mut running = running;
            terminate_and_reap(&mut running.child, running.process_group);
        })
        .await;
        return;
    }

    let _ = tokio::task::spawn_blocking(move || {
        drive_process(
            running,
            deferred_control,
            controls,
            events,
            cancellation,
            execution,
        )
    })
    .await;
}

enum PrestartControl {
    Signal,
    Deferred(protocol::v1::GuestProcessInput),
}

fn prestart_control(control: protocol::v1::GuestProcessInput) -> Result<PrestartControl, Status> {
    match &control.message {
        Some(Message::SignalProcess(signal)) => {
            let raw_signal = signal
                .signal
                .ok_or_else(|| invalid_request("a positive process signal is required"))?;
            let raw_signal = i32::try_from(raw_signal)
                .map_err(|_| invalid_request("process signal is out of range"))?;
            Signal::try_from(raw_signal)
                .map(|_| PrestartControl::Signal)
                .map_err(|_| invalid_request("a valid Linux process signal is required"))
        }
        Some(Message::Start(_)) => Err(invalid_request(
            "StartGuestProcess is only valid as the first Execute request",
        )),
        Some(_) => Ok(PrestartControl::Deferred(control)),
        None => Err(invalid_request("Execute request message is required")),
    }
}

async fn cancel_pending_launch(
    spawn: tokio::task::JoinHandle<Result<RunningProcess, LaunchFailure>>,
) {
    if let Ok(Ok(mut running)) = spawn.await {
        let _ = tokio::task::spawn_blocking(move || {
            terminate_and_reap(&mut running.child, running.process_group);
        })
        .await;
    }
}

impl GuestProcessServiceImpl {
    fn validate_start(&self, start: &StartGuestProcess) -> Result<Uuid, Status> {
        let execution_id = Uuid::parse_str(&start.execution_id)
            .map_err(|_| invalid_request("execution_id must be a UUID"))?;
        if start.expected_agent_instance_id != self.instance_id {
            return Err(protocol::status_with_error(
                tonic::Code::FailedPrecondition,
                protocol::v1::ErrorCode::PreconditionFailed,
                "expected agent instance ID does not match this agent",
                None,
            ));
        }
        if start.expected_agent_boot_id != self.boot_id {
            return Err(protocol::status_with_error(
                tonic::Code::FailedPrecondition,
                protocol::v1::ErrorCode::PreconditionFailed,
                "expected agent boot ID does not match this guest boot",
                None,
            ));
        }
        Ok(execution_id)
    }
}

struct ExecutionLease {
    active_executions: Arc<Mutex<HashSet<Uuid>>>,
    execution_id: Uuid,
    _permit: OwnedSemaphorePermit,
}

impl ExecutionLease {
    fn acquire(
        active_executions: Arc<Mutex<HashSet<Uuid>>>,
        execution_id: Uuid,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, Status> {
        {
            let mut executions = lock_or_recover(&active_executions);
            if !executions.insert(execution_id) {
                return Err(protocol::status_with_error(
                    tonic::Code::AlreadyExists,
                    protocol::v1::ErrorCode::AlreadyExists,
                    "an Execute call already owns this execution ID",
                    None,
                ));
            }
        }
        Ok(Self {
            active_executions,
            execution_id,
            _permit: permit,
        })
    }
}

impl Drop for ExecutionLease {
    fn drop(&mut self) {
        lock_or_recover(&self.active_executions).remove(&self.execution_id);
    }
}

struct ProcessPlan {
    argv: Vec<String>,
    environment: Vec<(String, String)>,
    working_directory: PathBuf,
    identity: Identity,
    stdio: ProcessStdio,
}

enum ProcessStdio {
    Pipes { stdin: bool },
    Pty { size: TerminalSize },
}

impl ProcessPlan {
    fn from_start(start: StartGuestProcess) -> Result<Self, LaunchFailure> {
        let spec = start
            .process
            .ok_or_else(|| LaunchFailure::invalid_spec("StartGuestProcess.process is required"))?;
        Self::from_spec(spec)
    }

    fn from_spec(spec: ProcessSpec) -> Result<Self, LaunchFailure> {
        if spec.argv.is_empty() {
            return Err(LaunchFailure::invalid_spec("argv must not be empty"));
        }
        if spec.argv.iter().any(|argument| argument.contains('\0')) {
            return Err(LaunchFailure::invalid_spec(
                "argv must not contain NUL bytes",
            ));
        }

        let mut names = HashSet::new();
        let mut environment = Vec::with_capacity(spec.environment.len() + 1);
        let mut has_path = false;
        for variable in spec.environment {
            if !valid_environment_name(&variable.name) || variable.value.contains('\0') {
                return Err(LaunchFailure::invalid_spec(
                    "environment contains an invalid variable",
                ));
            }
            if !names.insert(variable.name.clone()) {
                return Err(LaunchFailure::invalid_spec(
                    "environment variable names must be unique",
                ));
            }
            has_path |= variable.name == "PATH";
            environment.push((variable.name, variable.value));
        }
        if !has_path {
            environment.push(("PATH".to_string(), DEFAULT_PATH.to_string()));
        }

        let working_directory = PathBuf::from(spec.working_directory.unwrap_or_else(|| "/".into()));
        if working_directory
            .as_os_str()
            .as_encoded_bytes()
            .contains(&0)
        {
            return Err(LaunchFailure::invalid_spec(
                "working directory must not contain NUL bytes",
            ));
        }
        match fs::metadata(&working_directory) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(LaunchFailure::working_directory_not_directory(
                    &working_directory,
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(LaunchFailure::working_directory_not_found(
                    &working_directory,
                ));
            }
            Err(error) => {
                return Err(LaunchFailure::from_io(
                    LaunchFailureReason::PermissionDenied,
                    error,
                ))
            }
        }

        let identity = resolve_identity(spec.user.as_deref().unwrap_or("0:0"))?;
        let stdio = match spec.stdio {
            None => return Err(LaunchFailure::invalid_spec("stdio mode is required")),
            Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio { stdin })) => {
                ProcessStdio::Pipes { stdin }
            }
            Some(protocol::v1::process_spec::Stdio::Pty(PtyStdio {
                initial_size,
                terminal,
            })) => {
                let size = initial_size
                    .ok_or_else(|| LaunchFailure::invalid_spec("PTY initial_size is required"))?;
                validate_terminal_size(&size)?;
                let terminal = terminal
                    .or_else(|| {
                        environment
                            .iter()
                            .find_map(|(name, value)| (name == "TERM").then(|| value.clone()))
                    })
                    .unwrap_or_else(|| DEFAULT_PTY_TERM.to_string());
                if terminal.contains('\0') {
                    return Err(LaunchFailure::invalid_spec(
                        "PTY terminal contains a NUL byte",
                    ));
                }
                if !names.contains("TERM") {
                    environment.push(("TERM".to_string(), terminal));
                }
                ProcessStdio::Pty { size }
            }
        };

        Ok(Self {
            argv: spec.argv,
            environment,
            working_directory,
            identity,
            stdio,
        })
    }
}

#[derive(Clone)]
struct Identity {
    uid: u32,
    gid: u32,
    groups: Vec<Gid>,
}

struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
}

fn resolve_identity(selector: &str) -> Result<Identity, LaunchFailure> {
    let (user_selector, group_selector) = match selector.split_once(':') {
        Some((user, group)) if !user.is_empty() && !group.is_empty() && !group.contains(':') => {
            (user, Some(group))
        }
        Some(_) => return Err(LaunchFailure::invalid_identity("invalid user selector")),
        None if !selector.is_empty() => (selector, None),
        None => {
            return Err(LaunchFailure::invalid_identity(
                "user selector must not be empty",
            ))
        }
    };
    let passwd = read_passwd()?;
    let numeric_uid = user_selector.parse::<u32>().ok();
    let user = match numeric_uid {
        Some(uid) => passwd.into_iter().find(|entry| entry.uid == uid),
        None => passwd.into_iter().find(|entry| entry.name == user_selector),
    };

    let (uid, primary_gid, user_name) = match user {
        Some(user) => (user.uid, user.gid, Some(user.name)),
        None => match (numeric_uid, group_selector) {
            (Some(uid), Some(_)) => (uid, 0, None),
            (Some(_), None) => {
                return Err(LaunchFailure::invalid_identity(
                    "a numeric UID without a passwd entry requires an explicit group",
                ));
            }
            (None, _) => {
                return Err(LaunchFailure::identity_not_found(format!(
                    "user `{user_selector}` was not found"
                )))
            }
        },
    };

    if let Some(group_selector) = group_selector {
        return Ok(Identity {
            uid,
            gid: resolve_group(group_selector)?,
            groups: Vec::new(),
        });
    }

    let user_name = user_name.ok_or_else(|| {
        LaunchFailure::invalid_identity("a numeric UID without a passwd entry requires a group")
    })?;
    let name = CString::new(user_name.as_str())
        .map_err(|_| LaunchFailure::invalid_identity("user name contains a NUL byte"))?;
    let groups = getgrouplist(&name, Gid::from_raw(primary_gid)).map_err(|error| {
        LaunchFailure::from_io(
            LaunchFailureReason::IdentityNotFound,
            io::Error::from(error),
        )
    })?;
    Ok(Identity {
        uid,
        gid: primary_gid,
        groups,
    })
}

fn read_passwd() -> Result<Vec<PasswdEntry>, LaunchFailure> {
    let content = fs::read_to_string("/etc/passwd")
        .map_err(|error| LaunchFailure::from_io(LaunchFailureReason::IdentityNotFound, error))?;
    Ok(content
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() >= 4).then(|| {
                Some(PasswdEntry {
                    name: fields[0].to_string(),
                    uid: fields[2].parse().ok()?,
                    gid: fields[3].parse().ok()?,
                })
            })?
        })
        .collect())
}

fn resolve_group(selector: &str) -> Result<u32, LaunchFailure> {
    if let Ok(gid) = selector.parse::<u32>() {
        return Ok(gid);
    }
    let content = fs::read_to_string("/etc/group")
        .map_err(|error| LaunchFailure::from_io(LaunchFailureReason::IdentityNotFound, error))?;
    content
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() >= 3 && fields[0] == selector).then(|| fields[2].parse::<u32>().ok())?
        })
        .ok_or_else(|| {
            LaunchFailure::identity_not_found(format!("group `{selector}` was not found"))
        })
}

fn validate_terminal_size(size: &TerminalSize) -> Result<(), LaunchFailure> {
    if !(1..=u32::from(u16::MAX)).contains(&size.columns)
        || !(1..=u32::from(u16::MAX)).contains(&size.rows)
    {
        return Err(LaunchFailure::invalid_spec(
            "PTY columns and rows must be from 1 through 65535",
        ));
    }
    Ok(())
}

struct RunningProcess {
    child: Child,
    guard: ChildGuard,
    process_group: i32,
    stdin: ProcessInput,
    outputs: Vec<(OutputKind, Box<dyn Read + Send>)>,
    pty_resize: Option<File>,
}

enum ProcessInput {
    Null,
    Pipe(Option<ChildStdin>),
    Pty(File),
}

enum InputCommand {
    Data(Vec<u8>),
}

enum ActiveInput {
    Null,
    Pipe(Option<std_mpsc::SyncSender<InputCommand>>),
    Pty(std_mpsc::SyncSender<InputCommand>),
}

#[derive(Clone, Copy)]
enum OutputKind {
    Stdout,
    Stderr,
    Terminal,
}

fn spawn_process(
    plan: ProcessPlan,
    supervisor: &ProcessSupervisor,
) -> Result<RunningProcess, LaunchFailure> {
    let path = plan
        .environment
        .iter()
        .find_map(|(name, value)| (name == "PATH").then_some(value.as_str()))
        .unwrap_or(DEFAULT_PATH);
    let program = resolve_program(&plan.argv[0], path)?;
    let mut command = Command::new(&program);
    command
        .arg0(&plan.argv[0])
        .args(&plan.argv[1..])
        .current_dir(&plan.working_directory)
        .env_clear()
        .envs(plan.environment.iter().map(|(name, value)| (name, value)));
    prepare_identity_child(
        &mut command,
        plan.identity.uid,
        plan.identity.gid,
        plan.identity.groups,
    );

    match plan.stdio {
        ProcessStdio::Pipes { stdin } => {
            command
                .process_group(0)
                .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let (mut child, guard) = supervisor
                .spawn_child(&mut command, "guest process")
                .map_err(LaunchFailure::spawn)?;
            let process_group = child_process_group(&child)?;
            let input = if stdin {
                ProcessInput::Pipe(Some(child.stdin.take().ok_or_else(|| {
                    LaunchFailure::spawn_failed("guest process stdin was not piped")
                })?))
            } else {
                ProcessInput::Null
            };
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| LaunchFailure::spawn_failed("guest process stdout was not piped"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| LaunchFailure::spawn_failed("guest process stderr was not piped"))?;
            Ok(RunningProcess {
                child,
                guard,
                process_group,
                stdin: input,
                outputs: vec![
                    (OutputKind::Stdout, Box::new(stdout)),
                    (OutputKind::Stderr, Box::new(stderr)),
                ],
                pty_resize: None,
            })
        }
        ProcessStdio::Pty { size } => {
            let pty = open_process_pty(size.columns, size.rows, 0, 0).map_err(|error| {
                LaunchFailure::from_io(LaunchFailureReason::SpawnFailed, io::Error::from(error))
            })?;
            let master = File::from(pty.master);
            let reader = master.try_clone().map_err(LaunchFailure::spawn)?;
            let writer = master.try_clone().map_err(LaunchFailure::spawn)?;
            let resize = master.try_clone().map_err(LaunchFailure::spawn)?;
            attach_pty_slave(&mut command, pty.slave).map_err(LaunchFailure::spawn)?;
            prepare_pty_child(&mut command);
            let (child, guard) = supervisor
                .spawn_session_child(&mut command, "guest process PTY")
                .map_err(LaunchFailure::spawn)?;
            let process_group = child_process_group(&child)?;
            Ok(RunningProcess {
                child,
                guard,
                process_group,
                stdin: ProcessInput::Pty(writer),
                outputs: vec![(OutputKind::Terminal, Box::new(reader))],
                pty_resize: Some(resize),
            })
        }
    }
}

fn resolve_program(argv0: &str, path: &str) -> Result<OsString, LaunchFailure> {
    if argv0.contains('/') {
        return Ok(OsString::from(argv0));
    }
    let mut permission_denied = None;
    for directory in path.split(':') {
        let directory = if directory.is_empty() { "." } else { directory };
        let candidate = Path::new(directory).join(argv0);
        match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() && is_executable(&metadata) => {
                return Ok(candidate.into_os_string())
            }
            Ok(metadata) if metadata.is_file() => permission_denied = Some(candidate),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                permission_denied = Some(candidate)
            }
            Err(error) => {
                return Err(LaunchFailure::from_io(
                    LaunchFailureReason::SpawnFailed,
                    error,
                ))
            }
        }
    }
    if let Some(path) = permission_denied {
        return Err(LaunchFailure::new(
            LaunchFailureReason::PermissionDenied,
            format!("command is not executable: {}", path.display()),
        ));
    }
    Err(LaunchFailure::command_not_found(argv0))
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

fn child_process_group(child: &Child) -> Result<i32, LaunchFailure> {
    i32::try_from(child.id())
        .map_err(|_| LaunchFailure::spawn_failed("child PID does not fit in i32"))
}

fn drive_process(
    mut process: RunningProcess,
    mut deferred_control: Option<protocol::v1::GuestProcessInput>,
    mut controls: mpsc::Receiver<protocol::v1::GuestProcessInput>,
    events: EventSender,
    cancellation: watch::Receiver<bool>,
    _execution: ExecutionLease,
) {
    let mut input = start_input_writer(std::mem::replace(&mut process.stdin, ProcessInput::Null));
    let disconnected = Arc::new(AtomicBool::new(false));
    let readers = process
        .outputs
        .drain(..)
        .filter_map(|(kind, reader)| {
            spawn_output_reader(kind, reader, events.clone(), Arc::clone(&disconnected))
        })
        .collect::<Vec<_>>();

    let status = loop {
        if *cancellation.borrow() || disconnected.load(Ordering::Acquire) {
            terminate_and_reap(&mut process.child, process.process_group);
            break process.child.wait().ok();
        }
        let control = deferred_control
            .take()
            .map_or_else(|| controls.try_recv(), Ok);
        match control {
            Ok(control) => {
                if let Err(status) = apply_control(&mut process, &mut input, control) {
                    let _ = events.blocking_send(Err(status));
                    terminate_and_reap(&mut process.child, process.process_group);
                    break process.child.wait().ok();
                }
                continue;
            }
            Err(mpsc::error::TryRecvError::Disconnected)
            | Err(mpsc::error::TryRecvError::Empty) => {}
        }
        match process.child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                let _ = events.blocking_send(Err(protocol::detailed_status(Status::internal(
                    format!("wait for guest process: {error}"),
                ))));
                terminate_and_reap(&mut process.child, process.process_group);
                break process.child.wait().ok();
            }
        }
    };
    drop(input);
    for reader in readers {
        let _ = reader.join();
    }
    drop(process.guard);

    if disconnected.load(Ordering::Acquire) || *cancellation.borrow() {
        return;
    }
    if let Some(status) = status {
        let _ = events.blocking_send(Ok(terminal_event(status)));
    }
}

fn start_input_writer(input: ProcessInput) -> ActiveInput {
    match input {
        ProcessInput::Null => ActiveInput::Null,
        ProcessInput::Pipe(writer) => {
            let Some(writer) = writer else {
                return ActiveInput::Pipe(None);
            };
            ActiveInput::Pipe(Some(spawn_input_writer(writer)))
        }
        ProcessInput::Pty(writer) => ActiveInput::Pty(spawn_input_writer(writer)),
    }
}

fn spawn_input_writer<W>(mut writer: W) -> std_mpsc::SyncSender<InputCommand>
where
    W: Write + Send + 'static,
{
    let (sender, receiver) = std_mpsc::sync_channel(QUEUE_CAPACITY);
    let _ = thread::Builder::new()
        .name("silo-guest-process-stdin".to_string())
        .spawn(move || {
            for command in receiver {
                match command {
                    InputCommand::Data(data) => {
                        if let Err(error) = writer.write_all(&data) {
                            if error.kind() != io::ErrorKind::BrokenPipe {
                                tracing::debug!(error = %error, "guest process stdin write failed");
                            }
                            return;
                        }
                    }
                }
            }
        });
    sender
}

fn spawn_output_reader(
    kind: OutputKind,
    mut reader: Box<dyn Read + Send>,
    events: EventSender,
    disconnected: Arc<AtomicBool>,
) -> Option<thread::JoinHandle<()>> {
    let reader_disconnected = Arc::clone(&disconnected);
    match thread::Builder::new()
        .name("silo-guest-process-output".to_string())
        .spawn(move || {
            let mut buffer = vec![0; protocol::CHUNK_64_KIB];
            loop {
                let read = match reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        tracing::debug!(error = %error, "guest process output read failed");
                        return;
                    }
                };
                let event = match kind {
                    OutputKind::Stdout => Event::Stdout(GuestProcessStdout {
                        data: Bytes::copy_from_slice(&buffer[..read]),
                    }),
                    OutputKind::Stderr => Event::Stderr(GuestProcessStderr {
                        data: Bytes::copy_from_slice(&buffer[..read]),
                    }),
                    OutputKind::Terminal => Event::TerminalOutput(GuestProcessTerminalOutput {
                        data: Bytes::copy_from_slice(&buffer[..read]),
                    }),
                };
                if events
                    .blocking_send(Ok(GuestProcessEvent { event: Some(event) }))
                    .is_err()
                {
                    reader_disconnected.store(true, Ordering::Release);
                    return;
                }
            }
        }) {
        Ok(reader) => Some(reader),
        Err(error) => {
            tracing::warn!(error = %error, "failed to spawn guest process output reader");
            disconnected.store(true, Ordering::Release);
            None
        }
    }
}

fn apply_control(
    process: &mut RunningProcess,
    input: &mut ActiveInput,
    control: protocol::v1::GuestProcessInput,
) -> Result<(), Status> {
    match control.message {
        Some(Message::StdinData(StdinData { data })) => write_stdin(input, data),
        Some(Message::CloseStdin(_)) => close_stdin(input),
        Some(Message::ResizePty(resize)) => resize_pty(process, resize),
        Some(Message::SignalProcess(signal)) => signal_process(process, signal),
        Some(Message::Start(_)) => Err(invalid_request(
            "StartGuestProcess is only valid as the first Execute request",
        )),
        None => Err(invalid_request("Execute request message is required")),
    }
}

fn write_stdin(input: &mut ActiveInput, data: Bytes) -> Result<(), Status> {
    if data.len() > protocol::CHUNK_64_KIB {
        return Err(invalid_request("stdin data exceeds 64 KiB"));
    }
    let sender = match input {
        ActiveInput::Pipe(Some(sender)) => sender,
        ActiveInput::Pipe(None) => {
            return Err(protocol::detailed_status(Status::failed_precondition(
                "stdin is already closed",
            )));
        }
        ActiveInput::Pty(sender) => sender,
        ActiveInput::Null => {
            return Err(protocol::detailed_status(Status::failed_precondition(
                "this process has no stdin pipe",
            )));
        }
    };
    sender
        .try_send(InputCommand::Data(data.to_vec()))
        .map_err(|error| match error {
            std_mpsc::TrySendError::Full(_) => protocol::status_with_error(
                tonic::Code::ResourceExhausted,
                protocol::v1::ErrorCode::ResourceExhausted,
                "guest process stdin queue is full",
                None,
            ),
            std_mpsc::TrySendError::Disconnected(_) => protocol::detailed_status(
                Status::failed_precondition("guest process stdin is closed"),
            ),
        })
}

fn close_stdin(input: &mut ActiveInput) -> Result<(), Status> {
    match input {
        ActiveInput::Pipe(sender @ Some(_)) => {
            drop(sender.take());
            Ok(())
        }
        ActiveInput::Pipe(None) => Err(protocol::detailed_status(Status::failed_precondition(
            "stdin is already closed",
        ))),
        ActiveInput::Pty(_) => Err(protocol::detailed_status(Status::failed_precondition(
            "PTY stdin cannot be half-closed",
        ))),
        ActiveInput::Null => Err(protocol::detailed_status(Status::failed_precondition(
            "this process has no stdin pipe",
        ))),
    }
}

fn resize_pty(process: &mut RunningProcess, resize: ResizePty) -> Result<(), Status> {
    let size = resize
        .size
        .ok_or_else(|| invalid_request("PTY resize size is required"))?;
    validate_terminal_size(&size).map_err(|failure| invalid_request(&failure.message))?;
    let master = process.pty_resize.as_ref().ok_or_else(|| {
        protocol::detailed_status(Status::failed_precondition("this process has no PTY"))
    })?;
    resize_process_pty(master, size.columns, size.rows, 0, 0).map_err(|error| {
        protocol::detailed_status(Status::internal(format!("resize PTY: {error}")))
    })
}

fn signal_process(process: &RunningProcess, signal: SignalProcess) -> Result<(), Status> {
    let raw_signal = signal
        .signal
        .ok_or_else(|| invalid_request("a positive process signal is required"))?;
    let raw_signal =
        i32::try_from(raw_signal).map_err(|_| invalid_request("process signal is out of range"))?;
    let signal = Signal::try_from(raw_signal)
        .map_err(|_| invalid_request("a valid Linux process signal is required"))?;
    signal_process_group(process.process_group, signal);
    Ok(())
}

fn terminate_and_reap(child: &mut Child, process_group: i32) {
    signal_process_group(process_group, Signal::SIGTERM);
    let deadline = Instant::now() + DISCONNECT_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => thread::sleep(POLL_INTERVAL),
        }
    }
    signal_process_group(process_group, Signal::SIGKILL);
    let _ = child.wait();
}

fn terminal_event(status: ExitStatus) -> GuestProcessEvent {
    if let Some(code) = status.code() {
        return GuestProcessEvent {
            event: Some(Event::Exited(GuestProcessExited {
                code: u32::try_from(code).ok(),
            })),
        };
    }
    GuestProcessEvent {
        event: Some(Event::Signaled(GuestProcessSignaled {
            signal: status
                .signal()
                .and_then(|signal| u32::try_from(signal).ok()),
        })),
    }
}

#[derive(Debug)]
struct LaunchFailure {
    reason: LaunchFailureReason,
    message: String,
}

impl LaunchFailure {
    fn invalid_spec(message: impl Into<String>) -> Self {
        Self::new(LaunchFailureReason::InvalidProcessSpec, message)
    }
    fn invalid_identity(message: impl Into<String>) -> Self {
        Self::new(LaunchFailureReason::InvalidIdentity, message)
    }
    fn identity_not_found(message: impl Into<String>) -> Self {
        Self::new(LaunchFailureReason::IdentityNotFound, message)
    }
    fn command_not_found(command: &str) -> Self {
        Self::new(
            LaunchFailureReason::CommandNotFound,
            format!("command not found: {command}"),
        )
    }
    fn working_directory_not_found(path: &Path) -> Self {
        Self::new(
            LaunchFailureReason::WorkingDirectoryNotFound,
            format!("working directory does not exist: {}", path.display()),
        )
    }
    fn working_directory_not_directory(path: &Path) -> Self {
        Self::new(
            LaunchFailureReason::WorkingDirectoryNotDirectory,
            format!("working directory is not a directory: {}", path.display()),
        )
    }
    fn spawn_failed(message: impl Into<String>) -> Self {
        Self::new(LaunchFailureReason::SpawnFailed, message)
    }
    fn spawn(error: io::Error) -> Self {
        let reason = match error.kind() {
            io::ErrorKind::NotFound => LaunchFailureReason::CommandNotFound,
            io::ErrorKind::PermissionDenied => LaunchFailureReason::PermissionDenied,
            io::ErrorKind::Interrupted => LaunchFailureReason::CancelledBeforeStart,
            _ => LaunchFailureReason::SpawnFailed,
        };
        Self::from_io(reason, error)
    }
    fn from_io(reason: LaunchFailureReason, error: io::Error) -> Self {
        Self::new(reason, error.to_string())
    }
    fn new(reason: LaunchFailureReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
    fn event(self) -> GuestProcessEvent {
        GuestProcessEvent {
            event: Some(Event::LaunchFailed(GuestProcessLaunchFailed {
                reason: Some(self.reason as i32),
                message: Some(self.message),
            })),
        }
    }
}

fn log_launch_failure(execution_id: Uuid, failure: &LaunchFailure) {
    tracing::warn!(
        execution_id = %execution_id,
        reason = ?failure.reason,
        detail = %failure.message,
        "guest process launch failed"
    );
}

fn invalid_request(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::invalid_argument(message.into()))
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use nix::unistd::{getgid, getuid};
    use protocol::v1::guest_process_event::Event;
    use protocol::v1::guest_process_input::Message;
    use protocol::v1::{
        EnvironmentVariable, GuestProcessInput, LaunchFailureReason, PipeStdio, ProcessSpec,
        PtyStdio, ResizePty, SignalProcess, StdinData, TerminalSize,
    };
    use tokio::sync::{mpsc, watch};

    use crate::guest_process::{
        drive_process, resolve_identity, spawn_process, ExecutionLease, ProcessPlan, QUEUE_CAPACITY,
    };
    use crate::pid1::ProcessSupervisor;

    fn privileged() -> bool {
        getuid().is_root()
    }

    fn current_identity() -> String {
        format!("{}:{}", getuid().as_raw(), getgid().as_raw())
    }

    fn pipes(argv: &[&str], stdin: bool) -> ProcessSpec {
        ProcessSpec {
            argv: argv.iter().map(|value| (*value).to_string()).collect(),
            environment: Vec::new(),
            working_directory: None,
            user: Some(current_identity()),
            stdio: Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio {
                stdin,
            })),
        }
    }

    fn pty(argv: &[&str], columns: u32, rows: u32) -> ProcessSpec {
        ProcessSpec {
            argv: argv.iter().map(|value| (*value).to_string()).collect(),
            environment: Vec::new(),
            working_directory: None,
            user: Some(current_identity()),
            stdio: Some(protocol::v1::process_spec::Stdio::Pty(PtyStdio {
                initial_size: Some(TerminalSize { columns, rows }),
                terminal: None,
            })),
        }
    }

    fn start(
        spec: ProcessSpec,
    ) -> (
        mpsc::Sender<GuestProcessInput>,
        mpsc::Receiver<Result<protocol::v1::GuestProcessEvent, tonic::Status>>,
        thread::JoinHandle<()>,
    ) {
        let plan = ProcessPlan::from_spec(spec).expect("valid test process plan");
        let running = spawn_process(plan, &ProcessSupervisor::default()).expect("spawn test child");
        let (controls, control_receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (events, event_receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (_cancel, cancel_receiver) = watch::channel(false);
        let active = Arc::new(Mutex::new(Default::default()));
        let permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .expect("acquire test capacity");
        let lease = ExecutionLease::acquire(active, uuid::Uuid::new_v4(), permit)
            .expect("acquire test execution");
        let task = thread::spawn(move || {
            drive_process(
                running,
                None,
                control_receiver,
                events,
                cancel_receiver,
                lease,
            )
        });
        (controls, event_receiver, task)
    }

    async fn collect(
        receiver: &mut mpsc::Receiver<Result<protocol::v1::GuestProcessEvent, tonic::Status>>,
    ) -> Vec<protocol::v1::GuestProcessEvent> {
        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            events.push(event.expect("process event"));
        }
        events
    }

    #[test]
    fn active_execution_ids_reject_collisions_until_the_owner_finishes() {
        let active = Arc::new(Mutex::new(Default::default()));
        let execution_id = uuid::Uuid::new_v4();
        let capacity = Arc::new(tokio::sync::Semaphore::new(2));
        let owner = ExecutionLease::acquire(
            Arc::clone(&active),
            execution_id,
            Arc::clone(&capacity)
                .try_acquire_owned()
                .expect("first test capacity"),
        )
        .expect("acquire first owner");
        assert!(ExecutionLease::acquire(
            Arc::clone(&active),
            execution_id,
            Arc::clone(&capacity)
                .try_acquire_owned()
                .expect("second test capacity"),
        )
        .is_err());
        drop(owner);
        assert!(ExecutionLease::acquire(
            active,
            execution_id,
            capacity
                .try_acquire_owned()
                .expect("replacement test capacity"),
        )
        .is_ok());
    }

    #[test]
    fn process_specs_require_stdio_and_do_not_override_explicit_term() {
        let mut missing_stdio = pipes(&["/bin/true"], false);
        missing_stdio.stdio = None;
        assert!(ProcessPlan::from_spec(missing_stdio).is_err());

        let mut explicit_term = pty(&["/bin/true"], 80, 24);
        explicit_term.environment.push(EnvironmentVariable {
            name: "TERM".to_string(),
            value: "screen-256color".to_string(),
        });
        let plan = ProcessPlan::from_spec(explicit_term).expect("valid explicit TERM");
        let terms = plan
            .environment
            .iter()
            .filter(|(name, _)| name == "TERM")
            .collect::<Vec<_>>();
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].1, "screen-256color");
    }

    #[test]
    fn missing_identity_names_the_requested_user() {
        let failure = match resolve_identity("silo-user-that-cannot-exist") {
            Ok(_) => panic!("test user unexpectedly exists"),
            Err(failure) => failure,
        };

        assert_eq!(failure.reason, LaunchFailureReason::IdentityNotFound);
        assert_eq!(
            failure.message,
            "user `silo-user-that-cannot-exist` was not found"
        );
    }

    #[test]
    fn only_valid_signals_can_cancel_a_pending_launch() {
        let signal = GuestProcessInput {
            message: Some(Message::SignalProcess(SignalProcess {
                signal: Some(nix::libc::SIGTERM as u32),
            })),
        };
        assert!(matches!(
            crate::guest_process::prestart_control(signal),
            Ok(crate::guest_process::PrestartControl::Signal)
        ));

        let stdin = GuestProcessInput {
            message: Some(Message::StdinData(StdinData {
                data: bytes::Bytes::new(),
            })),
        };
        assert!(matches!(
            crate::guest_process::prestart_control(stdin),
            Ok(crate::guest_process::PrestartControl::Deferred(_))
        ));
    }

    #[tokio::test]
    async fn executes_exact_argv_with_literal_empty_quotes_and_metacharacters() {
        if !privileged() {
            return;
        }
        let (controls, mut events, task) = start(pipes(
            &[
                "/usr/bin/printf",
                "%s|%s|%s",
                "",
                "quoted value",
                "$(not-a-shell)",
            ],
            false,
        ));
        drop(controls);
        let events = collect(&mut events).await;
        task.join().expect("driver thread");
        let stdout = events.iter().find_map(|event| match &event.event {
            Some(Event::Stdout(stdout)) => Some(stdout.data.clone()),
            _ => None,
        });
        assert_eq!(
            stdout.as_deref(),
            Some(b"|quoted value|$(not-a-shell)".as_slice())
        );
        assert!(events
            .iter()
            .any(|event| matches!(&event.event, Some(Event::Exited(_)))));
    }

    #[tokio::test]
    async fn clears_ambient_environment_defaults_path_and_honors_working_directory() {
        if !privileged() {
            return;
        }
        let mut spec = pipes(&["/usr/bin/env"], false);
        spec.environment = vec![EnvironmentVariable {
            name: "ONLY_THIS".to_string(),
            value: "present".to_string(),
        }];
        let (controls, mut events, task) = start(spec);
        drop(controls);
        let text = collect(&mut events)
            .await
            .into_iter()
            .find_map(|event| match event.event {
                Some(Event::Stdout(stdout)) => String::from_utf8(stdout.data.to_vec()).ok(),
                _ => None,
            })
            .expect("environment output");
        task.join().expect("driver thread");
        assert!(text.contains("ONLY_THIS=present\n"));
        assert!(
            text.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
        );
        assert!(!text.contains("HOME="));

        let mut cwd = pipes(&["/bin/pwd"], false);
        cwd.working_directory = Some("/tmp".to_string());
        let (controls, mut events, task) = start(cwd);
        drop(controls);
        let output = collect(&mut events)
            .await
            .into_iter()
            .find_map(|event| match event.event {
                Some(Event::Stdout(stdout)) => Some(stdout.data),
                _ => None,
            })
            .expect("pwd output");
        task.join().expect("driver thread");
        assert_eq!(output.as_ref(), b"/tmp\n".as_slice());
    }

    #[tokio::test]
    async fn keeps_pipe_streams_separate_and_requires_explicit_eof() {
        if !privileged() {
            return;
        }
        let (controls, mut events, task) = start(pipes(
            &[
                "/bin/sh",
                "-c",
                "read line; printf 'out:%s' \"$line\"; printf 'err:%s' \"$line\" >&2",
            ],
            true,
        ));
        controls
            .send(GuestProcessInput {
                message: Some(Message::StdinData(StdinData {
                    data: b"value\n".as_slice().into(),
                })),
            })
            .await
            .expect("stdin data");
        controls
            .send(GuestProcessInput {
                message: Some(Message::CloseStdin(protocol::v1::CloseStdin {})),
            })
            .await
            .expect("explicit EOF");
        drop(controls);
        let events = collect(&mut events).await;
        task.join().expect("driver thread");
        assert!(events.iter().any(|event| matches!(
            &event.event,
            Some(Event::Stdout(output)) if output.data == b"out:value".as_slice()
        )));
        assert!(events.iter().any(|event| matches!(
            &event.event,
            Some(Event::Stderr(output)) if output.data == b"err:value".as_slice()
        )));

        let (controls, mut events, task) = start(pipes(&["/bin/cat"], true));
        controls
            .send(GuestProcessInput {
                message: Some(Message::StdinData(StdinData {
                    data: b"not EOF".as_slice().into(),
                })),
            })
            .await
            .expect("cat stdin data");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        controls
            .send(GuestProcessInput {
                message: Some(Message::CloseStdin(protocol::v1::CloseStdin {})),
            })
            .await
            .expect("cat explicit EOF");
        drop(controls);
        let events = collect(&mut events).await;
        task.join().expect("cat driver thread");
        assert!(events
            .iter()
            .any(|event| matches!(&event.event, Some(Event::Exited(_)))));
    }

    #[tokio::test]
    async fn pty_combines_output_supports_resize_and_signal_is_terminal_signal() {
        if !privileged() {
            return;
        }
        let (controls, mut events, task) = start(pty(
            &[
                "/bin/sh",
                "-c",
                "read line; stty size; printf out; printf err >&2; read second",
            ],
            80,
            24,
        ));
        controls
            .send(GuestProcessInput {
                message: Some(Message::ResizePty(ResizePty {
                    size: Some(TerminalSize {
                        columns: 120,
                        rows: 40,
                    }),
                })),
            })
            .await
            .expect("resize PTY");
        controls
            .send(GuestProcessInput {
                message: Some(Message::StdinData(StdinData {
                    data: b"go\n".as_slice().into(),
                })),
            })
            .await
            .expect("PTY input");
        let mut all_events = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .expect("PTY output timeout")
                .expect("PTY output event")
                .expect("valid PTY event");
            all_events.push(event);
            let observed = all_events
                .iter()
                .filter_map(|event| match &event.event {
                    Some(Event::TerminalOutput(output)) => Some(output.data.as_ref()),
                    _ => None,
                })
                .flatten()
                .copied()
                .collect::<Vec<_>>();
            if String::from_utf8_lossy(&observed).contains("40 120") {
                break;
            }
        }
        controls
            .send(GuestProcessInput {
                message: Some(Message::SignalProcess(SignalProcess {
                    signal: Some(nix::libc::SIGTERM as u32),
                })),
            })
            .await
            .expect("terminate process group");
        drop(controls);
        all_events.extend(collect(&mut events).await);
        task.join().expect("driver thread");
        assert!(all_events
            .iter()
            .any(|event| matches!(&event.event, Some(Event::TerminalOutput(_)))));
        let terminal_output = all_events
            .iter()
            .filter_map(|event| match &event.event {
                Some(Event::TerminalOutput(output)) => Some(output.data.as_ref()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let terminal_output = String::from_utf8_lossy(&terminal_output);
        assert!(terminal_output.contains("40 120"));
        assert!(terminal_output.contains("out"));
        assert!(terminal_output.contains("err"));
        assert!(all_events.iter().any(|event| matches!(
            &event.event,
            Some(Event::Signaled(signal)) if signal.signal == Some(nix::libc::SIGTERM as u32)
        )));
    }
}

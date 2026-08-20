use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::v1::execute_input::Message as ExecuteMessage;
use protocol::v1::execution_event::Event as ExecutionWireEvent;
use protocol::v1::{
    CloseStdin, EnvironmentVariable, ExecuteInput, ExecutionEvent as WireExecutionEvent, PipeStdio,
    ProcessSpec, PtyStdio, ResizePty, SignalProcess, StartExecution, StdinData, TerminalSize,
};
use russh::client::Msg as ClientMsg;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, ChannelWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::machine::{Machine, MachineRef, MachineUserConfig};
use crate::runtime::core::RuntimeStatus;
use crate::store::models::MachineRuntimeState;
use crate::LibVmError;

const DEFAULT_TERM: &str = "xterm-256color";
const DEFAULT_ATTACH_DETACH_KEY: u8 = 0x1d;
const DEFAULT_LOGIN_SHELL_SCRIPT: &str = "exec \"${SHELL:-/bin/bash}\" -l || exec /bin/sh";
const EXECUTION_REQUEST_QUEUE_CAPACITY: usize = 64;
const EXECUTION_CHUNK_SIZE: usize = protocol::CHUNK_64_KIB;
const SSH_HANDSHAKE_READY_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Options for one structured guest process execution.
#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Vec<(String, String)>,
    pub timeout: Option<Duration>,
    pub stdin: StdinMode,
    pub tty: bool,
    pub term: String,
}

#[derive(Debug, Default)]
pub struct ExecutionOptionsBuilder {
    options: ExecutionOptions,
}

/// Structured process stdin mode.
#[derive(Debug, Clone, Default)]
pub enum StdinMode {
    #[default]
    Null,
    Pipe,
    Bytes(Vec<u8>),
}

/// The exact terminal result reported by vmmon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionResult {
    Exited { code: Option<u32> },
    Signaled { signal: Option<u32> },
    LaunchFailed(ExecutionLaunchFailure),
    Lost(ExecutionLost),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLaunchFailure {
    pub reason: ExecutionLaunchFailureReason,
    pub message: Option<String>,
}

impl std::fmt::Display for ExecutionLaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "launch failed ({:?})", self.reason)?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionLaunchFailureReason {
    Unspecified,
    CommandNotFound,
    InvalidProcessSpec,
    WorkingDirectoryNotFound,
    WorkingDirectoryNotDirectory,
    InvalidIdentity,
    IdentityNotFound,
    PermissionDenied,
    SpawnFailed,
    CancelledBeforeStart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLost {
    pub reason: ExecutionLostReason,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionLostReason {
    Unspecified,
    AgentInstanceReplaced,
    AgentBootReplaced,
    AgentUnavailable,
    GuestStreamLost,
    VmStopped,
    VmmonExited,
}

/// One event from the host execution service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEvent {
    Accepted,
    Started,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    TerminalOutput(Vec<u8>),
    Terminal(ExecutionResult),
}

/// Captured structured execution output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    result: ExecutionResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    terminal_output: Vec<u8>,
}

impl ExecutionOutput {
    pub fn result(&self) -> &ExecutionResult {
        &self.result
    }
    pub fn stdout_bytes(&self) -> &[u8] {
        &self.stdout
    }
    pub fn stderr_bytes(&self) -> &[u8] {
        &self.stderr
    }
    pub fn terminal_output_bytes(&self) -> &[u8] {
        &self.terminal_output
    }
    pub fn stdout(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stdout.clone())
    }
    pub fn stderr(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stderr.clone())
    }
    pub fn terminal_output(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.terminal_output.clone())
    }
}

/// A live bidirectional structured execution call.
pub struct ExecutionSession {
    reference: String,
    requests: Arc<Mutex<Option<mpsc::Sender<ExecuteInput>>>>,
    input_open: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    input_order: Arc<AsyncMutex<()>>,
    request_closed: Arc<watch::Sender<bool>>,
    pipe_stdin: bool,
    events: Option<tonic::Streaming<WireExecutionEvent>>,
}

/// Cloneable request-side controls for a live structured execution.
#[derive(Clone)]
pub struct ExecutionControl {
    reference: String,
    requests: Arc<Mutex<Option<mpsc::Sender<ExecuteInput>>>>,
    input_open: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    input_order: Arc<AsyncMutex<()>>,
    request_closed: Arc<watch::Sender<bool>>,
    pipe_stdin: bool,
}

/// Cloneable writer for a structured execution's stdin or PTY input.
#[derive(Clone)]
pub struct ExecutionStdin {
    reference: String,
    requests: Arc<Mutex<Option<mpsc::Sender<ExecuteInput>>>>,
    input_open: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    input_order: Arc<AsyncMutex<()>>,
    request_closed: Arc<watch::Sender<bool>>,
    pipe_stdin: bool,
}

impl ExecutionSession {
    /// Returns controls that remain usable while another task receives events.
    pub fn control(&self) -> ExecutionControl {
        ExecutionControl {
            reference: self.reference.clone(),
            requests: Arc::clone(&self.requests),
            input_open: Arc::clone(&self.input_open),
            started: Arc::clone(&self.started),
            input_order: Arc::clone(&self.input_order),
            request_closed: Arc::clone(&self.request_closed),
            pipe_stdin: self.pipe_stdin,
        }
    }

    /// Returns a stdin writer while the request half remains open.
    pub fn stdin(&self) -> Option<ExecutionStdin> {
        self.control().stdin()
    }
    pub async fn recv(&mut self) -> Result<Option<ExecutionEvent>, LibVmError> {
        let Some(events) = self.events.as_mut() else {
            return Ok(None);
        };
        match events.message().await {
            Ok(Some(wire)) => {
                let event = execution_event_from_wire(wire);
                mark_execution_started(&event, &self.started);
                if matches!(event, ExecutionEvent::Terminal(_)) {
                    self.close_requests();
                    self.events = None;
                }
                Ok(Some(event))
            }
            Ok(None) => {
                self.events = None;
                self.close_requests();
                Ok(None)
            }
            Err(error) => {
                self.events = None;
                self.close_requests();
                if caller_status(error.code()) {
                    Err(guest_session_error(
                        &self.reference,
                        format!("execution request failed: {error}"),
                    ))
                } else {
                    Ok(Some(ExecutionEvent::Terminal(ExecutionResult::Lost(
                        ExecutionLost {
                            reason: ExecutionLostReason::GuestStreamLost,
                            message: Some(format!("execution event stream failed: {error}")),
                        },
                    ))))
                }
            }
        }
    }

    /// Writes bytes to the process stdin or PTY.
    pub async fn write_stdin(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.control().write_stdin(data).await
    }

    /// Sends EOF to the process stdin while keeping the execution call open.
    pub async fn close_stdin(&self) -> Result<(), LibVmError> {
        self.control().close_stdin().await
    }

    /// Resizes the process PTY.
    pub async fn resize_pty(&self, rows: u16, columns: u16) -> Result<(), LibVmError> {
        self.control().resize_pty(rows, columns).await
    }

    /// Delivers a positive Linux signal number to the process group.
    pub async fn signal(&self, signal: u32) -> Result<(), LibVmError> {
        self.control().signal(signal).await
    }

    /// Finishes the request half of the bidirectional call.
    pub fn close_requests(&self) {
        self.control().close_requests();
    }

    /// Cancels the complete bidirectional call, including the response stream.
    pub fn cancel(&mut self) {
        self.close_requests();
        self.events = None;
    }

    pub async fn wait(&mut self) -> Result<ExecutionResult, LibVmError> {
        while let Some(event) = self.recv().await? {
            if let ExecutionEvent::Terminal(result) = event {
                return Ok(result);
            }
        }
        Err(guest_session_error(
            &self.reference,
            "execution ended without a terminal result",
        ))
    }

    pub async fn collect(&mut self) -> Result<ExecutionOutput, LibVmError> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut terminal_output = Vec::new();
        while let Some(event) = self.recv().await? {
            match event {
                ExecutionEvent::Stdout(data) => stdout.extend(data),
                ExecutionEvent::Stderr(data) => stderr.extend(data),
                ExecutionEvent::TerminalOutput(data) => terminal_output.extend(data),
                ExecutionEvent::Terminal(result) => {
                    return Ok(ExecutionOutput {
                        result,
                        stdout,
                        stderr,
                        terminal_output,
                    });
                }
                ExecutionEvent::Accepted | ExecutionEvent::Started => {}
            }
        }
        Err(guest_session_error(
            &self.reference,
            "execution ended without a terminal result",
        ))
    }
}

impl ExecutionControl {
    /// Returns a stdin writer while the request half remains open.
    pub fn stdin(&self) -> Option<ExecutionStdin> {
        self.requests.lock().ok()?.as_ref()?;
        if !self.started.load(Ordering::Acquire) || !self.input_open.load(Ordering::Acquire) {
            return None;
        }
        Some(ExecutionStdin {
            reference: self.reference.clone(),
            requests: Arc::clone(&self.requests),
            input_open: Arc::clone(&self.input_open),
            started: Arc::clone(&self.started),
            input_order: Arc::clone(&self.input_order),
            request_closed: Arc::clone(&self.request_closed),
            pipe_stdin: self.pipe_stdin,
        })
    }

    /// Writes bytes to the process stdin or PTY.
    pub async fn write_stdin(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.send_stdin_data(data.into()).await
    }

    /// Sends EOF to pipe stdin while leaving the response stream open.
    pub async fn close_stdin(&self) -> Result<(), LibVmError> {
        if !self.pipe_stdin {
            return Err(guest_session_error(
                &self.reference,
                "explicit EOF is only valid for pipe stdin",
            ));
        }
        let _order = self.input_order.lock().await;
        self.ensure_started()?;
        if !self.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.reference,
                "execution input is closed",
            ));
        }
        self.send(ExecuteMessage::CloseStdin(CloseStdin {})).await?;
        self.input_open.store(false, Ordering::Release);
        Ok(())
    }

    /// Resizes the process PTY.
    pub async fn resize_pty(&self, rows: u16, columns: u16) -> Result<(), LibVmError> {
        self.ensure_started()?;
        self.send(ExecuteMessage::ResizePty(ResizePty {
            size: Some(TerminalSize {
                columns: u32::from(columns),
                rows: u32::from(rows),
            }),
        }))
        .await
    }

    /// Delivers a Linux signal number to the process group.
    pub async fn signal(&self, signal: u32) -> Result<(), LibVmError> {
        if !(1..=64).contains(&signal) {
            return Err(guest_session_error(
                &self.reference,
                "signal must be a Linux signal number from 1 through 64",
            ));
        }
        if !self.started.load(Ordering::Acquire) {
            self.close_requests();
            return Ok(());
        }
        self.send(ExecuteMessage::SignalProcess(SignalProcess {
            signal: Some(signal),
        }))
        .await
    }

    /// Finishes the request half without closing process stdin.
    pub fn close_requests(&self) {
        self.request_closed.send_replace(true);
        if let Ok(mut requests) = self.requests.lock() {
            requests.take();
        }
        self.input_open.store(false, Ordering::Release);
    }

    async fn send(&self, message: ExecuteMessage) -> Result<(), LibVmError> {
        let requests = self
            .requests
            .lock()
            .map_err(|_| {
                guest_session_error(&self.reference, "execution request lock is poisoned")
            })?
            .clone();
        let Some(requests) = requests else {
            return Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            ));
        };
        let mut request_closed = self.request_closed.subscribe();
        if *request_closed.borrow() {
            return Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            ));
        }
        tokio::select! {
            biased;
            _ = request_closed.changed() => Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            )),
            result = requests.send(ExecuteInput { message: Some(message) }) => result.map_err(|_| {
                guest_session_error(&self.reference, "execution request stream is closed")
            }),
        }
    }

    async fn send_stdin_data(&self, data: Vec<u8>) -> Result<(), LibVmError> {
        let _order = self.input_order.lock().await;
        self.ensure_started()?;
        if !self.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.reference,
                "execution input is closed",
            ));
        }
        if data.is_empty() {
            return self
                .send(ExecuteMessage::StdinData(StdinData {
                    data: Vec::new().into(),
                }))
                .await;
        }
        for chunk in data.chunks(EXECUTION_CHUNK_SIZE) {
            self.send(ExecuteMessage::StdinData(StdinData {
                data: chunk.to_vec().into(),
            }))
            .await?;
        }
        Ok(())
    }

    fn ensure_started(&self) -> Result<(), LibVmError> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(guest_session_error(
            &self.reference,
            "execution has not started",
        ))
    }
}

impl ExecutionStdin {
    pub async fn write(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        let _order = self.input_order.lock().await;
        self.ensure_started()?;
        if !self.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.reference,
                "execution input is closed",
            ));
        }
        let data = data.into();
        if data.is_empty() {
            return self
                .send(ExecuteMessage::StdinData(StdinData {
                    data: Vec::new().into(),
                }))
                .await;
        }
        for chunk in data.chunks(EXECUTION_CHUNK_SIZE) {
            self.send(ExecuteMessage::StdinData(StdinData {
                data: chunk.to_vec().into(),
            }))
            .await?;
        }
        Ok(())
    }

    pub async fn close(&self) -> Result<(), LibVmError> {
        if !self.pipe_stdin {
            return Err(guest_session_error(
                &self.reference,
                "explicit EOF is only valid for pipe stdin",
            ));
        }
        let _order = self.input_order.lock().await;
        self.ensure_started()?;
        if !self.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.reference,
                "execution input is closed",
            ));
        }
        self.send(ExecuteMessage::CloseStdin(CloseStdin {})).await?;
        self.input_open.store(false, Ordering::Release);
        Ok(())
    }

    async fn send(&self, message: ExecuteMessage) -> Result<(), LibVmError> {
        let requests = self
            .requests
            .lock()
            .map_err(|_| {
                guest_session_error(&self.reference, "execution request lock is poisoned")
            })?
            .clone();
        let Some(requests) = requests else {
            return Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            ));
        };
        let mut request_closed = self.request_closed.subscribe();
        if *request_closed.borrow() {
            return Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            ));
        }
        tokio::select! {
            biased;
            _ = request_closed.changed() => Err(guest_session_error(
                &self.reference,
                "execution request stream is closed",
            )),
            result = requests.send(ExecuteInput { message: Some(message) }) => result.map_err(|_| {
                guest_session_error(&self.reference, "execution request stream is closed")
            }),
        }
    }

    fn ensure_started(&self) -> Result<(), LibVmError> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(guest_session_error(
            &self.reference,
            "execution has not started",
        ))
    }
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            cwd: None,
            user: None,
            env: Vec::new(),
            timeout: None,
            stdin: StdinMode::Null,
            tty: false,
            term: DEFAULT_TERM.to_string(),
        }
    }
}

impl ExecutionOptionsBuilder {
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.options
            .env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }
    pub fn stdin_null(mut self) -> Self {
        self.options.stdin = StdinMode::Null;
        self
    }
    pub fn stdin_pipe(mut self) -> Self {
        self.options.stdin = StdinMode::Pipe;
        self
    }
    pub fn stdin_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin = StdinMode::Bytes(data.into());
        self
    }
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }
    pub fn build(self) -> ExecutionOptions {
        self.options
    }
}

/// SSH-only shell attachment options. Agent forwarding is intentionally kept here.
#[derive(Debug, Clone)]
pub struct SshShellOptions {
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Vec<(String, String)>,
    pub term: String,
    pub detach_keys: Option<String>,
    pub forward_agent: bool,
    best_effort_cwd: bool,
}

#[derive(Debug, Default)]
pub struct SshShellOptionsBuilder {
    options: SshShellOptions,
}

impl Default for SshShellOptions {
    fn default() -> Self {
        Self {
            cwd: None,
            user: None,
            env: Vec::new(),
            term: std::env::var("TERM").unwrap_or_else(|_| DEFAULT_TERM.to_string()),
            detach_keys: None,
            forward_agent: false,
            best_effort_cwd: false,
        }
    }
}
impl SshShellOptionsBuilder {
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }
    pub fn forward_agent(mut self, enabled: bool) -> Self {
        self.options.forward_agent = enabled;
        self
    }
    #[doc(hidden)]
    pub fn best_effort_cwd(mut self) -> Self {
        self.options.best_effort_cwd = true;
        self
    }
    pub fn build(self) -> SshShellOptions {
        self.options
    }
}

/// SSH shell exit status, used only by SSH shell attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshExitStatus {
    pub code: i32,
    pub success: bool,
}

impl Machine {
    pub async fn exec<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExecutionOutput, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exec_with(program, |options| options.args(args)).await
    }

    pub async fn exec_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionOutput, LibVmError> {
        let options = configure(ExecutionOptionsBuilder::default()).build();
        let timeout = options.timeout;
        let mut session = self.start_execution(program.into(), options).await?;
        if let Some(timeout) = timeout {
            match tokio::time::timeout(timeout, session.collect()).await {
                Ok(output) => output,
                Err(_) => {
                    session.cancel();
                    Err(guest_session_error(
                        &self.inspect().await?.name,
                        format!("guest command timed out after {}s", timeout.as_secs()),
                    ))
                }
            }
        } else {
            session.collect().await
        }
    }

    pub async fn spawn<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExecutionSession, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.spawn_with(program, |options| options.args(args)).await
    }

    pub async fn spawn_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionSession, LibVmError> {
        self.start_execution(
            program.into(),
            configure(ExecutionOptionsBuilder::default()).build(),
        )
        .await
    }

    pub async fn shell(&self, script: impl Into<String>) -> Result<ExecutionOutput, LibVmError> {
        self.shell_with(script, |options| options).await
    }
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionOutput, LibVmError> {
        self.exec_with("/bin/sh", |options| {
            configure(options).arg("-lc").arg(script.into())
        })
        .await
    }

    pub async fn attach<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExecutionResult, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.attach_with(program, |options| options.args(args))
            .await
    }

    pub async fn attach_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionResult, LibVmError> {
        let options = configure(ExecutionOptionsBuilder::default())
            .stdin_pipe()
            .tty(true)
            .build();
        let mut session = self.start_execution(program.into(), options).await?;
        attach_execution_stdio(&mut session).await
    }

    pub async fn attach_shell(&self) -> Result<SshExitStatus, LibVmError> {
        self.attach_shell_with(|options| options).await
    }
    pub async fn attach_shell_with(
        &self,
        configure: impl FnOnce(SshShellOptionsBuilder) -> SshShellOptionsBuilder,
    ) -> Result<SshExitStatus, LibVmError> {
        let options = configure(SshShellOptionsBuilder::default()).build();
        self.attach_ssh_shell(options).await
    }

    async fn start_execution(
        &self,
        program: String,
        mut options: ExecutionOptions,
    ) -> Result<ExecutionSession, LibVmError> {
        let config = self
            .runtime()
            .resolve_machine_config(&MachineRef::id(self.machine_id()))
            .await?;
        let status = self
            .runtime()
            .reconcile_machine_runtime_best_effort(&config)
            .await?;
        let run_id = current_run_id(&config.name, &status)?;
        apply_default_execution_user(&mut options, config.guest.user.as_ref());
        let reference = config.name;
        let stdin = options.stdin.clone();
        let tty = options.tty;
        let pipe_stdin = !tty && matches!(stdin, StdinMode::Pipe | StdinMode::Bytes(_));
        let input_open = match &stdin {
            StdinMode::Null => tty,
            StdinMode::Pipe => true,
            StdinMode::Bytes(_) => false,
        };
        let process = process_spec(program, options);
        let (requests, receiver) = mpsc::channel(EXECUTION_REQUEST_QUEUE_CAPACITY);
        let execution_id = Uuid::new_v4();
        requests
            .send(ExecuteInput {
                message: Some(ExecuteMessage::Start(StartExecution {
                    machine_id: self.machine_id().to_string(),
                    machine_run_id: run_id.to_string(),
                    execution_id: execution_id.to_string(),
                    process: Some(process),
                })),
            })
            .await
            .map_err(|_| guest_session_error(&reference, "execution request stream is closed"))?;
        let events = self
            .runtime()
            .execution_client(self.machine_id())
            .execute(ReceiverStream::new(receiver))
            .await
            .map_err(|error| guest_session_error(&reference, error.to_string()))?;
        if let StdinMode::Bytes(data) = stdin {
            for chunk in data.chunks(EXECUTION_CHUNK_SIZE) {
                requests
                    .send(ExecuteInput {
                        message: Some(ExecuteMessage::StdinData(StdinData {
                            data: chunk.to_vec().into(),
                        })),
                    })
                    .await
                    .map_err(|_| {
                        guest_session_error(&reference, "execution request stream is closed")
                    })?;
            }
            if pipe_stdin {
                requests
                    .send(ExecuteInput {
                        message: Some(ExecuteMessage::CloseStdin(CloseStdin {})),
                    })
                    .await
                    .map_err(|_| {
                        guest_session_error(&reference, "execution request stream is closed")
                    })?;
            }
        }
        Ok(ExecutionSession {
            reference,
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(input_open)),
            started: Arc::new(AtomicBool::new(false)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin,
            events: Some(events),
        })
    }

    async fn attach_ssh_shell(
        &self,
        options: SshShellOptions,
    ) -> Result<SshExitStatus, LibVmError> {
        let reference = self.inspect().await?.name;
        let client = self
            .connect_guest_ssh(&reference, options.user.as_deref(), options.forward_agent)
            .await?;
        let mut channel = open_session_channel(&client).await?;
        let (columns, rows) = current_terminal_size();
        channel
            .request_pty(true, &options.term, columns, rows, 0, 0, &[])
            .await
            .map_err(|error| ssh_error(&reference, "request PTY", error))?;
        wait_channel_success(&mut channel, &reference, "request PTY").await?;
        if options.forward_agent {
            request_agent_forward(&mut channel, &reference).await?;
        }
        if options.cwd.is_some() || !options.env.is_empty() {
            channel
                .exec(true, ssh_shell_command(&options)?)
                .await
                .map_err(|error| ssh_error(&reference, "send shell exec request", error))?;
            wait_channel_success(&mut channel, &reference, "shell exec request").await?;
        } else {
            channel
                .request_shell(true)
                .await
                .map_err(|error| ssh_error(&reference, "request shell", error))?;
            wait_channel_success(&mut channel, &reference, "request shell").await?;
        }
        attach_ssh_stdio(
            reference,
            channel,
            detach_sequence(options.detach_keys.as_deref())?,
            client,
        )
        .await
    }

    async fn connect_guest_ssh(
        &self,
        reference: &str,
        user: Option<&str>,
        forward_agent: bool,
    ) -> Result<GuestSshClient, LibVmError> {
        let agent_socket = resolve_agent_socket(reference, forward_agent)?;
        let user = match user {
            Some(user) => user.to_string(),
            None => self
                .runtime()
                .resolve_machine_config(&MachineRef::id(self.machine_id()))
                .await?
                .guest
                .user
                .map(|user| user.name)
                .unwrap_or_else(|| "root".to_string()),
        };
        let keypair = self.runtime().load_guest_ssh_keypair().map_err(|error| {
            guest_session_error(reference, format!("load guest SSH keypair: {error}"))
        })?;
        let private_key = load_secret_key(&keypair.private_key_path, None).map_err(|error| {
            guest_session_error(reference, format!("load SSH private key: {error}"))
        })?;
        let started = std::time::Instant::now();
        let mut handle = loop {
            let stream = self.open_shell_stream().await?;
            match russh::client::connect_stream(
                Arc::new(russh::client::Config::default()),
                stream,
                SshClientHandler {
                    agent_socket: agent_socket.clone(),
                },
            )
            .await
            {
                Ok(handle) => break handle,
                Err(error)
                    if is_transient_ssh_handshake_error(&error.to_string())
                        && started.elapsed() < SSH_HANDSHAKE_READY_TIMEOUT =>
                {
                    tokio::time::sleep(SSH_HANDSHAKE_RETRY_DELAY).await
                }
                Err(error) => return Err(ssh_error(reference, "client handshake", error)),
            }
        };
        let hash_alg = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|error| ssh_error(reference, "server signature algorithms", error))?
            .flatten();
        let auth = handle
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(private_key), hash_alg),
            )
            .await
            .map_err(|error| ssh_error(reference, "public-key authentication", error))?;
        if !auth.success() {
            return Err(guest_session_error(
                reference,
                "SSH public-key authentication failed",
            ));
        }
        Ok(GuestSshClient {
            reference: reference.to_string(),
            handle,
        })
    }
}

fn current_run_id(reference: &str, status: &RuntimeStatus) -> Result<Uuid, LibVmError> {
    if status.state != MachineRuntimeState::Running {
        return Err(guest_session_error(reference, "machine is not running"));
    }
    let run_id = status
        .run_id
        .as_deref()
        .ok_or_else(|| guest_session_error(reference, "running machine has no run ID"))?;
    Uuid::parse_str(run_id).map_err(|error| {
        guest_session_error(
            reference,
            format!("running machine has invalid run ID: {error}"),
        )
    })
}

fn process_spec(program: String, options: ExecutionOptions) -> ProcessSpec {
    let mut argv = Vec::with_capacity(options.args.len() + 1);
    argv.push(program);
    argv.extend(options.args);
    let stdio = if options.tty {
        Some(protocol::v1::process_spec::Stdio::Pty(PtyStdio {
            initial_size: Some(terminal_size()),
            terminal: Some(options.term),
        }))
    } else {
        Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio {
            stdin: matches!(options.stdin, StdinMode::Pipe | StdinMode::Bytes(_)),
        }))
    };
    ProcessSpec {
        argv,
        environment: options
            .env
            .into_iter()
            .map(|(name, value)| EnvironmentVariable { name, value })
            .collect(),
        working_directory: options.cwd,
        user: options.user,
        stdio,
    }
}

fn apply_default_execution_user(
    options: &mut ExecutionOptions,
    configured_user: Option<&MachineUserConfig>,
) {
    if options.user.is_none() {
        options.user = configured_user.map(|user| user.name.clone());
    }
}

fn terminal_size() -> TerminalSize {
    let (columns, rows) = current_terminal_size();
    TerminalSize { columns, rows }
}

pub(crate) fn execution_event_from_wire(event: WireExecutionEvent) -> ExecutionEvent {
    match event.event {
        Some(ExecutionWireEvent::Accepted(_)) => ExecutionEvent::Accepted,
        Some(ExecutionWireEvent::Started(_)) => ExecutionEvent::Started,
        Some(ExecutionWireEvent::Stdout(output)) => ExecutionEvent::Stdout(output.data.to_vec()),
        Some(ExecutionWireEvent::Stderr(output)) => ExecutionEvent::Stderr(output.data.to_vec()),
        Some(ExecutionWireEvent::TerminalOutput(output)) => {
            ExecutionEvent::TerminalOutput(output.data.to_vec())
        }
        Some(ExecutionWireEvent::Exited(exited)) => {
            ExecutionEvent::Terminal(ExecutionResult::Exited { code: exited.code })
        }
        Some(ExecutionWireEvent::Signaled(signaled)) => {
            ExecutionEvent::Terminal(ExecutionResult::Signaled {
                signal: signaled.signal,
            })
        }
        Some(ExecutionWireEvent::LaunchFailed(failure)) => {
            ExecutionEvent::Terminal(ExecutionResult::LaunchFailed(ExecutionLaunchFailure {
                reason: launch_failure_reason(failure.reason),
                message: failure.message,
            }))
        }
        Some(ExecutionWireEvent::Lost(lost)) => {
            ExecutionEvent::Terminal(ExecutionResult::Lost(ExecutionLost {
                reason: lost_reason(lost.reason),
                message: lost.message,
            }))
        }
        None => ExecutionEvent::Terminal(ExecutionResult::Lost(ExecutionLost {
            reason: ExecutionLostReason::Unspecified,
            message: Some("execution event has no payload".to_string()),
        })),
    }
}

fn mark_execution_started(event: &ExecutionEvent, started: &AtomicBool) {
    if matches!(event, ExecutionEvent::Started) {
        started.store(true, Ordering::Release);
    }
}

fn caller_status(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::InvalidArgument
            | tonic::Code::FailedPrecondition
            | tonic::Code::OutOfRange
            | tonic::Code::ResourceExhausted
            | tonic::Code::AlreadyExists
            | tonic::Code::NotFound
            | tonic::Code::PermissionDenied
            | tonic::Code::Unauthenticated
    )
}

pub(crate) fn launch_failure_reason(value: Option<i32>) -> ExecutionLaunchFailureReason {
    match protocol::v1::LaunchFailureReason::try_from(value.unwrap_or_default())
        .unwrap_or(protocol::v1::LaunchFailureReason::Unspecified)
    {
        protocol::v1::LaunchFailureReason::CommandNotFound => {
            ExecutionLaunchFailureReason::CommandNotFound
        }
        protocol::v1::LaunchFailureReason::InvalidProcessSpec => {
            ExecutionLaunchFailureReason::InvalidProcessSpec
        }
        protocol::v1::LaunchFailureReason::WorkingDirectoryNotFound => {
            ExecutionLaunchFailureReason::WorkingDirectoryNotFound
        }
        protocol::v1::LaunchFailureReason::WorkingDirectoryNotDirectory => {
            ExecutionLaunchFailureReason::WorkingDirectoryNotDirectory
        }
        protocol::v1::LaunchFailureReason::InvalidIdentity => {
            ExecutionLaunchFailureReason::InvalidIdentity
        }
        protocol::v1::LaunchFailureReason::IdentityNotFound => {
            ExecutionLaunchFailureReason::IdentityNotFound
        }
        protocol::v1::LaunchFailureReason::PermissionDenied => {
            ExecutionLaunchFailureReason::PermissionDenied
        }
        protocol::v1::LaunchFailureReason::SpawnFailed => ExecutionLaunchFailureReason::SpawnFailed,
        protocol::v1::LaunchFailureReason::CancelledBeforeStart => {
            ExecutionLaunchFailureReason::CancelledBeforeStart
        }
        _ => ExecutionLaunchFailureReason::Unspecified,
    }
}
pub(crate) fn lost_reason(value: Option<i32>) -> ExecutionLostReason {
    match protocol::v1::LostReason::try_from(value.unwrap_or_default())
        .unwrap_or(protocol::v1::LostReason::Unspecified)
    {
        protocol::v1::LostReason::AgentInstanceReplaced => {
            ExecutionLostReason::AgentInstanceReplaced
        }
        protocol::v1::LostReason::AgentBootReplaced => ExecutionLostReason::AgentBootReplaced,
        protocol::v1::LostReason::AgentUnavailable => ExecutionLostReason::AgentUnavailable,
        protocol::v1::LostReason::GuestStreamLost => ExecutionLostReason::GuestStreamLost,
        protocol::v1::LostReason::VmStopped => ExecutionLostReason::VmStopped,
        protocol::v1::LostReason::VmmonExited => ExecutionLostReason::VmmonExited,
        _ => ExecutionLostReason::Unspecified,
    }
}

async fn attach_execution_stdio(
    session: &mut ExecutionSession,
) -> Result<ExecutionResult, LibVmError> {
    let mut host_stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut input = [0_u8; 1024];
    let mut _terminal = None;
    let mut stdin: Option<ExecutionStdin> = None;
    let mut stdin_closed = false;
    let mut started = false;
    let mut launch_cancelled = false;
    let mut resize_signal = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::window_change(),
    )
    .map_err(|error| {
        guest_session_error(
            &session.reference,
            format!("listen for terminal resize: {error}"),
        )
    })?;
    let mut resize_signal_open = true;
    let mut signals = HostSignalForwarders::new(&session.reference)?;
    loop {
        tokio::select! {
            read = host_stdin.read(&mut input), if started && !launch_cancelled && !stdin_closed => {
                let read = read.map_err(|error| guest_session_error(&session.reference, format!("read terminal input: {error}")))?;
                if read == 0 {
                    stdin_closed = true;
                } else {
                    let Some(stdin) = stdin.as_ref() else {
                        continue;
                    };
                    stdin.write(input[..read].to_vec()).await?;
                }
            }
            resized = resize_signal.recv(), if started && !launch_cancelled && resize_signal_open => {
                if resized.is_none() {
                    resize_signal_open = false;
                } else {
                    let (columns, rows) = current_terminal_size();
                    let rows = u16::try_from(rows).map_err(|_| guest_session_error(&session.reference, "terminal rows exceed 65535"))?;
                    let columns = u16::try_from(columns).map_err(|_| guest_session_error(&session.reference, "terminal columns exceed 65535"))?;
                    session.resize_pty(rows, columns).await?;
                }
            }
            signal = signals.recv() => {
                let Some(signal) = signal else {
                    return Err(guest_session_error(&session.reference, "host signal listeners stopped"));
                };
                if started && !launch_cancelled {
                    session.signal(signal).await?;
                } else if !launch_cancelled {
                    session.close_requests();
                    launch_cancelled = true;
                }
            }
            event = session.recv() => match event? {
                Some(ExecutionEvent::Stdout(data)) | Some(ExecutionEvent::Stderr(data)) | Some(ExecutionEvent::TerminalOutput(data)) => {
                    stdout.write_all(&data).await.map_err(|error| guest_session_error(&session.reference, format!("write terminal output: {error}")))?;
                    stdout.flush().await.map_err(|error| guest_session_error(&session.reference, format!("flush terminal output: {error}")))?;
                }
                Some(ExecutionEvent::Terminal(result)) => return Ok(result),
                Some(ExecutionEvent::Accepted) => {}
                Some(ExecutionEvent::Started) if !launch_cancelled => {
                    let raw_terminal = RawTerminalGuard::new().map_err(|error| {
                        guest_session_error(&session.reference, format!("enable raw terminal: {error}"))
                    })?;
                    let execution_stdin = session
                        .stdin()
                        .ok_or_else(|| guest_session_error(&session.reference, "execution stdin is closed"))?;
                    let (columns, rows) = current_terminal_size();
                    let rows = u16::try_from(rows).map_err(|_| guest_session_error(&session.reference, "terminal rows exceed 65535"))?;
                    let columns = u16::try_from(columns).map_err(|_| guest_session_error(&session.reference, "terminal columns exceed 65535"))?;
                    session.resize_pty(rows, columns).await?;
                    _terminal = Some(raw_terminal);
                    stdin = Some(execution_stdin);
                    started = true;
                }
                Some(ExecutionEvent::Started) => started = true,
                None => return Err(guest_session_error(&session.reference, "execution ended without a terminal result")),
            }
        }
    }
}

struct HostSignalForwarders {
    receiver: mpsc::Receiver<u32>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl HostSignalForwarders {
    fn new(reference: &str) -> Result<Self, LibVmError> {
        let (sender, receiver) = mpsc::channel(64);
        let mut tasks = Vec::new();
        for signal in forwardable_signals() {
            let Ok(mut listener) = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::from_raw(signal as i32),
            ) else {
                continue;
            };
            let sender = sender.clone();
            tasks.push(tokio::spawn(async move {
                while listener.recv().await.is_some() {
                    if sender.send(signal).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(sender);
        if tasks.is_empty() {
            return Err(guest_session_error(reference, "listen for host signals"));
        }
        Ok(Self { receiver, tasks })
    }

    async fn recv(&mut self) -> Option<u32> {
        self.receiver.recv().await
    }
}

impl Drop for HostSignalForwarders {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn forwardable_signals() -> impl Iterator<Item = u32> {
    (1..=64).filter(|signal| {
        !matches!(
            *signal as i32,
            libc::SIGKILL | libc::SIGSTOP | libc::SIGCHLD | libc::SIGWINCH
        )
    })
}

struct GuestSshClient {
    reference: String,
    handle: russh::client::Handle<SshClientHandler>,
}
#[derive(Clone)]
struct SshClientHandler {
    agent_socket: Option<PathBuf>,
}
impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<ClientMsg>,
        _: russh::ChannelOpenHandleInner<ClientMsg>,
        _: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        #[cfg(unix)]
        if let Some(agent_socket) = self.agent_socket.clone() {
            tokio::spawn(async move {
                let mut guest_agent = channel.into_stream();
                if let Ok(mut host_agent) = tokio::net::UnixStream::connect(agent_socket).await {
                    let _ = tokio::io::copy_bidirectional(&mut guest_agent, &mut host_agent).await;
                }
            });
        }
        #[cfg(not(unix))]
        let _ = channel;
        Ok(())
    }
}
async fn open_session_channel(client: &GuestSshClient) -> Result<Channel<ClientMsg>, LibVmError> {
    client
        .handle
        .channel_open_session()
        .await
        .map_err(|error| ssh_error(&client.reference, "open session channel", error))
}
async fn wait_channel_success(
    channel: &mut Channel<ClientMsg>,
    reference: &str,
    context: &str,
) -> Result<(), LibVmError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(guest_session_error(
                    reference,
                    format!("SSH {context} failed"),
                ));
            }
            Some(ChannelMsg::Close) | None => {
                return Err(guest_session_error(
                    reference,
                    format!("SSH channel closed during {context}"),
                ));
            }
            _ => {}
        }
    }
}
async fn request_agent_forward(
    channel: &mut Channel<ClientMsg>,
    reference: &str,
) -> Result<(), LibVmError> {
    channel
        .agent_forward(true)
        .await
        .map_err(|error| ssh_error(reference, "request SSH agent forwarding", error))?;
    wait_channel_success(channel, reference, "request SSH agent forwarding").await
}

fn ssh_shell_command(options: &SshShellOptions) -> Result<String, LibVmError> {
    let mut command = String::new();
    if let Some(cwd) = &options.cwd {
        command.push_str("cd ");
        command.push_str(&quote_ssh_shell_argument(cwd));
        if options.best_effort_cwd {
            command.push_str(" 2>/dev/null || true; ");
        } else {
            command.push_str(" && ");
        }
    }
    command.push_str("exec ");
    if !options.env.is_empty() {
        command.push_str("env");
        for (key, value) in &options.env {
            if !valid_environment_name(key) {
                return Err(guest_session_error(
                    "shell",
                    format!("invalid environment variable name {key:?}"),
                ));
            }
            command.push(' ');
            command.push_str(key);
            command.push('=');
            command.push_str(&quote_ssh_shell_argument(value));
        }
        command.push(' ');
    }
    command.push_str("/bin/sh -lc ");
    command.push_str(&quote_ssh_shell_argument(DEFAULT_LOGIN_SHELL_SCRIPT));
    Ok(command)
}

fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || index > 0 && byte.is_ascii_digit()
        })
}

fn quote_ssh_shell_argument(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

async fn attach_ssh_stdio(
    reference: String,
    channel: Channel<ClientMsg>,
    detach_keys: Vec<u8>,
    _client: GuestSshClient,
) -> Result<SshExitStatus, LibVmError> {
    let _terminal = RawTerminalGuard::new().map_err(|error| {
        guest_session_error(&reference, format!("enable raw terminal: {error}"))
    })?;
    let (mut rx, tx) = channel.split();
    let tx = Arc::new(tx);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut input = [0_u8; 1024];
    let mut match_pos = 0;
    let mut exit_code = None;
    let mut detached = false;
    let mut stdin_closed = false;
    let mut resize_signal =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).map_err(
            |error| guest_session_error(&reference, format!("listen for terminal resize: {error}")),
        )?;
    let mut resize_signal_open = true;
    loop {
        tokio::select! {
            read = stdin.read(&mut input), if !stdin_closed => {
                let read = read.map_err(|error| guest_session_error(&reference, format!("read terminal input: {error}")))?;
                if read == 0 {
                    stdin_closed = true;
                    tx.eof().await.map_err(|error| ssh_error(&reference, "close terminal input", error))?;
                } else if input_contains_detach_sequence(&input[..read], &detach_keys, &mut match_pos) {
                    detached = true;
                    break;
                } else {
                    tx.data_bytes(input[..read].to_vec()).await.map_err(|error| ssh_error(&reference, "write terminal input", error))?;
                }
            }
            resized = resize_signal.recv(), if resize_signal_open => {
                if resized.is_none() {
                    resize_signal_open = false;
                } else {
                    resize_attached_pty(&reference, tx.as_ref()).await?;
                }
            }
            message = rx.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    stdout.write_all(&data).await.map_err(|error| guest_session_error(&reference, format!("write terminal output: {error}")))?;
                    stdout.flush().await.map_err(|error| guest_session_error(&reference, format!("flush terminal output: {error}")))?;
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => exit_code = Some(exit_status as i32),
                Some(ChannelMsg::ExitSignal { .. }) => exit_code = Some(128),
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    }
    ssh_exit_status(&reference, exit_code, detached)
}

fn ssh_exit_status(
    reference: &str,
    exit_code: Option<i32>,
    detached: bool,
) -> Result<SshExitStatus, LibVmError> {
    if detached {
        return Ok(SshExitStatus {
            code: 0,
            success: true,
        });
    }
    let code = exit_code.ok_or_else(|| {
        guest_session_error(
            reference,
            "attached SSH session ended without an exit status",
        )
    })?;
    Ok(SshExitStatus {
        code,
        success: code == 0,
    })
}

async fn resize_attached_pty(
    reference: &str,
    channel: &ChannelWriteHalf<ClientMsg>,
) -> Result<(), LibVmError> {
    let (columns, rows) = current_terminal_size();
    channel
        .window_change(columns, rows, 0, 0)
        .await
        .map_err(|error| ssh_error(reference, "resize PTY", error))
}

fn detach_sequence(spec: Option<&str>) -> Result<Vec<u8>, LibVmError> {
    let Some(spec) = spec else {
        return Ok(vec![DEFAULT_ATTACH_DETACH_KEY]);
    };
    let mut sequence = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(control) = part.strip_prefix("ctrl-") {
            let byte = match control {
                "]" => 0x1d,
                "[" => 0x1b,
                "\\" => 0x1c,
                "^" => 0x1e,
                "_" => 0x1f,
                "@" => 0x00,
                value if value.len() == 1 => {
                    let byte = value.as_bytes()[0];
                    if byte.is_ascii_lowercase() {
                        byte - b'a' + 1
                    } else if byte.is_ascii_uppercase() {
                        byte - b'A' + 1
                    } else {
                        return Err(invalid_detach_key(part));
                    }
                }
                _ => return Err(invalid_detach_key(part)),
            };
            sequence.push(byte);
        } else if part.len() == 1 {
            sequence.push(part.as_bytes()[0]);
        } else {
            return Err(invalid_detach_key(part));
        }
    }
    if sequence.is_empty() {
        sequence.push(DEFAULT_ATTACH_DETACH_KEY);
    }
    Ok(sequence)
}

fn invalid_detach_key(key: &str) -> LibVmError {
    guest_session_error("shell", format!("invalid detach key {key:?}"))
}
fn input_contains_detach_sequence(data: &[u8], sequence: &[u8], position: &mut usize) -> bool {
    for byte in data {
        if *byte == sequence[*position] {
            *position += 1;
            if *position == sequence.len() {
                *position = 0;
                return true;
            }
        } else {
            *position = usize::from(*byte == sequence[0]);
        }
    }
    false
}
fn current_terminal_size() -> (u32, u32) {
    let stdout = std::io::stdout();
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(stdout.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
        && size.ws_row > 0
    {
        (u32::from(size.ws_col), u32::from(size.ws_row))
    } else {
        (80, 24)
    }
}
fn resolve_agent_socket(
    reference: &str,
    forward_agent: bool,
) -> Result<Option<PathBuf>, LibVmError> {
    if !forward_agent {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        std::env::var_os("SSH_AUTH_SOCK")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(Some)
            .ok_or_else(|| {
                guest_session_error(
                    reference,
                    "SSH agent forwarding requested, but SSH_AUTH_SOCK is not set",
                )
            })
    }
    #[cfg(not(unix))]
    {
        Err(guest_session_error(
            reference,
            "SSH agent forwarding is only supported on Unix hosts",
        ))
    }
}
fn ssh_error(reference: &str, context: &str, error: russh::Error) -> LibVmError {
    guest_session_error(reference, format!("SSH {context}: {error}"))
}
fn is_transient_ssh_handshake_error(message: &str) -> bool {
    let value = message.to_ascii_lowercase();
    [
        "disconnected",
        "connection reset",
        "unexpected eof",
        "connection aborted",
        "connection refused",
    ]
    .iter()
    .any(|needle| value.contains(needle))
        || value == "eof"
        || value.ends_with(" eof")
}
fn guest_session_error(reference: &str, message: impl Into<String>) -> LibVmError {
    LibVmError::GuestSession {
        reference: reference.to_string(),
        message: message.into(),
    }
}

struct RawTerminalGuard {
    fd: OwnedFd,
    original: libc::termios,
    enabled: bool,
}
impl RawTerminalGuard {
    fn new() -> std::io::Result<Self> {
        let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
        if unsafe { libc::isatty(fd.as_raw_fd()) } == 0 {
            return Ok(Self {
                fd,
                original: unsafe { std::mem::zeroed() },
                enabled: false,
            });
        }
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut original) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut raw = original;
        raw.c_iflag &= !(libc::IGNBRK
            | libc::BRKINT
            | libc::PARMRK
            | libc::ISTRIP
            | libc::INLCR
            | libc::IGNCR
            | libc::ICRNL
            | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
        raw.c_cflag &= !(libc::CSIZE | libc::PARENB);
        raw.c_cflag |= libc::CS8;
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            original,
            enabled: true,
        })
    }
}
impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ =
                unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSAFLUSH, &self.original) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nix::sys::signal::{raise, Signal};
    use protocol::v1::execute_input::Message as ExecuteMessage;
    use tokio::sync::{watch, Mutex as AsyncMutex};
    use tokio::time::timeout;

    use crate::machine::session::{
        apply_default_execution_user, execution_event_from_wire, forwardable_signals,
        mark_execution_started, process_spec, ssh_shell_command, ExecutionControl, ExecutionEvent,
        ExecutionLostReason, ExecutionOptions, ExecutionResult, HostSignalForwarders,
        SshShellOptions, StdinMode,
    };
    use crate::machine::MachineUserConfig;

    #[test]
    fn vmmon_execution_process_spec_preserves_argv_environment_and_pipe_stdin() {
        let spec = process_spec(
            "program with spaces".to_string(),
            ExecutionOptions {
                args: vec!["one two".to_string()],
                cwd: Some("/work".to_string()),
                user: Some("alice".to_string()),
                env: vec![("KEY".to_string(), "value".to_string())],
                timeout: None,
                stdin: StdinMode::Pipe,
                tty: false,
                term: "xterm".to_string(),
            },
        );
        assert_eq!(spec.argv, ["program with spaces", "one two"]);
        assert_eq!(spec.environment[0].name, "KEY");
        assert_eq!(spec.working_directory.as_deref(), Some("/work"));
        assert!(matches!(
            spec.stdio,
            Some(protocol::v1::process_spec::Stdio::Pipes(
                protocol::v1::PipeStdio { stdin: true }
            ))
        ));
    }

    #[test]
    fn vmmon_execution_process_spec_uses_current_terminal_fallback_for_pty() {
        let spec = process_spec(
            "sh".to_string(),
            ExecutionOptions {
                tty: true,
                ..ExecutionOptions::default()
            },
        );
        let Some(protocol::v1::process_spec::Stdio::Pty(pty)) = spec.stdio else {
            panic!("expected pty");
        };
        let size = pty.initial_size.expect("pty size");
        assert!(size.columns > 0 && size.rows > 0);
        assert_eq!(pty.terminal.as_deref(), Some("xterm-256color"));
    }

    #[test]
    fn structured_execution_inherits_configured_user_without_overriding_explicit_user() {
        let configured = MachineUserConfig::new("configured", 1000, 1000, "/home/configured");
        let mut inherited = ExecutionOptions::default();
        apply_default_execution_user(&mut inherited, Some(&configured));
        assert_eq!(inherited.user.as_deref(), Some("configured"));

        let mut explicit = ExecutionOptions {
            user: Some("override".to_string()),
            ..ExecutionOptions::default()
        };
        apply_default_execution_user(&mut explicit, Some(&configured));
        assert_eq!(explicit.user.as_deref(), Some("override"));
    }

    #[test]
    fn vmmon_execution_wire_lost_event_stays_a_lost_terminal_result() {
        let event = execution_event_from_wire(protocol::v1::ExecutionEvent {
            event: Some(protocol::v1::execution_event::Event::Lost(
                protocol::v1::ExecutionLost {
                    reason: Some(protocol::v1::LostReason::VmmonExited as i32),
                    message: Some("monitor exited".to_string()),
                },
            )),
        });

        assert_eq!(
            event,
            ExecutionEvent::Terminal(ExecutionResult::Lost(crate::machine::ExecutionLost {
                reason: ExecutionLostReason::VmmonExited,
                message: Some("monitor exited".to_string()),
            }))
        );
    }

    #[tokio::test]
    async fn foreground_controls_follow_the_started_event_before_sending_input_or_resize() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(4);
        let started = Arc::new(AtomicBool::new(false));
        let control = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::clone(&started),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };

        assert!(control.stdin().is_none());
        assert!(control.write_stdin(b"before").await.is_err());
        assert!(control.resize_pty(24, 80).await.is_err());
        assert!(receiver.try_recv().is_err());

        mark_execution_started(&ExecutionEvent::Accepted, &started);
        assert!(!started.load(Ordering::Acquire));
        mark_execution_started(&ExecutionEvent::Started, &started);
        assert!(started.load(Ordering::Acquire));

        control
            .write_stdin(b"after")
            .await
            .expect("write after Started");
        control
            .resize_pty(24, 80)
            .await
            .expect("resize after Started");

        assert!(matches!(
            receiver.recv().await.and_then(|request| request.message),
            Some(ExecuteMessage::StdinData(data)) if data.data.as_ref() == b"after"
        ));
        assert!(matches!(
            receiver.recv().await.and_then(|request| request.message),
            Some(ExecuteMessage::ResizePty(resize))
                if matches!(resize.size, Some(protocol::v1::TerminalSize { rows: 24, columns: 80 }))
        ));
    }

    #[tokio::test]
    async fn foreground_signal_closes_pending_request_and_forwards_only_after_started() {
        let (pending_requests, mut pending_receiver) = tokio::sync::mpsc::channel(1);
        let pending = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(pending_requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::new(AtomicBool::new(false)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };

        pending
            .signal(libc::SIGINT as u32)
            .await
            .expect("cancel pending execution");
        assert!(pending_receiver.recv().await.is_none());

        let (running_requests, mut running_receiver) = tokio::sync::mpsc::channel(1);
        let running = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(running_requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::new(AtomicBool::new(true)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };

        running
            .signal(libc::SIGTERM as u32)
            .await
            .expect("forward running execution signal");
        assert!(matches!(
            running_receiver.recv().await.and_then(|request| request.message),
            Some(ExecuteMessage::SignalProcess(signal)) if signal.signal == Some(libc::SIGTERM as u32)
        ));
    }

    #[test]
    fn pty_signal_forwarding_excludes_only_unforwardable_signals() {
        let signals = forwardable_signals().collect::<Vec<_>>();

        for signal in 1..=64 {
            let excluded = matches!(
                signal,
                value if value == libc::SIGKILL as u32
                    || value == libc::SIGSTOP as u32
                    || value == libc::SIGCHLD as u32
                    || value == libc::SIGWINCH as u32
            );
            assert_eq!(signals.contains(&signal), !excluded, "signal {signal}");
        }
    }

    #[tokio::test]
    async fn pty_signal_forwarder_receives_registered_host_signals() {
        let mut forwarders = HostSignalForwarders::new("dev").expect("register host signals");

        raise(Signal::SIGUSR1).expect("raise SIGUSR1");
        let signal = timeout(Duration::from_secs(1), forwarders.recv())
            .await
            .expect("receive SIGUSR1")
            .expect("signal relay is open");

        assert_eq!(signal, libc::SIGUSR1 as u32);
    }

    #[tokio::test]
    async fn vmmon_execution_control_splits_large_stdin_without_losing_bytes() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(4);
        let control = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::new(AtomicBool::new(true)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };
        let input = vec![7; protocol::CHUNK_64_KIB + 3];

        control
            .write_stdin(input.clone())
            .await
            .expect("write stdin");

        let mut received = Vec::new();
        for _ in 0..2 {
            let request = receiver.recv().await.expect("stdin request");
            let Some(protocol::v1::execute_input::Message::StdinData(data)) = request.message
            else {
                panic!("expected stdin data");
            };
            assert!(data.data.len() <= protocol::CHUNK_64_KIB);
            received.extend_from_slice(&data.data);
        }
        assert_eq!(received, input);
    }

    #[test]
    fn vmmon_execution_control_hides_unavailable_stdin() {
        let (requests, _receiver) = tokio::sync::mpsc::channel(1);
        let control = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicBool::new(true)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: false,
        };

        assert!(control.stdin().is_none());
    }

    #[tokio::test]
    async fn concurrent_stdin_closes_publish_exactly_one_eof() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(4);
        let control = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::new(AtomicBool::new(true)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };
        let stdin = control.stdin().expect("stdin writer");

        let (control_result, stdin_result) = tokio::join!(control.close_stdin(), stdin.close());
        assert_ne!(control_result.is_ok(), stdin_result.is_ok());
        assert!(matches!(
            receiver.recv().await.and_then(|request| request.message),
            Some(ExecuteMessage::CloseStdin(_))
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn closing_requests_cancels_backpressured_eof() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
        requests
            .try_send(protocol::v1::ExecuteInput {
                message: Some(ExecuteMessage::StdinData(protocol::v1::StdinData {
                    data: vec![1].into(),
                })),
            })
            .expect("fill request queue");
        let control = ExecutionControl {
            reference: "dev".to_string(),
            requests: Arc::new(Mutex::new(Some(requests))),
            input_open: Arc::new(AtomicBool::new(true)),
            started: Arc::new(AtomicBool::new(true)),
            input_order: Arc::new(AsyncMutex::new(())),
            request_closed: Arc::new(watch::channel(false).0),
            pipe_stdin: true,
        };
        let pending = tokio::spawn({
            let control = control.clone();
            async move { control.close_stdin().await }
        });
        tokio::task::yield_now().await;

        control.close_requests();
        assert!(pending.await.expect("join pending EOF").is_err());
        assert!(matches!(
            receiver.recv().await.and_then(|request| request.message),
            Some(ExecuteMessage::StdinData(_))
        ));
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn ssh_shell_rejects_environment_names_that_change_the_command() {
        let mut options = SshShellOptions::default();
        options
            .env
            .push(("GOOD; touch /tmp/nope".to_string(), "value".to_string()));

        assert!(ssh_shell_command(&options).is_err());
    }
}

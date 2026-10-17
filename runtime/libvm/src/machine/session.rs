use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::v1::execute_input::Message as ExecuteMessage;
use protocol::v1::execution_event::Event as ExecutionWireEvent;
use protocol::v1::{
    CloseStdin, EnvironmentVariable, ExecuteInput, ExecutionEvent as WireExecutionEvent, PipeStdio,
    ProcessSpec, PtyStdio, ResizePty, SignalProcess, StartExecution, StdinData, TerminalSize,
};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::machine::{Machine, MachineRef, MachineUserConfig};
use crate::runtime::core::RuntimeStatus;
use crate::store::models::MachineRuntimeState;
use crate::LibVmError;

pub(super) mod host;
pub(super) mod ssh;
use ssh::DEFAULT_TERM;

const EXECUTION_REQUEST_QUEUE_CAPACITY: usize = 64;
const EXECUTION_CHUNK_SIZE: usize = protocol::CHUNK_64_KIB;

/// RPC options shared by exec, spawn and exec_script. Guest failures are reported
/// through structured results; see the [execution examples](crate).
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
    pub initial_pty_size: Option<(u16, u16)>,
}

/// Builds owned RPC process options. Setters replace scalar values and append argv
/// and environment entries. See [execution examples](crate).
#[derive(Debug, Default)]
pub struct ExecutionOptionsBuilder {
    options: ExecutionOptions,
}

/// Owned initial RPC stdin policy. Bytes are sent before Started, followed by pipe
/// EOF; Pipe exposes Started-gated live input. See [execution examples](crate).
#[derive(Debug, Clone, Default)]
pub enum StdinMode {
    #[default]
    Null,
    Pipe,
    Bytes(Vec<u8>),
}

/// RPC terminal outcome, distinct from SSH status. Launch and transport loss are
/// not fabricated process exits. See [execution examples](crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionResult {
    Exited { code: Option<u32> },
    Signaled { signal: Option<u32> },
    LaunchFailed(ExecutionLaunchFailure),
    Lost(ExecutionLost),
}

/// Guest RPC process launch failure with categorized reason and optional detail.
/// See [execution examples](crate).
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

/// Categorized RPC launch failure; not an SSH protocol status. See [examples](crate).
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

/// RPC fencing or stream loss, rather than a successful process outcome.
/// See [execution examples](crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLost {
    pub reason: ExecutionLostReason,
    pub message: Option<String>,
}

/// Categorized host/guest RPC stream loss. See [execution examples](crate).
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

/// Ordered RPC event. Receive Started before accessing live stdin; keep receiving
/// through Terminal. See [execution examples](crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEvent {
    Accepted,
    Started,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    TerminalOutput(Vec<u8>),
    Terminal(ExecutionResult),
}

/// Buffered RPC output and its structured terminal result. Byte accessors borrow
/// the captured data; text accessors validate UTF-8. See [examples](crate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    result: ExecutionResult,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    terminal_output: Vec<u8>,
}

impl ExecutionOutput {
    /// Borrows the RPC terminal result. See [execution examples](crate).
    pub fn result(&self) -> &ExecutionResult {
        &self.result
    }
    /// Borrows captured pipe stdout bytes. See [execution examples](crate).
    pub fn stdout_bytes(&self) -> &[u8] {
        &self.stdout
    }
    /// Borrows captured pipe stderr bytes. See [execution examples](crate).
    pub fn stderr_bytes(&self) -> &[u8] {
        &self.stderr
    }
    /// Borrows captured RPC PTY output bytes. See [execution examples](crate).
    pub fn terminal_output_bytes(&self) -> &[u8] {
        &self.terminal_output
    }
    /// Copies captured stdout as UTF-8, returning a decoding error for binary data.
    /// See [execution examples](crate).
    pub fn stdout(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stdout.clone())
    }
    /// Copies captured stderr as UTF-8, returning a decoding error for binary data.
    /// See [execution examples](crate).
    pub fn stderr(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stderr.clone())
    }
    /// Copies captured RPC PTY output as UTF-8, rejecting invalid encoding.
    /// See [execution examples](crate).
    pub fn terminal_output(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.terminal_output.clone())
    }
}

/// Owned live RPC call. Terminal/error/cancel/drop closes requests and invalidates
/// cloned controls. It is not reconnectable. See [execution examples](crate).
pub struct ExecutionSession {
    control: ExecutionControl,
    events: Option<tonic::Streaming<WireExecutionEvent>>,
}

/// Cloneable request-side controls for a live RPC call; terminal/cancel/drop
/// invalidates them. See [execution examples](crate).
#[derive(Clone)]
pub struct ExecutionControl {
    state: Arc<ExecutionControlState>,
}

struct ExecutionControlState {
    reference: String,
    requests: Mutex<Option<mpsc::Sender<ExecuteInput>>>,
    input_open: AtomicBool,
    started: AtomicBool,
    input_order: AsyncMutex<()>,
    request_closed: watch::Sender<bool>,
    pipe_stdin: bool,
}

/// Cloneable RPC stdin writer. Obtain it only after receiving Started; see the
/// [execution guide](crate). Session completion invalidates surviving writers.
#[derive(Clone)]
pub struct ExecutionStdin {
    control: ExecutionControl,
}

impl Drop for ExecutionSession {
    fn drop(&mut self) {
        self.close_requests();
    }
}

impl ExecutionSession {
    /// Returns controls that remain usable while another task receives events.
    /// Clones one shared RPC control handle; session completion invalidates it.
    /// See [execution examples](crate).
    pub fn control(&self) -> ExecutionControl {
        self.control.clone()
    }

    /// Returns a stdin writer while the request half remains open.
    /// Returns None before Started or after input/request closure. See [examples](crate).
    pub fn stdin(&self) -> Option<ExecutionStdin> {
        self.control.stdin()
    }
    /// Receives one RPC event, advancing Started gating. Caller errors propagate;
    /// other transport errors become Lost. Completion closes controls. See [examples](crate).
    pub async fn recv(&mut self) -> Result<Option<ExecutionEvent>, LibVmError> {
        let Some(events) = self.events.as_mut() else {
            return Ok(None);
        };
        match events.message().await {
            Ok(Some(event)) => {
                let event = execution_event_from_wire(event);
                mark_execution_started(&event, &self.control.state.started);
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
                        &self.control.state.reference,
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
    /// Requires Started and open input; serializes chunks with EOF. Errors propagate.
    /// See [execution examples](crate).
    pub async fn write_stdin(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.control.write_stdin(data).await
    }

    /// Sends EOF to the process stdin while keeping the execution call open.
    /// Requires Started and pipe stdin; concurrent closes emit at most one EOF.
    /// See [execution examples](crate).
    pub async fn close_stdin(&self) -> Result<(), LibVmError> {
        self.control.close_stdin().await
    }

    /// Resizes the process PTY.
    /// Requires Started; request closure or guest rejection fails. See [examples](crate).
    pub async fn resize_pty(&self, rows: u16, columns: u16) -> Result<(), LibVmError> {
        self.control.resize_pty(rows, columns).await
    }

    /// Delivers a positive Linux signal number to the process group.
    /// Accepts Linux signals 1..=64. A valid pre-Started signal closes requests
    /// without waiting for launch. See [execution examples](crate).
    pub async fn signal(&self, signal: u32) -> Result<(), LibVmError> {
        self.control.signal(signal).await
    }

    /// Finishes the request half of the bidirectional call.
    /// Invalidates clones and wakes blocked sends, but retains the response stream.
    /// See [execution examples](crate).
    pub fn close_requests(&self) {
        self.control.close_requests();
    }

    /// Cancels the complete bidirectional call, including the response stream.
    /// Drops the response stream and closes requests. This requests cancellation,
    /// not an awaited guest-process join. See [execution examples](crate).
    pub fn cancel(&mut self) {
        self.close_requests();
        self.events = None;
    }

    /// Receives through terminal status, discarding output. Missing status is an error;
    /// this does not reconnect or impose a deadline. See [execution examples](crate).
    pub async fn wait(&mut self) -> Result<ExecutionResult, LibVmError> {
        while let Some(event) = self.recv().await? {
            if let ExecutionEvent::Terminal(result) = event {
                return Ok(result);
            }
        }
        Err(guest_session_error(
            &self.control.state.reference,
            "execution ended without a terminal result",
        ))
    }

    /// Buffers all output through terminal status. Missing status is an error and
    /// output is unbounded by this method. See [execution examples](crate).
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
            &self.control.state.reference,
            "execution ended without a terminal result",
        ))
    }
}

impl ExecutionControl {
    /// Returns a stdin writer while the request half remains open.
    /// Returns None before Started or after input/request closure. See [examples](crate).
    pub fn stdin(&self) -> Option<ExecutionStdin> {
        self.state.requests.lock().ok()?.as_ref()?;
        if !self.state.started.load(Ordering::Acquire)
            || !self.state.input_open.load(Ordering::Acquire)
        {
            return None;
        }
        Some(ExecutionStdin {
            control: self.clone(),
        })
    }

    /// Writes bytes to the process stdin or PTY.
    /// Requires Started/open input; ordered chunking prevents EOF overtaking a write.
    /// Live empty writes send an empty data message. See [execution examples](crate).
    pub async fn write_stdin(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.send_stdin_data(data.into()).await
    }

    /// Sends EOF to pipe stdin while leaving the response stream open.
    /// Requires Started and pipe stdin; only one concurrent close can succeed.
    /// Closed requests/input and PTY mode return errors. See [examples](crate).
    pub async fn close_stdin(&self) -> Result<(), LibVmError> {
        if !self.state.pipe_stdin {
            return Err(guest_session_error(
                &self.state.reference,
                "explicit EOF is only valid for pipe stdin",
            ));
        }
        let _order = self.state.input_order.lock().await;
        self.ensure_started()?;
        if !self.state.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.state.reference,
                "execution input is closed",
            ));
        }
        self.send(ExecuteMessage::CloseStdin(CloseStdin {})).await?;
        self.state.input_open.store(false, Ordering::Release);
        Ok(())
    }

    /// Resizes the process PTY.
    /// Requires Started; request closure or guest rejection fails. See [examples](crate).
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
    /// Accepts Linux numbers 1..=64; rejects invalid numbers without side effects.
    /// Before Started, closes requests to cancel launch. See [examples](crate).
    pub async fn signal(&self, signal: u32) -> Result<(), LibVmError> {
        if !(1..=64).contains(&signal) {
            return Err(guest_session_error(
                &self.state.reference,
                "signal must be a Linux signal number from 1 through 64",
            ));
        }
        if *self.state.request_closed.borrow() {
            return Err(self.closed_request_error());
        }
        if !self.state.started.load(Ordering::Acquire) {
            self.close_requests();
            return Ok(());
        }
        self.send(ExecuteMessage::SignalProcess(SignalProcess {
            signal: Some(signal),
        }))
        .await
    }

    /// Finishes the request half without closing process stdin.
    /// Invalidates shared input and wakes pending sends; does not drop responses.
    /// See [execution examples](crate).
    pub fn close_requests(&self) {
        self.state.request_closed.send_replace(true);
        if let Ok(mut requests) = self.state.requests.lock() {
            requests.take();
        }
        self.state.input_open.store(false, Ordering::Release);
    }

    async fn send(&self, message: ExecuteMessage) -> Result<(), LibVmError> {
        let requests = self
            .state
            .requests
            .lock()
            .map_err(|_| {
                guest_session_error(&self.state.reference, "execution request lock is poisoned")
            })?
            .clone();
        let requests = requests.ok_or_else(|| self.closed_request_error())?;
        let mut request_closed = self.state.request_closed.subscribe();
        if *request_closed.borrow() {
            return Err(self.closed_request_error());
        }
        tokio::select! {
            biased;
            _ = request_closed.changed() => Err(self.closed_request_error()),
            result = requests.send(ExecuteInput { message: Some(message) }) =>
                result.map_err(|_| self.closed_request_error()),
        }
    }

    fn closed_request_error(&self) -> LibVmError {
        guest_session_error(&self.state.reference, "execution request stream is closed")
    }

    async fn send_stdin_data(&self, data: Vec<u8>) -> Result<(), LibVmError> {
        let _order = self.state.input_order.lock().await;
        self.ensure_started()?;
        if !self.state.input_open.load(Ordering::Acquire) {
            return Err(guest_session_error(
                &self.state.reference,
                "execution input is closed",
            ));
        }
        if data.is_empty() {
            return self
                .send(ExecuteMessage::StdinData(StdinData {
                    data: bytes::Bytes::new(),
                }))
                .await;
        }
        for data in stdin_chunks(data) {
            self.send(ExecuteMessage::StdinData(StdinData { data }))
                .await?;
        }
        Ok(())
    }

    fn ensure_started(&self) -> Result<(), LibVmError> {
        if self.state.started.load(Ordering::Acquire) {
            return Ok(());
        }
        Err(guest_session_error(
            &self.state.reference,
            "execution has not started",
        ))
    }
}

impl ExecutionStdin {
    /// Writes binary input with the same Started and ordering guarantees as controls.
    /// Closed/not-started input fails; writes serialize with EOF. See [examples](crate).
    pub async fn write(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.control.write_stdin(data).await
    }

    /// Sends pipe EOF exactly once; PTY EOF is not a pipe operation.
    /// Closed/not-started input and PTY mode fail. See [execution examples](crate).
    pub async fn close(&self) -> Result<(), LibVmError> {
        self.control.close_stdin().await
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
            initial_pty_size: None,
        }
    }
}

impl ExecutionOptionsBuilder {
    /// Sets initial PTY rows/columns; used only with tty. Later calls replace the size.
    /// See [execution examples](crate).
    pub fn initial_pty_size(mut self, rows: u16, columns: u16) -> Self {
        self.options.initial_pty_size = Some((rows, columns));
        self
    }
    /// Appends one literal argv element, without shell interpretation.
    /// See [execution examples](crate).
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }
    /// Appends literal argv elements in iterator order, without shell interpretation.
    /// See [execution examples](crate).
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }
    /// Sets the guest working directory; failures remain launch outcomes.
    /// See [execution examples](crate).
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }
    /// Sets the guest user, overriding the configured default execution user.
    /// See [execution examples](crate).
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }
    /// Appends one guest environment entry, without shell quoting.
    /// See [execution examples](crate).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }
    /// Appends guest environment entries in iterator order.
    /// See [execution examples](crate).
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
    /// Sets the collected execution timeout, applied after startup. Spawn ignores
    /// this as a deadline; manage the live session explicitly.
    /// See [execution examples](crate).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }
    /// Selects null pipe stdin (the default). PTY input policy remains separate.
    /// See [execution examples](crate).
    pub fn stdin_null(mut self) -> Self {
        self.options.stdin = StdinMode::Null;
        self
    }
    /// Selects live stdin. Access it only after receiving Started.
    /// See [execution examples](crate).
    pub fn stdin_pipe(mut self) -> Self {
        self.options.stdin = StdinMode::Pipe;
        self
    }
    /// Moves initial bytes into the request stream before Started, then sends pipe
    /// EOF. Later stdin setters replace this owned payload.
    /// See [execution examples](crate).
    pub fn stdin_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin = StdinMode::Bytes(data.into());
        self
    }
    /// Selects RPC PTY versus pipe stdio. Pipe-only CloseStdin is invalid for a PTY.
    /// See [execution examples](crate).
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }
    /// Sets the RPC PTY TERM value; used only with tty.
    /// See [execution examples](crate).
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }
    /// Consumes this builder into owned RPC process options.
    /// See [execution examples](crate).
    pub fn build(self) -> ExecutionOptions {
        self.options
    }
}

impl Machine {
    /// Runs literal argv through agent RPC and collects output. Shell syntax is not
    /// interpreted. Requires a running guest execution service; startup errors propagate.
    /// See the [literal argv example](crate).
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

    /// Configures literal argv RPC execution and buffers its result/output. A timeout
    /// applies only after startup; timeout cancels the session. See [examples](crate).
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

    /// Starts a caller-driven agent RPC execution. Consume Started before writing
    /// input, and keep consuming through terminal status. Drop invalidates controls
    /// and requests cancellation; see the [spawn example](crate).
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

    /// Configures a live agent RPC execution, including optional PTY. The timeout
    /// option does not create a spawn deadline. Startup errors propagate; session
    /// completion or drop invalidates controls. See [execution examples](crate).
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

    /// Collects `/bin/sh -l -c SCRIPT` through agent RPC. Login startup files apply;
    /// the caller is responsible for shell injection safety. Never concatenate
    /// untrusted input. See the [script example](crate).
    pub async fn exec_script(
        &self,
        script: impl Into<String>,
    ) -> Result<ExecutionOutput, LibVmError> {
        self.exec_script_with(script, |options| options).await
    }
    /// Configures the existing `/bin/sh -l -c SCRIPT` RPC convenience. Arguments
    /// configured here precede the convenience arguments. Timeout starts after
    /// startup; guest outcomes stay structured. See [execution examples](crate).
    pub async fn exec_script_with(
        &self,
        script: impl Into<String>,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionOutput, LibVmError> {
        self.exec_with("/bin/sh", |options| {
            configure(options).arg("-l").arg("-c").arg(script.into())
        })
        .await
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
        let stdin = std::mem::take(&mut options.stdin);
        let tty = options.tty;
        let pipe_stdin = !tty && matches!(stdin, StdinMode::Pipe | StdinMode::Bytes(_));
        let input_open = match &stdin {
            StdinMode::Null => tty,
            StdinMode::Pipe => true,
            StdinMode::Bytes(_) => false,
        };
        let process = process_spec(program, options, pipe_stdin);
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
            send_initial_stdin(&requests, &reference, data, pipe_stdin).await?;
        }
        Ok(ExecutionSession {
            control: ExecutionControl {
                state: Arc::new(ExecutionControlState {
                    reference,
                    requests: Mutex::new(Some(requests)),
                    input_open: AtomicBool::new(input_open),
                    started: AtomicBool::new(false),
                    input_order: AsyncMutex::new(()),
                    request_closed: watch::channel(false).0,
                    pipe_stdin,
                }),
            },
            events: Some(events),
        })
    }
}

fn stdin_chunks(data: Vec<u8>) -> impl Iterator<Item = bytes::Bytes> {
    let data = bytes::Bytes::from(data);
    (0..data.len())
        .step_by(EXECUTION_CHUNK_SIZE)
        .map(move |offset| data.slice(offset..(offset + EXECUTION_CHUNK_SIZE).min(data.len())))
}

async fn send_initial_stdin(
    requests: &mpsc::Sender<ExecuteInput>,
    reference: &str,
    data: Vec<u8>,
    pipe_stdin: bool,
) -> Result<(), LibVmError> {
    for data in stdin_chunks(data) {
        requests
            .send(ExecuteInput {
                message: Some(ExecuteMessage::StdinData(StdinData { data })),
            })
            .await
            .map_err(|_| guest_session_error(reference, "execution request stream is closed"))?;
    }
    if pipe_stdin {
        requests
            .send(ExecuteInput {
                message: Some(ExecuteMessage::CloseStdin(CloseStdin {})),
            })
            .await
            .map_err(|_| guest_session_error(reference, "execution request stream is closed"))?;
    }
    Ok(())
}

pub(super) fn current_run_id(reference: &str, status: &RuntimeStatus) -> Result<Uuid, LibVmError> {
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

fn process_spec(program: String, options: ExecutionOptions, pipe_stdin: bool) -> ProcessSpec {
    let mut argv = Vec::with_capacity(options.args.len() + 1);
    argv.push(program);
    argv.extend(options.args);
    let stdio = if options.tty {
        Some(protocol::v1::process_spec::Stdio::Pty(PtyStdio {
            initial_size: Some(
                options
                    .initial_pty_size
                    .map(|(rows, columns)| TerminalSize {
                        rows: u32::from(rows),
                        columns: u32::from(columns),
                    })
                    .unwrap_or_else(terminal_size),
            ),
            terminal: Some(options.term),
        }))
    } else {
        Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio {
            stdin: pipe_stdin,
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
    let (columns, rows) = host::current_terminal_size();
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

pub(super) fn guest_session_error(reference: &str, message: impl Into<String>) -> LibVmError {
    LibVmError::GuestSession {
        reference: reference.to_string(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use protocol::v1::execute_input::Message as ExecuteMessage;
    use tokio::sync::{watch, Mutex as AsyncMutex};

    use super::{
        apply_default_execution_user, execution_event_from_wire, mark_execution_started,
        process_spec, ExecutionControl, ExecutionControlState, ExecutionEvent, ExecutionLostReason,
        ExecutionOptions, ExecutionResult, StdinMode,
    };
    use crate::machine::MachineUserConfig;

    #[test]
    fn vmm_execution_process_spec_preserves_argv_environment_and_pipe_stdin() {
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
                initial_pty_size: None,
            },
            true,
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
    fn vmm_execution_process_spec_uses_current_terminal_fallback_for_pty() {
        let spec = process_spec(
            "sh".to_string(),
            ExecutionOptions {
                tty: true,
                ..ExecutionOptions::default()
            },
            false,
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
    fn vmm_execution_wire_lost_event_stays_a_lost_terminal_result() {
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
        let control = ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(false),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
        };
        let started = &control.state.started;

        assert!(control.stdin().is_none());
        assert!(control.write_stdin(b"before").await.is_err());
        assert!(control.resize_pty(24, 80).await.is_err());
        assert!(receiver.try_recv().is_err());

        mark_execution_started(&ExecutionEvent::Accepted, started);
        assert!(!started.load(Ordering::Acquire));
        mark_execution_started(&ExecutionEvent::Started, started);
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
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(pending_requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(false),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
        };

        pending
            .signal(libc::SIGINT as u32)
            .await
            .expect("cancel pending execution");
        assert!(pending_receiver.recv().await.is_none());

        let (running_requests, mut running_receiver) = tokio::sync::mpsc::channel(1);
        let running = ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(running_requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
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

    #[tokio::test]
    async fn vmm_execution_control_splits_large_stdin_without_losing_bytes() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(4);
        let control = ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
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
    fn vmm_execution_control_hides_unavailable_stdin() {
        let (requests, _receiver) = tokio::sync::mpsc::channel(1);
        let control = ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(false),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: false,
            }),
        };

        assert!(control.stdin().is_none());
    }

    #[tokio::test]
    async fn concurrent_stdin_closes_publish_exactly_one_eof() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(4);
        let control = ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
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
            state: Arc::new(ExecutionControlState {
                reference: "dev".to_string(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
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

    fn live_control(
        requests: tokio::sync::mpsc::Sender<protocol::v1::ExecuteInput>,
    ) -> ExecutionControl {
        ExecutionControl {
            state: Arc::new(ExecutionControlState {
                reference: "regression".into(),
                requests: Mutex::new(Some(requests)),
                input_open: AtomicBool::new(true),
                started: AtomicBool::new(true),
                input_order: AsyncMutex::new(()),
                request_closed: watch::channel(false).0,
                pipe_stdin: true,
            }),
        }
    }

    #[tokio::test]
    async fn binary_live_write_and_concurrent_eof_preserve_whole_input_order() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
        let control = live_control(requests);
        let input: Vec<u8> = (0..3 * protocol::CHUNK_64_KIB + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let writer = tokio::spawn({
            let control = control.clone();
            let input = input.clone();
            async move { control.write_stdin(input).await }
        });
        let first = receiver.recv().await.unwrap();
        let closer = tokio::spawn({
            let stdin = control.stdin().unwrap();
            async move { stdin.close().await }
        });
        let Some(ExecuteMessage::StdinData(first)) = first.message else {
            panic!("write must precede EOF");
        };
        let mut received = first.data.to_vec();
        loop {
            match receiver.recv().await.unwrap().message.unwrap() {
                ExecuteMessage::StdinData(data) => {
                    assert!(data.data.len() <= protocol::CHUNK_64_KIB);
                    received.extend_from_slice(&data.data);
                }
                ExecuteMessage::CloseStdin(_) => break,
                _ => panic!("unexpected request"),
            }
        }
        writer.await.unwrap().unwrap();
        closer.await.unwrap().unwrap();
        assert_eq!(received, input);
        assert!(control.close_stdin().await.is_err());
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn preloaded_binary_input_is_chunked_before_one_eof() {
        for input in [
            Vec::new(),
            (0..3 * protocol::CHUNK_64_KIB + 19)
                .map(|index| (index % 256) as u8)
                .collect(),
        ] {
            let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
            let sender = tokio::spawn({
                let input = input.clone();
                async move { super::send_initial_stdin(&requests, "preload", input, true).await }
            });
            let mut received = Vec::new();
            let mut eof = 0;
            while let Some(request) = receiver.recv().await {
                match request.message.unwrap() {
                    ExecuteMessage::StdinData(data) => {
                        assert!(!data.data.is_empty());
                        assert!(data.data.len() <= protocol::CHUNK_64_KIB);
                        received.extend_from_slice(&data.data);
                    }
                    ExecuteMessage::CloseStdin(_) => eof += 1,
                    _ => panic!("unexpected initial input"),
                }
            }
            sender.await.unwrap().unwrap();
            assert_eq!(received, input);
            assert_eq!(eof, 1);
        }
    }

    #[tokio::test]
    async fn session_drop_invalidates_surviving_controls_and_wakes_queued_write() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
        let control = live_control(requests);
        let stdin = control.stdin().unwrap();
        control.write_stdin(Vec::new()).await.unwrap();
        let pending = tokio::spawn({
            let stdin = stdin.clone();
            async move { stdin.write(vec![9]).await }
        });
        tokio::task::yield_now().await;
        drop(super::ExecutionSession {
            control: control.clone(),
            events: None,
        });
        assert!(pending.await.unwrap().is_err());
        assert!(stdin.write(Vec::new()).await.is_err());
        assert!(stdin.close().await.is_err());
        assert!(control.resize_pty(24, 80).await.is_err());
        assert!(control.signal(15).await.is_err());
        assert!(control.stdin().is_none());
        let Some(ExecuteMessage::StdinData(data)) = receiver.recv().await.unwrap().message else {
            panic!("expected live empty write");
        };
        assert!(data.data.is_empty());
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn invalid_prestart_signal_does_not_close_requests() {
        let (requests, mut receiver) = tokio::sync::mpsc::channel(1);
        let control = live_control(requests);
        control.state.started.store(false, Ordering::Release);
        assert!(control.signal(0).await.is_err());
        assert!(control.signal(65).await.is_err());
        assert!(receiver.try_recv().is_err());
        control.signal(15).await.unwrap();
        assert!(receiver.recv().await.is_none());
    }
}

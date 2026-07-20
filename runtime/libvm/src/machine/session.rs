use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::Msg as ClientMsg;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, ChannelWriteHalf, Sig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::machine::{Machine, MachineRef};
use crate::LibVmError;

const DEFAULT_TERM: &str = "xterm-256color";
const DEFAULT_ATTACH_DETACH_KEY: u8 = 0x1d;
const DEFAULT_LOGIN_SHELL_SCRIPT: &str = "exec \"${SHELL:-/bin/bash}\" -l || exec /bin/sh";
const EXEC_EVENT_QUEUE_CAPACITY: usize = 64;
const EXEC_STDIN_QUEUE_CAPACITY: usize = 64;
const SSH_HANDSHAKE_READY_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Options for running a guest command.
///
/// These options describe the process that runs inside the guest VM. The host
/// process only opens an internal transport to the guest and forwards data.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Command-line arguments passed after the executable.
    pub args: Vec<String>,
    /// Guest working directory for the command.
    pub cwd: Option<String>,
    /// Guest user for the command. Defaults to the configured guest user, then root.
    pub user: Option<String>,
    /// Environment variables set for the command.
    pub env: Vec<(String, String)>,
    /// Maximum runtime for captured execution.
    pub timeout: Option<Duration>,
    /// Stdin behavior for the command.
    pub stdin: StdinMode,
    /// Whether to allocate a guest PTY.
    pub tty: bool,
    /// Whether to forward the host SSH agent into the guest session.
    pub forward_agent: bool,
}

/// Builder for [`ExecOptions`].
#[derive(Debug, Default)]
pub struct ExecOptionsBuilder {
    options: ExecOptions,
}

/// Stdin behavior for guest execution.
#[derive(Debug, Clone, Default)]
pub enum StdinMode {
    /// Close stdin immediately.
    #[default]
    Null,
    /// Return an [`ExecSink`] so the caller can stream stdin.
    Pipe,
    /// Send these bytes to stdin, then close it.
    Bytes(Vec<u8>),
}

/// Output captured from a completed guest command.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Exit status for a guest command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    /// Numeric process exit code.
    pub code: i32,
    /// Whether the command exited with code 0.
    pub success: bool,
}

/// Streaming event from a guest command.
#[derive(Debug)]
pub enum ExecEvent {
    /// The SSH exec request was accepted by the guest.
    Started,
    /// Bytes written by the guest process to stdout.
    Stdout(Vec<u8>),
    /// Bytes written by the guest process to stderr.
    Stderr(Vec<u8>),
    /// The guest process exited.
    Exited { code: i32 },
    /// The guest failed the session before a normal exit status was available.
    Failed { message: String },
    /// Writing to stdin failed. The process may still emit more events.
    StdinError { message: String },
}

/// Handle for a streaming guest command.
pub struct ExecHandle {
    reference: String,
    events: mpsc::Receiver<ExecEvent>,
    stdin: Option<ExecSink>,
    control: ExecControl,
    _client: GuestSshClient,
}

/// Stdin writer for a streaming guest command.
pub struct ExecSink {
    reference: String,
    tx: mpsc::Sender<Vec<u8>>,
}

/// Cloneable control handle for a streaming guest command.
#[derive(Clone)]
pub struct ExecControl {
    reference: String,
    channel: Arc<ChannelWriteHalf<ClientMsg>>,
}

/// Options for attaching the host terminal to a guest process.
///
/// Attach requests a guest PTY, switches the host terminal to raw mode while
/// attached, forwards stdin/stdout, and returns the guest process exit code.
#[derive(Debug, Clone)]
pub struct AttachOptions {
    /// Command-line arguments passed after the executable.
    pub args: Vec<String>,
    /// Guest working directory for the attached process.
    pub cwd: Option<String>,
    /// Guest user for the attached process. Defaults to the provisioned Silo user.
    pub user: Option<String>,
    /// Environment variables set for the attached process.
    pub env: Vec<(String, String)>,
    /// Terminal name requested from the guest.
    pub term: String,
    /// Detach key sequence. Defaults to Ctrl+].
    pub detach_keys: Option<String>,
    /// Whether to forward the host SSH agent into the guest session.
    pub forward_agent: bool,
}

/// Builder for [`AttachOptions`].
#[derive(Debug, Default)]
pub struct AttachOptionsBuilder {
    options: AttachOptions,
}

struct GuestSshClient {
    reference: String,
    handle: russh::client::Handle<SshClientHandler>,
}

#[derive(Clone)]
struct SshClientHandler {
    agent_socket: Option<PathBuf>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            cwd: None,
            user: None,
            env: Vec::new(),
            timeout: None,
            stdin: StdinMode::Null,
            tty: false,
            forward_agent: false,
        }
    }
}

impl ExecOptionsBuilder {
    /// Append one command-line argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the guest working directory.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Run as a different guest user.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.options.env.extend(
            vars.into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    /// Set a timeout for captured execution.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }

    /// Close stdin immediately.
    pub fn stdin_null(mut self) -> Self {
        self.options.stdin = StdinMode::Null;
        self
    }

    /// Pipe stdin through [`ExecHandle::take_stdin`].
    pub fn stdin_pipe(mut self) -> Self {
        self.options.stdin = StdinMode::Pipe;
        self
    }

    /// Send fixed bytes to stdin, then close it.
    pub fn stdin_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin = StdinMode::Bytes(data.into());
        self
    }

    /// Allocate a guest PTY.
    pub fn tty(mut self, enabled: bool) -> Self {
        self.options.tty = enabled;
        self
    }

    /// Forward the host SSH agent into the guest session.
    pub fn forward_agent(mut self, enabled: bool) -> Self {
        self.options.forward_agent = enabled;
        self
    }

    /// Finalize the options.
    pub fn build(self) -> ExecOptions {
        self.options
    }
}

impl ExecOutput {
    fn from_parts(status: ExitStatus, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            status,
            stdout,
            stderr,
        }
    }

    /// Returns the exit status.
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    /// Returns stdout as bytes.
    pub fn stdout_bytes(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns stderr as bytes.
    pub fn stderr_bytes(&self) -> &[u8] {
        &self.stderr
    }

    /// Decodes stdout as UTF-8.
    pub fn stdout(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stdout.clone())
    }

    /// Decodes stderr as UTF-8.
    pub fn stderr(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.stderr.clone())
    }
}

impl ExecHandle {
    /// Receives the next event, or `None` when the session has ended.
    pub async fn recv(&mut self) -> Option<ExecEvent> {
        self.events.recv().await
    }

    /// Takes the stdin sink when this command was spawned with piped stdin.
    pub fn take_stdin(&mut self) -> Option<ExecSink> {
        self.stdin.take()
    }

    /// Returns a cloneable control handle for signals and PTY resize events.
    pub fn control(&self) -> ExecControl {
        self.control.clone()
    }

    /// Waits for process exit and returns its status.
    pub async fn wait(&mut self) -> Result<ExitStatus, LibVmError> {
        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Exited { code } => {
                    return Ok(ExitStatus {
                        code,
                        success: code == 0,
                    });
                }
                ExecEvent::Failed { message } => {
                    return Err(guest_session_error(&self.reference, message));
                }
                _ => {}
            }
        }

        Err(guest_session_error(
            &self.reference,
            "guest command ended without an exit status",
        ))
    }

    /// Waits for process exit and captures stdout/stderr.
    pub async fn collect(&mut self) -> Result<ExecOutput, LibVmError> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        while let Some(event) = self.events.recv().await {
            match event {
                ExecEvent::Started => {}
                ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
                ExecEvent::Stderr(data) => stderr.extend_from_slice(&data),
                ExecEvent::Exited { code } => {
                    exit_code = Some(code);
                    break;
                }
                ExecEvent::Failed { message } => {
                    return Err(guest_session_error(&self.reference, message));
                }
                ExecEvent::StdinError { .. } => {}
            }
        }

        let code = exit_code.ok_or_else(|| {
            guest_session_error(
                &self.reference,
                "guest command ended without an exit status",
            )
        })?;
        Ok(ExecOutput::from_parts(
            ExitStatus {
                code,
                success: code == 0,
            },
            stdout,
            stderr,
        ))
    }

    /// Sends a Unix signal to the guest process.
    pub async fn signal(&self, signal: i32) -> Result<(), LibVmError> {
        self.control.signal(signal).await
    }

    /// Sends SIGKILL to the guest process.
    pub async fn kill(&self) -> Result<(), LibVmError> {
        self.control.kill().await
    }

    /// Resizes the guest PTY.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<(), LibVmError> {
        self.control.resize(rows, cols).await
    }
}

impl ExecSink {
    /// Writes bytes to the guest process stdin.
    pub async fn write(&self, data: impl Into<Vec<u8>>) -> Result<(), LibVmError> {
        self.tx
            .send(data.into())
            .await
            .map_err(|_| guest_session_error(&self.reference, "guest stdin is closed"))
    }

    /// Closes stdin by dropping the sink.
    pub fn close(self) {}
}

impl ExecControl {
    /// Sends a Unix signal to the guest process.
    pub async fn signal(&self, signal: i32) -> Result<(), LibVmError> {
        let signal = ssh_signal(signal).ok_or_else(|| {
            guest_session_error(
                &self.reference,
                format!("unsupported guest signal number {signal}"),
            )
        })?;
        self.channel
            .signal(signal)
            .await
            .map_err(|error| ssh_error(&self.reference, "send signal", error))
    }

    /// Sends SIGKILL to the guest process.
    pub async fn kill(&self) -> Result<(), LibVmError> {
        self.signal(libc::SIGKILL).await
    }

    /// Resizes the guest PTY.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<(), LibVmError> {
        self.channel
            .window_change(u32::from(cols), u32::from(rows), 0, 0)
            .await
            .map_err(|error| ssh_error(&self.reference, "resize PTY", error))
    }
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            args: Vec::new(),
            cwd: None,
            user: None,
            env: Vec::new(),
            term: std::env::var("TERM").unwrap_or_else(|_| DEFAULT_TERM.to_string()),
            detach_keys: None,
            forward_agent: false,
        }
    }
}

impl AttachOptionsBuilder {
    /// Append one command-line argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.options.args.push(arg.into());
        self
    }

    /// Append multiple command-line arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.options.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set the guest working directory.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }

    /// Run as a different guest user.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }

    /// Add multiple environment variables.
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.options.env.extend(
            vars.into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    /// Set the terminal type requested from the guest.
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }

    /// Set Docker-style detach keys such as `ctrl-]` or `ctrl-p,ctrl-q`.
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }

    /// Forward the host SSH agent into the guest session.
    pub fn forward_agent(mut self, enabled: bool) -> Self {
        self.options.forward_agent = enabled;
        self
    }

    /// Finalize the options.
    pub fn build(self) -> AttachOptions {
        self.options
    }
}

impl Machine {
    /// Runs a guest executable, captures stdout/stderr, and returns its exit status.
    ///
    /// The `program` and `args` describe guest argv. They are shell-quoted before
    /// being sent through the current SSH-backed transport, so callers should pass
    /// arguments as separate values instead of building a shell string. Use
    /// [`Machine::shell`] when you intentionally want pipes, redirects, or other
    /// shell syntax.
    pub async fn exec<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExecOutput, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        self.exec_with(program, |command| command.args(args)).await
    }

    /// Runs a guest executable with custom options and captures output.
    pub async fn exec_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> Result<ExecOutput, LibVmError> {
        let options = configure(ExecOptionsBuilder::default()).build();
        let timeout = options.timeout;
        let mut handle = self.start_exec(program.into(), options).await?;
        if let Some(timeout) = timeout {
            match tokio::time::timeout(timeout, handle.collect()).await {
                Ok(result) => result,
                Err(_) => {
                    let _ = handle.kill().await;
                    Err(guest_session_error(
                        &handle.reference,
                        format!("guest command timed out after {}s", timeout.as_secs()),
                    ))
                }
            }
        } else {
            handle.collect().await
        }
    }

    /// Spawns a guest executable and returns a streaming handle.
    pub async fn spawn<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExecHandle, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        self.spawn_with(program, |command| command.args(args)).await
    }

    /// Spawns a guest executable with custom options and returns a streaming handle.
    pub async fn spawn_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> Result<ExecHandle, LibVmError> {
        let options = configure(ExecOptionsBuilder::default()).build();
        self.start_exec(program.into(), options).await
    }

    /// Runs a shell script inside the guest and captures output.
    ///
    /// This uses `/bin/sh -lc <script>` in the guest. Prefer [`Machine::exec`]
    /// for argv-safe command execution when shell syntax is not needed.
    pub async fn shell(&self, script: impl Into<String>) -> Result<ExecOutput, LibVmError> {
        self.shell_with(script, |command| command).await
    }

    /// Runs a shell script inside the guest with custom options.
    pub async fn shell_with(
        &self,
        script: impl Into<String>,
        configure: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> Result<ExecOutput, LibVmError> {
        let script = script.into();
        self.exec_with("/bin/sh", |command| {
            configure(command).arg("-lc").arg(script)
        })
        .await
    }

    /// Attaches the host terminal to a guest executable running in a PTY.
    pub async fn attach<I, S>(
        &self,
        program: impl Into<String>,
        args: I,
    ) -> Result<ExitStatus, LibVmError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        self.attach_with(program, |attach| attach.args(args)).await
    }

    /// Attaches the host terminal to a guest executable with custom options.
    pub async fn attach_with(
        &self,
        program: impl Into<String>,
        configure: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> Result<ExitStatus, LibVmError> {
        let options = configure(AttachOptionsBuilder::default()).build();
        self.attach_command(Some(program.into()), options).await
    }

    /// Attaches the host terminal to the guest user's default shell.
    pub async fn attach_shell(&self) -> Result<ExitStatus, LibVmError> {
        self.attach_shell_with(|attach| attach).await
    }

    /// Attaches the host terminal to the guest user's default shell with options.
    pub async fn attach_shell_with(
        &self,
        configure: impl FnOnce(AttachOptionsBuilder) -> AttachOptionsBuilder,
    ) -> Result<ExitStatus, LibVmError> {
        let options = configure(AttachOptionsBuilder::default()).build();
        self.attach_command(None, options).await
    }

    async fn start_exec(
        &self,
        program: String,
        options: ExecOptions,
    ) -> Result<ExecHandle, LibVmError> {
        let reference = self.inspect().await?.name;
        let client = self
            .connect_guest_ssh(&reference, options.user.as_deref(), options.forward_agent)
            .await?;
        let mut channel = open_session_channel(&client).await?;
        if options.tty {
            let (cols, rows) = current_terminal_size();
            channel
                .request_pty(true, DEFAULT_TERM, cols, rows, 0, 0, &[])
                .await
                .map_err(|error| ssh_error(&reference, "request PTY", error))?;
            wait_channel_success(&mut channel, &reference, "request PTY").await?;
        }
        if options.forward_agent {
            request_agent_forward(&mut channel, &reference).await?;
        }

        let stdin = options.stdin.clone();
        let command = command_line(&program, &options.args, &options);
        channel
            .exec(true, command)
            .await
            .map_err(|error| ssh_error(&reference, "send exec request", error))?;
        wait_channel_success(&mut channel, &reference, "exec request").await?;

        let (mut channel_rx, channel_tx) = channel.split();
        let channel_tx = Arc::new(channel_tx);
        let (events_tx, events_rx) = mpsc::channel(EXEC_EVENT_QUEUE_CAPACITY);
        events_tx
            .send(ExecEvent::Started)
            .await
            .map_err(|_| guest_session_error(&reference, "guest event stream is closed"))?;
        let reader_events_tx = events_tx.clone();
        spawn_exec_reader(reference.clone(), reader_events_tx.clone(), async move {
            while let Some(msg) = channel_rx.wait().await {
                if handle_exec_channel_msg(&reader_events_tx, msg).await {
                    break;
                }
            }
        });

        let stdin_sink = match stdin {
            StdinMode::Null => {
                channel_tx
                    .eof()
                    .await
                    .map_err(|error| ssh_error(&reference, "close stdin", error))?;
                None
            }
            StdinMode::Bytes(data) => {
                if !data.is_empty() {
                    channel_tx
                        .data_bytes(data)
                        .await
                        .map_err(|error| ssh_error(&reference, "write stdin", error))?;
                }
                channel_tx
                    .eof()
                    .await
                    .map_err(|error| ssh_error(&reference, "close stdin", error))?;
                None
            }
            StdinMode::Pipe => {
                let (stdin_tx, stdin_rx) = mpsc::channel(EXEC_STDIN_QUEUE_CAPACITY);
                spawn_stdin_writer(
                    reference.clone(),
                    Arc::clone(&channel_tx),
                    stdin_rx,
                    events_tx,
                );
                Some(ExecSink {
                    reference: reference.clone(),
                    tx: stdin_tx,
                })
            }
        };

        Ok(ExecHandle {
            reference: reference.clone(),
            events: events_rx,
            stdin: stdin_sink,
            control: ExecControl {
                reference,
                channel: channel_tx,
            },
            _client: client,
        })
    }

    async fn attach_command(
        &self,
        program: Option<String>,
        options: AttachOptions,
    ) -> Result<ExitStatus, LibVmError> {
        let reference = self.inspect().await?.name;
        let detach_keys = detach_sequence(options.detach_keys.as_deref()).map_err(|message| {
            guest_session_error(&reference, format!("invalid detach keys: {message}"))
        })?;
        let client = self
            .connect_guest_ssh(&reference, options.user.as_deref(), options.forward_agent)
            .await?;
        let mut channel = open_session_channel(&client).await?;
        let (cols, rows) = current_terminal_size();
        channel
            .request_pty(true, &options.term, cols, rows, 0, 0, &[])
            .await
            .map_err(|error| ssh_error(&reference, "request PTY", error))?;
        wait_channel_success(&mut channel, &reference, "request PTY").await?;
        if options.forward_agent {
            request_agent_forward(&mut channel, &reference).await?;
        }

        if let Some(program) = program {
            let command = command_line(&program, &options.args, &attach_as_exec_options(&options));
            channel
                .exec(true, command)
                .await
                .map_err(|error| ssh_error(&reference, "send exec request", error))?;
            wait_channel_success(&mut channel, &reference, "exec request").await?;
        } else if attach_shell_needs_exec(&options) {
            let command = attach_shell_command_line(&options);
            channel
                .exec(true, command)
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

        attach_stdio(reference, channel, detach_keys, client).await
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
        let started = Instant::now();
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
                Err(error) => {
                    let message = error.to_string();
                    if !is_transient_ssh_handshake_error(&message) {
                        return Err(ssh_error(reference, "client handshake", error));
                    }
                    if started.elapsed() >= SSH_HANDSHAKE_READY_TIMEOUT {
                        return Err(guest_session_error(
                            reference,
                            format!(
                                "SSH endpoint did not become handshake-ready within {:?}; last error: {message}",
                                SSH_HANDSHAKE_READY_TIMEOUT
                            ),
                        ));
                    }
                    tokio::time::sleep(SSH_HANDSHAKE_RETRY_DELAY).await;
                }
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

impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<ClientMsg>,
        _open_handle: russh::ChannelOpenHandleInner<ClientMsg>,
        _session: &mut russh::client::Session,
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

fn command_line(program: &str, args: &[String], options: &ExecOptions) -> String {
    let mut command = String::new();
    if let Some(cwd) = &options.cwd {
        command.push_str("cd ");
        command.push_str(&shell_quote(cwd));
        command.push_str(" && ");
    }
    command.push_str("exec ");
    if !options.env.is_empty() {
        command.push_str("env");
        for (key, value) in &options.env {
            command.push(' ');
            command.push_str(&shell_env_assignment(key, value));
        }
        command.push(' ');
    }
    command.push_str(&shell_quote(program));
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }
    command
}

fn attach_shell_needs_exec(options: &AttachOptions) -> bool {
    options.cwd.is_some() || !options.env.is_empty()
}

fn attach_shell_command_line(options: &AttachOptions) -> String {
    let args = vec!["-lc".to_string(), DEFAULT_LOGIN_SHELL_SCRIPT.to_string()];
    command_line("/bin/sh", &args, &attach_as_exec_options(options))
}

fn attach_as_exec_options(options: &AttachOptions) -> ExecOptions {
    ExecOptions {
        args: options.args.clone(),
        cwd: options.cwd.clone(),
        user: options.user.clone(),
        env: options.env.clone(),
        timeout: None,
        stdin: StdinMode::Pipe,
        tty: true,
        forward_agent: options.forward_agent,
    }
}

fn shell_env_assignment(key: &str, value: &str) -> String {
    format!("{}={}", shell_env_key(key), shell_quote(value))
}

fn shell_env_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn spawn_exec_reader<F>(reference: String, events_tx: mpsc::Sender<ExecEvent>, future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        future.await;
        drop(events_tx);
        drop(reference);
    });
}

async fn handle_exec_channel_msg(events_tx: &mpsc::Sender<ExecEvent>, msg: ChannelMsg) -> bool {
    match msg {
        ChannelMsg::Data { data } => events_tx
            .send(ExecEvent::Stdout(data.to_vec()))
            .await
            .is_err(),
        ChannelMsg::ExtendedData { data, .. } => events_tx
            .send(ExecEvent::Stderr(data.to_vec()))
            .await
            .is_err(),
        ChannelMsg::ExitStatus { exit_status } => events_tx
            .send(ExecEvent::Exited {
                code: exit_status as i32,
            })
            .await
            .is_err(),
        ChannelMsg::ExitSignal {
            signal_name,
            error_message,
            ..
        } => {
            let message = if error_message.is_empty() {
                format!("guest process exited by signal {signal_name:?}")
            } else {
                error_message
            };
            if events_tx
                .send(ExecEvent::Stderr(message.into_bytes()))
                .await
                .is_err()
            {
                return true;
            }
            events_tx
                .send(ExecEvent::Exited { code: 128 })
                .await
                .is_err()
        }
        ChannelMsg::Close => true,
        _ => false,
    }
}

fn spawn_stdin_writer(
    reference: String,
    channel: Arc<ChannelWriteHalf<ClientMsg>>,
    mut stdin_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<ExecEvent>,
) {
    tokio::spawn(async move {
        while let Some(data) = stdin_rx.recv().await {
            if let Err(error) = channel.data_bytes(data).await {
                let _ = events_tx
                    .send(ExecEvent::StdinError {
                        message: format!("write stdin for {reference}: {error}"),
                    })
                    .await;
                return;
            }
        }
        if let Err(error) = channel.eof().await {
            let _ = events_tx
                .send(ExecEvent::StdinError {
                    message: format!("close stdin for {reference}: {error}"),
                })
                .await;
        }
    });
}

async fn attach_stdio(
    reference: String,
    channel: Channel<ClientMsg>,
    detach_keys: Vec<u8>,
    _client: GuestSshClient,
) -> Result<ExitStatus, LibVmError> {
    let _raw_terminal = RawTerminalGuard::new().map_err(|error| {
        guest_session_error(&reference, format!("enable raw terminal: {error}"))
    })?;
    let (mut channel_rx, channel_tx) = channel.split();
    let channel_tx = Arc::new(channel_tx);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut input_buf = [0_u8; 1024];
    let mut match_pos = 0usize;
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
            read = stdin.read(&mut input_buf), if !stdin_closed => {
                let read = read.map_err(|error| guest_session_error(&reference, format!("read terminal input: {error}")))?;
                if read == 0 {
                    stdin_closed = true;
                    channel_tx
                        .eof()
                        .await
                        .map_err(|error| ssh_error(&reference, "close terminal input", error))?;
                    continue;
                }
                let data = &input_buf[..read];
                if input_contains_detach_sequence(data, &detach_keys, &mut match_pos) {
                    detached = true;
                    break;
                }
                channel_tx
                    .data_bytes(data.to_vec())
                    .await
                    .map_err(|error| ssh_error(&reference, "write terminal input", error))?;
            }
            resized = resize_signal.recv(), if resize_signal_open => {
                if resized.is_none() {
                    resize_signal_open = false;
                    continue;
                }
                resize_attached_pty(&reference, channel_tx.as_ref()).await?;
            }
            msg = channel_rx.wait() => {
                let Some(msg) = msg else {
                    break;
                };
                match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        stdout
                            .write_all(&data)
                            .await
                            .map_err(|error| guest_session_error(&reference, format!("write terminal output: {error}")))?;
                        stdout
                            .flush()
                            .await
                            .map_err(|error| guest_session_error(&reference, format!("flush terminal output: {error}")))?;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i32);
                    }
                    ChannelMsg::ExitSignal { .. } => {
                        exit_code = Some(128);
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        }
    }

    attached_exit_status(&reference, exit_code, detached)
}

fn attached_exit_status(
    reference: &str,
    exit_code: Option<i32>,
    detached: bool,
) -> Result<ExitStatus, LibVmError> {
    if let Some(code) = exit_code {
        return Ok(ExitStatus {
            code,
            success: code == 0,
        });
    }

    if detached {
        return Ok(ExitStatus {
            code: 0,
            success: true,
        });
    }

    Err(guest_session_error(
        reference,
        "attached guest session ended without an exit status",
    ))
}

async fn resize_attached_pty(
    reference: &str,
    channel: &ChannelWriteHalf<ClientMsg>,
) -> Result<(), LibVmError> {
    let (cols, rows) = current_terminal_size();
    channel
        .window_change(cols, rows, 0, 0)
        .await
        .map_err(|error| ssh_error(reference, "resize PTY", error))
}

fn detach_sequence(spec: Option<&str>) -> Result<Vec<u8>, String> {
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
                        return Err(format!("invalid detach key {part:?}"));
                    }
                }
                _ => return Err(format!("invalid detach key {part:?}")),
            };
            sequence.push(byte);
        } else if part.len() == 1 {
            sequence.push(part.as_bytes()[0]);
        } else {
            return Err(format!("invalid detach key {part:?}"));
        }
    }

    if sequence.is_empty() {
        sequence.push(DEFAULT_ATTACH_DETACH_KEY);
    }
    Ok(sequence)
}

fn input_contains_detach_sequence(data: &[u8], sequence: &[u8], match_pos: &mut usize) -> bool {
    for &byte in data {
        if byte == sequence[*match_pos] {
            *match_pos += 1;
            if *match_pos == sequence.len() {
                *match_pos = 0;
                return true;
            }
        } else {
            *match_pos = usize::from(byte == sequence[0]);
        }
    }
    false
}

fn current_terminal_size() -> (u32, u32) {
    let stdout = std::io::stdout();
    let fd = stdout.as_raw_fd();
    let mut size = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
        && size.ws_row > 0
    {
        (u32::from(size.ws_col), u32::from(size.ws_row))
    } else {
        (80, 24)
    }
}

fn ssh_signal(signal: i32) -> Option<Sig> {
    match signal {
        libc::SIGABRT => Some(Sig::ABRT),
        libc::SIGALRM => Some(Sig::ALRM),
        libc::SIGFPE => Some(Sig::FPE),
        libc::SIGHUP => Some(Sig::HUP),
        libc::SIGILL => Some(Sig::ILL),
        libc::SIGINT => Some(Sig::INT),
        libc::SIGKILL => Some(Sig::KILL),
        libc::SIGPIPE => Some(Sig::PIPE),
        libc::SIGQUIT => Some(Sig::QUIT),
        libc::SIGSEGV => Some(Sig::SEGV),
        libc::SIGTERM => Some(Sig::TERM),
        libc::SIGUSR1 => Some(Sig::USR1),
        _ => None,
    }
}

fn resolve_agent_socket(
    reference: &str,
    forward_agent: bool,
) -> Result<Option<PathBuf>, LibVmError> {
    resolve_agent_socket_from_env(reference, forward_agent, std::env::var_os("SSH_AUTH_SOCK"))
}

fn resolve_agent_socket_from_env(
    reference: &str,
    forward_agent: bool,
    socket: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, LibVmError> {
    if !forward_agent {
        return Ok(None);
    }

    #[cfg(unix)]
    {
        let socket = socket.filter(|value| !value.as_os_str().is_empty());
        socket.map(PathBuf::from).map(Some).ok_or_else(|| {
            guest_session_error(
                reference,
                "SSH agent forwarding requested, but SSH_AUTH_SOCK is not set",
            )
        })
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
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
    let message = message.to_ascii_lowercase();
    [
        "disconnected",
        "connection reset",
        "unexpected eof",
        "connection aborted",
        "connection refused",
    ]
    .iter()
    .any(|needle| message.contains(needle))
        || message == "eof"
        || message.ends_with(" eof")
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
        let stdin = std::io::stdin();
        let fd = stdin.as_fd().try_clone_to_owned()?;
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
    use crate::machine::session::{
        attach_shell_command_line, attached_exit_status, command_line, detach_sequence,
        input_contains_detach_sequence, is_transient_ssh_handshake_error,
        resolve_agent_socket_from_env, AttachOptions, AttachOptionsBuilder, ExecOptions,
        ExecOptionsBuilder, StdinMode,
    };
    use crate::LibVmError;

    #[test]
    fn command_line_quotes_argv_and_options() {
        let options = ExecOptions {
            args: vec!["hello world".to_string(), "it's fine".to_string()],
            cwd: Some("/work dir".to_string()),
            user: None,
            env: vec![("RUST_LOG".to_string(), "info debug".to_string())],
            timeout: None,
            stdin: StdinMode::Null,
            tty: false,
            forward_agent: false,
        };

        assert_eq!(
            command_line("cargo test", &options.args, &options),
            "cd '/work dir' && exec env RUST_LOG='info debug' 'cargo test' 'hello world' 'it'\"'\"'s fine'"
        );
    }

    #[test]
    fn exec_options_builder_sets_forward_agent() {
        let options = ExecOptionsBuilder::default().forward_agent(true).build();

        assert!(options.forward_agent);
    }

    #[test]
    fn attach_options_builder_sets_forward_agent() {
        let options = AttachOptionsBuilder::default().forward_agent(true).build();

        assert!(options.forward_agent);
    }

    #[test]
    fn transient_ssh_handshake_errors_are_retried() {
        assert!(is_transient_ssh_handshake_error("Disconnected"));
        assert!(is_transient_ssh_handshake_error("connection reset by peer"));
        assert!(is_transient_ssh_handshake_error("unexpected EOF"));
        assert!(!is_transient_ssh_handshake_error(
            "public-key authentication failed"
        ));
        assert!(!is_transient_ssh_handshake_error(
            "invalid SSH identification string"
        ));
    }

    #[test]
    fn attach_shell_command_line_applies_cwd_and_env() {
        let options = AttachOptions {
            args: Vec::new(),
            cwd: Some("/work dir".to_string()),
            user: None,
            env: vec![("FOO".to_string(), "bar baz".to_string())],
            term: "xterm".to_string(),
            detach_keys: None,
            forward_agent: false,
        };

        assert_eq!(
            attach_shell_command_line(&options),
            "cd '/work dir' && exec env FOO='bar baz' '/bin/sh' '-lc' 'exec \"${SHELL:-/bin/bash}\" -l || exec /bin/sh'"
        );
    }

    #[test]
    fn attached_exit_status_uses_observed_status() {
        let status = attached_exit_status("dev", Some(42), false).expect("status should resolve");

        assert_eq!(status.code, 42);
        assert!(!status.success);
    }

    #[test]
    fn attached_exit_status_allows_explicit_detach_without_guest_status() {
        let status = attached_exit_status("dev", None, true).expect("detach should resolve");

        assert_eq!(status.code, 0);
        assert!(status.success);
    }

    #[test]
    fn attached_exit_status_errors_without_status_or_detach() {
        let error = attached_exit_status("dev", None, false)
            .expect_err("missing status should fail attached session");

        let LibVmError::GuestSession { reference, message } = error else {
            panic!("expected guest session error");
        };
        assert_eq!(reference, "dev");
        assert_eq!(
            message,
            "attached guest session ended without an exit status"
        );
    }

    #[test]
    fn agent_socket_not_required_when_forwarding_is_disabled() {
        let socket = resolve_agent_socket_from_env("dev", false, None)
            .expect("disabled forwarding should not inspect SSH_AUTH_SOCK");

        assert_eq!(socket, None);
    }

    #[cfg(unix)]
    #[test]
    fn agent_socket_uses_ssh_auth_sock_when_forwarding_is_enabled() {
        let socket = resolve_agent_socket_from_env(
            "dev",
            true,
            Some(std::ffi::OsString::from("/tmp/agent.sock")),
        )
        .expect("socket should resolve");

        assert_eq!(socket, Some(std::path::PathBuf::from("/tmp/agent.sock")));
    }

    #[cfg(unix)]
    #[test]
    fn agent_socket_requires_ssh_auth_sock_when_forwarding_is_enabled() {
        let error = resolve_agent_socket_from_env("dev", true, None)
            .expect_err("missing socket should fail");

        let LibVmError::GuestSession { reference, message } = error else {
            panic!("expected guest session error");
        };
        assert_eq!(reference, "dev");
        assert_eq!(
            message,
            "SSH agent forwarding requested, but SSH_AUTH_SOCK is not set"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn agent_socket_rejects_forwarding_on_non_unix_hosts() {
        let error = resolve_agent_socket_from_env("dev", true, None)
            .expect_err("non-Unix hosts should fail");

        let LibVmError::GuestSession { reference, message } = error else {
            panic!("expected guest session error");
        };
        assert_eq!(reference, "dev");
        assert_eq!(
            message,
            "SSH agent forwarding is only supported on Unix hosts"
        );
    }

    #[test]
    fn detach_sequence_defaults_to_ctrl_bracket() {
        assert_eq!(detach_sequence(None).expect("default keys"), vec![0x1d]);
        assert_eq!(
            detach_sequence(Some("ctrl-p,ctrl-q")).expect("keys"),
            vec![0x10, 0x11]
        );
    }

    #[test]
    fn input_detects_detach_sequence_across_chunks() {
        let sequence = vec![0x10, 0x11];
        let mut pos = 0;
        assert!(!input_contains_detach_sequence(
            b"abc\x10", &sequence, &mut pos
        ));
        assert!(input_contains_detach_sequence(
            b"\x11def", &sequence, &mut pos
        ));
    }
}

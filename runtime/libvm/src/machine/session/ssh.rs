//! Certificate-authenticated SSH setup, relay, and connection ownership.
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::Msg as ClientMsg;
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::machine::session::host::{
    self, AttachmentSignal, LocalAdapter, LocalInput, LocalReader, Signals,
};
use crate::machine::session::{current_run_id, guest_session_error};
use crate::machine::Machine;
use crate::LibVmError;

pub(super) const DEFAULT_TERM: &str = "xterm-256color";
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_LOGIN_SHELL_SCRIPT: &str = "exec \"${SHELL:-/bin/bash}\" -l || exec /bin/sh";

type Reader = Pin<Box<dyn AsyncRead + Send>>;
type Writer = Pin<Box<dyn AsyncWrite + Send>>;

/// Owned, one-call SSH I/O, with no host terminal or process-signal side effects.
/// Both dimensions must be positive. Input EOF sends channel EOF, not Ctrl-D.
/// See the supplied-attachment example in the [crate execution guide](crate).
pub struct SshShellAttachment {
    stdin: Reader,
    stdout: Writer,
    stderr: Writer,
    rows: u16,
    columns: u16,
    controls: Option<mpsc::Receiver<SshShellControl>>,
}
impl std::fmt::Debug for SshShellAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshShellAttachment")
            .field("rows", &self.rows)
            .field("columns", &self.columns)
            .field("io", &"owned asynchronous streams")
            .field("controls", &self.controls.is_some())
            .finish()
    }
}
impl SshShellAttachment {
    /// Takes ownership of the streams once; output channels remain distinct.
    /// Stalled I/O is interruptible by operation cancellation. See [crate].
    pub fn new<R, W, E>(stdin: R, stdout: W, stderr: E, rows: u16, columns: u16) -> Self
    where
        R: AsyncRead + Send + 'static,
        W: AsyncWrite + Send + 'static,
        E: AsyncWrite + Send + 'static,
    {
        Self {
            stdin: Box::pin(stdin),
            stdout: Box::pin(stdout),
            stderr: Box::pin(stderr),
            rows,
            columns,
            controls: None,
        }
    }
    /// Supplies typed controls. Closure disables controls without ending the shell.
    /// Replaces a previous receiver; see the [crate execution guide](crate).
    pub fn controls(mut self, controls: mpsc::Receiver<SshShellControl>) -> Self {
        self.controls = Some(controls);
        self
    }
}

/// Signals supported by SSH and Linux guests. See [SshShellControl].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshShellSignal {
    Hup,
    Int,
    Quit,
    Ill,
    Abrt,
    Fpe,
    Kill,
    Usr1,
    Segv,
    Usr2,
    Pipe,
    Alrm,
    Term,
}
impl SshShellSignal {
    /// Accepts only supported Linux signal numbers, independent of host numbering.
    pub fn from_linux(signal: u32) -> Option<Self> {
        Some(match signal {
            1 => Self::Hup,
            2 => Self::Int,
            3 => Self::Quit,
            4 => Self::Ill,
            6 => Self::Abrt,
            8 => Self::Fpe,
            9 => Self::Kill,
            10 => Self::Usr1,
            11 => Self::Segv,
            12 => Self::Usr2,
            13 => Self::Pipe,
            14 => Self::Alrm,
            15 => Self::Term,
            _ => return None,
        })
    }
    fn ssh(self) -> russh::Sig {
        match self {
            Self::Hup => russh::Sig::HUP,
            Self::Int => russh::Sig::INT,
            Self::Quit => russh::Sig::QUIT,
            Self::Ill => russh::Sig::ILL,
            Self::Abrt => russh::Sig::ABRT,
            Self::Fpe => russh::Sig::FPE,
            Self::Kill => russh::Sig::KILL,
            Self::Usr1 => russh::Sig::USR1,
            Self::Segv => russh::Sig::SEGV,
            Self::Usr2 => russh::Sig::Custom("USR2".to_string()),
            Self::Pipe => russh::Sig::PIPE,
            Self::Alrm => russh::Sig::ALRM,
            Self::Term => russh::Sig::TERM,
        }
    }
}
/// Caller-driven SSH controls. Resize dimensions must both be positive.
/// No host terminal query or remote WINCH conversion occurs; see [SshShellAttachment].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshShellControl {
    Resize { rows: u16, columns: u16 },
    Signal(SshShellSignal),
}

/// SSH login-shell configuration. Streams are owned and consumed once, not cloned.
/// Cwd/env use a quoted exec wrapper; without them this sends an SSH shell request.
/// See [Machine::shell_with] and the [crate execution guide](crate).
#[derive(Debug)]
pub struct SshShellOptions {
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub env: Vec<(String, String)>,
    pub term: String,
    pub detach_keys: Option<String>,
    pub forward_agent: bool,
    best_effort_cwd: bool,
    attachment: Option<SshShellAttachment>,
    local_signals: Option<mpsc::Receiver<AttachmentSignal>>,
    cancellation: Option<CancellationToken>,
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
            attachment: None,
            local_signals: None,
            cancellation: None,
        }
    }
}
/// Configures one SSH operation; owned setters replace previous values.
/// See [Machine::shell_with] for local and supplied-I/O examples.
#[derive(Debug, Default)]
pub struct SshShellOptionsBuilder {
    options: SshShellOptions,
}
impl SshShellOptionsBuilder {
    /// Requests a quoted directory change before login; failures normally abort. See [Machine::shell_with].
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.options.cwd = Some(cwd.into());
        self
    }
    /// Selects the certificate principal; defaults to the configured guest user or root. See [Machine::shell_with].
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.options.user = Some(user.into());
        self
    }
    /// Supplies a quoted environment assignment through the exec wrapper, not AcceptEnv. See [Machine::shell_with].
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }
    /// Sets the guest PTY TERM, defaulting to host TERM or xterm-256color. See [Machine::shell_with].
    pub fn term(mut self, term: impl Into<String>) -> Self {
        self.options.term = term.into();
        self
    }
    /// Configures local detach keys. Invalid with supplied I/O; default is Ctrl+]. See [Machine::shell_with].
    pub fn detach_keys(mut self, keys: impl Into<String>) -> Self {
        self.options.detach_keys = Some(keys.into());
        self
    }
    /// Explicitly enables host SSH-agent forwarding, requiring SSH_AUTH_SOCK and guest acknowledgement. See [Machine::shell_with].
    pub fn forward_agent(mut self, enabled: bool) -> Self {
        self.options.forward_agent = enabled;
        self
    }
    #[doc(hidden)]
    pub fn best_effort_cwd(mut self) -> Self {
        self.options.best_effort_cwd = true;
        self
    }
    /// Uses only supplied streams, size and controls, with transparent bytes. See [SshShellAttachment].
    pub fn attachment(mut self, attachment: SshShellAttachment) -> Self {
        self.options.attachment = Some(attachment);
        self
    }
    /// Replaces automatic signal subscriptions in local mode only. See [AttachmentSignal].
    pub fn local_signals(mut self, signals: mpsc::Receiver<AttachmentSignal>) -> Self {
        self.options.local_signals = Some(signals);
        self
    }
    /// Observes the caller token without canceling it. Awaited return includes wire release;
    /// dropping the future only requests cancellation through RAII. See [Machine::shell_with].
    pub fn cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.options.cancellation = Some(cancellation);
        self
    }
    /// Consumes the builder for one operation; see [Machine::shell_with].
    pub fn build(self) -> SshShellOptions {
        self.options
    }
}
/// SSH result: signal exits map to 128, local detach to successful zero.
/// Transport loss, cancellation, or missing terminal status is an error, not a result.
/// See [Machine::shell].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshExitStatus {
    pub code: i32,
    pub success: bool,
}

pub(super) struct TransportGuard(pub CancellationToken);
impl Drop for TransportGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Cancellation wakes russh and releases the actual wire, then acknowledges release.
pub(super) struct CancellableStream<S> {
    stream: Option<S>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: Option<oneshot::Sender<()>>,
}
impl<S> CancellableStream<S> {
    fn new(stream: S, cancel: CancellationToken, closed: oneshot::Sender<()>) -> Self {
        Self {
            stream: Some(stream),
            cancelled: Box::pin(cancel.cancelled_owned()),
            closed: Some(closed),
        }
    }
    fn release(&mut self) {
        drop(self.stream.take());
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.release();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SSH session cancelled",
            ));
        }
        Ok(())
    }
}
impl<S> Drop for CancellableStream<S> {
    fn drop(&mut self) {
        self.release();
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for CancellableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_read(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into())),
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CancellableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into())),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_flush(cx),
            None => Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        match self.stream.as_mut() {
            Some(stream) => Pin::new(stream).poll_shutdown(cx),
            None => Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into())),
        }
    }
}

struct GuestSshClient {
    handle: Option<russh::client::Handle<SshClientHandler>>,
    transport: TransportGuard,
    closed: Option<oneshot::Receiver<()>>,
    forwarding: TaskTracker,
}
impl GuestSshClient {
    fn new() -> Self {
        Self {
            handle: None,
            transport: TransportGuard(CancellationToken::new()),
            closed: None,
            forwarding: TaskTracker::new(),
        }
    }
    async fn finish(
        &mut self,
        mut channel: Option<ChannelWriteHalf<ClientMsg>>,
        graceful: bool,
        cancellation: &CancellationToken,
    ) {
        let mut joined = false;
        if graceful {
            let graceful = async {
                if let Some(channel) = channel.take() {
                    let _ = channel.close().await;
                    drop(channel);
                }
                if let Some(handle) = self.handle.as_mut() {
                    let _ = handle
                        .disconnect(russh::Disconnect::ByApplication, "shell finished", "en")
                        .await;
                    let _ = handle.await;
                }
            };
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {},
                result = tokio::time::timeout(SHUTDOWN_TIMEOUT, graceful) => joined = result.is_ok(),
            }
        }
        drop(channel.take());
        self.transport.0.cancel();
        // This drains an acknowledgement, not an additional network grace period.
        if let Some(closed) = self.closed.take() {
            let _ = closed.await;
        }
        if !joined {
            if let Some(handle) = self.handle.as_mut() {
                let _ = handle.await;
            }
        }
        self.handle.take();
        self.forwarding.close();
        self.forwarding.wait().await;
    }
}
#[derive(Clone)]
struct SshClientHandler {
    agent_socket: Option<PathBuf>,
    expected_key: ssh_key::PublicKey,
    cancellation: CancellationToken,
    forwarding: TaskTracker,
}
impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(key.key_data() == self.expected_key.key_data())
    }
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<ClientMsg>,
        reply: russh::ChannelOpenHandleInner<ClientMsg>,
        _: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        #[cfg(unix)]
        if let Some(socket) = self.agent_socket.clone() {
            let cancel = self.cancellation.clone();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                _ = reply.accept() => {},
            }
            self.forwarding.spawn(async move {
                let mut guest = channel.into_stream();
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {},
                    _ = async {
                        if let Ok(mut host) = tokio::net::UnixStream::connect(socket).await {
                            let _ = tokio::io::copy_bidirectional(&mut guest, &mut host).await;
                        }
                    } => {},
                }
            });
        }
        #[cfg(not(unix))]
        let _ = channel;
        Ok(())
    }
}

impl Machine {
    /// Opens a local interactive SSH login over vsock 22, returning SSH status.
    /// Requires Running/non-stopping generation, immutable pin and accepted certificate,
    /// not fresh agent readiness. Owns local raw mode/input until return. See [crate].
    pub async fn shell(&self) -> Result<SshExitStatus, LibVmError> {
        self.shell_with(|options| options).await
    }
    /// Configures a certificate-authenticated SSH login, never process RPC.
    /// Setup has one 30-second budget. Cancellation covers setup and stalled I/O;
    /// awaited completion releases the wire, while future drop only requests cancellation.
    /// See the local and supplied examples in the [crate execution guide](crate).
    pub async fn shell_with(
        &self,
        configure: impl FnOnce(SshShellOptionsBuilder) -> SshShellOptionsBuilder,
    ) -> Result<SshExitStatus, LibVmError> {
        let mut options = configure(SshShellOptionsBuilder::default()).build();
        let (sequence, command) = validate_options(&options)?;
        let cancellation = options.cancellation.take().unwrap_or_default();
        if cancellation.is_cancelled() {
            return Err(guest_session_error("shell", "SSH shell cancelled"));
        }
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let mut client = GuestSshClient::new();
        let mut channel = None;
        let mut reference = "shell".to_string();
        let mut pending = EarlyMessages::default();
        let size = options
            .attachment
            .as_ref()
            .map(|a| (u32::from(a.columns), u32::from(a.rows)))
            .unwrap_or_else(host::current_terminal_size);
        let setup = async {
            let config = self.running_config().await?;
            reference = config.name.clone();
            self.connect_guest_ssh(
                &config,
                &reference,
                options.user.as_deref(),
                options.forward_agent,
                &mut client,
            )
            .await?;
            let handle = client
                .handle
                .as_ref()
                .ok_or_else(|| guest_session_error(&reference, "SSH connection is closed"))?;
            channel = Some(
                handle
                    .channel_open_session()
                    .await
                    .map_err(|e| ssh_error(&reference, "open session channel", e))?,
            );
            let channel = channel
                .as_mut()
                .ok_or_else(|| guest_session_error(&reference, "SSH channel is closed"))?;
            request_shell(
                channel,
                &reference,
                &options.term,
                options.forward_agent,
                size,
                &mut pending,
                command,
            )
            .await
        };
        let setup_result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(guest_session_error("shell", "SSH shell cancelled")),
            result = tokio::time::timeout_at(deadline, setup) => result.unwrap_or_else(|_| Err(guest_session_error("shell", "SSH shell setup timed out"))),
        };
        let (mut receiver, mut sender) = channel
            .take()
            .map(Channel::split)
            .map_or((None, None), |(receiver, sender)| {
                (Some(receiver), Some(sender))
            });
        let result = match setup_result {
            Err(error) => Err(error),
            Ok(()) => match (receiver.as_mut(), sender.as_ref()) {
                (Some(receiver), Some(sender)) => {
                    let io = match options.attachment.take() {
                        Some(attachment) => Ok(RelayIo::supplied(attachment)),
                        None => {
                            LocalAdapter::new(&reference, sequence, options.local_signals.take())
                                .map(RelayIo::local)
                        }
                    };
                    match io {
                        Ok(io) => {
                            relay(&reference, receiver, sender, io, pending, &cancellation).await
                        }
                        Err(error) => Err(error),
                    }
                }
                _ => Err(guest_session_error(&reference, "SSH channel is closed")),
            },
        };
        // Wake any backpressured russh channel delivery before awaiting wire release.
        drop(receiver.take());
        client
            .finish(sender.take(), result.is_ok(), &cancellation)
            .await;
        if result.is_ok() && cancellation.is_cancelled() {
            return Err(guest_session_error(&reference, "SSH shell cancelled"));
        }
        result
    }
    async fn connect_guest_ssh(
        &self,
        config: &crate::store::models::MachineConfig,
        reference: &str,
        user: Option<&str>,
        forward_agent: bool,
        client: &mut GuestSshClient,
    ) -> Result<(), LibVmError> {
        let status = self
            .runtime()
            .reconcile_machine_runtime_best_effort(config)
            .await?;
        let run_id = current_run_id(reference, &status)?;
        let expected_key =
            utils::ssh::read_host_key_pin(self.runtime().machine_paths(self.machine_id()).dir())
                .map_err(|e| {
                    guest_session_error(reference, format!("guest SSH host key is not pinned: {e}"))
                })?;
        let agent_socket = resolve_agent_socket(reference, forward_agent)?;
        let user = user.map(str::to_owned).unwrap_or_else(|| {
            config
                .guest
                .user
                .as_ref()
                .map(|user| user.name.clone())
                .unwrap_or_else(|| "root".to_string())
        });
        let (private_key, certificate) =
            crate::ssh_ca::issue(self.runtime().secret_store(), self.machine_id(), &user).map_err(
                |e| guest_session_error(reference, format!("issue SSH certificate: {e}")),
            )?;
        let handle = loop {
            let stream = self.open_shell_stream().await?;
            let (closed, receiver) = oneshot::channel();
            client.closed = Some(receiver);
            match russh::client::connect_stream(
                Arc::new(Default::default()),
                CancellableStream::new(stream, client.transport.0.clone(), closed),
                SshClientHandler {
                    agent_socket: agent_socket.clone(),
                    expected_key: expected_key.clone(),
                    cancellation: client.transport.0.clone(),
                    forwarding: client.forwarding.clone(),
                },
            )
            .await
            {
                Ok(handle) => break handle,
                Err(error) if is_transient_ssh_handshake_error(&error.to_string()) => {
                    if let Some(closed) = client.closed.take() {
                        let _ = closed.await;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(ssh_error(reference, "client handshake", error)),
            }
        };
        client.handle = Some(handle);
        let auth = client
            .handle
            .as_mut()
            .ok_or_else(|| guest_session_error(reference, "SSH connection is closed"))?
            .authenticate_openssh_cert(user, private_key, certificate)
            .await
            .map_err(|e| ssh_error(reference, "public-key authentication", e))?;
        if !auth.success() {
            return Err(guest_session_error(
                reference,
                "SSH public-key authentication failed",
            ));
        }
        let current = self
            .runtime()
            .reconcile_machine_runtime_best_effort(config)
            .await?;
        if current_run_id(reference, &current)? != run_id {
            return Err(guest_session_error(
                reference,
                "machine run changed during SSH setup",
            ));
        }
        Ok(())
    }
}

fn validate_options(options: &SshShellOptions) -> Result<(Vec<u8>, Option<String>), LibVmError> {
    let sequence = if let Some(attachment) = &options.attachment {
        if attachment.rows == 0 || attachment.columns == 0 {
            return Err(guest_session_error(
                "shell",
                "SSH attachment dimensions must be positive",
            ));
        }
        if options.local_signals.is_some() || options.detach_keys.is_some() {
            return Err(guest_session_error(
                "shell",
                "supplied SSH attachment cannot use local signals or detach keys",
            ));
        }
        Vec::new()
    } else {
        host::detach_sequence(options.detach_keys.as_deref())?
    };
    let command = if options.cwd.is_some() || !options.env.is_empty() {
        Some(ssh_shell_command(options)?)
    } else {
        None
    };
    Ok((sequence, command))
}
#[derive(Default)]
struct EarlyMessages {
    messages: VecDeque<ChannelMsg>,
    bytes: usize,
}
impl EarlyMessages {
    fn push(&mut self, reference: &str, message: ChannelMsg) -> Result<(), LibVmError> {
        let payload = match &message {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => data.len(),
            _ => 0,
        };
        if self.messages.len() >= 64 || self.bytes + payload > 65536 {
            return Err(guest_session_error(
                reference,
                "SSH early-message buffer exceeded setup limit",
            ));
        }
        self.bytes += payload;
        self.messages.push_back(message);
        Ok(())
    }
}
async fn wait_channel_success(
    channel: &mut Channel<ClientMsg>,
    reference: &str,
    context: &str,
    pending: &mut EarlyMessages,
) -> Result<(), LibVmError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(guest_session_error(
                    reference,
                    format!("SSH {context} failed"),
                ))
            }
            Some(ChannelMsg::Close) | None => {
                return Err(guest_session_error(
                    reference,
                    format!("SSH channel closed during {context}"),
                ))
            }
            Some(
                message @ (ChannelMsg::Data { .. }
                | ChannelMsg::ExtendedData { .. }
                | ChannelMsg::ExitStatus { .. }
                | ChannelMsg::ExitSignal { .. }
                | ChannelMsg::Eof),
            ) => pending.push(reference, message)?,
            _ => {}
        }
    }
}

enum Input {
    Supplied(Reader),
    Local(Box<LocalReader>),
}
enum Controls {
    Supplied(mpsc::Receiver<SshShellControl>),
    Local(Signals),
}
impl Controls {
    async fn recv(&mut self) -> Option<SshShellControl> {
        match self {
            Self::Supplied(receiver) => receiver.recv().await,
            Self::Local(signals) => signals.recv().await,
        }
    }
}
enum InputRead {
    Supplied(usize),
    Local(LocalInput),
}
impl Input {
    async fn read(&mut self, buffer: &mut bytes::BytesMut) -> io::Result<InputRead> {
        match self {
            Self::Supplied(reader) => {
                if buffer.capacity() == 0 {
                    buffer.reserve(65536);
                }
                reader.read_buf(buffer).await.map(InputRead::Supplied)
            }
            Self::Local(reader) => reader.read().await.map(InputRead::Local),
        }
    }
}
struct RelayIo {
    input: Input,
    controls: Option<Controls>,
    stdout: Writer,
    stderr: Writer,
}
impl RelayIo {
    fn supplied(attachment: SshShellAttachment) -> Self {
        Self {
            input: Input::Supplied(attachment.stdin),
            controls: attachment.controls.map(Controls::Supplied),
            stdout: attachment.stdout,
            stderr: attachment.stderr,
        }
    }
    fn local(adapter: LocalAdapter) -> Self {
        let (input, signals) = adapter.into_parts();
        // Local terminal presentation deliberately merges extended output.
        Self {
            input: Input::Local(Box::new(input)),
            controls: Some(Controls::Local(signals)),
            stdout: Box::pin(host::LocalOutput::new()),
            stderr: Box::pin(host::LocalOutput::new()),
        }
    }
}
async fn interrupt<T>(
    reference: &str,
    cancellation: &CancellationToken,
    peer_deadline: Option<Instant>,
    future: impl Future<Output = Result<T, LibVmError>>,
) -> Result<T, LibVmError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(guest_session_error(reference, "SSH shell cancelled")),
        _ = async { if let Some(deadline) = peer_deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } } => Err(guest_session_error(reference, "SSH peer stopped before channel closure")),
        result = future => result,
    }
}
#[derive(Default)]
struct RelayState {
    exit_code: Option<i32>,
    peer_deadline: Option<Instant>,
    input_closed: bool,
    channel_closed: bool,
}
async fn receive_peer(
    reference: &str,
    message: Option<ChannelMsg>,
    io: &mut RelayIo,
    state: &mut RelayState,
    cancellation: &CancellationToken,
) -> Result<(), LibVmError> {
    // Only peer messages refresh the budget. Output delivery suspends its countdown.
    if state.peer_deadline.is_some() {
        state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
    }
    match message {
        Some(ChannelMsg::Data { data }) => {
            interrupt(reference, cancellation, None, async {
                io.stdout
                    .write_all(&data)
                    .await
                    .map_err(|e| guest_session_error(reference, format!("write SSH stdout: {e}")))
            })
            .await?;
            if state.peer_deadline.is_some() {
                state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
            }
        }
        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
            interrupt(reference, cancellation, None, async {
                io.stderr
                    .write_all(&data)
                    .await
                    .map_err(|e| guest_session_error(reference, format!("write SSH stderr: {e}")))
            })
            .await?;
            if state.peer_deadline.is_some() {
                state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
            }
        }
        Some(ChannelMsg::ExitStatus { exit_status }) => {
            state.exit_code = Some(exit_status as i32);
            state.input_closed = true;
            state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
        }
        Some(ChannelMsg::ExitSignal { .. }) => {
            state.exit_code = Some(128);
            state.input_closed = true;
            state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT);
        }
        Some(ChannelMsg::Eof) => state.peer_deadline = Some(Instant::now() + SHUTDOWN_TIMEOUT),
        Some(ChannelMsg::Close) | None => {
            state.channel_closed = true;
            state.peer_deadline = None;
        }
        _ => {}
    }
    Ok(())
}
/// Receive peer traffic while an outbound operation is flow-controlled. Otherwise
/// a process that exits without reading stdin could strand the relay in a send.
async fn send_while_receiving(
    reference: &str,
    receiver: &mut ChannelReadHalf,
    io: &mut RelayIo,
    state: &mut RelayState,
    controls_sender: Option<&ChannelWriteHalf<ClientMsg>>,
    cancellation: &CancellationToken,
    send: impl Future<Output = Result<(), LibVmError>>,
) -> Result<(), LibVmError> {
    let mut send = std::pin::pin!(send);
    loop {
        enum Event {
            Sent(Result<(), LibVmError>),
            Peer(Option<ChannelMsg>),
            Control(Option<SshShellControl>),
        }
        let event = interrupt(reference, cancellation, state.peer_deadline, async {
            Ok(tokio::select! {
                result = &mut send => Event::Sent(result),
                message = receiver.wait() => Event::Peer(message),
                control = async { match io.controls.as_mut() { Some(controls) => controls.recv().await, None => std::future::pending().await } }, if controls_sender.is_some() && io.controls.is_some() && state.exit_code.is_none() => Event::Control(control),
            })
        })
        .await?;
        match event {
            Event::Sent(result) => return result,
            Event::Peer(message) => {
                receive_peer(reference, message, io, state, cancellation).await?;
                if state.channel_closed || state.exit_code.is_some() {
                    return Ok(());
                }
            }
            Event::Control(None) => io.controls = None,
            Event::Control(Some(control)) => {
                if let Some(sender) = controls_sender {
                    let mut control_send = std::pin::pin!(send_control(reference, sender, control));
                    let mut input_sent = false;
                    loop {
                        enum ControlEvent {
                            Sent(Result<(), LibVmError>),
                            Input(Result<(), LibVmError>),
                            Peer(Option<ChannelMsg>),
                        }
                        let event = interrupt(reference, cancellation, state.peer_deadline, async {
                            Ok(tokio::select! {
                                result = &mut control_send => ControlEvent::Sent(result),
                                result = &mut send, if !input_sent => ControlEvent::Input(result),
                                message = receiver.wait() => ControlEvent::Peer(message),
                            })
                        }).await?;
                        match event {
                            ControlEvent::Sent(result) => {
                                result?;
                                if input_sent {
                                    return Ok(());
                                }
                                break;
                            }
                            ControlEvent::Input(result) => {
                                result?;
                                input_sent = true;
                            }
                            ControlEvent::Peer(message) => {
                                receive_peer(reference, message, io, state, cancellation).await?;
                                if state.channel_closed || state.exit_code.is_some() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
async fn send_control(
    reference: &str,
    sender: &ChannelWriteHalf<ClientMsg>,
    control: SshShellControl,
) -> Result<(), LibVmError> {
    match control {
        SshShellControl::Resize { rows, columns } => {
            if rows == 0 || columns == 0 {
                return Err(guest_session_error(
                    reference,
                    "SSH resize dimensions must be positive",
                ));
            }
            sender
                .window_change(u32::from(columns), u32::from(rows), 0, 0)
                .await
                .map_err(|e| ssh_error(reference, "resize PTY", e))
        }
        SshShellControl::Signal(signal) => sender
            .signal(signal.ssh())
            .await
            .map_err(|e| ssh_error(reference, "send signal", e)),
    }
}
async fn relay(
    reference: &str,
    receiver: &mut ChannelReadHalf,
    sender: &ChannelWriteHalf<ClientMsg>,
    mut io: RelayIo,
    mut pending: EarlyMessages,
    cancellation: &CancellationToken,
) -> Result<SshExitStatus, LibVmError> {
    let mut buffer = bytes::BytesMut::new();
    let mut state = RelayState::default();
    while !state.channel_closed {
        enum Event {
            Input(io::Result<InputRead>),
            Control(Option<SshShellControl>),
            Peer(Option<ChannelMsg>),
        }
        let event = if let Some(message) = pending.messages.pop_front() {
            Event::Peer(Some(message))
        } else {
            interrupt(reference, cancellation, state.peer_deadline, async {
                Ok(tokio::select! {
                    message = receiver.wait() => Event::Peer(message),
                    input = io.input.read(&mut buffer), if !state.input_closed => Event::Input(input),
                    control = async { match io.controls.as_mut() { Some(controls) => controls.recv().await, None => std::future::pending().await } }, if io.controls.is_some() && state.exit_code.is_none() => Event::Control(control),
                })
            }).await?
        };
        match event {
            Event::Input(input) => {
                let input = input
                    .map_err(|e| guest_session_error(reference, format!("read SSH input: {e}")))?;
                match input {
                    InputRead::Supplied(0) | InputRead::Local(LocalInput::Eof) => {
                        state.input_closed = true;
                        send_while_receiving(
                            reference,
                            receiver,
                            &mut io,
                            &mut state,
                            Some(sender),
                            cancellation,
                            async {
                                sender
                                    .eof()
                                    .await
                                    .map_err(|e| ssh_error(reference, "close input", e))
                            },
                        )
                        .await?;
                    }
                    InputRead::Local(LocalInput::Detach) => {
                        return Ok(SshExitStatus {
                            code: 0,
                            success: true,
                        })
                    }
                    InputRead::Supplied(_) => {
                        let bytes = buffer.split().freeze();
                        send_while_receiving(
                            reference,
                            receiver,
                            &mut io,
                            &mut state,
                            Some(sender),
                            cancellation,
                            async {
                                sender
                                    .data_bytes(bytes)
                                    .await
                                    .map_err(|e| ssh_error(reference, "write input", e))
                            },
                        )
                        .await?;
                    }
                    InputRead::Local(LocalInput::Bytes(bytes)) => {
                        send_while_receiving(
                            reference,
                            receiver,
                            &mut io,
                            &mut state,
                            Some(sender),
                            cancellation,
                            async {
                                sender
                                    .data_bytes(bytes)
                                    .await
                                    .map_err(|e| ssh_error(reference, "write input", e))
                            },
                        )
                        .await?;
                    }
                }
            }
            Event::Control(None) => io.controls = None,
            Event::Control(Some(control)) => {
                send_while_receiving(
                    reference,
                    receiver,
                    &mut io,
                    &mut state,
                    None,
                    cancellation,
                    send_control(reference, sender, control),
                )
                .await?;
            }
            Event::Peer(message) => {
                receive_peer(reference, message, &mut io, &mut state, cancellation).await?
            }
        }
    }
    interrupt(reference, cancellation, None, async {
        io.stdout
            .flush()
            .await
            .map_err(|e| guest_session_error(reference, format!("flush SSH stdout: {e}")))?;
        io.stderr
            .flush()
            .await
            .map_err(|e| guest_session_error(reference, format!("flush SSH stderr: {e}")))
    })
    .await?;
    let code = state.exit_code.ok_or_else(|| {
        guest_session_error(reference, "SSH session ended without an exit status")
    })?;
    Ok(SshExitStatus {
        code,
        success: code == 0,
    })
}

fn ssh_shell_command(options: &SshShellOptions) -> Result<String, LibVmError> {
    let mut command = String::new();
    if let Some(cwd) = &options.cwd {
        command.push_str("cd ");
        command.push_str(&quote_ssh_shell_argument(cwd));
        command.push_str(if options.best_effort_cwd {
            " 2>/dev/null || true; "
        } else {
            " && "
        });
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
    command.push_str("/bin/sh -l -c ");
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
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
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

async fn request_shell(
    channel: &mut Channel<ClientMsg>,
    reference: &str,
    term: &str,
    forward_agent: bool,
    size: (u32, u32),
    pending: &mut EarlyMessages,
    command: Option<String>,
) -> Result<(), LibVmError> {
    channel
        .request_pty(true, term, size.0, size.1, 0, 0, &[])
        .await
        .map_err(|e| ssh_error(reference, "request PTY", e))?;
    wait_channel_success(channel, reference, "PTY request", pending).await?;
    if forward_agent {
        channel
            .agent_forward(true)
            .await
            .map_err(|e| ssh_error(reference, "request agent forwarding", e))?;
        wait_channel_success(channel, reference, "agent forwarding", pending).await?;
    }
    if let Some(command) = command {
        channel
            .exec(true, command)
            .await
            .map_err(|e| ssh_error(reference, "request login command", e))?;
    } else {
        channel
            .request_shell(true)
            .await
            .map_err(|e| ssh_error(reference, "request shell", e))?;
    }
    wait_channel_success(channel, reference, "shell request", pending).await
}

#[cfg(test)]
mod tests {
    use crate::machine::session::ssh::*;
    use russh::server::{Auth, ChannelOpenHandle, Session};
    use russh::ChannelId;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::{Mutex, Notify};

    struct PausedRead<S> {
        stream: S,
        paused: Arc<AtomicBool>,
    }
    impl<S: AsyncRead + Unpin> AsyncRead for PausedRead<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.paused.load(Ordering::Acquire) {
                Poll::Pending
            } else {
                Pin::new(&mut self.stream).poll_read(cx, buffer)
            }
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for PausedRead<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, bytes)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }
    struct StalledFlush(Arc<Notify>);
    impl AsyncWrite for StalledFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.notify_one();
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    struct FailedOutput;
    impl AsyncWrite for FailedOutput {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("caller output failed")))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Output {
        fn bytes(&self) -> Vec<u8> {
            self.0.try_lock().unwrap().clone()
        }
    }
    impl AsyncWrite for Output {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.try_lock().unwrap().extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    struct StalledOutput(Arc<Notify>);
    impl AsyncWrite for StalledOutput {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.notify_one();
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    struct SlowOutput {
        output: Output,
        delay: Pin<Box<tokio::time::Sleep>>,
    }
    impl AsyncWrite for SlowOutput {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            Pin::new(&mut self.output).poll_write(cx, bytes)
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[derive(Clone, Copy)]
    enum Mode {
        Normal,
        Early,
        OverflowBytes,
        OverflowMessages,
        Withhold,
        MissingStatus,
        StatusWithoutClose,
        Flood,
        BlockInput,
        ExitWithoutInput,
        EofWithoutInput,
        SignalExit,
        PauseReads,
        SignalAfterBlockedInput,
        WithholdAuthentication,
    }
    struct ShellServer {
        observations: mpsc::UnboundedSender<String>,
        mode: Mode,
        paused: Arc<AtomicBool>,
        forwarding: TaskTracker,
        cancellation: CancellationToken,
    }
    impl russh::server::Handler for ShellServer {
        type Error = russh::Error;
        async fn auth_publickey(
            &mut self,
            user: &str,
            _: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            assert_eq!(user, "alice");
            Ok(Auth::Accept)
        }
        async fn auth_openssh_certificate(
            &mut self,
            user: &str,
            _: &ssh_key::Certificate,
        ) -> Result<Auth, Self::Error> {
            assert_eq!(user, "alice");
            if matches!(self.mode, Mode::WithholdAuthentication) {
                self.observations
                    .send("certificate-authentication".into())
                    .unwrap();
                self.cancellation.cancelled().await;
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                });
            }
            Ok(Auth::Accept)
        }
        async fn channel_open_session(
            &mut self,
            _: Channel<russh::server::Msg>,
            reply: ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            term: &str,
            columns: u32,
            rows: u32,
            _: u32,
            _: u32,
            _: &[(russh::Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations
                .send(format!("pty:{term}:{rows}:{columns}"))
                .unwrap();
            session.channel_success(channel)?;
            Ok(())
        }
        async fn shell_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations.send("shell".into()).unwrap();
            match self.mode {
                Mode::Early => {
                    session.exit_status_request(channel, 7)?;
                    session.data(channel, b"early-out".to_vec())?;
                    session.extended_data(channel, 1, b"early-err".to_vec())?;
                    session.eof(channel)?;
                }
                Mode::OverflowBytes => {
                    session.data(channel, vec![b'x'; 65537])?;
                }
                Mode::OverflowMessages => {
                    for _ in 0..65 {
                        session.data(channel, vec![b'x'])?;
                    }
                }
                Mode::Withhold => return Ok(()),
                _ => {}
            }
            session.channel_success(channel)?;
            if matches!(self.mode, Mode::Early) {
                session.close(channel)?;
            }
            if matches!(self.mode, Mode::Flood) {
                session.data(channel, vec![b'o'; 196613])?;
                session.extended_data(channel, 1, vec![b'e'; 196619])?;
            }
            if matches!(self.mode, Mode::ExitWithoutInput | Mode::SignalExit) {
                if matches!(self.mode, Mode::SignalExit) {
                    session.exit_signal_request(channel, russh::Sig::TERM, false, "", "en")?;
                } else {
                    session.exit_status_request(channel, 7)?;
                }
                session.data(channel, b"after-status".to_vec())?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            if matches!(self.mode, Mode::EofWithoutInput) {
                session.eof(channel)?;
            }
            if matches!(self.mode, Mode::PauseReads) {
                self.paused.store(true, Ordering::Release);
            }
            Ok(())
        }
        async fn exec_request(
            &mut self,
            channel: ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations
                .send(format!("exec:{}", String::from_utf8_lossy(command)))
                .unwrap();
            session.channel_success(channel)?;
            Ok(())
        }
        async fn agent_request(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            session.channel_success(channel)?;
            let handle = session.handle();
            let cancellation = self.cancellation.clone();
            self.forwarding.spawn(async move {
                tokio::select! {
                    _ = cancellation.cancelled() => {},
                    _ = async {
                        if let Ok(channel) = handle.channel_open_agent().await {
                            let _ = channel.data_bytes(b"agent-request".to_vec()).await;
                            std::future::pending::<()>().await;
                        }
                    } => {},
                }
            });
            Ok(true)
        }
        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())?;
            Ok(())
        }
        async fn window_change_request(
            &mut self,
            _: ChannelId,
            columns: u32,
            rows: u32,
            _: u32,
            _: u32,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations
                .send(format!("resize:{rows}:{columns}"))
                .unwrap();
            Ok(())
        }
        async fn signal(
            &mut self,
            channel: ChannelId,
            signal: russh::Sig,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let name = match signal {
                russh::Sig::Custom(name) => name,
                other => format!("{other:?}"),
            };
            self.observations.send(format!("signal:{name}")).unwrap();
            if matches!(self.mode, Mode::SignalAfterBlockedInput) && name == "INT" {
                session.exit_status_request(channel, 130)?;
                session.data(channel, b"interrupted-unread-input".to_vec())?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Ok(())
        }
        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations.send("eof".into()).unwrap();
            session.data(channel, b"last-output".to_vec())?;
            session.extended_data(channel, 1, b"last-error".to_vec())?;
            session.eof(channel)?;
            if !matches!(self.mode, Mode::MissingStatus) {
                session.exit_status_request(channel, 7)?;
            }
            if !matches!(self.mode, Mode::MissingStatus | Mode::StatusWithoutClose) {
                session.close(channel)?;
            }
            Ok(())
        }
    }
    struct Fixture {
        client: GuestSshClient,
        channel: Option<Channel<ClientMsg>>,
        sender: Option<ChannelWriteHalf<ClientMsg>>,
        observations: mpsc::UnboundedReceiver<String>,
        server: tokio::task::JoinHandle<()>,
        server_guard: TransportGuard,
        server_forwarding: TaskTracker,
    }
    async fn fixture(mode: Mode, wrong_pin: bool) -> Result<Fixture, russh::Error> {
        fixture_with_agent(mode, wrong_pin, None).await
    }
    async fn fixture_with_agent(
        mode: Mode,
        wrong_pin: bool,
        agent_socket: Option<PathBuf>,
    ) -> Result<Fixture, russh::Error> {
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]));
        let other =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[43; 32]));
        let pin = if wrong_pin {
            other.public_key().clone()
        } else {
            key.public_key().clone()
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let (observations, receiver) = mpsc::unbounded_channel();
        let server_guard = TransportGuard(CancellationToken::new());
        let server_forwarding = TaskTracker::new();
        let cancellation = server_guard.0.clone();
        let forwarding = server_forwarding.clone();
        let server = tokio::spawn(async move {
            let config = russh::server::Config {
                keys: vec![key],
                window_size: if matches!(
                    mode,
                    Mode::BlockInput
                        | Mode::ExitWithoutInput
                        | Mode::EofWithoutInput
                        | Mode::SignalExit
                        | Mode::SignalAfterBlockedInput
                ) {
                    0
                } else {
                    2097152
                },
                ..Default::default()
            };
            let paused = Arc::new(AtomicBool::new(false));
            let (closed, _receiver) = oneshot::channel();
            let stream = CancellableStream::new(
                PausedRead {
                    stream: peer,
                    paused: paused.clone(),
                },
                cancellation.clone(),
                closed,
            );
            if let Ok(server) = russh::server::run_stream(
                Arc::new(config),
                stream,
                ShellServer {
                    observations,
                    mode,
                    cancellation,
                    forwarding,
                    paused,
                },
            )
            .await
            {
                let _ = server.await;
            }
        });
        let mut client = GuestSshClient::new();
        let (closed, receiver_closed) = oneshot::channel();
        client.closed = Some(receiver_closed);
        let connected = russh::client::connect_stream(
            Arc::new(russh::client::Config {
                channel_buffer_size: 4,
                ..Default::default()
            }),
            CancellableStream::new(socket, client.transport.0.clone(), closed),
            SshClientHandler {
                agent_socket,
                expected_key: pin,
                cancellation: client.transport.0.clone(),
                forwarding: client.forwarding.clone(),
            },
        )
        .await;
        let handle = match connected {
            Ok(handle) => handle,
            Err(error) => {
                client.finish(None, false, &CancellationToken::new()).await;
                tokio::time::timeout(Duration::from_secs(3), server)
                    .await
                    .unwrap()
                    .unwrap();
                return Err(error);
            }
        };
        client.handle = Some(handle);
        let channel = if matches!(mode, Mode::WithholdAuthentication) {
            None
        } else {
            let handle = client.handle.as_mut().unwrap();
            assert!(handle
                .authenticate_publickey(
                    "alice",
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(other), None)
                )
                .await?
                .success());
            Some(handle.channel_open_session().await?)
        };
        Ok(Fixture {
            client,
            channel,
            sender: None,
            observations: receiver,
            server,
            server_guard,
            server_forwarding,
        })
    }
    async fn start(fixture: &mut Fixture, options: &SshShellOptions) -> EarlyMessages {
        let mut pending = EarlyMessages::default();
        let (_, command) = validate_options(options).unwrap();
        tokio::time::timeout(
            Duration::from_secs(3),
            request_shell(
                fixture.channel.as_mut().unwrap(),
                "fixture",
                &options.term,
                options.forward_agent,
                (119, 37),
                &mut pending,
                command,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        pending
    }
    async fn relay_fixture(
        reference: &str,
        fixture: &mut Fixture,
        io: RelayIo,
        pending: EarlyMessages,
        token: &CancellationToken,
    ) -> Result<SshExitStatus, LibVmError> {
        let (mut receiver, sender) = fixture.channel.take().unwrap().split();
        fixture.sender = Some(sender);
        relay(
            reference,
            &mut receiver,
            fixture.sender.as_ref().unwrap(),
            io,
            pending,
            token,
        )
        .await
    }
    async fn finish(mut fixture: Fixture, success: bool) {
        let sender = fixture
            .sender
            .take()
            .or_else(|| fixture.channel.take().map(|channel| channel.split().1));
        fixture
            .client
            .finish(sender, success, &CancellationToken::new())
            .await;
        fixture.server_guard.0.cancel();
        fixture.server_forwarding.close();
        fixture.server_forwarding.wait().await;
        tokio::time::timeout(Duration::from_secs(3), fixture.server)
            .await
            .unwrap()
            .unwrap();
    }
    fn attachment(input: impl AsyncRead + Send + 'static) -> (SshShellAttachment, Output, Output) {
        let stdout = Output::default();
        let stderr = Output::default();
        (
            SshShellAttachment::new(input, stdout.clone(), stderr.clone(), 37, 119),
            stdout,
            stderr,
        )
    }
    fn options() -> SshShellOptions {
        SshShellOptionsBuilder::default().term("vt100").build()
    }

    #[test]
    fn supplied_configuration_is_validated_without_host_resources() {
        let make = || {
            SshShellAttachment::new(
                tokio::io::empty(),
                tokio::io::sink(),
                tokio::io::sink(),
                37,
                119,
            )
        };
        assert!(
            validate_options(&SshShellOptionsBuilder::default().attachment(make()).build()).is_ok()
        );
        assert!(validate_options(
            &SshShellOptionsBuilder::default()
                .attachment(make())
                .detach_keys("ctrl-]")
                .build()
        )
        .is_err());
        let (_sender, receiver) = mpsc::channel(1);
        assert!(validate_options(
            &SshShellOptionsBuilder::default()
                .attachment(make())
                .local_signals(receiver)
                .build()
        )
        .is_err());
        for (rows, columns) in [(0, 119), (37, 0)] {
            let attachment = SshShellAttachment::new(
                tokio::io::empty(),
                tokio::io::sink(),
                tokio::io::sink(),
                rows,
                columns,
            );
            assert!(validate_options(
                &SshShellOptionsBuilder::default()
                    .attachment(attachment)
                    .build()
            )
            .is_err());
        }
        assert!(validate_options(
            &SshShellOptionsBuilder::default()
                .env("BAD;echo", "x")
                .build()
        )
        .is_err());
    }
    #[tokio::test]
    async fn real_shell_transparent_bytes_controls_stderr_and_nonzero_status() {
        let mut fixture = fixture(Mode::Normal, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        assert_eq!(
            fixture.observations.recv().await.unwrap(),
            "pty:vt100:37:119"
        );
        assert_eq!(fixture.observations.recv().await.unwrap(), "shell");
        let (mut input, reader) = tokio::io::duplex(65536);
        let (attachment, stdout, stderr) = attachment(reader);
        let (sender, controls) = mpsc::channel(64);
        let attachment = attachment.controls(controls);
        let mut observations =
            std::mem::replace(&mut fixture.observations, mpsc::unbounded_channel().1);
        let worker = tokio::spawn(async move {
            sender
                .send(SshShellControl::Resize {
                    rows: 50,
                    columns: 120,
                })
                .await
                .unwrap();
            for number in [1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 13, 14, 15] {
                sender
                    .send(SshShellControl::Signal(
                        SshShellSignal::from_linux(number).unwrap(),
                    ))
                    .await
                    .unwrap();
            }
            // Wait for every control to arrive before closing input and ending the remote process.
            for expected in [
                "resize:50:120",
                "signal:HUP",
                "signal:INT",
                "signal:QUIT",
                "signal:ILL",
                "signal:ABRT",
                "signal:FPE",
                "signal:KILL",
                "signal:USR1",
                "signal:SEGV",
                "signal:USR2",
                "signal:PIPE",
                "signal:ALRM",
                "signal:TERM",
            ] {
                assert_eq!(observations.recv().await.unwrap(), expected);
            }
            input.write_all(b"literal:$HOME;\x1d\0\xff").await.unwrap();
            input.shutdown().await.unwrap();
            observations
        });
        let status = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        fixture.observations = worker.await.unwrap();
        assert_eq!(fixture.observations.recv().await.unwrap(), "eof");
        assert!(fixture.observations.try_recv().is_err());
        assert_eq!(
            status,
            SshExitStatus {
                code: 7,
                success: false
            }
        );
        assert_eq!(stdout.bytes(), b"literal:$HOME;\x1d\0\xfflast-output");
        assert_eq!(stderr.bytes(), b"last-error");
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn early_output_and_status_are_replayed_in_order() {
        let mut fixture = fixture(Mode::Early, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let (attachment, stdout, stderr) = attachment(tokio::io::empty());
        let status = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(status.code, 7);
        assert_eq!(stdout.bytes(), b"early-out");
        assert_eq!(stderr.bytes(), b"early-err");
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn early_message_limits_reject_real_transport_overflow() {
        for mode in [Mode::OverflowBytes, Mode::OverflowMessages] {
            let mut fixture = fixture(mode, false).await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                request_shell(
                    fixture.channel.as_mut().unwrap(),
                    "fixture",
                    "xterm-256color",
                    false,
                    (119, 37),
                    &mut EarlyMessages::default(),
                    None,
                ),
            )
            .await
            .unwrap();
            assert!(result.unwrap_err().to_string().contains("buffer exceeded"));
            finish(fixture, false).await;
        }
    }
    #[tokio::test]
    async fn withheld_acknowledgement_is_cancellable_and_deadline_bounded() {
        for cancel in [false, true] {
            let mut fixture = fixture(Mode::Withhold, false).await.unwrap();
            let token = CancellationToken::new();
            let timeout = Instant::now() + Duration::from_millis(100);
            let trigger = token.clone();
            let worker = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if cancel {
                    trigger.cancel();
                }
            });
            let result = interrupt(
                "fixture",
                &token,
                Some(timeout),
                request_shell(
                    fixture.channel.as_mut().unwrap(),
                    "fixture",
                    "xterm-256color",
                    false,
                    (119, 37),
                    &mut EarlyMessages::default(),
                    None,
                ),
            )
            .await;
            assert!(result.is_err());
            worker.await.unwrap();
            finish(fixture, false).await;
        }
    }
    #[tokio::test]
    async fn missing_status_or_channel_close_is_an_error_not_truncated_success() {
        for mode in [Mode::MissingStatus, Mode::StatusWithoutClose] {
            let mut fixture = fixture(mode, false).await.unwrap();
            let pending = start(&mut fixture, &options()).await;
            let (attachment, stdout, stderr) = attachment(tokio::io::empty());
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                relay_fixture(
                    "fixture",
                    &mut fixture,
                    RelayIo::supplied(attachment),
                    pending,
                    &CancellationToken::new(),
                ),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            assert_eq!(stdout.bytes(), b"last-output");
            assert_eq!(stderr.bytes(), b"last-error");
            finish(fixture, false).await;
        }
    }
    #[tokio::test]
    async fn slow_received_output_does_not_consume_peer_wait_budget() {
        let mut fixture = fixture(Mode::Early, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let stdout = Output::default();
        let slow = SlowOutput {
            output: stdout.clone(),
            delay: Box::pin(tokio::time::sleep(Duration::from_millis(2200))),
        };
        let attachment =
            SshShellAttachment::new(tokio::io::empty(), slow, tokio::io::sink(), 37, 119);
        let status = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(status.code, 7);
        assert_eq!(stdout.bytes(), b"early-out");
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn cancellation_interrupts_stalled_output_and_releases_wire() {
        let mut fixture = fixture(Mode::Flood, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let entered = Arc::new(Notify::new());
        let attachment = SshShellAttachment::new(
            tokio::io::empty(),
            StalledOutput(entered.clone()),
            tokio::io::sink(),
            37,
            119,
        );
        let token = CancellationToken::new();
        let trigger = token.clone();
        let cancel = tokio::spawn(async move {
            entered.notified().await;
            trigger.cancel();
        });
        let result = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &token,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        cancel.await.unwrap();
        finish(fixture, false).await;
    }
    #[tokio::test]
    async fn large_separate_outputs_drain_after_input_eof() {
        let mut fixture = fixture(Mode::Flood, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let (attachment, stdout, stderr) = attachment(&b"command\n"[..]);
        let token = CancellationToken::new();
        let status = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &token,
        )
        .await
        .unwrap();
        assert_eq!(status.code, 7);
        let mut expected = vec![b'o'; 196613];
        expected.extend_from_slice(b"command\nlast-output");
        assert_eq!(stdout.bytes(), expected);
        let mut expected = vec![b'e'; 196619];
        expected.extend_from_slice(b"last-error");
        assert_eq!(stderr.bytes(), expected);
        assert!(!token.is_cancelled());
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn real_transport_pin_mismatch_is_rejected() {
        assert!(fixture(Mode::Normal, true).await.is_err());
    }
    #[tokio::test]
    async fn cancelling_handshake_acknowledges_actual_socket_release() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut client = GuestSshClient::new();
        let (closed, receiver) = oneshot::channel();
        client.closed = Some(receiver);
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[41; 32]));
        let handshake = tokio::spawn(russh::client::connect_stream(
            Arc::new(Default::default()),
            CancellableStream::new(socket, client.transport.0.clone(), closed),
            SshClientHandler {
                agent_socket: None,
                expected_key: key.public_key().clone(),
                cancellation: client.transport.0.clone(),
                forwarding: client.forwarding.clone(),
            },
        ));
        let mut buffer = [0; 1024];
        assert!(peer.read(&mut buffer).await.unwrap() > 0);
        client.finish(None, false, &CancellationToken::new()).await;
        assert!(handshake.await.unwrap().is_err());
        assert_eq!(peer.read(&mut buffer).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn dropping_outer_owner_requests_wire_release() {
        let mut fixture = fixture(Mode::Normal, false).await.unwrap();
        let _pending = start(&mut fixture, &options()).await;
        let Fixture {
            client,
            channel,
            server,
            ..
        } = fixture;
        drop(channel);
        drop(client);
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn ssh_cwd_env_use_quoted_exec_wrapper_not_environment_requests() {
        let mut fixture = fixture(Mode::Normal, false).await.unwrap();
        let options = SshShellOptionsBuilder::default()
            .term("vt100")
            .cwd("/a'b")
            .env("VALUE", "$HOME;'\n")
            .best_effort_cwd()
            .build();
        let pending = start(&mut fixture, &options).await;
        assert_eq!(
            fixture.observations.recv().await.unwrap(),
            "pty:vt100:37:119"
        );
        assert_eq!(
            fixture.observations.recv().await.unwrap(),
            format!("exec:{}", ssh_shell_command(&options).unwrap())
        );
        let (attachment, _, _) = attachment(tokio::io::empty());
        assert_eq!(
            relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment),
                pending,
                &CancellationToken::new()
            )
            .await
            .unwrap()
            .code,
            7
        );
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn cancelling_one_attachment_leaves_other_connection_usable() {
        let mut first = fixture(Mode::Normal, false).await.unwrap();
        let early_first = start(&mut first, &options()).await;
        let (hold_first, input_first) = tokio::io::duplex(65536);
        let (attachment_first, _, _) = attachment(input_first);
        let token = CancellationToken::new();
        let cancel = token.clone();
        let first_task = tokio::spawn(async move {
            let result = relay_fixture(
                "first",
                &mut first,
                RelayIo::supplied(attachment_first),
                early_first,
                &token,
            )
            .await;
            assert!(result.is_err());
            finish(first, false).await;
        });
        let mut second = fixture(Mode::Normal, false).await.unwrap();
        let early_second = start(&mut second, &options()).await;
        let (mut input_second, reader) = tokio::io::duplex(65536);
        let (output, mut output_reader) = tokio::io::duplex(65536);
        let (sender, controls) = mpsc::channel(1);
        drop(sender);
        let attachment_second =
            SshShellAttachment::new(reader, output, tokio::io::sink(), 37, 119).controls(controls);
        let second_task = tokio::spawn(async move {
            let status = relay_fixture(
                "second",
                &mut second,
                RelayIo::supplied(attachment_second),
                early_second,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
            finish(second, true).await;
            status
        });
        input_second.write_all(b"before").await.unwrap();
        let mut before = [0; 6];
        output_reader.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), first_task)
            .await
            .unwrap()
            .unwrap();
        drop(hold_first);
        input_second.write_all(b"after").await.unwrap();
        input_second.shutdown().await.unwrap();
        let mut after = Vec::new();
        output_reader.read_to_end(&mut after).await.unwrap();
        assert_eq!(after, b"afterlast-output");
        assert_eq!(second_task.await.unwrap().code, 7);
    }
    #[tokio::test]
    async fn cancellation_interrupts_zero_window_input_backpressure() {
        let mut fixture = fixture(Mode::BlockInput, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let (attachment, _, _) = attachment(&b"blocked-input"[..]);
        let token = CancellationToken::new();
        let trigger = token.clone();
        let cancel = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            trigger.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment),
                pending,
                &token,
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        cancel.await.unwrap();
        finish(fixture, false).await;
    }
    #[tokio::test]
    async fn already_cancelled_shell_and_invalid_attachment_never_resolve_machine() {
        let home = tempfile::tempdir().unwrap();
        let runtime = crate::Runtime::open(
            crate::paths::LocalPaths::new(home.path()),
            crate::runtime::RuntimeNetworkingConfig::default(),
        )
        .await
        .unwrap();
        let machine = Machine::new(runtime, crate::store::models::MachineId::new());
        let token = CancellationToken::new();
        token.cancel();
        let (attachment, _, _) = attachment(tokio::io::empty());
        let result = machine
            .shell_with(|options| options.attachment(attachment).cancellation(token))
            .await;
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        let invalid = SshShellAttachment::new(
            tokio::io::empty(),
            tokio::io::sink(),
            tokio::io::sink(),
            0,
            119,
        );
        let result = machine
            .shell_with(|options| options.attachment(invalid))
            .await;
        assert!(result.unwrap_err().to_string().contains("dimensions"));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn awaited_cancellation_joins_forwarding_and_closes_actual_agent_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut fixture = fixture_with_agent(Mode::Normal, false, Some(path))
            .await
            .unwrap();
        let options = SshShellOptionsBuilder::default()
            .term("vt100")
            .forward_agent(true)
            .build();
        let pending = start(&mut fixture, &options).await;
        let (mut host, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut request = [0; 13];
        host.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"agent-request");
        let (hold, reader) = tokio::io::duplex(65536);
        let (attachment, _, _) = attachment(reader);
        let token = CancellationToken::new();
        token.cancel();
        assert!(relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &token
        )
        .await
        .is_err());
        finish(fixture, false).await;
        assert_eq!(host.read(&mut request).await.unwrap(), 0);
        drop(hold);
    }
    async fn qualify_certificate_image(image_variable: &str, native: bool, external: bool) {
        if std::env::var("SILO_E2E_KVM").as_deref() != Ok("1") {
            eprintln!("SKIPPED {image_variable}: SILO_E2E_KVM=1 required");
            return;
        }
        let (Some(root), Ok(image)) = (
            std::env::var_os("SILO_TEST_RUNTIME_ROOT"),
            std::env::var(image_variable),
        ) else {
            eprintln!("SKIPPED: SILO_TEST_RUNTIME_ROOT and {image_variable} required");
            return;
        };
        assert!(std::path::Path::new("/dev/kvm").exists());
        let home = tempfile::tempdir().unwrap();
        let runtime =
            crate::Runtime::new(crate::RuntimeConfig::local(home.path()).with_runtime_root(root))
                .await
                .unwrap();
        let stale = Arc::new(ssh_key::PrivateKey::from(
            ssh_key::private::Ed25519Keypair::from_seed(&[77; 32]),
        ));
        let userdata = format!("#!/bin/sh\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\nprintf '%s\\n' '{}' > /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\nprintf '#!/bin/sh\\nprintf certificate-session\\nexit 7\\n' > /run/silo-test-login\nchmod 755 /run/silo-test-login\n", stale.public_key().to_openssh().unwrap());
        let machine = runtime
            .machine()
            .name("phase5-cert")
            .image(image)
            .userdata(userdata)
            .vsock(true)
            .create()
            .await
            .unwrap();
        let task_machine = machine.clone();
        let mut task = tokio::spawn(async move {
            let mut pin = None;
            for _ in 0..2 {
                task_machine.start().await.unwrap();
                let ready = task_machine
                    .wait_ready(Duration::from_secs(75))
                    .await
                    .unwrap();
                assert_eq!(ready.outcome, crate::MachineReadinessOutcome::Ready);
                if external {
                    let monitor = task_machine.monitor_status().await.unwrap();
                    let crate::MachineAgentStatus::Enabled(agent) = monitor.agent else {
                        panic!("missing guest agent status");
                    };
                    assert_eq!(
                        agent.status.unwrap().report.ssh.unwrap().backend,
                        crate::MachineSshBackend::SystemdOpenSsh
                    );
                }
                let data = task_machine.inspect().await.unwrap();
                let key = utils::ssh::read_host_key_pin(&data.machine_dir).unwrap();
                if let Some(previous) = &pin {
                    assert_eq!(previous, key.key_data());
                } else {
                    pin = Some(key.key_data().clone());
                }
                let mut negative = GuestSshClient::new();
                let (closed, receiver) = oneshot::channel();
                negative.closed = Some(receiver);
                let stream = task_machine.open_shell_stream().await.unwrap();
                let mut handle = russh::client::connect_stream(
                    Arc::new(Default::default()),
                    CancellableStream::new(stream, negative.transport.0.clone(), closed),
                    SshClientHandler {
                        agent_socket: None,
                        expected_key: key,
                        cancellation: negative.transport.0.clone(),
                        forwarding: negative.forwarding.clone(),
                    },
                )
                .await
                .unwrap();
                assert!(!handle
                    .authenticate_publickey(
                        "root",
                        russh::keys::PrivateKeyWithHashAlg::new(stale.clone(), None)
                    )
                    .await
                    .unwrap()
                    .success());
                negative.handle = Some(handle);
                negative.finish(None, true, &CancellationToken::new()).await;
                let (attachment, stdout, stderr) = attachment(tokio::io::empty());
                let status = task_machine
                    .shell_with(|options| {
                        options
                            .user("root")
                            .term("vt100")
                            .env("SHELL", "/run/silo-test-login")
                            .attachment(attachment)
                    })
                    .await
                    .unwrap();
                assert_eq!(
                    status,
                    SshExitStatus {
                        code: 7,
                        success: false
                    }
                );
                assert!(String::from_utf8(stdout.bytes())
                    .unwrap()
                    .contains("certificate-session"));
                assert!(stderr.bytes().is_empty());
                if !native {
                    let log = task_machine
                        .exec(
                            "sh",
                            [
                                "-c",
                                "journalctl --no-pager -b | grep 'silo:cli:' | grep 'CA ED25519'",
                            ],
                        )
                        .await
                        .unwrap();
                    assert!(log.stdout().unwrap().contains("silo:cli:"));
                }
                task_machine.stop().await.unwrap();
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(210), &mut task).await;
        if result.is_err() {
            task.abort();
            let _ = task.await;
        }
        machine
            .stop_with(
                crate::MachineStopOptions::new().force_after_timeout(Duration::from_secs(20)),
            )
            .await
            .unwrap();
        machine.remove().await.unwrap();
        result.unwrap().unwrap();
    }
    #[tokio::test]
    async fn phase5_fedora_certificate_guest() {
        qualify_certificate_image("SILO_TEST_SSH_FEDORA_IMAGE", false, false).await;
    }
    #[tokio::test]
    async fn phase5_arch_certificate_guest() {
        qualify_certificate_image("SILO_TEST_SSH_ARCH_IMAGE", false, false).await;
    }
    #[tokio::test]
    async fn phase5_ubuntu_certificate_guest() {
        qualify_certificate_image("SILO_TEST_SSH_UBUNTU_IMAGE", false, false).await;
    }
    #[tokio::test]
    async fn phase5_system_certificate_guest() {
        qualify_certificate_image("SILO_TEST_SSH_SYSTEM_IMAGE", true, false).await;
    }
    #[tokio::test]
    async fn phase5_systemd_owned_certificate_guest() {
        qualify_certificate_image("SILO_TEST_SSH_SYSTEMD_IMAGE", false, true).await;
    }
    #[tokio::test]
    async fn peer_terminal_outcome_interrupts_unconsumed_stdin_and_drains_trailing_output() {
        for (mode, code) in [(Mode::ExitWithoutInput, 7), (Mode::SignalExit, 128)] {
            let mut fixture = fixture(mode, false).await.unwrap();
            let pending = start(&mut fixture, &options()).await;
            let (attachment, stdout, _) = attachment(&b"unconsumed-input"[..]);
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                relay_fixture(
                    "fixture",
                    &mut fixture,
                    RelayIo::supplied(attachment),
                    pending,
                    &CancellationToken::new(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.code, code);
            assert_eq!(stdout.bytes(), b"after-status");
            finish(fixture, true).await;
        }
    }
    #[tokio::test]
    async fn eof_peer_budget_interrupts_an_outbound_zero_window_write() {
        let mut fixture = fixture(Mode::EofWithoutInput, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let (attachment, _, _) = attachment(&b"unconsumed-input"[..]);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment),
                pending,
                &CancellationToken::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("peer stopped"));
        finish(fixture, false).await;
    }
    #[tokio::test]
    async fn caller_output_failure_is_preserved_and_wire_is_released() {
        for stderr in [false, true] {
            let mut fixture = fixture(Mode::Flood, false).await.unwrap();
            let pending = start(&mut fixture, &options()).await;
            let attachment = if stderr {
                SshShellAttachment::new(
                    tokio::io::empty(),
                    tokio::io::sink(),
                    FailedOutput,
                    37,
                    119,
                )
            } else {
                SshShellAttachment::new(
                    tokio::io::empty(),
                    FailedOutput,
                    tokio::io::sink(),
                    37,
                    119,
                )
            };
            let result = relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment),
                pending,
                &CancellationToken::new(),
            )
            .await;
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("caller output failed"));
            finish(fixture, false).await;
        }
    }
    #[tokio::test]
    async fn cancellation_interrupts_control_writes_to_a_nonreading_peer() {
        let mut fixture = fixture(Mode::PauseReads, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let (hold, input) = tokio::io::duplex(65536);
        let (attachment, _, _) = attachment(input);
        let (sender, controls) = mpsc::channel(64);
        let token = CancellationToken::new();
        let pump_token = token.clone();
        let pump = tokio::spawn(async move {
            for _ in 0..300000 {
                tokio::select! {
                    biased;
                    _ = pump_token.cancelled() => return,
                    result = sender.send(SshShellControl::Signal(SshShellSignal::Usr1)) => if result.is_err() { return; },
                }
            }
        });
        let trigger = token.clone();
        let cancel = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            trigger.cancel();
        });
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment.controls(controls)),
                pending,
                &token,
            ),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        pump.await.unwrap();
        cancel.await.unwrap();
        drop(hold);
        finish(fixture, false).await;
    }
    #[test]
    fn immutable_pin_requires_an_existing_valid_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(utils::ssh::read_host_key_pin(dir.path()).is_err());
        std::fs::create_dir(dir.path().join("ssh")).unwrap();
        std::fs::write(dir.path().join("ssh/known_host"), "not a public key").unwrap();
        assert!(utils::ssh::read_host_key_pin(dir.path()).is_err());
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]));
        std::fs::write(
            dir.path().join("ssh/known_host"),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        assert_eq!(
            utils::ssh::read_host_key_pin(dir.path())
                .unwrap()
                .key_data(),
            key.public_key().key_data()
        );
    }
    #[test]
    fn supplied_attachment_leaves_host_terminal_signals_and_stdout_untouched() {
        const CHILD: &str = "SILO_SUPPLIED_SSH_HOST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            use nix::fcntl::{fcntl, FcntlArg};
            use nix::sys::signal::Signal;
            use nix::sys::termios::tcgetattr;
            fn action(signal: Signal) -> libc::sigaction {
                let mut action = unsafe { std::mem::zeroed() };
                // nix lacks a read-only sigaction query.
                assert_eq!(
                    unsafe { libc::sigaction(signal as i32, std::ptr::null(), &mut action) },
                    0
                );
                action
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let stdin = std::io::stdin();
                let terminal = tcgetattr(&stdin).unwrap();
                let flags = fcntl(&stdin, FcntlArg::F_GETFL).unwrap();
                let watched = [
                    Signal::SIGHUP,
                    Signal::SIGINT,
                    Signal::SIGQUIT,
                    Signal::SIGTERM,
                    Signal::SIGUSR1,
                    Signal::SIGUSR2,
                    Signal::SIGWINCH,
                ];
                let actions = watched.map(action);
                let mut fixture = fixture(Mode::Normal, false).await.unwrap();
                let pending = start(&mut fixture, &options()).await;
                let entered = Arc::new(Notify::new());
                let token = CancellationToken::new();
                let worker_token = token.clone();
                let worker_entered = entered.clone();
                let task = tokio::spawn(async move {
                    let attachment = SshShellAttachment::new(
                        &b"provided-shell-bytes"[..],
                        StalledOutput(worker_entered),
                        tokio::io::sink(),
                        37,
                        119,
                    );
                    assert!(relay_fixture(
                        "fixture",
                        &mut fixture,
                        RelayIo::supplied(attachment),
                        pending,
                        &worker_token
                    )
                    .await
                    .is_err());
                    finish(fixture, false).await;
                });
                tokio::time::timeout(Duration::from_secs(3), entered.notified())
                    .await
                    .unwrap();
                assert_eq!(tcgetattr(&stdin).unwrap(), terminal);
                assert_eq!(fcntl(&stdin, FcntlArg::F_GETFL).unwrap(), flags);
                for (signal, previous) in watched.into_iter().zip(actions) {
                    let current = action(signal);
                    assert_eq!(current.sa_sigaction, previous.sa_sigaction);
                    assert_eq!(current.sa_flags, previous.sa_flags);
                }
                token.cancel();
                tokio::time::timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(tcgetattr(&stdin).unwrap(), terminal);
            });
            return;
        }
        let pty = nix::pty::openpty(None, None).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "machine::session::ssh::tests::supplied_attachment_leaves_host_terminal_signals_and_stdout_untouched", "--nocapture"])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::from(nix::unistd::dup(&pty.slave).unwrap()))
            .stdout(std::process::Stdio::piped())
            .spawn().unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8(output.stdout)
            .unwrap()
            .contains("provided-shell-bytes"));
    }
    #[tokio::test]
    async fn final_flush_disarms_peer_timer_but_remains_cancellable() {
        let mut fixture = fixture(Mode::Early, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        let entered = Arc::new(Notify::new());
        let attachment = SshShellAttachment::new(
            tokio::io::empty(),
            StalledFlush(entered.clone()),
            tokio::io::sink(),
            37,
            119,
        );
        let token = CancellationToken::new();
        let trigger = token.clone();
        let cancel = tokio::spawn(async move {
            entered.notified().await;
            tokio::time::sleep(Duration::from_millis(2200)).await;
            trigger.cancel();
        });
        let result = relay_fixture(
            "fixture",
            &mut fixture,
            RelayIo::supplied(attachment),
            pending,
            &token,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        cancel.await.unwrap();
        finish(fixture, false).await;
    }
    struct ObservedInput<R> {
        reader: R,
        read: Arc<Notify>,
    }
    impl<R: AsyncRead + Unpin> AsyncRead for ObservedInput<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buffer.filled().len();
            let result = Pin::new(&mut self.reader).poll_read(cx, buffer);
            if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
                self.read.notify_one();
            }
            result
        }
    }
    #[tokio::test]
    async fn resize_and_signal_remain_live_after_stdin_exhausts_remote_window() {
        let mut fixture = fixture(Mode::SignalAfterBlockedInput, false).await.unwrap();
        let pending = start(&mut fixture, &options()).await;
        assert_eq!(
            fixture.observations.recv().await.unwrap(),
            "pty:vt100:37:119"
        );
        assert_eq!(fixture.observations.recv().await.unwrap(), "shell");
        let read = Arc::new(Notify::new());
        let (hold, input) = tokio::io::duplex(65536);
        let mut hold = hold;
        hold.write_all(b"blocked-before-controls").await.unwrap();
        let (attachment, stdout, _) = attachment(ObservedInput {
            reader: input,
            read: read.clone(),
        });
        let (sender, controls) = mpsc::channel(4);
        let worker = tokio::spawn(async move {
            read.notified().await;
            sender
                .send(SshShellControl::Resize {
                    rows: 41,
                    columns: 123,
                })
                .await
                .unwrap();
            sender
                .send(SshShellControl::Signal(SshShellSignal::Int))
                .await
                .unwrap();
            drop(sender);
            hold
        });
        let status = tokio::time::timeout(
            Duration::from_secs(3),
            relay_fixture(
                "fixture",
                &mut fixture,
                RelayIo::supplied(attachment.controls(controls)),
                pending,
                &CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(status.code, 130);
        assert_eq!(stdout.bytes(), b"interrupted-unread-input");
        assert_eq!(fixture.observations.recv().await.unwrap(), "resize:41:123");
        assert_eq!(fixture.observations.recv().await.unwrap(), "signal:INT");
        drop(worker.await.unwrap());
        finish(fixture, true).await;
    }
    #[tokio::test]
    async fn cancellation_during_certificate_authentication_releases_and_joins_owned_connection() {
        let mut fixture = fixture(Mode::WithholdAuthentication, false).await.unwrap();
        let subject = Arc::new(ssh_key::PrivateKey::from(
            ssh_key::private::Ed25519Keypair::from_seed(&[51; 32]),
        ));
        let ca = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[52; 32]));
        let mut builder = ssh_key::certificate::Builder::new(
            [53; 32],
            subject.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("alice").unwrap();
        let certificate = builder.sign(&ca).unwrap();
        let token = CancellationToken::new();
        {
            let authentication = interrupt("fixture", &token, None, async {
                fixture
                    .client
                    .handle
                    .as_mut()
                    .unwrap()
                    .authenticate_openssh_cert("alice", subject, certificate)
                    .await
                    .map_err(|error| ssh_error("fixture", "certificate authentication", error))
            });
            let mut authentication = std::pin::pin!(authentication);
            tokio::select! {
                result = &mut authentication => panic!("authentication finished before cancellation: {result:?}"),
                observed = fixture.observations.recv() => assert_eq!(observed.unwrap(), "certificate-authentication"),
            }
            token.cancel();
            assert!(authentication
                .await
                .unwrap_err()
                .to_string()
                .contains("cancelled"));
        }
        tokio::time::timeout(Duration::from_secs(3), finish(fixture, false))
            .await
            .unwrap();
    }
}

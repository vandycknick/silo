use crate::machine::session::*;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct TransportGuard(pub CancellationToken);
impl Drop for TransportGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

// russh's public handle does not abort its connection task on drop. Wake its
// transport on cancellation, dropping the actual wire before returning an error.
pub(super) struct CancellableStream<S> {
    stream: Option<S>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl<S> CancellableStream<S> {
    pub(super) fn new(stream: S, cancel: CancellationToken) -> Self {
        Self {
            stream: Some(stream),
            cancelled: Box::pin(cancel.cancelled_owned()),
        }
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            self.stream.take();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SSH session cancelled",
            ));
        }
        Ok(())
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for CancellableStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(self.stream.as_mut().expect("checked transport")).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CancellableStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        Pin::new(self.stream.as_mut().expect("checked transport")).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(self.stream.as_mut().expect("checked transport")).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(self.stream.as_mut().expect("checked transport")).poll_shutdown(cx)
    }
}

impl Machine {
    /// Opens a certificate-authenticated SSH login shell for an embedding server.
    /// No host terminal, stdio, signal listeners or guest agent RPCs are used.
    /// Requires an existing immutable host-key pin and a current running VM.
    pub async fn spawn_ssh_shell_with(
        &self,
        configure: impl FnOnce(ExecutionOptionsBuilder) -> ExecutionOptionsBuilder,
    ) -> Result<ExecutionSession, LibVmError> {
        let options = configure(ExecutionOptionsBuilder::default()).build();
        validate_options(&options)?;
        let reference = self.running_config().await?.name;
        let setup = async {
            let client = self
                .connect_guest_ssh(&reference, options.user.as_deref(), false)
                .await?;
            let mut channel = open_session_channel(&client).await?;
            let (rows, columns) = options.initial_pty_size.unwrap_or((24, 80));
            channel
                .request_pty(
                    true,
                    &options.term,
                    u32::from(columns),
                    u32::from(rows),
                    0,
                    0,
                    &[],
                )
                .await
                .map_err(|error| ssh_error(&reference, "request PTY", error))?;
            wait_channel_success(&mut channel, &reference, "request PTY").await?;
            for (name, value) in &options.env {
                channel
                    .set_env(true, name, value)
                    .await
                    .map_err(|error| ssh_error(&reference, "set shell environment", error))?;
                wait_channel_success(&mut channel, &reference, "set shell environment").await?;
            }
            channel
                .request_shell(true)
                .await
                .map_err(|error| ssh_error(&reference, "request shell", error))?;
            wait_channel_success(&mut channel, &reference, "request shell").await?;
            Ok::<_, LibVmError>((client, channel))
        };
        let (client, channel) = tokio::time::timeout(SSH_HANDSHAKE_READY_TIMEOUT, setup)
            .await
            .map_err(|_| guest_session_error(&reference, "SSH shell setup timed out"))??;
        Ok(stream_session(reference, client, channel))
    }
}

fn validate_options(options: &ExecutionOptions) -> Result<(), LibVmError> {
    let unsupported = if !options.args.is_empty() {
        Some("args")
    } else if options.cwd.is_some() {
        Some("cwd")
    } else if options.timeout.is_some() {
        Some("timeout")
    } else if !options.tty {
        Some("tty=false (SSH shells require a PTY)")
    } else if !matches!(options.stdin, StdinMode::Pipe) {
        Some("stdin other than Pipe")
    } else {
        None
    };
    if let Some(field) = unsupported {
        return Err(guest_session_error(
            "SSH shell",
            format!("unsupported SSH shell option: {field}"),
        ));
    }
    if options.term.is_empty() || options.term.contains('\0') {
        return Err(guest_session_error(
            "SSH shell",
            "TERM must be nonempty and contain no NUL",
        ));
    }
    if options
        .initial_pty_size
        .is_some_and(|(rows, columns)| rows == 0 || columns == 0)
    {
        return Err(guest_session_error(
            "SSH shell",
            "PTY dimensions must be positive",
        ));
    }
    for (name, value) in &options.env {
        if !valid_environment_name(name) || value.contains('\0') {
            return Err(guest_session_error(
                "SSH shell",
                format!("invalid SSH environment variable {name:?}"),
            ));
        }
    }
    Ok(())
}

fn stream_session(
    reference: String,
    client: GuestSshClient,
    channel: Channel<ClientMsg>,
) -> ExecutionSession {
    let cancel = client.transport.0.clone();
    let (requests, receiver) = mpsc::channel(EXECUTION_REQUEST_QUEUE_CAPACITY);
    let (events, event_receiver) = mpsc::channel(EXECUTION_REQUEST_QUEUE_CAPACITY);
    let request_closed = Arc::new(watch::channel(false).0);
    tokio::spawn(run_shell(
        client,
        channel,
        receiver,
        events,
        request_closed.subscribe(),
        cancel.clone(),
    ));
    ExecutionSession {
        reference,
        requests: Arc::new(Mutex::new(Some(requests))),
        input_open: Arc::new(AtomicBool::new(true)),
        started: Arc::new(AtomicBool::new(false)),
        input_order: Arc::new(AsyncMutex::new(())),
        request_closed,
        // SSH EOF is supported even though this session always has a PTY.
        pipe_stdin: true,
        events: Some(ExecutionEvents::Ssh(event_receiver)),
        ssh_cancel: Some(cancel),
    }
}

async fn run_shell(
    client: GuestSshClient,
    channel: Channel<ClientMsg>,
    mut requests: mpsc::Receiver<ExecuteInput>,
    events: mpsc::Sender<ExecutionEvent>,
    mut closed: watch::Receiver<bool>,
    cancel: CancellationToken,
) {
    let (mut reader, writer) = channel.split();
    let mut cancellation = closed.clone();
    let run = async {
        events
            .send(ExecutionEvent::Accepted)
            .await
            .map_err(|_| "event receiver closed".to_string())?;
        events
            .send(ExecutionEvent::Started)
            .await
            .map_err(|_| "event receiver closed".to_string())?;
        let mut terminal = None;
        let mut end_deadline = None;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err("SSH shell cancelled".to_string()),
                _ = closed.changed() => return Err("SSH shell request stream closed".to_string()),
                _ = async { match end_deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending().await } } => break,
                message = reader.wait() => match message {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        events.send(ExecutionEvent::TerminalOutput(data.to_vec())).await.map_err(|_| "event receiver closed".to_string())?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        terminal = Some(ExecutionResult::Exited { code: Some(exit_status) });
                        end_deadline = Some(tokio::time::Instant::now() + SHUTDOWN_TIMEOUT);
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        terminal = Some(ExecutionResult::Signaled { signal: linux_signal(&signal_name) });
                        end_deadline = Some(tokio::time::Instant::now() + SHUTDOWN_TIMEOUT);
                    }
                    Some(ChannelMsg::Eof) => {
                        // Wait briefly for the exit status/close that normally follows EOF,
                        // rather than leaving a finished peer's shell stranded forever.
                        end_deadline.get_or_insert(tokio::time::Instant::now() + SHUTDOWN_TIMEOUT);
                    }
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                },
                request = requests.recv() => {
                    let Some(request) = request else { return Err("SSH shell request stream closed".to_string()); };
                    let result = match request.message {
                        Some(ExecuteMessage::StdinData(data)) => writer.data_bytes(data.data).await,
                        Some(ExecuteMessage::CloseStdin(_)) => writer.eof().await,
                        Some(ExecuteMessage::ResizePty(resize)) => {
                            let size = resize.size.ok_or_else(|| "missing PTY size".to_string())?;
                            if size.rows == 0 || size.columns == 0 { return Err("PTY dimensions must be positive".to_string()); }
                            writer.window_change(size.columns, size.rows, 0, 0).await
                        }
                        Some(ExecuteMessage::SignalProcess(signal)) => {
                            let signal = signal.signal.and_then(ssh_linux_signal).ok_or_else(|| "unsupported SSH signal".to_string())?;
                            writer.signal(signal).await
                        }
                        _ => return Err("unsupported SSH shell control".to_string()),
                    };
                    result.map_err(|error| format!("SSH shell control failed: {error}"))?;
                }
            }
        }
        terminal.ok_or_else(|| "SSH shell ended without an exit status".to_string())
    };
    // Backpressure must not prevent drop/cancel from closing the connection.
    let result = tokio::select! {
        _ = cancel.cancelled() => Err("SSH shell cancelled".to_string()),
        _ = events.closed() => Err("event receiver closed".to_string()),
        _ = cancellation.changed() => Err("SSH shell request stream closed".to_string()),
        result = run => result,
    };
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, writer.close()).await;
    let GuestSshClient {
        mut handle,
        transport,
        ..
    } = client;
    let _ = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        handle.disconnect(russh::Disconnect::ByApplication, "shell complete", "en"),
    )
    .await;
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut handle)
        .await
        .is_err()
    {
        transport.0.cancel();
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut handle).await;
    }
    let terminal = result.unwrap_or_else(|message| {
        ExecutionResult::Lost(ExecutionLost {
            reason: ExecutionLostReason::GuestStreamLost,
            message: Some(message),
        })
    });
    let _ = events.send(ExecutionEvent::Terminal(terminal)).await;
}

fn ssh_linux_signal(signal: u32) -> Option<russh::Sig> {
    Some(match signal {
        1 => russh::Sig::HUP,
        2 => russh::Sig::INT,
        3 => russh::Sig::QUIT,
        6 => russh::Sig::ABRT,
        8 => russh::Sig::FPE,
        9 => russh::Sig::KILL,
        4 => russh::Sig::ILL,
        11 => russh::Sig::SEGV,
        13 => russh::Sig::PIPE,
        14 => russh::Sig::ALRM,
        15 => russh::Sig::TERM,
        10 => russh::Sig::USR1,
        12 => russh::Sig::Custom("USR2".into()),
        _ => return None,
    })
}
fn linux_signal(signal: &russh::Sig) -> Option<u32> {
    match signal {
        russh::Sig::HUP => Some(1),
        russh::Sig::INT => Some(2),
        russh::Sig::QUIT => Some(3),
        russh::Sig::ILL => Some(4),
        russh::Sig::ABRT => Some(6),
        russh::Sig::FPE => Some(8),
        russh::Sig::KILL => Some(9),
        russh::Sig::USR1 => Some(10),
        russh::Sig::SEGV => Some(11),
        russh::Sig::PIPE => Some(13),
        russh::Sig::ALRM => Some(14),
        russh::Sig::TERM => Some(15),
        russh::Sig::Custom(name) if name == "USR2" => Some(12),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::machine::session::ssh::*;
    use russh::server::{Auth, ChannelOpenHandle, Session};
    use russh::ChannelId;
    use tokio::io::AsyncReadExt;

    #[test]
    fn shell_options_reject_execution_only_fields() {
        let base = || ExecutionOptionsBuilder::default().tty(true).stdin_pipe();
        assert!(validate_options(&base().build()).is_ok());
        for options in [
            base().arg("command").build(),
            base().cwd("/tmp").build(),
            base().timeout(Duration::from_secs(1)).build(),
            base().tty(false).build(),
            base().stdin_null().build(),
            base().stdin_bytes("data").build(),
            base().initial_pty_size(0, 80).build(),
            base().term("").build(),
            base().env("BAD NAME", "value").build(),
        ] {
            assert!(validate_options(&options).is_err());
        }
        assert!(validate_options(
            &base()
                .user("alice")
                .env("LANG", "C")
                .term("vt100")
                .initial_pty_size(40, 100)
                .build()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn cancelling_stalled_handshake_closes_real_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let cancel = CancellationToken::new();
        let guard = TransportGuard(cancel.clone());
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[41; 32]));
        let handshake = tokio::spawn(russh::client::connect_stream(
            Arc::new(Default::default()),
            CancellableStream::new(socket, cancel),
            SshClientHandler {
                agent_socket: None,
                expected_key: key.public_key().clone(),
            },
        ));
        let mut buffer = [0; 1024];
        assert!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut buffer))
                .await
                .unwrap()
                .unwrap()
                > 0
        );
        drop(guard);
        assert!(tokio::time::timeout(Duration::from_secs(2), handshake)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    struct ShellServer {
        observations: mpsc::UnboundedSender<String>,
        eof_only: bool,
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
        async fn env_request(
            &mut self,
            channel: ChannelId,
            name: &str,
            value: &str,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations
                .send(format!("env:{name}:{value}"))
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
            session.channel_success(channel)?;
            Ok(())
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
            _: ChannelId,
            signal: russh::Sig,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            self.observations
                .send(format!("signal:{signal:?}"))
                .unwrap();
            Ok(())
        }
        async fn channel_eof(
            &mut self,
            channel: ChannelId,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, b"last-output".to_vec())?;
            session.eof(channel)?;
            if !self.eof_only {
                session.exit_status_request(channel, 7)?;
                session.close(channel)?;
            }
            Ok(())
        }
    }

    async fn fixture(
        eof_only: bool,
        wrong_pin: bool,
    ) -> (
        Result<(GuestSshClient, Channel<ClientMsg>), russh::Error>,
        mpsc::UnboundedReceiver<String>,
        tokio::task::JoinHandle<()>,
    ) {
        let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]));
        let other =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[43; 32]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let (observations, receiver) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let config = russh::server::Config {
                keys: vec![key],
                ..Default::default()
            };
            if let Ok(server) = russh::server::run_stream(
                Arc::new(config),
                peer,
                ShellServer {
                    observations,
                    eof_only,
                },
            )
            .await
            {
                let _ = server.await;
            }
        });
        let cancel = CancellationToken::new();
        let guard = TransportGuard(cancel.clone());
        let pin = if wrong_pin {
            other.public_key().clone()
        } else {
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]))
                .public_key()
                .clone()
        };
        let result = async {
            let mut handle = russh::client::connect_stream(
                Arc::new(Default::default()),
                CancellableStream::new(socket, cancel),
                SshClientHandler {
                    agent_socket: None,
                    expected_key: pin,
                },
            )
            .await?;
            assert!(handle
                .authenticate_publickey(
                    "alice",
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(other), None)
                )
                .await?
                .success());
            let mut channel = handle.channel_open_session().await?;
            channel
                .request_pty(true, "vt100", 100, 40, 0, 0, &[])
                .await?;
            wait_channel_success(&mut channel, "fixture", "PTY")
                .await
                .unwrap();
            channel.set_env(true, "LANG", "C").await?;
            wait_channel_success(&mut channel, "fixture", "environment")
                .await
                .unwrap();
            channel.request_shell(true).await?;
            wait_channel_success(&mut channel, "fixture", "shell")
                .await
                .unwrap();
            Ok((
                GuestSshClient {
                    reference: "fixture".into(),
                    handle,
                    transport: guard,
                },
                channel,
            ))
        }
        .await;
        (result, receiver, server)
    }

    #[tokio::test]
    async fn real_ssh_shell_streams_controls_drains_output_and_reaps_connection() {
        let (connection, mut observations, server) = fixture(false, false).await;
        let (client, channel) = connection.unwrap();
        let mut session = stream_session("fixture".into(), client, channel);
        assert_eq!(
            session.recv().await.unwrap(),
            Some(ExecutionEvent::Accepted)
        );
        assert_eq!(session.recv().await.unwrap(), Some(ExecutionEvent::Started));
        assert_eq!(observations.recv().await.unwrap(), "pty:vt100:40:100");
        assert_eq!(observations.recv().await.unwrap(), "env:LANG:C");
        assert_eq!(observations.recv().await.unwrap(), "shell");
        session.write_stdin(b"hello").await.unwrap();
        assert_eq!(
            session.recv().await.unwrap(),
            Some(ExecutionEvent::TerminalOutput(b"hello".to_vec()))
        );
        session.resize_pty(50, 120).await.unwrap();
        session.signal(15).await.unwrap();
        assert_eq!(observations.recv().await.unwrap(), "resize:50:120");
        assert_eq!(observations.recv().await.unwrap(), "signal:TERM");
        session.close_stdin().await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), session.collect())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.terminal_output_bytes(), b"last-output");
        assert_eq!(output.result(), &ExecutionResult::Exited { code: Some(7) });
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn real_ssh_eof_without_status_is_bounded() {
        let (connection, _observations, server) = fixture(true, false).await;
        let (client, channel) = connection.unwrap();
        let mut session = stream_session("fixture".into(), client, channel);
        session.recv().await.unwrap();
        session.recv().await.unwrap();
        session.close_stdin().await.unwrap();
        let output = tokio::time::timeout(Duration::from_secs(10), session.collect())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.terminal_output_bytes(), b"last-output");
        assert!(matches!(output.result(), ExecutionResult::Lost(_)));
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn real_ssh_drop_and_cancel_close_connection_even_with_live_controls() {
        for explicit in [false, true] {
            let (connection, _observations, server) = fixture(false, false).await;
            let (client, channel) = connection.unwrap();
            let mut session = stream_session("fixture".into(), client, channel);
            let control = session.control();
            session.recv().await.unwrap();
            session.recv().await.unwrap();
            if explicit {
                session.cancel();
            }
            drop(session);
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .unwrap()
                .unwrap();
            assert!(control.write_stdin("late").await.is_err());
        }
    }

    #[tokio::test]
    async fn real_ssh_rejects_mismatched_immutable_pin() {
        let (connection, _observations, server) = fixture(false, true).await;
        assert!(connection.is_err());
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}

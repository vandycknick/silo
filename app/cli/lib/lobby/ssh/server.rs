use futures::future::BoxFuture;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::lobby::{
    caller::Caller,
    failure::Outcome,
    identity::Peer,
    identity_source::IdentitySource,
    metrics::Metrics,
    service::Service,
    session::{SessionExtras, SessionIo},
    ssh::{host_key, notices::Notice, session::Handler},
};

/// The production dispatcher and real function dispatchers share the same stream boundary.
pub(crate) trait Dispatcher: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        caller: &'a Caller,
        line: &'a str,
        io: &'a mut SessionIo,
        extras: &'a SessionExtras,
    ) -> BoxFuture<'a, i32>;

    fn notices<'a>(&'a self, _peer: &'a Peer) -> BoxFuture<'a, Outcome<Vec<Notice>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct ServiceDispatcher(Arc<Service>);

impl Dispatcher for ServiceDispatcher {
    fn dispatch<'a>(
        &'a self,
        caller: &'a Caller,
        line: &'a str,
        io: &'a mut SessionIo,
        extras: &'a SessionExtras,
    ) -> BoxFuture<'a, i32> {
        Box::pin(crate::lobby::dispatch::dispatch_session(
            &self.0, caller, line, io, extras,
        ))
    }

    fn notices<'a>(&'a self, peer: &'a Peer) -> BoxFuture<'a, Outcome<Vec<Notice>>> {
        Box::pin(async move {
            if !peer.permissions.has(crate::lobby::identity::Action::Read) {
                return Ok(Vec::new());
            }
            Ok(self
                .0
                .list(peer)
                .await?
                .into_iter()
                .map(|vm| Notice {
                    id: vm.id,
                    name: vm.name,
                    url: vm.approval_url,
                })
                .collect())
        })
    }
}

#[derive(Default)]
struct Counts {
    closing: bool,
    connections: usize,
    total: u64,
    peers: HashMap<String, u64>,
}

pub(crate) struct Shared {
    counts: Mutex<Counts>,
    drained: Notify,
    global: u64,
    per_peer: u64,
    force: CancellationToken,
    metrics: Arc<Metrics>,
}

impl Shared {
    pub(crate) fn admit(self: &Arc<Self>, peer: &str) -> Option<Permit> {
        let mut counts = self.counts.lock();
        if counts.closing
            || counts.total >= self.global
            || counts.peers.get(peer).copied().unwrap_or_default() >= self.per_peer
        {
            return None;
        }
        counts.total += 1;
        *counts.peers.entry(peer.to_owned()).or_default() += 1;
        self.metrics.session(1);
        Some(Permit {
            shared: self.clone(),
            peer: peer.to_owned(),
        })
    }
}

pub(crate) struct Permit {
    shared: Arc<Shared>,
    peer: String,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut counts = self.shared.counts.lock();
        counts.total -= 1;
        self.shared.metrics.session(-1);
        if let Some(count) = counts.peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                counts.peers.remove(&self.peer);
            }
        }
    }
}

struct ConnectionGuard {
    shared: Arc<Shared>,
    cancel: CancellationToken,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.shared.counts.lock().connections -= 1;
        self.shared.drained.notify_waiters();
    }
}

pub(crate) struct Server {
    config: Arc<russh::server::Config>,
    identity: IdentitySource,
    dispatcher: Arc<dyn Dispatcher>,
    shared: Arc<Shared>,
}

impl Server {
    pub(crate) fn new(
        home: &Path,
        settings: &crate::config::tailscale::TailscaleConfig,
        identity: IdentitySource,
        service: Arc<Service>,
    ) -> io::Result<Self> {
        let metrics = service.jobs().metrics().clone();
        Self::with_dispatcher(
            home,
            settings.session_limits(),
            identity,
            Arc::new(ServiceDispatcher(service)),
            metrics,
        )
    }

    pub(crate) fn with_dispatcher(
        home: &Path,
        limits: (u64, u64),
        identity: IdentitySource,
        dispatcher: Arc<dyn Dispatcher>,
        metrics: Arc<Metrics>,
    ) -> io::Result<Self> {
        if limits.0 == 0 || limits.1 == 0 || limits.1 > limits.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SSH session limits",
            ));
        }
        let config = russh::server::Config {
            keys: vec![host_key::load(home)?],
            methods: [russh::MethodKind::None].as_slice().into(),
            window_size: 65536,
            maximum_packet_size: 16384,
            channel_buffer_size: 8,
            event_buffer_size: 16,
            inactivity_timeout: None,
            auth_rejection_time: Duration::from_secs(1),
            ..Default::default()
        };
        Ok(Self {
            config: Arc::new(config),
            identity,
            dispatcher,
            shared: Arc::new(Shared {
                counts: Mutex::new(Counts::default()),
                metrics,
                drained: Notify::new(),
                global: limits.0,
                per_peer: limits.1,
                force: CancellationToken::new(),
            }),
        })
    }

    pub(crate) async fn serve_stream<S>(&self, remote: &str, stream: S) -> Result<(), russh::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        {
            let mut counts = self.shared.counts.lock();
            if counts.closing {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "SSH server is draining",
                )
                .into());
            }
            counts.connections += 1;
        }
        let cancel = self.shared.force.child_token();
        let _guard = ConnectionGuard {
            shared: self.shared.clone(),
            cancel: cancel.clone(),
        };
        let resolve = (self.identity)(remote);
        let initial = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            peer = tokio::time::timeout(Duration::from_secs(15), resolve()) => peer.ok().and_then(Result::ok).filter(Peer::valid),
        };
        let caller = initial.map(|peer| Caller::new(peer, resolve));
        let handler = Handler::new(
            caller,
            self.dispatcher.clone(),
            self.shared.clone(),
            cancel.clone(),
        );
        let stream = CancelStream {
            inner: stream,
            cancelled: Box::pin(cancel.cancelled_owned()),
        };
        russh::server::run_stream(self.config.clone(), stream, handler)
            .await?
            .await
    }

    /// Stop admission, allow existing connections to drain, then cancel their I/O.
    pub(crate) async fn shutdown(&self, deadline: Instant) {
        self.shared.counts.lock().closing = true;
        loop {
            let notified = self.shared.drained.notified();
            if self.shared.counts.lock().connections == 0 {
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.shared.force.cancel();
                return;
            }
        }
    }
}

struct CancelStream<S> {
    inner: S,
    cancelled: BoxFuture<'static, ()>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CancelStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CancelStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::{
        caller::Caller,
        failure::{Code, Failure},
        identity::{Peer, Principal},
        identity_source::IdentitySource,
        session::{SessionExtras, SessionIo, Signal},
        ssh::server::{Dispatcher, Server},
    };
    use futures::future::BoxFuture;
    use russh::{client, Channel, ChannelMsg};
    use std::{
        io,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::{
        io::AsyncWriteExt,
        net::UnixStream,
        time::{timeout, Instant},
    };

    struct Client;
    impl client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// A small real command interpreter exercises transport without a daemon.
    struct Commands;
    impl Dispatcher for Commands {
        fn dispatch<'a>(
            &'a self,
            caller: &'a Caller,
            line: &'a str,
            io: &'a mut SessionIo,
            extras: &'a SessionExtras,
        ) -> BoxFuture<'a, i32> {
            Box::pin(async move {
                match line {
                    "ls --json" => io
                        .stdout
                        .write_all(b"{\"ok\":true,\"data\":[]}\n")
                        .await
                        .unwrap(),
                    "whoami" => io
                        .stdout
                        .write_all(format!("{}\n", caller.peer.node_id).as_bytes())
                        .await
                        .unwrap(),
                    "cat" => {
                        tokio::io::copy(&mut io.stdin, &mut io.stdout)
                            .await
                            .unwrap();
                    }
                    "confirm" => {
                        let answer = extras.prompt.as_ref().unwrap()("Continue? ".into(), 32)
                            .await
                            .unwrap();
                        io.stdout.write_all(answer.as_bytes()).await.unwrap();
                    }
                    "resize" => {
                        let terminal = io.terminal.as_mut().unwrap();
                        io.stdout
                            .write_all(
                                format!(
                                    "{}:{}x{}\n",
                                    terminal.term,
                                    terminal.window.borrow().columns,
                                    terminal.window.borrow().rows
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                        terminal.window.changed().await.unwrap();
                        let size = *terminal.window.borrow();
                        io.stdout
                            .write_all(format!("{}x{}\n", size.columns, size.rows).as_bytes())
                            .await
                            .unwrap();
                    }
                    "signal" => {
                        io.stdout.write_all(b"ready\n").await.unwrap();
                        assert_eq!(io.signals.recv().await, Some(Signal::Usr2));
                        io.stdout.write_all(b"signal received\n").await.unwrap();
                    }
                    "wait" => std::future::pending().await,
                    _ => return 2,
                }
                0
            })
        }
    }

    fn identity(counter: Arc<AtomicUsize>) -> IdentitySource {
        Arc::new(move |remote| {
            let remote = remote.to_owned();
            let counter = counter.clone();
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let peer = Peer {
                    principals: vec![Principal::parse("user:1").unwrap()],
                    node_id: remote.clone(),
                    observed_at: chrono::Utc::now(),
                    ..Peer::default()
                };
                Box::pin(async move { Ok(peer) })
            })
        })
    }

    fn server(home: &std::path::Path, limits: (u64, u64)) -> Arc<Server> {
        Arc::new(
            Server::with_dispatcher(
                home,
                limits,
                identity(Arc::new(AtomicUsize::new(0))),
                Arc::new(Commands),
                Arc::new(crate::lobby::metrics::Metrics::new()),
            )
            .unwrap(),
        )
    }

    async fn connect(
        server: Arc<Server>,
        remote: &str,
    ) -> (
        client::Handle<Client>,
        tokio::task::JoinHandle<Result<(), russh::Error>>,
    ) {
        let (stream, client_stream) = UnixStream::pair().unwrap();
        let remote = remote.to_owned();
        let task = tokio::spawn(async move { server.serve_stream(&remote, stream).await });
        let mut client =
            client::connect_stream(Arc::new(client::Config::default()), client_stream, Client)
                .await
                .unwrap();
        assert!(client
            .authenticate_none("untrusted-root")
            .await
            .unwrap()
            .success());
        (client, task)
    }

    async fn disconnect(
        client: client::Handle<Client>,
        task: tokio::task::JoinHandle<Result<(), russh::Error>>,
    ) {
        client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    async fn collect(channel: &mut Channel<client::Msg>) -> (u32, Vec<u8>, Vec<u8>) {
        timeout(Duration::from_secs(3), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut status = None;
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                    ChannelMsg::Close => {
                        assert!(status.is_some(), "close preceded exit status");
                        break;
                    }
                    _ => {}
                }
            }
            (status.expect("exit status"), stdout, stderr)
        })
        .await
        .unwrap()
    }

    async fn until(channel: &mut Channel<client::Msg>, needle: &str) -> String {
        timeout(Duration::from_secs(3), async {
            let mut bytes = Vec::new();
            loop {
                match channel
                    .wait()
                    .await
                    .expect("channel closed before expected text")
                {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        bytes.extend_from_slice(&data)
                    }
                    _ => {}
                }
                let text = String::from_utf8_lossy(&bytes);
                if text.contains(needle) {
                    return text.into_owned();
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn exec_json_stdin_eof_and_confirmation_use_real_ssh() {
        let home = tempfile::tempdir().unwrap();
        let (client, task) = connect(server(home.path(), (8, 4)), "node").await;
        for (command, expected) in [
            ("whoami", "node\n"),
            ("ls --json", "{\"ok\":true,\"data\":[]}\n"),
        ] {
            let mut channel = client.channel_open_session().await.unwrap();
            channel.exec(true, command).await.unwrap();
            let (code, stdout, stderr) = collect(&mut channel).await;
            assert_eq!(code, 0);
            assert_eq!(stdout, expected.as_bytes());
            assert!(stderr.is_empty());
        }
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "cat").await.unwrap();
        channel.data(&b"binary\0data"[..]).await.unwrap();
        channel.eof().await.unwrap();
        let (code, stdout, _) = collect(&mut channel).await;
        assert_eq!(code, 0);
        assert_eq!(stdout, b"binary\0data");
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "confirm").await.unwrap();
        until(&mut channel, "Continue? ").await;
        channel.data(&b"yes\r"[..]).await.unwrap();
        let (code, stdout, _) = collect(&mut channel).await;
        assert_eq!(code, 0);
        assert_eq!(stdout, b"yes");
        disconnect(client, task).await;
    }

    #[tokio::test]
    async fn prompt_echo_unicode_control_keys_and_fresh_commands() {
        let home = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = Arc::new(
            Server::with_dispatcher(
                home.path(),
                (8, 4),
                identity(calls.clone()),
                Arc::new(Commands),
                Arc::new(crate::lobby::metrics::Metrics::new()),
            )
            .unwrap(),
        );
        let (client, task) = connect(server, "node").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        until(&mut channel, "silo> ").await;
        channel.data(&b"bad\x03"[..]).await.unwrap();
        assert!(until(&mut channel, "^C\r\n").await.contains("bad"));
        until(&mut channel, "silo> ").await;
        channel.data(&b"whoami\r\n"[..]).await.unwrap();
        until(&mut channel, "node\n").await;
        until(&mut channel, "silo> ").await;
        channel.data(&b"\x04"[..]).await.unwrap();
        assert_eq!(collect(&mut channel).await.0, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        disconnect(client, task).await;
    }

    #[tokio::test]
    async fn resize_and_named_signals_reach_session_io() {
        let home = tempfile::tempdir().unwrap();
        let (client, task) = connect(server(home.path(), (8, 4)), "node").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.exec(true, "resize").await.unwrap();
        until(&mut channel, "xterm:80x24\n").await;
        channel.window_change(120, 50, 0, 0).await.unwrap();
        let (code, stdout, _) = collect(&mut channel).await;
        assert_eq!(code, 0);
        assert_eq!(stdout, b"120x50\n");
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "signal").await.unwrap();
        until(&mut channel, "ready\n").await;
        channel
            .signal(russh::Sig::Custom("USR2".into()))
            .await
            .unwrap();
        assert_eq!(collect(&mut channel).await.1, b"signal received\n");
        disconnect(client, task).await;
    }

    #[tokio::test]
    async fn non_pty_shell_prints_help_and_forwarding_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let (client, task) = connect(server(home.path(), (8, 4)), "node").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel.request_shell(true).await.unwrap();
        let (code, _, stderr) = collect(&mut channel).await;
        assert_eq!(code, 2);
        assert!(String::from_utf8(stderr).unwrap().contains("whoami"));
        for request in 0..3 {
            let mut channel = client.channel_open_session().await.unwrap();
            match request {
                0 => channel.request_subsystem(true, "sftp").await.unwrap(),
                1 => channel.agent_forward(true).await.unwrap(),
                _ => channel
                    .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "cookie", 0)
                    .await
                    .unwrap(),
            }
            assert!(matches!(
                timeout(Duration::from_secs(2), channel.wait())
                    .await
                    .unwrap(),
                Some(ChannelMsg::Failure)
            ));
            channel.close().await.unwrap();
        }
        assert!(client
            .channel_open_direct_tcpip("localhost", 123, "localhost", 123)
            .await
            .is_err());
        assert!(client.tcpip_forward("localhost", 0).await.is_err());
        disconnect(client, task).await;
    }

    #[tokio::test]
    async fn global_and_per_peer_caps_release_on_channel_close_and_disconnect() {
        let home = tempfile::tempdir().unwrap();
        let server = server(home.path(), (2, 1));
        let (a, at) = connect(server.clone(), "a").await;
        let (b, bt) = connect(server.clone(), "b").await;
        let (c, ct) = connect(server.clone(), "c").await;
        let first = a.channel_open_session().await.unwrap();
        first.exec(true, "wait").await.unwrap();
        let mut denied = a.channel_open_session().await.unwrap();
        denied.exec(true, "whoami").await.unwrap();
        let (code, _, stderr) = collect(&mut denied).await;
        assert_eq!(code, 6);
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("session limit reached"));
        let second = b.channel_open_session().await.unwrap();
        second.exec(true, "wait").await.unwrap();
        let mut denied = c.channel_open_session().await.unwrap();
        denied.exec(true, "whoami").await.unwrap();
        assert_eq!(collect(&mut denied).await.0, 6);
        assert!(server
            .shared
            .metrics
            .render()
            .contains("lobby_active_sessions 2\n"));
        first.close().await.unwrap();
        timeout(Duration::from_secs(2), async {
            while server.shared.counts.lock().total != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(server
            .shared
            .metrics
            .render()
            .contains("lobby_active_sessions 1\n"));
        let mut accepted = a.channel_open_session().await.unwrap();
        accepted.exec(true, "whoami").await.unwrap();
        assert_eq!(collect(&mut accepted).await.0, 0);
        disconnect(b, bt).await;
        timeout(Duration::from_secs(2), async {
            while server.shared.counts.lock().total != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(server
            .shared
            .metrics
            .render()
            .contains("lobby_active_sessions 0\n"));
        let mut accepted = c.channel_open_session().await.unwrap();
        accepted.exec(true, "whoami").await.unwrap();
        assert_eq!(collect(&mut accepted).await.0, 0);
        disconnect(a, at).await;
        disconnect(c, ct).await;
        assert!(server
            .shared
            .metrics
            .render()
            .contains("lobby_active_sessions 0\n"));
    }

    #[tokio::test]
    async fn unresolvable_identity_is_denied_and_host_keys_survive_instances() {
        let home = tempfile::tempdir().unwrap();
        let first = server(home.path(), (8, 4));
        let second = server(home.path(), (8, 4));
        assert_eq!(
            first.config.keys[0].public_key(),
            second.config.keys[0].public_key()
        );
        let source: IdentitySource = Arc::new(|_| {
            Arc::new(|| {
                Box::pin(async {
                    Err(Failure::new(Code::Unavailable, "secret backend diagnostic"))
                })
            })
        });
        let denied = Arc::new(
            Server::with_dispatcher(
                home.path(),
                (8, 4),
                source,
                Arc::new(Commands),
                Arc::new(crate::lobby::metrics::Metrics::new()),
            )
            .unwrap(),
        );
        let (client, task) = connect(denied, "node").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "whoami").await.unwrap();
        let (code, _, stderr) = collect(&mut channel).await;
        assert_eq!(code, 4);
        assert!(String::from_utf8(stderr)
            .unwrap()
            .contains("identity unavailable"));
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn shutdown_deadline_cancels_live_sessions_and_stops_admission() {
        let home = tempfile::tempdir().unwrap();
        let server = server(home.path(), (8, 4));
        let (client, task) = connect(server.clone(), "node").await;
        let channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "wait").await.unwrap();
        let started = Instant::now();
        server.shutdown(started + Duration::from_millis(30)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(server
            .shared
            .metrics
            .render()
            .contains("lobby_active_sessions 0\n"));
        let (stream, _) = UnixStream::pair().unwrap();
        assert!(server.serve_stream("node", stream).await.is_err());
        drop(client);
    }

    #[tokio::test]
    async fn system_openssh_exec_and_forced_pty_prompt() {
        if let Err(error) = tokio::process::Command::new("ssh").arg("-V").output().await {
            if error.kind() == io::ErrorKind::NotFound {
                eprintln!("skipping OpenSSH interoperability: ssh is absent");
                return;
            }
            panic!("checking ssh: {error}");
        }
        let home = tempfile::tempdir().unwrap();
        let server = server(home.path(), (8, 4));
        for pty in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = server.clone();
            let task = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let (mut bridge, stream) = UnixStream::pair().unwrap();
                let copy = tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut bridge).await;
                });
                let result = server.serve_stream("openssh", stream).await;
                copy.await.unwrap();
                result
            });
            let mut command = tokio::process::Command::new("ssh");
            command.args([
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=3",
                "-p",
                &port.to_string(),
                if pty { "-tt" } else { "-T" },
                "ignored@127.0.0.1",
            ]);
            command.kill_on_drop(true);
            if !pty {
                command.args(["ls", "--json"]);
            }
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut child = command.spawn().unwrap();
            if pty {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"\x03\x04")
                    .await
                    .unwrap();
            }
            let output = timeout(Duration::from_secs(5), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "ssh failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if pty {
                assert!(String::from_utf8_lossy(&output.stderr).contains("silo> "));
            } else {
                assert_eq!(output.stdout, b"{\"ok\":true,\"data\":[]}\n");
            }
            timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn production_dispatcher_runs_service_commands_and_prompt() {
        use crate::lobby::{identity::Action, service::testing};
        let fixture = testing::fixture().await;
        let caller = testing::caller("user:1", &[Action::Read]);
        let source: IdentitySource = Arc::new(move |_| {
            let caller = caller.clone();
            Arc::new(move || {
                let caller = caller.clone();
                Box::pin(async move { caller.fresh().await })
            })
        });
        let server = Arc::new(
            Server::new(
                &fixture.root.path().join("home"),
                &Default::default(),
                source,
                Arc::new(fixture.service.clone()),
            )
            .unwrap(),
        );
        let (client, task) = connect(server, "transport-address").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "whoami --json").await.unwrap();
        let (code, stdout, stderr) = collect(&mut channel).await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        let json: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(json["ok"], true);
        assert!(String::from_utf8(stdout).unwrap().contains("node-user:1"));
        let mut channel = client.channel_open_session().await.unwrap();
        channel.exec(true, "ls --json").await.unwrap();
        let (code, stdout, _) = collect(&mut channel).await;
        assert_eq!(code, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&stdout).unwrap()["data"],
            serde_json::json!([])
        );
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        until(&mut channel, "silo> ").await;
        channel.data(&b"exit\r"[..]).await.unwrap();
        assert_eq!(collect(&mut channel).await.0, 0);
        disconnect(client, task).await;
    }

    #[tokio::test]
    async fn native_guest_exec_copy_both_directions_and_shell() {
        use crate::lobby::{identity::Action, service::testing};
        if std::env::var_os("SILO_LOBBY_E2E_RUNTIME").is_none() {
            eprintln!("skipping native SSH guest paths: set SILO_LOBBY_E2E_RUNTIME");
            return;
        }
        #[cfg(target_os = "linux")]
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("skipping native SSH guest paths: /dev/kvm is required");
            return;
        }
        let fixture = testing::fixture().await;
        let vm = fixture.running_vm("user:1").await.unwrap();
        let caller = testing::caller(
            "user:1",
            &[Action::Read, Action::Exec, Action::Shell, Action::Files],
        );
        let source: IdentitySource = Arc::new(move |_| {
            let caller = caller.clone();
            Arc::new(move || {
                let caller = caller.clone();
                Box::pin(async move { caller.fresh().await })
            })
        });
        let server = Arc::new(
            Server::new(
                &fixture.root.path().join("home"),
                &Default::default(),
                source,
                Arc::new(fixture.service.clone()),
            )
            .unwrap(),
        );
        let (client, task) = connect(server, "transport-address").await;
        let mut upload = client.channel_open_session().await.unwrap();
        upload
            .exec(true, format!("cp - {vm}:/tmp/lobby-ssh-copy"))
            .await
            .unwrap();
        upload.data(&b"ssh payload\n"[..]).await.unwrap();
        upload.eof().await.unwrap();
        let (code, _, stderr) = collect(&mut upload).await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        let mut download = client.channel_open_session().await.unwrap();
        download
            .exec(true, format!("cp {vm}:/tmp/lobby-ssh-copy -"))
            .await
            .unwrap();
        let (code, stdout, stderr) = collect(&mut download).await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(stdout, b"ssh payload\n");
        let mut exec = client.channel_open_session().await.unwrap();
        exec.exec(true, format!("exec {vm} -- cat")).await.unwrap();
        exec.data(&b"guest stdin\n"[..]).await.unwrap();
        exec.eof().await.unwrap();
        let (code, stdout, stderr) = collect(&mut exec).await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(stdout, b"guest stdin\n");
        let mut shell = client.channel_open_session().await.unwrap();
        shell
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        shell.exec(true, format!("shell {vm}")).await.unwrap();
        shell.window_change(120, 50, 0, 0).await.unwrap();
        shell
            .data(&b"printf 'guest-shell-ok\\n'; exit\n"[..])
            .await
            .unwrap();
        let (code, stdout, stderr) = collect(&mut shell).await;
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert!(String::from_utf8_lossy(&stdout).contains("guest-shell-ok"));
        disconnect(client, task).await;
        fixture.cleanup_vm(&vm).await.unwrap();
    }

    #[tokio::test]
    async fn idle_identity_revocation_closes_the_prompt_with_exit_four() {
        use std::sync::atomic::AtomicBool;
        let home = tempfile::tempdir().unwrap();
        let valid = Arc::new(AtomicBool::new(true));
        let current = valid.clone();
        let source: IdentitySource = Arc::new(move |_| {
            let current = current.clone();
            Arc::new(move || {
                let valid = current.load(Ordering::SeqCst);
                Box::pin(async move {
                    if !valid {
                        return Err(Failure::new(Code::Forbidden, "revoked"));
                    }
                    Ok(Peer {
                        principals: vec![Principal::parse("user:1").unwrap()],
                        node_id: "node".into(),
                        observed_at: chrono::Utc::now(),
                        ..Peer::default()
                    })
                })
            })
        });
        let server = Arc::new(
            Server::with_dispatcher(
                home.path(),
                (8, 4),
                source,
                Arc::new(Commands),
                Arc::new(crate::lobby::metrics::Metrics::new()),
            )
            .unwrap(),
        );
        let (client, task) = connect(server, "node").await;
        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        until(&mut channel, "silo> ").await;
        valid.store(false, Ordering::SeqCst);
        let status = timeout(Duration::from_secs(35), async {
            loop {
                if let Some(ChannelMsg::ExitStatus { exit_status }) = channel.wait().await {
                    break exit_status;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(status, 4);
        disconnect(client, task).await;
    }
}

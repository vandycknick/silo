use std::collections::{hash_map::Entry, HashMap};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use agent_spec::AgentSshConfig;
use eyre::Context;
use nix::pty::{openpty, OpenptyResult, Winsize};
use nix::sys::signal::{self, Signal};
use nix::unistd::{
    chown, dup, getgrouplist, getpid, setgid, setgroups, setsid, setuid, tcsetpgrp, Gid, Pid, Uid,
};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig};
use tokio::net::UnixListener;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream;

use crate::pid1::ProcessSupervisor;

const PASSWD_PATH: &str = "/etc/passwd";
const DEFAULT_SHELL: &str = "/bin/sh";
const DEFAULT_SHELL_NAME: &str = "sh";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const AGENT_SOCKET_DIR: &str = "/run/silo-ssh-agent";
const STDERR_EXTENDED_DATA: u32 = 1;
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_AGENT_FORWARD_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) struct NativeSshBackend {
    auth: Arc<AuthDb>,
    server_config: Arc<Config>,
    process_supervisor: ProcessSupervisor,
}

impl NativeSshBackend {
    pub(crate) fn new(
        config: AgentSshConfig,
        process_supervisor: ProcessSupervisor,
    ) -> eyre::Result<Self> {
        let auth = Arc::new(AuthDb::from_config(&config)?);
        let mut server_config = Config::default();
        server_config.inactivity_timeout = None;
        server_config.keys.push(generate_host_key()?);

        Ok(Self {
            auth,
            server_config: Arc::new(server_config),
            process_supervisor,
        })
    }

    pub(crate) fn wait_ready(&self) -> eyre::Result<()> {
        if self.auth.users.is_empty() {
            eyre::bail!("native SSH backend has no configured users present in {PASSWD_PATH}");
        }

        tracing::info!(users = self.auth.users.len(), "native SSH backend is ready");
        Ok(())
    }

    pub(crate) async fn handle_connection(&self, stream: VsockStream) -> io::Result<()> {
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let peer_addr = stream.peer_addr().ok();
        let local_addr = stream.local_addr().ok();
        tracing::info!(
            connection_id,
            peer_addr = ?peer_addr,
            local_addr = ?local_addr,
            "native SSH connection accepted"
        );

        let handler = NativeSshHandler {
            connection_id,
            auth: Arc::clone(&self.auth),
            process_supervisor: self.process_supervisor.clone(),
            authenticated_user: None,
            channels: HashMap::new(),
            runtime: RuntimeHandle::current(),
        };

        let session =
            match russh::server::run_stream(Arc::clone(&self.server_config), stream, handler).await
            {
                Ok(session) => session,
                Err(error) => {
                    let error = ssh_error_to_io(error);
                    tracing::warn!(
                        connection_id,
                        peer_addr = ?peer_addr,
                        error = %error,
                        "native SSH connection failed during handshake"
                    );
                    return Err(error);
                }
            };

        match session.await {
            Ok(()) => {
                tracing::info!(
                    connection_id,
                    peer_addr = ?peer_addr,
                    "native SSH connection closed"
                );
                Ok(())
            }
            Err(error) => {
                let error = ssh_error_to_io(error);
                tracing::warn!(
                    connection_id,
                    peer_addr = ?peer_addr,
                    error = %error,
                    "native SSH connection failed"
                );
                Err(error)
            }
        }
    }
}

struct NativeSshHandler {
    connection_id: u64,
    auth: Arc<AuthDb>,
    process_supervisor: ProcessSupervisor,
    authenticated_user: Option<UserEntry>,
    channels: HashMap<ChannelId, ChannelState>,
    runtime: RuntimeHandle,
}

impl Handler for NativeSshHandler {
    type Error = eyre::Report;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if let Some(auth_user) = self.auth.authenticate_none(user) {
            tracing::info!(
                connection_id = self.connection_id,
                user = %auth_user.name,
                method = "none",
                "native SSH authentication succeeded"
            );
            self.authenticated_user = Some(auth_user);
            return Ok(Auth::Accept);
        }

        tracing::debug!(
            connection_id = self.connection_id,
            user,
            method = "none",
            "native SSH authentication rejected"
        );
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.auth.public_key_allowed(user, public_key) {
            tracing::debug!(
                connection_id = self.connection_id,
                user,
                method = "publickey",
                "native SSH public key offer accepted"
            );
            return Ok(Auth::Accept);
        }

        tracing::debug!(
            connection_id = self.connection_id,
            user,
            method = "publickey",
            "native SSH public key offer rejected"
        );
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if let Some(auth_user) = self.auth.authenticate_public_key(user, public_key) {
            tracing::info!(
                connection_id = self.connection_id,
                user = %auth_user.name,
                method = "publickey",
                "native SSH authentication succeeded"
            );
            self.authenticated_user = Some(auth_user);
            return Ok(Auth::Accept);
        }

        tracing::debug!(
            connection_id = self.connection_id,
            user,
            method = "publickey",
            "native SSH authentication rejected"
        );
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        reply.accept().await;
        self.channels.insert(channel_id, ChannelState::default());
        tracing::info!(
            connection_id = self.connection_id,
            channel = channel_id.number(),
            "native SSH session channel opened"
        );
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if state.process_group.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }

        state.pty = Some(PtyRequest {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
            width_px: pix_width,
            height_px: pix_height,
        });
        session.channel_success(channel)?;
        tracing::debug!(
            connection_id = self.connection_id,
            channel = channel.number(),
            term,
            cols = col_width,
            rows = row_height,
            "native SSH PTY request accepted"
        );
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if valid_environment_name(variable_name) && !variable_value.contains('\0') {
            state
                .env
                .insert(variable_name.to_string(), variable_value.to_string());
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self.authenticated_user.clone() else {
            session.channel_failure(channel)?;
            return Ok(true);
        };
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(true);
        };
        if state.process_group.is_some() {
            session.channel_failure(channel)?;
            return Ok(true);
        }
        if state.agent_forward.is_none() {
            let agent_forward =
                match start_agent_forward(session.handle(), self.connection_id, channel, &user) {
                    Ok(agent_forward) => agent_forward,
                    Err(err) => {
                        tracing::warn!(
                            connection_id = self.connection_id,
                            channel = channel.number(),
                            user = %user.name,
                            error = %err,
                            "failed to enable native SSH agent forwarding"
                        );
                        session.channel_failure(channel)?;
                        return Ok(true);
                    }
                };
            state.agent_forward = Some(agent_forward);
            tracing::info!(
                connection_id = self.connection_id,
                channel = channel.number(),
                user = %user.name,
                "native SSH agent forwarding enabled"
            );
        }
        session.channel_success(channel)?;
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start_process(channel, SessionRequest::Shell, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8(data.to_vec()).context("decode SSH exec command")?;
        self.start_process(channel, SessionRequest::Exec(command), session)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&channel) {
            if let Some(input) = &state.input {
                if input.send(data.to_vec()).is_err() {
                    tracing::debug!(channel = channel.number(), "SSH session stdin is closed");
                }
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get_mut(&channel) {
            state.input = None;
            tracing::debug!(
                connection_id = self.connection_id,
                channel = channel.number(),
                "native SSH channel EOF received"
            );
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&channel) {
            state.terminate();
            tracing::debug!(
                connection_id = self.connection_id,
                channel = channel.number(),
                "native SSH channel closed"
            );
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let Some(resize) = &state.pty_resize else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        resize_pty(
            resize,
            &PtyRequest {
                term: state
                    .pty
                    .as_ref()
                    .map(|request| request.term.clone())
                    .unwrap_or_default(),
                cols: col_width,
                rows: row_height,
                width_px: pix_width,
                height_px: pix_height,
            },
        )?;
        if let Some(pty) = &mut state.pty {
            pty.cols = col_width;
            pty.rows = row_height;
            pty.width_px = pix_width;
            pty.height_px = pix_height;
        }
        session.channel_success(channel)?;
        tracing::debug!(
            connection_id = self.connection_id,
            channel = channel.number(),
            cols = col_width,
            rows = row_height,
            "native SSH PTY resized"
        );
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get(&channel) else {
            return Ok(());
        };
        let Some(process_group) = state.process_group else {
            return Ok(());
        };
        if let Some(signal) = nix_signal(signal) {
            signal_process_group(process_group, signal);
            tracing::debug!(
                connection_id = self.connection_id,
                channel = channel.number(),
                process_group,
                signal = ?signal,
                "forwarded native SSH signal to session process group"
            );
        }
        Ok(())
    }
}

impl NativeSshHandler {
    fn start_process(
        &mut self,
        channel: ChannelId,
        request: SessionRequest,
        session: &mut Session,
    ) -> Result<(), eyre::Report> {
        let Some(user) = self.authenticated_user.clone() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let Some(state) = self.channels.get(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if state.process_group.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let request_kind = request.kind();
        let has_pty = state.pty.is_some();
        let launch = ProcessLaunch {
            user,
            request,
            pty: state.pty.clone(),
            env: state.env.clone(),
            agent_socket: state
                .agent_forward
                .as_ref()
                .map(|forward| forward.path.clone()),
        };
        let user_name = launch.user.name.clone();

        match launch.spawn(
            self.connection_id,
            channel,
            session.handle(),
            self.runtime.clone(),
            self.process_supervisor.clone(),
        ) {
            Ok(active) => {
                let process_group = active.process_group;
                let state = self
                    .channels
                    .get_mut(&channel)
                    .ok_or_else(|| eyre::eyre!("SSH channel disappeared after process spawn"))?;
                state.input = Some(active.input);
                state.process_group = Some(process_group);
                state.pty_resize = active.pty_resize;
                session.channel_success(channel)?;
                tracing::info!(
                    connection_id = self.connection_id,
                    channel = channel.number(),
                    user = %user_name,
                    request = request_kind,
                    pty = has_pty,
                    process_group,
                    "native SSH session process started"
                );
            }
            Err(err) => {
                tracing::warn!(
                    connection_id = self.connection_id,
                    channel = channel.number(),
                    user = %user_name,
                    request = request_kind,
                    pty = has_pty,
                    error = %err,
                    "failed to start SSH session process"
                );
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ChannelState {
    pty: Option<PtyRequest>,
    env: HashMap<String, String>,
    input: Option<mpsc::Sender<Vec<u8>>>,
    process_group: Option<i32>,
    pty_resize: Option<File>,
    agent_forward: Option<AgentForward>,
}

impl ChannelState {
    fn terminate(mut self) {
        self.input = None;
        if let Some(process_group) = self.process_group {
            signal_process_group(process_group, Signal::SIGTERM);
        }
    }
}

#[derive(Clone)]
struct PtyRequest {
    term: String,
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
}

struct ActiveProcess {
    input: mpsc::Sender<Vec<u8>>,
    process_group: i32,
    pty_resize: Option<File>,
}

struct ProcessLaunch {
    user: UserEntry,
    request: SessionRequest,
    pty: Option<PtyRequest>,
    env: HashMap<String, String>,
    agent_socket: Option<PathBuf>,
}

impl ProcessLaunch {
    fn spawn(
        self,
        connection_id: u64,
        channel: ChannelId,
        handle: russh::server::Handle,
        runtime: RuntimeHandle,
        process_supervisor: ProcessSupervisor,
    ) -> eyre::Result<ActiveProcess> {
        if let Some(pty) = self.pty.clone() {
            let command = self.command(false);
            self.spawn_pty(
                command,
                &pty,
                connection_id,
                channel,
                handle,
                runtime,
                process_supervisor,
            )
        } else {
            let command = self.command(true);
            self.spawn_piped(
                command,
                connection_id,
                channel,
                handle,
                runtime,
                process_supervisor,
            )
        }
    }

    fn command(&self, new_process_group: bool) -> Command {
        let shell = self.user.shell();
        let mut command = Command::new(shell);
        match &self.request {
            SessionRequest::Shell => {
                command.arg0(login_shell_arg0(shell));
            }
            SessionRequest::Exec(data) => {
                command.arg("-c").arg(data);
            }
        }
        command.current_dir(&self.user.home);
        command.env_clear();
        command.env("HOME", &self.user.home);
        command.env("USER", &self.user.name);
        command.env("LOGNAME", &self.user.name);
        command.env("SHELL", shell);
        command.env("PATH", DEFAULT_PATH);
        if let Some(pty) = &self.pty {
            command.env("TERM", &pty.term);
        }
        if let Some(agent_socket) = &self.agent_socket {
            command.env("SSH_AUTH_SOCK", agent_socket);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        if new_process_group {
            command.process_group(0);
        }
        prepare_user_child(&mut command, &self.user);
        command
    }

    fn spawn_piped(
        self,
        mut command: Command,
        connection_id: u64,
        channel: ChannelId,
        handle: russh::server::Handle,
        runtime: RuntimeHandle,
        process_supervisor: ProcessSupervisor,
    ) -> eyre::Result<ActiveProcess> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (mut child, guard) = process_supervisor
            .spawn_child(&mut command, "native ssh session")
            .context("spawn SSH session process")?;
        let process_group = process_group_from_child(&child)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| eyre::eyre!("SSH session process stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| eyre::eyre!("SSH session process stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| eyre::eyre!("SSH session process stderr was not piped"))?;
        let (input, input_rx) = mpsc::channel();

        spawn_input_writer(channel, input_rx, stdin);
        spawn_output_reader(
            channel,
            handle.clone(),
            runtime.clone(),
            stdout,
            OutputStream::Stdout,
        );
        spawn_output_reader(
            channel,
            handle.clone(),
            runtime.clone(),
            stderr,
            OutputStream::Stderr,
        );
        spawn_exit_waiter(connection_id, channel, handle, runtime, child, guard);

        Ok(ActiveProcess {
            input,
            process_group,
            pty_resize: None,
        })
    }

    fn spawn_pty(
        self,
        mut command: Command,
        pty: &PtyRequest,
        connection_id: u64,
        channel: ChannelId,
        handle: russh::server::Handle,
        runtime: RuntimeHandle,
        process_supervisor: ProcessSupervisor,
    ) -> eyre::Result<ActiveProcess> {
        let openpty = open_session_pty(pty).context("open SSH session pty")?;
        let master = File::from(openpty.master);
        let reader = master.try_clone().context("clone SSH pty reader")?;
        let writer = master.try_clone().context("clone SSH pty writer")?;
        let resize = master.try_clone().context("clone SSH pty resize handle")?;
        attach_pty_slave(&mut command, openpty.slave).context("attach SSH pty slave")?;
        prepare_pty_child(&mut command);

        let (child, guard) = process_supervisor
            .spawn_session_child(&mut command, "native ssh pty session")
            .context("spawn SSH pty session process")?;
        let process_group = process_group_from_child(&child)?;
        let (input, input_rx) = mpsc::channel();

        spawn_input_writer(channel, input_rx, writer);
        spawn_output_reader(
            channel,
            handle.clone(),
            runtime.clone(),
            reader,
            OutputStream::Stdout,
        );
        spawn_exit_waiter(connection_id, channel, handle, runtime, child, guard);

        Ok(ActiveProcess {
            input,
            process_group,
            pty_resize: Some(resize),
        })
    }
}

enum SessionRequest {
    Shell,
    Exec(String),
}

impl SessionRequest {
    fn kind(&self) -> &'static str {
        match self {
            SessionRequest::Shell => "shell",
            SessionRequest::Exec(_) => "exec",
        }
    }
}

struct AgentForward {
    path: PathBuf,
    dir: PathBuf,
    task: JoinHandle<()>,
}

impl Drop for AgentForward {
    fn drop(&mut self) {
        self.task.abort();
        if let Err(err) = fs::remove_file(&self.path) {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::debug!(path = %self.path.display(), error = %err, "failed to remove SSH agent socket");
            }
        }
        if let Err(err) = fs::remove_dir(&self.dir) {
            if err.kind() != io::ErrorKind::NotFound {
                tracing::debug!(path = %self.dir.display(), error = %err, "failed to remove SSH agent socket directory");
            }
        }
    }
}

#[derive(Clone)]
struct AuthDb {
    users: HashMap<String, AuthUser>,
}

impl AuthDb {
    fn from_config(config: &AgentSshConfig) -> eyre::Result<Self> {
        let passwd = parse_passwd(PASSWD_PATH)?;
        let mut users: HashMap<String, AuthUser> = HashMap::new();

        for configured in &config.authorized_users {
            let Some(mut user) = passwd.get(&configured.name).cloned() else {
                tracing::warn!(
                    user = configured.name,
                    "configured SSH user is not present in /etc/passwd"
                );
                continue;
            };
            let auth_user = match users.entry(user.name.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    user.groups = supplementary_groups(&user)?;
                    entry.insert(AuthUser {
                        user,
                        keys: Vec::new(),
                        allow_without_auth: false,
                    })
                }
            };
            auth_user.allow_without_auth |= configured.allow_without_auth;
            for key in &configured.authorized_keys {
                let key = key.trim();
                if key.is_empty() {
                    continue;
                }
                auth_user
                    .keys
                    .push(PublicKey::from_openssh(key).with_context(|| {
                        format!("parse SSH authorized key for {}", configured.name)
                    })?);
            }
        }

        Ok(Self { users })
    }

    fn authenticate_none(&self, name: &str) -> Option<UserEntry> {
        let user = self.users.get(name)?;
        user.allow_without_auth.then(|| user.user.clone())
    }

    fn public_key_allowed(&self, name: &str, public_key: &PublicKey) -> bool {
        self.users
            .get(name)
            .map(|user| user.keys.iter().any(|key| same_public_key(key, public_key)))
            .unwrap_or(false)
    }

    fn authenticate_public_key(&self, name: &str, public_key: &PublicKey) -> Option<UserEntry> {
        let user = self.users.get(name)?;
        user.keys
            .iter()
            .any(|key| same_public_key(key, public_key))
            .then(|| user.user.clone())
    }
}

#[derive(Clone)]
struct AuthUser {
    user: UserEntry,
    keys: Vec<PublicKey>,
    allow_without_auth: bool,
}

#[derive(Clone)]
struct UserEntry {
    name: String,
    uid: u32,
    gid: u32,
    groups: Vec<Gid>,
    home: PathBuf,
    shell: String,
}

impl UserEntry {
    fn shell(&self) -> &str {
        if self.shell.is_empty() {
            DEFAULT_SHELL
        } else {
            &self.shell
        }
    }
}

fn parse_passwd(path: impl AsRef<Path>) -> eyre::Result<HashMap<String, UserEntry>> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("read {}", path.as_ref().display()))?;
    let mut users = HashMap::new();
    for (line_index, line) in content.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 7 {
            tracing::warn!(line = line_index + 1, "skipping malformed passwd entry");
            continue;
        }
        let uid = match fields[2].parse::<u32>() {
            Ok(uid) => uid,
            Err(err) => {
                tracing::warn!(line = line_index + 1, error = %err, "skipping passwd entry with invalid uid");
                continue;
            }
        };
        let gid = match fields[3].parse::<u32>() {
            Ok(gid) => gid,
            Err(err) => {
                tracing::warn!(line = line_index + 1, error = %err, "skipping passwd entry with invalid gid");
                continue;
            }
        };
        let user = UserEntry {
            name: fields[0].to_string(),
            uid,
            gid,
            groups: Vec::new(),
            home: PathBuf::from(fields[5]),
            shell: fields[6].to_string(),
        };
        users.insert(user.name.clone(), user);
    }
    Ok(users)
}

fn supplementary_groups(user: &UserEntry) -> eyre::Result<Vec<Gid>> {
    let name = CString::new(user.name.as_str())
        .with_context(|| format!("prepare group lookup for user {}", user.name))?;
    getgrouplist(&name, Gid::from_raw(user.gid))
        .with_context(|| format!("lookup supplementary groups for user {}", user.name))
}

fn generate_host_key() -> eyre::Result<PrivateKey> {
    let mut seed = [0_u8; 32];
    File::open("/dev/urandom")
        .context("open /dev/urandom for native SSH host key")?
        .read_exact(&mut seed)
        .context("read native SSH host key seed")?;
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(&seed)))
}

fn open_session_pty(pty: &PtyRequest) -> nix::Result<OpenptyResult> {
    let winsize = Winsize {
        ws_row: clamp_to_u16(pty.rows),
        ws_col: clamp_to_u16(pty.cols),
        ws_xpixel: clamp_to_u16(pty.width_px),
        ws_ypixel: clamp_to_u16(pty.height_px),
    };
    openpty(Some(&winsize), None)
}

fn attach_pty_slave(command: &mut Command, slave: OwnedFd) -> io::Result<()> {
    let stdin = dup(&slave).map_err(io::Error::from)?;
    let stdout = dup(&slave).map_err(io::Error::from)?;
    command.stdin(Stdio::from(stdin));
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(slave));
    Ok(())
}

fn prepare_user_child(command: &mut Command, user: &UserEntry) {
    let groups = user.groups.clone();
    let gid = Gid::from_raw(user.gid);
    let uid = Uid::from_raw(user.uid);

    unsafe {
        command.pre_exec(move || {
            setgroups(&groups).map_err(io::Error::from)?;
            setgid(gid).map_err(io::Error::from)?;
            setuid(uid).map_err(io::Error::from)?;
            Ok(())
        });
    }
}

fn login_shell_arg0(shell: &str) -> OsString {
    let name = Path::new(shell)
        .file_name()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| OsStr::new(DEFAULT_SHELL_NAME));
    let mut arg0 = OsString::from("-");
    arg0.push(name);
    arg0
}

fn prepare_pty_child(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            setsid().map_err(io::Error::from)?;

            // nix does not expose a safe TIOCSCTTY wrapper.
            let result = nix::libc::ioctl(nix::libc::STDIN_FILENO, nix::libc::TIOCSCTTY, 0);
            if result == -1 {
                return Err(io::Error::last_os_error());
            }

            let stdin = BorrowedFd::borrow_raw(nix::libc::STDIN_FILENO);
            tcsetpgrp(stdin, getpid()).map_err(io::Error::from)?;
            Ok(())
        });
    }
}

fn resize_pty(master: &File, pty: &PtyRequest) -> io::Result<()> {
    let winsize = Winsize {
        ws_row: clamp_to_u16(pty.rows),
        ws_col: clamp_to_u16(pty.cols),
        ws_xpixel: clamp_to_u16(pty.width_px),
        ws_ypixel: clamp_to_u16(pty.height_px),
    };
    // nix exposes openpty but not a safe TIOCSWINSZ wrapper.
    let result = unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn start_agent_forward(
    handle: russh::server::Handle,
    connection_id: u64,
    channel: ChannelId,
    user: &UserEntry,
) -> io::Result<AgentForward> {
    fs::create_dir_all(AGENT_SOCKET_DIR)?;
    fs::set_permissions(AGENT_SOCKET_DIR, fs::Permissions::from_mode(0o755))?;

    let dir = create_agent_socket_dir(user, connection_id, channel)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    chown(
        &dir,
        Some(Uid::from_raw(user.uid)),
        Some(Gid::from_raw(user.gid)),
    )
    .map_err(io::Error::from)?;

    let path = dir.join("agent");
    let listener = UnixListener::bind(&path)?;
    chown(
        &path,
        Some(Uid::from_raw(user.uid)),
        Some(Gid::from_raw(user.gid)),
    )
    .map_err(io::Error::from)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    let task = tokio::spawn(async move {
        loop {
            let (mut local, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::debug!(error = %err, "SSH agent socket accept failed");
                    break;
                }
            };
            let handle = handle.clone();
            tokio::spawn(async move {
                let Ok(channel) = handle.channel_open_agent().await else {
                    tracing::debug!("failed to open SSH agent forwarding channel");
                    return;
                };
                let mut remote = channel.into_stream();
                if let Err(err) = tokio::io::copy_bidirectional(&mut local, &mut remote).await {
                    tracing::debug!(error = %err, "SSH agent forwarding proxy failed");
                }
            });
        }
    });
    Ok(AgentForward { path, dir, task })
}

fn create_agent_socket_dir(
    user: &UserEntry,
    connection_id: u64,
    channel: ChannelId,
) -> io::Result<PathBuf> {
    for _ in 0..128 {
        let forward_id = NEXT_AGENT_FORWARD_ID.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(AGENT_SOCKET_DIR).join(format!(
            "{}.{}.{}.{}.{}",
            user.uid,
            std::process::id(),
            connection_id,
            forward_id,
            channel.number()
        ));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                tracing::debug!(path = %dir.display(), "SSH agent socket directory already exists, retrying");
            }
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique SSH agent socket directory",
    ))
}

fn spawn_input_writer<W>(channel: ChannelId, input: mpsc::Receiver<Vec<u8>>, mut writer: W)
where
    W: Write + Send + 'static,
{
    if let Err(err) = thread::Builder::new()
        .name(format!("silo-ssh-stdin-{}", channel.number()))
        .spawn(move || {
            for data in input {
                if let Err(err) = writer.write_all(&data) {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        tracing::debug!(channel = channel.number(), error = %err, "SSH stdin write failed");
                    }
                    break;
                }
            }
        })
    {
        tracing::warn!(channel = channel.number(), error = %err, "failed to spawn SSH stdin thread");
    }
}

fn spawn_output_reader<R>(
    channel: ChannelId,
    handle: russh::server::Handle,
    runtime: RuntimeHandle,
    mut reader: R,
    stream: OutputStream,
) where
    R: Read + Send + 'static,
{
    if let Err(err) = thread::Builder::new()
        .name(format!("silo-ssh-{:?}-{}", stream, channel.number()))
        .spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                let read = match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(err) => {
                        if err.kind() != io::ErrorKind::Interrupted {
                            tracing::debug!(channel = channel.number(), error = %err, "SSH output read failed");
                            break;
                        }
                        continue;
                    }
                };
                let data = buffer[..read].to_vec();
                let result = match stream {
                    OutputStream::Stdout => runtime.block_on(handle.data(channel, data)),
                    OutputStream::Stderr => {
                        runtime.block_on(handle.extended_data(channel, STDERR_EXTENDED_DATA, data))
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
    {
        tracing::warn!(channel = channel.number(), error = %err, "failed to spawn SSH output thread");
    }
}

fn spawn_exit_waiter(
    connection_id: u64,
    channel: ChannelId,
    handle: russh::server::Handle,
    runtime: RuntimeHandle,
    mut child: Child,
    guard: crate::pid1::ChildGuard,
) {
    if let Err(err) = thread::Builder::new()
        .name(format!("silo-ssh-wait-{}", channel.number()))
        .spawn(move || {
            let status = child.wait();
            drop(guard);
            match status {
                Ok(status) => {
                    let code = exit_status_code(status);
                    tracing::info!(
                        connection_id,
                        channel = channel.number(),
                        exit_status = code,
                        success = status.success(),
                        "native SSH session process exited"
                    );
                    let _ = runtime.block_on(handle.exit_status_request(channel, code));
                }
                Err(err) => {
                    tracing::warn!(
                        connection_id,
                        channel = channel.number(),
                        error = %err,
                        "SSH session wait failed"
                    );
                    let _ = runtime.block_on(handle.exit_status_request(channel, 255));
                }
            }
            let _ = runtime.block_on(handle.eof(channel));
            let _ = runtime.block_on(handle.close(channel));
        })
    {
        tracing::warn!(channel = channel.number(), error = %err, "failed to spawn SSH wait thread");
    }
}

#[derive(Debug, Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

fn valid_environment_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn same_public_key(left: &PublicKey, right: &PublicKey) -> bool {
    left.key_data() == right.key_data()
}

fn process_group_from_child(child: &Child) -> eyre::Result<i32> {
    i32::try_from(child.id()).context("SSH session child pid does not fit in i32")
}

fn signal_process_group(process_group: i32, signal: Signal) {
    if process_group <= 0 {
        return;
    }
    if let Err(err) = signal::kill(Pid::from_raw(-process_group), signal) {
        tracing::debug!(process_group, signal = ?signal, error = %err, "failed to signal SSH session process group");
    }
}

fn nix_signal(signal: Sig) -> Option<Signal> {
    match signal {
        Sig::ABRT => Some(Signal::SIGABRT),
        Sig::ALRM => Some(Signal::SIGALRM),
        Sig::FPE => Some(Signal::SIGFPE),
        Sig::HUP => Some(Signal::SIGHUP),
        Sig::ILL => Some(Signal::SIGILL),
        Sig::INT => Some(Signal::SIGINT),
        Sig::KILL => Some(Signal::SIGKILL),
        Sig::PIPE => Some(Signal::SIGPIPE),
        Sig::QUIT => Some(Signal::SIGQUIT),
        Sig::SEGV => Some(Signal::SIGSEGV),
        Sig::TERM => Some(Signal::SIGTERM),
        Sig::USR1 => Some(Signal::SIGUSR1),
        Sig::Custom(_) => None,
    }
}

fn exit_status_code(status: ExitStatus) -> u32 {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        return u32::try_from(code).unwrap_or(255);
    }
    status
        .signal()
        .and_then(|signal| u32::try_from(128 + signal).ok())
        .unwrap_or(255)
}

fn clamp_to_u16(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn ssh_error_to_io(error: eyre::Report) -> io::Error {
    io::Error::other(error.to_string())
}

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::mpsc;
use vm_spec::{VsockEndpoint, VsockEndpointMode};

use super::endpoint_mode_name;

pub(super) struct RunningPlugin {
    pub(super) child: Child,
    pub(super) events: mpsc::UnboundedReceiver<PluginEvent>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct StartupMessage {
    api_version: u32,
    vsock_endpoint: String,
    mode: VsockEndpointMode,
    port: u32,
    transport: PluginTransport,
    runtime_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<serde_json::Value>,
    fd: i32,
}

impl StartupMessage {
    pub(super) fn new(endpoint: &VsockEndpoint, runtime_dir: PathBuf, fd: i32) -> Self {
        Self {
            api_version: 1,
            vsock_endpoint: endpoint.name.clone(),
            mode: endpoint.mode,
            port: endpoint.port,
            transport: PluginTransport::for_mode(endpoint.mode),
            runtime_dir: runtime_dir.to_string_lossy().into_owned(),
            config: endpoint.plugin.config.clone(),
            fd,
        }
    }
}

pub(super) fn spawn_plugin(
    endpoint: &VsockEndpoint,
    fd3: OwnedFd,
    startup: &StartupMessage,
) -> io::Result<RunningPlugin> {
    let raw_fd3 = fd3.as_raw_fd();
    let mut command = Command::new(&endpoint.plugin.command);
    command
        .args(&endpoint.plugin.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    if let Some(working_dir) = &endpoint.plugin.working_dir {
        command.current_dir(working_dir);
    }
    for (key, value) in &endpoint.plugin.env {
        command.env(key, value);
    }

    unsafe {
        // pre_exec runs after fork and before exec, so keep this to direct,
        // async-signal-safe libc syscalls while forcing the plugin control
        // socket onto fd 3.
        command.as_std_mut().pre_exec(move || {
            if libc::dup2(raw_fd3, 3) == -1 {
                return Err(io::Error::last_os_error());
            }

            let flags = libc::fcntl(3, libc::F_GETFD);
            if flags == -1 {
                return Err(io::Error::last_os_error());
            }

            if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(io::Error::last_os_error());
            }

            if raw_fd3 != 3 && libc::close(raw_fd3) == -1 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    let mut child = command.spawn()?;
    tracing::info!(
        endpoint = %endpoint.name,
        mode = %endpoint_mode_name(endpoint.mode),
        port = endpoint.port,
        pid = ?child.id(),
        command = %endpoint.plugin.command.display(),
        "spawned endpoint plugin"
    );
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "plugin stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "plugin stdout unavailable"))?;

    let payload = serde_json::to_vec(startup).map_err(io::Error::other)?;
    let (tx, rx) = mpsc::unbounded_channel();
    spawn_stdout_reader(stdout, tx);

    tokio::spawn(async move {
        if let Err(err) = stdin.write_all(&payload).await {
            tracing::warn!(error = %err, "failed to write plugin startup payload");
            return;
        }
        if let Err(err) = stdin.write_all(b"\n").await {
            tracing::warn!(error = %err, "failed to terminate plugin startup payload");
        }
    });

    Ok(RunningPlugin { child, events: rx })
}

pub(super) async fn terminate_plugin(child: &mut Child) -> io::Result<()> {
    match child.kill().await {
        Ok(()) => {
            let _ = child.wait().await;
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => Ok(()),
        Err(err) => Err(err),
    }
}

fn spawn_stdout_reader(stdout: ChildStdout, tx: mpsc::UnboundedSender<PluginEvent>) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => match serde_json::from_str::<PluginStdoutEvent>(&line) {
                    Ok(event) => {
                        if tx.send(event.into()).is_err() {
                            return;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(PluginEvent::Failed(format!(
                            "invalid plugin stdout event: {err}"
                        )));
                        return;
                    }
                },
                Ok(None) => return,
                Err(err) => {
                    let _ = tx.send(PluginEvent::Failed(format!("read plugin stdout: {err}")));
                    return;
                }
            }
        }
    });
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PluginTransport {
    BrokeredConnect,
    ListenAccept,
}

impl PluginTransport {
    fn for_mode(mode: VsockEndpointMode) -> Self {
        match mode {
            VsockEndpointMode::Connect => Self::BrokeredConnect,
            VsockEndpointMode::Listen => Self::ListenAccept,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum PluginStdoutEvent {
    Ready,
    Failed { message: String },
}

impl From<PluginStdoutEvent> for PluginEvent {
    fn from(value: PluginStdoutEvent) -> Self {
        match value {
            PluginStdoutEvent::Ready => Self::Ready,
            PluginStdoutEvent::Failed { message } => Self::Failed(message),
        }
    }
}

#[derive(Debug)]
pub(super) enum PluginEvent {
    Ready,
    Failed(String),
}

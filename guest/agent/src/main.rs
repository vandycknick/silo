#[cfg(target_os = "linux")]
mod forward;
#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
mod port;
#[cfg(target_os = "linux")]
mod provision;
#[cfg(target_os = "linux")]
mod rpc;
#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(target_os = "linux")]
use agent_spec::{AgentConfig, SSH_VSOCK_PORT};
#[cfg(target_os = "linux")]
use eyre::Context;
#[cfg(target_os = "linux")]
use nix::fcntl::{fcntl, FcntlArg, OFlag};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncBufReadExt, BufReader};
#[cfg(target_os = "linux")]
use tokio::process::{ChildStderr, Command};
#[cfg(target_os = "linux")]
use tokio_vsock::VsockStream;

#[cfg(target_os = "linux")]
use crate::forward::ForwardService;
#[cfg(target_os = "linux")]
use crate::port::from_kernel_cmdline;
#[cfg(target_os = "linux")]
use crate::provision::run_provisioning;
#[cfg(target_os = "linux")]
use crate::rpc::GuestControlClient;
#[cfg(target_os = "linux")]
use crate::server::VsockServer;

#[cfg(target_os = "linux")]
const SSHD_RUNTIME_DIR: &str = "/run/sshd";
#[cfg(target_os = "linux")]
const SSHD_RUNTIME_DIR_MODE: u32 = 0o755;
#[cfg(target_os = "linux")]
const UNIX_MODE_BITS: u32 = 0o7777;
#[cfg(target_os = "linux")]
const GROUP_OR_WORLD_WRITABLE: u32 = 0o022;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshdRuntimeDirKind {
    Directory,
    Symlink,
    Other,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshdRuntimeDirDisposition {
    Ready,
    Chmod0755,
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    let is_pid1 = std::process::id() == 1;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stdout)
        .try_init();

    // TODO: support direct PID 1 initialization in the future. For now the
    // agent expects silo-init to hand it off to systemd.
    if is_pid1 {
        tracing::info!("running as PID 1 without init mode enabled yet");
    }

    tracing::info!("agent starting");

    reject_unexpected_args()?;

    let control_port = from_kernel_cmdline();
    let mut control = GuestControlClient::connect(control_port).await?;

    let metadata_response = control.get_metadata().await?;
    let metadata_config = metadata_response
        .config
        .ok_or_else(|| eyre::eyre!("guest metadata response did not include a config object"))?;
    let metadata_json = protocol::protobuf_struct_to_serde_json(metadata_config)
        .context("decode metadata config returned by vmmon")?;
    let agent_config: AgentConfig =
        serde_json::from_value(metadata_json).context("parse metadata config returned by vmmon")?;

    run_provisioning(&agent_config.provision)?;

    let mut running_servers = Vec::new();

    match VsockServer::create(handle_ssh_connection)
        .with_concurrency(256)
        .with_tracing(tracing::info_span!("vsock_server", service = "ssh"))
        .listen(SSH_VSOCK_PORT)
    {
        Ok(shell_server) => {
            ensure_sshd_runtime_dir().context("prepare OpenSSH runtime directory")?;
            tracing::info!(port = SSH_VSOCK_PORT, "listening for SSH vsock connections");
            running_servers.push(shell_server);
        }
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            tracing::info!(
                port = SSH_VSOCK_PORT,
                "SSH vsock port is already in use, leaving the existing listener active"
            );
        }
        Err(err) => {
            return Err(eyre::eyre!(
                "listen for SSH vsock connections on port {SSH_VSOCK_PORT}: {err}"
            ));
        }
    }

    if agent_config.forward.enabled {
        if agent_config.forward.port == 0 {
            return Err(eyre::eyre!(
                "forward guest runtime is enabled but no 'forward' endpoint port was configured"
            ));
        }

        let forward_service = ForwardService::new(agent_config.forward.clone())?;
        let forward_server = VsockServer::create(move |stream| {
            let forward_service = forward_service.clone();
            async move { forward_service.handle_connection(stream).await }
        })
        .with_concurrency(256)
        .with_tracing(tracing::info_span!("vsock_server", service = "forward"))
        .listen(agent_config.forward.port)?;
        running_servers.push(forward_server);
    }

    control.register().await?;

    let mut join_set = tokio::task::JoinSet::new();
    for server in running_servers {
        join_set.spawn(async move {
            server
                .wait()
                .await
                .context("guest vsock server task panicked")
        });
    }
    join_set.spawn(async { std::future::pending::<eyre::Result<()>>().await });

    let result = match join_set.join_next().await {
        Some(result) => result
            .context("agent task panicked")?
            .and_then(|()| Err(eyre::eyre!("agent task exited unexpectedly"))),
        None => Ok(()),
    };

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}

    result
}

#[cfg(target_os = "linux")]
fn ensure_sshd_runtime_dir() -> eyre::Result<()> {
    ensure_sshd_runtime_dir_at(Path::new(SSHD_RUNTIME_DIR))
}

#[cfg(target_os = "linux")]
fn ensure_sshd_runtime_dir_at(path: &Path) -> eyre::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => prepare_existing_sshd_runtime_dir(path, metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(SSHD_RUNTIME_DIR_MODE);
            builder
                .create(path)
                .with_context(|| format!("create {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(SSHD_RUNTIME_DIR_MODE))
                .with_context(|| format!("set permissions on {}", path.display()))?;
            let metadata =
                fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
            prepare_existing_sshd_runtime_dir(path, metadata)
        }
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn prepare_existing_sshd_runtime_dir(path: &Path, metadata: fs::Metadata) -> eyre::Result<()> {
    let mode = metadata.permissions().mode() & UNIX_MODE_BITS;
    let disposition = assess_sshd_runtime_dir(
        sshd_runtime_dir_kind(metadata.file_type()),
        metadata.uid(),
        metadata.gid(),
        mode,
    )
    .with_context(|| format!("validate {}", path.display()))?;

    if disposition == SshdRuntimeDirDisposition::Chmod0755 {
        fs::set_permissions(path, fs::Permissions::from_mode(SSHD_RUNTIME_DIR_MODE))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn sshd_runtime_dir_kind(file_type: fs::FileType) -> SshdRuntimeDirKind {
    if file_type.is_symlink() {
        SshdRuntimeDirKind::Symlink
    } else if file_type.is_dir() {
        SshdRuntimeDirKind::Directory
    } else {
        SshdRuntimeDirKind::Other
    }
}

#[cfg(target_os = "linux")]
fn assess_sshd_runtime_dir(
    kind: SshdRuntimeDirKind,
    uid: u32,
    gid: u32,
    mode: u32,
) -> eyre::Result<SshdRuntimeDirDisposition> {
    match kind {
        SshdRuntimeDirKind::Directory => {}
        SshdRuntimeDirKind::Symlink => eyre::bail!("directory must not be a symlink"),
        SshdRuntimeDirKind::Other => eyre::bail!("path must be a directory"),
    }

    if uid != 0 || gid != 0 {
        eyre::bail!("directory must be owned by root:root, found uid {uid} gid {gid}");
    }

    if mode & GROUP_OR_WORLD_WRITABLE != 0 {
        eyre::bail!("directory must not be group/world-writable, found mode {mode:o}");
    }

    if mode == SSHD_RUNTIME_DIR_MODE {
        Ok(SshdRuntimeDirDisposition::Ready)
    } else {
        Ok(SshdRuntimeDirDisposition::Chmod0755)
    }
}

#[cfg(target_os = "linux")]
async fn handle_ssh_connection(stream: VsockStream) -> io::Result<()> {
    clear_nonblocking(stream.as_fd())?;

    let sshd_stdin = stream.as_fd().try_clone_to_owned()?;
    let sshd_stdout = stream.as_fd().try_clone_to_owned()?;

    let mut child = Command::new("/usr/sbin/sshd")
        .arg("-i")
        .stdin(Stdio::from(sshd_stdin))
        .stdout(Stdio::from(sshd_stdout))
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture sshd stderr"))?;
    let stderr_task = tokio::spawn(log_sshd_stderr(stderr));

    let status = child.wait().await?;
    stderr_task.await.map_err(io::Error::other)??;

    if status.success() {
        tracing::debug!(status = %status, "sshd connection handler exited");
    } else {
        tracing::warn!(status = %status, "sshd connection handler exited unsuccessfully");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_nonblocking(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    let mut flags =
        OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?);
    flags.remove(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn log_sshd_stderr(stderr: ChildStderr) -> io::Result<()> {
    let mut reader = BufReader::new(stderr);
    let mut line = Vec::new();

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        if line.ends_with(b"\n") {
            line.pop();
        }
        if line.ends_with(b"\r") {
            line.pop();
        }

        let message = String::from_utf8_lossy(&line);
        tracing::warn!(message = %message, "sshd stderr");
    }
}

#[cfg(target_os = "linux")]
fn reject_unexpected_args() -> eyre::Result<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    if let Some(arg) = args.next() {
        eyre::bail!("unknown argument {:?}", arg);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use crate::{
        assess_sshd_runtime_dir, SshdRuntimeDirDisposition, SshdRuntimeDirKind,
        SSHD_RUNTIME_DIR_MODE,
    };

    #[test]
    fn accepts_root_owned_0755_directory() {
        let result =
            assess_sshd_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, SSHD_RUNTIME_DIR_MODE)
                .expect("assess directory");

        assert_eq!(result, SshdRuntimeDirDisposition::Ready);
    }

    #[test]
    fn repairs_root_owned_non_writable_directory_modes() {
        let result = assess_sshd_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o700)
            .expect("assess directory");

        assert_eq!(result, SshdRuntimeDirDisposition::Chmod0755);
    }

    #[test]
    fn rejects_symlink_runtime_dir() {
        let err = assess_sshd_runtime_dir(SshdRuntimeDirKind::Symlink, 0, 0, 0o755)
            .expect_err("symlink must fail");

        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_non_directory_runtime_dir() {
        let err = assess_sshd_runtime_dir(SshdRuntimeDirKind::Other, 0, 0, 0o755)
            .expect_err("non-directory must fail");

        assert!(err.to_string().contains("directory"));
    }

    #[test]
    fn rejects_non_root_owned_runtime_dir() {
        let err = assess_sshd_runtime_dir(SshdRuntimeDirKind::Directory, 1000, 0, 0o755)
            .expect_err("non-root owner must fail");

        assert!(err.to_string().contains("root:root"));
    }

    #[test]
    fn rejects_group_writable_runtime_dir() {
        let err = assess_sshd_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o775)
            .expect_err("group writable mode must fail");

        assert!(err.to_string().contains("group/world-writable"));
    }

    #[test]
    fn rejects_world_writable_runtime_dir() {
        let err = assess_sshd_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o777)
            .expect_err("world writable mode must fail");

        assert!(err.to_string().contains("group/world-writable"));
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("silo-agent only runs inside Linux guests");
    std::process::exit(1);
}

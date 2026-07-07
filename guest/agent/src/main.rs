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
use std::ffi::{CString, OsStr, OsString};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(target_os = "linux")]
use agent_spec::{AgentConfig, SSH_VSOCK_PORT};
#[cfg(target_os = "linux")]
use eyre::Context;
#[cfg(target_os = "linux")]
use nix::fcntl::{fcntl, FcntlArg, OFlag};
#[cfg(target_os = "linux")]
use nix::sys::signal::{self, SigHandler, SigSet, SigmaskHow, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::{execv, fork, setsid, ForkResult};
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
const HANDOFF_AUTO: &str = "auto";
#[cfg(target_os = "linux")]
const HANDOFF_AUTO_CANDIDATES: &[&str] = &[
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
];
#[cfg(target_os = "linux")]
const AGENT_RUN_BINARY: &str = "/run/agent/silo-agent";
#[cfg(target_os = "linux")]
const DEFAULT_AGENT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
#[derive(Debug, Default)]
struct AgentArgs {
    init: bool,
    handoff: Option<OsString>,
}

#[cfg(target_os = "linux")]
fn main() -> eyre::Result<()> {
    let is_pid1 = std::process::id() == 1;

    init_tracing();

    let agent_args = parse_agent_args()?;
    prepare_agent_process(&agent_args, is_pid1)?;
    ensure_default_path();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime")?;
    runtime.block_on(run_agent())
}

#[cfg(target_os = "linux")]
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stdout)
        .try_init();
}

#[cfg(target_os = "linux")]
fn prepare_agent_process(agent_args: &AgentArgs, is_pid1: bool) -> eyre::Result<()> {
    if agent_args.init {
        tracing::info!(handoff = ?agent_args.handoff, "agent init mode requested");
        maybe_handoff_init(agent_args)?;
    } else if is_pid1 {
        tracing::info!("running as PID 1 without init mode enabled yet");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_agent() -> eyre::Result<()> {
    tracing::info!("agent starting");

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
fn maybe_handoff_init(agent_args: &AgentArgs) -> eyre::Result<()> {
    let Some(handoff) = agent_args.handoff.as_deref() else {
        tracing::warn!("agent init mode requested without a handoff target");
        return Ok(());
    };

    let Some(target) = resolve_handoff_target(handoff)? else {
        tracing::info!(
            handoff = ?handoff,
            "no executable handoff init found; staying in agent PID1 mode"
        );
        return Ok(());
    };

    fork_handoff_init(&target)
}

#[cfg(target_os = "linux")]
fn resolve_handoff_target(handoff: &OsStr) -> eyre::Result<Option<PathBuf>> {
    if handoff == OsStr::new(HANDOFF_AUTO) {
        for candidate in HANDOFF_AUTO_CANDIDATES {
            let path = Path::new(candidate);
            if init_candidate_is_executable_file(path)? {
                return Ok(Some(path.to_path_buf()));
            }
        }
        return Ok(None);
    }

    if handoff.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(handoff);
    if init_candidate_is_executable_file(&path)? {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn init_candidate_is_executable_file(path: &Path) -> eyre::Result<bool> {
    if is_agent_binary(path) {
        return Ok(false);
    }

    match fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            Ok(metadata.file_type().is_file() && mode & 0o111 != 0)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("stat handoff init {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
fn is_agent_binary(path: &Path) -> bool {
    let agent = Path::new(AGENT_RUN_BINARY);
    if path == agent {
        return true;
    }

    match (fs::canonicalize(path), fs::canonicalize(agent)) {
        (Ok(path), Ok(agent)) => path == agent,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn fork_handoff_init(target: &Path) -> eyre::Result<()> {
    let init = CString::new(target.as_os_str().as_bytes())
        .with_context(|| format!("prepare handoff init path {}", target.display()))?;

    // Fork before constructing the Tokio runtime so the child does not inherit
    // async runtime internals. PID 1 becomes the guest init; the child remains
    // the Silo agent.
    match unsafe { fork() }.context("fork init handoff")? {
        ForkResult::Parent { .. } => exec_handoff_parent(&init, target),
        ForkResult::Child => {
            if let Err(err) = setsid() {
                tracing::warn!(error = %err, "failed to isolate agent child session");
            }
            tracing::info!(init = %target.display(), "continuing as agent after init handoff");
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn exec_handoff_parent(init: &std::ffi::CStr, target: &Path) -> eyre::Result<()> {
    reset_handoff_exec_state();
    if let Err(err) = std::env::set_current_dir("/") {
        tracing::error!(error = %err, "failed to chdir before init handoff exec");
        std::process::exit(127);
    }

    let argv = [init];
    match execv(init, &argv) {
        Ok(_) => unreachable!("execv returned after replacing the process"),
        Err(err) => {
            tracing::error!(init = %target.display(), error = %err, "failed to exec handoff init");
            std::process::exit(127);
        }
    }
}

#[cfg(target_os = "linux")]
fn reset_handoff_exec_state() {
    for signal in [
        Signal::SIGHUP,
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGTERM,
        Signal::SIGCHLD,
    ] {
        let _ = unsafe { signal::signal(signal, SigHandler::SigDfl) };
    }

    let empty = SigSet::empty();
    let _ = signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&empty), None);
}

#[cfg(target_os = "linux")]
fn ensure_default_path() {
    if std::env::var_os("PATH").is_some_and(|path| !path.is_empty()) {
        return;
    }

    std::env::set_var("PATH", DEFAULT_AGENT_PATH);
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
fn parse_agent_args() -> eyre::Result<AgentArgs> {
    let mut parsed = AgentArgs::default();
    let mut args = std::env::args_os();
    let _program = args.next();

    for arg in args {
        if arg.as_os_str() == OsStr::new("--init") {
            parsed.init = true;
            continue;
        }
        if let Some(handoff) = parse_handoff_arg(arg.as_os_str()) {
            parsed.handoff = Some(handoff);
            continue;
        }
        eyre::bail!("unknown argument {:?}", arg);
    }

    Ok(parsed)
}

#[cfg(target_os = "linux")]
fn parse_handoff_arg(arg: &OsStr) -> Option<OsString> {
    const PREFIX: &[u8] = b"--handoff=";

    let bytes = arg.as_bytes();
    bytes
        .strip_prefix(PREFIX)
        .map(|value| OsString::from_vec(value.to_vec()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::{
        assess_sshd_runtime_dir, init_candidate_is_executable_file, parse_handoff_arg,
        SshdRuntimeDirDisposition, SshdRuntimeDirKind, HANDOFF_AUTO_CANDIDATES,
        SSHD_RUNTIME_DIR_MODE,
    };

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn parses_handoff_equals_argument() {
        let value = parse_handoff_arg(OsStr::new("--handoff=/sbin/init"));

        assert_eq!(value.as_deref(), Some(OsStr::new("/sbin/init")));
    }

    #[test]
    fn rejects_split_handoff_argument() {
        assert!(parse_handoff_arg(OsStr::new("--handoff")).is_none());
    }

    #[test]
    fn auto_handoff_candidates_do_not_include_init() {
        assert_eq!(
            HANDOFF_AUTO_CANDIDATES,
            [
                "/sbin/init",
                "/lib/systemd/systemd",
                "/usr/lib/systemd/systemd"
            ]
        );
    }

    #[test]
    fn init_candidate_requires_executable_regular_file() {
        let dir = temp_dir("handoff-candidate");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");

        let file = dir.join("init");
        fs::write(&file, b"").expect("write candidate");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644))
            .expect("set candidate permissions");
        assert!(!init_candidate_is_executable_file(&file).expect("stat candidate"));

        fs::set_permissions(&file, fs::Permissions::from_mode(0o755))
            .expect("set candidate permissions");
        assert!(init_candidate_is_executable_file(&file).expect("stat candidate"));

        let directory = dir.join("directory");
        fs::create_dir(&directory).expect("create candidate directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .expect("set directory permissions");
        assert!(!init_candidate_is_executable_file(&directory).expect("stat directory"));

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    fn temp_dir(name: &str) -> PathBuf {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "silo-agent-{name}-{}-{sequence}",
            std::process::id()
        ))
    }

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

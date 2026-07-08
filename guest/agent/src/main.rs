#[cfg(not(target_os = "linux"))]
compile_error!("silo-agent only supports Linux guests");

mod forward;
mod handoff;
mod host;
mod pid1;
mod port;
mod provision;
mod rpc;
mod server;
mod ssh;

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use agent_spec::{AgentConfig, SSH_VSOCK_PORT};
use clap::Parser;
use eyre::Context;
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use protocol::v1::ProvisionOverallStatus;

use crate::forward::ForwardService;
use crate::handoff::BootMode;
use crate::pid1::ProcessSupervisor;
use crate::port::from_kernel_cmdline;
use crate::provision::run_provisioning;
use crate::rpc::GuestControlClient;
use crate::server::VsockServer;
use crate::ssh::SshService;

const DEFAULT_AGENT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const RUN_DIR: &str = "/run";
const RUN_DIR_MODE: u32 = 0o755;
const TMP_DIR: &str = "/tmp";
const TMP_DIR_MODE: u32 = 0o1777;
const DEV_PTS_DIR: &str = "/dev/pts";
const DEV_PTS_DIR_MODE: u32 = 0o755;
const DEV_SHM_DIR: &str = "/dev/shm";
const DEV_SHM_DIR_MODE: u32 = 0o1777;
const SYS_FS_CGROUP_DIR: &str = "/sys/fs/cgroup";
const SYS_FS_CGROUP_DIR_MODE: u32 = 0o755;
const DEV_FD: &str = "/dev/fd";
const PROC_SELF_FD: &str = "/proc/self/fd";

#[derive(Debug, Parser)]
#[command(
    name = "silo-agent",
    disable_help_flag = true,
    disable_help_subcommand = true,
    disable_version_flag = true
)]
struct AgentArgs {
    #[arg(long, requires = "handoff")]
    init: bool,
    #[arg(
        long,
        value_name = "TARGET",
        require_equals = true,
        value_parser = clap::builder::OsStringValueParser::new(),
        requires = "init"
    )]
    handoff: Option<OsString>,
}

#[derive(Debug, Eq, PartialEq)]
enum AgentMode {
    Standard,
    Init { requested_init: OsString },
}

fn main() -> eyre::Result<()> {
    let is_pid1 = std::process::id() == 1;

    init_tracing();

    let agent_args = parse_agent_args()?;
    let agent_mode = select_agent_mode(agent_args, is_pid1)?;
    ensure_default_path();
    let boot_mode = prepare_agent_process(&agent_mode)?;
    let process_supervisor = ProcessSupervisor::activate(&boot_mode)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime")?;
    runtime.block_on(run_agent(&boot_mode, process_supervisor))
}

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

fn select_agent_mode(agent_args: AgentArgs, is_pid1: bool) -> eyre::Result<AgentMode> {
    if agent_args.init {
        if !is_pid1 {
            eyre::bail!("--init requires silo-agent to run as PID 1");
        }
        let requested_init = agent_args
            .handoff
            .ok_or_else(|| eyre::eyre!("--init requires --handoff=<target>"))?;
        return Ok(AgentMode::Init { requested_init });
    }

    if is_pid1 {
        eyre::bail!("refusing to run as PID 1 without --init");
    }
    if agent_args.handoff.is_some() {
        eyre::bail!("--handoff requires --init");
    }

    Ok(AgentMode::Standard)
}

fn prepare_agent_process(agent_mode: &AgentMode) -> eyre::Result<BootMode> {
    if let AgentMode::Init { requested_init } = agent_mode {
        tracing::info!(requested_init = ?requested_init, "agent init mode requested");
        prepare_pid1_environment()?;
        return handoff::maybe_handoff_init(requested_init);
    }
    Ok(BootMode::Standard)
}

async fn run_agent(
    boot_mode: &BootMode,
    process_supervisor: ProcessSupervisor,
) -> eyre::Result<()> {
    tracing::info!(boot_mode = ?boot_mode, "agent starting");

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

    let boot_report = boot_mode.report();
    let provision_report = run_provisioning(
        &agent_config.provision,
        &agent_config.ssh,
        &process_supervisor,
        boot_mode,
    )?;

    if provision_report.status == ProvisionOverallStatus::FailedBoot as i32 {
        control
            .register(boot_report, provision_report)
            .await
            .context("register fatal guest provisioning report")?;
        if process_supervisor.is_active() {
            return process_supervisor.shutdown().await;
        }
        eyre::bail!("guest provisioning requested boot failure");
    }

    let mut running_servers = Vec::new();
    let mut server_abort_handles = Vec::new();

    let ssh_service = SshService::new(agent_config.ssh.clone(), process_supervisor.clone())?;
    let ssh_connection_service = ssh_service.clone();
    let owns_ssh_listener = match VsockServer::create(move |stream| {
        let ssh_service = ssh_connection_service.clone();
        async move { ssh_service.handle_connection(stream).await }
    })
    .with_concurrency(256)
    .with_tracing(tracing::info_span!("vsock_server", service = "ssh"))
    .listen(SSH_VSOCK_PORT)
    {
        Ok(shell_server) => {
            tracing::info!(port = SSH_VSOCK_PORT, "listening for SSH vsock connections");
            if let Some(abort_handle) = shell_server.abort_handle() {
                server_abort_handles.push(abort_handle);
            }
            running_servers.push(shell_server);
            true
        }
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            tracing::info!(
                port = SSH_VSOCK_PORT,
                "SSH vsock port is already in use, leaving the existing listener active"
            );
            false
        }
        Err(err) => {
            return Err(eyre::eyre!(
                "listen for SSH vsock connections on port {SSH_VSOCK_PORT}: {err}"
            ));
        }
    };

    if owns_ssh_listener {
        ssh_service.wait_ready().await?;
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
        if let Some(abort_handle) = forward_server.abort_handle() {
            server_abort_handles.push(abort_handle);
        }
        running_servers.push(forward_server);
    }

    control.register(boot_report, provision_report).await?;

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

    let result = if let Some(mut shutdown_rx) = process_supervisor.shutdown_receiver() {
        tokio::select! {
            result = join_set.join_next() => agent_task_result(result),
            () = async {
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            } => {
                tracing::warn!("PID1 shutdown observed; stopping guest agent listeners");
                for abort_handle in &server_abort_handles {
                    abort_handle.abort();
                }
                process_supervisor.shutdown().await
            }
        }
    } else {
        agent_task_result(join_set.join_next().await)
    };

    join_set.abort_all();
    while join_set.join_next().await.is_some() {}

    result
}

fn agent_task_result(
    result: Option<Result<eyre::Result<()>, tokio::task::JoinError>>,
) -> eyre::Result<()> {
    match result {
        Some(result) => result
            .context("agent task panicked")?
            .and_then(|()| Err(eyre::eyre!("agent task exited unexpectedly"))),
        None => Ok(()),
    }
}

fn prepare_pid1_environment() -> eyre::Result<()> {
    ensure_directory(Path::new(RUN_DIR), RUN_DIR_MODE)?;
    ensure_directory(Path::new(TMP_DIR), TMP_DIR_MODE)?;
    ensure_directory(Path::new(DEV_PTS_DIR), DEV_PTS_DIR_MODE)?;
    mount_pseudo_fs("devpts", Path::new(DEV_PTS_DIR), "devpts", MsFlags::empty())
        .context("prepare /dev/pts")?;
    ensure_directory(Path::new(DEV_SHM_DIR), DEV_SHM_DIR_MODE)?;
    mount_pseudo_fs(
        "tmpfs",
        Path::new(DEV_SHM_DIR),
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
    )
    .context("prepare /dev/shm")?;
    if let Err(err) = prepare_cgroup_mountpoint().and_then(|()| {
        mount_pseudo_fs(
            "cgroup2",
            Path::new(SYS_FS_CGROUP_DIR),
            "cgroup2",
            MsFlags::empty(),
        )
    }) {
        tracing::warn!(error = %err, "failed to prepare /sys/fs/cgroup; continuing");
    }
    ensure_dev_fd_symlink()?;

    Ok(())
}

fn prepare_cgroup_mountpoint() -> eyre::Result<()> {
    ensure_mountpoint_directory(Path::new(SYS_FS_CGROUP_DIR), SYS_FS_CGROUP_DIR_MODE)
        .context("prepare /sys/fs/cgroup mountpoint")
}

fn ensure_directory(path: &Path, mode: u32) -> eyre::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                eyre::bail!("{} must be a directory", path.display());
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode);
            builder
                .create(path)
                .with_context(|| format!("create {}", path.display()))?;
        }
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    }

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions on {}", path.display()))
}

fn ensure_mountpoint_directory(path: &Path, mode: u32) -> eyre::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                eyre::bail!("{} must be a directory", path.display());
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(mode);
            builder
                .create(path)
                .with_context(|| format!("create {}", path.display()))
        }
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn mount_pseudo_fs(source: &str, target: &Path, fstype: &str, flags: MsFlags) -> eyre::Result<()> {
    match mount(Some(source), target, Some(fstype), flags, None::<&str>) {
        Ok(()) | Err(Errno::EBUSY) => Ok(()),
        Err(err) => Err(eyre::eyre!(
            "mount {fstype} on {} failed: {err}",
            target.display()
        )),
    }
}

fn ensure_dev_fd_symlink() -> eyre::Result<()> {
    match fs::symlink_metadata(DEV_FD) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(PROC_SELF_FD, DEV_FD)
                .with_context(|| format!("create {DEV_FD} symlink"))
        }
        Err(err) => Err(err).with_context(|| format!("stat {DEV_FD}")),
    }
}

fn ensure_default_path() {
    if std::env::var_os("PATH").is_some_and(|path| !path.is_empty()) {
        return;
    }

    std::env::set_var("PATH", DEFAULT_AGENT_PATH);
}

fn parse_agent_args() -> eyre::Result<AgentArgs> {
    parse_agent_args_from(std::env::args_os())
}

fn parse_agent_args_from<I, T>(args: I) -> eyre::Result<AgentArgs>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    AgentArgs::try_parse_from(args).map_err(|err| eyre::eyre!(err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use crate::{parse_agent_args_from, select_agent_mode, AgentArgs, AgentMode};

    #[test]
    fn parses_handoff_equals_argument() {
        let args = parse_agent_args_from(["silo-agent", "--init", "--handoff=/sbin/init"])
            .expect("parse agent args");

        assert!(args.init);
        assert_eq!(args.handoff.as_deref(), Some(OsStr::new("/sbin/init")));
    }

    #[test]
    fn parses_empty_handoff_equals_argument() {
        let args = parse_agent_args_from(["silo-agent", "--init", "--handoff="])
            .expect("parse agent args");

        assert!(args.init);
        assert_eq!(args.handoff.as_deref(), Some(OsStr::new("")));
    }

    #[test]
    fn rejects_split_handoff_argument() {
        assert!(parse_agent_args_from(["silo-agent", "--init", "--handoff", "auto"]).is_err());
    }

    #[test]
    fn rejects_init_without_handoff() {
        assert!(parse_agent_args_from(["silo-agent", "--init"]).is_err());
    }

    #[test]
    fn rejects_handoff_without_init() {
        assert!(parse_agent_args_from(["silo-agent", "--handoff=auto"]).is_err());
    }

    #[test]
    fn rejects_duplicate_handoff() {
        assert!(parse_agent_args_from([
            "silo-agent",
            "--init",
            "--handoff=auto",
            "--handoff=/sbin/init",
        ])
        .is_err());
    }

    #[test]
    fn selects_standard_mode_for_non_pid1_without_args() {
        let mode = select_agent_mode(
            AgentArgs {
                init: false,
                handoff: None,
            },
            false,
        )
        .expect("select mode");

        assert_eq!(mode, AgentMode::Standard);
    }

    #[test]
    fn rejects_pid1_without_init_arg() {
        let err = select_agent_mode(
            AgentArgs {
                init: false,
                handoff: None,
            },
            true,
        )
        .expect_err("PID1 without --init must fail");

        assert!(err.to_string().contains("without --init"));
    }

    #[test]
    fn rejects_init_arg_outside_pid1() {
        let err = select_agent_mode(
            AgentArgs {
                init: true,
                handoff: Some(OsStr::new("auto").to_os_string()),
            },
            false,
        )
        .expect_err("--init outside PID1 must fail");

        assert!(err.to_string().contains("PID 1"));
    }

    #[test]
    fn selects_init_mode_for_pid1_with_handoff() {
        let mode = select_agent_mode(
            AgentArgs {
                init: true,
                handoff: Some(OsStr::new("auto").to_os_string()),
            },
            true,
        )
        .expect("select mode");

        assert_eq!(
            mode,
            AgentMode::Init {
                requested_init: OsStr::new("auto").to_os_string()
            }
        );
    }
}

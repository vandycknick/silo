#[cfg(not(target_os = "linux"))]
compile_error!("silo-agent only supports Linux guests");

mod clock;
mod clock_profile;
mod diagnostics;
mod filesystem;
mod forward;
mod freezer;
mod generation;
mod guest_process;
mod handoff;
mod host;
mod lifecycle;
mod memory_reclaim;
mod metrics;
mod orderly_shutdown;
mod pid1;
mod port;
mod provision;
mod root_storage;
mod rpc;
mod server;
mod ssh;

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use agent_spec::{AgentConfig, MAX_AGENT_CONFIG_SIZE_BYTES, SSH_VSOCK_PORT};
use clap::Parser;
use eyre::Context;
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use protocol::v1::ProvisionOverallStatus;

use crate::handoff::BootMode;
use crate::pid1::ProcessSupervisor;
use crate::port::from_kernel_cmdline;
use crate::provision::{prepare_early_provisioning, run_provisioning, EarlyProvisioning};
use crate::rpc::AgentServer;
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
    #[arg(long, value_name = "PATH", require_equals = true)]
    config: PathBuf,
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

    let diagnostics = init_tracing()?;

    let agent_args = parse_agent_args()?;
    let agent_config = load_agent_config(&agent_args.config)?;
    let agent_mode = select_agent_mode(&agent_args, is_pid1)?;
    ensure_default_path();
    let (boot_mode, early_provisioning, storage, workloads) =
        prepare_agent_process(&agent_mode, &agent_config)?;
    workloads.qualify_profile(&boot_mode);
    let process_supervisor =
        ProcessSupervisor::activate(&boot_mode, storage, diagnostics, workloads.clone())?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime")?;
    runtime.block_on(run_agent(
        &boot_mode,
        process_supervisor,
        agent_config,
        early_provisioning,
        workloads,
    ))
}

fn init_tracing() -> eyre::Result<crate::diagnostics::Diagnostics> {
    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info"),
    };

    let diagnostics = crate::diagnostics::Diagnostics::new(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(diagnostics.clone())
        .try_init()
        .map_err(|error| eyre::eyre!("install owned agent tracing sink: {error}"))?;
    Ok(diagnostics)
}

fn select_agent_mode(agent_args: &AgentArgs, is_pid1: bool) -> eyre::Result<AgentMode> {
    if agent_args.init {
        if !is_pid1 {
            eyre::bail!("--init requires silo-agent to run as PID 1");
        }
        let requested_init = agent_args
            .handoff
            .clone()
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

fn prepare_agent_process(
    agent_mode: &AgentMode,
    agent_config: &AgentConfig,
) -> eyre::Result<(
    BootMode,
    EarlyProvisioning,
    crate::root_storage::StorageShutdown,
    crate::freezer::WorkloadController,
)> {
    crate::provision::validate_early_mounts(&agent_config.provision)
        .context("validate complete guest mount plan before effects")?;
    crate::root_storage::retained_root().context("validate retained root context")?;
    let mut storage = crate::root_storage::StorageShutdown::capture()
        .context("retain writeback-error cursors before agent mutations")?;
    if let AgentMode::Init { requested_init } = agent_mode {
        tracing::info!(requested_init = ?requested_init, "agent init mode requested");
        prepare_pid1_environment()?;
    }
    let workloads = crate::freezer::WorkloadController::discover();

    storage
        .register_current(false)
        .context("retain essential mounts before writes")?;
    let early_provisioning = prepare_early_provisioning(&agent_config.provision, &mut storage)
        .context("prepare required early guest provisioning")?;
    crate::provision::ssh::prepare(&agent_config.ssh)
        .context("prepare mandatory SSH trust before init handoff")?;
    let boot_mode = match agent_mode {
        AgentMode::Standard => BootMode::Standard,
        AgentMode::Init { requested_init } => {
            handoff::maybe_handoff_init(requested_init, &workloads)?
        }
    };
    Ok((boot_mode, early_provisioning, storage, workloads))
}

async fn run_agent(
    boot_mode: &BootMode,
    process_supervisor: ProcessSupervisor,
    agent_config: AgentConfig,
    early_provisioning: EarlyProvisioning,
    workloads: crate::freezer::WorkloadController,
) -> eyre::Result<()> {
    let runtime = crate::lifecycle::RuntimeContext::new(agent_config.storage_shutdown.clone())?;
    let orderly = crate::orderly_shutdown::OrderlyShutdown::new(runtime.clone());
    let memory_reclaim = memory_reclaim::start();
    let mut result = crate::root_storage::ShutdownResult::default();
    let mut join_set = tokio::task::JoinSet::new();
    let mut shutdown_handles = Vec::new();
    let agent_server = match AgentServer::start(
        from_kernel_cmdline(),
        boot_mode.report(),
        process_supervisor.clone(),
        memory_reclaim.clone(),
        orderly.clone(),
        runtime.clone(),
        workloads,
    )
    .await
    {
        Ok(server) => Some(server),
        Err(error) => {
            result.record(Err(error));
            None
        }
    };
    if let Some(agent_server) = &agent_server {
        result.record(
            run_agent_services(
                boot_mode,
                &process_supervisor,
                &agent_config,
                &early_provisioning,
                agent_server,
                &mut join_set,
                &mut shutdown_handles,
            )
            .await,
        );
        for handle in shutdown_handles {
            handle.send_replace(true);
        }
        // Close mutation admission before awaiting listener/worker completion.
        agent_server.stop_admissions();
        result.record(process_supervisor.begin_writer_shutdown());
        result.record(agent_server.drain_mutations().await);
    }
    result.record(
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while let Some(task) = join_set.join_next().await {
                result_from_server(task)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| eyre::eyre!("guest vsock handlers did not drain before shutdown"))
        .and_then(|result| result),
    );
    join_set.abort_all();
    result.record(memory_reclaim.shutdown().await);
    result.record(process_supervisor.wait_internal_writers().await);
    let terminal = process_supervisor.shutdown(result.finish(), orderly).await;
    drop(agent_server);
    terminal
}

fn result_from_server(
    result: Result<eyre::Result<()>, tokio::task::JoinError>,
) -> eyre::Result<()> {
    result.context("guest vsock server task panicked")?
}

async fn run_agent_services(
    boot_mode: &BootMode,
    process_supervisor: &ProcessSupervisor,
    agent_config: &AgentConfig,
    early_provisioning: &EarlyProvisioning,
    agent_server: &AgentServer,
    join_set: &mut tokio::task::JoinSet<eyre::Result<()>>,
    shutdown_handles: &mut Vec<tokio::sync::watch::Sender<bool>>,
) -> eyre::Result<()> {
    tracing::info!(boot_mode = ?boot_mode, "agent starting");
    let boot_report = boot_mode.report();
    let provisioned = match run_provisioning(
        &agent_config.provision,
        process_supervisor,
        early_provisioning,
    ) {
        Ok(report) => report,
        Err(err) => {
            agent_server.fail(format!("provisioning failed: {err}"));
            return Err(err);
        }
    };
    let provision_report = provisioned.report;
    agent_server.set_network(provisioned.network).await;
    agent_server.update(boot_report.clone(), provision_report.clone());
    crate::provision::ssh::verify_trust(&agent_config.ssh).map_err(|error| {
        agent_server.fail(format!("SSH trust verification failed: {error}"));
        error
    })?;

    if provision_report.status == Some(ProvisionOverallStatus::FailedBoot as i32) {
        agent_server.fail("guest provisioning requested boot failure");
        eyre::bail!("guest provisioning requested boot failure");
    }

    let ssh_service = SshService::new(
        agent_config.ssh.clone(),
        process_supervisor.clone(),
        agent_server.runtime(),
    )
    .map_err(|error| {
        agent_server.fail(format!("SSH startup failed: {error}"));
        error
    })?;
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
            shutdown_handles.push(shell_server.shutdown_handle());
            join_set.spawn(async move {
                shell_server
                    .wait()
                    .await
                    .context("guest SSH listener failed")
            });
            true
        }
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            crate::ssh::constrain_external_listener(process_supervisor).map_err(|error| {
                agent_server.fail(format!("external SSH listener is not CA-only: {error}"));
                error
            })?;
            tracing::info!(
                port = SSH_VSOCK_PORT,
                "delegating SSH vsock connections to validated systemd OpenSSH listener"
            );
            false
        }
        Err(err) => {
            agent_server.fail(format!("SSH listener startup failed: {err}"));
            return Err(eyre::eyre!(
                "listen for SSH vsock connections on port {SSH_VSOCK_PORT}: {err}"
            ));
        }
    };

    if owns_ssh_listener {
        ssh_service.wait_ready().await.map_err(|error| {
            agent_server.fail(format!("SSH startup failed: {error}"));
            error
        })?;
    }

    let forwards = agent_server.forwards();
    let forward_server = VsockServer::create(move |stream| {
        let forwards = forwards.clone();
        async move { forwards.handle_dialer(stream).await }
    })
    .with_concurrency(1024)
    .with_tracing(tracing::info_span!(
        "vsock_server",
        service = "forward-dialer"
    ))
    .listen(forward_spec::FORWARD_VSOCK_PORT)
    .map_err(|error| {
        agent_server.fail(format!(
            "forward dialer startup failed on port {}: {error}",
            forward_spec::FORWARD_VSOCK_PORT
        ));
        eyre::eyre!(
            "listen for forward dialer vsock connections on port {}: {error}",
            forward_spec::FORWARD_VSOCK_PORT
        )
    })?;
    tracing::info!(
        port = forward_spec::FORWARD_VSOCK_PORT,
        "listening for forward dialer vsock connections"
    );
    shutdown_handles.push(forward_server.shutdown_handle());
    join_set.spawn(async move {
        forward_server
            .wait()
            .await
            .context("guest forward listener failed")
    });

    agent_server.ready(
        boot_report,
        provision_report,
        ssh_service.descriptor(!owns_ssh_listener)?,
    );

    if let Some(mut shutdown_rx) = process_supervisor.shutdown_receiver() {
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
                Ok(())
            }
        }
    } else {
        agent_task_result(join_set.join_next().await)
    }
}

fn load_agent_config(path: &Path) -> eyre::Result<AgentConfig> {
    let file =
        fs::File::open(path).with_context(|| format!("open agent config {}", path.display()))?;
    if !file
        .metadata()
        .with_context(|| format!("inspect agent config {}", path.display()))?
        .is_file()
    {
        eyre::bail!("agent config is not a regular file: {}", path.display());
    }

    let mut bytes = Vec::new();
    file.take((MAX_AGENT_CONFIG_SIZE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read agent config {}", path.display()))?;
    if bytes.len() > MAX_AGENT_CONFIG_SIZE_BYTES {
        eyre::bail!(
            "agent config exceeds {} byte limit: {}",
            MAX_AGENT_CONFIG_SIZE_BYTES,
            path.display()
        );
    }
    let config: AgentConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse agent config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("validate agent config {}", path.display()))?;
    Ok(config)
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
    use std::path::PathBuf;

    use crate::{parse_agent_args_from, select_agent_mode, AgentArgs, AgentMode};

    #[test]
    fn guest_config_requires_valid_injected_shutdown_context() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("config.json");
        std::fs::write(&config_path, br#"{"provision":{},"ssh":{}}"#).unwrap();
        assert!(crate::load_agent_config(&config_path).is_err());
        let mut config = agent_spec::AgentConfig {
            storage_shutdown: protocol::shutdown::StorageShutdownContext {
                version: 1,
                machine_id: uuid::Uuid::new_v4().to_string(),
                run_id: uuid::Uuid::new_v4().to_string(),
                manifest: protocol::shutdown::StorageManifest::Unsupported {
                    reason: "unrepresentable launch storage".into(),
                },
            },
            ..Default::default()
        };
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(
            crate::load_agent_config(&config_path)
                .unwrap()
                .storage_shutdown,
            config.storage_shutdown
        );
        config.storage_shutdown.run_id = uuid::Uuid::nil().to_string();
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(crate::load_agent_config(&config_path).is_err());
    }

    #[test]
    fn invalid_mount_plan_fails_before_handoff_or_provisioning_effects() {
        let mut config = agent_spec::AgentConfig::default();
        config.provision.mounts.push(agent_spec::MountConfig {
            tag: "hide-maintenance".to_string(),
            path: "/run".to_string(),
            fstype: "virtiofs".to_string(),
            options: Vec::new(),
        });
        let mode = AgentMode::Init {
            requested_init: OsStr::new("/sbin/init").to_os_string(),
        };
        let error = crate::prepare_agent_process(&mode, &config)
            .err()
            .expect("invalid mounts reject before PID1 setup");
        assert!(error.to_string().contains("complete guest mount plan"));
    }

    #[test]
    fn parses_handoff_equals_argument() {
        let args = parse_agent_args_from([
            "silo-agent",
            "--config=/run/agent/config.json",
            "--init",
            "--handoff=/sbin/init",
        ])
        .expect("parse agent args");

        assert!(args.init);
        assert_eq!(args.handoff.as_deref(), Some(OsStr::new("/sbin/init")));
    }

    #[test]
    fn parses_empty_handoff_equals_argument() {
        let args = parse_agent_args_from([
            "silo-agent",
            "--config=/run/agent/config.json",
            "--init",
            "--handoff=",
        ])
        .expect("parse agent args");

        assert!(args.init);
        assert_eq!(args.handoff.as_deref(), Some(OsStr::new("")));
    }

    #[test]
    fn rejects_split_handoff_argument() {
        assert!(parse_agent_args_from([
            "silo-agent",
            "--config=/run/agent/config.json",
            "--init",
            "--handoff",
            "auto"
        ])
        .is_err());
    }

    #[test]
    fn rejects_init_without_handoff() {
        assert!(
            parse_agent_args_from(["silo-agent", "--config=/run/agent/config.json", "--init"])
                .is_err()
        );
    }

    #[test]
    fn rejects_handoff_without_init() {
        assert!(parse_agent_args_from([
            "silo-agent",
            "--config=/run/agent/config.json",
            "--handoff=auto"
        ])
        .is_err());
    }

    #[test]
    fn rejects_duplicate_handoff() {
        assert!(parse_agent_args_from([
            "silo-agent",
            "--config=/run/agent/config.json",
            "--init",
            "--handoff=auto",
            "--handoff=/sbin/init",
        ])
        .is_err());
    }

    #[test]
    fn selects_standard_mode_for_non_pid1_without_args() {
        let args = AgentArgs {
            config: PathBuf::from("/run/agent/config.json"),
            init: false,
            handoff: None,
        };
        let mode = select_agent_mode(&args, false).expect("select mode");

        assert_eq!(mode, AgentMode::Standard);
    }

    #[test]
    fn rejects_pid1_without_init_arg() {
        let args = AgentArgs {
            config: PathBuf::from("/run/agent/config.json"),
            init: false,
            handoff: None,
        };
        let err = select_agent_mode(&args, true).expect_err("PID1 without --init must fail");

        assert!(err.to_string().contains("without --init"));
    }

    #[test]
    fn rejects_init_arg_outside_pid1() {
        let args = AgentArgs {
            config: PathBuf::from("/run/agent/config.json"),
            init: true,
            handoff: Some(OsStr::new("auto").to_os_string()),
        };
        let err = select_agent_mode(&args, false).expect_err("--init outside PID1 must fail");

        assert!(err.to_string().contains("PID 1"));
    }

    #[test]
    fn selects_init_mode_for_pid1_with_handoff() {
        let args = AgentArgs {
            config: PathBuf::from("/run/agent/config.json"),
            init: true,
            handoff: Some(OsStr::new("auto").to_os_string()),
        };
        let mode = select_agent_mode(&args, true).expect("select mode");

        assert_eq!(
            mode,
            AgentMode::Init {
                requested_init: OsStr::new("auto").to_os_string()
            }
        );
    }
}

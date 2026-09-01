use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;

mod context;
mod exec_log;
mod execution;
mod exit_command;
mod exit_status;
mod ext;
mod guest;
mod lock;
mod machine;
mod secure_file;
mod services;
mod shutdown;
mod start_request;
mod startup;
mod state;
mod vsock;
// Library-style module: parts of its surface are only used on one platform,
// behind the mock-backend feature, or from tests.
#[allow(dead_code)]
mod virt;

use crate::context::RuntimeContext;
use crate::exit_command::ExitCommand;
use crate::exit_status::{ExitOutcome, ExitStatus};
use crate::lock::pid::PidGuard;
use crate::start_request::StartRequestPipe;
use crate::startup::{InheritedPipeFds, SyncReporter};

#[derive(Parser, Debug, Clone)]
#[command(name = "vmmon", disable_help_subcommand = true)]
struct Args {
    #[arg(long, help = "identifier of the virtual machine")]
    id: String,

    #[arg(long, help = "human-readable name of the virtual machine")]
    name: String,

    #[arg(long = "data-dir")]
    data_dir: PathBuf,

    #[arg(long = "runtime-dir")]
    runtime_dir: PathBuf,

    #[arg(long = "pidfile")]
    pidfile: PathBuf,

    #[arg(long = "exit-status", hide = true)]
    exit_status: PathBuf,

    #[arg(long = "config")]
    config: PathBuf,

    #[arg(long = "agent-enabled")]
    agent_enabled: bool,

    #[arg(long = "socket")]
    socket: PathBuf,

    #[arg(long = "serial-log")]
    serial_log: PathBuf,

    #[arg(long = "trace-log")]
    trace_log: PathBuf,

    #[arg(long = "network")]
    network: Vec<String>,

    #[arg(long = "run-id", hide = true)]
    run_id: String,

    #[arg(long = "krun-path", hide = true)]
    krun_path: PathBuf,

    #[arg(long = "exit-command", hide = true)]
    exit_command: Option<PathBuf>,

    #[arg(long = "exit-command-arg", hide = true, allow_hyphen_values = true, value_parser = clap::builder::OsStringValueParser::new())]
    exit_command_args: Vec<OsString>,

    #[arg(long, hide = true)]
    foreground: bool,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let inherited_fds = InheritedPipeFds::from_env()?;

    let inherited_fds = if args.foreground {
        inherited_fds
    } else {
        inherited_fds.require_for_daemon()?
    };

    if !args.foreground {
        daemonize(&args, inherited_fds)?;
    }

    let start_request = StartRequestPipe::from_fd(inherited_fds.startpipe)
        .map_err(|err| eyre::eyre!("open start request pipe: {err}"))?;
    let sync_reporter = SyncReporter::from_fd(inherited_fds.syncpipe)
        .map_err(|err| eyre::eyre!("open syncpipe reporter: {err}"))?;
    let machine_log_dir = inherited_fds.machine_log_dir;
    let _machine_lock = inherited_fds.take_machine_lock()?;

    let trace_file = secure_file::open_append(&args.trace_log)?;

    let (writer, _guard) = tracing_appender::non_blocking(trace_file);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(writer)
        .try_init()
        .map_err(|err| eyre::eyre!("initialize vmmon tracing: {err}"))?;

    tracing::info!(
        event = "generation_start",
        machine_id = %args.id,
        run_id = %args.run_id,
        "vmmon generation started"
    );
    let mut serial_file = secure_file::open_append(&args.serial_log)?;
    write_serial_generation_boundary(&mut serial_file, &args.id, &args.run_id)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| eyre::eyre!("build tokio runtime: {err}"))?
        .block_on(run(
            args,
            start_request,
            sync_reporter,
            serial_file,
            machine_log_dir,
        ))
}

fn write_serial_generation_boundary(
    file: &mut std::fs::File,
    machine_id: &str,
    run_id: &str,
) -> eyre::Result<()> {
    writeln!(
        file,
        "--- silo vmmon generation start machine_id={machine_id} run_id={run_id} ---"
    )
    .map_err(eyre::Report::from)?;
    file.flush().map_err(eyre::Report::from)
}

async fn run(
    args: Args,
    start_request: StartRequestPipe,
    sync_reporter: SyncReporter,
    serial_file: std::fs::File,
    machine_log_dir: Option<std::os::fd::RawFd>,
) -> eyre::Result<()> {
    let mut start_request = start_request;
    let mut sync_reporter = sync_reporter;
    let exit_command =
        ExitCommand::from_cli(args.exit_command.clone(), args.exit_command_args.clone())?;
    let runtime = RuntimeContext::new(
        args.data_dir.clone(),
        args.runtime_dir.clone(),
        args.config.clone(),
        args.socket.clone(),
    );
    let pid_guard = PidGuard::create(&args.pidfile).await?;

    let (exec_log, _exec_log_guard) = match machine_log_dir {
        Some(fd) => match crate::exec_log::ExecLogDirectory::from_fd(fd)
            .and_then(crate::exec_log::ExecLogWriter::start)
        {
            Ok((writer, guard)) => (Some(writer), Some(guard)),
            Err(error) => {
                tracing::warn!(%error, "exec.log is unavailable; execution will continue without capture");
                (None, None)
            }
        },
        None => (None, None),
    };
    let startup_inputs = startup::InitInputs {
        machine_id: &args.id,
        machine_run_id: &args.run_id,
        name: &args.name,
        network_args: &args.network,
        agent_enabled: args.agent_enabled,
        krun_path: &args.krun_path,
        serial_file,
    };
    let result = match startup::init(&runtime, startup_inputs, &mut start_request).await {
        Ok(initialized) => match services::start_services(
            &runtime,
            &initialized.context,
            initialized.startup_command,
            exec_log.clone(),
            initialized.vsock_surface,
            &mut sync_reporter,
        )
        .await
        {
            Ok(handles) => shutdown::run(runtime, initialized.context, handles).await,
            Err(err) => {
                if let Err(stop_error) = initialized.context.machine.stop().await {
                    tracing::error!(%stop_error, "failed to stop VM after service startup failure");
                }
                Err(err)
            }
        },
        Err(err) => Err(err),
    };

    let last_error = result.as_ref().err().map(format_error_chain);
    if let Some(exec_log) = &exec_log {
        exec_log.generation(&args.id, &args.run_id, "stopped");
    }
    if let Some(full_error) = &last_error {
        tracing::error!(error = %full_error, data_dir = %args.data_dir.display(), "vmmon exiting with error");
        let _ = sync_reporter.report_failed(full_error);
    }

    let outcome = if last_error.is_some() {
        ExitOutcome::Error
    } else {
        ExitOutcome::Clean
    };
    match ExitStatus::new(
        args.id.clone(),
        args.run_id.clone(),
        outcome,
        last_error.clone(),
    ) {
        Ok(status) => {
            if let Err(err) = exit_status::write(&args.exit_status, &status) {
                tracing::warn!(error = %err, path = %args.exit_status.display(), "write runtime exit status");
            }
        }
        Err(err) => tracing::warn!(error = %err, "build runtime exit status"),
    }

    drop(pid_guard);
    if let Some(exit_command) = &exit_command {
        exit_command.spawn(&args.id, &args.run_id);
    }

    result
}

fn format_error_chain(err: &eyre::Report) -> String {
    let mut parts = Vec::new();
    for cause in err.chain() {
        parts.push(cause.to_string());
    }
    parts.join(": ")
}

#[cfg(target_os = "macos")]
fn daemonize(args: &Args, inherited_fds: InheritedPipeFds) -> eyre::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    if nix::unistd::getsid(None)? == nix::unistd::getpid() {
        return Ok(());
    }

    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("--id")
        .arg(&args.id)
        .arg("--name")
        .arg(&args.name)
        .arg("--data-dir")
        .arg(&args.data_dir)
        .arg("--runtime-dir")
        .arg(&args.runtime_dir)
        .arg("--pidfile")
        .arg(&args.pidfile)
        .arg("--exit-status")
        .arg(&args.exit_status)
        .arg("--config")
        .arg(&args.config);
    if args.agent_enabled {
        cmd.arg("--agent-enabled");
    }
    cmd.arg("--socket")
        .arg(&args.socket)
        .arg("--serial-log")
        .arg(&args.serial_log)
        .arg("--trace-log")
        .arg(&args.trace_log);
    for network in &args.network {
        cmd.arg("--network").arg(network);
    }
    cmd.arg("--run-id")
        .arg(&args.run_id)
        .arg("--krun-path")
        .arg(&args.krun_path);
    if let Some(exit_command) = &args.exit_command {
        cmd.arg("--exit-command").arg(exit_command);
    }
    for arg in &args.exit_command_args {
        cmd.arg("--exit-command-arg").arg(arg);
    }
    inherited_fds.clear_cloexec()?;
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()
                .map(|_| ())
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        });
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn()?;
    std::process::exit(0);
}

#[cfg(not(target_os = "macos"))]
fn daemonize(_args: &Args, _inherited_fds: InheritedPipeFds) -> eyre::Result<()> {
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { .. }) => std::process::exit(0),
        Ok(nix::unistd::ForkResult::Child) => {}
        Err(err) => return Err(eyre::eyre!("fork: {err}")),
    }
    nix::unistd::setsid().map_err(|err| eyre::eyre!("setsid: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;

    use clap::Parser;

    use crate::{write_serial_generation_boundary, Args};

    #[test]
    fn serial_generation_boundary_is_stable_and_identifiable() {
        let path =
            std::env::temp_dir().join(format!("silo-vmmon-boundary-{}", uuid::Uuid::new_v4()));
        let mut file = fs::File::create(&path).expect("create serial log");

        write_serial_generation_boundary(&mut file, "machine-1", "run-1")
            .expect("write serial generation boundary");
        drop(file);

        let mut contents = String::new();
        fs::File::open(&path)
            .expect("open serial log")
            .read_to_string(&mut contents)
            .expect("read serial log");
        assert_eq!(
            contents,
            "--- silo vmmon generation start machine_id=machine-1 run_id=run-1 ---\n"
        );
        fs::remove_file(path).expect("remove serial log");
    }

    #[test]
    fn parses_hidden_exit_command_as_opaque_argv() {
        let args = Args::try_parse_from([
            "vmmon",
            "--id",
            "03147ec30bd748f4ad8574539c2e75ea",
            "--name",
            "ubuntu",
            "--data-dir",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea",
            "--runtime-dir",
            "/tmp/silo-run/machines/03147ec30bd748f4ad8574539c2e75ea",
            "--pidfile",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/vm.pid",
            "--exit-status",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/vm.exit.json",
            "--config",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/config.json",
            "--socket",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/vm.sock",
            "--serial-log",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/serial.log",
            "--trace-log",
            "/tmp/silo/machines/03147ec30bd748f4ad8574539c2e75ea/vm.trace.log",
            "--network",
            "none",
            "--run-id",
            "run-1",
            "--krun-path",
            "/tmp/silo-runtime/bin/krun",
            "--exit-command",
            "silo",
            "--exit-command-arg",
            "cleanup",
            "--exit-command-arg",
            "--data-dir",
            "--exit-command-arg",
            "/tmp/silo",
            "--exit-command-arg",
            "--machine-id",
            "--exit-command-arg",
            "03147ec30bd748f4ad8574539c2e75ea",
            "--foreground",
        ])
        .expect("vmmon args");

        assert_eq!(args.exit_command, Some(PathBuf::from("silo")));
        assert_eq!(args.krun_path, PathBuf::from("/tmp/silo-runtime/bin/krun"));
        assert_eq!(
            args.exit_command_args,
            vec![
                "cleanup",
                "--data-dir",
                "/tmp/silo",
                "--machine-id",
                "03147ec30bd748f4ad8574539c2e75ea"
            ]
        );
    }
}

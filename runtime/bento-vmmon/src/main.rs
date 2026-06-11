use std::fs::OpenOptions;
use std::path::PathBuf;

use clap::Parser;

mod context;
mod endpoints;
mod ext;
mod guest;
mod lock;
mod machine;
mod net;
mod services;
mod shutdown;
mod startup;
mod state;

use crate::context::RuntimeContext;
use crate::lock::pid::PidGuard;
use crate::startup::{InheritedPipeFds, StartGate, SyncReporter};

#[derive(Parser, Debug, Clone)]
#[command(name = "vmmon", disable_help_subcommand = true)]
struct Args {
    #[arg(long, help = "identifier of the virtual machine")]
    id: String,

    #[arg(long, help = "human-readable name of the virtual machine")]
    name: String,

    #[arg(long = "data-dir")]
    data_dir: PathBuf,

    #[arg(long = "pidfile")]
    pidfile: PathBuf,

    #[arg(long = "config")]
    config: PathBuf,

    #[arg(long = "metadata-config")]
    metadata_config: Option<PathBuf>,

    #[arg(long = "wait-for-registration", default_value_t = 0)]
    wait_for_registration: u64,

    #[arg(long = "socket")]
    socket: PathBuf,

    #[arg(long = "serial-log")]
    serial_log: PathBuf,

    #[arg(long = "trace-log")]
    trace_log: PathBuf,

    #[arg(long = "network")]
    network: Vec<String>,

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

    let start_gate = StartGate::from_fd(inherited_fds.startpipe)
        .map_err(|err| eyre::eyre!("open startpipe gate: {err}"))?;
    let sync_reporter = SyncReporter::from_fd(inherited_fds.syncpipe)
        .map_err(|err| eyre::eyre!("open syncpipe reporter: {err}"))?;

    let trace_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.trace_log)
        .map_err(|err| eyre::eyre!("open {}: {err}", args.trace_log.display()))?;

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

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| eyre::eyre!("build tokio runtime: {err}"))?
        .block_on(run(args, start_gate, sync_reporter))
}

async fn run(args: Args, start_gate: StartGate, sync_reporter: SyncReporter) -> eyre::Result<()> {
    let mut start_gate = start_gate;
    let mut sync_reporter = sync_reporter;
    let runtime = RuntimeContext::new(
        args.data_dir.clone(),
        args.config.clone(),
        args.socket.clone(),
        args.serial_log.clone(),
    );
    let _guard = PidGuard::create(&args.pidfile).await?;

    let result = match startup::init(
        &runtime,
        &args.id,
        &args.name,
        &args.network,
        args.metadata_config.as_deref(),
        std::time::Duration::from_secs(args.wait_for_registration),
        &mut start_gate,
    )
    .await
    {
        Ok(ctx) => match services::start_services(&runtime, &ctx, &mut sync_reporter).await {
            Ok(handles) => shutdown::run(runtime, ctx, handles).await,
            Err(err) => Err(err),
        },
        Err(err) => Err(err),
    };

    if let Err(err) = &result {
        let full_error = format_error_chain(err);
        tracing::error!(error = %full_error, data_dir = %args.data_dir.display(), "vmmon exiting with error");
        let _ = sync_reporter.report_failed(&full_error);
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
        .arg("--pidfile")
        .arg(&args.pidfile)
        .arg("--config")
        .arg(&args.config);
    if let Some(metadata_config) = &args.metadata_config {
        cmd.arg("--metadata-config").arg(metadata_config);
    }
    cmd.arg("--wait-for-registration")
        .arg(args.wait_for_registration.to_string())
        .arg("--socket")
        .arg(&args.socket)
        .arg("--serial-log")
        .arg(&args.serial_log)
        .arg("--trace-log")
        .arg(&args.trace_log);
    for network in &args.network {
        cmd.arg("--network").arg(network);
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

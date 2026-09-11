use clap::{Args, Subcommand};

use crate::context::Context;

#[derive(Debug, Args)]
pub struct Cmd {
    #[command(subcommand)]
    command: DaemonCommand,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Enable and start the per-user system VM.
    Up(Up),
    /// Disable the per-user service and stop the system VM.
    Down,
    /// Report live daemon state without starting the VM.
    Status(Status),
    /// Read bounded daemon supervisor logs.
    Logs(Logs),
    /// Replace the system image while retaining installation-owned engine data.
    Upgrade(Upgrade),
    #[command(hide = true)]
    Serve(Serve),
}

#[derive(Debug, Args)]
struct Up {
    #[arg(long)]
    foreground: bool,
    #[arg(long)]
    no_switch_context: bool,
}

#[derive(Debug, Args)]
struct Status {
    #[arg(long, value_enum, default_value_t = crate::ui::OutputFormat::Plain)]
    format: crate::ui::OutputFormat,
}

#[derive(Debug, Args)]
struct Logs {
    #[arg(long)]
    follow: bool,
    #[arg(long, default_value_t = 200)]
    lines: usize,
}

#[derive(Debug, Args)]
struct Upgrade {
    #[arg(long, required_unless_present = "recover", conflicts_with = "recover")]
    image: Option<String>,
    #[arg(long, conflicts_with = "image")]
    recover: bool,
}

#[derive(Debug, Args)]
struct Serve {
    #[arg(long)]
    config: std::path::PathBuf,
}

impl Cmd {
    pub(crate) async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            DaemonCommand::Up(command) => {
                if command.foreground {
                    return run_foreground(context).await;
                }
                let (paths, config) = context.resolved_system_config(None)?;
                let daemon_live = crate::system::service::status(&paths)?.is_some();
                crate::system::docker::preflight(&config, daemon_live)?;
                crate::system::service::up(&paths, config.clone())?;
                crate::system::docker::integrate(&config, !command.no_switch_context)
            }
            DaemonCommand::Down => {
                let paths = crate::system::ownership::default_system_paths()?;
                let Some(registration) =
                    crate::system::service::load_optional_registration(&paths.registration())?
                else {
                    return Ok(());
                };
                crate::system::service::down(&registration, &paths)?;
                // A daemon that was running has stopped its VM on SIGTERM by now. Cover the
                // case where none was running but an earlier interrupted start left the VM up.
                if let Some(installation) = crate::system::record::load_record::<
                    crate::system::record::InstallationRecord,
                >(&paths.installation())?
                {
                    let api = context.app_api().await?;
                    crate::system::provision::stop_system_machine(
                        api,
                        &paths,
                        installation.installation_id,
                        std::time::Duration::from_secs(60),
                    )
                    .await?;
                }
                Ok(())
            }
            DaemonCommand::Serve(command) => run_registered(command.config).await,
            DaemonCommand::Status(command) => {
                let paths = crate::system::ownership::default_system_paths()?;
                let view = DaemonStatusView::collect(&paths)?;
                match command.format {
                    crate::ui::OutputFormat::Json => crate::ui::print_json(&view),
                    crate::ui::OutputFormat::Plain => view.print_human(),
                }
            }
            DaemonCommand::Logs(command) => {
                let paths = crate::system::ownership::default_system_paths()?;
                let logs = crate::system::service::logs(&paths, command.lines)?;
                if !logs.is_empty() {
                    println!("{logs}");
                }
                if command.follow {
                    follow_logs(&paths.log()).await?;
                }
                Ok(())
            }
            DaemonCommand::Upgrade(command) => {
                let paths = crate::system::ownership::default_system_paths()?;
                if command.recover {
                    return crate::system::upgrade::recover(context.app_api().await?, &paths).await;
                }
                let image = command
                    .image
                    .ok_or_else(|| eyre::eyre!("--image is required"))?;
                let (_, config) = context.resolved_system_config(None)?;
                crate::system::upgrade::upgrade(context.app_api().await?, &paths, config, &image)
                    .await
            }
        }
    }
}

/// Operator-facing daemon status: the live supervisor record plus what the service
/// manager and registration say when no daemon is running.
#[derive(Debug, serde::Serialize)]
struct DaemonStatusView {
    /// Summary state: `stopped`, `starting`, `ready`, `degraded`, `failed`, `stopping`.
    state: &'static str,
    /// Whether the native user service starts the daemon at login.
    autostart: Option<bool>,
    /// Docker endpoint the daemon serves (or is registered to serve).
    endpoint: Option<String>,
    /// Configured guest memory, in bytes, from the registration.
    memory_bytes: Option<u64>,
    /// Live supervisor record; absent when no daemon process is running.
    daemon: Option<crate::system::supervisor::DaemonStatus>,
}

impl DaemonStatusView {
    fn collect(paths: &crate::system::record::SystemPaths) -> eyre::Result<Self> {
        use crate::system::supervisor::DaemonPhase;

        let daemon = crate::system::service::status(paths)?;
        let autostart = crate::system::service::is_enabled().ok();
        let registration =
            crate::system::service::load_optional_registration(&paths.registration())?;
        let endpoint = match &daemon {
            Some(status) => Some(status.docker_socket.clone()),
            None => registration
                .as_ref()
                .map(|registration| registration.config.docker_socket.display().to_string()),
        };
        let memory_bytes = registration
            .as_ref()
            .map(|registration| registration.config.memory_bytes);
        let state = match daemon.as_ref().map(|status| status.phase) {
            None | Some(DaemonPhase::Stopped) => "stopped",
            Some(DaemonPhase::Ready) => "ready",
            Some(DaemonPhase::Degraded) => "degraded",
            Some(DaemonPhase::Failed) => "failed",
            Some(DaemonPhase::Stopping) => "stopping",
            Some(
                DaemonPhase::PreparingStorage
                | DaemonPhase::Creating
                | DaemonPhase::StartingVm
                | DaemonPhase::WaitingGuest
                | DaemonPhase::ActivatingEngine,
            ) => "starting",
        };
        Ok(Self {
            state,
            autostart,
            endpoint,
            memory_bytes,
            daemon,
        })
    }

    fn print_human(&self) -> eyre::Result<()> {
        use crate::system::supervisor::DaemonPhase;

        let mut rows: Vec<(String, String)> = Vec::new();
        let state = match &self.daemon {
            Some(status) => match status.phase {
                DaemonPhase::PreparingStorage => "starting (preparing storage)".to_string(),
                DaemonPhase::Creating => "starting (creating system machine)".to_string(),
                DaemonPhase::StartingVm => "starting (booting VM)".to_string(),
                DaemonPhase::WaitingGuest => "starting (waiting for guest)".to_string(),
                DaemonPhase::ActivatingEngine => "starting (activating Docker)".to_string(),
                DaemonPhase::Ready => "ready".to_string(),
                DaemonPhase::Degraded => "degraded (Docker health probe failing)".to_string(),
                DaemonPhase::Failed => match status.restart_count {
                    0 | 1 => "failed (retrying)".to_string(),
                    attempts => format!("failed (retrying; {attempts} attempts so far)"),
                },
                DaemonPhase::Stopping => "stopping".to_string(),
                DaemonPhase::Stopped => "stopped".to_string(),
            },
            None => "stopped".to_string(),
        };
        rows.push(("State".to_string(), state));
        rows.push((
            "Autostart".to_string(),
            match self.autostart {
                Some(true) => "enabled".to_string(),
                Some(false) => "disabled".to_string(),
                None => "unknown".to_string(),
            },
        ));
        if let Some(endpoint) = &self.endpoint {
            rows.push(("Endpoint".to_string(), format!("unix://{endpoint}")));
        }
        if let Some(status) = &self.daemon {
            rows.push(("PID".to_string(), status.pid.to_string()));
            if let Some(machine_id) = &status.machine_id {
                rows.push(("Machine".to_string(), machine_id.clone()));
            }
            if let Some(digest) = &status.image_digest {
                rows.push(("Image".to_string(), digest.clone()));
            }
            if let (Some(memory), Some(target)) = (self.memory_bytes, status.memory_target_bytes) {
                rows.push((
                    "Memory".to_string(),
                    format!(
                        "{} configured, {} currently given to the guest",
                        crate::ui::human_bytes(Some(memory)),
                        crate::ui::human_bytes(Some(target))
                    ),
                ));
            }
            if let Ok(updated) = chrono::DateTime::parse_from_rfc3339(&status.updated_at) {
                let timestamp = updated.timestamp();
                let relative = crate::ui::relative_time(timestamp, crate::ui::now_unix());
                let mut relative = relative.chars();
                let relative = relative
                    .next()
                    .map(|first| first.to_lowercase().chain(relative).collect::<String>())
                    .unwrap_or_default();
                rows.push((
                    "Updated".to_string(),
                    format!("{} ({relative})", crate::ui::format_unix(timestamp)),
                ));
            }
            if let Some(error) = &status.last_error {
                rows.push(("Error".to_string(), error.clone()));
            }
        }
        crate::ui::print_detail_rows(&rows)
    }
}

async fn run_registered(path: std::path::PathBuf) -> eyre::Result<()> {
    let registration = crate::system::service::load_registration(&path)?;
    if std::env::current_exe()?.canonicalize()? != registration.executable {
        return Err(eyre::eyre!(
            "registration executable identity does not match this process"
        ));
    }
    let run_root = crate::system::ownership::default_system_paths()?.run_root;
    let paths = registration.paths(run_root);
    let installation = crate::system::record::load_record::<
        crate::system::record::InstallationRecord,
    >(&paths.installation())?
    .ok_or_else(|| eyre::eyre!("registered installation record is missing"))?;
    if installation.installation_id != registration.installation_id {
        return Err(eyre::eyre!("registration installation identity mismatch"));
    }
    let networking = registration.global_config()?.networking;
    let runtime = libvm::RuntimeConfig::local(&registration.data_root)
        .with_state_root(&registration.state_root)
        .with_run_root(&paths.run_root)
        .with_image_root(&registration.image_root)
        .with_networking(networking);
    let mut api = crate::api::AppApi::local(runtime);
    crate::system::supervisor::serve(&mut api, paths, registration.config).await
}

async fn follow_logs(path: &std::path::Path) -> eyre::Result<()> {
    use std::io::{Read as _, Seek as _};

    let mut offset = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => return result.map_err(Into::into),
            () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                let Ok(mut file) = std::fs::File::open(path) else { continue };
                let length = file.metadata()?.len();
                if length < offset { offset = 0; }
                file.seek(std::io::SeekFrom::Start(offset))?;
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                offset = length;
                print!("{content}");
                use std::io::Write as _;
                std::io::stdout().flush()?;
            }
        }
    }
}

async fn run_foreground(context: &mut Context) -> eyre::Result<()> {
    let (paths, config) = context.resolved_system_config(None)?;
    crate::system::docker::preflight(&config, false)?;
    let api = context.app_api().await?;
    crate::system::supervisor::serve(api, paths, config).await
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    #[test]
    fn parses_foreground_and_hidden_serve() {
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "up", "--foreground"]).is_ok());
        assert!(crate::app::Cli::try_parse_from([
            "silo",
            "daemon",
            "serve",
            "--config",
            "/tmp/registration.json"
        ])
        .is_ok());
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "down"]).is_ok());
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "logs", "--follow"]).is_ok());
        assert!(crate::app::Cli::try_parse_from([
            "silo",
            "daemon",
            "upgrade",
            "--image",
            "registry.example/system@sha256:test"
        ])
        .is_ok());
        assert!(
            crate::app::Cli::try_parse_from(["silo", "daemon", "upgrade", "--recover"]).is_ok()
        );
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "upgrade"]).is_err());
    }
}

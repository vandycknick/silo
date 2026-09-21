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
    /// Override the configured or built-in default system image.
    #[arg(long, conflicts_with = "recover")]
    image: Option<String>,
    #[arg(long, conflicts_with = "image")]
    recover: bool,
}

#[derive(Debug, Args)]
struct Serve {
    #[arg(long)]
    state: std::path::PathBuf,
}

impl Cmd {
    pub(crate) async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            DaemonCommand::Up(command) => {
                if command.foreground {
                    return run_foreground(context).await;
                }
                let (paths, config) = context.resolved_system_config()?;
                let daemon_live = crate::system::service::status(&paths)?.is_some();
                crate::system::docker::preflight(&config, daemon_live)?;
                crate::system::service::up(&paths, config.clone())?;
                crate::system::docker::integrate(&config, !command.no_switch_context)
            }
            DaemonCommand::Down => {
                let paths = crate::system::ownership::default_system_paths()?;
                crate::system::service::down(&paths).await
            }
            DaemonCommand::Serve(command) => run_service(command.state).await,
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
                    return crate::system::upgrade::recover(&paths).await;
                }
                let (_, config) = context.resolved_system_config()?;
                let image = command.image.unwrap_or_else(|| config.image.clone());
                crate::system::upgrade::upgrade(&paths, config, &image).await
            }
        }
    }
}

/// Operator-facing daemon status: the live supervisor record plus what the service
/// manager and state say when no daemon is running.
#[derive(Debug, serde::Serialize)]
struct DaemonStatusView {
    /// Summary state: `stopped`, `starting`, `ready`, `degraded`, `failed`, `stopping`.
    state: &'static str,
    /// Whether the native user service starts the daemon at login.
    autostart: Option<bool>,
    /// Docker endpoint the daemon serves (or is registered to serve).
    endpoint: Option<String>,
    /// Configured guest memory, in bytes, from the state.
    memory_bytes: Option<u64>,
    /// Live supervisor record; absent when no daemon process is running.
    daemon: Option<crate::system::supervisor::DaemonStatus>,
}

impl DaemonStatusView {
    fn collect(paths: &crate::system::record::SystemPaths) -> eyre::Result<Self> {
        use crate::system::supervisor::DaemonPhase;

        let daemon = crate::system::service::status(paths)?;
        let autostart = crate::system::service::is_enabled().ok();
        let state = crate::system::record::DaemonRecord::load(paths)?;
        let endpoint = match &daemon {
            Some(status) => Some(status.docker_socket.clone()),
            None => state
                .as_ref()
                .map(|state| state.config.docker_socket.display().to_string()),
        };
        let memory_bytes = state.as_ref().map(|state| state.config.memory_bytes);
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
            rows.push((
                "Backend".to_string(),
                format_actual_backend(status.actual_backend.as_deref()).to_string(),
            ));
            if let Some(memory) = self.memory_bytes {
                let reclaim = status
                    .memory_reclaim_outcome
                    .zip(status.memory_reclaim_at.as_deref())
                    .and_then(|(outcome, at)| {
                        let at = chrono::DateTime::parse_from_rfc3339(at).ok()?.timestamp();
                        Some(format_guest_reclaim(
                            status.memory_reclaim_mode.as_deref(),
                            outcome,
                            status.memory_reclaim_observed_cache_delta_bytes,
                            crate::ui::relative_time(at, crate::ui::now_unix()).to_lowercase(),
                        ))
                    })
                    .unwrap_or_default();
                rows.push((
                    "Memory".to_string(),
                    format!("{}{reclaim}", crate::ui::human_bytes(Some(memory))),
                ));
                rows.push((
                    "Host memory reclaim".to_string(),
                    format_host_memory_reclaim(
                        status.host_memory_reclaim_requested,
                        status.host_memory_reclaim_effective,
                        status.host_memory_reclaim_qualification.as_deref(),
                        status.host_memory_reclaim_released_bytes,
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

fn format_actual_backend(backend: Option<&str>) -> &str {
    backend.unwrap_or("unknown")
}

/// One clause describing the agent's last guest cache reclaim, for the Memory row.
fn format_guest_reclaim(
    mode: Option<&str>,
    outcome: crate::system::supervisor::MemoryReclaimOutcome,
    reclaimed_bytes: Option<u64>,
    when: String,
) -> String {
    use crate::system::supervisor::MemoryReclaimOutcome;

    let mode = match mode {
        Some("dropcache") => "cache drop",
        Some(_) | None => "gradual",
    };
    let outcome = match outcome {
        MemoryReclaimOutcome::Reclaimed => "reclaimed",
        MemoryReclaimOutcome::Partial => "reclaimed partially",
        MemoryReclaimOutcome::Nothing => "found nothing reclaimable",
        MemoryReclaimOutcome::Failed => "failed",
    };
    let reclaimed = reclaimed_bytes
        .filter(|_| outcome != "failed")
        .map(|bytes| {
            format!(
                ", guest cache fell by {}",
                crate::ui::human_bytes(Some(bytes))
            )
        })
        .unwrap_or_default();
    format!("; last idle {mode} reclaim in the guest {outcome} {when}{reclaimed}")
}

fn format_host_memory_reclaim(
    requested: bool,
    effective: Option<bool>,
    qualification: Option<&str>,
    released_bytes: Option<u64>,
) -> String {
    let requested = if requested { "auto" } else { "off" };
    let effective_text = match effective {
        Some(true) => "on",
        Some(false) => "off",
        None => "unknown (not yet reported by the VM backend)",
    };
    let mut text = format!("requested {requested}; effective {effective_text}");
    if let Some(qualification) = qualification {
        text.push_str(&format!(" (probe {qualification})"));
    }
    if let (Some(_), Some(bytes)) = (effective, released_bytes) {
        text.push_str(&format!(
            "; {} advised free since VM start",
            crate::ui::human_bytes(Some(bytes))
        ));
    }
    text
}

async fn run_service(path: std::path::PathBuf) -> eyre::Result<()> {
    let state = crate::system::record::DaemonRecord::load_from(&path)?
        .ok_or_else(|| eyre::eyre!("daemon state is missing: {}", path.display()))?;
    if std::env::current_exe()?.canonicalize()? != state.service.executable {
        return Err(eyre::eyre!(
            "state executable identity does not match this process"
        ));
    }
    let run_root = crate::system::ownership::default_system_paths()?.run_root;
    let paths = state.service.paths(run_root);
    let networking = state.service.global_config()?.networking;
    let runtime = state
        .service
        .runtime_config(&paths.run_root, &state.config, networking);
    let mut api = crate::api::AppApi::local(runtime);
    crate::system::supervisor::serve(&mut api, paths, state.config).await
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
    let (paths, config) = context.resolved_system_config()?;
    crate::system::docker::preflight(&config, false)?;
    let api = context
        .app_api_with_backend(config.backend.runtime_override())
        .await?;
    crate::system::supervisor::serve(api, paths, config).await
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::commands::daemon::{format_actual_backend, format_host_memory_reclaim};

    #[test]
    fn parses_foreground_and_hidden_serve() {
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "up", "--foreground"]).is_ok());
        assert!(crate::app::Cli::try_parse_from([
            "silo",
            "daemon",
            "serve",
            "--state",
            "/tmp/daemon.json"
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
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "upgrade"]).is_ok());
        assert!(crate::app::Cli::try_parse_from([
            "silo",
            "daemon",
            "upgrade",
            "--recover",
            "--image",
            "registry.example/system@sha256:test"
        ])
        .is_err());
        assert!(
            crate::app::Cli::try_parse_from(["silo", "daemon", "balloon", "--target", "1GiB"])
                .is_err()
        );
    }

    #[test]
    fn host_memory_reclaim_status_keeps_requested_and_effective_axes_separate() {
        for (requested, effective, expected) in [
            (false, Some(false), "requested off; effective off"),
            (false, Some(true), "requested off; effective on"),
            (
                false,
                None,
                "requested off; effective unknown (not yet reported by the VM backend)",
            ),
            (true, Some(false), "requested auto; effective off"),
            (true, Some(true), "requested auto; effective on"),
            (
                true,
                None,
                "requested auto; effective unknown (not yet reported by the VM backend)",
            ),
        ] {
            assert_eq!(
                format_host_memory_reclaim(requested, effective, None, None),
                expected
            );
        }
    }

    #[test]
    fn host_memory_reclaim_status_appends_probe_and_advised_bytes_once_reported() {
        assert_eq!(
            format_host_memory_reclaim(true, Some(true), Some("passed"), Some(6 * 1024 * 1024)),
            "requested auto; effective on (probe passed); 6MiB advised free since VM start"
        );
        assert_eq!(
            format_host_memory_reclaim(true, Some(false), Some("failed"), Some(0)),
            "requested auto; effective off (probe failed); 0B advised free since VM start"
        );
        // Counters are only meaningful alongside a reported effective state.
        assert_eq!(
            format_host_memory_reclaim(true, None, None, Some(10)),
            "requested auto; effective unknown (not yet reported by the VM backend)"
        );
    }

    #[test]
    fn guest_reclaim_clause_names_mode_outcome_and_measured_delta() {
        use crate::system::supervisor::MemoryReclaimOutcome;

        assert_eq!(
            crate::commands::daemon::format_guest_reclaim(
                Some("gradual"),
                MemoryReclaimOutcome::Partial,
                Some(512 * 1024 * 1024),
                "2 minutes ago".to_string(),
            ),
            "; last idle gradual reclaim in the guest reclaimed partially 2 minutes ago, guest cache fell by 512MiB"
        );
        assert_eq!(
            crate::commands::daemon::format_guest_reclaim(
                Some("dropcache"),
                MemoryReclaimOutcome::Failed,
                Some(7),
                "just now".to_string(),
            ),
            "; last idle cache drop reclaim in the guest failed just now"
        );
        assert_eq!(
            crate::commands::daemon::format_guest_reclaim(
                None,
                MemoryReclaimOutcome::Nothing,
                Some(0),
                "just now".to_string(),
            ),
            "; last idle gradual reclaim in the guest found nothing reclaimable just now, guest cache fell by 0B"
        );
    }

    #[test]
    fn missing_actual_backend_is_reported_as_unknown() {
        assert_eq!(format_actual_backend(None), "unknown");
        assert_eq!(format_actual_backend(Some("krun")), "krun");
    }
}

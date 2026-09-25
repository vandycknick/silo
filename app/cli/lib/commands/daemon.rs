use clap::{Args, Subcommand};

use silod_spec::paths::DaemonPaths;
use silod_spec::status::{DaemonPhase, DaemonStatus, MemoryReclaimOutcome};

use crate::context::Context;
use crate::daemon::service;
use crate::ui::Spinner;

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

impl Cmd {
    pub(crate) async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let paths = DaemonPaths::from_env()?;
        match self.command {
            DaemonCommand::Up(command) => {
                let mut spinner = Spinner::start("Checking", "daemon configuration");
                let arguments = context.config()?.daemon_overrides()?.to_args();
                let executable = crate::daemon::executable()?;
                let socket = paths.docker_socket();
                let live = service::status(&paths)?.is_some();
                crate::daemon::docker::preflight(&socket, live)?;
                crate::daemon::check(&executable, &arguments)?;
                if command.foreground {
                    spinner.finish_clear();
                    return crate::daemon::foreground(&executable, &arguments);
                }
                let service = service::ServiceConfig::new(&paths, executable)?;
                service::up(&service, &arguments, &mut spinner)?;
                spinner.finish_success("Started");
                crate::daemon::docker::integrate(&socket, !command.no_switch_context)?;
                crate::ui::hint(format!("Docker endpoint: unix://{}", socket.display()));
                Ok(())
            }
            DaemonCommand::Down => service::down(&paths, &crate::daemon::executable()?),
            DaemonCommand::Status(command) => {
                let view = DaemonStatusView::collect(&paths)?;
                match command.format {
                    crate::ui::OutputFormat::Json => crate::ui::print_json(&view),
                    crate::ui::OutputFormat::Plain => view.print_human(),
                }
            }
            DaemonCommand::Logs(command) => {
                let logs = service::logs(&paths, command.lines)?;
                if !logs.is_empty() {
                    println!("{logs}");
                }
                if command.follow {
                    follow_logs(&paths.log()).await?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct DaemonStatusView {
    /// Summary state: `stopped`, `starting`, `ready`, `degraded`, `failed`, `stopping`.
    state: &'static str,
    /// Whether the native user service starts the daemon at login.
    autostart: Option<bool>,
    /// Docker endpoint the daemon serves (or is registered to serve).
    endpoint: Option<String>,
    /// Configured guest memory ceiling, in bytes, as the running daemon reports it.
    memory_bytes: Option<u64>,
    /// Live supervisor record; absent when no daemon process is running.
    daemon: Option<DaemonStatus>,
}

impl DaemonStatusView {
    fn collect(paths: &DaemonPaths) -> eyre::Result<Self> {
        let daemon = service::status(paths)?;
        let autostart = service::is_enabled().ok();
        let endpoint = Some(match &daemon {
            Some(status) => status.docker_socket.clone(),
            None => paths.docker_socket().display().to_string(),
        });
        let memory_bytes = daemon.as_ref().and_then(|status| status.memory_bytes);
        let state = match daemon.as_ref().map(|status| status.phase) {
            None | Some(DaemonPhase::Stopped) => "stopped",
            Some(DaemonPhase::Ready) => "ready",
            Some(DaemonPhase::Degraded) => "degraded",
            Some(DaemonPhase::Failed) => "failed",
            Some(DaemonPhase::Stopping) => "stopping",
            Some(DaemonPhase::Upgrading) => "upgrading",
            Some(
                DaemonPhase::PreparingStorage
                | DaemonPhase::Creating
                | DaemonPhase::StartingVm
                | DaemonPhase::WaitingGuest
                | DaemonPhase::ActivatingEngine
                | DaemonPhase::Retrying,
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
                DaemonPhase::Upgrading => "upgrading (replacing the system VM)".to_string(),
                DaemonPhase::Retrying => format!(
                    "starting (retrying; {} attempts so far)",
                    status.restart_count
                ),
                DaemonPhase::Failed => "failed".to_string(),
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
            if let Some(image) = &status.configured_image {
                rows.push(("Image".to_string(), image.clone()));
            }
            if let Some(digest) = &status.image_digest {
                rows.push(("Digest".to_string(), digest.clone()));
            }
            rows.push(("Updates".to_string(), format_update_check(status)));
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

/// When silod last asked the registry about the system image, and what went wrong.
fn format_update_check(status: &DaemonStatus) -> String {
    let checked = status
        .update_checked_at
        .as_deref()
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| {
            format!(
                "checked {}",
                crate::ui::relative_time(at.timestamp(), crate::ui::now_unix()).to_lowercase()
            )
        })
        .unwrap_or_else(|| "not checked yet".to_string());
    match &status.update_error {
        Some(error) => format!("{checked}; {error}"),
        None => checked,
    }
}

fn format_actual_backend(backend: Option<&str>) -> &str {
    backend.unwrap_or("unknown")
}

/// One clause describing the agent's last guest cache reclaim, for the Memory row.
fn format_guest_reclaim(
    mode: Option<&str>,
    outcome: MemoryReclaimOutcome,
    reclaimed_bytes: Option<u64>,
    when: String,
) -> String {
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::commands::daemon::{
        format_actual_backend, format_host_memory_reclaim, format_update_check,
    };

    #[test]
    fn parses_controller_commands_only() {
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "up", "--foreground"]).is_ok());
        assert!(crate::app::Cli::try_parse_from([
            "silo",
            "daemon",
            "serve",
            "--state",
            "/tmp/daemon.json"
        ])
        .is_err());
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "down"]).is_ok());
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "logs", "--follow"]).is_ok());
        // silod upgrades the system VM itself; there is nothing to drive by hand.
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "upgrade"]).is_err());
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
        use silod_spec::status::MemoryReclaimOutcome;

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

    #[test]
    fn update_check_row_reports_errors_alongside_the_last_check() {
        let mut status: silod_spec::status::DaemonStatus =
            serde_json::from_value(serde_json::json!({
                "schema": 1, "generation": "d823458f-090b-48c3-87d4-33daf76c0000",
                "pid": 1, "phase": "ready", "machine_id": null, "run_id": null,
                "image_digest": null, "docker_socket": "/tmp/test.sock",
                "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
            }))
            .expect("status");
        assert_eq!(format_update_check(&status), "not checked yet");
        status.update_checked_at = Some(chrono::Utc::now().to_rfc3339());
        status.update_error = Some("registry unreachable".into());
        let row = format_update_check(&status);
        assert!(row.starts_with("checked "), "{row}");
        assert!(row.ends_with("; registry unreachable"), "{row}");
    }
}

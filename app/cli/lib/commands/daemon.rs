use clap::{Args, Subcommand};
use eyre::Context as _;

use silod_spec::paths::DaemonPaths;
use silod_spec::status::{CorePhase, DaemonStatus, MemoryReclaimOutcome, SystemStatus};

use crate::context::Context;
use crate::daemon::service;
use crate::ui::Spinner;

#[derive(Debug, Args)]
pub struct Cmd {
    #[command(subcommand)]
    pub(crate) command: DaemonCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DaemonCommand {
    /// Run the daemon in the foreground (what the registered service executes).
    Run(crate::daemon::serve::Run),
    // The controller commands need the host paths; the daemon resolves its own.
    #[command(flatten)]
    Control(ControlCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum ControlCommand {
    /// Enable and start the per-user daemon and selected integrations.
    Up(Up),
    /// Disable the per-user service and stop the system VM.
    Down,
    /// Report live daemon state without starting the VM.
    Status(Status),
    /// Read bounded daemon supervisor logs.
    Logs(Logs),
}

#[derive(Debug, Args)]
pub(crate) struct Up {
    #[arg(long)]
    foreground: bool,
    #[arg(long)]
    no_switch_context: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    system: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    tailscale: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true, conflicts_with = "foreground")]
    linger: Option<bool>,
}

#[derive(Debug, Args)]
pub(crate) struct Status {
    #[arg(long, value_enum, default_value_t = crate::ui::OutputFormat::Plain)]
    format: crate::ui::OutputFormat,
}

#[derive(Debug, Args)]
pub(crate) struct Logs {
    #[arg(long)]
    follow: bool,
    #[arg(long, default_value_t = 200)]
    lines: usize,
}

impl Cmd {
    pub(crate) async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let command = match self.command {
            DaemonCommand::Run(args) => return run_daemon(args).await,
            DaemonCommand::Control(command) => command,
        };
        let host = libvm::HostPaths::from_env()?;
        let paths = DaemonPaths::new(host.home());
        match command {
            ControlCommand::Up(command) => {
                eyre::ensure!(
                    !command.foreground || command.linger.is_none(),
                    "--linger cannot be used with --foreground"
                );
                #[cfg(not(target_os = "linux"))]
                eyre::ensure!(
                    command.linger.is_none(),
                    "--linger is supported only on Linux"
                );
                let spinner = Spinner::start("Checking", "daemon configuration");
                let selection = crate::config::FeatureOverrides {
                    system: command.system,
                    tailscale: command.tailscale,
                };
                let existing_installation = paths.daemon_data().join("daemon.json").try_exists()?;
                let features = context
                    .config()?
                    .resolve_features(selection, existing_installation);
                let socket = paths.docker_socket();
                let live = service::status(&paths)?.is_some();
                if features.system {
                    crate::daemon::docker::preflight(&socket, live)?;
                }
                let selected = crate::config::FeatureOverrides {
                    system: Some(features.system),
                    tailscale: Some(features.tailscale),
                };
                crate::daemon::serve::validate(&host, selected)?;
                if command.foreground {
                    spinner.finish_clear();
                    return run_daemon(crate::daemon::serve::Run {
                        system: silod_spec::arguments::SystemArgs::default(),
                        system_enabled: selected.system,
                        tailscale_enabled: selected.tailscale,
                        stop: false,
                    })
                    .await;
                }
                let executable = std::env::current_exe()
                    .and_then(|path| path.canonicalize())
                    .context("locate the silo executable")?;
                let service = service::ServiceConfig::new(&paths, executable)?;
                service::validate_registration(&service)?;
                spinner.finish_success("Checked");
                service::bootstrap_linger(command.linger)?;
                let mut spinner = Spinner::start("Starting", "daemon");
                crate::config::GlobalConfig::persist_features(
                    &host,
                    selection,
                    existing_installation,
                )?;
                let persisted = crate::config::GlobalConfig::load_from(&host)?;
                let features =
                    persisted.resolve_features(Default::default(), existing_installation);
                let identity = persisted.daemon_identity(features)?;
                service::up(&service, &identity, features.system, &mut spinner).await?;
                spinner.finish_success("Started");
                if features.tailscale {
                    if let Some(status) = service::status(&paths)? {
                        report_lobby(&status);
                    }
                }
                if features.system {
                    crate::daemon::docker::integrate(&socket, !command.no_switch_context)?;
                    crate::ui::hint(format!("Docker endpoint: unix://{}", socket.display()));
                }
                Ok(())
            }
            ControlCommand::Down => service::down(&paths).await,
            ControlCommand::Status(command) => {
                let view = DaemonStatusView::collect(&paths)?;
                match command.format {
                    crate::ui::OutputFormat::Json => crate::ui::print_json(&view),
                    crate::ui::OutputFormat::Plain => view.print_human(),
                }
            }
            ControlCommand::Logs(command) => {
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

/// Runs the daemon to completion, mapping a rejected configuration to exit code 2
/// so the service manager does not retry it.
async fn run_daemon(args: crate::daemon::serve::Run) -> eyre::Result<()> {
    crate::daemon::serve::run(args).await.map_err(|error| {
        let code = crate::daemon::serve::exit_code(&error);
        eyre::eyre!("{error:#}").wrap_err(crate::errors::ExecutionExit::new(code))
    })
}

#[derive(Debug, serde::Serialize)]
struct DaemonStatusView {
    /// Summary state: `stopped`, `starting`, `ready`, `degraded`, `failed`, `stopping`.
    state: &'static str,
    /// Whether the native user service starts the daemon at login.
    autostart: Option<bool>,
    linger: Option<bool>,
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
        let linger = service::linger_status();
        let system = daemon.as_ref().and_then(|status| status.system.as_ref());
        let endpoint = system.map(|system| system.docker_socket.clone());
        let memory_bytes = system.and_then(|system| system.memory_bytes);
        let state = match daemon.as_ref().map(|status| status.core) {
            None | Some(CorePhase::Stopped) => "stopped",
            Some(CorePhase::Ready) => "ready",
            Some(CorePhase::Failed) => "failed",
            Some(CorePhase::Stopping) => "stopping",
            Some(CorePhase::Starting) => "starting",
        };
        Ok(Self {
            state,
            autostart,
            linger,
            endpoint,
            memory_bytes,
            daemon,
        })
    }

    fn print_human(&self) -> eyre::Result<()> {
        crate::ui::print_detail_rows(&self.human_rows())
    }

    fn human_rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        rows.push(("Core".to_string(), self.state.to_string()));
        rows.push((
            "Autostart".to_string(),
            match self.autostart {
                Some(true) => "enabled".to_string(),
                Some(false) => "disabled".to_string(),
                None => "unknown".to_string(),
            },
        ));
        rows.push((
            "User linger".to_string(),
            match self.linger {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            }
            .to_string(),
        ));
        if let Some(endpoint) = &self.endpoint {
            rows.push(("Endpoint".to_string(), format!("unix://{endpoint}")));
        }
        if let Some(daemon) = &self.daemon {
            rows.push(("PID".to_string(), daemon.pid.to_string()));
            rows.push((
                "Control endpoint".to_string(),
                daemon.control_endpoint.display().to_string(),
            ));
            rows.push((
                "System".to_string(),
                daemon
                    .system
                    .as_ref()
                    .map(|system| format!("{:?}", system.phase))
                    .unwrap_or_else(|| "disabled".into()),
            ));
            rows.push((
                "Lobby".to_string(),
                daemon
                    .lobby
                    .as_ref()
                    .map(|lobby| lobby.phase.to_string())
                    .unwrap_or_else(|| "disabled".into()),
            ));
            if let Some(lobby) = &daemon.lobby {
                if let Some(dns_name) = &lobby.dns_name {
                    rows.push(("Lobby DNS".to_string(), dns_name.clone()));
                }
                if let Some(approval_url) = &lobby.approval_url {
                    rows.push(("Lobby login".to_string(), approval_url.clone()));
                }
                if let Some(diagnostic) = &lobby.diagnostic {
                    rows.push(("Lobby diagnostic".to_string(), diagnostic.clone()));
                }
                rows.push((
                    "Lobby restarts".to_string(),
                    lobby.restart_count.to_string(),
                ));
            }
            if let Some(error) = &daemon.last_error {
                rows.push(("Core error".to_string(), error.clone()));
            }
            if let Some(live) = &daemon.manager_live {
                crate::commands::system::append_live_rows(
                    &mut rows,
                    "Manager prospective host",
                    live.backend,
                    live.lane,
                    &live.live,
                );
            }
            if let Some(live) = &daemon.appliance_live {
                crate::commands::system::append_live_rows(
                    &mut rows,
                    "Appliance prospective host",
                    live.backend,
                    live.lane,
                    &live.live,
                );
            }
        }
        if let Some(status) = self
            .daemon
            .as_ref()
            .and_then(|daemon| daemon.system.as_ref())
        {
            if let Some(live) = &status.live {
                crate::commands::system::append_live_rows(
                    &mut rows,
                    "Appliance machine run",
                    live.backend,
                    live.lane,
                    &live.live,
                );
            }
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
                    format_host_memory_reclaim(status),
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
        rows
    }
}

/// Show the lobby's current phase and any approval action after starting the daemon.
pub(crate) fn report_lobby(status: &DaemonStatus) {
    if let Some(lobby) = &status.lobby {
        crate::ui::hint(format!("Lobby: {}", lobby.phase));
        if let Some(approval_url) = &lobby.approval_url {
            crate::ui::hint(format!("Lobby login: {approval_url}"));
        }
    }
}

/// When the daemon last asked the registry about the system image, and what went wrong.
fn format_update_check(status: &SystemStatus) -> String {
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

fn format_host_memory_reclaim(status: &silod_spec::status::SystemStatus) -> String {
    let requested = if status.host_memory_reclaim_requested {
        "auto"
    } else {
        "off"
    };
    let effective_text = match status.host_memory_reclaim_effective {
        Some(true) => "on",
        Some(false) => "off",
        None => "unknown (not yet reported by the VM backend)",
    };
    let mut text = format!("requested {requested}; effective {effective_text}");
    if let Some(qualification) = &status.host_memory_reclaim_qualification {
        text.push_str(&format!(" (probe {qualification})"));
    }
    if let Some(backing) = &status.host_memory_reclaim_backing {
        text.push_str(&format!("; backing {backing}"));
    }
    if let Some(reason) = &status.host_memory_reclaim_reason {
        text.push_str(&format!("; reason {reason}"));
    }
    if let (Some(_), Some(bytes)) = (
        status.host_memory_reclaim_effective,
        status.host_memory_reclaim_released_bytes,
    ) {
        text.push_str(&format!(
            "; {} released since VM start",
            crate::ui::human_bytes(Some(bytes))
        ));
    }
    if let Some(skips) = status
        .host_memory_reclaim_mapping_limit_skips
        .filter(|skips| *skips != 0)
    {
        text.push_str(&format!("; {skips} skipped at mapping limit"));
    }
    if let Some(islands) = status.host_memory_reclaim_replaced_islands {
        text.push_str(&format!("; {islands} replaced islands"));
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

    use crate::commands::daemon::{format_update_check, DaemonStatusView};
    use silod_spec::status::{LobbyPhase, LobbyStatus};

    fn status_view(lobby: Option<LobbyStatus>) -> DaemonStatusView {
        let daemon = serde_json::from_value(serde_json::json!({
            "schema": 2, "generation": "00000000-0000-4000-8000-000000000004",
            "pid": 1, "process_start": "1", "core": "ready", "home": "/tmp/home",
            "control_endpoint": "/tmp/control", "updated_at": "2026-11-11T00:00:00Z",
            "last_error": null, "system": null, "lobby": lobby,
            "configuration_identity": "test", "manager_live": null, "appliance_live": null,
        }))
        .unwrap();
        DaemonStatusView {
            state: "ready",
            autostart: Some(true),
            linger: None,
            endpoint: None,
            memory_bytes: None,
            daemon: Some(daemon),
        }
    }

    #[test]
    fn lobby_status_rows_render_all_phases_and_details() {
        for phase in [
            LobbyPhase::Starting,
            LobbyPhase::NeedsLogin,
            LobbyPhase::NeedsTag,
            LobbyPhase::Ready,
            LobbyPhase::Degraded,
            LobbyPhase::Failed,
        ] {
            let view = status_view(Some(LobbyStatus {
                phase,
                dns_name: Some("lobby.example.ts.net".into()),
                approval_url: Some("https://login.tailscale.com/a/example".into()),
                diagnostic: Some("waiting for approval".into()),
                restart_count: 3,
                updated_at: "2026-11-11T00:00:00Z".into(),
            }));
            let rows: Vec<_> = view
                .human_rows()
                .into_iter()
                .filter(|(key, _)| key.starts_with("Lobby"))
                .collect();
            assert_eq!(
                rows,
                vec![
                    ("Lobby".into(), phase.to_string()),
                    ("Lobby DNS".into(), "lobby.example.ts.net".into()),
                    (
                        "Lobby login".into(),
                        "https://login.tailscale.com/a/example".into()
                    ),
                    ("Lobby diagnostic".into(), "waiting for approval".into()),
                    ("Lobby restarts".into(), "3".into()),
                ]
            );
            let json = serde_json::to_value(&view).unwrap();
            assert_eq!(
                json["daemon"]["lobby"],
                serde_json::to_value(view.daemon.as_ref().unwrap().lobby.as_ref()).unwrap()
            );
        }
    }

    #[test]
    fn lobby_status_rows_omit_unavailable_details_and_mark_disabled() {
        let view = status_view(None);
        let rows: Vec<_> = view
            .human_rows()
            .into_iter()
            .filter(|(key, _)| key.starts_with("Lobby"))
            .collect();
        assert_eq!(rows, vec![("Lobby".into(), "disabled".into())]);
        assert!(serde_json::to_value(&view).unwrap()["daemon"]["lobby"].is_null());
        let view = status_view(Some(LobbyStatus {
            phase: LobbyPhase::Starting,
            dns_name: None,
            approval_url: None,
            diagnostic: None,
            restart_count: 0,
            updated_at: "2026-11-11T00:00:00Z".into(),
        }));
        let rows: Vec<_> = view
            .human_rows()
            .into_iter()
            .filter(|(key, _)| key.starts_with("Lobby"))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("Lobby".into(), "starting".into()),
                ("Lobby restarts".into(), "0".into()),
            ]
        );
    }

    #[test]
    fn feature_flags_distinguish_omitted_enabled_and_disabled() {
        #[derive(clap::Parser)]
        struct Options {
            #[command(flatten)]
            up: crate::commands::daemon::Up,
        }
        let omitted = Options::try_parse_from(["up"]).expect("omitted");
        assert_eq!(omitted.up.system, None);
        assert_eq!(omitted.up.tailscale, None);
        assert_eq!(omitted.up.linger, None);
        let linger = Options::try_parse_from(["up", "--linger"]).expect("linger");
        assert_eq!(linger.up.linger, Some(true));
        let no_linger = Options::try_parse_from(["up", "--linger=false"]).expect("no linger");
        assert_eq!(no_linger.up.linger, Some(false));
        let selected =
            Options::try_parse_from(["up", "--system=false", "--tailscale"]).expect("selection");
        assert_eq!(selected.up.system, Some(false));
        assert_eq!(selected.up.tailscale, Some(true));
        let reversed =
            Options::try_parse_from(["up", "--system", "--tailscale=false"]).expect("selection");
        assert_eq!(reversed.up.system, Some(true));
        assert_eq!(reversed.up.tailscale, Some(false));
        assert!(Options::try_parse_from(["up", "--foreground", "--linger"]).is_err());
        assert!(Options::try_parse_from(["up", "--system=invalid"]).is_err());
    }

    #[test]
    fn parses_controller_commands_and_the_daemon_entrypoint() {
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "up", "--foreground"]).is_ok());
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "run", "--stop"]).is_ok());
        // The daemon takes the normal Silo Home; there is no state/home argument.
        assert!(
            crate::app::Cli::try_parse_from(["silo", "daemon", "run", "--home", "/x"]).is_err()
        );
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "run", "--check"]).is_err());
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
        // The daemon upgrades the system VM itself; there is nothing to drive by hand.
        assert!(crate::app::Cli::try_parse_from(["silo", "daemon", "upgrade"]).is_err());
        assert!(
            crate::app::Cli::try_parse_from(["silo", "daemon", "balloon", "--target", "1GiB"])
                .is_err()
        );
    }

    #[test]
    fn update_check_row_reports_errors_alongside_the_last_check() {
        let mut status: silod_spec::status::SystemStatus =
            serde_json::from_value(serde_json::json!({
                "phase": "ready", "machine_id": null, "run_id": null,
                "image_digest": null, "docker_socket": "/tmp/test.sock",
                "updated_at": "2026-01-01T00:00:00Z", "last_error": null, "restart_count": 0,
                "live": null, "prospective_live": null,
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

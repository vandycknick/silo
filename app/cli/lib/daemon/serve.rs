//! The daemon entrypoint behind `silo daemon run`: argument validation, startup
//! ordering, and the serve loop that supervises the system VM and the tailscale
//! helper until it is told to stop.
use crate::config::{FeatureOverrides, GlobalConfig};
use silod_spec::arguments::{SystemArgs, SystemOverrides};
use silod_spec::paths::DaemonPaths;

use crate::daemon::control;
use crate::daemon::helper;
use crate::daemon::record::DaemonRecord;
use crate::daemon::shutdown;
use crate::daemon::status;
use crate::daemon::supervisor::{self, LifetimeLock};
use crate::daemon::system_config::{self, DesiredSystem};

#[derive(Debug, clap::Args)]
#[command(
    after_help = "Runs in the foreground. All --system-* resource options apply only to the system appliance; omitted ones use normal configuration or their defaults, except the backend and disk sizes, which keep the installation's values. The daemon follows the system image reference and upgrades the system VM in place when it changes. State uses the normal Silo Home (SILO_HOME, else ~/.silo). Use `silo daemon up` to register it as a service."
)]
pub(crate) struct Run {
    #[command(flatten)]
    pub(crate) system: SystemArgs,
    /// Override the configured system integration selection for validation.
    #[arg(long, hide = true)]
    pub(crate) system_enabled: Option<bool>,
    /// Override the configured Tailscale integration selection for validation.
    #[arg(long, hide = true)]
    pub(crate) tailscale_enabled: Option<bool>,
    /// Stop the installation's VMs if no daemon is running, then exit.
    #[arg(long)]
    pub(crate) stop: bool,
    /// Internal Linux user-service ExecStop entrypoint.
    #[arg(long, hide = true, conflicts_with = "stop")]
    pub(crate) host_shutdown: bool,
}

/// A rejected configuration: restarting the daemon cannot fix it, so the service
/// manager must not retry (exit code 2).
#[derive(Debug)]
struct ConfigurationError(eyre::Report);
impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}
impl std::error::Error for ConfigurationError {}
fn configuration<T>(result: eyre::Result<T>) -> eyre::Result<T> {
    result.map_err(|error| {
        if error.chain().any(|cause| cause.is::<std::io::Error>()) {
            error
        } else {
            ConfigurationError(error).into()
        }
    })
}

/// The process exit code for a failed `run`: 2 for a rejected configuration,
/// 1 for anything a restart might cure.
pub(crate) fn exit_code(error: &eyre::Report) -> i32 {
    if error.downcast_ref::<ConfigurationError>().is_some() {
        2
    } else {
        1
    }
}

/// Validates what `silo daemon up` would register (the stored overrides plus the
/// selected features), without creating daemon state or touching the service
/// locks, so a bad configuration fails before it lands in a unit definition.
pub(crate) fn validate(host: &libvm::HostPaths, features: FeatureOverrides) -> eyre::Result<()> {
    let global = configuration(GlobalConfig::load_from(host))?;
    let paths = DaemonPaths::new(host.home());
    let overrides = configuration(global.daemon_overrides())?;
    let features = global.resolve_features(
        features,
        configuration(DaemonRecord::load(&paths))?.is_some(),
    );
    if features.system {
        configuration(desired_system(&paths, &overrides))?;
    }
    Ok(())
}

/// Stops any VM of this installation still running with no daemon supervising
/// it, publishing the outcome like a daemon shutdown would.
pub(crate) async fn stop_installation() -> eyre::Result<()> {
    let host = configuration(libvm::HostPaths::from_env().map_err(Into::into))?;
    let global = configuration(GlobalConfig::load_from(&host))?;
    let paths = DaemonPaths::new(host.home());
    let features = global.resolve_features(
        FeatureOverrides::default(),
        configuration(DaemonRecord::load(&paths))?.is_some(),
    );
    let configuration_identity = configuration(global.daemon_identity(features))?;
    let host = configuration(crate::config::prepare_host_paths(&host))?;
    let _lock = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let system_status = supervisor::initial_status(&paths.docker_socket())?;
    let publisher = status::StatusPublisher::new(
        &host,
        uuid::Uuid::new_v4(),
        features,
        configuration_identity,
        Some(system_status.clone()),
    )?;
    let result = supervisor::stop_installation(&paths, system_status, &publisher).await;
    publisher.set_core(
        if result.is_ok() {
            silod_spec::status::CorePhase::Stopped
        } else {
            silod_spec::status::CorePhase::Failed
        },
        result.as_ref().err().map(|e| format!("{e:#}")),
    )?;
    result
}

pub(crate) async fn run(args: Run) -> eyre::Result<()> {
    if nix::unistd::geteuid().is_root() {
        return configuration(Err(eyre::eyre!(
            "silo daemon run is a per-user daemon; run without sudo/root"
        )));
    }
    if args.host_shutdown {
        return shutdown::run().await;
    }
    if args.stop {
        return stop_installation().await;
    }
    let host = configuration(libvm::HostPaths::from_env().map_err(Into::into))?;
    // Validate before creating daemon state or service locks.
    let global = configuration(GlobalConfig::load_from(&host))?;
    let paths = DaemonPaths::new(host.home());
    let overrides = merge_system_overrides(
        configuration(global.daemon_overrides())?,
        args.system.into_overrides(),
    );
    let features = global.resolve_features(
        FeatureOverrides {
            system: args.system_enabled,
            tailscale: args.tailscale_enabled,
        },
        configuration(DaemonRecord::load(&paths))?.is_some(),
    );
    let desired = if features.system {
        Some(configuration(desired_system(&paths, &overrides))?)
    } else {
        None
    };
    let configuration_identity = configuration(global.daemon_identity(features))?;
    let host = configuration(crate::config::prepare_host_paths(&host))?;
    let _lock = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let socket_ownership = control::socket::SocketOwnership::acquire()?;
    let generation = uuid::Uuid::new_v4();
    let system_status = features
        .system
        .then(|| supervisor::initial_status(&paths.docker_socket()))
        .transpose()?;
    let publisher = std::sync::Arc::new(status::StatusPublisher::new(
        &host,
        generation,
        features,
        configuration_identity,
        system_status.clone(),
    )?);
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let helper_config = global.tailscale().clone();
    let registry_policy = global.images().clone();
    let state = std::sync::Arc::new(control::ControlState::new(
        host,
        global,
        generation,
        publisher.clone(),
    ));
    let server = match socket_ownership.bind(state.clone()) {
        Ok(server) => server,
        Err(error) => {
            publisher.set_core(
                silod_spec::status::CorePhase::Failed,
                Some(format!("{error:#}")),
            )?;
            return Err(error);
        }
    };
    let api_shutdown = tokio_util::sync::CancellationToken::new();
    let mut api_task = tokio::spawn(server.serve(api_shutdown.clone()));
    let system_shutdown = tokio_util::sync::CancellationToken::new();
    let mut system_task = if let Some(desired) = desired {
        Some(tokio::spawn(supervisor::serve(
            paths.clone(),
            desired,
            system_status.ok_or_else(|| eyre::eyre!("enabled system has no initial status"))?,
            system_shutdown.clone(),
            publisher.clone(),
            registry_policy,
        )))
    } else {
        None
    };
    let helper_shutdown = tokio_util::sync::CancellationToken::new();
    let mut helper_task = features.tailscale.then(|| {
        tokio::spawn(helper::serve(
            state.clone(),
            helper_config,
            publisher.clone(),
            helper_shutdown.clone(),
        ))
    });
    publisher.set_core(silod_spec::status::CorePhase::Ready, None)?;
    let api_result = loop {
        tokio::select! {
            _ = interrupt.recv() => break None,
            _ = terminate.recv() => break None,
            result = &mut api_task => break Some(result),
            result = async {
                match system_task.as_mut() {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            } => {
                system_task = None;
                let error = match result {
                    Ok(Ok(())) => eyre::eyre!("system supervisor stopped unexpectedly"),
                    Ok(Err(error)) => error,
                    Err(error) => eyre::eyre!("system supervisor task failed: {error}"),
                };
                publisher.fail_system(format!("{error:#}"))?;
                if let Err(log_error) = supervisor::append_log(&paths, &format!("system supervisor failed: {error:#}")) {
                    eprintln!("system supervisor diagnostic could not be logged: {log_error:#}");
                }
                // Optional integration failure does not take away a working core API.
            }
            result = async {
                match helper_task.as_mut() {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            } => {
                helper_task = None;
                if let Err(error) = result.map_err(eyre::Report::from).and_then(|r| r) {
                    state.set_helper_generation(None).await;
                    publisher.set_tailscale(silod_spec::status::ComponentStatus {
                        enabled: true,
                        state: silod_spec::status::ComponentState::Failed,
                        diagnostic: Some(format!("helper supervisor failed: {error:#}")),
                        approval_url: None, dns_name: None, restart_count: 0,
                        shutdown_protection: if cfg!(target_os = "macos") {
                            silod_spec::status::ShutdownProtection::Unsupported
                        } else {
                            silod_spec::status::ShutdownProtection::Unavailable
                        },
                    })?;
                }
            }
        }
    };
    state.begin_stopping().await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(87);
    system_shutdown.cancel();
    helper_shutdown.cancel();
    let drained = tokio::time::timeout_at(deadline, async {
        let helper_result = if let Some(task) = helper_task.as_mut() {
            task.await.map_err(eyre::Report::from).and_then(|r| r)
        } else {
            Ok(())
        };
        state.set_helper_generation(None).await;
        state.seal_mutations().await;
        state.drain_mutations().await?;
        helper_result?;
        if let Some(task) = system_task {
            task.await??;
        }
        Ok::<(), eyre::Report>(())
    })
    .await
    .map_err(|_| eyre::eyre!("daemon shutdown deadline expired with incomplete mutation drain"))
    .and_then(|r| r);
    if drained.is_err() {
        if let Some(task) = helper_task.as_mut() {
            if !task.is_finished() {
                task.abort();
                let _ = task.await;
            }
        }
        state.set_helper_generation(None).await;
        state.seal_mutations().await;
    }
    api_shutdown.cancel();
    let api_result = match api_result {
        Some(result) => result.map_err(Into::into).and_then(|r| r),
        None => tokio::time::timeout(std::time::Duration::from_secs(3), api_task)
            .await
            .map_err(Into::into)
            .and_then(|r| r.map_err(Into::into))
            .and_then(|r| r),
    };
    let result = drained.and(api_result);
    publisher.set_core(
        if result.is_ok() {
            silod_spec::status::CorePhase::Stopped
        } else {
            silod_spec::status::CorePhase::Failed
        },
        result.as_ref().err().map(|e| format!("{e:#}")),
    )?;
    result
}

fn desired_system(paths: &DaemonPaths, overrides: &SystemOverrides) -> eyre::Result<DesiredSystem> {
    let installation = DaemonRecord::load(paths)?;
    let desired = system_config::resolve(
        overrides,
        &user_home()?,
        &paths.docker_socket(),
        installation.as_ref(),
    )?;
    if let Some(installation) = &installation {
        crate::daemon::provision::validate_installation(installation, &desired.config)?;
    }
    Ok(desired)
}

fn merge_system_overrides(stored: SystemOverrides, explicit: SystemOverrides) -> SystemOverrides {
    SystemOverrides {
        backend: explicit.backend.or(stored.backend),
        image: explicit.image.or(stored.image),
        cpus: explicit.cpus.or(stored.cpus),
        memory: explicit.memory.or(stored.memory),
        root_size: explicit.root_size.or(stored.root_size),
        data_size: explicit.data_size.or(stored.data_size),
        rosetta: explicit.rosetta.or(stored.rosetta),
        home_share: explicit.home_share.or(stored.home_share),
        additional_shares: explicit.additional_shares.or(stored.additional_shares),
        publish_bind: explicit.publish_bind.or(stored.publish_bind),
    }
}

fn user_home() -> eyre::Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| eyre::eyre!("HOME is required"))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::app::Cli;
    use crate::commands::daemon::DaemonCommand;
    use crate::commands::Command;
    use crate::daemon::serve::{configuration, merge_system_overrides, ConfigurationError, Run};

    fn parse<const N: usize>(args: [&str; N]) -> Result<Run, clap::Error> {
        let argv = ["silo", "daemon", "run"].into_iter().chain(args);
        let cli = Cli::try_parse_from(argv)?;
        match cli.command {
            Command::Daemon(daemon) => match daemon.command {
                DaemonCommand::Run(run) => Ok(run),
                other => panic!("parsed {other:?} instead of daemon run"),
            },
            other => panic!("parsed {other:?} instead of daemon run"),
        }
    }

    #[test]
    fn defaults_require_no_state_or_home_argument() {
        let defaults = parse([]).expect("defaults");
        assert!(!defaults.stop);
        assert!(!defaults.host_shutdown);
        assert_eq!(
            defaults.system.into_overrides(),
            silod_spec::arguments::SystemOverrides::default()
        );
        for flag in ["--state", "--home", "--check"] {
            assert!(parse([flag, "/tmp/unused"]).is_err());
        }
    }

    #[test]
    fn host_shutdown_is_explicit_and_not_ordinary_stop() {
        let args = parse(["--host-shutdown"]).expect("host shutdown");
        assert!(args.host_shutdown);
        assert!(!args.stop);
        assert!(parse(["--host-shutdown", "--stop"]).is_err());
    }

    #[test]
    fn only_explicit_system_overrides_are_set() {
        let args = parse(["--system-cpus", "10", "--system-rosetta", "false"]).expect("options");
        let overrides = args.system.into_overrides();
        assert_eq!(overrides.cpus, Some(10));
        assert_eq!(overrides.rosetta, Some(false));
        assert!(overrides.memory.is_none());
    }

    #[test]
    fn explicit_overrides_win_without_erasing_unset_configured_values() {
        use silod_spec::arguments::SystemOverrides;
        let stored = SystemOverrides {
            cpus: Some(6),
            memory: Some("12GiB".into()),
            rosetta: Some(true),
            additional_shares: Some(vec![silod_spec::arguments::Share {
                path: "/stored".into(),
                read_only: true,
            }]),
            ..Default::default()
        };
        let explicit = SystemOverrides {
            cpus: Some(2),
            rosetta: Some(false),
            additional_shares: Some(vec![]),
            ..Default::default()
        };
        let merged = merge_system_overrides(stored, explicit);
        assert_eq!(merged.cpus, Some(2));
        assert_eq!(merged.memory.as_deref(), Some("12GiB"));
        assert_eq!(merged.rosetta, Some(false));
        assert_eq!(merged.additional_shares, Some(vec![]));
    }

    #[test]
    fn feature_overrides_are_separate_from_system_resource_arguments() {
        let args =
            parse(["--system-enabled=false", "--tailscale-enabled=true"]).expect("feature options");
        assert_eq!(args.system_enabled, Some(false));
        assert_eq!(args.tailscale_enabled, Some(true));
        assert_eq!(args.system.into_overrides(), Default::default());
    }

    #[test]
    fn operational_io_failures_remain_restartable() {
        let io = eyre::Report::from(std::io::Error::from_raw_os_error(nix::libc::ENOSPC))
            .wrap_err("preparing the selected Home");
        let error = configuration::<()>(Err(io)).expect_err("operational failure");
        assert!(error.downcast_ref::<ConfigurationError>().is_none());
        assert_eq!(crate::daemon::serve::exit_code(&error), 1);
        let error = configuration::<()>(Err(eyre::eyre!("unsafe root")))
            .expect_err("invalid configuration");
        assert!(error.downcast_ref::<ConfigurationError>().is_some());
        assert_eq!(crate::daemon::serve::exit_code(&error), 2);
    }
}

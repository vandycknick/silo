mod config;
mod control;
mod engine;
mod helper;
mod paths;
mod provision;
mod record;
mod runtime;
mod status;
mod storage;
mod supervisor;
mod upgrade;

use clap::Parser;
use silo_config::{FeatureOverrides, GlobalConfig};
use silod_spec::arguments::{SystemArgs, SystemOverrides};

use crate::config::DesiredSystem;
use crate::paths::SystemPaths;
use crate::record::DaemonRecord;
use crate::supervisor::LifetimeLock;

#[derive(Debug, Parser)]
#[command(
    name = "silod",
    about = "Silo VM-management daemon",
    version,
    after_help = "Runs in the foreground. All --system-* resource options apply only to the system appliance; omitted ones use normal configuration or their defaults, except the backend and disk sizes, which keep the installation's values. silod follows the system image reference and upgrades the system VM in place when it changes. State uses the normal Silo Home (SILO_HOME, else ~/.silo). Use `silo daemon` for service management."
)]
struct Args {
    #[command(flatten)]
    system: SystemArgs,
    /// Override the configured system integration selection for validation.
    #[arg(long, hide = true)]
    system_enabled: Option<bool>,
    /// Override the configured Tailscale integration selection for validation.
    #[arg(long, hide = true)]
    tailscale_enabled: Option<bool>,
    /// Validate the options against the installation, then exit without changing
    /// anything.
    #[arg(long, conflicts_with = "stop")]
    check: bool,
    /// Stop the installation's VMs if no daemon is running, then exit.
    #[arg(long)]
    stop: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Args::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::from(if error.downcast_ref::<ConfigurationError>().is_some() {
                2
            } else {
                1
            })
        }
    }
}

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

async fn run(args: Args) -> eyre::Result<()> {
    if nix::unistd::geteuid().is_root() {
        return configuration(Err(eyre::eyre!(
            "silod is a per-user daemon; run without sudo/root"
        )));
    }
    let host = configuration(libvm::HostPaths::from_env().map_err(Into::into))?;
    // Validate before creating daemon state or service locks.
    let global = configuration(GlobalConfig::load_from(&host))?;
    let paths = SystemPaths::from_host(&host);
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
    if args.check {
        return if features.system {
            configuration(desired_system(&paths, &overrides)).map(drop)
        } else {
            Ok(())
        };
    }
    let desired = if features.system && !args.stop {
        Some(configuration(desired_system(&paths, &overrides))?)
    } else {
        None
    };
    let configuration_identity = configuration(global.daemon_identity(features))?;
    let host = configuration(silo_config::prepare_host_paths(&host))?;
    let paths = SystemPaths::from_host(&host);
    let _lock = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let generation = uuid::Uuid::new_v4();
    let system_status = if features.system || args.stop {
        Some(supervisor::initial_status(&paths.docker_socket())?)
    } else {
        None
    };
    let publisher = std::sync::Arc::new(status::StatusPublisher::new(
        &host,
        generation,
        features,
        configuration_identity,
        system_status.clone(),
    )?);
    if args.stop {
        let result =
            supervisor::stop_installation(&paths, system_status.unwrap(), &publisher).await;
        publisher.set_core(
            if result.is_ok() {
                silod_spec::status::CorePhase::Stopped
            } else {
                silod_spec::status::CorePhase::Failed
            },
            result.as_ref().err().map(|e| format!("{e:#}")),
        )?;
        return result;
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let helper_config = global.tailscale().clone();
    let state = std::sync::Arc::new(control::ControlState::new(
        host,
        global,
        generation,
        publisher.clone(),
    ));
    let server = match control::socket::BoundServer::bind(state.clone()) {
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
                        shutdown_protection: silod_spec::status::ShutdownProtection::Unavailable,
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

fn desired_system(paths: &SystemPaths, overrides: &SystemOverrides) -> eyre::Result<DesiredSystem> {
    let installation = DaemonRecord::load(paths)?;
    let desired = config::resolve(
        overrides,
        &user_home()?,
        &paths.docker_socket(),
        installation.as_ref(),
    )?;
    if let Some(installation) = &installation {
        provision::validate_installation(installation, &desired.config)?;
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
    use crate::Args;
    use clap::Parser as _;

    #[test]
    fn defaults_require_no_state_or_home_argument() {
        let defaults = Args::try_parse_from(["silod"]).expect("defaults");
        assert!(!defaults.check);
        assert!(!defaults.stop);
        assert!(Args::try_parse_from(["silod", "--check", "--stop"]).is_err());
        assert_eq!(
            defaults.system.into_overrides(),
            silod_spec::arguments::SystemOverrides::default()
        );
        for flag in ["--state", "--home"] {
            assert!(Args::try_parse_from(["silod", flag, "/tmp/unused"]).is_err());
        }
    }

    #[test]
    fn daemon_has_no_management_subcommands() {
        for command in [
            "service", "system", "start", "stop", "upgrade", "daemon", "serve",
        ] {
            assert!(Args::try_parse_from(["silod", command]).is_err());
        }
    }

    #[test]
    fn only_explicit_system_overrides_are_set() {
        let args =
            Args::try_parse_from(["silod", "--system-cpus", "10", "--system-rosetta", "false"])
                .expect("options");
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
        let merged = crate::merge_system_overrides(stored, explicit);
        assert_eq!(merged.cpus, Some(2));
        assert_eq!(merged.memory.as_deref(), Some("12GiB"));
        assert_eq!(merged.rosetta, Some(false));
        assert_eq!(merged.additional_shares, Some(vec![]));
    }

    #[test]
    fn feature_overrides_are_separate_from_system_resource_arguments() {
        let args = Args::try_parse_from([
            "silod",
            "--check",
            "--system-enabled=false",
            "--tailscale-enabled=true",
        ])
        .expect("feature options");
        assert_eq!(args.system_enabled, Some(false));
        assert_eq!(args.tailscale_enabled, Some(true));
        assert_eq!(args.system.into_overrides(), Default::default());
    }
    #[test]
    fn operational_io_failures_remain_restartable() {
        let io = eyre::Report::from(std::io::Error::from_raw_os_error(nix::libc::ENOSPC))
            .wrap_err("preparing the selected Home");
        let error = crate::configuration::<()>(Err(io)).expect_err("operational failure");
        assert!(error.downcast_ref::<crate::ConfigurationError>().is_none());
        let error = crate::configuration::<()>(Err(eyre::eyre!("unsafe root")))
            .expect_err("invalid configuration");
        assert!(error.downcast_ref::<crate::ConfigurationError>().is_some());
    }
}

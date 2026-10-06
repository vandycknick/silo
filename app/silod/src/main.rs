mod config;
mod engine;
mod paths;
mod provision;
mod record;
mod runtime;
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
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> eyre::Result<()> {
    if nix::unistd::geteuid().is_root() {
        eyre::bail!("silod is a per-user daemon; run without sudo/root");
    }
    let host = libvm::HostPaths::from_env()?;
    // Validate the shared document before creating daemon state or service locks.
    let global = GlobalConfig::load_from(&host)?;
    let paths = SystemPaths::from_host(&host);
    let overrides =
        merge_system_overrides(global.daemon_overrides()?, args.system.into_overrides());
    let features = global.resolve_features(
        FeatureOverrides {
            system: args.system_enabled,
            tailscale: args.tailscale_enabled,
        },
        DaemonRecord::load(&paths)?.is_some(),
    );
    if args.check {
        return if features.system {
            desired_system(&paths, &overrides).map(drop)
        } else {
            Ok(())
        };
    }
    let _lock = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let mut status = supervisor::initial_status(&paths.docker_socket())?;
    if args.stop {
        return supervisor::stop_installation(&paths, status).await;
    }
    let desired = match desired_system(&paths, &overrides) {
        Ok(desired) => desired,
        Err(error) => {
            // Report a configuration the installation cannot accept to the
            // controller waiting on status, not only to stderr.
            supervisor::publish_failure(&paths, &mut status, &error)?;
            return Err(error);
        }
    };
    // Component startup is still appliance-only. Reject unsupported activation
    // instead of claiming that a disabled appliance or enabled helper is running.
    if !features.system || features.tailscale {
        let error = eyre::eyre!("this silod supports only the system appliance; the selected optional-component configuration requires a daemon with optional-component startup support");
        supervisor::publish_failure(&paths, &mut status, &error)?;
        return Err(error);
    }
    supervisor::serve(paths, desired, status).await
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
}

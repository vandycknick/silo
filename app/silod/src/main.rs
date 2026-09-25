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
    after_help = "Runs in the foreground. All --system-* options apply only to the system appliance; omitted ones take their defaults, except the backend and disk sizes, which keep the installation's values. silod follows the system image reference and upgrades the system VM in place when it changes. State is managed internally under ~/.silo. Use `silo daemon` for service management."
)]
struct Args {
    #[command(flatten)]
    system: SystemArgs,
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
    let paths = SystemPaths::from_env()?;
    let overrides = args.system.into_overrides();
    if args.check {
        return desired_system(&paths, &overrides).map(drop);
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
}

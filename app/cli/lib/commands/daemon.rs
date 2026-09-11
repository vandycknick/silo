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
                crate::system::service::down(&registration, &paths)
            }
            DaemonCommand::Serve(command) => run_registered(command.config).await,
            DaemonCommand::Status(command) => {
                let paths = crate::system::ownership::default_system_paths()?;
                let status = crate::system::service::status(&paths)?;
                match command.format {
                    crate::ui::OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&status)?)
                    }
                    crate::ui::OutputFormat::Plain => match status {
                        Some(status) => println!("{:?}\t{}", status.phase, status.docker_socket),
                        None => println!("stopped"),
                    },
                }
                Ok(())
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
        }
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
    }
}

use clap::{Args, Subcommand};

use crate::context::Context;

#[derive(Debug, Args)]
pub struct Cmd {
    #[command(subcommand)]
    command: DaemonCommand,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Up(Up),
    Status(Status),
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
struct Serve {
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

impl Cmd {
    pub(crate) async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            DaemonCommand::Up(command) => {
                if !command.foreground {
                    return Err(eyre::eyre!("native service mode is unavailable in this build; use `silo daemon up --foreground`"));
                }
                let _ = command.no_switch_context;
                run_foreground(context).await
            }
            DaemonCommand::Serve(command) => {
                if let Some(path) = command.config {
                    if !path.is_absolute() {
                        return Err(eyre::eyre!("registration config path must be absolute"));
                    }
                }
                run_foreground(context).await
            }
            DaemonCommand::Status(command) => {
                let paths = crate::system::ownership::default_system_paths()?;
                let status = crate::system::supervisor::read_status(&paths)?;
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
        }
    }
}

async fn run_foreground(context: &mut Context) -> eyre::Result<()> {
    let (paths, config) = context.resolved_system_config(None)?;
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
    }
}

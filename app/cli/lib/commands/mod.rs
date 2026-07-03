use clap::Subcommand;

use crate::context::Context;

pub mod cleanup;
pub mod create;
pub mod default;
pub mod exec;
pub mod list;
pub mod logs;
pub mod network;
pub mod profile;
pub mod restart;
pub mod rm;
mod rootfs_image;
pub mod run;
pub mod secret;
pub mod set;
pub mod shell;
pub mod show;
pub mod start;
mod start_options;
pub mod stop;

#[derive(Debug, Subcommand)]
pub enum Command {
    Run(run::Cmd),
    Create(create::Cmd),
    #[command(hide = true)]
    Cleanup(cleanup::Cmd),
    Start(start::Cmd),
    Stop(stop::Cmd),
    Restart(restart::Cmd),
    #[command(name = "default")]
    Default(default::Cmd),
    Secret(secret::Cmd),
    #[command(name = "rm")]
    Rm(rm::Cmd),
    Shell(shell::Cmd),
    Exec(exec::Cmd),
    #[command(visible_alias = "ls")]
    List(list::Cmd),
    #[command(visible_alias = "status")]
    Show(show::Cmd),
    Logs(logs::Cmd),
    Network(network::Cmd),
    Profile(profile::Cmd),
    Set(set::Cmd),
}

impl Command {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self {
            Self::Run(command) => command.run(context).await,
            Self::Create(command) => command.run(context).await,
            Self::Cleanup(command) => command.run(context).await,
            Self::Start(command) => command.run(context).await,
            Self::Stop(command) => command.run(context).await,
            Self::Restart(command) => command.run(context).await,
            Self::Default(command) => command.run(context).await,
            Self::Secret(command) => command.run(context).await,
            Self::Rm(command) => command.run(context).await,
            Self::Shell(command) => command.run(context).await,
            Self::Exec(command) => command.run(context).await,
            Self::List(command) => command.run(context).await,
            Self::Show(command) => command.run(context).await,
            Self::Logs(command) => command.run(context).await,
            Self::Network(command) => command.run(context).await,
            Self::Profile(command) => command.run(context).await,
            Self::Set(command) => command.run(context).await,
        }
    }
}

use clap::Subcommand;

use crate::context::Context;

pub mod cleanup;
pub mod cp;
pub mod create;
pub mod daemon;
pub mod default;
pub mod exec;
pub mod forward;
pub mod info;
pub mod list;
pub mod live;
pub mod logs;
pub mod network;
pub mod restart;
pub mod rm;
pub mod run;
pub mod secret;
pub mod set;
pub mod shell;
pub mod start;
pub mod stop;
pub mod system;
pub mod template;

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
    Daemon(daemon::Cmd),
    Secret(secret::Cmd),
    #[command(name = "rm")]
    Rm(rm::Cmd),
    Shell(shell::Cmd),
    Exec(exec::Cmd),
    Cp(cp::Cmd),
    Forward(forward::Cmd),
    #[command(visible_alias = "ls")]
    List(list::Cmd),
    Info(info::Cmd),
    System(system::Cmd),
    Pause(live::Pause),
    Snapshot(live::Snapshot),
    Fork(live::Fork),
    Restore(live::Restore),
    Image(live::Image),
    Logs(logs::Cmd),
    Network(network::Cmd),
    Template(template::Cmd),
    Set(set::Cmd),
}

impl Command {
    pub(crate) fn transport_admission(&self) -> silo_vm_control::transport::Admission {
        use silo_vm_control::transport::Admission;
        match self {
            Self::Pause(_) | Self::System(_) => Admission::Owned,
            Self::Snapshot(command) if command.is_live() => Admission::Owned,
            Self::Fork(command) if command.live => Admission::Owned,
            Self::Restore(command) if command.execution => Admission::Owned,
            _ => Admission::Ready,
        }
    }

    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self {
            Self::Run(command) => command.run(context).await,
            Self::Create(command) => command.run(context).await,
            Self::Cleanup(command) => command.run(context).await,
            Self::Start(command) => command.run(context).await,
            Self::Stop(command) => command.run(context).await,
            Self::Restart(command) => command.run(context).await,
            Self::Default(command) => command.run(context).await,
            Self::Daemon(command) => command.run(context).await,
            Self::Secret(command) => command.run(context).await,
            Self::Rm(command) => command.run(context).await,
            Self::Shell(command) => command.run(context).await,
            Self::Exec(command) => command.run(context).await,
            Self::Cp(command) => command.run(context).await,
            Self::Forward(command) => command.run(context).await,
            Self::List(command) => command.run(context).await,
            Self::Info(command) => command.run(context).await,
            Self::System(command) => command.run(context).await,
            Self::Pause(command) => command.run(context).await,
            Self::Snapshot(command) => command.run(context).await,
            Self::Fork(command) => command.run(context).await,
            Self::Restore(command) => command.run(context).await,
            Self::Image(command) => command.run(context).await,
            Self::Logs(command) => command.run(context).await,
            Self::Network(command) => command.run(context).await,
            Self::Template(command) => command.run(context).await,
            Self::Set(command) => command.run(context).await,
        }
    }
}

use bento_libvm::LibVm;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::fmt::{Display, Formatter};

use crate::constants::HELP_TEMPLATE;
use eyre::Context;

pub mod create;
pub mod exec;
pub mod images;
pub mod inspect;
pub mod list;
pub mod logs;
pub mod network;
pub mod profile;
pub mod restart;
pub mod rm;
pub mod run;
pub mod shell;
pub mod shell_proxy;
pub mod start;
pub mod status;
pub mod stop;

#[derive(Parser)]
#[command(
    about = "BentoBox VM lifecycle control",
    disable_help_subcommand = true
)]
pub struct BentoCtlCmd {
    /// Increase diagnostic output. Repeat for full error chains.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Run(run::Cmd),
    Create(create::Cmd),
    #[command(name = "new", hide = true)]
    New(create::Cmd),
    Start(start::Cmd),
    Stop(stop::Cmd),
    Restart(restart::Cmd),
    #[command(name = "rm")]
    Rm(rm::Cmd),
    Shell(shell::Cmd),
    Exec(exec::Cmd),
    #[command(visible_alias = "ls")]
    List(list::Cmd),
    Status(status::Cmd),
    Inspect(inspect::Cmd),
    Logs(logs::Cmd),
    Network(network::Cmd),
    Profile(profile::Cmd),
    #[command(name = "images", alias = "image")]
    Images(images::Cmd),
    #[command(hide = true)]
    ShellProxy(shell_proxy::Cmd),
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Create(cmd) => write!(f, "create {}", cmd),
            Command::Run(cmd) => write!(f, "run {}", cmd),
            Command::New(cmd) => write!(f, "new {}", cmd),
            Command::Start(cmd) => write!(f, "start {}", cmd),
            Command::Stop(cmd) => write!(f, "stop {}", cmd),
            Command::Restart(cmd) => write!(f, "restart {}", cmd),
            Command::Rm(cmd) => write!(f, "rm {}", cmd),
            Command::Shell(cmd) => write!(f, "shell {}", cmd),
            Command::Exec(cmd) => write!(f, "exec {}", cmd),
            Command::List(_) => write!(f, "list"),
            Command::Status(cmd) => write!(f, "status {}", cmd),
            Command::Inspect(cmd) => write!(f, "inspect {}", cmd),
            Command::Logs(cmd) => write!(f, "logs {}", cmd),
            Command::Network(cmd) => write!(f, "network {}", cmd),
            Command::Profile(cmd) => write!(f, "profile {}", cmd),
            Command::Images(cmd) => write!(f, "images {}", cmd),
            Command::ShellProxy(cmd) => write!(f, "shell-proxy {}", cmd),
        }
    }
}

impl BentoCtlCmd {
    pub fn parse() -> Self {
        let mut matches = Self::command().get_matches();
        Self::from_arg_matches_mut(&mut matches).unwrap_or_else(|err| err.exit())
    }

    fn command() -> clap::Command {
        apply_help_template(<Self as CommandFactory>::command())
    }

    pub async fn run(&self) -> eyre::Result<()> {
        self.invoke_sub_command().await
    }

    async fn invoke_sub_command(&self) -> eyre::Result<()> {
        match &self.cmd {
            Command::Run(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Create(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::New(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Start(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Stop(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Restart(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Rm(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Shell(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Exec(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::List(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Status(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Inspect(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Logs(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Network(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
            Command::Profile(cmd) => cmd.run().await,

            Command::Images(cmd) => cmd.run().await,
            Command::ShellProxy(cmd) => {
                let libvm = libvm()?;
                cmd.run(&libvm).await
            }
        }
    }
}

fn apply_help_template(command: clap::Command) -> clap::Command {
    command
        .styles(clap::builder::Styles::plain())
        .help_template(HELP_TEMPLATE)
        .mut_subcommands(apply_help_template)
}

fn libvm() -> eyre::Result<LibVm> {
    LibVm::from_env().context("initialize bento-libvm")
}

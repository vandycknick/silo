use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use libvm::{Machine, MachineRef, Runtime, RuntimeConfig};
use std::fmt::{Display, Formatter};

use crate::config::GlobalConfig;
use crate::constants::HELP_TEMPLATE;
use eyre::Context;

pub mod cleanup;
pub mod create;
pub mod default_machine;
pub mod edit;
pub mod exec;
pub mod list;
pub mod logs;
pub mod machine_view;
pub mod network;
pub mod output;
pub mod profile;
pub mod restart;
pub mod rm;
mod rootfs_image;
pub mod run;
pub mod secret;
pub mod set;
pub mod shell;
pub mod shell_proxy;
pub mod show;
pub mod start;
mod start_options;
pub mod stop;

#[derive(Parser)]
#[command(
    about = "BentoBox VM lifecycle control",
    disable_help_subcommand = true
)]
pub struct BentoCmd {
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
    #[command(hide = true)]
    Cleanup(cleanup::Cmd),
    Start(start::Cmd),
    Stop(stop::Cmd),
    Restart(restart::Cmd),
    #[command(name = "default")]
    Default(default_machine::Cmd),
    Secret(secret::Cmd),
    #[command(name = "rm")]
    Rm(rm::Cmd),
    Shell(shell::Cmd),
    Exec(exec::Cmd),
    #[command(hide = true)]
    Edit(edit::Cmd),
    #[command(visible_alias = "ls")]
    List(list::Cmd),
    #[command(visible_alias = "status")]
    Show(show::Cmd),
    Logs(logs::Cmd),
    Network(network::Cmd),
    Profile(profile::Cmd),
    Set(set::Cmd),
    #[command(hide = true)]
    ShellProxy(shell_proxy::Cmd),
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Create(cmd) => write!(f, "create {}", cmd),
            Command::Cleanup(cmd) => write!(f, "cleanup {}", cmd),
            Command::Run(cmd) => write!(f, "run {}", cmd),
            Command::Start(cmd) => write!(f, "start {}", cmd),
            Command::Stop(cmd) => write!(f, "stop {}", cmd),
            Command::Restart(cmd) => write!(f, "restart {}", cmd),
            Command::Default(cmd) => write!(f, "default {}", cmd),
            Command::Secret(cmd) => write!(f, "secret {}", cmd),
            Command::Rm(cmd) => write!(f, "rm {}", cmd),
            Command::Shell(cmd) => write!(f, "shell {}", cmd),
            Command::Exec(cmd) => write!(f, "exec {}", cmd),
            Command::Edit(cmd) => write!(f, "edit {}", cmd),
            Command::List(_) => write!(f, "list"),
            Command::Show(cmd) => write!(f, "show {}", cmd),
            Command::Logs(cmd) => write!(f, "logs {}", cmd),
            Command::Network(cmd) => write!(f, "network {}", cmd),
            Command::Profile(cmd) => write!(f, "profile {}", cmd),
            Command::Set(cmd) => write!(f, "set {}", cmd),
            Command::ShellProxy(cmd) => write!(f, "shell-proxy {}", cmd),
        }
    }
}

impl BentoCmd {
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
                let libvm = libvm().await?;
                cmd.run(&libvm).await
            }
            Command::Create(cmd) => {
                let libvm = libvm().await?;
                cmd.run(&libvm).await
            }
            Command::Cleanup(cmd) => {
                let global_config = GlobalConfig::load().context("load global config")?;
                let runtime_config = RuntimeConfig::local(&cmd.data_dir)
                    .with_networking(global_config.networking.clone());
                let libvm = Runtime::new(runtime_config)
                    .await
                    .context("initialize libvm")?;
                cmd.run(&libvm).await
            }
            Command::Start(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Stop(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Restart(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Default(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Secret(cmd) => cmd.run().await,
            Command::Rm(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Shell(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Exec(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Edit(cmd) => {
                let libvm = libvm().await?;
                cmd.run(&libvm).await
            }
            Command::List(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Show(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Logs(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::Network(cmd) => {
                let libvm = libvm().await?;
                cmd.run(&libvm).await
            }
            Command::Profile(cmd) => cmd.run().await,
            Command::Set(cmd) => {
                let context = command_context().await?;
                cmd.run(&context.libvm, &context.config).await
            }
            Command::ShellProxy(cmd) => {
                let libvm = libvm().await?;
                cmd.run(&libvm).await
            }
        }
    }
}

pub(crate) struct CommandContext {
    pub(crate) libvm: Runtime,
    pub(crate) config: GlobalConfig,
}

pub(crate) fn resolve_machine_name(
    name: Option<&str>,
    config: &GlobalConfig,
) -> eyre::Result<String> {
    if let Some(name) = name {
        return Ok(name.to_string());
    }

    config.default_machine().map(str::to_string).ok_or_else(|| {
        eyre::eyre!("no default machine configured\n\nhint: run `bento default <vm>` or pass a machine name")
    })
}

pub(crate) async fn get_machine(
    libvm: &Runtime,
    config: &GlobalConfig,
    name: Option<&str>,
) -> eyre::Result<(String, Machine)> {
    let resolved = resolve_machine_name(name, config)?;
    let machine_ref = MachineRef::parse(resolved.clone())?;
    let machine = libvm.get_machine(&machine_ref).await?;
    Ok((resolved, machine))
}

pub(crate) fn not_running_error(name: &str) -> eyre::Report {
    eyre::eyre!("{name} is not running\n\nhint: start it with `bento start {name}`")
}

fn apply_help_template(command: clap::Command) -> clap::Command {
    command
        .styles(clap::builder::Styles::plain())
        .help_template(HELP_TEMPLATE)
        .mut_subcommands(apply_help_template)
}

async fn libvm() -> eyre::Result<Runtime> {
    let global_config = GlobalConfig::load().context("load global config")?;
    libvm_with_config(&global_config).await
}

async fn command_context() -> eyre::Result<CommandContext> {
    let config = GlobalConfig::load().context("load global config")?;
    let libvm = libvm_with_config(&config).await?;
    Ok(CommandContext { libvm, config })
}

async fn libvm_with_config(global_config: &GlobalConfig) -> eyre::Result<Runtime> {
    let runtime_config = RuntimeConfig::from_env()
        .context("resolve libvm runtime config")?
        .with_networking(global_config.networking.clone());
    Runtime::new(runtime_config)
        .await
        .context("initialize libvm")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::{BentoCmd, Command};

    #[test]
    fn images_command_is_not_available() {
        assert!(BentoCmd::try_parse_from(["bento", "images", "list"]).is_err());
    }

    #[test]
    fn show_accepts_status_alias_and_json() {
        let status =
            BentoCmd::try_parse_from(["bento", "status", "dev", "--json"]).expect("status");
        let Command::Show(status) = status.cmd else {
            panic!("expected show command");
        };
        assert_eq!(status.name.as_deref(), Some("dev"));
        assert!(status.json);

        assert!(BentoCmd::try_parse_from(["bento", "inspect", "dev"]).is_err());

        let show = BentoCmd::try_parse_from(["bento", "show", "dev"]).expect("show");
        assert!(matches!(show.cmd, Command::Show(_)));
    }

    #[test]
    fn default_command_parses_set_show_and_unset_forms() {
        let set = BentoCmd::try_parse_from(["bento", "default", "dev"]).expect("default set");
        let Command::Default(set) = set.cmd else {
            panic!("expected default command");
        };
        assert_eq!(set.name.as_deref(), Some("dev"));
        assert!(!set.unset);

        let show = BentoCmd::try_parse_from(["bento", "default"]).expect("default show");
        let Command::Default(show) = show.cmd else {
            panic!("expected default command");
        };
        assert_eq!(show.name, None);
        assert!(!show.unset);

        let unset =
            BentoCmd::try_parse_from(["bento", "default", "--unset"]).expect("default unset");
        let Command::Default(unset) = unset.cmd else {
            panic!("expected default command");
        };
        assert_eq!(unset.name, None);
        assert!(unset.unset);
    }

    #[test]
    fn set_command_parses_default_and_named_machine_forms() {
        let default =
            BentoCmd::try_parse_from(["bento", "set", "cpus=4", "memory=8G"]).expect("set");
        let Command::Set(default) = default.cmd else {
            panic!("expected set command");
        };
        assert_eq!(
            default.args,
            vec!["cpus=4".to_string(), "memory=8G".to_string()]
        );

        let named = BentoCmd::try_parse_from(["bento", "set", "dev", "disk=64G"]).expect("set");
        let Command::Set(named) = named.cmd else {
            panic!("expected set command");
        };
        assert_eq!(named.args, vec!["dev".to_string(), "disk=64G".to_string()]);
    }

    #[test]
    fn edit_command_is_hidden_from_help() {
        let mut command = BentoCmd::command();
        let help = command.render_long_help().to_string();

        assert!(!help.contains("edit"));
        assert!(BentoCmd::try_parse_from(["bento", "edit", "dev"]).is_ok());
    }

    #[test]
    fn cleanup_command_is_hidden_from_help() {
        let mut command = BentoCmd::command();
        let help = command.render_long_help().to_string();

        assert!(!help.contains("cleanup"));
        let parsed = BentoCmd::try_parse_from([
            "bento",
            "cleanup",
            "--data-dir",
            "/tmp/bento",
            "--machine-id",
            "0123456789abcdef0123456789abcdef",
        ])
        .expect("cleanup command");
        let Command::Cleanup(cleanup) = parsed.cmd else {
            panic!("expected cleanup command");
        };
        assert_eq!(cleanup.data_dir, std::path::PathBuf::from("/tmp/bento"));
        assert_eq!(cleanup.machine_id, "0123456789abcdef0123456789abcdef");
    }
}

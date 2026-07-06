use clap::{Args, Subcommand};
use libvm::{MachineRef, NetworkDriver, NetworkTopology};

use crate::context::Context;
use crate::network_policy::resolve_network_policy_source;
use crate::profile::{MachineNetworkSelection, ResolvedMachineNetwork};
use crate::ui::{self, OutputFormat, Table};

const EXAMPLES: &[&str] = &[
    "silo network list",
    "silo network create devnet --topology nat",
    "silo network set devbox devnet",
    "silo network show devnet",
    "silo network rm devnet",
];

#[derive(Debug, Args)]
#[command(
    about = "Manage named VM networks",
    after_help = crate::help::examples(EXAMPLES)
)]
pub struct Cmd {
    #[command(subcommand)]
    command: NetworkSubcommand,
}

#[derive(Debug, Subcommand)]
enum NetworkSubcommand {
    #[command(about = "List named networks", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Show a named network")]
    Show(ShowCmd),
    #[command(about = "Create or update a named network")]
    Create(CreateCmd),
    #[command(name = "rm", about = "Remove a named network")]
    Rm(RmCmd),
    #[command(about = "Set a VM's network config")]
    Set(Box<SetCmd>),
}

#[derive(Debug, Args)]
struct ListCmd {
    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct ShowCmd {
    /// Network name to show.
    #[arg(value_name = "NETWORK")]
    name: String,

    /// Output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
struct CreateCmd {
    /// Network name to create or update.
    #[arg(value_name = "NETWORK")]
    name: String,

    /// Network topology. Allowed: nat, bridge, isolated.
    #[arg(long, value_parser = parse_network_topology, default_value = "nat")]
    topology: NetworkTopology,

    /// Network driver. Allowed: auto, netd, vznat.
    #[arg(long, value_parser = parse_driver, default_value = "auto")]
    driver: NetworkDriver,
}

#[derive(Debug, Args)]
struct RmCmd {
    /// Network name to remove.
    #[arg(value_name = "NETWORK")]
    name: String,

    /// Remove without prompting.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct SetCmd {
    /// Name or ID of the VM to update.
    #[arg(value_name = "VM")]
    vm: String,

    /// Network to use. Allowed: private, none, name:NETWORK, or NETWORK.
    #[arg(value_name = "NETWORK", value_parser = parse_machine_network_config)]
    network: MachineNetworkSelection,

    /// Network policy to apply to private networks.
    #[arg(long, value_name = "POLICY")]
    policy: Option<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            NetworkSubcommand::List(command) => list_networks(context, command).await,
            NetworkSubcommand::Show(command) => show_network(context, command).await,
            NetworkSubcommand::Create(command) => create_network(context, command).await,
            NetworkSubcommand::Rm(command) => remove_network(context, command).await,
            NetworkSubcommand::Set(command) => set_machine_network(context, *command).await,
        }
    }
}

async fn list_networks(context: &mut Context, command: ListCmd) -> eyre::Result<()> {
    let definitions = context.runtime().await?.list_network_definitions().await?;
    match command.format {
        OutputFormat::Json => ui::print_json(&definitions),
        OutputFormat::Plain => {
            let mut table = Table::new(["NAME", "TOPOLOGY", "DRIVER"]);
            for definition in definitions {
                table.add_row([
                    definition.name,
                    format_network_topology(definition.topology).to_string(),
                    format_driver(definition.driver).to_string(),
                ]);
            }
            table.print()
        }
    }
}

async fn show_network(context: &mut Context, command: ShowCmd) -> eyre::Result<()> {
    let definition = context
        .runtime()
        .await?
        .get_network_definition(&command.name)
        .await?
        .ok_or_else(|| eyre::eyre!("network `{}` not found", command.name))?;

    match command.format {
        OutputFormat::Json => ui::print_json(&definition),
        OutputFormat::Plain => ui::print_detail_rows(&[
            ("name", definition.name),
            (
                "topology",
                format_network_topology(definition.topology).to_string(),
            ),
            ("driver", format_driver(definition.driver).to_string()),
        ]),
    }
}

async fn create_network(context: &mut Context, command: CreateCmd) -> eyre::Result<()> {
    context
        .runtime()
        .await?
        .network(command.name.clone())
        .topology(command.topology)
        .driver(command.driver)
        .create()
        .await?;
    ui::success(format!("created {}", command.name));
    Ok(())
}

async fn remove_network(context: &mut Context, command: RmCmd) -> eyre::Result<()> {
    if !command.force {
        eyre::bail!(
            "refusing to remove network `{}` without --force",
            command.name
        );
    }
    let runtime = context.runtime().await?;
    if runtime
        .get_network_definition(&command.name)
        .await?
        .is_none()
    {
        eyre::bail!("network `{}` not found", command.name);
    }
    runtime.remove_network_definition(&command.name).await?;
    ui::success(format!("removed {}", command.name));
    Ok(())
}

async fn set_machine_network(context: &mut Context, command: SetCmd) -> eyre::Result<()> {
    let policy_config_dir = context.config()?.networking.policy_config_dir.clone();
    let network = machine_network_with_policy(
        command.network,
        command.policy.as_deref(),
        policy_config_dir.as_deref(),
    )?;
    let runtime = context.runtime().await?;
    let machine = runtime
        .get_machine(&MachineRef::parse(command.vm.clone())?)
        .await?;
    let data = machine
        .set_network(|builder| network.apply(builder))
        .await?;
    ui::success(format!(
        "network for {} set to {}",
        data.name,
        data.network.name()
    ));
    if data.is_running() {
        ui::warn("change applies on next restart");
    }
    Ok(())
}

fn machine_network_with_policy(
    network: MachineNetworkSelection,
    policy_source: Option<&str>,
    policy_config_dir: Option<&std::path::Path>,
) -> eyre::Result<ResolvedMachineNetwork> {
    match (network, policy_source) {
        (MachineNetworkSelection::Private, Some(source)) => {
            let policy = resolve_network_policy_source(source, policy_config_dir)?;
            Ok(ResolvedMachineNetwork::Private {
                policy: Some(policy),
            })
        }
        (MachineNetworkSelection::Private, None) => {
            Ok(ResolvedMachineNetwork::Private { policy: None })
        }
        (network, None) => Ok(network.into()),
        (_, Some(_)) => eyre::bail!("--policy is only supported with private networks"),
    }
}

fn parse_machine_network_config(input: &str) -> Result<MachineNetworkSelection, String> {
    MachineNetworkSelection::parse(input)
}

fn parse_network_topology(input: &str) -> Result<NetworkTopology, String> {
    match input {
        "nat" => Ok(NetworkTopology::Nat),
        "bridge" => Ok(NetworkTopology::Bridge),
        "isolated" => Ok(NetworkTopology::Isolated),
        other => Err(format!(
            "invalid network topology '{other}', expected nat, bridge, or isolated"
        )),
    }
}

fn parse_driver(input: &str) -> Result<NetworkDriver, String> {
    match input {
        "auto" => Ok(NetworkDriver::Auto),
        "netd" => Ok(NetworkDriver::Netd),
        "vznat" => Ok(NetworkDriver::VzNat),
        other => Err(format!(
            "invalid network driver '{other}', expected auto, netd, or vznat"
        )),
    }
}

fn format_network_topology(topology: NetworkTopology) -> &'static str {
    match topology {
        NetworkTopology::Nat => "nat",
        NetworkTopology::Bridge => "bridge",
        NetworkTopology::Isolated => "isolated",
        _ => "unknown",
    }
}

fn format_driver(driver: NetworkDriver) -> &'static str {
    match driver {
        NetworkDriver::Auto => "auto",
        NetworkDriver::Netd => "netd",
        NetworkDriver::VzNat => "vznat",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::app::Cli;
    use crate::commands::Command;
    use crate::profile::{MachineNetworkSelection, ResolvedMachineNetwork};
    use clap::Parser;

    use super::{machine_network_with_policy, NetworkSubcommand};

    #[test]
    fn network_ls_alias_parses_as_network_list() {
        let cli = Cli::try_parse_from(["silo", "network", "ls", "--format", "json"])
            .expect("network ls alias should parse");

        let Command::Network(network) = cli.command else {
            panic!("expected network command");
        };
        let NetworkSubcommand::List(list) = network.command else {
            panic!("expected network list command");
        };

        assert_eq!(list.format, crate::ui::OutputFormat::Json);
    }

    #[test]
    fn network_set_parses_private_policy_name() {
        let set = network_set_cmd([
            "silo", "network", "set", "devbox", "private", "--policy", "github",
        ]);

        assert_eq!(set.vm, "devbox");
        assert_eq!(set.network, MachineNetworkSelection::Private);
        assert_eq!(set.policy.expect("policy").as_str(), "github");
    }

    #[test]
    fn machine_network_policy_applies_to_private_network() {
        let policy_dir = write_named_policy("github");
        let network = machine_network_with_policy(
            MachineNetworkSelection::Private,
            Some("github"),
            Some(policy_dir.path()),
        )
        .expect("policy should apply");

        let ResolvedMachineNetwork::Private { policy } = network else {
            panic!("expected private network");
        };
        assert_eq!(policy.expect("policy").metadata()["source"], "test");
    }

    #[test]
    fn machine_network_policy_rejects_none_network() {
        let err = machine_network_with_policy(MachineNetworkSelection::None, Some("github"), None)
            .expect_err("policy should be rejected");

        assert_eq!(
            err.to_string(),
            "--policy is only supported with private networks"
        );
    }

    #[test]
    fn machine_network_policy_rejects_relative_path() {
        let err = machine_network_with_policy(
            MachineNetworkSelection::Private,
            Some("policies/github.hcl"),
            None,
        )
        .expect_err("relative path should fail");

        assert!(err.to_string().contains("relative network policy paths"));
    }

    fn network_set_cmd(args: impl IntoIterator<Item = &'static str>) -> super::SetCmd {
        let cli = Cli::try_parse_from(args).expect("network set should parse");
        let Command::Network(network) = cli.command else {
            panic!("expected network command");
        };
        let NetworkSubcommand::Set(set) = network.command else {
            panic!("expected network set command");
        };
        *set
    }

    fn write_named_policy(name: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let policies = dir.path().join("policies");
        fs::create_dir(&policies).expect("create policies dir");
        fs::write(
            policies.join(format!("{name}.json")),
            r#"{ "version": 1, "metadata": { "source": "test" } }"#,
        )
        .expect("write policy");
        dir
    }
}

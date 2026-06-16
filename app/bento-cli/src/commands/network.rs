use std::fmt::{Display, Formatter};
use std::io::Write;

use bento_libvm::{
    MachineNetworkConfig, MachineRef, NetworkDefinition, NetworkDriverPreference, NetworkPolicyRef,
    NetworkTopology, Runtime,
};
use clap::{Args, Subcommand};
use tabwriter::TabWriter;

use crate::commands::profile::parse_machine_network_config;

#[derive(Args, Debug)]
#[command(
    about = "Manage named VM networks",
    after_help = "Examples:\n  bento network list\n  bento network create devnet --topology nat\n  bento network set devbox devnet\n  bento network show devnet\n  bento network rm devnet\n"
)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: NetworkSubcommand,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "network")
    }
}

#[derive(Subcommand, Debug)]
pub enum NetworkSubcommand {
    #[command(about = "List named networks", visible_alias = "ls")]
    List(ListCmd),
    #[command(about = "Show a named network")]
    Show(ShowCmd),
    #[command(about = "Create or update a named network")]
    Create(CreateCmd),
    #[command(name = "rm", about = "Remove a named network")]
    Rm(RmCmd),
    #[command(about = "Set a VM's network config")]
    Set(SetCmd),
}

#[derive(Args, Debug)]
pub struct ListCmd {
    /// Output named networks as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ShowCmd {
    /// Network name to show.
    #[arg(value_name = "NETWORK")]
    pub name: String,
    /// Output the network definition as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CreateCmd {
    /// Network name to create or update.
    #[arg(value_name = "NETWORK")]
    pub name: String,
    /// Network topology. Allowed: nat, bridge, isolated.
    #[arg(long, value_parser = parse_network_topology, default_value = "nat")]
    pub topology: NetworkTopology,
    /// Driver preference. Allowed: auto, netd, vznat.
    #[arg(long, value_parser = parse_driver_preference, default_value = "auto")]
    pub driver: NetworkDriverPreference,
}

#[derive(Args, Debug)]
pub struct RmCmd {
    /// Network name to remove.
    #[arg(value_name = "NETWORK")]
    pub name: String,
    /// Remove without prompting.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct SetCmd {
    /// Name or ID of the VM to update.
    #[arg(value_name = "VM")]
    pub vm: String,
    /// Network to use. Allowed: private, none, name:NETWORK, or NETWORK.
    #[arg(value_name = "NETWORK", value_parser = parse_machine_network_config)]
    pub network: MachineNetworkConfig,
    /// Network policy to apply to private networks.
    #[arg(long, value_name = "POLICY", value_parser = parse_network_policy_ref)]
    pub policy: Option<NetworkPolicyRef>,
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        match &self.command {
            NetworkSubcommand::List(cmd) => list_networks(libvm, cmd).await,
            NetworkSubcommand::Show(cmd) => show_network(libvm, cmd).await,
            NetworkSubcommand::Create(cmd) => create_network(libvm, cmd).await,
            NetworkSubcommand::Rm(cmd) => remove_network(libvm, cmd).await,
            NetworkSubcommand::Set(cmd) => set_machine_network(libvm, cmd).await,
        }
    }
}

async fn list_networks(libvm: &Runtime, cmd: &ListCmd) -> eyre::Result<()> {
    let definitions = libvm.list_network_definitions().await?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&definitions)?);
        return Ok(());
    }

    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "NAME\tTOPOLOGY\tDRIVER")?;
    for definition in definitions {
        writeln!(
            &mut out,
            "{}\t{}\t{}",
            definition.name,
            format_network_topology(definition.topology),
            format_driver_preference(definition.driver_preference),
        )?;
    }
    out.flush()?;
    Ok(())
}

async fn show_network(libvm: &Runtime, cmd: &ShowCmd) -> eyre::Result<()> {
    let definition = libvm
        .get_network_definition(&cmd.name)
        .await?
        .ok_or_else(|| eyre::eyre!("network `{}` not found", cmd.name))?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&definition)?);
    } else {
        println!("{}", serde_yaml_ng::to_string(&definition)?);
    }
    Ok(())
}

async fn create_network(libvm: &Runtime, cmd: &CreateCmd) -> eyre::Result<()> {
    let definition = NetworkDefinition {
        name: cmd.name.clone(),
        topology: cmd.topology,
        driver_preference: cmd.driver,
    };
    libvm.create_network_definition(definition).await?;
    println!("created {}", cmd.name);
    Ok(())
}

async fn remove_network(libvm: &Runtime, cmd: &RmCmd) -> eyre::Result<()> {
    if !cmd.force {
        eyre::bail!("refusing to remove network `{}` without --force", cmd.name);
    }
    if libvm.get_network_definition(&cmd.name).await?.is_none() {
        eyre::bail!("network `{}` not found", cmd.name);
    }
    libvm.remove_network_definition(&cmd.name).await?;
    println!("removed {}", cmd.name);
    Ok(())
}

async fn set_machine_network(libvm: &Runtime, cmd: &SetCmd) -> eyre::Result<()> {
    let network = machine_network_with_policy(cmd.network.clone(), cmd.policy.clone())?;
    let machine = libvm
        .get_machine(&MachineRef::parse(cmd.vm.clone())?)
        .await?;
    let inspect_data = machine.set_network(network).await?;
    println!(
        "network for {} set to {}",
        inspect_data.name,
        inspect_data.network.name()
    );
    if inspect_data.is_running() {
        println!("change applies on next restart");
    }
    Ok(())
}

fn machine_network_with_policy(
    network: MachineNetworkConfig,
    policy_ref: Option<NetworkPolicyRef>,
) -> eyre::Result<MachineNetworkConfig> {
    match (network, policy_ref) {
        (MachineNetworkConfig::Private { .. }, policy_ref) => {
            Ok(MachineNetworkConfig::Private { policy_ref })
        }
        (network @ (MachineNetworkConfig::None | MachineNetworkConfig::Named { .. }), None) => {
            Ok(network)
        }
        (MachineNetworkConfig::None | MachineNetworkConfig::Named { .. }, Some(_)) => {
            eyre::bail!("--policy is only supported with private networks")
        }
    }
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

fn parse_driver_preference(input: &str) -> Result<NetworkDriverPreference, String> {
    match input {
        "auto" => Ok(NetworkDriverPreference::Auto),
        "netd" => Ok(NetworkDriverPreference::Netd),
        "vznat" => Ok(NetworkDriverPreference::VzNat),
        other => Err(format!(
            "invalid driver preference '{other}', expected auto, netd, or vznat"
        )),
    }
}

fn parse_network_policy_ref(input: &str) -> Result<NetworkPolicyRef, String> {
    NetworkPolicyRef::new(input)
}

fn format_network_topology(topology: NetworkTopology) -> &'static str {
    match topology {
        NetworkTopology::Nat => "nat",
        NetworkTopology::Bridge => "bridge",
        NetworkTopology::Isolated => "isolated",
    }
}

fn format_driver_preference(preference: NetworkDriverPreference) -> &'static str {
    match preference {
        NetworkDriverPreference::Auto => "auto",
        NetworkDriverPreference::Netd => "netd",
        NetworkDriverPreference::VzNat => "vznat",
    }
}

#[cfg(test)]
mod tests {
    use bento_libvm::{MachineNetworkConfig, NetworkPolicyRef};
    use clap::Parser;

    use crate::commands::{BentoCmd, Command};

    use super::{machine_network_with_policy, NetworkSubcommand};

    #[test]
    fn network_ls_alias_parses_as_network_list() {
        let cmd = BentoCmd::try_parse_from(["bento", "network", "ls", "--json"])
            .expect("network ls alias should parse");

        let network = match cmd.cmd {
            Command::Network(cmd) => cmd,
            other => panic!("expected network command, got {other:?}"),
        };

        let list = match network.command {
            NetworkSubcommand::List(cmd) => cmd,
            other => panic!("expected network list command, got {other:?}"),
        };

        assert!(list.json);
    }

    #[test]
    fn network_set_parses_private_policy_name() {
        let cmd = BentoCmd::try_parse_from([
            "bento", "network", "set", "devbox", "private", "--policy", "github",
        ])
        .expect("network set should parse");

        let set = network_set_cmd(cmd);
        assert_eq!(set.vm, "devbox");
        assert_eq!(
            set.network,
            MachineNetworkConfig::Private { policy_ref: None }
        );
        assert_eq!(set.policy.expect("policy").as_str(), "github");
    }

    #[test]
    fn network_set_parses_private_absolute_policy_path() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
            "network",
            "set",
            "devbox",
            "private",
            "--policy",
            "/etc/bento/policy.hcl",
        ])
        .expect("network set should parse");

        let set = network_set_cmd(cmd);
        assert_eq!(
            set.policy.expect("policy").as_str(),
            "/etc/bento/policy.hcl"
        );
    }

    #[test]
    fn network_set_rejects_invalid_policy_ref() {
        let result = BentoCmd::try_parse_from([
            "bento",
            "network",
            "set",
            "devbox",
            "private",
            "--policy",
            "policies/github.hcl",
        ]);

        let err = match result {
            Ok(_) => panic!("relative policy paths should be rejected"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("relative network policy paths"));
    }

    #[test]
    fn network_set_parses_none_with_policy_for_command_validation() {
        let cmd = BentoCmd::try_parse_from([
            "bento", "network", "set", "devbox", "none", "--policy", "github",
        ])
        .expect("network set should parse");

        let set = network_set_cmd(cmd);
        assert_eq!(set.network, MachineNetworkConfig::None);
        assert_eq!(set.policy.expect("policy").as_str(), "github");
    }

    #[test]
    fn network_set_parses_named_with_policy_for_command_validation() {
        let cmd = BentoCmd::try_parse_from([
            "bento", "network", "set", "devbox", "devnet", "--policy", "github",
        ])
        .expect("network set should parse");

        let set = network_set_cmd(cmd);
        assert_eq!(
            set.network,
            MachineNetworkConfig::Named {
                name: "devnet".to_string(),
            }
        );
        assert_eq!(set.policy.expect("policy").as_str(), "github");
    }

    #[test]
    fn machine_network_policy_applies_to_private_network() {
        let policy_ref = NetworkPolicyRef::new("github").expect("policy ref");

        let network = machine_network_with_policy(
            MachineNetworkConfig::Private { policy_ref: None },
            Some(policy_ref.clone()),
        )
        .expect("policy should apply");

        assert_eq!(
            network,
            MachineNetworkConfig::Private {
                policy_ref: Some(policy_ref),
            }
        );
    }

    #[test]
    fn machine_network_policy_rejects_none_network() {
        let policy_ref = NetworkPolicyRef::new("github").expect("policy ref");

        let err = machine_network_with_policy(MachineNetworkConfig::None, Some(policy_ref))
            .expect_err("policy should be rejected");

        assert_eq!(
            err.to_string(),
            "--policy is only supported with private networks"
        );
    }

    #[test]
    fn machine_network_policy_rejects_named_network() {
        let policy_ref = NetworkPolicyRef::new("github").expect("policy ref");

        let err = machine_network_with_policy(
            MachineNetworkConfig::Named {
                name: "devnet".to_string(),
            },
            Some(policy_ref),
        )
        .expect_err("policy should be rejected");

        assert_eq!(
            err.to_string(),
            "--policy is only supported with private networks"
        );
    }

    fn network_set_cmd(cmd: BentoCmd) -> super::SetCmd {
        let network = match cmd.cmd {
            Command::Network(cmd) => cmd,
            other => panic!("expected network command, got {other:?}"),
        };

        match network.command {
            NetworkSubcommand::Set(cmd) => cmd,
            other => panic!("expected network set command, got {other:?}"),
        }
    }
}

use std::fmt::{Display, Formatter};
use std::io::Write;

use bento_libvm::{
    LibVm, MachineRef, NamedNetworkMode, NetworkDefinitionSpec, NetworkDriverPreference,
    RequestedNetwork,
};
use clap::{Args, Subcommand};
use tabwriter::TabWriter;

use crate::commands::profile::parse_requested_network;

#[derive(Args, Debug)]
#[command(
    about = "Manage named VM networks",
    after_help = "Examples:\n  bento network list\n  bento network create devnet --mode nat\n  bento network set devbox devnet\n  bento network show devnet\n  bento network rm devnet\n"
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
    #[command(about = "Set a VM's network mode")]
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
    /// Network mode. Allowed: nat, bridge, isolated.
    #[arg(long, value_parser = parse_network_mode, default_value = "nat")]
    pub mode: NamedNetworkMode,
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
    #[arg(value_name = "NETWORK", value_parser = parse_requested_network)]
    pub network: RequestedNetwork,
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        match &self.command {
            NetworkSubcommand::List(cmd) => list_networks(libvm, cmd),
            NetworkSubcommand::Show(cmd) => show_network(libvm, cmd),
            NetworkSubcommand::Create(cmd) => create_network(libvm, cmd),
            NetworkSubcommand::Rm(cmd) => remove_network(libvm, cmd),
            NetworkSubcommand::Set(cmd) => set_machine_network(libvm, cmd),
        }
    }
}

fn list_networks(libvm: &LibVm, cmd: &ListCmd) -> eyre::Result<()> {
    let definitions = libvm.list_network_definitions()?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&definitions)?);
        return Ok(());
    }

    let mut out = TabWriter::new(std::io::stdout()).padding(2);
    writeln!(&mut out, "NAME\tMODE\tDRIVER")?;
    for definition in definitions {
        writeln!(
            &mut out,
            "{}\t{}\t{}",
            definition.name,
            format_network_mode(definition.mode),
            format_driver_preference(definition.driver_preference),
        )?;
    }
    out.flush()?;
    Ok(())
}

fn show_network(libvm: &LibVm, cmd: &ShowCmd) -> eyre::Result<()> {
    let definition = libvm
        .get_network_definition(&cmd.name)?
        .ok_or_else(|| eyre::eyre!("network `{}` not found", cmd.name))?;
    if cmd.json {
        println!("{}", serde_json::to_string_pretty(&definition)?);
    } else {
        println!("{}", serde_yaml_ng::to_string(&definition)?);
    }
    Ok(())
}

fn create_network(libvm: &LibVm, cmd: &CreateCmd) -> eyre::Result<()> {
    let definition = NetworkDefinitionSpec {
        name: cmd.name.clone(),
        mode: cmd.mode,
        driver_preference: cmd.driver,
    };
    libvm.create_network_definition(definition)?;
    println!("created {}", cmd.name);
    Ok(())
}

fn remove_network(libvm: &LibVm, cmd: &RmCmd) -> eyre::Result<()> {
    if !cmd.force {
        eyre::bail!("refusing to remove network `{}` without --force", cmd.name);
    }
    if libvm.get_network_definition(&cmd.name)?.is_none() {
        eyre::bail!("network `{}` not found", cmd.name);
    }
    libvm.remove_network_definition(&cmd.name)?;
    println!("removed {}", cmd.name);
    Ok(())
}

fn set_machine_network(libvm: &LibVm, cmd: &SetCmd) -> eyre::Result<()> {
    let machine = libvm.set_network(&MachineRef::parse(cmd.vm.clone())?, cmd.network.clone())?;
    println!(
        "network for {} set to {}",
        machine.spec.name,
        machine.network.name()
    );
    if machine.status.is_running() {
        println!("change applies on next restart");
    }
    Ok(())
}

fn parse_network_mode(input: &str) -> Result<NamedNetworkMode, String> {
    match input {
        "nat" => Ok(NamedNetworkMode::Nat),
        "bridge" => Ok(NamedNetworkMode::Bridge),
        "isolated" => Ok(NamedNetworkMode::Isolated),
        other => Err(format!(
            "invalid network mode '{other}', expected nat, bridge, or isolated"
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

fn format_network_mode(mode: NamedNetworkMode) -> &'static str {
    match mode {
        NamedNetworkMode::Nat => "nat",
        NamedNetworkMode::Bridge => "bridge",
        NamedNetworkMode::Isolated => "isolated",
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
    use clap::Parser;

    use crate::commands::{BentoCtlCmd, Command};

    use super::NetworkSubcommand;

    #[test]
    fn network_ls_alias_parses_as_network_list() {
        let cmd = BentoCtlCmd::try_parse_from(["bento", "network", "ls", "--json"])
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
}

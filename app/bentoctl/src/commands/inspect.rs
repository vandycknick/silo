use std::fmt::{Display, Formatter};

use bento_libvm::{LibVm, MachineRef};
use clap::Args;
use serde_json::json;

use crate::constants::PROFILE_METADATA_KEY;

#[derive(Args, Debug)]
#[command(about = "Show full VM details")]
pub struct Cmd {
    /// Name or ID of the VM to inspect.
    #[arg(value_name = "VM")]
    pub name: String,
    /// Output full details as JSON.
    #[arg(long)]
    pub json: bool,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let machine = libvm.inspect(&MachineRef::parse(self.name.clone())?)?;
        let state = if machine.status.is_running() {
            "running"
        } else {
            "stopped"
        };
        let network = match machine.spec.network.driver {
            bento_core::NetworkDriver::Gvisor => "isolated",
            bento_core::NetworkDriver::None => "none",
            bento_core::NetworkDriver::VzNat => "vznat",
        };
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "id": machine.id.to_string(),
                    "name": machine.spec.name,
                    "state": state,
                    "profile": machine.metadata.get(PROFILE_METADATA_KEY),
                    "image": machine.image_ref,
                    "labels": machine.labels,
                    "metadata": machine.metadata,
                    "network": network,
                    "created_at": machine.created_at,
                    "dir": machine.dir,
                    "spec": machine.spec,
                }))?
            );
            return Ok(());
        }
        println!("id: {}", machine.id);
        println!("name: {}", machine.spec.name);
        println!("state: {state}");
        if let Some(profile) = machine.metadata.get(PROFILE_METADATA_KEY) {
            println!("profile: {profile}");
        }
        if !machine.image_ref.is_empty() {
            println!("image: {}", machine.image_ref);
        }
        println!("network: {network}");
        if !machine.labels.is_empty() {
            println!("labels:");
            for (key, value) in machine.labels {
                println!("  {key}: {value}");
            }
        }
        println!("dir: {}", machine.dir.display());
        Ok(())
    }
}

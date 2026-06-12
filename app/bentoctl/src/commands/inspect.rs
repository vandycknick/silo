use std::fmt::{Display, Formatter};

use bento_libvm::{MachineRef, Runtime};
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
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let machine = libvm
            .get_machine(&MachineRef::parse(self.name.clone())?)
            .await?;
        let inspection = machine.inspect().await?;
        let state = if inspection.is_running() {
            "running"
        } else {
            "stopped"
        };
        let network = inspection.network();
        let network_name = network.name();
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "id": inspection.id(),
                    "name": inspection.name(),
                    "state": state,
                    "profile": inspection.metadata().get(PROFILE_METADATA_KEY).cloned(),
                    "image": inspection.image_ref(),
                    "labels": inspection.labels(),
                    "metadata": inspection.metadata(),
                    "network": network,
                    "created_at": inspection.created_at(),
                    "dir": inspection.instance_dir(),
                    "spec": inspection.spec(),
                }))?
            );
            return Ok(());
        }
        println!("id: {}", inspection.id());
        println!("name: {}", inspection.name());
        println!("state: {state}");
        if let Some(profile) = inspection.metadata().get(PROFILE_METADATA_KEY) {
            println!("profile: {profile}");
        }
        if !inspection.image_ref().is_empty() {
            println!("image: {}", inspection.image_ref());
        }
        println!("network: {network_name}");
        if !inspection.labels().is_empty() {
            println!("labels:");
            for (key, value) in inspection.labels() {
                println!("  {key}: {value}");
            }
        }
        println!("dir: {}", inspection.instance_dir().display());
        Ok(())
    }
}

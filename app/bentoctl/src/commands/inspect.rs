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
        let config = inspection.config;
        let state = inspection.state;
        let state = if state.status.is_running() {
            "running"
        } else {
            "stopped"
        };
        let network_name = config.network.name();
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "id": config.id.to_string(),
                    "name": &config.name,
                    "state": state,
                    "profile": config.metadata.get(PROFILE_METADATA_KEY).cloned(),
                    "image": &config.image_ref,
                    "labels": &config.labels,
                    "metadata": &config.metadata,
                    "network": &config.network,
                    "created_at": config.created_at,
                    "dir": &config.instance_dir,
                    "spec": &config.spec,
                }))?
            );
            return Ok(());
        }
        println!("id: {}", config.id);
        println!("name: {}", config.name);
        println!("state: {state}");
        if let Some(profile) = config.metadata.get(PROFILE_METADATA_KEY) {
            println!("profile: {profile}");
        }
        if !config.image_ref.is_empty() {
            println!("image: {}", config.image_ref);
        }
        println!("network: {network_name}");
        if !config.labels.is_empty() {
            println!("labels:");
            for (key, value) in config.labels {
                println!("  {key}: {value}");
            }
        }
        println!("dir: {}", config.instance_dir.display());
        Ok(())
    }
}

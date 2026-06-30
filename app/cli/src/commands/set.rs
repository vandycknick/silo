use std::fmt::{Display, Formatter};

use clap::Args;
use libvm::{MachineUpdate, Memory, Runtime};
use utils::HumanSize;

use crate::commands::get_machine;
use crate::commands::profile::parse_machine_network_config;
use crate::config::GlobalConfig;

#[derive(Args, Debug)]
#[command(
    about = "Update stopped VM settings",
    after_help = "Settings:\n  name=NAME                         Rename the VM\n  cpus=N                            Set the virtual CPU count\n  memory=SIZE                       Set RAM size\n  disk=SIZE                         Set desired root disk size\n  network=private|none|NAME|name:NAME\n                                    Set the network target\n  nested-virtualization=true|false  Enable or disable nested virtualization\n  rosetta=true|false                Enable or disable Rosetta\n\nSize units:\n  m, mb, mib are stored as MiB; g, gb, gib are stored as GiB.\n\nExamples:\n  bento set cpus=4 memory=8G\n  bento set dev name=ubuntu disk=64G\n  bento set dev network=private rosetta=true\n"
)]
pub struct Cmd {
    /// Optional VM followed by one or more KEY=VALUE settings.
    #[arg(value_name = "[VM] KEY=VALUE", required = true)]
    pub args: Vec<String>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.args.join(" "))
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime, config: &GlobalConfig) -> eyre::Result<()> {
        let parsed = ParsedSet::parse(&self.args)?;
        let (_reference, machine) = get_machine(libvm, config, parsed.machine.as_deref()).await?;
        let old_name = if parsed.update.name.is_some() {
            Some(machine.inspect().await?.name)
        } else {
            None
        };
        let update_default = old_name
            .as_deref()
            .is_some_and(|name| config.default_machine() == Some(name));
        let inspect_data = machine.update(parsed.update).await.map_err(|err| match err {
            libvm::LibVmError::MachineAlreadyRunning { reference } => eyre::eyre!(
                "{reference} is running\n\nhint: stop it with `bento stop {reference}` before changing settings"
            ),
            other => eyre::Report::from(other),
        })?;
        if update_default {
            GlobalConfig::write_default_machine(Some(inspect_data.name.as_str()))?;
        }
        println!("updated {}", inspect_data.name);
        Ok(())
    }
}

struct ParsedSet {
    machine: Option<String>,
    update: MachineUpdate,
}

impl ParsedSet {
    fn parse(args: &[String]) -> eyre::Result<Self> {
        let (machine, settings) = match args.split_first() {
            Some((first, _)) if first.contains('=') => (None, args),
            Some((first, rest)) => (Some(first.clone()), rest),
            None => unreachable!("clap requires at least one set argument"),
        };

        if settings.is_empty() {
            eyre::bail!("at least one KEY=VALUE setting is required");
        }

        let mut update = MachineUpdate::new();
        let mut seen = Vec::new();
        for setting in settings {
            let (key, value) = setting
                .split_once('=')
                .ok_or_else(|| eyre::eyre!("invalid setting {setting:?}; expected KEY=VALUE"))?;
            if key.is_empty() {
                eyre::bail!("invalid setting {setting:?}; key cannot be empty");
            }
            if value.is_empty() {
                eyre::bail!("invalid setting {setting:?}; value cannot be empty");
            }
            let key = normalize_key(key)?;
            if seen.contains(&key) {
                eyre::bail!("setting {key:?} specified more than once");
            }
            seen.push(key);

            match key {
                "name" => {
                    update = update.name(value);
                }
                "cpus" => {
                    update = update.cpus(parse_cpus(value)?);
                }
                "memory" => {
                    update = update.memory(parse_memory(value)?);
                }
                "disk" => {
                    update = update.root_disk_size(parse_disk(value)?);
                }
                "network" => {
                    update = update
                        .network(parse_machine_network_config(value).map_err(eyre::Report::msg)?);
                }
                "nested-virtualization" => {
                    update = update.nested_virtualization(parse_bool(value)?);
                }
                "rosetta" => {
                    update = update.rosetta(parse_bool(value)?);
                }
                _ => unreachable!("normalize_key rejects unknown keys"),
            }
        }

        Ok(Self { machine, update })
    }
}

fn normalize_key(key: &str) -> eyre::Result<&'static str> {
    match key {
        "name" => Ok("name"),
        "cpus" | "cpu" => Ok("cpus"),
        "memory" | "mem" => Ok("memory"),
        "disk" | "root-disk" | "root_disk" => Ok("disk"),
        "network" | "net" => Ok("network"),
        "nested-virtualization" | "nested_virtualization" => Ok("nested-virtualization"),
        "rosetta" => Ok("rosetta"),
        _ => Err(eyre::eyre!(
            "unknown setting {key:?}; allowed settings are name, cpus, memory, disk, network, nested-virtualization, rosetta"
        )),
    }
}

fn parse_cpus(value: &str) -> eyre::Result<u8> {
    let cpus = value
        .parse::<u8>()
        .map_err(|err| eyre::eyre!("invalid cpus value {value:?}: {err}"))?;
    if cpus == 0 {
        eyre::bail!("cpus must be greater than 0");
    }
    Ok(cpus)
}

fn parse_memory(value: &str) -> eyre::Result<Memory> {
    let mebibytes = value
        .parse::<HumanSize>()
        .map_err(eyre::Report::msg)?
        .memory_mib()
        .map_err(eyre::Report::msg)?;
    Ok(Memory::mebibytes(u64::from(mebibytes)))
}

fn parse_disk(value: &str) -> eyre::Result<u64> {
    let bytes = value
        .parse::<HumanSize>()
        .map_err(eyre::Report::msg)?
        .storage_bytes()
        .map_err(eyre::Report::msg)?;
    if bytes == 0 {
        eyre::bail!("disk must be greater than 0");
    }
    Ok(bytes)
}

fn parse_bool(value: &str) -> eyre::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(eyre::eyre!("invalid boolean {value:?}; use true or false")),
    }
}

#[cfg(test)]
mod tests {
    use libvm::Memory;

    use super::ParsedSet;

    #[test]
    fn parses_default_machine_settings() {
        let parsed = ParsedSet::parse(&["cpus=4".to_string(), "memory=8G".to_string()])
            .expect("parse set args");

        assert_eq!(parsed.machine, None);
        assert_eq!(parsed.update.cpus, Some(4));
        assert_eq!(parsed.update.memory, Some(Memory::mebibytes(8192)));
    }

    #[test]
    fn parses_named_machine_settings() {
        let parsed =
            ParsedSet::parse(&["dev".to_string(), "disk=64G".to_string()]).expect("parse set args");

        assert_eq!(parsed.machine.as_deref(), Some("dev"));
        assert_eq!(parsed.update.root_disk_size, Some(64 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parses_rename_setting() {
        let parsed = ParsedSet::parse(&["dev".to_string(), "name=ubuntu".to_string()])
            .expect("parse set args");

        assert_eq!(parsed.machine.as_deref(), Some("dev"));
        assert_eq!(parsed.update.name.as_deref(), Some("ubuntu"));
    }

    #[test]
    fn rejects_duplicate_settings() {
        assert!(ParsedSet::parse(&["cpus=2".to_string(), "cpu=4".to_string()]).is_err());
    }
}

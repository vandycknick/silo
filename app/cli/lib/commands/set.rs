use clap::Args;
use libvm::{MachineUpdate, Memory};
use std::path::PathBuf;
use utils::HumanSize;

use crate::config::GlobalConfig;
use crate::context::Context;
use crate::machine_defaults::MachineNetworkSelection;
use crate::ui;

const SETTINGS: &[(&str, &str)] = &[
    ("name=NAME", "Rename the VM"),
    ("cpus=N", "Set the virtual CPU count"),
    ("memory=SIZE", "Set RAM size"),
    ("disk=SIZE", "Set desired root disk size"),
    (
        "network=private|none|NAME|name:NAME",
        "Set the network target",
    ),
    (
        "nested-virtualization=true|false",
        "Enable or disable nested virtualization",
    ),
    ("rosetta=true|false", "Enable or disable Rosetta"),
    (
        "agent=default|disabled|PATH",
        "Set managed guest agent selection",
    ),
    (
        "user=none|auto|NAME:UID:GID:HOME",
        "Experimental: configure guest-user provisioning",
    ),
];

const EXAMPLES: &[&str] = &[
    "silo set cpus=4 memory=8G",
    "silo set dev name=ubuntu disk=64G",
    "silo set dev network=private rosetta=true",
];

#[derive(Debug, Args)]
#[command(
    about = "Update machine configuration",
    after_help = after_help()
)]
pub struct Cmd {
    /// Optional VM followed by one or more KEY=VALUE settings.
    #[arg(value_name = "[VM] KEY=VALUE", required = true)]
    args: Vec<String>,
}

fn after_help() -> clap::builder::StyledStr {
    crate::help::HelpDoc::new()
        .section("Settings")
        .table(SETTINGS)
        .section("Size units")
        .text("m, mb, mib are stored as MiB; g, gb, gib are stored as GiB.")
        .section("Examples")
        .examples(EXAMPLES)
        .build()
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let parsed = ParsedSet::parse(&self.args)?;
        let reference = context.resolve_machine_name(parsed.machine.as_deref())?;
        let existing = context.app_api().await?.inspect_machine(&reference).await?;
        let managed_backend = crate::system::ownership::managed_system_backend(&existing.id)?;
        let direct_backend = context.virt_backend_override()?;
        validate_rosetta_update(&parsed.update, managed_backend, direct_backend.as_ref())?;
        let old_name = if parsed.update.name.is_some() {
            Some(existing.name)
        } else {
            None
        };
        let default_machine = context.config()?.default_machine().map(str::to_string);
        let update_default = old_name
            .as_deref()
            .is_some_and(|name| default_machine.as_deref() == Some(name));

        let data = context.app_api().await?.update_machine(&reference, parsed.update).await.map_err(|err| match err.downcast::<libvm::LibVmError>() {
            Ok(libvm::LibVmError::MachineAlreadyRunning { reference }) => eyre::eyre!(
                "{reference} is running\n\nhint: stop it with `silo stop {reference}` before changing settings"
            ),
            Ok(other) => eyre::Report::from(other),
            Err(other) => other,
        })?;

        if update_default {
            GlobalConfig::write_default_machine(Some(data.name.as_str()))?;
        }
        ui::success(format!("updated {}", data.name));
        Ok(())
    }
}

fn validate_rosetta_update(
    update: &MachineUpdate,
    managed_backend: Option<crate::system::config::SystemBackend>,
    direct_backend: Option<&libvm::VirtBackendOverride>,
) -> eyre::Result<()> {
    let uses_krun = managed_backend
        .map(|backend| backend == crate::system::config::SystemBackend::Krun)
        .unwrap_or(direct_backend == Some(&libvm::VirtBackendOverride::Krun));
    if update.rosetta == Some(true) && uses_krun {
        eyre::bail!(
            "rosetta is not supported on the krun backend yet\n\nhint: select the vz backend"
        );
    }
    Ok(())
}

struct ParsedSet {
    machine: Option<String>,
    update: MachineUpdate,
}

impl ParsedSet {
    fn parse(args: &[String]) -> eyre::Result<Self> {
        let Some((first, rest)) = args.split_first() else {
            eyre::bail!("at least one KEY=VALUE setting is required");
        };

        let (machine, settings) = if first.contains('=') {
            (None, args)
        } else {
            (Some(first.clone()), rest)
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
                "name" => update = update.name(value),
                "cpus" => update = update.cpus(parse_cpus(value)?),
                "memory" => update = update.memory(parse_memory(value)?),
                "disk" => update = update.root_disk_size(parse_disk(value)?),
                "network" => {
                    let network =
                        MachineNetworkSelection::parse(value).map_err(eyre::Report::msg)?;
                    update = update.network(|builder| network.apply(builder));
                }
                "nested-virtualization" => {
                    update = update.nested_virtualization(parse_bool(value)?);
                }
                "rosetta" => update = update.rosetta(parse_bool(value)?),
                "agent" => {
                    update = match value {
                        "default" => update.guest(|guest| guest),
                        "disabled" => update.guest(|guest| guest.agent(None)),
                        path => update.guest(|guest| guest.agent(Some(PathBuf::from(path)))),
                    };
                }
                "user" => {
                    update = match value {
                        "none" => update.clear_user(),
                        "auto" => update.user(crate::commands::create::current_host_user()?),
                        value => update.user(
                            crate::commands::create::parse_explicit_user(value)
                                .map_err(eyre::Report::msg)?,
                        ),
                    };
                }
                other => eyre::bail!("unsupported setting {other:?}"),
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
        "agent" => Ok("agent"),
        "user" => Ok("user"),
        _ => Err(eyre::eyre!(
            "unknown setting {key:?}; allowed settings are name, cpus, memory, disk, network, nested-virtualization, rosetta, agent, user"
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
    use libvm::{MachineUserUpdate, Memory};

    use crate::commands::set::{validate_rosetta_update, ParsedSet};

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

    #[test]
    fn parses_explicit_and_disabled_user_settings() {
        let parsed = ParsedSet::parse(&[
            "dev".to_string(),
            "user=alice:1000:2000:/home/alice".to_string(),
        ])
        .expect("parse explicit user");
        let Some(MachineUserUpdate::Set(user)) = parsed.update.user else {
            panic!("expected user update");
        };
        assert_eq!(user.name, "alice");
        assert_eq!(user.gid, 2000);

        let parsed = ParsedSet::parse(&["dev".to_string(), "user=none".to_string()])
            .expect("parse disabled user");
        assert!(matches!(parsed.update.user, Some(MachineUserUpdate::Clear)));
    }

    #[test]
    fn krun_rejects_enabling_rosetta_before_persisting_the_update() {
        let update = ParsedSet::parse(&["rosetta=true".to_string()])
            .expect("parse update")
            .update;
        let error = validate_rosetta_update(&update, None, Some(&libvm::VirtBackendOverride::Krun))
            .expect_err("reject Rosetta on krun");
        assert!(error.to_string().contains("select the vz backend"));
        validate_rosetta_update(&update, None, Some(&libvm::VirtBackendOverride::Vz))
            .expect("allow Rosetta on VZ");
    }

    #[test]
    fn managed_backend_wins_and_does_not_gate_ordinary_machines() {
        let update = ParsedSet::parse(&["rosetta=true".to_string()])
            .expect("parse update")
            .update;
        let krun = crate::system::config::SystemBackend::Krun;
        let vz = crate::system::config::SystemBackend::Vz;

        assert!(validate_rosetta_update(&update, Some(krun), None).is_err());
        assert!(validate_rosetta_update(
            &update,
            Some(krun),
            Some(&libvm::VirtBackendOverride::Vz)
        )
        .is_err());
        validate_rosetta_update(&update, Some(vz), Some(&libvm::VirtBackendOverride::Krun))
            .expect("managed VZ policy wins");
        validate_rosetta_update(&update, None, Some(&libvm::VirtBackendOverride::Vz))
            .expect("ordinary VZ machine");
    }
}

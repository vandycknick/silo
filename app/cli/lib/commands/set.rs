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
        "tmpfs-size=SIZE|off",
        "Select sized /tmp tmpfs or restore disk-backed /tmp on a stopped overlay VM",
    ),
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
    (
        "boot-assets=packaged|sha256:HEX|files",
        "Explicitly replace the pinned boot bundle of a stopped VM; never combined with other settings",
    ),
    (
        "boot-kernel=PATH boot-initramfs=PATH boot-agent=PATH|none",
        "The complete file tuple for boot-assets=files; the agent is never inherited",
    ),
];

const EXAMPLES: &[&str] = &[
    "silo set cpus=4 memory=8G",
    "silo set dev name=ubuntu disk=64G",
    "silo set dev network=private rosetta=true",
    "silo set dev boot-assets=packaged",
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
        let update = match parsed.operation {
            SetOperation::BootAssets(update) => {
                let data = context
                    .app_api()
                    .await?
                    .update_boot_assets(&reference, update)
                    .await
                    .map_err(stopped_hint)?;
                ui::success(format!("updated boot assets of {}", data.name));
                return Ok(());
            }
            SetOperation::Update(update) => *update,
        };
        let existing = context.app_api().await?.inspect_machine(&reference).await?;
        let old_name = if update.name.is_some() {
            Some(existing.name)
        } else {
            None
        };
        let default_machine = context.config()?.default_machine().map(str::to_string);
        let update_default = old_name
            .as_deref()
            .is_some_and(|name| default_machine.as_deref() == Some(name));

        let data = context
            .app_api()
            .await?
            .update_machine(&reference, update)
            .await
            .map_err(stopped_hint)?;

        if update_default {
            GlobalConfig::write_default_machine(Some(data.name.as_str()))?;
        }
        ui::success(format!("updated {}", data.name));
        Ok(())
    }
}

fn stopped_hint(err: eyre::Report) -> eyre::Report {
    match err.downcast::<libvm::LibVmError>() {
        Ok(libvm::LibVmError::MachineAlreadyRunning { reference }) => eyre::eyre!(
            "{reference} is running\n\nhint: stop it with `silo stop {reference}` before changing settings"
        ),
        Ok(other) => eyre::Report::from(other),
        Err(other) => other,
    }
}

/// Ordinary settings form one atomic update; a boot-bundle replacement is its
/// own explicit operation and is never mixed with them.
enum SetOperation {
    Update(Box<MachineUpdate>),
    BootAssets(libvm::BootAssetsUpdate),
}

struct ParsedSet {
    machine: Option<String>,
    operation: SetOperation,
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
        let mut boot = BootSettings::default();
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
                "tmpfs-size" => {
                    let policy = if value == "off" {
                        libvm::TemporaryDirectoryPolicy::DiskBacked
                    } else {
                        libvm::TemporaryDirectoryPolicy::Tmpfs {
                            capacity_bytes: parse_disk(value)?,
                        }
                    };
                    policy.validate()?;
                    update = update.temporary_directory(policy);
                }
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
                "boot-assets" => boot.assets = Some(value.to_owned()),
                "boot-kernel" => boot.kernel = Some(host_file(value)?),
                "boot-initramfs" => boot.initramfs = Some(host_file(value)?),
                "boot-agent" => {
                    boot.agent = Some(match value {
                        "none" => None,
                        path => Some(host_file(path)?),
                    })
                }
                other => eyre::bail!("unsupported setting {other:?}"),
            }
        }

        let boot_keys = seen.iter().filter(|key| key.starts_with("boot-")).count();
        let operation = if boot_keys == 0 {
            SetOperation::Update(Box::new(update))
        } else if boot_keys != seen.len() {
            eyre::bail!(
                "boot-assets is an explicit boot-bundle replacement; apply other settings separately"
            );
        } else {
            SetOperation::BootAssets(boot.selection()?)
        };
        Ok(Self { machine, operation })
    }
}

#[derive(Default)]
struct BootSettings {
    assets: Option<String>,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    agent: Option<Option<PathBuf>>,
}

impl BootSettings {
    fn selection(self) -> eyre::Result<libvm::BootAssetsUpdate> {
        let files = self.kernel.is_some() || self.initramfs.is_some() || self.agent.is_some();
        let selection = match self.assets.as_deref() {
            Some("files") => match (self.kernel, self.initramfs, self.agent) {
                (Some(kernel), Some(base_initramfs), Some(agent)) => {
                    libvm::BootAssetSelection::Files {
                        kernel,
                        base_initramfs,
                        agent,
                    }
                }
                _ => eyre::bail!(
                    "boot-assets=files requires boot-kernel, boot-initramfs and boot-agent=PATH|none together"
                ),
            },
            Some(_) if files => {
                eyre::bail!("boot-kernel, boot-initramfs and boot-agent require boot-assets=files")
            }
            Some("packaged") => libvm::BootAssetSelection::Packaged,
            Some(digest) if digest.starts_with("sha256:") => libvm::BootAssetSelection::Exact {
                bundle: silo_vm_control::boot::digest_from_wire(digest, "boot-assets")?,
            },
            Some(other) => eyre::bail!(
                "invalid boot-assets {other:?}; use packaged, sha256:HEX or files"
            ),
            None => eyre::bail!("boot file settings require boot-assets=files"),
        };
        Ok(libvm::BootAssetsUpdate { selection })
    }
}

/// Boot files are absolute, existing host files; the daemon never interprets
/// the client's working directory.
fn host_file(value: &str) -> eyre::Result<PathBuf> {
    let path = crate::machine_defaults::resolve_host_path(std::path::Path::new(value))?;
    let path = std::fs::canonicalize(&path)
        .map_err(|error| eyre::eyre!("resolve boot file {}: {error}", path.display()))?;
    if !path.is_file() {
        eyre::bail!("boot file is not a regular file: {}", path.display());
    }
    Ok(path)
}

fn normalize_key(key: &str) -> eyre::Result<&'static str> {
    match key {
        "name" => Ok("name"),
        "cpus" | "cpu" => Ok("cpus"),
        "memory" | "mem" => Ok("memory"),
        "disk" | "root-disk" | "root_disk" => Ok("disk"),
        "tmpfs-size" => Ok("tmpfs-size"),
        "network" | "net" => Ok("network"),
        "nested-virtualization" | "nested_virtualization" => Ok("nested-virtualization"),
        "rosetta" => Ok("rosetta"),
        "agent" => Ok("agent"),
        "user" => Ok("user"),
        "boot-assets" => Ok("boot-assets"),
        "boot-kernel" => Ok("boot-kernel"),
        "boot-initramfs" => Ok("boot-initramfs"),
        "boot-agent" => Ok("boot-agent"),
        _ => Err(eyre::eyre!(
            "unknown setting {key:?}; allowed settings are name, cpus, memory, disk, tmpfs-size, network, nested-virtualization, rosetta, agent, user, boot-assets, boot-kernel, boot-initramfs, boot-agent"
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
    use libvm::{MachineUpdate, MachineUserUpdate, Memory};

    use crate::commands::set::{ParsedSet, SetOperation};

    fn update(args: &[&str]) -> MachineUpdate {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        match ParsedSet::parse(&args).expect("parse set args").operation {
            SetOperation::Update(update) => *update,
            SetOperation::BootAssets(_) => panic!("expected an ordinary update"),
        }
    }

    fn boot(args: &[&str]) -> eyre::Result<libvm::BootAssetSelection> {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        match ParsedSet::parse(&args)?.operation {
            SetOperation::BootAssets(update) => Ok(update.selection),
            SetOperation::Update(_) => panic!("expected a boot-assets operation"),
        }
    }

    #[test]
    fn tmpfs_policy_is_sized_or_explicitly_removed() {
        assert_eq!(
            update(&["dev", "tmpfs-size=8mib"]).temporary_directory,
            Some(libvm::TemporaryDirectoryPolicy::Tmpfs {
                capacity_bytes: 8 * 1024 * 1024
            })
        );
        assert_eq!(
            update(&["dev", "tmpfs-size=off"]).temporary_directory,
            Some(libvm::TemporaryDirectoryPolicy::DiskBacked)
        );
        assert!(ParsedSet::parse(&["tmpfs-size=0".into()]).is_err());
    }

    #[test]
    fn reclaim_is_not_a_user_setting() {
        for key in ["memory-reclaim", "host-memory-reclaim", "balloon"] {
            assert!(ParsedSet::parse(&[format!("{key}=off")]).is_err());
        }
    }

    #[test]
    fn parses_default_and_named_machine_settings() {
        let parsed = ParsedSet::parse(&["cpus=4".to_string(), "memory=8G".to_string()])
            .expect("parse set args");
        assert_eq!(parsed.machine, None);
        let update = update(&["cpus=4", "memory=8G"]);
        assert_eq!(update.cpus, Some(4));
        assert_eq!(update.memory, Some(Memory::mebibytes(8192)));
        let parsed =
            ParsedSet::parse(&["dev".to_string(), "disk=64G".to_string()]).expect("parse set args");
        assert_eq!(parsed.machine.as_deref(), Some("dev"));
        assert_eq!(
            self::update(&["dev", "disk=64G"]).root_disk_size,
            Some(64 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            self::update(&["dev", "name=ubuntu"]).name.as_deref(),
            Some("ubuntu")
        );
    }

    #[test]
    fn rejects_duplicate_settings() {
        assert!(ParsedSet::parse(&["cpus=2".to_string(), "cpu=4".to_string()]).is_err());
    }

    #[test]
    fn parses_explicit_and_disabled_user_settings() {
        let Some(MachineUserUpdate::Set(user)) =
            update(&["dev", "user=alice:1000:2000:/home/alice"]).user
        else {
            panic!("expected user update");
        };
        assert_eq!(user.name, "alice");
        assert_eq!(user.gid, 2000);
        assert!(matches!(
            update(&["dev", "user=none"]).user,
            Some(MachineUserUpdate::Clear)
        ));
    }

    #[test]
    fn boot_assets_are_an_explicit_complete_operation_never_mixed() {
        assert_eq!(
            boot(&["dev", "boot-assets=packaged"]).unwrap(),
            libvm::BootAssetSelection::Packaged
        );
        let digest = format!("sha256:{}", "ef".repeat(32));
        assert_eq!(
            boot(&["dev", &format!("boot-assets={digest}")]).unwrap(),
            libvm::BootAssetSelection::Exact {
                bundle: digest.parse().unwrap()
            }
        );
        let temp = tempfile::tempdir().unwrap();
        let kernel = temp.path().join("kernel");
        let initramfs = temp.path().join("initramfs");
        std::fs::write(&kernel, b"k").unwrap();
        std::fs::write(&initramfs, b"i").unwrap();
        let kernel_arg = format!("boot-kernel={}", kernel.display());
        let initramfs_arg = format!("boot-initramfs={}", initramfs.display());
        assert_eq!(
            boot(&[
                "dev",
                "boot-assets=files",
                &kernel_arg,
                &initramfs_arg,
                "boot-agent=none"
            ])
            .unwrap(),
            libvm::BootAssetSelection::Files {
                kernel: kernel.canonicalize().unwrap(),
                base_initramfs: initramfs.canonicalize().unwrap(),
                agent: None,
            }
        );
        // The agent is never inherited: a file tuple must state it.
        assert!(boot(&["dev", "boot-assets=files", &kernel_arg, &initramfs_arg]).is_err());
        assert!(boot(&["dev", "boot-assets=packaged", &kernel_arg]).is_err());
        assert!(boot(&["dev", &kernel_arg]).is_err());
        assert!(boot(&["dev", "boot-assets=sha256:ABC"]).is_err());
        assert!(boot(&["dev", "boot-assets=latest"]).is_err());
        for mixed in [
            ["boot-assets=packaged", "cpus=2"],
            ["rosetta=false", "boot-assets=packaged"],
        ] {
            let args: Vec<String> = std::iter::once("dev")
                .chain(mixed)
                .map(str::to_string)
                .collect();
            assert!(ParsedSet::parse(&args).is_err(), "{mixed:?}");
        }
    }
}

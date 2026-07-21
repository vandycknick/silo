use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Args;
use eyre::Context as _;
use libvm::{ImageProgressSender, MachineBuilder, MachineUserConfig, Memory};
use nix::unistd::{Uid, User};
use utils::HumanSize;
use vm_spec::Mount;

use crate::commands::profile::{parse_label, parse_machine_network_config, parse_profile_mount};
use crate::commands::rootfs_image::parse_cli_image_source;
use crate::commands::start_options::machine_start_options;
use crate::config::GlobalConfig;
use crate::constants::{DEFAULT_PROFILE_NAME, PROFILE_METADATA_KEY};
use crate::context::Context;
use crate::profile::{
    resolve_host_path, MachineNetworkSelection, MountMode, ProfileMount, ProfileStore,
    ResolvedMachineNetwork,
};
use crate::ui::{success, watch_image_progress, Spinner};

const EXAMPLES: &[&str] = &[
    "silo create dev --start --default",
    "silo create dev rust-dev --start",
    "silo create dev --profile rust-dev",
    "silo create ubuntu --image ubuntu:24.04",
    "silo create dev rust-dev --image disk:./target/rootfs.img",
];

#[derive(Debug, Args)]
#[command(
    about = "Create a persistent VM from a profile or image",
    after_help = crate::help::examples(EXAMPLES)
)]
pub struct Cmd {
    /// Name of the persistent VM to create.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Profile to create the VM from.
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Profile name. Alternative to the positional profile argument.
    #[arg(long = "profile")]
    pub profile_name: Option<String>,
    /// Image reference to create from. Overrides the profile image when both are set.
    #[arg(long)]
    pub image: Option<String>,
    /// Start the VM immediately after it is created.
    #[arg(long)]
    pub start: bool,
    /// Make the created VM the default for commands that omit VM.
    #[arg(long)]
    pub default: bool,
    /// Path to a custom managed guest agent.
    #[arg(long, value_name = "PATH", conflicts_with = "no_agent")]
    pub agent: Option<PathBuf>,
    /// Disable managed guest-agent injection and readiness.
    #[arg(long, conflicts_with = "agent")]
    pub no_agent: bool,
    #[command(flatten)]
    pub(crate) overrides: VmOverrideArgs,
}

#[derive(Debug, Args, Default)]
pub(crate) struct VmOverrideArgs {
    /// Number of virtual CPUs.
    #[arg(long)]
    pub cpus: Option<u8>,
    /// Virtual machine RAM size, for example 512mb or 4gb.
    #[arg(long, value_name = "SIZE")]
    pub memory: Option<HumanSize>,
    /// Path to a custom kernel. Only works for Linux.
    #[arg(long)]
    pub kernel: Option<PathBuf>,
    /// Path to a custom initramfs image. Only works for Linux.
    #[arg(long = "initramfs", visible_alias = "initrd")]
    pub initramfs: Option<PathBuf>,
    /// Append an argument to the Linux kernel command line. May be repeated.
    #[arg(long = "kernel-arg", value_name = "ARG")]
    pub kernel_args: Vec<String>,
    /// Resize the image-backed root disk, for example 10gb or 512mb.
    #[arg(long, value_name = "SIZE")]
    pub disk_size: Option<HumanSize>,
    /// Enable nested virtualization for supported VZ guests.
    #[arg(long)]
    pub nested_virtualization: bool,
    /// Enable Rosetta for x86_64 Linux binaries in supported VZ guests.
    #[arg(long)]
    pub rosetta: bool,
    /// Path to userdata file.
    #[arg(long, value_name = "PATH")]
    pub userdata: Option<PathBuf>,
    /// Path to an existing disk image.
    #[arg(long = "disk", value_name = "PATH")]
    pub disks: Vec<PathBuf>,
    /// Add a mount or override profile mounts. Format: SRC:DST[:ro|rw].
    #[arg(long = "mount", value_name = "SRC:DST[:MODE]", value_parser = parse_profile_mount)]
    pub mounts: Vec<ProfileMount>,
    /// Override the profile network target. Allowed: private, none, NAME, or name:NAME.
    #[arg(long, value_parser = parse_machine_network_config)]
    pub network: Option<MachineNetworkSelection>,
    /// Add or override a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub labels: Vec<(String, String)>,
    /// Experimental: provision a guest user. Omit the value for the current host user.
    #[arg(
        long,
        value_name = "NAME:UID:GID:HOME",
        num_args = 0..=1,
        default_missing_value = "auto",
        require_equals = true,
        value_parser = parse_user_arg,
        help_heading = "Experimental"
    )]
    pub user: Option<UserArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserArg {
    Auto,
    Explicit(MachineUserConfig),
}

impl VmOverrideArgs {
    pub(crate) fn memory_mib(&self) -> eyre::Result<Option<u32>> {
        self.memory
            .map(HumanSize::memory_mib)
            .transpose()
            .map_err(eyre::Report::msg)
    }

    pub(crate) fn disk_size_bytes(&self) -> eyre::Result<Option<u64>> {
        self.disk_size
            .map(HumanSize::storage_bytes)
            .transpose()
            .map_err(eyre::Report::msg)
    }
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let policy_config_dir = context.config()?.networking.policy_config_dir.clone();
        let progress = Spinner::start("Reading", "VM recipe");
        let resolved = self.resolve(policy_config_dir.as_deref())?;
        let runtime = context.runtime().await?;
        progress.finish_clear();
        let image_source = parse_cli_image_source(&resolved.image_ref)?;
        let (image_progress, image_events) = ImageProgressSender::default_channel();
        let image_progress_task = watch_image_progress(resolved.image_ref.clone(), image_events);
        let machine_options = resolved.options;
        let machine = {
            let runtime_with_progress = (*runtime).clone().with_image_progress(image_progress);
            let builder = runtime_with_progress
                .machine()
                .image_source(image_source)
                .name(self.name.clone());

            apply_resolved_machine_options(builder, machine_options)
                .create()
                .await
        };
        let _ = image_progress_task.await;
        let machine = machine?;
        success(format!("Created {}", self.name));

        if self.default {
            GlobalConfig::write_default_machine(Some(&self.name))?;
            eprintln!("default machine is {}", self.name);
        }

        if self.start {
            let progress = Spinner::start("Starting", &self.name);
            machine
                .start_with_options(machine_start_options(runtime, &machine).await?)
                .await?;
            progress.finish_success("Started");
        }

        Ok(())
    }

    fn resolve(&self, policy_config_dir: Option<&Path>) -> eyre::Result<ResolvedCreate> {
        if self.profile.is_some() && self.profile_name.is_some() {
            eyre::bail!("profile specified twice; use either positional profile or --profile");
        }
        let profile_name = self.profile.clone().or_else(|| self.profile_name.clone());
        let profile_name = profile_name.or_else(|| {
            if self.image.is_none() {
                Some(DEFAULT_PROFILE_NAME.to_string())
            } else {
                None
            }
        });

        let mut labels = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut mounts = Vec::new();
        let mut network = ResolvedMachineNetwork::default();
        let mut userdata = None;
        let mut cpus = None;
        let mut memory_mib = None;
        let mut disk_size_bytes = None;
        let mut resolved_image_ref = if let Some(profile_name) = profile_name {
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&profile_name)?;
            network = named.profile.machine_network(policy_config_dir)?;
            userdata = named.profile.userdata.clone();
            cpus = named.profile.cpus();
            memory_mib = named.profile.memory_mib()?;
            disk_size_bytes = named.profile.disk_size_bytes()?;
            labels = named.profile.labels.clone();
            metadata.insert(PROFILE_METADATA_KEY.to_string(), named.name.clone());
            mounts = named.profile.resolved_mounts()?;
            for (key, value) in &self.overrides.labels {
                labels.insert(key.clone(), value.clone());
            }
            for mount in &self.overrides.mounts {
                mounts.push(profile_mount_to_mount(mount)?);
            }
            named.profile.image.clone()
        } else if let Some(image) = &self.image {
            for (key, value) in &self.overrides.labels {
                labels.insert(key.clone(), value.clone());
            }
            for mount in &self.overrides.mounts {
                mounts.push(profile_mount_to_mount(mount)?);
            }
            image.clone()
        } else {
            eyre::bail!("either a profile or image is required");
        };

        if let Some(image) = &self.image {
            resolved_image_ref = image.clone();
        }
        let image_ref = resolved_image_ref;
        if let Some(network_override) = self.overrides.network.clone() {
            network = network_override.into();
        }
        if let Some(userdata_path) = self.overrides.userdata.as_deref() {
            userdata = Some(read_userdata_path(userdata_path)?);
        }

        Ok(ResolvedCreate {
            image_ref,
            options: ResolvedMachineOptions {
                labels,
                metadata,
                mounts,
                network,
                userdata,
                cpus: self.overrides.cpus.or(cpus),
                memory_mib: self.overrides.memory_mib()?.or(memory_mib),
                disk_size_bytes: self.overrides.disk_size_bytes()?.or(disk_size_bytes),
                nested_virtualization: self.overrides.nested_virtualization,
                rosetta: self.overrides.rosetta,
                kernel: self.overrides.kernel.clone(),
                initramfs: self.overrides.initramfs.clone(),
                kernel_args: self.overrides.kernel_args.clone(),
                agent: if self.no_agent {
                    Some(None)
                } else {
                    self.agent.clone().map(Some)
                },
                disks: self.overrides.disks.clone(),
                user: self
                    .overrides
                    .user
                    .as_ref()
                    .map(resolve_user_arg)
                    .transpose()?,
            },
        })
    }
}

pub(crate) fn apply_resolved_machine_options(
    mut builder: MachineBuilder,
    options: ResolvedMachineOptions,
) -> MachineBuilder {
    let ResolvedMachineOptions {
        labels,
        metadata,
        mounts,
        network,
        userdata,
        cpus,
        memory_mib,
        disk_size_bytes,
        nested_virtualization,
        rosetta,
        kernel,
        initramfs,
        kernel_args,
        agent,
        disks,
        user,
    } = options;

    builder = builder
        .labels(labels)
        .metadata(metadata)
        .nested_virtualization(nested_virtualization)
        .rosetta(rosetta)
        .kernel_args(kernel_args)
        .disks(disks)
        .mounts(mounts)
        .network(|builder| network.apply(builder));

    if let Some(cpus) = cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(memory_mib) = memory_mib {
        builder = builder.memory(Memory::mebibytes(u64::from(memory_mib)));
    }
    if let Some(kernel) = kernel {
        builder = builder.kernel(kernel);
    }
    if let Some(initramfs) = initramfs {
        builder = builder.initramfs(initramfs);
    }
    if agent.is_some() || user.is_some() {
        builder = builder.guest(|guest| {
            let guest = match agent {
                Some(agent) => guest.agent(agent),
                None => guest,
            };
            match user {
                Some(user) => guest.user(user),
                None => guest,
            }
        });
    }
    if let Some(bytes) = disk_size_bytes {
        builder = builder.root_disk_size(bytes);
    }
    if let Some(userdata) = userdata {
        builder = builder.userdata(userdata);
    }

    builder
}

struct ResolvedCreate {
    image_ref: String,
    options: ResolvedMachineOptions,
}

pub(crate) struct ResolvedMachineOptions {
    pub(crate) labels: BTreeMap<String, String>,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) mounts: Vec<Mount>,
    pub(crate) network: ResolvedMachineNetwork,
    pub(crate) userdata: Option<String>,
    pub(crate) cpus: Option<u8>,
    pub(crate) memory_mib: Option<u32>,
    pub(crate) disk_size_bytes: Option<u64>,
    pub(crate) nested_virtualization: bool,
    pub(crate) rosetta: bool,
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initramfs: Option<PathBuf>,
    pub(crate) kernel_args: Vec<String>,
    pub(crate) agent: Option<Option<PathBuf>>,
    pub(crate) disks: Vec<PathBuf>,
    pub(crate) user: Option<MachineUserConfig>,
}

pub(crate) fn parse_user_arg(value: &str) -> Result<UserArg, String> {
    if value == "auto" {
        return Ok(UserArg::Auto);
    }

    parse_explicit_user(value).map(UserArg::Explicit)
}

pub(crate) fn resolve_user_arg(value: &UserArg) -> eyre::Result<MachineUserConfig> {
    match value {
        UserArg::Auto => current_host_user(),
        UserArg::Explicit(user) => Ok(user.clone()),
    }
}

pub(crate) fn current_host_user() -> eyre::Result<MachineUserConfig> {
    let uid = Uid::effective();
    let user = User::from_uid(uid)?
        .ok_or_else(|| eyre::eyre!("unable to resolve effective host user {uid}"))?;
    if user.name.is_empty() {
        eyre::bail!("effective host user has an empty account name");
    }

    let user = MachineUserConfig::new(
        &user.name,
        user.uid.as_raw(),
        user.uid.as_raw(),
        format!("/home/{}", user.name),
    );
    user.validate().map_err(eyre::Report::msg)?;
    Ok(user)
}

pub(crate) fn parse_explicit_user(value: &str) -> Result<MachineUserConfig, String> {
    let fields = value.split(':').collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err("expected NAME:UID:GID:HOME".to_string());
    }
    let name = fields[0];
    let uid = fields[1]
        .parse::<u32>()
        .map_err(|error| format!("invalid user uid {:?}: {error}", fields[1]))?;
    let gid = fields[2]
        .parse::<u32>()
        .map_err(|error| format!("invalid user gid {:?}: {error}", fields[2]))?;
    let home = fields[3];
    let user = MachineUserConfig::new(name, uid, gid, home);
    user.validate()?;
    Ok(user)
}

pub(crate) fn profile_mount_to_mount(mount: &ProfileMount) -> eyre::Result<Mount> {
    Ok(Mount {
        source: resolve_host_path(&mount.source)?,
        tag: mount.target.clone(),
        read_only: mount.mode == MountMode::Ro,
    })
}

pub(crate) fn read_userdata_path(path: &Path) -> eyre::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read userdata {}", path.display()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::create::UserArg;
    use crate::commands::Command;

    #[test]
    fn create_command_parses_profile_form() {
        let cli = Cli::try_parse_from(["silo", "create", "dev", "rust-dev"])
            .expect("create command should parse");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(create.name, "dev");
        assert_eq!(create.profile.as_deref(), Some("rust-dev"));
    }

    #[test]
    fn create_command_parses_default_machine_happy_path() {
        let cli = Cli::try_parse_from(["silo", "create", "dev", "--start", "--default"])
            .expect("create command should parse");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };

        assert_eq!(create.name, "dev");
        assert_eq!(create.profile, None);
        assert!(create.start);
        assert!(create.default);
        assert!(create.overrides.kernel_args.is_empty());
    }

    #[test]
    fn create_command_parses_experimental_user_forms() {
        let cli = Cli::try_parse_from(["silo", "create", "dev", "--user", "rust-dev"])
            .expect("parse bare user flag");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(create.profile.as_deref(), Some("rust-dev"));
        assert_eq!(create.overrides.user, Some(UserArg::Auto));

        let cli = Cli::try_parse_from([
            "silo",
            "create",
            "dev",
            "--user=alice:1000:2000:/home/alice",
        ])
        .expect("parse explicit user");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        let Some(UserArg::Explicit(user)) = create.overrides.user else {
            panic!("expected explicit user");
        };
        assert_eq!(user.name, "alice");
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 2000);
        assert_eq!(user.home, "/home/alice");
    }

    #[test]
    fn create_command_rejects_invalid_experimental_users() {
        for user in [
            "alice:1000:1000",
            "alice:nope:1000:/home/alice",
            "alice:1000:1000:relative",
            "root:0:0:/root",
        ] {
            assert!(
                Cli::try_parse_from(["silo", "create", "dev", &format!("--user={user}")]).is_err()
            );
        }
    }

    #[test]
    fn create_command_parses_vm_overrides() {
        let cli = Cli::try_parse_from([
            "silo",
            "create",
            "dev",
            "rust-dev",
            "--cpus",
            "4",
            "--memory",
            "4gb",
            "--kernel",
            "./vmlinuz",
            "--initrd",
            "./initrd.img",
            "--kernel-arg",
            "systemd.firstboot=off",
            "--kernel-arg",
            "quiet",
            "--agent",
            "./silo-agent",
            "--disk-size",
            "40gb",
            "--nested-virtualization",
            "--rosetta",
            "--userdata",
            "./user-data.yaml",
            "--disk",
            "./data.raw",
            "--mount",
            ".:/workspace:rw",
            "--network",
            "none",
            "--label",
            "env=dev",
        ])
        .expect("create command should parse");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };

        assert_eq!(create.overrides.cpus, Some(4));
        assert_eq!(
            create.overrides.memory_mib().expect("memory mib"),
            Some(4096)
        );
        assert_eq!(
            create.overrides.disk_size_bytes().expect("disk size bytes"),
            Some(40 * 1024 * 1024 * 1024)
        );
        assert!(create.overrides.nested_virtualization);
        assert!(create.overrides.rosetta);
        assert_eq!(
            create.overrides.kernel.as_deref(),
            Some("./vmlinuz".as_ref())
        );
        assert_eq!(
            create.overrides.initramfs.as_deref(),
            Some("./initrd.img".as_ref())
        );
        assert_eq!(
            create.overrides.kernel_args,
            ["systemd.firstboot=off", "quiet"]
        );
        assert_eq!(create.agent.as_deref(), Some("./silo-agent".as_ref()));
        assert_eq!(create.overrides.disks.len(), 1);
        assert_eq!(create.overrides.mounts.len(), 1);
        assert_eq!(
            create.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }

    #[test]
    fn create_command_rejects_custom_and_disabled_agent_together() {
        assert!(
            Cli::try_parse_from(["silo", "create", "dev", "--agent", "./agent", "--no-agent"])
                .is_err()
        );
    }

    #[test]
    fn create_command_rejects_bare_memory_and_disk_size() {
        assert!(
            Cli::try_parse_from(["silo", "create", "dev", "rust-dev", "--memory", "4096"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["silo", "create", "dev", "rust-dev", "--disk-size", "40"])
                .is_err()
        );
    }
}

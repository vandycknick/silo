use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Args;
use eyre::Context as _;
use libvm::{ImageProgressSender, MachineBuilder, MachineNetworkConfig, Memory};
use utils::HumanSize;
use vm_spec::Mount;

use crate::commands::profile::{parse_label, parse_machine_network_config, parse_profile_mount};
use crate::commands::rootfs_image::parse_cli_image_source;
use crate::commands::start_options::machine_start_options;
use crate::config::GlobalConfig;
use crate::constants::{DEFAULT_PROFILE_NAME, PROFILE_METADATA_KEY};
use crate::context::Context;
use crate::profile::{resolve_host_path, MountMode, ProfileMount, ProfileStore};
use crate::ui::{success, watch_image_progress, Spinner};

const EXAMPLES: &[&str] = &[
    "bento create dev --start --default",
    "bento create dev rust-dev --start",
    "bento create dev --profile rust-dev",
    "bento create ubuntu --image ubuntu:24.04",
    "bento create dev rust-dev --image disk:./target/rootfs.img",
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
    pub network: Option<MachineNetworkConfig>,
    /// Add or override a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub labels: Vec<(String, String)>,
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
        let progress = Spinner::start("Reading", "VM recipe");
        let resolved = self.resolve()?;
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
                .start_with_options(machine_start_options(runtime, &machine)?)
                .await?;
            progress.finish_success("Started");
        }

        Ok(())
    }

    fn resolve(&self) -> eyre::Result<ResolvedCreate> {
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
        let mut network = MachineNetworkConfig::default();
        let mut userdata = None;
        let mut cpus = None;
        let mut memory_mib = None;
        let mut disk_size_bytes = None;
        let mut resolved_image_ref = if let Some(profile_name) = profile_name {
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&profile_name)?;
            network = named.profile.machine_network();
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
            network = network_override;
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
                disks: self.overrides.disks.clone(),
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
        disks,
    } = options;

    builder = builder
        .labels(labels)
        .metadata(metadata)
        .nested_virtualization(nested_virtualization)
        .rosetta(rosetta)
        .disks(disks)
        .mounts(mounts)
        .network(network);

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
    pub(crate) network: MachineNetworkConfig,
    pub(crate) userdata: Option<String>,
    pub(crate) cpus: Option<u8>,
    pub(crate) memory_mib: Option<u32>,
    pub(crate) disk_size_bytes: Option<u64>,
    pub(crate) nested_virtualization: bool,
    pub(crate) rosetta: bool,
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initramfs: Option<PathBuf>,
    pub(crate) disks: Vec<PathBuf>,
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
    use crate::commands::Command;

    #[test]
    fn create_command_parses_profile_form() {
        let cli = Cli::try_parse_from(["bento", "create", "dev", "rust-dev"])
            .expect("create command should parse");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };
        assert_eq!(create.name, "dev");
        assert_eq!(create.profile.as_deref(), Some("rust-dev"));
    }

    #[test]
    fn create_command_parses_default_machine_happy_path() {
        let cli = Cli::try_parse_from(["bento", "create", "dev", "--start", "--default"])
            .expect("create command should parse");
        let Command::Create(create) = cli.command else {
            panic!("expected create command");
        };

        assert_eq!(create.name, "dev");
        assert_eq!(create.profile, None);
        assert!(create.start);
        assert!(create.default);
    }

    #[test]
    fn create_command_parses_vm_overrides() {
        let cli = Cli::try_parse_from([
            "bento",
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
        assert_eq!(create.overrides.disks.len(), 1);
        assert_eq!(create.overrides.mounts.len(), 1);
        assert_eq!(
            create.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }

    #[test]
    fn create_command_rejects_bare_memory_and_disk_size() {
        assert!(
            Cli::try_parse_from(["bento", "create", "dev", "rust-dev", "--memory", "4096"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["bento", "create", "dev", "rust-dev", "--disk-size", "40"])
                .is_err()
        );
    }
}

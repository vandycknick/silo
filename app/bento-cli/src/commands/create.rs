use bento_libvm::{MachineCreate, MachineNetworkConfig, Runtime};
use bento_utils::HumanSize;
use bento_vm_spec::Mount;
use clap::Args;
use eyre::Context;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

use crate::commands::profile::{parse_label, parse_machine_network_config, parse_profile_mount};
use crate::commands::rootfs_image::{get_base_rootfs_image, record_base_rootfs_metadata};
use crate::commands::start_options::machine_start_options;
use crate::config::GlobalConfig;
use crate::constants::{DEFAULT_PROFILE_NAME, PROFILE_METADATA_KEY};
use crate::profile::{resolve_host_path, MountMode, ProfileStore};
use crate::progress::Progress;

#[derive(Args, Debug)]
#[command(
    about = "Create a persistent VM from a profile or image",
    after_help = "Examples:\n  bento create dev --start --default\n  bento create dev rust-dev --start\n  bento create dev --profile rust-dev\n  bento create ubuntu --image ubuntu:24.04\n  bento create dev rust-dev --image disk:./target/rootfs.img\n"
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
    pub overrides: VmOverrideArgs,
}

#[derive(Args, Debug, Default)]
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
    pub mounts: Vec<crate::profile::ProfileMount>,
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

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &Runtime) -> eyre::Result<()> {
        let progress = Progress::start("reading VM recipe");
        let mut resolved = self.resolve()?;
        progress.step("finding boot assets");
        let data_dir = libvm.local_data_dir();
        let boot_assets =
            resolve_boot_assets(data_dir, resolved.kernel.take(), resolved.initramfs.take());
        let base_rootfs = {
            let image_progress = |event| progress.image(event);
            get_base_rootfs_image(libvm, &resolved.image_ref, Some(&image_progress)).await?
        };
        record_base_rootfs_metadata(&mut resolved.metadata, &base_rootfs);
        let request = MachineCreate {
            image_ref: resolved.image_ref.clone(),
            base_rootfs_path: base_rootfs.path,
            name: self.name.clone(),
            labels: resolved.labels,
            metadata: resolved.metadata,
            cpus: resolved.cpus,
            memory_mib: resolved.memory_mib,
            kernel: Some(boot_assets.kernel),
            initramfs: boot_assets.initramfs,
            disk_size_bytes: resolved.disk_size_bytes,
            nested_virtualization: resolved.nested_virtualization,
            rosetta: resolved.rosetta,
            userdata: resolved.userdata,
            disks: resolved.disks,
            mounts: resolved.mounts,
            network: Some(resolved.network),
        };

        progress.step(format!("creating VM {}", self.name));
        let machine = libvm.create_machine(request).await?;
        progress.clear();
        println!("created {}", self.name);

        if self.default {
            GlobalConfig::write_default_machine(Some(&self.name))?;
            println!("default machine is {}", self.name);
        }

        if self.start {
            let progress = Progress::start(format!("starting {}", self.name));
            machine
                .start_with(machine_start_options(libvm, &machine)?)
                .await?;
            progress.success(format!("{} started", self.name));
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
        let mut image_ref;
        let mut network = MachineNetworkConfig::default();
        let mut userdata = None;
        let mut cpus = None;
        let mut memory_mib = None;
        let mut disk_size_bytes = None;

        if let Some(profile_name) = profile_name {
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&profile_name)?;
            image_ref = named.profile.image.clone();
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
        } else {
            let Some(image) = &self.image else {
                unreachable!("profile_name defaults when image is absent")
            };
            image_ref = image.clone();
            for (key, value) in &self.overrides.labels {
                labels.insert(key.clone(), value.clone());
            }
            for mount in &self.overrides.mounts {
                mounts.push(profile_mount_to_mount(mount)?);
            }
        }
        if let Some(image) = &self.image {
            image_ref = image.clone();
        }
        if let Some(network_override) = self.overrides.network.clone() {
            network = network_override;
        }
        if let Some(userdata_path) = self.overrides.userdata.as_deref() {
            userdata = Some(read_userdata_path(userdata_path)?);
        }

        Ok(ResolvedCreate {
            image_ref,
            labels,
            metadata,
            mounts,
            network,
            userdata,
            cpus: self.overrides.cpus.or(cpus),
            memory_mib: self.overrides.memory_mib()?.or(memory_mib),
            kernel: self.overrides.kernel.clone(),
            initramfs: self.overrides.initramfs.clone(),
            disk_size_bytes: self.overrides.disk_size_bytes()?.or(disk_size_bytes),
            nested_virtualization: self.overrides.nested_virtualization,
            rosetta: self.overrides.rosetta,
            disks: self.overrides.disks.clone(),
        })
    }
}

pub(crate) struct BootAssets {
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: Option<PathBuf>,
}

pub(crate) fn resolve_boot_assets(
    data_dir: &Path,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
) -> BootAssets {
    let assets_dir = data_dir.join("assets");
    BootAssets {
        kernel: kernel.unwrap_or_else(|| assets_dir.join("default")),
        initramfs,
    }
}

struct ResolvedCreate {
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    mounts: Vec<Mount>,
    network: MachineNetworkConfig,
    userdata: Option<String>,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    disk_size_bytes: Option<u64>,
    nested_virtualization: bool,
    rosetta: bool,
    disks: Vec<PathBuf>,
}

pub(crate) fn profile_mount_to_mount(mount: &crate::profile::ProfileMount) -> eyre::Result<Mount> {
    Ok(Mount {
        source: resolve_host_path(&mount.source)?,
        tag: mount.target.clone(),
        read_only: mount.mode == MountMode::Ro,
    })
}

pub(crate) fn read_userdata_path(path: &std::path::Path) -> eyre::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read userdata {}", path.display()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::path::{Path, PathBuf};

    use crate::commands::create::resolve_boot_assets;
    use crate::commands::{BentoCmd, Command};

    #[test]
    fn default_boot_assets_use_flat_data_assets_dir() {
        let assets = resolve_boot_assets(Path::new("/data/bento"), None, None);

        assert_eq!(assets.kernel, PathBuf::from("/data/bento/assets/default"));
        assert_eq!(assets.initramfs, None);
    }

    #[test]
    fn explicit_boot_assets_override_defaults_independently() {
        let assets = resolve_boot_assets(
            Path::new("/data/bento"),
            Some(PathBuf::from("./kernel")),
            None,
        );

        assert_eq!(assets.kernel, PathBuf::from("./kernel"));
        assert_eq!(assets.initramfs, None);
    }

    #[test]
    fn explicit_initramfs_is_forwarded_to_libvm() {
        let assets = resolve_boot_assets(
            Path::new("/data/bento"),
            None,
            Some(PathBuf::from("./initrd.img")),
        );

        assert_eq!(assets.kernel, PathBuf::from("/data/bento/assets/default"));
        assert_eq!(assets.initramfs, Some(PathBuf::from("./initrd.img")));
    }

    #[test]
    fn create_command_parses_profile_form() {
        let cmd = BentoCmd::try_parse_from(["bento", "create", "dev", "rust-dev"])
            .expect("create command should parse");
        let create = match cmd.cmd {
            Command::Create(cmd) => cmd,
            other => panic!("expected create command, got {other:?}"),
        };
        assert_eq!(create.name, "dev");
        assert_eq!(create.profile.as_deref(), Some("rust-dev"));
    }

    #[test]
    fn create_command_parses_default_machine_happy_path() {
        let cmd = BentoCmd::try_parse_from(["bento", "create", "dev", "--start", "--default"])
            .expect("create command should parse");
        let create = match cmd.cmd {
            Command::Create(cmd) => cmd,
            other => panic!("expected create command, got {other:?}"),
        };

        assert_eq!(create.name, "dev");
        assert_eq!(create.profile, None);
        assert!(create.start);
        assert!(create.default);
    }

    #[test]
    fn create_image_override_takes_precedence_over_profile_image() {
        let cmd = BentoCmd::try_parse_from([
            "bento",
            "create",
            "dev",
            "default",
            "--image",
            "disk:./target/rootfs.img",
        ])
        .expect("create command should parse");
        let create = match cmd.cmd {
            Command::Create(cmd) => cmd,
            other => panic!("expected create command, got {other:?}"),
        };

        let resolved = create.resolve().expect("resolve create command");

        assert_eq!(resolved.image_ref, "disk:./target/rootfs.img");
    }

    #[test]
    fn create_command_parses_vm_overrides() {
        let cmd = BentoCmd::try_parse_from([
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
        let create = match cmd.cmd {
            Command::Create(cmd) => cmd,
            other => panic!("expected create command, got {other:?}"),
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
        assert_eq!(create.overrides.disks.len(), 1);
        assert_eq!(create.overrides.mounts.len(), 1);
        assert_eq!(
            create.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }

    #[test]
    fn create_command_rejects_bare_memory_and_disk_size() {
        assert!(BentoCmd::try_parse_from([
            "bento", "create", "dev", "rust-dev", "--memory", "4096"
        ])
        .is_err());
        assert!(BentoCmd::try_parse_from([
            "bento",
            "create",
            "dev",
            "rust-dev",
            "--disk-size",
            "40"
        ])
        .is_err());
    }
}

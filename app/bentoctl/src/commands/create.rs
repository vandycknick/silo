use bento_core::Mount;
use bento_libvm::{CreateMachineRequest, LibVm, MachineRef};
use clap::Args;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use crate::commands::profile::{parse_label, parse_network_mode, parse_profile_mount};
use crate::constants::{NETWORK_POLICY_METADATA_KEY, PROFILE_METADATA_KEY};
use crate::profile::{
    network_driver_name, resolve_host_path, MountMode, NetworkMode, ProfileStore,
};

#[derive(Args, Debug)]
#[command(
    about = "Create a persistent VM from a profile or image",
    after_help = "Examples:\n  bento create dev rust-dev\n  bento create dev rust-dev --start\n  bento create dev --profile rust-dev\n  bento create ubuntu --image ubuntu:24.04\n"
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
    /// Image reference to create from without using a profile.
    #[arg(long)]
    pub image: Option<String>,
    /// Start the VM immediately after it is created.
    #[arg(long)]
    pub start: bool,
    #[command(flatten)]
    pub overrides: VmOverrideArgs,
}

#[derive(Args, Debug, Default)]
pub(crate) struct VmOverrideArgs {
    /// Number of virtual CPUs.
    #[arg(long)]
    pub cpus: Option<u8>,
    /// Virtual machine RAM size in mibibytes.
    #[arg(long)]
    pub memory: Option<u32>,
    /// Path to a custom kernel. Only works for Linux.
    #[arg(long)]
    pub kernel: Option<PathBuf>,
    /// Path to a custom initramfs image. Only works for Linux.
    #[arg(long = "initramfs", visible_alias = "initrd")]
    pub initramfs: Option<PathBuf>,
    /// Resize the image-backed root disk to this size in GB.
    #[arg(long, value_name = "GB")]
    pub disk_size: Option<u64>,
    /// Enable nested virtualization for supported VZ guests.
    #[arg(long)]
    pub nested_virtualization: bool,
    /// Enable the Bento guest agent.
    #[arg(long)]
    pub agent: bool,
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
    /// Override the profile network mode. Allowed: isolated, none.
    #[arg(long, value_parser = parse_network_mode)]
    pub network: Option<NetworkMode>,
    /// Add or override a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub labels: Vec<(String, String)>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        let resolved = self.resolve()?;
        let request = CreateMachineRequest {
            image_ref: resolved.image_ref.clone(),
            name: self.name.clone(),
            labels: resolved.labels,
            metadata: resolved.metadata,
            cpus: resolved.cpus,
            memory_mib: resolved.memory_mib,
            kernel: resolved.kernel,
            initramfs: resolved.initramfs,
            disk_size_gb: resolved.disk_size_gb,
            nested_virtualization: resolved.nested_virtualization,
            agent: resolved.ssh_enabled,
            rosetta: resolved.rosetta,
            userdata: resolved.userdata,
            disks: resolved.disks,
            mounts: resolved.mounts,
            network: Some(network_driver_name(resolved.network).to_string()),
        };

        libvm.create_from_image(request)?;
        println!("created {}", self.name);

        if self.start {
            libvm.start(&MachineRef::parse(self.name.clone())?).await?;
        }

        Ok(())
    }

    fn resolve(&self) -> eyre::Result<ResolvedCreate> {
        if self.profile.is_some() && self.profile_name.is_some() {
            eyre::bail!("profile specified twice; use either positional profile or --profile");
        }
        let profile_name = self.profile.clone().or_else(|| self.profile_name.clone());
        if profile_name.is_some() && self.image.is_some() {
            eyre::bail!("use either a profile or --image, not both");
        }

        let mut labels = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut mounts = Vec::new();
        let image_ref;
        let mut network = NetworkMode::Isolated;
        let mut ssh_enabled = true;

        if let Some(profile_name) = profile_name {
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&profile_name)?;
            image_ref = named.profile.image.reference.clone();
            network = named.profile.network_mode();
            ssh_enabled = named
                .profile
                .ssh
                .as_ref()
                .map(|ssh| ssh.enabled)
                .unwrap_or(true);
            labels = named.profile.labels.clone();
            metadata.insert(PROFILE_METADATA_KEY.to_string(), named.name.clone());
            mounts = named.profile.resolved_mounts()?;
            for (key, value) in &self.overrides.labels {
                labels.insert(key.clone(), value.clone());
            }
            for mount in &self.overrides.mounts {
                mounts.push(profile_mount_to_mount(mount)?);
            }
            if let Some(network_override) = self.overrides.network {
                network = network_override;
            }
            if network == NetworkMode::Isolated {
                insert_network_policy_metadata(&mut metadata, &named.profile)?;
            }
            return Ok(ResolvedCreate::new(
                image_ref,
                labels,
                metadata,
                mounts,
                network,
                ssh_enabled,
                &self.overrides,
            ));
        }

        let Some(image) = &self.image else {
            eyre::bail!("either a profile or image is required\n\nexamples:\n  bento create dev rust-dev\n  bento create dev --profile rust-dev\n  bento create dev --image ubuntu:24.04");
        };

        image_ref = image.clone();
        for (key, value) in &self.overrides.labels {
            labels.insert(key.clone(), value.clone());
        }
        for mount in &self.overrides.mounts {
            mounts.push(profile_mount_to_mount(mount)?);
        }
        if let Some(network_override) = self.overrides.network {
            network = network_override;
        }

        Ok(ResolvedCreate::new(
            image_ref,
            labels,
            metadata,
            mounts,
            network,
            ssh_enabled,
            &self.overrides,
        ))
    }
}

fn insert_network_policy_metadata(
    metadata: &mut BTreeMap<String, String>,
    profile: &crate::profile::Profile,
) -> eyre::Result<()> {
    let Some(policy) = profile
        .network
        .as_ref()
        .and_then(|network| network.policy.as_ref())
    else {
        return Ok(());
    };
    metadata.insert(
        NETWORK_POLICY_METADATA_KEY.to_string(),
        serde_json::to_string(policy)?,
    );
    Ok(())
}

struct ResolvedCreate {
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    mounts: Vec<Mount>,
    network: NetworkMode,
    ssh_enabled: bool,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    disk_size_gb: Option<u64>,
    nested_virtualization: bool,
    rosetta: bool,
    userdata: Option<PathBuf>,
    disks: Vec<PathBuf>,
}

impl ResolvedCreate {
    fn new(
        image_ref: String,
        labels: BTreeMap<String, String>,
        metadata: BTreeMap<String, String>,
        mounts: Vec<Mount>,
        network: NetworkMode,
        ssh_enabled: bool,
        overrides: &VmOverrideArgs,
    ) -> Self {
        Self {
            image_ref,
            labels,
            metadata,
            mounts,
            network,
            ssh_enabled: ssh_enabled || overrides.agent,
            cpus: overrides.cpus,
            memory_mib: overrides.memory,
            kernel: overrides.kernel.clone(),
            initramfs: overrides.initramfs.clone(),
            disk_size_gb: overrides.disk_size,
            nested_virtualization: overrides.nested_virtualization,
            rosetta: overrides.rosetta,
            userdata: overrides.userdata.clone(),
            disks: overrides.disks.clone(),
        }
    }
}

pub(crate) fn profile_mount_to_mount(mount: &crate::profile::ProfileMount) -> eyre::Result<Mount> {
    Ok(Mount {
        source: resolve_host_path(&mount.source)?,
        tag: mount.target.clone(),
        read_only: mount.mode == MountMode::Ro,
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::commands::{BentoCtlCmd, Command};

    #[test]
    fn create_command_parses_profile_form() {
        let cmd = BentoCtlCmd::try_parse_from(["bento", "create", "dev", "rust-dev"])
            .expect("create command should parse");
        let create = match cmd.cmd {
            Command::Create(cmd) => cmd,
            other => panic!("expected create command, got {other:?}"),
        };
        assert_eq!(create.name, "dev");
        assert_eq!(create.profile.as_deref(), Some("rust-dev"));
        assert!(!create.overrides.agent);
    }

    #[test]
    fn create_command_parses_vm_overrides() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bento",
            "create",
            "dev",
            "rust-dev",
            "--cpus",
            "4",
            "--memory",
            "4096",
            "--kernel",
            "./vmlinuz",
            "--initrd",
            "./initrd.img",
            "--disk-size",
            "40",
            "--nested-virtualization",
            "--agent",
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
        assert_eq!(create.overrides.memory, Some(4096));
        assert_eq!(create.overrides.disk_size, Some(40));
        assert!(create.overrides.nested_virtualization);
        assert!(create.overrides.agent);
        assert!(create.overrides.rosetta);
        assert_eq!(create.overrides.disks.len(), 1);
        assert_eq!(create.overrides.mounts.len(), 1);
        assert_eq!(
            create.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }
}

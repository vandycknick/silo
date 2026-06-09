use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use bento_core::Mount;
use bento_libvm::{CreateMachineRequest, LibVm, MachineRef, RequestedNetwork};
use clap::Args;

use crate::commands::create::{
    profile_mount_to_mount, read_userdata_path, resolve_boot_assets, VmOverrideArgs,
};
use crate::commands::rootfs_image::{get_base_rootfs_image, record_base_rootfs_metadata};
use crate::constants::{DEFAULT_PROFILE_NAME, PROFILE_METADATA_KEY};
use crate::profile::ProfileStore;
use crate::ssh;

#[derive(Args, Debug)]
#[command(
    about = "Run an ephemeral VM from a profile or image",
    after_help = "Examples:\n  bento run\n  bento run dev\n  bento run dev -- cargo test\n  bento run dev --image disk:./target/rootfs.img -- cargo test\n  bento run dev --keep-on-failure -- cargo test\n"
)]
pub struct Cmd {
    /// Profile to run. Defaults to the default profile when omitted.
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Profile name. Alternative to the positional profile argument.
    #[arg(long = "profile")]
    pub profile_name: Option<String>,
    /// Image reference to run. Overrides the profile image when both are set.
    #[arg(long)]
    pub image: Option<String>,
    /// Keep the ephemeral VM after the shell or command exits.
    #[arg(long)]
    pub keep: bool,
    /// Keep the ephemeral VM only when the guest command exits non-zero.
    #[arg(long)]
    pub keep_on_failure: bool,
    #[command(flatten)]
    pub overrides: VmOverrideArgs,
    /// Guest command and arguments to execute after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl Display for Cmd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "run")
    }
}

impl Cmd {
    pub async fn run(&self, libvm: &LibVm) -> eyre::Result<()> {
        if self.keep_on_failure && self.command.is_empty() {
            eyre::bail!("--keep-on-failure requires a command");
        }

        let mut resolved = self.resolve(libvm).await?;
        if !resolved.ssh_enabled {
            eyre::bail!("profile ssh.enabled is false; bento run needs SSH to open a shell or execute a command");
        }
        let boot_assets = resolve_boot_assets(
            libvm.layout().data_dir(),
            resolved.kernel.take(),
            resolved.initramfs.take(),
        );
        let base_rootfs = get_base_rootfs_image(libvm, &resolved.image_ref).await?;
        record_base_rootfs_metadata(&mut resolved.metadata, &base_rootfs);
        let request = CreateMachineRequest {
            image_ref: resolved.image_ref.clone(),
            base_rootfs_path: base_rootfs.path,
            name: resolved.name.clone(),
            labels: resolved.labels,
            metadata: resolved.metadata,
            cpus: resolved.cpus,
            memory_mib: resolved.memory_mib,
            kernel: Some(boot_assets.kernel),
            initramfs: boot_assets.initramfs,
            disk_size_bytes: resolved.disk_size_bytes,
            nested_virtualization: resolved.nested_virtualization,
            agent: resolved.ssh_enabled,
            rosetta: resolved.rosetta,
            userdata: resolved.userdata,
            disks: resolved.disks,
            mounts: resolved.mounts,
            network: Some(resolved.network),
        };

        let machine = libvm.create_from_base_image(request).await?;
        let machine_ref = MachineRef::Id(machine.id);
        let machine = libvm.start(&machine_ref).await?;
        if machine.spec.settings.agent {
            libvm
                .wait_for_guest_running(&machine_ref, bento_libvm::DEFAULT_GUEST_READINESS_TIMEOUT)
                .await
                .map_err(|err| eyre::eyre!("guest readiness check failed: {err}"))?;
        }

        let status = if self.command.is_empty() {
            ssh::run_remote_shell_status(&resolved.name, None)?
        } else {
            ssh::run_remote_command(&resolved.name, None, &self.command)?
        };
        let code = status.code().unwrap_or(1);
        let should_keep = self.keep || (self.keep_on_failure && code != 0);

        if !should_keep {
            cleanup_ephemeral(libvm, &resolved.name).await?;
        } else {
            println!("kept {}", resolved.name);
        }

        std::process::exit(code);
    }

    async fn resolve(&self, libvm: &LibVm) -> eyre::Result<ResolvedRun> {
        if self.profile.is_some() && self.profile_name.is_some() {
            eyre::bail!("profile specified twice; use either positional profile or --profile");
        }

        let mut labels = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut mounts = Vec::<Mount>::new();
        let mut network = RequestedNetwork::default();
        let mut ssh_enabled = true;
        let mut userdata = None;
        let mut cpus = None;
        let mut memory_mib = None;
        let mut disk_size_bytes = None;
        let mut image_ref;
        let prefix;

        let selected_profile = self.profile.clone().or_else(|| self.profile_name.clone());
        if selected_profile.is_some() || self.image.is_none() {
            let selected = selected_profile.unwrap_or_else(|| DEFAULT_PROFILE_NAME.to_string());
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&selected)?;
            image_ref = named.profile.image.clone();
            network = named.profile.requested_network();
            ssh_enabled = named
                .profile
                .ssh
                .as_ref()
                .map(|ssh| ssh.enabled)
                .unwrap_or(true);
            userdata = named.profile.userdata.clone();
            cpus = named.profile.cpus();
            memory_mib = named.profile.memory_mib()?;
            disk_size_bytes = named.profile.disk_size_bytes()?;
            labels = named.profile.labels.clone();
            metadata.insert(PROFILE_METADATA_KEY.to_string(), named.name.clone());
            mounts = named.profile.resolved_mounts()?;
            prefix = named.name.clone();
        } else {
            let Some(image) = &self.image else {
                eyre::bail!("either a profile or image is required");
            };
            image_ref = image.clone();
            prefix = "run".to_string();
        }

        if let Some(image) = &self.image {
            image_ref = image.clone();
        }

        for (key, value) in &self.overrides.labels {
            labels.insert(key.clone(), value.clone());
        }
        for mount in &self.overrides.mounts {
            mounts.push(profile_mount_to_mount(mount)?);
        }
        if let Some(network_override) = self.overrides.network.clone() {
            network = network_override;
        }
        if let Some(userdata_path) = self.overrides.userdata.as_deref() {
            userdata = Some(read_userdata_path(userdata_path)?);
        }

        let name = libvm.allocate_ephemeral_name(&prefix).await?;
        Ok(ResolvedRun {
            name,
            image_ref,
            labels,
            metadata,
            mounts,
            network,
            ssh_enabled: ssh_enabled || self.overrides.agent,
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

struct ResolvedRun {
    name: String,
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    mounts: Vec<Mount>,
    network: RequestedNetwork,
    ssh_enabled: bool,
    userdata: Option<String>,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    kernel: Option<std::path::PathBuf>,
    initramfs: Option<std::path::PathBuf>,
    disk_size_bytes: Option<u64>,
    nested_virtualization: bool,
    rosetta: bool,
    disks: Vec<std::path::PathBuf>,
}

async fn cleanup_ephemeral(libvm: &LibVm, name: &str) -> eyre::Result<()> {
    let machine = MachineRef::parse(name.to_string())?;
    match libvm.stop(&machine).await {
        Ok(_) => {}
        Err(err) if err.to_string().contains("is not running") => {}
        Err(err) => return Err(err.into()),
    }
    libvm.remove(&machine).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::path::{Path, PathBuf};

    use crate::commands::create::resolve_boot_assets;
    use crate::commands::{BentoCtlCmd, Command};

    #[test]
    fn run_command_parses_create_parity_overrides() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bento",
            "run",
            "dev",
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
        .expect("run command should parse");
        let run = match cmd.cmd {
            Command::Run(cmd) => cmd,
            other => panic!("expected run command, got {other:?}"),
        };

        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert_eq!(run.overrides.cpus, Some(4));
        assert_eq!(run.overrides.memory_mib().expect("memory mib"), Some(4096));
        assert_eq!(
            run.overrides.disk_size_bytes().expect("disk size bytes"),
            Some(40_000_000_000)
        );
        assert!(run.overrides.nested_virtualization);
        assert!(run.overrides.agent);
        assert!(run.overrides.rosetta);
        assert_eq!(run.overrides.disks.len(), 1);
        assert_eq!(run.overrides.mounts.len(), 1);
        assert_eq!(
            run.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }

    #[test]
    fn run_command_accepts_image_override_with_profile() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bento",
            "run",
            "dev",
            "--image",
            "tar:./target/rootfs.tar",
            "--",
            "true",
        ])
        .expect("run command should parse");
        let run = match cmd.cmd {
            Command::Run(cmd) => cmd,
            other => panic!("expected run command, got {other:?}"),
        };

        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert_eq!(run.image.as_deref(), Some("tar:./target/rootfs.tar"));
    }

    #[test]
    fn run_command_leaves_default_initramfs_for_libvm_generation() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bento",
            "run",
            "dev",
            "--image",
            "disk:./target/rootfs.img",
            "--",
            "true",
        ])
        .expect("run command should parse");
        let run = match cmd.cmd {
            Command::Run(cmd) => cmd,
            other => panic!("expected run command, got {other:?}"),
        };

        let assets = resolve_boot_assets(
            Path::new("/data/bento"),
            run.overrides.kernel.clone(),
            run.overrides.initramfs.clone(),
        );

        assert_eq!(assets.kernel, PathBuf::from("/data/bento/assets/default"));
        assert_eq!(assets.initramfs, None);
    }

    #[test]
    fn run_command_forwards_explicit_initramfs_to_libvm() {
        let cmd = BentoCtlCmd::try_parse_from([
            "bento",
            "run",
            "dev",
            "--initrd",
            "./initrd.img",
            "--",
            "true",
        ])
        .expect("run command should parse");
        let run = match cmd.cmd {
            Command::Run(cmd) => cmd,
            other => panic!("expected run command, got {other:?}"),
        };

        let assets = resolve_boot_assets(
            Path::new("/data/bento"),
            run.overrides.kernel.clone(),
            run.overrides.initramfs.clone(),
        );

        assert_eq!(assets.kernel, PathBuf::from("/data/bento/assets/default"));
        assert_eq!(assets.initramfs, Some(PathBuf::from("./initrd.img")));
    }

    #[test]
    fn run_command_rejects_bare_memory_and_disk_size() {
        assert!(BentoCtlCmd::try_parse_from(["bento", "run", "dev", "--memory", "4096"]).is_err());
        assert!(BentoCtlCmd::try_parse_from(["bento", "run", "dev", "--disk-size", "40"]).is_err());
    }
}

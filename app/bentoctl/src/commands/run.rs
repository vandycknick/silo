use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use bento_core::Mount;
use bento_libvm::{CreateMachineRequest, LibVm, MachineRef};
use clap::Args;

use crate::commands::create::{profile_mount_to_mount, VmOverrideArgs};
use crate::constants::{DEFAULT_PROFILE_NAME, NETWORK_POLICY_METADATA_KEY, PROFILE_METADATA_KEY};
use crate::profile::{network_driver_name, NetworkMode, ProfileStore};
use crate::ssh;

#[derive(Args, Debug)]
#[command(
    about = "Run an ephemeral VM from a profile or image",
    after_help = "Examples:\n  bento run\n  bento run dev\n  bento run dev -- cargo test\n  bento run dev --keep-on-failure -- cargo test\n"
)]
pub struct Cmd {
    /// Profile to run. Defaults to the default profile when omitted.
    #[arg(value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Profile name. Alternative to the positional profile argument.
    #[arg(long = "profile")]
    pub profile_name: Option<String>,
    /// Image reference to run without using a profile.
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

        let resolved = self.resolve(libvm)?;
        if !resolved.ssh_enabled {
            eyre::bail!("profile ssh.enabled is false; bento run needs SSH to open a shell or execute a command");
        }
        let request = CreateMachineRequest {
            image_ref: resolved.image_ref.clone(),
            name: resolved.name.clone(),
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

        let machine = libvm.create_from_image(request)?;
        let machine_ref = MachineRef::Id(machine.id);
        let machine = libvm.start(&machine_ref).await?;
        if machine.spec.guest_agent().is_some() {
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

    fn resolve(&self, libvm: &LibVm) -> eyre::Result<ResolvedRun> {
        if self.profile.is_some() && self.profile_name.is_some() {
            eyre::bail!("profile specified twice; use either positional profile or --profile");
        }
        if (self.profile.is_some() || self.profile_name.is_some()) && self.image.is_some() {
            eyre::bail!("use either a profile or --image, not both");
        }

        let mut labels = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut mounts = Vec::<Mount>::new();
        let mut network = NetworkMode::Isolated;
        let mut network_policy_metadata = None;
        let mut ssh_enabled = true;
        let image_ref;
        let prefix;

        if let Some(image) = &self.image {
            image_ref = image.clone();
            prefix = "run".to_string();
        } else {
            let selected = self
                .profile
                .clone()
                .or_else(|| self.profile_name.clone())
                .unwrap_or_else(|| DEFAULT_PROFILE_NAME.to_string());
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&selected)?;
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
            network_policy_metadata = network_policy_json(&named.profile)?;
            mounts = named.profile.resolved_mounts()?;
            prefix = named.name.clone();
        }

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
            if let Some(policy) = network_policy_metadata {
                metadata.insert(NETWORK_POLICY_METADATA_KEY.to_string(), policy);
            }
        }

        let name = libvm.allocate_ephemeral_name(&prefix)?;
        Ok(ResolvedRun {
            name,
            image_ref,
            labels,
            metadata,
            mounts,
            network,
            ssh_enabled: ssh_enabled || self.overrides.agent,
            cpus: self.overrides.cpus,
            memory_mib: self.overrides.memory,
            kernel: self.overrides.kernel.clone(),
            initramfs: self.overrides.initramfs.clone(),
            disk_size_gb: self.overrides.disk_size,
            nested_virtualization: self.overrides.nested_virtualization,
            rosetta: self.overrides.rosetta,
            userdata: self.overrides.userdata.clone(),
            disks: self.overrides.disks.clone(),
        })
    }
}

fn network_policy_json(profile: &crate::profile::Profile) -> eyre::Result<Option<String>> {
    let Some(policy) = profile
        .network
        .as_ref()
        .and_then(|network| network.policy.as_ref())
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::to_string(policy)?))
}

struct ResolvedRun {
    name: String,
    image_ref: String,
    labels: BTreeMap<String, String>,
    metadata: BTreeMap<String, String>,
    mounts: Vec<Mount>,
    network: NetworkMode,
    ssh_enabled: bool,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    kernel: Option<std::path::PathBuf>,
    initramfs: Option<std::path::PathBuf>,
    disk_size_gb: Option<u64>,
    nested_virtualization: bool,
    rosetta: bool,
    userdata: Option<std::path::PathBuf>,
    disks: Vec<std::path::PathBuf>,
}

async fn cleanup_ephemeral(libvm: &LibVm, name: &str) -> eyre::Result<()> {
    let machine = MachineRef::parse(name.to_string())?;
    match libvm.stop(&machine).await {
        Ok(_) => {}
        Err(err) if err.to_string().contains("is not running") => {}
        Err(err) => return Err(err.into()),
    }
    libvm.remove(&machine)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

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
        .expect("run command should parse");
        let run = match cmd.cmd {
            Command::Run(cmd) => cmd,
            other => panic!("expected run command, got {other:?}"),
        };

        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert_eq!(run.overrides.cpus, Some(4));
        assert_eq!(run.overrides.memory, Some(4096));
        assert_eq!(run.overrides.disk_size, Some(40));
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
}

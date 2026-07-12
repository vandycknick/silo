use clap::Args;
use libvm::{ImageProgressSender, MachineRef, Runtime, DEFAULT_GUEST_READINESS_TIMEOUT};
use std::collections::BTreeMap;
use vm_spec::Mount;

use crate::commands::create::{
    apply_resolved_machine_options, profile_mount_to_mount, read_userdata_path,
    ResolvedMachineOptions, VmOverrideArgs,
};
use crate::commands::rootfs_image::parse_cli_image_source;
use crate::commands::start_options::machine_start_options;
use crate::constants::{DEFAULT_PROFILE_NAME, PROFILE_METADATA_KEY};
use crate::context::Context;
use crate::guest;
use crate::profile::{ProfileStore, ResolvedMachineNetwork};
use crate::ui::{watch_image_progress, Spinner};

const EXAMPLES: &[&str] = &[
    "silo run",
    "silo run dev",
    "silo run dev -- cargo test",
    "silo run -t agent -- opencode",
    "silo run dev --image disk:./target/rootfs.img -- cargo test",
    "silo run dev --keep-on-failure -- cargo test",
];

#[derive(Debug, Args)]
#[command(
    about = "Run an ephemeral VM from a profile or image",
    after_help = crate::help::examples(EXAMPLES)
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
    /// Attach a TTY to the guest command.
    #[arg(long, short = 't')]
    pub tty: bool,
    #[command(flatten)]
    pub(crate) overrides: VmOverrideArgs,
    /// Guest command and arguments to execute after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        if self.keep_on_failure && self.command.is_empty() {
            eyre::bail!("--keep-on-failure requires a command");
        }

        let policy_config_dir = context.config()?.networking.policy_config_dir.clone();
        let progress = Spinner::start("Reading", "run recipe");
        let resolved = self.resolve(policy_config_dir.as_deref())?;
        let runtime = context.runtime().await?;
        progress.finish_clear();
        let image_source = parse_cli_image_source(&resolved.image_ref)?;
        let (image_progress, image_events) = ImageProgressSender::default_channel();
        let image_progress_task = watch_image_progress(resolved.image_ref.clone(), image_events);
        let machine_options = resolved.options;
        let machine = {
            let runtime_with_progress = (*runtime).clone().with_image_progress(image_progress);
            let builder = runtime_with_progress.machine().image_source(image_source);

            apply_resolved_machine_options(builder, machine_options)
                .create()
                .await
        };
        let _ = image_progress_task.await;
        let machine = machine?;
        let machine_name = machine.inspect().await?.name;
        let mut progress = Spinner::start("Starting", &machine_name);
        machine
            .start_with_options(machine_start_options(runtime, &machine).await?)
            .await?;
        progress.step("Waiting", &machine_name);
        machine
            .wait_for_guest_running(DEFAULT_GUEST_READINESS_TIMEOUT)
            .await
            .map_err(|error| eyre::eyre!("guest readiness check failed: {error}"))?;

        progress.step("Ready", &machine_name);
        progress.finish_success("Started");

        let status = if self.command.is_empty() {
            guest::attach_shell(&machine, None, false).await?
        } else if self.tty {
            guest::attach_command(&machine, None, &self.command, false).await?
        } else {
            guest::run_command_streaming(&machine, None, &self.command, false).await?
        };
        let code = status.code;
        let should_keep = self.keep || (self.keep_on_failure && code != 0);

        if !should_keep {
            cleanup_ephemeral(runtime, &machine_name).await?;
        }

        std::process::exit(code);
    }

    fn resolve(&self, policy_config_dir: Option<&std::path::Path>) -> eyre::Result<ResolvedRun> {
        if self.profile.is_some() && self.profile_name.is_some() {
            eyre::bail!("profile specified twice; use either positional profile or --profile");
        }

        let mut labels = BTreeMap::new();
        let mut metadata = BTreeMap::new();
        let mut mounts = Vec::<Mount>::new();
        let mut network = ResolvedMachineNetwork::default();
        let mut userdata = None;
        let mut cpus = None;
        let mut memory_mib = None;
        let mut disk_size_bytes = None;

        let selected_profile = self.profile.clone().or_else(|| self.profile_name.clone());
        let mut image_ref = if selected_profile.is_some() || self.image.is_none() {
            let selected = selected_profile.unwrap_or_else(|| DEFAULT_PROFILE_NAME.to_string());
            let store = ProfileStore::from_env()?;
            let named = store.resolve(&selected)?;
            network = named.profile.machine_network(policy_config_dir)?;
            userdata = named.profile.userdata.clone();
            cpus = named.profile.cpus();
            memory_mib = named.profile.memory_mib()?;
            disk_size_bytes = named.profile.disk_size_bytes()?;
            labels = named.profile.labels.clone();
            metadata.insert(PROFILE_METADATA_KEY.to_string(), named.name.clone());
            mounts = named.profile.resolved_mounts()?;
            named.profile.image.clone()
        } else if let Some(image) = &self.image {
            image.clone()
        } else {
            eyre::bail!("either a profile or image is required");
        };

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
            network = network_override.into();
        }
        if let Some(userdata_path) = self.overrides.userdata.as_deref() {
            userdata = Some(read_userdata_path(userdata_path)?);
        }

        Ok(ResolvedRun {
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
                agent: None,
                disks: self.overrides.disks.clone(),
            },
        })
    }
}

struct ResolvedRun {
    image_ref: String,
    options: ResolvedMachineOptions,
}

async fn cleanup_ephemeral(runtime: &Runtime, name: &str) -> eyre::Result<()> {
    let machine = runtime
        .get_machine(&MachineRef::parse(name.to_string())?)
        .await?;
    match machine.stop().await {
        Ok(_) => {}
        Err(error) if error.to_string().contains("is not running") => {}
        Err(error) => return Err(error.into()),
    }
    machine.remove().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::Command;

    #[test]
    fn run_command_parses_create_parity_overrides() {
        let cli = Cli::try_parse_from([
            "silo",
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
        let Command::Run(run) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert_eq!(run.overrides.cpus, Some(4));
        assert_eq!(run.overrides.memory_mib().expect("memory mib"), Some(4096));
        assert_eq!(
            run.overrides.disk_size_bytes().expect("disk size bytes"),
            Some(40 * 1024 * 1024 * 1024)
        );
        assert!(run.overrides.nested_virtualization);
        assert!(run.overrides.rosetta);
        assert_eq!(run.overrides.kernel.as_deref(), Some("./vmlinuz".as_ref()));
        assert_eq!(
            run.overrides.initramfs.as_deref(),
            Some("./initrd.img".as_ref())
        );
        assert_eq!(run.overrides.disks.len(), 1);
        assert_eq!(run.overrides.mounts.len(), 1);
        assert_eq!(
            run.overrides.labels,
            vec![("env".to_string(), "dev".to_string())]
        );
    }

    #[test]
    fn run_command_accepts_image_override_with_profile() {
        let cli = Cli::try_parse_from([
            "silo",
            "run",
            "dev",
            "--image",
            "tar:./target/rootfs.tar",
            "--",
            "true",
        ])
        .expect("run command should parse");
        let Command::Run(run) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(run.profile.as_deref(), Some("dev"));
        assert!(!run.tty);
        assert_eq!(run.image.as_deref(), Some("tar:./target/rootfs.tar"));
    }

    #[test]
    fn run_command_parses_tty_command() {
        let cli = Cli::try_parse_from(["silo", "run", "-t", "agent", "--", "opencode"])
            .expect("run command should parse");
        let Command::Run(run) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(run.profile.as_deref(), Some("agent"));
        assert!(run.tty);
        assert_eq!(run.command, vec!["opencode".to_string()]);
    }

    #[test]
    fn run_command_keeps_boot_overrides_for_libvm() {
        let cli = Cli::try_parse_from([
            "silo",
            "run",
            "dev",
            "--kernel",
            "./vmlinuz",
            "--initrd",
            "./initrd.img",
            "--",
            "true",
        ])
        .expect("run command should parse");
        let Command::Run(run) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(run.overrides.kernel.as_deref(), Some("./vmlinuz".as_ref()));
        assert_eq!(
            run.overrides.initramfs.as_deref(),
            Some("./initrd.img".as_ref())
        );
    }

    #[test]
    fn run_command_rejects_bare_memory_and_disk_size() {
        assert!(Cli::try_parse_from(["silo", "run", "dev", "--memory", "4096"]).is_err());
        assert!(Cli::try_parse_from(["silo", "run", "dev", "--disk-size", "40"]).is_err());
    }
}

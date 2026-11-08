use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use eyre::Context as _;
use libvm::{
    ImageProgressSender, ImagePullPolicy, MachineAgent, MachineRetention, MachineUserConfig,
    PublishBind, RuntimeConfig,
};
use nix::unistd::{Uid, User};

use crate::environment::{read_environment_file, EnvironmentLayer, EnvironmentOverride};
use crate::machine_defaults::{
    resolve_host_path, MachineMount, MachineNetwork, MachineNetworkSelection, MachineResources,
};
use crate::planning::{
    self, MachineCreationSettings, MachineOverrides, Plan, PlanKind, ProcessOverrides, PullPolicy,
    ResolveRequest, ResolvedImage,
};
use crate::template::{Template, TemplateStore};
use crate::ui::{success, watch_image_progress, OutputFormat, Spinner};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum Pull {
    Always,
    Missing,
    Never,
}

impl Pull {
    pub(crate) fn policy(self) -> ImagePullPolicy {
        match self {
            Self::Always => ImagePullPolicy::Always,
            Self::Missing => ImagePullPolicy::IfMissing,
            Self::Never => ImagePullPolicy::Never,
        }
    }

    fn plan_policy(self) -> PullPolicy {
        match self {
            Self::Always => PullPolicy::Always,
            Self::Missing => PullPolicy::IfMissing,
            Self::Never => PullPolicy::Never,
        }
    }

    pub(crate) fn policies(self) -> (ImagePullPolicy, PullPolicy) {
        (self.policy(), self.plan_policy())
    }
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct VmOverrideArgs {
    /// Number of virtual CPUs.
    #[arg(long)]
    pub(crate) cpus: Option<u8>,
    /// Virtual machine RAM size, for example 512mb or 4gb.
    #[arg(long, value_name = "SIZE")]
    pub(crate) memory: Option<String>,
    /// Path to a custom kernel. Only works for Linux.
    #[arg(long)]
    pub(crate) kernel: Option<PathBuf>,
    /// Path to a custom initramfs image. Only works for Linux.
    #[arg(long = "initramfs")]
    pub(crate) initramfs: Option<PathBuf>,
    /// Append an argument to the Linux kernel command line. May be repeated.
    #[arg(long = "kernel-arg", value_name = "ARG")]
    pub(crate) kernel_args: Vec<String>,
    /// Root disk size, or private upper backing capacity for a layered OCI root.
    #[arg(long = "disk-size", value_name = "SIZE")]
    pub(crate) disk_size: Option<String>,
    /// Explicit memory-charged, nonpersistent /tmp tmpfs capacity.
    #[arg(long, value_name = "SIZE")]
    pub(crate) tmpfs_size: Option<String>,
    /// Enable nested virtualization for supported VZ guests.
    #[arg(long)]
    pub(crate) nested_virtualization: bool,
    /// Rosetta intent: `--rosetta` enables, `--rosetta=false` explicitly disables,
    /// absence leaves no intent. Required translation is derived from the platform.
    #[arg(
        long,
        value_name = "BOOL",
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true
    )]
    pub(crate) rosetta: Option<bool>,
    /// Linux userspace platform: OCI manifest selection or disk import metadata
    /// (linux/amd64, linux/arm64[/v8]). Defaults to the host-native platform.
    #[arg(long, value_name = "PLATFORM", value_parser = parse_platform_arg)]
    pub(crate) platform: Option<libvm::LinuxPlatform>,
    /// Root of a disk: source: whole-disk (default), auto (GPT discoverable
    /// partitions), gpt:GUID or mbr:N. Never inferred from a partitioned disk.
    #[arg(long, value_name = "SELECTION", value_parser = parse_root_arg)]
    pub(crate) root: Option<libvm::ImportRootSelection>,
    /// Path to userdata file.
    #[arg(long, value_name = "PATH")]
    pub(crate) userdata: Option<PathBuf>,
    /// Path to an existing disk image.
    #[arg(long = "disk", value_name = "PATH")]
    pub(crate) disks: Vec<PathBuf>,
    /// Add a host mount. Format: SRC:DST[:ro|rw].
    #[arg(long = "mount", value_name = "SRC:DST[:MODE]", value_parser = parse_mount)]
    pub(crate) mounts: Vec<MachineMount>,
    /// Declare a forward. Format: LISTEN=CONNECT. May be repeated.
    #[arg(long = "forward", value_name = "LISTEN=CONNECT", value_parser = parse_forward)]
    pub(crate) forwards: Vec<libvm::Forward>,
    /// Enable the public vsock surface.
    #[arg(long)]
    pub(crate) vsock: bool,
    /// Override the network target. Allowed: private, none, NAME, or name:NAME.
    #[arg(long, value_parser = MachineNetworkSelection::parse)]
    pub(crate) network: Option<MachineNetworkSelection>,
    /// HCL or canonical JSON network policy (absolute path or configured policy name).
    #[arg(long, value_name = "POLICY")]
    pub(crate) network_policy: Option<String>,
    /// Allow guest requests for host TCP publications.
    #[arg(long, value_name = "loopback|any")]
    pub(crate) guest_publish: Option<PublishBind>,
    /// Add or override a label. Format: KEY=VALUE.
    #[arg(long = "label", value_name = "KEY=VALUE", value_parser = parse_label)]
    pub(crate) labels: Vec<(String, String)>,
    /// Provision a guest user. Omit the value for the current host user.
    #[arg(
        long,
        value_name = "NAME:UID:GID:HOME",
        num_args = 0..=1,
        default_missing_value = "auto",
        require_equals = true,
        value_parser = parse_user_arg
    )]
    pub(crate) provision_user: Option<UserArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserArg {
    Auto,
    Explicit(MachineUserConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct MachineCliOptions {
    pub(crate) overrides: MachineOverrides,
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initramfs: Option<PathBuf>,
    pub(crate) kernel_args: Vec<String>,
    pub(crate) nested_virtualization: bool,
    pub(crate) rosetta: Option<bool>,
    pub(crate) disks: Vec<PathBuf>,
    pub(crate) source: crate::api::types::SourceOptions,
    pub(crate) agent: Option<PathBuf>,
    pub(crate) no_agent: bool,
    pub(crate) provision_user: Option<MachineUserConfig>,
}

impl VmOverrideArgs {
    pub(crate) fn resolve(&self) -> eyre::Result<MachineCliOptions> {
        let resources = if self.cpus.is_some() || self.memory.is_some() {
            Some(MachineResources {
                cpus: self.cpus,
                memory: self.memory.clone(),
            })
        } else {
            None
        };
        let userdata = self
            .userdata
            .as_deref()
            .map(read_userdata_path)
            .transpose()?;
        let network = match (&self.network_policy, &self.network) {
            (Some(policy), None | Some(MachineNetworkSelection::Private)) => {
                Some(MachineNetwork::Private {
                    policy_ref: Some(policy.clone()),
                    publish: None,
                })
            }
            (Some(_), _) => eyre::bail!("--network-policy requires a private network"),
            (None, network) => network
                .clone()
                .map(MachineNetworkSelection::into_machine_network),
        };
        Ok(MachineCliOptions {
            overrides: MachineOverrides {
                resources,
                disk_size: self.disk_size.clone(),
                tmpfs_size: self.tmpfs_size.clone(),
                userdata,
                mounts: self.mounts.clone(),
                forwards: (!self.forwards.is_empty()).then(|| self.forwards.clone()),
                vsock: self.vsock.then_some(true),
                network,
                guest_publish: self.guest_publish,
                labels: self.labels.iter().cloned().collect(),
            },
            kernel: self.kernel.clone(),
            initramfs: self.initramfs.clone(),
            kernel_args: self.kernel_args.clone(),
            nested_virtualization: self.nested_virtualization,
            rosetta: self.rosetta,
            disks: self.disks.clone(),
            source: crate::api::types::SourceOptions {
                platform: self.platform.clone(),
                root: self.root.clone(),
            },
            agent: None,
            no_agent: false,
            provision_user: self
                .provision_user
                .as_ref()
                .map(resolve_user_arg)
                .transpose()?,
        })
    }
}

#[derive(Debug, Args)]
#[command(about = "Create a persistent stopped VM from an image or template")]
pub struct Cmd {
    /// OCI registry reference or disk:PATH. Overrides the template image.
    #[arg(value_name = "IMAGE")]
    image: Option<String>,
    /// Template providing VM defaults.
    #[arg(long, value_name = "TEMPLATE")]
    template: Option<String>,
    /// Name of the persistent VM.
    #[arg(short = 'n', long, value_name = "NAME")]
    name: Option<String>,
    /// Make the created VM the default.
    #[arg(long)]
    set_default: bool,
    /// Path to a custom managed guest agent.
    #[arg(long, value_name = "PATH", conflicts_with = "no_agent")]
    agent: Option<PathBuf>,
    /// Disable managed guest-agent injection.
    #[arg(long, conflicts_with = "agent")]
    no_agent: bool,
    /// Image pull policy.
    #[arg(long, value_enum)]
    pull: Option<Pull>,
    /// Render the resolved plan without creating a machine.
    #[arg(long)]
    dry_run: bool,
    /// Plan output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
    #[command(flatten)]
    pub(crate) overrides: VmOverrideArgs,
}

impl Cmd {
    pub async fn run(self, context: &mut crate::context::Context) -> eyre::Result<()> {
        let requested_name = self.name.clone();
        let template = load_template(self.template.as_deref())?;
        let mut machine = self.overrides.resolve()?;
        machine.agent = self.agent;
        machine.no_agent = self.no_agent;
        preflight_create(
            &template.template,
            &machine,
            self.image.as_deref(),
            context.config()?.networking().policy_config_dir.as_deref(),
        )?;

        if self.dry_run {
            let resolution = crate::api::AppApi::resolve_read_only_creation(
                RuntimeConfig::from_env()?.with_registry_policy(context.config()?.images().clone()),
                requested_name,
                self.image.as_deref(),
                &template.template,
                self.pull.map(Pull::policies),
                &machine.source,
            )
            .await?;
            let settings = machine_settings(&machine);
            let plan = resolve_plan(PlanInputs {
                kind: PlanKind::Create,
                template,
                image: resolution.source.plan_image,
                image_is_positional: resolution.source.is_positional,
                machine_overrides: machine.overrides,
                machine_settings: settings,
                process_overrides: ProcessOverrides::default(),
                command_tail: Vec::new(),
                retention: MachineRetention::Persistent,
                name: Some(resolution.name),
                environment_files: Vec::new(),
                host_environment: BTreeMap::new(),
                environment_overrides: Vec::new(),
            })?;
            return render_plan(&plan, self.format);
        }

        let image_reference = selected_image_reference(self.image.as_deref(), &template.template)?;
        let recipe_progress = Spinner::start("Reading", "VM recipe");
        if let Some(name) = &requested_name {
            context.app_api().await?.ensure_name_available(name).await?;
        }
        recipe_progress.finish_clear();

        let (image_progress, image_events) = ImageProgressSender::default_channel();
        let image_progress_task = watch_image_progress(&image_reference, image_events);
        let image_result = async {
            let source = context
                .app_api()
                .await?
                .resolve_source(
                    self.image.as_deref(),
                    &template.template,
                    self.pull.map(Pull::policies),
                    &machine.source,
                    image_progress.clone(),
                )
                .await?;
            // A snapshot restores its complete captured configuration through the
            // existing restore path; nothing implicit is synthesized over it.
            if let crate::api::types::ResolvedSource::Managed(libvm::ManagedSourceRef::Snapshot(
                id,
            )) = &source.source
            {
                ensure_snapshot_has_no_overrides(&machine, &template)?;
                let options = libvm::RestoreOptions {
                    name: requested_name,
                    external_resources: libvm::ExternalResourcePolicy::Reject,
                    activation_hook: None,
                    resources: Default::default(),
                };
                return context
                    .app_api()
                    .await?
                    .restore_snapshot(&format!("image:{id}"), options)
                    .await;
            }
            let settings = machine_settings(&machine);
            let plan = resolve_plan(PlanInputs {
                kind: PlanKind::Create,
                template,
                image: source.plan_image.clone(),
                image_is_positional: source.is_positional,
                machine_overrides: machine.overrides.clone(),
                machine_settings: settings,
                process_overrides: ProcessOverrides::default(),
                command_tail: Vec::new(),
                retention: MachineRetention::Persistent,
                name: requested_name,
                environment_files: Vec::new(),
                host_environment: BTreeMap::new(),
                environment_overrides: Vec::new(),
            })?;
            let Plan::Create(plan) = plan else {
                unreachable!("create resolution returns a create plan")
            };
            let policy_config_dir = context.config()?.networking().policy_config_dir.clone();
            context
                .app_api()
                .await?
                .create_machine(&plan, source, policy_config_dir.as_deref(), image_progress)
                .await
        };
        let image_result = image_result.await;
        let _ = image_progress_task.await;
        let name = image_result?.name;
        success(format!("Created {name}"));
        if self.set_default {
            crate::config::GlobalConfig::write_default_machine(Some(&name))?;
        }
        println!("{name}");
        Ok(())
    }
}

pub(crate) fn load_template(name: Option<&str>) -> eyre::Result<crate::template::NamedTemplate> {
    match name {
        Some(name) => TemplateStore::from_env()?.resolve(name),
        None => Ok(crate::template::NamedTemplate {
            name: String::new(),
            path: PathBuf::new(),
            template: empty_template(),
        }),
    }
}

pub(crate) fn selected_image_reference(
    positional: Option<&str>,
    template: &Template,
) -> eyre::Result<String> {
    positional
        .map(str::to_string)
        .or_else(|| template.image.clone())
        .filter(|reference| !reference.trim().is_empty())
        .ok_or_else(|| eyre::eyre!("an image is required when the template does not provide one"))
}

/// A source spelling, parsed in the same order by both transports: `image:`
/// managed references first, then `disk:` paths, then OCI references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceSpelling {
    Managed(silo_vm_control::images::ManagedSpelling),
    Disk(PathBuf),
    Oci(String),
}

pub(crate) fn parse_source(reference: &str) -> eyre::Result<SourceSpelling> {
    if reference.starts_with("image:") {
        return Ok(SourceSpelling::Managed(
            silo_vm_control::images::parse_managed(reference)?,
        ));
    }
    if let Some(path) = reference.strip_prefix("disk:") {
        return Ok(SourceSpelling::Disk(disk_source_path(reference, path)?));
    }
    Ok(SourceSpelling::Oci(reference.to_owned()))
}

/// Source options belong to the selected source family; they are never
/// silently ignored for another one.
pub(crate) fn validate_source_options(
    spelling: &SourceSpelling,
    options: &crate::api::types::SourceOptions,
    pull: bool,
) -> eyre::Result<()> {
    match spelling {
        SourceSpelling::Oci(_) => {
            if options.root.is_some() {
                eyre::bail!("--root selects a partition of a disk: source only");
            }
        }
        SourceSpelling::Disk(_) => {
            if pull {
                eyre::bail!("--pull is only supported for OCI image sources");
            }
        }
        SourceSpelling::Managed(_) => {
            if pull {
                eyre::bail!("--pull is only supported for OCI image sources");
            }
            if options.platform.is_some() || options.root.is_some() {
                eyre::bail!(
                    "--platform and --root cannot change a managed image; its boot metadata is immutable"
                );
            }
        }
    }
    Ok(())
}

/// Snapshot creation is a full stopped restore: only the new name applies.
/// Explicit settings are refused rather than silently ignored; implicit
/// defaults are never sent.
pub(crate) fn ensure_snapshot_has_no_overrides(
    options: &MachineCliOptions,
    template: &crate::template::NamedTemplate,
) -> eyre::Result<()> {
    let explicit = options.overrides != MachineOverrides::default()
        || options.kernel.is_some()
        || options.initramfs.is_some()
        || !options.kernel_args.is_empty()
        || options.nested_virtualization
        || options.rosetta.is_some()
        || !options.disks.is_empty()
        || options.agent.is_some()
        || options.no_agent
        || options.provision_user.is_some()
        || !template.name.is_empty();
    if explicit {
        eyre::bail!(
            "a snapshot restores its complete captured configuration; only --name applies (use `silo restore` options, or `silo set` after creation)"
        );
    }
    Ok(())
}

/// `disk:` convenience: host-native userspace, whole-disk direct boot and
/// packaged assets pinned at creation, unless explicitly selected. The
/// assumption is complete and visible in the plan; creation publishes no alias.
pub(crate) fn disk_create_request(
    path: PathBuf,
    options: &crate::api::types::SourceOptions,
) -> eyre::Result<libvm::DiskImportRequest> {
    let platform = match &options.platform {
        Some(platform) => platform.clone(),
        None => silo_vm_control::boot::host_platform()?,
    };
    Ok(libvm::DiskImportRequest {
        path,
        boot: libvm::DiskImportBoot::LinuxDirect {
            platform,
            root: options
                .root
                .clone()
                .unwrap_or(libvm::ImportRootSelection::WholeDisk),
            assets: libvm::BootAssetSelection::Packaged,
        },
        alias: None,
    })
}

fn disk_path(reference: &str, path: &str) -> eyre::Result<PathBuf> {
    if path.trim().is_empty() {
        eyre::bail!("local image source path cannot be empty in {reference}");
    }
    Ok(PathBuf::from(path))
}

/// Absolute source path with canonical parent directories. The final component
/// is never resolved: libvm opens it without following symbolic links, so a
/// symlinked source is refused rather than silently replaced by its target.
pub(crate) fn disk_source_path(reference: &str, path: &str) -> eyre::Result<PathBuf> {
    let path = resolve_host_path(&disk_path(reference, path)?)?;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        eyre::bail!("local image disk path has no file name: {}", path.display());
    };
    let path = std::fs::canonicalize(parent)
        .with_context(|| format!("resolve local image disk directory {}", parent.display()))?
        .join(name);
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("inspect local image disk {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        eyre::bail!(
            "local image disk is a symbolic link; pass the quiesced regular file itself: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        eyre::bail!(
            "local image disk path is not a regular file: {}",
            path.display()
        );
    }
    Ok(path)
}

fn parse_platform_arg(value: &str) -> Result<libvm::LinuxPlatform, String> {
    silo_vm_control::boot::parse_platform(value).map_err(|error| error.to_string())
}

fn parse_root_arg(value: &str) -> Result<libvm::ImportRootSelection, String> {
    silo_vm_control::boot::parse_import_root(value).map_err(|error| error.to_string())
}

pub(crate) struct PlanInputs {
    pub(crate) kind: PlanKind,
    pub(crate) template: crate::template::NamedTemplate,
    pub(crate) image: ResolvedImage,
    pub(crate) image_is_positional: bool,
    pub(crate) machine_overrides: MachineOverrides,
    pub(crate) machine_settings: MachineCreationSettings,
    pub(crate) process_overrides: ProcessOverrides,
    pub(crate) command_tail: Vec<String>,
    pub(crate) retention: MachineRetention,
    pub(crate) name: Option<String>,
    pub(crate) environment_files: Vec<EnvironmentLayer>,
    pub(crate) host_environment: BTreeMap<String, String>,
    pub(crate) environment_overrides: Vec<EnvironmentOverride>,
}

pub(crate) fn resolve_plan(inputs: PlanInputs) -> eyre::Result<Plan> {
    let PlanInputs {
        kind,
        template,
        image,
        image_is_positional,
        machine_overrides,
        machine_settings,
        process_overrides,
        command_tail,
        retention,
        name,
        environment_files,
        host_environment,
        environment_overrides,
    } = inputs;
    planning::resolve(ResolveRequest {
        kind,
        template: template.template,
        template_name: (!template.name.is_empty()).then_some(template.name),
        template_image: (!image_is_positional).then_some(image.clone()),
        positional_image: image_is_positional.then_some(image),
        machine_overrides,
        machine_settings,
        environment_files,
        host_environment,
        environment_overrides,
        command_tail,
        process_overrides,
        retention,
        name,
    })
}

pub(crate) fn read_environment_layers(
    paths: &[PathBuf],
    host: &BTreeMap<String, String>,
) -> eyre::Result<Vec<EnvironmentLayer>> {
    paths
        .iter()
        .map(|path| read_environment_file(path, host))
        .collect()
}

pub(crate) fn machine_settings(options: &MachineCliOptions) -> MachineCreationSettings {
    let agent = if options.no_agent {
        MachineAgent::Disabled
    } else if let Some(path) = &options.agent {
        MachineAgent::Custom { path: path.clone() }
    } else {
        MachineAgent::Default
    };
    MachineCreationSettings {
        kernel: options.kernel.clone(),
        initramfs: options.initramfs.clone(),
        kernel_args: options.kernel_args.clone(),
        nested_virtualization: options.nested_virtualization,
        rosetta: options.rosetta,
        platform: options.source.platform.clone(),
        disks: options.disks.clone(),
        agent,
        provision_user: options.provision_user.clone(),
    }
}

pub(crate) fn render_plan(plan: &Plan, format: OutputFormat) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => crate::ui::print_json(plan),
        OutputFormat::Plain => {
            println!("{}", serde_json::to_string(plan)?);
            Ok(())
        }
    }
}

fn empty_template() -> Template {
    Template {
        version: "1".to_string(),
        description: None,
        image: None,
        resources: None,
        disk_size: None,
        tmpfs_size: None,
        userdata: None,
        mounts: Vec::new(),
        forwards: Vec::new(),
        vsock: None,
        network: None,
        labels: BTreeMap::new(),
    }
}

pub(crate) fn preflight_create(
    template: &Template,
    options: &MachineCliOptions,
    positional_image: Option<&str>,
    policy_config_dir: Option<&Path>,
) -> eyre::Result<()> {
    validate_machine_cli_options(options)?;
    crate::template::validate_tmpfs_size(
        options
            .overrides
            .tmpfs_size
            .as_deref()
            .or(template.tmpfs_size.as_deref()),
    )?;
    let reference = selected_image_reference(positional_image, template)?;
    if options
        .overrides
        .tmpfs_size
        .as_ref()
        .or(template.tmpfs_size.as_ref())
        .is_some()
        && (reference.starts_with("image:") || reference.starts_with("disk:"))
    {
        eyre::bail!("--tmpfs-size requires a new OCI root");
    }
    let spelling = parse_source(&reference)?;
    validate_source_options(&spelling, &options.source, false)?;
    for (label, path) in [
        ("custom guest agent", options.agent.as_ref()),
        ("kernel", options.kernel.as_ref()),
        ("initramfs", options.initramfs.as_ref()),
    ] {
        if let Some(path) = path {
            validate_readable_file(path, label)?;
        }
    }
    for disk in &options.disks {
        validate_readable_file(disk, "extra disk")?;
    }
    if let SourceSpelling::Disk(path) = &spelling {
        validate_readable_file(path, "local image disk")?;
    }

    let mounts = template
        .mounts
        .iter()
        .chain(options.overrides.mounts.iter());
    for mount in mounts {
        validate_readable_host_path(&mount.source, "mount source")?;
    }
    let network = options
        .overrides
        .network
        .as_ref()
        .or(template.network.as_ref());
    if let Some(MachineNetwork::Private {
        policy_ref: Some(policy_ref),
        ..
    }) = network
    {
        // Resolving here makes dry runs and real runs reject the same missing,
        // unreadable, or invalid policy before image resolution reaches a registry.
        let policy =
            crate::network_policy::resolve_network_policy_source(policy_ref, policy_config_dir)?;
        if !policy.tailscale().is_empty()
            && !options.overrides.vsock.or(template.vsock).unwrap_or(false)
        {
            eyre::bail!("Tailscale policy requires --vsock");
        }
    }
    Ok(())
}

pub(crate) fn validate_process_overrides(
    working_directory: Option<&str>,
    user: Option<&str>,
    shell: Option<&str>,
) -> eyre::Result<()> {
    if let Some(working_directory) = working_directory {
        validate_guest_working_directory(working_directory)?;
    }
    if let Some(user) = user {
        validate_guest_user(user)?;
    }
    if let Some(shell) = shell {
        validate_guest_shell(shell)?;
    }
    Ok(())
}

fn validate_machine_cli_options(options: &MachineCliOptions) -> eyre::Result<()> {
    if options.no_agent && options.provision_user.is_some() {
        eyre::bail!("--no-agent cannot be combined with --provision-user");
    }
    Ok(())
}

fn validate_readable_file(path: &Path, label: &str) -> eyre::Result<()> {
    let path = resolve_host_path(path)?;
    let metadata = std::fs::metadata(&path)
        .map_err(|error| eyre::eyre!("inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() {
        eyre::bail!("{label} path is not a file: {}", path.display());
    }
    std::fs::File::open(&path)
        .map_err(|error| eyre::eyre!("read {label} {}: {error}", path.display()))?;
    Ok(())
}

fn validate_readable_host_path(path: &Path, label: &str) -> eyre::Result<()> {
    let path = resolve_host_path(path)?;
    let metadata = std::fs::metadata(&path)
        .map_err(|error| eyre::eyre!("inspect {label} {}: {error}", path.display()))?;
    if metadata.is_file() {
        return validate_readable_file(&path, label);
    }
    if metadata.is_dir() {
        std::fs::read_dir(&path)
            .map_err(|error| eyre::eyre!("read {label} {}: {error}", path.display()))?;
        return Ok(());
    }
    eyre::bail!(
        "{label} path is neither a file nor directory: {}",
        path.display()
    )
}

fn validate_guest_working_directory(value: &str) -> eyre::Result<()> {
    if value.is_empty() || value.contains('\0') || !value.starts_with('/') {
        eyre::bail!("guest working directory must be a non-empty absolute path");
    }
    Ok(())
}

fn validate_guest_user(value: &str) -> eyre::Result<()> {
    let valid_component = |component: &str| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    };
    if value.contains('\0')
        || value.split(':').count() > 2
        || !value.split(':').all(valid_component)
    {
        eyre::bail!("guest user must be NAME, UID, NAME:GROUP, or UID:GID");
    }
    Ok(())
}

fn validate_guest_shell(value: &str) -> eyre::Result<()> {
    if value.is_empty() || value.contains('\0') || !value.starts_with('/') {
        eyre::bail!("guest shell must be a non-empty absolute path");
    }
    Ok(())
}

pub(crate) fn parse_environment(value: &str) -> Result<EnvironmentOverride, String> {
    EnvironmentOverride::parse(value).map_err(|error| error.to_string())
}

pub(crate) fn parse_mount(input: &str) -> Result<MachineMount, String> {
    let parts = input.split(':').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len()) || parts[0].is_empty() || parts[1].is_empty() {
        return Err("invalid mount, expected SRC:DST[:ro|rw]".to_string());
    }
    let mode = match parts.get(2).copied().unwrap_or("rw") {
        "ro" => crate::machine_defaults::MountMode::Ro,
        "rw" => crate::machine_defaults::MountMode::Rw,
        value => return Err(format!("invalid mount mode {value:?}, expected ro or rw")),
    };
    Ok(MachineMount {
        source: parts[0].into(),
        target: parts[1].to_string(),
        mode,
    })
}

pub(crate) fn parse_label(input: &str) -> Result<(String, String), String> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| "invalid label, expected KEY=VALUE".to_string())?;
    if key.is_empty() {
        return Err("invalid label, key cannot be empty".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}

fn parse_forward(input: &str) -> Result<libvm::Forward, String> {
    let Some((listen, connect)) = input.split_once('=') else {
        return Err("forward must be LISTEN=CONNECT".to_string());
    };
    if listen.is_empty() || connect.is_empty() {
        return Err("forward must contain a non-empty LISTEN=CONNECT pair".to_string());
    }
    let forward = libvm::Forward::new(
        listen
            .parse()
            .map_err(|error| format!("invalid forward listen endpoint: {error}"))?,
        connect
            .parse()
            .map_err(|error| format!("invalid forward connect endpoint: {error}"))?,
    );
    forward
        .validate()
        .map_err(|error| format!("invalid forward: {error}"))?;
    Ok(forward)
}

pub(crate) fn parse_user_arg(value: &str) -> Result<UserArg, String> {
    if value == "auto" {
        return Ok(UserArg::Auto);
    }
    parse_explicit_user(value).map(UserArg::Explicit)
}

fn resolve_user_arg(value: &UserArg) -> eyre::Result<MachineUserConfig> {
    match value {
        UserArg::Auto => current_host_user(),
        UserArg::Explicit(user) => Ok(user.clone()),
    }
}

pub(crate) fn current_host_user() -> eyre::Result<MachineUserConfig> {
    let uid = Uid::effective();
    let user = User::from_uid(uid)?
        .ok_or_else(|| eyre::eyre!("unable to resolve effective host user {uid}"))?;
    let user = MachineUserConfig::new(
        &user.name,
        user.uid.as_raw(),
        user.gid.as_raw(),
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
    let uid = fields[1]
        .parse::<u32>()
        .map_err(|error| format!("invalid user uid {:?}: {error}", fields[1]))?;
    let gid = fields[2]
        .parse::<u32>()
        .map_err(|error| format!("invalid user gid {:?}: {error}", fields[2]))?;
    let user = MachineUserConfig::new(fields[0], uid, gid, fields[3]);
    user.validate()?;
    Ok(user)
}

fn read_userdata_path(path: &Path) -> eyre::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read userdata {}", path.display()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use libvm::RuntimeConfig;

    use crate::api::AppApi;
    use crate::app::Cli;
    use crate::commands::Command;

    use crate::api::types::SourceOptions;
    use crate::commands::create::{
        disk_create_request, disk_source_path, empty_template, parse_source, preflight_create,
        validate_process_overrides, validate_source_options, Pull, SourceSpelling, VmOverrideArgs,
    };

    #[test]
    fn rosetta_intent_is_tri_state_and_platform_root_are_typed() {
        let parse = |args: &[&str]| {
            let mut argv = vec!["silo", "create", "disk:rootfs.img"];
            argv.extend_from_slice(args);
            let Command::Create(create) = Cli::try_parse_from(argv).expect("parse").command else {
                panic!("expected create")
            };
            create.overrides
        };
        assert_eq!(parse(&[]).rosetta, None);
        assert_eq!(parse(&["--rosetta"]).rosetta, Some(true));
        assert_eq!(parse(&["--rosetta=false"]).rosetta, Some(false));
        assert_eq!(parse(&["--rosetta=true"]).rosetta, Some(true));
        let overrides = parse(&["--platform", "linux/arm64/v8", "--root", "mbr:4"]);
        assert_eq!(
            overrides.platform,
            Some(libvm::LinuxPlatform {
                architecture: libvm::GuestArchitecture::Arm64,
                variant: Some("v8".into()),
            })
        );
        assert_eq!(
            overrides.root,
            Some(libvm::ImportRootSelection::MbrPartition { number: 4 })
        );
        for invalid in [
            ["--platform", "linux/riscv64"],
            ["--platform", "linux/amd64/v3"],
            ["--platform", "windows/amd64"],
            ["--root", "mbr:0"],
            ["--root", "mbr:5"],
            ["--root", "mbr:256"],
            ["--root", "gpt:00000000-0000-0000-0000-000000000000"],
            ["--root", "largest"],
        ] {
            let mut argv = vec!["silo", "create", "disk:rootfs.img"];
            argv.extend_from_slice(&invalid);
            assert!(Cli::try_parse_from(argv).is_err(), "{invalid:?}");
        }
        assert!(Cli::try_parse_from(["silo", "create", "x", "--rosetta=maybe"]).is_err());
    }

    #[test]
    fn managed_image_spelling_is_parsed_before_oci_and_options_follow_the_family() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            parse_source("image:base").unwrap(),
            SourceSpelling::Managed(silo_vm_control::images::ManagedSpelling::Reference(
                libvm::ManagedSourceRef::Alias("base".into())
            ))
        );
        assert_eq!(
            parse_source(&format!("image:{digest}")).unwrap(),
            SourceSpelling::Managed(silo_vm_control::images::ManagedSpelling::Digest(
                digest.parse().unwrap()
            ))
        );
        assert!(parse_source("image:sha256:ABC").is_err());
        assert!(parse_source("image:").is_err());
        assert!(parse_source("image:has space").is_err());
        assert_eq!(
            parse_source("ubuntu:24.04").unwrap(),
            SourceSpelling::Oci("ubuntu:24.04".into())
        );
        let root = SourceOptions {
            platform: None,
            root: Some(libvm::ImportRootSelection::AutoGpt),
        };
        let platform = SourceOptions {
            platform: Some(silo_vm_control::boot::parse_platform("arm64").unwrap()),
            root: None,
        };
        let oci = SourceSpelling::Oci("ubuntu".into());
        let managed = parse_source("image:base").unwrap();
        let disk = SourceSpelling::Disk("/disk.raw".into());
        assert!(validate_source_options(&oci, &root, false).is_err());
        assert!(validate_source_options(&oci, &platform, true).is_ok());
        assert!(validate_source_options(&managed, &platform, false).is_err());
        assert!(validate_source_options(&managed, &root, false).is_err());
        assert!(validate_source_options(&managed, &SourceOptions::default(), true).is_err());
        assert!(validate_source_options(&disk, &root, false).is_ok());
        assert!(validate_source_options(&disk, &platform, true).is_err());
    }

    #[test]
    fn disk_convenience_is_complete_host_native_whole_disk_packaged_without_alias() {
        let request = disk_create_request("/disk.raw".into(), &SourceOptions::default()).unwrap();
        assert_eq!(
            request,
            libvm::DiskImportRequest {
                path: "/disk.raw".into(),
                boot: libvm::DiskImportBoot::LinuxDirect {
                    platform: silo_vm_control::boot::host_platform().unwrap(),
                    root: libvm::ImportRootSelection::WholeDisk,
                    assets: libvm::BootAssetSelection::Packaged,
                },
                alias: None,
            }
        );
        let explicit = SourceOptions {
            platform: Some(silo_vm_control::boot::parse_platform("linux/amd64").unwrap()),
            root: Some(libvm::ImportRootSelection::AutoGpt),
        };
        let libvm::DiskImportBoot::LinuxDirect { platform, root, .. } =
            disk_create_request("/disk.raw".into(), &explicit)
                .unwrap()
                .boot;
        assert_eq!(Some(platform), explicit.platform);
        assert_eq!(root, libvm::ImportRootSelection::AutoGpt);
    }

    #[test]
    fn create_parses_the_final_image_first_form() {
        let cli = Cli::try_parse_from([
            "silo",
            "create",
            "ubuntu:24.04",
            "--template",
            "dev",
            "-n",
            "devbox",
            "--set-default",
            "--provision-user=alice:1000:1000:/home/alice",
        ])
        .expect("create parses");
        let Command::Create(create) = cli.command else {
            panic!("expected create")
        };
        assert_eq!(create.image.as_deref(), Some("ubuntu:24.04"));
        assert_eq!(create.template.as_deref(), Some("dev"));
        assert_eq!(create.name.as_deref(), Some("devbox"));
        assert!(create.set_default);
        assert!(create.overrides.provision_user.is_some());
    }

    #[test]
    fn create_rejects_removed_flags_and_incompatible_agent_options() {
        assert!(Cli::try_parse_from(["silo", "create", "--image", "ubuntu"]).is_err());
        assert!(Cli::try_parse_from(["silo", "create", "--start"]).is_err());
        assert!(Cli::try_parse_from(["silo", "create", "--initrd", "initrd.img"]).is_err());
        assert!(Cli::try_parse_from(["silo", "create", "--agent", "a", "--no-agent"]).is_err());
    }

    #[test]
    fn create_allows_libvm_to_generate_the_machine_name() {
        let cli = Cli::try_parse_from(["silo", "create", "disk:rootfs.img"])
            .expect("create parses without a name");
        let Command::Create(create) = cli.command else {
            panic!("expected create")
        };

        assert_eq!(create.name, None);
    }

    #[test]
    fn create_parses_stable_vm_overrides() {
        let cli = Cli::try_parse_from([
            "silo",
            "create",
            "disk:rootfs.img",
            "-n",
            "dev",
            "--cpus",
            "2",
            "--memory",
            "2gb",
            "--mount",
            ".:/workspace:ro",
            "--forward",
            "host:tcp:8080=guest:tcp:80",
            "--vsock",
            "--network",
            "none",
            "--label",
            "a=b",
        ])
        .expect("create parses overrides");
        let Command::Create(create) = cli.command else {
            panic!("expected create")
        };
        let options = create.overrides.resolve().expect("resolve overrides");
        assert_eq!(
            options.overrides.resources.expect("resources").cpus,
            Some(2)
        );
        assert_eq!(options.overrides.mounts.len(), 1);
        assert_eq!(
            options
                .overrides
                .forwards
                .as_ref()
                .expect("forward override")[0]
                .listen
                .to_string(),
            "host:tcp:127.0.0.1:8080"
        );
        assert_eq!(options.overrides.vsock, Some(true));
        assert_eq!(options.overrides.labels["a"], "b");
    }

    #[test]
    fn create_parses_guest_publish() {
        let cli = Cli::try_parse_from([
            "silo",
            "create",
            "disk:rootfs.img",
            "--guest-publish",
            "any",
        ])
        .expect("create parses guest publication");
        let Command::Create(create) = cli.command else {
            panic!("expected create")
        };
        let options = create.overrides.resolve().expect("resolve overrides");

        assert_eq!(
            options.overrides.guest_publish,
            Some(libvm::PublishBind::Any)
        );
        assert!(Cli::try_parse_from([
            "silo",
            "create",
            "disk:rootfs.img",
            "--guest-publish",
            "everything",
        ])
        .is_err());
    }

    #[tokio::test]
    async fn dry_run_source_resolution_accepts_disk_and_oci_without_runtime_initialization() {
        let temp = tempfile::tempdir().expect("create temp root");
        let data_root = temp.path().join("data");
        let disk = temp.path().join("disk.img");
        std::fs::write(&disk, [0u8; 512]).expect("write disk");
        let disk_source = AppApi::resolve_read_only_creation(
            RuntimeConfig::local(&data_root),
            None,
            Some(&format!("disk:{}", disk.display())),
            &empty_template(),
            None,
            &SourceOptions::default(),
        )
        .await
        .expect("resolve disk source")
        .source;
        let crate::planning::ResolvedImage::Disk { path, boot } = &disk_source.plan_image else {
            panic!("expected disk source")
        };
        assert_eq!(path, &std::fs::canonicalize(&disk).expect("canonical disk"));
        assert_eq!(
            boot,
            &disk_create_request(path.clone(), &SourceOptions::default())
                .unwrap()
                .boot
        );

        let oci_result = AppApi::resolve_read_only_creation(
            RuntimeConfig::local(&data_root),
            None,
            Some("example.test/missing:latest"),
            &empty_template(),
            Some(Pull::Never.policies()),
            &SourceOptions::default(),
        )
        .await;
        let Err(oci_error) = oci_result else {
            panic!("uncached OCI source must respect --pull never");
        };
        assert!(oci_error
            .to_string()
            .contains("image example.test/missing:latest not found"));
        assert!(!data_root.exists());
    }

    #[tokio::test]
    async fn disk_rejects_every_explicit_pull_policy() {
        let temp = tempfile::tempdir().expect("create temp root");
        let disk = temp.path().join("disk.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        for pull in [Pull::Missing, Pull::Always, Pull::Never] {
            let error = AppApi::resolve_read_only_creation(
                RuntimeConfig::local(temp.path().join("data")),
                None,
                Some(&format!("disk:{}", disk.display())),
                &empty_template(),
                Some(pull.policies()),
                &SourceOptions::default(),
            )
            .await
            .expect_err("explicit disk pull policy must fail");
            assert!(error
                .to_string()
                .contains("--pull is only supported for OCI image sources"));
        }
    }

    #[test]
    fn disk_source_keeps_the_final_component_and_refuses_symlinks_and_special_files() {
        let temp = tempfile::tempdir().expect("create temp root");
        let disk = temp.path().join("disk.img");
        let alias = temp.path().join("alias.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        std::os::unix::fs::symlink(&disk, &alias).expect("create disk alias");
        let spelled = temp.path().join("sub").join("..").join("disk.img");
        std::fs::create_dir(temp.path().join("sub")).expect("subdirectory");
        assert_eq!(
            disk_source_path("disk:", spelled.to_str().unwrap()).expect("regular disk"),
            std::fs::canonicalize(&disk).expect("canonical disk")
        );
        let error = disk_source_path("disk:", alias.to_str().unwrap()).expect_err("symlink");
        assert!(error.to_string().contains("symbolic link"), "{error}");
        let error =
            disk_source_path("disk:", temp.path().to_str().unwrap()).expect_err("directory");
        assert!(error.to_string().contains("not a regular file"), "{error}");
        assert!(disk_source_path("disk:", " ").is_err());
    }

    #[test]
    fn preflight_rejects_missing_local_disks_before_runtime_initialization() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut template = empty_template();
        template.image = Some(format!(
            "disk:{}",
            temp.path().join("missing.img").display()
        ));
        let options = VmOverrideArgs::default()
            .resolve()
            .expect("resolve options");

        let error = preflight_create(&template, &options, None, None)
            .expect_err("missing local disk must fail in preflight");

        assert!(error.to_string().contains("local image disk"));
    }

    #[test]
    fn process_override_preflight_enforces_guest_grammar() {
        validate_process_overrides(Some("/workspace"), Some("1000:1000"), Some("/bin/sh"))
            .expect("valid process options");
        assert!(validate_process_overrides(Some("workspace"), None, None).is_err());
        assert!(validate_process_overrides(None, Some("user name"), None).is_err());
        assert!(validate_process_overrides(None, None, Some("bin/sh")).is_err());
    }
}

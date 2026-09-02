use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use eyre::Context as _;
use libvm::{
    ImageProgressSender, ImagePullPolicy, ImageResolveOptions, ImageSource, MachineAgent,
    MachineBuilder, MachineRetention, MachineUserConfig, Memory, PublishBind, ReadOnlyRuntime,
    ResolvedOciImage, Runtime, RuntimeConfig,
};
use nix::unistd::{Uid, User};

use crate::environment::{read_environment_file, EnvironmentLayer, EnvironmentOverride};
use crate::machine_defaults::{
    disk_size_bytes, memory_mib, resolve_host_path, resolve_machine_mounts, MachineMount,
    MachineNetwork, MachineNetworkSelection, MachineResources,
};
use crate::planning::{
    self, ImageCacheState, MachineCreationSettings, MachineOverrides, Plan, PlanKind,
    ProcessOverrides, PullPolicy, ResolveRequest, ResolvedImage,
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
    /// Resize the image-backed root disk, for example 10gb or 512mb.
    #[arg(long = "disk-size", value_name = "SIZE")]
    pub(crate) disk_size: Option<String>,
    /// Enable nested virtualization for supported VZ guests.
    #[arg(long)]
    pub(crate) nested_virtualization: bool,
    /// Enable Rosetta for x86_64 Linux binaries in supported VZ guests.
    #[arg(long)]
    pub(crate) rosetta: bool,
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
    pub(crate) rosetta: bool,
    pub(crate) disks: Vec<PathBuf>,
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
        Ok(MachineCliOptions {
            overrides: MachineOverrides {
                resources,
                disk_size: self.disk_size.clone(),
                userdata,
                mounts: self.mounts.clone(),
                forwards: (!self.forwards.is_empty()).then(|| self.forwards.clone()),
                vsock: self.vsock.then_some(true),
                network: self
                    .network
                    .clone()
                    .map(MachineNetworkSelection::into_machine_network),
                guest_publish: self.guest_publish,
                labels: self.labels.iter().cloned().collect(),
            },
            kernel: self.kernel.clone(),
            initramfs: self.initramfs.clone(),
            kernel_args: self.kernel_args.clone(),
            nested_virtualization: self.nested_virtualization,
            rosetta: self.rosetta,
            disks: self.disks.clone(),
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
            context.config()?.networking.policy_config_dir.as_deref(),
        )?;

        if self.dry_run {
            let runtime = ReadOnlyRuntime::open(RuntimeConfig::from_env()?).await?;
            let name = match requested_name {
                Some(name) => {
                    ensure_read_only_name_available(&runtime, &name).await?;
                    name
                }
                None => runtime.propose_machine_name()?,
            };
            let source = resolve_read_only_source(
                &runtime,
                self.image.as_deref(),
                &template.template,
                self.pull,
            )
            .await?;
            let settings = machine_settings(&machine);
            let plan = resolve_plan(PlanInputs {
                kind: PlanKind::Create,
                template,
                image: source.plan_image,
                image_is_positional: source.is_positional,
                machine_overrides: machine.overrides,
                machine_settings: settings,
                process_overrides: ProcessOverrides::default(),
                command_tail: Vec::new(),
                retention: MachineRetention::Persistent,
                name: Some(name),
                environment_files: Vec::new(),
                host_environment: BTreeMap::new(),
                environment_overrides: Vec::new(),
            })?;
            return render_plan(&plan, self.format);
        }

        let image_reference = selected_image_reference(self.image.as_deref(), &template.template)?;
        let recipe_progress = Spinner::start("Reading", "VM recipe");
        let runtime = context.runtime().await?.clone();
        if let Some(name) = &requested_name {
            ensure_name_available(&runtime, name).await?;
        }
        recipe_progress.finish_clear();

        let (image_progress, image_events) = ImageProgressSender::default_channel();
        let image_progress_task = watch_image_progress(&image_reference, image_events);
        let progress_runtime = runtime.with_image_progress(image_progress);
        let image_result = async {
            let source = resolve_source(
                &progress_runtime,
                self.image.as_deref(),
                &template.template,
                self.pull,
            )
            .await?;
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
            create_machine(&progress_runtime, &plan, source, context).await
        };
        let image_result = image_result.await;
        drop(progress_runtime);
        let _ = image_progress_task.await;
        let machine = image_result?;
        let name = machine.inspect().await?.name;
        success(format!("Created {name}"));
        if self.set_default {
            crate::config::GlobalConfig::write_default_machine(Some(&name))?;
        }
        println!("{name}");
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct SourceResolution {
    pub(crate) plan_image: ResolvedImage,
    pub(crate) is_positional: bool,
    resolved_oci: Option<ResolvedOciImage>,
    disk: Option<PathBuf>,
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

pub(crate) async fn resolve_source(
    runtime: &Runtime,
    positional: Option<&str>,
    template: &Template,
    pull: Option<Pull>,
) -> eyre::Result<SourceResolution> {
    let reference = selected_image_reference(positional, template)?;
    if let Some(path) = reference.strip_prefix("disk:") {
        if pull.is_some() {
            eyre::bail!("--pull is only supported for OCI image sources");
        }
        let path = canonical_disk_source(&reference, path)?;
        return Ok(SourceResolution {
            plan_image: ResolvedImage::Disk { path: path.clone() },
            is_positional: positional.is_some(),
            resolved_oci: None,
            disk: Some(path),
        });
    }
    let pull = pull.unwrap_or(Pull::Missing);
    let resolved = runtime
        .images()
        .resolve_with(
            reference.clone(),
            ImageResolveOptions {
                policy: Some(pull.policy()),
            },
        )
        .await?;
    let plan_image = ResolvedImage::Oci {
        identity: planning::OciImageIdentity {
            requested_reference: reference,
            selected_reference: resolved.selected_reference.clone(),
            platform: resolved.platform.clone(),
            manifest_digest: resolved.manifest_digest.clone(),
            config_digest: resolved.config_digest.clone(),
            cache_state: image_cache_state(resolved.cache_state),
            pull_policy: pull.plan_policy(),
        },
        metadata: Box::new(resolved.config.clone()),
    };
    Ok(SourceResolution {
        plan_image,
        is_positional: positional.is_some(),
        resolved_oci: Some(resolved),
        disk: None,
    })
}

pub(crate) async fn resolve_read_only_source(
    runtime: &ReadOnlyRuntime,
    positional: Option<&str>,
    template: &Template,
    pull: Option<Pull>,
) -> eyre::Result<SourceResolution> {
    let reference = selected_image_reference(positional, template)?;
    if let Some(path) = reference.strip_prefix("disk:") {
        if pull.is_some() {
            eyre::bail!("--pull is only supported for OCI image sources");
        }
        let path = canonical_disk_source(&reference, path)?;
        let path = runtime.validate_disk_source(&path)?;
        return Ok(SourceResolution {
            plan_image: ResolvedImage::Disk { path: path.clone() },
            is_positional: positional.is_some(),
            resolved_oci: None,
            disk: Some(path),
        });
    }
    let pull = pull.unwrap_or(Pull::Missing);
    let resolved = runtime
        .resolve_oci_image(reference.clone(), pull.policy())
        .await?;
    Ok(SourceResolution {
        plan_image: ResolvedImage::Oci {
            identity: planning::OciImageIdentity {
                requested_reference: reference,
                selected_reference: resolved.selected_reference.clone(),
                platform: resolved.platform,
                manifest_digest: resolved.manifest_digest,
                config_digest: resolved.config_digest,
                cache_state: image_cache_state(resolved.cache_state),
                pull_policy: pull.plan_policy(),
            },
            metadata: Box::new(resolved.config),
        },
        is_positional: positional.is_some(),
        resolved_oci: None,
        disk: None,
    })
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

fn disk_path(reference: &str, path: &str) -> eyre::Result<PathBuf> {
    if path.trim().is_empty() {
        eyre::bail!("local image source path cannot be empty in {reference}");
    }
    Ok(PathBuf::from(path))
}

fn canonical_disk_source(reference: &str, path: &str) -> eyre::Result<PathBuf> {
    let path = resolve_host_path(&disk_path(reference, path)?)?;
    let path = std::fs::canonicalize(&path)
        .with_context(|| format!("resolve local image disk {}", path.display()))?;
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("inspect local image disk {}", path.display()))?;
    if !metadata.is_file() {
        eyre::bail!("local image disk path is not a file: {}", path.display());
    }
    std::fs::File::open(&path)
        .with_context(|| format!("read local image disk {}", path.display()))?;
    Ok(path)
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

pub(crate) async fn create_machine(
    runtime: &Runtime,
    plan: &planning::CreatePlan,
    source: SourceResolution,
    context: &mut crate::context::Context,
) -> eyre::Result<libvm::Machine> {
    ensure_source_matches_plan(plan, &source)?;
    let mut builder = runtime.machine();
    if let Some(name) = &plan.proposed_name {
        builder = builder.name(name);
    }
    builder = match source.resolved_oci {
        Some(image) => builder.resolved_image(image),
        None => builder.image_source(ImageSource::disk(
            source
                .disk
                .ok_or_else(|| eyre::eyre!("machine source was not resolved"))?,
        )),
    };
    builder = apply_plan(
        builder,
        plan,
        context.config()?.networking.policy_config_dir.as_deref(),
    )?;
    builder.create().await.map_err(Into::into)
}

fn apply_plan(
    mut builder: MachineBuilder,
    plan: &planning::CreatePlan,
    policy_config_dir: Option<&Path>,
) -> eyre::Result<MachineBuilder> {
    builder = builder
        .labels(plan.machine.labels.clone())
        .process(plan.process.clone())
        .retention(plan.retention)
        .template_name(plan.template.name.clone())
        .kernel_args(plan.machine_settings.kernel_args.clone())
        .nested_virtualization(plan.machine_settings.nested_virtualization)
        .rosetta(plan.machine_settings.rosetta)
        .disks(plan.machine_settings.disks.clone())
        .mounts(resolve_machine_mounts(&plan.machine.mounts)?)
        .forwards(plan.machine.forwards.clone());
    if let Some(vsock) = plan.machine.vsock {
        builder = builder.vsock(vsock);
    }
    if let Some(resources) = &plan.machine.resources {
        if let Some(cpus) = resources.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(memory) = memory_mib(Some(resources))? {
            builder = builder.memory(Memory::mebibytes(u64::from(memory)));
        }
    }
    if let Some(bytes) = disk_size_bytes(plan.machine.disk_size.as_deref())? {
        builder = builder.root_disk_size(bytes);
    }
    if let Some(userdata) = &plan.machine.userdata {
        builder = builder.userdata(userdata);
    }
    if let Some(network) = plan.machine.network.clone() {
        let network = network.resolve_machine_network(policy_config_dir)?;
        builder = builder.network(|network_builder| network.apply(network_builder));
    }
    if let Some(kernel) = &plan.machine_settings.kernel {
        builder = builder.kernel(kernel);
    }
    if let Some(initramfs) = &plan.machine_settings.initramfs {
        builder = builder.initramfs(initramfs);
    }
    let agent = plan.machine_settings.agent.clone();
    let user = plan.machine_settings.provision_user.clone();
    builder = builder.guest(|guest| {
        let guest = match agent.clone() {
            MachineAgent::Default => guest,
            MachineAgent::Custom { path } => guest.agent(Some(path)),
            MachineAgent::Disabled => guest.agent(None),
            _ => guest,
        };
        match user {
            Some(user) => guest.user(user),
            None => guest,
        }
    });
    builder = builder.agent_mode(Some(agent));
    Ok(builder)
}

fn ensure_source_matches_plan(
    plan: &planning::CreatePlan,
    source: &SourceResolution,
) -> eyre::Result<()> {
    let matches = match (&plan.image, &source.plan_image) {
        (planning::ImageIdentity::Oci(plan), ResolvedImage::Oci { identity, .. }) => {
            plan == identity
                && source.resolved_oci.as_ref().is_some_and(|image| {
                    image.selected_reference == plan.selected_reference
                        && image.platform == plan.platform
                        && image.manifest_digest == plan.manifest_digest
                        && image.config_digest == plan.config_digest
                        && image_cache_state(image.cache_state) == plan.cache_state
                })
        }
        (planning::ImageIdentity::Disk { path: plan }, ResolvedImage::Disk { path }) => {
            plan == path && source.resolved_oci.is_none() && source.disk.as_ref() == Some(path)
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        eyre::bail!("resolved image no longer matches the planned immutable identity")
    }
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
        disks: options.disks.clone(),
        agent,
        provision_user: options.provision_user.clone(),
    }
}

fn image_cache_state(state: libvm::ImageCacheState) -> ImageCacheState {
    match state {
        libvm::ImageCacheState::Complete => ImageCacheState::Complete,
        libvm::ImageCacheState::Missing => ImageCacheState::Missing,
    }
}

pub(crate) async fn ensure_name_available(runtime: &Runtime, name: &str) -> eyre::Result<()> {
    let reference = libvm::MachineRef::parse(name)?;
    match runtime.get_machine(&reference).await {
        Ok(_) => eyre::bail!("machine {name:?} already exists"),
        Err(libvm::LibVmError::MachineNotFound { .. }) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn ensure_read_only_name_available(
    runtime: &ReadOnlyRuntime,
    name: &str,
) -> eyre::Result<()> {
    let _ = libvm::MachineRef::parse(name)?;
    if runtime.machine_name_available(name).await? {
        Ok(())
    } else {
        eyre::bail!("machine {name:?} already exists")
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
    if let Some(path) = selected_image_reference(positional_image, template)?.strip_prefix("disk:")
    {
        validate_readable_file(
            &disk_path(&format!("disk:{path}"), path)?,
            "local image disk",
        )?;
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
        let _ =
            crate::network_policy::resolve_network_policy_source(policy_ref, policy_config_dir)?;
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
    use libvm::{ReadOnlyRuntime, RuntimeConfig};

    use crate::app::Cli;
    use crate::commands::Command;

    use crate::commands::create::{
        canonical_disk_source, empty_template, preflight_create, resolve_read_only_source,
        validate_process_overrides, Pull, VmOverrideArgs,
    };

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
        std::fs::write(&disk, b"disk").expect("write disk");
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(&data_root))
            .await
            .expect("open read-only runtime");

        let disk_source = resolve_read_only_source(
            &runtime,
            Some(&format!("disk:{}", disk.display())),
            &empty_template(),
            None,
        )
        .await
        .expect("resolve disk source");
        let crate::planning::ResolvedImage::Disk { path } = &disk_source.plan_image else {
            panic!("expected disk source")
        };
        assert_eq!(path, &std::fs::canonicalize(&disk).expect("canonical disk"));
        assert_eq!(disk_source.disk.as_ref(), Some(path));

        let oci_result = resolve_read_only_source(
            &runtime,
            Some("example.test/missing:latest"),
            &empty_template(),
            Some(Pull::Never),
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
        let runtime = ReadOnlyRuntime::open(RuntimeConfig::local(temp.path().join("data")))
            .await
            .expect("open read-only runtime");

        for pull in [Pull::Missing, Pull::Always, Pull::Never] {
            let error = resolve_read_only_source(
                &runtime,
                Some(&format!("disk:{}", disk.display())),
                &empty_template(),
                Some(pull),
            )
            .await
            .expect_err("explicit disk pull policy must fail");
            assert!(error
                .to_string()
                .contains("--pull is only supported for OCI image sources"));
        }
    }

    #[test]
    fn disk_source_is_canonicalized_before_planning() {
        let temp = tempfile::tempdir().expect("create temp root");
        let disk = temp.path().join("disk.img");
        let alias = temp.path().join("alias.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        std::os::unix::fs::symlink(&disk, &alias).expect("create disk alias");

        let canonical = canonical_disk_source(
            &format!("disk:{}", alias.display()),
            alias.to_str().expect("alias path is UTF-8"),
        )
        .expect("canonicalize disk source");

        assert_eq!(
            canonical,
            std::fs::canonicalize(&disk).expect("canonical disk")
        );
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

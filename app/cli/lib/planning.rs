use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use eyre::bail;
use libvm::{
    MachineAgent, MachineRetention, MachineUserConfig, OciImageConfigMetadata, Platform,
    ProcessConfig,
};
use serde::{Deserialize, Serialize};

use crate::environment::{
    resolve_environment, validate_no_nul, EnvironmentLayer, EnvironmentOverride,
};
use crate::machine_defaults::{
    validate_machine_defaults, MachineMount, MachineNetwork, MachineResources,
};
use crate::template::{validate_template, Template};

/// Immutable OCI identity retained by a plan without materializing a root disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OciImageIdentity {
    pub(crate) requested_reference: String,
    pub(crate) selected_reference: String,
    pub(crate) platform: Platform,
    pub(crate) manifest_digest: String,
    pub(crate) config_digest: String,
    pub(crate) cache_state: ImageCacheState,
    pub(crate) pull_policy: PullPolicy,
}

/// Cache state is recorded explicitly so a plan explains whether creation will pull.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ImageCacheState {
    Complete,
    Missing,
}

/// Resolved source information supplied by the image-resolution layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedImage {
    Oci {
        identity: OciImageIdentity,
        metadata: Box<OciImageConfigMetadata>,
    },
    Disk {
        path: PathBuf,
    },
}

/// Pull policies are meaningful only for OCI image sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PullPolicy {
    IfMissing,
    Always,
    Never,
}

/// Source identity preserved for dry-run output and later materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ImageIdentity {
    Oci(OciImageIdentity),
    Disk { path: PathBuf },
}

/// Explicit machine values, kept independent from the current CLI command structs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MachineOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resources: Option<MachineResources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) disk_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) userdata: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mounts: Vec<MachineMount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<MachineNetwork>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
}

/// Fully selected machine defaults, with no filesystem or runtime work performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MachinePlan {
    pub(crate) resources: Option<MachineResources>,
    pub(crate) disk_size: Option<String>,
    pub(crate) userdata: Option<String>,
    pub(crate) mounts: Vec<MachineMount>,
    pub(crate) network: Option<MachineNetwork>,
    pub(crate) labels: BTreeMap<String, String>,
}

/// Creation controls that are not supplied by a template, captured before planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MachineCreationSettings {
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initramfs: Option<PathBuf>,
    pub(crate) kernel_args: Vec<String>,
    pub(crate) nested_virtualization: bool,
    pub(crate) rosetta: bool,
    pub(crate) disks: Vec<PathBuf>,
    pub(crate) agent: MachineAgent,
    pub(crate) provision_user: Option<MachineUserConfig>,
}

/// Process options that may override OCI configuration before persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProcessOverrides {
    /// `Some` replaces OCI Entrypoint.
    pub(crate) entrypoint: Option<Vec<String>>,
    pub(crate) working_directory: Option<String>,
    pub(crate) user: Option<String>,
}

/// Whether a TTY was explicitly requested, disabled, or selected from host capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum TtyMode {
    #[default]
    Auto,
    Enabled,
    Disabled,
}

/// Snapshot of terminal capabilities taken outside the pure resolver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TtyCapabilities {
    pub(crate) stdin: bool,
    pub(crate) stdout: bool,
}

/// Transient run-only controls. They are intentionally not persisted in `CreatePlan`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RunOptions {
    pub(crate) detached: bool,
    pub(crate) tty: TtyMode,
    pub(crate) capabilities: TtyCapabilities,
    /// A shell fallback is transient execution behavior, never durable process state.
    pub(crate) shell: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlanKind {
    Create,
    Run(RunOptions),
}

/// All values required to resolve a plan are passed by value, making `resolve` pure.
#[derive(Debug, Clone)]
pub(crate) struct ResolveRequest {
    pub(crate) kind: PlanKind,
    pub(crate) template: Template,
    pub(crate) template_name: Option<String>,
    /// Resolution for `template.image`, when that image is selected.
    pub(crate) template_image: Option<ResolvedImage>,
    /// Positional image source. When present it takes precedence over `template.image`.
    pub(crate) positional_image: Option<ResolvedImage>,
    pub(crate) machine_overrides: MachineOverrides,
    pub(crate) machine_settings: MachineCreationSettings,
    pub(crate) environment_files: Vec<EnvironmentLayer>,
    pub(crate) host_environment: BTreeMap<String, String>,
    pub(crate) environment_overrides: Vec<EnvironmentOverride>,
    pub(crate) command_tail: Vec<String>,
    pub(crate) process_overrides: ProcessOverrides,
    pub(crate) retention: MachineRetention,
    pub(crate) name: Option<String>,
}

/// Durable machine creation state. This is serializable for stable dry-run output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatePlan {
    pub(crate) schema_version: u8,
    pub(crate) proposed_name: Option<String>,
    pub(crate) template: TemplateMetadata,
    pub(crate) image: ImageIdentity,
    pub(crate) machine: MachinePlan,
    pub(crate) machine_settings: MachineCreationSettings,
    pub(crate) process: ProcessConfig,
    pub(crate) retention: MachineRetention,
    pub(crate) cleanup: CleanupPlan,
}

/// Template identity and user-facing metadata selected while resolving this plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateMetadata {
    pub(crate) name: Option<String>,
    pub(crate) version: String,
    pub(crate) description: Option<String>,
}

/// The planned cleanup action after the workload exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CleanupPlan {
    RemoveAfterExit,
    RetainMachine,
}

/// Fixed vmmon execution-log behavior, included because it affects every run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecLogPolicy {
    pub(crate) active_max_bytes: u64,
    pub(crate) archives: Vec<String>,
    pub(crate) queue: String,
    pub(crate) queue_capacity: usize,
}

impl Default for ExecLogPolicy {
    fn default() -> Self {
        Self {
            active_max_bytes: 10 * 1024 * 1024,
            archives: vec![
                "exec.log.1".to_string(),
                "exec.log.2".to_string(),
                "exec.log.3".to_string(),
            ],
            queue: "lossy".to_string(),
            queue_capacity: 64,
        }
    }
}

/// Run state adds only transient execution choices to the durable creation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunPlan {
    pub(crate) schema_version: u8,
    pub(crate) create: CreatePlan,
    pub(crate) argv: Vec<String>,
    pub(crate) mode: RunMode,
    pub(crate) detached: bool,
    pub(crate) tty: bool,
    pub(crate) exec_log: ExecLogPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunMode {
    Foreground,
    Detached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum Plan {
    Create(CreatePlan),
    Run(RunPlan),
}

/// Resolves template, image, machine, environment, and process inputs into an immutable plan.
pub(crate) fn resolve(request: ResolveRequest) -> eyre::Result<Plan> {
    validate_template(&request.template)?;
    validate_template_nuls(&request.template)?;
    validate_request_nuls(&request)?;
    let (image, metadata) = {
        let selected_image = select_image(&request)?;
        (
            selected_image.identity(),
            selected_image.metadata().cloned(),
        )
    };
    let machine = resolve_machine(&request.template, request.machine_overrides)?;
    let process = resolve_process(
        metadata.as_ref(),
        &request.environment_files,
        &request.host_environment,
        &request.environment_overrides,
        &request.command_tail,
        &request.process_overrides,
    )?;
    let create = CreatePlan {
        schema_version: 1,
        proposed_name: request.name,
        template: TemplateMetadata {
            name: request.template_name,
            version: request.template.version.clone(),
            description: request.template.description.clone(),
        },
        image,
        machine,
        machine_settings: request.machine_settings,
        process,
        retention: request.retention,
        cleanup: cleanup_plan(request.retention),
    };

    match request.kind {
        PlanKind::Create => {
            if !request.command_tail.is_empty() {
                bail!("create plans cannot include a command tail");
            }
            Ok(Plan::Create(create))
        }
        PlanKind::Run(options) => resolve_run_plan(create, options),
    }
}

fn select_image(request: &ResolveRequest) -> eyre::Result<&ResolvedImage> {
    if let Some(image) = request.positional_image.as_ref() {
        return validate_image(image);
    }
    let Some(template_reference) = request.template.image.as_deref() else {
        bail!("an image is required when the template does not provide one");
    };
    let image = request.template_image.as_ref().ok_or_else(|| {
        eyre::eyre!("resolved image metadata is required for template image {template_reference:?}")
    })?;
    if image.requested_reference() != template_reference {
        bail!(
            "resolved template image {:?} does not match template image {template_reference:?}",
            image.requested_reference()
        );
    }
    validate_image(image)
}

fn validate_image(image: &ResolvedImage) -> eyre::Result<&ResolvedImage> {
    match image {
        ResolvedImage::Oci { identity, metadata } => {
            validate_no_nul(&identity.requested_reference, "image reference")?;
            validate_no_nul(&identity.selected_reference, "selected image reference")?;
            for digest in [&identity.manifest_digest, &identity.config_digest] {
                validate_no_nul(digest, "image digest")?;
            }
            validate_oci_metadata(metadata)?;
        }
        ResolvedImage::Disk { path } => {
            validate_no_nul(&path.to_string_lossy(), "disk image path")?;
        }
    }
    Ok(image)
}

fn resolve_machine(template: &Template, overrides: MachineOverrides) -> eyre::Result<MachinePlan> {
    let mut labels = template.labels.clone();
    labels.extend(overrides.labels);
    let mut mounts = template.mounts.clone();
    mounts.extend(overrides.mounts);
    let selected_resources = overrides
        .resources
        .or_else(|| template.resources.clone())
        .unwrap_or_default();
    let machine = MachinePlan {
        resources: Some(MachineResources {
            cpus: Some(selected_resources.cpus.unwrap_or(1)),
            memory: Some(
                selected_resources
                    .memory
                    .unwrap_or_else(|| "512mb".to_string()),
            ),
        }),
        disk_size: overrides.disk_size.or_else(|| template.disk_size.clone()),
        userdata: overrides.userdata.or_else(|| template.userdata.clone()),
        mounts,
        network: Some(
            overrides
                .network
                .or_else(|| template.network.clone())
                .unwrap_or(MachineNetwork::Private { policy_ref: None }),
        ),
        labels,
    };
    validate_machine_plan(&machine)?;
    Ok(machine)
}

fn resolve_process(
    metadata: Option<&OciImageConfigMetadata>,
    environment_files: &[EnvironmentLayer],
    host_environment: &BTreeMap<String, String>,
    environment_overrides: &[EnvironmentOverride],
    command_tail: &[String],
    overrides: &ProcessOverrides,
) -> eyre::Result<ProcessConfig> {
    let entrypoint = overrides
        .entrypoint
        .clone()
        .or_else(|| metadata.and_then(|metadata| metadata.entrypoint.clone()));
    let command = if command_tail.is_empty() {
        if overrides.entrypoint.is_some() {
            None
        } else {
            metadata.and_then(|metadata| metadata.cmd.clone())
        }
    } else {
        Some(command_tail.to_vec())
    };
    let working_directory = overrides
        .working_directory
        .clone()
        .or_else(|| metadata.and_then(|metadata| metadata.working_dir.clone()))
        .filter(|working_directory| !working_directory.is_empty())
        .unwrap_or_else(|| "/".to_string());
    let user = overrides
        .user
        .clone()
        .or_else(|| metadata.and_then(|metadata| metadata.user.clone()))
        .filter(|user| !user.is_empty());
    let environment = resolve_environment(
        metadata.and_then(|metadata| metadata.env.as_deref()),
        environment_files,
        environment_overrides,
        host_environment,
    )?;
    validate_process_parts(
        entrypoint.as_deref(),
        command.as_deref(),
        &working_directory,
        user.as_deref(),
    )?;
    let mut process = ProcessConfig::new();
    process.entrypoint = entrypoint;
    process.command = command;
    process.environment = environment;
    process.working_directory = working_directory;
    process.user = user;
    Ok(process)
}

fn resolve_run_plan(create: CreatePlan, options: RunOptions) -> eyre::Result<Plan> {
    if options.detached && options.tty == TtyMode::Enabled {
        bail!("--detach cannot be combined with TTY");
    }
    let tty = match options.tty {
        TtyMode::Auto => {
            !options.detached && options.capabilities.stdin && options.capabilities.stdout
        }
        TtyMode::Enabled => true,
        TtyMode::Disabled => false,
    };
    let mut argv = Vec::new();
    if let Some(entrypoint) = &create.process.entrypoint {
        argv.extend(entrypoint.clone());
    }
    if let Some(command) = &create.process.command {
        argv.extend(command.clone());
    }
    if let Some(shell) = options.shell {
        if !argv.is_empty() {
            bail!("--shell is only supported when the image process is empty");
        }
        if options.detached || !tty {
            bail!("--shell requires a foreground interactive run");
        }
        argv.push(shell);
    }
    if argv.is_empty() {
        if options.detached || !tty {
            bail!("an empty command requires a foreground interactive run");
        }
        argv.push("/bin/sh".to_string());
    }
    Ok(Plan::Run(RunPlan {
        schema_version: 1,
        create,
        argv,
        mode: if options.detached {
            RunMode::Detached
        } else {
            RunMode::Foreground
        },
        detached: options.detached,
        tty,
        exec_log: ExecLogPolicy::default(),
    }))
}

impl ResolvedImage {
    fn requested_reference(&self) -> String {
        match self {
            Self::Oci { identity, .. } => identity.requested_reference.clone(),
            Self::Disk { path, .. } => format!("disk:{}", path.display()),
        }
    }

    fn metadata(&self) -> Option<&OciImageConfigMetadata> {
        match self {
            Self::Oci { metadata, .. } => Some(metadata),
            Self::Disk { .. } => None,
        }
    }

    fn identity(&self) -> ImageIdentity {
        match self {
            Self::Oci { identity, .. } => ImageIdentity::Oci(identity.clone()),
            Self::Disk { path, .. } => ImageIdentity::Disk { path: path.clone() },
        }
    }
}

fn validate_request_nuls(request: &ResolveRequest) -> eyre::Result<()> {
    for value in [request.name.as_deref(), request.template_name.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_no_nul(value, "plan identity")?;
    }
    for command in &request.command_tail {
        validate_no_nul(command, "command argument")?;
    }
    for value in [
        request.process_overrides.working_directory.as_deref(),
        request.process_overrides.user.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_no_nul(value, "process override")?;
    }
    if let Some(entrypoint) = &request.process_overrides.entrypoint {
        for value in entrypoint {
            validate_no_nul(value, "entrypoint argument")?;
        }
    }
    Ok(())
}

fn validate_machine_plan(machine: &MachinePlan) -> eyre::Result<()> {
    validate_machine_defaults(
        machine.resources.as_ref(),
        machine.disk_size.as_deref(),
        machine.userdata.as_deref(),
        &machine.mounts,
        machine.network.as_ref(),
    )?;
    let mut targets = BTreeSet::new();
    for mount in &machine.mounts {
        validate_no_nul(&mount.source.to_string_lossy(), "mount source")?;
        validate_no_nul(&mount.target, "mount target")?;
        if !targets.insert(&mount.target) {
            bail!("duplicate mount target {:?}", mount.target);
        }
    }
    for (key, value) in &machine.labels {
        validate_no_nul(key, "label key")?;
        validate_no_nul(value, "label value")?;
    }
    for value in [machine.disk_size.as_deref(), machine.userdata.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_no_nul(value, "machine option")?;
    }
    if let Some(resources) = &machine.resources {
        if let Some(memory) = &resources.memory {
            validate_no_nul(memory, "machine memory")?;
        }
    }
    if let Some(network) = &machine.network {
        match network {
            MachineNetwork::Private { policy_ref } => {
                if let Some(policy_ref) = policy_ref {
                    validate_no_nul(policy_ref, "network policy reference")?;
                }
            }
            MachineNetwork::Named { name } => validate_no_nul(name, "network name")?,
            MachineNetwork::None => {}
        }
    }
    Ok(())
}

fn validate_template_nuls(template: &Template) -> eyre::Result<()> {
    for value in [template.description.as_deref(), template.image.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_no_nul(value, "template value")?;
    }
    validate_machine_plan(&MachinePlan {
        resources: template.resources.clone(),
        disk_size: template.disk_size.clone(),
        userdata: template.userdata.clone(),
        mounts: template.mounts.clone(),
        network: template.network.clone(),
        labels: template.labels.clone(),
    })
}

fn validate_oci_metadata(metadata: &OciImageConfigMetadata) -> eyre::Result<()> {
    for values in [
        metadata.entrypoint.as_deref(),
        metadata.cmd.as_deref(),
        metadata.env.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for value in values {
            validate_no_nul(value, "OCI metadata")?;
        }
    }
    for value in [metadata.working_dir.as_deref(), metadata.user.as_deref()]
        .into_iter()
        .flatten()
    {
        validate_no_nul(value, "OCI metadata")?;
    }
    Ok(())
}

fn validate_process_parts(
    entrypoint: Option<&[String]>,
    command: Option<&[String]>,
    working_directory: &str,
    user: Option<&str>,
) -> eyre::Result<()> {
    for values in [entrypoint, command].into_iter().flatten() {
        for value in values {
            validate_no_nul(value, "process argument")?;
        }
    }
    validate_no_nul(working_directory, "working directory")?;
    if !working_directory.starts_with('/') {
        bail!("working directory must be an absolute guest path");
    }
    if let Some(user) = user {
        validate_no_nul(user, "process user")?;
        let mut components = user.split(':');
        let valid = components
            .by_ref()
            .take(2)
            .all(|component| !component.is_empty() && !component.chars().any(char::is_whitespace));
        if !valid || components.next().is_some() {
            bail!("process user must be USER, UID, USER:GROUP, or UID:GID");
        }
    }
    let executable = entrypoint
        .and_then(|values| values.first())
        .or_else(|| command.and_then(|values| values.first()));
    if executable.is_some_and(String::is_empty) {
        bail!("process executable cannot be empty");
    }
    Ok(())
}

fn cleanup_plan(retention: MachineRetention) -> CleanupPlan {
    match retention {
        MachineRetention::Ephemeral => CleanupPlan::RemoveAfterExit,
        MachineRetention::Persistent => CleanupPlan::RetainMachine,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use libvm::{MachineAgent, MachineRetention, OciImageConfigMetadata, Platform};

    use crate::environment::{EnvironmentLayer, EnvironmentOverride, MINIMAL_LINUX_PATH};
    use crate::machine_defaults::{MachineMount, MountMode};
    use crate::planning::{
        resolve, CreatePlan, ImageCacheState, ImageIdentity, MachineCreationSettings,
        MachineOverrides, OciImageIdentity, Plan, PlanKind, ProcessOverrides, PullPolicy,
        ResolveRequest, ResolvedImage, RunOptions, TtyCapabilities, TtyMode,
    };
    use crate::template::Template;

    fn template(image: Option<&str>) -> Template {
        Template {
            version: "1".to_string(),
            description: None,
            image: image.map(str::to_string),
            resources: None,
            disk_size: None,
            userdata: None,
            mounts: Vec::new(),
            network: None,
            labels: BTreeMap::from([("template".to_string(), "yes".to_string())]),
        }
    }

    fn oci(reference: &str, metadata: OciImageConfigMetadata) -> ResolvedImage {
        ResolvedImage::Oci {
            identity: OciImageIdentity {
                requested_reference: reference.to_string(),
                selected_reference: format!("{reference}@sha256:selected"),
                platform: Platform::linux_amd64(),
                manifest_digest: "sha256:manifest".to_string(),
                config_digest: "sha256:config".to_string(),
                cache_state: ImageCacheState::Complete,
                pull_policy: PullPolicy::IfMissing,
            },
            metadata: Box::new(metadata),
        }
    }

    fn request(kind: PlanKind, metadata: OciImageConfigMetadata) -> ResolveRequest {
        ResolveRequest {
            kind,
            template: template(Some("example:template")),
            template_name: Some("development".to_string()),
            template_image: Some(oci("example:template", metadata)),
            positional_image: None,
            machine_overrides: MachineOverrides::default(),
            machine_settings: MachineCreationSettings {
                kernel: None,
                initramfs: None,
                kernel_args: Vec::new(),
                nested_virtualization: false,
                rosetta: false,
                disks: Vec::new(),
                agent: MachineAgent::Default,
                provision_user: None,
            },
            environment_files: Vec::new(),
            host_environment: BTreeMap::new(),
            environment_overrides: Vec::new(),
            command_tail: Vec::new(),
            process_overrides: ProcessOverrides::default(),
            retention: MachineRetention::Persistent,
            name: Some("dev".to_string()),
        }
    }

    fn create_plan(plan: Plan) -> CreatePlan {
        let Plan::Create(plan) = plan else {
            panic!("expected create plan");
        };
        plan
    }

    #[test]
    fn positional_image_overrides_the_template_image() {
        let mut input = request(PlanKind::Create, OciImageConfigMetadata::default());
        input.positional_image = Some(oci("example:positional", OciImageConfigMetadata::default()));
        let plan = create_plan(resolve(input).expect("resolve plan"));

        assert_eq!(
            plan.image,
            ImageIdentity::Oci(OciImageIdentity {
                requested_reference: "example:positional".to_string(),
                selected_reference: "example:positional@sha256:selected".to_string(),
                platform: Platform::linux_amd64(),
                manifest_digest: "sha256:manifest".to_string(),
                config_digest: "sha256:config".to_string(),
                cache_state: ImageCacheState::Complete,
                pull_policy: PullPolicy::IfMissing,
            })
        );
    }

    #[test]
    fn process_resolution_follows_oci_and_cli_precedence_table() {
        let metadata = OciImageConfigMetadata {
            entrypoint: Some(vec!["/oci-entrypoint".to_string()]),
            cmd: Some(vec!["oci-cmd".to_string()]),
            env: Some(vec!["OCI=one".to_string()]),
            working_dir: Some("/oci-workdir".to_string()),
            user: Some("oci-user".to_string()),
            ..OciImageConfigMetadata::default()
        };
        let cases = [
            (
                ProcessOverrides::default(),
                Vec::new(),
                Some(vec!["/oci-entrypoint".to_string()]),
                Some(vec!["oci-cmd".to_string()]),
            ),
            (
                ProcessOverrides {
                    entrypoint: Some(vec!["/cli-entrypoint".to_string()]),
                    ..ProcessOverrides::default()
                },
                Vec::new(),
                Some(vec!["/cli-entrypoint".to_string()]),
                None,
            ),
            (
                ProcessOverrides {
                    entrypoint: Some(vec!["/cli-entrypoint".to_string()]),
                    ..ProcessOverrides::default()
                },
                vec!["tail".to_string()],
                Some(vec!["/cli-entrypoint".to_string()]),
                Some(vec!["tail".to_string()]),
            ),
            (
                ProcessOverrides::default(),
                vec!["tail".to_string(), "arg".to_string()],
                Some(vec!["/oci-entrypoint".to_string()]),
                Some(vec!["tail".to_string(), "arg".to_string()]),
            ),
        ];
        for (overrides, command_tail, expected_entrypoint, expected_command) in cases {
            let mut input = request(PlanKind::Create, metadata.clone());
            input.process_overrides = overrides;
            input.command_tail = command_tail;
            if !input.command_tail.is_empty() {
                input.kind = PlanKind::Run(RunOptions {
                    tty: TtyMode::Auto,
                    capabilities: TtyCapabilities {
                        stdin: true,
                        stdout: true,
                    },
                    ..RunOptions::default()
                });
                let Plan::Run(plan) = resolve(input).expect("resolve run plan") else {
                    panic!("expected run plan")
                };
                assert_eq!(plan.create.process.entrypoint, expected_entrypoint);
                assert_eq!(plan.create.process.command, expected_command);
            } else {
                let plan = create_plan(resolve(input).expect("resolve create plan"));
                assert_eq!(plan.process.entrypoint, expected_entrypoint);
                assert_eq!(plan.process.command, expected_command);
            }
        }
    }

    #[test]
    fn environment_cwd_user_and_machine_values_are_deterministic() {
        let metadata = OciImageConfigMetadata {
            env: Some(vec!["SHARED=oci".to_string(), "OCI=one".to_string()]),
            working_dir: Some("/oci".to_string()),
            user: Some("oci-user".to_string()),
            ..OciImageConfigMetadata::default()
        };
        let mut input = request(PlanKind::Create, metadata);
        input.environment_files = vec![EnvironmentLayer::new(BTreeMap::from([(
            "SHARED".to_string(),
            "file".to_string(),
        )]))
        .expect("environment layer")];
        input.host_environment = BTreeMap::from([("HOST".to_string(), "captured".to_string())]);
        input.environment_overrides = vec![
            EnvironmentOverride::parse("SHARED=cli").expect("parse set"),
            EnvironmentOverride::parse("HOST").expect("parse import"),
        ];
        input.process_overrides = ProcessOverrides {
            working_directory: Some("/cli".to_string()),
            user: Some("cli-user".to_string()),
            ..ProcessOverrides::default()
        };
        input
            .machine_overrides
            .labels
            .insert("template".to_string(), "override".to_string());
        let plan = create_plan(resolve(input).expect("resolve plan"));

        assert_eq!(plan.process.environment["SHARED"], "cli");
        assert_eq!(plan.process.environment["HOST"], "captured");
        assert_eq!(plan.process.environment["PATH"], MINIMAL_LINUX_PATH);
        assert_eq!(plan.process.working_directory, "/cli");
        assert_eq!(plan.process.user.as_deref(), Some("cli-user"));
        assert_eq!(plan.machine.labels["template"], "override");
    }

    #[test]
    fn cwd_and_user_precedence_table_includes_oci_and_empty_fallbacks() {
        let cases = [
            (None, None, "/", None),
            (None, Some(("/oci", "oci-user")), "/oci", Some("oci-user")),
            (None, Some(("", "")), "/", None),
            (
                Some(("/cli", "cli-user")),
                Some(("/oci", "oci-user")),
                "/cli",
                Some("cli-user"),
            ),
        ];
        for (overrides, image_values, expected_cwd, expected_user) in cases {
            let metadata =
                image_values.map_or_else(OciImageConfigMetadata::default, |(cwd, user)| {
                    OciImageConfigMetadata {
                        working_dir: Some(cwd.to_string()),
                        user: Some(user.to_string()),
                        ..OciImageConfigMetadata::default()
                    }
                });
            let mut input = request(PlanKind::Create, metadata);
            input.process_overrides =
                overrides.map_or_else(ProcessOverrides::default, |(cwd, user)| ProcessOverrides {
                    working_directory: Some(cwd.to_string()),
                    user: Some(user.to_string()),
                    ..ProcessOverrides::default()
                });
            let plan = create_plan(resolve(input).expect("resolve plan"));

            assert_eq!(plan.process.working_directory, expected_cwd);
            assert_eq!(plan.process.user.as_deref(), expected_user);
        }
    }

    #[test]
    fn rejects_invalid_resolved_process_grammar() {
        for metadata in [
            OciImageConfigMetadata {
                working_dir: Some("relative".to_string()),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                user: Some("user:group:extra".to_string()),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                cmd: Some(vec![String::new()]),
                ..OciImageConfigMetadata::default()
            },
        ] {
            assert!(resolve(request(PlanKind::Create, metadata)).is_err());
        }
    }

    #[test]
    fn template_and_cli_resources_reject_zero_cpus() {
        let mut template_resources = request(PlanKind::Create, OciImageConfigMetadata::default());
        template_resources.template.resources = Some(crate::machine_defaults::MachineResources {
            cpus: Some(0),
            memory: None,
        });
        assert!(resolve(template_resources).is_err());

        let mut cli_resources = request(PlanKind::Create, OciImageConfigMetadata::default());
        cli_resources.machine_overrides.resources =
            Some(crate::machine_defaults::MachineResources {
                cpus: Some(0),
                memory: None,
            });
        assert!(resolve(cli_resources).is_err());
    }

    #[test]
    fn disk_has_no_oci_metadata() {
        let mut input = request(PlanKind::Create, OciImageConfigMetadata::default());
        input.positional_image = Some(ResolvedImage::Disk {
            path: PathBuf::from("rootfs.img"),
        });
        let plan = create_plan(resolve(input).expect("resolve disk plan"));
        assert_eq!(plan.process.entrypoint, None);
        assert_eq!(plan.process.command, None);
        assert!(matches!(plan.image, ImageIdentity::Disk { .. }));
    }

    #[test]
    fn run_uses_exact_argv_and_an_optional_transient_shell_fallback() {
        let metadata = OciImageConfigMetadata::default();
        let mut interactive = request(
            PlanKind::Run(RunOptions {
                tty: TtyMode::Auto,
                capabilities: TtyCapabilities {
                    stdin: true,
                    stdout: true,
                },
                shell: Some("/bin/sh".to_string()),
                ..RunOptions::default()
            }),
            metadata.clone(),
        );
        interactive.template_image = Some(oci("example:template", metadata));
        let Plan::Run(plan) = resolve(interactive).expect("interactive shell") else {
            panic!("expected run")
        };
        assert_eq!(plan.argv, ["/bin/sh"]);
        assert_eq!(plan.create.process.entrypoint, None);
        assert_eq!(plan.create.process.command, None);

        let default_shell = request(
            PlanKind::Run(RunOptions {
                tty: TtyMode::Enabled,
                ..RunOptions::default()
            }),
            OciImageConfigMetadata::default(),
        );
        let Plan::Run(plan) = resolve(default_shell).expect("default interactive shell") else {
            panic!("expected run")
        };
        assert_eq!(plan.argv, ["/bin/sh"]);

        let mut noninteractive = request(
            PlanKind::Run(RunOptions::default()),
            OciImageConfigMetadata::default(),
        );
        noninteractive.template_image =
            Some(oci("example:template", OciImageConfigMetadata::default()));
        assert!(resolve(noninteractive).is_err());

        let mut command = request(
            PlanKind::Run(RunOptions::default()),
            OciImageConfigMetadata::default(),
        );
        command.template_image = Some(oci("example:template", OciImageConfigMetadata::default()));
        command.command_tail = vec![
            "printf".to_string(),
            "%s".to_string(),
            "hello world".to_string(),
        ];
        let Plan::Run(plan) = resolve(command).expect("exact command") else {
            panic!("expected run")
        };
        assert_eq!(plan.argv, ["printf", "%s", "hello world"]);
    }

    #[test]
    fn shell_fallback_rejects_a_configured_process() {
        let input = request(
            PlanKind::Run(RunOptions {
                shell: Some("/bin/sh".to_string()),
                ..RunOptions::default()
            }),
            OciImageConfigMetadata {
                entrypoint: Some(vec!["/entrypoint".to_string()]),
                cmd: Some(vec!["serve".to_string()]),
                ..OciImageConfigMetadata::default()
            },
        );
        assert!(resolve(input).is_err());
    }

    #[test]
    fn shell_fallback_rejects_noninteractive_runs_and_command_tails() {
        let noninteractive = request(
            PlanKind::Run(RunOptions {
                tty: TtyMode::Disabled,
                shell: Some("/bin/sh".to_string()),
                ..RunOptions::default()
            }),
            OciImageConfigMetadata::default(),
        );
        assert!(resolve(noninteractive).is_err());

        let mut command_tail = request(
            PlanKind::Run(RunOptions {
                tty: TtyMode::Enabled,
                shell: Some("/bin/sh".to_string()),
                ..RunOptions::default()
            }),
            OciImageConfigMetadata::default(),
        );
        command_tail.command_tail = vec!["true".to_string()];
        assert!(resolve(command_tail).is_err());
    }

    #[test]
    fn tty_and_mount_validation_cover_invalid_plan_combinations() {
        let detached_tty = request(
            PlanKind::Run(RunOptions {
                detached: true,
                tty: TtyMode::Enabled,
                ..RunOptions::default()
            }),
            OciImageConfigMetadata {
                cmd: Some(vec!["true".to_string()]),
                ..OciImageConfigMetadata::default()
            },
        );
        assert!(resolve(detached_tty).is_err());

        let mut duplicate_mount = request(PlanKind::Create, OciImageConfigMetadata::default());
        duplicate_mount.template.mounts.push(MachineMount {
            source: "/one".into(),
            target: "/workspace".to_string(),
            mode: MountMode::Rw,
        });
        duplicate_mount.machine_overrides.mounts.push(MachineMount {
            source: "/two".into(),
            target: "/workspace".to_string(),
            mode: MountMode::Ro,
        });
        assert!(resolve(duplicate_mount).is_err());
    }

    #[test]
    fn tty_selection_table_uses_both_terminal_capabilities() {
        let cases = [
            (
                TtyMode::Auto,
                TtyCapabilities {
                    stdin: true,
                    stdout: true,
                },
                false,
                true,
            ),
            (
                TtyMode::Auto,
                TtyCapabilities {
                    stdin: true,
                    stdout: false,
                },
                false,
                false,
            ),
            (
                TtyMode::Auto,
                TtyCapabilities {
                    stdin: false,
                    stdout: true,
                },
                false,
                false,
            ),
            (
                TtyMode::Disabled,
                TtyCapabilities {
                    stdin: true,
                    stdout: true,
                },
                false,
                false,
            ),
            (
                TtyMode::Enabled,
                TtyCapabilities {
                    stdin: false,
                    stdout: false,
                },
                false,
                true,
            ),
            (
                TtyMode::Auto,
                TtyCapabilities {
                    stdin: true,
                    stdout: true,
                },
                true,
                false,
            ),
        ];
        for (tty, capabilities, detached, expected) in cases {
            let input = request(
                PlanKind::Run(RunOptions {
                    detached,
                    tty,
                    capabilities,
                    shell: None,
                }),
                OciImageConfigMetadata {
                    cmd: Some(vec!["true".to_string()]),
                    ..OciImageConfigMetadata::default()
                },
            );
            let Plan::Run(plan) = resolve(input).expect("resolve run plan") else {
                panic!("expected run plan");
            };
            assert_eq!(plan.tty, expected);
        }
    }

    fn json(plan: Plan) -> serde_json::Value {
        serde_json::to_value(plan).expect("serialize plan")
    }

    #[test]
    fn create_plan_serde_snapshot_has_complete_creation_state() {
        let plan = resolve(request(PlanKind::Create, OciImageConfigMetadata::default()))
            .expect("resolve plan");

        assert_eq!(
            json(plan),
            serde_json::json!({
                "operation": "create",
                "schemaVersion": 1,
                "proposedName": "dev",
                "template": {
                    "name": "development",
                    "version": "1",
                    "description": null
                },
                "image": {
                    "kind": "oci",
                    "requestedReference": "example:template",
                    "selectedReference": "example:template@sha256:selected",
                    "platform": { "os": "linux", "architecture": "amd64" },
                    "manifestDigest": "sha256:manifest",
                    "configDigest": "sha256:config",
                    "cacheState": "complete",
                    "pullPolicy": "if_missing"
                },
                "machine": {
                    "resources": { "cpus": 1, "memory": "512mb" },
                    "diskSize": null,
                    "userdata": null,
                    "mounts": [],
                    "network": { "kind": "private" },
                    "labels": { "template": "yes" }
                },
                "machineSettings": {
                    "kernel": null,
                    "initramfs": null,
                    "kernelArgs": [],
                    "nestedVirtualization": false,
                    "rosetta": false,
                    "disks": [],
                    "agent": { "mode": "default" },
                    "provisionUser": null
                },
                "process": {
                    "entrypoint": null,
                    "command": null,
                    "environment": {
                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                    },
                    "workingDirectory": "/",
                    "user": null
                },
                "retention": "persistent",
                "cleanup": "retain_machine"
            })
        );
    }

    #[test]
    fn foreground_run_plan_serde_snapshot_has_effective_argv_and_tty() {
        let plan = resolve(request(
            PlanKind::Run(RunOptions {
                tty: TtyMode::Auto,
                capabilities: TtyCapabilities {
                    stdin: true,
                    stdout: true,
                },
                ..RunOptions::default()
            }),
            OciImageConfigMetadata {
                entrypoint: Some(vec!["/entrypoint".to_string()]),
                cmd: Some(vec!["serve".to_string()]),
                ..OciImageConfigMetadata::default()
            },
        ))
        .expect("resolve plan");
        let output = json(plan);

        assert_eq!(output["operation"], "run");
        assert_eq!(output["schemaVersion"], 1);
        assert_eq!(output["argv"], serde_json::json!(["/entrypoint", "serve"]));
        assert_eq!(output["mode"], "foreground");
        assert_eq!(output["detached"], false);
        assert_eq!(output["tty"], true);
        assert_eq!(
            output["execLog"],
            serde_json::json!({
                "activeMaxBytes": 10_485_760,
                "archives": ["exec.log.1", "exec.log.2", "exec.log.3"],
                "queue": "lossy",
                "queueCapacity": 64
            })
        );
    }

    #[test]
    fn detached_run_plan_serde_snapshot_records_best_effort_cleanup() {
        let mut input = request(
            PlanKind::Run(RunOptions {
                detached: true,
                ..RunOptions::default()
            }),
            OciImageConfigMetadata {
                cmd: Some(vec!["worker".to_string()]),
                ..OciImageConfigMetadata::default()
            },
        );
        input.retention = MachineRetention::Ephemeral;
        let output = json(resolve(input).expect("resolve plan"));

        assert_eq!(output["operation"], "run");
        assert_eq!(output["schemaVersion"], 1);
        assert_eq!(output["argv"], serde_json::json!(["worker"]));
        assert_eq!(output["mode"], "detached");
        assert_eq!(output["detached"], true);
        assert_eq!(output["tty"], false);
        assert_eq!(output["create"]["cleanup"], "remove_after_exit");
    }

    #[test]
    fn oci_cache_state_serde_snapshot_distinguishes_cached_and_missing_images() {
        for (cache_state, expected) in [
            (ImageCacheState::Complete, "complete"),
            (ImageCacheState::Missing, "missing"),
        ] {
            let mut input = request(PlanKind::Create, OciImageConfigMetadata::default());
            let ResolvedImage::Oci { identity, .. } =
                input.template_image.as_mut().expect("template image")
            else {
                panic!("expected OCI image")
            };
            identity.cache_state = cache_state;
            let output = json(resolve(input).expect("resolve plan"));
            assert_eq!(output["image"]["cacheState"], expected);
            assert_eq!(output["image"]["pullPolicy"], "if_missing");
        }
    }

    #[test]
    fn disk_plan_serde_snapshot_has_no_oci_or_registry_state() {
        let mut input = request(PlanKind::Create, OciImageConfigMetadata::default());
        input.positional_image = Some(ResolvedImage::Disk {
            path: PathBuf::from("rootfs.img"),
        });
        let output = json(resolve(input).expect("resolve disk plan"));

        assert_eq!(
            output["image"],
            serde_json::json!({
                "kind": "disk",
                "path": "rootfs.img"
            })
        );
    }

    #[test]
    fn plan_serde_contains_the_exact_persisted_environment_and_userdata() {
        let mut input = request(PlanKind::Create, OciImageConfigMetadata::default());
        input.host_environment =
            BTreeMap::from([("HOST_TOKEN".to_string(), "not-for-output".to_string())]);
        input.environment_overrides = vec![EnvironmentOverride::Import {
            key: "HOST_TOKEN".to_string(),
        }];
        input.machine_overrides.userdata = Some("#!/bin/sh\necho not-for-output\n".to_string());
        let rendered =
            serde_json::to_string(&resolve(input).expect("resolve plan")).expect("serialize plan");

        assert!(rendered.contains("HOST_TOKEN"));
        assert!(rendered.matches("not-for-output").count() >= 2);
        assert!(!rendered.contains("<redacted>"));
    }
}

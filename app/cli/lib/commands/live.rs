use crate::context::Context;
use clap::{Args, Subcommand};

const EXACT_BYTES_WARNING: &str = "Copies exact storage bytes, including credentials, guest keys, dirty journals and deleted-data remnants. No sanitization, journal replay, implicit stop or implicit start is performed. External resources require explicit policy. Layered snapshots retain their authenticated immutable composition and exact writable upper.";

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CapturePolicyArgument {
    Full,
    Incremental,
}

#[derive(Debug, Args)]
struct CapturePolicyArgs {
    /// RAM capture policy (default incremental). Uses full capture without an admitted
    /// incremental backend or valid baseline; full always forces a complete capture.
    #[arg(long, requires = "live", value_enum)]
    capture_policy: Option<CapturePolicyArgument>,
    /// Fall back to full RAM capture at this dirty percentage (1..=60, default 60).
    #[arg(long, requires = "live", value_parser = clap::value_parser!(u8).range(1..=60))]
    dirty_crossover_percent: Option<u8>,
}

impl CapturePolicyArgs {
    fn policy(&self) -> vm_spec::lifecycle::CapturePolicy {
        match self.capture_policy {
            Some(CapturePolicyArgument::Incremental) | None => {
                vm_spec::lifecycle::CapturePolicy::Incremental
            }
            Some(CapturePolicyArgument::Full) => vm_spec::lifecycle::CapturePolicy::Full,
        }
    }

    fn crossover(&self) -> u8 {
        self.dirty_crossover_percent.unwrap_or(60)
    }
}

#[derive(Debug, Args)]
#[command(about = "Pause a running VM (requires live capability admission)")]
pub struct Pause {
    #[arg(value_name = "VM")]
    machine: String,
}
impl Pause {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        context
            .app_api()
            .await?
            .pause_machine(&self.machine)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Args)]
#[command(about = "Resume the current user-owned pause of a VM")]
pub struct Resume {
    #[arg(value_name = "VM")]
    machine: String,
}
impl Resume {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        context
            .app_api()
            .await?
            .resume_machine(&self.machine)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Args)]
#[command(about = "Create and manage immutable stopped-storage and live execution checkpoints", after_help = EXACT_BYTES_WARNING)]
pub struct Snapshot {
    #[command(subcommand)]
    command: SnapshotCommand,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Capture a stopped machine's storage, or explicitly request a live execution capture.
    Create {
        #[arg(value_name = "VM")]
        machine: String,
        /// Optional alias in the shared image: namespace. Unnamed snapshots remain retained.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Request live execution capture, never fall back to stopped storage.
        #[arg(long, conflicts_with = "external_requirements")]
        live: bool,
        /// Keep a running source paused after capture. An already user-paused source
        /// always stays paused, with or without this flag.
        #[arg(long, requires = "live")]
        preserve: bool,
        #[command(flatten)]
        capture: CapturePolicyArgs,
        /// Omit external resources and record required mappings for a later restore.
        #[arg(long)]
        external_requirements: bool,
    },
    /// Inspect an immutable snapshot by image: alias or image:sha256: identity.
    Inspect {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// List retained snapshots, including unnamed checkpoints.
    List,
    /// Release explicit snapshot retention. Aliases and other consumers still retain bytes.
    Remove {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
}
impl Snapshot {
    pub(crate) fn is_live(&self) -> bool {
        matches!(self.command, SnapshotCommand::Create { live: true, .. })
    }

    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let api = context.app_api().await?;
        match self.command {
            SnapshotCommand::Create {
                machine,
                name,
                live: true,
                preserve,
                capture,
                ..
            } => {
                let resume_policy = if preserve {
                    vm_spec::lifecycle::CaptureResumePolicy::Preserve
                } else {
                    vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired
                };
                let snapshot = api
                    .snapshot_live(
                        &machine,
                        libvm::LiveSnapshotOptions {
                            name,
                            resume_policy,
                            policy: capture.policy(),
                            dirty_crossover_percent: capture.crossover(),
                        },
                    )
                    .await?;
                crate::ui::warn(EXACT_BYTES_WARNING);
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
                snapshot.require_requested_name()?;
                Ok(())
            }
            SnapshotCommand::Create {
                machine,
                name,
                live: false,
                external_requirements,
                ..
            } => {
                let external_resources = if external_requirements {
                    libvm::ExternalResourcePolicy::RequireMappings
                } else {
                    libvm::ExternalResourcePolicy::Reject
                };
                let options = libvm::SnapshotOptions {
                    name,
                    external_resources,
                };
                let info = api.snapshot_stopped(&machine, options).await?;
                crate::ui::warn(EXACT_BYTES_WARNING);
                println!("{}", serde_json::to_string_pretty(&info)?);
                Ok(())
            }
            SnapshotCommand::Inspect { reference } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&api.inspect_snapshot(&reference).await?)?
                );
                Ok(())
            }
            SnapshotCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&api.list_snapshots().await?)?
                );
                Ok(())
            }
            SnapshotCommand::Remove { reference } => api.release_snapshot(&reference).await,
        }
    }
}

#[derive(Debug, Args)]
#[command(
    about = "Fork a stopped VM into a stopped machine, or a running VM into running children",
    long_about = "Fork a stopped VM into a new stopped machine, or (--live) fork a running VM's execution into running children.\n\nA live fork captures the source once and restores one running child per --name (or --children-json entry) under one durable operation. Its JSON result names every child with its reserved machine and run IDs, plus the source outcome. A failed child never rolls back its siblings and a nonzero exit never stops running children. More than 16 children requires an explicit --max-children. Children receive no host forwards or guest publication unless granted per child in --children-json. Interrupting the CLI does not cancel the operation: observe it with --operation ID, or record cancellation with --operation ID --cancel.\n\nStopped child publication requires catalog-owned secret-scope recovery. Custom Runtime::with_secret_store overrides are refused; the ordinary CLI FileStore and secret-provider path remains supported.",
    after_help = EXACT_BYTES_WARNING
)]
pub struct Fork {
    #[arg(value_name = "VM", required_unless_present = "operation")]
    machine: Option<String>,
    /// Child name. A stopped fork takes exactly one; repeat it once per child with --live.
    #[arg(
        long,
        value_name = "CHILD",
        required_unless_present_any = ["operation", "children_json"]
    )]
    name: Vec<String>,
    /// Request live execution fork, never implicitly stop the source.
    #[arg(long, conflicts_with_all = ["external_requirements", "map_disk", "map_share"])]
    live: bool,
    /// Live children as a bounded JSON array of {name, activationHook, destination}; destination
    /// grants explicit {forwards, guestPublish} and defaults to no host access.
    #[arg(long, value_name = "JSON", requires = "live", conflicts_with = "name", value_parser = live_fork_children)]
    children_json: Option<LiveForkChildren>,
    /// Explicit live fan-out maximum (default 16). It is a bound, never a child count.
    #[arg(long, value_name = "N", requires = "live")]
    max_children: Option<std::num::NonZeroU32>,
    /// Keep a running source paused after capture. An already user-paused source
    /// always stays paused, with or without this flag.
    #[arg(long, requires = "live")]
    preserve: bool,
    #[command(flatten)]
    capture: CapturePolicyArgs,
    /// Caller-selected live fork operation UUID. Repeating identical options replays the same
    /// operation; changed options conflict. Generated when omitted.
    #[arg(long, value_name = "UUID", requires = "live", value_parser = operation_id)]
    operation_id: Option<uuid::Uuid>,
    /// Observe an existing live fork operation by ID, independent of its source.
    #[arg(
        long,
        value_name = "UUID",
        value_parser = operation_id,
        conflicts_with_all = [
            "machine", "name", "live", "children_json", "max_children", "preserve",
            "operation_id",
            "external_requirements", "map_disk", "map_share",
            "capture_policy", "dirty_crossover_percent",
        ]
    )]
    operation: Option<uuid::Uuid>,
    /// Durably request cancellation of --operation: unsubmitted children never start, submitted
    /// children settle normally and running children are never stopped.
    #[arg(long, requires = "operation", conflicts_with_all = [
        "machine", "name", "live", "children_json", "max_children", "preserve",
        "operation_id",
        "external_requirements", "map_disk", "map_share",
        "capture_policy", "dirty_crossover_percent",
    ])]
    cancel: bool,
    #[command(flatten)]
    external: ExternalResources,
}

/// Strictly decoded `--children-json` array (newtype so clap keeps it one value).
#[derive(Debug, Clone)]
struct LiveForkChildren(Vec<libvm::LiveForkChild>);

#[derive(Debug)]
enum ForkMode {
    Stopped {
        machine: String,
        options: libvm::ForkOptions,
    },
    Live {
        machine: String,
        options: libvm::LiveForkOptions,
    },
    Inspect(uuid::Uuid),
    Cancel(uuid::Uuid),
}

impl Fork {
    /// Live execution modes may reach an owned, stopping daemon for typed refusal or observation.
    pub(crate) fn is_live(&self) -> bool {
        self.live || self.operation.is_some()
    }

    /// Resolves every option before any runtime, daemon or source access.
    fn mode(self) -> eyre::Result<ForkMode> {
        if let Some(operation) = self.operation {
            return Ok(if self.cancel {
                ForkMode::Cancel(operation)
            } else {
                ForkMode::Inspect(operation)
            });
        }
        let machine = self
            .machine
            .ok_or_else(|| eyre::eyre!("fork requires a source VM"))?;
        if !self.live {
            let [name] = <[String; 1]>::try_from(self.name).map_err(|_| {
                eyre::eyre!(
                    "a stopped fork takes exactly one --name; repeat --name only with --live"
                )
            })?;
            return Ok(ForkMode::Stopped {
                machine,
                options: libvm::ForkOptions {
                    name: Some(name),
                    external_resources: self.external.policy()?,
                },
            });
        }
        let children = match self.children_json {
            Some(LiveForkChildren(children)) => children,
            None => self
                .name
                .into_iter()
                .map(|name| libvm::LiveForkChild {
                    name,
                    activation_hook: None,
                    destination: libvm::ForkDestination::default(),
                })
                .collect(),
        };
        let options = libvm::LiveForkOptions {
            operation_id: self.operation_id.unwrap_or_else(uuid::Uuid::new_v4),
            children,
            policy: self.capture.policy(),
            dirty_crossover_percent: self.capture.crossover(),
            max_children: self
                .max_children
                .unwrap_or(libvm::DEFAULT_LIVE_FORK_MAX_CHILDREN),
            resume_policy: if self.preserve {
                vm_spec::lifecycle::CaptureResumePolicy::Preserve
            } else {
                vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired
            },
        };
        options.validate()?;
        Ok(ForkMode::Live { machine, options })
    }

    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mode = self.mode()?;
        let api = context.app_api().await?;
        match mode {
            ForkMode::Stopped { machine, options } => {
                let machine = api.fork_stopped(&machine, options).await?;
                crate::ui::warn(EXACT_BYTES_WARNING);
                println!("{}", machine.id);
                Ok(())
            }
            ForkMode::Live { machine, options } => {
                let operation_id = options.operation_id;
                let result = match api.fork_live(&machine, options).await {
                    Ok(result) => result,
                    Err(error) => {
                        if !fork_rejected_before_acceptance(&error)
                            && !matches!(
                                error.downcast_ref::<libvm::LibVmError>(),
                                Some(libvm::LibVmError::LiveOperationUnsupported { .. })
                            )
                        {
                            let observation = api.inspect_fork(operation_id).await;
                            if let Some(note) =
                                fork_confirmation_note(&error, operation_id, &observation)
                            {
                                crate::ui::warn(note);
                            }
                        }
                        return Err(error);
                    }
                };
                crate::ui::warn(EXACT_BYTES_WARNING);
                // The complete result precedes any failure status.
                println!("{}", serde_json::to_string_pretty(&result)?);
                live_fork_status(&result)
            }
            ForkMode::Inspect(operation_id) => {
                let result = api.inspect_fork(operation_id).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                Ok(())
            }
            ForkMode::Cancel(operation_id) => {
                let result = api.cancel_fork(operation_id).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if result.stage != libvm::ForkStage::Finished {
                    crate::ui::warn(format!(
                        "cancellation of live fork {operation_id} is recorded; submitted children are still settling and running children are never stopped. Observe it with `silo fork --operation {operation_id}`."
                    ));
                }
                Ok(())
            }
        }
    }
}

/// A completed rejection and an authoritative absent operation rule out
/// acceptance. After transport loss an absent lookup may race admission.
fn fork_confirmation_note(
    submission_error: &eyre::Report,
    operation_id: uuid::Uuid,
    observation: &eyre::Result<libvm::LiveForkResult>,
) -> Option<String> {
    if fork_rejected_before_acceptance(submission_error) {
        return None;
    }
    match observation {
        Ok(_) => Some(format!(
            "live fork operation {operation_id} was accepted; observe it with `silo fork --operation {operation_id}`"
        )),
        Err(error)
            if definitive_fork_reply(submission_error)
                && matches!(
                    error.downcast_ref::<libvm::LibVmError>(),
                    Some(libvm::LibVmError::LiveForkNotFound { .. })
                ) => None,
        Err(_) => Some(format!(
            "live fork operation {operation_id} was not confirmed; if it was accepted, observe it with `silo fork --operation {operation_id}`"
        )),
    }
}

fn fork_rejected_before_acceptance(error: &eyre::Report) -> bool {
    error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        status
            .metadata()
            .get("x-silo-mutation-rejected")
            .is_some_and(|value| value == "true")
    })
}

fn definitive_fork_reply(error: &eyre::Report) -> bool {
    if let Some(native) = error.downcast_ref::<libvm::LibVmError>() {
        return !matches!(native, libvm::LibVmError::Io(_));
    }
    error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        matches!(
            status.code(),
            tonic::Code::InvalidArgument
                | tonic::Code::FailedPrecondition
                | tonic::Code::ResourceExhausted
                | tonic::Code::PermissionDenied
                | tonic::Code::Unauthenticated
                | tonic::Code::NotFound
                | tonic::Code::AlreadyExists
        )
    })
}

/// Success means a finished, uncancelled operation with every child running
/// and the source continuation the policy requested. Anything else is a
/// failure status after the full result is printed, never a rollback.
fn live_fork_status(result: &libvm::LiveForkResult) -> eyre::Result<()> {
    let source_satisfied = match result.resume_policy {
        vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired => {
            matches!(result.source, libvm::ForkSourceOutcome::Resumed)
        }
        vm_spec::lifecycle::CaptureResumePolicy::Preserve => {
            matches!(result.source, libvm::ForkSourceOutcome::Preserved)
        }
    };
    let running = result
        .children
        .iter()
        .filter(|child| matches!(child.outcome, libvm::ForkChildOutcome::Running))
        .count();
    if result.stage == libvm::ForkStage::Finished
        && !result.cancellation_requested
        && source_satisfied
        && running == result.children.len()
    {
        return Ok(());
    }
    eyre::bail!(
        "live fork {} did not fully succeed: {running} of {} children running, source continuation {}, operation {}; the JSON result is authoritative and running children are retained",
        result.operation_id,
        result.children.len(),
        if source_satisfied { "as requested" } else { "not as requested" },
        if result.stage == libvm::ForkStage::Finished { "finished" } else { "still in progress" },
    )
}

fn live_fork_children(value: &str) -> Result<LiveForkChildren, String> {
    if value.len() > 1 << 20 {
        return Err("children JSON exceeds 1 MiB".into());
    }
    serde_json::from_str(value)
        .map(LiveForkChildren)
        .map_err(|error| error.to_string())
}

fn operation_id(value: &str) -> Result<uuid::Uuid, String> {
    let id = uuid::Uuid::parse_str(value).map_err(|error| error.to_string())?;
    if id.is_nil() {
        return Err("operation ID must not be the nil UUID".into());
    }
    Ok(id)
}

#[derive(Debug, Args)]
#[command(about = "Restore a checkpoint into a new machine", long_about = "Restore a checkpoint into a new machine.\n\nLive checkpoints resume captured execution through fenced activation; stopped checkpoints create a stopped child. Neither path cold-boots a failed execution restore. Publication uses catalog-owned secret-scope recovery. Custom Runtime::with_secret_store overrides are refused; the ordinary CLI FileStore and secret-provider path remains supported.", after_help = EXACT_BYTES_WARNING)]
pub struct Restore {
    #[arg(value_name = "IMAGE_OR_CHECKPOINT")]
    checkpoint: String,
    #[arg(long, value_name = "CHILD")]
    name: Option<String>,
    /// Bounded RestoreHook JSON (argv, environment, workingDirectory, timeoutMs).
    #[arg(long, value_name = "JSON", value_parser = activation_hook)]
    activation_hook: Option<libvm::RestoreHook>,
    #[command(flatten)]
    external: ExternalResources,
}
impl Restore {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let api = context.app_api().await?;
        let options = libvm::RestoreOptions {
            name: self.name,
            external_resources: self.external.policy()?,
            activation_hook: self.activation_hook,
        };
        let machine = api.restore_snapshot(&self.checkpoint, options).await?;
        crate::ui::warn(EXACT_BYTES_WARNING);
        println!("{}", machine.id);
        Ok(())
    }
}

#[derive(Debug, Args)]
#[command(about = "Recover only a live checkpoint's disks into a new stopped machine", long_about = "Explicitly recover a live checkpoint's captured disks and boot configuration into a new stopped private child. RAM and execution state are discarded, no activation is performed, and the disks may contain dirty journals. This never runs implicitly after a failed execution restore.", after_help = EXACT_BYTES_WARNING)]
pub struct RecoverDisks {
    #[arg(value_name = "IMAGE")]
    checkpoint: String,
    #[arg(long, value_name = "CHILD")]
    name: Option<String>,
    #[command(flatten)]
    external: ExternalResources,
}

impl RecoverDisks {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let options = libvm::RecoverDisksOptions {
            name: self.name,
            external_resources: self.external.policy()?,
        };
        let machine = context
            .app_api()
            .await?
            .recover_checkpoint_disks(&self.checkpoint, options)
            .await?;
        crate::ui::warn(EXACT_BYTES_WARNING);
        println!("{}", machine.id);
        Ok(())
    }
}

fn activation_hook(value: &str) -> Result<libvm::RestoreHook, String> {
    if value.len() > 1 << 20 {
        return Err("activation hook exceeds 1 MiB".into());
    }
    let hook: libvm::RestoreHook =
        serde_json::from_str(value).map_err(|error| error.to_string())?;
    hook.validate()?;
    Ok(hook)
}

#[derive(Debug, Args)]
#[command(about = "Import, convert and manage immutable images in the shared image: namespace")]
pub struct Image {
    #[command(subcommand)]
    command: ImageCommand,
}
#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// Acquire a complete VM artifact without starting it. Digest approval is
    /// integrity consent, not authenticated publisher identity.
    Pull {
        #[arg(value_name = "OCI_REFERENCE")]
        reference: String,
        #[arg(
            long,
            value_name = "SHA256",
            required_unless_present = "require_signature",
            conflicts_with = "require_signature"
        )]
        approve_digest: Option<libvm::ObjectDigest>,
        /// Refuse unless a signature provider is configured and verifies the index.
        #[arg(long)]
        require_signature: bool,
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Publish complete immutable image or checkpoint content to an OCI repository.
    Push {
        #[arg(value_name = "IMAGE")]
        source: String,
        #[arg(value_name = "OCI_DESTINATION")]
        destination: String,
        /// Use raw chunks instead of opportunistic zstd compression.
        #[arg(long)]
        raw: bool,
        /// Acknowledge that publishing a checkpoint exposes its disks and RAM,
        /// including secrets, to the named destination.
        #[arg(long)]
        acknowledge_checkpoint: bool,
    },
    /// Inspect a remote VM artifact's immutable index without retaining or booting it.
    InspectRemote {
        #[arg(value_name = "OCI_REFERENCE")]
        reference: String,
    },
    /// Import a quiesced raw or qcow2 disk as a reusable direct-boot image.
    /// Platform and root selection are required; the boot bundle is pinned now.
    Import {
        #[arg(value_name = "PATH")]
        path: String,
        /// Linux userspace platform of the disk (linux/amd64, linux/arm64[/v8]).
        #[arg(long, value_name = "PLATFORM", value_parser = platform_arg)]
        platform: libvm::LinuxPlatform,
        /// Root selection: whole-disk, auto, gpt:GUID or mbr:N.
        #[arg(long, value_name = "SELECTION", value_parser = root_arg)]
        root: libvm::ImportRootSelection,
        /// Boot profile. Only linux-direct is admitted.
        #[arg(long, value_enum)]
        boot: ImportBootProfile,
        /// Optional alias in the shared image: namespace.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Flatten exactly one selected OCI manifest into a reusable raw image.
    /// Cached per manifest, platform and flattener; never performed at start.
    Convert {
        #[arg(value_name = "OCI_REFERENCE")]
        reference: String,
        /// Explicit output format; conversion creates a whole-disk ext4 raw image.
        #[arg(long, value_enum, required = true)]
        disk_format: crate::commands::storage::ExportFormat,
        /// Linux platform to select from an OCI index; host-native when absent.
        #[arg(long, value_name = "PLATFORM", value_parser = platform_arg)]
        platform: Option<libvm::LinuxPlatform>,
        /// Image pull policy for selecting the manifest.
        #[arg(long, value_enum)]
        pull: Option<crate::commands::create::Pull>,
        /// Optional alias in the shared image: namespace.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Inspect an image or snapshot by image:NAME or image:sha256:HEX. Not a lease.
    Inspect {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// List managed images and snapshots in the shared namespace.
    List,
    /// Release explicit retention of an image or snapshot. Aliases and other
    /// consumers still retain its bytes.
    Release {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// Remove only an image: alias, never release explicit retention.
    Remove {
        #[arg(value_name = "IMAGE_ALIAS")]
        alias: String,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ImportBootProfile {
    LinuxDirect,
}
impl Image {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            ImageCommand::Pull {
                reference,
                approve_digest,
                require_signature,
                name,
            } => {
                let trust = if require_signature {
                    libvm::ArtifactTrust::RequireSignature
                } else {
                    libvm::ArtifactTrust::ApproveDigest {
                        digest: approve_digest
                            .ok_or_else(|| eyre::eyre!("--approve-digest is required"))?,
                    }
                };
                let request = libvm::ArtifactAcquireRequest {
                    reference,
                    trust,
                    alias: name
                        .map(|name| silo_vm_control::stopped::alias(&name))
                        .transpose()?,
                };
                print_json(&context.app_api().await?.acquire_artifact(request).await?)
            }
            ImageCommand::Push {
                source,
                destination,
                raw,
                acknowledge_checkpoint,
            } => {
                let api = context.app_api().await?;
                let source = api.managed_reference(&source).await?;
                let checkpoint_acknowledgement =
                    acknowledge_checkpoint.then(|| libvm::CheckpointPublication {
                        destination: destination.clone(),
                    });
                let request = libvm::ArtifactPublishRequest {
                    source,
                    destination,
                    encoding: if raw {
                        libvm::ArtifactEncoding::Raw
                    } else {
                        libvm::ArtifactEncoding::Zstd
                    },
                    checkpoint_acknowledgement,
                };
                print_json(&api.publish_artifact(request).await?)
            }
            ImageCommand::InspectRemote { reference } => print_json(
                &context
                    .app_api()
                    .await?
                    .inspect_artifact(&reference)
                    .await?,
            ),
            ImageCommand::Import {
                path,
                platform,
                root,
                boot: ImportBootProfile::LinuxDirect,
                name,
            } => {
                let path = crate::commands::create::disk_source_path("image import", &path)?;
                let request = libvm::DiskImportRequest {
                    path,
                    boot: libvm::DiskImportBoot::LinuxDirect {
                        platform,
                        root,
                        assets: libvm::BootAssetSelection::Packaged,
                    },
                    alias: name
                        .map(|name| silo_vm_control::stopped::alias(&name))
                        .transpose()?,
                };
                let (progress, events) = libvm::ImageProgressSender::default_channel();
                let watcher = crate::ui::watch_image_progress("image import", events);
                let result = context
                    .app_api()
                    .await?
                    .import_image(request, progress)
                    .await;
                let _ = watcher.await;
                print_json(&result?)
            }
            ImageCommand::Convert {
                reference,
                disk_format: crate::commands::storage::ExportFormat::Raw,
                platform,
                pull,
                name,
            } => {
                let options = libvm::RawConversionOptions {
                    alias: name
                        .map(|name| silo_vm_control::stopped::alias(&name))
                        .transpose()?,
                };
                let pull = pull.map_or(libvm::ImagePullPolicy::IfMissing, |pull| pull.policy());
                let (progress, events) = libvm::ImageProgressSender::default_channel();
                let watcher = crate::ui::watch_image_progress(&reference, events);
                let result = context
                    .app_api()
                    .await?
                    .convert_image(reference, pull, platform, options, progress)
                    .await;
                let _ = watcher.await;
                print_json(&result?)
            }
            ImageCommand::Inspect { reference } => {
                print_json(&context.app_api().await?.inspect_managed(&reference).await?)
            }
            ImageCommand::List => print_json(&context.app_api().await?.list_managed().await?),
            ImageCommand::Release { reference } => {
                context.app_api().await?.release_image(&reference).await
            }
            ImageCommand::Remove { alias } => {
                context.app_api().await?.remove_image_alias(&alias).await
            }
        }
    }
}

fn print_json(value: &impl serde::Serialize) -> eyre::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn platform_arg(value: &str) -> Result<libvm::LinuxPlatform, String> {
    silo_vm_control::boot::parse_platform(value).map_err(|error| error.to_string())
}

fn root_arg(value: &str) -> Result<libvm::ImportRootSelection, String> {
    silo_vm_control::boot::parse_import_root(value).map_err(|error| error.to_string())
}

#[derive(Debug, Args, Default)]
pub(crate) struct ExternalResources {
    /// Omit external files from capture and retain explicit required destination mappings.
    #[arg(long, conflicts_with_all = ["map_disk", "map_share"])]
    external_requirements: bool,
    /// Map an external disk's configured order to an absolute destination host path.
    #[arg(long, value_name = "ORDER=PATH", value_parser = disk_mapping)]
    map_disk: Vec<libvm::ExternalResourceMapping>,
    /// Map an external share tag to an absolute destination host path. No host trees are copied.
    #[arg(long, value_name = "TAG=PATH", value_parser = share_mapping)]
    map_share: Vec<libvm::ExternalResourceMapping>,
}
impl ExternalResources {
    pub(crate) fn policy(self) -> eyre::Result<libvm::ExternalResourcePolicy> {
        if self.external_requirements {
            return Ok(libvm::ExternalResourcePolicy::RequireMappings);
        }
        let mappings: Vec<_> = self.map_disk.into_iter().chain(self.map_share).collect();
        if mappings.is_empty() {
            return Ok(libvm::ExternalResourcePolicy::Reject);
        }
        // Use the same strict management validation for local and daemon callers.
        let policy = libvm::ExternalResourcePolicy::Map { mappings };
        Ok(silo_vm_control::stopped::policy_from_wire(
            silo_vm_control::stopped::policy_to_wire(&policy),
        )?)
    }
}

fn mapping_parts(value: &str) -> Result<(&str, std::path::PathBuf), String> {
    let (key, path) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY=PATH".to_owned())?;
    let path = std::path::PathBuf::from(path);
    if key.is_empty() || !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err("expected a nonempty resource key and absolute destination path".into());
    }
    Ok((key, path))
}
fn disk_mapping(value: &str) -> Result<libvm::ExternalResourceMapping, String> {
    let (key, path) = mapping_parts(value)?;
    let order = key
        .parse()
        .map_err(|_| "disk order must be an unsigned 32-bit integer".to_owned())?;
    let resource =
        silo_vm_control::stopped::resource_key(libvm::ExternalResourceKey::Disk { order })
            .map_err(|error| error.to_string())?;
    Ok(libvm::ExternalResourceMapping { resource, path })
}
fn share_mapping(value: &str) -> Result<libvm::ExternalResourceMapping, String> {
    let (tag, path) = mapping_parts(value)?;
    let resource = silo_vm_control::stopped::resource_key(libvm::ExternalResourceKey::Share {
        tag: tag.into(),
    })
    .map_err(|error| error.to_string())?;
    Ok(libvm::ExternalResourceMapping { resource, path })
}

#[cfg(test)]
mod tests {
    use crate::app::Cli;
    use crate::commands::live::{live_fork_status, ForkMode};
    use crate::commands::Command;
    use clap::Parser;
    use vm_spec::lifecycle::CaptureResumePolicy;

    const OPERATION: &str = "00000000-0000-4000-8000-0000000000aa";

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["silo", "fork"].iter().chain(args).copied())
    }

    #[test]
    fn snapshot_and_fork_default_to_incremental_with_explicit_full_override() {
        use crate::commands::live::SnapshotCommand;
        use vm_spec::lifecycle::CapturePolicy;

        for (flags, expected) in [
            (vec![], CapturePolicy::Incremental),
            (
                vec!["--capture-policy", "incremental"],
                CapturePolicy::Incremental,
            ),
            (vec!["--capture-policy", "full"], CapturePolicy::Full),
        ] {
            let prefix = ["silo", "snapshot", "create", "vm", "--live"];
            let cli = Cli::try_parse_from(prefix.iter().chain(flags.iter()).copied()).unwrap();
            let Command::Snapshot(snapshot) = cli.command else {
                panic!("expected snapshot");
            };
            let SnapshotCommand::Create { capture, .. } = snapshot.command else {
                panic!("expected create");
            };
            assert_eq!(capture.policy(), expected);
            assert_eq!(capture.crossover(), 60);

            let mut args = vec!["vm", "--live", "--name", "child"];
            args.extend(flags);
            let (_, options) = live(&args);
            assert_eq!(options.policy, expected);
            assert_eq!(options.dirty_crossover_percent, 60);
        }
    }

    #[test]
    fn incremental_options_require_live_mode_and_bounded_crossover() {
        for command in ["snapshot", "fork"] {
            let prefix = if command == "snapshot" {
                vec!["silo", "snapshot", "create", "vm"]
            } else {
                vec!["silo", "fork", "vm", "--name", "child"]
            };
            for flags in [
                vec!["--capture-policy", "incremental"],
                vec!["--dirty-crossover-percent", "60"],
            ] {
                assert!(Cli::try_parse_from(prefix.iter().chain(flags.iter()).copied()).is_err());
            }
            for percent in ["0", "61", "256", "-1", "1.5"] {
                let flags = [
                    "--live",
                    "--capture-policy",
                    "incremental",
                    "--dirty-crossover-percent",
                    percent,
                ];
                assert!(Cli::try_parse_from(prefix.iter().chain(flags.iter()).copied()).is_err());
            }
        }
        let (_, options) = live(&[
            "vm",
            "--name",
            "child",
            "--live",
            "--capture-policy",
            "incremental",
            "--dirty-crossover-percent",
            "1",
        ]);
        assert_eq!(
            options.policy,
            vm_spec::lifecycle::CapturePolicy::Incremental
        );
        assert_eq!(options.dirty_crossover_percent, 1);
        options.validate().unwrap();
    }

    #[test]
    fn disk_recovery_never_accepts_execution_activation_options() {
        for option in ["--activation-hook", "--memory-overcommit", "--live"] {
            assert!(
                Cli::try_parse_from(["silo", "recover-disks", "image:checkpoint", option]).is_err()
            );
        }
        let cli = Cli::try_parse_from([
            "silo",
            "recover-disks",
            "image:checkpoint",
            "--name",
            "recovered",
        ])
        .unwrap();
        let Command::RecoverDisks(command) = cli.command else {
            panic!("disk recovery command");
        };
        assert_eq!(command.checkpoint, "image:checkpoint");
        assert_eq!(command.name.as_deref(), Some("recovered"));
    }

    fn fork_mode(args: &[&str]) -> eyre::Result<ForkMode> {
        let Command::Fork(command) = parse(args)?.command else {
            panic!("fork command")
        };
        command.mode()
    }

    fn live(args: &[&str]) -> (String, libvm::LiveForkOptions) {
        match fork_mode(args).unwrap() {
            ForkMode::Live { machine, options } => (machine, options),
            mode => panic!("expected live fork: {mode:?}"),
        }
    }

    #[test]
    fn fork_grammar_separates_stopped_live_and_operation_modes() {
        for args in [
            vec!["vm", "--name", "a"],
            vec!["vm", "--name", "a", "--live", "--name", "b"],
            vec!["vm", "--live", "--children-json", r#"[{"name":"a"}]"#],
            vec![
                "vm",
                "--live",
                "--name",
                "a",
                "--max-children",
                "32",
                "--preserve",
                "--operation-id",
                OPERATION,
            ],
            vec!["--operation", OPERATION],
            vec!["--operation", OPERATION, "--cancel"],
        ] {
            assert!(parse(&args).is_ok(), "{args:?}");
        }
        for args in [
            vec!["vm"],
            vec!["--live", "--name", "a"],
            vec!["vm", "--name", "a", "--max-children", "4"],
            vec!["vm", "--name", "a", "--preserve"],
            vec!["vm", "--name", "a", "--private-write-percent", "10"],
            vec!["vm", "--name", "a", "--memory-overcommit"],
            vec!["vm", "--name", "a", "--operation-id", OPERATION],
            vec!["vm", "--children-json", r#"[{"name":"a"}]"#],
            vec![
                "vm",
                "--live",
                "--name",
                "a",
                "--children-json",
                r#"[{"name":"b"}]"#,
            ],
            vec!["vm", "--live", "--name", "a", "--max-children", "0"],
            vec![
                "vm",
                "--live",
                "--name",
                "a",
                "--operation-id",
                "00000000-0000-0000-0000-000000000000",
            ],
            vec![
                "vm",
                "--live",
                "--name",
                "a",
                "--operation-id",
                "not-a-uuid",
            ],
            vec![
                "vm",
                "--live",
                "--name",
                "a",
                "--private-write-percent",
                "101",
            ],
            vec![
                "vm",
                "--live",
                "--children-json",
                r#"[{"name":"a","unknown":1}]"#,
            ],
            vec!["vm", "--live", "--children-json", r#"{"name":"a"}"#],
            vec!["--cancel"],
            vec!["vm", "--name", "a", "--cancel"],
            vec!["vm", "--operation", OPERATION],
            vec!["--operation", OPERATION, "--name", "a"],
            vec!["--operation", OPERATION, "--live"],
            vec!["--operation", OPERATION, "--preserve"],
            vec!["--operation", OPERATION, "--max-children", "2"],
            vec!["--operation", OPERATION, "--operation-id", OPERATION],
            vec!["--operation", OPERATION, "--external-requirements"],
            vec!["--operation", "00000000-0000-0000-0000-000000000000"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        let oversized = format!(r#"[{{"name":"{}"}}]"#, "a".repeat(1 << 20));
        assert!(parse(&["vm", "--live", "--children-json", oversized.as_str()]).is_err());
    }

    #[test]
    fn live_fork_names_become_explicit_children_and_sixteen_is_only_a_bound() {
        let (machine, options) = live(&["vm", "--live", "--name", "a", "--name", "b"]);
        assert_eq!(machine, "vm");
        assert_eq!(
            options
                .children
                .iter()
                .map(|child| child.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        for child in &options.children {
            assert_eq!(child.activation_hook, None);
            assert_eq!(child.destination, libvm::ForkDestination::default());
        }
        assert_eq!(options.max_children, libvm::DEFAULT_LIVE_FORK_MAX_CHILDREN);
        assert_eq!(options.max_children.get(), 16);
        assert_eq!(options.resume_policy, CaptureResumePolicy::ResumeIfAcquired);
        assert!(!options.operation_id.is_nil());
        let (_, single) = live(&["vm", "--live", "--name", "a"]);
        assert_eq!(single.children.len(), 1);
        assert_ne!(
            single.operation_id, options.operation_id,
            "each creation selects a fresh operation ID"
        );

        let (_, explicit) = live(&[
            "vm",
            "--live",
            "--name",
            "a",
            "--max-children",
            "32",
            "--preserve",
            "--operation-id",
            "00000000-0000-4000-8000-0000000000AA",
        ]);
        assert_eq!(explicit.operation_id.to_string(), OPERATION);
        assert_eq!(explicit.max_children.get(), 32);
        assert_eq!(explicit.resume_policy, CaptureResumePolicy::Preserve);
        let wire = silo_vm_control::fork::request_to_wire(
            &libvm::MachineRef::parse("vm").unwrap(),
            &explicit,
        )
        .unwrap();
        assert_eq!(
            silo_vm_control::fork::request_from_wire(wire).unwrap().1,
            explicit
        );
    }

    #[test]
    fn live_fork_refuses_invalid_child_sets_before_any_runtime_access() {
        let names = |count: usize| {
            (0..count)
                .flat_map(|index| ["--name".to_owned(), format!("child-{index}")])
                .collect::<Vec<_>>()
        };
        let args = |count: usize, extra: &[&str]| {
            let names = names(count);
            let mut args = vec!["vm".to_owned(), "--live".to_owned()];
            args.extend(names);
            args.extend(extra.iter().map(|value| (*value).to_owned()));
            args
        };
        let run = |args: Vec<String>| {
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            fork_mode(&args)
        };
        assert!(run(args(16, &[])).is_ok());
        assert!(
            run(args(17, &[])).is_err(),
            "17 children need an explicit maximum"
        );
        assert!(run(args(17, &["--max-children", "17"])).is_ok());
        assert!(run(args(3, &["--max-children", "2"])).is_err());
        assert!(fork_mode(&["vm", "--live", "--name", "a", "--name", "a"]).is_err());
        assert!(fork_mode(&["vm", "--live", "--name", "../escape"]).is_err());
        assert!(fork_mode(&["vm", "--live", "--children-json", "[]"]).is_err());
        assert!(fork_mode(&[
            "vm",
            "--live",
            "--children-json",
            r#"[{"name":"a","activationHook":{"argv":[],"environment":[],"workingDirectory":"/","timeoutMs":1000}}]"#,
        ])
        .is_err());
        assert!(
            fork_mode(&["vm", "--name", "a", "--name", "b"]).is_err(),
            "a stopped fork takes exactly one child"
        );
        assert!(matches!(
            fork_mode(&["vm", "--name", "a"]).unwrap(),
            ForkMode::Stopped { .. }
        ));
        let operation: uuid::Uuid = OPERATION.parse().unwrap();
        assert!(matches!(
            fork_mode(&["--operation", OPERATION]).unwrap(),
            ForkMode::Inspect(id) if id == operation
        ));
        assert!(matches!(
            fork_mode(&["--operation", OPERATION, "--cancel"]).unwrap(),
            ForkMode::Cancel(id) if id == operation
        ));
    }

    #[test]
    fn children_json_carries_hooks_and_only_explicit_destination_grants() {
        let (_, options) = live(&[
            "vm",
            "--live",
            "--children-json",
            r#"[
                {"name":"web","activationHook":{"argv":["/bin/true"],"environment":[],"workingDirectory":"/","timeoutMs":30000},
                 "destination":{"forwards":[{"listen":"host:tcp:127.0.0.1:8080","connect":"guest:tcp:80"}],"guestPublish":{"bind":"loopback"}}},
                {"name":"worker"}
            ]"#,
        ]);
        let [web, worker] = options.children.as_slice() else {
            panic!("two children")
        };
        assert_eq!(web.name, "web");
        assert_eq!(
            web.activation_hook.as_ref().unwrap().argv,
            vec!["/bin/true".to_owned()]
        );
        assert_eq!(web.destination.forwards.len(), 1);
        assert_eq!(
            web.destination.guest_publish,
            Some(libvm::GuestPublish {
                bind: libvm::PublishBind::Loopback
            })
        );
        assert_eq!(worker.name, "worker");
        assert_eq!(worker.activation_hook, None);
        assert_eq!(worker.destination, libvm::ForkDestination::default());
    }

    fn result(
        source: libvm::ForkSourceOutcome,
        outcomes: [libvm::ForkChildOutcome; 2],
    ) -> libvm::LiveForkResult {
        libvm::LiveForkResult {
            operation_id: OPERATION.parse().unwrap(),
            source_machine_id: "000000000000400080000000000000dd".parse().unwrap(),
            source_run_id: "00000000-0000-4000-8000-0000000000cc".parse().unwrap(),
            capture_id: vm_spec::lifecycle::LiveId::parse("00000000-0000-4000-8000-0000000000bb")
                .unwrap(),
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            stage: libvm::ForkStage::Finished,
            cancellation_requested: false,
            capture: libvm::ForkCaptureOutcome::Sealed {
                cut_id: format!("sha256:{}", "e".repeat(64)).parse().unwrap(),
            },
            source,
            children: outcomes
                .into_iter()
                .enumerate()
                .map(|(index, outcome)| libvm::ForkChildResult {
                    index: u32::try_from(index).unwrap(),
                    name: format!("child-{index}"),
                    machine_id: format!("00000000000040008000000000001{index:03}")
                        .parse()
                        .unwrap(),
                    run_id: format!("00000000-0000-4000-8000-000000002{index:03}")
                        .parse()
                        .unwrap(),
                    outcome,
                    durability: Some(libvm::MachineDurability::Constructed),
                })
                .collect(),
        }
    }

    #[test]
    fn live_fork_status_succeeds_only_for_complete_requested_outcomes() {
        use libvm::{ForkChildOutcome as Child, ForkSourceOutcome as Source};
        let running = || [Child::Running, Child::Running];
        let ok = result(Source::Resumed, running());
        assert_eq!(
            serde_json::to_value(&ok).unwrap()["children"][0]["durability"],
            "constructed"
        );
        silo_vm_control::fork::validate_result(&ok).unwrap();
        live_fork_status(&ok).unwrap();
        let mut preserved = result(Source::Preserved, running());
        preserved.resume_policy = CaptureResumePolicy::Preserve;
        live_fork_status(&preserved).unwrap();

        let diagnostic = || vm_spec::lifecycle::Diagnostic::new("failed");
        let mut failures = vec![
            (
                result(Source::Preserved, running()),
                CaptureResumePolicy::ResumeIfAcquired,
            ),
            (
                result(Source::Resumed, running()),
                CaptureResumePolicy::Preserve,
            ),
            (
                result(
                    Source::ResumeFailed {
                        diagnostic: diagnostic(),
                    },
                    running(),
                ),
                CaptureResumePolicy::ResumeIfAcquired,
            ),
            (
                result(
                    Source::Resumed,
                    [
                        Child::Running,
                        Child::Failed {
                            phase: libvm::ForkFailurePhase::Activation,
                            diagnostic: diagnostic(),
                        },
                    ],
                ),
                CaptureResumePolicy::ResumeIfAcquired,
            ),
            (
                result(
                    Source::Resumed,
                    [
                        Child::Running,
                        Child::RecoveryPending {
                            diagnostic: diagnostic(),
                        },
                    ],
                ),
                CaptureResumePolicy::ResumeIfAcquired,
            ),
        ];
        let mut settling = result(Source::Resumed, [Child::Running, Child::Activating]);
        settling.stage = libvm::ForkStage::Settling;
        failures.push((settling, CaptureResumePolicy::ResumeIfAcquired));
        let mut cancelled = result(Source::Resumed, running());
        cancelled.cancellation_requested = true;
        failures.push((cancelled, CaptureResumePolicy::ResumeIfAcquired));
        for (mut result, policy) in failures {
            result.resume_policy = policy;
            silo_vm_control::fork::validate_result(&result).unwrap();
            let error = live_fork_status(&result).unwrap_err().to_string();
            assert!(error.contains(OPERATION), "{error}");
            assert!(error.contains("running children are retained"), "{error}");
        }
    }

    #[test]
    fn paused_live_fork_succeeds_with_resolved_policy_not_requested_default() {
        let (_, requested) = live(&["vm", "--live", "--name", "child"]);
        assert_eq!(
            requested.resume_policy,
            CaptureResumePolicy::ResumeIfAcquired
        );
        let mut completed = result(
            libvm::ForkSourceOutcome::Preserved,
            [
                libvm::ForkChildOutcome::Running,
                libvm::ForkChildOutcome::Running,
            ],
        );
        completed.resume_policy = CaptureResumePolicy::Preserve;
        let wire = silo_vm_control::fork::result_to_wire(&completed).unwrap();
        let observed = silo_vm_control::fork::result_from_wire(wire).unwrap();
        live_fork_status(&observed).unwrap();
    }

    #[test]
    fn fork_confirmation_distinguishes_rejection_acceptance_and_lost_observation() {
        use crate::commands::live::fork_confirmation_note;
        let operation = OPERATION.parse().unwrap();
        let absent = libvm::LibVmError::LiveForkNotFound {
            operation_id: OPERATION.into(),
        };
        let status = silo_vm_control::errors::native_error_to_status(&absent);
        let daemon_absent = silo_vm_control::errors::status_to_native_error(&status).unwrap();
        let rejected: eyre::Report = libvm::LibVmError::LiveProtocol {
            message: "capture admission refused".into(),
        }
        .into();
        for error in [absent, daemon_absent] {
            assert!(fork_confirmation_note(&rejected, operation, &Err(error.into())).is_none());
        }
        let accepted = result(
            libvm::ForkSourceOutcome::Resumed,
            [
                libvm::ForkChildOutcome::Running,
                libvm::ForkChildOutcome::Running,
            ],
        );
        let note = fork_confirmation_note(&rejected, operation, &Ok(accepted)).unwrap();
        assert!(note.contains("was accepted"), "{note}");
        assert!(!note.contains("was not confirmed"), "{note}");
        let lost = eyre::eyre!("connection lost");
        let note =
            fork_confirmation_note(&lost, operation, &Err(eyre::eyre!("connection lost"))).unwrap();
        assert!(note.contains("was not confirmed"), "{note}");
        let absent = Err(libvm::LibVmError::LiveForkNotFound {
            operation_id: OPERATION.into(),
        }
        .into());
        let note = fork_confirmation_note(&lost, operation, &absent).unwrap();
        assert!(note.contains("was not confirmed"), "{note}");
        let rejected = tonic::Status::failed_precondition("live operation unavailable").into();
        assert!(fork_confirmation_note(&rejected, operation, &absent).is_none());
        let mut stopping = tonic::Status::unavailable("daemon is stopping");
        stopping.metadata_mut().insert(
            "x-silo-mutation-rejected",
            tonic::metadata::MetadataValue::from_static("true"),
        );
        let rejected = stopping.into();
        assert!(
            fork_confirmation_note(&rejected, operation, &Err(eyre::eyre!("offline"))).is_none()
        );
        let lost = tonic::Status::unavailable("connection lost").into();
        assert!(fork_confirmation_note(&lost, operation, &absent).is_some());
    }

    #[test]
    fn restore_and_fork_reject_removed_ram_policy_flags() {
        assert!(Cli::try_parse_from(["silo", "restore", "checkpoint"]).is_ok());
        for flags in [
            vec!["--memory-overcommit"],
            vec!["--private-write-percent", "25"],
        ] {
            let mut restore = vec!["silo", "restore", "checkpoint"];
            restore.extend_from_slice(&flags);
            assert!(Cli::try_parse_from(restore).is_err());
            let mut fork = vec!["silo", "fork", "vm", "--live", "--name", "child"];
            fork.extend_from_slice(&flags);
            assert!(Cli::try_parse_from(fork).is_err());
        }
    }
}

use crate::context::Context;
use crate::ui::{self, OutputFormat, Spinner, Table};
use clap::{Args, Subcommand};
use std::time::{Duration, Instant};

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
    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
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
    /// Reread and authenticate every RAM, state and disk byte of a local snapshot, ignoring trust receipts.
    ///
    /// This can take as long as reading the whole snapshot.
    Verify {
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
        let progress_format = if matches!(
            &self.command,
            SnapshotCommand::Create { .. } | SnapshotCommand::Verify { .. }
        ) {
            self.format
        } else {
            OutputFormat::Json
        };
        let mut feedback = OperationFeedback::new(progress_format, "Admitting", "snapshot");
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
                feedback.step(
                    "Capturing",
                    format!("{machine} (memory, disks and publication)"),
                );
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
                let elapsed = feedback.finish();
                match self.format {
                    OutputFormat::Json => ui::print_json(&snapshot)?,
                    OutputFormat::Plain => {
                        ui::success(snapshot_result_line(&snapshot.snapshot, elapsed));
                        let source = match snapshot.capture.source_outcome {
                            libvm::LiveCaptureSource::Resumed => "resumed",
                            libvm::LiveCaptureSource::Preserved => "left paused",
                            libvm::LiveCaptureSource::ResumeFailed => "RESUME FAILED",
                            libvm::LiveCaptureSource::Unknown => "UNKNOWN",
                        };
                        let source_name = machine_display_name(api, &machine).await;
                        ui::secondary(format!("Source {source_name} {source}"));
                        if let Some(error) = &snapshot.capture.source_error {
                            ui::warn(error.as_str());
                        }
                    }
                }
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
                feedback.step("Capturing", format!("{machine} (disks and publication)"));
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
                let elapsed = feedback.finish();
                match self.format {
                    OutputFormat::Json => ui::print_json(&info)?,
                    OutputFormat::Plain => ui::success(snapshot_result_line(&info, elapsed)),
                }
                Ok(())
            }
            SnapshotCommand::Inspect { reference } => {
                feedback.finish();
                let snapshot = api.inspect_snapshot(&reference).await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&snapshot),
                    OutputFormat::Plain => ui::print_detail_rows(&snapshot_detail_rows(&snapshot)),
                }
            }
            SnapshotCommand::Verify { reference } => {
                let name = reference.strip_prefix("image:").unwrap_or(&reference);
                feedback.step("Verifying", name);
                let result = api.verify_snapshot(&reference).await;
                let elapsed = feedback.finish();
                match result {
                    Ok(report) => match self.format {
                        OutputFormat::Json => ui::print_json(&report),
                        OutputFormat::Plain => {
                            ui::success(verification_result_line(&report, name, elapsed));
                            Ok(())
                        }
                    },
                    Err(error) => {
                        if let Some(libvm::LibVmError::SnapshotVerification(failure)) =
                            error.downcast_ref::<libvm::LibVmError>()
                        {
                            if matches!(self.format, OutputFormat::Json) {
                                ui::print_json(&verification_error_json(failure))?;
                            }
                            return Err(eyre::eyre!("{}", verification_error_message(failure)));
                        }
                        Err(error)
                    }
                }
            }
            SnapshotCommand::List => {
                feedback.finish();
                let snapshots = api.list_snapshots().await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&snapshots),
                    OutputFormat::Plain => snapshot_table(&snapshots, ui::now_unix()).print(),
                }
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
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
        let format = self.format;
        let progress_format = if self.operation.is_some() {
            OutputFormat::Json
        } else {
            format
        };
        let mut feedback = OperationFeedback::new(progress_format, "Admitting", "fork");
        let mode = self.mode()?;
        let api = context.app_api().await?;
        match mode {
            ForkMode::Stopped { machine, options } => {
                let source = machine.clone();
                feedback.step("Forking", format!("{source} (disks and publication)"));
                let machine = api.fork_stopped(&machine, options).await?;
                print_machine_result(&machine, "Forked", feedback.finish(), format)?;
                if format == OutputFormat::Plain {
                    let source_name = machine_display_name(api, &source).await;
                    ui::secondary(format!("Source {source_name} unchanged (stopped)"));
                }
                Ok(())
            }
            ForkMode::Live { machine, options } => {
                let operation_id = options.operation_id;
                feedback.step(
                    "Forking",
                    format!("{machine} (capture and child activation)"),
                );
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
                let readiness = wait_fork_children(api, &result, &mut feedback).await;
                let elapsed = feedback.finish();
                print_fork_result(api, &result, elapsed, &readiness, format, false).await?;
                live_fork_status(&result).and_then(|()| readiness_status(&readiness))
            }
            ForkMode::Inspect(operation_id) => {
                let result = api.inspect_fork(operation_id).await?;
                print_fork_result(api, &result, feedback.finish(), &[], format, true).await?;
                Ok(())
            }
            ForkMode::Cancel(operation_id) => {
                let result = api.cancel_fork(operation_id).await?;
                print_fork_result(api, &result, feedback.finish(), &[], format, true).await?;
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
    let source_satisfied = fork_source_satisfied(result);
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
        "live fork {} did not fully succeed: {running} of {} children running, source continuation {}, operation {}; the result is authoritative and running children are retained",
        result.operation_id,
        result.children.len(),
        if source_satisfied { "as requested" } else { "not as requested" },
        if result.stage == libvm::ForkStage::Finished { "finished" } else { "still in progress" },
    )
}

fn fork_source_satisfied(result: &libvm::LiveForkResult) -> bool {
    match result.resume_policy {
        vm_spec::lifecycle::CaptureResumePolicy::ResumeIfAcquired => {
            matches!(result.source, libvm::ForkSourceOutcome::Resumed)
        }
        vm_spec::lifecycle::CaptureResumePolicy::Preserve => {
            matches!(result.source, libvm::ForkSourceOutcome::Preserved)
        }
    }
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
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}
impl Restore {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        let mut feedback = OperationFeedback::new(self.format, "Admitting", &self.checkpoint);
        let api = context.app_api().await?;
        let options = libvm::RestoreOptions {
            name: self.name,
            external_resources: self.external.policy()?,
            activation_hook: self.activation_hook,
        };
        feedback.step(
            "Restoring",
            format!("{} (disks and activation)", self.checkpoint),
        );
        let machine = api.restore_snapshot(&self.checkpoint, options).await?;
        let readiness = if machine.status.is_running() {
            feedback.step("Waiting for agent", &machine.name);
            wait_machine_ready(api, &machine.id).await
        } else {
            Ok(())
        };
        let elapsed = feedback.finish();
        match (&readiness, self.format) {
            (Err(error), OutputFormat::Plain) => eprintln!(
                "   ✗ {}: waiting for agent: {error}",
                ui::result_message(
                    "Failed",
                    &machine.name,
                    abbreviated_id(&machine.id),
                    elapsed
                ),
            ),
            _ => print_machine_result(&machine, "Restored", elapsed, self.format)?,
        }
        readiness
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
    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
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
                print_details(
                    &context.app_api().await?.acquire_artifact(request).await?,
                    self.format,
                )
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
                print_details(&api.publish_artifact(request).await?, self.format)
            }
            ImageCommand::InspectRemote { reference } => print_artifact_inspection(
                &context
                    .app_api()
                    .await?
                    .inspect_artifact(&reference)
                    .await?,
                self.format,
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
                let watcher = (self.format == OutputFormat::Plain)
                    .then(|| crate::ui::watch_image_progress("image import", events));
                let result = context
                    .app_api()
                    .await?
                    .import_image(request, progress)
                    .await;
                if let Some(watcher) = watcher {
                    let _ = watcher.await;
                }
                print_details(&result?, self.format)
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
                let watcher = (self.format == OutputFormat::Plain)
                    .then(|| crate::ui::watch_image_progress(&reference, events));
                let result = context
                    .app_api()
                    .await?
                    .convert_image(reference, pull, platform, options, progress)
                    .await;
                if let Some(watcher) = watcher {
                    let _ = watcher.await;
                }
                print_details(&result?, self.format)
            }
            ImageCommand::Inspect { reference } => print_managed_inspection(
                &context.app_api().await?.inspect_managed(&reference).await?,
                self.format,
            ),
            ImageCommand::List => {
                let sources = context.app_api().await?.list_managed().await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&sources),
                    OutputFormat::Plain => image_table(&sources).print(),
                }
            }
            ImageCommand::Release { reference } => {
                context.app_api().await?.release_image(&reference).await
            }
            ImageCommand::Remove { alias } => {
                context.app_api().await?.remove_image_alias(&alias).await
            }
        }
    }
}

fn print_details(value: &impl serde::Serialize, format: OutputFormat) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(value),
        OutputFormat::Plain => ui::print_serialized_details(value),
    }
}

fn snapshot_detail_rows(info: &libvm::SnapshotInfo) -> Vec<(String, String)> {
    let mut rows = vec![
        ("ID".into(), info.id.to_string()),
        ("Aliases".into(), aliases(&info.aliases)),
        ("Kind".into(), format!("{} snapshot", snapshot_kind(info))),
        ("Created".into(), ui::format_unix(info.created_at)),
        ("Record digest".into(), info.record_digest.to_string()),
        ("Retained".into(), ui::yes_no(info.retained).into()),
    ];
    for (index, source) in info.provenance.iter().enumerate() {
        let suffix = if index == 0 {
            String::new()
        } else {
            format!(" ({})", index + 1)
        };
        rows.extend([
            (
                format!("Source machine{suffix}"),
                source.machine_id.to_string(),
            ),
            (format!("Source run{suffix}"), source.run_id.to_string()),
            (format!("Capture{suffix}"), source.capture_id.to_string()),
            (
                format!("Evidence digest{suffix}"),
                source.evidence_digest.to_string(),
            ),
        ]);
    }
    rows
}

fn append_nested_details(
    rows: &mut Vec<(String, String)>,
    group: &str,
    value: &impl serde::Serialize,
) -> eyre::Result<()> {
    rows.extend(
        ui::serialized_detail_rows(value)?
            .into_iter()
            .map(|(label, value)| (format!("{group}.{label}"), value)),
    );
    Ok(())
}

fn architecture_label(architecture: libvm::GuestArchitecture) -> &'static str {
    match architecture {
        libvm::GuestArchitecture::Amd64 => "amd64",
        libvm::GuestArchitecture::Arm64 => "arm64",
    }
}

fn append_boot_details(
    rows: &mut Vec<(String, String)>,
    boot: &libvm::BootProfile,
) -> eyre::Result<()> {
    let libvm::BootProfile::LinuxDirect {
        userspace_platform,
        kernel_architecture,
        command_line_policy,
        binding,
        root_selector,
        root_filesystem,
        translation,
    } = boot
    else {
        return append_nested_details(rows, "Boot details", boot);
    };
    let mut platform = format!(
        "linux/{}",
        architecture_label(userspace_platform.architecture)
    );
    if let Some(variant) = &userspace_platform.variant {
        platform.push('/');
        platform.push_str(variant);
    }
    rows.extend([
        ("Platform".into(), platform),
        (
            "Kernel architecture".into(),
            architecture_label(*kernel_architecture).into(),
        ),
        (
            "Command line policy".into(),
            match command_line_policy {
                libvm::DirectCommandLinePolicy::SiloDirectV1 => "Silo direct v1",
            }
            .into(),
        ),
        (
            "Root selector".into(),
            match root_selector {
                libvm::RootSelector::ManagedOverlay => "managed overlay".into(),
                libvm::RootSelector::WholeDisk => "whole disk".into(),
                libvm::RootSelector::GptPartition { guid } => format!("GPT partition {guid}"),
                libvm::RootSelector::MbrPartition { number } => format!("MBR partition {number}"),
            },
        ),
        (
            "Root filesystem".into(),
            match root_filesystem {
                libvm::RootFilesystem::Ext4 => "ext4",
            }
            .into(),
        ),
        (
            "Translation".into(),
            match translation {
                libvm::Translation::None => "none",
                libvm::Translation::Rosetta => "Rosetta",
            }
            .into(),
        ),
    ]);
    match binding {
        libvm::BootBinding::RuntimeSelected => {
            rows.push(("Boot assets".into(), "runtime selected".into()))
        }
        libvm::BootBinding::Pinned {
            kernel,
            base_initramfs,
            agent,
            architecture,
            abi,
        } => {
            rows.extend([
                ("Boot assets".into(), "pinned".into()),
                ("Kernel".into(), kernel.to_string()),
                ("Base initramfs".into(), base_initramfs.to_string()),
                (
                    "Agent".into(),
                    agent
                        .map(|digest| digest.to_string())
                        .unwrap_or_else(|| "-".into()),
                ),
                (
                    "Boot architecture".into(),
                    architecture_label(*architecture).into(),
                ),
                ("Boot ABI".into(), abi.clone()),
            ]);
        }
    }
    Ok(())
}

fn managed_detail_rows(source: &libvm::ManagedSourceInfo) -> eyre::Result<Vec<(String, String)>> {
    match source {
        libvm::ManagedSourceInfo::Snapshot(info) => Ok(snapshot_detail_rows(info)),
        libvm::ManagedSourceInfo::Image(info) => {
            let mut rows = vec![
                ("ID".into(), info.id.to_string()),
                ("Aliases".into(), aliases(&info.aliases)),
                ("Kind".into(), "image".into()),
                (
                    "Size".into(),
                    ui::human_bytes(Some(info.record.root.stream.length)),
                ),
                ("Record digest".into(), info.record_digest.to_string()),
                ("Retained".into(), ui::yes_no(info.retained).into()),
                (
                    "Root stream".into(),
                    info.record.root.stream.stream.to_string(),
                ),
                ("Root map".into(), info.record.root.stream.map.to_string()),
                (
                    "Sector size".into(),
                    ui::human_bytes(Some(u64::from(
                        info.record.root.geometry.logical_sector_size,
                    ))),
                ),
                (
                    "Root layout".into(),
                    match info.record.root.layout {
                        libvm::RawLayout::WholeDisk => "whole disk",
                        libvm::RawLayout::Partitioned {
                            table: libvm::PartitionTable::Gpt,
                        } => "GPT",
                        libvm::RawLayout::Partitioned {
                            table: libvm::PartitionTable::Mbr,
                        } => "MBR",
                    }
                    .into(),
                ),
                (
                    "Boot".into(),
                    match &info.record.boot {
                        libvm::BootProfile::LinuxDirect { .. } => "Linux direct",
                        libvm::BootProfile::LinuxEfi { .. } => "Linux EFI",
                        libvm::BootProfile::MacOs { .. } => "macOS",
                    }
                    .into(),
                ),
            ];
            let storage = serde_json::to_value(&info.record.root.profile)?;
            let storage_kind = storage
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| eyre::eyre!("image storage profile is missing its kind"))?;
            rows.push(("Storage".into(), storage_kind.replace('-', " ")));
            if storage.as_object().is_some_and(|fields| fields.len() > 1) {
                append_nested_details(&mut rows, "Storage details", &info.record.root.profile)?;
            }
            append_boot_details(&mut rows, &info.record.boot)?;
            let process = &info.record.process;
            rows.extend([
                (
                    "Entrypoint".into(),
                    process
                        .entrypoint
                        .as_ref()
                        .map(|argv| format!("{argv:?}"))
                        .unwrap_or_else(|| "-".into()),
                ),
                (
                    "Command".into(),
                    process
                        .command
                        .as_ref()
                        .map(|argv| format!("{argv:?}"))
                        .unwrap_or_else(|| "-".into()),
                ),
                (
                    "Working directory".into(),
                    process.working_directory.clone(),
                ),
                (
                    "User".into(),
                    process.user.clone().unwrap_or_else(|| "-".into()),
                ),
            ]);
            for (key, value) in &process.environment {
                rows.push((format!("Environment {key}"), value.clone()));
            }
            for (index, provenance) in info.provenance.iter().enumerate() {
                let group = format!("Source {}", index + 1);
                rows.extend([
                    (group.clone(), provenance.source_spelling.clone()),
                    (
                        format!("{group} container"),
                        match provenance.container {
                            libvm::ImageContainerKind::Raw => "raw",
                            libvm::ImageContainerKind::Qcow2 => "qcow2",
                            libvm::ImageContainerKind::Oci => "OCI",
                        }
                        .into(),
                    ),
                    (
                        format!("{group} digest"),
                        provenance.source_digest.to_string(),
                    ),
                ]);
                if let Some(manifest) = provenance.source_manifest {
                    rows.push((format!("{group} manifest"), manifest.to_string()));
                }
                if let Some(config) = provenance.source_config {
                    rows.push((format!("{group} config"), config.to_string()));
                }
                if let Some(disk) = &provenance.disk {
                    rows.extend([
                        (
                            format!("{group} size"),
                            ui::human_bytes(Some(disk.source_length)),
                        ),
                        (
                            format!("{group} decoded size"),
                            ui::human_bytes(Some(disk.decoded_length)),
                        ),
                    ]);
                    if let Some(root) = &disk.selected_root {
                        append_nested_details(&mut rows, &format!("{group} root details"), root)?;
                    }
                }
            }
            Ok(rows)
        }
    }
}

fn print_managed_inspection(
    source: &libvm::ManagedSourceInfo,
    format: OutputFormat,
) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(source),
        OutputFormat::Plain => ui::print_detail_rows(&managed_detail_rows(source)?),
    }
}

fn artifact_detail_rows(info: &libvm::ArtifactInspection) -> Vec<(String, String)> {
    let (id, kind) = match info.content {
        libvm::ManagedSourceId::Image(id) => (id.to_string(), "image"),
        libvm::ManagedSourceId::Snapshot(id) => (
            id.to_string(),
            match info.capture_kind {
                Some(libvm::SnapshotCaptureKindName::LiveExecution) => "live snapshot",
                Some(libvm::SnapshotCaptureKindName::StoppedStorage) => "stopped snapshot",
                None => "snapshot",
            },
        ),
    };
    vec![
        ("ID".into(), id),
        ("Kind".into(), kind.into()),
        ("Repository".into(), info.repository.clone()),
        ("Index digest".into(), info.index_digest.to_string()),
        (
            "Purpose".into(),
            match info.purpose {
                libvm::ArtifactPurpose::Image => "image",
                libvm::ArtifactPurpose::Checkpoint => "checkpoint",
            }
            .into(),
        ),
        (
            "Root".into(),
            match info.root_family {
                libvm::ArtifactRootFamily::OpaqueRaw => "opaque raw",
                libvm::ArtifactRootFamily::LinuxOverlay => "Linux overlay",
            }
            .into(),
        ),
        (
            "Backend".into(),
            match info.backend {
                libvm::BackendRequirement::RawBlock => "raw block",
                libvm::BackendRequirement::KrunOverlay => "krun overlay",
            }
            .into(),
        ),
        (
            "Guest architecture".into(),
            match info.guest_architecture {
                libvm::GuestArchitecture::Amd64 => "amd64",
                libvm::GuestArchitecture::Arm64 => "arm64",
            }
            .into(),
        ),
        ("Live restore".into(), ui::yes_no(info.live_restore).into()),
    ]
}

fn print_artifact_inspection(
    info: &libvm::ArtifactInspection,
    format: OutputFormat,
) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(info),
        OutputFormat::Plain => ui::print_detail_rows(&artifact_detail_rows(info)),
    }
}

struct OperationFeedback {
    spinner: Spinner,
    started: Instant,
}

impl OperationFeedback {
    fn new(format: OutputFormat, label: &str, target: impl Into<String>) -> Self {
        Self {
            started: Instant::now(),
            spinner: match format {
                OutputFormat::Plain => Spinner::start(label, target),
                OutputFormat::Json => Spinner::quiet(),
            },
        }
    }

    fn step(&mut self, label: &str, target: impl Into<String>) {
        self.spinner.step(label, target);
    }

    fn finish(self) -> Duration {
        self.spinner.finish_clear();
        self.started.elapsed()
    }
}

fn abbreviated_id(id: &str) -> &str {
    ui::short_id(id.strip_prefix("sha256:").unwrap_or(id))
}

fn aliases(aliases: &[String]) -> String {
    if aliases.is_empty() {
        "-".into()
    } else {
        aliases.join(", ")
    }
}

fn snapshot_kind(info: &libvm::SnapshotInfo) -> &'static str {
    match info.capture_kind {
        libvm::SnapshotCaptureKindName::LiveExecution => "live",
        libvm::SnapshotCaptureKindName::StoppedStorage => "stopped",
    }
}

fn snapshot_result_line(info: &libvm::SnapshotInfo, elapsed: Duration) -> String {
    let name = if info.aliases.is_empty() {
        "(unnamed)".into()
    } else {
        aliases(&info.aliases)
    };
    ui::result_message(
        "Created",
        &name,
        abbreviated_id(&info.id.to_string()),
        elapsed,
    )
}

fn verification_result_line(
    report: &libvm::SnapshotVerificationReport,
    name: &str,
    elapsed: Duration,
) -> String {
    format!(
        "{:<12} {name} [{}] {} streams, {} {}",
        "Verified",
        abbreviated_id(&report.snapshot.to_string()),
        report.streams,
        ui::human_bytes(Some(report.bytes)),
        ui::format_duration(elapsed),
    )
}

const VERIFICATION_GUIDANCE: &str =
    "This snapshot should not be restored; restore from another snapshot or re-create it.";

fn verification_role(role: &libvm::SnapshotVerificationRole) -> String {
    use libvm::SnapshotVerificationRole;
    match role {
        SnapshotVerificationRole::Ram => "RAM".into(),
        SnapshotVerificationRole::Layout => "memory layout state".into(),
        SnapshotVerificationRole::Execution => "execution state".into(),
        SnapshotVerificationRole::Devices => "device state".into(),
        SnapshotVerificationRole::RootDisk => "root disk".into(),
        SnapshotVerificationRole::DataDisk { order } => format!("data disk {order}"),
        SnapshotVerificationRole::Dependency => "dependency".into(),
    }
}

fn verification_chunk(chunk: &libvm::storage::stream::Chunk) -> String {
    match chunk {
        libvm::storage::stream::Chunk::Zero => "zero".into(),
        libvm::storage::stream::Chunk::Data(digest) => digest.to_string(),
    }
}

fn verification_error_message(error: &libvm::SnapshotVerificationError) -> String {
    use libvm::{SnapshotVerificationError, SnapshotVerificationMember};
    let message = match error {
        SnapshotVerificationError::Structural {
            role,
            member,
            failure,
        } => {
            let member = match member {
                SnapshotVerificationMember::Stream(id) => format!("stream {id}"),
                SnapshotVerificationMember::Object(id) => format!("object {id}"),
            };
            format!("{} {member}: {failure}", verification_role(role))
        }
        SnapshotVerificationError::ChunkMismatch {
            role,
            stream,
            index,
            start,
            end,
            expected,
            actual,
        } => format!(
            "{} stream {stream} chunk {index} bytes {start}..{end}: expected {}, actual {}",
            verification_role(role),
            verification_chunk(expected),
            verification_chunk(actual),
        ),
        SnapshotVerificationError::ObjectMismatch {
            role,
            object,
            length,
            actual,
        } => format!(
            "{} object {object} ({length} bytes): expected {object}, actual {actual}",
            verification_role(role),
        ),
    };
    format!("{message}\n{VERIFICATION_GUIDANCE}")
}

fn verification_error_json(error: &libvm::SnapshotVerificationError) -> serde_json::Value {
    use libvm::{SnapshotStructuralFailure, SnapshotVerificationError, SnapshotVerificationMember};
    use serde_json::json;
    let error = match error {
        SnapshotVerificationError::Structural {
            role,
            member,
            failure,
        } => {
            let (member_type, member) = match member {
                SnapshotVerificationMember::Stream(id) => ("stream", id.to_string()),
                SnapshotVerificationMember::Object(id) => ("object", id.to_string()),
            };
            let failure = match failure {
                SnapshotStructuralFailure::Missing => json!({ "kind": "missing" }),
                SnapshotStructuralFailure::Truncated { expected, actual } => {
                    json!({ "kind": "truncated", "expected": expected, "actual": actual })
                }
                SnapshotStructuralFailure::Length { expected, actual } => {
                    json!({ "kind": "length", "expected": expected, "actual": actual })
                }
                SnapshotStructuralFailure::Writable { mode } => {
                    json!({ "kind": "writable", "mode": mode })
                }
                SnapshotStructuralFailure::Replaced => json!({ "kind": "replaced" }),
                SnapshotStructuralFailure::Invalid { message } => {
                    json!({ "kind": "invalid", "message": message })
                }
            };
            json!({
                "kind": "structural", "role": verification_role(role),
                "memberType": member_type, "member": member, "failure": failure,
            })
        }
        SnapshotVerificationError::ChunkMismatch {
            role,
            stream,
            index,
            start,
            end,
            expected,
            actual,
        } => json!({
            "kind": "chunkMismatch", "role": verification_role(role),
            "stream": stream, "index": index, "start": start, "end": end,
            "expected": verification_chunk(expected), "actual": verification_chunk(actual),
        }),
        SnapshotVerificationError::ObjectMismatch {
            role,
            object,
            length,
            actual,
        } => json!({
            "kind": "objectMismatch", "role": verification_role(role),
            "object": object, "length": length, "expected": object, "actual": actual,
        }),
    };
    json!({ "error": error, "guidance": VERIFICATION_GUIDANCE })
}

fn snapshot_table(snapshots: &[libvm::SnapshotInfo], now: i64) -> Table {
    let include_source = snapshots.iter().any(|info| !info.provenance.is_empty());
    let include_aliases =
        snapshots.is_empty() || snapshots.iter().any(|info| !info.aliases.is_empty());
    let mut headers = vec!["ID"];
    if include_aliases {
        headers.push("ALIASES");
    }
    headers.push("KIND");
    if include_source {
        headers.push("SOURCE");
    }
    headers.push("CREATED");
    let mut table = Table::new(headers);
    for info in snapshots {
        let sources = info
            .provenance
            .iter()
            .map(|entry| abbreviated_id(&entry.machine_id.to_string()).to_owned())
            .collect::<Vec<_>>();
        let mut row = vec![abbreviated_id(&info.id.to_string()).to_owned()];
        if include_aliases {
            row.push(aliases(&info.aliases));
        }
        row.push(snapshot_kind(info).into());
        if include_source {
            row.push(aliases(&sources));
        }
        row.push(ui::relative_time(info.created_at, now));
        table.add_row(row);
    }
    table
}

fn image_table(sources: &[libvm::ManagedSourceInfo]) -> Table {
    let include_size = sources
        .iter()
        .any(|source| matches!(source, libvm::ManagedSourceInfo::Image(_)));
    let include_name = sources.is_empty()
        || sources.iter().any(|source| match source {
            libvm::ManagedSourceInfo::Image(info) => !info.aliases.is_empty(),
            libvm::ManagedSourceInfo::Snapshot(info) => !info.aliases.is_empty(),
        });
    let mut headers = Vec::new();
    if include_name {
        headers.push("NAME");
    }
    headers.extend(["KIND", "ID"]);
    if include_size {
        headers.push("SIZE");
    }
    let mut table = Table::new(headers);
    for source in sources {
        let (names, kind, id, size) = match source {
            libvm::ManagedSourceInfo::Image(info) => (
                &info.aliases,
                "image".into(),
                info.id.to_string(),
                Some(info.record.root.stream.length),
            ),
            libvm::ManagedSourceInfo::Snapshot(info) => (
                &info.aliases,
                format!("{} snapshot", snapshot_kind(info)),
                info.id.to_string(),
                None,
            ),
        };
        let mut row = Vec::new();
        if include_name {
            row.push(aliases(names));
        }
        row.extend([kind, abbreviated_id(&id).to_owned()]);
        if include_size {
            row.push(ui::human_bytes(size));
        }
        table.add_row(row);
    }
    table
}

#[derive(serde::Serialize)]
struct CreatedMachine<'a> {
    id: &'a str,
    name: &'a str,
}

fn print_machine_result(
    machine: &libvm::MachineData,
    action: &str,
    elapsed: Duration,
    format: OutputFormat,
) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(&CreatedMachine {
            id: &machine.id,
            name: &machine.name,
        }),
        OutputFormat::Plain => {
            ui::success(ui::result_message(
                action,
                &machine.name,
                abbreviated_id(&machine.id),
                elapsed,
            ));
            Ok(())
        }
    }
}

async fn wait_machine_ready(api: &mut crate::api::AppApi, id: &str) -> eyre::Result<()> {
    let machine = api.machine(id).await?;
    let data = machine.inspect().await?;
    if crate::commands::start::requires_guest_readiness(&data) {
        let readiness = machine
            .wait_ready(libvm::DEFAULT_GUEST_READINESS_TIMEOUT)
            .await?;
        if readiness.outcome != libvm::MachineReadinessOutcome::Ready {
            return Err(machine.readiness_failure(&readiness));
        }
    }
    Ok(())
}

async fn wait_fork_children(
    api: &mut crate::api::AppApi,
    result: &libvm::LiveForkResult,
    feedback: &mut OperationFeedback,
) -> Vec<(u32, String)> {
    let mut failures = Vec::new();
    for child in &result.children {
        if matches!(child.outcome, libvm::ForkChildOutcome::Running) {
            feedback.step("Waiting for agent", &child.name);
            if let Err(error) = wait_machine_ready(api, &child.machine_id.to_string()).await {
                failures.push((child.index, error.to_string()));
            }
        }
    }
    failures
}

fn readiness_status(failures: &[(u32, String)]) -> eyre::Result<()> {
    eyre::ensure!(
        failures.is_empty(),
        "fork children did not become ready; running children are retained"
    );
    Ok(())
}

fn fork_result_lines(
    result: &libvm::LiveForkResult,
    elapsed: Duration,
    readiness_failures: &[(u32, String)],
    source_name: &str,
    observing: bool,
) -> Vec<String> {
    use libvm::{ForkCaptureOutcome, ForkChildOutcome, ForkSourceOutcome};
    let mut lines = Vec::new();
    if observing
        || result.stage != libvm::ForkStage::Finished
        || result.cancellation_requested
        || !fork_source_satisfied(result)
        || result
            .children
            .iter()
            .any(|child| !matches!(child.outcome, ForkChildOutcome::Running))
        || !readiness_failures.is_empty()
    {
        lines.push(format!(
            "     Operation {}: {:?}{}",
            result.operation_id,
            result.stage,
            if result.cancellation_requested {
                " (cancellation requested)"
            } else {
                ""
            },
        ));
    }
    if let ForkCaptureOutcome::Failed { diagnostic }
    | ForkCaptureOutcome::Abandoned { diagnostic } = &result.capture
    {
        lines.push(format!("   ✗ Capture failed: {}", diagnostic.as_str()));
    }
    for child in &result.children {
        let (glyph, action, diagnostic) = if let Some((_, error)) = readiness_failures
            .iter()
            .find(|(index, _)| *index == child.index)
        {
            ("✗", "Failed", Some(format!("waiting for agent: {error}")))
        } else {
            match &child.outcome {
                ForkChildOutcome::Running => ("✓", "Forked", None),
                ForkChildOutcome::Failed { phase, diagnostic } => (
                    "✗",
                    "Failed",
                    Some(format!("{phase:?}: {}", diagnostic.as_str())),
                ),
                ForkChildOutcome::Abandoned { diagnostic } => {
                    ("✗", "Abandoned", Some(diagnostic.as_str().into()))
                }
                ForkChildOutcome::RecoveryPending { diagnostic } => {
                    ("✗", "Recovery", Some(diagnostic.as_str().into()))
                }
                ForkChildOutcome::Cancelled => ("✗", "Cancelled", None),
                ForkChildOutcome::Pending => ("·", "Pending", None),
                ForkChildOutcome::Constructing => ("·", "Constructing", None),
                ForkChildOutcome::Activating => ("·", "Activating", None),
            }
        };
        let message = ui::result_message(
            action,
            &child.name,
            abbreviated_id(&child.machine_id.to_string()),
            elapsed,
        );
        lines.push(match diagnostic {
            Some(diagnostic) => format!("   {glyph} {message}: {diagnostic}"),
            None => format!("   {glyph} {message}"),
        });
    }
    let source = match &result.source {
        ForkSourceOutcome::Pending => "pending".into(),
        ForkSourceOutcome::Unchanged => "unchanged".into(),
        ForkSourceOutcome::Resumed => "resumed".into(),
        ForkSourceOutcome::Preserved => "left paused".into(),
        ForkSourceOutcome::ResumeFailed { diagnostic } => {
            format!("RESUME FAILED: {}", diagnostic.as_str())
        }
        ForkSourceOutcome::Unknown { diagnostic } => {
            format!("UNKNOWN: {}", diagnostic.as_str())
        }
    };
    lines.push(format!("     Source {source_name} {source}"));
    lines
}

async fn machine_display_name(api: &mut crate::api::AppApi, reference: &str) -> String {
    let Ok(machine) = api.machine(reference).await else {
        return reference.to_owned();
    };
    match machine.inspect().await {
        Ok(data) => data.name,
        Err(_) => reference.to_owned(),
    }
}

async fn print_fork_result(
    api: &mut crate::api::AppApi,
    result: &libvm::LiveForkResult,
    elapsed: Duration,
    readiness_failures: &[(u32, String)],
    format: OutputFormat,
    observing: bool,
) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(result),
        OutputFormat::Plain => {
            let source_name =
                machine_display_name(api, &result.source_machine_id.to_string()).await;
            for line in
                fork_result_lines(result, elapsed, readiness_failures, &source_name, observing)
            {
                if let Some(message) = line.strip_prefix("   ✓ ") {
                    ui::success(message);
                } else if let Some(message) = line.strip_prefix("     ") {
                    ui::secondary(message);
                } else {
                    eprintln!("{line}");
                }
            }
            Ok(())
        }
    }
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

    fn snapshot_info(alias: Option<&str>) -> libvm::SnapshotInfo {
        libvm::SnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            record_digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            capture_kind: libvm::SnapshotCaptureKindName::LiveExecution,
            provenance: vec![libvm::SnapshotCaptureProvenance {
                capture_id: "00000000-0000-4000-8000-0000000000bb".parse().unwrap(),
                machine_id: "12345678-0000-4000-8000-0000000000dd".parse().unwrap(),
                run_id: "00000000-0000-4000-8000-0000000000cc".parse().unwrap(),
                evidence_digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            }],
            retained: true,
            aliases: alias.into_iter().map(str::to_owned).collect(),
            created_at: 1_000,
        }
    }

    fn table_text(table: crate::ui::Table) -> String {
        let mut bytes = Vec::new();
        table.write_to(&mut bytes, false).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn plain_snapshot_results_and_lists_include_named_and_unnamed_checkpoints() {
        use crate::commands::live::{snapshot_result_line, snapshot_table};
        use std::time::Duration;

        let named = snapshot_info(Some("checkpoint"));
        let unnamed = snapshot_info(None);
        assert_eq!(
            snapshot_result_line(&named, Duration::from_millis(1250)),
            "Created      checkpoint [aaaaaaaa] (1.2s)"
        );
        assert_eq!(
            snapshot_result_line(&unnamed, Duration::from_millis(1250)),
            "Created      (unnamed) [aaaaaaaa] (1.2s)"
        );
        let text = table_text(snapshot_table(&[named, unnamed], 1_000));
        for value in [
            "ID",
            "ALIASES",
            "KIND",
            "SOURCE",
            "CREATED",
            "checkpoint",
            "aaaaaaaa",
            "12345678",
            "live",
        ] {
            assert!(text.contains(value), "{text}");
        }
        assert_eq!(text.lines().count(), 3);
        assert!(!text.contains("sha256:"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn plain_empty_lists_render_only_their_headers() {
        use crate::commands::live::{image_table, snapshot_table};
        let snapshots = table_text(snapshot_table(&[], 1_000));
        let images = table_text(image_table(&[]));
        assert_eq!(snapshots.lines().count(), 1);
        assert_eq!(images.lines().count(), 1);
        assert!(snapshots.starts_with("ID"));
        assert!(images.starts_with("NAME"));
        assert!(!snapshots.contains("SIZE"));
        assert!(!images.contains("CREATED"));
        assert!(!images.contains("SIZE"));
        assert!(!snapshots.contains("SOURCE"));
    }

    #[test]
    fn plain_image_list_uses_available_snapshot_metadata() {
        let sources = [libvm::ManagedSourceInfo::Snapshot(snapshot_info(None))];
        let text = table_text(crate::commands::live::image_table(&sources));
        assert!(text.contains("live snapshot"));
        assert!(text.contains("aaaaaaaa"));
        assert!(!text.contains("SIZE"));
        assert!(!text.contains("NAME"));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn plain_fork_result_retains_siblings_and_names_child_failures() {
        use crate::commands::live::fork_result_lines;
        use libvm::{ForkChildOutcome as Child, ForkSourceOutcome as Source};
        use std::time::Duration;
        let result = result(
            Source::Resumed,
            [
                Child::Running,
                Child::Failed {
                    phase: libvm::ForkFailurePhase::Activation,
                    diagnostic: vm_spec::lifecycle::Diagnostic::new("activation hook exited 7"),
                },
            ],
        );
        let text = fork_result_lines(
            &result,
            Duration::from_millis(1250),
            &[],
            "source-vm",
            false,
        )
        .join("\n");
        assert!(
            text.contains("   ✓ Forked       child-0 [00000000] (1.2s)"),
            "{text}"
        );
        assert!(
            text.contains(
                "   ✗ Failed       child-1 [00000000] (1.2s): Activation: activation hook exited 7"
            ),
            "{text}"
        );
        assert!(text.contains("     Source source-vm resumed"), "{text}");
        assert!(text.contains(OPERATION));
        assert!(live_fork_status(&result).is_err());
        let failures = [(0, "agent disconnected".into())];
        let text =
            fork_result_lines(&result, Duration::ZERO, &failures, "source-vm", false).join("\n");
        assert!(text.contains(
            "   ✗ Failed       child-0 [00000000] (0.0s): waiting for agent: agent disconnected"
        ));
        assert!(!text.contains("   ✓ Forked       child-0"));
    }

    #[test]
    fn plain_fork_observation_reports_cancellation_and_paused_source() {
        use libvm::{ForkChildOutcome as Child, ForkSourceOutcome as Source};
        let mut result = result(Source::Preserved, [Child::Running, Child::Cancelled]);
        result.cancellation_requested = true;
        let text = crate::commands::live::fork_result_lines(
            &result,
            std::time::Duration::ZERO,
            &[],
            "source-vm",
            true,
        )
        .join("\n");
        assert!(text.contains("cancellation requested"));
        assert!(text.contains("   ✗ Cancelled    child-1"));
        assert!(text.contains("left paused"));
    }

    #[test]
    fn snapshot_inspection_is_key_value_data_without_json_fragments() {
        use crate::commands::live::snapshot_detail_rows;
        let mut info = snapshot_info(Some("checkpoint"));
        info.aliases.push("another-alias".into());
        let rows = snapshot_detail_rows(&info);
        assert!(rows.contains(&("Aliases".into(), "checkpoint, another-alias".into())));
        assert!(rows.contains(&("Retained".into(), "yes".into())));
        assert!(rows.contains(&("Kind".into(), "live snapshot".into())));
        assert!(rows.contains(&("Created".into(), crate::ui::format_unix(1_000))));
        assert!(rows.contains(&(
            "Source machine".into(),
            "12345678-0000-4000-8000-0000000000dd".into()
        )));
        assert!(rows.iter().any(|(label, _)| label == "Source run"));
        assert!(rows.iter().any(|(label, _)| label == "Capture"));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('[') || label.contains('.')));
        let rows = snapshot_detail_rows(&snapshot_info(None));
        assert!(rows.contains(&("Aliases".into(), "-".into())));
    }

    #[test]
    fn feedback_commands_default_to_plain_and_explicitly_accept_json() {
        use crate::ui::OutputFormat;
        let commands = [
            vec!["snapshot", "create", "vm"],
            vec!["snapshot", "create", "vm", "--live"],
            vec!["snapshot", "list"],
            vec!["snapshot", "inspect", "image:checkpoint"],
            vec!["image", "list"],
            vec!["image", "inspect", "image:checkpoint"],
            vec!["image", "inspect-remote", "registry.example/image:tag"],
            vec![
                "image",
                "pull",
                "registry.example/image:tag",
                "--approve-digest",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ],
            vec![
                "image",
                "push",
                "image:checkpoint",
                "registry.example/image:tag",
            ],
            vec![
                "image",
                "import",
                "./disk.raw",
                "--platform",
                "linux/amd64",
                "--root",
                "whole-disk",
                "--boot",
                "linux-direct",
            ],
            vec!["image", "convert", "alpine", "--disk-format", "raw"],
            vec!["restore", "image:checkpoint"],
            vec!["fork", "vm", "--name", "child"],
            vec!["fork", "vm", "--live", "--name", "child"],
            vec!["fork", "--operation", OPERATION],
            vec!["fork", "--operation", OPERATION, "--cancel"],
        ];
        for args in commands {
            for (flags, expected) in [
                (vec![], OutputFormat::Plain),
                (vec!["--format", "plain"], OutputFormat::Plain),
                (vec!["--format", "json"], OutputFormat::Json),
            ] {
                let cli = Cli::try_parse_from(
                    ["silo"]
                        .into_iter()
                        .chain(args.iter().copied())
                        .chain(flags),
                )
                .unwrap();
                let format = match cli.command {
                    Command::Snapshot(command) => command.format,
                    Command::Image(command) => command.format,
                    Command::Fork(command) => command.format,
                    Command::Restore(command) => command.format,
                    _ => panic!("unexpected command"),
                };
                assert_eq!(format, expected, "{args:?}");
            }
        }
    }

    #[test]
    fn plain_image_results_render_real_managed_image_fields() {
        let digest = libvm::ObjectDigest::of_bytes(b"image renderer");
        let record = libvm::ImageRecord {
            schema: 1,
            kind: libvm::ImageRecordKind::Image,
            root: serde_json::from_value(serde_json::json!({
                "profile": {"kind": "opaque-raw"},
                "stream": {
                    "stream": digest,
                    "map": digest,
                    "mapPages": [digest],
                    "length": 512,
                },
                "geometry": {"length": 512, "logicalSectorSize": 512},
                "layout": {"kind": "whole-disk"},
            }))
            .unwrap(),
            boot: libvm::BootProfile::LinuxDirect {
                userspace_platform: libvm::LinuxPlatform {
                    architecture: libvm::GuestArchitecture::Amd64,
                    variant: None,
                },
                kernel_architecture: libvm::GuestArchitecture::Amd64,
                command_line_policy: libvm::DirectCommandLinePolicy::SiloDirectV1,
                binding: libvm::BootBinding::Pinned {
                    kernel: digest,
                    base_initramfs: digest,
                    agent: None,
                    architecture: libvm::GuestArchitecture::Amd64,
                    abi: "silo-direct-v2".into(),
                },
                root_selector: libvm::RootSelector::WholeDisk,
                root_filesystem: libvm::RootFilesystem::Ext4,
                translation: libvm::Translation::None,
            },
            process: libvm::ProcessConfig::default(),
        };
        record.validate().unwrap();
        let info = libvm::ManagedImageInfo {
            id: record.id().unwrap(),
            record_digest: digest,
            record,
            aliases: vec!["base".into(), "second-alias".into()],
            retained: true,
            provenance: Vec::new(),
        };
        let source = libvm::ManagedSourceInfo::Image(Box::new(info));
        let rows = crate::commands::live::managed_detail_rows(&source).unwrap();
        assert!(rows.contains(&("Kind".into(), "image".into())));
        assert!(rows.contains(&("Aliases".into(), "base, second-alias".into())));
        assert!(rows.contains(&("Size".into(), crate::ui::human_bytes(Some(512)))));
        assert!(!rows.iter().any(|(label, _)| label.starts_with("info.")));
        assert!(rows.contains(&("Platform".into(), "linux/amd64".into())));
        assert!(rows.contains(&("Storage".into(), "opaque raw".into())));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('.') || label.contains('[')));
        let sources = [
            source,
            libvm::ManagedSourceInfo::Snapshot(snapshot_info(None)),
        ];
        let text = table_text(crate::commands::live::image_table(&sources));
        assert!(text.contains("base, second-alias"));
        assert!(text.contains(&crate::ui::human_bytes(Some(512))));
        assert!(text.contains("SIZE"));
        assert!(text.lines().last().unwrap().ends_with('-'));
    }

    #[test]
    fn json_results_keep_the_previous_pretty_document_exactly() {
        let fork = result(
            libvm::ForkSourceOutcome::Resumed,
            [
                libvm::ForkChildOutcome::Running,
                libvm::ForkChildOutcome::Cancelled,
            ],
        );
        let mut bytes = Vec::new();
        crate::ui::write_json(&mut bytes, &fork).unwrap();
        let previous = format!("{}\n", serde_json::to_string_pretty(&fork).unwrap());
        assert_eq!(bytes, previous.as_bytes());
        let snapshot = snapshot_info(Some("checkpoint"));
        bytes.clear();
        crate::ui::write_json(&mut bytes, &snapshot).unwrap();
        let previous = format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap());
        assert_eq!(bytes, previous.as_bytes());
    }

    #[test]
    fn stopped_fork_and_restore_json_return_a_machine_object_not_a_bare_id() {
        let result = crate::commands::live::CreatedMachine {
            id: "123456780000400080000000000000dd",
            name: "restored",
        };
        let mut bytes = Vec::new();
        crate::ui::write_json(&mut bytes, &result).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            document,
            serde_json::json!({
                "id": "123456780000400080000000000000dd",
                "name": "restored",
            })
        );
    }

    #[test]
    fn successful_fork_uses_start_layout_without_an_operation_banner() {
        use crate::commands::live::fork_result_lines;
        use libvm::{ForkChildOutcome as Child, ForkSourceOutcome as Source};
        let result = result(Source::Resumed, [Child::Running, Child::Running]);
        let lines = fork_result_lines(
            &result,
            std::time::Duration::from_millis(700),
            &[],
            "source-vm",
            false,
        );
        assert_eq!(
            lines,
            [
                "   ✓ Forked       child-0 [00000000] (0.7s)",
                "   ✓ Forked       child-1 [00000000] (0.7s)",
                "     Source source-vm resumed",
            ]
        );
        assert!(!lines.iter().any(|line| line.contains(OPERATION)));
        let observed =
            fork_result_lines(&result, std::time::Duration::ZERO, &[], "source-vm", true);
        assert!(observed[0].contains(OPERATION));
    }

    #[test]
    fn stopped_snapshot_inspection_omits_unavailable_source_details() {
        let mut snapshot = snapshot_info(None);
        snapshot.capture_kind = libvm::SnapshotCaptureKindName::StoppedStorage;
        snapshot.provenance.clear();
        let rows = crate::commands::live::snapshot_detail_rows(&snapshot);
        assert!(rows.contains(&("Kind".into(), "stopped snapshot".into())));
        assert!(!rows.iter().any(|(label, _)| label == "Source machine"));
        let text = table_text(crate::commands::live::snapshot_table(&[snapshot], 1_000));
        assert!(!text.contains("SOURCE"));
    }

    #[test]
    fn remote_inspection_uses_human_labels_for_all_available_metadata() {
        let snapshot = snapshot_info(None);
        let inspection = libvm::ArtifactInspection {
            repository: "registry.example/team/checkpoint".into(),
            index_digest: snapshot.record_digest,
            content: libvm::ManagedSourceId::Snapshot(snapshot.id),
            purpose: libvm::ArtifactPurpose::Checkpoint,
            capture_kind: Some(libvm::SnapshotCaptureKindName::LiveExecution),
            root_family: libvm::ArtifactRootFamily::OpaqueRaw,
            backend: libvm::BackendRequirement::RawBlock,
            guest_architecture: libvm::GuestArchitecture::Amd64,
            live_restore: true,
        };
        let rows = crate::commands::live::artifact_detail_rows(&inspection);
        assert!(rows.contains(&("ID".into(), snapshot.id.to_string())));
        assert!(rows.contains(&("Kind".into(), "live snapshot".into())));
        assert!(rows.contains(&(
            "Repository".into(),
            "registry.example/team/checkpoint".into()
        )));
        assert!(rows.contains(&("Guest architecture".into(), "amd64".into())));
        assert!(rows.contains(&("Live restore".into(), "yes".into())));
        assert!(rows.contains(&("Backend".into(), "raw block".into())));
        assert!(!rows.iter().any(|(label, _)| label == "Created"));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('.') || label.contains('[')));
    }

    #[test]
    fn snapshot_verify_parses_alias_identity_and_json_format() {
        use crate::commands::live::SnapshotCommand;
        use crate::ui::OutputFormat;
        let digest = format!("image:sha256:{}", "a".repeat(64));
        for reference in ["image:checkpoint", digest.as_str()] {
            for args in [
                vec!["silo", "snapshot", "verify", reference],
                vec!["silo", "snapshot", "verify", reference, "--format", "json"],
                vec!["silo", "snapshot", "--format", "json", "verify", reference],
            ] {
                let cli = Cli::try_parse_from(&args).unwrap();
                let Command::Snapshot(snapshot) = cli.command else {
                    panic!("expected snapshot command");
                };
                assert!(!snapshot.is_live());
                let SnapshotCommand::Verify { reference: actual } = snapshot.command else {
                    panic!("expected snapshot verify");
                };
                assert_eq!(actual, reference);
                assert!(actual.parse::<libvm::SnapshotRef>().is_ok());
                assert!(
                    matches!(
                        snapshot.format,
                        OutputFormat::Json if args.contains(&"json")
                    ) || matches!(snapshot.format, OutputFormat::Plain) && !args.contains(&"json")
                );
            }
        }
        for args in [
            vec!["silo", "snapshot", "verify"],
            vec!["silo", "snapshot", "verify", "image:checkpoint", "extra"],
            vec!["silo", "snapshot", "verify", "image:checkpoint", "--live"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let help = Cli::try_parse_from(["silo", "snapshot", "verify", "--help"])
            .unwrap_err()
            .to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("RAM, state and disk"));
        assert!(help.contains("ignoring trust receipts"));
        assert!(help.contains("as long as reading the whole snapshot"));
    }

    #[test]
    fn snapshot_verify_success_renders_plain_and_json_reports() {
        use crate::commands::live::verification_result_line;
        let report = libvm::SnapshotVerificationReport {
            snapshot: snapshot_info(None).id,
            streams: 14,
            bytes: 30 * 1024 * 1024 * 1024,
        };
        let line = verification_result_line(
            &report,
            "archy-snap",
            std::time::Duration::from_millis(12_300),
        );
        assert_eq!(
            line,
            format!(
                "Verified     archy-snap [{}] 14 streams, {} (12.3s)",
                crate::commands::live::abbreviated_id(&report.snapshot.to_string()),
                crate::ui::human_bytes(Some(report.bytes)),
            )
        );
        assert!(
            verification_result_line(&report, "empty", std::time::Duration::from_secs(125))
                .ends_with("(2m 5s)")
        );
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({
                "snapshot": report.snapshot,
                "streams": 14,
                "bytes": report.bytes,
            })
        );
        let empty = libvm::SnapshotVerificationReport {
            streams: 0,
            bytes: 0,
            ..report
        };
        assert!(
            verification_result_line(&empty, "empty", std::time::Duration::ZERO)
                .contains("0 streams, 0B")
        );
        assert_eq!(serde_json::to_value(empty).unwrap()["bytes"], 0);
    }

    #[test]
    fn snapshot_verify_chunk_failures_render_role_range_and_identities() {
        use crate::commands::live::{
            verification_error_json, verification_error_message, VERIFICATION_GUIDANCE,
        };
        use libvm::storage::stream::Chunk;
        use libvm::{SnapshotVerificationError, SnapshotVerificationRole};
        let expected = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
        let actual = format!("sha256:{}", "b".repeat(64)).parse().unwrap();
        let stream = format!("sha256:{}", "c".repeat(64)).parse().unwrap();
        for (role, label) in [
            (SnapshotVerificationRole::Ram, "RAM"),
            (SnapshotVerificationRole::RootDisk, "root disk"),
            (
                SnapshotVerificationRole::DataDisk { order: 3 },
                "data disk 3",
            ),
            (SnapshotVerificationRole::Dependency, "dependency"),
        ] {
            let failure = SnapshotVerificationError::ChunkMismatch {
                role,
                stream,
                index: 2,
                start: 16_777_216,
                end: 25_165_824,
                expected: Box::new(Chunk::Data(expected)),
                actual: Box::new(Chunk::Data(actual)),
            };
            let text = verification_error_message(&failure);
            assert_eq!(
                text,
                format!("{label} stream {stream} chunk 2 bytes 16777216..25165824: expected {expected}, actual {actual}\n{VERIFICATION_GUIDANCE}")
            );
            assert_eq!(
                verification_error_json(&failure),
                serde_json::json!({
                    "error": {
                        "kind": "chunkMismatch", "role": label, "stream": stream,
                        "index": 2, "start": 16_777_216, "end": 25_165_824,
                        "expected": expected, "actual": actual,
                    },
                    "guidance": VERIFICATION_GUIDANCE,
                })
            );
        }
        for (expected, actual) in [
            (Chunk::Zero, Chunk::Data(actual)),
            (Chunk::Data(expected), Chunk::Zero),
        ] {
            let failure = SnapshotVerificationError::ChunkMismatch {
                role: SnapshotVerificationRole::Ram,
                stream,
                index: 0,
                start: 0,
                end: 512,
                expected: Box::new(expected),
                actual: Box::new(actual),
            };
            assert!(verification_error_message(&failure).contains("zero"));
            let json = verification_error_json(&failure);
            assert!(json["error"]["expected"] == "zero" || json["error"]["actual"] == "zero");
        }
    }

    #[test]
    fn snapshot_verify_state_failures_render_length_and_identities() {
        use crate::commands::live::{
            verification_error_json, verification_error_message, VERIFICATION_GUIDANCE,
        };
        use libvm::{SnapshotVerificationError, SnapshotVerificationRole};
        let object = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
        let actual = format!("sha256:{}", "b".repeat(64)).parse().unwrap();
        for (role, label) in [
            (SnapshotVerificationRole::Layout, "memory layout state"),
            (SnapshotVerificationRole::Execution, "execution state"),
            (SnapshotVerificationRole::Devices, "device state"),
        ] {
            let failure = SnapshotVerificationError::ObjectMismatch {
                role,
                object,
                length: 4096,
                actual,
            };
            assert_eq!(
                verification_error_message(&failure),
                format!("{label} object {object} (4096 bytes): expected {object}, actual {actual}\n{VERIFICATION_GUIDANCE}")
            );
            assert_eq!(
                verification_error_json(&failure),
                serde_json::json!({
                    "error": {
                        "kind": "objectMismatch", "role": label, "object": object,
                        "length": 4096, "expected": object, "actual": actual,
                    },
                    "guidance": VERIFICATION_GUIDANCE,
                })
            );
        }
    }

    #[test]
    fn snapshot_verify_structural_failures_render_member_and_failure_details() {
        use crate::commands::live::{
            verification_error_json, verification_error_message, VERIFICATION_GUIDANCE,
        };
        use libvm::{
            SnapshotStructuralFailure, SnapshotVerificationError, SnapshotVerificationMember,
            SnapshotVerificationRole,
        };
        let stream = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
        let object = format!("sha256:{}", "b".repeat(64)).parse().unwrap();
        for (member, member_type, identity) in [
            (
                SnapshotVerificationMember::Stream(stream),
                "stream",
                stream.to_string(),
            ),
            (
                SnapshotVerificationMember::Object(object),
                "object",
                object.to_string(),
            ),
        ] {
            for (failure, message, failure_json) in [
                (
                    SnapshotStructuralFailure::Missing,
                    "missing member",
                    serde_json::json!({ "kind": "missing" }),
                ),
                (
                    SnapshotStructuralFailure::Truncated {
                        expected: 4096,
                        actual: 512,
                    },
                    "truncated member: expected 4096 bytes, actual 512",
                    serde_json::json!({ "kind": "truncated", "expected": 4096, "actual": 512 }),
                ),
                (
                    SnapshotStructuralFailure::Length {
                        expected: 4096,
                        actual: 8192,
                    },
                    "length mismatch: expected 4096 bytes, actual 8192",
                    serde_json::json!({ "kind": "length", "expected": 4096, "actual": 8192 }),
                ),
                (
                    SnapshotStructuralFailure::Writable { mode: 0o600 },
                    "writable member (mode 600)",
                    serde_json::json!({ "kind": "writable", "mode": 384 }),
                ),
                (
                    SnapshotStructuralFailure::Replaced,
                    "member replaced or modified during verification",
                    serde_json::json!({ "kind": "replaced" }),
                ),
                (
                    SnapshotStructuralFailure::Invalid {
                        message: "not a regular file".into(),
                    },
                    "invalid member: not a regular file",
                    serde_json::json!({ "kind": "invalid", "message": "not a regular file" }),
                ),
            ] {
                let failure = SnapshotVerificationError::Structural {
                    role: SnapshotVerificationRole::Dependency,
                    member,
                    failure,
                };
                assert_eq!(
                    verification_error_message(&failure),
                    format!(
                        "dependency {member_type} {identity}: {message}\n{VERIFICATION_GUIDANCE}"
                    )
                );
                assert_eq!(
                    verification_error_json(&failure),
                    serde_json::json!({
                        "error": {
                            "kind": "structural", "role": "dependency",
                            "memberType": member_type, "member": identity, "failure": failure_json,
                        },
                        "guidance": VERIFICATION_GUIDANCE,
                    })
                );
            }
        }
    }
}

use crate::context::Context;
use crate::ui::{self, OutputFormat, Spinner, Table};
use clap::{Args, Subcommand};
use std::future::Future;
use std::time::{Duration, Instant};

const EXACT_BYTES_WARNING: &str = "Copies exact storage bytes, including credentials, guest keys, dirty journals and deleted-data remnants. No sanitization, journal replay, implicit stop or implicit start is performed. External resources require explicit policy. Layered snapshots retain their authenticated immutable composition and exact writable upper.";

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum CapturePolicyArgument {
    Full,
    Incremental,
}

impl CapturePolicyArgument {
    fn policy(self) -> vm_spec::lifecycle::CapturePolicy {
        match self {
            Self::Full => vm_spec::lifecycle::CapturePolicy::Full,
            Self::Incremental => vm_spec::lifecycle::CapturePolicy::Incremental,
        }
    }
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
        self.capture_policy.map_or(
            vm_spec::lifecycle::CapturePolicy::Incremental,
            CapturePolicyArgument::policy,
        )
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
#[command(
    about = "Create and manage snapshots: saved machines, with or without memory",
    after_help = EXACT_BYTES_WARNING
)]
pub struct Snapshot {
    #[command(subcommand)]
    command: SnapshotCommand,
    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Snapshot a stopped VM's disks and configuration, or a running VM's memory too with --memory.
    Create {
        #[arg(value_name = "VM")]
        machine: String,
        /// Optional local snapshot name (no ':' or '/'). Unnamed snapshots are listed by id.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Include RAM, CPU and device state of a running VM. Without it the VM must be stopped.
        #[arg(long, conflicts_with = "external_requirements")]
        memory: bool,
        /// Keep a running source paused after capture. An already user-paused source
        /// always stays paused, with or without this flag.
        #[arg(long, requires = "memory")]
        preserve: bool,
        /// RAM capture policy (default incremental). Uses full capture without an admitted
        /// incremental backend or valid baseline; full always forces a complete capture.
        #[arg(long, requires = "memory", value_enum)]
        capture_policy: Option<CapturePolicyArgument>,
        /// Fall back to full RAM capture at this dirty percentage (1..=60, default 60).
        #[arg(long, requires = "memory", value_parser = clap::value_parser!(u8).range(1..=60))]
        dirty_crossover_percent: Option<u8>,
        /// Omit external resources and record required mappings for a later restore.
        #[arg(long)]
        external_requirements: bool,
    },
    /// Inspect a snapshot by name, id or unique id prefix.
    Inspect {
        #[arg(value_name = "SNAPSHOT")]
        reference: String,
    },
    /// Reread and authenticate every RAM, state and disk byte of a local snapshot, ignoring trust receipts.
    ///
    /// This can take as long as reading the whole snapshot.
    Verify {
        #[arg(value_name = "SNAPSHOT")]
        reference: String,
    },
    /// List snapshots, one row per name; unnamed snapshots show <none>.
    List,
    /// Remove a snapshot name; the snapshot goes with its last name. An id or unique id
    /// prefix removes the snapshot and all its names. Restored machines are unaffected.
    Rm {
        #[arg(value_name = "SNAPSHOT")]
        reference: String,
    },
}
impl Snapshot {
    /// Capturing memory may reach an owned, stopping daemon for typed refusal.
    pub(crate) fn includes_memory(&self) -> bool {
        matches!(self.command, SnapshotCommand::Create { memory: true, .. })
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
                memory,
                preserve,
                capture_policy,
                dirty_crossover_percent,
                external_requirements,
            } => {
                feedback.step(
                    "Capturing",
                    if memory {
                        format!("{machine} (memory, disks and publication)")
                    } else {
                        format!("{machine} (disks and publication)")
                    },
                );
                let options = libvm::SnapshotOptions {
                    name,
                    memory,
                    preserve,
                    capture_policy: capture_policy.map(CapturePolicyArgument::policy),
                    dirty_crossover_percent,
                    external_requirements,
                };
                let (progress, stages) = libvm::LiveOperationProgressSender::default_channel();
                let operation = api.snapshot(&machine, options, Some(progress));
                let created = match feedback.during(operation, stages, &machine).await {
                    Ok(created) => created,
                    Err(error) => {
                        return Err(
                            capture_failure(api, &machine, CaptureAction::Snapshot, error).await,
                        );
                    }
                };
                let elapsed = feedback.finish();
                match self.format {
                    OutputFormat::Json => ui::print_json(&created)?,
                    OutputFormat::Plain => {
                        ui::success(snapshot_result_line(&created.snapshot, elapsed));
                        if let Some(capture) = &created.capture {
                            if let Some(reason) = &capture.first_snapshot_full_identity_reason {
                                match reason {
                                    libvm::SnapshotIdentityReason::UnknownAfterFork => ui::secondary(
                                        "Full content identity computed: this fork child's identity was not yet known",
                                    ),
                                }
                            }
                            let source = match capture.source_outcome {
                                libvm::LiveCaptureSource::Resumed => "resumed",
                                libvm::LiveCaptureSource::Preserved => "left paused",
                                libvm::LiveCaptureSource::ResumeFailed => "RESUME FAILED",
                                libvm::LiveCaptureSource::Unknown => "UNKNOWN",
                            };
                            let source_name = machine_display_name(api, &machine).await;
                            ui::secondary(format!("Source {source_name} {source}"));
                            if let Some(error) = &capture.source_error {
                                ui::warn(error.as_str());
                            }
                        }
                    }
                }
                created.require_requested_name()?;
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
                feedback.step("Verifying", &reference);
                let result = api.verify_snapshot(&reference).await;
                let elapsed = feedback.finish();
                match result {
                    Ok(report) => match self.format {
                        OutputFormat::Json => ui::print_json(&report),
                        OutputFormat::Plain => {
                            ui::success(verification_result_line(&report, &reference, elapsed));
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
                let mut snapshots = api.list_snapshots().await?;
                sort_snapshots(&mut snapshots);
                match self.format {
                    OutputFormat::Json => ui::print_json(&snapshots),
                    OutputFormat::Plain => snapshot_table(&snapshots, ui::now_unix()).print(),
                }
            }
            SnapshotCommand::Rm { reference } => {
                feedback.finish();
                let removal = api.remove_snapshot(&reference).await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&removal),
                    OutputFormat::Plain => {
                        ui::success(removal_line(
                            "snapshot",
                            &removal.id.to_string(),
                            &removal.names,
                            removal.record_removed,
                        ));
                        Ok(())
                    }
                }
            }
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
                let (progress, stages) = libvm::LiveOperationProgressSender::default_channel();
                let operation = api.fork_live(&machine, options, Some(progress));
                let result = match feedback.during(operation, stages, &machine).await {
                    Ok(result) => result,
                    Err(error) => {
                        let error =
                            capture_failure(api, &machine, CaptureAction::Fork, error).await;
                        if error.downcast_ref::<CaptureContactFailure>().is_some() {
                            return Err(error);
                        }
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
                if matches!(
                    result.capture,
                    libvm::ForkCaptureOutcome::Failed { .. }
                        | libvm::ForkCaptureOutcome::Abandoned { .. }
                ) && result
                    .children
                    .iter()
                    .all(|child| child.durability.is_none())
                {
                    if let Ok(source) = api.inspect_machine(&machine).await {
                        if source.observation == libvm::MachineObservation::Observed
                            && !source.status.is_active()
                        {
                            return Err(CaptureContactFailure {
                                name: source.name,
                                action: CaptureAction::Fork,
                                stopped: true,
                            }
                            .into());
                        }
                    }
                }
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
    if matches!(
        error.downcast_ref::<libvm::LibVmError>(),
        Some(
            libvm::LibVmError::MachineCaptureBusy { .. }
                | libvm::LibVmError::MachineAlreadyExists { .. }
        )
    ) {
        return true;
    }
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
#[command(
    about = "Restore a snapshot into a new machine",
    long_about = "Restore a snapshot into a new machine. This is the only way to turn a snapshot into a VM.\n\nREF is a local snapshot name, id or unique id prefix, or a registry reference. A local name wins; short registry names expand through search_registries, and a registry snapshot is pulled according to --pull.\n\nA snapshot with memory resumes its captured execution through fenced activation; a snapshot without memory creates a stopped machine that boots normally. A failed execution restore is never followed by a cold boot.\n\n--without-memory restores a snapshot with memory as a stopped machine from its disks only: RAM, CPU and device state are discarded, no activation runs, and the disks may need filesystem journal recovery on the next boot. It never runs implicitly, and it changes nothing for a snapshot without memory.\n\nPublication uses catalog-owned secret-scope recovery. Custom Runtime::with_secret_store overrides are refused; the ordinary CLI FileStore and secret-provider path remains supported.",
    after_help = EXACT_BYTES_WARNING
)]
pub struct Restore {
    /// Snapshot name, id, unique id prefix or registry reference.
    #[arg(value_name = "REF")]
    reference: String,
    /// Name of the restored machine.
    #[arg(long, value_name = "CHILD")]
    name: Option<String>,
    /// When to pull a registry snapshot.
    #[arg(long, value_enum, default_value = "missing")]
    pull: crate::commands::create::Pull,
    /// Restore only the disks of a snapshot with memory, as a stopped machine; RAM is
    /// discarded and the disks may need journal recovery on boot.
    #[arg(long)]
    without_memory: bool,
    /// Bounded RestoreHook JSON (argv, environment, workingDirectory, timeoutMs), run after
    /// a snapshot with memory resumes.
    #[arg(
        long,
        value_name = "JSON",
        value_parser = activation_hook,
        conflicts_with = "without_memory"
    )]
    activation_hook: Option<libvm::RestoreHook>,
    #[command(flatten)]
    external: ExternalResources,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}
impl Restore {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        if let Some(name) = &self.name {
            libvm::validate_new_machine_name(name)?;
        }
        let mut feedback = OperationFeedback::new(self.format, "Admitting", &self.reference);
        let api = context.app_api().await?;
        let options = libvm::RestoreOptions {
            name: self.name,
            pull: self.pull.policy(),
            without_memory: self.without_memory,
            activation_hook: self.activation_hook,
            external_resources: self.external.policy()?,
        };
        feedback.step(
            "Restoring",
            if self.without_memory {
                format!("{} (disks only)", self.reference)
            } else {
                format!("{} (disks and activation)", self.reference)
            },
        );
        let (progress, stages) = libvm::LiveOperationProgressSender::default_channel();
        let operation = api.restore(&self.reference, options, Some(progress));
        let machine = feedback.during(operation, stages, &self.reference).await?;
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
#[command(about = "Pull, import, convert and manage images: templates for new machines")]
pub struct Image {
    #[command(subcommand)]
    command: ImageCommand,
    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
}
#[derive(Debug, Subcommand)]
enum ImageCommand {
    /// List cached OCI images and stored images, one row per name.
    List,
    /// Inspect a local image by name, id or unique id prefix.
    Inspect {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// Pull an image from a registry, even when a local copy exists. An OCI container
    /// image is cached; a Silo image artifact becomes a stored image. A snapshot artifact
    /// is refused: restore it with `silo restore`.
    Pull {
        #[arg(value_name = "REFERENCE")]
        reference: String,
    },
    /// Publish a stored image as a Silo image artifact to an OCI repository.
    Push {
        #[arg(value_name = "IMAGE")]
        source: String,
        #[arg(value_name = "OCI_DESTINATION")]
        destination: String,
        /// Use raw chunks instead of opportunistic zstd compression.
        #[arg(long)]
        raw: bool,
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
        /// Optional local image name (no ':' or '/').
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
        /// Optional local image name (no ':' or '/').
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// Remove an image name; the image goes with its last name. An id or unique id prefix
    /// removes the image and all its names. Machines created from it are unaffected.
    Rm {
        #[arg(value_name = "IMAGE")]
        reference: String,
    },
    /// Remove images that have no name and that no machine uses.
    Prune,
    /// Inspect a remote Silo VM artifact's immutable index without pulling or booting it.
    InspectRemote {
        #[arg(value_name = "OCI_REFERENCE")]
        reference: String,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ImportBootProfile {
    LinuxDirect,
}
impl Image {
    pub async fn run(self, context: &mut Context) -> eyre::Result<()> {
        match self.command {
            ImageCommand::List => {
                let images = context.app_api().await?.list_images().await?;
                match self.format {
                    OutputFormat::Json => {
                        ui::print_json(&images.iter().map(ImageView::new).collect::<Vec<_>>())
                    }
                    OutputFormat::Plain => image_table(&images, ui::now_unix()).print(),
                }
            }
            ImageCommand::Inspect { reference } => print_image(
                &context.app_api().await?.inspect_image(&reference).await?,
                self.format,
            ),
            ImageCommand::Pull { reference } => {
                let (progress, events) = libvm::ImageProgressSender::default_channel();
                let watcher = (self.format == OutputFormat::Plain)
                    .then(|| crate::pull_progress::watch_image_progress(&reference, events));
                let options = libvm::ImagePullOptions {
                    policy: Some(libvm::PullPolicy::Always),
                };
                let result = context
                    .app_api()
                    .await?
                    .pull_image(&reference, options, progress)
                    .await;
                if let Some(watcher) = watcher {
                    let _ = watcher.await;
                }
                print_image(&result?, self.format)
            }
            ImageCommand::Push {
                source,
                destination,
                raw,
            } => {
                let request = libvm::ArtifactPublishRequest {
                    image: source.parse()?,
                    destination,
                    encoding: if raw {
                        libvm::ArtifactEncoding::Raw
                    } else {
                        libvm::ArtifactEncoding::Zstd
                    },
                };
                print_details(
                    &context.app_api().await?.publish_artifact(request).await?,
                    self.format,
                )
            }
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
                    name: name
                        .as_deref()
                        .map(silo_vm_control::local_name)
                        .transpose()?,
                };
                let (progress, events) = libvm::ImageProgressSender::default_channel();
                let watcher = (self.format == OutputFormat::Plain)
                    .then(|| crate::pull_progress::watch_image_progress("image import", events));
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
                    name: name
                        .as_deref()
                        .map(silo_vm_control::local_name)
                        .transpose()?,
                };
                let pull = pull.map_or(libvm::PullPolicy::IfMissing, |pull| pull.policy());
                let (progress, events) = libvm::ImageProgressSender::default_channel();
                let watcher = (self.format == OutputFormat::Plain)
                    .then(|| crate::pull_progress::watch_image_progress(&reference, events));
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
            ImageCommand::Rm { reference } => {
                let removal = context.app_api().await?.remove_image(&reference).await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&RemovalView {
                        id: removal.id.to_string(),
                        names: &removal.names,
                        record_removed: removal.record_removed,
                    }),
                    OutputFormat::Plain => {
                        ui::success(removal_line(
                            "image",
                            &removal.id.to_string(),
                            &removal.names,
                            removal.record_removed,
                        ));
                        Ok(())
                    }
                }
            }
            ImageCommand::Prune => {
                let report = context.app_api().await?.prune_images().await?;
                match self.format {
                    OutputFormat::Json => ui::print_json(&PruneView {
                        images_removed: report.images_removed,
                        bytes_removed: report.bytes_removed,
                    }),
                    OutputFormat::Plain => {
                        ui::success(prune_line(&report));
                        Ok(())
                    }
                }
            }
            ImageCommand::InspectRemote { reference } => print_artifact_inspection(
                &context
                    .app_api()
                    .await?
                    .inspect_artifact(&reference)
                    .await?,
                self.format,
            ),
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
        ("Names".into(), names_label(&info.names)),
        ("Memory".into(), memory_label(info.memory).into()),
        ("Created".into(), ui::format_unix(info.created_at)),
        ("Record digest".into(), info.record_digest.to_string()),
    ];
    for stream in &info.streams {
        let role = verification_role(&stream.role);
        rows.extend([
            (format!("{role} stream"), stream.stream.to_string()),
            (format!("{role} map root"), stream.map.to_string()),
            (
                format!("{role} length"),
                ui::human_bytes(Some(stream.length)),
            ),
            (
                format!("{role} identity chunk"),
                format!("{} bytes", stream.chunk_size),
            ),
        ]);
    }
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

fn stored_image_detail_rows(info: &libvm::StoredImageInfo) -> eyre::Result<Vec<(String, String)>> {
    let mut rows = vec![
        ("ID".into(), info.id.to_string()),
        ("Names".into(), names_label(&info.names)),
        ("Root".into(), "raw".into()),
        (
            "Size".into(),
            ui::human_bytes(Some(info.record.root.stream.length)),
        ),
        ("Record digest".into(), info.record_digest.to_string()),
        (
            "Root stream".into(),
            info.record.root.stream.stream.to_string(),
        ),
        ("Root map".into(), info.record.root.stream.map.to_string()),
        (
            "Root identity chunk".into(),
            format!("{} bytes", info.record.root.stream.chunk_size),
        ),
        ("Map format".into(), "sparse Merkle v1".into()),
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
            argv_label(process.entrypoint.as_deref()),
        ),
        ("Command".into(), argv_label(process.command.as_deref())),
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

fn oci_image_detail_rows(info: &libvm::OciImageInfo, now: i64) -> Vec<(String, String)> {
    let platform = &info.platform;
    let mut rows = vec![
        ("ID".into(), info.id.to_string()),
        ("Names".into(), names_label(&info.names)),
        ("Root".into(), "layered".into()),
        ("Size".into(), ui::human_bytes(Some(info.lower_length))),
        (
            "Compressed size".into(),
            ui::human_bytes(Some(info.compressed_size_bytes)),
        ),
        (
            "Platform".into(),
            match &platform.variant {
                Some(variant) => format!("{}/{}/{variant}", platform.os, platform.architecture),
                None => format!("{}/{}", platform.os, platform.architecture),
            },
        ),
        ("Config digest".into(), info.config_digest.clone()),
        ("Layers".into(), info.layers.len().to_string()),
        ("Created".into(), ui::format_unix(info.created_at)),
        ("Last used".into(), last_used_label(info.last_used_at, now)),
        (
            "Entrypoint".into(),
            argv_label(info.config.entrypoint.as_deref()),
        ),
        ("Command".into(), argv_label(info.config.cmd.as_deref())),
        (
            "Working directory".into(),
            info.config
                .working_dir
                .clone()
                .unwrap_or_else(|| "-".into()),
        ),
        (
            "User".into(),
            info.config.user.clone().unwrap_or_else(|| "-".into()),
        ),
    ];
    for variable in info.config.env.iter().flatten() {
        let (key, value) = variable.split_once('=').unwrap_or((variable, ""));
        rows.push((format!("Environment {key}"), value.into()));
    }
    rows
}

fn argv_label(argv: Option<&[String]>) -> String {
    argv.map(|argv| format!("{argv:?}"))
        .unwrap_or_else(|| "-".into())
}

fn last_used_label(last_used_at: Option<i64>, now: i64) -> String {
    last_used_at.map_or_else(|| "-".into(), |time| ui::relative_time(time, now))
}

/// JSON shape of one local image: `{"kind": "oci"|"stored", "info": {...}}`.
#[derive(serde::Serialize)]
#[serde(tag = "kind", content = "info", rename_all = "kebab-case")]
enum ImageView<'a> {
    Oci(OciImageView<'a>),
    Stored(&'a libvm::StoredImageInfo),
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OciImageView<'a> {
    id: libvm::ImageId,
    names: &'a [String],
    config_digest: &'a str,
    platform: &'a libvm::Platform,
    config: &'a libvm::OciImageConfigMetadata,
    layers: Vec<OciLayerView<'a>>,
    lower_length: u64,
    compressed_size_bytes: u64,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OciLayerView<'a> {
    position: i64,
    blob_digest: &'a str,
    diff_id: &'a str,
    media_type: &'a str,
    compressed_size_bytes: Option<u64>,
    uncompressed_size_bytes: Option<u64>,
}

impl<'a> ImageView<'a> {
    fn new(image: &'a libvm::ImageInfo) -> Self {
        match image {
            libvm::ImageInfo::Stored(info) => Self::Stored(info),
            libvm::ImageInfo::Oci(info) => Self::Oci(OciImageView {
                id: info.id,
                names: &info.names,
                config_digest: &info.config_digest,
                platform: &info.platform,
                config: &info.config,
                layers: info
                    .layers
                    .iter()
                    .map(|layer| OciLayerView {
                        position: layer.position,
                        blob_digest: &layer.blob_digest,
                        diff_id: &layer.diff_id,
                        media_type: &layer.media_type,
                        compressed_size_bytes: layer.compressed_size_bytes,
                        uncompressed_size_bytes: layer.uncompressed_size_bytes,
                    })
                    .collect(),
                lower_length: info.lower_length,
                compressed_size_bytes: info.compressed_size_bytes,
                created_at: info.created_at,
                last_used_at: info.last_used_at,
            }),
        }
    }
}

/// JSON shape of an image removal; a snapshot removal serializes the same way.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemovalView<'a> {
    id: String,
    names: &'a [String],
    record_removed: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PruneView {
    images_removed: u64,
    bytes_removed: u64,
}

fn removal_line(kind: &str, id: &str, names: &[String], record_removed: bool) -> String {
    let id = table_id(id);
    match (record_removed, names.is_empty()) {
        (true, true) => format!("Removed {kind} [{id}]"),
        (true, false) => format!("Removed {kind} {} [{id}]", names.join(", ")),
        (false, _) => format!(
            "Removed name {} [{id}]; the {kind} keeps its other names",
            names.join(", ")
        ),
    }
}

fn prune_line(report: &libvm::ImagePruneReport) -> String {
    format!(
        "Removed {} image{}; reclaimed {} of unreferenced data",
        report.images_removed,
        if report.images_removed == 1 { "" } else { "s" },
        ui::human_bytes(Some(report.bytes_removed)),
    )
}

fn print_image(image: &libvm::ImageInfo, format: OutputFormat) -> eyre::Result<()> {
    match format {
        OutputFormat::Json => ui::print_json(&ImageView::new(image)),
        OutputFormat::Plain => ui::print_detail_rows(&match image {
            libvm::ImageInfo::Stored(info) => stored_image_detail_rows(info)?,
            libvm::ImageInfo::Oci(info) => oci_image_detail_rows(info, ui::now_unix()),
        }),
    }
}

fn artifact_detail_rows(info: &libvm::ArtifactInspection) -> Vec<(String, String)> {
    let (id, kind) = match info.content {
        libvm::ArtifactContent::Image(id) => (id.to_string(), "image"),
        libvm::ArtifactContent::Snapshot(id) => (id.to_string(), "snapshot"),
    };
    vec![
        ("ID".into(), id),
        ("Kind".into(), kind.into()),
        ("Repository".into(), info.repository.clone()),
        ("Index digest".into(), info.index_digest.to_string()),
        (
            "Root".into(),
            match info.root {
                libvm::ArtifactRootFamily::OpaqueRaw => "raw",
                libvm::ArtifactRootFamily::LinuxOverlay => "layered",
            }
            .into(),
        ),
        (
            "Guest architecture".into(),
            architecture_label(info.guest_architecture).into(),
        ),
        ("Memory".into(), ui::yes_no(info.memory).into()),
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

    async fn during<T, E>(
        &mut self,
        operation: impl Future<Output = Result<T, E>>,
        mut stages: libvm::LiveOperationProgressReceiver,
        source: &str,
    ) -> Result<T, E> {
        tokio::pin!(operation);
        let mut open = true;
        loop {
            tokio::select! {
                biased;
                result = &mut operation => return result,
                stage = stages.recv(), if open => {
                    if let Some(stage) = stage {
                        let (label, target) = ui::live_operation_progress_words(&stage, source);
                        self.step(label, target);
                    } else {
                        open = false;
                    }
                }
            }
        }
    }

    fn finish(self) -> Duration {
        self.spinner.finish_clear();
        self.started.elapsed()
    }
}

fn abbreviated_id(id: &str) -> &str {
    ui::short_id(id.strip_prefix("sha256:").unwrap_or(id))
}

/// The first 12 hex digits of an image or snapshot id, as list tables show it.
fn table_id(id: &str) -> &str {
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    hex.get(..12).unwrap_or(hex)
}

fn names_label(names: &[String]) -> String {
    if names.is_empty() {
        "-".into()
    } else {
        names.join(", ")
    }
}

fn memory_label(memory: libvm::SnapshotMemory) -> &'static str {
    match memory {
        libvm::SnapshotMemory::None => "no",
        libvm::SnapshotMemory::Included => "yes",
    }
}

fn snapshot_result_line(info: &libvm::SnapshotInfo, elapsed: Duration) -> String {
    let name = if info.names.is_empty() {
        "(unnamed)".into()
    } else {
        names_label(&info.names)
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

fn verification_chunk(chunk: &vm_spec::stream_map::Chunk) -> String {
    match chunk {
        vm_spec::stream_map::Chunk::Zero => "zero".into(),
        vm_spec::stream_map::Chunk::Data(digest) => digest.to_string(),
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
            chunk_size,
            index,
            start,
            end,
            expected,
            actual,
        } => format!(
            "{} stream {stream} data chunk {index} ({chunk_size} bytes) bytes {start}..{end}: expected {}, actual {}",
            verification_role(role),
            verification_chunk(expected),
            verification_chunk(actual),
        ),
        SnapshotVerificationError::MapNode(error) => {
            let libvm::SnapshotMapNodeFailure { role, stream, node, height, first_index, end_index, start, end, failure } = error.as_ref();
            format!(
                "{} stream {stream} map node {node} height {height} chunks {first_index}..{end_index} bytes {start}..{end}: {failure}",
                verification_role(role),
            )
        }
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
            chunk_size,
            index,
            start,
            end,
            expected,
            actual,
        } => json!({
            "kind": "chunkMismatch", "role": verification_role(role),
            "stream": stream, "index": index, "start": start, "end": end,
            "chunkSize": chunk_size,
            "expected": verification_chunk(expected), "actual": verification_chunk(actual),
        }),
        SnapshotVerificationError::MapNode(error) => {
            let libvm::SnapshotMapNodeFailure {
                role,
                stream,
                node,
                height,
                first_index,
                end_index,
                start,
                end,
                failure,
            } = error.as_ref();
            json!({
            "kind": "mapNode", "role": verification_role(role), "stream": stream,
            "node": node, "height": height, "firstIndex": first_index, "endIndex": end_index,
            "start": start, "end": end,
            "failure": match failure {
                SnapshotStructuralFailure::Missing => json!({"kind": "missing"}),
                SnapshotStructuralFailure::Invalid { message } => json!({"kind": "invalid", "message": message}),
                failure => json!({"kind": "structural", "message": failure.to_string()}),
            },
            })
        }
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

/// Rows for one record: one per name, or a single `<none>` row when unnamed.
fn name_rows(names: &[String]) -> impl Iterator<Item = &str> {
    let unnamed = names.is_empty().then_some("<none>");
    names.iter().map(String::as_str).chain(unnamed)
}

#[derive(Debug, Clone, Copy)]
enum CaptureAction {
    Snapshot,
    Fork,
}

impl std::fmt::Display for CaptureAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Snapshot => "snapshot",
            Self::Fork => "fork",
        })
    }
}

#[derive(Debug)]
struct CaptureContactFailure {
    name: String,
    action: CaptureAction,
    stopped: bool,
}

impl std::error::Error for CaptureContactFailure {}

impl std::fmt::Display for CaptureContactFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.stopped {
            write!(formatter, "machine {} stopped unexpectedly during the {}; start it again with `silo start {}`", self.name, self.action, self.name)
        } else {
            write!(
                formatter,
                "lost contact with machine {} during the {}; check `silo list` before trying again",
                self.name, self.action
            )
        }
    }
}

async fn capture_failure(
    api: &mut crate::api::AppApi,
    reference: &str,
    action: CaptureAction,
    error: eyre::Report,
) -> eyre::Report {
    let transport = matches!(
        error.downcast_ref::<libvm::LibVmError>(),
        Some(
            libvm::LibVmError::MonitorConnection { .. } | libvm::LibVmError::LiveObservation { .. }
        )
    );
    let capture = matches!(
        error.downcast_ref::<libvm::LibVmError>(),
        Some(libvm::LibVmError::LiveCapture { .. } | libvm::LibVmError::LiveFork { .. })
    );
    if !transport && !capture {
        return error;
    }
    let observed = api.inspect_capture_source(reference).await;
    capture_failure_observed(
        reference,
        action,
        error,
        observed
            .filter(|machine| machine.observation == libvm::MachineObservation::Observed)
            .map(|machine| (machine.name, machine.status)),
    )
}

fn capture_failure_observed(
    reference: &str,
    action: CaptureAction,
    error: eyre::Report,
    observed: Option<(String, libvm::MachineStatus)>,
) -> eyre::Report {
    let transport = matches!(
        error.downcast_ref::<libvm::LibVmError>(),
        Some(
            libvm::LibVmError::MonitorConnection { .. } | libvm::LibVmError::LiveObservation { .. }
        )
    );
    let stopped = observed
        .as_ref()
        .is_some_and(|(_, status)| !status.is_active());
    if !transport && !stopped {
        return error;
    }
    CaptureContactFailure {
        name: observed.map_or_else(|| reference.to_owned(), |(name, _)| name),
        action,
        stopped,
    }
    .into()
}

fn sort_snapshots(snapshots: &mut [libvm::SnapshotInfo]) {
    snapshots.sort_unstable_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.names.cmp(&right.names))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn snapshot_table(snapshots: &[libvm::SnapshotInfo], now: i64) -> Table {
    let mut table = Table::new(["NAME", "ID", "MEMORY", "SOURCE", "CREATED"]);
    for info in snapshots {
        let id = info.id.to_string();
        let sources = info
            .provenance
            .iter()
            .map(|entry| abbreviated_id(&entry.machine_id.to_string()).to_owned())
            .collect::<Vec<_>>();
        let sources = names_label(&sources);
        let created = ui::relative_time(info.created_at, now);
        for name in name_rows(&info.names) {
            table.add_row([
                name,
                table_id(&id),
                memory_label(info.memory),
                &sources,
                &created,
            ]);
        }
    }
    table
}

fn image_table(images: &[libvm::ImageInfo], now: i64) -> Table {
    let mut table = Table::new(["NAME", "ID", "ROOT", "SIZE", "LAST USED"]);
    for image in images {
        let (root, size, last_used_at) = match image {
            libvm::ImageInfo::Oci(info) => ("layered", info.lower_length, info.last_used_at),
            libvm::ImageInfo::Stored(info) => ("raw", info.record.root.stream.length, None),
        };
        let id = image.id().to_string();
        let size = ui::human_bytes(Some(size));
        let last_used = last_used_label(last_used_at, now);
        for name in name_rows(image.names()) {
            table.add_row([name, table_id(&id), root, &size, &last_used]);
        }
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

    #[tokio::test]
    async fn live_feedback_preserves_results_when_progress_closes() {
        use crate::commands::live::OperationFeedback;
        use crate::ui::OutputFormat;

        let mut feedback = OperationFeedback::new(OutputFormat::Json, "Admitting", "archy");
        let (progress, stages) = libvm::LiveOperationProgressSender::default_channel();
        progress.send(libvm::LiveOperationProgress::CapturingMemory);
        drop(progress);
        let result = feedback
            .during(
                async {
                    tokio::task::yield_now().await;
                    Err::<(), _>("retained original operation error")
                },
                stages,
                "archy",
            )
            .await;
        assert_eq!(result, Err("retained original operation error"));
    }

    const OPERATION: &str = "00000000-0000-4000-8000-0000000000aa";

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["silo", "fork"].iter().chain(args).copied())
    }

    #[test]
    fn snapshot_and_fork_default_to_incremental_with_explicit_full_override() {
        use crate::commands::live::{CapturePolicyArgument, SnapshotCommand};
        use vm_spec::lifecycle::CapturePolicy;

        for (flags, expected) in [
            (vec![], CapturePolicy::Incremental),
            (
                vec!["--capture-policy", "incremental"],
                CapturePolicy::Incremental,
            ),
            (vec!["--capture-policy", "full"], CapturePolicy::Full),
        ] {
            let prefix = ["silo", "snapshot", "create", "vm", "--memory"];
            let cli = Cli::try_parse_from(prefix.iter().chain(flags.iter()).copied()).unwrap();
            let Command::Snapshot(snapshot) = cli.command else {
                panic!("expected snapshot");
            };
            assert!(snapshot.includes_memory());
            let SnapshotCommand::Create {
                memory,
                capture_policy,
                dirty_crossover_percent,
                ..
            } = snapshot.command
            else {
                panic!("expected create");
            };
            assert!(memory);
            assert_eq!(
                capture_policy.map_or(CapturePolicy::Incremental, CapturePolicyArgument::policy),
                expected
            );
            assert_eq!(dirty_crossover_percent, None);

            let mut args = vec!["vm", "--live", "--name", "child"];
            args.extend(flags);
            let (_, options) = live(&args);
            assert_eq!(options.policy, expected);
            assert_eq!(options.dirty_crossover_percent, 60);
        }
    }

    #[test]
    fn incremental_options_require_live_mode_and_bounded_crossover() {
        for (prefix, mode) in [
            (vec!["silo", "snapshot", "create", "vm"], "--memory"),
            (vec!["silo", "fork", "vm", "--name", "child"], "--live"),
        ] {
            for flags in [
                vec!["--capture-policy", "incremental"],
                vec!["--dirty-crossover-percent", "60"],
            ] {
                assert!(Cli::try_parse_from(prefix.iter().chain(flags.iter()).copied()).is_err());
            }
            for percent in ["0", "61", "256", "-1", "1.5"] {
                let flags = [
                    mode,
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
    fn memory_only_snapshot_options_require_memory() {
        for flags in [
            vec!["--preserve"],
            vec!["--capture-policy", "full"],
            vec!["--dirty-crossover-percent", "10"],
        ] {
            let mut args = vec!["silo", "snapshot", "create", "vm"];
            args.extend_from_slice(&flags);
            let error = Cli::try_parse_from(&args).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "{flags:?}"
            );
            args.push("--memory");
            assert!(Cli::try_parse_from(&args).is_ok(), "{flags:?}");
        }
        for args in [
            vec!["silo", "snapshot", "create", "vm", "--live"],
            vec![
                "silo",
                "snapshot",
                "create",
                "vm",
                "--memory",
                "--external-requirements",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn restore_folds_disk_recovery_into_without_memory() {
        let hook =
            r#"{"argv":["/bin/true"],"environment":[],"workingDirectory":"/","timeoutMs":1000}"#;
        let error = Cli::try_parse_from([
            "silo",
            "restore",
            "web",
            "--without-memory",
            "--activation-hook",
            hook,
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        assert!(Cli::try_parse_from(["silo", "restore", "web", "--activation-hook", hook]).is_ok());

        let cli = Cli::try_parse_from([
            "silo",
            "restore",
            "ghcr.io/acme/web:1",
            "--without-memory",
            "--pull",
            "never",
            "--name",
            "recovered",
        ])
        .unwrap();
        let Command::Restore(command) = cli.command else {
            panic!("restore command");
        };
        assert_eq!(command.reference, "ghcr.io/acme/web:1");
        assert_eq!(command.name.as_deref(), Some("recovered"));
        assert!(command.without_memory);
        assert_eq!(command.pull.policy(), libvm::PullPolicy::Never);

        let Command::Restore(command) = Cli::try_parse_from(["silo", "restore", "web"])
            .unwrap()
            .command
        else {
            panic!("restore command");
        };
        assert!(!command.without_memory);
        assert_eq!(command.pull.policy(), libvm::PullPolicy::IfMissing);
        for pull in ["always", "missing", "never"] {
            assert!(Cli::try_parse_from(["silo", "restore", "web", "--pull", pull]).is_ok());
        }
        assert!(Cli::try_parse_from(["silo", "restore", "web", "--pull", "sometimes"]).is_err());
    }

    #[test]
    fn removed_image_and_snapshot_commands_no_longer_parse() {
        for args in [
            vec!["silo", "recover-disks", "web"],
            vec!["silo", "recover-disks", "web", "--name", "recovered"],
            vec!["silo", "image", "release", "base"],
            vec!["silo", "image", "remove", "base"],
            vec!["silo", "snapshot", "remove", "web"],
            vec![
                "silo",
                "image",
                "pull",
                "registry.example/a:1",
                "--approve-digest",
                "x",
            ],
            vec![
                "silo",
                "image",
                "pull",
                "registry.example/a:1",
                "--require-signature",
            ],
            vec![
                "silo",
                "image",
                "pull",
                "registry.example/a:1",
                "--name",
                "a",
            ],
            vec![
                "silo",
                "image",
                "push",
                "base",
                "registry.example/a:1",
                "--acknowledge-checkpoint",
            ],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
        for args in [
            vec!["silo", "image", "rm", "base"],
            vec!["silo", "image", "prune"],
            vec!["silo", "image", "pull", "registry.example/a:1"],
            vec!["silo", "snapshot", "rm", "web"],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_ok(), "{args:?}");
        }
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
                cut_id: "00000000-0000-4000-8000-0000000000bb".parse().unwrap(),
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
        assert!(Cli::try_parse_from(["silo", "restore", "snap"]).is_ok());
        for flags in [
            vec!["--memory-overcommit"],
            vec!["--private-write-percent", "25"],
        ] {
            let mut restore = vec!["silo", "restore", "snap"];
            restore.extend_from_slice(&flags);
            assert!(Cli::try_parse_from(restore).is_err());
            let mut fork = vec!["silo", "fork", "vm", "--live", "--name", "child"];
            fork.extend_from_slice(&flags);
            assert!(Cli::try_parse_from(fork).is_err());
        }
    }

    fn snapshot_info(name: Option<&str>) -> libvm::SnapshotInfo {
        libvm::SnapshotInfo {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            record_digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            memory: libvm::SnapshotMemory::Included,
            provenance: vec![libvm::SnapshotCaptureProvenance {
                capture_id: "00000000-0000-4000-8000-0000000000bb".parse().unwrap(),
                machine_id: "12345678-0000-4000-8000-0000000000dd".parse().unwrap(),
                run_id: "00000000-0000-4000-8000-0000000000cc".parse().unwrap(),
                evidence_digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            }],
            names: name.into_iter().map(str::to_owned).collect(),
            created_at: 1_000,
            streams: vec![libvm::SnapshotStreamSummary {
                role: libvm::SnapshotVerificationRole::Ram,
                stream: format!("sha256:{}", "d".repeat(64)).parse().unwrap(),
                map: format!("sha256:{}", "d".repeat(64)).parse().unwrap(),
                length: 3 * 65_536,
                chunk_size: 65_536,
            }],
        }
    }

    fn table_text(table: crate::ui::Table) -> String {
        let mut bytes = Vec::new();
        table.write_to(&mut bytes, false).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn stored_image(names: &[&str]) -> libvm::StoredImageInfo {
        let digest = libvm::ObjectDigest::of_bytes(b"image renderer");
        let record = libvm::ImageRecord {
            schema: 1,
            kind: libvm::ImageRecordKind::Image,
            root: serde_json::from_value(serde_json::json!({
                "profile": {"kind": "opaque-raw"},
                "stream": {
                    "stream": digest,
                    "map": digest,
                    "chunkSize": 8_388_608,
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
                    abi: "silo-direct-v1".into(),
                },
                root_selector: libvm::RootSelector::WholeDisk,
                root_filesystem: libvm::RootFilesystem::Ext4,
                translation: libvm::Translation::None,
            },
            process: libvm::ProcessConfig::default(),
        };
        record.validate().unwrap();
        libvm::StoredImageInfo {
            id: record.id().unwrap(),
            record_digest: digest,
            record,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
            provenance: Vec::new(),
        }
    }

    fn oci_image(names: &[&str], last_used_at: Option<i64>) -> libvm::OciImageInfo {
        libvm::OciImageInfo {
            id: format!("sha256:{}", "e".repeat(64)).parse().unwrap(),
            names: names.iter().map(|name| (*name).to_owned()).collect(),
            config_digest: format!("sha256:{}", "f".repeat(64)),
            platform: libvm::Platform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            config: libvm::OciImageConfigMetadata {
                entrypoint: Some(vec!["/bin/app".into()]),
                env: Some(vec!["A=1".into()]),
                working_dir: Some("/srv".into()),
                ..libvm::OciImageConfigMetadata::default()
            },
            layers: vec![libvm::ImageLayerDetail {
                blob_digest: format!("sha256:{}", "1".repeat(64)),
                diff_id: format!("sha256:{}", "2".repeat(64)),
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                compressed_size_bytes: Some(100),
                uncompressed_size_bytes: Some(200),
                position: 0,
            }],
            lower_length: 4096,
            compressed_size_bytes: 100,
            created_at: 500,
            last_used_at,
        }
    }

    fn columns(line: &str) -> Vec<&str> {
        line.split("  ")
            .map(str::trim)
            .filter(|column| !column.is_empty())
            .collect()
    }

    #[test]
    fn plain_snapshot_results_and_lists_show_one_row_per_name_and_unnamed_records() {
        use crate::commands::live::{snapshot_result_line, snapshot_table};
        use std::time::Duration;

        let mut named = snapshot_info(Some("web"));
        named.names.push("web-v2".into());
        let mut unnamed = snapshot_info(None);
        unnamed.memory = libvm::SnapshotMemory::None;
        unnamed.provenance.clear();
        assert_eq!(
            snapshot_result_line(&named, Duration::from_millis(1250)),
            "Created      web, web-v2 [aaaaaaaa] (1.2s)"
        );
        assert_eq!(
            snapshot_result_line(&unnamed, Duration::from_millis(1250)),
            "Created      (unnamed) [aaaaaaaa] (1.2s)"
        );
        let text = table_text(snapshot_table(&[named, unnamed], 1_000));
        let lines = text.lines().map(columns).collect::<Vec<_>>();
        let created = crate::ui::relative_time(1_000, 1_000);
        assert_eq!(
            lines,
            [
                vec!["NAME", "ID", "MEMORY", "SOURCE", "CREATED"],
                vec!["web", "aaaaaaaaaaaa", "yes", "12345678", created.as_str()],
                vec![
                    "web-v2",
                    "aaaaaaaaaaaa",
                    "yes",
                    "12345678",
                    created.as_str()
                ],
                vec!["<none>", "aaaaaaaaaaaa", "no", "-", created.as_str()],
            ]
        );
        assert!(!text.contains("sha256:"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn plain_empty_lists_render_only_their_headers() {
        use crate::commands::live::{image_table, snapshot_table};
        let snapshots = table_text(snapshot_table(&[], 1_000));
        let images = table_text(image_table(&[], 1_000));
        assert_eq!(
            snapshots.lines().map(columns).collect::<Vec<_>>(),
            [vec!["NAME", "ID", "MEMORY", "SOURCE", "CREATED"]]
        );
        assert_eq!(
            images.lines().map(columns).collect::<Vec<_>>(),
            [vec!["NAME", "ID", "ROOT", "SIZE", "LAST USED"]]
        );
    }

    #[test]
    fn plain_image_list_shows_cached_and_stored_images_one_row_per_name() {
        let images = [
            libvm::ImageInfo::Oci(Box::new(oci_image(
                &[
                    "docker.io/library/python:3.12",
                    "docker.io/library/python:3",
                ],
                Some(400),
            ))),
            libvm::ImageInfo::Oci(Box::new(oci_image(&[], None))),
            libvm::ImageInfo::Stored(Box::new(stored_image(&["base"]))),
        ];
        let text = table_text(crate::commands::live::image_table(&images, 1_000));
        let lines = text.lines().map(columns).collect::<Vec<_>>();
        let oci_size = crate::ui::human_bytes(Some(4096));
        let stored_size = crate::ui::human_bytes(Some(512));
        let last_used = crate::ui::relative_time(400, 1_000);
        let stored_id = images[2].id().to_string();
        let stored_id = &stored_id["sha256:".len().."sha256:".len() + 12];
        assert_eq!(
            lines,
            [
                vec!["NAME", "ID", "ROOT", "SIZE", "LAST USED"],
                vec![
                    "docker.io/library/python:3.12",
                    "eeeeeeeeeeee",
                    "layered",
                    oci_size.as_str(),
                    last_used.as_str(),
                ],
                vec![
                    "docker.io/library/python:3",
                    "eeeeeeeeeeee",
                    "layered",
                    oci_size.as_str(),
                    last_used.as_str(),
                ],
                vec!["<none>", "eeeeeeeeeeee", "layered", oci_size.as_str(), "-"],
                vec!["base", stored_id, "raw", stored_size.as_str(), "-"],
            ]
        );
        assert!(!text.contains("snapshot"));
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
        let mut info = snapshot_info(Some("web"));
        info.names.push("web-v2".into());
        let rows = snapshot_detail_rows(&info);
        assert!(rows.contains(&("Names".into(), "web, web-v2".into())));
        assert!(rows.contains(&("Memory".into(), "yes".into())));
        assert!(rows.contains(&("Created".into(), crate::ui::format_unix(1_000))));
        assert!(rows.contains(&(
            "Source machine".into(),
            "12345678-0000-4000-8000-0000000000dd".into()
        )));
        assert!(rows.iter().any(|(label, _)| label == "Source run"));
        assert!(rows.iter().any(|(label, _)| label == "Capture"));
        assert!(!rows
            .iter()
            .any(|(label, _)| label == "Kind" || label == "Retained" || label == "Aliases"));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('[') || label.contains('.')));
        let rows = snapshot_detail_rows(&snapshot_info(None));
        assert!(rows.contains(&("Names".into(), "-".into())));
    }

    #[test]
    fn feedback_commands_default_to_plain_and_explicitly_accept_json() {
        use crate::ui::OutputFormat;
        let commands = [
            vec!["snapshot", "create", "vm"],
            vec!["snapshot", "create", "vm", "--memory"],
            vec!["snapshot", "list"],
            vec!["snapshot", "inspect", "web"],
            vec!["snapshot", "rm", "web"],
            vec!["image", "list"],
            vec!["image", "inspect", "base"],
            vec!["image", "inspect-remote", "registry.example/image:tag"],
            vec!["image", "pull", "registry.example/image:tag"],
            vec!["image", "push", "base", "registry.example/image:tag"],
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
            vec!["image", "rm", "base"],
            vec!["image", "prune"],
            vec!["restore", "web"],
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
    fn image_inspection_renders_stored_and_cached_image_fields() {
        use crate::commands::live::{oci_image_detail_rows, stored_image_detail_rows, ImageView};
        let stored = stored_image(&["base", "second-name"]);
        let rows = stored_image_detail_rows(&stored).unwrap();
        assert!(rows.contains(&("Names".into(), "base, second-name".into())));
        assert!(rows.contains(&("Root".into(), "raw".into())));
        assert!(rows.contains(&("Size".into(), crate::ui::human_bytes(Some(512)))));
        assert!(rows.contains(&("Root identity chunk".into(), "8388608 bytes".into())));
        assert!(rows.contains(&("Platform".into(), "linux/amd64".into())));
        assert!(rows.contains(&("Storage".into(), "opaque raw".into())));
        assert!(!rows
            .iter()
            .any(|(label, _)| label == "Kind" || label == "Retained" || label == "Aliases"));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('.') || label.contains('[')));
        let stored = libvm::ImageInfo::Stored(Box::new(stored));
        let json = serde_json::to_value(ImageView::new(&stored)).unwrap();
        assert_eq!(json["kind"], "stored");
        assert_eq!(
            json["info"]["names"],
            serde_json::json!(["base", "second-name"])
        );
        assert_eq!(json["info"]["id"], stored.id().to_string());
        assert_eq!(
            json["info"]["record"]["root"]["stream"]["chunkSize"],
            8_388_608
        );
        assert!(json["info"].get("retained").is_none());

        let cached = oci_image(&["docker.io/library/python:3.12"], Some(400));
        let rows = oci_image_detail_rows(&cached, 1_000);
        for row in [
            ("Names", "docker.io/library/python:3.12".to_owned()),
            ("Root", "layered".to_owned()),
            ("Size", crate::ui::human_bytes(Some(4096))),
            ("Platform", "linux/amd64".to_owned()),
            ("Layers", "1".to_owned()),
            ("Last used", crate::ui::relative_time(400, 1_000)),
            ("Entrypoint", r#"["/bin/app"]"#.to_owned()),
            ("Command", "-".to_owned()),
            ("Working directory", "/srv".to_owned()),
            ("Environment A", "1".to_owned()),
        ] {
            assert!(rows.contains(&(row.0.into(), row.1.clone())), "{row:?}");
        }
        let rows = oci_image_detail_rows(&oci_image(&[], None), 1_000);
        assert!(rows.contains(&("Names".into(), "-".into())));
        assert!(rows.contains(&("Last used".into(), "-".into())));
        let cached = libvm::ImageInfo::Oci(Box::new(cached));
        let json = serde_json::to_value(ImageView::new(&cached)).unwrap();
        assert_eq!(json["kind"], "oci");
        assert_eq!(json["info"]["id"], format!("sha256:{}", "e".repeat(64)));
        assert_eq!(
            json["info"]["names"],
            serde_json::json!(["docker.io/library/python:3.12"])
        );
        assert_eq!(json["info"]["lowerLength"], 4096);
        assert_eq!(json["info"]["lastUsedAt"], 400);
        assert_eq!(
            json["info"]["layers"][0]["blobDigest"],
            format!("sha256:{}", "1".repeat(64))
        );
    }

    #[test]
    fn removal_and_prune_lines_name_what_was_removed() {
        use crate::commands::live::{prune_line, removal_line};
        let id = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            removal_line("image", &id, &["base".into()], true),
            "Removed image base [aaaaaaaaaaaa]"
        );
        assert_eq!(
            removal_line("snapshot", &id, &[], true),
            "Removed snapshot [aaaaaaaaaaaa]"
        );
        assert_eq!(
            removal_line("image", &id, &["base".into()], false),
            "Removed name base [aaaaaaaaaaaa]; the image keeps its other names"
        );
        assert_eq!(
            prune_line(&libvm::ImagePruneReport {
                images_removed: 1,
                bytes_removed: 0,
            }),
            format!(
                "Removed 1 image; reclaimed {} of unreferenced data",
                crate::ui::human_bytes(Some(0))
            )
        );
        assert_eq!(
            prune_line(&libvm::ImagePruneReport {
                images_removed: 0,
                bytes_removed: 1024
            }),
            format!(
                "Removed 0 images; reclaimed {} of unreferenced data",
                crate::ui::human_bytes(Some(1024))
            )
        );
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
        let snapshot = snapshot_info(Some("snap"));
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
    fn snapshot_without_memory_inspection_omits_unavailable_source_details() {
        let mut snapshot = snapshot_info(None);
        snapshot.memory = libvm::SnapshotMemory::None;
        snapshot.provenance.clear();
        let rows = crate::commands::live::snapshot_detail_rows(&snapshot);
        assert!(rows.contains(&("Memory".into(), "no".into())));
        assert!(!rows.iter().any(|(label, _)| label == "Source machine"));
    }

    #[test]
    fn remote_inspection_uses_human_labels_for_all_available_metadata() {
        let snapshot = snapshot_info(None);
        let inspection = libvm::ArtifactInspection {
            repository: "registry.example/team/web".into(),
            index_digest: snapshot.record_digest,
            content: libvm::ArtifactContent::Snapshot(snapshot.id),
            root: libvm::ArtifactRootFamily::OpaqueRaw,
            guest_architecture: libvm::GuestArchitecture::Amd64,
            memory: true,
        };
        let rows = crate::commands::live::artifact_detail_rows(&inspection);
        assert!(rows.contains(&("ID".into(), snapshot.id.to_string())));
        assert!(rows.contains(&("Kind".into(), "snapshot".into())));
        assert!(rows.contains(&("Repository".into(), "registry.example/team/web".into())));
        assert!(rows.contains(&("Guest architecture".into(), "amd64".into())));
        assert!(rows.contains(&("Root".into(), "raw".into())));
        assert!(rows.contains(&("Memory".into(), "yes".into())));
        assert!(!rows.iter().any(|(label, _)| {
            ["Created", "Purpose", "Backend", "Live restore"].contains(&label.as_str())
        }));
        assert!(!rows
            .iter()
            .any(|(label, _)| label.contains('.') || label.contains('[')));
        let image = libvm::ArtifactInspection {
            content: libvm::ArtifactContent::Image(stored_image(&[]).id),
            root: libvm::ArtifactRootFamily::LinuxOverlay,
            memory: false,
            ..inspection
        };
        let rows = crate::commands::live::artifact_detail_rows(&image);
        assert!(rows.contains(&("Kind".into(), "image".into())));
        assert!(rows.contains(&("Root".into(), "layered".into())));
        assert!(rows.contains(&("Memory".into(), "no".into())));
    }

    #[test]
    fn snapshot_verify_parses_name_identity_and_json_format() {
        use crate::commands::live::SnapshotCommand;
        use crate::ui::OutputFormat;
        let digest = format!("sha256:{}", "a".repeat(64));
        for reference in ["web", "aaaaaa", digest.as_str()] {
            for args in [
                vec!["silo", "snapshot", "verify", reference],
                vec!["silo", "snapshot", "verify", reference, "--format", "json"],
                vec!["silo", "snapshot", "--format", "json", "verify", reference],
            ] {
                let cli = Cli::try_parse_from(&args).unwrap();
                let Command::Snapshot(snapshot) = cli.command else {
                    panic!("expected snapshot command");
                };
                assert!(!snapshot.includes_memory());
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
            vec!["silo", "snapshot", "verify", "web", "extra"],
            vec!["silo", "snapshot", "verify", "web", "--live"],
            vec!["silo", "snapshot", "verify", "web", "--memory"],
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
    fn snapshot_inspection_json_exposes_bounded_stream_roots() {
        let info = snapshot_info(None);
        let json = serde_json::to_value(&info).unwrap();
        let stream = &json["streams"][0];
        assert_eq!(stream["stream"], info.streams[0].stream.to_string());
        assert_eq!(stream["map"], info.streams[0].map.to_string());
        assert_eq!(stream["length"], 3 * 65_536);
        assert_eq!(stream["chunkSize"], 65_536);
        assert!(stream.get("role").is_some());
        assert!(stream.get("chunks").is_none());
        assert!(stream.get("mapPages").is_none());
        let rows = crate::commands::live::snapshot_detail_rows(&info);
        assert!(rows.contains(&("RAM identity chunk".into(), "65536 bytes".into())));
        assert!(rows.contains(&("RAM map root".into(), info.streams[0].map.to_string())));
    }

    #[test]
    fn snapshot_verify_chunk_failures_render_role_range_and_identities() {
        use crate::commands::live::{
            verification_error_json, verification_error_message, VERIFICATION_GUIDANCE,
        };
        use libvm::{SnapshotVerificationError, SnapshotVerificationRole};
        use vm_spec::stream_map::Chunk;
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
            let chunk_size = if matches!(role, SnapshotVerificationRole::Ram) {
                65_536
            } else {
                8_388_608
            };
            let start = 2 * chunk_size;
            let end = 3 * chunk_size;
            let failure = SnapshotVerificationError::ChunkMismatch {
                role,
                stream,
                chunk_size,
                index: 2,
                start,
                end,
                expected: Box::new(Chunk::Data(expected)),
                actual: Box::new(Chunk::Data(actual)),
            };
            let text = verification_error_message(&failure);
            assert_eq!(
                text,
                format!("{label} stream {stream} data chunk 2 ({chunk_size} bytes) bytes {start}..{end}: expected {expected}, actual {actual}\n{VERIFICATION_GUIDANCE}")
            );
            assert_eq!(
                verification_error_json(&failure),
                serde_json::json!({
                    "error": {
                        "kind": "chunkMismatch", "role": label, "stream": stream,
                        "index": 2, "start": start, "end": end, "chunkSize": chunk_size,
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
                chunk_size: 65_536,
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
    fn snapshot_verify_map_failures_do_not_invent_data_chunk_mismatches() {
        use crate::commands::live::{verification_error_json, verification_error_message};
        for failure in [
            libvm::SnapshotStructuralFailure::Missing,
            libvm::SnapshotStructuralFailure::Invalid {
                message: "node digest mismatch".into(),
            },
        ] {
            let error = libvm::SnapshotVerificationError::MapNode(Box::new(
                libvm::SnapshotMapNodeFailure {
                    role: libvm::SnapshotVerificationRole::Ram,
                    stream: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
                    node: libvm::ObjectDigest::of_bytes(b"node"),
                    height: 1,
                    first_index: 64,
                    end_index: 128,
                    start: 4_194_304,
                    end: 8_388_608,
                    failure,
                },
            ));
            let text = verification_error_message(&error);
            assert!(text.contains("RAM stream"));
            assert!(text.contains("map node"));
            assert!(text.contains("height 1 chunks 64..128 bytes 4194304..8388608"));
            assert!(!text.contains("data chunk"));
            let json = verification_error_json(&error);
            assert_eq!(json["error"]["kind"], "mapNode");
            assert_eq!(json["error"]["firstIndex"], 64);
            assert_eq!(json["error"]["endIndex"], 128);
            assert!(json["error"].get("index").is_none());
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
    #[test]
    fn busy_fork_and_existing_name_are_definitive_rejections() {
        use crate::commands::live::fork_rejected_before_acceptance;
        assert!(fork_rejected_before_acceptance(
            &libvm::LibVmError::MachineCaptureBusy {
                reference: "base".into()
            }
            .into()
        ));
        assert!(fork_rejected_before_acceptance(
            &libvm::LibVmError::MachineAlreadyExists {
                name: "base".into()
            }
            .into()
        ));
    }

    #[tokio::test]
    async fn restore_rejects_invalid_name_before_opening_context() {
        let cli = Cli::try_parse_from(["silo", "restore", "nonexistent", "--name", "wr-anon1.8g"])
            .unwrap();
        let Command::Restore(command) = cli.command else {
            panic!("restore command")
        };
        let mut context =
            crate::context::Context::new(0, silo_vm_control::transport::Admission::Ready);
        let error = command.run(&mut context).await.unwrap_err();
        assert!(
            matches!(error.downcast_ref::<libvm::LibVmError>(), Some(libvm::LibVmError::InvalidMachineName { name, .. }) if name == "wr-anon1.8g")
        );
    }

    #[test]
    fn snapshot_lists_sort_by_newest_then_name() {
        use crate::commands::live::sort_snapshots;
        let mut old = snapshot_info(Some("old"));
        old.created_at = 10;
        let mut newest_z = snapshot_info(Some("z"));
        newest_z.created_at = 20;
        let mut newest_a = snapshot_info(Some("a"));
        newest_a.created_at = 20;
        let mut snapshots = vec![old, newest_z, newest_a];
        sort_snapshots(&mut snapshots);
        assert_eq!(
            snapshots
                .iter()
                .map(|info| info.names[0].as_str())
                .collect::<Vec<_>>(),
            ["a", "z", "old"]
        );
    }

    #[test]
    fn capture_contact_diagnostics_distinguish_stopped_from_lost_contact() {
        use crate::commands::live::{
            capture_failure_observed, CaptureAction, CaptureContactFailure,
        };
        for status in [
            libvm::MachineStatus::Running {
                ready: true,
                guest_ready: true,
                message: None,
            },
            libvm::MachineStatus::Paused { message: None },
            libvm::MachineStatus::Capturing { message: None },
            libvm::MachineStatus::Stopped,
            libvm::MachineStatus::Error {
                message: Some("worker exited".into()),
            },
        ] {
            let error = capture_failure_observed(
                "id",
                CaptureAction::Snapshot,
                libvm::LibVmError::MonitorConnection {
                    reference: "id".into(),
                    message: "internal transport path".into(),
                }
                .into(),
                Some(("base".into(), status.clone())),
            );
            let failure = error.downcast_ref::<CaptureContactFailure>().unwrap();
            assert_eq!(failure.name, "base");
            assert_eq!(failure.stopped, !status.is_active());
            assert!(!error.to_string().contains("internal transport path"));
        }
        let error = capture_failure_observed(
            "id",
            CaptureAction::Fork,
            libvm::LibVmError::LiveObservation {
                reference: "id".into(),
                message: "connection refused".into(),
            }
            .into(),
            Some(("base".into(), libvm::MachineStatus::Stopped)),
        );
        assert!(error
            .downcast_ref::<CaptureContactFailure>()
            .is_some_and(|failure| failure.stopped));
        let error = capture_failure_observed(
            "base",
            CaptureAction::Snapshot,
            libvm::LibVmError::LiveCapture {
                capture_id: OPERATION.into(),
                message: "bad disk".into(),
            }
            .into(),
            Some((
                "base".into(),
                libvm::MachineStatus::Running {
                    ready: true,
                    guest_ready: true,
                    message: None,
                },
            )),
        );
        assert!(matches!(
            error.downcast_ref::<libvm::LibVmError>(),
            Some(libvm::LibVmError::LiveCapture { .. })
        ));
        let stopped = CaptureContactFailure {
            name: "base".into(),
            action: CaptureAction::Snapshot,
            stopped: true,
        };
        assert_eq!(stopped.to_string(), "machine base stopped unexpectedly during the snapshot; start it again with `silo start base`");
        let running = CaptureContactFailure {
            name: "base".into(),
            action: CaptureAction::Fork,
            stopped: false,
        };
        assert_eq!(
            running.to_string(),
            "lost contact with machine base during the fork; check `silo list` before trying again"
        );
    }
}

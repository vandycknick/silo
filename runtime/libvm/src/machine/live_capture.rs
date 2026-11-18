//! Live execution capture orchestration (ADR 0021 `Capture`).
//!
//! ```text
//!  admission (read-only)        exact Capture capability, state x resumePolicy
//!        |
//!  machine lock ── fresh exact observation ── SnapshotStore::reserve_capture
//!        |          (charges, pins, plan)     bind_capture_boot
//!        |                                    durable Capture intent (same ID)
//!  unlock ── Capture RPC ── GetOperation ... CaptureSealed
//!                                  |
//!                 publish_capture (independent of continuation)
//!                                  |
//!            continuation terminal ── record source ── ReleaseCapture
//! ```
//!
//! Capture success, publication and source continuation are independent
//! facts. A missing continuation never makes libvm send Resume: while the run
//! lives GetOperation is authoritative; after it ends the outcome is unknown.
//! An identity-pending cut is not a seal. If the exact source run has positively
//! ended, reconciliation completes retained clone identities without VM effects.
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vm_spec::capture::{
    CaptureConfiguration, CaptureContinuation, CaptureCutRecord, CaptureDiskCut, CaptureEvidence,
    CaptureInventoryEntry, CapturePauseAuthority, CapturePauseDisposition, CapturePlan,
    CaptureReleaseDisposition, CaptureRole, CaptureSourceRecord, Sha256Digest, CAPTURES_DIRECTORY,
    CAPTURE_CUT_FILE, CAPTURE_CUT_TEMPORARY_FILE, CAPTURE_EVIDENCE_FILE,
    CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_SOURCE_FILE, MAX_CAPTURE_RECORD_BYTES,
};
use vm_spec::lifecycle::{
    CaptureCommand, CaptureOutcome, CapturePolicy, CaptureResumePolicy, Diagnostic,
    GetOperationOutcome, LiveCommand, LiveCommandKind, LiveCommandResult, LiveId,
    LiveRejectionReason, OperationKind, OperationObservation, OperationOutcome, PauseOwner,
    ReleaseCaptureCommand, ReleaseCaptureOutcome, VmLifecycleState,
};
use vm_spec::live::LiveOperation;

use crate::machine::live::{require_live_operation, MachineLiveObservation};
use crate::machine::live_operations::{
    envelope, report_progress, require_same_observation, result_error, LiveOperationProgress,
    LiveOperationProgressSender,
};
use crate::machine::{Machine, MachineRef};
use crate::paths::OwnedDirectory;
use crate::store::live_store::LiveCommandIntent;
use crate::store::models::MachineId;
use crate::store::snapshot_store::{
    CaptureRecord, CaptureReservationRequest, CaptureSourceOutcome, CaptureState, SnapshotInfo,
    SnapshotRef, SnapshotStore,
};
use crate::{LibVmError, Runtime};

/// Bound on one CLI wait for monitor progress. Expiry is not cancellation:
/// the operation, reservation, staging and journal are retained.
const CAPTURE_WAIT: Duration = Duration::from_secs(600);
const CAPTURE_POLL: Duration = Duration::from_millis(50);
/// Bound for reading the launched `config.json` back for the capture plan.
const MAX_LAUNCH_SPEC_BYTES: usize = 4 << 20;

/// Caller choices for one memory capture of a running machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSnapshotOptions {
    /// Optional local name for the published snapshot.
    pub name: Option<String>,
    /// Resume only a pause acquired by this capture. A user-paused source
    /// resolves to `preserve` and borrows the pause without ever resuming it.
    pub resume_policy: CaptureResumePolicy,
    /// Prefer incremental capture when admitted; otherwise use full capture.
    pub policy: CapturePolicy,
    pub dirty_crossover_percent: u8,
}

impl Default for LiveSnapshotOptions {
    fn default() -> Self {
        Self {
            name: None,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            policy: CapturePolicy::Incremental,
            dirty_crossover_percent: 60,
        }
    }
}

impl LiveSnapshotOptions {
    pub fn validate(&self) -> Result<(), LibVmError> {
        if !(1..=60).contains(&self.dirty_crossover_percent) {
            return Err(protocol("dirty crossover percent must be between 1 and 60"));
        }
        Ok(())
    }
}

/// Resolve the preference before persisting a plan. Incremental availability
/// must never prevent a capture that the full-capture capability admits.
pub(crate) fn resolve_policy(
    policy: CapturePolicy,
    observation: &MachineLiveObservation,
) -> CapturePolicy {
    if policy == CapturePolicy::Incremental
        && !matches!(
            observation.report().live.incremental.availability,
            vm_spec::live::LiveAvailability::Supported
        )
    {
        CapturePolicy::Full
    } else {
        policy
    }
}

/// Resolve source continuation before recording immutable capture inputs.
/// Admission separately verifies that a paused source has user-owned authority.
pub(crate) fn resolve_resume_policy(
    policy: CaptureResumePolicy,
    observation: &MachineLiveObservation,
) -> Result<CaptureResumePolicy, LibVmError> {
    Ok(if observation.state()? == VmLifecycleState::Paused {
        CaptureResumePolicy::Preserve
    } else {
        policy
    })
}

/// Source continuation as libvm knows it. `Unknown` means the run ended
/// without a continuation record; it is never resolved by resuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LiveCaptureSource {
    Resumed,
    Preserved,
    ResumeFailed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotIdentityReason {
    UnknownAfterFork,
}

/// Capture identity and outcome of a published snapshot with memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveCaptureSummary {
    /// Equals the Capture request ID and the monitor operation ID.
    pub capture_id: LiveId,
    pub machine_id: LiveId,
    pub run_id: LiveId,
    pub resume_policy: CaptureResumePolicy,
    pub memory: vm_spec::capture::CaptureMemoryEvidence,
    pub first_snapshot_full_identity_reason: Option<SnapshotIdentityReason>,
    pub pause: CapturePauseDisposition,
    pub source_outcome: LiveCaptureSource,
    pub source_error: Option<Diagnostic>,
    /// The monitor released result ownership. A native accepted baseline may
    /// still map staging RAM; release never deletes staging.
    pub released: bool,
    /// Staging directory relative to the Silo home; diagnostic, never
    /// restore authority.
    pub staging: PathBuf,
}

/// A published snapshot with memory and its capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveSnapshot {
    pub snapshot: SnapshotInfo,
    pub capture: LiveCaptureSummary,
    pub naming_outcome: Option<crate::CaptureNamingOutcome>,
}

impl LiveSnapshot {
    /// Naming failure is reported only after capture settlement, not as
    /// publication uncertainty. The snapshot is kept without the name.
    pub fn require_requested_name(&self) -> Result<(), LibVmError> {
        if let Some(crate::CaptureNamingOutcome::NameConflict { name }) = &self.naming_outcome {
            return Err(LibVmError::CaptureNameConflict {
                name: name.clone(),
                snapshot: self.snapshot.id,
            });
        }
        Ok(())
    }
}

/// Durable stage of a retained capture, independent of the monitor's
/// operation status and the source continuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachineCaptureStage {
    /// Reserved and submitted; no coherent record has been verified yet.
    Reserved,
    Sealed,
    /// The snapshot is published; continuation or release is outstanding.
    Published,
}

/// A retained, not yet released capture of a machine, for inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineCapture {
    pub capture_id: LiveId,
    pub run_id: LiveId,
    pub resume_policy: CaptureResumePolicy,
    pub pause: CapturePauseDisposition,
    pub stage: MachineCaptureStage,
    pub snapshot_id: Option<crate::storage::identity::SnapshotId>,
    /// `None` until the continuation outcome is recorded.
    pub source_outcome: Option<LiveCaptureSource>,
    pub staging: PathBuf,
}

/// One reconciliation step's result for a retained capture.
#[derive(Debug)]
pub(crate) enum CaptureProgress {
    /// Still owned by the monitor or awaiting continuation; nothing guessed.
    Pending(&'static str),
    Finished(Box<LiveSnapshot>),
    Local,
    /// No admissible seal. The reservation is abandoned; diagnostics remain.
    Abandoned(String),
}

enum RunLiveness {
    Alive(Box<MachineLiveObservation>),
    Ended,
    /// The exact run could not be observed and was not positively ended.
    Uncertain,
}

fn protocol(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveProtocol {
        message: message.into(),
    }
}

fn capture_error(capture: &LiveId, message: impl Into<String>) -> LibVmError {
    LibVmError::LiveCapture {
        capture_id: capture.to_string(),
        message: message.into(),
    }
}

fn live_id(value: Uuid) -> Result<LiveId, LibVmError> {
    LiveId::parse(&value.to_string()).map_err(protocol)
}

fn snapshot_store(runtime: &Runtime) -> Result<SnapshotStore, LibVmError> {
    Ok(SnapshotStore::from_store(Arc::new(runtime.native_store()?)))
}

/// Pure admission of a NEW capture against one exact observation. Runs before
/// any lock, reservation, journal row or monitor command.
pub(crate) fn admission(
    observation: &MachineLiveObservation,
    resume_policy: CaptureResumePolicy,
) -> Result<(CapturePauseAuthority, CaptureResumePolicy), LibVmError> {
    require_live_operation(observation, LiveOperation::Capture)?;
    let state = observation.state()?;
    let pause = match state {
        VmLifecycleState::Running => CapturePauseAuthority::Acquire,
        VmLifecycleState::Paused => {
            let lifecycle = observation.lifecycle()?;
            let current = match lifecycle.current_pause {
                Some(current) => current,
                None => {
                    return Err(crate::machine::live_operations::missing_pause_authority(
                        observation,
                        &lifecycle,
                        Ok(None),
                        "paused machine has no current pause authority",
                    ));
                }
            };
            if current.token.owner != PauseOwner::User {
                return Err(protocol(
                    "only a user-owned pause can be borrowed by a capture",
                ));
            }
            CapturePauseAuthority::Borrow {
                pause_operation_id: current.operation_id,
                token: current.token,
            }
        }
        state => {
            return Err(protocol(format!(
                "capture is not admitted in state {state}"
            )))
        }
    };
    Ok((pause, resolve_resume_policy(resume_policy, observation)?))
}

impl Machine {
    /// Capture this exact running or user-paused run with its memory, publish
    /// the sealed snapshot through the snapshot store, settle the source
    /// continuation and release the monitor's result ownership.
    pub(crate) async fn snapshot_memory(
        &self,
        observation: &MachineLiveObservation,
        options: LiveSnapshotOptions,
        progress: Option<LiveOperationProgressSender>,
    ) -> Result<LiveSnapshot, LibVmError> {
        let capture_id = Uuid::new_v4();
        report_progress(progress.as_ref(), LiveOperationProgress::Admitting);
        match self
            .submit_capture(observation, capture_id, options)
            .await?
        {
            LiveCommandResult::Capture(CaptureOutcome::Accepted { receipt })
                if receipt.operation_id.as_str() == capture_id.to_string()
                    && receipt.kind == OperationKind::Capture => {}
            result => return Err(result_error(&result)),
        }
        self.complete_capture_with_progress(capture_id, progress.as_ref())
            .await
    }

    /// Reserve, journal and submit one capture under a caller-chosen identity
    /// without waiting for the seal. An exact replay of a retained identity
    /// returns the original result; the plan is never rebuilt.
    pub async fn submit_capture(
        &self,
        observation: &MachineLiveObservation,
        request_id: Uuid,
        mut options: LiveSnapshotOptions,
    ) -> Result<LiveCommandResult, LibVmError> {
        options.validate()?;
        if request_id.is_nil() {
            return Err(protocol("nil capture identity"));
        }
        self.require_observation(observation)?;
        options.policy = resolve_policy(options.policy, observation);
        let runtime = self.runtime();
        let store = runtime.native_store()?;
        let run = Uuid::parse_str(&observation.report().run_id)
            .map_err(|error| protocol(error.to_string()))?;
        if let Some(existing) = store
            .live_command_record(self.machine_id(), run, request_id)
            .await?
        {
            let LiveCommand::Capture(command) = &existing.intent.command else {
                return conflict(observation);
            };
            let reservation = snapshot_store(runtime)?
                .capture_reservation(request_id)
                .await?;
            let resume_policy =
                if matches!(command.plan.pause, CapturePauseAuthority::Borrow { .. }) {
                    CaptureResumePolicy::Preserve
                } else {
                    options.resume_policy
                };
            if command.plan.resume_policy != resume_policy
                || command.plan.policy != options.policy
                || command.plan.dirty_crossover_percent != options.dirty_crossover_percent
                || reservation.is_none_or(|record| record.name != options.name)
            {
                return conflict(observation);
            }
            return self
                .live_command(observation, existing.intent.command)
                .await;
        }
        let (pause, resume_policy) = admission(observation, options.resume_policy)?;
        options.resume_policy = resume_policy;
        let (reservation, intent) = {
            let (_lock, config) = runtime.lock_machine_config(self.machine_id()).await?;
            let fresh = runtime.observe_live(&MachineRef::id(config.id)).await?;
            require_same_observation(observation, &fresh)?;
            options.policy = resolve_policy(options.policy, &fresh);
            let (fresh_pause, fresh_resume_policy) = admission(&fresh, options.resume_policy)?;
            if fresh_pause != pause || fresh_resume_policy != options.resume_policy {
                return Err(protocol("pause authority changed since capture admission"));
            }
            if let Some(operation) = store.fork_for_capture(request_id).await? {
                let fork = store
                    .fork_result(operation)
                    .await?
                    .ok_or_else(|| protocol("fork capture owner disappeared"))?;
                if fork.cancellation_requested
                    || !matches!(fork.capture, crate::ForkCaptureOutcome::Pending)
                {
                    return Err(capture_error(
                        &live_id(request_id)?,
                        "fork no longer authorizes a new capture submission",
                    ));
                }
            }
            let configuration = launched_configuration(runtime, config.id)?;
            let snapshots = snapshot_store(runtime)?;
            let reservation = snapshots
                .reserve_capture(&CaptureReservationRequest {
                    machine_id: config.id,
                    run_id: run,
                    capture_id: request_id,
                    configuration,
                    name: options.name.clone(),
                    policy: options.policy,
                    dirty_crossover_percent: options.dirty_crossover_percent,
                    resume_policy: options.resume_policy,
                    pause,
                })
                .await?;
            if reservation.record.state != CaptureState::Reserved {
                return Err(capture_error(
                    &live_id(request_id)?,
                    "capture reservation is no longer eligible for submission",
                ));
            }
            let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir())?;
            let boot = crate::runtime::boot_assets::capture_boot(
                &reservation.record.storage,
                &config.spec,
                &config.guest.agent,
                runtime.captured_boot_context(&pool, &store, request_id),
                crate::runtime::boot_assets::CaptureLane::Live,
            )
            .await?;
            snapshots.bind_capture_boot(request_id, boot).await?;
            let command = LiveCommand::Capture(Box::new(CaptureCommand {
                envelope: envelope(&fresh, request_id)?,
                plan: reservation.record.plan.clone(),
            }));
            if let LiveCommand::Capture(capture) = &command {
                capture.validate_plan().map_err(protocol)?;
            }
            let intent = LiveCommandIntent {
                report: fresh.report().clone(),
                command,
            };
            let prepared = store
                .prepare_live_command(config.id, run, request_id, &intent)
                .await?;
            if let Some(result) = prepared.result {
                return Ok(result);
            }
            (reservation, prepared.intent)
        };
        // The reservation lease stays held until the monitor acknowledged the
        // plan; afterwards the run's inherited launch lease pins the capture.
        let result = self.send_prepared(intent).await;
        drop(reservation);
        result
    }

    /// Drive one retained capture to publication, continuation and release.
    /// Only the exact retained identity is followed; nothing is resubmitted
    /// under a new identity and nothing resumes the source.
    pub async fn complete_capture(&self, capture_id: Uuid) -> Result<LiveSnapshot, LibVmError> {
        self.complete_capture_with_progress(capture_id, None).await
    }

    async fn complete_capture_with_progress(
        &self,
        capture_id: Uuid,
        progress: Option<&LiveOperationProgressSender>,
    ) -> Result<LiveSnapshot, LibVmError> {
        let capture = live_id(capture_id)?;
        let deadline = tokio::time::Instant::now() + CAPTURE_WAIT;
        loop {
            // A snapshot capture never retains a local cut to open.
            let stage = match advance(
                self.runtime(),
                self.machine_id(),
                capture_id,
                progress,
                crate::storage::pool::PublicationLockPolicy::Wait,
            )
            .await?
            {
                CaptureProgress::Finished(snapshot) => {
                    report_progress(progress, LiveOperationProgress::Done);
                    return Ok(*snapshot);
                }
                CaptureProgress::Local => {
                    return Err(capture_error(
                        &capture,
                        "capture belongs to a live fork, not a snapshot",
                    ))
                }
                CaptureProgress::Abandoned(reason) => return Err(capture_error(&capture, reason)),
                CaptureProgress::Pending(stage) => stage,
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(capture_error(
                    &capture,
                    format!(
                        "still {stage}; operation, reservation and staging retained, not cancelled"
                    ),
                ));
            }
            tokio::time::sleep(CAPTURE_POLL).await;
        }
    }

    fn require_observation(&self, observation: &MachineLiveObservation) -> Result<(), LibVmError> {
        if observation.machine_id() != self.machine_id() {
            return Err(LibVmError::LiveObservation {
                reference: self.id(),
                message: "observation belongs to another machine".into(),
            });
        }
        Ok(())
    }
}

fn conflict(observation: &MachineLiveObservation) -> Result<LiveCommandResult, LibVmError> {
    Ok(LiveCommandResult::rejected(
        LiveCommandKind::Capture,
        vm_spec::lifecycle::LiveRejection::new(
            LiveRejectionReason::RequestConflict,
            observation.state()?,
            "capture identity conflicts with persisted inputs",
        ),
    ))
}

/// The exact `config.json` handed to the monitor for this run. The monitor
/// recomputes the same projection from the spec it loaded.
fn launched_configuration(
    runtime: &Runtime,
    machine: MachineId,
) -> Result<CaptureConfiguration, LibVmError> {
    let paths = runtime.machine_paths(machine);
    let directory = OwnedDirectory::open_existing_root(paths.machine_data_dir())?
        .ok_or_else(|| protocol("machine data directory is missing"))?;
    let name = paths
        .vm_spec_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| protocol("launch spec has no file name"))?;
    let bytes = read_bounded(&directory, &name, MAX_LAUNCH_SPEC_BYTES)?
        .ok_or_else(|| protocol("launched machine configuration is missing"))?;
    let spec: vm_spec::VmSpec =
        serde_json::from_slice(&bytes).map_err(|error| protocol(error.to_string()))?;
    CaptureConfiguration::from_spec(&spec).map_err(protocol)
}

fn read_bounded(
    directory: &OwnedDirectory,
    name: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, LibVmError> {
    let Some(file) = directory.open_file(name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(protocol(format!("{name} exceeds its bound")));
    }
    Ok(Some(bytes))
}

fn staging_relative(runtime: &Runtime, record: &CaptureRecord) -> Result<PathBuf, LibVmError> {
    let paths = runtime.machine_paths(record.machine_id);
    let relative = paths
        .machine_data_dir()
        .strip_prefix(runtime.local_home())
        .map_err(|_| protocol("machine data directory is outside the Silo home"))?;
    Ok(relative
        .join(CAPTURES_DIRECTORY)
        .join(record.plan.capture_id.as_str()))
}

fn staging_absolute(runtime: &Runtime, record: &CaptureRecord) -> PathBuf {
    runtime
        .machine_paths(record.machine_id)
        .machine_data_dir()
        .join(record.plan.directory())
}

/// Open the fixed capture directory beneath held owned directories, never an
/// arbitrary evidence-supplied path.
fn open_staging(
    runtime: &Runtime,
    record: &CaptureRecord,
) -> Result<Option<OwnedDirectory>, LibVmError> {
    let Some(data) = OwnedDirectory::open_existing_root(
        runtime.machine_paths(record.machine_id).machine_data_dir(),
    )?
    else {
        return Ok(None);
    };
    let Some(captures) = data.open_dir(CAPTURES_DIRECTORY)? else {
        return Ok(None);
    };
    captures.open_dir(record.plan.capture_id.as_str())
}

fn request_digest(record: &CaptureRecord) -> Result<Sha256Digest, LibVmError> {
    Ok(Sha256Digest::of_bytes(
        &record.plan.canonical_bytes().map_err(protocol)?,
    ))
}

enum CoherentRecord {
    Identified(Box<CaptureEvidence>),
    OwnedLocalCut,
}

/// A coherent, plan-correlated seal on disk. Storage re-verifies every byte
/// before publication; this only decides publish versus abandon.
fn coherent_record(
    runtime: &Runtime,
    record: &CaptureRecord,
) -> Result<Option<CoherentRecord>, LibVmError> {
    let Some(staging) = open_staging(runtime, record)? else {
        return Ok(None);
    };
    let Some(bytes) = read_bounded(&staging, CAPTURE_EVIDENCE_FILE, MAX_CAPTURE_RECORD_BYTES)?
    else {
        return Ok(None);
    };
    if record.plan.identity_policy == vm_spec::capture::CaptureIdentityPolicy::None {
        let cut = vm_spec::capture::OwnedLocalCut::decode(&bytes).map_err(protocol)?;
        crate::store::capture::validate_owned_cut(&staging, &record.plan, &cut)?;
        return Ok(Some(CoherentRecord::OwnedLocalCut));
    }
    let evidence = match CaptureEvidence::decode(&bytes) {
        Ok(evidence) => evidence,
        Err(error) => {
            tracing::warn!(capture = %record.plan.capture_id, %error, "capture evidence is not admissible");
            return Ok(None);
        }
    };
    if !evidence.is_sealed() {
        return Ok(None);
    }
    evidence
        .validate_against_plan(&record.plan, &request_digest(record)?)
        .map_err(|error| capture_error(&record.plan.capture_id, error))?;
    Ok(Some(CoherentRecord::Identified(Box::new(evidence))))
}

/// Only the sole-reaper's positive end observation permits a manager to take
/// over identity completion. A live monitor remains the only capture writer.
async fn recover_cut(runtime: &Runtime, record: &CaptureRecord) -> Result<(), LibVmError> {
    if record.plan.identity_policy == vm_spec::capture::CaptureIdentityPolicy::None {
        // An incomplete owned cut cannot be recreated by hashing or recapture.
        return Ok(());
    }
    let _lock = runtime.lock_machine_config(record.machine_id).await?;
    let Some(staging) = open_staging(runtime, record)? else {
        return Ok(());
    };
    let plan = record.plan.clone();
    tokio::task::spawn_blocking(move || complete_cut_identity(&staging, &plan))
        .await
        .map_err(|error| protocol(format!("capture identity recovery task failed: {error}")))??;
    Ok(())
}

fn cut_disk_fingerprint(file: &std::fs::File, cut: &CaptureDiskCut) -> Result<(), LibVmError> {
    let metadata = file.metadata()?;
    if metadata.dev() != cut.device
        || metadata.ino() != cut.inode
        || metadata.len() != cut.length
        || metadata.mode() != cut.mode
        || metadata.ctime() != cut.changed_seconds
        || metadata.ctime_nsec() != cut.changed_nanoseconds
        || metadata.nlink() != 1
    {
        return Err(protocol("pending capture disk changed after the cut"));
    }
    Ok(())
}

/// Replay uses retained immutable inodes only, never a source VM or pause.
/// Interrupted map writes are regenerated; the final seal is linked last.
fn complete_cut_identity(staging: &OwnedDirectory, plan: &CapturePlan) -> Result<(), LibVmError> {
    if staging.open_file(CAPTURE_EVIDENCE_FILE)?.is_some() {
        return Ok(());
    }
    let Some(bytes) = read_bounded(staging, CAPTURE_CUT_FILE, MAX_CAPTURE_RECORD_BYTES)? else {
        return Ok(());
    };
    let descriptor = staging
        .open_file(CAPTURE_CUT_FILE)?
        .ok_or_else(|| protocol("capture cut disappeared"))?;
    let metadata = descriptor.metadata()?;
    if metadata.nlink() == 2 {
        let temporary = staging
            .open_file(CAPTURE_CUT_TEMPORARY_FILE)?
            .ok_or_else(|| protocol("capture cut has an unowned extra link"))?;
        let temporary_metadata = temporary.metadata()?;
        if temporary_metadata.dev() != metadata.dev()
            || temporary_metadata.ino() != metadata.ino()
            || temporary_metadata.nlink() != 2
        {
            return Err(protocol(
                "capture cut temporary does not own its extra link",
            ));
        }
        nix::unistd::unlinkat(
            staging.fd(),
            CAPTURE_CUT_TEMPORARY_FILE,
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(std::io::Error::from)?;
    } else if metadata.nlink() != 1 {
        return Err(protocol("capture cut has extra links"));
    }
    let mut cut = CaptureCutRecord::decode(&bytes).map_err(protocol)?;
    let request = Sha256Digest::of_bytes(&plan.canonical_bytes().map_err(protocol)?);
    cut.validate_against_plan(plan, &request)
        .map_err(protocol)?;
    let disks = staging
        .open_dir("disks")?
        .ok_or_else(|| protocol("cut disks are missing"))?;
    let mut hasher =
        crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK);
    for pending in &cut.disks {
        let file = disks
            .open_file(&pending.name.file_name())?
            .ok_or_else(|| protocol("pending capture disk is missing"))?;
        cut_disk_fingerprint(&file, pending)?;
        let scan = hasher.hash_open_file(&file, pending.length)?;
        cut_disk_fingerprint(&file, pending)?;
        let fresh = disks
            .open_file(&pending.name.file_name())?
            .ok_or_else(|| protocol("pending capture disk disappeared"))?;
        cut_disk_fingerprint(&fresh, pending)?;
        let map_bytes = scan.map.canonical_bytes()?;
        let map_name = format!("{}.root", pending.name.as_str());
        if let Some(existing) = disks.open_file(&map_name)? {
            if existing.metadata()?.nlink() != 1 {
                return Err(protocol("pending capture disk map has extra links"));
            }
        }
        disks.write_file(&map_name, &map_bytes)?;
        crate::store::capture::stage_map_nodes(staging, &scan.map)?;
        cut.evidence
            .disk_stats
            .retain(|stats| stats.name != pending.name);
        cut.evidence
            .disk_stats
            .push(vm_spec::capture::CaptureDiskStats {
                name: pending.name.clone(),
                dirty_chunks: pending.tracking_receipt.as_ref().map_or(
                    pending
                        .length
                        .div_ceil(vm_spec::capture::STREAM_CHUNK_BYTES),
                    |receipt| receipt.dirty_chunks,
                ),
                total_chunks: pending
                    .length
                    .div_ceil(vm_spec::capture::STREAM_CHUNK_BYTES),
                bytes_hashed: scan.stats.logical_bytes_hashed,
                baseline_reused: false,
                full_scan_reason: Some(
                    if plan
                        .disks
                        .iter()
                        .any(|disk| disk.name == pending.name && !disk.tracking_eligible)
                    {
                        vm_spec::capture::DiskFullScanReason::External
                    } else {
                        pending
                            .tracking_receipt
                            .as_ref()
                            .and_then(|receipt| receipt.invalid_reason)
                            .map_or(
                                vm_spec::capture::DiskFullScanReason::MissingBaseline,
                                |reason| vm_spec::capture::DiskFullScanReason::InvalidReceipt {
                                    reason,
                                },
                            )
                    },
                ),
            });
        if let Some(receipt) = &pending.tracking_receipt {
            cut.evidence
                .disk_tracking_receipts
                .retain(|existing| existing.seed.attachment_index != receipt.seed.attachment_index);
            cut.evidence.disk_tracking_receipts.push(receipt.clone());
        }
        cut.evidence.inventory.extend([
            CaptureInventoryEntry {
                role: CaptureRole::Disk(pending.name.clone()),
                length: pending.length,
                sha256: None,
                identity: Some(Sha256Digest::from_bytes(*scan.map.id().as_bytes())),
            },
            CaptureInventoryEntry {
                role: CaptureRole::DiskMap(pending.name.clone()),
                length: map_bytes.len() as u64,
                sha256: Some(Sha256Digest::of_bytes(&map_bytes)),
                identity: None,
            },
        ]);
    }
    let roles = plan.roles();
    cut.evidence
        .inventory
        .sort_by_key(|entry| roles.iter().position(|role| role == &entry.role));
    cut.evidence
        .disk_tracking_receipts
        .sort_by_key(|receipt| receipt.seed.attachment_index);
    cut.evidence
        .disk_stats
        .sort_by_key(|stats| plan.disks.iter().position(|disk| disk.name == stats.name));
    cut.evidence.disk_copies_sealed = true;
    cut.evidence
        .validate_against_plan(plan, &request)
        .map_err(protocol)?;
    let mut charged = 2 * MAX_CAPTURE_RECORD_BYTES as u64;
    for name in [vm_spec::capture::CAPTURE_REQUEST_FILE, CAPTURE_CUT_FILE] {
        let file = staging
            .open_file(name)?
            .ok_or_else(|| protocol("capture control file is missing"))?;
        charged = charged.saturating_add(file.metadata()?.blocks().saturating_mul(512));
    }
    for directory in [staging, &disks] {
        let stat = nix::sys::stat::fstat(directory.fd()).map_err(std::io::Error::from)?;
        let blocks =
            u64::try_from(stat.st_blocks).map_err(|_| protocol("negative staging allocation"))?;
        charged = charged.saturating_add(blocks.saturating_mul(512));
    }
    for entry in &cut.evidence.inventory {
        let file = match &entry.role {
            CaptureRole::Disk(name) => disks.open_file(&name.file_name())?,
            CaptureRole::DiskMap(name) => disks.open_file(&format!("{}.root", name.as_str()))?,
            role => staging.open_file(&role.relative_path())?,
        }
        .ok_or_else(|| protocol("capture output disappeared"))?;
        let clone_charge = matches!(&entry.role, CaptureRole::Disk(name)
            if plan.disks.iter().any(|disk| disk.name == *name && disk.copy == vm_spec::capture::CaptureDiskCopy::Clone));
        charged = charged.saturating_add(if clone_charge {
            vm_spec::capture::CAPTURE_CLONE_RESERVE_BYTES
        } else {
            file.metadata()?.blocks().saturating_mul(512)
        });
    }
    charged = charged
        .checked_add(crate::store::capture::staged_node_bytes(staging)?)
        .ok_or_else(|| protocol("recovered node allocation overflow"))?;
    if charged > plan.reservation.staging_bytes {
        return Err(protocol(
            "recovered capture exceeds its staging reservation",
        ));
    }
    let bytes = cut.evidence.canonical_bytes().map_err(protocol)?;
    if let Some(temporary) = staging.open_file(CAPTURE_EVIDENCE_TEMPORARY_FILE)? {
        if temporary.metadata()?.nlink() != 1 {
            return Err(protocol("capture seal temporary has extra links"));
        }
    }
    staging.write_file(CAPTURE_EVIDENCE_TEMPORARY_FILE, &bytes)?;
    nix::unistd::linkat(
        staging.fd(),
        CAPTURE_EVIDENCE_TEMPORARY_FILE,
        staging.fd(),
        CAPTURE_EVIDENCE_FILE,
        nix::fcntl::AtFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    nix::unistd::unlinkat(
        staging.fd(),
        CAPTURE_EVIDENCE_TEMPORARY_FILE,
        nix::unistd::UnlinkatFlags::NoRemoveDir,
    )
    .map_err(std::io::Error::from)?;
    staging.sync()?;
    Ok(())
}

/// The continuation record, correlated with the coherent record. A malformed or
/// foreign record fails closed for continuation only; the seal stays valid.
fn source_record(
    runtime: &Runtime,
    record: &CaptureRecord,
) -> Result<Option<CaptureSourceRecord>, LibVmError> {
    if record.plan.identity_policy == vm_spec::capture::CaptureIdentityPolicy::None {
        // Owned cuts have no identified continuation record. Their source
        // outcome comes from the monitor, or remains unknown after its run ends.
        // Relocation has already removed the original staging payload paths.
        return Ok(None);
    }
    let Some(CoherentRecord::Identified(evidence)) = coherent_record(runtime, record)? else {
        return Ok(None);
    };
    let Some(staging) = open_staging(runtime, record)? else {
        return Ok(None);
    };
    let Some(bytes) = read_bounded(&staging, CAPTURE_SOURCE_FILE, MAX_CAPTURE_RECORD_BYTES)? else {
        return Ok(None);
    };
    match CaptureSourceRecord::decode(&bytes)
        .and_then(|source| source.validate_against(&evidence).map(|()| source))
    {
        Ok(source) => Ok(Some(source)),
        Err(error) => {
            tracing::warn!(capture = %record.plan.capture_id, %error, "capture continuation record rejected");
            Ok(None)
        }
    }
}

/// Positive run liveness: the exact run answering status, or the sole-reaper
/// reconciled state naming no live generation of that run.
async fn run_liveness(
    runtime: &Runtime,
    machine: MachineId,
    run: Uuid,
) -> Result<RunLiveness, LibVmError> {
    let run = run.to_string();
    let current = |state: &crate::store::models::MachineState| {
        state.run_id.as_deref() == Some(run.as_str())
            && (state.status.is_live() || state.vmm_pid.is_some())
    };
    if !current(&runtime.machine_state(machine).await?) {
        return Ok(RunLiveness::Ended);
    }
    match runtime.observe_live(&MachineRef::id(machine)).await {
        Ok(observation) if observation.report().run_id == run => {
            return Ok(RunLiveness::Alive(Box::new(observation)))
        }
        Ok(_) => return Ok(RunLiveness::Ended),
        Err(error) => {
            tracing::debug!(%machine, %error, "capture run status unavailable; reconciling owner");
        }
    }
    let (_lock, config) = runtime.lock_machine_config(machine).await?;
    runtime.reconcile_machine_runtime_locked(&config).await?;
    Ok(if current(&runtime.machine_state(machine).await?) {
        RunLiveness::Uncertain
    } else {
        RunLiveness::Ended
    })
}

enum MonitorCapture {
    Observed(Box<OperationObservation>),
    NotFound,
}

async fn observe_capture(
    machine: &Machine,
    observation: &MachineLiveObservation,
    capture: &LiveId,
) -> Result<MonitorCapture, LibVmError> {
    match machine
        .observe_operation(observation, capture.clone())
        .await?
    {
        LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) => {
            observation.validate().map_err(protocol)?;
            if observation.operation.operation_id != *capture
                || observation.operation.kind != OperationKind::Capture
                || observation.capture.is_none()
            {
                return Err(protocol("monitor answered for another operation"));
            }
            Ok(MonitorCapture::Observed(Box::new(observation)))
        }
        LiveCommandResult::GetOperation(GetOperationOutcome::Rejected { rejection })
            if rejection.reason == LiveRejectionReason::OperationNotFound =>
        {
            Ok(MonitorCapture::NotFound)
        }
        result => Err(result_error(&result)),
    }
}

/// A monitor that does not know the capture either never received it or
/// refused it. Decide only from the exact durable intent, under the machine
/// lock that serializes `submit_capture`'s reserve-and-journal step.
async fn unsubmitted(
    runtime: &Runtime,
    machine: &Machine,
    observation: Option<&MachineLiveObservation>,
    record: &CaptureRecord,
) -> Result<Option<CaptureProgress>, LibVmError> {
    let store = runtime.native_store()?;
    let (retained, attempted) = {
        let (_lock, config) = runtime.lock_machine_config(record.machine_id).await?;
        let mut retained = store
            .live_command_record(record.machine_id, record.run_id, record.capture_id)
            .await?;
        let current = snapshot_store(runtime)?
            .capture_reservation(record.capture_id)
            .await?
            .ok_or_else(|| {
                protocol("capture reservation disappeared before submission reconciliation")
            })?;
        let attempted = current.dispatch_attempted;
        if !attempted
            && retained
                .as_ref()
                .is_some_and(|retained| retained.result.is_none())
        {
            let pool = crate::storage::pool::StoragePool::open(runtime.local_images_dir())?;
            if let Some(_lease) = pool.try_exclusive_lease(record.capture_id)? {
                let result = LiveCommandResult::rejected(
                    LiveCommandKind::Capture,
                    vm_spec::lifecycle::LiveRejection::new(
                        LiveRejectionReason::InvalidPlan,
                        if matches!(record.plan.pause, CapturePauseAuthority::Borrow { .. }) { vm_spec::lifecycle::VmLifecycleState::Paused } else { vm_spec::lifecycle::VmLifecycleState::Running },
                        "dispatch refusal: producer ended before any send; exact request retired without replay",
                    ),
                );
                let intent = retained
                    .as_ref()
                    .ok_or_else(|| protocol("capture intent disappeared"))?;
                store
                    .complete_live_command(
                        config.id,
                        record.run_id,
                        record.capture_id,
                        &intent.intent.report.monitor_id,
                        &result,
                        None,
                    )
                    .await?;
                snapshot_store(runtime)?
                    .abandon_capture(record.capture_id)
                    .await?;
                if let Some(retained) = &mut retained {
                    retained.result = Some(result);
                }
            }
        }
        if retained.is_none() {
            // Fence a never-submitted reservation while holding the same
            // machine lock as submit_capture's journal-before-send step.
            snapshot_store(runtime)?
                .abandon_capture(record.capture_id)
                .await?;
        }
        (retained, attempted)
    };
    match retained {
        None => Ok(Some(CaptureProgress::Abandoned(
            "capture was reserved but never journaled or submitted".into(),
        ))),
        Some(retained) => match retained.result {
            Some(LiveCommandResult::Capture(CaptureOutcome::Rejected { rejection })) => {
                Ok(Some(CaptureProgress::Abandoned(format!(
                    "capture was refused without an accepted submission: {rejection}"
                ))))
            }
            Some(LiveCommandResult::Capture(CaptureOutcome::Accepted { .. })) => {
                match observation {
                    Some(_) => Err(protocol(
                        "monitor lost an accepted capture operation within its run",
                    )),
                    None => Ok(None),
                }
            }
            Some(_) => Err(protocol(
                "retained capture intent has another command's result",
            )),
            None if !attempted => Ok(Some(CaptureProgress::Pending(
                "capture awaiting its producer's first dispatch",
            ))),
            None => match observation {
                // Exact replay of the original full inputs, never a new plan.
                Some(observation) => {
                    match machine
                        .live_command(observation, retained.intent.command)
                        .await?
                    {
                        LiveCommandResult::Capture(CaptureOutcome::Accepted { .. }) => {
                            Ok(Some(CaptureProgress::Pending("capture submitted")))
                        }
                        LiveCommandResult::Capture(CaptureOutcome::Rejected { rejection }) => {
                            Ok(Some(CaptureProgress::Abandoned(format!(
                                "monitor refused the capture: {rejection}"
                            ))))
                        }
                        result => Err(result_error(&result)),
                    }
                }
                None => Ok(None),
            },
        },
    }
}

async fn retained_release(
    runtime: &Runtime,
    record: &CaptureRecord,
) -> Result<Option<vm_spec::capture::CaptureReleased>, LibVmError> {
    let json = runtime
        .native_store()?
        .capture_release_receipt_json(record.machine_id, record.run_id, &record.plan.capture_id)
        .await?;
    json.map(|json| {
        match serde_json::from_str::<LiveCommandResult>(&json)
            .map_err(|error| protocol(error.to_string()))?
        {
            LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released { released })
                if released.operation_id == record.plan.capture_id =>
            {
                Ok(released)
            }
            _ => Err(protocol(
                "retained capture release contradicts its journal key",
            )),
        }
    })
    .transpose()
}

async fn settle_abandoned_release(
    snapshots: &SnapshotStore,
    record: &CaptureRecord,
    released: &vm_spec::capture::CaptureReleased,
) -> Result<CaptureProgress, LibVmError> {
    let record = snapshots
        .capture_reservation(record.capture_id)
        .await?
        .ok_or_else(|| protocol("released capture reservation disappeared"))?;
    if released.operation_id != record.plan.capture_id
        || released.disposition != CaptureReleaseDisposition::Abandoned
        || record.source_outcome.is_none()
    {
        return Err(protocol(
            "abandoned release lacks its exact terminal source authority",
        ));
    }
    if matches!(record.state, CaptureState::Released { snapshot: None }) {
        return Ok(CaptureProgress::Abandoned(
            "failed capture result ownership was released".into(),
        ));
    }
    snapshots.abandon_capture(record.capture_id).await?;
    snapshots
        .finish_capture_release(record.capture_id, released.baseline_retained)
        .await?;
    Ok(CaptureProgress::Abandoned(
        "failed capture result ownership was released".into(),
    ))
}

async fn release(
    runtime: &Runtime,
    machine: &Machine,
    observation: &MachineLiveObservation,
    record: &CaptureRecord,
    disposition: CaptureReleaseDisposition,
) -> Result<Option<vm_spec::capture::CaptureReleased>, LibVmError> {
    if let Some(released) = retained_release(runtime, record).await? {
        if released.disposition != disposition {
            return Err(protocol(
                "retained release names another disposition for this capture",
            ));
        }
        return Ok(Some(released));
    }
    let store = runtime.native_store()?;
    let run = record.run_id;
    let pending = store
        .pending_live_commands(record.machine_id, run, &observation.report().monitor_id)
        .await?
        .into_iter()
        .find_map(|retained| match retained.intent.command {
            LiveCommand::ReleaseCapture(command)
                if command.operation_id == record.plan.capture_id =>
            {
                Some(LiveCommand::ReleaseCapture(command))
            }
            _ => None,
        });
    let command = match pending {
        Some(LiveCommand::ReleaseCapture(command)) if command.disposition != disposition => {
            return Err(protocol(
                "a retained release names another disposition for this capture",
            ))
        }
        Some(command) => command,
        // GetOperation may observe terminal continuation after the earlier
        // run observation still reported Capturing. Wait for an admissible
        // run projection before creating a new release; exact replays above
        // retain their original identity regardless of the current state.
        None if !observation.state()?.admits(LiveCommandKind::ReleaseCapture) => return Ok(None),
        None => LiveCommand::ReleaseCapture(ReleaseCaptureCommand {
            envelope: envelope(observation, Uuid::new_v4())?,
            operation_id: record.plan.capture_id.clone(),
            disposition,
        }),
    };
    match machine.live_command(observation, command).await? {
        LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released { released })
            if released.operation_id == record.plan.capture_id
                && released.disposition == disposition =>
        {
            Ok(Some(released))
        }
        LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Rejected { rejection })
            if rejection.reason == LiveRejectionReason::ContinuationPending =>
        {
            Ok(None)
        }
        LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Failed { failed }) => {
            Err(capture_error(
                &record.plan.capture_id,
                format!("release failed: {}", failed.cause),
            ))
        }
        result => Err(result_error(&result)),
    }
}

fn validate_capture_success(
    runtime: &Runtime,
    record: &CaptureRecord,
    success: &vm_spec::capture::CaptureSuccess,
) -> Result<(), LibVmError> {
    success.validate().map_err(protocol)?;
    if success.capture_id() != &record.plan.capture_id {
        return Err(protocol("native success names another capture"));
    }
    match (&record.plan.identity_policy, success) {
        (
            vm_spec::capture::CaptureIdentityPolicy::None,
            vm_spec::capture::CaptureSuccess::OwnedLocalCut { cut, cut_token },
        ) => {
            if let CapturePauseAuthority::Borrow { token, .. } = &record.plan.pause {
                if token != cut_token {
                    return Err(protocol(
                        "owned cut success names another borrowed pause generation",
                    ));
                }
            }
            if let Some(bytes) = &record.evidence {
                let expected =
                    vm_spec::capture::OwnedLocalCut::decode(bytes.as_bytes()).map_err(protocol)?;
                if expected != **cut {
                    return Err(protocol(
                        "owned cut native completion differs from its retained producer receipt",
                    ));
                }
                return Ok(());
            }
            let staging = open_staging(runtime, record)?
                .ok_or_else(|| protocol("owned cut staging is missing"))?;
            crate::store::capture::validate_owned_cut(&staging, &record.plan, cut)?;
            match read_bounded(&staging, CAPTURE_EVIDENCE_FILE, MAX_CAPTURE_RECORD_BYTES)? {
                Some(bytes)
                    if vm_spec::capture::OwnedLocalCut::decode(&bytes).map_err(protocol)?
                        != **cut =>
                {
                    Err(protocol(
                        "owned cut file receipt differs from exact native completion",
                    ))
                }
                Some(_) => Ok(()),
                None => staging.write_file_atomic(
                    CAPTURE_EVIDENCE_FILE,
                    &cut.canonical_bytes().map_err(protocol)?,
                ),
            }
        }
        (
            vm_spec::capture::CaptureIdentityPolicy::Full
            | vm_spec::capture::CaptureIdentityPolicy::SinceAnchor,
            vm_spec::capture::CaptureSuccess::Identified { .. },
        ) => Ok(()),
        _ => Err(protocol(
            "native capture success has the wrong input authority",
        )),
    }
}

/// Advance one retained capture by observed facts only. Never Resume, never
/// reinterpret an absent continuation, never resubmit under a new identity.
pub(crate) async fn advance(
    runtime: &Runtime,
    machine_id: MachineId,
    capture_id: Uuid,
    progress: Option<&LiveOperationProgressSender>,
    lock_policy: crate::storage::pool::PublicationLockPolicy,
) -> Result<CaptureProgress, LibVmError> {
    let snapshots = snapshot_store(runtime)?;
    let record = snapshots
        .capture_reservation(capture_id)
        .await?
        .ok_or_else(|| protocol(format!("capture {capture_id} is not retained")))?;
    if record.machine_id != machine_id {
        return Err(protocol("capture belongs to another machine"));
    }
    if matches!(
        record.state,
        CaptureState::Reserved | CaptureState::Abandoned
    ) {
        if let Some(released) = retained_release(runtime, &record).await? {
            if released.disposition == CaptureReleaseDisposition::Abandoned {
                return settle_abandoned_release(&snapshots, &record, &released).await;
            }
        }
    }
    match &record.state {
        CaptureState::Released {
            snapshot: Some(snapshot),
        } => return finished(runtime, &snapshots, &record, snapshot).await,
        CaptureState::ReleasedLocal { .. } => return Ok(CaptureProgress::Local),
        CaptureState::Released { snapshot: None } | CaptureState::Abandoned => {
            return Ok(CaptureProgress::Abandoned(
                "capture produced no admissible snapshot".into(),
            ))
        }
        CaptureState::Reserved
        | CaptureState::Sealed
        | CaptureState::Local { .. }
        | CaptureState::Published { .. } => {}
    }
    if record.state == CaptureState::Reserved
        && !record.dispatch_attempted
        && open_staging(runtime, &record)?.is_none()
    {
        let machine = Machine::new(runtime.clone(), machine_id);
        if let Some(progress) = unsubmitted(runtime, &machine, None, &record).await? {
            if matches!(progress, CaptureProgress::Abandoned(_)) {
                snapshots.abandon_capture(capture_id).await?;
            }
            return Ok(progress);
        }
    }
    let liveness = run_liveness(runtime, machine_id, record.run_id).await?;
    if matches!(liveness, RunLiveness::Ended)
        && !matches!(
            record.state,
            CaptureState::Published { .. } | CaptureState::Local { .. }
        )
    {
        recover_cut(runtime, &record).await?;
    }
    // Durable capture success does not depend on source continuation or on
    // reaching the original monitor. Preserve the closure before reconciling
    // run authority; uncertainty must retain ownership, not postpone publication.
    let mut publication_error = None;
    let record = if !matches!(
        record.state,
        CaptureState::Published { .. } | CaptureState::Local { .. }
    ) && (match record.fork_operation_id {
        Some(operation) => runtime
            .native_store()?
            .local_cut(operation)
            .await?
            .is_some(),
        None => false,
    } || coherent_record(runtime, &record)?.is_some())
    {
        match retain_or_publish(runtime, &snapshots, &record, progress, lock_policy).await {
            Ok(()) => {}
            Err(error) => publication_error = Some(error),
        }
        snapshots
            .capture_reservation(capture_id)
            .await?
            .ok_or_else(|| protocol("published capture record disappeared"))?
    } else {
        record
    };
    let machine = Machine::new(runtime.clone(), machine_id);
    let published = matches!(
        record.state,
        CaptureState::Published { .. } | CaptureState::Local { .. }
    );
    let monitor = match &liveness {
        RunLiveness::Alive(observation) => {
            let observed =
                match observe_capture(&machine, observation, &record.plan.capture_id).await {
                    Ok(observed) => observed,
                    Err(error) => {
                        // Status and GetOperation are separate RPCs. Losing the
                        // exact monitor between them does not invalidate a cut.
                        // Re-enter through owner reconciliation on the next step;
                        // never infer a terminal source outcome from transport.
                        if !matches!(
                            run_liveness(runtime, machine_id, record.run_id).await?,
                            RunLiveness::Alive(_)
                        ) {
                            return match publication_error {
                                Some(error) => Err(error),
                                None => Ok(CaptureProgress::Pending("run reconciliation")),
                            };
                        }
                        return Err(publication_error.take().map_or(error, |primary| primary));
                    }
                };
            match observed {
                MonitorCapture::Observed(observed) => {
                    if let Some(progress) = progress {
                        if let Some(activity) = observed
                            .activity
                            .as_ref()
                            .filter(|activity| activity.operation_id == record.plan.capture_id)
                        {
                            progress.send(activity.stage.into());
                        } else if matches!(observed.operation.outcome, OperationOutcome::InProgress)
                            && observed.capture.as_ref().is_some_and(|capture| {
                                matches!(
                                    capture.continuation,
                                    CaptureContinuation::Resumed { .. }
                                        | CaptureContinuation::Preserved { .. }
                                        | CaptureContinuation::ResumeFailed { .. }
                                )
                            })
                        {
                            // Post-continuation identity stages are traced but
                            // deliberately absent from monitor lifecycle activity.
                            progress.send(LiveOperationProgress::ComputingDiskIdentity);
                        }
                    }
                    Some(observed)
                }
                MonitorCapture::NotFound if published => None,
                MonitorCapture::NotFound => {
                    if let Some(error) = publication_error.take() {
                        return Err(error);
                    }
                    let releasing=runtime.native_store()?.pending_live_commands(record.machine_id,record.run_id,&observation.report().monitor_id).await?.into_iter().any(|retained| matches!(retained.intent.command,LiveCommand::ReleaseCapture(command) if command.operation_id==record.plan.capture_id && command.disposition==CaptureReleaseDisposition::Abandoned));
                    if releasing {
                        return match release(
                            runtime,
                            &machine,
                            observation,
                            &record,
                            CaptureReleaseDisposition::Abandoned,
                        )
                        .await?
                        {
                            Some(released) => {
                                settle_abandoned_release(&snapshots, &record, &released).await
                            }
                            None => Ok(CaptureProgress::Pending("failed capture release replay")),
                        };
                    }
                    return match unsubmitted(runtime, &machine, Some(observation), &record).await? {
                        Some(CaptureProgress::Abandoned(reason)) => {
                            snapshots.abandon_capture(capture_id).await?;
                            Ok(CaptureProgress::Abandoned(reason))
                        }
                        Some(progress) => Ok(progress),
                        None => Ok(CaptureProgress::Pending("capture submission")),
                    };
                }
            }
        }
        RunLiveness::Ended => None,
        RunLiveness::Uncertain => {
            return match publication_error {
                Some(error) => Err(error),
                None => Ok(CaptureProgress::Pending("run reconciliation")),
            }
        }
    };
    if let Some(observed) = &monitor {
        if let OperationOutcome::CaptureSealed { capture } = &observed.operation.outcome {
            validate_capture_success(runtime, &record, capture)?;
            if capture.capture_id() != &record.plan.capture_id {
                return Err(protocol("seal names another capture"));
            }
            snapshots.accept_live_disk_baselines(&record).await?;
        }
    }
    if let Some(error) = publication_error {
        return Err(error);
    }
    let sealed = published
        || match &monitor {
            Some(observed) => match &observed.operation.outcome {
                OperationOutcome::CaptureSealed { capture } => {
                    if capture.capture_id() != &record.plan.capture_id {
                        return Err(protocol("seal names another capture"));
                    }
                    true
                }
                OperationOutcome::InProgress => {
                    return Ok(CaptureProgress::Pending("capture in progress"))
                }
                OperationOutcome::Failed { failure } => {
                    return abandon_failed(
                        runtime,
                        &machine,
                        &liveness,
                        &snapshots,
                        &record,
                        observed,
                        failure.to_string(),
                    )
                    .await
                }
                OperationOutcome::Succeeded { .. } => {
                    return Err(protocol("capture operation carries pause success"))
                }
            },
            None => match unsubmitted(runtime, &machine, None, &record).await? {
                Some(CaptureProgress::Abandoned(reason)) => {
                    snapshots.abandon_capture(capture_id).await?;
                    return Ok(CaptureProgress::Abandoned(reason));
                }
                Some(progress) => return Ok(progress),
                None => coherent_record(runtime, &record)?.is_some(),
            },
        };
    if !sealed {
        // The run ended without a coherent record: no admissible capture.
        snapshots.abandon_capture(capture_id).await?;
        return Ok(CaptureProgress::Abandoned(
            "run ended before a coherent capture record".into(),
        ));
    }
    if !published {
        retain_or_publish(runtime, &snapshots, &record, progress, lock_policy).await?;
    }
    let record = snapshots
        .capture_reservation(capture_id)
        .await?
        .ok_or_else(|| protocol("published capture record disappeared"))?;
    if record.source_outcome.is_none() {
        let outcome = match (&liveness, &monitor) {
            (RunLiveness::Alive(_), Some(observed)) => {
                let continuation = observed
                    .capture
                    .as_ref()
                    .map(|capture| capture.continuation.clone())
                    .ok_or_else(|| protocol("capture observation lacks continuation"))?;
                match continuation {
                    CaptureContinuation::Pending => {
                        return Ok(CaptureProgress::Pending("source continuation"))
                    }
                    CaptureContinuation::Unchanged => {
                        return Err(protocol("a sealed capture reports an unchanged source"))
                    }
                    continuation => match source_record(runtime, &record)? {
                        Some(source) => CaptureSourceOutcome::Known { record: source },
                        None => CaptureSourceOutcome::Observed { continuation },
                    },
                }
            }
            (RunLiveness::Alive(_), None) => match source_record(runtime, &record)? {
                Some(source) => CaptureSourceOutcome::Known { record: source },
                None => return Ok(CaptureProgress::Pending("sealed capture monitor ownership")),
            },
            _ => match source_record(runtime, &record)? {
                Some(source) => CaptureSourceOutcome::Known { record: source },
                None => CaptureSourceOutcome::Unknown,
            },
        };
        snapshots.record_capture_source(capture_id, outcome).await?;
    }
    match &liveness {
        RunLiveness::Alive(observation) => {
            if release(
                runtime,
                &machine,
                observation,
                &record,
                CaptureReleaseDisposition::Published,
            )
            .await?
            .is_none()
            {
                return Ok(CaptureProgress::Pending("source continuation"));
            }
        }
        // The exact run ended: no monitor result ownership survives it.
        RunLiveness::Ended | RunLiveness::Uncertain => {}
    }
    snapshots.finish_capture_release(capture_id, true).await?;
    let record = snapshots
        .capture_reservation(capture_id)
        .await?
        .ok_or_else(|| protocol("released capture record disappeared"))?;
    match &record.state {
        CaptureState::Released {
            snapshot: Some(snapshot),
        } => finished(runtime, &snapshots, &record, snapshot).await,
        CaptureState::ReleasedLocal { .. } => Ok(CaptureProgress::Local),
        _ => Err(protocol("released capture lost its published snapshot")),
    }
}

async fn abandon_failed(
    runtime: &Runtime,
    machine: &Machine,
    liveness: &RunLiveness,
    snapshots: &SnapshotStore,
    record: &CaptureRecord,
    observed: &OperationObservation,
    failure: String,
) -> Result<CaptureProgress, LibVmError> {
    let filesystem = crate::paths::machine_data_dir_in(runtime.local_home(), record.machine_id);
    let available = (|| -> Result<u64, LibVmError> {
        let directory = OwnedDirectory::open_existing_root(&filesystem)?
            .ok_or_else(|| protocol("staging filesystem disappeared"))?;
        let stat = nix::sys::statvfs::fstatvfs(directory.fd()).map_err(std::io::Error::from)?;
        stat.blocks_available()
            .checked_mul(stat.fragment_size())
            .ok_or_else(|| protocol("staging filesystem availability overflow"))
    })()
    .map(|bytes| format!("{bytes} bytes"))
    .unwrap_or_else(|error| format!("unavailable ({error})"));
    let failure = format!("staging failure on filesystem {}: required {} bytes, available {available} (RAM staging {}, disk staging {}, publication {}, reserves {}): {failure}",
        filesystem.display(), record.reservation_bytes, record.plan.ram_bytes,
        record.plan.reservation.staging_bytes - record.plan.ram_bytes - vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES,
        record.reservation_bytes - record.plan.reservation.staging_bytes,
        vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES);
    if let RunLiveness::Alive(observation) = liveness {
        let terminal = observed
            .capture
            .as_ref()
            .is_some_and(|capture| capture.continuation.is_terminal());
        if !terminal {
            return Ok(CaptureProgress::Pending("failed capture continuation"));
        }
        if let Some(capture) = &observed.capture {
            snapshots
                .record_capture_source(
                    record.capture_id,
                    CaptureSourceOutcome::Observed {
                        continuation: capture.continuation.clone(),
                    },
                )
                .await?;
        }
        let Some(released) = release(
            runtime,
            machine,
            observation,
            record,
            CaptureReleaseDisposition::Abandoned,
        )
        .await?
        else {
            return Ok(CaptureProgress::Pending("failed capture continuation"));
        };
        settle_abandoned_release(snapshots, record, &released).await?;
        return Ok(CaptureProgress::Abandoned(failure));
    }
    snapshots.abandon_capture(record.capture_id).await?;
    Ok(CaptureProgress::Abandoned(failure))
}

async fn finished(
    runtime: &Runtime,
    snapshots: &SnapshotStore,
    record: &CaptureRecord,
    snapshot: &crate::storage::identity::SnapshotId,
) -> Result<CaptureProgress, LibVmError> {
    let info = snapshots.inspect(&SnapshotRef::Id(*snapshot)).await?;
    runtime.native_store()?.checkpoint_catalog().await?;
    Ok(CaptureProgress::Finished(Box::new(LiveSnapshot {
        snapshot: info,
        capture: summary(runtime, record)?,
        naming_outcome: record.naming_outcome.clone(),
    })))
}

fn source_view(
    outcome: &CaptureSourceOutcome,
) -> Result<(LiveCaptureSource, Option<Diagnostic>), LibVmError> {
    Ok(match outcome {
        CaptureSourceOutcome::Known { record } => (
            match record.source_outcome {
                vm_spec::capture::CaptureSourceOutcome::Resumed => LiveCaptureSource::Resumed,
                vm_spec::capture::CaptureSourceOutcome::Preserved => LiveCaptureSource::Preserved,
                vm_spec::capture::CaptureSourceOutcome::ResumeFailed => {
                    LiveCaptureSource::ResumeFailed
                }
            },
            record.error.clone(),
        ),
        CaptureSourceOutcome::Observed { continuation } => match continuation {
            CaptureContinuation::Resumed { .. } => (LiveCaptureSource::Resumed, None),
            CaptureContinuation::Preserved { .. } => (LiveCaptureSource::Preserved, None),
            CaptureContinuation::ResumeFailed { failure, .. } => (
                LiveCaptureSource::ResumeFailed,
                Some(Diagnostic::new(failure.to_string())),
            ),
            CaptureContinuation::Pending | CaptureContinuation::Unchanged => {
                return Err(protocol(
                    "recorded continuation is not a terminal source outcome",
                ))
            }
        },
        CaptureSourceOutcome::Unknown => (LiveCaptureSource::Unknown, None),
    })
}

fn pause_disposition(plan: &vm_spec::capture::CapturePlan) -> CapturePauseDisposition {
    match plan.pause {
        CapturePauseAuthority::Acquire => CapturePauseDisposition::Acquired,
        CapturePauseAuthority::Borrow { .. } => CapturePauseDisposition::Borrowed,
    }
}

fn summary(runtime: &Runtime, record: &CaptureRecord) -> Result<LiveCaptureSummary, LibVmError> {
    let (source_outcome, source_error) = source_view(
        record
            .source_outcome
            .as_ref()
            .ok_or_else(|| protocol("capture source outcome is not recorded"))?,
    )?;
    Ok(LiveCaptureSummary {
        capture_id: record.plan.capture_id.clone(),
        machine_id: record.plan.machine_id.clone(),
        run_id: record.plan.run_id.clone(),
        resume_policy: record.plan.resume_policy,
        first_snapshot_full_identity_reason: matches!(
            record.storage.ram_identity,
            crate::store::models::storage::ContentIdentityState::UnknownAfterFork
        )
        .then_some(SnapshotIdentityReason::UnknownAfterFork),
        memory: CaptureEvidence::decode(
            record
                .evidence
                .as_deref()
                .ok_or_else(|| protocol("published capture has no evidence"))?
                .as_bytes(),
        )
        .map_err(protocol)?
        .memory
        .ok_or_else(|| protocol("published capture has no memory evidence"))?,
        pause: pause_disposition(&record.plan),
        source_outcome,
        source_error,
        released: matches!(record.state, CaptureState::Released { .. }),
        staging: staging_relative(runtime, record)?,
    })
}

/// Retained, unreleased captures of one machine; read-only.
pub(crate) async fn machine_captures(
    runtime: &Runtime,
    machine: MachineId,
) -> Result<Vec<MachineCapture>, LibVmError> {
    let Some(store) = runtime.optional_native_store() else {
        return Ok(Vec::new());
    };
    SnapshotStore::from_store(Arc::new(store))
        .pending_captures(Some(machine))
        .await?
        .iter()
        .map(|record| {
            let (stage, snapshot_id) = match &record.state {
                CaptureState::Reserved => (MachineCaptureStage::Reserved, None),
                CaptureState::Sealed | CaptureState::Local { .. } => {
                    (MachineCaptureStage::Sealed, None)
                }
                CaptureState::Published { snapshot } => {
                    (MachineCaptureStage::Published, Some(*snapshot))
                }
                CaptureState::Released { .. }
                | CaptureState::ReleasedLocal { .. }
                | CaptureState::Abandoned => {
                    return Err(protocol("pending captures include a terminal capture"))
                }
            };
            Ok(MachineCapture {
                capture_id: record.plan.capture_id.clone(),
                run_id: record.plan.run_id.clone(),
                resume_policy: record.plan.resume_policy,
                pause: pause_disposition(&record.plan),
                stage,
                snapshot_id,
                source_outcome: record
                    .source_outcome
                    .as_ref()
                    .map(|outcome| source_view(outcome).map(|(source, _)| source))
                    .transpose()?,
                staging: staging_relative(runtime, record)?,
            })
        })
        .collect()
}

/// Advance every retained capture of `machine` (or all machines), logging
/// per-capture uncertainty instead of stopping at the first one.
pub(crate) async fn reconcile_captures(
    runtime: &Runtime,
    machine: Option<MachineId>,
    lock_policy: crate::storage::pool::PublicationLockPolicy,
) -> Result<(), LibVmError> {
    let Some(store) = runtime.optional_native_store() else {
        return Ok(());
    };
    let snapshots = SnapshotStore::from_store(Arc::new(store));
    for record in snapshots.pending_captures(machine).await? {
        // Reconciliation never opens a fork cut; a fork whose own loop is not
        // running here later authenticates its cut disks again.
        match advance(
            runtime,
            record.machine_id,
            record.capture_id,
            None,
            lock_policy,
        )
        .await
        {
            Ok(CaptureProgress::Pending(stage)) => {
                tracing::debug!(capture = %record.capture_id, stage, "capture remains owned by its run");
            }
            Ok(CaptureProgress::Finished(snapshot)) => {
                if let Some(crate::CaptureNamingOutcome::NameConflict { name }) =
                    &snapshot.naming_outcome
                {
                    tracing::info!(capture = %record.capture_id, snapshot = %snapshot.snapshot.id, name, "reconciled live capture kept without its conflicting name");
                } else {
                    tracing::info!(capture = %record.capture_id, snapshot = %snapshot.snapshot.id, "reconciled live capture");
                }
            }
            Ok(CaptureProgress::Local) => {}
            Ok(CaptureProgress::Abandoned(reason)) => {
                tracing::info!(capture = %record.capture_id, reason, "abandoned unsealed live capture");
            }
            Err(error) => {
                let deferred = matches!(
                    &error,
                    LibVmError::Storage(
                        crate::storage::StorageError::CaptureDiskBudget {
                            phase: "publication deferred",
                            ..
                        } | crate::storage::StorageError::CapturePublicationDeferred { .. }
                            | crate::storage::StorageError::PublicationBusy { .. }
                    )
                );
                if deferred {
                    tracing::warn!(capture = %record.capture_id, phase = "publication deferred", %error, "publication deferred; staging retained");
                } else {
                    tracing::warn!(capture = %record.capture_id, %error, "live capture reconciliation retained uncertainty");
                }
            }
        }
    }
    Ok(())
}

/// A fork capture yields the disks its seal verification authenticated;
/// snapshot publication copies into the pool and yields none.
async fn retain_or_publish(
    runtime: &Runtime,
    snapshots: &SnapshotStore,
    record: &CaptureRecord,
    progress: Option<&LiveOperationProgressSender>,
    lock_policy: crate::storage::pool::PublicationLockPolicy,
) -> Result<(), LibVmError> {
    if runtime
        .native_store()?
        .fork_for_capture(record.capture_id)
        .await?
        .is_some()
    {
        snapshots.retain_local_capture(record.capture_id).await?;
        return Ok(());
    }
    report_progress(progress, LiveOperationProgress::Publishing);
    snapshots
        .publish_capture(
            record.capture_id,
            &staging_absolute(runtime, record),
            record.name.clone(),
            lock_policy,
        )
        .await?;
    Ok(())
}

impl Runtime {
    /// Publish every retained valid seal, settle continuation facts and
    /// abandon captures that can no longer seal. Captures whose run is alive
    /// stay owned by that run; this never sends Resume.
    pub async fn reconcile_captures(&self) -> Result<(), LibVmError> {
        reconcile_captures(
            self,
            None,
            crate::storage::pool::PublicationLockPolicy::Wait,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use vm_spec::capture::CapturePauseAuthority;
    use vm_spec::lifecycle::{
        CaptureResumePolicy, CurrentPause, LiveId, LiveLifecycle, PauseOwner, PauseToken,
        VmLifecycleState,
    };
    use vm_spec::live::{
        LiveAvailability, LiveBackend, LiveCapability, LiveCapabilityVector, LiveLane,
        LiveMachineReport, LiveOperation, LiveReasonCode, LiveScope,
    };

    use crate::machine::live::MachineLiveObservation;
    use crate::machine::live_capture::admission;
    use crate::LibVmError;

    fn report(capture: bool) -> LiveMachineReport {
        let mut live = LiveCapabilityVector::all_unsupported(LiveReasonCode::BuildExcluded);
        if capture {
            live.capture = LiveCapability {
                native: true,
                availability: LiveAvailability::Supported,
            };
        }
        LiveMachineReport {
            schema_version: 1,
            scope: LiveScope::Machine,
            machine_id: "00000000-0000-4000-8000-000000000001".into(),
            run_id: "00000000-0000-4000-8000-000000000002".into(),
            monitor_id: "00000000-0000-4000-8000-000000000003".into(),
            backend: LiveBackend::Mock,
            lane: LiveLane::NotApplicable,
            topology_revision: 1,
            live,
        }
    }

    fn id(last: u8) -> LiveId {
        LiveId::parse(&format!("00000000-0000-4000-8000-0000000000{last:02x}")).unwrap()
    }

    fn token(owner: PauseOwner) -> PauseToken {
        PauseToken {
            machine_id: id(1),
            run_id: id(2),
            generation: NonZeroU64::new(3).unwrap(),
            owner,
        }
    }

    fn observed(
        capture: bool,
        state: VmLifecycleState,
        lifecycle: LiveLifecycle,
    ) -> MachineLiveObservation {
        MachineLiveObservation::for_test(report(capture), state, lifecycle)
    }

    fn paused(owner: PauseOwner) -> LiveLifecycle {
        LiveLifecycle {
            current_pause: Some(CurrentPause {
                token: token(owner),
                operation_id: id(9),
                freeze_epoch: NonZeroU64::new(4).unwrap(),
            }),
            ..LiveLifecycle::default()
        }
    }

    #[test]
    fn capture_without_pause_authority_names_the_observed_state() {
        let observation = observed(true, VmLifecycleState::Paused, LiveLifecycle::default());
        let message = admission(&observation, CaptureResumePolicy::Preserve)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("paused machine has no current pause authority"),
            "{message}"
        );
        assert!(message.contains("observed_state=paused"), "{message}");
        assert!(
            message.contains(&format!("machine_id={}", id(1))),
            "{message}"
        );
        assert!(message.contains(&format!("run_id={}", id(2))), "{message}");
    }

    #[test]
    fn capture_options_validate_crossover_before_any_operation() {
        let mut options = crate::LiveSnapshotOptions::default();
        assert_eq!(
            options.policy,
            vm_spec::lifecycle::CapturePolicy::Incremental
        );
        assert_eq!(options.dirty_crossover_percent, 60);
        for policy in [
            vm_spec::lifecycle::CapturePolicy::Full,
            vm_spec::lifecycle::CapturePolicy::Incremental,
        ] {
            options.policy = policy;
            for percent in [1, 59, 60] {
                options.dirty_crossover_percent = percent;
                options.validate().unwrap();
            }
            for percent in [0, 61, u8::MAX] {
                options.dirty_crossover_percent = percent;
                assert!(options.validate().is_err());
            }
        }
    }

    #[test]
    fn default_capture_policy_uses_incremental_only_when_admitted() {
        use vm_spec::lifecycle::CapturePolicy;

        for (backend, lane) in [
            (LiveBackend::Krun, LiveLane::KvmX86_64),
            (LiveBackend::Krun, LiveLane::KvmArm64GicV3),
            (LiveBackend::Krun, LiveLane::HvfArm64),
            (LiveBackend::Vz, LiveLane::NotApplicable),
        ] {
            for supported in [false, true] {
                let mut report = report(true);
                report.backend = backend;
                report.lane = lane;
                if supported {
                    report.live.incremental = LiveCapability {
                        native: true,
                        availability: LiveAvailability::Supported,
                    };
                }
                let observation = MachineLiveObservation::for_test(
                    report,
                    VmLifecycleState::Running,
                    LiveLifecycle::default(),
                );
                let options = crate::LiveSnapshotOptions::default();
                assert_eq!(
                    crate::machine::live_capture::resolve_policy(options.policy, &observation),
                    if supported {
                        CapturePolicy::Incremental
                    } else {
                        CapturePolicy::Full
                    },
                );
                assert_eq!(
                    crate::machine::live_capture::resolve_policy(CapturePolicy::Full, &observation),
                    CapturePolicy::Full,
                );
                assert!(admission(&observation, options.resume_policy).is_ok());
            }
        }
    }

    #[test]
    fn named_snapshot_uses_the_same_capture_contract() {
        let mut options = crate::LiveSnapshotOptions {
            name: Some("saved".into()),
            ..Default::default()
        };
        options.validate().unwrap();
        options.name = None;
        options.validate().unwrap();
    }

    #[test]
    fn capture_admission_refuses_absent_primitive_with_the_reported_reason() {
        let error = admission(
            &observed(false, VmLifecycleState::Running, LiveLifecycle::default()),
            CaptureResumePolicy::ResumeIfAcquired,
        )
        .unwrap_err();
        match error {
            LibVmError::LiveOperationUnsupported {
                operation, reason, ..
            } => {
                assert_eq!(operation, LiveOperation::Capture);
                assert_eq!(reason.code, LiveReasonCode::BuildExcluded);
            }
            error => panic!("wrong refusal: {error}"),
        }
    }

    #[test]
    fn capture_admission_acquires_only_from_running_for_both_policies() {
        for policy in [
            CaptureResumePolicy::ResumeIfAcquired,
            CaptureResumePolicy::Preserve,
        ] {
            assert_eq!(
                admission(
                    &observed(true, VmLifecycleState::Running, LiveLifecycle::default()),
                    policy,
                )
                .unwrap(),
                (CapturePauseAuthority::Acquire, policy)
            );
            assert_eq!(
                crate::machine::live_capture::resolve_resume_policy(
                    policy,
                    &observed(true, VmLifecycleState::Running, LiveLifecycle::default()),
                )
                .unwrap(),
                policy,
            );
        }
    }

    #[test]
    fn capture_admission_borrows_exact_user_pause_and_resolves_both_policies_to_preserve() {
        for policy in [
            CaptureResumePolicy::ResumeIfAcquired,
            CaptureResumePolicy::Preserve,
        ] {
            let observation = observed(true, VmLifecycleState::Paused, paused(PauseOwner::User));
            assert_eq!(
                admission(&observation, policy).unwrap(),
                (
                    CapturePauseAuthority::Borrow {
                        pause_operation_id: id(9),
                        token: token(PauseOwner::User),
                    },
                    CaptureResumePolicy::Preserve,
                )
            );
            assert_eq!(
                crate::machine::live_capture::resolve_resume_policy(policy, &observation).unwrap(),
                CaptureResumePolicy::Preserve,
            );
            assert!(admission(
                &observed(
                    true,
                    VmLifecycleState::Paused,
                    paused(PauseOwner::Capture {
                        operation_id: id(7)
                    })
                ),
                policy,
            )
            .is_err());
            assert!(admission(
                &observed(true, VmLifecycleState::Paused, LiveLifecycle::default()),
                policy,
            )
            .is_err());
        }
    }

    #[test]
    fn capture_admission_rejects_every_other_state_before_effects() {
        for state in VmLifecycleState::ALL
            .iter()
            .copied()
            .filter(|state| !matches!(state, VmLifecycleState::Running | VmLifecycleState::Paused))
        {
            let lifecycle = LiveLifecycle::default();
            for policy in [
                CaptureResumePolicy::ResumeIfAcquired,
                CaptureResumePolicy::Preserve,
            ] {
                assert!(
                    admission(&observed(true, state, lifecycle.clone()), policy).is_err(),
                    "{state}"
                );
            }
        }
    }

    fn identity_pending_files() -> (
        tempfile::TempDir,
        crate::paths::OwnedDirectory,
        vm_spec::capture::CapturePlan,
        vm_spec::capture::CaptureEvidence,
    ) {
        use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
        use vm_spec::capture::*;
        use vm_spec::lifecycle::CapturePolicy;

        let root = tempfile::tempdir().unwrap();
        let staging =
            crate::paths::OwnedDirectory::open_root(&root.path().join("capture")).unwrap();
        let disks = staging.ensure_dir("disks").unwrap();
        let name = CaptureDiskName::new("root").unwrap();
        let length = 2 * STREAM_CHUNK_BYTES + 4096;
        let block = vm_spec::BlockId::new("root").unwrap();
        let configuration = CaptureConfiguration {
            guest_os: None,
            cpus: 1,
            memory_mib: 1,
            nested_virtualization: false,
            rosetta: false,
            kernel_cmdline: Vec::new(),
            vsock: true,
            attachments: vec![CaptureAttachment {
                block_id: block.clone(),
                role: vm_spec::DiskRole::Root,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length,
                    logical_sector_size: 512,
                },
                read_only: false,
            }],
            shares: Vec::new(),
        };
        let plan = CapturePlan {
            identity_policy: vm_spec::capture::CaptureIdentityPolicy::Full,
            map_node_store: None,
            version: CAPTURE_RECORD_VERSION,
            machine_id: id(1),
            run_id: id(2),
            capture_id: id(3),
            ram_bytes: configuration.ram_bytes(),
            configuration_digest: configuration.digest().unwrap(),
            configuration,
            policy: CapturePolicy::Full,
            dirty_crossover_percent: 60,
            resume_policy: CaptureResumePolicy::ResumeIfAcquired,
            pause: CapturePauseAuthority::Acquire,
            disks: vec![CaptureDiskPlan {
                identity: vm_spec::capture::DiskIdentityState::Unknown,
                name: name.clone(),
                attachment_index: 0,
                block_id: block,
                length,
                baseline_map: None,
                tracking_eligible: true,
                copy: CaptureDiskCopy::Clone,
            }],
            read_only_inputs: Vec::new(),
            reservation: CaptureReservation {
                storage_operation_id: id(4),
                launch_lease: CaptureLaunchLease {
                    operation_id: id(5),
                    device: 1,
                    inode: 2,
                },
                staging_bytes: 128 << 20,
            },
        };
        plan.validate().unwrap();
        staging
            .write_file(CAPTURE_REQUEST_FILE, &plan.canonical_bytes().unwrap())
            .unwrap();
        let path = disks.path().join(name.file_name());
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        file.set_len(length).unwrap();
        file.write_all_at(b"mixed chunk", 4096).unwrap();
        file.write_all_at(b"tail", length - 4).unwrap();
        file.sync_all().unwrap();
        let metadata = file.metadata().unwrap();
        let disk = CaptureDiskCut {
            tracking_receipt: None,
            name: name.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            length,
            mode: metadata.mode(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        };
        let mut hasher =
            crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK);
        let expected_map = hasher
            .hash_reader(std::fs::File::open(&path).unwrap())
            .unwrap();
        let ram = vm_spec::stream_map::StreamRoot::empty(4096, vm_spec::stream_map::ChunkSize::RAM)
            .unwrap();
        let changes = b"KRUNRAM\0\x01\0\x10\0\0\0\0\0".to_vec();
        let mut inventory = Vec::new();
        for (role, bytes) in [
            (CaptureRole::Execution, b"execution".to_vec()),
            (CaptureRole::Devices, b"devices".to_vec()),
            (CaptureRole::Ram, vec![0; 4096]),
            (CaptureRole::Layout, br#"{"architecture":"x86_64","kind":"ram-layout","magic":"KRUNRAML","packedLength":4096,"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":4096,"streamOffset":0}],"schema":1,"topology":{"ramBelowGap":4096}}"#.to_vec()),
            (CaptureRole::RamMap, ram.canonical_bytes().unwrap()),
            (CaptureRole::RamChanges, changes.clone()),
        ] {
            staging.write_file(&role.relative_path(), &bytes).unwrap();
            let stream = role == CaptureRole::Ram;
            inventory.push(CaptureInventoryEntry {
                role, length: bytes.len() as u64,
                sha256: (!stream).then(|| Sha256Digest::of_bytes(&bytes)),
                identity: stream.then(|| ram.id()),
            });
        }
        let binding = Sha256Digest::of_bytes(b"native binding");
        let evidence = CaptureEvidence {
            disk_stats: Vec::new(),
            disk_tracking_receipts: Vec::new(),
            version: CAPTURE_RECORD_VERSION,
            machine_id: id(1),
            run_id: id(2),
            capture_id: id(3),
            pause_token: Some(PauseToken {
                machine_id: id(1),
                run_id: id(2),
                generation: NonZeroU64::new(3).unwrap(),
                owner: PauseOwner::Capture {
                    operation_id: id(3),
                },
            }),
            pause_disposition: Some(CapturePauseDisposition::Acquired),
            freeze_epoch: NonZeroU64::new(4),
            freeze_operation_id: Some(id(3)),
            configuration_digest: plan.configuration_digest,
            request_digest: Sha256Digest::of_bytes(&plan.canonical_bytes().unwrap()),
            memory: Some(CaptureMemoryEvidence {
                identity_policy: vm_spec::capture::CaptureIdentityPolicy::Full,
                identity_full_reason: Some(vm_spec::capture::CaptureIdentityFullReason::Requested),
                packed_length: 4096,
                page_granule: 4096,
                regions: 1,
                ram_stream: ram.id(),
                mode: CapturePolicy::Full,
                baseline: None,
                full_reason: Some(CaptureFullReason::Requested),
                identity_chunk_bytes: 1 << 16,
                changes: CaptureRamChanges {
                    byte_len: changes.len() as u64,
                    sha256: Sha256Digest::of_bytes(&changes),
                    record_count: 0,
                    coverage: CaptureRamCoverage::Full,
                    baseline_stream: None,
                },
                stats: CaptureMemoryStats {
                    logical_bytes: 4096,
                    identity_bytes_hashed: 0,
                    ..Default::default()
                },
                binding: CaptureStateBinding {
                    live_state_schema: "silo.live-state/1".into(),
                    architecture: "x86_64".into(),
                    profile: binding,
                    topology: binding,
                    ram_layout: binding,
                    source_run: id(2),
                    pause_generation: NonZeroU64::new(3).unwrap(),
                    capture: id(3),
                },
            }),
            inventory,
            started_at_unix_ms: 10,
            completed_at_unix_ms: 20,
            capture_outcome: CaptureRecordOutcome::Coherent,
            error: None,
            workloads_frozen: true,
            vcpus_paused: true,
            devices_quiesced: true,
            host_writers_drained: true,
            host_flush_completed: true,
            disk_copies_sealed: false,
            memory_state_sealed: true,
        };
        let cut = CaptureCutRecord {
            phase: CaptureCutPhase::IdentityPending,
            evidence: evidence.clone(),
            disks: vec![disk],
        };
        cut.validate_against_plan(&plan, &evidence.request_digest)
            .unwrap();
        staging
            .write_file(CAPTURE_CUT_FILE, &cut.canonical_bytes().unwrap())
            .unwrap();
        drop(file);
        let mut expected = evidence;
        expected.disk_copies_sealed = true;
        expected.disk_stats.push(CaptureDiskStats {
            name: name.clone(),
            dirty_chunks: length.div_ceil(STREAM_CHUNK_BYTES),
            total_chunks: length.div_ceil(STREAM_CHUNK_BYTES),
            bytes_hashed: expected_map
                .present_chunks()
                .map(|chunk| {
                    let index = chunk.unwrap().index;
                    (length - index * STREAM_CHUNK_BYTES).min(STREAM_CHUNK_BYTES)
                })
                .sum(),
            baseline_reused: false,
            full_scan_reason: Some(DiskFullScanReason::MissingBaseline),
        });
        let bytes = expected_map.canonical_bytes().unwrap();
        expected.inventory.extend([
            CaptureInventoryEntry {
                role: CaptureRole::Disk(name.clone()),
                length,
                sha256: None,
                identity: Some(Sha256Digest::from_bytes(*expected_map.id().as_bytes())),
            },
            CaptureInventoryEntry {
                role: CaptureRole::DiskMap(name),
                length: bytes.len() as u64,
                sha256: Some(Sha256Digest::of_bytes(&bytes)),
                identity: None,
            },
        ]);
        expected
            .validate_against_plan(&plan, &expected.request_digest)
            .unwrap();
        (root, staging, plan, expected)
    }

    #[test]
    fn identity_pending_recovery_matches_full_read_evidence_and_replays_partial_maps() {
        use vm_spec::capture::*;
        let (_root, staging, plan, expected) = identity_pending_files();
        assert!(staging.open_file(CAPTURE_EVIDENCE_FILE).unwrap().is_none());
        let disks = staging.open_dir("disks").unwrap().unwrap();
        disks.write_file("root.root", b"interrupted root").unwrap();
        staging
            .write_file(CAPTURE_EVIDENCE_TEMPORARY_FILE, b"interrupted seal")
            .unwrap();
        crate::machine::live_capture::complete_cut_identity(&staging, &plan).unwrap();
        let bytes = crate::machine::live_capture::read_bounded(
            &staging,
            CAPTURE_EVIDENCE_FILE,
            MAX_CAPTURE_RECORD_BYTES,
        )
        .unwrap()
        .unwrap();
        assert_eq!(CaptureEvidence::decode(&bytes).unwrap(), expected);
        assert_eq!(bytes, expected.canonical_bytes().unwrap());
        crate::machine::live_capture::complete_cut_identity(&staging, &plan).unwrap();
        assert_eq!(
            std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            bytes
        );
    }

    #[test]
    fn identity_pending_recovery_refuses_changed_or_replaced_clone_without_sealing() {
        use std::os::unix::fs::FileExt;
        use vm_spec::capture::*;
        for replace in [false, true] {
            let (_root, staging, plan, _) = identity_pending_files();
            let path = staging.path().join("disks/root.raw");
            if replace {
                let old = std::fs::File::open(&path).unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::File::create(&path)
                    .unwrap()
                    .set_len(old.metadata().unwrap().len())
                    .unwrap();
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .write_all_at(b"changed", 0)
                    .unwrap();
            }
            assert!(crate::machine::live_capture::complete_cut_identity(&staging, &plan).is_err());
            assert!(staging.open_file(CAPTURE_EVIDENCE_FILE).unwrap().is_none());
        }
    }

    #[test]
    fn identity_pending_recovery_settles_the_cut_link_and_never_promotes_a_failed_capture() {
        use vm_spec::capture::*;
        let (_root, staging, plan, expected) = identity_pending_files();
        std::fs::hard_link(
            staging.path().join(CAPTURE_CUT_FILE),
            staging.path().join(CAPTURE_CUT_TEMPORARY_FILE),
        )
        .unwrap();
        crate::machine::live_capture::complete_cut_identity(&staging, &plan).unwrap();
        assert!(!staging.path().join(CAPTURE_CUT_TEMPORARY_FILE).exists());
        assert_eq!(
            CaptureEvidence::decode(
                &std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            )
            .unwrap(),
            expected
        );
        let (_root, staging, plan, mut failed) = identity_pending_files();
        failed.capture_outcome = CaptureRecordOutcome::Failed;
        failed.memory = None;
        failed.inventory.clear();
        failed.error = Some(vm_spec::lifecycle::Diagnostic::new(
            "capture cancelled after continuation",
        ));
        let bytes = failed.canonical_bytes().unwrap();
        staging.write_file(CAPTURE_EVIDENCE_FILE, &bytes).unwrap();
        crate::machine::live_capture::complete_cut_identity(&staging, &plan).unwrap();
        assert_eq!(
            std::fs::read(staging.path().join(CAPTURE_EVIDENCE_FILE)).unwrap(),
            bytes
        );
        assert!(!staging.path().join("disks/root.root").exists());
    }
}

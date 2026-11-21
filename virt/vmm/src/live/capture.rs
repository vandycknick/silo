//! Snapshot, owned live fork and in-place hibernate on one run coordinator.
//!
//! ```text
//!  admit ─► prepare[staging, request.json, 5 outputs + launch-lease pin ─► worker]
//!        ─► pause[acquire: drain → freeze(e) → native Capture pause | borrow user pause]
//!        ─► flush[exact cut] ─► disks[clone | sparse copy; hash only snapshots]
//!        ─► snapshots: freeze disk generations ─► execution+devices ─► RAM receipt ─► verify
//!        ─► reflink lane: IdentityPending cut record ─► accept RAM baseline
//!             ─► continue[resume-if-acquired | preserve; publish source, open sessions if Running]
//!             ─► clone identities (new lifecycle operations remain fenced)
//!        ─► record[cancel/stop linearized; write-once coherent record]
//!        ─► commit disk generations + retain source maps independently of staging
//!        ═══ capture succeeded ═══ (cancel no longer has effect)
//!        ─► copy-only lane: accept baseline + continue ─► final source projection
//!  fork: prepare → pause/drain → flush → private disks → state + unhashed RAM
//!       → close writers → immutable exact-file record → accept owned byte baseline
//!       → continue source; identified RAM anchor and disk tracking history stay retained.
//!  hibernate: prepare → pause/drain → flush → report Rss+Swap estimate
//!       → await write authorization → unhashed state + sparse RAM → fsync cut
//!       → await durable manager commit → journal committed → kill/reap, no thaw.
//!  Old-run request/record/commit journals live in captures/<id>, not the save.
//!  A committed marker binds the exact old worker PID/start time until reap;
//!  clean release or precommit rollback deletes that operation journal.
//!
//!  unsealed failure/cancel ─► abort any frozen disk generations ─► resolve RAM candidate
//!       ─► snapshot-only failed evidence ─► continue once under policy
//! ```
//!
//! Capture success and source continuation are distinct facts: a failed
//! continuation never touches the seal, and a successful continuation never
//! turns a failed capture into a success. Nothing here unlinks staging.
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::Digest as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vm_spec::capture::{
    CaptureConfiguration, CaptureContinuation, CaptureCutPhase, CaptureCutRecord, CaptureDiskCopy,
    CaptureDiskCut, CaptureDiskPlan, CaptureEvidence, CaptureEvidenceReference,
    CaptureIdentityPolicy, CaptureInventoryEntry, CaptureLaunchLease, CaptureMemoryEvidence,
    CapturePauseAuthority, CapturePauseDisposition, CapturePlan, CaptureRecordOutcome,
    CaptureRecordReference, CaptureReleaseDisposition, CaptureReleaseState, CaptureReleased,
    CaptureRole, CaptureSealed, CaptureSourceOutcome, CaptureSourceRecord, CaptureSourceReference,
    CaptureStateBinding, CaptureSuccess, OwnedCutCompletion, OwnedCutMember, OwnedLocalCut,
    Sha256Digest, CAPTURE_CLONE_RESERVE_BYTES, CAPTURE_CUT_FILE, CAPTURE_CUT_TEMPORARY_FILE,
    CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE, CAPTURE_LAYOUT_FILE,
    CAPTURE_RECORD_VERSION, CAPTURE_SOURCE_FILE, CAPTURE_SOURCE_TEMPORARY_FILE,
    CAPTURE_STATE_RESERVE_BYTES, MAX_CAPTURE_RECORD_BYTES,
};
use vm_spec::capture::{CaptureMode, HibernateCapturePhase, HibernateCaptureStatus};
use vm_spec::hibernate::{
    HibernateCut, HibernateDiskBinding, HibernateFileBinding, HibernateSavedFile,
    HibernateSavedFileRole, HIBERNATE_CUT_VERSION,
};
use vm_spec::lifecycle::{
    CancelCompleted, CancelOperationOutcome, CaptureResumePolicy, CurrentPause, Diagnostic,
    LiveCommandKind, LiveCommandResult, LiveFailure, LiveFailureCode, LiveId, LiveOperationRecord,
    LiveRejectionReason, LiveStage, OperationKind, OperationOutcome, PauseOwner, PauseToken,
    ReleaseCaptureOutcome, ReleaseFailed, VmLifecycleState,
};
use vm_spec::live::{LiveBackend, LiveDeviceSubject, LiveLane, LiveOperation};
use vm_spec::stream_map::{StreamRole, StreamRoot, MAX_ROOT_BYTES};

use crate::live::coordinator::{
    failure, guest_observation, resume_code, resume_stage, stopped_cancel, wire_uuid, Continued,
    GuestError, Inner, LiveCoordinator, LiveError, NativeError, NATIVE_TRANSPORT_RETRIES,
    RETRY_DELAY,
};
use crate::live::gate::DrainError;
use crate::live::journal::{CaptureBinding, Eligibility, Phase, WorkerPreparation};
use crate::live::staging::{
    assemble_ram_map, hash_state, parse_layout, CaptureStaging, DiskCopyError, DiskCopyMethod,
    LayoutGeometry, RecordCommit,
};
use crate::state::ReadyAgentIdentity;
use crate::virt::lifecycle::{
    CancelSettlement, CaptureContinuation as NativeContinuation, CaptureDigests,
    CaptureObservation as NativeObservation, CaptureOutputFiles, CaptureOutputIdentities,
    CapturePauseSource, CapturePreparation, CaptureResumePolicy as NativeResumePolicy,
    CaptureStateBinding as NativeBinding, CommandOutcome, CommandState, Digest32, LifecycleCommand,
    LifecycleError, LifecycleRejection, LifecycleRequest, LifecycleRights, LifecycleUncertainty,
    NativePauseGeneration, NativePauseOwner, OutputIdentity, PausePurpose, SealedMemoryFiles,
};

/// Bound for the native canonical RAM layout read during verification.
const MAX_LAYOUT_BYTES: u64 = 64 * 1024;

/// This run's trusted capture identity, fixed at monitor startup.
#[derive(Debug)]
pub(crate) struct CaptureContext {
    data_dir: PathBuf,
    configuration: CaptureConfiguration,
    configuration_digest: Sha256Digest,
    launch: CaptureLaunchLease,
    lease: Arc<OwnedFd>,
    digests: CaptureDigests,
    baseline: std::sync::Mutex<IdentityAnchor>,
    disk_baselines: std::sync::Mutex<std::collections::BTreeMap<vm_spec::BlockId, Arc<StreamRoot>>>,
    disk_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct AcceptedMap {
    map: Arc<StreamRoot>,
    nodes: Option<crate::live::staging::MapNodeFiles>,
    layout: Sha256Digest,
    stream: Sha256Digest,
}

#[derive(Debug, Clone)]
enum IdentityAnchor {
    Unknown,
    Identified(AcceptedMap),
}

impl IdentityAnchor {
    fn identified(&self) -> Option<&AcceptedMap> {
        match self {
            Self::Unknown => None,
            Self::Identified(anchor) => Some(anchor),
        }
    }
}

impl CaptureContext {
    /// The profile binds backend and lane; topology binds configuration and
    /// attachment inventory. Neither is a monitor build identity.
    pub(crate) fn new(
        data_dir: PathBuf,
        spec: &vm_spec::VmSpec,
        launch: &crate::virt::StorageLaunch,
        backend: LiveBackend,
        lane: LiveLane,
    ) -> Result<Self, String> {
        let configuration = CaptureConfiguration::from_spec(spec)?;
        let configuration_digest = configuration.digest()?;
        launch.binding.validate()?;
        let launch_lease = CaptureLaunchLease {
            operation_id: LiveId::parse(&launch.binding.operation_id)?,
            device: launch.binding.file_device,
            inode: launch.binding.file_inode,
        };
        let mut profile = sha2::Sha256::new();
        profile.update(b"silo-capture-profile-v1\0");
        for field in [backend.as_str(), lane.as_str()] {
            profile.update((field.len() as u64).to_be_bytes());
            profile.update(field.as_bytes());
        }
        Ok(Self {
            data_dir,
            digests: CaptureDigests {
                profile: Digest32(profile.finalize().into()),
                topology: Digest32(*configuration_digest.as_bytes()),
            },
            configuration,
            configuration_digest,
            launch: launch_lease,
            lease: launch.lease.clone(),
            baseline: std::sync::Mutex::new(IdentityAnchor::Unknown),
            disk_baselines: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            disk_paths: spec
                .storage
                .as_ref()
                .map(|storage| storage.disks.iter().map(|disk| disk.path.clone()).collect())
                .unwrap_or_default(),
        })
    }

    pub(crate) fn inherit(&self, restore: &crate::virt::RestoreLaunch) -> io::Result<()> {
        let vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { evidence, .. } =
            &restore.request.authority
        else {
            *self
                .baseline
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = IdentityAnchor::Unknown;
            return Ok(());
        };
        let map =
            crate::restore::inputs::verified_ram_map(&restore.request, &restore.files.objects[4])?;
        let memory = evidence
            .memory
            .as_ref()
            .ok_or_else(|| io::Error::other("restore lacks RAM evidence"))?;
        *self
            .baseline
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = IdentityAnchor::Identified(AcceptedMap {
            map: Arc::new(map),
            nodes: restore
                .request
                .map_node_store
                .as_deref()
                .map(crate::live::staging::MapNodeFiles::open)
                .transpose()?,
            layout: memory.binding.ram_layout,
            stream: memory.ram_stream,
        });
        Ok(())
    }

    pub(crate) fn binding(&self) -> CaptureBinding {
        CaptureBinding {
            configuration: self.configuration.clone(),
            configuration_digest: self.configuration_digest,
            launch: self.launch.clone(),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn live_id(value: Uuid) -> Option<LiveId> {
    LiveId::parse(&value.hyphenated().to_string()).ok()
}

fn digest(value: Digest32) -> Sha256Digest {
    Sha256Digest::from_bytes(value.0)
}

fn io_capture_failure(
    error: &io::Error,
    stage: LiveStage,
    fallback: LiveFailureCode,
) -> LiveFailure {
    let full = error.kind() == io::ErrorKind::StorageFull
        || matches!(error.raw_os_error(), Some(code) if code == nix::errno::Errno::ENOSPC as i32 || code == nix::errno::Errno::EDQUOT as i32);
    failure(
        if full {
            LiveFailureCode::OutOfSpace
        } else {
            fallback
        },
        stage,
        format!("Could not save the machine: {error}; free space or fix the storage and retry"),
    )
}

/// Linux smaps_rollup reports KiB. Rss + Swap includes worker overhead and
/// swapped guest pages, not just resident RAM. This is an advisory space
/// estimate; ENOSPC during writing must still abandon the cut and resume.
fn parse_populated_memory_estimate(text: &str) -> io::Result<u64> {
    let mut rss = None;
    let mut swap = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let target = match words.next() {
            Some("Rss:") => &mut rss,
            Some("Swap:") => &mut swap,
            _ => continue,
        };
        if target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate memory counter",
            ));
        }
        let value = words
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid memory counter"))?;
        if words.next() != Some("kB") || words.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid memory counter unit",
            ));
        }
        *target = Some(value);
    }
    rss.zip(swap)
        .and_then(|(rss, swap)| rss.checked_add(swap))
        .and_then(|kib| kib.checked_mul(1024))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or overflowing memory counters",
            )
        })
}

fn hibernate_file_binding(file: &File, path: PathBuf) -> io::Result<HibernateFileBinding> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let binding = HibernateFileBinding {
        path,
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    };
    binding.validate().map_err(io::Error::other)?;
    let reopened = File::from(nix::fcntl::open(
        &binding.path,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )?);
    let current = reopened.metadata()?;
    if metadata.dev() != current.dev()
        || metadata.ino() != current.ino()
        || metadata.len() != current.len()
        || metadata.mode() != current.mode()
        || metadata.mtime() != current.mtime()
        || metadata.mtime_nsec() != current.mtime_nsec()
        || metadata.ctime() != current.ctime()
        || metadata.ctime_nsec() != current.ctime_nsec()
    {
        return Err(io::Error::other("saved path no longer names the held file"));
    }
    Ok(binding)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HibernateJournal<'a> {
    version: u32,
    machine_id: &'a LiveId,
    run_id: &'a LiveId,
    save_id: &'a LiveId,
    worker_pid: u32,
    worker_started_at: i64,
    status: &'a HibernateCaptureStatus,
}

/// Why the unsealed pipeline stopped.
enum Abort {
    Failed(LiveFailure),
    Stopped,
}

impl Abort {
    fn native(error: NativeError, code: LiveFailureCode, stage: LiveStage) -> Self {
        match error {
            NativeError::Stopped => Self::Stopped,
            error => Self::Failed(failure(error.code(code), stage, error.describe())),
        }
    }
}

/// How a capture's source continuation ended.
#[derive(Clone)]
enum Finish {
    Running(CaptureContinuation),
    Paused(CurrentPause, CaptureContinuation),
    /// No safe continuation: fenced Error, admitting only stop.
    Error(LiveFailure),
}

/// The seven positively observed facts, recorded exactly as observed.
#[derive(Debug, Default, Clone, Copy)]
struct Facts {
    workloads_frozen: bool,
    vcpus_paused: bool,
    devices_quiesced: bool,
    host_writers_drained: bool,
    host_flush_completed: bool,
    disk_copies_sealed: bool,
    memory_state_sealed: bool,
}

/// Where the source's pause stands for unwinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PauseState {
    /// Nothing frozen or parked by this capture.
    Untouched,
    /// The guest freeze of `epoch` may have taken effect; no native pause.
    Frozen(NonZeroU64),
    /// A native Capture pause was requested without a published token.
    NativePending(NonZeroU64),
    /// This capture owns the exact native cut token.
    Acquired(NonZeroU64, NativePauseGeneration),
    /// The exact user pause is borrowed, never changed.
    Borrowed,
}

/// One capture's in-flight facts, owned by its single pipeline task.
struct Run {
    operation: LiveId,
    plan: CapturePlan,
    cancel: CancellationToken,
    identity: Option<ReadyAgentIdentity>,
    borrowed: Option<CurrentPause>,
    started: u64,
    staging: Option<Arc<CaptureStaging>>,
    request_digest: Option<Sha256Digest>,
    outputs: Option<CaptureOutputIdentities>,
    worker: WorkerPreparation,
    pause: PauseState,
    cut: Option<PauseToken>,
    freeze_epoch: Option<NonZeroU64>,
    facts: Facts,
    binding: Option<NativeBinding>,
    memory: Option<CaptureMemoryEvidence>,
    owned_cut: Option<OwnedLocalCut>,
    inventory: Vec<CaptureInventoryEntry>,
    native_memory: Option<CommandOutcome>,
    resolved_map: Option<Arc<StreamRoot>>,
    pending_disks: Vec<CaptureDiskCut>,
    continued: Option<Finish>,
    source_continued: bool,
    disk_freeze_attempted: bool,
    disk_receipts: Vec<vm_spec::capture::DiskTrackingReceipt>,
    disk_stats: Vec<vm_spec::capture::CaptureDiskStats>,
    disk_maps: Vec<(vm_spec::BlockId, Arc<StreamRoot>)>,
}

enum CompletedRecord {
    Identified(Box<CaptureEvidence>),
    Owned(Box<OwnedLocalCut>),
}

impl Run {
    fn cut_generation(&self) -> Option<NativePauseGeneration> {
        match self.pause {
            PauseState::Acquired(_, generation) => Some(generation),
            PauseState::Borrowed => self
                .cut
                .as_ref()
                .and_then(|token| NativePauseGeneration::new(token.generation.get())),
            _ => None,
        }
    }

    fn capture_token(&self, generation: NativePauseGeneration) -> Option<PauseToken> {
        Some(PauseToken {
            machine_id: self.plan.machine_id.clone(),
            run_id: self.plan.run_id.clone(),
            generation: NonZeroU64::new(generation.get())?,
            owner: PauseOwner::Capture {
                operation_id: self.operation.clone(),
            },
        })
    }

    fn evidence(
        &self,
        outcome: CaptureRecordOutcome,
        error: Option<Diagnostic>,
    ) -> Option<CaptureEvidence> {
        let request_digest = self.request_digest?;
        if self.plan.identity_policy == CaptureIdentityPolicy::None {
            return None;
        }
        let token = self.cut.clone();
        Some(CaptureEvidence {
            disk_stats: self.disk_stats.clone(),
            disk_tracking_receipts: self.disk_receipts.clone(),
            version: CAPTURE_RECORD_VERSION,
            machine_id: self.plan.machine_id.clone(),
            run_id: self.plan.run_id.clone(),
            capture_id: self.plan.capture_id.clone(),
            pause_disposition: token.as_ref().map(|_| {
                if self.borrowed.is_none() {
                    CapturePauseDisposition::Acquired
                } else {
                    CapturePauseDisposition::Borrowed
                }
            }),
            pause_token: token,
            freeze_epoch: self.freeze_epoch,
            freeze_operation_id: self.freeze_epoch.map(|_| {
                self.borrowed.as_ref().map_or_else(
                    || self.operation.clone(),
                    |current| current.operation_id.clone(),
                )
            }),
            configuration_digest: self.plan.configuration_digest,
            request_digest,
            memory: match outcome {
                CaptureRecordOutcome::Coherent => self.memory.clone(),
                CaptureRecordOutcome::Failed => None,
            },
            inventory: match outcome {
                CaptureRecordOutcome::Coherent => self.inventory.clone(),
                CaptureRecordOutcome::Failed => Vec::new(),
            },
            started_at_unix_ms: self.started,
            completed_at_unix_ms: now_ms().max(self.started),
            capture_outcome: outcome,
            error,
            workloads_frozen: self.facts.workloads_frozen,
            vcpus_paused: self.facts.vcpus_paused,
            devices_quiesced: self.facts.devices_quiesced,
            host_writers_drained: self.facts.host_writers_drained,
            host_flush_completed: self.facts.host_flush_completed,
            disk_copies_sealed: self.facts.disk_copies_sealed,
            memory_state_sealed: self.facts.memory_state_sealed,
        })
    }
}

/// Verified staged inventory, computed before the seal.
struct Verified {
    inventory: Vec<CaptureInventoryEntry>,
    packed_length: u64,
    page_granule: u32,
    regions: u32,
    ram_stream: Sha256Digest,
    /// Actual staged bytes charged against the reservation, before the seal.
    staged_bytes: u64,
    map: Arc<StreamRoot>,
}

struct DiskIdentityResult {
    inventory: Vec<CaptureInventoryEntry>,
    bytes: u64,
    maps: Vec<(vm_spec::BlockId, Arc<StreamRoot>)>,
    stats: Vec<vm_spec::capture::CaptureDiskStats>,
}

fn read_disk_map(file: File) -> io::Result<StreamRoot> {
    let maximum = MAX_ROOT_BYTES as u64;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "disk map exceeds its bound",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    let map = StreamRoot::decode(&bytes).map_err(io::Error::other)?;
    map.validate_role(StreamRole::Disk)
        .map_err(io::Error::other)?;
    if map.canonical_bytes().map_err(io::Error::other)? != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "disk map is not canonical",
        ));
    }
    Ok(map)
}

/// A token tripped by cancel or stop for blocking stages; the watcher ends
/// with the stage (`JoinHandle::abort`).
fn abort_token(
    cancel: &CancellationToken,
    stop: &CancellationToken,
) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let abort = CancellationToken::new();
    let watcher = {
        let (abort, cancel, stop) = (abort.clone(), cancel.clone(), stop.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => abort.cancel(),
                () = stop.cancelled() => abort.cancel(),
                () = abort.cancelled() => {}
            }
        })
    };
    (abort, watcher)
}

/// What a `PrepareCapture` result proves about worker ownership. Only a
/// definitive refusal proves the worker holds nothing; any unanswered or
/// unexpected answer may follow an admission that retained every output and
/// the pin, so it is reconciled before abandonment or release. A worker
/// `RequestConflict` means it already knows this capture.
fn prepared_ownership(result: &Result<CommandOutcome, NativeError>) -> WorkerPreparation {
    match result {
        Ok(CommandOutcome::CapturePrepared { .. }) => WorkerPreparation::Prepared,
        Err(NativeError::Rejected(rejection))
            if *rejection != LifecycleRejection::RequestConflict =>
        {
            WorkerPreparation::Absent
        }
        Err(NativeError::Unsupported(_)) => WorkerPreparation::Absent,
        Ok(_)
        | Err(
            NativeError::Rejected(_)
            | NativeError::WorkerLost(_)
            | NativeError::Uncertain(_)
            | NativeError::Stopped,
        ) => WorkerPreparation::Uncertain,
    }
}

impl LiveCoordinator {
    #[cfg(test)]
    pub(crate) fn retained_identity_roots_for_tests(
        &self,
    ) -> (Option<Sha256Digest>, Vec<Sha256Digest>) {
        let Some(context) = &self.capture else {
            return (None, Vec::new());
        };
        let ram = context
            .baseline
            .lock()
            .unwrap()
            .identified()
            .map(|anchor| anchor.stream);
        let disks = context
            .disk_baselines
            .lock()
            .unwrap()
            .values()
            .map(|map| map.id())
            .collect();
        (ram, disks)
    }
    // ------------------------------------------------------------ preflight

    /// Asynchronous admission preflight, before any effect: native provider
    /// inventory and the held writable sources' identity, type and length.
    /// libvm's pre-freeze reservation is checked by the plan floor and then
    /// against actual staged allocation at verification ([`staging_budget`]),
    /// never against a second allocation sample of the still running guest.
    pub(crate) async fn check_capture(&self, plan: &CapturePlan) -> Result<Eligibility, LiveError> {
        if let CaptureMode::Hibernate { directory } = &plan.mode {
            let expected = self.capture.as_ref().map(|context| {
                context
                    .data_dir
                    .join("hibernation")
                    .join(plan.capture_id.as_str())
            });
            if expected.as_ref() != Some(directory) {
                return Ok(Eligibility::Rejected(
                    LiveRejectionReason::InvalidPlan,
                    "Save directory does not belong to this machine; retry hibernation".into(),
                ));
            }
        }
        if let Some(subject) = self.native_inventory(&plan.capture_id, true).await {
            return self.device_rejection(LiveOperation::Capture, subject);
        }
        let sources = match self.machine.capture_sources().await {
            Ok(sources) => sources,
            Err(error) => {
                tracing::warn!(%error, "capture sources unavailable");
                return self.device_rejection(
                    LiveOperation::Capture,
                    LiveDeviceSubject::GuestProfile {
                        profile: "capture-sources-unavailable".into(),
                    },
                );
            }
        };
        for disk in &plan.disks {
            let Some(source) = sources
                .iter()
                .find(|source| source.disk_index == disk.attachment_index && source.writable)
            else {
                return Ok(Eligibility::Rejected(
                    LiveRejectionReason::ConfigurationMismatch,
                    format!(
                        "writable attachment {} has no held source",
                        disk.attachment_index
                    ),
                ));
            };
            let metadata = match source.file.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    return Ok(Eligibility::Rejected(
                        LiveRejectionReason::ConfigurationMismatch,
                        format!(
                            "inspect writable attachment {}: {error}",
                            disk.attachment_index
                        ),
                    ))
                }
            };
            if !metadata.is_file() {
                return self.device_rejection(
                    LiveOperation::Capture,
                    LiveDeviceSubject::GuestProfile {
                        profile: "raw-device-attachment".into(),
                    },
                );
            }
            if metadata.len() != disk.length {
                return Ok(Eligibility::Rejected(
                    LiveRejectionReason::ConfigurationMismatch,
                    format!(
                        "writable attachment {} length differs from the plan",
                        disk.attachment_index
                    ),
                ));
            }
        }
        Ok(Eligibility::Eligible)
    }

    /// The second capture barrier is explicit. Identical authorizations are
    /// harmless; foreign runs, premature writes and failed captures are refused.
    pub(crate) fn control_hibernate_capture(
        &self,
        envelope: &vm_spec::lifecycle::LiveCommandEnvelope,
        operation: &LiveId,
        authorize_write: bool,
    ) -> Result<HibernateCaptureStatus, String> {
        let mut inner = self.lock();
        if &envelope.machine_id != inner.journal.machine_id()
            || &envelope.run_id != inner.journal.run_id()
        {
            return Err("Hibernation request belongs to another machine run".into());
        }
        let facts = inner
            .journal
            .capture_mut(operation)
            .ok_or("Hibernation capture is unknown; inspect the machine and retry")?;
        let status = facts
            .hibernation
            .as_ref()
            .ok_or("This capture does not save the machine in place")?;
        if authorize_write {
            if !facts.hibernate_write && status.phase != HibernateCapturePhase::AwaitingWrite {
                return Err("The machine is not waiting for its storage check".into());
            }
            if status.phase == HibernateCapturePhase::Failed {
                return Err("Hibernation failed; inspect the machine and retry".into());
            }
            facts.hibernate_write = true;
            facts.hibernate_changed.notify_one();
        }
        Ok(status.clone())
    }

    fn signal_hibernate_release(&self, operation: &LiveId) -> bool {
        let mut inner = self.lock();
        let Some(record) = inner.journal.operation_mut(operation) else {
            return false;
        };
        let Some(facts) = record.capture.as_mut() else {
            return false;
        };
        if facts.hibernation.is_none() || record.phase == Phase::Settled {
            return false;
        }
        facts.hibernate_changed.notify_one();
        true
    }

    async fn await_hibernate_authorization(&self, run: &Run, commit: bool) -> Result<(), Abort> {
        let deadline = tokio::time::Instant::now() + self.timeouts.native;
        loop {
            let (ready, changed) = {
                let mut inner = self.lock();
                let facts = inner.journal.capture_mut(&run.operation).ok_or_else(|| {
                    Abort::Failed(failure(
                        LiveFailureCode::Cancelled,
                        LiveStage::CaptureSeal,
                        "Hibernation capture was lost; retry",
                    ))
                })?;
                (
                    if commit {
                        facts.hibernate_release == Some(CaptureReleaseDisposition::Published)
                    } else {
                        facts.hibernate_write
                    },
                    facts.hibernate_changed.clone(),
                )
            };
            if ready {
                return Ok(());
            }
            self.checkpoint(run, LiveStage::CaptureSeal)?;
            tokio::select! {
                () = changed.notified() => {}
                () = run.cancel.cancelled() => { self.checkpoint(run, LiveStage::CaptureSeal)?; }
                () = self.stop.cancelled() => return Err(Abort::Stopped),
                () = tokio::time::sleep_until(deadline) => {
                    return Err(Abort::Failed(failure(LiveFailureCode::DeadlineExceeded,
                        LiveStage::CaptureSeal, "Hibernation authorization timed out; retry")));
                }
            }
        }
    }

    async fn hibernate_stages(&self, run: &mut Run) -> Result<(), Abort> {
        self.stage_prepare(run).await?;
        self.stage_pause(run).await?;
        self.stage_flush(run).await?;
        let pid = self.machine.worker_process_id().ok_or_else(|| {
            Abort::Failed(failure(
                LiveFailureCode::MemoryEstimateFailed,
                LiveStage::CaptureMemory,
                "Could not inspect the paused worker's memory; retry hibernation",
            ))
        })?;
        let estimated = tokio::task::spawn_blocking(move || {
            let text = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;
            parse_populated_memory_estimate(&text)
        })
        .await
        .map_err(|error| {
            Abort::Failed(failure(
                LiveFailureCode::MemoryEstimateFailed,
                LiveStage::CaptureMemory,
                error.to_string(),
            ))
        })?
        .map_err(|error| {
            Abort::Failed(failure(
                LiveFailureCode::MemoryEstimateFailed,
                LiveStage::CaptureMemory,
                format!("Could not inspect paused memory: {error}; retry hibernation"),
            ))
        })?;
        if self.machine.worker_process_id() != Some(pid) {
            return Err(Abort::Failed(failure(
                LiveFailureCode::WorkerLost,
                LiveStage::CaptureMemory,
                "The machine ended during its memory check",
            )));
        }
        if let Some(status) = self
            .lock()
            .journal
            .capture_mut(&run.operation)
            .and_then(|facts| facts.hibernation.as_mut())
        {
            status.phase = HibernateCapturePhase::AwaitingWrite;
            status.populated_memory_estimate_bytes = Some(estimated);
        }
        self.await_hibernate_authorization(run, false).await?;
        self.checkpoint(run, LiveStage::CaptureMemory)?;
        if let Some(status) = self
            .lock()
            .journal
            .capture_mut(&run.operation)
            .and_then(|facts| facts.hibernation.as_mut())
        {
            status.phase = HibernateCapturePhase::Writing;
        }
        self.stage_execution_and_memory(run).await?;
        let cut = self.verify_hibernate_cut(run).await?;
        let Some(CommandOutcome::MemoryCaptured {
            mode,
            full_reason,
            stats,
            ..
        }) = run.native_memory.as_ref()
        else {
            return Err(Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureVerify,
                "The saved machine lacks its memory receipt; retry hibernation",
            )));
        };
        let memory = vm_spec::capture::HibernateMemoryReceipt {
            mode: *mode,
            full_reason: *full_reason,
            stats: stats.as_ref().clone(),
        };
        tracing::info!(
            save_id = %run.operation,
            memory_mode = ?memory.mode,
            memory_full_reason = ?memory.full_reason,
            memory_seed_method = ?memory.stats.seed_method,
            memory_full_bytes_written = memory.stats.full_bytes_written,
            memory_baseline_bytes_written = memory.stats.baseline_bytes_written,
            memory_overlay_bytes_written = memory.stats.overlay_bytes_written,
            memory_layout_bytes_written = memory.stats.layout_bytes_written,
            memory_live_bytes_read = memory.stats.live_bytes_read,
            memory_baseline_bytes_read = memory.stats.baseline_bytes_read,
            memory_materialization_dirty_pages = memory.stats.materialization_dirty_pages,
            memory_live_pages_classified = memory.stats.live_pages_classified,
            "hibernation memory materialized"
        );
        let status = HibernateCaptureStatus {
            phase: HibernateCapturePhase::Prepared,
            populated_memory_estimate_bytes: Some(estimated),
            cut: Some(Box::new(cut)),
            memory: Some(memory),
            failure: None,
        };
        status.validate().map_err(|error| {
            Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureVerify,
                error,
            ))
        })?;
        self.write_hibernate_journal(run, &status, false).await?;
        self.checkpoint(run, LiveStage::CaptureSeal)?;
        {
            let mut inner = self.lock();
            if let Some(record) = inner.journal.operation_mut(&run.operation) {
                record.phase = Phase::HibernatePrepared;
                if let Some(facts) = record.capture.as_mut() {
                    facts.hibernation = Some(status);
                }
            }
        }
        self.await_hibernate_authorization(run, true).await
    }

    async fn verify_hibernate_cut(&self, run: &Run) -> Result<HibernateCut, Abort> {
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureVerify,
                message,
            ))
        };
        if !(run.facts.workloads_frozen
            && run.facts.vcpus_paused
            && run.facts.devices_quiesced
            && run.facts.host_writers_drained
            && run.facts.host_flush_completed
            && run.facts.memory_state_sealed)
        {
            return Err(fail(
                "The save lacks complete pause and closed-writer evidence".into(),
            ));
        }
        let Some(CommandOutcome::MemoryCaptured {
            memory_generation,
            predecessor_generation,
            identity_policy,
            changes,
            stats,
            ram,
            layout,
            ..
        }) = run.native_memory.as_ref()
        else {
            return Err(fail("The save has no memory receipt".into()));
        };
        if *identity_policy != CaptureIdentityPolicy::None
            || *changes != crate::virt::lifecycle::CaptureRamChangesAuthority::None
            || stats.identity_bytes_hashed != 0
            || stats.whole_file_bytes_hashed != 0
            || stats.map_nodes_written != 0
        {
            return Err(fail(
                "The in-place save unexpectedly computed content identity".into(),
            ));
        }
        let binding = run
            .binding
            .as_ref()
            .ok_or_else(|| fail("Missing execution binding".into()))?;
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("Missing save directory".into()))?;
        let outputs = run
            .outputs
            .ok_or_else(|| fail("Missing output identities".into()))?;
        let context = self
            .capture
            .as_ref()
            .ok_or_else(|| fail("Missing launch binding".into()))?;
        let sources = self
            .machine
            .capture_sources()
            .await
            .map_err(|error| fail(error.to_string()))?;
        let paths = context.disk_paths.clone();
        let configuration = run.plan.configuration.clone();
        let expected_ram = *ram;
        let expected_layout = *layout;
        let (saved_files, writable_disks, geometry) =
            tokio::task::spawn_blocking(move || -> io::Result<_> {
                let seal = |role: CaptureRole,
                            saved_role: HibernateSavedFileRole,
                            expected: OutputIdentity| {
                    let (file, facts) = staging.seal_owned(&role)?;
                    if (facts.device, facts.inode) != (expected.device, expected.inode) {
                        return Err(io::Error::other(
                            "saved file differs from its prepared descriptor",
                        ));
                    }
                    file.sync_all()?;
                    Ok(HibernateSavedFile {
                        role: saved_role,
                        file: hibernate_file_binding(
                            &file,
                            staging.path().join(role.relative_path()),
                        )?,
                    })
                };
                let saved_files = [
                    seal(
                        CaptureRole::Ram,
                        HibernateSavedFileRole::Memory,
                        outputs.ram,
                    )?,
                    seal(
                        CaptureRole::Layout,
                        HibernateSavedFileRole::MemoryLayout,
                        outputs.layout,
                    )?,
                    seal(
                        CaptureRole::Execution,
                        HibernateSavedFileRole::ExecutionState,
                        outputs.execution,
                    )?,
                    seal(
                        CaptureRole::Devices,
                        HibernateSavedFileRole::DeviceState,
                        outputs.devices,
                    )?,
                ];
                let (layout_file, facts) = staging.open_owned(&CaptureRole::Layout)?;
                if facts.length > MAX_LAYOUT_BYTES
                    || (facts.device, facts.inode, facts.length)
                        != (
                            expected_layout.device,
                            expected_layout.inode,
                            expected_layout.length,
                        )
                    || saved_files[0].file.size != expected_ram.length
                {
                    return Err(io::Error::other(
                        "saved RAM/layout differs from native completion",
                    ));
                }
                let mut bytes = Vec::new();
                layout_file
                    .take(MAX_LAYOUT_BYTES + 1)
                    .read_to_end(&mut bytes)?;
                let geometry = parse_layout(&bytes)?;
                if geometry.packed_length != saved_files[0].file.size {
                    return Err(io::Error::other("saved RAM is incomplete"));
                }
                let mut disks = Vec::new();
                for (index, attachment) in configuration.attachments.iter().enumerate() {
                    if attachment.read_only {
                        continue;
                    }
                    let index_u32 = u32::try_from(index).map_err(io::Error::other)?;
                    let source = sources
                        .iter()
                        .find(|source| source.disk_index == index_u32 && source.writable)
                        .ok_or_else(|| io::Error::other("writable disk descriptor is missing"))?;
                    source.file.sync_all()?;
                    let path = paths
                        .get(index)
                        .ok_or_else(|| io::Error::other("disk path is missing"))?;
                    let file = hibernate_file_binding(&source.file, path.clone())?;
                    let parent = path
                        .parent()
                        .ok_or_else(|| io::Error::other("disk parent is missing"))?;
                    let directory = nix::fcntl::open(
                        parent,
                        nix::fcntl::OFlag::O_RDONLY
                            | nix::fcntl::OFlag::O_DIRECTORY
                            | nix::fcntl::OFlag::O_NOFOLLOW
                            | nix::fcntl::OFlag::O_CLOEXEC,
                        nix::sys::stat::Mode::empty(),
                    )?;
                    nix::unistd::fsync(&directory)?;
                    disks.push(HibernateDiskBinding {
                        role: attachment.role,
                        attachment_index: index_u32,
                        block_id: attachment.block_id.clone(),
                        file,
                    });
                }
                staging.sync_hibernate_record("request.json")?;
                Ok((saved_files, disks, geometry))
            })
            .await
            .map_err(|error| fail(error.to_string()))?
            .map_err(|error| {
                Abort::Failed(io_capture_failure(
                    &error,
                    LiveStage::CaptureVerify,
                    LiveFailureCode::CaptureVerificationFailed,
                ))
            })?;
        let cut = HibernateCut {
            version: HIBERNATE_CUT_VERSION,
            save_id: run.plan.capture_id.clone(),
            machine_id: run.plan.machine_id.clone(),
            ended_run_id: run.plan.run_id.clone(),
            freeze_operation_id: run
                .borrowed
                .as_ref()
                .map_or_else(|| run.operation.clone(), |pause| pause.operation_id.clone()),
            freeze_epoch: run
                .freeze_epoch
                .ok_or_else(|| fail("Missing guest freeze epoch".into()))?,
            configuration: run.plan.configuration.clone(),
            binding: CaptureStateBinding {
                live_state_schema: binding.live_state_schema.clone(),
                architecture: binding.architecture.clone(),
                profile: digest(binding.profile),
                topology: digest(binding.topology),
                ram_layout: digest(binding.ram_layout),
                source_run: run.plan.run_id.clone(),
                pause_generation: NonZeroU64::new(binding.pause_generation.get())
                    .ok_or_else(|| fail("Missing pause generation".into()))?,
                capture: run.plan.capture_id.clone(),
            },
            materialization_generation: NonZeroU64::new(*memory_generation)
                .ok_or_else(|| fail("Missing memory generation".into()))?,
            predecessor_generation: *predecessor_generation,
            packed_length: geometry.packed_length,
            page_granule: geometry.page_granule,
            regions: geometry.regions,
            saved_files,
            writable_disks,
        };
        cut.validate().map_err(fail)?;
        Ok(cut)
    }

    async fn write_hibernate_journal(
        &self,
        run: &Run,
        status: &HibernateCaptureStatus,
        committed: bool,
    ) -> Result<(), Abort> {
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::SealFailed,
                LiveStage::CaptureSeal,
                message,
            ))
        };
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("Missing save directory".into()))?;
        let pid = self
            .machine
            .worker_process_id()
            .ok_or_else(|| fail("Saved worker ended before commit".into()))?;
        let pid_i32 = i32::try_from(pid).map_err(|error| fail(error.to_string()))?;
        let started = utils::process::start_time(pid_i32)
            .map_err(|error| fail(error.to_string()))?
            .ok_or_else(|| fail("Saved worker identity is unavailable".into()))?;
        let bytes = serde_json::to_vec(&HibernateJournal {
            version: 1,
            machine_id: &run.plan.machine_id,
            run_id: &run.plan.run_id,
            save_id: &run.plan.capture_id,
            worker_pid: pid,
            worker_started_at: started,
            status,
        })
        .map_err(|error| fail(error.to_string()))?;
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            let (name, temporary) = if committed {
                ("committed.json", "committed.tmp")
            } else {
                ("record.json", "record.tmp")
            };
            match staging.commit_record(name, temporary, &bytes)? {
                RecordCommit::Complete => staging.sync_hibernate_record(name),
                RecordCommit::Uncertain(error) => Err(error),
            }
        })
        .await
        .map_err(|error| fail(error.to_string()))?
        .map_err(|error| {
            Abort::Failed(io_capture_failure(
                &error,
                LiveStage::CaptureSeal,
                LiveFailureCode::SealFailed,
            ))
        })
    }

    /// No path after the manager's durable commit may resume or thaw.
    async fn finish_hibernate(&self, run: Run) {
        let status = self
            .lock()
            .journal
            .capture_mut(&run.operation)
            .and_then(|facts| facts.hibernation.clone());
        let Some(status) = status else { return };
        if let Err(error) = self.write_hibernate_journal(&run, &status, true).await {
            let cause = match error {
                Abort::Failed(cause) => cause,
                Abort::Stopped => failure(
                    LiveFailureCode::Stopped,
                    LiveStage::CaptureSeal,
                    "Monitor is stopping",
                ),
            };
            // The catalog already committed. Retain the parked worker and files
            // for exact-run recovery, never enter the precommit unwind.
            self.complete_hibernate_release(&run.operation, Err(cause));
            return;
        }
        self.gate.seal();
        let mut result = self.machine.hibernate_stop().await.map_err(|error| {
            failure(
                LiveFailureCode::ReleaseFailed,
                LiveStage::CaptureRelease,
                format!("Could not release saved machine: {error}; retry stopping its old run"),
            )
        });
        if result.is_ok() {
            if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                if let Some(status) = facts.hibernation.as_mut() {
                    status.phase = HibernateCapturePhase::Released;
                }
                facts.worker = WorkerPreparation::Absent;
            }
            if let Err(error) = self
                .store
                .set_vm_state(protocol::v1::VmState::Hibernated, "machine hibernated")
            {
                tracing::error!(%error, "publish hibernation terminal state");
            }
            if let Some(staging) = run.staging.clone() {
                result = match tokio::task::spawn_blocking(move || staging.remove_hibernate_journal()).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(io_capture_failure(&error, LiveStage::CaptureRelease,
                        LiveFailureCode::ReleaseFailed)),
                    Err(error) => Err(failure(LiveFailureCode::ReleaseFailed, LiveStage::CaptureRelease,
                        format!("Could not remove the completed hibernation journal: {error}; retry old-run cleanup"))),
                };
            }
        }
        self.complete_hibernate_release(&run.operation, result);
    }

    fn complete_hibernate_release(&self, operation: &LiveId, outcome: Result<(), LiveFailure>) {
        let state = self
            .store
            .live_snapshot()
            .map_or(VmLifecycleState::Stopping, |snapshot| snapshot.state);
        let mut inner = self.lock();
        let disposition = inner
            .journal
            .capture_mut(operation)
            .and_then(|facts| facts.hibernate_release);
        let Some(disposition) = disposition else {
            return;
        };
        let result = match outcome {
            Ok(()) => {
                if let Some(facts) = inner.journal.capture_mut(operation) {
                    facts.release = CaptureReleaseState::Released {
                        disposition,
                        baseline_retained: false,
                    };
                }
                LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released {
                    released: CaptureReleased {
                        operation_id: operation.clone(),
                        disposition,
                        baseline_retained: false,
                        state,
                    },
                })
            }
            Err(cause) => LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Failed {
                failed: ReleaseFailed { cause, state },
            }),
        };
        for request in inner.journal.take_release_requests(operation) {
            inner.journal.complete(&request, result.clone());
        }
    }

    // ------------------------------------------------------------- pipeline

    pub(crate) async fn run_capture(
        self: Arc<Self>,
        operation: LiveId,
        borrowed: Option<CurrentPause>,
    ) {
        let started = {
            let inner = self.lock();
            inner.journal.operation(&operation).and_then(|record| {
                record.capture.as_ref().map(|facts| {
                    (
                        facts.plan.clone(),
                        record.cancel.clone(),
                        inner.held.clone(),
                    )
                })
            })
        };
        let Some((plan, cancel, identity)) = started else {
            tracing::error!(operation = %operation, "admitted capture has no journal record");
            return;
        };
        let mut run = Run {
            operation,
            cut: borrowed.as_ref().map(|current| current.token.clone()),
            freeze_epoch: borrowed.as_ref().map(|current| current.freeze_epoch),
            pause: if borrowed.is_some() {
                PauseState::Borrowed
            } else {
                PauseState::Untouched
            },
            borrowed,
            plan,
            cancel,
            identity,
            started: now_ms(),
            staging: None,
            request_digest: None,
            outputs: None,
            worker: WorkerPreparation::Absent,
            facts: Facts::default(),
            binding: None,
            memory: None,
            owned_cut: None,
            inventory: Vec::new(),
            native_memory: None,
            resolved_map: None,
            pending_disks: Vec::new(),
            continued: None,
            source_continued: false,
            disk_freeze_attempted: false,
            disk_receipts: Vec::new(),
            disk_stats: Vec::new(),
            disk_maps: Vec::new(),
        };
        if !run.plan.mode.clones_disks() {
            match self.hibernate_stages(&mut run).await {
                Ok(()) => self.finish_hibernate(run).await,
                Err(abort) => self.unwind(run, abort).await,
            }
            return;
        }
        match self.capture_stages(&mut run).await {
            Ok(evidence) => self.seal(run, evidence).await,
            Err(abort) => self.unwind(run, abort).await,
        }
    }

    async fn capture_stages(&self, run: &mut Run) -> Result<CompletedRecord, Abort> {
        self.stage_prepare(run).await?;
        self.stage_pause(run).await?;
        self.stage_flush(run).await?;
        self.stage_disks(run).await?;
        if run.plan.identity_policy != CaptureIdentityPolicy::None {
            self.stage_freeze_disks(run).await?;
        }
        self.stage_execution_and_memory(run).await?;
        if run.plan.identity_policy == CaptureIdentityPolicy::None {
            let owned = self.verify_owned_cut(run).await?;
            run.owned_cut = Some(owned.clone());
            return Ok(CompletedRecord::Owned(Box::new(owned)));
        }
        let staged = self.stage_verify(run).await?;
        staging_budget(run.plan.reservation.staging_bytes, staged).map_err(Abort::Failed)?;
        if !run.pending_disks.is_empty() {
            self.stage_cut(run, staged).await?;
            let staging = run.staging.clone().ok_or_else(|| {
                Abort::Failed(failure(
                    LiveFailureCode::StagingFailed,
                    LiveStage::CaptureVerify,
                    "capture staging is not prepared",
                ))
            })?;
            match self.accept_baseline(run, &staging).await {
                Ok(()) => {}
                Err(Abort::Stopped) => return Err(Abort::Stopped),
                Err(Abort::Failed(cause)) => {
                    tracing::warn!(operation = %run.operation, %cause, "baseline acceptance failed before disk identity");
                    self.abandon(run).await?;
                }
            }
            let finish = self.source_finish(run).await.ok_or(Abort::Stopped)?;
            let continuation = match &finish {
                Finish::Running(continuation) | Finish::Paused(_, continuation) => {
                    continuation.clone()
                }
                Finish::Error(cause) => CaptureContinuation::ResumeFailed {
                    failure: cause.clone(),
                    state: VmLifecycleState::Error,
                },
            };
            self.write_source_record(run, &continuation).await;
            run.source_continued = true;
            run.continued = Some(finish.clone());
            if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                facts.continuation = continuation;
            }
            self.finish_projection(run, finish, false);
            self.stage_disk_identity(run, staged).await?;
        }
        run.evidence(CaptureRecordOutcome::Coherent, None)
            .map(|evidence| CompletedRecord::Identified(Box::new(evidence)))
            .ok_or_else(|| {
                Abort::Failed(failure(
                    LiveFailureCode::CaptureVerificationFailed,
                    LiveStage::CaptureVerify,
                    "capture has no request record",
                ))
            })
    }

    /// Stop and cancel are observed between stages; neither interrupts a
    /// native or blocking owner mid-flight.
    fn checkpoint(&self, run: &Run, stage: LiveStage) -> Result<(), Abort> {
        if self.stop.is_cancelled() {
            return Err(Abort::Stopped);
        }
        if run.cancel.is_cancelled() {
            return Err(Abort::Failed(failure(
                LiveFailureCode::Cancelled,
                stage,
                "capture cancelled",
            )));
        }
        Ok(())
    }

    fn capture_stage(&self, run: &Run, stage: LiveStage) {
        if run.source_continued {
            tracing::info!(operation = %run.operation, stage = stage.as_str(), "capture stage");
            return;
        }
        self.publish_stage(
            &run.operation,
            &run.operation,
            LiveCommandKind::Capture,
            stage,
            matches!(&run.continued, Some(Finish::Running(_))),
        );
    }

    async fn stage_prepare(&self, run: &mut Run) -> Result<(), Abort> {
        self.checkpoint(run, LiveStage::CapturePrepare)?;
        let staging_failed = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::StagingFailed,
                LiveStage::CapturePrepare,
                message,
            ))
        };
        let Some(context) = self.capture.clone() else {
            return Err(staging_failed("this run has no capture binding".into()));
        };
        let bytes = run.plan.canonical_bytes().map_err(staging_failed)?;
        let created = tokio::task::spawn_blocking({
            let context = context.clone();
            let capture = run.plan.capture_id.clone();
            let map_node_store = run.plan.map_node_store.clone();
            let run_identity = run.plan.identity_policy;
            let mode = run.plan.mode.clone();
            move || -> io::Result<_> {
                let staging = match &mode {
                    CaptureMode::Hibernate { directory } => {
                        CaptureStaging::create_hibernate(&context.data_dir, &capture, directory)?
                    }
                    _ => CaptureStaging::create(&context.data_dir, &capture)?,
                };
                let prepared = (|| -> io::Result<_> {
                    let request = if run_identity == CaptureIdentityPolicy::None {
                        staging.write_owned_request(&bytes)?;
                        None
                    } else {
                        staging.set_node_store(map_node_store.as_deref())?;
                        Some(staging.write_request(&bytes)?)
                    };
                    let files = CaptureOutputFiles {
                        execution: staging.create_output(&CaptureRole::Execution)?,
                        devices: staging.create_output(&CaptureRole::Devices)?,
                        ram: staging.create_output(&CaptureRole::Ram)?,
                        layout: staging.create_output(&CaptureRole::Layout)?,
                        changes: staging.create_output(&CaptureRole::RamChanges)?,
                        pin: File::from(context.lease.try_clone()?),
                    };
                    Ok((request, files))
                })();
                match prepared {
                    Ok((request, files)) => Ok((staging, request, files)),
                    Err(error) => {
                        if !mode.clones_disks() {
                            if let Err(cleanup) = staging.remove_hibernate() {
                                tracing::error!(%cleanup, "remove incomplete save directory");
                            }
                        }
                        Err(error)
                    }
                }
            }
        })
        .await
        .map_err(|error| staging_failed(format!("staging task failed: {error}")))?;
        let (staging, request, files) = created.map_err(|error| {
            Abort::Failed(io_capture_failure(
                &error,
                LiveStage::CapturePrepare,
                LiveFailureCode::StagingFailed,
            ))
        })?;
        tracing::info!(operation = %run.operation, path = %staging.path().display(), "capture staging and request.json are written");
        run.staging = Some(Arc::new(staging));
        run.request_digest = request;

        let identities = (|| -> io::Result<_> {
            Ok((
                CaptureOutputIdentities {
                    execution: OutputIdentity::of(&files.execution)?,
                    devices: OutputIdentity::of(&files.devices)?,
                    ram: OutputIdentity::of(&files.ram)?,
                    layout: OutputIdentity::of(&files.layout)?,
                    changes: OutputIdentity::of(&files.changes)?,
                },
                OutputIdentity::of(&files.pin)?,
            ))
        })();
        let (outputs, pin) = identities
            .map_err(|error| staging_failed(format!("inspect capture outputs: {error}")))?;
        if (pin.device, pin.inode) != (context.launch.device, context.launch.inode) {
            return Err(staging_failed(
                "inherited launch lease differs from its binding".into(),
            ));
        }
        let pause = match (&run.plan.pause, &run.borrowed) {
            (CapturePauseAuthority::Acquire, _) => CapturePauseSource::Acquire,
            (CapturePauseAuthority::Borrow { .. }, Some(current)) => {
                let generation = NativePauseGeneration::new(current.token.generation.get())
                    .ok_or_else(|| staging_failed("borrowed pause has no generation".into()))?;
                CapturePauseSource::Borrow {
                    operation: wire_uuid(&current.operation_id),
                    generation,
                }
            }
            (CapturePauseAuthority::Borrow { .. }, None) => {
                return Err(staging_failed("borrowed pause is not current".into()))
            }
        };
        let command = LifecycleCommand::PrepareCapture {
            operation: wire_uuid(&run.operation),
            preparation: CapturePreparation {
                outputs,
                pin,
                pause,
                policy: run.plan.policy,
                identity_policy: match run.plan.identity_policy {
                    CaptureIdentityPolicy::None => CaptureIdentityPolicy::None,
                    CaptureIdentityPolicy::Full => CaptureIdentityPolicy::Full,
                    _ if context
                        .baseline
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .identified()
                        .is_some() =>
                    {
                        CaptureIdentityPolicy::SinceAnchor
                    }
                    _ => CaptureIdentityPolicy::Full,
                },
                dirty_crossover_percent: run.plan.dirty_crossover_percent,
                baseline: if run.plan.identity_policy == CaptureIdentityPolicy::None {
                    None
                } else {
                    context
                        .baseline
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .identified()
                        .map(|baseline| Digest32(*baseline.stream.as_bytes()))
                },
                resume_policy: match run.plan.resume_policy {
                    // Success never continues Hibernate. On failure the native
                    // owner must allow rollback of the pause we acquired.
                    _ if !run.plan.mode.clones_disks() && run.borrowed.is_none() => {
                        NativeResumePolicy::ResumeIfAcquired
                    }
                    CaptureResumePolicy::ResumeIfAcquired => NativeResumePolicy::ResumeIfAcquired,
                    CaptureResumePolicy::Preserve => NativeResumePolicy::Preserve,
                },
                binding: context.digests,
            },
            timeout: self.timeouts.native,
        };
        let result = self
            .native_with_rights(self.native_request(&run.operation, command), || {
                Ok(LifecycleRights::CaptureOutputs(CaptureOutputFiles {
                    execution: files.execution.try_clone()?,
                    devices: files.devices.try_clone()?,
                    ram: files.ram.try_clone()?,
                    layout: files.layout.try_clone()?,
                    changes: files.changes.try_clone()?,
                    pin: files.pin.try_clone()?,
                }))
            })
            .await;
        // The worker owns the writers now; the monitor keeps no writable copy.
        drop(files);
        self.record_preparation(run, prepared_ownership(&result));
        match result {
            Ok(CommandOutcome::CapturePrepared {
                outputs: prepared,
                pin: prepared_pin,
            }) => {
                // A prepared capture is retained even if it is refused below.
                if prepared != outputs || prepared_pin != pin {
                    return Err(staging_failed(
                        "worker prepared other capture output identities".into(),
                    ));
                }
                run.outputs = Some(outputs);
                Ok(())
            }
            Ok(outcome) => Err(staging_failed(format!(
                "unexpected native prepare outcome {outcome:?}"
            ))),
            Err(error) => Err(Abort::native(
                error,
                LiveFailureCode::StagingFailed,
                LiveStage::CapturePrepare,
            )),
        }
    }

    async fn stage_pause(&self, run: &mut Run) -> Result<(), Abort> {
        if run.pause == PauseState::Borrowed {
            // Borrowed: the exact current freeze must still be positively
            // observed; nothing is refrozen, thawed or re-paused.
            let epoch = run.freeze_epoch.ok_or_else(|| {
                Abort::Failed(failure(
                    LiveFailureCode::FreezeFailed,
                    LiveStage::GuestFreeze,
                    "borrowed pause has no freeze epoch",
                ))
            })?;
            let frozen = self
                .store
                .live_snapshot()
                .ok()
                .and_then(|snapshot| snapshot.guest_lifecycle)
                .and_then(|status| guest_observation(&status).ok())
                .is_some_and(|observation| observation.positively_frozen(epoch));
            if !frozen {
                return Err(Abort::Failed(failure(
                    LiveFailureCode::FreezeFailed,
                    LiveStage::GuestFreeze,
                    "borrowed pause lacks positive frozen-workload evidence",
                )));
            }
            run.facts.workloads_frozen = true;
            return self.checkpoint(run, LiveStage::GuestFreeze);
        }

        self.capture_stage(run, LiveStage::MonitorDrain);
        let drain_deadline = tokio::time::Instant::now() + self.timeouts.drain;
        match self.gate.drain(drain_deadline).await {
            Ok(()) => {}
            Err(DrainError::Sealed) => return Err(Abort::Stopped),
            Err(DrainError::TimedOut { outstanding }) => {
                return Err(Abort::Failed(failure(
                    LiveFailureCode::DrainTimedOut,
                    LiveStage::MonitorDrain,
                    format!("{outstanding} admitted session/mutation operations did not settle"),
                )))
            }
        }
        self.checkpoint(run, LiveStage::MonitorDrain)?;
        let Some(identity) = run.identity.clone() else {
            return Err(Abort::Failed(failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::GuestFreeze,
                "capture admitted without a held guest identity",
            )));
        };
        let snapshot = self.store.live_snapshot().map_err(|error| {
            Abort::Failed(failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::GuestFreeze,
                error.to_string(),
            ))
        })?;
        if let Some(rejection) = snapshot.guest_rejection {
            return Err(Abort::Failed(failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::GuestFreeze,
                rejection,
            )));
        }
        if snapshot.observed_identity.as_ref() != Some(&identity) {
            return Err(Abort::Failed(failure(
                LiveFailureCode::GuestIdentityMismatch,
                LiveStage::GuestFreeze,
                "guest identity changed after capture admission",
            )));
        }
        let Some(epoch) = self.allocate_epoch(&run.operation, &snapshot) else {
            return Err(Abort::Failed(failure(
                LiveFailureCode::FreezeFailed,
                LiveStage::GuestFreeze,
                "freeze epoch exhausted",
            )));
        };
        self.capture_stage(run, LiveStage::GuestFreeze);
        run.pause = PauseState::Frozen(epoch);
        run.freeze_epoch = Some(epoch);
        let reference = self.freeze_ref(&run.operation, epoch);
        let (frozen, clock_profile) = match self
            .guest_freeze(&identity, &reference, LiveStage::GuestFreeze)
            .await
        {
            Ok(frozen) => frozen,
            Err(GuestError::Stopped) => return Err(Abort::Stopped),
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                return Err(Abort::Failed(cause))
            }
        };
        run.facts.workloads_frozen = frozen.positively_frozen(epoch);
        self.checkpoint(run, LiveStage::NativePause)?;

        self.capture_stage(run, LiveStage::NativePause);
        run.pause = PauseState::NativePending(epoch);
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::Pause {
                    operation: wire_uuid(&run.operation),
                    purpose: PausePurpose::Capture,
                    timeout: self.timeouts.native,
                    clock_profile,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::Paused { pause }) if pause.owner == NativePauseOwner::Capture => {
                let Some(token) = run.capture_token(pause.generation) else {
                    return Err(Abort::Failed(failure(
                        LiveFailureCode::NativeUncertain,
                        LiveStage::NativePause,
                        "native capture pause reported a zero generation",
                    )));
                };
                run.pause = PauseState::Acquired(epoch, pause.generation);
                tracing::info!(operation = %run.operation, generation = token.generation.get(), "capture pause established");
                run.cut = Some(token);
                self.lock().parked = true;
                self.checkpoint(run, LiveStage::NativePause)
            }
            Ok(CommandOutcome::PauseFailed { failure: native }) => Err(Abort::Failed(failure(
                LiveFailureCode::NativePauseFailed,
                LiveStage::NativePause,
                native.to_string(),
            ))),
            Ok(outcome) => Err(Abort::Failed(failure(
                LiveFailureCode::NativeUncertain,
                LiveStage::NativePause,
                format!("unexpected native capture pause outcome {outcome:?}"),
            ))),
            Err(error) => Err(Abort::native(
                error,
                LiveFailureCode::NativePauseFailed,
                LiveStage::NativePause,
            )),
        }
    }

    async fn stage_flush(&self, run: &mut Run) -> Result<(), Abort> {
        self.capture_stage(run, LiveStage::CaptureFlush);
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::DiskFlushFailed,
                LiveStage::CaptureFlush,
                message,
            ))
        };
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::FlushCapture {
                    operation: wire_uuid(&run.operation),
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::CaptureFlushed { pause, attachments }) => {
                if Some(pause.generation) != run.cut_generation() {
                    return Err(fail("flush belongs to another pause".into()));
                }
                // Coverage is derived against the admitted writable inventory.
                for disk in &run.plan.disks {
                    if !attachments
                        .iter()
                        .any(|attachment| attachment.configured_id == disk.block_id.as_str())
                    {
                        return Err(fail(format!(
                            "writable attachment {} was not flushed",
                            disk.block_id.as_str()
                        )));
                    }
                }
                run.facts.host_flush_completed = true;
                self.checkpoint(run, LiveStage::CaptureFlush)
            }
            Ok(CommandOutcome::CaptureFailed {
                failure: native, ..
            }) => {
                if native.kind == crate::virt::lifecycle::NativeFailureKind::OutOfSpace {
                    Err(Abort::Failed(failure(
                        LiveFailureCode::OutOfSpace,
                        LiveStage::CaptureFlush,
                        "Storage filled while flushing the machine; free space and retry",
                    )))
                } else {
                    Err(fail(native.to_string()))
                }
            }
            Ok(outcome) => Err(fail(format!("unexpected native flush outcome {outcome:?}"))),
            Err(error) => Err(Abort::native(
                error,
                LiveFailureCode::DiskFlushFailed,
                LiveStage::CaptureFlush,
            )),
        }
    }

    async fn stage_disks(&self, run: &mut Run) -> Result<(), Abort> {
        self.capture_stage(run, LiveStage::CaptureDisks);
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::DiskCopyFailed,
                LiveStage::CaptureDisks,
                message,
            ))
        };
        let Some(staging) = run.staging.clone() else {
            return Err(fail("capture staging is not prepared".into()));
        };
        let sources = self
            .machine
            .capture_sources()
            .await
            .map_err(|error| fail(format!("capture sources unavailable: {error}")))?;
        let mut work = Vec::with_capacity(run.plan.disks.len());
        for disk in &run.plan.disks {
            let source = sources
                .iter()
                .find(|source| source.disk_index == disk.attachment_index && source.writable)
                .ok_or_else(|| {
                    fail(format!(
                        "attachment {} has no held source",
                        disk.attachment_index
                    ))
                })?;
            let file = source
                .file
                .try_clone()
                .map_err(|error| fail(format!("duplicate held source: {error}")))?;
            work.push((
                CaptureRole::Disk(disk.name.clone()),
                file,
                disk.length,
                disk.copy,
            ));
        }
        drop(sources);
        let (abort, watcher) = abort_token(&run.cancel, &self.stop);
        let identity_policy = run.plan.identity_policy;
        let copied = tokio::task::spawn_blocking({
            let abort = abort.clone();
            move || -> Result<Vec<CaptureDiskCut>, DiskCopyError> {
                let mut pending = Vec::with_capacity(work.len());
                for (role, source, length, copy) in &work {
                    let method = staging.copy_disk(role, source, *length, *copy, identity_policy, &abort)?;
                    if identity_policy != CaptureIdentityPolicy::None && method == DiskCopyMethod::Clone {
                        let CaptureRole::Disk(name) = role else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "disk role required").into());
                        };
                        pending.push(staging.disk_cut(name)?);
                    }
                    if identity_policy == CaptureIdentityPolicy::None {
                        tracing::info!(role = %role.relative_path(), ?method, length, "owned writable disk bytes closed");
                    } else {
                        tracing::info!(role = %role.relative_path(), ?method, length, "sealed writable disk role");
                    }
                }
                Ok(pending)
            }
        })
        .await;
        watcher.abort();
        match copied {
            Ok(Ok(pending)) => {
                run.pending_disks = pending;
                run.facts.disk_copies_sealed = run.pending_disks.is_empty();
                self.checkpoint(run, LiveStage::CaptureDisks)
            }
            Ok(Err(DiskCopyError::Cancelled)) => {
                self.checkpoint(run, LiveStage::CaptureDisks)?;
                Err(fail("disk copy was interrupted".into()))
            }
            Ok(Err(error)) => Err(fail(error.to_string())),
            Err(error) => Err(fail(format!("disk copy task failed: {error}"))),
        }
    }

    async fn stage_freeze_disks(&self, run: &mut Run) -> Result<(), Abort> {
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::DiskFlushFailed,
                LiveStage::CaptureDisks,
                message,
            ))
        };
        run.disk_freeze_attempted = true;
        let response = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::FreezeCaptureDisks {
                    operation: wire_uuid(&run.operation),
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        match response {
            Ok(CommandOutcome::DiskGenerationsFrozen { receipts }) => run.disk_receipts = receipts,
            Ok(CommandOutcome::CaptureFailed { failure, .. })
                if failure.kind == crate::virt::lifecycle::NativeFailureKind::Unsupported =>
            {
                run.disk_freeze_attempted = false;
            }
            Ok(outcome) => return Err(fail(format!("disk freeze failed: {outcome:?}"))),
            Err(error) => {
                return Err(Abort::native(
                    error,
                    LiveFailureCode::DiskFlushFailed,
                    LiveStage::CaptureDisks,
                ))
            }
        }
        if let Some(context) = &self.capture {
            let mut baselines = context
                .disk_baselines
                .lock()
                .map_err(|_| fail("disk baseline owner is poisoned".into()))?;
            for disk in run.plan.disks.iter().filter(|disk| !disk.tracking_eligible) {
                baselines.remove(&disk.block_id);
            }
        }
        let sources = self
            .machine
            .capture_sources()
            .await
            .map_err(|error| fail(error.to_string()))?;
        if run.disk_freeze_attempted && run.disk_receipts.len() != run.plan.disks.len() {
            return Err(fail(
                "disk freeze does not cover every writable attachment".into(),
            ));
        }
        for (index, receipt) in run.disk_receipts.iter().enumerate() {
            receipt.validate().map_err(fail)?;
            let disk = run
                .plan
                .disks
                .iter()
                .find(|disk| {
                    disk.attachment_index == receipt.seed.attachment_index
                        && disk.block_id == receipt.seed.block_id
                })
                .ok_or_else(|| fail("disk receipt has no planned attachment".into()))?;
            let attachment = run
                .plan
                .configuration
                .attachments
                .get(disk.attachment_index as usize)
                .ok_or_else(|| fail("disk receipt attachment is absent".into()))?;
            let source = sources
                .iter()
                .find(|source| source.disk_index == disk.attachment_index && source.writable)
                .ok_or_else(|| fail("disk receipt has no held backing".into()))?;
            let metadata = source
                .file
                .metadata()
                .map_err(|error| fail(error.to_string()))?;
            use std::os::unix::fs::MetadataExt;
            if receipt.token.capture_id != run.operation
                || Some(receipt.token.pause_generation)
                    != run.cut_generation().map(|generation| generation.get())
                || receipt.seed.role != attachment.role
                || receipt.seed.file_device != metadata.dev()
                || receipt.seed.file_inode != metadata.ino()
                || receipt.seed.length != disk.length
                || receipt.seed.length != metadata.len()
                || run.disk_receipts[..index]
                    .iter()
                    .any(|previous| previous.seed.block_id == receipt.seed.block_id)
            {
                return Err(fail(
                    "disk receipt differs from the exact paused source".into(),
                ));
            }
        }
        for cut in &mut run.pending_disks {
            let planned = run
                .plan
                .disks
                .iter()
                .find(|disk| disk.name == cut.name)
                .ok_or_else(|| fail("clone has no planned attachment".into()))?;
            cut.tracking_receipt = run
                .disk_receipts
                .iter()
                .find(|receipt| receipt.seed.block_id == planned.block_id)
                .cloned();
        }
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("disk staging is absent".into()))?;
        let copies = run
            .plan
            .disks
            .iter()
            .filter(|disk| !run.pending_disks.iter().any(|cut| cut.name == disk.name))
            .map(|disk| {
                let dirty_chunks = run
                    .disk_receipts
                    .iter()
                    .find(|receipt| receipt.seed.block_id == disk.block_id)
                    .map_or(0, |receipt| receipt.dirty_chunks);
                (disk.clone(), dirty_chunks)
            })
            .collect::<Vec<_>>();
        let result = tokio::task::spawn_blocking(move || -> io::Result<_> {
            let mut maps = Vec::with_capacity(copies.len());
            let mut stats = Vec::with_capacity(copies.len());
            for (disk, dirty_chunks) in copies {
                let (file, _) = staging.open_sealed(&CaptureRole::DiskMap(disk.name.clone()))?;
                let map = read_disk_map(file)?;
                stats.push(vm_spec::capture::CaptureDiskStats {
                    name: disk.name,
                    dirty_chunks,
                    total_chunks: disk.length.div_ceil(vm_spec::capture::STREAM_CHUNK_BYTES),
                    bytes_hashed: crate::live::staging::hashed_map_bytes(
                        &map,
                        &mut staging.node_source(),
                    )?,
                    baseline_reused: false,
                    full_scan_reason: Some(
                        if disk.identity == vm_spec::capture::DiskIdentityState::UnknownAfterFork {
                            vm_spec::capture::DiskFullScanReason::UnknownAnchorAfterFork
                        } else if disk.tracking_eligible {
                            vm_spec::capture::DiskFullScanReason::CopyLane
                        } else {
                            vm_spec::capture::DiskFullScanReason::External
                        },
                    ),
                });
                maps.push((disk.block_id, Arc::new(map)));
            }
            Ok((maps, stats))
        })
        .await
        .map_err(|error| fail(error.to_string()))?
        .map_err(|error| fail(error.to_string()))?;
        run.disk_maps.extend(result.0);
        run.disk_stats.extend(result.1);
        self.checkpoint(run, LiveStage::CaptureDisks)
    }

    fn binding_matches(&self, run: &Run, binding: &NativeBinding) -> bool {
        let Some(context) = self.capture.as_ref() else {
            return false;
        };
        binding.capture == wire_uuid(&run.operation)
            && binding.source_run == self.run_uuid
            && Some(binding.pause_generation) == run.cut_generation()
            && binding.profile == context.digests.profile
            && binding.topology == context.digests.topology
            && !binding.live_state_schema.is_empty()
    }

    async fn stage_execution_and_memory(&self, run: &mut Run) -> Result<(), Abort> {
        let Some(outputs) = run.outputs else {
            return Err(Abort::Failed(failure(
                LiveFailureCode::ExecutionCaptureFailed,
                LiveStage::CaptureExecution,
                "capture outputs are not prepared",
            )));
        };

        self.capture_stage(run, LiveStage::CaptureExecution);
        let fail_execution = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::ExecutionCaptureFailed,
                LiveStage::CaptureExecution,
                message,
            ))
        };
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::CaptureExecution {
                    operation: wire_uuid(&run.operation),
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        let binding = match result {
            Ok(CommandOutcome::ExecutionCaptured {
                binding,
                execution,
                devices,
            }) => {
                if execution.identity() != outputs.execution
                    || devices.identity() != outputs.devices
                {
                    return Err(fail_execution(
                        "execution receipts name other outputs".into(),
                    ));
                }
                if !self.binding_matches(run, &binding) {
                    return Err(fail_execution(
                        "execution state binding differs from this cut".into(),
                    ));
                }
                binding
            }
            Ok(CommandOutcome::CaptureFailed {
                failure: native, ..
            }) => {
                if native.kind == crate::virt::lifecycle::NativeFailureKind::OutOfSpace {
                    return Err(Abort::Failed(failure(
                        LiveFailureCode::OutOfSpace,
                        LiveStage::CaptureExecution,
                        "Storage filled while saving the machine; free space and retry",
                    )));
                }
                return Err(fail_execution(native.to_string()));
            }
            Ok(outcome) => {
                return Err(fail_execution(format!(
                    "unexpected native execution outcome {outcome:?}"
                )))
            }
            Err(error) => {
                return Err(Abort::native(
                    error,
                    LiveFailureCode::ExecutionCaptureFailed,
                    LiveStage::CaptureExecution,
                ))
            }
        };
        self.checkpoint(run, LiveStage::CaptureExecution)?;

        self.capture_stage(run, LiveStage::CaptureMemory);
        let fail_memory = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::MemoryCaptureFailed,
                LiveStage::CaptureMemory,
                message,
            ))
        };
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::CaptureMemory {
                    operation: wire_uuid(&run.operation),
                    timeout: self.timeouts.native,
                },
            ))
            .await
            .map_err(|error| {
                Abort::native(
                    error,
                    LiveFailureCode::MemoryCaptureFailed,
                    LiveStage::CaptureMemory,
                )
            })?;
        let writers_closed = match &result {
            CommandOutcome::MemoryCaptured {
                binding: memory,
                ram,
                layout,
                writers_closed,
                ..
            } => {
                if ram.identity() != outputs.ram || layout.identity() != outputs.layout {
                    return Err(fail_memory("RAM receipts name other outputs".into()));
                }
                if memory != &binding {
                    return Err(fail_memory(
                        "RAM binding differs from the execution binding".into(),
                    ));
                }
                *writers_closed
            }
            CommandOutcome::CaptureFailed {
                failure: native, ..
            } => {
                if native.kind == crate::virt::lifecycle::NativeFailureKind::OutOfSpace {
                    return Err(Abort::Failed(failure(
                        LiveFailureCode::OutOfSpace,
                        LiveStage::CaptureMemory,
                        "Storage filled while saving the machine; free space and retry",
                    )));
                }
                return Err(fail_memory(native.to_string()));
            }
            outcome => {
                return Err(fail_memory(format!(
                    "unexpected native RAM outcome {outcome:?}"
                )))
            }
        };
        run.native_memory = Some(result);
        run.binding = Some(*binding);

        // Seal facts come from retained native authority, not RPC success.
        let observed = self.get_capture(&run.operation).await.map_err(|error| {
            Abort::native(
                error,
                LiveFailureCode::MemoryCaptureFailed,
                LiveStage::CaptureMemory,
            )
        })?;
        let cut = observed.pause.cut.map(|pause| pause.generation);
        let parked = observed.evidence.pause_completed && cut == run.cut_generation();
        run.facts.vcpus_paused = parked;
        run.facts.devices_quiesced = parked;
        run.facts.host_writers_drained = parked;
        run.facts.host_flush_completed &= observed.evidence.flush_completed;
        run.facts.memory_state_sealed = observed.evidence.execution_sealed
            && observed.evidence.memory_sealed
            && writers_closed
            && observed.outputs.all_closed();
        self.checkpoint(run, LiveStage::CaptureMemory)
    }

    async fn verify_owned_cut(&self, run: &mut Run) -> Result<OwnedLocalCut, Abort> {
        self.capture_stage(run, LiveStage::CaptureVerify);
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureVerify,
                message,
            ))
        };
        if !(run.facts.workloads_frozen
            && run.facts.vcpus_paused
            && run.facts.devices_quiesced
            && run.facts.host_writers_drained
            && run.facts.host_flush_completed
            && run.facts.disk_copies_sealed
            && run.facts.memory_state_sealed)
        {
            return Err(fail(
                "owned cut lacks complete pause, drain, flush or closed-writer evidence".into(),
            ));
        }
        let receipt = run
            .native_memory
            .take()
            .ok_or_else(|| fail("missing native RAM receipt".into()))?;
        let CommandOutcome::MemoryCaptured {
            ram,
            layout,
            memory_generation,
            predecessor_generation,
            identity_policy,
            changes,
            stats,
            ..
        } = receipt
        else {
            return Err(fail("unexpected owned RAM receipt".into()));
        };
        if identity_policy != CaptureIdentityPolicy::None
            || changes != crate::virt::lifecycle::CaptureRamChangesAuthority::None
            || stats.identity_bytes_hashed != 0
            || stats.whole_file_bytes_hashed != 0
            || stats.map_nodes_written != 0
        {
            return Err(fail(
                "owned capture unexpectedly computed content identity".into(),
            ));
        }
        let binding = run
            .binding
            .as_ref()
            .ok_or_else(|| fail("missing state binding".into()))?;
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("missing capture staging".into()))?;
        let outputs = run
            .outputs
            .ok_or_else(|| fail("missing capture output identities".into()))?;
        let disks = run.plan.disks.clone();
        let limit = run.plan.ram_bytes;
        let (members, geometry, staged) = tokio::task::spawn_blocking(move || -> io::Result<_> {
            use std::os::unix::fs::MetadataExt;
            let mut roles = vec![
                CaptureRole::Execution,
                CaptureRole::Devices,
                CaptureRole::Ram,
                CaptureRole::Layout,
            ];
            roles.extend(
                disks
                    .iter()
                    .map(|disk| CaptureRole::Disk(disk.name.clone())),
            );
            let mut members = Vec::with_capacity(roles.len());
            let mut staged = staging
                .request_allocation()?
                .saturating_add(staging.directory_allocation()?);
            let mut state_bytes = 0u64;
            for role in roles {
                let (file, facts) = staging.seal_owned(&role)?;
                let expected = match role {
                    CaptureRole::Execution => Some(outputs.execution),
                    CaptureRole::Devices => Some(outputs.devices),
                    CaptureRole::Ram => Some(outputs.ram),
                    CaptureRole::Layout => Some(outputs.layout),
                    _ => None,
                };
                if expected.is_some_and(|expected| {
                    (expected.device, expected.inode) != (facts.device, facts.inode)
                }) {
                    return Err(io::Error::other(
                        "owned member differs from prepared output",
                    ));
                }
                let metadata = file.metadata()?;
                let charge = match &role {
                    CaptureRole::Disk(name) => {
                        let disk = disks
                            .iter()
                            .find(|disk| disk.name == *name)
                            .ok_or_else(|| io::Error::other("owned disk has no plan"))?;
                        if facts.length != disk.length {
                            return Err(io::Error::other("owned disk length differs from plan"));
                        }
                        match disk.copy {
                            CaptureDiskCopy::Clone => CAPTURE_CLONE_RESERVE_BYTES,
                            CaptureDiskCopy::Copy => metadata.blocks().saturating_mul(512),
                        }
                    }
                    CaptureRole::Ram => metadata.blocks().saturating_mul(512),
                    _ => {
                        state_bytes = state_bytes.saturating_add(facts.length);
                        metadata.blocks().saturating_mul(512)
                    }
                };
                staged = staged.saturating_add(charge);
                members.push(OwnedCutMember {
                    role,
                    fingerprint: crate::restore::inputs::fingerprint(&file)?,
                    complete: true,
                });
            }
            if state_bytes > CAPTURE_STATE_RESERVE_BYTES {
                return Err(io::Error::other("owned state exceeds its reserve"));
            }
            let (layout_file, layout_facts) = staging.open_owned(&CaptureRole::Layout)?;
            let (_, ram_facts) = staging.open_owned(&CaptureRole::Ram)?;
            if layout_facts.length > MAX_LAYOUT_BYTES
                || (layout.device, layout.inode, layout.length)
                    != (layout_facts.device, layout_facts.inode, layout_facts.length)
                || (ram.device, ram.inode, ram.length)
                    != (ram_facts.device, ram_facts.inode, ram_facts.length)
            {
                return Err(io::Error::other(
                    "owned RAM/layout differs from native completion",
                ));
            }
            let mut bytes = Vec::new();
            layout_file
                .take(MAX_LAYOUT_BYTES + 1)
                .read_to_end(&mut bytes)?;
            let geometry = parse_layout(&bytes)?;
            if geometry.packed_length != ram.length || ram.length > limit {
                return Err(io::Error::other("owned RAM geometry differs from its plan"));
            }
            Ok((members, geometry, staged))
        })
        .await
        .map_err(|error| fail(error.to_string()))?
        .map_err(|error| fail(error.to_string()))?;
        staging_budget(run.plan.reservation.staging_bytes, staged).map_err(Abort::Failed)?;
        let cut = OwnedLocalCut::from_completed(
            &run.plan,
            OwnedCutCompletion {
                freeze_operation_id: run
                    .borrowed
                    .as_ref()
                    .map_or_else(|| run.operation.clone(), |pause| pause.operation_id.clone()),
                freeze_epoch: run
                    .freeze_epoch
                    .ok_or_else(|| fail("missing guest freeze epoch".into()))?,
                binding: CaptureStateBinding {
                    live_state_schema: binding.live_state_schema.clone(),
                    architecture: binding.architecture.clone(),
                    profile: digest(binding.profile),
                    topology: digest(binding.topology),
                    ram_layout: digest(binding.ram_layout),
                    source_run: run.plan.run_id.clone(),
                    pause_generation: NonZeroU64::new(binding.pause_generation.get())
                        .ok_or_else(|| fail("zero pause generation".into()))?,
                    capture: run.plan.capture_id.clone(),
                },
                materialization_generation: NonZeroU64::new(memory_generation)
                    .ok_or_else(|| fail("zero materialization generation".into()))?,
                predecessor_generation,
                packed_length: geometry.packed_length,
                page_granule: geometry.page_granule,
                regions: geometry.regions,
                members,
                stats: *stats,
            },
        )
        .map_err(fail)?;
        self.checkpoint(run, LiveStage::CaptureVerify)?;
        Ok(cut)
    }

    /// Verify every staged role and return the actual staged bytes charged
    /// against the reservation (see [`verify_staging`]).
    async fn stage_verify(&self, run: &mut Run) -> Result<u64, Abort> {
        self.capture_stage(run, LiveStage::CaptureVerify);
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureVerify,
                message,
            ))
        };
        let (Some(staging), Some(outputs)) = (run.staging.clone(), run.outputs) else {
            return Err(fail("capture staging is not prepared".into()));
        };
        if !run.facts.memory_state_sealed {
            return Err(fail(
                "native capture writers are not sealed and closed".into(),
            ));
        }
        let roles = run
            .plan
            .roles()
            .into_iter()
            .filter(|role| match role {
                CaptureRole::Disk(name) | CaptureRole::DiskMap(name) => {
                    !run.pending_disks.iter().any(|disk| disk.name == *name)
                }
                _ => true,
            })
            .collect::<Vec<_>>();
        let disks = run.plan.disks.clone();
        let ram_limit = run.plan.ram_bytes;
        let receipt = run
            .native_memory
            .take()
            .ok_or_else(|| fail("native memory receipt is missing".into()))?;
        let baseline = self.capture.as_ref().and_then(|context| {
            context
                .baseline
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .identified()
                .cloned()
        });
        let retained = match &receipt {
            CommandOutcome::MemoryCaptured {
                identity_policy: CaptureIdentityPolicy::SinceAnchor,
                baseline: Some(expected),
                binding,
                ..
            } => {
                let baseline = baseline
                    .as_ref()
                    .ok_or_else(|| fail("incremental receipt lacks its retained map".into()))?;
                if baseline.stream != *expected
                    || baseline.layout.as_bytes() != &binding.ram_layout.0
                {
                    return Err(fail(
                        "incremental receipt differs from the exact retained map/layout".into(),
                    ));
                }
                Some(baseline.map.clone())
            }
            CommandOutcome::MemoryCaptured {
                identity_policy: CaptureIdentityPolicy::Full,
                ..
            } => None,
            _ => return Err(fail("native memory mode or baseline is malformed".into())),
        };
        let CommandOutcome::MemoryCaptured {
            ram,
            changes,
            changes_output,
            ..
        } = &receipt
        else {
            return Err(fail("native memory receipt has the wrong role".into()));
        };
        let (change_file, change_facts) = staging
            .open_sealed(&CaptureRole::RamChanges)
            .map_err(|error| fail(error.to_string()))?;
        if (change_facts.device, change_facts.inode, change_facts.length)
            != (
                changes_output.device,
                changes_output.inode,
                changes_output.length,
            )
        {
            return Err(fail(
                "RAM changes differ from the native output receipt".into(),
            ));
        }
        let nodes = baseline
            .as_ref()
            .and_then(|baseline| baseline.nodes.clone())
            .unwrap_or_else(|| staging.node_source());
        let length = ram.length;
        let crate::virt::lifecycle::CaptureRamChangesAuthority::Identified(changes) = changes
        else {
            return Err(fail("snapshot RAM receipt lacks identified changes".into()));
        };
        let changes = changes.as_ref().clone();
        let (abort, watcher) = abort_token(&run.cancel, &self.stop);
        let verified = tokio::task::spawn_blocking({
            let abort = abort.clone();
            move || {
                let map = Arc::new(assemble_ram_map(
                    length,
                    &change_file,
                    &changes,
                    retained.as_deref(),
                    nodes,
                    &mut staging.node_sink(),
                    &abort,
                )?);
                verify_staging(
                    &staging,
                    &roles,
                    &disks,
                    outputs,
                    RamVerification {
                        limit: ram_limit,
                        map,
                        authenticated_changes: Some(&changes),
                    },
                    &abort,
                )
            }
        })
        .await;
        watcher.abort();
        let verified = match verified {
            Ok(Ok(verified)) => verified,
            Ok(Err(error)) => {
                self.checkpoint(run, LiveStage::CaptureVerify)?;
                return Err(fail(error.to_string()));
            }
            Err(error) => return Err(fail(format!("verification task failed: {error}"))),
        };
        let Some(binding) = run.binding.take() else {
            return Err(fail("capture binding was not observed".into()));
        };
        let Some(source_run) = live_id(binding.source_run) else {
            return Err(fail(
                "binding source run is not a canonical identity".into(),
            ));
        };
        let Some(pause_generation) = NonZeroU64::new(binding.pause_generation.get()) else {
            return Err(fail("binding pause generation is zero".into()));
        };
        let CommandOutcome::MemoryCaptured {
            mode,
            identity_policy,
            identity_full_reason,
            baseline,
            full_reason,
            identity_chunk_bytes,
            changes,
            stats,
            ..
        } = receipt
        else {
            return Err(fail("native memory receipt has the wrong role".into()));
        };
        run.resolved_map = Some(verified.map);
        run.memory = Some(CaptureMemoryEvidence {
            packed_length: verified.packed_length,
            page_granule: verified.page_granule,
            regions: verified.regions,
            ram_stream: verified.ram_stream,
            mode,
            identity_policy,
            identity_full_reason,
            baseline,
            full_reason,
            identity_chunk_bytes,
            changes: match changes {
                crate::virt::lifecycle::CaptureRamChangesAuthority::Identified(changes) => *changes,
                crate::virt::lifecycle::CaptureRamChangesAuthority::None => {
                    return Err(fail("snapshot has owned change authority".into()))
                }
            },
            stats: *stats,
            binding: CaptureStateBinding {
                live_state_schema: binding.live_state_schema,
                architecture: binding.architecture,
                profile: digest(binding.profile),
                topology: digest(binding.topology),
                ram_layout: digest(binding.ram_layout),
                source_run,
                pause_generation,
                capture: run.plan.capture_id.clone(),
            },
        });
        run.inventory = verified.inventory;
        self.checkpoint(run, LiveStage::CaptureVerify)?;
        let mut staged_bytes = verified.staged_bytes;
        let staging = run
            .staging
            .as_ref()
            .ok_or_else(|| fail("capture staging is missing".into()))?;
        for cut in &run.pending_disks {
            let planned = run
                .plan
                .disks
                .iter()
                .find(|disk| disk.name == cut.name)
                .ok_or_else(|| fail("pending disk has no plan".into()))?;
            let charge = match planned.copy {
                CaptureDiskCopy::Clone => CAPTURE_CLONE_RESERVE_BYTES,
                CaptureDiskCopy::Copy => {
                    let (file, _) = staging
                        .open_sealed(&CaptureRole::Disk(cut.name.clone()))
                        .map_err(|error| fail(error.to_string()))?;
                    std::os::unix::fs::MetadataExt::blocks(
                        &file.metadata().map_err(|error| fail(error.to_string()))?,
                    )
                    .saturating_mul(512)
                }
            };
            staged_bytes = staged_bytes.saturating_add(charge);
        }
        Ok(staged_bytes)
    }

    async fn stage_cut(&self, run: &Run, staged: u64) -> Result<(), Abort> {
        self.checkpoint(run, LiveStage::CaptureVerify)?;
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::SealFailed,
                LiveStage::CaptureVerify,
                message,
            ))
        };
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("capture staging is missing".into()))?;
        let mut cut = CaptureCutRecord {
            phase: CaptureCutPhase::IdentityPending,
            evidence: run
                .evidence(CaptureRecordOutcome::Coherent, None)
                .ok_or_else(|| fail("capture request is missing".into()))?,
            disks: run.pending_disks.clone(),
        };
        cut.evidence.disk_tracking_receipts.retain(|receipt| {
            !cut.disks.iter().any(|disk| {
                disk.tracking_receipt
                    .as_ref()
                    .is_some_and(|pending| pending.seed.block_id == receipt.seed.block_id)
            })
        });
        cut.validate_against_plan(&run.plan, &cut.evidence.request_digest)
            .map_err(fail)?;
        let bytes = cut.canonical_bytes().map_err(fail)?;
        staging_budget(
            run.plan.reservation.staging_bytes,
            staged
                .saturating_add(bytes.len() as u64)
                .saturating_add(4095),
        )
        .map_err(Abort::Failed)?;
        let result = tokio::task::spawn_blocking(move || {
            staging.commit_record(CAPTURE_CUT_FILE, CAPTURE_CUT_TEMPORARY_FILE, &bytes)
        })
        .await
        .map_err(|error| fail(format!("cut record task failed: {error}")))?
        .map_err(|error| fail(error.to_string()))?;
        match result {
            RecordCommit::Complete => {}
            RecordCommit::Uncertain(error) => return Err(fail(error.to_string())),
        }
        if let Some(record) = self.lock().journal.operation_mut(&run.operation) {
            record.phase = Phase::IdentityPending;
        }
        Ok(())
    }

    async fn stage_disk_identity(&self, run: &mut Run, staged: u64) -> Result<(), Abort> {
        self.capture_stage(run, LiveStage::CaptureDiskIdentity);
        self.checkpoint(run, LiveStage::CaptureDiskIdentity)?;
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::CaptureVerificationFailed,
                LiveStage::CaptureDiskIdentity,
                message,
            ))
        };
        let staging = run
            .staging
            .clone()
            .ok_or_else(|| fail("capture staging is missing".into()))?;
        let pending = std::mem::take(&mut run.pending_disks);
        let disks = run.plan.disks.clone();
        let outputs = run
            .outputs
            .ok_or_else(|| fail("capture outputs are missing".into()))?;
        let map = run
            .resolved_map
            .clone()
            .ok_or_else(|| fail("RAM map is missing".into()))?;
        let baselines = self
            .capture
            .as_ref()
            .and_then(|context| context.disk_baselines.lock().ok().map(|maps| maps.clone()))
            .unwrap_or_default();
        let (abort, watcher) = abort_token(&run.cancel, &self.stop);
        let result = tokio::task::spawn_blocking({
            let abort = abort.clone();
            move || -> Result<DiskIdentityResult, DiskCopyError> {
                let mut inventory = Vec::with_capacity(pending.len() * 2);
                let mut bytes = staged;
                let mut maps = Vec::with_capacity(pending.len());
                let metadata_before = staging.directory_allocation()?;
                let mut stats = Vec::with_capacity(pending.len());
                for cut in pending {
                    let planned = disks.iter().find(|disk| disk.name == cut.name)
                        .ok_or_else(|| io::Error::other("clone attachment is absent"))?;
                    let expected = cut.tracking_receipt.as_ref()
                        .filter(|receipt| planned.tracking_eligible && receipt.invalid_reason.is_none())
                        .and_then(|receipt| receipt.seed.baseline);
                    let mut baseline = expected.and_then(|_| baselines.get(&planned.block_id).cloned());
                    if expected.is_some() && baseline.as_ref().is_none_or(|map| Some(map.id()) != expected) {
                        baseline = planned.baseline_map.as_ref().and_then(|path| {
                            let loaded = nix::fcntl::open(std::path::Path::new(path),
                                nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC
                                    | nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK,
                                nix::sys::stat::Mode::empty())
                                .map(File::from).map_err(io::Error::from).and_then(read_disk_map);
                            match loaded {
                                Ok(map) if map.length() == cut.length && Some(map.id()) == expected => Some(Arc::new(map)),
                                Ok(_) => None,
                                Err(error) => {
                                    tracing::warn!(%error, block = %planned.block_id.as_str(), "disk baseline map is unavailable; hashing immutable clone");
                                    None
                                }
                            }
                        });
                    }
                    let (disk_map, mut disk_stats) = staging.complete_disk_identity(
                        &cut, baseline.as_deref(), planned.tracking_eligible, &abort)?;
                    if !disk_stats.baseline_reused && planned.identity == vm_spec::capture::DiskIdentityState::UnknownAfterFork {
                        disk_stats.full_scan_reason = Some(vm_spec::capture::DiskFullScanReason::UnknownAnchorAfterFork);
                    }
                    tracing::info!(disk = %cut.name.as_str(), dirty_chunks = disk_stats.dirty_chunks,
                        total_chunks = disk_stats.total_chunks, bytes_hashed = disk_stats.bytes_hashed,
                        baseline_reused = disk_stats.baseline_reused, full_scan_reason = ?disk_stats.full_scan_reason,
                        "completed disk identity");
                    maps.push((planned.block_id.clone(), Arc::new(disk_map)));
                    stats.push(disk_stats);
                    for role in [
                        CaptureRole::Disk(cut.name.clone()),
                        CaptureRole::DiskMap(cut.name),
                    ] {
                        let verified = verify_role(&staging, &role, &disks, outputs, &map, None, &abort)?;
                        if matches!(role, CaptureRole::DiskMap(_)) {
                            bytes = bytes.saturating_add(verified.staged_bytes);
                        }
                        inventory.push(verified.entry);
                    }
                }
                bytes = bytes.saturating_add(staging.directory_allocation()?.saturating_sub(metadata_before));
                let cut = staging.open_entry_allocation(CAPTURE_CUT_FILE)?;
                Ok(DiskIdentityResult { inventory, bytes: bytes.saturating_add(cut), maps, stats })
            }
        })
        .await;
        watcher.abort();
        self.checkpoint(run, LiveStage::CaptureDiskIdentity)?;
        let result = result
            .map_err(|error| fail(format!("disk identity task failed: {error}")))?
            .map_err(|error| fail(error.to_string()))?;
        run.inventory.extend(result.inventory);
        run.disk_maps.extend(result.maps);
        run.disk_stats.extend(result.stats);
        let roles = run.plan.roles();
        run.inventory
            .sort_by_key(|entry| roles.iter().position(|role| role == &entry.role));
        staging_budget(run.plan.reservation.staging_bytes, result.bytes).map_err(Abort::Failed)?;
        run.facts.disk_copies_sealed = true;
        Ok(())
    }

    async fn get_capture(&self, operation: &LiveId) -> Result<NativeObservation, NativeError> {
        let mut transport_failures = 0;
        loop {
            let response = tokio::select! {
                biased;
                () = self.stop.cancelled() => return Err(NativeError::Stopped),
                response = self.machine.lifecycle(self.native_request(
                    operation,
                    LifecycleCommand::GetCapture { operation: wire_uuid(operation) },
                )) => response,
            };
            match response {
                Ok(response) => {
                    return response.capture.ok_or_else(|| {
                        NativeError::Uncertain("native capture observation is missing".into())
                    })
                }
                Err(error) => self.transport_retry(error, &mut transport_failures).await?,
            }
        }
    }

    /// Record what the worker may retain, in the run and its journal facts.
    fn record_preparation(&self, run: &mut Run, preparation: WorkerPreparation) {
        run.worker = preparation;
        if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
            facts.worker = preparation;
        }
    }

    /// Whether the worker holds an uncertainly prepared capture. `GetCapture`
    /// follows the preparation on the same ordered lifecycle stream and the
    /// worker admits both on its reader thread, so only `UnknownCapture`
    /// proves the preparation never took effect.
    async fn reconcile_preparation(&self, operation: &LiveId) -> Result<bool, NativeError> {
        match self.get_capture(operation).await {
            Ok(_) => Ok(true),
            Err(NativeError::Rejected(LifecycleRejection::UnknownCapture)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Resolve whatever the worker may hold for a capture that will not be
    /// accepted: abandon a held candidate, closing every worker output owner.
    /// Ownership that cannot be established stays retained and fenced.
    async fn resolve_candidate(&self, run: &mut Run) -> Result<(), Abort> {
        let holds = match run.worker {
            WorkerPreparation::Absent => false,
            WorkerPreparation::Prepared => true,
            WorkerPreparation::Uncertain => {
                match self.reconcile_preparation(&run.operation).await {
                    Ok(holds) => {
                        let preparation = if holds {
                            WorkerPreparation::Prepared
                        } else {
                            WorkerPreparation::Absent
                        };
                        tracing::info!(operation = %run.operation, ?preparation, "uncertain capture preparation reconciled");
                        self.record_preparation(run, preparation);
                        holds
                    }
                    Err(NativeError::Stopped) => return Err(Abort::Stopped),
                    Err(error) => {
                        return Err(Abort::Failed(failure(
                            error.code(LiveFailureCode::AbandonFailed),
                            LiveStage::CaptureAbandon,
                            format!("capture preparation is unresolved: {}", error.describe()),
                        )))
                    }
                }
            }
        };
        if holds {
            self.abandon(run).await
        } else {
            Ok(())
        }
    }

    /// Classify one lifecycle error; transient uncertainty sleeps and asks
    /// the caller to replay the identical request.
    async fn transport_retry(
        &self,
        error: LifecycleError,
        transport_failures: &mut u32,
    ) -> Result<(), NativeError> {
        match error {
            LifecycleError::Rejected(rejection) => Err(self.native_rejection(rejection)),
            LifecycleError::Unsupported { backend } => {
                Err(NativeError::Unsupported(backend.to_string()))
            }
            LifecycleError::Unknown(LifecycleUncertainty::WorkerLost) => Err(
                NativeError::WorkerLost("worker lifecycle owner is gone".into()),
            ),
            LifecycleError::Unknown(uncertainty) => {
                *transport_failures += 1;
                if *transport_failures >= NATIVE_TRANSPORT_RETRIES {
                    return Err(NativeError::Uncertain(uncertainty.to_string()));
                }
                tokio::select! {
                    () = self.stop.cancelled() => Err(NativeError::Stopped),
                    () = tokio::time::sleep(RETRY_DELAY) => Ok(()),
                }
            }
        }
    }

    /// One rights-bearing native command to a terminal outcome. Every
    /// attempt carries fresh owned duplicates; a replay joins the retained
    /// worker command, which identity-checks and closes the duplicates.
    async fn native_with_rights(
        &self,
        request: LifecycleRequest,
        rights: impl Fn() -> io::Result<LifecycleRights>,
    ) -> Result<CommandOutcome, NativeError> {
        let mut transport_failures = 0;
        loop {
            let attempt = rights().map_err(|error| {
                NativeError::Uncertain(format!("duplicate capture descriptors: {error}"))
            })?;
            let response = tokio::select! {
                biased;
                () = self.stop.cancelled() => return Err(NativeError::Stopped),
                response = self.machine.lifecycle_with_rights(request.clone(), attempt) => response,
            };
            match response {
                Ok(response) => match response.command.map(|report| report.state) {
                    Some(CommandState::Completed { outcome }) => return Ok(outcome),
                    Some(CommandState::Accepted) => {}
                    None => {
                        return Err(NativeError::Uncertain(
                            "native report omitted the command".into(),
                        ))
                    }
                },
                Err(error) => self.transport_retry(error, &mut transport_failures).await?,
            }
        }
    }

    // ----------------------------------------------------------------- seal

    async fn seal(&self, mut run: Run, evidence: CompletedRecord) {
        // Linearization: cancel or stop admitted before this point wins and no
        // coherent record is ever linked; afterwards cancel waits and loses.
        let decided = {
            let mut inner = self.lock();
            if inner.journal.stopped || self.stop.is_cancelled() {
                Some(Abort::Stopped)
            } else if run.cancel.is_cancelled() {
                Some(Abort::Failed(failure(
                    LiveFailureCode::Cancelled,
                    LiveStage::CaptureSeal,
                    "capture cancelled before its seal",
                )))
            } else {
                if let Some(record) = inner.journal.operation_mut(&run.operation) {
                    record.phase = Phase::Sealing;
                }
                None
            }
        };
        if let Some(abort) = decided {
            return self.unwind(run, abort).await;
        }
        self.capture_stage(&run, LiveStage::CaptureSeal);
        let checked = (|| -> Result<_, String> {
            let staging = run
                .staging
                .clone()
                .ok_or("capture staging is not prepared")?;
            let cut_token = run.cut.clone().ok_or("capture pause token is missing")?;
            match evidence {
                CompletedRecord::Identified(mut evidence) => {
                    if let Some(memory) = evidence.memory.as_mut() {
                        memory.stats.map_nodes_written = staging.map_nodes_written();
                    }
                    let request = run
                        .request_digest
                        .ok_or("capture request identity is missing")?;
                    evidence.validate_against_plan(&run.plan, &request)?;
                    if !evidence.is_sealed() {
                        return Err("coherent evidence is incomplete".into());
                    }
                    let bytes = evidence.canonical_bytes()?;
                    let sha256 = Sha256Digest::of_bytes(&bytes);
                    Ok((
                        staging,
                        bytes,
                        CaptureRecordReference::Identified {
                            evidence: CaptureEvidenceReference {
                                outcome: CaptureRecordOutcome::Coherent,
                                sha256,
                            },
                        },
                        CaptureSuccess::Identified {
                            sealed: CaptureSealed {
                                capture_id: run.plan.capture_id.clone(),
                                evidence_sha256: sha256,
                                cut_token,
                            },
                        },
                    ))
                }
                CompletedRecord::Owned(cut) => {
                    cut.validate_against_plan(&run.plan)?;
                    let bytes = cut.canonical_bytes()?;
                    Ok((
                        staging,
                        bytes,
                        CaptureRecordReference::OwnedLocalCut { cut: cut.clone() },
                        CaptureSuccess::OwnedLocalCut { cut, cut_token },
                    ))
                }
            }
        })();
        let (staging, bytes, reference, success) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                self.reopen_pipeline(&run);
                return self
                    .unwind(
                        run,
                        Abort::Failed(failure(
                            LiveFailureCode::CaptureVerificationFailed,
                            LiveStage::CaptureSeal,
                            error,
                        )),
                    )
                    .await;
            }
        };
        // The commit is bounded blocking work that is never abandoned midway.
        // Complete means that the record's final name is its only link.
        let committed = tokio::task::spawn_blocking({
            let staging = staging.clone();
            move || {
                staging.commit_record(
                    CAPTURE_EVIDENCE_FILE,
                    CAPTURE_EVIDENCE_TEMPORARY_FILE,
                    &bytes,
                )
            }
        })
        .await;
        match committed {
            Ok(Ok(RecordCommit::Complete)) => {}
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                return self.seal_uncertain(run, error.to_string()).await;
            }
            Ok(Err(error)) => {
                // Nothing was linked: there is no record to preserve.
                self.reopen_pipeline(&run);
                return self
                    .unwind(
                        run,
                        Abort::Failed(failure(
                            LiveFailureCode::SealFailed,
                            LiveStage::CaptureSeal,
                            error.to_string(),
                        )),
                    )
                    .await;
            }
            Err(error) => {
                return self
                    .seal_uncertain(run, format!("seal task failed: {error}"))
                    .await;
            }
        }
        if run.cut.is_none() {
            return self
                .seal_uncertain(run, "sealed without a cut token".into())
                .await;
        }
        let disk_settlement = self.settle_disks(&mut run, true).await;
        {
            let mut inner = self.lock();
            let sealed = LiveOperationRecord {
                operation_id: run.operation.clone(),
                kind: OperationKind::Capture,
                outcome: OperationOutcome::CaptureSealed { capture: success },
            };
            if let Some(record) = inner.journal.operation_mut(&run.operation) {
                record.record = sealed.clone();
                record.phase = Phase::Continuing;
            }
            if let Some(facts) = inner.journal.capture_mut(&run.operation) {
                facts.evidence = Some(reference);
            }
            // Cancels that joined before the seal see the unchanged success.
            for request in inner.journal.take_cancel_requests(&run.operation) {
                let result =
                    LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed {
                        completed: CancelCompleted {
                            effective: false,
                            operation: sealed.clone(),
                            state: self
                                .store
                                .live_snapshot()
                                .map_or(VmLifecycleState::Capturing, |snapshot| snapshot.state),
                        },
                    });
                inner.journal.complete(&request, result);
            }
        }
        if let Err(cause) = disk_settlement {
            self.finish(&mut run, Finish::Error(cause)).await;
            return;
        }
        tracing::info!(operation = %run.operation, "capture sealed");
        if let Some(finish) = run.continued.take() {
            self.finish(&mut run, finish).await;
        } else {
            self.continue_sealed(&mut run, &staging).await;
        }
    }

    /// A refusal before the link: the pipeline owns the operation again.
    fn reopen_pipeline(&self, run: &Run) {
        if let Some(record) = self.lock().journal.operation_mut(&run.operation) {
            record.phase = Phase::Pipeline;
        }
    }

    /// The record is visible but unsettled: never claim
    /// success, never overwrite or remove it, never continue the source.
    /// Stay fenced in Error until stop; libvm reconciles the files.
    async fn seal_uncertain(&self, mut run: Run, detail: String) {
        if let Err(error) = self.settle_disks(&mut run, false).await {
            tracing::error!(%error, "uncertain seal disk abort could not be reconciled");
        }
        let cause = failure(
            LiveFailureCode::SealUncertain,
            LiveStage::CaptureSeal,
            detail,
        );
        tracing::error!(operation = %run.operation, cause = %cause, "capture record settlement is uncertain");
        let mut inner = self.lock();
        inner.held = None;
        let published = matches!(
            self.publish(
                &inner,
                VmLifecycleState::Error,
                None,
                Some(cause.clone()),
                false,
                "capture seal uncertain; fenced until stop",
            ),
            Ok(true)
        );
        let state = if published {
            VmLifecycleState::Error
        } else {
            VmLifecycleState::Stopping
        };
        self.capture_terminal(&mut inner, &run, Some(cause), state);
    }

    // --------------------------------------------------------- continuation

    async fn continue_sealed(&self, run: &mut Run, staging: &Arc<CaptureStaging>) {
        match self.accept_baseline(run, staging).await {
            Ok(()) => self.continue_source(run).await,
            Err(Abort::Stopped) => self.capture_stopped(run),
            Err(Abort::Failed(cause)) => {
                // The seal stands. The unaccepted native candidate is resolved
                // by abandonment before any continuation; if it cannot be
                // resolved the source stays fenced.
                tracing::warn!(operation = %run.operation, cause = %cause, "baseline acceptance failed after the seal");
                match self.abandon(run).await {
                    Ok(()) => self.continue_source(run).await,
                    Err(Abort::Stopped) => self.capture_stopped(run),
                    Err(Abort::Failed(abandon)) => self.finish(run, Finish::Error(abandon)).await,
                }
            }
        }
    }

    async fn accept_baseline(&self, run: &Run, staging: &Arc<CaptureStaging>) -> Result<(), Abort> {
        self.capture_stage(run, LiveStage::CaptureAccept);
        let fail = |message: String| {
            Abort::Failed(failure(
                LiveFailureCode::BaselineAcceptFailed,
                LiveStage::CaptureAccept,
                message,
            ))
        };
        let outputs = run
            .outputs
            .ok_or_else(|| fail("capture outputs are missing".into()))?;
        let authority = match (&run.memory, &run.owned_cut) {
            (Some(memory), None) => crate::virt::lifecycle::CaptureBaselineAuthority::Identified {
                stream: Digest32(*memory.ram_stream.as_bytes()),
            },
            (None, Some(cut)) => crate::virt::lifecycle::CaptureBaselineAuthority::OwnedLocalCut {
                materialization_generation: cut.materialization_generation.get(),
            },
            _ => return Err(fail("sealed capture authority is missing or mixed".into())),
        };
        let (ram, layout) = tokio::task::spawn_blocking({
            let staging = staging.clone();
            move || -> io::Result<(File, File)> {
                let (ram, _) = match authority {
                    crate::virt::lifecycle::CaptureBaselineAuthority::Identified { .. } => {
                        staging.open_sealed(&CaptureRole::Ram)?
                    }
                    crate::virt::lifecycle::CaptureBaselineAuthority::OwnedLocalCut { .. } => {
                        staging.open_owned(&CaptureRole::Ram)?
                    }
                };
                let (layout, _) = match authority {
                    crate::virt::lifecycle::CaptureBaselineAuthority::Identified { .. } => {
                        staging.open_sealed(&CaptureRole::Layout)?
                    }
                    crate::virt::lifecycle::CaptureBaselineAuthority::OwnedLocalCut { .. } => {
                        staging.open_owned(&CaptureRole::Layout)?
                    }
                };
                Ok((ram, layout))
            }
        })
        .await
        .map_err(|error| fail(format!("open sealed RAM task failed: {error}")))?
        .map_err(|error| fail(format!("open sealed RAM: {error}")))?;
        let command = LifecycleCommand::AcceptCapture {
            operation: wire_uuid(&run.operation),
            ram: outputs.ram,
            layout: outputs.layout,
            authority,
            timeout: self.timeouts.native,
        };
        let result = self
            .native_with_rights(self.native_request(&run.operation, command), || {
                Ok(LifecycleRights::SealedMemory(SealedMemoryFiles {
                    ram: ram.try_clone()?,
                    layout: layout.try_clone()?,
                }))
            })
            .await;
        match result {
            Ok(CommandOutcome::CaptureAccepted { memory_generation }) => {
                if let (Some(context), Some(map), Some(memory)) =
                    (&self.capture, &run.resolved_map, &run.memory)
                {
                    *context
                        .baseline
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) =
                        IdentityAnchor::Identified(AcceptedMap {
                            map: map.clone(),
                            nodes: run.staging.as_ref().map(|staging| staging.node_source()),
                            layout: memory.binding.ram_layout,
                            stream: memory.ram_stream,
                        });
                }
                tracing::info!(operation = %run.operation, memory_generation, "sealed RAM accepted as the source baseline");
                Ok(())
            }
            Ok(outcome) => Err(fail(format!(
                "unexpected native accept outcome {outcome:?}"
            ))),
            Err(error) => Err(Abort::native(
                error,
                LiveFailureCode::BaselineAcceptFailed,
                LiveStage::CaptureAccept,
            )),
        }
    }

    /// Continue a source whose native candidate is resolved, under the
    /// plan's resume policy and the pause the capture actually holds.
    async fn continue_source(&self, run: &mut Run) {
        let finish = self.source_finish(run).await;
        self.finish_or_stop(run, finish).await;
    }

    async fn source_finish(&self, run: &mut Run) -> Option<Finish> {
        match (run.pause, run.plan.resume_policy) {
            (PauseState::Acquired(epoch, generation), CaptureResumePolicy::ResumeIfAcquired) => {
                self.continue_resume(run, epoch, generation).await
            }
            (PauseState::Acquired(epoch, _), CaptureResumePolicy::Preserve) => {
                self.continue_preserve(run, epoch).await
            }
            (PauseState::Borrowed, _) => {
                let finish = match run.borrowed.clone() {
                    // Exactly the same operation, token and freeze; nothing
                    // is resumed, refrozen or transferred.
                    Some(current) => Finish::Paused(
                        current.clone(),
                        CaptureContinuation::Preserved { preserved: current },
                    ),
                    None => Finish::Error(failure(
                        LiveFailureCode::PreserveFailed,
                        LiveStage::CapturePreserve,
                        "borrowed pause authority is missing",
                    )),
                };
                Some(finish)
            }
            // No established pause: roll back, never a token transfer.
            (PauseState::Frozen(epoch) | PauseState::NativePending(epoch), _) => {
                self.rollback_capture_pause(run, epoch).await
            }
            (PauseState::Untouched, _) => Some(Finish::Running(CaptureContinuation::Unchanged)),
        }
    }

    async fn finish_or_stop(&self, run: &mut Run, finish: Option<Finish>) {
        match finish {
            Some(finish) => self.finish(run, finish).await,
            None => self.capture_stopped(run),
        }
    }

    /// ClockOnly release of the exact capture-owned cut, then the shared
    /// handshake/thaw/readiness barriers. `None`: stop took over.
    async fn continue_resume(
        &self,
        run: &Run,
        epoch: NonZeroU64,
        generation: NativePauseGeneration,
    ) -> Option<Finish> {
        self.capture_stage(run, LiveStage::ResumeNative);
        let Some(identity) = run.identity.clone() else {
            return Some(Finish::Error(failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::ResumeNative,
                "capture continuation without a held guest identity",
            )));
        };
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::ContinueCapture {
                    operation: wire_uuid(&run.operation),
                    continuation: NativeContinuation::Resume,
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::Resumed { clock }) => {
                tracing::info!(operation = %run.operation, sequence = clock.sequence, "capture pause released with ClockOnly");
                self.lock().parked = false;
            }
            // A capture-owned pause is never shown as an idle user pause.
            Ok(CommandOutcome::ResumeFailed {
                stage,
                failure: native,
                ..
            }) => {
                return Some(Finish::Error(failure(
                    resume_code(stage),
                    resume_stage(stage),
                    native.to_string(),
                )))
            }
            Ok(outcome) => {
                return Some(Finish::Error(failure(
                    LiveFailureCode::NativeUncertain,
                    LiveStage::ResumeNative,
                    format!("unexpected native continuation outcome {outcome:?}"),
                )))
            }
            Err(NativeError::Stopped) => return None,
            Err(error) => {
                return Some(Finish::Error(failure(
                    error.code(LiveFailureCode::NativeResumeFailed),
                    LiveStage::ResumeNative,
                    error.describe(),
                )))
            }
        }
        // A lost thaw re-pauses under a fresh request identity: the
        // capture's own key already names its first pause.
        let Some(recovery_request) = live_id(Uuid::new_v4()) else {
            return Some(Finish::Error(failure(
                LiveFailureCode::RecoveryPauseFailed,
                LiveStage::RecoveryPause,
                "could not allocate a recovery request identity",
            )));
        };
        match self
            .continue_released(
                &run.operation,
                &run.operation,
                LiveCommandKind::Capture,
                &recovery_request,
                &identity,
                epoch,
                generation,
            )
            .await
        {
            Continued::Running => Some(Finish::Running(match run.cut.clone() {
                Some(consumed_token) => CaptureContinuation::Resumed {
                    consumed_token,
                    thawed_epoch: epoch,
                },
                None => CaptureContinuation::Unchanged,
            })),
            Continued::Recovered { current, cause } => Some(Finish::Paused(
                current,
                CaptureContinuation::ResumeFailed {
                    failure: cause,
                    state: VmLifecycleState::Paused,
                },
            )),
            Continued::Failed { cause, recovery } => Some(Finish::Error(recovery.unwrap_or(cause))),
            Continued::Stopped => None,
        }
    }

    /// Native ownership transfer of the cut to `user`; the acquiring
    /// Capture operation owns the resulting user authority.
    async fn continue_preserve(&self, run: &Run, epoch: NonZeroU64) -> Option<Finish> {
        self.capture_stage(run, LiveStage::CapturePreserve);
        let fail = |message: String| {
            Some(Finish::Error(failure(
                LiveFailureCode::PreserveFailed,
                LiveStage::CapturePreserve,
                message,
            )))
        };
        let result = self
            .native(self.native_request(
                &run.operation,
                LifecycleCommand::ContinueCapture {
                    operation: wire_uuid(&run.operation),
                    continuation: NativeContinuation::Preserve,
                    timeout: self.timeouts.native,
                },
            ))
            .await;
        match result {
            Ok(CommandOutcome::CapturePreserved { pause })
                if pause.owner == NativePauseOwner::User =>
            {
                let Some(generation) = NonZeroU64::new(pause.generation.get()) else {
                    return fail("preserved pause reported a zero generation".into());
                };
                let current = CurrentPause {
                    token: PauseToken {
                        machine_id: run.plan.machine_id.clone(),
                        run_id: run.plan.run_id.clone(),
                        generation,
                        owner: PauseOwner::User,
                    },
                    operation_id: run.operation.clone(),
                    freeze_epoch: epoch,
                };
                Some(Finish::Paused(
                    current.clone(),
                    CaptureContinuation::Preserved { preserved: current },
                ))
            }
            Ok(CommandOutcome::CaptureFailed {
                failure: native, ..
            }) => fail(native.to_string()),
            Ok(outcome) => fail(format!("unexpected native preserve outcome {outcome:?}")),
            Err(NativeError::Stopped) => None,
            Err(error) => Some(Finish::Error(failure(
                error.code(LiveFailureCode::PreserveFailed),
                LiveStage::CapturePreserve,
                error.describe(),
            ))),
        }
    }

    /// The guest freeze (and possibly a native pause request) took effect
    /// without an established token: settle native, thaw exactly, require
    /// readiness. `None`: stop took over.
    async fn rollback_capture_pause(&self, run: &mut Run, epoch: NonZeroU64) -> Option<Finish> {
        if run.pause == PauseState::NativePending(epoch) {
            self.capture_stage(run, LiveStage::CancelNative);
            let result = self
                .native(self.native_request(
                    &run.operation,
                    LifecycleCommand::CancelPause {
                        operation: wire_uuid(&run.operation),
                        timeout: self.timeouts.native,
                    },
                ))
                .await;
            match result {
                Ok(CommandOutcome::CancelSettled {
                    settlement: CancelSettlement::RetainedCompletedPause { pause },
                }) => {
                    // A completed capture pause retained under preserve is a
                    // real token: abandon the candidate, transfer to user.
                    run.pause = PauseState::Acquired(epoch, pause.generation);
                    run.cut = run.capture_token(pause.generation);
                    self.lock().parked = true;
                    match self.resolve_candidate(run).await {
                        Ok(()) => {}
                        Err(Abort::Stopped) => return None,
                        Err(Abort::Failed(cause)) => return Some(Finish::Error(cause)),
                    }
                    return self.continue_preserve(run, epoch).await;
                }
                Ok(CommandOutcome::CancelSettled { settlement }) => {
                    tracing::info!(operation = %run.operation, ?settlement, "capture pause rolled back");
                    self.lock().parked = false;
                }
                // The worker never accepted the pause: nothing to undo.
                Err(NativeError::Rejected(LifecycleRejection::UnknownTarget)) => {}
                Err(NativeError::Stopped) => return None,
                Ok(outcome) => {
                    return Some(Finish::Error(failure(
                        LiveFailureCode::NativeRollbackFailed,
                        LiveStage::CancelNative,
                        format!("capture pause rollback: {outcome:?}"),
                    )))
                }
                Err(error) => {
                    return Some(Finish::Error(failure(
                        error.code(LiveFailureCode::NativeRollbackFailed),
                        LiveStage::CancelNative,
                        error.describe(),
                    )))
                }
            }
        }
        let Some(identity) = run.identity.clone() else {
            return Some(Finish::Error(failure(
                LiveFailureCode::GuestUnavailable,
                LiveStage::RollbackThaw,
                "capture rollback without a held guest identity",
            )));
        };
        self.capture_stage(run, LiveStage::RollbackThaw);
        let reference = self.freeze_ref(&run.operation, epoch);
        match self
            .rollback_thaw(&identity, &reference, LiveStage::RollbackThaw)
            .await
        {
            Ok(thawed_at) => {
                self.capture_stage(run, LiveStage::Readiness);
                match self.await_readiness(thawed_at, &identity).await {
                    Ok(()) => Some(Finish::Running(CaptureContinuation::Unchanged)),
                    Err(GuestError::Stopped) => None,
                    Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                        Some(Finish::Error(cause))
                    }
                }
            }
            Err(GuestError::Stopped) => None,
            Err(GuestError::Refused(cause) | GuestError::Unknown(cause)) => {
                Some(Finish::Error(cause))
            }
        }
    }

    /// The worker journal owns retries, even after source stop/cancellation.
    /// An empty settlement list aborts any native cut retained before a failed reply.
    async fn settle_disks(&self, run: &mut Run, commit: bool) -> Result<(), LiveFailure> {
        if !run.disk_freeze_attempted {
            return Ok(());
        }
        let fail = |message: String| {
            failure(
                LiveFailureCode::BaselineAcceptFailed,
                LiveStage::CaptureAccept,
                message,
            )
        };
        let settlements = if commit {
            run.disk_receipts
                .iter()
                .map(|receipt| {
                    let map = run
                        .disk_maps
                        .iter()
                        .find(|(block, _)| block == &receipt.seed.block_id)
                        .ok_or_else(|| fail("sealed disk map is absent at settlement".into()))?;
                    Ok(vm_spec::capture::DiskTrackingSettlement {
                        version: vm_spec::capture::DISK_TRACKING_VERSION,
                        block_id: receipt.seed.block_id.clone(),
                        token: receipt.token.clone(),
                        settlement: vm_spec::capture::DiskGenerationSettlement::Commit {
                            baseline: map.1.id(),
                        },
                    })
                })
                .collect::<Result<Vec<_>, LiveFailure>>()?
        } else {
            Vec::new()
        };
        let mut request = self.native_request(
            &run.operation,
            LifecycleCommand::SettleCaptureDisks {
                operation: wire_uuid(&run.operation),
                settlements,
                timeout: self.timeouts.native,
            },
        );
        let deadline =
            tokio::time::Instant::now() + self.timeouts.native + std::time::Duration::from_secs(5);
        loop {
            match self.machine.lifecycle(request.clone()).await {
                Ok(response) => match response.command.map(|report| report.state) {
                    Some(CommandState::Completed {
                        outcome: CommandOutcome::DiskGenerationsSettled,
                    }) => break,
                    Some(CommandState::Accepted) => {}
                    Some(CommandState::Completed { outcome }) => {
                        return Err(fail(format!(
                            "disk generation settlement failed: {outcome:?}"
                        )))
                    }
                    None => return Err(fail("disk settlement omitted its journal report".into())),
                },
                Err(LifecycleError::Unknown(LifecycleUncertainty::WorkerLost)) => {
                    run.disk_freeze_attempted = false;
                    return Ok(());
                }
                Err(LifecycleError::Unknown(_)) if tokio::time::Instant::now() < deadline => {}
                Err(LifecycleError::Rejected(
                    LifecycleRejection::Busy | LifecycleRejection::CapturePending,
                )) if tokio::time::Instant::now() < deadline => {
                    request.request_id = Uuid::new_v4();
                }
                Err(error) => return Err(fail(error.to_string())),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(fail(
                    "disk settlement journal is unresolved; source remains fenced".into(),
                ));
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
        run.disk_freeze_attempted = false;
        if commit {
            if let Some(context) = &self.capture {
                let mut maps = context
                    .disk_baselines
                    .lock()
                    .map_err(|_| fail("accepted disk baseline owner is poisoned".into()))?;
                for (block, map) in &run.disk_maps {
                    if run
                        .plan
                        .disks
                        .iter()
                        .any(|disk| disk.block_id == *block && disk.tracking_eligible)
                    {
                        maps.insert(block.clone(), map.clone());
                    } else {
                        maps.remove(block);
                    }
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- unwind

    /// The capture did not seal. Resolve the native candidate (an uncertain
    /// preparation first by exact observation), write the failed diagnostic
    /// record, then continue the source under its policy.
    async fn unwind(&self, mut run: Run, abort: Abort) {
        if !run.plan.mode.clones_disks() {
            let committed = {
                let mut inner = self.lock();
                inner
                    .journal
                    .operation_mut(&run.operation)
                    .is_some_and(|record| {
                        if record.phase == Phase::HibernateCommitted {
                            true
                        } else {
                            record.phase = Phase::Continuing;
                            record.cancel.cancel();
                            false
                        }
                    })
            };
            if committed {
                return self.finish_hibernate(run).await;
            }
        }
        let disk_settlement = self.settle_disks(&mut run, false).await;
        let cause = match abort {
            Abort::Failed(cause) if !self.stop.is_cancelled() => cause,
            _ => {
                // The run is terminating, not continuing unsuccessfully. Leave
                // any retained cut for dead-run identity recovery; a failed
                // diagnostic would permanently prevent its publication.
                return self.capture_stopped(&mut run);
            }
        };
        if let Some(status) = self
            .lock()
            .journal
            .capture_mut(&run.operation)
            .and_then(|facts| facts.hibernation.as_mut())
        {
            status.phase = HibernateCapturePhase::Failed;
            status.failure = Some(cause.clone());
            status.cut = None;
            status.memory = None;
        }
        if let Err(cause) = disk_settlement {
            self.write_failed_record(&run, &cause).await;
            self.finish(&mut run, Finish::Error(cause)).await;
            return;
        }
        tracing::warn!(operation = %run.operation, cause = %cause, "capture failed before its seal");
        {
            let mut inner = self.lock();
            if let Some(record) = inner.journal.operation_mut(&run.operation) {
                record.record.outcome = OperationOutcome::Failed {
                    failure: cause.clone(),
                };
                // Cancel no longer interrupts: the source continuation runs.
                record.phase = Phase::Continuing;
            }
        }
        if let Some(finish) = run.continued.take() {
            self.write_failed_record(&run, &cause).await;
            self.finish(&mut run, finish).await;
            return;
        }
        match self.resolve_candidate(&mut run).await {
            Ok(()) => {}
            Err(Abort::Stopped) => {
                self.write_failed_record(&run, &cause).await;
                return self.capture_stopped(&mut run);
            }
            Err(Abort::Failed(unresolved)) => {
                self.write_failed_record(&run, &cause).await;
                return self.finish(&mut run, Finish::Error(unresolved)).await;
            }
        }
        if !run.plan.mode.clones_disks() {
            if let Some(staging) = run.staging.take() {
                let removed = tokio::task::spawn_blocking(move || staging.remove_hibernate()).await;
                if !matches!(removed, Ok(Ok(()))) {
                    tracing::error!(?removed, "remove failed hibernation files");
                    self.finish(&mut run, Finish::Error(failure(
                        LiveFailureCode::StagingFailed, LiveStage::CaptureAbandon,
                        "Could not remove the incomplete save; stop the machine before retrying",
                    ))).await;
                    return;
                }
            }
            run.plan.resume_policy = if run.borrowed.is_some() {
                CaptureResumePolicy::Preserve
            } else {
                CaptureResumePolicy::ResumeIfAcquired
            };
        }
        self.write_failed_record(&run, &cause).await;
        self.continue_source(&mut run).await;
    }

    /// Resolve the unsealed (or unaccepted) native candidate and close every
    /// worker output owner. The worker itself awaits pending native work to
    /// terminality within the command deadline before abandoning, so the
    /// first attempt is keyed on the capture. A refusal is retained by the
    /// worker per request identity: a refused attempt (another stage
    /// mutator still running) is retried only under a fresh identity.
    async fn abandon(&self, run: &Run) -> Result<(), Abort> {
        self.capture_stage(run, LiveStage::CaptureAbandon);
        let deadline = tokio::time::Instant::now() + self.timeouts.native;
        let mut request = run.operation.clone();
        loop {
            let result = self
                .native(self.native_request(
                    &request,
                    LifecycleCommand::AbandonCapture {
                        operation: wire_uuid(&run.operation),
                        timeout: self.timeouts.native,
                    },
                ))
                .await;
            match result {
                Ok(CommandOutcome::CaptureAbandoned) => return Ok(()),
                Err(NativeError::Rejected(
                    LifecycleRejection::CapturePending | LifecycleRejection::Busy,
                )) if tokio::time::Instant::now() < deadline => {
                    tokio::select! {
                        () = self.stop.cancelled() => return Err(Abort::Stopped),
                        () = tokio::time::sleep(RETRY_DELAY) => {}
                    }
                    request = live_id(Uuid::new_v4()).ok_or_else(|| {
                        Abort::Failed(failure(
                            LiveFailureCode::AbandonFailed,
                            LiveStage::CaptureAbandon,
                            "could not allocate an abandon request identity",
                        ))
                    })?;
                }
                Ok(CommandOutcome::CaptureFailed {
                    failure: native, ..
                }) => {
                    // Native work stayed pending past the deadline: the
                    // outputs remain owned; the source stays fenced.
                    return Err(Abort::Failed(failure(
                        LiveFailureCode::AbandonFailed,
                        LiveStage::CaptureAbandon,
                        native.to_string(),
                    )));
                }
                Ok(outcome) => {
                    return Err(Abort::Failed(failure(
                        LiveFailureCode::AbandonFailed,
                        LiveStage::CaptureAbandon,
                        format!("unexpected native abandon outcome {outcome:?}"),
                    )))
                }
                Err(error) => {
                    return Err(Abort::native(
                        error,
                        LiveFailureCode::AbandonFailed,
                        LiveStage::CaptureAbandon,
                    ))
                }
            }
        }
    }

    /// Diagnostic `captureOutcome: failed`, written once the same way as a
    /// seal. Its failure is logged; it never changes the operation outcome.
    async fn write_failed_record(&self, run: &Run, cause: &LiveFailure) {
        let (Some(staging), Some(evidence)) = (
            run.staging.clone(),
            run.evidence(
                CaptureRecordOutcome::Failed,
                Some(Diagnostic::new(cause.to_string())),
            ),
        ) else {
            return;
        };
        let bytes = match evidence.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(%error, "encode failed capture record");
                return;
            }
        };
        let sha256 = Sha256Digest::of_bytes(&bytes);
        let committed = tokio::task::spawn_blocking(move || {
            staging.commit_record(
                CAPTURE_EVIDENCE_FILE,
                CAPTURE_EVIDENCE_TEMPORARY_FILE,
                &bytes,
            )
        })
        .await;
        match committed {
            Ok(Ok(RecordCommit::Complete)) => {
                if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                    facts.evidence = Some(CaptureRecordReference::Identified {
                        evidence: CaptureEvidenceReference {
                            outcome: CaptureRecordOutcome::Failed,
                            sha256,
                        },
                    });
                }
            }
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                tracing::warn!(%error, operation = %run.operation, "failed capture record settlement uncertain")
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, operation = %run.operation, "could not write failed capture record")
            }
            Err(error) => {
                tracing::warn!(%error, operation = %run.operation, "failed capture record task failed")
            }
        }
    }

    // ------------------------------------------------------------- terminal

    /// Settle the operation (an unfinished outcome fails with `unfinished`)
    /// and complete joined cancellations with the final state.
    fn capture_terminal(
        &self,
        inner: &mut Inner,
        run: &Run,
        unfinished: Option<LiveFailure>,
        state: VmLifecycleState,
    ) {
        let Some(record) = inner.journal.operation_mut(&run.operation).map(|record| {
            if let (OperationOutcome::InProgress, Some(cause)) =
                (&record.record.outcome, unfinished)
            {
                record.record.outcome = OperationOutcome::Failed { failure: cause };
            }
            record.phase = Phase::Settled;
            record.record.clone()
        }) else {
            return;
        };
        for request in inner.journal.take_cancel_requests(&run.operation) {
            let result = if state.is_stopping_or_terminal() {
                stopped_cancel(record.clone())
            } else {
                LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed {
                    completed: CancelCompleted {
                        effective: matches!(
                            &record.outcome,
                            OperationOutcome::Failed { failure }
                                if failure.code == LiveFailureCode::Cancelled
                        ),
                        operation: record.clone(),
                        state,
                    },
                })
            };
            inner.journal.complete(&request, result);
        }
    }

    /// Record the observed continuation while capture still owns admission,
    /// then publish its final state and settle under the same journal lock.
    async fn finish(&self, run: &mut Run, finish: Finish) {
        if self.stop.is_cancelled() {
            return self.capture_stopped(run);
        }
        let continuation = match &finish {
            Finish::Running(continuation) | Finish::Paused(_, continuation) => continuation.clone(),
            Finish::Error(cause) => CaptureContinuation::ResumeFailed {
                failure: cause.clone(),
                state: VmLifecycleState::Error,
            },
        };
        if !run.source_continued {
            self.write_source_record(run, &continuation).await;
        }
        self.finish_projection(run, finish, true);
        if !run.plan.mode.clones_disks() {
            self.complete_hibernate_release(&run.operation, Ok(()));
        }
    }

    fn finish_projection(&self, run: &mut Run, finish: Finish, settle: bool) {
        let state = {
            let mut inner = self.lock();
            let (state, continuation, published) = match finish {
                Finish::Running(continuation) => {
                    inner.held = None;
                    inner.journal.current = None;
                    inner.parked = false;
                    let published = matches!(
                        self.publish(
                            &inner,
                            VmLifecycleState::Running,
                            None,
                            None,
                            false,
                            "running"
                        ),
                        Ok(true)
                    );
                    if published {
                        // Fences reopen last.
                        self.gate.reopen();
                    }
                    (VmLifecycleState::Running, continuation, published)
                }
                Finish::Paused(current, continuation) => {
                    inner.journal.current = Some(current);
                    inner.parked = true;
                    let published = matches!(
                        self.publish(
                            &inner,
                            VmLifecycleState::Paused,
                            None,
                            None,
                            false,
                            "paused"
                        ),
                        Ok(true)
                    );
                    if !published {
                        inner.journal.current = None;
                    }
                    (VmLifecycleState::Paused, continuation, published)
                }
                Finish::Error(cause) => {
                    tracing::error!(operation = %run.operation, cause = %cause, "capture continuation entered live Error");
                    inner.held = None;
                    inner.journal.current = None;
                    inner.parked = false;
                    let published = matches!(
                        self.publish(
                            &inner,
                            VmLifecycleState::Error,
                            None,
                            Some(cause.clone()),
                            false,
                            "live lifecycle error; fenced until stop"
                        ),
                        Ok(true)
                    );
                    if let Some(record) = inner.journal.operation_mut(&run.operation) {
                        if settle && record.record.outcome == OperationOutcome::InProgress {
                            record.record.outcome = OperationOutcome::Failed {
                                failure: cause.clone(),
                            };
                        }
                    }
                    (
                        VmLifecycleState::Error,
                        CaptureContinuation::ResumeFailed {
                            failure: cause,
                            state: VmLifecycleState::Error,
                        },
                        published,
                    )
                }
            };
            if !published {
                // Stop took over: no continuation is claimed.
                drop(inner);
                return self.capture_stopped(run);
            }
            if let Some(facts) = inner.journal.capture_mut(&run.operation) {
                facts.continuation = continuation.clone();
            }
            if settle {
                self.capture_terminal(&mut inner, run, None, state);
            }
            state
        };
        if settle {
            tracing::info!(operation = %run.operation, %state, "capture continuation finished");
        } else {
            tracing::info!(operation = %run.operation, %state, "capture source continued before disk identity");
        }
    }

    /// Stop took over: no continuation is claimed and no source record is
    /// fabricated; an absent record after the run ends means `unknown`.
    fn capture_stopped(&self, run: &mut Run) {
        let mut inner = self.lock();
        self.capture_terminal(
            &mut inner,
            run,
            Some(failure(
                LiveFailureCode::Stopped,
                LiveStage::Admission,
                "monitor is stopping",
            )),
            VmLifecycleState::Stopping,
        );
        tracing::info!(operation = %run.operation, "capture finalized by stop");
    }

    /// `vm.capture-source.json` for a terminal outcome of a source this
    /// capture paused or borrowed. A write failure leaves the real outcome
    /// in GetOperation; libvm never resumes because the file is absent.
    async fn write_source_record(&self, run: &Run, continuation: &CaptureContinuation) {
        if !run.plan.mode.clones_disks() {
            return;
        }
        let (Some(staging), Some(cut)) = (run.staging.clone(), run.cut.clone()) else {
            return;
        };
        let (outcome, error, current) = match continuation {
            CaptureContinuation::Resumed { .. } => (CaptureSourceOutcome::Resumed, None, None),
            CaptureContinuation::Preserved { preserved } => (
                CaptureSourceOutcome::Preserved,
                None,
                Some(preserved.token.clone()),
            ),
            CaptureContinuation::ResumeFailed { failure, .. } => (
                CaptureSourceOutcome::ResumeFailed,
                Some(Diagnostic::new(failure.to_string())),
                None,
            ),
            CaptureContinuation::Pending | CaptureContinuation::Unchanged => return,
        };
        let record = CaptureSourceRecord {
            version: CAPTURE_RECORD_VERSION,
            machine_id: run.plan.machine_id.clone(),
            run_id: run.plan.run_id.clone(),
            capture_id: run.plan.capture_id.clone(),
            pause_token: cut,
            source_outcome: outcome,
            error,
            current_pause: current,
            completed_at_unix_ms: now_ms(),
        };
        let bytes = match record.validate().and_then(|()| record.canonical_bytes()) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(%error, operation = %run.operation, "capture source record is inconsistent");
                return;
            }
        };
        let reference = if run.plan.identity_policy == CaptureIdentityPolicy::None {
            CaptureSourceReference::OwnedLocalCut {
                capture_id: run.plan.capture_id.clone(),
                outcome,
            }
        } else {
            CaptureSourceReference::Identified {
                sha256: Sha256Digest::of_bytes(&bytes),
            }
        };
        // A resumed source has already passed readiness. Keep its verified
        // identity eligible while persisting continuation, until Running
        // publishes and reopens the gates.
        self.publish_stage(
            &run.operation,
            &run.operation,
            LiveCommandKind::Capture,
            LiveStage::CaptureSourceRecord,
            matches!(continuation, CaptureContinuation::Resumed { .. }),
        );
        let committed = tokio::task::spawn_blocking(move || {
            staging.commit_record(CAPTURE_SOURCE_FILE, CAPTURE_SOURCE_TEMPORARY_FILE, &bytes)
        })
        .await;
        match committed {
            Ok(Ok(RecordCommit::Complete)) => {
                if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                    facts.source_record = Some(reference);
                }
            }
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                tracing::warn!(%error, operation = %run.operation, "capture source record settlement uncertain")
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, operation = %run.operation, "could not write capture source record")
            }
            Err(error) => {
                tracing::warn!(%error, operation = %run.operation, "capture source record task failed")
            }
        }
    }

    // --------------------------------------------------------------- release

    /// Release native capture-result ownership once libvm published or
    /// abandoned the result. An accepted baseline (and its pin) survives in
    /// the worker while the live source still maps the staging RAM.
    pub(crate) async fn run_release(
        self: Arc<Self>,
        request: LiveId,
        operation: LiveId,
        disposition: CaptureReleaseDisposition,
    ) {
        if self.signal_hibernate_release(&operation) {
            return;
        }
        let worker = self
            .lock()
            .journal
            .capture_mut(&operation)
            .map_or(WorkerPreparation::Absent, |facts| facts.worker);
        // An unanswered preparation is never evidence of absence: release
        // succeeds without the worker only after it definitively has no record.
        let holds = match worker {
            WorkerPreparation::Absent => Ok(false),
            WorkerPreparation::Prepared => Ok(true),
            WorkerPreparation::Uncertain => match self.reconcile_preparation(&operation).await {
                Ok(holds) => {
                    if let Some(facts) = self.lock().journal.capture_mut(&operation) {
                        facts.worker = if holds {
                            WorkerPreparation::Prepared
                        } else {
                            WorkerPreparation::Absent
                        };
                    }
                    Ok(holds)
                }
                Err(error) => Err(failure(
                    error.code(LiveFailureCode::ReleaseFailed),
                    LiveStage::CaptureRelease,
                    format!("capture preparation is unresolved: {}", error.describe()),
                )),
            },
        };
        let outcome = match holds {
            Ok(true) => {
                tracing::debug!(operation = %operation, request = %request, "releasing native capture ownership");
                match self
                    .native(self.native_request(
                        &request,
                        LifecycleCommand::ReleaseCapture {
                            operation: wire_uuid(&operation),
                            timeout: self.timeouts.native,
                        },
                    ))
                    .await
                {
                    Ok(CommandOutcome::CaptureReleased { baseline_retained }) => {
                        Ok(baseline_retained)
                    }
                    Ok(outcome) => Err(failure(
                        LiveFailureCode::ReleaseFailed,
                        LiveStage::CaptureRelease,
                        format!("unexpected native release outcome {outcome:?}"),
                    )),
                    Err(error) => Err(failure(
                        error.code(LiveFailureCode::ReleaseFailed),
                        LiveStage::CaptureRelease,
                        error.describe(),
                    )),
                }
            }
            // The worker definitively never held this capture.
            Ok(false) => Ok(false),
            Err(cause) => Err(cause),
        };
        let state = self
            .store
            .live_snapshot()
            .map_or(VmLifecycleState::Stopping, |snapshot| snapshot.state);
        let mut inner = self.lock();
        let result = match outcome {
            Ok(baseline_retained) => {
                if let Some(facts) = inner.journal.capture_mut(&operation) {
                    facts.release = CaptureReleaseState::Released {
                        disposition,
                        baseline_retained,
                    };
                }
                tracing::info!(operation = %operation, ?disposition, baseline_retained, "capture released");
                LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Released {
                    released: CaptureReleased {
                        operation_id: operation.clone(),
                        disposition,
                        baseline_retained,
                        state,
                    },
                })
            }
            Err(cause) => {
                tracing::warn!(operation = %operation, cause = %cause, "capture release failed");
                LiveCommandResult::ReleaseCapture(ReleaseCaptureOutcome::Failed {
                    failed: ReleaseFailed { cause, state },
                })
            }
        };
        for waiting in inner.journal.take_release_requests(&operation) {
            inner.journal.complete(&waiting, result.clone());
        }
    }
}

struct RamVerification<'a> {
    limit: u64,
    map: Arc<StreamRoot>,
    authenticated_changes: Option<&'a vm_spec::capture::CaptureRamChanges>,
}

/// Validate closed writer fingerprints and lengths, resolve stream identities
/// from the recorded maps, and authenticate only the small state roles.
fn verify_staging(
    staging: &CaptureStaging,
    roles: &[CaptureRole],
    disks: &[CaptureDiskPlan],
    outputs: CaptureOutputIdentities,
    ram: RamVerification<'_>,
    abort: &CancellationToken,
) -> io::Result<Verified> {
    let RamVerification {
        limit: ram_limit,
        map,
        authenticated_changes,
    } = ram;
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    map.validate_role(StreamRole::Ram)
        .map_err(io::Error::other)?;
    let staged_request_bytes = staging.request_allocation()?;
    if roles.contains(&CaptureRole::RamMap) {
        staging.publish_map(&CaptureRole::RamMap, &map)?;
    }
    let mut inventory = Vec::with_capacity(roles.len());
    let mut state_bytes = 0u64;
    let mut staged_bytes = staged_request_bytes;
    let mut geometry = None;
    let mut ram = None;
    for role in roles {
        let verified = verify_role(
            staging,
            role,
            disks,
            outputs,
            &map,
            authenticated_changes,
            abort,
        )?;
        state_bytes = state_bytes.saturating_add(verified.state_bytes);
        staged_bytes = staged_bytes.saturating_add(verified.staged_bytes);
        geometry = verified.geometry.or(geometry);
        if *role == CaptureRole::Ram {
            ram = verified
                .entry
                .identity
                .map(|identity| (verified.entry.length, identity));
        }
        inventory.push(verified.entry);
    }
    staged_bytes = staged_bytes.saturating_add(staging.directory_allocation()?);
    if state_bytes > CAPTURE_STATE_RESERVE_BYTES {
        return Err(invalid("captured state exceeds its 64 MiB reserve".into()));
    }
    let (Some(geometry), Some((ram_length, ram_stream))) = (geometry, ram) else {
        return Err(invalid("RAM image or layout is missing".into()));
    };
    if geometry.packed_length != ram_length || ram_length > ram_limit {
        return Err(invalid(
            "RAM length differs from its layout or the planned memory".into(),
        ));
    }
    Ok(Verified {
        inventory,
        packed_length: geometry.packed_length,
        page_granule: geometry.page_granule,
        regions: geometry.regions,
        ram_stream,
        staged_bytes,
        map,
    })
}

/// Authentication of one exact staged inode, before cross-role reduction.
#[derive(Debug)]
struct VerifiedRole {
    entry: CaptureInventoryEntry,
    state_bytes: u64,
    staged_bytes: u64,
    geometry: Option<LayoutGeometry>,
}

fn verify_role(
    staging: &CaptureStaging,
    role: &CaptureRole,
    disks: &[CaptureDiskPlan],
    outputs: CaptureOutputIdentities,
    ram_map: &StreamRoot,
    authenticated_changes: Option<&vm_spec::capture::CaptureRamChanges>,
    abort: &CancellationToken,
) -> io::Result<VerifiedRole> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    if abort.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "capture verification cancelled",
        ));
    }
    let (file, facts) = staging.open_sealed(role)?;
    let prepared = match role {
        CaptureRole::Execution => Some(outputs.execution),
        CaptureRole::Devices => Some(outputs.devices),
        CaptureRole::Ram => Some(outputs.ram),
        CaptureRole::Layout => Some(outputs.layout),
        CaptureRole::RamChanges => Some(outputs.changes),
        CaptureRole::Disk(_) | CaptureRole::RamMap | CaptureRole::DiskMap(_) => None,
    };
    if let Some(expected) = prepared {
        if (facts.device, facts.inode) != (expected.device, expected.inode) {
            return Err(invalid(format!(
                "{} is not the prepared output inode",
                role.relative_path()
            )));
        }
    }
    let disk = match role {
        CaptureRole::Disk(name) => Some(
            disks
                .iter()
                .find(|disk| disk.name == *name)
                .ok_or_else(|| invalid(format!("{} has no disk plan", role.relative_path())))?,
        ),
        _ => None,
    };
    if disk.is_some_and(|disk| facts.length != disk.length) {
        return Err(invalid(format!(
            "{} length differs from its attachment",
            role.relative_path()
        )));
    }
    if matches!(role, CaptureRole::RamMap | CaptureRole::DiskMap(_))
        && facts.length > MAX_ROOT_BYTES as u64
    {
        return Err(invalid(
            "complete RAM map exceeds its metadata bound".into(),
        ));
    }
    let state_bytes = if matches!(
        role,
        CaptureRole::Execution
            | CaptureRole::Devices
            | CaptureRole::Layout
            | CaptureRole::RamMap
            | CaptureRole::DiskMap(_)
    ) {
        if facts.length == 0 {
            return Err(invalid(format!("{} is empty", role.relative_path())));
        }
        facts.length
    } else {
        0
    };
    let geometry = if *role == CaptureRole::Layout {
        if facts.length > MAX_LAYOUT_BYTES {
            return Err(invalid(format!("{CAPTURE_LAYOUT_FILE} exceeds its bound")));
        }
        let length =
            usize::try_from(facts.length).map_err(|_| invalid("layout length overflows".into()))?;
        let mut bytes = vec![0u8; length];
        std::os::unix::fs::FileExt::read_exact_at(&file, &mut bytes, 0)?;
        Some(parse_layout(&bytes)?)
    } else {
        None
    };
    let (sha256, identity) = match role {
        CaptureRole::Ram => {
            if facts.length != ram_map.length() {
                return Err(invalid(
                    "RAM receipt length differs from the closed file".into(),
                ));
            }
            (None, Some(ram_map.id()))
        }
        CaptureRole::RamChanges if authenticated_changes.is_some() => {
            let summary = authenticated_changes
                .ok_or_else(|| invalid("RAM change summary missing".into()))?;
            if facts.length != summary.byte_len {
                return Err(invalid(
                    "RAM change file changed length after assembly".into(),
                ));
            }
            (Some(summary.sha256), None)
        }
        CaptureRole::Disk(name) => {
            let (map_file, map_facts) = staging.open_sealed(&CaptureRole::DiskMap(name.clone()))?;
            let limit = MAX_ROOT_BYTES as u64;
            if map_facts.length > limit {
                return Err(invalid("disk map exceeds its metadata bound".into()));
            }
            let mut bytes = vec![0; map_facts.length as usize];
            std::os::unix::fs::FileExt::read_exact_at(&map_file, &mut bytes, 0)?;
            let map = StreamRoot::decode(&bytes).map_err(io::Error::other)?;
            map.validate_role(StreamRole::Disk)
                .map_err(io::Error::other)?;
            if map.length() != facts.length {
                return Err(invalid(
                    "disk map length differs from its closed file".into(),
                ));
            }
            (None, Some(map.id()))
        }
        _ => (Some(hash_state(&file, facts.length, abort)?), None),
    };
    let staged_bytes = match disk.map(|disk| disk.copy) {
        Some(CaptureDiskCopy::Clone) => CAPTURE_CLONE_RESERVE_BYTES,
        Some(CaptureDiskCopy::Copy) | None => {
            std::os::unix::fs::MetadataExt::blocks(&file.metadata()?).saturating_mul(512)
        }
    };
    Ok(VerifiedRole {
        entry: CaptureInventoryEntry {
            role: role.clone(),
            length: facts.length,
            sha256,
            identity,
        },
        state_bytes,
        staged_bytes,
        geometry,
    })
}

/// Charge the sealed staging total against libvm's pre-freeze reservation
/// (ADR 0021 `Resource Limits`): the planned RAM, each copied disk's
/// allocation when reserved, each clone's metadata charge and a 64 MiB state
/// and evidence allowance.
///
/// A running source keeps allocating (guest writes into holes of a sparse
/// raw disk) between that reservation and the pause, so any earlier sample
/// of its allocation races the guest. The race-free bound is the actual
/// total once every file is synced: `staged` bytes plus the two control
/// records still to be written (`vm.capture.json` before the seal and
/// `vm.capture-source.json` after it), each charged at its enforced
/// [`MAX_CAPTURE_RECORD_BYTES`] bound. Unused RAM and state allowance
/// absorbs disk growth; the allowance itself is never counted as usage.
/// Exceeding the total fails the capture before its seal.
///
/// This is libvm's accounting charge, not a host filesystem quota: it bounds
/// what this capture consumes against what libvm charged, and claims nothing
/// about allocation by any other host writer.
fn staging_budget(reserved: u64, staged: u64) -> Result<u64, LiveFailure> {
    let records = 2 * MAX_CAPTURE_RECORD_BYTES as u64;
    let total = staged.saturating_add(records);
    if total > reserved {
        return Err(failure(
            LiveFailureCode::StagingBudgetExceeded,
            LiveStage::CaptureVerify,
            format!(
                "sealed staging needs {} ({} staged, {} bounded \
                 control records), the reservation holds {} (short by {})",
                utils::format_storage_size(total),
                utils::format_storage_size(staged),
                utils::format_storage_size(records),
                utils::format_storage_size(reserved),
                utils::format_storage_size(total.saturating_sub(reserved))
            ),
        ));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;
    use vm_spec::capture::{
        CaptureDiskCopy, CaptureDiskName, CaptureDiskPlan, CaptureRole, Sha256Digest,
        CAPTURE_CLONE_RESERVE_BYTES, CAPTURE_REQUEST_FILE, CAPTURE_STATE_RESERVE_BYTES,
        MAX_CAPTURE_RECORD_BYTES,
    };
    use vm_spec::lifecycle::{LiveFailureCode, LiveId, LiveStage};
    use vm_spec::stream_map::{build_sorted, ChunkSize, PresentChunk, StreamRoot};

    use crate::live::coordinator::capture::{staging_budget, RamVerification, Verified};
    use crate::live::staging::CaptureStaging;
    use crate::virt::lifecycle::{CaptureOutputIdentities, OutputIdentity};

    #[test]
    fn hibernate_memory_estimate_requires_rss_and_swap_with_checked_units() {
        use crate::live::coordinator::capture::parse_populated_memory_estimate;
        assert_eq!(
            parse_populated_memory_estimate(
                "0000-ffff ---p [rollup]\nRss: 1024 kB\nPss: 99 kB\nSwap: 32 kB\n"
            )
            .unwrap(),
            1056 * 1024
        );
        for text in [
            "",
            "Rss: 1 kB",
            "Swap: 1 kB",
            "Rss: 1 MB\nSwap: 0 kB",
            "Rss: -1 kB\nSwap: 0 kB",
            "Rss: 1 kB\nRss: 1 kB\nSwap: 0 kB",
            "Rss: 18446744073709551615 kB\nSwap: 1 kB",
            "Rss: 1 kB extra\nSwap: 0 kB",
            "Rss: 18446744073709551615 kB\nSwap: 0 kB",
        ] {
            assert!(parse_populated_memory_estimate(text).is_err(), "{text}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hibernate_memory_estimate_reads_the_current_process_rollup() {
        let text = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
        assert!(
            crate::live::coordinator::capture::parse_populated_memory_estimate(&text).unwrap() > 0
        );
    }

    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const LAYOUT: &[u8] = br#"{"architecture":"x86_64","kind":"ram-layout","magic":"KRUNRAML","packedLength":8192,"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":8192,"streamOffset":0}],"schema":1,"topology":{"ramBelowGap":8192}}"#;

    /// Logical length of the staged fixture's writable source.
    const SOURCE_BYTES: u64 = 1 << 20;
    /// Planned RAM of the staged fixture (its RAM image is 8 KiB).
    const PLANNED_RAM: u64 = 1 << 20;
    /// Both bounded control records still to be written at verification.
    const RECORDS: u64 = 2 * MAX_CAPTURE_RECORD_BYTES as u64;

    struct Staged {
        _root: Root,
        staging: CaptureStaging,
        outputs: CaptureOutputIdentities,
        roles: Vec<CaptureRole>,
        /// Source allocation when libvm reserved, before the `grown` writes.
        reserved_disk: u64,
    }

    fn staged() -> (
        Root,
        CaptureStaging,
        CaptureOutputIdentities,
        Vec<CaptureRole>,
    ) {
        let staged = staged_with(4096, &[], &[]);
        (staged._root, staged.staging, staged.outputs, staged.roles)
    }

    /// Staging with every role sealed. The source writes nonzero 4 KiB
    /// blocks at `reserved` offsets, records its allocation as libvm's
    /// reservation sample, then writes `grown` offsets (the running guest
    /// filling holes before the pause) and is copied into the disk role.
    fn staged_with(length: u64, reserved: &[u64], grown: &[u64]) -> Staged {
        let root = Root(std::env::temp_dir().join(format!(
            "silo-verify-{:x}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        )));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root.0)
            .unwrap();
        let id = LiveId::parse(&uuid::Uuid::new_v4().hyphenated().to_string()).unwrap();
        let staging = CaptureStaging::create(&root.0, &id).unwrap();
        staging.write_request(b"{\"request\":true}").unwrap();
        let write = |role: &CaptureRole, bytes: &[u8]| {
            let mut file = staging.create_output(role).unwrap();
            file.write_all(bytes).unwrap();
            OutputIdentity::of(&file).unwrap()
        };
        let outputs = CaptureOutputIdentities {
            execution: write(&CaptureRole::Execution, b"execution"),
            devices: write(&CaptureRole::Devices, b"devices"),
            ram: write(&CaptureRole::Ram, &[7u8; 8192]),
            layout: write(&CaptureRole::Layout, LAYOUT),
            changes: write(&CaptureRole::RamChanges, b"KRUNRAM\0\x01\0\x10\0\0\0\0\0"),
        };
        let source = root.0.join("source.raw");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        file.set_len(length).unwrap();
        let fill = |offsets: &[u64]| {
            for offset in offsets {
                file.write_all_at(&[0x5a; 4096], *offset).unwrap();
            }
            file.sync_all().unwrap();
        };
        fill(reserved);
        let reserved_disk = file.metadata().unwrap().blocks() * 512;
        fill(grown);
        let disk = CaptureRole::Disk(CaptureDiskName::new("data").unwrap());
        let method = staging
            .copy_disk(
                &disk,
                &file,
                length,
                CaptureDiskCopy::Copy,
                vm_spec::capture::CaptureIdentityPolicy::Full,
                &CancellationToken::new(),
            )
            .unwrap();
        if method == crate::live::staging::DiskCopyMethod::Clone {
            let name = CaptureDiskName::new("data").unwrap();
            staging
                .complete_disk_identity(
                    &staging.disk_cut(&name).unwrap(),
                    None,
                    true,
                    &CancellationToken::new(),
                )
                .unwrap();
        }
        let roles = vec![
            CaptureRole::Execution,
            CaptureRole::Devices,
            CaptureRole::Ram,
            CaptureRole::Layout,
            disk,
            CaptureRole::DiskMap(CaptureDiskName::new("data").unwrap()),
        ];
        Staged {
            _root: root,
            staging,
            outputs,
            roles,
            reserved_disk,
        }
    }

    fn disk_plan(length: u64, copy: CaptureDiskCopy) -> Vec<CaptureDiskPlan> {
        vec![CaptureDiskPlan {
            identity: vm_spec::capture::DiskIdentityState::Unknown,
            name: CaptureDiskName::new("data").unwrap(),
            attachment_index: 0,
            block_id: vm_spec::BlockId::new("data").unwrap(),
            length,
            copy,
            baseline_map: None,
            tracking_eligible: true,
        }]
    }

    fn ram_map() -> Arc<StreamRoot> {
        let (_directory, staging, _, _) = staged();
        Arc::new(
            build_sorted(
                8192,
                ChunkSize::RAM,
                [Ok(PresentChunk {
                    index: 0,
                    digest: Sha256Digest::of_bytes(&[7; 8192]),
                })],
                &mut staging.node_sink(),
            )
            .unwrap(),
        )
    }

    fn verify_staging(
        staging: &CaptureStaging,
        roles: &[CaptureRole],
        disks: &[CaptureDiskPlan],
        outputs: CaptureOutputIdentities,
        ram_limit: u64,
        map: Arc<StreamRoot>,
        abort: &CancellationToken,
    ) -> std::io::Result<Verified> {
        crate::live::coordinator::capture::verify_staging(
            staging,
            roles,
            disks,
            outputs,
            RamVerification {
                limit: ram_limit,
                map,
                authenticated_changes: None,
            },
            abort,
        )
    }

    fn allocated(path: &Path) -> u64 {
        std::fs::metadata(path).unwrap().blocks() * 512
    }

    #[test]
    fn verification_binds_prepared_inodes_layout_and_lengths() {
        let (_root, staging, outputs, roles) = staged();
        let disks = disk_plan(4096, CaptureDiskCopy::Copy);
        let verified = verify_staging(
            &staging,
            &roles,
            &disks,
            outputs,
            1 << 20,
            ram_map(),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(verified.inventory.len(), 6);
        assert_eq!(
            verified
                .inventory
                .iter()
                .map(|entry| &entry.role)
                .collect::<Vec<_>>(),
            roles.iter().collect::<Vec<_>>()
        );
        for entry in &verified.inventory {
            let bytes = std::fs::read(staging.path().join(entry.role.relative_path())).unwrap();
            assert_eq!(entry.length, bytes.len() as u64);
            if let Some(digest) = entry.sha256 {
                assert_eq!(digest, Sha256Digest::of_bytes(&bytes));
                assert!(entry.identity.is_none());
            } else {
                let chunk_size = if entry.role == CaptureRole::Ram {
                    ChunkSize::RAM
                } else {
                    ChunkSize::DISK
                };
                let present = bytes
                    .chunks(chunk_size.bytes() as usize)
                    .enumerate()
                    .filter(|(_, chunk)| !vm_spec::capture::is_all_zero(chunk))
                    .map(|(index, chunk)| {
                        Ok(PresentChunk {
                            index: index as u64,
                            digest: Sha256Digest::of_bytes(chunk),
                        })
                    });
                let root = build_sorted(
                    bytes.len() as u64,
                    chunk_size,
                    present,
                    &mut staging.node_sink(),
                )
                .unwrap();
                assert_eq!(entry.identity, Some(root.id()));
            }
        }
        assert_eq!(verified.packed_length, 8192);
        assert_eq!(verified.regions, 1);
        let ram = &verified.inventory[2];
        assert_eq!(ram.role, CaptureRole::Ram);
        assert_eq!(ram.length, 8192);
        assert_eq!(ram.sha256, None);
        assert_eq!(ram.identity, Some(ram_map().id()));

        // RAM beyond the planned memory is refused.
        assert!(verify_staging(
            &staging,
            &roles,
            &disks,
            outputs,
            4096,
            ram_map(),
            &CancellationToken::new()
        )
        .is_err());
        // A role that is not the prepared inode is refused.
        let mut swapped = outputs;
        swapped.ram = outputs.layout;
        assert!(verify_staging(
            &staging,
            &roles,
            &disks,
            swapped,
            1 << 20,
            ram_map(),
            &CancellationToken::new()
        )
        .is_err());
        // A disk whose length differs from its attachment is refused.
        let wrong = disk_plan(8192, CaptureDiskCopy::Copy);
        assert!(verify_staging(
            &staging,
            &roles,
            &wrong,
            outputs,
            1 << 20,
            ram_map(),
            &CancellationToken::new()
        )
        .is_err());
        // A missing role is refused.
        let mut missing = roles.clone();
        missing.push(CaptureRole::Disk(CaptureDiskName::new("absent").unwrap()));
        assert!(verify_staging(
            &staging,
            &missing,
            &disks,
            outputs,
            1 << 20,
            ram_map(),
            &CancellationToken::new()
        )
        .is_err());
    }

    #[test]
    fn verification_refuses_a_ram_image_that_disagrees_with_its_layout() {
        let (_root, staging, outputs, roles) = staged();
        let disks = disk_plan(4096, CaptureDiskCopy::Copy);
        // Grow RAM behind the layout's packed length.
        let path = staging.path().join("memory.ram");
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(12288).unwrap();
        assert!(verify_staging(
            &staging,
            &roles,
            &disks,
            outputs,
            1 << 20,
            ram_map(),
            &CancellationToken::new()
        )
        .is_err());
    }

    #[test]
    fn verification_charges_actual_staged_allocation() {
        let staged = staged_with(SOURCE_BYTES, &[0, SOURCE_BYTES / 2], &[]);
        let verify = |copy| {
            verify_staging(
                &staged.staging,
                &staged.roles,
                &disk_plan(SOURCE_BYTES, copy),
                staged.outputs,
                PLANNED_RAM,
                ram_map(),
                &CancellationToken::new(),
            )
            .unwrap()
        };
        // Copy-planned: the sealed role's actual allocation, never its length.
        let copied = verify(CaptureDiskCopy::Copy);
        let directory = staged.staging.path();
        let state: u64 = [
            directory.join(CAPTURE_REQUEST_FILE),
            directory.join(staged.roles[5].relative_path()),
        ]
        .into_iter()
        .chain(
            staged.roles[..4]
                .iter()
                .map(|role| directory.join(role.relative_path())),
        )
        .map(|path| allocated(&path))
        .sum::<u64>()
            + staged.staging.directory_allocation().unwrap();
        let disk = allocated(&directory.join(staged.roles[4].relative_path()));
        assert!(disk > 0 && state > 0);
        assert_eq!(copied.staged_bytes, state + disk);
        assert!(disk < SOURCE_BYTES, "holes stay unallocated");
        // Clone-planned: the contract's metadata charge, not shared extents.
        let cloned = verify(CaptureDiskCopy::Clone);
        assert_eq!(cloned.staged_bytes, state + CAPTURE_CLONE_RESERVE_BYTES);
        // The 64 MiB state allowance is a reservation term, never usage.
        assert!(copied.staged_bytes < CAPTURE_STATE_RESERVE_BYTES);
    }

    #[test]
    fn staging_budget_admits_source_growth_within_the_reserved_total() {
        // libvm sampled one allocated block; the running guest then filled a
        // hole before the pause, as the retained real-VM refusals observed.
        let staged = staged_with(SOURCE_BYTES, &[0], &[SOURCE_BYTES / 2]);
        let verified = verify_staging(
            &staged.staging,
            &staged.roles,
            &disk_plan(SOURCE_BYTES, CaptureDiskCopy::Copy),
            staged.outputs,
            PLANNED_RAM,
            ram_map(),
            &CancellationToken::new(),
        )
        .unwrap();
        let sealed_disk = allocated(&staged.staging.path().join(staged.roles[4].relative_path()));
        assert!(
            sealed_disk > staged.reserved_disk,
            "the source grew after its reservation"
        );
        // ADR 0021 formula at reservation time.
        let reserved = PLANNED_RAM + CAPTURE_STATE_RESERVE_BYTES + staged.reserved_disk;
        // A second pre-freeze allocation sample would refuse this capture.
        assert!(PLANNED_RAM + CAPTURE_STATE_RESERVE_BYTES + sealed_disk > reserved);
        assert_eq!(
            staging_budget(reserved, verified.staged_bytes).unwrap(),
            verified.staged_bytes + RECORDS
        );
    }

    #[test]
    fn staging_budget_fails_a_sealed_total_beyond_the_reservation() {
        let staged = staged_with(SOURCE_BYTES, &[0, SOURCE_BYTES / 2], &[]);
        let verified = verify_staging(
            &staged.staging,
            &staged.roles,
            &disk_plan(SOURCE_BYTES, CaptureDiskCopy::Copy),
            staged.outputs,
            PLANNED_RAM,
            ram_map(),
            &CancellationToken::new(),
        )
        .unwrap();
        let exact = verified.staged_bytes + RECORDS;
        assert_eq!(staging_budget(exact, verified.staged_bytes).unwrap(), exact);
        let refused = staging_budget(exact - 1, verified.staged_bytes).unwrap_err();
        assert_eq!(refused.code, LiveFailureCode::StagingBudgetExceeded);
        assert_eq!(refused.stage, LiveStage::CaptureVerify);
        let message = refused.message.unwrap().to_string();
        assert!(
            message.contains(&utils::format_storage_size(exact)),
            "{message}"
        );
        assert!(
            message.contains(&utils::format_storage_size(exact - 1)),
            "{message}"
        );
        assert!(message.ends_with("(short by 1B)"), "{message}");
    }

    #[test]
    fn only_a_definitive_refusal_proves_no_worker_owns_a_preparation() {
        use crate::live::coordinator::capture::prepared_ownership;
        use crate::live::coordinator::NativeError;
        use crate::live::journal::WorkerPreparation;
        use crate::virt::lifecycle::{
            CommandOutcome, LifecycleRejection, OutputDefect, OutputProblem, OutputRole,
        };

        let identity = OutputIdentity {
            device: 1,
            inode: 2,
        };
        let outputs = CaptureOutputIdentities {
            execution: identity,
            devices: identity,
            ram: identity,
            layout: identity,
            changes: identity,
        };
        assert_eq!(
            prepared_ownership(&Ok(CommandOutcome::CapturePrepared {
                outputs,
                pin: identity,
            })),
            WorkerPreparation::Prepared
        );
        for refused in [
            LifecycleRejection::Busy,
            LifecycleRejection::CaptureActive,
            LifecycleRejection::Stopping,
            LifecycleRejection::CaptureOutputs(OutputProblem {
                role: OutputRole::Ram,
                problem: OutputDefect::NotEmpty,
            }),
        ] {
            assert_eq!(
                prepared_ownership(&Err(NativeError::Rejected(refused))),
                WorkerPreparation::Absent,
                "{refused:?} is refused at admission, before any ownership"
            );
        }
        assert_eq!(
            prepared_ownership(&Err(NativeError::Unsupported("vz".into()))),
            WorkerPreparation::Absent
        );
        // A lost report, a lost worker, a stop racing submission, an
        // existing worker record or an unexpected answer never prove absence.
        for unanswered in [
            Err(NativeError::Uncertain(
                "worker did not acknowledge the command".into(),
            )),
            Err(NativeError::WorkerLost("gone".into())),
            Err(NativeError::Stopped),
            Err(NativeError::Rejected(LifecycleRejection::RequestConflict)),
            Ok(CommandOutcome::CaptureAbandoned),
        ] {
            assert_eq!(
                prepared_ownership(&unanswered),
                WorkerPreparation::Uncertain
            );
        }
    }

    #[test]
    fn complete_map_sidecar_is_canonical_authenticated_and_part_of_staged_inventory() {
        let (_root, staging, outputs, mut roles) = staged();
        roles.insert(4, CaptureRole::RamMap);
        let disks = disk_plan(4096, CaptureDiskCopy::Copy);
        let verified = verify_staging(
            &staging,
            &roles,
            &disks,
            outputs,
            PLANNED_RAM,
            ram_map(),
            &CancellationToken::new(),
        )
        .unwrap();
        let bytes = std::fs::read(staging.path().join("memory.root")).unwrap();
        let map = StreamRoot::decode(&bytes).unwrap();
        assert_eq!(map.canonical_bytes().unwrap(), bytes);
        assert_eq!(map.id(), verified.ram_stream);
        assert_eq!(&map, verified.map.as_ref());
        assert_eq!(verified.inventory[4].role, CaptureRole::RamMap);
        assert_eq!(verified.inventory[4].length, bytes.len() as u64);
        assert_eq!(
            verified.inventory[4].sha256,
            Some(vm_spec::capture::Sha256Digest::of_bytes(&bytes))
        );
        assert_eq!(
            std::fs::metadata(staging.path().join("memory.root"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

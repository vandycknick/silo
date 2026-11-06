//! ADR 0021 full capture on the run's single live coordinator.
//!
//! ```text
//!  admit ─► prepare[staging, request.json, 4 outputs + launch-lease pin ─► worker]
//!        ─► pause[acquire: drain → freeze(e) → native Capture pause | borrow user pause]
//!        ─► flush[exact cut] ─► disks[clone/copy every writable role, sync]
//!        ─► execution+devices ─► full RAM ─► native facts ─► verify[hash, layout, sync]
//!        ─► seal[cancel/stop linearized; write-once vm.capture.json; dir fsync]
//!        ═══ capture succeeded ═══ (cancel no longer has effect)
//!        ─► accept baseline ─► continue[resume-if-acquired | preserve] ─► vm.capture-source.json
//!
//!  unsealed failure/cancel ─► abandon native candidate ─► failed vm.capture.json
//!                          ─► continue under policy (or roll back an unestablished pause)
//! ```
//!
//! Capture success and source continuation are distinct facts: a failed
//! continuation never touches the seal, and a successful continuation never
//! turns a failed capture into a success. Nothing here unlinks staging.
use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::Digest as _;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vm_spec::capture::{
    CaptureConfiguration, CaptureContinuation, CaptureDiskCopy, CaptureDiskPlan, CaptureEvidence,
    CaptureEvidenceReference, CaptureInventoryEntry, CaptureLaunchLease, CaptureMemoryEvidence,
    CapturePauseAuthority, CapturePauseDisposition, CapturePlan, CaptureRecordOutcome,
    CaptureReleaseDisposition, CaptureReleaseState, CaptureReleased, CaptureRole, CaptureSealed,
    CaptureSourceOutcome, CaptureSourceRecord, CaptureStateBinding, Sha256Digest,
    CAPTURE_CLONE_RESERVE_BYTES, CAPTURE_EVIDENCE_FILE, CAPTURE_EVIDENCE_TEMPORARY_FILE,
    CAPTURE_LAYOUT_FILE, CAPTURE_RECORD_VERSION, CAPTURE_SOURCE_FILE,
    CAPTURE_SOURCE_TEMPORARY_FILE, CAPTURE_STATE_RESERVE_BYTES, MAX_CAPTURE_RECORD_BYTES,
};
use vm_spec::lifecycle::{
    CancelCompleted, CancelOperationOutcome, CaptureResumePolicy, CurrentPause, Diagnostic,
    LiveCommandKind, LiveCommandResult, LiveFailure, LiveFailureCode, LiveId, LiveOperationRecord,
    LiveRejectionReason, LiveStage, OperationKind, OperationOutcome, PauseOwner, PauseToken,
    ReleaseCaptureOutcome, ReleaseFailed, VmLifecycleState,
};
use vm_spec::live::{LiveBackend, LiveDeviceSubject, LiveLane, LiveOperation};

use crate::live::coordinator::{
    failure, guest_observation, resume_code, resume_stage, stopped_cancel, wire_uuid, Continued,
    GuestError, Inner, LiveCoordinator, LiveError, NativeError, NATIVE_TRANSPORT_RETRIES,
    RETRY_DELAY,
};
use crate::live::gate::DrainError;
use crate::live::journal::{CaptureBinding, Eligibility, Phase, WorkerPreparation};
use crate::live::staging::{parse_layout, CaptureStaging, DiskCopyError, Hasher, RecordCommit};
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
}

impl CaptureContext {
    /// `producer` is the monitor's compiled build identity digest; the
    /// compatibility profile binds backend, lane and build target; the
    /// topology is the configuration and attachment inventory digest.
    pub(crate) fn new(
        data_dir: PathBuf,
        spec: &vm_spec::VmSpec,
        launch: &crate::virt::StorageLaunch,
        producer: [u8; 32],
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
        for field in [backend.as_str(), lane.as_str(), env!("SILO_BUILD_TARGET")] {
            profile.update((field.len() as u64).to_be_bytes());
            profile.update(field.as_bytes());
        }
        Ok(Self {
            data_dir,
            digests: CaptureDigests {
                silo_producer: Digest32(producer),
                profile: Digest32(profile.finalize().into()),
                topology: Digest32(*configuration_digest.as_bytes()),
            },
            configuration,
            configuration_digest,
            launch: launch_lease,
            lease: launch.lease.clone(),
        })
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
    inventory: Vec<CaptureInventoryEntry>,
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
        let token = self.cut.clone();
        Some(CaptureEvidence {
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
    // ------------------------------------------------------------ preflight

    /// Asynchronous admission preflight, before any effect: native provider
    /// inventory and the held writable sources' identity, type and length.
    /// libvm's pre-freeze reservation is checked by the plan floor and then
    /// against actual staged allocation at verification ([`staging_budget`]),
    /// never against a second allocation sample of the still running guest.
    pub(crate) async fn check_capture(&self, plan: &CapturePlan) -> Result<Eligibility, LiveError> {
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
            inventory: Vec::new(),
        };
        match self.capture_stages(&mut run).await {
            Ok(evidence) => self.seal(run, evidence).await,
            Err(abort) => self.unwind(run, abort).await,
        }
    }

    async fn capture_stages(&self, run: &mut Run) -> Result<CaptureEvidence, Abort> {
        self.stage_prepare(run).await?;
        self.stage_pause(run).await?;
        self.stage_flush(run).await?;
        self.stage_disks(run).await?;
        self.stage_execution_and_memory(run).await?;
        let staged = self.stage_verify(run).await?;
        staging_budget(run.plan.reservation.staging_bytes, staged).map_err(Abort::Failed)?;
        run.evidence(CaptureRecordOutcome::Coherent, None)
            .ok_or_else(|| {
                Abort::Failed(failure(
                    LiveFailureCode::CaptureVerificationFailed,
                    LiveStage::CaptureVerify,
                    "capture has no durable request record",
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
        self.publish_stage(
            &run.operation,
            &run.operation,
            LiveCommandKind::Capture,
            stage,
            false,
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
            move || -> io::Result<_> {
                let staging = CaptureStaging::create(&context.data_dir, &capture)?;
                let request = staging.write_request(&bytes)?;
                let files = CaptureOutputFiles {
                    execution: staging.create_output(&CaptureRole::Execution)?,
                    devices: staging.create_output(&CaptureRole::Devices)?,
                    ram: staging.create_output(&CaptureRole::Ram)?,
                    layout: staging.create_output(&CaptureRole::Layout)?,
                    pin: File::from(context.lease.try_clone()?),
                };
                Ok((staging, request, files))
            }
        })
        .await
        .map_err(|error| staging_failed(format!("staging task failed: {error}")))?;
        let (staging, request, files) =
            created.map_err(|error| staging_failed(format!("create capture staging: {error}")))?;
        tracing::info!(operation = %run.operation, path = %staging.path().display(), "capture staging and request.json are durable");
        run.staging = Some(Arc::new(staging));
        run.request_digest = Some(request);

        let identities = (|| -> io::Result<_> {
            Ok((
                CaptureOutputIdentities {
                    execution: OutputIdentity::of(&files.execution)?,
                    devices: OutputIdentity::of(&files.devices)?,
                    ram: OutputIdentity::of(&files.ram)?,
                    layout: OutputIdentity::of(&files.layout)?,
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
                resume_policy: match run.plan.resume_policy {
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
            }) => Err(fail(native.to_string())),
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
        let copied = tokio::task::spawn_blocking({
            let abort = abort.clone();
            move || -> Result<(), DiskCopyError> {
                for (role, source, length, copy) in &work {
                    let method = staging.copy_disk(role, source, *length, *copy, &abort)?;
                    tracing::info!(role = %role.relative_path(), ?method, length, "sealed writable disk role");
                }
                Ok(())
            }
        })
        .await;
        watcher.abort();
        match copied {
            Ok(Ok(())) => self.checkpoint(run, LiveStage::CaptureDisks),
            Ok(Err(DiskCopyError::Cancelled)) => {
                self.checkpoint(run, LiveStage::CaptureDisks)?;
                Err(fail("disk copy was interrupted".into()))
            }
            Ok(Err(error)) => Err(fail(error.to_string())),
            Err(error) => Err(fail(format!("disk copy task failed: {error}"))),
        }
    }

    fn binding_matches(&self, run: &Run, binding: &NativeBinding) -> bool {
        let Some(context) = self.capture.as_ref() else {
            return false;
        };
        binding.capture == wire_uuid(&run.operation)
            && binding.source_run == self.run_uuid
            && Some(binding.pause_generation) == run.cut_generation()
            && binding.silo_producer == context.digests.silo_producer
            && binding.profile == context.digests.profile
            && binding.topology == context.digests.topology
            && !binding.native_producer.is_empty()
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
            }) => return Err(fail_execution(native.to_string())),
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
            .await;
        let writers_closed = match result {
            Ok(CommandOutcome::MemoryCaptured {
                binding: memory,
                ram,
                layout,
                writers_closed,
                ..
            }) => {
                if ram.identity() != outputs.ram || layout.identity() != outputs.layout {
                    return Err(fail_memory("RAM receipts name other outputs".into()));
                }
                if memory != binding {
                    return Err(fail_memory(
                        "RAM binding differs from the execution binding".into(),
                    ));
                }
                writers_closed
            }
            Ok(CommandOutcome::CaptureFailed {
                failure: native, ..
            }) => return Err(fail_memory(native.to_string())),
            Ok(outcome) => {
                return Err(fail_memory(format!(
                    "unexpected native RAM outcome {outcome:?}"
                )))
            }
            Err(error) => {
                return Err(Abort::native(
                    error,
                    LiveFailureCode::MemoryCaptureFailed,
                    LiveStage::CaptureMemory,
                ))
            }
        };
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
        let roles = run.plan.roles();
        let disks = run.plan.disks.clone();
        let ram_limit = run.plan.ram_bytes;
        let (abort, watcher) = abort_token(&run.cancel, &self.stop);
        let verified = tokio::task::spawn_blocking({
            let abort = abort.clone();
            move || verify_staging(&staging, &roles, &disks, outputs, ram_limit, &abort)
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
        let Some(binding) = run.binding.clone() else {
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
        run.memory = Some(CaptureMemoryEvidence {
            packed_length: verified.packed_length,
            page_granule: verified.page_granule,
            regions: verified.regions,
            ram_stream: verified.ram_stream,
            binding: CaptureStateBinding {
                native_producer: binding.native_producer.clone(),
                silo_producer: digest(binding.silo_producer),
                profile: digest(binding.profile),
                topology: digest(binding.topology),
                ram_layout: digest(binding.ram_layout),
                source_run,
                pause_generation,
                capture: run.plan.capture_id.clone(),
            },
        });
        run.inventory = verified.inventory;
        // Every role was copied, closed, re-identified, hashed and synced.
        run.facts.disk_copies_sealed = true;
        self.checkpoint(run, LiveStage::CaptureVerify)?;
        Ok(verified.staged_bytes)
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

    async fn seal(&self, mut run: Run, evidence: CaptureEvidence) {
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
        let checked = match (&run.request_digest, &run.staging) {
            (Some(request), Some(staging)) => evidence
                .validate_against_plan(&run.plan, request)
                .and_then(|()| {
                    if evidence.is_sealed() {
                        Ok(())
                    } else {
                        Err("coherent evidence is incomplete".into())
                    }
                })
                .and_then(|()| evidence.canonical_bytes())
                .map(|bytes| (staging.clone(), bytes)),
            _ => Err("capture staging is not prepared".into()),
        };
        let (staging, bytes) = match checked {
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
        let evidence_sha256 = Sha256Digest::of_bytes(&bytes);
        // The commit is bounded blocking work that is never abandoned midway.
        // It reports Durable only once the record is the single link of the
        // linked inode, the temporary name is gone and the directory synced.
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
            Ok(Ok(RecordCommit::Durable)) => {}
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                return self.seal_uncertain(run, error.to_string());
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
                return self.seal_uncertain(run, format!("seal task failed: {error}"));
            }
        }
        let Some(cut) = run.cut.clone() else {
            return self.seal_uncertain(run, "sealed without a cut token".into());
        };
        {
            let mut inner = self.lock();
            let sealed = LiveOperationRecord {
                operation_id: run.operation.clone(),
                kind: OperationKind::Capture,
                outcome: OperationOutcome::CaptureSealed {
                    capture: CaptureSealed {
                        capture_id: run.plan.capture_id.clone(),
                        evidence_sha256,
                        cut_token: cut,
                    },
                },
            };
            if let Some(record) = inner.journal.operation_mut(&run.operation) {
                record.record = sealed.clone();
                record.phase = Phase::Continuing;
            }
            if let Some(facts) = inner.journal.capture_mut(&run.operation) {
                facts.evidence = Some(CaptureEvidenceReference {
                    outcome: CaptureRecordOutcome::Coherent,
                    sha256: evidence_sha256,
                });
            }
            // Cancels that joined before the seal see the unchanged success.
            for request in inner.journal.take_cancel_requests(&run.operation) {
                let result =
                    LiveCommandResult::CancelOperation(CancelOperationOutcome::Completed {
                        completed: CancelCompleted {
                            effective: false,
                            operation: sealed.clone(),
                            state: VmLifecycleState::Capturing,
                        },
                    });
                inner.journal.complete(&request, result);
            }
        }
        tracing::info!(operation = %run.operation, evidence = %evidence_sha256, "capture sealed");
        self.continue_sealed(&mut run, &staging).await;
    }

    /// A refusal before the link: the pipeline owns the operation again.
    fn reopen_pipeline(&self, run: &Run) {
        if let Some(record) = self.lock().journal.operation_mut(&run.operation) {
            record.phase = Phase::Pipeline;
        }
    }

    /// The record is visible but its durability is unknown: never claim
    /// success, never overwrite or remove it, never continue the source.
    /// Stay fenced in Error until stop; libvm reconciles the files.
    fn seal_uncertain(&self, run: Run, detail: String) {
        let cause = failure(
            LiveFailureCode::SealUncertain,
            LiveStage::CaptureSeal,
            detail,
        );
        tracing::error!(operation = %run.operation, cause = %cause, "capture seal durability is uncertain");
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
        let (Some(outputs), Some(memory)) = (run.outputs, run.memory.as_ref()) else {
            return Err(fail("sealed capture has no RAM identity".into()));
        };
        let (ram, layout) = tokio::task::spawn_blocking({
            let staging = staging.clone();
            move || -> io::Result<(File, File)> {
                let (ram, _) = staging.open_sealed(&CaptureRole::Ram)?;
                let (layout, _) = staging.open_sealed(&CaptureRole::Layout)?;
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
            stream: Digest32(*memory.ram_stream.as_bytes()),
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
        match (run.pause, run.plan.resume_policy) {
            (PauseState::Acquired(epoch, generation), CaptureResumePolicy::ResumeIfAcquired) => {
                let finish = self.continue_resume(run, epoch, generation).await;
                self.finish_or_stop(run, finish).await
            }
            (PauseState::Acquired(epoch, _), CaptureResumePolicy::Preserve) => {
                let finish = self.continue_preserve(run, epoch).await;
                self.finish_or_stop(run, finish).await
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
                self.finish(run, finish).await
            }
            // No established pause: roll back, never a token transfer.
            (PauseState::Frozen(epoch) | PauseState::NativePending(epoch), _) => {
                let finish = self.rollback_capture_pause(run, epoch).await;
                self.finish_or_stop(run, finish).await
            }
            (PauseState::Untouched, _) => {
                self.finish(run, Finish::Running(CaptureContinuation::Unchanged))
                    .await
            }
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

    // ---------------------------------------------------------------- unwind

    /// The capture did not seal. Resolve the native candidate (an uncertain
    /// preparation first by exact observation), write the failed diagnostic
    /// record, then continue the source under its policy.
    async fn unwind(&self, mut run: Run, abort: Abort) {
        let cause = match abort {
            Abort::Stopped => {
                // Stop never resumes or thaws; worker and outputs stay owned
                // until the sole reaper terminates them.
                let stopped = failure(
                    LiveFailureCode::Stopped,
                    LiveStage::Admission,
                    "monitor is stopping",
                );
                self.write_failed_record(&run, &stopped).await;
                return self.capture_stopped(&mut run);
            }
            Abort::Failed(cause) => cause,
        };
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
            Ok(Ok(RecordCommit::Durable)) => {
                if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                    facts.evidence = Some(CaptureEvidenceReference {
                        outcome: CaptureRecordOutcome::Failed,
                        sha256,
                    });
                }
            }
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                tracing::warn!(%error, operation = %run.operation, "failed capture record durability uncertain")
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
        let continuation = match &finish {
            Finish::Running(continuation) | Finish::Paused(_, continuation) => continuation.clone(),
            Finish::Error(cause) => CaptureContinuation::ResumeFailed {
                failure: cause.clone(),
                state: VmLifecycleState::Error,
            },
        };
        self.write_source_record(run, &continuation).await;
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
                        if record.record.outcome == OperationOutcome::InProgress {
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
            self.capture_terminal(&mut inner, run, None, state);
            state
        };
        tracing::info!(operation = %run.operation, %state, "capture continuation finished");
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
        let sha256 = Sha256Digest::of_bytes(&bytes);
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
            Ok(Ok(RecordCommit::Durable)) => {
                if let Some(facts) = self.lock().journal.capture_mut(&run.operation) {
                    facts.source_record = Some(sha256);
                }
            }
            Ok(Ok(RecordCommit::Uncertain(error))) => {
                tracing::warn!(%error, operation = %run.operation, "capture source record durability uncertain")
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

/// Reopen every staged role read-only, check identity, ownership, mode,
/// single link and length, parse the RAM layout, hash every byte (RAM also
/// to its stream identity), then synchronize files and directories.
///
/// Also measures the staged bytes charged against libvm's reservation, once
/// every role and directory is synced: the allocated bytes of the capture and
/// `disks/` directories, `request.json`, RAM, layout and state, plus each
/// `Copy`-planned disk's allocated bytes (conservatively all of a clone's
/// shared extents, since its host has no qualified clone contract). A
/// `Clone`-planned disk is charged the contract's metadata bytes: it must be
/// a clone (see [`CaptureDiskCopy`]) and was reserved at exactly that.
fn verify_staging(
    staging: &CaptureStaging,
    roles: &[CaptureRole],
    disks: &[CaptureDiskPlan],
    outputs: CaptureOutputIdentities,
    ram_limit: u64,
    abort: &CancellationToken,
) -> io::Result<Verified> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    let mut hasher = Hasher::new();
    let mut inventory = Vec::with_capacity(roles.len());
    let mut state_bytes = 0u64;
    let mut staged_bytes = staging.request_allocation()?;
    let mut geometry = None;
    let mut ram = None;
    for role in roles {
        let (file, facts) = staging.open_sealed(role)?;
        let prepared = match role {
            CaptureRole::Execution => Some(outputs.execution),
            CaptureRole::Devices => Some(outputs.devices),
            CaptureRole::Ram => Some(outputs.ram),
            CaptureRole::Layout => Some(outputs.layout),
            CaptureRole::Disk(_) => None,
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
        if matches!(
            role,
            CaptureRole::Execution | CaptureRole::Devices | CaptureRole::Layout
        ) {
            if facts.length == 0 {
                return Err(invalid(format!("{} is empty", role.relative_path())));
            }
            state_bytes = state_bytes.saturating_add(facts.length);
        }
        if *role == CaptureRole::Layout {
            if facts.length > MAX_LAYOUT_BYTES {
                return Err(invalid(format!("{CAPTURE_LAYOUT_FILE} exceeds its bound")));
            }
            let length = usize::try_from(facts.length)
                .map_err(|_| invalid("layout length overflows".into()))?;
            let mut bytes = vec![0u8; length];
            std::os::unix::fs::FileExt::read_exact_at(&file, &mut bytes, 0)?;
            geometry = Some(parse_layout(&bytes)?);
        }
        let hashed = hasher.hash(&file, facts.length, *role == CaptureRole::Ram, abort)?;
        if *role == CaptureRole::Ram {
            ram = hashed.stream.map(|stream| (hashed.length, stream));
        }
        // fsync of the exact inode; native and copy writers are closed.
        file.sync_all()?;
        let charge = match disk.map(|disk| disk.copy) {
            Some(CaptureDiskCopy::Clone) => CAPTURE_CLONE_RESERVE_BYTES,
            Some(CaptureDiskCopy::Copy) | None => {
                std::os::unix::fs::MetadataExt::blocks(&file.metadata()?).saturating_mul(512)
            }
        };
        staged_bytes = staged_bytes.saturating_add(charge);
        inventory.push(CaptureInventoryEntry {
            role: role.clone(),
            length: hashed.length,
            sha256: hashed.sha256,
        });
    }
    staging.sync_directories()?;
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
                "sealed staging needs {total} bytes ({staged} staged, {records} bounded \
                 control records), the reservation holds {reserved}"
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

    use tokio_util::sync::CancellationToken;
    use vm_spec::capture::{
        CaptureDiskCopy, CaptureDiskName, CaptureDiskPlan, CaptureRole,
        CAPTURE_CLONE_RESERVE_BYTES, CAPTURE_REQUEST_FILE, CAPTURE_STATE_RESERVE_BYTES,
        MAX_CAPTURE_RECORD_BYTES,
    };
    use vm_spec::lifecycle::{LiveFailureCode, LiveId, LiveStage};

    use crate::live::coordinator::capture::{staging_budget, verify_staging};
    use crate::live::staging::CaptureStaging;
    use crate::virt::lifecycle::{CaptureOutputIdentities, OutputIdentity};

    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const LAYOUT: &[u8] = br#"{"architecture":"x86_64","kind":"ram-layout","packedLength":8192,"pageGranule":4096,"regions":[{"guestPhysicalAddress":0,"length":8192,"streamOffset":0}],"schema":1,"topology":{"ramBelowGap":8192}}"#;

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
        staging
            .copy_disk(
                &disk,
                &file,
                length,
                CaptureDiskCopy::Copy,
                &CancellationToken::new(),
            )
            .unwrap();
        let roles = vec![
            CaptureRole::Execution,
            CaptureRole::Devices,
            CaptureRole::Ram,
            CaptureRole::Layout,
            disk,
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
            name: CaptureDiskName::new("data").unwrap(),
            attachment_index: 0,
            block_id: vm_spec::BlockId::new("data").unwrap(),
            length,
            copy,
        }]
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
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(verified.inventory.len(), 5);
        assert_eq!(verified.packed_length, 8192);
        assert_eq!(verified.regions, 1);
        let ram = &verified.inventory[2];
        assert_eq!(ram.role, CaptureRole::Ram);
        assert_eq!(ram.length, 8192);
        assert_eq!(
            ram.sha256,
            vm_spec::capture::Sha256Digest::of_bytes(&[7u8; 8192])
        );

        // RAM beyond the planned memory is refused.
        assert!(verify_staging(
            &staging,
            &roles,
            &disks,
            outputs,
            4096,
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
                &CancellationToken::new(),
            )
            .unwrap()
        };
        // Copy-planned: the sealed role's actual allocation, never its length.
        let copied = verify(CaptureDiskCopy::Copy);
        let directory = staged.staging.path();
        let state: u64 = [
            directory.to_path_buf(),
            directory.join("disks"),
            directory.join(CAPTURE_REQUEST_FILE),
        ]
        .into_iter()
        .chain(
            staged.roles[..4]
                .iter()
                .map(|role| directory.join(role.relative_path())),
        )
        .map(|path| allocated(&path))
        .sum();
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
            &CancellationToken::new(),
        )
        .unwrap();
        let exact = verified.staged_bytes + RECORDS;
        assert_eq!(staging_budget(exact, verified.staged_bytes).unwrap(), exact);
        let refused = staging_budget(exact - 1, verified.staged_bytes).unwrap_err();
        assert_eq!(refused.code, LiveFailureCode::StagingBudgetExceeded);
        assert_eq!(refused.stage, LiveStage::CaptureVerify);
        let message = refused.message.unwrap().to_string();
        assert!(message.contains(&exact.to_string()), "{message}");
        assert!(message.contains(&(exact - 1).to_string()), "{message}");
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
}

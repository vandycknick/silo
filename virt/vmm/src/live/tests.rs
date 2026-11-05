//! Hypervisor-free coordinator tests: the real coordinator, gate, store and
//! guest status supervision against the ADR 0018 scenario backend, whose
//! guest follows the real agent's freeze/thaw coordinator and whose native
//! side runs the real worker client/state machine over a socketpair.
use std::num::NonZeroU64;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use protocol::v1::VmState;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vm_spec::lifecycle::{
    CancelOperationCommand, CancelOperationOutcome, CaptureCommand, CapturePolicy,
    CaptureResumePolicy, GetOperationCommand, GetOperationOutcome, LiveCommand,
    LiveCommandEnvelope, LiveCommandResult, LiveFailureCode, LiveId, LiveOperationRecord,
    LiveRejectionReason, LiveStage, OperationObservation, OperationOutcome, OperationStatus,
    PauseCommand, PauseOutcome, PauseOwner, PauseToken, ResumeCommand, ResumeOutcome,
    VmLifecycleState,
};
use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveCapability, LiveCapabilityVector, LiveDeviceSubject,
    LiveLane, LiveReasonCode,
};

use crate::live::coordinator::{LiveCoordinator, LiveTimeouts, StopMode};
use crate::live::gate::{GateKind, GateRefusal, LiveGate};
use crate::state::{InstanceStore, RunLiveProfile};
use crate::virt::{BackendKind, VirtualMachine, VmConfig};

struct Harness {
    root: PathBuf,
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    live: Arc<LiveCoordinator>,
    gate: Arc<LiveGate>,
    machine_id: LiveId,
    run_id: LiveId,
    shutdown: CancellationToken,
    guest: tokio::task::JoinHandle<()>,
}

fn live_id(value: Uuid) -> LiveId {
    LiveId::parse(&value.hyphenated().to_string()).unwrap()
}

fn timeouts() -> LiveTimeouts {
    LiveTimeouts {
        drain: Duration::from_millis(300),
        guest_stage: Duration::from_secs(5),
        native: Duration::from_secs(5),
        handshake: Duration::from_secs(20),
        readiness: Duration::from_secs(20),
    }
}

fn baseline() -> LiveCapabilityVector {
    let mut live = LiveCapabilityVector::all_unsupported(LiveReasonCode::NotDelivered);
    live.pause = LiveCapability {
        native: true,
        availability: LiveAvailability::Supported,
    };
    // A scenario may advertise capture; the monitor still never delivers it.
    live.capture = LiveCapability {
        native: true,
        availability: LiveAvailability::Supported,
    };
    live
}

impl Harness {
    async fn start(lifecycle: Option<serde_json::Value>) -> Self {
        Self::start_with(lifecycle, timeouts(), true).await
    }

    async fn start_with(
        lifecycle: Option<serde_json::Value>,
        timeouts: LiveTimeouts,
        wait_ready: bool,
    ) -> Self {
        let root = Path::new("/tmp").join(format!(
            "lv-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let machine_uuid = Uuid::new_v4();
        let run_uuid = Uuid::new_v4();
        let scenario = match lifecycle {
            Some(lifecycle) => serde_json::json!({ "lifecycle": lifecycle }),
            None => serde_json::json!({}),
        };
        let mut config = VmConfig::builder("live-test")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .build()
            .with_storage_launch(
                crate::virt::test_storage_launch(&root, machine_uuid, run_uuid).unwrap(),
            );
        config.set_resolved_mock_scenario(Arc::new(
            test_utils::Scenario::from_json(&scenario.to_string()).unwrap(),
        ));
        let machine = VirtualMachine::with_backend(BackendKind::Mock, config).unwrap();
        machine.start().await.unwrap();
        let store = Arc::new(
            InstanceStore::new(
                machine_uuid.hyphenated().to_string(),
                "live-test".into(),
                true,
                RunLiveProfile {
                    run_id: run_uuid.hyphenated().to_string(),
                    backend: LiveBackend::Mock,
                    lane: LiveLane::NotApplicable,
                    live: baseline(),
                },
            )
            .unwrap(),
        );
        store.set_vm_state(VmState::Running, "running").unwrap();
        let gate = LiveGate::new();
        let forwards = crate::forward::ForwardTable::prepare_machine(
            &[],
            &root,
            None,
            crate::forward::inbound::PARK_TIMEOUT,
            gate.clone(),
        )
        .await
        .unwrap();
        let shutdown = CancellationToken::new();
        let guest = crate::guest::spawn_guest_services(
            &machine,
            &root,
            store.clone(),
            forwards,
            shutdown.clone(),
        )
        .await
        .unwrap();
        let live = LiveCoordinator::new(
            machine_uuid,
            run_uuid,
            store.clone(),
            machine.clone(),
            gate.clone(),
            timeouts,
        )
        .unwrap();
        let harness = Self {
            root,
            machine,
            store,
            live,
            gate,
            machine_id: live_id(machine_uuid),
            run_id: live_id(run_uuid),
            shutdown,
            guest,
        };
        if wait_ready {
            harness
                .until("guest ready for live admission", |snapshot| {
                    snapshot.ready_identity.is_some() && snapshot.guest_rejection.is_none()
                })
                .await;
        }
        harness
    }

    async fn until(
        &self,
        what: &str,
        predicate: impl Fn(&crate::state::LiveSnapshot) -> bool,
    ) -> crate::state::LiveSnapshot {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut changes = self.store.subscribe();
        loop {
            let snapshot = self.store.live_snapshot().unwrap();
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::select! {
                _ = changes.changed() => {}
                () = tokio::time::sleep(Duration::from_millis(50)) => {}
                () = tokio::time::sleep_until(deadline) => panic!("timed out waiting for {what}: {snapshot:?}"),
            }
        }
    }

    fn envelope(&self, request: &LiveId) -> LiveCommandEnvelope {
        LiveCommandEnvelope {
            machine_id: self.machine_id.clone(),
            run_id: self.run_id.clone(),
            request_id: request.clone(),
        }
    }

    async fn run(&self, command: LiveCommand) -> LiveCommandResult {
        let result = self.live.handle(command).await.unwrap();
        result.validate().unwrap();
        result
    }

    fn pause_command(&self, request: &LiveId) -> LiveCommand {
        LiveCommand::Pause(PauseCommand {
            envelope: self.envelope(request),
        })
    }

    async fn pause(&self) -> LiveId {
        let request = live_id(Uuid::new_v4());
        let result = self.run(self.pause_command(&request)).await;
        let LiveCommandResult::Pause(PauseOutcome::Accepted { receipt }) = result else {
            panic!("pause must be accepted: {result:?}");
        };
        assert_eq!(receipt.operation_id, request);
        assert_eq!(receipt.state, VmLifecycleState::Pausing);
        request
    }

    async fn observe(&self, operation: &LiveId) -> OperationObservation {
        let result = self
            .run(LiveCommand::GetOperation(GetOperationCommand {
                envelope: self.envelope(&live_id(Uuid::new_v4())),
                operation_id: operation.clone(),
            }))
            .await;
        let LiveCommandResult::GetOperation(GetOperationOutcome::Observation { observation }) =
            result
        else {
            panic!("observation expected: {result:?}");
        };
        observation
    }

    /// Poll with fresh request IDs until the operation and machine settle.
    async fn settled(&self, operation: &LiveId) -> OperationObservation {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let observation = self.observe(operation).await;
            let busy = observation.state == VmLifecycleState::Pausing
                && observation
                    .activity
                    .as_ref()
                    .is_some_and(|activity| activity.stage != LiveStage::PauseFailed);
            if observation.operation.status() != OperationStatus::InProgress && !busy {
                return observation;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "operation did not settle: {observation:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn resume(&self, operation: &LiveId, token: PauseToken) -> ResumeOutcome {
        let result = self
            .run(LiveCommand::Resume(ResumeCommand {
                envelope: self.envelope(&live_id(Uuid::new_v4())),
                operation_id: operation.clone(),
                token,
            }))
            .await;
        let LiveCommandResult::Resume(outcome) = result else {
            panic!("resume outcome expected");
        };
        outcome
    }

    async fn cancel(&self, operation: &LiveId) -> CancelOperationOutcome {
        let result = self
            .run(LiveCommand::CancelOperation(CancelOperationCommand {
                envelope: self.envelope(&live_id(Uuid::new_v4())),
                operation_id: operation.clone(),
            }))
            .await;
        let LiveCommandResult::CancelOperation(outcome) = result else {
            panic!("cancel outcome expected");
        };
        outcome
    }

    fn status(&self) -> (VmLifecycleState, vm_spec::lifecycle::LiveLifecycle, bool) {
        let status = self.store.status().unwrap();
        let (state, lifecycle) = protocol::lifecycle::status_lifecycle(&status).unwrap();
        (state, lifecycle, status.readiness.unwrap().ready.unwrap())
    }

    async fn stop(self) {
        self.live.begin_stop();
        self.shutdown.cancel();
        self.machine.stop().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.guest).await;
        let _ = std::fs::remove_dir_all(self.root);
    }
}

fn paused_token(observation: &OperationObservation) -> PauseToken {
    match &observation.operation.outcome {
        OperationOutcome::Succeeded { pause } => pause.token.clone(),
        outcome => panic!("pause did not succeed: {outcome:?}"),
    }
}

fn failure_code(record: &LiveOperationRecord) -> LiveFailureCode {
    match &record.outcome {
        OperationOutcome::Failed { failure } => failure.code,
        outcome => panic!("operation did not fail: {outcome:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_pause_and_clock_only_resume_roundtrip_through_barriers() {
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let held = harness
        .store
        .live_snapshot()
        .unwrap()
        .ready_identity
        .unwrap();
    let mut sessions = harness.store.subscribe_ready_agent_identity();
    let operation = harness.pause().await;
    let paused = harness.settled(&operation).await;
    assert_eq!(paused.state, VmLifecycleState::Paused);
    let token = paused_token(&paused);
    assert_eq!(token.owner, PauseOwner::User);
    assert_eq!(token.machine_id, harness.machine_id);
    assert_eq!(token.run_id, harness.run_id);
    let current = paused
        .current_pause
        .clone()
        .expect("current authority while paused");
    assert_eq!(current.token, token);
    assert_eq!(current.operation_id, operation);
    let OperationOutcome::Succeeded { pause } = &paused.operation.outcome else {
        unreachable!()
    };
    assert!(pause.capture_eligible);
    assert!(pause.guest.positively_frozen(pause.freeze_epoch));

    let (state, lifecycle, ready) = harness.status();
    assert_eq!(state, VmLifecycleState::Paused);
    assert_eq!(lifecycle.current_pause, Some(current.clone()));
    assert!(!ready, "readiness is false outside Running");
    // Existing sessions stay bound to the held identity; new ones are fenced.
    assert_eq!(sessions.borrow_and_update().clone(), Some(held.clone()));
    assert!(matches!(
        harness.gate.try_admit(GateKind::ExecSession),
        Err(GateRefusal::Fenced(GateKind::ExecSession))
    ));
    // A new Pause and a Cancel are matrix-rejected while paused.
    let again = harness
        .run(harness.pause_command(&live_id(Uuid::new_v4())))
        .await;
    assert_eq!(
        again.rejection().unwrap().reason,
        LiveRejectionReason::InvalidState
    );
    let CancelOperationOutcome::Rejected { rejection } = harness.cancel(&operation).await else {
        panic!("cancel in paused is rejected");
    };
    assert_eq!(rejection.reason, LiveRejectionReason::InvalidState);

    let ResumeOutcome::Resumed { resumed } = harness.resume(&operation, token.clone()).await else {
        panic!("resume must succeed");
    };
    assert_eq!(resumed.consumed_token, token);
    assert_eq!(resumed.thawed_epoch, current.freeze_epoch);
    let (state, lifecycle, ready) = harness.status();
    assert_eq!(state, VmLifecycleState::Running);
    assert_eq!(lifecycle, vm_spec::lifecycle::LiveLifecycle::default());
    assert!(ready, "readiness re-established before Running");
    assert!(harness.gate.is_open());
    let identity = harness
        .store
        .live_snapshot()
        .unwrap()
        .ready_identity
        .unwrap();
    assert_eq!(identity, held, "source resume never rotates guest identity");
    // The original terminal outcome is immutable after the resume.
    let after = harness.observe(&operation).await;
    assert_eq!(after.operation, paused.operation);
    assert!(after.current_pause.is_none());
    // The consumed token resumes nothing.
    let stale = harness.resume(&operation, token).await;
    assert!(
        matches!(stale, ResumeOutcome::Rejected { ref rejection } if rejection.reason == LiveRejectionReason::InvalidState)
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_lost_pause_response_is_recovered_by_replay_and_get_operation() {
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let request = live_id(Uuid::new_v4());
    let command = harness.pause_command(&request);
    let first = harness.run(command.clone()).await;
    let settled = harness.settled(&request).await;
    assert_eq!(settled.state, VmLifecycleState::Paused);
    // Replay in Paused returns the original receipt, not a state refusal.
    assert_eq!(harness.run(command).await, first);
    // Same request ID, different inputs: conflict.
    let conflict = harness
        .run(LiveCommand::GetOperation(GetOperationCommand {
            envelope: harness.envelope(&request),
            operation_id: request.clone(),
        }))
        .await;
    assert_eq!(
        conflict.rejection().unwrap().reason,
        LiveRejectionReason::RequestConflict
    );
    // GetOperation same-ID replay returns the captured observation.
    let get = LiveCommand::GetOperation(GetOperationCommand {
        envelope: harness.envelope(&live_id(Uuid::new_v4())),
        operation_id: request.clone(),
    });
    let observed = harness.run(get.clone()).await;
    let token = paused_token(&settled);
    let ResumeOutcome::Resumed { .. } = harness.resume(&request, token).await else {
        panic!("resume");
    };
    assert_eq!(harness.run(get).await, observed);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_freeze_failure_rolls_back_and_stays_running() {
    let harness = Harness::start(Some(serde_json::json!({
        "freeze": [{ "result": "freezeFailed" }]
    })))
    .await;
    let operation = harness.pause().await;
    let settled = harness.settled(&operation).await;
    assert_eq!(settled.state, VmLifecycleState::Running);
    assert_eq!(
        failure_code(&settled.operation),
        LiveFailureCode::FreezeFailed
    );
    assert!(settled.current_pause.is_none());
    let (state, lifecycle, ready) = harness.status();
    assert_eq!(state, VmLifecycleState::Running);
    assert!(lifecycle.error.is_none());
    assert!(ready);
    assert!(harness.gate.is_open());
    // A retry is a new Pause and succeeds.
    let retry = harness.pause().await;
    assert_eq!(
        harness.settled(&retry).await.state,
        VmLifecycleState::Paused
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_lost_freeze_response_is_joined_not_refrozen() {
    let harness = Harness::start(Some(serde_json::json!({
        "freeze": [{ "result": "dropResponse" }]
    })))
    .await;
    let operation = harness.pause().await;
    let settled = harness.settled(&operation).await;
    assert_eq!(settled.state, VmLifecycleState::Paused);
    let OperationOutcome::Succeeded { pause } = &settled.operation.outcome else {
        panic!("identical retry joins the frozen epoch");
    };
    assert_eq!(pause.freeze_epoch.get(), 1);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_native_failure_is_fenced_pausing_until_cancel() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativePause": [{ "result": "fail" }]
    })))
    .await;
    let operation = harness.pause().await;
    let failed = harness.settled(&operation).await;
    assert_eq!(failed.state, VmLifecycleState::Pausing);
    assert_eq!(failed.operation.status(), OperationStatus::Failed);
    assert_eq!(
        failure_code(&failed.operation),
        LiveFailureCode::NativePauseFailed
    );
    assert_eq!(
        failed.activity.as_ref().unwrap().stage,
        LiveStage::PauseFailed
    );
    assert!(
        failed.current_pause.is_none(),
        "a partial pause is never a token"
    );
    assert!(!harness.gate.is_open());
    // Only Cancel or stop leave a failed Pausing.
    let again = harness
        .run(harness.pause_command(&live_id(Uuid::new_v4())))
        .await;
    assert_eq!(
        again.rejection().unwrap().reason,
        LiveRejectionReason::InvalidState
    );

    let CancelOperationOutcome::Completed { completed } = harness.cancel(&operation).await else {
        panic!("cancel returns to running");
    };
    assert!(completed.effective);
    assert_eq!(completed.state, VmLifecycleState::Running);
    // The original failure stays the operation's terminal outcome.
    assert_eq!(
        failure_code(&completed.operation),
        LiveFailureCode::NativePauseFailed
    );
    let (state, _, ready) = harness.status();
    assert_eq!(state, VmLifecycleState::Running);
    assert!(ready);
    assert!(harness.gate.is_open());
    // Cancel of the finished operation is matrix-rejected in Running.
    assert!(matches!(
        harness.cancel(&operation).await,
        CancelOperationOutcome::Rejected { .. }
    ));
    let retry = harness.pause().await;
    assert_eq!(
        harness.settled(&retry).await.state,
        VmLifecycleState::Paused
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_failed_native_rollback_is_sticky_error() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativePause": [{ "result": "fail" }],
        "nativeCancel": [{ "result": "fail" }]
    })))
    .await;
    let operation = harness.pause().await;
    harness.settled(&operation).await;
    let CancelOperationOutcome::Failed { failed } = harness.cancel(&operation).await else {
        panic!("rollback failure is reported");
    };
    assert_eq!(failed.state, VmLifecycleState::Error);
    assert_eq!(failed.cause.code, LiveFailureCode::NativeRollbackFailed);
    let (state, lifecycle, ready) = harness.status();
    assert_eq!(state, VmLifecycleState::Error);
    assert!(lifecycle.error.is_some());
    assert!(!ready);
    assert!(!harness.gate.is_open(), "error stays fenced");
    let pause = harness
        .run(harness.pause_command(&live_id(Uuid::new_v4())))
        .await;
    assert_eq!(
        pause.rejection().unwrap().reason,
        LiveRejectionReason::InvalidState
    );
    assert_eq!(
        harness.observe(&operation).await.state,
        VmLifecycleState::Error
    );
    assert_eq!(harness.live.begin_stop(), StopMode::Terminate);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_cancel_racing_native_completion_never_strands_authority() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativePause": [{ "delayMs": 400, "result": "complete" }]
    })))
    .await;
    let operation = harness.pause().await;
    harness
        .until("native pause pending", |snapshot| {
            snapshot
                .lifecycle
                .activity
                .as_ref()
                .is_some_and(|activity| activity.stage == LiveStage::NativePause)
        })
        .await;
    let CancelOperationOutcome::Completed { completed } = harness.cancel(&operation).await else {
        panic!("cancel settles");
    };
    assert!(completed.effective);
    assert_eq!(completed.state, VmLifecycleState::Running);
    assert_eq!(
        failure_code(&completed.operation),
        LiveFailureCode::Cancelled
    );
    let (state, lifecycle, _) = harness.status();
    assert_eq!(state, VmLifecycleState::Running);
    assert!(lifecycle.current_pause.is_none());
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_lost_thaw_refreezes_next_epoch_and_publishes_new_authority() {
    // The thaw takes effect but its reply is lost for every identical retry
    // inside the stage budget (agent unreachable after the effect).
    let harness = Harness::start_with(
        Some(serde_json::json!({ "thaw": [{ "result": "dropResponse" }] })),
        LiveTimeouts {
            guest_stage: Duration::from_secs(2),
            ..timeouts()
        },
        true,
    )
    .await;
    let operation = harness.pause().await;
    let paused = harness.settled(&operation).await;
    let original = paused_token(&paused);
    let original_epoch = paused.current_pause.as_ref().unwrap().freeze_epoch;
    let ResumeOutcome::Failed { failed } = harness.resume(&operation, original.clone()).await
    else {
        panic!("lost thaw fails the resume");
    };
    assert_eq!(failed.cause.code, LiveFailureCode::ThawUnacknowledged);
    assert_eq!(failed.state, VmLifecycleState::Paused);
    assert_eq!(failed.requested_token, original);
    let recovered = failed.current_pause.clone().expect("new authority");
    assert!(recovered.token.generation > original.generation);
    assert_eq!(recovered.operation_id, operation);
    assert_eq!(recovered.freeze_epoch.get(), original_epoch.get() + 1);
    // Historical establishing result is immutable; current authority moved.
    let observed = harness.observe(&operation).await;
    assert_eq!(observed.operation, paused.operation);
    assert_eq!(observed.current_pause, Some(recovered.clone()));
    // The old token resumes nothing; the new one does.
    let stale = harness.resume(&operation, original).await;
    assert!(
        matches!(stale, ResumeOutcome::Rejected { ref rejection } if rejection.reason == LiveRejectionReason::StaleToken)
    );
    let ResumeOutcome::Resumed { resumed } =
        harness.resume(&operation, recovered.token.clone()).await
    else {
        panic!("resume with recovered authority");
    };
    assert_eq!(resumed.thawed_epoch, recovered.freeze_epoch);
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_failed_thaw_and_refused_recovery_freeze_is_error() {
    let harness = Harness::start(Some(serde_json::json!({
        "thaw": [{ "result": "faulted" }]
    })))
    .await;
    let operation = harness.pause().await;
    let token = paused_token(&harness.settled(&operation).await);
    let ResumeOutcome::Failed { failed } = harness.resume(&operation, token).await else {
        panic!("faulted thaw fails the resume");
    };
    assert_eq!(failed.state, VmLifecycleState::Error);
    assert!(
        failed.current_pause.is_none(),
        "never Paused from a failed recovery"
    );
    assert_eq!(
        failed.recovery_failure.as_ref().map(|failure| failure.code),
        Some(LiveFailureCode::RecoveryFreezeFailed)
    );
    assert_eq!(harness.status().0, VmLifecycleState::Error);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_resume_native_refusal_keeps_the_exact_pause() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativeResume": [{ "result": "prepareFail" }]
    })))
    .await;
    let operation = harness.pause().await;
    let paused = harness.settled(&operation).await;
    let token = paused_token(&paused);
    let parked = harness
        .store
        .parked_since()
        .expect("an established pause suspends agent staleness");
    let ResumeOutcome::Failed { failed } = harness.resume(&operation, token.clone()).await else {
        panic!("prepare failure fails the resume");
    };
    assert_eq!(failed.state, VmLifecycleState::Paused);
    assert_eq!(
        failed.current_pause.as_ref().map(|current| &current.token),
        Some(&token)
    );
    // Native retained the pause: the parked interval never ended.
    assert_eq!(harness.store.parked_since(), Some(parked));
    // Still resumable with the same token.
    assert!(matches!(
        harness.resume(&operation, token).await,
        ResumeOutcome::Resumed { .. }
    ));
    assert_eq!(harness.store.parked_since(), None);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_resume_keeps_native_parked_freshness_until_positive_release() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativeResume": [{ "delayMs": 1500, "result": "complete" }]
    })))
    .await;
    let operation = harness.pause().await;
    let token = paused_token(&harness.settled(&operation).await);
    let parked = harness
        .store
        .parked_since()
        .expect("an established pause suspends agent staleness");
    let live = harness.live.clone();
    let envelope = harness.envelope(&live_id(Uuid::new_v4()));
    let pending = tokio::spawn(async move {
        live.handle(LiveCommand::Resume(ResumeCommand {
            envelope,
            operation_id: operation,
            token,
        }))
        .await
        .unwrap()
    });
    harness
        .until("native resume in flight", |snapshot| {
            snapshot.state == VmLifecycleState::Pausing
                && snapshot
                    .lifecycle
                    .activity
                    .as_ref()
                    .is_some_and(|activity| activity.stage == LiveStage::ResumeNative)
        })
        .await;
    assert_eq!(
        harness.store.parked_since(),
        Some(parked),
        "native still holds the pause during ResumeNative: one uninterrupted interval"
    );
    let LiveCommandResult::Resume(outcome) = pending.await.unwrap() else {
        panic!("resume outcome expected");
    };
    assert!(
        matches!(outcome, ResumeOutcome::Resumed { .. }),
        "{outcome:?}"
    );
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    assert_eq!(
        harness.store.parked_since(),
        None,
        "a positive release ends the parked interval"
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_missing_clock_acknowledgement_is_error_not_running() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativeResume": [{ "result": "clockFail" }]
    })))
    .await;
    let operation = harness.pause().await;
    let token = paused_token(&harness.settled(&operation).await);
    let ResumeOutcome::Failed { failed } = harness.resume(&operation, token).await else {
        panic!("clock failure fails the resume");
    };
    assert_eq!(failed.cause.code, LiveFailureCode::ClockGenerationFailed);
    assert_eq!(failed.state, VmLifecycleState::Error);
    assert_eq!(harness.status().0, VmLifecycleState::Error);
    assert_eq!(
        harness.store.parked_since(),
        None,
        "a resume without retained native authority ends the parked interval"
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_stop_while_paused_terminates_without_resume_and_seals_admission() {
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let operation = harness.pause().await;
    harness.settled(&operation).await;
    assert_eq!(harness.live.begin_stop(), StopMode::Terminate);
    assert!(!harness.gate.reopen(), "stop seals fences permanently");
    harness
        .store
        .set_vm_state(VmState::Stopping, "stop")
        .unwrap();
    let (state, lifecycle, _) = harness.status();
    assert_eq!(state, VmLifecycleState::Stopping);
    assert_eq!(lifecycle, vm_spec::lifecycle::LiveLifecycle::default());
    let resume = harness
        .run(LiveCommand::Resume(ResumeCommand {
            envelope: harness.envelope(&live_id(Uuid::new_v4())),
            operation_id: operation.clone(),
            token: PauseToken {
                machine_id: harness.machine_id.clone(),
                run_id: harness.run_id.clone(),
                generation: NonZeroU64::new(1).unwrap(),
                owner: PauseOwner::User,
            },
        }))
        .await;
    assert_eq!(
        resume.rejection().unwrap().reason,
        LiveRejectionReason::MonitorStopping
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_stop_preempts_an_in_flight_resume_without_publishing() {
    let harness = Harness::start(Some(serde_json::json!({
        "nativeResume": [{ "delayMs": 1500, "result": "complete" }]
    })))
    .await;
    let operation = harness.pause().await;
    let token = paused_token(&harness.settled(&operation).await);
    let live = harness.live.clone();
    let envelope = harness.envelope(&live_id(Uuid::new_v4()));
    let pending = tokio::spawn(async move {
        live.handle(LiveCommand::Resume(ResumeCommand {
            envelope,
            operation_id: operation,
            token,
        }))
        .await
        .unwrap()
    });
    harness
        .until("resume in flight", |snapshot| {
            snapshot.state == VmLifecycleState::Pausing
        })
        .await;
    assert_eq!(harness.live.begin_stop(), StopMode::Terminate);
    harness
        .store
        .set_vm_state(VmState::Stopping, "stop")
        .unwrap();
    let LiveCommandResult::Resume(ResumeOutcome::Failed { failed }) = pending.await.unwrap() else {
        panic!("stop preempts the resume");
    };
    assert_eq!(failed.cause.code, LiveFailureCode::Stopped);
    assert_eq!(harness.status().0, VmLifecycleState::Stopping);
    assert!(!harness.gate.is_open());
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_admitted_work_must_drain_before_freeze() {
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let mutation = harness
        .gate
        .try_admit(GateKind::FilesystemMutation)
        .unwrap();
    let operation = harness.pause().await;
    let failed = harness.settled(&operation).await;
    assert_eq!(
        failure_code(&failed.operation),
        LiveFailureCode::DrainTimedOut
    );
    assert_eq!(failed.state, VmLifecycleState::Running);
    assert!(harness.gate.is_open(), "nothing was frozen; fences reopen");
    drop(mutation);
    // Admitted work that settles in time does not block the pause.
    let held = harness
        .gate
        .try_admit(GateKind::FilesystemMutation)
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(held);
    });
    let operation = harness.pause().await;
    assert_eq!(
        harness.settled(&operation).await.state,
        VmLifecycleState::Paused
    );
    release.await.unwrap();
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_guest_and_native_profile_reject_pause_before_effects() {
    let harness = Harness::start_with(
        Some(serde_json::json!({ "generationDriverReady": false })),
        timeouts(),
        false,
    )
    .await;
    let snapshot = harness
        .until("guest observed", |snapshot| {
            snapshot.ready_identity.is_some()
        })
        .await;
    assert_eq!(
        snapshot.guest_rejection,
        Some("guest-generation-driver-missing")
    );
    let status = harness.store.status().unwrap();
    let live = vm_spec::live::LiveMachineReport::try_from(status.live.unwrap()).unwrap();
    assert!(matches!(
        &live.live.pause.availability,
        LiveAvailability::Unsupported { reason }
            if reason.code == LiveReasonCode::DeviceProfileRejected
                && reason.subject == Some(LiveDeviceSubject::GuestProfile { profile: "guest-generation-driver-missing".into() })
    ));
    let rejected = harness
        .run(harness.pause_command(&live_id(Uuid::new_v4())))
        .await;
    assert!(matches!(
        rejected.rejection().unwrap().reason,
        LiveRejectionReason::Unsupported { .. }
    ));
    assert!(harness.gate.is_open());
    harness.stop().await;

    let harness = Harness::start(Some(serde_json::json!({
        "providers": [
            { "deviceId": 2, "configuredId": "root", "activationFenced": false, "blockBacking": "vmdk" }
        ]
    })))
    .await;
    let rejected = harness
        .run(harness.pause_command(&live_id(Uuid::new_v4())))
        .await;
    let LiveRejectionReason::Unsupported { unsupported } = &rejected.rejection().unwrap().reason
    else {
        panic!("vmdk-backed provider rejects pause");
    };
    assert_eq!(
        unsupported.reason.subject,
        Some(LiveDeviceSubject::GuestProfile {
            profile: "native-block-backing-unsupported".into()
        })
    );
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_is_not_delivered_even_when_advertised() {
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let result = harness
        .run(LiveCommand::Capture(CaptureCommand {
            envelope: harness.envelope(&live_id(Uuid::new_v4())),
            expected_configuration_digest: "sha256:abc".into(),
            policy: CapturePolicy::Full,
            resume_policy: CaptureResumePolicy::Preserve,
        }))
        .await;
    let LiveRejectionReason::Unsupported { unsupported } = &result.rejection().unwrap().reason
    else {
        panic!("capture is unsupported");
    };
    assert_eq!(unsupported.reason.code, LiveReasonCode::NotDelivered);
    assert!(
        !harness.root.join("captures").exists(),
        "no staging allocation"
    );
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    harness.stop().await;
}

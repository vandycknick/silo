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
    LiveRejectionCode, LiveRejectionReason, LiveStage, OperationObservation, OperationOutcome,
    OperationStatus, PauseCommand, PauseOutcome, PauseOwner, PauseToken, ResumeCommand,
    ResumeOutcome, VmLifecycleState,
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
    root_disk_bytes: u64,
    shutdown: CancellationToken,
    guest: Option<tokio::task::JoinHandle<()>>,
}

/// The harness's default writable raw root attachment.
const ROOT_DISK_BYTES: u64 = 1 << 20;

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
    // The scenario's vector delivers capture; production keeps it unqualified.
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
        Self::start_shaped(lifecycle, timeouts, wait_ready, None, ROOT_DISK_BYTES).await
    }

    /// `memory_mib` is the configured guest memory (the planned RAM), and
    /// `root_disk_bytes` the sparse root attachment's logical length.
    async fn start_shaped(
        lifecycle: Option<serde_json::Value>,
        timeouts: LiveTimeouts,
        wait_ready: bool,
        memory_mib: Option<u32>,
        root_disk_bytes: u64,
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
        // One writable raw root whose block ID matches the scenario's
        // standard native block provider, so captures seal a real disk role.
        let root_disk = root.join("root.raw");
        let disk_file = std::fs::File::create(&root_disk).unwrap();
        disk_file.set_len(root_disk_bytes).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&disk_file, b"root-disk-bytes", 4096).unwrap();
        drop(disk_file);
        let disk = vm_spec::Disk {
            path: root_disk,
            role: vm_spec::DiskRole::Root,
            format: vm_spec::DiskFormat::Raw,
            geometry: vm_spec::DiskGeometry {
                length: root_disk_bytes,
                logical_sector_size: 512,
            },
            block_id: vm_spec::BlockId::new("root").unwrap(),
            read_only: false,
        };
        let spec = vm_spec::VmSpec {
            hardware: memory_mib.map(|memory| vm_spec::Hardware {
                cpus: None,
                memory: Some(memory),
                nested_virtualization: None,
                rosetta: None,
            }),
            storage: Some(vm_spec::Storage {
                disks: vec![disk.clone()],
            }),
            ..vm_spec::VmSpec::current()
        };
        let launch = crate::virt::test_storage_launch(&root, machine_uuid, run_uuid).unwrap();
        let mut config = VmConfig::builder("live-test")
            .base_directory(&root)
            .kernel(Path::new("/mock-kernel"))
            .disk(disk)
            .build()
            .with_storage_launch(launch.clone());
        config.set_resolved_mock_scenario(Arc::new(
            test_utils::Scenario::from_json(&scenario.to_string()).unwrap(),
        ));
        let capture = crate::live::coordinator::capture::CaptureContext::new(
            root.clone(),
            &spec,
            &launch,
            crate::capabilities::capture_producer().unwrap(),
            LiveBackend::Mock,
            LiveLane::NotApplicable,
        )
        .unwrap();
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
            Some(capture),
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
            root_disk_bytes,
            shutdown,
            guest: Some(guest),
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

    async fn stop_guest_services(&mut self) {
        self.shutdown.cancel();
        if let Some(guest) = self.guest.take() {
            tokio::time::timeout(Duration::from_secs(5), guest)
                .await
                .unwrap()
                .unwrap();
        }
    }

    async fn stop(mut self) {
        self.live.begin_stop();
        self.shutdown.cancel();
        self.machine.stop().await.unwrap();
        if let Some(guest) = self.guest.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), guest).await;
        }
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
async fn live_resume_requests_post_thaw_status_without_unsolicited_heartbeats() {
    let mut deadlines = timeouts();
    deadlines.handshake = Duration::from_secs(1);
    let mut harness = Harness::start_with(Some(serde_json::json!({})), deadlines, true).await;
    let operation = harness.pause().await;
    let paused = harness.settled(&operation).await;
    let current = paused.current_pause.unwrap();
    let held = harness
        .store
        .live_snapshot()
        .unwrap()
        .observed_identity
        .unwrap();

    // Keep lifecycle RPCs serving, but stop every unsolicited status/metrics/SSH
    // supervisor. The pre-thaw handshake alone cannot satisfy the post-thaw
    // boundary. No test-injected receipt or periodic heartbeat can rescue it.
    harness.stop_guest_services().await;
    assert!(!harness.status().2);
    assert!(!harness.gate.is_open());
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        harness.resume(&operation, current.token.clone()),
    )
    .await
    .expect("resume must request fresh status after exact Thaw, without a heartbeat");
    let ResumeOutcome::Resumed { resumed } = outcome else {
        panic!("fresh post-thaw readiness completes resume: {outcome:?}");
    };
    assert_eq!(resumed.consumed_token, current.token);
    assert_eq!(resumed.thawed_epoch, current.freeze_epoch);
    let snapshot = harness.store.live_snapshot().unwrap();
    assert_eq!(snapshot.ready_identity, Some(held));
    assert_eq!(snapshot.state, VmLifecycleState::Running);
    assert!(harness.status().2);
    assert!(harness.gate.is_open());

    let channel = crate::guest::connect(&harness.machine).await.unwrap();
    let status = crate::guest::agent_client(channel)
        .get_status(protocol::v1::GetAgentStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    let lifecycle = status.report.as_ref().unwrap().lifecycle.as_ref().unwrap();
    assert_eq!(
        lifecycle.state,
        protocol::v1::GuestLifecycleState::Thawed as i32
    );
    assert_eq!(
        lifecycle.freeze_ref.as_ref().unwrap().freeze_epoch,
        Some(current.freeze_epoch.get())
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

    // A writable VMDK provider is refused before any effect.
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
        panic!("writable vmdk-backed provider rejects pause");
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
async fn live_read_only_vmdk_lower_is_admitted() {
    let harness = Harness::start(Some(serde_json::json!({
        "providers": [
            { "deviceId": 2, "configuredId": "silo-root-lower", "activationFenced": false, "blockBacking": "vmdk", "readOnly": true },
            { "deviceId": 2, "configuredId": "root", "activationFenced": false, "blockBacking": "raw" }
        ]
    })))
    .await;
    let operation = harness.pause().await;
    assert_eq!(
        harness.settled(&operation).await.state,
        VmLifecycleState::Paused,
        "the read-only flat lower is a native provider, not a refusal"
    );
    harness.stop().await;
}

// ------------------------------------------------------------------ capture

impl Harness {
    fn capture_plan(
        &self,
        request: &LiveId,
        pause: vm_spec::capture::CapturePauseAuthority,
        resume_policy: CaptureResumePolicy,
    ) -> vm_spec::capture::CapturePlan {
        use vm_spec::capture::*;
        let binding = self
            .live
            .capture_binding_for_tests()
            .expect("capture binding");
        CapturePlan {
            version: CAPTURE_RECORD_VERSION,
            machine_id: self.machine_id.clone(),
            run_id: self.run_id.clone(),
            capture_id: request.clone(),
            ram_bytes: binding.configuration.ram_bytes(),
            configuration_digest: binding.configuration_digest,
            configuration: binding.configuration,
            policy: CapturePolicy::Full,
            resume_policy,
            pause,
            disks: vec![CaptureDiskPlan {
                name: CaptureDiskName::new("root").unwrap(),
                attachment_index: 0,
                block_id: vm_spec::BlockId::new("root").unwrap(),
                length: self.root_disk_bytes,
                copy: CaptureDiskCopy::Copy,
            }],
            read_only_inputs: Vec::new(),
            reservation: CaptureReservation {
                storage_operation_id: live_id(Uuid::new_v4()),
                launch_lease: binding.launch,
                staging_bytes: 1 << 40,
            },
        }
    }

    async fn capture(&self, plan: vm_spec::capture::CapturePlan) -> LiveCommandResult {
        self.run(LiveCommand::Capture(Box::new(CaptureCommand {
            envelope: self.envelope(&plan.capture_id),
            plan,
        })))
        .await
    }

    /// Poll until the capture and its source continuation are terminal.
    async fn capture_settled(&self, operation: &LiveId) -> OperationObservation {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let observation = self.observe(operation).await;
            let done = observation
                .capture
                .as_ref()
                .is_some_and(|capture| capture.continuation.is_terminal())
                && observation.state != VmLifecycleState::Capturing;
            if done {
                return observation;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "capture did not settle: {observation:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn capture_dir(&self, operation: &LiveId) -> std::path::PathBuf {
        self.root.join("captures").join(operation.as_str())
    }
}

fn sealed(observation: &OperationObservation) -> vm_spec::capture::CaptureSealed {
    match &observation.operation.outcome {
        OperationOutcome::CaptureSealed { capture } => capture.clone(),
        outcome => panic!("capture did not seal: {outcome:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_seals_exact_evidence_then_resumes_the_source() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let request = live_id(Uuid::new_v4());
    let plan = harness.capture_plan(
        &request,
        CapturePauseAuthority::Acquire,
        CaptureResumePolicy::ResumeIfAcquired,
    );
    let accepted = harness.capture(plan.clone()).await;
    assert!(matches!(
        accepted,
        LiveCommandResult::Capture(vm_spec::lifecycle::CaptureOutcome::Accepted { ref receipt })
            if receipt.state == VmLifecycleState::Capturing
    ));
    let observation = harness.capture_settled(&request).await;
    assert_eq!(observation.state, VmLifecycleState::Running);
    let seal = sealed(&observation);
    let directory = harness.capture_dir(&request);

    // request.json is exactly the plan; the seal is its coherent evidence.
    let request_bytes = std::fs::read(directory.join(CAPTURE_REQUEST_FILE)).unwrap();
    assert_eq!(request_bytes, plan.canonical_bytes().unwrap());
    let evidence_bytes = std::fs::read(directory.join(CAPTURE_EVIDENCE_FILE)).unwrap();
    assert_eq!(
        Sha256Digest::of_bytes(&evidence_bytes),
        seal.evidence_sha256
    );
    let evidence = CaptureEvidence::decode(&evidence_bytes).unwrap();
    evidence
        .validate_against_plan(&plan, &Sha256Digest::of_bytes(&request_bytes))
        .unwrap();
    assert!(evidence.is_sealed());
    assert_eq!(
        evidence.freeze_operation_id.as_ref(),
        Some(&request),
        "an acquired cut freezes under the capture operation"
    );
    assert_eq!(evidence.pause_token.as_ref(), Some(&seal.cut_token));
    assert_eq!(
        seal.cut_token.owner,
        PauseOwner::Capture {
            operation_id: request.clone()
        }
    );
    // Every inventory digest is the actual staged byte content.
    for entry in &evidence.inventory {
        let bytes = std::fs::read(directory.join(entry.role.relative_path())).unwrap();
        assert_eq!(
            bytes.len() as u64,
            entry.length,
            "{}",
            entry.role.relative_path()
        );
        assert_eq!(Sha256Digest::of_bytes(&bytes), entry.sha256);
    }
    // The sealed disk is the paused source's bytes, in a private inode.
    let sealed_disk = std::fs::read(directory.join("disks/root.raw")).unwrap();
    assert_eq!(
        sealed_disk,
        std::fs::read(harness.root.join("root.raw")).unwrap()
    );
    for path in [directory.clone(), directory.join("disks")] {
        let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&path).unwrap());
        assert_eq!(mode & 0o7777, 0o700);
    }
    let mode = std::os::unix::fs::MetadataExt::mode(
        &std::fs::metadata(directory.join(CAPTURE_EVIDENCE_FILE)).unwrap(),
    );
    assert_eq!(mode & 0o7777, 0o600);

    // Continuation is a separate fact with its own durable record.
    let facts = observation.capture.clone().unwrap();
    assert!(matches!(
        facts.continuation,
        CaptureContinuation::Resumed { ref consumed_token, .. } if consumed_token == &seal.cut_token
    ));
    let source =
        CaptureSourceRecord::decode(&std::fs::read(directory.join(CAPTURE_SOURCE_FILE)).unwrap())
            .unwrap();
    source.validate_against(&evidence).unwrap();
    assert_eq!(source.source_outcome, CaptureSourceOutcome::Resumed);
    assert!(
        harness.gate.is_open(),
        "fences reopen after the source resumes"
    );

    // A later source write never reaches the sealed role.
    std::os::unix::fs::FileExt::write_all_at(
        &std::fs::OpenOptions::new()
            .write(true)
            .open(harness.root.join("root.raw"))
            .unwrap(),
        b"after-the-cut",
        4096,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(directory.join("disks/root.raw")).unwrap(),
        sealed_disk
    );

    // Release is idempotent and keeps the accepted baseline accounted.
    let release = |request: LiveId| {
        LiveCommand::ReleaseCapture(vm_spec::lifecycle::ReleaseCaptureCommand {
            envelope: harness.envelope(&request),
            operation_id: live_id_of(&observation),
            disposition: CaptureReleaseDisposition::Published,
        })
    };
    let first = harness.run(release(live_id(Uuid::new_v4()))).await;
    let LiveCommandResult::ReleaseCapture(vm_spec::lifecycle::ReleaseCaptureOutcome::Released {
        released,
    }) = first
    else {
        panic!("release succeeds: {first:?}");
    };
    let second = harness.run(release(live_id(Uuid::new_v4()))).await;
    assert!(matches!(
        second,
        LiveCommandResult::ReleaseCapture(vm_spec::lifecycle::ReleaseCaptureOutcome::Released { released: ref again })
            if again.baseline_retained == released.baseline_retained
    ));
    assert!(
        directory.join(CAPTURE_EVIDENCE_FILE).exists(),
        "release never removes staging"
    );
    harness.stop().await;
}

fn live_id_of(observation: &OperationObservation) -> LiveId {
    observation.operation.operation_id.clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_preserve_transfers_its_pause_to_user_authority() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let request = live_id(Uuid::new_v4());
    let plan = harness.capture_plan(
        &request,
        CapturePauseAuthority::Acquire,
        CaptureResumePolicy::Preserve,
    );
    harness.capture(plan).await;
    let observation = harness.capture_settled(&request).await;
    assert_eq!(observation.state, VmLifecycleState::Paused);
    let seal = sealed(&observation);
    let current = observation.current_pause.clone().expect("user authority");
    assert_eq!(current.token.owner, PauseOwner::User);
    assert_eq!(
        current.operation_id, request,
        "the acquiring capture owns it"
    );
    assert!(current.token.generation >= seal.cut_token.generation);
    assert!(matches!(
        observation.capture.as_ref().unwrap().continuation,
        CaptureContinuation::Preserved { ref preserved } if preserved == &current
    ));
    let source = CaptureSourceRecord::decode(
        &std::fs::read(harness.capture_dir(&request).join(CAPTURE_SOURCE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(source.source_outcome, CaptureSourceOutcome::Preserved);
    assert_eq!(source.current_pause.as_ref(), Some(&current.token));
    // The historical cut token is not resume authority; the user token is.
    let stale = harness.resume(&request, seal.cut_token.clone()).await;
    assert!(matches!(stale, ResumeOutcome::Rejected { .. }));
    let ResumeOutcome::Resumed { .. } = harness.resume(&request, current.token).await else {
        panic!("the preserved user pause resumes through its capture");
    };
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_borrowing_a_user_pause_never_resumes_it() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let pause = harness.pause().await;
    let paused = harness.settled(&pause).await;
    let token = paused_token(&paused);
    let request = live_id(Uuid::new_v4());
    // resume-if-acquired cannot borrow: refused as an invalid plan, no effect.
    let refused = harness
        .capture(harness.capture_plan(
            &live_id(Uuid::new_v4()),
            CapturePauseAuthority::Borrow {
                pause_operation_id: pause.clone(),
                token: token.clone(),
            },
            CaptureResumePolicy::ResumeIfAcquired,
        ))
        .await;
    assert_eq!(
        refused.rejection().unwrap().reason,
        LiveRejectionReason::InvalidPlan
    );
    harness
        .capture(harness.capture_plan(
            &request,
            CapturePauseAuthority::Borrow {
                pause_operation_id: pause.clone(),
                token: token.clone(),
            },
            CaptureResumePolicy::Preserve,
        ))
        .await;
    let observation = harness.capture_settled(&request).await;
    assert_eq!(observation.state, VmLifecycleState::Paused);
    assert_eq!(sealed(&observation).cut_token, token);
    let current = observation.current_pause.clone().unwrap();
    assert_eq!(current.token, token, "the user pause is unchanged");
    assert_eq!(current.operation_id, pause, "and still owned by its pause");
    let record = CaptureEvidence::decode(
        &std::fs::read(harness.capture_dir(&request).join(CAPTURE_EVIDENCE_FILE)).unwrap(),
    )
    .unwrap();
    assert!(record.is_sealed());
    assert_eq!(
        record.freeze_operation_id.as_ref(),
        Some(&pause),
        "a borrowed cut keeps the user pause's frozen operation, never the capture request"
    );
    assert_ne!(record.freeze_operation_id.as_ref(), Some(&request));
    assert_eq!(record.freeze_epoch, Some(current.freeze_epoch));
    let ResumeOutcome::Resumed { .. } = harness.resume(&pause, token).await else {
        panic!("the user resumes their own pause");
    };
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_failure_before_seal_writes_diagnostics_and_continues() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({
        "capture": { "memory": [{ "result": "fail" }] }
    })))
    .await;
    let request = live_id(Uuid::new_v4());
    harness
        .capture(harness.capture_plan(
            &request,
            CapturePauseAuthority::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        ))
        .await;
    let observation = harness.capture_settled(&request).await;
    assert_eq!(
        failure_code(&observation.operation),
        LiveFailureCode::MemoryCaptureFailed
    );
    assert_eq!(observation.state, VmLifecycleState::Running);
    let facts = observation.capture.unwrap();
    assert!(matches!(
        facts.continuation,
        CaptureContinuation::Resumed { .. }
    ));
    let record = CaptureEvidence::decode(
        &std::fs::read(harness.capture_dir(&request).join(CAPTURE_EVIDENCE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(record.capture_outcome, CaptureRecordOutcome::Failed);
    assert!(!record.is_sealed(), "a failed record is never a seal");
    assert_eq!(
        facts.evidence.map(|evidence| evidence.outcome),
        Some(CaptureRecordOutcome::Failed)
    );
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_cancel_before_seal_continues_the_source() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({
        "capture": { "memory": [{ "delayMs": 1500, "result": "complete" }] }
    })))
    .await;
    let request = live_id(Uuid::new_v4());
    harness
        .capture(harness.capture_plan(
            &request,
            CapturePauseAuthority::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        ))
        .await;
    harness
        .until("capture reached RAM", |snapshot| {
            snapshot
                .lifecycle
                .activity
                .as_ref()
                .is_some_and(|activity| activity.stage == LiveStage::CaptureMemory)
        })
        .await;
    let CancelOperationOutcome::Completed { completed } = harness.cancel(&request).await else {
        panic!("cancel before the seal completes after continuation");
    };
    assert!(completed.effective);
    assert_eq!(
        failure_code(&completed.operation),
        LiveFailureCode::Cancelled
    );
    assert_eq!(completed.state, VmLifecycleState::Running);
    let record = CaptureEvidence::decode(
        &std::fs::read(harness.capture_dir(&request).join(CAPTURE_EVIDENCE_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(record.capture_outcome, CaptureRecordOutcome::Failed);
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_refusals_precede_staging_and_freeze() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let acquire = |change: &dyn Fn(&mut CapturePlan)| {
        let mut plan = harness.capture_plan(
            &live_id(Uuid::new_v4()),
            CapturePauseAuthority::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        );
        change(&mut plan);
        plan
    };
    let cases: Vec<(CapturePlan, LiveRejectionCode)> = vec![
        (
            acquire(&|plan| {
                plan.configuration.cpus = 9;
                plan.configuration_digest = plan.configuration.digest().unwrap();
            }),
            LiveRejectionCode::ConfigurationMismatch,
        ),
        (
            // Below libvm's formula floor: refused before any effect.
            acquire(&|plan| plan.reservation.staging_bytes = plan.ram_bytes + (64 << 20) - 1),
            LiveRejectionCode::InvalidPlan,
        ),
        (
            acquire(&|plan| plan.policy = CapturePolicy::Incremental),
            LiveRejectionCode::Unsupported,
        ),
    ];
    for (plan, expected) in cases {
        let result = harness.capture(plan).await;
        assert_eq!(result.rejection().unwrap().reason.code(), expected);
    }
    assert!(
        !harness.root.join("captures").exists(),
        "no staging allocation before admission"
    );
    assert_eq!(harness.status().0, VmLifecycleState::Running);
    assert!(harness.gate.is_open());
    harness.stop().await;
}

impl Harness {
    /// Allocated bytes of the source root, as libvm samples it.
    fn root_allocation(&self) -> u64 {
        std::os::unix::fs::MetadataExt::blocks(
            &std::fs::metadata(self.root.join("root.raw")).unwrap(),
        ) * 512
    }

    /// The running guest writing nonzero blocks into holes of its root.
    fn grow_root(&self, offset: u64, bytes: u64) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.root.join("root.raw"))
            .unwrap();
        let block = vec![0x5a_u8; 1 << 20];
        let mut written = 0;
        while written < bytes {
            let span = (bytes - written).min(block.len() as u64);
            std::os::unix::fs::FileExt::write_all_at(
                &file,
                &block[..span as usize],
                offset + written,
            )
            .unwrap();
            written += span;
        }
        file.sync_all().unwrap();
    }

    /// An acquiring capture reserved by libvm's ADR 0021 formula from the
    /// source allocation sampled now: planned RAM, the root's allocated bytes
    /// and the 64 MiB state allowance.
    fn reserved_plan(
        &self,
        request: &LiveId,
        resume_policy: CaptureResumePolicy,
    ) -> vm_spec::capture::CapturePlan {
        let mut plan = self.capture_plan(
            request,
            vm_spec::capture::CapturePauseAuthority::Acquire,
            resume_policy,
        );
        plan.reservation.staging_bytes =
            plan.ram_bytes + vm_spec::capture::CAPTURE_STATE_RESERVE_BYTES + self.root_allocation();
        plan
    }
}

/// The retained real-VM refusals: an idle guest allocated root blocks
/// between libvm's reservation and admission. A second pre-freeze sample
/// refused it; the sealed total still fits the reservation, so it seals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_seals_source_growth_within_the_reserved_total() {
    use vm_spec::capture::*;
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let request = live_id(Uuid::new_v4());
    let plan = harness.reserved_plan(&request, CaptureResumePolicy::ResumeIfAcquired);
    let reserved_root = harness.root_allocation();
    harness.grow_root(ROOT_DISK_BYTES / 2, 64 << 10);
    let grown_root = harness.root_allocation();
    assert!(
        grown_root > reserved_root,
        "the source grew after reservation"
    );
    assert!(
        plan.ram_bytes + CAPTURE_STATE_RESERVE_BYTES + grown_root > plan.reservation.staging_bytes,
        "a fresh allocation sample exceeds the reserved formula"
    );
    let accepted = harness.capture(plan).await;
    assert!(
        accepted.rejection().is_none(),
        "no stale allocation refusal: {accepted:?}"
    );
    let observation = harness.capture_settled(&request).await;
    sealed(&observation);
    assert_eq!(observation.state, VmLifecycleState::Running);
    // The cut includes the growth, and the sealed role is the source bytes.
    assert_eq!(
        std::fs::read(harness.capture_dir(&request).join("disks/root.raw")).unwrap(),
        std::fs::read(harness.root.join("root.raw")).unwrap()
    );
    harness.stop().await;
}

/// Growth beyond the whole reservation (planned RAM 1 MiB, so the unused
/// RAM and 64 MiB state allowance cannot absorb 66 MiB of new root data)
/// fails before the seal: a failed record, no coherent capture, and the
/// source continues under its recorded policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_capture_exceeding_the_reserved_total_fails_before_its_seal() {
    use vm_spec::capture::*;
    for policy in [
        CaptureResumePolicy::ResumeIfAcquired,
        CaptureResumePolicy::Preserve,
    ] {
        let harness = Harness::start_shaped(
            Some(serde_json::json!({})),
            timeouts(),
            true,
            Some(1),
            128 << 20,
        )
        .await;
        let request = live_id(Uuid::new_v4());
        let plan = harness.reserved_plan(&request, policy);
        assert_eq!(plan.ram_bytes, 1 << 20);
        harness.grow_root(32 << 20, 66 << 20);
        let accepted = harness.capture(plan.clone()).await;
        assert!(
            accepted.rejection().is_none(),
            "admission no longer samples allocation: {accepted:?}"
        );
        let observation = harness.capture_settled(&request).await;
        let OperationOutcome::Failed { failure } = &observation.operation.outcome else {
            panic!("an over-budget capture never seals: {observation:?}");
        };
        assert_eq!(failure.code, LiveFailureCode::StagingBudgetExceeded);
        assert_eq!(failure.stage, LiveStage::CaptureVerify);
        let message = failure.message.as_ref().unwrap().to_string();
        assert!(
            message.contains(&plan.reservation.staging_bytes.to_string()),
            "{message}"
        );
        let directory = harness.capture_dir(&request);
        let record =
            CaptureEvidence::decode(&std::fs::read(directory.join(CAPTURE_EVIDENCE_FILE)).unwrap())
                .unwrap();
        assert_eq!(record.capture_outcome, CaptureRecordOutcome::Failed);
        assert!(!record.is_sealed());
        let facts = observation.capture.clone().unwrap();
        assert_eq!(
            facts.evidence.map(|evidence| evidence.outcome),
            Some(CaptureRecordOutcome::Failed)
        );
        match policy {
            CaptureResumePolicy::ResumeIfAcquired => {
                assert_eq!(observation.state, VmLifecycleState::Running);
                assert!(matches!(
                    facts.continuation,
                    CaptureContinuation::Resumed { .. }
                ));
                assert!(harness.gate.is_open());
            }
            CaptureResumePolicy::Preserve => {
                assert_eq!(observation.state, VmLifecycleState::Paused);
                let current = observation.current_pause.clone().expect("user authority");
                assert_eq!(current.token.owner, PauseOwner::User);
                assert!(matches!(
                    facts.continuation,
                    CaptureContinuation::Preserved { ref preserved } if preserved == &current
                ));
            }
        }
        harness.stop().await;
    }
}

impl Harness {
    /// One native lifecycle request straight to the backend, as any monitor
    /// task would submit it.
    async fn native(
        &self,
        command: crate::virt::lifecycle::LifecycleCommand,
    ) -> Result<crate::virt::lifecycle::LifecycleResponse, crate::virt::lifecycle::LifecycleError>
    {
        let uuid = |id: &LiveId| Uuid::parse_str(id.as_str()).unwrap();
        self.machine
            .lifecycle(crate::virt::lifecycle::LifecycleRequest {
                machine_id: uuid(&self.machine_id),
                run_id: uuid(&self.run_id),
                request_id: Uuid::new_v4(),
                command,
            })
            .await
    }

    async fn native_control(&self) -> crate::virt::lifecycle::NativeControl {
        match self
            .native(crate::virt::lifecycle::LifecycleCommand::GetControl { target: None })
            .await
            .expect("native observation stays available")
            .control
        {
            crate::virt::lifecycle::ControlObservation::Observed { control } => control,
            unavailable => panic!("native control unobserved: {unavailable:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_begin_stop_fences_native_submission_before_backend_termination() {
    use crate::virt::lifecycle::{
        LifecycleCommand, LifecycleError, LifecycleRejection, NativeControl, NativePauseGeneration,
        NativePauseOwner,
    };
    let harness = Harness::start(Some(serde_json::json!({}))).await;
    let operation = harness.pause().await;
    let token = paused_token(&harness.settled(&operation).await);
    let generation = NativePauseGeneration::new(token.generation.get()).unwrap();
    // Shutdown awaits its service handoff after begin_stop while the backend
    // is still alive: the native submission fence is already closed.
    assert_eq!(harness.live.begin_stop(), StopMode::Terminate);
    let resume = harness
        .native(LifecycleCommand::Resume {
            operation: Uuid::parse_str(operation.as_str()).unwrap(),
            generation,
            timeout: Duration::from_secs(5),
        })
        .await;
    assert!(
        matches!(
            resume,
            Err(LifecycleError::Rejected(LifecycleRejection::Stopping))
        ),
        "a resume submitted after stop began never reaches the worker: {resume:?}"
    );
    assert_eq!(
        harness.native_control().await,
        NativeControl::Paused {
            generation,
            owner: NativePauseOwner::User
        },
        "the worker stays observable and the source stays paused"
    );
    assert!(!harness.gate.reopen(), "stop seals fences permanently");
    harness.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_stop_during_capture_never_continues_the_capture_pause() {
    use crate::virt::lifecycle::{
        CaptureProgress, LifecycleCommand, NativeControl, NativePauseOwner,
    };
    use vm_spec::capture::CapturePauseAuthority;
    let harness = Harness::start(Some(serde_json::json!({
        "capture": { "memory": [{ "delayMs": 1000, "result": "complete" }] }
    })))
    .await;
    let request = live_id(Uuid::new_v4());
    harness
        .capture(harness.capture_plan(
            &request,
            CapturePauseAuthority::Acquire,
            CaptureResumePolicy::ResumeIfAcquired,
        ))
        .await;
    harness
        .until("capture reached RAM", |snapshot| {
            snapshot
                .lifecycle
                .activity
                .as_ref()
                .is_some_and(|activity| activity.stage == LiveStage::CaptureMemory)
        })
        .await;
    // The projected stage precedes native enqueue. Observe native admission
    // before closing the fence, otherwise stop may correctly refuse RAM.
    let capture = Uuid::parse_str(request.as_str()).unwrap();
    let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let observed = harness
            .native(LifecycleCommand::GetCapture { operation: capture })
            .await
            .unwrap()
            .capture
            .unwrap();
        if observed.progress == CaptureProgress::MemoryPending {
            break;
        }
        assert!(
            tokio::time::Instant::now() < admission_deadline,
            "native RAM was not admitted: {observed:?}"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(harness.live.begin_stop(), StopMode::Terminate);
    // RAM work admitted before the fence still completes natively.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let observed = harness
            .native(LifecycleCommand::GetCapture { operation: capture })
            .await
            .expect("capture observation")
            .capture
            .expect("capture facts");
        if observed.progress == CaptureProgress::CandidateComplete {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "native RAM never completed: {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Neither a ClockOnly resume nor a preserve transfer follows stop: the
    // capture-owned cut stays exactly as it was until the reaper ends it.
    for _ in 0..10 {
        assert!(matches!(
            harness.native_control().await,
            NativeControl::Paused {
                owner: NativePauseOwner::Capture,
                ..
            }
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!harness.gate.reopen(), "stop seals fences permanently");
    harness.stop().await;
}

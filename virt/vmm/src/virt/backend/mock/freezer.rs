//! Scenario guest workload freezer for the mock agent.
//!
//! Mirrors the real agent's lifecycle coordinator contract: exact next freeze
//! epoch, identical-input retries join one owned attempt (including
//! `deadline_ms`), changed inputs conflict, a failed freeze carries its own
//! rollback, a rollback Thaw may queue behind an in-flight freeze, stale thaw
//! references are refused and new sessions/mutations are refused while the
//! workload gate is closed. Outcomes and latencies come from
//! [`test_utils::LifecycleScenario`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use protocol::v1::{
    ExpectedGuestIdentity, FreezeRef, FreezeWorkloadsRequest, FreezeWorkloadsResponse,
    GuestLifecycleState as State, GuestLifecycleStatus, ThawRequest, ThawResponse,
};
use test_utils::{
    GuestFreezeResult, GuestFreezeStep, GuestThawResult, GuestThawStep, LifecycleScenario,
};
use tokio::sync::watch;
use tonic::Status;

const MAX_DEADLINE_MS: u32 = 5000;

/// The guest's reversible workload admission gate.
#[derive(Debug, Default)]
pub(crate) struct GuestAdmission {
    closed: AtomicBool,
}

impl GuestAdmission {
    pub(crate) fn admit_mutation(&self) -> Result<(), Status> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Status::failed_precondition(
                "guest workload mutation admission is closed",
            ));
        }
        Ok(())
    }

    pub(crate) fn admit_session(&self) -> Result<(), Status> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Status::failed_precondition(
                "guest session admission is closed",
            ));
        }
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    fn open(&self) {
        self.closed.store(false, Ordering::Release);
    }
}

type Completion<T> = watch::Sender<Option<Result<T, Status>>>;
type CompletionReceiver<T> = watch::Receiver<Option<Result<T, Status>>>;

#[derive(Default)]
struct Coordinator {
    freeze: Option<(FreezeWorkloadsRequest, Completion<FreezeWorkloadsResponse>)>,
    thaw: Option<(ThawRequest, tokio::time::Instant, Completion<ThawResponse>)>,
    busy: bool,
    /// Modeled kernel freezer state of the workload roots.
    frozen: bool,
    freeze_steps: VecDeque<GuestFreezeStep>,
    thaw_steps: VecDeque<GuestThawStep>,
}

#[derive(Debug)]
pub(crate) struct GuestLifecycle {
    machine_id: String,
    run_id: String,
    workload_roots: Vec<String>,
    unsupported: Option<String>,
    status: watch::Sender<GuestLifecycleStatus>,
    coordinator: Mutex<Coordinator>,
    admission: Arc<GuestAdmission>,
}

impl std::fmt::Debug for Coordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coordinator")
            .field("busy", &self.busy)
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

fn lock(coordinator: &Mutex<Coordinator>) -> MutexGuard<'_, Coordinator> {
    coordinator.lock().unwrap_or_else(PoisonError::into_inner)
}

impl GuestLifecycle {
    pub(crate) fn new(
        scenario: &LifecycleScenario,
        launch: Option<(String, String)>,
        admission: Arc<GuestAdmission>,
    ) -> Self {
        let (machine_id, run_id) = launch.unwrap_or_default();
        let status = GuestLifecycleStatus {
            state: State::Running as i32,
            freeze_ref: None,
            workload_roots: scenario.workload_roots.clone(),
            observed_frozen_roots: Vec::new(),
            unsupported_reason: scenario.freezer_unsupported.clone(),
            failure: None,
            rollback_succeeded: None,
            machine_id: machine_id.clone(),
            run_id: run_id.clone(),
            activation_id: None,
            generation_driver_ready: Some(scenario.generation_driver_ready),
            clock_profile: None,
            clock_profile_unavailable_reason: None,
        };
        Self {
            machine_id,
            run_id,
            workload_roots: scenario.workload_roots.clone(),
            unsupported: scenario.freezer_unsupported.clone(),
            status: watch::Sender::new(status),
            coordinator: Mutex::new(Coordinator {
                freeze_steps: scenario.freeze.iter().cloned().collect(),
                thaw_steps: scenario.thaw.iter().cloned().collect(),
                ..Coordinator::default()
            }),
            admission,
        }
    }

    pub(crate) fn status(&self) -> GuestLifecycleStatus {
        self.status.borrow().clone()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<GuestLifecycleStatus> {
        self.status.subscribe()
    }

    fn publish(
        &self,
        state: State,
        reference: &FreezeRef,
        observed: bool,
        failure: Option<String>,
        rollback: Option<bool>,
    ) {
        self.status.send_modify(|status| {
            status.state = state as i32;
            status.freeze_ref = Some(reference.clone());
            status.observed_frozen_roots = if observed {
                self.workload_roots.clone()
            } else {
                Vec::new()
            };
            status.failure = failure;
            status.rollback_succeeded = rollback;
        });
    }

    fn reference(&self, reference: Option<&FreezeRef>) -> Result<FreezeRef, Status> {
        let reference = reference.ok_or_else(|| Status::invalid_argument("freeze_ref required"))?;
        for id in [
            &reference.machine_id,
            &reference.run_id,
            &reference.operation_id,
        ] {
            protocol::shutdown::validate_uuid(id).map_err(Status::invalid_argument)?;
        }
        if reference.freeze_epoch.is_none_or(|epoch| epoch == 0) {
            return Err(Status::invalid_argument("nonzero freeze_epoch required"));
        }
        if reference.machine_id != self.machine_id || reference.run_id != self.run_id {
            return Err(Status::failed_precondition(
                "freeze reference belongs to another run",
            ));
        }
        Ok(reference.clone())
    }

    pub(crate) async fn freeze(
        self: &Arc<Self>,
        request: FreezeWorkloadsRequest,
        current: &ExpectedGuestIdentity,
        boot_ready: bool,
    ) -> Result<FreezeWorkloadsResponse, Status> {
        wait(self.begin_freeze(request, current, boot_ready)?).await
    }

    fn begin_freeze(
        self: &Arc<Self>,
        request: FreezeWorkloadsRequest,
        current: &ExpectedGuestIdentity,
        boot_ready: bool,
    ) -> Result<CompletionReceiver<FreezeWorkloadsResponse>, Status> {
        let deadline = deadline(request.deadline_ms)?;
        let mut owner = lock(&self.coordinator);
        expected(request.expected.as_ref(), current)?;
        let reference = self.reference(request.freeze_ref.as_ref())?;
        if let Some(reason) = &self.unsupported {
            return Err(Status::failed_precondition(reason.clone()));
        }
        if !boot_ready {
            return Err(Status::failed_precondition(
                "guest cold provisioning is incomplete or shutdown is in progress",
            ));
        }
        let status = self.status();
        if let Some((input, completion)) = &owner.freeze {
            if input.freeze_ref == request.freeze_ref {
                if input != &request {
                    return Err(Status::already_exists("freeze retry inputs conflict"));
                }
                if status.state == State::Freezing as i32
                    || status.state == State::FreezeFailed as i32
                {
                    return Ok(completion.subscribe());
                }
                if status.state == State::Frozen as i32 {
                    if !owner.frozen {
                        return Err(Status::failed_precondition(
                            "cached freeze no longer matches kernel state",
                        ));
                    }
                    return Ok(completed(FreezeWorkloadsResponse {
                        status: Some(status),
                    }));
                }
                return Err(Status::failed_precondition(
                    "completed freeze epoch cannot be reused; advance epoch",
                ));
            }
        }
        if owner.busy {
            return Err(Status::failed_precondition(
                "guest lifecycle operation in progress",
            ));
        }
        if !matches!(
            State::try_from(status.state),
            Ok(State::Running | State::Thawed | State::Frozen | State::FreezeFailed)
        ) {
            return Err(Status::failed_precondition(
                "guest lifecycle state refuses freeze",
            ));
        }
        let previous = status
            .freeze_ref
            .as_ref()
            .and_then(|reference| reference.freeze_epoch)
            .unwrap_or(0);
        let next = previous
            .checked_add(1)
            .ok_or_else(|| Status::failed_precondition("freeze epoch exhausted"))?;
        if reference.freeze_epoch != Some(next) {
            return Err(Status::failed_precondition(
                "freeze requires exact next epoch",
            ));
        }
        let step = owner.freeze_steps.pop_front().unwrap_or(GuestFreezeStep {
            delay_ms: 0,
            result: GuestFreezeResult::Frozen,
        });
        self.admission.close();
        let (completion, receiver) = watch::channel(None);
        owner.busy = true;
        owner.freeze = Some((request, completion.clone()));
        owner.thaw = None;
        self.publish(State::Freezing, &reference, false, None, None);
        let lifecycle = self.clone();
        tokio::spawn(async move {
            let result = lifecycle.perform_freeze(&reference, deadline, step).await;
            let rollback = {
                let mut owner = lock(&lifecycle.coordinator);
                let rollback = owner
                    .thaw
                    .as_ref()
                    .map(|(_, deadline, completion)| (*deadline, completion.clone()));
                if rollback.is_none() {
                    owner.busy = false;
                }
                rollback
            };
            completion.send_replace(Some(result));
            if let Some((rollback_deadline, completion)) = rollback {
                let result = if lifecycle.status().state == State::Faulted as i32 {
                    Err(Status::failed_precondition("freeze rollback faulted"))
                } else {
                    let step = lifecycle.next_thaw_step();
                    lifecycle
                        .perform_thaw(&reference, rollback_deadline, step)
                        .await
                };
                lock(&lifecycle.coordinator).busy = false;
                completion.send_replace(Some(result));
            }
        });
        Ok(receiver)
    }

    async fn perform_freeze(
        &self,
        reference: &FreezeRef,
        deadline: tokio::time::Instant,
        step: GuestFreezeStep,
    ) -> Result<FreezeWorkloadsResponse, Status> {
        let finishes = tokio::time::Instant::now() + Duration::from_millis(step.delay_ms);
        let timed_out = step.result == GuestFreezeResult::Hang || finishes > deadline;
        tokio::time::sleep_until(if timed_out { deadline } else { finishes }).await;
        let response = |lifecycle: &Self| FreezeWorkloadsResponse {
            status: Some(lifecycle.status()),
        };
        if timed_out || step.result == GuestFreezeResult::FreezeFailed {
            lock(&self.coordinator).frozen = false;
            self.admission.open();
            let failure = if timed_out {
                "freeze deadline exceeded"
            } else {
                "scripted freeze failure"
            };
            self.publish(
                State::FreezeFailed,
                reference,
                false,
                Some(failure.to_string()),
                Some(true),
            );
            return Ok(response(self));
        }
        match step.result {
            GuestFreezeResult::Faulted => {
                self.publish(
                    State::Faulted,
                    reference,
                    false,
                    Some("scripted freeze failure; rollback failed".to_string()),
                    Some(false),
                );
                Ok(response(self))
            }
            GuestFreezeResult::DropResponse => {
                lock(&self.coordinator).frozen = true;
                self.publish(State::Frozen, reference, true, None, None);
                Err(Status::unavailable("scripted lost freeze response"))
            }
            GuestFreezeResult::Frozen
            | GuestFreezeResult::FreezeFailed
            | GuestFreezeResult::Hang => {
                lock(&self.coordinator).frozen = true;
                self.publish(State::Frozen, reference, true, None, None);
                Ok(response(self))
            }
        }
    }

    pub(crate) async fn thaw(
        self: &Arc<Self>,
        request: ThawRequest,
        current: &ExpectedGuestIdentity,
    ) -> Result<ThawResponse, Status> {
        wait(self.begin_thaw(request, current)?).await
    }

    fn next_thaw_step(&self) -> GuestThawStep {
        lock(&self.coordinator)
            .thaw_steps
            .pop_front()
            .unwrap_or(GuestThawStep {
                delay_ms: 0,
                result: GuestThawResult::Thawed,
            })
    }

    fn begin_thaw(
        self: &Arc<Self>,
        request: ThawRequest,
        current: &ExpectedGuestIdentity,
    ) -> Result<CompletionReceiver<ThawResponse>, Status> {
        let deadline = deadline(request.deadline_ms)?;
        let mut owner = lock(&self.coordinator);
        expected(request.expected.as_ref(), current)?;
        let reference = self.reference(request.freeze_ref.as_ref())?;
        let status = self.status();
        if status.freeze_ref.as_ref() != Some(&reference) {
            return Err(Status::failed_precondition("stale thaw reference"));
        }
        if let Some((input, _, completion)) = &owner.thaw {
            if input == &request {
                return Ok(completion.subscribe());
            }
            return Err(Status::already_exists("thaw retry inputs conflict"));
        }
        if owner.busy && request.rollback && status.state == State::Freezing as i32 {
            let (completion, receiver) = watch::channel(None);
            owner.thaw = Some((request, deadline, completion));
            return Ok(receiver);
        }
        if owner.busy {
            return Err(Status::failed_precondition(
                "guest lifecycle operation in progress",
            ));
        }
        let allowed = match State::try_from(status.state) {
            Ok(State::Frozen) => true,
            Ok(State::FreezeFailed) => request.rollback,
            _ => false,
        };
        if !allowed {
            return Err(Status::failed_precondition(
                "guest lifecycle state refuses thaw",
            ));
        }
        let step = owner.thaw_steps.pop_front().unwrap_or(GuestThawStep {
            delay_ms: 0,
            result: GuestThawResult::Thawed,
        });
        let (completion, receiver) = watch::channel(None);
        owner.busy = true;
        owner.thaw = Some((request, deadline, completion.clone()));
        self.publish(State::Thawing, &reference, true, None, None);
        let lifecycle = self.clone();
        tokio::spawn(async move {
            let response = lifecycle.perform_thaw(&reference, deadline, step).await;
            lock(&lifecycle.coordinator).busy = false;
            completion.send_replace(Some(response));
        });
        Ok(receiver)
    }

    async fn perform_thaw(
        &self,
        reference: &FreezeRef,
        deadline: tokio::time::Instant,
        step: GuestThawStep,
    ) -> Result<ThawResponse, Status> {
        self.publish(State::Thawing, reference, true, None, None);
        let finishes = tokio::time::Instant::now() + Duration::from_millis(step.delay_ms);
        if finishes > deadline {
            tokio::time::sleep_until(deadline).await;
            self.publish(
                State::Faulted,
                reference,
                false,
                Some("thaw deadline exceeded".to_string()),
                None,
            );
            return Err(Status::internal("thaw deadline exceeded"));
        }
        tokio::time::sleep_until(finishes).await;
        match step.result {
            GuestThawResult::Faulted => {
                self.publish(
                    State::Faulted,
                    reference,
                    false,
                    Some("scripted thaw failure".to_string()),
                    None,
                );
                Err(Status::internal("scripted thaw failure"))
            }
            GuestThawResult::Thawed | GuestThawResult::DropResponse => {
                lock(&self.coordinator).frozen = false;
                self.admission.open();
                self.publish(State::Thawed, reference, false, None, None);
                if step.result == GuestThawResult::DropResponse {
                    Err(Status::unavailable("scripted lost thaw response"))
                } else {
                    Ok(ThawResponse {
                        status: Some(self.status()),
                    })
                }
            }
        }
    }
}

fn expected(
    expected: Option<&ExpectedGuestIdentity>,
    current: &ExpectedGuestIdentity,
) -> Result<(), Status> {
    let expected =
        expected.ok_or_else(|| Status::invalid_argument("expected identity required"))?;
    for id in [
        &expected.machine_id,
        &expected.run_id,
        &expected.agent_instance_id,
        &expected.boot_id,
    ] {
        protocol::shutdown::validate_uuid(id).map_err(Status::invalid_argument)?;
    }
    if expected != current {
        return Err(Status::failed_precondition(
            "guest runtime identity mismatch",
        ));
    }
    Ok(())
}

fn deadline(value: Option<u32>) -> Result<tokio::time::Instant, Status> {
    let value = value
        .filter(|value| (1..=MAX_DEADLINE_MS).contains(value))
        .ok_or_else(|| {
            Status::invalid_argument(format!("deadline_ms required in 1..={MAX_DEADLINE_MS}"))
        })?;
    Ok(tokio::time::Instant::now() + Duration::from_millis(u64::from(value)))
}

async fn wait<T: Clone>(mut completion: CompletionReceiver<T>) -> Result<T, Status> {
    loop {
        if let Some(result) = completion.borrow().clone() {
            return result;
        }
        completion
            .changed()
            .await
            .map_err(|_| Status::unavailable("lifecycle operation owner disappeared"))?;
    }
}

fn completed<T>(value: T) -> CompletionReceiver<T> {
    watch::channel(Some(Ok(value))).1
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protocol::v1::{
        ExpectedGuestIdentity, FreezeRef, FreezeWorkloadsRequest, GuestLifecycleState as State,
        ThawRequest,
    };
    use test_utils::LifecycleScenario;
    use tonic::Code;
    use uuid::Uuid;

    use crate::virt::backend::mock::freezer::{GuestAdmission, GuestLifecycle};

    struct Guest {
        lifecycle: Arc<GuestLifecycle>,
        admission: Arc<GuestAdmission>,
        identity: ExpectedGuestIdentity,
        operation: String,
    }

    fn guest(scenario: &str) -> Guest {
        let scenario: LifecycleScenario = serde_json::from_str(scenario).expect("scenario");
        let identity = ExpectedGuestIdentity {
            machine_id: Uuid::new_v4().to_string(),
            run_id: Uuid::new_v4().to_string(),
            agent_instance_id: Uuid::new_v4().to_string(),
            boot_id: Uuid::new_v4().to_string(),
        };
        let admission = Arc::new(GuestAdmission::default());
        Guest {
            lifecycle: Arc::new(GuestLifecycle::new(
                &scenario,
                Some((identity.machine_id.clone(), identity.run_id.clone())),
                admission.clone(),
            )),
            admission,
            identity,
            operation: Uuid::new_v4().to_string(),
        }
    }

    impl Guest {
        fn reference(&self, epoch: u64) -> FreezeRef {
            FreezeRef {
                machine_id: self.identity.machine_id.clone(),
                run_id: self.identity.run_id.clone(),
                operation_id: self.operation.clone(),
                freeze_epoch: Some(epoch),
            }
        }

        fn freeze_request(&self, epoch: u64, deadline_ms: u32) -> FreezeWorkloadsRequest {
            FreezeWorkloadsRequest {
                expected: Some(self.identity.clone()),
                freeze_ref: Some(self.reference(epoch)),
                deadline_ms: Some(deadline_ms),
            }
        }

        fn thaw_request(&self, epoch: u64, rollback: bool) -> ThawRequest {
            ThawRequest {
                expected: Some(self.identity.clone()),
                freeze_ref: Some(self.reference(epoch)),
                rollback,
                deadline_ms: Some(1000),
            }
        }

        async fn freeze(&self, epoch: u64) -> Result<State, tonic::Status> {
            self.lifecycle
                .freeze(self.freeze_request(epoch, 1000), &self.identity, true)
                .await
                .map(|response| state(response.status.as_ref()))
        }

        async fn thaw(&self, epoch: u64, rollback: bool) -> Result<State, tonic::Status> {
            self.lifecycle
                .thaw(self.thaw_request(epoch, rollback), &self.identity)
                .await
                .map(|response| state(response.status.as_ref()))
        }
    }

    fn state(status: Option<&protocol::v1::GuestLifecycleStatus>) -> State {
        State::try_from(status.expect("status").state).expect("closed state")
    }

    #[tokio::test]
    async fn epochs_advance_exactly_and_frozen_gate_refuses_new_work() {
        let guest = guest("{}");
        assert_eq!(
            guest.freeze(2).await.expect_err("skipped epoch").code(),
            Code::FailedPrecondition
        );
        assert_eq!(guest.freeze(1).await.expect("freeze"), State::Frozen);
        let status = guest.lifecycle.status();
        assert_eq!(status.observed_frozen_roots, status.workload_roots);
        assert_eq!(status.generation_driver_ready, Some(true));
        assert_eq!(
            guest.admission.admit_session().expect_err("frozen").code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            guest.admission.admit_mutation().expect_err("frozen").code(),
            Code::FailedPrecondition
        );
        // The same epoch and inputs report the cached kernel barrier.
        assert_eq!(guest.freeze(1).await.expect("cached"), State::Frozen);
        let conflicting = guest
            .lifecycle
            .freeze(guest.freeze_request(1, 999), &guest.identity, true)
            .await
            .expect_err("changed deadline");
        assert_eq!(conflicting.code(), Code::AlreadyExists);
        assert_eq!(
            guest.thaw(2, false).await.expect_err("stale thaw").code(),
            Code::FailedPrecondition
        );
        assert_eq!(guest.thaw(1, false).await.expect("thaw"), State::Thawed);
        guest.admission.admit_session().expect("reopened");
        assert_eq!(
            guest.freeze(1).await.expect_err("consumed epoch").code(),
            Code::FailedPrecondition
        );
        assert_eq!(guest.freeze(2).await.expect("next epoch"), State::Frozen);
    }

    #[tokio::test]
    async fn identity_and_run_mismatches_are_refused_before_effects() {
        let guest = guest("{}");
        let mut stale = guest.identity.clone();
        stale.agent_instance_id = Uuid::new_v4().to_string();
        let error = guest
            .lifecycle
            .freeze(guest.freeze_request(1, 1000), &stale, true)
            .await
            .expect_err("identity mismatch");
        assert_eq!(error.code(), Code::FailedPrecondition);
        let mut foreign = guest.freeze_request(1, 1000);
        if let Some(reference) = foreign.freeze_ref.as_mut() {
            reference.run_id = Uuid::new_v4().to_string();
        }
        assert_eq!(
            guest
                .lifecycle
                .freeze(foreign, &guest.identity, true)
                .await
                .expect_err("foreign run")
                .code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            guest
                .lifecycle
                .freeze(guest.freeze_request(1, 1000), &guest.identity, false)
                .await
                .expect_err("not booted")
                .code(),
            Code::FailedPrecondition
        );
        let unsupported = self::guest(r#"{"freezerUnsupported": "image-owned cgroups"}"#);
        assert_eq!(
            unsupported.freeze(1).await.expect_err("unsupported").code(),
            Code::FailedPrecondition
        );
        assert_eq!(guest.lifecycle.status().state, State::Running as i32);
        guest.admission.admit_mutation().expect("gate untouched");
    }

    #[tokio::test]
    async fn failed_freeze_carries_its_own_rollback_and_faults_stay_fenced() {
        let guest = guest(r#"{"freeze": [{"result": "freezeFailed"}, {"result": "faulted"}]}"#);
        assert_eq!(guest.freeze(1).await.expect("report"), State::FreezeFailed);
        assert_eq!(guest.lifecycle.status().rollback_succeeded, Some(true));
        guest
            .admission
            .admit_session()
            .expect("rollback reopened the gate");
        assert_eq!(
            guest.thaw(1, true).await.expect("explicit rollback"),
            State::Thawed
        );
        assert_eq!(guest.freeze(2).await.expect("report"), State::Faulted);
        assert_eq!(guest.lifecycle.status().rollback_succeeded, Some(false));
        assert!(
            guest.admission.admit_session().is_err(),
            "faulted stays fenced"
        );
        assert_eq!(
            guest
                .thaw(2, true)
                .await
                .expect_err("faulted refuses thaw")
                .code(),
            Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn rollback_thaw_queues_behind_an_in_flight_freeze_and_joins_retries() {
        let guest = guest(r#"{"freeze": [{"delayMs": 150, "result": "frozen"}]}"#);
        let freezing = {
            let lifecycle = guest.lifecycle.clone();
            let request = guest.freeze_request(1, 1000);
            let identity = guest.identity.clone();
            tokio::spawn(async move { lifecycle.freeze(request, &identity, true).await })
        };
        while guest.lifecycle.status().state != State::Freezing as i32 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            guest
                .thaw(1, false)
                .await
                .expect_err("normal thaw while busy")
                .code(),
            Code::FailedPrecondition
        );
        let (first, second) = tokio::join!(guest.thaw(1, true), guest.thaw(1, true));
        assert_eq!(first.expect("rollback"), State::Thawed);
        assert_eq!(second.expect("joined rollback"), State::Thawed);
        assert!(freezing.await.expect("join").is_ok());
        guest
            .admission
            .admit_mutation()
            .expect("gate reopened after rollback");
    }

    #[tokio::test]
    async fn lost_responses_keep_their_effects() {
        let guest = guest(
            r#"{"freeze": [{"result": "dropResponse"}], "thaw": [{"result": "dropResponse"}]}"#,
        );
        assert_eq!(
            guest.freeze(1).await.expect_err("lost freeze reply").code(),
            Code::Unavailable
        );
        assert_eq!(guest.lifecycle.status().state, State::Frozen as i32);
        // The identical retry observes the established barrier.
        assert_eq!(guest.freeze(1).await.expect("retry"), State::Frozen);
        assert_eq!(
            guest
                .thaw(1, false)
                .await
                .expect_err("lost thaw reply")
                .code(),
            Code::Unavailable
        );
        assert_eq!(guest.lifecycle.status().state, State::Thawed as i32);
        guest
            .admission
            .admit_session()
            .expect("workloads run after a lost thaw");
        // Recovery is the exact next epoch, never a reused one.
        assert_eq!(
            guest.freeze(2).await.expect("recovery freeze"),
            State::Frozen
        );
    }

    #[tokio::test]
    async fn hung_freeze_fails_at_its_deadline_with_rollback() {
        let guest = guest(r#"{"freeze": [{"result": "hang"}]}"#);
        let started = tokio::time::Instant::now();
        let result = guest
            .lifecycle
            .freeze(guest.freeze_request(1, 100), &guest.identity, true)
            .await
            .map(|response| state(response.status.as_ref()));
        assert_eq!(result.expect("report"), State::FreezeFailed);
        assert!(started.elapsed() >= Duration::from_millis(100));
        guest.admission.admit_session().expect("rolled back");
    }
}

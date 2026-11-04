//! Run-bound guest lifecycle. Kernel completion, not transport lifetime, owns progress.
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use protocol::shutdown::StorageShutdownContext;
use protocol::v1::{self, GuestLifecycleState as State};
use tokio::sync::{watch, Notify};
use tonic::Status;

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    match value.lock() {
        Ok(value) => value,
        Err(error) => error.into_inner(),
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeIdentity {
    pub(crate) expected: v1::ExpectedGuestIdentity,
    pub(crate) shutdown: StorageShutdownContext,
}

#[derive(Default)]
struct Admission {
    closed: bool,
    shutting_down: bool,
    boot_ready: bool,
    active: usize,
    sessions: usize,
}

pub(crate) struct RuntimeContext {
    identity: Mutex<RuntimeIdentity>,
    admission: Mutex<Admission>,
    idle: Notify,
    pub(crate) lifecycle: watch::Sender<v1::GuestLifecycleStatus>,
    retirement: watch::Sender<u64>,
}

pub(crate) struct MutationLease {
    runtime: Arc<RuntimeContext>,
}
impl Drop for MutationLease {
    fn drop(&mut self) {
        let mut admission = lock(&self.runtime.admission);
        admission.active = admission.active.saturating_sub(1);
        self.runtime.idle.notify_waiters();
    }
}

#[derive(Clone)]
pub(crate) struct SessionLease {
    _lease: Arc<SessionLifetime>,
}
struct SessionLifetime {
    runtime: Arc<RuntimeContext>,
}
impl Drop for SessionLifetime {
    fn drop(&mut self) {
        let mut admission = lock(&self.runtime.admission);
        admission.sessions = admission.sessions.saturating_sub(1);
        self.runtime.idle.notify_waiters();
    }
}

impl RuntimeContext {
    pub(crate) fn new(context: StorageShutdownContext) -> eyre::Result<Arc<Self>> {
        context.validate().map_err(|error| eyre::eyre!(error))?;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        protocol::shutdown::validate_uuid(&boot).map_err(|error| eyre::eyre!(error))?;
        Ok(Self::from_identity(
            context,
            uuid::Uuid::new_v4().to_string(),
            boot,
        ))
    }

    pub(crate) fn from_identity(
        context: StorageShutdownContext,
        instance: String,
        boot: String,
    ) -> Arc<Self> {
        let status = v1::GuestLifecycleStatus {
            state: State::Running as i32,
            machine_id: context.machine_id.clone(),
            run_id: context.run_id.clone(),
            ..Default::default()
        };
        let (lifecycle, _) = watch::channel(status);
        let (retirement, _) = watch::channel(0);
        Arc::new(Self {
            identity: Mutex::new(RuntimeIdentity {
                expected: v1::ExpectedGuestIdentity {
                    machine_id: context.machine_id.clone(),
                    run_id: context.run_id.clone(),
                    agent_instance_id: instance,
                    boot_id: boot,
                },
                shutdown: context,
            }),
            admission: Mutex::new(Admission::default()),
            idle: Notify::new(),
            lifecycle,
            retirement,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests() -> Arc<Self> {
        Self::from_identity(
            StorageShutdownContext {
                version: 1,
                machine_id: uuid::Uuid::new_v4().to_string(),
                run_id: uuid::Uuid::new_v4().to_string(),
                manifest: protocol::shutdown::StorageManifest::Unsupported {
                    reason: "unit-test inventory".into(),
                },
            },
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        )
    }

    pub(crate) fn identity(&self) -> RuntimeIdentity {
        lock(&self.identity).clone()
    }
    pub(crate) fn expected(&self) -> v1::ExpectedGuestIdentity {
        lock(&self.identity).expected.clone()
    }
    pub(crate) fn instance_id(&self) -> String {
        lock(&self.identity).expected.agent_instance_id.clone()
    }
    pub(crate) fn set_boot_ready(&self, ready: bool) {
        lock(&self.admission).boot_ready = ready;
    }
    pub(crate) fn retirement(&self) -> watch::Receiver<u64> {
        self.retirement.subscribe()
    }
    pub(crate) fn admit_mutation(self: &Arc<Self>) -> Result<MutationLease, Status> {
        let mut gate = lock(&self.admission);
        if gate.closed || gate.shutting_down {
            return Err(Status::failed_precondition(
                "guest workload mutation admission is closed",
            ));
        }
        gate.active = gate
            .active
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("mutation lease overflow"))?;
        Ok(MutationLease {
            runtime: self.clone(),
        })
    }
    pub(crate) fn admit_session(self: &Arc<Self>) -> Result<SessionLease, Status> {
        let mut gate = lock(&self.admission);
        if gate.closed || gate.shutting_down {
            return Err(Status::failed_precondition(
                "guest session admission is closed",
            ));
        }
        gate.sessions = gate
            .sessions
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("session lease overflow"))?;
        Ok(SessionLease {
            _lease: Arc::new(SessionLifetime {
                runtime: self.clone(),
            }),
        })
    }
    async fn drain_sessions(&self, deadline: tokio::time::Instant) -> Result<(), Status> {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if lock(&self.admission).sessions == 0 {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| Status::deadline_exceeded("captured sessions did not retire"))?;
        }
    }
    fn close(&self) -> Result<(), Status> {
        let mut gate = lock(&self.admission);
        if gate.shutting_down {
            return Err(Status::failed_precondition(
                "orderly shutdown already admitted",
            ));
        }
        gate.closed = true;
        Ok(())
    }
    fn open(&self) {
        let mut gate = lock(&self.admission);
        if !gate.shutting_down {
            gate.closed = false;
        }
    }
    pub(crate) fn admit_shutdown(&self) -> Result<(), Status> {
        let mut gate = lock(&self.admission);
        if gate.closed || gate.shutting_down {
            return Err(Status::failed_precondition(
                "guest lifecycle or shutdown already admitted",
            ));
        }
        gate.shutting_down = true;
        gate.closed = true;
        Ok(())
    }
    pub(crate) fn cancel_shutdown_admission(&self) {
        let mut gate = lock(&self.admission);
        gate.shutting_down = false;
        gate.closed = false;
    }
    pub(crate) fn stop_admissions(&self) {
        let mut gate = lock(&self.admission);
        gate.closed = true;
        gate.shutting_down = true;
        gate.boot_ready = false;
    }
    async fn drain(&self, deadline: tokio::time::Instant) -> Result<(), Status> {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if lock(&self.admission).active == 0 {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| Status::deadline_exceeded("guest mutation workers did not drain"))?;
        }
    }
    pub(crate) fn rotate(&self, destination: StorageShutdownContext) -> v1::ExpectedGuestIdentity {
        let mut current = lock(&self.identity);
        current.expected.machine_id = destination.machine_id.clone();
        current.expected.run_id = destination.run_id.clone();
        current.expected.agent_instance_id = uuid::Uuid::new_v4().to_string();
        current.shutdown = destination;
        let identity = current.expected.clone();
        self.lifecycle.send_modify(|status| {
            status.machine_id = identity.machine_id.clone();
            status.run_id = identity.run_id.clone();
            if let Some(reference) = status.freeze_ref.as_mut() {
                reference.machine_id = identity.machine_id.clone();
                reference.run_id = identity.run_id.clone();
            }
        });
        drop(current);
        self.retirement
            .send_modify(|epoch| *epoch = epoch.saturating_add(1));
        identity
    }
    pub(crate) fn project(&self, mut status: v1::AgentStatus) -> v1::AgentStatus {
        let identity = lock(&self.identity);
        if let Some(value) = status.identity.as_mut() {
            value.instance_id = Some(identity.expected.agent_instance_id.clone());
            value.boot_id = Some(identity.expected.boot_id.clone());
        }
        if let Some(report) = status.report.as_mut() {
            let lifecycle = self.lifecycle.borrow().clone();
            if !matches!(
                State::try_from(lifecycle.state),
                Ok(State::Running | State::Thawed)
            ) {
                report.state = Some(v1::AgentStatusState::Starting as i32);
                report.code = Some("WORKLOAD_NOT_READY".into());
            }
            report.lifecycle = Some(lifecycle);
        }
        status
    }
}

type Completion<T> = watch::Sender<Option<Result<T, Status>>>;
type CompletionReceiver<T> = watch::Receiver<Option<Result<T, Status>>>;
struct Coordinator {
    freeze: Option<(
        v1::FreezeWorkloadsRequest,
        Completion<v1::FreezeWorkloadsResponse>,
    )>,
    thaw: Option<(
        v1::ThawRequest,
        tokio::time::Instant,
        Completion<v1::ThawResponse>,
    )>,
    activation: Option<(v1::ActivateRequest, Completion<v1::ActivateResponse>)>,
    busy: bool,
}

impl Coordinator {
    fn activation_replay(
        &self,
        request: &v1::ActivateRequest,
    ) -> Result<Option<CompletionReceiver<v1::ActivateResponse>>, Status> {
        match &self.activation {
            Some((input, completion)) if input == request => Ok(Some(completion.subscribe())),
            Some(_) => Err(Status::already_exists(
                "activation attempt is already bound to different input",
            )),
            None => Ok(None),
        }
    }
}

pub(crate) struct Lifecycle {
    runtime: Arc<RuntimeContext>,
    controller: crate::freezer::WorkloadController,
    supervisor: crate::pid1::ProcessSupervisor,
    forwards: crate::forward::listen::GuestForwardServiceImpl,
    network: tokio::sync::Mutex<Option<crate::provision::network::AppliedNetwork>>,
    status: watch::Sender<v1::AgentStatus>,
    coordinator: Mutex<Coordinator>,
}

impl Lifecycle {
    pub(crate) fn new(
        runtime: Arc<RuntimeContext>,
        controller: crate::freezer::WorkloadController,
        supervisor: crate::pid1::ProcessSupervisor,
        forwards: crate::forward::listen::GuestForwardServiceImpl,
        status: watch::Sender<v1::AgentStatus>,
    ) -> Arc<Self> {
        runtime.lifecycle.send_modify(|status| {
            status.unsupported_reason = controller.unsupported_reason();
            status.workload_roots = controller.roots();
        });
        Arc::new(Self {
            runtime,
            controller,
            supervisor,
            forwards,
            network: tokio::sync::Mutex::new(None),
            status,
            coordinator: Mutex::new(Coordinator {
                freeze: None,
                thaw: None,
                activation: None,
                busy: false,
            }),
        })
    }
    pub(crate) async fn set_network(
        &self,
        network: Option<crate::provision::network::AppliedNetwork>,
    ) {
        *self.network.lock().await = network;
    }
    fn expected(&self, expected: Option<&v1::ExpectedGuestIdentity>) -> Result<(), Status> {
        let expected =
            expected.ok_or_else(|| Status::invalid_argument("expected identity required"))?;
        for id in [
            &expected.machine_id,
            &expected.run_id,
            &expected.agent_instance_id,
            &expected.boot_id,
        ] {
            validate_uuid(id)?;
        }
        if expected != &lock(&self.runtime.identity).expected {
            return Err(Status::failed_precondition(
                "guest runtime identity mismatch",
            ));
        }
        Ok(())
    }
    fn reference(&self, reference: Option<&v1::FreezeRef>) -> Result<v1::FreezeRef, Status> {
        let reference = reference.ok_or_else(|| Status::invalid_argument("freeze_ref required"))?;
        validate_ref(reference)?;
        let current = lock(&self.runtime.identity);
        if reference.machine_id != current.expected.machine_id
            || reference.run_id != current.expected.run_id
        {
            return Err(Status::failed_precondition(
                "freeze reference belongs to another run",
            ));
        }
        Ok(reference.clone())
    }
    fn publish(
        &self,
        state: State,
        reference: &v1::FreezeRef,
        observed: bool,
        failure: Option<String>,
        rollback: Option<bool>,
    ) {
        self.runtime.lifecycle.send_modify(|status| {
            status.state = state as i32;
            status.freeze_ref = Some(reference.clone());
            status.machine_id = reference.machine_id.clone();
            status.run_id = reference.run_id.clone();
            status.observed_frozen_roots = if observed {
                self.controller.roots()
            } else {
                Vec::new()
            };
            status.failure = failure;
            status.rollback_succeeded = rollback;
        });
    }
    pub(crate) async fn freeze(
        self: &Arc<Self>,
        request: v1::FreezeWorkloadsRequest,
    ) -> Result<v1::FreezeWorkloadsResponse, Status> {
        wait(self.begin_freeze(request)?).await
    }
    fn begin_freeze(
        self: &Arc<Self>,
        request: v1::FreezeWorkloadsRequest,
    ) -> Result<CompletionReceiver<v1::FreezeWorkloadsResponse>, Status> {
        let deadline = deadline(request.deadline_ms, 5000)?;
        let receiver = {
            let mut owner = lock(&self.coordinator);
            self.expected(request.expected.as_ref())?;
            let reference = self.reference(request.freeze_ref.as_ref())?;
            if let Some(reason) = self.controller.unsupported_reason() {
                return Err(Status::failed_precondition(reason));
            }
            if !lock(&self.runtime.admission).boot_ready
                || self
                    .supervisor
                    .shutdown_receiver()
                    .is_some_and(|receiver| *receiver.borrow())
            {
                return Err(Status::failed_precondition(
                    "guest cold provisioning is incomplete or shutdown is in progress",
                ));
            }
            let current = self.runtime.lifecycle.borrow().clone();
            if let Some((input, completion)) = &owner.freeze {
                if input.freeze_ref == request.freeze_ref {
                    if input != &request {
                        return Err(Status::already_exists("freeze retry inputs conflict"));
                    }
                    if current.state == State::Freezing as i32
                        || current.state == State::FreezeFailed as i32
                    {
                        return Ok(completion.subscribe());
                    }
                    if matches!(
                        State::try_from(current.state),
                        Ok(State::Frozen | State::ActivatedFrozen)
                    ) {
                        if !self.controller.is_frozen().map_err(internal)? {
                            return Err(Status::failed_precondition(
                                "cached freeze no longer matches kernel state",
                            ));
                        }
                        return Ok(completed(v1::FreezeWorkloadsResponse {
                            status: Some(current),
                        }));
                    }
                    return Err(Status::failed_precondition(
                        "completed freeze epoch cannot be reused; advance epoch",
                    ));
                }
            }
            // Activate explicitly transfers the inherited epoch to its destination.
            // A destination verification must still observe the real kernel barrier.
            if current.state == State::ActivatedFrozen as i32
                && current.freeze_ref.as_ref() == Some(&reference)
            {
                if !self.controller.is_frozen().map_err(internal)? {
                    return Err(Status::failed_precondition(
                        "activated workload root is no longer frozen",
                    ));
                }
                return Ok(completed(v1::FreezeWorkloadsResponse {
                    status: Some(current),
                }));
            }
            if owner.busy {
                return Err(Status::failed_precondition(
                    "guest lifecycle operation in progress",
                ));
            }
            if !matches!(
                State::try_from(current.state),
                Ok(State::Running
                    | State::Thawed
                    | State::Frozen
                    | State::ActivatedFrozen
                    | State::FreezeFailed)
            ) {
                return Err(Status::failed_precondition(
                    "guest lifecycle state refuses freeze",
                ));
            }
            validate_next_epoch(current.freeze_ref.as_ref(), &reference)?;
            self.runtime.close()?;
            if let Err(error) = self.controller.close_spawn_admission() {
                self.runtime.open();
                return Err(internal(error));
            }
            let (completion, receiver) = watch::channel(None);
            owner.busy = true;
            owner.freeze = Some((request.clone(), completion.clone()));
            owner.thaw = None;
            self.publish(State::Freezing, &reference, false, None, None);
            let lifecycle = self.clone();
            tokio::spawn(async move {
                let result = lifecycle.perform_freeze(&reference, deadline).await;
                let rollback = {
                    let mut owner = lock(&lifecycle.coordinator);
                    let rollback = owner.thaw.clone();
                    if rollback.is_none() {
                        owner.busy = false;
                    }
                    rollback
                };
                completion.send_replace(Some(result));
                if let Some((_request, rollback_deadline, completion)) = rollback {
                    let faulted =
                        lifecycle.runtime.lifecycle.borrow().state == State::Faulted as i32;
                    let result = if faulted {
                        Err(Status::failed_precondition("freeze rollback faulted"))
                    } else {
                        lifecycle.perform_thaw(&reference, rollback_deadline).await
                    };
                    lock(&lifecycle.coordinator).busy = false;
                    completion.send_replace(Some(result));
                }
            });
            receiver
        };
        Ok(receiver)
    }
    async fn perform_freeze(
        &self,
        reference: &v1::FreezeRef,
        deadline: tokio::time::Instant,
    ) -> Result<v1::FreezeWorkloadsResponse, Status> {
        let result = async {
            self.runtime.drain(deadline).await?;
            self.controller.freeze(deadline).await.map_err(internal)
        }
        .await;
        match result {
            Ok(()) => self.publish(State::Frozen, reference, true, None, None),
            Err(error) => {
                let observed = self.controller.is_frozen().unwrap_or(false);
                let rollback_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                let rollback = match self.controller.thaw(rollback_deadline).await {
                    Ok(()) => self.controller.open_spawn_admission(),
                    Err(error) => Err(error),
                };
                let succeeded = rollback.is_ok();
                if succeeded {
                    self.runtime.open();
                }
                let diagnostic = match rollback {
                    Ok(()) => error.to_string(),
                    Err(rollback) => format!("{error}; rollback failed: {rollback:#}"),
                };
                self.publish(
                    if succeeded {
                        State::FreezeFailed
                    } else {
                        State::Faulted
                    },
                    reference,
                    observed,
                    Some(diagnostic),
                    Some(succeeded),
                );
            }
        }
        Ok(v1::FreezeWorkloadsResponse {
            status: Some(self.runtime.lifecycle.borrow().clone()),
        })
    }
    pub(crate) async fn thaw(
        self: &Arc<Self>,
        request: v1::ThawRequest,
    ) -> Result<v1::ThawResponse, Status> {
        wait(self.begin_thaw(request)?).await
    }
    fn begin_thaw(
        self: &Arc<Self>,
        request: v1::ThawRequest,
    ) -> Result<CompletionReceiver<v1::ThawResponse>, Status> {
        let deadline = deadline(request.deadline_ms, 5000)?;
        let receiver = {
            let mut owner = lock(&self.coordinator);
            self.expected(request.expected.as_ref())?;
            let reference = self.reference(request.freeze_ref.as_ref())?;
            let current = self.runtime.lifecycle.borrow().clone();
            if current.freeze_ref.as_ref() != Some(&reference) {
                return Err(Status::failed_precondition("stale thaw reference"));
            }
            if let Some((input, _, completion)) = &owner.thaw {
                if input == &request {
                    return Ok(completion.subscribe());
                }
                return Err(Status::already_exists("thaw retry inputs conflict"));
            }
            if self
                .supervisor
                .shutdown_receiver()
                .is_some_and(|receiver| *receiver.borrow())
            {
                return Err(Status::failed_precondition("guest shutdown is in progress"));
            }
            if owner.busy && request.rollback && current.state == State::Freezing as i32 {
                let (completion, receiver) = watch::channel(None);
                owner.thaw = Some((request, deadline, completion));
                return Ok(receiver);
            }
            if owner.busy {
                return Err(Status::failed_precondition(
                    "guest lifecycle operation in progress",
                ));
            }
            let thaw_allowed = match State::try_from(current.state) {
                Ok(State::Frozen | State::ActivatedFrozen) => true,
                Ok(State::FreezeFailed) => request.rollback,
                _ => false,
            };
            if !thaw_allowed {
                return Err(Status::failed_precondition(
                    "guest lifecycle state refuses thaw",
                ));
            }
            let (completion, receiver) = watch::channel(None);
            owner.busy = true;
            owner.thaw = Some((request.clone(), deadline, completion.clone()));
            self.publish(State::Thawing, &reference, true, None, None);
            let lifecycle = self.clone();
            tokio::spawn(async move {
                let response = lifecycle.perform_thaw(&reference, deadline).await;
                lock(&lifecycle.coordinator).busy = false;
                completion.send_replace(Some(response));
            });
            receiver
        };
        Ok(receiver)
    }
    async fn perform_thaw(
        &self,
        reference: &v1::FreezeRef,
        deadline: tokio::time::Instant,
    ) -> Result<v1::ThawResponse, Status> {
        self.publish(State::Thawing, reference, true, None, None);
        let result = match self.controller.thaw(deadline).await {
            Ok(()) => self.controller.open_spawn_admission(),
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => {
                self.runtime.open();
                self.publish(State::Thawed, reference, false, None, None);
                Ok(v1::ThawResponse {
                    status: Some(self.runtime.lifecycle.borrow().clone()),
                })
            }
            Err(error) => {
                self.publish(
                    State::Faulted,
                    reference,
                    false,
                    Some(error.to_string()),
                    None,
                );
                Err(internal(error))
            }
        }
    }
    pub(crate) async fn activate(
        self: &Arc<Self>,
        request: v1::ActivateRequest,
    ) -> Result<v1::ActivateResponse, Status> {
        wait(self.begin_activate(request)?).await
    }
    fn begin_activate(
        self: &Arc<Self>,
        request: v1::ActivateRequest,
    ) -> Result<CompletionReceiver<v1::ActivateResponse>, Status> {
        // Replay is bound to the original source request, even after rotation.
        // A changed payload is a conflict, not a fresh validation/effect attempt.
        if let Some(replay) = lock(&self.coordinator).activation_replay(&request)? {
            return Ok(replay);
        }
        let deadline = deadline(request.deadline_ms, 30000)?;
        // Validate pure input before admitting any side effects.
        let (network, shutdown) = validate_activation(&request)?;
        crate::forward::listen::validate_activation_listeners(&request.listeners)?;
        let receiver = {
            let mut owner = lock(&self.coordinator);
            if let Some(replay) = owner.activation_replay(&request)? {
                return Ok(replay);
            }
            if !lock(&self.runtime.admission).boot_ready
                || self
                    .supervisor
                    .shutdown_receiver()
                    .is_some_and(|receiver| *receiver.borrow())
            {
                return Err(Status::failed_precondition(
                    "guest cold provisioning is incomplete or shutdown is in progress",
                ));
            }
            self.expected(request.expected.as_ref())?;
            let reference = self.reference(request.freeze_ref.as_ref())?;
            let current = self.runtime.lifecycle.borrow().clone();
            if owner.busy
                || current.state != State::Frozen as i32
                || current.freeze_ref.as_ref() != Some(&reference)
            {
                return Err(Status::failed_precondition(
                    "activation requires exact settled frozen epoch",
                ));
            }
            if !self.controller.is_frozen().map_err(internal)? {
                return Err(Status::failed_precondition(
                    "activation workload root is not frozen",
                ));
            }
            {
                let retained = self
                    .network
                    .try_lock()
                    .map_err(|_| Status::failed_precondition("network configuration is busy"))?;
                match (retained.as_ref(), network.as_ref()) {
                    (Some(applied), Some(network)) => applied
                        .validate_activation(network)
                        .map_err(|error| Status::failed_precondition(error.to_string()))?,
                    (None, None) => {}
                    _ => {
                        return Err(Status::failed_precondition(
                            "activation network attachment topology differs from capture",
                        ))
                    }
                }
            }
            self.runtime.close()?;
            let (completion, receiver) = watch::channel(None);
            owner.busy = true;
            owner.activation = Some((request.clone(), completion.clone()));
            self.publish(State::Activating, &reference, true, None, None);
            self.runtime
                .lifecycle
                .send_modify(|status| status.activation_id = Some(request.activation_id.clone()));
            let lifecycle = self.clone();
            tokio::spawn(async move {
                let result = lifecycle
                    .perform_activation(&request, network, shutdown, deadline)
                    .await;
                if let Err(error) = &result {
                    let reference = lifecycle.runtime.lifecycle.borrow().freeze_ref.clone();
                    if let Some(reference) = reference {
                        lifecycle.publish(
                            State::ActivationFailed,
                            &reference,
                            true,
                            Some(error.to_string()),
                            None,
                        );
                    }
                }
                lock(&lifecycle.coordinator).busy = false;
                completion.send_replace(Some(result));
            });
            receiver
        };
        Ok(receiver)
    }
    async fn perform_activation(
        &self,
        request: &v1::ActivateRequest,
        network: Option<agent_spec::NetworkConfig>,
        shutdown: StorageShutdownContext,
        deadline: tokio::time::Instant,
    ) -> Result<v1::ActivateResponse, Status> {
        let result = tokio::time::timeout_at(deadline, async {
            self.runtime.drain(deadline).await?;
            let mut retained = self.network.lock().await;
            self.forwards.reset_for_activation().await?;
            let identity = self.runtime.rotate(shutdown);
            let mut reference = request
                .freeze_ref
                .clone()
                .ok_or_else(|| Status::invalid_argument("freeze_ref required"))?;
            reference.machine_id = identity.machine_id.clone();
            reference.run_id = identity.run_id.clone();
            self.publish(State::Activating, &reference, true, None, None);
            self.runtime.drain_sessions(deadline).await?;
            crate::clock::activate_realtime(request.host_time.as_ref()).map_err(internal)?;
            if let (Some(applied), Some(network)) = (retained.as_ref(), network.as_ref()) {
                let replacement = crate::provision::network::activate_network(applied, network)
                    .await
                    .map_err(internal)?;
                *retained = Some(replacement);
            }
            drop(retained);
            let listeners = self
                .forwards
                .register_activation(&request.listeners)
                .await?;
            if let Some(hook) = &request.hook {
                self.run_hook(hook, deadline).await?;
            }
            if !self.controller.is_frozen().map_err(internal)? {
                return Err(Status::failed_precondition(
                    "workload freeze lost during activation",
                ));
            }
            Ok(v1::ActivateResponse {
                identity: Some(identity),
                freeze_ref: Some(reference),
                listeners,
                status: None,
            })
        })
        .await;
        // Activation replaces kernel-owned identity (managed addresses), including partial
        // destination state left by a failed or cancelled attempt. Observe it once here so
        // GetStatus/WatchStatus stop serving the cold-boot source addresses.
        crate::rpc::refresh_system(&self.status);
        // Every terminal path drains hook descendants, including timeout cancellation.
        let cleanup = self
            .controller
            .kill_activation(tokio::time::Instant::now() + Duration::from_secs(5))
            .await;
        cleanup.map_err(internal)?;
        let mut response =
            result.map_err(|_| Status::deadline_exceeded("activation deadline exceeded"))??;
        let reference = response
            .freeze_ref
            .as_ref()
            .ok_or_else(|| Status::internal("activation result lost freeze reference"))?;
        self.publish(State::ActivatedFrozen, reference, true, None, None);
        response.status = Some(self.runtime.lifecycle.borrow().clone());
        Ok(response)
    }
    async fn run_hook(
        &self,
        hook: &v1::ActivationHook,
        activation_deadline: tokio::time::Instant,
    ) -> Result<(), Status> {
        let (program, args) = hook
            .argv
            .split_first()
            .ok_or_else(|| Status::invalid_argument("hook argv required"))?;
        let mut command = std::process::Command::new(program);
        command
            .args(args)
            .env_clear()
            .current_dir(&hook.working_directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for variable in &hook.environment {
            command.env(&variable.name, &variable.value);
        }
        let (mut child, guard) = self
            .supervisor
            .spawn_activation_child(&mut command, "activation hook")
            .map_err(internal)?;
        let deadline = activation_deadline.min(
            tokio::time::Instant::now()
                + Duration::from_millis(u64::from(hook.timeout_ms.unwrap_or(30000))),
        );
        let mut outcome = None;
        while tokio::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait().map_err(internal)? {
                outcome = Some(status);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let background =
            outcome.is_some() && self.controller.activation_populated().map_err(internal)?;
        self.controller
            .kill_activation(tokio::time::Instant::now() + Duration::from_secs(5))
            .await
            .map_err(internal)?;
        // ChildGuard cooperates with PID1 reaping; wait is safe if it was already reaped.
        let _ = child.wait();
        drop(guard);
        if background {
            return Err(Status::failed_precondition(
                "activation hook left background descendants",
            ));
        }
        match outcome {
            Some(status) if status.success() => Ok(()),
            Some(status) => Err(Status::failed_precondition(format!(
                "activation hook exited {status}"
            ))),
            None => Err(Status::deadline_exceeded(
                "activation hook deadline exceeded",
            )),
        }
    }
}

fn internal(error: impl std::fmt::Display) -> Status {
    Status::internal(error.to_string())
}
fn validate_uuid(id: &str) -> Result<(), Status> {
    protocol::shutdown::validate_uuid(id).map_err(Status::invalid_argument)
}
fn validate_ref(reference: &v1::FreezeRef) -> Result<(), Status> {
    for id in [
        &reference.machine_id,
        &reference.run_id,
        &reference.operation_id,
    ] {
        validate_uuid(id)?;
    }
    if reference.freeze_epoch.is_none_or(|epoch| epoch == 0) {
        return Err(Status::invalid_argument("nonzero freeze_epoch required"));
    }
    Ok(())
}
fn validate_next_epoch(
    current: Option<&v1::FreezeRef>,
    requested: &v1::FreezeRef,
) -> Result<(), Status> {
    let previous = current
        .and_then(|reference| reference.freeze_epoch)
        .unwrap_or(0);
    let next = previous
        .checked_add(1)
        .ok_or_else(|| Status::failed_precondition("freeze epoch exhausted"))?;
    if requested.freeze_epoch != Some(next) {
        return Err(Status::failed_precondition(
            "freeze requires exact next epoch",
        ));
    }
    Ok(())
}
fn deadline(value: Option<u32>, max: u32) -> Result<tokio::time::Instant, Status> {
    let value = value
        .filter(|value| (1..=max).contains(value))
        .ok_or_else(|| Status::invalid_argument(format!("deadline_ms required in 1..={max}")))?;
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
fn validate_activation(
    request: &v1::ActivateRequest,
) -> Result<(Option<agent_spec::NetworkConfig>, StorageShutdownContext), Status> {
    validate_uuid(&request.activation_id)?;
    validate_uuid(&request.destination_machine_id)?;
    validate_uuid(&request.destination_run_id)?;
    let expected = request
        .expected
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("expected identity required"))?;
    if request.destination_run_id == expected.run_id
        || request.destination_machine_id == expected.machine_id
    {
        return Err(Status::invalid_argument(
            "activation requires a new machine and run",
        ));
    }
    crate::clock::validate_host_time(request.host_time.as_ref())
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let target = request.network.as_ref().map(validate_network).transpose()?;
    let context = request
        .shutdown
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("destination shutdown context required"))?;
    let manifest = protocol::shutdown::manifest_from_json(&context.manifest_json)
        .map_err(Status::invalid_argument)?;
    let shutdown = StorageShutdownContext {
        version: 1,
        machine_id: request.destination_machine_id.clone(),
        run_id: request.destination_run_id.clone(),
        manifest,
    };
    shutdown.validate().map_err(Status::invalid_argument)?;
    if let Some(hook) = &request.hook {
        validate_hook(hook)?;
    }
    Ok((target, shutdown))
}
fn validate_network(network: &v1::ActivationNetwork) -> Result<agent_spec::NetworkConfig, Status> {
    let parse_ip = |value: &str| {
        value
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| Status::invalid_argument("invalid destination IPv4 address"))
    };
    let target = agent_spec::NetworkConfig {
        interfaces: vec![agent_spec::NetworkInterfaceConfig {
            mac_address: network.mac.clone(),
            ipv4: agent_spec::NetworkIpv4Config {
                address: parse_ip(&network.ipv4)?,
                prefix_length: u8::try_from(network.prefix_length)
                    .map_err(|_| Status::invalid_argument("invalid prefix length"))?,
                gateway: parse_ip(&network.gateway)?,
            },
            dns: agent_spec::NetworkDnsConfig {
                servers: network
                    .dns_servers
                    .iter()
                    .map(|value| {
                        value
                            .parse::<std::net::IpAddr>()
                            .map_err(|_| Status::invalid_argument("invalid DNS server"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                search: network.dns_search.clone(),
            },
        }],
    };
    target
        .validate()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(target)
}
fn validate_hook(hook: &v1::ActivationHook) -> Result<(), Status> {
    if hook.argv.is_empty()
        || hook.argv.len() > 128
        || hook
            .argv
            .iter()
            .any(|arg| arg.contains('\0') || arg.len() > 32768)
        || hook.argv.first().is_none_or(|arg| !arg.starts_with('/'))
        || !hook.working_directory.starts_with('/')
        || hook.working_directory.contains('\0')
        || hook.environment.len() > 128
        || hook
            .timeout_ms
            .is_none_or(|value| !(1..=30000).contains(&value))
    {
        return Err(Status::invalid_argument("invalid bounded activation hook"));
    }
    let mut names = std::collections::HashSet::new();
    for value in &hook.environment {
        if !crate::ssh::agent::valid_environment_name(&value.name)
            || value.value.contains('\0')
            || value.value.len() > 32768
            || !names.insert(&value.name)
        {
            return Err(Status::invalid_argument(
                "invalid or duplicate hook environment",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::lifecycle::{validate_hook, validate_next_epoch, validate_ref, RuntimeContext};
    use protocol::v1;

    fn reference(epoch: u64) -> v1::FreezeRef {
        v1::FreezeRef {
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            freeze_epoch: Some(epoch),
        }
    }
    #[test]
    fn epoch_requires_exact_successor_and_never_wraps() {
        assert!(validate_ref(&reference(0)).is_err());
        assert!(validate_next_epoch(None, &reference(1)).is_ok());
        assert!(validate_next_epoch(Some(&reference(1)), &reference(1)).is_err());
        assert!(validate_next_epoch(Some(&reference(1)), &reference(2)).is_ok());
        assert!(validate_next_epoch(Some(&reference(u64::MAX)), &reference(1)).is_err());
    }
    #[tokio::test]
    async fn reversible_admission_drains_real_owned_leases() {
        let runtime = RuntimeContext::for_tests();
        let lease = runtime.admit_mutation().unwrap();
        runtime.close().unwrap();
        assert!(runtime.admit_mutation().is_err());
        assert!(runtime.drain(tokio::time::Instant::now()).await.is_err());
        drop(lease);
        runtime
            .drain(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap();
        runtime.open();
        assert!(runtime.admit_mutation().is_ok());
    }
    #[test]
    fn identity_rotation_preserves_boot_and_rebinds_shutdown_atomically() {
        let runtime = RuntimeContext::for_tests();
        let old = runtime.identity();
        let mut destination = old.shutdown.clone();
        destination.machine_id = uuid::Uuid::new_v4().to_string();
        destination.run_id = uuid::Uuid::new_v4().to_string();
        let new = runtime.rotate(destination.clone());
        assert_eq!(new.boot_id, old.expected.boot_id);
        assert_ne!(new.agent_instance_id, old.expected.agent_instance_id);
        assert_eq!(runtime.identity().shutdown, destination);
        assert_eq!(runtime.identity().expected, new);
    }
    #[test]
    fn shutdown_and_freeze_admission_are_mutually_exclusive() {
        let runtime = RuntimeContext::for_tests();
        runtime.admit_shutdown().unwrap();
        assert!(runtime.close().is_err());
        runtime.cancel_shutdown_admission();
        runtime.close().unwrap();
        assert!(runtime.admit_shutdown().is_err());
    }
    #[test]
    fn hook_rejects_unbounded_and_implicit_shell_inputs() {
        let mut hook = v1::ActivationHook {
            argv: vec!["relative".into()],
            working_directory: "/".into(),
            timeout_ms: Some(100),
            ..Default::default()
        };
        assert!(validate_hook(&hook).is_err());
        hook.argv[0] = "/bin/true".into();
        assert!(validate_hook(&hook).is_ok());
        hook.environment = vec![
            v1::EnvironmentVariable {
                name: "X".into(),
                value: "1".into()
            };
            2
        ];
        assert!(validate_hook(&hook).is_err());
    }

    #[tokio::test]
    async fn activation_replay_joins_and_retains_exact_terminal_result() {
        let request = v1::ActivateRequest {
            activation_id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let (completion, _) = tokio::sync::watch::channel(None);
        let coordinator = crate::lifecycle::Coordinator {
            freeze: None,
            thaw: None,
            activation: Some((request.clone(), completion.clone())),
            busy: true,
        };
        let first = coordinator.activation_replay(&request).unwrap().unwrap();
        let duplicate = coordinator.activation_replay(&request).unwrap().unwrap();
        drop(first);
        let result = v1::ActivateResponse {
            identity: Some(v1::ExpectedGuestIdentity {
                agent_instance_id: uuid::Uuid::new_v4().to_string(),
                ..Default::default()
            }),
            listeners: vec![v1::ActivationListenerBound {
                name: "selected".into(),
                bound: Some(v1::ListenerBound {
                    address: "tcp:127.0.0.1:1234".into(),
                }),
            }],
            ..Default::default()
        };
        completion.send_replace(Some(Ok(result.clone())));
        assert_eq!(crate::lifecycle::wait(duplicate).await.unwrap(), result);
        assert_eq!(
            crate::lifecycle::wait(coordinator.activation_replay(&request).unwrap().unwrap())
                .await
                .unwrap(),
            result
        );
        let mut conflict = request.clone();
        conflict.hook = Some(v1::ActivationHook::default());
        assert!(coordinator.activation_replay(&conflict).is_err());
        let (failed, _) = tokio::sync::watch::channel(Some(Err(
            tonic::Status::failed_precondition("hook failed"),
        )));
        let coordinator = crate::lifecycle::Coordinator {
            freeze: None,
            thaw: None,
            activation: Some((request.clone(), failed)),
            busy: false,
        };
        assert_eq!(
            crate::lifecycle::wait(coordinator.activation_replay(&request).unwrap().unwrap())
                .await
                .unwrap_err()
                .message(),
            "hook failed"
        );
    }

    #[tokio::test]
    async fn session_retirement_counts_actual_cloned_workers() {
        let runtime = RuntimeContext::for_tests();
        let mut retirement = runtime.retirement();
        let session = runtime.admit_session().unwrap();
        let worker = session.clone();
        runtime.close().unwrap();
        assert!(runtime.admit_session().is_err());
        let destination = runtime.identity().shutdown;
        runtime.rotate(destination);
        retirement.changed().await.unwrap();
        drop(session);
        assert!(runtime
            .drain_sessions(tokio::time::Instant::now())
            .await
            .is_err());
        drop(worker);
        runtime
            .drain_sessions(tokio::time::Instant::now() + std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }
}

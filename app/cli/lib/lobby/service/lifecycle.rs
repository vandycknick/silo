use crate::daemon::control::lobby::categorize;
use crate::lobby::{
    caller::Caller,
    failure::{Code, Failure, Outcome},
    identity::{Action, Peer},
    jobs::{Completion, Operation, Progress},
    service::{
        create::has_forwards,
        documents::{valid_document_name, DocumentKind, POLICY_LABEL},
        vm, Service,
    },
};
use silod_spec::daemon::v1 as w;

#[derive(Clone, Default)]
pub(crate) struct StopRequest {
    pub(crate) force: bool,
    pub(crate) timeout: chrono::TimeDelta,
}
#[derive(Clone, Default)]
pub(crate) struct RemoveRequest {
    pub(crate) force: bool,
}
pub(crate) struct RemovalTarget {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) running: bool,
}
#[derive(Clone, Default)]
pub(crate) struct SetRequest {
    pub(crate) name: Option<String>,
    pub(crate) cpus: Option<u8>,
    pub(crate) memory: Option<u64>,
    pub(crate) disk: Option<u64>,
    pub(crate) policy_ref: Option<String>,
    pub(crate) clear_policy: bool,
}
#[derive(Clone)]
enum Mutation {
    Start,
    Stop(StopRequest),
    Restart,
    Remove(RemoveRequest),
    Set(SetRequest),
}
impl Mutation {
    fn kind(&self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop(_) => "stop",
            Self::Restart => "restart",
            Self::Remove(_) => "remove",
            Self::Set(_) => "set",
        }
    }
    fn action(&self) -> Action {
        match self {
            Self::Start => Action::Start,
            Self::Stop(_) => Action::Stop,
            Self::Restart => Action::Restart,
            Self::Remove(_) => Action::Delete,
            Self::Set(_) => Action::Update,
        }
    }
}
impl Service {
    pub(crate) async fn reauthorize(
        &self,
        caller: &Caller,
        action: Action,
        machine: &w::MachineSnapshot,
    ) -> Outcome<()> {
        let peer = caller.fresh().await?;
        self.inspect_for(&peer, &machine.id, action).await?;
        Ok(())
    }
    pub(crate) async fn wait_ready(&self, id: &str, run: &str) -> Outcome<()> {
        let ready = self
            .management()
            .wait_ready(
                id,
                run,
                prost_types::Duration {
                    seconds: 120,
                    nanos: 0,
                },
            )
            .await
            .map_err(|status| categorize(&status))?;
        if ready.outcome == w::ReadinessOutcome::Ready as i32 {
            Ok(())
        } else {
            Err(Failure::new(
                Code::OperationFailed,
                "guest did not become ready; inspect VM state",
            ))
        }
    }
    pub(crate) async fn preflight_remove(
        &self,
        caller: &Caller,
        reference: &str,
        force: bool,
    ) -> Outcome<RemovalTarget> {
        let peer = caller.fresh().await?;
        let machine = self.inspect_for(&peer, reference, Action::Delete).await?;
        let running = vm::state(&machine) != "stopped";
        if running {
            if !force {
                return Err(running_error());
            }
            self.authorize(&peer, Action::Stop, Some(&machine))?;
        }
        Ok(RemovalTarget {
            id: machine.id,
            name: machine.name,
            running,
        })
    }
    async fn mutation(
        &self,
        caller: &Caller,
        reference: &str,
        mutation: Mutation,
    ) -> Outcome<Operation> {
        let action = mutation.action();
        let kind = mutation.kind();
        let machine = self.inspect_for(&caller.peer, reference, action).await?;
        if self.admission.lock().names.contains_key(&machine.name) {
            return Err(Failure::new(
                Code::Conflict,
                "VM bootstrap setup is still in progress",
            ));
        }
        let service = self.clone();
        let caller = caller.clone();
        let id = machine.id.clone();
        self.jobs().submit_result(kind, machine.id.clone(), vm::owner(&machine)?, move |cancel, progress| async move {
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Failure::new(Code::Cancelled, "operation cancelled")),
                result = async {
                    let peer = caller.fresh().await?;
                    let machine = service.inspect_for(&peer, &id, action).await?;
                    progress(format!("{kind} {}", machine.name));
                    service.run_mutation(&caller, &peer, &machine, &mutation, &progress).await?;
                    let view = if kind == "set" { vm::project(&service.management().inspect(&id).await.map_err(|status| categorize(&status))?)? } else { vm::project(&machine)? };
                    let mut completion = Completion { vm_id: id.clone(), name: view.name, image: view.image, user: view.default_user, node_state: "none".into(), running: matches!(kind, "start" | "restart"), ..Default::default() };
                    if completion.running { service.complete_node(&id, &mut completion, &progress).await; }
                    Ok(Some(completion))
                } => result,
            }
        }, || {})
    }
    async fn run_mutation(
        &self,
        caller: &Caller,
        peer: &Peer,
        machine: &w::MachineSnapshot,
        mutation: &Mutation,
        progress: &Progress,
    ) -> Outcome<()> {
        let action = mutation.action();
        match mutation {
            Mutation::Start | Mutation::Restart => {
                let mut machine = machine.clone();
                if matches!(mutation, Mutation::Restart)
                    && vm::state(&machine) != "stopped"
                    && !(vm::state(&machine) == "error" && machine.run_id.is_none())
                {
                    let run = machine.run_id.clone().ok_or_else(|| {
                        Failure::new(Code::Conflict, "VM running generation unavailable")
                    })?;
                    progress(format!("stopping {}", machine.name));
                    self.reauthorize(caller, action, &machine).await?;
                    machine = self
                        .management()
                        .stop(&machine.id, Some(run), false, None)
                        .await
                        .map_err(|status| categorize(&status))?;
                }
                self.prepare_node(caller, action, &machine).await?;
                self.reauthorize(caller, action, &machine).await?;
                progress(format!("starting {}", machine.name));
                let start = self
                    .management()
                    .start(&machine.id)
                    .await
                    .map_err(|status| categorize(&status))?;
                progress(format!("preparing {}", machine.name));
                self.wait_ready(&machine.id, &start.run_id).await
            }
            Mutation::Stop(request) => {
                if vm::state(machine) == "stopped"
                    || (vm::state(machine) == "error" && machine.run_id.is_none())
                {
                    return Ok(());
                }
                let run = machine
                    .run_id
                    .clone()
                    .ok_or_else(|| Failure::new(Code::Conflict, "VM is not running"))?;
                self.reauthorize(caller, action, machine).await?;
                let timeout = (request.timeout != chrono::TimeDelta::zero())
                    .then(|| duration(request.timeout));
                self.management()
                    .stop(&machine.id, Some(run), request.force, timeout)
                    .await
                    .map_err(|status| categorize(&status))?;
                Ok(())
            }
            Mutation::Remove(request) => {
                if vm::state(machine) != "stopped" {
                    if !request.force {
                        return Err(running_error());
                    }
                    if machine.run_id.is_none() && vm::state(machine) != "error" {
                        return Err(Failure::new(
                            Code::Conflict,
                            "VM run identity unavailable; inspect VM state",
                        ));
                    }
                    self.authorize(peer, Action::Stop, Some(machine))?;
                    self.reauthorize(caller, Action::Delete, machine).await?;
                    self.reauthorize(caller, Action::Stop, machine).await?;
                    if let Some(run) = &machine.run_id {
                        self.management()
                            .stop(
                                &machine.id,
                                Some(run.clone()),
                                true,
                                Some(prost_types::Duration {
                                    seconds: 10,
                                    nanos: 0,
                                }),
                            )
                            .await
                            .map_err(|status| categorize(&status))?;
                    }
                }
                self.reauthorize(caller, Action::Delete, machine).await?;
                if let Some(run) = &machine.run_id {
                    self.management()
                        .remove_after_run(&machine.id, run)
                        .await
                        .map_err(|status| categorize(&status))
                } else {
                    self.management()
                        .remove(&machine.id)
                        .await
                        .map_err(|status| categorize(&status))
                }
            }
            Mutation::Set(request) => self.apply_set(caller, peer, machine, request).await,
        }
    }
    pub(crate) async fn start(&self, caller: &Caller, reference: &str) -> Outcome<Operation> {
        self.mutation(caller, reference, Mutation::Start).await
    }
    pub(crate) async fn stop(
        &self,
        caller: &Caller,
        reference: &str,
        request: StopRequest,
    ) -> Outcome<Operation> {
        if request.timeout < chrono::TimeDelta::zero()
            || request.timeout > chrono::TimeDelta::minutes(1)
        {
            return Err(Failure::new(Code::Usage, "stop timeout must be 0..1m"));
        }
        self.mutation(caller, reference, Mutation::Stop(request))
            .await
    }
    pub(crate) async fn restart(&self, caller: &Caller, reference: &str) -> Outcome<Operation> {
        self.mutation(caller, reference, Mutation::Restart).await
    }
    pub(crate) async fn remove(
        &self,
        caller: &Caller,
        reference: &str,
        request: RemoveRequest,
    ) -> Outcome<Operation> {
        self.mutation(caller, reference, Mutation::Remove(request))
            .await
    }
    pub(crate) async fn set(
        &self,
        caller: &Caller,
        reference: &str,
        request: SetRequest,
    ) -> Outcome<Operation> {
        if request.name.is_none()
            && request.cpus.is_none()
            && request.memory.is_none()
            && request.disk.is_none()
            && request.policy_ref.is_none()
            && !request.clear_policy
        {
            return Err(Failure::new(Code::Usage, "set requires a setting"));
        }
        if request
            .name
            .as_ref()
            .is_some_and(|name| !valid_document_name(name))
        {
            return Err(Failure::new(Code::Usage, "invalid VM name"));
        }
        if request.clear_policy && request.policy_ref.is_some() {
            return Err(Failure::new(
                Code::Usage,
                "cannot set and clear policy together",
            ));
        }
        self.mutation(caller, reference, Mutation::Set(request))
            .await
    }
    async fn apply_set(
        &self,
        caller: &Caller,
        peer: &Peer,
        machine: &w::MachineSnapshot,
        request: &SetRequest,
    ) -> Outcome<()> {
        if vm::state(machine) != "stopped" {
            return Err(Failure::new(Code::Conflict, "set requires a stopped VM"));
        }
        let view = vm::project(machine)?;
        let disk = request.disk.unwrap_or(view.disk);
        if disk < view.disk {
            return Err(Failure::new(Code::Conflict, "disk may only grow"));
        }
        self.resources(
            peer,
            u64::from(request.cpus.unwrap_or(view.cpus)),
            request.memory.unwrap_or(view.memory),
            disk,
        )?;
        let _growth = if disk > view.disk {
            Some(
                self.reserve_disk_growth(&machine.id, disk - view.disk)
                    .await?,
            )
        } else {
            None
        };
        let mut update = w::MachineUpdate {
            cpus: request.cpus.map(u32::from),
            memory_bytes: request.memory,
            root_disk_size_bytes: request.disk,
            ..Default::default()
        };
        let mut labels = machine.labels.clone();
        let policy_change = request.policy_ref.is_some() || request.clear_policy;
        if policy_change {
            let mut policy = if let Some(reference) = &request.policy_ref {
                let document = self
                    .store
                    .read(DocumentKind::Policy, &view.owner, reference, self)
                    .await?;
                let policy = self.parse_policy(&document.content).await?;
                if has_forwards(&policy)? && machine.tailscale.is_none() {
                    return Err(Failure::new(
                        Code::Usage,
                        "policy forwards require a VM created with --tailscale",
                    ));
                }
                self.check_secrets(&policy).await?;
                Some(policy)
            } else {
                None
            };
            if let Some(node) = &machine.tailscale {
                policy = Some(
                    self.inject_node(
                        policy.as_ref(),
                        &node.hostname,
                        &view.owner,
                        &view.tags,
                        vm::label(machine, vm::MODE_LABEL),
                    )
                    .await?,
                );
            }
            update.policy = Some(w::PolicyUpdate {
                update: Some(match policy {
                    Some(policy) => w::policy_update::Update::Set(policy.canonical_json),
                    None => w::policy_update::Update::Clear(()),
                }),
            });
            if let Some(reference) = &request.policy_ref {
                labels.insert(POLICY_LABEL.into(), reference.clone());
            } else {
                labels.remove(POLICY_LABEL);
            }
            update.labels = Some(w::StringMap {
                values: labels.clone(),
            });
        }
        let _name_guard = if request
            .name
            .as_ref()
            .is_some_and(|name| *name != machine.name)
        {
            if machine.tailscale.is_some() {
                return Err(Failure::new(
                    Code::Conflict,
                    "cannot rename a VM with a tailscale declaration",
                ));
            }
            let guard = self.create_lock.lock().await;
            let name = request
                .name
                .as_ref()
                .ok_or_else(|| Failure::new(Code::Usage, "name required"))?;
            if !self
                .name_available(name, &self.visible_names().await?)
                .await?
            {
                return Err(Failure::new(
                    Code::Conflict,
                    "exact VM name is already taken",
                ));
            }
            labels.insert(vm::NAME_LABEL.into(), name.clone());
            update.name = Some(name.clone());
            update.labels = Some(w::StringMap { values: labels });
            Some(guard)
        } else {
            None
        };
        self.reauthorize(caller, Action::Update, machine).await?;
        self.management()
            .update(&machine.id, update)
            .await
            .map_err(|status| categorize(&status))?;
        Ok(())
    }
}
fn duration(value: chrono::TimeDelta) -> prost_types::Duration {
    prost_types::Duration {
        seconds: value.num_seconds(),
        nanos: value.subsec_nanos(),
    }
}
fn running_error() -> Failure {
    Failure::new(Code::Conflict, "VM is running; use --force")
}

#[cfg(test)]
mod tests {
    use crate::lobby::{
        identity::Action,
        service::{lifecycle::*, testing},
    };
    async fn finished(
        fixture: &testing::Fixture,
        caller: &Caller,
        operation: Operation,
    ) -> Operation {
        loop {
            let (operation, mut changed) = fixture
                .service
                .jobs()
                .observe(&caller.peer, &operation.id)
                .unwrap();
            if operation.finished.is_some() {
                return operation;
            }
            changed.changed().await.unwrap();
        }
    }
    #[tokio::test]
    async fn stopped_set_remove_and_growth_only_are_real_daemon_jobs() {
        let fixture = testing::fixture().await;
        let caller = testing::caller("user:1", &[Action::Read, Action::Update, Action::Delete]);
        let machine = testing::stopped_vm(&fixture, "before", "user:1").await;
        let operation = fixture
            .service
            .set(
                &caller,
                &machine.id,
                SetRequest {
                    name: Some("after".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert_eq!(
            fixture
                .service
                .show(&caller.peer, &machine.id)
                .await
                .unwrap()
                .name,
            "after"
        );
        let operation = fixture
            .service
            .set(
                &caller,
                &machine.id,
                SetRequest {
                    disk: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            finished(&fixture, &caller, operation)
                .await
                .error
                .unwrap()
                .exit,
            5
        );
        let target = fixture
            .service
            .preflight_remove(&caller, "after", false)
            .await
            .unwrap();
        assert!(!target.running);
        let operation = fixture
            .service
            .remove(&caller, &target.id, RemoveRequest::default())
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert_eq!(
            fixture
                .service
                .show(&caller.peer, &machine.id)
                .await
                .unwrap_err()
                .exit,
            3
        );
    }
    #[tokio::test]
    async fn queued_mutation_reauthorizes_before_native_write() {
        let fixture = testing::fixture().await;
        let caller = testing::caller("user:1", &[Action::Update]);
        let machine = testing::stopped_vm(&fixture, "unchanged", "user:1").await;
        let denied = crate::lobby::caller::Caller::new(
            caller.peer.clone(),
            std::sync::Arc::new(move || {
                let mut peer = caller.peer.clone();
                peer.permissions.actions.clear();
                Box::pin(async move { Ok(peer) })
            }),
        );
        let operation = fixture
            .service
            .set(
                &denied,
                &machine.id,
                SetRequest {
                    name: Some("must-not-change".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            finished(&fixture, &denied, operation)
                .await
                .error
                .unwrap()
                .exit,
            4
        );
        assert_eq!(
            fixture.management.inspect(&machine.id).await.unwrap().name,
            "unchanged"
        );
    }
    #[tokio::test]
    async fn stopped_policy_replace_clear_and_bindings_use_native_management() {
        let fixture = testing::fixture().await;
        let caller = testing::caller(
            "user:1",
            &[Action::Read, Action::Update, Action::TemplateManage],
        );
        let machine = testing::stopped_vm(&fixture, "policy-vm", "user:1").await;
        fixture
            .management
            .update(
                &machine.id,
                w::MachineUpdate {
                    network: Some(w::ResolvedNetwork {
                        attachment: Some(w::resolved_network::Attachment::Private(
                            w::PrivateNetwork::default(),
                        )),
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let raw = "endpoint \"https\" \"api\" { hosts = [\"api.example.test\"] }\n";
        fixture
            .service
            .documents(&caller, "policy", "create", "access", None, raw)
            .await
            .unwrap();
        let operation = fixture
            .service
            .set(
                &caller,
                &machine.id,
                SetRequest {
                    policy_ref: Some("access".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert_eq!(
            fixture
                .service
                .show(&caller.peer, &machine.id)
                .await
                .unwrap()
                .policy,
            "access"
        );
        let edited = fixture
            .service
            .documents(&caller, "policy", "edit", "access", None, raw)
            .await
            .unwrap();
        assert_eq!(edited[0].bound_vms.len(), 1);
        assert_eq!(edited[0].bound_vms[0].name, "policy-vm");
        let operation = fixture
            .service
            .set(
                &caller,
                &machine.id,
                SetRequest {
                    clear_policy: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert!(fixture
            .service
            .show(&caller.peer, &machine.id)
            .await
            .unwrap()
            .policy
            .is_empty());
    }
    #[tokio::test]
    async fn lifecycle_runtime_preserves_fences_across_restarts_and_removal() {
        if std::env::var_os("SILO_LOBBY_E2E_RUNTIME").is_none() {
            eprintln!("set SILO_LOBBY_E2E_RUNTIME to run lobby lifecycle guest tests");
            return;
        }
        #[cfg(target_os = "linux")]
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("/dev/kvm is required for lobby lifecycle guest tests");
            return;
        }
        let fixture = testing::fixture().await;
        let id = fixture.running_vm("user:1").await.unwrap();
        let caller = testing::caller(
            "user:1",
            &[
                Action::Read,
                Action::Start,
                Action::Stop,
                Action::Update,
                Action::Delete,
            ],
        );
        let first = fixture
            .management
            .inspect(&id)
            .await
            .unwrap()
            .run_id
            .unwrap();
        assert_eq!(
            fixture
                .service
                .preflight_remove(&caller, &id, false)
                .await
                .err()
                .unwrap()
                .exit,
            5
        );
        let operation = fixture
            .service
            .stop(&caller, &id, StopRequest::default())
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        let operation = fixture.service.start(&caller, &id).await.unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        let second = fixture
            .management
            .inspect(&id)
            .await
            .unwrap()
            .run_id
            .unwrap();
        assert_ne!(first, second);
        let operation = fixture.service.restart(&caller, &id).await.unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert_ne!(
            second,
            fixture
                .management
                .inspect(&id)
                .await
                .unwrap()
                .run_id
                .unwrap()
        );
        let operation = fixture
            .service
            .remove(&caller, &id, RemoveRequest { force: true })
            .await
            .unwrap();
        assert!(finished(&fixture, &caller, operation).await.error.is_none());
        assert_eq!(
            fixture
                .service
                .show(&caller.peer, &id)
                .await
                .unwrap_err()
                .exit,
            3
        );
    }
}

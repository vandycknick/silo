use std::sync::Mutex;

use protocol::v1::{
    GuestBootReport, InspectResponse, LifecycleState, PingResponse, ProvisionReport, StatusSource,
    StatusUpdate,
};
use tokio::sync::broadcast;

#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("vmmon state store lock is poisoned")]
    Poisoned,
}

#[derive(Debug)]
pub(crate) struct Bus<E>
where
    E: Clone + Send + 'static,
{
    tx: broadcast::Sender<E>,
}

impl<E> Bus<E>
where
    E: Clone + Send + 'static,
{
    pub(crate) fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<E> {
        self.tx.subscribe()
    }

    pub(crate) fn publish(&self, event: E) {
        let _ = self.tx.send(event);
    }
}

#[derive(Debug)]
pub(crate) struct Store<S, A, E>
where
    E: Clone + Send + 'static,
{
    state: Mutex<S>,
    reducer: fn(&S, &A) -> S,
    projector: fn(&A) -> Option<E>,
    bus: Bus<E>,
}

impl<S, A, E> Store<S, A, E>
where
    E: Clone + Send + 'static,
{
    pub(crate) fn new(
        initial_state: S,
        reducer: fn(&S, &A) -> S,
        projector: fn(&A) -> Option<E>,
        bus_capacity: usize,
    ) -> Self {
        Self {
            state: Mutex::new(initial_state),
            reducer,
            projector,
            bus: Bus::new(bus_capacity),
        }
    }

    pub(crate) fn dispatch(&self, action: A) -> Result<(), StoreError> {
        {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned)?;
            let next = (self.reducer)(&state, &action);
            *state = next;
        }

        if let Some(event) = (self.projector)(&action) {
            self.bus.publish(event);
        }

        Ok(())
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<E> {
        self.bus.subscribe()
    }

    pub(crate) fn snapshot(&self) -> Result<S, StoreError>
    where
        S: Clone,
    {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| StoreError::Poisoned)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct InstanceState {
    vm: LifecycleState,
    guest: LifecycleState,
    agent_required: bool,
    guest_message: String,
    boot_report: Option<GuestBootReport>,
    provision_report: Option<ProvisionReport>,
}

#[derive(Debug, Clone)]
pub(crate) enum Action {
    VmTransition {
        state: LifecycleState,
        message: String,
    },
    GuestTransition {
        state: LifecycleState,
        message: String,
        boot_report: Option<Box<GuestBootReport>>,
        provision_report: Option<Box<ProvisionReport>>,
    },
}

impl Action {
    pub(crate) fn vm_starting() -> Self {
        Self::VmTransition {
            state: LifecycleState::Starting,
            message: String::from("vm starting"),
        }
    }

    pub(crate) fn vm_running() -> Self {
        Self::VmTransition {
            state: LifecycleState::Running,
            message: String::from("vm running"),
        }
    }

    pub(crate) fn guest_starting() -> Self {
        Self::GuestTransition {
            state: LifecycleState::Starting,
            message: String::from("waiting for guest service registration"),
            boot_report: None,
            provision_report: None,
        }
    }

    pub(crate) fn guest_running() -> Self {
        Self::GuestTransition {
            state: LifecycleState::Running,
            message: String::from("guest service registered"),
            boot_report: None,
            provision_report: None,
        }
    }

    pub(crate) fn guest_running_with_reports(
        boot_report: GuestBootReport,
        provision_report: ProvisionReport,
    ) -> Self {
        Self::GuestTransition {
            state: LifecycleState::Running,
            message: String::from("guest service registered"),
            boot_report: Some(Box::new(boot_report)),
            provision_report: Some(Box::new(provision_report)),
        }
    }

    pub(crate) fn guest_error(message: impl Into<String>) -> Self {
        Self::GuestTransition {
            state: LifecycleState::Error,
            message: message.into(),
            boot_report: None,
            provision_report: None,
        }
    }

    pub(crate) fn guest_error_with_reports(
        message: impl Into<String>,
        boot_report: GuestBootReport,
        provision_report: ProvisionReport,
    ) -> Self {
        Self::GuestTransition {
            state: LifecycleState::Error,
            message: message.into(),
            boot_report: Some(Box::new(boot_report)),
            provision_report: Some(Box::new(provision_report)),
        }
    }
}

pub(crate) type InstanceStore = Store<InstanceState, Action, StatusUpdate>;

pub(crate) fn new_instance_store(agent_required: bool) -> InstanceStore {
    Store::new(
        InstanceState {
            agent_required,
            ..InstanceState::default()
        },
        reduce_instance_state,
        project_status_update,
        256,
    )
}

pub(crate) fn select_current_ping(state: &InstanceState) -> PingResponse {
    let ok = instance_ready(state);
    PingResponse {
        ok,
        message: status_summary(state),
    }
}

pub(crate) fn select_current_inspect(state: &InstanceState) -> InspectResponse {
    InspectResponse {
        vm_state: state.vm as i32,
        guest_state: state.guest as i32,
        ready: instance_ready(state),
        summary: status_summary(state),
        boot_report: state.boot_report.clone(),
        provision_report: state.provision_report.clone(),
    }
}

pub(crate) fn select_current_events(state: &InstanceState) -> Vec<StatusUpdate> {
    let mut events = Vec::new();

    if state.vm != LifecycleState::Unspecified {
        events.push(StatusUpdate::new(StatusSource::Vm, state.vm, String::new()));
    }

    if state.guest != LifecycleState::Unspecified {
        events.push(StatusUpdate::new(
            StatusSource::Guest,
            state.guest,
            state.guest_message.clone(),
        ));
    }

    events
}

pub(crate) fn guest_shell_ready(state: &InstanceState) -> bool {
    state.guest == LifecycleState::Running
}

fn reduce_instance_state(current: &InstanceState, action: &Action) -> InstanceState {
    let mut next = current.clone();

    match action {
        Action::VmTransition { state, .. } => {
            next.vm = *state;
        }
        Action::GuestTransition {
            state,
            message,
            boot_report,
            provision_report,
        } => {
            next.guest = *state;
            next.guest_message = message.clone();
            if let Some(boot_report) = boot_report {
                next.boot_report = Some((**boot_report).clone());
            }
            if let Some(provision_report) = provision_report {
                next.provision_report = Some((**provision_report).clone());
            }
        }
    }

    next
}

fn project_status_update(action: &Action) -> Option<StatusUpdate> {
    match action {
        Action::VmTransition { state, message } => {
            Some(StatusUpdate::new(StatusSource::Vm, *state, message.clone()))
        }
        Action::GuestTransition { state, message, .. } => Some(StatusUpdate::new(
            StatusSource::Guest,
            *state,
            message.clone(),
        )),
    }
}

fn status_summary(state: &InstanceState) -> String {
    if state.vm != LifecycleState::Running {
        return format!("vm not ready (vm_state={:?})", state.vm);
    }

    if !state.agent_required {
        return String::from("instance ready (guest agent not required)");
    }

    if state.guest == LifecycleState::Running {
        return String::from("instance ready");
    }

    state.guest_message.clone()
}

fn instance_ready(state: &InstanceState) -> bool {
    state.vm == LifecycleState::Running
        && (!state.agent_required || state.guest == LifecycleState::Running)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use protocol::v1::{
        GuestBootMode, GuestBootReport, LifecycleState, ProvisionOverallStatus, ProvisionReport,
    };
    use tokio::sync::broadcast::error::TryRecvError;

    use crate::state::{new_instance_store, select_current_inspect, Action, StoreError};

    #[test]
    fn dispatch_updates_state_before_publishing() {
        let store = new_instance_store(true);
        let mut rx = store.subscribe();

        store.dispatch(Action::guest_running()).unwrap();

        let snapshot = store.snapshot().unwrap();
        assert!(crate::state::guest_shell_ready(&snapshot));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn poisoned_store_does_not_publish_events() {
        let store = Arc::new(new_instance_store(true));
        let poisoned_store = store.clone();
        let mut rx = store.subscribe();

        let _ = std::thread::spawn(move || {
            let _guard = poisoned_store.state.lock().unwrap();
            panic!("poison state store lock");
        })
        .join();

        assert!(matches!(
            store.dispatch(Action::guest_running()),
            Err(StoreError::Poisoned)
        ));
        assert!(matches!(store.snapshot(), Err(StoreError::Poisoned)));
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn inspect_includes_latest_guest_reports() {
        let store = new_instance_store(true);
        let boot_report = GuestBootReport {
            mode: GuestBootMode::AgentPid1 as i32,
            requested_init: String::from("auto"),
            message: String::from("agent stayed PID1"),
            ..GuestBootReport::default()
        };
        let provision_report = ProvisionReport {
            status: ProvisionOverallStatus::Degraded as i32,
            message: String::from("one step failed"),
            ..ProvisionReport::default()
        };

        store.dispatch(Action::vm_running()).unwrap();
        store
            .dispatch(Action::guest_running_with_reports(
                boot_report.clone(),
                provision_report.clone(),
            ))
            .unwrap();

        let snapshot = store.snapshot().unwrap();
        let inspect = select_current_inspect(&snapshot);

        assert!(inspect.ready);
        assert!(crate::state::select_current_ping(&snapshot).ok);
        assert_eq!(inspect.boot_report, Some(boot_report));
        assert_eq!(inspect.provision_report, Some(provision_report));
    }

    #[test]
    fn failed_boot_report_sets_guest_error_without_ready() {
        let store = new_instance_store(true);
        let boot_report = GuestBootReport::default();
        let provision_report = ProvisionReport {
            status: ProvisionOverallStatus::FailedBoot as i32,
            message: String::from("fatal provisioner failed"),
            ..ProvisionReport::default()
        };

        store.dispatch(Action::vm_running()).unwrap();
        store
            .dispatch(Action::guest_error_with_reports(
                "fatal provisioner failed",
                boot_report.clone(),
                provision_report.clone(),
            ))
            .unwrap();

        let snapshot = store.snapshot().unwrap();
        let inspect = select_current_inspect(&snapshot);

        assert!(!inspect.ready);
        assert_eq!(
            LifecycleState::try_from(inspect.guest_state),
            Ok(LifecycleState::Error)
        );
        assert_eq!(inspect.summary, "fatal provisioner failed");
        assert_eq!(inspect.boot_report, Some(boot_report));
        assert_eq!(inspect.provision_report, Some(provision_report));
    }

    #[test]
    fn disabled_agent_is_ready_without_guest_registration() {
        let store = new_instance_store(false);
        store.dispatch(Action::vm_running()).unwrap();

        let snapshot = store.snapshot().unwrap();
        let inspect = select_current_inspect(&snapshot);

        assert!(inspect.ready);
        assert!(crate::state::select_current_ping(&snapshot).ok);
        assert_eq!(
            LifecycleState::try_from(inspect.guest_state),
            Ok(LifecycleState::Unspecified)
        );
        assert!(!crate::state::guest_shell_ready(&snapshot));
        assert_eq!(inspect.summary, "instance ready (guest agent not required)");
    }
}

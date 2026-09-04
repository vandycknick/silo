mod agent;
mod host_socket;
mod inbound;
mod outbound;
pub(crate) mod service;
mod task;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use forward_spec::{Address, Forward, ForwardShape, GuestHalf, Token};
use rand::RngExt;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::forward::host_socket::OwnedHostListener;
use crate::forward::task::OwnedTask;
use crate::virt::VirtualMachine;

const MAX_FORWARDS: usize = 128;
const MAX_SESSION_FORWARDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardScope {
    Machine,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardState {
    Pending,
    Active,
    Unsupported,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardStatusSnapshot {
    pub(crate) state: ForwardState,
    pub(crate) bound: Option<forward_spec::Endpoint>,
    pub(crate) active_connections: u32,
    pub(crate) refused_connections: u32,
    pub(crate) error: Option<protocol::v1::ErrorDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuestHalfAvailability {
    Unknown,
    Available(Option<crate::state::ReadyAgentIdentity>),
    Unsupported,
}

pub(crate) struct ForwardEntry {
    id: u64,
    pub(crate) scope: ForwardScope,
    pub(crate) spec: Forward,
    pub(crate) name: String,
    pub(crate) shape: ForwardShape,
    pub(crate) guest_half: GuestHalf,
    pub(crate) host_target: Option<Address>,
    pub(crate) token: Option<Token>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) availability: watch::Sender<GuestHalfAvailability>,
    pub(crate) status: watch::Sender<ForwardStatusSnapshot>,
    connection_generation: Mutex<Option<CancellationToken>>,
    listener: Mutex<Option<OwnedHostListener>>,
    vsock_listener: Mutex<Option<crate::virt::VsockListener>>,
    total_permit: Mutex<Option<OwnedSemaphorePermit>>,
    session_permit: Mutex<Option<OwnedSemaphorePermit>>,
    task: Mutex<Option<OwnedTask>>,
}

pub(crate) struct ForwardTable {
    entries: Mutex<Vec<Arc<ForwardEntry>>>,
    operation: tokio::sync::Mutex<()>,
    runtime_dir: PathBuf,
    mux_filename: Option<String>,
    machine: std::sync::OnceLock<VirtualMachine>,
    running: AtomicBool,
    next_id: AtomicU64,
    total_capacity: Arc<Semaphore>,
    session_capacity: Arc<Semaphore>,
    availability: watch::Sender<GuestHalfAvailability>,
    pub(crate) shutdown: CancellationToken,
    return_registered: AtomicBool,
    return_listener: Mutex<Option<crate::virt::VsockListener>>,
    return_task: Mutex<Option<OwnedTask>>,
    invalid_warning: Mutex<Option<std::time::Instant>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OpenError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    AddressInUse(String),
    #[error("{0}")]
    Limit(String),
    #[error("{0}")]
    NotRunning(String),
    #[error("{0}")]
    Unavailable(String),
}

impl ForwardTable {
    pub(crate) async fn prepare_machine(
        forwards: &[Forward],
        runtime_dir: &Path,
        mux_filename: Option<&str>,
    ) -> eyre::Result<Arc<Self>> {
        forward_spec::validate_forwards(forwards, mux_filename)
            .map_err(|error| eyre::eyre!("validate machine-scoped forwards: {error}"))?;
        if forwards.len() > MAX_FORWARDS {
            return Err(eyre::eyre!(
                "machine-scoped forwards exceed the limit of {MAX_FORWARDS}"
            ));
        }
        let shutdown = CancellationToken::new();
        let (availability, _) = watch::channel(GuestHalfAvailability::Unknown);
        let table = Arc::new(Self {
            entries: Mutex::new(Vec::with_capacity(forwards.len())),
            operation: tokio::sync::Mutex::new(()),
            runtime_dir: runtime_dir.to_path_buf(),
            mux_filename: mux_filename.map(str::to_owned),
            machine: std::sync::OnceLock::new(),
            running: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            total_capacity: Arc::new(Semaphore::new(MAX_FORWARDS - forwards.len())),
            session_capacity: Arc::new(Semaphore::new(MAX_SESSION_FORWARDS)),
            availability,
            shutdown,
            return_registered: AtomicBool::new(false),
            return_listener: Mutex::new(None),
            return_task: Mutex::new(None),
            invalid_warning: Mutex::new(None),
        });
        for spec in forwards {
            let entry = table
                .build_entry(spec.clone(), ForwardScope::Machine, None, None)
                .await
                .map_err(|error| eyre::eyre!(error.to_string()))?;
            table
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(entry);
        }
        Ok(table)
    }

    async fn build_entry(
        &self,
        spec: Forward,
        scope: ForwardScope,
        total_permit: Option<OwnedSemaphorePermit>,
        session_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<Arc<ForwardEntry>, OpenError> {
        let shape = spec
            .validate()
            .map_err(|error| OpenError::Invalid(error.to_string()))?;
        let name = spec.display_name();
        let guest_half = spec
            .guest_half()
            .map_err(|error| OpenError::Invalid(error.to_string()))?;
        let host_target = resolve_host_target(&spec, &self.runtime_dir)
            .map_err(|error| OpenError::Invalid(error.to_string()))?;
        let token = if shape == ForwardShape::OutboundAgent {
            let mut bytes = [0_u8; 16];
            rand::rng().fill(&mut bytes);
            Some(Token::new(bytes))
        } else {
            None
        };
        let listener = match shape {
            ForwardShape::InboundAgent | ForwardShape::InboundVsock => {
                let forward_spec::Endpoint::Host(address) = &spec.listen else {
                    return Err(OpenError::Invalid(
                        "validated inbound forward has no host listener".to_string(),
                    ));
                };
                Some(
                    OwnedHostListener::bind(address, spec.mode, &self.runtime_dir)
                        .await
                        .map_err(|error| bind_error(&name, &spec.listen, error))?,
                )
            }
            ForwardShape::OutboundAgent | ForwardShape::OutboundVsock => None,
        };
        let bound = listener.as_ref().map(OwnedHostListener::bound_endpoint);
        let initial_availability = match guest_half {
            GuestHalf::Vsock(_) if listener.is_some() => GuestHalfAvailability::Available(None),
            GuestHalf::Vsock(_) => GuestHalfAvailability::Unknown,
            GuestHalf::Agent(_) => self.availability.borrow().clone(),
        };
        let initial_state = match initial_availability {
            GuestHalfAvailability::Available(_) if shape == ForwardShape::InboundAgent => {
                ForwardState::Active
            }
            GuestHalfAvailability::Available(_) if shape == ForwardShape::InboundVsock => {
                ForwardState::Active
            }
            GuestHalfAvailability::Unsupported => ForwardState::Unsupported,
            _ => ForwardState::Pending,
        };
        let (entry_availability, _) = watch::channel(initial_availability);
        let (status, _) = watch::channel(ForwardStatusSnapshot {
            state: initial_state,
            bound,
            active_connections: 0,
            refused_connections: 0,
            error: (initial_state == ForwardState::Unsupported).then(unsupported_detail),
        });
        let entry_shutdown = self.shutdown.child_token();
        let connection_generation = (shape == ForwardShape::InboundAgent
            && initial_state == ForwardState::Active)
            .then(|| entry_shutdown.child_token());
        Ok(Arc::new(ForwardEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            scope,
            spec,
            name,
            shape,
            guest_half,
            host_target,
            token,
            shutdown: entry_shutdown,
            availability: entry_availability,
            status,
            connection_generation: Mutex::new(connection_generation),
            listener: Mutex::new(listener),
            vsock_listener: Mutex::new(None),
            total_permit: Mutex::new(total_permit),
            session_permit: Mutex::new(session_permit),
            task: Mutex::new(None),
        }))
    }

    pub(crate) async fn register_outbound(
        self: &Arc<Self>,
        machine: &VirtualMachine,
    ) -> eyre::Result<()> {
        let _operation = self.operation.lock().await;
        let entries = self.entries();
        for entry in entries {
            if let forward_spec::Endpoint::Vsock(port) = entry.spec.listen {
                let listener = machine.listen_public_vsock(port).await.map_err(|error| {
                    eyre::eyre!(
                        "register outbound forward {} on vsock port {port}: {error}",
                        entry.name
                    )
                })?;
                *entry
                    .vsock_listener
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(listener);
            }
        }
        if self
            .entries()
            .iter()
            .any(|entry| entry.shape == ForwardShape::OutboundAgent)
        {
            let listener = machine
                .listen_public_vsock(forward_spec::FORWARD_VSOCK_PORT)
                .await
                .map_err(|error| eyre::eyre!("register forward return port 1028: {error}"))?;
            *self
                .return_listener
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(listener);
            self.return_registered.store(true, Ordering::Release);
        }
        Ok(())
    }

    pub(crate) fn activate(self: &Arc<Self>, machine: VirtualMachine) {
        let _ = self.machine.set(machine.clone());
        self.running.store(true, Ordering::Release);
        for entry in self.entries() {
            self.activate_entry(entry, machine.clone());
        }
        if let Some(listener) = self
            .return_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            self.start_return_task(listener);
        }
    }

    pub(crate) fn mark_stopping(&self) {
        self.running.store(false, Ordering::Release);
    }

    pub(crate) async fn lock_registrations(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.operation.lock().await
    }

    fn activate_entry(self: &Arc<Self>, entry: Arc<ForwardEntry>, machine: VirtualMachine) {
        if let Some(listener) = entry
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            entry.spawn(inbound::serve(listener, entry.clone(), machine.clone()));
        }
        if let Some(listener) = entry
            .vsock_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            entry.set_state(ForwardState::Active, None);
            entry.spawn(outbound::serve_raw(listener, entry.clone()));
        }
        if entry.shape == ForwardShape::OutboundAgent {
            entry.spawn(agent::supervise_listener(machine, entry.clone()));
        }
    }

    pub(crate) async fn add_session(
        self: &Arc<Self>,
        spec: Forward,
    ) -> Result<Arc<ForwardEntry>, OpenError> {
        let _operation = self.operation.lock().await;
        if !self.running.load(Ordering::Acquire) || self.shutdown.is_cancelled() {
            return Err(OpenError::NotRunning("VM is not running".to_string()));
        }
        let entries = self.entries();
        let mut specs = entries
            .iter()
            .map(|entry| entry.spec.clone())
            .collect::<Vec<_>>();
        specs.push(spec.clone());
        if let Err(error) = forward_spec::validate_forwards(&specs, self.mux_filename.as_deref()) {
            return match error {
                forward_spec::ForwardError::DuplicateVsockListenPort(_) => {
                    Err(OpenError::AddressInUse(error.to_string()))
                }
                _ => Err(OpenError::Invalid(error.to_string())),
            };
        }
        if entries
            .iter()
            .any(|entry| listen_conflicts(&entry.spec.listen, &spec.listen))
        {
            return Err(OpenError::AddressInUse(format!(
                "listen endpoint {} is already owned",
                spec.listen
            )));
        }
        let total = self
            .total_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                OpenError::Limit(format!("forward limit of {MAX_FORWARDS} is exhausted"))
            })?;
        let session = self
            .session_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                OpenError::Limit(format!(
                    "session-scoped forward limit of {MAX_SESSION_FORWARDS} is exhausted"
                ))
            })?;
        let entry = self
            .build_entry(spec, ForwardScope::Session, Some(total), Some(session))
            .await?;
        let machine = self
            .machine
            .get()
            .cloned()
            .ok_or_else(|| OpenError::Unavailable("VM backend is unavailable".to_string()))?;
        match entry.shape {
            ForwardShape::OutboundVsock => self.attach_raw(&machine, entry.clone()).await?,
            ForwardShape::OutboundAgent => self.ensure_return_listener(&machine).await?,
            ForwardShape::InboundAgent | ForwardShape::InboundVsock => {}
        }
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry.clone());
        if matches!(entry.guest_half, GuestHalf::Agent(_)) {
            entry.set_availability(self.availability.borrow().clone());
        }
        self.activate_entry(entry.clone(), machine);
        Ok(entry)
    }

    async fn attach_raw(
        self: &Arc<Self>,
        machine: &VirtualMachine,
        entry: Arc<ForwardEntry>,
    ) -> Result<(), OpenError> {
        let forward_spec::Endpoint::Vsock(port) = entry.spec.listen else {
            return Err(OpenError::Invalid(
                "raw forward has no vsock listener".to_string(),
            ));
        };
        let listener = machine.listen_public_vsock(port).await.map_err(|error| {
            OpenError::Unavailable(format!("register vsock port {port}: {error}"))
        })?;
        *entry
            .vsock_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(listener);
        Ok(())
    }

    async fn ensure_return_listener(
        self: &Arc<Self>,
        machine: &VirtualMachine,
    ) -> Result<(), OpenError> {
        if self.return_registered.load(Ordering::Acquire) {
            return Ok(());
        }
        let listener = machine
            .listen_public_vsock(forward_spec::FORWARD_VSOCK_PORT)
            .await
            .map_err(|error| {
                OpenError::Unavailable(format!("register forward return port 1028: {error}"))
            })?;
        self.return_registered.store(true, Ordering::Release);
        self.start_return_task(listener);
        Ok(())
    }

    pub(crate) async fn remove(self: &Arc<Self>, id: u64) {
        let _operation = self.operation.lock().await;
        let removed = {
            let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            entries
                .iter()
                .position(|entry| entry.id == id)
                .map(|index| entries.remove(index))
        };
        let Some(entry) = removed else {
            return;
        };
        entry.stop().await;
        entry
            .total_permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        entry
            .session_permit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if !self
            .entries()
            .iter()
            .any(|entry| entry.shape == ForwardShape::OutboundAgent)
        {
            self.stop_return_task().await;
        }
    }

    pub(crate) fn entries(&self) -> Vec<Arc<ForwardEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn registered_ports(&self) -> BTreeSet<u32> {
        let mut ports = self
            .entries()
            .iter()
            .filter_map(|entry| match entry.spec.listen {
                forward_spec::Endpoint::Vsock(port) => Some(port),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        if self.return_registered.load(Ordering::Acquire) {
            ports.insert(forward_spec::FORWARD_VSOCK_PORT);
        }
        ports
    }

    fn start_return_task(self: &Arc<Self>, listener: crate::virt::VsockListener) {
        let shutdown = self.shutdown.child_token();
        let task = OwnedTask::spawn(
            shutdown.clone(),
            outbound::serve_return(listener, self.clone(), shutdown),
        );
        *self
            .return_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    async fn stop_return_task(&self) {
        let task = self
            .return_task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.stop().await;
        }
        self.return_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.return_registered.store(false, Ordering::Release);
    }

    fn token_entry(&self, token: Token) -> Option<Arc<ForwardEntry>> {
        self.entries()
            .into_iter()
            .find(|entry| entry.token == Some(token))
    }

    fn warn_invalid_token(&self) {
        const WARNING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        let now = std::time::Instant::now();
        let mut previous = self
            .invalid_warning
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if previous
            .is_none_or(|previous| now.saturating_duration_since(previous) >= WARNING_INTERVAL)
        {
            tracing::warn!("rejected malformed or unknown forward return token");
            *previous = Some(now);
        }
    }

    pub(crate) fn set_agent_availability(&self, availability: GuestHalfAvailability) {
        let changed = self.availability.send_if_modified(|current| {
            if *current == availability {
                return false;
            }
            *current = availability.clone();
            true
        });
        if changed {
            for entry in self.entries() {
                if matches!(&entry.guest_half, GuestHalf::Agent(_)) {
                    entry.set_availability(availability.clone());
                }
            }
        }
    }

    pub(crate) async fn shutdown(&self) -> eyre::Result<()> {
        self.running.store(false, Ordering::Release);
        self.shutdown.cancel();
        let _operation = self.operation.lock().await;
        for entry in self.entries() {
            entry.stop().await;
        }
        self.stop_return_task().await;
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        Ok(())
    }
}

fn bind_error(name: &str, endpoint: &forward_spec::Endpoint, error: eyre::Report) -> OpenError {
    let address_in_use = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse)
    });
    let message = format!("bind forward {name} at {endpoint}: {error}");
    if address_in_use {
        OpenError::AddressInUse(message)
    } else {
        OpenError::Unavailable(message)
    }
}

fn listen_conflicts(left: &forward_spec::Endpoint, right: &forward_spec::Endpoint) -> bool {
    if left != right {
        return false;
    }
    !matches!(
        left,
        forward_spec::Endpoint::Host(Address::Tcp(address))
            | forward_spec::Endpoint::Guest(Address::Tcp(address))
            if address.port() == 0
    )
}

fn resolve_host_target(spec: &Forward, runtime_dir: &Path) -> eyre::Result<Option<Address>> {
    let forward_spec::Endpoint::Host(address) = &spec.connect else {
        return Ok(None);
    };
    Ok(Some(match address {
        Address::Tcp(address) => Address::Tcp(*address),
        Address::Unix(path) if path.is_relative() => Address::Unix(runtime_dir.join(path)),
        Address::Unix(path) => Address::Unix(path.clone()),
    }))
}

pub(crate) fn spawn_capability_supervisor(
    machine: VirtualMachine,
    store: Arc<crate::state::InstanceStore>,
    forwards: Arc<ForwardTable>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    agent::spawn(machine, store, forwards, shutdown)
}

impl ForwardEntry {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(OwnedTask::spawn(self.shutdown.clone(), future));
    }

    async fn stop(&self) {
        self.shutdown.cancel();
        self.set_state(ForwardState::Closed, None);
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.stop().await;
        }
        self.listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.vsock_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn snapshot(&self) -> ForwardStatusSnapshot {
        self.status.borrow().clone()
    }

    fn set_state(&self, state: ForwardState, error: Option<protocol::v1::ErrorDetail>) {
        self.status.send_modify(|snapshot| {
            snapshot.state = state;
            snapshot.error = error;
            if state == ForwardState::Active && self.shape == ForwardShape::OutboundVsock {
                snapshot.bound = Some(self.spec.listen.clone());
            }
        });
    }

    fn set_availability(&self, availability: GuestHalfAvailability) {
        let mut generation = self
            .connection_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *self.availability.borrow() == availability {
            return;
        }
        if let Some(previous) = generation.take() {
            previous.cancel();
        }
        if self.shape == ForwardShape::InboundAgent
            && matches!(availability, GuestHalfAvailability::Available(_))
        {
            *generation = Some(self.shutdown.child_token());
        }
        self.apply_availability(availability.clone());
        self.availability.send_replace(availability);
    }

    pub(crate) fn connection_lifetime(&self) -> Option<CancellationToken> {
        if matches!(self.guest_half, GuestHalf::Vsock(_)) {
            return Some(self.shutdown.clone());
        }
        self.connection_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|token| !token.is_cancelled())
            .cloned()
    }

    pub(crate) fn activate_guest_listener(
        &self,
        identity: &crate::state::ReadyAgentIdentity,
        bound: forward_spec::Address,
    ) -> bool {
        let mut generation = self
            .connection_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.shutdown.is_cancelled()
            || *self.availability.borrow()
                != GuestHalfAvailability::Available(Some(identity.clone()))
        {
            return false;
        }
        if let Some(previous) = generation.replace(self.shutdown.child_token()) {
            previous.cancel();
        }
        self.status.send_modify(|snapshot| {
            snapshot.state = ForwardState::Active;
            snapshot.bound = Some(forward_spec::Endpoint::Guest(bound));
            snapshot.error = None;
        });
        true
    }

    pub(crate) fn end_guest_listener(&self) {
        let mut generation = self
            .connection_generation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(previous) = generation.take() {
            previous.cancel();
        }
        if !self.shutdown.is_cancelled()
            && matches!(
                *self.availability.borrow(),
                GuestHalfAvailability::Available(_)
            )
        {
            self.status
                .send_modify(|snapshot| snapshot.state = ForwardState::Pending);
        }
    }

    fn apply_availability(&self, availability: GuestHalfAvailability) {
        match availability {
            GuestHalfAvailability::Unknown => self.set_state(ForwardState::Pending, None),
            GuestHalfAvailability::Available(_) => match self.shape {
                ForwardShape::InboundAgent => self.set_state(ForwardState::Active, None),
                ForwardShape::OutboundAgent => self.set_state(ForwardState::Pending, None),
                ForwardShape::InboundVsock | ForwardShape::OutboundVsock => {}
            },
            GuestHalfAvailability::Unsupported => {
                self.set_state(ForwardState::Unsupported, Some(unsupported_detail()))
            }
        }
    }

    pub(crate) fn refuse(&self) {
        self.refuse_by(1);
    }

    pub(crate) fn refuse_by(&self, count: usize) {
        let increment = u32::try_from(count).unwrap_or(u32::MAX);
        self.status.send_modify(|snapshot| {
            snapshot.refused_connections = snapshot.refused_connections.saturating_add(increment);
            snapshot.error = Some(error_detail(protocol::v1::ErrorCode::BackendUnavailable));
        });
    }

    pub(crate) fn connection_opened(self: &Arc<Self>) -> ConnectionGuard {
        self.status
            .send_modify(|snapshot| snapshot.active_connections += 1);
        ConnectionGuard(self.clone())
    }
}

pub(crate) struct ConnectionGuard(Arc<ForwardEntry>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.status.send_modify(|snapshot| {
            snapshot.active_connections = snapshot.active_connections.saturating_sub(1);
        });
    }
}

fn error_detail(code: protocol::v1::ErrorCode) -> protocol::v1::ErrorDetail {
    protocol::v1::ErrorDetail {
        code: Some(code as i32),
        retry_after: None,
    }
}

fn unsupported_detail() -> protocol::v1::ErrorDetail {
    error_detail(protocol::v1::ErrorCode::ForwardUnsupported)
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for entry in self
            .entries
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
        {
            entry.shutdown.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::forward::{ForwardScope, ForwardState, ForwardTable};

    #[tokio::test]
    async fn removing_raw_sessions_reclaims_the_task_and_registration() {
        use crate::virt::capacity::{ListenerAdmissionClass, VsockCapacity};
        let root =
            std::path::Path::new("/tmp").join(format!("fr-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("listen");
        let table = ForwardTable::prepare_machine(&[], &root, None)
            .await
            .unwrap();
        let capacity = VsockCapacity::new("forward-unit-test");
        for port in 5000..6100 {
            let spec = forward_spec::Forward::new(
                forward_spec::Endpoint::Vsock(port),
                "host:tcp:1".parse().unwrap(),
            );
            let entry = table
                .build_entry(spec, ForwardScope::Session, None, None)
                .await
                .unwrap();
            let socket = tokio::net::UnixListener::bind(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            let listener = crate::virt::VsockListener::from_unix_listener(
                socket,
                port,
                capacity.listener(ListenerAdmissionClass::Public),
            );
            entry.spawn(crate::forward::outbound::serve_raw(listener, entry.clone()));
            table.entries.lock().unwrap().push(entry.clone());
            assert!(table.registered_ports().contains(&port));
            table.remove(entry.id()).await;
            assert!(table.registered_ports().is_empty());
            assert!(entry.task.lock().unwrap().is_none());
            assert_eq!(entry.snapshot().state, ForwardState::Closed);
            assert_eq!(std::sync::Arc::strong_count(&entry), 1);
        }
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn activated_raw_listener_reports_its_registered_port() {
        let forward = forward_spec::Forward::new(
            "vsock:5000".parse().unwrap(),
            "host:tcp:5432".parse().unwrap(),
        );
        let table =
            ForwardTable::prepare_machine(&[forward], std::path::Path::new("/unused"), None)
                .await
                .unwrap();
        let entry = &table.entries()[0];
        entry.set_state(ForwardState::Active, None);
        assert_eq!(
            entry.snapshot().bound,
            Some(forward_spec::Endpoint::Vsock(5000))
        );
    }
}

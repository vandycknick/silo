mod agent;
mod host_socket;
mod inbound;
mod outbound;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use forward_spec::{Address, Forward, ForwardShape, GuestHalf, Token};
use rand::RngExt;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::forward::host_socket::OwnedHostListener;
use crate::virt::VirtualMachine;

const MAX_DECLARED_FORWARDS: usize = 128;

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
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuestHalfAvailability {
    Unknown,
    Available(Option<crate::state::ReadyAgentIdentity>),
    Unsupported,
}

pub(crate) struct ForwardEntry {
    pub(crate) spec: Forward,
    pub(crate) name: String,
    pub(crate) shape: ForwardShape,
    pub(crate) guest_half: GuestHalf,
    pub(crate) host_target: Option<Address>,
    pub(crate) token: Option<Token>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) availability: watch::Sender<GuestHalfAvailability>,
    status: watch::Sender<ForwardStatusSnapshot>,
    active: AtomicU32,
    refused: AtomicU32,
    listener: Mutex<Option<OwnedHostListener>>,
    vsock_listener: Mutex<Option<crate::virt::VsockListener>>,
}

pub(crate) struct ForwardTable {
    entries: Vec<Arc<ForwardEntry>>,
    shutdown: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    return_listener: Mutex<Option<crate::virt::VsockListener>>,
    registered_ports: BTreeSet<u32>,
    invalid_warning: Mutex<Option<std::time::Instant>>,
}

impl ForwardTable {
    pub(crate) async fn prepare_declared(
        forwards: &[Forward],
        runtime_dir: &Path,
        mux_filename: Option<&str>,
    ) -> eyre::Result<Arc<Self>> {
        forward_spec::validate_forwards(forwards, mux_filename)
            .map_err(|error| eyre::eyre!("validate declared forwards: {error}"))?;
        if forwards.len() > MAX_DECLARED_FORWARDS {
            return Err(eyre::eyre!(
                "declared forwards exceed the limit of {MAX_DECLARED_FORWARDS}"
            ));
        }
        let shutdown = CancellationToken::new();
        let mut entries = Vec::with_capacity(forwards.len());
        for spec in forwards {
            let shape = spec.validate()?;
            let name = spec.display_name();
            let guest_half = spec.guest_half()?;
            let host_target = resolve_host_target(spec, runtime_dir)?;
            let token = if shape == ForwardShape::OutboundAgent {
                let mut bytes = [0_u8; 16];
                rand::rng().fill(&mut bytes);
                Some(Token::new(bytes))
            } else {
                None
            };
            let listener = match shape {
                ForwardShape::InboundAgent | ForwardShape::InboundVsock => {
                    let address = match &spec.listen {
                        forward_spec::Endpoint::Host(address) => address,
                        _ => {
                            return Err(eyre::eyre!(
                                "validated inbound forward has no host listener"
                            ))
                        }
                    };
                    Some(
                        OwnedHostListener::bind(address, spec.mode, runtime_dir)
                            .await
                            .map_err(|error| {
                                eyre::eyre!("prepare forward {name} at {}: {error}", spec.listen)
                            })?,
                    )
                }
                ForwardShape::OutboundAgent | ForwardShape::OutboundVsock => {
                    tracing::info!(forward = %name, "declared outbound forward remains pending until outbound support is enabled");
                    None
                }
            };
            let bound = listener.as_ref().map(OwnedHostListener::bound_endpoint);
            let initial_availability = match guest_half {
                GuestHalf::Vsock(_) if listener.is_some() => GuestHalfAvailability::Available(None),
                _ => GuestHalfAvailability::Unknown,
            };
            let initial_state =
                if matches!(initial_availability, GuestHalfAvailability::Available(_)) {
                    ForwardState::Active
                } else {
                    ForwardState::Pending
                };
            let (availability, _) = watch::channel(initial_availability);
            let (status, _) = watch::channel(ForwardStatusSnapshot {
                state: initial_state,
                bound,
                active_connections: 0,
                refused_connections: 0,
                error: None,
            });
            entries.push(Arc::new(ForwardEntry {
                spec: spec.clone(),
                name,
                shape,
                guest_half,
                host_target,
                token,
                shutdown: shutdown.child_token(),
                availability,
                status,
                active: AtomicU32::new(0),
                refused: AtomicU32::new(0),
                listener: Mutex::new(listener),
                vsock_listener: Mutex::new(None),
            }));
        }
        let mut registered_ports: BTreeSet<_> = entries
            .iter()
            .filter_map(|entry| match entry.spec.listen {
                forward_spec::Endpoint::Vsock(port) => Some(port),
                _ => None,
            })
            .collect();
        if entries
            .iter()
            .any(|entry| entry.shape == ForwardShape::OutboundAgent)
        {
            registered_ports.insert(forward_spec::FORWARD_VSOCK_PORT);
        }
        Ok(Arc::new(Self {
            entries,
            shutdown,
            tasks: Mutex::new(Vec::new()),
            return_listener: Mutex::new(None),
            registered_ports,
            invalid_warning: Mutex::new(None),
        }))
    }

    pub(crate) async fn register_outbound(&self, machine: &VirtualMachine) -> eyre::Result<()> {
        for entry in &self.entries {
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
            .entries
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
        }
        Ok(())
    }

    pub(crate) fn activate(self: &Arc<Self>, machine: VirtualMachine) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        for entry in &self.entries {
            let listener = entry
                .listener
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(listener) = listener {
                tasks.push(tokio::spawn(inbound::serve(
                    listener,
                    entry.clone(),
                    machine.clone(),
                )));
            }
            let vsock_listener = entry
                .vsock_listener
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(listener) = vsock_listener {
                entry.set_state(ForwardState::Active, None);
                tasks.push(tokio::spawn(outbound::serve_raw(listener, entry.clone())));
            }
            if entry.shape == ForwardShape::OutboundAgent {
                tasks.push(tokio::spawn(agent::supervise_listener(
                    machine.clone(),
                    entry.clone(),
                )));
            }
        }
        let return_listener = self
            .return_listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(listener) = return_listener {
            tasks.push(tokio::spawn(outbound::serve_return(listener, self.clone())));
        }
    }

    pub(crate) fn registered_ports(&self) -> &BTreeSet<u32> {
        &self.registered_ports
    }

    fn token_entry(&self, token: Token) -> Option<Arc<ForwardEntry>> {
        self.entries
            .iter()
            .find(|entry| entry.token == Some(token))
            .cloned()
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

    pub(crate) fn has_agent_forwards(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.guest_half, GuestHalf::Agent(_)))
    }

    pub(crate) fn set_agent_availability(&self, availability: GuestHalfAvailability) {
        for entry in &self.entries {
            if matches!(&entry.guest_half, GuestHalf::Agent(_)) {
                entry.availability.send_replace(availability.clone());
                entry.apply_availability(availability.clone());
            }
        }
    }

    pub(crate) async fn shutdown(&self) -> eyre::Result<()> {
        self.shutdown.cancel();
        for entry in &self.entries {
            entry.shutdown.cancel();
            entry.set_state(ForwardState::Closed, None);
        }
        let tasks = {
            let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            task.await
                .map_err(|error| eyre::eyre!("forward task failed: {error}"))?;
        }
        Ok(())
    }
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
    fn set_state(&self, state: ForwardState, error: Option<String>) {
        self.status.send_modify(|snapshot| {
            snapshot.state = state;
            snapshot.error = error;
        });
    }

    pub(crate) fn apply_availability(&self, availability: GuestHalfAvailability) {
        match availability {
            GuestHalfAvailability::Unknown => self.set_state(ForwardState::Pending, None),
            GuestHalfAvailability::Available(_) => match self.shape {
                ForwardShape::InboundAgent => self.set_state(ForwardState::Active, None),
                ForwardShape::OutboundAgent => self.set_state(ForwardState::Pending, None),
                ForwardShape::InboundVsock | ForwardShape::OutboundVsock => {}
            },
            GuestHalfAvailability::Unsupported => self.set_state(
                ForwardState::Unsupported,
                Some("agent does not serve silo.v1.GuestForwardService".to_string()),
            ),
        }
    }

    pub(crate) fn refuse(&self) {
        self.refuse_by(1);
    }

    pub(crate) fn refuse_by(&self, count: usize) {
        let increment = u32::try_from(count).unwrap_or(u32::MAX);
        let value = self
            .refused
            .fetch_add(increment, Ordering::Relaxed)
            .saturating_add(increment);
        self.status
            .send_modify(|snapshot| snapshot.refused_connections = value);
    }

    pub(crate) fn connection_opened(&self) {
        let value = self
            .active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.status
            .send_modify(|snapshot| snapshot.active_connections = value);
    }

    pub(crate) fn connection_closed(&self) {
        let previous = self.active.fetch_sub(1, Ordering::Relaxed);
        let value = previous.saturating_sub(1);
        self.status
            .send_modify(|snapshot| snapshot.active_connections = value);
    }
}

impl Drop for ForwardTable {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for entry in &self.entries {
            entry.shutdown.cancel();
        }
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use forward_spec::{Address, Endpoint, Forward, ForwardShape};

    use crate::forward::{ForwardState, ForwardTable, GuestHalfAvailability};

    #[tokio::test]
    async fn supported_outbound_agent_forward_stays_pending_until_listener_support_exists() {
        let forward = Forward::new(
            Endpoint::Guest(Address::Tcp(
                "127.0.0.1:18080".parse().expect("guest listen address"),
            )),
            Endpoint::Host(Address::Tcp(
                "127.0.0.1:18081".parse().expect("host target address"),
            )),
        );
        let table = ForwardTable::prepare_declared(&[forward], Path::new("/tmp"), None)
            .await
            .expect("prepare outbound forward");
        let entry = &table.entries[0];
        assert_eq!(entry.shape, ForwardShape::OutboundAgent);
        assert!(table
            .registered_ports()
            .contains(&forward_spec::FORWARD_VSOCK_PORT));

        table.set_agent_availability(GuestHalfAvailability::Available(None));
        assert_eq!(entry.status.borrow().state, ForwardState::Pending);

        table.set_agent_availability(GuestHalfAvailability::Unsupported);
        assert_eq!(entry.status.borrow().state, ForwardState::Unsupported);
    }
}

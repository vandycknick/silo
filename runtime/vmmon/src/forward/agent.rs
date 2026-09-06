use std::sync::Arc;
use std::time::Duration;

use protocol::v1::guest_forward_service_client::GuestForwardServiceClient;
use protocol::v1::listen_event::Event;
use protocol::v1::ListenRequest;
use tonic_health::pb::{health_check_response::ServingStatus, HealthCheckRequest};

use crate::forward::{ForwardEntry, ForwardState, ForwardTable, GuestHalfAvailability};
use crate::state::InstanceStore;
use crate::virt::VirtualMachine;

const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(100);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

pub(crate) async fn supervise(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    forwards: Arc<ForwardTable>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut identities = store.subscribe_ready_agent_identity();
    let mut capability = CapabilityCache::default();
    loop {
        let identity = identities.borrow_and_update().clone();
        forwards.set_agent_availability(capability.availability(identity.as_ref()));
        if identity.is_none() || capability.checked(identity.as_ref()) {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                changed = identities.changed() => if changed.is_err() { return; },
            }
            continue;
        }
        let Some(identity) = identity else {
            continue;
        };
        let mut backoff = ReconnectBackoff::new();
        let result = 'checks: loop {
            let mut check = Box::pin(check_capability(&machine));
            let result = loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    changed = identities.changed() => {
                        if changed.is_err() { return; }
                        let current = identities.borrow_and_update().clone();
                        if current.as_ref() != Some(&identity) {
                            break 'checks None;
                        }
                    }
                    result = &mut check => break result,
                }
            };
            match result {
                Ok(supported) => break Some(supported),
                Err(error) => {
                    let delay = backoff.next_delay();
                    tracing::debug!(%error, retry_in_ms = delay.as_millis(), "guest forward capability check failed; retrying while capability is unknown");
                    let deadline = tokio::time::Instant::now() + delay;
                    loop {
                        tokio::select! {
                            _ = shutdown.cancelled() => return,
                            _ = tokio::time::sleep_until(deadline) => break,
                            changed = identities.changed() => {
                                if changed.is_err() { return; }
                                let current = identities.borrow_and_update().clone();
                                if current.as_ref() != Some(&identity) {
                                    break 'checks None;
                                }
                            }
                        }
                    }
                }
            }
        };
        let Some(supported) = result else {
            continue;
        };
        if identities.borrow().as_ref() != Some(&identity) {
            continue;
        }
        capability.observation = Some((identity.clone(), supported));
        if let Err(error) = store.set_forward_service(identity.clone(), supported) {
            tracing::error!(%error, "failed to cache guest forward capability");
            return;
        }
        if identities.borrow().as_ref() != Some(&identity) {
            continue;
        }
        if !supported {
            tracing::warn!(agent_instance_id = %identity.instance_id, "guest agent does not serve GuestForwardService");
        }
    }
}

#[derive(Default)]
struct CapabilityCache {
    observation: Option<(crate::state::ReadyAgentIdentity, bool)>,
}

impl CapabilityCache {
    fn checked(&self, identity: Option<&crate::state::ReadyAgentIdentity>) -> bool {
        self.observation
            .as_ref()
            .is_some_and(|(checked, _)| Some(checked) == identity)
    }

    fn availability(
        &self,
        identity: Option<&crate::state::ReadyAgentIdentity>,
    ) -> GuestHalfAvailability {
        match (&self.observation, identity) {
            (Some((checked, supported)), Some(ready)) if checked == ready => {
                if *supported {
                    GuestHalfAvailability::Available(Some(ready.clone()))
                } else {
                    GuestHalfAvailability::Unsupported
                }
            }
            _ => GuestHalfAvailability::Unknown,
        }
    }
}

struct ReconnectBackoff {
    next: Duration,
}

impl ReconnectBackoff {
    fn new() -> Self {
        Self {
            next: INITIAL_RECONNECT_BACKOFF,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(MAX_RECONNECT_BACKOFF);
        delay
    }
}

async fn check_capability(machine: &VirtualMachine) -> Result<bool, tonic::Status> {
    let channel = crate::guest::connect(machine).await?;
    let mut health = tonic_health::pb::health_client::HealthClient::new(channel);
    match tokio::time::timeout(
        Duration::from_secs(5),
        health.check(HealthCheckRequest {
            service: "silo.v1.GuestForwardService".to_string(),
        }),
    )
    .await
    .map_err(|_| tonic::Status::deadline_exceeded("forward health check timed out"))?
    {
        Ok(response) => Ok(response.into_inner().status == ServingStatus::Serving as i32),
        Err(status)
            if status.code() == tonic::Code::NotFound
                || status.code() == tonic::Code::Unimplemented =>
        {
            Ok(false)
        }
        Err(status) => Err(status),
    }
}

pub(crate) async fn supervise_listener(machine: VirtualMachine, entry: Arc<ForwardEntry>) {
    let mut availability = entry.availability.subscribe();
    loop {
        let current = availability.borrow_and_update().clone();
        let GuestHalfAvailability::Available(Some(identity)) = current else {
            tokio::select! {
                _ = entry.shutdown.cancelled() => return,
                changed = availability.changed() => if changed.is_err() { return; },
            }
            continue;
        };
        let mut backoff = ReconnectBackoff::new();
        loop {
            entry.set_state(ForwardState::Pending, None);
            let result = tokio::select! {
                _ = entry.shutdown.cancelled() => return,
                result = listen_once(&machine, &entry, &identity, &mut availability) => result,
            };
            entry.end_guest_listener();
            if availability.borrow().clone()
                != GuestHalfAvailability::Available(Some(identity.clone()))
            {
                break;
            }
            if let Err(error) = result {
                if entry.status.borrow().error.is_none() {
                    entry.set_state(
                        ForwardState::Pending,
                        Some(protocol::v1::ErrorDetail {
                            code: Some(protocol::v1::ErrorCode::BackendUnavailable as i32),
                            retry_after: None,
                        }),
                    );
                }
                tracing::debug!(forward = %entry.name, %error, "guest forward listener ended; retrying");
            }
            let delay = backoff.next_delay();
            tokio::select! {
                _ = entry.shutdown.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
                changed = availability.changed() => {
                    if changed.is_err() { return; }
                    if availability.borrow().clone() != GuestHalfAvailability::Available(Some(identity.clone())) { break; }
                }
            }
        }
    }
}

async fn listen_once(
    machine: &VirtualMachine,
    entry: &ForwardEntry,
    identity: &crate::state::ReadyAgentIdentity,
    availability: &mut tokio::sync::watch::Receiver<GuestHalfAvailability>,
) -> eyre::Result<()> {
    let forward_spec::Endpoint::Guest(requested) = &entry.spec.listen else {
        return Err(eyre::eyre!("outbound agent forward has no guest listener"));
    };
    let token = entry
        .token
        .ok_or_else(|| eyre::eyre!("outbound agent forward has no token"))?;
    let channel = crate::guest::connect(machine).await?;
    let mut client = GuestForwardServiceClient::new(channel)
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB);
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.listen(ListenRequest {
            listen: requested.to_string(),
            token: token.as_bytes().to_vec().into(),
            unix_mode: entry.spec.mode.map(forward_spec::UnixMode::get),
        }),
    )
    .await
    .map_err(|_| eyre::eyre!("guest forward Listen setup timed out"))??;
    let mut stream = response.into_inner();
    let first = tokio::select! {
        message = tokio::time::timeout(Duration::from_secs(5), stream.message()) => message.map_err(|_| eyre::eyre!("guest forward ListenerBound timed out"))??,
        changed = availability.changed() => {
            let _ = changed;
            return Ok(());
        }
        _ = entry.shutdown.cancelled() => return Ok(()),
    }
    .ok_or_else(|| eyre::eyre!("guest forward Listen ended before ListenerBound"))?;
    match first.event {
        Some(Event::Bound(bound)) => {
            let actual = bound.address.parse::<forward_spec::Address>()?;
            validate_bound(requested, &actual)?;
            if !entry.activate_guest_listener(identity, actual) {
                return Ok(());
            }
        }
        Some(Event::Failed(failed)) => {
            entry.status.send_modify(|snapshot| {
                snapshot.state = ForwardState::Pending;
                snapshot.error = failed.error;
            });
            let detail = failed.error.map_or_else(
                || "listener failed without detail".to_string(),
                |error| format!("listener failed with code {:?}", error.code),
            );
            return Err(eyre::eyre!("guest listener failed: {detail}"));
        }
        None => return Err(eyre::eyre!("guest forward Listen returned an empty event")),
    }
    loop {
        tokio::select! {
            _ = entry.shutdown.cancelled() => return Ok(()),
            changed = availability.changed() => {
                if changed.is_err() || availability.borrow().clone() != GuestHalfAvailability::Available(Some(identity.clone())) {
                    return Ok(());
                }
            }
            message = stream.message() => match message? {
                None => return Err(eyre::eyre!("guest forward Listen stream ended")),
                Some(event) => return Err(eyre::eyre!("guest forward Listen returned unexpected event after ListenerBound: {:?}", event.event.map(|_| "event"))),
            }
        }
    }
}

fn validate_bound(
    requested: &forward_spec::Address,
    actual: &forward_spec::Address,
) -> eyre::Result<()> {
    let valid = match (requested, actual) {
        (forward_spec::Address::Unix(requested), forward_spec::Address::Unix(actual)) => {
            requested == actual
        }
        (forward_spec::Address::Tcp(requested), forward_spec::Address::Tcp(actual)) => {
            requested.ip() == actual.ip()
                && if requested.port() == 0 {
                    actual.port() != 0
                } else {
                    requested.port() == actual.port()
                }
        }
        _ => false,
    };
    if !valid {
        return Err(eyre::eyre!(
            "guest ListenerBound address {actual} does not match requested {requested}"
        ));
    }
    Ok(())
}

pub(crate) fn spawn(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    forwards: Arc<ForwardTable>,
    shutdown: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(supervise(machine, store, forwards, shutdown))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::forward::agent::{CapabilityCache, ReconnectBackoff};
    use crate::forward::GuestHalfAvailability;

    #[test]
    fn cached_capability_tracks_readiness_loss_recovery_and_replacement() {
        let identity = crate::state::ReadyAgentIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: uuid::Uuid::new_v4(),
        };
        for supported in [true, false] {
            let cache = CapabilityCache {
                observation: Some((identity.clone(), supported)),
            };
            let expected = if supported {
                GuestHalfAvailability::Available(Some(identity.clone()))
            } else {
                GuestHalfAvailability::Unsupported
            };
            assert_eq!(cache.availability(Some(&identity)), expected);
            assert_eq!(cache.availability(None), GuestHalfAvailability::Unknown);
            assert_eq!(cache.availability(Some(&identity)), expected);
            assert!(cache.checked(Some(&identity)));
            let replacement = crate::state::ReadyAgentIdentity {
                instance_id: uuid::Uuid::new_v4(),
                ..identity.clone()
            };
            assert!(!cache.checked(Some(&replacement)));
            assert_eq!(
                cache.availability(Some(&replacement)),
                GuestHalfAvailability::Unknown
            );
        }
    }

    #[test]
    fn capability_reconnect_backoff_doubles_and_caps_at_five_seconds() {
        let mut backoff = ReconnectBackoff::new();
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(), Duration::from_millis(200));
        assert_eq!(backoff.next_delay(), Duration::from_millis(400));
        for _ in 0..16 {
            backoff.next_delay();
        }
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
    }
}

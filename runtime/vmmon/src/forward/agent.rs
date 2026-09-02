use std::sync::Arc;
use std::time::Duration;

use tonic_health::pb::{health_check_response::ServingStatus, HealthCheckRequest};

use crate::forward::{ForwardTable, GuestHalfAvailability};
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
    if !forwards.has_agent_forwards() {
        return;
    }
    let mut identities = store.subscribe_ready_agent_identity();
    let mut checked_identity = None;
    loop {
        if identities.borrow().is_none() {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                changed = identities.changed() => if changed.is_err() { return; },
            }
            continue;
        }
        let Some(identity) = identities.borrow_and_update().clone() else {
            continue;
        };
        if checked_identity.as_ref() == Some(&identity) {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                changed = identities.changed() => if changed.is_err() { return; },
            }
            continue;
        }
        forwards.set_agent_availability(GuestHalfAvailability::Unknown);
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
        checked_identity = Some(identity.clone());
        if let Err(error) = store.set_forward_service(identity.clone(), supported) {
            tracing::error!(%error, "failed to cache guest forward capability");
            return;
        }
        if identities.borrow().as_ref() != Some(&identity) {
            continue;
        }
        match supported {
            true => {
                forwards.set_agent_availability(GuestHalfAvailability::Available(Some(
                    identity.clone(),
                )));
            }
            false => {
                tracing::warn!(agent_instance_id = %identity.instance_id, "guest agent does not serve GuestForwardService");
                forwards.set_agent_availability(GuestHalfAvailability::Unsupported);
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            changed = identities.changed() => {
                if changed.is_err() { return; }
                let current = identities.borrow_and_update().clone();
                if current.as_ref() != checked_identity.as_ref() {
                    forwards.set_agent_availability(GuestHalfAvailability::Unknown);
                }
            }
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
    match health
        .check(HealthCheckRequest {
            service: "silo.v1.GuestForwardService".to_string(),
        })
        .await
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

    use crate::forward::agent::ReconnectBackoff;

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

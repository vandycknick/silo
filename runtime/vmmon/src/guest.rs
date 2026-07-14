use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use protocol::v1::guest_agent_service_client::GuestAgentServiceClient;
use protocol::v1::{WatchAgentMetricsRequest, WatchAgentStatusRequest};
use rand::Rng;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use virt::VirtualMachine;

use crate::state::{InstanceStore, StoreError};

pub(crate) const GUEST_CONTROL_PORT: u32 = 1027;
const HEARTBEAT: Duration = Duration::from_secs(5);
const METRICS_INTERVAL: Duration = Duration::from_secs(5);
const FIRST_STATUS_DEADLINE: Duration = Duration::from_secs(5);
const FAST_DISCOVERY_WINDOW: Duration = Duration::from_secs(2);
const FAST_DISCOVERY_RETRY: Duration = Duration::from_millis(25);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

pub(crate) async fn spawn_guest_services(
    machine: &VirtualMachine,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) -> eyre::Result<JoinHandle<()>> {
    tracing::info!(
        port = GUEST_CONTROL_PORT,
        "connecting to guest agent over vsock"
    );
    let machine = machine.clone();
    Ok(tokio::spawn(async move {
        let status = supervise_status(machine.clone(), store.clone(), shutdown.clone());
        let metrics = supervise_metrics(machine, store, shutdown);
        tokio::join!(status, metrics);
    }))
}

async fn supervise_status(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) {
    let mut retries = RetrySchedule::discovery();
    let mut attempt = 0_u64;
    let mut publish_connecting = false;
    let mut reset = store.subscribe_identity_reset();
    loop {
        if shutdown.is_cancelled() {
            return;
        }
        if publish_connecting {
            if let Err(error) = store.agent_connecting() {
                tracing::error!(%error, "failed to publish guest connection state");
                return;
            }
            publish_connecting = false;
        }
        attempt = attempt.saturating_add(1);
        tracing::debug!(
            stream = "status",
            port = GUEST_CONTROL_PORT,
            attempt,
            elapsed_ms = retries.elapsed().as_millis(),
            "attempting guest agent connection"
        );
        let result = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = async {
                match connect(&machine).await {
                    Ok(channel) => {
                        status_stream(
                            agent_client(channel),
                            store.clone(),
                            &mut reset,
                            retries.started_at(),
                        )
                        .await
                    }
                    Err(error) => Err((error, false)),
                }
            } => result,
        };
        let (error, received_snapshot) = match result {
            Err(error) => error,
            Ok(()) => {
                tracing::error!("guest status stream ended without a disconnect reason");
                return;
            }
        };
        tracing::debug!(
            stream = "status",
            code = ?error.code(),
            message = error.message(),
            received_snapshot,
            "guest agent stream ended"
        );
        let retry = retries.next(received_snapshot, Instant::now());
        if retry.phase == RetryPhase::Backoff {
            if let Err(store_error) = store.agent_failure(error.message()) {
                tracing::error!(%store_error, "failed to publish guest connection failure");
                return;
            }
            publish_connecting = true;
        }
        if !retry_sleep(&shutdown, retry, "status").await {
            return;
        }
    }
}

async fn supervise_metrics(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) {
    let mut retries = RetrySchedule::reconnect();
    let mut attempt = 0_u64;
    let mut generation = store.subscribe();
    loop {
        if !wait_for_identity(&store, &shutdown, &mut generation).await {
            return;
        }
        attempt = attempt.saturating_add(1);
        tracing::debug!(
            stream = "metrics",
            port = GUEST_CONTROL_PORT,
            attempt,
            "attempting guest agent connection"
        );
        let result = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = async {
                match connect(&machine).await {
                    Ok(channel) => metrics_stream(agent_client(channel), &store).await,
                    Err(error) => Err((error, false)),
                }
            } => result,
        };
        let (error, received_snapshot) = match result {
            Err(error) => error,
            Ok(()) => {
                tracing::error!("guest metrics stream ended without a disconnect reason");
                return;
            }
        };
        tracing::debug!(
            stream = "metrics",
            code = ?error.code(),
            message = error.message(),
            received_snapshot,
            "guest agent stream ended"
        );
        let retry = retries.next(received_snapshot, Instant::now());
        if !retry_sleep(&shutdown, retry, "metrics").await {
            return;
        }
    }
}

async fn status_stream(
    mut client: GuestAgentServiceClient<Channel>,
    store: Arc<InstanceStore>,
    reset: &mut tokio::sync::watch::Receiver<u64>,
    discovery_started_at: Instant,
) -> Result<(), (tonic::Status, bool)> {
    let response = tokio::time::timeout(
        FIRST_STATUS_DEADLINE,
        client.watch_status(WatchAgentStatusRequest {
            heartbeat_interval: Some(duration(HEARTBEAT)),
        }),
    )
    .await
    .map_err(|_| {
        (
            tonic::Status::deadline_exceeded("guest status watch setup timed out"),
            false,
        )
    })?
    .map_err(|error| (error, false))?;
    tracing::debug!(stream = "status", "guest agent watch established");
    let mut stream = response.into_inner();
    let mut received_snapshot = false;
    loop {
        tokio::select! {
            changed = reset.changed() => {
                if changed.is_ok() {
                    reset.borrow_and_update();
                    return Err((tonic::Status::aborted("metric identity mismatch"), received_snapshot));
                }
            }
            message = tokio::time::timeout(
                if received_snapshot { HEARTBEAT * 3 } else { FIRST_STATUS_DEADLINE },
                stream.message(),
            ) => {
                let message = message.map_err(|_| (tonic::Status::deadline_exceeded("guest status stream became silent"), received_snapshot))?
                    .map_err(|error| (error, received_snapshot))?
                    .ok_or_else(|| (tonic::Status::unavailable("guest status stream ended"), received_snapshot))?;
                store
                    .observe_status(message, HEARTBEAT * 3)
                    .map_err(|error| (observation_error(error), received_snapshot))?;
                if !received_snapshot {
                    tracing::debug!(
                        elapsed_ms = discovery_started_at.elapsed().as_millis(),
                        "guest agent status stream received its first snapshot"
                    );
                }
                received_snapshot = true;
            }
        }
    }
}

async fn metrics_stream(
    mut client: GuestAgentServiceClient<Channel>,
    store: &InstanceStore,
) -> Result<(), (tonic::Status, bool)> {
    let response = tokio::time::timeout(
        METRICS_INTERVAL * 3,
        client.watch_metrics(WatchAgentMetricsRequest {
            interval: Some(duration(METRICS_INTERVAL)),
        }),
    )
    .await
    .map_err(|_| {
        (
            tonic::Status::deadline_exceeded("guest metrics watch setup timed out"),
            false,
        )
    })?
    .map_err(|error| (error, false))?;
    tracing::debug!(stream = "metrics", "guest agent watch established");
    let mut stream = response.into_inner();
    let mut received_snapshot = false;
    loop {
        let metrics = tokio::time::timeout(METRICS_INTERVAL * 3, stream.message())
            .await
            .map_err(|_| {
                (
                    tonic::Status::deadline_exceeded("guest metrics stream became silent"),
                    received_snapshot,
                )
            })?
            .map_err(|error| (error, received_snapshot))?
            .ok_or_else(|| {
                (
                    tonic::Status::unavailable("guest metrics stream ended"),
                    received_snapshot,
                )
            })?;
        let agent_instance_id = metrics.agent_instance_id.clone();
        store
            .observe_metrics(metrics, METRICS_INTERVAL * 3)
            .map_err(|error| (observation_error(error), received_snapshot))?;
        if !received_snapshot {
            if let Some(agent_instance_id) = agent_instance_id {
                tracing::info!(agent_instance_id, "guest agent metrics stream is healthy");
            }
        }
        received_snapshot = true;
    }
}

fn observation_error(error: StoreError) -> tonic::Status {
    match error {
        StoreError::Validation(_) | StoreError::Protocol(_) | StoreError::IdentityMismatch => {
            tonic::Status::invalid_argument(error.to_string())
        }
        StoreError::Poisoned | StoreError::Clock => tonic::Status::internal(error.to_string()),
    }
}

async fn wait_for_identity(
    store: &InstanceStore,
    shutdown: &CancellationToken,
    generation: &mut tokio::sync::watch::Receiver<u64>,
) -> bool {
    loop {
        match store.has_identity() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(error) => {
                tracing::error!(%error, "failed to read guest identity state");
                return false;
            }
        }
        generation.borrow_and_update();
        tokio::select! {
            _ = shutdown.cancelled() => return false,
            changed = generation.changed() => if changed.is_err() { return false; },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryPhase {
    Discovery,
    Backoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetryPlan {
    phase: RetryPhase,
    ceiling: Duration,
}

impl RetryPlan {
    fn delay(self) -> Duration {
        if self.phase == RetryPhase::Discovery {
            return self.ceiling;
        }
        let upper = u64::try_from(self.ceiling.as_millis()).map_or(u64::MAX, |value| value);
        Duration::from_millis(rand::rng().random_range(0..=upper))
    }
}

#[derive(Debug)]
struct RetrySchedule {
    started_at: Instant,
    backoff: Duration,
    discovered: bool,
}

impl RetrySchedule {
    fn discovery() -> Self {
        Self::new(Instant::now(), false)
    }

    fn reconnect() -> Self {
        Self::new(Instant::now(), true)
    }

    fn new(started_at: Instant, discovered: bool) -> Self {
        Self {
            started_at,
            backoff: INITIAL_BACKOFF,
            discovered,
        }
    }

    fn started_at(&self) -> Instant {
        self.started_at
    }

    fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    fn next(&mut self, received_snapshot: bool, now: Instant) -> RetryPlan {
        if received_snapshot {
            self.discovered = true;
            self.backoff = INITIAL_BACKOFF;
        }
        if !self.discovered
            && now.saturating_duration_since(self.started_at) < FAST_DISCOVERY_WINDOW
        {
            return RetryPlan {
                phase: RetryPhase::Discovery,
                ceiling: FAST_DISCOVERY_RETRY,
            };
        }

        let ceiling = self.backoff;
        self.backoff = self.backoff.saturating_mul(2).min(MAX_BACKOFF);
        RetryPlan {
            phase: RetryPhase::Backoff,
            ceiling,
        }
    }
}

async fn retry_sleep(shutdown: &CancellationToken, plan: RetryPlan, stream: &'static str) -> bool {
    let sleep = plan.delay();
    tracing::debug!(
        stream,
        phase = ?plan.phase,
        ceiling_ms = plan.ceiling.as_millis(),
        retry_in_ms = sleep.as_millis(),
        "guest agent reconnect scheduled"
    );
    tokio::select! { _ = shutdown.cancelled() => false, _ = tokio::time::sleep(sleep) => true }
}

async fn connect(machine: &VirtualMachine) -> Result<Channel, tonic::Status> {
    let machine = machine.clone();
    Endpoint::from_static("http://guest-agent.invalid")
        .connect_timeout(Duration::from_secs(5))
        .connect_with_connector(service_fn(move |_| {
            let machine = machine.clone();
            async move {
                machine
                    .connect_vsock(GUEST_CONTROL_PORT)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await
        .map_err(|error| tonic::Status::unavailable(error.to_string()))
}

fn duration(value: Duration) -> prost_types::Duration {
    prost_types::Duration {
        seconds: value.as_secs() as i64,
        nanos: value.subsec_nanos() as i32,
    }
}

fn agent_client(channel: Channel) -> GuestAgentServiceClient<Channel> {
    GuestAgentServiceClient::new(channel)
        .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
        .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::guest::{
        RetryPhase, RetrySchedule, FAST_DISCOVERY_RETRY, FAST_DISCOVERY_WINDOW, INITIAL_BACKOFF,
        MAX_BACKOFF,
    };

    #[test]
    fn initial_discovery_retries_are_bounded_during_fast_window() {
        let started_at = Instant::now();
        let mut retries = RetrySchedule::new(started_at, false);

        for elapsed in [
            Duration::ZERO,
            Duration::from_millis(500),
            FAST_DISCOVERY_WINDOW - Duration::from_nanos(1),
        ] {
            let plan = retries.next(false, started_at + elapsed);
            assert_eq!(plan.phase, RetryPhase::Discovery);
            assert_eq!(plan.ceiling, FAST_DISCOVERY_RETRY);
            assert_eq!(plan.delay(), FAST_DISCOVERY_RETRY);
        }
    }

    #[test]
    fn initial_discovery_transitions_to_exponential_backoff() {
        let started_at = Instant::now();
        let mut retries = RetrySchedule::new(started_at, false);

        let first = retries.next(false, started_at + FAST_DISCOVERY_WINDOW);
        let second = retries.next(false, started_at + FAST_DISCOVERY_WINDOW);

        assert_eq!(first.phase, RetryPhase::Backoff);
        assert_eq!(first.ceiling, INITIAL_BACKOFF);
        assert_eq!(second.ceiling, INITIAL_BACKOFF * 2);
    }

    #[test]
    fn reconnect_uses_exponential_backoff_immediately() {
        let started_at = Instant::now();
        let mut retries = RetrySchedule::new(started_at, true);

        assert_eq!(retries.next(false, started_at).ceiling, INITIAL_BACKOFF);
        assert_eq!(retries.next(false, started_at).ceiling, INITIAL_BACKOFF * 2);
    }

    #[test]
    fn successful_stream_resets_and_caps_reconnect_backoff() {
        let started_at = Instant::now();
        let mut retries = RetrySchedule::new(started_at, true);
        for _ in 0..16 {
            retries.next(false, started_at);
        }
        assert_eq!(retries.next(false, started_at).ceiling, MAX_BACKOFF);

        let reset = retries.next(true, started_at);
        let next = retries.next(false, started_at);
        assert_eq!(reset.ceiling, INITIAL_BACKOFF);
        assert_eq!(next.ceiling, INITIAL_BACKOFF * 2);
    }
}

//! Keeps the guest wall clock pinned to the host.
//!
//! On macOS the guest counter and libkrun's PL031 RTC both follow host uptime,
//! which stops while the Mac sleeps. After a wake the guest `CLOCK_REALTIME`
//! lags by the sleep length and nothing in the guest notices. We push host
//! wall time to the agent:
//!
//! ```text
//!   new agent identity ─┐
//!   host wall jump     ─┼─> SyncPlanner ─> SyncClock RPC ─> agent steps if > 1 s off
//!   every PERIOD       ─┘
//! ```
//!
//! A wake is detected by comparing how far wall time moved against how far the
//! monotonic clock moved between 1 s ticks. Host clock steps trip the same
//! check, which is exactly what we want.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use protocol::v1::guest_agent_service_client::GuestAgentServiceClient;
use protocol::v1::SyncClockRequest;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::state::InstanceStore;
use crate::virt::VirtualMachine;

const TICK: Duration = Duration::from_secs(1);
const PERIOD: Duration = Duration::from_secs(60);
const JUMP_THRESHOLD: Duration = Duration::from_secs(2);
const RPC_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
struct ClockSample {
    mono: Instant,
    wall: SystemTime,
}

impl ClockSample {
    fn now() -> Self {
        Self {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncReason {
    NewAgent,
    HostClockJump,
    Periodic,
}

struct SyncPlanner {
    previous: ClockSample,
    last_sync: Option<Instant>,
    synced_instance: Option<String>,
    unsupported_instance: Option<String>,
    jump_pending: bool,
}

impl SyncPlanner {
    fn new(now: ClockSample) -> Self {
        Self {
            previous: now,
            last_sync: None,
            synced_instance: None,
            unsupported_instance: None,
            jump_pending: false,
        }
    }

    fn next(&mut self, now: ClockSample, instance: Option<&str>) -> Option<SyncReason> {
        if host_clock_jumped(self.previous, now) {
            self.jump_pending = true;
        }
        self.previous = now;
        let instance = instance?;
        if self.unsupported_instance.as_deref() == Some(instance) {
            return None;
        }
        if self.synced_instance.as_deref() != Some(instance) {
            return Some(SyncReason::NewAgent);
        }
        if self.jump_pending {
            return Some(SyncReason::HostClockJump);
        }
        match self.last_sync {
            Some(last) if now.mono.saturating_duration_since(last) < PERIOD => None,
            _ => Some(SyncReason::Periodic),
        }
    }

    fn synced(&mut self, now: Instant, instance: &str) {
        self.synced_instance = Some(instance.to_owned());
        self.last_sync = Some(now);
        self.jump_pending = false;
    }

    fn unsupported(&mut self, instance: &str) {
        self.unsupported_instance = Some(instance.to_owned());
    }
}

fn host_clock_jumped(previous: ClockSample, current: ClockSample) -> bool {
    let (Some(previous_wall), Some(current_wall)) =
        (unix_nanos(previous.wall), unix_nanos(current.wall))
    else {
        return true;
    };
    let mono_delta = i128::try_from(
        current
            .mono
            .saturating_duration_since(previous.mono)
            .as_nanos(),
    )
    .unwrap_or(i128::MAX);
    let wall_delta = current_wall - previous_wall;
    let threshold = i128::try_from(JUMP_THRESHOLD.as_nanos()).unwrap_or(i128::MAX);
    wall_delta.saturating_sub(mono_delta).abs() > threshold
}

fn unix_nanos(time: SystemTime) -> Option<i128> {
    let since_epoch = time.duration_since(UNIX_EPOCH).ok()?;
    i128::try_from(since_epoch.as_nanos()).ok()
}

pub(crate) async fn supervise_clock(
    machine: VirtualMachine,
    store: Arc<InstanceStore>,
    shutdown: CancellationToken,
) {
    let mut planner = SyncPlanner::new(ClockSample::now());
    let mut client: Option<GuestAgentServiceClient<Channel>> = None;
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = interval.tick() => {}
        }
        let instance = match store.agent_instance_id() {
            Ok(instance) => instance,
            Err(error) => {
                tracing::error!(%error, "failed to read guest identity for clock sync");
                return;
            }
        };
        let Some(reason) = planner.next(ClockSample::now(), instance.as_deref()) else {
            continue;
        };
        let Some(instance) = instance else {
            continue;
        };
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = sync_once(&machine, &mut client, &mut planner, reason, &instance) => {}
        }
    }
}

async fn sync_once(
    machine: &VirtualMachine,
    client: &mut Option<GuestAgentServiceClient<Channel>>,
    planner: &mut SyncPlanner,
    reason: SyncReason,
    instance: &str,
) {
    let agent = match client {
        Some(agent) => agent,
        None => match crate::guest::connect(machine).await {
            Ok(channel) => client.insert(crate::guest::agent_client(channel)),
            Err(error) => {
                tracing::debug!(%error, ?reason, "guest clock sync connect failed");
                return;
            }
        },
    };
    let Some(host_time) = timestamp(SystemTime::now()) else {
        tracing::error!("host clock is before the unix epoch; skipping guest clock sync");
        return;
    };
    let request = SyncClockRequest {
        host_time: Some(host_time),
    };
    match tokio::time::timeout(RPC_DEADLINE, agent.sync_clock(request)).await {
        Ok(Ok(response)) => {
            planner.synced(Instant::now(), instance);
            let response = response.into_inner();
            let offset_ms = response.offset.map_or(0, |offset| {
                offset
                    .seconds
                    .saturating_mul(1000)
                    .saturating_add(i64::from(offset.nanos / 1_000_000))
            });
            if response.stepped {
                tracing::info!(
                    ?reason,
                    offset_ms,
                    "stepped guest realtime clock to host time"
                );
            } else {
                tracing::debug!(?reason, offset_ms, "guest realtime clock within tolerance");
            }
        }
        Ok(Err(status)) if status.code() == tonic::Code::Unimplemented => {
            planner.unsupported(instance);
            tracing::info!(
                agent_instance_id = instance,
                "guest agent does not support clock sync"
            );
        }
        Ok(Err(status)) => {
            tracing::debug!(
                ?reason,
                code = ?status.code(),
                message = status.message(),
                "guest clock sync failed"
            );
            *client = None;
        }
        Err(_) => {
            tracing::debug!(?reason, "guest clock sync timed out");
            *client = None;
        }
    }
}

fn timestamp(time: SystemTime) -> Option<prost_types::Timestamp> {
    let since_epoch = time.duration_since(UNIX_EPOCH).ok()?;
    Some(prost_types::Timestamp {
        seconds: i64::try_from(since_epoch.as_secs()).ok()?,
        nanos: i32::try_from(since_epoch.subsec_nanos()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant, UNIX_EPOCH};

    use crate::clock_sync::{host_clock_jumped, ClockSample, SyncPlanner, SyncReason, PERIOD};

    fn base() -> ClockSample {
        ClockSample {
            mono: Instant::now(),
            wall: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        }
    }

    fn advance(sample: ClockSample, mono: Duration, wall: Duration) -> ClockSample {
        ClockSample {
            mono: sample.mono + mono,
            wall: sample.wall + wall,
        }
    }

    fn rewind_wall(sample: ClockSample, mono: Duration, wall: Duration) -> ClockSample {
        ClockSample {
            mono: sample.mono + mono,
            wall: sample.wall - wall,
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn steady_clocks_do_not_jump() {
        let start = base();
        assert!(!host_clock_jumped(start, advance(start, SECOND, SECOND)));
    }

    #[test]
    fn jump_threshold_is_exclusive() {
        let start = base();
        let at_threshold = advance(start, SECOND, Duration::from_secs(3));
        assert!(!host_clock_jumped(start, at_threshold));
        let past_threshold = advance(
            start,
            SECOND,
            Duration::from_secs(3) + Duration::from_nanos(1),
        );
        assert!(host_clock_jumped(start, past_threshold));
    }

    #[test]
    fn wake_from_sleep_is_a_jump() {
        let start = base();
        let woke = advance(start, SECOND, Duration::from_secs(3 * 60 * 60));
        assert!(host_clock_jumped(start, woke));
    }

    #[test]
    fn backwards_host_step_is_a_jump() {
        let start = base();
        let stepped = rewind_wall(start, SECOND, Duration::from_secs(5));
        assert!(host_clock_jumped(start, stepped));
    }

    #[test]
    fn pre_epoch_wall_time_is_a_jump() {
        let start = base();
        let broken = ClockSample {
            mono: start.mono + SECOND,
            wall: UNIX_EPOCH - SECOND,
        };
        assert!(host_clock_jumped(start, broken));
    }

    #[test]
    fn new_agent_then_quiet_then_periodic() {
        let start = base();
        let mut planner = SyncPlanner::new(start);
        let first = advance(start, SECOND, SECOND);
        assert_eq!(planner.next(first, Some("a")), Some(SyncReason::NewAgent));
        planner.synced(first.mono, "a");

        let quiet = advance(first, SECOND, SECOND);
        assert_eq!(planner.next(quiet, Some("a")), None);

        let almost = advance(first, PERIOD - SECOND, PERIOD - SECOND);
        assert_eq!(planner.next(almost, Some("a")), None);

        let due = advance(first, PERIOD, PERIOD);
        assert_eq!(planner.next(due, Some("a")), Some(SyncReason::Periodic));
    }

    #[test]
    fn jump_stays_pending_until_synced() {
        let start = base();
        let mut planner = SyncPlanner::new(start);
        assert_eq!(planner.next(start, Some("a")), Some(SyncReason::NewAgent));
        planner.synced(start.mono, "a");

        let woke = advance(start, SECOND, Duration::from_secs(3600));
        assert_eq!(
            planner.next(woke, Some("a")),
            Some(SyncReason::HostClockJump)
        );
        let retry = advance(woke, SECOND, SECOND);
        assert_eq!(
            planner.next(retry, Some("a")),
            Some(SyncReason::HostClockJump)
        );
        planner.synced(retry.mono, "a");

        let after = advance(retry, SECOND, SECOND);
        assert_eq!(planner.next(after, Some("a")), None);
    }

    #[test]
    fn jump_without_agent_waits_and_new_agent_wins() {
        let start = base();
        let mut planner = SyncPlanner::new(start);
        let woke = advance(start, SECOND, Duration::from_secs(3600));
        assert_eq!(planner.next(woke, None), None);

        let agent = advance(woke, SECOND, SECOND);
        assert_eq!(planner.next(agent, Some("a")), Some(SyncReason::NewAgent));
        planner.synced(agent.mono, "a");

        let after = advance(agent, SECOND, SECOND);
        assert_eq!(planner.next(after, Some("a")), None);
    }

    #[test]
    fn replaced_agent_is_synced_immediately() {
        let start = base();
        let mut planner = SyncPlanner::new(start);
        assert_eq!(planner.next(start, Some("a")), Some(SyncReason::NewAgent));
        planner.synced(start.mono, "a");

        let replaced = advance(start, SECOND, SECOND);
        assert_eq!(
            planner.next(replaced, Some("b")),
            Some(SyncReason::NewAgent)
        );
    }

    #[test]
    fn unsupported_agent_is_left_alone_until_replaced() {
        let start = base();
        let mut planner = SyncPlanner::new(start);
        assert_eq!(planner.next(start, Some("a")), Some(SyncReason::NewAgent));
        planner.unsupported("a");

        let later = advance(start, Duration::from_secs(120), Duration::from_secs(120));
        assert_eq!(planner.next(later, Some("a")), None);
        let woke = advance(later, SECOND, Duration::from_secs(3600));
        assert_eq!(planner.next(woke, Some("a")), None);

        let replaced = advance(woke, SECOND, SECOND);
        assert_eq!(
            planner.next(replaced, Some("b")),
            Some(SyncReason::NewAgent)
        );
    }
}

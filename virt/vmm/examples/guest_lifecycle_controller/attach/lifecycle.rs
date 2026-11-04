//! Exact Freeze/Activate/Thaw RPCs with independent kernel observations.

use std::future::Future;
use std::time::Duration;

use protocol::v1;
use serde::{Deserialize, Serialize};

use crate::attach::dto::{
    monotonic_ns, Checks, Discard, EnvironmentVariable, ExpectRpc, FreezeRef, Identity, Lifecycle,
    LifecycleState, ListenRegistration, RpcError, RpcOutcome, RpcRecord,
};
use crate::attach::observe::{CgroupGroup, Guest, Observation, Observe};

const DISCARD_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreezeRequest {
    pub(crate) expected: Identity,
    pub(crate) freeze_ref: FreezeRef,
    #[serde(default)]
    pub(crate) deadline_ms: Option<u32>,
}

impl FreezeRequest {
    fn to_wire(&self) -> v1::FreezeWorkloadsRequest {
        v1::FreezeWorkloadsRequest {
            expected: Some((&self.expected).into()),
            freeze_ref: Some((&self.freeze_ref).into()),
            deadline_ms: self.deadline_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreezeOperation {
    pub(crate) request: FreezeRequest,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
    #[serde(default)]
    pub(crate) observe: Observe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThawRequest {
    pub(crate) expected: Identity,
    pub(crate) freeze_ref: FreezeRef,
    pub(crate) rollback: bool,
    #[serde(default)]
    pub(crate) deadline_ms: Option<u32>,
}

impl ThawRequest {
    fn to_wire(&self) -> v1::ThawRequest {
        v1::ThawRequest {
            expected: Some((&self.expected).into()),
            freeze_ref: Some((&self.freeze_ref).into()),
            rollback: self.rollback,
            deadline_ms: self.deadline_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThawOperation {
    pub(crate) request: ThawRequest,
    #[serde(default)]
    pub(crate) lost_reply: bool,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
    #[serde(default)]
    pub(crate) observe: Observe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationNetwork {
    pub(crate) mac: String,
    pub(crate) ipv4: String,
    pub(crate) prefix_length: u32,
    pub(crate) gateway: String,
    pub(crate) dns_servers: Vec<String>,
    pub(crate) dns_search: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationListener {
    pub(crate) name: String,
    pub(crate) registration: ListenRegistration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationHook {
    pub(crate) argv: Vec<String>,
    pub(crate) environment: Vec<EnvironmentVariable>,
    pub(crate) working_directory: String,
    #[serde(default)]
    pub(crate) timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostTime {
    pub(crate) seconds: i64,
    pub(crate) nanos: i32,
}

impl HostTime {
    /// Host CLOCK_REALTIME sampled immediately before the call.
    fn now() -> eyre::Result<Self> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        Ok(Self {
            seconds: i64::try_from(elapsed.as_secs())?,
            nanos: i32::try_from(elapsed.subsec_nanos())?,
        })
    }
}

/// Every `ActivateRequest` field; replay resends this DTO byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivateRequest {
    pub(crate) activation_id: String,
    pub(crate) expected: Identity,
    pub(crate) freeze_ref: FreezeRef,
    pub(crate) destination_machine_id: String,
    pub(crate) destination_run_id: String,
    pub(crate) network: Option<ActivationNetwork>,
    pub(crate) listeners: Vec<ActivationListener>,
    pub(crate) hook: Option<ActivationHook>,
    pub(crate) host_time: Option<HostTime>,
    pub(crate) shutdown_manifest_json: String,
    #[serde(default)]
    pub(crate) deadline_ms: Option<u32>,
}

impl ActivateRequest {
    /// Fills only an absent host time; an explicit one is preserved exactly.
    fn resolve(&self) -> eyre::Result<Self> {
        let mut resolved = self.clone();
        if resolved.host_time.is_none() {
            resolved.host_time = Some(HostTime::now()?);
        }
        Ok(resolved)
    }

    fn to_wire(&self) -> eyre::Result<v1::ActivateRequest> {
        Ok(v1::ActivateRequest {
            activation_id: self.activation_id.clone(),
            expected: Some((&self.expected).into()),
            freeze_ref: Some((&self.freeze_ref).into()),
            destination_machine_id: self.destination_machine_id.clone(),
            destination_run_id: self.destination_run_id.clone(),
            network: self.network.as_ref().map(|network| v1::ActivationNetwork {
                mac: network.mac.clone(),
                ipv4: network.ipv4.clone(),
                prefix_length: network.prefix_length,
                gateway: network.gateway.clone(),
                dns_servers: network.dns_servers.clone(),
                dns_search: network.dns_search.clone(),
            }),
            listeners: self
                .listeners
                .iter()
                .map(|listener| {
                    Ok(v1::ActivationListener {
                        name: listener.name.clone(),
                        registration: Some(listener.registration.to_wire()?),
                    })
                })
                .collect::<eyre::Result<_>>()?,
            hook: self.hook.as_ref().map(|hook| v1::ActivationHook {
                argv: hook.argv.clone(),
                environment: hook.environment.iter().map(Into::into).collect(),
                working_directory: hook.working_directory.clone(),
                timeout_ms: hook.timeout_ms,
            }),
            host_time: self.host_time.map(|time| prost_types::Timestamp {
                seconds: time.seconds,
                nanos: time.nanos,
            }),
            shutdown: Some(v1::ActivationShutdownContext {
                manifest_json: self.shutdown_manifest_json.clone().into_bytes(),
            }),
            deadline_ms: self.deadline_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivateOperation {
    pub(crate) request: ActivateRequest,
    #[serde(default)]
    pub(crate) lost_reply: bool,
    #[serde(default)]
    pub(crate) expect_rpc: ExpectRpc,
    #[serde(default)]
    pub(crate) observe: Observe,
}

#[derive(Debug, Serialize)]
pub(crate) struct LifecycleResponse {
    pub(crate) status: Option<Lifecycle>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BoundListener {
    pub(crate) name: String,
    pub(crate) address: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActivateResponse {
    pub(crate) identity: Option<Identity>,
    pub(crate) freeze_ref: Option<FreezeRef>,
    pub(crate) listeners: Vec<BoundListener>,
    pub(crate) status: Option<Lifecycle>,
}

impl From<&v1::ActivateResponse> for ActivateResponse {
    fn from(value: &v1::ActivateResponse) -> Self {
        Self {
            identity: value.identity.as_ref().map(Identity::from),
            freeze_ref: value.freeze_ref.as_ref().map(FreezeRef::from),
            listeners: value
                .listeners
                .iter()
                .map(|listener| BoundListener {
                    name: listener.name.clone(),
                    address: listener.bound.as_ref().map(|bound| bound.address.clone()),
                })
                .collect(),
            status: value.status.as_ref().map(Lifecycle::from),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct LifecycleOutput {
    pub(crate) rpc: RpcRecord<LifecycleResponse>,
    pub(crate) observation: Observation,
}

#[derive(Debug, Serialize)]
pub(crate) struct ActivateOutput {
    pub(crate) resolved_request: ActivateRequest,
    pub(crate) rpc: RpcRecord<ActivateResponse>,
    pub(crate) observation: Observation,
}

fn record<R>(
    started: u64,
    finished: u64,
    request_debug: String,
    result: Result<(R, String), tonic::Status>,
) -> RpcRecord<R> {
    match result {
        Ok((response, debug)) => RpcRecord {
            outcome: RpcOutcome::Ok,
            started_monotonic_ns: started,
            finished_monotonic_ns: finished,
            request_debug,
            response: Some(response),
            response_debug: Some(debug),
            error: None,
            discard: None,
        },
        Err(status) => RpcRecord {
            outcome: RpcOutcome::Error,
            started_monotonic_ns: started,
            finished_monotonic_ns: finished,
            request_debug,
            response: None,
            response_debug: None,
            error: Some(RpcError::from(&status)),
            discard: None,
        },
    }
}

fn json(value: &impl Serialize) -> serde_json::Value {
    serde_json::to_value(value)
        .unwrap_or_else(|error| serde_json::Value::String(format!("unserializable: {error}")))
}

/// Drops an in-flight reply unread once `probe` independently observes the
/// guest-side effect. If the reply arrives first and the effect is still not
/// visible, it stops with `effect_observed: false` (reply still unread) so the
/// failure evidence is retained instead of spinning to the attach deadline.
async fn discard_after<T, F, Probe>(
    reply: tokio::task::JoinHandle<T>,
    mut probe: F,
) -> eyre::Result<Discard>
where
    F: FnMut() -> Probe,
    Probe: Future<Output = (bool, serde_json::Value)>,
{
    loop {
        // Sampled before probing, so a probe after the reply sees its effect.
        let reply_finished = reply.is_finished();
        let (effect_observed, observed) = probe().await;
        if effect_observed || reply_finished {
            let observed_monotonic_ns = monotonic_ns()?;
            let reply_task_finished_before_discard = reply.is_finished();
            reply.abort();
            return Ok(Discard {
                effect_observed,
                observed,
                observed_monotonic_ns,
                reply_task_finished_before_discard,
            });
        }
        tokio::time::sleep(DISCARD_POLL).await;
    }
}

fn discarded<R>(started: u64, request_debug: String, discard: Discard) -> RpcRecord<R> {
    RpcRecord {
        outcome: RpcOutcome::Discarded,
        started_monotonic_ns: started,
        finished_monotonic_ns: discard.observed_monotonic_ns,
        request_debug,
        response: None,
        response_debug: None,
        error: None,
        discard: Some(discard),
    }
}

fn kernel_frozen(observation: &Observation) -> Option<bool> {
    observation
        .cgroup(CgroupGroup::Workloads)
        .and_then(|events| events.frozen)
}

pub(crate) async fn freeze(
    guest: &Guest,
    operation: &FreezeOperation,
    checks: &mut Checks,
) -> eyre::Result<LifecycleOutput> {
    let request = operation.request.to_wire();
    let started = monotonic_ns()?;
    let result = guest.agent().freeze_workloads(request.clone()).await;
    let finished = monotonic_ns()?;
    let observe = operation.observe.with_workloads();
    let observation = guest.observe(&observe).await?;
    let rpc = record(
        started,
        finished,
        format!("{request:?}"),
        result.map(|response| {
            let response = response.into_inner();
            let debug = format!("{response:?}");
            (
                LifecycleResponse {
                    status: response.status.as_ref().map(Lifecycle::from),
                },
                debug,
            )
        }),
    );
    if let Some(actual) = rpc.actual() {
        operation.expect_rpc.evaluate(actual, checks);
    }
    if let Some(response) = &rpc.response {
        let status = response.status.as_ref();
        checks.check(
            "freeze_status_frozen",
            status.and_then(|status| status.state) == Some(LifecycleState::Frozen),
            format!("{:?}", status.map(|status| status.state)),
        );
        checks.check(
            "freeze_ref_exact",
            status.and_then(|status| status.freeze_ref.as_ref())
                == Some(&operation.request.freeze_ref),
            format!("{:?}", status.map(|status| &status.freeze_ref)),
        );
        checks.check(
            "kernel_frozen",
            kernel_frozen(&observation) == Some(true),
            format!("{:?}", kernel_frozen(&observation)),
        );
        checks.check(
            "frozen_not_ready",
            observation.status().is_some_and(|status| !status.ready()),
            format!(
                "{:?}",
                observation.status().map(|status| &status.report_state)
            ),
        );
    }
    observation.evaluate(&observe, checks);
    Ok(LifecycleOutput { rpc, observation })
}

pub(crate) async fn thaw(
    guest: &Guest,
    operation: &ThawOperation,
    checks: &mut Checks,
) -> eyre::Result<LifecycleOutput> {
    let request = operation.request.to_wire();
    let started = monotonic_ns()?;
    let rpc = if operation.lost_reply {
        let mut client = guest.agent();
        let call = request.clone();
        let reply = tokio::spawn(async move { client.thaw(call).await });
        // Intentionally discard this exact reply after independently observing
        // the real kernel thaw event, exactly like the cold lost-reply oracle.
        let discard = discard_after(reply, move || async move {
            let events = guest.cgroup(CgroupGroup::Workloads).await;
            (events.frozen == Some(false), json(&events))
        })
        .await?;
        discarded(started, format!("{request:?}"), discard)
    } else {
        let result = guest.agent().thaw(request.clone()).await;
        let finished = monotonic_ns()?;
        record(
            started,
            finished,
            format!("{request:?}"),
            result.map(|response| {
                let response = response.into_inner();
                let debug = format!("{response:?}");
                (
                    LifecycleResponse {
                        status: response.status.as_ref().map(Lifecycle::from),
                    },
                    debug,
                )
            }),
        )
    };
    let observe = operation.observe.with_workloads();
    let observation = guest.observe(&observe).await?;
    match rpc.actual() {
        Some(actual) => operation.expect_rpc.evaluate(actual, checks),
        None => checks.check(
            "reply_discarded_after_kernel_thaw",
            rpc.discard
                .as_ref()
                .is_some_and(|discard| discard.effect_observed),
            "kernel frozen=0 observed before discarding the unread reply",
        ),
    }
    if let Some(response) = &rpc.response {
        let status = response.status.as_ref();
        if !operation.request.rollback {
            checks.check(
                "thaw_status_thawed",
                status.and_then(|status| status.state) == Some(LifecycleState::Thawed),
                format!("{:?}", status.map(|status| status.state)),
            );
        }
        checks.check(
            "kernel_thawed",
            kernel_frozen(&observation) == Some(false),
            format!("{:?}", kernel_frozen(&observation)),
        );
    }
    observation.evaluate(&observe, checks);
    Ok(LifecycleOutput { rpc, observation })
}

pub(crate) async fn activate(
    guest: &Guest,
    operation: &ActivateOperation,
    checks: &mut Checks,
) -> eyre::Result<ActivateOutput> {
    let resolved = operation.request.resolve()?;
    let request = resolved.to_wire()?;
    let started = monotonic_ns()?;
    let rpc = if operation.lost_reply {
        let mut client = guest.agent();
        let call = request.clone();
        let reply = tokio::spawn(async move { client.activate(call).await });
        // The spawned guest coordinator survives RPC loss; observe its terminal
        // state for this exact activation, then drop the reply unread.
        let activation_id = &resolved.activation_id;
        let discard = discard_after(reply, move || async move {
            let status = guest.status().await;
            let lifecycle = status
                .status
                .as_ref()
                .and_then(|status| status.lifecycle.as_ref());
            let terminal = lifecycle.is_some_and(|lifecycle| {
                lifecycle.activation_id.as_ref() == Some(activation_id)
                    && matches!(
                        lifecycle.state,
                        Some(LifecycleState::ActivatedFrozen | LifecycleState::ActivationFailed)
                    )
            });
            (terminal, json(&status))
        })
        .await?;
        discarded(started, format!("{request:?}"), discard)
    } else {
        let result = guest.agent().activate(request.clone()).await;
        let finished = monotonic_ns()?;
        record(
            started,
            finished,
            format!("{request:?}"),
            result.map(|response| {
                let response = response.into_inner();
                (ActivateResponse::from(&response), format!("{response:?}"))
            }),
        )
    };
    let observe = operation.observe.with_workloads();
    let observation = guest.observe(&observe).await?;
    match rpc.actual() {
        Some(actual) => operation.expect_rpc.evaluate(actual, checks),
        None => checks.check(
            "reply_discarded_after_terminal_status",
            rpc.discard
                .as_ref()
                .is_some_and(|discard| discard.effect_observed),
            "activation_id terminal lifecycle observed before discarding the unread reply",
        ),
    }
    if let Some(response) = &rpc.response {
        activation_checks(&resolved, response, &observation, checks);
    }
    observation.evaluate(&observe, checks);
    Ok(ActivateOutput {
        resolved_request: resolved,
        rpc,
        observation,
    })
}

/// Invariants of every successful activation response, including exact replays.
fn activation_checks(
    request: &ActivateRequest,
    response: &ActivateResponse,
    observation: &Observation,
    checks: &mut Checks,
) {
    let identity = response.identity.as_ref();
    checks.check(
        "destination_identity",
        identity.is_some_and(|identity| {
            identity.machine_id == request.destination_machine_id
                && identity.run_id == request.destination_run_id
        }),
        format!("{identity:?}"),
    );
    checks.check(
        "boot_preserved",
        identity.is_some_and(|identity| identity.boot_id == request.expected.boot_id),
        format!(
            "expected {}, got {:?}",
            request.expected.boot_id,
            identity.map(|identity| &identity.boot_id)
        ),
    );
    checks.check(
        "agent_instance_rotated",
        identity.is_some_and(|identity| {
            identity.agent_instance_id != request.expected.agent_instance_id
        }),
        format!(
            "source {}, got {:?}",
            request.expected.agent_instance_id,
            identity.map(|identity| &identity.agent_instance_id)
        ),
    );
    let destination_ref = FreezeRef {
        machine_id: request.destination_machine_id.clone(),
        run_id: request.destination_run_id.clone(),
        operation_id: request.freeze_ref.operation_id.clone(),
        freeze_epoch: request.freeze_ref.freeze_epoch,
    };
    checks.check(
        "freeze_ref_destination_bound",
        response.freeze_ref.as_ref() == Some(&destination_ref),
        format!(
            "expected {destination_ref:?}, got {:?}",
            response.freeze_ref
        ),
    );
    let status = response.status.as_ref();
    checks.check(
        "status_activated_frozen",
        status.is_some_and(|status| {
            status.state == Some(LifecycleState::ActivatedFrozen)
                && status.activation_id.as_ref() == Some(&request.activation_id)
                && status.freeze_ref.as_ref() == Some(&destination_ref)
        }),
        format!("{status:?}"),
    );
    let requested: Vec<_> = request
        .listeners
        .iter()
        .map(|listener| &listener.name)
        .collect();
    let bound: Vec<_> = response
        .listeners
        .iter()
        .map(|listener| &listener.name)
        .collect();
    checks.check(
        "listeners_bound",
        requested == bound
            && response
                .listeners
                .iter()
                .all(|listener| listener.address.is_some()),
        format!("requested {requested:?}, bound {:?}", response.listeners),
    );
    checks.check(
        "kernel_still_frozen",
        kernel_frozen(observation) == Some(true),
        format!("{:?}", kernel_frozen(observation)),
    );
    let observed = observation.status();
    checks.check(
        "activated_not_ready",
        observed.is_some_and(|status| !status.ready()),
        format!("{:?}", observed.map(|status| &status.report_state)),
    );
    checks.check(
        "observed_identity_rotated",
        observed.and_then(|status| status.expected_identity.as_ref()) == identity,
        format!("{:?}", observed.map(|status| &status.expected_identity)),
    );
}

#[cfg(test)]
mod tests {
    use crate::attach::lifecycle::{ActivateOperation, ActivateRequest};

    const REQUEST: &str = r#"{
        "activation_id":"7d4f2d2a-6c1e-4d0b-9b8a-2f6f7d1a0c01",
        "expected":{"machine_id":"a","run_id":"b","agent_instance_id":"c","boot_id":"d"},
        "freeze_ref":{"machine_id":"a","run_id":"b","operation_id":"e","freeze_epoch":1},
        "destination_machine_id":"f","destination_run_id":"g",
        "network":{"mac":"02:00:00:00:00:02","ipv4":"192.168.128.2","prefix_length":24,
                   "gateway":"192.168.128.1","dns_servers":["192.168.128.1"],"dns_search":[]},
        "listeners":[{"name":"svc","registration":{"listen":"tcp:0.0.0.0:8080",
                      "token_hex":"000102030405060708090a0b0c0d0e0f","unix_mode":null}}],
        "hook":{"argv":["/bin/true"],"environment":[{"name":"K","value":"V"}],
                "working_directory":"/","timeout_ms":5000},
        "host_time":null,
        "shutdown_manifest_json":"{\"version\":1}",
        "deadline_ms":30000}"#;

    #[test]
    fn resolution_samples_only_absent_host_time_and_replays_exactly() {
        let request: ActivateRequest = serde_json::from_str(REQUEST).unwrap();
        let resolved = request.resolve().unwrap();
        assert!(resolved.host_time.is_some());
        assert_eq!(resolved.resolve().unwrap(), resolved);
        let encoded = serde_json::to_string(&resolved).unwrap();
        let replay: ActivateRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(replay, resolved);
        assert_eq!(replay.to_wire().unwrap(), resolved.to_wire().unwrap());
    }

    #[test]
    fn activation_requests_reject_unknown_fields_and_bad_tokens() {
        let operation = format!(r#"{{"request":{REQUEST},"extra":true}}"#);
        assert!(serde_json::from_str::<ActivateOperation>(&operation).is_err());
        let mut request: ActivateRequest = serde_json::from_str(REQUEST).unwrap();
        request.listeners[0].registration.token_hex = "0g".into();
        assert!(request.to_wire().is_err());
    }
}

//! The monitor's sole restore activation owner (ADR 0021 `Activation`).
//!
//! ```text
//!  Restoring ─prepared─► Activating
//!     fresh generation + vCPU release + exact ack (5 s absolute)
//!     source-bound handshake (seal machine/run/freeze ref, positively frozen)
//!     Activate (30 s) ─► stage guest listeners, bind host listeners and the
//!       vsock surface, no accept ─► Thaw (exact ack) ─► alive
//!     exposure commit (last) ─► serve, accept, gate open, Running, started
//!  any failure ─► close listeners ─► [re-freeze] ─► private park ─► ActivationFailed
//!                                  └─ park/freeze not re-established ─► kill + reap
//!  exposure possibly committed, or stop requested ─► kill + reap
//! ```
//! Every fallible step precedes the commit; nothing after it can fail
//! activation. Host admission stays closed until the commit.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use protocol::v1::{
    ActivateRequest, ActivateResponse, ActivationHook, ActivationListenerBound, ActivationNetwork,
    ActivationShutdownContext, EnvironmentVariable, ExpectedGuestIdentity, FreezeRef,
    FreezeWorkloadsRequest, GuestLifecycleStatus, ThawRequest,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vm_spec::lifecycle::{GuestLifecycleState, LiveLifecycle, VmLifecycleState};
use vm_spec::restore::RestoreRequest;

use crate::context::DaemonContext;
use crate::state::{LiveTransition, ReadyAgentIdentity};
use crate::virt::lifecycle::{
    ActivationExposure, ActivationStage, CommandOutcome, CommandState, LifecycleCommand,
    LifecycleError, LifecycleRequest,
};

const GENERATION_TIMEOUT: Duration =
    Duration::from_millis(vm_spec::restore::GENERATION_ACK_TIMEOUT_MS);
const ACTIVATE_TIMEOUT: Duration = Duration::from_millis(vm_spec::restore::ACTIVATE_TIMEOUT_MS);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const THAW_TIMEOUT: Duration = Duration::from_secs(15);
const NATIVE_TIMEOUT: Duration = Duration::from_secs(30);
const GUEST_DEADLINE_MS: u32 = 5_000;
const RETRY_DELAY: Duration = Duration::from_millis(200);
const NATIVE_TRANSPORT_RETRIES: u32 = 3;

/// Inputs bound at startup, validated before launch; consumed exactly once.
pub(crate) struct Activation {
    request: RestoreRequest,
    activation: Uuid,
    machine: Uuid,
    run: Uuid,
    /// The destination's public SSH CA; never a source secret.
    ssh_trusted_ca: String,
    shutdown_manifest: Vec<u8>,
    /// The public vsock surface: bound after Activate, served after commit.
    vsock_filename: Option<PathBuf>,
}

pub(crate) enum Activated {
    /// Exposure committed; the machine is Running and accepting.
    Running(Option<crate::vsock::VsockSurface>),
    /// Positively parked and fenced; stop is the only transition.
    Failed(String),
}

#[derive(Debug)]
struct Failure {
    stage: ActivationStage,
    code: &'static str,
    detail: String,
    cpus_released: bool,
    /// The destination workload may have run: re-freeze it before parking.
    thawed: Option<Box<(ExpectedGuestIdentity, FreezeRef)>>,
}

impl Failure {
    fn after_thaw(self, identity: &ExpectedGuestIdentity, reference: &FreezeRef) -> Self {
        Self {
            thawed: Some(Box::new((identity.clone(), reference.clone()))),
            ..self
        }
    }

    /// The single consumer-visible failure message (syncpipe, store, smoke).
    fn message(&self) -> String {
        format!(
            "restore activation failed: stage={} code={}: {}",
            stage_name(self.stage),
            self.code,
            self.detail
        )
    }
}

/// Why the sequence stopped short of Running.
#[derive(Debug)]
enum Abort {
    /// Exposure is still fenced: settle into ActivationFailed, or reap when
    /// the fenced park cannot be re-established.
    Fenced(Failure),
    /// Exposure may have committed: never labelled fenced; kill and reap.
    Uncertain(String),
}

impl From<Failure> for Abort {
    fn from(failure: Failure) -> Self {
        Self::Fenced(failure)
    }
}

fn fail(stage: ActivationStage, code: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        stage,
        code,
        detail: detail.into(),
        cpus_released: true,
        thawed: None,
    }
}

fn stage_name(stage: ActivationStage) -> &'static str {
    match stage {
        ActivationStage::PrepareGeneration => "prepare_generation",
        ActivationStage::ReleaseCpus => "release_cpus",
        ActivationStage::Acknowledgement => "acknowledgement",
        ActivationStage::Exposure => "exposure",
        ActivationStage::Park => "park",
    }
}

/// Native reconciled every provider fence closed.
fn fenced(exposure: ActivationExposure) -> bool {
    matches!(
        exposure,
        ActivationExposure::Fenced | ActivationExposure::Sealed
    )
}

/// Guest transport failures an identical replay may resolve.
fn retryable(code: tonic::Code) -> bool {
    matches!(
        code,
        tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Cancelled
    )
}

fn ready_identity(identity: &ExpectedGuestIdentity) -> Option<ReadyAgentIdentity> {
    Some(ReadyAgentIdentity {
        instance_id: Uuid::parse_str(&identity.agent_instance_id).ok()?,
        boot_id: Uuid::parse_str(&identity.boot_id).ok()?,
    })
}

/// The inherited agent, still frozen at exactly the sealed source reference
/// with every workload root observed frozen. Another reference is a refusal.
fn source_frozen(
    status: &GuestLifecycleStatus,
    reference: &FreezeRef,
    epoch: NonZeroU64,
) -> Result<bool, String> {
    match status.freeze_ref.as_ref() {
        Some(actual) if actual != reference => {
            Err("restored agent is frozen under another source reference".into())
        }
        Some(_) => Ok(crate::live::coordinator::guest_observation(status)
            .is_ok_and(|observation| observation.positively_frozen(epoch))),
        None => Ok(false),
    }
}

/// The destination guest after an exact Activate reply.
#[derive(Debug, Clone, PartialEq)]
struct ActivatedGuest {
    identity: ExpectedGuestIdentity,
    agent: ReadyAgentIdentity,
    reference: FreezeRef,
    listeners: Vec<ActivationListenerBound>,
}

/// An Activate reply is accepted only as the exact activated-frozen
/// destination: new machine/run, rotated agent instance on the same boot,
/// the original operation/epoch rebound to the destination, every workload
/// root still frozen and one bound listener per requested name.
fn verify_activation(
    request: &ActivateRequest,
    response: ActivateResponse,
    source: &ReadyAgentIdentity,
) -> Result<ActivatedGuest, Failure> {
    let mismatch = |detail: &str| {
        fail(
            ActivationStage::Exposure,
            "guest-identity-mismatch",
            detail.to_string(),
        )
    };
    let identity = response
        .identity
        .ok_or_else(|| mismatch("activate reply lacks identity"))?;
    let reference = response
        .freeze_ref
        .ok_or_else(|| mismatch("activate reply lacks freeze reference"))?;
    let status = response
        .status
        .ok_or_else(|| mismatch("activate reply lacks lifecycle status"))?;
    let source_ref = request
        .freeze_ref
        .as_ref()
        .ok_or_else(|| mismatch("activate request lacks its source reference"))?;
    let agent = ready_identity(&identity)
        .ok_or_else(|| mismatch("activate reply identity is not canonical"))?;
    let destination = (
        request.destination_machine_id.as_str(),
        request.destination_run_id.as_str(),
    );
    let exact = (identity.machine_id.as_str(), identity.run_id.as_str()) == destination
        && agent.boot_id == source.boot_id
        && agent.instance_id != source.instance_id
        && (reference.machine_id.as_str(), reference.run_id.as_str()) == destination
        && reference.operation_id == source_ref.operation_id
        && reference.freeze_epoch == source_ref.freeze_epoch
        && status.freeze_ref.as_ref() == Some(&reference)
        && status.state == protocol::v1::GuestLifecycleState::ActivatedFrozen as i32
        && status.activation_id.as_deref() == Some(request.activation_id.as_str())
        && crate::live::coordinator::guest_observation(&status).is_ok()
        && !status.workload_roots.is_empty()
        && status.workload_roots == status.observed_frozen_roots
        && response.listeners.len() == request.listeners.len()
        && request.listeners.iter().all(|listener| {
            response
                .listeners
                .iter()
                .filter(|bound| bound.name == listener.name)
                .count()
                == 1
        });
    if !exact {
        return Err(mismatch(
            "activate reply is not the exact activated-frozen destination",
        ));
    }
    Ok(ActivatedGuest {
        identity,
        agent,
        reference,
        listeners: response.listeners,
    })
}

/// Exact Thawed acknowledgement of the destination reference.
fn thawed_exactly(status: &GuestLifecycleStatus, reference: &FreezeRef) -> bool {
    status.freeze_ref.as_ref() == Some(reference)
        && status.state == protocol::v1::GuestLifecycleState::Thawed as i32
        && crate::live::coordinator::guest_observation(status).is_ok()
}

impl Activation {
    /// Bind and validate every activation input before the launch, so a
    /// refusal happens before any guest instruction.
    pub(crate) fn new(
        request: RestoreRequest,
        machine: Uuid,
        run: Uuid,
        shutdown: &protocol::shutdown::StorageShutdownContext,
        vsock_filename: Option<PathBuf>,
    ) -> eyre::Result<Self> {
        let activation = Uuid::parse_str(request.activation_id.as_str())
            .map_err(|error| eyre::eyre!("restore activation ID: {error}"))?;
        let ssh_trusted_ca =
            crate::start_request::destination_ssh_ca(request.ssh_trusted_ca.as_deref())?
                .to_string();
        let shutdown_manifest = serde_json::to_vec(&shutdown.manifest)
            .map_err(|error| eyre::eyre!("encode restore shutdown manifest: {error}"))?;
        protocol::shutdown::manifest_from_json(&shutdown_manifest)
            .map_err(|error| eyre::eyre!("restore shutdown manifest: {error}"))?;
        Ok(Self {
            request,
            activation,
            machine,
            run,
            ssh_trusted_ca,
            shutdown_manifest,
            vsock_filename,
        })
    }

    pub(crate) fn activation_id(&self) -> Uuid {
        self.activation
    }

    fn publish(&self, ctx: &DaemonContext, state: VmLifecycleState, message: String, parked: bool) {
        let transition = LiveTransition {
            state,
            lifecycle: LiveLifecycle::default(),
            message,
            held_identity: None,
            parked,
            readiness_probe: false,
        };
        if let Err(error) = ctx.store.publish_live(transition) {
            tracing::error!(%error, "restore state publication failed");
        }
    }

    /// One native activation command to its terminal outcome. Accepted and
    /// transport uncertainty replay the identical request, which joins.
    async fn native(
        &self,
        ctx: &DaemonContext,
        cancel: &CancellationToken,
        command: LifecycleCommand,
    ) -> Result<CommandOutcome, String> {
        let request = LifecycleRequest {
            machine_id: self.machine,
            run_id: self.run,
            request_id: self.activation,
            command,
        };
        let mut transport = 0;
        loop {
            let response = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err("startup cancelled".into()),
                response = ctx.machine.lifecycle(request.clone()) => response,
            };
            match response {
                Ok(response) => match response.command.map(|report| report.state) {
                    Some(CommandState::Completed { outcome }) => return Ok(outcome),
                    Some(CommandState::Accepted) => {}
                    None => return Err("native report omitted the command".into()),
                },
                Err(LifecycleError::Unknown(uncertainty))
                    if transport < NATIVE_TRANSPORT_RETRIES =>
                {
                    transport += 1;
                    tracing::warn!(%uncertainty, "restore native command uncertain; replaying");
                }
                Err(error) => return Err(error.to_string()),
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    fn source_freeze_ref(&self) -> Result<(FreezeRef, NonZeroU64), Failure> {
        let evidence = &self.request.evidence;
        let epoch = evidence.freeze_epoch.ok_or_else(|| {
            fail(
                ActivationStage::Acknowledgement,
                "handshake-failed",
                "seal has no freeze epoch",
            )
        })?;
        Ok((
            FreezeRef {
                machine_id: evidence.machine_id.as_str().to_string(),
                run_id: evidence.run_id.as_str().to_string(),
                operation_id: self.request.freeze_operation_id.as_str().to_string(),
                freeze_epoch: Some(epoch.get()),
            },
            epoch,
        ))
    }

    /// The inherited agent, still source-bound and frozen at the exact sealed
    /// reference, observed over the recreated control-only transport.
    async fn handshake(
        &self,
        ctx: &DaemonContext,
        cancel: &CancellationToken,
        reference: &FreezeRef,
        epoch: NonZeroU64,
    ) -> Result<ReadyAgentIdentity, Failure> {
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let mut changes = ctx.store.subscribe();
        loop {
            changes.borrow_and_update();
            let observed = ctx.store.shutdown_agent_identity().ok();
            let lifecycle = ctx
                .store
                .live_snapshot()
                .ok()
                .and_then(|snapshot| snapshot.guest_lifecycle);
            if let (Some(identity), Some(status)) = (observed, lifecycle) {
                match source_frozen(&status, reference, epoch) {
                    Ok(true) => return Ok(identity),
                    Ok(false) => {}
                    Err(detail) => {
                        return Err(fail(
                            ActivationStage::Acknowledgement,
                            "guest-identity-mismatch",
                            detail,
                        ))
                    }
                }
            }
            tokio::select! {
                () = cancel.cancelled() => return Err(fail(ActivationStage::Acknowledgement, "stopped", "startup cancelled")),
                () = tokio::time::sleep_until(deadline) => return Err(fail(
                    ActivationStage::Acknowledgement,
                    "handshake-failed",
                    "restored agent did not report the sealed frozen reference",
                )),
                changed = changes.changed() => if changed.is_err() {
                    return Err(fail(ActivationStage::Acknowledgement, "stopped", "status owner stopped"));
                },
            }
        }
    }

    fn activate_request(
        &self,
        ctx: &DaemonContext,
        expected: ExpectedGuestIdentity,
        reference: FreezeRef,
    ) -> ActivateRequest {
        let network = self
            .request
            .network
            .as_ref()
            .map(|network| ActivationNetwork {
                mac: network.mac.clone(),
                ipv4: network.ipv4.to_string(),
                prefix_length: u32::from(network.prefix_length),
                gateway: network.gateway.to_string(),
                dns_servers: network
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                dns_search: network.dns_search.clone(),
            });
        let hook = self.request.hook.as_ref().map(|hook| ActivationHook {
            argv: hook.argv.clone(),
            environment: hook
                .environment
                .iter()
                .map(|variable| EnvironmentVariable {
                    name: variable.name.clone(),
                    value: variable.value.clone(),
                })
                .collect(),
            working_directory: hook.working_directory.clone(),
            timeout_ms: Some(hook.timeout_ms),
        });
        ActivateRequest {
            activation_id: self.activation.hyphenated().to_string(),
            expected: Some(expected),
            freeze_ref: Some(reference),
            destination_machine_id: self.machine.hyphenated().to_string(),
            destination_run_id: self.run.hyphenated().to_string(),
            network,
            listeners: ctx.forwards.activation_listeners(),
            hook,
            // Sampled once: an identical replay stays identical.
            host_time: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            shutdown: Some(ActivationShutdownContext {
                manifest_json: self.shutdown_manifest.clone(),
            }),
            deadline_ms: Some(
                u32::try_from(vm_spec::restore::ACTIVATE_TIMEOUT_MS).unwrap_or(u32::MAX),
            ),
            ssh_trusted_ca: Some(self.ssh_trusted_ca.clone()),
        }
    }

    /// Bounded Activate with identical replays inside the original deadline.
    async fn activate(
        &self,
        ctx: &DaemonContext,
        cancel: &CancellationToken,
        request: &ActivateRequest,
        source: &ReadyAgentIdentity,
    ) -> Result<ActivatedGuest, Failure> {
        let deadline = tokio::time::Instant::now() + ACTIVATE_TIMEOUT;
        let mut last = String::from("activate not acknowledged before its deadline");
        loop {
            let attempt = async {
                let channel = crate::guest::connect(&ctx.machine).await?;
                crate::guest::agent_client(channel)
                    .activate(request.clone())
                    .await
            };
            let result = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(fail(ActivationStage::Exposure, "stopped", "startup cancelled")),
                result = tokio::time::timeout_at(deadline, attempt) => result,
            };
            match result {
                Err(_) => return Err(fail(ActivationStage::Exposure, "deadline-exceeded", last)),
                Ok(Ok(response)) => {
                    return verify_activation(request, response.into_inner(), source)
                }
                Ok(Err(status)) if retryable(status.code()) => {
                    last = status.message().to_string();
                }
                Ok(Err(status)) if status.code() == tonic::Code::DeadlineExceeded => {
                    return Err(fail(
                        ActivationStage::Exposure,
                        "deadline-exceeded",
                        status.message().to_string(),
                    ))
                }
                Ok(Err(status)) => {
                    return Err(fail(
                        ActivationStage::Exposure,
                        "handshake-failed",
                        status.message().to_string(),
                    ))
                }
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    /// Exact Thaw of the destination reference. Every error is treated as a
    /// possibly effective thaw by the caller: (code, detail).
    async fn thaw(
        &self,
        ctx: &DaemonContext,
        expected: &ExpectedGuestIdentity,
        reference: &FreezeRef,
    ) -> Result<(), (&'static str, String)> {
        let request = ThawRequest {
            expected: Some(expected.clone()),
            freeze_ref: Some(reference.clone()),
            rollback: false,
            deadline_ms: Some(GUEST_DEADLINE_MS),
        };
        let deadline = tokio::time::Instant::now() + THAW_TIMEOUT;
        loop {
            let attempt = async {
                let channel = crate::guest::connect(&ctx.machine).await?;
                crate::guest::agent_client(channel)
                    .thaw(request.clone())
                    .await
            };
            match tokio::time::timeout_at(deadline, attempt).await {
                Err(_) => {
                    return Err((
                        "thaw-unacknowledged",
                        "thaw not acknowledged before its deadline".into(),
                    ))
                }
                Ok(Ok(response)) => {
                    let status = response.into_inner().status.unwrap_or_default();
                    if thawed_exactly(&status, reference) {
                        return Ok(());
                    }
                    return Err((
                        "thaw-unacknowledged",
                        "guest did not acknowledge the exact thaw".into(),
                    ));
                }
                Ok(Err(status)) if retryable(status.code()) => {}
                Ok(Err(status)) => return Err(("thaw-failed", status.message().to_string())),
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    /// Re-establish the frozen barrier at a strictly newer epoch with
    /// positive frozen-root evidence.
    async fn refreeze(
        &self,
        ctx: &DaemonContext,
        expected: &ExpectedGuestIdentity,
        thawed: &FreezeRef,
    ) -> bool {
        let Some(epoch) = thawed
            .freeze_epoch
            .and_then(|epoch| epoch.checked_add(1))
            .and_then(NonZeroU64::new)
        else {
            return false;
        };
        let reference = FreezeRef {
            freeze_epoch: Some(epoch.get()),
            ..thawed.clone()
        };
        let request = FreezeWorkloadsRequest {
            expected: Some(expected.clone()),
            freeze_ref: Some(reference.clone()),
            deadline_ms: Some(GUEST_DEADLINE_MS),
        };
        let deadline = tokio::time::Instant::now() + THAW_TIMEOUT;
        loop {
            let attempt = async {
                let channel = crate::guest::connect(&ctx.machine).await?;
                crate::guest::agent_client(channel)
                    .freeze_workloads(request.clone())
                    .await
            };
            match tokio::time::timeout_at(deadline, attempt).await {
                Err(_) => return false,
                Ok(Ok(response)) => {
                    let status = response.into_inner().status.unwrap_or_default();
                    return status.freeze_ref.as_ref() == Some(&reference)
                        && crate::live::coordinator::guest_observation(&status).is_ok_and(
                            |observation| {
                                observation.state == GuestLifecycleState::Frozen
                                    && observation.positively_frozen(epoch)
                            },
                        );
                }
                Ok(Err(status)) if retryable(status.code()) => {}
                Ok(Err(_)) => return false,
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    /// Fail closed. Listeners close, the workload is re-frozen when it may
    /// have run, vCPUs are privately re-parked, and only then ActivationFailed.
    /// A stop request never thaws or resumes: it reaps.
    async fn settle_failure(
        &self,
        ctx: &DaemonContext,
        cancel: &CancellationToken,
        failure: Failure,
    ) -> eyre::Result<Activated> {
        let activation = self.activation;
        let message = failure.message();
        if cancel.is_cancelled() {
            tracing::info!(%activation, "restore activation reaping child");
            return Err(eyre::eyre!("restore activation stopped: {message}"));
        }
        if let Err(error) = ctx.forwards.shutdown().await {
            tracing::warn!(%error, "closing restore listeners failed");
        }
        if let Some((expected, thawed)) = failure.thawed.as_deref() {
            tracing::info!(%activation, "restore thaw recovery freezing");
            if !self.refreeze(ctx, expected, thawed).await {
                tracing::info!(%activation, "restore activation reaping child");
                return Err(eyre::eyre!(
                    "restore re-freeze after an unacknowledged thaw failed: {message}"
                ));
            }
            tracing::info!(%activation, "restore thaw recovery frozen");
        }
        if failure.cpus_released {
            let parked = self
                .native(
                    ctx,
                    cancel,
                    LifecycleCommand::ParkActivation {
                        activation,
                        timeout: NATIVE_TIMEOUT,
                    },
                )
                .await;
            if !matches!(parked, Ok(CommandOutcome::ActivationParked { .. })) {
                tracing::info!(%activation, "restore activation reaping child");
                return Err(eyre::eyre!(
                    "restore park failed after {message}: {parked:?}"
                ));
            }
        }
        tracing::info!(
            %activation,
            stage = stage_name(failure.stage),
            code = failure.code,
            "restore activation failed"
        );
        self.publish(
            ctx,
            VmLifecycleState::ActivationFailed,
            message.clone(),
            true,
        );
        Ok(Activated::Failed(message))
    }

    /// Run the whole sequence. `Err` means the child must be killed and reaped.
    pub(crate) async fn run(
        self,
        ctx: &DaemonContext,
        runtime_dir: &Path,
        cancel: &CancellationToken,
        startup_deadline: tokio::time::Instant,
    ) -> eyre::Result<Activated> {
        let activation = self.activation;
        self.publish(
            ctx,
            VmLifecycleState::Activating,
            "restore activating".into(),
            false,
        );
        let result = tokio::select! {
            biased;
            result = self.sequence(ctx, runtime_dir, cancel, startup_deadline) => result,
            exit = ctx.machine.wait() => Err(Abort::Uncertain(format!(
                "restore worker terminated during activation: {exit:?}"
            ))),
        };
        match result {
            Ok(vsock) => Ok(Activated::Running(vsock)),
            Err(Abort::Uncertain(detail)) => {
                tracing::info!(%activation, "restore activation reaping child");
                Err(eyre::eyre!("restore exposure uncertain: {detail}"))
            }
            Err(Abort::Fenced(failure)) => self.settle_failure(ctx, cancel, failure).await,
        }
    }

    async fn sequence(
        &self,
        ctx: &DaemonContext,
        runtime_dir: &Path,
        cancel: &CancellationToken,
        startup_deadline: tokio::time::Instant,
    ) -> Result<Option<crate::vsock::VsockSurface>, Abort> {
        let activation = self.activation;
        tracing::info!(%activation, "restore generation installed");
        match self
            .native(
                ctx,
                cancel,
                LifecycleCommand::ActivateGeneration {
                    activation,
                    timeout: GENERATION_TIMEOUT,
                },
            )
            .await
        {
            Ok(CommandOutcome::GenerationAcknowledged { generation }) => {
                tracing::info!(%activation, sequence = generation.sequence, "restore generation acknowledged");
            }
            Ok(CommandOutcome::ActivationFailed {
                stage,
                failure,
                cpus_released,
                exposure,
            }) => {
                if !fenced(exposure) {
                    return Err(Abort::Uncertain(format!(
                        "generation failed with exposure {exposure:?}: {failure}"
                    )));
                }
                if stage == ActivationStage::Acknowledgement {
                    tracing::info!(%activation, "restore generation acknowledgement expired");
                }
                return Err(Failure {
                    cpus_released,
                    ..fail(stage, "clock-generation-failed", failure.to_string())
                }
                .into());
            }
            Ok(other) => {
                return Err(fail(
                    ActivationStage::Acknowledgement,
                    "native-uncertain",
                    format!("{other:?}"),
                )
                .into())
            }
            Err(detail) => {
                return Err(
                    fail(ActivationStage::Acknowledgement, "native-uncertain", detail).into(),
                )
            }
        }
        let (source_ref, epoch) = self.source_freeze_ref()?;
        let source = self.handshake(ctx, cancel, &source_ref, epoch).await?;
        let expected = ExpectedGuestIdentity {
            machine_id: source_ref.machine_id.clone(),
            run_id: source_ref.run_id.clone(),
            agent_instance_id: source.instance_id.hyphenated().to_string(),
            boot_id: source.boot_id.hyphenated().to_string(),
        };
        let request = self.activate_request(ctx, expected, source_ref);
        tracing::info!(%activation, "restore activate sending");
        let guest = self.activate(ctx, cancel, &request, &source).await?;
        tracing::info!(%activation, "restore activate acknowledged");
        // Everything fallible below happens while the guest is frozen and
        // every native fence is closed; nothing accepts before the commit.
        ctx.forwards
            .stage_activation_listeners(&guest.agent, &guest.listeners)
            .map_err(|error| {
                fail(
                    ActivationStage::Exposure,
                    "listener-mismatch",
                    error.to_string(),
                )
            })?;
        let bound =
            ctx.forwards.bind_deferred().await.map_err(|error| {
                fail(ActivationStage::Exposure, "bind-failed", error.to_string())
            })?;
        for listener in bound {
            tracing::info!(%activation, listener = %listener, "restore listener bound");
        }
        let vsock = match &self.vsock_filename {
            Some(filename) => {
                let prepared = crate::vsock::PreparedVsockSurface::prepare(runtime_dir, filename)
                    .map_err(|error| {
                    fail(ActivationStage::Exposure, "bind-failed", error.to_string())
                })?;
                let staged = prepared
                    .stage(ctx.machine.clone(), ctx.forwards.clone())
                    .await
                    .map_err(|error| {
                        fail(ActivationStage::Exposure, "bind-failed", error.to_string())
                    })?;
                tracing::info!(%activation, listener = "vsock", "restore listener bound");
                Some(staged)
            }
            None => None,
        };
        tracing::info!(%activation, "restore thaw sending");
        if let Err((code, detail)) = self.thaw(ctx, &guest.identity, &guest.reference).await {
            return Err(fail(ActivationStage::Exposure, code, detail)
                .after_thaw(&guest.identity, &guest.reference)
                .into());
        }
        tracing::info!(%activation, "restore thaw acknowledged");
        if let Err(error) = ctx.machine.ensure_alive().await {
            return Err(fail(
                ActivationStage::Exposure,
                "machine-exited",
                error.to_string(),
            )
            .after_thaw(&guest.identity, &guest.reference)
            .into());
        }
        if cancel.is_cancelled() {
            return Err(
                fail(ActivationStage::Exposure, "stopped", "startup cancelled")
                    .after_thaw(&guest.identity, &guest.reference)
                    .into(),
            );
        }
        let release_timeout = startup_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                fail(
                    ActivationStage::Exposure,
                    "deadline",
                    "startup deadline elapsed before exposure",
                )
                .after_thaw(&guest.identity, &guest.reference)
            })?
            .min(NATIVE_TIMEOUT);
        tracing::info!(%activation, "restore exposure committing");
        match self
            .native(
                ctx,
                cancel,
                LifecycleCommand::ReleaseActivation {
                    activation,
                    timeout: release_timeout,
                },
            )
            .await
        {
            Ok(CommandOutcome::ActivationReleased) => {}
            Ok(CommandOutcome::ActivationFailed {
                failure, exposure, ..
            }) if fenced(exposure) => {
                return Err(fail(
                    ActivationStage::Exposure,
                    "release-failed",
                    failure.to_string(),
                )
                .after_thaw(&guest.identity, &guest.reference)
                .into())
            }
            other => return Err(Abort::Uncertain(format!("{other:?}"))),
        }
        tracing::info!(%activation, "restore exposure committed");
        // Committed: nothing below can fail activation.
        let vsock = vsock.map(crate::vsock::StagedVsockSurface::serve);
        ctx.forwards.activate(ctx.machine.clone());
        ctx.live.gate().reopen();
        self.publish(ctx, VmLifecycleState::Running, "vm running".into(), false);
        Ok(vsock)
    }
}

#[cfg(test)]
mod tests {
    use protocol::v1::{
        ActivateRequest, ActivateResponse, ActivationListener, ActivationListenerBound,
        ExpectedGuestIdentity, FreezeRef, GuestLifecycleState, GuestLifecycleStatus, ListenRequest,
        ListenerBound,
    };
    use uuid::Uuid;

    use crate::restore::activation::{
        fail, fenced, source_frozen, thawed_exactly, verify_activation, Failure,
    };
    use crate::state::ReadyAgentIdentity;
    use crate::virt::lifecycle::{ActivationExposure, ActivationStage};

    const SOURCE_MACHINE: &str = "11111111-1111-4111-8111-111111111111";
    const SOURCE_RUN: &str = "22222222-2222-4222-8222-222222222222";
    const DESTINATION_MACHINE: &str = "33333333-3333-4333-8333-333333333333";
    const DESTINATION_RUN: &str = "44444444-4444-4444-8444-444444444444";
    const OPERATION: &str = "55555555-5555-4555-8555-555555555555";
    const ACTIVATION: &str = "66666666-6666-4666-8666-666666666666";

    fn source() -> ReadyAgentIdentity {
        ReadyAgentIdentity {
            instance_id: Uuid::from_u128(7),
            boot_id: Uuid::from_u128(8),
        }
    }

    fn reference(machine: &str, run: &str, epoch: u64) -> FreezeRef {
        FreezeRef {
            machine_id: machine.into(),
            run_id: run.into(),
            operation_id: OPERATION.into(),
            freeze_epoch: Some(epoch),
        }
    }

    fn status(state: GuestLifecycleState, reference: FreezeRef) -> GuestLifecycleStatus {
        GuestLifecycleStatus {
            state: state as i32,
            machine_id: reference.machine_id.clone(),
            run_id: reference.run_id.clone(),
            freeze_ref: Some(reference),
            workload_roots: vec!["/sys/fs/cgroup/silo".into()],
            observed_frozen_roots: vec!["/sys/fs/cgroup/silo".into()],
            activation_id: Some(ACTIVATION.into()),
            ..GuestLifecycleStatus::default()
        }
    }

    fn request() -> ActivateRequest {
        ActivateRequest {
            activation_id: ACTIVATION.into(),
            freeze_ref: Some(reference(SOURCE_MACHINE, SOURCE_RUN, 3)),
            destination_machine_id: DESTINATION_MACHINE.into(),
            destination_run_id: DESTINATION_RUN.into(),
            listeners: vec![ActivationListener {
                name: "guest:tcp:8080".into(),
                registration: Some(ListenRequest {
                    listen: "tcp:127.0.0.1:8080".into(),
                    ..ListenRequest::default()
                }),
            }],
            ..ActivateRequest::default()
        }
    }

    fn reply() -> ActivateResponse {
        let destination = reference(DESTINATION_MACHINE, DESTINATION_RUN, 3);
        ActivateResponse {
            identity: Some(ExpectedGuestIdentity {
                machine_id: DESTINATION_MACHINE.into(),
                run_id: DESTINATION_RUN.into(),
                agent_instance_id: Uuid::from_u128(9).hyphenated().to_string(),
                boot_id: source().boot_id.hyphenated().to_string(),
            }),
            freeze_ref: Some(destination.clone()),
            listeners: vec![ActivationListenerBound {
                name: "guest:tcp:8080".into(),
                bound: Some(ListenerBound {
                    address: "tcp:127.0.0.1:8080".into(),
                }),
            }],
            status: Some(status(GuestLifecycleState::ActivatedFrozen, destination)),
        }
    }

    fn refused(response: ActivateResponse) -> bool {
        verify_activation(&request(), response, &source()).is_err_and(|failure| {
            failure.code == "guest-identity-mismatch"
                && failure.stage == ActivationStage::Exposure
                && failure.thawed.is_none()
        })
    }

    #[test]
    fn exact_activated_frozen_destination_is_accepted() {
        let guest = verify_activation(&request(), reply(), &source()).expect("exact reply");
        assert_eq!(guest.agent.instance_id, Uuid::from_u128(9));
        assert_eq!(guest.agent.boot_id, source().boot_id);
        assert_eq!(
            guest.reference,
            reference(DESTINATION_MACHINE, DESTINATION_RUN, 3)
        );
        assert_eq!(guest.listeners.len(), 1);
    }

    #[test]
    fn every_activate_reply_deviation_fails_closed() {
        let mutations: &[fn(&mut ActivateResponse)] = &[
            |reply| reply.identity = None,
            |reply| reply.freeze_ref = None,
            |reply| reply.status = None,
            // Still source-bound.
            |reply| reply.identity.as_mut().unwrap().machine_id = SOURCE_MACHINE.into(),
            |reply| reply.identity.as_mut().unwrap().run_id = SOURCE_RUN.into(),
            // Agent instance not rotated.
            |reply| {
                reply.identity.as_mut().unwrap().agent_instance_id =
                    source().instance_id.hyphenated().to_string();
            },
            // Another boot is not a continuation.
            |reply| reply.identity.as_mut().unwrap().boot_id = Uuid::from_u128(10).to_string(),
            |reply| reply.identity.as_mut().unwrap().boot_id = "not-a-uuid".into(),
            |reply| reply.freeze_ref.as_mut().unwrap().operation_id = ACTIVATION.into(),
            |reply| reply.freeze_ref.as_mut().unwrap().freeze_epoch = Some(4),
            |reply| reply.freeze_ref.as_mut().unwrap().machine_id = SOURCE_MACHINE.into(),
            |reply| reply.status.as_mut().unwrap().state = GuestLifecycleState::Frozen as i32,
            |reply| reply.status.as_mut().unwrap().state = GuestLifecycleState::Thawed as i32,
            |reply| reply.status.as_mut().unwrap().activation_id = None,
            |reply| reply.status.as_mut().unwrap().activation_id = Some(OPERATION.into()),
            |reply| reply.status.as_mut().unwrap().freeze_ref = None,
            // A root not observed frozen.
            |reply| reply.status.as_mut().unwrap().observed_frozen_roots.clear(),
            |reply| reply.status.as_mut().unwrap().workload_roots.clear(),
            |reply| reply.listeners.clear(),
            |reply| reply.listeners[0].name = "guest:tcp:9090".into(),
            |reply| {
                let duplicate = reply.listeners[0].clone();
                reply.listeners.push(duplicate);
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut response = reply();
            mutate(&mut response);
            assert!(refused(response), "mutation {index} was accepted");
        }
    }

    #[test]
    fn source_handshake_requires_the_sealed_reference_positively_frozen() {
        let sealed = reference(SOURCE_MACHINE, SOURCE_RUN, 3);
        let epoch = std::num::NonZeroU64::new(3).unwrap();
        let frozen = status(GuestLifecycleState::Frozen, sealed.clone());
        assert_eq!(source_frozen(&frozen, &sealed, epoch), Ok(true));

        let mut partial = frozen.clone();
        partial.observed_frozen_roots.clear();
        assert_eq!(source_frozen(&partial, &sealed, epoch), Ok(false));
        let mut freezing = frozen.clone();
        freezing.state = GuestLifecycleState::Freezing as i32;
        assert_eq!(source_frozen(&freezing, &sealed, epoch), Ok(false));
        let mut unreported = frozen.clone();
        unreported.freeze_ref = None;
        assert_eq!(source_frozen(&unreported, &sealed, epoch), Ok(false));

        for other in [
            reference(SOURCE_MACHINE, SOURCE_RUN, 4),
            reference(DESTINATION_MACHINE, SOURCE_RUN, 3),
            FreezeRef {
                operation_id: ACTIVATION.into(),
                ..sealed.clone()
            },
        ] {
            let foreign = status(GuestLifecycleState::Frozen, other);
            assert!(source_frozen(&foreign, &sealed, epoch).is_err());
        }
    }

    #[test]
    fn thaw_is_acknowledged_only_for_the_exact_destination_reference() {
        let destination = reference(DESTINATION_MACHINE, DESTINATION_RUN, 3);
        let thawed = status(GuestLifecycleState::Thawed, destination.clone());
        assert!(thawed_exactly(&thawed, &destination));
        assert!(!thawed_exactly(
            &status(GuestLifecycleState::ActivatedFrozen, destination.clone()),
            &destination
        ));
        assert!(!thawed_exactly(
            &status(
                GuestLifecycleState::Thawed,
                reference(DESTINATION_MACHINE, DESTINATION_RUN, 2)
            ),
            &destination
        ));
        assert!(!thawed_exactly(
            &status(
                GuestLifecycleState::Thawed,
                reference(SOURCE_MACHINE, SOURCE_RUN, 3)
            ),
            &destination
        ));
        assert!(!thawed_exactly(
            &GuestLifecycleStatus::default(),
            &destination
        ));
    }

    #[test]
    fn only_closed_native_exposure_may_settle_as_fenced() {
        assert!(fenced(ActivationExposure::Fenced));
        assert!(fenced(ActivationExposure::Sealed));
        assert!(!fenced(ActivationExposure::Committed));
        assert!(!fenced(ActivationExposure::Uncertain));
    }

    #[test]
    fn failure_message_is_the_stable_consumer_schema() {
        let failure: Failure = fail(ActivationStage::Exposure, "bind-failed", "port 8080 in use");
        assert_eq!(
            failure.message(),
            "restore activation failed: stage=exposure code=bind-failed: port 8080 in use"
        );
        assert!(failure.cpus_released);
        assert!(failure.thawed.is_none());
        let identity = ExpectedGuestIdentity::default();
        let destination = reference(DESTINATION_MACHINE, DESTINATION_RUN, 3);
        let thawed = fail(ActivationStage::Exposure, "thaw-unacknowledged", "lost")
            .after_thaw(&identity, &destination);
        assert_eq!(thawed.thawed, Some(Box::new((identity, destination))));
        assert_eq!(
            fail(
                ActivationStage::Acknowledgement,
                "clock-generation-failed",
                "late"
            )
            .message(),
            "restore activation failed: stage=acknowledgement code=clock-generation-failed: late"
        );
    }
}

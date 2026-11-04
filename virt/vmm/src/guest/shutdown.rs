//! One run-bound orderly-shutdown exchange on the private guest service.
//!
//! The request stream is retained through guest drains and terminal poweroff.
//! Receiving COMPLETED establishes only the guest fact, never host flush or
//! attachment closure. A later timeout, force or transport error cannot erase
//! an already observed completion.

use futures::{Stream, StreamExt};
use std::sync::Mutex;

use protocol::shutdown::{
    identity_to_proto, validate_guest_frame, validate_host_frame, ShutdownIdentity,
    StorageShutdownContext, MAX_FRAME_BYTES,
};
use protocol::v1::{
    shutdown_guest_frame, shutdown_host_frame, ShutdownAllowPoweroff, ShutdownBegin,
    ShutdownCompleted, ShutdownCompletionResult, ShutdownGuestFrame, ShutdownHostFrame,
};
use tokio_stream::wrappers::ReceiverStream;

use crate::context::DaemonContext;

pub(crate) struct ShutdownState {
    context: StorageShutdownContext,
    exchange: Mutex<Exchange>,
}

#[derive(Default)]
struct Exchange {
    identity: Option<ShutdownIdentity>,
    accepted: bool,
    completion: Option<ShutdownCompletionResult>,
    diagnostic: Option<String>,
    poweroff_receipt: bool,
}

impl ShutdownState {
    pub(crate) fn new(context: StorageShutdownContext) -> Result<Self, String> {
        context.validate()?;
        Ok(Self {
            context,
            exchange: Mutex::new(Exchange::default()),
        })
    }

    fn begin(&self, identity: ShutdownIdentity) -> Result<ShutdownHostFrame, String> {
        identity.validate_context(&self.context)?;
        let mut exchange = self
            .exchange
            .lock()
            .map_err(|_| "shutdown state poisoned")?;
        if exchange.identity.is_some() {
            return Err("shutdown attempt already initiated".to_string());
        }
        let manifest_json = serde_json::to_vec(&self.context.manifest)
            .map_err(|error| format!("encode shutdown manifest: {error}"))?;
        let frame = ShutdownHostFrame {
            identity: Some(identity_to_proto(&identity)),
            payload: Some(shutdown_host_frame::Payload::Begin(ShutdownBegin {
                manifest_json,
            })),
        };
        validate_host_frame(&frame, &identity)?;
        exchange.identity = Some(identity);
        Ok(frame)
    }

    /// Validate the complete frame before advancing. Completion is sticky even
    /// when a duplicate, identity change or malformed subsequent frame arrives.
    fn observe(&self, frame: &ShutdownGuestFrame) -> Result<bool, String> {
        let mut exchange = self
            .exchange
            .lock()
            .map_err(|_| "shutdown state poisoned")?;
        let identity = exchange.identity.as_ref().ok_or("shutdown has not begun")?;
        validate_guest_frame(frame, identity)?;
        if exchange.completion.is_some() {
            return Err("guest sent a frame after shutdown completion".to_string());
        }
        match &frame.payload {
            Some(shutdown_guest_frame::Payload::Accepted(_)) => {
                if exchange.accepted {
                    return Err("duplicate shutdown acceptance".to_string());
                }
                exchange.accepted = true;
                Ok(false)
            }
            Some(shutdown_guest_frame::Payload::Completed(completed)) => {
                if !exchange.accepted {
                    return Err("shutdown completion preceded acceptance".to_string());
                }
                let result = completed
                    .result
                    .and_then(|value| ShutdownCompletionResult::try_from(value).ok())
                    .ok_or("invalid shutdown completion result")?;
                if result == ShutdownCompletionResult::Succeeded {
                    if let Some(reason) = self.context.manifest.unsupported_reason() {
                        return Err(format!(
                            "guest success cannot certify unsupported storage: {reason}"
                        ));
                    }
                }
                exchange.completion = Some(result);
                exchange.diagnostic = completed.diagnostic.clone();
                Ok(true)
            }
            None => Err("shutdown frame has no payload".to_string()),
        }
    }

    fn allow_poweroff(&self) -> Result<ShutdownHostFrame, String> {
        let mut exchange = self
            .exchange
            .lock()
            .map_err(|_| "shutdown state poisoned")?;
        if exchange.completion.is_none() {
            return Err("poweroff receipt requires guest completion".to_string());
        }
        if exchange.poweroff_receipt {
            return Err("poweroff receipt already sent".to_string());
        }
        let identity = exchange.identity.as_ref().ok_or("shutdown has not begun")?;
        let frame = ShutdownHostFrame {
            identity: Some(identity_to_proto(identity)),
            payload: Some(shutdown_host_frame::Payload::AllowPoweroff(
                ShutdownAllowPoweroff {},
            )),
        };
        validate_host_frame(&frame, identity)?;
        exchange.poweroff_receipt = true;
        Ok(frame)
    }

    pub(crate) fn guest_protocol_completed(&self) -> Result<bool, String> {
        let exchange = self
            .exchange
            .lock()
            .map_err(|_| "shutdown state poisoned")?;
        Ok(exchange.completion == Some(ShutdownCompletionResult::Succeeded))
    }

    pub(crate) fn guest_failure(&self) -> Result<Option<String>, String> {
        let exchange = self
            .exchange
            .lock()
            .map_err(|_| "shutdown state poisoned")?;
        Ok(
            if exchange.completion == Some(ShutdownCompletionResult::Failed) {
                exchange.diagnostic.clone()
            } else {
                None
            },
        )
    }
}

/// Begin before cancelling any service or asking the backend to stop. The
/// caller supplies the overall deadline/escalation; cancelling this future
/// closes transport but does not remove a valid receipt from ShutdownState.
/// Success means the backend's actual terminal wait completed, not merely that
/// ALLOW_POWEROFF entered the request queue. The caller's deadline and signal
/// selection cover this entire future, including the post-receipt wait.
pub(crate) async fn orderly_shutdown(ctx: &DaemonContext) -> eyre::Result<()> {
    if !ctx.guest_services_enabled {
        return Err(eyre::eyre!(
            "guest shutdown protocol unavailable: agent disabled"
        ));
    }
    let agent = ctx.store.shutdown_agent_identity()?;
    let identity = ShutdownIdentity {
        version: protocol::shutdown::VERSION,
        machine_id: ctx.machine_id.to_string(),
        run_id: ctx.machine_run_id.to_string(),
        shutdown_id: uuid::Uuid::new_v4().to_string(),
        agent_instance_id: agent.instance_id.to_string(),
        boot_id: agent.boot_id.to_string(),
    };
    let begin = ctx
        .shutdown_state
        .begin(identity)
        .map_err(eyre::Report::msg)?;
    let channel = crate::guest::connect(&ctx.machine).await?;
    let mut client =
        protocol::v1::guest_agent_service_client::GuestAgentServiceClient::new(channel)
            .max_decoding_message_size(MAX_FRAME_BYTES)
            .max_encoding_message_size(MAX_FRAME_BYTES);
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    sender
        .send(begin)
        .await
        .map_err(|_| eyre::eyre!("shutdown request stream closed before BEGIN"))?;
    let mut stream = client
        .orderly_shutdown(ReceiverStream::new(receiver))
        .await?
        .into_inner();
    let completion = receive_completion(&ctx.shutdown_state, &mut stream, || {
        let current = ctx.store.shutdown_agent_identity()?;
        if current != agent {
            return Err(eyre::eyre!("guest identity changed during shutdown"));
        }
        Ok(())
    })
    .await?;
    sender
        .send(
            ctx.shutdown_state
                .allow_poweroff()
                .map_err(eyre::Report::msg)?,
        )
        .await
        .map_err(|_| eyre::eyre!("shutdown request stream closed before ALLOW_POWEROFF"))?;
    tracing::info!(machine_id = %ctx.machine_id, run_id = %ctx.machine_run_id,
        result = ?completion.result, diagnostic = ?completion.diagnostic,
        "guest shutdown completion observed");
    // Queueing ALLOW is not delivery confirmation. Retain both RPC halves until
    // actual terminal observation, or until the caller's deadline/escalation
    // cancels this future. EOF cannot shorten that terminal wait.
    tokio::select! {
        result = ctx.machine.wait() => { result?; }
        next = stream.message() => {
            if let Ok(Some(frame)) = next {
                ctx.shutdown_state.observe(&frame).map_err(eyre::Report::msg)?;
            }
            ctx.machine.wait().await?;
        }
    }
    drop(sender);
    if completion.result == Some(ShutdownCompletionResult::Failed as i32) {
        return Err(eyre::eyre!(
            "guest storage shutdown failed: {}",
            completion
                .diagnostic
                .as_deref()
                .map_or("missing required diagnostic", |value| value)
        ));
    }
    Ok(())
}

async fn receive_completion<S>(
    state: &ShutdownState,
    stream: &mut S,
    validate_current_identity: impl Fn() -> eyre::Result<()>,
) -> eyre::Result<ShutdownCompleted>
where
    S: Stream<Item = Result<ShutdownGuestFrame, tonic::Status>> + Unpin,
{
    loop {
        let frame = stream
            .next()
            .await
            .ok_or_else(|| eyre::eyre!("guest disconnected before shutdown completion"))??;
        validate_current_identity()?;
        if state.observe(&frame).map_err(eyre::Report::msg)? {
            let Some(shutdown_guest_frame::Payload::Completed(completed)) = frame.payload else {
                return Err(eyre::eyre!("shutdown completion payload missing"));
            };
            return Ok(completed);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use protocol::shutdown::{identity_to_proto, StorageAttachment, StorageManifest, VERSION};
    use protocol::v1::{
        shutdown_guest_frame, ShutdownAccepted, ShutdownAuthority, ShutdownCompleted,
        ShutdownCompletionResult, ShutdownGuestFrame,
    };
    use tokio_stream::wrappers::ReceiverStream;

    use crate::guest::shutdown::{
        receive_completion, ShutdownIdentity, ShutdownState, StorageShutdownContext,
    };

    fn context() -> StorageShutdownContext {
        StorageShutdownContext {
            version: VERSION,
            machine_id: uuid::Uuid::new_v4().to_string(),
            run_id: uuid::Uuid::new_v4().to_string(),
            manifest: StorageManifest::Complete {
                attachments: vec![
                    StorageAttachment::Block {
                        block_id: vm_spec::BlockId::new("root").unwrap(),
                        role: vm_spec::DiskRole::Root,
                        format: vm_spec::DiskFormat::Raw,
                        geometry: vm_spec::DiskGeometry {
                            length: 64 * 1024 * 1024,
                            logical_sector_size: 512,
                        },
                        read_only: false,
                        exclusive_writer: true,
                    },
                    StorageAttachment::Share {
                        tag: "generated-read-only".into(),
                        read_only: true,
                    },
                ],
            },
        }
    }

    fn identity(context: &StorageShutdownContext) -> ShutdownIdentity {
        ShutdownIdentity {
            version: VERSION,
            machine_id: context.machine_id.clone(),
            run_id: context.run_id.clone(),
            shutdown_id: uuid::Uuid::new_v4().to_string(),
            agent_instance_id: uuid::Uuid::new_v4().to_string(),
            boot_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn accepted(identity: &ShutdownIdentity) -> ShutdownGuestFrame {
        ShutdownGuestFrame {
            identity: Some(identity_to_proto(identity)),
            payload: Some(shutdown_guest_frame::Payload::Accepted(ShutdownAccepted {
                authority: Some(ShutdownAuthority::AgentPid1 as i32),
            })),
        }
    }

    fn completed(
        identity: &ShutdownIdentity,
        result: ShutdownCompletionResult,
    ) -> ShutdownGuestFrame {
        ShutdownGuestFrame {
            identity: Some(identity_to_proto(identity)),
            payload: Some(shutdown_guest_frame::Payload::Completed(
                ShutdownCompleted {
                    result: Some(result as i32),
                    diagnostic: (result != ShutdownCompletionResult::Succeeded)
                        .then(|| "first checked failure".into()),
                },
            )),
        }
    }

    #[test]
    fn shutdown_begin_preserves_entire_manifest_and_binds_one_attempt() {
        let context = context();
        let identity = identity(&context);
        let state = ShutdownState::new(context.clone()).unwrap();
        assert!(state.allow_poweroff().is_err());
        let frame = state.begin(identity.clone()).unwrap();
        let Some(protocol::v1::shutdown_host_frame::Payload::Begin(begin)) = frame.payload else {
            panic!("missing BEGIN");
        };
        assert_eq!(
            protocol::shutdown::manifest_from_json(&begin.manifest_json).unwrap(),
            context.manifest
        );
        assert!(state.begin(identity.clone()).is_err());
        assert!(state.allow_poweroff().is_err());
        assert!(!state.observe(&accepted(&identity)).unwrap());
        assert!(state.allow_poweroff().is_err());
        assert!(state
            .observe(&completed(&identity, ShutdownCompletionResult::Succeeded))
            .unwrap());
        assert!(state.allow_poweroff().is_ok());
        assert!(state.allow_poweroff().is_err());
        assert!(state.guest_protocol_completed().unwrap());
    }

    #[test]
    fn shutdown_rejects_every_identity_change_and_out_of_order_completion() {
        let context = context();
        let identity = identity(&context);
        let state = ShutdownState::new(context).unwrap();
        assert!(state.observe(&accepted(&identity)).is_err());
        state.begin(identity.clone()).unwrap();
        assert!(state
            .observe(&completed(&identity, ShutdownCompletionResult::Succeeded))
            .is_err());
        for field in 0..6 {
            let mut frame = accepted(&identity);
            let frame_identity = frame.identity.as_mut().unwrap();
            let replacement = Some(uuid::Uuid::new_v4().to_string());
            match field {
                0 => frame_identity.version = Some(VERSION + 1),
                1 => frame_identity.machine_id = replacement,
                2 => frame_identity.run_id = replacement,
                3 => frame_identity.shutdown_id = replacement,
                4 => frame_identity.agent_instance_id = replacement,
                _ => frame_identity.boot_id = replacement,
            }
            assert!(state.observe(&frame).is_err());
            assert!(!state.guest_protocol_completed().unwrap());
        }
        state.observe(&accepted(&identity)).unwrap();
        assert!(state.observe(&accepted(&identity)).is_err());
        assert!(!state.guest_protocol_completed().unwrap());
    }

    #[test]
    fn shutdown_completion_is_sticky_for_success_failure_and_unsupported() {
        for first in [
            ShutdownCompletionResult::Succeeded,
            ShutdownCompletionResult::Failed,
            ShutdownCompletionResult::Unsupported,
        ] {
            let context = context();
            let identity = identity(&context);
            let state = ShutdownState::new(context).unwrap();
            state.begin(identity.clone()).unwrap();
            state.observe(&accepted(&identity)).unwrap();
            state.observe(&completed(&identity, first)).unwrap();
            for later in [
                ShutdownCompletionResult::Succeeded,
                ShutdownCompletionResult::Failed,
            ] {
                assert!(state.observe(&completed(&identity, later)).is_err());
                assert_eq!(
                    state.guest_protocol_completed().unwrap(),
                    first == ShutdownCompletionResult::Succeeded
                );
                assert_eq!(
                    state.guest_failure().unwrap(),
                    (first == ShutdownCompletionResult::Failed)
                        .then(|| "first checked failure".to_string())
                );
            }
            assert!(state.allow_poweroff().is_ok());
        }
    }

    #[test]
    fn unsupported_manifest_never_accepts_guest_success() {
        let mut context = context();
        context.manifest = StorageManifest::Unsupported {
            reason: "unrepresentable inventory".into(),
        };
        let identity = identity(&context);
        let state = ShutdownState::new(context).unwrap();
        state.begin(identity.clone()).unwrap();
        state.observe(&accepted(&identity)).unwrap();
        assert!(state
            .observe(&completed(&identity, ShutdownCompletionResult::Succeeded))
            .is_err());
        assert!(!state.guest_protocol_completed().unwrap());
        assert!(state.allow_poweroff().is_err());
    }

    #[tokio::test]
    async fn shutdown_disconnect_transport_error_and_timeout_do_not_complete() {
        for failure in 0..3 {
            let context = context();
            let identity = identity(&context);
            let state = ShutdownState::new(context).unwrap();
            state.begin(identity.clone()).unwrap();
            let (sender, receiver) = tokio::sync::mpsc::channel(2);
            sender.send(Ok(accepted(&identity))).await.unwrap();
            let mut stream = ReceiverStream::new(receiver);
            match failure {
                0 => {
                    drop(sender);
                    assert!(receive_completion(&state, &mut stream, || Ok(()))
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("disconnected"));
                }
                1 => {
                    sender
                        .send(Err(tonic::Status::data_loss("truncated frame")))
                        .await
                        .unwrap();
                    assert!(receive_completion(&state, &mut stream, || Ok(()))
                        .await
                        .is_err());
                }
                _ => {
                    assert!(tokio::time::timeout(
                        Duration::from_millis(1),
                        receive_completion(&state, &mut stream, || Ok(()))
                    )
                    .await
                    .is_err());
                }
            }
            assert!(!state.guest_protocol_completed().unwrap());
            assert!(state.allow_poweroff().is_err());
        }
    }

    #[tokio::test]
    async fn observed_identity_replacement_prevents_receipt() {
        let context = context();
        let identity = identity(&context);
        let state = ShutdownState::new(context).unwrap();
        state.begin(identity.clone()).unwrap();
        let mut stream = tokio_stream::iter([Ok(accepted(&identity))]);
        assert!(
            receive_completion(&state, &mut stream, || Err(eyre::eyre!("agent replaced")))
                .await
                .is_err()
        );
        assert!(!state.guest_protocol_completed().unwrap());
    }

    #[test]
    fn malformed_frames_never_advance_shutdown_or_supply_a_fact() {
        let context = context();
        let identity = identity(&context);
        let state = ShutdownState::new(context).unwrap();
        let mut wrong_run = identity.clone();
        wrong_run.run_id = uuid::Uuid::new_v4().to_string();
        assert!(state.begin(wrong_run).is_err());
        state.begin(identity.clone()).unwrap();
        let mut no_authority = accepted(&identity);
        if let Some(shutdown_guest_frame::Payload::Accepted(payload)) = &mut no_authority.payload {
            payload.authority = None;
        }
        assert!(state.observe(&no_authority).is_err());
        state.observe(&accepted(&identity)).unwrap();
        let mut malformed = completed(&identity, ShutdownCompletionResult::Succeeded);
        if let Some(shutdown_guest_frame::Payload::Completed(payload)) = &mut malformed.payload {
            payload.diagnostic = Some("success with an error is invalid".into());
        }
        assert!(state.observe(&malformed).is_err());
        if let Some(shutdown_guest_frame::Payload::Completed(payload)) = &mut malformed.payload {
            payload.result = None;
            payload.diagnostic = None;
        }
        assert!(state.observe(&malformed).is_err());
        assert!(!state.guest_protocol_completed().unwrap());
        assert!(state.allow_poweroff().is_err());
        state
            .observe(&completed(&identity, ShutdownCompletionResult::Succeeded))
            .unwrap();
        assert!(state.guest_protocol_completed().unwrap());
    }
}

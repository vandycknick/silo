use std::sync::Arc;
use std::time::Duration;

use protocol::v1::execution_event::Event as ExecutionEventKind;
use protocol::v1::{
    EnvironmentVariable, GuestProcessInput, PipeStdio, ProcessSpec, StartGuestProcess,
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use uuid::Uuid;

use crate::context::DaemonContext;
use crate::exec_log::ExecLogWriter;
use crate::execution::{
    ensure_agent_generation, identity_loss, log_execution_output, log_guest_launch_failure,
    translate_event, GuestEventState, QUEUE_CAPACITY,
};
use crate::guest::process_client;
use crate::start_request::{StartupCommand, StartupProcess};
use crate::state::{InstanceStore, ReadyAgentIdentity};

const STARTUP_READINESS_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const START_HANDOFF_GRACE: Duration = Duration::from_secs(1);

pub(crate) struct StartupCommandHandle {
    pub(crate) task: tokio::task::JoinHandle<()>,
    pub(crate) started: oneshot::Receiver<Result<(), StartupCommandStartError>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum StartupCommandStartError {
    #[error("guest process launch failed: {message}")]
    LaunchFailed {
        reason: Option<i32>,
        message: String,
    },
    #[error("{0}")]
    Unavailable(String),
}

pub(crate) fn spawn_startup_command(
    ctx: &DaemonContext,
    command: StartupCommand,
    exec_log: Option<ExecLogWriter>,
) -> StartupCommandHandle {
    let (started, started_receiver) = oneshot::channel();
    let machine = ctx.machine.clone();
    let store = ctx.store.clone();
    let stop_requested = ctx.stop_requested.clone();
    let shutdown = ctx.shutdown.clone();
    let task = tokio::spawn(async move {
        let mut started = Some(started);
        let agent = match tokio::time::timeout(
            STARTUP_READINESS_TIMEOUT,
            wait_for_ready_agent(&store, &shutdown),
        )
        .await
        {
            Ok(Ok(agent)) => agent,
            Ok(Err(message)) => {
                stop_machine(&machine, &shutdown).await;
                report_start_failure(
                    &mut started,
                    StartupCommandStartError::Unavailable(message.to_string()),
                );
                return;
            }
            Err(_) => {
                stop_machine(&machine, &shutdown).await;
                report_start_failure(
                    &mut started,
                    StartupCommandStartError::Unavailable(
                        "guest agent did not become ready within five minutes".to_string(),
                    ),
                );
                return;
            }
        };

        let execution_id = match Uuid::parse_str(&command.execution_id) {
            Ok(execution_id) => execution_id,
            Err(error) => {
                stop_machine(&machine, &shutdown).await;
                report_start_failure(
                    &mut started,
                    StartupCommandStartError::Unavailable(format!(
                        "invalid startup command execution UUID: {error}"
                    )),
                );
                return;
            }
        };
        let failure = run_guest(
            &machine,
            &store,
            &shutdown,
            agent,
            execution_id,
            process_spec(command.process),
            exec_log.as_ref(),
            &mut started,
        )
        .await
        .err();
        if let Some(message) = &failure {
            tracing::warn!(%execution_id, detail = %message, "startup command ended without a guest terminal result");
        }
        if started.is_none() {
            tokio::select! {
                _ = tokio::time::sleep(START_HANDOFF_GRACE) => {}
                _ = shutdown.cancelled() => return,
            }
            stop_requested.cancel();
            return;
        }
        stop_machine(&machine, &shutdown).await;
        report_start_failure(
            &mut started,
            failure.unwrap_or_else(|| {
                StartupCommandStartError::Unavailable(
                    "startup command ended before Started".to_string(),
                )
            }),
        );
    });
    StartupCommandHandle {
        task,
        started: started_receiver,
    }
}

async fn wait_for_ready_agent(
    store: &Arc<InstanceStore>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<ReadyAgentIdentity, &'static str> {
    let mut changes = store.subscribe_ready_agent_identity();
    loop {
        if shutdown.is_cancelled() {
            return Err("vmmon stopped before the guest became ready");
        }
        if let Ok(identity) = store.ready_agent_identity() {
            return Ok(identity);
        }
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return Err("guest identity notifications stopped");
                }
            }
            _ = shutdown.cancelled() => {
                return Err("vmmon stopped before the guest became ready");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_guest(
    machine: &crate::virt::VirtualMachine,
    store: &Arc<InstanceStore>,
    shutdown: &tokio_util::sync::CancellationToken,
    expected_agent: ReadyAgentIdentity,
    execution_id: Uuid,
    process: ProcessSpec,
    exec_log: Option<&ExecLogWriter>,
    started: &mut Option<oneshot::Sender<Result<(), StartupCommandStartError>>>,
) -> Result<(), StartupCommandStartError> {
    let current = store
        .ready_agent_identity()
        .map_err(|_| unavailable("guest agent is no longer ready"))?;
    if let Some((_, message)) = identity_loss(expected_agent.clone(), Some(current)) {
        return Err(unavailable(message));
    }
    let mut identity_changes = store.subscribe_ready_agent_identity();
    let mut client = tokio::select! {
        _ = shutdown.cancelled() => return Err(unavailable("vmmon is stopping")),
        result = process_client(machine) => result.map_err(|error| unavailable(error.message()))?,
    };
    let (guest_inputs, guest_input_receiver) = mpsc::channel(QUEUE_CAPACITY);
    guest_inputs
        .send(GuestProcessInput {
            message: Some(protocol::v1::guest_process_input::Message::Start(
                StartGuestProcess {
                    execution_id: execution_id.hyphenated().to_string(),
                    expected_agent_instance_id: expected_agent.instance_id.hyphenated().to_string(),
                    expected_agent_boot_id: expected_agent.boot_id.hyphenated().to_string(),
                    process: Some(process),
                },
            )),
        })
        .await
        .map_err(|_| unavailable("guest input stream closed"))?;
    drop(guest_inputs);
    let response = tokio::select! {
        _ = shutdown.cancelled() => return Err(unavailable("vmmon is stopping")),
        result = client.execute(Request::new(ReceiverStream::new(guest_input_receiver))) => {
            result.map_err(|error| unavailable(error.message()))?
        }
    };
    let mut guest_events = response.into_inner();
    let mut guest_state = GuestEventState::default();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Err(unavailable("vmmon is stopping")),
            changed = identity_changes.changed() => {
                if changed.is_err() {
                    return Err(unavailable("guest identity notifications stopped"));
                }
                if let Some((_, message)) = identity_loss(
                    expected_agent.clone(),
                    identity_changes.borrow_and_update().clone(),
                ) {
                    return Err(unavailable(message));
                }
            }
            guest = guest_events.message() => {
                let guest = guest
                    .map_err(|error| unavailable(error.message()))?
                    .ok_or_else(|| unavailable("guest process stream ended before a terminal result"))?;
                ensure_agent_generation(&expected_agent, &identity_changes)
                    .map_err(|error| unavailable(error.message()))?;
                log_guest_launch_failure(execution_id, &guest);
                let (event, terminal) = translate_event(guest, &mut guest_state)
                    .map_err(unavailable)?;
                log_execution_output(exec_log, execution_id, &event);
                match event.event.as_ref() {
                    Some(ExecutionEventKind::Started(_)) => {
                        if let Some(started) = started.take() {
                            let _ = started.send(Ok(()));
                        }
                    }
                    Some(ExecutionEventKind::LaunchFailed(failure)) => {
                        return Err(StartupCommandStartError::LaunchFailed {
                            reason: failure.reason,
                            message: failure
                                .message
                                .clone()
                                .unwrap_or_else(|| "guest process launch failed".to_string()),
                        });
                    }
                    _ => {}
                }
                if terminal {
                    return Ok(());
                }
            }
        }
    }
}

fn process_spec(process: StartupProcess) -> ProcessSpec {
    ProcessSpec {
        argv: process.argv,
        environment: process
            .environment
            .into_iter()
            .map(|variable| EnvironmentVariable {
                name: variable.name,
                value: variable.value,
            })
            .collect(),
        working_directory: process.working_directory,
        user: process.user,
        stdio: Some(protocol::v1::process_spec::Stdio::Pipes(PipeStdio {
            stdin: false,
        })),
    }
}

fn report_start_failure(
    started: &mut Option<oneshot::Sender<Result<(), StartupCommandStartError>>>,
    error: StartupCommandStartError,
) {
    if let Some(started) = started.take() {
        let _ = started.send(Err(error));
    }
}

fn unavailable(message: impl Into<String>) -> StartupCommandStartError {
    StartupCommandStartError::Unavailable(message.into())
}

async fn stop_machine(
    machine: &crate::virt::VirtualMachine,
    shutdown: &tokio_util::sync::CancellationToken,
) {
    if shutdown.is_cancelled() {
        return;
    }
    if let Err(error) = machine.stop().await {
        tracing::error!(%error, "stop machine after startup command completion");
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::startup::process_spec;
    use crate::start_request::{StartupEnvironmentVariable, StartupProcess};

    #[test]
    fn startup_command_uses_null_pipe_input_and_preserves_process_values() {
        let process = process_spec(StartupProcess {
            argv: vec!["program".to_string(), "two words".to_string()],
            working_directory: Some("/work".to_string()),
            environment: vec![StartupEnvironmentVariable {
                name: "KEY".to_string(),
                value: "value".to_string(),
            }],
            user: Some("1000:1000".to_string()),
        });
        assert_eq!(process.argv, ["program", "two words"]);
        assert_eq!(process.working_directory.as_deref(), Some("/work"));
        assert_eq!(process.user.as_deref(), Some("1000:1000"));
        assert!(matches!(
            process.stdio,
            Some(protocol::v1::process_spec::Stdio::Pipes(
                protocol::v1::PipeStdio { stdin: false }
            ))
        ));
    }
}

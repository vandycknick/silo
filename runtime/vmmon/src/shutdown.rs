use std::time::Duration;

use protocol::v1::LifecycleState;
use tokio::signal;
use virt::VmExit;

use crate::context::{DaemonContext, RuntimeContext};
use crate::services::ServiceHandles;
use crate::state::{select_current_inspect, Action};

const VM_STOP_TIMEOUT: Duration = Duration::from_secs(45);

pub async fn run(
    runtime: RuntimeContext,
    ctx: DaemonContext,
    mut handles: ServiceHandles,
) -> eyre::Result<()> {
    let forced = tokio::select! {
        _ = wait_for_signal() => {
            tracing::info!(instance = %ctx.machine.name(), "shutdown signal received");
            ctx.store.dispatch(Action::VmTransition {
                state: LifecycleState::Stopping,
                message: String::from("shutdown requested"),
            })?;
            ctx.shutdown.cancel();
            graceful_stop(&ctx).await?
        }
        result = wait_for_machine_stop(&ctx.machine) => {
            let stop_info = result?;
            tracing::info!(instance = %ctx.machine.name(), message = %stop_info.message, "machine exited");
            ctx.store.dispatch(Action::VmTransition {
                state: LifecycleState::Stopped,
                message: stop_info.message,
            })?;
            ctx.shutdown.cancel();
            false
        }
    };

    drain(&mut handles).await;
    cleanup(&runtime, &ctx).await?;

    if forced {
        tracing::warn!(instance = %ctx.machine.name(), "forced shutdown completed");
    }

    Ok(())
}

async fn graceful_stop(ctx: &DaemonContext) -> eyre::Result<bool> {
    let stop_task = tokio::spawn({
        let machine = ctx.machine.clone();
        async move { machine.stop().await }
    });

    tokio::select! {
        result = stop_task => {
            match result {
                Ok(Ok(())) => {
                    ctx.store.dispatch(Action::VmTransition {
                        state: LifecycleState::Stopped,
                        message: String::from("vm stopped"),
                    })?;
                    Ok(false)
                }
                Ok(Err(err)) => Err(err.into()),
                Err(err) => Err(eyre::eyre!("vm stop task failed: {err}")),
            }
        }
        _ = wait_for_signal() => {
            tracing::warn!(instance = %ctx.machine.name(), "second shutdown signal received, forcing exit");
            Ok(true)
        }
        _ = tokio::time::sleep(VM_STOP_TIMEOUT) => {
            Err(eyre::eyre!("timed out after {:?} waiting for vm stop", VM_STOP_TIMEOUT))
        }
    }
}

async fn drain(handles: &mut ServiceHandles) {
    if let Some(task) = handles.guest_monitor.take() {
        if let Err(err) = task.await {
            tracing::error!(error = %err, "guest monitor task failed during shutdown");
        }
    }

    if let Some(task) = handles.endpoint_supervisor.take() {
        if let Err(err) = task.await {
            tracing::error!(error = %err, "endpoint supervisor task failed during shutdown");
        }
    }

    match (&mut handles.control_socket).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::error!(error = %err, "control socket exited with error during shutdown");
        }
        Err(err) => {
            tracing::error!(error = %err, "control socket task failed during shutdown");
        }
    }

    handles.serial_log.abort();
    let _ = (&mut handles.serial_log).await;
}

struct VmStopInfo {
    message: String,
}

async fn wait_for_machine_stop(machine: &virt::VirtualMachine) -> Result<VmStopInfo, eyre::Report> {
    let exit = machine.wait().await?;
    let message = match exit {
        VmExit::Stopped => String::from("machine stopped"),
        VmExit::StoppedWithError(error) => format!("machine stopped with error: {error}"),
    };
    Ok(VmStopInfo { message })
}

async fn cleanup(_runtime: &RuntimeContext, ctx: &DaemonContext) -> eyre::Result<()> {
    let snapshot = ctx.store.snapshot()?;
    let inspect = select_current_inspect(&snapshot);
    tracing::debug!(summary = %inspect.summary, "final vmmon status snapshot");

    tracing::info!(instance = %ctx.machine.name(), "instance stopped");
    Ok(())
}

async fn wait_for_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

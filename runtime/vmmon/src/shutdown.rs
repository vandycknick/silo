use std::time::Duration;

use protocol::v1::VmState;
use tokio::signal;
use virt::VmExit;

use crate::context::{DaemonContext, RuntimeContext};
use crate::services::ServiceHandles;

const VM_STOP_TIMEOUT: Duration = Duration::from_secs(45);
const SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn run(
    runtime: RuntimeContext,
    ctx: DaemonContext,
    mut handles: ServiceHandles,
) -> eyre::Result<()> {
    let forced = tokio::select! {
        _ = wait_for_signal() => {
            tracing::info!(instance = %ctx.machine.name(), "shutdown signal received");
            ctx.store.set_vm_state(VmState::Stopping, "shutdown requested")?;
            handles.mark_stopping().await;
            ctx.shutdown.cancel();
            graceful_stop(&ctx).await?
        }
        result = wait_for_machine_stop(&ctx.machine) => {
            let stop_info = result?;
            tracing::info!(instance = %ctx.machine.name(), message = %stop_info.message, "machine exited");
            ctx.store.set_vm_state(VmState::Stopped, stop_info.message)?;
            handles.mark_stopping().await;
            ctx.shutdown.cancel();
            false
        }
    };

    handles.mark_not_serving().await;
    handles.server_shutdown.cancel();
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
                    ctx.store.set_vm_state(VmState::Stopped, "vm stopped")?;
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
        drain_task(task, "guest monitor").await;
    }

    if let Some(task) = handles.endpoint_supervisor.take() {
        drain_task(task, "endpoint supervisor").await;
    }

    drain_result_task(&mut handles.control_socket, "control socket").await;

    handles.serial_log.abort();
    let _ = (&mut handles.serial_log).await;
}

async fn drain_task(mut task: tokio::task::JoinHandle<()>, label: &'static str) {
    match tokio::time::timeout(SERVICE_DRAIN_TIMEOUT, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::error!(%error, task = label, "service task failed during shutdown")
        }
        Err(_) => {
            tracing::warn!(
                task = label,
                "service task exceeded shutdown drain; aborting"
            );
            task.abort();
            let _ = task.await;
        }
    }
}

async fn drain_result_task(
    task: &mut tokio::task::JoinHandle<eyre::Result<()>>,
    label: &'static str,
) {
    match tokio::time::timeout(SERVICE_DRAIN_TIMEOUT, &mut *task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::error!(%error, task = label, "service task exited with error")
        }
        Ok(Err(error)) => {
            tracing::error!(%error, task = label, "service task failed during shutdown")
        }
        Err(_) => {
            tracing::warn!(
                task = label,
                "service task exceeded shutdown drain; aborting"
            );
            task.abort();
            let _ = task.await;
        }
    }
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
    let status = ctx.store.status()?;
    tracing::debug!(?status, "final vmmon status snapshot");

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

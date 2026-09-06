use std::time::Duration;

use crate::virt::VmExit;
use protocol::v1::VmState;
use tokio::signal;

use crate::context::{DaemonContext, RuntimeContext};
use crate::services::ServiceHandles;

const VM_STOP_TIMEOUT: Duration = Duration::from_secs(45);
const SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn run(
    runtime: RuntimeContext,
    ctx: DaemonContext,
    mut handles: ServiceHandles,
) -> eyre::Result<()> {
    let trigger = tokio::select! {
        _ = wait_for_signal() => {
            tracing::info!(instance = %ctx.machine.name(), "shutdown signal received");
            ShutdownTrigger::Requested("shutdown requested")
        }
        _ = ctx.stop_requested.cancelled() => {
            tracing::info!(instance = %ctx.machine.name(), "startup command completed");
            ShutdownTrigger::Requested("startup command completed")
        }
        result = wait_for_machine_stop(&ctx.machine) => {
            let stop_info = result?;
            tracing::info!(instance = %ctx.machine.name(), message = %stop_info.message, "machine exited");
            ShutdownTrigger::Backend(stop_info)
        }
    };

    handles.mark_stopping().await;
    ctx.shutdown.cancel();
    stop_forwards(&mut handles).await;
    stop_vsock_surface(&mut handles).await;
    let (forced, backend_error) = match trigger {
        ShutdownTrigger::Requested(message) => {
            ctx.store.set_vm_state(VmState::Stopping, message)?;
            (graceful_stop(&ctx).await?, None)
        }
        ShutdownTrigger::Backend(stop_info) => {
            ctx.store
                .set_vm_state(VmState::Stopped, stop_info.message)?;
            (false, stop_info.error)
        }
    };

    handles.mark_not_serving().await;
    handles.server_shutdown.cancel();
    drain(&mut handles, &ctx.machine).await;
    cleanup(&runtime, &ctx).await?;

    if forced {
        tracing::warn!(instance = %ctx.machine.name(), "forced shutdown completed");
    }

    if let Some(error) = backend_error {
        return Err(eyre::eyre!("virtual machine exited with error: {error}"));
    }

    Ok(())
}

enum ShutdownTrigger {
    Requested(&'static str),
    Backend(VmStopInfo),
}

async fn stop_vsock_surface(handles: &mut ServiceHandles) {
    let Some(mut surface) = handles.vsock_surface.take() else {
        return;
    };
    match tokio::time::timeout(SERVICE_DRAIN_TIMEOUT, surface.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(%error, "vsock surface shutdown failed"),
        Err(_) => tracing::warn!("vsock surface exceeded shutdown drain timeout"),
    }
}

async fn stop_forwards(handles: &mut ServiceHandles) {
    let Some(forwards) = handles.forwards.take() else {
        return;
    };
    match tokio::time::timeout(SERVICE_DRAIN_TIMEOUT, forwards.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(%error, "forward shutdown failed"),
        Err(_) => tracing::warn!("forwards exceeded shutdown drain timeout"),
    }
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

async fn drain(handles: &mut ServiceHandles, machine: &crate::virt::VirtualMachine) {
    if let Some(task) = handles.startup_command.take() {
        drain_task(task, "startup command supervisor").await;
    }

    if let Some(task) = handles.guest_monitor.take() {
        drain_task(task, "guest monitor").await;
    }

    drain_result_task(&mut handles.control_socket, "control socket").await;

    match tokio::time::timeout(SERVICE_DRAIN_TIMEOUT, machine.drain_serial()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(%error, "serial log drain failed during shutdown"),
        Err(_) => tracing::warn!("serial log drain exceeded shutdown drain timeout"),
    }
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
    error: Option<String>,
}

async fn wait_for_machine_stop(
    machine: &crate::virt::VirtualMachine,
) -> Result<VmStopInfo, eyre::Report> {
    let exit = machine.wait().await?;
    Ok(vm_stop_info(exit))
}

fn vm_stop_info(exit: VmExit) -> VmStopInfo {
    match exit {
        VmExit::Stopped => VmStopInfo {
            message: String::from("machine stopped"),
            error: None,
        },
        VmExit::StoppedWithError(error) => VmStopInfo {
            message: format!("machine stopped with error: {error}"),
            error: Some(error),
        },
    }
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

#[cfg(test)]
mod tests {
    use crate::virt::VmExit;

    #[test]
    fn backend_failure_is_preserved_for_monitor_exit_status() {
        let info = crate::shutdown::vm_stop_info(VmExit::StoppedWithError(
            "krun exited with status code 127".to_string(),
        ));

        assert_eq!(
            info.message,
            "machine stopped with error: krun exited with status code 127"
        );
        assert_eq!(
            info.error.as_deref(),
            Some("krun exited with status code 127")
        );
    }

    #[test]
    fn normal_backend_stop_remains_clean() {
        let info = crate::shutdown::vm_stop_info(VmExit::Stopped);

        assert_eq!(info.message, "machine stopped");
        assert_eq!(info.error, None);
    }
}

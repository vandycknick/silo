use std::time::Duration;

use crate::virt::VmExit;
use protocol::v1::VmState;
use tokio::signal;

use crate::context::{DaemonContext, RuntimeContext};
use crate::services::ServiceHandles;

// Allow the backend's graceful stop budget before requesting escalation.
const VM_STOP_TIMEOUT: Duration = Duration::from_secs(65);
const SERVICE_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn run(
    runtime: RuntimeContext,
    ctx: DaemonContext,
    mut handles: ServiceHandles,
) -> eyre::Result<()> {
    let mut errors = Vec::new();
    let trigger = tokio::select! {
        result = wait_for_signal() => {
            if let Err(error) = result { errors.push(error.to_string()); }
            tracing::info!(instance = %ctx.machine.name(), "shutdown signal received");
            ShutdownTrigger::Requested("shutdown requested")
        }
        _ = ctx.stop_requested.cancelled() => {
            tracing::info!(instance = %ctx.machine.name(), "startup command completed");
            ShutdownTrigger::Requested("startup command completed")
        }
        result = wait_for_machine_stop(&ctx.machine) => {
            match result {
                Ok(stop_info) => {
                    tracing::info!(instance = %ctx.machine.name(), message = %stop_info.message, "machine exited");
                    ShutdownTrigger::Backend(stop_info)
                }
                Err(error) => {
                    errors.push(error.to_string());
                    ShutdownTrigger::Requested("backend wait failed")
                }
            }
        }
    };

    handles.mark_stopping().await;
    ctx.shutdown.cancel();
    stop_forwards(&mut handles).await;
    stop_vsock_surface(&mut handles).await;
    match trigger {
        ShutdownTrigger::Requested(message) => {
            if let Err(error) = ctx.store.set_vm_state(VmState::Stopping, message) {
                errors.push(error.to_string());
            }
            if let Err(error) = graceful_stop(&ctx).await {
                errors.push(error.to_string());
            }
            match wait_for_machine_stop(&ctx.machine).await {
                Ok(info) => record_stop(&ctx, info, &mut errors),
                Err(error) => errors.push(error.to_string()),
            }
        }
        ShutdownTrigger::Backend(info) => {
            record_stop(&ctx, info, &mut errors);
            if let Err(error) = ctx.machine.stop().await {
                errors.push(error.to_string());
            }
        }
    }

    handles.mark_not_serving().await;
    handles.server_shutdown.cancel();
    if let Err(error) = drain(&mut handles, &ctx.machine).await {
        errors.push(error.to_string());
    }
    if let Err(error) = cleanup(&runtime, &ctx).await {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(eyre::eyre!(errors.join("; ")))
    }
}

fn record_stop(ctx: &DaemonContext, info: VmStopInfo, errors: &mut Vec<String>) {
    if let Err(error) = ctx.store.set_vm_state(VmState::Stopped, info.message) {
        errors.push(error.to_string());
    }
    if let Some(error) = info.error {
        errors.push(format!("virtual machine exited with error: {error}"));
    }
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

async fn graceful_stop(ctx: &DaemonContext) -> eyre::Result<()> {
    let mut stop_task = tokio::spawn({
        let machine = ctx.machine.clone();
        async move { machine.stop().await }
    });

    tokio::select! {
        result = &mut stop_task => return result.map_err(eyre::Report::from)?.map_err(eyre::Report::from),
        result = wait_for_signal() => {
            if let Err(error) = result { tracing::warn!(%error, "shutdown signal listener failed"); }
            tracing::warn!(instance = %ctx.machine.name(), "second shutdown signal received; escalating backend stop");
        }
        _ = tokio::time::sleep(VM_STOP_TIMEOUT) => {
            tracing::warn!(instance = %ctx.machine.name(), "graceful stop deadline elapsed; escalating backend stop");
        }
    }
    // Escalation never abandons the owner. Terminal metadata requires the worker
    // to be reaped (or the in-process backend to confirm termination).
    let forced = ctx.machine.force_stop().await;
    let stopped = stop_task.await.map_err(eyre::Report::from)?;
    match (forced, stopped) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error.into()),
        (Err(force), Err(stop)) => Err(eyre::eyre!(
            "force stop failed: {force}; stop failed: {stop}"
        )),
    }
}

async fn drain(
    handles: &mut ServiceHandles,
    machine: &crate::virt::VirtualMachine,
) -> eyre::Result<()> {
    if let Some(task) = handles.startup_command.take() {
        drain_task(task, "startup command supervisor").await;
    }

    if let Some(task) = handles.guest_monitor.take() {
        drain_task(task, "guest monitor").await;
    }

    drain_result_task(&mut handles.control_socket, "control socket").await;

    machine.drain_serial().await.map_err(eyre::Report::from)
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
    let error = exit.error();
    let message = match &error {
        Some(error) => format!("machine stopped with error: {error}"),
        None if exit.forced() => "machine force-stopped".to_string(),
        None => "machine stopped".to_string(),
    };
    VmStopInfo { message, error }
}

async fn cleanup(_runtime: &RuntimeContext, ctx: &DaemonContext) -> eyre::Result<()> {
    let status = ctx.store.status()?;
    tracing::debug!(?status, "final silo-vmmon status snapshot");

    tracing::info!(instance = %ctx.machine.name(), "instance stopped");
    Ok(())
}

async fn wait_for_signal() -> std::io::Result<()> {
    let ctrl_c = signal::ctrl_c();

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())?
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("SIGTERM listener closed"))
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<std::io::Result<()>>();

    tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    }
}

#[cfg(test)]
mod tests {
    use crate::virt::exit::StartupStage;
    use crate::virt::VmExit;

    #[test]
    fn backend_failure_is_preserved_for_monitor_exit_status() {
        let info = crate::shutdown::vm_stop_info(VmExit::failed(
            StartupStage::Started,
            "krun exited with status code 127",
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
        let info = crate::shutdown::vm_stop_info(VmExit::stopped(StartupStage::Started));

        assert_eq!(info.message, "machine stopped");
        assert_eq!(info.error, None);
    }
}

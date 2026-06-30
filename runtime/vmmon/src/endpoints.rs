use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use vm_spec::{RestartPolicy, VsockEndpoint, VsockEndpointMode};

use crate::context::DaemonContext;

mod control;
mod plugin;

use control::{
    control_message_name, send_control_message, BrokerControlSocket, ControlMessageKind,
};
use plugin::{spawn_plugin, terminate_plugin, PluginEvent, RunningPlugin, StartupMessage};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STABLE_RUN_RESET: Duration = Duration::from_secs(30);

pub(crate) fn start_endpoint_supervisor(
    ctx: DaemonContext,
    instance_dir: PathBuf,
) -> Option<JoinHandle<()>> {
    let endpoints = ctx
        .spec
        .vsock
        .as_ref()
        .map(|vsock| vsock.endpoints.clone())
        .unwrap_or_default();
    if endpoints.is_empty() {
        return None;
    }

    Some(tokio::spawn(async move {
        let mut handles = Vec::new();
        for endpoint in endpoints {
            if !endpoint.lifecycle.autostart {
                continue;
            }

            let endpoint_ctx = ctx.clone();
            let endpoint_instance_dir = instance_dir.clone();
            handles.push(tokio::spawn(async move {
                supervise_endpoint(endpoint_ctx, endpoint_instance_dir, endpoint).await;
            }));
        }

        ctx.shutdown.cancelled().await;

        for handle in handles {
            if let Err(err) = handle.await {
                tracing::error!(error = %err, "endpoint task failed during shutdown");
            }
        }
    }))
}

async fn supervise_endpoint(ctx: DaemonContext, instance_dir: PathBuf, endpoint: VsockEndpoint) {
    let mut backoff = endpoint_backoff_initial(&endpoint);

    tracing::info!(
        endpoint = %endpoint.name,
        mode = %endpoint_mode_name(endpoint.mode),
        port = endpoint.port,
        autostart = endpoint.lifecycle.autostart,
        restart_policy = %restart_policy_name(endpoint.lifecycle.restart),
        "starting endpoint supervision"
    );

    loop {
        if ctx.shutdown.is_cancelled() {
            return;
        }

        let started_at = Instant::now();
        let outcome = match endpoint.mode {
            VsockEndpointMode::Connect => {
                run_connect_endpoint(&ctx, &instance_dir, &endpoint).await
            }
            VsockEndpointMode::Listen => run_listen_endpoint(&ctx, &instance_dir, &endpoint).await,
        };

        let should_restart = match (&endpoint.lifecycle.restart, &outcome) {
            (_, EndpointOutcome::Shutdown) => false,
            (RestartPolicy::Never, _) => false,
            (RestartPolicy::OnFailure, EndpointOutcome::ExitedCleanly) => false,
            (RestartPolicy::OnFailure, EndpointOutcome::Failed(_)) => true,
            (RestartPolicy::Always, _) => true,
        };

        match &outcome {
            EndpointOutcome::Shutdown => {
                return;
            }
            EndpointOutcome::ExitedCleanly => {
                tracing::info!(
                    endpoint = %endpoint.name,
                    mode = %endpoint_mode_name(endpoint.mode),
                    port = endpoint.port,
                    "endpoint plugin exited cleanly"
                );
            }
            EndpointOutcome::Failed(message) => {
                tracing::error!(
                    endpoint = %endpoint.name,
                    mode = %endpoint_mode_name(endpoint.mode),
                    port = endpoint.port,
                    error = %message,
                    "endpoint failed"
                );
            }
        }

        if !should_restart {
            tracing::warn!(
                endpoint = %endpoint.name,
                mode = %endpoint_mode_name(endpoint.mode),
                port = endpoint.port,
                restart_policy = %restart_policy_name(endpoint.lifecycle.restart),
                "endpoint plugin will not be restarted"
            );
            return;
        }

        if started_at.elapsed() >= STABLE_RUN_RESET {
            backoff = endpoint_backoff_initial(&endpoint);
        }

        tokio::select! {
            _ = ctx.shutdown.cancelled() => {
                return;
            }
            _ = tokio::time::sleep(backoff) => {}
        }

        tracing::warn!(
            endpoint = %endpoint.name,
            mode = %endpoint_mode_name(endpoint.mode),
            port = endpoint.port,
            restart_policy = %restart_policy_name(endpoint.lifecycle.restart),
            backoff = ?backoff,
            "restarting endpoint plugin after failure"
        );

        backoff = std::cmp::min(backoff.saturating_mul(2), endpoint_backoff_max(&endpoint));
    }
}

async fn run_connect_endpoint(
    ctx: &DaemonContext,
    instance_dir: &Path,
    endpoint: &VsockEndpoint,
) -> EndpointOutcome {
    let (control_parent, mut plugin) = match start_endpoint_plugin(instance_dir, endpoint) {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };

    let broker = tokio::spawn(run_connect_broker(
        ctx.clone(),
        endpoint.clone(),
        control_parent,
    ));

    let ready = wait_for_plugin_ready(ctx, endpoint, &mut plugin).await;
    if let Err(outcome) = ready {
        broker.abort();
        return outcome;
    }

    let outcome = run_plugin_event_loop(ctx, endpoint, &mut plugin, Some(broker)).await;
    if !matches!(outcome, EndpointOutcome::Shutdown) {
        let _ = terminate_plugin(&mut plugin.child).await;
    }
    outcome
}

async fn run_listen_endpoint(
    ctx: &DaemonContext,
    instance_dir: &Path,
    endpoint: &VsockEndpoint,
) -> EndpointOutcome {
    let listener = match ctx.machine.listen_vsock(endpoint.port).await {
        Ok(listener) => listener,
        Err(err) => return EndpointOutcome::Failed(format!("listen vsock: {err}")),
    };

    let (control_parent, mut plugin) = match start_endpoint_plugin(instance_dir, endpoint) {
        Ok(value) => value,
        Err(outcome) => return outcome,
    };

    let ready = wait_for_plugin_ready(ctx, endpoint, &mut plugin).await;
    if let Err(outcome) = ready {
        return outcome;
    }

    let dispatcher = tokio::spawn(run_listen_dispatch(
        ctx.clone(),
        endpoint.clone(),
        listener,
        control_parent,
    ));

    let outcome = run_plugin_event_loop(ctx, endpoint, &mut plugin, Some(dispatcher)).await;
    if !matches!(outcome, EndpointOutcome::Shutdown) {
        let _ = terminate_plugin(&mut plugin.child).await;
    }
    outcome
}

fn start_endpoint_plugin(
    instance_dir: &Path,
    endpoint: &VsockEndpoint,
) -> Result<(OwnedFd, RunningPlugin), EndpointOutcome> {
    let (control_parent, control_child) = match socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    ) {
        Ok(pair) => pair,
        Err(err) => {
            return Err(EndpointOutcome::Failed(format!(
                "create control socketpair: {err}"
            )))
        }
    };

    let runtime_dir = instance_dir.to_path_buf();
    if let Err(err) = std::fs::create_dir_all(&runtime_dir) {
        return Err(EndpointOutcome::Failed(format!(
            "create endpoint runtime dir {}: {err}",
            runtime_dir.display()
        )));
    }

    let startup = StartupMessage::new(endpoint, runtime_dir, 3);
    tracing::info!(
        endpoint = %endpoint.name,
        mode = %endpoint_mode_name(endpoint.mode),
        port = endpoint.port,
        command = %endpoint.plugin.command.display(),
        args = ?endpoint.plugin.args,
        working_dir = ?endpoint.plugin.working_dir,
        "starting endpoint plugin"
    );
    let plugin = match spawn_plugin(endpoint, control_child, &startup) {
        Ok(plugin) => plugin,
        Err(err) => return Err(EndpointOutcome::Failed(format!("spawn plugin: {err}"))),
    };

    Ok((control_parent, plugin))
}

async fn wait_for_plugin_ready(
    ctx: &DaemonContext,
    endpoint: &VsockEndpoint,
    plugin: &mut RunningPlugin,
) -> Result<(), EndpointOutcome> {
    let timeout = Duration::from_millis(endpoint.lifecycle.startup_timeout_ms);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    tokio::select! {
        _ = ctx.shutdown.cancelled() => {
            let _ = terminate_plugin(&mut plugin.child).await;
            Err(EndpointOutcome::Shutdown)
        }
        _ = &mut deadline => {
            let _ = terminate_plugin(&mut plugin.child).await;
            Err(EndpointOutcome::Failed(format!("plugin did not become ready within {timeout:?}")))
        }
        status = plugin.child.wait() => {
            Err(child_exit_outcome(status))
        }
        event = plugin.events.recv() => {
            match event {
                Some(PluginEvent::Ready) => {
                    tracing::info!(
                        endpoint = %endpoint.name,
                        mode = %endpoint_mode_name(endpoint.mode),
                        port = endpoint.port,
                        "endpoint plugin ready"
                    );
                    Ok(())
                }
                Some(PluginEvent::Failed(message)) => {
                    tracing::error!(
                        endpoint = %endpoint.name,
                        mode = %endpoint_mode_name(endpoint.mode),
                        port = endpoint.port,
                        plugin_message = %message,
                        "endpoint plugin reported failure"
                    );
                    let _ = terminate_plugin(&mut plugin.child).await;
                    Err(EndpointOutcome::Failed(message))
                }
                None => Err(EndpointOutcome::Failed("plugin stdout closed before ready".to_string())),
            }
        }
    }
}

async fn run_plugin_event_loop(
    ctx: &DaemonContext,
    endpoint: &VsockEndpoint,
    plugin: &mut RunningPlugin,
    broker: Option<JoinHandle<Result<(), String>>>,
) -> EndpointOutcome {
    let mut broker = broker;
    loop {
        tokio::select! {
            _ = ctx.shutdown.cancelled() => {
                stop_control_task(&mut broker).await;
                let _ = terminate_plugin(&mut plugin.child).await;
                return EndpointOutcome::Shutdown;
            }
            status = plugin.child.wait() => {
                stop_control_task(&mut broker).await;
                return child_exit_outcome(status);
            }
            event = plugin.events.recv() => {
                if let Some(outcome) = handle_plugin_event(endpoint, event) {
                    stop_control_task(&mut broker).await;
                    if !matches!(outcome, EndpointOutcome::ExitedCleanly) {
                        let _ = terminate_plugin(&mut plugin.child).await;
                    }
                    return outcome;
                }
            }
            result = await_broker(&mut broker), if broker.is_some() => {
                if !matches!(result, Ok(())) {
                    let _ = terminate_plugin(&mut plugin.child).await;
                    return EndpointOutcome::Failed(result.err().unwrap());
                }
            }
        }
    }
}

async fn stop_control_task(broker: &mut Option<JoinHandle<Result<(), String>>>) {
    let Some(handle) = broker.take() else {
        return;
    };

    handle.abort();
    match handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "endpoint control task returned error during shutdown");
        }
        Err(err) if err.is_cancelled() => {}
        Err(err) => {
            tracing::debug!(error = %err, "endpoint control task join failed during shutdown");
        }
    }
}

async fn await_broker(broker: &mut Option<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    let Some(handle) = broker.take() else {
        return Err("broker handle missing".to_string());
    };
    match handle.await {
        Ok(result) => result,
        Err(err) if err.is_cancelled() => Ok(()),
        Err(err) => Err(format!("broker task failed: {err}")),
    }
}

fn handle_plugin_event(
    endpoint: &VsockEndpoint,
    event: Option<PluginEvent>,
) -> Option<EndpointOutcome> {
    match event {
        Some(PluginEvent::Ready) => None,
        Some(PluginEvent::Failed(message)) => {
            tracing::error!(
                endpoint = %endpoint.name,
                mode = %endpoint_mode_name(endpoint.mode),
                port = endpoint.port,
                plugin_message = %message,
                "endpoint plugin reported failure"
            );
            Some(EndpointOutcome::Failed(message))
        }
        None => Some(EndpointOutcome::Failed(
            "plugin stdout closed unexpectedly".to_string(),
        )),
    }
}

async fn send_incoming_conn_with_retry(
    ctx: &DaemonContext,
    endpoint: &VsockEndpoint,
    control: &OwnedFd,
    conn_fd: OwnedFd,
    conn_id: u64,
) -> Result<(), String> {
    let mut backoff = endpoint_backoff_initial(endpoint);
    loop {
        match send_control_message(
            control,
            &ControlMessageKind::ListenIncoming { conn_id },
            Some(&conn_fd),
        ) {
            Ok(()) => return Ok(()),
            Err(err) if err.raw_os_error() == Some(libc::ETOOMANYREFS) => {
                tracing::warn!(endpoint = %endpoint.name, error = %err, "endpoint fd passing hit backpressure");
            }
            Err(err) => return Err(format!("send connection fd: {err}")),
        }

        tokio::select! {
            _ = ctx.shutdown.cancelled() => return Err("shutdown requested".to_string()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = std::cmp::min(backoff.saturating_mul(2), endpoint_backoff_max(endpoint));
    }
}

async fn run_connect_broker(
    ctx: DaemonContext,
    endpoint: VsockEndpoint,
    control: OwnedFd,
) -> Result<(), String> {
    let control = Arc::new(
        BrokerControlSocket::new(control).map_err(|err| format!("wrap broker socket: {err}"))?,
    );

    loop {
        let message = match control.recv_message().await {
            Ok(message) => message,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(format!("read broker request: {err}")),
        };

        match message {
            ControlMessageKind::ConnectOpen { request_id } => {
                let result =
                    tokio::time::timeout(CONNECT_TIMEOUT, ctx.machine.connect_vsock(endpoint.port))
                        .await;
                match result {
                    Ok(Ok(stream)) => {
                        let fd = stream
                            .dup_fd()
                            .map_err(|err| format!("duplicate stream fd: {err}"))?;
                        control
                            .send_message(
                                &ControlMessageKind::ConnectOpenOk { request_id },
                                Some(&fd),
                            )
                            .await
                            .map_err(|err| format!("send connect_open_ok: {err}"))?;
                    }
                    Ok(Err(err)) => {
                        tracing::info!(endpoint = %endpoint.name, error = %err, "broker connect request failed");
                        control
                            .send_message(
                                &ControlMessageKind::ConnectOpenErr {
                                    request_id,
                                    retryable: true,
                                    message: format!("connect_vsock: {err}"),
                                },
                                None,
                            )
                            .await
                            .map_err(|err| format!("send connect_open_err: {err}"))?;
                    }
                    Err(_) => {
                        tracing::info!(endpoint = %endpoint.name, timeout = ?CONNECT_TIMEOUT, "broker connect request timed out");
                        control
                            .send_message(
                                &ControlMessageKind::ConnectOpenErr {
                                    request_id,
                                    retryable: true,
                                    message: format!(
                                        "connect_vsock timed out after {CONNECT_TIMEOUT:?}"
                                    ),
                                },
                                None,
                            )
                            .await
                            .map_err(|err| format!("send connect_open_err: {err}"))?;
                    }
                }
            }
            other => {
                return Err(format!(
                    "unexpected control message for connect broker: {}",
                    control_message_name(&other)
                ));
            }
        }
    }
}

async fn run_listen_dispatch(
    ctx: DaemonContext,
    endpoint: VsockEndpoint,
    mut listener: virt::VsockListener,
    control: OwnedFd,
) -> Result<(), String> {
    let mut conn_id = 0_u64;
    loop {
        tokio::select! {
            _ = ctx.shutdown.cancelled() => return Ok(()),
            accept_result = listener.accept() => {
                let stream = accept_result
                    .map_err(|err| format!("accept vsock connection: {err}"))?;

                let fd = stream
                    .dup_fd()
                    .map_err(|err| format!("duplicate accepted fd: {err}"))?;

                conn_id = conn_id.saturating_add(1);
                tracing::debug!(
                    endpoint = %endpoint.name,
                    mode = %endpoint_mode_name(endpoint.mode),
                    port = endpoint.port,
                    conn_id,
                    "accepted endpoint connection"
                );
                send_incoming_conn_with_retry(&ctx, &endpoint, &control, fd, conn_id).await?;
                tracing::debug!(
                    endpoint = %endpoint.name,
                    mode = %endpoint_mode_name(endpoint.mode),
                    port = endpoint.port,
                    conn_id,
                    "handed endpoint connection to plugin"
                );
            }
        }
    }
}

fn endpoint_backoff_initial(endpoint: &VsockEndpoint) -> Duration {
    Duration::from_millis(endpoint.lifecycle.backoff_ms.initial)
}

fn endpoint_backoff_max(endpoint: &VsockEndpoint) -> Duration {
    Duration::from_millis(endpoint.lifecycle.backoff_ms.max)
}

fn child_exit_outcome(status: io::Result<std::process::ExitStatus>) -> EndpointOutcome {
    match status {
        Ok(exit_status) if exit_status.success() => EndpointOutcome::ExitedCleanly,
        Ok(exit_status) => {
            EndpointOutcome::Failed(format!("plugin exited with status {exit_status}"))
        }
        Err(err) => EndpointOutcome::Failed(format!("wait for plugin exit: {err}")),
    }
}

#[derive(Debug)]
enum EndpointOutcome {
    Shutdown,
    ExitedCleanly,
    Failed(String),
}

fn endpoint_mode_name(mode: VsockEndpointMode) -> &'static str {
    match mode {
        VsockEndpointMode::Connect => "connect",
        VsockEndpointMode::Listen => "listen",
    }
}

fn restart_policy_name(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::Never => "never",
        RestartPolicy::OnFailure => "on_failure",
        RestartPolicy::Always => "always",
    }
}

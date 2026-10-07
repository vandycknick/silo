//! Linux ExecStop guard. Host state authorization belongs to the adjacent Go helper.
//! Neither ordinary termination nor failure to reach an owner authorizes takeover.
#[cfg(not(target_os = "linux"))]
pub(crate) async fn run() -> eyre::Result<()> {
    eyre::bail!("host shutdown protection is unsupported on this platform")
}

#[cfg(target_os = "linux")]
pub(crate) async fn run() -> eyre::Result<()> {
    use crate::{
        control::{socket::SocketOwnership, ControlState},
        helper,
        paths::SystemPaths,
        status::StatusPublisher,
        supervisor::LifetimeLock,
    };
    use silo_vm_control::transport::{probe, Admission};
    use silod_spec::status::CorePhase;
    use std::{sync::Arc, time::Duration};
    use tokio_util::sync::CancellationToken;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(85);
    let helper_deadline = deadline - Duration::from_secs(5);
    let host = libvm::HostPaths::from_env()?;
    let global = silo_config::GlobalConfig::load_from(&host)?;
    if let Some(selected) = probe(&host, Admission::Owned).await? {
        // Keep the admitted connection alive throughout the child invocation.
        // Never refresh identity or register/revoke a normal helper generation.
        return helper::host_shutdown(&selected.status, global.tailscale(), helper_deadline).await;
    }

    let host = silo_config::prepare_host_paths(&host)?;
    let paths = SystemPaths::from_host(&host);
    let _lifetime = LifetimeLock::acquire(&paths.lifetime_lock())?;
    let ownership = SocketOwnership::acquire()?;
    // Both ownership domains are held before touching status or the endpoint.
    let features = silo_config::FeatureSelection {
        system: false,
        tailscale: false,
    };
    let generation = uuid::Uuid::new_v4();
    let identity = global.daemon_identity(features)?;
    let config = global.tailscale().clone();
    let publisher = Arc::new(StatusPublisher::new(
        &host, generation, features, identity, None,
    )?);
    let state = Arc::new(ControlState::shutdown_only(
        host,
        global,
        generation,
        publisher.clone(),
    ));
    let server = match ownership.bind(state.clone()) {
        Ok(server) => server,
        Err(error) => {
            publisher.set_core(CorePhase::Failed, Some(format!("{error:#}")))?;
            return Err(error);
        }
    };
    publisher.set_core(CorePhase::Ready, None)?;
    let identity = state.get_status().await?;
    let shutdown = CancellationToken::new();
    let mut api = tokio::spawn(server.serve(shutdown.clone()));
    let child = helper::host_shutdown(&identity, &config, helper_deadline).await;
    // Child waiter retirement is not native completion. Seal only after the
    // helper has reaped, then settle every accepted operation independently.
    state.seal_mutations().await;
    let drain = tokio::time::timeout_at(deadline, state.drain_mutations())
        .await
        .map_err(|_| {
            eyre::eyre!("host shutdown deadline expired with incomplete native mutation drain")
        })
        .and_then(|result| result.map_err(Into::into));
    shutdown.cancel();
    let api_result = match tokio::time::timeout(Duration::from_secs(2), &mut api).await {
        Ok(result) => result.map_err(eyre::Report::from).and_then(|result| result),
        Err(_) => {
            api.abort();
            let _ = api.await;
            Err(eyre::eyre!("shutdown control service deadline expired"))
        }
    };
    let result = child.and(drain).and(api_result);
    publisher.set_core(
        if result.is_ok() {
            CorePhase::Stopped
        } else {
            CorePhase::Failed
        },
        result.as_ref().err().map(|error| format!("{error:#}")),
    )?;
    result
}

#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod forward;
#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
mod port;
#[cfg(target_os = "linux")]
mod provision;
#[cfg(target_os = "linux")]
mod rpc;
#[cfg(target_os = "linux")]
mod server;

#[cfg(target_os = "linux")]
use std::io;

#[cfg(target_os = "linux")]
use bento_core::agent::RESERVED_SHELL_PORT;
#[cfg(target_os = "linux")]
use tokio::io::copy_bidirectional;
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
use crate::config::load_agent_config;
#[cfg(target_os = "linux")]
use crate::dns::DnsServer;
#[cfg(target_os = "linux")]
use crate::forward::ForwardService;
#[cfg(target_os = "linux")]
use crate::port::from_kernel_cmdline;
#[cfg(target_os = "linux")]
use crate::provision::run_provisioning;
#[cfg(target_os = "linux")]
use crate::rpc::{serve_agent_connection, AgentContext};
#[cfg(target_os = "linux")]
use crate::server::VsockServer;

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    let is_pid1 = std::process::id() == 1;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_writer(std::io::stdout)
        .try_init();

    // TODO: support direct PID 1 initialization in the future. For now the
    // agent still expects systemd/cloud-init to own early system setup.
    if is_pid1 {
        tracing::info!("running as PID 1 without init mode enabled yet");
    }

    tracing::info!("agent starting");

    let agent_config = load_agent_config()?;
    run_provisioning(&agent_config.provision)?;

    let control_port = from_kernel_cmdline();
    let mut running_servers = Vec::new();
    let dns_server = if agent_config.dns.enabled {
        let dns_server = DnsServer::new(&agent_config.dns).await?;
        DnsServer::write_resolv_conf(Some(agent_config.dns.listen_address))?;
        Some(dns_server)
    } else {
        None
    };

    if agent_config.ssh.enabled {
        let shell_server = VsockServer::create(|mut stream| async move {
            let mut ssh = TcpStream::connect("127.0.0.1:22").await?;
            let _ = copy_bidirectional(&mut stream, &mut ssh).await?;
            Ok(())
        })
        .with_concurrency(256)
        .with_tracing(tracing::info_span!("vsock_server", service = "shell"))
        .listen(RESERVED_SHELL_PORT)?;
        running_servers.push(shell_server);
    }

    if agent_config.forward.enabled {
        if agent_config.forward.port == 0 {
            return Err(eyre::eyre!(
                "forward guest runtime is enabled but no 'forward' endpoint port was configured"
            ));
        }

        let forward_service = ForwardService::new(agent_config.forward.clone())?;
        let forward_server = VsockServer::create(move |stream| {
            let forward_service = forward_service.clone();
            async move { forward_service.handle_connection(stream).await }
        })
        .with_concurrency(256)
        .with_tracing(tracing::info_span!("vsock_server", service = "forward"))
        .listen(agent_config.forward.port)?;
        running_servers.push(forward_server);
    }

    let agent_service = AgentContext::new(agent_config.clone());

    let control_server = VsockServer::create(move |stream| {
        let agent = agent_service.clone();
        async move {
            serve_agent_connection(stream, agent)
                .await
                .map_err(|err| io::Error::other(err.to_string()))
        }
    })
    .with_concurrency(64)
    .with_tracing(tracing::info_span!("vsock_server", service = "agent"))
    .listen(control_port)?;

    running_servers.push(control_server);

    let mut join_set = tokio::task::JoinSet::new();
    for server in running_servers {
        join_set.spawn(server.wait());
    }
    let cancel = tokio_util::sync::CancellationToken::new();

    let dns_handle = dns_server.map(|dns_server| {
        let token = cancel.clone();
        tokio::spawn(async move {
            if let Err(err) = dns_server.run(token).await {
                tracing::error!(error = %err, "dns server exited unexpectedly");
            }
        })
    });

    while let Some(result) = join_set.join_next().await {
        result??;
    }

    // Shut down background tasks.
    cancel.cancel();
    if let Some(dns_handle) = dns_handle {
        let _ = tokio::join!(dns_handle);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("bento-agent only runs inside Linux guests");
    std::process::exit(1);
}

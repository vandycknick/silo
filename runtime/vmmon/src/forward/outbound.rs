use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use forward_spec::{Address, ErrReason, Reply, TargetLine, MAX_TARGET_LINE_BYTES};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;

use crate::forward::host_socket::HostStream;
use crate::forward::{ForwardEntry, ForwardTable};
use crate::virt::VsockListener;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn serve_raw_retained(
    mut listener: VsockListener,
    target: Arc<RwLock<Option<Arc<ForwardEntry>>>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(guest) => {
                    let entry = target.read().unwrap_or_else(PoisonError::into_inner).clone();
                    if let Some(entry) = entry {
                        connections.spawn(async move {
                            if let Err(error) = relay_to_target(guest, entry.clone()).await {
                                entry.refuse();
                                tracing::debug!(forward = %entry.name, %error, "raw outbound forward connection failed");
                            }
                        });
                    }
                }
                Err(error) => tracing::warn!(%error, "raw outbound forward accept failed"),
            },
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "raw outbound forward task failed");
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

pub(crate) async fn serve_return(mut listener: VsockListener, table: Arc<ForwardTable>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = table.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(stream) => {
                    let table = table.clone();
                    connections.spawn(async move { handle_return(stream, table).await });
                }
                Err(error) => tracing::warn!(%error, "forward return-port accept failed"),
            },
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!(%error, "forward return-port task failed");
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn handle_return(mut guest: crate::virt::VsockStream, table: Arc<ForwardTable>) {
    let setup = tokio::time::timeout(SETUP_TIMEOUT, async {
        let line = forward_spec::io::read_line(&mut guest, MAX_TARGET_LINE_BYTES).await;
        let token = match line
            .ok()
            .and_then(|line| forward_spec::parse_connect(&line).ok())
        {
            Some(TargetLine::Token(token)) => token,
            _ => {
                table.warn_invalid_token();
                guest
                    .write_all(forward_spec::encode_reply(&Reply::Err(ErrReason::Invalid)))
                    .await?;
                return Ok::<_, io::Error>(None);
            }
        };
        let Some(entry) = table.token_entry(token) else {
            table.warn_invalid_token();
            guest
                .write_all(forward_spec::encode_reply(&Reply::Err(ErrReason::Invalid)))
                .await?;
            return Ok(None);
        };
        let Some(target) = entry.host_target.as_ref() else {
            return Ok(None);
        };
        match connect_target(target).await {
            Ok(host) => {
                guest
                    .write_all(forward_spec::encode_reply(&Reply::Ok))
                    .await?;
                Ok(Some((entry, host)))
            }
            Err(error) => {
                let reason = map_error(&error);
                guest
                    .write_all(forward_spec::encode_reply(&Reply::Err(reason)))
                    .await?;
                entry.refuse();
                tracing::debug!(
                    forward = %entry.name,
                    target = %target,
                    %reason,
                    %error,
                    "outbound forward host target refused connection"
                );
                Ok(None)
            }
        }
    })
    .await;
    let Ok(Ok(Some((entry, mut host)))) = setup else {
        if setup.is_err() {
            let _ = guest
                .write_all(forward_spec::encode_reply(&Reply::Err(ErrReason::Timeout)))
                .await;
        }
        return;
    };
    entry.connection_opened();
    let _ = crate::vsock::relay::relay(&mut guest, &mut host, entry.shutdown.clone()).await;
    entry.connection_closed();
}

async fn relay_to_target(
    mut guest: crate::virt::VsockStream,
    entry: Arc<ForwardEntry>,
) -> eyre::Result<()> {
    let target = entry
        .host_target
        .as_ref()
        .ok_or_else(|| eyre::eyre!("outbound forward has no host target"))?;
    let mut host = tokio::time::timeout(SETUP_TIMEOUT, connect_target(target))
        .await
        .map_err(|_| eyre::eyre!("host target setup timed out"))??;
    entry.connection_opened();
    let result = crate::vsock::relay::relay(&mut guest, &mut host, entry.shutdown.clone()).await;
    entry.connection_closed();
    result.map_err(eyre::Report::from)
}

async fn connect_target(address: &Address) -> io::Result<HostStream> {
    match address {
        Address::Tcp(address) => tokio::net::TcpStream::connect(address)
            .await
            .map(|stream| Box::new(stream) as HostStream),
        Address::Unix(path) => tokio::net::UnixStream::connect(path)
            .await
            .map(|stream| Box::new(stream) as HostStream),
    }
}

fn map_error(error: &io::Error) -> ErrReason {
    match error.kind() {
        io::ErrorKind::NotFound => ErrReason::NotFound,
        io::ErrorKind::PermissionDenied => ErrReason::Permission,
        io::ErrorKind::TimedOut => ErrReason::Timeout,
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::AddrNotAvailable => ErrReason::Unreachable,
        _ => ErrReason::Refused,
    }
}

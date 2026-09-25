use std::io;
use std::sync::Arc;
use std::time::Duration;

use forward_spec::{Address, ErrReason, Reply, TargetLine, MAX_TARGET_LINE_BYTES};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;

use crate::forward::host_socket::HostStream;
use crate::forward::{ForwardEntry, ForwardTable};
use crate::virt::VsockListener;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn serve_raw(mut listener: VsockListener, entry: Arc<ForwardEntry>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = entry.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(guest) => {
                    let entry = entry.clone();
                    connections.spawn(async move {
                        if let Err(error) = relay_to_target(guest, entry.clone()).await {
                            entry.refuse();
                            tracing::debug!(forward = %entry.name, %error, "raw outbound forward connection failed");
                        }
                    });
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

pub(crate) async fn serve_return(
    mut listener: VsockListener,
    table: Arc<ForwardTable>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
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
        let Some(lifetime) = entry.connection_lifetime() else {
            guest
                .write_all(forward_spec::encode_reply(&Reply::Err(ErrReason::Invalid)))
                .await?;
            return Ok(None);
        };
        let Some(target) = entry.host_target.as_ref() else {
            return Ok(None);
        };
        let connected = tokio::select! {
            _ = lifetime.cancelled() => return Ok(None),
            result = connect_target(target) => result,
        };
        match connected {
            Ok(host) => {
                guest
                    .write_all(forward_spec::encode_reply(&Reply::Ok))
                    .await?;
                Ok(Some((entry, host, lifetime)))
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
    let Ok(Ok(Some((entry, mut host, lifetime)))) = setup else {
        if setup.is_err() {
            let _ = guest
                .write_all(forward_spec::encode_reply(&Reply::Err(ErrReason::Timeout)))
                .await;
        }
        return;
    };
    let _connection = entry.connection_opened();
    let _ = crate::vsock::relay::relay(&mut guest, &mut host, lifetime).await;
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
    let _connection = entry.connection_opened();
    let result = crate::vsock::relay::relay(&mut guest, &mut host, entry.shutdown.clone()).await;
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

#[cfg(test)]
mod tests {
    use crate::forward::{ForwardTable, GuestHalfAvailability};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn return_streams_are_fenced_on_readiness_loss_and_listener_end() {
        let host = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forward = forward_spec::Forward::new(
            "guest:tcp:0".parse().unwrap(),
            forward_spec::Endpoint::Host(forward_spec::Address::Tcp(host.local_addr().unwrap())),
        );
        let table =
            ForwardTable::prepare_machine(&[forward], std::path::Path::new("/unused"), None)
                .await
                .unwrap();
        let entry = table.entries().remove(0);
        let identity = crate::state::ReadyAgentIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: uuid::Uuid::new_v4(),
        };
        let available = GuestHalfAvailability::Available(Some(identity.clone()));
        let line =
            forward_spec::encode_connect(&forward_spec::TargetLine::Token(entry.token.unwrap()))
                .unwrap();
        for readiness_loss in [true, false] {
            table.set_agent_availability(available.clone());
            assert!(entry.activate_guest_listener(&identity, "tcp:127.0.0.1:5432".parse().unwrap()));
            let generation = entry.connection_lifetime().unwrap();
            let (mut guest, server) = tokio::net::UnixStream::pair().unwrap();
            let stream = crate::virt::VsockStream::from_unix_stream(
                server,
                Some(5000),
                forward_spec::FORWARD_VSOCK_PORT,
                None,
            );
            let task = tokio::spawn(crate::forward::outbound::handle_return(
                stream,
                table.clone(),
            ));
            guest.write_all(&line).await.unwrap();
            let (mut target, _) = host.accept().await.unwrap();
            assert_eq!(
                forward_spec::io::read_line(&mut guest, 512).await.unwrap(),
                b"OK\n"
            );
            guest.write_all(b"hello").await.unwrap();
            let mut bytes = [0; 5];
            target.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            assert_eq!(entry.snapshot().active_connections, 1);
            table.set_agent_availability(available.clone());
            assert!(
                !generation.is_cancelled(),
                "duplicate readiness must not kill streams"
            );
            if readiness_loss {
                table.set_agent_availability(GuestHalfAvailability::Unknown);
            } else {
                entry.end_guest_listener();
            }
            assert!(generation.is_cancelled());
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(entry.snapshot().active_connections, 0);
            assert_eq!(target.read(&mut bytes).await.unwrap(), 0);
            assert_eq!(guest.read(&mut bytes).await.unwrap(), 0);

            let (mut guest, server) = tokio::net::UnixStream::pair().unwrap();
            let stream = crate::virt::VsockStream::from_unix_stream(
                server,
                Some(5001),
                forward_spec::FORWARD_VSOCK_PORT,
                None,
            );
            let task = tokio::spawn(crate::forward::outbound::handle_return(
                stream,
                table.clone(),
            ));
            guest.write_all(&line).await.unwrap();
            assert_eq!(
                forward_spec::io::read_line(&mut guest, 512).await.unwrap(),
                b"ERR invalid\n"
            );
            task.await.unwrap();
        }
    }
}

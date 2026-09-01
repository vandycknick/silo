use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::virt::VirtualMachine;
use crate::vsock::relay;

const CONNECTION_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_COMMAND_BYTES: usize = 32;

pub(crate) async fn serve(
    listener: UnixListener,
    owner_uid: u32,
    machine: VirtualMachine,
    shutdown: CancellationToken,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    let credentials = match stream.peer_cred() {
                        Ok(credentials) if peer_uid_authorized(owner_uid, credentials.uid()) => credentials,
                        Ok(credentials) => {
                            tracing::warn!(uid = credentials.uid(), expected_uid = owner_uid, "rejected vsock mux connection from unauthorized UID");
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(%error, "rejected vsock mux connection without peer credentials");
                            continue;
                        }
                    };
                    if machine.vsock_capacity_exhausted() {
                        tracing::warn!(machine = machine.name(), "rejected vsock mux connection at active connection limit");
                        continue;
                    }
                    tracing::debug!(uid = credentials.uid(), pid = ?credentials.pid(), "accepted vsock mux connection");
                    let machine = machine.clone();
                    let shutdown = shutdown.clone();
                    connections.spawn(async move {
                        if let Err(error) = handle_connection(stream, machine, shutdown).await {
                            tracing::debug!(%error, "closed vsock mux connection without acknowledgement");
                        }
                    });
                }
                Err(error) => tracing::warn!(%error, "vsock mux accept failed"),
            },
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "vsock mux connection task failed");
                }
            }
        }
    }
    while connections.join_next().await.is_some() {}
}

fn peer_uid_authorized(owner_uid: u32, peer_uid: u32) -> bool {
    owner_uid == peer_uid
}

async fn handle_connection(
    mut client: UnixStream,
    machine: VirtualMachine,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    let port = tokio::select! {
        result = read_command(&mut client) => result?,
        _ = shutdown.cancelled() => return Ok(()),
    };
    let lease = machine.reserve_vsock()?;
    let mut guest = tokio::select! {
        result = tokio::time::timeout(
            CONNECTION_REQUEST_TIMEOUT,
            machine.connect_vsock_reserved(port, lease),
        ) => result.map_err(|_| eyre::eyre!("guest vsock connection timed out"))??,
        _ = shutdown.cancelled() => return Ok(()),
    };
    let source_port = guest
        .source_port()
        .ok_or_else(|| eyre::eyre!("backend did not report a host-side vsock source port"))?;
    client
        .write_all(format!("OK {source_port}\n").as_bytes())
        .await?;
    relay::relay(&mut client, &mut guest, shutdown).await?;
    Ok(())
}

async fn read_command(stream: &mut UnixStream) -> eyre::Result<u32> {
    let mut command = Vec::with_capacity(MAX_COMMAND_BYTES);
    for _ in 0..MAX_COMMAND_BYTES {
        let byte = stream.read_u8().await?;
        command.push(byte);
        if byte == b'\n' {
            return parse_command(&command);
        }
    }
    Err(eyre::eyre!("vsock mux command exceeds 32 bytes"))
}

fn parse_command(command: &[u8]) -> eyre::Result<u32> {
    let command = command
        .strip_suffix(b"\n")
        .and_then(|command| command.strip_prefix(b"CONNECT "))
        .ok_or_else(|| eyre::eyre!("malformed vsock mux command"))?;
    let raw = std::str::from_utf8(command)?;
    let port = raw
        .parse::<u32>()
        .map_err(|_| eyre::eyre!("invalid vsock mux port"))?;
    if raw != port.to_string() {
        return Err(eyre::eyre!("non-canonical vsock mux port"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use crate::vsock::mux::{parse_command, peer_uid_authorized, read_command, MAX_COMMAND_BYTES};

    #[test]
    fn command_parser_accepts_only_the_canonical_protocol() {
        for (command, expected) in [
            (&b"CONNECT 0\n"[..], Some(0)),
            (&b"CONNECT 22\n"[..], Some(22)),
            (&b"CONNECT 4294967295\n"[..], Some(u32::MAX)),
            (&b"CONNECT 01\n"[..], None),
            (&b"CONNECT +1\n"[..], None),
            (&b"CONNECT -1\n"[..], None),
            (&b"CONNECT 4294967296\n"[..], None),
            (&b"CONNECT 22\r\n"[..], None),
            (&b"connect 22\n"[..], None),
            (&b"CONNECT 22"[..], None),
            (&b"CONNECT\n"[..], None),
        ] {
            assert_eq!(parse_command(command).ok(), expected, "{command:?}");
        }
    }

    #[tokio::test]
    async fn command_reader_does_not_consume_pipelined_payload() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(b"CONNECT 22\npayload")
            .await
            .expect("write command and payload");

        assert_eq!(read_command(&mut server).await.expect("read command"), 22);
        let mut payload = [0_u8; 7];
        server
            .read_exact(&mut payload)
            .await
            .expect("read untouched payload");
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn command_reader_rejects_partial_and_oversized_commands() {
        let (mut partial_client, mut partial_server) = UnixStream::pair().expect("partial pair");
        partial_client
            .write_all(b"CONNECT 22")
            .await
            .expect("write partial command");
        partial_client
            .shutdown()
            .await
            .expect("close partial command");
        assert!(read_command(&mut partial_server).await.is_err());

        let (mut large_client, mut large_server) = UnixStream::pair().expect("large pair");
        large_client
            .write_all(&[b'x'; MAX_COMMAND_BYTES])
            .await
            .expect("write oversized command");
        assert!(read_command(&mut large_server).await.is_err());
    }

    #[tokio::test]
    async fn local_peer_credentials_match_the_effective_uid() {
        let (client, _server) = UnixStream::pair().expect("socket pair");
        let credentials = client.peer_cred().expect("read peer credentials");
        assert_eq!(credentials.uid(), nix::unistd::geteuid().as_raw());
        assert!(peer_uid_authorized(credentials.uid(), credentials.uid()));
        assert!(!peer_uid_authorized(
            credentials.uid(),
            credentials.uid().wrapping_add(1)
        ));
    }
}

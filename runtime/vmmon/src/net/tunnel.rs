use std::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use virt::VsockStream;

pub fn spawn_tunnel(stream: UnixStream, vsock_stream: VsockStream) {
    tokio::spawn(async move {
        if let Err(err) = proxy_streams(stream, vsock_stream).await {
            if is_expected_disconnect(&err) {
                tracing::debug!(error = %err, "vsock relay closed");
            } else {
                tracing::error!(error = %err, "vsock relay failed");
            }
        }
    });
}

async fn proxy_streams(
    client_stream: UnixStream,
    vsock_stream: VsockStream,
) -> std::io::Result<()> {
    let (client_read, client_write) = client_stream.into_split();
    let (vsock_read, vsock_write) = tokio::io::split(vsock_stream);

    let input = relay_input(client_read, vsock_write);
    let output = relay_output(vsock_read, client_write);

    tokio::pin!(input);
    tokio::pin!(output);

    tokio::select! {
        result = &mut output => result,
        result = &mut input => {
            result?;
            output.await
        }
    }
}

async fn relay_input<W>(mut client_read: OwnedReadHalf, mut vsock_write: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    copy_or_expected_disconnect(&mut client_read, &mut vsock_write).await?;
    shutdown_or_expected_disconnect(&mut vsock_write).await
}

async fn relay_output<R>(mut vsock_read: R, mut client_write: OwnedWriteHalf) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    copy_or_expected_disconnect(&mut vsock_read, &mut client_write).await?;
    shutdown_or_expected_disconnect(&mut client_write).await
}

async fn copy_or_expected_disconnect<R, W>(read: &mut R, write: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match tokio::io::copy(read, write).await {
        Ok(_) => Ok(()),
        Err(err) if is_expected_disconnect(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

async fn shutdown_or_expected_disconnect<W>(write: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match write.shutdown().await {
        Ok(()) => Ok(()),
        Err(err) if is_expected_disconnect(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn is_expected_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::Interrupted
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Duration;

    use tokio::net::UnixStream;
    use virt::VsockStream;

    use crate::net::tunnel::proxy_streams;

    #[tokio::test]
    async fn proxy_streams_exits_after_client_disconnect() {
        let (client_stream, peer_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        let (vsock_stream, guest_stream) =
            StdUnixStream::pair().expect("guest stream pair should be created");
        vsock_stream
            .set_nonblocking(true)
            .expect("vsock stream should be nonblocking");
        guest_stream
            .set_nonblocking(true)
            .expect("guest stream should be nonblocking");

        let vsock_stream =
            UnixStream::from_std(vsock_stream).expect("tokio stream should wrap std unix stream");
        let vsock_stream = VsockStream::from_unix_stream(vsock_stream);
        let tunnel = tokio::spawn(async move { proxy_streams(client_stream, vsock_stream).await });

        drop(peer_stream);
        drop(guest_stream);

        let result = tokio::time::timeout(Duration::from_secs(1), tunnel)
            .await
            .expect("proxy task should exit promptly")
            .expect("proxy task should join successfully");

        result.expect("proxy should treat disconnect as clean shutdown");
    }

    #[tokio::test]
    async fn proxy_streams_exits_after_guest_disconnect_while_client_stays_open() {
        let (client_stream, _peer_stream) =
            UnixStream::pair().expect("unix stream pair should be created");
        let (vsock_stream, guest_stream) =
            StdUnixStream::pair().expect("guest stream pair should be created");
        vsock_stream
            .set_nonblocking(true)
            .expect("vsock stream should be nonblocking");
        guest_stream
            .set_nonblocking(true)
            .expect("guest stream should be nonblocking");

        let vsock_stream =
            UnixStream::from_std(vsock_stream).expect("tokio stream should wrap std unix stream");
        let vsock_stream = VsockStream::from_unix_stream(vsock_stream);
        let tunnel = tokio::spawn(async move { proxy_streams(client_stream, vsock_stream).await });

        drop(guest_stream);

        let result = tokio::time::timeout(Duration::from_secs(1), tunnel)
            .await
            .expect("proxy task should exit promptly after guest disconnect")
            .expect("proxy task should join successfully");

        result.expect("proxy should treat guest disconnect as clean shutdown");
    }
}

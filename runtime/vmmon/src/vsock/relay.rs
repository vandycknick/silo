use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub(crate) async fn relay<A, B>(
    mut left: A,
    mut right: B,
    shutdown: CancellationToken,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut left, &mut right) => result.map(|_| ()),
        _ = shutdown.cancelled() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio_util::sync::CancellationToken;

    use crate::vsock::relay::relay;

    #[tokio::test]
    async fn relay_preserves_both_half_closes() {
        let (mut left_client, left_relay) = UnixStream::pair().expect("left socket pair");
        let (right_relay, mut right_client) = UnixStream::pair().expect("right socket pair");
        let task = tokio::spawn(relay(left_relay, right_relay, CancellationToken::new()));

        left_client
            .write_all(b"request")
            .await
            .expect("write request");
        left_client.shutdown().await.expect("half-close request");
        let mut request = Vec::new();
        right_client
            .read_to_end(&mut request)
            .await
            .expect("read request and EOF");
        assert_eq!(request, b"request");

        right_client
            .write_all(b"response")
            .await
            .expect("write response");
        right_client.shutdown().await.expect("half-close response");
        let mut response = Vec::new();
        left_client
            .read_to_end(&mut response)
            .await
            .expect("read response and EOF");
        assert_eq!(response, b"response");
        task.await.expect("relay task").expect("relay succeeds");
    }

    #[tokio::test]
    async fn cancellation_closes_a_blocked_relay() {
        let (left_client, left_relay) = UnixStream::pair().expect("left socket pair");
        let (right_relay, right_client) = UnixStream::pair().expect("right socket pair");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(relay(left_relay, right_relay, shutdown.clone()));

        shutdown.cancel();
        task.await.expect("relay task").expect("relay cancellation");
        drop(left_client);
        drop(right_client);
    }
}

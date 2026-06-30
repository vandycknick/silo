use std::future::Future;

use protocol::negotiate::{RejectCode, Upgrade};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::net::listener::NegotiateListener;

pub(crate) struct NegotiationRejection {
    pub(crate) code: RejectCode,
    pub(crate) message: String,
    pub(crate) retry_after_ms: Option<u32>,
}

pub(crate) struct NegotiateServer {
    listener: UnixListener,
    shutdown: CancellationToken,
}

impl NegotiateServer {
    pub(crate) fn new(listener: UnixListener, shutdown: CancellationToken) -> Self {
        Self { listener, shutdown }
    }

    pub(crate) fn listen<P, H, Fut>(self, policy: P, handler: H) -> JoinHandle<eyre::Result<()>>
    where
        P: Fn(&Upgrade) -> Option<NegotiationRejection> + Clone + Send + Sync + 'static,
        H: Fn(UnixStream, Upgrade) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = eyre::Result<()>> + Send + 'static,
    {
        tokio::spawn(async move {
            let incoming = NegotiateListener::new(self.listener, self.shutdown);
            while let Some(pending) = incoming.next().await {
                if let Some(rejection) = policy(pending.upgrade()) {
                    if let Err(err) = pending
                        .reject(rejection.code, rejection.message, rejection.retry_after_ms)
                        .await
                    {
                        tracing::warn!(error = %err, "failed to reject negotiated connection");
                    }
                    continue;
                }

                let (stream, upgrade) = match pending.accept().await {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(error = %err, "failed to accept negotiated connection");
                        continue;
                    }
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(err) = handler(stream, upgrade).await {
                        tracing::warn!(error = %err, "shell control request failed");
                    }
                });
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use protocol::negotiate::{ClientUpgradeStreamError, Negotiate, RejectCode, Upgrade};
    use tokio::net::{UnixListener, UnixStream};
    use tokio_util::sync::CancellationToken;

    use crate::net::server::{NegotiateServer, NegotiationRejection};

    #[tokio::test]
    async fn policy_rejection_is_sent_before_handler_runs() {
        let socket = test_socket_path();
        let listener = UnixListener::bind(&socket).unwrap();
        let shutdown = CancellationToken::new();
        let handled = Arc::new(AtomicBool::new(false));
        let handled_by_handler = handled.clone();

        let server = NegotiateServer::new(listener, shutdown.clone()).listen(
            |upgrade| match upgrade {
                Upgrade::Shell => Some(NegotiationRejection {
                    code: RejectCode::ServiceStarting,
                    message: String::from("guest shell is not ready"),
                    retry_after_ms: Some(1_000),
                }),
                Upgrade::Serial | Upgrade::Api { .. } => None,
            },
            move |_stream, _upgrade| {
                let handled = handled_by_handler.clone();
                async move {
                    handled.store(true, Ordering::Release);
                    Ok(())
                }
            },
        );

        let stream = UnixStream::connect(&socket).await.unwrap();
        let error = Negotiate::client_upgrade_stream_v1(stream, Upgrade::Shell)
            .await
            .unwrap_err();

        match error {
            ClientUpgradeStreamError::Reject(reject) => {
                assert_eq!(reject.code, RejectCode::ServiceStarting);
                assert_eq!(reject.retry_after_ms, Some(1_000));
            }
            ClientUpgradeStreamError::Io(err) => panic!("expected rejection, got io error: {err}"),
        }
        assert!(!handled.load(Ordering::Acquire));

        shutdown.cancel();
        server.await.unwrap().unwrap();
        let _ = std::fs::remove_file(socket);
    }

    fn test_socket_path() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::path::PathBuf::from(format!(
            "/tmp/vmmon-neg-{}-{nanos}.sock",
            std::process::id()
        ))
    }
}

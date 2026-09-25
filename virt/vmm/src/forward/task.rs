use std::future::Future;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Owns one listener task, including cancellation during teardown itself.
pub(crate) struct OwnedTask {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl OwnedTask {
    pub(crate) fn spawn(
        shutdown: CancellationToken,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            shutdown,
            handle: Some(tokio::spawn(future)),
        }
    }

    pub(crate) async fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.handle.as_mut() {
            if let Err(error) = handle.await {
                tracing::warn!(%error, "forward listener task failed");
            }
        }
        self.handle = None;
    }
}

impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::forward::task::OwnedTask;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn stopping_or_dropping_task_releases_its_listener() {
        for graceful in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let shutdown = CancellationToken::new();
            let stop = shutdown.clone();
            let task = OwnedTask::spawn(shutdown, async move {
                let _listener = listener;
                stop.cancelled().await;
            });
            if graceful {
                task.stop().await;
            } else {
                drop(task);
            }
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                loop {
                    if tokio::net::TcpListener::bind(address).await.is_ok() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }
}

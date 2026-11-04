use std::future::Future;
use std::io;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};
use tracing::{Instrument, Span};

pub struct RunningServer {
    task: Option<JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
}

impl RunningServer {
    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown.clone()
    }

    pub async fn wait(mut self) -> Result<(), tokio::task::JoinError> {
        if let Some(task) = self.task.take() {
            task.await
        } else {
            Ok(())
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub struct VsockServer<H> {
    handler: H,
    concurrency: usize,
    span: Span,
}

impl<H> VsockServer<H> {
    pub fn create(handler: H) -> Self {
        Self {
            handler,
            concurrency: 128,
            span: Span::none(),
        }
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_tracing(mut self, span: Span) -> Self {
        self.span = span;
        self
    }
}

impl<H, F> VsockServer<H>
where
    H: Fn(VsockStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = io::Result<()>> + Send + 'static,
{
    pub fn listen(self, port: u32) -> io::Result<RunningServer> {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
            .map_err(|err| io::Error::new(err.kind(), format!("bind listener on {port}: {err}")))?;
        let handler = self.handler;
        let concurrency = self.concurrency;
        let span = self.span;
        let (shutdown, mut shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(
            async move {
                let mut incoming = listener.incoming();
                let semaphore = Arc::new(Semaphore::new(concurrency));
                let mut handlers = tokio::task::JoinSet::new();

                loop {
                    let connection = tokio::select! {
                        connection = incoming.next() => connection,
                        _ = shutdown_rx.changed() => break,
                        Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                            if let Err(error) = result {
                                tracing::warn!(%error, "vsock handler stopped");
                            }
                            continue;
                        }
                    };
                    match connection {
                        Some(Ok(stream)) if stream.peer_addr().is_ok_and(|peer| peer.cid() == VMADDR_CID_HOST) => {
                            let permit = tokio::select! {
                                permit = Arc::clone(&semaphore).acquire_owned() => match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                },
                                _ = shutdown_rx.changed() => break,
                            };

                            let handler = handler.clone();
                            handlers.spawn(async move {
                                let _permit = permit;
                                if let Err(err) = handler(stream).await {
                                    tracing::error!(error = %err, "connection handler failed");
                                }
                            });
                        }
                        Some(Ok(stream)) => {
                            tracing::warn!(peer = ?stream.peer_addr().ok(), "rejected non-host vsock peer");
                        }
                        Some(Err(err)) => {
                            tracing::warn!(error = %err, "accept failed");
                        }
                        None => break,
                    }
                }
                handlers.abort_all();
                while handlers.join_next().await.is_some() {}
            }
            .instrument(span),
        );

        Ok(RunningServer {
            task: Some(task),
            shutdown,
        })
    }
}

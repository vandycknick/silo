use std::future::Future;
use std::io;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tracing::{Instrument, Span};

pub struct RunningServer {
    task: Option<JoinHandle<()>>,
}

impl RunningServer {
    pub async fn wait(mut self) -> Result<(), tokio::task::JoinError> {
        if let Some(task) = self.task.take() {
            task.await
        } else {
            Ok(())
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

        let task = tokio::spawn(
            async move {
                let mut incoming = listener.incoming();
                let semaphore = Arc::new(Semaphore::new(concurrency));

                loop {
                    match incoming.next().await {
                        Some(Ok(stream)) => {
                            let permit = match Arc::clone(&semaphore).acquire_owned().await {
                                Ok(permit) => permit,
                                Err(err) => {
                                    tracing::warn!(error = %err, "semaphore closed while accepting connection");
                                    break;
                                }
                            };

                            let handler = handler.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(err) = handler(stream).await {
                                    tracing::error!(error = %err, "connection handler failed");
                                }
                            });
                        }
                        Some(Err(err)) => {
                            tracing::warn!(error = %err, "accept failed");
                        }
                        None => break,
                    }
                }
            }
            .instrument(span),
        );

        Ok(RunningServer { task: Some(task) })
    }
}

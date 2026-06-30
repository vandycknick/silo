use std::pin::Pin;
use std::sync::Arc;

use agent_spec::SSH_VSOCK_PORT;
use eyre::Context;
use futures::stream::{self, Stream, StreamExt};
use protocol::negotiate::{RejectCode, Upgrade};
use protocol::v1::vm_monitor_service_server::{VmMonitorService, VmMonitorServiceServer};
use protocol::v1::{
    InspectRequest, InspectResponse, PingRequest, PingResponse, StatusUpdate, WatchStatusRequest,
};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use virt::{spawn_serial_tunnel, SerialAccess};

use crate::context::{DaemonContext, RuntimeContext};
use crate::endpoints::start_endpoint_supervisor;
use crate::ext::VmSpecExt;
use crate::guest::spawn_guest_services;
use crate::net::server::{NegotiateServer, NegotiationRejection};
use crate::net::tunnel::spawn_tunnel;
use crate::startup::SyncReporter;
use crate::state::{
    guest_shell_ready as state_guest_shell_ready, select_current_events, select_current_inspect,
    select_current_ping, Action, InstanceStore, StoreError,
};

type WatchStatusStream = Pin<Box<dyn Stream<Item = Result<StatusUpdate, Status>> + Send>>;
const SHELL_RETRY_AFTER_MS: u32 = 1_000;

pub struct ServiceHandles {
    pub(crate) control_socket: JoinHandle<eyre::Result<()>>,
    pub(crate) guest_monitor: Option<JoinHandle<()>>,
    pub(crate) endpoint_supervisor: Option<JoinHandle<()>>,
    pub(crate) serial_log: JoinHandle<()>,
}

#[derive(Clone)]
struct VmMonitorSvc {
    store: Arc<InstanceStore>,
}

#[tonic::async_trait]
impl VmMonitorService for VmMonitorSvc {
    type WatchStatusStream = WatchStatusStream;

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let snapshot = self.store.snapshot().map_err(store_status)?;
        let response = select_current_ping(&snapshot);

        tracing::info!(
            service = "vm_monitor.ping",
            ok = response.ok,
            message = %response.message,
            "vm monitor ping request"
        );

        Ok(Response::new(response))
    }

    async fn inspect(
        &self,
        _request: Request<InspectRequest>,
    ) -> Result<Response<InspectResponse>, Status> {
        let snapshot = self.store.snapshot().map_err(store_status)?;
        Ok(Response::new(select_current_inspect(&snapshot)))
    }

    async fn watch_status(
        &self,
        _request: Request<WatchStatusRequest>,
    ) -> Result<Response<Self::WatchStatusStream>, Status> {
        let snapshot = self.store.snapshot().map_err(store_status)?;
        let snapshots = select_current_events(&snapshot);
        let rx = self.store.subscribe();

        let snapshot_stream = stream::iter(snapshots.into_iter().map(Ok));
        let update_stream = stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(update) => Some((Ok(update), rx)),
                Err(broadcast::error::RecvError::Lagged(skipped)) => Some((
                    Err(Status::resource_exhausted(format!(
                        "status stream lagged, skipped {skipped} updates"
                    ))),
                    rx,
                )),
                Err(broadcast::error::RecvError::Closed) => None,
            }
        });

        Ok(Response::new(Box::pin(
            snapshot_stream.chain(update_stream),
        )))
    }
}

pub async fn start_services(
    runtime: &RuntimeContext,
    ctx: &DaemonContext,
    sync_reporter: &mut SyncReporter,
) -> eyre::Result<ServiceHandles> {
    let path = runtime.socket().to_path_buf();
    let listener = UnixListener::bind(&path).context(format!("bind socket {}", path.display()))?;
    let server = NegotiateServer::new(listener, ctx.shutdown.clone());
    let policy_store = ctx.store.clone();
    let handler_ctx = ctx.clone();
    let control_socket = server.listen(
        move |upgrade| upgrade_rejection(upgrade, &policy_store),
        move |stream, upgrade| {
            let ctx = handler_ctx.clone();
            async move { handle_connection(stream, upgrade, ctx).await }
        },
    );

    let serial_log_path = runtime.serial_log().to_path_buf();
    let serial_console_for_log = ctx.serial_console.clone();
    let serial_log = tokio::spawn(async move {
        if let Err(err) = serial_console_for_log
            .stream_to_file(&serial_log_path)
            .await
        {
            tracing::warn!(error = %err, path = %serial_log_path.display(), "serial log attachment failed");
        }
    });

    let guest_monitor = if ctx.guest_services_enabled {
        if ctx.wait_for_registration.is_zero() {
            ctx.store.dispatch(Action::guest_running())?;
        } else {
            ctx.store.dispatch(Action::guest_starting())?;
        }

        Some(
            spawn_guest_services(
                &ctx.machine,
                ctx.store.clone(),
                ctx.metadata_config.clone().unwrap_or_default(),
                ctx.spec.rosetta_or_default(),
                ctx.wait_for_registration,
                ctx.shutdown.clone(),
            )
            .await?,
        )
    } else {
        ctx.store.dispatch(Action::guest_running())?;
        None
    };

    let endpoint_supervisor = start_endpoint_supervisor(ctx.clone(), runtime.dir().to_path_buf());

    sync_reporter.report_started()?;
    tracing::info!(instance = %ctx.machine.name(), "vmmon running");

    Ok(ServiceHandles {
        control_socket,
        guest_monitor,
        endpoint_supervisor,
        serial_log,
    })
}

pub(crate) async fn serve(stream: UnixStream, store: Arc<InstanceStore>) -> eyre::Result<()> {
    let incoming = stream::once(async move { Ok::<_, std::io::Error>(stream) });
    tonic::transport::Server::builder()
        .add_service(VmMonitorServiceServer::new(VmMonitorSvc { store }))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    upgrade: Upgrade,
    ctx: DaemonContext,
) -> eyre::Result<()> {
    match upgrade {
        Upgrade::Serial => {
            let serial_stream = ctx
                .serial_console
                .open_stream(SerialAccess::Interactive)
                .await?;
            spawn_serial_tunnel(stream, serial_stream);
            Ok(())
        }
        Upgrade::Shell => {
            if !guest_shell_ready(&ctx.store)? {
                tracing::warn!("shell requested before guest shell was ready, closing connection");
                return Ok(());
            }

            match ctx.machine.connect_vsock(SSH_VSOCK_PORT).await {
                Ok(vsock_stream) => {
                    spawn_tunnel(stream, vsock_stream);
                    Ok(())
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to connect shell backend, closing connection");
                    Ok(())
                }
            }
        }
        Upgrade::Api { .. } => serve(stream, ctx.store).await,
    }
}

fn upgrade_rejection(upgrade: &Upgrade, store: &InstanceStore) -> Option<NegotiationRejection> {
    match upgrade {
        Upgrade::Shell => match guest_shell_ready(store) {
            Ok(true) => None,
            Ok(false) => Some(NegotiationRejection {
                code: RejectCode::ServiceStarting,
                message: String::from("guest shell is not ready"),
                retry_after_ms: Some(SHELL_RETRY_AFTER_MS),
            }),
            Err(err) => Some(NegotiationRejection {
                code: RejectCode::Internal,
                message: format!("vmmon state unavailable: {err}"),
                retry_after_ms: None,
            }),
        },
        Upgrade::Serial | Upgrade::Api { .. } => None,
    }
}

fn guest_shell_ready(store: &InstanceStore) -> Result<bool, StoreError> {
    let snapshot = store.snapshot()?;
    Ok(state_guest_shell_ready(&snapshot))
}

fn store_status(err: StoreError) -> Status {
    Status::internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use protocol::negotiate::{RejectCode, Upgrade};

    use crate::state::{new_instance_store, Action};

    use super::upgrade_rejection;

    #[test]
    fn shell_upgrade_is_rejected_until_guest_is_ready() {
        let store = new_instance_store();

        let rejection = upgrade_rejection(&Upgrade::Shell, &store).expect("shell rejection");

        assert_eq!(rejection.code, RejectCode::ServiceStarting);
        assert_eq!(rejection.retry_after_ms, Some(super::SHELL_RETRY_AFTER_MS));
    }

    #[test]
    fn shell_upgrade_is_allowed_after_guest_is_ready() {
        let store = new_instance_store();
        store.dispatch(Action::guest_running()).unwrap();

        assert!(upgrade_rejection(&Upgrade::Shell, &store).is_none());
    }
}

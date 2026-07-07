use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::Context as EyreContext;
use futures::stream::{self, Stream};
use protocol::prost_types::Struct;
use protocol::v1::guest_control_service_server::{GuestControlService, GuestControlServiceServer};
use protocol::v1::metadata_service_server::{MetadataService, MetadataServiceServer};
use protocol::v1::{
    GetMetadataRequest, GetMetadataResponse, ProvisionOverallStatus, RegisterGuestRequest,
    RegisterGuestResponse,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};
use virt::{VirtualMachine, VsockListener, VsockStream};

use crate::state::{Action, InstanceStore};

pub(crate) const GUEST_CONTROL_PORT: u32 = 1027;

#[derive(Clone)]
struct GuestControlSvc {
    store: Arc<InstanceStore>,
    ready: Arc<AtomicBool>,
}

impl GuestControlSvc {
    fn new(store: Arc<InstanceStore>, ready: Arc<AtomicBool>) -> Self {
        Self { store, ready }
    }
}

#[tonic::async_trait]
impl GuestControlService for GuestControlSvc {
    async fn register(
        &self,
        request: Request<RegisterGuestRequest>,
    ) -> Result<Response<RegisterGuestResponse>, Status> {
        let request = request.into_inner();
        let hostname = request
            .system_info
            .as_ref()
            .map(|system| system.hostname.as_str())
            .unwrap_or("");
        let arch = request
            .system_info
            .as_ref()
            .map(|system| system.arch.as_str())
            .unwrap_or("");

        tracing::info!(
            guest_service_version = %request.guest_service_version,
            hostname,
            arch,
            "guest service registered"
        );
        let provision_failed_boot = request
            .provision_report
            .as_ref()
            .is_some_and(|report| report.status == ProvisionOverallStatus::FailedBoot as i32);
        let provision_message = request
            .provision_report
            .as_ref()
            .map(|report| report.message.clone())
            .unwrap_or_default();

        let action = match (
            provision_failed_boot,
            request.boot_report,
            request.provision_report,
        ) {
            (true, Some(boot_report), Some(provision_report)) => Action::guest_error_with_reports(
                provision_message.clone(),
                boot_report,
                provision_report,
            ),
            (false, Some(boot_report), Some(provision_report)) => {
                Action::guest_running_with_reports(boot_report, provision_report)
            }
            (true, _, _) => Action::guest_error(provision_message.clone()),
            (false, _, _) => Action::guest_running(),
        };

        self.store
            .dispatch(action)
            .map_err(|err| Status::internal(err.to_string()))?;
        self.ready.store(true, Ordering::Release);

        Ok(Response::new(RegisterGuestResponse {
            accepted: true,
            message: if provision_failed_boot {
                String::from("registered fatal provisioning report")
            } else {
                String::from("registered")
            },
        }))
    }
}

#[derive(Clone)]
struct MetadataSvc {
    config: Arc<Struct>,
    rosetta_enabled: bool,
}

impl MetadataSvc {
    fn new(config: Struct, rosetta_enabled: bool) -> Self {
        Self {
            config: Arc::new(config),
            rosetta_enabled,
        }
    }
}

#[tonic::async_trait]
impl MetadataService for MetadataSvc {
    async fn get_metadata(
        &self,
        _request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        tracing::info!(
            config_fields = self.config.fields.len(),
            rosetta_enabled = self.rosetta_enabled,
            "guest metadata requested"
        );
        Ok(Response::new(GetMetadataResponse {
            timestamp_unix: current_unix_timestamp(),
            rosetta_enabled: self.rosetta_enabled,
            config: Some(self.config.as_ref().clone()),
        }))
    }
}

#[derive(Debug)]
struct ConnectedVsock(VsockStream);

impl Connected for ConnectedVsock {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for ConnectedVsock {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnectedVsock {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub(crate) async fn spawn_guest_services(
    machine: &VirtualMachine,
    store: Arc<InstanceStore>,
    metadata_config: Struct,
    rosetta_enabled: bool,
    wait_for_registration: Duration,
    shutdown: CancellationToken,
) -> eyre::Result<JoinHandle<()>> {
    let listener = machine
        .listen_vsock(GUEST_CONTROL_PORT)
        .await
        .context("listen for guest control connections")?;
    let ready = Arc::new(AtomicBool::new(false));
    let control = GuestControlSvc::new(store.clone(), ready.clone());
    let metadata = MetadataSvc::new(metadata_config, rosetta_enabled);
    let timeout_task = spawn_readiness_timeout(
        store.clone(),
        ready,
        wait_for_registration,
        shutdown.clone(),
    );

    Ok(tokio::spawn(async move {
        let result = serve_guest_services(listener, control, metadata, shutdown).await;
        if let Some(timeout_task) = timeout_task {
            timeout_task.abort();
        }

        if let Err(err) = result {
            tracing::warn!(error = %err, "guest service RPC server failed");
            if let Err(store_err) = store.dispatch(Action::guest_error(format!(
                "guest service RPC server failed: {err}"
            ))) {
                tracing::error!(error = %store_err, "failed to publish guest service error");
            }
        }
    }))
}

async fn serve_guest_services(
    listener: VsockListener,
    control: GuestControlSvc,
    metadata: MetadataSvc,
    shutdown: CancellationToken,
) -> eyre::Result<()> {
    tonic::transport::Server::builder()
        .add_service(GuestControlServiceServer::new(control))
        .add_service(MetadataServiceServer::new(metadata))
        .serve_with_incoming_shutdown(incoming_vsock_connections(listener), shutdown.cancelled())
        .await?;
    Ok(())
}

fn incoming_vsock_connections(
    listener: VsockListener,
) -> impl Stream<Item = io::Result<ConnectedVsock>> {
    stream::unfold(listener, |mut listener| async move {
        let accepted = listener.accept().await.map(ConnectedVsock);
        Some((accepted, listener))
    })
}

fn spawn_readiness_timeout(
    store: Arc<InstanceStore>,
    ready: Arc<AtomicBool>,
    timeout: Duration,
    shutdown: CancellationToken,
) -> Option<JoinHandle<()>> {
    if timeout.is_zero() {
        return None;
    }

    Some(tokio::spawn(async move {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = tokio::time::sleep(timeout) => {
                if !ready.load(Ordering::Acquire) {
                    tracing::warn!(timeout = ?timeout, "guest service did not register before timeout");
                    if let Err(err) = store.dispatch(Action::guest_error(format!(
                        "guest service did not register within {} seconds",
                        timeout.as_secs()
                    ))) {
                        tracing::error!(error = %err, "failed to publish guest readiness timeout");
                    }
                }
            }
        }
    }))
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{spawn_readiness_timeout, GUEST_CONTROL_PORT};
    use crate::state::new_instance_store;

    #[test]
    fn guest_control_port_is_fixed() {
        assert_eq!(GUEST_CONTROL_PORT, 1027);
    }

    #[test]
    fn zero_registration_wait_disables_timeout_task() {
        let task = spawn_readiness_timeout(
            std::sync::Arc::new(new_instance_store()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Duration::ZERO,
            tokio_util::sync::CancellationToken::new(),
        );

        assert!(task.is_none());
    }
}

use std::io;
use std::sync::Arc;

use eyre::Context;
use hyper_util::rt::TokioIo;
use protocol::v1::guest_control_service_client::GuestControlServiceClient;
use protocol::v1::{GuestBootReport, ProvisionReport, RegisterGuestRequest};
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockStream, VMADDR_CID_HOST};
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

use crate::host::info::get_system_info;

pub(crate) struct GuestControlClient {
    control: GuestControlServiceClient<Channel>,
}

impl GuestControlClient {
    pub(crate) async fn connect(port: u32) -> eyre::Result<Self> {
        let channel = connect_guest_services_channel(port).await?;
        Ok(Self {
            control: GuestControlServiceClient::new(channel),
        })
    }

    pub(crate) async fn register(
        &mut self,
        boot_report: GuestBootReport,
        provision_report: ProvisionReport,
    ) -> eyre::Result<()> {
        let system_info = get_system_info().context("collect system info for guest register")?;
        let response = self
            .control
            .register(RegisterGuestRequest {
                guest_service_version: env!("CARGO_PKG_VERSION").to_string(),
                system_info: Some(system_info),
                boot_report: Some(boot_report),
                provision_report: Some(provision_report),
            })
            .await
            .context("register guest service")?
            .into_inner();

        if !response.accepted {
            eyre::bail!("guest service registration rejected: {}", response.message);
        }

        Ok(())
    }
}

async fn connect_guest_services_channel(port: u32) -> eyre::Result<Channel> {
    let stream = VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, port)).await?;
    let stream_slot = Arc::new(Mutex::new(Some(stream)));
    let connector = service_fn(move |_| {
        let stream_slot = Arc::clone(&stream_slot);
        async move {
            let mut guard = stream_slot.lock().await;
            guard
                .take()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "guest services connector stream already consumed",
                    )
                })
                .map(TokioIo::new)
        }
    });

    Endpoint::from_static("http://guest-services.local")
        .connect_with_connector(connector)
        .await
        .context("connect guest services rpc client")
}

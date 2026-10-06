//! Local daemon management transport. Session methods never use this channel.
use std::path::Path;
use std::time::Duration;

use eyre::Context as _;
use hyper_util::rt::TokioIo;
use silod_spec::daemon::v1::{
    daemon_service_client::DaemonServiceClient, machine_service_client::MachineServiceClient,
    network_service_client::NetworkServiceClient, runtime_service_client::RuntimeServiceClient,
};
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct DaemonVmService {
    pub(crate) daemon: DaemonServiceClient<Channel>,
    pub(crate) machines: MachineServiceClient<Channel>,
    pub(crate) networks: NetworkServiceClient<Channel>,
    pub(crate) runtime: RuntimeServiceClient<Channel>,
}

impl DaemonVmService {
    /// Establish a channel only to a verified same-user private Unix socket.
    /// Backend selection performs status/product/Home admission before use.
    pub(crate) async fn connect(socket: &Path) -> eyre::Result<Self> {
        validate_endpoint(socket)?;
        let path = socket.to_path_buf();
        let connector = service_fn(move |_| {
            let path = path.clone();
            async move {
                validate_endpoint(&path)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(TokioIo::new)
            }
        });
        let channel = Endpoint::from_static("http://silod.local")
            .connect_timeout(Duration::from_secs(2))
            .connect_with_connector(connector)
            .await
            .context("connect to silod management socket")?;
        Ok(Self {
            daemon: DaemonServiceClient::new(channel.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
            machines: MachineServiceClient::new(channel.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
            networks: NetworkServiceClient::new(channel.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
            runtime: RuntimeServiceClient::new(channel)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        })
    }
}

fn validate_endpoint(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if !path.is_absolute() {
        eyre::bail!("silod control endpoint must be absolute");
    }
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("control endpoint has no parent"))?;
    for (selected, socket) in [(parent, false), (path, true)] {
        let metadata = std::fs::symlink_metadata(selected)?;
        let valid_kind = if socket {
            metadata.file_type().is_socket()
        } else {
            metadata.is_dir()
        };
        let mode = if socket { 0o600 } else { 0o700 };
        if !valid_kind
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7777 != mode
        {
            eyre::bail!("unsafe silod control endpoint {}", selected.display());
        }
    }
    Ok(())
}

//! Same-user daemon management. Native sessions share a lazy exact-component runtime.
mod management;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eyre::Context as _;
use libvm::{HostPaths, Runtime, RuntimeConfig};
use silod_spec::daemon::v1::{
    daemon_service_client::DaemonServiceClient, machine_service_client::MachineServiceClient,
    network_service_client::NetworkServiceClient, runtime_service_client::RuntimeServiceClient,
};
use tokio::sync::OnceCell;
use tonic::transport::Channel;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct SessionState {
    config: RuntimeConfig,
    home: PathBuf,
    generation: String,
    runtime: OnceCell<Runtime>,
}

#[derive(Debug, Clone)]
pub(crate) struct DaemonVmService {
    daemon: DaemonServiceClient<Channel>,
    machines: MachineServiceClient<Channel>,
    networks: NetworkServiceClient<Channel>,
    runtime: RuntimeServiceClient<Channel>,
    session: Arc<SessionState>,
}

impl DaemonVmService {
    /// Probe without creating directories or state. Only proven absence allows local management.
    pub(crate) async fn probe(
        config: &RuntimeConfig,
        host: &HostPaths,
    ) -> eyre::Result<Option<Self>> {
        let Some(selected) =
            silo_vm_control::transport::probe(host, silo_vm_control::transport::Admission::Ready)
                .await?
        else {
            return Ok(None);
        };
        let channel = selected.channel;
        let status = selected.status;
        let home = silo_vm_control::path_from_wire(status.home)?;
        Ok(Some(Self {
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
            session: Arc::new(SessionState {
                config: config.clone(),
                home,
                generation: status.generation,
                runtime: OnceCell::new(),
            }),
        }))
    }

    pub(crate) fn home(&self) -> &Path {
        &self.session.home
    }

    pub(crate) async fn session_runtime(&self) -> eyre::Result<&Runtime> {
        self.session.runtime.get_or_try_init(|| async {
            let info = self.daemon.clone().get_runtime_info(()).await.map_err(native_status)?.into_inner();
            eyre::ensure!(info.generation == self.session.generation, "silod generation changed before native session initialization; retry the command");
            eyre::ensure!(silo_vm_control::path_from_wire(info.home)? == self.session.home, "silod runtime Home changed");
            let c = info.components.ok_or_else(|| eyre::eyre!("silod omitted runtime components"))?;
            let components = libvm::ResolvedRuntimeComponents::from_paths(
                silo_vm_control::path_from_wire(c.supervisor_path)?, silo_vm_control::path_from_wire(c.netd_path)?,
                silo_vm_control::path_from_wire(c.kernel_path)?, silo_vm_control::path_from_wire(c.initramfs_path)?,
                silo_vm_control::path_from_wire(c.agent_path)?, silo_vm_control::path_from_wire(c.asset_dir)?,
            )?;
            let mut config = self.session.config.clone().with_runtime_components(components);
            config.home = Some(self.session.home.clone());
            let runtime = Runtime::new(config).await.context("initialize native daemon-mode session runtime")?;
            let provider = libvm::HostCommand::new(std::env::current_exe()?).arg("secret").arg("provide").arg("--store-file").arg(runtime.local_home().join("secrets.json"));
            Ok::<_, eyre::Report>(runtime.with_secret_provider(provider))
        }).await
    }
}

fn native_status(status: tonic::Status) -> libvm::LibVmError {
    silo_vm_control::errors::status_to_native_error(&status).unwrap_or_else(|_| {
        std::io::Error::other(format!(
            "silod management {}: {}",
            status.code(),
            status.message()
        ))
        .into()
    })
}
fn invalid_response(error: impl std::fmt::Display) -> libvm::LibVmError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid silod response: {error}"),
    )
    .into()
}

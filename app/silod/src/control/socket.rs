use crate::control::{ControlState, Service};
use futures::StreamExt;
use libvm::HostPaths;
use silod_spec::daemon::v1 as w;
use std::sync::Arc;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
pub(crate) struct BoundServer {
    state: Arc<ControlState>,
    listener: Option<UnixListener>,
    path: PathBuf,
    identity: (u64, u64),
    _lock: nix::fcntl::Flock<File>,
}
impl BoundServer {
    pub(crate) fn bind(state: Arc<ControlState>) -> eyre::Result<Self> {
        let root = HostPaths::run_root();
        private_directory(&root)?;
        Self::bind_at(state, root.join("silod"))
    }
    pub(super) fn bind_at(state: Arc<ControlState>, dir: PathBuf) -> eyre::Result<Self> {
        private_directory(&dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                (nix::fcntl::OFlag::O_NOFOLLOW
                    | nix::fcntl::OFlag::O_CLOEXEC
                    | nix::fcntl::OFlag::O_NONBLOCK)
                    .bits(),
            )
            .open(dir.join("owner.lock"))?;
        let m = lock.metadata()?;
        eyre::ensure!(
            m.is_file()
                && m.uid() == nix::unistd::geteuid().as_raw()
                && m.mode() & 0o777 == 0o600
                && m.nlink() == 1,
            "unsafe owner lock"
        );
        let lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| {
                eyre::eyre!("another silod owns this UID; down and reconfigure its Home: {error}")
            })?;
        let path = dir.join("control.sock");
        match std::fs::symlink_metadata(&path) {
            Ok(m) => {
                eyre::ensure!(
                    m.file_type().is_socket()
                        && m.uid() == nix::unistd::geteuid().as_raw()
                        && m.nlink() == 1,
                    "unsafe existing control endpoint"
                );
                std::fs::remove_file(&path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&path)?;
        let m = std::fs::symlink_metadata(&path)?;
        let bound = Self {
            state,
            listener: Some(listener),
            path,
            identity: (m.dev(), m.ino()),
            _lock: lock,
        };
        std::fs::set_permissions(&bound.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(bound)
    }
    pub(crate) async fn serve(mut self, shutdown: CancellationToken) -> eyre::Result<()> {
        let incoming = UnixListenerStream::new(self.listener.take().expect("bound listener"))
            .filter_map(|connection| async move {
                match connection {
                    Ok(stream) => match stream.peer_cred() {
                        Ok(cred) if cred.uid() == nix::unistd::geteuid().as_raw() => {
                            Some(Ok(stream))
                        }
                        _ => None,
                    },
                    Err(e) => Some(Err(e)),
                }
            });
        let limit = 16 * 1024 * 1024;
        tonic::transport::Server::builder()
            .add_service(
                w::daemon_service_server::DaemonServiceServer::new(Service(self.state.clone()))
                    .max_decoding_message_size(limit)
                    .max_encoding_message_size(limit),
            )
            .add_service(
                w::machine_service_server::MachineServiceServer::new(Service(self.state.clone()))
                    .max_decoding_message_size(limit)
                    .max_encoding_message_size(limit),
            )
            .add_service(
                w::network_service_server::NetworkServiceServer::new(Service(self.state.clone()))
                    .max_decoding_message_size(limit)
                    .max_encoding_message_size(limit),
            )
            .add_service(
                w::runtime_service_server::RuntimeServiceServer::new(Service(self.state.clone()))
                    .max_decoding_message_size(limit)
                    .max_encoding_message_size(limit),
            )
            .serve_with_incoming_shutdown(incoming, async {
                shutdown.cancelled().await;
                self.state.stream_shutdown.cancel();
            })
            .await?;
        Ok(())
    }
}
impl Drop for BoundServer {
    fn drop(&mut self) {
        if let Ok(m) = std::fs::symlink_metadata(&self.path) {
            if m.file_type().is_socket() && (m.dev(), m.ino()) == self.identity {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}
fn private_directory(path: &std::path::Path) -> eyre::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = std::fs::symlink_metadata(path)?;
    eyre::ensure!(
        m.is_dir()
            && !m.file_type().is_symlink()
            && m.uid() == nix::unistd::geteuid().as_raw()
            && m.mode() & 0o777 == 0o700,
        "unsafe control directory"
    );
    Ok(())
}

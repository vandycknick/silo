//! Same-user daemon management. Native sessions share a lazy exact-component runtime.
mod management;

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eyre::Context as _;
use hyper_util::rt::TokioIo;
use libvm::{HostPaths, Runtime, RuntimeConfig};
use silod_spec::daemon::v1::{
    self as w, daemon_service_client::DaemonServiceClient,
    machine_service_client::MachineServiceClient, network_service_client::NetworkServiceClient,
    runtime_service_client::RuntimeServiceClient,
};
use tokio::sync::OnceCell;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

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
        Self::probe_at(
            config,
            host,
            HostPaths::run_root().join("silod/control.sock"),
        )
        .await
    }

    async fn probe_at(
        config: &RuntimeConfig,
        host: &HostPaths,
        socket: PathBuf,
    ) -> eyre::Result<Option<Self>> {
        validate_existing_parents(&socket)?;
        match validate_endpoint(&socket) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(is_absence) =>
            {
                ensure_unowned(&socket)?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        let selected = tokio::time::timeout(Duration::from_secs(2), async {
            let stream = match tokio::net::UnixStream::connect(&socket).await {
                Ok(stream) => stream,
                Err(error) if is_absence(&error) => {
                    ensure_unowned(&socket)?;
                    return Ok(None);
                }
                Err(error) => return Err(error.into()),
            };
            eyre::ensure!(
                stream.peer_cred()?.uid() == nix::unistd::geteuid().as_raw(),
                "silod peer UID mismatch"
            );
            let first = Arc::new(std::sync::Mutex::new(Some(stream)));
            let path = socket.clone();
            let connector = service_fn(move |_| {
                let path = path.clone();
                let first = first.clone();
                async move {
                    validate_endpoint(&path)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let initial = first
                        .lock()
                        .map_err(|_| std::io::Error::other("silod connector lock poisoned"))?
                        .take();
                    let stream =
                        match initial {
                            Some(stream) => stream,
                            None => return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "selected silod connection was lost; refusing daemon replacement",
                            )),
                        };
                    if stream.peer_cred()?.uid() != nix::unistd::geteuid().as_raw() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "silod peer UID mismatch",
                        ));
                    }
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            });
            let channel = Endpoint::from_static("http://silod.local")
                .connect_with_connector(connector)
                .await
                .context("connect to silod management socket")?;
            let mut daemon = DaemonServiceClient::new(channel.clone())
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES);
            let status = daemon
                .get_status(())
                .await
                .map_err(native_status)?
                .into_inner();
            let home = admit_status(&status, host)?;
            Ok(Some(Self {
                daemon,
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
        })
        .await
        .context(
            "silod is unavailable: connect/status exceeded two seconds; no local fallback",
        )??;
        Ok(selected)
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
fn is_absence(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == nix::libc::ENOENT || code == nix::libc::ECONNREFUSED)
}
fn validate_existing_parents(socket: &Path) -> eyre::Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| eyre::eyre!("missing endpoint parent"))?;
    let root = parent
        .parent()
        .ok_or_else(|| eyre::eyre!("missing run root"))?;
    for path in [root, parent] {
        match std::fs::symlink_metadata(path) {
            Ok(m) => eyre::ensure!(
                m.is_dir()
                    && m.uid() == nix::unistd::geteuid().as_raw()
                    && m.mode() & 0o7777 == 0o700,
                "unsafe silod control directory {}",
                path.display()
            ),
            Err(error) if error.raw_os_error() == Some(nix::libc::ENOENT) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn validate_endpoint(path: &Path) -> eyre::Result<()> {
    validate_existing_parents(path)?;
    let m = std::fs::symlink_metadata(path)?;
    eyre::ensure!(
        m.file_type().is_socket()
            && m.uid() == nix::unistd::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1,
        "unsafe silod control endpoint {}",
        path.display()
    );
    Ok(())
}
fn ensure_unowned(socket: &Path) -> eyre::Result<()> {
    let path = socket.with_file_name("owner.lock");
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(
            (nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NONBLOCK)
                .bits(),
        )
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(nix::libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let m = file.metadata()?;
    eyre::ensure!(
        m.is_file()
            && m.uid() == nix::unistd::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1,
        "unsafe silod owner lock"
    );
    let _guard: nix::fcntl::Flock<File> = nix::fcntl::Flock::lock(
        file,
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| {
        eyre::eyre!("silod owns this UID but its API is unavailable; no local fallback: {error}")
    })?;
    Ok(())
}
fn admit_status(status: &w::DaemonStatus, host: &HostPaths) -> eyre::Result<PathBuf> {
    eyre::ensure!(
        status.product_version == env!("CARGO_PKG_VERSION") && status.protocol_major == 1,
        "silod product/protocol mismatch; restart with the matching silo installation"
    );
    silo_vm_control::validate_uuid(&status.generation, "daemon.generation")?;
    let home = silo_vm_control::path_from_wire(status.home.clone())?;
    let config = silo_vm_control::path_from_wire(status.config_dir.clone())?;
    eyre::ensure!(
        home.is_absolute()
            && config.is_absolute()
            && std::fs::canonicalize(&home)? == home
            && std::fs::canonicalize(&config)? == config,
        "silod returned noncanonical roots"
    );
    eyre::ensure!(
        canonical_selected(host.home())? == home
            && canonical_selected(host.config_dir())? == config,
        "silod is bound to another Home/config root; run silo daemon down and reconfigure it"
    );
    eyre::ensure!(
        status.core == w::CorePhase::Ready as i32,
        "silod core is unavailable (starting, stopping or failed); no local fallback"
    );
    Ok(home)
}
fn canonical_selected(path: &Path) -> eyre::Result<PathBuf> {
    // Resolve existing ancestors without creating missing CLI roots.
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.raw_os_error() == Some(nix::libc::ENOENT) => {
            let parent = path
                .parent()
                .ok_or_else(|| eyre::eyre!("cannot canonicalize selected root"))?;
            let name = path
                .file_name()
                .ok_or_else(|| eyre::eyre!("invalid selected root"))?;
            Ok(canonical_selected(parent)?.join(name))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::api::daemon::{admit_status, DaemonVmService};
    use libvm::{HostPaths, RuntimeConfig};
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, HostPaths, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("silod/control.sock");
        let host = HostPaths::new(root.path().join("home"), root.path().join("config"));
        (root, host, socket)
    }

    #[tokio::test]
    async fn absent_daemon_creates_no_state() {
        let (root, host, socket) = fixture();
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn held_owner_without_socket_never_falls_back() {
        let (_root, host, socket) = fixture();
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(socket.with_file_name("owner.lock"))
            .unwrap();
        let _owner: nix::fcntl::Flock<File> =
            nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock).unwrap();
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn refused_owned_stale_socket_allows_local_without_deletion() {
        let (_root, host, socket) = fixture();
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert!(socket.exists());
    }

    #[tokio::test]
    async fn unsafe_endpoints_and_owner_locks_never_fall_back() {
        let (root, host, socket) = fixture();
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::os::unix::fs::symlink(root.path().join("missing"), &socket).unwrap();
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket.clone())
                .await
                .is_err()
        );
        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("missing"),
            socket.with_file_name("owner.lock"),
        )
        .unwrap();
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket.clone())
                .await
                .is_err()
        );
        std::fs::remove_file(socket.with_file_name("owner.lock")).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(
            DaemonVmService::probe_at(&RuntimeConfig::default(), &host, socket)
                .await
                .is_err()
        );
    }

    #[test]
    fn status_admission_requires_identity_canonical_roots_and_ready_core() {
        let (root, _, _) = fixture();
        let home = std::fs::canonicalize(root.path()).unwrap();
        let host = HostPaths::new(&home, &home);
        let mut status = silod_spec::daemon::v1::DaemonStatus {
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol_major: 1,
            generation: "12345678-1234-4234-8234-123456789abc".into(),
            home: silo_vm_control::path_to_wire(&home),
            config_dir: silo_vm_control::path_to_wire(&home),
            core: silod_spec::daemon::v1::CorePhase::Ready as i32,
            ..Default::default()
        };
        assert_eq!(admit_status(&status, &host).unwrap(), home);
        status.protocol_major = 2;
        assert!(admit_status(&status, &host).is_err());
        status.protocol_major = 1;
        status.product_version = "incompatible".into();
        assert!(admit_status(&status, &host).is_err());
        status.product_version = env!("CARGO_PKG_VERSION").into();
        status.generation = "invalid".into();
        assert!(admit_status(&status, &host).is_err());
        status.generation = "12345678-1234-4234-8234-123456789abc".into();
        status.core = silod_spec::daemon::v1::CorePhase::Starting as i32;
        assert!(admit_status(&status, &host).is_err());
        status.core = silod_spec::daemon::v1::CorePhase::Ready as i32;
        let different = HostPaths::new(home.join("different"), &home);
        assert!(admit_status(&status, &different).is_err());
        status.home.push(0);
        assert!(admit_status(&status, &host).is_err());
    }
}

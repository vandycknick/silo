//! Proven-absence-only selection of the same-user daemon management transport.
//! Selection pins one authenticated stream and never reconnects to a replacement owner.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use eyre::Context as _;
use hyper_util::rt::TokioIo;
use libvm::HostPaths;
use silod_spec::daemon::v1::{self as w, daemon_service_client::DaemonServiceClient};
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The identity checks always apply; only ordinary management requires a ready core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Ready,
    Owned,
}

/// An authenticated daemon identity and its single admitted connection.
pub struct SelectedDaemon {
    pub channel: Channel,
    pub status: w::DaemonStatus,
}

/// Probe without creating state. Only proven absence permits another runtime owner.
pub async fn probe(host: &HostPaths, admission: Admission) -> eyre::Result<Option<SelectedDaemon>> {
    probe_at(
        host,
        admission,
        HostPaths::run_root().join("silod/control.sock"),
    )
    .await
}

// Alternate endpoints are private to transport fixtures, never an operator setting.
async fn probe_at(
    host: &HostPaths,
    admission: Admission,
    socket: PathBuf,
) -> eyre::Result<Option<SelectedDaemon>> {
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
                let stream = match initial {
                    Some(stream) => stream,
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "selected silod connection was lost; refusing daemon replacement",
                        ))
                    }
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
            .map_err(|status| {
                crate::errors::status_to_native_error(&status).unwrap_or_else(|_| {
                    std::io::Error::other(format!(
                        "silod management {}: {}",
                        status.code(),
                        status.message()
                    ))
                    .into()
                })
            })?
            .into_inner();
        admit_status(&status, host, admission)?;
        Ok(Some(SelectedDaemon { channel, status }))
    })
    .await
    .context("silod is unavailable: connect/status exceeded two seconds; no local fallback")??;
    Ok(selected)
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
fn admit_status(
    status: &w::DaemonStatus,
    host: &HostPaths,
    admission: Admission,
) -> eyre::Result<()> {
    eyre::ensure!(
        status.product_version == env!("CARGO_PKG_VERSION") && status.protocol_major == 1,
        "silod product/protocol mismatch; restart with the matching silo installation"
    );
    crate::validate_uuid(&status.generation, "daemon.generation")?;
    let home = crate::path_from_wire(status.home.clone())?;
    let config = crate::path_from_wire(status.config_dir.clone())?;
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
        admission == Admission::Owned || status.core == w::CorePhase::Ready as i32,
        "silod core is unavailable (starting, stopping or failed); no local fallback"
    );
    Ok(())
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
    use super::{admit_status, probe_at, Admission};
    use libvm::HostPaths;
    use silod_spec::daemon::v1::{
        self as w,
        daemon_service_server::{DaemonService, DaemonServiceServer},
    };
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    #[derive(Clone)]
    struct StatusService(w::DaemonStatus);

    #[tonic::async_trait]
    impl DaemonService for StatusService {
        async fn get_status(
            &self,
            _: tonic::Request<()>,
        ) -> Result<tonic::Response<w::DaemonStatus>, tonic::Status> {
            Ok(tonic::Response::new(self.0.clone()))
        }

        async fn get_runtime_info(
            &self,
            _: tonic::Request<()>,
        ) -> Result<tonic::Response<w::RuntimeInfo>, tonic::Status> {
            Err(tonic::Status::unimplemented("fixture status only"))
        }

        async fn report_tailscale_status(
            &self,
            _: tonic::Request<w::TailscaleStatusReport>,
        ) -> Result<tonic::Response<()>, tonic::Status> {
            Err(tonic::Status::unimplemented("fixture status only"))
        }

        async fn drain_mutations(
            &self,
            _: tonic::Request<w::DrainMutationsRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status> {
            Err(tonic::Status::unimplemented("fixture status only"))
        }
    }

    fn status(host: &HostPaths, core: w::CorePhase) -> w::DaemonStatus {
        std::fs::create_dir_all(host.home()).unwrap();
        std::fs::create_dir_all(host.config_dir()).unwrap();
        w::DaemonStatus {
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol_major: 1,
            generation: "12345678-1234-4234-8234-123456789abc".into(),
            home: crate::path_to_wire(&std::fs::canonicalize(host.home()).unwrap()),
            config_dir: crate::path_to_wire(&std::fs::canonicalize(host.config_dir()).unwrap()),
            core: core as i32,
            ..Default::default()
        }
    }

    fn listener(socket: &std::path::Path) -> tokio::net::UnixListener {
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }

    #[tokio::test]
    async fn live_stopping_owner_is_selected_only_for_owned_admission() {
        let (_root, host, socket) = fixture();
        let status = status(&host, w::CorePhase::Stopping);
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener(&socket));
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(DaemonServiceServer::new(StatusService(status.clone())))
                .serve_with_incoming(incoming),
        );
        let selected = probe_at(&host, Admission::Owned, socket.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.status, status);
        let mut client = w::daemon_service_client::DaemonServiceClient::new(selected.channel);
        assert_eq!(client.get_status(()).await.unwrap().into_inner(), status);
        assert!(probe_at(&host, Admission::Ready, socket.clone())
            .await
            .is_err());
        let different = HostPaths::new(host.home().join("different"), host.config_dir());
        assert!(probe_at(&different, Admission::Owned, socket)
            .await
            .is_err());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn lost_admitted_connection_never_connects_to_replacement_endpoint() {
        let (_root, host, socket) = fixture();
        let status = status(&host, w::CorePhase::Ready);
        let listener = listener(&socket);
        let (mut bridge, server_stream) = tokio::net::UnixStream::pair().unwrap();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(DaemonServiceServer::new(StatusService(status)))
                .serve_with_incoming(tokio_stream::iter([Ok::<_, std::io::Error>(server_stream)])),
        );
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::io::copy_bidirectional(&mut stream, &mut bridge).await
        });
        let selected = probe_at(&host, Admission::Ready, socket.clone())
            .await
            .unwrap()
            .unwrap();
        proxy.abort();
        let _ = proxy.await;
        std::fs::remove_file(&socket).unwrap();
        let replacement = self::listener(&socket);
        let mut client = w::daemon_service_client::DaemonServiceClient::new(selected.channel);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(2), client.get_status(()))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), replacement.accept())
                .await
                .is_err()
        );
        server.abort();
        let _ = server.await;
    }

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
        assert!(probe_at(&host, Admission::Ready, socket)
            .await
            .unwrap()
            .is_none());
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
        for admission in [Admission::Ready, Admission::Owned] {
            assert!(probe_at(&host, admission, socket.clone()).await.is_err());
        }
        // A refused socket is no more authority for takeover than a missing socket.
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
        for admission in [Admission::Ready, Admission::Owned] {
            assert!(probe_at(&host, admission, socket.clone()).await.is_err());
        }
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
        assert!(probe_at(&host, Admission::Ready, socket.clone())
            .await
            .unwrap()
            .is_none());
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
        assert!(probe_at(&host, Admission::Ready, socket.clone())
            .await
            .is_err());
        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("missing"),
            socket.with_file_name("owner.lock"),
        )
        .unwrap();
        assert!(probe_at(&host, Admission::Ready, socket.clone())
            .await
            .is_err());
        std::fs::remove_file(socket.with_file_name("owner.lock")).unwrap();
        std::fs::set_permissions(
            socket.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(probe_at(&host, Admission::Ready, socket).await.is_err());
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
            home: crate::path_to_wire(&home),
            config_dir: crate::path_to_wire(&home),
            core: silod_spec::daemon::v1::CorePhase::Ready as i32,
            ..Default::default()
        };
        admit_status(&status, &host, Admission::Ready).unwrap();
        status.protocol_major = 2;
        assert!(admit_status(&status, &host, Admission::Ready).is_err());
        assert!(admit_status(&status, &host, Admission::Owned).is_err());
        status.protocol_major = 1;
        status.product_version = "incompatible".into();
        assert!(admit_status(&status, &host, Admission::Ready).is_err());
        assert!(admit_status(&status, &host, Admission::Owned).is_err());
        status.product_version = env!("CARGO_PKG_VERSION").into();
        status.generation = "invalid".into();
        assert!(admit_status(&status, &host, Admission::Ready).is_err());
        assert!(admit_status(&status, &host, Admission::Owned).is_err());
        status.generation = "12345678-1234-4234-8234-123456789abc".into();
        for core in [
            w::CorePhase::Starting,
            w::CorePhase::Stopping,
            w::CorePhase::Stopped,
            w::CorePhase::Failed,
        ] {
            status.core = core as i32;
            assert!(admit_status(&status, &host, Admission::Ready).is_err());
            admit_status(&status, &host, Admission::Owned).unwrap();
        }
        status.core = silod_spec::daemon::v1::CorePhase::Ready as i32;
        let different = HostPaths::new(home.join("different"), &home);
        assert!(admit_status(&status, &different, Admission::Ready).is_err());
        assert!(admit_status(&status, &different, Admission::Owned).is_err());
        status.home.push(0);
        assert!(admit_status(&status, &host, Admission::Ready).is_err());
        assert!(admit_status(&status, &host, Admission::Owned).is_err());
    }
}

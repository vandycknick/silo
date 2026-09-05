use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use eyre::Context;
use forward_spec::{Address, Endpoint, UnixMode};
use nix::fcntl::AtFlags;
use nix::sys::stat::{fchmodat, fstat, fstatat, FchmodatFlags, Mode, SFlag};
use tokio::net::{TcpListener, UnixListener};

use crate::vsock::paths::{
    open_owned_dir, remove_stale_socket, unlink_if_matches, validate_socket_path,
};

pub(crate) enum OwnedHostListener {
    Unix {
        listener: UnixListener,
        owned: OwnedUnixPath,
        enforce_peer_uid: bool,
    },
    Tcp {
        listener: TcpListener,
        bound: std::net::SocketAddr,
    },
}

pub(crate) struct OwnedUnixPath {
    path: PathBuf,
    directory: OwnedFd,
    filename: OsString,
    device: libc::dev_t,
    inode: libc::ino_t,
    owner_uid: u32,
}

impl OwnedHostListener {
    pub(crate) async fn bind(
        address: &Address,
        mode: Option<UnixMode>,
        runtime_dir: &Path,
    ) -> eyre::Result<Self> {
        match address {
            Address::Tcp(address) => {
                let listener = TcpListener::bind(address)
                    .await
                    .wrap_err_with(|| format!("bind TCP forward {address}"))?;
                let bound = listener
                    .local_addr()
                    .wrap_err_with(|| format!("read bound TCP forward {address}"))?;
                Ok(Self::Tcp { listener, bound })
            }
            Address::Unix(address) => Self::bind_unix(address, mode, runtime_dir),
        }
    }

    fn bind_unix(address: &Path, mode: Option<UnixMode>, runtime_dir: &Path) -> eyre::Result<Self> {
        Self::bind_unix_after_parent_open(address, mode, runtime_dir, || Ok(()))
    }

    fn bind_unix_after_parent_open(
        address: &Path,
        mode: Option<UnixMode>,
        runtime_dir: &Path,
        after_parent_open: impl FnOnce() -> eyre::Result<()>,
    ) -> eyre::Result<Self> {
        let (path, parent, filename, restrict_parent) = if address.is_absolute() {
            let parent = address.parent().ok_or_else(|| {
                eyre::eyre!("Unix forward path has no parent: {}", address.display())
            })?;
            let filename = address.file_name().ok_or_else(|| {
                eyre::eyre!("Unix forward path has no filename: {}", address.display())
            })?;
            (
                address.to_path_buf(),
                parent.to_path_buf(),
                filename.to_os_string(),
                false,
            )
        } else {
            (
                runtime_dir.join(address),
                runtime_dir.to_path_buf(),
                address.as_os_str().to_os_string(),
                true,
            )
        };
        validate_socket_path(&path)?;
        let directory = open_owned_dir(&parent, restrict_parent)?;
        let parent_identity = directory_identity(&directory)?;
        remove_stale_socket(&directory, &filename, &path, "forward socket")?;
        after_parent_open()?;

        // POSIX has no bindat(2), and neither Linux nor macOS provides a
        // portable dirfd-relative AF_UNIX bind. Bind the pathname, then prove
        // it still names the owner-validated directory before trusting it.
        let listener = UnixListener::bind(&path)
            .wrap_err_with(|| format!("bind Unix forward {}", path.display()))?;
        let resolved_directory = open_owned_dir(&parent, false).wrap_err_with(|| {
            format!(
                "reopen Unix forward parent after binding {}",
                path.display()
            )
        })?;
        if directory_identity(&resolved_directory)? != parent_identity {
            cleanup_socket_in(&resolved_directory, &filename);
            return Err(eyre::eyre!(
                "Unix forward parent changed while binding {}",
                path.display()
            ));
        }
        let bound = fstatat(
            &directory,
            filename.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect bound Unix forward {}", path.display()))?;
        if SFlag::from_bits_truncate(bound.st_mode) != SFlag::S_IFSOCK {
            return Err(eyre::eyre!(
                "bound Unix forward was replaced by a non-socket entry: {}",
                path.display()
            ));
        }
        let socket_mode = platform_socket_mode(mode.map_or(0o600, UnixMode::get))?;
        if let Err(error) = fchmodat(
            &directory,
            filename.as_os_str(),
            Mode::from_bits_retain(socket_mode),
            FchmodatFlags::NoFollowSymlink,
        ) {
            let _ = unlink_if_matches(&directory, &filename, bound.st_dev, bound.st_ino);
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("set Unix forward mode on {}", path.display()));
        }
        let verified = fstatat(
            &directory,
            filename.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("verify bound Unix forward {}", path.display()))?;
        if SFlag::from_bits_truncate(verified.st_mode) != SFlag::S_IFSOCK
            || verified.st_dev != bound.st_dev
            || verified.st_ino != bound.st_ino
        {
            return Err(eyre::eyre!(
                "bound Unix forward was replaced during setup: {}",
                path.display()
            ));
        }
        let final_directory = open_owned_dir(&parent, false).wrap_err_with(|| {
            format!("reopen Unix forward parent after setup {}", path.display())
        })?;
        if directory_identity(&final_directory)? != parent_identity {
            let _ = unlink_if_matches(&directory, &filename, verified.st_dev, verified.st_ino);
            return Err(eyre::eyre!(
                "Unix forward parent changed during setup {}",
                path.display()
            ));
        }
        Ok(Self::Unix {
            listener,
            owned: OwnedUnixPath {
                path,
                directory,
                filename,
                device: verified.st_dev,
                inode: verified.st_ino,
                owner_uid: verified.st_uid,
            },
            enforce_peer_uid: mode.is_none(),
        })
    }

    pub(crate) fn bound_endpoint(&self) -> Endpoint {
        match self {
            Self::Unix { owned, .. } => Endpoint::Host(Address::Unix(owned.path.clone())),
            Self::Tcp { bound, .. } => Endpoint::Host(Address::Tcp(*bound)),
        }
    }

    pub(crate) async fn accept(&self) -> io::Result<HostStream> {
        match self {
            Self::Tcp { listener, .. } => listener
                .accept()
                .await
                .map(|(stream, _)| Box::new(stream) as HostStream),
            Self::Unix {
                listener,
                owned,
                enforce_peer_uid,
            } => loop {
                let (stream, _) = listener.accept().await?;
                if !enforce_peer_uid {
                    return Ok(Box::new(stream));
                }
                match stream.peer_cred() {
                    Ok(credentials)
                        if crate::vsock::peer::peer_uid_authorized(
                            owned.owner_uid,
                            credentials.uid(),
                        ) =>
                    {
                        return Ok(Box::new(stream))
                    }
                    Ok(credentials) => tracing::warn!(
                        path = %owned.path.display(),
                        uid = credentials.uid(),
                        expected_uid = owned.owner_uid,
                        "rejected forward connection from unauthorized UID"
                    ),
                    Err(error) => tracing::warn!(
                        path = %owned.path.display(),
                        %error,
                        "rejected forward connection without peer credentials"
                    ),
                }
            },
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_socket_mode(mode: u32) -> eyre::Result<u32> {
    Ok(mode)
}

#[cfg(target_os = "macos")]
fn platform_socket_mode(mode: u32) -> eyre::Result<u16> {
    mode.try_into()
        .map_err(|_| eyre::eyre!("Unix forward mode is not representable on this host: {mode:#o}"))
}

fn directory_identity(directory: &OwnedFd) -> eyre::Result<(libc::dev_t, libc::ino_t)> {
    let metadata = fstat(directory).map_err(eyre::Report::from)?;
    Ok((metadata.st_dev, metadata.st_ino))
}

fn cleanup_socket_in(directory: &OwnedFd, filename: &std::ffi::OsStr) {
    let Ok(metadata) = fstatat(directory, filename, AtFlags::AT_SYMLINK_NOFOLLOW) else {
        return;
    };
    if SFlag::from_bits_truncate(metadata.st_mode) == SFlag::S_IFSOCK {
        let _ = unlink_if_matches(directory, filename, metadata.st_dev, metadata.st_ino);
    }
}

impl Drop for OwnedUnixPath {
    fn drop(&mut self) {
        if let Err(error) =
            unlink_if_matches(&self.directory, &self.filename, self.device, self.inode)
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to clean owned forward socket");
        }
    }
}

pub(crate) trait AsyncStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}

impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

pub(crate) type HostStream = Box<dyn AsyncStream>;

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use forward_spec::{Address, Endpoint, UnixMode};

    use crate::forward::host_socket::OwnedHostListener;

    #[tokio::test]
    async fn tcp_port_zero_records_the_exact_bound_address() {
        let requested = "127.0.0.1:0".parse().expect("requested address");
        let listener = OwnedHostListener::bind(
            &Address::Tcp(requested),
            None,
            std::path::Path::new("/unused"),
        )
        .await
        .expect("bind ephemeral TCP forward");
        let Endpoint::Host(Address::Tcp(bound)) = listener.bound_endpoint() else {
            panic!("TCP listener must report a TCP host endpoint");
        };
        assert_eq!(bound.ip(), requested.ip());
        assert_ne!(bound.port(), 0);
    }

    #[tokio::test]
    async fn live_unix_listener_is_preserved_for_absolute_and_relative_paths() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory =
            std::path::Path::new("/tmp").join(format!("fl-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("service.sock");
        let original = tokio::net::UnixListener::bind(&path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        for address in [
            Address::Unix(path.clone()),
            Address::Unix("service.sock".into()),
        ] {
            let error =
                OwnedHostListener::bind(&address, Some(UnixMode::new(0o666).unwrap()), &directory)
                    .await
                    .err()
                    .expect("live listener must not be replaced");
            assert!(
                error.chain().any(|cause| cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse)),
                "{error:?}"
            );
            let preserved = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(preserved.ino(), metadata.ino());
            assert_eq!(
                preserved.permissions().mode(),
                metadata.permissions().mode()
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let client = async {
                let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
                client.write_all(b"ping").await.unwrap();
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                client.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"pong");
            };
            let server = async {
                loop {
                    let (mut client, _) = original.accept().await.unwrap();
                    let mut request = Vec::new();
                    client.read_to_end(&mut request).await.unwrap();
                    if request.is_empty() {
                        continue;
                    } // Closed liveness probes carry no data.
                    assert_eq!(request, b"ping");
                    client.write_all(b"pong").await.unwrap();
                    break;
                }
            };
            tokio::join!(client, server);
        })
        .await
        .unwrap();
        drop(original);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_full_unix_backlog_is_not_mistaken_for_a_stale_socket() {
        use nix::sys::socket::{
            connect, listen, socket, AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
        };
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let directory =
            std::path::Path::new("/tmp").join(format!("fb-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("service.sock");
        let original = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listen(&original, Backlog::new(1).unwrap()).unwrap();
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let mut queued = Vec::new();
        let mut full = false;
        for _ in 0..16 {
            let stream = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                None,
            )
            .unwrap();
            match connect(stream.as_raw_fd(), &UnixAddr::new(&path).unwrap()) {
                Ok(()) => queued.push(stream),
                Err(nix::errno::Errno::EAGAIN) => {
                    full = true;
                    break;
                }
                Err(error) => panic!("unexpected connection failure: {error}"),
            }
        }
        assert!(full, "test must fill the accept backlog");
        let started = std::time::Instant::now();
        assert!(
            OwnedHostListener::bind(&Address::Unix(path.clone()), None, &directory)
                .await
                .is_err()
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        drop(queued);
        drop(original);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn unix_listener_applies_mode_and_preserves_replacement_inode() {
        let directory = std::path::Path::new("/tmp").join(format!(
            "fh-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&directory).expect("create forward directory");
        let path = directory.join("forward.sock");
        let listener = OwnedHostListener::bind(
            &Address::Unix(path.clone()),
            Some(UnixMode::new(0o660).expect("mode")),
            &directory,
        )
        .await
        .expect("bind Unix forward");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("forward metadata")
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        std::fs::remove_file(&path).expect("unlink owned socket");
        let replacement = tokio::net::UnixListener::bind(&path).expect("bind replacement");
        drop(listener);
        assert!(path.exists());
        drop(replacement);
        std::fs::remove_dir_all(directory).expect("remove forward directory");
    }

    #[tokio::test]
    async fn unix_listener_rejects_a_symlink_parent() {
        let root = std::path::Path::new("/tmp").join(format!(
            "fs-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let real = root.join("real");
        let alias = root.join("alias");
        std::fs::create_dir_all(&real).expect("create real parent");
        symlink(&real, &alias).expect("create parent symlink");

        let error =
            match OwnedHostListener::bind(&Address::Unix(alias.join("forward.sock")), None, &root)
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("symlink parent must be rejected"),
            };
        assert!(error.to_string().contains("open machine runtime directory"));
        assert!(!real.join("forward.sock").exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn unix_listener_detects_parent_replacement_during_bind() {
        let root = std::path::Path::new("/tmp").join(format!(
            "fr-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let parent = root.join("parent");
        let original = root.join("original");
        std::fs::create_dir_all(&parent).expect("create parent");
        let path = parent.join("forward.sock");

        let error = match OwnedHostListener::bind_unix_after_parent_open(&path, None, &root, || {
            std::fs::rename(&parent, &original)?;
            std::fs::create_dir(&parent)?;
            Ok(())
        }) {
            Err(error) => error,
            Ok(_) => panic!("parent replacement must be detected"),
        };
        assert!(error.to_string().contains("parent changed while binding"));
        assert!(!parent.join("forward.sock").exists());
        assert!(!original.join("forward.sock").exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }
}

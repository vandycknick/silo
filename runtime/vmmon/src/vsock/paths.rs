use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use eyre::Context;
#[cfg(target_os = "macos")]
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::fcntl::{open, AtFlags, OFlag, AT_FDCWD};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
use nix::sys::stat::{fchmod, fchmodat, fstat, fstatat, FchmodatFlags, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use tokio::net::UnixListener;

#[derive(Debug)]
pub(crate) struct OwnedMux {
    path: PathBuf,
    device: libc::dev_t,
    inode: libc::ino_t,
    owner_uid: u32,
    directory: OwnedFd,
    filename: OsString,
    listener: Option<UnixListener>,
}

impl OwnedMux {
    pub(crate) fn bind(runtime_dir: &Path, filename: &Path) -> eyre::Result<Self> {
        let directory = open_owned_dir(runtime_dir, true)?;
        let path = runtime_dir.join(filename);
        validate_socket_path(&path)?;
        validate_socket_path(&listener_path(&path, u32::MAX))?;
        let filename = filename.as_os_str().to_os_string();
        remove_stale_socket(&directory, &filename, &path, "vsock mux")?;

        let listener = UnixListener::bind(&path)
            .wrap_err_with(|| format!("bind vsock mux {}", path.display()))?;
        let bound = fstatat(
            &directory,
            filename.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect bound vsock mux {}", path.display()))?;
        if SFlag::from_bits_truncate(bound.st_mode) != SFlag::S_IFSOCK {
            return Err(eyre::eyre!(
                "bound vsock mux was replaced by a non-socket entry: {}",
                path.display()
            ));
        }
        if let Err(error) = fchmodat(
            &directory,
            filename.as_os_str(),
            Mode::from_bits_retain(0o600),
            FchmodatFlags::NoFollowSymlink,
        ) {
            let _ = unlink_if_matches(&directory, &filename, bound.st_dev, bound.st_ino);
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("set vsock mux permissions on {}", path.display()));
        }
        let metadata = fstatat(
            &directory,
            filename.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("verify bound vsock mux {}", path.display()))?;
        if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFSOCK
            || metadata.st_dev != bound.st_dev
            || metadata.st_ino != bound.st_ino
        {
            return Err(eyre::eyre!(
                "bound vsock mux was replaced during setup: {}",
                path.display()
            ));
        }

        Ok(Self {
            path,
            device: metadata.st_dev,
            inode: metadata.st_ino,
            owner_uid: metadata.st_uid,
            directory,
            filename,
            listener: Some(listener),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub(crate) fn take_listener(&mut self) -> eyre::Result<UnixListener> {
        self.listener
            .take()
            .ok_or_else(|| eyre::eyre!("vsock mux listener was already activated"))
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.listener.take();
        unlink_if_matches(&self.directory, &self.filename, self.device, self.inode)
    }
}

impl Drop for OwnedMux {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(path = %self.path.display(), %error, "failed to clean owned vsock mux");
        }
    }
}

pub(crate) fn listener_path(mux_path: &Path, port: u32) -> PathBuf {
    let mut path = mux_path.as_os_str().to_os_string();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

pub(crate) fn open_owned_dir(path: &Path, require_0700: bool) -> eyre::Result<OwnedFd> {
    let directory = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(eyre::Report::from)
    .wrap_err_with(|| format!("open machine runtime directory {}", path.display()))?;
    let metadata = fstat(&directory)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("inspect machine runtime directory {}", path.display()))?;
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFDIR {
        return Err(eyre::eyre!(
            "machine runtime path is not a directory: {}",
            path.display()
        ));
    }
    let effective_uid = nix::unistd::geteuid().as_raw();
    if metadata.st_uid != effective_uid {
        return Err(eyre::eyre!(
            "machine runtime directory {} is owned by UID {}, expected {}",
            path.display(),
            metadata.st_uid,
            effective_uid
        ));
    }
    if require_0700 {
        fchmod(&directory, Mode::from_bits_retain(0o700))
            .map_err(eyre::Report::from)
            .wrap_err_with(|| format!("secure machine runtime directory {}", path.display()))?;
    }
    Ok(directory)
}

pub(crate) fn remove_stale_socket(
    directory: &OwnedFd,
    filename: &std::ffi::OsStr,
    path: &Path,
    kind: &str,
) -> eyre::Result<()> {
    let metadata = match fstatat(directory, filename, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(error) => {
            return Err(eyre::Report::from(error))
                .wrap_err_with(|| format!("inspect {}", path.display()))
        }
    };
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFSOCK {
        return Err(eyre::eyre!(
            "refusing to replace non-socket {kind} entry {}",
            path.display()
        ));
    }
    let occupied = || {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "{kind} {} is active or cannot be proven stale",
                path.display()
            ),
        )
    };
    let matches_path = || {
        fstatat(AT_FDCWD, path, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok_and(|current| {
            current.st_dev == metadata.st_dev && current.st_ino == metadata.st_ino
        })
    };
    if !matches_path() {
        return Err(occupied().into());
    }
    // A nonblocking probe must positively refuse the connection. Success,
    // backlog exhaustion, permissions, and all other errors preserve the path.
    #[cfg(target_os = "linux")]
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = SockFlag::empty();
    let probe = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
    #[cfg(target_os = "macos")]
    {
        // Darwin has no SOCK_NONBLOCK/CLOEXEC flags for socket creation.
        fcntl(&probe, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl(&probe, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    }
    if connect(probe.as_raw_fd(), &UnixAddr::new(path)?) != Err(nix::errno::Errno::ECONNREFUSED)
        || !matches_path()
    {
        return Err(occupied().into());
    }
    unlink_if_matches(directory, filename, metadata.st_dev, metadata.st_ino)
        .map_err(eyre::Report::from)
        .wrap_err_with(|| format!("remove stale {kind} {}", path.display()))
}

pub(crate) fn unlink_if_matches(
    directory: &OwnedFd,
    filename: &std::ffi::OsStr,
    device: libc::dev_t,
    inode: libc::ino_t,
) -> io::Result<()> {
    let metadata = match fstatat(directory, filename, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(io::Error::from(error)),
    };
    if SFlag::from_bits_truncate(metadata.st_mode) == SFlag::S_IFSOCK
        && metadata.st_dev == device
        && metadata.st_ino == inode
    {
        // Unix has no inode-conditional unlink. The owner-only runtime directory
        // is the trust boundary; this check prevents ordinary path replacement.
        unlinkat(directory, filename, UnlinkatFlags::NoRemoveDir).map_err(io::Error::from)?;
    }
    Ok(())
}

pub(crate) fn validate_socket_path(path: &Path) -> eyre::Result<()> {
    let length = path.as_os_str().as_bytes().len();
    let limit = unix_socket_path_limit();
    if length > limit {
        return Err(eyre::eyre!(
            "Unix socket path {} is {length} bytes, exceeding the platform limit of {limit}",
            path.display()
        ));
    }
    Ok(())
}

fn unix_socket_path_limit() -> usize {
    std::mem::size_of::<libc::sockaddr_un>() - std::mem::offset_of!(libc::sockaddr_un, sun_path) - 1
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use tokio::net::UnixListener;

    use crate::vsock::paths::{listener_path, unix_socket_path_limit, OwnedMux};

    fn temp_dir(_label: &str) -> std::path::PathBuf {
        let path = std::path::Path::new("/tmp").join(format!(
            "vp-{:x}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&path).expect("create temp directory");
        path
    }

    #[test]
    fn listener_suffix_is_appended_to_the_complete_mux_path() {
        assert_eq!(
            listener_path(std::path::Path::new("/tmp/run/vsock.sock"), 5000),
            std::path::PathBuf::from("/tmp/run/vsock.sock_5000")
        );
    }

    #[tokio::test]
    async fn bind_replaces_only_stale_sockets_and_cleans_its_own_inode() {
        let dir = temp_dir("stale");
        let path = dir.join("mux");
        let stale = UnixListener::bind(&path).expect("bind stale socket");
        drop(stale);

        let mut mux = OwnedMux::bind(&dir, std::path::Path::new("mux")).expect("replace stale");
        assert_eq!(
            std::fs::metadata(&dir)
                .expect("runtime metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("mux metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        mux.cleanup().expect("clean owned mux");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn bind_preserves_live_and_unprobeable_sockets() {
        for label in ["live", "permissions", "datagram"] {
            let dir = temp_dir(label);
            let path = dir.join("mux");
            let stream = (label != "datagram").then(|| UnixListener::bind(&path).unwrap());
            let datagram = (label == "datagram")
                .then(|| std::os::unix::net::UnixDatagram::bind(&path).unwrap());
            if label == "permissions" {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
            }
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            let error = OwnedMux::bind(&dir, std::path::Path::new("mux"))
                .expect_err("socket must be preserved");
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse)));
            let preserved = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(preserved.ino(), metadata.ino());
            assert_eq!(
                preserved.permissions().mode(),
                metadata.permissions().mode()
            );
            drop((stream, datagram));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn bind_refuses_symlinks_and_regular_files() {
        for label in ["symlink", "regular"] {
            let dir = temp_dir(label);
            let path = dir.join("mux");
            if label == "symlink" {
                symlink("missing", &path).expect("create symlink");
            } else {
                std::fs::write(&path, b"do not remove").expect("create regular file");
            }
            let error = OwnedMux::bind(&dir, std::path::Path::new("mux"))
                .expect_err("unsafe entry must be rejected");
            assert!(error.to_string().contains("refusing to replace"));
            assert!(std::fs::symlink_metadata(&path).is_ok());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn validates_the_longest_listener_path() {
        let limit = unix_socket_path_limit();
        let suffix_len = "_4294967295".len();
        let fitting_dir = temp_dir("path-limit");
        let fitting_root_len = fitting_dir.as_os_str().as_encoded_bytes().len() + 1;
        let fitting_name = "x".repeat(limit - fitting_root_len - suffix_len);
        OwnedMux::bind(&fitting_dir, std::path::Path::new(&fitting_name))
            .expect("longest listener path at limit");

        let too_long = format!("{fitting_name}x");
        let error = OwnedMux::bind(&fitting_dir, std::path::Path::new(&too_long))
            .expect_err("listener path beyond limit");
        assert!(error.to_string().contains("platform limit"));
        let _ = std::fs::remove_dir_all(fitting_dir);
    }

    #[tokio::test]
    async fn cleanup_does_not_remove_a_replacement_socket() {
        let dir = temp_dir("replacement");
        let path = dir.join("mux");
        let mut mux = OwnedMux::bind(&dir, std::path::Path::new("mux")).expect("bind mux");
        std::fs::remove_file(&path).expect("unlink original mux");
        let replacement = UnixListener::bind(&path).expect("bind replacement");

        mux.cleanup().expect("skip replacement");
        assert!(path.exists());

        drop(replacement);
        let _ = std::fs::remove_dir_all(dir);
    }
}

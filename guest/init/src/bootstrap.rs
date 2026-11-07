//! The mandatory launch-only root bootstrap. Every Silo direct boot carries
//! one, with or without an injected agent; absence is a launch error, never a
//! signal to fall back to a kernel or disk-order root.
use crate::owned::{read_fd, Fd};
use rootfs_spec::Bootstrap;

pub(crate) fn load() -> Result<Bootstrap, &'static str> {
    let fd = Fd::open(rootfs_spec::BOOTSTRAP_PATH.as_bytes(), libc::O_RDONLY)
        .map_err(|_| "bootstrap: missing or unreadable root bootstrap")?;
    let stat = fd.stat()?;
    if stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err("bootstrap: must be root-owned regular mode 0600");
    }
    let bytes = read_fd(&fd, rootfs_spec::MAX_JSON_BYTES)?;
    rootfs_spec::decode_bootstrap(&bytes).map_err(|_| "bootstrap: invalid root bootstrap")
}

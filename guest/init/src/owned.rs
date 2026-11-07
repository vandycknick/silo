//! Owned descriptors and bounded, exact reads shared by root assembly and
//! Rosetta preparation. The static no_std init cannot link nix/std; libc is
//! used consistently with its existing syscall layer.
use crate::io;
use alloc::vec::Vec;

pub(crate) struct Fd(pub(crate) i32);
impl Drop for Fd {
    fn drop(&mut self) {
        io::close(self.0);
    }
}
impl Fd {
    /// Opens without following a final symlink, close-on-exec.
    pub(crate) fn open(path: &[u8], flags: i32) -> Result<Self, &'static str> {
        let fd = io::open(path, flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0);
        if fd < 0 {
            Err("open failed")
        } else {
            Ok(Self(fd))
        }
    }
    pub(crate) fn stat(&self) -> Result<libc::stat, &'static str> {
        let mut stat = io::stat_zeroed();
        if unsafe { libc::fstat(self.0, &mut stat) } != 0 {
            return Err("fstat failed");
        }
        Ok(stat)
    }
    pub(crate) fn statfs(&self) -> Result<libc::statfs, &'static str> {
        // SAFETY: statfs is plain old data; the kernel fills it on success.
        let mut stat: libc::statfs = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstatfs(self.0, &mut stat) } != 0 {
            return Err("fstatfs failed");
        }
        Ok(stat)
    }
}

pub(crate) fn read_fd(fd: &Fd, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = io::read(fd.0, &mut buffer);
        if count < 0 {
            if io::errno() == libc::EINTR {
                continue;
            }
            return Err("read failed");
        }
        if count == 0 {
            return Ok(bytes);
        }
        let count = count as usize;
        if count > maximum.saturating_sub(bytes.len()) {
            return Err("input exceeds bound");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}
pub(crate) fn read_file(path: &[u8], maximum: usize) -> Result<Vec<u8>, &'static str> {
    read_fd(&Fd::open(path, libc::O_RDONLY)?, maximum)
}
pub(crate) fn path(prefix: &[u8], name: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + name.len() + suffix.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(name);
    out.extend_from_slice(suffix);
    out
}

/// Exact positioned read: EOF or error is never zero-filled.
pub(crate) fn pread_all(fd: &Fd, offset: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
    let mut done = 0;
    while done < bytes.len() {
        let at = offset
            .checked_add(done as u64)
            .and_then(|value| libc::off_t::try_from(value).ok())
            .ok_or("device read offset overflow")?;
        let read = unsafe {
            libc::pread(
                fd.0,
                bytes[done..].as_mut_ptr().cast(),
                bytes.len() - done,
                at,
            )
        };
        if read < 0 && io::errno() == libc::EINTR {
            continue;
        }
        if read <= 0 {
            return Err("truncated device read");
        }
        done += read as usize;
    }
    Ok(())
}

/// Creates or admits a root-owned trusted directory with an exact mode.
pub(crate) fn directory(path: &[u8], mode: u32) -> Result<(), &'static str> {
    if io::mkdir(path, mode) != 0 && io::errno() != libc::EEXIST {
        return Err("cannot create trusted directory");
    }
    let stat = Fd::open(path, libc::O_RDONLY | libc::O_DIRECTORY)?.stat()?;
    if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o7777 != mode {
        return Err("unsafe trusted directory");
    }
    Ok(())
}

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::OciResult;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};

#[cfg(unix)]
pub(crate) struct FileLock {
    _lock: Flock<File>,
}

#[cfg(not(unix))]
pub(crate) struct FileLock {
    _file: File,
}

impl FileLock {
    pub(crate) fn exclusive(path: &Path) -> OciResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        #[cfg(unix)]
        {
            let lock = Flock::lock(file, FlockArg::LockExclusive)
                .map_err(|(_, err)| std::io::Error::from(err))?;
            Ok(Self { _lock: lock })
        }

        #[cfg(not(unix))]
        {
            Ok(Self { _file: file })
        }
    }
}

use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct LockId(u32);

impl LockId {
    pub(crate) fn as_u32(self) -> u32 {
        self.0
    }
}

impl Display for LockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for LockId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<LockId> for u32 {
    fn from(value: LockId) -> Self {
        value.0
    }
}

/// Allocates and retrieves advisory machine locks.
///
/// Lock files serve two related but separate purposes:
///
/// - File existence reserves a numeric lock ID for one machine.
/// - `flock` on that file serializes operations on that machine.
///
/// A reserved lock file is not proof that a machine exists. SQLite remains the
/// source of truth for persisted machines. If the process dies after allocation
/// but before the machine record is committed, a tombstone lock can remain:
///
/// - create allocates `locks/0`
/// - the process is killed before SQLite commit
/// - `locks/0` remains, but no machine row points at it
/// - the next create skips `0` and allocates `1`
///
/// That wastes a lock ID until external cleanup, but it is not corrupting.
/// Allocation uses atomic create-new semantics, so two live creates do not
/// receive the same lock ID, and runtime machine discovery is driven by SQLite.
#[derive(Debug, Clone)]
pub(crate) struct LockManager {
    dir: PathBuf,
}

/// A reserved numeric lock ID.
///
/// Holding a `ManagedLock` does not mean the advisory lock is currently held;
/// call `lock` or `try_lock` to acquire the `flock` guard. Dropping a
/// `ManagedLock` also does not free the allocation. The owner must call `free`
/// when the machine create fails or when the persisted machine is removed.
#[derive(Debug, Clone)]
pub(crate) struct ManagedLock {
    id: LockId,
    manager: LockManager,
}

#[must_use = "lock releases when dropped"]
pub(crate) struct LockGuard {
    _file: Flock<File>,
}

impl LockManager {
    pub(crate) fn open(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Reserves the lowest available numeric lock ID.
    ///
    /// `create_lock_allocation` uses `create_new(true)`, so concurrent callers
    /// racing for the same ID get exactly one winner. Losers see
    /// `AlreadyExists` and continue scanning.
    pub(crate) fn allocate(&self) -> io::Result<ManagedLock> {
        std::fs::create_dir_all(&self.dir)?;
        for raw_id in 0..=u32::MAX {
            let id = LockId::from(raw_id);
            match create_lock_allocation(&self.lock_path(id)) {
                Ok(()) => return Ok(self.retrieve(id)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(io::Error::other("no lock IDs available"))
    }

    #[cfg(test)]
    pub(crate) fn allocate_existing(&self, id: LockId) -> io::Result<ManagedLock> {
        std::fs::create_dir_all(&self.dir)?;
        create_lock_allocation(&self.lock_path(id))?;
        Ok(self.retrieve(id))
    }

    pub(crate) fn retrieve(&self, id: LockId) -> ManagedLock {
        ManagedLock {
            id,
            manager: self.clone(),
        }
    }

    pub(crate) fn free(&self, id: LockId) -> io::Result<()> {
        match std::fs::remove_file(self.lock_path(id)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn lock_path(&self, id: LockId) -> PathBuf {
        self.dir.join(id.as_u32().to_string())
    }
}

impl ManagedLock {
    pub(crate) fn id(&self) -> LockId {
        self.id
    }

    pub(crate) fn lock(&self) -> io::Result<LockGuard> {
        let mut file = open_lock_file(&self.manager.lock_path(self.id))?;
        loop {
            match Flock::lock(file, FlockArg::LockExclusive) {
                Ok(locked) => return Ok(LockGuard { _file: locked }),
                Err((returned_file, Errno::EINTR)) => file = returned_file,
                Err((_, err)) => return Err(lock_error(err)),
            }
        }
    }

    pub(crate) fn try_lock(&self) -> io::Result<Option<LockGuard>> {
        let mut file = open_lock_file(&self.manager.lock_path(self.id))?;
        loop {
            match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
                Ok(locked) => return Ok(Some(LockGuard { _file: locked })),
                Err((_, err)) if err == Errno::EAGAIN || err == Errno::EWOULDBLOCK => {
                    return Ok(None);
                }
                Err((returned_file, Errno::EINTR)) => file = returned_file,
                Err((_, err)) => return Err(lock_error(err)),
            }
        }
    }

    pub(crate) fn free(self) -> io::Result<()> {
        self.manager.free(self.id)
    }
}

fn create_lock_allocation(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    Ok(())
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn lock_error(err: Errno) -> io::Error {
    io::Error::from_raw_os_error(err as i32)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Barrier};

    use crate::lock_manager::{LockId, LockManager};

    #[test]
    fn lock_id_serializes_as_number() {
        let json = serde_json::to_string(&LockId::from(7)).expect("serialize lock id");
        let parsed: LockId = serde_json::from_str(&json).expect("deserialize lock id");

        assert_eq!(json, "7");
        assert_eq!(parsed, LockId::from(7));
    }

    #[test]
    fn allocate_creates_numeric_lock_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");

        let lock = manager.allocate().expect("allocate lock");

        assert_eq!(lock.id(), LockId::from(0));
        assert!(manager.lock_path(lock.id()).exists());
    }

    #[test]
    fn allocate_skips_existing_lock_ids() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");
        let _allocated = manager
            .allocate_existing(LockId::from(0))
            .expect("allocate lock 0");

        let lock = manager.allocate().expect("allocate next lock");

        assert_eq!(lock.id(), LockId::from(1));
        assert!(manager.lock_path(lock.id()).exists());
    }

    #[test]
    fn allocate_returns_unique_ids_under_concurrency() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager =
            Arc::new(LockManager::open(temp.path().join("locks")).expect("open lock manager"));
        let thread_count = 16usize;
        let start = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let manager = Arc::clone(&manager);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    manager.allocate().expect("allocate lock").id()
                })
            })
            .collect();

        let ids: BTreeSet<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("allocation thread should not panic"))
            .collect();

        assert_eq!(ids.len(), thread_count);
        for id in ids {
            assert!(manager.lock_path(id).exists());
        }
    }

    #[test]
    fn allocate_reuses_freed_lock_id() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");
        let lock = manager.allocate().expect("allocate lock");
        let id = lock.id();
        lock.free().expect("free lock");

        let reused = manager.allocate().expect("allocate reused lock");

        assert_eq!(reused.id(), id);
    }

    #[test]
    fn try_lock_returns_none_when_lock_is_held() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");
        let lock = manager.allocate().expect("allocate lock");
        let _guard = lock.lock().expect("lock allocation");

        assert!(manager
            .retrieve(lock.id())
            .try_lock()
            .expect("try lock allocation")
            .is_none());
    }

    #[test]
    fn try_lock_returns_guard_when_available() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");
        let lock = manager.allocate().expect("allocate lock");

        assert!(lock.try_lock().expect("try lock allocation").is_some());
    }

    #[test]
    fn lock_recreates_missing_allocation_file() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let manager = LockManager::open(temp.path().join("locks")).expect("open lock manager");
        let lock = manager.allocate().expect("allocate lock");
        let id = lock.id();
        let path = manager.lock_path(id);
        lock.free().expect("free lock");

        let _guard = manager.retrieve(id).lock().expect("recreate and lock");

        assert!(path.exists());
    }
}

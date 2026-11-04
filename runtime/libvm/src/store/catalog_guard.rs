use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{open, FlockArg, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use nix::unistd::geteuid;

use crate::LibVmError;

/// This is not a SQLite file. Closing a guard cannot cancel SQLite's locks.
/// The final descriptor close releases flock, including inherited duplicates.
#[derive(Debug)]
pub(crate) struct CatalogGuard(File, Option<CloseNotification>);

/// Fields are dropped in declaration order: CatalogGuard's File closes before
/// this notification is emitted. Native SQLite and pool options independently
/// own the guard, so completion fences both native shutdown and flock release.
#[derive(Debug)]
struct CloseNotification(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for CloseNotification {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl CatalogGuard {
    /// SQLx 0.9 drops pool options before its SQLite worker necessarily exits.
    /// A registered SQLite collation instead owns this guard until sqlite3_close
    /// destroys the native connection, after closing its Btrees. The reserved
    /// collation must never be replaced. It performs ordinary byte ordering;
    /// its purpose here is native connection ownership, not query semantics.
    ///
    /// Startup options must contain only connection-local settings: all
    /// database-touching PRAGMAs run in after_connect, after this is installed.
    /// Qualified against SQLx 0.9.0 options/connect.rs and bundled SQLite
    /// 3.51.3 main.c: sqlite3BtreeClose precedes collation xDel. The default
    /// foreign_keys startup pragma is a connection flag without NeedSchema.
    /// Requalify these orderings when upgrading either dependency.
    /// See <https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-sqlite/src/options/connect.rs>
    /// and <https://github.com/sqlite/sqlite/blob/version-3.51.3/src/main.c#L1371-L1428>.
    pub(crate) fn attach_sqlite(
        guard: Arc<Self>,
        options: sqlx::sqlite::SqliteConnectOptions,
    ) -> sqlx::sqlite::SqliteConnectOptions {
        options.collation("silo_catalog_access_v1", move |left, right| {
            let _keep_alive = &guard;
            left.as_bytes().cmp(right.as_bytes())
        })
    }

    pub(crate) async fn writable(home: &Path) -> Result<Arc<Self>, LibVmError> {
        let flags = OFlag::O_RDWR
            | OFlag::O_CREAT
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK;
        let guard = Self::open(home, flags)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !guard.try_lock(FlockArg::LockSharedNonblock)? {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "storage catalog is busy",
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(Arc::new(guard))
    }

    pub(crate) fn readonly(home: &Path) -> Result<Arc<Self>, LibVmError> {
        let guard = Self::open(home, OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .map_err(|error| match error {
                LibVmError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => LibVmError::StateDecode {
                    field: "state_db.catalog_access",
                    message: "state lacks current catalog exclusion; reinstall Silo and explicitly wipe incompatible state".to_string(),
                },
                other => other,
            })?;
        if !guard.try_lock(FlockArg::LockExclusiveNonblock)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "storage catalog is active; no-write planning requires exclusive access",
            )
            .into());
        }
        Ok(Arc::new(guard))
    }

    /// A live observer shares catalog exclusion with initialized writers, but
    /// never creates the lock or waits behind exclusive read-only planning.
    pub(crate) fn observation(
        home: &Path,
    ) -> Result<(Arc<Self>, tokio::sync::oneshot::Receiver<()>), LibVmError> {
        let mut guard = Self::open(
            home,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        )?;
        if !guard.try_lock(FlockArg::LockSharedNonblock)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "storage catalog is held by exclusive read-only planning",
            )
            .into());
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        guard.1 = Some(CloseNotification(Some(sender)));
        Ok((Arc::new(guard), receiver))
    }

    fn open(home: &Path, flags: OFlag) -> Result<Self, LibVmError> {
        let path = home.join("catalog.lock");
        let fd = open(&path, flags, Mode::S_IRUSR | Mode::S_IWUSR).map_err(std::io::Error::from)?;
        let stat = fstat(&fd).map_err(std::io::Error::from)?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
            || stat.st_uid != geteuid().as_raw()
            || stat.st_nlink != 1
            || stat.st_mode & 0o777 != 0o600
        {
            return Err(LibVmError::InvalidOwnedPath {
                path,
                message: "catalog lock must be an owner-controlled mode 0600 regular file"
                    .to_string(),
            });
        }
        Ok(Self(File::from(fd), None))
    }

    fn try_lock(&self, argument: FlockArg) -> Result<bool, LibVmError> {
        loop {
            #[allow(deprecated)]
            match nix::fcntl::flock(self.0.as_raw_fd(), argument) {
                Ok(()) => return Ok(true),
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => return Ok(false),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::ConnectOptions;

    use crate::store::catalog_guard::CatalogGuard;
    use crate::store::Store;

    struct OptionsDropped(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for OptionsDropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn cancelled_connection_retains_native_guard_until_blocked_worker_closes() {
        cancelled_native_connection(false).await;
    }

    #[tokio::test]
    async fn live_capabilities_cancelled_observer_retains_native_guard_until_worker_closes() {
        cancelled_native_connection(true).await;
    }

    async fn cancelled_native_connection(observer: bool) {
        let home = tempfile::tempdir().unwrap();
        let state = home.path().join("state.db");
        Store::open(&state).await.unwrap().close().await;
        let quiescent = catalog_quiescent(home.path()).await;
        let wal = home.path().join("state.db-wal");
        drop(quiescent);
        let (sqlite_options, observer_closed) = if observer {
            let connection = crate::store::observation::connection_options(&state).unwrap();
            (connection.options, Some(connection.closed))
        } else {
            (
                CatalogGuard::attach_sqlite(
                    CatalogGuard::writable(home.path()).await.unwrap(),
                    SqliteConnectOptions::new().filename(&state),
                ),
                None,
            )
        };
        let (options_dropped, options_gone) = tokio::sync::oneshot::channel();
        let marker = Arc::new(OptionsDropped(Some(options_dropped)));
        let options = sqlite_options.thread_name(move |id| {
            let _keep_alive = &marker;
            format!("silo-catalog-cancel-{id}")
        });
        let (entered, mut worker_entered) = tokio::sync::mpsc::unbounded_channel();
        let (release, worker_release) = std::sync::mpsc::channel();
        // A single native connection avoids pool after_connect retry masking
        // the original schema/setup error before a progress callback can run.
        let mut connecting = tokio::spawn(async move {
            let mut connection = options.connect().await?;
            let mut handle = connection.lock_handle().await?;
            handle.set_progress_handler(1, move || {
                let _ = entered.send(());
                let _ = worker_release.recv();
                false
            });
            drop(handle);
            sqlx::query("SELECT 7").execute(&mut connection).await?;
            Ok::<_, sqlx::Error>(connection)
        });
        let progress = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                Some(()) = worker_entered.recv() => Ok(()),
                result = &mut connecting => Err(format!("SQLite setup failed before progress callback: {result:?}")),
            }
        }).await;
        if !matches!(progress, Ok(Ok(()))) {
            connecting.abort();
            let _ = release.send(());
            if !connecting.is_finished() {
                let _ = connecting.await;
            }
            panic!("native cancellation fixture setup: {progress:?}");
        }
        connecting.abort();
        assert!(connecting.await.unwrap_err().is_cancelled());
        // The marker lives only in ConnectOptions, not in SQLite. Its drop
        // proves pool/options ownership cannot be what retains this lock.
        tokio::time::timeout(Duration::from_secs(2), options_gone)
            .await
            .unwrap()
            .unwrap();
        let blocked = CatalogGuard::readonly(home.path()).is_err();
        release.send(()).unwrap();
        assert!(
            blocked,
            "native worker lost catalog exclusion before SQLite close"
        );
        if let Some(closed) = observer_closed {
            tokio::time::timeout(Duration::from_secs(2), closed)
                .await
                .unwrap()
                .unwrap();
        }
        let closed = catalog_quiescent(home.path()).await;
        if !observer {
            assert!(
                !wal.exists(),
                "catalog released before writable WAL teardown"
            );
        }
        drop(closed);
    }

    async fn catalog_quiescent(home: &std::path::Path) -> Arc<CatalogGuard> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(guard) = CatalogGuard::readonly(home) {
                return guard;
            }
            assert!(
                Instant::now() < deadline,
                "native guard leaked after SQLite worker shutdown"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

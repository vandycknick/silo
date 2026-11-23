use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;

use crate::lobby::failure::Code;
use crate::lobby::identity::Principal;
use crate::lobby::state::{private_dir, sync_dir};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Decision {
    pub(crate) time: DateTime<Utc>,
    pub(crate) principals: Vec<Principal>,
    pub(crate) node_id: String,
    pub(crate) action: String,
    pub(crate) allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<Code>,
}

const QUEUE_CAPACITY: usize = 1024;
const COMMIT_RECORDS: usize = 64;
const COMMIT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
enum Rotation {
    Idle,
    Sync,
    Shift(usize),
    Rename,
    Quarantine,
    RemoveQuarantined,
    Open,
    SyncDirectory,
}

struct Writer {
    path: PathBuf,
    limit: u64,
    backups: usize,
    file: File,
    size: u64,
    rotation: Rotation,
    next_quarantine: u64,
}

pub(crate) struct Audit {
    sender: Mutex<Option<mpsc::SyncSender<Decision>>>,
    failure: tokio::sync::watch::Sender<Option<String>>,
    closing: Arc<AtomicBool>,
    worker: tokio::sync::Mutex<Option<JoinHandle<io::Result<()>>>>,
}

impl Audit {
    pub(crate) fn open(home: impl AsRef<Path>, limit: u64, backups: usize) -> io::Result<Self> {
        if limit == 0 || backups == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid audit rotation limits",
            ));
        }
        let dir = home.as_ref().join("lobby");
        private_dir(&dir)?;
        let path = dir.join("audit.log");
        let (file, size) = open_file(&path)?;
        let writer = Writer {
            path,
            limit,
            backups,
            file,
            size,
            rotation: Rotation::Idle,
            next_quarantine: 0,
        };
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (failure, _) = tokio::sync::watch::channel(None);
        let failed = failure.clone();
        let closing = Arc::new(AtomicBool::new(false));
        let stop = closing.clone();
        let worker = std::thread::Builder::new()
            .name("lobby-audit".into())
            .spawn(move || writer.run(receiver, &failed, &stop))?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            failure,
            closing,
            worker: tokio::sync::Mutex::new(Some(worker)),
        })
    }

    /// Admission is nonblocking. A full queue or failed writer denies the decision.
    pub(crate) fn append(&self, mut decision: Decision) -> io::Result<()> {
        let sender = self.sender.lock();
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(io::Error::other(error.clone()));
        }
        let sender = sender
            .as_ref()
            .ok_or_else(|| io::Error::other("audit closed"))?;
        decision.time = Utc::now();
        sender.try_send(decision).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => {
                io::Error::new(io::ErrorKind::WouldBlock, "audit queue full")
            }
            mpsc::TrySendError::Disconnected(_) => io::Error::other("audit writer unavailable"),
        })
    }

    pub(crate) fn diagnostic(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.failure.subscribe()
    }

    /// Dropping the sender drains queued records and commits them before joining.
    pub(crate) async fn close(&self) -> io::Result<()> {
        self.closing.store(true, Ordering::Release);
        self.sender.lock().take();
        let mut worker = self.worker.lock().await;
        if let Some(worker) = worker.take() {
            let result = tokio::task::spawn_blocking(move || {
                worker
                    .join()
                    .map_err(|_| io::Error::other("audit writer panicked"))?
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))
            .and_then(|result| result);
            if let Err(error) = result {
                self.failure.send_replace(Some(error.to_string()));
                return Err(error);
            }
        }
        if let Some(error) = self.failure.borrow().as_ref() {
            return Err(io::Error::other(error.clone()));
        }
        Ok(())
    }
}

impl Drop for Audit {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
    }
}

impl Writer {
    fn run(
        mut self,
        receiver: mpsc::Receiver<Decision>,
        failure: &tokio::sync::watch::Sender<Option<String>>,
        closing: &AtomicBool,
    ) -> io::Result<()> {
        let mut pending = 0;
        let mut deadline = Instant::now() + COMMIT_INTERVAL;
        loop {
            let disconnected =
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(decision) => {
                        self.retry(failure, closing, |writer| writer.append(&decision))?;
                        pending += 1;
                        false
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => false,
                    Err(mpsc::RecvTimeoutError::Disconnected) => true,
                };
            if disconnected || pending >= COMMIT_RECORDS || Instant::now() >= deadline {
                if pending > 0 {
                    self.commit(&receiver, failure, closing)?;
                    pending = 0;
                }
                if disconnected {
                    return Ok(());
                }
                deadline = Instant::now() + COMMIT_INTERVAL;
            }
        }
    }
    fn commit(
        &mut self,
        receiver: &mpsc::Receiver<Decision>,
        failure: &tokio::sync::watch::Sender<Option<String>>,
        closing: &AtomicBool,
    ) -> io::Result<()> {
        while let Ok(decision) = receiver.try_recv() {
            self.retry(failure, closing, |writer| writer.append(&decision))?;
        }
        self.retry(failure, closing, |writer| writer.file.sync_all())
    }

    fn retry(
        &mut self,
        failure: &tokio::sync::watch::Sender<Option<String>>,
        closing: &AtomicBool,
        mut operation: impl FnMut(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut delay = Duration::from_millis(100);
        loop {
            match operation(self) {
                Ok(()) => {
                    failure.send_if_modified(|diagnostic| diagnostic.take().is_some());
                    return Ok(());
                }
                Err(error) => {
                    tracing::error!(%error, "lobby audit writer failed; retrying");
                    failure.send_replace(Some(error.to_string()));
                    if closing.load(Ordering::Acquire) {
                        return Err(error);
                    }
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    fn append(&mut self, decision: &Decision) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(decision)?;
        bytes.push(b'\n');
        if matches!(self.rotation, Rotation::Idle)
            && self.size > 0
            && self.size.saturating_add(bytes.len() as u64) > self.limit
        {
            self.rotation = Rotation::Sync;
        }
        self.rotate()?;
        if let Err(error) = self.file.write_all(&bytes) {
            self.rollback_partial_write()?;
            return Err(error);
        }
        self.size += bytes.len() as u64;
        Ok(())
    }
    fn rollback_partial_write(&mut self) -> io::Result<()> {
        if let Err(error) = self.file.set_len(self.size) {
            // Never append another record after an unrepairable partial JSON tail.
            self.rotation = Rotation::Quarantine;
            return Err(error);
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        loop {
            self.rotation = match self.rotation {
                Rotation::Idle => return Ok(()),
                Rotation::Sync => {
                    self.file.sync_all()?;
                    Rotation::Shift(self.backups)
                }
                Rotation::Shift(index) if index >= 2 => {
                    match fs::rename(self.backup(index - 1), self.backup(index)) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    Rotation::Shift(index - 1)
                }
                Rotation::Shift(_) => Rotation::Rename,
                Rotation::Rename => {
                    fs::rename(&self.path, self.backup(1))?;
                    Rotation::Open
                }
                Rotation::Quarantine => {
                    self.quarantine()?;
                    Rotation::RemoveQuarantined
                }
                Rotation::RemoveQuarantined => {
                    if let Some(parent) = self.path.parent() {
                        sync_dir(parent)?;
                    }
                    fs::remove_file(&self.path)?;
                    Rotation::Open
                }
                Rotation::Open => {
                    let (file, size) = open_file(&self.path)?;
                    self.file = file;
                    self.size = size;
                    Rotation::SyncDirectory
                }
                Rotation::SyncDirectory => {
                    if let Some(parent) = self.path.parent() {
                        sync_dir(parent)?;
                    }
                    Rotation::Idle
                }
            };
        }
    }

    fn quarantine(&mut self) -> io::Result<()> {
        loop {
            let sequence = self.next_quarantine;
            self.next_quarantine = sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("audit quarantine sequence exhausted"))?;
            let mut damaged = self.path.as_os_str().to_os_string();
            damaged.push(format!(".damaged.{sequence}"));
            // Linking is a portable no-replace operation. Keep the source name
            // until the new evidence link is durable, then resume at unlink.
            match fs::hard_link(&self.path, PathBuf::from(damaged)) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn backup(&self, index: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }
}

fn open_file(path: &Path) -> io::Result<(File, u64)> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.mode() & 0o077 != 0 => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit must be a private regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC).bits())
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit must be a private regular file",
        ));
    }
    Ok((file, metadata.len()))
}

#[cfg(test)]
mod tests {
    use crate::lobby::audit::{Audit, Decision};
    use crate::lobby::identity::Principal;
    use std::{
        collections::HashSet,
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::Arc,
    };

    fn decision(node_id: String) -> Decision {
        Decision {
            time: chrono::DateTime::default(),
            principals: vec![Principal::parse("user:1").unwrap()],
            node_id,
            action: "vm.read".into(),
            allowed: true,
            code: None,
        }
    }

    #[tokio::test]
    async fn rotation_concurrent_real_files() {
        let home = tempfile::tempdir().unwrap();
        let audit = Arc::new(Audit::open(home.path(), 1024, 100).unwrap());
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let audit = audit.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        audit.append(decision(format!("{worker}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        audit.close().await.unwrap();
        audit.close().await.unwrap();
        assert!(audit.append(decision("closed".into())).is_err());
        let mut seen = HashSet::new();
        for entry in fs::read_dir(home.path().join("lobby")).unwrap() {
            let path = entry.unwrap().path();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            for line in fs::read_to_string(path).unwrap().lines() {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                assert!(seen.insert(value["node_id"].as_str().unwrap().to_owned()));
                assert_ne!(value["time"], "1970-01-01T00:00:00Z");
                assert!(value.get("code").is_none());
            }
        }
        assert_eq!(seen.len(), 160);
    }

    #[test]
    fn unsafe_files_and_invalid_rotation_limits_are_rejected() {
        let home = tempfile::tempdir().unwrap();
        assert!(Audit::open(home.path(), 0, 1).is_err());
        assert!(Audit::open(home.path(), 1, 0).is_err());
        let dir = home.path().join("lobby");
        crate::lobby::state::private_dir(&dir).unwrap();
        let path = dir.join("audit.log");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Audit::open(home.path(), 1024, 1).is_err());
        fs::remove_file(&path).unwrap();
        symlink(home.path().join("target"), &path).unwrap();
        assert!(Audit::open(home.path(), 1024, 1).is_err());
    }

    #[tokio::test]
    async fn backups_are_bounded_and_reopening_appends() {
        let home = tempfile::tempdir().unwrap();
        let audit = Audit::open(home.path(), 1, 2).unwrap();
        for i in 0..5 {
            audit.append(decision(i.to_string())).unwrap();
        }
        audit.close().await.unwrap();
        assert_eq!(fs::read_dir(home.path().join("lobby")).unwrap().count(), 3);
        let audit = Audit::open(home.path(), 4096, 2).unwrap();
        audit.append(decision("last".into())).unwrap();
        audit.close().await.unwrap();
        assert_eq!(
            fs::read_to_string(home.path().join("lobby/audit.log"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn close_commits_queued_decisions_in_order() {
        let home = tempfile::tempdir().unwrap();
        let audit = Audit::open(home.path(), 1 << 20, 3).unwrap();
        for index in 0..200 {
            audit.append(decision(index.to_string())).unwrap();
        }
        let (first, second) = tokio::join!(audit.close(), audit.close());
        first.unwrap();
        second.unwrap();
        let text = fs::read_to_string(home.path().join("lobby/audit.log")).unwrap();
        let ids: Vec<_> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["node_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(ids, (0..200).map(|i| i.to_string()).collect::<Vec<_>>());
        assert!(audit.append(decision("closed".into())).is_err());
    }

    #[test]
    fn commit_drains_the_entire_backlog_before_syncing() {
        use crate::lobby::audit::{open_file, Writer};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit.log");
        let (file, size) = open_file(&path).unwrap();
        let mut writer = Writer {
            path: path.clone(),
            limit: 1 << 20,
            backups: 1,
            file,
            size,
            rotation: crate::lobby::audit::Rotation::Idle,
            next_quarantine: 0,
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(1024);
        for index in 0..200 {
            sender.send(decision(index.to_string())).unwrap();
        }
        let (failure, _) = tokio::sync::watch::channel(None);
        writer
            .commit(
                &receiver,
                &failure,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 200);
    }

    #[test]
    fn rotation_retry_resumes_without_shifting_completed_backups_again() {
        use crate::lobby::audit::{open_file, Rotation, Writer};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit.log");
        let (file, size) = open_file(&path).unwrap();
        let mut writer = Writer {
            path: path.clone(),
            limit: 1,
            backups: 3,
            file,
            size,
            rotation: Rotation::Idle,
            next_quarantine: 0,
        };
        writer.append(&decision("current".into())).unwrap();
        fs::write(writer.backup(1), "previous-one").unwrap();
        fs::write(writer.backup(2), "previous-two").unwrap();
        let held = root.path().join("held");
        fs::rename(&path, &held).unwrap();
        assert!(writer.append(&decision("next".into())).is_err());
        assert!(matches!(writer.rotation, Rotation::Rename));
        fs::rename(&held, &path).unwrap();
        writer.append(&decision("next".into())).unwrap();
        assert_eq!(
            fs::read_to_string(writer.backup(3)).unwrap(),
            "previous-two"
        );
        assert_eq!(
            fs::read_to_string(writer.backup(2)).unwrap(),
            "previous-one"
        );
        assert!(fs::read_to_string(writer.backup(1))
            .unwrap()
            .contains("current"));
        assert!(fs::read_to_string(path).unwrap().contains("next"));
    }

    #[test]
    fn failed_partial_write_truncation_quarantines_before_reopening() {
        use crate::lobby::audit::{open_file, Rotation, Writer};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit.log");
        let (file, size) = open_file(&path).unwrap();
        let mut writer = Writer {
            path: path.clone(),
            limit: 1 << 20,
            backups: 1,
            file,
            size,
            rotation: Rotation::Idle,
            next_quarantine: 0,
        };
        fs::write(
            root.path().join("audit.log.damaged.0"),
            b"existing evidence",
        )
        .unwrap();
        writer.append(&decision("complete".into())).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"{\"incomplete\":").unwrap();
        // A real read-only descriptor makes ftruncate fail, leaving the partial tail.
        writer.file = std::fs::File::open(&path).unwrap();
        assert!(writer.rollback_partial_write().is_err());
        assert!(matches!(writer.rotation, Rotation::Quarantine));
        writer.append(&decision("recovered".into())).unwrap();
        let current = fs::read_to_string(&path).unwrap();
        assert_eq!(current.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&current).unwrap()["node_id"],
            "recovered"
        );
        let first = fs::read_to_string(root.path().join("audit.log.damaged.1")).unwrap();
        assert!(first.ends_with("{\"incomplete\":"));
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"{\"second-incomplete\":").unwrap();
        writer.file = std::fs::File::open(&path).unwrap();
        assert!(writer.rollback_partial_write().is_err());
        writer.append(&decision("second-recovery".into())).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("audit.log.damaged.0")).unwrap(),
            "existing evidence"
        );
        assert_eq!(
            fs::read_to_string(root.path().join("audit.log.damaged.1")).unwrap(),
            first
        );
        let second = fs::read_to_string(root.path().join("audit.log.damaged.2")).unwrap();
        assert!(second.contains("recovered"));
        assert!(second.ends_with("{\"second-incomplete\":"));
        let current: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(current["node_id"], "second-recovery");
    }

    #[tokio::test]
    async fn writer_recovers_after_transient_rotation_failure() {
        let home = tempfile::tempdir().unwrap();
        let audit = Audit::open(home.path(), 1, 1).unwrap();
        fs::create_dir(home.path().join("lobby/audit.log.1")).unwrap();
        audit.append(decision("first".into())).unwrap();
        audit.append(decision("rotate".into())).unwrap();
        let mut diagnostic = audit.diagnostic();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while diagnostic.borrow_and_update().is_none() {
                diagnostic.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(audit.append(decision("after-failure".into())).is_err());
        fs::remove_dir(home.path().join("lobby/audit.log.1")).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while diagnostic.borrow_and_update().is_some() {
                diagnostic.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        audit.append(decision("recovered".into())).unwrap();
        audit.close().await.unwrap();
        let records = fs::read_to_string(home.path().join("lobby/audit.log")).unwrap();
        assert!(records.contains("recovered"));
        assert!(diagnostic.borrow().is_none());
    }
}

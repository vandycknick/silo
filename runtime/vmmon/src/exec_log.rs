use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use nix::fcntl::{openat, renameat, Flock, FlockArg, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use serde::Serialize;
use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
use uuid::Uuid;

const EXEC_LOG_FILE_NAME: &str = "exec.log";
const MAX_ACTIVE_BYTES: u64 = 10 * 1024 * 1024;
const WRITER_QUEUE_LINES: usize = 64;
const ARCHIVE_NAMES: [&str; 3] = ["exec.log.1", "exec.log.2", "exec.log.3"];

/// One validated machine log directory inherited from the machine owner.
pub(crate) struct ExecLogDirectory {
    fd: OwnedFd,
}

impl ExecLogDirectory {
    /// Takes ownership of a private directory descriptor for the future writer.
    pub(crate) fn from_fd(fd: RawFd) -> eyre::Result<Self> {
        // The descriptor is inherited only for setup and must not escape another exec.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        nix::fcntl::fcntl(
            &fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )?;
        validate_directory(&fd)?;
        Ok(Self { fd })
    }
}

/// Source recorded for a best-effort execution log line.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExecLogSource {
    Stdout,
    Stderr,
    Output,
    System,
}

impl ExecLogSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Output => "output",
            Self::System => "system",
        }
    }
}

/// Non-blocking best-effort writer for the machine-owned execution log.
#[derive(Clone)]
pub(crate) struct ExecLogWriter {
    writer: NonBlocking,
}

/// Keeps the background writer alive. Drop it after all `ExecLogWriter` clones.
pub(crate) struct ExecLogGuard {
    _worker: WorkerGuard,
}

impl ExecLogWriter {
    pub(crate) fn start(directory: ExecLogDirectory) -> eyre::Result<(Self, ExecLogGuard)> {
        Self::start_with_limit(directory, MAX_ACTIVE_BYTES)
    }

    fn start_with_limit(
        directory: ExecLogDirectory,
        maximum_active_bytes: u64,
    ) -> eyre::Result<(Self, ExecLogGuard)> {
        if maximum_active_bytes == 0 {
            return Err(eyre::eyre!("exec log maximum size must be positive"));
        }
        let output = RotatingExecLog::open(directory, maximum_active_bytes)?;
        let (writer, worker) = NonBlockingBuilder::default()
            .buffered_lines_limit(WRITER_QUEUE_LINES)
            .lossy(true)
            .finish(output);
        Ok((Self { writer }, ExecLogGuard { _worker: worker }))
    }

    /// Records bytes without affecting the execution that produced them.
    pub(crate) fn write(&self, source: ExecLogSource, id: Uuid, data: &[u8]) {
        self.write_record(ExecLogRecord::output(source, id, data));
    }

    /// Marks the current machine generation without recording execution inputs or results.
    pub(crate) fn generation(&self, machine_id: &str, run_id: &str, state: &str) {
        let message = format!(
            "--- silo vmmon generation {state} machine_id={machine_id} run_id={run_id} ---\n"
        );
        self.write_record(ExecLogRecord::system(&message));
    }

    fn write_record(&self, record: ExecLogRecord) {
        let Ok(mut line) = serde_json::to_vec(&record) else {
            return;
        };
        line.push(b'\n');
        let mut writer = self.writer.clone();
        let _ = writer.write_all(&line);
    }
}

#[derive(Serialize)]
struct ExecLogRecord {
    t: String,
    s: &'static str,
    d: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<&'static str>,
}

impl ExecLogRecord {
    fn output(source: ExecLogSource, id: Uuid, data: &[u8]) -> Self {
        let (d, e) = match std::str::from_utf8(data) {
            Ok(data) => (data.to_owned(), None),
            Err(_) => (
                base64::engine::general_purpose::STANDARD.encode(data),
                Some("b64"),
            ),
        };
        Self {
            t: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            s: source.as_str(),
            d,
            id: Some(id.hyphenated().to_string()),
            e,
        }
    }

    fn system(message: &str) -> Self {
        Self {
            t: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            s: ExecLogSource::System.as_str(),
            d: message.to_string(),
            id: None,
            e: None,
        }
    }
}

struct RotatingExecLog {
    directory: OwnedFd,
    _ownership: Flock<OwnedFd>,
    active: Flock<File>,
    bytes: u64,
    maximum_active_bytes: u64,
}

impl RotatingExecLog {
    fn open(directory: ExecLogDirectory, maximum_active_bytes: u64) -> eyre::Result<Self> {
        // Locking the directory, rather than a rotating file, preserves exclusive
        // ownership while the active filename is replaced.
        let ownership = Flock::lock(directory.fd.try_clone()?, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| eyre::Report::from(error))?;
        let active = open_active_file(&directory.fd)?;
        let bytes = active.metadata()?.len();
        Ok(Self {
            directory: directory.fd,
            _ownership: ownership,
            active,
            bytes,
            maximum_active_bytes,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.active.flush()?;
        validate_known_entries(&self.directory).map_err(io::Error::other)?;

        remove_if_present(&self.directory, "exec.log.3").map_err(io::Error::other)?;
        rename_if_present(&self.directory, "exec.log.2", "exec.log.3").map_err(io::Error::other)?;
        rename_if_present(&self.directory, "exec.log.1", "exec.log.2").map_err(io::Error::other)?;
        renameat(
            &self.directory,
            EXEC_LOG_FILE_NAME,
            &self.directory,
            "exec.log.1",
        )
        .map_err(io::Error::other)?;
        sync_directory(&self.directory).map_err(io::Error::other)?;

        self.active = open_active_file(&self.directory).map_err(io::Error::other)?;
        self.bytes = 0;
        Ok(())
    }
}

impl Write for RotatingExecLog {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let length =
            u64::try_from(data.len()).map_err(|_| io::Error::other("exec log line too large"))?;
        if self.bytes > 0 && self.bytes.saturating_add(length) > self.maximum_active_bytes {
            self.rotate()?;
        }
        self.active.write_all(data)?;
        self.bytes = self.bytes.saturating_add(length);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.active.flush()
    }
}

fn open_active_file(directory: &OwnedFd) -> eyre::Result<Flock<File>> {
    let fd = openat(
        directory,
        EXEC_LOG_FILE_NAME,
        OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_retain(0o600),
    )?;
    fchmod(&fd, Mode::from_bits_retain(0o600))?;
    validate_regular_file(&fd, EXEC_LOG_FILE_NAME)?;
    Flock::lock(File::from(fd), FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| eyre::Report::from(error))
}

fn validate_known_entries(directory: &OwnedFd) -> eyre::Result<()> {
    validate_existing_regular_file(directory, EXEC_LOG_FILE_NAME)?;
    for name in ARCHIVE_NAMES {
        validate_existing_regular_file(directory, name)?;
    }
    Ok(())
}

fn validate_existing_regular_file(directory: &OwnedFd, name: &str) -> eyre::Result<bool> {
    let fd = match openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    validate_regular_file(&fd, name)?;
    Ok(true)
}

fn remove_if_present(directory: &OwnedFd, name: &str) -> eyre::Result<()> {
    if validate_existing_regular_file(directory, name)? {
        unlinkat(directory, name, UnlinkatFlags::NoRemoveDir)?;
    }
    Ok(())
}

fn rename_if_present(directory: &OwnedFd, from: &str, to: &str) -> eyre::Result<()> {
    if validate_existing_regular_file(directory, from)? {
        renameat(directory, from, directory, to)?;
    }
    Ok(())
}

fn validate_directory(fd: &OwnedFd) -> eyre::Result<()> {
    let stat = fstat(fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR {
        return Err(eyre::eyre!("exec log parent is not a directory"));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err(eyre::eyre!(
            "exec log parent is not a private owned directory"
        ));
    }
    Ok(())
}

fn validate_regular_file(fd: &OwnedFd, name: &str) -> eyre::Result<()> {
    let stat = fstat(fd)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
        return Err(eyre::eyre!("{name} is not a regular file"));
    }
    if stat.st_uid != nix::unistd::geteuid().as_raw() || stat.st_mode & 0o777 != 0o600 {
        return Err(eyre::eyre!("{name} is not a private owned file"));
    }
    Ok(())
}

fn sync_directory(directory: &OwnedFd) -> eyre::Result<()> {
    File::from(directory.try_clone()?).sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use serde_json::Value;

    use crate::exec_log::{ExecLogDirectory, ExecLogSource, ExecLogWriter};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("silo-exec-log-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).expect("create temporary directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure temporary directory");
            Self(path)
        }

        fn directory(&self) -> ExecLogDirectory {
            let file = fs::File::open(&self.0).expect("open temporary directory");
            ExecLogDirectory::from_fd(file.into_raw_fd()).expect("validate temporary directory")
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn records(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("read exec log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse JSON line"))
            .collect()
    }

    #[test]
    fn writes_utf8_base64_and_generation_records() {
        let temp = TempDir::new();
        let (writer, guard) = ExecLogWriter::start(temp.directory()).expect("start writer");
        let stdout_id = uuid::Uuid::new_v4();
        let stderr_id = uuid::Uuid::new_v4();
        writer.write(ExecLogSource::Stdout, stdout_id, b"hello\n");
        writer.write(ExecLogSource::Stderr, stderr_id, &[0xff, 0]);
        writer.generation("machine", "run", "started");
        drop(writer);
        drop(guard);

        let records = records(&temp.path().join("exec.log"));
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["s"], "stdout");
        assert_eq!(records[0]["d"], "hello\n");
        assert_eq!(records[0]["id"], stdout_id.to_string());
        assert!(records[0].get("e").is_none());
        assert_eq!(records[1]["s"], "stderr");
        assert_eq!(records[1]["d"], "/wA=");
        assert_eq!(records[1]["e"], "b64");
        assert_eq!(records[2]["s"], "system");
        assert_eq!(
            records[2]["d"],
            "--- silo vmmon generation started machine_id=machine run_id=run ---\n"
        );
        assert!(records[2].get("id").is_none());
        assert!(records.iter().all(|record| record["t"].is_string()));
    }

    #[test]
    fn rotates_to_exactly_three_private_archives() {
        let temp = TempDir::new();
        let (writer, guard) =
            ExecLogWriter::start_with_limit(temp.directory(), 70).expect("start writer");
        let ids = (0..5).map(|_| uuid::Uuid::new_v4()).collect::<Vec<_>>();
        for id in &ids {
            writer.write(ExecLogSource::Output, *id, b"01234567890123456789");
        }
        drop(writer);
        drop(guard);

        assert!(temp.path().join("exec.log").is_file());
        for generation in 1..=3 {
            let archive = temp.path().join(format!("exec.log.{generation}"));
            assert!(archive.is_file());
            assert_eq!(
                fs::metadata(archive)
                    .expect("archive metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(!temp.path().join("exec.log.4").exists());
        for (name, expected) in [
            ("exec.log", ids[4]),
            ("exec.log.1", ids[3]),
            ("exec.log.2", ids[2]),
            ("exec.log.3", ids[1]),
        ] {
            let records = records(&temp.path().join(name));
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["id"], expected.to_string());
        }
        assert!(!fs::read_dir(temp.path())
            .expect("read log directory")
            .filter_map(Result::ok)
            .any(|entry| fs::read_to_string(entry.path())
                .is_ok_and(|contents| contents.contains(&ids[0].to_string()))));
    }

    #[test]
    fn only_one_writer_can_own_a_machine_log_directory() {
        let temp = TempDir::new();
        let (writer, guard) = ExecLogWriter::start(temp.directory()).expect("start writer");
        assert!(ExecLogWriter::start(temp.directory()).is_err());
        drop(writer);
        drop(guard);
    }
}

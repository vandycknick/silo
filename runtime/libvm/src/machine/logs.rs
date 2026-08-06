use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;

use crate::machine::Machine;
use crate::store::models::MachineNetworkConfig;
use crate::LibVmError;

const LOG_POLL_INTERVAL: Duration = Duration::from_millis(50);
const LOG_CHUNK_SIZE: usize = 8 * 1024;
const LOG_STREAM_BUFFER: usize = 8;
const EXEC_LOG_SNAPSHOT_RETRIES: usize = 8;

/// Selects one persisted machine log source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MachineLogSource {
    /// vmmon diagnostic output.
    Monitor,
    /// VM serial console output.
    Serial,
    /// Structured best-effort guest execution records.
    Exec,
    /// Private network service diagnostics.
    Network,
    /// Private network audit events.
    NetworkAudit,
}

/// Options for reading persisted machine logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineLogOptions {
    /// Continue after the snapshot until the stream is dropped.
    ///
    /// Machine-owned logs persist across stops and starts, so a following stream
    /// remains attached through later machine generations.
    pub follow: bool,
}

/// Output channel associated with a machine log chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MachineLogOutput {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Bytes read from one persisted machine log source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLogChunk {
    /// Output channel for these bytes.
    pub output: MachineLogOutput,
    /// Log bytes, preserved without text decoding.
    pub data: Bytes,
}

/// Async stream of semantic machine log chunks.
pub struct MachineLogStream {
    receiver: ReceiverStream<Result<MachineLogChunk, LibVmError>>,
}

impl Stream for MachineLogStream {
    type Item = Result<MachineLogChunk, LibVmError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl Machine {
    /// Opens one semantic persisted log source.
    ///
    /// This API intentionally exposes neither paths nor filenames. A
    /// non-following stream is a finite snapshot of the selected source. A
    /// following stream keeps one validated descriptor from that snapshot through
    /// appended bytes, so there is no snapshot-to-follow gap. Machine-owned logs
    /// append across stops and starts, so following remains attached through later
    /// producer generations until the stream is dropped. A source file that does
    /// not exist yet is an empty snapshot unless it is being followed.
    pub async fn logs(
        &self,
        source: MachineLogSource,
        options: MachineLogOptions,
    ) -> Result<MachineLogStream, LibVmError> {
        let runtime = self.runtime().clone();
        let machine_id = self.machine_id();
        let (_lock, config) = runtime.lock_machine_config(machine_id).await?;
        validate_log_source(&config, source)?;
        let paths = runtime.local_paths().clone();
        let file = (source != MachineLogSource::Exec)
            .then(|| open_log(&paths, machine_id, source))
            .transpose()?
            .flatten();
        let (sender, receiver) = mpsc::channel(LOG_STREAM_BUFFER);

        tokio::spawn(async move {
            let result = if source == MachineLogSource::Exec {
                stream_exec_log(paths, machine_id, options.follow, sender.clone()).await
            } else {
                stream_log(
                    paths,
                    machine_id,
                    source,
                    file,
                    options.follow,
                    sender.clone(),
                )
                .await
            };
            if let Err(error) = result {
                let _ = sender.send(Err(error)).await;
            }
        });

        Ok(MachineLogStream {
            receiver: ReceiverStream::new(receiver),
        })
    }
}

fn validate_log_source(
    config: &crate::store::models::MachineConfig,
    source: MachineLogSource,
) -> Result<(), LibVmError> {
    match source {
        MachineLogSource::Monitor | MachineLogSource::Serial | MachineLogSource::Exec => Ok(()),
        MachineLogSource::Network | MachineLogSource::NetworkAudit => {
            if !matches!(&config.network, MachineNetworkConfig::Private { .. }) {
                return Err(LibVmError::MachineLogSourceUnavailable {
                    reference: config.name.clone(),
                    log_source: source,
                });
            }
            Ok(())
        }
    }
}

async fn stream_log(
    paths: crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
    source: MachineLogSource,
    mut file: Option<OpenedLog>,
    follow: bool,
    sender: mpsc::Sender<Result<MachineLogChunk, LibVmError>>,
) -> Result<(), LibVmError> {
    if follow {
        while file.is_none() {
            if !wait_for_log(&sender).await {
                return Ok(());
            }
            file = open_log(&paths, machine_id, source)?;
        }
    }

    let Some(mut file) = file else {
        return Ok(());
    };
    send_snapshot(&mut file, &sender).await?;
    if !follow {
        return Ok(());
    }

    loop {
        if read_append(&mut file.file, &sender).await? {
            continue;
        }
        if !wait_for_log(&sender).await {
            return Ok(());
        }
    }
}

async fn wait_for_log(sender: &mpsc::Sender<Result<MachineLogChunk, LibVmError>>) -> bool {
    tokio::select! {
        () = sender.closed() => false,
        () = sleep(LOG_POLL_INTERVAL) => true,
    }
}

struct OpenedLog {
    file: File,
    snapshot_len: u64,
    identity: FileIdentity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

type ExecLogSignature = [Option<FileIdentity>; 4];

struct ExecLogSnapshot {
    archives: Vec<OpenedLog>,
    active: Option<OpenedLog>,
    signature: ExecLogSignature,
}

fn open_log(
    paths: &crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
    source: MachineLogSource,
) -> Result<Option<OpenedLog>, LibVmError> {
    let file = match source {
        MachineLogSource::Monitor => paths.open_vm_trace_log(machine_id)?,
        MachineLogSource::Serial => paths.open_serial_log(machine_id)?,
        MachineLogSource::Exec => paths.open_exec_log(machine_id)?,
        MachineLogSource::Network => paths.open_network_service_log(machine_id)?,
        MachineLogSource::NetworkAudit => paths.open_network_audit_log(machine_id)?,
    };
    let Some(file) = file else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    Ok(Some(OpenedLog {
        file,
        snapshot_len: metadata.len(),
        identity: FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    }))
}

async fn stream_exec_log(
    paths: crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
    follow: bool,
    sender: mpsc::Sender<Result<MachineLogChunk, LibVmError>>,
) -> Result<(), LibVmError> {
    let (archives, mut active) = open_exec_log_snapshots(&paths, machine_id)?;
    for mut archive in archives {
        send_snapshot(&mut archive, &sender).await?;
    }

    if let Some(active_file) = active.as_mut() {
        send_snapshot(active_file, &sender).await?;
    }
    if !follow {
        return Ok(());
    }

    loop {
        if let Some(active_file) = active.as_mut() {
            if read_append(&mut active_file.file, &sender).await? {
                continue;
            }
        }
        if !wait_for_log(&sender).await {
            return Ok(());
        }

        let (mut archives, replacement) = open_exec_log_snapshots(&paths, machine_id)?;
        let Some(mut replacement) = replacement else {
            continue;
        };
        if let Some(active_file) = active.as_mut() {
            if active_file.identity == replacement.identity {
                continue;
            }
            while read_append(&mut active_file.file, &sender).await? {}
            let first_newer_archive = archives
                .iter()
                .position(|archive| archive.identity == active_file.identity)
                .map_or(0, |index| index + 1);
            for archive in archives.iter_mut().skip(first_newer_archive) {
                send_snapshot(archive, &sender).await?;
            }
        } else {
            for archive in &mut archives {
                send_snapshot(archive, &sender).await?;
            }
        }
        send_snapshot(&mut replacement, &sender).await?;
        active = Some(replacement);
    }
}

fn open_exec_log_snapshots(
    paths: &crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
) -> Result<(Vec<OpenedLog>, Option<OpenedLog>), LibVmError> {
    for _ in 0..EXEC_LOG_SNAPSHOT_RETRIES {
        let snapshot = open_exec_log_snapshots_once(paths, machine_id)?;
        if snapshot.signature == exec_log_signature(paths, machine_id)? {
            return Ok((snapshot.archives, snapshot.active));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "exec log rotated continuously while opening a stable snapshot",
    )
    .into())
}

fn open_exec_log_snapshots_once(
    paths: &crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
) -> Result<ExecLogSnapshot, LibVmError> {
    let mut archives = Vec::with_capacity(3);
    let mut signature = [None; 4];
    for (index, generation) in [3, 2, 1].into_iter().enumerate() {
        if let Some(file) = paths.open_exec_log_archive(machine_id, generation)? {
            let file = opened_log(file)?;
            signature[index] = Some(file.identity);
            archives.push(file);
        }
    }
    let active = paths
        .open_exec_log(machine_id)?
        .map(opened_log)
        .transpose()?;
    signature[3] = active.as_ref().map(|file| file.identity);
    Ok(ExecLogSnapshot {
        archives,
        active,
        signature,
    })
}

fn exec_log_signature(
    paths: &crate::paths::LocalPaths,
    machine_id: crate::store::models::MachineId,
) -> Result<ExecLogSignature, LibVmError> {
    let mut signature = [None; 4];
    for (index, generation) in [3, 2, 1].into_iter().enumerate() {
        signature[index] = paths
            .open_exec_log_archive(machine_id, generation)?
            .map(file_identity)
            .transpose()?;
    }
    signature[3] = paths
        .open_exec_log(machine_id)?
        .map(file_identity)
        .transpose()?;
    Ok(signature)
}

fn opened_log(file: File) -> Result<OpenedLog, LibVmError> {
    let metadata = file.metadata()?;
    Ok(OpenedLog {
        file,
        snapshot_len: metadata.len(),
        identity: FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    })
}

fn file_identity(file: File) -> Result<FileIdentity, LibVmError> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

async fn send_snapshot(
    file: &mut OpenedLog,
    sender: &mpsc::Sender<Result<MachineLogChunk, LibVmError>>,
) -> Result<(), LibVmError> {
    let mut remaining = file.snapshot_len;
    while remaining > 0 {
        let read = read_chunk(&mut file.file, remaining)?;
        if read.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "machine log shrank while reading its snapshot",
            )
            .into());
        }
        let read_len = u64::try_from(read.len())
            .map_err(|_| std::io::Error::other("machine log chunk length does not fit in u64"))?;
        remaining = remaining.saturating_sub(read_len);
        send_chunk(sender, read).await?;
    }
    Ok(())
}

async fn read_append(
    file: &mut File,
    sender: &mpsc::Sender<Result<MachineLogChunk, LibVmError>>,
) -> Result<bool, LibVmError> {
    let bytes = read_chunk(file, LOG_CHUNK_SIZE as u64)?;
    if bytes.is_empty() {
        return Ok(false);
    }
    send_chunk(sender, bytes).await?;
    Ok(true)
}

fn read_chunk(file: &mut File, limit: u64) -> Result<Bytes, LibVmError> {
    let capacity = limit.min(LOG_CHUNK_SIZE as u64) as usize;
    let mut buffer = vec![0; capacity];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(Bytes::from(buffer))
}

async fn send_chunk(
    sender: &mpsc::Sender<Result<MachineLogChunk, LibVmError>>,
    data: Bytes,
) -> Result<(), LibVmError> {
    sender
        .send(Ok(MachineLogChunk {
            output: MachineLogOutput::Stdout,
            data,
        }))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "log reader dropped"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::process::{Child, Command};
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_stream::StreamExt;
    use vm_spec::VmSpec;

    use crate::machine::logs::{stream_log, LOG_STREAM_BUFFER};
    use crate::machine::{Machine, MachineLogOptions, MachineLogSource};
    use crate::paths::LocalPaths;
    use crate::runtime::RuntimeNetworkingConfig;
    use crate::store::models::{
        MachineConfig, MachineId, MachineNetworkConfig as StoredMachineNetworkConfig,
        MachineRuntimeState, MachineState,
    };
    use crate::{LibVmError, Runtime};

    async fn test_machine(
        network: StoredMachineNetworkConfig,
    ) -> (tempfile::TempDir, Runtime, Machine, MachineId) {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let paths = LocalPaths::new(temp.path().join("data"));
        let runtime = Runtime::open(paths.clone(), RuntimeNetworkingConfig::default())
            .await
            .expect("open runtime");
        let id = MachineId::new();
        let lock = runtime.allocate_machine_lock().expect("allocate lock");
        let config = MachineConfig {
            id,
            lock_id: lock.id(),
            name: "logs-test".to_string(),
            spec: VmSpec::current(),
            guest: crate::machine::MachineGuestConfig::default(),
            machine_dir: paths.machine(id).machine_data_dir().to_path_buf(),
            created_at: 1,
            modified_at: 1,
            image_ref: "test-image".to_string(),
            root_disk_size: None,
            labels: BTreeMap::new(),
            metadata: BTreeMap::new(),
            network,
        };
        runtime
            .add_machine_record(
                &config,
                &MachineState {
                    machine_id: id,
                    status: MachineRuntimeState::Stopped,
                    vmmon_pid: None,
                    started_at: None,
                    run_id: None,
                    last_error: None,
                    updated_at: 1,
                },
            )
            .await
            .expect("seed machine");
        (temp, runtime.clone(), Machine::new(runtime, id), id)
    }

    fn write_log(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().expect("log parent")).expect("create log parent");
        for directory in path.ancestors().skip(1).take(4) {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure log directory");
        }
        std::fs::write(path, bytes).expect("write log");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("secure log");
    }

    fn spawn_producer() -> Child {
        Command::new("sh")
            .args(["-c", "while :; do sleep 1; done"])
            .spawn()
            .expect("spawn producer")
    }

    async fn set_running(runtime: &Runtime, id: MachineId, child: &Child, run_id: &str) {
        let pid = i32::try_from(child.id()).expect("child pid fits in i32");
        let started_at = crate::vmmon::process::ProcessIdentity::for_pid(pid)
            .expect("read process identity")
            .and_then(|identity| identity.started_at());
        runtime
            .set_machine_state(
                id,
                MachineRuntimeState::Running,
                Some(pid),
                started_at,
                Some(run_id.to_string()),
                None,
            )
            .await
            .expect("mark machine running");
    }

    async fn stop_child(child: &mut Child) {
        child.kill().expect("stop producer");
        child.wait().expect("reap producer");
    }

    async fn collect(mut stream: crate::MachineLogStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("read log chunk");
            assert_eq!(chunk.output, crate::MachineLogOutput::Stdout);
            bytes.extend_from_slice(&chunk.data);
        }
        bytes
    }

    async fn read_bytes(stream: &mut crate::MachineLogStream, length: usize) -> Vec<u8> {
        timeout(Duration::from_secs(2), async {
            let mut bytes = Vec::new();
            while bytes.len() < length {
                let chunk = stream
                    .next()
                    .await
                    .expect("follow stream remains open")
                    .expect("read log chunk");
                bytes.extend_from_slice(&chunk.data);
            }
            bytes
        })
        .await
        .expect("receive followed log bytes")
    }

    #[tokio::test]
    async fn snapshot_returns_exact_bytes_and_stopped_missing_log_is_empty() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).vm_trace_log_path();
        write_log(&path, b"first\0line\n");

        let snapshot = collect(
            machine
                .logs(MachineLogSource::Monitor, MachineLogOptions::default())
                .await
                .expect("open snapshot"),
        )
        .await;
        assert_eq!(snapshot, b"first\0line\n");

        let network_path = runtime.machine_paths(id).network_service_log_path();
        write_log(&network_path, b"network\n");
        let network = collect(
            machine
                .logs(MachineLogSource::Network, MachineLogOptions::default())
                .await
                .expect("open network snapshot"),
        )
        .await;
        assert_eq!(network, b"network\n");

        let audit_path = runtime.machine_paths(id).network_audit_log_path();
        write_log(&audit_path, b"{\"event\":\"audit\"}\n");
        let audit = collect(
            machine
                .logs(MachineLogSource::NetworkAudit, MachineLogOptions::default())
                .await
                .expect("open network audit snapshot"),
        )
        .await;
        assert_eq!(audit, b"{\"event\":\"audit\"}\n");

        std::fs::remove_file(&path).expect("remove log");
        let missing = collect(
            machine
                .logs(MachineLogSource::Monitor, MachineLogOptions::default())
                .await
                .expect("open missing snapshot"),
        )
        .await;
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn missing_log_snapshot_does_not_create_the_log_tree() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let log_dir = runtime.machine_paths(id).machine_logs_dir().to_path_buf();
        assert!(!log_dir.exists());

        let snapshot = collect(
            machine
                .logs(MachineLogSource::Monitor, MachineLogOptions::default())
                .await
                .expect("open missing snapshot"),
        )
        .await;

        assert!(snapshot.is_empty());
        assert!(!log_dir.exists());
    }

    #[tokio::test]
    async fn follow_waits_for_initial_file_then_reads_it() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).serial_log_path();
        let mut stream = machine
            .logs(MachineLogSource::Serial, MachineLogOptions { follow: true })
            .await
            .expect("open follow stream");

        assert!(timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err());
        write_log(&path, b"created later");

        let bytes = read_bytes(&mut stream, b"created later".len()).await;
        assert_eq!(bytes, b"created later");
    }

    #[tokio::test]
    async fn follow_has_no_snapshot_to_append_gap() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).vm_trace_log_path();
        write_log(&path, b"before-");

        let mut stream = machine
            .logs(
                MachineLogSource::Monitor,
                MachineLogOptions { follow: true },
            )
            .await
            .expect("open follow stream");
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open append log")
            .write_all(b"after")
            .expect("append log");

        let bytes = read_bytes(&mut stream, b"before-after".len()).await;
        assert_eq!(bytes, b"before-after");
    }

    #[tokio::test]
    async fn exec_snapshot_reads_archives_before_the_active_log() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let paths = runtime.machine_paths(id);
        write_log(&paths.exec_log_archive_path(3), b"three\n");
        write_log(&paths.exec_log_archive_path(2), b"two\n");
        write_log(&paths.exec_log_archive_path(1), b"one\n");
        write_log(&paths.exec_log_path(), b"active\n");

        let snapshot = collect(
            machine
                .logs(MachineLogSource::Exec, MachineLogOptions::default())
                .await
                .expect("open exec snapshot"),
        )
        .await;

        assert_eq!(snapshot, b"three\ntwo\none\nactive\n");
    }

    #[tokio::test]
    async fn exec_follow_switches_to_a_rotated_active_file() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).exec_log_path();
        write_log(&path, b"old\n");
        let mut stream = machine
            .logs(MachineLogSource::Exec, MachineLogOptions { follow: true })
            .await
            .expect("open exec follow stream");

        assert_eq!(read_bytes(&mut stream, b"old\n".len()).await, b"old\n");
        std::fs::rename(&path, path.with_extension("log.1")).expect("rotate exec log");
        write_log(&path, b"new\n");

        assert_eq!(read_bytes(&mut stream, b"new\n".len()).await, b"new\n");
    }

    #[tokio::test]
    async fn exec_follow_drains_bytes_appended_immediately_before_rotation() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).exec_log_path();
        write_log(&path, b"old\n");
        let mut stream = machine
            .logs(MachineLogSource::Exec, MachineLogOptions { follow: true })
            .await
            .expect("open exec follow stream");
        assert_eq!(read_bytes(&mut stream, b"old\n".len()).await, b"old\n");
        assert!(timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err());

        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open old active log")
            .write_all(b"late\n")
            .expect("append before rotation");
        std::fs::rename(&path, path.with_extension("log.1")).expect("rotate exec log");
        write_log(&path, b"new\n");

        assert_eq!(
            read_bytes(&mut stream, b"late\nnew\n".len()).await,
            b"late\nnew\n"
        );
    }

    #[tokio::test]
    async fn exec_follow_reads_intermediate_archives_after_multiple_rotations() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let paths = runtime.machine_paths(id);
        let active = paths.exec_log_path();
        write_log(&active, b"a\n");
        let mut stream = machine
            .logs(MachineLogSource::Exec, MachineLogOptions { follow: true })
            .await
            .expect("open exec follow stream");
        assert_eq!(read_bytes(&mut stream, 2).await, b"a\n");
        assert!(timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err());

        std::fs::rename(&active, paths.exec_log_archive_path(1)).expect("first rotation");
        write_log(&active, b"b\n");
        std::fs::rename(
            paths.exec_log_archive_path(1),
            paths.exec_log_archive_path(2),
        )
        .expect("shift first archive");
        std::fs::rename(&active, paths.exec_log_archive_path(1)).expect("second rotation");
        write_log(&active, b"c\n");

        assert_eq!(read_bytes(&mut stream, 4).await, b"b\nc\n");
    }

    #[tokio::test]
    async fn exec_follow_discovers_archives_created_before_the_active_log() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let paths = runtime.machine_paths(id);
        let mut stream = machine
            .logs(MachineLogSource::Exec, MachineLogOptions { follow: true })
            .await
            .expect("open missing exec follow stream");
        assert!(timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err());

        write_log(&paths.exec_log_archive_path(2), b"two\n");
        write_log(&paths.exec_log_archive_path(1), b"one\n");
        write_log(&paths.exec_log_path(), b"active\n");

        assert_eq!(
            read_bytes(&mut stream, b"two\none\nactive\n".len()).await,
            b"two\none\nactive\n"
        );
    }

    #[tokio::test]
    async fn follow_continues_across_a_replacement_generation() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).vm_trace_log_path();
        write_log(&path, b"old");
        let mut old = spawn_producer();
        set_running(&runtime, id, &old, "old-run").await;
        let mut stream = machine
            .logs(
                MachineLogSource::Monitor,
                MachineLogOptions { follow: true },
            )
            .await
            .expect("open follow stream");

        assert_eq!(read_bytes(&mut stream, b"old".len()).await, b"old");
        stop_child(&mut old).await;
        runtime
            .set_machine_state(id, MachineRuntimeState::Stopped, None, None, None, None)
            .await
            .expect("mark machine stopped");
        assert!(timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err());

        let mut replacement = spawn_producer();
        set_running(&runtime, id, &replacement, "replacement-run").await;
        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open replacement log")
            .write_all(b"new")
            .expect("append replacement log");
        assert_eq!(read_bytes(&mut stream, b"new".len()).await, b"new");
        stop_child(&mut replacement).await;
    }

    #[tokio::test]
    async fn follow_stops_polling_when_the_reader_is_dropped() {
        let temp = tempfile::tempdir().expect("create temporary directory");
        let paths = LocalPaths::new(temp.path().join("data"));
        let (sender, receiver) = mpsc::channel(LOG_STREAM_BUFFER);
        drop(receiver);

        timeout(
            Duration::from_secs(2),
            stream_log(
                paths,
                MachineId::new(),
                MachineLogSource::Monitor,
                None,
                true,
                sender,
            ),
        )
        .await
        .expect("follow task observes reader cancellation")
        .expect("follow task exits cleanly");
    }

    #[tokio::test]
    async fn unsafe_log_objects_are_rejected() {
        let (_temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let path = runtime.machine_paths(id).vm_trace_log_path();
        std::fs::create_dir_all(path.parent().expect("log parent")).expect("create log parent");

        std::fs::write(&path, b"unsafe").expect("write permissive log");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make log permissive");
        assert!(machine
            .logs(MachineLogSource::Monitor, MachineLogOptions::default())
            .await
            .is_err());
        std::fs::remove_file(&path).expect("remove permissive log");

        let target = path.with_extension("target");
        write_log(&target, b"target");
        symlink(&target, &path).expect("create log symlink");
        assert!(machine
            .logs(MachineLogSource::Monitor, MachineLogOptions::default())
            .await
            .is_err());
        std::fs::remove_file(&path).expect("remove log symlink");

        std::fs::create_dir(&path).expect("create directory log");
        assert!(machine
            .logs(MachineLogSource::Monitor, MachineLogOptions::default())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn log_directory_symlinks_are_rejected_without_following_them() {
        let (temp, runtime, machine, id) =
            test_machine(StoredMachineNetworkConfig::Private { policy: None }).await;
        let state_root = runtime.local_paths().roots().state_root().to_path_buf();
        let external = temp.path().join("external");
        std::fs::create_dir(&external).expect("create external directory");
        std::fs::write(external.join("keep"), b"safe").expect("write external sentinel");

        std::fs::create_dir_all(&state_root).expect("create state root");
        std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o700))
            .expect("secure state root");
        symlink(&external, state_root.join("logs")).expect("create logs symlink");
        assert!(machine
            .logs(MachineLogSource::Monitor, MachineLogOptions::default())
            .await
            .is_err());
        std::fs::remove_file(state_root.join("logs")).expect("remove logs symlink");

        let machine_parent = state_root.join("logs/machines");
        std::fs::create_dir_all(&machine_parent).expect("create log machine parent");
        for directory in [state_root.join("logs"), machine_parent.clone()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .expect("secure log directory");
        }
        symlink(&external, machine_parent.join(id.to_string())).expect("create machine symlink");
        assert!(machine
            .logs(MachineLogSource::Monitor, MachineLogOptions::default())
            .await
            .is_err());
        std::fs::remove_file(machine_parent.join(id.to_string())).expect("remove machine symlink");

        let network_parent = machine_parent.join(id.to_string());
        std::fs::create_dir(&network_parent).expect("create machine log directory");
        std::fs::set_permissions(&network_parent, std::fs::Permissions::from_mode(0o700))
            .expect("secure machine log directory");
        symlink(&external, network_parent.join("network")).expect("create network symlink");
        assert!(machine
            .logs(MachineLogSource::Network, MachineLogOptions::default())
            .await
            .is_err());

        assert_eq!(
            std::fs::read(external.join("keep")).expect("read external sentinel"),
            b"safe"
        );
    }

    #[tokio::test]
    async fn network_sources_require_private_networking() {
        let (_temp, _runtime, machine, _id) = test_machine(StoredMachineNetworkConfig::None).await;

        let error = match machine
            .logs(MachineLogSource::Network, MachineLogOptions::default())
            .await
        {
            Ok(_) => panic!("network source should be unavailable"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            LibVmError::MachineLogSourceUnavailable {
                log_source: MachineLogSource::Network,
                ..
            }
        ));

        let error = match machine
            .logs(MachineLogSource::NetworkAudit, MachineLogOptions::default())
            .await
        {
            Ok(_) => panic!("network audit source should be unavailable"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            LibVmError::MachineLogSourceUnavailable {
                log_source: MachineLogSource::NetworkAudit,
                ..
            }
        ));
    }
}

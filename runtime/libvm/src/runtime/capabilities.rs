//! Machine-less discovery and the exact selection shared with monitor start.
use std::collections::VecDeque;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use vm_spec::live::{
    LiveAvailability, LiveBackend, LiveHostReport, LiveOperation, LiveReasonCode,
    LiveUnsupportedReason,
};

use crate::runtime::{RuntimeConfig, VirtBackendOverride};
use crate::LibVmError;

const SCENARIO_LIMIT: u64 = 1024 * 1024;
const REPORT_LIMIT: u64 = 64 * 1024;
const STDERR_LIMIT: u64 = 8 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_LIMIT: usize = 8;

#[derive(Debug)]
pub struct ResolvedBackendSelection {
    pub(crate) backend: LiveBackend,
    pub(crate) scenario: Option<PathBuf>,
    pub(crate) scenario_json: Option<String>,
    pub(crate) scenario_digest: Option<String>,
}

impl ResolvedBackendSelection {
    pub(crate) fn resolve(
        selection: Option<&VirtBackendOverride>,
    ) -> Result<Arc<Self>, LibVmError> {
        let (backend, scenario) = match selection {
            None | Some(VirtBackendOverride::Krun) => (LiveBackend::Krun, None),
            Some(VirtBackendOverride::Vz) => (LiveBackend::Vz, None),
            Some(VirtBackendOverride::Mock { scenario }) => (LiveBackend::Mock, scenario.clone()),
        };
        let scenario_json = scenario
            .as_ref()
            .map(|path| {
                if !path.is_absolute() {
                    return Err(discovery("scenario path must be absolute"));
                }
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|error| discovery(error.to_string()))?;
                if !file
                    .metadata()
                    .map_err(|error| discovery(error.to_string()))?
                    .is_file()
                {
                    return Err(discovery("scenario must be a regular file"));
                }
                let mut bytes = Vec::new();
                file.take(SCENARIO_LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| discovery(error.to_string()))?;
                if bytes.len() as u64 > SCENARIO_LIMIT {
                    return Err(discovery("scenario exceeds 1 MiB"));
                }
                String::from_utf8(bytes).map_err(|error| discovery(error.to_string()))
            })
            .transpose()?;
        let scenario_digest = scenario_json.as_ref().map(|json| digest(json.as_bytes()));
        Ok(Arc::new(Self {
            backend,
            scenario,
            scenario_json,
            scenario_digest,
        }))
    }

    pub(crate) fn request(&self) -> crate::supervisor::start_request::VmmVirtBackend {
        crate::supervisor::start_request::VmmVirtBackend {
            kind: self.backend.as_str().to_string(),
            scenario: self.scenario.clone(),
            scenario_json: self.scenario_json.clone(),
            scenario_digest: self.scenario_digest.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableStat {
    canonical: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl ExecutableStat {
    fn read(path: &Path) -> Result<Self, LibVmError> {
        let canonical =
            std::fs::canonicalize(path).map_err(|error| discovery(error.to_string()))?;
        let metadata =
            std::fs::metadata(&canonical).map_err(|error| discovery(error.to_string()))?;
        if !metadata.is_file() {
            return Err(discovery("monitor executable is not a regular file"));
        }
        Ok(Self {
            canonical,
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheKey {
    executable: ExecutableStat,
    executable_digest: String,
    boot: String,
    backend: LiveBackend,
    scenario_digest: Option<String>,
}

#[derive(Debug, Default)]
struct QueryCache {
    executable: Option<(ExecutableStat, String)>,
    entries: VecDeque<(CacheKey, LiveHostReport)>,
}

#[derive(Debug, Clone)]
pub struct LiveCapabilityQuery {
    executable: PathBuf,
    selection: Arc<ResolvedBackendSelection>,
    cache: Arc<Mutex<QueryCache>>,
}

impl LiveCapabilityQuery {
    /// Resolves paths/selection only, never installation roots or a store.
    pub fn open(config: &RuntimeConfig) -> Result<Self, LibVmError> {
        let executable = match &config.supervisor_path {
            Some(path) => path.clone(),
            None => config.resolve_components()?.supervisor().to_path_buf(),
        };
        Self::resolved(
            executable,
            ResolvedBackendSelection::resolve(config.virt_backend.as_ref())?,
        )
    }

    pub(crate) fn resolved(
        executable: PathBuf,
        selection: Arc<ResolvedBackendSelection>,
    ) -> Result<Self, LibVmError> {
        if !executable.is_absolute() {
            return Err(discovery("monitor executable path must be absolute"));
        }
        Ok(Self {
            executable,
            selection,
            cache: Arc::new(Mutex::new(QueryCache::default())),
        })
    }

    pub(crate) fn selection(&self) -> &Arc<ResolvedBackendSelection> {
        &self.selection
    }

    pub async fn host_report(&self) -> Result<LiveHostReport, LibVmError> {
        let stat = ExecutableStat::read(&self.executable)?;
        let boot = boot_identity()?;
        let mut cache = self.cache.lock().await;
        if self.selection.scenario.is_some() {
            let current = ResolvedBackendSelection::resolve(Some(&VirtBackendOverride::Mock {
                scenario: self.selection.scenario.clone(),
            }))?;
            if current.scenario_digest != self.selection.scenario_digest {
                return Err(discovery(
                    "scenario changed after backend selection was resolved",
                ));
            }
        }
        let executable_digest = match &cache.executable {
            Some((known, digest)) if known == &stat => digest.clone(),
            _ => {
                let value = executable_digest(&stat.canonical).await?;
                if ExecutableStat::read(&self.executable)? != stat {
                    return Err(discovery("monitor executable changed while hashing"));
                }
                cache.executable = Some((stat.clone(), value.clone()));
                value
            }
        };
        let key = CacheKey {
            executable: stat.clone(),
            executable_digest,
            boot,
            backend: self.selection.backend,
            scenario_digest: self.selection.scenario_digest.clone(),
        };
        if let Some((_, report)) = cache
            .entries
            .iter()
            .find(|(candidate, _)| candidate == &key)
        {
            return Ok(report.clone());
        }
        let report = query_process(&self.executable, &self.selection).await?;
        if ExecutableStat::read(&self.executable)? != stat {
            return Err(discovery(
                "monitor executable changed during capability query",
            ));
        }
        report.validate().map_err(protocol)?;
        if report.backend != self.selection.backend
            || report.scenario_digest != self.selection.scenario_digest
        {
            return Err(protocol(
                "capability report does not match exact backend/scenario selection",
            ));
        }
        // Runtime host admission can change within one boot. Never cache a
        // positive report; only immutable product exclusions are reusable.
        if LiveOperation::ALL.iter().all(|operation| matches!(report.live.get(*operation).availability,
            LiveAvailability::Unsupported { ref reason } if matches!(reason.code, LiveReasonCode::NotDelivered | LiveReasonCode::BackendExcluded))) {
            if cache.entries.len() == CACHE_LIMIT { cache.entries.pop_front(); }
            cache.entries.push_back((key, report.clone()));
        }
        Ok(report)
    }
}

async fn executable_digest(path: &Path) -> Result<String, LibVmError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| discovery(error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16384];
    loop {
        let count = file
            .read(&mut buffer)
            .await
            .map_err(|error| discovery(error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn boot_identity() -> Result<String, LibVmError> {
    #[cfg(target_os = "linux")]
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| discovery(error.to_string()))?;
    #[cfg(target_os = "macos")]
    let value = {
        // nix has no sysctlbyname wrapper. Read the kernel's actual boot UUID,
        // not a wall-clock-derived approximation or process/guest identity.
        let mut bytes = [0u8; 128];
        let mut length = bytes.len();
        let result = unsafe {
            nix::libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return Err(discovery(std::io::Error::last_os_error().to_string()));
        }
        String::from_utf8(
            bytes
                .get(..length)
                .ok_or_else(|| discovery("boot identity too long"))?
                .to_vec(),
        )
        .map_err(|error| discovery(error.to_string()))?
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(discovery(
        "host boot identity is unavailable on this platform",
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let value = value.trim_matches(['\0', '\n', '\r', ' ']);
        let id = uuid::Uuid::parse_str(value).map_err(|error| discovery(error.to_string()))?;
        if id.is_nil() {
            return Err(discovery("host boot identity is nil"));
        }
        Ok(id.to_string())
    }
}

async fn query_process(
    executable: &Path,
    selection: &ResolvedBackendSelection,
) -> Result<LiveHostReport, LibVmError> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args([
            "capabilities",
            "--backend",
            selection.backend.as_str(),
            "--json",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(path) = &selection.scenario {
        command.arg("--scenario").arg(path);
    }
    let child = command
        .spawn()
        .map_err(|error| discovery(error.to_string()))?;
    let (stdout, stderr, status) = collect_child(child).await?;
    if !status.success() {
        return Err(discovery(format!(
            "capability query exited {status}: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    serde_json::from_slice(&stdout).map_err(|error| protocol(error.to_string()))
}

async fn collect_child(
    mut child: tokio::process::Child,
) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus), LibVmError> {
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(discovery("monitor output pipes unavailable"));
    };
    let (mut sender, receiver) = tokio::sync::oneshot::channel();
    // This task owns the child even when the calling future is cancelled. It
    // kills AND waits, rather than relying on kill_on_drop's eventual reaper.
    tokio::spawn(async move {
        let result = tokio::select! {
            _ = sender.closed() => None,
            result = tokio::time::timeout(QUERY_TIMEOUT, async {
                tokio::try_join!(bounded_read(stdout, REPORT_LIMIT), bounded_read(stderr, STDERR_LIMIT), async {
                    child.wait().await.map_err(|error| discovery(error.to_string()))
                })
            }) => Some(match result {
                Ok(result) => result,
                Err(_) => Err(discovery("capability query exceeded five-second deadline")),
            }),
        };
        if result.as_ref().is_none_or(|result| result.is_err()) {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(result) = result {
            let _ = sender.send(result);
        }
    });
    receiver
        .await
        .map_err(|_| discovery("capability query worker stopped"))?
}

async fn bounded_read(
    reader: impl tokio::io::AsyncRead + Unpin,
    limit: u64,
) -> Result<Vec<u8>, LibVmError> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| discovery(error.to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(discovery("capability query output exceeded bound"));
    }
    Ok(bytes)
}

pub fn require_host_live_operation(
    report: &LiveHostReport,
    operation: LiveOperation,
) -> Result<(), LibVmError> {
    report.validate().map_err(protocol)?;
    let reason = match &report.live.get(operation).availability {
        LiveAvailability::Unsupported { reason } => reason.clone(),
        LiveAvailability::Supported => LiveUnsupportedReason::new(LiveReasonCode::NotDelivered),
    };
    Err(LibVmError::LiveOperationUnsupported {
        operation,
        backend: report.backend,
        lane: report.lane,
        reason,
    })
}

fn discovery(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveDiscovery {
        message: message.into(),
    }
}
fn protocol(message: impl Into<String>) -> LibVmError {
    LibVmError::LiveProtocol {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::capabilities::{bounded_read, collect_child, ResolvedBackendSelection};
    use crate::runtime::VirtBackendOverride;
    use std::future::Future;
    use vm_spec::live::LiveBackend;

    #[test]
    fn live_capabilities_scenario_selection_is_exact_and_missing_never_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scenario");
        assert!(
            ResolvedBackendSelection::resolve(Some(&VirtBackendOverride::Mock {
                scenario: Some(path.clone())
            }))
            .is_err()
        );
        std::fs::write(&path, b"{}\n").unwrap();
        let first = ResolvedBackendSelection::resolve(Some(&VirtBackendOverride::Mock {
            scenario: Some(path.clone()),
        }))
        .unwrap();
        std::fs::write(&path, b"{}").unwrap();
        let second = ResolvedBackendSelection::resolve(Some(&VirtBackendOverride::Mock {
            scenario: Some(path),
        }))
        .unwrap();
        assert_ne!(first.scenario_digest, second.scenario_digest);
        assert_eq!(first.request().scenario_json.as_deref(), Some("{}\n"));
        assert_eq!(first.request().scenario_digest, first.scenario_digest);
        assert_eq!(
            ResolvedBackendSelection::resolve(None).unwrap().backend,
            LiveBackend::Krun
        );
        assert!(
            ResolvedBackendSelection::resolve(Some(&VirtBackendOverride::Mock { scenario: None }))
                .unwrap()
                .scenario_digest
                .is_none()
        );
    }

    #[tokio::test]
    async fn live_capabilities_output_bound_is_enforced_before_accumulation() {
        assert_eq!(bounded_read(&b"four"[..], 4).await.unwrap(), b"four");
        assert!(bounded_read(&b"five!"[..], 4).await.is_err());
        assert!(bounded_read(&b""[..], 0).await.unwrap().is_empty());
    }

    async fn stopped_real_query() -> (tokio::process::Child, nix::unistd::Pid) {
        use nix::sys::signal::{kill, Signal};
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        // Stop the actual scenario-capable monitor, not a script that invents
        // reports. Retry only if the real query completed before SIGSTOP won.
        for _ in 0..8 {
            let mut child = tokio::process::Command::new(test_utils::mock_vmm_binary())
                .args(["capabilities", "--backend", "mock", "--json"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let pid = nix::unistd::Pid::from_raw(child.id().unwrap() as i32);
            if kill(pid, Signal::SIGSTOP).is_ok()
                && matches!(
                    waitpid(pid, Some(WaitPidFlag::WUNTRACED)),
                    Ok(WaitStatus::Stopped(_, Signal::SIGSTOP))
                )
            {
                return (child, pid);
            }
            let _ = child.wait().await;
        }
        panic!("real query repeatedly completed before process stop");
    }

    async fn assert_reaped(pid: nix::unistd::Pid) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match nix::sys::signal::kill(pid, None) {
                Err(nix::errno::Errno::ESRCH) => return,
                Ok(()) => {}
                result => panic!("unexpected process probe: {result:?}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "query child was not reaped"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn live_capabilities_query_deadline_kills_and_reaps_real_monitor() {
        let (child, pid) = stopped_real_query().await;
        assert!(matches!(
            collect_child(child).await,
            Err(crate::LibVmError::LiveDiscovery { .. })
        ));
        assert_reaped(pid).await;
    }

    #[tokio::test]
    async fn live_capabilities_cancelled_query_kills_and_reaps_real_monitor() {
        let (child, pid) = stopped_real_query().await;
        let mut collecting = Box::pin(collect_child(child));
        // One explicit poll establishes the child-owning worker and receiver.
        // Dropping that receiver is cancellation, without scheduling guesses.
        assert!(
            std::future::poll_fn(|context| {
                std::task::Poll::Ready(collecting.as_mut().poll(context).is_pending())
            })
            .await
        );
        drop(collecting);
        assert_reaped(pid).await;
    }
}

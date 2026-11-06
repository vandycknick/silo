//! Backend contract and selection.
//!
//! Each virtualization backend implements [`VirtBackend`]; everything above
//! this module (the [`crate::virt::VirtualMachine`] handle, the serial console)
//! works purely against the trait. [`create_backend`] is the single
//! cfg-aware construction point — no other code in the module branches on
//! target platform or features.
//!
//! # Backend contract
//!
//! - `start` boots at most once; a second call fails with `AlreadyRunning`.
//! - `stop` is idempotent; before `start` it permanently cancels the instance.
//! - The exit status is cached: `wait`/`try_wait` after the machine exits (or
//!   after `stop`) resolve immediately and never hang.
//! - `open_serial` is called exactly once per boot, by the serial console.
//! - `lifecycle` is the finite native pause/resume seam. Accepted native work
//!   outlives a dropped caller; backends without a native pause authority
//!   refuse every request as `Unsupported`.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::virt::capacity::{VsockLease, VsockListenerAdmission};
use crate::virt::config::VmConfig;
use crate::virt::error::VirtError;
use crate::virt::stream::{SerialDevice, VsockListener, VsockStream};
use crate::virt::VmExit;

mod krun;
pub(crate) mod lifecycle;
#[cfg(feature = "mock-backend")]
pub(crate) mod mock;
pub(crate) mod storage;
#[cfg(target_os = "macos")]
mod vz;

/// A single virtual machine instance owned by one backend implementation.
///
/// Methods take `&self`: the backend is shared behind an `Arc` by clone-able
/// machine handles and the serial console, so implementations keep their
/// state behind interior mutability.
#[async_trait]
pub(crate) trait VirtBackend: Send + Sync + fmt::Debug + 'static {
    /// Boot the machine. Fails with [`VirtError::AlreadyRunning`] once started.
    async fn start(&self) -> Result<(), VirtError>;

    /// Stop the machine (graceful where supported, then hard). Idempotent.
    async fn stop(&self) -> Result<(), VirtError>;

    /// Escalate a supervised stop without abandoning backend ownership.
    async fn force_stop(&self) -> Result<(), VirtError> {
        self.stop().await
    }

    /// Block until the machine exits; resolves immediately once exited.
    async fn wait(&self) -> Result<VmExit, VirtError>;

    /// Non-blocking exit check.
    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError>;

    /// Includes observed death while the immutable terminal report is draining.
    async fn is_terminated(&self) -> Result<bool, VirtError> {
        Ok(self.try_wait().await?.is_some())
    }

    /// Finalize retained storage only after every native owner is terminal.
    async fn finalize_storage(
        &self,
        _guest_protocol_completed: bool,
    ) -> Result<StorageFinalization, VirtError> {
        Ok(StorageFinalization::default())
    }

    /// Dynamically connect to a guest endpoint port, consuming its admission lease.
    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError>;

    /// Dynamically register a host endpoint port for guest-initiated connections.
    async fn listen_vsock(
        &self,
        port: u32,
        admission: VsockListenerAdmission,
    ) -> Result<VsockListener, VirtError>;

    /// Whether console resources exist before native startup can execute guest code.
    fn serial_available_before_start(&self) -> bool {
        false
    }

    /// Open the guest serial device. Called once per boot by the serial console.
    async fn open_serial(&self) -> Result<SerialDevice, VirtError>;

    /// Live host memory reclaim reports, for backends that can observe them.
    /// The value is `None` until the first report of the current boot.
    fn host_memory_reclaim_updates(
        &self,
    ) -> Option<watch::Receiver<Option<HostMemoryReclaimReport>>> {
        None
    }

    /// Owned duplicates of the run's retained disk attachments, the held
    /// sources a live capture clones or copies without re-resolving any
    /// pathname. Backends without retained attachments cannot capture.
    async fn capture_sources(&self) -> Result<Vec<CaptureSource>, VirtError> {
        Err(VirtError::Backend(
            "this backend retains no capture sources".into(),
        ))
    }

    /// The finite native lifecycle seam. Backends without a native pause
    /// authority refuse every request, including observation, as Unsupported.
    /// `rights` is the command's fixed descriptor set (`None` for most).
    async fn lifecycle(
        &self,
        request: crate::virt::lifecycle::LifecycleRequest,
        rights: crate::virt::lifecycle::LifecycleRights,
    ) -> Result<crate::virt::lifecycle::LifecycleResponse, crate::virt::lifecycle::LifecycleError>;

    /// Permanently close native mutator submission, synchronously: once this
    /// returns no new lifecycle mutator can reach the worker, while
    /// observation and replays of already admitted commands stay available.
    /// Backends without a native lifecycle seam have nothing to close.
    fn close_lifecycle_admission(&self) {}
}

/// Independently observed host storage facts, never inferred from exit status.
#[derive(Debug, Clone, Default)]
pub struct StorageFinalization {
    pub host_writes_flushed: bool,
    pub attachments_closed: bool,
    pub error: Option<String>,
}

/// One retained disk attachment, duplicated for a capture's disk seal.
#[derive(Debug)]
pub(crate) struct CaptureSource {
    pub(crate) disk_index: u32,
    pub(crate) file: std::fs::File,
    pub(crate) writable: bool,
}

/// A single launch attempt, including failures before a VM exists.
#[derive(Debug, Default)]
pub(crate) struct StartAttempt(std::sync::atomic::AtomicBool);

impl StartAttempt {
    pub(crate) fn reserve(&self) -> bool {
        !self.0.swap(true, std::sync::atomic::Ordering::AcqRel)
    }

    pub(crate) fn close(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// Host memory reclaim state of the running VM as last reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMemoryReclaimReport {
    /// `boot` or `restored-private`.
    pub backing: &'static str,
    /// `none`, `tracked-capture`, or `restored-private-mapping`.
    pub reason: &'static str,
    pub requested: bool,
    /// `not-run`, `passed`, `failed`, or `inconclusive`.
    pub qualification: &'static str,
    pub effective: bool,
    /// Process-local successfully advised bytes/ranges, including repeats.
    pub released_bytes: u64,
    pub released_extents: u64,
    pub retried_faults: u64,
    /// Skipped operations, not a universal count of queue heads or pages.
    pub skipped_reports: u64,
    pub failed_operations: u64,
    pub observed_at: SystemTime,
}

/// Identifies a virtualization backend implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendKind {
    /// libkrun in a private worker process launched from silo-vmm.
    Krun,
    /// Apple Virtualization.framework (macOS).
    Vz,
    /// In-process fake for tests; serves the guest side itself.
    #[cfg(feature = "mock-backend")]
    Mock,
}

impl BackendKind {
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::Krun => "krun",
            BackendKind::Vz => "vz",
            #[cfg(feature = "mock-backend")]
            BackendKind::Mock => "mock",
        }
    }

    /// Backends compiled into this binary (target- and feature-dependent).
    pub fn compiled() -> &'static [BackendKind] {
        &[
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            BackendKind::Krun,
            #[cfg(target_os = "macos")]
            BackendKind::Vz,
            #[cfg(feature = "mock-backend")]
            BackendKind::Mock,
        ]
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Construct the requested backend. The single cfg-aware dispatch point.
pub(crate) fn create_backend(
    kind: BackendKind,
    config: VmConfig,
) -> Result<Arc<dyn VirtBackend>, VirtError> {
    if config.restore().is_some() && kind != BackendKind::Krun {
        return Err(VirtError::InvalidConfig {
            name: config.name().to_string(),
            reason: "execution restore requires the krun backend".to_string(),
        });
    }
    storage::publish_holders(&config, None)?;
    match kind {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        BackendKind::Krun => Ok(Arc::new(krun::KrunBackend::new(config)?)),
        #[cfg(target_os = "macos")]
        BackendKind::Vz => Ok(Arc::new(vz::VzBackend::new(config)?)),
        #[cfg(feature = "mock-backend")]
        BackendKind::Mock => Ok(Arc::new(mock::MockBackend::new(config)?)),
        #[allow(unreachable_patterns)]
        other => Err(VirtError::UnsupportedBackend {
            kind: other.name(),
            reason: "backend is not compiled into this binary".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use crate::virt::backend::StartAttempt;

    #[test]
    fn attempts_are_terminal_even_before_a_vm_exists() {
        let attempt = StartAttempt::default();
        assert!(attempt.reserve());
        assert!(!attempt.reserve());
        attempt.close();
        assert!(!attempt.reserve());
        let cancelled = StartAttempt::default();
        cancelled.close();
        assert!(!cancelled.reserve());
    }

    #[test]
    fn concurrent_attempts_have_one_winner() {
        let attempt = StartAttempt::default();
        std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| usize::from(attempt.reserve())))
                .collect();
            assert_eq!(
                tasks
                    .into_iter()
                    .map(|task| task.join().expect("join reservation"))
                    .sum::<usize>(),
                1
            );
        });
    }
}

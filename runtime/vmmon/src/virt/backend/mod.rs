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
//! - `stop` is idempotent and safe before `start`.
//! - The exit status is cached: `wait`/`try_wait` after the machine exits (or
//!   after `stop`) resolve immediately and never hang.
//! - `open_serial` is called exactly once per boot, by the serial console.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::virt::capacity::{VsockLease, VsockListenerAdmission};
use crate::virt::config::VmConfig;
use crate::virt::error::VirtError;
use crate::virt::stream::{SerialDevice, VsockListener, VsockStream};
use crate::virt::VmExit;

#[cfg(target_os = "linux")]
mod krun;
#[cfg(feature = "mock-backend")]
pub(crate) mod mock;
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

    /// Block until the machine exits; resolves immediately once exited.
    async fn wait(&self) -> Result<VmExit, VirtError>;

    /// Non-blocking exit check.
    async fn try_wait(&self) -> Result<Option<VmExit>, VirtError>;

    /// Dynamically connect to a guest endpoint port, consuming its admission lease.
    async fn connect_vsock(&self, port: u32, lease: VsockLease) -> Result<VsockStream, VirtError>;

    /// Dynamically register a host endpoint port for guest-initiated connections.
    async fn listen_vsock(
        &self,
        port: u32,
        admission: VsockListenerAdmission,
    ) -> Result<VsockListener, VirtError>;

    /// Open the guest serial device. Called once per boot by the serial console.
    async fn open_serial(&self) -> Result<SerialDevice, VirtError>;
}

/// Identifies a virtualization backend implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendKind {
    /// libkrun via the spawned `krun` helper binary (Linux).
    Krun,
    /// Apple Virtualization.framework (macOS).
    Vz,
    /// In-process fake for tests; serves the guest side itself.
    #[cfg(feature = "mock-backend")]
    Mock,
}

/// Result of probing whether a backend can run on this host.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Availability {
    Available,
    Unavailable { reason: String },
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
            #[cfg(target_os = "linux")]
            BackendKind::Krun,
            #[cfg(target_os = "macos")]
            BackendKind::Vz,
            #[cfg(feature = "mock-backend")]
            BackendKind::Mock,
        ]
    }

    /// Cheap host probe: can this backend plausibly start a machine here?
    ///
    /// Per-machine requirements (helper binary path, rosetta installation)
    /// are still validated at machine construction; this only answers whether
    /// the backend is present on this host at all.
    pub fn probe(self) -> Availability {
        if Self::compiled().contains(&self) {
            Availability::Available
        } else {
            Availability::Unavailable {
                reason: format!("backend {} is not compiled into this binary", self.name()),
            }
        }
    }

    /// Today's pinned selection policy: krun on Linux, vz on macOS.
    ///
    /// A future user-facing backend picker replaces callers of this with
    /// "user preference, validated against `compiled()` + `probe()`".
    pub fn default_for_host() -> Result<BackendKind, VirtError> {
        #[cfg(target_os = "linux")]
        {
            Ok(BackendKind::Krun)
        }

        #[cfg(target_os = "macos")]
        {
            Ok(BackendKind::Vz)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(VirtError::UnsupportedBackend {
                kind: "none",
                reason: "no virtualization backend is available for this host platform".to_string(),
            })
        }
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
    match kind {
        #[cfg(target_os = "linux")]
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
    use super::*;

    #[test]
    fn default_backend_matches_platform() {
        let kind = BackendKind::default_for_host().expect("host platform should be supported");
        #[cfg(target_os = "linux")]
        assert_eq!(kind, BackendKind::Krun);
        #[cfg(target_os = "macos")]
        assert_eq!(kind, BackendKind::Vz);
    }

    #[test]
    fn compiled_backends_probe_available() {
        for kind in BackendKind::compiled() {
            assert!(matches!(kind.probe(), Availability::Available));
        }
    }
}

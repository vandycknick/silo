use std::sync::Arc;

use crate::types::{VirtError, VmConfig};

#[cfg(target_os = "linux")]
pub(crate) type VmBackend = crate::krun::KrunMachineBackend;
#[cfg(target_os = "macos")]
pub(crate) type VmBackend = crate::vz::VzMachineBackend;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
pub(crate) struct VmBackend;

pub(crate) fn create_backend(config: VmConfig) -> Result<Arc<VmBackend>, VirtError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Arc::new(crate::vz::VzMachineBackend::new(config)?))
    }

    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(crate::krun::KrunMachineBackend::new(config)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = config;
        Err(VirtError::UnsupportedBackend {
            kind: "none",
            reason: "no machine backend is available for this host platform".to_string(),
        })
    }
}

use std::path::PathBuf;

use objc2::{rc::Retained, AllocAnyThread, ClassType};
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
};

use crate::error::VzError;

#[derive(Debug, Clone)]
pub struct StorageDeviceConfiguration {
    inner: Retained<VZVirtioBlockDeviceConfiguration>,
}

impl StorageDeviceConfiguration {
    pub fn new(path: PathBuf, read_only: bool) -> Result<Self, VzError> {
        if !path.is_file() {
            return Err(VzError::InvalidConfiguration {
                reason: format!("disk image path is not a file: {}", path.display()),
            });
        }

        unsafe {
            let disk_path = NSString::from_str(&path.to_string_lossy());
            let disk_url = NSURL::initFileURLWithPath(NSURL::alloc(), &disk_path);
            let attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &disk_url,
                read_only,
                VZDiskImageCachingMode::Cached,
                VZDiskImageSynchronizationMode::Full,
            )
            .map_err(|err| VzError::Backend(format!("failed to initialize disk image attachment {}: {err}", path.display())))?;

            Ok(Self {
                inner: VZVirtioBlockDeviceConfiguration::initWithAttachment(
                    VZVirtioBlockDeviceConfiguration::alloc(),
                    &attachment,
                ),
            })
        }
    }

    pub(crate) fn as_inner(&self) -> &VZStorageDeviceConfiguration {
        self.inner.as_super()
    }
}

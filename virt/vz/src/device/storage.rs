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
    /// Creates a disk with the supplied guest-visible virtio block identifier.
    ///
    /// Identifiers must be ASCII and at most 20 bytes, and must pass Apple's
    /// identifier validator. Requires macOS 12.3 or later.
    pub fn new(path: PathBuf, read_only: bool, block_id: &str) -> Result<Self, VzError> {
        validate_block_identifier(block_id)?;
        if !path.is_file() {
            return Err(VzError::InvalidConfiguration {
                reason: format!("disk image path is not a file: {}", path.display()),
            });
        }

        unsafe {
            let identifier = NSString::from_str(block_id);
            // Apple documents invalid setter input as a fatal error. Ask the
            // framework to validate it before creating or configuring the device.
            VZVirtioBlockDeviceConfiguration::validateBlockDeviceIdentifier_error(&identifier)
                .map_err(|error| VzError::InvalidConfiguration {
                    reason: format!("invalid virtio block identifier: {error}"),
                })?;
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

            let inner = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &attachment,
            );
            inner.setBlockDeviceIdentifier(&identifier);
            Ok(Self { inner })
        }
    }

    pub(crate) fn as_inner(&self) -> &VZStorageDeviceConfiguration {
        self.inner.as_super()
    }
}

fn validate_block_identifier(block_id: &str) -> Result<(), VzError> {
    if !block_id.is_ascii() || block_id.len() > 20 {
        return Err(VzError::InvalidConfiguration {
            reason: "virtio block identifier must be ASCII and at most 20 bytes".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::device::storage::validate_block_identifier;
    use crate::error::VzError;

    #[test]
    fn accepts_silo_attachment_identifiers() {
        for identifier in ["silo-root", "silo-root-lower", "silo-root-upper", "data-01"] {
            assert!(validate_block_identifier(identifier).is_ok());
        }
    }

    #[test]
    fn accepts_exactly_twenty_ascii_bytes() {
        assert!(validate_block_identifier("12345678901234567890").is_ok());
    }

    #[test]
    fn rejects_more_than_twenty_ascii_bytes() {
        assert!(matches!(
            validate_block_identifier("123456789012345678901"),
            Err(VzError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn rejects_non_ascii_even_within_byte_limit() {
        for identifier in ["é", "root-漢", "123456789012345678é"] {
            assert!(identifier.len() <= 20);
            assert!(matches!(
                validate_block_identifier(identifier),
                Err(VzError::InvalidConfiguration { .. })
            ));
        }
    }

    #[test]
    fn permits_empty_identifier_as_supported_by_apple() {
        // Apple's default is empty; Silo's BlockId enforces its stronger policy.
        assert!(validate_block_identifier("").is_ok());
    }
}

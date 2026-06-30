use std::path::{Path, PathBuf};

use objc2::{rc::Retained, AllocAnyThread, ClassType};
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{
    VZDirectoryShare, VZDirectorySharingDeviceConfiguration, VZLinuxRosettaDirectoryShare,
    VZSharedDirectory, VZSingleDirectoryShare, VZVirtioFileSystemDeviceConfiguration,
};

use crate::error::VzError;

#[derive(Debug, Clone)]
pub struct SharedDirectory {
    inner: Retained<VZSharedDirectory>,
    host_path: PathBuf,
    read_only: bool,
}

impl SharedDirectory {
    pub fn new(host_path: PathBuf, read_only: bool) -> Self {
        let inner = unsafe {
            let host = NSString::from_str(&host_path.to_string_lossy());
            let host_url = NSURL::initFileURLWithPath(NSURL::alloc(), &host);
            VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &host_url,
                read_only,
            )
        };
        Self {
            inner,
            host_path,
            read_only,
        }
    }

    pub(crate) fn as_inner(&self) -> &VZSharedDirectory {
        self.inner.as_ref()
    }

    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Debug, Clone)]
pub struct SingleDirectoryShare {
    inner: Retained<VZSingleDirectoryShare>,
}

impl SingleDirectoryShare {
    pub fn new(shared_directory: SharedDirectory) -> Self {
        Self {
            inner: unsafe {
                VZSingleDirectoryShare::initWithDirectory(
                    VZSingleDirectoryShare::alloc(),
                    shared_directory.as_inner(),
                )
            },
        }
    }

    pub(crate) fn as_inner(&self) -> &VZDirectoryShare {
        self.inner.as_super()
    }
}

#[derive(Debug, Clone)]
pub struct LinuxRosettaDirectoryShare {
    inner: Retained<VZLinuxRosettaDirectoryShare>,
}

impl LinuxRosettaDirectoryShare {
    pub fn new() -> Result<Self, VzError> {
        Ok(Self {
            inner: unsafe {
                VZLinuxRosettaDirectoryShare::initWithError(VZLinuxRosettaDirectoryShare::alloc())
            }
            .map_err(|err| {
                VzError::Backend(format!(
                    "failed to initialize Rosetta directory share: {err}"
                ))
            })?,
        })
    }

    pub(crate) fn as_inner(&self) -> &VZDirectoryShare {
        self.inner.as_super()
    }
}

#[derive(Debug, Clone)]
pub struct VirtioFileSystemDeviceConfiguration {
    inner: Retained<VZVirtioFileSystemDeviceConfiguration>,
    tag: String,
}

impl VirtioFileSystemDeviceConfiguration {
    pub fn new(tag: impl Into<String>) -> Self {
        let tag = tag.into();
        let inner = unsafe {
            VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str(&tag),
            )
        };
        Self { inner, tag }
    }

    pub fn set_share(&mut self, share: SingleDirectoryShare) {
        unsafe {
            self.inner.setShare(Some(share.as_inner()));
        }
    }

    pub fn set_rosetta_share(&mut self, share: LinuxRosettaDirectoryShare) {
        unsafe {
            self.inner.setShare(Some(share.as_inner()));
        }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn as_inner(&self) -> &VZDirectorySharingDeviceConfiguration {
        self.inner.as_super()
    }
}

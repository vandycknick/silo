use std::path::Path;

use objc2::{rc::Retained, AllocAnyThread};
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::VZLinuxBootLoader;

pub(crate) trait BootLoader {
    fn as_inner(&self) -> &VZLinuxBootLoader;
}

#[derive(Debug, Clone)]
pub struct LinuxBootLoader {
    inner: Retained<VZLinuxBootLoader>,
}

impl LinuxBootLoader {
    pub fn new(kernel_path: impl AsRef<Path>) -> Self {
        unsafe {
            let kernel = NSString::from_str(&kernel_path.as_ref().to_string_lossy());
            let kernel_url = NSURL::initFileURLWithPath(NSURL::alloc(), &kernel);
            Self {
                inner: VZLinuxBootLoader::initWithKernelURL(
                    VZLinuxBootLoader::alloc(),
                    &kernel_url,
                ),
            }
        }
    }

    pub fn set_initial_ramdisk(&mut self, path: impl AsRef<Path>) -> &mut Self {
        unsafe {
            let path = NSString::from_str(&path.as_ref().to_string_lossy());
            let path_url = NSURL::initFileURLWithPath(NSURL::alloc(), &path);
            self.inner.setInitialRamdiskURL(Some(&path_url));
        }
        self
    }

    pub fn set_command_line(&mut self, cmdline: &str) -> &mut Self {
        unsafe {
            self.inner.setCommandLine(&NSString::from_str(cmdline));
        }
        self
    }
}

impl BootLoader for LinuxBootLoader {
    fn as_inner(&self) -> &VZLinuxBootLoader {
        self.inner.as_ref()
    }
}

use objc2::{rc::Retained, ClassType};
use objc2_virtualization::{VZEntropyDeviceConfiguration, VZVirtioEntropyDeviceConfiguration};

#[derive(Debug, Clone)]
pub struct EntropyDeviceConfiguration {
    inner: Retained<VZVirtioEntropyDeviceConfiguration>,
}

impl EntropyDeviceConfiguration {
    pub fn new() -> Self {
        Self {
            inner: unsafe { VZVirtioEntropyDeviceConfiguration::new() },
        }
    }

    pub(crate) fn as_inner(&self) -> &VZEntropyDeviceConfiguration {
        self.inner.as_super()
    }
}

impl Default for EntropyDeviceConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

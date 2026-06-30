use objc2::{rc::Retained, ClassType};
use objc2_virtualization::{
    VZMemoryBalloonDeviceConfiguration, VZVirtioTraditionalMemoryBalloonDeviceConfiguration,
};

#[derive(Debug, Clone)]
pub struct MemoryBalloonDeviceConfiguration {
    inner: Retained<VZVirtioTraditionalMemoryBalloonDeviceConfiguration>,
}

impl MemoryBalloonDeviceConfiguration {
    pub fn new() -> Self {
        Self {
            inner: unsafe { VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new() },
        }
    }

    pub(crate) fn as_inner(&self) -> &VZMemoryBalloonDeviceConfiguration {
        self.inner.as_super()
    }
}

impl Default for MemoryBalloonDeviceConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

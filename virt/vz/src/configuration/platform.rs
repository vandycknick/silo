use objc2::{rc::Retained, AllocAnyThread};
use objc2_foundation::NSData;
use objc2_virtualization::{VZGenericMachineIdentifier, VZGenericPlatformConfiguration};

use crate::error::VzError;

#[derive(Debug, Clone)]
pub struct GenericMachineIdentifier {
    inner: Retained<VZGenericMachineIdentifier>,
}

impl GenericMachineIdentifier {
    pub fn new() -> Self {
        Self {
            inner: unsafe { VZGenericMachineIdentifier::new() },
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VzError> {
        let data = NSData::with_bytes(bytes);
        let inner = unsafe {
            VZGenericMachineIdentifier::initWithDataRepresentation(
                VZGenericMachineIdentifier::alloc(),
                &data,
            )
        }
        .ok_or_else(|| VzError::InvalidConfiguration {
            reason: "invalid machine identifier data representation".to_string(),
        })?;

        Ok(Self { inner })
    }

    pub fn data(&self) -> Vec<u8> {
        unsafe { self.inner.dataRepresentation().to_vec() }
    }

    pub(crate) fn as_inner(&self) -> &VZGenericMachineIdentifier {
        self.inner.as_ref()
    }
}

impl Default for GenericMachineIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct GenericPlatform {
    inner: Retained<VZGenericPlatformConfiguration>,
    machine_identifier: GenericMachineIdentifier,
}

// SAFETY: The wrapper owns a retained Objective-C object with thread-safe access controlled by
// the VM queue once attached to a virtual machine.
unsafe impl Send for GenericPlatform {}
// SAFETY: See above.
unsafe impl Sync for GenericPlatform {}

impl GenericPlatform {
    pub fn new() -> Self {
        let machine_identifier = GenericMachineIdentifier::new();
        let inner = unsafe { VZGenericPlatformConfiguration::new() };
        unsafe {
            inner.setMachineIdentifier(machine_identifier.as_inner());
        }
        Self {
            inner,
            machine_identifier,
        }
    }

    pub fn is_nested_virtualization_supported() -> bool {
        unsafe { VZGenericPlatformConfiguration::isNestedVirtualizationSupported() }
    }

    pub fn is_nested_virtualization_enabled(&self) -> bool {
        unsafe { self.inner.isNestedVirtualizationEnabled() }
    }

    pub fn set_nested_virtualization_enabled(&self, enabled: bool) {
        unsafe {
            self.inner.setNestedVirtualizationEnabled(enabled);
        }
    }

    pub fn set_machine_identifier(&mut self, machine_identifier: GenericMachineIdentifier) {
        unsafe {
            self.inner
                .setMachineIdentifier(machine_identifier.as_inner());
        }
        self.machine_identifier = machine_identifier;
    }

    pub(crate) fn as_inner(&self) -> &VZGenericPlatformConfiguration {
        self.inner.as_ref()
    }
}

impl Default for GenericPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#![allow(dead_code)]

use objc2_virtualization::{
    VZGenericPlatformConfiguration, VZLinuxRosettaAvailability, VZLinuxRosettaDirectoryShare,
    VZVirtualMachine,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosettaAvailability {
    NotSupported,
    NotInstalled,
    Installed,
}

pub(crate) fn os_version() -> (i64, i64, i64) {
    use objc2_foundation::NSProcessInfo;
    let version = NSProcessInfo::processInfo().operatingSystemVersion();
    (
        version.majorVersion as i64,
        version.minorVersion as i64,
        version.patchVersion as i64,
    )
}

pub(crate) fn is_os_version_at_least(major: i64, minor: i64, patch: i64) -> bool {
    os_version() >= (major, minor, patch)
}

pub(crate) fn vz_virtual_machine_is_supported() -> bool {
    unsafe { VZVirtualMachine::isSupported() }
}

pub(crate) fn vz_nested_virtualization_is_supported() -> bool {
    unsafe { VZGenericPlatformConfiguration::isNestedVirtualizationSupported() }
}

pub fn rosetta_availability() -> RosettaAvailability {
    match unsafe { VZLinuxRosettaDirectoryShare::availability() } {
        VZLinuxRosettaAvailability::NotSupported => RosettaAvailability::NotSupported,
        VZLinuxRosettaAvailability::NotInstalled => RosettaAvailability::NotInstalled,
        VZLinuxRosettaAvailability::Installed => RosettaAvailability::Installed,
        _ => RosettaAvailability::NotSupported,
    }
}

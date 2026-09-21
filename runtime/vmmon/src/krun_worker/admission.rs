#[cfg(target_os = "macos")]
use std::ffi::c_void;

#[cfg(target_os = "macos")]
const HV_SUCCESS: i32 = 0;
#[cfg(target_os = "macos")]
const HV_DENIED: i32 = -85_377_017;
#[cfg(target_os = "macos")]
const HV_NO_RESOURCES: i32 = -85_377_019;
#[cfg(target_os = "macos")]
const HV_NO_DEVICE: i32 = -85_377_018;
#[cfg(target_os = "macos")]
const HV_UNSUPPORTED: i32 = -85_377_009;

#[cfg(target_os = "macos")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum HvfAdmissionError {
    #[error(transparent)]
    Host(#[from] krun::HvfHostError),
    #[error("create an empty Hypervisor.framework VM: {status}.{guidance}")]
    Create {
        status: HvfStatus,
        guidance: &'static str,
    },
    #[error("destroy the empty Hypervisor.framework VM: {status}.{guidance}")]
    Destroy {
        status: HvfStatus,
        guidance: &'static str,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HvfStatus(i32);

#[cfg(target_os = "macos")]
impl std::fmt::Display for HvfStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.0 {
            HV_DENIED => "HV_DENIED",
            HV_NO_RESOURCES => "HV_NO_RESOURCES",
            HV_NO_DEVICE => "HV_NO_DEVICE",
            HV_UNSUPPORTED => "HV_UNSUPPORTED",
            _ => "unknown HVF status",
        };
        write!(formatter, "{name} ({:#010x})", self.0 as u32)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn check_hvf() -> Result<krun::HvfHostInfo, HvfAdmissionError> {
    let info = krun::check_host()?;

    // libkrun's native API does not expose an admission probe or destruction of its
    // private HvfVm. nix has no Hypervisor.framework binding; use the public SDK API.
    let create_status = unsafe { hv_vm_create(std::ptr::null_mut()) };
    if create_status != HV_SUCCESS {
        return Err(HvfAdmissionError::Create {
            status: HvfStatus(create_status),
            guidance: status_guidance(create_status),
        });
    }

    let destroy_status = unsafe { hv_vm_destroy() };
    if destroy_status != HV_SUCCESS {
        return Err(HvfAdmissionError::Destroy {
            status: HvfStatus(destroy_status),
            guidance: status_guidance(destroy_status),
        });
    }

    Ok(info)
}

#[cfg(target_os = "macos")]
fn status_guidance(status: i32) -> &'static str {
    match status {
        HV_DENIED => {
            " Hint: rebuild signed vmmon with `cargo run --locked -p xtask -- component vmmon` to grant com.apple.security.hypervisor, and verify sandbox policy permits Hypervisor.framework"
        }
        HV_NO_DEVICE | HV_UNSUPPORTED => {
            " Hint: verify hardware virtualization and Hypervisor.framework support are available on this Mac"
        }
        HV_NO_RESOURCES => {
            " Hint: stop unused virtual machines or other hypervisors, then retry"
        }
        _ => " Hint: inspect the helper signature, entitlements, and host virtualization state",
    }
}

// These signatures are from the public macOS arm64 Hypervisor/hv_vm.h SDK header.
#[cfg(target_os = "macos")]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vm_create(config: *mut c_void) -> i32;
    fn hv_vm_destroy() -> i32;
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use crate::krun_worker::admission::{status_guidance, HvfStatus, HV_DENIED, HV_NO_RESOURCES};

    #[test]
    fn denied_status_names_the_required_entitlement() {
        assert_eq!(HvfStatus(HV_DENIED).to_string(), "HV_DENIED (0xfae94007)");
        assert!(status_guidance(HV_DENIED).contains("com.apple.security.hypervisor"));
        assert!(
            status_guidance(HV_DENIED).contains("cargo run --locked -p xtask -- component vmmon")
        );
    }

    #[test]
    fn resource_failure_has_distinct_guidance() {
        assert!(status_guidance(HV_NO_RESOURCES).contains("unused virtual machines"));
    }
}

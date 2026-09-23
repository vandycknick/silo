#[cfg(target_os = "linux")]
use std::ffi::CStr;

#[cfg(target_os = "linux")]
use kvm_ioctls::{Cap, Kvm};

#[cfg(target_os = "linux")]
const EXPECTED_KVM_API_VERSION: i32 = 12;
#[cfg(target_os = "linux")]
const DEFAULT_KVM_DEVICE: &CStr = c"/dev/kvm";

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvmHostInfo {
    pub api_version: i32,
    pub vm_creation_checked: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum KvmHostError {
    #[error("open {device}: {source}.{guidance}")]
    Open {
        device: String,
        source: kvm_ioctls::Error,
        guidance: &'static str,
    },
    #[error(
        "{device} reports KVM API version {actual}, expected {expected}; this host KVM ABI is unsupported"
    )]
    ApiVersion {
        device: String,
        actual: i32,
        expected: i32,
    },
    #[error("{device} does not provide required KVM capability {capability}")]
    MissingCapability {
        device: String,
        capability: &'static str,
    },
    #[error("create an empty VM through {device}: {source}.{guidance}")]
    CreateVm {
        device: String,
        source: kvm_ioctls::Error,
        guidance: &'static str,
    },
}

#[cfg(target_os = "linux")]
pub fn check_host() -> Result<KvmHostInfo, KvmHostError> {
    check_host_at(DEFAULT_KVM_DEVICE, false)
}

#[cfg(target_os = "linux")]
pub fn check_host_with_vm_creation() -> Result<KvmHostInfo, KvmHostError> {
    check_host_at(DEFAULT_KVM_DEVICE, true)
}

#[cfg(target_os = "linux")]
fn check_host_at(device: &CStr, create_vm: bool) -> Result<KvmHostInfo, KvmHostError> {
    let device_name = device.to_string_lossy().into_owned();
    let kvm = Kvm::new_with_path(device).map_err(|source| KvmHostError::Open {
        device: device_name.clone(),
        guidance: errno_guidance(source.errno()),
        source,
    })?;
    let api_version = kvm.get_api_version();
    if api_version != EXPECTED_KVM_API_VERSION {
        return Err(KvmHostError::ApiVersion {
            device: device_name,
            actual: api_version,
            expected: EXPECTED_KVM_API_VERSION,
        });
    }
    for (capability, name) in required_capabilities() {
        if !kvm.check_extension(*capability) {
            return Err(KvmHostError::MissingCapability {
                device: device_name,
                capability: name,
            });
        }
    }
    if create_vm {
        let vm = kvm.create_vm().map_err(|source| KvmHostError::CreateVm {
            device: device_name,
            guidance: errno_guidance(source.errno()),
            source,
        })?;
        drop(vm);
    }

    Ok(KvmHostInfo {
        api_version,
        vm_creation_checked: create_vm,
    })
}

#[cfg(target_os = "linux")]
fn required_capabilities() -> &'static [(Cap, &'static str)] {
    #[cfg(target_arch = "x86_64")]
    {
        &[
            (Cap::Irqchip, "Irqchip"),
            (Cap::Ioeventfd, "Ioeventfd"),
            (Cap::Irqfd, "Irqfd"),
            (Cap::UserMemory, "UserMemory"),
            (Cap::SetTssAddr, "SetTssAddr"),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &[
            (Cap::Irqchip, "Irqchip"),
            (Cap::Ioeventfd, "Ioeventfd"),
            (Cap::Irqfd, "Irqfd"),
            (Cap::UserMemory, "UserMemory"),
            (Cap::ArmPsci02, "ArmPsci02"),
        ]
    }
    #[cfg(target_arch = "riscv64")]
    {
        &[
            (Cap::Irqchip, "Irqchip"),
            (Cap::Ioeventfd, "Ioeventfd"),
            (Cap::Irqfd, "Irqfd"),
            (Cap::UserMemory, "UserMemory"),
        ]
    }
}

#[cfg(target_os = "linux")]
fn errno_guidance(errno: i32) -> &'static str {
    match nix::errno::Errno::from_raw(errno) {
        nix::errno::Errno::ENOENT => {
            " Hint: expose /dev/kvm to this environment and ensure the KVM kernel modules are loaded"
        }
        nix::errno::Errno::EACCES | nix::errno::Errno::EPERM => {
            " Hint: grant this process access to /dev/kvm and check device-cgroup or sandbox policy"
        }
        nix::errno::Errno::ENODEV | nix::errno::Errno::ENXIO => {
            " Hint: enable hardware virtualization and load the host KVM kernel modules"
        }
        _ => " Hint: inspect the host KVM configuration and sandbox policy",
    }
}

#[cfg(target_os = "macos")]
const HV_SUPPORT_SYSCTL: &std::ffi::CStr = c"kern.hv_support";

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvfHostInfo {
    pub hv_supported: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug, thiserror::Error)]
pub enum HvfHostError {
    #[error("read kern.hv_support: {0}. Hint: verify this Mac and macOS version support Hypervisor.framework")]
    Sysctl(std::io::Error),
    #[error("kern.hv_support is 0; this Mac does not support Hypervisor.framework")]
    Unsupported,
    #[error(
        "kern.hv_support returned an unexpected {actual}-byte value, expected {expected} bytes"
    )]
    UnexpectedSize { actual: usize, expected: usize },
    #[error("kern.hv_support returned unexpected value {actual}, expected 0 or 1")]
    UnexpectedValue { actual: std::ffi::c_int },
}

#[cfg(target_os = "macos")]
pub fn check_host() -> Result<HvfHostInfo, HvfHostError> {
    let mut supported: std::ffi::c_int = 0;
    let mut size = std::mem::size_of_val(&supported);
    // nix does not expose sysctlbyname, so use its libc re-export for this read-only host probe.
    let result = unsafe {
        nix::libc::sysctlbyname(
            HV_SUPPORT_SYSCTL.as_ptr(),
            std::ptr::from_mut(&mut supported).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(HvfHostError::Sysctl(std::io::Error::last_os_error()));
    }
    validate_hv_support(supported, size)
}

#[cfg(target_os = "macos")]
fn validate_hv_support(
    supported: std::ffi::c_int,
    size: usize,
) -> Result<HvfHostInfo, HvfHostError> {
    let expected = std::mem::size_of::<std::ffi::c_int>();
    if size != expected {
        return Err(HvfHostError::UnexpectedSize {
            actual: size,
            expected,
        });
    }
    match supported {
        0 => Err(HvfHostError::Unsupported),
        1 => Ok(HvfHostInfo { hv_supported: true }),
        actual => Err(HvfHostError::UnexpectedValue { actual }),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::ffi::CString;
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    use crate::krun::host::{check_host_at, errno_guidance, KvmHostError};
    #[cfg(target_os = "macos")]
    use crate::krun::host::{validate_hv_support, HvfHostError};

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_kvm_device_returns_actionable_error_without_panicking() {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let device = CString::new(format!(
            "/tmp/silo-missing-kvm-{}-{timestamp}",
            std::process::id()
        ))
        .expect("valid device path");

        let error = check_host_at(&device, false).expect_err("missing KVM device must fail");
        match error {
            KvmHostError::Open {
                source, guidance, ..
            } => {
                assert_eq!(source.errno(), nix::errno::Errno::ENOENT as i32);
                assert!(guidance.contains("expose /dev/kvm"));
            }
            other => panic!("missing device returned the wrong error: {other}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn permission_errors_explain_common_container_restrictions() {
        let guidance = errno_guidance(nix::errno::Errno::EACCES as i32);

        assert!(guidance.contains("device-cgroup"));
        assert!(guidance.contains("sandbox"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hv_support_one_is_supported() {
        let info = validate_hv_support(1, std::mem::size_of::<std::ffi::c_int>())
            .expect("kern.hv_support=1 should be supported");

        assert!(info.hv_supported);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hv_support_zero_is_unsupported() {
        let error = validate_hv_support(0, std::mem::size_of::<std::ffi::c_int>())
            .expect_err("kern.hv_support=0 should be unsupported");

        assert!(matches!(error, HvfHostError::Unsupported));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hv_support_rejects_other_values() {
        let error = validate_hv_support(2, std::mem::size_of::<std::ffi::c_int>())
            .expect_err("kern.hv_support values other than 0 or 1 should fail");

        assert!(matches!(error, HvfHostError::UnexpectedValue { actual: 2 }));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn hv_support_rejects_unexpected_sizes() {
        let expected = std::mem::size_of::<std::ffi::c_int>();
        let error = validate_hv_support(1, expected + 1)
            .expect_err("unexpected kern.hv_support sizes should fail");

        assert!(matches!(
            error,
            HvfHostError::UnexpectedSize { actual, expected: value }
                if actual == expected + 1 && value == expected
        ));
    }
}

use std::ffi::CStr;

use kvm_ioctls::{Cap, Kvm};

const EXPECTED_KVM_API_VERSION: i32 = 12;
const DEFAULT_KVM_DEVICE: &CStr = c"/dev/kvm";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvmHostInfo {
    pub api_version: i32,
    pub vm_creation_checked: bool,
}

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

pub fn check_host() -> Result<KvmHostInfo, KvmHostError> {
    check_host_at(DEFAULT_KVM_DEVICE, false)
}

pub fn check_host_with_vm_creation() -> Result<KvmHostInfo, KvmHostError> {
    check_host_at(DEFAULT_KVM_DEVICE, true)
}

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

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::host::{check_host_at, errno_guidance, KvmHostError};

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

    #[test]
    fn permission_errors_explain_common_container_restrictions() {
        let guidance = errno_guidance(nix::errno::Errno::EACCES as i32);

        assert!(guidance.contains("device-cgroup"));
        assert!(guidance.contains("sandbox"));
    }
}

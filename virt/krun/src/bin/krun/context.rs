use std::ffi::{c_char, CString, NulError};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use thiserror::Error;

const KRUN_DISK_FORMAT_RAW: u32 = 0;
const KRUN_SYNC_RELAXED: u32 = 1;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const KRUN_KERNEL_FORMAT_RAW: u32 = 0;
#[cfg(target_arch = "x86_64")]
const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;
const NET_FEATURE_CSUM: u32 = 1 << 0;
const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
const NET_FEATURE_GUEST_UFO: u32 = 1 << 10;
const NET_FEATURE_HOST_TSO4: u32 = 1 << 11;
const NET_FEATURE_HOST_UFO: u32 = 1 << 14;
const COMPAT_NET_FEATURES: u32 = NET_FEATURE_CSUM
    | NET_FEATURE_GUEST_CSUM
    | NET_FEATURE_GUEST_TSO4
    | NET_FEATURE_GUEST_UFO
    | NET_FEATURE_HOST_TSO4
    | NET_FEATURE_HOST_UFO;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum KernelFormat {
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    Raw = KRUN_KERNEL_FORMAT_RAW,
    #[cfg(target_arch = "x86_64")]
    Elf = KRUN_KERNEL_FORMAT_ELF,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("libkrun {op} failed with errno {code}")]
    Libkrun { op: &'static str, code: i32 },

    #[error("libkrun string argument contains an interior nul byte")]
    InteriorNul(#[from] NulError),
}

pub(crate) struct Context {
    id: u32,
    active: bool,
}

impl Context {
    pub(crate) fn create() -> Result<Self, Error> {
        let id = checked_u32("create_ctx", libkrun::krun_create_ctx())?;
        Ok(Self { id, active: true })
    }

    pub(crate) fn set_vm_config(&self, vcpus: u8, ram_mib: u32) -> Result<(), Error> {
        check(
            "set_vm_config",
            libkrun::krun_set_vm_config(self.id, vcpus, ram_mib),
        )
    }

    pub(crate) fn disable_implicit_console(&self) -> Result<(), Error> {
        check(
            "disable_implicit_console",
            libkrun::krun_disable_implicit_console(self.id),
        )
    }

    pub(crate) fn disable_implicit_init(&self) -> Result<(), Error> {
        check(
            "disable_implicit_init",
            libkrun::krun_disable_implicit_init(self.id),
        )
    }

    pub(crate) fn disable_implicit_vsock(&self) -> Result<(), Error> {
        check(
            "disable_implicit_vsock",
            libkrun::krun_disable_implicit_vsock(self.id),
        )
    }

    pub(crate) fn set_kernel(
        &self,
        kernel: &Path,
        format: KernelFormat,
        initramfs: Option<&Path>,
        cmdline: Option<&str>,
    ) -> Result<(), Error> {
        let kernel = path_cstring(kernel)?;
        let initramfs = initramfs.map(path_cstring).transpose()?;
        let cmdline = cmdline.map(CString::new).transpose()?;
        check("set_kernel", unsafe {
            libkrun::krun_set_kernel(
                self.id,
                kernel.as_ptr(),
                format as u32,
                optional_cstring_ptr(initramfs.as_ref()),
                optional_cstring_ptr(cmdline.as_ref()),
            )
        })
    }

    pub(crate) fn add_raw_disk(
        &self,
        block_id: &str,
        disk_path: &Path,
        read_only: bool,
    ) -> Result<(), Error> {
        let block_id = CString::new(block_id)?;
        let disk_path = path_cstring(disk_path)?;
        check("add_disk3", unsafe {
            libkrun::krun_add_disk3(
                self.id,
                block_id.as_ptr(),
                disk_path.as_ptr(),
                KRUN_DISK_FORMAT_RAW,
                read_only,
                false,
                KRUN_SYNC_RELAXED,
            )
        })
    }

    pub(crate) fn add_virtiofs(
        &self,
        tag: &str,
        path: &Path,
        read_only: bool,
    ) -> Result<(), Error> {
        let tag = CString::new(tag)?;
        let path = path_cstring(path)?;
        check("add_virtiofs3", unsafe {
            libkrun::krun_add_virtiofs3(self.id, tag.as_ptr(), path.as_ptr(), 0, read_only)
        })
    }

    pub(crate) fn add_vsock(&self) -> Result<(), Error> {
        check("add_vsock", libkrun::krun_add_vsock(self.id, 0))
    }

    pub(crate) fn add_vsock_port(&self, port: u32, path: &Path, listen: bool) -> Result<(), Error> {
        let path = path_cstring(path)?;
        check("add_vsock_port2", unsafe {
            libkrun::krun_add_vsock_port2(self.id, port, path.as_ptr(), listen)
        })
    }

    pub(crate) fn add_net_unixgram_fd(&self, fd: RawFd, mac: [u8; 6]) -> Result<(), Error> {
        check("add_net_unixgram", unsafe {
            libkrun::krun_add_net_unixgram(
                self.id,
                std::ptr::null(),
                fd,
                mac.as_ptr(),
                COMPAT_NET_FEATURES,
                NET_FLAG_DHCP_CLIENT,
            )
        })
    }

    pub(crate) fn add_net_unixstream(&self, path: &Path, mac: [u8; 6]) -> Result<(), Error> {
        let path = path_cstring(path)?;
        check("add_net_unixstream", unsafe {
            libkrun::krun_add_net_unixstream(
                self.id,
                path.as_ptr(),
                -1,
                mac.as_ptr(),
                COMPAT_NET_FEATURES,
                NET_FLAG_DHCP_CLIENT,
            )
        })
    }

    pub(crate) fn add_net_tap(&self, name: &str, mac: [u8; 6]) -> Result<(), Error> {
        let name = CString::new(name)?;
        check("add_net_tap", unsafe {
            libkrun::krun_add_net_tap(
                self.id,
                name.as_ptr(),
                mac.as_ptr(),
                COMPAT_NET_FEATURES,
                NET_FLAG_DHCP_CLIENT,
            )
        })
    }

    pub(crate) fn add_virtio_console_default(
        &self,
        input_fd: i32,
        output_fd: i32,
        err_fd: i32,
    ) -> Result<(), Error> {
        check("add_virtio_console_default", unsafe {
            libkrun::krun_add_virtio_console_default(self.id, input_fd, output_fd, err_fd)
        })
    }

    pub(crate) fn set_kernel_console(&self, console_id: &str) -> Result<(), Error> {
        let console_id = CString::new(console_id)?;
        check("set_kernel_console", unsafe {
            libkrun::krun_set_kernel_console(self.id, console_id.as_ptr())
        })
    }

    pub(crate) fn start_enter(mut self) -> Result<(), Error> {
        let ret = libkrun::krun_start_enter(self.id);
        if ret < 0 {
            let _ = libkrun::krun_free_ctx(self.id);
        }
        self.active = false;
        check("start_enter", ret)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.active {
            let _ = libkrun::krun_free_ctx(self.id);
        }
    }
}

const fn check(op: &'static str, ret: i32) -> Result<(), Error> {
    if ret < 0 {
        Err(Error::Libkrun { op, code: ret })
    } else {
        Ok(())
    }
}

fn checked_u32(op: &'static str, ret: i32) -> Result<u32, Error> {
    if ret < 0 {
        Err(Error::Libkrun { op, code: ret })
    } else {
        Ok(ret as u32)
    }
}

fn path_cstring(path: &Path) -> Result<CString, NulError> {
    CString::new(path.as_os_str().as_bytes())
}

fn optional_cstring_ptr(value: Option<&CString>) -> *const c_char {
    value.map_or(std::ptr::null(), |value| value.as_ptr())
}

#[cfg(test)]
mod tests {
    use crate::context::{
        COMPAT_NET_FEATURES, KRUN_DISK_FORMAT_RAW, KRUN_SYNC_RELAXED, NET_FLAG_DHCP_CLIENT,
    };

    #[test]
    fn constants_match_libkrun_api() {
        assert_eq!(KRUN_DISK_FORMAT_RAW, 0);
        assert_eq!(KRUN_SYNC_RELAXED, 1);
        assert_eq!(COMPAT_NET_FEATURES, 19_587);
        assert_eq!(NET_FLAG_DHCP_CLIENT, 2);
    }

    #[test]
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    fn raw_kernel_format_matches_libkrun_api() {
        assert_eq!(
            crate::context::KernelFormat::Raw as u32,
            crate::context::KRUN_KERNEL_FORMAT_RAW
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn elf_kernel_format_matches_libkrun_api() {
        assert_eq!(
            crate::context::KernelFormat::Elf as u32,
            crate::context::KRUN_KERNEL_FORMAT_ELF
        );
    }
}

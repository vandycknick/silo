use std::ffi::{c_char, c_void, CString};
use std::os::fd::RawFd;

use crate::error::{KrunError, Result};
use crate::sys;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DiskFormat {
    Raw = sys::KRUN_DISK_FORMAT_RAW,
    Qcow2 = sys::KRUN_DISK_FORMAT_QCOW2,
    Vmdk = sys::KRUN_DISK_FORMAT_VMDK,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncMode {
    None = sys::KRUN_SYNC_NONE,
    Relaxed = sys::KRUN_SYNC_RELAXED,
    Full = sys::KRUN_SYNC_FULL,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogStyle {
    Auto = sys::KRUN_LOG_STYLE_AUTO,
    Always = sys::KRUN_LOG_STYLE_ALWAYS,
    Never = sys::KRUN_LOG_STYLE_NEVER,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KernelFormat {
    Raw = sys::KRUN_KERNEL_FORMAT_RAW,
    Elf = sys::KRUN_KERNEL_FORMAT_ELF,
    PeGz = sys::KRUN_KERNEL_FORMAT_PE_GZ,
    ImageBz2 = sys::KRUN_KERNEL_FORMAT_IMAGE_BZ2,
    ImageGz = sys::KRUN_KERNEL_FORMAT_IMAGE_GZ,
    ImageZstd = sys::KRUN_KERNEL_FORMAT_IMAGE_ZSTD,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Feature {
    Net = sys::KRUN_FEATURE_NET as u64,
    Blk = sys::KRUN_FEATURE_BLK as u64,
    Gpu = sys::KRUN_FEATURE_GPU as u64,
    Snd = sys::KRUN_FEATURE_SND as u64,
    Input = sys::KRUN_FEATURE_INPUT as u64,
    Efi = sys::KRUN_FEATURE_EFI as u64,
    Tee = sys::KRUN_FEATURE_TEE as u64,
    AmdSev = sys::KRUN_FEATURE_AMD_SEV as u64,
    IntelTdx = sys::KRUN_FEATURE_INTEL_TDX as u64,
    AwsNitro = sys::KRUN_FEATURE_AWS_NITRO as u64,
    VirglResourceMap2 = sys::KRUN_FEATURE_VIRGL_RESOURCE_MAP2 as u64,
}

struct CStringArray {
    _owned: Vec<CString>,
    ptrs: Vec<*const c_char>,
}

impl CStringArray {
    fn new(strings: &[String]) -> Result<Self> {
        let owned: Vec<CString> = strings
            .iter()
            .map(|value| CString::new(value.as_str()))
            .collect::<std::result::Result<_, _>>()?;
        let mut ptrs: Vec<*const c_char> = owned.iter().map(|value| value.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    fn as_ptr(&self) -> *const *const c_char {
        self.ptrs.as_ptr()
    }
}

const fn check(op: &'static str, ret: i32) -> Result<()> {
    if ret < 0 {
        Err(KrunError::Krun { op, code: ret })
    } else {
        Ok(())
    }
}

fn checked_u32(op: &'static str, ret: i32) -> Result<u32> {
    if ret < 0 {
        Err(KrunError::Krun { op, code: ret })
    } else {
        Ok(ret as u32)
    }
}

pub fn create_ctx() -> Result<u32> {
    checked_u32("create_ctx", unsafe { sys::krun_create_ctx() })
}

pub fn free_ctx(ctx: u32) -> Result<()> {
    check("free_ctx", unsafe { sys::krun_free_ctx(ctx) })
}

pub fn start_enter(ctx: u32) -> Result<()> {
    check("start_enter", unsafe { sys::krun_start_enter(ctx) })
}

pub fn set_vm_config(ctx: u32, vcpus: u8, ram_mib: u32) -> Result<()> {
    check("set_vm_config", unsafe {
        sys::krun_set_vm_config(ctx, vcpus, ram_mib)
    })
}

pub fn set_root(ctx: u32, path: &str) -> Result<()> {
    let path = CString::new(path)?;
    check("set_root", unsafe {
        sys::krun_set_root(ctx, path.as_ptr())
    })
}

#[allow(clippy::too_many_arguments, reason = "1:1 wrapper for libkrun API")]
pub fn add_disk3(
    ctx: u32,
    block_id: &str,
    disk_path: &str,
    format: DiskFormat,
    read_only: bool,
    direct_io: bool,
    sync_mode: SyncMode,
) -> Result<()> {
    let block_id = CString::new(block_id)?;
    let disk_path = CString::new(disk_path)?;
    check("add_disk3", unsafe {
        sys::krun_add_disk3(
            ctx,
            block_id.as_ptr(),
            disk_path.as_ptr(),
            format as u32,
            read_only,
            direct_io,
            sync_mode as u32,
        )
    })
}

pub fn add_virtiofs3(
    ctx: u32,
    tag: &str,
    path: &str,
    shm_size: u64,
    read_only: bool,
) -> Result<()> {
    let tag = CString::new(tag)?;
    let path = CString::new(path)?;
    check("add_virtiofs3", unsafe {
        sys::krun_add_virtiofs3(ctx, tag.as_ptr(), path.as_ptr(), shm_size, read_only)
    })
}

pub fn add_vsock_port2(ctx: u32, port: u32, path: &str, listen: bool) -> Result<()> {
    let path = CString::new(path)?;
    check("add_vsock_port2", unsafe {
        sys::krun_add_vsock_port2(ctx, port, path.as_ptr(), listen)
    })
}

pub fn add_vsock(ctx: u32, tsi_features: u32) -> Result<()> {
    check("add_vsock", unsafe {
        sys::krun_add_vsock(ctx, tsi_features)
    })
}

pub fn add_net_unixgram(ctx: u32, path: &str, mut mac: [u8; 6]) -> Result<()> {
    let path = CString::new(path)?;
    check("add_net_unixgram", unsafe {
        sys::krun_add_net_unixgram(
            ctx,
            path.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            sys::COMPAT_NET_FEATURES,
            sys::NET_FLAG_VFKIT | sys::NET_FLAG_DHCP_CLIENT,
        )
    })
}

pub fn add_net_unixstream(ctx: u32, path: &str, mut mac: [u8; 6]) -> Result<()> {
    let path = CString::new(path)?;
    check("add_net_unixstream", unsafe {
        sys::krun_add_net_unixstream(
            ctx,
            path.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            sys::COMPAT_NET_FEATURES,
            sys::NET_FLAG_DHCP_CLIENT,
        )
    })
}

pub fn add_net_tap(ctx: u32, tap_name: &str, mut mac: [u8; 6]) -> Result<()> {
    let tap_name = CString::new(tap_name)?;
    check("add_net_tap", unsafe {
        sys::krun_add_net_tap(
            ctx,
            tap_name.as_ptr().cast_mut(),
            mac.as_mut_ptr(),
            sys::COMPAT_NET_FEATURES,
            sys::NET_FLAG_DHCP_CLIENT,
        )
    })
}

pub fn add_net_unixgram_fd(ctx: u32, fd: RawFd, mut mac: [u8; 6]) -> Result<()> {
    check("add_net_unixgram", unsafe {
        sys::krun_add_net_unixgram(
            ctx,
            std::ptr::null(),
            fd,
            mac.as_mut_ptr(),
            sys::COMPAT_NET_FEATURES,
            sys::NET_FLAG_DHCP_CLIENT,
        )
    })
}

pub fn set_console_output(ctx: u32, path: &str) -> Result<()> {
    let path = CString::new(path)?;
    check("set_console_output", unsafe {
        sys::krun_set_console_output(ctx, path.as_ptr())
    })
}

pub fn disable_implicit_console(ctx: u32) -> Result<()> {
    check("disable_implicit_console", unsafe {
        sys::krun_disable_implicit_console(ctx)
    })
}

pub fn set_kernel_console(ctx: u32, console_id: &str) -> Result<()> {
    let console_id = CString::new(console_id)?;
    check("set_kernel_console", unsafe {
        sys::krun_set_kernel_console(ctx, console_id.as_ptr())
    })
}

pub fn add_virtio_console_default(
    ctx: u32,
    input_fd: i32,
    output_fd: i32,
    err_fd: i32,
) -> Result<()> {
    check("add_virtio_console_default", unsafe {
        sys::krun_add_virtio_console_default(ctx, input_fd, output_fd, err_fd)
    })
}

pub fn disable_implicit_vsock(ctx: u32) -> Result<()> {
    check("disable_implicit_vsock", unsafe {
        sys::krun_disable_implicit_vsock(ctx)
    })
}

pub fn set_kernel(
    ctx: u32,
    kernel_path: &str,
    format: KernelFormat,
    initramfs: Option<&str>,
    cmdline: Option<&str>,
) -> Result<()> {
    let kernel_path = CString::new(kernel_path)?;
    let initramfs = initramfs.map(CString::new).transpose()?;
    let cmdline = cmdline.map(CString::new).transpose()?;
    check("set_kernel", unsafe {
        sys::krun_set_kernel(
            ctx,
            kernel_path.as_ptr(),
            format as u32,
            initramfs
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            cmdline
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
        )
    })
}

pub fn set_root_disk_remount(
    ctx: u32,
    device: &str,
    fstype: Option<&str>,
    options: Option<&str>,
) -> Result<()> {
    let device = CString::new(device)?;
    let fstype = fstype.map(CString::new).transpose()?;
    let options = options.map(CString::new).transpose()?;
    check("set_root_disk_remount", unsafe {
        sys::krun_set_root_disk_remount(
            ctx,
            device.as_ptr(),
            fstype
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            options
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
        )
    })
}

pub fn check_nested_virt() -> Result<bool> {
    let ret = unsafe { sys::krun_check_nested_virt() };
    if ret < 0 {
        Err(KrunError::Krun {
            op: "check_nested_virt",
            code: ret,
        })
    } else {
        Ok(ret == 1)
    }
}

pub fn get_max_vcpus() -> Result<u32> {
    checked_u32("get_max_vcpus", unsafe { sys::krun_get_max_vcpus() })
}

pub fn has_feature(feature: Feature) -> Result<bool> {
    let ret = unsafe { sys::krun_has_feature(feature as u64) };
    if ret < 0 {
        Err(KrunError::Krun {
            op: "has_feature",
            code: ret,
        })
    } else {
        Ok(ret == 1)
    }
}

pub fn set_env(ctx: u32, envp: &[String]) -> Result<()> {
    let envp = CStringArray::new(envp)?;
    check("set_env", unsafe { sys::krun_set_env(ctx, envp.as_ptr()) })
}

/// Configure libkrun display output using a caller-provided backend struct.
///
/// # Safety
///
/// `backend` must point to a valid `krun_display_backend`-compatible value
/// for the loaded libkrun version and remain valid for the duration required
/// by libkrun. `backend_size` must exactly match the pointed-to struct size.
pub unsafe fn set_display_backend(
    ctx: u32,
    backend: *const c_void,
    backend_size: usize,
) -> Result<()> {
    check("set_display_backend", unsafe {
        sys::krun_set_display_backend(ctx, backend, backend_size)
    })
}

#[cfg(test)]
mod tests {
    use crate::ctx::{DiskFormat, KernelFormat, LogStyle, SyncMode};

    #[test]
    fn enums_match_libkrun_constants() {
        assert_eq!(DiskFormat::Raw as u32, 0);
        assert_eq!(DiskFormat::Qcow2 as u32, 1);
        assert_eq!(SyncMode::Relaxed as u32, 1);
        assert_eq!(LogStyle::Never as u32, 2);
        assert_eq!(KernelFormat::ImageZstd as u32, 5);
    }
}

//! Block-device discovery and measurement shared by the overlay and raw root
//! paths. Role- and filesystem-specific admission stays with each caller.
use crate::io;
use crate::owned::{path, pread_all, read_fd, read_file, Fd};
use ::init::root_checks::{self, DeviceFacts};
use alloc::vec::Vec;
use rootfs_spec::DeviceNumber;

/// Bound on entries enumerated from one sysfs directory.
const MAX_ENTRIES: usize = 4096;

/// A held block-special descriptor whose identity and geometry were measured.
pub(crate) struct Block {
    pub(crate) fd: Fd,
    pub(crate) path: Vec<u8>,
    pub(crate) facts: DeviceFacts,
}

/// Measures `/dev/{name}` against its sysfs directory: device number,
/// block-special identity, size, logical sector size (from the owning disk's
/// `queue`) and read-only state, cross-checked through ioctls on the held FD.
pub(crate) fn measure(
    sysfs: &[u8],
    name: &[u8],
    queue: &[u8],
    writable: bool,
) -> Result<Block, &'static str> {
    let number = read_file(&path(sysfs, b"/dev", b""), 64)?;
    let number = number.strip_suffix(b"\n").unwrap_or(&number);
    let at = number
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("block: invalid sysfs device number")?;
    let major = u32::try_from(root_checks::decimal(&number[..at])?)
        .map_err(|_| "block: device major overflow")?;
    let minor = u32::try_from(root_checks::decimal(&number[at + 1..])?)
        .map_err(|_| "block: device minor overflow")?;
    let device_path = path(b"/dev/", name, b"");
    let fd = Fd::open(
        &device_path,
        if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        },
    )?;
    let stat = fd.stat()?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFBLK
        || libc::major(stat.st_rdev) != major
        || libc::minor(stat.st_rdev) != minor
    {
        return Err("block: block-special identity mismatch");
    }
    let sectors = root_checks::decimal(&read_file(&path(sysfs, b"/size", b""), 64)?)?;
    let length = sectors
        .checked_mul(512)
        .ok_or("block: device size overflow")?;
    let sector_size =
        root_checks::decimal(&read_file(&path(queue, b"/logical_block_size", b""), 64)?)?;
    let ro = root_checks::decimal(&read_file(&path(sysfs, b"/ro", b""), 64)?)?;
    if ro > 1 {
        return Err("block: invalid read-only state");
    }
    let mut ioctl_length = 0u64;
    let mut ioctl_sector = 0i32;
    let mut ioctl_ro = 0i32;
    // GNU uses an unsigned-long request, musl an int. Infer libc's target
    // type from ioctl while preserving the Linux request's u32 bit pattern.
    if unsafe { libc::ioctl(fd.0, 0x80081272u32 as _, &mut ioctl_length) } != 0
        || unsafe { libc::ioctl(fd.0, 0x1268u32 as _, &mut ioctl_sector) } != 0
        || unsafe { libc::ioctl(fd.0, 0x125eu32 as _, &mut ioctl_ro) } != 0
        || ioctl_length != length
        || u64::try_from(ioctl_sector).ok() != Some(sector_size)
        || u64::try_from(ioctl_ro).ok() != Some(ro)
    {
        return Err("block: kernel block geometry disagreement");
    }
    Ok(Block {
        fd,
        path: device_path,
        facts: DeviceFacts {
            number: DeviceNumber { major, minor },
            length_bytes: length,
            logical_sector_size: u32::try_from(sector_size)
                .map_err(|_| "block: sector size overflow")?,
            read_only: ro != 0,
        },
    })
}

/// Visits each entry of a bounded directory with its `d_type`, closing the
/// directory on every outcome, including a visitor failure.
pub(crate) fn for_each_entry(
    directory: &[u8],
    mut visit: impl FnMut(&[u8], u8) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let dir = io::opendir(directory);
    if dir.is_null() {
        return Err("block: cannot enumerate sysfs directory");
    }
    let result = (|| {
        let mut count = 0usize;
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = io::readdir(dir);
            if entry.is_null() {
                if io::errno() != 0 {
                    return Err("block: sysfs enumeration failed");
                }
                return Ok(());
            }
            count += 1;
            if count > MAX_ENTRIES {
                return Err("block: too many sysfs entries");
            }
            let raw = unsafe { &(*entry).d_name };
            let end = raw
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("block: unterminated sysfs name")?;
            let name = unsafe { core::slice::from_raw_parts(raw.as_ptr().cast::<u8>(), end) };
            if name == b"." || name == b".." {
                continue;
            }
            if name.is_empty() || name.contains(&b'/') {
                return Err("block: invalid sysfs name");
            }
            visit(name, unsafe { (*entry).d_type })?;
        }
    })();
    if io::closedir(dir) != 0 && result.is_ok() {
        return Err("block: sysfs directory close failed");
    }
    result
}

/// Visits every whole block device that reports a serial. Devices without a
/// serial attribute cannot carry a Silo role and are skipped.
pub(crate) fn for_each_serial(
    mut visit: impl FnMut(&[u8], &[u8]) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    for_each_entry(b"/sys/block", |name, _| {
        let serial_path = path(b"/sys/block/", name, b"/serial");
        let serial_fd = io::open(
            &serial_path,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        );
        if serial_fd < 0 {
            if io::errno() == libc::ENOENT {
                return Ok(());
            }
            return Err("block: cannot read block serial");
        }
        let serial = read_fd(&Fd(serial_fd), 64)?;
        visit(name, &serial)
    })
}

/// The shared partition parser's exact positioned reads over a held FD.
pub(crate) struct HeldDevice<'a>(pub(crate) &'a Fd);

impl disk_partition::ReadAt for HeldDevice<'_> {
    type Error = &'static str;

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        pread_all(self.0, offset, output)
    }
}

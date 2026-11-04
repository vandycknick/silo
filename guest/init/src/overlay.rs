//! Managed root assembly. The static no_std init cannot link nix/std; libc is
//! used here consistently with its existing syscall layer, with owned FDs.
use crate::{applets, io};
use ::init::{overlay_verify, root_checks};
use alloc::vec::Vec;
use rootfs_spec::{
    DeviceExpectation, DeviceNumber, Observation, OverlayRoot, Root, TemporaryDirectory,
};

const ROOT: &[u8] = b"/run/silo/rootfs";
const LOWER: &[u8] = b"/run/silo/rootfs/lower";
const UPPER: &[u8] = b"/run/silo/rootfs/upperfs";
const UPPER_DIR: &[u8] = b"/run/silo/rootfs/upperfs/upper";
const WORK_DIR: &[u8] = b"/run/silo/rootfs/upperfs/work";
const TARGET: &[u8] = b"/mnt/root";
const MAX_MOUNTINFO: usize = 256 * 1024;

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        io::close(self.0);
    }
}
impl Fd {
    fn open(path: &[u8], flags: i32) -> Result<Self, &'static str> {
        let fd = io::open(path, flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0);
        if fd < 0 {
            Err("overlay: open failed")
        } else {
            Ok(Self(fd))
        }
    }
}

pub(crate) fn bootstrap() -> Result<Option<Root>, &'static str> {
    let fd = io::open(
        rootfs_spec::BOOTSTRAP_PATH.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    );
    if fd < 0 {
        return if io::errno() == libc::ENOENT {
            Ok(None)
        } else {
            Err("overlay: bootstrap open failed")
        };
    }
    let fd = Fd(fd);
    let mut stat = io::stat_zeroed();
    if unsafe { libc::fstat(fd.0, &mut stat) } != 0
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o7777 != 0o600
    {
        return Err("overlay: bootstrap must be root-owned regular mode 0600");
    }
    let bytes = read_fd(&fd, rootfs_spec::MAX_JSON_BYTES)?;
    let bootstrap =
        rootfs_spec::decode_bootstrap(&bytes).map_err(|_| "overlay: invalid root bootstrap")?;
    Ok(Some(bootstrap.root))
}

fn read_fd(fd: &Fd, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = io::read(fd.0, &mut buffer);
        if count < 0 {
            if io::errno() == libc::EINTR {
                continue;
            }
            return Err("overlay: read failed");
        }
        if count == 0 {
            return Ok(bytes);
        }
        let count = count as usize;
        if count > maximum.saturating_sub(bytes.len()) {
            return Err("overlay: input exceeds bound");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}
fn read_file(path: &[u8], maximum: usize) -> Result<Vec<u8>, &'static str> {
    read_fd(&Fd::open(path, libc::O_RDONLY)?, maximum)
}
fn path(prefix: &[u8], name: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + name.len() + suffix.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(name);
    out.extend_from_slice(suffix);
    out
}

struct Device {
    fd: Fd,
    path: Vec<u8>,
    facts: root_checks::DeviceFacts,
    span: u64,
}
fn pread_all(fd: &Fd, offset: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
    let mut done = 0;
    while done < bytes.len() {
        let at = offset
            .checked_add(done as u64)
            .and_then(|value| libc::off_t::try_from(value).ok())
            .ok_or("overlay: device read offset overflow")?;
        let read = unsafe {
            libc::pread(
                fd.0,
                bytes[done..].as_mut_ptr().cast(),
                bytes.len() - done,
                at,
            )
        };
        if read < 0 && io::errno() == libc::EINTR {
            continue;
        }
        if read <= 0 {
            return Err("overlay: truncated filesystem metadata");
        }
        done += read as usize;
    }
    Ok(())
}
fn superblock(fd: &Fd) -> Result<[u8; 1024], &'static str> {
    let mut bytes = [0; 1024];
    pread_all(fd, 1024, &mut bytes)?;
    Ok(bytes)
}

fn walk_journal(
    fd: &Fd,
    node: &[u8],
    expected_depth: Option<u16>,
    map: &mut root_checks::JournalMap,
) -> Result<(), &'static str> {
    let (depth, entries) = root_checks::extent_header(node)?;
    if expected_depth.is_some_and(|expected| depth != expected) {
        return Err("overlay: invalid actual journal extent depth");
    }
    for index in 0..entries {
        let (logical, physical, blocks) = root_checks::extent_entry(node, index)?;
        if depth == 0 {
            map.add_extent(logical, physical, blocks)?;
        } else {
            if logical != map.next_logical {
                return Err("overlay: journal index has a hole or overlap");
            }
            map.add_node(physical)?;
            let mut child = [0; 4096];
            pread_all(fd, physical * 4096, &mut child)?;
            walk_journal(fd, &child, Some(depth - 1), map)?;
        }
    }
    Ok(())
}

fn check_journal(
    fd: &Fd,
    sb: &[u8; 1024],
    expected: &DeviceExpectation,
    span: u64,
) -> Result<(), &'static str> {
    // ext4 replays the journal described by the actual inode, not s_jnl_blocks.
    // The fixed 4 KiB/256-byte-inode profile puts inode 8 in group zero.
    if u32::from_le_bytes([sb[0xe0], sb[0xe1], sb[0xe2], sb[0xe3]]) != 8 {
        return Err("overlay: unexpected journal inode");
    }
    let mut descriptor = [0; 32];
    pread_all(fd, 4096, &mut descriptor)?;
    let table = u64::from(u32::from_le_bytes([
        descriptor[8],
        descriptor[9],
        descriptor[10],
        descriptor[11],
    ]));
    let inode_offset = table * 4096 + 7 * 256;
    if table == 0 || inode_offset.checked_add(256).is_none_or(|end| end > span) {
        return Err("overlay: actual journal inode outside filesystem");
    }
    let mut inode = [0; 256];
    pread_all(fd, inode_offset, &mut inode)?;
    let blocks = root_checks::check_journal_inode(&inode, span)?;
    let mut map = root_checks::JournalMap::new(blocks, span)?;
    walk_journal(fd, &inode[0x28..0x64], None, &mut map)?;
    let first = map.finish()?;
    let mut journal = [0; 4096];
    pread_all(fd, first * 4096, &mut journal)?;
    if root_checks::check_journal(&journal, expected, span)? != blocks {
        return Err("overlay: actual journal inode and JBD2 lengths disagree");
    }
    Ok(())
}
fn measure(name: &[u8], expected: &DeviceExpectation, upper: bool) -> Result<Device, &'static str> {
    let prefix = path(b"/sys/block/", name, b"");
    let number = read_file(&path(&prefix, b"", b"/dev"), 64)?;
    let number = number.strip_suffix(b"\n").unwrap_or(&number);
    let at = number
        .iter()
        .position(|byte| *byte == b':')
        .ok_or("overlay: invalid sysfs device number")?;
    let major = u32::try_from(root_checks::decimal(&number[..at])?)
        .map_err(|_| "overlay: device major overflow")?;
    let minor = u32::try_from(root_checks::decimal(&number[at + 1..])?)
        .map_err(|_| "overlay: device minor overflow")?;
    let device_path = path(b"/dev/", name, b"");
    let fd = Fd::open(
        &device_path,
        if upper { libc::O_RDWR } else { libc::O_RDONLY },
    )?;
    let mut stat = io::stat_zeroed();
    if unsafe { libc::fstat(fd.0, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFBLK
        || libc::major(stat.st_rdev) != major
        || libc::minor(stat.st_rdev) != minor
    {
        return Err("overlay: block-special identity mismatch");
    }
    let sectors = root_checks::decimal(&read_file(&path(&prefix, b"", b"/size"), 64)?)?;
    let length = sectors
        .checked_mul(512)
        .ok_or("overlay: device size overflow")?;
    let sector_size = root_checks::decimal(&read_file(
        &path(&prefix, b"", b"/queue/logical_block_size"),
        64,
    )?)?;
    let ro = root_checks::decimal(&read_file(&path(&prefix, b"", b"/ro"), 64)?)?;
    if ro > 1 {
        return Err("overlay: invalid read-only state");
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
        return Err("overlay: kernel block geometry disagreement");
    }
    let facts = root_checks::DeviceFacts {
        number: DeviceNumber { major, minor },
        length_bytes: length,
        logical_sector_size: u32::try_from(sector_size)
            .map_err(|_| "overlay: sector size overflow")?,
        read_only: ro != 0,
    };
    root_checks::check_device(expected, facts)?;
    let sb = superblock(&fd)?;
    let span = root_checks::check_superblock(&sb, expected, upper)?;
    if upper {
        check_journal(&fd, &sb, expected, span)?;
    }
    Ok(Device {
        fd,
        path: device_path,
        facts,
        span,
    })
}

fn discover(root: &OverlayRoot) -> Result<(Device, Device), &'static str> {
    let dir = io::opendir(b"/sys/block");
    if dir.is_null() {
        return Err("overlay: cannot enumerate block devices");
    }
    // Close the directory on every failure, including duplicate identities.
    let result = (|| {
        let mut lower = None;
        let mut upper = None;
        let mut count = 0usize;
        let mut identities = root_checks::SerialDiscovery::default();
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = io::readdir(dir);
            if entry.is_null() {
                if io::errno() != 0 {
                    return Err("overlay: block enumeration failed");
                }
                break;
            }
            count += 1;
            if count > 4096 {
                return Err("overlay: too many block devices");
            }
            let name = unsafe { &(*entry).d_name };
            let end = name
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("overlay: unterminated block name")?;
            let name = unsafe { core::slice::from_raw_parts(name.as_ptr().cast::<u8>(), end) };
            if name == b"." || name == b".." {
                continue;
            }
            if name.is_empty() || name.contains(&b'/') {
                return Err("overlay: invalid block name");
            }
            let serial_path = path(b"/sys/block/", name, b"/serial");
            let serial_fd = io::open(
                &serial_path,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            );
            if serial_fd < 0 {
                if io::errno() == libc::ENOENT {
                    continue;
                }
                return Err("overlay: cannot read block serial");
            }
            let serial = read_fd(&Fd(serial_fd), 64)?;
            match identities.observe(&serial)? {
                Some(rootfs_spec::RootSerial::Lower) => {
                    io::write(io::STDERR, "init: overlay: validating lower device\n");
                    lower = Some(measure(name, &root.lower, false)?);
                }
                Some(rootfs_spec::RootSerial::Upper) => {
                    io::write(io::STDERR, "init: overlay: validating upper device\n");
                    upper = Some(measure(name, &root.upper, true)?);
                }
                None => {}
            }
        }
        identities.finish()?;
        let lower = lower.ok_or("overlay: missing lower serial")?;
        let upper = upper.ok_or("overlay: missing upper serial")?;
        if lower.facts.number == upper.facts.number {
            return Err("overlay: root devices alias");
        }
        Ok((lower, upper))
    })();
    if io::closedir(dir) != 0 && result.is_ok() {
        return Err("overlay: block directory close failed");
    }
    result
}

fn directory(path: &[u8], mode: u32) -> Result<(), &'static str> {
    if io::mkdir(path, mode) != 0 && io::errno() != libc::EEXIST {
        return Err("overlay: cannot create maintenance directory");
    }
    let fd = Fd::open(path, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut stat = io::stat_zeroed();
    if unsafe { libc::fstat(fd.0, &mut stat) } != 0
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != mode
    {
        return Err("overlay: unsafe maintenance directory");
    }
    Ok(())
}
fn upper_directories() -> Result<(), &'static str> {
    let root = Fd::open(UPPER, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut root_stat = io::stat_zeroed();
    if unsafe { libc::fstat(root.0, &mut root_stat) } != 0
        || root_stat.st_uid != 0
        || root_stat.st_gid != 0
    {
        return Err("overlay: unsafe upper filesystem root");
    }
    for (name, private) in [(b"upper\0".as_slice(), false), (b"work\0".as_slice(), true)] {
        let fd = unsafe {
            libc::openat(
                root.0,
                name.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("overlay: upper/work must be real directories");
        }
        let fd = Fd(fd);
        let mut stat = io::stat_zeroed();
        if unsafe { libc::fstat(fd.0, &mut stat) } != 0
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_dev != root_stat.st_dev
            || (private && stat.st_mode & 0o7777 != 0o700)
        {
            return Err("overlay: unsafe upper/work directory");
        }
    }
    Ok(())
}
fn module_defaults() -> Result<overlay_verify::ModuleDefaults, &'static str> {
    fn parameter(name: &[u8]) -> Result<bool, &'static str> {
        overlay_verify::sysfs_bool(&read_file(
            &path(b"/sys/module/overlay/parameters/", name, b""),
            16,
        )?)
    }
    Ok(overlay_verify::ModuleDefaults {
        index: parameter(b"index")?,
        metacopy: parameter(b"metacopy")?,
        redirect_dir: parameter(b"redirect_dir")?,
        redirect_always_follow: parameter(b"redirect_always_follow")?,
        xino_auto: parameter(b"xino_auto")?,
        nfs_export: parameter(b"nfs_export")?,
    })
}

pub(crate) fn assemble(root: OverlayRoot) -> Result<(), &'static str> {
    root.validate()
        .map_err(|_| "overlay: invalid managed root")?;
    let (lower, mut upper) = discover(&root)?;
    directory(b"/run/silo", 0o700)?;
    directory(ROOT, 0o700)?;
    directory(LOWER, 0o700)?;
    directory(UPPER, 0o700)?;
    if applets::system::mount_one(
        &lower.path,
        LOWER,
        Some(b"ext4"),
        libc::MS_RDONLY,
        Some(b"noload"),
    ) != 0
    {
        return Err("overlay: lower ro,noload mount failed");
    }
    if applets::system::mount_one(&upper.path, UPPER, Some(b"ext4"), 0, None) != 0 {
        return Err("overlay: upper replay mount failed");
    }
    let upper_mount = Fd::open(UPPER, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if unsafe { libc::syncfs(upper_mount.0) } != 0 {
        return Err("overlay: upper replay sync failed");
    }
    upper.span = root_checks::check_superblock(&superblock(&upper.fd)?, &root.upper, true)?;
    let predicted = rootfs_spec::upper_geometry::UpperGeometry::for_capacity(
        rootfs_spec::upper_geometry::UpperCapacity::new(root.upper.length_bytes)
            .map_err(|_| "overlay: invalid growth capacity")?,
    );
    if upper.span > predicted.filesystem_bytes {
        return Err("overlay: upper shrink prohibited");
    }
    if upper.span < predicted.filesystem_bytes {
        let blocks = root.upper.length_bytes / 4096;
        // EXT4_IOC_RESIZE_FS = _IOW('f',16,__u64), on upperfs, never overlay /.
        if unsafe { libc::ioctl(upper_mount.0, 0x40086610u32 as _, &blocks) } != 0 {
            return Err("overlay: upper resize ioctl failed");
        }
        if unsafe { libc::syncfs(upper_mount.0) } != 0 {
            return Err("overlay: upper resize sync failed");
        }
        upper.span = root_checks::check_superblock(&superblock(&upper.fd)?, &root.upper, true)?;
    }
    let tail = root_checks::check_achieved_span(root.upper.length_bytes, upper.span)?;
    check_journal(&upper.fd, &superblock(&upper.fd)?, &root.upper, upper.span)?;
    upper_directories()?;
    let mut options = b"lowerdir=/run/silo/rootfs/lower,upperdir=/run/silo/rootfs/upperfs/upper,workdir=/run/silo/rootfs/upperfs/work,".to_vec();
    options.extend_from_slice(rootfs_spec::OVERLAY_OPTIONS.as_bytes());
    if applets::system::mount_one(b"overlay", TARGET, Some(b"overlay"), 0, Some(&options)) != 0 {
        return Err("overlay: merged mount failed");
    }
    let mountinfo = read_file(b"/proc/self/mountinfo", MAX_MOUNTINFO)?;
    overlay_verify::verify_ext4_mount(
        &mountinfo,
        LOWER,
        (lower.facts.number.major, lower.facts.number.minor),
        true,
    )?;
    overlay_verify::verify_ext4_mount(
        &mountinfo,
        UPPER,
        (upper.facts.number.major, upper.facts.number.minor),
        false,
    )?;
    overlay_verify::verify(
        root.rendering_abi.as_str(),
        &mountinfo,
        module_defaults()?,
        overlay_verify::MountPaths {
            target: TARGET,
            lower: LOWER,
            upper: UPPER_DIR,
            work: WORK_DIR,
        },
    )?;
    temporary_directory(root.temporary_directory)?;
    let observation = Observation {
        root,
        lower_device: lower.facts.number,
        upper_device: upper.facts.number,
        upper_filesystem_bytes: upper.span,
        unusable_tail_bytes: tail,
        effective_overlay_profile: root.overlay_profile,
    };
    let mut bytes = [0; rootfs_spec::MAX_JSON_BYTES];
    let len = rootfs_spec::encode_observation(&observation, &mut bytes)
        .map_err(|_| "overlay: observation encoding failed")?;
    let fd = io::open(
        rootfs_spec::OBSERVATION_PATH.as_bytes(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        return Err("overlay: observation create failed");
    }
    let fd = Fd(fd);
    if io::write_buf(fd.0, &bytes[..len]) != len as isize {
        return Err("overlay: observation write failed");
    }
    if unsafe { libc::fsync(fd.0) } != 0 {
        return Err("overlay: observation sync failed");
    }
    io::write(io::STDERR, "init: overlay: verified managed root\n");
    Ok(())
}

fn temporary_directory(policy: TemporaryDirectory) -> Result<(), &'static str> {
    let target = b"/mnt/root/tmp";
    let created = io::mkdir(target, 0o1777) == 0;
    if !created && io::errno() != libc::EEXIST {
        return Err("overlay: /tmp directory creation failed");
    }
    let directory = Fd::open(target, libc::O_RDONLY | libc::O_DIRECTORY)?;
    if created && unsafe { libc::fchmod(directory.0, 0o1777) } != 0 {
        return Err("overlay: /tmp directory permissions failed");
    }
    if let TemporaryDirectory::Tmpfs { capacity_bytes } = policy {
        let mut options = b"mode=1777,size=".to_vec();
        let mut digits = [0; 20];
        let mut value = capacity_bytes;
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        options.extend_from_slice(&digits[start..]);
        if applets::system::mount_one(
            b"tmpfs",
            target,
            Some(b"tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(&options),
        ) != 0
        {
            return Err("overlay: selected /tmp tmpfs mount failed");
        }
    }
    Ok(())
}

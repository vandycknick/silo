//! Opaque raw root: resolve the bootstrap-selected filesystem on the
//! `silo-root` attachment and mount it at the handoff target. Pure policy is
//! in `::init::raw_root`; this module only measures and mounts.
use crate::owned::{path, read_fd, read_file, Fd};
use crate::{applets, block, io};
use ::init::raw_root::{
    self, ChildFacts, ChildSearch, PartitionExpectation, RootDiscovery, Selection,
};
use ::init::root_checks::decimal;
use rootfs_spec::{RawRoot, RootFilesystem};

const TARGET: &[u8] = b"/mnt/root";

pub(crate) fn mount(root: &RawRoot) -> Result<(), &'static str> {
    root.validate().map_err(|_| "raw: invalid root contract")?;
    let mut discovery = RootDiscovery::default();
    block::for_each_serial(|name, serial| discovery.observe(name, serial))?;
    let name = discovery.finish()?;
    let sysfs = path(b"/sys/block/", &name, b"");
    let queue = path(&sysfs, b"/queue", b"");
    let writable = !root.device.read_only;
    let parent = block::measure(&sysfs, &name, &queue, writable)?;
    raw_root::check_parent(&root.device, parent.facts)?;
    let geometry = disk_partition::Geometry::new(parent.facts.length_bytes)
        .map_err(|_| "raw: unsupported root attachment geometry")?;
    // The same held parent FD feeds the shared parser; nothing is reopened.
    let table = disk_partition::read_table(
        &mut block::HeldDevice(&parent.fd),
        geometry,
        disk_partition::ReadMode::GuestBoot,
    )
    .map_err(|error| match error {
        disk_partition::Error::Io { .. } => "raw: partition metadata read failed",
        _ => "raw: invalid or unsupported partition table",
    })?;
    let child = match raw_root::select(&table, root.selector)? {
        Selection::WholeDisk => None,
        Selection::Partition(selected) => Some(partition(
            &sysfs, &queue, writable, root, &parent, selected,
        )?),
    };
    // Both FDs stay held until the mounted identity has been verified.
    let device = child.as_ref().unwrap_or(&parent);
    let filesystem: &[u8] = match root.filesystem {
        RootFilesystem::Ext4 => b"ext4",
    };
    let flags = if root.device.read_only {
        libc::MS_RDONLY
    } else {
        0
    };
    if applets::system::mount_one(&device.path, TARGET, Some(filesystem), flags, None) != 0 {
        return Err("raw: root filesystem mount failed");
    }
    let mounted = Fd::open(TARGET, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let stat = mounted.stat()?;
    // f_type is __fsword_t (signed) on glibc and unsigned long on musl; the
    // filesystem magic is a nonnegative bit pattern either way.
    let magic = mounted.statfs()?.f_type as u64;
    raw_root::check_mounted_root(
        magic,
        (libc::major(stat.st_dev), libc::minor(stat.st_dev)),
        device.facts,
    )?;
    io::write(io::STDERR, "init: raw: verified bootstrap-selected root\n");
    Ok(())
}

/// Resolves the selected partition among the kernel children enumerated under
/// the root attachment's own sysfs directory, never by synthesized name.
fn partition(
    sysfs: &[u8],
    queue: &[u8],
    writable: bool,
    root: &RawRoot,
    parent: &block::Block,
    selected: PartitionExpectation,
) -> Result<block::Block, &'static str> {
    let mut search = ChildSearch::new(selected.number);
    block::for_each_entry(sysfs, |name, kind| {
        // Children are directories; device/, bdi/ and subsystem/ are links.
        if kind != libc::DT_DIR {
            return Ok(());
        }
        let attribute = path(sysfs, b"/", &path(name, b"/partition", b""));
        let fd = io::open(
            &attribute,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        );
        if fd < 0 {
            if io::errno() == libc::ENOENT {
                return Ok(());
            }
            return Err("raw: cannot read kernel partition number");
        }
        search.observe(name, &read_fd(&Fd(fd), 32)?)
    })?;
    let name = search.finish()?;
    let child_sysfs = path(sysfs, b"/", &name);
    let child = block::measure(&child_sysfs, &name, queue, writable)?;
    let number = decimal(&read_file(&path(&child_sysfs, b"/partition", b""), 32)?)?;
    let start_sector = decimal(&read_file(&path(&child_sysfs, b"/start", b""), 32)?)?;
    raw_root::check_child(
        &root.device,
        parent.facts,
        selected,
        ChildFacts {
            number: u32::try_from(number).map_err(|_| "raw: kernel partition number overflow")?,
            start_sector,
            device: child.facts,
        },
    )?;
    Ok(child)
}

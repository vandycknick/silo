//! Early cgroup-v2 layout. The mount moves with /sys during switch_root.
//! Init uses the existing no_std syscall helpers; nix requires std here.

use crate::{applets, io};

const ROOT: &[u8] = b"/sys/fs/cgroup";
const CONTROL_PROCS: &[u8] = b"/sys/fs/cgroup/silo/control/cgroup.procs";
const WORKLOAD_PROCS: &[u8] = b"/sys/fs/cgroup/silo/workloads/cgroup.procs";

pub(crate) fn prepare() -> Result<(), &'static str> {
    if applets::files::mkdir_parents(ROOT, 0o755) != 0 {
        return Err("cannot create cgroup mountpoint");
    }
    if applets::system::mount_one(b"cgroup2", ROOT, Some(b"cgroup2"), 0, None) != 0
        && io::errno() != libc::EBUSY
    {
        return Err("cannot mount cgroup v2");
    }
    // The v2 freezer is a core interface, not a subtree_control controller.
    for path in [
        b"/sys/fs/cgroup/silo".as_slice(),
        b"/sys/fs/cgroup/silo/control",
        b"/sys/fs/cgroup/silo/workloads",
        b"/sys/fs/cgroup/silo/activation",
    ] {
        if io::mkdir(path, 0o755) != 0 && io::errno() != libc::EEXIST {
            return Err("cannot create Silo cgroup layout");
        }
    }
    place(CONTROL_PROCS)
}

pub(crate) fn place_image_init() -> Result<(), &'static str> {
    place(WORKLOAD_PROCS)
}

fn place(path: &[u8]) -> Result<(), &'static str> {
    let fd = io::open(path, libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0);
    if fd < 0 {
        return Err("cannot open cgroup placement target");
    }
    let result = io::write_buf(fd, b"0");
    io::close(fd);
    if result != 1 {
        return Err("cannot enter Silo cgroup");
    }
    Ok(())
}

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::applets::get_arg;
use crate::io;

pub fn mount(argc: i32, argv: *const *const u8) -> i32 {
    if argc <= 1 {
        return print_mounts();
    }

    let mut fstype: Option<&[u8]> = None;
    let mut options: Option<&[u8]> = None;
    let mut args: [&[u8]; 2] = [b"", b""];
    let mut arg_count = 0usize;
    let mut index = 1;
    while index < argc {
        let Some(arg) = (unsafe { get_arg(argv, index) }) else {
            index += 1;
            continue;
        };
        if arg == b"-t" {
            index += 1;
            fstype = unsafe { get_arg(argv, index) };
        } else if arg == b"-o" {
            index += 1;
            options = unsafe { get_arg(argv, index) };
        } else if !arg.starts_with(b"-") && arg_count < args.len() {
            args[arg_count] = arg;
            arg_count += 1;
        }
        index += 1;
    }

    if arg_count != 2 {
        io::write(
            io::STDERR,
            "mount: usage: mount [-t type] [-o opts] SOURCE TARGET\n",
        );
        return 1;
    }

    let flags = options.map(parse_mount_flags).unwrap_or(0);
    if mount_one(args[0], args[1], fstype, flags, options) == 0 {
        0
    } else {
        io::write(io::STDERR, "mount: failed to mount ");
        io::write_buf(io::STDERR, args[0]);
        io::write(io::STDERR, " on ");
        io::write_buf(io::STDERR, args[1]);
        io::write(io::STDERR, "\n");
        1
    }
}

fn print_mounts() -> i32 {
    let fd = io::open(b"/proc/mounts", libc::O_RDONLY, 0);
    if fd < 0 {
        io::write(io::STDERR, "mount: cannot open /proc/mounts\n");
        return 1;
    }

    let mut buf = [0u8; 4096];
    loop {
        let len = io::read(fd, &mut buf);
        if len <= 0 {
            break;
        }
        io::write_buf(io::STDOUT, &buf[..len as usize]);
    }
    io::close(fd);
    0
}

pub(crate) fn mount_one(
    source: &[u8],
    target: &[u8],
    fstype: Option<&[u8]>,
    flags: libc::c_ulong,
    data: Option<&[u8]>,
) -> i32 {
    let mut source_buf = [0u8; io::PATH_MAX];
    let mut target_buf = [0u8; io::PATH_MAX];
    let mut fstype_buf = [0u8; 64];
    let mut data_buf = [0u8; io::PATH_MAX];
    if !io::path_to_cstr(source, &mut source_buf) || !io::path_to_cstr(target, &mut target_buf) {
        return -1;
    }

    let fstype_ptr = if let Some(value) = fstype {
        if !io::bytes_to_cstr(value, &mut fstype_buf) {
            return -1;
        }
        fstype_buf.as_ptr().cast::<libc::c_char>()
    } else {
        core::ptr::null()
    };
    let data_ptr = if let Some(value) = data {
        if !io::bytes_to_cstr(value, &mut data_buf) {
            return -1;
        }
        data_buf.as_ptr().cast::<libc::c_void>()
    } else {
        core::ptr::null()
    };

    unsafe {
        libc::mount(
            source_buf.as_ptr().cast::<libc::c_char>(),
            target_buf.as_ptr().cast::<libc::c_char>(),
            fstype_ptr,
            flags,
            data_ptr,
        )
    }
}

pub(crate) fn mount_block_auto(source: &[u8], target: &[u8]) -> i32 {
    const TYPES: &[&[u8]] = &[b"ext4", b"xfs", b"btrfs", b"erofs", b"squashfs"];
    for &fstype in TYPES {
        if mount_one(source, target, Some(fstype), 0, None) == 0 {
            return 0;
        }
    }
    -1
}

fn parse_mount_flags(options: &[u8]) -> libc::c_ulong {
    #[cfg(feature = "alloc")]
    {
        let mut flags = 0;
        for option in split_options(options) {
            if option == b"ro" {
                flags |= libc::MS_RDONLY;
            } else if option == b"nosuid" {
                flags |= libc::MS_NOSUID;
            } else if option == b"nodev" {
                flags |= libc::MS_NODEV;
            } else if option == b"noexec" {
                flags |= libc::MS_NOEXEC;
            } else if option == b"noatime" {
                flags |= libc::MS_NOATIME;
            }
        }
        flags
    }

    #[cfg(not(feature = "alloc"))]
    {
        let _ = options;
        0
    }
}

#[cfg(feature = "alloc")]
fn split_options(options: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for index in 0..=options.len() {
        if index == options.len() || options[index] == b',' {
            if start < index {
                out.push(&options[start..index]);
            }
            start = index + 1;
        }
    }
    out
}

use crate::applets::get_arg;
use crate::io;

pub fn umount(argc: i32, argv: *const *const u8) -> i32 {
    let mut flags = 0;
    let mut status = 0;
    let mut saw_path = false;
    let mut index = 1;
    while index < argc {
        let Some(arg) = (unsafe { get_arg(argv, index) }) else {
            index += 1;
            continue;
        };
        if arg == b"-l" {
            flags |= libc::MNT_DETACH;
        } else if arg == b"-f" {
            flags |= libc::MNT_FORCE;
        } else {
            saw_path = true;
            if umount_one(arg, flags) != 0 {
                io::write(io::STDERR, "umount: failed to unmount ");
                io::write_buf(io::STDERR, arg);
                io::write(io::STDERR, "\n");
                status = 1;
            }
        }
        index += 1;
    }

    if !saw_path {
        io::write(io::STDERR, "umount: usage: umount TARGET...\n");
        return 1;
    }
    status
}

pub(crate) fn umount_one(target: &[u8], flags: i32) -> i32 {
    let mut target_buf = [0u8; io::PATH_MAX];
    if !io::path_to_cstr(target, &mut target_buf) {
        return -1;
    }
    unsafe { libc::umount2(target_buf.as_ptr().cast::<libc::c_char>(), flags) }
}

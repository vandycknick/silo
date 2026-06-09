#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::io;

pub fn ps(_argc: i32, _argv: *const *const u8) -> i32 {
    io::write(io::STDOUT, "PID CMD\n");
    let dir = io::opendir(b"/proc");
    if dir.is_null() {
        io::write(io::STDERR, "ps: cannot open /proc\n");
        return 1;
    }

    loop {
        let entry = io::readdir(dir);
        if entry.is_null() {
            break;
        }
        let name = unsafe { (*entry).d_name.as_ptr().cast::<u8>() };
        let len = io::strlen(name);
        let pid = unsafe { core::slice::from_raw_parts(name, len) };
        if pid.is_empty() || !pid.iter().all(u8::is_ascii_digit) {
            continue;
        }
        print_process(pid);
    }

    io::closedir(dir);
    0
}

fn print_process(pid: &[u8]) {
    let mut path = Vec::new();
    path.extend_from_slice(b"/proc/");
    path.extend_from_slice(pid);
    path.extend_from_slice(b"/comm");

    io::write_buf(io::STDOUT, pid);
    io::write(io::STDOUT, " ");
    let fd = io::open(&path, libc::O_RDONLY, 0);
    if fd < 0 {
        io::write(io::STDOUT, "?\n");
        return;
    }
    let command = io::read_all(fd);
    io::close(fd);
    if command.is_empty() {
        io::write(io::STDOUT, "?\n");
    } else {
        io::write_buf(io::STDOUT, io::trim_ascii(&command));
        io::write(io::STDOUT, "\n");
    }
}

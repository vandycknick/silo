use crate::applets::{cstr_arg, get_arg};
use crate::io;

pub fn ls(argc: i32, argv: *const *const u8) -> i32 {
    let mut status = 0;
    if argc <= 1 {
        return list_path(b".");
    }

    let mut index = 1;
    while index < argc {
        let Some(path) = (unsafe { get_arg(argv, index) }) else {
            index += 1;
            continue;
        };
        if path.starts_with(b"-") {
            index += 1;
            continue;
        }
        if list_path(path) != 0 {
            status = 1;
        }
        index += 1;
    }
    status
}

fn list_path(path: &[u8]) -> i32 {
    let mut path_buf = [0u8; io::PATH_MAX];
    if !cstr_arg(path, &mut path_buf) {
        return 1;
    }

    let dir = unsafe { libc::opendir(path_buf.as_ptr().cast::<libc::c_char>()) };
    if dir.is_null() {
        let mut stat: libc::stat = unsafe { core::mem::zeroed() };
        if io::stat(path, &mut stat) == 0 {
            io::write_buf(io::STDOUT, path);
            io::write(io::STDOUT, "\n");
            return 0;
        }
        io::write(io::STDERR, "ls: cannot access ");
        io::write_buf(io::STDERR, path);
        io::write(io::STDERR, "\n");
        return 1;
    }

    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { (*entry).d_name.as_ptr().cast::<u8>() };
        let len = io::strlen(name);
        let bytes = unsafe { core::slice::from_raw_parts(name, len) };
        if bytes == b"." || bytes == b".." {
            continue;
        }
        io::write_buf(io::STDOUT, bytes);
        io::write(io::STDOUT, "\n");
    }

    unsafe {
        libc::closedir(dir);
    }
    0
}

use crate::applets::get_arg;
use crate::io;

pub fn mkdir(argc: i32, argv: *const *const u8) -> i32 {
    let mut parents = false;
    let mut mode = 0o755;
    let mut status = 0;
    let mut index = 1;

    while index < argc {
        let Some(arg) = (unsafe { get_arg(argv, index) }) else {
            index += 1;
            continue;
        };
        if arg == b"-p" {
            parents = true;
        } else if arg == b"-m" {
            index += 1;
            if let Some(value) = unsafe { get_arg(argv, index) } {
                if let Some(parsed) = io::parse_octal(value) {
                    mode = parsed;
                }
            }
        } else if parents {
            if mkdir_parents(arg, mode) != 0 {
                status = 1;
            }
        } else if io::mkdir(arg, mode) != 0 && io::errno() != libc::EEXIST {
            io::write(io::STDERR, "mkdir: cannot create ");
            io::write_buf(io::STDERR, arg);
            io::write(io::STDERR, "\n");
            status = 1;
        }
        index += 1;
    }

    status
}

pub(crate) fn mkdir_parents(path: &[u8], mode: u32) -> i32 {
    if path.is_empty() {
        return -1;
    }

    let mut current = [0u8; io::PATH_MAX];
    let mut len = 0;
    for (index, &byte) in path.iter().enumerate() {
        if len >= current.len() - 1 {
            return -1;
        }
        current[len] = byte;
        len += 1;
        if byte == b'/' && index > 0 {
            let part = &current[..len - 1];
            if !part.is_empty() {
                let ret = io::mkdir(part, mode);
                if ret != 0 && io::errno() != libc::EEXIST {
                    return ret;
                }
            }
        }
    }

    let ret = io::mkdir(&current[..len], mode);
    if ret != 0 && io::errno() == libc::EEXIST {
        0
    } else {
        ret
    }
}

use crate::applets::get_arg;
use crate::io;

pub fn cat(argc: i32, argv: *const *const u8) -> i32 {
    if argc <= 1 {
        copy_fd(0);
        return 0;
    }

    let mut status = 0;
    let mut index = 1;
    while index < argc {
        let Some(path) = (unsafe { get_arg(argv, index) }) else {
            index += 1;
            continue;
        };
        if path == b"-" {
            copy_fd(0);
            index += 1;
            continue;
        }
        let fd = io::open(path, libc::O_RDONLY, 0);
        if fd < 0 {
            io::write(io::STDERR, "cat: cannot open ");
            io::write_buf(io::STDERR, path);
            io::write(io::STDERR, "\n");
            status = 1;
        } else {
            copy_fd(fd);
            io::close(fd);
        }
        index += 1;
    }
    status
}

fn copy_fd(fd: i32) {
    let mut buf = [0u8; 4096];
    loop {
        let len = io::read(fd, &mut buf);
        if len <= 0 {
            break;
        }
        io::write_buf(io::STDOUT, &buf[..len as usize]);
    }
}

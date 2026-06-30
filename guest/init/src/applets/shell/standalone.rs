use crate::applets::get_arg;
use crate::io;

pub fn echo(argc: i32, argv: *const *const u8) -> i32 {
    let mut newline = true;
    let mut index = 1;
    if argc > 1 {
        if let Some(arg) = unsafe { get_arg(argv, 1) } {
            if arg == b"-n" {
                newline = false;
                index = 2;
            }
        }
    }

    let mut first = true;
    while index < argc {
        if let Some(arg) = unsafe { get_arg(argv, index) } {
            if !first {
                io::write(io::STDOUT, " ");
            }
            io::write_buf(io::STDOUT, arg);
            first = false;
        }
        index += 1;
    }
    if newline {
        io::write(io::STDOUT, "\n");
    }
    0
}

pub fn true_cmd(_argc: i32, _argv: *const *const u8) -> i32 {
    0
}

pub fn false_cmd(_argc: i32, _argv: *const *const u8) -> i32 {
    1
}

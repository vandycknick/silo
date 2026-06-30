#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::applets::get_arg;
use crate::io;

pub fn switch_root(argc: i32, argv: *const *const u8) -> i32 {
    if argc < 3 {
        io::write(
            io::STDERR,
            "switch_root: usage: switch_root NEWROOT INIT [ARGS...]\n",
        );
        return 1;
    }

    let Some(new_root) = (unsafe { get_arg(argv, 1) }) else {
        return 1;
    };

    let mut init_argv = Vec::new();
    let mut index = 2;
    while index < argc {
        if let Some(arg) = unsafe { get_arg(argv, index) } {
            init_argv.push(arg);
        }
        index += 1;
    }

    let init = init_argv
        .first()
        .copied()
        .unwrap_or(crate::init::DEFAULT_INIT);
    crate::init::do_switch_root(new_root, init, &init_argv)
}

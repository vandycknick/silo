use crate::applets::get_arg;
use crate::io;

pub fn cttyhack(argc: i32, argv: *const *const u8) -> i32 {
    io::setsid();
    let console = io::open(b"/dev/console", libc::O_RDWR, 0);
    if console >= 0 {
        io::dup2(console, io::STDIN);
        io::dup2(console, io::STDOUT);
        io::dup2(console, io::STDERR);
        if console > 2 {
            io::close(console);
        }
    }

    if argc > 1 {
        let Some(command) = (unsafe { get_arg(argv, 1) }) else {
            return 1;
        };
        let exec_argv = unsafe {
            core::slice::from_raw_parts(argv.add(1).cast::<*const libc::c_char>(), argc as usize)
        };
        io::execvp(command, exec_argv);
        io::write(io::STDERR, "cttyhack: exec failed: ");
        io::write_buf(io::STDERR, command);
        io::write(io::STDERR, "\n");
        return 127;
    }

    crate::init::exec_shell_once();
    127
}

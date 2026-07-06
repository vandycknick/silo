//! Shell entry points.
//!
//! Adapted from Armybox `src/applets/shell/entry.rs`.

use alloc::vec::Vec;

use crate::io;

use super::execute::execute_script;
use super::get_arg;
use super::state::Shell;

pub fn sh(argc: i32, argv: *const *const u8) -> i32 {
    let mut script_file: Option<&[u8]> = None;
    let mut command_string: Option<&[u8]> = None;
    let mut login_shell = false;
    let mut script_args: Vec<&[u8]> = Vec::new();

    let shell_name = unsafe { get_arg(argv, 0) }.unwrap_or(b"sh");

    let mut i = 1;
    while i < argc {
        let arg = match unsafe { get_arg(argv, i) } {
            Some(a) => a,
            None => {
                i += 1;
                continue;
            }
        };

        if script_file.is_some() {
            script_args.push(arg);
            i += 1;
            continue;
        }

        if arg == b"-c" {
            if i + 1 < argc {
                command_string = unsafe { get_arg(argv, i + 1) };
                i += 1;
            }
            i += 1;
            if command_string.is_some() {
                while i < argc {
                    if let Some(a) = unsafe { get_arg(argv, i) } {
                        script_args.push(a);
                    }
                    i += 1;
                }
            }
            break;
        } else if arg == b"-l" || arg == b"--login" {
            login_shell = true;
        } else if arg == b"-s"
            || arg == b"-i"
            || arg == b"-e"
            || arg == b"-x"
            || arg == b"-v"
            || arg == b"-n"
            || (!arg.is_empty() && arg[0] == b'-')
        {
        } else {
            script_file = Some(arg);
        }
        i += 1;
    }

    if let Some(cmd) = command_string {
        let mut shell = Shell::new(false);
        if login_shell {
            source_profile(&mut shell);
        }
        if !script_args.is_empty() {
            let dollar0 = script_args[0];
            let params: Vec<&[u8]> = script_args[1..].to_vec();
            shell.set_positional_params(dollar0, &params);
        } else {
            shell.set_positional_params(shell_name, &[]);
        }
        execute_script(&mut shell, cmd);
        return shell.last_status;
    }

    if let Some(file) = script_file {
        let fd = io::open(file, libc::O_RDONLY, 0);
        if fd < 0 {
            io::write(io::STDERR, "sh: cannot open ");
            io::write_buf(io::STDERR, file);
            io::write(io::STDERR, "\n");
            return 127;
        }
        let content = io::read_all(fd);
        io::close(fd);

        let mut shell = Shell::new(false);
        if login_shell {
            source_profile(&mut shell);
        }
        shell.set_positional_params(file, &script_args);
        execute_script(&mut shell, &content);
        return shell.last_status;
    }

    let interactive = io::isatty(0);
    let mut shell = Shell::new(interactive);
    shell.set_positional_params(shell_name, &[]);

    if login_shell || interactive {
        source_profile(&mut shell);
    }

    if interactive {
        io::write(io::STDOUT, "Silo sh\n");
    }

    interactive_loop(&mut shell);
    shell.exit_code
}

pub fn ash(argc: i32, argv: *const *const u8) -> i32 {
    sh(argc, argv)
}

pub fn dash(argc: i32, argv: *const *const u8) -> i32 {
    sh(argc, argv)
}

fn source_profile(shell: &mut Shell) {
    let profile = b"/etc/profile";
    let fd = io::open(profile, libc::O_RDONLY, 0);
    if fd >= 0 {
        let content = io::read_all(fd);
        io::close(fd);
        execute_script(shell, &content);
    }
}

pub(super) fn interactive_loop(shell: &mut Shell) {
    let mut line_buf = Vec::new();

    loop {
        if shell.should_exit {
            return;
        }

        if shell.interactive {
            io::write(io::STDOUT, "$ ");
        }

        line_buf.clear();
        loop {
            let mut c = [0u8; 1];
            let n = io::read(io::STDIN, &mut c);
            if n <= 0 {
                if line_buf.is_empty() {
                    shell.should_exit = true;
                    return;
                }
                break;
            }
            if c[0] == b'\n' {
                break;
            }
            line_buf.push(c[0]);
        }

        if line_buf.is_empty() {
            continue;
        }

        execute_script(shell, &line_buf);
    }
}

//! Shell built-in commands.
//!
//! Adapted from Armybox `src/applets/shell/builtins.rs`.

use alloc::vec::Vec;

use crate::io;
use crate::sys;

use super::execute::{execute_command, execute_script};
use super::parser::Command;
use super::state::Shell;
use super::util::{
    file_exists, file_size, is_directory, is_executable, is_readable, is_regular_file, is_symlink,
    is_writable,
};

pub(super) fn execute_builtin(shell: &mut Shell, cmd: &Command) -> bool {
    if cmd.args.is_empty() {
        return true;
    }

    let name = &cmd.args[0];

    if name == b"exit" {
        shell.should_exit = true;
        shell.exit_code = if cmd.args.len() > 1 {
            sys::parse_i64(&cmd.args[1]).unwrap_or(0) as i32
        } else {
            shell.last_status
        };
        return true;
    }

    if name == b"cd" {
        let path = if cmd.args.len() > 1 {
            &cmd.args[1]
        } else if let Some(home) = io::getenv(b"HOME") {
            home
        } else {
            b"/root"
        };

        if io::chdir(path) < 0 {
            io::write(io::STDERR, "cd: ");
            io::write_buf(io::STDERR, path);
            io::write(io::STDERR, ": No such directory\n");
            shell.last_status = 1;
        } else {
            shell.last_status = 0;
        }
        return true;
    }

    if name == b"pwd" {
        let mut buf = [0u8; 4096];
        if let Some(cwd) = io::getcwd(&mut buf) {
            io::write_buf(io::STDOUT, cwd);
            io::write(io::STDOUT, "\n");
            shell.last_status = 0;
        } else {
            shell.last_status = 1;
        }
        return true;
    }

    if name == b"export" {
        if cmd.args.len() > 1 {
            let arg = &cmd.args[1];
            if let Some(eq_pos) = arg.iter().position(|&c| c == b'=') {
                let name_part = &arg[..eq_pos];
                let value_part = &arg[eq_pos + 1..];
                io::setenv(name_part, value_part, true);
            } else if let Some(value) = shell.get_var(arg) {
                io::setenv(arg, value, true);
            }
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"unset" {
        if cmd.args.len() > 1 {
            let var = &cmd.args[1];
            shell.variables.remove(var);
            io::unsetenv(var);
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"echo" {
        let mut newline = true;
        let mut start = 1;

        if cmd.args.len() > 1 && cmd.args[1] == b"-n" {
            newline = false;
            start = 2;
        }

        let mut first = true;
        for arg in &cmd.args[start..] {
            if !first {
                io::write(io::STDOUT, " ");
            }
            io::write_buf(io::STDOUT, arg);
            first = false;
        }
        if newline {
            io::write(io::STDOUT, "\n");
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"test" || name == b"[" {
        shell.last_status = execute_test(&cmd.args[1..]);
        return true;
    }

    if name == b"true" {
        shell.last_status = 0;
        return true;
    }

    if name == b"false" {
        shell.last_status = 1;
        return true;
    }

    if name == b":" {
        shell.last_status = 0;
        return true;
    }

    if name == b"source" || name == b"." {
        if cmd.args.len() > 1 {
            let fd = io::open(&cmd.args[1], libc::O_RDONLY, 0);
            if fd >= 0 {
                let content = io::read_all(fd);
                io::close(fd);
                execute_script(shell, &content);
            } else {
                io::write(io::STDERR, "sh: cannot open ");
                io::write_buf(io::STDERR, &cmd.args[1]);
                io::write(io::STDERR, "\n");
                shell.last_status = 1;
            }
        }
        return true;
    }

    if name == b"read" {
        if cmd.args.len() > 1 {
            let var_name = &cmd.args[1];
            let mut line = Vec::new();
            let mut buf = [0u8; 1];
            loop {
                let n = io::read(io::STDIN, &mut buf);
                if n <= 0 || buf[0] == b'\n' {
                    break;
                }
                line.push(buf[0]);
            }
            shell.set_var(var_name, &line);
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"exec" {
        if cmd.args.len() > 1 {
            let mut cmd_exec = Command::new();
            for arg in &cmd.args[1..] {
                cmd_exec.args.push(arg.clone());
            }
            execute_command(&cmd_exec);
            shell.last_status = 127;
        }
        return true;
    }

    if name == b"set" {
        shell.last_status = 0;
        return true;
    }

    if name == b"shift" {
        let n = if cmd.args.len() > 1 {
            let mut val = 0usize;
            for &c in &cmd.args[1] {
                if c.is_ascii_digit() {
                    val = val * 10 + (c - b'0') as usize;
                }
            }
            if val == 0 {
                1
            } else {
                val
            }
        } else {
            1
        };

        let param_count = shell.param_count();
        if n > param_count {
            shell.last_status = 1;
        } else {
            for _ in 0..n {
                if shell.positional_params.len() > 1 {
                    shell.positional_params.remove(1);
                }
            }
            shell.last_status = 0;
        }
        return true;
    }

    if name == b"return" {
        shell.last_status = if cmd.args.len() > 1 {
            sys::parse_i64(&cmd.args[1]).unwrap_or(0) as i32
        } else {
            0
        };
        return true;
    }

    if name == b"eval" {
        if cmd.args.len() > 1 {
            let mut line = Vec::new();
            for (i, arg) in cmd.args[1..].iter().enumerate() {
                if i > 0 {
                    line.push(b' ');
                }
                line.extend_from_slice(arg);
            }
            execute_script(shell, &line);
        }
        return true;
    }

    if name == b"alias" {
        if cmd.args.len() == 1 {
            for (name, value) in &shell.aliases {
                io::write_buf(io::STDOUT, name);
                io::write(io::STDOUT, "='");
                io::write_buf(io::STDOUT, value);
                io::write(io::STDOUT, "'\n");
            }
        } else {
            for arg in &cmd.args[1..] {
                if let Some(eq_pos) = arg.iter().position(|&c| c == b'=') {
                    let alias_name = &arg[..eq_pos];
                    let alias_value = &arg[eq_pos + 1..];
                    shell
                        .aliases
                        .insert(alias_name.to_vec(), alias_value.to_vec());
                } else if let Some(value) = shell.aliases.get(arg.as_slice()) {
                    io::write_buf(io::STDOUT, arg);
                    io::write(io::STDOUT, " is an alias for '");
                    io::write_buf(io::STDOUT, value);
                    io::write(io::STDOUT, "'\n");
                } else {
                    io::write(io::STDERR, "sh: alias: ");
                    io::write_buf(io::STDERR, arg);
                    io::write(io::STDERR, ": not found\n");
                    shell.last_status = 1;
                    return true;
                }
            }
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"unalias" {
        if cmd.args.len() > 1 {
            if cmd.args[1] == b"-a" {
                shell.aliases.clear();
            } else {
                for arg in &cmd.args[1..] {
                    shell.aliases.remove(arg.as_slice());
                }
            }
        }
        shell.last_status = 0;
        return true;
    }

    if name == b"type" {
        if cmd.args.len() > 1 {
            let target = &cmd.args[1];
            let builtins: &[&[u8]] = &[
                b"exit", b"cd", b"pwd", b"export", b"unset", b"echo", b"test", b"[", b"true",
                b"false", b":", b"source", b".", b"read", b"exec", b"set", b"shift", b"return",
                b"eval", b"alias", b"unalias", b"type",
            ];
            if builtins.contains(&target.as_slice()) {
                io::write_buf(io::STDOUT, target);
                io::write(io::STDOUT, " is a shell builtin\n");
            } else if shell.aliases.contains_key(target.as_slice()) {
                io::write_buf(io::STDOUT, target);
                io::write(io::STDOUT, " is an alias for '");
                if let Some(value) = shell.aliases.get(target.as_slice()) {
                    io::write_buf(io::STDOUT, value);
                }
                io::write(io::STDOUT, "'\n");
            } else {
                io::write_buf(io::STDOUT, target);
                io::write(io::STDOUT, " is an external command\n");
            }
        }
        shell.last_status = 0;
        return true;
    }

    false
}

pub(super) fn execute_test(args: &[Vec<u8>]) -> i32 {
    if args.is_empty() {
        return 1;
    }

    let args: Vec<&[u8]> = args
        .iter()
        .map(|a| a.as_slice())
        .filter(|a| *a != b"]")
        .collect();

    if args.is_empty() {
        return 1;
    }

    if args.len() == 1 {
        return if args[0].is_empty() { 1 } else { 0 };
    }

    if args.len() == 2 {
        let op = args[0];
        let arg = args[1];

        if op == b"-n" {
            return if arg.is_empty() { 1 } else { 0 };
        }
        if op == b"-z" {
            return if arg.is_empty() { 0 } else { 1 };
        }
        if op == b"-e" || op == b"-a" {
            return if file_exists(arg) { 0 } else { 1 };
        }
        if op == b"-f" {
            return if is_regular_file(arg) { 0 } else { 1 };
        }
        if op == b"-d" {
            return if is_directory(arg) { 0 } else { 1 };
        }
        if op == b"-r" {
            return if is_readable(arg) { 0 } else { 1 };
        }
        if op == b"-w" {
            return if is_writable(arg) { 0 } else { 1 };
        }
        if op == b"-x" {
            return if is_executable(arg) { 0 } else { 1 };
        }
        if op == b"-s" {
            return if file_size(arg) > 0 { 0 } else { 1 };
        }
        if op == b"-L" || op == b"-h" {
            return if is_symlink(arg) { 0 } else { 1 };
        }
        if op == b"!" {
            return execute_test(&[arg.to_vec()]) ^ 1;
        }
    }

    if args.len() == 3 {
        let left = args[0];
        let op = args[1];
        let right = args[2];

        if op == b"=" || op == b"==" {
            return if left == right { 0 } else { 1 };
        }
        if op == b"!=" {
            return if left != right { 0 } else { 1 };
        }

        let ln = sys::parse_i64(left).unwrap_or(0);
        let rn = sys::parse_i64(right).unwrap_or(0);

        if op == b"-eq" {
            return if ln == rn { 0 } else { 1 };
        }
        if op == b"-ne" {
            return if ln != rn { 0 } else { 1 };
        }
        if op == b"-lt" {
            return if ln < rn { 0 } else { 1 };
        }
        if op == b"-le" {
            return if ln <= rn { 0 } else { 1 };
        }
        if op == b"-gt" {
            return if ln > rn { 0 } else { 1 };
        }
        if op == b"-ge" {
            return if ln >= rn { 0 } else { 1 };
        }
    }

    1
}

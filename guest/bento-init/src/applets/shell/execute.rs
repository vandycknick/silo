//! Shell command execution.
//!
//! Adapted from Armybox `src/applets/shell/execute.rs`.

use alloc::vec::Vec;

use crate::io;

use super::builtins::execute_builtin;
use super::control::{execute_case, execute_for, execute_if, execute_until, execute_while};
use super::expand::expand_string;
use super::parser::{parse_assignment_value, tokenize, Command, Token};
use super::state::Shell;
use super::util::{find_word_end, is_keyword_boundary, skip_whitespace_and_comments};

pub(super) fn execute_script(shell: &mut Shell, script: &[u8]) {
    let mut pos = 0;
    while pos < script.len() && !shell.should_exit {
        pos = execute_statement(shell, script, pos);
    }
}

pub(super) fn execute_statement(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let pos = skip_whitespace_and_comments(script, start);
    if pos >= script.len() {
        return pos;
    }

    let word_end = find_word_end(script, pos);
    let first_word = &script[pos..word_end];
    let at_boundary = is_keyword_boundary(script, word_end);

    if at_boundary {
        if first_word == b"if" {
            return execute_if(shell, script, pos);
        }
        if first_word == b"while" {
            return execute_while(shell, script, pos);
        }
        if first_word == b"until" {
            return execute_until(shell, script, pos);
        }
        if first_word == b"for" {
            return execute_for(shell, script, pos);
        }
        if first_word == b"case" {
            return execute_case(shell, script, pos);
        }
    }

    execute_simple_line(shell, script, pos)
}

pub(super) fn execute_simple_line(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let pos = start;
    let mut end = pos;
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while end < script.len() {
        let c = script[end];
        if in_single_quote {
            if c == b'\'' {
                in_single_quote = false;
            }
            end += 1;
        } else if in_double_quote {
            if c == b'"' {
                in_double_quote = false;
            } else if c == b'\\' && end + 1 < script.len() {
                end += 1;
            }
            end += 1;
        } else if c == b'\'' {
            in_single_quote = true;
            end += 1;
        } else if c == b'"' {
            in_double_quote = true;
            end += 1;
        } else if c == b'\n' || c == b';' {
            break;
        } else {
            end += 1;
        }
    }

    let line = &script[pos..end];
    if !line.trim_ascii().is_empty() {
        execute_line(shell, line);
    }

    if end < script.len() && (script[end] == b'\n' || script[end] == b';') {
        end + 1
    } else {
        end
    }
}

pub(super) fn execute_line(shell: &mut Shell, line: &[u8]) {
    let line = line.trim_ascii();
    if line.is_empty() || line[0] == b'#' {
        return;
    }

    if let Some(eq_pos) = line.iter().position(|&c| c == b'=') {
        let before_eq = &line[..eq_pos];
        if !before_eq.is_empty()
            && (before_eq[0].is_ascii_alphabetic() || before_eq[0] == b'_')
            && before_eq
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || c == b'_')
        {
            let after_eq = &line[eq_pos + 1..];
            let (value, rest) = parse_assignment_value(after_eq);
            let expanded_value = expand_string(shell, &value);

            if rest.trim_ascii().is_empty() {
                shell.set_var(before_eq, &expanded_value);
                shell.last_status = 0;
                return;
            }

            shell.set_var(before_eq, &expanded_value);
            execute_line(shell, rest.trim_ascii());
            return;
        }
    }

    let tokens = tokenize(shell, line);
    if tokens.is_empty() {
        return;
    }

    if let Some(Token::Word(first)) = tokens.first() {
        if let Some(alias_value) = shell.aliases.get(first.as_slice()) {
            let mut new_line = alias_value.clone();
            let mut skip = 0;
            while skip < line.len() && (line[skip] == b' ' || line[skip] == b'\t') {
                skip += 1;
            }
            while skip < line.len()
                && line[skip] != b' '
                && line[skip] != b'\t'
                && line[skip] != b'\n'
                && line[skip] != b';'
                && line[skip] != b'|'
                && line[skip] != b'&'
                && line[skip] != b'>'
                && line[skip] != b'<'
            {
                skip += 1;
            }
            if skip < line.len() {
                new_line.extend_from_slice(&line[skip..]);
            }
            execute_line(shell, &new_line);
            return;
        }
    }

    execute_pipeline(shell, &tokens);
}

pub(super) fn execute_pipeline(shell: &mut Shell, tokens: &[Token]) {
    let mut segments: Vec<(Vec<Token>, Option<Token>)> = Vec::new();
    let mut current_segment: Vec<Token> = Vec::new();

    for token in tokens {
        match token {
            Token::AndIf | Token::OrIf => {
                segments.push((current_segment, Some(token.clone())));
                current_segment = Vec::new();
            }
            _ => current_segment.push(token.clone()),
        }
    }
    if !current_segment.is_empty() {
        segments.push((current_segment, None));
    }

    let mut previous_connector: Option<Token> = None;
    for (segment, connector_after) in segments {
        let should_execute = match previous_connector {
            Some(Token::AndIf) => shell.last_status == 0,
            Some(Token::OrIf) => shell.last_status != 0,
            _ => true,
        };

        if should_execute {
            execute_simple_pipeline(shell, &segment);
        }
        previous_connector = connector_after;
    }
}

pub(super) fn execute_simple_pipeline(shell: &mut Shell, tokens: &[Token]) {
    let mut commands: Vec<Command> = Vec::new();
    let mut current = Command::new();

    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Word(w) => current.args.push(w.clone()),
            Token::Pipe => {
                if !current.args.is_empty() {
                    commands.push(current);
                    current = Command::new();
                }
            }
            Token::RedirectOut => {
                if i + 1 < tokens.len() {
                    if let Token::Word(f) = &tokens[i + 1] {
                        current.stdout_file = Some(f.clone());
                        current.stdout_append = false;
                        i += 1;
                    }
                }
            }
            Token::RedirectAppend => {
                if i + 1 < tokens.len() {
                    if let Token::Word(f) = &tokens[i + 1] {
                        current.stdout_file = Some(f.clone());
                        current.stdout_append = true;
                        i += 1;
                    }
                }
            }
            Token::RedirectIn => {
                if i + 1 < tokens.len() {
                    if let Token::Word(f) = &tokens[i + 1] {
                        current.stdin_file = Some(f.clone());
                        i += 1;
                    }
                }
            }
            Token::RedirectErr => {
                if i + 1 < tokens.len() {
                    if let Token::Word(f) = &tokens[i + 1] {
                        current.stderr_file = Some(f.clone());
                        i += 1;
                    }
                }
            }
            Token::Background => current.background = true,
            Token::AndIf | Token::OrIf => {}
        }
        i += 1;
    }

    if !current.args.is_empty() {
        commands.push(current);
    }

    if commands.is_empty() {
        return;
    }

    if commands.len() == 1 && !commands[0].background {
        let cmd = &commands[0];
        let has_redirects =
            cmd.stdout_file.is_some() || cmd.stdin_file.is_some() || cmd.stderr_file.is_some();

        if has_redirects {
            let saved_stdout = if cmd.stdout_file.is_some() {
                io::dup(io::STDOUT)
            } else {
                -1
            };
            let saved_stdin = if cmd.stdin_file.is_some() {
                io::dup(io::STDIN)
            } else {
                -1
            };
            let saved_stderr = if cmd.stderr_file.is_some() {
                io::dup(io::STDERR)
            } else {
                -1
            };

            let mut redirect_ok = true;

            if let Some(ref f) = cmd.stdin_file {
                let fd = io::open(f, libc::O_RDONLY, 0);
                if fd < 0 {
                    io::write(io::STDERR, "sh: ");
                    io::write_buf(io::STDERR, f);
                    io::write(io::STDERR, ": No such file or directory\n");
                    redirect_ok = false;
                    shell.last_status = 1;
                } else {
                    io::dup2(fd, io::STDIN);
                    io::close(fd);
                }
            }

            if redirect_ok {
                if let Some(ref f) = cmd.stdout_file {
                    let flags = if cmd.stdout_append {
                        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND
                    } else {
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC
                    };
                    let fd = io::open(f, flags, 0o644);
                    if fd < 0 {
                        io::write(io::STDERR, "sh: cannot create ");
                        io::write_buf(io::STDERR, f);
                        io::write(io::STDERR, "\n");
                        redirect_ok = false;
                        shell.last_status = 1;
                    } else {
                        io::dup2(fd, io::STDOUT);
                        io::close(fd);
                    }
                }
            }

            if redirect_ok {
                if let Some(ref f) = cmd.stderr_file {
                    let fd = io::open(f, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
                    if fd >= 0 {
                        io::dup2(fd, io::STDERR);
                        io::close(fd);
                    }
                }
            }

            if redirect_ok {
                execute_builtin(shell, cmd);
            }

            if saved_stdout >= 0 {
                io::dup2(saved_stdout, io::STDOUT);
                io::close(saved_stdout);
            }
            if saved_stdin >= 0 {
                io::dup2(saved_stdin, io::STDIN);
                io::close(saved_stdin);
            }
            if saved_stderr >= 0 {
                io::dup2(saved_stderr, io::STDERR);
                io::close(saved_stderr);
            }

            return;
        }

        if execute_builtin(shell, cmd) {
            return;
        }
    }

    let n = commands.len();
    let mut prev_pipe_read: i32 = -1;
    let mut pids: Vec<i32> = Vec::new();

    for (i, cmd) in commands.iter().enumerate() {
        let is_last = i == n - 1;

        let mut pipe_fds = [-1i32; 2];
        if !is_last {
            unsafe {
                if libc::pipe(pipe_fds.as_mut_ptr()) < 0 {
                    io::write(io::STDERR, "sh: pipe failed\n");
                    return;
                }
            }
        }

        let pid = io::fork();
        if pid < 0 {
            io::write(io::STDERR, "sh: fork failed\n");
            return;
        }

        if pid == 0 {
            if prev_pipe_read >= 0 {
                io::dup2(prev_pipe_read, io::STDIN);
                io::close(prev_pipe_read);
            }

            if !is_last {
                io::close(pipe_fds[0]);
                io::dup2(pipe_fds[1], io::STDOUT);
                io::close(pipe_fds[1]);
            }

            if let Some(ref f) = cmd.stdin_file {
                let fd = io::open(f, libc::O_RDONLY, 0);
                if fd < 0 {
                    io::write_buf(io::STDERR, f);
                    io::write(io::STDERR, ": No such file or directory\n");
                    io::exit(1);
                }
                io::dup2(fd, io::STDIN);
                io::close(fd);
            }

            if let Some(ref f) = cmd.stdout_file {
                let flags = if cmd.stdout_append {
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND
                } else {
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC
                };
                let fd = io::open(f, flags, 0o644);
                if fd < 0 {
                    io::write(io::STDERR, "sh: cannot create ");
                    io::write_buf(io::STDERR, f);
                    io::write(io::STDERR, "\n");
                    io::exit(1);
                }
                io::dup2(fd, io::STDOUT);
                io::close(fd);
            }

            if let Some(ref f) = cmd.stderr_file {
                let fd = io::open(f, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
                if fd >= 0 {
                    io::dup2(fd, io::STDERR);
                    io::close(fd);
                }
            }

            for (k, v) in &shell.variables {
                io::setenv(k, v, true);
            }

            execute_command(cmd);
            io::exit(127);
        }

        pids.push(pid);

        if prev_pipe_read >= 0 {
            io::close(prev_pipe_read);
        }

        if !is_last {
            io::close(pipe_fds[1]);
            prev_pipe_read = pipe_fds[0];
        }
    }

    let background = commands.last().map(|c| c.background).unwrap_or(false);
    if !background {
        for pid in pids {
            let mut status: i32 = 0;
            io::waitpid(pid, &mut status, 0);
            shell.last_status = io::status_code(status);
        }
    }
}

pub(super) fn execute_command(cmd: &Command) {
    if cmd.args.is_empty() {
        return;
    }

    let mut argv_ptrs: Vec<*const libc::c_char> = Vec::new();
    let mut argv_storage: Vec<Vec<u8>> = Vec::new();

    for arg in &cmd.args {
        let mut s = arg.clone();
        s.push(0);
        argv_storage.push(s);
    }

    for s in &argv_storage {
        argv_ptrs.push(s.as_ptr().cast::<libc::c_char>());
    }
    argv_ptrs.push(core::ptr::null());

    unsafe {
        libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
    }

    io::write(io::STDERR, "sh: ");
    io::write_buf(io::STDERR, &cmd.args[0]);
    io::write(io::STDERR, ": command not found\n");
}

//! Shell variable and command expansion.
//!
//! Adapted from Armybox `src/applets/shell/expand.rs`.

use alloc::vec::Vec;

use crate::io;

use super::arithmetic::eval_arithmetic;
use super::state::Shell;
use super::util::{format_number, format_signed};

pub(super) fn expand_dollar(shell: &Shell, input: &[u8], start: usize) -> (Vec<u8>, usize) {
    let mut pos = start + 1;

    if pos >= input.len() {
        return (b"$".to_vec(), pos);
    }

    let c = input[pos];

    if c == b'?' {
        let mut buf = [0u8; 16];
        let s = format_number(shell.last_status as u64, &mut buf);
        return (s.to_vec(), pos + 1);
    }

    if c == b'$' {
        let pid = io::getpid();
        let mut buf = [0u8; 16];
        let s = format_number(pid as u64, &mut buf);
        return (s.to_vec(), pos + 1);
    }

    if c == b'#' {
        let mut buf = [0u8; 16];
        let s = format_number(shell.param_count() as u64, &mut buf);
        return (s.to_vec(), pos + 1);
    }

    if c.is_ascii_digit() {
        let idx = (c - b'0') as usize;
        let value = shell.get_positional(idx).unwrap_or(b"");
        return (value.to_vec(), pos + 1);
    }

    if c == b'@' {
        let mut result = Vec::new();
        let count = shell.param_count();
        for i in 1..=count {
            if i > 1 {
                result.push(b' ');
            }
            if let Some(p) = shell.get_positional(i) {
                result.extend_from_slice(p);
            }
        }
        return (result, pos + 1);
    }

    if c == b'*' {
        let mut result = Vec::new();
        let count = shell.param_count();
        for i in 1..=count {
            if i > 1 {
                result.push(b' ');
            }
            if let Some(p) = shell.get_positional(i) {
                result.extend_from_slice(p);
            }
        }
        return (result, pos + 1);
    }

    if c == b'(' && pos + 1 < input.len() && input[pos + 1] == b'(' {
        pos += 2;
        let start_expr = pos;
        let mut depth = 2;
        while pos < input.len() && depth > 0 {
            if input[pos] == b'(' {
                depth += 1;
            } else if input[pos] == b')' {
                depth -= 1;
            }
            pos += 1;
        }
        let expr = &input[start_expr..pos - 2];
        let result = eval_arithmetic(shell, expr);
        let mut buf = [0u8; 20];
        let s = format_signed(result, &mut buf);
        return (s.to_vec(), pos);
    }

    if c == b'(' {
        pos += 1;
        let start_cmd = pos;
        let mut depth = 1;
        while pos < input.len() && depth > 0 {
            if input[pos] == b'(' {
                depth += 1;
            } else if input[pos] == b')' {
                depth -= 1;
            }
            pos += 1;
        }
        let cmd = &input[start_cmd..pos - 1];
        let output = execute_capture(shell, cmd);
        return (output.trim_ascii_end().to_vec(), pos);
    }

    let mut var_name = Vec::new();
    if c == b'{' {
        pos += 1;
        let length_op = pos < input.len()
            && input[pos] == b'#'
            && pos + 1 < input.len()
            && input[pos + 1] != b'}';

        if length_op {
            pos += 1;
        }

        while pos < input.len()
            && input[pos] != b'}'
            && input[pos] != b':'
            && input[pos] != b'-'
            && input[pos] != b'+'
            && input[pos] != b'='
            && (input[pos] != b'?' || var_name.is_empty())
        {
            var_name.push(input[pos]);
            pos += 1;
        }

        let mut op: u8 = 0;
        let mut colon_variant = false;
        if pos < input.len() && input[pos] != b'}' {
            if input[pos] == b':' {
                colon_variant = true;
                pos += 1;
                if pos < input.len() && input[pos] != b'}' {
                    op = input[pos];
                    pos += 1;
                }
            } else {
                op = input[pos];
                pos += 1;
            }

            let mut operand = Vec::new();
            let mut depth = 1;
            while pos < input.len() && depth > 0 {
                if input[pos] == b'{' {
                    depth += 1;
                } else if input[pos] == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                operand.push(input[pos]);
                pos += 1;
            }
            if pos < input.len() && input[pos] == b'}' {
                pos += 1;
            }

            let expanded_operand = expand_string(shell, &operand);
            let value = lookup_var(shell, &var_name);
            let is_unset_or_null = match &value {
                None => true,
                Some(v) if colon_variant && v.is_empty() => true,
                _ => false,
            };

            if length_op {
                let len = value.map(|v| v.len()).unwrap_or(0);
                let mut buf = [0u8; 16];
                let s = format_number(len as u64, &mut buf);
                return (s.to_vec(), pos);
            }

            match op {
                b'-' => {
                    if is_unset_or_null {
                        return (expanded_operand, pos);
                    }
                    return (value.unwrap_or_default(), pos);
                }
                b'+' => {
                    if is_unset_or_null {
                        return (Vec::new(), pos);
                    }
                    return (expanded_operand, pos);
                }
                b'=' => {
                    if is_unset_or_null {
                        return (expanded_operand, pos);
                    }
                    return (value.unwrap_or_default(), pos);
                }
                b'?' => {
                    if is_unset_or_null {
                        io::write(io::STDERR, "sh: ");
                        io::write_buf(io::STDERR, &var_name);
                        io::write(io::STDERR, ": ");
                        if expanded_operand.is_empty() {
                            io::write(io::STDERR, "parameter not set\n");
                        } else {
                            io::write_buf(io::STDERR, &expanded_operand);
                            io::write(io::STDERR, "\n");
                        }
                        return (Vec::new(), pos);
                    }
                    return (value.unwrap_or_default(), pos);
                }
                _ => return (value.unwrap_or_default(), pos),
            }
        } else {
            if pos < input.len() && input[pos] == b'}' {
                pos += 1;
            }

            if length_op {
                let value = lookup_var(shell, &var_name);
                let len = value.map(|v| v.len()).unwrap_or(0);
                let mut buf = [0u8; 16];
                let s = format_number(len as u64, &mut buf);
                return (s.to_vec(), pos);
            }
        }
    } else {
        while pos < input.len() && (input[pos].is_ascii_alphanumeric() || input[pos] == b'_') {
            var_name.push(input[pos]);
            pos += 1;
        }
    }

    if var_name.is_empty() {
        return (b"$".to_vec(), start + 1);
    }

    match lookup_var(shell, &var_name) {
        Some(v) => (v, pos),
        None => (Vec::new(), pos),
    }
}

fn lookup_var(shell: &Shell, name: &[u8]) -> Option<Vec<u8>> {
    if name.len() == 1 && name[0].is_ascii_digit() {
        let idx = (name[0] - b'0') as usize;
        return shell.get_positional(idx).map(|v| v.to_vec());
    }

    if !name.is_empty() && name.iter().all(|&c| c.is_ascii_digit()) {
        let idx = parse_usize(name);
        return shell.get_positional(idx).map(|v| v.to_vec());
    }

    if name == b"#" {
        let mut buf = [0u8; 16];
        let s = format_number(shell.param_count() as u64, &mut buf);
        return Some(s.to_vec());
    }
    if name == b"@" || name == b"*" {
        let mut result = Vec::new();
        let count = shell.param_count();
        for i in 1..=count {
            if i > 1 {
                result.push(b' ');
            }
            if let Some(p) = shell.get_positional(i) {
                result.extend_from_slice(p);
            }
        }
        return Some(result);
    }
    if name == b"?" {
        let mut buf = [0u8; 16];
        let s = format_number(shell.last_status as u64, &mut buf);
        return Some(s.to_vec());
    }

    if let Some(value) = shell.get_var(name) {
        return Some(value.to_vec());
    }

    io::getenv(name).map(|value| value.to_vec())
}

fn parse_usize(s: &[u8]) -> usize {
    let mut n: usize = 0;
    for &c in s {
        if c.is_ascii_digit() {
            n = n.wrapping_mul(10).wrapping_add((c - b'0') as usize);
        }
    }
    n
}

pub(super) fn expand_string(shell: &Shell, input: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < input.len() {
        if input[pos] == b'$' {
            let (expanded, new_pos) = expand_dollar(shell, input, pos);
            result.extend_from_slice(&expanded);
            pos = new_pos;
        } else {
            result.push(input[pos]);
            pos += 1;
        }
    }

    result
}

pub(super) fn execute_capture(shell: &Shell, cmd: &[u8]) -> Vec<u8> {
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        if libc::pipe(pipe_fds.as_mut_ptr()) < 0 {
            return Vec::new();
        }
    }

    let pid = io::fork();
    if pid == 0 {
        io::close(pipe_fds[0]);
        io::dup2(pipe_fds[1], io::STDOUT);
        io::close(pipe_fds[1]);

        let mut subshell = Shell::new(false);
        for (k, v) in &shell.variables {
            subshell.variables.insert(k.clone(), v.clone());
        }
        subshell.positional_params = shell.positional_params.clone();
        super::execute_script(&mut subshell, cmd);
        io::exit(subshell.last_status);
    }

    io::close(pipe_fds[1]);

    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = io::read(pipe_fds[0], &mut buf);
        if n <= 0 {
            break;
        }
        output.extend_from_slice(&buf[..n as usize]);
    }
    io::close(pipe_fds[0]);

    let mut status = 0;
    io::waitpid(pid, &mut status, 0);

    output
}

pub(super) fn split_words(shell: &Shell, s: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    let mut pos = 0;

    while pos < s.len() {
        pos = super::skip_whitespace_and_comments(s, pos);
        if pos >= s.len() {
            break;
        }

        let (word, new_pos) = super::parse_word(shell, s, pos);
        if !word.is_empty() {
            words.push(word);
        }
        pos = new_pos;
    }

    words
}

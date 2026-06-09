//! Arithmetic evaluation for shell.

use crate::sys;

use super::expand_string;
use super::state::Shell;

pub(super) fn eval_arithmetic(shell: &Shell, expr: &[u8]) -> i64 {
    let expanded = expand_string(shell, expr);
    eval_arith_expr_with_shell(shell, &expanded, 0).0
}

pub(super) fn eval_arith_expr_with_shell(shell: &Shell, expr: &[u8], pos: usize) -> (i64, usize) {
    let (mut left, mut pos) = eval_arith_term_with_shell(shell, expr, pos);

    loop {
        pos = skip_arith_ws(expr, pos);
        if pos >= expr.len() {
            break;
        }

        let op = expr[pos];
        if op == b'+' {
            let (right, new_pos) = eval_arith_term_with_shell(shell, expr, pos + 1);
            left += right;
            pos = new_pos;
        } else if op == b'-' {
            let (right, new_pos) = eval_arith_term_with_shell(shell, expr, pos + 1);
            left -= right;
            pos = new_pos;
        } else {
            break;
        }
    }

    (left, pos)
}

pub(super) fn eval_arith_term_with_shell(shell: &Shell, expr: &[u8], pos: usize) -> (i64, usize) {
    let (mut left, mut pos) = eval_arith_factor_with_shell(shell, expr, pos);

    loop {
        pos = skip_arith_ws(expr, pos);
        if pos >= expr.len() {
            break;
        }

        let op = expr[pos];
        if op == b'*' {
            let (right, new_pos) = eval_arith_factor_with_shell(shell, expr, pos + 1);
            left *= right;
            pos = new_pos;
        } else if op == b'/' {
            let (right, new_pos) = eval_arith_factor_with_shell(shell, expr, pos + 1);
            if right != 0 {
                left /= right;
            }
            pos = new_pos;
        } else if op == b'%' {
            let (right, new_pos) = eval_arith_factor_with_shell(shell, expr, pos + 1);
            if right != 0 {
                left %= right;
            }
            pos = new_pos;
        } else {
            break;
        }
    }

    (left, pos)
}

pub(super) fn eval_arith_factor_with_shell(shell: &Shell, expr: &[u8], pos: usize) -> (i64, usize) {
    let mut pos = skip_arith_ws(expr, pos);
    if pos >= expr.len() {
        return (0, pos);
    }

    if expr[pos] == b'(' {
        let (val, new_pos) = eval_arith_expr_with_shell(shell, expr, pos + 1);
        let mut pos = skip_arith_ws(expr, new_pos);
        if pos < expr.len() && expr[pos] == b')' {
            pos += 1;
        }
        return (val, pos);
    }

    if expr[pos] == b'-' {
        let (val, new_pos) = eval_arith_factor_with_shell(shell, expr, pos + 1);
        return (-val, new_pos);
    }

    if expr[pos] >= b'0' && expr[pos] <= b'9' {
        let mut num: i64 = 0;
        while pos < expr.len() && expr[pos] >= b'0' && expr[pos] <= b'9' {
            num = num * 10 + (expr[pos] - b'0') as i64;
            pos += 1;
        }
        return (num, pos);
    }

    if expr[pos].is_ascii_alphabetic() || expr[pos] == b'_' {
        let start = pos;
        while pos < expr.len() && (expr[pos].is_ascii_alphanumeric() || expr[pos] == b'_') {
            pos += 1;
        }
        let var_name = &expr[start..pos];
        if let Some(value) = shell.get_var(var_name) {
            let num = sys::parse_i64(value).unwrap_or(0);
            return (num, pos);
        }
        return (0, pos);
    }

    (0, pos)
}

#[allow(dead_code)]
pub(super) fn eval_arith_expr(expr: &[u8], pos: usize) -> (i64, usize) {
    let (mut left, mut pos) = eval_arith_term(expr, pos);

    loop {
        pos = skip_arith_ws(expr, pos);
        if pos >= expr.len() {
            break;
        }

        let op = expr[pos];
        if op == b'+' {
            let (right, new_pos) = eval_arith_term(expr, pos + 1);
            left += right;
            pos = new_pos;
        } else if op == b'-' {
            let (right, new_pos) = eval_arith_term(expr, pos + 1);
            left -= right;
            pos = new_pos;
        } else {
            break;
        }
    }

    (left, pos)
}

#[allow(dead_code)]
pub(super) fn eval_arith_term(expr: &[u8], pos: usize) -> (i64, usize) {
    let (mut left, mut pos) = eval_arith_factor(expr, pos);

    loop {
        pos = skip_arith_ws(expr, pos);
        if pos >= expr.len() {
            break;
        }

        let op = expr[pos];
        if op == b'*' {
            let (right, new_pos) = eval_arith_factor(expr, pos + 1);
            left *= right;
            pos = new_pos;
        } else if op == b'/' {
            let (right, new_pos) = eval_arith_factor(expr, pos + 1);
            if right != 0 {
                left /= right;
            }
            pos = new_pos;
        } else if op == b'%' {
            let (right, new_pos) = eval_arith_factor(expr, pos + 1);
            if right != 0 {
                left %= right;
            }
            pos = new_pos;
        } else {
            break;
        }
    }

    (left, pos)
}

#[allow(dead_code)]
pub(super) fn eval_arith_factor(expr: &[u8], pos: usize) -> (i64, usize) {
    let mut pos = skip_arith_ws(expr, pos);
    if pos >= expr.len() {
        return (0, pos);
    }

    if expr[pos] == b'(' {
        let (val, new_pos) = eval_arith_expr(expr, pos + 1);
        let mut pos = skip_arith_ws(expr, new_pos);
        if pos < expr.len() && expr[pos] == b')' {
            pos += 1;
        }
        return (val, pos);
    }

    if expr[pos] == b'-' {
        let (val, new_pos) = eval_arith_factor(expr, pos + 1);
        return (-val, new_pos);
    }

    let mut num: i64 = 0;
    while pos < expr.len() && expr[pos] >= b'0' && expr[pos] <= b'9' {
        num = num * 10 + (expr[pos] - b'0') as i64;
        pos += 1;
    }

    (num, pos)
}

pub(super) fn skip_arith_ws(expr: &[u8], pos: usize) -> usize {
    let mut pos = pos;
    while pos < expr.len() && (expr[pos] == b' ' || expr[pos] == b'\t') {
        pos += 1;
    }
    pos
}

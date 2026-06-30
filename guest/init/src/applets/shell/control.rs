//! Shell control flow structures.
//!
//! Adapted from Armybox `src/applets/shell/control.rs`.

use crate::io;

use super::expand::split_words;
use super::parser::parse_word;
use super::state::Shell;
use super::util::{
    find_keyword, find_matching_done, find_word_end, is_keyword_boundary, skip_to_next_token,
    skip_whitespace_and_comments,
};

pub(super) fn execute_if(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let mut pos = start + 2;

    let Some(then_pos) = find_keyword(script, pos, b"then") else {
        io::write(io::STDERR, "sh: syntax error: expected 'then'\n");
        return script.len();
    };

    let condition = &script[pos..then_pos];
    super::execute_script(shell, condition.trim_ascii());
    let condition_result = shell.last_status == 0;

    pos = then_pos + 4;

    let mut depth = 1;
    let mut first_else_pos: Option<usize> = None;
    let mut first_else_is_elif = false;
    let mut fi_pos: Option<usize> = None;
    let mut scan = pos;

    while scan < script.len() && depth > 0 {
        scan = skip_whitespace_and_comments(script, scan);
        if scan >= script.len() {
            break;
        }

        let word_end = find_word_end(script, scan);
        let word = &script[scan..word_end];
        let at_boundary = is_keyword_boundary(script, word_end);

        if word == b"if" && at_boundary {
            depth += 1;
            scan = word_end;
        } else if word == b"fi" && at_boundary {
            depth -= 1;
            if depth == 0 {
                fi_pos = Some(scan);
            }
            scan = word_end;
        } else if word == b"else" && depth == 1 && at_boundary && first_else_pos.is_none() {
            first_else_pos = Some(scan);
            first_else_is_elif = false;
            scan = word_end;
        } else if word == b"elif" && depth == 1 && at_boundary && first_else_pos.is_none() {
            first_else_pos = Some(scan);
            first_else_is_elif = true;
            scan = word_end;
        } else {
            scan = skip_to_next_token(script, scan);
        }
    }

    let Some(fi_pos) = fi_pos else {
        io::write(io::STDERR, "sh: syntax error: expected 'fi'\n");
        return script.len();
    };

    if condition_result {
        let end = first_else_pos.unwrap_or(fi_pos);
        let then_body = &script[pos..end];
        super::execute_script(shell, then_body);
    } else if let Some(else_start) = first_else_pos {
        if first_else_is_elif {
            let elif_body = &script[else_start + 2..fi_pos + 2];
            super::execute_script(shell, elif_body.trim_ascii());
        } else {
            let else_body = &script[else_start + 4..fi_pos];
            super::execute_script(shell, else_body);
        }
    }

    fi_pos + 2
}

pub(super) fn execute_while(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let mut pos = start + 5;

    let Some(do_pos) = find_keyword(script, pos, b"do") else {
        io::write(io::STDERR, "sh: syntax error: expected 'do'\n");
        return script.len();
    };
    let condition = &script[pos..do_pos];

    pos = do_pos + 2;

    let Some(done_pos) = find_matching_done(script, pos) else {
        io::write(io::STDERR, "sh: syntax error: expected 'done'\n");
        return script.len();
    };

    let body = &script[pos..done_pos];

    loop {
        super::execute_script(shell, condition.trim_ascii());
        if shell.last_status != 0 {
            break;
        }
        super::execute_script(shell, body);
        if shell.should_exit {
            break;
        }
    }

    done_pos + 4
}

pub(super) fn execute_until(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let mut pos = start + 5;

    let Some(do_pos) = find_keyword(script, pos, b"do") else {
        io::write(io::STDERR, "sh: syntax error: expected 'do'\n");
        return script.len();
    };
    let condition = &script[pos..do_pos];

    pos = do_pos + 2;

    let Some(done_pos) = find_matching_done(script, pos) else {
        io::write(io::STDERR, "sh: syntax error: expected 'done'\n");
        return script.len();
    };

    let body = &script[pos..done_pos];

    loop {
        super::execute_script(shell, condition.trim_ascii());
        if shell.last_status == 0 {
            break;
        }
        super::execute_script(shell, body);
        if shell.should_exit {
            break;
        }
    }

    done_pos + 4
}

pub(super) fn execute_for(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let mut pos = start + 3;
    pos = skip_whitespace_and_comments(script, pos);

    let var_end = find_word_end(script, pos);
    let var_name = script[pos..var_end].to_vec();
    pos = var_end;

    pos = skip_whitespace_and_comments(script, pos);

    let in_end = find_word_end(script, pos);
    if &script[pos..in_end] != b"in" || !is_keyword_boundary(script, in_end) {
        io::write(io::STDERR, "sh: syntax error: expected 'in'\n");
        return script.len();
    }
    pos = in_end;

    let Some(do_pos) = find_keyword(script, pos, b"do") else {
        io::write(io::STDERR, "sh: syntax error: expected 'do'\n");
        return script.len();
    };

    let words_str = &script[pos..do_pos];
    let words = split_words(shell, words_str);

    pos = do_pos + 2;

    let Some(done_pos) = find_matching_done(script, pos) else {
        io::write(io::STDERR, "sh: syntax error: expected 'done'\n");
        return script.len();
    };

    let body = &script[pos..done_pos];

    for word in words {
        shell.set_var(&var_name, &word);
        super::execute_script(shell, body);
        if shell.should_exit {
            break;
        }
    }

    done_pos + 4
}

fn find_matching_esac(script: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    let mut depth = 1;

    while pos < script.len() && depth > 0 {
        pos = skip_whitespace_and_comments(script, pos);
        if pos >= script.len() {
            return None;
        }

        let word_end = find_word_end(script, pos);
        let word = &script[pos..word_end];

        if word == b"case" && is_keyword_boundary(script, word_end) {
            depth += 1;
        } else if word == b"esac" && is_keyword_boundary(script, word_end) {
            depth -= 1;
            if depth == 0 {
                return Some(pos);
            }
        }

        pos = skip_to_next_token(script, pos);
    }
    None
}

pub(super) fn execute_case(shell: &mut Shell, script: &[u8], start: usize) -> usize {
    let mut pos = start + 4;
    pos = skip_whitespace_and_comments(script, pos);

    let (match_word, new_pos) = parse_word(shell, script, pos);
    pos = new_pos;

    pos = skip_whitespace_and_comments(script, pos);

    let word_end = find_word_end(script, pos);
    if &script[pos..word_end] != b"in" || !is_keyword_boundary(script, word_end) {
        io::write(io::STDERR, "sh: syntax error: expected 'in'\n");
        return script.len();
    }
    pos = word_end;

    let Some(esac_pos) = find_matching_esac(script, pos) else {
        io::write(io::STDERR, "sh: syntax error: expected 'esac'\n");
        return script.len();
    };

    let mut matched = false;
    while pos < esac_pos && !matched {
        pos = skip_whitespace_and_comments(script, pos);
        if pos >= esac_pos {
            break;
        }

        let Some(paren_rel) = script[pos..esac_pos].iter().position(|&c| c == b')') else {
            break;
        };
        let paren_pos = pos + paren_rel;

        let patterns = &script[pos..paren_pos];
        pos = paren_pos + 1;

        let end_pos = find_case_end(script, pos, esac_pos);
        let body = &script[pos..end_pos];

        for pattern in patterns.split(|&c| c == b'|') {
            let pattern = pattern.trim_ascii();
            if pattern_matches(&match_word, pattern) {
                super::execute_script(shell, body);
                matched = true;
                break;
            }
        }

        pos = end_pos;
        if pos < script.len() && script[pos..].starts_with(b";;") {
            pos += 2;
        }
    }

    esac_pos + 4
}

pub(super) fn pattern_matches(word: &[u8], pattern: &[u8]) -> bool {
    if pattern == b"*" {
        return true;
    }

    let mut wi = 0;
    let mut pi = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_wi: usize = 0;

    while wi < word.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == word[wi]) {
            wi += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_wi = wi;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_wi += 1;
            wi = star_wi;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

pub(super) fn find_case_end(script: &[u8], start: usize, esac_pos: usize) -> usize {
    let mut pos = start;
    while pos < esac_pos {
        if script[pos..].starts_with(b";;") {
            return pos;
        }
        pos += 1;
    }
    esac_pos
}

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenizeError {
    TooLong,
    NotOneLine,
    TrailingEscape,
    UnterminatedQuote,
    ShellSyntax,
}

impl fmt::Display for TokenizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "command too long",
            Self::NotOneLine => "command must be one line",
            Self::TrailingEscape => "trailing escape",
            Self::UnterminatedQuote => "unterminated quote",
            Self::ShellSyntax => "shell operators and expansion are not supported before --; when calling through ssh, quote the whole command: ssh silo \"exec VM -- CMD 'ARG'\"",
        })
    }
}

impl std::error::Error for TokenizeError {}

/// POSIX-style quoting without expansion or shell evaluation.
pub(crate) fn tokenize(line: &str) -> Result<Vec<String>, TokenizeError> {
    if line.len() > 16384 {
        return Err(TokenizeError::TooLong);
    }
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut active = false;
    let mut literal = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if matches!(c, '\0' | '\n' | '\r') {
            return Err(TokenizeError::NotOneLine);
        }
        if quote == Some('\'') {
            if c == '\'' {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        if c == '\\' {
            let Some(&next) = chars.peek() else {
                return Err(TokenizeError::TrailingEscape);
            };
            if quote == Some('"') && !matches!(next, '"' | '\\' | '$' | '`') {
                word.push(c);
                active = true;
                continue;
            }
            if matches!(next, '\0' | '\n' | '\r') {
                return Err(TokenizeError::NotOneLine);
            }
            chars.next();
            word.push(next);
            active = true;
            continue;
        }
        if quote == Some('"') {
            if c == '"' {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                active = true;
            }
            ' ' | '\t' => {
                if active {
                    literal |= word == "--";
                    tokens.push(std::mem::take(&mut word));
                    active = false;
                }
            }
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '$' | '`' if !literal => {
                return Err(TokenizeError::ShellSyntax);
            }
            _ => {
                word.push(c);
                active = true;
            }
        }
    }
    if quote.is_some() {
        return Err(TokenizeError::UnterminatedQuote);
    }
    if active {
        tokens.push(word);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use crate::lobby::grammar::tokenizer::{tokenize, TokenizeError};

    #[test]
    fn go_tokenizer_table() {
        for (line, want) in [
            ("", vec![]),
            ("whoami --json", vec!["whoami", "--json"]),
            (r#"a '' """#, vec!["a", "", ""]),
            (
                r#"a 'two words' "three words""#,
                vec!["a", "two words", "three words"],
            ),
            (r#"a\ b "x\"y""#, vec!["a b", "x\"y"]),
            (r#"a "x\qy""#, vec!["a", r"x\qy"]),
            ("a '$HOME'", vec!["a", "$HOME"]),
            (
                "exec vm -- python -c print(123)",
                vec!["exec", "vm", "--", "python", "-c", "print(123)"],
            ),
            (
                "exec vm -- a | b $x",
                vec!["exec", "vm", "--", "a", "|", "b", "$x"],
            ),
            (
                r"exec vm -- sh -c echo\ hi\;ls",
                vec!["exec", "vm", "--", "sh", "-c", "echo hi;ls"],
            ),
            (
                "exec vm -- python -c \"'print(1, 2)'\"",
                vec!["exec", "vm", "--", "python", "-c", "'print(1, 2)'"],
            ),
            ("exec vm '--' -- a|b", vec!["exec", "vm", "--", "--", "a|b"]),
            (
                "exec dev -- /bin/printf '%s' --json '--yes' '$HOME; | literal'",
                vec![
                    "exec",
                    "dev",
                    "--",
                    "/bin/printf",
                    "%s",
                    "--json",
                    "--yes",
                    "$HOME; | literal",
                ],
            ),
        ] {
            assert_eq!(tokenize(line).unwrap(), want, "{line}");
        }
        for line in [
            "a $HOME",
            "a; b",
            "a | b",
            "a\nb",
            "'open",
            "a\\",
            "exec vm -- 'open",
            "exec vm -- a\nb",
            "create --name a$b -- x",
            "exec vm --x a|b",
            "a\0",
            "a\r",
            "a\\\n",
        ] {
            assert!(tokenize(line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn byte_limit_and_unicode() {
        assert_eq!(tokenize(&"é".repeat(8193)), Err(TokenizeError::TooLong));
        assert_eq!(tokenize(&"é".repeat(8192)).unwrap(), vec!["é".repeat(8192)]);
        assert_eq!(tokenize("café\\ ☕").unwrap(), vec!["café ☕"]);
    }
}

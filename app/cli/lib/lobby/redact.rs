const REDACTED: &str = "[redacted]";

pub(crate) fn log_text(value: &str, secrets: &[&str]) -> String {
    let mut value = value.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            value = value.replace(secret, REDACTED);
        }
    }
    let mut tokens = String::with_capacity(value.len());
    let mut offset = 0;
    while offset < value.len() {
        let rest = &value[offset..];
        if let Some(length) = token_length(rest) {
            tokens.push_str(REDACTED);
            offset += length;
        } else if let Some(c) = rest.chars().next() {
            tokens.push(c);
            offset += c.len_utf8();
        }
    }
    let mut output = String::with_capacity(tokens.len());
    let mut offset = 0;
    while offset < tokens.len() {
        let rest = &tokens[offset..];
        if rest.starts_with("https://") || rest.starts_with("http://") {
            let end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '<' | '>'))
                .unwrap_or(rest.len());
            output.push_str("[url]");
            offset += end;
        } else if rest.starts_with('/')
            && (offset == 0
                || tokens[..offset]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_whitespace() || matches!(c, '=' | '"' | '\'' | '(')))
        {
            let end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')'))
                .unwrap_or(rest.len());
            if end > 1 {
                output.push_str("[path]");
                offset += end;
            } else {
                output.push('/');
                offset += 1;
            }
        } else if let Some(c) = rest.chars().next() {
            output.push(c);
            offset += c.len_utf8();
        }
    }
    output
}

fn prefix_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
}

fn token_length(value: &str) -> Option<usize> {
    if prefix_ignore_case(value, "tskey-") {
        let end = value[6..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .unwrap_or(value.len() - 6)
            + 6;
        if end > 6 {
            return Some(end);
        }
    }
    for scheme in ["bearer", "basic"] {
        if prefix_ignore_case(value, scheme) {
            let rest = &value[scheme.len()..];
            let trimmed = rest.trim_start_matches(char::is_whitespace);
            if trimmed.len() == rest.len() {
                continue;
            }
            let count = trimmed
                .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';'))
                .unwrap_or(trimmed.len());
            if count > 0 {
                return Some(value.len() - trimmed.len() + count);
            }
        }
    }
    for field in [
        "access_token",
        "client_secret",
        "authkey",
        "token",
        "password",
    ] {
        if !prefix_ignore_case(value, field) {
            continue;
        }
        let mut rest = &value[field.len()..];
        if rest.starts_with(['"', '\'']) {
            rest = &rest[1..];
        }
        rest = rest.trim_start_matches(char::is_whitespace);
        if !rest.starts_with(['=', ':']) {
            continue;
        }
        rest = rest[1..].trim_start_matches(char::is_whitespace);
        if rest.starts_with(['"', '\'']) {
            rest = &rest[1..];
        }
        let count = rest
            .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '}'))
            .unwrap_or(rest.len());
        if count > 0 {
            return Some(value.len() - rest.len() + count);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::lobby::redact::log_text;

    #[test]
    fn log_redaction_includes_errors_paths_and_login_url() {
        let value = "UserLogf tskey-auth-secret config=/etc/silo/config.yaml error=https://secret:password@control.test/token?access_token=secret /home/operator/private opaque-secret login=https://login.tailscale.com/a/valid-login-link";
        let output = log_text(value, &["opaque-secret"]);
        for forbidden in [
            "tskey-auth-secret",
            "opaque-secret",
            "/etc/silo",
            "/home/operator",
            "control.test",
            "password",
            "login.tailscale.com",
            "valid-login-link",
        ] {
            assert!(!output.contains(forbidden), "{forbidden}: {output}");
        }
    }

    #[test]
    fn token_and_path_tables() {
        for input in [
            "TSKEY-AUTH-123",
            "Bearer secret",
            "basic\tsecret",
            "access_token=secret",
            "client_secret: 'secret'",
            "authkey=secret",
            "TOKEN=secret",
            "password\":\"secret\"",
            "prefix token = secret",
        ] {
            assert!(!log_text(input, &[]).contains("secret"), "{input}");
        }
        for input in [
            "/home/private",
            "path=/home/private",
            "'/home/private'",
            "(/home/private)",
            "prefix /home/private",
        ] {
            assert!(!log_text(input, &[]).contains("/home/private"), "{input}");
        }
        assert_eq!(log_text("ordinary words", &[""]), "ordinary words");
        assert_eq!(
            log_text("你好 token=secret /private", &[]),
            "你好 [redacted] [path]"
        );
        assert_eq!(log_text("x/y /", &[]), "x/y /");
    }
}

//! Best-effort account environment enrichment. The guest agent remains the
//! authority for selecting credentials and rejecting unknown accounts.

use std::time::Duration;

use libvm::{ExecutionEvent, ExecutionLaunchFailureReason, ExecutionResult, Machine};
use silod_spec::daemon::v1 as w;

use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::service::streams::native_failure;

pub(crate) struct GuestAccount {
    pub(crate) name: String,
    pub(crate) home: String,
    pub(crate) shell: String,
}

pub(crate) async fn guest_identity(
    machine: &Machine,
    selector: &str,
    stored: Option<&w::User>,
) -> Outcome<GuestAccount> {
    let fallback = fallback(selector, stored);
    let lookup = async {
        let mut process = machine.spawn_with("/bin/sh", |options| options
            .args(["-c", "command -v read && command -v printf || exit 125\nwhile IFS= read -r line || [ -n \"$line\" ]; do printf '%s\\n' \"$line\"; done < /etc/passwd"])
            .user("0:0")).await.map_err(native_failure)?;
        let mut output = Vec::new();
        loop {
            match process.recv().await.map_err(native_failure)? {
                Some(ExecutionEvent::Stdout(data)) => {
                    if output.len() + data.len() > 1 << 20 {
                        return Err(Failure::new(
                            Code::OperationFailed,
                            "guest account database exceeds 1MiB",
                        ));
                    }
                    output.extend_from_slice(&data);
                }
                Some(ExecutionEvent::Terminal(ExecutionResult::Exited { code: Some(0) })) => {
                    return Ok(parse_account(&String::from_utf8_lossy(&output), selector));
                }
                Some(ExecutionEvent::Terminal(ExecutionResult::Exited {
                    code: Some(125 | 127),
                })) => return Ok(fallback),
                Some(ExecutionEvent::Terminal(ExecutionResult::LaunchFailed(failure)))
                    if failure.reason == ExecutionLaunchFailureReason::CommandNotFound =>
                {
                    return Ok(fallback)
                }
                Some(ExecutionEvent::Terminal(_)) | None => {
                    return Err(Failure::new(
                        Code::OperationFailed,
                        "unable to read guest account database",
                    ))
                }
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), lookup)
        .await
        .map_err(|_| Failure::new(Code::Unavailable, "guest account lookup timed out"))?
}

fn fallback(selector: &str, stored: Option<&w::User>) -> GuestAccount {
    let name = selector.split(':').next().unwrap_or_default();
    let uid = name.parse::<u32>().ok();
    if name == "root" || uid == Some(0) {
        GuestAccount {
            name: "root".into(),
            home: "/root".into(),
            shell: "/bin/sh".into(),
        }
    } else if let Some(user) = stored.filter(|user| name == user.name || uid == Some(user.uid)) {
        GuestAccount {
            name: user.name.clone(),
            home: user.home.clone(),
            shell: "/bin/bash".into(),
        }
    } else {
        GuestAccount {
            name: String::new(),
            home: String::new(),
            shell: "/bin/sh".into(),
        }
    }
}

fn parse_account(passwd: &str, selector: &str) -> GuestAccount {
    let name = selector.split(':').next().unwrap_or_default();
    let uid = name.parse::<u32>().ok();
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let (
            Some(entry_name),
            Some(_),
            Some(entry_uid),
            Some(_),
            Some(_),
            Some(home),
            Some(shell),
            None,
        ) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        )
        else {
            continue;
        };
        if entry_name != name && (uid.is_none() || entry_uid.parse::<u32>().ok() != uid) {
            continue;
        }
        return GuestAccount {
            name: entry_name.into(),
            home: if home.is_empty() { "/" } else { home }.into(),
            shell: if shell.is_empty() { "/bin/sh" } else { shell }.into(),
        };
    }
    GuestAccount {
        name: String::new(),
        home: String::new(),
        shell: "/bin/sh".into(),
    }
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::guest_identity::{fallback, parse_account};
    use silod_spec::daemon::v1::User;

    #[test]
    fn selected_guest_account_not_daemon_identity() {
        let passwd = "malformed\nroot:x:0:0::/root:/bin/bash\nnick:x:1000:1000::/home/nick:/bin/zsh\nempty:x:42:42:::\n";
        for selector in ["nick", "1000", "1000:123"] {
            let account = parse_account(passwd, selector);
            assert_eq!(
                (
                    account.name.as_str(),
                    account.home.as_str(),
                    account.shell.as_str()
                ),
                ("nick", "/home/nick", "/bin/zsh")
            );
        }
        let empty = parse_account(passwd, "42");
        assert_eq!(
            (empty.home.as_str(), empty.shell.as_str()),
            ("/", "/bin/sh")
        );
        assert!(parse_account(passwd, "missing").name.is_empty());
    }

    #[test]
    fn fallback_only_enriches_known_accounts() {
        let stored = User {
            name: "nick".into(),
            uid: 1000,
            gid: 1000,
            home: "/home/nick".into(),
        };
        assert_eq!(fallback("0:0", Some(&stored)).home, "/root");
        assert_eq!(fallback("1000:42", Some(&stored)).name, "nick");
        assert!(fallback("unknown", Some(&stored)).home.is_empty());
    }
}

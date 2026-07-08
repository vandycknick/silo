use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use agent_spec::AgentSshAuthorizedUser;
use eyre::{eyre, Context};

use crate::provision::{
    command_exists, run_command, write_file, ProvisionContext, ProvisionOutcome,
};

pub(crate) fn apply(
    context: &ProvisionContext,
    authorized_users: &[AgentSshAuthorizedUser],
) -> eyre::Result<ProvisionOutcome> {
    if authorized_users.is_empty() {
        return Ok(ProvisionOutcome::skipped(
            "no SSH authorized users configured",
        ));
    }

    let users = read_passwd_entries(context)?;
    let mut installed = Vec::new();
    let mut missing = Vec::new();
    let mut no_keys = Vec::new();

    for authorized_user in authorized_users {
        if authorized_user.authorized_keys.is_empty() {
            no_keys.push(authorized_user.name.clone());
            continue;
        }

        let Some(user) = users.get(&authorized_user.name) else {
            missing.push(authorized_user.name.clone());
            continue;
        };

        install_authorized_keys(context, user, &authorized_user.authorized_keys)?;
        installed.push(authorized_user.name.clone());
    }

    if installed.is_empty() {
        let mut reasons = Vec::new();
        if !missing.is_empty() {
            reasons.push(format!("missing users: {}", missing.join(", ")));
        }
        if !no_keys.is_empty() {
            reasons.push(format!("users without keys: {}", no_keys.join(", ")));
        }
        let message = if reasons.is_empty() {
            "no SSH authorized keys configured".to_string()
        } else {
            reasons.join("; ")
        };
        return Ok(ProvisionOutcome::skipped(message));
    }

    let mut message = format!("installed SSH authorized keys for {}", installed.join(", "));
    if !missing.is_empty() {
        message.push_str(&format!("; skipped missing users: {}", missing.join(", ")));
    }
    if !no_keys.is_empty() {
        message.push_str(&format!(
            "; skipped users without keys: {}",
            no_keys.join(", ")
        ));
    }

    Ok(ProvisionOutcome::Succeeded {
        changed: true,
        message,
    })
}

fn install_authorized_keys(
    context: &ProvisionContext,
    user: &PasswdEntry,
    authorized_keys: &[String],
) -> eyre::Result<()> {
    let ssh_dir = context.guest_path(&format!("{}/.ssh", user.home));
    fs::create_dir_all(&ssh_dir).with_context(|| format!("create {}", ssh_dir.display()))?;
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on {}", ssh_dir.display()))?;

    let mut keys = authorized_keys.join("\n");
    keys.push('\n');
    write_file(&ssh_dir.join("authorized_keys"), keys, 0o600)?;

    if command_exists("chown") {
        let owner = format!("{}:{}", user.uid, user.gid);
        let path = ssh_dir.to_string_lossy().to_string();
        run_command(
            context.process_supervisor(),
            "chown",
            ["-R", owner.as_str(), path.as_str()],
        )?;
    }

    tracing::info!(user = %user.name, "reconciled SSH authorized keys");
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
}

fn read_passwd_entries(context: &ProvisionContext) -> eyre::Result<BTreeMap<String, PasswdEntry>> {
    let passwd_path = context.guest_path("/etc/passwd");
    let contents = fs::read_to_string(&passwd_path)
        .with_context(|| format!("read {}", passwd_path.display()))?;

    let mut entries = BTreeMap::new();
    for line in contents.lines() {
        let Some(entry) = parse_passwd_entry(line)? else {
            continue;
        };
        entries.insert(entry.name.clone(), entry);
    }
    Ok(entries)
}

fn parse_passwd_entry(line: &str) -> eyre::Result<Option<PasswdEntry>> {
    if line.trim().is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    let mut fields = line.split(':');
    let name = fields
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| eyre!("malformed passwd entry: missing name"))?;
    let _password = fields.next();
    let uid = fields
        .next()
        .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing uid"))?
        .parse::<u32>()
        .with_context(|| format!("parse uid for user {name}"))?;
    let gid = fields
        .next()
        .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing gid"))?
        .parse::<u32>()
        .with_context(|| format!("parse gid for user {name}"))?;
    let _gecos = fields.next();
    let home = fields
        .next()
        .filter(|home| !home.is_empty())
        .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing home"))?;

    Ok(Some(PasswdEntry {
        name: name.to_string(),
        uid,
        gid,
        home: home.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use crate::provision::ssh::parse_passwd_entry;

    #[test]
    fn parses_passwd_entry() {
        let entry = parse_passwd_entry("root:x:0:0:root:/root:/bin/sh")
            .expect("parse passwd")
            .expect("entry");

        assert_eq!(entry.name, "root");
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.home, "/root");
    }

    #[test]
    fn skips_comment_passwd_entry() {
        assert!(parse_passwd_entry("# nope")
            .expect("parse passwd")
            .is_none());
    }
}

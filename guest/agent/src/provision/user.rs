use std::ffi::OsString;
use std::fs;

use agent_spec::UserConfig;
use eyre::{eyre, Context};

use crate::provision::{
    command_exists, format_error_chain, run_command, sanitize_unit_name, write_file,
    ProvisionContext, ProvisionOutcome,
};

pub(crate) fn apply(
    context: &ProvisionContext,
    users: &[UserConfig],
) -> eyre::Result<ProvisionOutcome> {
    if users.is_empty() {
        return Ok(ProvisionOutcome::skipped("no users configured"));
    }

    let mut failures = Vec::new();

    for user in users {
        if let Err(err) = apply_user(context, user) {
            let error = format_error_chain(&err);
            tracing::error!(user = %user.name, error = %error, "failed to provision user; continuing");
            failures.push(format!("{}: {error}", user.name));
        }
    }

    if failures.is_empty() {
        Ok(ProvisionOutcome::succeeded(false))
    } else {
        Err(eyre!(
            "failed to provision {} user(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

fn apply_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    ensure_user(context, user)?;
    write_sudoers(context, user)?;
    Ok(())
}

fn ensure_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    match read_user_entry(context, &user.name)? {
        Some(entry) => reconcile_existing_user(context, user, &entry),
        None => create_user(context, user),
    }
}

fn create_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    let uid = user.uid.to_string();
    run_command(
        context.process_supervisor(),
        "useradd",
        [
            "--uid",
            uid.as_str(),
            "--comment",
            user.gecos.as_str(),
            "--home-dir",
            user.home.as_str(),
            "--create-home",
            "--shell",
            user.shell.as_str(),
            user.name.as_str(),
        ],
    )?;

    if user.lock_passwd && command_exists("passwd") {
        run_command(
            context.process_supervisor(),
            "passwd",
            ["--lock", user.name.as_str()],
        )?;
    }

    tracing::info!(user = %user.name, uid = user.uid, "provisioned user");
    Ok(())
}

fn reconcile_existing_user(
    context: &ProvisionContext,
    user: &UserConfig,
    entry: &UserEntry,
) -> eyre::Result<()> {
    if entry.uid != user.uid {
        return Err(eyre!(
            "existing user {} has uid {}, expected {}; refusing to change uid",
            user.name,
            entry.uid,
            user.uid
        ));
    }

    let mut args = Vec::new();
    if entry.gecos != user.gecos {
        args.push(OsString::from("--comment"));
        args.push(OsString::from(&user.gecos));
    }
    if entry.home != user.home {
        args.push(OsString::from("--home"));
        args.push(OsString::from(&user.home));
    }
    if entry.shell != user.shell {
        args.push(OsString::from("--shell"));
        args.push(OsString::from(&user.shell));
    }

    if !args.is_empty() {
        args.push(OsString::from(&user.name));
        run_command(context.process_supervisor(), "usermod", args)?;
    }

    reconcile_home(context, user)?;
    reconcile_password_lock(context, user)?;

    tracing::info!(user = %user.name, uid = user.uid, "reconciled user");
    Ok(())
}

fn reconcile_home(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    fs::create_dir_all(&user.home)
        .with_context(|| format!("create home directory {}", user.home))?;
    if command_exists("chown") {
        let owner = format!("{}:{}", user.name, user.name);
        run_command(
            context.process_supervisor(),
            "chown",
            [owner.as_str(), user.home.as_str()],
        )?;
    }
    Ok(())
}

fn reconcile_password_lock(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    if !command_exists("passwd") {
        return Ok(());
    }

    if user.lock_passwd {
        run_command(
            context.process_supervisor(),
            "passwd",
            ["--lock", user.name.as_str()],
        )
    } else {
        run_command(
            context.process_supervisor(),
            "passwd",
            ["--unlock", user.name.as_str()],
        )
    }
}

fn write_sudoers(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    let path = context.guest_path(&format!(
        "/etc/sudoers.d/silo-{}",
        sanitize_unit_name(&user.name)
    ));
    if user.sudo.trim().is_empty() {
        remove_file_if_exists(&path)?;
        return Ok(());
    }

    write_file(&path, format!("{} {}\n", user.name, user.sudo), 0o440)
}

fn remove_file_if_exists(path: &std::path::Path) -> eyre::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UserEntry {
    uid: u32,
    gecos: String,
    home: String,
    shell: String,
}

fn read_user_entry(context: &ProvisionContext, name: &str) -> eyre::Result<Option<UserEntry>> {
    let passwd_path = context.guest_path("/etc/passwd");
    let contents = match fs::read_to_string(&passwd_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", passwd_path.display())),
    };

    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(entry_name) = fields.next() else {
            continue;
        };
        if entry_name != name {
            continue;
        }

        let _password = fields.next();
        let uid = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing uid"))?
            .parse::<u32>()
            .with_context(|| format!("parse uid for user {name}"))?;
        let _gid = fields.next();
        let gecos = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing gecos"))?
            .to_string();
        let home = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing home"))?
            .to_string();
        let shell = fields
            .next()
            .ok_or_else(|| eyre!("malformed passwd entry for {name}: missing shell"))?
            .to_string();

        return Ok(Some(UserEntry {
            uid,
            gecos,
            home,
            shell,
        }));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use crate::provision::ProvisionContext;

    #[test]
    fn reads_user_entry_from_passwd() {
        let root = temp_root("user-entry");
        let etc = root.join("etc");
        fs::create_dir_all(&etc).expect("create etc");
        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nsilo:x:1000:1000:Silo User:/home/silo:/bin/zsh\n",
        )
        .expect("write passwd");

        let context = ProvisionContext {
            root: root.clone(),
            process_supervisor: crate::pid1::ProcessSupervisor::default(),
            service_manager: crate::provision::ServiceManagerState::detect(
                &crate::handoff::BootMode::Standard,
            ),
        };
        let entry = super::read_user_entry(&context, "silo")
            .expect("read user")
            .expect("entry exists");

        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gecos, "Silo User");
        assert_eq!(entry.home, "/home/silo");
        assert_eq!(entry.shell, "/bin/zsh");

        fs::remove_dir_all(root).expect("clean temp root");
    }

    fn temp_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("silo-agent-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }
}

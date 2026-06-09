use bento_core::agent::UserConfig;
use eyre::eyre;

use crate::provision::{
    command_exists, format_error_chain, run_command, sanitize_unit_name, write_file,
    ProvisionContext,
};

pub(crate) fn apply(context: &ProvisionContext, users: &[UserConfig]) -> eyre::Result<()> {
    let mut failures = Vec::new();

    for user in users {
        if let Err(err) = apply_user(context, user) {
            let error = format_error_chain(&err);
            tracing::error!(user = %user.name, error = %error, "failed to provision user; continuing");
            failures.push(format!("{}: {error}", user.name));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(eyre!(
            "failed to provision {} user(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

fn apply_user(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    ensure_user(user)?;
    crate::provision::ssh::install_authorized_keys(context, user)?;
    write_sudoers(context, user)?;
    Ok(())
}

fn ensure_user(user: &UserConfig) -> eyre::Result<()> {
    if user_exists(&user.name) {
        tracing::info!(user = %user.name, "user already exists");
        return Ok(());
    }

    let uid = user.uid.to_string();
    run_command(
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
        run_command("passwd", ["--lock", user.name.as_str()])?;
    }

    tracing::info!(user = %user.name, uid = user.uid, "provisioned user");
    Ok(())
}

fn user_exists(name: &str) -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .arg(name)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn write_sudoers(context: &ProvisionContext, user: &UserConfig) -> eyre::Result<()> {
    if user.sudo.trim().is_empty() {
        return Ok(());
    }

    let path = context.guest_path(&format!(
        "/etc/sudoers.d/bento-{}",
        sanitize_unit_name(&user.name)
    ));
    write_file(&path, format!("{} {}\n", user.name, user.sudo), 0o440)
}

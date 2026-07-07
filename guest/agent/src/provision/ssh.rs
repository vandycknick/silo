use std::fs;
use std::os::unix::fs::PermissionsExt;

use agent_spec::UserConfig;
use eyre::Context;

use crate::provision::{command_exists, run_command, write_file, ProvisionContext};

pub(crate) fn install_authorized_keys(
    context: &ProvisionContext,
    user: &UserConfig,
) -> eyre::Result<()> {
    if user.ssh_authorized_keys.is_empty() {
        return Ok(());
    }

    let ssh_dir = context.guest_path(&format!("{}/.ssh", user.home));
    fs::create_dir_all(&ssh_dir).with_context(|| format!("create {}", ssh_dir.display()))?;
    fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on {}", ssh_dir.display()))?;

    let mut keys = user.ssh_authorized_keys.join("\n");
    keys.push('\n');
    write_file(&ssh_dir.join("authorized_keys"), keys, 0o600)?;

    if command_exists("chown") {
        let owner = format!("{}:{}", user.uid, user.uid);
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

use eyre::Context;

use crate::provision::{write_file, ProvisionContext};

pub(crate) fn is_complete(context: &ProvisionContext, state_path: &str) -> eyre::Result<bool> {
    let path = context.guest_path(state_path);
    path.try_exists()
        .with_context(|| format!("check provisioning state {}", path.display()))
}

pub(crate) fn mark_complete(context: &ProvisionContext, state_path: &str) -> eyre::Result<()> {
    let path = context.guest_path(state_path);
    write_file(&path, b"complete\n", 0o644)
}

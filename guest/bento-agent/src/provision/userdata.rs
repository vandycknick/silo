use bento_core::agent::{UserdataConfig, UserdataContentType};

use crate::provision::{run_command, write_file, ProvisionContext};

pub(crate) fn apply(
    context: &ProvisionContext,
    userdata: Option<&UserdataConfig>,
) -> eyre::Result<()> {
    let Some(userdata) = userdata else {
        return Ok(());
    };
    if userdata.content.trim().is_empty() {
        return Ok(());
    }

    if userdata.content_type != UserdataContentType::ShellScript {
        return Err(eyre::eyre!(
            "agent provisioning only supports shell-script userdata for now, got {:?}",
            userdata.content_type
        ));
    }

    let path = context.guest_path("/var/lib/bento-agent/userdata.sh");
    write_file(&path, &userdata.content, 0o700)?;
    let script = path.to_string_lossy().to_string();
    run_command("/bin/sh", [script.as_str()])?;
    tracing::info!(path = %path.display(), "provisioned userdata script");
    Ok(())
}

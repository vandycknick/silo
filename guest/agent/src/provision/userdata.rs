use std::fmt::Write as _;
use std::fs;

use agent_spec::{UserdataConfig, UserdataContentType, UserdataRunPolicy};
use eyre::Context;
use sha2::{Digest, Sha256};

use crate::provision::{run_command, write_file, ProvisionContext, ProvisionOutcome};

const USERDATA_SCRIPT_PATH: &str = "/var/lib/silo-agent/userdata.sh";
const USERDATA_HASH_PATH: &str = "/var/lib/silo-agent/userdata.sha256";

pub(crate) fn apply(
    context: &ProvisionContext,
    userdata: Option<&UserdataConfig>,
) -> eyre::Result<ProvisionOutcome> {
    let Some(userdata) = userdata else {
        return Ok(ProvisionOutcome::skipped("no userdata configured"));
    };
    if userdata.content.trim().is_empty() {
        return Ok(ProvisionOutcome::skipped("userdata content is empty"));
    }

    if userdata.content_type != UserdataContentType::ShellScript {
        return Ok(ProvisionOutcome::unsupported(format!(
            "agent provisioning only supports shell-script userdata for now, got {:?}",
            userdata.content_type
        )));
    }

    let hash = userdata_hash(userdata);
    let hash_path = context.guest_path(USERDATA_HASH_PATH);
    if userdata.run == UserdataRunPolicy::Once
        && applied_hash(&hash_path)?.as_deref() == Some(&hash)
    {
        tracing::info!(hash = %hash, "userdata already applied for content hash");
        return Ok(ProvisionOutcome::skipped(
            "userdata already applied for content hash",
        ));
    }

    let path = context.guest_path(USERDATA_SCRIPT_PATH);
    write_file(&path, &userdata.content, 0o700)?;
    let script = path.to_string_lossy().to_string();
    run_command(context.process_supervisor(), "/bin/sh", [script.as_str()])?;
    write_file(&hash_path, format!("{hash}\n"), 0o644)?;
    tracing::info!(path = %path.display(), hash = %hash, run = ?userdata.run, "reconciled userdata script");
    Ok(ProvisionOutcome::succeeded(true))
}

fn applied_hash(path: &std::path::Path) -> eyre::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("read userdata hash marker {}", path.display()))
        }
    }
}

fn userdata_hash(userdata: &UserdataConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(userdata_content_type_name(&userdata.content_type).as_bytes());
    hasher.update(b"\0");
    hasher.update(userdata.content.as_bytes());
    let digest = hasher.finalize();

    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hash, "{byte:02x}");
    }
    hash
}

fn userdata_content_type_name(content_type: &UserdataContentType) -> &'static str {
    match content_type {
        UserdataContentType::ShellScript => "shell_script",
        UserdataContentType::CloudConfig => "cloud_config",
        UserdataContentType::PlainText => "plain_text",
    }
}

#[cfg(test)]
mod tests {
    use agent_spec::{UserdataConfig, UserdataContentType, UserdataRunPolicy};

    #[test]
    fn userdata_hash_changes_with_content() {
        let first = UserdataConfig {
            content: "#!/bin/sh\necho one\n".to_string(),
            content_type: UserdataContentType::ShellScript,
            run: UserdataRunPolicy::Once,
        };
        let second = UserdataConfig {
            content: "#!/bin/sh\necho two\n".to_string(),
            content_type: UserdataContentType::ShellScript,
            run: UserdataRunPolicy::Once,
        };

        assert_ne!(super::userdata_hash(&first), super::userdata_hash(&second));
    }

    #[test]
    fn userdata_hash_ignores_run_policy() {
        let once = UserdataConfig {
            content: "#!/bin/sh\necho hello\n".to_string(),
            content_type: UserdataContentType::ShellScript,
            run: UserdataRunPolicy::Once,
        };
        let always = UserdataConfig {
            run: UserdataRunPolicy::Always,
            ..once.clone()
        };

        assert_eq!(super::userdata_hash(&once), super::userdata_hash(&always));
    }
}

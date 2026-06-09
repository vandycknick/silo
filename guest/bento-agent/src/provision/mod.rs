use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use bento_core::agent::ProvisionConfig;
use eyre::{eyre, Context};

mod ca;
mod growpart;
mod hostname;
mod locale;
mod mounts;
mod networkd;
mod ssh;
mod state;
mod timezone;
mod user;
mod userdata;

pub fn run_provisioning(config: &ProvisionConfig) -> eyre::Result<()> {
    if !config.enabled {
        tracing::debug!("guest provisioning disabled");
        return Ok(());
    }

    let context = ProvisionContext::default();
    if state::is_complete(&context, &config.state_path)? {
        tracing::info!(state_path = %config.state_path, "guest provisioning already complete");
        return Ok(());
    }

    tracing::info!("guest provisioning starting");
    hostname::apply(&context, config.hostname.as_deref())?;
    timezone::apply(&context, config.timezone.as_deref())?;
    locale::apply(&context, config.locale.as_deref())?;
    user::apply(&context, &config.users)?;
    ca::apply(&context, config.certificate_authority.as_ref())?;
    growpart::apply(&config.growpart)?;
    mounts::apply(&context, &config.mounts)?;
    networkd::apply(&context, &config.network)?;
    userdata::apply(&context, config.userdata.as_ref())?;
    state::mark_complete(&context, &config.state_path)?;
    tracing::info!("guest provisioning complete");

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct ProvisionContext {
    root: PathBuf,
}

impl Default for ProvisionContext {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }
}

impl ProvisionContext {
    pub(crate) fn guest_path(&self, path: &str) -> PathBuf {
        let path = path.strip_prefix('/').unwrap_or(path);
        self.root.join(path)
    }
}

pub(crate) fn write_file(path: &Path, contents: impl AsRef<[u8]>, mode: u32) -> eyre::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }

    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions on {}", path.display()))?;
    Ok(())
}

pub(crate) fn run_command<I, S>(program: &str, args: I) -> eyre::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect::<Vec<_>>();
    tracing::debug!(program, args = ?args, "running provisioning command");

    let status = Command::new(program)
        .args(&args)
        .status()
        .with_context(|| format!("run provisioning command {program}"))?;
    if !status.success() {
        return Err(eyre!(
            "provisioning command {program} failed with status {status}"
        ));
    }

    Ok(())
}

pub(crate) fn command_output<I, S>(program: &str, args: I) -> eyre::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect::<Vec<_>>();
    let output = Command::new(program)
        .args(&args)
        .output()
        .with_context(|| format!("run provisioning command {program}"))?;
    if !output.status.success() {
        return Err(eyre!(
            "provisioning command {program} failed with status {}",
            output.status
        ));
    }

    String::from_utf8(output.stdout).context("decode provisioning command output as UTF-8")
}

pub(crate) fn command_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).is_file();
    }

    let search_path = std::env::var_os("PATH").unwrap_or_else(|| {
        OsString::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    });

    std::env::split_paths(&search_path).any(|dir| dir.join(program).is_file())
}

pub(crate) fn sanitize_unit_name(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        sanitized.push_str("default");
    }
    sanitized
}

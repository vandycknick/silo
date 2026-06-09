use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bento_core::agent::ProvisionConfig;
use eyre::{eyre, Context};

mod ca;
mod hostname;
mod locale;
mod mounts;
mod networkd;
mod resize;
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
    match state::is_complete(&context, &config.state_path) {
        Ok(true) => {
            tracing::info!(state_path = %config.state_path, "guest provisioning already complete");
            return Ok(());
        }
        Ok(false) => {}
        Err(err) => {
            tracing::warn!(
                state_path = %config.state_path,
                error = %format_error_chain(&err),
                "could not read guest provisioning state; provisioning will continue"
            );
        }
    }

    tracing::info!("guest provisioning starting");

    let mut run = ProvisionRun::default();
    run.step("hostname", || {
        hostname::apply(&context, config.hostname.as_deref())
    });
    run.step("timezone", || {
        timezone::apply(&context, config.timezone.as_deref())
    });
    run.step("locale", || {
        locale::apply(&context, config.locale.as_deref())
    });
    run.step("users", || user::apply(&context, &config.users));
    run.step("certificate_authority", || {
        ca::apply(&context, config.certificate_authority.as_ref())
    });
    run.step("resize_rootfs", || resize::apply(&config.resize_rootfs));
    run.step("mounts", || mounts::apply(&context, &config.mounts));
    run.step("networkd", || networkd::apply(&context, &config.network));
    run.step("userdata", || {
        userdata::apply(&context, config.userdata.as_ref())
    });

    if run.is_success() {
        match state::mark_complete(&context, &config.state_path) {
            Ok(()) => {
                tracing::info!(state_path = %config.state_path, "guest provisioning complete")
            }
            Err(err) => {
                tracing::error!(
                    state_path = %config.state_path,
                    error = %format_error_chain(&err),
                    "failed to mark guest provisioning complete; provisioning will retry on next agent start"
                );
            }
        }
    } else {
        tracing::warn!(
            failures = run.failure_count(),
            provisioners = %run.failed_step_list(),
            "guest provisioning finished with failures; provisioning will retry on next agent start"
        );
    }

    Ok(())
}

#[derive(Debug, Default)]
struct ProvisionRun {
    failed_steps: Vec<&'static str>,
}

impl ProvisionRun {
    fn step(&mut self, name: &'static str, apply: impl FnOnce() -> eyre::Result<()>) {
        tracing::debug!(provisioner = name, "provisioner starting");
        match apply() {
            Ok(()) => tracing::debug!(provisioner = name, "provisioner complete"),
            Err(err) => {
                self.failed_steps.push(name);
                tracing::error!(
                    provisioner = name,
                    error = %format_error_chain(&err),
                    "provisioner failed; continuing"
                );
            }
        }
    }

    fn is_success(&self) -> bool {
        self.failed_steps.is_empty()
    }

    fn failure_count(&self) -> usize {
        self.failed_steps.len()
    }

    fn failed_step_list(&self) -> String {
        self.failed_steps.join(", ")
    }
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
    let args = collect_command_args(args);
    tracing::debug!(program, args = ?args, "running provisioning command");

    let output = Command::new(program)
        .args(&args)
        .output()
        .with_context(|| {
            format!(
                "run provisioning command {}",
                format_command(program, &args)
            )
        })?;
    if !output.status.success() {
        return Err(command_failure(program, &args, &output));
    }

    Ok(())
}

pub(crate) fn command_output<I, S>(program: &str, args: I) -> eyre::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = collect_command_args(args);
    tracing::debug!(program, args = ?args, "running provisioning command");

    let output = Command::new(program)
        .args(&args)
        .output()
        .with_context(|| {
            format!(
                "run provisioning command {}",
                format_command(program, &args)
            )
        })?;
    if !output.status.success() {
        return Err(command_failure(program, &args, &output));
    }

    String::from_utf8(output.stdout).with_context(|| {
        format!(
            "decode stdout from provisioning command {} as UTF-8",
            format_command(program, &args)
        )
    })
}

fn collect_command_args<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect()
}

fn command_failure(program: &str, args: &[OsString], output: &Output) -> eyre::Report {
    eyre!(
        "provisioning command {} failed with {}; stdout: {}; stderr: {}",
        format_command(program, args),
        output.status,
        command_stream_for_log(&output.stdout),
        command_stream_for_log(&output.stderr)
    )
}

fn format_command(program: &str, args: &[OsString]) -> String {
    let mut command = String::from(program);
    for arg in args {
        command.push(' ');
        command.push_str(&arg.to_string_lossy());
    }
    command
}

fn command_stream_for_log(value: &[u8]) -> String {
    let value = String::from_utf8_lossy(value).trim().to_string();
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        value
    }
}

pub(crate) fn format_error_chain(error: &eyre::Report) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
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

#[cfg(test)]
mod tests {
    use eyre::{eyre, WrapErr};

    use crate::provision::{command_stream_for_log, format_error_chain, ProvisionRun};

    #[test]
    fn provision_run_continues_after_failure() {
        let mut calls = Vec::new();
        let mut run = ProvisionRun::default();

        run.step("first", || {
            calls.push("first");
            Err(eyre!("boom"))
        });
        run.step("second", || {
            calls.push("second");
            Ok(())
        });

        assert_eq!(calls, ["first", "second"]);
        assert!(!run.is_success());
        assert_eq!(run.failure_count(), 1);
        assert_eq!(run.failed_step_list(), "first");
    }

    #[test]
    fn provision_run_reports_success_only_without_failures() {
        let mut run = ProvisionRun::default();
        assert!(run.is_success());

        run.step("broken", || Err(eyre!("nope")));

        assert!(!run.is_success());
    }

    #[test]
    fn error_chain_is_readable() {
        let error = Err::<(), _>(eyre!("inner"))
            .wrap_err("outer")
            .expect_err("error should be preserved");

        assert_eq!(format_error_chain(&error), "outer: inner");
    }

    #[test]
    fn empty_command_streams_are_explicit() {
        assert_eq!(command_stream_for_log(b""), "<empty>");
        assert_eq!(command_stream_for_log(b" hello\n"), "hello");
    }
}

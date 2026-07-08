use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agent_spec::{AgentSshConfig, ProvisionConfig, UserdataContentType};
use eyre::{eyre, Context};
use protocol::v1::{
    ProvisionFailurePolicy as ProtoProvisionFailurePolicy, ProvisionOverallStatus, ProvisionReport,
    ProvisionStepReport, ProvisionStepStatus,
};

use crate::handoff::BootMode;
use crate::pid1::ProcessSupervisor;

mod ca;
mod hostname;
mod locale;
mod mounts;
mod networkd;
mod resize;
mod rosetta;
mod service_manager;
mod ssh;
mod timezone;
mod user;
mod userdata;

pub(crate) use service_manager::ServiceManagerState;

pub fn run_provisioning(
    config: &ProvisionConfig,
    ssh_config: &AgentSshConfig,
    process_supervisor: &ProcessSupervisor,
    boot_mode: &BootMode,
) -> eyre::Result<ProvisionReport> {
    let started_unix_ms = unix_time_ms();
    let started = Instant::now();

    if !config.enabled {
        tracing::debug!("guest provisioning disabled");
        return Ok(ProvisionReport {
            status: ProvisionOverallStatus::Skipped as i32,
            started_unix_ms,
            finished_unix_ms: unix_time_ms(),
            duration_ms: started.elapsed().as_millis() as u64,
            steps: Vec::new(),
            message: String::from("guest provisioning disabled"),
        });
    }

    let context = ProvisionContext::new(process_supervisor.clone(), boot_mode);
    tracing::info!("guest reconciliation starting");

    let mut run = ProvisionRun::default();
    run.run(provisioners(&context, config, ssh_config));

    if run.is_success() {
        tracing::info!("guest reconciliation complete");
    } else {
        tracing::warn!(
            failures = run.failure_count(),
            unsupported = run.unsupported_count(),
            provisioners = %run.problem_step_list(),
            "guest reconciliation finished with failures; agent will continue"
        );
    }

    Ok(run.finish(started_unix_ms, started))
}

fn provisioners<'a>(
    context: &'a ProvisionContext,
    config: &'a ProvisionConfig,
    ssh_config: &'a AgentSshConfig,
) -> Vec<ProvisionerStep<'a>> {
    vec![
        ProvisionerStep::new(
            ProvisionerId::HOSTNAME,
            &[ProvisionResource::Hostname],
            move || configured_text(config.hostname.as_deref(), "no hostname configured"),
            move || hostname::apply(context, config.hostname.as_deref()),
        ),
        ProvisionerStep::new(
            ProvisionerId::TIMEZONE,
            &[ProvisionResource::Timezone],
            move || configured_text(config.timezone.as_deref(), "no timezone configured"),
            move || timezone::apply(context, config.timezone.as_deref()),
        ),
        ProvisionerStep::new(
            ProvisionerId::LOCALE,
            &[ProvisionResource::Locale],
            move || configured_text(config.locale.as_deref(), "no locale configured"),
            move || locale::apply(context, config.locale.as_deref()),
        ),
        ProvisionerStep::new(
            ProvisionerId::USERS,
            &[ProvisionResource::Users],
            move || configured(!config.users.is_empty(), "no users configured"),
            move || user::apply(context, &config.users),
        ),
        ProvisionerStep::new(
            ProvisionerId::SSH_AUTHORIZED_KEYS,
            &[ProvisionResource::SshAuthorizedKeys],
            move || {
                configured(
                    !ssh_config.authorized_users.is_empty(),
                    "no SSH authorized users configured",
                )
            },
            move || ssh::apply(context, &ssh_config.authorized_users),
        ),
        ProvisionerStep::new(
            ProvisionerId::CERTIFICATE_AUTHORITY,
            &[ProvisionResource::CertificateStore],
            move || {
                configured(
                    config.certificate_authority.is_some(),
                    "no certificate authority configured",
                )
            },
            move || ca::apply(context, config.certificate_authority.as_ref()),
        ),
        ProvisionerStep::new(
            ProvisionerId::RESIZE_ROOTFS,
            &[ProvisionResource::RootFilesystem],
            move || {
                configured(
                    config.resize_rootfs.enabled,
                    "root filesystem resize disabled",
                )
            },
            move || resize::apply(context, &config.resize_rootfs),
        ),
        ProvisionerStep::new(
            ProvisionerId::MOUNTS,
            &[ProvisionResource::MountTable],
            move || configured(!config.mounts.is_empty(), "no mounts configured"),
            move || mounts::apply(context, &config.mounts),
        ),
        ProvisionerStep::new(
            ProvisionerId::ROSETTA,
            &[ProvisionResource::Rosetta, ProvisionResource::MountTable],
            move || configured(config.rosetta.enabled, "Rosetta disabled"),
            move || rosetta::apply(context, &config.rosetta),
        ),
        ProvisionerStep::new(
            ProvisionerId::NETWORKD,
            &[
                ProvisionResource::NetworkConfig,
                ProvisionResource::ServiceManager,
            ],
            || ProvisionSupport::Supported,
            move || networkd::apply(context, &config.network),
        ),
        ProvisionerStep::new(
            ProvisionerId::USERDATA,
            &[ProvisionResource::Userdata],
            move || userdata_support(config.userdata.as_ref()),
            move || userdata::apply(context, config.userdata.as_ref()),
        ),
    ]
}

fn configured(condition: bool, skipped_message: &'static str) -> ProvisionSupport {
    if condition {
        ProvisionSupport::Supported
    } else {
        ProvisionSupport::Skipped {
            message: skipped_message.to_string(),
        }
    }
}

fn configured_text(value: Option<&str>, skipped_message: &'static str) -> ProvisionSupport {
    configured(
        value.map(str::trim).is_some_and(|value| !value.is_empty()),
        skipped_message,
    )
}

fn userdata_support(userdata: Option<&agent_spec::UserdataConfig>) -> ProvisionSupport {
    let Some(userdata) = userdata else {
        return ProvisionSupport::Skipped {
            message: String::from("no userdata configured"),
        };
    };
    if userdata.content.trim().is_empty() {
        return ProvisionSupport::Skipped {
            message: String::from("userdata content is empty"),
        };
    }
    if userdata.content_type != UserdataContentType::ShellScript {
        return ProvisionSupport::Unsupported {
            message: format!(
                "userdata content type {:?} is not supported",
                userdata.content_type
            ),
        };
    }
    ProvisionSupport::Supported
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ProvisionerId(&'static str);

impl ProvisionerId {
    const HOSTNAME: Self = Self("hostname");
    const TIMEZONE: Self = Self("timezone");
    const LOCALE: Self = Self("locale");
    const USERS: Self = Self("users");
    const SSH_AUTHORIZED_KEYS: Self = Self("ssh_authorized_keys");
    const CERTIFICATE_AUTHORITY: Self = Self("certificate_authority");
    const RESIZE_ROOTFS: Self = Self("resize_rootfs");
    const MOUNTS: Self = Self("mounts");
    const ROSETTA: Self = Self("rosetta");
    const NETWORKD: Self = Self("networkd");
    const USERDATA: Self = Self("userdata");

    fn as_str(self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProvisionResource {
    RootFilesystem,
    MountTable,
    Hostname,
    Timezone,
    Locale,
    Users,
    SshAuthorizedKeys,
    CertificateStore,
    ServiceManager,
    NetworkConfig,
    Rosetta,
    Userdata,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FailurePolicy {
    BestEffort,
    FailBoot,
}

impl FailurePolicy {
    fn as_proto(self) -> ProtoProvisionFailurePolicy {
        match self {
            Self::BestEffort => ProtoProvisionFailurePolicy::BestEffort,
            Self::FailBoot => ProtoProvisionFailurePolicy::FailBoot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProvisionSupport {
    Supported,
    Skipped { message: String },
    Unsupported { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvisionOutcome {
    Succeeded { changed: bool, message: String },
    Skipped { message: String },
    Unsupported { message: String },
}

impl ProvisionOutcome {
    pub(crate) fn succeeded(changed: bool) -> Self {
        Self::Succeeded {
            changed,
            message: String::from("provisioner complete"),
        }
    }

    pub(crate) fn skipped(message: impl Into<String>) -> Self {
        Self::Skipped {
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported {
            message: message.into(),
        }
    }
}

struct ProvisionerStep<'a> {
    id: ProvisionerId,
    dependencies: &'static [ProvisionerId],
    resources: &'static [ProvisionResource],
    failure_policy: FailurePolicy,
    supports: Box<dyn Fn() -> ProvisionSupport + 'a>,
    execute: Box<dyn Fn() -> eyre::Result<ProvisionOutcome> + 'a>,
}

struct StepRecord {
    id: ProvisionerId,
    status: ProvisionStepStatus,
    failure_policy: FailurePolicy,
    changed: bool,
    started: Instant,
    message: String,
    error_chain: String,
}

impl StepRecord {
    fn into_report(self) -> ProvisionStepReport {
        ProvisionStepReport {
            id: self.id.as_str().to_string(),
            status: self.status as i32,
            failure_policy: self.failure_policy.as_proto() as i32,
            changed: self.changed,
            backend: String::new(),
            duration_ms: self.started.elapsed().as_millis() as u64,
            message: self.message,
            error_chain: self.error_chain,
        }
    }
}

impl<'a> ProvisionerStep<'a> {
    fn new(
        id: ProvisionerId,
        resources: &'static [ProvisionResource],
        supports: impl Fn() -> ProvisionSupport + 'a,
        execute: impl Fn() -> eyre::Result<ProvisionOutcome> + 'a,
    ) -> Self {
        Self {
            id,
            dependencies: &[],
            resources,
            failure_policy: FailurePolicy::BestEffort,
            supports: Box::new(supports),
            execute: Box::new(execute),
        }
    }

    #[cfg(test)]
    fn with_dependencies(mut self, dependencies: &'static [ProvisionerId]) -> Self {
        self.dependencies = dependencies;
        self
    }

    #[cfg(test)]
    fn with_failure_policy(mut self, failure_policy: FailurePolicy) -> Self {
        self.failure_policy = failure_policy;
        self
    }
}

#[derive(Debug, Default)]
struct ProvisionRun {
    steps: Vec<ProvisionStepReport>,
    failed_boot: bool,
}

impl ProvisionRun {
    fn run<'a>(&mut self, provisioners: Vec<ProvisionerStep<'a>>) {
        for provisioner in provisioners {
            self.step(provisioner);
            if self.failed_boot {
                break;
            }
        }
    }

    fn step(&mut self, provisioner: ProvisionerStep<'_>) {
        let id = provisioner.id;
        let name = id.as_str();
        tracing::debug!(
            provisioner = name,
            dependencies = ?provisioner.dependencies,
            resources = ?provisioner.resources,
            failure_policy = ?provisioner.failure_policy,
            "provisioner starting"
        );
        let started = Instant::now();

        if let Some(dependency) = self.blocking_dependency(provisioner.dependencies) {
            let message = format!(
                "skipped because dependency {} did not succeed",
                dependency.as_str()
            );
            tracing::warn!(
                provisioner = name,
                dependency = dependency.as_str(),
                "provisioner skipped because dependency did not succeed"
            );
            self.push_step(StepRecord {
                id: provisioner.id,
                status: ProvisionStepStatus::Skipped,
                failure_policy: provisioner.failure_policy,
                changed: false,
                started,
                message,
                error_chain: String::new(),
            });
            return;
        }

        match (provisioner.supports)() {
            ProvisionSupport::Supported => {}
            ProvisionSupport::Skipped { message } => {
                tracing::debug!(provisioner = name, reason = %message, "provisioner skipped");
                self.push_step(StepRecord {
                    id,
                    status: ProvisionStepStatus::Skipped,
                    failure_policy: provisioner.failure_policy,
                    changed: false,
                    started,
                    message,
                    error_chain: String::new(),
                });
                return;
            }
            ProvisionSupport::Unsupported { message } => {
                tracing::warn!(provisioner = name, reason = %message, "provisioner unsupported");
                self.push_step(StepRecord {
                    id,
                    status: ProvisionStepStatus::Unsupported,
                    failure_policy: provisioner.failure_policy,
                    changed: false,
                    started,
                    message,
                    error_chain: String::new(),
                });
                self.maybe_mark_failed_boot(provisioner.failure_policy);
                return;
            }
        }

        match (provisioner.execute)() {
            Ok(outcome) => self.record_outcome(id, provisioner.failure_policy, started, outcome),
            Err(err) => self.record_failure(id, provisioner.failure_policy, started, err),
        }
    }

    fn record_outcome(
        &mut self,
        id: ProvisionerId,
        failure_policy: FailurePolicy,
        started: Instant,
        outcome: ProvisionOutcome,
    ) {
        match outcome {
            ProvisionOutcome::Succeeded { changed, message } => {
                tracing::debug!(provisioner = id.as_str(), changed, "provisioner complete");
                self.push_step(StepRecord {
                    id,
                    status: ProvisionStepStatus::Succeeded,
                    failure_policy,
                    changed,
                    started,
                    message,
                    error_chain: String::new(),
                });
            }
            ProvisionOutcome::Skipped { message } => {
                tracing::debug!(
                    provisioner = id.as_str(),
                    reason = %message,
                    "provisioner skipped"
                );
                self.push_step(StepRecord {
                    id,
                    status: ProvisionStepStatus::Skipped,
                    failure_policy,
                    changed: false,
                    started,
                    message,
                    error_chain: String::new(),
                });
            }
            ProvisionOutcome::Unsupported { message } => {
                tracing::warn!(
                    provisioner = id.as_str(),
                    reason = %message,
                    "provisioner unsupported"
                );
                self.push_step(StepRecord {
                    id,
                    status: ProvisionStepStatus::Unsupported,
                    failure_policy,
                    changed: false,
                    started,
                    message,
                    error_chain: String::new(),
                });
                self.maybe_mark_failed_boot(failure_policy);
            }
        }
    }

    fn record_failure(
        &mut self,
        id: ProvisionerId,
        failure_policy: FailurePolicy,
        started: Instant,
        err: eyre::Report,
    ) {
        let error_chain = format_error_chain(&err);
        tracing::error!(
            provisioner = id.as_str(),
            error = %error_chain,
            "provisioner failed; continuing"
        );
        self.push_step(StepRecord {
            id,
            status: ProvisionStepStatus::Failed,
            failure_policy,
            changed: false,
            started,
            message: failure_message(failure_policy),
            error_chain,
        });
        self.maybe_mark_failed_boot(failure_policy);
    }

    fn push_step(&mut self, record: StepRecord) {
        self.steps.push(record.into_report());
    }

    fn maybe_mark_failed_boot(&mut self, failure_policy: FailurePolicy) {
        if failure_policy == FailurePolicy::FailBoot {
            self.failed_boot = true;
        }
    }

    fn blocking_dependency(&self, dependencies: &[ProvisionerId]) -> Option<ProvisionerId> {
        dependencies.iter().copied().find(|dependency| {
            self.step_status(*dependency) != Some(ProvisionStepStatus::Succeeded)
        })
    }

    fn step_status(&self, id: ProvisionerId) -> Option<ProvisionStepStatus> {
        self.steps
            .iter()
            .find(|step| step.id == id.as_str())
            .map(|step| {
                ProvisionStepStatus::try_from(step.status)
                    .unwrap_or(ProvisionStepStatus::Unspecified)
            })
    }

    fn is_success(&self) -> bool {
        !self.failed_boot && self.problem_count() == 0
    }

    fn failure_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.status == ProvisionStepStatus::Failed as i32)
            .count()
    }

    fn unsupported_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.status == ProvisionStepStatus::Unsupported as i32)
            .count()
    }

    fn problem_count(&self) -> usize {
        self.failure_count() + self.unsupported_count()
    }

    fn problem_step_list(&self) -> String {
        self.steps
            .iter()
            .filter(|step| {
                matches!(
                    ProvisionStepStatus::try_from(step.status)
                        .unwrap_or(ProvisionStepStatus::Unspecified),
                    ProvisionStepStatus::Failed | ProvisionStepStatus::Unsupported
                )
            })
            .map(|step| step.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn finish(self, started_unix_ms: i64, started: Instant) -> ProvisionReport {
        let problem_count = self.problem_count();
        let status = if self.failed_boot {
            ProvisionOverallStatus::FailedBoot
        } else if problem_count == 0 {
            ProvisionOverallStatus::Succeeded
        } else {
            ProvisionOverallStatus::Degraded
        };
        let message = if self.failed_boot {
            String::from("guest reconciliation aborted after fail-boot provisioner failure")
        } else if problem_count == 0 {
            String::from("guest reconciliation complete")
        } else {
            format!(
                "guest reconciliation completed with {problem_count} best-effort provisioner issue(s)"
            )
        };

        ProvisionReport {
            status: status as i32,
            started_unix_ms,
            finished_unix_ms: unix_time_ms(),
            duration_ms: started.elapsed().as_millis() as u64,
            steps: self.steps,
            message,
        }
    }
}

fn failure_message(failure_policy: FailurePolicy) -> String {
    match failure_policy {
        FailurePolicy::BestEffort => String::from("provisioner failed; continuing"),
        FailurePolicy::FailBoot => String::from("provisioner failed; failing guest boot"),
    }
}

fn unix_time_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(_) => 0,
    }
}

#[derive(Clone)]
pub(crate) struct ProvisionContext {
    root: PathBuf,
    process_supervisor: ProcessSupervisor,
    service_manager: ServiceManagerState,
}

impl ProvisionContext {
    fn new(process_supervisor: ProcessSupervisor, boot_mode: &BootMode) -> Self {
        Self {
            root: PathBuf::from("/"),
            process_supervisor,
            service_manager: ServiceManagerState::detect(boot_mode),
        }
    }

    pub(crate) fn guest_path(&self, path: &str) -> PathBuf {
        let path = path.strip_prefix('/').unwrap_or(path);
        self.root.join(path)
    }

    pub(crate) fn process_supervisor(&self) -> &ProcessSupervisor {
        &self.process_supervisor
    }

    pub(crate) fn service_manager(&self) -> &ServiceManagerState {
        &self.service_manager
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

pub(crate) fn run_command<I, S>(
    process_supervisor: &ProcessSupervisor,
    program: &str,
    args: I,
) -> eyre::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = collect_command_args(args);
    tracing::debug!(program, args = ?args, "running provisioning command");

    let output = process_supervisor.output(program, &args).with_context(|| {
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

pub(crate) fn command_output<I, S>(
    process_supervisor: &ProcessSupervisor,
    program: &str,
    args: I,
) -> eyre::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = collect_command_args(args);
    tracing::debug!(program, args = ?args, "running provisioning command");

    let output = process_supervisor.output(program, &args).with_context(|| {
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

pub(crate) fn command_status<I, S>(
    process_supervisor: &ProcessSupervisor,
    program: &str,
    args: I,
) -> eyre::Result<std::process::ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = collect_command_args(args);
    tracing::debug!(program, args = ?args, "running provisioning command");

    process_supervisor.status(program, &args).with_context(|| {
        format!(
            "run provisioning command {}",
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
    use std::cell::RefCell;
    use std::time::Instant;

    use eyre::{eyre, WrapErr};
    use protocol::v1::{ProvisionFailurePolicy, ProvisionOverallStatus, ProvisionStepStatus};

    use crate::provision::{
        command_stream_for_log, format_error_chain, FailurePolicy, ProvisionOutcome, ProvisionRun,
        ProvisionSupport, ProvisionerId, ProvisionerStep,
    };

    #[test]
    fn provision_run_continues_after_failure() {
        let calls = RefCell::new(Vec::new());
        let mut run = ProvisionRun::default();

        run.run(vec![
            ProvisionerStep::new(
                ProvisionerId("first"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("first");
                    Err(eyre!("boom"))
                },
            ),
            ProvisionerStep::new(
                ProvisionerId("second"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("second");
                    Ok(ProvisionOutcome::succeeded(false))
                },
            ),
        ]);

        assert_eq!(calls.into_inner(), ["first", "second"]);
        assert!(!run.is_success());
        assert_eq!(run.failure_count(), 1);
        assert_eq!(run.problem_step_list(), "first");
    }

    #[test]
    fn provision_run_reports_success_when_everything_is_skipped() {
        let mut run = ProvisionRun::default();
        run.run(vec![ProvisionerStep::new(
            ProvisionerId("skipped"),
            &[],
            || ProvisionSupport::Skipped {
                message: String::from("nothing configured"),
            },
            || Ok(ProvisionOutcome::succeeded(true)),
        )]);

        let report = run.finish(100, Instant::now());

        assert_eq!(report.status, ProvisionOverallStatus::Succeeded as i32);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].status, ProvisionStepStatus::Skipped as i32);
        assert_eq!(report.steps[0].message, "nothing configured");
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

    #[test]
    fn provision_run_reports_best_effort_failure_as_degraded() {
        let mut run = ProvisionRun::default();
        run.run(vec![ProvisionerStep::new(
            ProvisionerId("broken"),
            &[],
            || ProvisionSupport::Supported,
            || Err(eyre!("nope")),
        )]);

        let report = run.finish(100, Instant::now());

        assert_eq!(report.status, ProvisionOverallStatus::Degraded as i32);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].id, "broken");
        assert_eq!(report.steps[0].status, ProvisionStepStatus::Failed as i32);
        assert_eq!(
            report.steps[0].failure_policy,
            ProvisionFailurePolicy::BestEffort as i32
        );
        assert_eq!(report.steps[0].error_chain, "nope");
    }

    #[test]
    fn fail_boot_failure_aborts_provisioning() {
        let calls = RefCell::new(Vec::new());
        let mut run = ProvisionRun::default();

        run.run(vec![
            ProvisionerStep::new(
                ProvisionerId("fatal"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("fatal");
                    Err(eyre!("fatal boom"))
                },
            )
            .with_failure_policy(FailurePolicy::FailBoot),
            ProvisionerStep::new(
                ProvisionerId("later"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("later");
                    Ok(ProvisionOutcome::succeeded(false))
                },
            ),
        ]);

        let report = run.finish(100, Instant::now());

        assert_eq!(calls.into_inner(), ["fatal"]);
        assert_eq!(report.status, ProvisionOverallStatus::FailedBoot as i32);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].id, "fatal");
        assert_eq!(report.steps[0].status, ProvisionStepStatus::Failed as i32);
        assert_eq!(
            report.steps[0].failure_policy,
            ProvisionFailurePolicy::FailBoot as i32
        );
    }

    #[test]
    fn dependency_failure_skips_dependent_provisioner() {
        const FIRST_DEPENDENCY: &[ProvisionerId] = &[ProvisionerId("first")];
        let calls = RefCell::new(Vec::new());
        let mut run = ProvisionRun::default();

        run.run(vec![
            ProvisionerStep::new(
                ProvisionerId("first"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("first");
                    Err(eyre!("boom"))
                },
            ),
            ProvisionerStep::new(
                ProvisionerId("dependent"),
                &[],
                || ProvisionSupport::Supported,
                || {
                    calls.borrow_mut().push("dependent");
                    Ok(ProvisionOutcome::succeeded(false))
                },
            )
            .with_dependencies(FIRST_DEPENDENCY),
        ]);

        let report = run.finish(100, Instant::now());

        assert_eq!(calls.into_inner(), ["first"]);
        assert_eq!(report.status, ProvisionOverallStatus::Degraded as i32);
        assert_eq!(report.steps.len(), 2);
        assert_eq!(report.steps[0].id, "first");
        assert_eq!(report.steps[1].id, "dependent");
        assert_eq!(report.steps[1].status, ProvisionStepStatus::Skipped as i32);
        assert!(report.steps[1]
            .message
            .contains("dependency first did not succeed"));
    }

    #[test]
    fn unsupported_best_effort_provisioner_degrades_report() {
        let mut run = ProvisionRun::default();

        run.run(vec![ProvisionerStep::new(
            ProvisionerId("unsupported"),
            &[],
            || ProvisionSupport::Unsupported {
                message: String::from("backend missing"),
            },
            || Ok(ProvisionOutcome::succeeded(true)),
        )]);

        let report = run.finish(100, Instant::now());

        assert_eq!(report.status, ProvisionOverallStatus::Degraded as i32);
        assert_eq!(report.steps.len(), 1);
        assert_eq!(
            report.steps[0].status,
            ProvisionStepStatus::Unsupported as i32
        );
        assert_eq!(report.steps[0].message, "backend missing");
    }
}

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;

use clap::Args;
use libvm::{
    ImageProgressSender, MachineReadinessOutcome, MachineRetention, MachineRunId,
    MachineStartOptions, ReadOnlyRuntime, RuntimeConfig, DEFAULT_GUEST_READINESS_TIMEOUT,
};

use crate::commands::create::{
    create_machine, ensure_name_available, ensure_read_only_name_available, load_template,
    machine_settings, parse_environment, read_environment_layers, render_plan, resolve_plan,
    resolve_read_only_source, resolve_source, selected_image_reference, validate_process_overrides,
    MachineCliOptions, PlanInputs, Pull, VmOverrideArgs,
};
use crate::commands::start_options::machine_start_options_without_cleanup;
use crate::environment::EnvironmentOverride;
use crate::planning::{Plan, PlanKind, ProcessOverrides, RunOptions, TtyCapabilities, TtyMode};
use crate::ui::{watch_image_progress, OutputFormat, Spinner};

#[derive(Debug, Args)]
#[command(about = "Run an image or template workload")]
pub struct Cmd {
    /// OCI registry reference or disk:PATH. Overrides the template image.
    #[arg(value_name = "IMAGE")]
    image: Option<String>,
    /// Template providing VM defaults.
    #[arg(long, value_name = "TEMPLATE")]
    template: Option<String>,
    /// Persist the VM under this name. Unnamed runs are ephemeral.
    #[arg(short = 'n', long, value_name = "NAME")]
    name: Option<String>,
    /// Return after vmmon starts the workload.
    #[arg(short = 'd', long, conflicts_with = "tty")]
    detach: bool,
    /// Attach a TTY to the guest workload.
    #[arg(short = 't', long, conflicts_with_all = ["no_tty", "detach"])]
    tty: bool,
    /// Disable a TTY even when stdin and stdout are terminals.
    #[arg(long, conflicts_with = "tty")]
    no_tty: bool,
    /// Replace the OCI entrypoint with this program.
    #[arg(long, value_name = "PROGRAM", value_parser = parse_entrypoint)]
    entrypoint: Option<String>,
    /// Set an environment variable, or import a host variable by name.
    #[arg(short = 'e', long = "env", value_name = "KEY[=VALUE]", value_parser = parse_environment)]
    env: Vec<EnvironmentOverride>,
    /// Read environment values from this file. May be repeated.
    #[arg(long, value_name = "PATH")]
    env_file: Vec<PathBuf>,
    /// Guest working directory.
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    workdir: Option<String>,
    /// Guest user for the workload.
    #[arg(short = 'u', long)]
    user: Option<String>,
    /// Fallback shell for an otherwise-empty foreground interactive run.
    #[arg(long, value_name = "PATH")]
    shell: Option<String>,
    /// Path to a custom managed guest agent.
    #[arg(long, value_name = "PATH")]
    agent: Option<PathBuf>,
    /// Image pull policy.
    #[arg(long, value_enum)]
    pull: Option<Pull>,
    /// Render the resolved plan without creating a machine.
    #[arg(long)]
    dry_run: bool,
    /// Plan output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
    format: OutputFormat,
    #[command(flatten)]
    overrides: VmOverrideArgs,
    /// Guest command and arguments to execute after `--`.
    #[arg(last = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl Cmd {
    pub async fn run(self, context: &mut crate::context::Context) -> eyre::Result<()> {
        let template = load_template(self.template.as_deref())?;
        let mut machine = self.overrides.resolve()?;
        machine.agent = self.agent;
        validate_options(&machine, self.detach, self.tty)?;
        let host_environment = std::env::vars().collect::<BTreeMap<_, _>>();
        let environment_files = read_environment_layers(&self.env_file, &host_environment)?;
        let process_overrides = ProcessOverrides {
            entrypoint: self.entrypoint.map(|program| vec![program]),
            working_directory: self.workdir,
            user: self.user,
        };
        let run_options = RunOptions {
            detached: self.detach,
            tty: tty_mode(self.tty, self.no_tty),
            capabilities: TtyCapabilities {
                stdin: std::io::stdin().is_terminal(),
                stdout: std::io::stdout().is_terminal(),
            },
            shell: self.shell,
        };
        validate_process_overrides(
            process_overrides.working_directory.as_deref(),
            process_overrides.user.as_deref(),
            run_options.shell.as_deref(),
        )?;
        let policy_config_dir = context.config()?.networking.policy_config_dir.clone();
        crate::commands::create::preflight_create(
            &template.template,
            &machine,
            self.image.as_deref(),
            policy_config_dir.as_deref(),
        )?;
        let retention = if self.name.is_some() {
            MachineRetention::Persistent
        } else {
            MachineRetention::Ephemeral
        };

        if self.dry_run {
            let runtime = ReadOnlyRuntime::open(RuntimeConfig::from_env()?)
                .await
                .map_err(|error| execution_infrastructure(error.into()))?;
            let name = match self.name {
                Some(name) => {
                    ensure_read_only_name_available(&runtime, &name).await?;
                    name
                }
                None => runtime.propose_machine_name()?,
            };
            let source = resolve_read_only_source(
                &runtime,
                self.image.as_deref(),
                &template.template,
                self.pull,
            )
            .await
            .map_err(execution_infrastructure)?;
            let settings = machine_settings(&machine);
            let plan = resolve_plan(PlanInputs {
                kind: PlanKind::Run(run_options),
                template,
                image: source.plan_image,
                image_is_positional: source.is_positional,
                machine_overrides: machine.overrides,
                machine_settings: settings,
                process_overrides,
                command_tail: self.command,
                retention,
                name: Some(name),
                environment_files,
                host_environment,
                environment_overrides: self.env,
            })?;
            return render_plan(&plan, self.format);
        }

        let image_reference = selected_image_reference(self.image.as_deref(), &template.template)?;
        let recipe_progress = Spinner::start("Reading", "run recipe");
        let runtime = context
            .runtime()
            .await
            .map_err(execution_infrastructure)?
            .clone();
        if let Some(name) = &self.name {
            ensure_name_available(&runtime, name).await?;
        }
        recipe_progress.finish_clear();

        let (image_progress, image_events) = ImageProgressSender::default_channel();
        let image_progress_task = watch_image_progress(&image_reference, image_events);
        let progress_runtime = runtime.clone().with_image_progress(image_progress);
        let image_result = async {
            let source = resolve_source(
                &progress_runtime,
                self.image.as_deref(),
                &template.template,
                self.pull,
            )
            .await
            .map_err(execution_infrastructure)?;
            let settings = machine_settings(&machine);
            let plan = resolve_plan(PlanInputs {
                kind: PlanKind::Run(run_options),
                template,
                image: source.plan_image.clone(),
                image_is_positional: source.is_positional,
                machine_overrides: machine.overrides.clone(),
                machine_settings: settings,
                process_overrides,
                command_tail: self.command,
                retention,
                name: self.name,
                environment_files,
                host_environment,
                environment_overrides: self.env,
            })?;
            let Plan::Run(plan) = plan else {
                unreachable!("run resolution returns a run plan")
            };
            let machine = create_machine(&progress_runtime, &plan.create, source, context)
                .await
                .map_err(execution_infrastructure)?;
            Ok::<_, eyre::Report>((plan, machine))
        };
        let image_result = image_result.await;
        drop(progress_runtime);
        let _ = image_progress_task.await;
        let (plan, machine) = image_result?;
        let name = match machine.inspect().await {
            Ok(data) => data.name,
            Err(error) => {
                return Err(cleanup_foreground_failure(
                    &machine,
                    plan.create.retention,
                    error.into(),
                )
                .await)
            }
        };
        if plan.detached {
            let progress = Spinner::start("Starting", &name);
            let options = match detached_start_options(&runtime, &machine, &plan).await {
                Ok(options) => options,
                Err(error) => {
                    return Err(
                        cleanup_foreground_failure(&machine, plan.create.retention, error).await,
                    )
                }
            };
            if let Err(error) = machine.start_with_options(options).await {
                cleanup_ephemeral_best_effort(&machine, plan.create.retention).await;
                return Err(start_failure(error));
            }
            progress.finish_success("Started");
            println!("{name}");
            return Ok(());
        }

        let mut progress = Spinner::start("Starting", &name);
        let options = match machine_start_options_without_cleanup(&runtime, &machine).await {
            Ok(options) => options,
            Err(error) => {
                return Err(
                    cleanup_foreground_failure(&machine, plan.create.retention, error).await,
                )
            }
        };
        let start = match machine.start_with_options(options).await {
            Ok(start) => start,
            Err(error) => {
                return Err(cleanup_foreground_failure(
                    &machine,
                    plan.create.retention,
                    error.into(),
                )
                .await)
            }
        };
        progress.step("Waiting", &name);
        let readiness = match machine.wait_ready(DEFAULT_GUEST_READINESS_TIMEOUT).await {
            Ok(readiness) => readiness,
            Err(error) => {
                return Err(cleanup_foreground_failure(
                    &machine,
                    plan.create.retention,
                    error.into(),
                )
                .await)
            }
        };
        if readiness.outcome != MachineReadinessOutcome::Ready {
            let error = eyre::eyre!("guest readiness check ended with {:?}", readiness.outcome);
            let stop = stop_run(&machine, start.run_id, plan.create.retention).await;
            return Err(
                foreground_stop_failure(&machine, plan.create.retention, stop, error).await,
            );
        }
        progress.step("Ready", &name);
        progress.finish_success("Started");
        let execution =
            crate::guest::run_process(&machine, &plan.create.process, &plan.argv, plan.tty).await;
        let stop = stop_run(&machine, start.run_id, plan.create.retention).await;
        let result = match execution {
            Ok(result) => result,
            Err(error) => {
                return Err(
                    foreground_stop_failure(&machine, plan.create.retention, stop, error).await,
                );
            }
        };
        if let Err(error) = stop {
            return Err(cleanup_foreground_failure(&machine, plan.create.retention, error).await);
        }
        if let Some(message) = crate::commands::exec::execution_failure_message(&result) {
            eprintln!("{} {message}", crate::ui::error_label());
        }
        std::process::exit(crate::commands::exec::execution_exit_code(result));
    }
}

fn validate_options(machine: &MachineCliOptions, detached: bool, tty: bool) -> eyre::Result<()> {
    if machine.no_agent && machine.provision_user.is_some() {
        eyre::bail!("--no-agent cannot be combined with --provision-user");
    }
    if detached && tty {
        eyre::bail!("--detach cannot be combined with --tty");
    }
    Ok(())
}

fn tty_mode(tty: bool, no_tty: bool) -> TtyMode {
    if tty {
        TtyMode::Enabled
    } else if no_tty {
        TtyMode::Disabled
    } else {
        TtyMode::Auto
    }
}

fn parse_entrypoint(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("entrypoint cannot be empty".to_string());
    }
    Ok(value.to_string())
}

async fn detached_start_options(
    runtime: &libvm::Runtime,
    machine: &libvm::Machine,
    plan: &crate::planning::RunPlan,
) -> eyre::Result<MachineStartOptions> {
    let process = &plan.create.process;
    let (program, args) = plan
        .argv
        .split_first()
        .ok_or_else(|| eyre::eyre!("guest command is required"))?;
    let options = crate::commands::start_options::machine_start_options(runtime, machine).await?;
    let process = process.clone();
    let program = program.clone();
    let args = args.to_vec();
    Ok(options.entrypoint(program, |entrypoint| {
        let entrypoint = entrypoint
            .args(args)
            .cwd(process.working_directory.clone())
            .envs(process.environment.clone());
        match &process.user {
            Some(user) => entrypoint.user(user),
            None => entrypoint,
        }
    }))
}

async fn stop_run(
    machine: &libvm::Machine,
    run_id: MachineRunId,
    retention: MachineRetention,
) -> eyre::Result<()> {
    match machine.stop_run(run_id).await {
        Ok(_) | Err(libvm::LibVmError::MachineNotRunning { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    cleanup_ephemeral_best_effort(machine, retention).await;
    Ok(())
}

fn start_failure(error: libvm::LibVmError) -> eyre::Report {
    let exit_code = match &error {
        libvm::LibVmError::EntrypointLaunchFailed { failure }
            if failure.reason == libvm::ExecutionLaunchFailureReason::CommandNotFound =>
        {
            127
        }
        libvm::LibVmError::EntrypointLaunchFailed { .. } => 126,
        _ => 125,
    };
    eyre::Report::from(error).wrap_err(crate::errors::ExecutionExit::new(exit_code))
}

fn execution_infrastructure(error: eyre::Report) -> eyre::Report {
    error.wrap_err(crate::errors::ExecutionExit::new(125))
}

async fn cleanup_foreground_failure(
    machine: &libvm::Machine,
    retention: MachineRetention,
    error: eyre::Report,
) -> eyre::Report {
    cleanup_ephemeral_best_effort(machine, retention).await;
    error.wrap_err(crate::errors::ExecutionExit::new(125))
}

async fn foreground_stop_failure(
    machine: &libvm::Machine,
    retention: MachineRetention,
    stop: eyre::Result<()>,
    error: eyre::Report,
) -> eyre::Report {
    match stop {
        Ok(()) => execution_infrastructure(error),
        Err(stop_error) => {
            cleanup_foreground_failure(
                machine,
                retention,
                error.wrap_err(format!("stop foreground machine: {stop_error}")),
            )
            .await
        }
    }
}

async fn cleanup_ephemeral_best_effort(machine: &libvm::Machine, retention: MachineRetention) {
    if retention != MachineRetention::Ephemeral {
        return;
    }
    if let Err(error) = machine.clone().remove().await {
        crate::ui::warn(format!(
            "could not remove ephemeral machine {}: {error}; remove it later with `silo rm {}`",
            machine.id(),
            machine.id()
        ));
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::app::Cli;
    use crate::commands::run::start_failure;
    use crate::commands::Command;

    #[test]
    fn run_parses_the_final_image_first_form() {
        let cli = Cli::try_parse_from([
            "silo",
            "run",
            "-d",
            "--no-tty",
            "-n",
            "worker",
            "--template",
            "dev",
            "ubuntu:24.04",
            "--entrypoint",
            "runner",
            "-e",
            "A=one",
            "-e",
            "HOST",
            "--env-file",
            "env",
            "-w",
            "/work",
            "-u",
            "1000",
            "--",
            "test",
            "one",
        ])
        .expect("run parses");
        let Command::Run(run) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(run.image.as_deref(), Some("ubuntu:24.04"));
        assert!(run.detach);
        assert!(run.no_tty);
        assert_eq!(run.command, ["test", "one"]);
        assert_eq!(run.env.len(), 2);
    }

    #[test]
    fn run_rejects_removed_flags_and_detached_tty() {
        assert!(Cli::try_parse_from(["silo", "run", "--image", "ubuntu"]).is_err());
        assert!(Cli::try_parse_from(["silo", "run", "-d", "-t", "ubuntu"]).is_err());
    }

    #[test]
    fn run_keeps_commands_after_the_separator_verbatim() {
        let cli = Cli::try_parse_from([
            "silo",
            "run",
            "disk:rootfs.img",
            "--",
            "printf",
            "%s",
            "hello world",
        ])
        .expect("run parses");
        let Command::Run(run) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(run.command, ["printf", "%s", "hello world"]);
    }

    #[test]
    fn run_parses_a_shell_fallback_path() {
        let cli = Cli::try_parse_from(["silo", "run", "--shell", "/bin/bash", "disk:rootfs.img"])
            .expect("run parses shell");
        let Command::Run(run) = cli.command else {
            panic!("expected run")
        };
        assert_eq!(run.shell.as_deref(), Some("/bin/bash"));
    }

    #[test]
    fn run_rejects_an_empty_entrypoint() {
        assert!(
            Cli::try_parse_from(["silo", "run", "--entrypoint", "", "disk:rootfs.img"]).is_err()
        );
    }

    #[test]
    fn detached_entrypoint_launch_failures_preserve_shell_exit_conventions() {
        let command_not_found = libvm::LibVmError::EntrypointLaunchFailed {
            failure: libvm::ExecutionLaunchFailure {
                reason: libvm::ExecutionLaunchFailureReason::CommandNotFound,
                message: None,
            },
        };
        let launch_failure = libvm::LibVmError::EntrypointLaunchFailed {
            failure: libvm::ExecutionLaunchFailure {
                reason: libvm::ExecutionLaunchFailureReason::SpawnFailed,
                message: None,
            },
        };

        assert_eq!(
            crate::errors::execution_exit_code(&start_failure(command_not_found)),
            Some(127)
        );
        assert_eq!(
            crate::errors::execution_exit_code(&start_failure(launch_failure)),
            Some(126)
        );
    }
}

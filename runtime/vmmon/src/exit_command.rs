use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use eyre::Context;

const MACHINE_ID_ENV: &str = "SILO_MACHINE_ID";
const MACHINE_RUN_ID_ENV: &str = "SILO_MACHINE_RUN_ID";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExitCommand {
    command: PathBuf,
    args: Vec<OsString>,
}

impl ExitCommand {
    pub(crate) fn from_cli(
        command: Option<PathBuf>,
        args: Vec<OsString>,
    ) -> eyre::Result<Option<Self>> {
        match command {
            Some(command) => Ok(Some(Self { command, args })),
            None if args.is_empty() => Ok(None),
            None => eyre::bail!("--exit-command-arg requires --exit-command"),
        }
    }

    pub(crate) fn spawn(&self, machine_id: &str, machine_run_id: &str) {
        if let Err(err) = self.spawn_inner(machine_id, machine_run_id) {
            tracing::warn!(error = %err, command = %self.command.display(), "exit command failed");
        }
    }

    fn spawn_inner(&self, machine_id: &str, machine_run_id: &str) -> eyre::Result<()> {
        let resolve_context = ResolveContext::current()?;
        tracing::debug!(
            command = %self.command.display(),
            args = ?self.args,
            cwd = %resolve_context.cwd.display(),
            "resolving exit command"
        );
        let executable = resolve_exit_command_with_context(&self.command, &resolve_context)?;

        tracing::info!(
            command = %self.command.display(),
            executable = %executable.display(),
            args = ?self.args,
            cwd = %resolve_context.cwd.display(),
            "spawning exit command"
        );

        let mut command = tokio::process::Command::new(&executable);
        command
            .args(&self.args)
            .env(MACHINE_ID_ENV, machine_id)
            .env(MACHINE_RUN_ID_ENV, machine_run_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);

        let child = command
            .spawn()
            .with_context(|| format!("spawn exit command {}", executable.display()))?;
        tracing::info!(pid = child.id(), executable = %executable.display(), "exit command spawned");
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ResolveContext {
    cwd: PathBuf,
    current_exe: PathBuf,
    path_entries: Vec<PathBuf>,
}

impl ResolveContext {
    fn current() -> eyre::Result<Self> {
        let path_entries = std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).collect())
            .unwrap_or_default();
        Ok(Self {
            cwd: std::env::current_dir().context("resolve current working directory")?,
            current_exe: std::env::current_exe().context("resolve vmmon executable path")?,
            path_entries,
        })
    }
}

fn resolve_exit_command_with_context(
    command: &Path,
    context: &ResolveContext,
) -> eyre::Result<PathBuf> {
    if command.as_os_str().is_empty() {
        eyre::bail!("exit command path is empty");
    }

    if command.is_absolute() {
        return validate_executable(command);
    }

    if has_path_separator(command) {
        return validate_executable(&context.cwd.join(command));
    }

    for entry in &context.path_entries {
        let candidate = entry.join(command);
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }

    if let Some(parent) = context.current_exe.parent() {
        let sibling = parent.join(command);
        if is_executable_file(&sibling) {
            return Ok(sibling);
        }
    }

    eyre::bail!(
        "exit command {} was not found in PATH or next to {}",
        command.display(),
        context.current_exe.display()
    );
}

fn has_path_separator(path: &Path) -> bool {
    path.components().count() > 1
}

fn validate_executable(path: &Path) -> eyre::Result<PathBuf> {
    let metadata =
        fs::metadata(path).with_context(|| format!("inspect exit command {}", path.display()))?;
    if !metadata.is_file() {
        eyre::bail!("exit command {} is not a file", path.display());
    }
    if !is_executable_metadata(&metadata) {
        eyre::bail!("exit command {} is not executable", path.display());
    }
    Ok(path.to_path_buf())
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && is_executable_metadata(&metadata))
        .unwrap_or(false)
}

#[cfg(unix)]
fn is_executable_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_metadata(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::exit_command::{resolve_exit_command_with_context, ExitCommand, ResolveContext};

    #[test]
    fn from_cli_returns_none_without_command_or_args() {
        assert!(ExitCommand::from_cli(None, Vec::new()).unwrap().is_none());
    }

    #[test]
    fn from_cli_rejects_args_without_command() {
        assert!(ExitCommand::from_cli(None, vec!["cleanup".into()]).is_err());
    }

    #[test]
    fn from_cli_preserves_structured_argv() {
        let command = ExitCommand::from_cli(
            Some(PathBuf::from("hook")),
            vec!["cleanup".into(), "--flag".into()],
        )
        .unwrap()
        .unwrap();

        assert_eq!(command.command, PathBuf::from("hook"));
        assert_eq!(command.args, vec!["cleanup", "--flag"]);
    }

    #[test]
    fn resolves_absolute_command_directly() {
        let fixture = Fixture::new("absolute");
        let command = fixture.executable("hook");
        let context = fixture.context(Vec::new());

        let resolved = resolve_exit_command_with_context(&command, &context).unwrap();

        assert_eq!(resolved, command);
    }

    #[test]
    fn resolves_relative_command_against_cwd() {
        let fixture = Fixture::new("relative");
        let command = fixture.executable("bin/hook");
        let context = fixture.context(Vec::new());

        let resolved = resolve_exit_command_with_context(Path::new("bin/hook"), &context).unwrap();

        assert_eq!(resolved, command);
    }

    #[test]
    fn resolves_bare_command_from_path_first() {
        let fixture = Fixture::new("path-first");
        let path_dir = fixture.dir.join("path-bin");
        fs::create_dir_all(&path_dir).unwrap();
        let path_command = make_executable(path_dir.join("hook"), "#!/bin/sh\nexit 0\n");
        let sibling_command = fixture.executable("hook");
        let context = fixture.context(vec![path_dir]);

        let resolved = resolve_exit_command_with_context(Path::new("hook"), &context).unwrap();

        assert_eq!(resolved, path_command);
        assert_ne!(resolved, sibling_command);
    }

    #[test]
    fn resolves_bare_command_next_to_vmmon_when_path_misses() {
        let fixture = Fixture::new("sibling");
        let sibling_command = fixture.executable("hook");
        let context = fixture.context(Vec::new());

        let resolved = resolve_exit_command_with_context(Path::new("hook"), &context).unwrap();

        assert_eq!(resolved, sibling_command);
    }

    #[test]
    fn missing_bare_command_errors() {
        let fixture = Fixture::new("missing");
        let context = fixture.context(Vec::new());

        assert!(resolve_exit_command_with_context(Path::new("missing-hook"), &context).is_err());
    }

    #[tokio::test]
    async fn spawned_command_outlives_the_handle_and_receives_generation() {
        let fixture = Fixture::new("spawned-watcher");
        let output = fixture.dir.join("generation");
        let script = fixture.executable_with(
            "watcher",
            "#!/bin/sh\nsleep 0.1\nprintf '%s\\n%s\\n' \"$SILO_MACHINE_ID\" \"$SILO_MACHINE_RUN_ID\" > \"$1\"\n",
        );
        let command = ExitCommand::from_cli(Some(script), vec![output.clone().into_os_string()])
            .expect("parse exit command")
            .expect("exit command exists");

        command.spawn("machine-id", "0198c783-cd1c-77c2-b66a-c06275f20d1f");
        drop(command);

        tokio::time::timeout(Duration::from_secs(2), async {
            while !output.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("spawned watcher writes output");
        assert_eq!(
            fs::read_to_string(output).expect("read watcher output"),
            "machine-id\n0198c783-cd1c-77c2-b66a-c06275f20d1f\n"
        );
    }

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "vmmon-exit-command-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn executable(&self, relative: &str) -> PathBuf {
            self.executable_with(relative, "#!/bin/sh\nexit 0\n")
        }

        fn executable_with(&self, relative: &str, contents: &str) -> PathBuf {
            make_executable(self.dir.join(relative), contents)
        }

        fn context(&self, path_entries: Vec<PathBuf>) -> ResolveContext {
            ResolveContext {
                cwd: self.dir.clone(),
                current_exe: self.dir.join("vmmon"),
                path_entries,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn make_executable(path: PathBuf, contents: &str) -> PathBuf {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).unwrap();
        }
        path
    }
}

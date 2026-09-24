//! The `--exit-command` runner.
//!
//! The exit command is not spawned by the supervisor at the end of a
//! generation. Instead a runner is forked early, while the supervisor is still
//! single-threaded and before it opens any machine resource beyond its inherited
//! descriptors, and waits on a pipe:
//!
//! ```text
//! silo-vmm ──fork──► runner (idle, holds only the pipe read end)
//!     │                    │
//!     │ finalize: write 1  │ read returns (byte or EOF)
//!     └──────── pipe ─────►│
//!                          └─ execve(exit command)
//! ```
//!
//! If the supervisor dies without finalizing, the pipe reaches EOF and the
//! command still runs. The runner is never reaped by the supervisor, which
//! exits right after triggering it; it is reparented. Keeping the command out of
//! the supervisor's own process also keeps it independent of any confinement
//! the supervisor enters later.

use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use eyre::Context;
use nix::fcntl::OFlag;

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
}

/// Write end of the pipe the forked runner waits on.
#[derive(Debug)]
pub(crate) struct ExitRunner {
    trigger: File,
}

impl ExitRunner {
    /// Resolve the exit command and fork its runner.
    ///
    /// Must be called while the process is single-threaded: before tracing
    /// (whose appender starts a thread) and before the Tokio runtime.
    pub(crate) fn fork(
        command: &ExitCommand,
        machine_id: &str,
        machine_run_id: &str,
    ) -> eyre::Result<Self> {
        let executable =
            resolve_exit_command_with_context(&command.command, &ResolveContext::current()?)?;
        let program = c_string(executable.as_os_str().as_bytes())?;
        let mut argv = vec![program.clone()];
        for arg in &command.args {
            argv.push(c_string(arg.as_bytes())?);
        }
        let mut envp = Vec::new();
        for (name, value) in std::env::vars_os() {
            if name == MACHINE_ID_ENV || name == MACHINE_RUN_ID_ENV {
                continue;
            }
            let mut entry = name.into_encoded_bytes();
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            envp.push(c_string(&entry)?);
        }
        envp.push(c_string(
            format!("{MACHINE_ID_ENV}={machine_id}").as_bytes(),
        )?);
        envp.push(c_string(
            format!("{MACHINE_RUN_ID_ENV}={machine_run_id}").as_bytes(),
        )?);

        let (read, write) = nix::unistd::pipe().context("create exit runner pipe")?;
        for fd in [&read, &write] {
            nix::fcntl::fcntl(
                fd,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .context("mark exit runner pipe close-on-exec")?;
        }
        // SAFETY: the caller guarantees no other thread exists, so the child
        // cannot inherit a lock held mid-operation by another thread.
        match unsafe { nix::unistd::fork() }.context("fork exit runner")? {
            nix::unistd::ForkResult::Parent { .. } => {
                drop(read);
                Ok(Self {
                    trigger: File::from(write),
                })
            }
            nix::unistd::ForkResult::Child => {
                drop(write);
                run_child(read, &program, &argv, &envp)
            }
        }
    }

    /// Release the runner. Called once, after the exit record is written.
    pub(crate) fn trigger(self) {
        let mut trigger = self.trigger;
        if let Err(error) = trigger.write_all(&[1]) {
            // The runner still observes EOF when this descriptor closes.
            tracing::warn!(%error, "exit runner trigger write failed");
        }
    }
}

fn run_child(trigger: OwnedFd, program: &CString, argv: &[CString], envp: &[CString]) -> ! {
    // Failures here cannot be reported anywhere useful; the command still runs.
    let _ = redirect_stdio_to_null();
    let _ = close_all_except(trigger.as_raw_fd());
    // One byte or EOF releases the runner; only EINTR keeps waiting.
    let mut byte = [0_u8; 1];
    while let Err(nix::errno::Errno::EINTR) = nix::unistd::read(&trigger, &mut byte) {}
    drop(trigger);
    let _ = nix::unistd::execve(program, argv, envp);
    // nix exposes no _exit. The forked child must not run the parent's atexit
    // handlers or destructors.
    unsafe { nix::libc::_exit(127) }
}

fn redirect_stdio_to_null() -> nix::Result<()> {
    let null = nix::fcntl::open("/dev/null", OFlag::O_RDWR, nix::sys::stat::Mode::empty())?;
    nix::unistd::dup2_stdin(&null)?;
    nix::unistd::dup2_stdout(&null)?;
    nix::unistd::dup2_stderr(&null)?;
    Ok(())
}

/// Close every descriptor above stdio except `keep`, so the runner never holds
/// `vm.lock` (flock state belongs to the open file description), log
/// directories or supervisor pipes.
fn close_all_except(keep: RawFd) -> nix::Result<()> {
    #[cfg(target_os = "linux")]
    const FD_DIR: &str = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    const FD_DIR: &str = "/dev/fd";
    let mut open = Vec::new();
    {
        let mut directory = nix::dir::Dir::open(
            FD_DIR,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        let own = directory.as_raw_fd();
        for entry in directory.iter().flatten() {
            if let Some(fd) = entry
                .file_name()
                .to_str()
                .ok()
                .and_then(|name| name.parse::<RawFd>().ok())
            {
                if fd > 2 && fd != keep && fd != own {
                    open.push(fd);
                }
            }
        }
    }
    for fd in open {
        // SAFETY: the single-threaded child owns every inherited descriptor.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    Ok(())
}

fn c_string(bytes: &[u8]) -> eyre::Result<CString> {
    CString::new(bytes).context("exit command argument contains a NUL byte")
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
            current_exe: std::env::current_exe().context("resolve silo-vmm executable path")?,
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn resolves_bare_command_next_to_vmm_when_path_misses() {
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
                "silo-vmm-exit-command-{name}-{}-{unique}",
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
                current_exe: self.dir.join("silo-vmm"),
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

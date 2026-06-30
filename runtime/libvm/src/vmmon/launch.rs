use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::unistd::pipe;

use crate::machine::MachineExitCommand;
use crate::network::VmmonNetworkAttachment;
use crate::store::models::MachineId;
use crate::vmmon::Vmmon;
use crate::LibVmError;

const ENV_VM_STARTPIPE: &str = "_VM_STARTPIPE";
const ENV_VM_SYNCPIPE: &str = "_VM_SYNCPIPE";
const VMMON_LAUNCHER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct VmmonLaunch<'a> {
    pub(crate) machine_id: MachineId,
    pub(crate) name: &'a str,
    pub(crate) machine_dir: &'a Path,
    pub(crate) pidfile: &'a Path,
    pub(crate) exit_status: &'a Path,
    pub(crate) config: &'a Path,
    pub(crate) socket: &'a Path,
    pub(crate) serial_log: &'a Path,
    pub(crate) trace_log: &'a Path,
    pub(crate) network: &'a VmmonNetworkAttachment,
    pub(crate) metadata_config: &'a Path,
    pub(crate) run_id: &'a str,
    pub(crate) exit_command: Option<&'a MachineExitCommand>,
    pub(crate) wait_for_registration: Duration,
}

impl Vmmon {
    pub(crate) async fn spawn(&self, launch: &VmmonLaunch<'_>) -> Result<(), LibVmError> {
        let (start_read, start_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
        let (sync_read, sync_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;

        let mut command = Command::new(resolve_vmmon_executable()?);
        command
            .arg("--id")
            .arg(launch.machine_id.to_string())
            .arg("--name")
            .arg(launch.name)
            .arg("--data-dir")
            .arg(launch.machine_dir)
            .arg("--pidfile")
            .arg(launch.pidfile)
            .arg("--exit-status")
            .arg(launch.exit_status)
            .arg("--config")
            .arg(launch.config)
            .arg("--socket")
            .arg(launch.socket)
            .arg("--serial-log")
            .arg(launch.serial_log)
            .arg("--trace-log")
            .arg(launch.trace_log)
            .arg("--network")
            .arg(launch.network.to_vmmon_arg())
            .arg("--metadata-config")
            .arg(launch.metadata_config)
            .arg("--run-id")
            .arg(launch.run_id)
            .arg("--wait-for-registration")
            .arg(launch.wait_for_registration.as_secs().to_string());
        if let Some(exit_command) = launch.exit_command {
            append_exit_command_args(&mut command, exit_command);
        }
        command
            .env(ENV_VM_STARTPIPE, start_read.as_raw_fd().to_string())
            .env(ENV_VM_SYNCPIPE, sync_write.as_raw_fd().to_string());

        // vmmon handles its own daemonization, so only the child-side pipe fds
        // must survive exec/self-spawn.
        clear_cloexec(&start_read)?;
        clear_cloexec(&sync_write)?;

        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        drop(start_read);
        drop(sync_write);
        wait_for_vmmon_launcher(child).await?;

        release_startpipe(start_write)?;
        wait_for_start(sync_read, launch.trace_log).await
    }
}

fn append_exit_command_args(command: &mut Command, exit_command: &MachineExitCommand) {
    command.arg("--exit-command").arg(&exit_command.command);
    for arg in &exit_command.args {
        command.arg("--exit-command-arg").arg(arg);
    }
}

async fn wait_for_vmmon_launcher(child: std::process::Child) -> io::Result<()> {
    tokio::task::spawn_blocking(move || wait_for_vmmon_launcher_blocking(child))
        .await
        .map_err(|err| io::Error::other(format!("join vmmon launcher wait task: {err}")))?
}

fn wait_for_vmmon_launcher_blocking(mut child: std::process::Child) -> io::Result<()> {
    let deadline = Instant::now() + VMMON_LAUNCHER_EXIT_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "vmmon launcher did not daemonize within {:?}",
                    VMMON_LAUNCHER_EXIT_TIMEOUT
                ),
            ));
        }

        std::thread::sleep(Duration::from_millis(25));
    };

    if status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "vmmon launcher exited with {status}"
    )))
}

fn resolve_vmmon_executable() -> Result<PathBuf, LibVmError> {
    let current_exe = std::env::current_exe()?;
    let expected_path = current_exe
        .parent()
        .map(|parent| parent.join("vmmon"))
        .unwrap_or_else(|| PathBuf::from("vmmon"));

    if expected_path.exists() {
        return Ok(expected_path);
    }

    if let Some(path) = std::env::var_os("PATH") {
        if std::env::split_paths(&path)
            .map(|path| path.join("vmmon"))
            .any(|candidate| candidate.exists())
        {
            return Ok(PathBuf::from("vmmon"));
        }
    }

    Err(LibVmError::VmMonExecutableNotFound { expected_path })
}

async fn wait_for_start(syncpipe: OwnedFd, trace_path: &Path) -> Result<(), LibVmError> {
    let deadline_duration = Duration::from_secs(30);
    let trace_path = trace_path.to_path_buf();
    let result = tokio::time::timeout(
        deadline_duration,
        tokio::task::spawn_blocking(move || read_syncpipe(syncpipe)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "vmmon syncpipe did not report readiness in {:?} (hint: see {})",
                deadline_duration,
                trace_path.display(),
            ),
        )
    })?
    .map_err(|err| io::Error::other(format!("join vmmon syncpipe wait task: {err}")))??;

    match result {
        StartupResult::Started => Ok(()),
        StartupResult::Failed(message) => Err(io::Error::other(message).into()),
    }
}

fn release_startpipe(startpipe: OwnedFd) -> io::Result<()> {
    let mut file = std::fs::File::from(startpipe);
    file.write_all(&[1])?;
    file.flush()
}

fn read_syncpipe(syncpipe: OwnedFd) -> io::Result<StartupResult> {
    let mut input = String::new();
    let mut file = std::fs::File::from(syncpipe);
    std::io::BufReader::new(&mut file).read_line(&mut input)?;

    if input == "started\n" {
        return Ok(StartupResult::Started);
    }

    if let Some(message) = input.strip_prefix("failed\t") {
        return Ok(StartupResult::Failed(message.trim_end().to_string()));
    }

    if input.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vmmon exited before reporting syncpipe result",
        ));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected vmmon syncpipe message: {input:?}"),
    ))
}

fn clear_cloexec(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(|err| io::Error::other(err.to_string()))?;
    let mut fd_flags = FdFlag::from_bits_retain(flags);
    fd_flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(fd_flags)).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

enum StartupResult {
    Started,
    Failed(String),
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::process::Command;

    use nix::unistd::pipe;

    use crate::machine::MachineExitCommand;

    use super::{append_exit_command_args, read_syncpipe, release_startpipe, StartupResult};

    #[test]
    fn release_startpipe_writes_one_byte() {
        let (read_fd, write_fd) = pipe().expect("create pipe");

        release_startpipe(write_fd).expect("release startpipe");

        let mut file = std::fs::File::from(read_fd);
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).expect("read release byte");
        assert_eq!(byte, [1]);
    }

    #[test]
    fn read_syncpipe_accepts_started_message() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut write_file = std::fs::File::from(write_fd);
        write_file.write_all(b"started\n").expect("write started");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).expect("read syncpipe"),
            StartupResult::Started
        ));
    }

    #[test]
    fn read_syncpipe_accepts_failed_message() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut write_file = std::fs::File::from(write_fd);
        write_file
            .write_all(b"failed\tkrun exploded\n")
            .expect("write failure");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).expect("read syncpipe"),
            StartupResult::Failed(message) if message == "krun exploded"
        ));
    }

    #[test]
    fn append_exit_command_args_preserves_structured_argv() {
        let mut command = Command::new("vmmon");
        let exit_command = MachineExitCommand::new(
            "/usr/local/bin/bento",
            [
                OsString::from("cleanup"),
                OsString::from("--data-dir"),
                OsString::from("/tmp/bento"),
                OsString::from("--machine-id"),
                OsString::from("0123456789abcdef0123456789abcdef"),
            ],
        );

        append_exit_command_args(&mut command, &exit_command);

        let args = command
            .get_args()
            .map(|arg| arg.to_os_string())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                OsString::from("--exit-command"),
                OsString::from("/usr/local/bin/bento"),
                OsString::from("--exit-command-arg"),
                OsString::from("cleanup"),
                OsString::from("--exit-command-arg"),
                OsString::from("--data-dir"),
                OsString::from("--exit-command-arg"),
                OsString::from("/tmp/bento"),
                OsString::from("--exit-command-arg"),
                OsString::from("--machine-id"),
                OsString::from("--exit-command-arg"),
                OsString::from("0123456789abcdef0123456789abcdef"),
            ]
        );
    }
}

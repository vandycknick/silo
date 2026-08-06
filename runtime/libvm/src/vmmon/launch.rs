use std::io::{self, BufRead};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::unistd::pipe;
use serde::Deserialize;
use tokio::io::unix::AsyncFd;

use crate::machine::{ExecutionLaunchFailure, MachineExitCommand};
use crate::network::VmmonNetworkAttachment;
use crate::paths::OwnedDirectory;
use crate::store::models::MachineId;
use crate::vmmon::start_request::{encode_start_request, VmmonStartRequest, VmmonStartupCommand};
use crate::vmmon::Vmmon;
use crate::LibVmError;

const ENV_VM_STARTPIPE: &str = "_VM_STARTPIPE";
const ENV_VM_SYNCPIPE: &str = "_VM_SYNCPIPE";
const ENV_VM_MACHINE_LOG_DIR: &str = "_VM_MACHINE_LOG_DIR";
const VMMON_LAUNCHER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const VMMON_START_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub(crate) run_id: &'a str,
    pub(crate) exit_command: Option<&'a MachineExitCommand>,
    pub(crate) agent_enabled: bool,
    pub(crate) startup_command: Option<&'a VmmonStartupCommand>,
    pub(crate) machine_log_dir: &'a OwnedDirectory,
}

impl Vmmon {
    pub(crate) async fn spawn(&self, launch: &VmmonLaunch<'_>) -> Result<(), LibVmError> {
        let (start_read, start_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
        let (sync_read, sync_write) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
        configure_pipe_inheritance(&start_read, &start_write, &sync_read, &sync_write)?;
        let machine_log_dir = launch.machine_log_dir.duplicate_inheritable()?;

        let mut command = Command::new(self.executable());
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
            .arg("--run-id")
            .arg(launch.run_id)
            .arg("--krun-path")
            .arg(self.krun_path());
        if launch.agent_enabled {
            command.arg("--agent-enabled");
        }
        if let Some(exit_command) = launch.exit_command {
            append_exit_command_args(&mut command, exit_command);
        }
        command
            .env(ENV_VM_STARTPIPE, start_read.as_raw_fd().to_string())
            .env(ENV_VM_SYNCPIPE, sync_write.as_raw_fd().to_string());
        command.env(
            ENV_VM_MACHINE_LOG_DIR,
            machine_log_dir.as_raw_fd().to_string(),
        );

        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        drop(start_read);
        drop(sync_write);
        drop(machine_log_dir);
        wait_for_vmmon_launcher(child).await?;

        let start_request = VmmonStartRequest::new(
            launch.machine_id.to_string(),
            launch.run_id,
            launch.startup_command.cloned(),
        );
        handoff_start_request(start_write, &start_request, VMMON_START_REQUEST_TIMEOUT).await?;
        let readiness_timeout = if launch.startup_command.is_some() {
            Duration::from_secs(5 * 60 + 30)
        } else {
            Duration::from_secs(30)
        };
        wait_for_start(sync_read, launch.trace_log, readiness_timeout).await
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

async fn wait_for_start(
    syncpipe: OwnedFd,
    trace_path: &Path,
    deadline_duration: Duration,
) -> Result<(), LibVmError> {
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

    startup_result(result)
}

fn startup_result(result: StartupResult) -> Result<(), LibVmError> {
    match result {
        StartupResult::Started => Ok(()),
        StartupResult::Failed(message) => Err(io::Error::other(message).into()),
        StartupResult::StartupCommandLaunchFailed { reason, message } => {
            Err(LibVmError::StartupCommandLaunchFailed {
                failure: ExecutionLaunchFailure {
                    reason: crate::machine::launch_failure_reason(reason),
                    message,
                },
            })
        }
    }
}

async fn handoff_start_request(
    startpipe: OwnedFd,
    request: &VmmonStartRequest,
    timeout: Duration,
) -> io::Result<()> {
    let encoded = encode_start_request(request)?;
    tokio::time::timeout(timeout, write_start_request(startpipe, &encoded))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("vmmon start request handoff exceeded {timeout:?}"),
            )
        })?
}

async fn write_start_request(startpipe: OwnedFd, encoded: &[u8]) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let flags = fcntl(&startpipe, FcntlArg::F_GETFL).map_err(io::Error::other)?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    fcntl(&startpipe, FcntlArg::F_SETFL(flags)).map_err(io::Error::other)?;
    let writer = AsyncFd::new(startpipe)?;
    let mut remaining = encoded;
    while !remaining.is_empty() {
        let mut writable = writer.writable().await?;
        match writable.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), remaining)
                .map_err(|error| io::Error::from_raw_os_error(error as i32))
        }) {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vmmon startpipe accepted zero bytes",
                ))
            }
            Ok(Ok(written)) => remaining = &remaining[written..],
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
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

    if let Some(failure) = input.strip_prefix("startup-command-launch-failed\t") {
        let failure = serde_json::from_str::<StartupCommandLaunchFailure>(failure.trim_end())
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid startup command launch failure: {error}"),
                )
            })?;
        return Ok(StartupResult::StartupCommandLaunchFailed {
            reason: failure.reason,
            message: failure.message,
        });
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
    set_cloexec(fd, false)
}

fn configure_pipe_inheritance(
    start_read: &OwnedFd,
    start_write: &OwnedFd,
    sync_read: &OwnedFd,
    sync_write: &OwnedFd,
) -> io::Result<()> {
    // vmmon daemonizes itself, so only its two child-side descriptors survive exec.
    clear_cloexec(start_read)?;
    clear_cloexec(sync_write)?;
    set_cloexec(start_write, true)?;
    set_cloexec(sync_read, true)
}

fn set_cloexec(fd: &OwnedFd, enabled: bool) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};

    let flags = fcntl(fd, FcntlArg::F_GETFD).map_err(|err| io::Error::other(err.to_string()))?;
    let mut fd_flags = FdFlag::from_bits_retain(flags);
    if enabled {
        fd_flags.insert(FdFlag::FD_CLOEXEC);
    } else {
        fd_flags.remove(FdFlag::FD_CLOEXEC);
    }
    fcntl(fd, FcntlArg::F_SETFD(fd_flags)).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

enum StartupResult {
    Started,
    Failed(String),
    StartupCommandLaunchFailed {
        reason: Option<i32>,
        message: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupCommandLaunchFailure {
    reason: Option<i32>,
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::process::Command;
    use std::time::Duration;

    use nix::unistd::pipe;

    use crate::machine::{ExecutionLaunchFailureReason, MachineExitCommand};

    use crate::vmmon::start_request::{
        encode_start_request, VmmonEnvironmentVariable, VmmonProcessSpec, VmmonStartRequest,
        VmmonStartupCommand, VMMON_START_REQUEST_MAX_BYTES,
    };

    use super::{
        append_exit_command_args, configure_pipe_inheritance, handoff_start_request, read_syncpipe,
        StartupResult,
    };

    #[test]
    fn only_child_pipe_ends_survive_exec() {
        let (start_read, start_write) = pipe().expect("create start pipe");
        let (sync_read, sync_write) = pipe().expect("create sync pipe");

        configure_pipe_inheritance(&start_read, &start_write, &sync_read, &sync_write)
            .expect("configure pipe inheritance");

        assert!(!cloexec(&start_read));
        assert!(cloexec(&start_write));
        assert!(cloexec(&sync_read));
        assert!(!cloexec(&sync_write));
    }

    fn cloexec(fd: &std::os::fd::OwnedFd) -> bool {
        let flags =
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("read descriptor flags");
        nix::fcntl::FdFlag::from_bits_retain(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
    }

    #[tokio::test]
    async fn handoff_writes_json_and_closes_the_pipe() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let request = VmmonStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
        );

        handoff_start_request(write_fd, &request, Duration::from_secs(1))
            .await
            .expect("handoff request");

        let mut file = std::fs::File::from(read_fd);
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read request");
        assert!(contents.starts_with("{\"version\":1,"));
        assert!(contents.ends_with("}\n"));
    }

    #[tokio::test]
    async fn handoff_timeout_closes_a_blocked_writer() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let request = crate::vmmon::start_request::VmmonStartRequest::new(
            uuid::Uuid::nil().to_string(),
            uuid::Uuid::nil().to_string(),
            Some(crate::vmmon::start_request::VmmonStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: crate::vmmon::start_request::VmmonProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![crate::vmmon::start_request::VmmonEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value: "x".repeat(1024 * 1024),
                    }],
                    user: None,
                },
            }),
        );

        let error = handoff_start_request(write_fd, &request, Duration::from_millis(20))
            .await
            .expect_err("blocked handoff should time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        let mut file = std::fs::File::from(read_fd);
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .expect("writer should close after timeout");
        assert!(!contents.is_empty());
    }

    #[tokio::test]
    async fn cancelling_handoff_closes_a_blocked_writer() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let request = crate::vmmon::start_request::VmmonStartRequest::new(
            uuid::Uuid::nil().to_string(),
            uuid::Uuid::nil().to_string(),
            Some(crate::vmmon::start_request::VmmonStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: crate::vmmon::start_request::VmmonProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![crate::vmmon::start_request::VmmonEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value: "x".repeat(1024 * 1024),
                    }],
                    user: None,
                },
            }),
        );
        let handoff = tokio::spawn(async move {
            handoff_start_request(write_fd, &request, Duration::from_secs(30)).await
        });
        let partial_read = tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::from(read_fd);
            let mut prefix = vec![0; 4096];
            file.read_exact(&mut prefix).expect("read partial request");
            (file, prefix)
        });
        let (mut file, prefix) = partial_read.await.expect("join partial reader");
        assert_eq!(prefix.len(), 4096);
        handoff.abort();
        assert!(handoff
            .await
            .expect_err("handoff should be cancelled")
            .is_cancelled());

        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .expect("writer should close after cancellation");
    }

    #[tokio::test]
    async fn handoff_exact_limit_crosses_the_async_pipe_with_eof() {
        let base = large_start_request(String::new());
        let base_len = encode_start_request(&base)
            .expect("encode base request")
            .len();
        let request = large_start_request("x".repeat(VMMON_START_REQUEST_MAX_BYTES - base_len));
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let reader = tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::from(read_fd);
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).expect("read exact request");
            contents
        });

        handoff_start_request(write_fd, &request, Duration::from_secs(5))
            .await
            .expect("handoff exact request");
        let contents = reader.await.expect("join exact request reader");

        assert_eq!(contents.len(), VMMON_START_REQUEST_MAX_BYTES);
        assert_eq!(contents.last(), Some(&b'\n'));
    }

    fn large_start_request(value: String) -> VmmonStartRequest {
        VmmonStartRequest::new(
            uuid::Uuid::nil().to_string(),
            uuid::Uuid::nil().to_string(),
            Some(VmmonStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: VmmonProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![VmmonEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value,
                    }],
                    user: None,
                },
            }),
        )
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
    fn read_syncpipe_accepts_structured_startup_command_launch_failure() {
        let (read_fd, write_fd) = pipe().expect("create pipe");
        let mut write_file = std::fs::File::from(write_fd);
        write_file
            .write_all(b"startup-command-launch-failed\t{\"reason\":1,\"message\":\"missing\"}\n")
            .expect("write startup command launch failure");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).expect("read syncpipe"),
            StartupResult::StartupCommandLaunchFailed { reason: Some(1), message: Some(message) }
                if message == "missing"
        ));
    }

    #[test]
    fn structured_startup_command_launch_failure_remains_typed() {
        let error = super::startup_result(StartupResult::StartupCommandLaunchFailed {
            reason: Some(protocol::v1::LaunchFailureReason::CommandNotFound as i32),
            message: Some("missing".to_string()),
        })
        .expect_err("startup command launch failure");

        assert!(matches!(
            error,
            crate::LibVmError::StartupCommandLaunchFailed { failure }
                if failure.reason == ExecutionLaunchFailureReason::CommandNotFound
                    && failure.message.as_deref() == Some("missing")
        ));
    }

    #[test]
    fn append_exit_command_args_preserves_structured_argv() {
        let mut command = Command::new("/tmp/vmmon");
        let exit_command = MachineExitCommand::new(
            "/usr/local/bin/silo",
            [
                OsString::from("cleanup"),
                OsString::from("--data-dir"),
                OsString::from("/tmp/silo"),
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
                OsString::from("/usr/local/bin/silo"),
                OsString::from("--exit-command-arg"),
                OsString::from("cleanup"),
                OsString::from("--exit-command-arg"),
                OsString::from("--data-dir"),
                OsString::from("--exit-command-arg"),
                OsString::from("/tmp/silo"),
                OsString::from("--exit-command-arg"),
                OsString::from("--machine-id"),
                OsString::from("--exit-command-arg"),
                OsString::from("0123456789abcdef0123456789abcdef"),
            ]
        );
    }
}

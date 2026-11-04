use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "linux"))]
use nix::unistd::pipe;
use serde::Deserialize;
use tokio::io::unix::AsyncFd;

use crate::lock_manager::MachineLifetimeLock;
use crate::machine::{ExecutionLaunchFailure, HostCommand};
use crate::network::VmmNetworkAttachment;
use crate::paths::OwnedDirectory;
use crate::store::models::MachineId;
use crate::supervisor::start_request::{encode_start_request, VmmStartRequest, VmmStartupCommand};
use crate::supervisor::VmSupervisor;
use crate::LibVmError;

const ENV_VM_STARTPIPE: &str = "_VM_STARTPIPE";
const ENV_VM_SYNCPIPE: &str = "_VM_SYNCPIPE";
const ENV_VM_MACHINE_LOG_DIR: &str = "_VM_MACHINE_LOG_DIR";
const ENV_VM_MACHINE_LOCK: &str = "_VM_MACHINE_LOCK";
const VMM_LAUNCHER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const VMM_START_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct VmmLaunch<'a> {
    pub(crate) machine_id: MachineId,
    pub(crate) name: &'a str,
    pub(crate) machine_dir: &'a Path,
    pub(crate) machine_runtime_dir: &'a Path,
    pub(crate) pidfile: &'a Path,
    pub(crate) exit_status: &'a Path,
    pub(crate) config: &'a Path,
    pub(crate) socket: &'a Path,
    pub(crate) serial_log: &'a Path,
    pub(crate) trace_log: &'a Path,
    pub(crate) network: &'a VmmNetworkAttachment,
    pub(crate) run_id: &'a str,
    pub(crate) exit_command: Option<&'a HostCommand>,
    pub(crate) agent_enabled: bool,
    pub(crate) rosetta_intent: crate::supervisor::start_request::VmmRosettaIntent,
    pub(crate) asset_directory: std::path::PathBuf,
    pub(crate) startup_command: Option<&'a VmmStartupCommand>,
    pub(crate) machine_log_dir: &'a OwnedDirectory,
    pub(crate) machine_lock: &'a MachineLifetimeLock,
    pub(crate) qualification: Option<&'a crate::QualifiedOverlayBoot>,
    pub(crate) storage_lease: &'a crate::storage::locks::StorageLock,
    pub(crate) storage_lease_binding: protocol::shutdown::StorageLeaseBinding,
    pub(crate) storage_shutdown: &'a protocol::shutdown::StorageShutdownContext,
}

impl VmSupervisor {
    pub(crate) async fn spawn(&self, launch: &VmmLaunch<'_>) -> Result<(), LibVmError> {
        let startup_budget = startup_budget(launch);
        let startup_deadline = Instant::now() + startup_budget;
        let (start_read, start_write) = launch_pipe()?;
        let (sync_read, sync_write) = launch_pipe()?;
        let machine_log_dir = launch.machine_log_dir.duplicate_inheritable()?;
        let machine_lock = launch.machine_lock.duplicate_inheritable()?;
        let storage_lease = launch.storage_lease.duplicate_inheritable()?;

        let mut command = monitor_command(
            self.executable(),
            launch
                .qualification
                .map(|qualification| qualification.native_executable_fd()),
        )?;
        command
            .arg("--id")
            .arg(uuid::Uuid::from(launch.machine_id).to_string())
            .arg("--name")
            .arg(launch.name)
            .arg("--data-dir")
            .arg(launch.machine_dir)
            .arg("--runtime-dir")
            .arg(launch.machine_runtime_dir)
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
            .arg(launch.network.to_vmm_arg())
            .arg("--run-id")
            .arg(launch.run_id);
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
        command.env(ENV_VM_MACHINE_LOCK, machine_lock.as_raw_fd().to_string());
        command.env(
            "_VM_STORAGE_LEASES",
            format!("[{}]", storage_lease.as_raw_fd()),
        );
        if let Some(writer) = launch.network.exit_writer() {
            command.env("_VM_NETD_EXIT", writer.as_raw_fd().to_string());
        } else {
            command.env_remove("_VM_NETD_EXIT");
        }
        install_child_inheritance(
            &mut command,
            [
                Some(start_read.as_raw_fd()),
                Some(sync_write.as_raw_fd()),
                Some(machine_log_dir.as_raw_fd()),
                Some(machine_lock.as_raw_fd()),
                Some(storage_lease.as_raw_fd()),
                launch.network.exit_writer().map(AsRawFd::as_raw_fd),
            ],
        )?;

        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(qualification) = launch.qualification {
            qualification.recheck_native_executable()?;
        }
        let child = command.spawn()?;

        drop(start_read);
        drop(sync_write);
        drop(machine_log_dir);
        drop(machine_lock);
        drop(storage_lease);
        wait_for_vmm_launcher(child).await?;

        let start_request = VmmStartRequest::new(
            uuid::Uuid::from(launch.machine_id).to_string(),
            launch.run_id,
            launch.startup_command.cloned(),
            launch.storage_lease_binding.clone(),
            launch.storage_shutdown.clone(),
        )
        .with_virt_backend(self.virt_backend_request())
        .with_rosetta_intent(launch.rosetta_intent)
        .with_asset_directory(launch.asset_directory.clone())
        .with_startup_budget(startup_deadline.saturating_duration_since(Instant::now()));
        handoff_start_request(start_write, &start_request, VMM_START_REQUEST_TIMEOUT).await?;
        wait_for_start(
            sync_read,
            launch.trace_log,
            startup_deadline.saturating_duration_since(Instant::now()),
        )
        .await
    }
}

fn monitor_command(executable: &Path, qualified: Option<BorrowedFd<'_>>) -> io::Result<Command> {
    match qualified {
        None => Ok(Command::new(executable)),
        Some(descriptor) => {
            #[cfg(target_os = "linux")]
            {
                // The retained ELF is resolved before exec closes CLOEXEC FDs.
                // Keep the parent's descriptor CLOEXEC during concurrent starts.
                Ok(Command::new(format!(
                    "/proc/self/fd/{}",
                    descriptor.as_raw_fd()
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = descriptor;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "qualified native executable FD launch requires Linux",
                ))
            }
        }
    }
}

fn startup_budget(launch: &VmmLaunch<'_>) -> Duration {
    let translated = matches!(
        launch.rosetta_intent,
        crate::supervisor::start_request::VmmRosettaIntent::Enabled {}
    );
    match (translated, launch.startup_command.is_some()) {
        (true, true) => Duration::from_secs(420),
        (true, false) => Duration::from_secs(120),
        (false, true) => Duration::from_secs(330),
        (false, false) => Duration::from_secs(30),
    }
}

fn append_exit_command_args(command: &mut Command, exit_command: &HostCommand) {
    command.arg("--exit-command").arg(&exit_command.command);
    for arg in &exit_command.args {
        command.arg("--exit-command-arg").arg(arg);
    }
}

async fn wait_for_vmm_launcher(child: std::process::Child) -> io::Result<()> {
    tokio::task::spawn_blocking(move || wait_for_vmm_launcher_blocking(child))
        .await
        .map_err(|err| io::Error::other(format!("join silo-vmm launcher wait task: {err}")))?
}

fn wait_for_vmm_launcher_blocking(mut child: std::process::Child) -> io::Result<()> {
    let deadline = Instant::now() + VMM_LAUNCHER_EXIT_TIMEOUT;
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
                    "silo-vmm launcher did not daemonize within {:?}",
                    VMM_LAUNCHER_EXIT_TIMEOUT
                ),
            ));
        }

        std::thread::sleep(Duration::from_millis(25));
    };

    if status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "silo-vmm launcher exited with {status}"
    )))
}

async fn wait_for_start(
    syncpipe: OwnedFd,
    trace_path: &Path,
    deadline_duration: Duration,
) -> Result<(), LibVmError> {
    let trace_path = trace_path.to_path_buf();
    let result = tokio::time::timeout(deadline_duration, read_syncpipe(syncpipe))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "silo-vmm syncpipe did not report readiness in {:?} (hint: see {})",
                    deadline_duration,
                    trace_path.display(),
                ),
            )
        })??;

    startup_result(result)
}

fn startup_result(result: StartupResult) -> Result<(), LibVmError> {
    match result {
        StartupResult::Started => Ok(()),
        StartupResult::Failed(message) => Err(io::Error::other(message).into()),
        StartupResult::StartupCommandLaunchFailed { reason, message } => {
            Err(LibVmError::EntrypointLaunchFailed {
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
    request: &VmmStartRequest,
    timeout: Duration,
) -> io::Result<()> {
    let encoded = encode_start_request(request)?;
    tokio::time::timeout(timeout, write_start_request(startpipe, &encoded))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("silo-vmm start request handoff exceeded {timeout:?}"),
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
                    "silo-vmm startpipe accepted zero bytes",
                ))
            }
            Ok(Ok(written)) => remaining = &remaining[written..],
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

async fn read_syncpipe(syncpipe: OwnedFd) -> io::Result<StartupResult> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    const MAX_RESULT_BYTES: usize = 128 * 1024;
    let reader = tokio::net::unix::pipe::Receiver::from_owned_fd(syncpipe)?;
    let mut input = String::new();
    tokio::io::BufReader::new(reader.take((MAX_RESULT_BYTES + 1) as u64))
        .read_line(&mut input)
        .await?;
    if input.len() > MAX_RESULT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "silo-vmm startup result exceeds byte limit",
        ));
    }

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
            "silo-vmm exited before reporting syncpipe result",
        ));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected silo-vmm syncpipe message: {input:?}"),
    ))
}

fn launch_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    #[cfg(target_os = "linux")]
    let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
    #[cfg(not(target_os = "linux"))]
    let (read, write) = {
        // Darwin has no pipe2. The lifetime lease itself always uses atomic
        // CLOEXEC creation/duplication; these pipes are marked before spawn.
        let (read, write) = pipe()?;
        set_cloexec(&read, true)?;
        set_cloexec(&write, true)?;
        (read, write)
    };
    Ok((normalize_launch_fd(read)?, normalize_launch_fd(write)?))
}

fn normalize_launch_fd(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    let raw = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(3))?;
    // SAFETY: the duplicate is new and exclusively owned by this call.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) })
}

fn install_child_inheritance(command: &mut Command, allowed: [Option<i32>; 6]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let ceiling = {
        let mut ceiling =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?
                .0
                .min(i32::MAX as u64) as i32;
        // Existing descriptors may exceed a subsequently lowered soft limit.
        let mut directory = nix::dir::Dir::open(
            "/dev/fd",
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        for entry in directory.iter() {
            let entry = entry?;
            if let Some(raw) = entry
                .file_name()
                .to_str()
                .ok()
                .and_then(|name| name.parse::<i32>().ok())
            {
                ceiling = ceiling.max(raw.saturating_add(1));
            }
        }
        ceiling
    };
    // SAFETY: only numeric OS operations and inline errno errors after fork.
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            {
                // nix has no close_range(CLOEXEC). Do not close the qualified
                // executable FD: the kernel resolves it before CLOEXEC applies.
                if nix::libc::syscall(
                    nix::libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    nix::libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "macos")]
            for raw in 3..ceiling {
                let flags = nix::libc::fcntl(raw, nix::libc::F_GETFD);
                if flags < 0 {
                    if *nix::libc::__error() == nix::libc::EBADF {
                        continue;
                    }
                    return Err(io::Error::last_os_error());
                }
                if nix::libc::fcntl(raw, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for raw in allowed.into_iter().flatten() {
                let fd = BorrowedFd::borrow_raw(raw);
                let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD)
                    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
                nix::fcntl::fcntl(
                    fd,
                    nix::fcntl::FcntlArg::F_SETFD(
                        nix::fcntl::FdFlag::from_bits_retain(flags)
                            & !nix::fcntl::FdFlag::FD_CLOEXEC,
                    ),
                )
                .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
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

    use std::os::fd::OwnedFd;

    use crate::machine::{ExecutionLaunchFailureReason, HostCommand};

    use crate::supervisor::start_request::{
        encode_start_request, VmmEnvironmentVariable, VmmProcessSpec, VmmStartRequest,
        VmmStartupCommand, VMM_START_REQUEST_MAX_BYTES,
    };

    use crate::supervisor::launch::{
        append_exit_command_args, handoff_start_request, install_child_inheritance, launch_pipe,
        read_syncpipe, StartupResult,
    };

    /// A pipe no concurrently spawned test child can inherit. Tests that observe a
    /// pipe closing (EOF, EPIPE) fail at random if some child holds an end open.
    fn private_pipe() -> (OwnedFd, OwnedFd) {
        #[cfg(target_os = "linux")]
        {
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("create pipe")
        }
        // macOS has no pipe2; this leaves a window of two syscalls, not the whole test.
        #[cfg(not(target_os = "linux"))]
        {
            let (read, write) = pipe().expect("create pipe");
            crate::supervisor::launch::set_cloexec(&read, true).expect("cloexec read end");
            crate::supervisor::launch::set_cloexec(&write, true).expect("cloexec write end");
            (read, write)
        }
    }

    #[test]
    fn only_child_pipe_ends_survive_exec() {
        use std::os::fd::AsRawFd;
        let (start_read, start_write) = launch_pipe().expect("start pipe");
        let (sync_read, sync_write) = launch_pipe().expect("sync pipe");
        let mut child = Command::new("/bin/sh");
        child.arg("-c").arg(format!(
            "test -e /dev/fd/{} && test -e /dev/fd/{} && test ! -e /dev/fd/{} && test ! -e /dev/fd/{}",
            start_read.as_raw_fd(), sync_write.as_raw_fd(), start_write.as_raw_fd(), sync_read.as_raw_fd()
        ));
        install_child_inheritance(
            &mut child,
            [
                Some(start_read.as_raw_fd()),
                Some(sync_write.as_raw_fd()),
                None,
                None,
                None,
                None,
            ],
        )
        .expect("child allowlist");
        assert!(cloexec(&start_read));
        assert!(cloexec(&start_write));
        assert!(cloexec(&sync_read));
        assert!(cloexec(&sync_write));
        assert!(child.status().expect("actual child").success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_elf_fd_is_resolved_before_cloexec_and_absent_after_exec() {
        use std::os::fd::{AsFd, AsRawFd, FromRawFd};
        let executable = std::fs::File::open("/bin/sh").expect("ELF executable");
        let raw = nix::fcntl::fcntl(&executable, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(120))
            .expect("high retained executable");
        let retained = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut command = crate::supervisor::launch::monitor_command(
            std::path::Path::new("/nonexistent/staged/executable"),
            Some(retained.as_fd()),
        )
        .expect("retained ELF command");
        install_child_inheritance(&mut command, [None; 6]).expect("install cleanup");
        command
            .arg("-c")
            .arg(format!("test ! -e /proc/self/fd/{}", retained.as_raw_fd()));
        assert!(command.status().expect("execute retained ELF").success());
        assert!(cloexec(&retained), "parent executable must stay CLOEXEC");
    }

    fn cloexec(fd: &std::os::fd::OwnedFd) -> bool {
        let flags =
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).expect("read descriptor flags");
        nix::fcntl::FdFlag::from_bits_retain(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
    }

    fn storage_lease() -> protocol::shutdown::StorageLeaseBinding {
        protocol::shutdown::StorageLeaseBinding {
            operation_id: "33333333-3333-4333-8333-333333333333".into(),
            file_device: 1,
            file_inode: 2,
        }
    }

    fn storage_shutdown() -> protocol::shutdown::StorageShutdownContext {
        protocol::shutdown::StorageShutdownContext {
            version: 1,
            machine_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            run_id: "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3".into(),
            manifest: protocol::shutdown::StorageManifest::Unsupported {
                reason: "pipe-only fixture has no attachments".into(),
            },
        }
    }

    #[tokio::test]
    async fn handoff_writes_json_and_closes_the_pipe() {
        let (read_fd, write_fd) = private_pipe();
        let request = VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            None,
            storage_lease(),
            storage_shutdown(),
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
        let (read_fd, write_fd) = private_pipe();
        let request = crate::supervisor::start_request::VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(crate::supervisor::start_request::VmmStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: crate::supervisor::start_request::VmmProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![crate::supervisor::start_request::VmmEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value: "x".repeat(1024 * 1024),
                    }],
                    user: None,
                },
            }),
            storage_lease(),
            storage_shutdown(),
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
        let (read_fd, write_fd) = private_pipe();
        let request = crate::supervisor::start_request::VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(crate::supervisor::start_request::VmmStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: crate::supervisor::start_request::VmmProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![crate::supervisor::start_request::VmmEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value: "x".repeat(1024 * 1024),
                    }],
                    user: None,
                },
            }),
            storage_lease(),
            storage_shutdown(),
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
        let request = large_start_request("x".repeat(VMM_START_REQUEST_MAX_BYTES - base_len));
        let (read_fd, write_fd) = private_pipe();
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

        assert_eq!(contents.len(), VMM_START_REQUEST_MAX_BYTES);
        assert_eq!(contents.last(), Some(&b'\n'));
    }

    fn large_start_request(value: String) -> VmmStartRequest {
        VmmStartRequest::new(
            "01234567-89ab-cdef-0123-456789abcdef",
            "9e7d6ad8-f804-4936-9633-1fd3df6bd7d3",
            Some(VmmStartupCommand {
                execution_id: uuid::Uuid::nil(),
                process: VmmProcessSpec {
                    argv: vec!["true".to_string()],
                    working_directory: None,
                    environment: vec![VmmEnvironmentVariable {
                        name: "LARGE".to_string(),
                        value,
                    }],
                    user: None,
                },
            }),
            storage_lease(),
            storage_shutdown(),
        )
    }

    #[tokio::test]
    async fn cancelling_startup_result_read_closes_the_pipe() {
        let (reader, writer) = private_pipe();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), read_syncpipe(reader))
                .await
                .is_err()
        );
        assert_eq!(
            nix::unistd::write(&writer, b"started\n"),
            Err(nix::errno::Errno::EPIPE)
        );
    }

    #[tokio::test]
    async fn read_syncpipe_accepts_started_message() {
        let (read_fd, write_fd) = private_pipe();
        let mut write_file = std::fs::File::from(write_fd);
        write_file.write_all(b"started\n").expect("write started");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).await.expect("read syncpipe"),
            StartupResult::Started
        ));
    }

    #[tokio::test]
    async fn read_syncpipe_accepts_failed_message() {
        let (read_fd, write_fd) = private_pipe();
        let mut write_file = std::fs::File::from(write_fd);
        write_file
            .write_all(b"failed\tkrun exploded\n")
            .expect("write failure");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).await.expect("read syncpipe"),
            StartupResult::Failed(message) if message == "krun exploded"
        ));
    }

    #[tokio::test]
    async fn read_syncpipe_accepts_structured_startup_command_launch_failure() {
        let (read_fd, write_fd) = private_pipe();
        let mut write_file = std::fs::File::from(write_fd);
        write_file
            .write_all(b"startup-command-launch-failed\t{\"reason\":1,\"message\":\"missing\"}\n")
            .expect("write startup command launch failure");
        drop(write_file);

        assert!(matches!(
            read_syncpipe(read_fd).await.expect("read syncpipe"),
            StartupResult::StartupCommandLaunchFailed { reason: Some(1), message: Some(message) }
                if message == "missing"
        ));
    }

    #[test]
    fn structured_startup_command_launch_failure_remains_typed() {
        let error =
            crate::supervisor::launch::startup_result(StartupResult::StartupCommandLaunchFailed {
                reason: Some(protocol::v1::LaunchFailureReason::CommandNotFound as i32),
                message: Some("missing".to_string()),
            })
            .expect_err("startup command launch failure");

        assert!(matches!(
            error,
            crate::LibVmError::EntrypointLaunchFailed { failure }
                if failure.reason == ExecutionLaunchFailureReason::CommandNotFound
                    && failure.message.as_deref() == Some("missing")
        ));
    }

    #[test]
    fn append_exit_command_args_preserves_structured_argv() {
        let mut command = Command::new("/tmp/silo-vmm");
        let exit_command = HostCommand::new("/usr/local/bin/silo").args([
            OsString::from("cleanup"),
            OsString::from("--data-dir"),
            OsString::from("/tmp/silo"),
            OsString::from("--machine-id"),
            OsString::from("0123456789abcdef0123456789abcdef"),
        ]);

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

    #[cfg(target_os = "linux")]
    #[test]
    fn vmdk_monitor_exec_uses_retained_elf_after_atomic_path_replacement() {
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("selected-monitor");
        let replacement = temp.path().join("replacement-monitor");
        std::fs::copy("/bin/sh", &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let retained = std::fs::File::open(&executable).unwrap();
        let flags = nix::fcntl::fcntl(retained.as_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
        assert!(
            nix::fcntl::FdFlag::from_bits_retain(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
        let mut magic = [0; 4];
        std::os::unix::fs::FileExt::read_exact_at(&retained, &mut magic, 0).unwrap();
        assert_eq!(&magic, b"\x7fELF");
        std::fs::copy("/bin/false", &replacement).unwrap();
        std::fs::rename(&replacement, &executable).unwrap();

        let mut command =
            crate::supervisor::launch::monitor_command(&executable, Some(retained.as_fd()))
                .unwrap();
        let output = command
            .args([
                "-c",
                &format!(
                    "test ! -e /proc/self/fd/{} || exit 91; printf retained-qualified-native",
                    retained.as_raw_fd()
                ),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"retained-qualified-native");
        assert_eq!(
            nix::fcntl::fcntl(retained.as_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap(),
            flags
        );

        let control = crate::supervisor::launch::monitor_command(&executable, None)
            .unwrap()
            .output()
            .unwrap();
        assert_eq!(control.status.code(), Some(1));
        assert!(control.stdout.is_empty());
    }
}

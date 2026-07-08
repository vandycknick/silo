use std::fs;
use std::io::{self, BufRead};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use eyre::Context;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};
use tokio::process::{ChildStderr as TokioChildStderr, Command as TokioCommand};
use tokio_vsock::VsockStream;

use crate::pid1::ProcessSupervisor;

const SSHD_RUNTIME_DIR: &str = "/run/sshd";
const SSHD_RUNTIME_DIR_MODE: u32 = 0o755;
const OPENSSH_SERVER_PATH: &str = "/usr/sbin/sshd";
const OPENSSH_READY_TIMEOUT: Duration = Duration::from_secs(30);
const OPENSSH_READY_POLL: Duration = Duration::from_millis(250);
const UNIX_MODE_BITS: u32 = 0o7777;
const GROUP_OR_WORLD_WRITABLE: u32 = 0o022;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshdRuntimeDirKind {
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshdRuntimeDirDisposition {
    Ready,
    Chmod0755,
}

pub(crate) fn exists() -> bool {
    fs::metadata(OPENSSH_SERVER_PATH)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

pub(crate) fn ensure_runtime_dir() -> eyre::Result<()> {
    ensure_runtime_dir_at(Path::new(SSHD_RUNTIME_DIR))
}

fn ensure_runtime_dir_at(path: &Path) -> eyre::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => prepare_existing_runtime_dir(path, metadata),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(SSHD_RUNTIME_DIR_MODE);
            builder
                .create(path)
                .with_context(|| format!("create {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(SSHD_RUNTIME_DIR_MODE))
                .with_context(|| format!("set permissions on {}", path.display()))?;
            let metadata =
                fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
            prepare_existing_runtime_dir(path, metadata)
        }
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn prepare_existing_runtime_dir(path: &Path, metadata: fs::Metadata) -> eyre::Result<()> {
    let mode = metadata.permissions().mode() & UNIX_MODE_BITS;
    let disposition = assess_runtime_dir(
        runtime_dir_kind(metadata.file_type()),
        metadata.uid(),
        metadata.gid(),
        mode,
    )
    .with_context(|| format!("validate {}", path.display()))?;

    if disposition == SshdRuntimeDirDisposition::Chmod0755 {
        fs::set_permissions(path, fs::Permissions::from_mode(SSHD_RUNTIME_DIR_MODE))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }

    Ok(())
}

fn runtime_dir_kind(file_type: fs::FileType) -> SshdRuntimeDirKind {
    if file_type.is_symlink() {
        SshdRuntimeDirKind::Symlink
    } else if file_type.is_dir() {
        SshdRuntimeDirKind::Directory
    } else {
        SshdRuntimeDirKind::Other
    }
}

fn assess_runtime_dir(
    kind: SshdRuntimeDirKind,
    uid: u32,
    gid: u32,
    mode: u32,
) -> eyre::Result<SshdRuntimeDirDisposition> {
    match kind {
        SshdRuntimeDirKind::Directory => {}
        SshdRuntimeDirKind::Symlink => eyre::bail!("directory must not be a symlink"),
        SshdRuntimeDirKind::Other => eyre::bail!("path must be a directory"),
    }

    if uid != 0 || gid != 0 {
        eyre::bail!("directory must be owned by root:root, found uid {uid} gid {gid}");
    }

    if mode & GROUP_OR_WORLD_WRITABLE != 0 {
        eyre::bail!("directory must not be group/world-writable, found mode {mode:o}");
    }

    if mode == SSHD_RUNTIME_DIR_MODE {
        Ok(SshdRuntimeDirDisposition::Ready)
    } else {
        Ok(SshdRuntimeDirDisposition::Chmod0755)
    }
}

pub(crate) async fn wait_ready(process_supervisor: &ProcessSupervisor) -> eyre::Result<()> {
    let metadata = fs::metadata(OPENSSH_SERVER_PATH)
        .with_context(|| format!("stat OpenSSH server at {OPENSSH_SERVER_PATH}"))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        eyre::bail!("{OPENSSH_SERVER_PATH} must be an executable regular file");
    }

    let started = Instant::now();

    loop {
        let process_supervisor = process_supervisor.clone();
        let output = tokio::task::spawn_blocking(move || {
            process_supervisor.output(OPENSSH_SERVER_PATH, ["-t"])
        })
        .await
        .context("join OpenSSH readiness check task")?;

        match output {
            Ok(output) if output.status.success() => {
                tracing::info!(
                    elapsed_ms = started.elapsed().as_millis(),
                    "OpenSSH server is ready"
                );
                return Ok(());
            }
            Ok(output) => {
                let last_check = format!(
                    "{}; stdout: {}; stderr: {}",
                    output.status,
                    command_stream_for_log(&output.stdout),
                    command_stream_for_log(&output.stderr)
                );
                if started.elapsed() >= OPENSSH_READY_TIMEOUT {
                    eyre::bail!(
                        "OpenSSH server did not become ready within {:?}; last check: {last_check}",
                        OPENSSH_READY_TIMEOUT
                    );
                }
                tracing::debug!(last_check = %last_check, "waiting for OpenSSH server readiness");
            }
            Err(err) => {
                let last_check = err.to_string();
                if started.elapsed() >= OPENSSH_READY_TIMEOUT {
                    eyre::bail!(
                        "OpenSSH server did not become ready within {:?}; last check: {last_check}",
                        OPENSSH_READY_TIMEOUT
                    );
                }
                tracing::debug!(last_check = %last_check, "waiting for OpenSSH server readiness");
            }
        }
        tokio::time::sleep(OPENSSH_READY_POLL).await;
    }
}

fn command_stream_for_log(value: &[u8]) -> String {
    let value = String::from_utf8_lossy(value).trim().to_string();
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        value
    }
}

pub(crate) async fn handle_connection(
    process_supervisor: ProcessSupervisor,
    stream: VsockStream,
) -> io::Result<()> {
    if process_supervisor.is_active() {
        return tokio::task::spawn_blocking(move || {
            handle_connection_blocking(process_supervisor, stream)
        })
        .await
        .map_err(io::Error::other)?;
    }

    handle_connection_async(stream).await
}

async fn handle_connection_async(stream: VsockStream) -> io::Result<()> {
    clear_nonblocking(stream.as_fd())?;

    let sshd_stdin = stream.as_fd().try_clone_to_owned()?;
    let sshd_stdout = stream.as_fd().try_clone_to_owned()?;

    let mut child = TokioCommand::new(OPENSSH_SERVER_PATH)
        .arg("-i")
        .stdin(Stdio::from(sshd_stdin))
        .stdout(Stdio::from(sshd_stdout))
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture sshd stderr"))?;
    let stderr_task = tokio::spawn(log_stderr_async(stderr));

    let status = child.wait().await?;
    stderr_task.await.map_err(io::Error::other)??;

    if status.success() {
        tracing::debug!(status = %status, "sshd connection handler exited");
    } else {
        tracing::warn!(status = %status, "sshd connection handler exited unsuccessfully");
    }

    Ok(())
}

fn handle_connection_blocking(
    process_supervisor: ProcessSupervisor,
    stream: VsockStream,
) -> io::Result<()> {
    clear_nonblocking(stream.as_fd())?;

    let sshd_stdin = stream.as_fd().try_clone_to_owned()?;
    let sshd_stdout = stream.as_fd().try_clone_to_owned()?;

    let mut command = StdCommand::new(OPENSSH_SERVER_PATH);
    command
        .arg("-i")
        .stdin(Stdio::from(sshd_stdin))
        .stdout(Stdio::from(sshd_stdout))
        .stderr(Stdio::piped());

    let (mut child, guard) = process_supervisor.spawn_child(&mut command, "sshd")?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("failed to capture sshd stderr"))?;
    let stderr_thread = std::thread::spawn(move || log_stderr_blocking(stderr));

    let status = child.wait()?;
    drop(guard);
    stderr_thread
        .join()
        .map_err(|_| io::Error::other("sshd stderr logger panicked"))??;

    if status.success() {
        tracing::debug!(status = %status, "sshd connection handler exited");
    } else {
        tracing::warn!(status = %status, "sshd connection handler exited unsuccessfully");
    }

    Ok(())
}

fn clear_nonblocking(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    let mut flags =
        OFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?);
    flags.remove(OFlag::O_NONBLOCK);
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(())
}

async fn log_stderr_async(stderr: TokioChildStderr) -> io::Result<()> {
    let mut reader = TokioBufReader::new(stderr);
    let mut line = Vec::new();

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line).await?;
        if bytes_read == 0 {
            return Ok(());
        }

        if line.ends_with(b"\n") {
            line.pop();
        }
        if line.ends_with(b"\r") {
            line.pop();
        }

        let message = String::from_utf8_lossy(&line);
        tracing::warn!(message = %message, "sshd stderr");
    }
}

fn log_stderr_blocking(stderr: std::process::ChildStderr) -> io::Result<()> {
    let mut reader = std::io::BufReader::new(stderr);
    let mut line = Vec::new();

    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            return Ok(());
        }

        if line.ends_with(b"\n") {
            line.pop();
        }
        if line.ends_with(b"\r") {
            line.pop();
        }

        let message = String::from_utf8_lossy(&line);
        tracing::warn!(message = %message, "sshd stderr");
    }
}

#[cfg(test)]
mod tests {
    use crate::ssh::openssh::{
        assess_runtime_dir, SshdRuntimeDirDisposition, SshdRuntimeDirKind, SSHD_RUNTIME_DIR_MODE,
    };

    #[test]
    fn accepts_secure_sshd_runtime_dir() {
        let disposition =
            assess_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, SSHD_RUNTIME_DIR_MODE)
                .expect("secure directory");

        assert_eq!(disposition, SshdRuntimeDirDisposition::Ready);
    }

    #[test]
    fn repairs_sshd_runtime_dir_mode() {
        let disposition = assess_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o700)
            .expect("directory with repairable mode");

        assert_eq!(disposition, SshdRuntimeDirDisposition::Chmod0755);
    }

    #[test]
    fn rejects_group_writable_sshd_runtime_dir() {
        let err = assess_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o775)
            .expect_err("group writable directory must fail");

        assert!(err.to_string().contains("group/world-writable"));
    }

    #[test]
    fn rejects_world_writable_sshd_runtime_dir() {
        let err = assess_runtime_dir(SshdRuntimeDirKind::Directory, 0, 0, 0o777)
            .expect_err("world writable directory must fail");

        assert!(err.to_string().contains("group/world-writable"));
    }

    #[test]
    fn rejects_non_root_sshd_runtime_dir_owner() {
        let err = assess_runtime_dir(
            SshdRuntimeDirKind::Directory,
            1000,
            0,
            SSHD_RUNTIME_DIR_MODE,
        )
        .expect_err("non-root owner must fail");

        assert!(err.to_string().contains("root:root"));
    }

    #[test]
    fn rejects_non_root_sshd_runtime_dir_group() {
        let err = assess_runtime_dir(
            SshdRuntimeDirKind::Directory,
            0,
            1000,
            SSHD_RUNTIME_DIR_MODE,
        )
        .expect_err("non-root group must fail");

        assert!(err.to_string().contains("root:root"));
    }

    #[test]
    fn rejects_symlink_sshd_runtime_dir() {
        let err = assess_runtime_dir(SshdRuntimeDirKind::Symlink, 0, 0, SSHD_RUNTIME_DIR_MODE)
            .expect_err("symlink must fail");

        assert!(err.to_string().contains("symlink"));
    }

    #[test]
    fn rejects_non_directory_sshd_runtime_dir() {
        let err = assess_runtime_dir(SshdRuntimeDirKind::Other, 0, 0, SSHD_RUNTIME_DIR_MODE)
            .expect_err("non-directory must fail");

        assert!(err.to_string().contains("directory"));
    }
}

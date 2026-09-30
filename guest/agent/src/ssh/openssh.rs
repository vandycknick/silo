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
            process_supervisor.output(
                OPENSSH_SERVER_PATH,
                ["-t", "-f", crate::provision::ssh::CONFIG],
            )
        })
        .await
        .context("join OpenSSH readiness check task")?;

        match output {
            Ok(output) if output.status.success() => {
                verify_effective_config(
                    Path::new(OPENSSH_SERVER_PATH),
                    Path::new(crate::provision::ssh::CONFIG),
                )?;
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

pub(crate) fn verify_effective_config(sshd: &Path, config: &Path) -> eyre::Result<()> {
    let output = StdCommand::new(sshd)
        .arg("-T")
        .arg("-f")
        .arg(config)
        .output()?;
    if !output.status.success() {
        eyre::bail!(
            "sshd effective configuration check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let effective = String::from_utf8(output.stdout)?;
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    for expected in [
        "authenticationmethods publickey",
        "pubkeyauthentication yes",
        "pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com",
        "casignaturealgorithms ssh-ed25519",
        "authorizedkeysfile none",
        "authorizedkeyscommand none",
        "authorizedprincipalsfile none",
        "authorizedprincipalscommand none",
        "passwordauthentication no",
        "kbdinteractiveauthentication no",
        "hostbasedauthentication no",
        "gssapiauthentication no",
        "permitemptypasswords no",
        "loglevel VERBOSE",
        "acceptenv SILO_*",
    ] {
        if !effective
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(expected))
        {
            // OpenSSH 10.5 omits an empty authorized-key path list from -T.
            if expected == "authorizedkeysfile none"
                && !effective.lines().any(|line| {
                    line.split_whitespace()
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case("authorizedkeysfile"))
                })
            {
                continue;
            }
            // A build without GSSAPI has no such authentication mechanism.
            if expected == "gssapiauthentication no"
                && diagnostics.contains("Unsupported option GSSAPIAuthentication")
            {
                continue;
            }
            eyre::bail!("sshd does not enforce {expected}");
        }
    }
    for directive in ["trustedusercakeys", "hostkey"] {
        let configured = std::fs::read_to_string(config)?;
        let desired = configured
            .lines()
            .find(|line| {
                line.split_whitespace()
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(directive))
            })
            .ok_or_else(|| eyre::eyre!("missing {directive}"))?;
        let values: Vec<_> = effective
            .lines()
            .filter(|line| {
                line.split_whitespace()
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(directive))
            })
            .collect();
        if values.len() != 1
            || values[0]
                .split_whitespace()
                .skip(1)
                .ne(desired.split_whitespace().skip(1))
        {
            eyre::bail!("sshd has unexpected {directive}");
        }
    }
    Ok(())
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
        .args(["-i", "-f", crate::provision::ssh::CONFIG])
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
        .args(["-i", "-f", crate::provision::ssh::CONFIG])
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

    #[tokio::test]
    async fn real_sshd_inetd_is_ca_only_and_ignores_stale_authorized_key() {
        use crate::ssh::agent::tests::{certificate, Client};
        use russh::keys::ssh_key::{private::Ed25519Keypair, LineEnding, PrivateKey};
        use std::process::Stdio;
        use std::sync::Arc;
        let sshd = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join("sshd"))
            .find(|path| path.is_file());
        let Some(sshd) = sshd else {
            eprintln!("SKIPPED real sshd authentication: sshd binary unavailable");
            return;
        };
        let home = tempfile::tempdir().unwrap();
        let ca = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let host = PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        let ca_path = home.path().join("ca.pub");
        let host_path = home.path().join("host");
        std::fs::write(&ca_path, ca.public_key().to_openssh().unwrap()).unwrap();
        host.write_openssh_file(&host_path, LineEnding::LF).unwrap();
        let config = home.path().join("sshd_config");
        // PAM account checks need the guest's root-owned PAM service and shadow
        // database. This unprivileged host fixture exercises the identical
        // credential policy with account management disabled for its own UID.
        std::fs::write(
            &config,
            crate::provision::ssh::policy(&ca_path, &host_path).replace("UsePAM yes", "UsePAM no"),
        )
        .unwrap();
        crate::ssh::openssh::verify_effective_config(&sshd, &config).unwrap();
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap()
            .name;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (key, cert) = certificate(&ca, &user, now - 60, now + 300, false, false);
        let stale = home.path().join("authorized_keys");
        std::fs::write(&stale, key.public_key().to_openssh().unwrap()).unwrap();

        async fn connect(
            sshd: &std::path::Path,
            config: &std::path::Path,
            host: &PrivateKey,
            overrides: &[String],
        ) -> (russh::client::Handle<Client>, tokio::process::Child) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            let mut command = tokio::process::Command::new(sshd);
            command
                .arg("-i")
                .arg("-e")
                .arg("-f")
                .arg(config)
                .args(overrides)
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                    server.try_clone().unwrap(),
                )))
                .stdout(Stdio::from(std::os::fd::OwnedFd::from(server)))
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            let mut child = command.spawn().unwrap();
            client.set_nonblocking(true).unwrap();
            let stream = tokio::net::TcpStream::from_std(client).unwrap();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                russh::client::connect_stream(
                    Arc::new(Default::default()),
                    stream,
                    Client {
                        key: host.public_key().clone(),
                    },
                ),
            )
            .await
            .unwrap();
            match result {
                Ok(client) => (client, child),
                Err(error) => {
                    use tokio::io::AsyncReadExt;
                    let _ = child.kill().await;
                    let mut stderr = String::new();
                    child
                        .stderr
                        .take()
                        .unwrap()
                        .read_to_string(&mut stderr)
                        .await
                        .unwrap();
                    panic!("sshd handshake failed: {error}; {stderr}");
                }
            }
        }

        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let (mut client, mut child) = connect(&sshd, &config, &host, &[]).await;
            assert!(!client.authenticate_none(&user).await.unwrap().success());
            assert!(!client.authenticate_password(&user, "not-a-password").await.unwrap().success());
            assert!(!client.authenticate_publickey(&user, russh::keys::PrivateKeyWithHashAlg::new(key.clone(), None)).await.unwrap().success());
            if !client.authenticate_openssh_cert(&user, key.clone(), cert).await.unwrap().success() {
                let _ = client.disconnect(russh::Disconnect::ByApplication, "rejected", "en").await;
                drop(client);
                let _ = child.kill().await;
                let output = child.wait_with_output().await.unwrap();
                panic!("certificate rejected: {}", String::from_utf8_lossy(&output.stderr));
            }
            client.disconnect(russh::Disconnect::ByApplication, "done", "en").await.unwrap();
            let output = child.wait_with_output().await.unwrap();
            let log = String::from_utf8_lossy(&output.stderr);
            assert!(log.contains("silo:cli:uid1000:test") && log.contains("CA ED25519"), "{log}");

            let overrides = vec!["-o".into(), format!("AuthorizedKeysFile={}", stale.display()), "-o".into(), "PubkeyAcceptedAlgorithms=ssh-ed25519".into(), "-o".into(), "StrictModes=no".into()];
            let (mut control, _child) = connect(&sshd, &config, &host, &overrides).await;
            assert!(control.authenticate_publickey(&user, russh::keys::PrivateKeyWithHashAlg::new(key.clone(), None)).await.unwrap().success(), "stale-key control must authenticate to prove account eligibility");
            control.disconnect(russh::Disconnect::ByApplication, "done", "en").await.unwrap();
            let other = PrivateKey::from(Ed25519Keypair::from_seed(&[4; 32]));
            for (signer, principal, after, before, host_type, critical) in [
                (&ca, user.as_str(), now - 400, now - 1, false, false),
                (&ca, user.as_str(), now + 60, now + 300, false, false),
                (&ca, "wrong-principal", now - 60, now + 300, false, false),
                (&other, user.as_str(), now - 60, now + 300, false, false),
                (&ca, user.as_str(), now - 60, now + 300, true, false),
                (&ca, user.as_str(), now - 60, now + 300, false, true),
            ] {
                let (key, cert) = certificate(signer, principal, after, before, host_type, critical);
                let (mut client, _child) = connect(&sshd, &config, &host, &[]).await;
                assert!(!client.authenticate_openssh_cert(&user, key, cert).await.unwrap().success(), "invalid certificate accepted: {principal} {after} {before} {host_type} {critical}");
                client.disconnect(russh::Disconnect::ByApplication, "done", "en").await.unwrap();
            }
        }).await.expect("bounded real sshd authentication");
    }
}

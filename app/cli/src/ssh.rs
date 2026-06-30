use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use eyre::{bail, Context};
use libvm::host::{current_host_user, generate_ssh_keypair};

use crate::constants::{GUEST_SSH_PRIVATE_KEY_FILE_NAME, GUEST_SSH_PUBLIC_KEY_FILE_NAME};

pub(crate) fn exec_remote_shell(
    data_dir: &Path,
    name: &str,
    user: Option<&str>,
) -> eyre::Result<()> {
    let remote_command = format!(
        "/bin/sh -lc '{}; exec \"${{SHELL:-/bin/bash}}\" -l || exec /bin/sh'",
        current_dir_prologue()?
    );
    let err = ssh_command(data_dir, name, user, true, Some(&remote_command))?.exec();

    if err.kind() == io::ErrorKind::NotFound {
        bail!("`ssh` command not found. install OpenSSH client and retry")
    }

    bail!("failed to execute ssh: {err}")
}

pub(crate) fn run_remote_shell_status(
    data_dir: &Path,
    name: &str,
    user: Option<&str>,
) -> eyre::Result<ExitStatus> {
    let remote_command = format!(
        "/bin/sh -lc '{}; exec \"${{SHELL:-/bin/bash}}\" -l || exec /bin/sh'",
        current_dir_prologue()?
    );
    ssh_command(data_dir, name, user, true, Some(&remote_command))?
        .status()
        .context("run remote shell over ssh")
}

pub(crate) fn run_remote_command(
    data_dir: &Path,
    name: &str,
    user: Option<&str>,
    argv: &[String],
) -> eyre::Result<ExitStatus> {
    if argv.is_empty() {
        bail!("remote command is required")
    }

    let remote_command = format!("{}; exec {}", current_dir_prologue()?, shell_join(argv));

    ssh_command(data_dir, name, user, false, Some(&remote_command))?
        .status()
        .context("run remote command over ssh")
}

fn ssh_command(
    data_dir: &Path,
    name: &str,
    user: Option<&str>,
    allocate_tty: bool,
    remote_command: Option<&str>,
) -> eyre::Result<Command> {
    let exe = std::env::current_exe().context("resolve CLI binary path")?;

    let proxy_command = format!(
        "{} shell-proxy --name {}",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(name),
    );
    let host_user = current_host_user().context("resolve current host user")?;
    let ssh_user = user.unwrap_or(host_user.name.as_str());
    let private_key_path = ensure_guest_ssh_keypair(data_dir).context("ensure bento SSH keys")?;

    let mut command = Command::new("ssh");
    command
        .arg("-F")
        .arg("/dev/null")
        .arg("-A")
        .arg("-o")
        .arg(format!(
            "IdentityFile={}",
            private_key_path.to_string_lossy()
        ))
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("GSSAPIAuthentication=no")
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("-o")
        .arg(format!("HostKeyAlias=bento/{}", name))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("Compression=no")
        .arg("-o")
        .arg("Ciphers=^aes128-gcm@openssh.com,aes256-gcm@openssh.com")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg(format!("User={ssh_user}"));

    if allocate_tty {
        command.arg("-t").arg("-o").arg("SendEnv=COLORTERM");
    } else {
        command.arg("-T");
    }

    command.arg(name);

    if let Some(remote_command) = remote_command {
        command.arg(remote_command);
    }

    Ok(command)
}

fn ensure_guest_ssh_keypair(data_dir: &Path) -> eyre::Result<PathBuf> {
    let (private_key_path, public_key_path) = guest_ssh_key_paths(data_dir);
    if !private_key_path.is_file() || !public_key_path.is_file() {
        generate_ssh_keypair(&private_key_path, &public_key_path, None)
            .context("generate bento SSH keypair")?;
    }

    Ok(private_key_path)
}

fn guest_ssh_key_paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    let keys_dir = data_dir.join("keys");
    (
        keys_dir.join(GUEST_SSH_PRIVATE_KEY_FILE_NAME),
        keys_dir.join(GUEST_SSH_PUBLIC_KEY_FILE_NAME),
    )
}

fn current_dir_prologue() -> eyre::Result<String> {
    let cwd = std::env::current_dir().context("resolve current working directory")?;
    Ok(format!(
        "cd {} 2>/dev/null || true",
        shell_quote(&cwd.to_string_lossy())
    ))
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use crate::ssh::guest_ssh_key_paths;

    #[test]
    fn guest_ssh_key_paths_use_data_dir_keys_dir() {
        let temp_dir = tempfile::tempdir().expect("tempdir should be created");

        let (private_key_path, public_key_path) = guest_ssh_key_paths(temp_dir.path());

        assert_eq!(private_key_path, temp_dir.path().join("keys/id_ed25519"));
        assert_eq!(public_key_path, temp_dir.path().join("keys/id_ed25519.pub"));
    }
}

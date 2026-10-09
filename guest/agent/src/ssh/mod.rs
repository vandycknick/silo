use std::io;

use agent_spec::AgentSshConfig;
use eyre::Context;
use tokio_vsock::VsockStream;

use crate::pid1::ProcessSupervisor;

pub(crate) mod agent;
mod openssh;

pub(crate) fn constrain_external_listener() -> eyre::Result<()> {
    use std::process::Command;
    let socket = Command::new("systemctl")
        .args([
            "show",
            "sshd-vsock.socket",
            "--property=ActiveState",
            "--property=Listen",
            "--property=Accept",
        ])
        .output()?;
    let socket = if socket.status.success() {
        String::from_utf8(socket.stdout)?
    } else {
        eyre::bail!("cannot inspect external SSH socket ownership");
    };
    if !socket.lines().any(|line| line == "ActiveState=active")
        || !socket.lines().any(|line| line == "Accept=yes")
        || !socket
            .lines()
            .any(|line| line == "Listen=vsock::22 (Stream)")
    {
        eyre::bail!("unknown external SSH socket listener configuration");
    }
    let output = Command::new("systemctl")
        .args([
            "show",
            "sshd-vsock.socket",
            "--property=Triggers",
            "--value",
        ])
        .output()?;
    if !output.status.success() {
        eyre::bail!("cannot identify external SSH vsock listener");
    }
    let units = String::from_utf8(output.stdout)?;
    let units: Vec<_> = units.split_whitespace().collect();
    if units.len() != 1 {
        eyre::bail!("unknown external SSH vsock listener");
    }
    let unit = units[0];
    if unit != "sshd-vsock.service" && unit != "sshd-vsock@.service" {
        eyre::bail!("unsupported external SSH service {unit}");
    }
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=ExecStart", "--value"])
        .output()?;
    let command = String::from_utf8(output.stdout)?;
    if !output.status.success()
        || !command.contains("path=/usr/sbin/sshd ;")
        || !command.contains(" -i")
        || command.matches("path=").count() != 1
    {
        eyre::bail!("unknown external SSH listener command");
    }
    let dir = std::path::Path::new("/run/systemd/system").join(format!("{unit}.d"));
    std::fs::create_dir_all(&dir)?;
    let expected = crate::provision::ssh::systemd_override(
        std::path::Path::new(crate::provision::ssh::CONFIG),
        true,
    );
    std::fs::write(dir.join("00-silo-ca.conf"), expected)?;
    let status = Command::new("systemctl").arg("daemon-reload").status()?;
    if !status.success() {
        eyre::bail!("cannot reload constrained external SSH listener");
    }
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=ExecStart", "--value"])
        .output()?;
    let actual = String::from_utf8(output.stdout)?;
    if !output.status.success() || !exclusive_external_command(&actual) {
        eyre::bail!("external SSH listener override did not take effect");
    }
    let output = Command::new("systemctl")
        .args(["show", unit, "--property=ExecStartPre", "--value"])
        .output()?;
    if !output.status.success() || !exclusive_sshd_command(&String::from_utf8(output.stdout)?, "-t")
    {
        eyre::bail!("external SSH listener preflight override did not take effect");
    }
    openssh::verify_effective_config(
        std::path::Path::new("/usr/sbin/sshd"),
        std::path::Path::new(crate::provision::ssh::CONFIG),
    )
}

fn exclusive_external_command(command: &str) -> bool {
    exclusive_sshd_command(command, "-i")
}

fn exclusive_sshd_command(command: &str, mode: &str) -> bool {
    command.matches("path=").count() == 1
        && command.contains("path=/usr/sbin/sshd ;")
        && command.contains(&format!(
            "argv[]=/usr/sbin/sshd {mode} -f {} ;",
            crate::provision::ssh::CONFIG
        ))
}

#[derive(Clone)]
pub(crate) struct SshService {
    backend: SshBackend,
}

#[derive(Clone)]
enum SshBackend {
    OpenSsh {
        process_supervisor: ProcessSupervisor,
    },
    Agent(agent::NativeSshBackend),
}

impl SshService {
    pub(crate) fn descriptor(
        &self,
        external: bool,
    ) -> eyre::Result<protocol::v1::SshListenerReport> {
        let key = match &self.backend {
            SshBackend::Agent(native) if !external => native.host_public_key()?,
            _ => russh::keys::PrivateKey::read_openssh_file(std::path::Path::new(
                crate::provision::ssh::HOST_KEY,
            ))?
            .public_key()
            .clone(),
        };
        let backend = if external {
            "systemd-openssh"
        } else {
            match &self.backend {
                SshBackend::OpenSsh { .. } => "openssh",
                SshBackend::Agent(_) => "native",
            }
        };
        Ok(protocol::v1::SshListenerReport {
            backend: backend.into(),
            port: 22,
            host_public_key: key.to_openssh()?,
            config_verified: true,
            kex_verified: false,
        })
    }
    pub(crate) fn new(
        config: AgentSshConfig,
        process_supervisor: ProcessSupervisor,
    ) -> eyre::Result<Self> {
        if openssh::exists() {
            tracing::info!(backend = "openssh", "selected SSH backend");
            return Ok(Self {
                backend: SshBackend::OpenSsh { process_supervisor },
            });
        }

        tracing::info!(backend = "agent", "selected SSH backend");
        Ok(Self {
            backend: SshBackend::Agent(agent::NativeSshBackend::new(config, process_supervisor)?),
        })
    }

    pub(crate) async fn wait_ready(&self) -> eyre::Result<()> {
        match &self.backend {
            SshBackend::OpenSsh { process_supervisor } => {
                openssh::ensure_runtime_dir().context("prepare OpenSSH runtime directory")?;
                openssh::wait_ready(process_supervisor)
                    .await
                    .context("wait for OpenSSH server readiness")
            }
            SshBackend::Agent(agent) => agent.wait_ready(),
        }
    }

    pub(crate) async fn handle_connection(&self, stream: VsockStream) -> io::Result<()> {
        match &self.backend {
            SshBackend::OpenSsh { process_supervisor } => {
                openssh::handle_connection(process_supervisor.clone(), stream).await
            }
            SshBackend::Agent(agent) => agent.handle_connection(stream).await,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn external_exec_policy_rejects_generator_overrides_and_additional_commands() {
        let valid = format!(
            "{{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -i -f {} ; ignore_errors=no }}",
            crate::provision::ssh::CONFIG
        );
        assert!(crate::ssh::exclusive_external_command(&valid));
        assert!(!crate::ssh::exclusive_external_command(&format!(
            "{valid} {{ path=/bin/sh ; argv[]=/bin/sh ; }}"
        )));
        assert!(!crate::ssh::exclusive_external_command(&valid.replace(
            " ; ignore_errors",
            " -o AuthorizedKeysFile=/run/generated/authorized_keys ; ignore_errors"
        )));
        assert!(!crate::ssh::exclusive_external_command("{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -i -o AuthorizedKeysFile=/run/generated/authorized_keys ; }"));
    }
}

use std::io;

use agent_spec::AgentSshConfig;
use eyre::Context;
use tokio_vsock::VsockStream;

use crate::pid1::ProcessSupervisor;

mod agent;
mod openssh;

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

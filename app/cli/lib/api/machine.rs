use libvm::{
    Forward, MachineData, MachineExit, MachineForwardSession, MachineForwardStatus,
    MachineLogOptions, MachineLogSource, MachineReadiness, MachineRunId, MachineStart,
    MachineStartOptions, MachineWaitOptions, SshExitStatus,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

#[derive(Debug, Clone)]
pub(crate) struct AppMachine {
    inner: libvm::Machine,
}

impl AppMachine {
    pub(in crate::api) fn new(inner: libvm::Machine) -> Self {
        Self { inner }
    }

    pub(in crate::api) fn inner(&self) -> &libvm::Machine {
        &self.inner
    }

    pub(crate) fn id(&self) -> String {
        self.inner.id()
    }

    pub(crate) async fn inspect(&self) -> Result<MachineData, libvm::LibVmError> {
        self.inner.inspect().await
    }

    pub(crate) async fn start_with_options(
        &self,
        options: MachineStartOptions,
    ) -> Result<MachineStart, libvm::LibVmError> {
        self.inner.start_with_options(options).await
    }

    pub(crate) async fn wait_ready(
        &self,
        timeout: std::time::Duration,
    ) -> Result<MachineReadiness, libvm::LibVmError> {
        self.inner.wait_ready(timeout).await
    }

    pub(crate) async fn stop_run(
        &self,
        run_id: MachineRunId,
    ) -> Result<MachineData, libvm::LibVmError> {
        self.inner.stop_run(run_id).await
    }

    pub(crate) async fn wait_for_run_with(
        &self,
        run_id: MachineRunId,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, libvm::LibVmError> {
        self.inner.wait_for_run_with(run_id, options).await
    }

    pub(crate) async fn remove(self) -> Result<(), libvm::LibVmError> {
        self.inner.remove().await
    }

    pub(crate) async fn open_serial_stream(
        &self,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, libvm::LibVmError> {
        self.inner.open_serial_stream().await
    }

    pub(crate) async fn logs(
        &self,
        source: MachineLogSource,
        options: MachineLogOptions,
    ) -> Result<
        impl Stream<Item = Result<libvm::MachineLogChunk, libvm::LibVmError>> + Unpin,
        libvm::LibVmError,
    > {
        self.inner.logs(source, options).await
    }

    pub(crate) async fn list_forwards(
        &self,
    ) -> Result<Vec<MachineForwardStatus>, libvm::LibVmError> {
        self.inner.list_forwards().await
    }

    pub(crate) async fn open_forward(
        &self,
        forward: Forward,
    ) -> Result<AppForwardSession, libvm::LibVmError> {
        Ok(AppForwardSession(self.inner.open_forward(forward).await?))
    }

    pub(crate) async fn agent_version(&self) -> Option<String> {
        self.inner
            .monitor_status()
            .await
            .ok()
            .and_then(|status| match status.agent {
                libvm::MachineAgentStatus::Enabled(agent) => {
                    agent.identity.map(|identity| identity.version)
                }
                libvm::MachineAgentStatus::Disabled => None,
            })
    }

    pub(crate) async fn attach_shell(
        &self,
        user: Option<&str>,
        forward_agent: bool,
    ) -> eyre::Result<SshExitStatus> {
        crate::api::streams::attach_shell(self, user, forward_agent).await
    }
}

pub(crate) struct AppForwardSession(MachineForwardSession);

impl AppForwardSession {
    pub(crate) async fn next_status(
        &mut self,
    ) -> Result<Option<MachineForwardStatus>, libvm::LibVmError> {
        self.0.next_status().await
    }
}

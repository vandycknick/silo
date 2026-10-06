use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use libvm::{
    Forward, MachineData, MachineExit, MachineForwardSession, MachineForwardStatus,
    MachineLogOptions, MachineLogSource, MachineReadiness, MachineRunId, MachineStart,
    MachineWaitOptions, SshExitStatus,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::OnceCell;
use tokio_stream::Stream;

use crate::api::daemon::DaemonVmService;
use crate::api::start_options::AppStartOptions;

#[derive(Debug, Clone)]
pub(crate) enum AppMachine {
    Local {
        native: libvm::Machine,
        home: PathBuf,
    },
    Daemon {
        id: String,
        service: DaemonVmService,
        native: Arc<OnceCell<libvm::Machine>>,
    },
}

impl AppMachine {
    pub(in crate::api) fn new(native: libvm::Machine, home: PathBuf) -> Self {
        Self::Local { native, home }
    }

    pub(in crate::api) fn daemon(id: String, service: DaemonVmService) -> Self {
        Self::Daemon {
            id,
            service,
            native: Arc::new(OnceCell::new()),
        }
    }

    pub(in crate::api) async fn session_machine(&self) -> eyre::Result<&libvm::Machine> {
        match self {
            Self::Local { native, .. } => Ok(native),
            Self::Daemon {
                id,
                service,
                native,
            } => {
                native
                    .get_or_try_init(|| async {
                        let reference = libvm::MachineRef::parse(id.clone())?;
                        eyre::ensure!(
                            reference.id_uuid().is_some(),
                            "native session requires an immutable machine UUID"
                        );
                        Ok(service
                            .session_runtime()
                            .await?
                            .get_machine(&reference)
                            .await?)
                    })
                    .await
            }
        }
    }

    fn home(&self) -> &Path {
        match self {
            Self::Local { home, .. } => home,
            Self::Daemon { service, .. } => service.home(),
        }
    }

    pub(crate) fn id(&self) -> String {
        match self {
            Self::Local { native, .. } => native.id(),
            Self::Daemon { id, .. } => id.clone(),
        }
    }

    pub(crate) async fn inspect(&self) -> Result<MachineData, libvm::LibVmError> {
        match self {
            Self::Local { native, .. } => native.inspect().await,
            Self::Daemon { id, service, .. } => service.inspect(id).await,
        }
    }

    pub(crate) async fn start_with_options(
        &self,
        options: AppStartOptions,
    ) -> eyre::Result<MachineStart> {
        let result = match self {
            Self::Local { native, home } => {
                native
                    .start_with_options(options.into_native(home, &native.id())?)
                    .await
            }
            Self::Daemon { id, service, .. } => service.start_with_options(id, options).await,
        };
        result.map_err(|error| crate::commands::secret::map_start_error(error, Some(self.home())))
    }

    pub(crate) async fn wait_ready(
        &self,
        timeout: Duration,
    ) -> Result<MachineReadiness, libvm::LibVmError> {
        match self {
            Self::Local { native, .. } => native.wait_ready(timeout).await,
            Self::Daemon { id, service, .. } => service.wait_ready(id, timeout).await,
        }
    }

    pub(crate) async fn stop_run(
        &self,
        run_id: MachineRunId,
    ) -> Result<MachineData, libvm::LibVmError> {
        // Allow the backend's 45-second shutdown and service drain to complete.
        let options = libvm::MachineStopOptions::new()
            .timeout(Duration::from_secs(60))
            .force_after_timeout(Duration::from_secs(5));
        match self {
            Self::Local { native, .. } => native.stop_run_with(run_id, options).await,
            Self::Daemon { id, service, .. } => service.stop_run(id, run_id, options).await,
        }
    }

    pub(crate) async fn force_stop_run(
        &self,
        run_id: MachineRunId,
    ) -> Result<MachineData, libvm::LibVmError> {
        let options = libvm::MachineKillOptions::new().timeout(Duration::from_secs(5));
        let exit = match self {
            Self::Local { native, .. } => native.kill_run_with(run_id, options).await,
            Self::Daemon { id, service, .. } => service.kill_run(id, run_id, options).await,
        }?;
        Ok(exit.machine)
    }

    pub(crate) async fn wait_for_run_with(
        &self,
        run_id: MachineRunId,
        options: MachineWaitOptions,
    ) -> Result<MachineExit, libvm::LibVmError> {
        match self {
            Self::Local { native, .. } => native.wait_for_run_with(run_id, options).await,
            Self::Daemon { id, service, .. } => {
                service.wait_for_run_with(id, run_id, options).await
            }
        }
    }

    pub(crate) async fn remove(self) -> Result<(), libvm::LibVmError> {
        match self {
            Self::Local { native, .. } => native.remove().await,
            Self::Daemon { id, service, .. } => service.remove(&id).await,
        }
    }

    pub(crate) async fn remove_after_run(
        self,
        run_id: MachineRunId,
    ) -> Result<(), libvm::LibVmError> {
        match self {
            Self::Local { native, .. } => native.remove_after_run(run_id).await,
            Self::Daemon { id, service, .. } => service.remove_after_run(&id, run_id).await,
        }
    }

    pub(crate) async fn open_serial_stream(
        &self,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, libvm::LibVmError> {
        self.session_machine()
            .await
            .map_err(session_error)?
            .open_serial_stream()
            .await
    }

    pub(crate) async fn logs(
        &self,
        source: MachineLogSource,
        options: MachineLogOptions,
    ) -> Result<
        impl Stream<Item = Result<libvm::MachineLogChunk, libvm::LibVmError>> + Unpin,
        libvm::LibVmError,
    > {
        self.session_machine()
            .await
            .map_err(session_error)?
            .logs(source, options)
            .await
    }

    pub(crate) async fn list_forwards(
        &self,
    ) -> Result<Vec<MachineForwardStatus>, libvm::LibVmError> {
        self.session_machine()
            .await
            .map_err(session_error)?
            .list_forwards()
            .await
    }

    pub(crate) async fn open_forward(
        &self,
        forward: Forward,
    ) -> Result<AppForwardSession, libvm::LibVmError> {
        Ok(AppForwardSession(
            self.session_machine()
                .await
                .map_err(session_error)?
                .open_forward(forward)
                .await?,
        ))
    }

    pub(crate) async fn agent_version(&self) -> Option<String> {
        self.session_machine()
            .await
            .ok()?
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

fn session_error(error: eyre::Report) -> libvm::LibVmError {
    match error.downcast::<libvm::LibVmError>() {
        Ok(error) => error,
        Err(error) => std::io::Error::other(error.to_string()).into(),
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

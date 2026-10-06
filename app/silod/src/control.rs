//! Same-user management boundary. Sessions deliberately remain native and direct.
// Accepted native mutations own their semaphore permit independently of RPC waiters.
// Sealing admission precedes draining; native sessions are outside this tracker.
use libvm::{HostPaths, ResolvedRuntimeComponents, Runtime, RuntimeConfig};
use parking_lot::Mutex;
use silo_config::GlobalConfig;
use silod_spec::daemon::v1 as w;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{oneshot, OnceCell, Semaphore};
use tonic::{Request, Status};
mod daemon;
mod machine;
mod network;
mod runtime;
pub(crate) mod socket;
#[cfg(test)]
mod tests;
pub(super) type Stream<T> =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<T, Status>> + Send>>;
#[derive(Clone)]
pub(super) struct Service(Arc<ControlState>);
impl std::ops::Deref for Service {
    type Target = ControlState;
    fn deref(&self) -> &ControlState {
        &self.0
    }
}
pub(super) fn conversion(e: silo_vm_control::ConversionError) -> Status {
    Status::invalid_argument(e.to_string())
}
pub(super) fn native(e: libvm::LibVmError) -> Status {
    silo_vm_control::errors::native_error_to_status(&e)
}
pub(super) fn required<T>(v: Option<T>) -> Result<T, Status> {
    v.ok_or_else(|| Status::invalid_argument("missing required field"))
}
pub(super) fn duration(v: Option<prost_types::Duration>) -> Result<Duration, Status> {
    let d = silo_vm_control::duration_from_wire(required(v)?).map_err(conversion)?;
    if d > Duration::from_secs(300) {
        return Err(Status::invalid_argument("timeout exceeds five minutes"));
    }
    Ok(d)
}
pub(super) fn reference(v: Option<w::MachineRef>) -> Result<libvm::MachineRef, Status> {
    silo_vm_control::lifecycle::reference_from_wire(required(v)?).map_err(conversion)
}
pub(super) fn id(v: &str) -> Result<libvm::MachineRef, Status> {
    silo_vm_control::validate_uuid(v, "machine.id").map_err(conversion)?;
    libvm::MachineRef::parse(v).map_err(native)
}
pub(super) fn run(v: &str) -> Result<libvm::MachineRunId, Status> {
    silo_vm_control::validate_uuid(v, "run.id").map_err(conversion)?;
    v.parse()
        .map_err(|_| Status::invalid_argument("invalid run ID"))
}
struct Admission {
    sealed: bool,
    stopping: bool,
    helper: Option<String>,
    instance: Option<String>,
}
pub(crate) struct ControlState {
    pub(super) host: HostPaths,
    config: RuntimeConfig,
    pub(super) generation: uuid::Uuid,
    components: OnceCell<ResolvedRuntimeComponents>,
    runtime: OnceCell<Runtime>,
    publisher: Arc<crate::status::StatusPublisher>,
    admission: Mutex<Admission>,
    capacity: Arc<Semaphore>,
    stream_shutdown: tokio_util::sync::CancellationToken,
}
impl ControlState {
    pub(crate) fn new(
        host: HostPaths,
        global: GlobalConfig,
        generation: uuid::Uuid,
        publisher: Arc<crate::status::StatusPublisher>,
    ) -> Self {
        let config = RuntimeConfig::local(host.home()).with_networking(global.networking().clone());
        Self {
            host,
            config,
            generation,
            components: OnceCell::new(),
            runtime: OnceCell::new(),
            publisher,
            admission: Mutex::new(Admission {
                sealed: false,
                stopping: false,
                helper: None,
                instance: None,
            }),
            capacity: Arc::new(Semaphore::new(64)),
            stream_shutdown: tokio_util::sync::CancellationToken::new(),
        }
    }
    pub(super) fn response_stream<T: Send + 'static>(
        &self,
        rx: tokio::sync::mpsc::Receiver<Result<T, Status>>,
    ) -> Stream<T> {
        use futures::StreamExt;
        Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx)
                .take_until(self.stream_shutdown.clone().cancelled_owned()),
        )
    }
    pub(crate) async fn get_status(&self) -> Result<w::DaemonStatus, Status> {
        self.publisher
            .wire()
            .map_err(|_| Status::internal("cannot read daemon status"))
    }
    pub(crate) fn check_helper(&self, request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(tag) = request.metadata().get("x-silo-helper-generation") {
            let admission = self.admission.lock();
            if tag.to_str().ok().is_none() || tag.to_str().ok() != admission.helper.as_deref() {
                return Err(Status::failed_precondition("stale helper generation"));
            }
        }
        Ok(request)
    }
    pub(crate) async fn set_helper_generation(&self, generation: Option<uuid::Uuid>) {
        self.admission.lock().helper = generation.map(|v| v.to_string());
    }
    pub(crate) async fn begin_stopping(&self) -> eyre::Result<()> {
        self.admission.lock().stopping = true;
        self.publisher
            .set_core(silod_spec::status::CorePhase::Stopping, None)
    }
    pub(crate) async fn seal_mutations(&self) {
        self.admission.lock().sealed = true;
    }
    pub(crate) async fn drain_mutations(&self) -> Result<(), Status> {
        let _permits = self
            .capacity
            .clone()
            .acquire_many_owned(64)
            .await
            .map_err(|_| Status::internal("mutation tracker closed"))?;
        Ok(())
    }
    pub(super) async fn components(&self) -> Result<&ResolvedRuntimeComponents, Status> {
        self.components
            .get_or_try_init(|| async { self.config.resolve_components().map_err(native) })
            .await
    }
    pub(super) async fn runtime(&self) -> Result<Runtime, Status> {
        let components = self.components().await?.clone();
        let runtime = self
            .runtime
            .get_or_try_init(|| async {
                let command = sibling_cli()
                    .map_err(|_| Status::unavailable("matching sibling silo unavailable"))?;
                let runtime = Runtime::new(self.config.clone().with_runtime_components(components))
                    .await
                    .map_err(native)?;
                let store = runtime.local_home().join("secrets.json");
                Ok::<_, Status>(
                    runtime.with_secret_provider(
                        libvm::HostCommand::new(command)
                            .arg("secret")
                            .arg("provide")
                            .arg("--store-file")
                            .arg(store),
                    ),
                )
            })
            .await?;
        Ok(runtime.clone())
    }
    pub(super) async fn machine(&self, r: &libvm::MachineRef) -> Result<libvm::Machine, Status> {
        self.runtime().await?.get_machine(r).await.map_err(native)
    }
    pub(super) async fn admit(
        &self,
        request: &Request<impl Sized>,
        protected: bool,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        let admission = self.admission.lock();
        let tag = request.metadata().get("x-silo-helper-generation");
        let helper = tag
            .map(|v| v.to_str())
            .transpose()
            .map_err(|_| Status::failed_precondition("stale helper generation"))?;
        if tag.is_some() && helper != admission.helper.as_deref() {
            return Err(Status::failed_precondition("stale helper generation"));
        }
        if admission.sealed
            || (admission.stopping && helper != admission.helper.as_deref())
            || (admission.stopping && helper.is_none())
        {
            return Err(Status::unavailable("mutation admission sealed"));
        }
        if protected {
            match std::fs::symlink_metadata(self.host.home().join("taild/shutdown")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(Status::failed_precondition(
                        "host shutdown admission sealed",
                    ))
                }
            }
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("64 active mutations"))?;
        Ok(permit)
    }
    pub(super) async fn mutate<T, F>(
        &self,
        request: &Request<impl Sized>,
        protected: bool,
        work: F,
    ) -> Result<T, Status>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let permit = self.admit(request, protected).await?;
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = work.await;
            let _ = tx.send(result);
            drop(permit);
        });
        rx.await
            .map_err(|_| Status::internal("mutation task failed"))?
    }
}
fn sibling_cli() -> eyre::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let exe = std::env::current_exe()?.canonicalize()?;
    let path = exe
        .parent()
        .ok_or_else(|| eyre::eyre!("missing executable parent"))?
        .join("silo");
    let m = std::fs::symlink_metadata(&path)?;
    eyre::ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.mode() & 0o111 != 0
            && (m.uid() == nix::unistd::geteuid().as_raw() || m.uid() == 0)
            && m.mode() & 0o022 == 0,
        "unsafe sibling silo"
    );
    Ok(path.canonicalize()?)
}

//! Same-user management boundary. Sessions deliberately remain native and direct.
// Accepted native mutations own their semaphore permit independently of RPC waiters.
// Native sessions are outside this tracker.
use crate::config::GlobalConfig;
use libvm::{HostPaths, ResolvedRuntimeComponents, Runtime, RuntimeConfig};
use parking_lot::Mutex;
use silod_spec::daemon::v1 as w;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{oneshot, OnceCell, Semaphore};
use tonic::Status;
mod daemon;
mod handoff;
pub(crate) mod lobby;
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
#[derive(Debug)]
pub(super) struct MutationPermit {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    settled: Arc<tokio::sync::Notify>,
}
impl Drop for MutationPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.settled.notify_waiters();
    }
}
pub(crate) struct ControlState {
    pub(super) host: HostPaths,
    config: RuntimeConfig,
    pub(super) generation: uuid::Uuid,
    components: OnceCell<ResolvedRuntimeComponents>,
    runtime: OnceCell<Runtime>,
    handoff: OnceCell<libvm::handoff::service::HandoffService>,
    live_query: OnceCell<libvm::LiveCapabilityQuery>,
    publisher: Arc<crate::daemon::status::StatusPublisher>,
    stopping: Mutex<bool>,
    capacity: Arc<Semaphore>,
    settled: Arc<tokio::sync::Notify>,
    stream_shutdown: tokio_util::sync::CancellationToken,
}
impl ControlState {
    pub(crate) fn new(
        host: HostPaths,
        global: GlobalConfig,
        generation: uuid::Uuid,
        publisher: Arc<crate::daemon::status::StatusPublisher>,
    ) -> Self {
        let config = RuntimeConfig::local(host.home())
            .with_networking(global.networking().clone())
            .with_registry_policy(global.images().clone());
        Self {
            host,
            config,
            generation,
            components: OnceCell::new(),
            runtime: OnceCell::new(),
            handoff: OnceCell::new(),
            live_query: OnceCell::new(),
            publisher,
            stopping: Mutex::new(false),
            capacity: Arc::new(Semaphore::new(64)),
            settled: Arc::new(tokio::sync::Notify::new()),
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
    pub(crate) async fn begin_stopping(&self) -> eyre::Result<()> {
        *self.stopping.lock() = true;
        self.publisher
            .set_core(silod_spec::status::CorePhase::Stopping, None)
    }
    pub(crate) async fn wait_for_mutations(&self) -> Result<(), Status> {
        loop {
            let settled = self.settled.notified();
            tokio::pin!(settled);
            // Register before inspecting to avoid losing the last retirement.
            settled.as_mut().enable();
            if self.capacity.available_permits() == 64 {
                return Ok(());
            }
            settled.await;
        }
    }
    pub(super) async fn components(&self) -> Result<&ResolvedRuntimeComponents, Status> {
        self.components
            .get_or_try_init(|| async { self.config.resolve_components().map_err(native) })
            .await
    }
    pub(super) async fn live_capabilities(&self) -> Result<vm_spec::live::LiveHostReport, Status> {
        match self.runtime.get() {
            Some(runtime) => runtime.live_capabilities().await.map_err(native),
            None => self
                .live_query
                .get_or_try_init(|| async {
                    libvm::LiveCapabilityQuery::open(&self.config).map_err(native)
                })
                .await?
                .host_report()
                .await
                .map_err(native),
        }
    }

    pub(super) async fn observe_machine_live(
        &self,
        reference: &libvm::MachineRef,
    ) -> Result<libvm::MachineLiveObservation, Status> {
        match self.runtime.get() {
            Some(runtime) => runtime.observe_live(reference).await.map_err(native),
            None => libvm::LiveObservationReader::open(&self.config)
                .map_err(native)?
                .observe(reference)
                .await
                .map_err(native),
        }
    }

    pub(super) async fn require_machine_live(
        &self,
        reference: &libvm::MachineRef,
        operation: vm_spec::live::LiveOperation,
    ) -> Result<(), Status> {
        let observation = match self.runtime.get() {
            Some(runtime) => runtime.observe_live(reference).await.map_err(native)?,
            None => {
                let reader = libvm::LiveObservationReader::open(&self.config).map_err(native)?;
                if !reader.catalog_exists().map_err(native)? {
                    libvm::require_host_live_operation(&self.live_capabilities().await?, operation)
                        .map_err(native)?;
                }
                reader.observe(reference).await.map_err(native)?
            }
        };
        // This pure guard precedes admit/mutate and every operational reservation.
        libvm::require_live_operation(&observation, operation).map_err(native)
    }
    pub(crate) async fn publish_live_capabilities(&self) -> Result<(), Status> {
        let report = self.live_capabilities().await?;
        self.publisher
            .set_manager_live(report)
            .map_err(|_| Status::internal("cannot publish manager capabilities"))
    }
    pub(super) async fn runtime(&self) -> Result<Runtime, Status> {
        let components = self.components().await?.clone();
        let runtime = self
            .runtime
            .get_or_try_init(|| async {
                let command = std::env::current_exe()
                    .and_then(|path| path.canonicalize())
                    .map_err(|_| Status::unavailable("silo executable path unavailable"))?;
                let config = self.config.clone().with_runtime_components(components);
                let runtime = match self.live_query.get() {
                    Some(query) => Runtime::new_with_capability_query(config, query.clone()).await,
                    None => Runtime::new(config).await,
                }
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
    pub(super) async fn admit(&self) -> Result<MutationPermit, Status> {
        let stopping = self.stopping.lock();
        if *stopping {
            return Err(Status::unavailable("daemon is stopping"));
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("64 active mutations"))?;
        Ok(MutationPermit {
            permit: Some(permit),
            settled: self.settled.clone(),
        })
    }
    pub(super) async fn mutate<T, F>(&self, work: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, Status>> + Send + 'static,
    {
        let permit = self.admit().await.map_err(|mut status| {
            status.metadata_mut().insert(
                "x-silo-mutation-rejected",
                tonic::metadata::MetadataValue::from_static("true"),
            );
            status
        })?;
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

//! Transport-independent handoff participant API. Stable operation locks
//! serialize independent services and processes; each service owns its caches
//! and active operations' bulk-root leases.
//!
//! Every mutating call runs on a detached blocking owner, so a dropped RPC
//! cannot cancel a transition between its durable steps; the caller observes
//! the outcome through `status` and replays the same request.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::handoff::destination::{DestinationState, HandoffPayloadWriter};
use crate::handoff::files::OperationFiles;
use crate::handoff::plan::{
    invalid, ApprovedPlan, CaptureOffer, DestinationRequest, HandoffCapabilities, HandoffProposal,
    NeedCursor, NeedsPage, PayloadDescriptor, PayloadFrame, PayloadReceipt, SourceObservation,
    SourceStop, MAX_DOCUMENT_BYTES, MAX_FRAME_BYTES, MAX_PAGE_ENTRIES,
};
use crate::handoff::source::SourceIndex;
use crate::handoff::types::{
    CommitAuthorization, HandoffBinding, HandoffError, HandoffIntent, HandoffPhase, HandoffRecord,
    HandoffRole, OperationId, PreparedReceipt, TerminalReceipt,
};
use crate::storage::locks::StorageLock;
use crate::{LibVmError, MachineRef, Runtime};

/// Per-operation state, serialized by its own async mutex.
#[derive(Default)]
struct OperationSlot {
    lease: Option<StorageLock>,
    source: Option<Arc<SourceIndex>>,
    destination: Option<DestinationState>,
}

type Slot = Arc<tokio::sync::Mutex<OperationSlot>>;

/// The single most recently served verified chunk, so successive frames of
/// one chunk neither reread nor rehash it.
type ChunkCache = Option<(OperationId, PayloadDescriptor, Arc<Vec<u8>>)>;

#[derive(Clone)]
pub struct HandoffService {
    runtime: Runtime,
    slots: Arc<Mutex<BTreeMap<OperationId, Slot>>>,
    chunk: Arc<Mutex<ChunkCache>>,
}

impl HandoffService {
    pub fn new(runtime: Runtime) -> Self {
        Self {
            runtime,
            slots: Arc::new(Mutex::new(BTreeMap::new())),
            chunk: Arc::new(Mutex::new(None)),
        }
    }

    fn slot(&self, operation: OperationId) -> Result<Slot, LibVmError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| invalid("handoff service state is poisoned"))?;
        Ok(slots.entry(operation).or_default().clone())
    }

    /// Release this process's lease and caches after a terminal decision,
    /// then mark the bulk root finished and drop bulk working files.
    async fn release(&self, operation: OperationId) -> Result<(), LibVmError> {
        let store = self.runtime.native_store()?;
        store.finish_handoff_storage(operation).await?;
        if let Some(files) = OperationFiles::open(self.runtime.local_home(), operation)? {
            files.release_bulk()?;
        }
        let temporary = self.runtime.local_images_dir().join("tmp");
        if let Some(temporary) = crate::paths::OwnedDirectory::open_existing_root(&temporary)? {
            let name = operation.to_string();
            if temporary.open_dir(&name)?.is_some() {
                temporary.remove_tree(&name)?;
                temporary.sync()?;
            }
        }
        let slot = self
            .slots
            .lock()
            .map_err(|_| invalid("handoff service state is poisoned"))?
            .remove(&operation);
        if let Some(slot) = slot {
            *slot.lock().await = OperationSlot::default();
        }
        let mut chunk = self
            .chunk
            .lock()
            .map_err(|_| invalid("handoff service state is poisoned"))?;
        if chunk
            .as_ref()
            .is_some_and(|(cached, _, _)| *cached == operation)
        {
            *chunk = None;
        }
        Ok(())
    }

    /// Run one transition on a blocking owner that outlives its requester.
    /// Acquire the stable operation lock before any service-local slot,
    /// lifecycle lock or storage roots lock, including terminal cleanup.
    async fn detached<T, F, Fut>(&self, operation: OperationId, body: F) -> Result<T, LibVmError>
    where
        T: Send + 'static,
        F: FnOnce(HandoffService) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, LibVmError>>,
    {
        let service = self.clone();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let files = OperationFiles::create(service.runtime.local_home(), operation)?;
            let _transition = files.lock()?;
            handle.block_on(body(service))
        })
        .await?
    }

    async fn record(&self, operation: OperationId) -> Result<HandoffRecord, LibVmError> {
        self.runtime
            .native_store()?
            .get_handoff(operation)
            .await?
            .ok_or_else(|| HandoffError::UnknownOperation { operation }.into())
    }

    pub async fn capabilities(&self) -> Result<HandoffCapabilities, LibVmError> {
        Ok(HandoffCapabilities {
            runtime: self.runtime.native_store()?.runtime_id().await?,
            kernel_architecture: crate::handoff::destination::host_architecture()?,
            backend: self.runtime.effective_backend(),
            max_frame_bytes: MAX_FRAME_BYTES,
            max_page_entries: MAX_PAGE_ENTRIES,
            max_document_bytes: MAX_DOCUMENT_BYTES,
        })
    }

    pub async fn status(
        &self,
        operation: OperationId,
    ) -> Result<Option<HandoffRecord>, LibVmError> {
        self.runtime.native_store()?.get_handoff(operation).await
    }

    /// The exact plan this runtime persisted for `operation`, in either role.
    pub async fn plan(&self, operation: OperationId) -> Result<ApprovedPlan, LibVmError> {
        crate::handoff::source::stored_plan(&self.runtime, operation)
    }

    pub async fn observe_source(
        &self,
        machine: &MachineRef,
    ) -> Result<SourceObservation, LibVmError> {
        crate::handoff::source::observe(&self.runtime, machine).await
    }

    pub async fn begin_source(&self, plan: &ApprovedPlan) -> Result<HandoffRecord, LibVmError> {
        let plan = plan.clone();
        self.detached(plan.plan().operation(), move |service| async move {
            let operation = plan.plan().operation();
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let store = service.runtime.native_store()?;
            crate::handoff::source::begin(&service.runtime, &store, &plan, &mut slot.lease).await
        })
        .await
    }

    pub async fn capture_source(
        &self,
        plan: &ApprovedPlan,
        stop: SourceStop,
    ) -> Result<CaptureOffer, LibVmError> {
        let plan = plan.clone();
        self.detached(plan.plan().operation(), move |service| async move {
            let operation = plan.plan().operation();
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let store = service.runtime.native_store()?;
            let offer = crate::handoff::source::capture(
                &service.runtime,
                &store,
                &plan,
                stop,
                &mut slot.lease,
            )
            .await?;
            slot.source = None;
            Ok(offer)
        })
        .await
    }

    /// One frame of a payload this source operation is allowed to serve.
    pub async fn read_payload(
        &self,
        operation: OperationId,
        descriptor: PayloadDescriptor,
        offset: u64,
        max_bytes: u32,
    ) -> Result<PayloadFrame, LibVmError> {
        self.detached(operation, move |service| async move {
            let record = service.record(operation).await?;
            if record.role != HandoffRole::Source {
                return Err(HandoffError::WrongRuntime.into());
            }
            if record.phase.is_terminal() {
                return Err(HandoffError::InvalidState.into());
            }
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let index = match &slot.source {
                Some(index) if index.captured || record.binding.is_none() => index.clone(),
                _ => {
                    let index = Arc::new(SourceIndex::build(&service.runtime, operation)?);
                    slot.source = Some(index.clone());
                    index
                }
            };
            let cached = match descriptor {
                PayloadDescriptor::Chunk { .. } => service
                    .chunk
                    .lock()
                    .map_err(|_| invalid("handoff service state is poisoned"))?
                    .as_ref()
                    .filter(|(cached, cached_descriptor, _)| {
                        *cached == operation && *cached_descriptor == descriptor
                    })
                    .map(|(_, _, bytes)| bytes.clone()),
                _ => None,
            };
            let (frame, chunk) = index
                .frame(&service.runtime, descriptor, offset, max_bytes, cached)
                .await?;
            if let Some(bytes) = chunk {
                *service
                    .chunk
                    .lock()
                    .map_err(|_| invalid("handoff service state is poisoned"))? =
                    Some((operation, descriptor, bytes));
            }
            Ok(frame)
        })
        .await
    }

    pub async fn fence_source(
        &self,
        prepared: &PreparedReceipt,
    ) -> Result<CommitAuthorization, LibVmError> {
        let prepared = prepared.clone();
        self.detached(
            prepared.binding.intent.operation,
            move |service| async move {
                service
                    .runtime
                    .native_store()?
                    .fence_handoff_source(&prepared)
                    .await
            },
        )
        .await
    }

    /// Apply the destination's terminal decision. Only an exact durable
    /// abort unfences; a committed receipt records the successor.
    pub async fn resolve_source(
        &self,
        receipt: &TerminalReceipt,
    ) -> Result<HandoffRecord, LibVmError> {
        let receipt = receipt.clone();
        self.detached(receipt.intent.operation, move |service| async move {
            let record = service
                .runtime
                .native_store()?
                .resolve_handoff_source(&receipt)
                .await?;
            if record.phase.is_terminal() {
                service.release(record.intent.operation).await?;
            }
            Ok(record)
        })
        .await
    }

    pub async fn preflight_destination(
        &self,
        observation: &SourceObservation,
        request: &DestinationRequest,
    ) -> Result<HandoffProposal, LibVmError> {
        crate::handoff::destination::preflight(&self.runtime, observation, request).await
    }

    pub async fn receive(&self, plan: &ApprovedPlan) -> Result<HandoffRecord, LibVmError> {
        let plan = plan.clone();
        self.detached(plan.plan().operation(), move |service| async move {
            let operation = plan.plan().operation();
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let store = service.runtime.native_store()?;
            crate::handoff::destination::receive(&service.runtime, &store, &plan, &mut slot.lease)
                .await
        })
        .await
    }

    pub async fn offer_capture(&self, offer: &CaptureOffer) -> Result<HandoffRecord, LibVmError> {
        let offer = offer.clone();
        self.detached(
            offer.binding().intent.operation,
            move |service| async move {
                let operation = offer.binding().intent.operation;
                let slot = service.slot(operation)?;
                // Serialize with other requests of this operation; offer itself
                // records only the manifest and binding, never bulk pins.
                let _slot = slot.lock().await;
                let store = service.runtime.native_store()?;
                crate::handoff::destination::offer(&service.runtime, &store, &offer).await
            },
        )
        .await
    }

    /// Reacquire the bulk root lease and cached inventory after a restart.
    async fn destination_slot<'a>(
        &self,
        slot: &'a mut OperationSlot,
        operation: OperationId,
    ) -> Result<&'a mut DestinationState, LibVmError> {
        if slot.lease.is_none() {
            slot.lease = Some(
                self.runtime
                    .native_store()?
                    .begin_handoff_storage(operation)
                    .await?,
            );
        }
        if slot.destination.is_none() {
            slot.destination = Some(DestinationState::load(&self.runtime, operation).await?);
        }
        slot.destination
            .as_mut()
            .ok_or_else(|| invalid("destination state is unavailable"))
    }

    fn receiving(record: &HandoffRecord) -> Result<(), LibVmError> {
        if record.role != HandoffRole::Destination {
            return Err(HandoffError::WrongRuntime.into());
        }
        match record.phase {
            HandoffPhase::Receiving => Ok(()),
            HandoffPhase::Aborted => Err(HandoffError::OperationAborted {
                operation: record.intent.operation,
            }
            .into()),
            _ => Err(HandoffError::InvalidState.into()),
        }
    }

    pub async fn list_needs(
        &self,
        operation: OperationId,
        cursor: Option<NeedCursor>,
        limit: u32,
    ) -> Result<NeedsPage, LibVmError> {
        self.detached(operation, move |service| async move {
            let record = service.record(operation).await?;
            if record.role == HandoffRole::Destination
                && matches!(
                    record.phase,
                    HandoffPhase::Prepared | HandoffPhase::Committed
                )
            {
                return Ok(NeedsPage {
                    needs: Vec::new(),
                    next: None,
                });
            }
            Self::receiving(&record)?;
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let store = service.runtime.native_store()?;
            let state = service.destination_slot(&mut slot, operation).await?;
            state
                .needs(&service.runtime, &store, operation, cursor, limit)
                .await
        })
        .await
    }

    /// Begin one verified payload write for a member of this operation.
    pub async fn open_payload(
        &self,
        operation: OperationId,
        descriptor: PayloadDescriptor,
    ) -> Result<HandoffPayloadWriter, LibVmError> {
        descriptor.validate()?;
        self.detached(operation, move |service| async move {
            let record = service.record(operation).await?;
            Self::receiving(&record)?;
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let state = service.destination_slot(&mut slot, operation).await?;
            state.refresh(&service.runtime, operation)?;
            if !state.inventory.contains(&descriptor) {
                return Err(invalid("payload is not part of this handoff inventory"));
            }
            HandoffPayloadWriter::open(service.runtime.clone(), operation, descriptor)
        })
        .await
    }

    pub async fn prepare(&self, binding: &HandoffBinding) -> Result<PreparedReceipt, LibVmError> {
        let binding = binding.clone();
        self.detached(binding.intent.operation, move |service| async move {
            let operation = binding.intent.operation;
            let slot = service.slot(operation)?;
            let mut slot = slot.lock().await;
            let store = service.runtime.native_store()?;
            let record = store
                .get_handoff(operation)
                .await?
                .ok_or(HandoffError::UnknownOperation { operation })?;
            if record.phase == HandoffPhase::Aborted {
                return Err(HandoffError::OperationAborted { operation }.into());
            }
            if let Some(prepared) = record.prepared {
                if prepared.binding != binding {
                    return Err(HandoffError::ReceiptMismatch.into());
                }
                return Ok(prepared);
            }
            let state = service.destination_slot(&mut slot, operation).await?;
            crate::handoff::destination::prepare(&service.runtime, &store, state, &binding).await
        })
        .await
    }

    pub async fn commit(
        &self,
        authorization: &CommitAuthorization,
    ) -> Result<TerminalReceipt, LibVmError> {
        let authorization = authorization.clone();
        self.detached(
            authorization.prepared.binding.intent.operation,
            move |service| async move {
                let operation = authorization.prepared.binding.intent.operation;
                let slot = service.slot(operation)?;
                let guard = slot.lock().await;
                let store = service.runtime.native_store()?;
                let receipt =
                    crate::handoff::destination::commit(&service.runtime, &store, &authorization)
                        .await?;
                drop(guard);
                service.release(operation).await?;
                Ok(receipt)
            },
        )
        .await
    }

    /// Durable abort, or the immutable committed receipt if commit won.
    pub async fn abort(&self, intent: &HandoffIntent) -> Result<TerminalReceipt, LibVmError> {
        let intent = intent.clone();
        self.detached(intent.operation, move |service| async move {
            let slot = service.slot(intent.operation)?;
            let guard = slot.lock().await;
            let store = service.runtime.native_store()?;
            let receipt =
                crate::handoff::destination::abort(&service.runtime, &store, &intent).await?;
            drop(guard);
            service.release(intent.operation).await?;
            Ok(receipt)
        })
        .await
    }
}

impl HandoffPayloadWriter {
    /// Verify the complete payload, publish it durably and pin it.
    pub async fn finish(self) -> Result<PayloadReceipt, LibVmError> {
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || handle.block_on(self.finish_inner())).await?
    }
}

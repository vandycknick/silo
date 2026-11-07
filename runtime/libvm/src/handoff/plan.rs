//! Bounded, digest-sealed handoff documents and wire values.
//!
//! Every document crossing the control channel is canonical JSON whose SHA-256
//! is its identity. A receiver re-decodes the exact bytes with unknown fields
//! rejected and re-encodes them; any non-canonical spelling fails closed, so an
//! approval digest names exactly one plan.
//!
//! ```text
//!  source              coordinator                 destination
//!  observe_source ───► SourceObservation ───────► preflight_destination
//!                      HandoffProposal ◄────────── (plan + estimate)
//!                      ApprovedPlan (caller approves the plan digest)
//!  begin_source  ◄──── plan ─────────────────────► receive
//!  read_payload  ◄──── needs/frames ─────────────► list_needs / open_payload
//!  capture_source ───► CaptureOffer ─────────────► offer_capture
//!                      needs/frames again, then prepare/fence/commit/resolve
//! ```
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::handoff::types::{
    CaptureId, HandoffBinding, HandoffError, HandoffIntent, HandoffMode, OperationId,
    OwnershipEpoch, RuntimeId,
};
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::{
    BootProfile, ExternalResourcePolicy, ExternalResourceRequirement, GuestArchitecture,
    LibVmError, MachineId, MachineStorageRecord, SnapshotConfiguration, StorageStopOutcome,
};

/// Largest payload frame either participant produces or accepts.
pub const MAX_FRAME_BYTES: u32 = 1 << 20;
/// Largest number of descriptors in one needs page.
pub const MAX_PAGE_ENTRIES: u32 = 1024;
/// Largest sealed document. Plans and manifests are metadata, never payload.
pub const MAX_DOCUMENT_BYTES: u32 = 1 << 20;

pub(crate) fn invalid(message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "handoff",
        message: message.to_string(),
    }
}

/// Exact canonical bytes of one immutable handoff document and their digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDocument {
    digest: ObjectDigest,
    bytes: Vec<u8>,
}

impl SealedDocument {
    /// Admit wire bytes: bounded length and matching SHA-256. Typed decoding
    /// happens in the specific document constructor.
    pub fn new(digest: ObjectDigest, bytes: Vec<u8>) -> Result<Self, LibVmError> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES as usize {
            return Err(invalid("handoff document is empty or exceeds its bound"));
        }
        if ObjectDigest::of_bytes(&bytes) != digest {
            return Err(invalid("handoff document digest does not match its bytes"));
        }
        Ok(Self { digest, bytes })
    }

    pub fn digest(&self) -> ObjectDigest {
        self.digest
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn seal<T: Serialize>(value: &T) -> Result<Self, LibVmError> {
        let value = serde_json::to_value(value).map_err(invalid)?;
        let bytes = crate::store::models::snapshot::canonical_value(&value)?;
        Self::new(ObjectDigest::of_bytes(&bytes), bytes)
    }

    fn open<T: Serialize + DeserializeOwned>(&self) -> Result<T, LibVmError> {
        let value = crate::store::models::snapshot::decode_identity_value(&self.bytes)?;
        let decoded: T = serde_json::from_value(value.clone()).map_err(invalid)?;
        if serde_json::to_value(&decoded).map_err(invalid)? != value {
            return Err(invalid("handoff document is not its closed canonical form"));
        }
        Ok(decoded)
    }
}

/// One writable private role of a stopped machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WritableRole {
    Root,
    Disk { order: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WritableFile {
    pub(crate) role: WritableRole,
    pub(crate) length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImmutableObject {
    pub(crate) digest: ObjectDigest,
    pub(crate) length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImmutableStream {
    pub(crate) stream: StreamId,
    pub(crate) length: u64,
}

/// The source's exact immutable closure. Destination presence is decided by
/// local verification, never by an untrusted `have` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImmutableClosure {
    pub(crate) objects: Vec<ImmutableObject>,
    pub(crate) streams: Vec<ImmutableStream>,
}

/// Running plans name one execution; stopped plans name the private bytes'
/// filesystem generation without hashing those bytes during preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum SourceExecution {
    Running {
        run: uuid::Uuid,
    },
    Stopped {
        files: Vec<crate::storage::identity_file::SourceFingerprint>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservationBody {
    pub(crate) schema: u32,
    pub(crate) runtime: RuntimeId,
    pub(crate) machine: MachineId,
    pub(crate) name: String,
    pub(crate) ownership_epoch: OwnershipEpoch,
    pub(crate) storage_generation: u64,
    pub(crate) execution: SourceExecution,
    pub(crate) configuration: SnapshotConfiguration,
    pub(crate) storage: MachineStorageRecord,
    pub(crate) external_requirements: Vec<ExternalResourceRequirement>,
    pub(crate) immutable: ImmutableClosure,
    pub(crate) writable: Vec<WritableFile>,
}

/// A read-only description of a source machine. Not a reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceObservation {
    document: SealedDocument,
    body: ObservationBody,
}

impl SourceObservation {
    pub(crate) fn new(body: ObservationBody) -> Result<Self, LibVmError> {
        body.validate()?;
        Ok(Self {
            document: SealedDocument::seal(&body)?,
            body,
        })
    }

    pub fn from_document(document: SealedDocument) -> Result<Self, LibVmError> {
        let body: ObservationBody = document.open()?;
        body.validate()?;
        Ok(Self { document, body })
    }

    pub fn document(&self) -> &SealedDocument {
        &self.document
    }

    pub fn runtime(&self) -> RuntimeId {
        self.body.runtime
    }

    pub fn machine(&self) -> MachineId {
        self.body.machine
    }

    pub fn name(&self) -> &str {
        &self.body.name
    }

    pub fn ownership_epoch(&self) -> OwnershipEpoch {
        self.body.ownership_epoch
    }

    pub(crate) fn body(&self) -> &ObservationBody {
        &self.body
    }
}

impl ObservationBody {
    fn validate(&self) -> Result<(), LibVmError> {
        if self.schema != 1 || uuid::Uuid::from(self.machine).is_nil() {
            return Err(invalid("unsupported source observation"));
        }
        self.storage.validate()?;
        self.storage.ownership.ensure_owned(self.machine)?;
        if self.storage.ownership_epoch != self.ownership_epoch.get()
            || self.storage.storage_generation != self.storage_generation
            || self.storage.operation.is_some()
        {
            return Err(invalid("source observation contradicts its storage record"));
        }
        let mut roles = std::collections::BTreeSet::new();
        if self.writable.first().map(|file| file.role) != Some(WritableRole::Root)
            || !self.writable.iter().all(|file| roles.insert(file.role))
        {
            return Err(invalid("source observation writable roles are invalid"));
        }
        match &self.execution {
            SourceExecution::Running { run } if run.is_nil() => {
                return Err(invalid("source observation has no run identity"));
            }
            SourceExecution::Stopped { files } if files.len() != self.writable.len() => {
                return Err(invalid(
                    "source observation omits a writable file generation",
                ));
            }
            _ => {}
        }
        for requirement in &self.external_requirements {
            requirement.validate()?;
        }
        let sorted = |items: &[ImmutableObject]| items.windows(2).all(|pair| pair[0] < pair[1]);
        if !sorted(&self.immutable.objects)
            || !self
                .immutable
                .streams
                .windows(2)
                .all(|pair| pair[0].stream < pair[1].stream)
        {
            return Err(invalid("immutable closure is not canonical"));
        }
        Ok(())
    }
}

/// Boot approval: keep the exact recorded tuple or adopt one complete
/// destination bundle (including its derived translation) at commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BootSelection {
    ExactRecorded,
    DestinationBundle { bundle: ObjectDigest },
}

/// Caller choices for a destination preflight. `operation` is chosen once by
/// the caller; a fork's destination machine ID derives from it, so repeated
/// preflight of the same request yields the same plan digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationRequest {
    pub operation: OperationId,
    pub mode: HandoffMode,
    pub name: Option<String>,
    pub boot_bundle: Option<ObjectDigest>,
    pub resources: ExternalResourcePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PlanBody {
    pub(crate) schema: u32,
    pub(crate) operation: OperationId,
    pub(crate) mode: HandoffMode,
    pub(crate) observation: ObservationBody,
    pub(crate) observation_digest: ObjectDigest,
    pub(crate) destination_runtime: RuntimeId,
    pub(crate) destination_machine: MachineId,
    pub(crate) destination_name: String,
    pub(crate) boot_selection: BootSelection,
    pub(crate) boot: BootProfile,
    pub(crate) configuration: SnapshotConfiguration,
    pub(crate) external_requirements: Vec<ExternalResourceRequirement>,
    pub(crate) resources: ExternalResourcePolicy,
}

impl PlanBody {
    fn validate(&self) -> Result<(), LibVmError> {
        self.observation.validate()?;
        if self.schema != 1
            || SealedDocument::seal(&self.observation)?.digest() != self.observation_digest
        {
            return Err(invalid("handoff plan observation binding is invalid"));
        }
        crate::validate_new_machine_name(&self.destination_name)?;
        self.boot.validate()?;
        if !matches!(
            &self.boot,
            BootProfile::LinuxDirect {
                binding: crate::BootBinding::Pinned { .. },
                ..
            }
        ) {
            return Err(invalid("approved destination boot must be a pinned bundle"));
        }
        if let BootSelection::DestinationBundle { bundle } = self.boot_selection {
            if boot_bundle(&self.boot)? != bundle {
                return Err(invalid("approved boot bundle contradicts the plan boot"));
            }
        } else if self.boot != self.observation.storage.boot {
            return Err(invalid(
                "exact recorded boot differs from the source record",
            ));
        }
        for requirement in &self.external_requirements {
            requirement.validate()?;
        }
        self.intent()?.validate()?;
        Ok(())
    }

    pub(crate) fn intent(&self) -> Result<HandoffIntent, LibVmError> {
        let mut intent = HandoffIntent {
            operation: self.operation,
            mode: self.mode,
            source_runtime: self.observation.runtime,
            destination_runtime: self.destination_runtime,
            source_machine: self.observation.machine,
            destination_machine: self.destination_machine,
            from_epoch: self.observation.ownership_epoch,
            intent_digest: ObjectDigest::of_bytes(&[]),
            approved_plan_digest: SealedDocument::seal(self)?.digest(),
        };
        intent.intent_digest = SealedDocument::seal(&IntentIdentity {
            operation: intent.operation,
            mode: intent.mode,
            source_runtime: intent.source_runtime,
            destination_runtime: intent.destination_runtime,
            source_machine: intent.source_machine,
            destination_machine: intent.destination_machine,
            from_epoch: intent.from_epoch,
            approved_plan_digest: intent.approved_plan_digest,
        })?
        .digest();
        Ok(intent)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IntentIdentity {
    operation: OperationId,
    mode: HandoffMode,
    source_runtime: RuntimeId,
    destination_runtime: RuntimeId,
    source_machine: MachineId,
    destination_machine: MachineId,
    from_epoch: OwnershipEpoch,
    approved_plan_digest: ObjectDigest,
}

pub(crate) fn boot_bundle(boot: &BootProfile) -> Result<ObjectDigest, LibVmError> {
    match boot {
        BootProfile::LinuxDirect { binding, .. } => binding.digest(),
        _ => Err(invalid("handoff requires Linux direct boot")),
    }
}

/// A complete destination proposal. Its digest is what a caller approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffPlan {
    document: SealedDocument,
    body: PlanBody,
}

impl HandoffPlan {
    pub(crate) fn new(body: PlanBody) -> Result<Self, LibVmError> {
        body.validate()?;
        Ok(Self {
            document: SealedDocument::seal(&body)?,
            body,
        })
    }

    pub fn from_document(document: SealedDocument) -> Result<Self, LibVmError> {
        let body: PlanBody = document.open()?;
        body.validate()?;
        Ok(Self { document, body })
    }

    pub fn document(&self) -> &SealedDocument {
        &self.document
    }

    pub fn digest(&self) -> ObjectDigest {
        self.document.digest
    }

    pub fn operation(&self) -> OperationId {
        self.body.operation
    }

    pub fn mode(&self) -> HandoffMode {
        self.body.mode
    }

    pub fn source_runtime(&self) -> RuntimeId {
        self.body.observation.runtime
    }

    pub fn destination_runtime(&self) -> RuntimeId {
        self.body.destination_runtime
    }

    pub fn source_machine(&self) -> MachineId {
        self.body.observation.machine
    }

    pub fn source_name(&self) -> &str {
        &self.body.observation.name
    }

    pub fn destination_machine(&self) -> MachineId {
        self.body.destination_machine
    }

    pub fn destination_name(&self) -> &str {
        &self.body.destination_name
    }

    pub fn boot_selection(&self) -> BootSelection {
        self.body.boot_selection
    }

    pub fn boot_bundle(&self) -> Result<ObjectDigest, LibVmError> {
        boot_bundle(&self.body.boot)
    }

    pub fn kernel_architecture(&self) -> Option<GuestArchitecture> {
        match &self.body.boot {
            BootProfile::LinuxDirect {
                kernel_architecture,
                ..
            } => Some(*kernel_architecture),
            _ => None,
        }
    }

    /// Exactly the caller choices this plan was produced from. A retried
    /// transfer with different options must replan, never reuse this plan.
    pub fn validate_request(&self, request: &DestinationRequest) -> Result<(), LibVmError> {
        let name = request
            .name
            .as_deref()
            .unwrap_or(&self.body.observation.name);
        let boot = match request.boot_bundle {
            None => BootSelection::ExactRecorded,
            Some(bundle) => BootSelection::DestinationBundle { bundle },
        };
        if request.operation != self.body.operation
            || request.mode != self.body.mode
            || name != self.body.destination_name
            || boot != self.body.boot_selection
            || request.resources != self.body.resources
        {
            return Err(HandoffError::OperationConflict {
                operation: self.body.operation,
            }
            .into());
        }
        Ok(())
    }

    /// Explicit caller approval of exactly this digest.
    pub fn approve(self, approved: ObjectDigest) -> Result<ApprovedPlan, LibVmError> {
        if self.document.digest != approved {
            return Err(HandoffError::AdmissionStale.into());
        }
        Ok(ApprovedPlan { plan: self })
    }

    pub(crate) fn body(&self) -> &PlanBody {
        &self.body
    }
}

/// Preflight result: the plan to approve plus a non-binding cost estimate.
/// The estimate depends on the destination cache and is not part of the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffProposal {
    pub plan: HandoffPlan,
    pub estimate: TransferEstimate,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferEstimate {
    /// Logical bytes of the private writable files to capture.
    pub writable_bytes: u64,
    /// Bytes of the immutable closure.
    pub immutable_bytes: u64,
    /// Immutable bytes not verifiably present at the destination now.
    pub missing_immutable_bytes: u64,
    /// Free bytes on the destination home filesystem at preflight.
    pub available_bytes: u64,
}

/// A plan the caller approved. Participants accept only this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedPlan {
    plan: HandoffPlan,
}

impl ApprovedPlan {
    /// A plan document received from a coordinator that already approved its
    /// digest. Each participant binds the digest into the durable intent.
    pub fn from_document(document: SealedDocument) -> Result<Self, LibVmError> {
        Ok(Self {
            plan: HandoffPlan::from_document(document)?,
        })
    }

    pub fn plan(&self) -> &HandoffPlan {
        &self.plan
    }

    pub fn document(&self) -> &SealedDocument {
        &self.plan.document
    }

    pub fn digest(&self) -> ObjectDigest {
        self.plan.document.digest
    }

    /// The deterministic intent both participants persist.
    pub fn intent(&self) -> Result<HandoffIntent, LibVmError> {
        let intent = self.plan.body.intent()?;
        if intent.approved_plan_digest != self.digest() {
            return Err(invalid("approved plan digest contradicts its body"));
        }
        Ok(intent)
    }

    pub(crate) fn body(&self) -> &PlanBody {
        &self.plan.body
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CapturedFile {
    pub(crate) role: WritableRole,
    pub(crate) stream: StreamId,
    pub(crate) length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ManifestBody {
    pub(crate) schema: u32,
    pub(crate) capture: CaptureId,
    pub(crate) operation: OperationId,
    pub(crate) approved_plan_digest: ObjectDigest,
    pub(crate) stop_outcome: StorageStopOutcome,
    pub(crate) files: Vec<CapturedFile>,
}

/// One sealed stopped cut: every writable role's exact stream identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureManifest {
    document: SealedDocument,
    body: ManifestBody,
}

impl CaptureManifest {
    pub(crate) fn new(body: ManifestBody) -> Result<Self, LibVmError> {
        body.validate()?;
        Ok(Self {
            document: SealedDocument::seal(&body)?,
            body,
        })
    }

    pub fn from_document(document: SealedDocument) -> Result<Self, LibVmError> {
        let body: ManifestBody = document.open()?;
        body.validate()?;
        Ok(Self { document, body })
    }

    pub fn document(&self) -> &SealedDocument {
        &self.document
    }

    pub fn capture(&self) -> CaptureId {
        self.body.capture
    }

    pub(crate) fn body(&self) -> &ManifestBody {
        &self.body
    }
}

impl ManifestBody {
    fn validate(&self) -> Result<(), LibVmError> {
        let mut roles = std::collections::BTreeSet::new();
        if self.schema != 1
            || self.files.first().map(|file| file.role) != Some(WritableRole::Root)
            || !self.files.iter().all(|file| roles.insert(file.role))
        {
            return Err(invalid("capture manifest is invalid"));
        }
        Ok(())
    }

    /// Exactly the plan's writable roles and lengths, in order.
    pub(crate) fn check_plan(&self, plan: &ApprovedPlan) -> Result<(), LibVmError> {
        let expected = &plan.body().observation.writable;
        if self.operation != plan.body().operation
            || self.approved_plan_digest != plan.digest()
            || self.files.len() != expected.len()
            || self.files.iter().zip(expected).any(|(file, expected)| {
                file.role != expected.role || file.length != expected.length
            })
        {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        Ok(())
    }
}

/// A source's bound cut, as sent to the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOffer {
    binding: HandoffBinding,
    manifest: CaptureManifest,
}

impl CaptureOffer {
    pub fn new(binding: HandoffBinding, manifest: CaptureManifest) -> Result<Self, LibVmError> {
        binding.intent.validate()?;
        if binding.capture != manifest.capture()
            || binding.capture_manifest_digest != manifest.document().digest()
            || manifest.body.operation != binding.intent.operation
            || manifest.body.approved_plan_digest != binding.intent.approved_plan_digest
        {
            return Err(HandoffError::ReceiptMismatch.into());
        }
        Ok(Self { binding, manifest })
    }

    pub fn binding(&self) -> &HandoffBinding {
        &self.binding
    }

    pub fn manifest(&self) -> &CaptureManifest {
        &self.manifest
    }
}

/// What travels as payload: verified immutable objects, canonical stream maps
/// and decoded chunks. Never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PayloadDescriptor {
    /// Exact object bytes, verified by SHA-256 and length.
    Object { digest: ObjectDigest, length: u64 },
    /// The canonical `silo-chunks-v1` map of `stream`, verified by its identity.
    StreamMap { stream: StreamId },
    /// One decoded nonzero chunk (at most 8 MiB), verified by SHA-256 and length.
    Chunk { digest: ObjectDigest, length: u64 },
}

impl PayloadDescriptor {
    pub fn validate(&self) -> Result<(), LibVmError> {
        match *self {
            Self::Object { length: 0, .. } => Err(invalid("empty immutable object descriptor")),
            Self::Chunk { length, .. }
                if length == 0 || length > crate::storage::limits::CHUNK_SIZE as u64 =>
            {
                Err(invalid("chunk descriptor length is outside 1..=8 MiB"))
            }
            _ => Ok(()),
        }
    }

    /// Exact payload length, when the descriptor names it.
    pub fn exact_length(&self) -> Option<u64> {
        match *self {
            Self::Object { length, .. } | Self::Chunk { length, .. } => Some(length),
            Self::StreamMap { .. } => None,
        }
    }

    /// Largest payload a writer accepts for this descriptor.
    pub fn max_length(&self) -> u64 {
        self.exact_length().unwrap_or_else(max_map_bytes)
    }
}

/// Bound on canonical `silo-chunks-v1` map bytes for the largest admitted
/// stream: a fixed header plus one quoted digest and separator per chunk.
pub fn max_map_bytes() -> u64 {
    const HEADER_BYTES: u64 = 128;
    const ENTRY_BYTES: u64 = 76;
    let chunks = crate::storage::limits::Resource::ArtifactStreamBytes
        .maximum()
        .div_ceil(crate::storage::limits::CHUNK_SIZE as u64);
    HEADER_BYTES + chunks * ENTRY_BYTES
}

/// Opaque cursor into the destination's complete inventory for one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NeedCursor(pub u64);

/// One bounded page of descriptors the destination cannot satisfy locally.
/// `next` indexes the complete inventory, not the filtered list, so filling
/// earlier needs never shifts later pages. A pass ends at `next == None`;
/// coordinators repeat passes until one returns no needs at all, because
/// received maps reveal further chunk needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedsPage {
    pub needs: Vec<PayloadDescriptor>,
    pub next: Option<NeedCursor>,
}

/// One bounded slice of a source payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadFrame {
    pub bytes: Vec<u8>,
    /// The descriptor's complete payload length; identical in every frame.
    pub total_length: u64,
    /// True when `offset + bytes.len() == total_length`.
    pub end: bool,
}

/// A verified, durable destination publication of one descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadReceipt {
    pub descriptor: PayloadDescriptor,
    pub bytes: u64,
}

/// Whether capture may deliberately stop a running source after reserving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceStop {
    RequireStopped,
    StopRunning,
}

/// This runtime's identity and handoff bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffCapabilities {
    pub runtime: RuntimeId,
    pub kernel_architecture: GuestArchitecture,
    pub backend: vm_spec::live::LiveBackend,
    pub max_frame_bytes: u32,
    pub max_page_entries: u32,
    pub max_document_bytes: u32,
}

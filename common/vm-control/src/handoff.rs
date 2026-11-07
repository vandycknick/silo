//! Typed stopped-handoff identities and durable receipts.
use crate::{invalid, required, ConversionError};
use libvm::handoff::types as h;
use silod_spec::daemon::v1 as w;

pub fn intent_from_wire(value: w::HandoffIntent) -> Result<h::HandoffIntent, ConversionError> {
    let result = h::HandoffIntent {
        operation: h::OperationId::new(crate::boot::guid_from_wire(
            &value.operation,
            "handoff.operation",
        )?)
        .map_err(|_| invalid("handoff.operation", "invalid identity"))?,
        mode: match w::HandoffMode::try_from(value.mode) {
            Ok(w::HandoffMode::Fork) => h::HandoffMode::Fork,
            Ok(w::HandoffMode::Relocate) => h::HandoffMode::Relocate,
            _ => return Err(invalid("handoff.mode", "unknown mode")),
        },
        source_runtime: h::RuntimeId::new(crate::boot::guid_from_wire(
            &value.source_runtime,
            "handoff.source_runtime",
        )?)
        .map_err(|_| invalid("handoff.source_runtime", "invalid identity"))?,
        destination_runtime: h::RuntimeId::new(crate::boot::guid_from_wire(
            &value.destination_runtime,
            "handoff.destination_runtime",
        )?)
        .map_err(|_| invalid("handoff.destination_runtime", "invalid identity"))?,
        source_machine: crate::boot::guid_from_wire(
            &value.source_machine,
            "handoff.source_machine",
        )?
        .into(),
        destination_machine: crate::boot::guid_from_wire(
            &value.destination_machine,
            "handoff.destination_machine",
        )?
        .into(),
        from_epoch: h::OwnershipEpoch::new(value.from_epoch)
            .map_err(|_| invalid("handoff.from_epoch", "invalid ownership epoch"))?,
        intent_digest: value
            .intent_digest
            .parse()
            .map_err(|_| invalid("handoff.intent_digest", "invalid digest"))?,
        approved_plan_digest: value
            .approved_plan_digest
            .parse()
            .map_err(|_| invalid("handoff.approved_plan_digest", "invalid digest"))?,
    };
    result
        .validate()
        .map_err(|_| invalid("handoff.intent", "inconsistent identities or epoch"))?;
    Ok(result)
}

pub fn intent_to_wire(value: &h::HandoffIntent) -> Result<w::HandoffIntent, ConversionError> {
    value
        .validate()
        .map_err(|_| invalid("handoff.intent", "inconsistent identities or epoch"))?;
    Ok(w::HandoffIntent {
        operation: value.operation.to_string(),
        mode: match value.mode {
            h::HandoffMode::Fork => w::HandoffMode::Fork,
            h::HandoffMode::Relocate => w::HandoffMode::Relocate,
        } as i32,
        source_runtime: value.source_runtime.to_string(),
        destination_runtime: value.destination_runtime.to_string(),
        source_machine: uuid::Uuid::from(value.source_machine).to_string(),
        destination_machine: uuid::Uuid::from(value.destination_machine).to_string(),
        from_epoch: value.from_epoch.get(),
        intent_digest: value.intent_digest.to_string(),
        approved_plan_digest: value.approved_plan_digest.to_string(),
    })
}

pub fn binding_from_wire(value: w::HandoffBinding) -> Result<h::HandoffBinding, ConversionError> {
    Ok(h::HandoffBinding {
        intent: intent_from_wire(required(value.intent, "handoff.binding.intent")?)?,
        capture: h::CaptureId::new(crate::boot::guid_from_wire(
            &value.capture,
            "handoff.capture",
        )?)
        .map_err(|_| invalid("handoff.capture", "invalid identity"))?,
        capture_manifest_digest: value
            .capture_manifest_digest
            .parse()
            .map_err(|_| invalid("handoff.capture_manifest_digest", "invalid digest"))?,
    })
}

pub fn binding_to_wire(value: &h::HandoffBinding) -> Result<w::HandoffBinding, ConversionError> {
    Ok(w::HandoffBinding {
        intent: Some(intent_to_wire(&value.intent)?),
        capture: value.capture.to_string(),
        capture_manifest_digest: value.capture_manifest_digest.to_string(),
    })
}

pub fn prepared_from_wire(
    value: w::HandoffPreparedReceipt,
) -> Result<h::PreparedReceipt, ConversionError> {
    Ok(h::PreparedReceipt {
        binding: binding_from_wire(required(value.binding, "handoff.prepared.binding")?)?,
        receipt_id: nonnil_guid(&value.receipt_id, "handoff.receipt_id")?,
    })
}

pub fn prepared_to_wire(
    value: &h::PreparedReceipt,
) -> Result<w::HandoffPreparedReceipt, ConversionError> {
    Ok(w::HandoffPreparedReceipt {
        binding: Some(binding_to_wire(&value.binding)?),
        receipt_id: nonnil_guid_to_wire(value.receipt_id, "handoff.receipt_id")?,
    })
}

pub fn authorization_from_wire(
    value: w::HandoffCommitAuthorization,
) -> Result<h::CommitAuthorization, ConversionError> {
    Ok(h::CommitAuthorization {
        prepared: prepared_from_wire(required(value.prepared, "handoff.authorization.prepared")?)?,
        nonce: nonnil_guid(&value.nonce, "handoff.nonce")?,
    })
}

pub fn authorization_to_wire(
    value: &h::CommitAuthorization,
) -> Result<w::HandoffCommitAuthorization, ConversionError> {
    Ok(w::HandoffCommitAuthorization {
        prepared: Some(prepared_to_wire(&value.prepared)?),
        nonce: nonnil_guid_to_wire(value.nonce, "handoff.nonce")?,
    })
}

pub fn terminal_from_wire(
    value: w::HandoffTerminalReceipt,
) -> Result<h::TerminalReceipt, ConversionError> {
    let result = h::TerminalReceipt {
        intent: intent_from_wire(required(value.intent, "handoff.terminal.intent")?)?,
        binding: value.binding.map(binding_from_wire).transpose()?,
        decision: match w::HandoffDecision::try_from(value.decision) {
            Ok(w::HandoffDecision::Committed) => h::HandoffDecision::Committed,
            Ok(w::HandoffDecision::Aborted) => h::HandoffDecision::Aborted,
            _ => return Err(invalid("handoff.decision", "unknown decision")),
        },
        authorization: value
            .authorization
            .map(authorization_from_wire)
            .transpose()?,
    };
    result
        .validate()
        .map_err(|_| invalid("handoff.terminal", "inconsistent terminal receipt"))?;
    Ok(result)
}

pub fn terminal_to_wire(
    value: &h::TerminalReceipt,
) -> Result<w::HandoffTerminalReceipt, ConversionError> {
    value
        .validate()
        .map_err(|_| invalid("handoff.terminal", "inconsistent terminal receipt"))?;
    Ok(w::HandoffTerminalReceipt {
        intent: Some(intent_to_wire(&value.intent)?),
        binding: value.binding.as_ref().map(binding_to_wire).transpose()?,
        decision: match value.decision {
            h::HandoffDecision::Committed => w::HandoffDecision::Committed,
            h::HandoffDecision::Aborted => w::HandoffDecision::Aborted,
        } as i32,
        authorization: value
            .authorization
            .as_ref()
            .map(authorization_to_wire)
            .transpose()?,
    })
}

pub fn operation_from_wire(value: &str) -> Result<h::OperationId, ConversionError> {
    h::OperationId::new(crate::boot::guid_from_wire(value, "handoff.operation")?)
        .map_err(|_| invalid("handoff.operation", "invalid identity"))
}

pub fn status_from_wire(
    value: w::HandoffStatus,
) -> Result<Option<h::HandoffRecord>, ConversionError> {
    value.record.map(record_from_wire).transpose()
}

pub fn status_to_wire(
    value: Option<&h::HandoffRecord>,
) -> Result<w::HandoffStatus, ConversionError> {
    Ok(w::HandoffStatus {
        record: value.map(record_to_wire).transpose()?,
    })
}

pub fn record_from_wire(value: w::HandoffRecord) -> Result<h::HandoffRecord, ConversionError> {
    let record = h::HandoffRecord {
        schema: value.schema,
        role: match w::HandoffRole::try_from(value.role) {
            Ok(w::HandoffRole::Source) => h::HandoffRole::Source,
            Ok(w::HandoffRole::Destination) => h::HandoffRole::Destination,
            _ => return Err(invalid("handoff.role", "unknown role")),
        },
        intent: intent_from_wire(required(value.intent, "handoff.record.intent")?)?,
        binding: value.binding.map(binding_from_wire).transpose()?,
        phase: match w::HandoffPhase::try_from(value.phase) {
            Ok(w::HandoffPhase::Intended) => h::HandoffPhase::Intended,
            Ok(w::HandoffPhase::Reserved) => h::HandoffPhase::Reserved,
            Ok(w::HandoffPhase::Captured) => h::HandoffPhase::Captured,
            Ok(w::HandoffPhase::Fenced) => h::HandoffPhase::Fenced,
            Ok(w::HandoffPhase::Receiving) => h::HandoffPhase::Receiving,
            Ok(w::HandoffPhase::Prepared) => h::HandoffPhase::Prepared,
            Ok(w::HandoffPhase::Committed) => h::HandoffPhase::Committed,
            Ok(w::HandoffPhase::Aborted) => h::HandoffPhase::Aborted,
            _ => return Err(invalid("handoff.phase", "unknown phase")),
        },
        prepared: value.prepared.map(prepared_from_wire).transpose()?,
        authorization: value
            .authorization
            .map(authorization_from_wire)
            .transpose()?,
        terminal: value.terminal.map(terminal_from_wire).transpose()?,
    };
    record
        .validate()
        .map_err(|_| invalid("handoff.record", "inconsistent durable record"))?;
    Ok(record)
}

pub fn record_to_wire(value: &h::HandoffRecord) -> Result<w::HandoffRecord, ConversionError> {
    value
        .validate()
        .map_err(|_| invalid("handoff.record", "inconsistent durable record"))?;
    Ok(w::HandoffRecord {
        schema: value.schema,
        role: match value.role {
            h::HandoffRole::Source => w::HandoffRole::Source,
            h::HandoffRole::Destination => w::HandoffRole::Destination,
        } as i32,
        intent: Some(intent_to_wire(&value.intent)?),
        binding: value.binding.as_ref().map(binding_to_wire).transpose()?,
        phase: match value.phase {
            h::HandoffPhase::Intended => w::HandoffPhase::Intended,
            h::HandoffPhase::Reserved => w::HandoffPhase::Reserved,
            h::HandoffPhase::Captured => w::HandoffPhase::Captured,
            h::HandoffPhase::Fenced => w::HandoffPhase::Fenced,
            h::HandoffPhase::Receiving => w::HandoffPhase::Receiving,
            h::HandoffPhase::Prepared => w::HandoffPhase::Prepared,
            h::HandoffPhase::Committed => w::HandoffPhase::Committed,
            h::HandoffPhase::Aborted => w::HandoffPhase::Aborted,
        } as i32,
        prepared: value.prepared.as_ref().map(prepared_to_wire).transpose()?,
        authorization: value
            .authorization
            .as_ref()
            .map(authorization_to_wire)
            .transpose()?,
        terminal: value.terminal.as_ref().map(terminal_to_wire).transpose()?,
    })
}

fn nonnil_guid(value: &str, field: &'static str) -> Result<uuid::Uuid, ConversionError> {
    let value = crate::boot::guid_from_wire(value, field)?;
    nonnil_guid_to_wire(value, field)?;
    Ok(value)
}

fn nonnil_guid_to_wire(value: uuid::Uuid, field: &'static str) -> Result<String, ConversionError> {
    if value.is_nil() {
        return Err(invalid(field, "nil UUID"));
    }
    crate::boot::guid_to_wire(&value, field)
}

pub fn validate_payload_length(
    value: &libvm::handoff::plan::PayloadDescriptor,
    length: u64,
) -> Result<(), ConversionError> {
    value
        .validate()
        .map_err(|_| invalid("handoff.payload", "invalid descriptor"))?;
    if length == 0
        || length > value.max_length()
        || value
            .exact_length()
            .is_some_and(|expected| expected != length)
    {
        return Err(invalid("handoff.payload.length", "invalid payload length"));
    }
    Ok(())
}

pub fn descriptor_from_wire(
    value: w::HandoffPayloadDescriptor,
) -> Result<libvm::handoff::plan::PayloadDescriptor, ConversionError> {
    use w::handoff_payload_descriptor::Payload;
    let (identity, chunk) = match required(value.payload, "handoff.payload")? {
        Payload::Object(identity) => (identity, false),
        Payload::Chunk(identity) => (identity, true),
        Payload::StreamMap(stream) => {
            return Ok(libvm::handoff::plan::PayloadDescriptor::StreamMap {
                stream: stream
                    .parse()
                    .map_err(|_| invalid("handoff.payload.stream", "invalid stream identity"))?,
            })
        }
    };
    if identity.length == 0
        || identity.length > i64::MAX as u64
        || chunk && identity.length > 8 * 1024 * 1024
    {
        return Err(invalid("handoff.payload.length", "invalid payload length"));
    }
    let digest = identity
        .digest
        .parse()
        .map_err(|_| invalid("handoff.payload.digest", "invalid digest"))?;
    Ok(if chunk {
        libvm::handoff::plan::PayloadDescriptor::Chunk {
            digest,
            length: identity.length,
        }
    } else {
        libvm::handoff::plan::PayloadDescriptor::Object {
            digest,
            length: identity.length,
        }
    })
}

pub fn descriptor_to_wire(
    value: &libvm::handoff::plan::PayloadDescriptor,
) -> Result<w::HandoffPayloadDescriptor, ConversionError> {
    use w::handoff_payload_descriptor::Payload;
    let (digest, length, chunk) = match value {
        libvm::handoff::plan::PayloadDescriptor::Object { digest, length } => {
            (digest, *length, false)
        }
        libvm::handoff::plan::PayloadDescriptor::Chunk { digest, length } => {
            (digest, *length, true)
        }
        libvm::handoff::plan::PayloadDescriptor::StreamMap { stream } => {
            return Ok(w::HandoffPayloadDescriptor {
                payload: Some(Payload::StreamMap(stream.to_string())),
            })
        }
    };
    if length == 0 || length > i64::MAX as u64 || chunk && length > 8 * 1024 * 1024 {
        return Err(invalid("handoff.payload.length", "invalid payload length"));
    }
    let identity = w::HandoffPayloadIdentity {
        digest: digest.to_string(),
        length,
    };
    Ok(w::HandoffPayloadDescriptor {
        payload: Some(if chunk {
            Payload::Chunk(identity)
        } else {
            Payload::Object(identity)
        }),
    })
}

pub fn read_from_wire(
    value: w::HandoffReadRequest,
) -> Result<
    (
        h::OperationId,
        libvm::handoff::plan::PayloadDescriptor,
        u64,
        u32,
    ),
    ConversionError,
> {
    let operation = operation_from_wire(&value.operation)?;
    let descriptor = descriptor_from_wire(required(value.descriptor, "handoff.read.descriptor")?)?;
    if value.max_bytes == 0
        || value.max_bytes > 1024 * 1024
        || value.offset > descriptor.max_length()
    {
        return Err(invalid("handoff.read", "invalid offset or frame bound"));
    }
    Ok((operation, descriptor, value.offset, value.max_bytes))
}

pub fn frame_to_wire(
    value: libvm::handoff::plan::PayloadFrame,
) -> Result<w::HandoffPayloadFrame, ConversionError> {
    if value.bytes.len() > 1024 * 1024
        || value.bytes.is_empty() && !value.end
        || value.bytes.len() as u64 > value.total_length
    {
        return Err(invalid("handoff.frame", "invalid payload frame size"));
    }
    Ok(w::HandoffPayloadFrame {
        content: value.bytes,
        end: value.end,
        total_length: value.total_length,
    })
}

pub fn frame_from_wire(
    value: w::HandoffPayloadFrame,
) -> Result<libvm::handoff::plan::PayloadFrame, ConversionError> {
    if value.content.len() > 1024 * 1024
        || value.content.is_empty() && !value.end
        || value.content.len() as u64 > value.total_length
    {
        return Err(invalid("handoff.frame", "invalid payload frame size"));
    }
    Ok(libvm::handoff::plan::PayloadFrame {
        bytes: value.content,
        end: value.end,
        total_length: value.total_length,
    })
}

pub fn payload_receipt_to_wire(
    value: &libvm::handoff::plan::PayloadReceipt,
) -> Result<w::HandoffPayloadReceipt, ConversionError> {
    validate_payload_length(&value.descriptor, value.bytes)?;
    Ok(w::HandoffPayloadReceipt {
        descriptor: Some(descriptor_to_wire(&value.descriptor)?),
        bytes: value.bytes,
    })
}

pub fn payload_receipt_from_wire(
    value: w::HandoffPayloadReceipt,
) -> Result<libvm::handoff::plan::PayloadReceipt, ConversionError> {
    let descriptor = descriptor_from_wire(required(
        value.descriptor,
        "handoff.payload_receipt.descriptor",
    )?)?;
    validate_payload_length(&descriptor, value.bytes)?;
    Ok(libvm::handoff::plan::PayloadReceipt {
        descriptor,
        bytes: value.bytes,
    })
}

pub fn needs_from_wire(
    value: w::HandoffNeedsRequest,
) -> Result<
    (
        h::OperationId,
        Option<libvm::handoff::plan::NeedCursor>,
        u32,
    ),
    ConversionError,
> {
    if value.limit == 0 || value.limit > libvm::handoff::plan::MAX_PAGE_ENTRIES {
        return Err(invalid(
            "handoff.needs.limit",
            "page limit exceeds the advertised bound",
        ));
    }
    Ok((
        operation_from_wire(&value.operation)?,
        value.cursor.map(libvm::handoff::plan::NeedCursor),
        value.limit,
    ))
}

pub fn needs_to_wire(
    value: &libvm::handoff::plan::NeedsPage,
) -> Result<w::HandoffNeedsPage, ConversionError> {
    if value.needs.len() > libvm::handoff::plan::MAX_PAGE_ENTRIES as usize {
        return Err(invalid(
            "handoff.needs",
            "page exceeds the advertised bound",
        ));
    }
    Ok(w::HandoffNeedsPage {
        needs: value
            .needs
            .iter()
            .map(descriptor_to_wire)
            .collect::<Result<_, _>>()?,
        next: value.next.as_ref().map(|cursor| cursor.0),
    })
}

pub fn needs_page_from_wire(
    value: w::HandoffNeedsPage,
) -> Result<libvm::handoff::plan::NeedsPage, ConversionError> {
    if value.needs.len() > libvm::handoff::plan::MAX_PAGE_ENTRIES as usize {
        return Err(invalid(
            "handoff.needs",
            "page exceeds the advertised bound",
        ));
    }
    Ok(libvm::handoff::plan::NeedsPage {
        needs: value
            .needs
            .into_iter()
            .map(descriptor_from_wire)
            .collect::<Result<_, _>>()?,
        next: value.next.map(libvm::handoff::plan::NeedCursor),
    })
}

pub fn document_from_wire(
    value: w::HandoffDocument,
) -> Result<libvm::handoff::plan::SealedDocument, ConversionError> {
    let digest = value
        .digest
        .parse()
        .map_err(|_| invalid("handoff.document.digest", "invalid digest"))?;
    libvm::handoff::plan::SealedDocument::new(digest, value.content).map_err(|_| {
        invalid(
            "handoff.document",
            "empty, oversized or digest-mismatched document",
        )
    })
}

pub fn document_to_wire(
    value: &libvm::handoff::plan::SealedDocument,
) -> Result<w::HandoffDocument, ConversionError> {
    Ok(w::HandoffDocument {
        digest: value.digest().to_string(),
        content: value.bytes().to_vec(),
    })
}

pub fn observation_from_wire(
    value: w::HandoffDocument,
) -> Result<libvm::handoff::plan::SourceObservation, ConversionError> {
    libvm::handoff::plan::SourceObservation::from_document(document_from_wire(value)?).map_err(
        |_| {
            invalid(
                "handoff.observation",
                "invalid canonical source observation",
            )
        },
    )
}

pub fn observation_to_wire(
    value: &libvm::handoff::plan::SourceObservation,
) -> Result<w::HandoffDocument, ConversionError> {
    document_to_wire(value.document())
}

pub fn proposal_to_wire(
    value: &libvm::handoff::plan::HandoffProposal,
) -> Result<w::HandoffProposal, ConversionError> {
    Ok(w::HandoffProposal {
        plan: Some(document_to_wire(value.plan.document())?),
        estimate: Some(w::HandoffTransferEstimate {
            writable_bytes: value.estimate.writable_bytes,
            immutable_bytes: value.estimate.immutable_bytes,
            missing_immutable_bytes: value.estimate.missing_immutable_bytes,
            available_bytes: value.estimate.available_bytes,
        }),
    })
}

pub fn proposal_from_wire(
    value: w::HandoffProposal,
) -> Result<libvm::handoff::plan::HandoffProposal, ConversionError> {
    let plan = libvm::handoff::plan::HandoffPlan::from_document(document_from_wire(required(
        value.plan,
        "handoff.proposal.plan",
    )?)?)
    .map_err(|_| invalid("handoff.proposal.plan", "invalid canonical plan"))?;
    let estimate = required(value.estimate, "handoff.proposal.estimate")?;
    if estimate.missing_immutable_bytes > estimate.immutable_bytes {
        return Err(invalid(
            "handoff.proposal.estimate",
            "missing bytes exceed immutable bytes",
        ));
    }
    Ok(libvm::handoff::plan::HandoffProposal {
        plan,
        estimate: libvm::handoff::plan::TransferEstimate {
            writable_bytes: estimate.writable_bytes,
            immutable_bytes: estimate.immutable_bytes,
            missing_immutable_bytes: estimate.missing_immutable_bytes,
            available_bytes: estimate.available_bytes,
        },
    })
}

pub fn approved_from_wire(
    value: w::HandoffDocument,
) -> Result<libvm::handoff::plan::ApprovedPlan, ConversionError> {
    libvm::handoff::plan::ApprovedPlan::from_document(document_from_wire(value)?)
        .map_err(|_| invalid("handoff.approved_plan", "invalid canonical approved plan"))
}

pub fn offer_from_wire(
    value: w::HandoffCaptureOffer,
) -> Result<libvm::handoff::plan::CaptureOffer, ConversionError> {
    let binding = binding_from_wire(required(value.binding, "handoff.offer.binding")?)?;
    let manifest = libvm::handoff::plan::CaptureManifest::from_document(document_from_wire(
        required(value.manifest, "handoff.offer.manifest")?,
    )?)
    .map_err(|_| {
        invalid(
            "handoff.offer.manifest",
            "invalid canonical capture manifest",
        )
    })?;
    libvm::handoff::plan::CaptureOffer::new(binding, manifest)
        .map_err(|_| invalid("handoff.offer", "capture binding differs from manifest"))
}

pub fn offer_to_wire(
    value: &libvm::handoff::plan::CaptureOffer,
) -> Result<w::HandoffCaptureOffer, ConversionError> {
    Ok(w::HandoffCaptureOffer {
        binding: Some(binding_to_wire(value.binding())?),
        manifest: Some(document_to_wire(value.manifest().document())?),
    })
}

pub fn capabilities_to_wire(
    value: &libvm::handoff::plan::HandoffCapabilities,
) -> Result<w::HandoffCapabilities, ConversionError> {
    Ok(w::HandoffCapabilities {
        runtime: value.runtime.to_string(),
        kernel_architecture: crate::boot::architecture_to_wire(value.kernel_architecture),
        backend: crate::live::backend_to_wire(value.backend),
        max_document_bytes: value.max_document_bytes,
        max_frame_bytes: value.max_frame_bytes,
        max_page_entries: value.max_page_entries,
    })
}

pub fn capabilities_from_wire(
    value: w::HandoffCapabilities,
) -> Result<libvm::handoff::plan::HandoffCapabilities, ConversionError> {
    if value.max_frame_bytes == 0
        || value.max_frame_bytes > libvm::handoff::plan::MAX_FRAME_BYTES
        || value.max_page_entries == 0
        || value.max_page_entries > libvm::handoff::plan::MAX_PAGE_ENTRIES
        || value.max_document_bytes == 0
        || value.max_document_bytes > libvm::handoff::plan::MAX_DOCUMENT_BYTES
    {
        return Err(invalid("handoff.capabilities", "invalid advertised bounds"));
    }
    Ok(libvm::handoff::plan::HandoffCapabilities {
        runtime: h::RuntimeId::new(crate::boot::guid_from_wire(
            &value.runtime,
            "handoff.runtime",
        )?)
        .map_err(|_| invalid("handoff.runtime", "invalid identity"))?,
        kernel_architecture: crate::boot::architecture_from_wire(
            value.kernel_architecture,
            "handoff.kernel_architecture",
        )?,
        backend: crate::live::backend_from_wire(value.backend)?,
        max_document_bytes: value.max_document_bytes,
        max_frame_bytes: value.max_frame_bytes,
        max_page_entries: value.max_page_entries,
    })
}

pub fn destination_from_wire(
    value: w::HandoffDestinationRequest,
) -> Result<libvm::handoff::plan::DestinationRequest, ConversionError> {
    use w::handoff_boot_selection::Selection;
    let mode = match w::HandoffMode::try_from(value.mode) {
        Ok(w::HandoffMode::Fork) => h::HandoffMode::Fork,
        Ok(w::HandoffMode::Relocate) => h::HandoffMode::Relocate,
        _ => return Err(invalid("handoff.mode", "unknown mode")),
    };
    let boot_bundle = match required(
        required(value.boot, "handoff.boot")?.selection,
        "handoff.boot.selection",
    )? {
        Selection::ExactRecorded(()) => None,
        Selection::DestinationBundle(bundle) => Some(
            bundle
                .parse()
                .map_err(|_| invalid("handoff.boot.bundle", "invalid digest"))?,
        ),
    };
    if let Some(name) = &value.name {
        libvm::validate_new_machine_name(name)
            .map_err(|_| invalid("handoff.name", "invalid machine name"))?;
    }
    Ok(libvm::handoff::plan::DestinationRequest {
        operation: operation_from_wire(&value.operation)?,
        mode,
        boot_bundle,
        resources: crate::stopped::policy_from_wire(required(
            value.resources,
            "handoff.resources",
        )?)?,
        name: value.name,
    })
}

pub fn destination_to_wire(
    value: &libvm::handoff::plan::DestinationRequest,
) -> Result<w::HandoffDestinationRequest, ConversionError> {
    use w::handoff_boot_selection::Selection;
    if let Some(name) = &value.name {
        libvm::validate_new_machine_name(name)
            .map_err(|_| invalid("handoff.name", "invalid machine name"))?;
    }
    Ok(w::HandoffDestinationRequest {
        operation: value.operation.to_string(),
        mode: match value.mode {
            h::HandoffMode::Fork => w::HandoffMode::Fork,
            h::HandoffMode::Relocate => w::HandoffMode::Relocate,
        } as i32,
        boot: Some(w::HandoffBootSelection {
            selection: Some(match value.boot_bundle {
                None => Selection::ExactRecorded(()),
                Some(bundle) => Selection::DestinationBundle(bundle.to_string()),
            }),
        }),
        resources: Some(crate::stopped::policy_to_wire(&value.resources)),
        name: value.name.clone(),
    })
}

pub fn preflight_from_wire(
    value: w::HandoffPreflightRequest,
) -> Result<
    (
        libvm::handoff::plan::SourceObservation,
        libvm::handoff::plan::DestinationRequest,
    ),
    ConversionError,
> {
    Ok((
        observation_from_wire(required(
            value.observation,
            "handoff.preflight.observation",
        )?)?,
        destination_from_wire(required(
            value.destination,
            "handoff.preflight.destination",
        )?)?,
    ))
}

pub fn receive_from_wire(
    value: w::HandoffReceiveRequest,
) -> Result<libvm::handoff::plan::ApprovedPlan, ConversionError> {
    let operation = operation_from_wire(&value.operation)?;
    let plan = approved_from_wire(required(value.approved_plan, "handoff.approved_plan")?)?;
    if plan.plan().operation() != operation {
        return Err(invalid(
            "handoff.operation",
            "operation differs from approved plan",
        ));
    }
    Ok(plan)
}

pub fn capture_from_wire(
    value: w::HandoffCaptureRequest,
) -> Result<
    (
        libvm::handoff::plan::ApprovedPlan,
        libvm::handoff::plan::SourceStop,
    ),
    ConversionError,
> {
    let stop = match w::HandoffSourceStop::try_from(value.stop) {
        Ok(w::HandoffSourceStop::Require) => libvm::handoff::plan::SourceStop::RequireStopped,
        Ok(w::HandoffSourceStop::StopRunning) => libvm::handoff::plan::SourceStop::StopRunning,
        _ => return Err(invalid("handoff.stop", "unknown source stop policy")),
    };
    let plan = receive_from_wire(w::HandoffReceiveRequest {
        operation: value.operation,
        approved_plan: value.approved_plan,
    })?;
    Ok((plan, stop))
}

#[cfg(test)]
mod tests {
    use crate::handoff::{
        intent_to_wire, prepared_from_wire, record_to_wire, status_from_wire, status_to_wire,
        terminal_from_wire,
    };
    use libvm::handoff::types as h;
    use silod_spec::daemon::v1 as w;

    fn intent() -> h::HandoffIntent {
        h::HandoffIntent {
            operation: h::OperationId::new(uuid::Uuid::new_v4()).unwrap(),
            mode: h::HandoffMode::Relocate,
            source_runtime: h::RuntimeId::new(uuid::Uuid::new_v4()).unwrap(),
            destination_runtime: h::RuntimeId::new(uuid::Uuid::new_v4()).unwrap(),
            source_machine: uuid::Uuid::new_v4().into(),
            destination_machine: uuid::Uuid::nil().into(),
            from_epoch: h::OwnershipEpoch::new(3).unwrap(),
            intent_digest: format!("sha256:{}", "ab".repeat(32)).parse().unwrap(),
            approved_plan_digest: format!("sha256:{}", "cd".repeat(32)).parse().unwrap(),
        }
    }

    #[test]
    fn unknown_status_is_not_an_abort_receipt() {
        assert_eq!(
            status_from_wire(w::HandoffStatus { record: None }).unwrap(),
            None
        );
        assert!(terminal_from_wire(w::HandoffTerminalReceipt::default()).is_err());
    }

    #[test]
    fn durable_status_round_trip_rejects_unknown_and_inconsistent_states() {
        let mut intent = intent();
        intent.destination_machine = intent.source_machine;
        let record = h::HandoffRecord {
            schema: 1,
            role: h::HandoffRole::Source,
            intent,
            binding: None,
            phase: h::HandoffPhase::Reserved,
            prepared: None,
            authorization: None,
            terminal: None,
        };
        let wire = status_to_wire(Some(&record)).unwrap();
        assert_eq!(
            status_from_wire(wire.clone()).unwrap(),
            Some(record.clone())
        );
        let mut unknown = wire;
        unknown.record.as_mut().unwrap().phase = 99;
        assert!(status_from_wire(unknown).is_err());
        let mut inconsistent = record;
        inconsistent.phase = h::HandoffPhase::Committed;
        assert!(record_to_wire(&inconsistent).is_err());
    }

    #[test]
    fn receipts_reject_nil_identity_and_wrong_capture_binding() {
        let mut intent = intent();
        intent.destination_machine = intent.source_machine;
        let binding = w::HandoffBinding {
            intent: Some(intent_to_wire(&intent).unwrap()),
            capture: uuid::Uuid::new_v4().to_string(),
            capture_manifest_digest: format!("sha256:{}", "ef".repeat(32)),
        };
        assert!(prepared_from_wire(w::HandoffPreparedReceipt {
            binding: Some(binding.clone()),
            receipt_id: uuid::Uuid::nil().to_string(),
        })
        .is_err());
        let authorization = w::HandoffCommitAuthorization {
            prepared: Some(w::HandoffPreparedReceipt {
                binding: Some(binding.clone()),
                receipt_id: uuid::Uuid::new_v4().to_string(),
            }),
            nonce: uuid::Uuid::new_v4().to_string(),
        };
        let mut wrong_binding = binding;
        wrong_binding.capture = uuid::Uuid::new_v4().to_string();
        assert!(terminal_from_wire(w::HandoffTerminalReceipt {
            intent: Some(intent_to_wire(&intent).unwrap()),
            binding: Some(wrong_binding),
            decision: w::HandoffDecision::Committed as i32,
            authorization: Some(authorization),
        })
        .is_err());
    }

    #[test]
    fn documents_reject_size_digest_and_untyped_content_before_admission() {
        use crate::handoff::{approved_from_wire, document_from_wire, observation_from_wire};
        use libvm::storage::identity::ObjectDigest;
        for content in [Vec::new(), vec![b'x'; 1024 * 1024 + 1]] {
            let wire = w::HandoffDocument {
                digest: ObjectDigest::of_bytes(&content).to_string(),
                content,
            };
            assert!(document_from_wire(wire).is_err());
        }
        let wire = w::HandoffDocument {
            digest: ObjectDigest::of_bytes(b"{}").to_string(),
            content: b"[]".to_vec(),
        };
        assert!(document_from_wire(wire).is_err());
        let wire = w::HandoffDocument {
            digest: ObjectDigest::of_bytes(b"{}").to_string(),
            content: b"{}".to_vec(),
        };
        assert!(observation_from_wire(wire.clone()).is_err());
        assert!(approved_from_wire(wire).is_err());
    }

    #[test]
    fn malformed_participants_enums_and_payload_bounds_are_rejected() {
        use crate::handoff::{
            descriptor_from_wire, frame_from_wire, intent_from_wire, needs_from_wire,
        };
        let mut native = intent();
        native.destination_machine = native.source_machine;
        let mut wire = intent_to_wire(&native).unwrap();
        wire.source_runtime = uuid::Uuid::nil().to_string();
        assert!(intent_from_wire(wire).is_err());
        let mut wire = intent_to_wire(&native).unwrap();
        wire.destination_runtime = wire.source_runtime.clone();
        assert!(intent_from_wire(wire).is_err());
        let mut wire = intent_to_wire(&native).unwrap();
        wire.mode = 99;
        assert!(intent_from_wire(wire).is_err());
        let identity = w::HandoffPayloadIdentity {
            digest: native.intent_digest.to_string(),
            length: 8 * 1024 * 1024 + 1,
        };
        assert!(descriptor_from_wire(w::HandoffPayloadDescriptor {
            payload: Some(w::handoff_payload_descriptor::Payload::Chunk(identity)),
        })
        .is_err());
        assert!(frame_from_wire(w::HandoffPayloadFrame {
            content: vec![1; 1024 * 1024 + 1],
            end: true,
            total_length: 1024 * 1024 + 1,
        })
        .is_err());
        assert!(frame_from_wire(w::HandoffPayloadFrame {
            content: vec![],
            end: false,
            total_length: 1,
        })
        .is_err());
        assert!(needs_from_wire(w::HandoffNeedsRequest {
            operation: native.operation.to_string(),
            cursor: None,
            limit: u32::MAX,
        })
        .is_err());
    }
}

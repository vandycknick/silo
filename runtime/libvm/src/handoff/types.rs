//! Immutable identities and durable decisions for stopped handoff.
use crate::storage::identity::ObjectDigest;
use crate::MachineId;
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! identity {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(try_from = "uuid::Uuid", into = "uuid::Uuid")]
        pub struct $name(uuid::Uuid);
        impl $name {
            pub fn new(value: uuid::Uuid) -> Result<Self, HandoffError> {
                if value.is_nil() {
                    return Err(HandoffError::InvalidIdentity);
                }
                Ok(Self(value))
            }
            pub fn as_uuid(self) -> uuid::Uuid {
                self.0
            }
        }
        impl TryFrom<uuid::Uuid> for $name {
            type Error = HandoffError;
            fn try_from(value: uuid::Uuid) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
        impl From<$name> for uuid::Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}
identity!(RuntimeId);
identity!(OperationId);
identity!(CaptureId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct OwnershipEpoch(u64);
impl OwnershipEpoch {
    pub fn new(value: u64) -> Result<Self, HandoffError> {
        if value > crate::storage::limits::Resource::JsonInteger.maximum() {
            return Err(HandoffError::EpochExhausted);
        }
        Ok(Self(value))
    }
    pub fn get(self) -> u64 {
        self.0
    }
    pub fn next(self) -> Result<Self, HandoffError> {
        Self::new(self.0.checked_add(1).ok_or(HandoffError::EpochExhausted)?)
    }
}
impl TryFrom<u64> for OwnershipEpoch {
    type Error = HandoffError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<OwnershipEpoch> for u64 {
    fn from(value: OwnershipEpoch) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffMode {
    Fork,
    Relocate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffIntent {
    pub operation: OperationId,
    pub mode: HandoffMode,
    pub source_runtime: RuntimeId,
    pub destination_runtime: RuntimeId,
    pub source_machine: MachineId,
    pub destination_machine: MachineId,
    pub from_epoch: OwnershipEpoch,
    pub intent_digest: ObjectDigest,
    pub approved_plan_digest: ObjectDigest,
}
impl HandoffIntent {
    pub fn validate(&self) -> Result<(), HandoffError> {
        if self.source_runtime == self.destination_runtime {
            return Err(HandoffError::SameRuntime);
        }
        if uuid::Uuid::from(self.source_machine).is_nil()
            || uuid::Uuid::from(self.destination_machine).is_nil()
        {
            return Err(HandoffError::InvalidIdentity);
        }
        match self.mode {
            HandoffMode::Relocate if self.source_machine != self.destination_machine => {
                return Err(HandoffError::ReceiptMismatch)
            }
            HandoffMode::Fork if self.source_machine == self.destination_machine => {
                return Err(HandoffError::ReceiptMismatch)
            }
            _ => {}
        }
        self.destination_epoch()?;
        Ok(())
    }
    pub fn destination_epoch(&self) -> Result<OwnershipEpoch, HandoffError> {
        match self.mode {
            HandoffMode::Relocate => self.from_epoch.next(),
            HandoffMode::Fork => OwnershipEpoch::new(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffBinding {
    pub intent: HandoffIntent,
    pub capture: CaptureId,
    pub capture_manifest_digest: ObjectDigest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedReceipt {
    pub binding: HandoffBinding,
    pub receipt_id: uuid::Uuid,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitAuthorization {
    pub prepared: PreparedReceipt,
    pub nonce: uuid::Uuid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffDecision {
    Committed,
    Aborted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalReceipt {
    pub intent: HandoffIntent,
    pub binding: Option<HandoffBinding>,
    pub decision: HandoffDecision,
    pub authorization: Option<CommitAuthorization>,
}
impl TerminalReceipt {
    pub fn validate(&self) -> Result<(), HandoffError> {
        self.intent.validate()?;
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.intent != self.intent)
        {
            return Err(HandoffError::ReceiptMismatch);
        }
        match (&self.decision, &self.authorization) {
            (HandoffDecision::Committed, Some(auth))
                if !auth.nonce.is_nil()
                    && !auth.prepared.receipt_id.is_nil()
                    && self.binding.as_ref() == Some(&auth.prepared.binding) =>
            {
                Ok(())
            }
            (HandoffDecision::Aborted, None) => Ok(()),
            _ => Err(HandoffError::ReceiptMismatch),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffRole {
    Source,
    Destination,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandoffPhase {
    Intended,
    Reserved,
    Captured,
    Fenced,
    Receiving,
    Prepared,
    Committed,
    Aborted,
}
impl HandoffPhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandoffRecord {
    pub schema: u32,
    pub role: HandoffRole,
    pub intent: HandoffIntent,
    pub binding: Option<HandoffBinding>,
    pub phase: HandoffPhase,
    pub prepared: Option<PreparedReceipt>,
    pub authorization: Option<CommitAuthorization>,
    pub terminal: Option<TerminalReceipt>,
}
impl HandoffRecord {
    pub fn decode(json: &str) -> Result<Self, crate::LibVmError> {
        crate::storage::limits::Resource::MetadataPageBytes
            .check(json.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        let record: Self =
            serde_json::from_str(json).map_err(|error| crate::LibVmError::StateDecode {
                field: "handoff_operation.record_json",
                message: error.to_string(),
            })?;
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<(), HandoffError> {
        self.intent.validate()?;
        let source = self.role == HandoffRole::Source;
        if self.schema != 1
            || !matches!(
                (self.role, self.phase),
                (
                    HandoffRole::Source,
                    HandoffPhase::Intended
                        | HandoffPhase::Reserved
                        | HandoffPhase::Captured
                        | HandoffPhase::Fenced
                        | HandoffPhase::Committed
                        | HandoffPhase::Aborted
                ) | (
                    HandoffRole::Destination,
                    HandoffPhase::Receiving
                        | HandoffPhase::Prepared
                        | HandoffPhase::Committed
                        | HandoffPhase::Aborted
                )
            )
        {
            return Err(HandoffError::InvalidState);
        }
        if self
            .binding
            .as_ref()
            .is_some_and(|value| value.intent != self.intent)
            || self.prepared.as_ref().is_some_and(|value| {
                value.receipt_id.is_nil() || self.binding.as_ref() != Some(&value.binding)
            })
            || self.authorization.as_ref().is_some_and(|value| {
                value.nonce.is_nil() || self.prepared.as_ref() != Some(&value.prepared)
            })
        {
            return Err(HandoffError::ReceiptMismatch);
        }
        if matches!(
            self.phase,
            HandoffPhase::Captured
                | HandoffPhase::Fenced
                | HandoffPhase::Prepared
                | HandoffPhase::Committed
        ) && self.binding.is_none()
            || matches!(
                self.phase,
                HandoffPhase::Prepared | HandoffPhase::Fenced | HandoffPhase::Committed
            ) && self.prepared.is_none()
            || matches!(self.phase, HandoffPhase::Fenced | HandoffPhase::Committed)
                && self.authorization.is_none()
            || self.phase.is_terminal() != self.terminal.is_some()
            || source
                && matches!(self.phase, HandoffPhase::Intended | HandoffPhase::Reserved)
                && self.binding.is_some()
        {
            return Err(HandoffError::InvalidState);
        }
        if matches!(
            self.phase,
            HandoffPhase::Intended
                | HandoffPhase::Reserved
                | HandoffPhase::Captured
                | HandoffPhase::Receiving
        ) && (self.prepared.is_some() || self.authorization.is_some())
            || self.phase == HandoffPhase::Prepared && self.authorization.is_some()
        {
            return Err(HandoffError::InvalidState);
        }
        if let Some(terminal) = &self.terminal {
            terminal.validate()?;
            if terminal
                .binding
                .as_ref()
                .is_some_and(|binding| self.binding.as_ref() != Some(binding))
                || terminal.decision == HandoffDecision::Committed
                    && (terminal.authorization != self.authorization
                        || terminal.binding != self.binding)
            {
                return Err(HandoffError::ReceiptMismatch);
            }
            if terminal.intent != self.intent
                || terminal.decision
                    != if self.phase == HandoffPhase::Committed {
                        HandoffDecision::Committed
                    } else {
                        HandoffDecision::Aborted
                    }
            {
                return Err(HandoffError::ReceiptMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoffError {
    #[error("handoff identity must be a nonnil UUID")]
    InvalidIdentity,
    #[error("source and destination runtime are identical")]
    SameRuntime,
    #[error("handoff belongs to a different runtime")]
    WrongRuntime,
    #[error("ownership epoch is exhausted or outside the JSON integer range")]
    EpochExhausted,
    #[error("operation {operation} has conflicting immutable intent")]
    OperationConflict { operation: OperationId },
    #[error("handoff receipt does not match the immutable binding")]
    ReceiptMismatch,
    #[error("handoff transition is not valid in the current durable state")]
    InvalidState,
    #[error("unknown handoff operation {operation}")]
    UnknownOperation { operation: OperationId },
    #[error("operation {operation} was durably aborted")]
    OperationAborted { operation: OperationId },
    #[error("machine {machine} is reserved by {operation}")]
    OwnershipReserved {
        machine: MachineId,
        operation: OperationId,
    },
    #[error("machine {machine} is fenced by {operation}")]
    OwnershipFenced {
        machine: MachineId,
        operation: OperationId,
    },
    #[error("machine {machine} was relocated by {operation}")]
    MachineRelocated {
        machine: MachineId,
        operation: OperationId,
    },
    #[error("destination machine {machine} already exists")]
    MachineIdConflict { machine: MachineId },
    #[error("prior owner of machine {machine} does not record this returning successor")]
    ReturnOwnerMismatch { machine: MachineId },
    #[error("source ownership or storage changed since admission")]
    AdmissionStale,
}

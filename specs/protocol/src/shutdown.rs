//! Current run-bound storage shutdown contracts. Diagnostics never confer authority.
use std::fmt;

use prost::Message;
use serde::{Deserialize, Serialize};
use vm_spec::{BlockId, DiskFormat, DiskGeometry, DiskRole};

use crate::v1;

pub const VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub const MAX_MANIFEST_ENTRIES: usize = 64;
pub const MAX_HOLDER_BYTES: usize = 4 * 1024;

pub fn validate_uuid(value: &str) -> Result<(), String> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| "invalid UUID".to_owned())?;
    let mut canonical = [0; 36];
    if parsed.is_nil() || parsed.hyphenated().encode_lower(&mut canonical) != value {
        return Err("UUID must be nonnil, lowercase and canonical".into());
    }
    Ok(())
}

fn diagnostic(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > MAX_DIAGNOSTIC_BYTES || value.contains('\0') {
        return Err("diagnostic must be nonempty, NUL-free and at most 4096 bytes".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageShutdownContext {
    pub version: u32,
    pub machine_id: String,
    pub run_id: String,
    pub manifest: StorageManifest,
}

impl StorageShutdownContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported shutdown context version".into());
        }
        validate_uuid(&self.machine_id)?;
        validate_uuid(&self.run_id)?;
        self.manifest.validate()
    }

    pub fn validate_binding(&self, machine_id: &str, run_id: &str) -> Result<(), String> {
        self.validate()?;
        if self.machine_id != machine_id || self.run_id != run_id {
            return Err("shutdown context belongs to another run".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageManifest {
    Complete { attachments: Vec<StorageAttachment> },
    Unsupported { reason: String },
}

impl Default for StorageManifest {
    fn default() -> Self {
        Self::Unsupported {
            reason: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StorageAttachment {
    Block {
        block_id: BlockId,
        role: DiskRole,
        format: DiskFormat,
        geometry: DiskGeometry,
        read_only: bool,
        exclusive_writer: bool,
    },
    Share {
        tag: String,
        read_only: bool,
    },
}

impl StorageManifest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Unsupported { reason } => diagnostic(reason)?,
            Self::Complete { attachments } => {
                if attachments.is_empty() || attachments.len() > MAX_MANIFEST_ENTRIES {
                    return Err("complete manifest requires 1..=64 attachments".into());
                }
                for (index, attachment) in attachments.iter().enumerate() {
                    match attachment {
                        StorageAttachment::Block {
                            block_id,
                            role,
                            format,
                            geometry,
                            read_only,
                            ..
                        } => {
                            vm_spec::Disk::validate_attachment(
                                *role, *format, *geometry, block_id, *read_only,
                            )?;
                        }
                        StorageAttachment::Share { tag, .. } => {
                            if tag.trim().is_empty()
                                || tag.len() > vm_spec::VIRTIOFS_TAG_MAX_BYTES
                                || tag.contains('\0')
                            {
                                return Err("invalid manifest share tag".into());
                            }
                            if attachments[..index].iter().any(|other| {
                                matches!(other,
                                StorageAttachment::Share { tag: other, .. } if other == tag)
                            }) {
                                return Err("duplicate manifest share tag".into());
                            }
                        }
                    }
                }
                vm_spec::Storage::validate_attachment_sequence(attachments.iter().filter_map(
                    |attachment| match attachment {
                        StorageAttachment::Block { role, block_id, .. } => Some((*role, block_id)),
                        StorageAttachment::Share { .. } => None,
                    },
                ))?;
            }
        }
        // Count serialized bytes without allocating a second manifest buffer.
        let mut counter = ByteCounter(0);
        serde_json::to_writer(&mut counter, self).map_err(|error| error.to_string())?;
        if counter.0 > MAX_FRAME_BYTES {
            return Err("manifest exceeds 64 KiB".into());
        }
        Ok(())
    }

    /// Inherent exclusions only. Guest mount/writer coverage must also be proven.
    pub fn unsupported_reason(&self) -> Option<String> {
        match self {
            Self::Unsupported { reason } => Some(reason.clone()),
            Self::Complete { attachments } => {
                attachments.iter().find_map(|attachment| match attachment {
                    StorageAttachment::Share {
                        read_only: false, ..
                    } => Some("writable directory shares lack all-writer coverage".into()),
                    StorageAttachment::Block {
                        read_only: false,
                        exclusive_writer: false,
                        ..
                    } => Some("external/concurrent block writers are not excluded".into()),
                    _ => None,
                })
            }
        }
    }
}

struct ByteCounter(usize);
impl std::io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn manifest_from_json(bytes: &[u8]) -> Result<StorageManifest, String> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("manifest exceeds 64 KiB".into());
    }
    let manifest: StorageManifest =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    manifest.validate()?;
    Ok(manifest)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShutdownIdentity {
    pub version: u32,
    pub machine_id: String,
    pub run_id: String,
    pub shutdown_id: String,
    pub agent_instance_id: String,
    pub boot_id: String,
}

impl ShutdownIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported shutdown frame version".into());
        }
        for identity in [
            &self.machine_id,
            &self.run_id,
            &self.shutdown_id,
            &self.agent_instance_id,
            &self.boot_id,
        ] {
            validate_uuid(identity)?;
        }
        Ok(())
    }
    pub fn validate_context(&self, context: &StorageShutdownContext) -> Result<(), String> {
        self.validate()?;
        context.validate_binding(&self.machine_id, &self.run_id)
    }
}

fn required<T>(value: Option<T>, field: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("missing shutdown field {field}"))
}

pub fn identity_from_proto(
    identity: &v1::ShutdownFrameIdentity,
) -> Result<ShutdownIdentity, String> {
    let value = ShutdownIdentity {
        version: required(identity.version, "version")?,
        machine_id: required(identity.machine_id.clone(), "machine_id")?,
        run_id: required(identity.run_id.clone(), "run_id")?,
        shutdown_id: required(identity.shutdown_id.clone(), "shutdown_id")?,
        agent_instance_id: required(identity.agent_instance_id.clone(), "agent_instance_id")?,
        boot_id: required(identity.boot_id.clone(), "boot_id")?,
    };
    value.validate()?;
    Ok(value)
}

pub fn identity_to_proto(identity: &ShutdownIdentity) -> v1::ShutdownFrameIdentity {
    v1::ShutdownFrameIdentity {
        version: Some(identity.version),
        machine_id: Some(identity.machine_id.clone()),
        run_id: Some(identity.run_id.clone()),
        shutdown_id: Some(identity.shutdown_id.clone()),
        agent_instance_id: Some(identity.agent_instance_id.clone()),
        boot_id: Some(identity.boot_id.clone()),
    }
}

fn validate_frame_identity(
    identity: Option<&v1::ShutdownFrameIdentity>,
    expected: &ShutdownIdentity,
) -> Result<(), String> {
    expected.validate()?;
    let identity = required(identity, "identity")?;
    // Validate without constructing/cloning a second domain identity.
    if identity.version != Some(VERSION)
        || identity.machine_id.as_deref() != Some(expected.machine_id.as_str())
        || identity.run_id.as_deref() != Some(expected.run_id.as_str())
        || identity.shutdown_id.as_deref() != Some(expected.shutdown_id.as_str())
        || identity.agent_instance_id.as_deref() != Some(expected.agent_instance_id.as_str())
        || identity.boot_id.as_deref() != Some(expected.boot_id.as_str())
    {
        return Err("shutdown frame identity mismatch or missing required identity".into());
    }
    Ok(())
}

pub fn validate_host_frame(
    frame: &v1::ShutdownHostFrame,
    expected: &ShutdownIdentity,
) -> Result<(), String> {
    if frame.encoded_len() > MAX_FRAME_BYTES {
        return Err("shutdown frame exceeds 64 KiB".into());
    }
    validate_frame_identity(frame.identity.as_ref(), expected)?;
    match required(frame.payload.as_ref(), "payload")? {
        v1::shutdown_host_frame::Payload::Begin(begin) => {
            manifest_from_json(&begin.manifest_json)?;
        }
        v1::shutdown_host_frame::Payload::AllowPoweroff(_) => {}
    }
    Ok(())
}

pub fn validate_guest_frame(
    frame: &v1::ShutdownGuestFrame,
    expected: &ShutdownIdentity,
) -> Result<(), String> {
    if frame.encoded_len() > MAX_FRAME_BYTES {
        return Err("shutdown frame exceeds 64 KiB".into());
    }
    validate_frame_identity(frame.identity.as_ref(), expected)?;
    match required(frame.payload.as_ref(), "payload")? {
        v1::shutdown_guest_frame::Payload::Accepted(accepted) => {
            if accepted.authority != Some(v1::ShutdownAuthority::AgentPid1 as i32) {
                return Err("unsupported or absent shutdown authority".into());
            }
        }
        v1::shutdown_guest_frame::Payload::Completed(completed) => {
            match required(completed.result, "result")? {
                result if result == v1::ShutdownCompletionResult::Succeeded as i32 => {
                    if completed.diagnostic.is_some() {
                        return Err("success cannot carry diagnostic".into());
                    }
                }
                result
                    if result == v1::ShutdownCompletionResult::Failed as i32
                        || result == v1::ShutdownCompletionResult::Unsupported as i32 =>
                {
                    diagnostic(required(completed.diagnostic.as_deref(), "diagnostic")?)?;
                }
                _ => return Err("unknown or unspecified shutdown result".into()),
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageShutdown {
    pub version: u32,
    pub guest_protocol_completed: bool,
    pub host_flush_completed: bool,
    pub attachments_closed: bool,
}
impl StorageShutdown {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported storage shutdown version".into());
        }
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        self.version == VERSION
            && self.guest_protocol_completed
            && self.host_flush_completed
            && self.attachments_closed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageEvidence {
    Missing,
    Valid(StorageShutdown),
    UnsupportedVersion(u64),
    Malformed(String),
}

pub fn decode_evidence(raw: Option<&str>) -> StorageEvidence {
    let Some(raw) = raw else {
        return StorageEvidence::Missing;
    };
    if raw.len() > MAX_FRAME_BYTES {
        return StorageEvidence::Malformed("evidence exceeds 64 KiB".into());
    }
    // Parse the complete required shape before inspecting version. This retains
    // duplicate/missing-field errors instead of erasing them through Value.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Evidence {
        version: u64,
        guest_protocol_completed: bool,
        host_flush_completed: bool,
        attachments_closed: bool,
    }
    match serde_json::from_str::<Evidence>(raw) {
        Ok(value) if value.version != u64::from(VERSION) => {
            StorageEvidence::UnsupportedVersion(value.version)
        }
        Ok(value) => StorageEvidence::Valid(StorageShutdown {
            version: VERSION,
            guest_protocol_completed: value.guest_protocol_completed,
            host_flush_completed: value.host_flush_completed,
            attachments_closed: value.attachments_closed,
        }),
        Err(error) => StorageEvidence::Malformed(error.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitOutcome {
    Clean,
    Error,
    Forced,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageStopOutcome {
    Clean,
    Forced,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentExitRecord {
    pub machine_id: String,
    pub run_id: String,
    pub pid: i32,
    pub exited_at: i64,
    pub outcome: ExitOutcome,
    pub error: Option<String>,
    pub backend: Option<serde_json::Value>,
    pub storage_shutdown: StorageEvidence,
}
impl CurrentExitRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > crate::STRUCTURED_16_MIB {
            return Err("exit record exceeds 16 MiB".into());
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Outer {
            machine_id: String,
            run_id: String,
            pid: i32,
            exited_at: i64,
            outcome: ExitOutcome,
            error: Option<String>,
            backend: Option<UniqueJson>,
            storage_shutdown: Option<Box<serde_json::value::RawValue>>,
        }
        let outer: Outer = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        validate_uuid(&outer.machine_id)?;
        validate_uuid(&outer.run_id)?;
        if outer.pid <= 0 || outer.exited_at < 0 {
            return Err("invalid exit process/time".into());
        }
        if outer
            .backend
            .as_ref()
            .is_some_and(|backend| !backend.0.is_object())
        {
            return Err("exit backend diagnostic must be an object".into());
        }
        Ok(Self {
            machine_id: outer.machine_id,
            run_id: outer.run_id,
            pid: outer.pid,
            exited_at: outer.exited_at,
            outcome: outer.outcome,
            error: outer.error,
            backend: outer.backend.map(|value| value.0),
            storage_shutdown: decode_evidence(
                outer.storage_shutdown.as_deref().map(|value| value.get()),
            ),
        })
    }
    /// The caller MUST independently establish terminal holders before using this.
    pub fn classify(&self, expected_machine_id: &str, expected_run_id: &str) -> StorageStopOutcome {
        if validate_uuid(expected_machine_id).is_err()
            || validate_uuid(expected_run_id).is_err()
            || self.machine_id != expected_machine_id
            || self.run_id != expected_run_id
        {
            return StorageStopOutcome::Unknown;
        }
        match self.outcome {
            ExitOutcome::Error | ExitOutcome::Forced => StorageStopOutcome::Forced,
            ExitOutcome::Clean => match &self.storage_shutdown {
                StorageEvidence::Valid(value) if value.is_complete() => StorageStopOutcome::Clean,
                _ => StorageStopOutcome::Unknown,
            },
        }
    }
}

// Diagnostics are opaque but duplicate JSON members still make the outer record
// ambiguous. Raw evidence is intentionally decoded independently above.
struct UniqueJson(serde_json::Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueJson(number.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueJson(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate diagnostic key"));
                    }
                    values.insert(key, map.next_value::<UniqueJson>()?.0);
                }
                Ok(UniqueJson(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageLeaseBinding {
    pub operation_id: String,
    pub file_device: u64,
    pub file_inode: u64,
}
impl StorageLeaseBinding {
    pub fn validate(&self) -> Result<(), String> {
        validate_uuid(&self.operation_id)?;
        if self.file_inode == 0 {
            return Err("lease inode must be nonzero".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerStorageContext {
    pub version: u32,
    pub machine_id: String,
    pub run_id: String,
    pub storage_lease: StorageLeaseBinding,
    pub raw_handles: Vec<RawHandleBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawHandleBinding {
    pub disk_index: u32,
    pub child_fd: i32,
    pub device: u64,
    pub inode: u64,
    pub length_bytes: u64,
    pub read_only: bool,
}
impl WorkerStorageContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err("unsupported worker storage version".into());
        }
        validate_uuid(&self.machine_id)?;
        validate_uuid(&self.run_id)?;
        self.storage_lease.validate()?;
        if self.raw_handles.len() > 16 {
            return Err("at most sixteen Raw handles".into());
        }
        let mut last_index = None;
        for (index, handle) in self.raw_handles.iter().enumerate() {
            if handle.child_fd != 9 + index as i32
                || handle.disk_index >= 16
                || last_index.is_some_and(|last| handle.disk_index <= last)
                || handle.inode == 0
                || handle.length_bytes == 0
                || handle.length_bytes > 1 << 40
                || !handle.length_bytes.is_multiple_of(512)
            {
                return Err("invalid Raw handle binding/order".into());
            }
            last_index = Some(handle.disk_index);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageHolderRole {
    Monitor,
    KrunWorker,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageHolder {
    pub role: StorageHolderRole,
    pub pid: u32,
    pub started_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageHolderRecord {
    pub schema_version: u32,
    pub machine_id: String,
    pub run_id: String,
    pub operation_id: String,
    pub holders: Vec<StorageHolder>,
}
impl StorageHolderRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != VERSION {
            return Err("unsupported storage holder schema".into());
        }
        for identity in [&self.machine_id, &self.run_id, &self.operation_id] {
            validate_uuid(identity)?;
        }
        if self.holders.is_empty()
            || self.holders.len() > 2
            || self
                .holders
                .iter()
                .filter(|holder| holder.role == StorageHolderRole::Monitor)
                .count()
                != 1
        {
            return Err("holder topology requires one monitor and optional worker".into());
        }
        for (index, holder) in self.holders.iter().enumerate() {
            if holder.pid == 0
                || holder.pid > i32::MAX as u32
                || holder.started_at == 0
                || self.holders[..index]
                    .iter()
                    .any(|other| other.role == holder.role || other.pid == holder.pid)
            {
                return Err("invalid or duplicate storage holder".into());
            }
        }
        Ok(())
    }
    pub fn validate_binding(
        &self,
        machine_id: &str,
        run_id: &str,
        operation_id: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.machine_id != machine_id
            || self.run_id != run_id
            || self.operation_id != operation_id
        {
            return Err("storage holder belongs to another operation/run".into());
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_HOLDER_BYTES {
            return Err("storage holder exceeds 4 KiB".into());
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        record.validate()?;
        Ok(record)
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_HOLDER_BYTES {
            return Err("storage holder exceeds 4 KiB".into());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::shutdown::*;
    use prost::Message;

    const MACHINE: &str = "11111111-1111-4111-8111-111111111111";
    const RUN: &str = "22222222-2222-4222-8222-222222222222";
    const ATTEMPT: &str = "33333333-3333-4333-8333-333333333333";
    const AGENT: &str = "44444444-4444-4444-8444-444444444444";
    const BOOT: &str = "55555555-5555-4555-8555-555555555555";

    fn identity() -> ShutdownIdentity {
        ShutdownIdentity {
            version: VERSION,
            machine_id: MACHINE.into(),
            run_id: RUN.into(),
            shutdown_id: ATTEMPT.into(),
            agent_instance_id: AGENT.into(),
            boot_id: BOOT.into(),
        }
    }

    fn root() -> StorageAttachment {
        StorageAttachment::Block {
            block_id: BlockId::new("root").unwrap(),
            role: DiskRole::Root,
            format: DiskFormat::Raw,
            geometry: DiskGeometry {
                length: 64 << 20,
                logical_sector_size: 512,
            },
            read_only: false,
            exclusive_writer: true,
        }
    }

    fn manifest() -> StorageManifest {
        StorageManifest::Complete {
            attachments: vec![root()],
        }
    }

    fn exit(outcome: &str, evidence: Option<&str>) -> String {
        let evidence = evidence
            .map(|raw| format!(",\"storageShutdown\":{raw}"))
            .unwrap_or_default();
        format!(
            r#"{{"machineId":"{MACHINE}","runId":"{RUN}","pid":12,"exitedAt":100,"outcome":"{outcome}"{evidence}}}"#
        )
    }

    #[test]
    fn exact_run_and_independent_fact_classification_matrix() {
        for outcome in ["clean", "forced", "error"] {
            for mask in 0..8 {
                let evidence = StorageShutdown {
                    version: VERSION,
                    guest_protocol_completed: mask & 1 != 0,
                    host_flush_completed: mask & 2 != 0,
                    attachments_closed: mask & 4 != 0,
                };
                let raw = serde_json::to_string(&evidence).unwrap();
                let record =
                    CurrentExitRecord::decode(exit(outcome, Some(&raw)).as_bytes()).unwrap();
                let expected = if outcome != "clean" {
                    StorageStopOutcome::Forced
                } else if mask == 7 {
                    StorageStopOutcome::Clean
                } else {
                    StorageStopOutcome::Unknown
                };
                assert_eq!(record.classify(MACHINE, RUN), expected);
                assert_eq!(
                    record.classify(MACHINE, ATTEMPT),
                    StorageStopOutcome::Unknown
                );
                assert_eq!(record.classify(AGENT, RUN), StorageStopOutcome::Unknown);
                assert_eq!(record.classify("", RUN), StorageStopOutcome::Unknown);
                assert_eq!(record.storage_shutdown, StorageEvidence::Valid(evidence));
            }
        }
    }

    #[test]
    fn malformed_evidence_never_overrides_valid_forced_outcome() {
        let malformed = [
            "null",
            "false",
            "{}",
            "[]",
            r#"{"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true}"#,
            r#"{"version":1,"guestProtocolCompleted":"true","hostFlushCompleted":true,"attachmentsClosed":true}"#,
            r#"{"version":1,"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}"#,
            r#"{"version":1,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true,"other":true}"#,
            r#"{"version":2,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}"#,
        ];
        for raw in malformed.into_iter().map(Some).chain([None]) {
            for outcome in ["forced", "error", "clean"] {
                let record = CurrentExitRecord::decode(exit(outcome, raw).as_bytes()).unwrap();
                assert_eq!(
                    record.classify(MACHINE, RUN),
                    if outcome == "clean" {
                        StorageStopOutcome::Unknown
                    } else {
                        StorageStopOutcome::Forced
                    },
                    "{raw:?}"
                );
            }
        }
        assert_eq!(
            decode_evidence(Some(
                r#"{"version":2,"guestProtocolCompleted":true,"hostFlushCompleted":true,"attachmentsClosed":true}"#
            )),
            StorageEvidence::UnsupportedVersion(2)
        );
        assert!(matches!(
            decode_evidence(Some(&" ".repeat(MAX_FRAME_BYTES + 1))),
            StorageEvidence::Malformed(_)
        ));
    }

    #[test]
    fn malformed_outer_record_has_no_trusted_outcome() {
        for raw in [
            exit("bogus", None),
            exit("forced", None).replace("\"pid\":12", "\"pid\":0"),
            exit("forced", None).replace("\"pid\":12", "\"pid\":12,\"pid\":12"),
            exit("forced", None).replace(
                "\"outcome\":\"forced\"",
                "\"outcome\":\"forced\",\"outcome\":\"clean\"",
            ),
            exit("forced", None).replace(MACHINE, "not-a-uuid"),
            exit("forced", None).replace("\"pid\":12,", ""),
            exit("forced", None).replace(
                "\"outcome\":\"forced\"",
                "\"outcome\":\"forced\",\"backend\":{\"a\":1,\"a\":2}",
            ),
            format!("{} trailing", exit("forced", None)),
        ] {
            assert!(CurrentExitRecord::decode(raw.as_bytes()).is_err(), "{raw}");
        }
    }

    #[test]
    fn required_evidence_members_and_duplicate_keys_are_rejected() {
        let value = serde_json::to_value(StorageShutdown {
            version: 1,
            guest_protocol_completed: true,
            host_flush_completed: true,
            attachments_closed: true,
        })
        .unwrap();
        for key in [
            "version",
            "guestProtocolCompleted",
            "hostFlushCompleted",
            "attachmentsClosed",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(matches!(
                decode_evidence(Some(&missing.to_string())),
                StorageEvidence::Malformed(_)
            ));
            let raw = value.to_string();
            let duplicated = format!("{{\"{key}\":{},{}", value[key], &raw[1..]);
            assert!(matches!(
                decode_evidence(Some(&duplicated)),
                StorageEvidence::Malformed(_)
            ));
        }
    }

    #[test]
    fn identity_presence_canonical_form_and_wrong_attempt_are_rejected() {
        let expected = identity();
        let wire = identity_to_proto(&expected);
        assert_eq!(identity_from_proto(&wire).unwrap(), expected);
        for raw in [
            "",
            "11111111111141118111111111111111",
            "00000000-0000-0000-0000-000000000000",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "11111111-1111-4111-8111-111111111111 ",
        ] {
            assert!(validate_uuid(raw).is_err(), "{raw}");
        }
        let mut missing = wire.clone();
        missing.version = None;
        assert!(identity_from_proto(&missing).is_err());
        for index in 0..5 {
            let mut missing = wire.clone();
            match index {
                0 => missing.machine_id = None,
                1 => missing.run_id = None,
                2 => missing.shutdown_id = None,
                3 => missing.agent_instance_id = None,
                _ => missing.boot_id = None,
            }
            assert!(identity_from_proto(&missing).is_err());
        }
        let mut frame = v1::ShutdownHostFrame {
            identity: Some(wire),
            payload: Some(v1::shutdown_host_frame::Payload::AllowPoweroff(
                v1::ShutdownAllowPoweroff {},
            )),
        };
        validate_host_frame(&frame, &expected).unwrap();
        frame.identity.as_mut().unwrap().shutdown_id = Some(AGENT.into());
        assert!(validate_host_frame(&frame, &expected).is_err());
        let context = StorageShutdownContext {
            version: 1,
            machine_id: MACHINE.into(),
            run_id: ATTEMPT.into(),
            manifest: manifest(),
        };
        assert!(expected.validate_context(&context).is_err());
    }

    #[test]
    fn manifest_complete_bounds_and_explicit_unsupported_coverage() {
        let mut attachments = vec![root()];
        for index in 0..63 {
            attachments.push(StorageAttachment::Share {
                tag: format!("share-{index}"),
                read_only: true,
            });
        }
        let complete = StorageManifest::Complete {
            attachments: attachments.clone(),
        };
        complete.validate().unwrap();
        assert_eq!(complete.unsupported_reason(), None);
        attachments.push(StorageAttachment::Share {
            tag: "overflow".into(),
            read_only: true,
        });
        assert!(StorageManifest::Complete { attachments }
            .validate()
            .is_err());
        let mut attachments = vec![root()];
        for index in 0..15 {
            attachments.push(StorageAttachment::Block {
                block_id: BlockId::new(format!("data-{index}")).unwrap(),
                role: DiskRole::Data,
                format: DiskFormat::Raw,
                geometry: DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
                read_only: false,
                exclusive_writer: true,
            });
        }
        StorageManifest::Complete {
            attachments: attachments.clone(),
        }
        .validate()
        .unwrap();
        attachments.push(StorageAttachment::Block {
            block_id: BlockId::new("data-overflow").unwrap(),
            role: DiskRole::Data,
            format: DiskFormat::Raw,
            geometry: DiskGeometry {
                length: 512,
                logical_sector_size: 512,
            },
            read_only: true,
            exclusive_writer: true,
        });
        assert!(StorageManifest::Complete { attachments }
            .validate()
            .is_err());
        for attachment in [
            StorageAttachment::Share {
                tag: "writable".into(),
                read_only: false,
            },
            StorageAttachment::Block {
                block_id: BlockId::new("external").unwrap(),
                role: DiskRole::Data,
                format: DiskFormat::Raw,
                geometry: DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
                read_only: false,
                exclusive_writer: false,
            },
        ] {
            let value = StorageManifest::Complete {
                attachments: vec![root(), attachment],
            };
            value.validate().unwrap();
            assert!(value.unsupported_reason().is_some());
        }
        let unsupported = StorageManifest::Unsupported {
            reason: "inventory cannot be represented".into(),
        };
        unsupported.validate().unwrap();
        assert!(unsupported.unsupported_reason().is_some());
        assert!(StorageManifest::Complete {
            attachments: vec![]
        }
        .validate()
        .is_err());
        assert!(StorageManifest::Complete {
            attachments: vec![root(), root()]
        }
        .validate()
        .is_err());
    }

    #[test]
    fn manifest_required_fields_duplicates_and_byte_bounds() {
        let value = serde_json::to_value(manifest()).unwrap();
        for key in [
            "blockId",
            "role",
            "format",
            "geometry",
            "readOnly",
            "exclusiveWriter",
        ] {
            let mut missing = value.clone();
            missing["attachments"][0]
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                manifest_from_json(missing.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
        let raw = serde_json::to_string(&manifest()).unwrap();
        let padded = format!("{raw}{}", " ".repeat(MAX_FRAME_BYTES - raw.len()));
        manifest_from_json(padded.as_bytes()).unwrap();
        assert!(manifest_from_json(format!("{padded} ").as_bytes()).is_err());
        assert!(
            manifest_from_json(br#"{"kind":"complete","attachments":[],"attachments":[]}"#)
                .is_err()
        );
        assert!(
            manifest_from_json(br#"{"kind":"unsupported","reason":"x","reason":"y"}"#).is_err()
        );
        assert!(manifest_from_json(br#"{"kind":"unsupported","reason":""}"#).is_err());
    }

    #[test]
    fn manifest_share_tags_preserve_projected_mount_semantics() {
        for tag in [
            "space tag".to_owned(),
            "共有 データ".to_owned(),
            "a".repeat(36),
            "é".repeat(18),
        ] {
            let value = StorageManifest::Complete {
                attachments: vec![
                    root(),
                    StorageAttachment::Share {
                        tag: tag.clone(),
                        read_only: true,
                    },
                ],
            };
            value.validate().unwrap();
            let bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(manifest_from_json(&bytes).unwrap(), value);
            let projected = vm_spec::project_mounts(&[vm_spec::Mount {
                source: "/fixture".into(),
                tag: tag.clone(),
                read_only: true,
            }])
            .unwrap();
            assert_eq!(projected[0].backend_tag, tag);
        }
        for tag in [
            "".to_owned(),
            " \t".to_owned(),
            "has\0nul".to_owned(),
            "a".repeat(37),
            "é".repeat(19),
        ] {
            let value = StorageManifest::Complete {
                attachments: vec![
                    root(),
                    StorageAttachment::Share {
                        tag,
                        read_only: true,
                    },
                ],
            };
            assert!(value.validate().is_err());
            assert!(manifest_from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn encoded_frame_accepts_exact_64kib_and_rejects_next_byte() {
        let expected = identity();
        let mut bytes = serde_json::to_vec(&manifest()).unwrap();
        bytes.resize(MAX_FRAME_BYTES - 512, b' ');
        let mut frame = v1::ShutdownHostFrame {
            identity: Some(identity_to_proto(&expected)),
            payload: Some(v1::shutdown_host_frame::Payload::Begin(v1::ShutdownBegin {
                manifest_json: bytes,
            })),
        };
        let padding = MAX_FRAME_BYTES - frame.encoded_len();
        let Some(v1::shutdown_host_frame::Payload::Begin(begin)) = frame.payload.as_mut() else {
            panic!("begin")
        };
        begin
            .manifest_json
            .resize(begin.manifest_json.len() + padding, b' ');
        assert_eq!(frame.encoded_len(), MAX_FRAME_BYTES);
        validate_host_frame(&frame, &expected).unwrap();
        let Some(v1::shutdown_host_frame::Payload::Begin(begin)) = frame.payload.as_mut() else {
            panic!("begin")
        };
        begin.manifest_json.push(b' ');
        assert_eq!(frame.encoded_len(), MAX_FRAME_BYTES + 1);
        assert!(validate_host_frame(&frame, &expected).is_err());
    }

    #[test]
    fn frame_payloads_diagnostic_bound_and_unsupported_result() {
        let expected = identity();
        let completed = |result, diagnostic| v1::ShutdownGuestFrame {
            identity: Some(identity_to_proto(&expected)),
            payload: Some(v1::shutdown_guest_frame::Payload::Completed(
                v1::ShutdownCompleted { result, diagnostic },
            )),
        };
        for result in [
            v1::ShutdownCompletionResult::Failed,
            v1::ShutdownCompletionResult::Unsupported,
        ] {
            validate_guest_frame(
                &completed(Some(result as i32), Some("x".repeat(MAX_DIAGNOSTIC_BYTES))),
                &expected,
            )
            .unwrap();
            assert!(validate_guest_frame(
                &completed(
                    Some(result as i32),
                    Some("x".repeat(MAX_DIAGNOSTIC_BYTES + 1))
                ),
                &expected
            )
            .is_err());
            assert!(
                validate_guest_frame(&completed(Some(result as i32), None), &expected).is_err()
            );
        }
        validate_guest_frame(
            &completed(Some(v1::ShutdownCompletionResult::Succeeded as i32), None),
            &expected,
        )
        .unwrap();
        assert!(validate_guest_frame(
            &completed(
                Some(v1::ShutdownCompletionResult::Succeeded as i32),
                Some("error".into())
            ),
            &expected
        )
        .is_err());
        assert!(validate_guest_frame(&completed(None, None), &expected).is_err());
        assert!(validate_guest_frame(&completed(Some(99), None), &expected).is_err());
        let accepted = |authority| v1::ShutdownGuestFrame {
            identity: Some(identity_to_proto(&expected)),
            payload: Some(v1::shutdown_guest_frame::Payload::Accepted(
                v1::ShutdownAccepted { authority },
            )),
        };
        validate_guest_frame(
            &accepted(Some(v1::ShutdownAuthority::AgentPid1 as i32)),
            &expected,
        )
        .unwrap();
        assert!(validate_guest_frame(&accepted(None), &expected).is_err());
        assert!(validate_guest_frame(&accepted(Some(0)), &expected).is_err());
        let frame = v1::ShutdownHostFrame {
            identity: Some(identity_to_proto(&expected)),
            payload: Some(v1::shutdown_host_frame::Payload::Begin(v1::ShutdownBegin {
                manifest_json: vec![b' '; MAX_FRAME_BYTES],
            })),
        };
        assert!(frame.encoded_len() > MAX_FRAME_BYTES);
        assert!(validate_host_frame(&frame, &expected).is_err());
        assert!(validate_host_frame(
            &v1::ShutdownHostFrame {
                identity: Some(identity_to_proto(&expected)),
                payload: None
            },
            &expected
        )
        .is_err());
    }

    #[test]
    fn holder_lease_and_worker_metadata_are_required_and_run_bound() {
        let mut record = StorageHolderRecord {
            schema_version: VERSION,
            machine_id: MACHINE.into(),
            run_id: RUN.into(),
            operation_id: ATTEMPT.into(),
            holders: vec![StorageHolder {
                role: StorageHolderRole::Monitor,
                pid: 10,
                started_at: 20,
            }],
        };
        assert_eq!(
            StorageHolderRecord::decode(&record.encode().unwrap()).unwrap(),
            record
        );
        record.holders.push(StorageHolder {
            role: StorageHolderRole::KrunWorker,
            pid: 11,
            started_at: 21,
        });
        record.validate_binding(MACHINE, RUN, ATTEMPT).unwrap();
        assert!(record.validate_binding(MACHINE, BOOT, ATTEMPT).is_err());
        assert!(record.validate_binding(MACHINE, RUN, BOOT).is_err());
        for key in [
            "schemaVersion",
            "machineId",
            "runId",
            "operationId",
            "holders",
        ] {
            let mut value = serde_json::to_value(&record).unwrap();
            value.as_object_mut().unwrap().remove(key);
            assert!(
                StorageHolderRecord::decode(value.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
        for key in ["role", "pid", "startedAt"] {
            let mut value = serde_json::to_value(&record).unwrap();
            value["holders"][0].as_object_mut().unwrap().remove(key);
            assert!(
                StorageHolderRecord::decode(value.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
        let raw = String::from_utf8(record.encode().unwrap()).unwrap();
        let duplicated = raw.replace(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
        );
        assert!(StorageHolderRecord::decode(duplicated.as_bytes()).is_err());
        let unsupported = raw.replace("\"schemaVersion\":1", "\"schemaVersion\":2");
        assert!(StorageHolderRecord::decode(unsupported.as_bytes()).is_err());
        let bytes = record.encode().unwrap();
        let mut padded = bytes.clone();
        padded.resize(MAX_HOLDER_BYTES, b' ');
        StorageHolderRecord::decode(&padded).unwrap();
        padded.push(b' ');
        assert!(StorageHolderRecord::decode(&padded).is_err());
        record.holders[1].role = StorageHolderRole::Monitor;
        assert!(record.validate().is_err());
        record.holders[1].role = StorageHolderRole::KrunWorker;
        record.holders[1].pid = 10;
        assert!(record.validate().is_err());
        let binding = StorageLeaseBinding {
            operation_id: ATTEMPT.into(),
            file_device: 0,
            file_inode: 1,
        };
        binding.validate().unwrap();
        for key in ["operationId", "fileDevice", "fileInode"] {
            let mut value = serde_json::to_value(&binding).unwrap();
            value.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<StorageLeaseBinding>(value).is_err());
        }
        let mut worker = WorkerStorageContext {
            version: VERSION,
            machine_id: MACHINE.into(),
            run_id: RUN.into(),
            storage_lease: binding,
            raw_handles: vec![RawHandleBinding {
                disk_index: 0,
                child_fd: 9,
                device: 1,
                inode: 2,
                length_bytes: 512,
                read_only: false,
            }],
        };
        worker.validate().unwrap();
        for key in [
            "version",
            "machineId",
            "runId",
            "storageLease",
            "rawHandles",
        ] {
            let mut value = serde_json::to_value(&worker).unwrap();
            value.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<WorkerStorageContext>(value).is_err());
        }
        worker.raw_handles.push(RawHandleBinding {
            disk_index: 1,
            child_fd: 10,
            device: 1,
            inode: 2,
            length_bytes: 512,
            read_only: true,
        });
        // Existing disk semantics permit repeated backing paths/inodes.
        worker.validate().unwrap();
        worker.raw_handles[0].child_fd = 8;
        assert!(worker.validate().is_err());
        assert!(WorkerStorageContext::default().validate().is_err());
    }
}

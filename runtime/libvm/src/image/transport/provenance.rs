//! Portable capture provenance: exact transported seal and historical plan.
//! Verification proves the record-to-inventory and immutable-input
//! relationships of one checkpoint. It never
//! proves that a trusted monitor performed the cut, and it never creates local
//! capture, launch, pause or reservation authority.
use std::collections::BTreeMap;
use std::fs::File;
use std::sync::Arc;

use oci::vm_artifact::wire::{canonical_bytes, decode_record, strict_value, RecordRef};
use serde::{Deserialize, Serialize};
use vm_spec::capture::{
    CaptureConfiguration, CaptureEvidence, CaptureInventoryEntry, CapturePlan, CaptureRole,
    Sha256Digest,
};
use vm_spec::DiskFormat;

use crate::image::transport::blobs::invalid;
use crate::storage::identity::{ObjectDigest, SnapshotId, StreamId};
use crate::store::models::snapshot::{
    SnapshotCaptureKind, SnapshotExecution, SnapshotRecord, SnapshotRootProfile,
};
use crate::LibVmError;

const FIXED_ROLES: [CaptureRole; 5] = [
    CaptureRole::Execution,
    CaptureRole::Devices,
    CaptureRole::Ram,
    CaptureRole::Layout,
    CaptureRole::RamMap,
];
const MAX_LAYOUT_BYTES: u64 = 65536;

fn failure(message: impl std::fmt::Display) -> LibVmError {
    invalid("capture provenance", message)
}

/// `portable-capture-provenance`, direct record JSON in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PortableCaptureProvenanceV1 {
    pub(crate) schema: u32,
    pub(crate) kind: String,
    pub(crate) snapshot: SnapshotId,
    pub(crate) evidence: RecordRef,
    pub(crate) disks: Vec<PortableCaptureDisk>,
    pub(crate) plan: CapturePlan,
}

/// One sealed writable attachment. The role is an opaque identifier from the
/// closed capture role set, never a destination path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PortableCaptureDisk {
    pub(crate) role: CaptureRole,
    pub(crate) attachment_index: u32,
}

impl PortableCaptureProvenanceV1 {
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, LibVmError> {
        Ok(canonical_bytes(self)?)
    }

    /// Strict closed decoding of exactly canonical bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LibVmError> {
        let wrapper: Self = decode_record(bytes)?;
        if wrapper.schema != 1 || wrapper.kind != "portable-capture-provenance" {
            return Err(failure("unsupported provenance schema or kind"));
        }
        if wrapper.canonical_bytes()? != bytes {
            return Err(failure("provenance record is not canonical"));
        }
        Ok(wrapper)
    }
}

/// Structurally verified portable seal of one live checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct PortableBinding {
    pub(crate) wrapper_digest: ObjectDigest,
    pub(crate) evidence: CaptureEvidence,
    pub(crate) evidence_digest: ObjectDigest,
    pub(crate) configuration: CaptureConfiguration,
    /// Writable disk seal rows paired with the semantic stream they seal.
    pub(crate) disks: Vec<(CaptureInventoryEntry, StreamId)>,
}

/// Decode evidence with the stricter portable view: the local decoder accepts
/// additive top-level fields, a transported seal must be the closed schema.
pub(crate) fn decode_portable_evidence(bytes: &[u8]) -> Result<CaptureEvidence, LibVmError> {
    let evidence = CaptureEvidence::decode(bytes).map_err(failure)?;
    let value = strict_value(bytes)?;
    if serde_json::to_value(&evidence).map_err(failure)? != value {
        return Err(failure(
            "capture evidence carries unknown or omitted portable fields",
        ));
    }
    if !evidence.is_sealed() {
        return Err(failure("capture evidence is not a coherent seal"));
    }
    Ok(evidence)
}

fn execution(record: &SnapshotRecord) -> Result<&SnapshotExecution, LibVmError> {
    match &record.capture {
        SnapshotCaptureKind::LiveExecution { execution } => Ok(execution),
        SnapshotCaptureKind::StoppedStorage { .. } => Err(failure(
            "portable capture provenance requires a live-execution checkpoint",
        )),
    }
}

/// The semantic stream sealed for each writable attachment, in attachment order.
fn writable_streams(
    record: &SnapshotRecord,
    configuration: &CaptureConfiguration,
) -> Result<Vec<(u32, StreamId, u64)>, LibVmError> {
    let mut sealed = Vec::new();
    for (index, attachment) in configuration.attachments.iter().enumerate() {
        if attachment.read_only {
            continue;
        }
        let index = u32::try_from(index).map_err(failure)?;
        if attachment.format != DiskFormat::Raw {
            return Err(failure("sealed writable attachment is not raw"));
        }
        let stream = match (&record.root.profile, index) {
            (SnapshotRootProfile::OpaqueRaw, 0) | (SnapshotRootProfile::LinuxOverlay { .. }, 1) => {
                &record.root.stream
            }
            (SnapshotRootProfile::LinuxOverlay { .. }, 0) => {
                return Err(failure("overlay lower cannot be a sealed writable disk"))
            }
            _ => {
                let disk = record
                    .disks
                    .iter()
                    .find(|disk| disk.order == index)
                    .ok_or_else(|| failure("writable attachment has no included stream"))?;
                if !disk.writable {
                    return Err(failure(
                        "read-only included disk is substituted for a writable seal",
                    ));
                }
                &disk.content
            }
        };
        if stream.length != attachment.geometry.length {
            return Err(failure(
                "sealed attachment geometry differs from its stream",
            ));
        }
        sealed.push((index, stream.stream, stream.length));
    }
    Ok(sealed)
}

/// Reconstruct the portable wrapper for a local seal from the checkpoint's own
/// configuration: fixed state roles followed by every writable attachment and
/// its chunk map in order. Disks are paired by position, never by
/// byte equality, which is ambiguous for identical disks.
pub(crate) fn build_local(
    record: &SnapshotRecord,
    snapshot: SnapshotId,
    evidence_bytes: &[u8],
    plan: &CapturePlan,
) -> Result<(PortableBinding, Vec<u8>), LibVmError> {
    let evidence = decode_portable_evidence(evidence_bytes)?;
    let configuration =
        CaptureConfiguration::from_spec(&record.configuration.spec).map_err(failure)?;
    let sealed = writable_streams(record, &configuration)?;
    let disks = evidence
        .inventory
        .get(FIXED_ROLES.len()..)
        .ok_or_else(|| failure("capture inventory lacks its fixed state roles"))?;
    if disks.len() != sealed.len() * 2 {
        return Err(failure(
            "capture inventory disk count differs from writable attachments",
        ));
    }
    let wrapper = PortableCaptureProvenanceV1 {
        schema: 1,
        kind: "portable-capture-provenance".into(),
        snapshot,
        evidence: RecordRef::of_bytes(evidence_bytes),
        plan: plan.clone(),
        disks: disks
            .chunks_exact(2)
            .zip(&sealed)
            .map(|(entries, (index, _, _))| PortableCaptureDisk {
                role: entries[0].role.clone(),
                attachment_index: *index,
            })
            .collect(),
    };
    let bytes = wrapper.canonical_bytes()?;
    let binding = verify_portable_binding(record, snapshot, &bytes, evidence_bytes)?;
    Ok((binding, bytes))
}

/// Every structural relation between the canonical checkpoint, the wrapper and
/// the exact evidence bytes. Byte measurements are [`verify_portable_capture`].
pub(crate) fn verify_portable_binding(
    record: &SnapshotRecord,
    snapshot: SnapshotId,
    wrapper_bytes: &[u8],
    evidence_bytes: &[u8],
) -> Result<PortableBinding, LibVmError> {
    let execution = execution(record)?;
    let wrapper = PortableCaptureProvenanceV1::decode(wrapper_bytes)?;
    if wrapper.snapshot != snapshot {
        return Err(failure("provenance names a different snapshot"));
    }
    if wrapper.evidence != RecordRef::of_bytes(evidence_bytes) {
        return Err(failure(
            "provenance evidence reference differs from its bytes",
        ));
    }
    let evidence = decode_portable_evidence(evidence_bytes)?;
    let memory = evidence
        .memory
        .as_ref()
        .ok_or_else(|| failure("coherent seal lacks RAM evidence"))?;
    let configuration =
        CaptureConfiguration::from_spec(&record.configuration.spec).map_err(failure)?;
    wrapper.plan.validate().map_err(failure)?;
    let plan_bytes = wrapper.plan.canonical_bytes().map_err(failure)?;
    evidence
        .validate_against_plan(&wrapper.plan, &Sha256Digest::of_bytes(&plan_bytes))
        .map_err(failure)?;
    if wrapper.plan.configuration != configuration {
        return Err(failure(
            "retained capture plan differs from checkpoint configuration",
        ));
    }
    for input in &wrapper.plan.read_only_inputs {
        let identity = match (&record.root.profile, input.attachment_index) {
            (SnapshotRootProfile::LinuxOverlay { lower, .. }, 0) => lower.result.to_string(),
            _ => record
                .disks
                .iter()
                .find(|disk| disk.order == input.attachment_index && !disk.writable)
                .ok_or_else(|| {
                    failure("capture read-only input has no immutable checkpoint binding")
                })?
                .content
                .stream
                .to_string(),
        };
        if input.identity != identity {
            return Err(failure(
                "captured immutable input differs from the checkpoint graph",
            ));
        }
    }
    let digest = configuration.digest().map_err(failure)?;
    if evidence.configuration_digest != digest || memory.binding.topology != digest {
        return Err(failure(
            "captured configuration differs from the checkpoint configuration",
        ));
    }
    if memory.ram_stream.as_bytes() != execution.memory.stream.as_bytes()
        || memory.packed_length != execution.memory.length
    {
        return Err(failure(
            "RAM stream or packed length differs from the checkpoint",
        ));
    }
    let profile = &execution.compatibility_profile;
    let pins = [
        (
            memory.binding.live_state_schema == profile.live_state_schema,
            "live state schema",
        ),
        (
            memory.binding.architecture == profile.architecture,
            "architecture",
        ),
        (
            same(&memory.binding.profile, &profile.profile),
            "CPU/clock profile",
        ),
        (
            same(&memory.binding.topology, &profile.topology),
            "device topology",
        ),
        (
            same(&memory.binding.ram_layout, &profile.ram_layout),
            "RAM layout",
        ),
        (profile.ram_layout == execution.layout, "RAM layout object"),
    ];
    if let Some((_, pin)) = pins.iter().find(|(matches, _)| !matches) {
        return Err(failure(format!(
            "compatibility pin {pin} differs from the capture binding"
        )));
    }
    let inventory = &evidence.inventory;
    if inventory.len() < FIXED_ROLES.len()
        || inventory
            .iter()
            .zip(FIXED_ROLES.iter())
            .any(|(entry, role)| &entry.role != role)
    {
        return Err(failure(
            "capture inventory does not begin with execution, devices, RAM and layout",
        ));
    }
    let sealed = writable_streams(record, &configuration)?;
    let disk_entries = &inventory[FIXED_ROLES.len()..];
    if disk_entries.len() != sealed.len() * 2 || wrapper.disks.len() != sealed.len() {
        return Err(failure(
            "sealed disk inventory omits or adds a writable attachment",
        ));
    }
    let mut disks = Vec::with_capacity(sealed.len());
    for ((entries, declared), (index, stream, length)) in disk_entries
        .chunks_exact(2)
        .zip(&wrapper.disks)
        .zip(&sealed)
    {
        let entry = &entries[0];
        let CaptureRole::Disk(name) = &entry.role else {
            return Err(failure("sealed disk inventory has a non-disk role"));
        };
        if entries[1].role != CaptureRole::DiskMap(name.clone())
            || declared.role != entry.role
            || declared.attachment_index != *index
            || entry.length != *length
            || entry.identity != Some(Sha256Digest::from_bytes(*stream.as_bytes()))
        {
            return Err(failure(
                "sealed disk role, attachment order or length differs from the checkpoint",
            ));
        }
        disks.push((entry.clone(), *stream));
    }
    Ok(PortableBinding {
        wrapper_digest: ObjectDigest::of_bytes(wrapper_bytes),
        evidence,
        evidence_digest: ObjectDigest::of_bytes(evidence_bytes),
        configuration,
        disks,
    })
}

/// Authenticated decoded chunk maps measured during ingest, never copied from
/// the capture inventory. Whole-byte transport digests are checked separately.
pub(crate) struct MeasuredCapture<'a> {
    pub(crate) stream_maps: &'a BTreeMap<StreamId, Arc<crate::storage::stream::StreamMap>>,
    pub(crate) layout: &'a [u8],
    pub(crate) execution: &'a File,
    pub(crate) devices: &'a File,
}

/// Byte-level checks of section 4.2 items 5 to 7, then the native header
/// correlation shared with local capture.
pub(crate) fn verify_portable_capture(
    record: &SnapshotRecord,
    binding: &PortableBinding,
    measured: &MeasuredCapture<'_>,
) -> Result<(), LibVmError> {
    let execution = execution(record)?;
    let memory = binding
        .evidence
        .memory
        .as_ref()
        .ok_or_else(|| failure("coherent seal lacks RAM evidence"))?;
    let inventory = &binding.evidence.inventory;
    let stream_map = |stream: &StreamId| {
        measured
            .stream_maps
            .get(stream)
            .ok_or_else(|| failure(format!("stream {stream} was not measured")))
    };
    for (entry, stream) in &binding.disks {
        let map = stream_map(stream)?;
        if map.id() != *stream
            || map.length() != entry.length
            || entry.identity != Some(Sha256Digest::from_bytes(*map.id().as_bytes()))
        {
            return Err(failure(format!(
                "writable disk {} stream identity differs from its seal",
                entry.role.relative_path()
            )));
        }
        let CaptureRole::Disk(name) = &entry.role else {
            return Err(failure("sealed disk binding has a non-disk role"));
        };
        let map_bytes = map.canonical_bytes()?;
        let map_entry = inventory
            .iter()
            .find(|entry| entry.role == CaptureRole::DiskMap(name.clone()))
            .ok_or_else(|| failure("sealed disk lacks its chunk map"))?;
        if map_entry.length != map_bytes.len() as u64
            || map_entry.sha256 != Some(Sha256Digest::of_bytes(&map_bytes))
        {
            return Err(failure("complete disk map differs from its seal"));
        }
    }
    let state = |role: CaptureRole| {
        inventory
            .iter()
            .find(|entry| entry.role == role)
            .ok_or_else(|| failure("capture inventory lacks a fixed role"))
    };
    let ram = state(CaptureRole::Ram)?;
    let ram_map = stream_map(&execution.memory.stream)?;
    if ram_map.id() != execution.memory.stream
        || ram.identity != Some(Sha256Digest::from_bytes(*ram_map.id().as_bytes()))
        || ram.length != execution.memory.length
    {
        return Err(failure(
            "RAM stream identity or length differs from its seal",
        ));
    }
    let map = state(CaptureRole::RamMap)?;
    let map_bytes = ram_map.canonical_bytes()?;
    if ram_map.id() != execution.memory.stream
        || map.length != map_bytes.len() as u64
        || map.sha256 != Some(Sha256Digest::of_bytes(&map_bytes))
    {
        return Err(failure("complete RAM map differs from its seal"));
    }
    for (role, object, length, maximum) in [
        (
            CaptureRole::Execution,
            execution.execution,
            measured.execution.metadata()?.len(),
            crate::store::capture_native::MAX_EXECUTION_BYTES,
        ),
        (
            CaptureRole::Devices,
            execution.devices,
            measured.devices.metadata()?.len(),
            crate::store::capture_native::MAX_DEVICE_BYTES,
        ),
        (
            CaptureRole::Layout,
            execution.layout,
            measured.layout.len() as u64,
            MAX_LAYOUT_BYTES,
        ),
    ] {
        let entry = state(role)?;
        if entry.sha256 != Some(Sha256Digest::from_bytes(*object.as_bytes()))
            || entry.length != length
            || length > maximum
        {
            return Err(failure(format!(
                "{} object differs from its seal",
                entry.role.relative_path()
            )));
        }
    }
    if ObjectDigest::of_bytes(measured.layout) != execution.layout {
        return Err(failure(
            "RAM layout bytes differ from the checkpoint layout",
        ));
    }
    let layout = crate::store::capture::validate_layout(
        measured.layout,
        memory,
        binding.configuration.ram_bytes(),
    )?;
    crate::store::capture_native::verify_headers(
        measured.execution,
        measured.devices,
        &memory.binding,
        &binding.configuration,
        &layout,
    )
}

fn same(left: &Sha256Digest, right: &ObjectDigest) -> bool {
    left.as_bytes() == right.as_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use vm_spec::capture::{CaptureEvidence, Sha256Digest};

    use crate::image::transport::provenance::{
        build_local, verify_portable_binding, verify_portable_capture, MeasuredCapture,
        PortableCaptureProvenanceV1,
    };
    use crate::storage::identity::{SnapshotId, StreamId};
    use crate::storage::pool::StoragePool;
    use crate::storage::stream::{Chunk, StreamMap};
    use crate::store::models::snapshot::{SnapshotCaptureKind, SnapshotRecord};
    use crate::store::snapshot_store::SnapshotRef;

    /// A real locally sealed and published live checkpoint.
    struct Published {
        _fixture: crate::store::capture::tests::Fixture,
        pool: StoragePool,
        record: SnapshotRecord,
        id: SnapshotId,
        evidence: Vec<u8>,
        plan: vm_spec::capture::CapturePlan,
    }

    async fn published() -> Published {
        let fixture = crate::store::capture::tests::fixture().await;
        let (directory, _) = crate::store::capture::tests::seal(&fixture);
        let info = fixture
            .snapshots
            .publish_capture(
                fixture.reservation.record.capture_id,
                directory.path(),
                fixture.reservation.record.alias.clone(),
            )
            .await
            .unwrap();
        let consumer = fixture
            .snapshots
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        let pool = StoragePool::open(fixture.snapshots.store.images_path()).unwrap();
        let evidence = pool
            .read_object(&info.provenance[0].evidence_digest, 1 << 20)
            .unwrap();
        Published {
            record: consumer.record.clone(),
            plan: fixture.reservation.record.plan.clone(),
            _fixture: fixture,
            pool,
            id: info.id,
            evidence,
        }
    }

    fn reencode(evidence: &[u8], change: impl FnOnce(&mut CaptureEvidence)) -> Vec<u8> {
        let mut decoded = CaptureEvidence::decode(evidence).unwrap();
        change(&mut decoded);
        decoded.canonical_bytes().unwrap()
    }

    fn rewrap(wrapper: &[u8], change: impl FnOnce(&mut PortableCaptureProvenanceV1)) -> Vec<u8> {
        let mut decoded = PortableCaptureProvenanceV1::decode(wrapper).unwrap();
        change(&mut decoded);
        decoded.canonical_bytes().unwrap()
    }

    #[tokio::test]
    async fn local_seal_rebinds_to_a_closed_portable_wrapper_with_its_exact_plan() {
        let published = published().await;
        let (binding, wrapper) = build_local(
            &published.record,
            published.id,
            &published.evidence,
            &published.plan,
        )
        .unwrap();
        assert_eq!(
            binding.wrapper_digest,
            crate::storage::identity::ObjectDigest::of_bytes(&wrapper)
        );
        let decoded = PortableCaptureProvenanceV1::decode(&wrapper).unwrap();
        assert_eq!(decoded.snapshot, published.id);
        assert_eq!(decoded.plan, published.plan);
        assert_eq!(
            Sha256Digest::of_bytes(&decoded.plan.canonical_bytes().unwrap()),
            binding.evidence.request_digest,
        );
        assert_eq!(decoded.disks.len(), binding.disks.len());
        assert!(!decoded.disks.is_empty());
        assert_eq!(
            verify_portable_binding(
                &published.record,
                published.id,
                &wrapper,
                &published.evidence
            )
            .unwrap()
            .evidence,
            binding.evidence
        );
        // Non-canonical spelling of an otherwise identical wrapper is refused.
        let mut spaced = wrapper.clone();
        spaced.insert(1, b' ');
        assert!(verify_portable_binding(
            &published.record,
            published.id,
            &spaced,
            &published.evidence
        )
        .is_err());
    }

    #[tokio::test]
    async fn provenance_matrix_rejects_every_contradiction() {
        let published = published().await;
        let record = &published.record;
        let id = published.id;
        let (_, wrapper) = build_local(record, id, &published.evidence, &published.plan).unwrap();
        let other = SnapshotId::from_sha256([7; 32]);
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            (
                "other snapshot",
                rewrap(&wrapper, |wrapper| wrapper.snapshot = other),
                published.evidence.clone(),
            ),
            (
                "attachment index",
                rewrap(&wrapper, |wrapper| wrapper.disks[0].attachment_index += 1),
                published.evidence.clone(),
            ),
            (
                "dropped writable disk",
                rewrap(&wrapper, |wrapper| {
                    wrapper.disks.pop();
                }),
                published.evidence.clone(),
            ),
            (
                "fixed role substituted for a disk",
                rewrap(&wrapper, |wrapper| {
                    wrapper.disks[0].role = vm_spec::capture::CaptureRole::Ram
                }),
                published.evidence.clone(),
            ),
            (
                "evidence reference",
                wrapper.clone(),
                reencode(&published.evidence, |evidence| {
                    evidence.completed_at_unix_ms += 1
                }),
            ),
            (
                "different historical plan",
                rewrap(&wrapper, |wrapper| {
                    wrapper.plan.dirty_crossover_percent += 1
                }),
                published.evidence.clone(),
            ),
            (
                "foreign immutable input",
                rewrap(&wrapper, |wrapper| {
                    wrapper
                        .plan
                        .read_only_inputs
                        .push(vm_spec::capture::CaptureReadOnlyInput {
                            attachment_index: 0,
                            block_id: wrapper.plan.configuration.attachments[0].block_id.clone(),
                            identity: format!("sha256:{}", "ab".repeat(32)),
                        });
                }),
                published.evidence.clone(),
            ),
        ];
        for (case, wrapper, evidence) in cases {
            assert!(
                verify_portable_binding(record, id, &wrapper, &evidence).is_err(),
                "{case}"
            );
        }
        // Evidence changes rebuilt through a matching wrapper still fail.
        let evidence_cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "configuration digest",
                reencode(&published.evidence, |evidence| {
                    evidence.configuration_digest = Sha256Digest::of_bytes(b"other")
                }),
            ),
            (
                "native producer pin",
                reencode(&published.evidence, |evidence| {
                    if let Some(memory) = &mut evidence.memory {
                        memory.binding.live_state_schema.push('x');
                    }
                }),
            ),
            (
                "RAM stream",
                reencode(&published.evidence, |evidence| {
                    if let Some(memory) = &mut evidence.memory {
                        memory.ram_stream = Sha256Digest::of_bytes(b"other ram");
                    }
                }),
            ),
            (
                "inventory order",
                reencode(&published.evidence, |evidence| {
                    evidence.inventory.swap(0, 1)
                }),
            ),
            (
                "failed seal",
                reencode(&published.evidence, |evidence| {
                    evidence.vcpus_paused = false
                }),
            ),
        ];
        for (case, evidence) in evidence_cases {
            assert!(
                build_local(record, id, &evidence, &published.plan).is_err(),
                "{case}"
            );
        }
        // The local decoder admits additive fields; a portable seal does not,
        // and its bytes are never stripped into a different blob.
        let mut value: serde_json::Value = serde_json::from_slice(&published.evidence).unwrap();
        value["futureField"] = serde_json::json!(true);
        let extended = serde_json::to_vec(&value).unwrap();
        assert!(CaptureEvidence::decode(&extended).is_ok());
        assert!(build_local(record, id, &extended, &published.plan).is_err());
        // A stopped snapshot has no portable capture.
        let mut stopped = record.clone();
        stopped.capture = SnapshotCaptureKind::StoppedStorage {
            stop_outcome: crate::store::models::storage::StorageStopOutcome::Unknown,
        };
        assert!(build_local(&stopped, id, &published.evidence, &published.plan).is_err());
    }

    #[tokio::test]
    async fn stream_measurements_bind_disks_ram_layout_and_native_headers() {
        let published = published().await;
        let record = &published.record;
        let (binding, _) =
            build_local(record, published.id, &published.evidence, &published.plan).unwrap();
        let SnapshotCaptureKind::LiveExecution { execution } = &record.capture else {
            panic!("live checkpoint expected");
        };
        let mut maps = BTreeMap::new();
        for stream in record.streams() {
            let map = published.pool.verify_stream(&stream.stream).unwrap();
            maps.insert(stream.stream, Arc::new(map));
        }
        let layout = published
            .pool
            .read_object(&execution.layout, 65536)
            .unwrap();
        let execution_file = published.pool.verify_object(&execution.execution).unwrap();
        let devices_file = published.pool.verify_object(&execution.devices).unwrap();
        let measured = |maps: &BTreeMap<StreamId, Arc<StreamMap>>,
                        layout: &[u8],
                        swap: bool|
         -> Result<(), crate::LibVmError> {
            let (first, second) = if swap {
                (&devices_file, &execution_file)
            } else {
                (&execution_file, &devices_file)
            };
            verify_portable_capture(
                record,
                &binding,
                &MeasuredCapture {
                    stream_maps: maps,
                    layout,
                    execution: first,
                    devices: second,
                },
            )
        };
        measured(&maps, layout.as_slice(), false).unwrap();
        assert!(
            measured(&maps, layout.as_slice(), true).is_err(),
            "swapped state objects"
        );
        let wrong_map = |length: u64, bytes: &[u8]| {
            Arc::new(
                StreamMap::new(
                    length,
                    vec![
                        Chunk::Data(crate::storage::identity::ObjectDigest::of_bytes(bytes));
                        length.div_ceil(crate::storage::limits::CHUNK_SIZE as u64) as usize
                    ],
                )
                .unwrap(),
            )
        };
        let mut ram = maps.clone();
        ram.insert(
            execution.memory.stream,
            wrong_map(execution.memory.length, b"valid id, wrong bytes"),
        );
        assert!(
            measured(&ram, layout.as_slice(), false).is_err(),
            "RAM stream identity"
        );
        let mut disk = maps.clone();
        disk.insert(
            record.root.stream.stream,
            wrong_map(record.root.stream.length, b"other disk"),
        );
        assert!(
            measured(&disk, layout.as_slice(), false).is_err(),
            "writable disk stream identity"
        );
        let mut missing = maps.clone();
        missing.remove(&record.root.stream.stream);
        assert!(
            measured(&missing, layout.as_slice(), false).is_err(),
            "unmeasured disk"
        );
        let mut tampered = layout.clone();
        tampered.push(b' ');
        assert!(
            measured(&maps, tampered.as_slice(), false).is_err(),
            "layout bytes"
        );
    }
}

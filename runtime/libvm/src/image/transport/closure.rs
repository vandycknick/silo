//! One semantic closure for both directions. The VM config, the object table
//! and the stream table are projections of the exact canonical image or
//! snapshot record. Only table/provenance references are free; every other
//! config field and every closure row is derived here and compared, so a
//! config can never assert semantics that differ from its record.
use std::collections::BTreeMap;

use oci::changeset::model::{ContentDigest, StreamIdentity};
use oci::vm_artifact::wire::{
    self, ContentKind, ContentRef, ExecutionRequirements, GuestPlatform, MinimumCapabilities,
    PayloadMediaType, Purpose, RecordRef, VmArtifactConfigV1,
};

use crate::image::import_types::ManagedSourceId;
use crate::image::transport::blobs::invalid;
use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::limits::Resource;
use crate::store::models::image::{image_id, ImageRecord};
use crate::store::models::snapshot::{
    snapshot_id, SnapshotCaptureKind, SnapshotRecord, SnapshotRoot, SnapshotRootProfile,
    SnapshotStream,
};
use crate::store::models::storage::{BootBinding, BootProfile, GuestArchitecture};
use crate::LibVmError;

/// Native execution envelope constants accepted by the current header reader.
const EXECUTION_KIND: &str = "krun-v1";
const MAX_LAYOUT_BYTES: u64 = 65536;

pub(crate) fn content(digest: ObjectDigest) -> ContentDigest {
    ContentDigest::from_sha256(*digest.as_bytes())
}

pub(crate) fn object(digest: ContentDigest) -> ObjectDigest {
    ObjectDigest::from_sha256(*digest.as_bytes())
}

pub(crate) fn identity(stream: StreamId) -> StreamIdentity {
    StreamIdentity::from_sha256(*stream.as_bytes())
}

pub(crate) fn stream_id(stream: StreamIdentity) -> StreamId {
    StreamId::from_sha256(*stream.as_bytes())
}

/// Exact canonical local map root and page bytes of a decoded map: the
/// encoding the semantic record's `map`/`mapPages` digests name.
pub(crate) fn canonical_map_bytes(
    map: &crate::storage::stream::StreamMap,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), LibVmError> {
    let mut pages = Vec::new();
    let mut digests = Vec::new();
    for page in crate::storage::map::pages(map) {
        let page = page?;
        digests.push(ObjectDigest::of_bytes(&page));
        pages.push(page);
    }
    let root = crate::storage::map::StreamMapRoot::new(map, digests)?.encode()?;
    Ok((root, pages))
}

fn failure(message: impl std::fmt::Display) -> LibVmError {
    invalid("semantic closure", message)
}

/// How one closure object must travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectRole {
    /// Direct record JSON within the given role-specific byte bound.
    Record {
        maximum: u64,
    },
    Execution,
    Devices,
    /// Opaque boot bytes: always reconstructed through a chunk stream.
    Streamed,
    /// EROFS metadata keeps whole-byte object identity even when chunked.
    Fsmeta,
}

impl ObjectRole {
    pub(crate) fn media(self) -> Option<PayloadMediaType> {
        match self {
            Self::Record { .. } => Some(PayloadMediaType::Record),
            Self::Execution => Some(PayloadMediaType::Execution),
            Self::Devices => Some(PayloadMediaType::DeviceState),
            Self::Streamed | Self::Fsmeta => None,
        }
    }

    pub(crate) fn maximum(self) -> u64 {
        match self {
            Self::Record { maximum } => maximum,
            Self::Execution => crate::store::capture_native::MAX_EXECUTION_BYTES,
            Self::Devices => crate::store::capture_native::MAX_DEVICE_BYTES,
            Self::Streamed => wire::MAX_STREAM_BYTES,
            Self::Fsmeta => Resource::FsmetaBytes.maximum(),
        }
    }
}

/// Add a role, keeping the stricter bound for identical representations and
/// rejecting one digest that would need two different representations.
pub(crate) fn add_role(
    roles: &mut BTreeMap<ObjectDigest, ObjectRole>,
    digest: ObjectDigest,
    role: ObjectRole,
) -> Result<(), LibVmError> {
    match roles.get(&digest).copied() {
        None => {
            roles.insert(digest, role);
        }
        Some(ObjectRole::Record { maximum: existing }) => {
            let ObjectRole::Record { maximum } = role else {
                return Err(failure(format!(
                    "{digest} has contradictory representations"
                )));
            };
            roles.insert(
                digest,
                ObjectRole::Record {
                    maximum: existing.min(maximum),
                },
            );
        }
        Some(existing) if existing == role => {}
        Some(_) => {
            return Err(failure(format!(
                "{digest} has contradictory representations"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) enum SemanticRecord {
    Image(Box<ImageRecord>),
    Snapshot(Box<SnapshotRecord>),
}

/// An exact canonical semantic record with both of its identities.
#[derive(Debug, Clone)]
pub(crate) struct Semantic {
    pub(crate) record: SemanticRecord,
    pub(crate) bytes: Vec<u8>,
    pub(crate) digest: ObjectDigest,
    pub(crate) id: ManagedSourceId,
}

impl Semantic {
    pub(crate) fn image(record: ImageRecord) -> Result<Self, LibVmError> {
        let bytes = record.canonical_bytes()?;
        Ok(Self {
            id: ManagedSourceId::Image(image_id(&bytes)),
            digest: ObjectDigest::of_bytes(&bytes),
            record: SemanticRecord::Image(Box::new(record)),
            bytes,
        })
    }

    pub(crate) fn snapshot(record: SnapshotRecord) -> Result<Self, LibVmError> {
        let bytes = record.canonical_bytes()?;
        Ok(Self {
            id: ManagedSourceId::Snapshot(snapshot_id(&bytes)),
            digest: ObjectDigest::of_bytes(&bytes),
            record: SemanticRecord::Snapshot(Box::new(record)),
            bytes,
        })
    }

    /// Decode received bytes with the existing closed decoders and require
    /// them to be exactly canonical. Nothing is reserialized into a different
    /// identity.
    pub(crate) fn decode(kind: ContentKind, bytes: Vec<u8>) -> Result<Self, LibVmError> {
        let semantic = match kind {
            ContentKind::Image => Self::image(ImageRecord::decode(&bytes)?)?,
            ContentKind::Snapshot => Self::snapshot(SnapshotRecord::decode(&bytes)?)?,
        };
        if semantic.bytes != bytes {
            return Err(failure("semantic record bytes are not canonical"));
        }
        Ok(semantic)
    }

    pub(crate) fn snapshot_record(&self) -> Option<&SnapshotRecord> {
        match &self.record {
            SemanticRecord::Snapshot(record) => Some(record),
            SemanticRecord::Image(_) => None,
        }
    }

    pub(crate) fn live(&self) -> bool {
        matches!(
            self.snapshot_record().map(|record| &record.capture),
            Some(SnapshotCaptureKind::LiveExecution { .. })
        )
    }

    fn root(&self) -> &SnapshotRoot {
        match &self.record {
            SemanticRecord::Image(record) => &record.root,
            SemanticRecord::Snapshot(record) => &record.root,
        }
    }

    fn boot(&self) -> &BootProfile {
        match &self.record {
            SemanticRecord::Image(record) => &record.boot,
            SemanticRecord::Snapshot(record) => &record.boot,
        }
    }

    /// Ordered semantic streams with repeats; geometry stays in the record.
    pub(crate) fn streams(&self) -> Vec<&SnapshotStream> {
        match &self.record {
            SemanticRecord::Image(record) => {
                let mut streams = vec![&record.root.stream];
                if let SnapshotRootProfile::LinuxOverlay { lower, .. } = &record.root.profile {
                    streams.extend(lower.layers.iter().map(|layer| &layer.pack));
                }
                streams
            }
            SemanticRecord::Snapshot(record) => record.streams().collect(),
        }
    }

    pub(crate) fn composition(
        &self,
    ) -> Option<&crate::store::models::snapshot::SnapshotComposition> {
        match &self.root().profile {
            SnapshotRootProfile::LinuxOverlay { lower, .. } => Some(lower),
            SnapshotRootProfile::OpaqueRaw => None,
        }
    }

    /// Validate every retained edge and actual EROFS/body mapping before any
    /// graph is published or accepted. No encoder or source registry is used.
    pub(crate) fn authenticate_lower(
        &self,
        read_object: impl FnMut(&ObjectDigest, u64) -> Result<Vec<u8>, LibVmError>,
        open_object: impl FnMut(&ObjectDigest) -> Result<std::fs::File, LibVmError>,
        mut open_stream: impl FnMut(&SnapshotStream) -> Result<std::fs::File, LibVmError>,
    ) -> Result<(), LibVmError> {
        let SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            lower_filesystem_uuid,
            upper_uuid,
            ..
        } = &self.root().profile
        else {
            return Ok(());
        };
        let upper = open_stream(&self.root().stream)?;
        crate::machine::root_storage::validate_upper_file(
            &upper,
            *upper_uuid,
            self.root().geometry.length,
        )?;
        let authenticated = lower.authenticate(read_object)?;
        authenticated.check_root_claims(lower_geometry, *lower_filesystem_uuid)?;
        crate::machine::root_storage::check_lower_platform(
            &authenticated.recipe.platform,
            self.boot(),
        )?;
        authenticate_composition_bytes(lower, &authenticated, open_object, open_stream)
    }

    fn binding(&self) -> Result<(&BootBinding, GuestArchitecture, &str), LibVmError> {
        match self.boot() {
            BootProfile::LinuxDirect {
                binding: binding @ BootBinding::Pinned { abi, .. },
                kernel_architecture,
                ..
            } => Ok((binding, *kernel_architecture, abi)),
            _ => Err(failure(
                "only pinned Linux direct boot closures are portable in v1",
            )),
        }
    }

    pub(crate) fn content_ref(&self) -> ContentRef {
        let (kind, id) = match self.id {
            ManagedSourceId::Image(id) => (ContentKind::Image, *id.as_bytes()),
            ManagedSourceId::Snapshot(id) => (ContentKind::Snapshot, *id.as_bytes()),
        };
        ContentRef {
            kind,
            id: ContentDigest::from_sha256(id),
            record: RecordRef::of_bytes(&self.bytes),
        }
    }

    /// The complete VM config for the given table and provenance roots.
    pub(crate) fn config(
        &self,
        streams: RecordRef,
        objects: RecordRef,
        capture_provenance: Option<RecordRef>,
    ) -> Result<VmArtifactConfigV1, LibVmError> {
        let (_, kernel_architecture, abi) = self.binding()?;
        let (root_family, backend_requirement, storage_profile) = match &self.root().profile {
            SnapshotRootProfile::OpaqueRaw => (
                wire::RootFamily::OpaqueRaw,
                wire::BackendRequirement::RawBlock,
                wire::StorageProfile::OpaqueRawV1,
            ),
            SnapshotRootProfile::LinuxOverlay { .. } => (
                wire::RootFamily::LinuxOverlay,
                wire::BackendRequirement::KrunOverlay,
                wire::StorageProfile::LinuxErofsOverlayV1,
            ),
        };
        let (purpose, capture_kind, execution_requirements) = match &self.record {
            SemanticRecord::Image(_) => (Purpose::Image, None, None),
            SemanticRecord::Snapshot(record) => match &record.capture {
                SnapshotCaptureKind::StoppedStorage { .. } => (
                    Purpose::Checkpoint,
                    Some(wire::CaptureKind::StoppedStorage),
                    None,
                ),
                SnapshotCaptureKind::LiveExecution { execution } => {
                    let profile = &execution.compatibility_profile;
                    (
                        Purpose::Checkpoint,
                        Some(wire::CaptureKind::LiveExecution),
                        Some(ExecutionRequirements {
                            kind: EXECUTION_KIND.into(),
                            execution_version: 1,
                            execution_abi: 1,
                            device_version: 1,
                            compatibility_profile: wire::CompatibilityProfile {
                                native_producer: profile.native_producer.clone(),
                                silo_producer: content(profile.silo_producer),
                                profile: content(profile.profile),
                                topology: content(profile.topology),
                                ram_layout: content(profile.ram_layout),
                            },
                        }),
                    )
                }
            },
        };
        let config = VmArtifactConfigV1 {
            schema: 1,
            kind: "vm-artifact".into(),
            encoding: "silo-chunks-v1".into(),
            content: self.content_ref(),
            purpose,
            capture_kind,
            root_family,
            backend_requirement,
            guest_platform: GuestPlatform {
                os: wire::GuestOs::Linux,
                architecture: match kernel_architecture {
                    GuestArchitecture::Amd64 => wire::Architecture::Amd64,
                    GuestArchitecture::Arm64 => wire::Architecture::Arm64,
                },
            },
            minimum_capabilities: MinimumCapabilities {
                storage_profile,
                boot_abi: abi.to_owned(),
                live_restore: self.live(),
            },
            execution_requirements,
            streams,
            objects,
            capture_provenance,
        };
        config.validate()?;
        Ok(config)
    }

    /// Typed object closure of the record plus the selected provenance pair.
    /// Canonical maps of object-only streams are added by the caller once the
    /// streamed objects' maps are known.
    pub(crate) fn object_roles(
        &self,
        provenance: Option<(ObjectDigest, ObjectDigest)>,
    ) -> Result<BTreeMap<ObjectDigest, ObjectRole>, LibVmError> {
        if self.live() != provenance.is_some() {
            return Err(failure(
                "capture provenance is required exactly for live checkpoints",
            ));
        }
        let metadata = ObjectRole::Record {
            maximum: Resource::MetadataPageBytes.maximum(),
        };
        let mut roles = BTreeMap::new();
        add_role(&mut roles, self.digest, metadata)?;
        for stream in self.streams() {
            add_role(&mut roles, stream.map, metadata)?;
            for page in &stream.map_pages {
                add_role(&mut roles, *page, metadata)?;
            }
        }
        if let Some(lower) = self.composition() {
            for digest in [lower.record, lower.recipe] {
                add_role(&mut roles, digest, metadata)?;
            }
            add_role(&mut roles, lower.fsmeta, ObjectRole::Fsmeta)?;
            for layer in &lower.layers {
                for digest in [layer.recipe, layer.result, layer.index_root] {
                    add_role(&mut roles, digest, metadata)?;
                }
                for page in &layer.index_pages {
                    add_role(&mut roles, *page, metadata)?;
                }
            }
        }
        let (binding, _, _) = self.binding()?;
        let BootBinding::Pinned {
            kernel,
            base_initramfs,
            agent,
            ..
        } = binding
        else {
            return Err(failure("boot bundle is not pinned"));
        };
        add_role(&mut roles, binding.digest()?, metadata)?;
        for opaque in [Some(kernel), Some(base_initramfs), agent.as_ref()]
            .into_iter()
            .flatten()
        {
            add_role(&mut roles, *opaque, ObjectRole::Streamed)?;
        }
        if let Some(SnapshotRecord {
            capture: SnapshotCaptureKind::LiveExecution { execution },
            ..
        }) = self.snapshot_record()
        {
            add_role(
                &mut roles,
                execution.layout,
                ObjectRole::Record {
                    maximum: MAX_LAYOUT_BYTES,
                },
            )?;
            add_role(&mut roles, execution.execution, ObjectRole::Execution)?;
            add_role(&mut roles, execution.devices, ObjectRole::Devices)?;
        }
        if let Some((wrapper, evidence)) = provenance {
            add_role(&mut roles, wrapper, metadata)?;
            add_role(
                &mut roles,
                evidence,
                ObjectRole::Record {
                    maximum: vm_spec::capture::MAX_CAPTURE_RECORD_BYTES as u64,
                },
            )?;
        }
        // Agreement with the record's own dependency derivation: the table
        // closure is exactly content dependencies plus record and provenance.
        let (_, dependencies) = match &self.record {
            SemanticRecord::Image(record) => record.content_dependencies()?,
            SemanticRecord::Snapshot(record) => record.content_dependencies()?,
        };
        let mut expected = dependencies;
        expected.insert(self.digest);
        if let Some((wrapper, evidence)) = provenance {
            expected.insert(wrapper);
            expected.insert(evidence);
        }
        if roles.keys().ne(expected.iter()) {
            return Err(failure(
                "object roles differ from the record's typed dependencies",
            ));
        }
        Ok(roles)
    }
}

/// Authenticate held whole-byte fsmeta and occurrence-preserving pack files,
/// including the logical concatenation identity, without materializing it.
pub(crate) fn authenticate_composition_bytes(
    lower: &crate::store::models::snapshot::SnapshotComposition,
    authenticated: &crate::store::models::snapshot::AuthenticatedComposition,
    mut open_object: impl FnMut(&ObjectDigest) -> Result<std::fs::File, LibVmError>,
    mut open_stream: impl FnMut(&SnapshotStream) -> Result<std::fs::File, LibVmError>,
) -> Result<(), LibVmError> {
    let fsmeta = open_object(&lower.fsmeta)?;
    let mut packs = BTreeMap::new();
    for layer in &lower.layers {
        if let std::collections::btree_map::Entry::Vacant(entry) = packs.entry(layer.pack.stream) {
            entry.insert(open_stream(&layer.pack)?);
        }
    }
    let layers = authenticated
        .layers
        .iter()
        .zip(&lower.layers)
        .map(|(layer, occurrence)| {
            let pack = packs
                .get(&occurrence.pack.stream)
                .ok_or_else(|| failure("authenticated pack occurrence lost its held file"))?;
            Ok(oci::erofs::Layer {
                result: &layer.result,
                changeset: &layer.changeset,
                pack,
            })
        })
        .collect::<Result<Vec<_>, LibVmError>>()?;
    crate::storage::composition::load_exact(
        &authenticated.recipe,
        &layers,
        &authenticated.result,
        &fsmeta,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use oci::vm_artifact::wire::{self, ContentKind, RecordRef};

    use crate::image::import_types::ManagedSourceId;
    use crate::image::transport::closure::{ObjectRole, Semantic};
    use crate::storage::identity::{ObjectDigest, StreamId};
    use crate::store::models::snapshot::tests::record;

    fn stream() -> StreamId {
        crate::storage::stream::StreamMap::new(
            512,
            vec![crate::storage::stream::Chunk::Data(ObjectDigest::of_bytes(
                b"data",
            ))],
        )
        .unwrap()
        .id()
    }

    #[test]
    fn fsmeta_is_a_streamed_object_with_its_own_four_gibibyte_bound() {
        assert_eq!(ObjectRole::Fsmeta.media(), None);
        assert_eq!(ObjectRole::Fsmeta.maximum(), 4 * 1024 * 1024 * 1024);
        assert_ne!(ObjectRole::Fsmeta, ObjectRole::Streamed);
        let mut roles = std::collections::BTreeMap::new();
        let digest = ObjectDigest::of_bytes(b"fsmeta");
        crate::image::transport::closure::add_role(&mut roles, digest, ObjectRole::Fsmeta).unwrap();
        assert!(crate::image::transport::closure::add_role(
            &mut roles,
            digest,
            ObjectRole::Record {
                maximum: 4 * 1024 * 1024
            },
        )
        .is_err());
    }

    #[test]
    fn decode_requires_exact_canonical_bytes_and_preserves_identity() {
        let snapshot = record(
            stream(),
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let semantic = Semantic::snapshot(snapshot.clone()).unwrap();
        let ManagedSourceId::Snapshot(id) = semantic.id else {
            panic!("snapshot identity expected");
        };
        assert_eq!(id, snapshot.id().unwrap());
        let decoded = Semantic::decode(ContentKind::Snapshot, semantic.bytes.clone()).unwrap();
        assert_eq!(decoded.digest, semantic.digest);
        assert!(Semantic::decode(ContentKind::Image, semantic.bytes.clone()).is_err());
        let mut spaced = semantic.bytes.clone();
        spaced.insert(1, b' ');
        assert!(Semantic::decode(ContentKind::Snapshot, spaced).is_err());
    }

    #[test]
    fn config_is_a_pure_projection_of_the_record() {
        let snapshot = record(
            stream(),
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let semantic = Semantic::snapshot(snapshot).unwrap();
        let table = RecordRef::of_bytes(b"{}");
        let config = semantic.config(table, table, None).unwrap();
        assert_eq!(config.purpose, wire::Purpose::Checkpoint);
        assert_eq!(config.capture_kind, Some(wire::CaptureKind::StoppedStorage));
        assert_eq!(config.root_family, wire::RootFamily::OpaqueRaw);
        assert_eq!(
            config.backend_requirement,
            wire::BackendRequirement::RawBlock
        );
        assert_eq!(
            config.guest_platform.architecture,
            wire::Architecture::Amd64
        );
        assert!(!config.minimum_capabilities.live_restore);
        assert_eq!(config.content.record, RecordRef::of_bytes(&semantic.bytes));
        // A stopped snapshot cannot carry capture provenance.
        assert!(semantic.config(table, table, Some(table)).is_err());
        assert!(semantic
            .object_roles(Some((
                ObjectDigest::of_bytes(b"w"),
                ObjectDigest::of_bytes(b"e")
            )))
            .is_err());
    }

    #[test]
    fn object_roles_match_typed_dependencies_and_choose_representations() {
        let kernel = ObjectDigest::of_bytes(b"kernel");
        let map = ObjectDigest::of_bytes(b"map");
        let snapshot = record(stream(), map, kernel);
        let semantic = Semantic::snapshot(snapshot.clone()).unwrap();
        let roles = semantic.object_roles(None).unwrap();
        assert_eq!(roles.get(&kernel), Some(&ObjectRole::Streamed));
        assert!(matches!(roles.get(&map), Some(ObjectRole::Record { .. })));
        assert!(matches!(
            roles.get(&semantic.digest),
            Some(ObjectRole::Record { .. })
        ));
        let crate::BootProfile::LinuxDirect { binding, .. } = &snapshot.boot else {
            panic!("direct boot expected");
        };
        assert!(matches!(
            roles.get(&binding.digest().unwrap()),
            Some(ObjectRole::Record { .. })
        ));
        assert_eq!(roles.len(), 4);
    }

    #[test]
    fn one_digest_cannot_take_two_representations() {
        let mut roles = std::collections::BTreeMap::new();
        let digest = ObjectDigest::of_bytes(b"x");
        crate::image::transport::closure::add_role(
            &mut roles,
            digest,
            ObjectRole::Record { maximum: 10 },
        )
        .unwrap();
        crate::image::transport::closure::add_role(
            &mut roles,
            digest,
            ObjectRole::Record { maximum: 5 },
        )
        .unwrap();
        assert_eq!(roles.get(&digest), Some(&ObjectRole::Record { maximum: 5 }));
        assert!(crate::image::transport::closure::add_role(
            &mut roles,
            digest,
            ObjectRole::Streamed
        )
        .is_err());
        assert!(crate::image::transport::closure::add_role(
            &mut roles,
            digest,
            ObjectRole::Execution
        )
        .is_err());
    }
}

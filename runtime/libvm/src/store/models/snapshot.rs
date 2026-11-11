//! Closed snapshot content schema and RFC 8785 identity. Capture provenance is
//! stored separately, never salted into execution or storage content identity.
use std::collections::BTreeSet;
use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vm_spec::{DiskGeometry, DiskRole};

use crate::machine::stopped::{ExternalResourceRequirement, SnapshotConfiguration};
use crate::storage::identity::{LowerResultId, ObjectDigest, SnapshotId, StreamId};
use crate::storage::limits::{Resource, JSON_SAFE_INTEGER_MAX};
use crate::store::models::storage::{
    BootBinding, BootFileRole, BootProfile, RawLayout, StorageStopOutcome,
};
use crate::LibVmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotKind {
    Snapshot,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "captureKind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SnapshotCaptureKind {
    StoppedStorage { stop_outcome: StorageStopOutcome },
    LiveExecution { execution: Box<SnapshotExecution> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotExecution {
    pub memory: SnapshotStream,
    pub layout: ObjectDigest,
    pub execution: ObjectDigest,
    pub devices: ObjectDigest,
    pub compatibility_profile: SnapshotCompatibilityProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotCompatibilityProfile {
    pub live_state_schema: String,
    pub architecture: String,
    pub profile: ObjectDigest,
    pub topology: ObjectDigest,
    pub ram_layout: ObjectDigest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPurpose {
    Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotStream {
    pub stream: StreamId,
    pub map: ObjectDigest,
    pub map_pages: Vec<ObjectDigest>,
    pub length: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotRoot {
    pub profile: SnapshotRootProfile,
    pub stream: SnapshotStream,
    pub geometry: DiskGeometry,
    pub layout: RawLayout,
}

impl SnapshotRoot {
    pub(crate) fn validate_lower(&self) -> Result<(), LibVmError> {
        if let SnapshotRootProfile::LinuxOverlay {
            lower,
            lower_geometry,
            lower_filesystem_uuid,
            upper_uuid,
            ..
        } = &self.profile
        {
            if self.layout != RawLayout::WholeDisk {
                return Err(invalid("overlay upper must use whole-disk layout"));
            }
            lower.validate_shape()?;
            let packs = Resource::LogicalLowerBytes
                .sum(lower.layers.iter().map(|layer| layer.pack.length))
                .map_err(crate::storage::StorageError::from)?;
            Resource::LogicalLowerBytes
                .check(lower_geometry.length)
                .map_err(crate::storage::StorageError::from)?;
            let fsmeta = lower_geometry.length.saturating_sub(packs);
            if lower_geometry.logical_sector_size != 512
                || fsmeta == 0
                || !lower_geometry
                    .length
                    .is_multiple_of(oci::changeset::limits::PACK_ALIGNMENT)
            {
                return Err(invalid(
                    "overlay lower geometry contradicts its composition occurrences",
                ));
            }
            Resource::FsmetaBytes
                .check(fsmeta)
                .map_err(crate::storage::StorageError::from)?;
            if lower_filesystem_uuid.is_nil()
                || upper_uuid.is_nil()
                || lower_filesystem_uuid == upper_uuid
            {
                return Err(invalid(
                    "overlay filesystem identities must be nonnil and distinct",
                ));
            }
        }
        Ok(())
    }
}

/// The complete layered lower graph, never one materialized lower stream.
/// `record`/`recipe` are the canonical composition-result/recipe objects;
/// layer order and repetition are the exact composition occurrences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotComposition {
    pub result: LowerResultId,
    pub record: ObjectDigest,
    pub recipe: ObjectDigest,
    pub fsmeta: ObjectDigest,
    pub layers: Vec<SnapshotLayer>,
}

/// One occurrence: canonical layer recipe/result objects, the paged index
/// closure (root plus the strictly increasing set of every page it names)
/// and the payload pack stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotLayer {
    pub recipe: ObjectDigest,
    pub result: ObjectDigest,
    pub index_root: ObjectDigest,
    pub index_pages: Vec<ObjectDigest>,
    pub pack: SnapshotStream,
}

/// Canonical records proved to describe exactly one closed composition graph.
/// Fsmeta bytes and pack streams are authenticated by their held owners.
#[derive(Debug)]
pub struct AuthenticatedComposition {
    pub recipe: oci::composition::CompositionRecipe,
    pub result: oci::composition::CompositionResult,
    pub layers: Vec<oci::composition::AuthenticatedLayer>,
}

const LAYER_RECORD_BYTES: u64 = 65536;

impl SnapshotComposition {
    /// Record-local shape: bounded occurrences and a canonical page set.
    pub(crate) fn validate_shape(&self) -> Result<(), LibVmError> {
        Resource::LayerOccurrences
            .check(self.layers.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        for layer in &self.layers {
            let expected_pages = layer
                .pack
                .length
                .div_ceil(crate::storage::limits::CHUNK_SIZE as u64)
                .div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
            if layer.pack.map_pages.len() as u64 != expected_pages {
                return Err(invalid("layer pack map page count contradicts its length"));
            }
            if layer.index_pages.windows(2).any(|pair| pair[0] >= pair[1])
                || layer.index_pages.contains(&layer.index_root)
            {
                return Err(invalid(
                    "layer index pages must be a strictly increasing set excluding the root",
                ));
            }
            if !layer
                .pack
                .length
                .is_multiple_of(oci::changeset::limits::PACK_ALIGNMENT)
            {
                return Err(invalid("layer pack length is not block aligned"));
            }
        }
        Ok(())
    }

    /// Every immutable object of the graph, excluding pack stream maps.
    pub(crate) fn objects(&self) -> impl Iterator<Item = ObjectDigest> + '_ {
        [self.record, self.recipe, self.fsmeta]
            .into_iter()
            .chain(self.layers.iter().flat_map(|layer| {
                [layer.recipe, layer.result, layer.index_root]
                    .into_iter()
                    .chain(layer.index_pages.iter().copied())
            }))
    }

    /// Authenticate every cross-record identity through `read_object`
    /// (digest, maximum bytes). The callback is never asked for fsmeta.
    pub fn authenticate(
        &self,
        mut read_object: impl FnMut(&ObjectDigest, u64) -> Result<Vec<u8>, LibVmError>,
    ) -> Result<AuthenticatedComposition, LibVmError> {
        use oci::composition::{CompositionRecipe, CompositionResult, MAX_RECORD_BYTES};
        self.validate_shape()?;
        let mut read_exact = |digest: &ObjectDigest, maximum: u64| {
            let bytes = read_object(digest, maximum)?;
            if bytes.len() as u64 > maximum || ObjectDigest::of_bytes(&bytes) != *digest {
                return Err(invalid("composition object bytes differ from their digest"));
            }
            Ok::<_, LibVmError>(bytes)
        };
        let recipe = CompositionRecipe::decode(&read_exact(&self.recipe, MAX_RECORD_BYTES as u64)?)
            .map_err(invalid)?;
        let result = CompositionResult::decode(&read_exact(&self.record, MAX_RECORD_BYTES as u64)?)
            .map_err(invalid)?;
        if LowerResultId::from_composition(result.id().map_err(invalid)?) != self.result {
            return Err(invalid(
                "composition record differs from its lower identity",
            ));
        }
        result.validate_recipe(&recipe).map_err(invalid)?;
        if content_object(result.fsmeta.digest)? != self.fsmeta
            || recipe.layers.len() != self.layers.len()
        {
            return Err(invalid(
                "composition fsmeta or occurrence count contradicts its records",
            ));
        }
        let limits = oci::changeset::ChangesetLimits::default();
        let mut layers: Vec<oci::composition::AuthenticatedLayer> =
            Vec::with_capacity(self.layers.len());
        for (index, ((layer, binding), range)) in self
            .layers
            .iter()
            .zip(&recipe.layers)
            .zip(&result.packs)
            .enumerate()
        {
            if content_object(binding.index_root)? != layer.index_root {
                return Err(invalid(
                    "layer index root contradicts its composition recipe",
                ));
            }
            // Repeated occurrences of one exact layer reuse its authentication.
            let previous = self.layers[..index]
                .iter()
                .position(|other| other == layer)
                .and_then(|position| layers.get(position));
            let authenticated = match previous {
                Some(previous) => oci::composition::AuthenticatedLayer {
                    result: previous.result,
                    changeset: previous.changeset.clone(),
                },
                None => {
                    let diff_id =
                        decode_layer_recipe(&read_exact(&layer.recipe, LAYER_RECORD_BYTES)?)?;
                    let result_bytes = read_exact(&layer.result, LAYER_RECORD_BYTES)?;
                    let root_bytes =
                        read_exact(&layer.index_root, oci::changeset::limits::MAX_ROOT_BYTES)?;
                    let mut observed = BTreeSet::new();
                    let mut page_error = None;
                    let authenticated = oci::composition::authenticate_layer(
                        binding.result,
                        &result_bytes,
                        &root_bytes,
                        |digest| {
                            let page = content_object(digest).map_err(|error| {
                                oci::changeset::ChangesetError::Invalid(error.to_string())
                            })?;
                            observed.insert(page);
                            match read_exact(&page, limits.max_page_bytes) {
                                Ok(bytes) => Ok(bytes),
                                Err(error) => {
                                    page_error = Some(error);
                                    Err(oci::changeset::ChangesetError::Invalid(
                                        "layer index page unavailable".into(),
                                    ))
                                }
                            }
                        },
                        diff_id,
                        &limits,
                    );
                    if let Some(error) = page_error {
                        return Err(error);
                    }
                    let authenticated = authenticated.map_err(invalid)?;
                    if observed.into_iter().collect::<Vec<_>>() != layer.index_pages {
                        return Err(invalid("layer index page closure differs from its record"));
                    }
                    authenticated
                }
            };
            if authenticated.result.pack_stream.as_bytes() != layer.pack.stream.as_bytes()
                || authenticated.result.pack_length != layer.pack.length
                || range.stream != authenticated.result.pack_stream
                || range.length != layer.pack.length
            {
                return Err(invalid(
                    "layer pack stream contradicts its result or composition range",
                ));
            }
            layers.push(authenticated);
        }
        Ok(AuthenticatedComposition {
            recipe,
            result,
            layers,
        })
    }
}

impl AuthenticatedComposition {
    pub fn id(&self) -> Result<LowerResultId, LibVmError> {
        Ok(LowerResultId::from_composition(
            self.result.id().map_err(invalid)?,
        ))
    }

    pub fn lower_geometry(&self) -> DiskGeometry {
        DiskGeometry {
            length: self.result.lower_length,
            logical_sector_size: 512,
        }
    }

    pub fn filesystem_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.result.fsmeta.uuid)
    }

    /// Derived root claims are admissible only when they equal the result.
    pub fn check_root_claims(
        &self,
        lower_geometry: &DiskGeometry,
        lower_filesystem_uuid: uuid::Uuid,
    ) -> Result<(), LibVmError> {
        if *lower_geometry != self.lower_geometry()
            || lower_filesystem_uuid != self.filesystem_uuid()
        {
            return Err(invalid(
                "root lower geometry or filesystem UUID differs from its composition",
            ));
        }
        Ok(())
    }
}

pub(crate) fn content_object(
    digest: oci::changeset::ContentDigest,
) -> Result<ObjectDigest, LibVmError> {
    Ok(ObjectDigest::from_sha256(*digest.as_bytes()))
}

/// Authenticate a canonical layer recipe without trusting its parsed form.
pub(crate) fn decode_layer_recipe(
    bytes: &[u8],
) -> Result<oci::changeset::ContentDigest, LibVmError> {
    let value: Value = serde_json::from_slice(bytes).map_err(invalid)?;
    let diff_id: oci::changeset::ContentDigest = value
        .get("diffId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("layer recipe has no diff ID"))?
        .parse()
        .map_err(invalid)?;
    if (oci::changeset::LayerRecipe { diff_id })
        .canonical_bytes()
        .map_err(invalid)?
        != bytes
    {
        return Err(invalid("layer recipe is not its canonical record"));
    }
    Ok(diff_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SnapshotRootProfile {
    OpaqueRaw,
    LinuxOverlay {
        lower: Box<SnapshotComposition>,
        lower_geometry: DiskGeometry,
        lower_filesystem_uuid: uuid::Uuid,
        upper_uuid: uuid::Uuid,
        ext4_profile: crate::store::models::storage::Ext4Profile,
        overlay_profile: crate::store::models::storage::OverlayProfile,
        temporary_directory: crate::store::models::storage::TemporaryDirectoryPolicy,
    },
}

/// Name retired or unknown snapshot root formats (including the flat-lower
/// single `SnapshotStream`) instead of reporting a generic schema failure.
/// `root` is the record's `root` JSON value.
pub(crate) fn refuse_retired_snapshot_root(root: &Value) -> Result<(), LibVmError> {
    let profile = root.get("profile");
    let kind = profile
        .and_then(|profile| profile.get("kind"))
        .and_then(Value::as_str);
    match kind {
        Some("opaque-raw") => Ok(()),
        Some("linux-overlay") => {
            let lower = profile.and_then(|profile| profile.get("lower"));
            if lower.is_some_and(|lower| lower.get("layers").is_some()) {
                Ok(())
            } else if lower.is_some_and(|lower| lower.get("stream").is_some()) {
                Err(LibVmError::IncompatibleRootProfile {
                    profile: "linux-overlay/flat-ext4".into(),
                })
            } else {
                Err(LibVmError::IncompatibleRootProfile {
                    profile: "linux-overlay/unspecified-lower".into(),
                })
            }
        }
        Some(other) => Err(LibVmError::IncompatibleRootProfile {
            profile: other.into(),
        }),
        None => Err(LibVmError::IncompatibleRootProfile {
            profile: "unspecified".into(),
        }),
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotDisk {
    pub role: DiskRole,
    pub order: u32,
    pub writable: bool,
    pub content: SnapshotStream,
    pub geometry: DiskGeometry,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotPlatformFile {
    pub role: BootFileRole,
    pub object: ObjectDigest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRecord {
    pub schema: u32,
    pub kind: SnapshotKind,
    #[serde(flatten)]
    pub capture: SnapshotCaptureKind,
    pub purpose: SnapshotPurpose,
    pub root: SnapshotRoot,
    pub disks: Vec<SnapshotDisk>,
    pub platform_files: Vec<SnapshotPlatformFile>,
    pub configuration: SnapshotConfiguration,
    pub boot: BootProfile,
    pub external_requirements: Vec<ExternalResourceRequirement>,
}

pub(crate) fn invalid(message: impl fmt::Display) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "snapshot",
        message: message.to_string(),
    }
}

impl SnapshotRecord {
    pub fn validate(&self) -> Result<(), LibVmError> {
        self.validate_semantics()?;
        validate_numbers(&serde_json::to_value(self).map_err(invalid)?)
    }

    fn validate_semantics(&self) -> Result<(), LibVmError> {
        if self.schema != 1 {
            return Err(invalid("unsupported snapshot schema"));
        }
        Resource::IncludedDisks
            .check(
                self.disks.len() as u64
                    + if matches!(self.root.profile, SnapshotRootProfile::LinuxOverlay { .. }) {
                        2
                    } else {
                        1
                    },
            )
            .map_err(crate::storage::StorageError::from)?;
        validate_geometry(&self.root.stream, &self.root.geometry)?;
        self.root.validate_lower()?;
        let mut logical = 0u64;
        for stream in self.streams() {
            logical = logical
                .checked_add(stream.length)
                .ok_or_else(|| invalid("snapshot closure length overflow"))?;
            let expected_pages = stream
                .length
                .div_ceil(crate::storage::limits::CHUNK_SIZE as u64)
                .div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
            if stream.map_pages.len() as u64 != expected_pages {
                return Err(invalid(
                    "snapshot stream map page count contradicts its length",
                ));
            }
        }
        Resource::ArtifactStreamBytes
            .check(logical)
            .map_err(crate::storage::StorageError::from)?;
        if let SnapshotCaptureKind::LiveExecution { execution } = &self.capture {
            Resource::CapturedRamBytes
                .check(execution.memory.length)
                .map_err(crate::storage::StorageError::from)?;
            if execution.memory.length == 0
                || execution.compatibility_profile.live_state_schema.is_empty()
                || execution.compatibility_profile.live_state_schema.len()
                    > vm_spec::capture::MAX_LIVE_STATE_SCHEMA_BYTES
                || execution
                    .compatibility_profile
                    .live_state_schema
                    .contains('\0')
                || execution.compatibility_profile.architecture.is_empty()
                || execution.compatibility_profile.architecture.len()
                    > vm_spec::capture::MAX_ARCHITECTURE_BYTES
                || execution.compatibility_profile.architecture.contains('\0')
            {
                return Err(invalid("invalid execution memory or compatibility profile"));
            }
            if self
                .external_requirements
                .iter()
                .any(|resource| !resource.read_only)
            {
                return Err(invalid(
                    "live execution cannot omit writable external resources",
                ));
            }
        }
        self.boot.validate()?;
        self.configuration.spec.validate().map_err(invalid)?;
        if self
            .configuration
            .spec
            .boot
            .as_ref()
            .and_then(|boot| boot.kernel.as_ref())
            .is_some_and(|kernel| kernel.path.is_some() || kernel.initramfs.is_some())
        {
            return Err(invalid(
                "snapshot boot selection contains host path authority",
            ));
        }
        if let Some(storage) = &self.configuration.spec.storage {
            for (order, disk) in storage.disks.iter().enumerate() {
                if disk.path != std::path::Path::new(&format!("captured-disk-{order}")) {
                    return Err(invalid("snapshot disk contains host path authority"));
                }
            }
        }
        for mount in &self.configuration.spec.mounts {
            if mount.source != std::path::Path::new("required-external-share") {
                return Err(invalid("snapshot share contains host path authority"));
            }
        }
        for agent in std::iter::once(&self.configuration.guest.agent)
            .chain(self.configuration.agent_mode.iter())
        {
            if let crate::MachineAgent::Custom { path } = agent {
                if path != std::path::Path::new("captured-agent") {
                    return Err(invalid("snapshot agent contains host path authority"));
                }
            }
        }
        let mut previous = None;
        for disk in &self.disks {
            if disk.role != DiskRole::Data || previous.is_some_and(|order| order >= disk.order) {
                return Err(invalid(
                    "included Data disks must have unique increasing order",
                ));
            }
            previous = Some(disk.order);
            validate_geometry(&disk.content, &disk.geometry)?;
            if disk.order == 0 || disk.order >= Resource::IncludedDisks.maximum() as u32 {
                return Err(invalid(
                    "included Data disk ordinal is outside the attachment bound",
                ));
            }
        }
        // No Mac/EFI or mutable platform profile is admitted in this phase.
        if !self.platform_files.is_empty() {
            return Err(invalid(
                "platform files require an admitted platform capture profile",
            ));
        }
        match &self.boot {
            BootProfile::LinuxDirect {
                binding:
                    BootBinding::Pinned {
                        architecture, abi, ..
                    },
                kernel_architecture,
                ..
            } if architecture == kernel_architecture
                && abi == crate::runtime::boot_assets::DIRECT_BOOT_ABI => {}
            _ => {
                return Err(invalid(
                    "snapshot requires an exact pinned Linux direct boot bundle",
                ))
            }
        }
        let mut requirements = BTreeSet::new();
        for requirement in &self.external_requirements {
            requirement.validate()?;
            if !requirements.insert(&requirement.resource) {
                return Err(invalid("duplicate external resource requirement"));
            }
        }
        validate_configured_closure(self)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LibVmError> {
        self.validate_semantics()?;
        let bytes = canonical_value(&serde_json::to_value(self).map_err(invalid)?)?;
        Resource::MetadataPageBytes
            .check(bytes.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        Ok(bytes)
    }

    pub fn id(&self) -> Result<SnapshotId, LibVmError> {
        Ok(snapshot_id(&self.canonical_bytes()?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LibVmError> {
        Resource::MetadataPageBytes
            .check(bytes.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let StrictValue(value) = StrictValue::deserialize(&mut decoder).map_err(invalid)?;
        decoder.end().map_err(invalid)?;
        validate_numbers(&value)?;
        let record = match Self::deserialize(&value) {
            Ok(record) => record,
            Err(error) => {
                if let Some(root) = value.get("root") {
                    refuse_retired_snapshot_root(root)?;
                }
                return Err(invalid(error));
            }
        };
        // Nested configuration types have defaults/flattening. A round-trip
        // equality check rejects ignored keys and omitted required current data.
        if serde_json::to_value(&record).map_err(invalid)? != value {
            return Err(invalid("record is not the closed current schema"));
        }
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn storage_streams(&self) -> impl Iterator<Item = &SnapshotStream> {
        let packs = match &self.root.profile {
            SnapshotRootProfile::LinuxOverlay { lower, .. } => lower.layers.as_slice(),
            SnapshotRootProfile::OpaqueRaw => &[],
        };
        std::iter::once(&self.root.stream)
            .chain(packs.iter().map(|layer| &layer.pack))
            .chain(self.disks.iter().map(|disk| &disk.content))
    }

    /// The layered lower graph of an overlay root, if any.
    pub fn lower(&self) -> Option<&SnapshotComposition> {
        match &self.root.profile {
            SnapshotRootProfile::LinuxOverlay { lower, .. } => Some(lower),
            SnapshotRootProfile::OpaqueRaw => None,
        }
    }

    pub fn streams(&self) -> impl Iterator<Item = &SnapshotStream> {
        let memory = match &self.capture {
            SnapshotCaptureKind::LiveExecution { execution } => Some(&execution.memory),
            SnapshotCaptureKind::StoppedStorage { .. } => None,
        };
        self.storage_streams().chain(memory)
    }

    #[cfg(test)]
    pub fn dependencies(&self) -> Result<(BTreeSet<StreamId>, BTreeSet<ObjectDigest>), LibVmError> {
        let canonical = self.canonical_bytes()?;
        let (streams, mut objects) = self.content_dependencies()?;
        objects.insert(ObjectDigest::of_bytes(&canonical));
        Ok((streams, objects))
    }

    /// Typed content edges only. Catalog root traversal adds the separately
    /// authenticated record ObjectDigest without hashing under coordination.
    pub(crate) fn storage_content_dependencies(
        &self,
    ) -> Result<(BTreeSet<StreamId>, BTreeSet<ObjectDigest>), LibVmError> {
        let mut streams = BTreeSet::new();
        let mut objects = BTreeSet::new();
        for stream in self.storage_streams() {
            streams.insert(stream.stream);
            objects.insert(stream.map);
            objects.extend(stream.map_pages.iter().copied());
        }
        if let Some(lower) = self.lower() {
            objects.extend(lower.objects());
        }
        if let BootProfile::LinuxDirect {
            binding:
                binding @ BootBinding::Pinned {
                    kernel,
                    base_initramfs,
                    agent,
                    ..
                },
            ..
        } = &self.boot
        {
            objects.insert(*kernel);
            objects.insert(*base_initramfs);
            objects.extend(agent.iter().copied());
            objects.insert(binding.digest()?);
        }
        objects.extend(self.platform_files.iter().map(|file| file.object));
        Ok((streams, objects))
    }

    pub(crate) fn content_dependencies(
        &self,
    ) -> Result<(BTreeSet<StreamId>, BTreeSet<ObjectDigest>), LibVmError> {
        let (mut streams, mut objects) = self.storage_content_dependencies()?;
        if let SnapshotCaptureKind::LiveExecution { execution } = &self.capture {
            streams.insert(execution.memory.stream);
            objects.insert(execution.memory.map);
            objects.extend(execution.memory.map_pages.iter().copied());
            objects.extend([execution.layout, execution.execution, execution.devices]);
        }
        Ok((streams, objects))
    }
}

pub(crate) fn snapshot_id(canonical: &[u8]) -> SnapshotId {
    let mut hash = Sha256::new();
    hash.update(b"silo:snapshot:v1\n");
    hash.update(canonical);
    SnapshotId::from_sha256(hash.finalize().into())
}

fn validate_numbers(value: &Value) -> Result<(), LibVmError> {
    match value {
        Value::Number(number) => {
            let valid = number.as_u64().is_some_and(|n| n <= JSON_SAFE_INTEGER_MAX)
                || number
                    .as_i64()
                    .is_some_and(|n| n.unsigned_abs() <= JSON_SAFE_INTEGER_MAX);
            if !valid || number.is_f64() {
                return Err(invalid("only exact JSON safe integers are admitted"));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_configured_closure(record: &SnapshotRecord) -> Result<(), LibVmError> {
    use crate::machine::stopped::ExternalResourceKey;
    use crate::store::models::storage::{PartitionTable, RootSelector};
    let stopped = matches!(record.capture, SnapshotCaptureKind::StoppedStorage { .. });
    let BootProfile::LinuxDirect { root_selector, .. } = &record.boot else {
        return Err(invalid("unadmitted snapshot boot profile"));
    };
    let selector_matches = match (&record.root.profile, &record.root.layout, root_selector) {
        (
            SnapshotRootProfile::LinuxOverlay { .. },
            RawLayout::WholeDisk,
            RootSelector::ManagedOverlay,
        ) => true,
        (SnapshotRootProfile::OpaqueRaw, RawLayout::WholeDisk, RootSelector::WholeDisk) => true,
        (
            SnapshotRootProfile::OpaqueRaw,
            RawLayout::Partitioned {
                table: PartitionTable::Gpt,
            },
            RootSelector::GptPartition { guid },
        ) => !guid.is_nil(),
        (
            SnapshotRootProfile::OpaqueRaw,
            RawLayout::Partitioned {
                table: PartitionTable::Mbr,
            },
            RootSelector::MbrPartition { number },
        ) => (1..=4).contains(number),
        _ => false,
    };
    if !selector_matches {
        return Err(invalid(
            "snapshot raw layout and boot root selector disagree",
        ));
    }
    let configured = record
        .configuration
        .spec
        .storage
        .as_ref()
        .map(|storage| storage.disks.as_slice())
        .unwrap_or_default();
    let root_count = match &record.root.profile {
        SnapshotRootProfile::OpaqueRaw => {
            if let Some(root) = configured.first() {
                if root.role != DiskRole::Root
                    || root.read_only
                    || root.geometry != record.root.geometry
                    || (stopped && root.block_id.as_str() != "silo-root")
                {
                    return Err(invalid("snapshot root contradicts configured attachment"));
                }
            }
            1
        }
        SnapshotRootProfile::LinuxOverlay { lower_geometry, .. } => {
            if configured.len() < 2
                || configured[0].role != DiskRole::RootLower
                || !configured[0].read_only
                || configured[0].geometry != *lower_geometry
                || (stopped && configured[0].block_id.as_str() != "silo-root-lower")
                || configured[1].role != DiskRole::RootUpper
                || configured[1].read_only
                || configured[1].geometry != record.root.geometry
                || (stopped && configured[1].block_id.as_str() != "silo-root-upper")
            {
                return Err(invalid(
                    "snapshot overlay contradicts configured attachments",
                ));
            }
            2
        }
    };
    for disk in &record.disks {
        let configured = configured
            .get(disk.order as usize)
            .ok_or_else(|| invalid("included disk is absent from configured attachments"))?;
        if configured.role != disk.role
            || configured.geometry != disk.geometry
            || configured.read_only == disk.writable
        {
            return Err(invalid("included disk contradicts configured attachment"));
        }
    }
    for (order, disk) in configured.iter().enumerate().skip(root_count) {
        let included = record
            .disks
            .iter()
            .any(|included| included.order as usize == order);
        let required = record.external_requirements.iter().any(|requirement| {
            matches!(&requirement.resource, ExternalResourceKey::Disk { order: ordinal } if *ordinal as usize == order)
                && requirement.read_only == disk.read_only
        });
        if disk.role != DiskRole::Data
            || included == required
            || (stopped && disk.block_id.as_str() != format!("silo-data-{order}"))
        {
            return Err(invalid("each configured Data disk requires exactly one included stream or external declaration"));
        }
    }
    for mount in &record.configuration.spec.mounts {
        if !record.external_requirements.iter().any(|requirement| {
            matches!(&requirement.resource, ExternalResourceKey::Share { tag } if tag == &mount.tag)
                && requirement.read_only == mount.read_only
        }) {
            return Err(invalid("configured share has no external declaration"));
        }
    }
    for requirement in &record.external_requirements {
        let matches = match &requirement.resource {
            ExternalResourceKey::Disk { order } => {
                configured.get(*order as usize).is_some_and(|disk| {
                    disk.role == DiskRole::Data && disk.read_only == requirement.read_only
                })
            }
            ExternalResourceKey::Share { tag } => record
                .configuration
                .spec
                .mounts
                .iter()
                .any(|mount| mount.tag == *tag && mount.read_only == requirement.read_only),
        };
        if !matches {
            return Err(invalid(
                "external declaration is absent from configured resources",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_geometry(
    stream: &SnapshotStream,
    geometry: &DiskGeometry,
) -> Result<(), LibVmError> {
    if stream.length != geometry.length
        || geometry.logical_sector_size != 512
        || geometry.length == 0
        || !geometry.length.is_multiple_of(512)
    {
        return Err(invalid(
            "snapshot stream and 512-byte disk geometry disagree",
        ));
    }
    Resource::VirtualDiskBytes
        .check(stream.length)
        .map_err(crate::storage::StorageError::from)?;
    Ok(())
}

/// RFC 8785 for the admitted JSON subset: no floating point, safe integers,
/// UTF-16 property ordering, no Unicode normalization, ECMAScript string escapes.
pub(crate) fn canonical_value(value: &Value) -> Result<Vec<u8>, LibVmError> {
    fn emit(value: &Value, out: &mut Vec<u8>) -> Result<(), LibVmError> {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::String(value) => serde_json::to_writer(out, value).map_err(invalid)?,
            Value::Number(number) => {
                let valid = number.as_u64().is_some_and(|n| n <= JSON_SAFE_INTEGER_MAX)
                    || number
                        .as_i64()
                        .is_some_and(|n| n.unsigned_abs() <= JSON_SAFE_INTEGER_MAX);
                if !valid || number.is_f64() {
                    return Err(invalid("only exact JSON safe integers are admitted"));
                }
                out.extend_from_slice(number.to_string().as_bytes());
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    emit(value, out)?;
                }
                out.push(b']');
            }
            Value::Object(values) => {
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|(left, _), (right, _)| {
                    left.encode_utf16().cmp(right.encode_utf16())
                });
                out.push(b'{');
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key).map_err(invalid)?;
                    out.push(b':');
                    emit(value, out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }
    let mut bytes = Vec::new();
    emit(value, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn decode_identity_value(bytes: &[u8]) -> Result<Value, LibVmError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut decoder).map_err(invalid)?;
    decoder.end().map_err(invalid)?;
    validate_numbers(&value)?;
    if canonical_value(&value)? != bytes {
        return Err(invalid("identity metadata is not its canonical encoding"));
    }
    Ok(value)
}

// serde_json::Value normally accepts duplicate object properties. Reject them
// before typed decoding, at every nesting level (including configured maps).
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate keys or floating point")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::from(value)))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON property"));
                    }
                    let StrictValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        decoder.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::machine::stopped::SnapshotConfiguration;
    use crate::storage::identity::{ObjectDigest, StreamId};
    use crate::store::models::snapshot::{
        canonical_value, SnapshotCaptureKind, SnapshotKind, SnapshotPurpose, SnapshotRecord,
        SnapshotRoot, SnapshotStream, StrictValue,
    };
    use crate::store::models::storage::{
        BootBinding, BootProfile, DirectCommandLinePolicy, GuestArchitecture, LinuxPlatform,
        RawLayout, RootSelector, StorageStopOutcome, Translation,
    };
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub(crate) fn record(
        stream: StreamId,
        map: ObjectDigest,
        kernel: ObjectDigest,
    ) -> SnapshotRecord {
        SnapshotRecord {
            schema: 1,
            kind: SnapshotKind::Snapshot,
            capture: SnapshotCaptureKind::StoppedStorage {
                stop_outcome: StorageStopOutcome::Unknown,
            },
            purpose: SnapshotPurpose::Checkpoint,
            root: SnapshotRoot {
                profile: crate::store::models::snapshot::SnapshotRootProfile::OpaqueRaw,
                stream: SnapshotStream {
                    stream,
                    map,
                    map_pages: vec![map],
                    length: 512,
                },
                geometry: vm_spec::DiskGeometry {
                    length: 512,
                    logical_sector_size: 512,
                },
                layout: RawLayout::WholeDisk,
            },
            disks: Vec::new(),
            platform_files: Vec::new(),
            configuration: SnapshotConfiguration {
                secret_scope: crate::SecretScopePolicy::default(),
                spec: vm_spec::VmSpec::current(),
                retention: crate::MachineRetention::Persistent,
                process: crate::ProcessConfig::default(),
                template_name: None,
                agent_mode: None,
                guest: crate::MachineGuestConfig::default(),
                labels: BTreeMap::from([
                    ("\u{e000}".into(), "private".into()),
                    ("\u{1f600}".into(), "astral".into()),
                    ("é".into(), "e\u{301}".into()),
                ]),
                metadata: BTreeMap::new(),
                network: crate::store::models::MachineNetworkConfig::default(),
            },
            boot: BootProfile::LinuxDirect {
                userspace_platform: LinuxPlatform {
                    architecture: GuestArchitecture::Amd64,
                    variant: None,
                },
                kernel_architecture: GuestArchitecture::Amd64,
                command_line_policy: DirectCommandLinePolicy::SiloDirectV1,
                binding: BootBinding::Pinned {
                    kernel,
                    base_initramfs: kernel,
                    agent: None,
                    architecture: GuestArchitecture::Amd64,
                    abi: crate::runtime::boot_assets::DIRECT_BOOT_ABI.into(),
                },
                root_selector: RootSelector::WholeDisk,
                root_filesystem: crate::store::models::storage::RootFilesystem::Ext4,
                translation: Translation::None,
            },
            external_requirements: Vec::new(),
        }
    }

    #[test]
    fn snapshot_jcs_uses_utf16_order_and_exact_string_escaping_without_normalization() {
        let value = serde_json::json!({
            "\u{e000}": "private", "\u{1f600}": "astral", "é": "e\u{301}",
            "\\": "\u{0000}\u{0008}\t\n\u{000c}\r\"\\/\u{2028}",
        });
        let expected = "{\"\\\\\":\"\\u0000\\b\\t\\n\\f\\r\\\"\\\\/\u{2028}\",\"é\":\"e\u{301}\",\"\u{1f600}\":\"astral\",\"\u{e000}\":\"private\"}";
        assert_eq!(canonical_value(&value).unwrap(), expected.as_bytes());
    }

    #[test]
    fn snapshot_parser_rejects_duplicate_keys_at_all_levels_and_invalid_unicode() {
        for json in [
            r#"{"x":1,"x":2}"#,
            r#"{"nested":{"x":1,"\u0078":2}}"#,
            r#"{"array":[{"x":1,"x":1}]}"#,
            r#""\ud800""#,
            r#"{"value":1.0}"#,
        ] {
            let mut decoder = serde_json::Deserializer::from_str(json);
            assert!(StrictValue::deserialize(&mut decoder).is_err(), "{json}");
        }
    }

    #[test]
    fn snapshot_jcs_rejects_floats_and_unsafe_integers() {
        for value in [
            serde_json::json!(9007199254740992_u64),
            serde_json::json!(-9007199254740992_i64),
            serde_json::json!(1.0),
        ] {
            assert!(canonical_value(&value).is_err());
        }
        for value in [
            serde_json::json!(9007199254740991_u64),
            serde_json::json!(-9007199254740991_i64),
        ] {
            assert!(canonical_value(&value).is_ok());
        }
    }

    #[test]
    fn snapshot_identity_is_domain_separated_and_preserves_configured_null_empty() {
        let stream = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let mut record = record(
            stream,
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let bytes = record.canonical_bytes().unwrap();
        assert_eq!(SnapshotRecord::decode(&bytes).unwrap(), record);
        assert_ne!(
            record.id().unwrap().to_string(),
            ObjectDigest::of_bytes(&bytes).to_string()
        );
        let id = record.id().unwrap();
        record.configuration.process.entrypoint = Some(Vec::new());
        assert_ne!(record.id().unwrap(), id);
        record.configuration.process.entrypoint = None;
        record.capture = SnapshotCaptureKind::StoppedStorage {
            stop_outcome: StorageStopOutcome::Clean,
        };
        assert_ne!(record.id().unwrap(), id);
        assert_eq!(record.root.stream.stream, stream);
    }

    #[test]
    fn snapshot_decode_is_closed_and_current_schema_only() {
        let stream = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let record = record(
            stream,
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let value = serde_json::to_value(&record).unwrap();
        for (field, replacement) in [
            ("schema", serde_json::json!(2)),
            ("captureKind", serde_json::json!("stopped")),
            ("captureKind", serde_json::json!("live-execution")),
            ("purpose", serde_json::json!("generalized-image")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            assert!(SnapshotRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        for field in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(
                SnapshotRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut changed = value;
        changed["configuration"]["spec"]["extra"] = serde_json::json!(true);
        assert!(SnapshotRecord::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }

    #[test]
    fn snapshot_configured_data_requires_exact_included_or_external_closure() {
        use crate::machine::stopped::{ExternalResourceKey, ExternalResourceRequirement};
        use crate::store::models::snapshot::SnapshotDisk;
        let stream = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let mut record = record(
            stream,
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let geometry = record.root.geometry;
        let disk = |order, role, serial: &str| vm_spec::Disk {
            path: format!("captured-disk-{order}").into(),
            role,
            format: vm_spec::DiskFormat::Raw,
            geometry,
            block_id: vm_spec::BlockId::new(serial).unwrap(),
            read_only: false,
        };
        record.configuration.spec.storage = Some(vm_spec::Storage {
            disks: vec![
                disk(0, vm_spec::DiskRole::Root, "silo-root"),
                disk(1, vm_spec::DiskRole::Data, "silo-data-1"),
            ],
        });
        record.disks.push(SnapshotDisk {
            role: vm_spec::DiskRole::Data,
            order: 1,
            writable: true,
            content: record.root.stream.clone(),
            geometry,
        });
        record.validate().unwrap();
        let included = record.disks.pop().unwrap();
        assert!(record.validate().is_err());
        record
            .external_requirements
            .push(ExternalResourceRequirement {
                resource: ExternalResourceKey::Disk { order: 1 },
                read_only: false,
            });
        record.validate().unwrap();
        record.disks.push(included);
        assert!(record.validate().is_err());
        record.external_requirements.clear();
        record.disks[0].writable = false;
        assert!(record.validate().is_err());
        record.disks[0].writable = true;
        record.configuration.spec.storage.as_mut().unwrap().disks[1].path =
            "/source/data.raw".into();
        assert!(record.validate().is_err());
    }

    #[test]
    fn checkpoint_live_identity_has_no_stop_or_capture_provenance_and_enforces_ram_limit() {
        use crate::store::models::snapshot::{SnapshotCompatibilityProfile, SnapshotExecution};
        let digest = ObjectDigest::of_bytes(b"content");
        let stream = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let mut record = record(stream, digest, digest);
        let mut memory = record.root.stream.clone();
        memory.length = 1 << 40;
        memory.map_pages = vec![digest; 32];
        record.capture = SnapshotCaptureKind::LiveExecution {
            execution: Box::new(SnapshotExecution {
                memory,
                layout: digest,
                execution: digest,
                devices: digest,
                compatibility_profile: SnapshotCompatibilityProfile {
                    live_state_schema: "silo.live-state/1".into(),
                    architecture: "x86_64".into(),
                    profile: digest,
                    topology: digest,
                    ram_layout: digest,
                },
            }),
        };
        let bytes = record.canonical_bytes().unwrap();
        assert_eq!(SnapshotRecord::decode(&bytes).unwrap(), record);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["captureKind"], "live-execution");
        for key in [
            "stopOutcome",
            "captureId",
            "runId",
            "pauseToken",
            "evidenceDigest",
            "createdAt",
        ] {
            assert!(value.get(key).is_none(), "{key}");
        }
        if let SnapshotCaptureKind::LiveExecution { execution } = &mut record.capture {
            execution.memory.length += crate::storage::limits::CHUNK_SIZE as u64;
            execution.memory.map_pages.push(digest);
        }
        assert!(record.validate().is_err());
    }

    /// Shape-valid layered lower graph (identities are not authenticated).
    pub(crate) fn composition() -> crate::store::models::snapshot::SnapshotComposition {
        use crate::store::models::snapshot::{SnapshotComposition, SnapshotLayer};
        let digest = |byte: u8| ObjectDigest::from_sha256([byte; 32]);
        SnapshotComposition {
            result: format!("sha256:{}", "0c".repeat(32)).parse().unwrap(),
            record: digest(1),
            recipe: digest(2),
            fsmeta: digest(3),
            layers: vec![SnapshotLayer {
                recipe: digest(4),
                result: digest(5),
                index_root: digest(6),
                index_pages: vec![digest(7)],
                pack: SnapshotStream {
                    stream: StreamId::from_sha256([8; 32]),
                    map: digest(9),
                    map_pages: vec![digest(10)],
                    length: 4096,
                },
            }],
        }
    }

    #[test]
    fn layered_lower_shape_and_retired_flat_snapshot_roots_are_refused() {
        let mut graph = composition();
        graph.validate_shape().unwrap();
        let duplicate = graph.layers[0].index_pages[0];
        graph.layers[0].index_pages.push(duplicate);
        assert!(graph.validate_shape().is_err(), "duplicate page");
        let mut graph = composition();
        graph.layers[0].index_pages = vec![graph.layers[0].index_root];
        assert!(graph.validate_shape().is_err(), "root listed as a page");
        let mut graph = composition();
        graph.layers[0].pack.length = 512;
        assert!(graph.validate_shape().is_err(), "unaligned pack");

        let stream = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let raw = record(
            stream,
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        let mut value = serde_json::to_value(&raw).unwrap();
        value["root"]["profile"] = serde_json::json!({
            "kind": "linux-overlay",
            "lower": serde_json::to_value(&raw.root.stream).unwrap(),
            "lowerGeometry": {"length": 512, "logicalSectorSize": 512},
            "lowerFilesystemUuid": uuid::Uuid::new_v4(),
            "upperUuid": uuid::Uuid::new_v4(),
            "ext4Profile": "silo-upper-ext4-v1",
            "overlayProfile": "silo-overlay-v1",
            "temporaryDirectory": {"kind": "disk-backed"},
        });
        match SnapshotRecord::decode(&serde_json::to_vec(&value).unwrap()) {
            Err(crate::LibVmError::IncompatibleRootProfile { profile }) => {
                assert_eq!(profile, "linux-overlay/flat-ext4")
            }
            other => panic!("{other:?}"),
        }
        value["root"]["profile"] = serde_json::json!({"kind": "linux-flat-overlay"});
        assert!(matches!(
            SnapshotRecord::decode(&serde_json::to_vec(&value).unwrap()),
            Err(crate::LibVmError::IncompatibleRootProfile { .. })
        ));
    }
}

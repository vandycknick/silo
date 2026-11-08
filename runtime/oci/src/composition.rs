//! Canonical, path-independent EROFS lower composition records.
//!
//! Pack descriptors must already be authenticated and kept immutable by the
//! caller. This module authenticates their indexes and binds occurrence order;
//! only the storage layer computes the concatenated lower's `StreamIdentity`.
//! Outputs are staging files: publish only after preparation, stream
//! authentication, and finalization all succeed.

use std::{fmt, fs::File, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::changeset::index::{encode_index_to, LayerRecipe, LayerResult};
use crate::changeset::limits::{FORMAT_LIMITS, PACK_ALIGNMENT};
use crate::changeset::namespace::{compose, NamespaceError, ValidatedNamespace};
use crate::changeset::{
    decode_index, ChangesetError, ChangesetLimits, ContentDigest, LayerChangeset, LayerResultId,
    StreamIdentity,
};
use crate::erofs::{self, EncodedFsmeta, ErofsError, Layer};
use crate::vm_artifact::wire;
use crate::Platform;

pub const NAMESPACE_ABI: &str = "silo-namespace-v1";
pub const FSMETA_ABI: &str = "silo-erofs-v1";
pub const OVERLAY_PROFILE: &str = "silo-overlay-v1";
pub const MAX_FSMETA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_LOWER_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
// 1024 occurrences, each with two SHA256 identities and bounded platform data.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CompositionError {
    #[error("invalid composition: {0}")]
    Invalid(&'static str),
    #[error("composition does not match its retained result")]
    ResultMismatch,
    #[error(transparent)]
    Changeset(#[from] ChangesetError),
    #[error(transparent)]
    Namespace(#[from] NamespaceError),
    #[error(transparent)]
    Erofs(#[from] ErofsError),
    #[error(transparent)]
    Record(#[from] crate::vm_artifact::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
pub type CompositionResultValue<T> = Result<T, CompositionError>;

macro_rules! identity {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(ContentDigest);
        impl $name {
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
            fn of_record(bytes: &[u8]) -> Self {
                let mut hash = Sha256::new();
                hash.update($domain);
                hash.update(bytes);
                Self(ContentDigest::from_sha256(hash.finalize().into()))
            }
        }
        impl FromStr for $name {
            type Err = ChangesetError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse().map(Self)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
    };
}
identity!(CompositionRecipeId, b"silo:composition-recipe:v1\n");
identity!(CompositionResultId, b"silo:composition-result:v1\n");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LayerBinding {
    pub result: LayerResultId,
    pub index_root: ContentDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionRecipe {
    pub platform: Platform,
    pub layers: Vec<LayerBinding>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipePlatform {
    architecture: String,
    os: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
}
impl From<RecipePlatform> for Platform {
    fn from(platform: RecipePlatform) -> Self {
        Self {
            os: platform.os,
            architecture: platform.architecture,
            variant: platform.variant,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecipeRecord {
    fsmeta_abi: String,
    kind: String,
    layers: Vec<LayerBinding>,
    namespace_abi: String,
    overlay_profile: String,
    platform: RecipePlatform,
    schema: u64,
}

impl CompositionRecipe {
    pub fn from_layers(platform: Platform, layers: &[Layer<'_>]) -> CompositionResultValue<Self> {
        check_layer_count(layers.len())?;
        let recipe = Self {
            platform,
            layers: layers
                .iter()
                .map(|layer| {
                    Ok(LayerBinding {
                        result: layer.result.id()?,
                        index_root: layer.result.index_root,
                    })
                })
                .collect::<Result<_, ChangesetError>>()?,
        };
        recipe.validate()?;
        Ok(recipe)
    }

    fn validate(&self) -> CompositionResultValue<()> {
        check_layer_count(self.layers.len())?;
        let token = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')
                })
        };
        if self.platform.os != "linux"
            || !token(&self.platform.architecture)
            || self
                .platform
                .variant
                .as_deref()
                .is_some_and(|value| !token(value))
        {
            return Err(CompositionError::Invalid(
                "unsupported or noncanonical platform",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> CompositionResultValue<Vec<u8>> {
        self.validate()?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record<'a> {
            fsmeta_abi: &'a str,
            kind: &'a str,
            layers: &'a [LayerBinding],
            namespace_abi: &'a str,
            overlay_profile: &'a str,
            platform: &'a Platform,
            schema: u64,
        }
        canonical(&Record {
            fsmeta_abi: FSMETA_ABI,
            kind: "composition-recipe",
            layers: &self.layers,
            namespace_abi: NAMESPACE_ABI,
            overlay_profile: OVERLAY_PROFILE,
            platform: &self.platform,
            schema: 1,
        })
    }
    pub fn id(&self) -> CompositionResultValue<CompositionRecipeId> {
        Ok(CompositionRecipeId::of_record(&self.canonical_bytes()?))
    }
    pub fn decode(bytes: &[u8]) -> CompositionResultValue<Self> {
        let record: RecipeRecord = decode_record(bytes)?;
        if record.schema != 1
            || record.kind != "composition-recipe"
            || record.fsmeta_abi != FSMETA_ABI
            || record.namespace_abi != NAMESPACE_ABI
            || record.overlay_profile != OVERLAY_PROFILE
        {
            return Err(CompositionError::Invalid(
                "unsupported composition recipe profile",
            ));
        }
        let recipe = Self {
            platform: record.platform.into(),
            layers: record.layers,
        };
        require_canonical(bytes, &recipe.canonical_bytes()?)?;
        Ok(recipe)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmetaIdentity {
    pub digest: ContentDigest,
    pub length: u64,
    pub uuid: [u8; 16],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackRange {
    pub stream: StreamIdentity,
    pub offset: u64,
    pub length: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionResult {
    pub recipe: CompositionRecipeId,
    pub fsmeta: FsmetaIdentity,
    pub packs: Vec<PackRange>,
    pub lower_length: u64,
    pub lower_stream: StreamIdentity,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FsmetaRecord {
    digest: ContentDigest,
    length: u64,
    uuid: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackRecord {
    block_length: u64,
    block_offset: u64,
    length: u64,
    offset: u64,
    stream: StreamIdentity,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultRecord {
    fsmeta: FsmetaRecord,
    kind: String,
    lower_length: u64,
    lower_stream: StreamIdentity,
    packs: Vec<PackRecord>,
    recipe: CompositionRecipeId,
    schema: u64,
}

impl CompositionResult {
    fn validate(&self) -> CompositionResultValue<()> {
        check_ranges(self.fsmeta.length, &self.packs, self.lower_length)?;
        if self.fsmeta.uuid != recipe_uuid(self.recipe) {
            return Err(CompositionError::Invalid(
                "fsmeta UUID does not bind the recipe",
            ));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> CompositionResultValue<Vec<u8>> {
        self.validate()?;
        canonical(&ResultRecord {
            fsmeta: FsmetaRecord {
                digest: self.fsmeta.digest,
                length: self.fsmeta.length,
                uuid: hex_uuid(self.fsmeta.uuid),
            },
            kind: "composition-result".into(),
            lower_length: self.lower_length,
            lower_stream: self.lower_stream,
            packs: self
                .packs
                .iter()
                .map(|pack| PackRecord {
                    block_length: pack.length / PACK_ALIGNMENT,
                    block_offset: pack.offset / PACK_ALIGNMENT,
                    length: pack.length,
                    offset: pack.offset,
                    stream: pack.stream,
                })
                .collect(),
            recipe: self.recipe,
            schema: 1,
        })
    }
    pub fn id(&self) -> CompositionResultValue<CompositionResultId> {
        Ok(CompositionResultId::of_record(&self.canonical_bytes()?))
    }
    pub fn decode(bytes: &[u8]) -> CompositionResultValue<Self> {
        let record: ResultRecord = decode_record(bytes)?;
        if record.schema != 1 || record.kind != "composition-result" {
            return Err(CompositionError::Invalid(
                "unsupported composition result schema",
            ));
        }
        check_layer_count(record.packs.len())?;
        let mut packs = Vec::with_capacity(record.packs.len());
        for pack in record.packs {
            if pack.block_length.checked_mul(PACK_ALIGNMENT) != Some(pack.length)
                || pack.block_offset.checked_mul(PACK_ALIGNMENT) != Some(pack.offset)
            {
                return Err(CompositionError::Invalid(
                    "pack byte and block ranges disagree",
                ));
            }
            packs.push(PackRange {
                stream: pack.stream,
                offset: pack.offset,
                length: pack.length,
            });
        }
        let result = Self {
            recipe: record.recipe,
            fsmeta: FsmetaIdentity {
                digest: record.fsmeta.digest,
                length: record.fsmeta.length,
                uuid: parse_uuid(&record.fsmeta.uuid)?,
            },
            packs,
            lower_length: record.lower_length,
            lower_stream: record.lower_stream,
        };
        require_canonical(bytes, &result.canonical_bytes()?)?;
        Ok(result)
    }

    /// Bind a decoded result to an authenticated recipe, without reading files.
    pub fn validate_recipe(&self, recipe: &CompositionRecipe) -> CompositionResultValue<()> {
        self.validate()?;
        if self.recipe != recipe.id()? || self.packs.len() != recipe.layers.len() {
            return Err(CompositionError::ResultMismatch);
        }
        Ok(())
    }

    pub fn logical_extents(&self) -> impl Iterator<Item = LogicalExtent> + '_ {
        logical_extents(self.fsmeta, &self.packs)
    }
}

/// Identity of the whole backing object; never a host path or descriptor text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentSource {
    Fsmeta(ContentDigest),
    Pack {
        occurrence: usize,
        stream: StreamIdentity,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogicalExtent {
    pub source: ExtentSource,
    pub offset: u64,
    pub length: u64,
}
fn logical_extents(
    fsmeta: FsmetaIdentity,
    packs: &[PackRange],
) -> impl Iterator<Item = LogicalExtent> + '_ {
    std::iter::once(LogicalExtent {
        source: ExtentSource::Fsmeta(fsmeta.digest),
        offset: 0,
        length: fsmeta.length,
    })
    .chain(
        packs
            .iter()
            .enumerate()
            .map(|(occurrence, pack)| LogicalExtent {
                source: ExtentSource::Pack {
                    occurrence,
                    stream: pack.stream,
                },
                offset: pack.offset,
                length: pack.length,
            }),
    )
}

/// Structurally authenticated fsmeta, awaiting the storage-owned stream hash.
#[derive(Debug)]
pub struct PreparedComposition {
    recipe: CompositionRecipeId,
    fsmeta: FsmetaIdentity,
    packs: Vec<PackRange>,
    lower_length: u64,
    expected_lower: Option<StreamIdentity>,
}
impl PreparedComposition {
    pub fn recipe_id(&self) -> CompositionRecipeId {
        self.recipe
    }
    pub fn fsmeta(&self) -> &FsmetaIdentity {
        &self.fsmeta
    }
    pub fn pack_ranges(&self) -> &[PackRange] {
        &self.packs
    }
    pub fn lower_length(&self) -> u64 {
        self.lower_length
    }
    /// Whole-object occurrences, including zero-length slots. Feed these to the
    /// existing libvm VMDK planner, which splits at 2 GiB and omits zero extents.
    pub fn logical_extents(&self) -> impl Iterator<Item = LogicalExtent> + '_ {
        logical_extents(self.fsmeta, &self.packs)
    }
    /// The caller computes this identity over exact fsmeta + occurrence bytes
    /// with the existing storage StreamHasher, not SHA256 of the concatenation.
    pub fn finalize(
        self,
        lower_stream: StreamIdentity,
    ) -> CompositionResultValue<CompositionResult> {
        if self
            .expected_lower
            .is_some_and(|expected| expected != lower_stream)
        {
            return Err(CompositionError::ResultMismatch);
        }
        let result = CompositionResult {
            recipe: self.recipe,
            fsmeta: self.fsmeta,
            packs: self.packs,
            lower_length: self.lower_length,
            lower_stream,
        };
        result.validate()?;
        Ok(result)
    }
    fn bind_retained(mut self, retained: &CompositionResult) -> CompositionResultValue<Self> {
        retained.validate()?;
        if self.recipe != retained.recipe
            || self.fsmeta != retained.fsmeta
            || self.packs != retained.packs
            || self.lower_length != retained.lower_length
        {
            return Err(CompositionError::ResultMismatch);
        }
        self.expected_lower = Some(retained.lower_stream);
        Ok(self)
    }
}

/// Re-authenticate canonical indexes and rebuild the namespace before encoding.
/// `layers` carries held, exact, previously stream-authenticated pack handles.
pub fn prepare(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    output: &mut File,
) -> CompositionResultValue<PreparedComposition> {
    let namespace = authenticate_namespace(recipe, layers)?;
    let recipe_id = recipe.id()?;
    let encoded = erofs::encode(&namespace, layers, &recipe_id.to_string(), output)?;
    prepared(recipe_id, layers, encoded)
}

/// Validate retained exact fsmeta without invoking an encoder or rewriting it.
/// Finalization also requires the independently authenticated retained lower ID.
pub fn load_exact(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    retained: &CompositionResult,
    fsmeta: &File,
) -> CompositionResultValue<PreparedComposition> {
    load_retained(
        recipe,
        layers,
        retained,
        fsmeta,
        |file, namespace, layers, id| {
            erofs::validate(file, namespace, layers, id).map(|encoded| (encoded, ()))
        },
    )
    .map(|(_, prepared, ())| prepared)
}

/// The authenticated namespace of the exact retained lower, validated and
/// bound like `load_exact`, for rendering it without any source blob.
pub(crate) fn load_namespace(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    retained: &CompositionResult,
    fsmeta: &File,
) -> CompositionResultValue<ValidatedNamespace> {
    load_retained(
        recipe,
        layers,
        retained,
        fsmeta,
        |file, namespace, layers, id| {
            erofs::validate(file, namespace, layers, id).map(|encoded| (encoded, ()))
        },
    )
    .map(|(namespace, _, ())| namespace)
}

/// The exact retained lower as an OverlayFS guest observed it: the
/// authenticated namespace plus every inode's EROFS export identity.
pub(crate) fn load_exported(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    retained: &CompositionResult,
    fsmeta: &File,
) -> CompositionResultValue<(ValidatedNamespace, crate::erofs::handles::ExportHandles)> {
    load_retained(recipe, layers, retained, fsmeta, erofs::validate_exported)
        .map(|(namespace, _, handles)| (namespace, handles))
}

/// Shared retained-lower authentication: the storage owner has already
/// authenticated each held pack's stream and keeps the descriptors immutable;
/// this re-authenticates indexes and namespace, strictly validates fsmeta and
/// binds every metadata identity and range to the retained result.
fn load_retained<T>(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    retained: &CompositionResult,
    fsmeta: &File,
    validate: impl FnOnce(
        &File,
        &ValidatedNamespace,
        &[Layer<'_>],
        &str,
    ) -> Result<(EncodedFsmeta, T), ErofsError>,
) -> CompositionResultValue<(ValidatedNamespace, PreparedComposition, T)> {
    retained.validate_recipe(recipe)?;
    let metadata = fsmeta.metadata()?;
    if !metadata.is_file() || metadata.len() != retained.fsmeta.length {
        return Err(CompositionError::ResultMismatch);
    }
    let namespace = authenticate_namespace(recipe, layers)?;
    let recipe_id = recipe.id()?;
    let (encoded, extra) = validate(fsmeta, &namespace, layers, &recipe_id.to_string())?;
    let bound = prepared(recipe_id, layers, encoded)?.bind_retained(retained)?;
    Ok((namespace, bound, extra))
}

/// Regeneration is admissible only if every retained metadata byte identity and
/// range agrees. A mismatch is an error, never permission to replace the result.
pub fn regenerate_exact(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
    retained: &CompositionResult,
    output: &mut File,
) -> CompositionResultValue<PreparedComposition> {
    retained.validate_recipe(recipe)?;
    prepare(recipe, layers, output)?.bind_retained(retained)
}

fn authenticate_namespace(
    recipe: &CompositionRecipe,
    layers: &[Layer<'_>],
) -> CompositionResultValue<ValidatedNamespace> {
    recipe.validate()?;
    if layers.len() != recipe.layers.len() {
        return Err(CompositionError::Invalid(
            "layer occurrence count differs from recipe",
        ));
    }
    for (binding, layer) in recipe.layers.iter().zip(layers) {
        if layer.result.id()? != binding.result
            || layer.result.index_root != binding.index_root
            || layer.result.recipe
                != (LayerRecipe {
                    diff_id: layer.changeset.diff_id,
                })
                .id()?
            || layer.result.pack_length != layer.changeset.pack_length
        {
            return Err(CompositionError::Invalid(
                "layer result differs from recipe or changeset",
            ));
        }
        let root = encode_index_to(layer.changeset, &FORMAT_LIMITS, |_| Ok(()))?;
        if root.digest != binding.index_root {
            return Err(CompositionError::Invalid(
                "changeset differs from authenticated index root",
            ));
        }
        let metadata = layer.pack.metadata()?;
        if !metadata.is_file() || metadata.len() != layer.result.pack_length {
            return Err(CompositionError::Invalid(
                "pack handle is not an exact regular object",
            ));
        }
    }
    let changesets = layers
        .iter()
        .map(|layer| layer.changeset)
        .collect::<Vec<_>>();
    Ok(compose(&changesets, &FORMAT_LIMITS)?)
}
fn prepared(
    recipe: CompositionRecipeId,
    layers: &[Layer<'_>],
    encoded: EncodedFsmeta,
) -> CompositionResultValue<PreparedComposition> {
    let packs = encoded
        .device_ranges
        .into_iter()
        .map(|range| PackRange {
            stream: range.stream,
            offset: range.offset,
            length: range.length,
        })
        .collect::<Vec<_>>();
    if packs.len() != layers.len()
        || packs.iter().zip(layers).any(|(pack, layer)| {
            pack.stream != layer.result.pack_stream || pack.length != layer.result.pack_length
        })
    {
        return Err(CompositionError::Invalid(
            "encoded device ranges differ from layer occurrences",
        ));
    }
    let lower_length = packs
        .iter()
        .try_fold(encoded.length, |end, pack| end.checked_add(pack.length))
        .ok_or(CompositionError::Invalid("logical lower length overflow"))?;
    check_ranges(encoded.length, &packs, lower_length)?;
    if encoded.uuid != recipe_uuid(recipe) {
        return Err(CompositionError::Invalid(
            "encoded UUID differs from recipe",
        ));
    }
    Ok(PreparedComposition {
        recipe,
        fsmeta: FsmetaIdentity {
            digest: encoded.digest,
            length: encoded.length,
            uuid: encoded.uuid,
        },
        packs,
        lower_length,
        expected_lower: None,
    })
}

/// Canonical layer-result and authenticated paged-index loading. The storage
/// owner still authenticates `result.pack_stream` using its existing stream ABI.
#[derive(Debug)]
pub struct AuthenticatedLayer {
    pub result: LayerResult,
    pub changeset: LayerChangeset,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LayerResultRecord {
    index_root: ContentDigest,
    kind: String,
    pack_length: u64,
    pack_stream: StreamIdentity,
    recipe: crate::changeset::LayerRecipeId,
    schema: u64,
}
pub fn authenticate_layer(
    expected: LayerResultId,
    result_bytes: &[u8],
    root_bytes: &[u8],
    read_object: impl FnMut(ContentDigest) -> crate::changeset::ChangesetResult<Vec<u8>>,
    diff_id: ContentDigest,
    limits: &ChangesetLimits,
) -> CompositionResultValue<AuthenticatedLayer> {
    if root_bytes.len() as u64 > crate::changeset::limits::MAX_ROOT_BYTES {
        return Err(CompositionError::Invalid("index root exceeds format bound"));
    }
    let record: LayerResultRecord = decode_record(result_bytes)?;
    if record.schema != 1 || record.kind != "layer-result" {
        return Err(CompositionError::Invalid("unsupported layer result schema"));
    }
    let result = LayerResult {
        recipe: record.recipe,
        pack_stream: record.pack_stream,
        pack_length: record.pack_length,
        index_root: record.index_root,
    };
    require_canonical(result_bytes, &result.canonical_bytes()?)?;
    if result.id()? != expected
        || result.index_root != ContentDigest::of_bytes(root_bytes)
        || result.recipe != (LayerRecipe { diff_id }).id()?
    {
        return Err(CompositionError::Invalid(
            "layer result or index authentication failed",
        ));
    }
    let changeset = decode_index(root_bytes, read_object, diff_id, limits)?;
    if changeset.pack_length != result.pack_length {
        return Err(CompositionError::Invalid(
            "layer index and result lengths disagree",
        ));
    }
    Ok(AuthenticatedLayer { result, changeset })
}

fn check_layer_count(count: usize) -> CompositionResultValue<()> {
    if count as u64 > FORMAT_LIMITS.max_layers {
        return Err(CompositionError::Invalid("too many layer occurrences"));
    }
    Ok(())
}
fn check_ranges(fsmeta: u64, packs: &[PackRange], total: u64) -> CompositionResultValue<()> {
    check_layer_count(packs.len())?;
    if fsmeta == 0 || fsmeta > MAX_FSMETA_BYTES || !fsmeta.is_multiple_of(PACK_ALIGNMENT) {
        return Err(CompositionError::Invalid("invalid fsmeta length"));
    }
    let mut cursor = fsmeta;
    for pack in packs {
        if pack.offset != cursor || !pack.length.is_multiple_of(PACK_ALIGNMENT) {
            return Err(CompositionError::Invalid(
                "unaligned or noncontiguous pack occurrence",
            ));
        }
        cursor = cursor
            .checked_add(pack.length)
            .ok_or(CompositionError::Invalid("pack range overflow"))?;
        if cursor > MAX_LOWER_BYTES {
            return Err(CompositionError::Invalid(
                "logical lower exceeds format bound",
            ));
        }
    }
    if cursor != total || total > MAX_LOWER_BYTES {
        return Err(CompositionError::Invalid("logical lower length mismatch"));
    }
    Ok(())
}
fn recipe_uuid(recipe: CompositionRecipeId) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"silo-erofs-uuid-v1\n");
    hash.update(recipe.to_string().as_bytes());
    let digest = hash.finalize();
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}
fn hex_uuid(uuid: [u8; 16]) -> String {
    // Every UUID nibble is encoded directly, with no native-endian conversion.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in uuid {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    value
}
fn parse_uuid(text: &str) -> CompositionResultValue<[u8; 16]> {
    if text.len() != 32 {
        return Err(CompositionError::Invalid("invalid UUID length"));
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CompositionError::Invalid("noncanonical UUID")),
    };
    let mut uuid = [0; 16];
    for (slot, pair) in uuid.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(uuid)
}
fn canonical(value: &impl Serialize) -> CompositionResultValue<Vec<u8>> {
    let bytes = wire::canonical_bytes(value)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CompositionError::Invalid(
            "composition record exceeds bound",
        ));
    }
    Ok(bytes)
}
fn decode_record<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> CompositionResultValue<T> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CompositionError::Invalid(
            "composition record exceeds bound",
        ));
    }
    let value = wire::strict_value(bytes)?;
    if !value.is_object() {
        return Err(CompositionError::Invalid("expected a JSON object"));
    }
    Ok(serde_json::from_value(value)?)
}
fn require_canonical(actual: &[u8], expected: &[u8]) -> CompositionResultValue<()> {
    if actual != expected {
        return Err(CompositionError::Invalid("noncanonical record spelling"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs::File, io::Read, os::unix::fs::FileExt};

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use crate::changeset::index::{encode_index, LayerRecipe, LayerResult};
    use crate::changeset::{
        ChangeEntry, ChangesetError, ChangesetLimits, ContentDigest, EntryKind, LayerChangeset,
        Metadata, MetadataPresence, PayloadRef, StreamIdentity,
    };
    use crate::composition::{
        authenticate_layer, load_exact, prepare, regenerate_exact, CompositionError,
        CompositionRecipe, CompositionRecipeId, CompositionResult, ExtentSource, LayerBinding,
        MAX_LOWER_BYTES, MAX_RECORD_BYTES,
    };
    use crate::erofs::Layer;
    use crate::vm_artifact::wire;
    use crate::Platform;

    struct Fixture {
        changeset: LayerChangeset,
        result: LayerResult,
        pack: File,
        root: Vec<u8>,
        pages: BTreeMap<ContentDigest, Vec<u8>>,
    }
    impl Fixture {
        fn new(body: Option<&[u8]>) -> Self {
            let mut changeset = LayerChangeset {
                diff_id: ContentDigest::of_bytes(b"composition test layer"),
                pack_length: 0,
                entries: Vec::new(),
            };
            let pack = tempfile::tempfile().unwrap();
            if let Some(body) = body {
                changeset.pack_length = (body.len() as u64).div_ceil(4096) * 4096;
                changeset.entries.push(ChangeEntry {
                    ordinal: 0,
                    path: b"payload".to_vec(),
                    metadata: Metadata {
                        uid: 0,
                        gid: 0,
                        mode: 0o644,
                        mtime_seconds: 0,
                        mtime_nanos: 0,
                        xattrs: vec![],
                    },
                    presence: MetadataPresence::default(),
                    kind: EntryKind::Regular(PayloadRef {
                        pack_offset: 0,
                        length: body.len() as u64,
                        sparse: vec![],
                    }),
                });
                pack.set_len(changeset.pack_length).unwrap();
                pack.write_all_at(body, 0).unwrap();
            }
            let index = encode_index(&changeset, &ChangesetLimits::default()).unwrap();
            let result = LayerResult {
                recipe: (LayerRecipe {
                    diff_id: changeset.diff_id,
                })
                .id()
                .unwrap(),
                // Unit-test input token supplied at the storage-owned stream
                // authentication boundary, not a second stream-hash algorithm.
                pack_stream: StreamIdentity::from_sha256([7; 32]),
                pack_length: changeset.pack_length,
                index_root: index.root.digest,
            };
            Self {
                changeset,
                result,
                pack,
                root: index.root.bytes,
                pages: index
                    .pages
                    .into_iter()
                    .map(|page| (page.digest, page.bytes))
                    .collect(),
            }
        }
        fn layer(&self) -> Layer<'_> {
            Layer {
                result: &self.result,
                changeset: &self.changeset,
                pack: &self.pack,
            }
        }
    }
    fn lower() -> StreamIdentity {
        StreamIdentity::from_sha256([19; 32])
    }
    fn bytes(file: &File) -> Vec<u8> {
        let mut output = Vec::new();
        let mut cloned = file.try_clone().unwrap();
        std::io::Seek::rewind(&mut cloned).unwrap();
        cloned.read_to_end(&mut output).unwrap();
        output
    }
    fn mutate_record(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        mutate(&mut value);
        wire::canonical_bytes(&value).unwrap()
    }
    fn empty_result() -> (CompositionRecipe, CompositionResult, File) {
        let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &[]).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &[], &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        (recipe, result, fsmeta)
    }

    #[test]
    fn empty_recipe_has_exact_canonical_bytes_and_domain_separated_ids() {
        let (recipe, result, _) = empty_result();
        let expected = br#"{"fsmetaAbi":"silo-erofs-v1","kind":"composition-recipe","layers":[],"namespaceAbi":"silo-namespace-v1","overlayProfile":"silo-overlay-v1","platform":{"architecture":"amd64","os":"linux"},"schema":1}"#;
        assert_eq!(recipe.canonical_bytes().unwrap(), expected);
        let mut independent = Sha256::new();
        independent.update(b"silo:composition-recipe:v1\n");
        independent.update(expected);
        let recipe_hash: [u8; 32] = independent.finalize().into();
        assert_eq!(recipe.id().unwrap().as_bytes(), &recipe_hash);
        let raw_hash: [u8; 32] = Sha256::digest(expected).into();
        assert_ne!(recipe_hash, raw_hash);
        let result_bytes = result.canonical_bytes().unwrap();
        let mut independent_result = Sha256::new();
        independent_result.update(b"silo:composition-result:v1\n");
        independent_result.update(&result_bytes);
        let result_hash: [u8; 32] = independent_result.finalize().into();
        assert_eq!(result.id().unwrap().as_bytes(), &result_hash);
        assert_eq!(CompositionRecipe::decode(expected).unwrap(), recipe);
        assert_eq!(CompositionResult::decode(&result_bytes).unwrap(), result);
        assert_eq!(result.fsmeta.uuid[6] >> 4, 8);
        assert_eq!(result.fsmeta.uuid[8] >> 6, 2);
        let mut uuid_hash = Sha256::new();
        uuid_hash.update(b"silo-erofs-uuid-v1\n");
        uuid_hash.update(recipe.id().unwrap().to_string());
        let mut uuid: [u8; 16] = uuid_hash.finalize()[..16].try_into().unwrap();
        uuid[6] = (uuid[6] & 15) | 0x80;
        uuid[8] = (uuid[8] & 63) | 0x80;
        assert_eq!(result.fsmeta.uuid, uuid);
    }

    #[test]
    fn recipe_identity_binds_order_repeats_index_root_platform_and_result() {
        let a = Fixture::new(Some(b"first"));
        let mut b = Fixture::new(Some(b"second"));
        b.result.pack_stream = StreamIdentity::from_sha256([8; 32]);
        let ab = CompositionRecipe::from_layers(Platform::linux_amd64(), &[a.layer(), b.layer()])
            .unwrap();
        let ba = CompositionRecipe::from_layers(Platform::linux_amd64(), &[b.layer(), a.layer()])
            .unwrap();
        assert_ne!(ab.id().unwrap(), ba.id().unwrap());
        let mut changed = ab.clone();
        changed.layers.push(changed.layers[0]);
        assert_ne!(ab.id().unwrap(), changed.id().unwrap());
        changed = ab.clone();
        changed.layers[0].index_root = ContentDigest::of_bytes(b"other root");
        assert_ne!(ab.id().unwrap(), changed.id().unwrap());
        changed = ab.clone();
        changed.layers[0].result = b.result.id().unwrap();
        assert_ne!(ab.id().unwrap(), changed.id().unwrap());
        changed = ab.clone();
        changed.platform = Platform::linux_arm64();
        assert_ne!(ab.id().unwrap(), changed.id().unwrap());
        changed = ab.clone();
        changed.platform.variant = Some("v8".into());
        assert_ne!(ab.id().unwrap(), changed.id().unwrap());
    }

    #[test]
    fn repeated_and_empty_occurrences_retain_slots_and_ranges() {
        let a = Fixture::new(Some(b"payload"));
        let empty = Fixture::new(None);
        let layers = [
            empty.layer(),
            a.layer(),
            empty.layer(),
            a.layer(),
            empty.layer(),
        ];
        let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &layers).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let prepared = prepare(&recipe, &layers, &mut fsmeta).unwrap();
        let start = prepared.fsmeta().length;
        let extents = prepared.logical_extents().collect::<Vec<_>>();
        assert_eq!(extents.len(), 6);
        assert_eq!(
            extents[0].source,
            ExtentSource::Fsmeta(prepared.fsmeta().digest)
        );
        assert_eq!(
            prepared
                .pack_ranges()
                .iter()
                .map(|range| (range.offset, range.length))
                .collect::<Vec<_>>(),
            vec![
                (start, 0),
                (start, 4096),
                (start + 4096, 0),
                (start + 4096, 4096),
                (start + 8192, 0)
            ]
        );
        for (occurrence, extent) in extents.iter().skip(1).enumerate() {
            assert!(
                matches!(extent.source, ExtentSource::Pack { occurrence: value, .. } if value == occurrence)
            );
        }
        assert_eq!(prepared.lower_length(), start + 8192);
        let result = prepared.finalize(lower()).unwrap();
        assert_eq!(
            CompositionResult::decode(&result.canonical_bytes().unwrap()).unwrap(),
            result
        );
        assert_eq!(
            load_exact(&recipe, &layers, &result, &fsmeta)
                .unwrap()
                .finalize(lower())
                .unwrap(),
            result
        );
    }

    #[test]
    fn zero_layers_and_metadata_only_layers_are_distinct_real_images() {
        let (empty_recipe, empty_result, _) = empty_result();
        let layer = Fixture::new(None);
        let layers = [layer.layer()];
        let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &layers).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &layers, &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        assert_ne!(recipe.id().unwrap(), empty_recipe.id().unwrap());
        assert_ne!(result.fsmeta.digest, empty_result.fsmeta.digest);
        assert_eq!(result.packs.len(), 1);
        assert_eq!(result.packs[0].length, 0);
        assert_eq!(result.lower_length, result.fsmeta.length);
        assert_eq!(
            result
                .logical_extents()
                .filter(|extent| extent.length != 0)
                .count(),
            1
        );
    }

    #[test]
    fn strict_recipe_decoder_rejects_shape_aliases_profiles_and_noncanonical_json() {
        let fixture = Fixture::new(None);
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &[fixture.layer()]).unwrap();
        let encoded = recipe.canonical_bytes().unwrap();
        for mutation in [
            mutate_record(&encoded, |v| v["namespaceAbi"] = json!("other")),
            mutate_record(&encoded, |v| v["fsmetaAbi"] = json!("other")),
            mutate_record(&encoded, |v| v["overlayProfile"] = json!("other")),
            mutate_record(&encoded, |v| v["kind"] = json!("other")),
            mutate_record(&encoded, |v| v["schema"] = json!(2)),
            mutate_record(&encoded, |v| v["schema"] = json!("1")),
            mutate_record(&encoded, |v| v["unexpected"] = json!(1)),
            mutate_record(&encoded, |v| v["platform"]["unexpected"] = json!(1)),
            mutate_record(&encoded, |v| {
                v["platform"] = json!(["amd64", "linux", null])
            }),
            mutate_record(&encoded, |v| v["layers"][0]["unexpected"] = json!(1)),
            mutate_record(&encoded, |v| {
                v["layers"][0] = json!([fixture.result.id().unwrap(), fixture.result.index_root])
            }),
            mutate_record(&encoded, |v| v["platform"]["os"] = json!("windows")),
            mutate_record(&encoded, |v| v["platform"]["variant"] = json!(null)),
        ] {
            assert!(
                CompositionRecipe::decode(&mutation).is_err(),
                "accepted {}",
                String::from_utf8_lossy(&mutation)
            );
        }
        let text = String::from_utf8(encoded.clone()).unwrap();
        for mutation in [
            format!(" {text}"),
            format!("{text}\n"),
            text.replace("\"schema\":1", "\"schema\":1.0"),
            text.replace("\"schema\":1", "\"schema\":1e0"),
            text.replace("\"schema\":1", "\"schema\":9007199254740992"),
            text.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
            text.replace("\"os\":\"linux\"", "\"os\":\"linux\",\"os\":\"linux\""),
            text.replace("\"linux\"", "\"lin\\u0075x\""),
            "[]".into(),
            "null".into(),
        ] {
            assert!(CompositionRecipe::decode(mutation.as_bytes()).is_err());
        }
        assert!(CompositionRecipe::decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
        assert!(text
            .replace("sha256:", "SHA256:")
            .parse::<CompositionRecipeId>()
            .is_err());
        let uppercase = recipe.id().unwrap().to_string().to_ascii_uppercase();
        assert!(uppercase.parse::<CompositionRecipeId>().is_err());
    }

    #[test]
    fn strict_result_decoder_rejects_nested_aliases_and_corrupt_geometry() {
        let fixture = Fixture::new(Some(b"payload"));
        let layers = [fixture.layer()];
        let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &layers).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &layers, &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        let encoded = result.canonical_bytes().unwrap();
        for mutation in [
            mutate_record(&encoded, |v| v["schema"] = json!(0)),
            mutate_record(&encoded, |v| v["kind"] = json!("layer-result")),
            mutate_record(&encoded, |v| v["extra"] = json!(0)),
            mutate_record(&encoded, |v| v["fsmeta"]["extra"] = json!(0)),
            mutate_record(&encoded, |v| v["fsmeta"]["length"] = json!(0)),
            mutate_record(&encoded, |v| v["fsmeta"]["length"] = json!(4097)),
            mutate_record(&encoded, |v| {
                v["fsmeta"]["uuid"] = json!("00000000000000000000000000000000")
            }),
            mutate_record(&encoded, |v| {
                v["fsmeta"]["uuid"] = json!(v["fsmeta"]["uuid"].as_str().unwrap().to_uppercase())
            }),
            mutate_record(&encoded, |v| {
                v["fsmeta"] = json!([
                    result.fsmeta.digest,
                    result.fsmeta.length,
                    v["fsmeta"]["uuid"]
                ])
            }),
            mutate_record(&encoded, |v| v["packs"][0]["extra"] = json!(0)),
            mutate_record(&encoded, |v| {
                v["packs"][0]["offset"] = json!(result.fsmeta.length + 4096)
            }),
            mutate_record(&encoded, |v| v["packs"][0]["blockOffset"] = json!(0)),
            mutate_record(&encoded, |v| v["packs"][0]["blockLength"] = json!(0)),
            mutate_record(&encoded, |v| v["packs"][0]["length"] = json!(1)),
            mutate_record(&encoded, |v| {
                v["lowerLength"] = json!(result.lower_length + 4096)
            }),
            mutate_record(&encoded, |v| {
                v["lowerLength"] = json!(MAX_LOWER_BYTES + 4096)
            }),
        ] {
            assert!(
                CompositionResult::decode(&mutation).is_err(),
                "accepted {}",
                String::from_utf8_lossy(&mutation)
            );
        }
    }

    #[test]
    fn authenticated_indexes_results_pages_and_diff_ids_are_all_bound() {
        let fixture = Fixture::new(Some(b"payload"));
        let expected = fixture.result.id().unwrap();
        let result_bytes = fixture.result.canonical_bytes().unwrap();
        let authenticate = |result: &[u8], root: &[u8], corrupt_page: bool, diff_id| {
            authenticate_layer(
                expected,
                result,
                root,
                |digest| {
                    let mut page = fixture
                        .pages
                        .get(&digest)
                        .cloned()
                        .ok_or_else(|| ChangesetError::Invalid("missing page".into()))?;
                    if corrupt_page {
                        page.push(b' ');
                    }
                    Ok(page)
                },
                diff_id,
                &ChangesetLimits::default(),
            )
        };
        let authenticated = authenticate(
            &result_bytes,
            &fixture.root,
            false,
            fixture.changeset.diff_id,
        )
        .unwrap();
        assert_eq!(authenticated.changeset, fixture.changeset);
        assert_eq!(authenticated.result, fixture.result);
        let mut root = fixture.root.clone();
        root.push(b' ');
        assert!(authenticate(&result_bytes, &root, false, fixture.changeset.diff_id).is_err());
        assert!(authenticate(
            &result_bytes,
            &fixture.root,
            true,
            fixture.changeset.diff_id
        )
        .is_err());
        assert!(authenticate(
            &result_bytes,
            &fixture.root,
            false,
            ContentDigest::of_bytes(b"other diff")
        )
        .is_err());
        let result = mutate_record(&result_bytes, |v| v["packLength"] = json!(0));
        assert!(authenticate(&result, &fixture.root, false, fixture.changeset.diff_id).is_err());
        let result = mutate_record(&result_bytes, |v| v["extra"] = json!(0));
        assert!(authenticate(&result, &fixture.root, false, fixture.changeset.diff_id).is_err());
        let result = format!("{} ", String::from_utf8(result_bytes).unwrap());
        assert!(authenticate(
            result.as_bytes(),
            &fixture.root,
            false,
            fixture.changeset.diff_id
        )
        .is_err());
    }

    #[test]
    fn prepare_rejects_unbound_changesets_wrong_results_and_pack_lengths() {
        let mut fixture = Fixture::new(Some(b"payload"));
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &[fixture.layer()]).unwrap();
        let mut output = tempfile::tempfile().unwrap();
        fixture.changeset.entries[0].path = b"other".to_vec();
        assert!(prepare(&recipe, &[fixture.layer()], &mut output).is_err());
        fixture.changeset.entries[0].path = b"payload".to_vec();
        fixture.pack.set_len(8192).unwrap();
        assert!(prepare(&recipe, &[fixture.layer()], &mut output).is_err());
        fixture.pack.set_len(4096).unwrap();
        fixture.result.pack_stream = StreamIdentity::from_sha256([8; 32]);
        assert!(prepare(&recipe, &[fixture.layer()], &mut output).is_err());
        assert!(prepare(&recipe, &[], &mut output).is_err());
    }

    #[test]
    fn exact_loading_and_regeneration_refuse_every_retained_identity_mismatch() {
        let fixture = Fixture::new(Some(b"payload"));
        let layers = [fixture.layer()];
        let recipe = CompositionRecipe::from_layers(Platform::linux_amd64(), &layers).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &layers, &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        let mut regenerated = tempfile::tempfile().unwrap();
        let prepared = regenerate_exact(&recipe, &layers, &result, &mut regenerated).unwrap();
        assert_eq!(bytes(&fsmeta), bytes(&regenerated));
        assert_eq!(prepared.finalize(lower()).unwrap(), result);
        assert!(matches!(
            load_exact(&recipe, &layers, &result, &fsmeta)
                .unwrap()
                .finalize(StreamIdentity::from_sha256([2; 32])),
            Err(CompositionError::ResultMismatch)
        ));
        let mut mismatched = result.clone();
        mismatched.fsmeta.digest = ContentDigest::of_bytes(b"wrong fsmeta");
        assert!(matches!(
            load_exact(&recipe, &layers, &mismatched, &fsmeta),
            Err(CompositionError::ResultMismatch)
        ));
        assert!(matches!(
            regenerate_exact(&recipe, &layers, &mismatched, &mut regenerated),
            Err(CompositionError::ResultMismatch)
        ));
        mismatched = result.clone();
        mismatched.packs[0].stream = StreamIdentity::from_sha256([1; 32]);
        assert!(load_exact(&recipe, &layers, &mismatched, &fsmeta).is_err());
        assert!(regenerate_exact(&recipe, &layers, &mismatched, &mut regenerated).is_err());
        fsmeta.write_all_at(&[1], 4096 + 72).unwrap();
        assert!(load_exact(&recipe, &layers, &result, &fsmeta).is_err());
    }

    #[test]
    fn determinism_ignores_host_file_path_cursor_and_sparse_allocation() {
        let fixture = Fixture::new(Some(&vec![0; 4097]));
        fixture.pack.set_len(0).unwrap();
        fixture.pack.set_len(8192).unwrap();
        let dense = tempfile::NamedTempFile::new().unwrap();
        dense.as_file().write_all_at(&vec![0; 8192], 0).unwrap();
        let layers_sparse = [fixture.layer()];
        let layers_dense = [Layer {
            result: &fixture.result,
            changeset: &fixture.changeset,
            pack: dense.as_file(),
        }];
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &layers_sparse).unwrap();
        let mut first = tempfile::NamedTempFile::new().unwrap();
        let mut second = tempfile::NamedTempFile::new().unwrap();
        use std::io::{Seek, SeekFrom};
        first.as_file_mut().seek(SeekFrom::Start(17)).unwrap();
        second.as_file_mut().seek(SeekFrom::Start(65536)).unwrap();
        let a = prepare(&recipe, &layers_sparse, first.as_file_mut())
            .unwrap()
            .finalize(lower())
            .unwrap();
        let b = prepare(&recipe, &layers_dense, second.as_file_mut())
            .unwrap()
            .finalize(lower())
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(bytes(first.as_file()), bytes(second.as_file()));
    }

    #[test]
    fn bounds_reject_too_many_occurrences_and_oversized_ranges_without_payloads() {
        let fixture = Fixture::new(None);
        let binding = LayerBinding {
            result: fixture.result.id().unwrap(),
            index_root: fixture.result.index_root,
        };
        let mut recipe = CompositionRecipe {
            platform: Platform::linux_amd64(),
            layers: vec![binding; 1024],
        };
        assert!(recipe.canonical_bytes().is_ok());
        recipe.layers.push(binding);
        assert!(recipe.canonical_bytes().is_err());
        let (_, mut result, _) = empty_result();
        result.fsmeta.length = 4 * 1024 * 1024 * 1024 + 4096;
        assert!(result.canonical_bytes().is_err());
        let (_, mut result, _) = empty_result();
        result.packs.push(crate::composition::PackRange {
            stream: lower(),
            offset: result.fsmeta.length,
            length: MAX_LOWER_BYTES,
        });
        result.lower_length += MAX_LOWER_BYTES;
        assert!(result.canonical_bytes().is_err());
        result.packs[0].length = u64::MAX - 4095;
        assert!(result.canonical_bytes().is_err());
    }

    #[test]
    fn empty_regular_body_keeps_empty_pack_and_nonzero_final_padding_is_rejected() {
        let empty = Fixture::new(Some(b""));
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &[empty.layer()]).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &[empty.layer()], &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        assert_eq!(result.packs[0].length, 0);
        assert_eq!(empty.pack.metadata().unwrap().len(), 0);
        load_exact(&recipe, &[empty.layer()], &result, &fsmeta).unwrap();

        let short = Fixture::new(Some(b"x"));
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &[short.layer()]).unwrap();
        short.pack.write_all_at(&[1], 4095).unwrap();
        assert!(prepare(&recipe, &[short.layer()], &mut fsmeta).is_err());
    }

    #[test]
    fn exact_loading_refuses_truncation_trailing_bytes_and_output_pack_aliases() {
        let fixture = Fixture::new(Some(b"payload"));
        let recipe =
            CompositionRecipe::from_layers(Platform::linux_amd64(), &[fixture.layer()]).unwrap();
        let mut fsmeta = tempfile::tempfile().unwrap();
        let result = prepare(&recipe, &[fixture.layer()], &mut fsmeta)
            .unwrap()
            .finalize(lower())
            .unwrap();
        fsmeta.set_len(result.fsmeta.length + 4096).unwrap();
        assert!(matches!(
            load_exact(&recipe, &[fixture.layer()], &result, &fsmeta),
            Err(CompositionError::ResultMismatch)
        ));
        fsmeta.set_len(result.fsmeta.length - 1).unwrap();
        assert!(matches!(
            load_exact(&recipe, &[fixture.layer()], &result, &fsmeta),
            Err(CompositionError::ResultMismatch)
        ));
        let original = bytes(&fixture.pack);
        let mut alias = fixture.pack.try_clone().unwrap();
        assert!(prepare(&recipe, &[fixture.layer()], &mut alias).is_err());
        assert_eq!(bytes(&fixture.pack), original);
    }
}

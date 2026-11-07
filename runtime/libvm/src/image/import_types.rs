//! Typed managed-image requests and inspection data. Inspection is not a lease.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::storage::identity::{ImageId, ObjectDigest, SnapshotId};
use crate::store::models::image::ImageRecord;
use crate::store::models::storage::{LinuxPlatform, RootSelector};
use crate::store::snapshot_store::SnapshotInfo;
use crate::LibVmError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ImportRootSelection {
    WholeDisk,
    AutoGpt,
    GptPartition { guid: uuid::Uuid },
    MbrPartition { number: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BootAssetSelection {
    Packaged,
    Files {
        kernel: PathBuf,
        base_initramfs: PathBuf,
        agent: Option<PathBuf>,
    },
    Exact {
        bundle: ObjectDigest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DiskImportBoot {
    LinuxDirect {
        platform: LinuxPlatform,
        root: ImportRootSelection,
        assets: BootAssetSelection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskImportRequest {
    pub path: PathBuf,
    pub boot: DiskImportBoot,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ManagedSourceRef {
    Alias(String),
    Image(ImageId),
    Snapshot(SnapshotId),
}

impl std::fmt::Display for ManagedSourceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alias(name) => write!(f, "image:{name}"),
            Self::Image(id) => write!(f, "image:{id}"),
            Self::Snapshot(id) => write!(f, "image:{id}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ManagedSourceId {
    Image(ImageId),
    Snapshot(SnapshotId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootAssetsUpdate {
    pub selection: BootAssetSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawConversionOptions {
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawConversionKey {
    pub source_manifest: ObjectDigest,
    pub platform: LinuxPlatform,
    pub flattener_abi: String,
}

impl RawConversionKey {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LibVmError> {
        self.platform.validate()?;
        if self.flattener_abi.is_empty() {
            return Err(crate::store::models::snapshot::invalid(
                "empty flattener ABI",
            ));
        }
        let bytes = crate::store::models::snapshot::canonical_value(
            &serde_json::to_value(self).map_err(crate::store::models::snapshot::invalid)?,
        )?;
        crate::storage::limits::Resource::MetadataPageBytes
            .check(bytes.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<ObjectDigest, LibVmError> {
        Ok(ObjectDigest::of_bytes(&self.canonical_bytes()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageContainerKind {
    Raw,
    Qcow2,
    Oci,
}

/// Appendable diagnostic facts, not dependencies or canonical image identity.
/// A source-container digest does not assert that its bytes remain retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageProvenance {
    pub container: ImageContainerKind,
    pub source_digest: ObjectDigest,
    pub source_spelling: String,
    pub source_manifest: Option<ObjectDigest>,
    pub source_config: Option<ObjectDigest>,
    pub disk: Option<DiskImportFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskImportFacts {
    pub source_length: u64,
    pub decoded_length: u64,
    pub selected_root: Option<RootCandidate>,
}

/// Complete diagnostic response, never a truncated history. Managed-image
/// inspection/list admission allows at most one `MetadataPageBytes` (4 MiB)
/// and `MetadataPageEntries` (4096 entries) aggregate, including canonical
/// records, aliases, provenance and conversion metadata. Larger appendable
/// catalogs remain consumable and collectable through bounded authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedImageInfo {
    pub id: ImageId,
    pub record_digest: ObjectDigest,
    pub record: ImageRecord,
    pub aliases: Vec<String>,
    pub retained: bool,
    pub provenance: Vec<ImageProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "info",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ManagedSourceInfo {
    Image(Box<ManagedImageInfo>),
    Snapshot(SnapshotInfo),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootCandidate {
    pub selector: RootSelector,
    pub first_lba: u64,
    pub length_lbas: u64,
    pub gpt_type: Option<uuid::Uuid>,
    pub mbr_type: Option<u8>,
    /// GPT bitmask encoded as sixteen lowercase hex digits in JSON.
    /// DPS flags occupy bits beyond the exact JSON integer range.
    #[serde(with = "partition_attributes")]
    pub attributes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootSelectionFailed {
    pub requested: ImportRootSelection,
    pub candidates: Vec<RootCandidate>,
    pub reason: String,
}

mod partition_attributes {
    pub fn serialize<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        struct Hex(u64);
        impl std::fmt::Display for Hex {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:016x}", self.0)
            }
        }
        serializer.collect_str(&Hex(*value))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        if value.len() != 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "partition attributes require sixteen lowercase hex digits",
            ));
        }
        u64::from_str_radix(&value, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::image::import_types::RootCandidate;

    #[test]
    fn partition_attributes_preserve_high_bits_in_canonical_provenance() {
        for attributes in [0, 1 << 59, 1 << 60, 1 << 63, u64::MAX] {
            let candidate = RootCandidate {
                selector: crate::RootSelector::GptPartition {
                    guid: uuid::Uuid::from_u128(1),
                },
                first_lba: 2048,
                length_lbas: 4096,
                gpt_type: Some(uuid::Uuid::from_u128(2)),
                mbr_type: None,
                attributes,
            };
            let value = serde_json::to_value(&candidate).unwrap();
            let bytes = crate::store::models::snapshot::canonical_value(&value).unwrap();
            let decoded: RootCandidate = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded, candidate);
            for invalid in [
                serde_json::json!(attributes),
                serde_json::json!("800000000000000"),
                serde_json::json!("80000000000000000"),
                serde_json::json!("FFFFFFFFFFFFFFFF"),
                serde_json::json!("000000000000000g"),
            ] {
                let mut malformed = value.clone();
                malformed["attributes"] = invalid;
                assert!(serde_json::from_value::<RootCandidate>(malformed).is_err());
            }
        }
    }
}

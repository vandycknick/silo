use std::path::PathBuf;

use crate::image::ImageSourceKind;

use super::MachineId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageManifestRecord {
    pub digest: String,
    pub media_type: String,
    pub image_id: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub platform_variant: Option<String>,
    pub config_digest: Option<String>,
    pub layer_count: i64,
    pub total_size_bytes: i64,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRefRecord {
    pub reference: String,
    pub manifest_digest: String,
    pub image_id: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub platform_variant: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageConfigRecord {
    pub manifest_digest: String,
    pub digest: Option<String>,
    pub env_json: String,
    pub cmd_json: String,
    pub entrypoint_json: String,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    pub labels_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageLayerRecord {
    pub diff_id: String,
    pub blob_digest: String,
    pub media_type: String,
    pub compressed_size_bytes: Option<u64>,
    pub uncompressed_size_bytes: Option<u64>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageManifestLayerRecord {
    pub manifest_digest: String,
    pub layer_diff_id: String,
    pub position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRootfsArtifactRecord {
    pub image_id: String,
    pub source_kind: ImageSourceKind,
    pub manifest_digest: Option<String>,
    pub source_reference: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub platform_variant: Option<String>,
    pub filesystem: String,
    pub rootfs_path: PathBuf,
    pub size_bytes: u64,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineRootfsRecord {
    pub machine_id: MachineId,
    pub source_kind: ImageSourceKind,
    pub source_reference: String,
    pub manifest_digest: Option<String>,
    pub image_id: Option<String>,
    pub root_disk_path: PathBuf,
    pub root_disk_size_bytes: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OciImageRecord {
    pub manifest: ImageManifestRecord,
    pub reference: ImageRefRecord,
    pub config: ImageConfigRecord,
    pub layers: Vec<ImageLayerRecord>,
    pub manifest_layers: Vec<ImageManifestLayerRecord>,
    pub artifact: ImageRootfsArtifactRecord,
}

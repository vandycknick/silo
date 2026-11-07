use std::path::PathBuf;

use crate::image::{ImageSourceKind, OciImageConfigMetadata};

use crate::store::models::MachineId;

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
    pub requested_reference: String,
    pub selected_reference: String,
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
    pub digest: String,
    pub metadata: OciImageConfigMetadata,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageLayerRecord {
    pub diff_id: String,
    pub blob_digest: String,
    pub compressed_size_bytes: Option<u64>,
    pub uncompressed_size_bytes: Option<u64>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageManifestLayerRecord {
    pub manifest_digest: String,
    pub layer_diff_id: String,
    pub layer_blob_digest: String,
    pub media_type: String,
    pub position: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRootfsArtifactRecord {
    pub image_id: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub platform_variant: Option<String>,
    pub filesystem: String,
    pub rootfs_path: PathBuf,
    pub size_bytes: u64,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub stream_id: crate::storage::identity::StreamId,
    pub conversion_abi: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineRootfsRecord {
    pub machine_id: MachineId,
    pub source_kind: ImageSourceKind,
    pub requested_reference: String,
    pub selected_reference: Option<String>,
    pub manifest_digest: Option<String>,
    pub config_digest: Option<String>,
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

/// Only outcomes whose bytes and durable deletion jobs remain safely retained
/// belong here. Corruption, unsafe ownership and failed transactions are errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CacheCleanupDeferral {
    ExternalDependency { machine: String, path: PathBuf },
    ActiveLease { operation_id: uuid::Uuid },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CacheRecoveryReport {
    pub deferred: Vec<CacheCleanupDeferral>,
}

/// Immutable reusable raw image semantics, distinct from captured machines.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRecord {
    pub schema: u32,
    pub kind: ImageRecordKind,
    pub root: crate::store::models::snapshot::SnapshotRoot,
    pub boot: crate::store::models::storage::BootProfile,
    pub process: crate::ProcessConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageRecordKind {
    Image,
}

impl ImageRecord {
    pub fn validate(&self) -> Result<(), crate::LibVmError> {
        use crate::store::models::snapshot::{invalid, validate_geometry, SnapshotRootProfile};
        use crate::store::models::storage::{validate_root_selection, BootBinding, BootProfile};
        if self.schema != 1 || self.root.profile != SnapshotRootProfile::OpaqueRaw {
            return Err(invalid("image requires current schema and opaque raw root"));
        }
        validate_geometry(&self.root.stream, &self.root.geometry)?;
        let expected_pages = self
            .root
            .stream
            .length
            .div_ceil(crate::storage::limits::CHUNK_SIZE as u64)
            .div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
        if self.root.stream.map_pages.len() as u64 != expected_pages {
            return Err(invalid("image map page count contradicts stream length"));
        }
        self.boot.validate()?;
        let BootProfile::LinuxDirect {
            binding: BootBinding::Pinned { abi, .. },
            root_selector,
            ..
        } = &self.boot
        else {
            return Err(invalid(
                "image requires a complete pinned Linux direct bundle",
            ));
        };
        if abi != crate::runtime::boot_assets::DIRECT_BOOT_ABI {
            return Err(invalid("unsupported image direct boot ABI"));
        }
        validate_root_selection(&self.root.layout, root_selector)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::LibVmError> {
        self.validate()?;
        let bytes = crate::store::models::snapshot::canonical_value(
            &serde_json::to_value(self).map_err(crate::store::models::snapshot::invalid)?,
        )?;
        crate::storage::limits::Resource::MetadataPageBytes
            .check(bytes.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        Ok(bytes)
    }

    pub fn id(&self) -> Result<crate::storage::identity::ImageId, crate::LibVmError> {
        Ok(image_id(&self.canonical_bytes()?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, crate::LibVmError> {
        use crate::store::models::snapshot::invalid;
        crate::storage::limits::Resource::MetadataPageBytes
            .check(bytes.len() as u64)
            .map_err(crate::storage::StorageError::from)?;
        let value = crate::store::models::snapshot::decode_identity_value(bytes)?;
        let record: Self = serde_json::from_value(value.clone()).map_err(invalid)?;
        if serde_json::to_value(&record).map_err(invalid)? != value {
            return Err(invalid("image is not the closed current schema"));
        }
        record.validate()?;
        Ok(record)
    }

    pub fn boot_binding(
        &self,
    ) -> Result<&crate::store::models::storage::BootBinding, crate::LibVmError> {
        match &self.boot {
            crate::store::models::storage::BootProfile::LinuxDirect { binding, .. } => Ok(binding),
            _ => Err(crate::store::models::snapshot::invalid(
                "image has no direct boot binding",
            )),
        }
    }

    pub(crate) fn content_dependencies(
        &self,
    ) -> Result<
        (
            std::collections::BTreeSet<crate::storage::identity::StreamId>,
            std::collections::BTreeSet<crate::storage::identity::ObjectDigest>,
        ),
        crate::LibVmError,
    > {
        use crate::store::models::storage::BootBinding;
        let mut objects = std::collections::BTreeSet::from([self.root.stream.map]);
        objects.extend(self.root.stream.map_pages.iter().copied());
        let binding = self.boot_binding()?;
        let BootBinding::Pinned {
            kernel,
            base_initramfs,
            agent,
            ..
        } = binding
        else {
            return Err(crate::store::models::snapshot::invalid(
                "image boot bundle is not pinned",
            ));
        };
        objects.extend([binding.digest()?, *kernel, *base_initramfs]);
        objects.extend(agent.iter().copied());
        Ok((
            std::collections::BTreeSet::from([self.root.stream.stream]),
            objects,
        ))
    }
}

pub(crate) fn image_id(canonical: &[u8]) -> crate::storage::identity::ImageId {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"silo:image:v1\n");
    hash.update(canonical);
    crate::storage::identity::ImageId::from_sha256(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use crate::storage::identity::{ObjectDigest, StreamId};
    use crate::store::models::image::{ImageRecord, ImageRecordKind};
    use crate::store::models::storage::{
        BootBinding, BootProfile, PartitionTable, RawLayout, RootSelector,
    };

    fn image() -> ImageRecord {
        let snapshot = crate::store::models::snapshot::tests::record(
            StreamId::from_sha256([1; 32]),
            ObjectDigest::of_bytes(b"map"),
            ObjectDigest::of_bytes(b"kernel"),
        );
        ImageRecord {
            schema: 1,
            kind: ImageRecordKind::Image,
            root: snapshot.root,
            boot: snapshot.boot,
            process: crate::ProcessConfig::default(),
        }
    }

    #[test]
    fn image_identity_binds_semantics_but_not_snapshot_capture_configuration() {
        let record = image();
        let bytes = record.canonical_bytes().unwrap();
        assert_eq!(ImageRecord::decode(&bytes).unwrap(), record);
        let snapshot = crate::store::models::snapshot::tests::record(
            record.root.stream.stream,
            record.root.stream.map,
            ObjectDigest::of_bytes(b"kernel"),
        );
        assert_ne!(
            record.id().unwrap().to_string(),
            snapshot.id().unwrap().to_string()
        );
        let mut changed = record.clone();
        changed.process.entrypoint = Some(vec!["/init".into()]);
        assert_ne!(changed.id().unwrap(), record.id().unwrap());
        assert_eq!(changed.root.stream.stream, record.root.stream.stream);
        changed = record.clone();
        if let BootProfile::LinuxDirect {
            binding: BootBinding::Pinned { kernel, .. },
            ..
        } = &mut changed.boot
        {
            *kernel = ObjectDigest::of_bytes(b"replacement kernel");
        }
        assert_ne!(changed.id().unwrap(), record.id().unwrap());
        changed = record.clone();
        changed.root.layout = RawLayout::Partitioned {
            table: PartitionTable::Gpt,
        };
        if let BootProfile::LinuxDirect { root_selector, .. } = &mut changed.boot {
            *root_selector = RootSelector::GptPartition {
                guid: uuid::Uuid::from_bytes([9; 16]),
            };
        }
        assert_ne!(changed.id().unwrap(), record.id().unwrap());
        assert_eq!(changed.root.stream, record.root.stream);
        changed = record.clone();
        if let BootProfile::LinuxDirect {
            userspace_platform,
            kernel_architecture,
            binding: BootBinding::Pinned { architecture, .. },
            ..
        } = &mut changed.boot
        {
            userspace_platform.architecture = crate::GuestArchitecture::Arm64;
            *kernel_architecture = crate::GuestArchitecture::Arm64;
            *architecture = crate::GuestArchitecture::Arm64;
        }
        assert_ne!(changed.id().unwrap(), record.id().unwrap());
        assert_eq!(changed.root.stream.stream, record.root.stream.stream);
    }

    #[test]
    fn image_rejects_missing_unknown_duplicate_and_noncanonical_metadata() {
        let record = image();
        let bytes = record.canonical_bytes().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["schema", "kind", "root", "boot", "process"] {
            let mut value = original.clone();
            value.as_object_mut().unwrap().remove(field);
            let bytes = crate::store::models::snapshot::canonical_value(&value).unwrap();
            assert!(ImageRecord::decode(&bytes).is_err(), "{field}");
        }
        let mut value = original.clone();
        value["process"]["extra"] = true.into();
        assert!(ImageRecord::decode(
            &crate::store::models::snapshot::canonical_value(&value).unwrap()
        )
        .is_err());
        let mut value = original.clone();
        value["boot"]
            .as_object_mut()
            .unwrap()
            .remove("rootFilesystem");
        assert!(ImageRecord::decode(
            &crate::store::models::snapshot::canonical_value(&value).unwrap()
        )
        .is_err());
        let mut value = original.clone();
        value["boot"]["rootFilesystem"] = "btrfs".into();
        assert!(ImageRecord::decode(
            &crate::store::models::snapshot::canonical_value(&value).unwrap()
        )
        .is_err());
        let duplicate = format!(
            "{{\"schema\":1,{}",
            std::str::from_utf8(&bytes[1..]).unwrap()
        );
        assert!(ImageRecord::decode(duplicate.as_bytes()).is_err());
        assert!(ImageRecord::decode(&[bytes.as_slice(), b" "].concat()).is_err());
        assert!(ImageRecord::decode(&serde_json::to_vec_pretty(&original).unwrap()).is_err());
    }

    #[test]
    fn image_requires_pinned_complete_bundle_and_exact_raw_selection() {
        let record = image();
        let mut changed = record.clone();
        if let BootProfile::LinuxDirect { binding, .. } = &mut changed.boot {
            *binding = BootBinding::RuntimeSelected;
        }
        assert!(changed.validate().is_err());
        changed = record.clone();
        changed.root.geometry.length += 512;
        assert!(changed.validate().is_err());
        changed = record.clone();
        changed.root.stream.map_pages.clear();
        assert!(changed.validate().is_err());
        for selector in [
            RootSelector::GptPartition {
                guid: uuid::Uuid::nil(),
            },
            RootSelector::GptPartition {
                guid: uuid::Uuid::from_bytes([2; 16]),
            },
            RootSelector::MbrPartition { number: 4 },
            RootSelector::ManagedOverlay,
        ] {
            changed = record.clone();
            if let BootProfile::LinuxDirect { root_selector, .. } = &mut changed.boot {
                *root_selector = selector;
            }
            assert!(changed.validate().is_err());
        }
        let binding = record.boot_binding().unwrap();
        let bytes = binding.canonical_bytes().unwrap();
        assert_eq!(BootBinding::decode(&bytes).unwrap(), *binding);
        assert_eq!(binding.digest().unwrap(), ObjectDigest::of_bytes(&bytes));
        assert!(BootBinding::RuntimeSelected.canonical_bytes().is_err());
    }
}

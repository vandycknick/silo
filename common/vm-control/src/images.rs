use crate::{invalid, required, ConversionError};
use libvm::storage::identity::ObjectDigest;
use silod_spec::daemon::v1 as w;
pub fn progress_to_wire(v: &libvm::ImageProgress) -> Result<w::ImageProgress, ConversionError> {
    use w::image_progress::Event;
    Ok(w::ImageProgress {
        event: Some(match v {
            libvm::ImageProgress::ResolvingManifest { image_ref } => {
                Event::ResolvingManifest(w::ImageReferenceProgress {
                    image_ref: image_ref.clone(),
                })
            }
            libvm::ImageProgress::CheckingCache { image_ref } => {
                Event::CheckingCache(w::ImageReferenceProgress {
                    image_ref: image_ref.clone(),
                })
            }
            libvm::ImageProgress::CacheHit { image_ref } => {
                Event::CacheHit(w::ImageReferenceProgress {
                    image_ref: image_ref.clone(),
                })
            }
            libvm::ImageProgress::CacheMiss { image_ref } => {
                Event::CacheMiss(w::ImageReferenceProgress {
                    image_ref: image_ref.clone(),
                })
            }
            libvm::ImageProgress::UsingLocalDisk { image_ref } => {
                Event::UsingLocalDisk(w::ImageReferenceProgress {
                    image_ref: image_ref.clone(),
                })
            }
            libvm::ImageProgress::ResolvedManifest {
                image_ref,
                manifest_digest,
                layer_count,
                total_download_bytes,
            } => Event::ResolvedManifest(w::ManifestProgress {
                image_ref: image_ref.clone(),
                manifest_digest: manifest_digest.clone(),
                layer_count: (*layer_count)
                    .try_into()
                    .map_err(|_| invalid("layer_count", "overflow"))?,
                total_download_bytes: *total_download_bytes,
            }),
            libvm::ImageProgress::LayerDownloadStarted {
                index,
                total,
                digest,
                size_bytes,
            } => Event::LayerDownloadStarted(w::LayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
                size_bytes: *size_bytes,
                downloaded_bytes: 0,
            }),
            libvm::ImageProgress::LayerDownloadProgress {
                index,
                total,
                digest,
                size_bytes,
                downloaded_bytes,
            } => Event::LayerDownloadProgress(w::LayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
                size_bytes: *size_bytes,
                downloaded_bytes: *downloaded_bytes,
            }),
            libvm::ImageProgress::LayerDownloadVerifying {
                index,
                total,
                digest,
            } => Event::LayerDownloadVerifying(w::LayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
                size_bytes: None,
                downloaded_bytes: 0,
            }),
            libvm::ImageProgress::LayerDownloadFinished {
                index,
                total,
                digest,
            } => Event::LayerDownloadFinished(w::LayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
                size_bytes: None,
                downloaded_bytes: 0,
            }),
            libvm::ImageProgress::LayerDownloadSkipped {
                index,
                total,
                digest,
            } => Event::LayerDownloadSkipped(w::LayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
                size_bytes: None,
                downloaded_bytes: 0,
            }),
            libvm::ImageProgress::ApplyingLayer {
                index,
                total,
                digest,
            } => Event::ApplyingLayer(w::ApplyingLayerProgress {
                index: (*index)
                    .try_into()
                    .map_err(|_| invalid("index", "overflow"))?,
                total: (*total)
                    .try_into()
                    .map_err(|_| invalid("total", "overflow"))?,
                digest: digest.clone(),
            }),
            libvm::ImageProgress::MaterializingRootfs => Event::MaterializingRootfs(()),
            libvm::ImageProgress::PublishingRootfs => Event::PublishingRootfs(()),
            libvm::ImageProgress::Complete => Event::Complete(()),
        }),
    })
}
pub fn progress_from_wire(v: w::ImageProgress) -> Result<libvm::ImageProgress, ConversionError> {
    use w::image_progress::Event;
    Ok(match required(v.event, "image_progress.event")? {
        Event::ResolvingManifest(v) => libvm::ImageProgress::ResolvingManifest {
            image_ref: v.image_ref,
        },
        Event::CheckingCache(v) => libvm::ImageProgress::CheckingCache {
            image_ref: v.image_ref,
        },
        Event::CacheHit(v) => libvm::ImageProgress::CacheHit {
            image_ref: v.image_ref,
        },
        Event::CacheMiss(v) => libvm::ImageProgress::CacheMiss {
            image_ref: v.image_ref,
        },
        Event::UsingLocalDisk(v) => libvm::ImageProgress::UsingLocalDisk {
            image_ref: v.image_ref,
        },
        Event::ResolvedManifest(v) => libvm::ImageProgress::ResolvedManifest {
            image_ref: v.image_ref,
            manifest_digest: v.manifest_digest,
            layer_count: v
                .layer_count
                .try_into()
                .map_err(|_| invalid("layer_count", "overflow"))?,
            total_download_bytes: v.total_download_bytes,
        },
        Event::LayerDownloadStarted(v) => libvm::ImageProgress::LayerDownloadStarted {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
            size_bytes: v.size_bytes,
        },
        Event::LayerDownloadProgress(v) => libvm::ImageProgress::LayerDownloadProgress {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
            size_bytes: v.size_bytes,
            downloaded_bytes: v.downloaded_bytes,
        },
        Event::LayerDownloadVerifying(v) => libvm::ImageProgress::LayerDownloadVerifying {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
        },
        Event::LayerDownloadFinished(v) => libvm::ImageProgress::LayerDownloadFinished {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
        },
        Event::LayerDownloadSkipped(v) => libvm::ImageProgress::LayerDownloadSkipped {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
        },
        Event::ApplyingLayer(v) => libvm::ImageProgress::ApplyingLayer {
            index: v
                .index
                .try_into()
                .map_err(|_| invalid("index", "overflow"))?,
            total: v
                .total
                .try_into()
                .map_err(|_| invalid("total", "overflow"))?,
            digest: v.digest,
        },
        Event::MaterializingRootfs(()) => libvm::ImageProgress::MaterializingRootfs,
        Event::PublishingRootfs(()) => libvm::ImageProgress::PublishingRootfs,
        Event::Complete(()) => libvm::ImageProgress::Complete,
    })
}
pub fn pull_policy_to_wire(v: libvm::ImagePullPolicy) -> i32 {
    match v {
        libvm::ImagePullPolicy::IfMissing => 1,
        libvm::ImagePullPolicy::Always => 2,
        libvm::ImagePullPolicy::Never => 3,
    }
}
pub fn pull_policy_from_wire(v: i32) -> Result<libvm::ImagePullPolicy, ConversionError> {
    match v {
        1 => Ok(libvm::ImagePullPolicy::IfMissing),
        2 => Ok(libvm::ImagePullPolicy::Always),
        3 => Ok(libvm::ImagePullPolicy::Never),
        _ => Err(invalid("pull_policy", "invalid enum")),
    }
}
#[derive(Debug, Clone)]
pub struct OciIdentity {
    pub requested_reference: String,
    pub selected_reference: String,
    pub platform: libvm::Platform,
    pub manifest_digest: String,
    pub config_digest: String,
    pub pull_policy: libvm::ImagePullPolicy,
}
impl OciIdentity {
    pub fn verify(&self, image: &libvm::ResolvedOciImage) -> Result<(), ConversionError> {
        if self.selected_reference != image.selected_reference
            || self.platform != image.platform
            || self.manifest_digest != image.manifest_digest
            || self.config_digest != image.config_digest
        {
            return Err(invalid(
                "oci_identity",
                "resolved immutable identity mismatch",
            ));
        }
        Ok(())
    }
}
pub fn identity_to_wire(
    v: &libvm::ResolvedOciImage,
    policy: libvm::ImagePullPolicy,
) -> w::OciIdentity {
    w::OciIdentity {
        requested_reference: v.requested_reference.clone(),
        selected_reference: v.selected_reference.clone(),
        platform: v.platform.to_string(),
        manifest_digest: v.manifest_digest.clone(),
        config_digest: v.config_digest.clone(),
        pull_policy: pull_policy_to_wire(policy),
    }
}
pub fn identity_from_wire(v: w::OciIdentity) -> Result<OciIdentity, ConversionError> {
    let mut parts = v.platform.split('/');
    let os = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("platform", "missing OS"))?;
    let architecture = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid("platform", "missing architecture"))?;
    let variant = parts.next();
    if variant == Some("") || parts.next().is_some() {
        return Err(invalid("platform", "invalid variant"));
    }
    if v.requested_reference.is_empty()
        || v.selected_reference.is_empty()
        || v.manifest_digest.is_empty()
        || v.config_digest.is_empty()
    {
        return Err(invalid("oci_identity", "missing immutable identity"));
    }
    if !v
        .selected_reference
        .rsplit_once('@')
        .is_some_and(|(repository, digest)| !repository.is_empty() && digest == v.manifest_digest)
    {
        return Err(invalid(
            "selected_reference",
            "not pinned to manifest digest",
        ));
    }
    let platform = libvm::Platform {
        os: os.into(),
        architecture: architecture.into(),
        variant: variant.map(str::to_owned),
    };
    Ok(OciIdentity {
        requested_reference: v.requested_reference,
        selected_reference: v.selected_reference,
        platform,
        manifest_digest: v.manifest_digest,
        config_digest: v.config_digest,
        pull_policy: pull_policy_from_wire(v.pull_policy)?,
    })
}
pub fn resolved_image_to_wire(
    v: &libvm::ResolvedOciImage,
    policy: libvm::ImagePullPolicy,
) -> Result<w::ResolvedImage, ConversionError> {
    Ok(w::ResolvedImage {
        identity: Some(identity_to_wire(v, policy)),
        cache_state: match v.cache_state {
            libvm::ImageCacheState::Complete => 1,
            libvm::ImageCacheState::Missing => 2,
        },
        oci_config_json: serde_json::to_string(&v.config)
            .map_err(|_| invalid("oci_config_json", "cannot encode OCI config"))?,
    })
}
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub identity: OciIdentity,
    pub cache_state: libvm::ImageCacheState,
    pub config: libvm::OciImageConfigMetadata,
}
pub fn resolved_image_from_wire(v: w::ResolvedImage) -> Result<ResolvedImage, ConversionError> {
    Ok(ResolvedImage {
        identity: identity_from_wire(required(v.identity, "image.identity")?)?,
        cache_state: match v.cache_state {
            1 => libvm::ImageCacheState::Complete,
            2 => libvm::ImageCacheState::Missing,
            _ => return Err(invalid("cache_state", "invalid enum")),
        },
        config: serde_json::from_str(&v.oci_config_json)
            .map_err(|_| invalid("oci_config_json", "invalid OCI config"))?,
    })
}

const MAX_LISTED: usize = 4096;
const MAX_SPELLING_BYTES: usize = 4096;

/// `ResolveImage` request: an optional requested Linux platform. The selected
/// platform remains part of the resolved identity.
pub fn resolve_request_to_wire(
    reference: String,
    policy: libvm::ImagePullPolicy,
    platform: Option<&libvm::LinuxPlatform>,
) -> w::ResolveImageRequest {
    w::ResolveImageRequest {
        reference,
        pull_policy: pull_policy_to_wire(policy),
        platform: platform.map(crate::boot::platform_to_wire),
    }
}

pub fn resolve_options_from_wire(
    v: &w::ResolveImageRequest,
) -> Result<libvm::ImageResolveOptions, ConversionError> {
    Ok(libvm::ImageResolveOptions {
        policy: Some(pull_policy_from_wire(v.pull_policy)?),
        platform: v
            .platform
            .clone()
            .map(crate::boot::platform_from_wire)
            .transpose()?,
    })
}

impl OciIdentity {
    /// Re-resolution options for exactly this selected identity and platform.
    pub fn resolve_options(&self) -> Result<libvm::ImageResolveOptions, ConversionError> {
        Ok(libvm::ImageResolveOptions {
            policy: Some(self.pull_policy),
            platform: Some(crate::boot::platform_from_oci(&self.platform)?),
        })
    }
}

/// A user-facing `image:` spelling. A bare digest carries no kind and must be
/// resolved to a typed reference before use; no kind is ever preferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedSpelling {
    Reference(libvm::ManagedSourceRef),
    Digest(ObjectDigest),
}

pub fn parse_managed(value: &str) -> Result<ManagedSpelling, ConversionError> {
    let value = value
        .strip_prefix("image:")
        .ok_or_else(|| invalid("image", "expected image:NAME or image:sha256:HEX"))?;
    if value.starts_with("sha256:") {
        return Ok(ManagedSpelling::Digest(crate::boot::digest_from_wire(
            value, "image",
        )?));
    }
    Ok(ManagedSpelling::Reference(libvm::ManagedSourceRef::Alias(
        crate::stopped::alias(value)?,
    )))
}

pub fn managed_id_to_ref(value: libvm::ManagedSourceId) -> libvm::ManagedSourceRef {
    match value {
        libvm::ManagedSourceId::Image(id) => libvm::ManagedSourceRef::Image(id),
        libvm::ManagedSourceId::Snapshot(id) => libvm::ManagedSourceRef::Snapshot(id),
    }
}

pub fn managed_ref_to_wire(
    value: &libvm::ManagedSourceRef,
) -> Result<w::ManagedSourceRef, ConversionError> {
    use w::managed_source_ref::Reference;
    Ok(w::ManagedSourceRef {
        reference: Some(match value {
            libvm::ManagedSourceRef::Alias(alias) => {
                Reference::Alias(crate::stopped::alias(alias)?)
            }
            libvm::ManagedSourceRef::Image(id) => Reference::ImageId(id.to_string()),
            libvm::ManagedSourceRef::Snapshot(id) => Reference::SnapshotId(id.to_string()),
        }),
    })
}

pub fn managed_ref_from_wire(
    value: w::ManagedSourceRef,
) -> Result<libvm::ManagedSourceRef, ConversionError> {
    use w::managed_source_ref::Reference;
    Ok(match required(value.reference, "managed.reference")? {
        Reference::Alias(alias) => libvm::ManagedSourceRef::Alias(crate::stopped::alias(&alias)?),
        Reference::ImageId(id) => libvm::ManagedSourceRef::Image(
            id.parse()
                .map_err(|_| invalid("managed.image_id", "invalid image identity"))?,
        ),
        Reference::SnapshotId(id) => libvm::ManagedSourceRef::Snapshot(
            id.parse()
                .map_err(|_| invalid("managed.snapshot_id", "invalid snapshot identity"))?,
        ),
    })
}

pub fn managed_digest_to_wire(value: &ObjectDigest) -> w::ManagedDigest {
    w::ManagedDigest {
        digest: value.to_string(),
    }
}

pub fn managed_digest_from_wire(value: w::ManagedDigest) -> Result<ObjectDigest, ConversionError> {
    crate::boot::digest_from_wire(&value.digest, "managed.digest")
}

pub fn managed_id_to_wire(value: &libvm::ManagedSourceId) -> w::ManagedSourceId {
    use w::managed_source_id::Id;
    w::ManagedSourceId {
        id: Some(match value {
            libvm::ManagedSourceId::Image(id) => Id::ImageId(id.to_string()),
            libvm::ManagedSourceId::Snapshot(id) => Id::SnapshotId(id.to_string()),
        }),
    }
}

pub fn managed_id_from_wire(
    value: w::ManagedSourceId,
) -> Result<libvm::ManagedSourceId, ConversionError> {
    use w::managed_source_id::Id;
    Ok(match required(value.id, "managed.id")? {
        Id::ImageId(id) => libvm::ManagedSourceId::Image(
            id.parse()
                .map_err(|_| invalid("managed.image_id", "invalid image identity"))?,
        ),
        Id::SnapshotId(id) => libvm::ManagedSourceId::Snapshot(
            id.parse()
                .map_err(|_| invalid("managed.snapshot_id", "invalid snapshot identity"))?,
        ),
    })
}

fn container_to_wire(value: libvm::ImageContainerKind) -> i32 {
    match value {
        libvm::ImageContainerKind::Raw => w::ImageContainerKind::Raw as i32,
        libvm::ImageContainerKind::Qcow2 => w::ImageContainerKind::Qcow2 as i32,
        libvm::ImageContainerKind::Oci => w::ImageContainerKind::Oci as i32,
    }
}

fn container_from_wire(value: i32) -> Result<libvm::ImageContainerKind, ConversionError> {
    match w::ImageContainerKind::try_from(value) {
        Ok(w::ImageContainerKind::Raw) => Ok(libvm::ImageContainerKind::Raw),
        Ok(w::ImageContainerKind::Qcow2) => Ok(libvm::ImageContainerKind::Qcow2),
        Ok(w::ImageContainerKind::Oci) => Ok(libvm::ImageContainerKind::Oci),
        _ => Err(invalid("provenance.container", "unknown container kind")),
    }
}

/// Disk containers carry observed import facts and no OCI manifest/config;
/// OCI provenance names the selected manifest and config, without disk facts.
fn validate_provenance(value: &libvm::ImageProvenance) -> Result<(), ConversionError> {
    if value.source_spelling.is_empty()
        || value.source_spelling.len() > MAX_SPELLING_BYTES
        || value.source_spelling.contains('\0')
    {
        return Err(invalid(
            "provenance.source_spelling",
            "empty, oversized or NUL",
        ));
    }
    let consistent = match value.container {
        libvm::ImageContainerKind::Raw | libvm::ImageContainerKind::Qcow2 => {
            value.source_manifest.is_none() && value.source_config.is_none() && value.disk.is_some()
        }
        libvm::ImageContainerKind::Oci => {
            value.source_manifest.is_some() && value.source_config.is_some() && value.disk.is_none()
        }
    };
    if !consistent {
        return Err(invalid(
            "provenance",
            "OCI identities contradict the source container",
        ));
    }
    Ok(())
}

fn provenance_to_wire(
    value: &libvm::ImageProvenance,
) -> Result<w::ImageProvenance, ConversionError> {
    validate_provenance(value)?;
    Ok(w::ImageProvenance {
        container: container_to_wire(value.container),
        source_digest: value.source_digest.to_string(),
        source_spelling: value.source_spelling.clone(),
        source_manifest: value.source_manifest.map(|digest| digest.to_string()),
        source_config: value.source_config.map(|digest| digest.to_string()),
        disk: value
            .disk
            .as_ref()
            .map(|disk| {
                Ok::<_, ConversionError>(w::DiskImportFacts {
                    source_length: disk.source_length,
                    decoded_length: disk.decoded_length,
                    selected_root: disk
                        .selected_root
                        .as_ref()
                        .map(crate::boot::root_candidate_to_wire)
                        .transpose()?,
                })
            })
            .transpose()?,
    })
}

fn provenance_from_wire(
    value: w::ImageProvenance,
) -> Result<libvm::ImageProvenance, ConversionError> {
    let digest = |value: Option<String>, field| {
        value
            .map(|value| crate::boot::digest_from_wire(&value, field))
            .transpose()
    };
    let provenance = libvm::ImageProvenance {
        container: container_from_wire(value.container)?,
        source_digest: crate::boot::digest_from_wire(
            &value.source_digest,
            "provenance.source_digest",
        )?,
        source_spelling: value.source_spelling,
        source_manifest: digest(value.source_manifest, "provenance.source_manifest")?,
        source_config: digest(value.source_config, "provenance.source_config")?,
        disk: value
            .disk
            .map(|disk| {
                Ok::<_, ConversionError>(libvm::DiskImportFacts {
                    source_length: disk.source_length,
                    decoded_length: disk.decoded_length,
                    selected_root: disk
                        .selected_root
                        .map(crate::boot::root_candidate_from_wire)
                        .transpose()?,
                })
            })
            .transpose()?,
    };
    validate_provenance(&provenance)?;
    Ok(provenance)
}

fn aliases_from_wire(values: Vec<String>) -> Result<Vec<String>, ConversionError> {
    if values.len() > MAX_LISTED {
        return Err(invalid("image.aliases", "too many aliases"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in &values {
        if !seen.insert(crate::stopped::alias(value)?) {
            return Err(invalid("image.aliases", "duplicate alias"));
        }
    }
    Ok(values)
}

/// The record travels as its canonical bytes; both directions authenticate the
/// record digest, the domain-separated image identity and the closed schema.
pub fn managed_image_to_wire(
    value: &libvm::ManagedImageInfo,
) -> Result<w::ManagedImageInfo, ConversionError> {
    let record = value
        .record
        .canonical_bytes()
        .map_err(|_| invalid("image.record", "record is not canonical"))?;
    let wire = w::ManagedImageInfo {
        id: value.id.to_string(),
        record_digest: value.record_digest.to_string(),
        record,
        aliases: value.aliases.clone(),
        retained: value.retained,
        provenance: value
            .provenance
            .iter()
            .map(provenance_to_wire)
            .collect::<Result<_, _>>()?,
    };
    managed_image_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn managed_image_from_wire(
    value: w::ManagedImageInfo,
) -> Result<libvm::ManagedImageInfo, ConversionError> {
    let id: libvm::storage::identity::ImageId = value
        .id
        .parse()
        .map_err(|_| invalid("image.id", "invalid image identity"))?;
    let record_digest = crate::boot::digest_from_wire(&value.record_digest, "image.record_digest")?;
    if ObjectDigest::of_bytes(&value.record) != record_digest {
        return Err(invalid(
            "image.record_digest",
            "does not match the record bytes",
        ));
    }
    let record = libvm::ImageRecord::decode(&value.record)
        .map_err(|_| invalid("image.record", "not a canonical current image record"))?;
    if record
        .id()
        .map_err(|_| invalid("image.record", "not a canonical current image record"))?
        != id
    {
        return Err(invalid("image.id", "does not identify the record"));
    }
    if value.provenance.len() > MAX_LISTED {
        return Err(invalid("image.provenance", "too many provenance records"));
    }
    Ok(libvm::ManagedImageInfo {
        id,
        record_digest,
        record,
        aliases: aliases_from_wire(value.aliases)?,
        retained: value.retained,
        provenance: value
            .provenance
            .into_iter()
            .map(provenance_from_wire)
            .collect::<Result<_, _>>()?,
    })
}

pub fn managed_info_to_wire(
    value: &libvm::ManagedSourceInfo,
) -> Result<w::ManagedSourceInfo, ConversionError> {
    use w::managed_source_info::Info;
    Ok(w::ManagedSourceInfo {
        info: Some(match value {
            libvm::ManagedSourceInfo::Image(image) => Info::Image(managed_image_to_wire(image)?),
            libvm::ManagedSourceInfo::Snapshot(snapshot) => {
                Info::Snapshot(crate::stopped::info_to_wire(snapshot)?)
            }
        }),
    })
}

pub fn managed_info_from_wire(
    value: w::ManagedSourceInfo,
) -> Result<libvm::ManagedSourceInfo, ConversionError> {
    use w::managed_source_info::Info;
    Ok(match required(value.info, "managed.info")? {
        Info::Image(image) => {
            libvm::ManagedSourceInfo::Image(Box::new(managed_image_from_wire(image)?))
        }
        Info::Snapshot(snapshot) => {
            libvm::ManagedSourceInfo::Snapshot(crate::stopped::info_from_wire(snapshot)?)
        }
    })
}

pub fn managed_list_to_wire(
    values: &[libvm::ManagedSourceInfo],
) -> Result<w::ManagedSourceList, ConversionError> {
    if values.len() > MAX_LISTED {
        return Err(invalid("managed.list", "too many managed sources"));
    }
    Ok(w::ManagedSourceList {
        values: values
            .iter()
            .map(managed_info_to_wire)
            .collect::<Result<_, _>>()?,
    })
}

pub fn managed_list_from_wire(
    value: w::ManagedSourceList,
) -> Result<Vec<libvm::ManagedSourceInfo>, ConversionError> {
    if value.values.len() > MAX_LISTED {
        return Err(invalid("managed.list", "too many managed sources"));
    }
    value
        .values
        .into_iter()
        .map(managed_info_from_wire)
        .collect()
}

pub fn oci_identity_to_wire(source: &OciIdentity) -> w::OciIdentity {
    w::OciIdentity {
        requested_reference: source.requested_reference.clone(),
        selected_reference: source.selected_reference.clone(),
        platform: source.platform.to_string(),
        manifest_digest: source.manifest_digest.clone(),
        config_digest: source.config_digest.clone(),
        pull_policy: pull_policy_to_wire(source.pull_policy),
    }
}

pub fn convert_request_to_wire(
    source: &OciIdentity,
    options: &libvm::RawConversionOptions,
) -> Result<w::ConvertImageRequest, ConversionError> {
    Ok(w::ConvertImageRequest {
        source: Some(oci_identity_to_wire(source)),
        alias: options
            .alias
            .as_deref()
            .map(crate::stopped::alias)
            .transpose()?,
    })
}

pub fn convert_request_from_wire(
    value: w::ConvertImageRequest,
) -> Result<(OciIdentity, libvm::RawConversionOptions), ConversionError> {
    let source = identity_from_wire(required(value.source, "convert.source")?)?;
    crate::boot::platform_from_oci(&source.platform)?;
    Ok((
        source,
        libvm::RawConversionOptions {
            alias: value
                .alias
                .map(|alias| crate::stopped::alias(&alias))
                .transpose()?,
        },
    ))
}

pub fn managed_event_progress(
    value: &libvm::ImageProgress,
) -> Result<w::ManagedImageEvent, ConversionError> {
    Ok(w::ManagedImageEvent {
        event: Some(w::managed_image_event::Event::Progress(progress_to_wire(
            value,
        )?)),
    })
}

pub fn managed_event_image(
    value: &libvm::ManagedImageInfo,
) -> Result<w::ManagedImageEvent, ConversionError> {
    Ok(w::ManagedImageEvent {
        event: Some(w::managed_image_event::Event::Image(managed_image_to_wire(
            value,
        )?)),
    })
}

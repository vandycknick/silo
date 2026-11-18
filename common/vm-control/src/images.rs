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
pub fn pull_policy_to_wire(v: libvm::PullPolicy) -> i32 {
    (match v {
        libvm::PullPolicy::IfMissing => w::PullPolicy::IfMissing,
        libvm::PullPolicy::Always => w::PullPolicy::Always,
        libvm::PullPolicy::Never => w::PullPolicy::Never,
    }) as i32
}
pub fn pull_policy_from_wire(v: i32) -> Result<libvm::PullPolicy, ConversionError> {
    match w::PullPolicy::try_from(v) {
        Ok(w::PullPolicy::IfMissing) => Ok(libvm::PullPolicy::IfMissing),
        Ok(w::PullPolicy::Always) => Ok(libvm::PullPolicy::Always),
        Ok(w::PullPolicy::Never) => Ok(libvm::PullPolicy::Never),
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
    pub pull_policy: libvm::PullPolicy,
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
pub fn identity_to_wire(v: &libvm::ResolvedOciImage, policy: libvm::PullPolicy) -> w::OciIdentity {
    w::OciIdentity {
        requested_reference: v.requested_reference.clone(),
        selected_reference: v.selected_reference.clone(),
        platform: v.platform.to_string(),
        manifest_digest: v.manifest_digest.clone(),
        config_digest: v.config_digest.clone(),
        pull_policy: pull_policy_to_wire(policy),
    }
}
fn platform_from_wire(value: &str) -> Result<libvm::Platform, ConversionError> {
    let mut parts = value.split('/');
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
    Ok(libvm::Platform {
        os: os.into(),
        architecture: architecture.into(),
        variant: variant.map(str::to_owned),
    })
}
pub fn identity_from_wire(v: w::OciIdentity) -> Result<OciIdentity, ConversionError> {
    let platform = platform_from_wire(&v.platform)?;
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
    policy: libvm::PullPolicy,
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
    policy: libvm::PullPolicy,
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

pub fn reject_local_cut(value: &str) -> Result<(), ConversionError> {
    if value.starts_with("fork:") {
        return Err(invalid(
            "source",
            "local fork cut is not an identified snapshot; snapshot the child first",
        ));
    }
    Ok(())
}

fn reference_spelling(value: &str) -> Result<(), ConversionError> {
    if value.len() > MAX_SPELLING_BYTES || value.contains('\0') {
        return Err(invalid("image.reference", "oversized or NUL"));
    }
    Ok(())
}

pub fn image_ref_to_wire(value: &libvm::ImageRef) -> Result<w::ImageRef, ConversionError> {
    use w::image_ref::Reference;
    let wire = w::ImageRef {
        reference: Some(match value {
            libvm::ImageRef::Id(id) => Reference::Id(id.to_string()),
            libvm::ImageRef::Name(name) => Reference::Name(name.clone()),
        }),
    };
    image_ref_from_wire(wire.clone())?;
    Ok(wire)
}

/// A name is a local name, registry reference or unique id prefix; a full
/// id travels only as `id`.
pub fn image_ref_from_wire(value: w::ImageRef) -> Result<libvm::ImageRef, ConversionError> {
    use w::image_ref::Reference;
    match required(value.reference, "image.reference")? {
        Reference::Id(id) => {
            Ok(libvm::ImageRef::Id(id.parse().map_err(|_| {
                invalid("image.id", "invalid image identity")
            })?))
        }
        Reference::Name(name) => {
            reference_spelling(&name)?;
            match name.parse::<libvm::ImageRef>() {
                Ok(reference @ libvm::ImageRef::Name(_)) => Ok(reference),
                _ => Err(invalid("image.name", "invalid image name")),
            }
        }
    }
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

/// The record travels as its canonical bytes; both directions authenticate the
/// record digest, the domain-separated image identity and the closed schema.
pub fn stored_image_to_wire(
    value: &libvm::StoredImageInfo,
) -> Result<w::StoredImageInfo, ConversionError> {
    let record = value
        .record
        .canonical_bytes()
        .map_err(|_| invalid("image.record", "record is not canonical"))?;
    let wire = w::StoredImageInfo {
        id: value.id.to_string(),
        record_digest: value.record_digest.to_string(),
        record,
        names: value.names.clone(),
        provenance: value
            .provenance
            .iter()
            .map(provenance_to_wire)
            .collect::<Result<_, _>>()?,
    };
    stored_image_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn stored_image_from_wire(
    value: w::StoredImageInfo,
) -> Result<libvm::StoredImageInfo, ConversionError> {
    let id: libvm::ImageId = value
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
    Ok(libvm::StoredImageInfo {
        id,
        record_digest,
        record,
        names: crate::names_from_wire(value.names, "image.names")?,
        provenance: value
            .provenance
            .into_iter()
            .map(provenance_from_wire)
            .collect::<Result<_, _>>()?,
    })
}

pub fn oci_image_to_wire(value: &libvm::OciImageInfo) -> Result<w::OciImageInfo, ConversionError> {
    let wire = w::OciImageInfo {
        id: value.id.to_string(),
        names: value.names.clone(),
        config_digest: value.config_digest.clone(),
        platform: value.platform.to_string(),
        oci_config_json: serde_json::to_string(&value.config)
            .map_err(|_| invalid("image.oci_config_json", "cannot encode OCI config"))?,
        layers: value
            .layers
            .iter()
            .map(|layer| w::OciImageLayer {
                blob_digest: layer.blob_digest.clone(),
                diff_id: layer.diff_id.clone(),
                media_type: layer.media_type.clone(),
                compressed_size_bytes: layer.compressed_size_bytes,
                uncompressed_size_bytes: layer.uncompressed_size_bytes,
                position: layer.position,
            })
            .collect(),
        lower_length: value.lower_length,
        compressed_size_bytes: value.compressed_size_bytes,
        created_at: value.created_at,
        last_used_at: value.last_used_at,
    };
    oci_image_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn oci_image_from_wire(value: w::OciImageInfo) -> Result<libvm::OciImageInfo, ConversionError> {
    crate::boot::digest_from_wire(&value.config_digest, "image.config_digest")?;
    if value.layers.len() > MAX_LISTED {
        return Err(invalid("image.layers", "too many layers"));
    }
    let layers = value
        .layers
        .into_iter()
        .map(|layer| {
            crate::boot::digest_from_wire(&layer.blob_digest, "image.layer.blob_digest")?;
            crate::boot::digest_from_wire(&layer.diff_id, "image.layer.diff_id")?;
            if layer.media_type.is_empty() || layer.media_type.len() > MAX_SPELLING_BYTES {
                return Err(invalid("image.layer.media_type", "empty or oversized"));
            }
            Ok(libvm::ImageLayerDetail {
                blob_digest: layer.blob_digest,
                diff_id: layer.diff_id,
                media_type: layer.media_type,
                compressed_size_bytes: layer.compressed_size_bytes,
                uncompressed_size_bytes: layer.uncompressed_size_bytes,
                position: layer.position,
            })
        })
        .collect::<Result<_, ConversionError>>()?;
    Ok(libvm::OciImageInfo {
        id: value
            .id
            .parse()
            .map_err(|_| invalid("image.id", "invalid image identity"))?,
        names: crate::names_from_wire(value.names, "image.names")?,
        config_digest: value.config_digest,
        platform: platform_from_wire(&value.platform)?,
        config: serde_json::from_str(&value.oci_config_json)
            .map_err(|_| invalid("image.oci_config_json", "invalid OCI config"))?,
        layers,
        lower_length: value.lower_length,
        compressed_size_bytes: value.compressed_size_bytes,
        created_at: value.created_at,
        last_used_at: value.last_used_at,
    })
}

pub fn image_info_to_wire(value: &libvm::ImageInfo) -> Result<w::ImageInfo, ConversionError> {
    use w::image_info::Info;
    Ok(w::ImageInfo {
        info: Some(match value {
            libvm::ImageInfo::Oci(image) => Info::Oci(oci_image_to_wire(image)?),
            libvm::ImageInfo::Stored(image) => Info::Stored(stored_image_to_wire(image)?),
        }),
    })
}

pub fn image_info_from_wire(value: w::ImageInfo) -> Result<libvm::ImageInfo, ConversionError> {
    use w::image_info::Info;
    Ok(match required(value.info, "image.info")? {
        Info::Oci(image) => libvm::ImageInfo::Oci(Box::new(oci_image_from_wire(image)?)),
        Info::Stored(image) => libvm::ImageInfo::Stored(Box::new(stored_image_from_wire(image)?)),
    })
}

pub fn image_list_to_wire(values: &[libvm::ImageInfo]) -> Result<w::ImageList, ConversionError> {
    if values.len() > MAX_LISTED {
        return Err(invalid("image.list", "too many images"));
    }
    Ok(w::ImageList {
        images: values
            .iter()
            .map(image_info_to_wire)
            .collect::<Result<_, _>>()?,
    })
}

pub fn image_list_from_wire(value: w::ImageList) -> Result<Vec<libvm::ImageInfo>, ConversionError> {
    if value.images.len() > MAX_LISTED {
        return Err(invalid("image.list", "too many images"));
    }
    value.images.into_iter().map(image_info_from_wire).collect()
}

pub fn image_removal_to_wire(
    value: &libvm::ImageRemoval,
) -> Result<w::ImageRemoval, ConversionError> {
    let wire = w::ImageRemoval {
        id: value.id.to_string(),
        names: value.names.clone(),
        record_removed: value.record_removed,
    };
    image_removal_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn image_removal_from_wire(
    value: w::ImageRemoval,
) -> Result<libvm::ImageRemoval, ConversionError> {
    Ok(libvm::ImageRemoval {
        id: value
            .id
            .parse()
            .map_err(|_| invalid("image.id", "invalid image identity"))?,
        names: crate::names_from_wire(value.names, "image.names")?,
        record_removed: value.record_removed,
    })
}

pub fn prune_report_to_wire(value: &libvm::ImagePruneReport) -> w::ImagePruneReport {
    w::ImagePruneReport {
        images_removed: value.images_removed,
        bytes_removed: value.bytes_removed,
    }
}

pub fn prune_report_from_wire(value: w::ImagePruneReport) -> libvm::ImagePruneReport {
    libvm::ImagePruneReport {
        images_removed: value.images_removed,
        bytes_removed: value.bytes_removed,
    }
}

/// An absent policy defers to the daemon runtime's pull policy.
pub fn pull_request_to_wire(
    reference: &str,
    options: &libvm::ImagePullOptions,
) -> Result<w::PullImageRequest, ConversionError> {
    let wire = w::PullImageRequest {
        reference: reference.to_owned(),
        pull_policy: options
            .policy
            .map(pull_policy_to_wire)
            .unwrap_or(w::PullPolicy::Unspecified as i32),
    };
    pull_request_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn pull_request_from_wire(
    value: w::PullImageRequest,
) -> Result<(String, libvm::ImagePullOptions), ConversionError> {
    if value.reference.is_empty() {
        return Err(invalid("image.reference", "empty"));
    }
    reference_spelling(&value.reference)?;
    let policy = (value.pull_policy != w::PullPolicy::Unspecified as i32)
        .then(|| pull_policy_from_wire(value.pull_policy))
        .transpose()?;
    Ok((value.reference, libvm::ImagePullOptions { policy }))
}

pub fn pull_event_progress(
    value: &libvm::ImageProgress,
) -> Result<w::PullImageEvent, ConversionError> {
    Ok(w::PullImageEvent {
        event: Some(w::pull_image_event::Event::Progress(progress_to_wire(
            value,
        )?)),
    })
}

pub fn pull_event_image(value: &libvm::ImageInfo) -> Result<w::PullImageEvent, ConversionError> {
    Ok(w::PullImageEvent {
        event: Some(w::pull_image_event::Event::Image(image_info_to_wire(
            value,
        )?)),
    })
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
        name: options.name.as_deref().map(crate::local_name).transpose()?,
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
            name: value.name.as_deref().map(crate::local_name).transpose()?,
        },
    ))
}

pub fn stored_event_progress(
    value: &libvm::ImageProgress,
) -> Result<w::StoredImageEvent, ConversionError> {
    Ok(w::StoredImageEvent {
        event: Some(w::stored_image_event::Event::Progress(progress_to_wire(
            value,
        )?)),
    })
}

pub fn stored_event_image(
    value: &libvm::StoredImageInfo,
) -> Result<w::StoredImageEvent, ConversionError> {
    Ok(w::StoredImageEvent {
        event: Some(w::stored_image_event::Event::Image(stored_image_to_wire(
            value,
        )?)),
    })
}

#[cfg(test)]
mod tests {
    use silod_spec::daemon::v1 as w;

    fn oci_image() -> libvm::OciImageInfo {
        libvm::OciImageInfo {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            names: vec![
                "docker.io/library/alpine:3.21".into(),
                "alpine-local".into(),
            ],
            config_digest: format!("sha256:{}", "b".repeat(64)),
            platform: libvm::Platform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            config: serde_json::from_str("{}").unwrap(),
            layers: vec![libvm::ImageLayerDetail {
                blob_digest: format!("sha256:{}", "c".repeat(64)),
                diff_id: format!("sha256:{}", "d".repeat(64)),
                media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                compressed_size_bytes: Some(10),
                uncompressed_size_bytes: None,
                position: 0,
            }],
            lower_length: 4096,
            compressed_size_bytes: 10,
            created_at: 1,
            last_used_at: Some(2),
        }
    }

    #[test]
    fn local_cut_spelling_is_refused_with_a_hint() {
        let error = crate::images::reject_local_cut("fork:00000000-0000-4000-8000-000000000001")
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("local fork cut is not an identified snapshot; snapshot the child first"));
        assert!(crate::images::reject_local_cut("hello").is_ok());
    }

    #[test]
    fn image_refs_round_trip_names_registry_references_and_ids() {
        for value in [
            "hello",
            "abc123",
            "docker.io/library/alpine:3.21",
            "alpine:3.21",
            &format!("sha256:{}", "e".repeat(64)),
        ] {
            let reference: libvm::ImageRef = value.parse().unwrap();
            let wire = crate::images::image_ref_to_wire(&reference).unwrap();
            assert_eq!(crate::images::image_ref_from_wire(wire).unwrap(), reference);
        }
        assert!(matches!(
            crate::images::image_ref_to_wire(
                &format!("sha256:{}", "e".repeat(64)).parse().unwrap()
            )
            .unwrap()
            .reference,
            Some(w::image_ref::Reference::Id(_))
        ));
    }

    #[test]
    fn image_refs_reject_absent_invalid_and_disguised_ids() {
        use w::image_ref::Reference;
        assert!(crate::images::image_ref_from_wire(w::ImageRef::default()).is_err());
        for name in [
            String::new(),
            "Hello".into(),
            "has space".into(),
            "nul\0".into(),
            format!("sha256:{}", "e".repeat(64)),
            "a".repeat(4097),
        ] {
            let wire = w::ImageRef {
                reference: Some(Reference::Name(name.clone())),
            };
            assert!(
                crate::images::image_ref_from_wire(wire).is_err(),
                "{name:?}"
            );
        }
        let wire = w::ImageRef {
            reference: Some(Reference::Id("sha256:short".into())),
        };
        assert!(crate::images::image_ref_from_wire(wire).is_err());
    }

    #[test]
    fn oci_image_info_round_trips_through_image_list() {
        let images = vec![libvm::ImageInfo::Oci(Box::new(oci_image()))];
        let wire = crate::images::image_list_to_wire(&images).unwrap();
        assert_eq!(crate::images::image_list_from_wire(wire).unwrap(), images);
    }

    #[test]
    fn oci_image_info_rejects_invalid_names_digests_and_platform() {
        let wire = crate::images::oci_image_to_wire(&oci_image()).unwrap();
        let mut duplicate = wire.clone();
        duplicate.names.push("alpine-local".into());
        assert!(crate::images::oci_image_from_wire(duplicate).is_err());
        let mut invalid_name = wire.clone();
        invalid_name.names.push("Not A Name".into());
        assert!(crate::images::oci_image_from_wire(invalid_name).is_err());
        let mut digest = wire.clone();
        digest.config_digest = "sha256:nope".into();
        assert!(crate::images::oci_image_from_wire(digest).is_err());
        let mut layer = wire.clone();
        layer.layers[0].diff_id = "plain".into();
        assert!(crate::images::oci_image_from_wire(layer).is_err());
        let mut platform = wire.clone();
        platform.platform = "linux".into();
        assert!(crate::images::oci_image_from_wire(platform).is_err());
        let mut config = wire;
        config.oci_config_json = "not json".into();
        assert!(crate::images::oci_image_from_wire(config).is_err());
        assert!(crate::images::image_info_from_wire(w::ImageInfo::default()).is_err());
    }

    #[test]
    fn removal_and_prune_reports_round_trip() {
        let removal = libvm::ImageRemoval {
            id: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            names: vec!["hello".into()],
            record_removed: true,
        };
        let wire = crate::images::image_removal_to_wire(&removal).unwrap();
        assert_eq!(
            crate::images::image_removal_from_wire(wire).unwrap(),
            removal
        );
        let report = libvm::ImagePruneReport {
            images_removed: 2,
            bytes_removed: 4096,
        };
        assert_eq!(
            crate::images::prune_report_from_wire(crate::images::prune_report_to_wire(&report)),
            report
        );
    }

    #[test]
    fn pull_request_keeps_an_absent_policy_absent_and_rejects_unknown_policies() {
        for policy in [
            None,
            Some(libvm::PullPolicy::IfMissing),
            Some(libvm::PullPolicy::Always),
            Some(libvm::PullPolicy::Never),
        ] {
            let options = libvm::ImagePullOptions { policy };
            let wire = crate::images::pull_request_to_wire("alpine:3.21", &options).unwrap();
            let (reference, decoded) = crate::images::pull_request_from_wire(wire).unwrap();
            assert_eq!(reference, "alpine:3.21");
            assert_eq!(decoded.policy, policy);
        }
        assert!(crate::images::pull_request_from_wire(w::PullImageRequest {
            reference: "alpine".into(),
            pull_policy: 9,
        })
        .is_err());
        assert!(crate::images::pull_request_from_wire(w::PullImageRequest::default()).is_err());
    }

    #[test]
    fn conversion_names_are_local_names_only() {
        let identity = crate::images::OciIdentity {
            requested_reference: "docker.io/library/alpine:3.21".into(),
            selected_reference: format!("docker.io/library/alpine@sha256:{}", "a".repeat(64)),
            platform: libvm::Platform {
                os: "linux".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
            config_digest: format!("sha256:{}", "b".repeat(64)),
            pull_policy: libvm::PullPolicy::IfMissing,
        };
        let options = libvm::RawConversionOptions {
            name: Some("raw-alpine".into()),
        };
        let wire = crate::images::convert_request_to_wire(&identity, &options).unwrap();
        assert_eq!(
            crate::images::convert_request_from_wire(wire.clone())
                .unwrap()
                .1,
            options
        );
        for name in ["alpine:3.21", "team/alpine", "Upper"] {
            let mut invalid = wire.clone();
            invalid.name = Some(name.into());
            assert!(
                crate::images::convert_request_from_wire(invalid).is_err(),
                "{name}"
            );
        }
    }
}

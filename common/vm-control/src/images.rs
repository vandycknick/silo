use crate::{invalid, required, ConversionError};
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

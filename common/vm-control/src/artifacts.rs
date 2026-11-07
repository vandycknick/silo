//! Same-user management protocol for explicitly approved VM artifact acquisition.
use crate::{invalid, required, ConversionError};
use silod_spec::daemon::v1 as w;

pub fn validate_reference(value: &str) -> Result<(), ConversionError> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid("artifact.reference", "invalid bounded reference"));
    }
    Ok(())
}

pub fn acquire_to_wire(
    value: &libvm::ArtifactAcquireRequest,
) -> Result<w::AcquireArtifactRequest, ConversionError> {
    validate_reference(&value.reference)?;
    if let Some(alias) = &value.alias {
        crate::stopped::alias(alias)?;
    }
    Ok(w::AcquireArtifactRequest {
        reference: value.reference.clone(),
        alias: value.alias.clone(),
        trust: Some(match &value.trust {
            libvm::ArtifactTrust::ApproveDigest { digest } => {
                w::acquire_artifact_request::Trust::ApprovedDigest(digest.to_string())
            }
            libvm::ArtifactTrust::RequireSignature => {
                w::acquire_artifact_request::Trust::RequireSignature(())
            }
        }),
    })
}

pub fn acquire_from_wire(
    value: w::AcquireArtifactRequest,
) -> Result<libvm::ArtifactAcquireRequest, ConversionError> {
    validate_reference(&value.reference)?;
    let alias = value
        .alias
        .map(|alias| crate::stopped::alias(&alias))
        .transpose()?;
    let trust = match required(value.trust, "artifact.trust")? {
        w::acquire_artifact_request::Trust::ApprovedDigest(digest) => {
            libvm::ArtifactTrust::ApproveDigest {
                digest: crate::boot::digest_from_wire(&digest, "artifact.approved_digest")?,
            }
        }
        w::acquire_artifact_request::Trust::RequireSignature(()) => {
            libvm::ArtifactTrust::RequireSignature
        }
    };
    Ok(libvm::ArtifactAcquireRequest {
        reference: value.reference,
        trust,
        alias,
    })
}

pub fn publish_to_wire(
    value: &libvm::ArtifactPublishRequest,
) -> Result<w::PublishArtifactRequest, ConversionError> {
    validate_reference(&value.destination)?;
    if let Some(ack) = &value.checkpoint_acknowledgement {
        if ack.destination != value.destination {
            return Err(invalid(
                "artifact.checkpoint_acknowledgement",
                "destination mismatch",
            ));
        }
    }
    Ok(w::PublishArtifactRequest {
        source: Some(crate::images::managed_ref_to_wire(&value.source)?),
        destination: value.destination.clone(),
        encoding: match value.encoding {
            libvm::ArtifactEncoding::Zstd => w::ArtifactEncoding::Zstd as i32,
            libvm::ArtifactEncoding::Raw => w::ArtifactEncoding::Raw as i32,
        },
        checkpoint_acknowledgement: value
            .checkpoint_acknowledgement
            .as_ref()
            .map(|ack| ack.destination.clone()),
    })
}

pub fn publish_from_wire(
    value: w::PublishArtifactRequest,
) -> Result<libvm::ArtifactPublishRequest, ConversionError> {
    validate_reference(&value.destination)?;
    let encoding = match w::ArtifactEncoding::try_from(value.encoding) {
        Ok(w::ArtifactEncoding::Zstd) => libvm::ArtifactEncoding::Zstd,
        Ok(w::ArtifactEncoding::Raw) => libvm::ArtifactEncoding::Raw,
        _ => return Err(invalid("artifact.encoding", "unknown encoding")),
    };
    let acknowledgement = value
        .checkpoint_acknowledgement
        .map(|destination| {
            if destination != value.destination {
                return Err(invalid(
                    "artifact.checkpoint_acknowledgement",
                    "destination mismatch",
                ));
            }
            Ok(libvm::CheckpointPublication { destination })
        })
        .transpose()?;
    Ok(libvm::ArtifactPublishRequest {
        source: crate::images::managed_ref_from_wire(required(value.source, "artifact.source")?)?,
        destination: value.destination,
        encoding,
        checkpoint_acknowledgement: acknowledgement,
    })
}

fn purpose_to_wire(value: libvm::ArtifactPurpose) -> i32 {
    match value {
        libvm::ArtifactPurpose::Image => w::ArtifactPurpose::Image as i32,
        libvm::ArtifactPurpose::Checkpoint => w::ArtifactPurpose::Checkpoint as i32,
    }
}
fn purpose_from_wire(value: i32) -> Result<libvm::ArtifactPurpose, ConversionError> {
    match w::ArtifactPurpose::try_from(value) {
        Ok(w::ArtifactPurpose::Image) => Ok(libvm::ArtifactPurpose::Image),
        Ok(w::ArtifactPurpose::Checkpoint) => Ok(libvm::ArtifactPurpose::Checkpoint),
        _ => Err(invalid("artifact.purpose", "unknown purpose")),
    }
}
fn capture_to_wire(value: libvm::SnapshotCaptureKindName) -> i32 {
    match value {
        libvm::SnapshotCaptureKindName::StoppedStorage => {
            w::ArtifactCaptureKind::StoppedStorage as i32
        }
        libvm::SnapshotCaptureKindName::LiveExecution => {
            w::ArtifactCaptureKind::LiveExecution as i32
        }
    }
}
fn capture_from_wire(value: i32) -> Result<libvm::SnapshotCaptureKindName, ConversionError> {
    match w::ArtifactCaptureKind::try_from(value) {
        Ok(w::ArtifactCaptureKind::StoppedStorage) => {
            Ok(libvm::SnapshotCaptureKindName::StoppedStorage)
        }
        Ok(w::ArtifactCaptureKind::LiveExecution) => {
            Ok(libvm::SnapshotCaptureKindName::LiveExecution)
        }
        _ => Err(invalid("artifact.capture_kind", "unknown capture kind")),
    }
}
fn validate_purpose(
    purpose: libvm::ArtifactPurpose,
    capture: Option<libvm::SnapshotCaptureKindName>,
    source: &libvm::ManagedSourceId,
) -> Result<(), ConversionError> {
    match (purpose, capture, source) {
        (libvm::ArtifactPurpose::Image, None, libvm::ManagedSourceId::Image(_)) => Ok(()),
        (libvm::ArtifactPurpose::Checkpoint, Some(_), libvm::ManagedSourceId::Snapshot(_)) => {
            Ok(())
        }
        _ => Err(invalid(
            "artifact.purpose",
            "purpose, capture kind and identity disagree",
        )),
    }
}

pub fn inspection_to_wire(
    value: &libvm::ArtifactInspection,
) -> Result<w::ArtifactInspection, ConversionError> {
    validate_reference(&value.repository)?;
    validate_purpose(value.purpose, value.capture_kind, &value.content)?;
    Ok(w::ArtifactInspection {
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
        purpose: purpose_to_wire(value.purpose),
        capture_kind: value.capture_kind.map(capture_to_wire),
        content: Some(crate::images::managed_id_to_wire(&value.content)),
        root_family: match value.root_family {
            libvm::ArtifactRootFamily::OpaqueRaw => w::ArtifactRootFamily::OpaqueRaw as i32,
            libvm::ArtifactRootFamily::LinuxOverlay => w::ArtifactRootFamily::LinuxOverlay as i32,
        },
        backend: match value.backend {
            libvm::BackendRequirement::RawBlock => w::BackendRequirement::RawBlock as i32,
            libvm::BackendRequirement::KrunOverlay => w::BackendRequirement::KrunOverlay as i32,
        },
        guest_architecture: crate::boot::architecture_to_wire(value.guest_architecture),
        live_restore: value.live_restore,
    })
}

pub fn inspection_from_wire(
    value: w::ArtifactInspection,
) -> Result<libvm::ArtifactInspection, ConversionError> {
    validate_reference(&value.repository)?;
    let content =
        crate::images::managed_id_from_wire(required(value.content, "artifact.content")?)?;
    let purpose = purpose_from_wire(value.purpose)?;
    let capture_kind = value.capture_kind.map(capture_from_wire).transpose()?;
    validate_purpose(purpose, capture_kind, &content)?;
    if value.live_restore != (capture_kind == Some(libvm::SnapshotCaptureKindName::LiveExecution)) {
        return Err(invalid(
            "artifact.live_restore",
            "disagrees with capture kind",
        ));
    }
    let (root_family, backend) = match (
        w::ArtifactRootFamily::try_from(value.root_family),
        w::BackendRequirement::try_from(value.backend),
    ) {
        (Ok(w::ArtifactRootFamily::OpaqueRaw), Ok(w::BackendRequirement::RawBlock)) => (
            libvm::ArtifactRootFamily::OpaqueRaw,
            libvm::BackendRequirement::RawBlock,
        ),
        (Ok(w::ArtifactRootFamily::LinuxOverlay), Ok(w::BackendRequirement::KrunOverlay)) => (
            libvm::ArtifactRootFamily::LinuxOverlay,
            libvm::BackendRequirement::KrunOverlay,
        ),
        _ => {
            return Err(invalid(
                "artifact.root_family",
                "unknown or inconsistent backend/root",
            ))
        }
    };
    Ok(libvm::ArtifactInspection {
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
        content,
        purpose,
        capture_kind,
        root_family,
        backend,
        guest_architecture: crate::boot::architecture_from_wire(
            value.guest_architecture,
            "artifact.guest_architecture",
        )?,
        live_restore: value.live_restore,
    })
}

pub fn acquired_to_wire(
    value: &libvm::ArtifactAcquireReport,
) -> Result<w::ArtifactAcquireReport, ConversionError> {
    validate_reference(&value.repository)?;
    Ok(w::ArtifactAcquireReport {
        source: Some(crate::images::managed_info_to_wire(&value.source)?),
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
        publisher: match value.publisher {
            libvm::PublisherAuthentication::Unauthenticated => {
                w::ArtifactPublisher::Unauthenticated as i32
            }
        },
    })
}

pub fn acquired_from_wire(
    value: w::ArtifactAcquireReport,
) -> Result<libvm::ArtifactAcquireReport, ConversionError> {
    validate_reference(&value.repository)?;
    let publisher = match w::ArtifactPublisher::try_from(value.publisher) {
        Ok(w::ArtifactPublisher::Unauthenticated) => {
            libvm::PublisherAuthentication::Unauthenticated
        }
        _ => {
            return Err(invalid(
                "artifact.publisher",
                "unknown publisher authentication",
            ))
        }
    };
    Ok(libvm::ArtifactAcquireReport {
        source: crate::images::managed_info_from_wire(required(value.source, "artifact.source")?)?,
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
        publisher,
    })
}

pub fn published_to_wire(
    value: &libvm::ArtifactPublishReport,
) -> Result<w::ArtifactPublishReport, ConversionError> {
    validate_reference(&value.repository)?;
    validate_purpose(value.purpose, value.capture_kind, &value.source)?;
    Ok(w::ArtifactPublishReport {
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
        tag: value.tag.clone(),
        source: Some(crate::images::managed_id_to_wire(&value.source)),
        purpose: purpose_to_wire(value.purpose),
        capture_kind: value.capture_kind.map(capture_to_wire),
    })
}

pub fn published_from_wire(
    value: w::ArtifactPublishReport,
) -> Result<libvm::ArtifactPublishReport, ConversionError> {
    validate_reference(&value.repository)?;
    let source = crate::images::managed_id_from_wire(required(value.source, "artifact.source")?)?;
    let purpose = purpose_from_wire(value.purpose)?;
    let capture_kind = value.capture_kind.map(capture_from_wire).transpose()?;
    validate_purpose(purpose, capture_kind, &source)?;
    if let Some(tag) = &value.tag {
        validate_reference(tag)?;
    }
    Ok(libvm::ArtifactPublishReport {
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
        tag: value.tag,
        source,
        purpose,
        capture_kind,
    })
}

#[cfg(test)]
mod tests {
    use crate::artifacts::{acquire_from_wire, inspection_from_wire};
    use silod_spec::daemon::v1 as w;

    fn inspection() -> w::ArtifactInspection {
        w::ArtifactInspection {
            repository: "localhost:5000/vm".into(),
            index_digest: format!("sha256:{}", "a".repeat(64)),
            purpose: w::ArtifactPurpose::Image as i32,
            capture_kind: None,
            root_family: w::ArtifactRootFamily::OpaqueRaw as i32,
            guest_architecture: w::GuestArchitecture::Amd64 as i32,
            live_restore: false,
            content: Some(w::ManagedSourceId {
                id: Some(w::managed_source_id::Id::ImageId(format!(
                    "sha256:{}",
                    "b".repeat(64)
                ))),
            }),
            backend: w::BackendRequirement::RawBlock as i32,
        }
    }

    #[test]
    fn acquisition_requires_explicit_canonical_digest_or_signature_policy() {
        let request = w::AcquireArtifactRequest {
            reference: "localhost:5000/vm:latest".into(),
            trust: None,
            alias: None,
        };
        assert!(acquire_from_wire(request.clone()).is_err());
        let mut request = request;
        request.trust = Some(w::acquire_artifact_request::Trust::ApprovedDigest(
            "sha256:bad".into(),
        ));
        assert!(acquire_from_wire(request.clone()).is_err());
        request.trust = Some(w::acquire_artifact_request::Trust::ApprovedDigest(format!(
            "sha256:{}",
            "a".repeat(64)
        )));
        let decoded = acquire_from_wire(request).unwrap();
        assert!(
            matches!(decoded.trust, libvm::ArtifactTrust::ApproveDigest { digest } if digest.to_string() == format!("sha256:{}", "a".repeat(64)))
        );
    }

    #[test]
    fn inspection_rejects_conflicting_identity_and_capture_semantics() {
        assert_eq!(
            inspection_from_wire(inspection()).unwrap().purpose,
            libvm::ArtifactPurpose::Image
        );
        let mut value = inspection();
        value.capture_kind = Some(w::ArtifactCaptureKind::StoppedStorage as i32);
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.live_restore = true;
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.purpose = w::ArtifactPurpose::Checkpoint as i32;
        value.capture_kind = Some(w::ArtifactCaptureKind::LiveExecution as i32);
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.root_family = 999;
        assert!(inspection_from_wire(value).is_err());
    }
}

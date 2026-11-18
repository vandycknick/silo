//! Same-user management protocol for VM artifact inspection, image
//! acquisition and image publication. Snapshots are never published here.
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
    let wire = w::AcquireArtifactRequest {
        reference: value.reference.clone(),
        name: value.name.clone(),
    };
    acquire_from_wire(wire.clone())?;
    Ok(wire)
}

pub fn acquire_from_wire(
    value: w::AcquireArtifactRequest,
) -> Result<libvm::ArtifactAcquireRequest, ConversionError> {
    validate_reference(&value.reference)?;
    Ok(libvm::ArtifactAcquireRequest {
        reference: value.reference,
        name: value.name.as_deref().map(crate::local_name).transpose()?,
    })
}

pub fn publish_to_wire(
    value: &libvm::ArtifactPublishRequest,
) -> Result<w::PublishArtifactRequest, ConversionError> {
    validate_reference(&value.destination)?;
    Ok(w::PublishArtifactRequest {
        image: Some(crate::images::image_ref_to_wire(&value.image)?),
        destination: value.destination.clone(),
        encoding: match value.encoding {
            libvm::ArtifactEncoding::Zstd => w::ArtifactEncoding::Zstd as i32,
            libvm::ArtifactEncoding::Raw => w::ArtifactEncoding::Raw as i32,
        },
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
    Ok(libvm::ArtifactPublishRequest {
        image: crate::images::image_ref_from_wire(required(value.image, "artifact.image")?)?,
        destination: value.destination,
        encoding,
    })
}

fn content_to_wire(value: &libvm::ArtifactContent) -> w::ArtifactContent {
    use w::artifact_content::Id;
    w::ArtifactContent {
        id: Some(match value {
            libvm::ArtifactContent::Image(id) => Id::ImageId(id.to_string()),
            libvm::ArtifactContent::Snapshot(id) => Id::SnapshotId(id.to_string()),
        }),
    }
}

fn content_from_wire(value: w::ArtifactContent) -> Result<libvm::ArtifactContent, ConversionError> {
    use w::artifact_content::Id;
    Ok(match required(value.id, "artifact.content")? {
        Id::ImageId(id) => libvm::ArtifactContent::Image(
            id.parse()
                .map_err(|_| invalid("artifact.content.image_id", "invalid image identity"))?,
        ),
        Id::SnapshotId(id) => {
            libvm::ArtifactContent::Snapshot(id.parse().map_err(|_| {
                invalid("artifact.content.snapshot_id", "invalid snapshot identity")
            })?)
        }
    })
}

/// Only a snapshot can include memory.
fn validate_memory(content: &libvm::ArtifactContent, memory: bool) -> Result<(), ConversionError> {
    if memory && matches!(content, libvm::ArtifactContent::Image(_)) {
        return Err(invalid("artifact.memory", "an image carries no memory"));
    }
    Ok(())
}

pub fn inspection_to_wire(
    value: &libvm::ArtifactInspection,
) -> Result<w::ArtifactInspection, ConversionError> {
    validate_reference(&value.repository)?;
    validate_memory(&value.content, value.memory)?;
    Ok(w::ArtifactInspection {
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
        content: Some(content_to_wire(&value.content)),
        root: match value.root {
            libvm::ArtifactRootFamily::OpaqueRaw => w::ArtifactRootFamily::OpaqueRaw as i32,
            libvm::ArtifactRootFamily::LinuxOverlay => w::ArtifactRootFamily::LinuxOverlay as i32,
        },
        guest_architecture: crate::boot::architecture_to_wire(value.guest_architecture),
        memory: value.memory,
    })
}

pub fn inspection_from_wire(
    value: w::ArtifactInspection,
) -> Result<libvm::ArtifactInspection, ConversionError> {
    validate_reference(&value.repository)?;
    let content = content_from_wire(required(value.content, "artifact.content")?)?;
    validate_memory(&content, value.memory)?;
    let root = match w::ArtifactRootFamily::try_from(value.root) {
        Ok(w::ArtifactRootFamily::OpaqueRaw) => libvm::ArtifactRootFamily::OpaqueRaw,
        Ok(w::ArtifactRootFamily::LinuxOverlay) => libvm::ArtifactRootFamily::LinuxOverlay,
        _ => return Err(invalid("artifact.root", "unknown root family")),
    };
    Ok(libvm::ArtifactInspection {
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
        content,
        root,
        guest_architecture: crate::boot::architecture_from_wire(
            value.guest_architecture,
            "artifact.guest_architecture",
        )?,
        memory: value.memory,
    })
}

pub fn acquired_to_wire(
    value: &libvm::ArtifactAcquireReport,
) -> Result<w::ArtifactAcquireReport, ConversionError> {
    validate_reference(&value.repository)?;
    Ok(w::ArtifactAcquireReport {
        image: Some(crate::images::stored_image_to_wire(&value.image)?),
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
    })
}

pub fn acquired_from_wire(
    value: w::ArtifactAcquireReport,
) -> Result<libvm::ArtifactAcquireReport, ConversionError> {
    validate_reference(&value.repository)?;
    Ok(libvm::ArtifactAcquireReport {
        image: crate::images::stored_image_from_wire(required(value.image, "artifact.image")?)?,
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
    })
}

pub fn published_to_wire(
    value: &libvm::ArtifactPublishReport,
) -> Result<w::ArtifactPublishReport, ConversionError> {
    let wire = w::ArtifactPublishReport {
        repository: value.repository.clone(),
        index_digest: value.index_digest.to_string(),
        tag: value.tag.clone(),
        content: Some(content_to_wire(&value.content)),
    };
    published_from_wire(wire.clone())?;
    Ok(wire)
}

/// Publication over the management API carries images only.
pub fn published_from_wire(
    value: w::ArtifactPublishReport,
) -> Result<libvm::ArtifactPublishReport, ConversionError> {
    validate_reference(&value.repository)?;
    let content = content_from_wire(required(value.content, "artifact.content")?)?;
    if !matches!(content, libvm::ArtifactContent::Image(_)) {
        return Err(invalid("artifact.content", "only images are published"));
    }
    if let Some(tag) = &value.tag {
        validate_reference(tag)?;
    }
    Ok(libvm::ArtifactPublishReport {
        repository: value.repository,
        index_digest: crate::boot::digest_from_wire(&value.index_digest, "artifact.index_digest")?,
        tag: value.tag,
        content,
    })
}

#[cfg(test)]
mod tests {
    use crate::artifacts::{
        acquire_from_wire, acquire_to_wire, inspection_from_wire, inspection_to_wire,
        publish_from_wire, publish_to_wire, published_from_wire, published_to_wire,
    };
    use silod_spec::daemon::v1 as w;

    fn id(byte: &str) -> String {
        format!("sha256:{}", byte.repeat(64))
    }

    fn inspection() -> w::ArtifactInspection {
        w::ArtifactInspection {
            repository: "localhost:5000/vm".into(),
            index_digest: id("a"),
            content: Some(w::ArtifactContent {
                id: Some(w::artifact_content::Id::ImageId(id("b"))),
            }),
            root: w::ArtifactRootFamily::OpaqueRaw as i32,
            guest_architecture: w::GuestArchitecture::Amd64 as i32,
            memory: false,
        }
    }

    #[test]
    fn acquisition_takes_a_reference_and_an_optional_local_name() {
        let request = libvm::ArtifactAcquireRequest {
            reference: "localhost:5000/vm:latest".into(),
            name: Some("vm".into()),
        };
        assert_eq!(
            acquire_from_wire(acquire_to_wire(&request).unwrap()).unwrap(),
            request
        );
        for (reference, name) in [
            ("", None),
            ("localhost:5000/vm", Some("registry/name")),
            ("localhost:5000/vm", Some("Upper")),
        ] {
            let wire = w::AcquireArtifactRequest {
                reference: reference.into(),
                name: name.map(Into::into),
            };
            assert!(acquire_from_wire(wire).is_err(), "{reference:?} {name:?}");
        }
    }

    #[test]
    fn inspection_round_trips_content_kind_root_and_memory() {
        let image = inspection_from_wire(inspection()).unwrap();
        assert!(matches!(image.content, libvm::ArtifactContent::Image(_)));
        assert_eq!(inspection_to_wire(&image).unwrap(), inspection());

        let mut snapshot = inspection();
        snapshot.content = Some(w::ArtifactContent {
            id: Some(w::artifact_content::Id::SnapshotId(id("c"))),
        });
        snapshot.root = w::ArtifactRootFamily::LinuxOverlay as i32;
        snapshot.memory = true;
        let decoded = inspection_from_wire(snapshot.clone()).unwrap();
        assert!(decoded.memory);
        assert_eq!(decoded.root, libvm::ArtifactRootFamily::LinuxOverlay);
        assert_eq!(inspection_to_wire(&decoded).unwrap(), snapshot);
    }

    #[test]
    fn inspection_rejects_image_memory_and_unknown_fields() {
        let mut value = inspection();
        value.memory = true;
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.root = 999;
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.content = None;
        assert!(inspection_from_wire(value).is_err());
        let mut value = inspection();
        value.index_digest = "sha256:short".into();
        assert!(inspection_from_wire(value).is_err());
    }

    #[test]
    fn publication_takes_an_image_reference_and_reports_images_only() {
        let request = libvm::ArtifactPublishRequest {
            image: "hello".parse().unwrap(),
            destination: "localhost:5000/vm:v1".into(),
            encoding: libvm::ArtifactEncoding::Zstd,
        };
        assert_eq!(
            publish_from_wire(publish_to_wire(&request).unwrap()).unwrap(),
            request
        );
        let mut missing = publish_to_wire(&request).unwrap();
        missing.image = None;
        assert!(publish_from_wire(missing).is_err());

        let report = libvm::ArtifactPublishReport {
            repository: "localhost:5000/vm".into(),
            index_digest: id("a").parse().unwrap(),
            tag: Some("v1".into()),
            content: libvm::ArtifactContent::Image(id("b").parse().unwrap()),
        };
        let wire = published_to_wire(&report).unwrap();
        assert_eq!(published_from_wire(wire.clone()).unwrap(), report);
        let mut snapshot = wire;
        snapshot.content = Some(w::ArtifactContent {
            id: Some(w::artifact_content::Id::SnapshotId(id("c"))),
        });
        assert!(published_from_wire(snapshot).is_err());
    }
}

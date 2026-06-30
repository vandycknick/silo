use std::path::PathBuf;

use crate::{OciDiskError, OciDiskResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImageSource {
    RemoteOci(String),
    LocalDisk(PathBuf),
    RootfsTar(PathBuf),
    OciArchive(PathBuf),
}

impl ImageSource {
    pub(crate) fn parse(image_ref: &str) -> OciDiskResult<Self> {
        let image_ref = image_ref.trim();
        if image_ref.is_empty() {
            return Err(OciDiskError::InvalidImageSource {
                reference: image_ref.to_string(),
                message: "image reference cannot be empty".to_string(),
            });
        }

        if let Some(path) = image_ref.strip_prefix("disk:") {
            return Ok(Self::LocalDisk(parse_local_path(image_ref, path)?));
        }
        if let Some(path) = image_ref.strip_prefix("tar:") {
            return Ok(Self::RootfsTar(parse_local_path(image_ref, path)?));
        }
        if let Some(path) = image_ref.strip_prefix("oci:") {
            return Ok(Self::OciArchive(parse_local_path(image_ref, path)?));
        }

        Ok(Self::RemoteOci(image_ref.to_string()))
    }
}

fn parse_local_path(reference: &str, path: &str) -> OciDiskResult<PathBuf> {
    if path.trim().is_empty() {
        return Err(OciDiskError::InvalidImageSource {
            reference: reference.to_string(),
            message: "local image source path cannot be empty".to_string(),
        });
    }

    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use crate::source::ImageSource;

    #[test]
    fn parses_local_image_sources() {
        assert!(matches!(
            ImageSource::parse("disk:./rootfs.img").expect("parse disk"),
            ImageSource::LocalDisk(_)
        ));
        assert!(matches!(
            ImageSource::parse("tar:./rootfs.tar").expect("parse tar"),
            ImageSource::RootfsTar(_)
        ));
        assert!(matches!(
            ImageSource::parse("oci:./image.tar").expect("parse oci"),
            ImageSource::OciArchive(_)
        ));
        assert!(matches!(
            ImageSource::parse("ghcr.io/org/image:latest").expect("parse remote"),
            ImageSource::RemoteOci(_)
        ));
    }

    #[test]
    fn rejects_empty_local_paths() {
        let err = ImageSource::parse("disk:").expect_err("empty local path should fail");

        assert!(err.to_string().contains("path cannot be empty"));
    }
}

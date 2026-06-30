use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use containerregistry_image::{ImageConfig, ImageIndex, Manifest, MediaType};

use crate::{OciDiskError, OciDiskResult, Platform};

pub(crate) struct LocalOciImage {
    pub(crate) manifest_digest: String,
    pub(crate) config_digest: String,
    pub(crate) layers: Vec<LocalOciLayer>,
}

pub(crate) struct LocalOciLayer {
    pub(crate) media_type: MediaType,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn read_oci_archive(
    path: &Path,
    reference: &str,
    platform: &Platform,
) -> OciDiskResult<LocalOciImage> {
    let entries = read_archive_entries(path)?;
    let index_bytes = entries.get("index.json").ok_or_else(|| OciDiskError::OciArchive {
        path: path.to_path_buf(),
        message: "archive must contain OCI index.json; Docker save archives are not supported by oci: yet".to_string(),
    })?;
    let index = ImageIndex::from_bytes(index_bytes).map_err(|err| OciDiskError::OciArchive {
        path: path.to_path_buf(),
        message: format!("invalid OCI index.json: {err}"),
    })?;

    let mut available = Vec::new();
    for descriptor in index.manifests() {
        let manifest_digest = descriptor.digest.to_string();
        let manifest_bytes = blob_bytes(path, &entries, &manifest_digest)?;
        let manifest =
            Manifest::from_bytes(manifest_bytes).map_err(|err| OciDiskError::OciArchive {
                path: path.to_path_buf(),
                message: format!("invalid manifest {manifest_digest}: {err}"),
            })?;
        let config_digest = manifest.config().digest.to_string();
        let config_bytes = blob_bytes(path, &entries, &config_digest)?;
        let config =
            ImageConfig::from_bytes(config_bytes).map_err(|err| OciDiskError::OciArchive {
                path: path.to_path_buf(),
                message: format!("invalid config {config_digest}: {err}"),
            })?;
        let actual = Platform {
            os: config.os.clone(),
            architecture: config.architecture.clone(),
            variant: config.variant.clone(),
        };
        available.push(actual.to_string());

        if !platform.matches_config(&config.os, &config.architecture, config.variant.as_deref()) {
            continue;
        }

        let layers = manifest
            .layers()
            .iter()
            .map(|layer| {
                let digest = layer.digest.to_string();
                let bytes = blob_bytes(path, &entries, &digest)?.to_vec();
                Ok(LocalOciLayer {
                    media_type: layer.media_type.clone(),
                    bytes,
                })
            })
            .collect::<OciDiskResult<Vec<_>>>()?;

        return Ok(LocalOciImage {
            manifest_digest,
            config_digest,
            layers,
        });
    }

    available.sort();
    available.dedup();
    Err(OciDiskError::MissingPlatform {
        reference: reference.to_string(),
        requested: platform.to_string(),
        available: if available.is_empty() {
            "none declared".to_string()
        } else {
            available.join(", ")
        },
    })
}

fn read_archive_entries(path: &Path) -> OciDiskResult<BTreeMap<String, Vec<u8>>> {
    let file = File::open(path)?;
    let mut archive = tar::Archive::new(file);
    let entries = archive.entries().map_err(|err| OciDiskError::OciArchive {
        path: path.to_path_buf(),
        message: err.to_string(),
    })?;
    let mut files = BTreeMap::new();
    for entry in entries {
        let mut entry = entry.map_err(|err| OciDiskError::OciArchive {
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let entry_path = archive_entry_path(path, entry.path()?.as_ref())?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        files.insert(entry_path, bytes);
    }
    Ok(files)
}

fn archive_entry_path(archive_path: &Path, path: &Path) -> OciDiskResult<String> {
    let mut clean = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let Some(part) = part.to_str() else {
                    return Err(OciDiskError::OciArchive {
                        path: archive_path.to_path_buf(),
                        message: format!("archive entry path {path:?} must be UTF-8"),
                    });
                };
                if part.contains('\0') {
                    return Err(OciDiskError::OciArchive {
                        path: archive_path.to_path_buf(),
                        message: format!("archive entry path {path:?} must not contain NUL bytes"),
                    });
                }
                clean.push(part.to_string());
            }
            Component::ParentDir => {
                return Err(OciDiskError::OciArchive {
                    path: archive_path.to_path_buf(),
                    message: format!("archive entry path {path:?} must not contain '..'"),
                })
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }

    if clean.is_empty() {
        return Err(OciDiskError::OciArchive {
            path: archive_path.to_path_buf(),
            message: "archive entry path cannot be empty".to_string(),
        });
    }

    Ok(clean.join("/"))
}

fn blob_bytes<'a>(
    archive_path: &Path,
    entries: &'a BTreeMap<String, Vec<u8>>,
    digest: &str,
) -> OciDiskResult<&'a [u8]> {
    let Some((algorithm, encoded)) = digest.split_once(':') else {
        return Err(OciDiskError::OciArchive {
            path: archive_path.to_path_buf(),
            message: format!("digest {digest:?} must contain an algorithm and value"),
        });
    };
    let blob_path = PathBuf::from("blobs").join(algorithm).join(encoded);
    let blob_path = blob_path.to_string_lossy().into_owned();
    entries
        .get(&blob_path)
        .map(Vec::as_slice)
        .ok_or_else(|| OciDiskError::OciArchive {
            path: archive_path.to_path_buf(),
            message: format!("archive is missing blob {digest}"),
        })
}

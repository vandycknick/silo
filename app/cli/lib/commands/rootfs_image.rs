use std::path::PathBuf;

use libvm::ImageSource;

/// Parses CLI image syntax into libvm's explicit image-source API.
///
/// The Rust API treats strings as OCI references only. The CLI keeps its
/// historical `disk:` and `tar:` prefixes as command-line conveniences.
pub(crate) fn parse_cli_image_source(value: &str) -> eyre::Result<ImageSource> {
    let value = value.trim();
    if value.is_empty() {
        eyre::bail!("image reference cannot be empty");
    }

    if let Some(path) = value.strip_prefix("disk:") {
        return Ok(ImageSource::disk(parse_local_image_path(value, path)?));
    }
    if let Some(path) = value.strip_prefix("tar:") {
        return Ok(ImageSource::tar(parse_local_image_path(value, path)?));
    }
    if value.starts_with("oci:") {
        eyre::bail!("OCI archive image sources are no longer supported");
    }

    Ok(ImageSource::oci(value.to_string()))
}

fn parse_local_image_path(reference: &str, path: &str) -> eyre::Result<PathBuf> {
    if path.trim().is_empty() {
        eyre::bail!("local image source path cannot be empty in {reference}");
    }
    Ok(PathBuf::from(path))
}

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use containerregistry_image::MediaType;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ext4_writer::Ext4Writer;
use crate::layer::apply_layer;
use crate::oci_archive::read_oci_archive;
use crate::platform::sanitize_component;
use crate::registry::{RegistryClient, ResolvedManifest};
use crate::source::ImageSource;
use crate::{OciDiskError, OciDiskResult, Platform};

const METADATA_VERSION: u32 = 1;
const DEFAULT_ROOTFS_SIZE_BYTES: u64 = 512 * 1024 * 1024;
const INDEX_FILE_NAME: &str = "index.json";
const INDEX_VERSION: u32 = 1;
const METADATA_FILE_NAME: &str = "metadata.json";
const ROOTFS_FILE_NAME: &str = "rootfs.img";
const ROOTFS_FILESYSTEM: &str = "ext4";
const STAGING_DIR_NAME: &str = ".staging";

#[derive(Debug, Clone)]
pub struct RootfsOptions {
    pub platform: Platform,
    pub disk_size_bytes: u64,
}

impl RootfsOptions {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            disk_size_bytes: DEFAULT_ROOTFS_SIZE_BYTES,
        }
    }

    pub fn for_host() -> OciDiskResult<Self> {
        Ok(Self::new(Platform::host()?))
    }

    pub fn with_disk_size_bytes(mut self, disk_size_bytes: u64) -> Self {
        self.disk_size_bytes = disk_size_bytes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsImage {
    pub path: PathBuf,
    pub image_ref: String,
    pub image_id: String,
    pub platform: Platform,
    pub source: RootfsImageSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootfsImageSource {
    OciRegistry,
    Disk,
    Tar,
    OciArchive,
}

impl Display for RootfsImageSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OciRegistry => write!(f, "oci-registry"),
            Self::Disk => write!(f, "disk"),
            Self::Tar => write!(f, "tar"),
            Self::OciArchive => write!(f, "oci-archive"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreIndex {
    version: u32,
    #[serde(default)]
    tags: BTreeMap<String, TagRecord>,
}

impl Default for StoreIndex {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TagRecord {
    image_ref: String,
    platform: Platform,
    manifest_digest: String,
    updated_at_unix: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImageMetadata {
    version: u32,
    image_ref: String,
    image_id: String,
    source: RootfsImageSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_digest: Option<String>,
    platform: Platform,
    filesystem: String,
    rootfs_file: String,
    created_at_unix: i64,
}

impl ImageStore {
    pub fn open(root: impl AsRef<Path>) -> OciDiskResult<Self> {
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    pub async fn get_or_create(
        &self,
        image_ref: &str,
        options: RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        match ImageSource::parse(image_ref)? {
            ImageSource::RemoteOci(image_ref) => {
                self.get_or_create_remote_oci(&image_ref, options).await
            }
            ImageSource::LocalDisk(path) => self.local_disk(image_ref, path, options),
            ImageSource::RootfsTar(path) => self.get_or_create_rootfs_tar(image_ref, path, options),
            ImageSource::OciArchive(path) => {
                self.get_or_create_oci_archive(image_ref, path, options)
            }
        }
    }

    async fn get_or_create_remote_oci(
        &self,
        image_ref: &str,
        options: RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;

        let reference = RegistryClient::parse_reference(image_ref)?;
        let canonical_ref = reference.to_string();
        let registry = RegistryClient::new()?;
        let resolved = registry
            .resolve_manifest(&reference, &options.platform)
            .await?;

        if let Some(image) = self.cached_image(
            &canonical_ref,
            &resolved.manifest_digest,
            &options.platform,
            RootfsImageSource::OciRegistry,
        )? {
            if reference.is_tag() {
                self.update_tag_mapping(
                    &canonical_ref,
                    &options.platform,
                    &resolved.manifest_digest,
                )?;
            }
            return Ok(image);
        }

        let image = self
            .create_rootfs(&registry, &canonical_ref, &resolved, &options)
            .await?;
        if reference.is_tag() {
            self.update_tag_mapping(&canonical_ref, &options.platform, &resolved.manifest_digest)?;
        }
        Ok(image)
    }

    async fn create_rootfs(
        &self,
        registry: &RegistryClient,
        image_ref: &str,
        resolved: &ResolvedManifest,
        options: &RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        let image_id = &resolved.manifest_digest;
        let final_dir = self.image_dir(image_id, &options.platform)?;
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                image_id,
                &options.platform,
                RootfsImageSource::OciRegistry,
            )? {
                return Ok(image);
            }
        }

        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;

        for layer in resolved.manifest.layers() {
            let bytes = registry
                .pull_blob(&resolved.reference, layer, image_ref)
                .await?;
            let reader = layer_reader(&layer.media_type, bytes)?;
            apply_layer(reader, &mut writer)?;
        }

        writer.finish()?;
        self.write_metadata(
            staging.path(),
            image_ref,
            image_id,
            RootfsImageSource::OciRegistry,
            Some(&resolved.config_digest),
            &options.platform,
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                image_id,
                &options.platform,
                RootfsImageSource::OciRegistry,
            )? {
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id: image_id.to_string(),
            platform: options.platform.clone(),
            source: RootfsImageSource::OciRegistry,
        })
    }

    fn local_disk(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        let path = canonical_local_file(image_ref, &path)?;
        let image_id = format!(
            "local-disk-sha256:{}",
            sha256_bytes(path.to_string_lossy().as_bytes())
        );
        Ok(RootfsImage {
            path,
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::Disk,
        })
    }

    fn get_or_create_rootfs_tar(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;
        let path = canonical_local_file(image_ref, &path)?;
        reject_known_tar_compression(image_ref, &path)?;
        println!("Creating sha256 from file");
        let image_id = format!("tar-sha256:{}", sha256_file(&path)?);
        println!("DONE Creating sha256 from file");

        if let Some(image) = self.cached_image(
            image_ref,
            &image_id,
            &options.platform,
            RootfsImageSource::Tar,
        )? {
            return Ok(image);
        }

        let final_dir = self.image_dir(&image_id, &options.platform)?;
        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;
        let file = fs::File::open(&path)?;
        apply_layer(file, &mut writer)?;
        writer.finish()?;
        self.write_metadata(
            staging.path(),
            image_ref,
            &image_id,
            RootfsImageSource::Tar,
            None,
            &options.platform,
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                &image_id,
                &options.platform,
                RootfsImageSource::Tar,
            )? {
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::Tar,
        })
    }

    fn get_or_create_oci_archive(
        &self,
        image_ref: &str,
        path: PathBuf,
        options: RootfsOptions,
    ) -> OciDiskResult<RootfsImage> {
        fs::create_dir_all(&self.root)?;
        let path = canonical_local_file(image_ref, &path)?;
        let archive = read_oci_archive(&path, image_ref, &options.platform)?;
        let image_id = archive.manifest_digest.clone();

        if let Some(image) = self.cached_image(
            image_ref,
            &image_id,
            &options.platform,
            RootfsImageSource::OciArchive,
        )? {
            return Ok(image);
        }

        let final_dir = self.image_dir(&image_id, &options.platform)?;
        let staging = StagingDir::create(&self.root)?;
        let stage_rootfs = staging.path().join(ROOTFS_FILE_NAME);
        let mut writer = Ext4Writer::create(&stage_rootfs, options.disk_size_bytes)?;
        for layer in archive.layers {
            let reader = layer_reader(&layer.media_type, layer.bytes)?;
            apply_layer(reader, &mut writer)?;
        }
        writer.finish()?;
        self.write_metadata(
            staging.path(),
            image_ref,
            &image_id,
            RootfsImageSource::OciArchive,
            Some(&archive.config_digest),
            &options.platform,
        )?;

        if let Some(parent) = final_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        if final_dir.exists() {
            if let Some(image) = self.cached_image(
                image_ref,
                &image_id,
                &options.platform,
                RootfsImageSource::OciArchive,
            )? {
                return Ok(image);
            }
        }
        fs::rename(staging.path(), &final_dir)?;
        staging.disarm();

        Ok(RootfsImage {
            path: final_dir.join(ROOTFS_FILE_NAME),
            image_ref: image_ref.to_string(),
            image_id,
            platform: options.platform,
            source: RootfsImageSource::OciArchive,
        })
    }

    fn cached_image(
        &self,
        image_ref: &str,
        image_id: &str,
        platform: &Platform,
        source: RootfsImageSource,
    ) -> OciDiskResult<Option<RootfsImage>> {
        let dir = self.image_dir(image_id, platform)?;
        if !dir.exists() {
            return Ok(None);
        }

        let rootfs_path = dir.join(ROOTFS_FILE_NAME);
        if !rootfs_path.is_file() {
            return Err(OciDiskError::CorruptCacheEntry {
                path: dir,
                reason: format!("missing {ROOTFS_FILE_NAME}"),
            });
        }

        let metadata_path = dir.join(METADATA_FILE_NAME);
        let metadata = read_metadata(&metadata_path)?;
        if metadata.version != METADATA_VERSION {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata version {} does not match expected version {METADATA_VERSION}",
                    metadata.version
                ),
            });
        }
        if metadata.image_id != image_id {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata image id {} does not match cache image id {image_id}",
                    metadata.image_id
                ),
            });
        }
        if metadata.source != source {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata source {} does not match cache source {source}",
                    metadata.source
                ),
            });
        }
        if metadata.platform != *platform {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata platform {} does not match cache platform {platform}",
                    metadata.platform
                ),
            });
        }
        if metadata.filesystem != ROOTFS_FILESYSTEM {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!(
                    "metadata filesystem {} does not match expected {ROOTFS_FILESYSTEM}",
                    metadata.filesystem
                ),
            });
        }
        if metadata.rootfs_file != ROOTFS_FILE_NAME {
            return Err(OciDiskError::CorruptCacheEntry {
                path: metadata_path,
                reason: format!("metadata rootfs file is {}", metadata.rootfs_file),
            });
        }

        Ok(Some(RootfsImage {
            path: rootfs_path,
            image_ref: image_ref.to_string(),
            image_id: image_id.to_string(),
            platform: platform.clone(),
            source,
        }))
    }

    fn image_dir(&self, image_id: &str, platform: &Platform) -> OciDiskResult<PathBuf> {
        Ok(self
            .root
            .join(image_id_path_component(image_id)?)
            .join(platform.cache_key()))
    }

    fn write_metadata(
        &self,
        dir: &Path,
        image_ref: &str,
        image_id: &str,
        source: RootfsImageSource,
        config_digest: Option<&str>,
        platform: &Platform,
    ) -> OciDiskResult<()> {
        let metadata = ImageMetadata {
            version: METADATA_VERSION,
            image_ref: image_ref.to_string(),
            image_id: image_id.to_string(),
            source,
            config_digest: config_digest.map(str::to_string),
            platform: platform.clone(),
            filesystem: ROOTFS_FILESYSTEM.to_string(),
            rootfs_file: ROOTFS_FILE_NAME.to_string(),
            created_at_unix: now_unix(),
        };
        let data = serde_json::to_vec_pretty(&metadata)?;
        fs::write(dir.join(METADATA_FILE_NAME), data)?;
        Ok(())
    }

    fn update_tag_mapping(
        &self,
        image_ref: &str,
        platform: &Platform,
        manifest_digest: &str,
    ) -> OciDiskResult<()> {
        let mut index = self.read_index()?;
        index.tags.insert(
            tag_key(image_ref, platform),
            TagRecord {
                image_ref: image_ref.to_string(),
                platform: platform.clone(),
                manifest_digest: manifest_digest.to_string(),
                updated_at_unix: now_unix(),
            },
        );
        self.write_index(&index)
    }

    fn read_index(&self) -> OciDiskResult<StoreIndex> {
        let path = self.root.join(INDEX_FILE_NAME);
        match fs::read(&path) {
            Ok(data) => {
                let index = serde_json::from_slice::<StoreIndex>(&data).map_err(|err| {
                    OciDiskError::CorruptCacheEntry {
                        path: path.clone(),
                        reason: err.to_string(),
                    }
                })?;
                if index.version != INDEX_VERSION {
                    return Err(OciDiskError::CorruptCacheEntry {
                        path,
                        reason: format!(
                            "index version {} does not match expected version {INDEX_VERSION}",
                            index.version
                        ),
                    });
                }
                Ok(index)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(StoreIndex::default()),
            Err(err) => Err(err.into()),
        }
    }

    fn write_index(&self, index: &StoreIndex) -> OciDiskResult<()> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join(INDEX_FILE_NAME);
        let temp_path = self.root.join(format!("{INDEX_FILE_NAME}.tmp"));
        fs::write(&temp_path, serde_json::to_vec_pretty(index)?)?;
        fs::rename(temp_path, path)?;
        Ok(())
    }
}

fn read_metadata(path: &Path) -> OciDiskResult<ImageMetadata> {
    let data = fs::read(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OciDiskError::CorruptCacheEntry {
                path: path.to_path_buf(),
                reason: "metadata file is missing".to_string(),
            }
        } else {
            OciDiskError::Io(err)
        }
    })?;
    serde_json::from_slice(&data).map_err(|err| OciDiskError::CorruptCacheEntry {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn layer_reader(media_type: &MediaType, bytes: Vec<u8>) -> OciDiskResult<Box<dyn Read>> {
    match media_type {
        MediaType::OciLayer | MediaType::OciLayerNondistributable => {
            Ok(Box::new(Cursor::new(bytes)))
        }
        MediaType::OciLayerGzip
        | MediaType::DockerLayerGzip
        | MediaType::OciLayerNondistributableGzip => {
            Ok(Box::new(GzDecoder::new(Cursor::new(bytes))))
        }
        MediaType::OciLayerZstd | MediaType::OciLayerNondistributableZstd => {
            Ok(Box::new(zstd::Decoder::new(Cursor::new(bytes))?))
        }
        MediaType::Other(value) if value == "application/vnd.docker.image.rootfs.diff.tar" => {
            Ok(Box::new(Cursor::new(bytes)))
        }
        other => Err(OciDiskError::UnsupportedLayerMediaType {
            media_type: other.as_str().to_string(),
        }),
    }
}

fn canonical_local_file(reference: &str, path: &Path) -> OciDiskResult<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|err| OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: path.to_path_buf(),
            message: err.to_string(),
        })?;
    let metadata = canonical
        .metadata()
        .map_err(|err| OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: canonical.clone(),
            message: err.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(OciDiskError::LocalImageSource {
            reference: reference.to_string(),
            path: canonical,
            message: "path must point to a regular file".to_string(),
        });
    }
    Ok(canonical)
}

fn reject_known_tar_compression(reference: &str, path: &Path) -> OciDiskResult<()> {
    let mut file = fs::File::open(path)?;
    let mut magic = [0_u8; 6];
    let read = file.read(&mut magic)?;
    let compression = if read >= 2 && magic[..2] == [0x1f, 0x8b] {
        Some("gzip")
    } else if read >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        Some("zstd")
    } else if read >= 6 && magic == [0xfd, b'7', b'z', b'X', b'Z', 0x00] {
        Some("xz")
    } else {
        None
    };

    if let Some(compression) = compression {
        return Err(OciDiskError::UnsupportedTarCompression {
            reference: reference.to_string(),
            path: path.to_path_buf(),
            compression,
        });
    }

    Ok(())
}

fn sha256_file(path: &Path) -> OciDiskResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn image_id_path_component(image_id: &str) -> OciDiskResult<String> {
    let Some((algorithm, encoded)) = image_id.split_once(':') else {
        return Err(OciDiskError::CorruptCacheEntry {
            path: PathBuf::from(image_id),
            reason: "image id must contain a kind and value".to_string(),
        });
    };
    if algorithm.is_empty() || encoded.is_empty() {
        return Err(OciDiskError::CorruptCacheEntry {
            path: PathBuf::from(image_id),
            reason: "image id kind and value must be non-empty".to_string(),
        });
    }
    Ok(format!(
        "{}-{}",
        sanitize_component(algorithm),
        sanitize_component(encoded)
    ))
}

fn tag_key(image_ref: &str, platform: &Platform) -> String {
    format!("{}|{}", image_ref, platform.cache_key())
}

fn now_unix() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    seconds.min(i64::MAX as u64) as i64
}

struct StagingDir {
    path: PathBuf,
    armed: bool,
}

impl StagingDir {
    fn create(root: &Path) -> OciDiskResult<Self> {
        let parent = root.join(STAGING_DIR_NAME);
        fs::create_dir_all(&parent)?;
        let path = parent.join(format!("{}-{}", std::process::id(), now_unix_nanos()));
        fs::create_dir(&path)?;
        Ok(Self { path, armed: true })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bento_ext4::Reader;
    use tar::{Builder, Header};

    use crate::store::{
        image_id_path_component, sha256_bytes, ImageMetadata, ImageStore, RootfsImageSource,
        RootfsOptions, METADATA_VERSION, ROOTFS_FILESYSTEM, ROOTFS_FILE_NAME,
    };
    use crate::{Platform, RootfsImage};

    #[test]
    fn image_id_and_platform_define_cache_path() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let path = store
            .image_dir("sha256:abc123", &Platform::linux_amd64())
            .expect("cache path");

        assert_eq!(path, temp.path().join("sha256-abc123/linux-amd64"));
    }

    #[test]
    fn validates_existing_cache_metadata() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_arm64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                source: RootfsImageSource::OciRegistry,
                config_digest: Some("sha256:config".to_string()),
                platform: platform.clone(),
                filesystem: ROOTFS_FILESYSTEM.to_string(),
                rootfs_file: ROOTFS_FILE_NAME.to_string(),
                created_at_unix: 1,
            })
            .expect("serialize metadata"),
        )
        .expect("write metadata");

        let image = store
            .cached_image(
                "index.docker.io/library/alpine:latest",
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect("cache validation")
            .expect("cache hit");

        assert_eq!(
            image,
            RootfsImage {
                path: dir.join(ROOTFS_FILE_NAME),
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                platform,
                source: RootfsImageSource::OciRegistry,
            }
        );
    }

    #[test]
    fn corrupt_cache_metadata_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(dir.join("metadata.json"), b"not json").expect("write metadata");

        let err = store
            .cached_image(
                "alpine:latest",
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect_err("corrupt metadata should fail");

        assert!(err.to_string().contains("corrupt"));
    }

    #[test]
    fn cache_metadata_filesystem_mismatch_is_reported() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let store = ImageStore::open(temp.path()).expect("open store");
        let platform = Platform::linux_amd64();
        let dir = store
            .image_dir("sha256:def456", &platform)
            .expect("cache path");
        std::fs::create_dir_all(&dir).expect("create cache dir");
        std::fs::write(dir.join(ROOTFS_FILE_NAME), b"disk").expect("write rootfs");
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_vec_pretty(&ImageMetadata {
                version: METADATA_VERSION,
                image_ref: "index.docker.io/library/alpine:latest".to_string(),
                image_id: "sha256:def456".to_string(),
                source: RootfsImageSource::OciRegistry,
                config_digest: Some("sha256:config".to_string()),
                platform: platform.clone(),
                filesystem: "xfs".to_string(),
                rootfs_file: ROOTFS_FILE_NAME.to_string(),
                created_at_unix: 1,
            })
            .expect("serialize metadata"),
        )
        .expect("write metadata");

        let err = store
            .cached_image(
                "index.docker.io/library/alpine:latest",
                "sha256:def456",
                &platform,
                RootfsImageSource::OciRegistry,
            )
            .expect_err("filesystem mismatch should fail");

        assert!(err.to_string().contains("metadata filesystem"));
    }

    #[test]
    fn image_id_path_rejects_invalid_id() {
        let err = image_id_path_component("not-an-id").expect_err("image id should fail");

        assert!(err.to_string().contains("image id must contain"));
    }

    #[test]
    fn disk_source_uses_local_file_directly_without_creating_cache() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let cache = temp.path().join("cache");
        let disk = temp.path().join("rootfs.img");
        std::fs::write(&disk, b"disk").expect("write disk");
        let store = ImageStore::open(&cache).expect("open store");
        let image = store
            .local_disk(
                &format!("disk:{}", disk.display()),
                disk.clone(),
                RootfsOptions::new(Platform::linux_amd64()),
            )
            .expect("local disk");

        assert_eq!(image.path, disk.canonicalize().expect("canonical disk"));
        assert_eq!(image.source, RootfsImageSource::Disk);
        assert!(!cache.exists());
    }

    #[test]
    fn rootfs_tar_converts_to_cached_ext4() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        std::fs::write(&tar_path, tar_file("etc/os-release", b"NAME=Bento\n")).expect("write tar");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let image = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024),
            )
            .expect("convert tar");

        assert_eq!(image.source, RootfsImageSource::Tar);
        assert!(image.image_id.starts_with("tar-sha256:"));
        assert_eq!(
            image.path.file_name().and_then(|name| name.to_str()),
            Some("rootfs.img")
        );
        let mut reader = Reader::new(&image.path).expect("open ext4");
        let bytes = reader
            .read_file("/etc/os-release", 0, Some(64))
            .expect("read converted file");
        assert_eq!(bytes, b"NAME=Bento\n");
    }

    #[test]
    fn rootfs_tar_reuses_content_cache() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar");
        std::fs::write(&tar_path, tar_file("etc/issue", b"one")).expect("write tar");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let options =
            RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024);

        let first = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path.clone(),
                options.clone(),
            )
            .expect("first convert");
        let second = store
            .get_or_create_rootfs_tar(&format!("tar:{}", tar_path.display()), tar_path, options)
            .expect("second convert");

        assert_eq!(first.path, second.path);
        assert_eq!(first.image_id, second.image_id);
    }

    #[test]
    fn rootfs_tar_rejects_known_compression() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let tar_path = temp.path().join("rootfs.tar.gz");
        std::fs::write(&tar_path, [0x1f, 0x8b, 0, 0]).expect("write gzip magic");
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");

        let err = store
            .get_or_create_rootfs_tar(
                &format!("tar:{}", tar_path.display()),
                tar_path,
                RootfsOptions::new(Platform::linux_amd64()),
            )
            .expect_err("compressed tar should fail");

        assert!(err.to_string().contains("only plain tar"));
    }

    #[test]
    fn oci_archive_converts_selected_platform() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let archive_path = temp.path().join("image.tar");
        write_oci_archive(&archive_path, "amd64", tar_file("etc/arch", b"amd64"));
        let store = ImageStore::open(temp.path().join("cache")).expect("open store");
        let image = store
            .get_or_create_oci_archive(
                &format!("oci:{}", archive_path.display()),
                archive_path,
                RootfsOptions::new(Platform::linux_amd64()).with_disk_size_bytes(64 * 1024 * 1024),
            )
            .expect("convert oci archive");

        assert_eq!(image.source, RootfsImageSource::OciArchive);
        let mut reader = Reader::new(&image.path).expect("open ext4");
        let bytes = reader
            .read_file("/etc/arch", 0, Some(64))
            .expect("read converted file");
        assert_eq!(bytes, b"amd64");
    }

    fn tar_file(path: &str, data: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append file");
        builder.into_inner().expect("finish tar")
    }

    fn write_oci_archive(path: &std::path::Path, architecture: &str, layer: Vec<u8>) {
        let config = format!(
            r#"{{"architecture":"{architecture}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#
        )
        .into_bytes();
        let config_digest = format!("sha256:{}", sha256_bytes(&config));
        let layer_digest = format!("sha256:{}", sha256_bytes(&layer));
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{config_size}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{layer_size}}}]}}"#,
            config_size = config.len(),
            layer_size = layer.len()
        )
        .into_bytes();
        let manifest_digest = format!("sha256:{}", sha256_bytes(&manifest));
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{manifest_size},"platform":{{"architecture":"{architecture}","os":"linux"}}}}]}}"#,
            manifest_size = manifest.len()
        )
        .into_bytes();

        let mut builder = Builder::new(Vec::new());
        append_archive_file(&mut builder, "index.json", &index);
        append_blob(&mut builder, &config_digest, &config);
        append_blob(&mut builder, &layer_digest, &layer);
        append_blob(&mut builder, &manifest_digest, &manifest);
        let data = builder.into_inner().expect("finish oci archive");
        std::fs::write(path, data).expect("write oci archive");
    }

    fn append_blob(builder: &mut Builder<Vec<u8>>, digest: &str, data: &[u8]) {
        let (algorithm, encoded) = digest.split_once(':').expect("digest shape");
        append_archive_file(builder, &format!("blobs/{algorithm}/{encoded}"), data);
    }

    fn append_archive_file(builder: &mut Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("set path");
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append(&header, Cursor::new(data.to_vec()))
            .expect("append archive file");
    }
}

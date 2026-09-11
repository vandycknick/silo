use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{bail, Context as _};
use libvm::PublishBind;
use serde::{Deserialize, Serialize};
use utils::HumanSize;

#[cfg(debug_assertions)]
const DEVELOPMENT_IMAGE: &str = "ghcr.io/vandycknick/silo/system:dev";
const RELEASE_IMAGE: Option<&str> = option_env!("SILO_SYSTEM_IMAGE");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemConfig {
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) system: SystemOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemOptions {
    #[serde(default)]
    pub(crate) engine: EngineKind,
    #[serde(default)]
    pub(crate) image: Option<String>,
    #[serde(default)]
    pub(crate) resources: SystemResources,
    #[serde(default)]
    pub(crate) storage: SystemStorage,
    #[serde(default)]
    pub(crate) mounts: SystemMounts,
    #[serde(default)]
    pub(crate) networking: SystemNetworking,
    #[serde(default)]
    pub(crate) docker: DockerIntegration,
    /// Rosetta translation for x86_64 containers. Unset means on when the host is
    /// Apple silicon with Rosetta installed, off otherwise.
    #[serde(default)]
    pub(crate) rosetta: Option<bool>,
}

impl Default for SystemOptions {
    fn default() -> Self {
        Self {
            engine: EngineKind::Docker,
            image: None,
            resources: SystemResources::default(),
            storage: SystemStorage::default(),
            mounts: SystemMounts::default(),
            networking: SystemNetworking::default(),
            docker: DockerIntegration::default(),
            rosetta: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EngineKind {
    #[default]
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemResources {
    #[serde(default = "default_cpus")]
    pub(crate) cpus: u8,
    #[serde(default = "default_memory")]
    pub(crate) memory: String,
}

impl Default for SystemResources {
    fn default() -> Self {
        Self {
            cpus: default_cpus(),
            memory: default_memory(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub(crate) struct SystemStorage {
    /// Appliance root disk size. Fixed once the system machine exists.
    #[serde(default, rename = "root-size")]
    pub(crate) root_size: Option<String>,
    /// Installation data disk size. Fixed once the data disk exists.
    #[serde(default, rename = "data-size")]
    pub(crate) data_size: Option<String>,
}

impl SystemStorage {
    /// Whether the user pinned sizes; unset sizes follow the recorded installation
    /// rather than whatever the current default happens to be.
    pub(crate) fn explicit_root_size(&self) -> bool {
        self.root_size.is_some()
    }
    pub(crate) fn explicit_data_size(&self) -> bool {
        self.data_size.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemMounts {
    #[serde(default = "default_true")]
    pub(crate) home: bool,
    #[serde(default)]
    pub(crate) additional: Vec<AdditionalShare>,
}

impl Default for SystemMounts {
    fn default() -> Self {
        Self {
            home: true,
            additional: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdditionalShare {
    pub(crate) path: PathBuf,
    #[serde(default, rename = "read-only")]
    pub(crate) read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemNetworking {
    #[serde(default = "default_publish_bind", rename = "publish-bind")]
    pub(crate) publish_bind: PublishBind,
}

impl Default for SystemNetworking {
    fn default() -> Self {
        Self {
            publish_bind: default_publish_bind(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DockerIntegration {
    #[serde(default, rename = "compatibility-socket")]
    pub(crate) compatibility_socket: CompatibilitySocket,
}

impl Default for DockerIntegration {
    fn default() -> Self {
        Self {
            compatibility_socket: CompatibilitySocket::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CompatibilitySocket {
    #[default]
    Auto,
    Disabled,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedSystemConfig {
    pub(crate) schema: u32,
    pub(crate) engine: EngineKind,
    pub(crate) image: String,
    pub(crate) cpus: u8,
    pub(crate) memory_bytes: u64,
    pub(crate) root_size_bytes: u64,
    pub(crate) data_size_bytes: u64,
    pub(crate) shares: Vec<ResolvedShare>,
    pub(crate) publish_bind: PublishBind,
    pub(crate) compatibility_socket: CompatibilitySocket,
    pub(crate) docker_socket: PathBuf,
    #[serde(default)]
    pub(crate) rosetta: bool,
    pub(crate) identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedShare {
    pub(crate) path: PathBuf,
    pub(crate) read_only: bool,
}

impl SystemConfig {
    pub(crate) fn resolve(
        &self,
        home: &Path,
        image_override: Option<&str>,
    ) -> eyre::Result<ResolvedSystemConfig> {
        if self.version != "1" {
            bail!(
                "unsupported daemon config version {:?}; expected \"1\"",
                self.version
            );
        }
        if self.system.resources.cpus == 0 {
            bail!("daemon.system.resources.cpus must be greater than zero");
        }
        let memory_bytes = parse_size(&self.system.resources.memory, "memory")?;
        let root_size_bytes = parse_size(
            self.system
                .storage
                .root_size
                .as_deref()
                .unwrap_or(DEFAULT_ROOT_SIZE),
            "root-size",
        )?;
        let data_size_bytes = parse_size(
            self.system
                .storage
                .data_size
                .as_deref()
                .unwrap_or(DEFAULT_DATA_SIZE),
            "data-size",
        )?;
        if root_size_bytes < 512 * 1024 * 1024 {
            bail!("daemon.system.storage.root-size must be at least 512MiB");
        }
        if data_size_bytes < 512 * 1024 * 1024 {
            bail!("daemon.system.storage.data-size must be at least 512MiB");
        }

        let home = home
            .canonicalize()
            .context("resolve configured home directory")?;
        let mut shares = Vec::new();
        if self.system.mounts.home {
            shares.push(ResolvedShare {
                path: home.clone(),
                read_only: false,
            });
        }
        for share in &self.system.mounts.additional {
            if !share.path.is_absolute() {
                bail!(
                    "additional share must be absolute: {}",
                    share.path.display()
                );
            }
            let path = share
                .path
                .canonicalize()
                .with_context(|| format!("resolve additional share {}", share.path.display()))?;
            if !path.is_dir() {
                bail!("additional share is not a directory: {}", path.display());
            }
            if path == Path::new("/") {
                bail!("sharing the host root directory is not supported");
            }
            if shares
                .iter()
                .any(|existing: &ResolvedShare| existing.path == path)
            {
                bail!("duplicate system share: {}", path.display());
            }
            if shares.iter().any(|existing| {
                existing.path.starts_with(&path) || path.starts_with(&existing.path)
            }) {
                bail!(
                    "overlapping system shares are not supported: {}",
                    path.display()
                );
            }
            shares.push(ResolvedShare {
                path,
                read_only: share.read_only,
            });
        }
        shares.sort_by(|left, right| left.path.cmp(&right.path));

        let image = image_override
            .map(str::to_owned)
            .or_else(|| self.system.image.clone())
            .map(Ok)
            .unwrap_or_else(default_image)?;
        if image.trim().is_empty() {
            bail!("daemon.system.image cannot be empty");
        }
        let docker_socket = home.join(".docker/run/silo.sock");
        let mut resolved = ResolvedSystemConfig {
            schema: 1,
            engine: self.system.engine,
            image,
            cpus: self.system.resources.cpus,
            memory_bytes,
            root_size_bytes,
            data_size_bytes,
            shares,
            publish_bind: self.system.networking.publish_bind,
            compatibility_socket: self.system.docker.compatibility_socket,
            docker_socket,
            rosetta: self.system.rosetta.unwrap_or_else(rosetta_available),
            identity: String::new(),
        };
        let bytes = serde_json::to_vec(&resolved).context("serialize resolved system config")?;
        resolved.identity = format!("fnv1a64:{:016x}", fnv1a64(&bytes));
        Ok(resolved)
    }
}

impl ResolvedSystemConfig {
    pub(crate) fn with_image(mut self, image: String) -> eyre::Result<Self> {
        self.image = image;
        self.recompute_identity()
    }

    /// Adopts the disk sizes an existing installation was created with.
    pub(crate) fn with_disk_sizes(
        mut self,
        root_size_bytes: u64,
        data_size_bytes: u64,
    ) -> eyre::Result<Self> {
        self.root_size_bytes = root_size_bytes;
        self.data_size_bytes = data_size_bytes;
        self.recompute_identity()
    }

    fn recompute_identity(mut self) -> eyre::Result<Self> {
        self.identity.clear();
        let bytes = serde_json::to_vec(&self).context("serialize resolved system config")?;
        self.identity = format!("fnv1a64:{:016x}", fnv1a64(&bytes));
        Ok(self)
    }
}

fn default_image() -> eyre::Result<String> {
    if let Some(image) = RELEASE_IMAGE {
        if !image.contains("@sha256:") {
            bail!("the build-time SILO_SYSTEM_IMAGE must use an immutable sha256 digest");
        }
        return Ok(image.to_string());
    }
    #[cfg(debug_assertions)]
    {
        Ok(DEVELOPMENT_IMAGE.to_string())
    }
    #[cfg(not(debug_assertions))]
    bail!("this release has no qualified default system image; configure daemon.system.image explicitly")
}

fn parse_size(value: &str, field: &str) -> eyre::Result<u64> {
    HumanSize::from_str(value)
        .map_err(|error| eyre::eyre!("invalid daemon.system {field}: {error}"))?
        .bytes()
        .map_err(|error| eyre::eyre!("invalid daemon.system {field}: {error}"))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

const fn default_cpus() -> u8 {
    4
}
fn default_memory() -> String {
    "8GiB".to_string()
}
/// Rosetta's Linux runtime, installed by `softwareupdate --install-rosetta`. vmmon
/// performs the authoritative Virtualization.framework check at start; this only picks
/// a sensible default so hosts without Rosetta keep working.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rosetta_available() -> bool {
    Path::new("/Library/Apple/usr/share/rosetta/rosetta").is_file()
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn rosetta_available() -> bool {
    false
}

// Both disks are sparse files: the sizes only bound what the guest may grow into and
// cost nothing on the host until written, so they are generous by default.
const DEFAULT_ROOT_SIZE: &str = "20GiB";
const DEFAULT_DATA_SIZE: &str = "500GiB";
const fn default_true() -> bool {
    true
}
const fn default_publish_bind() -> PublishBind {
    PublishBind::Any
}

#[cfg(test)]
mod tests {
    use crate::system::config::{CompatibilitySocket, SystemConfig};

    #[test]
    fn strict_config_resolves_home_and_defaults() {
        let temp = tempfile::tempdir().expect("temp home");
        let config: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nsystem:\n  image: 'registry.example/system@sha256:test'\n",
        )
        .expect("config");
        let resolved = config.resolve(temp.path(), None).expect("resolve");
        assert_eq!(resolved.shares.len(), 1);
        assert_eq!(resolved.memory_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(resolved.root_size_bytes, 20 * 1024 * 1024 * 1024);
        assert_eq!(resolved.data_size_bytes, 500 * 1024 * 1024 * 1024);
        assert!(!config.system.storage.explicit_data_size());
        let pinned_off: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem:\n  rosetta: false\n").expect("config");
        assert!(
            !pinned_off
                .resolve(temp.path(), None)
                .expect("resolve")
                .rosetta
        );
        let pinned = resolved
            .clone()
            .with_disk_sizes(8 << 30, 64 << 30)
            .expect("adopt sizes");
        assert_eq!(pinned.data_size_bytes, 64 << 30);
        assert_ne!(pinned.identity, resolved.identity);
        assert_eq!(resolved.compatibility_socket, CompatibilitySocket::Auto);
        assert!(resolved.identity.starts_with("fnv1a64:"));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_build_has_an_explicit_development_image() {
        let temp = tempfile::tempdir().expect("temp home");
        let config: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem: {}\n").expect("config");
        assert_eq!(
            config.resolve(temp.path(), None).expect("resolve").image,
            "ghcr.io/vandycknick/silo/system:dev"
        );
    }

    #[test]
    fn rejects_unknown_fields_and_overlapping_shares() {
        assert!(serde_yaml_ng::from_str::<SystemConfig>("version: '1'\nunknown: true\n").is_err());
        let home = tempfile::tempdir().expect("temp home");
        let child = home.path().join("child");
        std::fs::create_dir(&child).expect("child");
        let raw = format!(
            "version: '1'\nsystem:\n  mounts:\n    additional:\n      - path: {}\n",
            child.display()
        );
        let config: SystemConfig = serde_yaml_ng::from_str(&raw).expect("config");
        assert!(config.resolve(home.path(), None).is_err());
    }
}

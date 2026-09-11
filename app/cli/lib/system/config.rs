use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{bail, Context as _};
use libvm::PublishBind;
use serde::{Deserialize, Serialize};
use utils::HumanSize;

const DEFAULT_IMAGE: &str = "ghcr.io/vandycknick/system:dev";

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
pub(crate) struct SystemStorage {
    #[serde(default = "default_root_size", rename = "root-size")]
    pub(crate) root_size: String,
    #[serde(default = "default_data_size", rename = "data-size")]
    pub(crate) data_size: String,
}

impl Default for SystemStorage {
    fn default() -> Self {
        Self {
            root_size: default_root_size(),
            data_size: default_data_size(),
        }
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
        let root_size_bytes = parse_size(&self.system.storage.root_size, "root-size")?;
        let data_size_bytes = parse_size(&self.system.storage.data_size, "data-size")?;
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
            .unwrap_or_else(|| DEFAULT_IMAGE.to_string());
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
            identity: String::new(),
        };
        let bytes = serde_json::to_vec(&resolved).context("serialize resolved system config")?;
        resolved.identity = format!("fnv1a64:{:016x}", fnv1a64(&bytes));
        Ok(resolved)
    }
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
    "4GiB".to_string()
}
fn default_root_size() -> String {
    "8GiB".to_string()
}
fn default_data_size() -> String {
    "64GiB".to_string()
}
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
        let config: SystemConfig =
            serde_yaml_ng::from_str("version: '1'\nsystem: {}\n").expect("config");
        let resolved = config.resolve(temp.path(), None).expect("resolve");
        assert_eq!(resolved.shares.len(), 1);
        assert_eq!(resolved.data_size_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(resolved.compatibility_socket, CompatibilitySocket::Auto);
        assert!(resolved.identity.starts_with("fnv1a64:"));
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

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
    /// Backend selected for this daemon registration. Explicit config wins over the environment.
    #[serde(default)]
    pub(crate) backend: Option<SystemBackend>,
    #[serde(default)]
    pub(crate) system: SystemOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SystemBackend {
    Krun,
    Vz,
}

impl SystemBackend {
    pub(crate) fn runtime_override(self) -> libvm::VirtBackendOverride {
        match self {
            Self::Krun => libvm::VirtBackendOverride::Krun,
            Self::Vz => libvm::VirtBackendOverride::Vz,
        }
    }

    fn default_for_host() -> Self {
        Self::Krun
    }

    /// Preserve the meaning of schema-1 records written before `backend` was persisted.
    fn legacy_record_default() -> Self {
        if cfg!(target_os = "macos") {
            Self::Vz
        } else {
            Self::Krun
        }
    }
}

impl TryFrom<libvm::VirtBackendOverride> for SystemBackend {
    type Error = eyre::Report;

    fn try_from(value: libvm::VirtBackendOverride) -> Result<Self, Self::Error> {
        match value {
            libvm::VirtBackendOverride::Krun => Ok(Self::Krun),
            libvm::VirtBackendOverride::Vz => Ok(Self::Vz),
            libvm::VirtBackendOverride::Mock { .. } => {
                bail!("the mock backend cannot be used by the system daemon")
            }
            _ => bail!("the selected backend cannot be used by the system daemon"),
        }
    }
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
    #[serde(default = "SystemBackend::legacy_record_default")]
    pub(crate) backend: SystemBackend,
    #[serde(default)]
    pub(crate) rosetta: bool,
    /// Whether `rosetta` was explicitly configured. Old registrations preserve their value.
    #[serde(default = "default_true")]
    pub(crate) rosetta_explicit: bool,
    /// Retired installation-record policy, discarded during migration.
    #[serde(default, skip_serializing, deserialize_with = "discard_legacy_reclaim")]
    pub(crate) memory_reclaim: (),
    /// Accept old installation records without letting their retired policy disable reclaim.
    #[serde(
        default,
        skip_serializing,
        rename = "host_memory_reclaim",
        deserialize_with = "discard_legacy_reclaim"
    )]
    pub(crate) legacy_host_reclaim: (),
    #[serde(default, skip_serializing, deserialize_with = "discard_legacy_reclaim")]
    pub(crate) memory_reclaim_after_secs: (),
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
        let environment_backend = if self.backend.is_some() {
            None
        } else {
            libvm::VirtBackendOverride::from_env()?
                .map(SystemBackend::try_from)
                .transpose()?
        };
        self.resolve_with_backend_override(home, image_override, environment_backend)
    }

    fn resolve_with_backend_override(
        &self,
        home: &Path,
        image_override: Option<&str>,
        environment_backend: Option<SystemBackend>,
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
        let backend = self
            .backend
            .or(environment_backend)
            .unwrap_or_else(SystemBackend::default_for_host);
        let rosetta = self
            .system
            .rosetta
            .unwrap_or_else(|| backend == SystemBackend::Vz && rosetta_available());
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
            backend,
            rosetta,
            rosetta_explicit: self.system.rosetta.is_some(),
            memory_reclaim: (),
            legacy_host_reclaim: (),
            memory_reclaim_after_secs: (),
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
fn discard_legacy_reclaim<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<(), D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| ())
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
    use crate::system::config::{CompatibilitySocket, SystemBackend, SystemConfig};

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
        for key in [
            "memory-reclaim",
            "memory-reclaim-after",
            "host-memory-reclaim",
            "balloon",
        ] {
            assert!(serde_yaml_ng::from_str::<SystemConfig>(&format!(
                "version: '1'\nsystem:\n  resources:\n    {key}: off\n"
            ))
            .is_err());
        }
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
        assert_eq!(resolved.backend, SystemBackend::Krun);
        assert!(!resolved.rosetta);
        assert!(!resolved.rosetta_explicit);
        assert!(resolved.identity.starts_with("fnv1a64:"));
    }

    #[test]
    fn legacy_resolved_config_without_backend_keeps_historical_platform_selection() {
        let config: crate::system::config::ResolvedSystemConfig =
            serde_json::from_value(serde_json::json!({
                "schema": 1,
                "engine": "docker",
                "image": "registry.example/system@sha256:test",
                "cpus": 2,
                "memory_bytes": 1073741824,
                "root_size_bytes": 1073741824,
                "data_size_bytes": 1073741824,
                "shares": [],
                "publish_bind": "any",
                "compatibility_socket": "disabled",
                "docker_socket": "/tmp/silo.sock",
                "rosetta": true,
                "identity": "fnv1a64:test"
            }))
            .expect("legacy resolved config");

        assert_eq!(config.backend, SystemBackend::legacy_record_default());
        assert!(config.rosetta);
        assert!(config.rosetta_explicit);
        for old_policy in [false, true] {
            let mut encoded = serde_json::to_value(&config).expect("encode");
            encoded["host_memory_reclaim"] = serde_json::json!(old_policy);
            encoded["memory_reclaim"] = serde_json::json!(false);
            let migrated: crate::system::config::ResolvedSystemConfig =
                serde_json::from_value(encoded).expect("read legacy host policy");
            let encoded = serde_json::to_value(&migrated).expect("encode migrated");
            for key in [
                "host_memory_reclaim",
                "memory_reclaim",
                "memory_reclaim_after_secs",
            ] {
                assert!(encoded.get(key).is_none());
            }
        }
    }

    #[test]
    fn krun_defaults_rosetta_off_and_preserves_explicit_enablement() {
        let home = tempfile::tempdir().expect("temp home");
        let config: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nbackend: krun\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        let resolved = config.resolve(home.path(), None).expect("resolve");
        assert_eq!(resolved.backend, SystemBackend::Krun);
        assert!(!resolved.rosetta);
        assert!(!resolved.rosetta_explicit);

        let enabled: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nbackend: krun\nsystem:\n  image: registry.example/system@sha256:test\n  rosetta: true\n",
        )
        .expect("config");
        let enabled = enabled
            .resolve(home.path(), None)
            .expect("resolve Rosetta opt-in");
        assert!(enabled.rosetta);
        assert!(enabled.rosetta_explicit);
    }

    #[test]
    fn explicit_backend_wins_over_environment_and_resolved_value_is_persistable() {
        let home = tempfile::tempdir().expect("temp home");
        let config: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nbackend: vz\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        let resolved = config
            .resolve_with_backend_override(home.path(), None, Some(SystemBackend::Krun))
            .expect("resolve explicit VZ");
        assert_eq!(resolved.backend, SystemBackend::Vz);
        assert_eq!(
            serde_json::from_slice::<crate::system::config::ResolvedSystemConfig>(
                &serde_json::to_vec(&resolved).expect("serialize")
            )
            .expect("deserialize")
            .backend,
            SystemBackend::Vz
        );

        let environment_selected: SystemConfig = serde_yaml_ng::from_str(
            "version: '1'\nsystem:\n  image: registry.example/system@sha256:test\n",
        )
        .expect("config");
        assert_eq!(
            environment_selected
                .resolve_with_backend_override(home.path(), None, Some(SystemBackend::Krun))
                .expect("resolve environment krun")
                .backend,
            SystemBackend::Krun
        );
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

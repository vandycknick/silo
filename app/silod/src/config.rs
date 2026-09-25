//! Resolves the controller's explicit overrides against the installation.
//!
//! An omitted setting takes silod's default, except those fixed when the system VM
//! and its data disk were created (backend, root and data disk sizes), which keep the
//! recorded value.
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{bail, Context as _};
use libvm::PublishBind;
use serde::{Deserialize, Serialize};
use silod_spec::arguments::{Backend, SystemOverrides};
use utils::HumanSize;

use crate::record::DaemonRecord;

#[cfg(debug_assertions)]
const DEVELOPMENT_IMAGE: &str = "ghcr.io/vandycknick/silo/system:dev";
const RELEASE_IMAGE: Option<&str> = option_env!("SILO_SYSTEM_IMAGE");

const DEFAULT_CPUS: u8 = 4;
const DEFAULT_MEMORY: &str = "8GiB";
// Both disks are sparse files: the sizes only bound what the guest may grow into and
// cost nothing on the host until written, so they are generous by default.
const DEFAULT_ROOT_SIZE: &str = "20GiB";
const DEFAULT_DATA_SIZE: &str = "500GiB";

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
}

impl From<Backend> for SystemBackend {
    fn from(backend: Backend) -> Self {
        match backend {
            Backend::Krun => Self::Krun,
            Backend::Vz => Self::Vz,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EngineKind {
    #[default]
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedSystemConfig {
    pub(crate) schema: u32,
    pub(crate) engine: EngineKind,
    /// The digest-pinned image the active system VM runs, once it exists; before
    /// that, the reference to create it from.
    pub(crate) image: String,
    pub(crate) cpus: u8,
    pub(crate) memory_bytes: u64,
    pub(crate) root_size_bytes: u64,
    pub(crate) data_size_bytes: u64,
    pub(crate) shares: Vec<ResolvedShare>,
    pub(crate) publish_bind: PublishBind,
    pub(crate) docker_socket: PathBuf,
    pub(crate) backend: SystemBackend,
    pub(crate) rosetta: bool,
    pub(crate) rosetta_explicit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedShare {
    pub(crate) path: PathBuf,
    pub(crate) read_only: bool,
}

/// What the controller asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesiredSystem {
    pub(crate) config: ResolvedSystemConfig,
    /// The image reference silod follows, upgrading whenever it resolves to a
    /// different manifest than the active system VM runs.
    pub(crate) image: String,
}

/// `user_home` is shared into the system VM when configured; `docker_socket` is the
/// host endpoint silod serves.
pub(crate) fn resolve(
    overrides: &SystemOverrides,
    user_home: &Path,
    docker_socket: &Path,
    installation: Option<&DaemonRecord>,
) -> eyre::Result<DesiredSystem> {
    let recorded = installation.map(|record| &record.config);
    let cpus = overrides.cpus.unwrap_or(DEFAULT_CPUS);
    if cpus == 0 {
        bail!("system cpus must be greater than zero");
    }
    let memory_bytes = parse_size(
        overrides.memory.as_deref().unwrap_or(DEFAULT_MEMORY),
        "memory",
    )?;
    if memory_bytes < 128 * 1024 * 1024 {
        bail!("system memory must be at least 128MiB");
    }
    let root_size_bytes = match (&overrides.root_size, recorded) {
        (Some(size), _) => parse_size(size, "root-size")?,
        (None, Some(recorded)) => recorded.root_size_bytes,
        (None, None) => parse_size(DEFAULT_ROOT_SIZE, "root-size")?,
    };
    let data_size_bytes = match (&overrides.data_size, installation) {
        (Some(size), _) => parse_size(size, "data-size")?,
        (None, Some(record)) => record.data_size_bytes,
        (None, None) => parse_size(DEFAULT_DATA_SIZE, "data-size")?,
    };
    if root_size_bytes < 512 * 1024 * 1024 {
        bail!("system root-size must be at least 512MiB");
    }
    if data_size_bytes < 512 * 1024 * 1024 {
        bail!("system data-size must be at least 512MiB");
    }

    let user_home = user_home.canonicalize().context("resolve home directory")?;
    let mut shares = Vec::new();
    if overrides.home_share.unwrap_or(true) {
        shares.push(ResolvedShare {
            path: user_home.clone(),
            read_only: false,
        });
    }
    for share in overrides.additional_shares.as_deref().unwrap_or_default() {
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
        if shares
            .iter()
            .any(|existing| existing.path.starts_with(&path) || path.starts_with(&existing.path))
        {
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

    let image = match &overrides.image {
        Some(image) => image.clone(),
        None => default_image()?,
    };
    if image.trim().is_empty() {
        bail!("system image cannot be empty");
    }
    let backend = overrides
        .backend
        .map(SystemBackend::from)
        .or(recorded.map(|recorded| recorded.backend))
        .unwrap_or(SystemBackend::Krun);
    let rosetta = overrides
        .rosetta
        .unwrap_or_else(|| backend == SystemBackend::Vz && rosetta_available());
    let publish_bind = match overrides.publish_bind {
        Some(silod_spec::arguments::PublishBind::Loopback) => PublishBind::Loopback,
        Some(silod_spec::arguments::PublishBind::Any) | None => PublishBind::Any,
    };
    Ok(DesiredSystem {
        config: ResolvedSystemConfig {
            schema: 1,
            engine: EngineKind::Docker,
            image: image.clone(),
            cpus,
            memory_bytes,
            root_size_bytes,
            data_size_bytes,
            shares,
            publish_bind,
            docker_socket: docker_socket.to_path_buf(),
            backend,
            rosetta,
            rosetta_explicit: overrides.rosetta.is_some(),
        },
        image,
    })
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
    bail!("this release has no qualified default system image; specify --system-image explicitly")
}

fn parse_size(value: &str, field: &str) -> eyre::Result<u64> {
    HumanSize::from_str(value)
        .map_err(|error| eyre::eyre!("invalid system {field}: {error}"))?
        .bytes()
        .map_err(|error| eyre::eyre!("invalid system {field}: {error}"))
}

/// Rosetta's Linux runtime, installed by `softwareupdate --install-rosetta`. silo-vmm
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

#[cfg(test)]
mod tests {
    use silod_spec::arguments::{Backend, PublishBind, Share, SystemOverrides};

    use crate::config::{resolve, ResolvedSystemConfig, SystemBackend};
    use crate::paths::SystemPaths;
    use crate::record::DaemonRecord;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn pinned() -> SystemOverrides {
        SystemOverrides {
            image: Some("registry.example/system@sha256:test".into()),
            ..SystemOverrides::default()
        }
    }

    #[test]
    fn defaults_share_home_and_serve_the_given_socket() {
        let temp = tempfile::tempdir().expect("temp home");
        let socket = temp.path().join(".silo/run/docker.sock");
        let desired = resolve(&pinned(), temp.path(), &socket, None).expect("resolve");
        let config = &desired.config;
        assert_eq!(desired.image, "registry.example/system@sha256:test");
        assert_eq!(config.image, desired.image);
        assert_eq!(config.shares.len(), 1);
        assert!(!config.shares[0].read_only);
        assert_eq!(config.docker_socket, socket);
        assert_eq!(config.cpus, 4);
        assert_eq!(config.memory_bytes, 8 * GIB);
        assert_eq!(config.root_size_bytes, 20 * GIB);
        assert_eq!(config.data_size_bytes, 500 * GIB);
        assert_eq!(config.publish_bind, libvm::PublishBind::Any);
        assert_eq!(config.backend, SystemBackend::Krun);
        assert!(!config.rosetta);
        assert!(!config.rosetta_explicit);
    }

    #[test]
    fn explicit_overrides_apply_and_are_validated() {
        let temp = tempfile::tempdir().expect("temp home");
        let socket = temp.path().join("docker.sock");
        let overrides = SystemOverrides {
            backend: Some(Backend::Vz),
            cpus: Some(2),
            memory: Some("4GiB".into()),
            rosetta: Some(true),
            home_share: Some(false),
            publish_bind: Some(PublishBind::Loopback),
            ..pinned()
        };
        let config = resolve(&overrides, temp.path(), &socket, None)
            .expect("resolve")
            .config;
        assert_eq!(config.backend, SystemBackend::Vz);
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_bytes, 4 * GIB);
        assert!(config.rosetta && config.rosetta_explicit);
        assert!(config.shares.is_empty());
        assert_eq!(config.publish_bind, libvm::PublishBind::Loopback);
        assert_eq!(
            serde_json::from_value::<ResolvedSystemConfig>(
                serde_json::to_value(&config).expect("serialize")
            )
            .expect("record format")
            .backend,
            SystemBackend::Vz
        );

        for invalid in [
            SystemOverrides {
                cpus: Some(0),
                ..pinned()
            },
            SystemOverrides {
                memory: Some("64MiB".into()),
                ..pinned()
            },
            SystemOverrides {
                data_size: Some("not a size".into()),
                ..pinned()
            },
            SystemOverrides {
                image: Some(" ".into()),
                ..SystemOverrides::default()
            },
        ] {
            assert!(resolve(&invalid, temp.path(), &socket, None).is_err());
        }
    }

    #[test]
    fn additional_shares_must_be_distinct_existing_directories() {
        let home = tempfile::tempdir().expect("temp home");
        let child = home.path().join("child");
        std::fs::create_dir(&child).expect("child");
        let other = tempfile::tempdir().expect("other");
        let socket = home.path().join("docker.sock");
        let with = |shares: Vec<Share>| SystemOverrides {
            additional_shares: Some(shares),
            ..pinned()
        };
        let share = |path: &std::path::Path| Share {
            path: path.to_path_buf(),
            read_only: true,
        };
        let config = resolve(&with(vec![share(other.path())]), home.path(), &socket, None)
            .expect("separate share")
            .config;
        assert_eq!(config.shares.len(), 2);
        assert!(config.shares.iter().any(|share| share.read_only));
        for invalid in [
            vec![share(&child)],
            vec![share(std::path::Path::new("relative"))],
            vec![share(&home.path().join("missing"))],
            vec![share(other.path()), share(other.path())],
        ] {
            assert!(resolve(&with(invalid), home.path(), &socket, None).is_err());
        }
    }

    #[test]
    fn omission_defaults_changeable_settings_but_keeps_creation_fixed_ones() {
        let home = tempfile::tempdir().expect("home");
        let paths = SystemPaths::new(home.path().join(".silo"), home.path().join("run"));
        let socket = paths.docker_socket();
        let initial = SystemOverrides {
            backend: Some(Backend::Vz),
            cpus: Some(10),
            memory: Some("12GiB".into()),
            root_size: Some("24GiB".into()),
            data_size: Some("128GiB".into()),
            rosetta: Some(true),
            home_share: Some(false),
            publish_bind: Some(PublishBind::Loopback),
            ..pinned()
        };
        let created = resolve(&initial, home.path(), &socket, None).expect("initial");
        let record = DaemonRecord::new(created.config.clone());

        let restarted = resolve(
            &SystemOverrides::default(),
            home.path(),
            &socket,
            Some(&record),
        )
        .expect("restart")
        .config;
        assert_eq!(restarted.backend, SystemBackend::Vz);
        assert_eq!(restarted.root_size_bytes, 24 * GIB);
        assert_eq!(restarted.data_size_bytes, 128 * GIB);
        assert_eq!(restarted.cpus, 4);
        assert_eq!(restarted.memory_bytes, 8 * GIB);
        assert_eq!(restarted.shares.len(), 1);
        assert_eq!(restarted.publish_bind, libvm::PublishBind::Any);
        assert!(!restarted.rosetta_explicit);

        let resized = SystemOverrides {
            root_size: Some("30GiB".into()),
            ..SystemOverrides::default()
        };
        assert_eq!(
            resolve(&resized, home.path(), &socket, Some(&record))
                .expect("explicit root size")
                .config
                .root_size_bytes,
            30 * GIB
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_build_follows_the_development_image() {
        let temp = tempfile::tempdir().expect("temp home");
        let desired = resolve(
            &SystemOverrides::default(),
            temp.path(),
            &temp.path().join("docker.sock"),
            None,
        )
        .expect("resolve");
        let expected =
            option_env!("SILO_SYSTEM_IMAGE").unwrap_or("ghcr.io/vandycknick/silo/system:dev");
        assert_eq!(desired.image, expected);
    }
}

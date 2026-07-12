use std::path::{Path, PathBuf};

use crate::machine::{MachineAgent, MachineGuestConfig};
use crate::LibVmError;

const ENV_ASSET_DIR: &str = "SILO_ASSET_DIR";
const SYSTEM_ASSETS_DIR: &str = "/usr/local/share/silo/assets";
const USER_ASSETS_SUFFIX: &str = ".local/share/silo/assets";
const DEFAULT_KERNEL_FILENAME: &str = "kernel-default";
const DEFAULT_INITRAMFS_FILENAME: &str = "initramfs";
const DEFAULT_AGENT_FILENAME: &str = "agent";

#[derive(Debug, Clone)]
pub(crate) struct BootAssetOverrides<'a> {
    pub(crate) kernel: Option<&'a Path>,
    pub(crate) initramfs: Option<&'a Path>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedBootAssets {
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
}

pub(crate) fn resolve_boot_assets(
    overrides: BootAssetOverrides<'_>,
) -> Result<ResolvedBootAssets, LibVmError> {
    let directories = asset_directories()?;
    Ok(ResolvedBootAssets {
        kernel: resolve_asset(
            "kernel",
            overrides.kernel,
            DEFAULT_KERNEL_FILENAME,
            &directories,
        )?,
        initramfs: resolve_asset(
            "initramfs",
            overrides.initramfs,
            DEFAULT_INITRAMFS_FILENAME,
            &directories,
        )?,
    })
}

pub(crate) fn canonicalize_boot_overrides(
    overrides: BootAssetOverrides<'_>,
) -> Result<(Option<PathBuf>, Option<PathBuf>), LibVmError> {
    Ok((
        overrides
            .kernel
            .map(|path| require_asset("kernel", path))
            .transpose()?,
        overrides
            .initramfs
            .map(|path| require_asset("initramfs", path))
            .transpose()?,
    ))
}

pub(crate) fn canonicalize_guest_config(
    mut guest: MachineGuestConfig,
) -> Result<MachineGuestConfig, LibVmError> {
    if let MachineAgent::Custom { path } = &mut guest.agent {
        *path = require_asset("agent", path)?;
    }
    Ok(guest)
}

pub(crate) fn resolve_agent(agent: &MachineAgent) -> Result<Option<PathBuf>, LibVmError> {
    match agent {
        MachineAgent::Default => {
            let directories = asset_directories()?;
            resolve_asset("agent", None, DEFAULT_AGENT_FILENAME, &directories).map(Some)
        }
        MachineAgent::Custom { path } => require_asset("agent", path).map(Some),
        MachineAgent::Disabled => Ok(None),
    }
}

fn resolve_asset(
    asset: &'static str,
    explicit: Option<&Path>,
    filename: &'static str,
    directories: &[PathBuf],
) -> Result<PathBuf, LibVmError> {
    if let Some(path) = explicit {
        return require_asset(asset, path);
    }

    let mut checked = Vec::new();
    for directory in directories {
        let path = directory.join(filename);
        checked.push(path.display().to_string());
        if path.is_file() {
            return canonicalize_asset(asset, &path);
        }
    }

    Err(LibVmError::BootAssetNotFound {
        asset,
        checked: checked.join(", "),
    })
}

fn require_asset(asset: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    let absolute = absolute_path(path)?;
    if !absolute.is_file() {
        return Err(LibVmError::BootAssetInvalid {
            asset,
            path: absolute,
        });
    }
    canonicalize_asset(asset, &absolute)
}

fn canonicalize_asset(asset: &'static str, path: &Path) -> Result<PathBuf, LibVmError> {
    std::fs::canonicalize(path).map_err(|_| LibVmError::BootAssetInvalid {
        asset,
        path: path.to_path_buf(),
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, LibVmError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn asset_directories() -> Result<Vec<PathBuf>, LibVmError> {
    let mut directories = Vec::new();
    if let Some(value) = std::env::var_os(ENV_ASSET_DIR) {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(LibVmError::RelativeEnvironmentPath {
                name: ENV_ASSET_DIR,
                path,
            });
        }
        directories.push(path);
    }
    directories.push(PathBuf::from(SYSTEM_ASSETS_DIR));
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.is_absolute() {
            directories.push(home.join(USER_ASSETS_SUFFIX));
        }
    }
    Ok(directories)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use crate::machine::{MachineAgent, MachineGuestConfig};
    use crate::runtime::boot_assets::{
        canonicalize_boot_overrides, canonicalize_guest_config, resolve_asset, BootAssetOverrides,
    };

    fn write_asset(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("create asset dir");
        let path = dir.join(name);
        std::fs::write(&path, b"asset").expect("write asset");
        path
    }

    #[test]
    fn explicit_overrides_are_canonicalized_without_default_lookup() {
        let temp = TempDir::new().expect("tempdir");
        let kernel = write_asset(temp.path(), "custom-kernel");

        let (resolved_kernel, resolved_initramfs) =
            canonicalize_boot_overrides(BootAssetOverrides {
                kernel: Some(&kernel),
                initramfs: None,
            })
            .expect("canonicalize overrides");

        assert_eq!(
            resolved_kernel,
            Some(kernel.canonicalize().expect("canonical"))
        );
        assert!(resolved_initramfs.is_none());
    }

    #[test]
    fn defaults_fall_through_directories_independently() {
        let temp = TempDir::new().expect("tempdir");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let expected = write_asset(&second, "agent");

        let resolved = resolve_asset("agent", None, "agent", &[first, second])
            .expect("resolve fallback asset");

        assert_eq!(resolved, expected.canonicalize().expect("canonical"));
    }

    #[test]
    fn custom_agent_is_canonicalized_for_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let agent = write_asset(temp.path(), "custom-agent");
        let guest = MachineGuestConfig {
            agent: MachineAgent::Custom {
                path: agent.clone(),
            },
        };

        let guest = canonicalize_guest_config(guest).expect("canonicalize guest");

        assert_eq!(
            guest.agent,
            MachineAgent::Custom {
                path: agent.canonicalize().expect("canonical")
            }
        );
    }
}

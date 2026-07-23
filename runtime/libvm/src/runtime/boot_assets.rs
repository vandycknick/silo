use std::path::{Path, PathBuf};

use crate::machine::{MachineAgent, MachineGuestConfig};
use crate::LibVmError;

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
    default_kernel: &Path,
    default_initramfs: &Path,
) -> Result<ResolvedBootAssets, LibVmError> {
    Ok(ResolvedBootAssets {
        kernel: resolve_asset("kernel", overrides.kernel, default_kernel)?,
        initramfs: resolve_asset("initramfs", overrides.initramfs, default_initramfs)?,
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

pub(crate) fn resolve_agent(
    agent: &MachineAgent,
    default_agent: &Path,
) -> Result<Option<PathBuf>, LibVmError> {
    match agent {
        MachineAgent::Default => Ok(Some(default_agent.to_path_buf())),
        MachineAgent::Custom { path } => require_asset("agent", path).map(Some),
        MachineAgent::Disabled => Ok(None),
    }
}

fn resolve_asset(
    asset: &'static str,
    explicit: Option<&Path>,
    default: &Path,
) -> Result<PathBuf, LibVmError> {
    if let Some(path) = explicit {
        return require_asset(asset, path);
    }

    Ok(default.to_path_buf())
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use crate::machine::{MachineAgent, MachineGuestConfig};
    use crate::runtime::boot_assets::{
        canonicalize_boot_overrides, canonicalize_guest_config, BootAssetOverrides,
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
    fn custom_agent_is_canonicalized_for_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let agent = write_asset(temp.path(), "custom-agent");
        let guest = MachineGuestConfig {
            agent: MachineAgent::Custom {
                path: agent.clone(),
            },
            user: None,
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

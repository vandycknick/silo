use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::LibVmError;

const ENV_KERNEL_PATH: &str = "SILO_KERNEL_PATH";
const ENV_INITRAMFS_PATH: &str = "SILO_INITRAMFS_PATH";
const SYSTEM_ASSETS_DIR: &str = "/usr/local/share/silo/assets";
const USER_ASSETS_SUFFIX: &str = ".local/share/silo/assets";
const DEFAULT_KERNEL_FILENAME: &str = "kernel-default";
const DEFAULT_INITRAMFS_FILENAME: &str = "initramfs";

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeBootDefaults {
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initramfs: Option<PathBuf>,
}

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
    defaults: &RuntimeBootDefaults,
) -> Result<ResolvedBootAssets, LibVmError> {
    let standard_dirs = standard_asset_dirs();
    Ok(ResolvedBootAssets {
        kernel: resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: overrides.kernel,
            runtime_default: defaults.kernel.as_deref(),
            env_name: ENV_KERNEL_PATH,
            env_value: std::env::var_os(ENV_KERNEL_PATH),
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: &standard_dirs,
        })?,
        initramfs: resolve_asset(ResolveAssetInput {
            asset: "initramfs",
            explicit: overrides.initramfs,
            runtime_default: defaults.initramfs.as_deref(),
            env_name: ENV_INITRAMFS_PATH,
            env_value: std::env::var_os(ENV_INITRAMFS_PATH),
            filename: DEFAULT_INITRAMFS_FILENAME,
            standard_dirs: &standard_dirs,
        })?,
    })
}

struct ResolveAssetInput<'a> {
    asset: &'static str,
    explicit: Option<&'a Path>,
    runtime_default: Option<&'a Path>,
    env_name: &'static str,
    env_value: Option<OsString>,
    filename: &'static str,
    standard_dirs: &'a [PathBuf],
}

fn resolve_asset(input: ResolveAssetInput<'_>) -> Result<PathBuf, LibVmError> {
    let mut checked = Vec::new();

    if let Some(path) = input.explicit {
        checked.push(format!("machine override {}", display_path(path)));
        return require_asset(input.asset, path);
    }

    if let Some(path) = input.runtime_default {
        checked.push(format!("runtime default {}", display_path(path)));
        return require_asset(input.asset, path);
    }

    match input.env_value {
        Some(value) => {
            let path = PathBuf::from(value);
            checked.push(format!("{}={}", input.env_name, display_path(&path)));
            if !path.is_absolute() {
                return Err(LibVmError::RelativeEnvironmentPath {
                    name: input.env_name,
                    path,
                });
            }
            return require_asset(input.asset, &path);
        }
        None => checked.push(format!("{} unset", input.env_name)),
    }

    for dir in input.standard_dirs {
        let path = dir.join(input.filename);
        checked.push(display_path(&path));
        if path.is_file() {
            return canonicalize_asset(input.asset, &path);
        }
    }

    Err(LibVmError::BootAssetNotFound {
        asset: input.asset,
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

fn standard_asset_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(SYSTEM_ASSETS_DIR)];
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if home.is_absolute() {
            dirs.push(home.join(USER_ASSETS_SUFFIX));
        }
    }
    dirs
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use crate::runtime::boot_assets::{
        resolve_asset, ResolveAssetInput, DEFAULT_KERNEL_FILENAME, ENV_KERNEL_PATH,
    };
    use crate::LibVmError;

    fn write_asset(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("create asset dir");
        let path = dir.join(name);
        std::fs::write(&path, b"asset").expect("write asset");
        path
    }

    #[test]
    fn explicit_asset_wins_over_runtime_default() {
        let temp = TempDir::new().expect("tempdir");
        let explicit = write_asset(temp.path(), "explicit-kernel");
        let runtime_default = write_asset(temp.path(), "runtime-kernel");

        let resolved = resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: Some(&explicit),
            runtime_default: Some(&runtime_default),
            env_name: ENV_KERNEL_PATH,
            env_value: None,
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: &[],
        })
        .expect("resolve explicit asset");

        assert_eq!(
            resolved,
            explicit.canonicalize().expect("canonical explicit")
        );
    }

    #[test]
    fn runtime_default_wins_over_environment() {
        let temp = TempDir::new().expect("tempdir");
        let runtime_default = write_asset(temp.path(), "runtime-kernel");
        let env_default = write_asset(temp.path(), "env-kernel");

        let resolved = resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: None,
            runtime_default: Some(&runtime_default),
            env_name: ENV_KERNEL_PATH,
            env_value: Some(env_default.into_os_string()),
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: &[],
        })
        .expect("resolve runtime default");

        assert_eq!(
            resolved,
            runtime_default.canonicalize().expect("canonical runtime")
        );
    }

    #[test]
    fn environment_wins_over_standard_locations() {
        let temp = TempDir::new().expect("tempdir");
        let env_default = write_asset(temp.path(), "env-kernel");
        let standard_dir = temp.path().join("standard");
        write_asset(&standard_dir, DEFAULT_KERNEL_FILENAME);

        let resolved = resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: None,
            runtime_default: None,
            env_name: ENV_KERNEL_PATH,
            env_value: Some(env_default.clone().into_os_string()),
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: &[standard_dir],
        })
        .expect("resolve env asset");

        assert_eq!(resolved, env_default.canonicalize().expect("canonical env"));
    }

    #[test]
    fn standard_locations_are_checked_in_order() {
        let temp = TempDir::new().expect("tempdir");
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let expected = write_asset(&second, DEFAULT_KERNEL_FILENAME);

        let resolved = resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: None,
            runtime_default: None,
            env_name: ENV_KERNEL_PATH,
            env_value: None,
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: &[first, second],
        })
        .expect("resolve standard asset");

        assert_eq!(
            resolved,
            expected.canonicalize().expect("canonical standard")
        );
    }

    #[test]
    fn missing_asset_lists_checked_sources() {
        let temp = TempDir::new().expect("tempdir");
        let standard_dir = temp.path().join("missing");

        let err = resolve_asset(ResolveAssetInput {
            asset: "kernel",
            explicit: None,
            runtime_default: None,
            env_name: ENV_KERNEL_PATH,
            env_value: None,
            filename: DEFAULT_KERNEL_FILENAME,
            standard_dirs: std::slice::from_ref(&standard_dir),
        })
        .expect_err("missing asset should fail");

        assert!(matches!(
            err,
            LibVmError::BootAssetNotFound { asset: "kernel", checked }
                if checked.contains("SILO_KERNEL_PATH unset")
                    && checked.contains(&standard_dir.join(DEFAULT_KERNEL_FILENAME).display().to_string())
        ));
    }
}

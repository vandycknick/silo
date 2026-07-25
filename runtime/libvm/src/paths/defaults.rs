use std::ffi::OsString;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::LibVmError;

const APP_DIR_NAME: &str = "silo";

pub(crate) fn resolve_default_data_dir() -> Result<PathBuf, LibVmError> {
    let home = env_absolute_path("HOME")?;
    let data_home = env_absolute_path("XDG_DATA_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".local/share")));

    data_home
        .map(|path| path.join(APP_DIR_NAME))
        .ok_or(LibVmError::DataDirUnavailable)
}

pub(crate) fn resolve_default_state_dir() -> Result<PathBuf, LibVmError> {
    let home = env_absolute_path("HOME")?;
    let state_home = env_absolute_path("XDG_STATE_HOME")?
        .or_else(|| home.as_ref().map(|path| path.join(".local/state")));

    state_home
        .map(|path| path.join(APP_DIR_NAME))
        .ok_or(LibVmError::StateDirUnavailable)
}

pub(crate) fn resolve_default_run_dir() -> Result<PathBuf, LibVmError> {
    if let Some(runtime_dir) = env_absolute_path("XDG_RUNTIME_DIR")? {
        return Ok(runtime_dir.join(APP_DIR_NAME));
    }

    let temp_dir = std::env::temp_dir();
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    #[cfg(target_os = "macos")]
    {
        Ok(fallback_run_dir(&temp_dir, effective_uid))
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback_run_dir(&temp_dir, effective_uid)
    }
}

#[cfg(target_os = "macos")]
fn fallback_run_dir(_temp_dir: &Path, effective_uid: u32) -> PathBuf {
    Path::new("/tmp").join(format!("{APP_DIR_NAME}-{effective_uid}"))
}

#[cfg(not(target_os = "macos"))]
fn fallback_run_dir(temp_dir: &Path, effective_uid: u32) -> Result<PathBuf, LibVmError> {
    if directory_is_private_to_effective_user(temp_dir)? {
        Ok(temp_dir.join(APP_DIR_NAME))
    } else {
        Ok(temp_dir.join(format!("{APP_DIR_NAME}-{effective_uid}")))
    }
}

pub(crate) fn ensure_secure_run_dir(path: &Path) -> Result<(), LibVmError> {
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }

    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    let expected_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || mode & 0o077 != 0
    {
        return Err(LibVmError::UnsafeRunDirectory {
            path: path.to_path_buf(),
            expected_uid,
            actual_uid: metadata.uid(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn directory_is_private_to_effective_user(path: &Path) -> Result<bool, LibVmError> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(!metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.mode() & 0o077 == 0)
}

fn env_absolute_path(name: &'static str) -> Result<Option<PathBuf>, LibVmError> {
    match std::env::var_os(name) {
        Some(value) => absolute_path(name, value).map(Some),
        None => Ok(None),
    }
}

fn absolute_path(name: &'static str, value: OsString) -> Result<PathBuf, LibVmError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(LibVmError::RelativeEnvironmentPath { name, path })
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;
    use std::process::Command;

    use std::os::unix::fs::{symlink, PermissionsExt};

    #[cfg(target_os = "macos")]
    use super::fallback_run_dir;
    use super::{absolute_path, ensure_secure_run_dir};
    use crate::LibVmError;

    const UMASK_CHILD_RUN_DIR: &str = "SILO_RUN_DIR_UMASK_CHILD";

    #[test]
    fn absolute_path_rejects_relative_env_values() {
        let err = absolute_path("XDG_DATA_HOME", OsString::from("relative"))
            .expect_err("relative path should be rejected");

        assert!(matches!(
            err,
            LibVmError::RelativeEnvironmentPath {
                name: "XDG_DATA_HOME",
                path
            } if path == Path::new("relative")
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_fallback_uses_short_user_specific_tmp_path() {
        let nix_temp =
            Path::new("/var/folders/5v/l61twqw154d2gpwj7r8n7vyh0000gn/T/nix-shell.E8PWtQ");

        assert_eq!(fallback_run_dir(nix_temp, 501), Path::new("/tmp/silo-501"));
    }

    #[test]
    fn secure_run_directory_is_private() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("runtime");

        ensure_secure_run_dir(&path).expect("create secure runtime dir");

        let metadata = std::fs::metadata(path).expect("runtime metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn secure_run_directory_creates_private_missing_parent_directories() {
        if let Some(path) = std::env::var_os(UMASK_CHILD_RUN_DIR) {
            ensure_secure_run_dir(Path::new(&path)).expect("create child runtime dir");
            return;
        }

        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("missing/parent/runtime");

        let test_binary = std::env::current_exe().expect("test binary");
        let status = Command::new("sh")
            .args(["-c", "umask 000; exec \"$@\"", "sh"])
            .arg(test_binary)
            .args([
                "--exact",
                "paths::defaults::tests::secure_run_directory_creates_private_missing_parent_directories",
                "--nocapture",
            ])
            .env(UMASK_CHILD_RUN_DIR, &path)
            .status()
            .expect("run secure directory child");
        assert!(status.success(), "secure directory child failed: {status}");

        for directory in [
            temp.path().join("missing"),
            temp.path().join("missing/parent"),
            path,
        ] {
            let metadata = std::fs::metadata(&directory).expect("runtime metadata");
            assert!(metadata.is_dir());
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o700,
                "unexpected mode for {}",
                directory.display()
            );
        }
    }

    #[test]
    fn secure_run_directory_rejects_unsafe_permissions() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let path = temp.path().join("runtime");
        std::fs::create_dir(&path).expect("create runtime dir");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("set unsafe permissions");

        let error = ensure_secure_run_dir(&path).expect_err("unsafe mode must fail");
        assert!(matches!(error, LibVmError::UnsafeRunDirectory { .. }));
    }

    #[test]
    fn secure_run_directory_rejects_symlinks() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let target = temp.path().join("target");
        let path = temp.path().join("runtime");
        std::fs::create_dir(&target).expect("create target");
        symlink(target, &path).expect("create symlink");

        let error = ensure_secure_run_dir(&path).expect_err("symlink must fail");
        assert!(matches!(error, LibVmError::UnsafeRunDirectory { .. }));
    }
}

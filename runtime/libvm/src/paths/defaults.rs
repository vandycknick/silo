use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode};
use nix::unistd::geteuid;

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
    env_absolute_path("XDG_RUNTIME_DIR")
        .map(|runtime_dir| runtime_dir.map(|path| path.join(APP_DIR_NAME)))
        .map(|runtime_dir| {
            runtime_dir
                .unwrap_or_else(|| PathBuf::from(format!("/tmp/silo-{}", geteuid().as_raw())))
        })
}

pub(crate) fn ensure_run_root(path: &Path) -> Result<(), LibVmError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_run_root(path, "has no parent directory"))?;
    fs::create_dir_all(parent).map_err(|err| invalid_run_root(path, err))?;

    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => false,
        Err(err) => return Err(invalid_run_root(path, err)),
    };

    let directory = open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|err| invalid_run_root(path, err))?;
    if created {
        fchmod(&directory, Mode::from_bits_truncate(0o700))
            .map_err(|err| invalid_run_root(path, err))?;
    }

    let metadata = fstat(&directory).map_err(|err| invalid_run_root(path, err))?;
    if metadata.st_uid != geteuid().as_raw() {
        return Err(invalid_run_root(
            path,
            format!(
                "is owned by uid {}, expected effective uid {}",
                metadata.st_uid,
                geteuid().as_raw()
            ),
        ));
    }
    if metadata.st_mode & 0o7777 != 0o700 {
        return Err(invalid_run_root(
            path,
            format!("has mode {:o}, expected 700", metadata.st_mode & 0o7777),
        ));
    }
    Ok(())
}

fn invalid_run_root(path: &Path, message: impl std::fmt::Display) -> LibVmError {
    LibVmError::InvalidRunRoot {
        path: path.to_path_buf(),
        message: message.to_string(),
    }
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
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::process::Command;

    use nix::unistd::geteuid;

    use crate::paths::defaults::{
        absolute_path, ensure_run_root, resolve_default_data_dir, resolve_default_run_dir,
        resolve_default_state_dir,
    };
    use crate::LibVmError;

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

    #[test]
    fn run_root_creation_requires_exact_private_permissions() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let run_root = temp.path().join("run");

        ensure_run_root(&run_root).expect("create run root");

        let metadata = std::fs::metadata(&run_root).expect("stat run root");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
        assert_eq!(metadata.uid(), geteuid().as_raw());
    }

    #[test]
    fn run_root_rejects_symlink_file_and_unsafe_mode() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let target = temp.path().join("target");
        std::fs::create_dir(&target).expect("create target");
        let symlink_root = temp.path().join("symlink");
        symlink(&target, &symlink_root).expect("create symlink");
        assert!(ensure_run_root(&symlink_root).is_err());

        let file_root = temp.path().join("file");
        std::fs::write(&file_root, b"not a directory").expect("create file");
        assert!(ensure_run_root(&file_root).is_err());

        let mode_root = temp.path().join("mode");
        std::fs::create_dir(&mode_root).expect("create mode directory");
        std::fs::set_permissions(&mode_root, std::fs::Permissions::from_mode(0o755))
            .expect("set unsafe mode");
        assert!(ensure_run_root(&mode_root).is_err());
    }

    #[test]
    fn run_root_rejects_foreign_owner_when_running_as_root() {
        if !geteuid().is_root() {
            return;
        }

        let temp = tempfile::tempdir().expect("create temp dir");
        let run_root = temp.path().join("foreign");
        std::fs::create_dir(&run_root).expect("create run root");
        nix::unistd::chown(&run_root, Some(nix::unistd::Uid::from_raw(1)), None)
            .expect("change owner");

        assert!(ensure_run_root(&run_root).is_err());
    }

    #[test]
    fn environment_probe() {
        let Some(mode) = std::env::var_os("SILO_PATHS_TEST_PROBE") else {
            return;
        };
        if mode == "reject-relative" {
            let operation = std::env::var("SILO_PATHS_TEST_OPERATION").expect("probe operation");
            let error = match operation.as_str() {
                "data" => resolve_default_data_dir().expect_err("reject relative data path"),
                "state" => resolve_default_state_dir().expect_err("reject relative state path"),
                "run" => resolve_default_run_dir().expect_err("reject relative run path"),
                _ => panic!("unknown probe operation {operation}"),
            };
            assert!(matches!(error, LibVmError::RelativeEnvironmentPath { .. }));
            return;
        }

        let expected_data = std::env::var_os("SILO_EXPECT_DATA").expect("expected data path");
        let expected_state = std::env::var_os("SILO_EXPECT_STATE").expect("expected state path");
        let expected_run = std::env::var_os("SILO_EXPECT_RUN").expect("expected run path");
        assert_eq!(
            resolve_default_data_dir().expect("resolve data"),
            std::path::PathBuf::from(expected_data)
        );
        assert_eq!(
            resolve_default_state_dir().expect("resolve state"),
            std::path::PathBuf::from(expected_state)
        );
        assert_eq!(
            resolve_default_run_dir().expect("resolve run"),
            std::path::PathBuf::from(expected_run)
        );
    }

    #[test]
    fn environment_resolution_uses_absolute_xdg_paths_and_fallbacks() {
        let temp = tempfile::tempdir().expect("create temp dir");
        run_environment_probe(
            [
                ("HOME", temp.path().join("home")),
                ("XDG_DATA_HOME", temp.path().join("data")),
                ("XDG_STATE_HOME", temp.path().join("state")),
                ("XDG_RUNTIME_DIR", temp.path().join("runtime")),
            ],
            temp.path().join("data/silo"),
            temp.path().join("state/silo"),
            temp.path().join("runtime/silo"),
        );
        run_environment_probe(
            [("HOME", temp.path().join("home"))],
            temp.path().join("home/.local/share/silo"),
            temp.path().join("home/.local/state/silo"),
            std::path::PathBuf::from(format!("/tmp/silo-{}", geteuid().as_raw())),
        );
    }

    #[test]
    fn environment_resolution_rejects_relative_xdg_and_home_paths() {
        for (name, value, operation) in [
            ("XDG_DATA_HOME", "relative", "data"),
            ("XDG_STATE_HOME", "relative", "state"),
            ("XDG_RUNTIME_DIR", "relative", "run"),
            ("HOME", "relative", "data"),
        ] {
            let output = Command::new(std::env::current_exe().expect("current test executable"))
                .arg("--exact")
                .arg("paths::defaults::tests::environment_probe")
                .env_clear()
                .env("SILO_PATHS_TEST_PROBE", "reject-relative")
                .env("SILO_PATHS_TEST_OPERATION", operation)
                .env(name, value)
                .output()
                .expect("run environment probe");
            assert!(output.status.success(), "{name} should be rejected");
        }
    }

    fn run_environment_probe<const N: usize>(
        environment: [(&str, std::path::PathBuf); N],
        data: std::path::PathBuf,
        state: std::path::PathBuf,
        run: std::path::PathBuf,
    ) {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("paths::defaults::tests::environment_probe")
            .env_clear()
            .env("SILO_PATHS_TEST_PROBE", "1")
            .env("SILO_EXPECT_DATA", data)
            .env("SILO_EXPECT_STATE", state)
            .env("SILO_EXPECT_RUN", run);
        for (name, value) in environment {
            command.env(name, value);
        }
        let status = command.status().expect("run environment probe");
        assert!(status.success(), "environment probe should succeed");
    }
}

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fchmod, fstat, Mode};
use nix::unistd::geteuid;

use crate::LibVmError;

/// Directory under `$HOME` holding every piece of persistent Silo state.
const HOME_DIR_NAME: &str = ".silo";
/// Overrides the Silo home; must be absolute.
pub(crate) const SILO_HOME_ENV: &str = "SILO_HOME";

/// Resolves the Silo home: `SILO_HOME`, else `$HOME/.silo`.
pub(crate) fn resolve_default_home() -> Result<PathBuf, LibVmError> {
    if let Some(home) = env_absolute_path(SILO_HOME_ENV)? {
        return Ok(home);
    }
    env_absolute_path("HOME")?
        .map(|home| home.join(HOME_DIR_NAME))
        .ok_or(LibVmError::HomeUnavailable)
}

/// The run root for generated sockets, pidfiles and locks. It is fixed and
/// independent of the home directory so Unix socket paths stay well inside
/// `sun_path` no matter how long the home path is.
pub(crate) fn default_run_root() -> PathBuf {
    PathBuf::from(format!("/tmp/silo-{}", geteuid().as_raw()))
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

pub(crate) fn env_absolute_path(name: &'static str) -> Result<Option<PathBuf>, LibVmError> {
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
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use nix::unistd::geteuid;

    use crate::paths::defaults::{
        absolute_path, default_run_root, ensure_run_root, resolve_default_home,
    };
    use crate::LibVmError;

    #[test]
    fn absolute_path_rejects_relative_env_values() {
        let err = absolute_path("SILO_HOME", OsString::from("relative"))
            .expect_err("relative path should be rejected");

        assert!(matches!(
            err,
            LibVmError::RelativeEnvironmentPath {
                name: "SILO_HOME",
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

    /// Runs in a child process with a controlled environment (see the tests below).
    #[test]
    fn environment_probe() {
        let Some(mode) = std::env::var_os("SILO_PATHS_TEST_PROBE") else {
            return;
        };
        if mode == "reject" {
            assert!(matches!(
                resolve_default_home().expect_err("reject home"),
                LibVmError::RelativeEnvironmentPath { .. } | LibVmError::HomeUnavailable
            ));
            return;
        }
        let expected_home = std::env::var_os("SILO_EXPECT_HOME").expect("expected home");
        assert_eq!(
            resolve_default_home().expect("resolve home"),
            PathBuf::from(expected_home)
        );
        assert_eq!(
            default_run_root(),
            PathBuf::from(format!("/tmp/silo-{}", geteuid().as_raw()))
        );
    }

    fn probe<const N: usize>(mode: &str, environment: [(&str, PathBuf); N]) -> bool {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .arg("--exact")
            .arg("paths::defaults::tests::environment_probe")
            .env_clear()
            .env("SILO_PATHS_TEST_PROBE", mode);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.status().expect("run environment probe").success()
    }

    #[test]
    fn home_prefers_silo_home_then_dot_silo_and_ignores_xdg() {
        let temp = tempfile::tempdir().expect("create temp dir");
        assert!(probe(
            "resolve",
            [
                ("HOME", temp.path().join("user")),
                ("SILO_HOME", temp.path().join("custom")),
                ("SILO_EXPECT_HOME", temp.path().join("custom")),
            ]
        ));
        assert!(probe(
            "resolve",
            [
                ("HOME", temp.path().join("user")),
                ("XDG_DATA_HOME", temp.path().join("data")),
                ("XDG_STATE_HOME", temp.path().join("state")),
                ("XDG_RUNTIME_DIR", temp.path().join("runtime")),
                ("SILO_EXPECT_HOME", temp.path().join("user/.silo")),
            ]
        ));
    }

    #[test]
    fn home_rejects_relative_or_missing_environment() {
        assert!(probe("reject", [("SILO_HOME", PathBuf::from("relative"))]));
        assert!(probe("reject", [("HOME", PathBuf::from("relative"))]));
        assert!(probe("reject", []));
    }
}

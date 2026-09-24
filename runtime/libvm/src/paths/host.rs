use std::path::{Path, PathBuf};

use crate::paths::defaults::{default_run_root, env_absolute_path, resolve_default_home};
use crate::LibVmError;

const CONFIG_FILE_NAME: &str = "config.yaml";

/// Host locations shared by every Silo frontend.
///
/// ```text
/// $XDG_CONFIG_HOME/silo/   configuration: config.yaml, templates/, policies
///                          (default ~/.config/silo)
/// <home>/                  all persistent state (SILO_HOME, else ~/.silo);
///                          <home>/config.yaml is the fallback config file
/// /tmp/silo-<euid>/        generated sockets, pidfiles and locks
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    home: PathBuf,
    config_dir: PathBuf,
}

impl HostPaths {
    /// Resolves the host paths from the process environment.
    pub fn from_env() -> Result<Self, LibVmError> {
        let home = resolve_default_home()?;
        let config_dir = match env_absolute_path("XDG_CONFIG_HOME")? {
            Some(config_home) => config_home,
            None => env_absolute_path("HOME")?
                .map(|home| home.join(".config"))
                .ok_or(LibVmError::ConfigDirUnavailable)?,
        }
        .join("silo");
        Ok(Self::new(home, config_dir))
    }

    /// Host paths with explicit roots.
    pub fn new(home: impl Into<PathBuf>, config_dir: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            config_dir: config_dir.into(),
        }
    }

    /// The Silo home holding all persistent state.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The configuration directory: `config.yaml`, templates and policies.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// The config file to read: `<config_dir>/config.yaml` if it exists, else
    /// `<home>/config.yaml` if that exists, else `<config_dir>/config.yaml`,
    /// which is also where new configuration is written.
    pub fn config_file(&self) -> PathBuf {
        let primary = self.config_dir.join(CONFIG_FILE_NAME);
        let fallback = self.home.join(CONFIG_FILE_NAME);
        if !primary.exists() && fallback.exists() {
            return fallback;
        }
        primary
    }

    /// Directory for fixed-name control sockets such as `docker.sock`.
    pub fn control_socket_dir(&self) -> PathBuf {
        self.home.join("run")
    }

    /// Create `<home>/logs/<component>` for a frontend with the same ownership,
    /// no-symlink, and private-mode requirements as libvm's machine logs.
    pub fn ensure_log_dir(home: &Path, component: &str) -> Result<PathBuf, LibVmError> {
        crate::paths::OwnedDirectory::open_root(home)?
            .ensure_dir("logs")?
            .ensure_dir(component)?;
        Ok(home.join("logs").join(component))
    }

    /// Root for generated sockets, pidfiles and locks. Fixed so socket paths
    /// stay inside `sun_path` regardless of the home path's length.
    pub fn run_root() -> PathBuf {
        default_run_root()
    }
}

#[cfg(test)]
mod tests {
    use crate::paths::HostPaths;

    #[test]
    fn config_file_prefers_the_config_dir_then_the_home_fallback() {
        let temp = tempfile::tempdir().expect("temp dir");
        let paths = HostPaths::new(temp.path().join("home"), temp.path().join("config"));
        assert_eq!(paths.config_file(), temp.path().join("config/config.yaml"));

        std::fs::create_dir_all(temp.path().join("home")).expect("home");
        std::fs::write(temp.path().join("home/config.yaml"), b"{}").expect("fallback");
        assert_eq!(paths.config_file(), temp.path().join("home/config.yaml"));

        std::fs::create_dir_all(temp.path().join("config")).expect("config dir");
        std::fs::write(temp.path().join("config/config.yaml"), b"{}").expect("primary");
        assert_eq!(paths.config_file(), temp.path().join("config/config.yaml"));
    }

    #[test]
    fn frontend_log_directories_are_private_and_reusable() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::tempdir().expect("temp");
        let paths = HostPaths::new(temp.path().join("home"), temp.path().join("config"));
        let log_dir = HostPaths::ensure_log_dir(paths.home(), "daemon").expect("create logs");
        assert_eq!(log_dir, paths.home().join("logs/daemon"));
        for path in [paths.home().join("logs"), log_dir.clone()] {
            assert_eq!(
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            HostPaths::ensure_log_dir(paths.home(), "daemon").expect("reuse"),
            log_dir
        );
        assert!(HostPaths::ensure_log_dir(paths.home(), "../escape").is_err());
    }

    #[test]
    fn frontend_logs_refuse_foreign_modes_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let temp = tempfile::tempdir().expect("temp");
        let paths = HostPaths::new(temp.path().join("home"), temp.path().join("config"));
        std::fs::create_dir_all(paths.home()).expect("home");
        symlink(temp.path(), paths.home().join("logs")).expect("symlink");
        assert!(HostPaths::ensure_log_dir(paths.home(), "daemon").is_err());
        std::fs::remove_file(paths.home().join("logs")).expect("remove symlink");
        let logs = HostPaths::ensure_log_dir(paths.home(), "daemon").expect("logs");
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o755))
            .expect("wrong mode");
        assert!(HostPaths::ensure_log_dir(paths.home(), "daemon").is_err());
        assert_eq!(
            std::fs::metadata(logs)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn control_sockets_live_in_home_and_generated_state_in_tmp() {
        let paths = HostPaths::new("/Users/me/.silo", "/Users/me/.config/silo");
        assert_eq!(
            paths.control_socket_dir(),
            std::path::PathBuf::from("/Users/me/.silo/run")
        );
        assert_eq!(
            HostPaths::run_root(),
            std::path::PathBuf::from(format!("/tmp/silo-{}", nix::unistd::geteuid()))
        );
    }
}

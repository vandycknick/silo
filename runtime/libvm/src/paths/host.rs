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

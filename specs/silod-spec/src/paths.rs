//! Files silod publishes for its controller. The layout is fixed under the user's
//! `~/.silo`; neither side honors `SILO_HOME` for daemon state.
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathsError {
    #[error("HOME is required")]
    HomeUnset,
    #[error("HOME must be absolute: {0}")]
    HomeRelative(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    home: PathBuf,
}

impl DaemonPaths {
    /// The layout for the user in `HOME`.
    pub fn from_env() -> Result<Self, PathsError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(PathsError::HomeUnset)?;
        if !home.is_absolute() {
            return Err(PathsError::HomeRelative(home));
        }
        Ok(Self::for_user_home(&home))
    }

    pub fn for_user_home(user_home: &Path) -> Self {
        Self::new(user_home.join(".silo"))
    }

    /// The layout rooted at an explicit Silo home.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// silod-private state (installation record, data disk, backups) lives here.
    pub fn daemon_data(&self) -> PathBuf {
        self.home.join("daemon")
    }

    /// Live status, written atomically by silod. See [`crate::status`].
    pub fn status(&self) -> PathBuf {
        self.daemon_data().join("status.json")
    }

    /// Held exclusively by the silod process that owns the installation. It is
    /// released only when that process exits.
    pub fn lifetime_lock(&self) -> PathBuf {
        self.daemon_data().join("daemon.lock")
    }

    /// Serializes controller operations (service registration, start, stop).
    pub fn operation_lock(&self) -> PathBuf {
        self.daemon_data().join("operation.lock")
    }

    pub fn log_dir(&self) -> PathBuf {
        self.home.join("logs/daemon")
    }

    /// silod's own log.
    pub fn log(&self) -> PathBuf {
        self.log_dir().join("daemon.log")
    }

    /// Raw stdout/stderr of the service process, where the service manager has no
    /// journal (launchd).
    pub fn native_log(&self) -> PathBuf {
        self.log_dir().join("native.log")
    }

    /// The host Docker endpoint silod serves.
    pub fn docker_socket(&self) -> PathBuf {
        self.home.join("run/docker.sock")
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::paths::DaemonPaths;

    #[test]
    fn layout_is_fixed_under_the_user_home() {
        let paths = DaemonPaths::for_user_home(Path::new("/Users/me"));
        assert_eq!(paths.home(), Path::new("/Users/me/.silo"));
        assert_eq!(
            paths.status(),
            Path::new("/Users/me/.silo/daemon/status.json")
        );
        assert_eq!(
            paths.lifetime_lock(),
            Path::new("/Users/me/.silo/daemon/daemon.lock")
        );
        assert_eq!(
            paths.log(),
            Path::new("/Users/me/.silo/logs/daemon/daemon.log")
        );
        assert_eq!(
            paths.native_log(),
            Path::new("/Users/me/.silo/logs/daemon/native.log")
        );
        assert_eq!(
            paths.docker_socket(),
            Path::new("/Users/me/.silo/run/docker.sock")
        );
    }
}

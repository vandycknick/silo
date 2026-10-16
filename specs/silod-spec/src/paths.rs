//! Files silod publishes for its controller, rooted in the manager-selected Silo
//! Home. Resolve Home with libvm's HostPaths before constructing this layout.
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    home: PathBuf,
}

impl DaemonPaths {
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

    /// The installation record; the daemon is its only reader and writer.
    pub fn record(&self) -> PathBuf {
        self.daemon_data().join("daemon.json")
    }

    pub fn data_image(&self) -> PathBuf {
        self.daemon_data().join("system/data.img")
    }

    pub fn backups(&self) -> PathBuf {
        self.daemon_data().join("backups")
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

/// The daemon's private control directory under the per-user run root.
pub fn control_dir(run_root: &Path) -> PathBuf {
    run_root.join("silod")
}

/// The Unix socket serving the daemon's control API.
pub fn control_socket(run_root: &Path) -> PathBuf {
    control_dir(run_root).join("control.sock")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::paths::{control_dir, control_socket, DaemonPaths};

    #[test]
    fn layout_uses_the_selected_silo_home_without_appending_a_default() {
        let paths = DaemonPaths::new("/Users/me/.silo");
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
        assert_eq!(
            paths.record(),
            Path::new("/Users/me/.silo/daemon/daemon.json")
        );
        assert_eq!(
            paths.data_image(),
            Path::new("/Users/me/.silo/daemon/system/data.img")
        );
        assert_eq!(paths.backups(), Path::new("/Users/me/.silo/daemon/backups"));
        let custom = DaemonPaths::new("/srv/custom-silo");
        assert_eq!(
            custom.status(),
            Path::new("/srv/custom-silo/daemon/status.json")
        );
    }

    #[test]
    fn control_socket_lives_in_the_private_run_directory() {
        let run_root = Path::new("/run/user/1000/silo");
        assert_eq!(control_dir(run_root), run_root.join("silod"));
        assert_eq!(
            control_socket(run_root),
            Path::new("/run/user/1000/silo/silod/control.sock")
        );
    }
}

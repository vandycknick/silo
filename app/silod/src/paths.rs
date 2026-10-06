use std::path::{Path, PathBuf};

use silod_spec::paths::DaemonPaths;

/// The published layout plus silod-private files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemPaths {
    published: DaemonPaths,
    run_root: PathBuf,
}

impl SystemPaths {
    pub(crate) fn from_host(host: &libvm::HostPaths) -> Self {
        Self {
            published: DaemonPaths::new(host.home()),
            run_root: libvm::HostPaths::run_root(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(home: PathBuf, run_root: PathBuf) -> Self {
        Self {
            published: DaemonPaths::new(home),
            run_root,
        }
    }

    pub(crate) fn home(&self) -> &Path {
        self.published.home()
    }
    pub(crate) fn run_root(&self) -> &Path {
        &self.run_root
    }
    pub(crate) fn daemon_data(&self) -> PathBuf {
        self.published.daemon_data()
    }
    /// The installation record. silod is its only reader and writer.
    pub(crate) fn record(&self) -> PathBuf {
        self.daemon_data().join("daemon.json")
    }
    pub(crate) fn data_image(&self) -> PathBuf {
        self.daemon_data().join("system/data.img")
    }
    pub(crate) fn backups(&self) -> PathBuf {
        self.daemon_data().join("backups")
    }
    pub(crate) fn lifetime_lock(&self) -> PathBuf {
        self.published.lifetime_lock()
    }
    pub(crate) fn status(&self) -> PathBuf {
        self.published.status()
    }
    pub(crate) fn log(&self) -> PathBuf {
        self.published.log()
    }
    pub(crate) fn docker_socket(&self) -> PathBuf {
        self.published.docker_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::SystemPaths;

    #[test]
    fn selected_host_home_is_shared_with_the_published_layout() {
        let host = libvm::HostPaths::new("/srv/silo-home", "/srv/config/silo");
        let paths = SystemPaths::from_host(&host);
        assert_eq!(paths.home(), host.home());
        assert_eq!(paths.record(), host.home().join("daemon/daemon.json"));
        assert_eq!(paths.log(), host.home().join("logs/daemon/daemon.log"));
        assert_eq!(paths.run_root(), libvm::HostPaths::run_root());
    }
}

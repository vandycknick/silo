use std::fs;
use std::path::{Path, PathBuf};

#[must_use = "hold this guard for the process lifetime to keep PID file cleanup active"]
pub struct PidGuard {
    path: PathBuf,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl PidGuard {
    pub async fn create(path: &Path) -> eyre::Result<Self> {
        let pid = std::process::id();
        crate::secure_file::write_private(path, format!("{pid}\n").as_bytes())?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

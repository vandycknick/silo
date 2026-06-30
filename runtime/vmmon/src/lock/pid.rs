use eyre::Context;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

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
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context(format!("create pid parent {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .await
            .context(format!("open {}", path.display()))?;

        file.write_all(format!("{pid}\n").as_bytes())
            .await
            .context("write pid")?;
        file.flush().await.context("flush pid")?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::Context;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExitStatus {
    run_id: String,
    pid: i32,
    exited_at: i64,
    outcome: ExitOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExitOutcome {
    Clean,
    Error,
}

impl ExitStatus {
    pub(crate) fn new(
        run_id: String,
        outcome: ExitOutcome,
        error: Option<String>,
    ) -> eyre::Result<Self> {
        let pid = i32::try_from(std::process::id()).context("convert vmmon pid")?;
        Ok(Self {
            run_id,
            pid,
            exited_at: current_unix(),
            outcome,
            error,
        })
    }
}

pub(crate) async fn write(path: &Path, status: &ExitStatus) -> eyre::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context(format!("create exit status parent {}", parent.display()))?;
    }

    let payload = serde_json::to_vec_pretty(status).context("serialize exit status")?;
    let tmp_path = path.with_extension("json.tmp");
    tokio::fs::write(&tmp_path, payload)
        .await
        .context(format!("write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, path).await.context(format!(
        "rename {} to {}",
        tmp_path.display(),
        path.display()
    ))?;
    Ok(())
}

fn current_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub mod collect;
pub mod diff;

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("coverage I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid coverage report at {path}:{line}: {reason}")]
    Parse {
        path: PathBuf,
        line: usize,
        reason: String,
    },
    #[error(transparent)]
    Command(#[from] crate::command::CommandError),
    #[error("Go coverage report at {path} is not UTF-8: {source}")]
    Utf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("failed to serialize coverage summary: {0}")]
    Json(#[from] serde_json::Error),
    #[error("coverage baseline and current paths must be directories (invalid path: {path})")]
    InvalidDirectory { path: PathBuf },
    #[error("coverage regression: {failures} FAIL rows")]
    Regressions { failures: usize },
}

impl CoverageError {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }

    fn parse(line: usize, reason: impl Into<String>) -> Self {
        Self::Parse {
            path: PathBuf::from("<input>"),
            line,
            reason: reason.into(),
        }
    }

    pub(crate) fn with_path(self, path: &Path) -> Self {
        match self {
            Self::Parse { line, reason, .. } => Self::Parse {
                path: path.to_owned(),
                line,
                reason,
            },
            error => error,
        }
    }
}

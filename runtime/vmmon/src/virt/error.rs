use thiserror::Error;

/// Errors surfaced by the virtualization layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VirtError {
    #[error("machine {name} is already running")]
    AlreadyRunning { name: String },

    #[error("machine {name} is not running")]
    NotRunning { name: String },

    #[error("machine backend {kind} is unsupported on this host: {reason}")]
    UnsupportedBackend { kind: &'static str, reason: String },

    #[error("machine {name} is invalid: {reason}")]
    InvalidConfig { name: String, reason: String },

    #[error("backend error: {0}")]
    Backend(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

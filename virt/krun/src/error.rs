use thiserror::Error;

pub type Result<T> = std::result::Result<T, KrunBackendError>;

#[derive(Debug, Error)]
pub enum KrunBackendError {
    #[error("invalid krun config: {0}")]
    InvalidConfig(String),

    #[error("krun serial stream was already taken")]
    SerialAlreadyTaken,

    #[error("krun serial stream is not configured; enable stdio_console first")]
    SerialNotConfigured,

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

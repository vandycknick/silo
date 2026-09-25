use thiserror::Error;

pub type Result<T> = std::result::Result<T, KrunBackendError>;

#[derive(Debug, Error)]
pub enum KrunBackendError {
    #[error("invalid krun config: {0}")]
    InvalidConfig(String),
}

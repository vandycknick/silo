use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VzError {
    #[error("unsupported host platform: {reason}")]
    UnsupportedHost { reason: String },

    #[error("invalid virtual machine configuration: {reason}")]
    InvalidConfiguration { reason: String },

    #[error("invalid virtual machine state, expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("operation timed out: {0}")]
    Timeout(String),

    #[error("operation is not implemented yet: {0}")]
    Unimplemented(&'static str),

    #[error("{0}")]
    Backend(String),

    #[error(transparent)]
    Io(#[from] io::Error),
}

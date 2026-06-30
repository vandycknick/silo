use std::ffi::NulError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, KrunError>;

#[derive(Debug, Error)]
pub enum KrunError {
    #[error("libkrun {op} failed with errno {code}")]
    Krun { op: &'static str, code: i32 },

    #[error("string argument contains an interior nul byte")]
    InteriorNul(#[from] NulError),

    #[error("{0}")]
    InvalidArgument(String),
}

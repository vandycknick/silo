//! Bounded OCI VM artifact syntax and codecs. These types prove transport
//! integrity only, never semantic identity, publisher authentication or admission.

pub mod codec;
pub mod graph;
pub mod wire;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid VM artifact: {0}")]
    Invalid(String),
    #[error("incompatible VM artifact storage profile {profile}; exact artifacts require an admitted current root profile")]
    IncompatibleStorageProfile { profile: String },
    #[error("VM artifact JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("VM artifact I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("VM artifact metadata required: {0:?}")]
    MissingMetadata(Box<graph::Descriptor>),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

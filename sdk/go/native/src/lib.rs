//! Versioned C ABI bridge between the public Go SDK and `libvm`.

mod abi;
mod buffer;
mod dto;
mod error;
mod exec;
mod handles;
mod images;
mod logs;
mod machine;
mod network;
mod runtime;

pub use crate::abi::{silo_ffi_abi_version, silo_ffi_sdk_version};
pub use crate::buffer::{silo_buffer_free, SiloBuffer};
pub use crate::error::{silo_error_free, SiloError};

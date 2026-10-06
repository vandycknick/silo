//! Native adapters for the typed, same-user daemon management contract.
//! This crate owns no runtime, transport connection, or session implementation.
pub mod create;
pub mod errors;
pub mod images;
pub mod lifecycle;
pub mod network;
pub mod policy;
pub mod readiness;
pub mod reports;
pub mod requests;
pub mod snapshots;
pub mod spec;
pub mod updates;
pub mod values;

#[cfg(test)]
mod tests;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid management field {field}: {reason}")]
pub struct ConversionError {
    pub field: &'static str,
    pub reason: &'static str,
}
pub(crate) fn invalid(field: &'static str, reason: &'static str) -> ConversionError {
    ConversionError { field, reason }
}
pub(crate) fn required<T>(value: Option<T>, field: &'static str) -> Result<T, ConversionError> {
    value.ok_or_else(|| invalid(field, "required value is absent"))
}
pub fn path_to_wire(value: &Path) -> Vec<u8> {
    value.as_os_str().as_bytes().to_vec()
}
pub fn path_from_wire(value: Vec<u8>) -> Result<PathBuf, ConversionError> {
    if value.contains(&0) {
        return Err(invalid("path", "contains NUL"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(value)))
}
pub fn validate_uuid(value: &str, field: &'static str) -> Result<(), ConversionError> {
    uuid::Uuid::parse_str(value).map_err(|_| invalid(field, "invalid UUID"))?;
    Ok(())
}
pub fn duration_from_wire(
    value: prost_types::Duration,
) -> Result<std::time::Duration, ConversionError> {
    if !(0..=315_576_000_000).contains(&value.seconds) || !(0..1_000_000_000).contains(&value.nanos)
    {
        return Err(invalid("duration", "invalid nonnegative duration"));
    }
    Ok(std::time::Duration::new(
        value.seconds as u64,
        value.nanos as u32,
    ))
}
pub fn duration_to_wire(
    value: std::time::Duration,
) -> Result<prost_types::Duration, ConversionError> {
    if value.as_secs() > 315_576_000_000 {
        return Err(invalid("duration", "overflow"));
    }
    Ok(prost_types::Duration {
        seconds: value
            .as_secs()
            .try_into()
            .map_err(|_| invalid("duration", "overflow"))?,
        nanos: value.subsec_nanos() as i32,
    })
}

use crate::LibVmError;

pub(super) fn serialize<T>(field: &'static str, value: &T) -> Result<String, LibVmError>
where
    T: serde::Serialize,
{
    serde_json::to_string(value).map_err(|err| LibVmError::InvalidCreateRequest {
        name: field.to_string(),
        reason: format!("serialize {field}: {err}"),
    })
}

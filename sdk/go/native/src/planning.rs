use serde::{Deserialize, Serialize};

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, error_from_libvm, invalid_argument, SiloError};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum PlanningRequest {
    Memory { input: String },
    Disk { input: String },
    Name {},
}

#[derive(Serialize)]
#[serde(untagged)]
enum PlanningResponse {
    Size { bytes: u64 },
    Name { name: String },
}

/// Runs stateless planning. No runtime handle or home directory is required.
/// Requests are strict objects: memory/disk require input; name accepts no input.
///
/// # Safety
/// Request bytes must be readable for request_len; out_data must be writable.
#[no_mangle]
pub unsafe extern "C" fn silo_planning_query(
    request_ptr: *const u8,
    request_len: usize,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        if out_data.is_null() {
            return Err(invalid_argument("out_data must not be null"));
        }
        *out_data = SiloBuffer::empty();
        let request: PlanningRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|_| invalid_argument("invalid planning query: use memory or disk with one string input, or name without input"))?;
        let response = match request {
            PlanningRequest::Memory { input } => PlanningResponse::Size {
                bytes: libvm::planning::parse_machine_memory(&input).map_err(invalid_argument)?,
            },
            PlanningRequest::Disk { input } => PlanningResponse::Size {
                bytes: libvm::planning::parse_root_disk_size(&input).map_err(invalid_argument)?,
            },
            PlanningRequest::Name {} => PlanningResponse::Name {
                name: libvm::planning::propose_machine_name().map_err(error_from_libvm)?,
            },
        };
        *out_data = SiloBuffer::from_vec(
            serde_json::to_vec(&response)
                .map_err(|_| SiloError::new("Serialization", "encode planning response failed"))?,
        );
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::buffer::SiloBuffer;
    use crate::planning::silo_planning_query;
    use crate::silo_error_free;
    use std::ffi::CStr;

    #[test]
    fn strict_query_rejects_invalid_objects_without_echoing_input() {
        for request in [
            r#"[]"#,
            r#"null"#,
            r#"{}"#,
            r#"{"operation":"secret-value"}"#,
            r#"{"operation":"memory"}"#,
            r#"{"operation":"disk","input":0}"#,
            r#"{"operation":"name","input":"secret-value"}"#,
            r#"{"operation":"name","secret-value":true}"#,
            r#"{"operation":"memory","input":"secret-value"}"#,
            r#"{"operation":"disk","input":"0gb"}"#,
            r#"{"operation":"memory","input":"8gb","input":"9gb"}"#,
            r#"{"operation":"name","operation":"name"}"#,
            r#"{"operation":"memory","input":null}"#,
            r#"{"operation":"disk","input":"8gb"} trailing"#,
        ] {
            let mut output = SiloBuffer::empty();
            let error =
                unsafe { silo_planning_query(request.as_ptr(), request.len(), &mut output) };
            assert!(!error.is_null(), "{request}");
            assert!(output.ptr.is_null());
            let message = unsafe { CStr::from_ptr((*error).message) }
                .to_str()
                .unwrap();
            assert!(!message.contains("secret-value"));
            assert_eq!(
                unsafe { CStr::from_ptr((*error).variant) }
                    .to_str()
                    .unwrap(),
                "InvalidArgument"
            );
            unsafe { silo_error_free(error) };
        }
    }

    #[test]
    fn query_returns_exact_bytes_and_validates_pointers() {
        for (request, bytes) in [
            (r#"{"operation":"memory","input":"8GB"}"#, 8_u64 << 30),
            (r#"{"operation":"disk","input":"512mb"}"#, 512_u64 << 20),
        ] {
            let mut output = SiloBuffer::empty();
            let error =
                unsafe { silo_planning_query(request.as_ptr(), request.len(), &mut output) };
            assert!(error.is_null());
            let response: serde_json::Value = serde_json::from_slice(unsafe {
                std::slice::from_raw_parts(output.ptr, output.len)
            })
            .unwrap();
            assert_eq!(response["bytes"].as_u64(), Some(bytes));
            unsafe { crate::silo_buffer_free(output) };
        }
        let mut output = SiloBuffer::empty();
        let error = unsafe { silo_planning_query(std::ptr::null(), 1, &mut output) };
        assert!(!error.is_null());
        assert!(output.ptr.is_null());
        unsafe { silo_error_free(error) };
        let error = unsafe { silo_planning_query(std::ptr::null(), 0, std::ptr::null_mut()) };
        assert!(!error.is_null());
        unsafe { silo_error_free(error) };
    }
}

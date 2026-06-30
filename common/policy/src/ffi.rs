use crate::{HttpConditionContext, Policy};
use serde::Serialize;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

// The C ABI exposes opaque pointers only. The real Rust values live in the
// private handle structs below, and we cast between the two at the boundary.
// cbindgen sees these marker types, but does not emit their fields, so Go
// cannot accidentally rely on Rust's private Policy or HttpConditionContext
// layout.
/// cbindgen:no-export
#[repr(C)]
pub struct bento_policy_t {
    _private: [u8; 0],
}

/// cbindgen:no-export
#[repr(C)]
pub struct bento_policy_http_context_t {
    _private: [u8; 0],
}

struct PolicyHandle {
    policy: Policy,
}

struct HttpContextHandle {
    context: HttpConditionContext,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct bento_policy_bytes_t {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct bento_policy_buffer_t {
    pub ptr: *mut u8,
    pub len: usize,
}

impl Default for bento_policy_buffer_t {
    fn default() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

#[allow(non_camel_case_types)]
pub type bento_policy_status_t = u32;

pub const BENTO_POLICY_OK: bento_policy_status_t = 0;
pub const BENTO_POLICY_LOAD_ERROR: bento_policy_status_t = 1;
pub const BENTO_POLICY_INVALID_ARGUMENT: bento_policy_status_t = 2;
pub const BENTO_POLICY_EVAL_ERROR: bento_policy_status_t = 3;
pub const BENTO_POLICY_PANIC: bento_policy_status_t = 255;

#[no_mangle]
/// Parse a policy source into a Rust-owned policy handle.
///
/// # Safety
/// `filename` and `source` must either be null with length zero or point to readable memory for
/// their lengths for the duration of the call. `out_policy` must be non-null and writable.
/// `out_error_json`, when non-null, must be writable. Returned handles and buffers must be freed
/// with the matching `bento_policy_*_free` functions.
pub unsafe extern "C" fn bento_policy_parse_source(
    filename: bento_policy_bytes_t,
    source: bento_policy_bytes_t,
    out_policy: *mut *mut bento_policy_t,
    out_error_json: *mut bento_policy_buffer_t,
) -> bento_policy_status_t {
    catch_status(out_error_json, || {
        if out_policy.is_null() {
            write_error(out_error_json, "out_policy is null");
            return BENTO_POLICY_INVALID_ARGUMENT;
        }
        *out_policy = ptr::null_mut();
        let filename = match bytes_to_str(filename) {
            Ok(value) => value,
            Err(err) => {
                write_error(out_error_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        let source = match bytes_to_str(source) {
            Ok(value) => value,
            Err(err) => {
                write_error(out_error_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        match Policy::parse_str(filename.to_owned(), source) {
            Ok(policy) => {
                let handle = Box::new(PolicyHandle { policy });
                *out_policy = Box::into_raw(handle) as *mut bento_policy_t;
                BENTO_POLICY_OK
            }
            Err(err) => {
                write_json(out_error_json, &err);
                BENTO_POLICY_LOAD_ERROR
            }
        }
    })
}

#[no_mangle]
/// Serialize a policy snapshot as JSON.
///
/// The JSON snapshot is a load-time transfer format, not the runtime state.
/// It contains the document model Go needs to rebuild its own evaluator
/// indexes, while compiled CEL programs and other private indexes remain in
/// this Rust policy handle and are addressed from Go by condition id.
///
/// # Safety
/// `policy` must be a valid handle returned by `bento_policy_parse_source`. `out_json` must be
/// non-null and writable. The returned buffer must be freed with `bento_policy_buffer_free`.
pub unsafe extern "C" fn bento_policy_snapshot_json(
    policy: *const bento_policy_t,
    out_json: *mut bento_policy_buffer_t,
) -> bento_policy_status_t {
    catch_status(out_json, || {
        let policy = match policy_handle(policy) {
            Ok(policy) => policy,
            Err(err) => {
                write_error(out_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        write_json(out_json, &policy.policy);
        BENTO_POLICY_OK
    })
}

#[no_mangle]
/// Build an HTTP condition evaluation context from JSON.
///
/// This is the request-time half of the bridge. Go still owns endpoint/rule
/// decision making, but it serializes the normalized request facets once into a
/// short-lived Rust context so multiple condition ids can be evaluated without
/// reparsing query/header data for each rule.
///
/// # Safety
/// `input_json` must either be null with length zero or point to readable memory for its length
/// for the duration of the call. `out_context` must be non-null and writable. `out_error_json`,
/// when non-null, must be writable. The returned context must be freed with
/// `bento_policy_http_context_free`.
pub unsafe extern "C" fn bento_policy_http_context_from_json(
    input_json: bento_policy_bytes_t,
    out_context: *mut *mut bento_policy_http_context_t,
    out_error_json: *mut bento_policy_buffer_t,
) -> bento_policy_status_t {
    catch_status(out_error_json, || {
        if out_context.is_null() {
            write_error(out_error_json, "out_context is null");
            return BENTO_POLICY_INVALID_ARGUMENT;
        }
        *out_context = ptr::null_mut();
        let bytes = match bytes_to_slice(input_json) {
            Ok(value) => value,
            Err(err) => {
                write_error(out_error_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        match serde_json::from_slice::<HttpConditionContext>(bytes) {
            Ok(context) => {
                let handle = Box::new(HttpContextHandle { context });
                *out_context = Box::into_raw(handle) as *mut bento_policy_http_context_t;
                BENTO_POLICY_OK
            }
            Err(err) => {
                write_error(
                    out_error_json,
                    format!("decode HTTP condition context: {err}"),
                );
                BENTO_POLICY_INVALID_ARGUMENT
            }
        }
    })
}

#[no_mangle]
/// Evaluate one compiled HTTP condition from a policy against a context.
///
/// # Safety
/// `policy` and `context` must be valid handles returned by this library. `out_matches` must be
/// non-null and writable. `out_error_json`, when non-null, must be writable.
pub unsafe extern "C" fn bento_policy_http_condition_evaluate(
    policy: *const bento_policy_t,
    condition_id: u32,
    context: *const bento_policy_http_context_t,
    out_matches: *mut bool,
    out_error_json: *mut bento_policy_buffer_t,
) -> bento_policy_status_t {
    catch_status(out_error_json, || {
        if out_matches.is_null() {
            write_error(out_error_json, "out_matches is null");
            return BENTO_POLICY_INVALID_ARGUMENT;
        }
        *out_matches = false;
        let policy = match policy_handle(policy) {
            Ok(policy) => policy,
            Err(err) => {
                write_error(out_error_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        let context = match context_handle(context) {
            Ok(context) => context,
            Err(err) => {
                write_error(out_error_json, err);
                return BENTO_POLICY_INVALID_ARGUMENT;
            }
        };
        match policy
            .policy
            .evaluate_http_condition(condition_id, &context.context)
        {
            Ok(matches) => {
                *out_matches = matches;
                BENTO_POLICY_OK
            }
            Err(err) => {
                write_error(out_error_json, err.to_string());
                BENTO_POLICY_EVAL_ERROR
            }
        }
    })
}

#[no_mangle]
/// Free a policy handle returned by `bento_policy_parse_source`.
///
/// # Safety
/// `policy` must be null or a handle returned by `bento_policy_parse_source` that has not already
/// been freed.
pub unsafe extern "C" fn bento_policy_free(policy: *mut bento_policy_t) {
    if !policy.is_null() {
        drop(Box::from_raw(policy as *mut PolicyHandle));
    }
}

#[no_mangle]
/// Free an HTTP condition context returned by `bento_policy_http_context_from_json`.
///
/// # Safety
/// `context` must be null or a handle returned by `bento_policy_http_context_from_json` that has
/// not already been freed.
pub unsafe extern "C" fn bento_policy_http_context_free(context: *mut bento_policy_http_context_t) {
    if !context.is_null() {
        drop(Box::from_raw(context as *mut HttpContextHandle));
    }
}

#[no_mangle]
/// Free a buffer returned by this library.
///
/// # Safety
/// `buffer` must be empty or a buffer returned by this library that has not already been freed.
pub unsafe extern "C" fn bento_policy_buffer_free(buffer: bento_policy_buffer_t) {
    if !buffer.ptr.is_null() && buffer.len > 0 {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len));
    }
}

fn catch_status(
    out_error_json: *mut bento_policy_buffer_t,
    run: impl FnOnce() -> bento_policy_status_t,
) -> bento_policy_status_t {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(status) => status,
        Err(_) => {
            unsafe {
                write_error(out_error_json, "bento policy FFI panic");
            }
            BENTO_POLICY_PANIC
        }
    }
}

unsafe fn policy_handle<'a>(policy: *const bento_policy_t) -> Result<&'a PolicyHandle, String> {
    (policy as *const PolicyHandle)
        .as_ref()
        .ok_or_else(|| "policy is null".to_owned())
}

unsafe fn context_handle<'a>(
    context: *const bento_policy_http_context_t,
) -> Result<&'a HttpContextHandle, String> {
    (context as *const HttpContextHandle)
        .as_ref()
        .ok_or_else(|| "context is null".to_owned())
}

unsafe fn bytes_to_str<'a>(bytes: bento_policy_bytes_t) -> Result<&'a str, String> {
    let slice = bytes_to_slice(bytes)?;
    std::str::from_utf8(slice).map_err(|err| format!("input is not UTF-8: {err}"))
}

unsafe fn bytes_to_slice<'a>(bytes: bento_policy_bytes_t) -> Result<&'a [u8], String> {
    if bytes.len == 0 {
        return Ok(&[]);
    }
    if bytes.ptr.is_null() {
        return Err("input pointer is null".to_owned());
    }
    Ok(std::slice::from_raw_parts(bytes.ptr, bytes.len))
}

unsafe fn write_json<T: Serialize>(out: *mut bento_policy_buffer_t, value: &T) {
    match serde_json::to_vec(value) {
        Ok(bytes) => write_buffer(out, bytes),
        Err(err) => write_error(out, format!("encode JSON: {err}")),
    }
}

#[derive(Serialize)]
struct ErrorMessage<'a> {
    message: &'a str,
}

unsafe fn write_error(out: *mut bento_policy_buffer_t, message: impl AsRef<str>) {
    let message = message.as_ref();
    let bytes = serde_json::to_vec(&ErrorMessage { message })
        .unwrap_or_else(|_| b"{\"message\":\"unknown policy FFI error\"}".to_vec());
    write_buffer(out, bytes);
}

unsafe fn write_buffer(out: *mut bento_policy_buffer_t, mut bytes: Vec<u8>) {
    if out.is_null() {
        return;
    }
    if bytes.is_empty() {
        *out = bento_policy_buffer_t::default();
        return;
    }
    let buffer = bento_policy_buffer_t {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    // Transfer ownership to the caller. Go immediately copies the buffer and
    // returns it to Rust with bento_policy_buffer_free.
    std::mem::forget(bytes);
    *out = buffer;
}

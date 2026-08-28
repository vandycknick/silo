use std::ffi::{c_char, CString};
use std::ptr;

use libvm::LibVmError;

#[repr(C)]
pub struct SiloError {
    pub variant: *mut c_char,
    pub message: *mut c_char,
}

impl SiloError {
    pub(crate) fn new(variant: &str, message: impl Into<String>) -> *mut Self {
        let variant = c_string(variant);
        let message = c_string(&message.into());
        Box::into_raw(Box::new(Self {
            variant: variant.into_raw(),
            message: message.into_raw(),
        }))
    }
}

pub(crate) fn invalid_argument(message: impl Into<String>) -> *mut SiloError {
    SiloError::new("InvalidArgument", message)
}

pub(crate) fn error_from_libvm(error: LibVmError) -> *mut SiloError {
    SiloError::new(error.variant(), error.to_string())
}

fn c_string(value: &str) -> CString {
    let sanitized = value.replace('\0', "\\0");
    CString::new(sanitized).unwrap_or_default()
}

pub(crate) fn catch_ffi(f: impl FnOnce() -> Result<(), *mut SiloError>) -> *mut SiloError {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => ptr::null_mut(),
        Ok(Err(error)) => error,
        Err(_) => SiloError::new("InternalPanic", "the native Silo bridge panicked"),
    }
}

pub(crate) fn catch_ffi_void(f: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
}

/// Frees an error returned by this bridge.
///
/// # Safety
/// `error` must be null or an unmodified pointer returned by this exact bridge and freed once.
#[no_mangle]
pub unsafe extern "C" fn silo_error_free(error: *mut SiloError) {
    catch_ffi_void(|| {
        if error.is_null() {
            return;
        }
        let error = Box::from_raw(error);
        if !error.variant.is_null() {
            drop(CString::from_raw(error.variant));
        }
        if !error.message.is_null() {
            drop(CString::from_raw(error.message));
        }
    });
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::error::{catch_ffi, SiloError};
    use crate::silo_error_free;

    #[test]
    fn owns_and_frees_error_strings() {
        let error = SiloError::new("Example", "message");
        let value = unsafe { &*error };
        assert_eq!(
            unsafe { CStr::from_ptr(value.variant) }.to_bytes(),
            b"Example"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(value.message) }.to_bytes(),
            b"message"
        );
        unsafe { silo_error_free(error) };
    }

    #[test]
    fn catches_panics() {
        let error = catch_ffi(|| panic!("boom"));
        assert!(!error.is_null());
        unsafe { silo_error_free(error) };
    }
}

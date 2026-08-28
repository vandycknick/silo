use std::ptr;

use crate::error::catch_ffi_void;

#[repr(C)]
pub struct SiloBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl SiloBuffer {
    pub(crate) fn from_vec(value: Vec<u8>) -> Self {
        let mut value = value.into_boxed_slice();
        let buffer = Self {
            ptr: value.as_mut_ptr(),
            len: value.len(),
        };
        std::mem::forget(value);
        buffer
    }

    pub(crate) fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

/// Frees a buffer returned by this bridge.
///
/// # Safety
/// `buffer` must be an unmodified value returned by this exact bridge and must be freed once.
#[no_mangle]
pub unsafe extern "C" fn silo_buffer_free(buffer: SiloBuffer) {
    catch_ffi_void(|| {
        if !buffer.ptr.is_null() {
            let slice = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
            drop(Box::from_raw(slice));
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::{silo_buffer_free, SiloBuffer};

    #[test]
    fn owns_and_frees_bytes() {
        let buffer = SiloBuffer::from_vec(vec![1, 2, 3]);
        assert_eq!(buffer.len, 3);
        unsafe { silo_buffer_free(buffer) };
    }

    #[test]
    fn frees_empty_buffer() {
        unsafe { silo_buffer_free(SiloBuffer::empty()) };
    }
}

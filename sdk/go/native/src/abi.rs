use std::ffi::c_char;

const ABI_VERSION: u32 = 1;
const SDK_VERSION: &[u8] = b"0.1.0\0";

#[no_mangle]
pub extern "C" fn silo_ffi_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn silo_ffi_sdk_version() -> *const c_char {
    SDK_VERSION.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::{silo_ffi_abi_version, silo_ffi_sdk_version};

    #[test]
    fn reports_bridge_versions() {
        assert_eq!(silo_ffi_abi_version(), 1);
        let version = unsafe { CStr::from_ptr(silo_ffi_sdk_version()) };
        assert_eq!(version.to_bytes(), b"0.1.0");
    }
}

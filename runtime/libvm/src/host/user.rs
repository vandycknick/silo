use std::ffi::CStr;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUser {
    pub name: String,
    pub uid: u32,
    pub gecos: String,
}

pub fn current_host_user() -> io::Result<HostUser> {
    let uid = unsafe { libc::geteuid() };

    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result_ptr: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];

    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result_ptr,
        )
    };

    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }

    if result_ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "unable to resolve current user with getpwuid_r",
        ));
    }

    let pwd = unsafe { pwd.assume_init() };
    let name = c_string_field(pwd.pw_name, "pw_name")?;
    let gecos_raw = c_string_field(pwd.pw_gecos, "pw_gecos")?;
    let gecos = gecos_raw
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name.as_str())
        .to_string();

    Ok(HostUser { name, uid, gecos })
}

fn c_string_field(ptr: *const libc::c_char, field_name: &str) -> io::Result<String> {
    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing {field_name} in passwd entry"),
        ));
    }

    let value = unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid UTF-8 in {field_name}: {err}"),
        )
    })?;

    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("empty {field_name} in passwd entry"),
        ));
    }

    Ok(value.to_owned())
}

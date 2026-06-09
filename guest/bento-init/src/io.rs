#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub const PATH_MAX: usize = 4096;
pub const STDIN: i32 = 0;
pub const STDOUT: i32 = 1;
pub const STDERR: i32 = 2;

pub fn write_buf(fd: i32, buf: &[u8]) -> isize {
    let mut written = 0;
    while written < buf.len() {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr().cast::<libc::c_void>(),
                buf.len() - written,
            )
        };
        if ret < 0 {
            return ret;
        }
        written += ret as usize;
    }
    written as isize
}

pub fn write(fd: i32, text: &str) -> isize {
    write_buf(fd, text.as_bytes())
}

pub fn read(fd: i32, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) }
}

#[cfg(feature = "alloc")]
pub fn read_all(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let len = read(fd, &mut buf);
        if len <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..len as usize]);
    }
    out
}

pub fn open(path: &[u8], flags: i32, mode: u32) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe {
        libc::open(
            path_buf.as_ptr().cast::<libc::c_char>(),
            flags,
            mode as libc::mode_t,
        )
    }
}

pub fn close(fd: i32) -> i32 {
    unsafe { libc::close(fd) }
}

pub fn mkdir(path: &[u8], mode: u32) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe {
        libc::mkdir(
            path_buf.as_ptr().cast::<libc::c_char>(),
            mode as libc::mode_t,
        )
    }
}

pub fn unlink(path: &[u8]) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::unlink(path_buf.as_ptr().cast::<libc::c_char>()) }
}

pub fn symlink(target: &[u8], link_path: &[u8]) -> i32 {
    let mut target_buf = [0u8; PATH_MAX];
    let mut link_buf = [0u8; PATH_MAX];
    if !path_to_cstr(target, &mut target_buf) || !path_to_cstr(link_path, &mut link_buf) {
        return -1;
    }
    unsafe {
        libc::symlink(
            target_buf.as_ptr().cast::<libc::c_char>(),
            link_buf.as_ptr().cast::<libc::c_char>(),
        )
    }
}

pub fn readlink(path: &[u8], out: &mut [u8]) -> isize {
    let mut path_buf = [0u8; PATH_MAX];
    if out.is_empty() || !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe {
        libc::readlink(
            path_buf.as_ptr().cast::<libc::c_char>(),
            out.as_mut_ptr().cast::<libc::c_char>(),
            out.len() - 1,
        )
    }
}

pub fn stat(path: &[u8], stat: &mut libc::stat) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::stat(path_buf.as_ptr().cast::<libc::c_char>(), stat) }
}

pub fn lstat(path: &[u8], stat: &mut libc::stat) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::lstat(path_buf.as_ptr().cast::<libc::c_char>(), stat) }
}

pub fn stat_zeroed() -> libc::stat {
    unsafe { core::mem::zeroed() }
}

pub fn access(path: &[u8], mode: i32) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::access(path_buf.as_ptr().cast::<libc::c_char>(), mode) }
}

pub fn chdir(path: &[u8]) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::chdir(path_buf.as_ptr().cast::<libc::c_char>()) }
}

pub fn chroot(path: &[u8]) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::chroot(path_buf.as_ptr().cast::<libc::c_char>()) }
}

pub fn getcwd(out: &mut [u8]) -> Option<&[u8]> {
    if out.is_empty() {
        return None;
    }
    let ptr = unsafe { libc::getcwd(out.as_mut_ptr().cast::<libc::c_char>(), out.len()) };
    if ptr.is_null() {
        return None;
    }
    let len = strlen(out.as_ptr());
    Some(&out[..len])
}

pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

pub fn fork() -> i32 {
    unsafe { libc::fork() }
}

pub fn waitpid(pid: i32, status: &mut i32, options: i32) -> i32 {
    unsafe { libc::waitpid(pid, status as *mut i32, options) }
}

pub fn isatty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn dup2(old_fd: i32, new_fd: i32) -> i32 {
    unsafe { libc::dup2(old_fd, new_fd) }
}

pub fn dup(fd: i32) -> i32 {
    unsafe { libc::dup(fd) }
}

pub fn setsid() -> i32 {
    unsafe { libc::setsid() }
}

pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

pub fn sleep(seconds: u32) {
    unsafe {
        libc::sleep(seconds);
    }
}

pub fn exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

pub fn strlen(ptr: *const u8) -> usize {
    let mut len = 0;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    len
}

pub fn path_to_cstr(path: &[u8], out: &mut [u8; PATH_MAX]) -> bool {
    if path.len() >= PATH_MAX {
        return false;
    }
    out[..path.len()].copy_from_slice(path);
    out[path.len()] = 0;
    true
}

pub fn bytes_to_cstr<const N: usize>(bytes: &[u8], out: &mut [u8; N]) -> bool {
    if bytes.len() >= N {
        return false;
    }
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = 0;
    true
}

pub fn getenv(name: &[u8]) -> Option<&'static [u8]> {
    let mut name_buf = [0u8; PATH_MAX];
    if !bytes_to_cstr(name, &mut name_buf) {
        return None;
    }
    let value = unsafe { libc::getenv(name_buf.as_ptr().cast::<libc::c_char>()) };
    if value.is_null() {
        return None;
    }
    let len = strlen(value.cast::<u8>());
    Some(unsafe { core::slice::from_raw_parts(value.cast::<u8>(), len) })
}

pub fn setenv(name: &[u8], value: &[u8], overwrite: bool) -> i32 {
    let mut name_buf = [0u8; PATH_MAX];
    let mut value_buf = [0u8; PATH_MAX];
    if !bytes_to_cstr(name, &mut name_buf) || !bytes_to_cstr(value, &mut value_buf) {
        return -1;
    }
    unsafe {
        libc::setenv(
            name_buf.as_ptr().cast::<libc::c_char>(),
            value_buf.as_ptr().cast::<libc::c_char>(),
            i32::from(overwrite),
        )
    }
}

pub fn unsetenv(name: &[u8]) -> i32 {
    let mut name_buf = [0u8; PATH_MAX];
    if !bytes_to_cstr(name, &mut name_buf) {
        return -1;
    }
    unsafe { libc::unsetenv(name_buf.as_ptr().cast::<libc::c_char>()) }
}

pub fn opendir(path: &[u8]) -> *mut libc::DIR {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return core::ptr::null_mut();
    }
    unsafe { libc::opendir(path_buf.as_ptr().cast::<libc::c_char>()) }
}

pub fn readdir(dir: *mut libc::DIR) -> *mut libc::dirent {
    unsafe { libc::readdir(dir) }
}

pub fn closedir(dir: *mut libc::DIR) -> i32 {
    unsafe { libc::closedir(dir) }
}

pub fn execv(path: &[u8], argv: &[*const libc::c_char]) -> i32 {
    let mut path_buf = [0u8; PATH_MAX];
    if !path_to_cstr(path, &mut path_buf) {
        return -1;
    }
    unsafe { libc::execv(path_buf.as_ptr().cast::<libc::c_char>(), argv.as_ptr()) }
}

pub fn execvp(file: &[u8], argv: &[*const libc::c_char]) -> i32 {
    let mut file_buf = [0u8; PATH_MAX];
    if !path_to_cstr(file, &mut file_buf) {
        return -1;
    }
    unsafe { libc::execvp(file_buf.as_ptr().cast::<libc::c_char>(), argv.as_ptr()) }
}

pub fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = input.split_first() {
        if first != b' ' && first != b'\t' && first != b'\r' && first != b'\n' {
            break;
        }
        input = rest;
    }

    while let Some((&last, rest)) = input.split_last() {
        if last != b' ' && last != b'\t' && last != b'\r' && last != b'\n' {
            break;
        }
        input = rest;
    }

    input
}

pub fn parse_octal(input: &[u8]) -> Option<u32> {
    if input.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for &byte in input {
        if !(b'0'..=b'7').contains(&byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add((byte - b'0') as u32)?;
    }
    Some(value)
}

pub fn status_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

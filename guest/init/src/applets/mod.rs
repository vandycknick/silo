use crate::io;

pub(crate) mod files;
mod network;
mod other;
mod process;
mod shell;
pub(crate) mod system;

pub type AppletFn = fn(i32, *const *const u8) -> i32;

const APPLETS: &[(&[u8], AppletFn)] = &[
    (b"ash", shell::ash),
    (b"cat", files::cat),
    (b"cttyhack", other::cttyhack),
    (b"dash", shell::dash),
    (b"echo", shell::echo),
    (b"false", shell::false_cmd),
    (b"ls", files::ls),
    (b"mkdir", files::mkdir),
    (b"mount", system::mount),
    (b"netstat", network::netstat),
    (b"ps", process::ps),
    (b"sh", shell::sh),
    (b"switch_root", other::switch_root),
    (b"true", shell::true_cmd),
    (b"umount", system::umount),
];

pub fn run_applet(name: &[u8], argc: i32, argv: *const *const u8) -> i32 {
    match find_applet(name) {
        Some(function) => function(argc, argv),
        None => {
            io::write(io::STDERR, "init: applet not found: ");
            io::write_buf(io::STDERR, name);
            io::write(io::STDERR, "\n");
            127
        }
    }
}

pub fn find_applet(name: &[u8]) -> Option<AppletFn> {
    for &(applet, function) in APPLETS {
        if applet == name {
            return Some(function);
        }
    }
    None
}

pub fn list_applets() {
    for &(name, _) in APPLETS {
        io::write_buf(io::STDOUT, name);
        io::write(io::STDOUT, "\n");
    }
}

pub fn install(dir: &[u8]) -> i32 {
    let (target, target_len) = executable_path();
    let mut failures = 0;

    for &(name, _) in APPLETS {
        let mut link_path = [0u8; io::PATH_MAX];
        let Some(len) = join_path(dir, name, &mut link_path) else {
            failures += 1;
            continue;
        };
        let path = &link_path[..len];
        io::unlink(path);
        if io::symlink(&target[..target_len], path) != 0 {
            io::write(io::STDERR, "init: failed to create applet symlink ");
            io::write_buf(io::STDERR, path);
            io::write(io::STDERR, "\n");
            failures += 1;
        }
    }

    if failures == 0 {
        0
    } else {
        1
    }
}

pub unsafe fn get_arg<'a>(argv: *const *const u8, index: i32) -> Option<&'a [u8]> {
    if argv.is_null() || index < 0 {
        return None;
    }
    let ptr = *argv.add(index as usize);
    if ptr.is_null() {
        return None;
    }
    let len = io::strlen(ptr);
    Some(core::slice::from_raw_parts(ptr, len))
}

fn executable_path() -> ([u8; io::PATH_MAX], usize) {
    let mut path = [0u8; io::PATH_MAX];
    let len = io::readlink(b"/proc/self/exe", &mut path);
    if len > 0 {
        return (path, len as usize);
    }

    path[..5].copy_from_slice(b"/init");
    path[5] = 0;
    (path, 5)
}

fn join_path(dir: &[u8], name: &[u8], out: &mut [u8; io::PATH_MAX]) -> Option<usize> {
    if dir.is_empty() || dir.len() + name.len() + 1 >= io::PATH_MAX {
        return None;
    }

    let mut len = 0;
    out[..dir.len()].copy_from_slice(dir);
    len += dir.len();
    if out[len - 1] != b'/' {
        out[len] = b'/';
        len += 1;
    }
    out[len..len + name.len()].copy_from_slice(name);
    len += name.len();
    out[len] = 0;
    Some(len)
}

pub fn cstr_arg<const N: usize>(arg: &[u8], out: &mut [u8; N]) -> bool {
    io::bytes_to_cstr(arg, out)
}

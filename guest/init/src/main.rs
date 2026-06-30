//! Bentobox initramfs init and rescue applets.
//!
//! This binary follows Armybox's multicall shape: the same executable is copied
//! into the initramfs as `/init`, then applets are invoked through symlinks whose
//! basename selects the implementation.

#![no_std]
#![no_main]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod applets;
mod init;
mod io;
mod sys;

use crate::applets::{get_arg, run_applet};

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    if argc < 1 || argv.is_null() {
        return 1;
    }

    let Some(program) = (unsafe { get_arg(argv, 0) }) else {
        return 1;
    };
    let applet = basename(program);

    if applet == b"init" {
        if is_init_control_invocation(argc, argv) {
            return run_init_control(argv);
        }
        return init::init(argc, argv);
    }

    run_applet(applet, argc, argv)
}

fn is_init_control_invocation(argc: i32, argv: *const *const u8) -> bool {
    if argc <= 1 {
        return false;
    }
    let Some(arg) = (unsafe { get_arg(argv, 1) }) else {
        return false;
    };
    arg == b"--list" || arg == b"-l" || arg == b"--help" || arg == b"-h" || arg == b"--install"
}

fn run_init_control(argv: *const *const u8) -> i32 {
    let Some(arg) = (unsafe { get_arg(argv, 1) }) else {
        usage();
        return 1;
    };

    if arg == b"--list" || arg == b"-l" {
        applets::list_applets();
        return 0;
    }
    if arg == b"--help" || arg == b"-h" {
        usage();
        return 0;
    }
    if arg == b"--install" {
        let Some(dir) = (unsafe { get_arg(argv, 2) }) else {
            io::write(io::STDERR, "init: --install requires a directory\n");
            return 1;
        };
        return applets::install(dir);
    }

    usage();
    1
}

fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&byte| byte == b'/') {
        Some(index) => &path[index + 1..],
        None => path,
    }
}

fn usage() {
    io::write(io::STDOUT, "init - Bentobox initramfs multicall binary\n\n");
    io::write(io::STDOUT, "Usage: init --list\n");
    io::write(io::STDOUT, "       init --install DIR\n");
    io::write(
        io::STDOUT,
        "       APPLET [ARGS...] via installed symlink\n",
    );
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    io::write(io::STDERR, "init: panic\n");
    io::exit(1)
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[cfg(feature = "alloc")]
mod allocator {
    use core::alloc::{GlobalAlloc, Layout};

    pub struct LibcAllocator;

    unsafe impl GlobalAlloc for LibcAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            libc::malloc(layout.size()) as *mut u8
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            libc::free(ptr.cast::<libc::c_void>());
        }

        unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
            libc::realloc(ptr.cast::<libc::c_void>(), new_size).cast::<u8>()
        }
    }

    #[global_allocator]
    static ALLOCATOR: LibcAllocator = LibcAllocator;
}

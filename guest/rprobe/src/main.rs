#![no_std]
#![no_main]

#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")))]
compile_error!("silo-rprobe only supports aarch64-unknown-linux-musl");

mod sys;

// A no_std binary does not otherwise ask rustc to link the musl C runtime that enters main.
#[link(name = "c")]
unsafe extern "C" {}

#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    sys::execute()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    sys::panic_poweroff()
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

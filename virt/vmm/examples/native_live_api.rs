//! Explicit host-only API proof entry. Never run by Cargo test or normal worker launch.
#![allow(dead_code)]
#[path = "../src/capabilities.rs"]
mod capabilities;
#[path = "../src/clock_sync.rs"]
mod clock_sync;
#[path = "../src/context.rs"]
mod context;
#[path = "../src/durable_file.rs"]
mod durable_file;
#[path = "../src/exec_log.rs"]
mod exec_log;
#[path = "../src/execution.rs"]
mod execution;
#[path = "../src/exit_command.rs"]
mod exit_command;
#[path = "../src/exit_status.rs"]
mod exit_status;
#[path = "../src/ext.rs"]
mod ext;
#[path = "../src/finalize.rs"]
mod finalize;
#[path = "../src/forward/mod.rs"]
mod forward;
#[path = "../src/guest.rs"]
mod guest;
#[path = "../src/krun/mod.rs"]
mod krun;
#[path = "../src/live.rs"]
mod live;
#[path = "../src/lock/mod.rs"]
mod lock;
#[path = "../src/machine.rs"]
mod machine;
#[path = "../src/restore/mod.rs"]
mod restore;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "../src/rosetta/mod.rs"]
mod rosetta;
#[path = "../src/secure_file.rs"]
mod secure_file;
#[path = "../src/services.rs"]
mod services;
#[path = "../src/shutdown.rs"]
mod shutdown;
#[path = "../src/start_request.rs"]
mod start_request;
#[path = "../src/startup.rs"]
mod startup;
#[path = "../src/state.rs"]
mod state;
#[path = "../src/virt/mod.rs"]
mod virt;
#[path = "../src/vsock/mod.rs"]
mod vsock;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
#[path = "native_live_api/stream_map.rs"]
mod native_stream_map;

#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
#[path = "native_live_api/entry.rs"]
mod entry;

fn main() -> eyre::Result<()> {
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    {
        entry::main()
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        eyre::bail!("native API proof requires KVM x86_64 or HVF arm64")
    }
}

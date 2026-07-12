mod builder;
mod config;
mod guest;
mod handle;
mod inspect;
mod lifecycle;
mod lifecycle_options;
mod memory;
mod mounts;
mod name_generator;
mod reference;
pub(crate) mod root_disk;
mod session;
mod start;
mod streams;
mod update;

pub use builder::MachineBuilder;
pub use guest::{GuestBuilder, MachineAgent, MachineGuestConfig};
pub use handle::Machine;
pub use inspect::{
    MachineBootMode, MachineBootReport, MachineData, MachineProvisionFailurePolicy,
    MachineProvisionReport, MachineProvisionStatus, MachineProvisionStepReport,
    MachineProvisionStepStatus, MachineStatus,
};
pub use lifecycle_options::{
    MachineExit, MachineExitOutcome, MachineKillOptions, MachineStopOptions, MachineWaitOptions,
    DEFAULT_MACHINE_WAIT_TIMEOUT,
};
pub use memory::Memory;
pub use mounts::resolve_mount_location;
pub use reference::MachineRef;
pub use session::{
    AttachOptions, AttachOptionsBuilder, ExecControl, ExecEvent, ExecHandle, ExecOptions,
    ExecOptionsBuilder, ExecOutput, ExecSink, ExitStatus, StdinMode,
};
pub use start::{
    MachineExitCommand, MachineStartOptions, NetworkLaunch, NetworkLaunchSecret, OAuthRefreshHook,
};
pub use update::{MachineUpdate, NetworkPolicyUpdate};

pub(crate) use name_generator::generate_machine_name;
pub(crate) use reference::{validate_machine_name, MachineRefKind};

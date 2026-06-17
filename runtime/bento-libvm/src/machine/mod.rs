mod config;
mod create;
mod handle;
mod inspect;
mod lifecycle;
mod name_generator;
mod reference;
mod start;
mod streams;
mod update;

pub use create::MachineCreate;
pub use handle::Machine;
pub use inspect::{MachineData, MachineStatus};
pub use reference::MachineRef;
pub use start::{MachineExitCommand, MachineStartOptions};
pub use update::MachineUpdate;

pub(crate) use name_generator::generate_machine_name;
pub(crate) use reference::{validate_machine_name, MachineRefKind};

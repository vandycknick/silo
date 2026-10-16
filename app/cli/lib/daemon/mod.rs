//! The system daemon (`serve`), and its controller: service registration
//! (`service`) and Docker integration (`docker`).
pub(crate) mod docker;
pub(crate) mod service;

mod control;
mod engine;
mod helper;
mod provision;
mod record;
mod runtime;
pub(crate) mod serve;
mod shutdown;
mod status;
mod storage;
mod supervisor;
mod system_config;
mod upgrade;

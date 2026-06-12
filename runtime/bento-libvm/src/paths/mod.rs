mod defaults;
mod local;
mod machine;
mod network;

pub(crate) use defaults::{resolve_default_config_dir, resolve_default_data_dir};
pub(crate) use local::{LocalPaths, LocalRoots};
pub(crate) use machine::{
    metadata_config_path_in, root_disk_relative_path, vm_spec_path_in, vmmon_trace_log_path_in,
    MachinePaths,
};

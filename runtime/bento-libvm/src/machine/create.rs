use std::collections::BTreeMap;
use std::path::PathBuf;

use bento_vm_spec::Mount;

use crate::network::RequestedNetwork;

#[derive(Debug, Clone)]
pub struct MachineCreate {
    pub image_ref: String,
    pub base_rootfs_path: PathBuf,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
    pub cpus: Option<u8>,
    pub memory_mib: Option<u32>,
    pub kernel: Option<PathBuf>,
    pub initramfs: Option<PathBuf>,
    pub disk_size_bytes: Option<u64>,
    pub nested_virtualization: bool,
    pub rosetta: bool,
    pub userdata: Option<String>,
    pub disks: Vec<PathBuf>,
    pub mounts: Vec<Mount>,
    pub network: Option<RequestedNetwork>,
}

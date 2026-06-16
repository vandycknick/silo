use std::collections::BTreeMap;
use std::path::PathBuf;

use bento_vm_spec::Mount;

use crate::network::MachineNetworkConfig;

/// Machine creation request.
///
/// This is caller input, not a storage model. The runtime fills in IDs, paths,
/// timestamps, cloned root disks, and validated runtime state while creating the
/// machine.
#[derive(Debug, Clone)]
pub struct MachineCreate {
    /// Source image reference recorded for the machine.
    pub image_ref: String,
    /// Root filesystem image to clone into the machine root disk.
    pub base_rootfs_path: PathBuf,
    /// Requested machine name.
    pub name: String,
    /// User-defined labels to attach to the machine.
    pub labels: BTreeMap<String, String>,
    /// User-defined metadata to attach to the machine.
    pub metadata: BTreeMap<String, String>,
    /// Optional CPU count override.
    pub cpus: Option<u8>,
    /// Optional memory size override in MiB.
    pub memory_mib: Option<u32>,
    /// Optional kernel path override.
    pub kernel: Option<PathBuf>,
    /// Optional initramfs path override.
    pub initramfs: Option<PathBuf>,
    /// Optional desired root disk size in bytes.
    pub disk_size_bytes: Option<u64>,
    /// Whether nested virtualization should be enabled.
    pub nested_virtualization: bool,
    /// Whether Rosetta support should be enabled.
    pub rosetta: bool,
    /// Optional cloud-init style guest userdata.
    pub userdata: Option<String>,
    /// Additional disk image paths to attach.
    pub disks: Vec<PathBuf>,
    /// Host paths or volumes to mount into the guest.
    pub mounts: Vec<Mount>,
    /// Durable network config recorded for the machine.
    pub network: Option<MachineNetworkConfig>,
}

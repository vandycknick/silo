/// Well-known filenames in an instance directory owned by libvm.
pub enum InstanceFile {
    Config,
    VmmonPid,
    VmmonSocket,
    VmmonTraceLog,
    SerialLog,
    RootDisk,
    Initramfs,
    CidataDisk,
}

impl InstanceFile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config.yaml",
            Self::VmmonPid => "vm.pid",
            Self::VmmonSocket => "vm.sock",
            Self::VmmonTraceLog => "vm.trace.log",
            Self::SerialLog => "serial.log",
            Self::RootDisk => "rootfs.img",
            Self::Initramfs => "initramfs",
            Self::CidataDisk => "cidata.img",
        }
    }
}

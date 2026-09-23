use vm_spec::VmSpec;

pub(crate) trait VmSpecExt {
    fn cpus_or_default(&self) -> u8;
    fn memory_or_default(&self) -> u32;
    fn nested_virtualization_or_default(&self) -> bool;
    fn rosetta_or_default(&self) -> bool;
}

impl VmSpecExt for VmSpec {
    fn cpus_or_default(&self) -> u8 {
        self.hardware
            .as_ref()
            .and_then(|hardware| hardware.cpus)
            .unwrap_or(1)
    }

    fn memory_or_default(&self) -> u32 {
        self.hardware
            .as_ref()
            .and_then(|hardware| hardware.memory)
            .unwrap_or(512)
    }

    fn nested_virtualization_or_default(&self) -> bool {
        self.hardware
            .as_ref()
            .and_then(|hardware| hardware.nested_virtualization)
            .unwrap_or(false)
    }

    fn rosetta_or_default(&self) -> bool {
        self.hardware
            .as_ref()
            .and_then(|hardware| hardware.rosetta)
            .unwrap_or(false)
    }
}

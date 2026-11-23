use crate::values::*;
use crate::{invalid, path_from_wire, path_to_wire, required, ConversionError};
use silod_spec::daemon::v1 as w;

pub fn spec_to_wire(v: &vm_spec::VmSpec) -> w::VmSpec {
    w::VmSpec {
        spec_version: v.spec_version.to_string(),
        guest: v.guest.as_ref().map(|v| w::VmGuest {
            os: v.os.map(|_| 1),
        }),
        boot: v.boot.as_ref().map(|v| w::Boot {
            kernel: v.kernel.as_ref().map(|v| w::Kernel {
                path: v.path.as_deref().map(path_to_wire),
                cmdline: v.cmdline.clone(),
                initramfs: v.initramfs.as_deref().map(path_to_wire),
            }),
            userdata: v.userdata.clone(),
        }),
        hardware: v.hardware.as_ref().map(|v| w::Hardware {
            cpus: v.cpus.map(u32::from),
            memory_bytes: v.memory.map(|v| u64::from(v) * 1024 * 1024),
            nested_virtualization: v.nested_virtualization,
            rosetta: v.rosetta,
        }),
        storage: v.storage.as_ref().map(|v| w::Storage {
            disks: v
                .disks
                .iter()
                .map(|v| w::Disk {
                    path: path_to_wire(&v.path),
                    read_only: Some(v.read_only),
                    role: Some(match v.role {
                        vm_spec::DiskRole::Root => w::DiskRole::Root as i32,
                        vm_spec::DiskRole::RootLower => w::DiskRole::RootLower as i32,
                        vm_spec::DiskRole::RootUpper => w::DiskRole::RootUpper as i32,
                        vm_spec::DiskRole::Data => w::DiskRole::Data as i32,
                    }),
                    format: Some(match v.format {
                        vm_spec::DiskFormat::Raw => w::DiskFormat::Raw as i32,
                        vm_spec::DiskFormat::Vmdk => w::DiskFormat::Vmdk as i32,
                    }),
                    geometry: Some(w::DiskGeometry {
                        length: v.geometry.length,
                        logical_sector_size: v.geometry.logical_sector_size,
                    }),
                    block_id: Some(v.block_id.as_str().to_owned()),
                })
                .collect(),
        }),
        mounts: v.mounts.iter().map(mount_to_wire).collect(),
        forwards: v.forwards.iter().map(forward_to_wire).collect(),
        vsock: v.vsock.as_ref().map(vsock_to_wire),
        annotations: v.annotations.clone(),
    }
}

pub fn spec_from_wire(v: w::VmSpec) -> Result<vm_spec::VmSpec, ConversionError> {
    let result = vm_spec::VmSpec {
        spec_version: v
            .spec_version
            .parse()
            .map_err(|_| invalid("spec_version", "invalid semantic version"))?,
        guest: v
            .guest
            .map(|v| -> Result<_, ConversionError> {
                Ok(vm_spec::Guest {
                    os: v
                        .os
                        .map(|v| match v {
                            1 => Ok(vm_spec::GuestOs::Linux),
                            _ => Err(invalid("guest.os", "invalid enum")),
                        })
                        .transpose()?,
                })
            })
            .transpose()?,
        boot: v
            .boot
            .map(|v| -> Result<_, ConversionError> {
                Ok(vm_spec::Boot {
                    kernel: v
                        .kernel
                        .map(|v| -> Result<_, ConversionError> {
                            Ok(vm_spec::Kernel {
                                path: v.path.map(path_from_wire).transpose()?,
                                cmdline: v.cmdline,
                                initramfs: v.initramfs.map(path_from_wire).transpose()?,
                            })
                        })
                        .transpose()?,
                    userdata: v.userdata,
                })
            })
            .transpose()?,
        hardware: v
            .hardware
            .map(|v| -> Result<_, ConversionError> {
                Ok(vm_spec::Hardware {
                    cpus: v.cpus.map(crate::updates::cpu_from_wire).transpose()?,
                    memory: v
                        .memory_bytes
                        .map(|v| {
                            if v % (1024 * 1024) != 0 {
                                return Err(invalid("spec.memory_bytes", "not whole mebibytes"));
                            }
                            u32::try_from(v / (1024 * 1024))
                                .map_err(|_| invalid("spec.memory_bytes", "overflow"))
                        })
                        .transpose()?,
                    nested_virtualization: v.nested_virtualization,
                    rosetta: v.rosetta,
                })
            })
            .transpose()?,
        storage: v
            .storage
            .map(|v| -> Result<_, ConversionError> {
                Ok(vm_spec::Storage {
                    disks: v
                        .disks
                        .into_iter()
                        .map(|v| -> Result<_, ConversionError> {
                            let geometry = required(v.geometry, "disk.geometry")?;
                            Ok(vm_spec::Disk {
                                path: path_from_wire(v.path)?,
                                read_only: required(v.read_only, "disk.read_only")?,
                                role: match w::DiskRole::try_from(required(v.role, "disk.role")?) {
                                    Ok(w::DiskRole::Root) => vm_spec::DiskRole::Root,
                                    Ok(w::DiskRole::RootLower) => vm_spec::DiskRole::RootLower,
                                    Ok(w::DiskRole::RootUpper) => vm_spec::DiskRole::RootUpper,
                                    Ok(w::DiskRole::Data) => vm_spec::DiskRole::Data,
                                    _ => return Err(invalid("disk.role", "unknown role")),
                                },
                                format: match w::DiskFormat::try_from(required(
                                    v.format,
                                    "disk.format",
                                )?) {
                                    Ok(w::DiskFormat::Raw) => vm_spec::DiskFormat::Raw,
                                    Ok(w::DiskFormat::Vmdk) => vm_spec::DiskFormat::Vmdk,
                                    _ => return Err(invalid("disk.format", "unknown format")),
                                },
                                geometry: vm_spec::DiskGeometry {
                                    length: geometry.length,
                                    logical_sector_size: geometry.logical_sector_size,
                                },
                                block_id: vm_spec::BlockId::new(required(
                                    v.block_id,
                                    "disk.block_id",
                                )?)
                                .map_err(|_| invalid("disk.block_id", "invalid block ID"))?,
                            })
                        })
                        .collect::<Result<_, _>>()?,
                })
            })
            .transpose()?,
        mounts: v
            .mounts
            .into_iter()
            .map(mount_from_wire)
            .collect::<Result<_, _>>()?,
        forwards: v
            .forwards
            .into_iter()
            .map(forward_from_wire)
            .collect::<Result<_, _>>()?,
        vsock: v.vsock.map(vsock_from_wire).transpose()?,
        annotations: v.annotations,
    };
    result
        .validate()
        .map_err(|_| invalid("spec", "invalid current VM specification"))?;
    Ok(result)
}

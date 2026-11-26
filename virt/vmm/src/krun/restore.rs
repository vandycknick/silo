//! Native restore mapping shared by the worker bootstrap and `inspect-restore`:
//! the exact native identities bound by the authenticated seal and the
//! destination's complete semantic device inventory. The native state codecs
//! stay in libkrun; nothing here parses a state object.

use std::fs::File;
use std::io;
use std::time::Instant;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use libkrun::live::inspection::HvfCompatibilityError;
use libkrun::live::inspection::{
    AdmittedDeviceKind, AdmittedShape, ExpectedDevice, ExpectedDeviceKind, InspectionError,
    InspectionInputs,
};
use libkrun::live::restore::{
    NativeFileFingerprint, RestoreIdentity, StateObjectAuthority, StateObjectIdentity,
};
use libkrun::live::{RamImageAuthentication, RamInputAuthority, StateBinding};
use vm_spec::capture::{CaptureConfiguration, Sha256Digest};
use vm_spec::lifecycle::LiveId;
use vm_spec::restore::{
    RestoreAdmittedDevice, RestoreDeviceKind, RestoreObjectRole, RestorePortabilityRefusal,
    RestoreRequest, RESTORE_BALLOON_ID as BALLOON_ID, RESTORE_CONSOLE_ID as CONSOLE_ID,
    RESTORE_GENERATION_ID as GENERATION_ID, RESTORE_NETWORK_ID as NETWORK_ID,
    RESTORE_RNG_ID as RNG_ID, RESTORE_VSOCK_ID as VSOCK_ID,
};

/// The managed console is one terminal port named "" carrying input and
/// output (the PTY slave), as the cold plan's default console builds it.
pub(crate) const CONSOLE_PORT: (&str, bool, bool, bool) = ("", true, true, true);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn uuid_bytes(id: &LiveId) -> io::Result<[u8; 16]> {
    uuid::Uuid::parse_str(id.as_str())
        .map(|id| *id.as_bytes())
        .map_err(|error| invalid(format!("restore identity is not a UUID: {error}")))
}

fn object(request: &RestoreRequest, role: RestoreObjectRole) -> io::Result<StateObjectAuthority> {
    let object = request
        .objects
        .iter()
        .find(|object| object.role == role)
        .ok_or_else(|| invalid(format!("restore object {role:?} is missing")))?;
    Ok(match &object.authority {
        vm_spec::restore::RestoreObjectAuthority::Identified { identity } => {
            StateObjectAuthority::Identified(StateObjectIdentity {
                length: object.length,
                sha256: *identity.as_bytes(),
            })
        }
        vm_spec::restore::RestoreObjectAuthority::Owned { fingerprint } => {
            StateObjectAuthority::OwnedLocalFile {
                fingerprint: NativeFileFingerprint {
                    device: fingerprint.device,
                    inode: fingerprint.inode,
                    length: fingerprint.length,
                    mode: fingerprint.mode,
                    modified_seconds: fingerprint.modified_seconds,
                    modified_nanoseconds: fingerprint.modified_nanoseconds,
                    changed_seconds: fingerprint.changed_seconds,
                    changed_nanoseconds: fingerprint.changed_nanoseconds,
                },
            }
        }
        vm_spec::restore::RestoreObjectAuthority::Hibernation { file } => {
            StateObjectAuthority::OwnedLocalFile {
                fingerprint: NativeFileFingerprint {
                    device: object.file_device,
                    inode: file.inode,
                    length: file.size,
                    mode: file.mode,
                    modified_seconds: file.modified_seconds,
                    modified_nanoseconds: file.modified_nanoseconds,
                    changed_seconds: file.changed_seconds,
                    changed_nanoseconds: file.changed_nanoseconds,
                },
            }
        }
    })
}

pub(crate) fn binding(
    request: &RestoreRequest,
) -> io::Result<&vm_spec::capture::CaptureStateBinding> {
    match &request.authority {
        vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { evidence, .. } => evidence
            .memory
            .as_ref()
            .map(|memory| &memory.binding)
            .ok_or_else(|| invalid("restore seal has no memory binding")),
        vm_spec::restore::RestoreAuthority::OwnedLocalCut { cut } => Ok(&cut.binding),
        vm_spec::restore::RestoreAuthority::Hibernation { cut } => Ok(&cut.binding),
    }
}

/// Native identities bound by the seal: the state binding, RAM stream and the
/// exact execution, devices and layout objects.
pub(crate) fn identity(
    request: &RestoreRequest,
) -> io::Result<(RestoreIdentity, StateObjectAuthority)> {
    let binding = binding(request)?;
    let binding = StateBinding {
        live_state_schema: binding.live_state_schema.clone(),
        architecture: binding.architecture.clone(),
        profile: *binding.profile.as_bytes(),
        topology: *binding.topology.as_bytes(),
        ram_layout: *binding.ram_layout.as_bytes(),
        source_run: uuid_bytes(&binding.source_run)?,
        pause_generation: binding.pause_generation.get(),
        capture: uuid_bytes(&binding.capture)?,
    };
    Ok((
        RestoreIdentity {
            ram_image: match &request.authority {
                vm_spec::restore::RestoreAuthority::IdentifiedSnapshot { evidence, .. } => {
                    let memory = evidence
                        .memory
                        .as_ref()
                        .ok_or_else(|| invalid("restore lacks identified memory"))?;
                    RamInputAuthority::IdentifiedSnapshot(RamImageAuthentication {
                        state: binding.clone(),
                        stream: *memory.ram_stream.as_bytes(),
                    })
                }
                vm_spec::restore::RestoreAuthority::OwnedLocalCut { cut } => {
                    RamInputAuthority::OwnedLocalCut {
                        state: binding.clone(),
                        materialization_generation: cut.materialization_generation.get(),
                    }
                }
                vm_spec::restore::RestoreAuthority::Hibernation { cut } => {
                    RamInputAuthority::OwnedLocalCut {
                        state: binding.clone(),
                        materialization_generation: cut.materialization_generation.get(),
                    }
                }
            },
            binding,
            execution_object: object(request, RestoreObjectRole::Execution)?,
            devices_object: object(request, RestoreObjectRole::Devices)?,
        },
        object(request, RestoreObjectRole::Layout)?,
    ))
}

/// The destination's complete device inventory, in the cold plan's terms:
/// console, every disk, the vsock mux, the managed NIC iff the destination
/// has one, RNG, balloon and the VM generation device. Shares and Rosetta
/// have no restore representation and refuse here.
pub(crate) fn expected_devices(
    configuration: &CaptureConfiguration,
    network: bool,
) -> io::Result<Vec<ExpectedDevice>> {
    if !configuration.shares.is_empty() || configuration.rosetta {
        return Err(invalid(
            "restore of shared directories or Rosetta is not supported",
        ));
    }
    let mut devices = Vec::with_capacity(configuration.attachments.len() + 6);
    devices.push(ExpectedDevice {
        configured_id: CONSOLE_ID.into(),
        kind: ExpectedDeviceKind::Console {
            ports: vec![(
                CONSOLE_PORT.0.into(),
                CONSOLE_PORT.1,
                CONSOLE_PORT.2,
                CONSOLE_PORT.3,
            )],
        },
    });
    for attachment in &configuration.attachments {
        devices.push(ExpectedDevice {
            configured_id: attachment.block_id.as_str().into(),
            kind: ExpectedDeviceKind::Block {
                format: crate::krun::engine::disk_format(attachment.format),
                byte_length: attachment.geometry.length,
                read_only: attachment.read_only,
            },
        });
    }
    devices.push(ExpectedDevice {
        configured_id: VSOCK_ID.into(),
        kind: ExpectedDeviceKind::Vsock {
            cid: crate::krun::engine::GUEST_CID,
        },
    });
    if network {
        devices.push(ExpectedDevice {
            configured_id: NETWORK_ID.into(),
            kind: ExpectedDeviceKind::Network,
        });
    }
    for (configured_id, kind) in [
        (RNG_ID, ExpectedDeviceKind::Rng),
        (BALLOON_ID, ExpectedDeviceKind::Balloon),
        (GENERATION_ID, ExpectedDeviceKind::Generation),
    ] {
        devices.push(ExpectedDevice {
            configured_id: configured_id.into(),
            kind,
        });
    }
    Ok(devices)
}

/// Borrowed metadata objects of one restore.
pub(crate) struct StateObjects<'a> {
    pub(crate) layout: &'a File,
    pub(crate) execution: &'a File,
    pub(crate) devices: &'a File,
}

/// Authenticate the bounded metadata objects against the seal and probe the
/// actual destination host. Never maps RAM or allocates a child resource.
pub(crate) fn inspect(
    request: &RestoreRequest,
    network: bool,
    objects: StateObjects<'_>,
    deadline: Instant,
) -> io::Result<AdmittedShape> {
    let (expected, layout_object) = identity(request)?;
    let devices = expected_devices(&request.configuration, network)?;
    let shape = libkrun::live::inspection::inspect_compatibility(
        InspectionInputs {
            execution: objects.execution,
            devices: objects.devices,
            layout: objects.layout,
            expected: &expected,
            layout_object: &layout_object,
        },
        &devices,
        deadline,
    )
    .map_err(|error| native_inspection_error(error, &expected.binding))?;
    if shape.cpu_count() != usize::from(request.configuration.cpus) {
        return Err(invalid(
            "restored vCPU count differs from the captured configuration",
        ));
    }
    Ok(shape)
}

pub(crate) fn native_inspection_error(error: InspectionError, binding: &StateBinding) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        inspection_refusal(error, binding),
    )
}

pub(crate) fn inspection_refusal(
    error: InspectionError,
    binding: &StateBinding,
) -> RestorePortabilityRefusal {
    let pin = match error {
        InspectionError::Schema { expected, found } => {
            return RestorePortabilityRefusal::new("live-state-schema", expected, found);
        }
        InspectionError::Architecture { expected, found } => {
            return RestorePortabilityRefusal::new("architecture", expected, found);
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        InspectionError::HvfHost(error) => return hvf_refusal(error),
        InspectionError::Lane => "guest-isa/hypervisor",
        InspectionError::Codec { .. } => "capture-abi/device-codec",
        InspectionError::Binding => "execution-binding",
        InspectionError::Profile(ref cause)
            if cause.contains("cpuid") || cause.contains("CPUID") =>
        {
            "cpu.cpuid"
        }
        InspectionError::Profile(ref cause)
            if cause.contains("xsave") || cause.contains("XSAVE") =>
        {
            "cpu.xsave"
        }
        InspectionError::Profile(ref cause) if cause.contains("msr") || cause.contains("MSR") => {
            "cpu.msr-inventory"
        }
        InspectionError::Profile(ref cause) if cause.contains("rate-disagreement") => {
            "clock.tsc-rate"
        }
        InspectionError::Profile(_) => "cpu.profile",
        InspectionError::Device { .. } | InspectionError::Expectations => "topology.devices",
        InspectionError::Layout(_) => "ram-layout",
        InspectionError::Host { ref cause }
            if cause.contains("cpuid") || cause.contains("CPUID") =>
        {
            "cpu.cpuid"
        }
        InspectionError::Host { ref cause }
            if cause.contains("xsave") || cause.contains("XSAVE") =>
        {
            "cpu.xsave"
        }
        InspectionError::Host { ref cause } if cause.contains("msr") || cause.contains("MSR") => {
            "cpu.msr-inventory"
        }
        InspectionError::Host { ref cause }
            if cause.contains("tsc")
                || cause.contains("TSC")
                || cause.contains("unscaled-rate-mismatch") =>
        {
            "clock.tsc-rate"
        }
        InspectionError::Host { .. } | InspectionError::Deadline => "host-build",
        InspectionError::Descriptor(_) => "storage",
    };
    let expected = if pin == "ram-layout" {
        binding.ram_layout
    } else {
        binding.profile
    };
    RestorePortabilityRefusal::new(
        pin,
        Sha256Digest::from_bytes(expected).to_string(),
        error.to_string(),
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_refusal(error: HvfCompatibilityError) -> RestorePortabilityRefusal {
    use HvfCompatibilityError::*;

    let (pin, expected, actual) = match error {
        HostQuery(error) => (
            "host.hvf-query",
            "destination HVF compatibility facts".into(),
            error.to_string(),
        ),
        CpuCapacity { saved, maximum } => (
            "cpu.capacity",
            format!("{saved} vCPUs"),
            format!("maximum {maximum} vCPUs"),
        ),
        IpaRange {
            region,
            start,
            length,
            destination_bits,
        } => (
            "memory.ipa-range",
            format!("{region:?} at {start:#x} (length {length:#x})"),
            format!("{destination_bits}-bit IPA space"),
        ),
        PageGranule { saved, destination } => (
            "memory.page-granule",
            saved.to_string(),
            destination.to_string(),
        ),
        CpuModelRegister { cpu, register, saved, destination } => (
            "cpu.arm64-model",
            format!("CPU {cpu} register {register:#06x} = {saved:#018x}"),
            format!("{destination:#018x}"),
        ),
        CounterFrequency { saved, destination } => (
            "clock.counter-frequency",
            saved.to_string(),
            destination.to_string(),
        ),
        MachTimebase { saved, destination } => (
            "clock.mach-timebase",
            format!("{}/{}", saved.0, saved.1),
            format!("{}/{}", destination.0, destination.1),
        ),
        GicGeometry { saved, destination } => {
            let geometry = |[dist, dist_len, redist, redist_len]: [u64; 4]| {
                format!("distributor {dist:#x}/{dist_len:#x}, redistributors {redist:#x}/{redist_len:#x}")
            };
            (
                "interrupt-controller.gic-geometry",
                geometry(saved),
                geometry(destination),
            )
        }
        GicBaseAlignment { region, address, alignment } => (
            "interrupt-controller.gic-base-alignment",
            format!("{region:?} base {address:#x}"),
            format!("alignment {alignment:#x}"),
        ),
        GicTopology { saved, destination } => (
            "interrupt-controller.gic-topology",
            format!("SPI {saved}"),
            format!("SPI range [{}, {})", destination.start, destination.end),
        ),
        MmioPlacement { address, irq, minimum_address, alignment, minimum_irq, maximum_irq } => (
            "topology.mmio-placement",
            format!("address {address:#x}, IRQ {irq}"),
            format!("base >= {minimum_address:#x}, alignment {alignment:#x}, IRQs {minimum_irq}..={maximum_irq}"),
        ),
    };
    RestorePortabilityRefusal::new(pin, expected, actual)
}

/// The admitted saved device routing, in saved order.
pub(crate) fn admitted_devices(shape: &AdmittedShape) -> Vec<RestoreAdmittedDevice> {
    shape
        .devices()
        .iter()
        .map(|device| RestoreAdmittedDevice {
            configured_id: device.attachment().configured_id.clone(),
            kind: match device.kind() {
                AdmittedDeviceKind::Block(_) => RestoreDeviceKind::Block,
                AdmittedDeviceKind::Network { .. } => RestoreDeviceKind::Network,
                AdmittedDeviceKind::Vsock { .. } => RestoreDeviceKind::Vsock,
                AdmittedDeviceKind::Console { .. } => RestoreDeviceKind::Console,
                AdmittedDeviceKind::Rng => RestoreDeviceKind::Rng,
                AdmittedDeviceKind::Balloon => RestoreDeviceKind::Balloon,
                AdmittedDeviceKind::Generation => RestoreDeviceKind::Generation,
            },
            address: device.attachment().address,
            irq: device.attachment().irq,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use libkrun::live::inspection::{HvfCompatibilityError, HvfIpaRegion};
    use vm_spec::capture::{CaptureAttachment, CaptureConfiguration, CaptureShare};

    use crate::krun::restore::expected_devices;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use crate::krun::restore::hvf_refusal;

    fn configuration() -> CaptureConfiguration {
        CaptureConfiguration {
            guest_os: None,
            cpus: 2,
            memory_mib: 512,
            nested_virtualization: false,
            rosetta: false,
            kernel_cmdline: Vec::new(),
            vsock: true,
            attachments: vec![CaptureAttachment {
                block_id: vm_spec::BlockId::new("root").expect("block id"),
                role: vm_spec::DiskRole::Root,
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: 1 << 20,
                    logical_sector_size: 512,
                },
                read_only: false,
            }],
            shares: Vec::new(),
        }
    }

    #[test]
    fn restore_refuses_shares_and_rosetta_before_native_inspection() {
        let mut shared = configuration();
        shared.shares.push(CaptureShare {
            tag: "src".into(),
            read_only: true,
        });
        assert!(expected_devices(&shared, false).is_err());
        let mut rosetta = configuration();
        rosetta.rosetta = true;
        assert!(expected_devices(&rosetta, false).is_err());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_hvf_refusal(error: HvfCompatibilityError, pin: &str, expected: &str, actual: &str) {
        let refusal = hvf_refusal(error);
        refusal.validate().unwrap();
        assert_eq!(refusal.pin, pin);
        assert_eq!(refusal.expected, expected);
        assert_eq!(refusal.actual, actual);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_cpu_capacity() {
        assert_hvf_refusal(
            HvfCompatibilityError::CpuCapacity {
                saved: 65,
                maximum: 64,
            },
            "cpu.capacity",
            "65 vCPUs",
            "maximum 64 vCPUs",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_ipa_range() {
        assert_hvf_refusal(
            HvfCompatibilityError::IpaRange {
                region: HvfIpaRegion::Ram,
                start: 0x10_0000_0000,
                length: 0x4000,
                destination_bits: 36,
            },
            "memory.ipa-range",
            "Ram at 0x1000000000 (length 0x4000)",
            "36-bit IPA space",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_page_granule() {
        assert_hvf_refusal(
            HvfCompatibilityError::PageGranule {
                saved: 16384,
                destination: 4096,
            },
            "memory.page-granule",
            "16384",
            "4096",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_cpu_model_register() {
        assert_hvf_refusal(
            HvfCompatibilityError::CpuModelRegister {
                cpu: 1,
                register: 0xc020,
                saved: 0x1101000011110011,
                destination: 0x1101000011110010,
            },
            "cpu.arm64-model",
            "CPU 1 register 0xc020 = 0x1101000011110011",
            "0x1101000011110010",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_counter_frequency() {
        assert_hvf_refusal(
            HvfCompatibilityError::CounterFrequency {
                saved: 24_000_000,
                destination: 19_200_000,
            },
            "clock.counter-frequency",
            "24000000",
            "19200000",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_mach_timebase() {
        assert_hvf_refusal(
            HvfCompatibilityError::MachTimebase {
                saved: (125, 3),
                destination: (1, 1),
            },
            "clock.mach-timebase",
            "125/3",
            "1/1",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_gic_geometry() {
        assert_hvf_refusal(
            HvfCompatibilityError::GicGeometry {
                saved: [0x9fb0000, 0x10000, 0x9fc0000, 0x40000],
                destination: [0x9fc0000, 0x20000, 0x9fe0000, 0x20000],
            },
            "interrupt-controller.gic-geometry",
            "distributor 0x9fb0000/0x10000, redistributors 0x9fc0000/0x40000",
            "distributor 0x9fc0000/0x20000, redistributors 0x9fe0000/0x20000",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_gic_base_alignment() {
        assert_hvf_refusal(
            HvfCompatibilityError::GicBaseAlignment {
                region: HvfIpaRegion::GicDistributor,
                address: 0x9fb0000,
                alignment: 0x20000,
            },
            "interrupt-controller.gic-base-alignment",
            "GicDistributor base 0x9fb0000",
            "alignment 0x20000",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_gic_topology() {
        assert_hvf_refusal(
            HvfCompatibilityError::GicTopology {
                saved: 1020,
                destination: 32..1020,
            },
            "interrupt-controller.gic-topology",
            "SPI 1020",
            "SPI range [32, 1020)",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn hvf_refusal_mmio_placement() {
        assert_hvf_refusal(
            HvfCompatibilityError::MmioPlacement {
                address: 0x09f0_1000,
                irq: 128,
                minimum_address: 0x0a00_0000,
                alignment: 0x1000,
                minimum_irq: 32,
                maximum_irq: 127,
            },
            "topology.mmio-placement",
            "address 0x9f01000, IRQ 128",
            "base >= 0xa000000, alignment 0x1000, IRQs 32..=127",
        );
    }
}

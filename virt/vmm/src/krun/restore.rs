//! Native restore mapping shared by the worker bootstrap and `inspect-restore`:
//! the exact native identities bound by the authenticated seal and the
//! destination's complete semantic device inventory. The native state codecs
//! stay in libkrun; nothing here parses a state object.

use std::fs::File;
use std::io;
use std::time::Instant;

use libkrun::live::inspection::{
    AdmittedDeviceKind, AdmittedShape, ExpectedDevice, ExpectedDeviceKind, InspectionInputs,
};
use libkrun::live::restore::{RestoreIdentity, StateObjectIdentity};
use libkrun::live::{RamImageAuthentication, StateBinding};
use vm_spec::capture::CaptureConfiguration;
use vm_spec::lifecycle::LiveId;
use vm_spec::restore::{
    RestoreAdmittedDevice, RestoreDeviceKind, RestoreObjectRole, RestoreRequest,
    RESTORE_BALLOON_ID as BALLOON_ID, RESTORE_CONSOLE_ID as CONSOLE_ID,
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

fn object(request: &RestoreRequest, role: RestoreObjectRole) -> io::Result<StateObjectIdentity> {
    let object = request
        .objects
        .iter()
        .find(|object| object.role == role)
        .ok_or_else(|| invalid(format!("restore object {role:?} is missing")))?;
    Ok(StateObjectIdentity {
        length: object.length,
        sha256: *object.identity.as_bytes(),
    })
}

/// Native identities bound by the seal: the state binding, RAM stream and the
/// exact execution, devices and layout objects.
pub(crate) fn identity(
    request: &RestoreRequest,
) -> io::Result<(RestoreIdentity, StateObjectIdentity)> {
    let memory = request
        .evidence
        .memory
        .as_ref()
        .ok_or_else(|| invalid("restore seal has no memory binding"))?;
    let binding = &memory.binding;
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
            ram_image: RamImageAuthentication {
                state: binding.clone(),
                stream: *memory.ram_stream.as_bytes(),
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
    .map_err(|error| {
        use libkrun::live::inspection::InspectionError;
        let format_refusal = match &error {
            InspectionError::Schema { expected, found } => {
                Some(vm_spec::restore::RestorePortabilityRefusal::new(
                    "live-state-schema",
                    *expected,
                    found.clone(),
                ))
            }
            InspectionError::Architecture { expected, found } => {
                Some(vm_spec::restore::RestorePortabilityRefusal::new(
                    "architecture",
                    *expected,
                    found.clone(),
                ))
            }
            _ => None,
        };
        if let Some(refusal) = format_refusal {
            return io::Error::new(io::ErrorKind::InvalidData, refusal);
        }
        let pin = match &error {
            InspectionError::Schema { .. } => "live-state-schema",
            InspectionError::Architecture { .. } => "architecture",
            InspectionError::Lane => "guest-isa/hypervisor",
            InspectionError::Codec { .. } => "capture-abi/device-codec",
            InspectionError::Binding => "execution-binding",
            InspectionError::Profile(cause)
                if cause.contains("cpuid") || cause.contains("CPUID") =>
            {
                "cpu.cpuid"
            }
            InspectionError::Profile(cause)
                if cause.contains("xsave") || cause.contains("XSAVE") =>
            {
                "cpu.xsave"
            }
            InspectionError::Profile(cause) if cause.contains("msr") || cause.contains("MSR") => {
                "cpu.msr-inventory"
            }
            InspectionError::Profile(cause) if cause.contains("rate-disagreement") => {
                "clock.tsc-rate"
            }
            InspectionError::Profile(_) => "cpu.profile",
            InspectionError::Device { .. } | InspectionError::Expectations => "topology.devices",
            InspectionError::Layout(_) => "ram-layout",
            InspectionError::Host { cause }
                if cause.contains("cpuid") || cause.contains("CPUID") =>
            {
                "cpu.cpuid"
            }
            InspectionError::Host { cause }
                if cause.contains("xsave") || cause.contains("XSAVE") =>
            {
                "cpu.xsave"
            }
            InspectionError::Host { cause } if cause.contains("msr") || cause.contains("MSR") => {
                "cpu.msr-inventory"
            }
            InspectionError::Host { cause }
                if cause.contains("tsc")
                    || cause.contains("TSC")
                    || cause.contains("unscaled-rate-mismatch") =>
            {
                "clock.tsc-rate"
            }
            InspectionError::Host { .. } => "host-build",
            InspectionError::Descriptor(_) => "storage",
            InspectionError::Deadline => "host-build",
        };
        let expected = request
            .evidence
            .memory
            .as_ref()
            .map(|memory| match pin {
                "live-state-schema" => memory.binding.live_state_schema.clone(),
                "architecture" => memory.binding.architecture.clone(),
                "ram-layout" => memory.binding.ram_layout.to_string(),
                _ => memory.binding.profile.to_string(),
            })
            .unwrap_or_else(|| "captured execution contract".into());
        io::Error::new(
            io::ErrorKind::InvalidData,
            vm_spec::restore::RestorePortabilityRefusal::new(pin, expected, error.to_string()),
        )
    })?;
    if shape.cpu_count() != usize::from(request.configuration.cpus) {
        return Err(invalid(
            "restored vCPU count differs from the captured configuration",
        ));
    }
    Ok(shape)
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
    use vm_spec::capture::{CaptureAttachment, CaptureConfiguration, CaptureShare};

    use crate::krun::restore::expected_devices;

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
}

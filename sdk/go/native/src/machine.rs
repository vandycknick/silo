use std::collections::BTreeMap;
use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use libvm::{ImageSource, MachineNetworkBuilder, Memory, NetworkPolicy};
use serde::Deserialize;
use vm_spec::Mount;

use crate::buffer::SiloBuffer;
use crate::dto;
use crate::error::{catch_ffi, error_from_libvm, invalid_argument, SiloError};
use crate::handles::{MachineHandle, RuntimeHandle};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineCreateRequest {
    source: ImageSourceRequest,
    name: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    cpus: Option<u8>,
    memory_bytes: Option<u64>,
    kernel: Option<String>,
    initramfs: Option<String>,
    #[serde(default)]
    agent_set: bool,
    agent_path: Option<String>,
    root_disk_size_bytes: Option<u64>,
    nested_virtualization: Option<bool>,
    rosetta: Option<bool>,
    userdata: Option<String>,
    #[serde(default)]
    disks: Vec<String>,
    #[serde(default)]
    mounts: Vec<MountRequest>,
    network: Option<NetworkRequest>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ImageSourceRequest {
    Oci { reference: String },
    Disk { path: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MountRequest {
    source: String,
    tag: String,
    #[serde(default)]
    read_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRequest {
    kind: String,
    name: Option<String>,
    policy_json: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_machine_create(
    runtime: *const RuntimeHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_machine: *mut *mut MachineHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let runtime = runtime
            .as_ref()
            .ok_or_else(|| invalid_argument("runtime must not be null"))?;
        if out_machine.is_null() {
            return Err(invalid_argument("out_machine must not be null"));
        }
        *out_machine = ptr::null_mut();
        let request: MachineCreateRequest =
            serde_json::from_slice(request_bytes(request_ptr, request_len)?).map_err(|error| {
                invalid_argument(format!("decode machine create request: {error}"))
            })?;
        let builder = apply_create_request(runtime.context.runtime.machine(), request)?;
        let machine = runtime
            .context
            .tokio
            .block_on(builder.create())
            .map_err(error_from_libvm)?;
        *out_machine = Box::into_raw(Box::new(MachineHandle {
            context: Arc::clone(&runtime.context),
            machine,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_id(
    machine: *const MachineHandle,
    out_id: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_id.is_null() {
            return Err(invalid_argument("out_id must not be null"));
        }
        *out_id = SiloBuffer::from_vec(machine.machine.id().into_bytes());
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_inspect(
    machine: *const MachineHandle,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    machine_data_operation(machine, out_data, |machine| async move {
        machine.inspect().await
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_start(
    machine: *const MachineHandle,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    machine_data_operation(machine, out_data, |machine| async move {
        machine.start().await.map(|start| start.machine)
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_stop(
    machine: *const MachineHandle,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    machine_data_operation(
        machine,
        out_data,
        |machine| async move { machine.stop().await },
    )
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_remove(machine: *const MachineHandle) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        machine
            .context
            .tokio
            .block_on(machine.machine.clone().remove())
            .map_err(error_from_libvm)
    })
}

unsafe fn machine_data_operation<F, Fut>(
    machine: *const MachineHandle,
    out_data: *mut SiloBuffer,
    operation: F,
) -> *mut SiloError
where
    F: FnOnce(libvm::Machine) -> Fut,
    Fut: std::future::Future<Output = Result<libvm::MachineData, libvm::LibVmError>>,
{
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_data.is_null() {
            return Err(invalid_argument("out_data must not be null"));
        }
        *out_data = SiloBuffer::empty();
        let data = machine
            .context
            .tokio
            .block_on(operation(machine.machine.clone()))
            .map_err(error_from_libvm)?;
        let data = serde_json::to_vec(&dto::machine_data(data))
            .map_err(|error| SiloError::new("Serialization", error.to_string()))?;
        *out_data = SiloBuffer::from_vec(data);
        Ok(())
    })
}

fn apply_create_request(
    mut builder: libvm::MachineBuilder,
    request: MachineCreateRequest,
) -> Result<libvm::MachineBuilder, *mut SiloError> {
    builder = builder.image_source(match request.source {
        ImageSourceRequest::Oci { reference } => ImageSource::oci(reference),
        ImageSourceRequest::Disk { path } => ImageSource::disk(path),
    });
    if let Some(name) = request.name {
        builder = builder.name(name);
    }
    builder = builder.labels(request.labels).metadata(request.metadata);
    if let Some(cpus) = request.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(bytes) = request.memory_bytes {
        builder = builder.memory(Memory::bytes(bytes));
    }
    if let Some(kernel) = request.kernel {
        builder = builder.kernel(kernel);
    }
    if let Some(initramfs) = request.initramfs {
        builder = builder.initramfs(initramfs);
    }
    if request.agent_set {
        builder = builder.guest(|guest| guest.agent(request.agent_path.map(PathBuf::from)));
    }
    if let Some(bytes) = request.root_disk_size_bytes {
        builder = builder.root_disk_size(bytes);
    }
    if let Some(enabled) = request.nested_virtualization {
        builder = builder.nested_virtualization(enabled);
    }
    if let Some(enabled) = request.rosetta {
        builder = builder.rosetta(enabled);
    }
    if let Some(userdata) = request.userdata {
        builder = builder.userdata(userdata);
    }
    builder = builder.disks(request.disks.into_iter().map(PathBuf::from).collect());
    builder = builder.mounts(
        request
            .mounts
            .into_iter()
            .map(|mount| Mount {
                source: PathBuf::from(mount.source),
                tag: mount.tag,
                read_only: mount.read_only,
            })
            .collect(),
    );
    if let Some(network) = request.network {
        let parsed = parse_network(network)?;
        builder = builder.network(|network_builder| parsed.apply(network_builder));
    }
    Ok(builder)
}

struct ParsedNetwork {
    kind: String,
    name: Option<String>,
    policy: Option<NetworkPolicy>,
}

impl ParsedNetwork {
    fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        let builder = match self.kind.as_str() {
            "private" => builder.private(),
            "none" => builder.none(),
            "named" => builder.named(self.name.unwrap_or_default()),
            _ => builder,
        };
        self.policy
            .map_or(builder.clone(), |policy| builder.policy(policy))
    }
}

fn parse_network(network: NetworkRequest) -> Result<ParsedNetwork, *mut SiloError> {
    match network.kind.as_str() {
        "private" | "none" => {}
        "named" if network.name.as_ref().is_some_and(|name| !name.is_empty()) => {}
        "named" => return Err(invalid_argument("named network requires name")),
        _ => return Err(invalid_argument("unsupported machine network kind")),
    }
    let policy = network
        .policy_json
        .map(|value| {
            NetworkPolicy::from_json_str(&value)
                .map_err(|error| invalid_argument(format!("invalid network policy: {error}")))
        })
        .transpose()?;
    Ok(ParsedNetwork {
        kind: network.kind,
        name: network.name,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use crate::machine::silo_machine_id;

    #[test]
    fn rejects_null_machine() {
        let error = unsafe { silo_machine_id(ptr::null(), ptr::null_mut()) };
        assert!(!error.is_null());
        unsafe { crate::silo_error_free(error) };
    }
}

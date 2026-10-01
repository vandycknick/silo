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
use crate::handles::{MachineHandle, NodeStateLeaseHandle, RuntimeHandle};
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
    #[serde(default)]
    forwards: Vec<libvm::Forward>,
    vsock: Option<bool>,
    network: Option<NetworkRequest>,
    guest_user: Option<GuestUserRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestUserRequest {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
}

impl GuestUserRequest {
    fn into_config(self) -> libvm::MachineUserConfig {
        libvm::MachineUserConfig::new(self.name, self.uid, self.gid, self.home)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineUpdateRequest {
    name: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    cpus: Option<u8>,
    memory_bytes: Option<u64>,
    root_disk_size_bytes: Option<u64>,
    nested_virtualization: Option<bool>,
    rosetta: Option<bool>,
    forwards: Option<Vec<libvm::Forward>>,
    vsock: Option<bool>,
    network: Option<NetworkRequest>,
    policy_json: Option<String>,
    #[serde(default)]
    clear_policy: bool,
    guest_user: Option<GuestUserRequest>,
    #[serde(default)]
    clear_guest_user: bool,
    guest_agent: Option<GuestAgentRequest>,
    publish: Option<libvm::GuestPublish>,
    #[serde(default)]
    clear_publish: bool,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum GuestAgentRequest {
    Default {},
    Custom { path: String },
    Disabled {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopRequest {
    timeout_ms: Option<u64>,
    #[serde(default)]
    force: bool,
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_update(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let request: MachineUpdateRequest =
            serde_json::from_slice(request_bytes(request_ptr, request_len)?)
                .map_err(|error| invalid_argument(format!("decode machine update: {error}")))?;
        if request.clear_policy && request.policy_json.is_some()
            || request.clear_guest_user && request.guest_user.is_some()
            || request.clear_publish && request.publish.is_some()
        {
            return Err(invalid_argument("set and clear cannot be combined"));
        }
        let mut update = libvm::MachineUpdate::new();
        update.name = request.name;
        update.labels = request.labels;
        update.cpus = request.cpus;
        update.memory = request.memory_bytes.map(Memory::bytes);
        update.root_disk_size = request.root_disk_size_bytes;
        update.nested_virtualization = request.nested_virtualization;
        update.rosetta = request.rosetta;
        update.forwards = request.forwards;
        update.vsock = request
            .vsock
            .map(|enabled| vm_spec::Vsock { enabled, uds: None });
        if let Some(network) = request.network {
            let parsed = parse_network(network)?;
            update = update.network(|builder| parsed.apply(builder));
        }
        if let Some(json) = request.policy_json {
            update = update.set_network_policy(
                NetworkPolicy::from_json_str(&json)
                    .map_err(|error| invalid_argument(error.to_string()))?,
            );
        }
        if request.clear_policy {
            update = update.clear_network_policy();
        }
        if let Some(user) = request.guest_user {
            update = update.user(user.into_config());
        }
        if request.clear_guest_user {
            update = update.clear_user();
        }
        if let Some(agent) = request.guest_agent {
            update = update.guest(|guest| match agent {
                GuestAgentRequest::Default {} => guest,
                GuestAgentRequest::Custom { path } => guest.agent(Some(PathBuf::from(path))),
                GuestAgentRequest::Disabled {} => guest.agent(None),
            });
        }
        if let Some(publish) = request.publish {
            update = update.publish(Some(publish.bind));
        }
        if request.clear_publish {
            update = update.publish(None);
        }
        let result = machine_data_operation(machine, out_data, |machine| async move {
            machine.update(update).await
        });
        if result.is_null() {
            Ok(())
        } else {
            Err(result)
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_stop_with(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let request: StopRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|error| invalid_argument(format!("decode stop options: {error}")))?;
        let mut options = libvm::MachineStopOptions::new();
        if let Some(ms) = request.timeout_ms {
            options = options.timeout(std::time::Duration::from_millis(ms));
        }
        if request.force {
            options = options.force_after_timeout(std::time::Duration::from_secs(10));
        }
        let result = machine_data_operation(machine, out_data, |machine| async move {
            machine.stop_with(options).await
        });
        if result.is_null() {
            Ok(())
        } else {
            Err(result)
        }
    })
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
    publish: Option<libvm::GuestPublish>,
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
pub unsafe extern "C" fn silo_machine_lease_node_state(
    machine: *const MachineHandle,
    out_lease: *mut *mut NodeStateLeaseHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_lease.is_null() {
            return Err(invalid_argument("out_lease must not be null"));
        }
        *out_lease = ptr::null_mut();
        let lease = machine
            .context
            .tokio
            .block_on(machine.machine.lease_node_state())
            .map_err(error_from_libvm)?;
        *out_lease = Box::into_raw(Box::new(NodeStateLeaseHandle { _lease: lease }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_node_state_lease_free(lease: *mut NodeStateLeaseHandle) {
    if !lease.is_null() {
        drop(Box::from_raw(lease));
    }
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
        builder = builder.guest(|guest| guest.agent(request.agent_path.clone().map(PathBuf::from)));
    }
    if let Some(user) = request.guest_user {
        let user = user.into_config();
        builder = builder.guest(|guest| {
            let guest = guest.user(user);
            if request.agent_set {
                guest.agent(request.agent_path.map(PathBuf::from))
            } else {
                guest
            }
        });
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
    builder = builder.forwards(request.forwards);
    if let Some(enabled) = request.vsock {
        builder = builder.vsock(enabled);
    }
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
    publish: Option<libvm::GuestPublish>,
}

impl ParsedNetwork {
    fn apply(self, builder: MachineNetworkBuilder) -> MachineNetworkBuilder {
        let builder = match self.kind.as_str() {
            "private" => builder.private(),
            "none" => builder.none(),
            "named" => builder.named(self.name.unwrap_or_default()),
            _ => builder,
        };
        let builder = match self.policy {
            Some(policy) => builder.policy(policy),
            None => builder,
        };
        match self.publish {
            Some(publish) => builder.publish(publish.bind),
            None => builder,
        }
    }
}

fn parse_network(network: NetworkRequest) -> Result<ParsedNetwork, *mut SiloError> {
    match network.kind.as_str() {
        "private" | "none" => {}
        "named" if network.name.as_ref().is_some_and(|name| !name.is_empty()) => {}
        "named" => return Err(invalid_argument("named network requires name")),
        _ => return Err(invalid_argument("unsupported machine network kind")),
    }
    if network.publish.is_some() && network.kind != "private" {
        return Err(invalid_argument(
            "guest publication requires a private network",
        ));
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
        publish: network.publish,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn update_and_stop_requests_preserve_zero_and_reject_unknown_fields() {
        let request: crate::machine::MachineUpdateRequest =
            serde_json::from_str(r#"{"cpus":0,"vsock":false,"labels":{},"forwards":[]}"#).unwrap();
        assert_eq!(request.cpus, Some(0));
        assert_eq!(request.vsock, Some(false));
        assert_eq!(request.labels.unwrap().len(), 0);
        assert_eq!(request.forwards.unwrap().len(), 0);
        for json in [
            r#"{"unknown":true}"#,
            r#"{"guest_user":{"name":"silo","uid":1000,"gid":1000,"home":"/home/silo","unknown":true}}"#,
            r#"{"network":{"kind":"private","unknown":true}}"#,
            r#"{"guest_agent":{"mode":"disabled","unknown":true}}"#,
        ] {
            assert!(serde_json::from_str::<crate::machine::MachineUpdateRequest>(json).is_err());
        }
        assert!(
            serde_json::from_str::<crate::machine::StopRequest>(r#"{"timeout_ms":0,"force":true}"#)
                .unwrap()
                .force
        );
        assert!(serde_json::from_str::<crate::machine::StopRequest>(
            r#"{"force":true,"unknown":true}"#
        )
        .is_err());
    }
    use std::ptr;

    use crate::machine::silo_machine_id;

    #[test]
    fn forwarding_create_contract_preserves_typed_configuration() {
        let request: crate::machine::MachineCreateRequest = serde_json::from_str(r#"{
            "source":{"kind":"disk","path":"root.img"},
            "forwards":[{"listen":"host:unix:docker.sock","connect":"guest:unix:/run/docker.sock","mode":"0660"}],
            "vsock":false,
            "network":{"kind":"private","publish":{"bind":"loopback"}}
        }"#).unwrap();
        assert_eq!(request.forwards.len(), 1);
        assert_eq!(request.forwards[0].mode.unwrap().get(), 0o660);
        assert_eq!(request.vsock, Some(false));
        let network = crate::machine::parse_network(request.network.unwrap())
            .ok()
            .unwrap();
        assert_eq!(network.publish.unwrap().bind, libvm::PublishBind::Loopback);
        for kind in ["none", "named"] {
            let network = crate::machine::NetworkRequest {
                kind: kind.to_string(),
                name: Some("shared".into()),
                policy_json: None,
                publish: Some(libvm::GuestPublish {
                    bind: libvm::PublishBind::Any,
                }),
            };
            let error = crate::machine::parse_network(network).err().unwrap();
            unsafe { crate::silo_error_free(error) };
        }
        assert!(serde_json::from_str::<crate::machine::NetworkRequest>(
            r#"{"kind":"private","publish":{"bind":"invalid"}}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_null_machine() {
        let error = unsafe { silo_machine_id(ptr::null(), ptr::null_mut()) };
        assert!(!error.is_null());
        unsafe { crate::silo_error_free(error) };
    }
}

use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use libvm::{MachineRef, ResolvedRuntimeComponents, Runtime, RuntimeConfig};
use serde::Deserialize;

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, catch_ffi_void, error_from_libvm, invalid_argument, SiloError};
use crate::handles::{MachineHandle, MachineHandleList, RuntimeContext, RuntimeHandle};

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum QueryRequest {
    Inventory {},
    SecretReadiness {
        policy_json: String,
        machine: Option<String>,
    },
    CheckPolicySecrets {
        policy_json: String,
        machine: Option<String>,
        #[serde(default)]
        secrets: std::collections::BTreeMap<String, String>,
    },
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_query(
    runtime: *const RuntimeHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_data: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let runtime = runtime
            .as_ref()
            .ok_or_else(|| invalid_argument("runtime must not be null"))?;
        if out_data.is_null() {
            return Err(invalid_argument("out_data must not be null"));
        }
        *out_data = SiloBuffer::empty();
        let request: QueryRequest =
            serde_json::from_slice(request_bytes(request_ptr, request_len)?)
                .map_err(|error| invalid_argument(format!("decode runtime query: {error}")))?;
        let value = match request {
            QueryRequest::CheckPolicySecrets {
                policy_json,
                machine,
                secrets,
            } => {
                let policy = libvm::NetworkPolicy::from_json_str(&policy_json)
                    .map_err(|error| invalid_argument(error.to_string()))?;
                let machine = machine
                    .map(MachineRef::parse)
                    .transpose()
                    .map_err(error_from_libvm)?;
                let mut explicit = libvm::EgressCredentials::default();
                for (slot, value) in secrets {
                    explicit = explicit.secret(&slot, value);
                }
                let result = runtime
                    .context
                    .tokio
                    .block_on(runtime.context.runtime.check_policy_secrets(
                        &policy,
                        machine.as_ref(),
                        &explicit,
                    ))
                    .map_err(error_from_libvm)?;
                match result {
                    libvm::policy_secrets::PolicySecretsCheck::Ready => {
                        serde_json::json!({"status":"ready"})
                    }
                    libvm::policy_secrets::PolicySecretsCheck::Missing {
                        requirements,
                        slots,
                    } => {
                        serde_json::json!({"status":"missing", "slots":slots, "requirements":requirements.into_iter().map(|r| serde_json::json!({"owner":r.owner,"alternatives":r.alternatives.into_iter().map(|a| a.slots).collect::<Vec<_>>()})).collect::<Vec<_>>()})
                    }
                    libvm::policy_secrets::PolicySecretsCheck::Unavailable { slot, key, code } => {
                        serde_json::json!({"status":"unavailable","slot":slot,"key":key,"code":code})
                    }
                }
            }
            QueryRequest::Inventory {} => {
                let entries = runtime
                    .context
                    .tokio
                    .block_on(runtime.context.runtime.inventory())
                    .map_err(error_from_libvm)?;
                serde_json::Value::Array(entries.into_iter().map(|entry| {
                    let mut issues = entry.issues;
                    if let Some(data) = &entry.data { issues.extend(data.issues.clone()); }
                    let data = match entry.data.map(crate::dto::machine_data).transpose() {
                        Ok(data) => data,
                        Err(error) => {
                            // Timestamp errors contain a fixed field prefix. Keep the
                            // category/field, without exposing stored values in inventory.
                            let field = match &error {
                                libvm::LibVmError::InvalidCreateRequest { name, reason }
                                    if name == "timestamp" => reason.split_once(':').map(|(field, _)| field),
                                _ => None,
                            };
                            issues.push(libvm::MachineIssue {
                                component: libvm::MachineIssueComponent::Configuration,
                                message: format!("{}: native DTO conversion failed ({})", field.unwrap_or("machine"), error.variant()),
                            });
                            None
                        }
                    };
                    serde_json::json!({"id": entry.id, "name": entry.name, "data": data, "issues": issues})
                }).collect())
            }
            QueryRequest::SecretReadiness {
                policy_json,
                machine,
            } => {
                let policy = libvm::NetworkPolicy::from_json_str(&policy_json)
                    .map_err(|error| invalid_argument(error.to_string()))?;
                let machine = machine
                    .map(MachineRef::parse)
                    .transpose()
                    .map_err(error_from_libvm)?;
                let ready = runtime
                    .context
                    .tokio
                    .block_on(
                        runtime
                            .context
                            .runtime
                            .policy_secrets_ready(&policy, machine.as_ref()),
                    )
                    .map_err(error_from_libvm)?;
                serde_json::json!({"ready": ready})
            }
        };
        *out_data = SiloBuffer::from_vec(
            serde_json::to_vec(&value)
                .map_err(|error| SiloError::new("Serialization", error.to_string()))?,
        );
        Ok(())
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeOpenRequest {
    home: Option<String>,
    runtime_root: Option<String>,
    supervisor_path: Option<String>,
    runtime_components: Option<RuntimeComponentsRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeComponentsRequest {
    supervisor_path: PathBuf,
    netd_path: PathBuf,
    kernel_path: PathBuf,
    initramfs_path: PathBuf,
    agent_path: PathBuf,
    asset_dir: PathBuf,
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_open(
    request_ptr: *const u8,
    request_len: usize,
    out_runtime: *mut *mut RuntimeHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        if out_runtime.is_null() {
            return Err(invalid_argument("out_runtime must not be null"));
        }
        *out_runtime = ptr::null_mut();
        let request = request_bytes(request_ptr, request_len)?;
        let request: RuntimeOpenRequest = serde_json::from_slice(request)
            .map_err(|error| invalid_argument(format!("decode runtime open request: {error}")))?;
        let config = runtime_config(request)?;
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| SiloError::new("Io", format!("create Tokio runtime: {error}")))?;
        let runtime = tokio
            .block_on(Runtime::new(config))
            .map_err(error_from_libvm)?;
        let context = Arc::new(RuntimeContext { runtime, tokio });
        *out_runtime = Box::into_raw(Box::new(RuntimeHandle { context }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_free(runtime: *mut RuntimeHandle) {
    catch_ffi_void(|| {
        if !runtime.is_null() {
            drop(Box::from_raw(runtime));
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_machine_get(
    runtime: *const RuntimeHandle,
    reference_ptr: *const u8,
    reference_len: usize,
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
        let reference = request_string(reference_ptr, reference_len, "reference")?;
        let machine_ref = MachineRef::parse(reference).map_err(error_from_libvm)?;
        let machine = runtime
            .context
            .tokio
            .block_on(runtime.context.runtime.get_machine(&machine_ref))
            .map_err(error_from_libvm)?;
        *out_machine = Box::into_raw(Box::new(MachineHandle {
            context: Arc::clone(&runtime.context),
            machine,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_runtime_machines(
    runtime: *const RuntimeHandle,
    out_machines: *mut MachineHandleList,
) -> *mut SiloError {
    catch_ffi(|| {
        let runtime = runtime
            .as_ref()
            .ok_or_else(|| invalid_argument("runtime must not be null"))?;
        if out_machines.is_null() {
            return Err(invalid_argument("out_machines must not be null"));
        }
        *out_machines = MachineHandleList {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let machines = runtime
            .context
            .tokio
            .block_on(runtime.context.runtime.list_machines())
            .map_err(error_from_libvm)?;
        *out_machines = MachineHandleList::from_machines(&runtime.context, machines);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_handle_list_at(
    machines: *const MachineHandleList,
    index: usize,
) -> *mut MachineHandle {
    let Some(machines) = machines.as_ref() else {
        return ptr::null_mut();
    };
    if index >= machines.len || machines.ptr.is_null() {
        return ptr::null_mut();
    }
    *machines.ptr.add(index)
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_handle_list_free(machines: MachineHandleList) {
    catch_ffi_void(|| {
        if !machines.ptr.is_null() {
            let slice = std::ptr::slice_from_raw_parts_mut(machines.ptr, machines.len);
            drop(Box::from_raw(slice));
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_free(machine: *mut MachineHandle) {
    catch_ffi_void(|| {
        if !machine.is_null() {
            drop(Box::from_raw(machine));
        }
    });
}

fn runtime_config(request: RuntimeOpenRequest) -> Result<RuntimeConfig, *mut SiloError> {
    if request.runtime_components.is_some()
        && (request.runtime_root.is_some() || request.supervisor_path.is_some())
    {
        return Err(invalid_argument(
            "runtime components conflict with runtime root or supervisor path",
        ));
    }
    let mut config = match request.home {
        Some(home) => RuntimeConfig::local(home),
        None => RuntimeConfig::from_env().map_err(error_from_libvm)?,
    };
    if let Some(runtime_root) = request.runtime_root {
        config = config.with_runtime_root(PathBuf::from(runtime_root));
    }
    if let Some(supervisor_path) = request.supervisor_path {
        config = config.with_supervisor_path(PathBuf::from(supervisor_path));
    }
    if let Some(components) = request.runtime_components {
        let components = ResolvedRuntimeComponents::from_paths(
            components.supervisor_path,
            components.netd_path,
            components.kernel_path,
            components.initramfs_path,
            components.agent_path,
            components.asset_dir,
        )
        .map_err(error_from_libvm)?;
        config = config.with_runtime_components(components);
    }
    Ok(config)
}

pub(crate) unsafe fn request_bytes<'a>(
    pointer: *const u8,
    length: usize,
) -> Result<&'a [u8], *mut SiloError> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(invalid_argument(
            "input pointer must not be null when length is non-zero",
        ));
    }
    Ok(std::slice::from_raw_parts(pointer, length))
}

pub(crate) unsafe fn request_string(
    pointer: *const u8,
    length: usize,
    name: &str,
) -> Result<String, *mut SiloError> {
    let value = request_bytes(pointer, length)?;
    let value = std::str::from_utf8(value)
        .map_err(|error| invalid_argument(format!("{name} must be UTF-8: {error}")))?;
    if value.is_empty() {
        return Err(invalid_argument(format!("{name} must not be empty")));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use crate::runtime::{runtime_config, RuntimeOpenRequest};
    use std::os::unix::fs::PermissionsExt;

    fn components_request(root: &std::path::Path) -> serde_json::Value {
        let mut value = serde_json::Map::new();
        for name in [
            "supervisor_path",
            "netd_path",
            "kernel_path",
            "initramfs_path",
            "agent_path",
        ] {
            let path = root.join(name);
            std::fs::write(&path, b"component").expect("write component");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("component mode");
            value.insert(name.into(), serde_json::json!(path));
        }
        value.insert("asset_dir".into(), serde_json::json!(root));
        serde_json::Value::Object(value)
    }

    #[test]
    fn runtime_components_preserve_exact_paths_without_opening_store() {
        let temp = tempfile::tempdir().expect("temp dir");
        let components = components_request(temp.path());
        let home = temp.path().join("unopened-home");
        let request = serde_json::from_value::<RuntimeOpenRequest>(serde_json::json!({
            "home": home, "runtime_components": components,
        }))
        .expect("decode");
        let config = runtime_config(request).expect("config");
        let resolved = config.resolve_components().expect("resolve components");
        for (actual, key) in [
            (resolved.supervisor(), "supervisor_path"),
            (resolved.netd(), "netd_path"),
            (resolved.kernel(), "kernel_path"),
            (resolved.initramfs(), "initramfs_path"),
            (resolved.agent(), "agent_path"),
            (resolved.asset_dir(), "asset_dir"),
        ] {
            assert_eq!(
                actual,
                std::path::Path::new(components[key].as_str().expect("path"))
                    .canonicalize()
                    .expect("canonical path"),
            );
        }
        assert!(!home.exists());
    }

    #[test]
    fn runtime_components_reject_mixed_incomplete_and_unknown_options() {
        let temp = tempfile::tempdir().expect("temp dir");
        let components = components_request(temp.path());
        for selector in ["runtime_root", "supervisor_path"] {
            let mut value = serde_json::json!({
                "home": temp.path(), "runtime_components": components,
            });
            value[selector] = serde_json::json!("");
            let request = serde_json::from_value::<RuntimeOpenRequest>(value).expect("decode");
            let error = runtime_config(request).expect_err("mixed selection");
            unsafe { crate::error::silo_error_free(error) };
        }
        for key in [
            "supervisor_path",
            "netd_path",
            "kernel_path",
            "initramfs_path",
            "agent_path",
            "asset_dir",
        ] {
            let mut incomplete = components.clone();
            incomplete.as_object_mut().expect("object").remove(key);
            assert!(
                serde_json::from_value::<RuntimeOpenRequest>(serde_json::json!({
                    "runtime_components": incomplete,
                }))
                .is_err()
            );
        }
        let mut unknown = components.clone();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<RuntimeOpenRequest>(serde_json::json!({
                "runtime_components": unknown,
            }))
            .is_err()
        );
        for invalid in ["", "relative", "/nonexistent/silo-component"] {
            let mut value = components.clone();
            value["kernel_path"] = serde_json::json!(invalid);
            let request = serde_json::from_value::<RuntimeOpenRequest>(serde_json::json!({
                "home": temp.path(), "runtime_components": value,
            }))
            .expect("decode invalid path");
            let error = runtime_config(request).expect_err("invalid exact component");
            unsafe { crate::error::silo_error_free(error) };
        }
    }
    #[test]
    fn runtime_query_schema_is_strict_for_every_operation() {
        assert!(serde_json::from_str::<crate::runtime::QueryRequest>(
            r#"{"operation":"inventory"}"#
        )
        .is_ok());
        for input in [
            r#"{"operation":"inventory","unknown":true}"#,
            r#"{"operation":"secret_readiness","policy_json":"{}","unknown":true}"#,
            r#"{"operation":"check_policy_secrets","policy_json":"{}","unknown":true}"#,
            r#"{"operation":"check_policy_secrets","policy_json":"{}","secrets":null}"#,
            r#"{"operation":"check_policy_secrets","policy_json":"{}","secrets":[]}"#,
        ] {
            assert!(serde_json::from_str::<crate::runtime::QueryRequest>(input).is_err());
        }
    }
}

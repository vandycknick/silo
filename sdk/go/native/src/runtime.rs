use std::path::PathBuf;
use std::ptr;
use std::sync::Arc;

use libvm::{MachineRef, Runtime, RuntimeConfig};
use serde::Deserialize;

use crate::error::{catch_ffi, catch_ffi_void, error_from_libvm, invalid_argument, SiloError};
use crate::handles::{MachineHandle, MachineHandleList, RuntimeContext, RuntimeHandle};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeOpenRequest {
    data_root: Option<String>,
    run_root: Option<String>,
    image_root: Option<String>,
    runtime_root: Option<String>,
    vmmon_path: Option<String>,
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
        let tokio = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| SiloError::new("Io", format!("create Tokio runtime: {error}")))?;
        let config = runtime_config(request)?;
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
    let mut config = match request.data_root {
        Some(data_root) => RuntimeConfig::local(data_root),
        None => RuntimeConfig::from_env().map_err(error_from_libvm)?,
    };
    if let Some(run_root) = request.run_root {
        config = config.with_run_root(PathBuf::from(run_root));
    }
    if let Some(image_root) = request.image_root {
        config = config.with_image_root(PathBuf::from(image_root));
    }
    if let Some(runtime_root) = request.runtime_root {
        config = config.with_runtime_root(PathBuf::from(runtime_root));
    }
    if let Some(vmmon_path) = request.vmmon_path {
        config = config.with_vmmon_path(PathBuf::from(vmmon_path));
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

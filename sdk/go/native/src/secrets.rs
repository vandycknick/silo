use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;

use crate::error::{catch_ffi, error_from_libvm, invalid_argument, SiloError};
use crate::handles::MachineHandle;
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Set { name: String, value: String },
    Delete { name: String },
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_secret(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine is null"))?;
        if request_len > 32768 {
            return Err(invalid_argument("secret request exceeds limit"));
        }
        let request: Request = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|_| invalid_argument("invalid secret request"))?;
        machine.context.tokio.block_on(async {
            match request {
                Request::Set { name, value } => {
                    let value = STANDARD
                        .decode(value)
                        .map_err(|_| invalid_argument("invalid secret encoding"))?;
                    machine
                        .machine
                        .set_secret(&name, value)
                        .await
                        .map_err(error_from_libvm)
                }
                Request::Delete { name } => machine
                    .machine
                    .delete_secret(&name)
                    .await
                    .map_err(error_from_libvm),
            }
        })
    })
}

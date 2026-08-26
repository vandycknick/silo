use std::ptr;
use std::sync::Arc;

use libvm::{MachineLogOptions, MachineLogOutput, MachineLogSource};
use serde::Deserialize;
use tokio_stream::StreamExt;

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, catch_ffi_void, invalid_argument, SiloError};
use crate::handles::{LogHandle, LogState, MachineHandle};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogRequest {
    source: String,
    #[serde(default)]
    follow: bool,
}
#[repr(C)]
pub struct SiloLogChunk {
    pub output: u32,
    pub data: SiloBuffer,
}

impl SiloLogChunk {
    fn empty() -> Self {
        Self {
            output: 0,
            data: SiloBuffer::empty(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_logs(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_log: *mut *mut LogHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_log.is_null() {
            return Err(invalid_argument("out_log must not be null"));
        }
        *out_log = ptr::null_mut();
        let request: LogRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|error| invalid_argument(format!("decode log request: {error}")))?;
        let source = match request.source.as_str() {
            "monitor" => MachineLogSource::Monitor,
            "serial" => MachineLogSource::Serial,
            "exec" => MachineLogSource::Exec,
            "network" => MachineLogSource::Network,
            "network_audit" => MachineLogSource::NetworkAudit,
            _ => return Err(invalid_argument("unsupported machine log source")),
        };
        let stream = machine
            .context
            .tokio
            .block_on(machine.machine.logs(
                source,
                MachineLogOptions {
                    follow: request.follow,
                },
            ))
            .map_err(crate::error::error_from_libvm)?;
        let (cancellation, _) = tokio::sync::watch::channel(false);
        *out_log = Box::into_raw(Box::new(LogHandle {
            context: Arc::clone(&machine.context),
            state: std::sync::Mutex::new(LogState {
                stream: Some(stream),
                receive_in_flight: false,
                closed: false,
                cancellation,
            }),
        }));
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_log_recv(
    log: *const LogHandle,
    out_chunk: *mut SiloLogChunk,
    out_eof: *mut bool,
) -> *mut SiloError {
    catch_ffi(|| {
        let log = log
            .as_ref()
            .ok_or_else(|| invalid_argument("log must not be null"))?;
        if out_chunk.is_null() || out_eof.is_null() {
            return Err(invalid_argument("log receive outputs must not be null"));
        }
        *out_chunk = SiloLogChunk::empty();
        *out_eof = false;
        let (mut stream, mut cancellation) = {
            let mut state = log
                .state
                .lock()
                .map_err(|_| SiloError::new("Closed", "log lock is poisoned"))?;
            if state.closed || state.receive_in_flight {
                return Err(SiloError::new("Closed", "log stream is closed or busy"));
            }
            state.receive_in_flight = true;
            (
                state
                    .stream
                    .take()
                    .ok_or_else(|| SiloError::new("Closed", "log stream is closed"))?,
                state.cancellation.subscribe(),
            )
        };
        let chunk = log.context.tokio.block_on(async {
            tokio::select! {biased;_=cancellation.changed()=>None,value=stream.next()=>Some(value)}
        });
        let mut state = log
            .state
            .lock()
            .map_err(|_| SiloError::new("Closed", "log lock is poisoned"))?;
        state.receive_in_flight = false;
        if state.closed {
            return Err(SiloError::new("Closed", "log stream is closed"));
        }
        match chunk {
            None => {
                state.closed = true;
                Err(SiloError::new("Closed", "log stream is closed"))
            }
            Some(None) => {
                state.closed = true;
                *out_eof = true;
                Ok(())
            }
            Some(Some(Err(error))) => {
                state.closed = true;
                Err(crate::error::error_from_libvm(error))
            }
            Some(Some(Ok(chunk))) => {
                let output = match chunk.output {
                    MachineLogOutput::Stdout => 1,
                    MachineLogOutput::Stderr => 2,
                    _ => return Err(SiloError::new("Unknown", "unsupported log output")),
                };
                state.stream = Some(stream);
                *out_chunk = SiloLogChunk {
                    output,
                    data: SiloBuffer::from_vec(chunk.data.to_vec()),
                };
                Ok(())
            }
        }
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_log_close(log: *const LogHandle) -> *mut SiloError {
    catch_ffi(|| {
        let log = log
            .as_ref()
            .ok_or_else(|| invalid_argument("log must not be null"))?;
        let mut state = log
            .state
            .lock()
            .map_err(|_| SiloError::new("Closed", "log lock is poisoned"))?;
        state.closed = true;
        state.stream = None;
        state.cancellation.send_replace(true);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_log_free(log: *mut LogHandle) {
    catch_ffi_void(|| {
        if !log.is_null() {
            let log = Box::from_raw(log);
            if let Ok(mut state) = log.state.lock() {
                state.closed = true;
                state.stream = None;
                state.cancellation.send_replace(true);
            };
        }
    });
}

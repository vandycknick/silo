use std::collections::BTreeMap;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use libvm::{
    ExecutionEvent, ExecutionOptionsBuilder, ExecutionOutput, ExecutionResult,
    SshShellOptionsBuilder,
};
use serde::{Deserialize, Serialize};

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, catch_ffi_void, error_from_libvm, invalid_argument, SiloError};
use crate::handles::{ExecutionHandle, ExecutionSessionState, MachineHandle, StdinHandle};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequest {
    program: Option<String>,
    script: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    additional_args: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    timeout_millis: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_bytes")]
    stdin: Option<Vec<u8>>,
    #[serde(default)]
    pipe_stdin: bool,
    tty: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshRequest {
    cwd: Option<String>,
    user: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    term: Option<String>,
    detach_keys: Option<String>,
    forward_agent: Option<bool>,
}

#[derive(Serialize)]
struct ResultDto {
    kind: &'static str,
    code: Option<u32>,
    signal: Option<u32>,
    reason: Option<&'static str>,
    message: Option<String>,
}

#[repr(C)]
pub struct SiloExecutionOutput {
    pub result: SiloBuffer,
    pub stdout_data: SiloBuffer,
    pub stderr_data: SiloBuffer,
    pub terminal_output: SiloBuffer,
}

impl SiloExecutionOutput {
    fn empty() -> Self {
        Self {
            result: SiloBuffer::empty(),
            stdout_data: SiloBuffer::empty(),
            stderr_data: SiloBuffer::empty(),
            terminal_output: SiloBuffer::empty(),
        }
    }
}

#[repr(C)]
pub struct SiloExecutionEvent {
    pub metadata: SiloBuffer,
    pub data: SiloBuffer,
}

impl SiloExecutionEvent {
    fn empty() -> Self {
        Self {
            metadata: SiloBuffer::empty(),
            data: SiloBuffer::empty(),
        }
    }
}

#[derive(Serialize)]
struct EventDto {
    kind: &'static str,
    result: Option<ResultDto>,
}

#[derive(Serialize)]
struct SshStatusDto {
    code: i32,
    success: bool,
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_exec(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_output: *mut SiloExecutionOutput,
) -> *mut SiloError {
    collected(machine, request_ptr, request_len, out_output, false)
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_shell(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_output: *mut SiloExecutionOutput,
) -> *mut SiloError {
    collected(machine, request_ptr, request_len, out_output, true)
}

unsafe fn collected(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_output: *mut SiloExecutionOutput,
    shell: bool,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_output.is_null() {
            return Err(invalid_argument("out_output must not be null"));
        }
        *out_output = SiloExecutionOutput::empty();
        let request = decode_request(request_ptr, request_len)?;
        let output = if shell {
            let script = request
                .script
                .clone()
                .ok_or_else(|| invalid_argument("shell requires script"))?;
            machine.context.tokio.block_on(
                machine
                    .machine
                    .shell_with(script, |builder| apply_options(builder, request)),
            )
        } else {
            let program = request
                .program
                .clone()
                .ok_or_else(|| invalid_argument("exec requires program"))?;
            let args = request.args.clone();
            machine
                .context
                .tokio
                .block_on(machine.machine.exec_with(program, |builder| {
                    apply_options(builder.args(args), request)
                }))
        }
        .map_err(error_from_libvm)?;
        *out_output = execution_output(output)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_spawn(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_session: *mut *mut ExecutionHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_session.is_null() {
            return Err(invalid_argument("out_session must not be null"));
        }
        *out_session = ptr::null_mut();
        let request = decode_request(request_ptr, request_len)?;
        let program = request
            .program
            .clone()
            .ok_or_else(|| invalid_argument("spawn requires program"))?;
        let args = request.args.clone();
        let session = machine
            .context
            .tokio
            .block_on(machine.machine.spawn_with(program, |builder| {
                apply_options(builder.args(args), request)
            }))
            .map_err(error_from_libvm)?;
        let control = session.control();
        *out_session = Box::into_raw(Box::new(ExecutionHandle {
            context: Arc::clone(&machine.context),
            state: std::sync::Mutex::new(ExecutionSessionState::new(session)),
            control,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_attach(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_result: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_result.is_null() {
            return Err(invalid_argument("out_result must not be null"));
        }
        let request = decode_request(request_ptr, request_len)?;
        let program = request
            .program
            .clone()
            .ok_or_else(|| invalid_argument("attach requires program"))?;
        let args = request.args.clone();
        let result = machine
            .context
            .tokio
            .block_on(machine.machine.attach_with(program, |builder| {
                apply_options(builder.args(args), request).tty(true)
            }))
            .map_err(error_from_libvm)?;
        *out_result = json_buffer(result_dto(result))?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_attach_shell(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_status: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_status.is_null() {
            return Err(invalid_argument("out_status must not be null"));
        }
        let request: SshRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|error| invalid_argument(format!("decode SSH request: {error}")))?;
        let status = machine
            .context
            .tokio
            .block_on(
                machine
                    .machine
                    .attach_shell_with(|builder| apply_ssh_options(builder, request)),
            )
            .map_err(error_from_libvm)?;
        *out_status = json_buffer(SshStatusDto {
            code: status.code,
            success: status.success,
        })?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_recv(
    session: *const ExecutionHandle,
    out_event: *mut SiloExecutionEvent,
    out_eof: *mut bool,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        if out_event.is_null() || out_eof.is_null() {
            return Err(invalid_argument(
                "execution receive outputs must not be null",
            ));
        }
        *out_event = SiloExecutionEvent::empty();
        *out_eof = false;
        let (mut value, mut cancellation) = begin_operation(session)?;
        let event = session.context.tokio.block_on(async { tokio::select! { biased; _ = cancellation.changed() => None, event = value.recv() => Some(event) } });
        match event {
            None => {
                finish_operation(session, None)?;
                return Err(SiloError::new("Closed", "execution session is closed"));
            }
            Some(Ok(Some(event))) => {
                let terminal = matches!(event, ExecutionEvent::Terminal(_));
                let (metadata, data) = execution_event(event);
                *out_event = SiloExecutionEvent {
                    metadata: json_buffer(metadata)?,
                    data: SiloBuffer::from_vec(data),
                };
                finish_operation(session, (!terminal).then_some(value))?;
            }
            Some(Ok(None)) => {
                *out_eof = true;
                finish_operation(session, None)?;
            }
            Some(Err(error)) => {
                finish_operation(session, None)?;
                return Err(error_from_libvm(error));
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_wait(
    session: *const ExecutionHandle,
    out_result: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        if out_result.is_null() {
            return Err(invalid_argument("out_result must not be null"));
        }
        *out_result = SiloBuffer::empty();
        let (mut value, mut cancellation) = begin_operation(session)?;
        let result = session.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = cancellation.changed() => None,
                result = value.wait() => Some(result),
            }
        });
        finish_operation(session, None)?;
        match result {
            Some(Ok(result)) => {
                *out_result = json_buffer(result_dto(result))?;
                Ok(())
            }
            Some(Err(error)) => Err(error_from_libvm(error)),
            None => Err(SiloError::new("Closed", "execution session is closed")),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_collect(
    session: *const ExecutionHandle,
    out_output: *mut SiloExecutionOutput,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        if out_output.is_null() {
            return Err(invalid_argument("out_output must not be null"));
        }
        *out_output = SiloExecutionOutput::empty();
        let (mut value, mut cancellation) = begin_operation(session)?;
        let result = session.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = cancellation.changed() => None,
                result = value.collect() => Some(result),
            }
        });
        finish_operation(session, None)?;
        match result {
            Some(Ok(output)) => {
                *out_output = execution_output(output)?;
                Ok(())
            }
            Some(Err(error)) => Err(error_from_libvm(error)),
            None => Err(SiloError::new("Closed", "execution session is closed")),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_stdin(
    session: *const ExecutionHandle,
    out_stdin: *mut *mut StdinHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        if out_stdin.is_null() {
            return Err(invalid_argument("out_stdin must not be null"));
        }
        *out_stdin = session
            .control
            .stdin()
            .map(|stdin| {
                Box::into_raw(Box::new(StdinHandle {
                    context: Arc::clone(&session.context),
                    stdin,
                }))
            })
            .unwrap_or(ptr::null_mut());
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_signal(
    session: *const ExecutionHandle,
    signal: u32,
) -> *mut SiloError {
    control(session, |value| Box::pin(value.signal(signal)))
}
#[no_mangle]
pub unsafe extern "C" fn silo_execution_resize_pty(
    session: *const ExecutionHandle,
    rows: u16,
    columns: u16,
) -> *mut SiloError {
    control(session, |value| Box::pin(value.resize_pty(rows, columns)))
}

unsafe fn control<'a>(
    session: *const ExecutionHandle,
    operation: impl FnOnce(
        &'a libvm::ExecutionControl,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), libvm::LibVmError>> + 'a>,
    >,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        session
            .context
            .tokio
            .block_on(operation(&session.control))
            .map_err(error_from_libvm)
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_execution_close_requests(
    session: *const ExecutionHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        session.control.close_requests();
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_execution_cancel(session: *const ExecutionHandle) -> *mut SiloError {
    catch_ffi(|| {
        let session = session
            .as_ref()
            .ok_or_else(|| invalid_argument("session must not be null"))?;
        session.control.close_requests();
        close_state(session)?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_execution_free(session: *mut ExecutionHandle) {
    catch_ffi_void(|| {
        if !session.is_null() {
            let session = Box::from_raw(session);
            if let Ok(mut state) = session.state.lock() {
                state.closed = true;
                state.session = None;
                state.cancellation.send_replace(true);
            };
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn silo_stdin_write(
    stdin: *const StdinHandle,
    data_ptr: *const u8,
    data_len: usize,
) -> *mut SiloError {
    catch_ffi(|| {
        let stdin = stdin
            .as_ref()
            .ok_or_else(|| invalid_argument("stdin must not be null"))?;
        let data = request_bytes(data_ptr, data_len)?.to_vec();
        stdin
            .context
            .tokio
            .block_on(stdin.stdin.write(data))
            .map_err(error_from_libvm)
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_stdin_close(stdin: *const StdinHandle) -> *mut SiloError {
    catch_ffi(|| {
        let stdin = stdin
            .as_ref()
            .ok_or_else(|| invalid_argument("stdin must not be null"))?;
        stdin
            .context
            .tokio
            .block_on(stdin.stdin.close())
            .map_err(error_from_libvm)
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_stdin_free(stdin: *mut StdinHandle) {
    catch_ffi_void(|| {
        if !stdin.is_null() {
            drop(Box::from_raw(stdin));
        }
    });
}

fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|encoded| STANDARD.decode(encoded).map_err(serde::de::Error::custom))
        .transpose()
}

fn decode_request(pointer: *const u8, length: usize) -> Result<ExecRequest, *mut SiloError> {
    unsafe {
        serde_json::from_slice(request_bytes(pointer, length)?)
            .map_err(|error| invalid_argument(format!("decode execution request: {error}")))
    }
}
fn apply_options(
    mut builder: ExecutionOptionsBuilder,
    request: ExecRequest,
) -> ExecutionOptionsBuilder {
    builder = builder.args(request.additional_args);
    if let Some(cwd) = request.cwd {
        builder = builder.cwd(cwd)
    }
    if let Some(user) = request.user {
        builder = builder.user(user)
    }
    for (key, value) in request.env {
        builder = builder.env(key, value)
    }
    if let Some(ms) = request.timeout_millis {
        builder = builder.timeout(Duration::from_millis(ms))
    }
    if let Some(data) = request.stdin {
        builder = builder.stdin_bytes(data)
    } else if request.pipe_stdin {
        builder = builder.stdin_pipe()
    }
    if let Some(tty) = request.tty {
        builder = builder.tty(tty)
    }
    builder
}
fn apply_ssh_options(
    mut builder: SshShellOptionsBuilder,
    request: SshRequest,
) -> SshShellOptionsBuilder {
    if let Some(cwd) = request.cwd {
        builder = builder.cwd(cwd)
    }
    if let Some(user) = request.user {
        builder = builder.user(user)
    }
    for (key, value) in request.env {
        builder = builder.env(key, value)
    }
    if let Some(term) = request.term {
        builder = builder.term(term)
    }
    if let Some(keys) = request.detach_keys {
        builder = builder.detach_keys(keys)
    }
    if let Some(value) = request.forward_agent {
        builder = builder.forward_agent(value)
    }
    builder
}

fn begin_operation(
    session: &ExecutionHandle,
) -> Result<(libvm::ExecutionSession, tokio::sync::watch::Receiver<bool>), *mut SiloError> {
    let mut state = session
        .state
        .lock()
        .map_err(|_| SiloError::new("Closed", "execution session lock is poisoned"))?;
    if state.closed || state.operation_in_flight {
        return Err(SiloError::new(
            "Closed",
            "execution session is closed or busy",
        ));
    }
    let value = state
        .session
        .take()
        .ok_or_else(|| SiloError::new("Closed", "execution session is closed"))?;
    state.operation_in_flight = true;
    Ok((value, state.cancellation.subscribe()))
}
fn finish_operation(
    session: &ExecutionHandle,
    value: Option<libvm::ExecutionSession>,
) -> Result<(), *mut SiloError> {
    let mut state = session
        .state
        .lock()
        .map_err(|_| SiloError::new("Closed", "execution session lock is poisoned"))?;
    state.operation_in_flight = false;
    if state.closed {
        return Ok(());
    }
    state.session = value;
    if state.session.is_none() {
        state.closed = true;
        state.cancellation.send_replace(true);
    }
    Ok(())
}
fn close_state(session: &ExecutionHandle) -> Result<(), *mut SiloError> {
    let mut state = session
        .state
        .lock()
        .map_err(|_| SiloError::new("Closed", "execution session lock is poisoned"))?;
    state.closed = true;
    state.session = None;
    state.cancellation.send_replace(true);
    Ok(())
}
fn json_buffer(value: impl Serialize) -> Result<SiloBuffer, *mut SiloError> {
    serde_json::to_vec(&value)
        .map(SiloBuffer::from_vec)
        .map_err(|error| SiloError::new("Serialization", error.to_string()))
}

fn execution_output(value: ExecutionOutput) -> Result<SiloExecutionOutput, *mut SiloError> {
    Ok(SiloExecutionOutput {
        result: json_buffer(result_dto(value.result().clone()))?,
        stdout_data: SiloBuffer::from_vec(value.stdout_bytes().to_vec()),
        stderr_data: SiloBuffer::from_vec(value.stderr_bytes().to_vec()),
        terminal_output: SiloBuffer::from_vec(value.terminal_output_bytes().to_vec()),
    })
}
fn result_dto(value: ExecutionResult) -> ResultDto {
    match value {
        ExecutionResult::Exited { code } => ResultDto {
            kind: "exited",
            code,
            signal: None,
            reason: None,
            message: None,
        },
        ExecutionResult::Signaled { signal } => ResultDto {
            kind: "signaled",
            code: None,
            signal,
            reason: None,
            message: None,
        },
        ExecutionResult::LaunchFailed(value) => ResultDto {
            kind: "launch_failed",
            code: None,
            signal: None,
            reason: Some(launch_reason(value.reason)),
            message: value.message,
        },
        ExecutionResult::Lost(value) => ResultDto {
            kind: "lost",
            code: None,
            signal: None,
            reason: Some(lost_reason(value.reason)),
            message: value.message,
        },
    }
}
fn execution_event(value: ExecutionEvent) -> (EventDto, Vec<u8>) {
    match value {
        ExecutionEvent::Accepted => (
            EventDto {
                kind: "accepted",
                result: None,
            },
            Vec::new(),
        ),
        ExecutionEvent::Started => (
            EventDto {
                kind: "started",
                result: None,
            },
            Vec::new(),
        ),
        ExecutionEvent::Stdout(data) => (
            EventDto {
                kind: "stdout",
                result: None,
            },
            data,
        ),
        ExecutionEvent::Stderr(data) => (
            EventDto {
                kind: "stderr",
                result: None,
            },
            data,
        ),
        ExecutionEvent::TerminalOutput(data) => (
            EventDto {
                kind: "terminal_output",
                result: None,
            },
            data,
        ),
        ExecutionEvent::Terminal(result) => (
            EventDto {
                kind: "terminal",
                result: Some(result_dto(result)),
            },
            Vec::new(),
        ),
    }
}
fn launch_reason(value: libvm::ExecutionLaunchFailureReason) -> &'static str {
    use libvm::ExecutionLaunchFailureReason::*;
    match value {
        Unspecified => "unspecified",
        CommandNotFound => "command_not_found",
        InvalidProcessSpec => "invalid_process_spec",
        WorkingDirectoryNotFound => "working_directory_not_found",
        WorkingDirectoryNotDirectory => "working_directory_not_directory",
        InvalidIdentity => "invalid_identity",
        IdentityNotFound => "identity_not_found",
        PermissionDenied => "permission_denied",
        SpawnFailed => "spawn_failed",
        CancelledBeforeStart => "cancelled_before_start",
    }
}
fn lost_reason(value: libvm::ExecutionLostReason) -> &'static str {
    use libvm::ExecutionLostReason::*;
    match value {
        Unspecified => "unspecified",
        AgentInstanceReplaced => "agent_instance_replaced",
        AgentBootReplaced => "agent_boot_replaced",
        AgentUnavailable => "agent_unavailable",
        GuestStreamLost => "guest_stream_lost",
        VmStopped => "vm_stopped",
        VmmonExited => "vmmon_exited",
    }
}

#[cfg(test)]
mod tests {
    use libvm::ExecutionEvent;

    use crate::exec::{decode_request, execution_event};

    #[test]
    fn execution_request_decodes_go_base64_stdin() {
        let request = br#"{"program":"cat","stdin":"AP+A"}"#;
        let decoded = decode_request(request.as_ptr(), request.len()).expect("decode request");
        assert_eq!(decoded.stdin, Some(vec![0, 255, 128]));
    }

    #[test]
    fn execution_events_keep_output_as_raw_bytes() {
        let (metadata, data) = execution_event(ExecutionEvent::Stdout(vec![0, 255, 128]));
        assert_eq!(metadata.kind, "stdout");
        assert_eq!(data, [0, 255, 128]);
    }
}

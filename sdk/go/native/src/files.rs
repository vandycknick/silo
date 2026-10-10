use std::ptr;
use std::sync::{Arc, Mutex};

use libvm::{
    FileWriteDisposition, LibVmError, MachineDirectoryCreateDisposition, MachineEntryKind,
    MachineFileDownload, MachineFileUploadOptions,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, SimplexStream, WriteHalf};
use tokio::sync::watch;

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, catch_ffi_void, error_from_libvm, invalid_argument, SiloError};
use crate::handles::{MachineHandle, RuntimeContext};
use crate::runtime::request_bytes;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathRequest {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryRequest {
    path: String,
    #[serde(default)]
    parents: bool,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadRequest {
    path: String,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}
#[derive(Serialize)]
struct FileEntryDto {
    path: String,
    name: String,
    kind: &'static str,
    size_bytes: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_at_unix_millis: u64,
}
#[derive(Serialize)]
struct DispositionDto {
    disposition: &'static str,
}

pub struct UploadHandle {
    context: Arc<RuntimeContext>,
    state: Mutex<UploadState>,
}
struct UploadState {
    writer: Option<WriteHalf<SimplexStream>>,
    task: Option<tokio::task::JoinHandle<Result<FileWriteDisposition, LibVmError>>>,
    abort: tokio::task::AbortHandle,
    cancellation: watch::Sender<bool>,
    finished: bool,
    busy: bool,
}
pub struct DownloadHandle {
    context: Arc<RuntimeContext>,
    state: Mutex<DownloadState>,
}
struct DownloadState {
    reader: Option<MachineFileDownload>,
    cancellation: watch::Sender<bool>,
    eof: bool,
    busy: bool,
}
fn closed(message: &str) -> *mut SiloError {
    SiloError::new("Closed", message)
}
fn json_buffer(value: impl Serialize) -> Result<SiloBuffer, *mut SiloError> {
    serde_json::to_vec(&value)
        .map(SiloBuffer::from_vec)
        .map_err(|e| SiloError::new("Serialization", e.to_string()))
}
fn kind_name(kind: MachineEntryKind) -> &'static str {
    match kind {
        MachineEntryKind::File => "file",
        MachineEntryKind::Directory => "directory",
        MachineEntryKind::Symlink => "symlink",
        MachineEntryKind::Fifo => "fifo",
        MachineEntryKind::Socket => "socket",
        MachineEntryKind::BlockDevice => "block_device",
        MachineEntryKind::CharacterDevice => "character_device",
    }
}

#[no_mangle]
pub unsafe extern "C" fn silo_machine_file_stat(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_entry: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_entry.is_null() {
            return Err(invalid_argument("out_entry must not be null"));
        }
        *out_entry = SiloBuffer::empty();
        let request: PathRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|e| invalid_argument(e.to_string()))?;
        let entry = machine
            .context
            .tokio
            .block_on(machine.machine.get_file_entry(request.path))
            .map_err(error_from_libvm)?;
        let millis = entry
            .modified_at
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SiloError::new("Serialization", e.to_string()))?
            .as_millis();
        let modified_at_unix_millis =
            u64::try_from(millis).map_err(|e| SiloError::new("Serialization", e.to_string()))?;
        *out_entry = json_buffer(FileEntryDto {
            path: entry.path,
            name: entry.name,
            kind: kind_name(entry.kind),
            size_bytes: entry.size_bytes,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            modified_at_unix_millis,
        })?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_machine_create_directory(
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
        *out_result = SiloBuffer::empty();
        let q: DirectoryRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|e| invalid_argument(e.to_string()))?;
        let result = machine
            .context
            .tokio
            .block_on(
                machine
                    .machine
                    .create_directory(q.path, q.parents, q.mode, q.uid, q.gid),
            )
            .map_err(error_from_libvm)?;
        *out_result = json_buffer(DispositionDto {
            disposition: match result {
                MachineDirectoryCreateDisposition::Created => "created",
                MachineDirectoryCreateDisposition::AlreadyExists => "already_exists",
            },
        })?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_machine_upload_open(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_upload: *mut *mut UploadHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_upload.is_null() {
            return Err(invalid_argument("out_upload must not be null"));
        }
        *out_upload = ptr::null_mut();
        let q: UploadRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|e| invalid_argument(e.to_string()))?;
        let (reader, writer) = tokio::io::simplex(65536);
        let value = machine.machine.clone();
        let task = machine.context.tokio.spawn(async move {
            value
                .upload_file(
                    MachineFileUploadOptions {
                        path: q.path,
                        mode: q.mode,
                        uid: q.uid,
                        gid: q.gid,
                    },
                    reader,
                )
                .await
        });
        let abort = task.abort_handle();
        *out_upload = Box::into_raw(Box::new(UploadHandle {
            context: Arc::clone(&machine.context),
            state: Mutex::new(UploadState {
                writer: Some(writer),
                task: Some(task),
                abort,
                cancellation: watch::channel(false).0,
                finished: false,
                busy: false,
            }),
        }));
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_upload_write(
    upload: *const UploadHandle,
    data_ptr: *const u8,
    data_len: usize,
) -> *mut SiloError {
    catch_ffi(|| {
        let upload = upload
            .as_ref()
            .ok_or_else(|| invalid_argument("upload must not be null"))?;
        let bytes = request_bytes(data_ptr, data_len)?.to_vec();
        let (mut writer, mut cancellation) = {
            let mut state = upload
                .state
                .lock()
                .map_err(|_| closed("upload lock is poisoned"))?;
            if state.finished || state.busy || *state.cancellation.borrow() {
                return Err(closed("upload is closed or busy"));
            }
            let writer = state
                .writer
                .take()
                .ok_or_else(|| closed("upload is closed"))?;
            state.busy = true;
            (writer, state.cancellation.subscribe())
        };
        let result = upload.context.tokio.block_on(async { tokio::select! { biased; _ = cancellation.changed() => Err(closed("upload is cancelled")), result = writer.write_all(&bytes) => result.map_err(|e| SiloError::new("Io", e.to_string())) } });
        let task = {
            let mut state = upload
                .state
                .lock()
                .map_err(|_| closed("upload lock is poisoned"))?;
            state.busy = false;
            if result.is_ok() && !*state.cancellation.borrow() {
                state.writer = Some(writer);
                return Ok(());
            }
            state.finished = true;
            state.task.take()
        };
        if !*cancellation.borrow() {
            if let Some(task) = task {
                upload
                    .context
                    .tokio
                    .block_on(task)
                    .map_err(|e| closed(&e.to_string()))?
                    .map_err(error_from_libvm)?;
            }
        }
        result
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_upload_finish(
    upload: *const UploadHandle,
    out_result: *mut SiloBuffer,
) -> *mut SiloError {
    catch_ffi(|| {
        let upload = upload
            .as_ref()
            .ok_or_else(|| invalid_argument("upload must not be null"))?;
        if out_result.is_null() {
            return Err(invalid_argument("out_result must not be null"));
        }
        *out_result = SiloBuffer::empty();
        let (mut writer, task, mut cancellation) = {
            let mut state = upload
                .state
                .lock()
                .map_err(|_| closed("upload lock is poisoned"))?;
            if state.finished || state.busy || *state.cancellation.borrow() {
                return Err(closed("upload is closed or busy"));
            }
            let writer = state
                .writer
                .take()
                .ok_or_else(|| closed("upload is closed"))?;
            state.finished = true;
            (
                writer,
                state
                    .task
                    .take()
                    .ok_or_else(|| closed("upload is closed"))?,
                state.cancellation.subscribe(),
            )
        };
        let result = upload.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = cancellation.changed() => Err(closed("upload is cancelled")),
                result = async {
                    // Simplex halves share one stream: dropping the writer does not
                    // signal EOF, only shutdown does. A shutdown failure means the
                    // upload task already ended, and its result says why.
                    let _ = writer.shutdown().await;
                    drop(writer);
                    task.await
                } => result.map_err(|e| closed(&e.to_string()))?.map_err(error_from_libvm),
            }
        })?;
        *out_result = json_buffer(DispositionDto {
            disposition: match result {
                FileWriteDisposition::Created => "created",
                FileWriteDisposition::Replaced => "replaced",
            },
        })?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_upload_cancel(upload: *const UploadHandle) -> *mut SiloError {
    catch_ffi(|| {
        let upload = upload
            .as_ref()
            .ok_or_else(|| invalid_argument("upload must not be null"))?;
        let mut state = upload
            .state
            .lock()
            .map_err(|_| closed("upload lock is poisoned"))?;
        state.cancellation.send_replace(true);
        state.abort.abort();
        state.writer = None;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_upload_free(upload: *mut UploadHandle) {
    catch_ffi_void(|| {
        if !upload.is_null() {
            let upload = Box::from_raw(upload);
            if let Ok(state) = upload.state.lock() {
                state.abort.abort();
            };
        }
    });
}
#[no_mangle]
pub unsafe extern "C" fn silo_machine_download_open(
    machine: *const MachineHandle,
    request_ptr: *const u8,
    request_len: usize,
    out_download: *mut *mut DownloadHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        if out_download.is_null() {
            return Err(invalid_argument("out_download must not be null"));
        }
        *out_download = ptr::null_mut();
        let q: PathRequest = serde_json::from_slice(request_bytes(request_ptr, request_len)?)
            .map_err(|e| invalid_argument(e.to_string()))?;
        let reader = machine
            .context
            .tokio
            .block_on(machine.machine.download_file(q.path))
            .map_err(error_from_libvm)?;
        *out_download = Box::into_raw(Box::new(DownloadHandle {
            context: Arc::clone(&machine.context),
            state: Mutex::new(DownloadState {
                reader: Some(reader),
                cancellation: watch::channel(false).0,
                eof: false,
                busy: false,
            }),
        }));
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_download_read(
    download: *const DownloadHandle,
    out_chunk: *mut SiloBuffer,
    out_eof: *mut bool,
) -> *mut SiloError {
    catch_ffi(|| {
        let download = download
            .as_ref()
            .ok_or_else(|| invalid_argument("download must not be null"))?;
        if out_chunk.is_null() || out_eof.is_null() {
            return Err(invalid_argument("download outputs must not be null"));
        }
        *out_chunk = SiloBuffer::empty();
        *out_eof = false;
        let (mut reader, mut cancellation) = {
            let mut state = download
                .state
                .lock()
                .map_err(|_| closed("download lock is poisoned"))?;
            if *state.cancellation.borrow() || state.busy {
                return Err(closed("download is closed or busy"));
            }
            if state.eof {
                *out_eof = true;
                return Ok(());
            }
            let reader = state
                .reader
                .take()
                .ok_or_else(|| closed("download is closed"))?;
            state.busy = true;
            (reader, state.cancellation.subscribe())
        };
        let mut bytes = Vec::with_capacity(65536);
        let result = download.context.tokio.block_on(async { tokio::select! { biased; _ = cancellation.changed() => Err(closed("download is cancelled")), result = reader.read_buf(&mut bytes) => result.map_err(|e| SiloError::new("Io", e.to_string())) } });
        let mut state = download
            .state
            .lock()
            .map_err(|_| closed("download lock is poisoned"))?;
        state.busy = false;
        let count = result?;
        state.eof = count == 0;
        if !state.eof && !*state.cancellation.borrow() {
            state.reader = Some(reader);
        }
        *out_eof = state.eof;
        *out_chunk = SiloBuffer::from_vec(bytes);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_download_cancel(download: *const DownloadHandle) -> *mut SiloError {
    catch_ffi(|| {
        let download = download
            .as_ref()
            .ok_or_else(|| invalid_argument("download must not be null"))?;
        let mut state = download
            .state
            .lock()
            .map_err(|_| closed("download lock is poisoned"))?;
        state.cancellation.send_replace(true);
        state.reader = None;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_download_free(download: *mut DownloadHandle) {
    catch_ffi_void(|| {
        if !download.is_null() {
            drop(Box::from_raw(download));
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::files::{kind_name, DirectoryRequest, PathRequest, UploadRequest};
    use libvm::MachineEntryKind;
    #[test]
    fn strict_requests() {
        assert!(serde_json::from_str::<PathRequest>(r#"{"path":"/x","extra":true}"#).is_err());
        assert!(serde_json::from_str::<DirectoryRequest>(r#"{"path":"/x","extra":true}"#).is_err());
        assert!(serde_json::from_str::<UploadRequest>(r#"{"path":"/x","extra":true}"#).is_err());
        assert!(
            !serde_json::from_str::<DirectoryRequest>(r#"{"path":"/x"}"#)
                .unwrap()
                .parents
        );
    }
    #[test]
    fn entry_kinds() {
        for (kind, name) in [
            (MachineEntryKind::File, "file"),
            (MachineEntryKind::Directory, "directory"),
            (MachineEntryKind::Symlink, "symlink"),
            (MachineEntryKind::Fifo, "fifo"),
            (MachineEntryKind::Socket, "socket"),
            (MachineEntryKind::BlockDevice, "block_device"),
            (MachineEntryKind::CharacterDevice, "character_device"),
        ] {
            assert_eq!(kind_name(kind), name);
        }
    }
}

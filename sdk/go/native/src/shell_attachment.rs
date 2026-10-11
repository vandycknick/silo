use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use libvm::{SshShellAttachment, SshShellControl, SshShellSignal};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::SiloBuffer;
use crate::error::{catch_ffi, catch_ffi_void, invalid_argument, SiloError};
use crate::exec::AttachmentCancellation;
use crate::handles::{MachineHandle, RuntimeContext};
use crate::runtime::request_bytes;

type Reader = ReadHalf<SimplexStream>;
type Writer = WriteHalf<SimplexStream>;

// The shared output writer lets completion explicitly shut down each simplex
// writer after libvm drops the attachment. Poll methods never retain a lock.
#[derive(Clone)]
struct OutputWriter(Arc<Mutex<Writer>>);
impl AsyncWrite for OutputWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.0.lock() {
            Ok(mut writer) => Pin::new(&mut *writer).poll_write(cx, data),
            Err(_) => Poll::Ready(Err(std::io::Error::other("SSH output lock poisoned"))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.0.lock() {
            Ok(mut writer) => Pin::new(&mut *writer).poll_flush(cx),
            Err(_) => Poll::Ready(Err(std::io::Error::other("SSH output lock poisoned"))),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.0.lock() {
            Ok(mut writer) => Pin::new(&mut *writer).poll_shutdown(cx),
            Err(_) => Poll::Ready(Err(std::io::Error::other("SSH output lock poisoned"))),
        }
    }
}

struct Direction<T> {
    io: Option<T>,
    closed: bool,
}
impl<T> Direction<T> {
    fn take(&mut self) -> Result<T, *mut SiloError> {
        if self.closed {
            return Err(closed("SSH attachment direction is closed"));
        }
        self.io
            .take()
            .ok_or_else(|| invalid_argument("SSH attachment direction is busy"))
    }
}

/// Opaque, single-consumption bounded SSH attachment. The caller must join the
/// shell and all byte/control operations before free; no Go pointers are kept.
pub struct SshAttachmentHandle {
    context: Arc<RuntimeContext>,
    token_identity: usize,
    cancellation: CancellationToken,
    input_complete: CancellationToken,
    attachment: Mutex<Option<SshShellAttachment>>,
    stdin: Mutex<Direction<Writer>>,
    stdout: Mutex<Direction<Reader>>,
    stderr: Mutex<Direction<Reader>>,
    outputs: [OutputWriter; 2],
    controls: mpsc::Sender<SshShellControl>,
}
fn closed(message: &str) -> *mut SiloError {
    SiloError::new("Closed", message)
}
fn cancelled() -> *mut SiloError {
    SiloError::new("Cancelled", "SSH attachment cancelled")
}
fn io_error(error: std::io::Error) -> *mut SiloError {
    SiloError::new("Io", error.to_string())
}

impl SshAttachmentHandle {
    pub(crate) fn take_attachment(
        &self,
        token: Option<&AttachmentCancellation>,
    ) -> Result<SshShellAttachment, *mut SiloError> {
        if token.map(|t| t as *const _ as usize) != Some(self.token_identity) {
            return Err(invalid_argument(
                "SSH attachment cancellation token does not match",
            ));
        }
        self.attachment
            .lock()
            .map_err(|_| closed("SSH attachment lock poisoned"))?
            .take()
            .ok_or_else(|| invalid_argument("SSH attachment already consumed"))
    }
    pub(crate) async fn finish(&self, success: bool) {
        self.input_complete.cancel();
        if !success {
            self.cancellation.cancel();
        }
        // Shutdown is required: dropping a simplex writer does not publish EOF.
        for mut writer in self.outputs.clone() {
            if writer.shutdown().await.is_err() {
                self.cancellation.cancel();
            }
        }
    }
    fn control(&self, control: SshShellControl) -> Result<(), *mut SiloError> {
        self.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => Err(cancelled()),
                _ = self.input_complete.cancelled() => Err(closed("SSH shell completed")),
                result = self.controls.send(control) => result.map_err(|_| closed("SSH controls closed")),
            }
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_new(
    machine: *const MachineHandle,
    token: *const AttachmentCancellation,
    rows: u16,
    columns: u16,
    out_handle: *mut *mut SshAttachmentHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        if out_handle.is_null() {
            return Err(invalid_argument("out_handle must not be null"));
        }
        *out_handle = std::ptr::null_mut();
        let machine = machine
            .as_ref()
            .ok_or_else(|| invalid_argument("machine must not be null"))?;
        let cancellation = token
            .as_ref()
            .ok_or_else(|| invalid_argument("token must not be null"))?;
        if rows == 0 || columns == 0 {
            return Err(invalid_argument("SSH rows and columns must be positive"));
        }
        let (input, stdin) = tokio::io::simplex(65536);
        let (stdout, output) = tokio::io::simplex(65536);
        let (stderr, error) = tokio::io::simplex(65536);
        let outputs = [
            OutputWriter(Arc::new(Mutex::new(output))),
            OutputWriter(Arc::new(Mutex::new(error))),
        ];
        let (controls, receiver) = mpsc::channel(64);
        let attachment =
            SshShellAttachment::new(input, outputs[0].clone(), outputs[1].clone(), rows, columns)
                .controls(receiver);
        *out_handle = Box::into_raw(Box::new(SshAttachmentHandle {
            context: Arc::clone(&machine.context),
            token_identity: token as usize,
            cancellation: cancellation.cancellation.clone(),
            input_complete: CancellationToken::new(),
            attachment: Mutex::new(Some(attachment)),
            stdin: Mutex::new(Direction {
                io: Some(stdin),
                closed: false,
            }),
            stdout: Mutex::new(Direction {
                io: Some(stdout),
                closed: false,
            }),
            stderr: Mutex::new(Direction {
                io: Some(stderr),
                closed: false,
            }),
            outputs,
            controls,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_write(
    handle: *const SshAttachmentHandle,
    data_ptr: *const u8,
    data_len: usize,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        if data_len > 65536 {
            return Err(invalid_argument("SSH write exceeds 64 KiB"));
        }
        let data = request_bytes(data_ptr, data_len)?;
        let mut writer = h
            .stdin
            .lock()
            .map_err(|_| closed("SSH input lock poisoned"))?
            .take()?;
        let result = h.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = h.cancellation.cancelled() => Err(cancelled()),
                _ = h.input_complete.cancelled() => Err(closed("SSH shell completed")),
                result = writer.write_all(data) => result.map_err(io_error),
            }
        });
        h.stdin
            .lock()
            .map_err(|_| closed("SSH input lock poisoned"))?
            .io = Some(writer);
        result
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_close_stdin(
    handle: *const SshAttachmentHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        let mut writer = h
            .stdin
            .lock()
            .map_err(|_| closed("SSH input lock poisoned"))?
            .take()?;
        let result = h.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = h.cancellation.cancelled() => Err(cancelled()),
                _ = h.input_complete.cancelled() => Err(closed("SSH shell completed")),
                result = writer.shutdown() => result.map_err(io_error),
            }
        });
        let mut state = h
            .stdin
            .lock()
            .map_err(|_| closed("SSH input lock poisoned"))?;
        state.closed = true;
        state.io = Some(writer);
        result
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_read(
    handle: *const SshAttachmentHandle,
    stderr: bool,
    out_buffer: *mut SiloBuffer,
    out_eof: *mut bool,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        if out_buffer.is_null() || out_eof.is_null() {
            return Err(invalid_argument("read outputs must not be null"));
        }
        *out_buffer = SiloBuffer::empty();
        *out_eof = false;
        let direction = if stderr { &h.stderr } else { &h.stdout };
        let mut reader = {
            let mut state = direction
                .lock()
                .map_err(|_| closed("SSH output lock poisoned"))?;
            if state.closed {
                *out_eof = true;
                return Ok(());
            }
            state.take()?
        };
        let mut bytes = vec![0; 65536];
        let result = h.context.tokio.block_on(async {
            tokio::select! {
                biased;
                _ = h.cancellation.cancelled() => Err(cancelled()),
                result = reader.read(&mut bytes) => result.map_err(io_error),
            }
        });
        let mut state = direction
            .lock()
            .map_err(|_| closed("SSH output lock poisoned"))?;
        state.io = Some(reader);
        let length = result?;
        state.closed = length == 0;
        *out_eof = state.closed;
        bytes.truncate(length);
        *out_buffer = SiloBuffer::from_vec(bytes);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_resize(
    handle: *const SshAttachmentHandle,
    rows: u16,
    columns: u16,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        if rows == 0 || columns == 0 {
            return Err(invalid_argument("SSH rows and columns must be positive"));
        }
        h.control(SshShellControl::Resize { rows, columns })
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_signal(
    handle: *const SshAttachmentHandle,
    linux_signal: u32,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        let signal = SshShellSignal::from_linux(linux_signal)
            .ok_or_else(|| invalid_argument("unsupported SSH signal"))?;
        h.control(SshShellControl::Signal(signal))
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_cancel(
    handle: *const SshAttachmentHandle,
) -> *mut SiloError {
    catch_ffi(|| {
        let h = handle
            .as_ref()
            .ok_or_else(|| invalid_argument("handle must not be null"))?;
        h.cancellation.cancel();
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn silo_ssh_attachment_free(handle: *mut SshAttachmentHandle) {
    catch_ffi_void(|| {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_output_shutdown_preserves_all_buffered_bytes() {
        let (mut reader, writer) = tokio::io::simplex(65536);
        let mut writer = OutputWriter(Arc::new(Mutex::new(writer)));
        let expected: Vec<u8> = (0..196619).map(|n| (n % 251) as u8).collect();
        let send = async {
            writer.write_all(&expected).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).await.unwrap();
            actual
        };
        let ((), actual) = tokio::join!(send, receive);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn stalled_output_poll_releases_lock_and_cancellation_wakes_it() {
        let (_reader, writer) = tokio::io::simplex(65536);
        let mut writer = OutputWriter(Arc::new(Mutex::new(writer)));
        writer.write_all(&vec![7; 65536]).await.unwrap();
        let cancellation = CancellationToken::new();
        let blocked = async {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => (),
                result = writer.write_all(&[8]) => panic!("full pipe write completed: {result:?}"),
            }
        };
        let cancel = async {
            tokio::task::yield_now().await;
            cancellation.cancel();
        };
        tokio::join!(blocked, cancel);
        // Completion/free can acquire the writer lock after a pending poll.
        assert!(writer.0.try_lock().is_ok());
        writer.shutdown().await.unwrap();
    }
}

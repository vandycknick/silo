use crate::{
    apply_ssh_shell_options, invalid_arg, invalid_state, to_napi_error, NativeSshExitStatus,
    NativeSshShellOptionsInput,
};
use libvm::{Machine, SshShellAttachment, SshShellControl, SshShellSignal};
use napi::{
    bindgen_prelude::{Buffer, Uint8Array},
    Error, Result, Status,
};
use napi_derive::napi;
use parking_lot::Mutex;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, SimplexStream, WriteHalf},
    sync::{mpsc, watch, Mutex as AsyncMutex},
};
use tokio_util::sync::CancellationToken;

type Reader = ReadHalf<SimplexStream>;
type Writer = WriteHalf<SimplexStream>;
#[derive(Clone)]
struct Output(Arc<Mutex<Writer>>);
impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.0.lock()).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_shutdown(cx)
    }
}
#[napi(object)]
pub struct NativeShellSize {
    pub rows: u16,
    pub columns: u16,
}
#[napi]
pub struct NativeShellOperation {
    _machine: Machine,
    cancel: CancellationToken,
    input_done: CancellationToken,
    stdin_closed: AtomicBool,
    stdin: Option<AsyncMutex<Writer>>,
    stdout: Option<AsyncMutex<Reader>>,
    stderr: Option<AsyncMutex<Reader>>,
    controls: Option<mpsc::Sender<SshShellControl>>,
    outcome: watch::Receiver<Option<std::result::Result<i32, (Status, String)>>>,
    task: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Drop for NativeShellOperation {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl NativeShellOperation {
    pub fn start(
        machine: Machine,
        options: Option<NativeSshShellOptionsInput>,
        size: Option<NativeShellSize>,
    ) -> Result<Self> {
        if let Some(size) = &size {
            if size.rows == 0 || size.columns == 0 {
                return Err(invalid_arg("shell dimensions must be positive"));
            }
            if options
                .as_ref()
                .and_then(|o| o.detach_keys.as_ref())
                .is_some()
            {
                return Err(invalid_arg("detachKeys requires local I/O"));
            }
        }
        let cancel = CancellationToken::new();
        let input_done = CancellationToken::new();
        let (publish, outcome) = watch::channel(None);
        let mut attachment = None;
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut controls = None;
        let mut outputs = None;
        if let Some(size) = size {
            let (input, writer) = tokio::io::simplex(65536);
            let (out, out_writer) = tokio::io::simplex(65536);
            let (err, err_writer) = tokio::io::simplex(65536);
            let out_writer = Output(Arc::new(Mutex::new(out_writer)));
            let err_writer = Output(Arc::new(Mutex::new(err_writer)));
            let (tx, rx) = mpsc::channel(64);
            attachment = Some(
                SshShellAttachment::new(
                    input,
                    out_writer.clone(),
                    err_writer.clone(),
                    size.rows,
                    size.columns,
                )
                .controls(rx),
            );
            stdin = Some(AsyncMutex::new(writer));
            stdout = Some(AsyncMutex::new(out));
            stderr = Some(AsyncMutex::new(err));
            controls = Some(tx);
            outputs = Some((out_writer, err_writer));
        }
        let task_cancel = cancel.clone();
        let task_input_done = input_done.clone();
        let retained_machine = machine.clone();
        let task = napi::bindgen_prelude::spawn(async move {
            let mut result = machine
                .shell_with(|builder| {
                    let builder =
                        apply_ssh_shell_options(builder, options).cancellation(task_cancel.clone());
                    match attachment {
                        Some(attachment) => builder.attachment(attachment),
                        None => builder,
                    }
                })
                .await
                .map(|status| status.code)
                .map_err(to_napi_error);
            if let Some((mut out, mut err)) = outputs {
                // Simplex shutdown publishes EOF without dropping buffered bytes.
                let stdout_shutdown = out.shutdown().await;
                let stderr_shutdown = err.shutdown().await;
                if result.is_ok() {
                    if let Err(error) = stdout_shutdown.and(stderr_shutdown) {
                        result = Err(invalid_state(format!("shell output shutdown: {error}")));
                    }
                }
            }
            let failed = result.is_err();
            publish.send_replace(Some(result.map_err(|error| (error.status, error.reason))));
            if failed {
                task_cancel.cancel();
            }
            task_input_done.cancel();
        });
        Ok(Self {
            _machine: retained_machine,
            cancel,
            input_done,
            stdin_closed: AtomicBool::new(false),
            stdin,
            stdout,
            stderr,
            controls,
            outcome,
            task: AsyncMutex::new(Some(task)),
        })
    }
    async fn read(&self, stderr: bool) -> Result<Option<Buffer>> {
        let source = if stderr { &self.stderr } else { &self.stdout };
        let source = source
            .as_ref()
            .ok_or_else(|| invalid_arg("byte I/O requires an attachment"))?;
        let mut reader = source
            .try_lock()
            .map_err(|_| invalid_arg("shell read already active"))?;
        let mut bytes = vec![0; 65536];
        let count = tokio::select! { biased; _ = self.cancel.cancelled() => return Err(self.cancellation_error()), result = reader.read(&mut bytes) => result.map_err(|e| invalid_state(e.to_string()))? };
        if count == 0 {
            return Ok(None);
        }
        bytes.truncate(count);
        Ok(Some(bytes.into()))
    }
}
#[napi]
impl NativeShellOperation {
    #[napi(js_name = "writeStdin")]
    pub async fn write_stdin(&self, data: Uint8Array) -> Result<()> {
        if data.len() > 65536 {
            return Err(invalid_arg("shell input chunk exceeds 64 KiB"));
        }
        let data = data.to_vec();
        let mut writer = self
            .stdin
            .as_ref()
            .ok_or_else(|| invalid_arg("byte I/O requires an attachment"))?
            .try_lock()
            .map_err(|_| invalid_arg("shell write already active"))?;
        if self.stdin_closed.load(Ordering::Acquire) {
            return Err(invalid_state("shell stdin closed"));
        }
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(self.cancellation_error()),
            _ = self.input_done.cancelled() => Err(invalid_state("shell input closed")),
            result = writer.write_all(&data) => result.map_err(|error| {
                if error.kind() == std::io::ErrorKind::BrokenPipe {
                    invalid_state("shell input closed")
                } else {
                    invalid_state(error.to_string())
                }
            }),
        }
    }
    #[napi(js_name = "closeStdin")]
    pub async fn close_stdin(&self) -> Result<()> {
        let mut writer = self
            .stdin
            .as_ref()
            .ok_or_else(|| invalid_arg("byte I/O requires an attachment"))?
            .try_lock()
            .map_err(|_| invalid_arg("shell write already active"))?;
        if self.stdin_closed.swap(true, Ordering::AcqRel) {
            return Err(invalid_state("shell stdin closed"));
        }
        tokio::select! { biased; _ = self.cancel.cancelled() => Err(self.cancellation_error()), result = writer.shutdown() => result.map_err(|e| invalid_state(e.to_string())) }
    }
    #[napi(js_name = "readStdout")]
    pub async fn read_stdout(&self) -> Result<Option<Buffer>> {
        self.read(false).await
    }
    #[napi(js_name = "readStderr")]
    pub async fn read_stderr(&self) -> Result<Option<Buffer>> {
        self.read(true).await
    }
    #[napi]
    pub async fn resize(&self, rows: u16, columns: u16) -> Result<()> {
        if rows == 0 || columns == 0 {
            return Err(invalid_arg("shell dimensions must be positive"));
        }
        self.send(SshShellControl::Resize { rows, columns }).await
    }
    #[napi]
    pub async fn signal(&self, signal: String) -> Result<()> {
        let signal = match signal.as_str() {
            "HUP" => SshShellSignal::Hup,
            "INT" => SshShellSignal::Int,
            "QUIT" => SshShellSignal::Quit,
            "ILL" => SshShellSignal::Ill,
            "ABRT" => SshShellSignal::Abrt,
            "FPE" => SshShellSignal::Fpe,
            "KILL" => SshShellSignal::Kill,
            "USR1" => SshShellSignal::Usr1,
            "SEGV" => SshShellSignal::Segv,
            "USR2" => SshShellSignal::Usr2,
            "PIPE" => SshShellSignal::Pipe,
            "ALRM" => SshShellSignal::Alrm,
            "TERM" => SshShellSignal::Term,
            _ => return Err(invalid_arg("unsupported SSH signal")),
        };
        self.send(SshShellControl::Signal(signal)).await
    }
    #[napi]
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    #[napi]
    pub async fn result(&self) -> Result<NativeSshExitStatus> {
        let mut result = self.outcome.clone();
        loop {
            if let Some(outcome) = result.borrow().clone() {
                return outcome
                    .map(|code| NativeSshExitStatus {
                        code,
                        success: code == 0,
                    })
                    .map_err(|(status, reason)| Error::new(status, reason));
            }
            result
                .changed()
                .await
                .map_err(|_| invalid_arg("shell task closed without result"))?;
        }
    }
    #[napi]
    pub async fn close(&self) -> Result<()> {
        self.cancel.cancel();
        if let Some(task) = self.task.lock().await.take() {
            task.await.map_err(|e| invalid_arg(e.to_string()))?;
        }
        // Cancellation wakes pending byte calls before their buffers are released.
        if let Some(input) = &self.stdin {
            drop(input.lock().await);
        }
        if let Some(output) = &self.stdout {
            drop(output.lock().await);
        }
        if let Some(error) = &self.stderr {
            drop(error.lock().await);
        }
        Ok(())
    }
}
impl NativeShellOperation {
    fn cancellation_error(&self) -> Error {
        match self.outcome.borrow().as_ref() {
            Some(Err((status, reason))) => Error::new(*status, reason.clone()),
            _ => invalid_state("shell canceled"),
        }
    }
    async fn send(&self, control: SshShellControl) -> Result<()> {
        let controls = self
            .controls
            .as_ref()
            .ok_or_else(|| invalid_arg("controls require an attachment"))?;
        tokio::select! { biased; _ = self.cancel.cancelled() => Err(self.cancellation_error()), _ = self.input_done.cancelled() => Err(invalid_state("shell controls closed")), result = controls.send(control) => result.map_err(|_| invalid_state("shell controls closed")) }
    }
}

//! Serial console: pumps the backend serial device into log sinks and live
//! client streams.
//!
//! One console exists per machine. On first attach (machine start or first
//! stream open) it opens the backend serial device exactly once, splits it,
//! and spawns a single reader task that fans guest output out to every
//! registered sink and to a broadcast channel for live streams. At most one
//! `Interactive` stream may exist at a time and only it may write guest
//! input; `Watch` streams are unlimited and their writes are ignored.

use std::io;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::{broadcast, Mutex};

use super::backend::VirtBackend;
use super::error::VirtError;
use super::stream::SerialDevice;

/// Access level of a serial client stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAccess {
    /// Exclusive read/write client; only one may be attached at a time.
    Interactive,
    /// Read-only observer; input writes are silently ignored.
    Watch,
}

#[derive(Debug)]
struct SerialHub {
    next_id: u64,
    interactive_owner: Option<u64>,
}

impl SerialHub {
    fn new() -> Self {
        Self {
            next_id: 1,
            interactive_owner: None,
        }
    }

    fn attach(&mut self, access: SerialAccess) -> Result<u64, VirtError> {
        if access == SerialAccess::Interactive && self.interactive_owner.is_some() {
            return Err(VirtError::Backend(
                "interactive serial client is already attached".to_string(),
            ));
        }

        let id = self.next_id;
        self.next_id += 1;

        if access == SerialAccess::Interactive {
            self.interactive_owner = Some(id);
        }

        Ok(id)
    }

    fn detach(&mut self, id: u64) {
        if self.interactive_owner == Some(id) {
            self.interactive_owner = None;
        }
    }

    fn can_write_input(&self, id: u64) -> bool {
        self.interactive_owner == Some(id)
    }
}

#[derive(Debug)]
struct SerialAttachment {
    guest_input: WriteHalf<SerialDevice>,
    reader_task: tokio::task::JoinHandle<Result<(), VirtError>>,
}

struct SerialSink {
    writer: Pin<Box<dyn AsyncWrite + Send>>,
}

impl std::fmt::Debug for SerialSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerialSink").finish_non_exhaustive()
    }
}

impl SerialSink {
    fn new<W>(writer: W) -> Self
    where
        W: AsyncWrite + Send + 'static,
    {
        Self {
            writer: Box::pin(writer),
        }
    }
}

/// Fan-out hub for a machine's serial device. Obtain via
/// [`super::VirtualMachine::serial`].
#[derive(Debug)]
pub struct SerialConsole {
    backend: Arc<dyn VirtBackend>,
    hub: Arc<Mutex<SerialHub>>,
    attachment: Arc<Mutex<Option<SerialAttachment>>>,
    sinks: Arc<Mutex<Vec<SerialSink>>>,
    output_tx: broadcast::Sender<Vec<u8>>,
    attach_lock: Arc<Mutex<()>>,
}

impl SerialConsole {
    pub(crate) fn new(backend: Arc<dyn VirtBackend>) -> Self {
        let (output_tx, _) = broadcast::channel(256);
        Self {
            backend,
            hub: Arc::new(Mutex::new(SerialHub::new())),
            attachment: Arc::new(Mutex::new(None)),
            sinks: Arc::new(Mutex::new(Vec::new())),
            output_tx,
            attach_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Register a writer that receives all guest serial output (e.g. a log
    /// file). Failing sinks are dropped; others keep receiving. Sinks stay
    /// registered across machine restarts.
    pub async fn add_sink<W>(&self, sink: W)
    where
        W: AsyncWrite + Send + 'static,
    {
        self.sinks.lock().await.push(SerialSink::new(sink));
        tracing::info!("serial output sink attached");
    }

    /// Open the backend serial device and start pumping output. Idempotent;
    /// called by machine start and lazily by `open_stream`.
    pub(crate) async fn attach(&self) -> Result<(), VirtError> {
        if self.attachment.lock().await.is_some() {
            return Ok(());
        }

        let _guard = self.attach_lock.lock().await;
        if self.attachment.lock().await.is_some() {
            return Ok(());
        }

        let device = self.backend.open_serial().await?;
        tracing::info!("serial backend stream opened");
        let (guest_output, guest_input) = tokio::io::split(device);
        let output_tx = self.output_tx.clone();
        let sinks = self.sinks.clone();
        let reader_task =
            tokio::spawn(async move { run_serial_reader(guest_output, sinks, output_tx).await });

        *self.attachment.lock().await = Some(SerialAttachment {
            guest_input,
            reader_task,
        });
        Ok(())
    }

    /// Open a live client stream over the serial console.
    pub async fn open_stream(
        self: &Arc<Self>,
        access: SerialAccess,
    ) -> Result<SerialStream, VirtError> {
        self.attach().await?;

        let client_id = {
            let mut hub = self.hub.lock().await;
            hub.attach(access)?
        };
        tracing::info!(client_id, access = ?access, "serial client attached");

        Ok(SerialStream {
            console: self.clone(),
            client_id,
            access,
            output_rx: self.output_tx.subscribe(),
        })
    }

    async fn write_input(&self, client_id: u64, chunk: &[u8]) -> io::Result<()> {
        let is_owner = self.hub.lock().await.can_write_input(client_id);
        if !is_owner {
            return Ok(());
        }

        let mut attachment = self.attachment.lock().await;
        let Some(attachment) = attachment.as_mut() else {
            return Err(io::Error::other("serial console is not attached"));
        };

        tracing::debug!(
            client_id,
            bytes = chunk.len(),
            "serial input forwarded to guest"
        );
        attachment.guest_input.write_all(chunk).await?;
        attachment.guest_input.flush().await
    }

    async fn detach_client(&self, client_id: u64) {
        self.hub.lock().await.detach(client_id);
    }

    /// Detach from the device and wait for the reader task to flush the final
    /// output to all sinks. Idempotent; called on machine stop.
    pub async fn drain(&self) -> Result<(), VirtError> {
        let Some(mut attachment) = self.attachment.lock().await.take() else {
            return Ok(());
        };
        attachment
            .guest_input
            .shutdown()
            .await
            .map_err(VirtError::from)?;
        attachment
            .reader_task
            .await
            .map_err(|error| VirtError::Backend(format!("serial reader task failed: {error}")))?
    }
}

impl Drop for SerialConsole {
    fn drop(&mut self) {
        if let Ok(mut attachment) = self.attachment.try_lock() {
            if let Some(attachment) = attachment.take() {
                attachment.reader_task.abort();
            }
        }
    }
}

/// A live client stream over the serial console.
#[derive(Debug)]
pub struct SerialStream {
    console: Arc<SerialConsole>,
    client_id: u64,
    access: SerialAccess,
    output_rx: broadcast::Receiver<Vec<u8>>,
}

impl SerialStream {
    /// Read the next output chunk; `None` once the console shuts down.
    /// Lagged consumers are disconnected rather than silently losing output.
    pub async fn read_output(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.output_rx.recv().await {
            Ok(chunk) => Ok(Some(chunk)),
            Err(broadcast::error::RecvError::Closed) => Ok(None),
            Err(broadcast::error::RecvError::Lagged(skipped)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("serial consumer lagged by {skipped} chunks"),
            )),
        }
    }

    /// Write interactive input to the guest. Watch-only streams ignore input.
    pub async fn write_input(&self, chunk: &[u8]) -> io::Result<()> {
        match self.access {
            SerialAccess::Interactive => self.console.write_input(self.client_id, chunk).await,
            SerialAccess::Watch => Ok(()),
        }
    }
}

impl Drop for SerialStream {
    fn drop(&mut self) {
        let console = self.console.clone();
        let client_id = self.client_id;
        tokio::spawn(async move {
            console.detach_client(client_id).await;
        });
    }
}

async fn run_serial_reader<R>(
    mut guest_output: R,
    sinks: Arc<Mutex<Vec<SerialSink>>>,
    output_tx: broadcast::Sender<Vec<u8>>,
) -> Result<(), VirtError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut saw_output = false;
    tracing::info!("serial reader started");

    loop {
        let n = match guest_output.read(&mut buf).await {
            Ok(0) => {
                tracing::warn!(saw_output, "serial reader reached EOF");
                break;
            }
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                tracing::error!(error = %err, "serial read failed");
                return Err(err.into());
            }
        };

        if !saw_output {
            tracing::info!(bytes = n, "serial reader received first output");
            saw_output = true;
        } else {
            tracing::debug!(bytes = n, "serial reader received output");
        }

        let chunk = buf[..n].to_vec();

        {
            let mut sinks = sinks.lock().await;
            let sink_count = sinks.len();
            if sink_count == 0 {
                tracing::debug!(bytes = chunk.len(), "serial output has no sinks");
            }
            let mut index = 0;
            while index < sinks.len() {
                let sink = &mut sinks[index];
                let write_result = async {
                    sink.writer.as_mut().write_all(&chunk).await?;
                    sink.writer.as_mut().flush().await
                }
                .await;
                match write_result {
                    Ok(()) => {
                        tracing::debug!(
                            bytes = chunk.len(),
                            sink_index = index,
                            sink_count,
                            "serial sink wrote output"
                        );
                        index += 1;
                    }
                    Err(error) => {
                        tracing::error!(%error, sink_index = index, "serial sink write failed");
                        sinks.remove(index);
                    }
                }
            }
        }

        let _ = output_tx.send(chunk);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    use super::{run_serial_reader, SerialSink};

    fn temporary_file(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vmmon-serial-{name}-{}-{timestamp}",
            std::process::id()
        ))
    }

    async fn run_reader(sinks: Arc<Mutex<Vec<SerialSink>>>, output: &[u8]) {
        let (reader, mut writer) = tokio::io::duplex(1024);
        let (output_tx, _) = tokio::sync::broadcast::channel(1);
        let drain = tokio::spawn(run_serial_reader(reader, sinks, output_tx));

        writer.write_all(output).await.expect("write serial output");
        writer.shutdown().await.expect("close serial producer");
        drain
            .await
            .expect("serial reader joins")
            .expect("serial reader drains");
    }

    #[tokio::test]
    async fn serial_reader_fans_out_and_drains_final_output() {
        let first_path = temporary_file("fan-out-first");
        let second_path = temporary_file("fan-out-second");
        let sinks = Arc::new(Mutex::new(vec![
            SerialSink::new(tokio::fs::File::from_std(
                fs::File::create(&first_path).expect("create first serial sink"),
            )),
            SerialSink::new(tokio::fs::File::from_std(
                fs::File::create(&second_path).expect("create second serial sink"),
            )),
        ]));

        run_reader(sinks, b"final serial output").await;

        assert_eq!(
            fs::read(&first_path).expect("read first serial sink"),
            b"final serial output"
        );
        assert_eq!(
            fs::read(&second_path).expect("read second serial sink"),
            b"final serial output"
        );
        fs::remove_file(first_path).expect("remove first serial sink");
        fs::remove_file(second_path).expect("remove second serial sink");
    }

    #[tokio::test]
    async fn failed_sink_does_not_interrupt_other_sinks() {
        let path = temporary_file("failure-isolation");
        let (failed_sink, failed_reader) = tokio::io::duplex(16);
        drop(failed_reader);
        let sinks = Arc::new(Mutex::new(vec![
            SerialSink::new(failed_sink),
            SerialSink::new(tokio::fs::File::from_std(
                fs::File::create(&path).expect("create surviving serial sink"),
            )),
        ]));

        run_reader(sinks.clone(), b"serial output survives").await;

        assert_eq!(sinks.lock().await.len(), 1);
        assert_eq!(
            fs::read(&path).expect("read surviving serial sink"),
            b"serial output survives"
        );
        fs::remove_file(path).expect("remove surviving serial sink");
    }

    #[tokio::test]
    async fn sinks_remain_registered_across_reader_sessions() {
        let path = temporary_file("reattach");
        let sinks = Arc::new(Mutex::new(vec![SerialSink::new(
            tokio::fs::File::from_std(
                fs::File::create(&path).expect("create reusable serial sink"),
            ),
        )]));

        run_reader(sinks.clone(), b"first session\n").await;
        run_reader(sinks, b"second session\n").await;

        assert_eq!(
            fs::read(&path).expect("read reusable serial sink"),
            b"first session\nsecond session\n"
        );
        fs::remove_file(path).expect("remove reusable serial sink");
    }
}

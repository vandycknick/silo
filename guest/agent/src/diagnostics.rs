//! Owned synchronous tracing sink, closed before final filesystem synchronization.
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) struct Diagnostics<W = io::Stdout> {
    state: Arc<Mutex<State<W>>>,
}

struct State<W> {
    output: W,
    closed: bool,
}

impl<W> Clone for Diagnostics<W> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<W: Write> Diagnostics<W> {
    pub(crate) fn new(output: W) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                output,
                closed: false,
            })),
        }
    }

    /// Serialize with the entire current tracing event, flush its actual sink,
    /// and permanently close admission before the final storage sync begins.
    pub(crate) fn close(&self) -> io::Result<()> {
        let mut state = lock(&self.state);
        if state.closed {
            return Ok(());
        }
        state.closed = true;
        state.output.flush()
    }
}

pub(crate) struct DiagnosticWriter<'a, W> {
    state: MutexGuard<'a, State<W>>,
}

impl<'a, W: Write + 'a> tracing_subscriber::fmt::MakeWriter<'a> for Diagnostics<W> {
    type Writer = DiagnosticWriter<'a, W>;
    fn make_writer(&'a self) -> Self::Writer {
        DiagnosticWriter {
            state: lock(&self.state),
        }
    }
}

impl<W: Write> Write for DiagnosticWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.state.closed {
            return Ok(bytes.len());
        }
        self.state.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.state.closed {
            return Ok(());
        }
        self.state.output.flush()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use tracing_subscriber::fmt::MakeWriter;

    #[test]
    fn diagnostic_close_drains_actual_file_and_prevents_later_persistent_logs() {
        let mut file = tempfile::tempfile().unwrap();
        let diagnostics = crate::diagnostics::Diagnostics::new(file.try_clone().unwrap());
        diagnostics
            .make_writer()
            .write_all(b"before storage completion")
            .unwrap();
        diagnostics.close().unwrap();
        diagnostics
            .make_writer()
            .write_all(b"must not reach persistent storage")
            .unwrap();
        diagnostics.close().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"before storage completion");
    }

    #[test]
    fn diagnostic_close_waits_for_actual_inflight_event_owner() {
        let file = tempfile::tempfile().unwrap();
        let diagnostics = crate::diagnostics::Diagnostics::new(file);
        let mut event = diagnostics.make_writer();
        let (closed, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn({
            let diagnostics = diagnostics.clone();
            move || {
                diagnostics.close().unwrap();
                closed.send(()).unwrap();
            }
        });
        assert!(result
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        event.write_all(b"last admitted event").unwrap();
        drop(event);
        result
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
        assert!(crate::diagnostics::lock(&diagnostics.state).closed);
    }
}

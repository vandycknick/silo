//! Stream-only guest file copies, with bounded uploads and SHA-256 diagnostics.
//! No host filesystem endpoint is exposed. No-clobber is a best-effort preflight;
//! libvm owns temporary-file upload commit and replacement-mode preservation.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use libvm::{FileWriteDisposition, MachineEntryKind, MachineFileUploadOptions};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio_util::sync::CancellationToken;

use crate::lobby::caller::Caller;
use crate::lobby::failure::{Code, Failure, Outcome};
use crate::lobby::identity::Action;
use crate::lobby::service::streams::{cancelled, ensure_running, native_failure};
use crate::lobby::service::Service;
use crate::lobby::session::SessionIo;

#[derive(Default)]
pub(crate) struct CopyRequest {
    pub(crate) vm: String,
    pub(crate) path: String,
    pub(crate) upload: bool,
    pub(crate) mode: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) parents: bool,
    pub(crate) no_clobber: bool,
}

#[derive(Debug, Default)]
pub(crate) struct CopySummary {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) disposition: String,
}

/// Local host paths are never endpoints. Only the transport's stdin/stdout is local.
pub(crate) fn parse_endpoint(endpoint: &str) -> Outcome<(String, String)> {
    let Some((vm, path)) = endpoint.split_once(':') else {
        return Err(usage("expected VM:/absolute/path"));
    };
    if vm.is_empty()
        || vm.len() > 4096
        || vm
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\'))
    {
        return Err(usage("invalid VM file endpoint"));
    }
    validate_path(path)?;
    Ok((vm.into(), path.into()))
}

fn validate_path(path: &str) -> Outcome<()> {
    if !path.starts_with('/') || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(usage("guest file path must be absolute"));
    }
    Ok(())
}

fn validate_request(request: &CopyRequest, upload: bool) -> Outcome<()> {
    validate_path(&request.path)?;
    if request.vm.is_empty()
        || request.upload != upload
        || request.mode.is_some_and(|mode| mode > 0o7777)
        || (request.gid.is_some() && request.uid.is_none())
    {
        return Err(usage("invalid file transfer request"));
    }
    if !upload
        && (request.mode.is_some()
            || request.uid.is_some()
            || request.gid.is_some()
            || request.parents
            || request.no_clobber)
    {
        return Err(usage("file options apply only to uploads"));
    }
    Ok(())
}

impl Service {
    pub(crate) async fn copy_to_vm(
        &self,
        caller: &Caller,
        request: CopyRequest,
        io: &mut SessionIo,
    ) -> Outcome<CopySummary> {
        validate_request(&request, true)?;
        let peer = caller.fresh().await?;
        let snapshot = self.inspect_for(&peer, &request.vm, Action::Files).await?;
        ensure_running(&snapshot)?;
        let cancel = io.cancel.clone();
        self.run_stream(caller, &snapshot.id.clone(), Action::Files, &cancel, |token| async move {
            let transfer = async {
                let machine = self.guest_machine(&snapshot.id).await?;
                match machine.get_file_entry(&request.path).await {
                    Ok(_) if request.no_clobber => return Err(Failure::new(Code::Conflict, "destination exists")),
                    Ok(entry) if entry.kind == MachineEntryKind::Directory => return Err(usage("destination is a directory; give the full target path")),
                    Ok(_) | Err(libvm::LibVmError::GuestPathNotFound { .. }) => {},
                    Err(error) => return Err(native_failure(error)),
                }
                if request.parents {
                    if let Some(parent) = request.path.rsplit_once('/').map(|(parent, _)| parent).filter(|parent| !parent.is_empty()) {
                        machine.create_directory(parent, true, None, None, None).await.map_err(native_failure)?;
                    }
                }
                let (mut writer, reader) = tokio::io::duplex(64 << 10);
                let state = Arc::new(Mutex::new(TransferState::default()));
                let reader = TransferReader::new(reader, self.config().settings.file_transfer_limit(), state.clone(), token.clone());
                let done = token.child_token();
                let producer = async {
                    let result = tokio::select! {
                        biased;
                        _ = done.cancelled() => return,
                        result = tokio::io::copy(&mut io.stdin, &mut writer) => result,
                    };
                    if result.is_err() { token.cancel(); }
                    drop(writer);
                };
                let upload = async {
                    let result = machine.upload_file(MachineFileUploadOptions { path: request.path, mode: request.mode, uid: request.uid, gid: request.gid }, reader).await;
                    done.cancel();
                    result
                };
                let (result, ()) = tokio::join!(upload, producer);
                let summary = {
                    let state = state.lock();
                    if state.exceeded { return Err(limit()); }
                    let disposition = match result.map_err(native_failure)? { FileWriteDisposition::Created => "created", FileWriteDisposition::Replaced => "replaced" };
                    CopySummary { bytes: state.bytes, sha256: digest_hex(state.hash.clone()), disposition: disposition.into() }
                };
                print_summary(io, &summary).await?;
                Ok(summary)
            };
            tokio::select! { biased; _ = token.cancelled() => Err(cancelled()), result = transfer => result }
        }).await
    }

    pub(crate) async fn copy_from_vm(
        &self,
        caller: &Caller,
        request: CopyRequest,
        io: &mut SessionIo,
    ) -> Outcome<CopySummary> {
        validate_request(&request, false)?;
        let peer = caller.fresh().await?;
        let snapshot = self.inspect_for(&peer, &request.vm, Action::Files).await?;
        ensure_running(&snapshot)?;
        let cancel = io.cancel.clone();
        self.run_stream(caller, &snapshot.id.clone(), Action::Files, &cancel, |token| async move {
            let transfer = async {
                let machine = self.guest_machine(&snapshot.id).await?;
                let entry = machine.get_file_entry(&request.path).await.map_err(native_failure)?;
                if entry.kind != MachineEntryKind::File { return Err(usage("source must be a regular file; use exec with tar for directories")); }
                let mut download = machine.download_file(request.path).await.map_err(native_failure)?;
                let mut buffer = vec![0; 64 << 10];
                let mut hash = Sha256::new();
                let mut bytes = 0;
                loop {
                    let count = download.read(&mut buffer).await.map_err(|_| unavailable("guest download failed"))?;
                    if count == 0 { break; }
                    io.stdout.write_all(&buffer[..count]).await.map_err(|_| unavailable("file output transport failed"))?;
                    hash.update(&buffer[..count]);
                    bytes += count as u64;
                }
                io.stdout.flush().await.map_err(|_| unavailable("file output transport failed"))?;
                let summary = CopySummary { bytes, sha256: digest_hex(hash), disposition: String::new() };
                print_summary(io, &summary).await?;
                Ok(summary)
            };
            tokio::select! { biased; _ = token.cancelled() => Err(cancelled()), result = transfer => result }
        }).await
    }
}

fn digest_hex(hash: Sha256) -> String {
    let mut output = String::with_capacity(64);
    for byte in hash.finalize() {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

async fn print_summary(io: &mut SessionIo, summary: &CopySummary) -> Outcome<()> {
    let disposition = if summary.disposition.is_empty() {
        "".into()
    } else {
        format!(" ({})", summary.disposition)
    };
    let message = format!(
        "{} bytes{}; sha256 {}\n",
        summary.bytes, disposition, summary.sha256
    );
    io.stderr
        .write_all(message.as_bytes())
        .await
        .map_err(|_| unavailable("file summary transport failed"))?;
    io.stderr
        .flush()
        .await
        .map_err(|_| unavailable("file summary transport failed"))
}

#[derive(Default)]
struct TransferState {
    bytes: u64,
    hash: Sha256,
    exceeded: bool,
}
struct TransferReader<R> {
    input: R,
    remaining: u64,
    state: Arc<Mutex<TransferState>>,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl<R> TransferReader<R> {
    fn new(
        input: R,
        limit: u64,
        state: Arc<Mutex<TransferState>>,
        token: CancellationToken,
    ) -> Self {
        Self {
            input,
            remaining: limit,
            state,
            cancelled: Box::pin(token.cancelled_owned()),
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for TransferReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "transfer cancelled",
            )));
        }
        let before = output.filled().len();
        match Pin::new(&mut self.input).poll_read(cx, output) {
            Poll::Ready(Ok(())) => {
                let data = &output.filled()[before..];
                if data.len() as u64 > self.remaining {
                    self.state.lock().exceeded = true;
                    output.set_filled(before);
                    return Poll::Ready(Err(io::Error::other(
                        "upload exceeds the operator file transfer limit",
                    )));
                }
                self.remaining -= data.len() as u64;
                let mut state = self.state.lock();
                state.bytes += data.len() as u64;
                state.hash.update(data);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

fn usage(message: &str) -> Failure {
    Failure::new(Code::Usage, message)
}
fn unavailable(message: &str) -> Failure {
    Failure::new(Code::Unavailable, message)
}
fn limit() -> Failure {
    Failure::new(
        Code::Limit,
        "upload exceeds the operator file transfer limit",
    )
}

#[cfg(test)]
mod tests {
    use crate::lobby::service::files::{
        parse_endpoint, validate_request, CopyRequest, TransferReader, TransferState,
    };
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn endpoints_only_allow_vm_absolute_paths() {
        for endpoint in [
            "dev:/root/file",
            "dev:/",
            "dev:/path with spaces",
            "dev:/a:b",
        ] {
            assert!(parse_endpoint(endpoint).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "",
            "-",
            "file",
            "/host/path",
            ":/x",
            "dev:relative",
            "dev:",
            "dev:/x\0",
            "a/b:/x",
            "dev:/x\n",
        ] {
            assert!(parse_endpoint(endpoint).is_err(), "{endpoint}");
        }
        assert_eq!(
            parse_endpoint("dev:/root/x").unwrap(),
            ("dev".into(), "/root/x".into())
        );
    }

    #[tokio::test]
    async fn transfer_limit_rejects_extra_byte_before_commit() {
        for size in [0, 4, 5] {
            let state = Arc::new(Mutex::new(TransferState::default()));
            let mut reader = TransferReader::new(
                std::io::Cursor::new(vec![1; size]),
                4,
                state.clone(),
                CancellationToken::new(),
            );
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output).await;
            if size <= 4 {
                assert!(result.is_ok());
                assert_eq!(output.len(), size);
                let state = state.lock();
                assert_eq!(state.bytes, size as u64);
                assert_eq!(state.hash.clone().finalize(), Sha256::digest(&output));
            } else {
                assert!(result.is_err());
                assert!(state.lock().exceeded);
            }
        }
    }

    #[tokio::test]
    async fn cancellation_does_not_become_clean_upload_eof() {
        let token = CancellationToken::new();
        token.cancel();
        let state = Arc::new(Mutex::new(TransferState::default()));
        let mut reader = TransferReader::new(tokio::io::empty(), 0, state, token);
        assert!(reader.read(&mut [0]).await.is_err());
    }

    #[test]
    fn download_rejects_upload_options() {
        let mut request = CopyRequest {
            vm: "dev".into(),
            path: "/tmp/x".into(),
            ..Default::default()
        };
        assert!(validate_request(&request, false).is_ok());
        request.parents = true;
        assert!(validate_request(&request, false).is_err());
        request.upload = true;
        request.mode = Some(0o10000);
        assert!(validate_request(&request, true).is_err());
    }
    #[test]
    fn digest_summary_uses_lowercase_sha256() {
        let mut hash = Sha256::new();
        hash.update(b"abc");
        assert_eq!(
            crate::lobby::service::files::digest_hex(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn native_copy_digest_metadata_no_clobber_and_cancellation() {
        use crate::lobby::failure::Code;
        use crate::lobby::identity::Action;
        use crate::lobby::service::streams::tests::{captured_io, native_enabled};
        use crate::lobby::service::testing::{caller, fixture};
        use std::time::Duration;
        if !native_enabled() {
            return;
        }
        let fixture = fixture().await;
        let caller = caller("user:1", &[Action::Files]);
        let id = fixture.running_vm("user:1").await.unwrap();
        let run = fixture.management.inspect(&id).await.unwrap().run_id;
        let path = "/tmp/lobby-files/nested/payload";
        let payload: Vec<_> = (0..196613).map(|index| (index % 251) as u8).collect();
        let mut input = captured_io(payload.clone(), false);
        let uploaded = fixture
            .service
            .copy_to_vm(
                &caller,
                CopyRequest {
                    vm: id.clone(),
                    path: path.into(),
                    upload: true,
                    mode: Some(0o640),
                    uid: Some(0),
                    gid: Some(0),
                    parents: true,
                    ..Default::default()
                },
                &mut input.io,
            )
            .await
            .unwrap();
        assert_eq!(uploaded.bytes, payload.len() as u64);
        assert_eq!(uploaded.disposition, "created");
        assert!(input.stdout.lock().is_empty());
        assert!(String::from_utf8_lossy(&input.stderr.lock()).contains(&uploaded.sha256));

        let machine = fixture.service.guest_machine(&id).await.unwrap();
        let entry = machine.get_file_entry(path).await.unwrap();
        assert_eq!(entry.mode & 0o7777, 0o640);
        assert_eq!((entry.uid, entry.gid), (0, 0));
        let mut output = captured_io(Vec::new(), false);
        let downloaded = fixture
            .service
            .copy_from_vm(
                &caller,
                CopyRequest {
                    vm: id.clone(),
                    path: path.into(),
                    ..Default::default()
                },
                &mut output.io,
            )
            .await
            .unwrap();
        assert_eq!(downloaded.sha256, uploaded.sha256);
        assert_eq!(downloaded.bytes, uploaded.bytes);
        assert_eq!(*output.stdout.lock(), payload);
        assert!(String::from_utf8_lossy(&output.stderr.lock()).contains(&downloaded.sha256));
        let mut overwrite = captured_io(b"new".to_vec(), false);
        assert_eq!(
            fixture
                .service
                .copy_to_vm(
                    &caller,
                    CopyRequest {
                        vm: id.clone(),
                        path: path.into(),
                        upload: true,
                        no_clobber: true,
                        ..Default::default()
                    },
                    &mut overwrite.io
                )
                .await
                .unwrap_err()
                .code,
            Code::Conflict
        );
        assert_eq!(
            machine.get_file_entry(path).await.unwrap().size_bytes,
            payload.len() as u64
        );

        let mut upload = captured_io(Vec::new(), false);
        let (writer, reader) = tokio::io::duplex(4096);
        upload.io.stdin = Box::new(reader);
        let cancel = upload.io.cancel.clone();
        let interrupt = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel();
        };
        let transfer = fixture.service.copy_to_vm(
            &caller,
            CopyRequest {
                vm: id.clone(),
                path: "/tmp/lobby-cancelled-upload".into(),
                upload: true,
                ..Default::default()
            },
            &mut upload.io,
        );
        let (result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(transfer, interrupt)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().code, Code::Cancelled);
        drop(writer);

        let mut download = captured_io(Vec::new(), false);
        let (blocked, reader) = tokio::io::duplex(4);
        download.io.stdout = Box::new(blocked);
        let cancel = download.io.cancel.clone();
        let interrupt = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            cancel.cancel();
        };
        let transfer = fixture.service.copy_from_vm(
            &caller,
            CopyRequest {
                vm: id.clone(),
                path: path.into(),
                ..Default::default()
            },
            &mut download.io,
        );
        let (result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(transfer, interrupt)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().code, Code::Cancelled);
        drop(reader);
        assert_eq!(fixture.management.inspect(&id).await.unwrap().run_id, run);
        fixture.management.stop(&id, run, true, None).await.unwrap();
        fixture.management.remove(&id).await.unwrap();
    }
}

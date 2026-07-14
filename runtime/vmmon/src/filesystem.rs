use std::pin::Pin;
use std::time::Duration;

use futures::{Stream, StreamExt};
use hyper_util::rt::TokioIo;
use protocol::v1::guest_filesystem_service_client::GuestFilesystemServiceClient;
use protocol::v1::guest_filesystem_service_server::GuestFilesystemService;
use protocol::v1::{
    ByteChunk, CreateDirectoryRequest, CreateDirectoryResponse, DirectoryCreateDisposition,
    DirectoryPage, DownloadFileRequest, ErrorCode, FileWriteDisposition, FilesystemEntry,
    FilesystemEntryKind, GetEntryRequest, ListDirectoryRequest, RemoveEntryRequest,
    RemoveEntryResponse, UploadFileRequest, UploadFileResponse,
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Response, Status};
use tower::service_fn;
use virt::VirtualMachine;

const MAX_TRANSFER_BYTES: usize = 8 * 1024 * 1024 * 1024;
const RELAY_CAPACITY: usize = 8;
const TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

type DownloadStream = Pin<Box<dyn Stream<Item = Result<ByteChunk, Status>> + Send>>;

#[derive(Clone)]
pub(super) struct FilesystemProxy {
    machine: VirtualMachine,
    shutdown: CancellationToken,
    capacity: std::sync::Arc<Semaphore>,
}

impl FilesystemProxy {
    pub(super) fn new(machine: VirtualMachine, shutdown: CancellationToken) -> Self {
        Self {
            machine,
            shutdown,
            capacity: std::sync::Arc::new(Semaphore::new(8)),
        }
    }

    async fn client(&self) -> Result<GuestFilesystemServiceClient<Channel>, Status> {
        if self.shutdown.is_cancelled() {
            return Err(protocol::status_with_error(
                Code::Unavailable,
                ErrorCode::MonitorStopping,
                "monitor is stopping",
                None,
            ));
        }
        connect(&self.machine).await.map(|channel| {
            GuestFilesystemServiceClient::new(channel)
                .max_decoding_message_size(protocol::STRUCTURED_16_MIB)
                .max_encoding_message_size(protocol::STRUCTURED_16_MIB)
        })
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, Status> {
        self.capacity.clone().try_acquire_owned().map_err(|_| {
            protocol::status_with_error(
                Code::ResourceExhausted,
                ErrorCode::ResourceExhausted,
                "guest filesystem capacity is exhausted",
                None,
            )
        })
    }
}

#[tonic::async_trait]
impl GuestFilesystemService for FilesystemProxy {
    type DownloadFileStream = DownloadStream;

    async fn get_entry(
        &self,
        request: Request<GetEntryRequest>,
    ) -> Result<Response<FilesystemEntry>, Status> {
        let _permit = self.admit()?;
        let request = request.into_inner();
        let path = validate_path(request.path, true)?;
        let response = self
            .client()
            .await?
            .get_entry(timed_request(
                GetEntryRequest {
                    path: Some(path.clone()),
                },
                METADATA_TIMEOUT,
            ))
            .await
            .map_err(sanitize_status)?
            .into_inner();
        validate_entry(&response, &path)?;
        Ok(Response::new(response))
    }

    async fn remove_entry(
        &self,
        request: Request<RemoveEntryRequest>,
    ) -> Result<Response<RemoveEntryResponse>, Status> {
        let _permit = self.admit()?;
        let request = request.into_inner();
        let path = validate_path(request.path, false)?;
        let response = self
            .client()
            .await?
            .remove_entry(timed_request(
                RemoveEntryRequest {
                    path: Some(path),
                    recursive: request.recursive,
                },
                METADATA_TIMEOUT,
            ))
            .await
            .map_err(sanitize_status)?
            .into_inner();
        Ok(Response::new(response))
    }

    async fn download_file(
        &self,
        request: Request<DownloadFileRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let permit = self.admit()?;
        let path = validate_path(request.into_inner().path, false)?;
        let response = self
            .client()
            .await?
            .download_file(timed_request(
                DownloadFileRequest { path: Some(path) },
                TRANSFER_TOTAL_TIMEOUT,
            ))
            .await
            .map_err(sanitize_status)?;
        let mut source = response.into_inner();
        let (sender, receiver) = mpsc::channel(RELAY_CAPACITY);
        let delivery_slots = std::sync::Arc::new(Semaphore::new(RELAY_CAPACITY - 1));
        tokio::spawn(async move {
            let mut permit = Some(permit);
            let mut total = 0_usize;
            let deadline = tokio::time::Instant::now() + TRANSFER_TOTAL_TIMEOUT;
            let mut idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
            loop {
                let progress_deadline = idle_deadline.min(deadline);
                let chunk = match tokio::time::timeout_at(progress_deadline, source.next()).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => return,
                    Err(_) => {
                        permit.take();
                        let _ = sender
                            .send((
                                Err(protocol::detailed_status(Status::deadline_exceeded(
                                    "download made no progress before its deadline",
                                ))),
                                None,
                            ))
                            .await;
                        return;
                    }
                };
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        permit.take();
                        let _ = sender.send((Err(sanitize_status(error)), None)).await;
                        return;
                    }
                };
                let data = match chunk.data {
                    Some(data) if data.len() <= protocol::CHUNK_64_KIB => data,
                    _ => {
                        permit.take();
                        let _ = sender.send((Err(protocol_error()), None)).await;
                        return;
                    }
                };
                if data.is_empty() {
                    continue;
                }
                idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
                total = match total.checked_add(data.len()) {
                    Some(total) if total <= MAX_TRANSFER_BYTES => total,
                    _ => {
                        permit.take();
                        let _ = sender.send((Err(protocol_error()), None)).await;
                        return;
                    }
                };
                let delivery_slot = match tokio::time::timeout_at(
                    idle_deadline.min(deadline),
                    delivery_slots.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(slot)) => slot,
                    Ok(Err(_)) => return,
                    Err(_) => {
                        permit.take();
                        let _ = sender
                            .send((
                                Err(protocol::detailed_status(Status::deadline_exceeded(
                                    "download delivery made no progress before its deadline",
                                ))),
                                None,
                            ))
                            .await;
                        return;
                    }
                };
                if sender
                    .send((Ok(ByteChunk { data: Some(data) }), Some(delivery_slot)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(
            ReceiverStream::new(receiver).map(|(item, _delivery_slot)| item),
        )))
    }

    async fn upload_file(
        &self,
        request: Request<tonic::Streaming<UploadFileRequest>>,
    ) -> Result<Response<UploadFileResponse>, Status> {
        let _permit = self.admit()?;
        let mut input = request.into_inner();
        let deadline = tokio::time::Instant::now() + TRANSFER_TOTAL_TIMEOUT;
        let mut idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
        let header = tokio::time::timeout_at(idle_deadline.min(deadline), input.next())
            .await
            .map_err(|_| {
                detailed_status(Status::deadline_exceeded(
                    "upload header did not arrive before its deadline",
                ))
            })?
            .transpose()?
            .ok_or_else(|| invalid_status("upload header is required"))?;
        idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
        let header = match header.payload {
            Some(protocol::v1::upload_file_request::Payload::Header(header)) => header,
            _ => return Err(invalid_status("upload header must be first")),
        };
        let path = validate_path(header.path, false)?;
        validate_mode(header.mode)?;
        let (sender, receiver) = mpsc::channel(RELAY_CAPACITY);
        sender
            .send(UploadFileRequest {
                payload: Some(protocol::v1::upload_file_request::Payload::Header(
                    protocol::v1::UploadFileHeader {
                        path: Some(path),
                        mode: header.mode,
                        uid: header.uid,
                        gid: header.gid,
                    },
                )),
            })
            .await
            .map_err(|_| detailed_status(Status::cancelled("upload relay stopped")))?;
        let request_guard = sender.clone();
        let (completion_tx, mut completion_rx) = tokio::sync::oneshot::channel();
        let producer = AbortOnDropHandle::new(tokio::spawn(async move {
            let result = async {
                let mut total = 0_usize;
                loop {
                    let progress_deadline = idle_deadline.min(deadline);
                    let message =
                        match tokio::time::timeout_at(progress_deadline, input.next()).await {
                            Ok(Some(message)) => message,
                            Ok(None) => return Ok::<(), Status>(()),
                            Err(_) => {
                                return Err(protocol::detailed_status(Status::deadline_exceeded(
                                    "upload made no progress before its deadline",
                                )));
                            }
                        };
                    let message = message?;
                    let data = match message.payload {
                        Some(protocol::v1::upload_file_request::Payload::Chunk(ByteChunk {
                            data: Some(data),
                        })) if data.len() <= protocol::CHUNK_64_KIB => data,
                        Some(protocol::v1::upload_file_request::Payload::Chunk(ByteChunk {
                            data: None,
                        })) => return Err(invalid_status("upload chunk data is required")),
                        Some(protocol::v1::upload_file_request::Payload::Chunk(_)) => {
                            return Err(invalid_status("upload chunk exceeds 64 KiB"));
                        }
                        _ => return Err(invalid_status("only chunks may follow upload header")),
                    };
                    total = total
                        .checked_add(data.len())
                        .filter(|total| *total <= MAX_TRANSFER_BYTES)
                        .ok_or_else(|| {
                            detailed_status(Status::resource_exhausted("upload exceeds 8 GiB"))
                        })?;
                    if data.is_empty() {
                        continue;
                    }
                    idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
                    tokio::time::timeout_at(
                        idle_deadline.min(deadline),
                        sender.send(UploadFileRequest {
                            payload: Some(protocol::v1::upload_file_request::Payload::Chunk(
                                ByteChunk { data: Some(data) },
                            )),
                        }),
                    )
                    .await
                    .map_err(|_| {
                        detailed_status(Status::deadline_exceeded(
                            "upload relay made no progress before its deadline",
                        ))
                    })?
                    .map_err(|_| detailed_status(Status::cancelled("upload relay stopped")))?;
                    idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
                }
            }
            .await;
            match result {
                Ok(()) => {
                    drop(sender);
                    let _ = completion_tx.send(Ok(()));
                }
                Err(error) => {
                    if completion_tx.send(Err(error)).is_ok() {
                        std::future::pending::<()>().await;
                    }
                }
            }
        }));
        let mut client = self.client().await?;
        let mut rpc = Box::pin(client.upload_file(timed_request(
            ReceiverStream::new(receiver),
            TRANSFER_TOTAL_TIMEOUT,
        )));
        let outcome = tokio::select! {
            produced = &mut completion_rx => futures::future::Either::Left(produced),
            response = &mut rpc => futures::future::Either::Right(response),
        };
        let response = match outcome {
            futures::future::Either::Left(Ok(Ok(()))) => {
                drop(request_guard);
                rpc.await.map_err(sanitize_status)?.into_inner()
            }
            futures::future::Either::Left(Ok(Err(error))) => {
                drop(rpc);
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                return Err(protocol::detailed_status(error));
            }
            futures::future::Either::Left(Err(_)) => {
                drop(rpc);
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                return Err(protocol_error());
            }
            futures::future::Either::Right(response) => {
                drop(request_guard);
                producer.abort();
                let _ = producer.await;
                response.map_err(sanitize_status)?.into_inner()
            }
        };
        validate_file_disposition(&response)?;
        Ok(Response::new(response))
    }

    async fn list_directory(
        &self,
        request: Request<ListDirectoryRequest>,
    ) -> Result<Response<DirectoryPage>, Status> {
        let _permit = self.admit()?;
        let request = request.into_inner();
        let path = validate_path(request.path, true)?;
        let limit = request
            .limit
            .unwrap_or(protocol::DEFAULT_DIRECTORY_PAGE_SIZE);
        if !(1..=protocol::MAX_DIRECTORY_PAGE_SIZE).contains(&limit) {
            return Err(invalid_status("directory limit must be 1 through 1024"));
        }
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > protocol::MAX_CURSOR_BYTES)
        {
            return Err(invalid_status("cursor exceeds 8 KiB"));
        }
        let response = self
            .client()
            .await?
            .list_directory(timed_request(
                ListDirectoryRequest {
                    path: Some(path.clone()),
                    limit: Some(limit),
                    cursor: request.cursor,
                },
                METADATA_TIMEOUT,
            ))
            .await
            .map_err(sanitize_status)?
            .into_inner();
        validate_directory_page(&response, &path, limit)?;
        Ok(Response::new(response))
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
    ) -> Result<Response<CreateDirectoryResponse>, Status> {
        let _permit = self.admit()?;
        let request = request.into_inner();
        let path = validate_path(request.path, false)?;
        validate_mode(request.mode)?;
        let response = self
            .client()
            .await?
            .create_directory(timed_request(
                CreateDirectoryRequest {
                    path: Some(path),
                    parents: request.parents,
                    mode: request.mode,
                    uid: request.uid,
                    gid: request.gid,
                },
                METADATA_TIMEOUT,
            ))
            .await
            .map_err(sanitize_status)?
            .into_inner();
        validate_directory_disposition(&response)?;
        Ok(Response::new(response))
    }
}

async fn connect(machine: &VirtualMachine) -> Result<Channel, Status> {
    let machine = machine.clone();
    Endpoint::from_static("http://guest-agent.invalid")
        .connect_timeout(Duration::from_secs(5))
        .connect_with_connector(service_fn(move |_| {
            let machine = machine.clone();
            async move {
                machine
                    .connect_vsock(crate::guest::GUEST_CONTROL_PORT)
                    .await
                    .map(TokioIo::new)
            }
        }))
        .await
        .map_err(|error| detailed_status(Status::unavailable(error.to_string())))
}

fn validate_path(path: Option<String>, root_allowed: bool) -> Result<String, Status> {
    let path = path.ok_or_else(|| invalid_status("path is required"))?;
    if path.is_empty()
        || path.len() > protocol::MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains('\0')
    {
        return Err(invalid_status(
            "path must be a bounded absolute canonical path",
        ));
    }
    if path == "/" {
        return root_allowed
            .then_some(path)
            .ok_or_else(|| invalid_status("root path is not allowed"));
    }
    if path.ends_with('/') {
        return Err(invalid_status("path must not have a trailing separator"));
    }
    for part in path[1..].split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.len() > protocol::MAX_FILENAME_BYTES
        {
            return Err(invalid_status("path must be lexically canonical"));
        }
    }
    Ok(path)
}

fn validate_mode(mode: Option<u32>) -> Result<(), Status> {
    if mode.is_some_and(|mode| mode > 0o7777) {
        return Err(invalid_status("mode may not exceed 07777"));
    }
    Ok(())
}

fn validate_entry(entry: &FilesystemEntry, expected_path: &str) -> Result<(), Status> {
    if entry.path.as_deref() != Some(expected_path)
        || entry.name.as_deref() != Some(entry_name(expected_path))
        || entry.size_bytes.is_none()
        || entry.mode.is_none_or(|mode| mode > 0o7777)
        || entry.uid.is_none()
        || entry.gid.is_none()
        || !matches!(
            entry
                .kind
                .and_then(|value| FilesystemEntryKind::try_from(value).ok()),
            Some(
                FilesystemEntryKind::File
                    | FilesystemEntryKind::Directory
                    | FilesystemEntryKind::Symlink
                    | FilesystemEntryKind::Fifo
                    | FilesystemEntryKind::Socket
                    | FilesystemEntryKind::BlockDevice
                    | FilesystemEntryKind::CharacterDevice
            )
        )
        || !valid_timestamp(entry.modified_at.as_ref())
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn entry_name(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        path.rsplit('/').next().unwrap_or_default()
    }
}

fn valid_timestamp(timestamp: Option<&prost_types::Timestamp>) -> bool {
    const MIN_SECONDS: i64 = -62_135_596_800;
    const MAX_SECONDS: i64 = 253_402_300_799;
    timestamp.is_some_and(|timestamp| {
        (0..1_000_000_000).contains(&timestamp.nanos)
            && (MIN_SECONDS..=MAX_SECONDS).contains(&timestamp.seconds)
    })
}

fn validate_directory_page(page: &DirectoryPage, path: &str, limit: u32) -> Result<(), Status> {
    if page.entries.len() > limit as usize
        || page
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > protocol::MAX_CURSOR_BYTES)
    {
        return Err(protocol_error());
    }
    let mut previous = None;
    for entry in &page.entries {
        let name = entry.name.as_deref().ok_or_else(protocol_error)?;
        if name.is_empty()
            || name.contains('/')
            || name == "."
            || name == ".."
            || name.len() > protocol::MAX_FILENAME_BYTES
        {
            return Err(protocol_error());
        }
        let expected = if path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        };
        validate_entry(entry, &expected)?;
        if previous.is_some_and(|previous: &str| previous >= name) {
            return Err(protocol_error());
        }
        previous = Some(name);
    }
    Ok(())
}

fn validate_file_disposition(response: &UploadFileResponse) -> Result<(), Status> {
    match response
        .disposition
        .and_then(|value| FileWriteDisposition::try_from(value).ok())
    {
        Some(FileWriteDisposition::Created | FileWriteDisposition::Replaced) => Ok(()),
        _ => Err(protocol_error()),
    }
}

fn validate_directory_disposition(response: &CreateDirectoryResponse) -> Result<(), Status> {
    match response
        .disposition
        .and_then(|value| DirectoryCreateDisposition::try_from(value).ok())
    {
        Some(DirectoryCreateDisposition::Created | DirectoryCreateDisposition::AlreadyExists) => {
            Ok(())
        }
        _ => Err(protocol_error()),
    }
}

fn sanitize_status(status: Status) -> Status {
    let status = protocol::detailed_status(status);
    let details = status.details();
    if status.message().len() > protocol::MAX_DIAGNOSTIC_BYTES
        || details.len() > protocol::STRUCTURED_16_MIB
    {
        return protocol_error();
    }
    let Ok(detail) = protocol::decode_error_detail(details) else {
        return protocol_error();
    };
    let Some(error_code) = detail
        .code
        .and_then(|value| ErrorCode::try_from(value).ok())
    else {
        return protocol_error();
    };
    if !valid_error_detail(error_code, detail.retry_after.as_ref())
        || status.code() != error_status(error_code)
    {
        return protocol_error();
    }
    Status::with_details(
        status.code(),
        status.message().to_string(),
        bytes::Bytes::copy_from_slice(details),
    )
}

fn valid_error_detail(code: ErrorCode, retry_after: Option<&prost_types::Duration>) -> bool {
    code != ErrorCode::Unspecified
        && retry_after.is_none_or(|duration| {
            duration.seconds >= 0 && (0..1_000_000_000).contains(&duration.nanos)
        })
}

fn error_status(code: ErrorCode) -> Code {
    match code {
        ErrorCode::InvalidRequest | ErrorCode::InvalidPath | ErrorCode::InvalidCursor => {
            Code::InvalidArgument
        }
        ErrorCode::ResourceExhausted | ErrorCode::RequestTooLarge | ErrorCode::SerialInUse => {
            Code::ResourceExhausted
        }
        ErrorCode::PathNotFound | ErrorCode::ParentNotFound => Code::NotFound,
        ErrorCode::PermissionDenied => Code::PermissionDenied,
        ErrorCode::NotRegularFile
        | ErrorCode::NotDirectory
        | ErrorCode::DirectoryNotEmpty
        | ErrorCode::CursorExpired
        | ErrorCode::UnsupportedFilename => Code::FailedPrecondition,
        ErrorCode::AgentUnavailable
        | ErrorCode::BackendUnavailable
        | ErrorCode::MonitorStopping => Code::Unavailable,
        ErrorCode::AgentTimeout => Code::DeadlineExceeded,
        ErrorCode::AgentProtocolError => Code::DataLoss,
        ErrorCode::Internal => Code::Internal,
        ErrorCode::OperationCancelled => Code::Cancelled,
        ErrorCode::PreconditionFailed => Code::FailedPrecondition,
        ErrorCode::AlreadyExists => Code::AlreadyExists,
        ErrorCode::Unsupported => Code::Unimplemented,
        ErrorCode::Unspecified => Code::Unknown,
    }
}

fn protocol_error() -> Status {
    Status::with_details(
        Code::DataLoss,
        "guest filesystem protocol violation",
        protocol::encode_error_detail(&protocol::v1::ErrorDetail {
            code: Some(ErrorCode::AgentProtocolError as i32),
            retry_after: None,
        })
        .into(),
    )
}

fn invalid_status(message: impl Into<String>) -> Status {
    detailed_status(Status::invalid_argument(message.into()))
}

fn detailed_status(status: Status) -> Status {
    protocol::detailed_status(status)
}

fn timed_request<T>(message: T, timeout: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

#[cfg(test)]
mod tests {
    use crate::services::filesystem::{valid_timestamp, validate_directory_page, validate_path};
    use protocol::v1::{DirectoryPage, FilesystemEntry};

    #[test]
    fn canonical_paths_require_one_absolute_spelling() {
        assert_eq!(
            validate_path(Some("/a/b".to_string()), true).expect("canonical path"),
            "/a/b"
        );
        for path in ["", "a", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\0b"] {
            assert!(
                validate_path(Some(path.to_string()), true).is_err(),
                "{path}"
            );
        }
        assert!(validate_path(Some("/".to_string()), false).is_err());
    }

    #[test]
    fn directory_entries_must_be_sorted_direct_children() {
        let page = DirectoryPage {
            entries: vec![FilesystemEntry {
                name: Some("b".to_string()),
                ..Default::default()
            }],
            next_cursor: None,
        };
        assert!(validate_directory_page(&page, "/tmp", 1).is_err());
    }

    #[test]
    fn timestamps_use_the_protobuf_range() {
        for seconds in [-62_135_596_800, 253_402_300_799] {
            assert!(valid_timestamp(Some(&prost_types::Timestamp {
                seconds,
                nanos: 999_999_999,
            })));
        }
        for seconds in [-62_135_596_801, 253_402_300_800] {
            assert!(!valid_timestamp(Some(&prost_types::Timestamp {
                seconds,
                nanos: 0,
            })));
        }
    }
}

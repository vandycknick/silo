//! Fake guest filesystem service, rooted at the mock guest sandbox directory.
//!
//! Guest paths map onto `<guest_root>/<path>` with a traversal guard.
//! Structured errors use the same `ErrorDetail`/`ErrorCode` scheme as the
//! real agent so libvm's error mapping is exercised end to end.

use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use futures::Stream;
use prost_types::Timestamp;
use protocol::v1::guest_filesystem_service_server::GuestFilesystemService;
use protocol::v1::upload_file_request::Payload;
use protocol::v1::{
    ByteChunk, CreateDirectoryRequest, CreateDirectoryResponse, DirectoryCreateDisposition,
    DirectoryPage, DownloadFileRequest, ErrorCode, FileWriteDisposition, FilesystemEntry,
    FilesystemEntryKind, GetEntryRequest, ListDirectoryRequest, RemoveEntryRequest,
    RemoveEntryResponse, UploadFileRequest, UploadFileResponse,
};
use test_utils::FilesystemScenario;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tonic::{Code, Request, Response, Status, Streaming};

type ChunkStream = Pin<Box<dyn Stream<Item = Result<ByteChunk, Status>> + Send + 'static>>;

pub(crate) struct MockFilesystemService {
    root: PathBuf,
    scenario: FilesystemScenario,
}

impl MockFilesystemService {
    pub(crate) fn new(root: PathBuf, scenario: FilesystemScenario) -> Self {
        Self { root, scenario }
    }

    /// Map a guest path into the sandbox, rejecting traversal escapes and
    /// applying scripted per-path errors.
    fn resolve(&self, guest_path: Option<&str>) -> Result<(String, PathBuf), Status> {
        let guest_path = guest_path.filter(|path| !path.is_empty()).ok_or_else(|| {
            error_status(
                Code::InvalidArgument,
                ErrorCode::InvalidPath,
                "path is required",
            )
        })?;
        if !guest_path.starts_with('/') {
            return Err(error_status(
                Code::InvalidArgument,
                ErrorCode::InvalidPath,
                format!("path must be absolute: {guest_path}"),
            ));
        }

        if let Some(code) = self.scenario.errors.get(guest_path) {
            return Err(scripted_error(guest_path, code));
        }

        let mut resolved = self.root.clone();
        for component in Path::new(guest_path).components() {
            match component {
                Component::RootDir => {}
                Component::Normal(part) => resolved.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(error_status(
                        Code::InvalidArgument,
                        ErrorCode::InvalidPath,
                        format!("path escapes the guest root: {guest_path}"),
                    ));
                }
            }
        }
        Ok((guest_path.to_string(), resolved))
    }
}

fn scripted_error(path: &str, code: &str) -> Status {
    let code = match code.trim_start_matches("ERROR_CODE_") {
        "INVALID_PATH" => ErrorCode::InvalidPath,
        "PATH_NOT_FOUND" => ErrorCode::PathNotFound,
        "PARENT_NOT_FOUND" => ErrorCode::ParentNotFound,
        "PERMISSION_DENIED" => ErrorCode::PermissionDenied,
        "NOT_REGULAR_FILE" => ErrorCode::NotRegularFile,
        "NOT_DIRECTORY" => ErrorCode::NotDirectory,
        "DIRECTORY_NOT_EMPTY" => ErrorCode::DirectoryNotEmpty,
        "RESOURCE_EXHAUSTED" => ErrorCode::ResourceExhausted,
        _ => ErrorCode::Internal,
    };
    error_status(
        Code::PermissionDenied,
        code,
        format!("scripted filesystem error for {path}"),
    )
}

fn error_status(code: Code, error: ErrorCode, message: impl Into<String>) -> Status {
    protocol::status_with_error(code, error, message.into(), None)
}

fn io_error_status(path: &str, err: std::io::Error) -> Status {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::NotFound => error_status(
            Code::NotFound,
            ErrorCode::PathNotFound,
            format!("path not found: {path}"),
        ),
        ErrorKind::PermissionDenied => error_status(
            Code::PermissionDenied,
            ErrorCode::PermissionDenied,
            format!("permission denied: {path}"),
        ),
        _ => error_status(
            Code::Internal,
            ErrorCode::Internal,
            format!("filesystem operation on {path} failed: {err}"),
        ),
    }
}

fn entry_from_metadata(
    guest_path: &str,
    name: Option<String>,
    metadata: &std::fs::Metadata,
) -> FilesystemEntry {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let kind = if metadata.is_dir() {
        FilesystemEntryKind::Directory
    } else if metadata.is_symlink() {
        FilesystemEntryKind::Symlink
    } else if metadata.is_file() {
        FilesystemEntryKind::File
    } else {
        FilesystemEntryKind::Unspecified
    };
    let modified_at = metadata.modified().ok().and_then(|time| {
        time.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| Timestamp {
                seconds: i64::try_from(value.as_secs()).unwrap_or(i64::MAX),
                nanos: value.subsec_nanos() as i32,
            })
    });
    FilesystemEntry {
        path: Some(guest_path.to_string()),
        name: name.or_else(|| {
            Path::new(guest_path)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }),
        kind: Some(kind as i32),
        size_bytes: Some(metadata.len()),
        mode: Some(metadata.permissions().mode() & 0o7777),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        modified_at,
    }
}

fn join_guest_path(base: &str, name: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

#[tonic::async_trait]
impl GuestFilesystemService for MockFilesystemService {
    type DownloadFileStream = ChunkStream;

    async fn get_entry(
        &self,
        request: Request<GetEntryRequest>,
    ) -> Result<Response<FilesystemEntry>, Status> {
        let (guest_path, host_path) = self.resolve(request.into_inner().path.as_deref())?;
        let metadata = tokio::fs::symlink_metadata(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;
        Ok(Response::new(entry_from_metadata(
            &guest_path,
            None,
            &metadata,
        )))
    }

    async fn remove_entry(
        &self,
        request: Request<RemoveEntryRequest>,
    ) -> Result<Response<RemoveEntryResponse>, Status> {
        let request = request.into_inner();
        let (guest_path, host_path) = self.resolve(request.path.as_deref())?;
        let metadata = tokio::fs::symlink_metadata(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;

        let result = if metadata.is_dir() {
            if request.recursive.unwrap_or(false) {
                tokio::fs::remove_dir_all(&host_path).await
            } else {
                tokio::fs::remove_dir(&host_path).await
            }
        } else {
            tokio::fs::remove_file(&host_path).await
        };
        result.map_err(|err| {
            if err.raw_os_error() == Some(libc::ENOTEMPTY) {
                error_status(
                    Code::FailedPrecondition,
                    ErrorCode::DirectoryNotEmpty,
                    format!("directory not empty: {guest_path}"),
                )
            } else {
                io_error_status(&guest_path, err)
            }
        })?;
        Ok(Response::new(RemoveEntryResponse {}))
    }

    async fn download_file(
        &self,
        request: Request<DownloadFileRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let (guest_path, host_path) = self.resolve(request.into_inner().path.as_deref())?;
        let metadata = tokio::fs::metadata(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;
        if !metadata.is_file() {
            return Err(error_status(
                Code::FailedPrecondition,
                ErrorCode::NotRegularFile,
                format!("not a regular file: {guest_path}"),
            ));
        }
        let mut file = tokio::fs::File::open(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;

        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buffer = vec![0u8; protocol::CHUNK_64_KIB];
            loop {
                match file.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = ByteChunk {
                            data: Some(buffer[..n].to_vec().into()),
                        };
                        if sender.send(Ok(chunk)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = sender
                            .send(Err(error_status(
                                Code::Internal,
                                ErrorCode::Internal,
                                format!("read failed: {err}"),
                            )))
                            .await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
        )))
    }

    async fn upload_file(
        &self,
        request: Request<Streaming<UploadFileRequest>>,
    ) -> Result<Response<UploadFileResponse>, Status> {
        let mut input = request.into_inner();
        let header = match input.next().await {
            Some(Ok(UploadFileRequest {
                payload: Some(Payload::Header(header)),
            })) => header,
            _ => {
                return Err(error_status(
                    Code::InvalidArgument,
                    ErrorCode::InvalidRequest,
                    "first upload message must be a header",
                ))
            }
        };
        let (guest_path, host_path) = self.resolve(header.path.as_deref())?;
        let parent = host_path.parent().ok_or_else(|| {
            error_status(
                Code::InvalidArgument,
                ErrorCode::InvalidPath,
                format!("path has no parent: {guest_path}"),
            )
        })?;
        if !parent.is_dir() {
            return Err(error_status(
                Code::NotFound,
                ErrorCode::ParentNotFound,
                format!("parent directory not found for: {guest_path}"),
            ));
        }

        let existed = host_path.exists();
        let mut file = tokio::fs::File::create(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;
        while let Some(message) = input.next().await {
            match message {
                Ok(UploadFileRequest {
                    payload: Some(Payload::Chunk(chunk)),
                }) => {
                    if let Some(data) = chunk.data {
                        file.write_all(&data)
                            .await
                            .map_err(|err| io_error_status(&guest_path, err))?;
                    }
                }
                Ok(_) => {
                    return Err(error_status(
                        Code::InvalidArgument,
                        ErrorCode::InvalidRequest,
                        "unexpected upload payload after header",
                    ))
                }
                Err(status) => return Err(status),
            }
        }
        file.flush()
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;

        if let Some(mode) = header.mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(
                &host_path,
                std::fs::Permissions::from_mode(mode & 0o7777),
            )
            .await;
        }

        Ok(Response::new(UploadFileResponse {
            disposition: Some(if existed {
                FileWriteDisposition::Replaced as i32
            } else {
                FileWriteDisposition::Created as i32
            }),
        }))
    }

    async fn list_directory(
        &self,
        request: Request<ListDirectoryRequest>,
    ) -> Result<Response<DirectoryPage>, Status> {
        let request = request.into_inner();
        let (guest_path, host_path) = self.resolve(request.path.as_deref())?;
        let metadata = tokio::fs::metadata(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;
        if !metadata.is_dir() {
            return Err(error_status(
                Code::FailedPrecondition,
                ErrorCode::NotDirectory,
                format!("not a directory: {guest_path}"),
            ));
        }

        let offset: usize = match request.cursor.as_deref() {
            None | Some(b"") => 0,
            Some(cursor) => std::str::from_utf8(cursor)
                .ok()
                .and_then(|cursor| cursor.parse().ok())
                .ok_or_else(|| {
                    error_status(
                        Code::InvalidArgument,
                        ErrorCode::InvalidCursor,
                        "bad cursor",
                    )
                })?,
        };
        let limit = request
            .limit
            .filter(|limit| *limit > 0)
            .unwrap_or(protocol::DEFAULT_DIRECTORY_PAGE_SIZE)
            .min(protocol::MAX_DIRECTORY_PAGE_SIZE) as usize;

        let mut names = Vec::new();
        let mut reader = tokio::fs::read_dir(&host_path)
            .await
            .map_err(|err| io_error_status(&guest_path, err))?;
        while let Some(entry) = reader
            .next_entry()
            .await
            .map_err(|err| io_error_status(&guest_path, err))?
        {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();

        let mut entries = Vec::new();
        for name in names.iter().skip(offset).take(limit) {
            let child_guest = join_guest_path(&guest_path, name);
            let child_host = host_path.join(name);
            if let Ok(metadata) = tokio::fs::symlink_metadata(&child_host).await {
                entries.push(entry_from_metadata(
                    &child_guest,
                    Some(name.clone()),
                    &metadata,
                ));
            }
        }

        let next_cursor =
            (offset + limit < names.len()).then(|| (offset + limit).to_string().into_bytes());
        Ok(Response::new(DirectoryPage {
            entries,
            next_cursor,
        }))
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
    ) -> Result<Response<CreateDirectoryResponse>, Status> {
        let request = request.into_inner();
        let (guest_path, host_path) = self.resolve(request.path.as_deref())?;

        if host_path.is_dir() {
            return Ok(Response::new(CreateDirectoryResponse {
                disposition: Some(DirectoryCreateDisposition::AlreadyExists as i32),
            }));
        }

        let result = if request.parents.unwrap_or(false) {
            tokio::fs::create_dir_all(&host_path).await
        } else {
            tokio::fs::create_dir(&host_path).await
        };
        result.map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                error_status(
                    Code::NotFound,
                    ErrorCode::ParentNotFound,
                    format!("parent directory not found for: {guest_path}"),
                )
            } else {
                io_error_status(&guest_path, err)
            }
        })?;

        if let Some(mode) = request.mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(
                &host_path,
                std::fs::Permissions::from_mode(mode & 0o7777),
            )
            .await;
        }

        Ok(Response::new(CreateDirectoryResponse {
            disposition: Some(DirectoryCreateDisposition::Created as i32),
        }))
    }
}

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use nix::sys::stat::{fchmod, Mode};
use prost_types::Timestamp;
use protocol::v1::guest_filesystem_service_server::GuestFilesystemService;
use protocol::v1::{
    ByteChunk, CreateDirectoryRequest, CreateDirectoryResponse, DirectoryCreateDisposition,
    DirectoryPage, DownloadFileRequest, FileWriteDisposition, FilesystemEntry, FilesystemEntryKind,
    GetEntryRequest, ListDirectoryRequest, RemoveEntryRequest, RemoveEntryResponse,
    UploadFileRequest, UploadFileResponse,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const RELAY_CAPACITY: usize = 8;
const CURSOR_VERSION: &[u8] = b"v1";
const MODE_MASK: u32 = 0o7777;
const TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TOTAL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

type DownloadStream = Pin<Box<dyn Stream<Item = Result<ByteChunk, Status>> + Send + 'static>>;

#[derive(Clone)]
pub(crate) struct FilesystemService {
    root: PathBuf,
    instance_id: String,
    capacity: std::sync::Arc<Semaphore>,
}

impl FilesystemService {
    pub(crate) fn new(root: impl Into<PathBuf>, instance_id: String) -> Self {
        Self {
            root: root.into(),
            instance_id,
            capacity: std::sync::Arc::new(Semaphore::new(8)),
        }
    }

    fn resolve(&self, value: Option<String>) -> Result<(String, PathBuf), Status> {
        let path = value.ok_or_else(|| invalid("path is required"))?;
        let bytes = path.as_bytes();
        if bytes.is_empty()
            || bytes.len() > protocol::MAX_PATH_BYTES
            || !path.starts_with('/')
            || bytes.contains(&0)
            || path.contains("//")
            || (path.len() > 1 && path.ends_with('/'))
        {
            return Err(invalid("path is not canonical"));
        }
        if path != "/"
            && path[1..].split('/').any(|part| {
                part == "." || part == ".." || part.len() > protocol::MAX_FILENAME_BYTES
            })
        {
            return Err(invalid("path is not canonical"));
        }

        Ok((path.clone(), self.root.join(&path[1..])))
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, Status> {
        self.capacity.clone().try_acquire_owned().map_err(|_| {
            protocol::status_with_error(
                tonic::Code::ResourceExhausted,
                protocol::v1::ErrorCode::ResourceExhausted,
                "guest filesystem capacity is exhausted",
                None,
            )
        })
    }
}

#[tonic::async_trait]
impl GuestFilesystemService for FilesystemService {
    type DownloadFileStream = DownloadStream;

    async fn get_entry(
        &self,
        request: Request<GetEntryRequest>,
    ) -> Result<Response<FilesystemEntry>, Status> {
        let permit = std::sync::Arc::new(self.admit()?);
        let (path, target) = self.resolve(request.into_inner().path)?;
        run_blocking(permit, move || entry(&path, &target))
            .await
            .map_err(join_error)?
            .map(Response::new)
    }

    async fn remove_entry(
        &self,
        request: Request<RemoveEntryRequest>,
    ) -> Result<Response<RemoveEntryResponse>, Status> {
        let permit = std::sync::Arc::new(self.admit()?);
        let request = request.into_inner();
        let (path, target) = self.resolve(request.path)?;
        reject_root(&path, "remove")?;
        run_blocking(permit, move || {
            remove(&target, request.recursive.unwrap_or(false))
        })
        .await
        .map_err(join_error)??;
        Ok(Response::new(RemoveEntryResponse {}))
    }

    async fn download_file(
        &self,
        request: Request<DownloadFileRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let permit = std::sync::Arc::new(self.admit()?);
        let (_, target) = self.resolve(request.into_inner().path)?;
        let file = run_blocking(permit.clone(), move || {
            let file = open_no_follow(&target, false)?;
            if !file.metadata().map_err(fs_status)?.is_file() {
                return Err(protocol::status_with_error(
                    tonic::Code::FailedPrecondition,
                    protocol::v1::ErrorCode::NotRegularFile,
                    "path is not a regular file",
                    None,
                ));
            }
            Ok::<File, Status>(file)
        })
        .await
        .map_err(join_error)??;
        let (sender, receiver) = tokio::sync::mpsc::channel(RELAY_CAPACITY);
        let delivery_slots = std::sync::Arc::new(Semaphore::new(RELAY_CAPACITY - 1));
        tokio::spawn(async move {
            let mut file = Some(file);
            let mut total = 0_u64;
            let deadline = tokio::time::Instant::now() + TRANSFER_TOTAL_TIMEOUT;
            let mut idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
            loop {
                let progress_deadline = idle_deadline.min(deadline);
                let current = match file.take() {
                    Some(file) => file,
                    None => {
                        let _ = sender
                            .send((Err(internal("download file handle is unavailable")), None))
                            .await;
                        return;
                    }
                };
                let chunk = match tokio::time::timeout_at(
                    progress_deadline,
                    run_blocking(permit.clone(), move || read_download_chunk(current)),
                )
                .await
                {
                    Ok(Ok(Ok((next, chunk)))) => {
                        file = Some(next);
                        chunk
                    }
                    Ok(Ok(Err(error))) => {
                        let _ = sender.send((Err(fs_status(error)), None)).await;
                        return;
                    }
                    Ok(Err(error)) => {
                        let _ = sender.send((Err(join_error(error)), None)).await;
                        return;
                    }
                    Err(_) => {
                        let _ = sender
                            .send((
                                Err(protocol::detailed_status(Status::deadline_exceeded(
                                    "download read made no progress before its deadline",
                                ))),
                                None,
                            ))
                            .await;
                        return;
                    }
                };
                if chunk.is_empty() {
                    return;
                }
                idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
                total = match total.checked_add(chunk.len() as u64) {
                    Some(total) if total <= MAX_UPLOAD_BYTES => total,
                    _ => {
                        let _ = sender
                            .send((
                                Err(protocol::detailed_status(Status::resource_exhausted(
                                    "download exceeds 8GiB",
                                ))),
                                None,
                            ))
                            .await;
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
                    .send((Ok(ByteChunk { data: Some(chunk) }), Some(delivery_slot)))
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
        let permit = std::sync::Arc::new(self.admit()?);
        let mut stream = request.into_inner();
        let deadline = tokio::time::Instant::now() + TRANSFER_TOTAL_TIMEOUT;
        let mut idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
        let header = tokio::time::timeout_at(idle_deadline.min(deadline), stream.message())
            .await
            .map_err(|_| {
                protocol::detailed_status(Status::deadline_exceeded(
                    "upload header did not arrive before its deadline",
                ))
            })??
            .ok_or_else(|| invalid("upload header is required"))?
            .payload
            .ok_or_else(|| invalid("upload header is required"))?;
        let protocol::v1::upload_file_request::Payload::Header(header) = header else {
            return Err(invalid("upload header must be first"));
        };
        let (path, target) = self.resolve(header.path.clone())?;
        reject_root(&path, "upload")?;
        validate_mode(header.mode)?;

        let prepared = tokio::time::timeout_at(
            deadline,
            run_blocking(permit.clone(), move || prepare_upload(target, header)),
        )
        .await
        .map_err(|_| {
            protocol::detailed_status(Status::deadline_exceeded(
                "upload preparation exceeded its deadline",
            ))
        })?
        .map_err(join_error)??;
        let mut upload = prepared;
        let mut total = 0_u64;

        idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
        loop {
            let progress_deadline = idle_deadline.min(deadline);
            let message = match tokio::time::timeout_at(progress_deadline, stream.message()).await {
                Ok(Ok(Some(message))) => message,
                Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(protocol::detailed_status(Status::deadline_exceeded(
                        "upload made no progress before its deadline",
                    )));
                }
            };
            let Some(protocol::v1::upload_file_request::Payload::Chunk(chunk)) = message.payload
            else {
                return Err(invalid("only chunks may follow upload header"));
            };
            let data = chunk
                .data
                .ok_or_else(|| invalid("upload chunk data is required"))?;
            if data.is_empty() {
                continue;
            }
            idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
            if data.len() > protocol::CHUNK_64_KIB {
                return Err(invalid("upload chunk exceeds 64KiB"));
            }
            total = total
                .checked_add(data.len() as u64)
                .ok_or_else(|| resource_exhausted("upload exceeds 8GiB"))?;
            if total > MAX_UPLOAD_BYTES {
                return Err(resource_exhausted("upload exceeds 8GiB"));
            }
            upload = tokio::time::timeout_at(
                idle_deadline.min(deadline),
                run_blocking(permit.clone(), move || {
                    upload
                        .file
                        .as_mut()
                        .ok_or_else(|| internal("upload file handle is unavailable"))?
                        .write_all(&data)
                        .map_err(fs_status)?;
                    Ok::<Upload, Status>(upload)
                }),
            )
            .await
            .map_err(|_| {
                protocol::detailed_status(Status::deadline_exceeded(
                    "upload write made no progress before its deadline",
                ))
            })?
            .map_err(join_error)??;
            idle_deadline = tokio::time::Instant::now() + TRANSFER_IDLE_TIMEOUT;
        }

        let replaced = tokio::time::timeout_at(
            idle_deadline.min(deadline),
            run_blocking(permit, move || upload.commit()),
        )
        .await
        .map_err(|_| {
            protocol::detailed_status(Status::deadline_exceeded(
                "upload commit exceeded its deadline",
            ))
        })?
        .map_err(join_error)??;
        Ok(Response::new(UploadFileResponse {
            disposition: Some(if replaced {
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
        let permit = std::sync::Arc::new(self.admit()?);
        let request = request.into_inner();
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > protocol::MAX_CURSOR_BYTES)
        {
            return Err(invalid("cursor exceeds protocol limit"));
        }
        let limit = match request.limit {
            Some(limit) if limit == 0 || limit > protocol::MAX_DIRECTORY_PAGE_SIZE => {
                return Err(invalid("directory limit must be 1 through 1024"));
            }
            Some(limit) => limit as usize,
            None => protocol::DEFAULT_DIRECTORY_PAGE_SIZE as usize,
        };
        let (path, target) = self.resolve(request.path)?;
        let cursor = request.cursor.unwrap_or_default();
        let instance = self.instance_id.clone();
        run_blocking(permit, move || {
            list(&instance, &path, &target, limit, cursor)
        })
        .await
        .map_err(join_error)?
        .map(Response::new)
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
    ) -> Result<Response<CreateDirectoryResponse>, Status> {
        let permit = std::sync::Arc::new(self.admit()?);
        let request = request.into_inner();
        validate_mode(request.mode)?;
        let (path, target) = self.resolve(request.path.clone())?;
        reject_root(&path, "create")?;
        let root = self.root.clone();
        let created = run_blocking(permit, move || create_directory(&root, &target, request))
            .await
            .map_err(join_error)??;
        Ok(Response::new(CreateDirectoryResponse {
            disposition: Some(if created {
                DirectoryCreateDisposition::Created as i32
            } else {
                DirectoryCreateDisposition::AlreadyExists as i32
            }),
        }))
    }
}

async fn run_blocking<T, F>(
    permit: std::sync::Arc<OwnedSemaphorePermit>,
    work: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
}

fn reject_root(path: &str, operation: &str) -> Result<(), Status> {
    if path == "/" {
        Err(invalid(format!("cannot {operation} the root")))
    } else {
        Ok(())
    }
}

fn entry(path: &str, target: &Path) -> Result<FilesystemEntry, Status> {
    let metadata = std::fs::symlink_metadata(target).map_err(fs_status)?;
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        FilesystemEntryKind::File
    } else if file_type.is_dir() {
        FilesystemEntryKind::Directory
    } else if file_type.is_symlink() {
        FilesystemEntryKind::Symlink
    } else if file_type.is_fifo() {
        FilesystemEntryKind::Fifo
    } else if file_type.is_socket() {
        FilesystemEntryKind::Socket
    } else if file_type.is_block_device() {
        FilesystemEntryKind::BlockDevice
    } else if file_type.is_char_device() {
        FilesystemEntryKind::CharacterDevice
    } else {
        return Err(precondition("unrecognized filesystem entry type"));
    };
    Ok(FilesystemEntry {
        path: Some(path.to_string()),
        name: Some(if path == "/" {
            "/".to_string()
        } else {
            target
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(unsupported_filename)?
                .to_string()
        }),
        kind: Some(kind as i32),
        size_bytes: Some(metadata.size()),
        mode: Some(metadata.mode() & MODE_MASK),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        modified_at: Some(Timestamp {
            seconds: metadata.mtime(),
            nanos: metadata.mtime_nsec() as i32,
        }),
    })
}

fn entry_at(path: &str, directory: &File, name: &str) -> Result<FilesystemEntry, Status> {
    let metadata = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(rustix_status)?;
    let kind = match rustix::fs::FileType::from_raw_mode(metadata.st_mode) {
        rustix::fs::FileType::RegularFile => FilesystemEntryKind::File,
        rustix::fs::FileType::Directory => FilesystemEntryKind::Directory,
        rustix::fs::FileType::Symlink => FilesystemEntryKind::Symlink,
        rustix::fs::FileType::Fifo => FilesystemEntryKind::Fifo,
        rustix::fs::FileType::Socket => FilesystemEntryKind::Socket,
        rustix::fs::FileType::BlockDevice => FilesystemEntryKind::BlockDevice,
        rustix::fs::FileType::CharacterDevice => FilesystemEntryKind::CharacterDevice,
        rustix::fs::FileType::Unknown => {
            return Err(precondition("unrecognized filesystem entry type"));
        }
    };
    Ok(FilesystemEntry {
        path: Some(path.to_string()),
        name: Some(name.to_string()),
        kind: Some(kind as i32),
        size_bytes: Some(metadata.st_size as u64),
        mode: Some(metadata.st_mode & MODE_MASK),
        uid: Some(metadata.st_uid),
        gid: Some(metadata.st_gid),
        modified_at: Some(Timestamp {
            seconds: metadata.st_mtime,
            nanos: metadata.st_mtime_nsec as i32,
        }),
    })
}

fn read_download_chunk(mut file: File) -> std::io::Result<(File, Bytes)> {
    let mut buffer = vec![0; protocol::CHUNK_64_KIB];
    let count = file.read(&mut buffer)?;
    buffer.truncate(count);
    Ok((file, Bytes::from(buffer)))
}

fn open_no_follow(path: &Path, write: bool) -> Result<File, Status> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    options.open(path).map_err(fs_status)
}

fn open_directory_no_follow(path: &Path) -> Result<File, Status> {
    OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits())
        .open(path)
        .map_err(fs_status)
}

fn open_parent_directory(target: &Path) -> Result<File, Status> {
    let parent = target
        .parent()
        .ok_or_else(|| invalid("upload path has no parent"))?;
    // The parent is an intermediate component, so it follows guest filesystem symlinks.
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_DIRECTORY.bits())
        .open(parent)
        .map_err(fs_status)
}

fn remove(target: &Path, recursive: bool) -> Result<(), Status> {
    let parent = open_parent_directory(target)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("remove path has no filename"))?;
    remove_at(&parent, name, recursive)
}

fn remove_at(parent: &File, name: &str, recursive: bool) -> Result<(), Status> {
    let metadata = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(rustix_status)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir() {
        if recursive {
            let directory = rustix::fs::openat(
                parent,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(rustix_status)?;
            remove_directory_contents(&directory)?;
        }
        rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR).map_err(rustix_status)
    } else {
        rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()).map_err(rustix_status)
    }
}

fn remove_directory_contents(directory: &File) -> Result<(), Status> {
    let mut entries = rustix::fs::Dir::read_from(directory)
        .map_err(|error| internal(format!("read directory: {error}")))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|error| internal(format!("read directory: {error}")))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| unsupported_filename())?;
        if name != "." && name != ".." {
            remove_at(directory, name, true)?;
        }
    }
    Ok(())
}

fn list(
    instance: &str,
    path: &str,
    target: &Path,
    limit: usize,
    cursor: Vec<u8>,
) -> Result<DirectoryPage, Status> {
    let start = decode_cursor(instance, path, &cursor)?;
    // Read from a no-follow directory descriptor so a replacement cannot redirect listing.
    let directory = open_directory_no_follow(target)?;
    let mut entries = rustix::fs::Dir::read_from(&directory)
        .map_err(|error| internal(format!("read directory: {error}")))?;
    let mut names = Vec::new();
    while let Some(item) = entries.read() {
        let item = item.map_err(|error| internal(format!("read directory: {error}")))?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| unsupported_filename())?;
        if name != "." && name != ".." {
            names.push(name.to_string());
        }
    }
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let names: Vec<_> = names
        .into_iter()
        .filter(|name| {
            start
                .as_ref()
                .is_none_or(|start| name.as_bytes() > start.as_bytes())
        })
        .collect();
    let more = names.len() > limit;
    let selected = names.into_iter().take(limit).collect::<Vec<_>>();
    let entries = selected
        .iter()
        .map(|name| {
            let child_path = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            entry_at(&child_path, &directory, name)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if more {
        Some(encode_cursor(
            instance,
            path,
            selected
                .last()
                .ok_or_else(|| internal("directory page has no final entry"))?,
        )?)
    } else {
        None
    };
    Ok(DirectoryPage {
        entries,
        next_cursor,
    })
}

fn encode_cursor(instance: &str, path: &str, name: &str) -> Result<Vec<u8>, Status> {
    let cursor = [
        CURSOR_VERSION,
        instance.as_bytes(),
        path.as_bytes(),
        name.as_bytes(),
    ]
    .join(&0);
    if cursor.len() > protocol::MAX_CURSOR_BYTES {
        return Err(internal("generated cursor exceeds protocol limit"));
    }
    Ok(cursor)
}

fn decode_cursor(instance: &str, path: &str, cursor: &[u8]) -> Result<Option<String>, Status> {
    if cursor.is_empty() {
        return Ok(None);
    }
    let mut fields = cursor.split(|byte| *byte == 0);
    let (Some(version), Some(cursor_instance), Some(cursor_path), Some(name), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(invalid_cursor());
    };
    if version != CURSOR_VERSION || name.is_empty() {
        return Err(invalid_cursor());
    }
    let cursor_instance = std::str::from_utf8(cursor_instance).map_err(|_| invalid_cursor())?;
    let cursor_path = std::str::from_utf8(cursor_path).map_err(|_| invalid_cursor())?;
    let name = std::str::from_utf8(name).map_err(|_| invalid_cursor())?;
    if cursor_instance != instance || cursor_path != path {
        return Err(protocol::status_with_error(
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::CursorExpired,
            "cursor has expired",
            None,
        ));
    }
    Ok(Some(name.to_string()))
}

struct Upload {
    file: Option<File>,
    parent: File,
    temporary: String,
    name: String,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    requested_mode: Option<u32>,
    requested_uid: Option<u32>,
    requested_gid: Option<u32>,
    committed: bool,
}

impl Upload {
    fn commit(mut self) -> Result<bool, Status> {
        let file = self
            .file
            .take()
            .ok_or_else(|| internal("upload file handle is unavailable"))?;
        apply_attributes(&file, self.mode, self.uid, self.gid)?;
        file.sync_all().map_err(fs_status)?;
        let replaced = match rustix::fs::renameat_with(
            &self.parent,
            &self.temporary,
            &self.parent,
            &self.name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => false,
            Err(rustix::io::Errno::EXIST) => {
                let target = rustix::fs::statat(
                    &self.parent,
                    &self.name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(rustix_status)?;
                if !rustix::fs::FileType::from_raw_mode(target.st_mode).is_file() {
                    return Err(precondition("existing path is not a regular file"));
                }
                apply_attributes(
                    &file,
                    self.requested_mode.unwrap_or(target.st_mode & MODE_MASK),
                    self.requested_uid.or(Some(target.st_uid)),
                    self.requested_gid.or(Some(target.st_gid)),
                )?;
                file.sync_all().map_err(fs_status)?;
                rustix::fs::renameat(&self.parent, &self.temporary, &self.parent, &self.name)
                    .map_err(rustix_status)?;
                true
            }
            Err(error) => return Err(rustix_status(error)),
        };
        drop(file);
        rustix::fs::fsync(&self.parent).map_err(rustix_status)?;
        self.committed = true;
        Ok(replaced)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.committed {
            let _ =
                rustix::fs::unlinkat(&self.parent, &self.temporary, rustix::fs::AtFlags::empty());
        }
    }
}

fn prepare_upload(
    target: PathBuf,
    header: protocol::v1::UploadFileHeader,
) -> Result<Upload, Status> {
    let parent = open_parent_directory(&target)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("upload path has no filename"))?
        .to_string();
    let existing = match rustix::fs::statat(&parent, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => Some(metadata),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(rustix_status(error)),
    };
    if existing
        .as_ref()
        .is_some_and(|metadata| !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file())
    {
        return Err(precondition("existing path is not a regular file"));
    }
    let mode = header
        .mode
        .or_else(|| existing.as_ref().map(|metadata| metadata.st_mode))
        .unwrap_or(0o644)
        & MODE_MASK;
    let uid = header
        .uid
        .or_else(|| existing.as_ref().map(|metadata| metadata.st_uid));
    let gid = header
        .gid
        .or_else(|| existing.as_ref().map(|metadata| metadata.st_gid));
    let temporary = format!(".silo-upload-{}", uuid::Uuid::new_v4());
    let file = rustix::fs::openat(
        &parent,
        &temporary,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::from_raw_mode(mode),
    )
    .map(File::from)
    .map_err(rustix_status)?;
    Ok(Upload {
        file: Some(file),
        temporary,
        parent,
        name,
        mode,
        uid,
        gid,
        requested_mode: header.mode,
        requested_uid: header.uid,
        requested_gid: header.gid,
        committed: false,
    })
}

fn create_directory(
    root: &Path,
    target: &Path,
    request: CreateDirectoryRequest,
) -> Result<bool, Status> {
    let (parent, name) = open_create_parent(root, target, request.parents.unwrap_or(false))?;
    create_directory_at(&parent, &name, request)
}

fn open_create_parent(root: &Path, target: &Path, parents: bool) -> Result<(File, String), Status> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| invalid("create path is outside the root"))?;
    let mut components = relative.components();
    let name = components
        .next_back()
        .and_then(|component| component.as_os_str().to_str())
        .ok_or_else(|| invalid("create path has no filename"))?
        .to_string();
    let mut directory = open_directory_no_follow(root)?;
    for component in components {
        let name = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| invalid("create path has a non-UTF-8 component"))?;
        directory = match rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        ) {
            Ok(directory) => File::from(directory),
            Err(rustix::io::Errno::NOENT) if parents => {
                match rustix::fs::mkdirat(&directory, name, rustix::fs::Mode::from_raw_mode(0o777))
                {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(rustix_status(error)),
                }
                rustix::fs::openat(
                    &directory,
                    name,
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(rustix_status)?
            }
            Err(error) => return Err(rustix_status(error)),
        };
    }
    Ok((directory, name))
}

fn create_directory_at(
    parent: &File,
    name: &str,
    request: CreateDirectoryRequest,
) -> Result<bool, Status> {
    let existing = match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => Some(metadata),
        Err(rustix::io::Errno::NOENT) => None,
        Err(error) => return Err(rustix_status(error)),
    };
    let created = match existing {
        Some(_) => false,
        None => match rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_raw_mode(0o777)) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(rustix_status(error)),
        },
    };
    let directory = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(rustix_status)?;
    let metadata = rustix::fs::fstat(&directory).map_err(rustix_status)?;
    if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(precondition("existing path is not a directory"));
    }
    if created {
        let mode = request.mode.unwrap_or(0o755);
        apply_attributes(&directory, mode, request.uid, request.gid)?;
    }
    Ok(created)
}

fn validate_mode(mode: Option<u32>) -> Result<(), Status> {
    if mode.is_some_and(|mode| mode > MODE_MASK) {
        Err(protocol::detailed_status(Status::invalid_argument(
            "mode may not exceed 07777",
        )))
    } else {
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::invalid_argument(message.into()))
}

fn precondition(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::failed_precondition(message.into()))
}

fn resource_exhausted(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::resource_exhausted(message.into()))
}

fn internal(message: impl Into<String>) -> Status {
    protocol::detailed_status(Status::internal(message.into()))
}

fn invalid_cursor() -> Status {
    protocol::status_with_error(
        tonic::Code::InvalidArgument,
        protocol::v1::ErrorCode::InvalidCursor,
        "malformed cursor",
        None,
    )
}

fn unsupported_filename() -> Status {
    protocol::status_with_error(
        tonic::Code::FailedPrecondition,
        protocol::v1::ErrorCode::UnsupportedFilename,
        "filesystem name is not valid UTF-8",
        None,
    )
}

fn apply_attributes(
    file: &File,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), Status> {
    if uid.is_some() || gid.is_some() {
        nix::unistd::fchown(
            file,
            uid.map(nix::unistd::Uid::from_raw),
            gid.map(nix::unistd::Gid::from_raw),
        )
        .map_err(nix_status)?;
    }
    // Linux clears set-ID bits on chown, so mode must be applied last.
    fchmod(file, Mode::from_bits_truncate(mode)).map_err(nix_status)?;
    Ok(())
}

fn fs_status(error: std::io::Error) -> Status {
    if let Some(errno) = error.raw_os_error().map(nix::errno::Errno::from_raw) {
        return errno_status(errno, error.to_string());
    }
    protocol::detailed_status(match error.kind() {
        std::io::ErrorKind::NotFound => Status::not_found(error.to_string()),
        std::io::ErrorKind::PermissionDenied => Status::permission_denied(error.to_string()),
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotADirectory => {
            Status::failed_precondition(error.to_string())
        }
        _ => Status::internal(error.to_string()),
    })
}

fn nix_status(error: nix::Error) -> Status {
    errno_status(error, error.to_string())
}

fn rustix_status(error: rustix::io::Errno) -> Status {
    errno_status(
        nix::errno::Errno::from_raw(error.raw_os_error()),
        error.to_string(),
    )
}

fn errno_status(error: nix::errno::Errno, message: String) -> Status {
    let (grpc, code) = match error {
        nix::errno::Errno::ENOENT => (tonic::Code::NotFound, protocol::v1::ErrorCode::PathNotFound),
        nix::errno::Errno::EACCES | nix::errno::Errno::EPERM => (
            tonic::Code::PermissionDenied,
            protocol::v1::ErrorCode::PermissionDenied,
        ),
        nix::errno::Errno::ENOTDIR => (
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::NotDirectory,
        ),
        nix::errno::Errno::ENOTEMPTY => (
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::DirectoryNotEmpty,
        ),
        nix::errno::Errno::EISDIR => (
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::NotRegularFile,
        ),
        nix::errno::Errno::EEXIST => (
            tonic::Code::AlreadyExists,
            protocol::v1::ErrorCode::AlreadyExists,
        ),
        nix::errno::Errno::ELOOP => (
            tonic::Code::FailedPrecondition,
            protocol::v1::ErrorCode::PreconditionFailed,
        ),
        nix::errno::Errno::ENAMETOOLONG => (
            tonic::Code::InvalidArgument,
            protocol::v1::ErrorCode::InvalidPath,
        ),
        nix::errno::Errno::EFBIG => (
            tonic::Code::ResourceExhausted,
            protocol::v1::ErrorCode::ResourceExhausted,
        ),
        _ => (tonic::Code::Internal, protocol::v1::ErrorCode::Internal),
    };
    protocol::status_with_error(grpc, code, message, None)
}

fn join_error(error: tokio::task::JoinError) -> Status {
    protocol::detailed_status(Status::internal(format!(
        "filesystem worker failed: {error}"
    )))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use tonic::Code;

    use crate::filesystem::{
        create_directory, create_directory_at, entry, entry_at, list, open_directory_no_follow,
        open_no_follow, prepare_upload, remove, remove_at, run_blocking, FilesystemService,
        MODE_MASK,
    };

    fn service(root: &std::path::Path) -> FilesystemService {
        FilesystemService::new(root, "agent-a".to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_blocking_work_retains_its_admission_permit() {
        let capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::new(
            capacity
                .clone()
                .try_acquire_owned()
                .expect("initial admission permit"),
        );
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(run_blocking(permit, move || {
            let _ = started_tx.send(());
            worker_barrier.wait();
        }));
        started_rx.await.expect("blocking work started");

        worker.abort();
        let _ = worker.await;
        assert!(capacity.clone().try_acquire_owned().is_err());

        barrier.wait();
        let permit = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(permit) = capacity.clone().try_acquire_owned() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking work releases admission permit");
        drop(permit);
    }

    #[test]
    fn paths_require_canonical_absolute_spelling() {
        let root = tempfile::tempdir().expect("tempdir");
        let service = service(root.path());
        for path in [
            "", "relative", "//x", "/x//y", "/x/", "/./x", "/x/../y", "/x\0y",
        ] {
            assert_eq!(
                service
                    .resolve(Some(path.to_string()))
                    .expect_err("invalid path")
                    .code(),
                Code::InvalidArgument
            );
        }
        assert_eq!(service.resolve(Some("/".to_string())).expect("root").0, "/");
        assert_eq!(
            service.resolve(Some("/x/y".to_string())).expect("path").0,
            "/x/y"
        );
    }

    #[test]
    fn entry_uses_lstat_and_reports_root_name_and_masked_mode() {
        let root = tempfile::tempdir().expect("tempdir");
        let file = root.path().join("file");
        fs::write(&file, b"data").expect("write file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o10644)).expect("chmod file");
        symlink(&file, root.path().join("link")).expect("symlink");

        let root_entry = entry("/", root.path()).expect("root entry");
        assert_eq!(root_entry.name.as_deref(), Some("/"));
        let link = entry("/link", &root.path().join("link")).expect("link entry");
        assert_eq!(
            link.kind,
            Some(protocol::v1::FilesystemEntryKind::Symlink as i32)
        );
        let file_entry = entry("/file", &file).expect("file entry");
        assert_eq!(file_entry.mode, Some(0o10644 & MODE_MASK));
    }

    #[test]
    fn list_sorts_utf8_bytes_and_binds_versioned_cursor() {
        let root = tempfile::tempdir().expect("tempdir");
        fs::write(root.path().join("z"), b"").expect("z");
        fs::write(root.path().join("a"), b"").expect("a");
        fs::write(root.path().join("é"), b"").expect("accent");
        let first = list("agent-a", "/", root.path(), 2, Vec::new()).expect("first page");
        assert_eq!(
            first
                .entries
                .iter()
                .filter_map(|item| item.name.as_deref())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        let cursor = first.next_cursor.clone().expect("next cursor");
        let second = list("agent-a", "/", root.path(), 2, cursor.clone()).expect("second page");
        assert_eq!(second.entries[0].name.as_deref(), Some("é"));
        assert_eq!(
            list("agent-b", "/", root.path(), 2, Vec::new())
                .expect("fresh page")
                .entries
                .len(),
            2
        );
        let stale = list("agent-b", "/", root.path(), 2, cursor).expect_err("stale cursor");
        assert_eq!(stale.code(), Code::FailedPrecondition);
        assert_eq!(
            list("agent-a", "/", root.path(), 2, b"bad".to_vec())
                .expect_err("bad cursor")
                .code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn listing_non_utf8_names_fails() {
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().expect("tempdir");
        fs::write(
            root.path().join(std::ffi::OsString::from_vec(vec![0xff])),
            b"",
        )
        .expect("write");
        assert_eq!(
            list("agent-a", "/", root.path(), 1, Vec::new())
                .expect_err("non utf8")
                .code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn upload_replaces_only_regular_files_and_preserves_omitted_mode() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = root.path().join("file");
        fs::write(&target, b"old").expect("write old file");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).expect("chmod old file");
        let header = protocol::v1::UploadFileHeader {
            path: Some("/file".to_string()),
            mode: None,
            uid: None,
            gid: None,
        };
        let mut upload = prepare_upload(target.clone(), header).expect("prepare upload");
        upload
            .file
            .as_mut()
            .expect("temporary file")
            .write_all(b"new")
            .expect("write upload");
        assert!(upload.commit().expect("commit upload"));
        assert_eq!(fs::read(&target).expect("read replacement"), b"new");
        assert_eq!(
            fs::metadata(&target).expect("metadata").mode() & MODE_MASK,
            0o640
        );

        let directory_header = protocol::v1::UploadFileHeader {
            path: Some("/directory".to_string()),
            mode: None,
            uid: None,
            gid: None,
        };
        fs::create_dir(root.path().join("directory")).expect("create directory");
        assert_eq!(
            prepare_upload(root.path().join("directory"), directory_header)
                .err()
                .expect("directory upload must fail")
                .code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn upload_holds_the_resolved_parent_across_path_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        fs::create_dir(&parent).expect("create parent");
        let target = parent.join("file");
        let header = protocol::v1::UploadFileHeader {
            path: Some("/parent/file".to_string()),
            mode: None,
            uid: None,
            gid: None,
        };
        let mut upload = prepare_upload(target, header).expect("prepare upload");
        upload
            .file
            .as_mut()
            .expect("temporary file")
            .write_all(b"new")
            .expect("write upload");

        let held_parent = root.path().join("held-parent");
        fs::rename(&parent, &held_parent).expect("replace parent");
        fs::create_dir(&parent).expect("create replacement parent");

        assert!(!upload.commit().expect("commit upload"));
        assert_eq!(
            fs::read(held_parent.join("file")).expect("read held file"),
            b"new"
        );
        assert!(!parent.join("file").exists());
    }

    #[test]
    fn uploads_follow_intermediate_parent_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let actual = root.path().join("actual");
        fs::create_dir(&actual).expect("create actual parent");
        let link = root.path().join("parent");
        symlink("actual", &link).expect("symlink parent");
        let header = protocol::v1::UploadFileHeader {
            path: Some("/parent/file".to_string()),
            mode: None,
            uid: None,
            gid: None,
        };
        let mut upload = prepare_upload(link.join("file"), header).expect("prepare upload");
        upload
            .file
            .as_mut()
            .expect("temporary file")
            .write_all(b"new")
            .expect("write upload");
        assert!(!upload.commit().expect("commit upload"));
        assert_eq!(fs::read(actual.join("file")).expect("read upload"), b"new");
    }

    #[test]
    fn child_metadata_uses_the_held_directory_after_path_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        fs::create_dir(&parent).expect("create parent");
        fs::write(parent.join("child"), b"old").expect("write child");
        let directory = open_directory_no_follow(&parent).expect("open parent");

        let held_parent = root.path().join("held-parent");
        fs::rename(&parent, &held_parent).expect("replace parent");
        fs::create_dir(&parent).expect("create replacement parent");
        fs::create_dir(parent.join("child")).expect("create replacement child");

        let child = entry_at("/parent/child", &directory, "child").expect("held child metadata");
        assert_eq!(
            child.kind,
            Some(protocol::v1::FilesystemEntryKind::File as i32)
        );
    }

    #[test]
    fn no_follow_download_and_recursive_remove_do_not_follow_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside");
        let outside_file = outside.path().join("kept");
        fs::write(&outside_file, b"keep").expect("write outside file");
        let link = root.path().join("link");
        symlink(&outside_file, &link).expect("symlink");
        assert_eq!(
            open_no_follow(&link, false)
                .expect_err("symlink must not open")
                .code(),
            Code::FailedPrecondition
        );
        remove(&link, true).expect("remove symlink");
        assert!(outside_file.exists());

        let directory = root.path().join("directory");
        fs::create_dir(&directory).expect("create directory");
        symlink(outside.path(), directory.join("outside")).expect("nested symlink");
        remove(&directory, true).expect("remove directory tree");
        assert!(outside_file.exists());
    }

    #[test]
    fn directory_creation_accepts_existing_directories_but_not_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let directory = root.path().join("directory");
        fs::create_dir(&directory).expect("create directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("set existing directory mode");
        assert!(!create_directory(
            root.path(),
            &directory,
            protocol::v1::CreateDirectoryRequest {
                path: Some("/directory".to_string()),
                parents: Some(false),
                mode: Some(0o750),
                uid: None,
                gid: None,
            },
        )
        .expect("existing directory"));
        assert_eq!(
            fs::metadata(&directory).expect("metadata").mode() & MODE_MASK,
            0o700
        );

        let file = root.path().join("file");
        fs::write(&file, b"").expect("write file");
        assert_eq!(
            create_directory(
                root.path(),
                &file,
                protocol::v1::CreateDirectoryRequest {
                    path: Some("/file".to_string()),
                    parents: Some(true),
                    mode: None,
                    uid: None,
                    gid: None,
                },
            )
            .expect_err("file cannot become directory")
            .code(),
            Code::FailedPrecondition
        );
    }

    #[test]
    fn directory_creation_with_parents_follows_intermediate_symlinks() {
        let root = tempfile::tempdir().expect("tempdir");
        let actual = root.path().join("actual");
        fs::create_dir(&actual).expect("create actual parent");
        let link = root.path().join("parent");
        symlink("actual", &link).expect("symlink parent");

        assert!(create_directory(
            root.path(),
            &link.join("missing/created"),
            protocol::v1::CreateDirectoryRequest {
                path: Some("/parent/missing/created".to_string()),
                parents: Some(true),
                mode: Some(0o750),
                uid: None,
                gid: None,
            },
        )
        .expect("create directory"));
        assert!(actual.join("missing/created").is_dir());
        assert_eq!(
            fs::metadata(actual.join("missing/created"))
                .expect("metadata")
                .mode()
                & MODE_MASK,
            0o750
        );
    }

    #[test]
    fn remove_and_create_hold_the_parent_across_path_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        fs::create_dir(&parent).expect("create parent");
        fs::write(parent.join("remove"), b"held").expect("write held file");
        let held_parent = open_directory_no_follow(&parent).expect("open parent");

        let original_parent = root.path().join("original-parent");
        fs::rename(&parent, &original_parent).expect("replace parent");
        fs::create_dir(&parent).expect("create replacement parent");
        fs::write(parent.join("remove"), b"replacement").expect("write replacement file");

        remove_at(&held_parent, "remove", false).expect("remove held file");
        assert!(!original_parent.join("remove").exists());
        assert_eq!(
            fs::read(parent.join("remove")).expect("read replacement"),
            b"replacement"
        );

        create_directory_at(
            &held_parent,
            "created",
            protocol::v1::CreateDirectoryRequest {
                path: Some("/parent/created".to_string()),
                parents: Some(false),
                mode: Some(0o750),
                uid: None,
                gid: None,
            },
        )
        .expect("create held directory");
        assert!(original_parent.join("created").is_dir());
        assert!(!parent.join("created").exists());
    }
}

//! Managed raw and qcow2 disk import.
//!
//! ```text
//!  caller path ──► OpenDiskSource::open: one O_NOFOLLOW open, classify by
//!                  bytes, qcow2 admission, source fingerprint
//!      │
//!      ▼ begin_stopped_operation("import"): original operation OFD
//!  blocking worker (owns a duplicate of that OFD and the catalog)
//!      raw:   held fd ─copy+verify─► pool stream ─authenticate, SHA-256─┐
//!      qcow2: SHA-256(container); decode ─SparseSink─► op staging ──────┤
//!                                                                       ▼
//!             owned bytes: table (StrictImport) → Linux table policy →
//!             concrete selector → bounded ext4 superblock admission
//!      qcow2: owned staging ─copy+verify─► pool stream
//!      publish_map ─► SnapshotRoot (stream, map, pages: operation-pinned)
//!      │
//!      ▼
//!  direct_boot_profile → pin_image_boot (same operation) → ImageRecord
//!      ▼
//!  ManagedImageStore::publish_owned (the original OFD moves into its worker)
//! ```
//!
//! Identity is computed over decoded raw bytes and canonical semantics only.
//! The source path, container encoding and timestamps are provenance.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use disk_partition::{PartitionTable, ReadMode, SECTOR_SIZE};

use crate::image::import_types::{
    DiskImportBoot, DiskImportFacts, DiskImportRequest, ImageProvenance, ImportRootSelection,
    ManagedImageInfo, RootCandidate, RootSelectionFailed,
};
use crate::image::local_disk::{AdmittedInput, OpenDiskSource};
use crate::paths::OwnedDirectory;
use crate::storage::identity::ObjectDigest;
use crate::storage::pool::{OperationPaths, StoragePool};
use crate::storage::stream::{write_sparse_at, StreamHasher};
use crate::storage::StorageError;
use crate::store::managed_image_store::ManagedImageStore;
use crate::store::models::image::{ImageRecord, ImageRecordKind};
use crate::store::models::snapshot::{SnapshotRoot, SnapshotRootProfile};
use crate::store::models::storage::{GuestArchitecture, RawLayout, RootSelector};
use crate::store::Store;
use crate::LibVmError;

/// A caller-owned disk that cannot become an admitted managed image.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiskImportError {
    #[error("could not open disk image {}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("disk image {} is a symbolic link; import its target path explicitly", path.display())]
    SymbolicLink { path: PathBuf },
    #[error("disk image {} is not a regular file; block devices and special files are not imported", path.display())]
    NotRegularFile { path: PathBuf },
    #[error("could not read disk image {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("disk image {} is a {container} container; convert it to raw or qcow2 offline before import", path.display())]
    UnsupportedContainer {
        path: PathBuf,
        container: ForeignContainer,
    },
    #[error("raw disk image {} has {}; expected a positive multiple of 512 up to 1 TiB", path.display(), utils::format_storage_size(*length))]
    RawGeometry { path: PathBuf, length: u64 },
    #[error("qcow2 disk image {} is not admitted", path.display())]
    Qcow2 {
        path: PathBuf,
        #[source]
        source: disk_image::qcow2::Error,
    },
    #[error("disk image {} changed during import; quiesce every writer and retry", path.display())]
    SourceChanged { path: PathBuf },
    #[error("decoded disk has {}, outside the admitted partition geometry", utils::format_storage_size(*length))]
    DecodedGeometry { length: u64 },
    #[error("decoded disk partition table is not admitted")]
    PartitionTable(#[source] disk_partition::Error<std::io::Error>),
    #[error(transparent)]
    DirectTable(#[from] disk_partition::DirectTableError),
    #[error(transparent)]
    RootFilesystem(#[from] crate::image::ext4_admission::Ext4Rejection),
    #[error("decoded disk stream has {}, expected exactly {}", utils::format_storage_size(*actual), utils::format_storage_size(*expected))]
    OutputLength { expected: u64, actual: u64 },
    #[error("owned disk copy space requires {}, available {} (short by {})", utils::format_storage_size(*required), utils::format_storage_size(*available), utils::format_storage_size(required.saturating_sub(*available)))]
    Capacity { required: u64, available: u64 },
}

impl From<DiskImportError> for LibVmError {
    fn from(error: DiskImportError) -> Self {
        LibVmError::DiskImport(Box::new(error))
    }
}

/// Recognized disk containers outside the admitted raw/qcow2 import set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForeignContainer {
    Vmdk,
    Vhd,
    Vhdx,
    Vdi,
    Qed,
    Luks,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

impl fmt::Display for ForeignContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Vmdk => "VMDK",
            Self::Vhd => "VHD",
            Self::Vhdx => "VHDX",
            Self::Vdi => "VDI",
            Self::Qed => "QED",
            Self::Luks => "LUKS encrypted",
            Self::Gzip => "gzip compressed",
            Self::Xz => "xz compressed",
            Self::Zstd => "zstd compressed",
            Self::Bzip2 => "bzip2 compressed",
        })
    }
}

/// Operation-pinned owned root of an import, before boot pinning and catalog
/// publication. A failed or abandoned import leaves only operation-pinned
/// pool content for existing abandoned-operation recovery, never an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedDiskRoot {
    pub(crate) root: SnapshotRoot,
    pub(crate) selector: RootSelector,
    pub(crate) provenance: ImageProvenance,
}

/// A structurally admitted disk request with its one held source descriptor.
/// Create this before opening a writable runtime to reject malformed sources
/// without initialization/recovery effects. Not cloneable: the descriptor is
/// transferred into the actual import worker, never reopened by path.
#[derive(Debug)]
pub struct AdmittedDiskImport {
    request: DiskImportRequest,
    source: OpenDiskSource,
}

impl DiskImportRequest {
    /// Validates platform, selector and container/geometry before any owned
    /// state is opened. The caller must keep all source writers quiesced.
    pub async fn admit(self) -> Result<AdmittedDiskImport, LibVmError> {
        tokio::task::spawn_blocking(move || {
            let DiskImportBoot::LinuxDirect { platform, root, .. } = &self.boot;
            platform.validate()?;
            validate_requested_root(root)?;
            let source = OpenDiskSource::open(&self.path)?;
            Ok(AdmittedDiskImport {
                request: self,
                source,
            })
        })
        .await?
    }
}

impl crate::image::Images {
    /// Imports a quiesced caller-owned raw or qcow2 disk as an immutable
    /// managed image with a complete pinned direct-boot bundle.
    ///
    /// The source must be a regular file that no process writes during the
    /// import. It is never modified, attached or retained: its decoded bytes
    /// are copied into Silo's pool and the source is checked for change.
    /// Symbolic links, devices, VMDK and other containers are rejected.
    ///
    /// The whole import runs in a spawned task that owns the runtime, the
    /// request, the registered operation's original OFD and its staging.
    /// Dropping the returned future detaches the caller only: protected work,
    /// boot pinning and publication either complete or leave a registered
    /// operation for existing abandoned-operation recovery.
    pub async fn import_disk(
        &self,
        request: DiskImportRequest,
    ) -> Result<ManagedImageInfo, LibVmError> {
        self.import_admitted_disk(request.admit().await?).await
    }

    /// Consumes a held source admitted before writable runtime initialization.
    pub async fn import_admitted_disk(
        &self,
        admitted: AdmittedDiskImport,
    ) -> Result<ManagedImageInfo, LibVmError> {
        let runtime = self.runtime.clone();
        tokio::spawn(import_disk_owned(runtime, admitted)).await?
    }
}

/// Runs only inside the owned task spawned by `import_admitted_disk`.
async fn import_disk_owned(
    runtime: crate::runtime::Runtime,
    admitted: AdmittedDiskImport,
) -> Result<ManagedImageInfo, LibVmError> {
    let AdmittedDiskImport { request, source } = admitted;
    let DiskImportRequest { boot, alias, .. } = request;
    let DiskImportBoot::LinuxDirect {
        platform,
        root,
        assets,
    } = boot;
    // Initialization may have taken time. The pre-runtime descriptor and
    // fingerprint remain authoritative, including across rename/replacement.
    source.ensure_unchanged()?;

    let store = runtime.native_store()?;
    let (operation_id, lease) = store.begin_stopped_operation("import", &[], &[]).await?;
    let pool = StoragePool::open(runtime.local_images_dir())?;
    let operation = pool.create_operation_with_lease(operation_id, lease.duplicate()?)?;
    let prepared = prepare_disk_root(
        source,
        root,
        platform.architecture,
        store.clone(),
        operation,
    )
    .await?;

    let intent = crate::runtime::boot_assets::direct_boot_profile(&platform, prepared.selector)?;
    let boot = crate::runtime::boot_assets::pin_image_boot(
        &intent,
        &assets,
        runtime.captured_boot_context(&pool, &store, operation_id),
    )
    .await?;
    let record = ImageRecord {
        schema: 1,
        kind: ImageRecordKind::Image,
        root: prepared.root,
        boot,
        process: crate::ProcessConfig::default(),
    };
    ManagedImageStore::from_store(Arc::new(store))
        .publish_owned(
            record,
            operation_id,
            lease,
            alias,
            vec![prepared.provenance],
            None,
        )
        .await
}

/// Structurally impossible selectors fail before any source byte is copied.
fn validate_requested_root(requested: &ImportRootSelection) -> Result<(), LibVmError> {
    let reason = match requested {
        ImportRootSelection::GptPartition { guid } if guid.is_nil() => {
            "a nil GPT unique partition GUID cannot identify a root partition"
        }
        ImportRootSelection::MbrPartition { number } if !(1..=4).contains(number) => {
            "MBR roots must be primary partitions 1..4; logical partitions are unsupported"
        }
        _ => return Ok(()),
    };
    Err(LibVmError::RootSelectionFailed(Box::new(
        RootSelectionFailed {
            requested: requested.clone(),
            candidates: Vec::new(),
            reason: reason.to_owned(),
        },
    )))
}

/// Decode or copy, admit and pool-publish the held source's root under a
/// registered operation. The real blocking worker owns a duplicate of the
/// operation OFD and the catalog, so cancelling the caller cannot unprotect
/// outputs while they are still being produced or read.
pub(crate) async fn prepare_disk_root(
    source: OpenDiskSource,
    requested: ImportRootSelection,
    userspace: GuestArchitecture,
    store: Store,
    operation: OperationPaths,
) -> Result<PreparedDiskRoot, LibVmError> {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let pool = StoragePool::open(&store.home_path().join("images"))?;
        // Admission and release execute in the real worker while it owns the
        // operation OFD. Losing an async waiter cannot release a live writer's
        // peak charge; process loss leaves the journal to retire it.
        let bytes = import_space_charge(&source)?;
        runtime.block_on(store.reserve_import_space(operation.id, bytes))?;
        let prepared = prepare_blocking(
            &runtime, &pool, &store, &operation, &source, &requested, userspace,
        );
        let release = runtime.block_on(store.release_import_space(operation.id));
        let prepared = match (prepared, release) {
            (Ok(prepared), Ok(())) => Ok(prepared),
            (Err(error), release) => {
                if let Err(release) = release {
                    tracing::warn!(operation = %operation.id, %release, "import space release requires recovery");
                }
                Err(error)
            }
            (Ok(_), Err(error)) => Err(error),
        };
        drop(operation);
        prepared
    })
    .await?
}

/// Logical worst case, independent of holes, reflink support or deduplication.
/// qcow2 decoding and immutable publication coexist; raw needs only the latter.
/// Private machine copies are a later, separately admitted ownership phase.
fn import_space_charge(source: &OpenDiskSource) -> Result<u64, LibVmError> {
    let length = source.decoded_length();
    let copies = match source.format() {
        AdmittedInput::Raw { .. } => 1,
        AdmittedInput::Qcow2(_) => 2,
    };
    let chunks = length.div_ceil(crate::storage::limits::CHUNK_SIZE as u64);
    let pages = chunks.div_ceil(crate::storage::map::MAP_PAGE_ENTRIES as u64);
    // Same conservative canonical map allowance used by capture admission,
    // including simultaneous object staging and final map objects.
    let maps = chunks
        .checked_mul(74)
        .and_then(|bytes| bytes.checked_add(pages.checked_mul(330)?))
        .and_then(|bytes| bytes.checked_add(256))
        .and_then(|bytes| bytes.checked_mul(2));
    length
        .checked_mul(copies)
        .and_then(|bytes| bytes.checked_add(maps?))
        .ok_or_else(|| crate::machine::root_storage::invalid("import space reservation overflow"))
}

fn prepare_blocking(
    runtime: &tokio::runtime::Handle,
    pool: &StoragePool,
    store: &Store,
    operation: &OperationPaths,
    source: &OpenDiskSource,
    requested: &ImportRootSelection,
    userspace: GuestArchitecture,
) -> Result<PreparedDiskRoot, LibVmError> {
    let length = source.decoded_length();
    let (map, owned, source_digest) = match source.format() {
        AdmittedInput::Raw { .. } => {
            // The duplicate shares the held open file; no path is resolved.
            let input = source.file().try_clone()?;
            let (published, roots) = pool
                .publish_stream_file_for_catalog(input, length)
                .map_err(|error| source.storage_error(error))?;
            runtime.block_on(store.pin_published_storage_dependencies(
                operation.id,
                &[published.id],
                &[],
            ))?;
            drop(roots);
            source.ensure_unchanged()?;
            // Facts come from the owned pool bytes, authenticated against the
            // published map, never from the caller's still-mutable file.
            let (owned, sha256) = StreamHasher::new()
                .authenticate_with_sha256(pool.open_stream(&published.id)?, length)?;
            if *owned.map() != published.map {
                return Err(StorageError::ContentMismatch(published.path).into());
            }
            let root = admit_owned_root(owned.file(), length, requested, userspace)?;
            // Raw container bytes are the decoded stream.
            let digest = ObjectDigest::from_sha256(*sha256.as_bytes());
            (published.map, root, digest)
        }
        AdmittedInput::Qcow2(admission) => {
            let digest = source.container_digest()?;
            let staging = DecodeStaging::create(&operation.temporary)?;
            let mut sink = SparseSink::new(&staging.file, length);
            disk_image::qcow2::decode(source.file(), admission, &mut sink)
                .map_err(|error| source.qcow2_error(error))?;
            sink.finish()?;
            source.ensure_unchanged()?;
            let root = admit_owned_root(&staging.file, length, requested, userspace)?;
            let (published, roots) =
                pool.publish_stream_file_for_catalog(staging.file.try_clone()?, length)?;
            runtime.block_on(store.pin_published_storage_dependencies(
                operation.id,
                &[published.id],
                &[],
            ))?;
            drop(roots);
            drop(staging);
            (published.map, root, digest)
        }
    };
    let stream = runtime.block_on(crate::store::snapshot_store::publish_map(
        pool,
        store,
        operation.id,
        &map,
    ))?;
    Ok(PreparedDiskRoot {
        root: SnapshotRoot {
            profile: SnapshotRootProfile::OpaqueRaw,
            stream,
            geometry: vm_spec::DiskGeometry {
                length,
                logical_sector_size: SECTOR_SIZE as u32,
            },
            layout: owned.layout,
        },
        selector: owned.selector,
        provenance: ImageProvenance {
            container: source.container(),
            source_digest,
            source_spelling: source.diagnostic_path().display().to_string(),
            source_manifest: None,
            source_config: None,
            disk: Some(DiskImportFacts {
                source_length: source.source_length(),
                decoded_length: length,
                selected_root: owned.observed,
            }),
        },
    })
}

/// Facts admitted from owned decoded bytes. The observed partition is a
/// diagnostic, never persisted device authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedRoot {
    layout: RawLayout,
    selector: RootSelector,
    observed: Option<RootCandidate>,
}

/// A concrete root and the byte range its filesystem must fit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedRoot {
    root: OwnedRoot,
    offset: u64,
    length: u64,
}

fn admit_owned_root(
    file: &File,
    length: u64,
    requested: &ImportRootSelection,
    userspace: GuestArchitecture,
) -> Result<OwnedRoot, LibVmError> {
    let geometry = disk_partition::Geometry::new(length)
        .map_err(|_| DiskImportError::DecodedGeometry { length })?;
    let table = disk_partition::read_table(&mut HeldRead(file), geometry, ReadMode::StrictImport)
        .map_err(DiskImportError::PartitionTable)?;
    disk_partition::validate_linux_direct_table(&table).map_err(DiskImportError::DirectTable)?;
    let selected = select_root(&table, requested, userspace, length)?;
    let facts = crate::image::ext4_admission::admit(file, selected.offset, selected.length)?;
    tracing::debug!(
        selector = ?selected.root.selector,
        block_size = facts.block_size,
        blocks = facts.blocks,
        "admitted imported ext4 root"
    );
    Ok(selected.root)
}

/// Positional reads of a held owned file; the shared cursor is never moved.
struct HeldRead<'a>(&'a File);

impl disk_partition::ReadAt for HeldRead<'_> {
    type Error = std::io::Error;

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
        std::os::unix::fs::FileExt::read_exact_at(self.0, output, offset)
    }
}

/// Exactly one disk-local candidate or a typed refusal listing candidates.
/// No largest/first choice, no compacted MBR numbering, no whole-disk
/// fallback for a partitioned disk and no global partition search.
fn select_root(
    table: &PartitionTable,
    requested: &ImportRootSelection,
    userspace: GuestArchitecture,
    disk_length: u64,
) -> Result<SelectedRoot, LibVmError> {
    let fail = |reason: String| {
        LibVmError::RootSelectionFailed(Box::new(RootSelectionFailed {
            requested: requested.clone(),
            candidates: candidates(table),
            reason,
        }))
    };
    let gpt_root = |partition: &disk_partition::GptPartition| {
        // DPS read-only marks a root the writable opaque profile cannot use.
        if partition.read_only() && is_dps_root_type(partition.type_guid()) {
            return Err(fail(format!(
                "DPS root partition {} is marked read-only; a writable root cannot use it",
                partition.unique_guid()
            )));
        }
        Ok(SelectedRoot {
            root: OwnedRoot {
                layout: RawLayout::Partitioned {
                    table: crate::store::models::storage::PartitionTable::Gpt,
                },
                selector: RootSelector::GptPartition {
                    guid: partition.unique_guid(),
                },
                observed: Some(gpt_candidate(partition)),
            },
            offset: partition.extent().byte_offset(),
            length: partition.extent().byte_length(),
        })
    };
    match (requested, table) {
        (ImportRootSelection::WholeDisk, PartitionTable::None) => Ok(SelectedRoot {
            root: OwnedRoot {
                layout: RawLayout::WholeDisk,
                selector: RootSelector::WholeDisk,
                observed: None,
            },
            offset: 0,
            length: disk_length,
        }),
        (ImportRootSelection::AutoGpt, PartitionTable::Gpt(gpt)) => gpt
            .select_dps_root(dps_root_type(userspace))
            .map_err(|error| fail(error.to_string()))
            .and_then(gpt_root),
        (ImportRootSelection::GptPartition { guid }, PartitionTable::Gpt(gpt)) => gpt
            .find_unique_guid(*guid)
            .map_err(|error| fail(error.to_string()))
            .and_then(gpt_root),
        (ImportRootSelection::MbrPartition { number }, PartitionTable::Mbr(mbr)) => {
            let partition = mbr
                .find_primary_slot(*number)
                .map_err(|error| fail(error.to_string()))?;
            Ok(SelectedRoot {
                root: OwnedRoot {
                    layout: RawLayout::Partitioned {
                        table: crate::store::models::storage::PartitionTable::Mbr,
                    },
                    selector: RootSelector::MbrPartition {
                        number: partition.slot(),
                    },
                    observed: Some(mbr_candidate(partition)),
                },
                offset: partition.extent().byte_offset(),
                length: partition.extent().byte_length(),
            })
        }
        (ImportRootSelection::WholeDisk, PartitionTable::Gpt(_)) => Err(fail(
            "disk has a GPT partition table; select gpt:GUID or auto, never the whole disk".into(),
        )),
        (ImportRootSelection::WholeDisk, PartitionTable::Mbr(_)) => Err(fail(
            "disk has an MBR partition table; select mbr:N, never the whole disk".into(),
        )),
        (_, PartitionTable::None) => Err(fail(
            "disk has no partition table; select whole-disk".into(),
        )),
        (_, PartitionTable::Mbr(_)) => Err(fail(
            "disk has an MBR partition table, not GPT; select mbr:N".into(),
        )),
        (_, PartitionTable::Gpt(_)) => Err(fail(
            "disk has a GPT partition table, not MBR; select gpt:GUID or auto".into(),
        )),
    }
}

/// DPS roots follow the declared userspace, never the host or kernel ISA.
fn dps_root_type(userspace: GuestArchitecture) -> uuid::Uuid {
    match userspace {
        GuestArchitecture::Amd64 => disk_partition::DPS_ROOT_AMD64,
        GuestArchitecture::Arm64 => disk_partition::DPS_ROOT_ARM64,
    }
}

fn is_dps_root_type(type_guid: uuid::Uuid) -> bool {
    type_guid == disk_partition::DPS_ROOT_AMD64 || type_guid == disk_partition::DPS_ROOT_ARM64
}

/// Observations bounded by the parser's 128-entry/4-slot limits. Extents are
/// diagnostics, not persisted root authority.
fn candidates(table: &PartitionTable) -> Vec<RootCandidate> {
    match table {
        PartitionTable::None => Vec::new(),
        PartitionTable::Gpt(gpt) => gpt.partitions().iter().map(gpt_candidate).collect(),
        PartitionTable::Mbr(mbr) => mbr.partitions().iter().map(mbr_candidate).collect(),
    }
}

fn gpt_candidate(partition: &disk_partition::GptPartition) -> RootCandidate {
    RootCandidate {
        selector: RootSelector::GptPartition {
            guid: partition.unique_guid(),
        },
        first_lba: partition.extent().first_lba(),
        length_lbas: partition.extent().byte_length() / SECTOR_SIZE,
        gpt_type: Some(partition.type_guid()),
        mbr_type: None,
        attributes: partition.attributes(),
    }
}

fn mbr_candidate(partition: &disk_partition::MbrPartition) -> RootCandidate {
    RootCandidate {
        selector: RootSelector::MbrPartition {
            number: partition.slot(),
        },
        first_lba: partition.extent().first_lba(),
        length_lbas: partition.extent().byte_length() / SECTOR_SIZE,
        gpt_type: None,
        mbr_type: Some(partition.partition_type()),
        attributes: 0,
    }
}

/// Private decode output inside the registered operation's staging. Removed
/// on drop; a partial decode is never published.
struct DecodeStaging {
    parent: OwnedDirectory,
    name: String,
    file: File,
}

impl DecodeStaging {
    fn create(temporary: &Path) -> Result<Self, LibVmError> {
        let parent = OwnedDirectory::open_existing_root(temporary)?.ok_or_else(|| {
            LibVmError::InvalidStorageRecord {
                record: "disk-import",
                message: "registered import staging is missing".to_owned(),
            }
        })?;
        let name = format!("decoded-{}", uuid::Uuid::new_v4());
        let fd = nix::fcntl::openat(
            parent.fd(),
            name.as_str(),
            nix::fcntl::OFlag::O_RDWR
                | nix::fcntl::OFlag::O_CREAT
                | nix::fcntl::OFlag::O_EXCL
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .map_err(std::io::Error::from)?;
        Ok(Self {
            parent,
            name,
            file: File::from(fd),
        })
    }
}

impl Drop for DecodeStaging {
    fn drop(&mut self) {
        if let Err(error) = self.parent.remove_tree(&self.name) {
            tracing::warn!(%error, "decoded import staging cleanup deferred");
        }
    }
}

/// Decoder sink over a fresh empty staging file. All-zero 4 KiB blocks stay
/// holes; `finish` establishes the exact length, including trailing zeros.
/// Only the decoder's current chunk is ever in memory.
struct SparseSink<'a> {
    file: &'a File,
    offset: u64,
    length: u64,
}

impl<'a> SparseSink<'a> {
    fn new(file: &'a File, length: u64) -> Self {
        Self {
            file,
            offset: 0,
            length,
        }
    }

    fn finish(self) -> Result<(), LibVmError> {
        if self.offset != self.length {
            return Err(DiskImportError::OutputLength {
                expected: self.length,
                actual: self.offset,
            }
            .into());
        }
        self.file.set_len(self.length)?;
        self.file.sync_all()?;
        let actual = self.file.metadata()?.len();
        if actual != self.length {
            return Err(DiskImportError::OutputLength {
                expected: self.length,
                actual,
            }
            .into());
        }
        Ok(())
    }
}

impl Write for SparseSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decoded stream exceeds its admitted length",
                )
            })?;
        write_sparse_at(self.file, bytes, self.offset)?;
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::image::ext4_admission::Ext4Rejection;
    use crate::image::import::{
        admit_owned_root, prepare_disk_root, validate_requested_root, DiskImportError, OwnedRoot,
        PreparedDiskRoot, SparseSink,
    };
    use crate::image::import_types::{
        DiskImportFacts, ImageContainerKind, ImportRootSelection, RootCandidate,
        RootSelectionFailed,
    };
    use crate::image::local_disk::OpenDiskSource;
    use crate::paths::LocalPaths;
    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::StoragePool;
    use crate::store::models::storage::{
        GuestArchitecture, PartitionTable, RawLayout, RootSelector,
    };
    use crate::store::Store;
    use crate::LibVmError;

    const SECTOR: u64 = 512;
    const ESP: Uuid = Uuid::from_u128(0xc12a7328_f81f_11d2_ba4b_00a0c93ec93b);
    const ESP_GUID: Uuid = Uuid::from_u128(0x11111111_2222_4333_8444_555555555555);
    const ROOT_GUID: Uuid = Uuid::from_u128(0x01234567_89ab_4def_8123_456789abcdef);
    const OTHER_GUID: Uuid = Uuid::from_u128(0x99999999_8888_4777_8666_555555555555);
    const ROOT_LBA: u64 = 4096;

    #[test]
    fn import_size_errors_are_human_readable() {
        assert_eq!(
            DiskImportError::Capacity {
                required: (1 << 30) + 1,
                available: 1 << 30,
            }
            .to_string(),
            "owned disk copy space requires 1.0GiB, available 1GiB (short by 1B)"
        );
        assert_eq!(
            DiskImportError::OutputLength {
                expected: 2 << 20,
                actual: 1 << 20,
            }
            .to_string(),
            "decoded disk stream has 1MiB, expected exactly 2MiB"
        );
        assert_eq!(
            DiskImportError::DecodedGeometry { length: 0 }.to_string(),
            "decoded disk has 0B, outside the admitted partition geometry"
        );
    }

    fn put(bytes: &mut [u8], offset: u64, data: &[u8]) {
        let at = offset as usize;
        bytes[at..at + data.len()].copy_from_slice(data);
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    /// Independent test-only qcow2 v3 encoder: 64 KiB clusters, one plain
    /// data cluster per nonzero guest cluster, consistent refcounts.
    pub(crate) fn qcow2_image(raw: &[u8]) -> Vec<u8> {
        const BITS: u32 = 16;
        const CLUSTER: u64 = 1 << BITS;
        const COPIED: u64 = 1 << 63;
        assert!(!raw.is_empty() && raw.len().is_multiple_of(512));
        let size = raw.len() as u64;
        let l2_entries = CLUSTER / 8;
        let l1_size = size.div_ceil(CLUSTER).div_ceil(l2_entries);
        let l1_clusters = (l1_size * 8).div_ceil(CLUSTER).max(1);
        let l1_offset = CLUSTER;
        let refcount_table_offset = (1 + l1_clusters) * CLUSTER;
        let mut next = 2 + l1_clusters;
        let data: Vec<(u64, &[u8])> = raw
            .chunks(CLUSTER as usize)
            .enumerate()
            .filter(|(_, chunk)| chunk.iter().any(|byte| *byte != 0))
            .map(|(index, chunk)| (index as u64, chunk))
            .collect();
        let mut l2_offsets = std::collections::BTreeMap::new();
        for (guest, _) in &data {
            l2_offsets.entry(guest / l2_entries).or_insert_with(|| {
                next += 1;
                (next - 1) * CLUSTER
            });
        }
        let mut hosts = Vec::new();
        for (guest, chunk) in &data {
            hosts.push((*guest, next * CLUSTER, *chunk));
            next += 1;
        }
        let refcount_block = next;
        let total = next + 1;
        assert!(
            total <= (CLUSTER * 8) >> 4,
            "fixture needs one refcount block"
        );

        let mut bytes = vec![0; (total * CLUSTER) as usize];
        put(&mut bytes, 0, b"QFI\xfb");
        put(&mut bytes, 4, &3_u32.to_be_bytes());
        put(&mut bytes, 20, &BITS.to_be_bytes());
        put(&mut bytes, 24, &size.to_be_bytes());
        put(
            &mut bytes,
            36,
            &u32::try_from(l1_size).unwrap().to_be_bytes(),
        );
        put(&mut bytes, 40, &l1_offset.to_be_bytes());
        put(&mut bytes, 48, &refcount_table_offset.to_be_bytes());
        put(&mut bytes, 56, &1_u32.to_be_bytes());
        put(&mut bytes, 96, &4_u32.to_be_bytes());
        put(&mut bytes, 100, &112_u32.to_be_bytes());
        for (index, offset) in &l2_offsets {
            put(
                &mut bytes,
                l1_offset + index * 8,
                &(offset | COPIED).to_be_bytes(),
            );
        }
        for (guest, host, chunk) in hosts {
            let table = l2_offsets[&(guest / l2_entries)];
            put(
                &mut bytes,
                table + (guest % l2_entries) * 8,
                &(host | COPIED).to_be_bytes(),
            );
            put(&mut bytes, host, chunk);
        }
        put(
            &mut bytes,
            refcount_table_offset,
            &(refcount_block * CLUSTER).to_be_bytes(),
        );
        for cluster in 0..total {
            put(
                &mut bytes,
                refcount_block * CLUSTER + cluster * 2,
                &1_u16.to_be_bytes(),
            );
        }
        bytes
    }

    fn ext4_bytes() -> Vec<u8> {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("root.ext4");
        disk_image::ext4::Formatter::new(&path, 4096, 256 * 1024)
            .unwrap()
            .close()
            .unwrap();
        std::fs::read(path).unwrap()
    }

    struct GptEntry {
        type_guid: Uuid,
        unique: Uuid,
        first_lba: u64,
        attributes: u64,
        content: Vec<u8>,
    }

    fn esp() -> GptEntry {
        GptEntry {
            type_guid: ESP,
            unique: ESP_GUID,
            first_lba: 2048,
            attributes: 0,
            content: vec![0; 1 << 20],
        }
    }

    fn dps_root(unique: Uuid, first_lba: u64, attributes: u64, content: &[u8]) -> GptEntry {
        GptEntry {
            type_guid: disk_partition::DPS_ROOT_AMD64,
            unique,
            first_lba,
            attributes,
            content: content.to_vec(),
        }
    }

    /// Independent GPT writer: protective MBR, both headers and arrays, CRCs.
    fn gpt_disk(entry_size: u32, entries: &[GptEntry]) -> Vec<u8> {
        let end = entries
            .iter()
            .map(|entry| entry.first_lba + entry.content.len() as u64 / SECTOR)
            .max()
            .unwrap();
        let sectors = end + 2048;
        let mut disk = vec![0; (sectors * SECTOR) as usize];
        for entry in entries {
            put(&mut disk, entry.first_lba * SECTOR, &entry.content);
        }
        let mut record = [0; 16];
        record[4] = 0xee;
        record[8..12].copy_from_slice(&1_u32.to_le_bytes());
        record[12..16].copy_from_slice(&u32::try_from(sectors - 1).unwrap().to_le_bytes());
        put(&mut disk, 446, &record);
        put(&mut disk, 510, &[0x55, 0xaa]);

        let count = 128_u32;
        let array_bytes = u64::from(count) * u64::from(entry_size);
        let reserved = array_bytes.max(16_384).div_ceil(SECTOR);
        let mut array = vec![0; array_bytes as usize];
        for (index, entry) in entries.iter().enumerate() {
            let at = (index as u64) * u64::from(entry_size);
            let last = entry.first_lba + entry.content.len() as u64 / SECTOR - 1;
            put(&mut array, at, &entry.type_guid.to_bytes_le());
            put(&mut array, at + 16, &entry.unique.to_bytes_le());
            put(&mut array, at + 32, &entry.first_lba.to_le_bytes());
            put(&mut array, at + 40, &last.to_le_bytes());
            put(&mut array, at + 48, &entry.attributes.to_le_bytes());
        }
        let array_crc = crc32(&array);
        let disk_guid = Uuid::from_u128(0xdddddddd_eeee_4fff_8000_111111111111);
        for (lba, alternate, array_lba) in [
            (1, sectors - 1, 2),
            (sectors - 1, 1, sectors - 1 - reserved),
        ] {
            let mut header = [0; 512];
            put(&mut header, 0, b"EFI PART");
            put(&mut header, 8, &0x0001_0000_u32.to_le_bytes());
            put(&mut header, 12, &92_u32.to_le_bytes());
            put(&mut header, 24, &u64::to_le_bytes(lba));
            put(&mut header, 32, &u64::to_le_bytes(alternate));
            put(&mut header, 40, &(2 + reserved).to_le_bytes());
            put(&mut header, 48, &(sectors - 2 - reserved).to_le_bytes());
            put(&mut header, 56, &disk_guid.to_bytes_le());
            put(&mut header, 72, &u64::to_le_bytes(array_lba));
            put(&mut header, 80, &count.to_le_bytes());
            put(&mut header, 84, &entry_size.to_le_bytes());
            put(&mut header, 88, &array_crc.to_le_bytes());
            let crc = crc32(&header[..92]);
            put(&mut header, 16, &crc.to_le_bytes());
            put(&mut disk, lba * SECTOR, &header);
            put(&mut disk, array_lba * SECTOR, &array);
        }
        disk
    }

    /// Primary MBR with one partition in an original, possibly sparse, slot.
    fn mbr_disk(slot: u8, partition_type: u8, first_lba: u64, content: &[u8]) -> Vec<u8> {
        let sectors = first_lba + content.len() as u64 / SECTOR + 2048;
        let mut disk = vec![0; (sectors * SECTOR) as usize];
        put(&mut disk, first_lba * SECTOR, content);
        let record = 446 + (u64::from(slot) - 1) * 16;
        disk[record as usize + 4] = partition_type;
        put(
            &mut disk,
            record + 8,
            &u32::try_from(first_lba).unwrap().to_le_bytes(),
        );
        let length = u32::try_from(content.len() as u64 / SECTOR).unwrap();
        put(&mut disk, record + 12, &length.to_le_bytes());
        put(&mut disk, 510, &[0x55, 0xaa]);
        disk
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn held(path: &Path) -> (std::fs::File, u64) {
        let file = std::fs::File::open(path).unwrap();
        let length = file.metadata().unwrap().len();
        (file, length)
    }

    fn chosen(result: Result<OwnedRoot, LibVmError>) -> (RawLayout, RootSelector) {
        let root = result.unwrap();
        (root.layout, root.selector)
    }

    fn gpt_choice(guid: Uuid) -> (RawLayout, RootSelector) {
        (
            RawLayout::Partitioned {
                table: PartitionTable::Gpt,
            },
            RootSelector::GptPartition { guid },
        )
    }

    fn selection_failure(result: Result<OwnedRoot, LibVmError>) -> RootSelectionFailed {
        match result {
            Err(LibVmError::RootSelectionFailed(failure)) => *failure,
            other => panic!("expected root selection failure, got {other:?}"),
        }
    }

    fn import_error(result: Result<OwnedRoot, LibVmError>) -> DiskImportError {
        match result {
            Err(LibVmError::DiskImport(error)) => *error,
            other => panic!("expected disk import error, got {other:?}"),
        }
    }

    async fn catalog() -> (tempfile::TempDir, Store) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        (temp, store)
    }

    #[test]
    fn raw_and_qcow2_capacity_charges_cover_their_distinct_simultaneous_copies() {
        let temporary = tempfile::tempdir().unwrap();
        let raw = ext4_bytes();
        let raw_path = write(temporary.path(), "root.raw", &raw);
        let qcow_path = write(temporary.path(), "root.qcow2", &qcow2_image(&raw));
        let raw_source = OpenDiskSource::open(&raw_path).unwrap();
        let qcow_source = OpenDiskSource::open(&qcow_path).unwrap();
        let raw_charge = crate::image::import::import_space_charge(&raw_source).unwrap();
        let qcow_charge = crate::image::import::import_space_charge(&qcow_source).unwrap();
        assert!(
            raw_charge > raw.len() as u64,
            "publication includes map objects"
        );
        assert_eq!(
            qcow_charge - raw_charge,
            raw.len() as u64,
            "decoded qcow2 staging coexists with the immutable publication copy"
        );
    }

    async fn prepare_source(
        store: &Store,
        source: OpenDiskSource,
        requested: ImportRootSelection,
    ) -> (Result<PreparedDiskRoot, LibVmError>, PathBuf) {
        let pool = StoragePool::open(&store.home_path().join("images")).unwrap();
        let (operation_id, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let operation = pool
            .create_operation_with_lease(operation_id, lease.duplicate().unwrap())
            .unwrap();
        let temporary = operation.temporary.clone();
        let prepared = prepare_disk_root(
            source,
            requested,
            GuestArchitecture::Amd64,
            store.clone(),
            operation,
        )
        .await;
        let reserved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM capture_resource_reservation WHERE operation_id=?1)",
        )
        .bind(operation_id.to_string())
        .fetch_one(store.test_pool())
        .await
        .unwrap();
        assert!(
            !reserved,
            "a completed root worker releases its peak on success or refusal"
        );
        drop(lease);
        (prepared, temporary)
    }

    async fn prepare(
        store: &Store,
        path: &Path,
        requested: ImportRootSelection,
    ) -> (Result<PreparedDiskRoot, LibVmError>, PathBuf) {
        prepare_source(store, OpenDiskSource::open(path).unwrap(), requested).await
    }

    fn pool_bytes(store: &Store, prepared: &PreparedDiskRoot) -> Vec<u8> {
        let pool = StoragePool::open(&store.home_path().join("images")).unwrap();
        let mut bytes = Vec::new();
        pool.open_stream(&prepared.root.stream.stream)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }

    fn sha256(bytes: &[u8]) -> ObjectDigest {
        ObjectDigest::from_sha256(Sha256::digest(bytes).into())
    }

    #[tokio::test]
    async fn raw_and_qcow2_of_the_same_bytes_prepare_the_same_owned_root() {
        let (temp, store) = catalog().await;
        let raw = ext4_bytes();
        let qcow2 = qcow2_image(&raw);
        let raw_path = write(temp.path(), "root.raw", &raw);
        let qcow2_path = write(temp.path(), "root.qcow2", &qcow2);

        let (from_raw, _) = prepare(&store, &raw_path, ImportRootSelection::WholeDisk).await;
        let from_raw = from_raw.unwrap();
        let (from_qcow2, staging) =
            prepare(&store, &qcow2_path, ImportRootSelection::WholeDisk).await;
        let from_qcow2 = from_qcow2.unwrap();

        assert_eq!(
            from_raw.root, from_qcow2.root,
            "identity ignores the container"
        );
        assert_eq!(from_raw.selector, RootSelector::WholeDisk);
        assert_eq!(from_raw.root.layout, RawLayout::WholeDisk);
        assert_eq!(from_raw.root.geometry.length, raw.len() as u64);
        assert_eq!(from_raw.root.geometry.logical_sector_size, 512);
        assert_eq!(from_raw.root.stream.length, raw.len() as u64);
        assert_eq!(from_raw.provenance.container, ImageContainerKind::Raw);
        assert_eq!(from_raw.provenance.source_digest, sha256(&raw));
        assert_eq!(
            from_raw.provenance.source_spelling,
            raw_path.display().to_string()
        );
        assert_eq!(
            from_raw.provenance.disk,
            Some(DiskImportFacts {
                source_length: raw.len() as u64,
                decoded_length: raw.len() as u64,
                selected_root: None,
            })
        );
        assert_eq!(from_qcow2.provenance.container, ImageContainerKind::Qcow2);
        assert_eq!(from_qcow2.provenance.source_digest, sha256(&qcow2));
        assert_eq!(
            from_qcow2.provenance.disk,
            Some(DiskImportFacts {
                source_length: qcow2.len() as u64,
                decoded_length: raw.len() as u64,
                selected_root: None,
            })
        );
        assert_eq!(pool_bytes(&store, &from_raw), raw);
        assert_eq!(pool_bytes(&store, &from_qcow2), raw);

        assert!(
            std::fs::read_dir(staging).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("decoded-")),
            "decoded staging never outlives publication"
        );
        assert_eq!(std::fs::read(&raw_path).unwrap(), raw, "sources unchanged");
        assert_eq!(std::fs::read(&qcow2_path).unwrap(), qcow2);
    }

    #[tokio::test]
    async fn gpt_roots_are_selected_by_unique_guid_or_declared_dps_type() {
        let (temp, store) = catalog().await;
        let ext4 = ext4_bytes();
        let disk = gpt_disk(128, &[esp(), dps_root(ROOT_GUID, ROOT_LBA, 0, &ext4)]);
        let raw_path = write(temp.path(), "cloud.img", &disk);
        let qcow2_path = write(temp.path(), "cloud.qcow2", &qcow2_image(&disk));

        let (auto, _) = prepare(&store, &raw_path, ImportRootSelection::AutoGpt).await;
        let auto = auto.unwrap();
        assert_eq!(
            (auto.root.layout.clone(), auto.selector.clone()),
            gpt_choice(ROOT_GUID),
            "auto persists the concrete unique GUID, never `auto`"
        );
        let observed = auto
            .provenance
            .disk
            .as_ref()
            .and_then(|facts| facts.selected_root.clone())
            .unwrap();
        assert_eq!(observed.first_lba, ROOT_LBA);
        assert_eq!(observed.length_lbas, ext4.len() as u64 / SECTOR);
        assert_eq!(observed.gpt_type, Some(disk_partition::DPS_ROOT_AMD64));

        let (explicit, _) = prepare(
            &store,
            &qcow2_path,
            ImportRootSelection::GptPartition { guid: ROOT_GUID },
        )
        .await;
        let explicit = explicit.unwrap();
        assert_eq!(explicit.root, auto.root);
        assert_eq!(explicit.selector, auto.selector);
        assert_eq!(pool_bytes(&store, &explicit), disk);
    }

    #[test]
    fn gpt_refusals_are_typed_and_list_every_disk_local_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let ext4 = ext4_bytes();
        let disk = gpt_disk(128, &[esp(), dps_root(ROOT_GUID, ROOT_LBA, 0, &ext4)]);
        let (file, length) = held(&write(temp.path(), "cloud.img", &disk));
        let expected = vec![
            RootCandidate {
                selector: RootSelector::GptPartition { guid: ESP_GUID },
                first_lba: 2048,
                length_lbas: 2048,
                gpt_type: Some(ESP),
                mbr_type: None,
                attributes: 0,
            },
            RootCandidate {
                selector: RootSelector::GptPartition { guid: ROOT_GUID },
                first_lba: ROOT_LBA,
                length_lbas: ext4.len() as u64 / SECTOR,
                gpt_type: Some(disk_partition::DPS_ROOT_AMD64),
                mbr_type: None,
                attributes: 0,
            },
        ];
        for (requested, userspace) in [
            (ImportRootSelection::WholeDisk, GuestArchitecture::Amd64),
            // DPS follows the declared userspace: no arm64 root on this disk.
            (ImportRootSelection::AutoGpt, GuestArchitecture::Arm64),
            (
                ImportRootSelection::GptPartition { guid: OTHER_GUID },
                GuestArchitecture::Amd64,
            ),
            (
                ImportRootSelection::MbrPartition { number: 1 },
                GuestArchitecture::Amd64,
            ),
        ] {
            let failure = selection_failure(admit_owned_root(&file, length, &requested, userspace));
            assert_eq!(failure.requested, requested);
            assert_eq!(failure.candidates, expected, "{requested:?}");
            assert!(!failure.reason.is_empty());
        }
        // A selected non-ext4 partition fails admission; nothing else is tried.
        assert!(matches!(
            import_error(admit_owned_root(
                &file,
                length,
                &ImportRootSelection::GptPartition { guid: ESP_GUID },
                GuestArchitecture::Amd64,
            )),
            DiskImportError::RootFilesystem(Ext4Rejection::NotExt4 { .. })
        ));
    }

    #[test]
    fn auto_refuses_ambiguous_no_auto_and_read_only_dps_roots() {
        let temp = tempfile::tempdir().unwrap();
        let ext4 = ext4_bytes();
        let second_lba = ROOT_LBA + ext4.len() as u64 / SECTOR + 2048;
        let ambiguous = gpt_disk(
            128,
            &[
                dps_root(ROOT_GUID, ROOT_LBA, 0, &ext4),
                dps_root(OTHER_GUID, second_lba, 0, &ext4),
            ],
        );
        let (file, length) = held(&write(temp.path(), "ambiguous.img", &ambiguous));
        let failure = selection_failure(admit_owned_root(
            &file,
            length,
            &ImportRootSelection::AutoGpt,
            GuestArchitecture::Amd64,
        ));
        assert_eq!(failure.candidates.len(), 2, "never largest or first");
        assert_eq!(
            chosen(admit_owned_root(
                &file,
                length,
                &ImportRootSelection::GptPartition { guid: OTHER_GUID },
                GuestArchitecture::Amd64,
            )),
            gpt_choice(OTHER_GUID)
        );

        let no_auto = gpt_disk(128, &[dps_root(ROOT_GUID, ROOT_LBA, 1 << 63, &ext4)]);
        let (file, length) = held(&write(temp.path(), "no-auto.img", &no_auto));
        selection_failure(admit_owned_root(
            &file,
            length,
            &ImportRootSelection::AutoGpt,
            GuestArchitecture::Amd64,
        ));
        assert_eq!(
            chosen(admit_owned_root(
                &file,
                length,
                &ImportRootSelection::GptPartition { guid: ROOT_GUID },
                GuestArchitecture::Amd64,
            )),
            gpt_choice(ROOT_GUID),
            "no-auto restricts only automatic selection"
        );

        let read_only = gpt_disk(128, &[dps_root(ROOT_GUID, ROOT_LBA, 1 << 60, &ext4)]);
        let (file, length) = held(&write(temp.path(), "read-only.img", &read_only));
        for requested in [
            ImportRootSelection::AutoGpt,
            ImportRootSelection::GptPartition { guid: ROOT_GUID },
        ] {
            let failure = selection_failure(admit_owned_root(
                &file,
                length,
                &requested,
                GuestArchitecture::Amd64,
            ));
            assert!(failure.reason.contains("read-only"), "{}", failure.reason);
        }
    }

    #[test]
    fn wide_gpt_entries_are_parsed_but_not_admitted_for_linux_direct_boot() {
        let temp = tempfile::tempdir().unwrap();
        let disk = gpt_disk(256, &[dps_root(ROOT_GUID, ROOT_LBA, 0, &ext4_bytes())]);
        let (file, length) = held(&write(temp.path(), "wide.img", &disk));
        assert!(matches!(
            import_error(admit_owned_root(
                &file,
                length,
                &ImportRootSelection::GptPartition { guid: ROOT_GUID },
                GuestArchitecture::Amd64,
            )),
            DiskImportError::DirectTable(disk_partition::DirectTableError::GptEntrySize {
                size: 256
            })
        ));
    }

    #[test]
    fn mbr_roots_use_original_primary_slot_numbers() {
        let temp = tempfile::tempdir().unwrap();
        let ext4 = ext4_bytes();
        let disk = mbr_disk(2, 0x83, 2048, &ext4);
        let (file, length) = held(&write(temp.path(), "mbr.img", &disk));
        let candidate = RootCandidate {
            selector: RootSelector::MbrPartition { number: 2 },
            first_lba: 2048,
            length_lbas: ext4.len() as u64 / SECTOR,
            gpt_type: None,
            mbr_type: Some(0x83),
            attributes: 0,
        };
        assert_eq!(
            admit_owned_root(
                &file,
                length,
                &ImportRootSelection::MbrPartition { number: 2 },
                GuestArchitecture::Amd64,
            )
            .unwrap(),
            OwnedRoot {
                layout: RawLayout::Partitioned {
                    table: PartitionTable::Mbr
                },
                selector: RootSelector::MbrPartition { number: 2 },
                observed: Some(candidate.clone()),
            }
        );
        for requested in [
            ImportRootSelection::MbrPartition { number: 1 },
            ImportRootSelection::AutoGpt,
            ImportRootSelection::GptPartition { guid: ROOT_GUID },
            ImportRootSelection::WholeDisk,
        ] {
            let failure = selection_failure(admit_owned_root(
                &file,
                length,
                &requested,
                GuestArchitecture::Amd64,
            ));
            assert_eq!(failure.candidates, vec![candidate.clone()], "{requested:?}");
        }
    }

    #[test]
    fn whole_disk_roots_reject_partition_selectors_and_non_ext4_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let (file, length) = held(&write(temp.path(), "root.img", &ext4_bytes()));
        assert_eq!(
            admit_owned_root(
                &file,
                length,
                &ImportRootSelection::WholeDisk,
                GuestArchitecture::Arm64,
            )
            .unwrap(),
            OwnedRoot {
                layout: RawLayout::WholeDisk,
                selector: RootSelector::WholeDisk,
                observed: None,
            }
        );
        let failure = selection_failure(admit_owned_root(
            &file,
            length,
            &ImportRootSelection::AutoGpt,
            GuestArchitecture::Amd64,
        ));
        assert!(failure.candidates.is_empty());

        let (file, length) = held(&write(temp.path(), "zero.img", &vec![0; 1 << 20]));
        assert!(matches!(
            import_error(admit_owned_root(
                &file,
                length,
                &ImportRootSelection::WholeDisk,
                GuestArchitecture::Amd64,
            )),
            DiskImportError::RootFilesystem(Ext4Rejection::NotExt4 { magic: 0 })
        ));
    }

    #[test]
    fn structurally_impossible_selectors_fail_before_reading() {
        for requested in [
            ImportRootSelection::GptPartition { guid: Uuid::nil() },
            ImportRootSelection::MbrPartition { number: 0 },
            ImportRootSelection::MbrPartition { number: 5 },
        ] {
            match validate_requested_root(&requested) {
                Err(LibVmError::RootSelectionFailed(failure)) => {
                    assert_eq!(failure.requested, requested);
                    assert!(failure.candidates.is_empty());
                }
                other => panic!("expected refusal for {requested:?}, got {other:?}"),
            }
        }
        for requested in [
            ImportRootSelection::WholeDisk,
            ImportRootSelection::AutoGpt,
            ImportRootSelection::GptPartition { guid: ROOT_GUID },
            ImportRootSelection::MbrPartition { number: 4 },
        ] {
            validate_requested_root(&requested).unwrap();
        }
    }

    #[tokio::test]
    async fn a_source_changed_after_open_never_prepares_a_root() {
        let (temp, store) = catalog().await;
        let raw = ext4_bytes();
        for (name, bytes) in [("root.raw", raw.clone()), ("root.qcow2", qcow2_image(&raw))] {
            let path = write(temp.path(), name, &bytes);
            let source = OpenDiskSource::open(&path).unwrap();
            // Explicit timestamps keep this deterministic on coarse clocks.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
                .unwrap();
            let (prepared, _) =
                prepare_source(&store, source, ImportRootSelection::WholeDisk).await;
            assert!(
                matches!(
                    &prepared,
                    Err(LibVmError::DiskImport(error))
                        if matches!(**error, DiskImportError::SourceChanged { .. })
                ),
                "{name}: {prepared:?}"
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "source never modified"
            );
        }
    }

    #[test]
    fn sparse_sink_skips_zero_blocks_and_establishes_the_exact_length() {
        let temp = tempfile::tempdir().unwrap();
        let open = |name: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(temp.path().join(name))
                .unwrap()
        };
        let file = open("decoded");
        let length = 8_u64 << 20;
        let mut sink = SparseSink::new(&file, length);
        let mut chunk = vec![0; 1 << 20];
        chunk[4096] = 7;
        sink.write_all(&chunk).unwrap();
        let zeros = vec![0; 1 << 20];
        for _ in 1..8 {
            sink.write_all(&zeros).unwrap();
        }
        sink.finish().unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), length, "trailing zeros still count");
        assert!(
            metadata.blocks() * 512 < 1 << 20,
            "zero runs stay holes: {} allocated bytes",
            metadata.blocks() * 512
        );
        let bytes = std::fs::read(temp.path().join("decoded")).unwrap();
        assert_eq!(bytes.len() as u64, length);
        assert_eq!(bytes[4096], 7);
        assert_eq!(bytes.iter().filter(|byte| **byte != 0).count(), 1);

        let overflow = open("overflow");
        let mut sink = SparseSink::new(&overflow, 4096);
        assert!(sink.write_all(&[1; 8192]).is_err());

        let short = open("short");
        let mut sink = SparseSink::new(&short, 8192);
        sink.write_all(&[1; 4096]).unwrap();
        match sink.finish() {
            Err(LibVmError::DiskImport(error)) => assert!(matches!(
                *error,
                DiskImportError::OutputLength {
                    expected: 8192,
                    actual: 4096
                }
            )),
            other => panic!("expected short output refusal, got {other:?}"),
        }
    }
}

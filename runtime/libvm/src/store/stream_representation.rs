//! Retained encoded transport payloads and shared flat materializations.
//! Payload geometry is independent of the authenticated stream identity profile.
//! Operation stream pins protect representations, map roots and flat inodes.
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use oci::vm_artifact::wire::{ChunkEntry, TransferRoot};
use sqlx::Row;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::limits::Resource;
use crate::storage::map::{AuthenticatedMap, MapAuthority};
use crate::storage::pool::StoragePool;
use crate::store::models::snapshot::{invalid, SnapshotStream};
use crate::store::snapshot_store::{recheck_closure, ClosureFingerprints};
use crate::store::Store;
use crate::LibVmError;
use vm_spec::stream_map::{ChunkSize, StreamRole};

#[derive(Clone, Copy)]
enum FlatAuthority {
    Unverified,
    Exported(Option<crate::storage::identity_file::SourceFingerprint>),
}

/// Constructible only by authenticating the complete local canonical closure.
/// This carries no lease: the containing acquisition must retain its one owner.
pub(crate) struct VerifiedStreamRepresentation {
    content: SnapshotStream,
    root: ObjectDigest,
    members: BTreeSet<ObjectDigest>,
    fingerprints: ClosureFingerprints,
    encoding: oci::vm_artifact::codec::ChunkEncoding,
    raw_only: bool,
    flat: FlatAuthority,
}

fn digest(value: oci::changeset::model::ContentDigest) -> ObjectDigest {
    ObjectDigest::from_sha256(*value.as_bytes())
}

fn transfer(
    pool: &StoragePool,
    operation: Uuid,
    content: &SnapshotStream,
    root_digest: ObjectDigest,
) -> Result<(Vec<ChunkEntry>, BTreeSet<ObjectDigest>, AuthenticatedMap), LibVmError> {
    transfer_with_authority(
        pool,
        content,
        root_digest,
        pool.map_authority(Arc::new(pool.existing_lease(operation)?))?,
    )
}

fn transfer_with_authority(
    pool: &StoragePool,
    content: &SnapshotStream,
    root_digest: ObjectDigest,
    authority: Arc<dyn MapAuthority>,
) -> Result<(Vec<ChunkEntry>, BTreeSet<ObjectDigest>, AuthenticatedMap), LibVmError> {
    let root_bytes = pool.read_object(&root_digest, Resource::MetadataPageBytes.maximum())?;
    let root: TransferRoot = oci::vm_artifact::wire::decode_record(&root_bytes).map_err(invalid)?;
    if root.stream.as_bytes() != content.stream.as_bytes() || root.length != content.length {
        return Err(invalid(
            "retained transfer root contradicts canonical stream",
        ));
    }
    let mut members = BTreeSet::from([root_digest, content.map]);
    let entries = oci::vm_artifact::wire::verify_transfer(&root, |page| {
        let page = digest(page);
        members.insert(page);
        pool.read_object(&page, Resource::MetadataPageBytes.maximum())
            .map_err(|error| oci::vm_artifact::Error::Invalid(error.to_string()))
    })
    .map_err(invalid)?;
    let role = representation_role(content)?;
    let map = pool.load_map(content.map, role, authority)?;
    if map.id() != content.stream
        || map.length() != content.length
        || map.chunk_size().bytes() != content.chunk_size
    {
        return Err(invalid(
            "retained representation changes canonical stream root",
        ));
    }
    for entry in &entries {
        if let ChunkEntry::Data { encoded, .. } = entry {
            members.insert(digest(encoded.digest));
        }
    }
    Ok((entries, members, map))
}

fn representation_role(content: &SnapshotStream) -> Result<StreamRole, LibVmError> {
    let role = match content.chunk_size {
        65536 => StreamRole::Ram,
        8388608 => StreamRole::Disk,
        _ => return Err(invalid("unsupported retained stream identity profile")),
    };
    content.validate_profile(role)?;
    Ok(role)
}

/// Every occurrence is checked at its logical position, even when encoded
/// payload objects are shared. Only the current decoded 8 MiB payload is held.
fn authenticate_payloads(
    pool: &StoragePool,
    map: &AuthenticatedMap,
    entries: &[ChunkEntry],
    output: Option<&std::fs::File>,
) -> Result<(), LibVmError> {
    let mut bytes = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        bytes.clear();
        match entry {
            ChunkEntry::Zero { length } => {
                bytes.resize(usize::try_from(*length).map_err(invalid)?, 0)
            }
            ChunkEntry::Data { encoded, .. } => {
                oci::vm_artifact::codec::decode_chunk(
                    entry,
                    pool.open_object(&digest(encoded.digest))?,
                    &mut bytes,
                )
                .map_err(invalid)?;
            }
        }
        crate::image::transport::identity::verify_payload(map, index as u64, &bytes)?;
        if let Some(output) = output {
            crate::storage::stream::write_sparse_at(
                output,
                &bytes,
                index as u64 * oci::vm_artifact::wire::CHUNK_SIZE,
            )?;
        }
    }
    Ok(())
}

impl VerifiedStreamRepresentation {
    pub(crate) fn verify(
        pool: &StoragePool,
        operation: Uuid,
        content: SnapshotStream,
        root: ObjectDigest,
    ) -> Result<Self, LibVmError> {
        Self::verify_with_authority(
            pool,
            content,
            root,
            pool.map_authority(Arc::new(pool.existing_lease(operation)?))?,
        )
    }

    fn verify_with_authority(
        pool: &StoragePool,
        content: SnapshotStream,
        root: ObjectDigest,
        authority: Arc<dyn MapAuthority>,
    ) -> Result<Self, LibVmError> {
        let (verified, map, entries) = Self::metadata(pool, content, root, authority)?;
        authenticate_payloads(pool, &map, &entries, None)?;
        recheck_closure(&verified.fingerprints)?;
        Ok(verified)
    }

    /// The local exporter has hashed these identity units from its held input
    /// while publishing the encoded payloads. This is not imported authority.
    pub(crate) fn from_export(
        pool: &StoragePool,
        operation: Uuid,
        content: SnapshotStream,
        root: ObjectDigest,
        produced: &AuthenticatedMap,
        flat_fingerprint: Option<crate::storage::identity_file::SourceFingerprint>,
    ) -> Result<Self, LibVmError> {
        let (mut verified, map, _) = Self::metadata(
            pool,
            content,
            root,
            pool.map_authority(Arc::new(pool.existing_lease(operation)?))?,
        )?;
        if map != *produced {
            return Err(invalid(
                "exported representation contradicts measured stream root",
            ));
        }
        recheck_closure(&verified.fingerprints)?;
        verified.flat = FlatAuthority::Exported(flat_fingerprint);
        Ok(verified)
    }

    /// Import already authenticated every decoded occurrence while writing
    /// this exact held inode. Its capability cannot be supplied by a receipt.
    pub(crate) fn from_import(
        pool: &StoragePool,
        operation: Uuid,
        stream: &crate::image::transport::import::VerifiedStream,
    ) -> Result<Self, LibVmError> {
        crate::store::snapshot_store::bind_held(&stream.file, stream.fingerprint)?;
        let content = SnapshotStream {
            stream: stream.id,
            length: stream.length,
            map: stream.canonical_map,
            chunk_size: stream.map.chunk_size().bytes(),
        };
        let (verified, map, _) = Self::metadata(
            pool,
            content,
            stream.transport.root.0,
            pool.map_authority(Arc::new(pool.existing_lease(operation)?))?,
        )?;
        if map != *stream.map {
            return Err(invalid(
                "imported representation contradicts authenticated root",
            ));
        }
        recheck_closure(&verified.fingerprints)?;
        Ok(verified.for_import())
    }

    fn metadata(
        pool: &StoragePool,
        content: SnapshotStream,
        root: ObjectDigest,
        authority: Arc<dyn MapAuthority>,
    ) -> Result<(Self, AuthenticatedMap, Vec<ChunkEntry>), LibVmError> {
        crate::storage::limits::preflight_fd_budget(2)
            .map_err(crate::storage::StorageError::from)?;
        let (entries, members, map) = transfer_with_authority(pool, &content, root, authority)?;
        let mut fingerprints = Vec::with_capacity(members.len());
        let encoded = entries
            .iter()
            .filter_map(|entry| match entry {
                ChunkEntry::Data { encoded, .. } => Some(digest(encoded.digest)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for member in &members {
            let path = pool.object_path(member);
            let file = if encoded.contains(member) {
                pool.open_object(member)?
            } else {
                pool.verify_object(member)?
            };
            let fingerprint =
                crate::storage::identity_file::SourceFingerprint::new(&file.metadata()?);
            crate::store::snapshot_store::bind_reopened(
                &file,
                crate::storage::identity_file::SourceFingerprint::new(&std::fs::symlink_metadata(
                    &path,
                )?),
            )?;
            fingerprints.push((path, fingerprint));
        }
        recheck_closure(&fingerprints)?;
        let raw_only=entries.iter().all(|entry| !matches!(entry,ChunkEntry::Data{encoded,..} if encoded.media_type==oci::vm_artifact::wire::PayloadMediaType::ZstdChunk));
        let encoding = if raw_only {
            oci::vm_artifact::codec::ChunkEncoding::Raw
        } else {
            oci::vm_artifact::codec::ChunkEncoding::Zstd
        };
        Ok((
            Self {
                content,
                root,
                members,
                fingerprints,
                encoding,
                raw_only,
                flat: FlatAuthority::Unverified,
            },
            map,
            entries,
        ))
    }
    pub(crate) fn for_encoding(
        mut self,
        encoding: oci::vm_artifact::codec::ChunkEncoding,
    ) -> Result<Self, LibVmError> {
        if encoding == oci::vm_artifact::codec::ChunkEncoding::Raw && !self.raw_only {
            return Err(invalid(
                "raw writer profile contradicts compressed representation",
            ));
        }
        self.encoding = encoding;
        Ok(self)
    }

    /// The wire format does not record writer policy. Raw and zero entries are
    /// also valid zstd fallbacks, so imported bytes remain reusable by zstd.
    pub(crate) fn for_import(mut self) -> Self {
        self.encoding = oci::vm_artifact::codec::ChunkEncoding::Zstd;
        self
    }
}

pub(crate) struct RetainedStreamRepresentation {
    pub(crate) root: (ObjectDigest, Vec<u8>),
    pub(crate) pages: Vec<(ObjectDigest, Vec<u8>)>,
    pub(crate) entries: Vec<ChunkEntry>,
}

fn encoding_name(encoding: oci::vm_artifact::codec::ChunkEncoding) -> &'static str {
    match encoding {
        oci::vm_artifact::codec::ChunkEncoding::Raw => "raw",
        oci::vm_artifact::codec::ChunkEncoding::Zstd => "zstd",
    }
}

impl Store {
    pub(crate) async fn retained_stream_representation(
        &self,
        operation: Uuid,
        content: &SnapshotStream,
        encoding: oci::vm_artifact::codec::ChunkEncoding,
    ) -> Result<Option<RetainedStreamRepresentation>, LibVmError> {
        crate::store::snapshot_store::require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::new(),
        )
        .await?;
        let root=sqlx::query_scalar::<_,String>("SELECT root_digest FROM stream_representation_profile WHERE stream_id=?1 AND encoding=?2 ORDER BY root_digest LIMIT 1")
            .bind(content.stream.to_string()).bind(encoding_name(encoding)).fetch_optional(&self.pool).await?;
        let Some(root) = root else { return Ok(None) };
        let root: ObjectDigest = root.parse().map_err(invalid)?;
        let pool = StoragePool::open_existing(&self.images_dir)?
            .ok_or_else(|| invalid("retained representation pool is missing"))?;
        let verified =
            VerifiedStreamRepresentation::verify(&pool, operation, content.clone(), root)?
                .for_encoding(encoding)?;
        exact_members(
            &mut *self.pool.acquire().await?,
            content.stream,
            root,
            &verified.members,
        )
        .await?;
        let root_bytes = pool.read_object(&root, Resource::MetadataPageBytes.maximum())?;
        let record: TransferRoot =
            oci::vm_artifact::wire::decode_record(&root_bytes).map_err(invalid)?;
        let pages = record
            .pages
            .into_iter()
            .map(|page| {
                let page = digest(page);
                Ok((
                    page,
                    pool.read_object(&page, Resource::MetadataPageBytes.maximum())?,
                ))
            })
            .collect::<Result<Vec<_>, LibVmError>>()?;
        let (entries, _, _) = transfer(&pool, operation, content, root)?;
        Ok(Some(RetainedStreamRepresentation {
            root: (root, root_bytes),
            pages,
            entries,
        }))
    }

    pub(crate) async fn register_object_stream_representation(
        &self,
        operation: Uuid,
        object: ObjectDigest,
        stream: StreamId,
    ) -> Result<(), LibVmError> {
        crate::store::snapshot_store::require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([stream]),
            &BTreeSet::from([object]),
        )
        .await?;
        let pool = StoragePool::open(&self.images_dir)?;
        let fingerprint = authenticate_object_binding(&pool, object, stream)?;
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(&[(pool.object_path(&object), fingerprint)])?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        insert_object_binding(&mut tx, object, stream).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The caller's existing operation pins every object before verification.
    pub(crate) async fn register_stream_representation(
        &self,
        operation: Uuid,
        verified: &VerifiedStreamRepresentation,
    ) -> Result<(), LibVmError> {
        crate::store::snapshot_store::require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([verified.content.stream]),
            &verified.members,
        )
        .await?;
        let pool = StoragePool::open(&self.images_dir)?;
        let (_, _, map) = transfer(&pool, operation, &verified.content, verified.root)?;
        let retained = self.admit_published_map_root(operation, &map).await?;
        let flat = match verified.flat {
            FlatAuthority::Unverified => authenticate_flat_if_present(&pool, &verified.content)?,
            FlatAuthority::Exported(fingerprint) => fingerprint
                .map(|fingerprint| (pool.stream_path(&verified.content.stream), fingerprint)),
        };
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(flat.as_slice())?;
        recheck_closure(&verified.fingerprints)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        insert_representation(&mut tx, verified, flat.is_some()).await?;
        tx.commit().await?;
        drop(retained);
        Ok(())
    }

    /// Must run in the actual blocking owner, after registering the consumer.
    /// Only an explicitly evicted flat may be absent. Missing ordinary backing
    /// is corruption, not permission to silently repair it or contact a registry.
    pub(crate) async fn materialize_stream(
        &self,
        operation: Uuid,
        content: &SnapshotStream,
    ) -> Result<(), LibVmError> {
        crate::store::snapshot_store::require_consumer_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::new(),
        )
        .await?;
        crate::storage::limits::preflight_fd_budget(4)
            .map_err(crate::storage::StorageError::from)?;
        let pool = StoragePool::open(&self.images_dir)?;
        let row = sqlx::query(
            "SELECT length,map_digest,chunk_shift,flat_state FROM storage_stream WHERE stream_id=?1",
        )
        .bind(content.stream.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(()) };
        if row.try_get::<i64, _>("length")? != content.length as i64
            || row.try_get::<String, _>("map_digest")? != content.map.to_string()
            || (1u64 << row.try_get::<u32, _>("chunk_shift")?) != content.chunk_size
        {
            return Err(invalid("stream catalog contradicts semantic map"));
        }
        let state: String = row.try_get("flat_state")?;
        if !matches!(state.as_str(), "present" | "evicting" | "absent") {
            return Err(invalid("unknown flat materialization state"));
        }
        if pool.stream_path(&content.stream).try_exists()? {
            if state != "present" {
                let flat = authenticate_flat_if_present(&pool, content)?;
                if flat.is_none() {
                    return Err(invalid("flat stream disappeared during reconciliation"));
                }
                let _roots = pool.lock_roots_shared()?;
                recheck_closure(flat.as_slice())?;
                mark_flat_present(&mut *self.pool.acquire().await?, content).await?;
            }
            return Ok(());
        }
        if state == "present" {
            return Err(invalid(
                "retained flat stream disappeared without eviction authority",
            ));
        }
        let root: String = sqlx::query_scalar("SELECT root_digest FROM stream_representation WHERE stream_id=?1 ORDER BY root_digest LIMIT 1")
            .bind(content.stream.to_string()).fetch_optional(&self.pool).await?
            .ok_or_else(|| invalid("evicted stream has no retained representation"))?;
        let root = root.parse().map_err(invalid)?;
        let (entries, members, map) = transfer(&pool, operation, content, root)?;
        exact_members(
            &mut *self.pool.acquire().await?,
            content.stream,
            root,
            &members,
        )
        .await?;
        // Disposable reconstruction bytes use the pool's publication lease,
        // not the consumer's operation directory, which restore owns later.
        let (staging, output) = pool.stage()?;
        output.set_len(content.length)?;
        authenticate_payloads(&pool, &map, &entries, Some(&output))?;
        output.sync_all()?;
        let retained = self.admit_published_map_root(operation, &map).await?;
        let (published, roots) = pool.publish_staged_stream_for_catalog(staging, output, &map)?;
        if published.map().id() != content.stream || published.map().length() != content.length {
            return Err(invalid("reconstructed stream identity mismatch"));
        }
        drop(retained);
        mark_flat_present(&mut *self.pool.acquire().await?, content).await?;
        drop(roots);
        Ok(())
    }
    /// Flat eviction is an explicit prune action, never a TTL for retained data.
    pub(crate) async fn evict_flat_materializations(&self) -> Result<u64, LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        crate::store::cache_paths::check_machine_dependencies(self).await?;
        let mut cursor = String::new();
        let mut removed = 0u64;
        loop {
            let rows = sqlx::query("SELECT stream_id,length,map_digest,chunk_shift FROM storage_stream WHERE stream_id>?1 AND flat_state IN ('present','evicting') ORDER BY stream_id LIMIT 256")
                .bind(&cursor).fetch_all(&self.pool).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = row.try_get("stream_id")?;
                let stream: StreamId = cursor.parse().map_err(invalid)?;
                let root: Option<String> = sqlx::query_scalar("SELECT root_digest FROM stream_representation WHERE stream_id=?1 ORDER BY root_digest LIMIT 1")
                    .bind(&cursor).fetch_optional(&self.pool).await?;
                let Some(root) = root else { continue };
                let map = row
                    .try_get::<String, _>("map_digest")?
                    .parse()
                    .map_err(invalid)?;
                let content = SnapshotStream {
                    stream,
                    length: u64::try_from(row.try_get::<i64, _>("length")?).map_err(invalid)?,
                    map,
                    chunk_size: 1u64 << row.try_get::<u32, _>("chunk_shift")?,
                };
                // A scoped collection guard owns the graph during the sole-copy
                // byte check; release it before the exclusive eviction fence.
                let verified = VerifiedStreamRepresentation::verify_with_authority(
                    &pool,
                    content,
                    root.parse().map_err(invalid)?,
                    pool.map_authority(Arc::new(pool.lock_roots_shared()?))?,
                )?;
                let _roots = pool.lock_roots()?;
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                let state: Option<String> =
                    sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                        .bind(&cursor)
                        .fetch_optional(&mut *tx)
                        .await?;
                let path = pool.stream_path(&stream);
                match state.as_deref() {
                    Some("present") if !path.try_exists()? => {
                        return Err(invalid(
                            "retained flat stream disappeared without eviction authority",
                        ));
                    }
                    Some("present" | "evicting") => {}
                    Some("absent") | None => {
                        tx.commit().await?;
                        continue;
                    }
                    Some(_) => return Err(invalid("unknown flat materialization state")),
                }
                let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE stream_id=?1 UNION ALL SELECT 1 FROM layer_result WHERE pack_stream=?1)")
                    .bind(&cursor).fetch_one(&mut *tx).await?;
                if busy
                    || crate::store::cache_paths::machine_retains_stream(&mut tx, stream).await?
                {
                    tx.commit().await?;
                    continue;
                }
                recheck_closure(&verified.fingerprints)?;
                exact_members(&mut tx, stream, verified.root, &verified.members).await?;
                crate::store::ensure_cache_paths_unreferenced(
                    &mut tx,
                    std::slice::from_ref(&path),
                    &self.home,
                )
                .await?;
                sqlx::query("UPDATE storage_stream SET flat_state='evicting' WHERE stream_id=?1")
                    .bind(&cursor)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                // Recovery must retain eviction authority if the flat is gone.
                self.checkpoint_catalog().await?;
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                crate::store::ensure_cache_paths_unreferenced(&mut tx, &[path], &self.home).await?;
                if pool.remove_stream(&stream)? {
                    removed = removed.saturating_add(verified.content.length);
                }
                sqlx::query("UPDATE storage_stream SET flat_state='absent' WHERE stream_id=?1")
                    .bind(&cursor)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        Ok(removed)
    }
}

/// Hash an existing owned flat before giving it presence authority. The caller
/// rechecks this fingerprint under roots coordination before committing.
fn authenticate_flat_if_present(
    pool: &StoragePool,
    content: &SnapshotStream,
) -> Result<
    Option<(
        std::path::PathBuf,
        crate::storage::identity_file::SourceFingerprint,
    )>,
    LibVmError,
> {
    let path = pool.stream_path(&content.stream);
    if !path.try_exists()? {
        return Ok(None);
    }
    let authenticated =
        pool.authenticate_stream_full(&content.stream, representation_role(content)?)?;
    if authenticated.map().length() != content.length {
        return Err(invalid("flat stream contradicts canonical length"));
    }
    Ok(Some((path, authenticated.fingerprint())))
}

/// Requires an authenticated flat and its publication/roots guard. A missing
/// row is normal before a new import's final semantic publication transaction.
pub(crate) async fn mark_flat_present(
    connection: &mut sqlx::SqliteConnection,
    content: &SnapshotStream,
) -> Result<(), LibVmError> {
    let row =
        sqlx::query("SELECT length,map_digest,chunk_shift FROM storage_stream WHERE stream_id=?1")
            .bind(content.stream.to_string())
            .fetch_optional(&mut *connection)
            .await?;
    if let Some(row) = row {
        if row.try_get::<i64, _>("length")? != content.length as i64
            || row.try_get::<String, _>("map_digest")? != content.map.to_string()
            || (1u64 << row.try_get::<u32, _>("chunk_shift")?) != content.chunk_size
        {
            return Err(invalid("immutable stream catalog identity contradiction"));
        }
        sqlx::query("UPDATE storage_stream SET flat_state='present' WHERE stream_id=?1")
            .bind(content.stream.to_string())
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

pub(crate) async fn insert_representation(
    connection: &mut sqlx::SqliteConnection,
    verified: &VerifiedStreamRepresentation,
    flat_present: bool,
) -> Result<(), LibVmError> {
    recheck_closure(&verified.fingerprints)?;
    let content = &verified.content;
    let role = representation_role(content)?;
    sqlx::query("INSERT INTO storage_stream(stream_id,length,map_digest,chunk_shift,flat_state) VALUES(?1,?2,?3,?4,?5) ON CONFLICT DO NOTHING")
        .bind(content.stream.to_string()).bind(content.length as i64).bind(content.map.to_string())
        .bind(role.chunk_size().shift())
        .bind(if flat_present { "present" } else { "absent" }).execute(&mut *connection).await?;
    let row =
        sqlx::query("SELECT length,map_digest,chunk_shift FROM storage_stream WHERE stream_id=?1")
            .bind(content.stream.to_string())
            .fetch_one(&mut *connection)
            .await?;
    if row.try_get::<i64, _>("length")? != content.length as i64
        || row.try_get::<String, _>("map_digest")? != content.map.to_string()
        || row.try_get::<u8, _>("chunk_shift")? != role.chunk_size().shift()
    {
        return Err(invalid("immutable stream catalog identity contradiction"));
    }
    if flat_present {
        sqlx::query("UPDATE storage_stream SET flat_state='present' WHERE stream_id=?1")
            .bind(content.stream.to_string())
            .execute(&mut *connection)
            .await?;
    }
    let inserted = sqlx::query("INSERT INTO stream_representation(stream_id,root_digest) VALUES(?1,?2) ON CONFLICT DO NOTHING")
        .bind(content.stream.to_string()).bind(verified.root.to_string()).execute(&mut *connection).await?.rows_affected();
    if inserted == 1 {
        for member in &verified.members {
            sqlx::query("INSERT INTO stream_representation_object(stream_id,root_digest,object_digest) VALUES(?1,?2,?3)")
                .bind(content.stream.to_string()).bind(verified.root.to_string()).bind(member.to_string()).execute(&mut *connection).await?;
        }
    }
    sqlx::query("INSERT OR IGNORE INTO stream_representation_profile(stream_id,root_digest,encoding) VALUES(?1,?2,?3)")
        .bind(content.stream.to_string()).bind(verified.root.to_string()).bind(encoding_name(verified.encoding)).execute(&mut *connection).await?;
    if verified.raw_only && verified.encoding != oci::vm_artifact::codec::ChunkEncoding::Raw {
        sqlx::query("INSERT OR IGNORE INTO stream_representation_profile(stream_id,root_digest,encoding) VALUES(?1,?2,'raw')")
            .bind(content.stream.to_string()).bind(verified.root.to_string()).execute(&mut *connection).await?;
    }
    exact_members(connection, content.stream, verified.root, &verified.members).await
}

async fn exact_members(
    connection: &mut sqlx::SqliteConnection,
    stream: StreamId,
    root: ObjectDigest,
    expected: &BTreeSet<ObjectDigest>,
) -> Result<(), LibVmError> {
    let actual = sqlx::query_scalar::<_,String>("SELECT object_digest FROM stream_representation_object WHERE stream_id=?1 AND root_digest=?2")
        .bind(stream.to_string()).bind(root.to_string()).fetch_all(connection).await?
        .into_iter().map(|value|value.parse().map_err(invalid)).collect::<Result<BTreeSet<ObjectDigest>,_>>()?;
    if &actual != expected {
        return Err(invalid("retained representation dependency contradiction"));
    }
    Ok(())
}

/// Authenticate structural metadata before destructive collection. Payload
/// presence and geometry use metadata-only resolution: recovery precedes launch
/// FD admission and must not open a lower that is also a raw transfer chunk.
/// Registration and admitted consumers authenticate the exact payload bytes.
pub(crate) async fn check_catalog(store: &Store) -> Result<(), LibVmError> {
    let pool = StoragePool::open(&store.images_dir)?;
    let incomplete:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_stream s WHERE NOT EXISTS(SELECT 1 FROM stream_representation r WHERE r.stream_id=s.stream_id))").fetch_one(&store.pool).await?;
    if incomplete {
        return Err(invalid(
            "stream catalog has no complete retained representation",
        ));
    }
    let mut cursor = (String::new(), String::new());
    loop {
        let rows = sqlx::query("SELECT s.stream_id,s.length,s.map_digest,s.chunk_shift,r.root_digest FROM storage_stream s JOIN stream_representation r USING(stream_id) WHERE (s.stream_id,r.root_digest)>(?1,?2) ORDER BY s.stream_id,r.root_digest LIMIT 256")
            .bind(&cursor.0).bind(&cursor.1).fetch_all(&store.pool).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = (row.try_get("stream_id")?, row.try_get("root_digest")?);
            let map = row
                .try_get::<String, _>("map_digest")?
                .parse()
                .map_err(invalid)?;
            let content = SnapshotStream {
                stream: cursor.0.parse().map_err(invalid)?,
                length: u64::try_from(row.try_get::<i64, _>("length")?).map_err(invalid)?,
                map,
                chunk_size: 1u64 << row.try_get::<u32, _>("chunk_shift")?,
            };
            let root = cursor.1.parse().map_err(invalid)?;
            let (entries, members, _) = transfer_with_authority(
                &pool,
                &content,
                root,
                pool.map_authority(Arc::new(pool.lock_roots_shared()?))?,
            )?;
            exact_members(
                &mut *store.pool.acquire().await?,
                content.stream,
                root,
                &members,
            )
            .await?;
            for member in &members {
                pool.lower_object_occurrence(member)?;
            }
            let profiles=sqlx::query_scalar::<_,String>("SELECT encoding FROM stream_representation_profile WHERE stream_id=?1 AND root_digest=?2")
                .bind(content.stream.to_string()).bind(root.to_string()).fetch_all(&store.pool).await?;
            let compressed=entries.iter().any(|entry|matches!(entry,ChunkEntry::Data{encoded,..} if encoded.media_type==oci::vm_artifact::wire::PayloadMediaType::ZstdChunk));
            if profiles.is_empty()
                || profiles.iter().any(|profile| {
                    !matches!(profile.as_str(), "raw" | "zstd") || profile == "raw" && compressed
                })
            {
                return Err(invalid(
                    "retained representation writer profile contradiction",
                ));
            }
        }
    }
    let mut cursor = String::new();
    loop {
        let rows=sqlx::query_as::<_,(String,i64)>("SELECT b.object_digest,s.length FROM object_stream_representation b JOIN storage_stream s ON s.stream_id=b.stream_id WHERE b.object_digest>?1 ORDER BY b.object_digest LIMIT 256")
            .bind(&cursor).fetch_all(&store.pool).await?;
        if rows.is_empty() {
            break;
        }
        for (object, length) in rows {
            cursor.clone_from(&object);
            let object = object.parse().map_err(invalid)?;
            let expected = u64::try_from(length).map_err(invalid)?;
            if pool.lower_object_occurrence(&object)?.length() != expected {
                return Err(invalid(
                    "whole-object stream representation contradicts byte length",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) async fn insert_object_binding(
    connection: &mut sqlx::SqliteConnection,
    object: ObjectDigest,
    stream: StreamId,
) -> Result<(), LibVmError> {
    sqlx::query("INSERT INTO object_stream_representation(object_digest,stream_id) VALUES(?1,?2) ON CONFLICT(object_digest) DO NOTHING")
        .bind(object.to_string()).bind(stream.to_string()).execute(&mut *connection).await?;
    let actual: String = sqlx::query_scalar(
        "SELECT stream_id FROM object_stream_representation WHERE object_digest=?1",
    )
    .bind(object.to_string())
    .fetch_one(connection)
    .await?;
    if actual != stream.to_string() {
        return Err(invalid(
            "immutable whole-object stream binding contradiction",
        ));
    }
    Ok(())
}

fn authenticate_object_binding(
    pool: &StoragePool,
    object: ObjectDigest,
    stream: StreamId,
) -> Result<crate::storage::identity_file::SourceFingerprint, LibVmError> {
    crate::storage::limits::preflight_fd_budget(1).map_err(crate::storage::StorageError::from)?;
    let file = pool.open_object(&object)?;
    let length = file.metadata()?.len();
    let (authenticated, sha) = crate::storage::stream::StreamHasher::new(ChunkSize::DISK)
        .authenticate_with_sha256(file, length)?;
    if authenticated.map().id() != stream || sha.as_bytes() != object.as_bytes() {
        return Err(invalid(
            "whole-object stream representation contradicts byte identity",
        ));
    }
    Ok(authenticated.fingerprint())
}

pub(crate) async fn retained_objects(store: &Store) -> Result<HashSet<ObjectDigest>, LibVmError> {
    let mut retained = HashSet::new();
    let mut rows = sqlx::query_scalar::<_, String>("SELECT object_digest FROM retained_object")
        .fetch(&store.pool);
    while let Some(value) = rows.next().await {
        retained.insert(value?.parse().map_err(invalid)?);
    }
    Ok(retained)
}

pub(crate) async fn unreachable_objects(
    connection: &mut sqlx::SqliteConnection,
    objects: &[ObjectDigest],
) -> Result<Vec<ObjectDigest>, LibVmError> {
    let values = sqlx::query_scalar::<_, String>(
        "SELECT c.value FROM json_each(?1) c LEFT JOIN retained_object r ON r.object_digest=c.value WHERE r.object_digest IS NULL",
    )
    .bind(serde_json::to_string(objects).map_err(invalid)?)
    .fetch_all(connection)
    .await?;
    values
        .into_iter()
        .map(|value| value.parse().map_err(invalid))
        .collect()
}

pub(crate) async fn retire_unrooted(store: &Store, pool: &StoragePool) -> Result<(), LibVmError> {
    crate::store::cache_paths::check_machine_dependencies(store).await?;
    let _roots = pool.lock_roots()?;
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query(
        "DELETE FROM storage_stream WHERE stream_id NOT IN (SELECT stream_id FROM retained_stream)",
    )
    .execute(&mut *tx)
    .await?;
    crate::store::map_store::retire_unreachable_graph(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheKind {
    SourceBlob,
    Transport,
}

impl CacheKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SourceBlob => "source-blob",
            Self::Transport => "transport",
        }
    }
    fn directory(self) -> &'static str {
        match self {
            Self::SourceBlob => "source-blobs",
            Self::Transport => "transport",
        }
    }
    fn ttl(self) -> i64 {
        match self {
            Self::SourceBlob => 7 * 86400,
            Self::Transport => 30 * 86400,
        }
    }
}

impl Store {
    /// Register expected cache identities before a lookup or producer starts.
    /// The existing operation lease, not one descriptor per blob, owns readers
    /// and publishers through their actual blocking worker.
    pub(crate) async fn pin_cache_inputs(
        &self,
        operation: Uuid,
        kind: CacheKind,
        digests: &[ObjectDigest],
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(&self.images_dir)?;
        let _roots = pool.lock_roots_shared()?;
        if pool.try_exclusive_lease(operation)?.is_some() {
            return Err(invalid("cache access requires a live operation lease"));
        }
        let (device, inode) = pool.operation_lease_identity(operation)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state IN ('staging','committing') AND file_device=?2 AND file_inode=?3)")
            .bind(operation.to_string()).bind(device.to_string()).bind(inode.to_string()).fetch_one(&mut *tx).await?;
        if !active {
            return Err(invalid("cache operation is missing, frozen or replaced"));
        }
        let now = chrono::Utc::now().timestamp();
        for digest in digests {
            sqlx::query("INSERT INTO storage_cache_entry(kind,digest,last_used_at) VALUES(?1,?2,?3) ON CONFLICT(kind,digest) DO UPDATE SET last_used_at=max(last_used_at,excluded.last_used_at)")
                .bind(kind.as_str()).bind(digest.to_string()).bind(now).execute(&mut *tx).await?;
            sqlx::query("INSERT OR IGNORE INTO storage_operation_cache(operation_id,kind,digest) VALUES(?1,?2,?3)")
                .bind(operation.to_string()).bind(kind.as_str()).bind(digest.to_string()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Runs only in the GC blocking owner. Unknown/unindexed files are retained
    /// for recovery classification; age alone cannot authorize their deletion.
    pub(crate) async fn prune_transport_caches(
        &self,
        pool: &StoragePool,
        pressure: bool,
    ) -> Result<(u64, crate::store::models::CacheRecoveryReport), LibVmError> {
        let mut removed = 0u64;
        let mut recovery = crate::store::models::CacheRecoveryReport::default();
        for kind in [CacheKind::SourceBlob, CacheKind::Transport] {
            let mut cursor = String::new();
            let cutoff = chrono::Utc::now().timestamp().saturating_sub(kind.ttl());
            loop {
                let candidates = sqlx::query_scalar::<_,String>("SELECT digest FROM storage_cache_entry WHERE kind=?1 AND digest>?2 AND (?3 OR last_used_at<=?4) ORDER BY digest LIMIT 256")
                    .bind(kind.as_str()).bind(&cursor).bind(pressure).bind(cutoff).fetch_all(&self.pool).await?;
                if candidates.is_empty() {
                    break;
                }
                if let Some(last) = candidates.last() {
                    cursor.clone_from(last);
                }
                let candidates = serde_json::to_string(&candidates).map_err(invalid)?;
                let _roots = pool.lock_roots()?;
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                let eligible =
                    eligible_cache_entries(&mut tx, kind, &candidates, pressure, cutoff).await?;
                if eligible.is_empty() {
                    tx.commit().await?;
                    continue;
                }
                let paths = eligible
                    .iter()
                    .map(|digest| {
                        self.images_dir
                            .join(kind.directory())
                            .join("sha256")
                            .join(digest.hex())
                    })
                    .collect::<Vec<_>>();
                crate::store::ensure_cache_paths_unreferenced(&mut tx, &paths, &self.home).await?;
                tx.commit().await?;
                // Stabilize pin absence before unlink, then recheck under the
                // same roots guard and a fresh SQLite writer fence.
                if let Some(deferred) = self.try_checkpoint_catalog().await?.deferral() {
                    recovery.deferred.push(deferred);
                    return Ok((removed, recovery));
                }
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                let eligible =
                    eligible_cache_entries(&mut tx, kind, &candidates, pressure, cutoff).await?;
                crate::store::ensure_cache_paths_unreferenced(&mut tx, &paths, &self.home).await?;
                let directory = crate::paths::OwnedDirectory::open_existing_root(
                    &self.images_dir.join(kind.directory()).join("sha256"),
                )?
                .ok_or_else(|| invalid("cache directory disappeared"))?;
                for digest in &eligible {
                    if let Some(file) = directory.open_file(&digest.hex())? {
                        use std::os::unix::fs::MetadataExt;
                        let metadata = file.metadata()?;
                        if !metadata.is_file()
                            || metadata.nlink() != 1
                            || metadata.uid() != nix::unistd::geteuid().as_raw()
                            || metadata.mode() & 0o7777 != 0o600
                        {
                            return Err(invalid("unsafe cache entry"));
                        }
                        removed = removed.saturating_add(metadata.len());
                        directory.remove_tree(&digest.hex())?;
                        directory.sync()?;
                    }
                }
                sqlx::query("DELETE FROM storage_cache_entry WHERE kind=?1 AND digest IN (SELECT value FROM json_each(?2))")
                    .bind(kind.as_str()).bind(serde_json::to_string(&eligible).map_err(invalid)?)
                    .execute(&mut *tx).await?;
                tx.commit().await?;
            }
        }
        Ok((removed, recovery))
    }
}

async fn eligible_cache_entries(
    connection: &mut sqlx::SqliteConnection,
    kind: CacheKind,
    candidates: &str,
    pressure: bool,
    cutoff: i64,
) -> Result<Vec<ObjectDigest>, LibVmError> {
    let values = sqlx::query_scalar::<_, String>(
        "SELECT e.digest FROM storage_cache_entry e JOIN json_each(?2) c ON c.value=e.digest WHERE e.kind=?1 AND (?3 OR e.last_used_at<=?4) AND NOT EXISTS(SELECT 1 FROM storage_operation_cache p WHERE p.kind=e.kind AND p.digest=e.digest)",
    ).bind(kind.as_str()).bind(candidates).bind(pressure).bind(cutoff)
        .fetch_all(connection).await?;
    values
        .into_iter()
        .map(|value| value.parse().map_err(invalid))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::paths::LocalPaths;
    use crate::storage::identity::ObjectDigest;
    use crate::storage::pool::{OperationPaths, StoragePool};
    use crate::store::snapshot_store::{RecordInput, SnapshotRef, SnapshotStore};
    use crate::store::stream_representation::{
        check_catalog, CacheKind, VerifiedStreamRepresentation,
    };
    use crate::store::Store;
    use std::sync::Arc;

    async fn publish_object(
        store: &Store,
        pool: &StoragePool,
        operation: uuid::Uuid,
        bytes: &[u8],
    ) -> ObjectDigest {
        let input = RecordInput::new(&store.images_dir, operation, bytes).unwrap();
        let (object, roots) = pool.publish_object_for_catalog(&input.path()).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[], &[object.digest])
            .await
            .unwrap();
        drop(roots);
        object.digest
    }

    type RetainedFixture = (
        tempfile::TempDir,
        Arc<Store>,
        crate::store::models::snapshot::SnapshotRecord,
        crate::SnapshotInfo,
        OperationPaths,
        ObjectDigest,
    );

    async fn retained(bytes: &[u8]) -> RetainedFixture {
        retained_paginated(bytes, oci::vm_artifact::wire::MAX_PAGE_ENTRIES).await
    }

    pub(crate) async fn retained_paginated(
        bytes: &[u8],
        entries_per_page: usize,
    ) -> RetainedFixture {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new(&LocalPaths::new(temp.path().join("home")))
                .await
                .unwrap(),
        );
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("snapshot", &[], &[])
            .await
            .unwrap();
        let owner = pool.create_operation_with_lease(operation, lease).unwrap();
        let source = RecordInput::new(&store.images_dir, operation, bytes).unwrap();
        let (stream, roots) = pool.publish_stream_for_catalog(&source.path()).unwrap();
        store
            .pin_published_storage_dependencies(operation, &[stream.id], &[])
            .await
            .unwrap();
        drop(roots);
        let content =
            crate::store::snapshot_store::publish_map(&pool, &store, operation, &stream.map)
                .await
                .unwrap();
        let mut entries = Vec::new();
        for chunk in bytes.chunks(crate::storage::limits::CHUNK_SIZE) {
            if chunk.iter().all(|b| *b == 0) {
                entries.push(serde_json::json!({"kind":"zero","length":chunk.len()}));
            } else {
                let digest = publish_object(&store, &pool, operation, chunk).await;
                entries.push(serde_json::json!({"kind":"data","length":chunk.len(),"digest":digest,"encoded":{"mediaType":"application/vnd.silo.vm.chunk.v1","digest":digest,"size":chunk.len()}}));
            }
        }
        let mut pages = Vec::new();
        for (index, entries) in entries.chunks(entries_per_page).enumerate() {
            let page = oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({
                "schema":1,"kind":"silo-chunk-map",
                "firstChunk":index * entries_per_page,"entries":entries
            }))
            .unwrap();
            pages.push(publish_object(&store, &pool, operation, &page).await);
        }
        let root_bytes=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({"schema":1,"kind":"silo-chunks-v1","stream":stream.id,"length":bytes.len(),"chunkSize":8388608,"pages":pages})).unwrap();
        let root = publish_object(&store, &pool, operation, &root_bytes).await;
        let representation =
            VerifiedStreamRepresentation::verify(&pool, operation, content.clone(), root).unwrap();
        store
            .register_stream_representation(operation, &representation)
            .await
            .unwrap();
        let kernel = publish_object(&store, &pool, operation, b"retained exact boot").await;
        let mut record =
            crate::store::models::snapshot::tests::record(stream.id, content.map, kernel);
        record.root.stream = content;
        record.root.geometry.length = bytes.len() as u64;
        let crate::BootProfile::LinuxDirect { binding, .. } = &record.boot else {
            panic!("direct fixture")
        };
        publish_object(
            &store,
            &pool,
            operation,
            &binding.canonical_bytes().unwrap(),
        )
        .await;
        let info = SnapshotStore::from_store(store.clone())
            .publish(&record, operation, None)
            .await
            .unwrap();
        (temp, store, record, info, owner, root)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn startup_recovery_precedes_fd_admission_without_opening_raw_lower_backings() {
        use crate::storage::limits::FileDescriptorBudgetError;
        use crate::storage::vmdk::FlatLowerPlan;
        use crate::storage::StorageError;
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use nix::sys::resource::{getrlimit, setrlimit, Resource as HostResource};
        use std::os::unix::fs::PermissionsExt;

        let Ok(mode) = std::env::var("SILO_RECOVERY_LOWER_FD_CHILD") else {
            for mode in ["refuse", "raise"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "store::stream_representation::tests::startup_recovery_precedes_fd_admission_without_opening_raw_lower_backings",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("SILO_RECOVERY_LOWER_FD_CHILD", mode)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };

        // A small fsmeta object's raw transfer chunk is the object itself.
        // Retain that exact storage shape, including its whole-object binding.
        let (temp, store, record, _info, owner, _) = retained(&[7; 512]).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let object = ObjectDigest::of_bytes(&[7; 512]);
        store
            .register_object_stream_representation(owner.id, object, record.root.stream.stream)
            .await
            .unwrap();
        drop(owner);
        store.pool.close().await;
        drop(store);

        let watcher = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).unwrap();
        for path in [
            pool.object_path(&object),
            pool.stream_path(&record.root.stream.stream),
        ] {
            watcher
                .add_watch(
                    &path,
                    AddWatchFlags::IN_OPEN | AddWatchFlags::IN_CLOSE_NOWRITE,
                )
                .unwrap();
        }
        drop(std::fs::File::open(pool.object_path(&object)).unwrap());
        assert!(watcher
            .read_events()
            .unwrap()
            .iter()
            .any(|event| event.mask.contains(AddWatchFlags::IN_OPEN)));
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );

        let (_, original_hard) = getrlimit(HostResource::RLIMIT_NOFILE).unwrap();
        assert!(original_hard >= 512);
        let hard = if mode == "refuse" { 256 } else { 512 };
        setrlimit(HostResource::RLIMIT_NOFILE, 256, hard).unwrap();
        let paths = LocalPaths::new(temp.path().join("home"));
        let _reopened = Store::open(&paths.state_db_path()).await.unwrap();
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN,
            "startup recovery must not open raw chunks or whole-object backings"
        );
        let occurrences = [
            pool.lower_object_occurrence(&object).unwrap(),
            pool.lower_occurrence(&record.root.stream.stream).unwrap(),
        ];
        let result = FlatLowerPlan::new(&occurrences).unwrap().preflight(0);
        if mode == "refuse" {
            assert!(matches!(
                result,
                Err(StorageError::FileDescriptorBudget(
                    FileDescriptorBudgetError::Insufficient {
                        required: 258,
                        soft: 256,
                        hard: 256,
                    }
                ))
            ));
            assert_eq!(
                watcher.read_events().unwrap_err(),
                nix::errno::Errno::EAGAIN
            );
        } else {
            let admitted = result.unwrap();
            assert_eq!(getrlimit(HostResource::RLIMIT_NOFILE).unwrap(), (512, 512));
            admitted.verify(&pool).unwrap();
            assert!(watcher
                .read_events()
                .unwrap()
                .iter()
                .any(|event| event.mask.contains(AddWatchFlags::IN_OPEN)));
            let path = pool.object_path(&object);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&path, [8; 512]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
            assert!(admitted.verify(&pool).is_err());
        }
    }

    #[tokio::test]
    async fn retained_sparse_chunks_reconstruct_offline_with_one_consumer_lease() {
        let chunk = crate::storage::limits::CHUNK_SIZE;
        let mut bytes = vec![0u8; chunk * 3 + 512];
        bytes[..chunk].fill(7);
        bytes[chunk * 2..chunk * 3].fill(7);
        bytes[chunk * 3..].fill(9);
        let (_temp, store, record, info, owner, _) = retained(&bytes).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 0);
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(
            store.evict_flat_materializations().await.unwrap(),
            bytes.len() as u64
        );
        assert!(!pool.stream_path(&record.root.stream.stream).exists());
        store.prune_transport_caches(&pool, true).await.unwrap();
        store.recover_layer_objects().await.unwrap();
        let snapshots = SnapshotStore::from_store(store.clone());
        let consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
        assert_eq!(
            std::fs::read(pool.stream_path(&record.root.stream.stream)).unwrap(),
            bytes
        );
        let staging = crate::machine::stopped::OperationStaging::new(
            &pool,
            consumer.operation_id,
            &consumer.lease,
        )
        .expect("reconstructed consumer must still admit restore-owned staging");
        let temporary = staging.directory().unwrap().path().to_path_buf();
        assert!(temporary.is_dir());
        drop(staging);
        assert!(
            !temporary.exists(),
            "restore staging cleanup must own its directory"
        );
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 0);
        let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM storage_operation")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(operations, 1);
        snapshots.remove(&SnapshotRef::Id(info.id)).await.unwrap();
        store.recover_layer_objects().await.unwrap();
        assert!(pool.object_path(&record.root.stream.map).exists());
        assert_eq!(
            consumer
                .open_stream(&pool, &record.root.stream.stream, bytes.len() as u64)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            bytes.len() as u64
        );
        drop(consumer);
        store.recover_layer_objects().await.unwrap();
        assert!(!pool.object_path(&record.root.stream.map).exists());
    }

    #[tokio::test]
    async fn all_zero_retained_stream_reconstructs_without_payload_objects() {
        let bytes = vec![0; 512];
        let (_temp, store, record, info, owner, _) = retained(&bytes).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        store.evict_flat_materializations().await.unwrap();
        let _consumer = SnapshotStore::from_store(store.clone())
            .consume(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(pool.stream_path(&record.root.stream.stream)).unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn missing_and_extra_representation_edges_are_corruption() {
        for extra in [false, true] {
            let (_temp, store, record, _info, _owner, root) = retained(&[7; 512]).await;
            if extra {
                sqlx::query("INSERT INTO stream_representation_object(stream_id,root_digest,object_digest) VALUES(?1,?2,?3)")
                    .bind(record.root.stream.stream.to_string()).bind(root.to_string()).bind(ObjectDigest::of_bytes(b"extra").to_string()).execute(&store.pool).await.unwrap();
            } else {
                sqlx::query("DELETE FROM stream_representation_object WHERE stream_id=?1 AND object_digest=?2")
                    .bind(record.root.stream.stream.to_string()).bind(root.to_string()).execute(&store.pool).await.unwrap();
            }
            assert!(check_catalog(&store).await.is_err());
            assert!(store.recover_layer_objects().await.is_err());
            assert!(StoragePool::open(&store.images_dir)
                .unwrap()
                .stream_path(&record.root.stream.stream)
                .exists());
        }
    }

    #[tokio::test]
    async fn cache_age_pressure_and_operation_pins_never_evict_canonical_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let owner = pool.create_operation_with_lease(operation, lease).unwrap();
        let digest = ObjectDigest::of_bytes(b"cached");
        store
            .pin_cache_inputs(operation, CacheKind::SourceBlob, &[digest])
            .await
            .unwrap();
        let path = store
            .images_dir
            .join("source-blobs/sha256")
            .join(digest.hex());
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(b"cached")
            .unwrap();
        let canonical = publish_object(&store, &pool, operation, b"cached").await;
        sqlx::query("UPDATE storage_cache_entry SET last_used_at=0")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.prune_transport_caches(&pool, true).await.unwrap().0,
            0
        );
        assert!(path.exists());
        let mut reader = store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_cache_entry")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let (removed, recovery) = store.prune_transport_caches(&pool, false).await.unwrap();
        assert_eq!(removed, 0);
        assert!(recovery.checkpoint_deferred(), "{recovery:?}");
        let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM storage_cache_entry")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(retained, 1);
        let _reopened = Store::open(&store.home.join("state.db")).await.unwrap();
        assert!(path.exists());
        reader.rollback().await.unwrap();
        assert_eq!(
            store.prune_transport_caches(&pool, false).await.unwrap().0,
            6
        );
        assert!(!path.exists());
        assert!(pool.object_path(&canonical).exists());
        for (kind, age, expired) in [
            (CacheKind::SourceBlob, 7 * 86400, true),
            (CacheKind::SourceBlob, 6 * 86400, false),
            (CacheKind::Transport, 30 * 86400, true),
            (CacheKind::Transport, 29 * 86400, false),
            (CacheKind::Transport, -86400, false),
        ] {
            let digest = ObjectDigest::of_bytes(format!("{kind:?}/{age}").as_bytes());
            let directory = store.images_dir.join(kind.directory()).join("sha256");
            let path = directory.join(digest.hex());
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(b"cached")
                .unwrap();
            sqlx::query(
                "INSERT INTO storage_cache_entry(kind,digest,last_used_at) VALUES(?1,?2,?3)",
            )
            .bind(kind.as_str())
            .bind(digest.to_string())
            .bind(chrono::Utc::now().timestamp() - age)
            .execute(&store.pool)
            .await
            .unwrap();
            store.prune_transport_caches(&pool, false).await.unwrap();
            assert_eq!(!path.exists(), expired);
        }
        store.prune_transport_caches(&pool, true).await.unwrap();
    }
    #[tokio::test]
    async fn corrupt_or_missing_canonical_chunks_never_become_zero_fill_or_network_fallback() {
        use std::os::unix::fs::PermissionsExt;
        for missing in [false, true] {
            let bytes = [7; 512];
            let (_temp, store, record, info, owner, _) = retained(&bytes).await;
            let pool = StoragePool::open(&store.images_dir).unwrap();
            drop(owner);
            store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            store.evict_flat_materializations().await.unwrap();
            let chunk = pool.object_path(&ObjectDigest::of_bytes(&bytes));
            if missing {
                std::fs::remove_file(&chunk).unwrap();
            } else {
                std::fs::set_permissions(&chunk, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::write(&chunk, [8; 512]).unwrap();
                std::fs::set_permissions(&chunk, std::fs::Permissions::from_mode(0o400)).unwrap();
            }
            assert!(SnapshotStore::from_store(store.clone())
                .consume(&SnapshotRef::Id(info.id))
                .await
                .is_err());
            assert!(!pool.stream_path(&record.root.stream.stream).exists());
        }
    }

    #[tokio::test]
    async fn missing_flat_without_eviction_intent_is_corruption_even_with_complete_chunks() {
        let (_temp, store, record, info, _owner, _) = retained(&[7; 512]).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        std::fs::remove_file(pool.stream_path(&record.root.stream.stream)).unwrap();
        assert!(SnapshotStore::from_store(store)
            .consume(&SnapshotRef::Id(info.id))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn zstd_writer_profile_reuses_exact_raw_fallback_encoding() {
        use oci::vm_artifact::codec::{ChunkEncoder, ChunkEncoding};
        let mut state = 0x4d595df4d0f33173u64;
        let bytes = (0..512)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect::<Vec<_>>();
        let encoded = ChunkEncoder::new(ChunkEncoding::Zstd)
            .unwrap()
            .encode(&bytes)
            .unwrap();
        assert!(
            matches!(encoded.entry,oci::vm_artifact::wire::ChunkEntry::Data{encoded,..} if encoded.media_type==oci::vm_artifact::wire::PayloadMediaType::RawChunk)
        );
        let (_temp, store, record, _info, owner, root) = retained(&bytes).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        assert!(store
            .retained_stream_representation(owner.id, &record.root.stream, ChunkEncoding::Zstd)
            .await
            .unwrap()
            .is_none());
        let verified =
            VerifiedStreamRepresentation::verify(&pool, owner.id, record.root.stream.clone(), root)
                .unwrap()
                .for_encoding(ChunkEncoding::Zstd)
                .unwrap();
        store
            .register_stream_representation(owner.id, &verified)
            .await
            .unwrap();
        for encoding in [ChunkEncoding::Raw, ChunkEncoding::Zstd] {
            let retained = store
                .retained_stream_representation(owner.id, &record.root.stream, encoding)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.root.0, root);
            assert_eq!(retained.entries.len(), 1);
        }
    }

    #[tokio::test]
    async fn whole_object_keeps_its_chunk_encoding_without_an_immortal_self_cycle() {
        let (_temp, store, _record, info, owner, _) = retained(&[7; 512]).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let bytes = b"retained exact boot";
        let object = ObjectDigest::of_bytes(bytes);
        let file = pool.verify_object(&object).unwrap();
        let map = crate::storage::stream::StreamHasher::new(vm_spec::stream_map::ChunkSize::DISK)
            .hash_open_file(&file, bytes.len() as u64)
            .unwrap()
            .map;
        let content = crate::store::snapshot_store::publish_map(&pool, &store, owner.id, &map)
            .await
            .unwrap();
        let page=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({"schema":1,"kind":"silo-chunk-map","firstChunk":0,"entries":[{"kind":"data","length":bytes.len(),"digest":object,"encoded":{"mediaType":"application/vnd.silo.vm.chunk.v1","digest":object,"size":bytes.len()}}]})).unwrap();
        let page = publish_object(&store, &pool, owner.id, &page).await;
        let root_bytes=oci::vm_artifact::wire::canonical_bytes(&serde_json::json!({"schema":1,"kind":"silo-chunks-v1","stream":map.id(),"length":bytes.len(),"chunkSize":8388608,"pages":[page]})).unwrap();
        let root = publish_object(&store, &pool, owner.id, &root_bytes).await;
        let verified =
            VerifiedStreamRepresentation::verify(&pool, owner.id, content, root).unwrap();
        store
            .register_stream_representation(owner.id, &verified)
            .await
            .unwrap();
        store
            .register_object_stream_representation(owner.id, object, map.id())
            .await
            .unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        store.recover_layer_objects().await.unwrap();
        assert!(pool.object_path(&root).exists());
        assert!(!pool.stream_path(&map.id()).exists());
        SnapshotStore::from_store(store.clone())
            .remove(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        store.recover_layer_objects().await.unwrap();
        assert!(!pool.object_path(&root).exists());
        assert!(!pool.object_path(&object).exists());
    }

    #[tokio::test]
    async fn flat_eviction_stabilizes_recovery_authority_before_unlink() {
        let (_temp, store, record, _info, owner, _) = retained(&[7; 512]).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        let path = pool.stream_path(&record.root.stream.stream);
        let mut reader = store.pool.begin().await.unwrap();
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM storage_stream")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let error = store.evict_flat_materializations().await.unwrap_err();
        assert!(
            matches!(error, crate::LibVmError::DurabilityPending),
            "{error}"
        );
        assert!(path.exists());
        reader.rollback().await.unwrap();
        assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn durable_flat_republication_reconciles_presence_without_replacing_inode() {
        use std::os::unix::fs::MetadataExt;
        for state in ["absent", "evicting"] {
            let bytes = [7; 512];
            let (_temp, store, record, info, owner, _) = retained(&bytes).await;
            let pool = StoragePool::open(&store.images_dir).unwrap();
            drop(owner);
            store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
            sqlx::query("UPDATE storage_stream SET flat_state=?1 WHERE stream_id=?2")
                .bind(state)
                .bind(record.root.stream.stream.to_string())
                .execute(&store.pool)
                .await
                .unwrap();
            let (operation, lease) = store
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            let owner = pool.create_operation_with_lease(operation, lease).unwrap();
            let input = RecordInput::new(&store.images_dir, operation, &bytes).unwrap();
            let (published, roots) = pool.publish_stream_for_catalog(&input.path()).unwrap();
            assert_eq!(published.id, record.root.stream.stream);
            let inode = std::fs::metadata(&published.path).unwrap().ino();
            // Crash boundary: durable publication, but no catalog state update.
            drop(roots);
            drop(owner);
            store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            let consumer = SnapshotStore::from_store(store.clone())
                .consume(&SnapshotRef::Id(info.id))
                .await
                .unwrap();
            assert_eq!(std::fs::metadata(&published.path).unwrap().ino(), inode);
            let actual: String =
                sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                    .bind(published.id.to_string())
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
            assert_eq!(actual, "present");
            drop(consumer);
            store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            assert_eq!(store.evict_flat_materializations().await.unwrap(), 512);
            assert!(!published.path.exists());
        }
    }

    #[tokio::test]
    async fn flat_reconciliation_authenticates_existing_bytes_before_granting_presence() {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, store, record, info, owner, _) = retained(&[7; 512]).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        store.evict_flat_materializations().await.unwrap();
        let path = pool.stream_path(&record.root.stream.stream);
        std::fs::write(&path, [8; 512]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(SnapshotStore::from_store(store.clone())
            .consume(&SnapshotRef::Id(info.id))
            .await
            .is_err());
        let state: String =
            sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                .bind(record.root.stream.stream.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(state, "absent");
    }

    #[tokio::test]
    async fn prune_refuses_missing_present_flat_but_completes_existing_eviction_intent() {
        for authorized in [false, true] {
            let bytes = [7; 512];
            let (_temp, store, record, info, owner, _) = retained(&bytes).await;
            let pool = StoragePool::open(&store.images_dir).unwrap();
            drop(owner);
            store
                .retire_abandoned_storage_operations(&pool)
                .await
                .unwrap();
            let roots = pool.lock_roots().unwrap();
            if authorized {
                sqlx::query("UPDATE storage_stream SET flat_state='evicting' WHERE stream_id=?1")
                    .bind(record.root.stream.stream.to_string())
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            assert!(pool.remove_stream(&record.root.stream.stream).unwrap());
            drop(roots);
            let result = store.evict_flat_materializations().await;
            let state: String =
                sqlx::query_scalar("SELECT flat_state FROM storage_stream WHERE stream_id=?1")
                    .bind(record.root.stream.stream.to_string())
                    .fetch_one(&store.pool)
                    .await
                    .unwrap();
            let snapshots = SnapshotStore::from_store(store.clone());
            if authorized {
                assert_eq!(result.unwrap(), 0);
                assert_eq!(state, "absent");
                let _consumer = snapshots.consume(&SnapshotRef::Id(info.id)).await.unwrap();
                assert_eq!(
                    std::fs::read(pool.stream_path(&record.root.stream.stream)).unwrap(),
                    bytes
                );
            } else {
                assert!(result.is_err());
                assert_eq!(state, "present");
                assert!(snapshots.consume(&SnapshotRef::Id(info.id)).await.is_err());
                assert!(!pool.stream_path(&record.root.stream.stream).exists());
            }
        }
    }

    struct RepresentationFixture {
        _temporary: tempfile::TempDir,
        store: Arc<Store>,
        owner: OperationPaths,
        content: crate::store::models::snapshot::SnapshotStream,
        root: ObjectDigest,
    }

    async fn publish_entries(
        store: &Store,
        pool: &StoragePool,
        operation: uuid::Uuid,
        content: &crate::store::models::snapshot::SnapshotStream,
        entries: &[oci::vm_artifact::wire::ChunkEntry],
    ) -> ObjectDigest {
        let table = oci::vm_artifact::wire::encode_transfer(
            content.stream.to_string().parse().unwrap(),
            content.length,
            entries,
        )
        .unwrap();
        for page in table.pages {
            publish_object(store, pool, operation, &page.bytes).await;
        }
        publish_object(store, pool, operation, &table.root.bytes).await
    }

    async fn encode_payloads(
        store: &Store,
        pool: &StoragePool,
        operation: uuid::Uuid,
        bytes: &[u8],
        encoding: oci::vm_artifact::codec::ChunkEncoding,
    ) -> Vec<oci::vm_artifact::wire::ChunkEntry> {
        let mut encoder = oci::vm_artifact::codec::ChunkEncoder::new(encoding).unwrap();
        let mut entries = Vec::new();
        for payload in bytes.chunks(oci::vm_artifact::wire::CHUNK_SIZE as usize) {
            let encoded = encoder.encode(payload).unwrap();
            if let oci::vm_artifact::wire::ChunkEntry::Data {
                encoded: descriptor,
                ..
            } = &encoded.entry
            {
                let digest = publish_object(store, pool, operation, &encoded.bytes).await;
                assert_eq!(digest.as_bytes(), descriptor.digest.as_bytes());
            }
            entries.push(encoded.entry);
        }
        entries
    }

    async fn representation_fixture(
        bytes: &[u8],
        profile: vm_spec::stream_map::ChunkSize,
        encoding: oci::vm_artifact::codec::ChunkEncoding,
    ) -> RepresentationFixture {
        let temporary = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new(&LocalPaths::new(temporary.path().join("home")))
                .await
                .unwrap(),
        );
        let pool = StoragePool::open(&store.images_dir).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let owner = pool.create_operation_with_lease(operation, lease).unwrap();
        let (staging, mut file) = pool.stage().unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        file.sync_all().unwrap();
        let map = crate::storage::stream::StreamHasher::new(profile)
            .hash_open_file(&file, bytes.len() as u64)
            .unwrap()
            .map;
        let (_stream, roots) = pool
            .publish_staged_stream_for_catalog(staging, file, &map)
            .unwrap();
        store
            .pin_published_storage_dependencies(operation, &[map.id()], &[])
            .await
            .unwrap();
        drop(roots);
        let content = crate::store::snapshot_store::publish_map(&pool, &store, operation, &map)
            .await
            .unwrap();
        let entries = encode_payloads(&store, &pool, operation, bytes, encoding).await;
        let root = publish_entries(&store, &pool, operation, &content, &entries).await;
        let verified =
            VerifiedStreamRepresentation::verify(&pool, operation, content.clone(), root)
                .unwrap()
                .for_encoding(encoding)
                .unwrap();
        store
            .register_stream_representation(operation, &verified)
            .await
            .unwrap();
        RepresentationFixture {
            _temporary: temporary,
            store,
            owner,
            content,
            root,
        }
    }

    async fn reconstruct_fixture(fixture: RepresentationFixture, bytes: &[u8]) {
        let RepresentationFixture {
            _temporary,
            store,
            owner,
            content,
            root,
        } = fixture;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(
            store.evict_flat_materializations().await.unwrap(),
            bytes.len() as u64
        );
        let (operation, lease) = store
            .begin_stopped_operation("raw-export", &[content.stream], &[content.map])
            .await
            .unwrap();
        let _owner = pool.create_operation_with_lease(operation, lease).unwrap();
        store.materialize_stream(operation, &content).await.unwrap();
        assert_eq!(
            std::fs::read(pool.stream_path(&content.stream)).unwrap(),
            bytes
        );
        let actual = crate::storage::stream::StreamHasher::new(
            vm_spec::stream_map::ChunkSize::from_shift(if content.chunk_size == 65536 {
                16
            } else {
                23
            })
            .unwrap(),
        )
        .hash_file(&pool.stream_path(&content.stream))
        .unwrap();
        assert_eq!(actual.id(), content.stream);
        VerifiedStreamRepresentation::verify(&pool, operation, content, root).unwrap();
    }

    #[tokio::test]
    async fn ram_and_disk_representations_round_trip_raw_zstd_zero_gaps_and_short_tails() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use vm_spec::stream_map::ChunkSize;
        let payload = oci::vm_artifact::wire::CHUNK_SIZE as usize;
        let mut bytes = vec![0; payload * 2 + 65536 + 17];
        bytes[4096..8192].fill(7);
        bytes[payload * 2 + 65536..].fill(9);
        for profile in [ChunkSize::RAM, ChunkSize::DISK] {
            for encoding in [ChunkEncoding::Raw, ChunkEncoding::Zstd] {
                let fixture = representation_fixture(&bytes, profile, encoding).await;
                let pool = StoragePool::open(&fixture.store.images_dir).unwrap();
                let (entries, members, map) = crate::store::stream_representation::transfer(
                    &pool,
                    fixture.owner.id,
                    &fixture.content,
                    fixture.root,
                )
                .unwrap();
                assert_eq!(entries.len(), 3);
                assert!(matches!(
                    entries[1],
                    oci::vm_artifact::wire::ChunkEntry::Zero { .. }
                ));
                assert_eq!(map.chunk_size(), profile);
                for chunk in map.present_chunks() {
                    let leaf = ObjectDigest::from_sha256(*chunk.unwrap().digest.as_bytes());
                    if profile == ChunkSize::RAM {
                        assert!(!members.contains(&leaf));
                        assert!(!pool.object_path(&leaf).exists());
                    }
                }
                drop(map);
                reconstruct_fixture(fixture, &bytes).await;
            }
        }
    }

    #[tokio::test]
    async fn valid_payload_sha_does_not_authorize_bytes_under_another_root() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use vm_spec::stream_map::ChunkSize;
        for profile in [ChunkSize::RAM, ChunkSize::DISK] {
            let bytes = vec![7; 65536 + 17];
            let fixture = representation_fixture(&bytes, profile, ChunkEncoding::Raw).await;
            let pool = StoragePool::open(&fixture.store.images_dir).unwrap();
            let mut wrong = bytes.clone();
            wrong[4096..8192].fill(8);
            let entries = encode_payloads(
                &fixture.store,
                &pool,
                fixture.owner.id,
                &wrong,
                ChunkEncoding::Raw,
            )
            .await;
            let root = publish_entries(
                &fixture.store,
                &pool,
                fixture.owner.id,
                &fixture.content,
                &entries,
            )
            .await;
            assert!(VerifiedStreamRepresentation::verify(
                &pool,
                fixture.owner.id,
                fixture.content.clone(),
                root
            )
            .is_err());
            let (_, _, map) = crate::store::stream_representation::transfer(
                &pool,
                fixture.owner.id,
                &fixture.content,
                root,
            )
            .unwrap();
            let output = tempfile::tempfile().unwrap();
            output.set_len(bytes.len() as u64).unwrap();
            assert!(crate::store::stream_representation::authenticate_payloads(
                &pool,
                &map,
                &entries,
                Some(&output)
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn missing_reordered_members_and_wrong_profile_are_refused() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use oci::vm_artifact::wire::ChunkEntry;
        use vm_spec::stream_map::ChunkSize;
        let payload = oci::vm_artifact::wire::CHUNK_SIZE as usize;
        let mut bytes = vec![7; payload * 2];
        bytes[payload..].fill(8);
        for profile in [ChunkSize::RAM, ChunkSize::DISK] {
            let fixture = representation_fixture(&bytes, profile, ChunkEncoding::Raw).await;
            let pool = StoragePool::open(&fixture.store.images_dir).unwrap();
            let (mut entries, _, _) = crate::store::stream_representation::transfer(
                &pool,
                fixture.owner.id,
                &fixture.content,
                fixture.root,
            )
            .unwrap();
            entries.swap(0, 1);
            let reordered = publish_entries(
                &fixture.store,
                &pool,
                fixture.owner.id,
                &fixture.content,
                &entries,
            )
            .await;
            assert!(VerifiedStreamRepresentation::verify(
                &pool,
                fixture.owner.id,
                fixture.content.clone(),
                reordered
            )
            .is_err());
            let mut wrong_profile = fixture.content.clone();
            wrong_profile.chunk_size = if profile == ChunkSize::RAM {
                8388608
            } else {
                65536
            };
            assert!(VerifiedStreamRepresentation::verify(
                &pool,
                fixture.owner.id,
                wrong_profile,
                fixture.root
            )
            .is_err());
            let ChunkEntry::Data { encoded, .. } = entries[0] else {
                panic!("data fixture")
            };
            std::fs::remove_file(
                pool.object_path(&ObjectDigest::from_sha256(*encoded.digest.as_bytes())),
            )
            .unwrap();
            assert!(VerifiedStreamRepresentation::verify(
                &pool,
                fixture.owner.id,
                fixture.content,
                fixture.root
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn scattered_ram_pages_change_only_their_transport_payloads() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use vm_spec::stream_map::ChunkSize;
        let payload = oci::vm_artifact::wire::CHUNK_SIZE as usize;
        let before = vec![3; payload * 4 + 17];
        let mut after = before.clone();
        after[4096..8192].fill(5);
        after[payload * 2 + 65536..payload * 2 + 65536 + 4096].fill(6);
        let baseline = representation_fixture(&before, ChunkSize::RAM, ChunkEncoding::Raw).await;
        let changed = representation_fixture(&after, ChunkSize::RAM, ChunkEncoding::Raw).await;
        assert_ne!(baseline.content.stream, changed.content.stream);
        let baseline_pool = StoragePool::open(&baseline.store.images_dir).unwrap();
        let changed_pool = StoragePool::open(&changed.store.images_dir).unwrap();
        let (before_entries, _, before_map) = crate::store::stream_representation::transfer(
            &baseline_pool,
            baseline.owner.id,
            &baseline.content,
            baseline.root,
        )
        .unwrap();
        let (after_entries, _, after_map) = crate::store::stream_representation::transfer(
            &changed_pool,
            changed.owner.id,
            &changed.content,
            changed.root,
        )
        .unwrap();
        let changed_payloads = before_entries
            .iter()
            .zip(&after_entries)
            .enumerate()
            .filter_map(|(index, (before, after))| (before != after).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(changed_payloads, [0, 2]);
        let changed_units = before_map
            .present_chunks()
            .zip(after_map.present_chunks())
            .filter_map(|(before, after)| {
                let before = before.unwrap();
                let after = after.unwrap();
                (before.digest != after.digest).then_some(after.index)
            })
            .collect::<Vec<_>>();
        assert_eq!(changed_units, [0, 257]);
        drop(after_map);
        reconstruct_fixture(changed, &after).await;
    }

    #[tokio::test]
    async fn empty_and_all_zero_profiles_authenticate_without_payload_objects() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use vm_spec::stream_map::ChunkSize;
        for profile in [ChunkSize::RAM, ChunkSize::DISK] {
            for length in [0, oci::vm_artifact::wire::CHUNK_SIZE as usize + 17] {
                let bytes = vec![0; length];
                let fixture = representation_fixture(&bytes, profile, ChunkEncoding::Zstd).await;
                let pool = StoragePool::open(&fixture.store.images_dir).unwrap();
                let (entries, members, map) = crate::store::stream_representation::transfer(
                    &pool,
                    fixture.owner.id,
                    &fixture.content,
                    fixture.root,
                )
                .unwrap();
                assert!(entries
                    .iter()
                    .all(|entry| matches!(entry, oci::vm_artifact::wire::ChunkEntry::Zero { .. })));
                assert!(map.root().tree_digest().is_none());
                assert_eq!(members.len(), 2 + usize::from(!entries.is_empty()));
                drop(map);
                reconstruct_fixture(fixture, &bytes).await;
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn measured_export_reuses_exact_flat_fingerprint_without_another_payload_scan() {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        use oci::vm_artifact::codec::ChunkEncoding;
        use std::os::unix::fs::PermissionsExt;
        use vm_spec::stream_map::ChunkSize;

        let fixture =
            representation_fixture(&[7; 65536 + 17], ChunkSize::RAM, ChunkEncoding::Raw).await;
        let pool = StoragePool::open(&fixture.store.images_dir).unwrap();
        let path = pool.stream_path(&fixture.content.stream);
        let file = pool.open_stream(&fixture.content.stream).unwrap();
        let map = crate::storage::stream::StreamHasher::new(ChunkSize::RAM)
            .hash_open_file(&file, fixture.content.length)
            .unwrap()
            .map;
        let fingerprint =
            crate::storage::identity_file::SourceFingerprint::new(&file.metadata().unwrap());
        let watcher = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK).unwrap();
        watcher
            .add_watch(&path, AddWatchFlags::IN_OPEN | AddWatchFlags::IN_ACCESS)
            .unwrap();
        let verified = VerifiedStreamRepresentation::from_export(
            &pool,
            fixture.owner.id,
            fixture.content.clone(),
            fixture.root,
            &map,
            Some(fingerprint),
        )
        .unwrap();
        fixture
            .store
            .register_stream_representation(fixture.owner.id, &verified)
            .await
            .unwrap();
        assert_eq!(
            watcher.read_events().unwrap_err(),
            nix::errno::Errno::EAGAIN
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![8; fixture.content.length as usize]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(fixture
            .store
            .register_stream_representation(fixture.owner.id, &verified)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn raw_export_materialization_requires_the_exact_stream_pin() {
        use oci::vm_artifact::codec::ChunkEncoding;
        use vm_spec::stream_map::ChunkSize;

        let bytes = [7; 512];
        let RepresentationFixture {
            _temporary,
            store,
            owner,
            content,
            ..
        } = representation_fixture(&bytes, ChunkSize::RAM, ChunkEncoding::Raw).await;
        let pool = StoragePool::open(&store.images_dir).unwrap();
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(
            store.evict_flat_materializations().await.unwrap(),
            bytes.len() as u64
        );
        let (operation, lease) = store
            .begin_stopped_operation("raw-export", &[], &[content.map])
            .await
            .unwrap();
        let _owner = pool.create_operation_with_lease(operation, lease).unwrap();

        let error = store
            .materialize_stream(operation, &content)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::LibVmError::InvalidStorageRecord { message, .. }
                if message == "snapshot stream was not pinned before access"
        ));
        assert!(!pool.stream_path(&content.stream).exists());

        store
            .pin_published_storage_dependencies(operation, &[content.stream], &[])
            .await
            .unwrap();
        store.materialize_stream(operation, &content).await.unwrap();
        assert_eq!(
            std::fs::read(pool.stream_path(&content.stream)).unwrap(),
            bytes
        );
    }
}

//! Complete canonical chunk representations and shared flat materializations.
//! Operation stream pins protect both representations and flat inodes. Neither
//! canonical objects nor representation edges participate in cache age policy.
use std::collections::{BTreeSet, HashMap};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;

use oci::vm_artifact::wire::{ChunkEntry, TransferRoot};
use sqlx::Row;
use uuid::Uuid;

use crate::storage::identity::{ObjectDigest, StreamId};
use crate::storage::limits::Resource;
use crate::storage::pool::StoragePool;
use crate::storage::stream::{Chunk, StreamMap};
use crate::store::models::snapshot::{invalid, SnapshotStream};
use crate::store::snapshot_store::{recheck_closure, ClosureFingerprints};
use crate::store::Store;
use crate::LibVmError;

/// Constructible only by authenticating the complete local canonical closure.
/// This carries no lease: the containing acquisition must retain its one owner.
pub(crate) struct VerifiedStreamRepresentation {
    content: SnapshotStream,
    root: ObjectDigest,
    members: BTreeSet<ObjectDigest>,
    fingerprints: ClosureFingerprints,
    encoding: oci::vm_artifact::codec::ChunkEncoding,
    raw_only: bool,
}

fn digest(value: oci::changeset::model::ContentDigest) -> ObjectDigest {
    ObjectDigest::from_sha256(*value.as_bytes())
}

fn transfer(
    pool: &StoragePool,
    content: &SnapshotStream,
    root_digest: ObjectDigest,
) -> Result<(Vec<ChunkEntry>, BTreeSet<ObjectDigest>), LibVmError> {
    let root_bytes = pool.read_object(&root_digest, Resource::MetadataPageBytes.maximum())?;
    let root: TransferRoot = oci::vm_artifact::wire::decode_record(&root_bytes).map_err(invalid)?;
    if root.stream.as_bytes() != content.stream.as_bytes() || root.length != content.length {
        return Err(invalid(
            "retained transfer root contradicts canonical stream",
        ));
    }
    let mut members = BTreeSet::from([root_digest, content.map]);
    members.extend(content.map_pages.iter().copied());
    let entries = oci::vm_artifact::wire::verify_transfer(&root, |page| {
        let page = digest(page);
        members.insert(page);
        pool.read_object(&page, Resource::MetadataPageBytes.maximum())
            .map_err(|error| oci::vm_artifact::Error::Invalid(error.to_string()))
    })
    .map_err(invalid)?;
    let mut chunks = Vec::with_capacity(entries.len());
    for entry in &entries {
        chunks.push(match entry {
            ChunkEntry::Zero { .. } => Chunk::Zero,
            ChunkEntry::Data {
                digest: decoded,
                encoded,
                ..
            } => {
                members.insert(digest(encoded.digest));
                Chunk::Data(digest(*decoded))
            }
        });
    }
    let projected = StreamMap::new(content.length, chunks)?;
    let canonical = crate::storage::map::StreamMapRoot::decode(
        &pool.read_object(&content.map, Resource::MetadataPageBytes.maximum())?,
    )?;
    if projected.id() != content.stream
        || canonical.stream != content.stream
        || canonical.length != content.length
        || canonical.pages != content.map_pages
        || canonical.read_map(pool)? != projected
    {
        return Err(invalid(
            "retained representation changes canonical stream map",
        ));
    }
    Ok((entries, members))
}

impl VerifiedStreamRepresentation {
    pub(crate) fn verify(
        pool: &StoragePool,
        content: SnapshotStream,
        root: ObjectDigest,
    ) -> Result<Self, LibVmError> {
        crate::storage::limits::preflight_fd_budget(2)
            .map_err(crate::storage::StorageError::from)?;
        let (entries, members) = transfer(pool, &content, root)?;
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
        let mut decoded = HashMap::new();
        for entry in &entries {
            if let ChunkEntry::Data {
                digest,
                length,
                encoded,
            } = entry
            {
                let facts = (*digest, *length, encoded.media_type);
                if let Some(previous) = decoded.insert(encoded.digest, facts) {
                    if previous != facts {
                        return Err(invalid(
                            "one encoded chunk has contradictory decoded assertions",
                        ));
                    }
                    continue;
                }
                let input =
                    pool.open_object(&crate::store::stream_representation::digest(encoded.digest))?;
                oci::vm_artifact::codec::decode_chunk(entry, input, std::io::sink())
                    .map_err(invalid)?;
            }
        }
        recheck_closure(&fingerprints)?;
        let raw_only=entries.iter().all(|entry| !matches!(entry,ChunkEntry::Data{encoded,..} if encoded.media_type==oci::vm_artifact::wire::PayloadMediaType::ZstdChunk));
        let encoding = if raw_only {
            oci::vm_artifact::codec::ChunkEncoding::Raw
        } else {
            oci::vm_artifact::codec::ChunkEncoding::Zstd
        };
        Ok(Self {
            content,
            root,
            members,
            fingerprints,
            encoding,
            raw_only,
        })
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
        crate::store::snapshot_store::require_operation_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::new(),
            None,
        )
        .await?;
        let root=sqlx::query_scalar::<_,String>("SELECT root_digest FROM stream_representation_profile WHERE stream_id=?1 AND encoding=?2 ORDER BY root_digest LIMIT 1")
            .bind(content.stream.to_string()).bind(encoding_name(encoding)).fetch_optional(&self.pool).await?;
        let Some(root) = root else { return Ok(None) };
        let root: ObjectDigest = root.parse().map_err(invalid)?;
        let pool = StoragePool::open_existing(&self.images_dir)?
            .ok_or_else(|| invalid("retained representation pool is missing"))?;
        let verified = VerifiedStreamRepresentation::verify(&pool, content.clone(), root)?
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
        let (entries, _) = transfer(&pool, content, root)?;
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
        crate::store::snapshot_store::require_operation_closure(
            self,
            operation,
            &BTreeSet::from([stream]),
            &BTreeSet::from([object]),
            None,
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
        crate::store::snapshot_store::require_operation_closure(
            self,
            operation,
            &BTreeSet::from([verified.content.stream]),
            &verified.members,
            None,
        )
        .await?;
        let pool = StoragePool::open(&self.images_dir)?;
        let flat = authenticate_flat_if_present(&pool, &verified.content)?;
        let _roots = pool.lock_roots_shared()?;
        recheck_closure(flat.as_slice())?;
        recheck_closure(&verified.fingerprints)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        insert_representation(&mut tx, verified, flat.is_some()).await?;
        tx.commit().await?;
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
        crate::store::snapshot_store::require_operation_closure(
            self,
            operation,
            &BTreeSet::from([content.stream]),
            &BTreeSet::new(),
            None,
        )
        .await?;
        crate::storage::limits::preflight_fd_budget(4)
            .map_err(crate::storage::StorageError::from)?;
        let pool = StoragePool::open(&self.images_dir)?;
        let row = sqlx::query(
            "SELECT length,map_digest,flat_state FROM storage_stream WHERE stream_id=?1",
        )
        .bind(content.stream.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(()) };
        if row.try_get::<i64, _>("length")? != content.length as i64
            || row.try_get::<String, _>("map_digest")? != content.map.to_string()
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
        let (entries, members) = transfer(&pool, content, root)?;
        exact_members(
            &mut *self.pool.acquire().await?,
            content.stream,
            root,
            &members,
        )
        .await?;
        // Disposable reconstruction bytes use the pool's publication lease,
        // not the consumer's operation directory, which restore owns later.
        let (input, mut output) = pool.stage()?;
        output.set_len(content.length)?;
        let mut decoded = HashMap::new();
        let mut repeated = Vec::new();
        let mut offset = 0u64;
        for entry in &entries {
            let length = match entry {
                ChunkEntry::Zero { length } => {
                    output.seek(SeekFrom::Current(i64::try_from(*length).map_err(invalid)?))?;
                    *length
                }
                ChunkEntry::Data {
                    digest: expected,
                    length,
                    encoded,
                } => {
                    let facts = (*expected, *length, encoded.media_type);
                    if let Some((previous_offset, previous)) = decoded.get(&encoded.digest) {
                        if *previous != facts {
                            return Err(invalid(
                                "one encoded chunk has contradictory decoded assertions",
                            ));
                        }
                        repeated.resize(usize::try_from(*length).map_err(invalid)?, 0);
                        output.read_exact_at(&mut repeated, *previous_offset)?;
                        output.write_all(&repeated)?;
                    } else {
                        oci::vm_artifact::codec::decode_chunk(
                            entry,
                            pool.open_object(&digest(encoded.digest))?,
                            &mut output,
                        )
                        .map_err(invalid)?;
                        decoded.insert(encoded.digest, (offset, facts));
                    }
                    *length
                }
            };
            offset = offset
                .checked_add(length)
                .ok_or_else(|| invalid("reconstruction offset overflow"))?;
        }
        output.sync_all()?;
        drop(output);
        let (published, roots) = pool.publish_stream_for_catalog(&input.path())?;
        if published.id != content.stream || published.length != content.length {
            return Err(invalid("reconstructed stream identity mismatch"));
        }
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
            let rows = sqlx::query("SELECT stream_id,length,map_digest FROM storage_stream WHERE stream_id>?1 AND flat_state IN ('present','evicting') ORDER BY stream_id LIMIT 256")
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
                let canonical = crate::storage::map::StreamMapRoot::decode(
                    &pool.read_object(&map, Resource::MetadataPageBytes.maximum())?,
                )?;
                let content = SnapshotStream {
                    stream,
                    length: u64::try_from(row.try_get::<i64, _>("length")?).map_err(invalid)?,
                    map,
                    map_pages: canonical.pages,
                };
                // Authenticate the complete sole-copy alternative outside roots.
                let verified = VerifiedStreamRepresentation::verify(
                    &pool,
                    content,
                    root.parse().map_err(invalid)?,
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
    let authenticated = pool.authenticate_stream(&content.stream)?;
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
    let row = sqlx::query("SELECT length,map_digest FROM storage_stream WHERE stream_id=?1")
        .bind(content.stream.to_string())
        .fetch_optional(&mut *connection)
        .await?;
    if let Some(row) = row {
        if row.try_get::<i64, _>("length")? != content.length as i64
            || row.try_get::<String, _>("map_digest")? != content.map.to_string()
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
    sqlx::query("INSERT INTO storage_stream(stream_id,length,map_digest,flat_state) VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING")
        .bind(content.stream.to_string()).bind(content.length as i64).bind(content.map.to_string())
        .bind(if flat_present { "present" } else { "absent" }).execute(&mut *connection).await?;
    let row = sqlx::query("SELECT length,map_digest FROM storage_stream WHERE stream_id=?1")
        .bind(content.stream.to_string())
        .fetch_one(&mut *connection)
        .await?;
    if row.try_get::<i64, _>("length")? != content.length as i64
        || row.try_get::<String, _>("map_digest")? != content.map.to_string()
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
        let rows = sqlx::query("SELECT s.stream_id,s.length,s.map_digest,r.root_digest FROM storage_stream s JOIN stream_representation r USING(stream_id) WHERE (s.stream_id,r.root_digest)>(?1,?2) ORDER BY s.stream_id,r.root_digest LIMIT 256")
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
            let canonical = crate::storage::map::StreamMapRoot::decode(
                &pool.read_object(&map, Resource::MetadataPageBytes.maximum())?,
            )?;
            let content = SnapshotStream {
                stream: cursor.0.parse().map_err(invalid)?,
                length: u64::try_from(row.try_get::<i64, _>("length")?).map_err(invalid)?,
                map,
                map_pages: canonical.pages,
            };
            let root = cursor.1.parse().map_err(invalid)?;
            let (entries, members) = transfer(&pool, &content, root)?;
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

/// Reverse reachability shared by canonical object collection and representation
/// retirement. Semantic rows remain structural roots until their explicit release.
pub(crate) async fn stream_reachable(
    connection: &mut sqlx::SqliteConnection,
    stream: StreamId,
) -> Result<bool, LibVmError> {
    let direct:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation_stream WHERE stream_id=?1 UNION ALL SELECT 1 FROM snapshot_stream_dependency WHERE stream_id=?1 UNION ALL SELECT 1 FROM image_stream_dependency WHERE stream_id=?1 UNION ALL SELECT 1 FROM layer_result WHERE pack_stream=?1)")
        .bind(stream.to_string()).fetch_one(&mut *connection).await?;
    if direct {
        return Ok(true);
    }
    let object: Option<String> = sqlx::query_scalar(
        "SELECT object_digest FROM object_stream_representation WHERE stream_id=?1",
    )
    .bind(stream.to_string())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(object) = object else {
        return Ok(false);
    };
    object_base_reachable(connection, object.parse().map_err(invalid)?).await
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

async fn object_base_reachable(
    connection: &mut sqlx::SqliteConnection,
    object: ObjectDigest,
) -> Result<bool, LibVmError> {
    if crate::store::cache_paths::machine_retains_object(connection, object).await? {
        return Ok(true);
    }
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM layer_object_dependency WHERE object_digest=?1 UNION ALL SELECT 1 FROM composition_recipe WHERE record_digest=?1 UNION ALL SELECT 1 FROM composition_result WHERE record_digest=?1 OR fsmeta_digest=?1 UNION ALL SELECT 1 FROM storage_operation_object WHERE object_digest=?1 UNION ALL SELECT 1 FROM snapshot_object_dependency WHERE object_digest=?1 UNION ALL SELECT 1 FROM image_object_dependency WHERE object_digest=?1 UNION ALL SELECT 1 FROM snapshot_capture_provenance WHERE evidence_digest=?1 UNION ALL SELECT 1 FROM snapshot_imported_capture WHERE provenance_digest=?1 OR evidence_digest=?1 UNION ALL SELECT 1 FROM managed_artifact_acquisition a WHERE receipt_digest=?1 AND ((managed_kind='image' AND EXISTS(SELECT 1 FROM storage_image WHERE id=a.managed_id)) OR (managed_kind='snapshot' AND EXISTS(SELECT 1 FROM storage_snapshot WHERE id=a.managed_id))))")
        .bind(object.to_string()).fetch_one(connection).await?)
}

fn authenticate_object_binding(
    pool: &StoragePool,
    object: ObjectDigest,
    stream: StreamId,
) -> Result<crate::storage::identity_file::SourceFingerprint, LibVmError> {
    crate::storage::limits::preflight_fd_budget(1).map_err(crate::storage::StorageError::from)?;
    let file = pool.open_object(&object)?;
    let length = file.metadata()?.len();
    let (authenticated, sha) =
        crate::storage::stream::StreamHasher::new().authenticate_with_sha256(file, length)?;
    if authenticated.map().id() != stream || sha.as_bytes() != object.as_bytes() {
        return Err(invalid(
            "whole-object stream representation contradicts byte identity",
        ));
    }
    Ok(authenticated.fingerprint())
}

pub(crate) async fn object_reachable(
    connection: &mut sqlx::SqliteConnection,
    object: ObjectDigest,
) -> Result<bool, LibVmError> {
    if object_base_reachable(connection, object).await? {
        return Ok(true);
    }
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM stream_representation_object WHERE object_digest=?1)",
    )
    .bind(object.to_string())
    .fetch_one(connection)
    .await?)
}

pub(crate) async fn retire_unrooted(store: &Store, pool: &StoragePool) -> Result<(), LibVmError> {
    let mut cursor = String::new();
    crate::store::cache_paths::check_machine_dependencies(store).await?;
    loop {
        let ids = sqlx::query_scalar::<_, String>(
            "SELECT stream_id FROM storage_stream WHERE stream_id>?1 ORDER BY stream_id LIMIT 256",
        )
        .bind(&cursor)
        .fetch_all(&store.pool)
        .await?;
        if ids.is_empty() {
            break;
        }
        let _roots = pool.lock_roots()?;
        let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
        for id in ids {
            cursor.clone_from(&id);
            let stream = id.parse().map_err(invalid)?;
            if !crate::store::cache_paths::machine_retains_stream(&mut tx, stream).await?
                && !stream_reachable(&mut tx, stream).await?
            {
                sqlx::query("DELETE FROM storage_stream WHERE stream_id=?1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
    }
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
    ) -> Result<u64, LibVmError> {
        let mut removed = 0u64;
        for kind in [CacheKind::SourceBlob, CacheKind::Transport] {
            let mut cursor = String::new();
            let cutoff = chrono::Utc::now().timestamp().saturating_sub(kind.ttl());
            loop {
                let candidates = sqlx::query_scalar::<_,String>("SELECT digest FROM storage_cache_entry WHERE kind=?1 AND digest>?2 AND (?3 OR last_used_at<=?4) ORDER BY digest LIMIT 256")
                    .bind(kind.as_str()).bind(&cursor).bind(pressure).bind(cutoff).fetch_all(&self.pool).await?;
                if candidates.is_empty() {
                    break;
                }
                let _roots = pool.lock_roots()?;
                let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
                for value in candidates {
                    cursor.clone_from(&value);
                    let digest: ObjectDigest = value.parse().map_err(invalid)?;
                    let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_cache_entry e WHERE kind=?1 AND digest=?2 AND (?3 OR last_used_at<=?4) AND NOT EXISTS(SELECT 1 FROM storage_operation_cache p WHERE p.kind=e.kind AND p.digest=e.digest))")
                        .bind(kind.as_str()).bind(&value).bind(pressure).bind(cutoff).fetch_one(&mut *tx).await?;
                    if !eligible {
                        continue;
                    }
                    let path = self
                        .images_dir
                        .join(kind.directory())
                        .join("sha256")
                        .join(digest.hex());
                    crate::store::ensure_cache_paths_unreferenced(
                        &mut tx,
                        std::slice::from_ref(&path),
                        &self.home,
                    )
                    .await?;
                    let directory = crate::paths::OwnedDirectory::open_existing_root(
                        &self.images_dir.join(kind.directory()).join("sha256"),
                    )?
                    .ok_or_else(|| invalid("cache directory disappeared"))?;
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
                    sqlx::query("DELETE FROM storage_cache_entry WHERE kind=?1 AND digest=?2")
                        .bind(kind.as_str())
                        .bind(value)
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await?;
            }
        }
        let _ = pool;
        Ok(removed)
    }
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
            VerifiedStreamRepresentation::verify(&pool, content.clone(), root).unwrap();
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
        snapshots
            .release_retention(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
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
        assert_eq!(store.prune_transport_caches(&pool, true).await.unwrap(), 0);
        assert!(path.exists());
        drop(owner);
        store
            .retire_abandoned_storage_operations(&pool)
            .await
            .unwrap();
        assert_eq!(store.prune_transport_caches(&pool, false).await.unwrap(), 6);
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
            VerifiedStreamRepresentation::verify(&pool, record.root.stream.clone(), root)
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
        let map = crate::storage::stream::StreamHasher::new()
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
        let verified = VerifiedStreamRepresentation::verify(&pool, content, root).unwrap();
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
            .release_retention(&SnapshotRef::Id(info.id))
            .await
            .unwrap();
        store.recover_layer_objects().await.unwrap();
        assert!(!pool.object_path(&root).exists());
        assert!(!pool.object_path(&object).exists());
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
}

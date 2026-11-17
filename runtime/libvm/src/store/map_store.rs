//! Catalog ownership for immutable sparse stream maps.
use std::sync::Arc;

use sqlx::{Row, SqliteConnection};
use uuid::Uuid;
use vm_spec::stream_map::{StreamNode, StreamRoot, MAX_NODE_BYTES, MAX_ROOT_BYTES, ROOT_HEIGHT};

use crate::storage::identity::ObjectDigest;
use crate::storage::map::{AuthenticatedMap, PublishedMapNode};
use crate::storage::pool::StoragePool;
use crate::store::models::snapshot::invalid;
use crate::store::Store;
use crate::LibVmError;

/// The map authority owns a shared operation lease. Its root pin therefore
/// survives capture staging release and protects shared descendants from GC.
#[derive(Clone, Debug)]
pub(crate) struct RetainedMap {
    map: AuthenticatedMap,
}

impl RetainedMap {
    pub(crate) fn into_map(self) -> AuthenticatedMap {
        self.map
    }
}

impl Store {
    pub(crate) async fn retain_memory_baseline(
        &self,
        operation: Uuid,
        root: ObjectDigest,
    ) -> Result<(), LibVmError> {
        let pool = StoragePool::open(self.images_path())?;
        let _lease = pool.existing_lease(operation)?;
        let _roots = pool.lock_roots_shared()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation o JOIN stream_map_root r ON r.root_digest=?2 WHERE o.operation_id=?1 AND o.kind='launch' AND o.state IN ('prepared','staging','committing') AND r.chunk_shift=16)")
            .bind(operation.to_string()).bind(root.to_string()).fetch_one(&mut *tx).await?;
        if !valid {
            return Err(invalid(
                "RAM baseline requires an active launch and admitted RAM root",
            ));
        }
        sqlx::query("INSERT INTO storage_operation_memory_baseline(operation_id,root_digest) VALUES(?1,?2) ON CONFLICT(operation_id) DO UPDATE SET root_digest=excluded.root_digest")
            .bind(operation.to_string()).bind(root.to_string()).execute(&mut *tx).await?;
        sqlx::query(
            "DELETE FROM storage_operation_cut WHERE operation_id=?1 AND role='ram-baseline'",
        )
        .bind(operation.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn admit_published_map_root(
        &self,
        operation: Uuid,
        map: &AuthenticatedMap,
    ) -> Result<RetainedMap, LibVmError> {
        self.admit_published_map_roots(operation, &[map])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("single map admission returned no map"))
    }

    pub(crate) async fn admit_published_map_roots(
        &self,
        operation: Uuid,
        maps: &[&AuthenticatedMap],
    ) -> Result<Vec<RetainedMap>, LibVmError> {
        let pool = StoragePool::open(self.images_path())?;
        let lease = Arc::new(pool.existing_lease(operation)?);
        let _roots = pool.lock_roots_shared()?;
        let mut unique = std::collections::BTreeSet::new();
        let mut missing = Vec::new();
        for map in maps {
            if !unique.insert(map.id()) {
                continue;
            }
            let root = ObjectDigest::from_sha256(*map.id().as_bytes());
            let admitted: Option<(i64, i64)> = sqlx::query_as(
                "SELECT length,chunk_shift FROM stream_map_root WHERE root_digest=?1",
            )
            .bind(root.to_string())
            .fetch_optional(&self.pool)
            .await?;
            match admitted {
                Some((length, shift))
                    if length != map.length() as i64
                        || shift != i64::from(map.chunk_size().shift()) =>
                {
                    return Err(invalid("stream map root has conflicting admitted geometry"));
                }
                // An admitted catalog root is immutable graph authority, unlike
                // a filename hit. Root coordination prevents concurrent prune.
                Some(_) => {}
                None => missing.push(*map),
            }
        }
        // Every graph in this operation shares one file-sync/install/directory
        // barrier. No catalog write can precede completion of that barrier.
        let published = pool.publish_maps_with_observer(&missing, &|_| {})?;
        let published: std::collections::HashMap<_, _> =
            published.iter().map(|node| (node.digest, node)).collect();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operation WHERE operation_id=?1 AND state IN ('prepared','staging','committing'))")
            .bind(operation.to_string()).fetch_one(&mut *tx).await?;
        if !active {
            return Err(invalid(
                "map admission requires an active storage operation",
            ));
        }
        for map in &missing {
            admit_graph_with_nodes(&mut tx, &pool, map.root(), &published).await?;
        }
        for id in unique {
            let root = ObjectDigest::from_sha256(*id.as_bytes());
            sqlx::query("INSERT INTO storage_operation_object(operation_id,object_digest) VALUES(?1,?2) ON CONFLICT DO NOTHING")
                .bind(operation.to_string()).bind(root.to_string()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        let authority = pool.map_authority(lease)?;
        maps.iter()
            .map(|map| {
                Ok(RetainedMap {
                    map: AuthenticatedMap::from_admitted_root(
                        *map.root(),
                        map.role(),
                        Arc::clone(&authority),
                    )?,
                })
            })
            .collect()
    }
}

/// Admit only previously unknown nodes, child first. Existing admitted subtree
/// roots are authority boundaries, not invitations to expand their descendants.
/// The caller holds roots coordination until its ownership transaction commits.
pub(crate) async fn admit_graph(
    connection: &mut SqliteConnection,
    pool: &StoragePool,
    root: &StreamRoot,
) -> Result<(), LibVmError> {
    admit_graph_with_nodes(connection, pool, root, &std::collections::HashMap::new()).await
}

struct GraphNode<'a> {
    height: u8,
    children: std::borrow::Cow<'a, [(u8, ObjectDigest)]>,
}

async fn admit_graph_with_nodes(
    connection: &mut SqliteConnection,
    pool: &StoragePool,
    root: &StreamRoot,
    published: &std::collections::HashMap<ObjectDigest, &PublishedMapNode>,
) -> Result<(), LibVmError> {
    let root_digest = ObjectDigest::from_sha256(*root.id().as_bytes());
    if let Some(row) = published.get(&root_digest) {
        let expected = root
            .tree_digest()
            .map(|digest| vec![(0, ObjectDigest::from_sha256(*digest.as_bytes()))])
            .unwrap_or_default();
        if row.height.is_some() || row.children != expected {
            return Err(invalid("published root edges contradict stream header"));
        }
    } else {
        let bytes = pool.read_object(&root_digest, MAX_ROOT_BYTES as u64)?;
        if StreamRoot::decode(&bytes).map_err(invalid)? != *root {
            return Err(invalid("stream map root contradicts its canonical object"));
        }
    }
    let mut pending = root
        .tree_digest()
        .map(|tree| (ObjectDigest::from_sha256(*tree.as_bytes()), ROOT_HEIGHT));
    let mut stack: Vec<(ObjectDigest, GraphNode<'_>, usize)> = Vec::with_capacity(5);
    loop {
        if let Some((digest, height)) = pending.take() {
            let admitted: Option<Option<i64>> =
                sqlx::query_scalar("SELECT height FROM stream_map_object WHERE digest=?1")
                    .bind(digest.to_string())
                    .fetch_optional(&mut *connection)
                    .await?;
            match admitted {
                Some(admitted_height) if admitted_height != Some(i64::from(height)) => {
                    return Err(invalid("stream map node has conflicting admitted height"));
                }
                Some(_) => {}
                None => {
                    let node = if let Some(row) = published.get(&digest) {
                        if row.height != Some(height) {
                            return Err(invalid("published map node has conflicting height"));
                        }
                        GraphNode {
                            height,
                            children: std::borrow::Cow::Borrowed(&row.children),
                        }
                    } else {
                        let bytes = pool.read_object(&digest, MAX_NODE_BYTES as u64)?;
                        let node = StreamNode::decode(&bytes, height).map_err(invalid)?;
                        GraphNode {
                            height,
                            children: std::borrow::Cow::Owned(if height == 0 {
                                Vec::new()
                            } else {
                                node.entries()
                                    .map(|(slot, child)| {
                                        (slot, ObjectDigest::from_sha256(*child.as_bytes()))
                                    })
                                    .collect()
                            }),
                        }
                    };
                    stack.push((digest, node, 0));
                }
            }
        }
        let Some((_, node, next_slot)) = stack.last_mut() else {
            break;
        };
        if let Some((_, child)) = node.children.get(*next_slot) {
            *next_slot += 1;
            pending = Some((*child, node.height - 1));
        }
        if pending.is_some() {
            continue;
        }
        let Some((digest, node, _)) = stack.pop() else {
            return Err(invalid("stream map admission lost its traversal frame"));
        };
        sqlx::query("INSERT INTO stream_map_object(digest,height) VALUES(?1,?2)")
            .bind(digest.to_string())
            .bind(i64::from(node.height))
            .execute(&mut *connection)
            .await?;
        if node.height > 0 {
            for &(slot, child) in node.children.iter() {
                sqlx::query(
                    "INSERT INTO stream_map_edge(parent_digest,slot,child_digest) VALUES(?1,?2,?3)",
                )
                .bind(digest.to_string())
                .bind(i64::from(slot))
                .bind(child.to_string())
                .execute(&mut *connection)
                .await?;
            }
        }
    }
    sqlx::query(
        "INSERT INTO stream_map_object(digest,height) VALUES(?1,NULL) ON CONFLICT DO NOTHING",
    )
    .bind(root_digest.to_string())
    .execute(&mut *connection)
    .await?;
    sqlx::query("INSERT INTO stream_map_root(root_digest,length,chunk_shift) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING")
        .bind(root_digest.to_string()).bind(root.length() as i64)
        .bind(i64::from(root.chunk_size().shift())).execute(&mut *connection).await?;
    if let Some(tree) = root.tree_digest() {
        sqlx::query("INSERT INTO stream_map_edge(parent_digest,slot,child_digest) VALUES(?1,0,?2) ON CONFLICT DO NOTHING")
            .bind(root_digest.to_string()).bind(ObjectDigest::from_sha256(*tree.as_bytes()).to_string())
            .execute(&mut *connection).await?;
    }
    let row = sqlx::query("SELECT length,chunk_shift FROM stream_map_root WHERE root_digest=?1")
        .bind(root_digest.to_string())
        .fetch_one(connection)
        .await?;
    if row.try_get::<i64, _>("length")? != root.length() as i64
        || row.try_get::<i64, _>("chunk_shift")? != i64::from(root.chunk_size().shift())
    {
        return Err(invalid("stream map root has conflicting admitted geometry"));
    }
    Ok(())
}

/// Graph rows are only an availability cache, not roots. Remove unreachable
/// parents and edges as one transaction before deleting the orphan objects.
pub(crate) async fn retire_unreachable_graph(
    connection: &mut SqliteConnection,
) -> Result<(), LibVmError> {
    sqlx::query("DELETE FROM stream_map_edge WHERE parent_digest NOT IN (SELECT object_digest FROM retained_map_object)")
        .execute(&mut *connection).await?;
    sqlx::query("DELETE FROM stream_map_object WHERE digest NOT IN (SELECT object_digest FROM retained_map_object)")
        .execute(connection).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vm_spec::capture::Sha256Digest;
    use vm_spec::stream_map::{
        build_sorted, Chunk, ChunkChange, ChunkSize, PresentChunk, StreamRole,
    };

    use crate::paths::LocalPaths;
    use crate::storage::identity::ObjectDigest;
    use crate::storage::map::{MapNodeWriter, ProducedMap};
    use crate::storage::pool::StoragePool;
    use crate::store::traits::ImageStore;
    use crate::store::Store;

    fn produced(role: StreamRole) -> ProducedMap {
        let size = role.chunk_size();
        let mut writer = MapNodeWriter::new().unwrap();
        let root = build_sorted(
            128 * size.bytes(),
            size,
            [0, 64].into_iter().map(|index| {
                Ok(PresentChunk {
                    index,
                    digest: Sha256Digest::of_bytes(&[index as u8 + 1]),
                })
            }),
            &mut writer,
        )
        .unwrap();
        writer.finish(root, role, None).unwrap()
    }

    #[tokio::test]
    async fn shared_subtrees_survive_until_last_root_and_prune_removes_only_unreachable_nodes() {
        for role in [StreamRole::Ram, StreamRole::Disk] {
            let temporary = tempfile::tempdir().unwrap();
            let paths = LocalPaths::new(temporary.path());
            let store = Store::new(&paths).await.unwrap();
            let pool = StoragePool::open(paths.images_dir()).unwrap();
            let (first_op, first_lease) = store
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            let (second_op, second_lease) = store
                .begin_stopped_operation("import", &[], &[])
                .await
                .unwrap();
            let first = store
                .admit_published_map_root(first_op, &produced(role).map)
                .await
                .unwrap()
                .into_map();
            let raw_data = ObjectDigest::from_sha256(*Sha256Digest::of_bytes(&[1]).as_bytes());
            assert!(
                !sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM retained_object WHERE object_digest=?1)"
                )
                .bind(raw_data.to_string())
                .fetch_one(&store.pool)
                .await
                .unwrap(),
                "leaf identities do not retain payload objects"
            );
            let old_nodes = sqlx::query_scalar::<_, String>(
                "SELECT digest FROM stream_map_object WHERE height=0",
            )
            .fetch_all(&store.pool)
            .await
            .unwrap();
            assert_eq!(old_nodes.len(), 2);
            let mut writer = MapNodeWriter::new().unwrap();
            let next = first
                .update_sorted(
                    [Ok(ChunkChange {
                        index: 0,
                        value: Chunk::Data(Sha256Digest::of_bytes(b"replacement")),
                    })],
                    &mut writer,
                )
                .unwrap();
            let second = store
                .admit_published_map_root(second_op, &next.map)
                .await
                .unwrap()
                .into_map();
            let current_root = ObjectDigest::from_sha256(*second.id().as_bytes());
            let shared = first.lookup(64).unwrap();
            drop(first);
            sqlx::query("DELETE FROM storage_operation_object WHERE operation_id=?1")
                .bind(first_op.to_string())
                .execute(&store.pool)
                .await
                .unwrap();
            store.prune_images().await.unwrap();
            assert_eq!(second.lookup(64).unwrap(), shared);
            assert!(pool.object_path(&current_root).exists());
            let survivors = old_nodes
                .iter()
                .filter(|value| pool.object_path(&value.parse().unwrap()).exists())
                .count();
            assert_eq!(survivors, 1, "only the shared old leaf remains");
            let present: i64 = sqlx::query_scalar("SELECT count(*) FROM stream_map_object")
                .fetch_one(&store.pool)
                .await
                .unwrap();
            assert!(present > 0);
            drop(second);
            sqlx::query("DELETE FROM storage_operation_object WHERE operation_id=?1")
                .bind(second_op.to_string())
                .execute(&store.pool)
                .await
                .unwrap();
            store.prune_images().await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM stream_map_object")
                    .fetch_one(&store.pool)
                    .await
                    .unwrap(),
                0
            );
            assert!(!pool.object_path(&current_root).exists());
            drop((first_lease, second_lease));
        }
    }

    #[tokio::test]
    async fn zero_root_admission_has_no_node_or_edge_expansion_at_supported_sizes() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path());
        let store = Store::new(&paths).await.unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        for role in [StreamRole::Ram, StreamRole::Disk] {
            for length in [30 << 30, 500 << 30, 1 << 40] {
                let root =
                    vm_spec::stream_map::StreamRoot::empty(length, role.chunk_size()).unwrap();
                let map = MapNodeWriter::new()
                    .unwrap()
                    .finish(root, role, None)
                    .unwrap();
                let retained = store
                    .admit_published_map_root(operation, &map.map)
                    .await
                    .unwrap()
                    .into_map();
                let root_digest = ObjectDigest::from_sha256(*retained.id().as_bytes());
                assert_eq!(pool.read_object(&root_digest, 57).unwrap().len(), 25);
            }
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM stream_map_edge")
                .fetch_one(&store.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM stream_map_object WHERE height IS NOT NULL"
            )
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM storage_operation_object WHERE operation_id=?1"
            )
            .bind(operation.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            6
        );
    }

    #[tokio::test]
    async fn interrupted_graph_admission_rolls_back_without_orphan_retention() {
        const CRASH_HOME: &str = "SILO_MAP_GRAPH_CRASH_HOME";
        if let Ok(home) = std::env::var(CRASH_HOME) {
            let paths = LocalPaths::new(home);
            let store = Store::new(&paths).await.unwrap();
            let pool = StoragePool::open(paths.images_dir()).unwrap();
            let ram = produced(StreamRole::Ram);
            let disk = produced(StreamRole::Disk);
            let (_rows, _roots) = pool
                .publish_maps_for_catalog(&[&ram.map, &disk.map])
                .unwrap();
            assert!(pool.scan_objects().unwrap().count() > 0);
            let mut tx = store.pool.begin().await.unwrap();
            for map in [&ram.map, &disk.map] {
                crate::store::map_store::admit_graph(&mut tx, &pool, map.root())
                    .await
                    .unwrap();
            }
            // Exit with the SQLite write transaction and publication guard live.
            std::process::exit(0);
        }
        let temporary = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("store::map_store::tests::interrupted_graph_admission_rolls_back_without_orphan_retention")
            .arg("--nocapture")
            .env(CRASH_HOME, temporary.path())
            .status().unwrap();
        assert!(status.success());
        let paths = LocalPaths::new(temporary.path());
        let store = Store::open(&paths.state_db_path()).await.unwrap();
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM stream_map_object")
                .fetch_one(&store.pool)
                .await
                .unwrap(),
            0
        );
        assert_eq!(pool.scan_objects().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn catalog_rejects_old_flat_records_receipts_and_invalid_graph_edges() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path());
        let store = Store::new(&paths).await.unwrap();
        for statement in [
            "INSERT INTO storage_snapshot VALUES('old','old',CAST('{\"schema\":1}' AS BLOB),1,0)",
            "INSERT INTO storage_image VALUES('old','old',CAST('{\"schema\":1}' AS BLOB),1,0)",
            "INSERT INTO storage_stream VALUES('a',0,'b',23,'present')",
            "INSERT INTO verified_object VALUES('old',0,0,0,0,0,0,CAST('{\"chunks\":[]}' AS BLOB),'now')",
        ] {
            assert!(sqlx::query(statement).execute(&store.pool).await.is_err(), "{statement}");
        }
        let pool = StoragePool::open(paths.images_dir()).unwrap();
        let (operation, lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let retained = store
            .admit_published_map_root(operation, &produced(StreamRole::Disk).map)
            .await
            .unwrap()
            .into_map();
        let root = ObjectDigest::from_sha256(*retained.id().as_bytes());
        let leaf: String =
            sqlx::query_scalar("SELECT digest FROM stream_map_object WHERE height=0 LIMIT 1")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(sqlx::query("INSERT INTO stream_map_edge VALUES(?1,1,?2)")
            .bind(root.to_string())
            .bind(&leaf)
            .execute(&store.pool)
            .await
            .is_err());
        assert!(pool.map_authority(Arc::new(lease)).is_ok());
        assert_eq!(retained.chunk_size(), ChunkSize::DISK);
    }

    #[tokio::test]
    async fn capture_root_batch_admission_reuses_admitted_authority_without_staging_reads() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let paths = LocalPaths::new(temporary.path());
        let store = Store::new(&paths).await.unwrap();
        let (operation, _lease) = store
            .begin_stopped_operation("import", &[], &[])
            .await
            .unwrap();
        let ram = produced(StreamRole::Ram);
        let disk = produced(StreamRole::Disk);
        let staged = tempfile::tempdir().unwrap();
        for map in [&ram.map, &disk.map] {
            for node in map.nodes() {
                let node = node.unwrap();
                let path = staged.path().join(node.digest.hex());
                std::fs::write(&path, node.bytes).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let writer = MapNodeWriter::adopt_directory(staged.path()).unwrap();
        let ram = writer
            .finish(*ram.map.root(), StreamRole::Ram, None)
            .unwrap()
            .into_map();
        let disk = ram.with_root(*disk.map.root(), StreamRole::Disk).unwrap();
        let retained = store
            .admit_published_map_roots(operation, &[&ram, &disk])
            .await
            .unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM storage_operation_object WHERE operation_id=?1"
            )
            .bind(operation.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            2
        );
        // Capture staging may now be released. A later admission must use the
        // already durable catalog root, not reopen its predecessor directory.
        staged.close().unwrap();
        let reused = store
            .admit_published_map_roots(operation, &[&ram, &disk])
            .await
            .unwrap();
        for (original, reused) in retained.into_iter().zip(reused) {
            let original = original.into_map();
            let reused = reused.into_map();
            assert_eq!(original, reused);
            assert_eq!(original.lookup(64).unwrap(), reused.lookup(64).unwrap());
        }
    }
}

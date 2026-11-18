//! One resolver for `create`, `run`, `restore` and `image pull`.
//!
//! ```text
//!   input ─┬─ sha256:<64 hex> ─────────────────► id of the expected kind
//!          └─ name
//!               1. exact local name of the expected kind ──► local
//!                  (the other kind has it: wrong-kind hint)
//!               2. each search_registries expansion stored ─► local
//!                  locally (skipped by PullPolicy::Always)
//!               3. unique id prefix (>= 3 hex) ─────────────► local
//!               4. PullPolicy::Never ───────────────────────► not found
//!                  otherwise ───────────────────────────────► remote
//! ```
//!
//! A unique id prefix is a local record, so it is tried before the registry:
//! pulling first would contact a registry for every abbreviated id. Local
//! names cannot contain `:` or `/`, so they shadow registry short names and
//! never collide with the canonical references pulled records are named by.
use crate::store::image_store::{image_by_id, image_prefix, named_image, LocalImage};
use crate::store::names::{id_prefix, is_local_name, parse_reference, Spelling};
use crate::store::snapshot_store::{named_snapshot, snapshot_prefix};
use crate::{ImageId, LibVmError, PullPolicy, RegistryPolicy, SnapshotId};

/// What the caller expects the reference to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Image,
    Snapshot,
}

/// One local record of the expected kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalRecord {
    Image(LocalImage),
    Snapshot(SnapshotId),
}

/// A local match, and the exact name it matched when resolved by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalMatch {
    pub(crate) record: LocalRecord,
    pub(crate) name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolution {
    Local(LocalMatch),
    /// Pull this reference; the pull expands it via `search_registries`.
    Remote(String),
}

pub(crate) async fn resolve(
    connection: &mut sqlx::SqliteConnection,
    policy: &RegistryPolicy,
    input: &str,
    kind: Kind,
    pull: PullPolicy,
) -> Result<Resolution, LibVmError> {
    let name = match parse_reference(input)? {
        Spelling::Id(digest) => {
            return by_id(connection, input, *digest.as_bytes(), kind)
                .await
                .map(Resolution::Local)
        }
        Spelling::Name(name) => name,
    };
    if is_local_name(&name) {
        if let Some(record) = named(connection, &name, kind).await? {
            return Ok(Resolution::Local(LocalMatch {
                record,
                name: Some(name),
            }));
        }
        refuse_other_kind(connection, &name, input, kind).await?;
    }
    let candidates = policy
        .candidates(&name)
        .ok()
        .map(|candidates| {
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if pull != PullPolicy::Always {
        for candidate in &candidates {
            if let Some(record) = named(connection, candidate, kind).await? {
                return Ok(Resolution::Local(LocalMatch {
                    record,
                    name: Some(candidate.clone()),
                }));
            }
            refuse_other_kind(connection, candidate, input, kind).await?;
        }
    }
    if let Some(prefix) = id_prefix(&name) {
        let matches = match kind {
            Kind::Image => image_prefix(connection, prefix)
                .await?
                .into_iter()
                .map(LocalRecord::Image)
                .collect::<Vec<_>>(),
            Kind::Snapshot => snapshot_prefix(connection, prefix)
                .await?
                .into_iter()
                .map(LocalRecord::Snapshot)
                .collect(),
        };
        match matches.as_slice() {
            [] => {}
            [record] => {
                return Ok(Resolution::Local(LocalMatch {
                    record: *record,
                    name: None,
                }))
            }
            matches => {
                return Err(LibVmError::AmbiguousRecordPrefix {
                    prefix: prefix.to_owned(),
                    count: matches.len(),
                })
            }
        }
    }
    if pull == PullPolicy::Never || candidates.is_empty() {
        return Err(not_found(input, kind));
    }
    Ok(Resolution::Remote(name))
}

/// Local steps only: never resolves to a registry pull.
pub(crate) async fn resolve_local(
    connection: &mut sqlx::SqliteConnection,
    policy: &RegistryPolicy,
    input: &str,
    kind: Kind,
) -> Result<LocalMatch, LibVmError> {
    match resolve(connection, policy, input, kind, PullPolicy::Never).await? {
        Resolution::Local(local) => Ok(local),
        Resolution::Remote(_) => Err(not_found(input, kind)),
    }
}

/// Typed refusal when `name` is a local name of the other kind.
async fn refuse_other_kind(
    connection: &mut sqlx::SqliteConnection,
    name: &str,
    input: &str,
    kind: Kind,
) -> Result<(), LibVmError> {
    let other = match kind {
        Kind::Image => Kind::Snapshot,
        Kind::Snapshot => Kind::Image,
    };
    if named(connection, name, other).await?.is_some() {
        return Err(wrong_kind(input, kind));
    }
    Ok(())
}

async fn named(
    connection: &mut sqlx::SqliteConnection,
    name: &str,
    kind: Kind,
) -> Result<Option<LocalRecord>, LibVmError> {
    Ok(match kind {
        Kind::Image => named_image(connection, name).await?.map(LocalRecord::Image),
        Kind::Snapshot => named_snapshot(connection, name)
            .await?
            .map(LocalRecord::Snapshot),
    })
}

async fn by_id(
    connection: &mut sqlx::SqliteConnection,
    input: &str,
    bytes: [u8; 32],
    kind: Kind,
) -> Result<LocalMatch, LibVmError> {
    let image = image_by_id(&mut *connection, ImageId::from_sha256(bytes)).await?;
    let snapshot =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM storage_snapshot WHERE id=?1)")
            .bind(SnapshotId::from_sha256(bytes).to_string())
            .fetch_one(connection)
            .await?
            .then(|| SnapshotId::from_sha256(bytes));
    let record = match (kind, image, snapshot) {
        (Kind::Image, Some(image), _) => LocalRecord::Image(image),
        (Kind::Snapshot, _, Some(snapshot)) => LocalRecord::Snapshot(snapshot),
        (Kind::Image, None, Some(_)) | (Kind::Snapshot, Some(_), None) => {
            return Err(wrong_kind(input, kind))
        }
        (_, None, None) => return Err(not_found(input, kind)),
    };
    Ok(LocalMatch { record, name: None })
}

fn not_found(input: &str, kind: Kind) -> LibVmError {
    match kind {
        Kind::Image => LibVmError::ImageNotFound {
            reference: input.to_owned(),
        },
        Kind::Snapshot => LibVmError::SnapshotNotFound {
            reference: input.to_owned(),
        },
    }
}

fn wrong_kind(input: &str, expected: Kind) -> LibVmError {
    match expected {
        Kind::Image => LibVmError::SnapshotIsNotAnImage {
            reference: input.to_owned(),
        },
        Kind::Snapshot => LibVmError::ImageIsNotASnapshot {
            reference: input.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::paths::LocalPaths;
    use crate::resolve::{resolve, resolve_local, Kind, LocalMatch, LocalRecord, Resolution};
    use crate::store::image_store::LocalImage;
    use crate::store::Store;
    use crate::{ImageId, LibVmError, PullPolicy, RegistryAction, RegistryPolicy, SnapshotId};

    /// A record row admitted by the catalog's checks; the resolver reads
    /// only ids and names.
    const RECORD: &str = r#"{"schema":1,"root":{"stream":{"chunkSize":8388608}}}"#;

    struct Catalog {
        _temp: tempfile::TempDir,
        store: Store,
    }

    async fn catalog() -> Catalog {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(&LocalPaths::new(temp.path().join("home")))
            .await
            .unwrap();
        Catalog { _temp: temp, store }
    }

    /// `sha256:` + `prefix` padded with zeros to 64 hex digits.
    fn id(prefix: &str) -> String {
        format!("sha256:{prefix:0<64}")
    }

    impl Catalog {
        async fn image(&self, prefix: &str, names: &[&str]) -> ImageId {
            let id = id(prefix);
            sqlx::query("INSERT INTO storage_image(id,record_digest,record_bytes,created_at) VALUES(?1,?1,CAST(?2 AS BLOB),0)")
                .bind(&id)
                .bind(RECORD)
                .execute(&self.store.pool)
                .await
                .unwrap();
            for name in names {
                sqlx::query(
                    "INSERT INTO image_name(name,stored_image_id,updated_at) VALUES(?1,?2,0)",
                )
                .bind(name)
                .bind(&id)
                .execute(&self.store.pool)
                .await
                .unwrap();
            }
            id.parse().unwrap()
        }

        async fn snapshot(&self, prefix: &str, names: &[&str]) -> SnapshotId {
            let id = id(prefix);
            sqlx::query("INSERT INTO storage_snapshot(id,record_digest,record_bytes,created_at) VALUES(?1,?1,CAST(?2 AS BLOB),0)")
                .bind(&id)
                .bind(RECORD)
                .execute(&self.store.pool)
                .await
                .unwrap();
            for name in names {
                sqlx::query(
                    "INSERT INTO snapshot_name(name,snapshot_id,updated_at) VALUES(?1,?2,0)",
                )
                .bind(name)
                .bind(&id)
                .execute(&self.store.pool)
                .await
                .unwrap();
            }
            id.parse().unwrap()
        }

        async fn resolve(
            &self,
            policy: &RegistryPolicy,
            input: &str,
            kind: Kind,
            pull: PullPolicy,
        ) -> Result<Resolution, LibVmError> {
            let mut connection = self.store.pool.acquire().await.unwrap();
            resolve(&mut connection, policy, input, kind, pull).await
        }
    }

    fn image(id: ImageId, name: Option<&str>) -> Resolution {
        Resolution::Local(LocalMatch {
            record: LocalRecord::Image(LocalImage::Stored(id)),
            name: name.map(str::to_owned),
        })
    }

    fn snapshot(id: SnapshotId, name: Option<&str>) -> Resolution {
        Resolution::Local(LocalMatch {
            record: LocalRecord::Snapshot(id),
            name: name.map(str::to_owned),
        })
    }

    fn search(registries: &[&str]) -> RegistryPolicy {
        RegistryPolicy::new(
            RegistryAction::Allow,
            registries
                .iter()
                .map(|registry| (*registry).to_owned())
                .collect(),
            Vec::new(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_local_name_wins_over_the_registry_short_name_for_every_pull_policy() {
        let catalog = catalog().await;
        let local = catalog.image("a1", &["hello"]).await;
        catalog
            .image("b1", &["docker.io/library/hello:latest"])
            .await;
        let policy = RegistryPolicy::default();
        for pull in [PullPolicy::IfMissing, PullPolicy::Always, PullPolicy::Never] {
            assert_eq!(
                catalog
                    .resolve(&policy, "hello", Kind::Image, pull)
                    .await
                    .unwrap(),
                image(local, Some("hello")),
                "{pull:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_image_and_a_snapshot_share_a_name_and_resolve_independently() {
        let catalog = catalog().await;
        let local_image = catalog.image("a1", &["hello"]).await;
        let local_snapshot = catalog.snapshot("b1", &["hello"]).await;
        let policy = RegistryPolicy::default();
        assert_eq!(
            catalog
                .resolve(&policy, "hello", Kind::Image, PullPolicy::Never)
                .await
                .unwrap(),
            image(local_image, Some("hello"))
        );
        assert_eq!(
            catalog
                .resolve(&policy, "hello", Kind::Snapshot, PullPolicy::Never)
                .await
                .unwrap(),
            snapshot(local_snapshot, Some("hello"))
        );
    }

    #[tokio::test]
    async fn references_with_a_colon_or_slash_are_always_registry_references() {
        let catalog = catalog().await;
        let policy = RegistryPolicy::default();
        for input in ["a:b", "a/b", "registry.example/a/b:c"] {
            for kind in [Kind::Image, Kind::Snapshot] {
                assert_eq!(
                    catalog
                        .resolve(&policy, input, kind, PullPolicy::IfMissing)
                        .await
                        .unwrap(),
                    Resolution::Remote(input.to_owned()),
                    "{input} {kind:?}"
                );
            }
            assert!(matches!(
                catalog
                    .resolve(&policy, input, Kind::Image, PullPolicy::Never)
                    .await,
                Err(LibVmError::ImageNotFound { reference }) if reference == input
            ));
            assert!(matches!(
                catalog
                    .resolve(&policy, input, Kind::Snapshot, PullPolicy::Never)
                    .await,
                Err(LibVmError::SnapshotNotFound { reference }) if reference == input
            ));
        }
        // A stored expansion of a reference is local; the input itself is
        // never matched as a local name.
        let pulled = catalog.image("a1", &["docker.io/library/a:b"]).await;
        assert_eq!(
            catalog
                .resolve(&policy, "a:b", Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap(),
            image(pulled, Some("docker.io/library/a:b"))
        );
    }

    #[tokio::test]
    async fn stored_expansions_follow_search_registry_order_and_always_skips_them() {
        let catalog = catalog().await;
        let first = catalog.image("a1", &["first.example/team/app:1"]).await;
        let second = catalog.image("b1", &["second.example/team/app:1"]).await;
        for (registries, expected, name) in [
            (
                ["first.example", "second.example"],
                first,
                "first.example/team/app:1",
            ),
            (
                ["second.example", "first.example"],
                second,
                "second.example/team/app:1",
            ),
        ] {
            let policy = search(&registries);
            assert_eq!(
                catalog
                    .resolve(&policy, "team/app:1", Kind::Image, PullPolicy::IfMissing)
                    .await
                    .unwrap(),
                image(expected, Some(name))
            );
            assert_eq!(
                catalog
                    .resolve(&policy, "team/app:1", Kind::Image, PullPolicy::Always)
                    .await
                    .unwrap(),
                Resolution::Remote("team/app:1".to_owned())
            );
        }
        // An expansion missing locally falls through to the next one.
        let policy = search(&["missing.example", "second.example"]);
        assert_eq!(
            catalog
                .resolve(&policy, "team/app:1", Kind::Image, PullPolicy::Never)
                .await
                .unwrap(),
            image(second, Some("second.example/team/app:1"))
        );
    }

    #[tokio::test]
    async fn the_other_kind_gets_a_wrong_kind_hint_by_name_expansion_or_id() {
        let catalog = catalog().await;
        let snapshot_id = catalog
            .snapshot("a1", &["saved", "docker.io/library/saved:v1"])
            .await;
        let image_id = catalog.image("b1", &["web"]).await;
        let policy = RegistryPolicy::default();
        for input in ["saved", "saved:v1", &snapshot_id.to_string()] {
            let error = catalog
                .resolve(&policy, input, Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, LibVmError::SnapshotIsNotAnImage { reference } if reference == input),
                "{input}: {error:?}"
            );
            assert!(error
                .to_string()
                .contains(&format!("use `silo restore {input}`")));
        }
        for input in ["web", &image_id.to_string()] {
            let error = catalog
                .resolve(&policy, input, Kind::Snapshot, PullPolicy::IfMissing)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, LibVmError::ImageIsNotASnapshot { reference } if reference == input),
                "{input}: {error:?}"
            );
            assert!(error
                .to_string()
                .contains(&format!("use `silo create {input}`")));
        }
    }

    #[tokio::test]
    async fn an_id_prefix_resolves_only_when_unique_and_of_the_expected_kind() {
        let catalog = catalog().await;
        let first = catalog.image("abc1", &[]).await;
        catalog.image("abc2", &[]).await;
        let snapshot_id = catalog.snapshot("def1", &[]).await;
        let policy = RegistryPolicy::default();
        assert!(matches!(
            catalog
                .resolve(&policy, "abc", Kind::Image, PullPolicy::IfMissing)
                .await,
            Err(LibVmError::AmbiguousRecordPrefix { prefix, count: 2 }) if prefix == "abc"
        ));
        assert_eq!(
            catalog
                .resolve(&policy, "abc1", Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap(),
            image(first, None)
        );
        let mut connection = catalog.store.pool.acquire().await.unwrap();
        assert_eq!(
            resolve_local(&mut connection, &policy, "def", Kind::Snapshot)
                .await
                .unwrap(),
            LocalMatch {
                record: LocalRecord::Snapshot(snapshot_id),
                name: None
            }
        );
        drop(connection);
        // A prefix never crosses kinds: `def` is not an image prefix.
        assert!(matches!(
            catalog
                .resolve(&policy, "def", Kind::Image, PullPolicy::Never)
                .await,
            Err(LibVmError::ImageNotFound { .. })
        ));
        // Full ids resolve without a name.
        assert_eq!(
            catalog
                .resolve(&policy, &first.to_string(), Kind::Image, PullPolicy::Always)
                .await
                .unwrap(),
            image(first, None)
        );
    }

    #[tokio::test]
    async fn a_unique_prefix_is_local_before_any_pull_but_a_name_still_wins() {
        let catalog = catalog().await;
        let prefixed = catalog.image("fed1", &[]).await;
        let policy = RegistryPolicy::default();
        // `fed` also expands to docker.io/library/fed:latest, which would pull.
        assert_eq!(
            catalog
                .resolve(&policy, "fed", Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap(),
            image(prefixed, None)
        );
        // Two hex characters are below the prefix minimum.
        assert_eq!(
            catalog
                .resolve(&policy, "fe", Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap(),
            Resolution::Remote("fe".to_owned())
        );
        let named = catalog.image("0a1", &["fed"]).await;
        assert_eq!(
            catalog
                .resolve(&policy, "fed", Kind::Image, PullPolicy::IfMissing)
                .await
                .unwrap(),
            image(named, Some("fed"))
        );
    }
}

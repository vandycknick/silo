//! Real files and SQLite, initialized through the existing unit-test store seam.
//! No capability query or hypervisor access. Native replay qualification lives in smoke.

#[cfg(target_os = "linux")]
#[path = "../../tests/support/live_catalog.rs"]
mod live_catalog;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use crate::{
        ExternalResourcePolicy, ForkOptions, ImageSource, Machine, MachineRef, ProcessConfig,
        ResolvedRuntimeComponents, RestoreOptions, Runtime, RuntimeConfig, SnapshotOptions,
        SnapshotRef, SnapshotStore,
    };
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use sqlx::{Connection, SqliteConnection};
    use test_utils::direct_kernel::host_kernel;

    struct Fixture {
        _files: tempfile::TempDir,
        _run: tempfile::TempDir,
        home: PathBuf,
        runtime: Runtime,
        source: Machine,
        components: ResolvedRuntimeComponents,
    }

    fn bytes(path: &Path) -> (u64, [u8; 32]) {
        let mut file = File::open(path).expect("independent raw byte reader");
        let before = file.metadata().expect("pinned source metadata");
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).expect("read complete logical bytes");
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        let after = file.metadata().expect("source after read");
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        (before.len(), digest.finalize().into())
    }

    fn root(home: &Path, machine: &Machine) -> PathBuf {
        home.join("machines").join(machine.id()).join("root.raw")
    }

    async fn config(home: &Path, machine: &Machine) -> Value {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(home.join("state.db"))
            .read_only(true)
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("real read-only SQLite connection");
        let raw: String =
            sqlx::query_scalar("SELECT json(config_json) FROM machine_config WHERE id=?")
                .bind(machine.id())
                .fetch_one(&mut connection)
                .await
                .expect("current machine configuration");
        connection.close().await.expect("close SQL reader");
        let value: Value = serde_json::from_str(&raw).expect("decode actual row");
        assert!(value.get("machineDir").is_none());
        value
    }

    async fn assert_stopped(home: &Path, machine: &Machine) {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(home.join("state.db"))
            .read_only(true)
            .create_if_missing(false);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .expect("read real child lifecycle row");
        let state: (String, Option<String>, Option<i64>) = sqlx::query_as("SELECT status,json_extract(state_json,'$.runId'),json_extract(state_json,'$.vmmonPid') FROM machine_state WHERE machine_id=?")
            .bind(machine.id()).fetch_one(&mut connection).await.expect("child stopped lifecycle");
        connection
            .close()
            .await
            .expect("close child lifecycle reader");
        assert_eq!(state, ("stopped".into(), None, None));
    }

    fn semantics(mut value: Value) -> Value {
        for key in [
            "id",
            "lockId",
            "name",
            "createdAt",
            "modifiedAt",
            "imageRef",
        ] {
            value.as_object_mut().expect("config object").remove(key);
        }
        let kernel = value["spec"]["boot"]["kernel"]
            .as_object_mut()
            .expect("kernel object");
        kernel.remove("path");
        kernel.remove("initramfs");
        for disk in value["spec"]["storage"]["disks"]
            .as_array_mut()
            .expect("disk array")
        {
            let disk = disk.as_object_mut().expect("disk object");
            disk.remove("path");
            disk.remove("blockId");
        }
        // Captured/default/custom agent paths are boot-byte authority, not
        // process policy. Exact pinned object bytes have separate assertions.
        if let Some(guest) = value.get_mut("guest").and_then(Value::as_object_mut) {
            guest.remove("agent");
        }
        value
    }

    impl Fixture {
        async fn new(empty_command: bool, external: bool) -> Self {
            let files = match std::env::var_os("SILO_TEST_COPY_DIR") {
                Some(parent) => tempfile::Builder::new()
                    .prefix("stopped-")
                    .tempdir_in(parent),
                None => tempfile::Builder::new().prefix("stopped-").tempdir(),
            }
            .expect("owned real-filesystem fixture");
            let run = tempfile::Builder::new()
                .prefix("stpr-")
                .tempdir_in(if cfg!(target_os = "macos") {
                    "/private/tmp"
                } else {
                    "/tmp"
                })
                .expect("short run-root fixture");
            let home = files.path().join("home");
            let kernel = files.path().join("kernel");
            let initramfs = files.path().join("base-initramfs");
            let agent = files.path().join("agent");
            std::fs::write(&kernel, host_kernel("exact kernel bytes, never executed"))
                .expect("write inert byte fixture");
            std::fs::write(&initramfs, b"exact base initramfs bytes, never booted")
                .expect("write init fixture");
            std::fs::write(&agent, b"exact agent bytes, never executed")
                .expect("write agent fixture");
            for asset in [&kernel, &initramfs] {
                std::fs::set_permissions(asset, std::fs::Permissions::from_mode(0o600))
                    .expect("private boot asset mode");
            }
            std::fs::set_permissions(run.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private run-root mode");
            std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700))
                .expect("executable component mode");
            // A real monitor component is retained as byte identity, but this
            // store-level test never invokes native capability discovery.
            let executable = test_utils::mock_vmm_binary().to_path_buf();
            let components = ResolvedRuntimeComponents::from_paths(
                executable.clone(),
                executable,
                kernel,
                initramfs,
                agent,
                files.path().to_owned(),
            )
            .expect("explicit file components");
            let config = RuntimeConfig::local(&home).with_run_root(run.path());
            let paths = crate::paths::LocalPaths::from_roots(
                config.resolve_roots().expect("explicit private paths"),
            );
            let store = crate::store::Store::new(&paths)
                .await
                .expect("real SQLite store");
            let runtime = Runtime::from_store(
                paths,
                std::sync::Arc::new(store),
                crate::RuntimeNetworkingConfig::default(),
                crate::RegistryPolicy::default(),
                components.clone(),
                None,
            )
            .await
            .expect("real runtime/catalog without host discovery");
            let disk = files.path().join("input.raw");
            disk_image::ext4::Formatter::new(&disk, 4096, 16 * 1024 * 1024)
                .expect("real ext4 root")
                .close()
                .expect("finish ext4 root");
            std::fs::set_permissions(&disk, std::fs::Permissions::from_mode(0o600))
                .expect("private raw input mode");
            let mut file = OpenOptions::new()
                .write(true)
                .open(&disk)
                .expect("private raw input");
            let filesystem_length = file.metadata().expect("ext4 geometry").len();
            file.set_len(filesystem_length + 512)
                .expect("short final stream chunk/trailing hole");
            file.seek(SeekFrom::End(-512)).expect("root tail");
            file.write_all(&[0xa3; 512]).expect("nonzero root tail");
            file.sync_all().expect("source bytes durable");
            let process = ProcessConfig {
                entrypoint: Some(Vec::new()),
                command: if empty_command {
                    Some(Vec::new())
                } else {
                    None
                },
                environment: BTreeMap::from([
                    ("EMPTY".into(), String::new()),
                    ("UNICODE".into(), "雪-é".into()),
                ]),
                working_directory: "/".into(),
                user: Some("root".into()),
            };
            let mut builder = runtime
                .machine()
                .name("source")
                .image_source(ImageSource::disk(disk))
                .network(|network| network.none())
                .cpus(2)
                .process(process)
                .label("é", "雪")
                .metadata_entry("unchanged", "configured")
                .kernel_args(vec!["silo.stopped=exact".into()])
                .userdata("configured user data");
            if external {
                let data = files.path().join("external.raw");
                std::fs::write(&data, [0x31; 4096]).expect("external data");
                builder = builder.disks(vec![data]);
            }
            let source = builder.create().await.expect("never-started source");
            Self {
                _files: files,
                _run: run,
                home,
                runtime,
                source,
                components,
            }
        }
    }

    #[tokio::test]
    async fn stopped_snapshot_two_private_children_full_config_and_retention() {
        for empty_command in [false, true] {
            let fixture = Fixture::new(empty_command, false).await;
            let baseline = bytes(&root(&fixture.home, &fixture.source));
            let source_config = semantics(config(&fixture.home, &fixture.source).await);
            let info = fixture
                .source
                .snapshot_stopped(SnapshotOptions {
                    name: Some("checkpoint".into()),
                    ..Default::default()
                })
                .await
                .expect("real stopped snapshot");
            let snapshots = SnapshotStore::open(&fixture.home)
                .await
                .expect("same real catalog");
            let reference = SnapshotRef::Id(info.id);
            assert!(info.retained);
            assert_eq!(info.aliases, vec!["checkpoint"]);
            assert_ne!(info.id.to_string(), info.record_digest.to_string());
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(fixture.home.join("state.db"))
                .read_only(true)
                .create_if_missing(false);
            let mut reader = SqliteConnection::connect_with(&options)
                .await
                .expect("artifact SQL evidence");
            let artifact: Vec<u8> =
                sqlx::query_scalar("SELECT record_bytes FROM storage_snapshot WHERE id=?")
                    .bind(info.id.to_string())
                    .fetch_one(&mut reader)
                    .await
                    .expect("immutable artifact bytes");
            reader.close().await.expect("close artifact reader");
            let artifact: Value = serde_json::from_slice(&artifact)
                .expect("decode actual immutable bytes independently");
            assert_eq!(artifact["captureKind"], "stopped-storage");
            assert_eq!(artifact["purpose"], "checkpoint");
            assert_eq!(
                artifact["stopOutcome"], "unknown",
                "a fresh fsync must not invent historical clean evidence"
            );
            assert_eq!(artifact["externalRequirements"], serde_json::json!([]));
            let first = fixture
                .runtime
                .restore_snapshot(
                    reference.clone(),
                    RestoreOptions {
                        name: Some("first".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("first private restore");
            let second = fixture
                .runtime
                .restore_snapshot(
                    "image:checkpoint".parse().expect("shared image namespace"),
                    RestoreOptions {
                        name: Some("second".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("second private restore");
            let first_root = root(&fixture.home, &first);
            let second_root = root(&fixture.home, &second);
            assert_eq!(bytes(&first_root), baseline);
            assert_eq!(bytes(&second_root), baseline);
            assert_eq!(
                source_config,
                semantics(config(&fixture.home, &first).await)
            );
            assert_eq!(
                source_config,
                semantics(config(&fixture.home, &second).await)
            );
            let source_meta =
                std::fs::metadata(root(&fixture.home, &fixture.source)).expect("source metadata");
            let a = std::fs::metadata(&first_root).expect("first metadata");
            let b = std::fs::metadata(&second_root).expect("second metadata");
            assert_ne!((source_meta.dev(), source_meta.ino()), (a.dev(), a.ino()));
            assert_ne!((a.dev(), a.ino()), (b.dev(), b.ino()));
            assert_eq!(
                (a.nlink(), b.nlink(), a.mode() & 0o777, b.mode() & 0o777),
                (1, 1, 0o600, 0o600)
            );
            for child in [&first, &second] {
                assert_stopped(&fixture.home, child).await;
            }
            let mut mutate = OpenOptions::new()
                .write(true)
                .open(&first_root)
                .expect("first independent writer");
            mutate.write_all(b"first-child-only").expect("write child");
            mutate.sync_all().expect("sync child");
            assert_eq!(bytes(&second_root), baseline);
            assert_eq!(bytes(&root(&fixture.home, &fixture.source)), baseline);
            assert!(snapshots
                .remove_alias("checkpoint")
                .await
                .expect("alias-only deletion"));
            assert!(
                snapshots
                    .inspect(&reference)
                    .await
                    .expect("unaliased retained artifact")
                    .retained
            );
            fixture
                .source
                .clone()
                .remove()
                .await
                .expect("remove source machine");
            std::fs::write(
                fixture.components.kernel(),
                host_kernel("replaced runtime kernel"),
            )
            .expect("replace old default kernel bytes");
            std::fs::write(
                fixture.components.initramfs(),
                b"replaced runtime base initramfs",
            )
            .expect("replace old init bytes");
            std::fs::write(fixture.components.agent(), b"replaced runtime agent")
                .expect("replace old agent bytes");
            let third = fixture
                .runtime
                .restore_snapshot(
                    reference.clone(),
                    RestoreOptions {
                        name: Some("after-source-delete".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("retained boot/storage restore");
            assert_eq!(bytes(&root(&fixture.home, &third)), baseline);
            assert!(snapshots
                .release_retention(&reference)
                .await
                .expect("release explicit retention"));
            fixture
                .runtime
                .images()
                .prune()
                .await
                .expect("real bounded GC");
            assert_eq!(bytes(&root(&fixture.home, &second)), baseline);
            assert_eq!(bytes(&root(&fixture.home, &third)), baseline);
        }
    }

    #[tokio::test]
    async fn stopped_external_default_refusal_has_no_catalog_or_storage_effects() {
        let fixture = Fixture::new(false, true).await;
        let before = crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await;
        let baseline = bytes(&root(&fixture.home, &fixture.source));
        let store = fixture.runtime.native_store().unwrap();
        let source_durability = store
            .machine_durability(fixture.source.machine_id())
            .await
            .unwrap();
        assert_eq!(source_durability, Some(crate::MachineDurability::Durable));
        assert!(fixture
            .source
            .fork_stopped(ForkOptions {
                name: Some("refused-fork".into()),
                ..Default::default()
            })
            .await
            .is_err());
        assert!(fixture
            .source
            .snapshot_stopped(SnapshotOptions {
                name: Some("refused-snapshot".into()),
                ..Default::default()
            })
            .await
            .is_err());
        assert_eq!(
            crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await,
            before
        );
        assert_eq!(bytes(&root(&fixture.home, &fixture.source)), baseline);
        assert_eq!(
            store
                .machine_durability(fixture.source.machine_id())
                .await
                .unwrap(),
            source_durability
        );
        let info = fixture
            .source
            .snapshot_stopped(SnapshotOptions {
                external_resources: ExternalResourcePolicy::RequireMappings,
                ..Default::default()
            })
            .await
            .expect("explicit omitted-as-requirement policy");
        let child = fixture
            .runtime
            .restore_snapshot(
                SnapshotRef::Id(info.id),
                RestoreOptions {
                    name: Some("unresolved".into()),
                    external_resources: ExternalResourcePolicy::RequireMappings,
                    activation_hook: None,
                    resources: Default::default(),
                },
            )
            .await
            .expect("stopped child with explicit requirements");
        assert_eq!(
            store.machine_durability(child.machine_id()).await.unwrap(),
            Some(crate::MachineDurability::Durable)
        );
        // Required mapping refusal must precede monitor execution. These bytes
        // are deliberately nonbootable, so no native invocation can pass this.
        let before_start =
            crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await;
        assert!(child.start().await.is_err());
        assert_eq!(
            store.machine_durability(child.machine_id()).await.unwrap(),
            Some(crate::MachineDurability::Durable)
        );
        assert_eq!(
            crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await,
            before_start
        );
        assert!(fixture
            .runtime
            .get_machine(&MachineRef::parse("refused-fork").expect("name"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stopped_restore_rejects_live_resource_policy_without_allocating_a_child() {
        let fixture = Fixture::new(false, false).await;
        let info = fixture
            .source
            .snapshot_stopped(SnapshotOptions::default())
            .await
            .unwrap();
        let before = crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await;
        for resources in [
            crate::RestoreResourcePolicy {
                memory: crate::RestoreMemoryPolicy::AllowOvercommit,
                ..Default::default()
            },
            crate::RestoreResourcePolicy {
                private_write_allowance: crate::PrivateWriteAllowance::try_from(33).unwrap(),
                ..Default::default()
            },
        ] {
            let error = fixture
                .runtime
                .restore_snapshot(
                    SnapshotRef::Id(info.id),
                    RestoreOptions {
                        name: Some("live-policy".into()),
                        resources,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("require a live execution checkpoint"),
                "{error}"
            );
            assert_eq!(
                crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await,
                before
            );
        }
    }

    #[tokio::test]
    async fn stopped_symlink_private_source_fails_without_following_or_overwriting() {
        let fixture = Fixture::new(false, false).await;
        let source = root(&fixture.home, &fixture.source);
        let held = source.with_file_name("original.raw");
        std::fs::rename(&source, &held).expect("retain original source inode");
        symlink(&held, &source).expect("malformed private leaf");
        let before = bytes(&held);
        assert!(fixture
            .source
            .fork_stopped(ForkOptions {
                name: Some("no-symlink-child".into()),
                ..Default::default()
            })
            .await
            .is_err());
        assert_eq!(bytes(&held), before);
        assert!(std::fs::symlink_metadata(&source)
            .expect("source leaf")
            .file_type()
            .is_symlink());
        assert!(fixture
            .runtime
            .get_machine(&MachineRef::parse("no-symlink-child").expect("name"))
            .await
            .is_err());
    }
}

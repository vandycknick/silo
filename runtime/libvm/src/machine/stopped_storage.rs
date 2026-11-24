//! Real files and SQLite, initialized through the existing unit-test store seam.
//! No capability query or hypervisor access. Native replay qualification lives in smoke.

#[path = "../../tests/support/live_catalog.rs"]
mod live_catalog;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use crate::{
        ExternalResourcePolicy, ForkOptions, ImageSource, LibVmError, Machine, MachineRef,
        MachineRetention, ProcessConfig, ResolvedRuntimeComponents, RestoreOptions, RestoreSource,
        Runtime, RuntimeConfig, SnapshotMemory, SnapshotOptions, SnapshotRef,
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
            Self::with_retention(empty_command, external, MachineRetention::Persistent).await
        }

        async fn with_retention(
            empty_command: bool,
            external: bool,
            retention: MachineRetention,
        ) -> Self {
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
                .retention(retention)
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

    fn source_ref(fixture: &Fixture) -> MachineRef {
        MachineRef::parse(fixture.source.id()).expect("source machine id")
    }

    #[tokio::test]
    async fn stopped_snapshot_two_private_children_full_config_and_retention() {
        for empty_command in [false, true] {
            let fixture =
                Fixture::with_retention(empty_command, false, MachineRetention::Ephemeral).await;
            let baseline = bytes(&root(&fixture.home, &fixture.source));
            let mut expected_child_config = semantics(config(&fixture.home, &fixture.source).await);
            assert_eq!(
                expected_child_config["retention"],
                serde_json::to_value(MachineRetention::Ephemeral).unwrap()
            );
            expected_child_config["retention"] =
                serde_json::to_value(MachineRetention::Persistent).unwrap();
            let created = fixture
                .runtime
                .snapshot(
                    &source_ref(&fixture),
                    SnapshotOptions {
                        name: Some("saved".into()),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .expect("real stopped snapshot");
            assert_eq!((created.capture, created.naming_outcome), (None, None));
            let info = created.snapshot;
            let snapshots = fixture.runtime.snapshots();
            let reference = SnapshotRef::Id(info.id);
            assert_eq!(info.names, vec!["saved"]);
            assert_eq!(info.memory, SnapshotMemory::None);
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
            assert_eq!(artifact["schema"], 1);
            assert_eq!(artifact["memory"], "none");
            assert_eq!(
                serde_json::from_value::<MachineRetention>(
                    artifact["configuration"]["retention"].clone()
                )
                .unwrap(),
                MachineRetention::Ephemeral,
                "snapshots retain the source policy, not the child policy"
            );
            assert!(artifact.get("purpose").is_none());
            assert!(artifact.get("captureKind").is_none());
            assert_eq!(
                artifact["stopOutcome"], "unknown",
                "a fresh fsync must not invent historical clean evidence"
            );
            assert_eq!(artifact["externalRequirements"], serde_json::json!([]));
            let first = fixture
                .runtime
                .restore(
                    RestoreSource::Local(reference.clone()),
                    RestoreOptions {
                        name: Some("first".into()),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .expect("first private restore");
            // A local name wins over the registry: the default policy would
            // otherwise expand `saved` to docker.io and pull.
            let second = fixture
                .runtime
                .restore(
                    RestoreSource::Registry("saved".into()),
                    RestoreOptions {
                        name: Some("second".into()),
                        ..Default::default()
                    },
                    None,
                )
                .await
                .expect("second private restore by name");
            let first_root = root(&fixture.home, &first);
            let second_root = root(&fixture.home, &second);
            assert_eq!(bytes(&first_root), baseline);
            assert_eq!(bytes(&second_root), baseline);
            assert_eq!(
                expected_child_config,
                semantics(config(&fixture.home, &first).await)
            );
            assert_eq!(
                expected_child_config,
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
                assert_eq!(
                    fixture
                        .runtime
                        .machine_config(child.machine_id())
                        .await
                        .unwrap()
                        .unwrap()
                        .retention,
                    MachineRetention::Persistent
                );
            }
            let mut mutate = OpenOptions::new()
                .write(true)
                .open(&first_root)
                .expect("first independent writer");
            mutate.write_all(b"first-child-only").expect("write child");
            mutate.sync_all().expect("sync child");
            assert_eq!(bytes(&second_root), baseline);
            assert_eq!(bytes(&root(&fixture.home, &fixture.source)), baseline);
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
            // A snapshot without memory is unchanged by `without_memory`.
            let third = fixture
                .runtime
                .restore(
                    RestoreSource::Local(reference.clone()),
                    RestoreOptions {
                        name: Some("after-source-delete".into()),
                        without_memory: true,
                        ..Default::default()
                    },
                    None,
                )
                .await
                .expect("retained boot/storage restore");
            assert_eq!(bytes(&root(&fixture.home, &third)), baseline);
            assert_stopped(&fixture.home, &third).await;
            assert_eq!(
                fixture
                    .runtime
                    .machine_config(third.machine_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .retention,
                MachineRetention::Persistent
            );
            let removal = snapshots
                .remove(&SnapshotRef::Name("saved".into()))
                .await
                .expect("remove the last name");
            assert_eq!(removal.id, info.id);
            assert_eq!(removal.names, vec!["saved"]);
            assert!(removal.record_removed, "the last name takes the record");
            assert!(matches!(
                snapshots.inspect(&reference).await,
                Err(LibVmError::SnapshotNotFound { .. })
            ));
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
    async fn stopped_fork_of_ephemeral_source_and_its_child_are_persistent() {
        let fixture = Fixture::with_retention(false, false, MachineRetention::Ephemeral).await;
        let baseline = bytes(&root(&fixture.home, &fixture.source));
        let child = fixture
            .source
            .fork_stopped(ForkOptions {
                name: Some("child".into()),
                ..Default::default()
            })
            .await
            .expect("fork an ephemeral stopped source");
        let grandchild = child
            .fork_stopped(ForkOptions {
                name: Some("grandchild".into()),
                ..Default::default()
            })
            .await
            .expect("fork a stopped fork child");
        for machine in [&child, &grandchild] {
            assert_stopped(&fixture.home, machine).await;
            assert_eq!(bytes(&root(&fixture.home, machine)), baseline);
            assert_eq!(
                fixture
                    .runtime
                    .machine_config(machine.machine_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .retention,
                MachineRetention::Persistent
            );
        }
        assert_eq!(
            fixture
                .runtime
                .machine_config(fixture.source.machine_id())
                .await
                .unwrap()
                .unwrap()
                .retention,
            MachineRetention::Ephemeral,
            "forking does not change the source retention"
        );
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
            .runtime
            .snapshot(
                &source_ref(&fixture),
                SnapshotOptions {
                    name: Some("refused-snapshot".into()),
                    ..Default::default()
                },
                None,
            )
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
            .runtime
            .snapshot(
                &source_ref(&fixture),
                SnapshotOptions {
                    external_requirements: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("explicit omitted-as-requirement policy")
            .snapshot;
        let child = fixture
            .runtime
            .restore(
                RestoreSource::Local(SnapshotRef::Id(info.id)),
                RestoreOptions {
                    name: Some("unresolved".into()),
                    external_resources: ExternalResourcePolicy::RequireMappings,
                    ..Default::default()
                },
                None,
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

    #[tokio::test]
    async fn snapshot_refuses_the_wrong_memory_mode_without_effects() {
        let fixture = Fixture::new(false, false).await;
        let source = source_ref(&fixture);
        let before = crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await;
        for options in [
            SnapshotOptions {
                preserve: true,
                ..Default::default()
            },
            SnapshotOptions {
                capture_policy: Some(vm_spec::lifecycle::CapturePolicy::Full),
                ..Default::default()
            },
            SnapshotOptions {
                dirty_crossover_percent: Some(10),
                ..Default::default()
            },
            SnapshotOptions {
                memory: true,
                external_requirements: true,
                ..Default::default()
            },
        ] {
            let result = fixture.runtime.snapshot(&source, options, None).await;
            assert!(
                matches!(result, Err(LibVmError::InvalidRequest { .. })),
                "{result:?}"
            );
        }
        // A held launch lifetime is exactly what a running machine looks like.
        let lifetime = fixture
            .runtime
            .machine_paths(fixture.source.machine_id())
            .vmm_lock_path();
        std::fs::create_dir_all(lifetime.parent().unwrap()).unwrap();
        let held = crate::lock_manager::MachineLifetimeLock::try_acquire(&lifetime)
            .unwrap()
            .unwrap();
        let result = fixture
            .runtime
            .snapshot(&source, SnapshotOptions::default(), None)
            .await;
        assert!(
            matches!(
                result,
                Err(LibVmError::SnapshotRequiresStoppedMachine { ref reference })
                    if reference == "source"
            ),
            "{result:?}"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("stop it first, or include its memory"));
        drop(held);
        assert_eq!(
            crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await,
            before
        );
    }

    #[tokio::test]
    async fn restore_refuses_an_activation_hook_without_memory() {
        let fixture = Fixture::new(false, false).await;
        let info = fixture
            .runtime
            .snapshot(&source_ref(&fixture), SnapshotOptions::default(), None)
            .await
            .expect("real stopped snapshot")
            .snapshot;
        let before = crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await;
        let hook = vm_spec::restore::RestoreHook {
            argv: vec!["/bin/true".into()],
            environment: Vec::new(),
            working_directory: "/".into(),
            timeout_ms: 1000,
        };
        for without_memory in [true, false] {
            let result = fixture
                .runtime
                .restore(
                    RestoreSource::Local(SnapshotRef::Id(info.id)),
                    RestoreOptions {
                        name: Some("hooked".into()),
                        without_memory,
                        activation_hook: Some(hook.clone()),
                        ..Default::default()
                    },
                    None,
                )
                .await;
            assert!(
                matches!(result, Err(LibVmError::InvalidRequest { .. })),
                "without_memory={without_memory}: {result:?}"
            );
        }
        assert_eq!(
            crate::machine::stopped_storage::live_catalog::snapshot(&fixture.home).await,
            before
        );
        assert!(fixture
            .runtime
            .get_machine(&MachineRef::parse("hooked").expect("name"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn snapshot_publication_is_refused_publicly_and_settles_internally() {
        let fixture = Fixture::new(false, false).await;
        let info = fixture
            .runtime
            .snapshot(
                &source_ref(&fixture),
                SnapshotOptions {
                    name: Some("saved".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("real stopped snapshot")
            .snapshot;
        // The public image push refuses a snapshot by type, by name or id.
        for image in [
            crate::ImageRef::Name("saved".into()),
            crate::ImageRef::Id(crate::ImageId::from_sha256(*info.id.as_bytes())),
        ] {
            let result = fixture
                .runtime
                .images()
                .publish_artifact(crate::ArtifactPublishRequest {
                    image,
                    destination: "registry.example/team/vm:v1".into(),
                    encoding: crate::ArtifactEncoding::Zstd,
                })
                .await;
            assert!(
                matches!(result, Err(LibVmError::SnapshotIsNotAnImage { .. })),
                "{result:?}"
            );
        }
        // The crate-private exporter runs, then the registry policy refuses
        // before any upload; the export operation is retired with it.
        let store = fixture.runtime.native_store().unwrap();
        let denied = Runtime::from_store(
            fixture.runtime.local_paths().clone(),
            std::sync::Arc::new(store.clone()),
            crate::RuntimeNetworkingConfig::default(),
            crate::RegistryPolicy::new(crate::RegistryAction::Deny, Vec::new(), Vec::new())
                .unwrap(),
            fixture.components.clone(),
            None,
        )
        .await
        .expect("runtime with a deny-all registry policy");
        let result = denied
            .images()
            .publish_snapshot_artifact(
                SnapshotRef::Name("saved".into()),
                "registry.example/team/vm:v1".into(),
                crate::ArtifactEncoding::Zstd,
            )
            .await;
        assert!(
            matches!(
                &result,
                Err(LibVmError::ImageReferenceRejected { message, .. })
                    if message.contains("denied by the registry policy")
            ),
            "{result:?}"
        );
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM storage_operation WHERE state<>'committed'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(pending, 0, "the failed export settled its operation");
    }
}

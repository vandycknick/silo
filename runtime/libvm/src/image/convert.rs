//! Explicit OCI-to-raw conversion (ADR 0014, "Explicit OCI-to-raw conversion").
//!
//! ```text
//! key = canonical(selected manifest, Linux platform, flattener ABI)
//!
//! lock(key) ─┬─ retained mapping ─► consume, authenticate complete closure
//!            │                      ─► original ImageId and pinned bundle
//!            │                      (missing/corrupt content refuses; it is
//!            │                       never replaced by a fresh flattening)
//!            └─ no mapping ───────► existing OCI rootfs cache / flattener
//!                                   ─► stream map ─► packaged pinned bundle
//!                                   ─► image + alias + mapping in one commit
//! ```
//!
//! Nothing here runs implicitly at machine creation or start. A backend that
//! cannot boot an OCI source names this operation as the remedy instead.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::image::import_types::{
    BootAssetSelection, ImageContainerKind, ImageProvenance, ManagedImageInfo, ManagedSourceInfo,
    ManagedSourceRef, RawConversionKey, RawConversionOptions,
};
use crate::image::oci::{acquire_rootfs, image_error, CONVERSION_ABI};
use crate::image::{ImageProgressSender, Images, OciImageConfigMetadata, ResolvedOciImage};
use crate::machine::stopped::OperationStaging;
use crate::runtime::boot_assets::{direct_boot_profile, pin_image_boot, CapturedBootContext};
use crate::storage::identity::ObjectDigest;
use crate::storage::pool::StoragePool;
use crate::store::managed_image_store::ManagedImageStore;
use crate::store::models::image::{ImageRecord, ImageRecordKind};
use crate::store::models::snapshot::{SnapshotRoot, SnapshotRootProfile};
use crate::store::models::storage::{GuestArchitecture, LinuxPlatform, RawLayout, RootSelector};
use crate::store::{ImageStore, Store};
use crate::{LibVmError, ProcessConfig};

impl Images {
    /// Explicitly converts an already selected OCI identity into a reusable,
    /// retained raw image. Repeating the conversion returns the original image
    /// and boot bundle; creation and start never convert implicitly.
    pub async fn convert(
        &self,
        resolved: &ResolvedOciImage,
        options: RawConversionOptions,
    ) -> Result<ManagedImageInfo, LibVmError> {
        let runtime = &self.runtime;
        let producer = runtime
            .image_store()
            .map_err(|error| image_error(&resolved.requested_reference, error))?;
        convert(
            ConversionContext {
                store: Arc::new(runtime.native_store()?),
                images_dir: runtime.local_images_dir().to_path_buf(),
                producer,
                progress: runtime.image_progress().cloned(),
                boot: runtime.packaged_boot(),
            },
            resolved.clone(),
            options,
        )
        .await
    }
}

/// Packaged boot inputs a fresh conversion pins. A cache hit never reads them:
/// it returns the bundle pinned when the image was first converted.
pub(crate) struct PackagedBoot {
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
    pub(crate) agent: PathBuf,
    pub(crate) native_executable: PathBuf,
    pub(crate) backend: vm_spec::live::LiveBackend,
}

/// Everything conversion needs from a runtime, owned so the conversion task
/// outlives its caller and stays testable against a real catalog.
pub(crate) struct ConversionContext {
    pub(crate) store: Arc<Store>,
    pub(crate) images_dir: PathBuf,
    pub(crate) producer: ::oci::OciMaterializer,
    pub(crate) progress: Option<ImageProgressSender>,
    pub(crate) boot: PackagedBoot,
}

impl ConversionContext {
    fn boot_context<'a>(
        &'a self,
        pool: &'a StoragePool,
        operation_id: uuid::Uuid,
    ) -> CapturedBootContext<'a> {
        CapturedBootContext {
            pool,
            store: &self.store,
            operation_id,
            default_kernel: &self.boot.kernel,
            default_initramfs: &self.boot.initramfs,
            default_agent: &self.boot.agent,
            native_executable: &self.boot.native_executable,
            backend: self.boot.backend,
        }
    }
}

/// Convert one selected OCI identity into a reusable, retained raw image.
///
/// The whole operation runs in its own task: the key lock, operation lease,
/// staging and every blocking verifier/flattener/publisher stay owned until the
/// work actually ends. Cancelling the caller only detaches it, so a dropped
/// future can never close the lease beneath an in-flight worker or let a second
/// conversion of the same key in before the mapping is settled.
pub(crate) async fn convert(
    context: ConversionContext,
    resolved: ResolvedOciImage,
    options: RawConversionOptions,
) -> Result<ManagedImageInfo, LibVmError> {
    tokio::spawn(async move { convert_owned(&context, &resolved, options).await }).await?
}

/// Runs only inside the task spawned by [`convert`], which owns every input.
async fn convert_owned(
    context: &ConversionContext,
    resolved: &ResolvedOciImage,
    options: RawConversionOptions,
) -> Result<ManagedImageInfo, LibVmError> {
    if let Some(alias) = &options.alias {
        crate::store::snapshot_store::validate_alias(alias)?;
    }
    // Admission precedes any lock wait, registry traffic or flattening: the
    // platform needs a native direct boot here and the defaults must be valid.
    let platform = linux_platform(&resolved.platform)?;
    let boot = direct_boot_profile(&platform, RootSelector::WholeDisk)?;
    let key = conversion_key(resolved, platform)?;
    let process = process_defaults(&resolved.requested_reference, &resolved.config)?;
    let provenance = source_provenance(resolved)?;

    let key_digest = key.digest()?;
    let pool = StoragePool::open(&context.images_dir)?;
    let (pool, key_lock) = tokio::task::spawn_blocking(move || {
        let lock = pool.lock_publication(&key_digest)?;
        Ok::<_, crate::storage::StorageError>((pool, lock))
    })
    .await??;

    let images = ManagedImageStore::from_store(context.store.clone());
    // Rechecked under the key lock: a concurrent identical conversion has
    // either committed its mapping or not started publishing.
    if let Some(consumer) = images.lookup_conversion(&key).await? {
        let Some(alias) = options.alias else {
            let ManagedSourceInfo::Image(info) = images
                .inspect(&ManagedSourceRef::Image(consumer.info.id))
                .await?
            else {
                return Err(invalid("conversion result resolved to a snapshot"));
            };
            return Ok(*info);
        };
        // The consumer's lease keeps the authenticated closure rooted until
        // the alias names it; the flattener is not rerun for a new name.
        let ManagedSourceInfo::Image(info) = images
            .add_alias(&ManagedSourceRef::Image(consumer.info.id), &alias)
            .await?
        else {
            return Err(invalid("conversion alias resolved to a snapshot"));
        };
        if info.id != consumer.info.id {
            return Err(invalid("conversion alias names a different image"));
        }
        return Ok(*info);
    }

    let operation_id = uuid::Uuid::new_v4();
    let lease = context.store.begin_storage_operation(operation_id).await?;
    let staging = OperationStaging::new(&pool, operation_id, &lease)?;
    let rootfs = acquire_rootfs(
        &*context.store,
        &context.images_dir,
        &context.producer,
        context.progress.as_ref(),
        resolved,
        operation_id,
    )
    .await?;
    let stream =
        crate::store::snapshot_store::publish_map(&pool, &context.store, operation_id, &rootfs.map)
            .await?;
    if stream.stream != rootfs.record.artifact.stream_id
        || stream.length != rootfs.record.artifact.size_bytes
    {
        return Err(invalid(
            "converted stream map contradicts the flattened rootfs",
        ));
    }
    let boot = pin_image_boot(
        &boot,
        &BootAssetSelection::Packaged,
        context.boot_context(&pool, operation_id),
    )
    .await?;
    let record = ImageRecord {
        schema: 1,
        kind: ImageRecordKind::Image,
        root: SnapshotRoot {
            profile: SnapshotRootProfile::OpaqueRaw,
            geometry: vm_spec::DiskGeometry {
                length: stream.length,
                logical_sector_size: 512,
            },
            stream,
            layout: RawLayout::WholeDisk,
        },
        boot,
        process,
    };
    let info = images
        .publish_owned(
            record,
            operation_id,
            lease,
            options.alias,
            vec![provenance],
            Some(key),
        )
        .await?;
    // The publisher stages its records under this operation's directory and
    // the mapping is settled only now; release staging, then the key.
    drop(staging);
    drop(key_lock);
    Ok(info)
}

fn invalid(message: impl Into<String>) -> LibVmError {
    LibVmError::InvalidStorageRecord {
        record: "image-conversion",
        message: message.into(),
    }
}

/// OCI spells architectures with GOARCH names; nothing else is admitted.
fn linux_platform(platform: &::oci::Platform) -> Result<LinuxPlatform, LibVmError> {
    if platform.os != "linux" {
        return Err(invalid(format!(
            "conversion requires Linux userspace, not {}",
            platform.os
        )));
    }
    let architecture = match platform.architecture.as_str() {
        "amd64" => GuestArchitecture::Amd64,
        "arm64" => GuestArchitecture::Arm64,
        other => {
            return Err(invalid(format!(
                "unsupported conversion architecture {other:?}"
            )))
        }
    };
    let platform = LinuxPlatform {
        architecture,
        variant: platform.variant.clone(),
    };
    platform.validate()?;
    Ok(platform)
}

/// Exactly the selected manifest, platform and flattener ABI. The manifest
/// already binds its config, so the config digest is provenance, not a key.
fn conversion_key(
    resolved: &ResolvedOciImage,
    platform: LinuxPlatform,
) -> Result<RawConversionKey, LibVmError> {
    Ok(RawConversionKey {
        source_manifest: oci_digest(&resolved.manifest_digest, "manifest")?,
        platform,
        flattener_abi: CONVERSION_ABI.to_owned(),
    })
}

fn oci_digest(value: &str, field: &str) -> Result<ObjectDigest, LibVmError> {
    value.parse().map_err(|_| {
        invalid(format!(
            "OCI {field} digest {value:?} is not a SHA-256 identity"
        ))
    })
}

fn source_provenance(resolved: &ResolvedOciImage) -> Result<ImageProvenance, LibVmError> {
    let manifest = oci_digest(&resolved.manifest_digest, "manifest")?;
    Ok(ImageProvenance {
        container: ImageContainerKind::Oci,
        source_digest: manifest,
        source_spelling: resolved.requested_reference.clone(),
        source_manifest: Some(manifest),
        source_config: Some(oci_digest(&resolved.config_digest, "config")?),
        disk: None,
    })
}

/// OCI execution defaults become the image's semantic process defaults. Absent
/// and empty command vectors stay distinct; an empty working directory or user
/// means the OCI default. Later duplicate `Env` entries win, as in OCI runtimes.
/// No launch-time defaults (such as `PATH`) are invented here.
fn process_defaults(
    reference: &str,
    config: &OciImageConfigMetadata,
) -> Result<ProcessConfig, LibVmError> {
    let refuse = |message: String| {
        crate::image::oci::image_error(
            reference,
            ::oci::OciError::ImageConfig {
                reference: reference.to_owned(),
                message,
            },
        )
    };
    for value in [config.entrypoint.as_deref(), config.cmd.as_deref()]
        .into_iter()
        .flatten()
        .flatten()
        .chain(config.working_dir.iter())
        .chain(config.user.iter())
    {
        if value.contains('\0') {
            return Err(refuse("execution defaults cannot contain NUL".into()));
        }
    }
    let mut environment = BTreeMap::new();
    for entry in config.env.iter().flatten() {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(refuse(format!(
                "environment entry {entry:?} is not KEY=VALUE"
            )));
        };
        let mut bytes = key.bytes();
        let valid_key = bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !valid_key || value.contains('\0') {
            return Err(refuse(format!("invalid environment entry {entry:?}")));
        }
        environment.insert(key.to_owned(), value.to_owned());
    }
    let working_directory = config
        .working_dir
        .clone()
        .filter(|directory| !directory.is_empty())
        .unwrap_or_else(|| "/".to_owned());
    if !working_directory.starts_with('/') {
        return Err(refuse(format!(
            "working directory {working_directory:?} is not absolute"
        )));
    }
    Ok(ProcessConfig {
        entrypoint: config.entrypoint.clone(),
        command: config.cmd.clone(),
        environment,
        working_directory,
        user: config.user.clone().filter(|user| !user.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::image::convert::{conversion_key, linux_platform, process_defaults};
    use crate::image::OciImageConfigMetadata;
    use crate::store::models::storage::{GuestArchitecture, LinuxPlatform};

    const MANIFEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const CONFIG: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn resolved(manifest: &str, config: &str, platform: oci::Platform) -> crate::ResolvedOciImage {
        crate::ResolvedOciImage {
            requested_reference: "example.test/app:1".into(),
            selected_reference: format!("example.test/app@{manifest}"),
            manifest_digest: manifest.into(),
            config_digest: config.into(),
            config: OciImageConfigMetadata::default(),
            platform,
            cache_state: crate::ImageCacheState::Complete,
            materialization: crate::image::ResolvedOciImageMaterialization::Cached,
        }
    }

    fn platform(architecture: &str, variant: Option<&str>) -> oci::Platform {
        oci::Platform {
            os: "linux".into(),
            architecture: architecture.into(),
            variant: variant.map(Into::into),
        }
    }

    #[test]
    fn key_binds_exactly_manifest_platform_and_flattener_abi() {
        let amd64 = platform("amd64", None);
        let base = resolved(MANIFEST, CONFIG, amd64.clone());
        let key = |image: &crate::ResolvedOciImage| {
            conversion_key(image, linux_platform(&image.platform).unwrap())
                .unwrap()
                .digest()
                .unwrap()
        };
        let original = key(&base);
        assert_eq!(
            original,
            key(&resolved(MANIFEST, CONFIG, amd64.clone())),
            "the key is deterministic"
        );
        let other_config =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let mut respelled = resolved(MANIFEST, other_config, amd64.clone());
        respelled.requested_reference = "other.test/alias:latest".into();
        respelled.selected_reference = "other.test/alias@sha256:abc".into();
        respelled.config.cmd = Some(vec!["different".into()]);
        assert_eq!(
            original,
            key(&respelled),
            "config, spelling and defaults are provenance, not key dimensions"
        );
        let other_manifest =
            "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        assert_ne!(original, key(&resolved(other_manifest, CONFIG, amd64)));
        let arm = key(&resolved(MANIFEST, CONFIG, platform("arm64", None)));
        let arm_v8 = key(&resolved(MANIFEST, CONFIG, platform("arm64", Some("v8"))));
        assert_ne!(original, arm);
        assert_ne!(arm, arm_v8, "a present variant cannot alias its absence");

        let exact = conversion_key(&base, linux_platform(&base.platform).unwrap()).unwrap();
        assert_eq!(exact.flattener_abi, crate::image::oci::CONVERSION_ABI);
        let mut other_abi = exact.clone();
        other_abi.flattener_abi.push_str(":next");
        assert_ne!(exact.digest().unwrap(), other_abi.digest().unwrap());
    }

    #[test]
    fn only_linux_goarch_platforms_with_admitted_variants_convert() {
        assert_eq!(
            linux_platform(&platform("arm64", Some("v8"))).unwrap(),
            LinuxPlatform {
                architecture: GuestArchitecture::Arm64,
                variant: Some("v8".into()),
            }
        );
        for rejected in [
            oci::Platform {
                os: "windows".into(),
                architecture: "amd64".into(),
                variant: None,
            },
            platform("x86_64", None),
            platform("riscv64", None),
            platform("amd64", Some("v3")),
            platform("arm64", Some("v7")),
        ] {
            assert!(linux_platform(&rejected).is_err(), "{rejected:?}");
        }
        let invalid_manifest = resolved("sha256:short", CONFIG, platform("amd64", None));
        assert!(conversion_key(
            &invalid_manifest,
            linux_platform(&invalid_manifest.platform).unwrap()
        )
        .is_err());
    }

    #[test]
    fn oci_execution_defaults_become_image_process_defaults() {
        let unset = process_defaults("ref", &OciImageConfigMetadata::default()).unwrap();
        assert_eq!(unset, crate::ProcessConfig::default());

        let config = OciImageConfigMetadata {
            entrypoint: Some(Vec::new()),
            cmd: Some(vec!["--serve".into(), "".into()]),
            env: Some(vec![
                "A=1".into(),
                "EMPTY=".into(),
                "EQUALS=x=y".into(),
                "A=2".into(),
            ]),
            working_dir: Some("/srv".into()),
            user: Some("app:app".into()),
            labels: Some(BTreeMap::from([("label".into(), "ignored".into())])),
            stop_signal: Some("SIGQUIT".into()),
        };
        let process = process_defaults("ref", &config).unwrap();
        assert_eq!(process.entrypoint, Some(Vec::new()));
        assert_eq!(process.command, Some(vec!["--serve".into(), "".into()]));
        assert_eq!(
            process.environment,
            BTreeMap::from([
                ("A".into(), "2".into()),
                ("EMPTY".into(), "".into()),
                ("EQUALS".into(), "x=y".into()),
            ])
        );
        assert_eq!(process.working_directory, "/srv");
        assert_eq!(process.user.as_deref(), Some("app:app"));

        let empty = OciImageConfigMetadata {
            working_dir: Some(String::new()),
            user: Some(String::new()),
            ..OciImageConfigMetadata::default()
        };
        let process = process_defaults("ref", &empty).unwrap();
        assert_eq!(process.working_directory, "/");
        assert_eq!(process.user, None);
    }

    #[test]
    fn malformed_oci_execution_defaults_are_refused() {
        let cases = [
            OciImageConfigMetadata {
                env: Some(vec!["NO_SEPARATOR".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                env: Some(vec!["=value".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                env: Some(vec!["1BAD=value".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                env: Some(vec!["KEY=nul\0".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                entrypoint: Some(vec!["/bin/\0sh".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                cmd: Some(vec!["\0".into()]),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                working_dir: Some("relative".into()),
                ..OciImageConfigMetadata::default()
            },
            OciImageConfigMetadata {
                user: Some("app\0".into()),
                ..OciImageConfigMetadata::default()
            },
        ];
        for config in cases {
            assert!(
                matches!(
                    process_defaults("ref", &config),
                    Err(crate::LibVmError::Image {
                        source: oci::OciError::ImageConfig { .. },
                        ..
                    })
                ),
                "{config:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    mod catalog {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        use tempfile::TempDir;
        use test_utils::direct_kernel::host_kernel;

        use crate::image::convert::{convert, ConversionContext, PackagedBoot};
        use crate::image::import_types::{
            ImageContainerKind, ImageProvenance, ManagedImageInfo, RawConversionOptions,
        };
        use crate::image::OciImageConfigMetadata;
        use crate::storage::pool::StoragePool;
        use crate::store::models::snapshot::SnapshotRootProfile;
        use crate::store::models::storage::{
            BootBinding, BootProfile, RawLayout, RootFilesystem, RootSelector,
        };
        use crate::store::{ImageStore, Store};

        const REFERENCE: &str = "example.test/app:1";
        const MANIFEST: &str =
            "sha256:5555555555555555555555555555555555555555555555555555555555555555";
        const CONFIG: &str =
            "sha256:6666666666666666666666666666666666666666666666666666666666666666";

        struct Fixture {
            _temp: TempDir,
            paths: crate::paths::LocalPaths,
            store: Store,
            producer: oci::OciMaterializer,
            kernel: PathBuf,
            initramfs: PathBuf,
            agent: PathBuf,
            resolved: crate::ResolvedOciImage,
            stream: crate::storage::identity::StreamId,
            rootfs_length: u64,
        }

        impl Fixture {
            /// A complete OCI rootfs cache row over real pool bytes, so the
            /// conversion path runs end to end without any registry traffic.
            async fn new() -> Self {
                let temp = TempDir::new().unwrap();
                let paths = crate::paths::LocalPaths::new(temp.path());
                let store = Store::new(&paths).await.unwrap();
                let pool = StoragePool::open(paths.images_dir()).unwrap();
                let private = temp.path().join("packaged");
                std::fs::create_dir(&private).unwrap();
                let kernel = private.join("kernel");
                let initramfs = private.join("base-initramfs");
                let agent = private.join("agent");
                std::fs::write(&kernel, host_kernel("packaged kernel v1")).unwrap();
                std::fs::write(&initramfs, b"packaged base initramfs v1").unwrap();
                std::fs::write(&agent, b"packaged agent v1").unwrap();
                for path in [&kernel, &initramfs, &agent] {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
                let rootfs = temp.path().join("flattened.raw");
                let mut bytes = vec![0_u8; 8192];
                bytes[1024..1032].copy_from_slice(b"ext4ish!");
                bytes[8000] = 0x7f;
                std::fs::write(&rootfs, &bytes).unwrap();
                let published = pool.publish_stream(&rootfs).unwrap();
                let metadata = oci::RootfsMetadata {
                    requested_reference: REFERENCE.into(),
                    selected_reference: format!("example.test/app@{MANIFEST}"),
                    manifest_digest: MANIFEST.into(),
                    config_digest: CONFIG.into(),
                    config: OciImageConfigMetadata {
                        entrypoint: Some(vec!["/bin/app".into()]),
                        cmd: Some(vec!["--serve".into()]),
                        env: Some(vec!["PATH=/usr/bin".into(), "MODE=prod".into()]),
                        working_dir: Some("/srv".into()),
                        user: Some("app".into()),
                        ..OciImageConfigMetadata::default()
                    },
                    layers: vec![oci::RootfsLayerMetadata {
                        blob_digest: format!("sha256:{}", "7".repeat(64)),
                        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
                        size_bytes: 10,
                        diff_id: format!("sha256:{}", "8".repeat(64)),
                    }],
                    platform: oci::Platform::host().unwrap(),
                    created_at_unix: 1,
                };
                let record =
                    crate::image::oci::oci_image_record(&published, &metadata, REFERENCE).unwrap();
                store.save_oci_image(&record).await.unwrap();
                let resolved =
                    crate::image::oci::cached_resolved_oci_image(&record, REFERENCE.into());
                let producer =
                    oci::OciMaterializer::open(paths.images_dir(), oci::RegistryPolicy::default())
                        .unwrap();
                Self {
                    _temp: temp,
                    paths,
                    store,
                    producer,
                    kernel,
                    initramfs,
                    agent,
                    resolved,
                    stream: published.id,
                    rootfs_length: published.length,
                }
            }

            fn context(&self) -> ConversionContext {
                ConversionContext {
                    store: Arc::new(self.store.clone()),
                    images_dir: self.paths.images_dir().to_path_buf(),
                    producer: self.producer.clone(),
                    progress: None,
                    boot: PackagedBoot {
                        kernel: self.kernel.clone(),
                        initramfs: self.initramfs.clone(),
                        agent: self.agent.clone(),
                        native_executable: self.kernel.clone(),
                        backend: vm_spec::live::LiveBackend::Krun,
                    },
                }
            }

            async fn convert(
                &self,
                alias: Option<&str>,
            ) -> Result<ManagedImageInfo, crate::LibVmError> {
                convert(
                    self.context(),
                    self.resolved.clone(),
                    RawConversionOptions {
                        alias: alias.map(Into::into),
                    },
                )
                .await
            }

            async fn count(&self, table: &str) -> i64 {
                let query = match table {
                    "storage_image" => "SELECT COUNT(*) FROM storage_image",
                    "raw_conversion_result" => "SELECT COUNT(*) FROM raw_conversion_result",
                    "storage_operation" => "SELECT COUNT(*) FROM storage_operation",
                    _ => panic!("unsupported fixture table: {table}"),
                };
                sqlx::query_scalar(query)
                    .fetch_one(self.store.test_pool())
                    .await
                    .unwrap()
            }

            async fn mapped_image(&self) -> String {
                sqlx::query_scalar("SELECT image_id FROM raw_conversion_result")
                    .fetch_one(self.store.test_pool())
                    .await
                    .unwrap()
            }
        }

        fn packaged_binding(info: &ManagedImageInfo) -> BootBinding {
            info.record.boot_binding().unwrap().clone()
        }

        fn overwrite(path: &Path, bytes: &[u8]) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(path, bytes).unwrap();
        }

        #[tokio::test]
        async fn miss_publishes_immutable_stream_defaults_provenance_and_pinned_boot() {
            let fixture = Fixture::new().await;
            let info = fixture.convert(Some("app-raw")).await.unwrap();

            assert_eq!(info.id, info.record.id().unwrap());
            assert!(info.retained);
            assert_eq!(info.aliases, vec!["app-raw".to_string()]);
            let root = &info.record.root;
            assert_eq!(root.profile, SnapshotRootProfile::OpaqueRaw);
            assert_eq!(root.layout, RawLayout::WholeDisk);
            assert_eq!(
                root.stream.stream, fixture.stream,
                "the flattened stream is reused"
            );
            assert_eq!(root.stream.length, fixture.rootfs_length);
            assert_eq!(root.geometry.length, fixture.rootfs_length);
            assert_eq!(root.geometry.logical_sector_size, 512);
            let BootProfile::LinuxDirect {
                binding,
                root_selector,
                root_filesystem,
                userspace_platform,
                ..
            } = &info.record.boot
            else {
                panic!("conversion must publish Linux direct boot");
            };
            assert!(matches!(
                binding,
                BootBinding::Pinned { agent: Some(_), .. }
            ));
            assert_eq!(*root_selector, RootSelector::WholeDisk);
            assert_eq!(*root_filesystem, RootFilesystem::Ext4);
            assert_eq!(
                *userspace_platform,
                crate::image::convert::linux_platform(&fixture.resolved.platform).unwrap()
            );
            let process = &info.record.process;
            assert_eq!(process.entrypoint, Some(vec!["/bin/app".to_string()]));
            assert_eq!(process.command, Some(vec!["--serve".to_string()]));
            assert_eq!(
                process.environment.get("MODE").map(String::as_str),
                Some("prod")
            );
            assert_eq!(process.working_directory, "/srv");
            assert_eq!(process.user.as_deref(), Some("app"));
            let manifest = MANIFEST.parse().unwrap();
            assert_eq!(
                info.provenance,
                vec![ImageProvenance {
                    container: ImageContainerKind::Oci,
                    source_digest: manifest,
                    source_spelling: REFERENCE.into(),
                    source_manifest: Some(manifest),
                    source_config: Some(CONFIG.parse().unwrap()),
                    disk: None,
                }]
            );
            assert_eq!(fixture.mapped_image().await, info.id.to_string());
            assert_eq!(fixture.count("storage_image").await, 1);
            // The pool stream itself is immutable: conversion never rewrote it.
            let pool = StoragePool::open(fixture.paths.images_dir()).unwrap();
            assert_eq!(
                pool.verify_stream(&fixture.stream).unwrap().id(),
                fixture.stream
            );
        }

        #[tokio::test]
        async fn hit_returns_original_image_and_bundle_after_packaged_update() {
            let fixture = Fixture::new().await;
            let first = fixture.convert(Some("first")).await.unwrap();

            overwrite(&fixture.kernel, &host_kernel("packaged kernel v2"));
            overwrite(&fixture.initramfs, b"packaged base initramfs v2");
            overwrite(&fixture.agent, b"packaged agent v2");
            let second = fixture.convert(Some("second")).await.unwrap();
            let third = fixture.convert(None).await.unwrap();

            for repeated in [&second, &third] {
                assert_eq!(repeated.id, first.id);
                assert_eq!(repeated.record_digest, first.record_digest);
                assert_eq!(repeated.record, first.record);
                assert_eq!(packaged_binding(repeated), packaged_binding(&first));
            }
            let mut aliases = second.aliases.clone();
            aliases.sort();
            assert_eq!(aliases, vec!["first".to_string(), "second".to_string()]);
            assert_eq!(fixture.count("storage_image").await, 1);
            assert_eq!(fixture.count("raw_conversion_result").await, 1);
        }

        #[tokio::test]
        async fn concurrent_identical_conversions_publish_one_mapping() {
            let fixture = Fixture::new().await;
            let (first, second, third, fourth) = tokio::join!(
                fixture.convert(None),
                fixture.convert(None),
                fixture.convert(None),
                fixture.convert(None),
            );
            let ids = [first, second, third, fourth]
                .into_iter()
                .map(|result| result.unwrap().id)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(ids.len(), 1, "every racer must observe one image: {ids:?}");
            assert_eq!(fixture.count("storage_image").await, 1);
            assert_eq!(fixture.count("raw_conversion_result").await, 1);
            let id = ids.into_iter().next().unwrap();
            assert_eq!(fixture.mapped_image().await, id.to_string());
        }

        #[tokio::test]
        async fn corrupt_retained_closure_refuses_instead_of_replacing() {
            for corrupt_kernel in [false, true] {
                let fixture = Fixture::new().await;
                let original = fixture.convert(None).await.unwrap();
                let pool = StoragePool::open(fixture.paths.images_dir()).unwrap();
                let target = if corrupt_kernel {
                    let BootBinding::Pinned { kernel, .. } = packaged_binding(&original) else {
                        panic!("binding is pinned");
                    };
                    pool.object_path(&kernel)
                } else {
                    pool.stream_path(&original.record.root.stream.stream)
                };
                let mut bytes = std::fs::read(&target).unwrap();
                bytes[0] ^= 0xff;
                overwrite(&target, &bytes);

                assert!(
                    fixture.convert(Some("replacement")).await.is_err(),
                    "corrupt {} must refuse",
                    if corrupt_kernel {
                        "kernel object"
                    } else {
                        "root stream"
                    }
                );
                assert_eq!(fixture.count("storage_image").await, 1);
                assert_eq!(fixture.count("raw_conversion_result").await, 1);
                assert_eq!(fixture.mapped_image().await, original.id.to_string());
                let aliases: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM image_alias WHERE name='replacement'")
                        .fetch_one(fixture.store.test_pool())
                        .await
                        .unwrap();
                assert_eq!(aliases, 0);
            }
        }

        #[tokio::test]
        async fn inadmissible_requests_fail_before_any_operation_registers() {
            let fixture = Fixture::new().await;
            let operations = fixture.count("storage_operation").await;
            let mut foreign = fixture.resolved.clone();
            foreign.platform = oci::Platform {
                os: "linux".into(),
                architecture: "riscv64".into(),
                variant: None,
            };
            assert!(convert(
                fixture.context(),
                foreign,
                RawConversionOptions { alias: None }
            )
            .await
            .is_err());
            assert!(fixture.convert(Some("-bad alias")).await.is_err());
            assert_eq!(fixture.count("storage_operation").await, operations);
            assert_eq!(fixture.count("storage_image").await, 0);
        }

        #[tokio::test]
        async fn cancelled_caller_cannot_revoke_the_owned_conversion() {
            let fixture = Fixture::new().await;
            let pool = StoragePool::open(fixture.paths.images_dir()).unwrap();
            let platform =
                crate::image::convert::linux_platform(&fixture.resolved.platform).unwrap();
            let key = crate::image::convert::conversion_key(&fixture.resolved, platform)
                .unwrap()
                .digest()
                .unwrap();
            // Holding the key parks the conversion for the whole caller timeout,
            // so the caller is deterministically dropped while work is pending.
            let held = pool.lock_publication(&key).unwrap();
            let cancelled = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                fixture.convert(Some("detached")),
            )
            .await;
            assert!(cancelled.is_err(), "the held key parks the conversion");
            drop(held);

            // The detached owner must still finish and settle everything it
            // registered; a caller-owned operation would never get here.
            let tmp = fixture.paths.images_dir().join("tmp");
            let mut settled = None;
            for _ in 0..3000 {
                let committed: Option<String> = sqlx::query_scalar(
                    "SELECT operation_id FROM storage_operation WHERE kind='convert' AND state='committed'",
                )
                .fetch_optional(fixture.store.test_pool())
                .await
                .unwrap();
                if let Some(operation) = committed {
                    if !tmp.join(&operation).exists() {
                        settled = Some(operation);
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(settled.is_some(), "detached conversion never settled");
            let staging: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM storage_operation WHERE kind='convert' AND state<>'committed'",
            )
            .fetch_one(fixture.store.test_pool())
            .await
            .unwrap();
            assert_eq!(staging, 0);
            let aliased: String =
                sqlx::query_scalar("SELECT image_id FROM image_alias WHERE name='detached'")
                    .fetch_one(fixture.store.test_pool())
                    .await
                    .unwrap();
            assert_eq!(aliased, fixture.mapped_image().await);
            let repeated = fixture.convert(None).await.unwrap();
            assert_eq!(repeated.id.to_string(), aliased);
            assert_eq!(fixture.count("storage_image").await, 1);
        }
    }
}

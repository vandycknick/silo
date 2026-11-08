//! Two real runtime catalogs in one process, driven through the participant
//! API exactly as a coordinator would. No VM is started; the source machine
//! is a real imported raw disk with a pinned direct-boot bundle.
#![cfg(target_os = "linux")]

use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::PathBuf;

use sha2::Digest;

use crate::handoff::destination::{fork_machine_id, host_architecture};
use crate::handoff::plan::{
    ApprovedPlan, BootSelection, DestinationRequest, PayloadDescriptor, SourceStop, WritableRole,
    MAX_FRAME_BYTES,
};
use crate::handoff::service::HandoffService;
use crate::handoff::types::{
    HandoffDecision, HandoffError, HandoffMode, HandoffPhase, OperationId, RuntimeId,
};
use crate::store::MachineStore;
use crate::{LibVmError, MachineId, MachineOwnership, MachineRef, Runtime};

pub(crate) struct Participant {
    _home: tempfile::TempDir,
    root: PathBuf,
    pub(crate) runtime: Runtime,
    pub(crate) service: HandoffService,
}

async fn open_runtime(root: &std::path::Path) -> Runtime {
    let runtime = Runtime::open(
        crate::paths::LocalPaths::new(root.join("silo")),
        crate::RuntimeNetworkingConfig::default(),
    )
    .await
    .unwrap();
    std::fs::create_dir_all(runtime.asset_directory()).unwrap();
    let kernel = runtime.asset_directory().join("kernel-default");
    let init = runtime.asset_directory().join("initramfs");
    std::fs::write(
        &kernel,
        test_utils::direct_kernel::host_kernel("handoff packaged kernel"),
    )
    .unwrap();
    std::fs::write(&init, b"handoff packaged base-init bytes").unwrap();
    for asset in [&kernel, &init] {
        std::fs::set_permissions(asset, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    runtime
}

pub(crate) async fn participant() -> Participant {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().to_path_buf();
    let runtime = open_runtime(&root).await;
    Participant {
        _home: home,
        root,
        service: HandoffService::new(runtime.clone()),
        runtime,
    }
}

impl Participant {
    /// Reopen the same home as a restarted daemon would.
    pub(crate) async fn restart(self) -> Self {
        let Self {
            _home,
            root,
            runtime,
            service,
        } = self;
        drop(service);
        drop(runtime);
        let runtime = open_runtime(&root).await;
        Self {
            _home,
            root,
            service: HandoffService::new(runtime.clone()),
            runtime,
        }
    }

    async fn runtime_id(&self) -> RuntimeId {
        self.runtime
            .native_store()
            .unwrap()
            .runtime_id()
            .await
            .unwrap()
    }

    pub(crate) async fn create_raw(&self, name: &str) -> MachineId {
        self.create_raw_with_agent(name, None).await
    }

    async fn create_raw_with_agent(&self, name: &str, agent: Option<PathBuf>) -> MachineId {
        let disk = self.root.join(format!("{name}.raw"));
        disk_image::ext4::Formatter::new(&disk, 4096, 64 * 1024 * 1024)
            .unwrap()
            .close()
            .unwrap();
        let mut image = crate::ImageSource::disk(&disk);
        if let crate::ImageSource::Disk(request) = &mut image {
            let crate::DiskImportBoot::LinuxDirect { assets, .. } = &mut request.boot;
            *assets = crate::BootAssetSelection::Files {
                kernel: self.runtime.asset_directory().join("kernel-default"),
                base_initramfs: self.runtime.asset_directory().join("initramfs"),
                agent,
            };
        }
        self.runtime
            .machine()
            .name(name)
            .image_source(image)
            .create()
            .await
            .unwrap()
            .machine_id()
    }

    pub(crate) async fn storage(&self, machine: MachineId) -> crate::MachineStorageRecord {
        self.runtime.machine_storage_record(machine).await.unwrap()
    }

    pub(crate) async fn root_file(&self, machine: MachineId) -> PathBuf {
        let config = self.runtime.machine_config(machine).await.unwrap().unwrap();
        let storage = self.storage(machine).await;
        let (path, _) = crate::machine::stopped::root_private(&storage);
        config.machine_dir.join(path.as_path())
    }

    async fn root_digest(&self, machine: MachineId) -> Vec<u8> {
        sha2::Sha256::digest(std::fs::read(self.root_file(machine).await).unwrap()).to_vec()
    }

    /// Overwrite part of a stopped private root, as a later guest run would.
    async fn write_root(&self, machine: MachineId, offset: u64, byte: u8) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.root_file(machine).await)
            .unwrap();
        file.write_all_at(&vec![byte; 4096], offset).unwrap();
        file.sync_all().unwrap();
    }
}

/// Install an authenticated layered root on a real stopped raw-machine catalog.
/// This is storage-only setup, never an admitted boot tuple or a launched VM.
async fn install_layered_root(
    participant: &Participant,
    machine: MachineId,
) -> crate::store::models::snapshot::SnapshotComposition {
    let store = participant.runtime.native_store().unwrap();
    let (_images, _, image) =
        crate::image::transport::tests::layered_image_in(std::sync::Arc::new(store.clone())).await;
    let crate::store::models::snapshot::SnapshotRootProfile::LinuxOverlay {
        lower,
        lower_geometry,
        lower_filesystem_uuid,
        upper_uuid,
        ext4_profile,
        overlay_profile,
        temporary_directory,
    } = image.root.profile
    else {
        panic!("layered fixture");
    };
    let mut config = participant
        .runtime
        .machine_config(machine)
        .await
        .unwrap()
        .unwrap();
    let mut storage = participant.storage(machine).await;
    let root = participant.root_file(machine).await;
    let pool =
        crate::storage::pool::StoragePool::open(participant.runtime.local_images_dir()).unwrap();
    let mut source = pool.open_stream(&image.root.stream.stream).unwrap();
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&root)
        .unwrap();
    std::io::copy(&mut source, &mut destination).unwrap();
    destination.sync_all().unwrap();
    let upper_path = crate::machine::stopped::root_private(&storage).0.clone();
    storage.root = crate::MachineRoot::LinuxOverlay {
        lower: crate::OverlayLower::ErofsComposition {
            record: lower.result,
            geometry: lower_geometry,
            filesystem_uuid: lower_filesystem_uuid,
        },
        upper: upper_path.clone(),
        upper_uuid,
        capacity: image.root.geometry.length,
        ext4_profile,
        overlay_profile,
        temporary_directory,
    };
    storage.profile = crate::StorageProfile::LinuxOverlayV1;
    storage.backend = crate::BackendRequirement::KrunOverlay;
    storage.storage_generation += 1;
    let crate::BootProfile::LinuxDirect { root_selector, .. } = &mut storage.boot else {
        panic!("direct boot fixture");
    };
    *root_selector = crate::RootSelector::ManagedOverlay;
    config.spec.storage.as_mut().unwrap().disks = vec![
        crate::machine::root_storage::disk(
            "lower.vmdk",
            vm_spec::DiskRole::RootLower,
            lower_geometry.length,
            "silo-root-lower".into(),
        )
        .unwrap(),
        crate::machine::root_storage::disk(
            upper_path.as_path(),
            vm_spec::DiskRole::RootUpper,
            image.root.geometry.length,
            "silo-root-upper".into(),
        )
        .unwrap(),
    ];
    config
        .spec
        .boot
        .as_mut()
        .unwrap()
        .kernel
        .as_mut()
        .unwrap()
        .cmdline
        .push("silo.rootfs=linux-erofs-overlay-v1".into());
    let mut transaction = store
        .test_pool()
        .begin_with("BEGIN IMMEDIATE")
        .await
        .unwrap();
    sqlx::query("UPDATE machine_config SET config_json=jsonb(?1) WHERE id=?2")
        .bind(serde_json::to_string(&config).unwrap())
        .bind(machine.to_string())
        .execute(&mut *transaction)
        .await
        .unwrap();
    crate::store::Store::write_machine_storage(&mut transaction, machine, &storage)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    *lower
}

#[tokio::test]
async fn layered_handoff_estimates_and_transfers_one_closed_graph_before_capture() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("layered-transfer").await;
    let lower = install_layered_root(&source, machine).await;
    let op = operation();
    let observation = source
        .service
        .observe_source(&MachineRef::id(machine))
        .await
        .unwrap();
    assert_eq!(
        observation.body().immutable.composition.as_ref(),
        Some(&lower)
    );
    assert_eq!(observation.body().immutable.streams.len(), 1);
    let proposal = destination
        .service
        .preflight_destination(&observation, &request(op, HandoffMode::Relocate))
        .await
        .unwrap();
    let expected: u64 = observation
        .body()
        .immutable
        .objects
        .iter()
        .map(|object| object.length)
        .chain(
            observation
                .body()
                .immutable
                .streams
                .iter()
                .map(|stream| stream.length),
        )
        .sum();
    assert_eq!(proposal.estimate.immutable_bytes, expected);
    let digest = proposal.plan.digest();
    let plan = proposal.plan.approve(digest).unwrap();
    source.service.begin_source(&plan).await.unwrap();
    destination.service.receive(&plan).await.unwrap();
    let mut moved = Moved::default();
    fill(&source, &destination, op, &mut moved).await;
    let pool =
        crate::storage::pool::StoragePool::open(destination.runtime.local_images_dir()).unwrap();
    let fsmeta = pool.verify_object(&lower.fsmeta).unwrap();
    assert!(fsmeta.metadata().unwrap().len() > 0);
    assert!(moved.objects > 0 && moved.chunks > 0);
    assert!(destination
        .runtime
        .machine_config(machine)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        source.storage(machine).await.ownership,
        MachineOwnership::Owned
    ));
    let receipt = destination
        .service
        .abort(&plan.intent().unwrap())
        .await
        .unwrap();
    assert_eq!(receipt.decision, HandoffDecision::Aborted);
    source.service.resolve_source(&receipt).await.unwrap();
    assert_eq!(
        destination
            .service
            .abort(&plan.intent().unwrap())
            .await
            .unwrap(),
        receipt
    );
}

#[tokio::test]
async fn unavailable_oci_source_falls_back_to_exact_layered_handoff_objects() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("layered-unavailable-source").await;
    let lower = install_layered_root(&source, machine).await;
    let manifest = crate::storage::identity::ObjectDigest::of_bytes(b"deleted OCI source manifest");
    let store = source.runtime.native_store().unwrap();
    sqlx::query("UPDATE machine_rootfs SET source_kind='oci',selected_reference=?1,manifest_digest=?2 WHERE machine_id=?3")
        .bind(format!("localhost:1/deleted/source@{manifest}")).bind(manifest.to_string())
        .bind(machine.to_string()).execute(store.test_pool()).await.unwrap();
    let op = operation();
    let plan = approve(
        &source,
        &destination,
        machine,
        &request(op, HandoffMode::Relocate),
    )
    .await;
    assert!(plan.body().observation.immutable.oci_source.is_some());
    source.service.begin_source(&plan).await.unwrap();
    destination.service.receive(&plan).await.unwrap();
    let mut moved = Moved::default();
    fill(&source, &destination, op, &mut moved).await;
    let pool =
        crate::storage::pool::StoragePool::open(destination.runtime.local_images_dir()).unwrap();
    assert!(pool.verify_object(&lower.fsmeta).is_ok());
    assert!(moved.chunks > 0);
    assert!(destination
        .service
        .list_needs(op, None, 256)
        .await
        .unwrap()
        .needs
        .is_empty());
    let receipt = destination
        .service
        .abort(&plan.intent().unwrap())
        .await
        .unwrap();
    source.service.resolve_source(&receipt).await.unwrap();
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Moved {
    objects: u64,
    maps: u64,
    chunks: u64,
    chunk_bytes: u64,
}

pub(crate) fn operation() -> OperationId {
    OperationId::new(uuid::Uuid::new_v4()).unwrap()
}

pub(crate) fn request(operation: OperationId, mode: HandoffMode) -> DestinationRequest {
    DestinationRequest {
        operation,
        mode,
        name: None,
        boot_bundle: None,
        resources: crate::ExternalResourcePolicy::Reject,
    }
}

pub(crate) async fn approve(
    source: &Participant,
    destination: &Participant,
    machine: MachineId,
    request: &DestinationRequest,
) -> ApprovedPlan {
    let observation = source
        .service
        .observe_source(&MachineRef::id(machine))
        .await
        .unwrap();
    let proposal = destination
        .service
        .preflight_destination(&observation, request)
        .await
        .unwrap();
    let digest = proposal.plan.digest();
    proposal.plan.approve(digest).unwrap()
}

/// Copy one descriptor in bounded frames through the real participant API.
async fn copy(
    source: &Participant,
    destination: &Participant,
    operation: OperationId,
    descriptor: PayloadDescriptor,
    moved: &mut Moved,
) {
    let mut writer = destination
        .service
        .open_payload(operation, descriptor)
        .await
        .unwrap();
    let mut offset = 0;
    loop {
        let frame = source
            .service
            .read_payload(operation, descriptor, offset, MAX_FRAME_BYTES)
            .await
            .unwrap();
        assert!(frame.total_length <= descriptor.max_length());
        writer.write_frame(&frame.bytes).unwrap();
        offset += frame.bytes.len() as u64;
        if frame.end {
            assert_eq!(offset, frame.total_length);
            break;
        }
    }
    let receipt = writer.finish().await.unwrap();
    assert_eq!(receipt.bytes, offset);
    match descriptor {
        PayloadDescriptor::Object { .. } => moved.objects += 1,
        PayloadDescriptor::StreamMap { .. } => moved.maps += 1,
        PayloadDescriptor::Chunk { length, .. } => {
            moved.chunks += 1;
            moved.chunk_bytes += length;
        }
    }
}

/// Repeat full needs passes until one pass needs nothing.
async fn fill(
    source: &Participant,
    destination: &Participant,
    operation: OperationId,
    moved: &mut Moved,
) {
    loop {
        let mut cursor = None;
        let mut any = false;
        loop {
            let page = destination
                .service
                .list_needs(operation, cursor, 256)
                .await
                .unwrap();
            for need in page.needs {
                any = true;
                copy(source, destination, operation, need, moved).await;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        if !any {
            return;
        }
    }
}

/// The complete coordinator sequence up to an offered, fully received cut.
async fn offered(
    source: &Participant,
    destination: &Participant,
    plan: &ApprovedPlan,
) -> (crate::handoff::plan::CaptureOffer, Moved) {
    let operation = plan.plan().operation();
    let mut moved = Moved::default();
    source.service.begin_source(plan).await.unwrap();
    destination.service.receive(plan).await.unwrap();
    fill(source, destination, operation, &mut moved).await;
    let offer = source
        .service
        .capture_source(plan, SourceStop::RequireStopped)
        .await
        .unwrap();
    destination.service.offer_capture(&offer).await.unwrap();
    fill(source, destination, operation, &mut moved).await;
    (offer, moved)
}

/// The complete coordinator sequence up to a prepared destination.
async fn prepare(
    source: &Participant,
    destination: &Participant,
    plan: &ApprovedPlan,
) -> (crate::handoff::types::PreparedReceipt, Moved) {
    let (offer, moved) = offered(source, destination, plan).await;
    let prepared = destination.service.prepare(offer.binding()).await.unwrap();
    (prepared, moved)
}

async fn complete(
    source: &Participant,
    destination: &Participant,
    plan: &ApprovedPlan,
) -> (
    crate::handoff::types::TerminalReceipt,
    Moved,
    crate::handoff::types::CommitAuthorization,
) {
    let (prepared, moved) = prepare(source, destination, plan).await;
    let authorization = source.service.fence_source(&prepared).await.unwrap();
    let receipt = destination.service.commit(&authorization).await.unwrap();
    source.service.resolve_source(&receipt).await.unwrap();
    (receipt, moved, authorization)
}

fn handoff_error(error: &LibVmError) -> Option<&HandoffError> {
    match error {
        LibVmError::Handoff(error) => Some(error),
        _ => None,
    }
}

#[tokio::test]
async fn relocation_cycles_move_ownership_and_only_changed_chunks() {
    let a = participant().await;
    let b = participant().await;
    let (a_id, b_id) = (a.runtime_id().await, b.runtime_id().await);
    assert_ne!(a_id, b_id);
    let machine = a.create_raw("traveller").await;
    let original = a.root_digest(machine).await;

    // A -> B: cold destination, everything nonzero travels once.
    let first = operation();
    let plan = approve(&a, &b, machine, &request(first, HandoffMode::Relocate)).await;
    assert_eq!(plan.plan().destination_machine(), machine);
    let (receipt1, moved, authorization1) = complete(&a, &b, &plan).await;
    assert_eq!(receipt1.decision, HandoffDecision::Committed);
    assert!(moved.objects > 0 && moved.chunks > 0 && moved.maps == 1);
    assert_eq!(b.root_digest(machine).await, original);
    let b_storage = b.storage(machine).await;
    assert_eq!(b_storage.ownership, MachineOwnership::Owned);
    assert_eq!(b_storage.ownership_epoch, 1);
    let state = b
        .runtime
        .native_store()
        .unwrap()
        .machine_state(machine)
        .await
        .unwrap()
        .unwrap();
    assert!(state.run_id.is_none() && state.vmm_pid.is_none());
    assert!(matches!(
        a.storage(machine).await.ownership,
        MachineOwnership::Relocated { successor_runtime, successor_epoch, .. }
            if successor_runtime == b_id && successor_epoch.get() == 1
    ));
    assert!(a
        .storage(machine)
        .await
        .ownership
        .ensure_owned(machine)
        .is_err());

    // B writes one 4 KiB block, then B -> A: only that chunk travels; the
    // boot closure and every unchanged chunk come from A's prior files.
    b.write_root(machine, 9 * 1024 * 1024, 0x5a).await;
    let changed = b.root_digest(machine).await;
    let second = operation();
    let plan = approve(&b, &a, machine, &request(second, HandoffMode::Relocate)).await;
    let (_, moved, _) = complete(&b, &a, &plan).await;
    assert_eq!(
        moved,
        Moved {
            objects: 0,
            maps: 1,
            chunks: 1,
            chunk_bytes: 8 * 1024 * 1024
        }
    );
    assert_eq!(a.root_digest(machine).await, changed);
    let a_storage = a.storage(machine).await;
    assert_eq!(a_storage.ownership, MachineOwnership::Owned);
    assert_eq!(a_storage.ownership_epoch, 2);

    // A -> B again with another change: B reuses its prior-owner files.
    a.write_root(machine, 20 * 1024 * 1024, 0xa5).await;
    let third = operation();
    let plan = approve(&a, &b, machine, &request(third, HandoffMode::Relocate)).await;
    let (_, moved, _) = complete(&a, &b, &plan).await;
    assert_eq!((moved.objects, moved.chunks), (0, 1));
    assert_eq!(b.storage(machine).await.ownership_epoch, 3);

    // A historical authorization replays only its historical receipt.
    let replay = b.service.commit(&authorization1).await.unwrap();
    assert_eq!(replay, receipt1);
    assert_eq!(b.storage(machine).await.ownership_epoch, 3);
    assert_eq!(b.storage(machine).await.ownership, MachineOwnership::Owned);
}

#[tokio::test]
async fn fork_creates_distinct_stopped_destination_and_keeps_source_owned() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("parent").await;
    let op = operation();
    let mut fork = request(op, HandoffMode::Fork);
    fork.name = Some("child".into());
    let plan = approve(&a, &b, machine, &fork).await;
    // Recomputing the same request yields the same digest and identity.
    assert_eq!(
        approve(&a, &b, machine, &fork).await.digest(),
        plan.digest()
    );
    let child = fork_machine_id(op, b.runtime_id().await);
    assert_eq!(plan.plan().destination_machine(), child);
    assert_ne!(child, machine);
    plan.plan().validate_request(&fork).unwrap();
    let mut changed = fork.clone();
    changed.name = Some("other".into());
    assert!(plan.plan().validate_request(&changed).is_err());
    complete(&a, &b, &plan).await;
    let source = a.storage(machine).await;
    assert_eq!(source.ownership, MachineOwnership::Owned);
    assert_eq!(source.ownership_epoch, 0);
    let destination = b.storage(child).await;
    assert_eq!(destination.ownership, MachineOwnership::Owned);
    assert_eq!(destination.ownership_epoch, 0);
    assert_eq!(
        b.runtime.machine_config(child).await.unwrap().unwrap().name,
        "child"
    );
    assert_eq!(a.root_digest(machine).await, b.root_digest(child).await);
    // Private writable files are independent after the fork.
    b.write_root(child, 0, 0x11).await;
    assert_ne!(a.root_digest(machine).await, b.root_digest(child).await);
}

#[tokio::test]
async fn durable_abort_unfences_source_and_forbids_late_commit() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("aborted").await;
    let op = operation();
    let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
    let (prepared, _) = prepare(&a, &b, &plan).await;
    let authorization = a.service.fence_source(&prepared).await.unwrap();
    assert!(matches!(
        a.storage(machine).await.ownership,
        MachineOwnership::Fenced { .. }
    ));
    let intent = plan.intent().unwrap();
    let aborted = b.service.abort(&intent).await.unwrap();
    assert_eq!(aborted.decision, HandoffDecision::Aborted);
    assert_eq!(b.service.abort(&intent).await.unwrap(), aborted);
    let late = b.service.commit(&authorization).await.unwrap_err();
    assert!(matches!(
        handoff_error(&late),
        Some(HandoffError::OperationAborted { .. })
    ));
    assert!(b.runtime.machine_config(machine).await.unwrap().is_none());
    assert!(!crate::paths::machine_data_dir_in(b.runtime.local_home(), machine).exists());
    let record = a.service.resolve_source(&aborted).await.unwrap();
    assert_eq!(record.phase, HandoffPhase::Aborted);
    let source = a.storage(machine).await;
    assert_eq!(source.ownership, MachineOwnership::Owned);
    assert_eq!(source.ownership_epoch, 0);
    // The saved plan still answers recovery after the terminal decision.
    assert_eq!(a.service.plan(op).await.unwrap().digest(), plan.digest());
}

#[tokio::test]
async fn commit_wins_over_late_abort_and_survives_participant_restart() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("restarted").await;
    let op = operation();
    let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
    a.service.begin_source(&plan).await.unwrap();
    b.service.receive(&plan).await.unwrap();
    // Both daemons restart before any payload; recovery uses saved state.
    let a = a.restart().await;
    let b = b.restart().await;
    assert_eq!(b.service.plan(op).await.unwrap().digest(), plan.digest());
    let saved = a.service.plan(op).await.unwrap();
    let (prepared, _) = prepare(&a, &b, &saved).await;
    let b = b.restart().await;
    assert_eq!(
        b.service.status(op).await.unwrap().unwrap().phase,
        HandoffPhase::Prepared
    );
    let authorization = a.service.fence_source(&prepared).await.unwrap();
    assert_eq!(
        a.service.fence_source(&prepared).await.unwrap(),
        authorization
    );
    let committed = b.service.commit(&authorization).await.unwrap();
    let late = b.service.abort(&plan.intent().unwrap()).await.unwrap();
    assert_eq!(late, committed);
    a.service.resolve_source(&committed).await.unwrap();
    assert!(matches!(
        a.storage(machine).await.ownership,
        MachineOwnership::Relocated { .. }
    ));
    assert_eq!(b.storage(machine).await.ownership_epoch, 1);
}

#[tokio::test]
async fn changed_source_configuration_refuses_before_reservation() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("drifting").await;
    let op = operation();
    let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
    a.service.begin_source(&plan).await.unwrap();
    let mut config = a.runtime.machine_config(machine).await.unwrap().unwrap();
    config.labels.insert("changed".into(), "after-plan".into());
    a.runtime
        .native_store()
        .unwrap()
        .save_machine_config(&config)
        .await
        .unwrap();
    let stale = a
        .service
        .capture_source(&plan, SourceStop::RequireStopped)
        .await
        .unwrap_err();
    assert!(matches!(
        handoff_error(&stale),
        Some(HandoffError::AdmissionStale)
    ));
    assert_eq!(a.storage(machine).await.ownership, MachineOwnership::Owned);
    assert_eq!(
        a.service.status(op).await.unwrap().unwrap().phase,
        HandoffPhase::Intended
    );
}

#[tokio::test]
async fn stopped_private_writes_invalidate_approval_before_begin_or_reservation() {
    for begun in [false, true] {
        let a = participant().await;
        let b = participant().await;
        let machine = a.create_raw("changed-bytes").await;
        let op = operation();
        let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
        if begun {
            a.service.begin_source(&plan).await.unwrap();
        }
        a.write_root(machine, 1024 * 1024, 0x59).await;
        let error = if begun {
            a.service
                .capture_source(&plan, SourceStop::RequireStopped)
                .await
                .unwrap_err()
        } else {
            a.service.begin_source(&plan).await.unwrap_err()
        };
        assert!(matches!(
            handoff_error(&error),
            Some(HandoffError::AdmissionStale)
        ));
        assert_eq!(a.storage(machine).await.ownership, MachineOwnership::Owned);
        assert_eq!(
            a.service
                .status(op)
                .await
                .unwrap()
                .map(|record| record.phase),
            begun.then_some(HandoffPhase::Intended),
        );
        assert!(b.service.status(op).await.unwrap().is_none());
        if begun {
            let receipt = b.service.abort(&plan.intent().unwrap()).await.unwrap();
            a.service.resolve_source(&receipt).await.unwrap();
        }
        let current = approve(
            &a,
            &b,
            machine,
            &request(operation(), HandoffMode::Relocate),
        )
        .await;
        complete(&a, &b, &current).await;
        assert_eq!(a.root_digest(machine).await, b.root_digest(machine).await);
    }
}

#[tokio::test]
async fn payload_writer_never_publishes_partial_oversized_or_foreign_bytes() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("writer").await;
    let op = operation();
    let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
    a.service.begin_source(&plan).await.unwrap();
    b.service.receive(&plan).await.unwrap();
    let page = b.service.list_needs(op, None, 256).await.unwrap();
    let object = page
        .needs
        .iter()
        .copied()
        .find(|need| matches!(need, PayloadDescriptor::Object { .. }))
        .unwrap();
    let PayloadDescriptor::Object { digest, length } = object else {
        unreachable!();
    };
    let staging = b
        .root
        .join("silo/handoff")
        .join(op.to_string())
        .join("staging");
    let pool = crate::storage::pool::StoragePool::open(b.runtime.local_images_dir()).unwrap();

    // Empty and oversized frames are refused.
    let mut writer = b.service.open_payload(op, object).await.unwrap();
    assert!(writer.write_frame(&[]).is_err());
    assert!(writer
        .write_frame(&vec![0; MAX_FRAME_BYTES as usize + 1])
        .is_err());
    // An early finish refuses and publishes nothing.
    writer.write_frame(&[1]).unwrap();
    assert!(writer.finish().await.is_err());
    assert!(!pool.object_path(&digest).exists());
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    // Wrong bytes of the right length never become the object.
    let mut writer = b.service.open_payload(op, object).await.unwrap();
    let mut remaining = length;
    while remaining > 0 {
        let size = remaining.min(u64::from(MAX_FRAME_BYTES));
        writer.write_frame(&vec![0x42; size as usize]).unwrap();
        remaining -= size;
    }
    assert!(writer.write_frame(&[0]).is_err());
    assert!(writer.finish().await.is_err());
    assert!(!pool.object_path(&digest).exists());
    // A dropped partial write leaves no staging residue.
    let mut writer = b.service.open_payload(op, object).await.unwrap();
    writer.write_frame(&[7; 16]).unwrap();
    drop(writer);
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    // Descriptors outside the inventory are refused before any staging.
    let foreign = PayloadDescriptor::Chunk {
        digest: crate::ObjectDigest::of_bytes(b"not part of this handoff"),
        length: 24,
    };
    assert!(b.service.open_payload(op, foreign).await.is_err());
    // Source reads stay within the operation closure and frame bounds.
    assert!(a.service.read_payload(op, foreign, 0, 1024).await.is_err());
    assert!(a.service.read_payload(op, object, 0, 0).await.is_err());
    assert!(a
        .service
        .read_payload(op, object, 0, MAX_FRAME_BYTES + 1)
        .await
        .is_err());
    assert!(a
        .service
        .read_payload(op, object, length, 1024)
        .await
        .is_err());
}

#[tokio::test]
async fn cross_architecture_requires_a_complete_destination_bundle() {
    let b = participant().await;
    let store = b.runtime.native_store().unwrap();
    let pool = crate::storage::pool::StoragePool::open(b.runtime.local_images_dir()).unwrap();
    let host = host_architecture().unwrap();
    let foreign = match host {
        crate::GuestArchitecture::Amd64 => crate::GuestArchitecture::Arm64,
        crate::GuestArchitecture::Arm64 => crate::GuestArchitecture::Amd64,
    };
    let source = |userspace, kernel, translation| crate::BootProfile::LinuxDirect {
        userspace_platform: crate::LinuxPlatform {
            architecture: userspace,
            variant: None,
        },
        kernel_architecture: kernel,
        command_line_policy: crate::DirectCommandLinePolicy::SiloDirectV1,
        binding: crate::BootBinding::Pinned {
            kernel: crate::ObjectDigest::of_bytes(b"source kernel"),
            base_initramfs: crate::ObjectDigest::of_bytes(b"source init"),
            agent: None,
            architecture: kernel,
            abi: crate::runtime::boot_assets::DIRECT_BOOT_ABI.into(),
        },
        root_selector: crate::RootSelector::WholeDisk,
        root_filesystem: crate::RootFilesystem::Ext4,
        translation,
    };
    // A source booted on another kernel architecture, running host userspace.
    let translated = if host == crate::GuestArchitecture::Amd64 {
        source(host, foreign, crate::Translation::Rosetta)
    } else {
        source(host, foreign, crate::Translation::None)
    };
    let boot = |profile: &crate::BootProfile, selection| {
        crate::handoff::destination::destination_boot(
            &b.runtime, &store, profile, false, selection, &pool,
        )
    };
    // The exact recorded bundle can never boot here.
    assert!(boot(&translated, BootSelection::ExactRecorded).is_err());
    // A bundle that is neither retained nor packaged is refused.
    assert!(boot(
        &translated,
        BootSelection::DestinationBundle {
            bundle: crate::ObjectDigest::of_bytes(b"unknown bundle"),
        }
    )
    .is_err());
    // The packaged complete bundle replaces kernel, init and translation.
    let mut native = translated.clone();
    if let crate::BootProfile::LinuxDirect {
        kernel_architecture,
        translation,
        binding,
        ..
    } = &mut native
    {
        *kernel_architecture = host;
        *translation = crate::Translation::None;
        *binding = crate::BootBinding::RuntimeSelected;
    }
    let context = b
        .runtime
        .captured_boot_context(&pool, &store, uuid::Uuid::nil());
    let packaged =
        crate::runtime::boot_assets::packaged_binding(&native, false, context.selection()).unwrap();
    let approved = boot(
        &translated,
        BootSelection::DestinationBundle {
            bundle: packaged.digest().unwrap(),
        },
    )
    .unwrap();
    assert!(matches!(
        approved,
        crate::BootProfile::LinuxDirect {
            kernel_architecture,
            translation: crate::Translation::None,
            ref binding,
            ..
        } if kernel_architecture == host && *binding == packaged
    ));
    // Foreign userspace with no admitted translation is rejected.
    if host == crate::GuestArchitecture::Amd64 {
        let reverse = source(
            crate::GuestArchitecture::Arm64,
            crate::GuestArchitecture::Arm64,
            crate::Translation::None,
        );
        assert!(boot(
            &reverse,
            BootSelection::DestinationBundle {
                bundle: packaged.digest().unwrap(),
            }
        )
        .is_err());
    }
}

/// A capture-named private file left by an interrupted prepare is reused
/// only when its bytes verify (and is then synchronized before Prepared);
/// any other leftover is replaced by a freshly assembled file.
#[tokio::test]
async fn interrupted_prepare_reuses_only_verified_private_files() {
    use std::os::unix::fs::MetadataExt;

    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("interrupted").await;
    let original = std::fs::read(a.root_file(machine).await).unwrap();
    for exact in [true, false] {
        let op = operation();
        let mut fork = request(op, HandoffMode::Fork);
        fork.name = Some(format!("interrupted-{exact}"));
        let plan = approve(&a, &b, machine, &fork).await;
        let child = plan.plan().destination_machine();
        let (offer, _) = offered(&a, &b, &plan).await;
        let name = crate::handoff::destination::prepared_name(
            offer.binding().capture,
            WritableRole::Root,
            &a.storage(machine).await,
        );
        let dir = crate::paths::machine_data_dir_in(b.runtime.local_home(), child);
        let directory = crate::paths::OwnedDirectory::open_root(dir.parent().unwrap())
            .unwrap()
            .ensure_dir(&child.to_string())
            .unwrap();
        // The final write landed but the process died before its sync.
        let mut bytes = original.clone();
        if !exact {
            bytes[4096] ^= 0xff;
        }
        let file = crate::image::transport::blobs::create_private_file(&directory, &name).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        let interrupted = file.metadata().unwrap().ino();
        drop(file);
        let prepared = b.service.prepare(offer.binding()).await.unwrap();
        assert_eq!(prepared.binding, *offer.binding());
        let path = dir.join(&name);
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino() == interrupted,
            exact
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let authorization = a.service.fence_source(&prepared).await.unwrap();
        let receipt = b.service.commit(&authorization).await.unwrap();
        a.service.resolve_source(&receipt).await.unwrap();
        assert_eq!(std::fs::read(b.root_file(child).await).unwrap(), original);
    }
}

/// A cold destination materializes exactly the approved packaged tuple,
/// including whether it carries an agent, instead of its own default.
#[tokio::test]
async fn cold_destination_prepares_the_exact_approved_agent_choice() {
    for agent in [false, true] {
        let a = participant().await;
        let b = participant().await;
        let source_agent = agent.then(|| a.runtime.asset_directory().join("agent"));
        if agent {
            for runtime in [&a.runtime, &b.runtime] {
                let path = runtime.asset_directory().join("agent");
                std::fs::write(&path, b"handoff packaged agent bytes").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let machine = a.create_raw_with_agent("bundled", source_agent).await;
        std::fs::write(
            b.runtime.asset_directory().join("kernel-default"),
            test_utils::direct_kernel::host_kernel("destination replacement kernel"),
        )
        .unwrap();
        let store = b.runtime.native_store().unwrap();
        let pool = crate::storage::pool::StoragePool::open(b.runtime.local_images_dir()).unwrap();
        let mut native = a.storage(machine).await.boot;
        if let crate::BootProfile::LinuxDirect {
            kernel_architecture,
            translation,
            binding,
            ..
        } = &mut native
        {
            *kernel_architecture = host_architecture().unwrap();
            *translation = crate::Translation::None;
            *binding = crate::BootBinding::RuntimeSelected;
        }
        let context = b
            .runtime
            .captured_boot_context(&pool, &store, uuid::Uuid::nil());
        let packaged =
            crate::runtime::boot_assets::packaged_binding(&native, agent, context.selection())
                .unwrap();
        let bundle = packaged.digest().unwrap();
        assert!(!pool.object_path(&bundle).exists());
        let op = operation();
        let mut relocate = request(op, HandoffMode::Relocate);
        relocate.boot_bundle = Some(bundle);
        let plan = approve(&a, &b, machine, &relocate).await;
        let (offer, _) = offered(&a, &b, &plan).await;
        assert!(!pool.object_path(&bundle).exists());
        let prepared = b.service.prepare(offer.binding()).await.unwrap();
        let authorization = a.service.fence_source(&prepared).await.unwrap();
        let receipt = b.service.commit(&authorization).await.unwrap();
        a.service.resolve_source(&receipt).await.unwrap();
        assert_eq!(receipt.decision, HandoffDecision::Committed);
        let crate::BootProfile::LinuxDirect { binding, .. } = b.storage(machine).await.boot else {
            panic!("handoff destination boot is Linux direct");
        };
        assert_eq!(binding, packaged);
        assert!(matches!(
            binding,
            crate::BootBinding::Pinned { agent: pinned, .. } if pinned.is_some() == agent
        ));
        assert!(pool.object_path(&bundle).is_file());
    }
}

/// A creating commit that dies after its side effects leaves a durable,
/// identity-bound authority: abort removes exactly that unpublished machine
/// directory and its SSH scope, never a directory that replaced it, and
/// aborting a return keeps the prior owner's scope and files.
#[tokio::test]
async fn abort_removes_only_recorded_unpublished_creation_leftovers() {
    use std::os::unix::fs::DirBuilderExt;

    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("unpublished").await;
    let op = operation();
    let plan = approve(&a, &b, machine, &request(op, HandoffMode::Relocate)).await;
    let intent = plan.intent().unwrap();
    let (prepared, _) = prepare(&a, &b, &plan).await;
    let authorization = a.service.fence_source(&prepared).await.unwrap();
    // A name taken after preflight makes the creating commit fail inside
    // its transaction, after the scope and config sidecar were written.
    b.create_raw("unpublished").await;
    let failed = b.service.commit(&authorization).await.unwrap_err();
    assert!(matches!(failed, LibVmError::MachineAlreadyExists { .. }));
    assert!(b.runtime.machine_config(machine).await.unwrap().is_none());
    let dir = crate::paths::machine_data_dir_in(b.runtime.local_home(), machine);
    assert!(crate::paths::vm_spec_path_in(&dir).exists());
    // The process died before its error cleanup could delete the scope.
    crate::ssh_ca::resolve(b.runtime.secret_store(), machine, true).unwrap();

    // Another directory now occupies the path: abort preserves it all.
    let moved = dir.with_extension("moved");
    std::fs::rename(&dir, &moved).unwrap();
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    std::fs::write(dir.join("foreign"), b"not this operation's").unwrap();
    // The original scope moved with its directory; give the replacement
    // its own scope so abort must preserve that identity too.
    let foreign_ca = crate::ssh_ca::resolve(b.runtime.secret_store(), machine, true).unwrap();
    let aborted = b.service.abort(&intent).await.unwrap();
    assert_eq!(aborted.decision, HandoffDecision::Aborted);
    assert!(dir.join("foreign").exists());
    assert_eq!(
        crate::ssh_ca::resolve(b.runtime.secret_store(), machine, false)
            .unwrap()
            .public,
        foreign_ca.public,
    );

    // The recorded directory back in place: a replay removes it and the scope.
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::rename(&moved, &dir).unwrap();
    assert_eq!(b.service.abort(&intent).await.unwrap(), aborted);
    assert!(b.runtime.machine_config(machine).await.unwrap().is_none());
    assert!(!dir.exists());
    assert!(crate::ssh_ca::resolve(b.runtime.secret_store(), machine, false).is_err());
    // Further replays repeat nothing harmful.
    assert_eq!(b.service.abort(&intent).await.unwrap(), aborted);
    let late = b.service.commit(&authorization).await.unwrap_err();
    assert!(matches!(
        handoff_error(&late),
        Some(HandoffError::OperationAborted { .. })
    ));
    assert!(!dir.exists());
    a.service.resolve_source(&aborted).await.unwrap();

    // A -> B commits, then an aborted B -> A return must not touch A's
    // fenced prior-owner record, files or SSH scope.
    let returner = a.create_raw("returner").await;
    complete(
        &a,
        &b,
        &approve(
            &a,
            &b,
            returner,
            &request(operation(), HandoffMode::Relocate),
        )
        .await,
    )
    .await;
    let prior_root = a.root_file(returner).await;
    let prior_bytes = std::fs::read(&prior_root).unwrap();
    let back = operation();
    let plan = approve(&b, &a, returner, &request(back, HandoffMode::Relocate)).await;
    let (offer, _) = offered(&b, &a, &plan).await;
    a.service.prepare(offer.binding()).await.unwrap();
    let aborted = a.service.abort(&plan.intent().unwrap()).await.unwrap();
    assert_eq!(aborted.decision, HandoffDecision::Aborted);
    crate::ssh_ca::resolve(a.runtime.secret_store(), returner, false).unwrap();
    assert_eq!(std::fs::read(&prior_root).unwrap(), prior_bytes);
    let prefix = format!("handoff-{}-", offer.binding().capture);
    assert!(std::fs::read_dir(prior_root.parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(&prefix)));
    b.service.resolve_source(&aborted).await.unwrap();
    assert!(matches!(
        a.storage(returner).await.ownership,
        MachineOwnership::Relocated { .. }
    ));
}

/// A return's replaced generation stays recoverable after the commit
/// transaction: replaying commit or abort retires exactly the recorded
/// directory and file identities, never a replacement or the current file.
#[tokio::test]
async fn return_commit_retires_replaced_generation_on_replay() {
    use std::os::unix::fs::MetadataExt;

    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("returning").await;
    let old = crate::machine::stopped::root_private(&a.storage(machine).await)
        .0
        .clone();
    let old_path = a.root_file(machine).await;
    complete(
        &a,
        &b,
        &approve(
            &a,
            &b,
            machine,
            &request(operation(), HandoffMode::Relocate),
        )
        .await,
    )
    .await;
    let back = operation();
    let plan = approve(&b, &a, machine, &request(back, HandoffMode::Relocate)).await;
    let (receipt, _, authorization) = complete(&b, &a, &plan).await;
    let current = crate::machine::stopped::root_private(&a.storage(machine).await)
        .0
        .clone();
    let current_path = a.root_file(machine).await;
    assert_ne!(current, old);
    assert!(!old_path.exists());
    let digest = a.root_digest(machine).await;
    let machine_dir = crate::paths::machine_data_dir_in(a.runtime.local_home(), machine);
    let identity = |path: &std::path::Path| {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        serde_json::json!({ "device": metadata.dev(), "inode": metadata.ino() })
    };
    let files =
        crate::handoff::files::OperationFiles::existing(a.runtime.local_home(), back).unwrap();
    let record =
        |directory: serde_json::Value, path: &crate::PrivatePath, file: serde_json::Value| {
            let record = serde_json::json!({
                "kind": "replaced",
                "machine": machine,
                "directory": directory,
                "files": [{ "path": path, "identity": file }],
            });
            files
                .store_cleanup(&serde_json::to_vec(&record).unwrap())
                .unwrap();
        };
    // A crash after the commit transaction, before retirement, leaves the
    // old generation and its unretired durable record behind.
    for replay in ["commit", "abort"] {
        std::fs::write(&old_path, b"replaced generation").unwrap();
        record(identity(&machine_dir), &old, identity(&old_path));
        let replayed = match replay {
            "commit" => a.service.commit(&authorization).await.unwrap(),
            _ => a.service.abort(&plan.intent().unwrap()).await.unwrap(),
        };
        assert_eq!(replayed, receipt);
        assert!(
            !old_path.exists(),
            "{replay} replay retires the old generation"
        );
        assert_eq!(a.root_digest(machine).await, digest);
    }
    // A different file now at the recorded name is preserved.
    std::fs::write(&old_path, b"recorded generation").unwrap();
    record(identity(&machine_dir), &old, identity(&old_path));
    let kept = old_path.with_extension("kept");
    std::fs::rename(&old_path, &kept).unwrap();
    std::fs::write(&old_path, b"a later file at the same name").unwrap();
    assert_eq!(a.service.commit(&authorization).await.unwrap(), receipt);
    assert_eq!(
        std::fs::read(&old_path).unwrap(),
        b"a later file at the same name"
    );
    // A record bound to another directory removes nothing here.
    record(
        identity(machine_dir.parent().unwrap()),
        &old,
        identity(&old_path),
    );
    assert_eq!(a.service.commit(&authorization).await.unwrap(), receipt);
    assert!(old_path.exists());
    // The catalog-selected generation is kept even if a record names it.
    record(identity(&machine_dir), &current, identity(&current_path));
    assert_eq!(a.service.commit(&authorization).await.unwrap(), receipt);
    assert_eq!(a.root_digest(machine).await, digest);
    assert_eq!(a.storage(machine).await.ownership, MachineOwnership::Owned);
}

/// Saved destination admission is rechecked: a required mapping removed
/// after preflight refuses prepare, and one removed after prepare refuses
/// commit, both as stale admission without publishing the machine.
#[tokio::test]
async fn removed_destination_mapping_is_stale_at_prepare_and_commit() {
    let a = participant().await;
    let b = participant().await;
    let machine = a.create_raw("mapped").await;
    let share = tempfile::tempdir().unwrap();
    let mut config = a.runtime.machine_config(machine).await.unwrap().unwrap();
    config.spec.mounts.push(vm_spec::Mount {
        source: share.path().to_path_buf(),
        tag: "data".into(),
        read_only: true,
    });
    a.runtime
        .native_store()
        .unwrap()
        .save_machine_config(&config)
        .await
        .unwrap();
    let targets = tempfile::tempdir().unwrap();
    let mapped = |op, path: PathBuf| {
        let mut mapped = request(op, HandoffMode::Relocate);
        mapped.resources = crate::ExternalResourcePolicy::Map {
            mappings: vec![crate::ExternalResourceMapping {
                resource: crate::ExternalResourceKey::Share { tag: "data".into() },
                path,
            }],
        };
        mapped
    };

    let first = targets.path().join("first");
    std::fs::create_dir(&first).unwrap();
    let op = operation();
    let plan = approve(&a, &b, machine, &mapped(op, first.clone())).await;
    let (offer, _) = offered(&a, &b, &plan).await;
    std::fs::remove_dir(&first).unwrap();
    let stale = b.service.prepare(offer.binding()).await.unwrap_err();
    assert!(matches!(
        handoff_error(&stale),
        Some(HandoffError::AdmissionStale)
    ));
    assert_eq!(
        b.service.status(op).await.unwrap().unwrap().phase,
        HandoffPhase::Receiving
    );
    let aborted = b.service.abort(&plan.intent().unwrap()).await.unwrap();
    a.service.resolve_source(&aborted).await.unwrap();

    let second = targets.path().join("second");
    std::fs::create_dir(&second).unwrap();
    let op = operation();
    let plan = approve(&a, &b, machine, &mapped(op, second.clone())).await;
    let (prepared, _) = prepare(&a, &b, &plan).await;
    let authorization = a.service.fence_source(&prepared).await.unwrap();
    std::fs::remove_dir(&second).unwrap();
    let stale = b.service.commit(&authorization).await.unwrap_err();
    assert!(matches!(
        handoff_error(&stale),
        Some(HandoffError::AdmissionStale)
    ));
    assert!(b.runtime.machine_config(machine).await.unwrap().is_none());
    assert_eq!(
        b.service.status(op).await.unwrap().unwrap().phase,
        HandoffPhase::Prepared
    );
    let aborted = b.service.abort(&plan.intent().unwrap()).await.unwrap();
    a.service.resolve_source(&aborted).await.unwrap();
    assert_eq!(a.storage(machine).await.ownership, MachineOwnership::Owned);
}

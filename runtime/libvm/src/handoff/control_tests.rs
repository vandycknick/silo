//! Real catalog/file regressions for independent handoff participants.
#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

use crate::handoff::chunks::extents;
use crate::handoff::files::{DocumentName, OperationFiles};
use crate::handoff::plan::{PayloadDescriptor, SourceStop, MAX_FRAME_BYTES};
use crate::handoff::service::HandoffService;
use crate::handoff::source::SourceIndex;
use crate::handoff::tests::{approve, operation, participant, request, Participant};
use crate::handoff::types::{HandoffMode, HandoffPhase, OperationId};
use crate::paths::OwnedDirectory;
use crate::storage::locks::StorageLock;
use crate::storage::stream::Chunk;
use crate::store::MachineStore;
use crate::{DiskStorage, IncludedDisk, MachineId, MachineOwnership, PrivatePath};

/// A real managed disk provides a lockable barrier between reservation and
/// sealing, without substituting any participant or storage implementation.
async fn add_managed_disk(source: &Participant, machine: MachineId) -> uuid::Uuid {
    let mut config = source
        .runtime
        .machine_config(machine)
        .await
        .unwrap()
        .unwrap();
    let mut storage = source.storage(machine).await;
    let path = config.machine_dir.join("data.raw");
    std::fs::write(&path, [0x91; 1024]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    config.spec.storage.as_mut().unwrap().disks.push(
        crate::machine::root_storage::disk(
            "data.raw",
            vm_spec::DiskRole::Data,
            1024,
            "silo-data-0".into(),
        )
        .unwrap(),
    );
    let id = uuid::Uuid::new_v4();
    storage.disks.push(IncludedDisk {
        id,
        role: vm_spec::DiskRole::Data,
        order: 1,
        storage: DiskStorage::ManagedWritable {
            path: PrivatePath::new("data.raw").unwrap(),
            geometry: vm_spec::DiskGeometry {
                length: 1024,
                logical_sector_size: 512,
            },
        },
    });
    source
        .runtime
        .native_store()
        .unwrap()
        .save_machine_config_with_storage(&config, &storage)
        .await
        .unwrap();
    id
}

fn hold_managed_disk(source: &Participant, disk: uuid::Uuid) -> StorageLock {
    let directory = OwnedDirectory::open_root(&source.runtime.local_home().join("locks"))
        .unwrap()
        .ensure_dir("managed-disks")
        .unwrap();
    crate::storage::locks::blocking(
        &directory,
        &format!("{disk}.lock"),
        nix::fcntl::FlockArg::LockExclusive,
    )
    .unwrap()
}

async fn wait_phase(service: &HandoffService, operation: OperationId, phase: HandoffPhase) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if service.status(operation).await.unwrap().unwrap().phase == phase {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn independent_captures_replay_one_durable_manifest() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("one-cut").await;
    let disk = add_managed_disk(&source, machine).await;
    let plan = approve(
        &source,
        &destination,
        machine,
        &request(operation(), HandoffMode::Relocate),
    )
    .await;
    let operation = plan.plan().operation();
    source.service.begin_source(&plan).await.unwrap();
    let barrier = hold_managed_disk(&source, disk);
    let first = tokio::spawn({
        let service = source.service.clone();
        let plan = plan.clone();
        async move {
            service
                .capture_source(&plan, SourceStop::RequireStopped)
                .await
        }
    });
    wait_phase(&source.service, operation, HandoffPhase::Reserved).await;
    let mut second = tokio::spawn({
        let service = HandoffService::new(source.runtime.clone());
        let plan = plan.clone();
        async move {
            service
                .capture_source(&plan, SourceStop::RequireStopped)
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut second)
            .await
            .is_err()
    );
    drop(barrier);
    let first = tokio::time::timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.binding(), second.binding());
    assert_eq!(first.manifest().document(), second.manifest().document());
    let source = source.restart().await;
    let replay = source
        .service
        .capture_source(&plan, SourceStop::RequireStopped)
        .await
        .unwrap();
    assert_eq!(first.binding(), replay.binding());
    assert_eq!(first.manifest().document(), replay.manifest().document());
    let record = source.service.status(operation).await.unwrap().unwrap();
    assert_eq!(record.binding.as_ref(), Some(replay.binding()));
    let files = OperationFiles::existing(source.runtime.local_home(), operation).unwrap();
    assert_eq!(
        files
            .load_document(DocumentName::Manifest)
            .unwrap()
            .unwrap(),
        *replay.manifest().document(),
    );
}

#[tokio::test]
async fn cancelled_capture_keeps_reservation_until_abort_can_serialize() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("abort-after-cut").await;
    let disk = add_managed_disk(&source, machine).await;
    let plan = approve(
        &source,
        &destination,
        machine,
        &request(operation(), HandoffMode::Relocate),
    )
    .await;
    let operation = plan.plan().operation();
    source.service.begin_source(&plan).await.unwrap();
    destination.service.receive(&plan).await.unwrap();
    let receipt = destination
        .service
        .abort(&plan.intent().unwrap())
        .await
        .unwrap();
    let lock_path = source
        .runtime
        .local_home()
        .join("handoff")
        .join(operation.to_string())
        .join("operation.lock");
    let identity = std::fs::metadata(&lock_path).unwrap();
    let barrier = hold_managed_disk(&source, disk);
    let capture = tokio::spawn({
        let service = source.service.clone();
        let plan = plan.clone();
        async move {
            service
                .capture_source(&plan, SourceStop::RequireStopped)
                .await
        }
    });
    wait_phase(&source.service, operation, HandoffPhase::Reserved).await;
    capture.abort();
    assert!(capture.await.unwrap_err().is_cancelled());
    let mut resolution = tokio::spawn({
        let service = HandoffService::new(source.runtime.clone());
        async move { service.resolve_source(&receipt).await }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut resolution)
            .await
            .is_err()
    );
    assert_eq!(
        source.storage(machine).await.ownership,
        MachineOwnership::Reserved { operation },
    );
    assert_eq!(
        source
            .service
            .status(operation)
            .await
            .unwrap()
            .unwrap()
            .phase,
        HandoffPhase::Reserved,
    );
    drop(barrier);
    let resolved = tokio::time::timeout(Duration::from_secs(10), resolution)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(resolved.phase, HandoffPhase::Aborted);
    assert!(
        resolved.binding.is_some(),
        "detached capture must seal before abort"
    );
    assert_eq!(
        source.storage(machine).await.ownership,
        MachineOwnership::Owned
    );
    let files = OperationFiles::existing(source.runtime.local_home(), operation).unwrap();
    assert!(files
        .load_document(DocumentName::Manifest)
        .unwrap()
        .is_some());
    let after = std::fs::metadata(&lock_path).unwrap();
    assert_eq!((identity.dev(), identity.ino()), (after.dev(), after.ino()));
    let operation_directory = lock_path.parent().unwrap();
    assert!(!operation_directory.join("maps").exists());
    assert!(!operation_directory.join("staging").exists());
}

#[tokio::test]
async fn warm_and_cold_chunks_require_exact_authorized_length() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("exact-chunk").await;
    add_managed_disk(&source, machine).await;
    let plan = approve(
        &source,
        &destination,
        machine,
        &request(operation(), HandoffMode::Fork),
    )
    .await;
    let operation = plan.plan().operation();
    let offer = source
        .service
        .capture_source(&plan, SourceStop::RequireStopped)
        .await
        .unwrap();
    let data = offer
        .manifest()
        .body()
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                crate::handoff::plan::WritableRole::Disk { order: 1 }
            )
        })
        .unwrap();
    let files = OperationFiles::existing(source.runtime.local_home(), operation).unwrap();
    let map = files.load_map(&data.stream).unwrap().unwrap();
    let (_, length, Chunk::Data(digest)) = extents(&map).next().unwrap() else {
        panic!("managed data must produce a nonzero chunk");
    };
    let descriptor = PayloadDescriptor::Chunk { digest, length };
    let frame = source
        .service
        .read_payload(operation, descriptor, 0, 17)
        .await
        .unwrap();
    assert_eq!(frame.bytes, [0x91; 17]);
    assert_eq!(frame.total_length, length);
    assert!(!frame.end);
    let index = SourceIndex::build(&source.runtime, operation).unwrap();
    for wrong_length in [1, length + 1] {
        let wrong = PayloadDescriptor::Chunk {
            digest,
            length: wrong_length,
        };
        let cold = HandoffService::new(source.runtime.clone());
        assert!(cold
            .read_payload(operation, wrong, 0, MAX_FRAME_BYTES)
            .await
            .is_err());
        assert!(source
            .service
            .read_payload(operation, wrong, 0, MAX_FRAME_BYTES)
            .await
            .is_err());
        // Membership is enforced inside the index even when bytes are cached.
        assert!(index
            .frame(
                &source.runtime,
                wrong,
                0,
                1,
                Some(std::sync::Arc::new(vec![0x91; length as usize]))
            )
            .await
            .is_err());
    }
    let tail = source
        .service
        .read_payload(operation, descriptor, length - 17, 17)
        .await
        .unwrap();
    assert_eq!(tail.bytes, [0x91; 17]);
    assert!(tail.end);
}

#[tokio::test]
async fn pending_map_writer_cannot_recreate_bulk_files_after_abort() {
    let source = participant().await;
    let destination = participant().await;
    let machine = source.create_raw("late-map").await;
    let plan = approve(
        &source,
        &destination,
        machine,
        &request(operation(), HandoffMode::Fork),
    )
    .await;
    let operation = plan.plan().operation();
    let offer = source
        .service
        .capture_source(&plan, SourceStop::RequireStopped)
        .await
        .unwrap();
    destination.service.receive(&plan).await.unwrap();
    destination.service.offer_capture(&offer).await.unwrap();
    let descriptor = PayloadDescriptor::StreamMap {
        stream: offer.manifest().body().files[0].stream,
    };
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
        writer.write_frame(&frame.bytes).unwrap();
        offset += frame.bytes.len() as u64;
        if frame.end {
            break;
        }
    }
    let independent = HandoffService::new(destination.runtime.clone());
    independent.abort(&plan.intent().unwrap()).await.unwrap();
    assert!(writer.finish().await.is_err());
    assert!(destination
        .service
        .open_payload(operation, descriptor)
        .await
        .is_err());
    assert!(destination
        .service
        .list_needs(operation, None, 16)
        .await
        .is_err());
    let directory = destination
        .runtime
        .local_home()
        .join("handoff")
        .join(operation.to_string());
    assert!(!directory.join("maps").exists());
    assert!(!directory.join("staging").exists());
}

//! Retained actual backing inodes and durable attachment-owner provenance.
//!
//! All Raw disks (root, upper and Data, including read-only attachments) are
//! opened before worker configuration is released. The worker uses checked
//! duplicates at FD 9+ and opens native devices through descriptor-derived
//! paths, so replacing an original pathname cannot redirect writes or fsync.
//! The generated read-only VMDK descriptor remains retained with the closure
//! lease; its immutable extents remain rooted by the launch operation.
//!
//! Finalization is allowed only after the actual worker reaper completes.
//! The blocking owner retains the same OFD lease while synchronizing every
//! writable Raw and explicitly checking every close. Cancellation of a waiter
//! cannot release that ownership. Darwin, VZ, writable shares and incomplete
//! attachment coverage cannot obtain this Linux Raw certificate.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::sync::Arc;

use protocol::shutdown::RawHandleBinding;

use crate::virt::backend::StorageFinalization;
use crate::virt::config::{StorageLaunch, VmConfig};

pub(crate) fn publish_holders(config: &VmConfig, worker: Option<u32>) -> io::Result<()> {
    let Some(launch) = config.storage_launch() else {
        return Ok(());
    };
    let context = worker_context(launch, Vec::new());
    crate::krun::storage_holder::publish(&launch.holder_path, &context, worker)
}

pub(crate) struct RetainedAttachment {
    file: File,
    disk_index: u32,
    writable: bool,
    device: u64,
    inode: u64,
}

pub(crate) struct PreparedAttachments {
    attachments: Vec<RetainedAttachment>,
    pub(crate) raw_bindings: Vec<RawHandleBinding>,
    // This duplicate stays with blocking finalization even if its async waiter dies.
    _lease: Arc<OwnedFd>,
    flush_qualified: bool,
    closure_qualified: bool,
    #[cfg(test)]
    finalization_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

impl PreparedAttachments {
    pub(crate) fn open(config: &VmConfig) -> io::Result<Self> {
        let launch = config
            .storage_launch()
            .ok_or_else(|| io::Error::other("managed launch lacks its storage lease"))?;
        vm_spec::Storage::validate_disks(config.disks()).map_err(io::Error::other)?;
        let (soft, hard) =
            nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?;
        // The manager preflights every generated FLAT record plus this reserve;
        // recheck the inherited reserve before allocating monitor proof copies
        // and the bounded transient child mapping table.
        if soft < 256 {
            return Err(io::Error::other(format!(
                "attachment FD reserve requires 256, soft {soft}, hard {hard}"
            )));
        }
        let mut prepared = Self {
            attachments: Vec::with_capacity(config.disks().len()),
            raw_bindings: Vec::with_capacity(config.disks().len()),
            _lease: launch.lease.clone(),
            flush_qualified: cfg!(target_os = "linux")
                && !config.disks().is_empty()
                && config.mounts().iter().all(|mount| mount.read_only),
            // On Linux all native block/virtiofs owners are threads in the
            // reaped worker. Writer coverage and flush semantics do not change
            // the independently observed process-owned descriptor closure.
            closure_qualified: cfg!(target_os = "linux")
                && (!config.disks().is_empty() || !config.mounts().is_empty()),
            #[cfg(test)]
            finalization_gate: None,
        };
        for (index, disk) in config.disks().iter().enumerate() {
            let raw = disk.format == vm_spec::DiskFormat::Raw;
            let file = OpenOptions::new()
                .read(true)
                .write(!disk.read_only)
                .custom_flags((nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK).bits())
                .open(&disk.path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file()
                && !metadata.file_type().is_block_device()
                && !metadata.file_type().is_char_device()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "attachment is not a regular file or raw device",
                ));
            }
            let flags = nix::fcntl::OFlag::from_bits_truncate(nix::fcntl::fcntl(
                &file,
                nix::fcntl::FcntlArg::F_GETFL,
            )?);
            nix::fcntl::fcntl(
                &file,
                nix::fcntl::FcntlArg::F_SETFL(flags & !nix::fcntl::OFlag::O_NONBLOCK),
            )?;
            // Raw host devices retain existing runtime support, but cannot certify
            // the regular-file Imago proof. Geometry is checked for regular Raw.
            if !metadata.is_file() {
                prepared.flush_qualified = false;
            }
            if raw && metadata.is_file() && metadata.len() != disk.geometry.length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Raw disk #{index} length differs from launch geometry"),
                ));
            }
            if !raw && !disk.read_only {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-Raw writable attachment is unsupported",
                ));
            }
            if raw {
                prepared.raw_bindings.push(RawHandleBinding {
                    disk_index: index as u32,
                    child_fd: 9 + prepared.raw_bindings.len() as i32,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    length_bytes: disk.geometry.length,
                    read_only: disk.read_only,
                });
            }
            prepared.attachments.push(RetainedAttachment {
                file,
                disk_index: index as u32,
                writable: !disk.read_only,
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }
        Ok(prepared)
    }

    pub(crate) fn worker_handles(&self) -> io::Result<Vec<OwnedFd>> {
        self.raw_bindings
            .iter()
            .map(|binding| {
                let attachment = self
                    .attachments
                    .get(binding.disk_index as usize)
                    .ok_or_else(|| io::Error::other("invalid retained disk index"))?;
                attachment.file.try_clone().map(OwnedFd::from)
            })
            .collect()
    }

    /// Duplicates of every retained attachment for a live capture's disk
    /// seal. The capture only reads them; identity is the retained inode.
    pub(crate) fn capture_sources(&self) -> io::Result<Vec<crate::virt::backend::CaptureSource>> {
        self.attachments
            .iter()
            .map(|attachment| {
                Ok(crate::virt::backend::CaptureSource {
                    disk_index: attachment.disk_index,
                    file: attachment.file.try_clone()?,
                    writable: attachment.writable,
                })
            })
            .collect()
    }

    /// Caller has reaped every native owner. Every handle is explicitly closed,
    /// including after a failed sync; first errors are sticky, later ones logged.
    pub(crate) fn finish(self, guest_completed: bool) -> StorageFinalization {
        #[cfg(test)]
        if let Some((entered, release)) = &self.finalization_gate {
            let _ = entered.send(());
            let _ = release.recv();
        }
        let mut report = StorageFinalization::default();
        let mut sync_ok = true;
        let mut close_ok = true;
        for attachment in self.attachments {
            if attachment.writable {
                tracing::info!(
                    disk_index = attachment.disk_index,
                    backing_fd = attachment.file.as_raw_fd(),
                    file_device = attachment.device,
                    file_inode = attachment.inode,
                    "synchronizing retained Raw attachment"
                );
                if let Err(error) = attachment.file.sync_all() {
                    sync_ok = false;
                    record_error(
                        &mut report,
                        format!("sync retained Raw disk #{}: {error}", attachment.disk_index),
                    );
                }
            }
            if let Err(error) = nix::unistd::close(attachment.file) {
                close_ok = false;
                record_error(
                    &mut report,
                    format!("close retained disk #{}: {error}", attachment.disk_index),
                );
            }
        }
        report.host_writes_flushed = self.flush_qualified && guest_completed && sync_ok;
        report.attachments_closed = self.closure_qualified && close_ok;
        report
    }
}

fn record_error(report: &mut StorageFinalization, error: String) {
    tracing::error!(%error, "storage attachment finalization failed");
    report.error.get_or_insert(error);
}

pub(crate) fn worker_context(
    launch: &StorageLaunch,
    raw_handles: Vec<RawHandleBinding>,
) -> protocol::shutdown::WorkerStorageContext {
    protocol::shutdown::WorkerStorageContext {
        version: 1,
        machine_id: launch.machine_id.clone(),
        run_id: launch.run_id.clone(),
        storage_lease: launch.binding.clone(),
        raw_handles,
    }
}

pub(crate) fn spawn_finalization(
    prepared: Option<PreparedAttachments>,
    completion: tokio::sync::watch::Sender<Option<StorageFinalization>>,
    guest_completed: bool,
) {
    tokio::task::spawn_blocking(move || {
        let report = prepared
            .map(|owner| owner.finish(guest_completed))
            .unwrap_or_default();
        completion.send_replace(Some(report));
    });
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::virt::backend::storage::{
        spawn_finalization, PreparedAttachments, RetainedAttachment,
    };
    use crate::virt::config::{StorageLaunch, VmConfig};

    struct Fixture {
        directory: PathBuf,
        config: VmConfig,
    }

    impl Fixture {
        #[allow(deprecated)]
        fn new() -> Self {
            let directory =
                std::env::temp_dir().join(format!("silo-retained-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&directory).expect("create fixture");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .expect("private fixture");
            let lease = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join("generation.lease"))
                .expect("lease");
            nix::fcntl::flock(lease.as_raw_fd(), nix::fcntl::FlockArg::LockSharedNonblock)
                .expect("shared lease");
            let metadata = lease.metadata().expect("lease metadata");
            let launch = StorageLaunch {
                machine_id: "11111111-1111-4111-8111-111111111111".to_string(),
                run_id: "22222222-2222-4222-8222-222222222222".to_string(),
                binding: protocol::shutdown::StorageLeaseBinding {
                    operation_id: "33333333-3333-4333-8333-333333333333".to_string(),
                    file_device: metadata.dev(),
                    file_inode: metadata.ino(),
                },
                lease: Arc::new(OwnedFd::from(lease)),
                holder_path: directory.join("vm.storage-holder.json"),
            };
            let mut builder = VmConfig::builder("retained").base_directory(&directory);
            for (index, read_only) in [false, false, true].into_iter().enumerate() {
                let path = directory.join(format!("disk-{index}.raw"));
                File::create(&path)
                    .expect("disk")
                    .set_len(4096)
                    .expect("disk geometry");
                builder = builder.disk(vm_spec::Disk {
                    path,
                    role: if index == 0 {
                        vm_spec::DiskRole::Root
                    } else {
                        vm_spec::DiskRole::Data
                    },
                    format: vm_spec::DiskFormat::Raw,
                    geometry: vm_spec::DiskGeometry {
                        length: 4096,
                        logical_sector_size: 512,
                    },
                    block_id: vm_spec::BlockId::new(format!("disk-{index}")).expect("block ID"),
                    read_only,
                });
            }
            Self {
                directory,
                config: builder.build().with_storage_launch(launch),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacement_cannot_redirect_any_writable_raw_backing() {
        let fixture = Fixture::new();
        let prepared = PreparedAttachments::open(&fixture.config).expect("retain disks");
        let handles = prepared.worker_handles().expect("checked duplicates");
        assert_eq!(handles.len(), 3, "include read-only Data lifetime");
        for (index, handle) in handles.iter().enumerate().take(2) {
            let original = &fixture.config.disks()[index].path;
            let pinned_name = original.with_extension("retained");
            std::fs::rename(original, &pinned_name).expect("replace pathname");
            File::create(original)
                .expect("replacement")
                .set_len(4096)
                .expect("replacement length");
            let native_path = PathBuf::from("/proc/self/fd").join(handle.as_raw_fd().to_string());
            let native = OpenOptions::new()
                .read(true)
                .write(true)
                .open(native_path)
                .expect("native FD-derived open");
            native.write_all_at(b"pinned", 0).expect("native write");
            let mut bytes = [0; 6];
            File::open(&pinned_name)
                .expect("retained inode")
                .read_exact_at(&mut bytes, 0)
                .expect("read pinned");
            assert_eq!(&bytes, b"pinned");
            File::open(original)
                .expect("replacement inode")
                .read_exact_at(&mut bytes, 0)
                .expect("read replacement");
            assert_eq!(bytes, [0; 6]);
        }
        drop(handles);
        let report = prepared.finish(true);
        assert!(report.host_writes_flushed);
        assert!(report.attachments_closed);
        assert!(report.error.is_none());
    }

    #[test]
    fn crash_sync_does_not_claim_guest_ordered_host_flush() {
        let fixture = Fixture::new();
        let report = PreparedAttachments::open(&fixture.config)
            .expect("retain")
            .finish(false);
        assert!(!report.host_writes_flushed);
        assert_eq!(report.attachments_closed, cfg!(target_os = "linux"));
    }

    #[test]
    fn actual_sync_failure_preserves_error_and_still_checks_close() {
        let fixture = Fixture::new();
        let mut prepared = PreparedAttachments::open(&fixture.config).expect("retain");
        let (pipe, _write) = nix::unistd::pipe().expect("real nonsyncable descriptor");
        prepared.attachments[1] = RetainedAttachment {
            file: File::from(pipe),
            disk_index: 1,
            writable: true,
            device: 0,
            inode: 0,
        };
        let report = prepared.finish(true);
        assert!(!report.host_writes_flushed);
        assert_eq!(report.attachments_closed, cfg!(target_os = "linux"));
        assert!(report
            .error
            .expect("actual fsync error")
            .contains("sync retained Raw disk #1"));
    }

    #[test]
    fn writable_share_refuses_flush_certification_without_erasing_actual_closure() {
        let fixture = Fixture::new();
        let mut builder = VmConfig::builder("writable-share")
            .base_directory(&fixture.directory)
            .mount(crate::virt::config::SharedDirectory {
                host_path: fixture.directory.clone(),
                tag: "writable".to_string(),
                read_only: false,
            });
        for disk in fixture.config.disks() {
            builder = builder.disk(disk.clone());
        }
        let config = builder
            .build()
            .with_storage_launch(fixture.config.storage_launch().expect("launch").clone());
        let report = PreparedAttachments::open(&config)
            .expect("retain complete coverage")
            .finish(true);
        assert!(!report.host_writes_flushed);
        assert_eq!(report.attachments_closed, cfg!(target_os = "linux"));
        assert!(report.error.is_none());
    }

    #[test]
    fn unqualified_raw_device_does_not_erase_actual_closure() {
        let fixture = Fixture::new();
        let mut disk = fixture.config.disks()[0].clone();
        disk.path = "/dev/null".into();
        let config = VmConfig::builder("raw-device")
            .base_directory(&fixture.directory)
            .disk(disk)
            .build()
            .with_storage_launch(fixture.config.storage_launch().expect("launch").clone());
        let report = PreparedAttachments::open(&config)
            .expect("retain character device")
            .finish(true);
        assert!(!report.host_writes_flushed);
        assert_eq!(report.attachments_closed, cfg!(target_os = "linux"));
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn cancelling_waiter_does_not_release_blocking_finalizer_lease() {
        let mut fixture = Fixture::new();
        let mut prepared = PreparedAttachments::open(&fixture.config).expect("retain");
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.directory.join("generation.lease"))
            .expect("independent probe");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        prepared.finalization_gate = Some((entered_tx, release_rx));
        let (completion, mut observation) = tokio::sync::watch::channel(None);
        spawn_finalization(Some(prepared), completion, true);
        tokio::task::spawn_blocking(move || entered_rx.recv().expect("finalizer entered"))
            .await
            .expect("entry observer");
        let mut cancelled_observation = observation.clone();
        let waiter = tokio::spawn(async move { cancelled_observation.changed().await });
        waiter.abort();
        let _ = waiter.await;
        // Drop every other reference to the shared OFD. Only finalizer remains.
        fixture.config = VmConfig::default();
        assert_eq!(
            nix::fcntl::flock(
                probe.as_raw_fd(),
                nix::fcntl::FlockArg::LockExclusiveNonblock
            ),
            Err(nix::errno::Errno::EWOULDBLOCK)
        );
        release_tx.send(()).expect("release finalizer");
        observation.changed().await.expect("completed report");
        assert!(observation
            .borrow()
            .as_ref()
            .expect("report")
            .error
            .is_none());
        nix::fcntl::flock(
            probe.as_raw_fd(),
            nix::fcntl::FlockArg::LockExclusiveNonblock,
        )
        .expect("lease released after completion");
    }
}

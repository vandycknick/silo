//! Normal-worker restore bootstrap: adopt the inherited state objects and
//! lower closure, inspect the exact seal against this host, construct every
//! destination resource and enter `engine::run_restore_process`. Prepared is
//! reported only after native install and lifecycle service; never started.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libkrun::live::inspection::AdmittedDeviceKind;
use libkrun::live::restore::{
    RestoreBlock, RestoreConsole, RestoreConsolePort, RestoreInputs, RestoreNetwork,
    RestoreResources, RestoreVsock, VmdkExtent,
};
use vm_spec::restore::RestoreRequest;

use crate::krun::engine::{self, RestoreProcessError};
use crate::krun::worker::lifecycle::{self, RestoreAuthority};
use crate::krun::worker::wire::{self, Event};
use crate::krun::worker::{
    emit, fds, native, serve_diagnostics, start_status_reporter, EventWriter,
};
use crate::krun::{KrunConfig, Network};
use crate::virt::exit::StartupStage;

/// Native construction budget, including the destination host probe.
const CONSTRUCTION_BUDGET: Duration = Duration::from_secs(120);
/// Bounded settlement of a retained failed native owner.
const CLEANUP_BUDGET: Duration = Duration::from_secs(5);

pub(crate) struct Launch<'a> {
    pub(crate) config: &'a KrunConfig,
    pub(crate) request: RestoreRequest,
    pub(crate) state: fds::RestoreStateFiles,
    pub(crate) lowers: Vec<File>,
    pub(crate) raw_handles: &'a [OwnedFd],
    pub(crate) console: &'a OwnedFd,
    pub(crate) mux: Option<OwnedFd>,
    pub(crate) lifecycle: OwnedFd,
    pub(crate) binding: lifecycle::Binding,
    pub(in crate::krun::worker) events: &'a Arc<Mutex<EventWriter>>,
    pub(crate) stage: &'a mut StartupStage,
}

fn invalid(message: impl Into<String>) -> eyre::Report {
    eyre::eyre!(message.into())
}

fn same(file: &File, device: u64, inode: u64, length: u64) -> eyre::Result<()> {
    let metadata = file.metadata()?;
    if metadata.dev() != device || metadata.ino() != inode || metadata.len() != length {
        return Err(invalid(
            "inherited restore role differs from its sealed identity",
        ));
    }
    Ok(())
}

/// The worker config is the destination launch: its projection must be the
/// captured configuration, never a reinterpretation of the source.
pub(crate) fn validate(config: &KrunConfig, request: &RestoreRequest) -> eyre::Result<bool> {
    request.validate().map_err(invalid)?;
    let captured = &request.configuration;
    let disks_match = config.disks.len() == captured.attachments.len()
        && config
            .disks
            .iter()
            .zip(&captured.attachments)
            .all(|(disk, attachment)| {
                disk.block_id == attachment.block_id
                    && disk.role == attachment.role
                    && disk.format == attachment.format
                    && disk.geometry == attachment.geometry
                    && disk.read_only == attachment.read_only
            });
    if config.cpus != captured.cpus
        || config.memory_mib != captured.memory_mib
        || captured.nested_virtualization
        || captured.rosetta
        || !captured.shares.is_empty()
        || !captured.vsock
        || !disks_match
        || !config.mounts.is_empty()
        || config.rosetta.is_some()
        || config.vsock_cid.is_some()
        || !config.vsock_mux
        || !config.stdio_console
        || !config.balloon
    {
        return Err(invalid(
            "restore launch configuration differs from the captured cut",
        ));
    }
    match (&config.network, &request.network) {
        (Network::None, None) => Ok(false),
        (Network::Unixgram(net), Some(destination))
            if destination
                .mac
                .split(':')
                .zip(net.mac)
                .all(|(part, octet)| u8::from_str_radix(part, 16).ok() == Some(octet)) =>
        {
            Ok(true)
        }
        _ => Err(invalid(
            "restore launch network differs from the destination binding",
        )),
    }
}

/// Inherited lowers in table order: per request lower, descriptor then extents.
fn lower_blocks(
    request: &RestoreRequest,
    lowers: Vec<File>,
) -> eyre::Result<Vec<(String, File, Vec<VmdkExtent>)>> {
    let expected: usize = request
        .lowers
        .iter()
        .map(|lower| 1 + lower.extents.len())
        .sum();
    if expected != lowers.len() {
        return Err(invalid("restore lower roles differ from the lower closure"));
    }
    let mut files = lowers.into_iter();
    let mut next = || {
        files
            .next()
            .ok_or_else(|| invalid("restore lower role is missing"))
    };
    let mut blocks = Vec::with_capacity(request.lowers.len());
    for lower in &request.lowers {
        let descriptor = next()?;
        let identity = &lower.descriptor;
        same(
            &descriptor,
            identity.file_device,
            identity.file_inode,
            identity.length,
        )?;
        let mut extents = Vec::with_capacity(lower.extents.len());
        for extent in &lower.extents {
            let file = next()?;
            same(&file, extent.file_device, extent.file_inode, extent.length)?;
            extents.push(VmdkExtent {
                path: PathBuf::from(&extent.path),
                file,
            });
        }
        blocks.push((lower.block_id.as_str().to_string(), descriptor, extents));
    }
    Ok(blocks)
}

/// Destination roles a restore consumes or borrows from the bootstrap.
struct Roles<'a> {
    config: &'a KrunConfig,
    request: &'a RestoreRequest,
    lowers: Vec<File>,
    raw_handles: &'a [OwnedFd],
    console: &'a OwnedFd,
    mux: Option<OwnedFd>,
}

fn resources(
    roles: Roles<'_>,
    shape: &libkrun::live::inspection::AdmittedShape,
) -> eyre::Result<RestoreResources> {
    let Roles {
        config,
        request,
        lowers,
        raw_handles,
        console,
        mut mux,
    } = roles;
    let mut vmdk = lower_blocks(request, lowers)?;
    let mut resources = RestoreResources::default();
    for device in shape.devices() {
        let attachment = device.attachment().clone();
        match device.kind() {
            AdmittedDeviceKind::Block(_) => {
                let index = config
                    .disks
                    .iter()
                    .position(|disk| disk.block_id.as_str() == attachment.configured_id)
                    .ok_or_else(|| invalid("restored block has no destination disk"))?;
                let disk = &config.disks[index];
                match disk.format {
                    vm_spec::DiskFormat::Raw => {
                        let slot = config
                            .storage_context
                            .raw_handles
                            .iter()
                            .position(|binding| binding.disk_index as usize == index)
                            .ok_or_else(|| invalid("restored Raw disk has no backing role"))?;
                        let file = File::from(
                            raw_handles
                                .get(slot)
                                .ok_or_else(|| invalid("restored Raw backing role is missing"))?
                                .try_clone()?,
                        );
                        resources
                            .blocks
                            .push(RestoreBlock::raw(attachment, file, disk.read_only));
                    }
                    vm_spec::DiskFormat::Vmdk => {
                        let position = vmdk
                            .iter()
                            .position(|(block, _, _)| *block == attachment.configured_id)
                            .ok_or_else(|| invalid("restored VMDK has no lower closure"))?;
                        let (_, descriptor, extents) = vmdk.swap_remove(position);
                        resources
                            .blocks
                            .push(RestoreBlock::readonly_vmdk(attachment, descriptor, extents));
                    }
                }
            }
            AdmittedDeviceKind::Network { .. } => {
                let Network::Unixgram(net) = &config.network else {
                    return Err(invalid("restored network has no destination socket"));
                };
                let socket = crate::krun::network::open_local_unix_datagram_socket(
                    &net.peer_path,
                    &config.id,
                    "krun",
                )?;
                resources.networks.push(RestoreNetwork {
                    attachment,
                    socket,
                    mac: net.mac,
                });
            }
            AdmittedDeviceKind::Vsock { .. } => {
                let mux = mux
                    .take()
                    .ok_or_else(|| invalid("restored vsock has no mux role"))?;
                resources.vsocks.push(RestoreVsock {
                    attachment,
                    mux,
                    cid: engine::GUEST_CID,
                    agent_port: NonZeroU32::new(crate::guest::GUEST_CONTROL_PORT)
                        .ok_or_else(|| invalid("agent control port is zero"))?,
                });
            }
            AdmittedDeviceKind::Console { .. } => {
                let (name, input, output, terminal) = crate::krun::restore::CONSOLE_PORT;
                let port = |present: bool| -> eyre::Result<Option<File>> {
                    if present {
                        Ok(Some(File::from(console.as_fd().try_clone_to_owned()?)))
                    } else {
                        Ok(None)
                    }
                };
                resources.consoles.push(RestoreConsole {
                    attachment,
                    ports: vec![RestoreConsolePort {
                        name: name.to_string(),
                        input: port(input)?,
                        output: port(output)?,
                        terminal,
                    }],
                });
            }
            AdmittedDeviceKind::Rng
            | AdmittedDeviceKind::Balloon
            | AdmittedDeviceKind::Generation => {}
        }
    }
    if !vmdk.is_empty() {
        return Err(invalid(
            "restore lower closure names a block that was not captured",
        ));
    }
    Ok(resources)
}

/// Settle a retained failed native owner. An owner that does not reach
/// native terminality is kept alive until process exit: an accepted native
/// user must never observe freed RAM.
fn settle(failed: libkrun::live::restore::FailedRestore<'_>) {
    if let Err(retained) = failed.cleanup(Instant::now() + CLEANUP_BUDGET) {
        std::mem::forget(retained);
    }
}

pub(crate) fn run(launch: Launch<'_>) -> eyre::Result<()> {
    let Launch {
        config,
        request,
        state,
        lowers,
        raw_handles,
        console,
        mux,
        lifecycle: endpoint,
        binding,
        events,
        stage,
    } = launch;
    let network = validate(config, &request)?;
    let fds::RestoreStateFiles {
        ram,
        layout,
        execution,
        devices,
        ram_map,
    } = state;
    for (file, object) in [&ram, &layout, &execution, &devices, &ram_map]
        .into_iter()
        .zip(&request.objects)
    {
        same(file, object.file_device, object.file_inode, object.length)?;
    }
    let inherited_map = crate::restore::inputs::verified_ram_map(&request, &ram_map)?;
    let inherited_layout = request
        .evidence
        .memory
        .as_ref()
        .ok_or_else(|| invalid("restore lacks RAM evidence"))?
        .binding
        .ram_layout;
    let deadline = Instant::now() + CONSTRUCTION_BUDGET;
    let shape = crate::krun::restore::inspect(
        &request,
        network,
        crate::krun::restore::StateObjects {
            layout: &layout,
            execution: &execution,
            devices: &devices,
        },
        deadline,
    )?;
    let (expected, _) = crate::krun::restore::identity(&request)?;
    let resources = resources(
        Roles {
            config,
            request: &request,
            lowers,
            raw_handles,
            console,
            mux,
        },
        &shape,
    )?;
    let activation = uuid::Uuid::parse_str(request.activation_id.as_str())
        .map_err(|error| invalid(format!("activation identity: {error}")))?;
    let result = engine::run_restore_process(
        RestoreInputs {
            ram,
            layout,
            execution,
            devices,
            expected,
        },
        resources,
        deadline,
        |control, token| {
            // Serving starts a thread and returns: native dispatch runs only
            // after this callback, so no blocking native call happens here.
            let served = lifecycle::serve(
                endpoint,
                binding,
                native::KrunNative::new(control.clone(), config).inherit_baseline(
                    crate::virt::lifecycle::Digest32(*inherited_map.id().as_bytes()),
                    crate::virt::lifecycle::Digest32(*inherited_layout.as_bytes()),
                ),
                Some(RestoreAuthority { activation, token }),
                Box::new(|reason: &str| {
                    eprintln!("krun lifecycle control lost: {reason}");
                    // nix exposes no immediate _exit. A worker that lost its
                    // only lifecycle authority terminates; it never resumes.
                    unsafe { nix::libc::_exit(124) }
                }),
            )?;
            serve_diagnostics(served, binding)?;
            start_status_reporter(events.clone(), control)?;
            emit(events, &Event::RestorePrepared {})?;
            *stage = StartupStage::Started;
            Ok(())
        },
    );
    match result {
        Ok(()) => Ok(()),
        Err(RestoreProcessError::Build(failure)) => {
            let reason = wire::diagnostic(&failure.reason);
            if let Some(failed) = failure.failed {
                settle(failed);
            }
            Err(invalid(format!("restore construction failed: {reason}")))
        }
        Err(RestoreProcessError::Handle { source, failed }) => {
            settle(failed);
            Err(invalid(format!("restore control handle failed: {source}")))
        }
        Err(RestoreProcessError::PreparedCallback { source, failed }) => {
            settle(failed);
            Err(invalid(format!("restore prepared setup failed: {source}")))
        }
        Err(RestoreProcessError::EventLoopTerminated) => {
            Err(invalid("restored libkrun event loop terminated"))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::num::NonZeroU64;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    use vm_spec::capture::{
        CaptureConfiguration, CaptureEvidence, CaptureInventoryEntry, CaptureMemoryEvidence,
        CapturePauseDisposition, CaptureRecordOutcome, CaptureStateBinding, Sha256Digest,
    };
    use vm_spec::lifecycle::{PauseOwner, PauseToken};
    use vm_spec::restore::{RestoreObject, RestoreObjectRole, RestoreRequest};

    use crate::krun::worker::restore::{lower_blocks, validate};
    use crate::krun::KrunConfig;

    pub(crate) fn request() -> RestoreRequest {
        let id = || vm_spec::lifecycle::LiveId::try_from(uuid::Uuid::new_v4().to_string()).unwrap();
        let machine = id();
        let run = id();
        let capture = id();
        let digest = Sha256Digest::of_bytes(b"state");
        let configuration = CaptureConfiguration {
            guest_os: None,
            cpus: 1,
            memory_mib: 128,
            nested_virtualization: false,
            rosetta: false,
            kernel_cmdline: vec![],
            vsock: true,
            attachments: vec![],
            shares: vec![],
        };
        let objects = std::array::from_fn(|index| RestoreObject {
            role: RestoreObjectRole::ALL[index],
            fd: 100 + index as i32,
            file_device: 1,
            file_inode: 100 + index as u64,
            length: if index == 0 { 4096 } else { 5 },
            identity: if index == 0 {
                vm_spec::capture::StreamMap::new(4096, vec![Some(digest)])
                    .unwrap()
                    .id()
            } else {
                digest
            },
        });
        let evidence = CaptureEvidence {
            version: 1,
            machine_id: machine.clone(),
            run_id: run.clone(),
            capture_id: capture.clone(),
            pause_token: Some(PauseToken {
                machine_id: machine,
                run_id: run.clone(),
                generation: NonZeroU64::new(1).unwrap(),
                owner: PauseOwner::Capture {
                    operation_id: capture.clone(),
                },
            }),
            pause_disposition: Some(CapturePauseDisposition::Acquired),
            freeze_epoch: NonZeroU64::new(1),
            freeze_operation_id: Some(capture.clone()),
            configuration_digest: configuration.digest().unwrap(),
            request_digest: digest,
            memory: Some(CaptureMemoryEvidence {
                packed_length: 4096,
                page_granule: 4096,
                regions: 1,
                ram_stream: objects[0].identity,
                binding: CaptureStateBinding {
                    live_state_schema: "silo.live-state/1".to_string(),
                    architecture: std::env::consts::ARCH.into(),
                    profile: digest,
                    topology: digest,
                    ram_layout: digest,
                    source_run: run,
                    pause_generation: NonZeroU64::new(1).unwrap(),
                    capture: capture.clone(),
                },
                mode: vm_spec::lifecycle::CapturePolicy::Full,
                baseline: None,
                full_reason: Some(vm_spec::capture::CaptureFullReason::Requested),
                dirty_chunks: vm_spec::capture::full_dirty_chunks(4096).unwrap(),
                chunk_digests: vec![Some(digest)],
                stats: vm_spec::capture::CaptureMemoryStats {
                    logical_bytes: 4096,
                    whole_file_bytes_hashed: 0,
                    identity_bytes_hashed: 4096,
                    ..Default::default()
                },
            }),
            inventory: objects
                .iter()
                .map(|object| CaptureInventoryEntry {
                    role: object.role.capture_role(),
                    length: object.length,
                    sha256: (object.role != RestoreObjectRole::Ram).then_some(object.identity),
                    identity: (object.role == RestoreObjectRole::Ram).then_some(object.identity),
                })
                .collect(),
            started_at_unix_ms: 1,
            completed_at_unix_ms: 2,
            capture_outcome: CaptureRecordOutcome::Coherent,
            error: None,
            workloads_frozen: true,
            vcpus_paused: true,
            devices_quiesced: true,
            host_writers_drained: true,
            host_flush_completed: true,
            disk_copies_sealed: true,
            memory_state_sealed: true,
        };
        let request = RestoreRequest {
            version: 1,
            checkpoint: digest,
            activation_id: id(),
            freeze_operation_id: capture,
            start_paused: true,
            configuration,
            evidence,
            objects,
            lowers: vec![],
            network: None,
            hook: None,
            ssh_trusted_ca: None,
        };
        request.validate().unwrap();
        request
    }

    pub(crate) fn launch(directory: &std::path::Path) -> crate::virt::RestoreLaunch {
        let mut request = request();
        let map =
            vm_spec::capture::StreamMap::new(4096, vec![Some(Sha256Digest::of_bytes(&[1; 4096]))])
                .unwrap();
        let map_bytes = map.canonical_bytes().unwrap();
        request.objects[4].length = map_bytes.len() as u64;
        request.evidence.inventory[4].length = map_bytes.len() as u64;
        request.evidence.memory.as_mut().unwrap().ram_stream = map.id();
        request.evidence.memory.as_mut().unwrap().chunk_digests = map.chunks().to_vec();
        let objects = std::array::from_fn(|index| {
            let path = directory.join(format!("restore-object-{index}"));
            let bytes = if index == 4 {
                map_bytes.clone()
            } else {
                vec![index as u8 + 1; request.objects[index].length as usize]
            };
            std::fs::write(&path, &bytes).unwrap();
            let file = File::open(path).unwrap();
            let metadata = file.metadata().unwrap();
            let object = &mut request.objects[index];
            object.fd = file.as_raw_fd();
            object.file_device = metadata.dev();
            object.file_inode = metadata.ino();
            if object.role == RestoreObjectRole::Ram {
                object.identity = map.id();
                request.evidence.inventory[index].identity = Some(object.identity);
            } else {
                object.identity = Sha256Digest::of_bytes(&bytes);
                request.evidence.inventory[index].sha256 = Some(object.identity);
            }
            file
        });
        request.validate().unwrap();
        crate::virt::RestoreLaunch {
            request,
            files: std::sync::Arc::new(crate::restore::inputs::RestoreFiles {
                objects,
                lowers: vec![],
            }),
        }
    }

    pub(crate) fn config(request: RestoreRequest) -> KrunConfig {
        KrunConfig {
            cpus: request.configuration.cpus,
            memory_mib: request.configuration.memory_mib,
            vsock_mux: true,
            stdio_console: true,
            balloon: true,
            restore: Some(request),
            ..KrunConfig::default()
        }
    }

    #[test]
    fn restore_config_needs_no_kernel_and_rejects_destination_drift() {
        let request = request();
        let base = config(request.clone());
        validate(&base, &request).unwrap();
        crate::krun::validate_config(&base).unwrap();
        for invalid in [
            KrunConfig {
                cpus: 2,
                ..base.clone()
            },
            KrunConfig {
                memory_mib: 256,
                ..base.clone()
            },
            KrunConfig {
                vsock_mux: false,
                ..base.clone()
            },
            KrunConfig {
                balloon: false,
                ..base.clone()
            },
            KrunConfig {
                stdio_console: false,
                ..base.clone()
            },
            KrunConfig {
                network: crate::krun::Network::Unixgram(crate::krun::NetUnixgram {
                    peer_path: "/tmp/destination.sock".into(),
                    mac: [2, 0, 0, 0, 0, 1],
                }),
                ..base.clone()
            },
        ] {
            assert!(crate::krun::validate_config(&invalid).is_err());
        }
        let cold = KrunConfig {
            restore: None,
            ..base
        };
        assert!(
            crate::krun::validate_config(&cold).is_err(),
            "cold launch still needs a kernel"
        );
    }

    #[test]
    fn restore_worker_network_must_match_the_destination_binding_exactly() {
        let mut request = request();
        request.network = Some(vm_spec::restore::RestoreNetwork {
            mac: "02:00:00:00:00:01".to_string(),
            ipv4: "192.0.2.2".parse().unwrap(),
            prefix_length: 24,
            gateway: "192.0.2.1".parse().unwrap(),
            dns_servers: vec![],
            dns_search: vec![],
        });
        let mut destination = config(request.clone());
        assert!(
            crate::krun::validate_config(&destination).is_err(),
            "missing destination NIC"
        );
        destination.network = crate::krun::Network::Unixgram(crate::krun::NetUnixgram {
            peer_path: "/tmp/destination.sock".into(),
            mac: [2, 0, 0, 0, 0, 1],
        });
        crate::krun::validate_config(&destination).unwrap();
        if let crate::krun::Network::Unixgram(network) = &mut destination.network {
            network.mac[5] = 2;
        }
        assert!(
            crate::krun::validate_config(&destination).is_err(),
            "a different MAC is not the binding"
        );
    }

    #[test]
    fn restore_lower_closure_keeps_genuine_readonly_vmdk_and_uses_inherited_extents() {
        use libkrun::live::restore::{RestoreAttachment, RestoreBlock, RestoreBlockBacking};
        use vm_spec::capture::CaptureAttachment;
        use vm_spec::restore::{RestoreDescriptor, RestoreExtent, RestoreLower};
        let root =
            std::env::temp_dir().join(format!("worker-restore-vmdk-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _directory = Directory(root.clone());
        let extent_path = root.join("extent");
        let descriptor_path = root.join("descriptor");
        let extent_bytes = [0x5a; 4096];
        std::fs::write(&extent_path, extent_bytes).unwrap();
        let text = format!(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\nRW 8 FLAT \"{}\" 0\n",
            extent_path.display()
        );
        std::fs::write(&descriptor_path, &text).unwrap();
        let files = [
            File::open(&descriptor_path).unwrap(),
            File::open(&extent_path).unwrap(),
        ];
        let descriptor = files[0].metadata().unwrap();
        let extent = files[1].metadata().unwrap();
        let launch = launch(&root);
        let mut request = launch.request.clone();
        let block_id = vm_spec::BlockId::new("silo-root-lower").unwrap();
        request.configuration.attachments.push(CaptureAttachment {
            block_id: block_id.clone(),
            role: vm_spec::DiskRole::RootLower,
            format: vm_spec::DiskFormat::Vmdk,
            geometry: vm_spec::DiskGeometry {
                length: 4096,
                logical_sector_size: 512,
            },
            read_only: true,
        });
        request.configuration.attachments.push(CaptureAttachment {
            block_id: vm_spec::BlockId::new("silo-root-upper").unwrap(),
            role: vm_spec::DiskRole::RootUpper,
            format: vm_spec::DiskFormat::Raw,
            geometry: vm_spec::DiskGeometry {
                length: 64 << 20,
                logical_sector_size: 512,
            },
            read_only: false,
        });
        request.evidence.configuration_digest = request.configuration.digest().unwrap();
        request.lowers.push(RestoreLower {
            block_id,
            descriptor: RestoreDescriptor {
                fd: files[0].as_raw_fd(),
                file_device: descriptor.dev(),
                file_inode: descriptor.ino(),
                length: descriptor.len(),
            },
            extents: vec![RestoreExtent {
                path: extent_path.to_str().unwrap().to_string(),
                fd: files[1].as_raw_fd(),
                file_device: extent.dev(),
                file_inode: extent.ino(),
                length: extent.len(),
            }],
        });
        request.validate().unwrap();
        // The native resource must keep using the inherited inode even after
        // the named path has been replaced with a different regular file.
        std::fs::remove_file(&extent_path).unwrap();
        std::fs::write(&extent_path, [0xa5; 4096]).unwrap();
        let duplicate_files = || {
            files
                .iter()
                .map(|file| file.try_clone().unwrap())
                .collect::<Vec<_>>()
        };
        let mut blocks = lower_blocks(&request, duplicate_files()).unwrap();
        let (id, descriptor, extents) = blocks.pop().unwrap();
        let block = RestoreBlock::readonly_vmdk(
            RestoreAttachment {
                configured_id: id,
                address: 0x1000,
                irq: 5,
            },
            descriptor,
            extents,
        );
        let RestoreBlockBacking::ReadonlyVmdk(mut backing) = block.backing else {
            panic!("restore must not flatten VMDK to Raw");
        };
        let mut actual = String::new();
        backing.descriptor.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, text);
        assert_eq!(backing.extents[0].path, extent_path);
        assert_eq!(
            backing.extents[0].file.metadata().unwrap().ino(),
            extent.ino()
        );
        let mut actual = Vec::new();
        backing.extents[0].file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, extent_bytes);
        assert!(backing.extents[0].file.write_all(b"forbidden").is_err());
        let mut malformed = request.clone();
        malformed.lowers[0].descriptor.file_inode += 1;
        assert!(lower_blocks(&malformed, duplicate_files()).is_err());
        assert!(lower_blocks(&request, vec![files[0].try_clone().unwrap()]).is_err());
    }
}

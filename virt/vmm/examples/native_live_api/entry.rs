use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::krun::engine::{self, ConsoleFds, ConsolePort, Control, Resources};
use crate::krun::worker::fds::{Bootstrap, RestoreStateFiles, StandaloneEndpoints};
use eyre::ensure;
use libkrun::control::{OperationId, PauseOwner, PauseToken};
use libkrun::live::restore::*;
use libkrun::live::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    kernel: PathBuf,
    initramfs: PathBuf,
    binding: PathBuf,
    restore: Option<PathBuf>,
    echo_port: NonZeroU32,
    generation_proof_mode: u8,
    #[serde(default)]
    proof: Option<RestoreProof>,
    #[serde(default)]
    silo_fixture: Option<SiloFixture>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SiloFixture {
    machine_id: String,
    run_id: String,
    mac: [u8; 6],
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestoreProof {
    PreparedCallbackFailure,
    InstallTimeout,
}

fn bounded(path: &Path, maximum: u64) -> eyre::Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= maximum,
        "bounded regular input"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "input grew beyond bound");
    Ok(bytes)
}
fn load(path: &Path) -> eyre::Result<Value> {
    Ok(serde_json::from_slice(&bounded(path, 65536)?)?)
}
fn save(path: &Path, value: &Value) -> eyre::Result<()> {
    let mut output = new_output(path)?;
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    Ok(())
}
fn new_output(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
fn reply(prefix: &str, value: &Value) -> eyre::Result<()> {
    writeln!(io::stdout().lock(), "{prefix} {value}")?;
    Ok(())
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn field<const N: usize>(path: &Path) -> eyre::Result<[u8; N]> {
    bounded(path, N as u64)?
        .try_into()
        .map_err(|_| eyre::eyre!("fixed binding field length"))
}
fn binding_json(binding: &StateBinding) -> Value {
    json!({"native_producer":binding.native_producer,"silo_producer":binding.silo_producer,
        "profile":binding.profile,"topology":binding.topology,"ram_layout":binding.ram_layout,
        "source_run":binding.source_run,"capture":binding.capture,"pause_generation":binding.pause_generation})
}
fn parse_binding(value: &Value) -> eyre::Result<StateBinding> {
    let binding = StateBinding {
        native_producer: serde_json::from_value(value["native_producer"].clone())?,
        silo_producer: serde_json::from_value(value["silo_producer"].clone())?,
        profile: serde_json::from_value(value["profile"].clone())?,
        topology: serde_json::from_value(value["topology"].clone())?,
        ram_layout: serde_json::from_value(value["ram_layout"].clone())?,
        source_run: serde_json::from_value(value["source_run"].clone())?,
        capture: serde_json::from_value(value["capture"].clone())?,
        pause_generation: serde_json::from_value(value["pause_generation"].clone())?,
    };
    ensure!(
        binding.native_producer
            == libkrun::capabilities::compiled_live_build()
                .execution_producer()
                .map_err(|error| eyre::eyre!(error))?,
        "independent expected native producer mismatch"
    );
    Ok(binding)
}
fn object_identity(file: &File, expected: &Value) -> eyre::Result<StateObjectIdentity> {
    let identity = StateObjectIdentity {
        length: serde_json::from_value(expected["length"].clone())?,
        sha256: serde_json::from_value(expected["sha256"].clone())?,
    };
    ensure!(
        file.metadata()?.len() == identity.length,
        "expected object length"
    );
    Ok(identity)
}
fn authentication(binding: StateBinding, path: &Path) -> eyre::Result<RamImageAuthentication> {
    let bytes: [u8; 64] = field(path)?;
    ensure!(
        bytes[..32] == binding.ram_layout,
        "authenticated layout binding"
    );
    Ok(RamImageAuthentication {
        state: binding,
        stream: bytes[32..].try_into()?,
    })
}

pub(crate) fn main() -> eyre::Result<()> {
    let restore = std::env::args().any(|arg| arg == "--restore");
    let Bootstrap {
        config,
        events,
        watchdog,
        console,
        mux,
        storage_lease,
        raw_handles,
        state_files,
        standalone,
    } = Bootstrap::adopt_standalone_fixed(restore)?;
    crate::krun::worker::fds::start_watchdog(watchdog)?;
    let mut bytes = Vec::new();
    File::from(config).take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "launch metadata bound");
    let launch: Launch = serde_json::from_slice(&bytes)?;
    ensure!(
        restore == launch.restore.is_some(),
        "restore state role coverage"
    );
    ensure!(raw_handles.len() == 2, "complete two-disk fixture coverage");
    ensure!(
        launch.proof.is_none() || restore,
        "restore-only proof mode on a cold launch"
    );
    if let Some(fixture) = &launch.silo_fixture {
        protocol::shutdown::validate_uuid(&fixture.machine_id)
            .map_err(|error| eyre::eyre!(error))?;
        protocol::shutdown::validate_uuid(&fixture.run_id).map_err(|error| eyre::eyre!(error))?;
        ensure!(
            fixture.mac != [0; 6] && fixture.mac[0] & 1 == 0,
            "unicast fixture MAC"
        );
        ensure!(
            launch.generation_proof_mode == 0 && launch.proof.is_none(),
            "real Silo guest cannot use diagnostic proof modes"
        );
        if !restore {
            ensure!(
                field::<16>(&launch.binding.join("source-run"))?
                    == *uuid::Uuid::parse_str(&fixture.run_id)?.as_bytes(),
                "source capture binding differs from guest run"
            );
        }
    }
    if let Some(proof) = launch.proof {
        reply(
            "RESTORE_CONSTRUCTION_WAITING",
            &json!({"proof":match proof {
                RestoreProof::PreparedCallbackFailure => "prepared-callback-failure",
                RestoreProof::InstallTimeout => "install-timeout",
            }}),
        )?;
        proof_gate("build")?;
    }
    let endpoints = standalone.ok_or_else(|| eyre::eyre!("standalone provider roles missing"))?;
    let mux = mux.ok_or_else(|| eyre::eyre!("mux role missing"))?;
    let mut worker = None;
    let mut queued_public = None;
    let mut install_thread = |control: Control, token: Option<RestoreToken>| -> io::Result<()> {
        let binding = launch.binding.clone();
        let disks: Vec<PathBuf> = raw_handles
            .iter()
            .map(|fd| PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())))
            .collect();
        worker = Some(
            std::thread::Builder::new()
                .name("native-api-proof-control".into())
                .spawn(move || {
                    let cleanup = control.clone();
                    let outcome = command_loop(control, token, binding, disks);
                    if outcome.is_err() {
                        // Malformed input never strands a native event-loop owner.
                        cleanup.stop(OperationId(u64::MAX), deadline())?;
                    }
                    outcome
                })?,
        );
        Ok(())
    };
    let result = if let Some(directory) = &launch.restore {
        let files = state_files.ok_or_else(|| eyre::eyre!("restore state roles missing"))?;
        let mac = launch
            .silo_fixture
            .as_ref()
            .map_or([2, 0, 0, 0, 0, 2], |fixture| fixture.mac);
        let (inputs, resources) = restored_inputs(
            directory,
            files,
            &raw_handles,
            &console,
            mux,
            endpoints,
            mac,
        )?;
        let build_deadline = if launch.proof == Some(RestoreProof::InstallTimeout) {
            Instant::now() + Duration::from_millis(1500)
        } else {
            deadline()
        };
        match engine::run_restore_process(inputs, resources, build_deadline, |control, token| {
            if launch.proof == Some(RestoreProof::PreparedCallbackFailure) {
                queued_public = Some(
                    std::thread::Builder::new()
                        .name("api-prep-MAX".into())
                        .spawn(move || {
                            let result =
                                control.pause(PauseOwner::User, OperationId(u64::MAX), deadline());
                            reply(
                                "PREPARED_PUBLIC_MAX_RESULT",
                                &json!({"operation":u64::MAX,"outcome":format!("{result:?}")}),
                            )?;
                            Ok::<(), eyre::Report>(())
                        })?,
                );
                writeln!(
                    io::stdout().lock(),
                    "PREPARED_CALLBACK_ENTERED no-dispatch/no-BackendStarted"
                )?;
                proof_gate("callback-fail")?;
                return Err(io::Error::other("explicit prepared callback setup refusal"));
            }
            install_thread(control, Some(token))
        }) {
            Ok(()) | Err(engine::RestoreProcessError::EventLoopTerminated) => Ok(()),
            Err(engine::RestoreProcessError::Build(failure)) => {
                settle_build_failure(failure, launch.proof)
            }
            Err(engine::RestoreProcessError::Handle { source, failed }) => {
                settle_prepared_failure(source.to_string(), failed)
            }
            Err(engine::RestoreProcessError::PreparedCallback { source, failed }) => {
                settle_prepared_failure(source.to_string(), failed)
            }
        }
    } else {
        let StandaloneEndpoints {
            network,
            console_input,
            console_output,
        } = endpoints;
        let mut disks = Vec::new();
        for (index, fd) in raw_handles.iter().enumerate() {
            disks.push(vm_spec::Disk {
                path: format!("/proc/self/fd/{}", fd.as_raw_fd()).into(),
                role: if index == 0 {
                    vm_spec::DiskRole::Root
                } else {
                    vm_spec::DiskRole::Data
                },
                format: vm_spec::DiskFormat::Raw,
                geometry: vm_spec::DiskGeometry {
                    length: File::from(fd.try_clone()?).metadata()?.len(),
                    logical_sector_size: 512,
                },
                block_id: vm_spec::BlockId::new(format!("disk{index}"))
                    .map_err(|error| eyre::eyre!("{error}"))?,
                read_only: false,
            });
        }
        let mut cmdline = if launch.silo_fixture.is_some() {
            "root=/dev/vda rootfstype=ext4 rw console=hvc0".to_string()
        } else {
            format!(
                "console=hvc0 rdinit=/init panic=-1 probe.echo_port={}",
                launch.echo_port
            )
        };
        ensure!(
            launch.generation_proof_mode <= 4,
            "generation proof mode bound"
        );
        if launch.generation_proof_mode != 0 {
            cmdline.push_str(&format!(
                " virtio_silo_vmgenid.proof_mode={}",
                launch.generation_proof_mode
            ));
        }
        let config = crate::krun::KrunConfig {
            id: launch.silo_fixture.as_ref().map_or_else(
                || "native-api-proof".into(),
                |fixture| fixture.machine_id.clone(),
            ),
            cpus: 2,
            memory_mib: 512,
            kernel: Some(launch.kernel.clone()),
            initramfs: Some(launch.initramfs.clone()),
            cmdline: vec![cmdline],
            disks,
            stdio_console: true,
            vsock_mux: true,
            balloon: true,
            network: crate::krun::Network::Unixgram(crate::krun::NetUnixgram {
                peer_path: "/caller-owned/already-connected".into(),
                mac: launch
                    .silo_fixture
                    .as_ref()
                    .map_or([2, 0, 0, 0, 0, 1], |fixture| fixture.mac),
            }),
            ..crate::krun::KrunConfig::default()
        };
        match engine::run_process(
            &config,
            Resources {
                console: ConsoleFds {
                    stdin: console.as_fd(),
                    stdout: console.as_fd(),
                    stderr: console.as_fd(),
                },
                vsock_mux: Some(mux),
                managed_network: Some(network),
                console_ports: vec![
                    ConsolePort {
                        name: "probe1",
                        input: Some(console_input.as_fd()),
                        output: None,
                    },
                    ConsolePort {
                        name: "probe2",
                        input: None,
                        output: Some(console_output.as_fd()),
                    },
                    ConsolePort {
                        name: "probe3",
                        input: None,
                        output: None,
                    },
                ],
            },
            |control| install_thread(control, None),
        ) {
            Ok(()) | Err(engine::Error::EventLoopTerminated) => Ok(()),
            Err(error) => Err(eyre::eyre!(error.to_string())),
        }
    };
    let control_result = worker
        .map(|join| {
            join.join()
                .map_err(|_| eyre::eyre!("control thread panicked"))
        })
        .transpose()?
        .transpose();
    let queued_result = queued_public
        .map(|join| {
            join.join()
                .map_err(|_| eyre::eyre!("queued public caller panicked"))
        })
        .transpose()?
        .transpose();
    // All bootstrap leases, disk/console/event descriptors remain owned until the
    // native loop has reconciled stop; errors terminate this dedicated process.
    let outcome = result
        .and(control_result.map(|_| ()))
        .and(queued_result.map(|_| ()));
    if let Err(error) = &outcome {
        writeln!(io::stderr(), "{error:#}")?;
    }
    let _retained = (storage_lease, raw_handles, console, events);
    std::process::exit(if outcome.is_ok() { 0 } else { 1 });
}

fn proof_gate(expected: &str) -> io::Result<()> {
    let input = io::stdin();
    let mut line = Vec::new();
    input.lock().take(129).read_until(b'\n', &mut line)?;
    if line != format!("{expected}\n").as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded exact standalone proof gate",
        ));
    }
    Ok(())
}

fn settle_build_failure(
    mut failure: RestoreBuildFailure<'_>,
    proof: Option<RestoreProof>,
) -> eyre::Result<()> {
    let reason = failure.reason.to_string();
    let retained = failure.failed.is_some();
    let install = matches!(
        failure.reason,
        RestoreError::Native {
            stage: RestoreStage::NativeInstall,
            ..
        }
    );
    reply(
        "RESTORE_FAILURE_PENDING",
        &json!({"reason":reason,"owner_retained":retained,"native_install_stage_failure":install}),
    )?;
    let Some(owner) = failure.failed.take() else {
        reply(
            "RESTORE_FAILURE",
            &json!({"reason":reason,"owner_retained":false,"terminal":true,"native_install_stage_failure":install}),
        )?;
        return Err(eyre::eyre!(reason));
    };
    let owner = if proof == Some(RestoreProof::InstallTimeout) {
        match owner.cleanup(Instant::now() + Duration::from_millis(100)) {
            Ok(()) => {
                reply(
                    "RESTORE_FAILURE",
                    &json!({"reason":reason,"owner_retained":true,"terminal":true,
                    "native_install_stage_failure":install,"first_cleanup_returned_owner":false}),
                )?;
                return Err(eyre::eyre!(reason));
            }
            Err(owner) => {
                reply(
                    "RESTORE_CLEANUP_PENDING",
                    &json!({"reason":reason,"owner_retained":true,
                    "native_install_stage_failure":install,"first_cleanup_returned_owner":true}),
                )?;
                proof_gate("cleanup")?;
                owner
            }
        }
    } else {
        owner
    };
    match owner.cleanup(deadline()) {
        Ok(()) => {
            reply(
                "RESTORE_FAILURE",
                &json!({"reason":reason,"owner_retained":retained,"terminal":true,
                "native_install_stage_failure":install,"first_cleanup_returned_owner":proof == Some(RestoreProof::InstallTimeout)}),
            )?;
            Err(eyre::eyre!(reason))
        }
        Err(owner) => {
            reply(
                "RESTORE_FAILURE",
                &json!({"reason":reason,"owner_retained":true,"terminal":false,"native_install_stage_failure":install}),
            )?;
            let _retained_until_exit = owner;
            std::process::exit(1);
        }
    }
}

fn settle_prepared_failure(reason: String, owner: FailedRestore<'_>) -> eyre::Result<()> {
    match owner.cleanup(deadline()) {
        Ok(()) => {
            reply(
                "RESTORE_FAILURE",
                &json!({"stage":"prepared_setup","reason":reason,
                "owner_retained":true,"terminal":true}),
            )?;
            Err(eyre::eyre!(reason))
        }
        Err(owner) => {
            reply(
                "RESTORE_FAILURE",
                &json!({"stage":"prepared_setup","reason":reason,
                "owner_retained":true,"terminal":false}),
            )?;
            let _retained_until_exit = owner;
            std::process::exit(1);
        }
    }
}

fn restored_inputs(
    directory: &Path,
    files: RestoreStateFiles,
    disks: &[std::os::fd::OwnedFd],
    console: &std::os::fd::OwnedFd,
    mux: std::os::fd::OwnedFd,
    endpoints: StandaloneEndpoints,
    mac: [u8; 6],
) -> eyre::Result<(RestoreInputs, RestoreResources)> {
    let manifest = load(&directory.join("api-capture.json"))?;
    let binding = parse_binding(&manifest["binding"])?;
    let expected = RestoreIdentity {
        ram_image: authentication(
            binding.clone(),
            &directory.join("memory-authentication.bin"),
        )?,
        execution_object: object_identity(&files.execution, &manifest["execution"])?,
        devices_object: object_identity(&files.devices, &manifest["devices"])?,
        binding,
    };
    let attachment = |id: &str| -> eyre::Result<RestoreAttachment> {
        let values = manifest["attachments"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("attachment array"))?;
        let mut matches = values.iter().filter(|item| item["configured_id"] == id);
        let value = matches
            .next()
            .ok_or_else(|| eyre::eyre!("missing attachment {id}"))?;
        ensure!(matches.next().is_none(), "duplicate attachment {id}");
        Ok(RestoreAttachment {
            configured_id: id.into(),
            address: serde_json::from_value(value["address"].clone())?,
            irq: serde_json::from_value(value["irq"].clone())?,
        })
    };
    let StandaloneEndpoints {
        network,
        console_input,
        console_output,
    } = endpoints;
    let mut resources = RestoreResources::default();
    for (index, fd) in disks.iter().enumerate() {
        resources.blocks.push(RestoreBlock {
            attachment: attachment(&format!("disk{index}"))?,
            file: File::from(fd.try_clone()?),
            read_only: false,
        });
    }
    resources.networks.push(RestoreNetwork {
        attachment: attachment("net0")?,
        socket: network.into(),
        mac,
    });
    resources.vsocks.push(RestoreVsock {
        attachment: attachment("vsock")?,
        mux,
        cid: 3,
        agent_port: NonZeroU32::new(1027).ok_or_else(|| eyre::eyre!("agent port"))?,
    });
    resources.consoles.push(RestoreConsole {
        attachment: attachment("hvc0")?,
        ports: vec![
            RestoreConsolePort {
                name: String::new(),
                input: Some(File::from(console.try_clone()?)),
                output: Some(File::from(console.try_clone()?)),
                terminal: true,
            },
            RestoreConsolePort {
                name: "probe1".into(),
                input: Some(console_input.into()),
                output: None,
                terminal: false,
            },
            RestoreConsolePort {
                name: "probe2".into(),
                input: None,
                output: Some(console_output.into()),
                terminal: false,
            },
            RestoreConsolePort {
                name: "probe3".into(),
                input: None,
                output: None,
                terminal: false,
            },
        ],
    });
    Ok((
        RestoreInputs {
            ram: files.ram,
            layout: files.layout,
            execution: files.execution,
            devices: files.devices,
            expected,
        },
        resources,
    ))
}

struct Commands {
    control: Control,
    restore: Option<RestoreToken>,
    pause: Option<PauseToken>,
    generation: Option<GenerationTicket>,
    operation: u64,
    binding: PathBuf,
    disks: Vec<PathBuf>,
    current: Option<(CaptureTicket, PathBuf)>,
    baselines: Vec<BaselineToken>,
}
impl Commands {
    fn operation(&mut self) -> eyre::Result<OperationId> {
        self.operation = self
            .operation
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("operation exhausted"))?;
        Ok(OperationId(self.operation))
    }
    fn pause(&self) -> eyre::Result<&PauseToken> {
        self.pause
            .as_ref()
            .ok_or_else(|| eyre::eyre!("no exact pause token"))
    }
    fn ticket(&self) -> eyre::Result<&CaptureTicket> {
        self.current
            .as_ref()
            .map(|(ticket, _)| ticket)
            .ok_or_else(|| eyre::eyre!("no capture ticket"))
    }
    fn snapshot(&self) -> eyre::Result<()> {
        let state = self.control.live_snapshot(deadline())?;
        reply(
            "LIVE",
            &json!({"state":format!("{:?}",state.state),"backing":format!("{:?}",state.backing),
            "file_backings":state.file_backings,"tracking":format!("{:?}",state.tracking),
            "coverage_valid":state.coverage_valid,"pending_dirty_pages":state.pending_dirty_pages,
            "native_commands_reconciled":state.native_commands_reconciled,"activation_released":state.activation_released,
            "activation_failed":state.activation_failed,
            "restore_installation":state.restore_installation.map(|facts|json!({
                "tracking_before_install":facts.tracking_before_install,"complete":facts.complete,"dirty_pages":facts.dirty_pages})),
            "providers":state.providers.iter().map(|provider|json!({"configured_id":provider.attachment.configured_id,
                "activation_fenced":provider.activation_fenced})).collect::<Vec<_>>(),
            "time_preparation":state.time_preparation.map(|preparation| json!({
                "key":format!("{:?}",preparation.key),
                "plans":preparation.plans.iter().map(|plan|match plan {
                    CpuTimePlan::Kvm(kvm::KvmCpuTimePlan::X86{id,offset,tsc_khz}) =>
                        json!({"id":id,"offset":offset,"tsc_khz":tsc_khz}),
                    other => json!({"unsupported":format!("{other:?}")}),
                }).collect::<Vec<_>>()}))}),
        )
    }
    fn generation_snapshot(&self) -> eyre::Result<()> {
        let snapshot = self.control.generation_snapshot(deadline())?;
        let (outcome, timely) = match snapshot.attempt {
            Some(GenerationObservation::Acknowledged(_)) => ("acknowledged".to_string(), true),
            Some(GenerationObservation::Pending) => ("pending".to_string(), false),
            Some(GenerationObservation::Failed(failure)) => {
                (format!("{failure:?}").to_lowercase(), false)
            }
            None => ("none".to_string(), false),
        };
        reply(
            "GENERATION",
            &json!({"sequence":snapshot.request.sequence,"id":snapshot.request.id,"flags":snapshot.request.flags,
            "processed_sequence":snapshot.processed.sequence,"processed_id":snapshot.processed.id,"driver_status":snapshot.driver_status,
            "clock_latch":snapshot.clock_latch,"config_generation":snapshot.config_generation,
            "committed_sequence":snapshot.committed.map_or(0,|tuple|tuple.sequence),"outcome":outcome,"timely":timely,
            "deadline":self.generation.as_ref().map(|ticket|format!("{:?}",ticket.deadline()))}),
        )
    }
    fn capture(&mut self, directory: &Path, mode: &str) -> eyre::Result<()> {
        ensure!(
            self.current.is_none(),
            "capture result requires explicit resolution/release"
        );
        std::fs::create_dir(directory)?;
        let operation = self.operation()?;
        let flush = self
            .control
            .flush_writable_disks(self.pause()?, operation, deadline())?;
        for (index, disk) in self.disks.iter().enumerate() {
            std::fs::copy(disk, directory.join(format!("disk{index}.raw")))?;
        }
        let layout = self.control.ram_layout(deadline())?;
        let binding = StateBinding {
            native_producer: libkrun::capabilities::compiled_live_build()
                .execution_producer()
                .map_err(|error| eyre::eyre!(error))?,
            silo_producer: field(&self.binding.join("silo-producer"))?,
            profile: field(&self.binding.join("profile"))?,
            topology: field(&self.binding.join("topology"))?,
            ram_layout: Sha256::digest(layout.canonical_bytes()).into(),
            source_run: field(&self.binding.join("source-run"))?,
            capture: *uuid::Uuid::new_v4().as_bytes(),
            pause_generation: self.pause()?.generation().0,
        };
        let operation = self.operation()?;
        let execution = self.control.capture_execution(
            self.pause()?,
            binding.clone(),
            ExecutionOutputs {
                execution: new_output(&directory.join("execution.state"))?,
                devices: new_output(&directory.join("devices.state"))?,
            },
            operation,
            deadline(),
        )?;
        self.current = Some((execution.ticket.clone(), directory.into()));
        let operation = self.operation()?;
        let baseline = if mode == "wrong" {
            self.baselines.first().cloned()
        } else {
            self.baselines.last().cloned()
        };
        let request = MemoryCaptureRequest {
            baseline,
            full_at_dirty_percent: if mode == "full" { 0 } else { 60 },
        };
        let output_directory = mode.strip_prefix("enospc:").map_or(directory, Path::new);
        let ram = new_output(&output_directory.join("memory.ram"))?;
        let layout_output = new_output(&output_directory.join("memory-layout.json"))?;
        reply(
            "OUTPUTS",
            &json!({"directory":output_directory,
            "ram":[ram.metadata()?.dev(),ram.metadata()?.ino()],
            "layout":[layout_output.metadata()?.dev(),layout_output.metadata()?.ino()]}),
        )?;
        let memory = self.control.capture_memory(
            &execution.ticket,
            request,
            MemoryOutputs {
                ram,
                layout: layout_output,
            },
            operation,
            if mode == "timeout" {
                Instant::now() + Duration::from_millis(50)
            } else {
                deadline()
            },
        )?;
        ensure!(memory.ram.writers_closed(), "native RAM writers still open");
        let attachments: Vec<Value> = flush.attachments.iter().map(|item|json!({"configured_id":item.configured_id,"address":item.address,"irq":item.irq})).collect();
        let object = |path: &Path, length: u64| -> eyre::Result<Value> {
            let bytes = bounded(path, 32 * 1024 * 1024)?;
            Ok(json!({"length":length,"sha256":<[u8;32]>::from(Sha256::digest(&bytes))}))
        };
        let stats = memory.ram.stats();
        save(
            &directory.join("api-capture.json"),
            &json!({"schema":1,"api":"Silo engine / public libkrun::live",
            "binding":binding_json(&binding),"attachments":attachments,
            "execution_evidence":execution_evidence(&directory.join("execution.state"))?,
            "execution":object(&directory.join("execution.state"), execution.execution.length)?,
            "devices":object(&directory.join("devices.state"), execution.devices.length)?,
            "writers_closed":memory.ram.writers_closed(),"mode":format!("{:?}",memory.ram.mode()),
            "full_reason":format!("{:?}",memory.full_reason),"memory_generation":memory.memory_generation,
            "output_identities":memory.ram.output_identities(),"affected_chunks":memory.ram.affected_chunks().collect::<Vec<_>>(),
            "stats":{"logical_bytes":stats.logical_bytes,"live_bytes_read":stats.live_bytes_read,
                "baseline_bytes_read":stats.baseline_bytes_read,"baseline_bytes_written":stats.baseline_bytes_written,
                "overlay_bytes_written":stats.overlay_bytes_written,"full_bytes_written":stats.full_bytes_written,
                "explicit_zero_bytes_written":stats.explicit_zero_bytes_written,"extent_queries":stats.extent_queries}}),
        )?;
        self.snapshot()?;
        Ok(())
    }
    fn execute(&mut self, name: &str, operand: &str) -> eyre::Result<bool> {
        let operation = self.operation()?;
        match name {
            "pause" => {
                self.pause = Some(self.control.pause(
                    PauseOwner::Capture,
                    operation,
                    deadline(),
                )?);
            }
            "preserve" => {
                self.pause = Some(self.control.preserve_pause(
                    self.pause()?.clone(),
                    operation,
                    deadline(),
                )?);
            }
            "resume" => {
                self.control.resume(
                    self.pause()?.clone(),
                    operation,
                    Instant::now() + Duration::from_secs(5),
                )?;
                self.pause = None;
                self.generation = None;
            }
            "status" | "state" => self.snapshot()?,
            "generation-fresh" | "generation-clock" => {
                let owner = if let Some(pause) = &self.pause {
                    StoppedOwner::Paused(pause)
                } else {
                    StoppedOwner::Restore(
                        self.restore
                            .as_ref()
                            .ok_or_else(|| eyre::eyre!("no stopped authority"))?,
                    )
                };
                self.generation = Some(self.control.prepare_generation(
                    owner,
                    if name == "generation-clock" {
                        GenerationKind::ClockOnly
                    } else {
                        GenerationKind::FreshIdentity
                    },
                    operation,
                    Instant::now() + Duration::from_secs(5),
                )?);
            }
            "generation-snapshot" => self.generation_snapshot()?,
            "generation-resume" => {
                let ticket = self
                    .generation
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("no generation ticket"))?;
                self.control.resume_generation(
                    self.pause()?.clone(),
                    ticket,
                    operation,
                    deadline(),
                )?;
                self.pause = None;
            }
            "release" => {
                self.control.resume_restored(
                    self.restore
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("no restore token"))?,
                    self.generation
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("no destination generation"))?,
                    operation,
                    deadline(),
                )?;
            }
            "activate" => {
                self.control.release_activation_fences(
                    self.restore
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("no restore token"))?,
                    self.generation
                        .as_ref()
                        .ok_or_else(|| eyre::eyre!("no destination generation"))?,
                    operation,
                    deadline(),
                )?;
                self.snapshot()?;
            }
            "generation-wait" => {
                let ticket = self
                    .generation
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("no generation ticket"))?;
                let until = Instant::now() + Duration::from_secs(6);
                loop {
                    match self.control.poll_generation(ticket, deadline())? {
                        GenerationObservation::Pending if Instant::now() < until => {
                            std::thread::sleep(Duration::from_millis(1))
                        }
                        GenerationObservation::Pending => eyre::bail!("generation observer bound"),
                        outcome => {
                            reply(
                                "GENERATION_RESULT",
                                &json!({"outcome":format!("{outcome:?}")}),
                            )?;
                            break;
                        }
                    }
                }
            }
            "memory-layout" => {
                let layout = self.control.ram_layout(deadline())?;
                new_output(Path::new(operand))?.write_all(layout.canonical_bytes())?;
            }
            "capture" => {
                let (directory, mode) = operand
                    .rsplit_once(' ')
                    .ok_or_else(|| eyre::eyre!("capture directory mode"))?;
                self.capture(Path::new(directory), mode)?;
            }
            "accept" | "accept-wrong" => {
                let (_, directory) = self
                    .current
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("no candidate"))?;
                let manifest = load(&directory.join("api-capture.json"))?;
                let binding = parse_binding(&manifest["binding"])?;
                let baseline = self.control.accept_baseline(
                    self.ticket()?,
                    BaselineImage {
                        ram: File::open(if name == "accept-wrong" {
                            PathBuf::from(operand)
                        } else {
                            directory.join("memory.ram")
                        })?,
                        layout: File::open(directory.join("memory-layout.json"))?,
                        authentication: authentication(
                            binding,
                            &directory.join("memory-authentication.bin"),
                        )?,
                    },
                    operation,
                    deadline(),
                )?;
                reply(
                    "ACCEPTED",
                    &json!({"memory_generation":baseline.memory_generation()}),
                )?;
                self.baselines.push(baseline);
            }
            "abandon" => self
                .control
                .abandon_capture(self.ticket()?, operation, deadline())?,
            "capture-status" => {
                let status = self
                    .control
                    .capture_status(self.ticket()?.id(), deadline())?;
                let stage = match &status {
                    CaptureStatus::ExecutionPending(_) => "ExecutionPending",
                    CaptureStatus::ExecutionComplete(_) => "ExecutionComplete",
                    CaptureStatus::MemoryPending(_) => "MemoryPending",
                    CaptureStatus::CandidateComplete(_) => "CandidateComplete",
                    CaptureStatus::Accepted { .. } => "Accepted",
                    CaptureStatus::Abandoned(_) => "Abandoned",
                    CaptureStatus::Failed { .. } => "Failed",
                    CaptureStatus::Released => "Released",
                };
                reply(
                    "CAPTURE_STATUS",
                    &json!({"stage":stage,"status":format!("{status:?}")}),
                )?;
            }
            "release-capture" => {
                self.control
                    .release_capture(self.ticket()?.id(), operation, deadline())?;
                self.current = None;
            }
            "baseline" => {
                reply(
                    "BASELINE",
                    &json!({"memory_generation":self.control.baseline(deadline())?.map(|token|token.memory_generation())}),
                )?;
            }
            "profile" => {
                self.control.set_capture_profile(
                    observed_profile(Path::new(operand))?,
                    operation,
                    deadline(),
                )?;
            }
            "stop" => {
                self.control.stop(operation, deadline())?;
                return Ok(true);
            }
            _ => eyre::bail!("unknown explicit API proof command"),
        }
        Ok(false)
    }
}
fn execution_evidence(path: &Path) -> eyre::Result<Value> {
    let saved = ExecutionEnvelope::decode(&bounded(path, 16 * 1024 * 1024)?)?;
    ensure!(
        saved.cpus.len() == 2,
        "exact two-CPU native execution inventory"
    );
    let mut cpus = Vec::new();
    for state in &saved.cpus {
        let CpuExecutionState::Kvm(kvm::KvmCpuState::X86(cpu)) = state else {
            eyre::bail!("proof lane requires actual KVM x86 execution");
        };
        cpus.push(json!({"id":cpu.id,"registers":cpu.regs,"events":cpu.events,
            "mp_state":cpu.mp_state,"tsc_offset":cpu.tsc_offset,"tsc_khz":cpu.tsc_khz,
            "tsc_observed":cpu.tsc_observed,"tsc_deadline":cpu.deadline,"lapic":cpu.lapic,
            "xsave_sha256":<[u8;32]>::from(Sha256::digest(&cpu.xsave)),
            "cpuid_count":cpu.cpuid.len(),"msr_inventory_count":cpu.inventory.len(),
            "cpuid_debug_sha256":<[u8;32]>::from(Sha256::digest(format!("{:?}",cpu.cpuid).as_bytes())),
            "msr_inventory_debug_sha256":<[u8;32]>::from(Sha256::digest(format!("{:?}",cpu.inventory).as_bytes()))}));
    }
    let VmExecutionState::Kvm(kvm::KvmVmState::X86(vm)) = &saved.vm else {
        eyre::bail!("proof lane requires actual KVM x86 controller");
    };
    ensure!(vm.pit_profile == 1, "actual retired-PIT profile required");
    Ok(
        json!({"decoder":"existing public ExecutionEnvelope::decode, not a second codec",
        "cpus":cpus,"clock":vm.clock,"clock_flags":vm.clock_flags,"host_tsc":vm.host_tsc,
        "realtime":vm.realtime,"pit_profile":vm.pit_profile,"pic":vm.pic,
        "ioapic_base":vm.ioapic_base,"ioapic_select":vm.ioapic_select,"ioapic_id":vm.ioapic_id,
        "ioapic_irr":vm.ioapic_irr,"ioapic_routes":vm.ioapic_routes,
        "irq_routes":format!("{:?}",saved.irq_routes),"legacy":format!("{:?}",saved.legacy)}),
    )
}

fn command_loop(
    control: Control,
    restore: Option<RestoreToken>,
    binding: PathBuf,
    disks: Vec<PathBuf>,
) -> eyre::Result<()> {
    let mut commands = Commands {
        control,
        restore,
        pause: None,
        generation: None,
        operation: 0,
        binding,
        disks,
        current: None,
        baselines: Vec::new(),
    };
    if let Some(baseline) = commands.control.baseline(deadline())? {
        commands.baselines.push(baseline);
    }
    if commands.restore.is_some() {
        writeln!(
            io::stdout().lock(),
            "PREPARED native-parked-fenced, not BackendStarted"
        )?;
    }
    writeln!(io::stdout().lock(), "READY whole-machine-production")?;
    let input = io::stdin();
    let mut input = input.lock();
    loop {
        let mut bytes = Vec::new();
        let length = (&mut input).take(65537).read_until(b'\n', &mut bytes)?;
        if length == 0 {
            let operation = commands.operation()?;
            commands.control.stop(operation, deadline())?;
            return Ok(());
        }
        ensure!(
            length <= 65536 && bytes.ends_with(b"\n"),
            "bounded complete command line"
        );
        let text = std::str::from_utf8(&bytes)?.trim_end();
        let (name, operand) = text.split_once(' ').unwrap_or((text, ""));
        match commands.execute(name, operand) {
            Ok(stop) => {
                writeln!(io::stdout().lock(), "OK {name}")?;
                if stop {
                    return Ok(());
                }
            }
            Err(error) => writeln!(io::stdout().lock(), "ERROR {name} {error:#}")?,
        }
    }
}
fn observed_profile(directory: &Path) -> eyre::Result<KvmCaptureProfile> {
    let text = |name: &str| -> eyre::Result<String> {
        Ok(String::from_utf8(bounded(&directory.join(name), 65536)?)?)
    };
    let kernel_identity = text("kernel-identity")?;
    let clocksource = text("clocksource")?;
    let clockevents = text("clockevents")?;
    let broadcast = text("broadcast-clockevent")?;
    let state = text("broadcast-clockevent-state")?;
    ensure!(
        !kernel_identity.trim().is_empty() && clocksource.trim() == "tsc",
        "actual same-boot kernel/clock profile"
    );
    ensure!(
        clockevents.lines().count() == 2
            && clockevents
                .lines()
                .all(|value| value.trim() == "lapic-deadline"),
        "two actual deadline clockevents"
    );
    let header="path=/sys/devices/system/clockevents/broadcast/current_device\nread_complete=1\nbytes_read=";
    let (length, kind) = state
        .strip_prefix(header)
        .and_then(|value| value.split_once("\nkind="))
        .ok_or_else(|| eyre::eyre!("complete actual broadcast read required"))?;
    let length: usize = length.parse()?;
    ensure!(
        (kind.trim() == "no-device" && length == 0 && broadcast == "\n")
            || (kind.trim() == "device"
                && length == broadcast.len()
                && !broadcast.trim().is_empty()
                && broadcast.trim() != "pit"),
        "broadcast observation binding/non-PIT"
    );
    ensure!(
        text("speaker-consumers")?.trim().is_empty() && !text("modules")?.contains("pcspkr"),
        "no active speaker consumer"
    );
    Ok(KvmCaptureProfile::RetiredLinuxPit {
        kernel_identity,
        clocksource_tsc: true,
        all_online_clockevents_deadline: true,
        broadcast_uses_pit: false,
        speaker_or_counter_consumer: false,
    })
}

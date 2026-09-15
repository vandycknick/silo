#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("silo-rprobe-vz-harness requires macOS ARM64");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
mod macos {
    use std::future::Future;
    use std::path::PathBuf;
    use std::time::Duration;

    use clap::Parser;
    use eyre::{eyre, Context, Result};
    use rprobe::frame::{Decoder, FrameError, SUCCESS_LEN};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;
    use tokio::time::Instant;
    use vz::device::{
        LinuxRosettaDirectoryShare, SerialPortConfiguration, SerialPortStream,
        VirtioFileSystemDeviceConfiguration,
    };
    use vz::{
        GenericPlatform, LinuxBootLoader, RosettaAvailability, VirtualMachine, VirtualMachineState,
    };

    const ACQUISITION_TIMEOUT: Duration = Duration::from_secs(60);
    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUESTED_MEMORY: u64 = 128 * 1024 * 1024;
    const MAX_PROBE_MEMORY: u64 = 512 * 1024 * 1024;
    const DIAGNOSTIC_LIMIT: usize = 64 * 1024;

    #[derive(Debug, Parser)]
    struct Args {
        #[arg(long, value_name = "PATH")]
        kernel: PathBuf,
        #[arg(long, value_name = "PATH")]
        initramfs: PathBuf,
        #[arg(long)]
        cancel_while_starting: bool,
    }

    struct Capture {
        decoder: Decoder,
    }

    struct DiagnosticStats {
        retained: Vec<u8>,
        total: u64,
    }

    struct CleanupReport {
        start_completion: &'static str,
        starting_direct_stop: String,
    }

    #[derive(Clone, Debug)]
    enum StartCompletion {
        Pending,
        Succeeded,
        Failed(String),
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        if !args.kernel.is_file() {
            return Err(eyre!("kernel is not a regular file"));
        }
        if !args.initramfs.is_file() {
            return Err(eyre!("initramfs is not a regular file"));
        }
        match vz::rosetta_availability() {
            RosettaAvailability::Installed => {}
            RosettaAvailability::NotInstalled => {
                return Err(eyre!("Rosetta for Linux VMs is not installed"));
            }
            RosettaAvailability::NotSupported => {
                return Err(eyre!("Rosetta for Linux VMs is not supported"));
            }
        }

        let limits = vz::virtual_machine_limits();
        if limits.minimum_cpu_count > 1 || limits.maximum_cpu_count < 1 {
            return Err(eyre!(
                "Virtualization.framework does not permit one probe CPU"
            ));
        }
        let memory = REQUESTED_MEMORY.max(limits.minimum_memory_size);
        if memory > limits.maximum_memory_size || memory > MAX_PROBE_MEMORY {
            return Err(eyre!(
                "Virtualization.framework minimum memory exceeds the bounded probe policy"
            ));
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("build hardware-test runtime")?;
        runtime.block_on(run(args, memory))
    }

    async fn run(args: Args, memory: u64) -> Result<()> {
        let started = Instant::now();
        let acquisition_deadline = started + ACQUISITION_TIMEOUT;

        let diagnostic_port = SerialPortConfiguration::virtio_console()
            .wrap_err("construct diagnostic serial port")?;
        let data_port =
            SerialPortConfiguration::virtio_console().wrap_err("construct raw data serial port")?;
        let mut diagnostic_stream = diagnostic_port
            .open_stream()
            .wrap_err("open diagnostic serial stream")?;
        let mut data_stream = data_port
            .open_stream()
            .wrap_err("open raw data serial stream")?;
        diagnostic_stream
            .shutdown()
            .await
            .wrap_err("close diagnostic input pipe")?;
        data_stream
            .shutdown()
            .await
            .wrap_err("close raw data input pipe")?;

        let mut boot_loader = LinuxBootLoader::new(args.kernel);
        boot_loader.set_initial_ramdisk(args.initramfs);
        boot_loader.set_command_line("rdinit=/init console=hvc0 panic=0 loglevel=4");

        let platform = GenericPlatform::new();
        platform.set_nested_virtualization_enabled(false);
        let mut filesystem =
            VirtioFileSystemDeviceConfiguration::new(agent_spec::ROSETTA_MOUNT_TAG)
                .wrap_err("construct Rosetta virtio-fs configuration")?;
        filesystem.set_rosetta_share(
            LinuxRosettaDirectoryShare::new().wrap_err("construct Rosetta directory share")?,
        );
        let vm = VirtualMachine::builder()
            .wrap_err("construct VZ configuration")?
            .set_cpu_count(1)
            .set_memory_size(memory)
            .set_platform(platform)
            .set_boot_loader(boot_loader)
            .add_serial_port(diagnostic_port.clone())
            .add_serial_port(data_port.clone())
            .add_directory_share(filesystem)
            .build()
            .wrap_err("validate VZ probe configuration")?;

        let diagnostic_task = tokio::spawn(drain_diagnostics(diagnostic_stream));
        let mut states = vm.subscribe_state();
        let start_vm = vm.clone();
        let (start_tx, mut start_rx) = watch::channel(StartCompletion::Pending);
        let start_task = tokio::spawn(async move {
            let result = start_vm.start().await;
            let completion = match &result {
                Ok(()) => StartCompletion::Succeeded,
                Err(error) => StartCompletion::Failed(error.to_string()),
            };
            let _ = start_tx.send(completion);
            result
        });
        let acquisition_result = if args.cancel_while_starting {
            bounded_acquisition(acquisition_deadline, wait_for_starting(&vm, &mut states))
                .await
                .map(|()| None)
        } else {
            bounded_acquisition(acquisition_deadline, async {
                wait_for_start_completion(&mut start_rx).await?;
                wait_for_state(&vm, &mut states, VirtualMachineState::Running).await?;
                receive_frame(&mut data_stream).await.map(Some)
            })
            .await
        };

        let cleanup_started = Instant::now();
        let cleanup_deadline = cleanup_started + CLEANUP_TIMEOUT;
        let cleanup_result =
            cleanup_with_start(&vm, &mut states, start_task, cleanup_deadline).await;
        drop(vm);
        drop(diagnostic_port);
        drop(data_port);

        let trailing_result = check_trailing_data(&mut data_stream, cleanup_deadline).await;
        drop(data_stream);
        let diagnostic_stats = tokio::time::timeout_at(cleanup_deadline, diagnostic_task)
            .await
            .map_err(|_| eyre!("diagnostic drain did not finish during cleanup"))?
            .map_err(|error| eyre!("diagnostic drain task failed: {error}"))??;

        let cleanup = cleanup_result?;
        trailing_result?;
        let capture = acquisition_result?;
        if args.cancel_while_starting {
            if capture.is_some() {
                return Err(eyre!(
                    "starting-state cancellation unexpectedly captured a frame"
                ));
            }
            println!(
                "host_harness_pid={} guest_pid=1 scenario=cancel-while-starting observed_state=Starting starting_direct_stop={} start_callback={} memory_bytes={} acquisition_ms={} cleanup_ms={} diagnostic_bytes={} diagnostic_retained={} vz_xpc_pid=not-observed cleanup=stopped-released",
                std::process::id(),
                cleanup.starting_direct_stop,
                cleanup.start_completion,
                memory,
                cleanup_started.duration_since(started).as_millis(),
                cleanup_started.elapsed().as_millis(),
                diagnostic_stats.total,
                diagnostic_stats.retained.len(),
            );
            return Ok(());
        }
        let capture = capture.ok_or_else(|| eyre!("probe capture completed without a frame"))?;
        let frame = capture
            .decoder
            .finish()
            .map_err(|error| eyre!("captured frame failed final validation: {error:?}"))?;
        if frame.header.result < 0 {
            return Err(eyre!(
                "probe ioctl failed status={} errno={} payload_len={}",
                frame.header.result,
                frame.header.errno,
                frame.payload.len()
            ));
        }
        if frame.payload.len() != 1024 {
            return Err(eyre!("successful probe frame has invalid payload length"));
        }

        println!(
            "host_harness_pid={} guest_pid=1 status={} payload_len={} cpu_count=1 memory_bytes={} acquisition_ms={} cleanup_ms={} diagnostic_bytes={} diagnostic_retained={} resources=disks:0,network:0,vsock:0,balloon:0 serial_ports=hvc0:diagnostic,hvc1:raw share=rosetta start_callback={} vz_xpc_pid=not-observed cleanup=stopped-released",
            std::process::id(),
            frame.header.result,
            frame.payload.len(),
            memory,
            cleanup_started.duration_since(started).as_millis(),
            cleanup_started.elapsed().as_millis(),
            diagnostic_stats.total,
            diagnostic_stats.retained.len(),
            cleanup.start_completion,
        );
        Ok(())
    }

    async fn bounded_acquisition<F, T>(deadline: Instant, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        tokio::select! {
            result = tokio::time::timeout_at(deadline, future) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(eyre!("probe acquisition timed out")),
                }
            }
            signal = tokio::signal::ctrl_c() => {
                match signal {
                    Ok(()) => Err(eyre!("probe acquisition cancelled")),
                    Err(error) => Err(eyre!("listen for cancellation: {error}")),
                }
            }
        }
    }

    async fn wait_for_start_completion(
        completion: &mut watch::Receiver<StartCompletion>,
    ) -> Result<()> {
        loop {
            match completion.borrow_and_update().clone() {
                StartCompletion::Pending => {}
                StartCompletion::Succeeded => return Ok(()),
                StartCompletion::Failed(error) => {
                    return Err(eyre!("start VZ probe: {error}"));
                }
            }
            completion
                .changed()
                .await
                .map_err(|_| eyre!("VZ start completion owner closed without a result"))?;
        }
    }

    async fn wait_for_starting(
        vm: &VirtualMachine,
        states: &mut watch::Receiver<VirtualMachineState>,
    ) -> Result<()> {
        loop {
            match vm.state() {
                VirtualMachineState::Starting => return Ok(()),
                VirtualMachineState::Stopped => {}
                state => {
                    return Err(eyre!(
                        "could not exercise Starting cleanup; VZ reached {state} first"
                    ));
                }
            }
            states
                .changed()
                .await
                .map_err(|_| eyre!("VZ state stream closed before Starting was observed"))?;
        }
    }

    async fn await_start_task(
        task: tokio::task::JoinHandle<std::result::Result<(), vz::VzError>>,
        deadline: Instant,
    ) -> Result<&'static str> {
        let result = tokio::time::timeout_at(deadline, task)
            .await
            .map_err(|_| eyre!("VZ start callback was not released during cleanup"))?
            .map_err(|error| eyre!("VZ start callback task failed: {error}"))?;
        Ok(if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        })
    }

    async fn cleanup_with_start(
        vm: &VirtualMachine,
        states: &mut watch::Receiver<VirtualMachineState>,
        start_task: tokio::task::JoinHandle<std::result::Result<(), vz::VzError>>,
        deadline: Instant,
    ) -> Result<CleanupReport> {
        if vm.state() != VirtualMachineState::Starting {
            let cleanup_result = cleanup_vm(vm, states, deadline).await;
            let start_completion = await_start_task(start_task, deadline).await;
            cleanup_result?;
            return Ok(CleanupReport {
                start_completion: start_completion?,
                starting_direct_stop: "not-attempted".to_string(),
            });
        }

        let starting_direct_stop = match tokio::time::timeout_at(deadline, vm.stop()).await {
            Ok(Ok(())) => "accepted".to_string(),
            Ok(Err(error)) => format!("rejected:{error}"),
            Err(_) => return Err(eyre!("direct VZ stop timed out while VZ was Starting")),
        };
        let start_completion = await_start_task(start_task, deadline).await?;
        cleanup_vm(vm, states, deadline).await?;
        Ok(CleanupReport {
            start_completion,
            starting_direct_stop,
        })
    }

    async fn receive_frame(stream: &mut SerialPortStream) -> Result<Capture> {
        let mut decoder = Decoder::new();
        let mut buffer = [0u8; SUCCESS_LEN];
        while !decoder.is_complete() {
            let maximum = decoder
                .expected_len()
                .unwrap_or(SUCCESS_LEN)
                .saturating_sub(decoder.received_len());
            if maximum == 0 {
                return Err(eyre!("probe frame made no progress"));
            }
            let count = stream
                .read(&mut buffer[..maximum])
                .await
                .wrap_err("read probe frame")?;
            if count == 0 {
                return Err(eyre!("probe frame ended before completion"));
            }
            decoder.push(&buffer[..count]).map_err(frame_error)?;
        }
        Ok(Capture { decoder })
    }

    async fn cleanup_vm(
        vm: &VirtualMachine,
        states: &mut tokio::sync::watch::Receiver<VirtualMachineState>,
        deadline: Instant,
    ) -> Result<()> {
        if vm.state() != VirtualMachineState::Stopped {
            tokio::time::timeout_at(deadline, vm.stop())
                .await
                .map_err(|_| eyre!("direct VZ stop timed out"))?
                .wrap_err("direct VZ stop failed")?;
        }
        tokio::time::timeout_at(
            deadline,
            wait_for_state(vm, states, VirtualMachineState::Stopped),
        )
        .await
        .map_err(|_| eyre!("VZ stopped-state wait timed out"))??;
        Ok(())
    }

    async fn check_trailing_data(stream: &mut SerialPortStream, deadline: Instant) -> Result<()> {
        let mut byte = [0u8; 1];
        let count = tokio::time::timeout_at(deadline, stream.read(&mut byte))
            .await
            .map_err(|_| eyre!("raw serial EOF check timed out after VZ release"))?
            .wrap_err("check raw serial trailing data")?;
        if count == 0 {
            Ok(())
        } else {
            Err(eyre!("raw serial contained trailing data"))
        }
    }

    async fn drain_diagnostics(mut stream: SerialPortStream) -> Result<DiagnosticStats> {
        let mut retained = Vec::with_capacity(DIAGNOSTIC_LIMIT);
        let mut total = 0u64;
        let mut buffer = [0u8; 4096];
        loop {
            let count = stream
                .read(&mut buffer)
                .await
                .wrap_err("drain probe diagnostics")?;
            if count == 0 {
                return Ok(DiagnosticStats { retained, total });
            }
            total = total.saturating_add(count as u64);
            let keep = (DIAGNOSTIC_LIMIT - retained.len()).min(count);
            retained.extend_from_slice(&buffer[..keep]);
        }
    }

    async fn wait_for_state(
        vm: &VirtualMachine,
        states: &mut tokio::sync::watch::Receiver<VirtualMachineState>,
        target: VirtualMachineState,
    ) -> Result<()> {
        loop {
            let state = vm.state();
            if state == target {
                return Ok(());
            }
            if state == VirtualMachineState::Error {
                return Err(eyre!(
                    "VZ probe entered error state while awaiting {target}"
                ));
            }
            states
                .changed()
                .await
                .map_err(|_| eyre!("VZ state stream closed while awaiting {target}"))?;
        }
    }

    fn frame_error(error: FrameError) -> eyre::Report {
        eyre!("invalid probe frame: {error:?}")
    }
}

#[cfg(target_os = "macos")]
fn main() -> eyre::Result<()> {
    macos::main()
}
